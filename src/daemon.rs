//! The local daemon: the single writer that owns SQLite fleet state and
//! serves the versioned hf-rpc-request/v1 protocol over a per-user Unix
//! socket (issue #5, AC1/AC2/AC4/AC5/AC7/AC8/AC10).
//!
//! Design invariants implemented here:
//!
//! - One daemon per host/user: `DaemonLock` (flock + stale recovery) is
//!   acquired before the socket binds, so a second daemon can never become a
//!   concurrent writer (AC1).
//! - Mutations journal their intent durably (hash-chained audit + claim)
//!   *before* any effect and resolve with a typed outcome and a recorded
//!   response; replaying the same request id + idempotency key returns the
//!   recorded response (AC6). A crash anywhere between intent and outcome is
//!   reconciled on restart: the claim is marked ambiguous with a typed
//!   outcome and a new key is required (AC4).
//! - Every journaled state change appends an `hf-event/v1` row; `events
//!   .subscribe` connections receive the response, then a snapshot when the
//!   cursor is stale/absent, then the contiguous replay, then live events
//!   (seq-ordered, one line each). Subscriber queues are bounded; a
//!   subscriber that does not drain is disconnected (AC7).
//! - Logs are JSONL with only allowlisted fields and redacted bounded
//!   summaries (AC8); there is no network listener, usage reporting,
//!   auto-update path, or notification integration anywhere (AC10).
//! - `CANTER_CRASH_POINT` (pre-rename alias: `HERDR_FLEET_CRASH_POINT`;
//!   docs/contracts/compatibility.md) aborts the process at a named journal
//!   boundary in **debug builds only**; release binaries ignore it, so it
//!   cannot be weaponized against a production daemon.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{SyncSender, TrySendError, sync_channel};
use std::sync::{Arc, Mutex};

use crate::backup;
use crate::canonical::canonical_text;
use crate::dirs::DaemonPaths;
use crate::lock::{DaemonLock, bind_listener};
use crate::redact::redact;
use crate::schema::{Family, RPC_METHODS, Refusal, validate_doc};
use crate::state::{AuditRow, ClaimAttempt, State, StateError, StateSummary};
use crate::time;
use crate::value::{Val, bool_, integer, null, object, string};

/// Maximum accepted request line length (bounded memory per connection).
pub const MAX_REQUEST_BYTES: usize = 1024 * 1024;

/// Upper bound for one replay window read. The default event retention
/// (2000 rows) is smaller, so a replay can never be truncated by this cap;
/// the bound exists to keep one hub-locked read finite.
pub const REPLAY_MAX_LINES: i64 = 8192;
/// Per-subscriber bounded event queue; a subscriber that does not drain it
/// is disconnected (bounded backpressure, AC7).
pub const SUBSCRIBER_QUEUE_CAP: usize = 64;
/// A subscriber that stops draining cannot pin its socket-writer thread.
const EVENT_STREAM_WRITE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);
/// Upper bound on journal records served per `journal.tail` call.
pub const JOURNAL_TAIL_LIMIT: i64 = 2000;
/// Fallback id used for responses to unparseable request bytes (schema-valid
/// 8-lowercase-hex; such requests carry no id to echo).
pub const FALLBACK_REQUEST_ID: &str = "00000000";
/// Canonical plan/step identity used by daemon-owned outcome documents.
pub const DAEMON_PLAN_ID: &str = "hf_plan_0000000000000000";
/// Canonical step id used by daemon-owned outcome documents.
pub const DAEMON_STEP_ID: &str = "daemon";

/// A daemon startup/serve failure (maps to CLI exit codes by the caller).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DaemonError {
    /// Stable code (`daemon.busy`, `daemon.state`, `daemon.bind`,
    /// `daemon.io`, `daemon.reconcile`).
    pub code: &'static str,
    /// Human message.
    pub message: String,
}

fn daemon_error(code: &'static str, message: impl Into<String>) -> DaemonError {
    DaemonError {
        code,
        message: message.into(),
    }
}

impl From<crate::dirs::PathError> for DaemonError {
    fn from(err: crate::dirs::PathError) -> DaemonError {
        DaemonError {
            code: "daemon.io",
            message: format!("{}: {}", err.code, err.message),
        }
    }
}

impl From<StateError> for DaemonError {
    fn from(err: StateError) -> DaemonError {
        DaemonError {
            code: "daemon.state",
            message: format!("{}: {}", err.code, err.message),
        }
    }
}

/// Allowlisted daemon log (JSONL; AC8). Only structured fields with a
/// redacted, bounded summary — full request bodies are never persisted.
#[derive(Debug)]
pub struct DaemonLog {
    path: std::path::PathBuf,
}

impl DaemonLog {
    /// Open the log path, rotating an oversized previous log at startup.
    pub fn open(path: &std::path::Path) -> Result<DaemonLog, DaemonError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|err| {
                daemon_error("daemon.io", format!("create {}: {err}", parent.display()))
            })?;
        }
        if let Ok(meta) = std::fs::metadata(path)
            && meta.len() > 8 * 1024 * 1024
        {
            let _ = std::fs::rename(path, path.with_extension("log.old"));
        }
        Ok(DaemonLog {
            path: path.to_path_buf(),
        })
    }

    /// Append one record: `{schema?no: ts, level, event, message}` with
    /// `message` a redacted, bounded summary (never a full payload).
    pub fn write(&self, level: &str, event: &str, message: &str) {
        let summary = bounded(redact(message).as_str(), 300);
        let line = canonical_text(&object(vec![
            ("ts", string(&time::rfc3339_now())),
            ("level", string(level)),
            ("event", string(event)),
            ("message", string(&summary)),
        ]));
        let result = (|| -> std::io::Result<()> {
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.path)?;
            file.write_all(line.as_bytes())?;
            Ok(())
        })();
        if let Err(err) = result {
            eprintln!("daemon log write failed: {err}");
        }
    }
}

/// Bound a summary string to `cap` chars at a char boundary.
fn bounded(text: &str, cap: usize) -> String {
    if text.len() <= cap {
        return text.to_string();
    }
    let mut end = cap;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &text[..end])
}

/// One registered event subscriber (bounded queue).
struct Subscriber {
    sender: SyncSender<String>,
}

/// Event fan-out hub. Locking rule (documented, deadlock-free by order):
/// the hub lock may be held while a *brief* state read happens
/// (`compute_replay`), but the hub is never acquired while a state guard is
/// held — state mutations release their guard before publishing.
struct Hub {
    subscribers: Vec<Subscriber>,
    /// Highest event seq already fanned out by this daemon run.
    last_published: i64,
}

impl Hub {
    fn new(last_published: i64) -> Hub {
        Hub {
            subscribers: Vec::new(),
            last_published,
        }
    }

    /// Publish one canonical event line; a subscriber whose queue is full
    /// (or gone) is dropped (bounded backpressure).
    fn publish(&mut self, line: &str) {
        let mut retained = Vec::with_capacity(self.subscribers.len());
        for subscriber in self.subscribers.drain(..) {
            match subscriber.sender.try_send(line.to_string()) {
                Ok(()) => retained.push(subscriber),
                Err(TrySendError::Full(_)) => {
                    // Backpressure: the subscriber is not draining; drop it.
                }
                Err(TrySendError::Disconnected(_)) => {}
            }
        }
        self.subscribers = retained;
    }
}

/// Everything shared between connection threads.
struct Shared {
    state: Arc<Mutex<State>>,
    hub: Mutex<Hub>,
    log: DaemonLog,
    paths: DaemonPaths,
    pid: u32,
    started_at: String,
    running: AtomicBool,
    /// The supervised reconciliation driver's wait/stop handle (issue #95):
    /// handing it a wake never blocks and never touches the state guard.
    supervisor: Arc<crate::supervision::SupervisorWake>,
}

impl Shared {
    fn lock_state(&self) -> Result<std::sync::MutexGuard<'_, State>, String> {
        self.state
            .lock()
            .map_err(|_| "state mutex poisoned".to_string())
    }

    /// Ask the supervision driver to re-evaluate promptly. Coalesced: the
    /// driver folds every wake into ONE pending trigger per run.
    fn wake_supervisor(&self) {
        self.supervisor.wake();
    }
}

/// A parsed and validated request plus its raw canonical line.
struct Request {
    id: String,
    method: String,
    params: Option<Val>,
    line: String,
}

/// The outcome of handling one request.
enum HandleOutcome {
    /// One response line.
    Response(String),
    /// A subscribe response, then a switch to event-stream mode.
    Subscribed {
        response: String,
        cursor: Option<i64>,
    },
}

/// Run the daemon until a fatal serve error (used by `daemon run`). On
/// return the lock is released, the lease dropped, and the socket unlinked.
pub fn serve(paths: &DaemonPaths) -> Result<(), DaemonError> {
    paths.prepare()?;
    let started_at = time::rfc3339_now();
    // Single-writer lock: a second daemon is refused with the owner detail.
    let _lock = DaemonLock::acquire(&paths.lock_path, &started_at).map_err(|err| {
        daemon_error(
            "daemon.busy",
            match err.code {
                "lock.busy" => format!("another daemon is already running: {}", err.message),
                _ => err.message,
            },
        )
    })?;
    // Reclaim a stale socket from a crashed previous daemon, then bind.
    let listener = bind_listener(&paths.socket_path)
        .map_err(|err| daemon_error("daemon.bind", err.message))?;

    let state = State::open(&paths.db_path, crate::state::Retention::default())
        .map_err(|err| daemon_error("daemon.state", format!("{}: {}", err.code, err.message)))?;
    let log = DaemonLog::open(&paths.log_path)?;
    log.write(
        "info",
        "daemon.start",
        &format!("pid {} serving", std::process::id()),
    );

    // Restart reconciliation BEFORE the daemon accepts requests (AC4):
    // claims left `claimed` by an interrupted run become ambiguous, and any
    // interrupted mutation needs a fresh key before it may retry.
    let mirrored = state.rebuild_audit_mirror(&paths.audit_mirror_path)?;
    if mirrored {
        log.write(
            "warn",
            "journal.mirror.rebuilt",
            "audit mirror drifted or was missing; rebuilt from the journal table",
        );
    }
    let events_mirrored = state.rebuild_events_mirror(&paths.events_mirror_path)?;
    if events_mirrored {
        log.write(
            "warn",
            "events.mirror.rebuilt",
            "events mirror drifted or was missing; rebuilt from the events table",
        );
    }
    let reconciled = reconcile_claims(&state, &log, &paths.checkpoints_dir)?;
    // Issue #86 run-scoped controls: after a restart no step is executing,
    // so every recorded pause request without in-flight work has reached
    // its safe boundary and commits `paused` here (the intent is durable;
    // the boundary is re-derived, never guessed).
    match state.reconcile_run_pause_boundaries(&time::rfc3339_now()) {
        Ok(reached) if reached > 0 => {
            log.write(
                "info",
                "run.pause.reconciled",
                &format!("{reached} pause request(s) reached their safe boundary"),
            );
        }
        Ok(_) => {}
        Err(err) => {
            return Err(daemon_error(
                "daemon.reconcile",
                format!(
                    "run pause boundary reconciliation failed: {}: {}",
                    err.code, err.message
                ),
            ));
        }
    }
    // Cold-boot schedule recovery (issue #9 AC2/AC9): every due schedule
    // fires at most ONE fresh coalesced evaluation per boot (missed windows
    // are skipped, never replayed), refused schedules park themselves, and
    // paused schedules stay paused. Runs even when Herdr is absent or
    // unhealthy: the evaluation path is daemon-state only and never spawns.
    match crate::lifecycle::reconcile_schedules(&state, time::unix_now(), None) {
        Ok(summary) => {
            if !summary.ran.is_empty() || !summary.paused.is_empty() {
                log.write(
                    "info",
                    "schedules.reconciled",
                    &format!(
                        "{} ran once; {} parked ({}); {} idle",
                        summary.ran.len(),
                        summary.paused.len(),
                        summary
                            .paused
                            .iter()
                            .map(|(_, reason)| reason.as_str())
                            .collect::<Vec<_>>()
                            .join(","),
                        summary.idle.len()
                    ),
                );
            }
        }
        Err(err) => {
            return Err(daemon_error(
                "daemon.reconcile",
                format!("schedule recovery failed: {}: {}", err.code, err.message),
            ));
        }
    }

    let (max_seq, _) = state
        .event_bounds()
        .map_err(|err| daemon_error("daemon.state", format!("{}: {}", err.code, err.message)))?;
    state.put_daemon_lease(std::process::id(), &started_at)?;
    let state = Arc::new(Mutex::new(state));
    // Issue #95: the supervised reconciliation driver. It starts after every
    // boot reconciliation above (schedule recovery, claim reconciliation,
    // pause boundaries) and runs ONE fresh snapshot reconciliation per armed
    // run before it waits for semantic wakes or its bounded timer deadline.
    // Issue #92 F4: the supervision driver's dispatch hook. It is created
    // before `Shared` (the driver starts first) and completed right after, so
    // a dispatch always sees the same handle the request handlers use.
    let dispatch = Arc::new(DaemonDispatch {
        shared: std::sync::OnceLock::new(),
        refusals: Arc::new(Mutex::new(std::collections::BTreeMap::new())),
        collecting: Arc::new(Mutex::new(Collections::default())),
    });
    let supervisor = crate::supervision::start(
        Arc::clone(&state),
        crate::supervision::SupervisorOptions {
            dispatch: Some(dispatch.clone()),
            ..crate::supervision::SupervisorOptions::default()
        },
    );
    let shared = Arc::new(Shared {
        state,
        hub: Mutex::new(Hub::new(max_seq.unwrap_or(0))),
        log,
        paths: paths.clone(),
        pid: std::process::id(),
        started_at,
        running: AtomicBool::new(true),
        supervisor: supervisor.wake_handle(),
    });
    let _ = dispatch.shared.set(Arc::clone(&shared));
    shared.log.write(
        "info",
        "daemon.ready",
        &format!(
            "state open; reconciled {} interrupted claim(s); serving {}",
            reconciled,
            paths.socket_path.display()
        ),
    );

    let result = serve_loop(&shared, &listener);
    // Shutdown: cancel and JOIN the supervision driver before the lease is
    // dropped.
    //
    // Issue #170 (N4) — the invariant, stated exactly: NO RECONCILIATION runs
    // after the lease is dropped. It is deliberately not "no thread outlives
    // the lease": a bounded collection the driver dispatched runs on its own
    // `canter-collect` thread (see the spawn below) and is NEVER joined —
    // a collection can wait on a pane worker for hours, and shutdown neither
    // blocks on it nor cancels the wait that is the run's own recorded
    // evidence. A collection still in flight here is abandoned exactly like a
    // daemon killed mid-request: its apply claim is already journaled and the
    // next start reconciles it as ambiguous (the modelled path, never a second
    // claim). The driver itself is the only thread whose writes were
    // lease-unsynchronized reconciliation, so joining it is what the lease
    // boundary needs.
    shared.supervisor.signal_stop();
    let mut supervisor = supervisor;
    let joined = supervisor.join();
    shared.log.write(
        "info",
        "daemon.stop",
        &format!("supervision driver joined: {joined}"),
    );
    // Graceful cleanup: drop the lease and unlink the socket so the next
    // start classifies it Absent rather than Stale.
    let state = shared
        .lock_state()
        .map_err(|message| daemon_error("daemon.io", message))?;
    let _ = state.drop_daemon_lease();
    drop(state);
    let _ = std::fs::remove_file(&paths.socket_path);
    result
}

/// Accept connections and handle requests until a fatal accept error.
fn serve_loop(shared: &Arc<Shared>, listener: &UnixListener) -> Result<(), DaemonError> {
    for stream in listener.incoming() {
        if !shared.running.load(Ordering::SeqCst) {
            break;
        }
        match stream {
            Ok(stream) => {
                let shared = Arc::clone(shared);
                std::thread::spawn(move || {
                    if let Err(err) = handle_connection(&shared, stream) {
                        shared
                            .log
                            .write("warn", "connection.error", &err.to_string());
                    }
                });
            }
            Err(err) => {
                return Err(daemon_error("daemon.io", format!("accept failed: {err}")));
            }
        }
    }
    Ok(())
}

/// Serve one client connection: request/response lines until EOF, with an
/// event-stream handoff for `events.subscribe`.
fn handle_connection(shared: &Arc<Shared>, stream: UnixStream) -> Result<(), String> {
    let reader_stream = stream.try_clone().map_err(|err| err.to_string())?;
    let mut reader = BufReader::new(reader_stream);
    let mut writer = stream;
    let mut line = String::new();
    loop {
        line.clear();
        let read = reader
            .read_line(&mut line)
            .map_err(|err| format!("read request: {err}"))?;
        if read == 0 {
            return Ok(()); // peer closed; clean end.
        }
        if line.len() > MAX_REQUEST_BYTES {
            writer
                .write_all(unsafe_response("request exceeds the maximum size").as_bytes())
                .and_then(|()| writer.write_all(b"\n"))
                .map_err(|err| err.to_string())?;
            writer.flush().map_err(|err| err.to_string())?;
            return Err("oversized request line".to_string());
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            continue;
        }
        match handle_request(shared, trimmed) {
            HandleOutcome::Response(response) => {
                writer
                    .write_all(response.as_bytes())
                    .and_then(|()| writer.write_all(b"\n"))
                    .and_then(|()| writer.flush())
                    .map_err(|err| format!("write response: {err}"))?;
            }
            HandleOutcome::Subscribed { response, cursor } => {
                writer
                    .write_all(response.as_bytes())
                    .and_then(|()| writer.write_all(b"\n"))
                    .and_then(|()| writer.flush())
                    .map_err(|err| format!("write response: {err}"))?;
                return serve_event_stream(shared, &mut writer, cursor);
            }
        }
    }
}

/// A schema-valid error response for bytes we could not parse (no id to
/// echo; the fallback id is documented).
fn unsafe_response(code: &str) -> String {
    response_line(FALLBACK_REQUEST_ID, false, None, code, code)
}

/// Parse and validate one request line, then dispatch.
fn handle_request(shared: &Arc<Shared>, line: &str) -> HandleOutcome {
    let parsed = Val::parse_json(line);
    let doc = match parsed {
        Ok(doc) => doc,
        Err(message) => {
            shared.log.write("warn", "request.parse", &message);
            return HandleOutcome::Response(unsafe_response("request does not parse"));
        }
    };
    let verdict = validate_doc(Family::RpcRequest, &doc);
    if !verdict.is_accepted() {
        // The id on an invalid doc is attacker-controlled (bounded only by
        // the request line cap): echo a capped version, never raw bytes.
        let id = bounded(
            doc.get("id")
                .and_then(Val::as_str)
                .unwrap_or(FALLBACK_REQUEST_ID),
            64,
        );
        let class = verdict
            .refusal()
            .map(|refusal| refusal_code(refusal).to_string())
            .unwrap_or_else(|| "refusal.malformed".to_string());
        shared.log.write(
            "warn",
            "request.refused",
            &format!("{class}: {}", verdict.message()),
        );
        return HandleOutcome::Response(response_line(&id, false, None, &class, verdict.message()));
    }
    let id = doc
        .get("id")
        .and_then(Val::as_str)
        .unwrap_or_default()
        .to_string();
    let method = doc
        .get("method")
        .and_then(Val::as_str)
        .unwrap_or_default()
        .to_string();
    let params = match doc.get("params") {
        Some(Val::Obj(_)) => Some(doc.get("params").expect("checked").clone()),
        _ => None,
    };
    let request = Request {
        id,
        method,
        params,
        line: canonical_text(&doc),
    };
    if request.method == "events.subscribe" {
        return subscribe_request(shared, &request);
    }
    HandleOutcome::Response(dispatch(shared, &request))
}

/// Map a schema refusal class onto the stable dotted RPC error code.
fn refusal_code(class: Refusal) -> &'static str {
    match class {
        Refusal::Parse => "refusal.parse",
        Refusal::Schema => "refusal.schema",
        Refusal::Version => "refusal.version",
        Refusal::Malformed => "refusal.malformed",
        Refusal::Noncanonical => "refusal.noncanonical",
    }
}

/// Build one canonical hf-rpc-response/v1 line.
fn response_line(id: &str, ok: bool, result: Option<Val>, code: &str, message: &str) -> String {
    let (result, error) = if ok {
        (result.unwrap_or_else(|| object(vec![])), null())
    } else {
        (
            null(),
            object(vec![
                ("code", string(code)),
                ("message", string(message)),
                ("retryable", bool_(false)),
            ]),
        )
    };
    canonical_text(&object(vec![
        ("schema", string("hf-rpc-response/v1")),
        ("id", string(id)),
        ("ok", bool_(ok)),
        ("result", result),
        ("error", error),
    ]))
}

fn ok_response(id: &str, result: Val) -> String {
    response_line(id, true, Some(result), "", "")
}

fn err_response(id: &str, code: &str, message: impl Into<String>) -> String {
    response_line(id, false, None, code, &message.into())
}

// ---------------------------------------------------------------------------
// Request dispatch (closed method set; unknown methods refused typed)
// ---------------------------------------------------------------------------

fn dispatch(shared: &Arc<Shared>, request: &Request) -> String {
    match request.method.as_str() {
        "capabilities" => method_capabilities(request),
        "doctor" => method_doctor(shared, request),
        "status" => method_status(shared, request),
        "state.epoch" => method_state_epoch(shared, request),
        "queue.submit" => method_queue_submit(shared, request),
        "queue.status" => method_queue_status(shared, request),
        "queue.redrive" => method_queue_redrive(shared, request),
        "run.pause" => method_run_pause(shared, request),
        "run.resume" => method_run_resume(shared, request),
        "run.retry" => method_run_retry(shared, request),
        "run.reevaluate" => method_run_reevaluate(shared, request),
        "run.release" => method_run_release(shared, request),
        "run.retire-lane" => method_run_retire_lane(shared, request),
        "run.resolve" => method_run_resolve(shared, request),
        "run.dispatch" => method_run_dispatch(shared, request),
        "run.status" => method_run_status(shared, request),
        "supervision.status" => method_supervision_status(shared, request),
        "supervision.arm" => method_supervision_arm(shared, request),
        "schedules.list" => method_schedules(shared, request),
        "schedules.create" => method_schedule_create(shared, request),
        "schedules.pause" => method_schedule_pause(shared, request),
        "schedules.resume" => method_schedule_resume(shared, request),
        "schedules.delete" => method_schedule_delete(shared, request),
        "schedules.evaluate" => method_schedule_evaluate(shared, request),
        "lane.replacement.request" => method_lane_replacement_request(shared, request),
        "lane.replacement.advance" => method_lane_replacement_advance(shared, request),
        "lane.replacement.hold" => method_lane_replacement_hold(shared, request),
        "lane.replacement.cancel" => method_lane_replacement_cancel(shared, request),
        "lane.replacement.status" => method_lane_replacement_status(shared, request),
        "lane.checkpoint.create" => method_lane_checkpoint_create(shared, request),
        "lane.checkpoint.status" => method_lane_checkpoint_status(shared, request),
        "lane.retire" => method_lane_retire(shared, request),
        "lane.start" => method_lane_start(shared, request),
        "lane.adopt" => method_lane_adopt(shared, request),
        "lane.successor.consume" => method_lane_successor_consume(shared, request),
        "grants.issue" => method_grants_issue(shared, request),
        "grants.list" => method_grants_list(shared, request),
        "journal.tail" => method_journal_tail(shared, request),
        "grants.revoke" => method_grants_revoke(shared, request),
        "backup.create" => method_backup_create(shared, request),
        "restore.begin" => method_restore_begin(shared, request),
        "plan" => method_plan(shared, request),
        "apply" => method_apply(shared, request),
        other => {
            shared.log.write("warn", "method.unknown", other);
            err_response(
                &request.id,
                "refusal.method",
                format!("unknown method {other:?}"),
            )
        }
    }
}

fn method_capabilities(request: &Request) -> String {
    let methods: Vec<Val> = RPC_METHODS.iter().map(|m| string(m)).collect();
    let result = object(vec![
        ("protocol", string("hf-rpc/v1")),
        (
            "schema_families",
            Val::Arr(vec![
                string("hf-rpc-request/v1"),
                string("hf-rpc-response/v1"),
                string("hf-event/v1"),
                string("hf-audit/v1"),
            ]),
        ),
        ("methods", Val::Arr(methods)),
        ("max_request_bytes", integer(MAX_REQUEST_BYTES as i64)),
        ("event_queue_cap", integer(SUBSCRIBER_QUEUE_CAP as i64)),
    ]);
    ok_response(&request.id, result)
}

fn method_doctor(shared: &Arc<Shared>, request: &Request) -> String {
    match summary_val(shared) {
        Ok(summary) => ok_response(
            &request.id,
            object(vec![
                ("state_writable", bool_(!summary.poisoned)),
                ("schema_version", integer(summary.schema_version)),
                ("epoch", integer(summary.epoch)),
                ("journal_seq", integer(summary.audit_seq)),
                ("event_seq", integer(summary.event_seq)),
                ("pending_claims", integer(summary.pending_claims)),
                ("active_grants", integer(summary.active_grants)),
            ]),
        ),
        Err(err) => err_response(&request.id, err.code, err.message),
    }
}

fn summary_val(shared: &Arc<Shared>) -> Result<StateSummary, StateError> {
    let state = shared.lock_state().map_err(|message| StateError {
        code: "state.unavailable",
        message,
    })?;
    state.status_summary()
}

fn method_status(shared: &Arc<Shared>, request: &Request) -> String {
    let summary = match summary_val(shared) {
        Ok(summary) => summary,
        Err(err) => return err_response(&request.id, err.code, err.message),
    };
    // Issue #270: the supervision driver's OWN pass progress. The daemon keeps
    // answering while a pass is stuck (that is exactly the shape the issue
    // measured: every run's tick frozen, `daemon status` still reading
    // healthy), so this block — and the `freshness` below it — is what says the
    // supervision plane is NOT advancing instead of a bare `fresh`.
    let supervision = shared.supervisor.pass_doc(time::unix_now());
    let stalled = supervision.get("state").and_then(Val::as_str) == Some("stalled");
    let result = object(vec![
        (
            "daemon",
            object(vec![
                ("pid", integer(shared.pid as i64)),
                ("started_at", string(&shared.started_at)),
                ("version", string(crate::PACKAGE_VERSION)),
            ]),
        ),
        (
            "state",
            object(vec![
                ("epoch", integer(summary.epoch)),
                ("journal_seq", integer(summary.audit_seq)),
                ("event_seq", integer(summary.event_seq)),
                ("schema_version", integer(summary.schema_version)),
                ("active_grants", integer(summary.active_grants)),
                ("pending_claims", integer(summary.pending_claims)),
                ("poisoned", bool_(summary.poisoned)),
            ]),
        ),
        ("supervision", supervision),
        // The pass is the fleet's single driver: a pass whose wait was
        // abandoned and has not resolved reads `stalled`, never `fresh`.
        (
            "freshness",
            string(if stalled { "stalled" } else { "fresh" }),
        ),
    ]);
    ok_response(&request.id, result)
}

fn method_state_epoch(shared: &Arc<Shared>, request: &Request) -> String {
    let state = shared
        .lock_state()
        .map_err(|message| err_response(&request.id, "state.unavailable", message));
    match state {
        Ok(state) => match state.epoch_doc() {
            Ok(doc) => ok_response(&request.id, object(vec![("epoch", doc)])),
            Err(err) => err_response(&request.id, err.code, err.message),
        },
        Err(response) => response,
    }
}

// ---------------------------------------------------------------------------
// Control-plane mutations (issue #8): `plan` render + `apply` dispatch
// ---------------------------------------------------------------------------

/// `plan`: render a deterministic `hf-plan/v1` document for one repository
/// issue from typed params (the same offline plan family the read-only CLI
/// renders, validated and digest-bound here so `apply` can bind it).
fn method_plan(_shared: &Arc<Shared>, request: &Request) -> String {
    let params = match &request.params {
        Some(params) => params,
        None => {
            return err_response(
                &request.id,
                "refusal.malformed",
                "plan requires params: repository, issue.number, issue.revision",
            );
        }
    };
    let repository = match params.get("repository").and_then(Val::as_str) {
        Some(value) if crate::formats::is_repository_identity(value) => value.to_string(),
        _ => {
            return err_response(
                &request.id,
                "refusal.malformed",
                "plan requires an owner/name repository identity",
            );
        }
    };
    let (owner, name) = repository.split_once('/').expect("validated identity");
    let issue_number = match params
        .get("issue")
        .and_then(|issue| issue.get("number"))
        .and_then(Val::as_int)
    {
        Some(number) if number > 0 => number,
        _ => {
            return err_response(
                &request.id,
                "refusal.malformed",
                "plan requires a positive issue.number",
            );
        }
    };
    let revision = match params
        .get("issue")
        .and_then(|issue| issue.get("revision"))
        .and_then(Val::as_str)
    {
        Some(value) if crate::formats::is_hex40(value) => value.to_string(),
        _ => {
            return err_response(
                &request.id,
                "refusal.malformed",
                "plan requires an exact 40-hex issue.revision",
            );
        }
    };
    let branch = params
        .get("branch")
        .and_then(Val::as_str)
        .unwrap_or("staging")
        .to_string();
    // Repository origin is not part of a rendered plan document; the
    // synthesized value is never persisted or displayed (identity only).
    let repo = crate::config::Repository {
        key: name.to_string(),
        owner: owner.to_string(),
        name: name.to_string(),
        origin: format!("https://example.invalid/{owner}/{name}"),
        branch: Some(branch),
        enabled: true,
    };
    let input = crate::plan::PlanInput {
        repository: &repo,
        issue_number: issue_number as u64,
        revision: revision.clone(),
        workflow: None,
    };
    match crate::plan::render_plan(&input) {
        Ok(rendered) => ok_response(
            &request.id,
            object(vec![
                ("plan", rendered.doc),
                ("digest", string(&rendered.digest)),
                ("plan_id", string(&rendered.plan_id)),
                ("workflow_id", string(&rendered.workflow_id)),
                ("workflow_hash", string(&rendered.workflow_hash)),
            ]),
        ),
        Err(refusal) => err_response(
            &request.id,
            "refusal.plan.unavailable",
            format!("cannot render plan: {:?}", refusal),
        ),
    }
}

/// Typed apply params (parsed once, then validated under the state lock).
struct ApplyParams {
    /// Plan document (schema-validated and digest-bound by the caller).
    plan: Val,
    /// Step id within the plan.
    step: String,
    /// Route grant id.
    grant_id: String,
    /// Workflow instance id.
    instance_id: String,
    /// Fresh observations (issue revision, policy hash, optional heads).
    issue_revision: String,
    policy_hash: String,
    /// Exact heads observed before the effect (merge gate bindings).
    feature_head: Option<String>,
    integration_base: Option<String>,
    /// Topology: integration branch + production branches + lane paths.
    integration_branch: String,
    production_branches: Vec<String>,
    /// The topology-declared integration publish route (issue #219): the
    /// closed `push` | `pull_request` set, defaulted to `push` when the
    /// topology declares none.
    integration_publish: String,
    worktrees_root: std::path::PathBuf,
    integration_repo: std::path::PathBuf,
    /// Daemon-owned archive/salvage root (optional; issue #9 AC7).
    archive_root: Option<std::path::PathBuf>,
    /// Production/hotfix/first-write flag bundle (typed, from the caller's
    /// interactive session — never from recurring automation).
    interactive: bool,
    digest_confirmed: bool,
    scheduled: bool,
    production_confirmation: Option<String>,
    target_scope: Option<String>,
    /// Fan-out admission bundle (issue #9 AC1): concurrency caps, the
    /// attested same-harness lane count, and the fresh host-resource proof.
    admission: Option<AdmissionParams>,
}

/// Typed `flags.admission` bundle for fan-out steps (harness_start/prompt).
#[derive(Clone, Debug, PartialEq, Eq)]
struct AdmissionParams {
    /// Global concurrency cap declared for this fan-out (>= 0).
    global_cap: Option<i64>,
    /// Per-repository concurrency cap declared for this fan-out (>= 0).
    repository_cap: Option<i64>,
    /// Per-harness concurrency cap declared for this fan-out (>= 0).
    harness_cap: Option<i64>,
    /// Client-attested count of active lanes on the same harness key
    /// (>= 0). Harness occupancy is not durable daemon state, so it is
    /// attested like the apply `observed` params (same trust boundary).
    harness_lanes: Option<i64>,
    /// Unix seconds when the host-resource measurement was taken.
    host_proof_at: Option<i64>,
    /// Free bytes the host exposed at the run's lane root when the proof was
    /// measured (issue #231), when the presenter observed them: the fan-out
    /// gate refuses below the documented floor.
    host_proof_bytes: Option<u64>,
}

fn apply_params(request: &Request) -> Result<ApplyParams, (String, String)> {
    let params = request.params.as_ref().ok_or_else(|| {
        (
            "refusal.malformed".to_string(),
            "apply requires params".to_string(),
        )
    })?;
    let get_str = |key: &str| -> Result<String, (String, String)> {
        params
            .get(key)
            .and_then(Val::as_str)
            .filter(|text| !text.is_empty())
            .map(str::to_string)
            .ok_or_else(|| {
                (
                    "refusal.malformed".to_string(),
                    format!("apply requires params.{key}"),
                )
            })
    };
    let plan = match params.get("plan") {
        Some(Val::Obj(_)) => params.get("plan").expect("checked").clone(),
        _ => {
            return Err((
                "refusal.malformed".to_string(),
                "apply requires params.plan (hf-plan/v1 object)".to_string(),
            ));
        }
    };
    let step = get_str("step")?;
    let grant_id = get_str("grant_id")?;
    if !crate::formats::is_grant_id(&grant_id) {
        return Err((
            "refusal.malformed".to_string(),
            "grant_id must be a gr_ id".to_string(),
        ));
    }
    let instance_id = get_str("instance_id")?;
    // The observed field must be an object when present.
    let observed = match params.get("observed") {
        Some(Val::Obj(_)) => params.get("observed").expect("checked"),
        None | Some(Val::Null) => {
            return Err((
                "refusal.malformed".to_string(),
                "apply requires params.observed with fresh issue_revision/policy_hash".to_string(),
            ));
        }
        Some(_) => {
            return Err((
                "refusal.malformed".to_string(),
                "apply params.observed must be an object".to_string(),
            ));
        }
    };
    let issue_revision = observed
        .get("issue_revision")
        .and_then(Val::as_str)
        .filter(|text| crate::formats::is_hex40(text))
        .map(str::to_string)
        .ok_or_else(|| {
            (
                "refusal.malformed".to_string(),
                "observed.issue_revision must be 40-hex".to_string(),
            )
        })?;
    let policy_hash = observed
        .get("policy_hash")
        .and_then(Val::as_str)
        .filter(|text| crate::formats::is_hex64(text))
        .map(str::to_string)
        .ok_or_else(|| {
            (
                "refusal.malformed".to_string(),
                "observed.policy_hash must be 64-hex".to_string(),
            )
        })?;
    let hex40 = |key: &str| -> Result<Option<String>, (String, String)> {
        match observed.get(key).and_then(Val::as_str) {
            Some(text) if crate::formats::is_hex40(text) => Ok(Some(text.to_string())),
            Some(_) => Err((
                "refusal.malformed".to_string(),
                format!("observed.{key} must be 40-hex when present"),
            )),
            None => Ok(None),
        }
    };
    let feature_head = hex40("feature_head")?;
    let integration_base = hex40("integration_base")?;
    let topology = match params.get("topology") {
        Some(Val::Obj(_)) => params.get("topology").expect("checked"),
        _ => {
            return Err((
                "refusal.malformed".to_string(),
                "apply requires params.topology (integration_branch, lane paths)".to_string(),
            ));
        }
    };
    let integration_branch = topology
        .get("integration_branch")
        .and_then(Val::as_str)
        .map(str::to_string)
        .ok_or_else(|| {
            (
                "refusal.malformed".to_string(),
                "topology.integration_branch is required".to_string(),
            )
        })?;
    let production_branches = match topology.get("production_branches") {
        None | Some(Val::Null) => Vec::new(),
        Some(Val::Arr(items)) => items
            .iter()
            .filter_map(Val::as_str)
            .map(str::to_string)
            .collect(),
        Some(_) => {
            return Err((
                "refusal.malformed".to_string(),
                "topology.production_branches must be an array".to_string(),
            ));
        }
    };
    // Issue #219: the integration PUBLISH route is a closed, DECLARED input.
    // It is never inferred from a refused push: an engine that fell back
    // silently would hide the refusal from the operator and violate the
    // plan-policy discipline (issue #196). Absent means the documented
    // default (`push`), which is every topology written before this field.
    let integration_publish = match topology.get("integration_publish") {
        None | Some(Val::Null) => crate::mutation::INTEGRATION_PUBLISH_DEFAULT.to_string(),
        Some(value)
            if value
                .as_str()
                .is_some_and(crate::mutation::is_publish_route) =>
        {
            value.as_str().expect("checked").to_string()
        }
        Some(_) => {
            return Err((
                "refusal.malformed".to_string(),
                format!(
                    "topology.integration_publish must be one of {:?}",
                    crate::mutation::INTEGRATION_PUBLISH_ROUTES
                ),
            ));
        }
    };
    let absolute = |key: &str| -> Result<std::path::PathBuf, (String, String)> {
        let text = topology.get(key).and_then(Val::as_str).ok_or_else(|| {
            (
                "refusal.malformed".to_string(),
                format!("topology.{key} is required"),
            )
        })?;
        let path = std::path::PathBuf::from(text);
        if !path.is_absolute() {
            return Err((
                "refusal.malformed".to_string(),
                format!("topology.{key} must be an absolute path"),
            ));
        }
        Ok(path)
    };
    let worktrees_root = absolute("worktrees_root")?;
    let integration_repo = absolute("integration_repo")?;
    // archive_root is optional but must be absolute when present.
    let archive_root = match topology.get("archive_root") {
        None | Some(Val::Null) => None,
        Some(Val::Str(_)) => Some(absolute("archive_root")?),
        Some(_) => {
            return Err((
                "refusal.malformed".to_string(),
                "topology.archive_root must be a string when present".to_string(),
            ));
        }
    };
    let flags = match params.get("flags") {
        None | Some(Val::Null) => None,
        Some(Val::Obj(_)) => params.get("flags"),
        Some(_) => {
            return Err((
                "refusal.malformed".to_string(),
                "apply params.flags must be an object".to_string(),
            ));
        }
    };
    let flag = |key: &str| -> bool {
        flags
            .and_then(|f| f.get(key))
            .and_then(Val::as_bool)
            .unwrap_or(false)
    };
    // Fan-out admission bundle (issue #9 AC1): flags.admission object with
    // caps, an attested same-harness lane count, and host-resource proof.
    // Optional for non-fan-out steps; REQUIRED for harness_start/prompt
    // (the gate refuses fan-out without it).
    let non_negative = |value: Option<&Val>| -> Option<i64> {
        match value {
            Some(Val::Int(seconds)) if *seconds >= 0 => Some(*seconds),
            _ => None,
        }
    };
    let admission = match flags.and_then(|f| f.get("admission")) {
        None | Some(Val::Null) => None,
        Some(Val::Obj(_)) => {
            let admission = flags.and_then(|f| f.get("admission")).expect("checked");
            let caps = admission
                .get("caps")
                .filter(|caps| matches!(caps, Val::Obj(_)));
            let int_field =
                |key: &str| -> Option<i64> { caps.and_then(|c| non_negative(c.get(key))) };
            let host_proof_at = admission
                .get("host_proof")
                .and_then(|proof| proof.get("measured_at"))
                .and_then(Val::as_str)
                .and_then(crate::time::unix_from_rfc3339);
            // Issue #231: the free-byte observation the presenter recorded
            // with the proof, when it measured one (the fan-out gate refuses
            // below the documented floor).
            let host_proof_bytes = admission
                .get("host_proof")
                .and_then(|proof| proof.get("available_bytes"))
                .and_then(Val::as_int)
                .and_then(|bytes| u64::try_from(bytes).ok());
            Some(AdmissionParams {
                global_cap: int_field("global"),
                repository_cap: int_field("repository"),
                harness_cap: int_field("harness"),
                harness_lanes: non_negative(admission.get("harness_lanes")),
                host_proof_at,
                host_proof_bytes,
            })
        }
        Some(_) => {
            return Err((
                "refusal.malformed".to_string(),
                "apply flags.admission must be an object".to_string(),
            ));
        }
    };
    Ok(ApplyParams {
        plan,
        step,
        grant_id,
        instance_id,
        issue_revision,
        policy_hash,
        feature_head,
        integration_base,
        integration_branch,
        production_branches,
        integration_publish,
        worktrees_root,
        integration_repo,
        archive_root,
        interactive: flag("interactive"),
        digest_confirmed: flag("digest_confirmed"),
        scheduled: flag("scheduled"),
        production_confirmation: flags
            .and_then(|f| f.get("production_confirmation"))
            .and_then(Val::as_str)
            .map(str::to_string),
        target_scope: flags
            .and_then(|f| f.get("target_scope"))
            .and_then(Val::as_str)
            .map(str::to_string),
        admission,
    })
}

/// The role binding and the bound session one harness step runs under
/// (issue #92 F2), resolved from DURABLE state only.
#[derive(Clone, Debug)]
struct RunBinding {
    /// The run's committed role configuration, when the run has one.
    role: Option<crate::config::ProfileBinding>,
    /// The session identity the run bound (`harness_start`), when it has one.
    session: Option<crate::adapters::SessionHandle>,
}

/// Resolve the role binding + session of a harness step of one run (issue
/// #92 F2). A run without a committed submission keeps `(None, None)`: its
/// presented plan declares its own profile/session explicitly. A queue run
/// resolves BOTH from durable state — the reviewed `hf-profile-binding/v1`
/// document the submission bound, and the session identity derived once from
/// the run — and a `prompt` whose `harness_start` step has no recorded
/// succeeded dispatch is refused (`refusal.session.unbound`): the prompt
/// continues the session start bound and never binds one itself.
fn resolve_run_binding(
    shared: &Arc<Shared>,
    instance_id: &str,
    kind: &str,
    presented: Option<&crate::config::ProfileBinding>,
) -> Result<RunBinding, (String, String)> {
    if !matches!(
        kind,
        "harness_start" | "prompt" | "collect_outcome" | "cleanup" | "review_evidence"
    ) {
        return Ok(RunBinding {
            role: None,
            session: None,
        });
    }
    let state = match shared.lock_state() {
        Ok(state) => state,
        Err(message) => return Err(("state.unavailable".to_string(), message)),
    };
    // Issue #193: a self-dispatching review step runs the run's own reviewer
    // in the run's lane, so it needs the run's bound implementer session —
    // and nothing else: the reviewer's role binding is the plan's own
    // registry-resolved reviewer leg, never the run's implementer role.
    if matches!(kind, "cleanup" | "collect_outcome" | "review_evidence") {
        let bound = state
            .run_bound_start_step(instance_id)
            .map_err(|err| (err.code.to_string(), err.message))?;
        let session = if bound.is_some() {
            Some(
                crate::mutation::run_session_handle(instance_id).map_err(|outcome| {
                    (
                        crate::mutation::code::SESSION_UNBOUND.to_string(),
                        outcome.message.unwrap_or_default(),
                    )
                })?,
            )
        } else {
            None
        };
        return Ok(RunBinding {
            role: None,
            session,
        });
    }
    let identity = state
        .run_role_identity(instance_id)
        .map_err(|err| (err.code.to_string(), err.message))?;
    let Some((key, revision)) = identity else {
        // A run without a committed submission has no reviewed role
        // configuration: its presented plan declares its own binding, and
        // there is no default profile.
        return Ok(RunBinding {
            role: None,
            session: None,
        });
    };
    // The run's committed role configuration is the ONLY binding its harness
    // steps run under. The full reviewed binding document is PRESENTED and
    // verified here against the durable revision the approval bound: a
    // tampered or foreign binding refuses, an absent one refuses (there is
    // no default profile and none is inferred).
    let Some(binding) = presented else {
        return Err((
            crate::config::CODE_PROFILE_BINDING.to_string(),
            format!(
                "the harness step of run {instance_id} presents no reviewed role configuration \
                 (params.profile); the run's role {key:?} (revision {revision}) is never defaulted"
            ),
        ));
    };
    if binding.key != key || binding.revision != revision {
        return Err((
            crate::config::CODE_PROFILE_REVISION.to_string(),
            format!(
                "the presented role configuration ({}, revision {}) is not the one run \
                 {instance_id} was approved under ({key}, revision {revision})",
                binding.key, binding.revision
            ),
        ));
    }
    let role = binding.clone();
    let role = Some(role);
    let derived = || {
        crate::mutation::run_session_handle(instance_id).map_err(|outcome| {
            (
                crate::mutation::code::SESSION_UNBOUND.to_string(),
                outcome
                    .message
                    .unwrap_or_else(|| "the run session could not be derived".to_string()),
            )
        })
    };
    let session = match kind {
        "harness_start" => Some(derived()?),
        _ => {
            let bound = state
                .run_bound_start_step(instance_id)
                .map_err(|err| (err.code.to_string(), err.message))?;
            match bound {
                Some(_) => Some(derived()?),
                None => {
                    return Err((
                        crate::mutation::code::SESSION_UNBOUND.to_string(),
                        format!(
                            "run {instance_id} has no recorded harness_start bind; a prompt \
                             continues the session its harness_start bound and never binds one \
                             itself"
                        ),
                    ));
                }
            }
        }
    };
    Ok(RunBinding { role, session })
}

/// Issue #243: a fan-out admission refusal about the host-resource proof names
/// the failing PRECONDITION and the reachable REMEDY, never a bare code.
///
/// Only the two proof codes carry a remedy clause; every other admission
/// refusal (caps, occupancy, overlap) keeps the gate's own message verbatim —
/// nothing else has a renewal path an operator has to be told about. The
/// remedy names BOTH renewal paths for the exact run and step the gate is
/// deciding for — the run's own bounded check re-evaluation, which re-measures
/// the lane root at dispatch time when the step is its own terminal-success
/// producer, and the operator's explicit attestation, which is the only path
/// for every other step and for a proof that was never recorded at all — so an
/// operator is never left with a bare code and no reachable action.
fn fanout_refusal_message(code: &str, message: &str, run: &str, step: &str) -> String {
    let remedy = match code {
        crate::lifecycle::code::PROOF_STALE => format!(
            "; renew with `canter run dispatch --run {run} --step {step} --operator IDENTITY \
             --reason TEXT` (the daemon measures the host for the recorded operator and binds the \
             measurement), or `canter run reevaluate --run {run} --step {step} --operator \
             IDENTITY --reason TEXT` for the run's own check producer; `canter run status --run \
             {run}` names the ONE control that applies"
        ),
        crate::lifecycle::code::PROOF_MISSING => format!(
            "; produce one with `canter run dispatch --run {run} --step {step} --operator IDENTITY \
             --reason TEXT` when the run recorded an admission to bind it into, otherwise present \
             `--admission FILE`; a measurement is never invented for a run that recorded none"
        ),
        _ => return message.to_string(),
    };
    format!("{message}{remedy}")
}

/// `apply`: bind the plan digest, revalidate every binding freshly under
/// the state lock, journal the intent, execute the typed effect, and
/// resolve with a typed outcome + exact read-back (issue #8 AC1/AC2/AC4).
/// Issue #9 AC1 fan-out admission gate (harness_start/prompt): refuse
/// before any intent is journaled when
/// - the caller omitted `flags.admission` or its host-resource proof
///   (`refusal.admission.proof_missing`) or the proof is stale
///   (`refusal.admission.proof_stale`) — unknown/stale measurements refuse;
/// - any applicable cap is missing (`refusal.admission.cap_missing`);
/// - any declared cap is exhausted (cap_global/cap_repository/cap_harness —
///   global and per-repository counts come from durable instance rows, the
///   per-harness count is client-attested like the apply `observed` params
///   because harness occupancy is not durable daemon state);
/// - the lane's declared scope overlaps a concurrent lane's scope in the
///   same repository (`refusal.admission.monorepo_overlap`).
fn admission_gate(
    shared: &Arc<Shared>,
    request: &Request,
    plan: &crate::mutation::PlanBindings,
    parsed: &ApplyParams,
    params: Option<&Val>,
) -> Result<(), String> {
    let Some(admission) = &parsed.admission else {
        return Err(err_response(
            &request.id,
            crate::lifecycle::code::PROOF_MISSING,
            fanout_refusal_message(
                crate::lifecycle::code::PROOF_MISSING,
                "fan-out requires flags.admission with caps and a fresh host-resource proof (unknown measurements refuse new work)",
                &parsed.instance_id,
                &parsed.step,
            ),
        ));
    };
    let caps = match (
        admission.global_cap,
        admission.repository_cap,
        admission.harness_cap,
    ) {
        (Some(global), Some(repository), Some(harness)) => crate::lifecycle::ConcurrencyCaps {
            global: usize::try_from(global).unwrap_or(usize::MAX),
            per_repository: usize::try_from(repository).unwrap_or(usize::MAX),
            per_harness: usize::try_from(harness).unwrap_or(usize::MAX),
        },
        _ => {
            return Err(err_response(
                &request.id,
                crate::lifecycle::code::CAP_MISSING,
                "fan-out requires flags.admission.caps {global, repository, harness}",
            ));
        }
    };
    // Per-harness axis: the attested active-lane count on this harness key.
    let harness_lanes = admission.harness_lanes.unwrap_or(0);
    let harness_key = params
        .and_then(|p| p.get("harness_key"))
        .and_then(Val::as_str)
        .unwrap_or("");
    if usize::try_from(harness_lanes).unwrap_or(usize::MAX) >= caps.per_harness {
        return Err(err_response(
            &request.id,
            crate::lifecycle::code::CAP_HARNESS,
            format!(
                "the per-harness concurrency cap ({}) is reached ({} attested lanes on harness {:?}); refuse fan-out",
                caps.per_harness, harness_lanes, harness_key
            ),
        ));
    }
    let harness_key = harness_key.to_string();
    // State-derived lanes + the proposed footprint.
    let state = match shared.lock_state() {
        Ok(state) => state,
        Err(message) => return Err(err_response(&request.id, "state.unavailable", message)),
    };
    let instance = match state.instance_by_id(&parsed.instance_id) {
        Ok(Some(instance)) => instance,
        Ok(None) => {
            return Err(err_response(
                &request.id,
                "refusal.instance.state",
                format!("no instance {} exists", parsed.instance_id),
            ));
        }
        Err(err) => return Err(err_response(&request.id, err.code, err.message)),
    };
    let proposed = crate::lifecycle::LaneFootprint {
        repository: plan.repository.clone(),
        harness_key,
        scope: instance.scope.clone(),
        issue_number: instance.issue_number,
        identity: instance.instance_id.clone(),
    };
    // Issue #285: a run that is terminal by outcome (a diagnosed step whose
    // bounded-retry budget is spent, with nothing held) can never be
    // dispatched again, so it is not an active lane here either — the SAME
    // exclusion the queue admission derives its counted set with.
    let terminal = state
        .retry_exhausted_run_ids()
        .map_err(|err| err_response(&request.id, err.code, err.message))?;
    let mut running = Vec::new();
    for row in state
        .list_instances()
        .map_err(|err| err_response(&request.id, err.code, err.message))?
    {
        if row.instance_id == parsed.instance_id {
            continue;
        }
        if terminal.contains(&row.instance_id) {
            continue;
        }
        if matches!(
            row.status.as_str(),
            "new" | "running" | "human_queue" | "blocked"
        ) {
            running.push(crate::lifecycle::LaneFootprint {
                repository: row.repository.clone(),
                harness_key: String::new(),
                scope: row.scope.clone(),
                // The durable identity of the holding lane: a cap refusal
                // names the run and issue that occupy the slot (#236).
                issue_number: row.issue_number,
                identity: row.instance_id.clone(),
            });
        }
    }
    drop(state);
    // Issue #231: the proof the gate decides carries the free-byte
    // observation the presenter recorded with it (when it measured one).
    let host_proof =
        admission
            .host_proof_at
            .map(|measured_at_unix| match admission.host_proof_bytes {
                Some(available_bytes) => {
                    crate::lifecycle::HostProof::measured(measured_at_unix, available_bytes)
                }
                None => crate::lifecycle::HostProof::at(measured_at_unix),
            });
    crate::lifecycle::check_fanout_admission(
        &proposed,
        &running,
        &caps,
        host_proof,
        time::unix_now(),
    )
    .map_err(|err| {
        err_response(
            &request.id,
            err.code,
            fanout_refusal_message(err.code, &err.message, &parsed.instance_id, &parsed.step),
        )
    })
}

/// The daemon-side dispatch hook of the supervision driver (issue #92 F4).
///
/// It holds a `Weak`-free `OnceLock` of the shared daemon handle because the
/// driver is started before `Shared` exists; every dispatch runs through
/// [`method_apply`], so capability, grant, admission, ownership, journal and
/// idempotency gates all re-derive exactly as they do for a client request.
#[derive(Clone)]
struct DaemonDispatch {
    shared: std::sync::OnceLock<Arc<Shared>>,
    /// The refused-continuation ladder per run (item 4a of issue #144).
    refusals: Arc<Mutex<std::collections::BTreeMap<String, RefusedDispatch>>>,
    /// Reserve before spawning; the durable claim then fences later ticks.
    collecting: Arc<Mutex<Collections>>,
}

/// The in-flight collection reservations (issue #170 N5): the `(run, step)`
/// pairs whose collection currently holds the daemon's in-memory slot.
///
/// Keyed by the PAIR, not by the run: the slot guards ONE dispatch of ONE
/// collection step, so a spine with two collection steps in the same run never
/// has the second silently answered `awaiting <the other step>`.
#[derive(Default)]
struct Collections {
    in_flight: std::collections::BTreeSet<(String, String)>,
}

impl Collections {
    /// Reserve `(run, step)`: `Err(step)` when THIS step already holds the
    /// slot (the duplicate dispatch the reservation exists for), `Ok(())`
    /// otherwise — including for a DIFFERENT step of the same run.
    fn begin(&mut self, instance_id: &str, step_id: &str) -> Result<(), String> {
        let key = (instance_id.to_string(), step_id.to_string());
        if self.in_flight.insert(key) {
            Ok(())
        } else {
            Err(step_id.to_string())
        }
    }

    /// Release the slot of one finished collection.
    fn finish(&mut self, instance_id: &str, step_id: &str) {
        self.in_flight
            .remove(&(instance_id.to_string(), step_id.to_string()));
    }
}

/// One run's refused-continuation ladder (item 4a of issue #144): the step
/// whose supervised dispatch keeps being refused, how many times in a row,
/// and when the next attempt is allowed.
struct RefusedDispatch {
    step: String,
    streak: u32,
    next_attempt_unix: i64,
}

/// Ceiling of the refused-dispatch back-off wait (item 4a of issue #144): the
/// ladder doubles from the run's own check interval up to this bound, so a
/// run nothing can progress is re-attempted a bounded number of times per
/// hour instead of once per tick. The run is never abandoned — the ladder is
/// cleared by any dispatch that succeeds, so an operator repair still
/// recovers it.
const DISPATCH_BACKOFF_MAX_SECS: i64 = 900;

impl DaemonDispatch {
    /// How long this run's next continuation attempt must wait, and the
    /// streak that produced the wait: `None` when the ladder allows an
    /// attempt now.
    fn back_off_wait(&self, instance_id: &str, step: &str, now_unix: i64) -> Option<(i64, u32)> {
        let ladders = self.refusals.lock().ok()?;
        let entry = ladders.get(instance_id)?;
        if entry.step != step || now_unix >= entry.next_attempt_unix {
            return None;
        }
        Some((entry.next_attempt_unix - now_unix, entry.streak))
    }

    /// Record one refused continuation dispatch and move the ladder one step:
    /// the wait doubles from the run's own check interval, capped. A refusal
    /// of a DIFFERENT step starts a fresh ladder (the frontier moved).
    fn note_refused(&self, instance_id: &str, step: &str, base_secs: i64, now_unix: i64) {
        let Ok(mut ladders) = self.refusals.lock() else {
            return;
        };
        let streak = match ladders.get(instance_id) {
            Some(entry) if entry.step == step => entry.streak.saturating_add(1),
            _ => 1,
        };
        let shift = streak.saturating_sub(1).min(16);
        let wait = base_secs
            .max(1)
            .saturating_mul(1i64 << shift)
            .min(DISPATCH_BACKOFF_MAX_SECS);
        ladders.insert(
            instance_id.to_string(),
            RefusedDispatch {
                step: step.to_string(),
                streak,
                next_attempt_unix: now_unix + wait,
            },
        );
    }

    /// A dispatch that reached the engine clears the run's ladder: the run
    /// progressed, so the next refusal starts over.
    fn note_dispatched(&self, instance_id: &str) {
        if let Ok(mut ladders) = self.refusals.lock() {
            ladders.remove(instance_id);
        }
    }
}

/// The run's own supervision check interval: the base of the refused-dispatch
/// ladder (item 4a of issue #144). A run whose supervision row cannot be read
/// uses the daemon default rather than blocking the attempt.
fn supervision_interval_secs(shared: &Arc<Shared>, instance_id: &str) -> i64 {
    let Ok(state) = shared.lock_state() else {
        return crate::supervision::DEFAULT_CHECK_INTERVAL_SECS;
    };
    match state.supervision_by_id(instance_id) {
        Ok(Some(row)) => row.check_interval_secs,
        _ => crate::supervision::DEFAULT_CHECK_INTERVAL_SECS,
    }
}

/// The identity recorded when the DRIVER drives a run's own recovery control
/// (issue #243): the act is the run's own armed supervision's, so the journal
/// names it exactly where an operator identity is named — never a fabricated
/// operator, and never a reason that carries a check status or a verdict.
const SUPERVISION_OPERATOR: &str = "supervision";

impl crate::supervision::SupervisedDispatch for DaemonDispatch {
    fn dispatch(&self, intent: &crate::supervision::DispatchIntent) -> Result<String, String> {
        self.dispatch_at(intent, time::unix_now())
    }
}

impl DaemonDispatch {
    fn dispatch_at(
        &self,
        intent: &crate::supervision::DispatchIntent,
        now_unix: i64,
    ) -> Result<String, String> {
        let Some(shared) = self.shared.get() else {
            return Err("the daemon dispatch hook is not wired yet".to_string());
        };
        // Issue #144 (4a): a continuation the engine keeps refusing is not
        // re-attempted on every check. `run-604cf9439372a5e5` re-attempted the
        // same refused `p3` dispatch every 60 s for over an hour; the ladder
        // paces the attempts instead of the tick, and the run's status still
        // names the engine's own refusal (nothing new is recorded here).
        if let Some((wait, streak)) =
            self.back_off_wait(&intent.instance_id, &intent.step_id, now_unix)
        {
            shared.log.write(
                "warn",
                "supervision.dispatch_backoff",
                &format!(
                    "run {} step {}: {streak} consecutive refused dispatches; next attempt in \
                     {wait}s",
                    intent.instance_id, intent.step_id
                ),
            );
            return Err(format!(
                "supervision.dispatch.backoff: run {} step {} is backed off after {streak} \
                 consecutive refused dispatches ({wait}s until the next attempt)",
                intent.instance_id, intent.step_id
            ));
        }
        let key = dispatch_key(
            format!("{}-{}", intent.instance_id, intent.step_id),
            now_unix,
        );
        // Issue #243: the driver's ONE recovery act runs through the engine's
        // OWN control (the same `run.reevaluate` an operator invokes), never a
        // plain re-dispatch of a succeeded step and never an adjudication.
        if intent.reason == crate::supervision::codes::REEVALUATION {
            return self.apply_reevaluation(shared, intent, &key, now_unix);
        }
        // Issue #272: the re-collect of the run's own fix delivery presents
        // the collector's own committed inputs with the repair leg's recorded
        // checkout as the worktree the collection observes. A handoff that
        // cannot be read back names no head to collect: the refusal is
        // recorded against the run and nothing is dispatched, never a guessed
        // path.
        let recollection = if intent.reason == crate::supervision::codes::RECOLLECT {
            match recollect_step_params(shared, &intent.instance_id, &intent.step_id) {
                Ok(params) => Some(params),
                Err(message) => {
                    record_unclaimed_dispatch_refusal(
                        shared,
                        &intent.instance_id,
                        &intent.step_id,
                        refusal_code_of(&message),
                        &message,
                        &key,
                    );
                    shared.log.write(
                        "warn",
                        "supervision.dispatch_refused",
                        &format!(
                            "run {} step {}: {message}",
                            intent.instance_id, intent.step_id
                        ),
                    );
                    self.note_refused(
                        &intent.instance_id,
                        &intent.step_id,
                        supervision_interval_secs(shared, &intent.instance_id),
                        now_unix,
                    );
                    return Err(message);
                }
            }
        } else {
            None
        };
        let request = match build_dispatch_request(
            shared,
            &intent.instance_id,
            &intent.step_id,
            recollection.as_ref(),
            &key,
        ) {
            Ok(request) => request,
            Err(message) => {
                record_unclaimed_dispatch_refusal(
                    shared,
                    &intent.instance_id,
                    &intent.step_id,
                    refusal_code_of(&message),
                    &message,
                    &key,
                );
                self.note_refused(
                    &intent.instance_id,
                    &intent.step_id,
                    supervision_interval_secs(shared, &intent.instance_id),
                    now_unix,
                );
                return Err(message);
            }
        };
        if let Err((code, message)) = preflight_apply_request(&request) {
            record_unclaimed_dispatch_refusal(
                shared,
                &intent.instance_id,
                &intent.step_id,
                &code,
                &message,
                &key,
            );
            shared.log.write(
                "info",
                "supervision.input_required",
                &format!(
                    "run {} step {} held before dispatch: {code}: {message}",
                    intent.instance_id, intent.step_id
                ),
            );
            self.note_refused(
                &intent.instance_id,
                &intent.step_id,
                supervision_interval_secs(shared, &intent.instance_id),
                now_unix,
            );
            return Err(format!("{code}: {message}"));
        }
        if intent.kind == "collect_outcome" {
            let mut collecting = self
                .collecting
                .lock()
                .map_err(|_| "collection mutex poisoned")?;
            // Issue #170 (N5): the in-memory reservation is keyed by
            // `(run, step)`, not by run. It exists to keep ONE dispatch of ONE
            // collection step from being spawned twice (the durable claim
            // fences later ticks); keying it by run would silently answer a
            // SECOND collection step of the same run with `awaiting <other>`
            // and never dispatch it.
            if let Err(step) = collecting.begin(&intent.instance_id, &intent.step_id) {
                return Ok(format!("awaiting {step}"));
            }
            let dispatcher = self.clone();
            let shared = Arc::clone(shared);
            let worker_intent = intent.clone();
            let reservation = (intent.instance_id.clone(), intent.step_id.clone());
            let spawn = std::thread::Builder::new()
                .name("canter-collect".to_string())
                .spawn(move || {
                    let _ = dispatcher.apply_dispatch(
                        &shared,
                        &worker_intent,
                        &request,
                        &key,
                        now_unix,
                    );
                    if let Ok(mut collecting) = dispatcher.collecting.lock() {
                        collecting.finish(&reservation.0, &reservation.1);
                    }
                    shared.wake_supervisor();
                });
            if let Err(err) = spawn {
                collecting.finish(&intent.instance_id, &intent.step_id);
                return Err(format!("cannot start bounded collection: {err}"));
            }
            return Ok("collection started".to_string());
        }
        self.apply_dispatch(shared, intent, &request, &key, now_unix)
    }
}

impl DaemonDispatch {
    fn apply_dispatch(
        &self,
        shared: &Arc<Shared>,
        intent: &crate::supervision::DispatchIntent,
        request: &Request,
        key: &str,
        now_unix: i64,
    ) -> Result<String, String> {
        let response = method_apply_from(shared, request, true);
        let doc = Val::parse_json(response.trim())
            .map_err(|message| format!("the dispatch response is unreadable ({message})"))?;
        if doc.get("ok").and_then(Val::as_bool) == Some(true) {
            self.note_dispatched(&intent.instance_id);
            shared.log.write(
                "info",
                "supervision.dispatch",
                &format!(
                    "run {} dispatched step {} ({})",
                    intent.instance_id, intent.step_id, intent.reason
                ),
            );
            return Ok(format!("dispatched {}", intent.step_id));
        }
        let code = doc
            .get("error")
            .and_then(|error| error.get("code"))
            .and_then(Val::as_str)
            .unwrap_or("error");
        let message = doc
            .get("error")
            .and_then(|error| error.get("message"))
            .and_then(Val::as_str)
            .unwrap_or("the dispatch was refused");
        // Issue #141: a refusal that left NO claim of its own (the fan-out
        // admission gate refuses before journaling an intent) is journaled
        // against the run, so the run's own surfaces can classify it instead
        // of reporting the step eligible while nothing happens. A dispatch
        // that reached its claim already has a recorded attempt.
        record_unclaimed_dispatch_refusal(
            shared,
            &intent.instance_id,
            &intent.step_id,
            code,
            message,
            key,
        );
        shared.log.write(
            "warn",
            "supervision.dispatch_refused",
            &format!(
                "run {} step {}: {code}: {message}",
                intent.instance_id, intent.step_id
            ),
        );
        self.note_refused(
            &intent.instance_id,
            &intent.step_id,
            supervision_interval_secs(shared, &intent.instance_id),
            now_unix,
        );
        Err(format!("{code}: {message}"))
    }

    /// Issue #243: the driver's ONE recovery act — the run's OWN check producer
    /// re-evaluated through the engine's own bounded, attributed, journaled
    /// control (`run.reevaluate`), with the driver's derived identity and
    /// reason.
    ///
    /// The control re-derives every one of its own gates (the step must really
    /// be the run's terminal-success check producer, the bound is read from the
    /// durable journal, the attributed record is written BEFORE anything is
    /// dispatched) and the re-run enters the ordinary dispatch path, so the
    /// fan-out admission gate — including the dispatch-time renewal — decides
    /// it exactly as any other dispatch. Nothing is adjudicated: the producer's
    /// own fresh verdict is what the consumer reads next, and a recomputation
    /// that comes back failing refuses the consumer exactly as before.
    fn apply_reevaluation(
        &self,
        shared: &Arc<Shared>,
        intent: &crate::supervision::DispatchIntent,
        key: &str,
        now_unix: i64,
    ) -> Result<String, String> {
        let params = crate::run_control::reevaluation_params(
            key,
            &intent.instance_id,
            &intent.step_id,
            SUPERVISION_OPERATOR,
            &crate::supervision::reevaluation_reason(&intent.step_id),
        );
        let request = Request {
            id: format!("reev_{}", intent.step_id),
            method: "run.reevaluate".to_string(),
            line: crate::canonical::canonical_text(&params),
            params: Some(params),
        };
        let response = method_run_reevaluate(shared, &request);
        let doc = Val::parse_json(response.trim())
            .map_err(|message| format!("the re-evaluation response is unreadable ({message})"))?;
        if doc.get("ok").and_then(Val::as_bool) == Some(true) {
            self.note_dispatched(&intent.instance_id);
            shared.log.write(
                "info",
                "supervision.dispatch",
                &format!(
                    "run {} re-evaluated step {} through the run's own bounded control ({})",
                    intent.instance_id, intent.step_id, intent.reason
                ),
            );
            return Ok(format!("re-evaluated {}", intent.step_id));
        }
        let code = doc
            .get("error")
            .and_then(|error| error.get("code"))
            .and_then(Val::as_str)
            .unwrap_or("error");
        let message = doc
            .get("error")
            .and_then(|error| error.get("message"))
            .and_then(Val::as_str)
            .unwrap_or("the re-evaluation was refused");
        // A refused recovery is recorded against the run exactly like a
        // refused continuation dispatch (issue #141): the control's own
        // outcome is durable either way, and the run's own surface names the
        // engine's code and message instead of a silent park.
        record_unclaimed_dispatch_refusal(
            shared,
            &intent.instance_id,
            &intent.step_id,
            code,
            message,
            key,
        );
        shared.log.write(
            "warn",
            "supervision.dispatch_refused",
            &format!(
                "run {} step {}: {code}: {message}",
                intent.instance_id, intent.step_id
            ),
        );
        self.note_refused(
            &intent.instance_id,
            &intent.step_id,
            supervision_interval_secs(shared, &intent.instance_id),
            now_unix,
        );
        Err(format!("{code}: {message}"))
    }
}

/// Journal ONE refused supervised dispatch that left no claim of its own
/// (issue #141).
///
/// The apply path refuses a dispatch BEFORE journaling an intent when the
/// request, the plan or the fan-out admission refuses it: such a refusal
/// leaves no idempotency row (and therefore no attempt), no pane and no
/// journal record, so the run's own evidence can never name it. Those are
/// exactly the refusals recorded here; a dispatch that reached its claim has
/// its own outcome row and is not recorded twice. The engine's own MESSAGE
/// rides the record with its code (issue #230), so the run's status can name
/// the reason an operator has to act on. A state that cannot record it is
/// logged, and the refusal still returns to the driver (a missing journal
/// record never becomes a silent success).
fn record_unclaimed_dispatch_refusal(
    shared: &Arc<Shared>,
    instance_id: &str,
    step: &str,
    code: &str,
    message: &str,
    key: &str,
) {
    let state = match shared.lock_state() {
        Ok(state) => state,
        Err(message) => {
            shared.log.write(
                "error",
                "supervision.dispatch_refused.record_failed",
                &message,
            );
            return;
        }
    };
    match state.claim(key) {
        Ok(Some(_)) => return,
        Ok(None) => {}
        Err(err) => {
            shared.log.write(
                "error",
                "supervision.dispatch_refused.record_failed",
                &format!("{}: {}", err.code, err.message),
            );
            return;
        }
    }
    if let Err(err) = state.record_supervision_dispatch_refusal(instance_id, step, code, message) {
        shared.log.write(
            "error",
            "supervision.dispatch_refused.record_failed",
            &format!("{}: {}", err.code, err.message),
        );
    }
}

/// The typed code of a refusal the dispatch hook could not classify further:
/// the daemon's own `"<code>: <message>"` rendering, or the whole text when
/// it carries no separator.
fn refusal_code_of(message: &str) -> &str {
    message
        .split_once(": ")
        .map(|(code, _)| code)
        .unwrap_or(message)
}

/// Issue #202 (AC2): the delivery head ONE step CONSUMES must be the head the
/// run's OWN collection certified.
///
/// A committed spine that declares a `collect_outcome` step owns its head
/// binding: that collection is the only observer whose head the run may
/// review or land. A consumption step that presents any other head — or that
/// arrives when no collection of this run ever certified a bindable head at
/// all — refuses typed (`refusal.delivery.unbound`) BEFORE its effect runs, so
/// a run can never carry a verdict for, or land, a head that no collection of
/// its own observed. The spine is read from the run's COMMITTED submission
/// (never from the presented plan, which a caller could trim); a run whose
/// spine declares no collection declares its own head facts and is untouched
/// by this gate (the operator's presented-evidence path).
fn check_certified_consumption(
    state: &crate::state::State,
    instance_id: &str,
    consumed_head: &str,
    kind: &str,
) -> Result<(), (String, String)> {
    let steps = state
        .run_step_documents(instance_id)
        .map_err(|err| (err.code.to_string(), err.message))?;
    let declares_collection = steps
        .unwrap_or_default()
        .iter()
        .any(|step| step.get("kind").and_then(Val::as_str) == Some("collect_outcome"));
    if !declares_collection {
        return Ok(());
    }
    let certificate = state.run_delivery_certificate(instance_id).map_err(|err| {
        (
            err.code.to_string(),
            format!("certified delivery read failed: {}", err.message),
        )
    })?;
    match certificate {
        None => Err((
            crate::mutation::code::DELIVERY_UNBOUND.to_string(),
            format!(
                "{kind} consumes the delivery head {consumed_head}, but no collection of \
                 {instance_id} has certified a delivery: a head this run never observed is \
                 never consumed"
            ),
        )),
        Some(certificate) if certificate.head != consumed_head => Err((
            crate::mutation::code::DELIVERY_UNBOUND.to_string(),
            format!(
                "{kind} consumes the delivery head {consumed_head}, but this run's own \
                 collection ({} {}) certified {}: the delivery must re-enter review and a new \
                 verdict must name {consumed_head} before any step consumes it",
                certificate.step_id, certificate.key, certificate.head
            ),
        )),
        Some(_) => Ok(()),
    }
}

/// The durable material of one committed-spine dispatch (issue #92), read
/// once: the run row, its committed step spine, the spine's step documents
/// and the run's own recorded dispatch context (topology + admission
/// inputs). Every absence is typed — nothing is invented.
struct DispatchMaterial {
    instance: crate::state::InstanceRow,
    spine: Vec<String>,
    steps: Vec<Val>,
    topology: Val,
    profile: Option<Val>,
    admission: Option<Val>,
    feature_head: Option<String>,
    integration_base: Option<String>,
}

/// Read the dispatch material of one run (issue #92 F4 and the operator
/// dispatch surface). Typed failures: an unknown run (`state.not_found`), a
/// run without a committed submission spine (`refusal.run.scope`) and a run
/// whose own applies recorded no topology (`refusal.run.scope` — the first
/// dispatch of a run belongs to the caller that holds it).
fn read_dispatch_material(
    state: &crate::state::State,
    instance_id: &str,
    topology: Option<&Val>,
) -> Result<DispatchMaterial, (String, String)> {
    let instance = state
        .instance_by_id(instance_id)
        .map_err(|err| (err.code.to_string(), err.message))?
        .ok_or_else(|| {
            (
                "state.not_found".to_string(),
                format!("no instance {instance_id}"),
            )
        })?;
    let no_spine = || {
        (
            crate::run_control::codes::SCOPE.to_string(),
            format!(
                "run {instance_id} has no committed queue submission spine; a dispatch derives \
                 its plan from a committed run only"
            ),
        )
    };
    let spine = state
        .run_step_spine(instance_id)
        .map_err(|err| (err.code.to_string(), err.message))?
        .ok_or_else(no_spine)?;
    let mut steps = state
        .run_step_documents(instance_id)
        .map_err(|err| (err.code.to_string(), err.message))?
        .ok_or_else(no_spine)?;
    let recorded = state
        .run_dispatch_context(instance_id)
        .map_err(|err| (err.code.to_string(), err.message))?;
    let topology = match (recorded.as_ref(), topology) {
        (Some(recorded), Some(presented)) if recorded.topology != *presented => {
            return Err((
                crate::run_control::codes::SCOPE.to_string(),
                format!(
                    "run {instance_id} already bound a different topology; dispatch never changes its lane paths"
                ),
            ));
        }
        (Some(recorded), _) => recorded.topology.clone(),
        (None, Some(presented)) => presented.clone(),
        (None, None) => {
            return Err((
                crate::run_control::codes::SCOPE.to_string(),
                format!(
                    "run {instance_id} needs --topology FILE for its first dispatch: integration_branch, production_branches, integration_repo and worktrees_root"
                ),
            ));
        }
    };
    let profile = state
        .run_role_binding(instance_id)
        .map_err(|err| (err.code.to_string(), err.message))?;
    if let Some(profile) = &profile {
        for step in &mut steps {
            if matches!(
                step.get("kind").and_then(Val::as_str),
                Some("harness_start" | "prompt")
            ) {
                let derived = object(vec![
                    (
                        "harness_key",
                        profile.get("key").cloned().unwrap_or_else(null),
                    ),
                    ("kind", profile.get("kind").cloned().unwrap_or_else(null)),
                ]);
                if let Some(params) = merged_step_params(Some(&derived), step.get("params")) {
                    *step = step_with_params(step, &params);
                }
            }
        }
    }
    if let Some(base) = recorded
        .as_ref()
        .and_then(|context| context.integration_base.as_deref())
    {
        for step in &mut steps {
            if step.get("kind").and_then(Val::as_str) == Some("collect_outcome") {
                let derived = object(vec![("base_head", string(base))]);
                if let Some(params) = merged_step_params(Some(&derived), step.get("params")) {
                    *step = step_with_params(step, &params);
                }
            }
        }
    }
    Ok(DispatchMaterial {
        instance,
        spine,
        steps,
        topology,
        profile,
        admission: recorded
            .as_ref()
            .and_then(|context| context.admission.clone()),
        feature_head: recorded
            .as_ref()
            .and_then(|context| context.feature_head.clone()),
        integration_base: recorded
            .as_ref()
            .and_then(|context| context.integration_base.clone()),
    })
}

/// Issue #256: bind a review round to the head the recorded handoff's OWN
/// repair leg DELIVERED.
///
/// The head the FAIL was handed at is a recorded fact and never moves by
/// itself; the leg advances the branch in its OWN lane checkout. That checkout
/// is the only durable state that names the delivered head, so it is observed
/// here — read-only, outside the state guard, through the same bounded git
/// runner every adapter read uses — and the observed descendant head replaces
/// the run's recorded head for THIS review dispatch: the reviewer leg's derived
/// checkout then materializes the delivered commit, and the round's own
/// head-keyed verification accepts a verdict that names it (the run's
/// delivery-certification gate, issue #202, is untouched and decides
/// consumption exactly as before). A handoff that names no lane, a leg that
/// never moved and every read that cannot be taken leave the material exactly
/// as the run recorded it.
fn bind_delivered_review_head(shared: &Arc<Shared>, instance_id: &str, head: &mut Option<String>) {
    if head.is_none() {
        return;
    }
    let (mut evidence, worktrees_root) = {
        let state = match shared.lock_state() {
            Ok(state) => state,
            Err(_) => return,
        };
        // Issue #268: the run's recorded rows are read once and both reads
        // below are derived from them.
        let records = match state.run_records(instance_id) {
            Ok(records) => records,
            Err(_) => return,
        };
        let evidence = match state.supervision_evidence_from(&records) {
            Ok(Some(evidence)) => evidence,
            _ => return,
        };
        let worktrees_root = crate::supervision::recorded_worktrees_root_of(&records);
        (evidence, worktrees_root)
    };
    crate::supervision::observe_fix_leg(&mut evidence, worktrees_root.as_deref());
    if let Some(delivered) = evidence
        .fix_leg
        .as_ref()
        .filter(|leg| leg.delivered)
        .map(|leg| leg.head.clone())
    {
        *head = Some(delivered);
    }
}

/// The step params of ONE re-collect (issue #272): the run's own committed
/// collector step's params, with the worktree the collection OBSERVES replaced
/// by the repair leg's own recorded lane checkout — the only recorded state
/// that names the head the handoff delivered.
///
/// The committed `branch` binding is dropped: the repair leg's checkout is the
/// engine's OWN `git worktree add --detach` checkout (a fresh branch cannot be
/// attached while the run's feature branch is checked out in the implementer
/// lane), so a branch pinned from the run's plan could never be the branch that
/// checkout holds. The collection observes the branch the leg's work left it
/// on, and a checkout left with no branch refuses typed — a branch is never
/// fabricated for it. Everything else (the run's own collection base,
/// `requires_delta`) stays the committed step's own binding: the re-collect is
/// the same collection over the repair leg's checkout and nothing is invented.
/// A handoff whose recorded checkout cannot be read back names no head to
/// collect, and the dispatch refuses typed rather than collecting a guessed
/// path.
fn recollect_step_params(
    shared: &Arc<Shared>,
    instance_id: &str,
    step_id: &str,
) -> Result<Val, String> {
    let (committed, worktree) = {
        let state = shared.lock_state()?;
        let material = read_dispatch_material(&state, instance_id, None)
            .map_err(|(code, message)| format!("{code}: {message}"))?;
        let committed = material
            .steps
            .iter()
            .find(|step| step.get("id").and_then(Val::as_str) == Some(step_id))
            .and_then(|step| step.get("params"))
            .cloned();
        let worktree = state
            .supervision_evidence(instance_id)
            .ok()
            .flatten()
            .and_then(|evidence| evidence.fix_round.map(|fix| fix.worktree))
            .unwrap_or_default();
        (committed, worktree)
    };
    if worktree.is_empty() {
        return Err(format!(
            "{}: the recorded fix-round handoff of run {instance_id} names no lane checkout, so \
             the head it delivered cannot be collected",
            crate::mutation::code::FIX_UNBOUND
        ));
    }
    let Some(Val::Obj(mut params)) = merged_step_params(committed.as_ref(), None) else {
        return Err(format!(
            "{}: step {step_id:?} of run {instance_id} declares no params; a re-collect presents \
             the collection's own inputs",
            crate::mutation::code::FIX_UNBOUND
        ));
    };
    params.remove("branch");
    params.insert("worktree".to_string(), string(&worktree));
    Ok(Val::Obj(params))
}

/// Build the `apply` request one committed-spine dispatch presents (issue #92
/// F4 and the operator dispatch surface) from already-read durable material:
/// the run's own committed step spine (params included), the run row (grant,
/// epoch, issue revision, workflow pins) and the topology + admission
/// occupancy one of the run's own applies presented.
///
/// `step_params` (when presented) are the OPERATOR's step-specific inputs:
/// they are merged over the named step's committed params in the derived plan
/// document, so a re-dispatch carries the corrected params — never a silent
/// substitution of the stale ones — and the plan id follows the merged
/// content. `key` is the idempotency key of THIS dispatch (the operator's on
/// the dispatch surface, the driver's own on the continuation path).
fn dispatch_request_from(
    material: &DispatchMaterial,
    step_id: &str,
    step_params: Option<&Val>,
    key: &str,
) -> Result<Request, (String, String)> {
    let instance = &material.instance;
    let plan = dispatch_plan_doc(instance, &material.steps, step_id, step_params);
    let plan =
        crate::mutation::bind_plan(&plan).map_err(|err| (err.code.to_string(), err.message))?;
    // Admission inputs are re-presented exactly as the run's own dispatch
    // attested them. Issue #198: a LAPSED proof is renewed by the
    // supervisor's own dispatch path before this builder runs
    // (`renew_host_proof_for_dispatch` — a measurement taken at dispatch
    // time), so what arrives here is either a fresh measurement or the
    // recorded attestation unchanged; the admission gate still decides every
    // fan-out step for itself.
    let mut flags = vec![
        ("interactive", bool_(false)),
        ("digest_confirmed", bool_(false)),
        ("scheduled", bool_(false)),
    ];
    if let Some(admission) = &material.admission {
        flags.push(("admission", admission.clone()));
    }
    let params = object(vec![
        ("idempotency_key", string(key)),
        ("plan", plan.doc.clone()),
        ("step", string(step_id)),
        ("grant_id", string(&instance.grant_id)),
        ("instance_id", string(&instance.instance_id)),
        (
            "observed",
            object(vec![
                ("issue_revision", string(&instance.issue_revision)),
                ("policy_hash", string(&instance.policy_hash)),
                (
                    "feature_head",
                    material
                        .feature_head
                        .as_deref()
                        .map(string)
                        .unwrap_or_else(null),
                ),
                (
                    "integration_base",
                    material
                        .integration_base
                        .as_deref()
                        .map(string)
                        .unwrap_or_else(null),
                ),
            ]),
        ),
        ("topology", material.topology.clone()),
        ("profile", material.profile.clone().unwrap_or_else(null)),
        ("flags", object(flags)),
    ]);
    let id = format!("disp_{step_id}");
    // The journaled claim must carry a canonical request line: the durable
    // attempt ledger (retry frontier, supervision evidence, readbacks) parses
    // it, so a line-less dispatch would record an unreadable attempt.
    let line = crate::canonical::canonical_text(&object(vec![
        ("schema", string("hf-rpc-request/v1")),
        ("id", string(&id)),
        ("method", string("apply")),
        ("params", params.clone()),
    ]));
    Ok(Request {
        id,
        method: "apply".to_string(),
        params: Some(params),
        line,
    })
}

/// [`dispatch_request_from`] over a freshly read [`DispatchMaterial`]: the
/// driver's continuation dispatch path.
///
/// Issue #198: before the request is built, the run's OWN lapsed
/// host-resource proof is renewed from a measurement the daemon takes at
/// THIS dispatch (see [`renew_host_proof_for_dispatch`]) — the supervisor is
/// a caller of the fan-out admission gate and may never re-present the
/// submit-time attestation of a slow worker's run.
fn build_dispatch_request(
    shared: &Arc<Shared>,
    instance_id: &str,
    step_id: &str,
    step_params: Option<&Val>,
    key: &str,
) -> Result<Request, String> {
    let mut material = {
        let state = shared.lock_state()?;
        read_dispatch_material(&state, instance_id, None)
            .map_err(|(code, message)| format!("{code}: {message}"))?
    };
    renew_host_proof_for_dispatch(shared, &mut material, step_id, key);
    dispatch_request_from(&material, step_id, step_params, key)
        .map_err(|(code, message)| format!("{code}: {message}"))
}

/// The daemon's own host-resource measurement at dispatch time (issue
/// #198).
///
/// The supervisor is a CALLER of the fan-out admission gate: when it
/// continues a run, the proof it presents must be a measurement taken at
/// DISPATCH time — never the submit-time attestation echoed back, and never
/// a fabricated instant. The daemon measures the host through the resource
/// a lane fan-out consumes: the host's filesystem serving the run's lane
/// root (`topology.worktrees_root`, where the lane's own worktree lives).
/// The observation is the free bytes the host exposes there, stamped with
/// the instant the observation was taken.
///
/// A host that does not expose its lane root cannot be observed
/// (`Unmeasurable`): the daemon then presents the run's recorded proof
/// unchanged and the admission gate refuses `refusal.admission.proof_stale`
/// exactly as before — the freshness bound, the caps and every other gate
/// stay untouched, because this only ever supplies a MEASUREMENT.
fn measure_host(lane_root: &Path) -> crate::lifecycle::HostMeasurement {
    match fs2::available_space(lane_root) {
        Ok(available_bytes) => crate::lifecycle::HostMeasurement::Measured {
            measured_at_unix: time::unix_now(),
            available_bytes,
        },
        Err(err) => crate::lifecycle::HostMeasurement::Unmeasurable {
            reason: format!(
                "the host does not expose the lane root {} ({err})",
                lane_root.display()
            ),
        },
    }
}

/// One admission document with its host proof replaced by the measurement
/// taken at this dispatch (issue #198). Every other key — caps, occupancy —
/// is preserved verbatim, and the proof object keeps any extra keys: only
/// its `measured_at` and its free-byte observation (issue #231) are
/// superseded.
fn admission_with_renewed_proof(
    admission: &Val,
    measured_at: &str,
    available_bytes: u64,
) -> Option<Val> {
    let Val::Obj(mut admission) = admission.clone() else {
        return None;
    };
    let mut proof = match admission.remove("host_proof") {
        Some(Val::Obj(proof)) => proof,
        _ => std::collections::BTreeMap::new(),
    };
    proof.insert("measured_at".to_string(), string(measured_at));
    proof.insert(
        "available_bytes".to_string(),
        integer(available_bytes as i64),
    );
    admission.insert("host_proof".to_string(), Val::Obj(proof));
    Some(Val::Obj(admission))
}

/// The step kinds the fan-out admission gate guards (issue #9 AC1): the
/// spawn kinds, plus the reviewer leg of a self-dispatching review step
/// (issue #193 — it starts the run's own reviewer lane). The supervisor
/// measures the host for exactly these steps.
fn fanout_step_kind(step: &Val) -> bool {
    match step.get("kind").and_then(Val::as_str) {
        Some("harness_start" | "prompt") => true,
        Some("review_evidence") => crate::mutation::declares_reviewer_leg(step.get("params")),
        _ => false,
    }
}

/// The step kinds whose dispatch resolves the run's issue's ledger-TERMINAL
/// lane generations before the effect runs (issue #190, extended by #222 and
/// #224): exactly the kinds that BIND a lane generation.
///
/// One fact, two readers: the resolution in `method_apply` below and the bind
/// effects that may retire residue with it. `worktree_create` creates (or
/// reclaims) the run's own implementer lane, `harness_start` registers the
/// worker's pane in it, and `review_evidence` binds the REVIEWER leg's own
/// lane checkout (issue #210) and starts its worker there — the measured #224
/// defect was that leg's residue (its registration, its pane and its checkout
/// outliving a completed run) refusing the NEXT run's bind with
/// `refusal.lane.name_collision`, and a reviewer-leg bind that resolved
/// nothing could not reclaim a thing. Nothing else pays for the resolution:
/// a step that binds no lane has no residue to reclaim, and only a bind step
/// may retire.
fn lane_binding_step_kind(kind: &str) -> bool {
    matches!(
        kind,
        "harness_start" | "worktree_create" | "review_evidence"
    )
}

/// The lane generations one step dispatch resolves from durable state before
/// the effect runs: the run's issue's ledger-TERMINAL generations for a BIND
/// kind ([`lane_binding_step_kind`]) and nothing at all for any other kind.
///
/// The resolution is a pure function of the ledger row set — never of the
/// substrate, and never of a name read back from it — so a caller can only
/// retire exactly what the ledger records as terminal for THIS repository
/// issue, and a live run's lane is unreachable by construction.
fn resolved_lane_generations(
    state: &State,
    repository: &str,
    issue_number: i64,
    kind: &str,
) -> Result<Vec<String>, StateError> {
    if !lane_binding_step_kind(kind) {
        return Ok(Vec::new());
    }
    state.retired_run_ids(repository, issue_number)
}

/// Renew the run's OWN lapsed host-resource proof at dispatch time (issue
/// #198), from a measurement the daemon takes NOW — the supervisor's own act,
/// exactly like the run's lapsed grant window (issue #184).
///
/// The defect this closes: the supervisor re-presented the proof the run
/// recorded at SUBMISSION, so every fan-out step reached more than
/// [`crate::lifecycle::HOST_PROOF_FRESHNESS_SECS`] after submission (a slow
/// worker's turn, `run-85a856d6b9e9e7d0` p6) was refused
/// `refusal.admission.proof_stale` forever.
///
/// Bounded and honest by construction:
/// - only a fan-out step of a run whose own recorded proof has ACTUALLY
///   lapsed (a fresh proof is presented as recorded, a missing one is never
///   invented, and a run that is not live never renews);
/// - only from a measurement of THIS dispatch (`Unmeasurable` hosts renew
///   nothing and keep the typed refusal);
/// - recorded BEFORE the renewed proof is presented — one `host.proof.renewal`
///   journal record (superseded instant, replacement instant, the observed
///   free bytes) and one `run.host_proof.renewed` log line. A renewal that
///   cannot be recorded is not presented: the gate then refuses the lapsed
///   proof exactly as before (fail closed).
///
/// Nothing else moves: caps, occupancy, pacing, overlap and the freshness
/// bound itself stay the admission gate's own unchanged decisions.
fn renew_host_proof_for_dispatch(
    shared: &Arc<Shared>,
    material: &mut DispatchMaterial,
    step_id: &str,
    key: &str,
) -> Option<crate::lifecycle::HostProofRenewal> {
    // Only a fan-out step owes a proof at all.
    let step = material
        .steps
        .iter()
        .find(|step| step.get("id").and_then(Val::as_str) == Some(step_id))?;
    if !fanout_step_kind(step) {
        return None;
    }
    let instance = &material.instance;
    let presented = material
        .admission
        .as_ref()
        .and_then(|admission| admission.get("host_proof"))
        .and_then(|proof| proof.get("measured_at"))
        .and_then(Val::as_str)
        .and_then(time::unix_from_rfc3339)
        .map(crate::lifecycle::HostProof::at)?;
    let now = time::unix_now();
    if presented.fresh_at(now) {
        // The run's own proof is still fresh: it is presented as recorded.
        return None;
    }
    // The renewal is the run's own act: only a live run renews (never a
    // paused, held, blocked, queued or finished one).
    let live = matches!(instance.status.as_str(), "new" | "running")
        && !instance.paused
        && !instance.pause_requested
        && !instance.human_queue
        && instance.terminal_blockers == 0;
    if !live {
        return None;
    }
    // The host resource a fan-out consumes: the lane root its worktree lives
    // in. A topology that records none names no host to measure.
    let lane_root = material
        .topology
        .get("worktrees_root")
        .and_then(Val::as_str)
        .map(PathBuf::from)?;
    let measurement = measure_host(&lane_root);
    let Some(renewal) =
        crate::lifecycle::renew_lapsed_host_proof(Some(presented), &measurement, live, now)
    else {
        if let crate::lifecycle::HostMeasurement::Unmeasurable { reason } = &measurement {
            shared.log.write(
                "warn",
                "run.host_proof.unmeasurable",
                &format!(
                    "run {} step {step_id}: {reason}; the recorded proof is presented unchanged \
                     and the admission gate decides",
                    instance.instance_id
                ),
            );
        }
        return None;
    };
    let superseded_at = time::rfc3339_from_unix(renewal.superseded.measured_at_unix);
    let measured_at = time::rfc3339_from_unix(renewal.replacement.measured_at_unix);
    // The audit record comes first: a renewal that cannot be recorded is
    // never presented.
    let recorded = {
        let state = match shared.lock_state() {
            Ok(state) => state,
            Err(message) => {
                shared.log.write(
                    "error",
                    "run.host_proof.renewal_failed",
                    &format!("run {} step {step_id}: {message}", instance.instance_id),
                );
                return None;
            }
        };
        state.record_host_proof_renewal(
            &instance.instance_id,
            key,
            &superseded_at,
            &measured_at,
            renewal.available_bytes,
        )
    };
    if let Err(err) = recorded {
        shared.log.write(
            "error",
            "run.host_proof.renewal_failed",
            &format!(
                "run {} step {step_id}: {}: {}",
                instance.instance_id, err.code, err.message
            ),
        );
        return None;
    }
    // Present the measurement: the run's recorded caps and occupancy ride
    // along verbatim; only the lapsed proof is superseded.
    let Some(admission) = material.admission.as_ref().and_then(|admission| {
        admission_with_renewed_proof(admission, &measured_at, renewal.available_bytes)
    }) else {
        shared.log.write(
            "error",
            "run.host_proof.renewal_failed",
            &format!(
                "run {} step {step_id}: the recorded admission is not an object",
                instance.instance_id
            ),
        );
        return None;
    };
    material.admission = Some(admission);
    shared.log.write(
        "info",
        "run.host_proof.renewed",
        &format!(
            "run {} renewed its own lapsed host-resource proof for step {step_id}: superseded \
             {superseded_at}, measured {measured_at} at dispatch time ({} bytes available at the \
             lane root)",
            instance.instance_id, renewal.available_bytes
        ),
    );
    Some(renewal)
}

/// Issue #250: produce the host-resource proof ONE dispatch presents, on an
/// audited operator's behalf.
///
/// The measured defect: every remedy a parked run named needed an artifact no
/// exposed control could produce — `run dispatch` asked for an `--admission
/// FILE` that nothing emitted. This is the control: when the caller presents
/// the audited operator pair, the daemon takes its OWN measurement of the
/// host at the run's lane root (the same observation #198 takes when it
/// continues a run) and binds it as the proof this dispatch presents.
///
/// Bounded and honest by construction:
/// - only a fan-out step of a LIVE run (never a paused, human-held or
///   finished one) and only when the run recorded an admission document to
///   bind the measurement INTO — the caps and the occupancy stay the run's
///   own recorded ones verbatim, because the measurement supplies a PROOF,
///   never a cap;
/// - only from a measurement of THIS dispatch (`Unmeasurable` hosts produce
///   nothing: the gate then refuses the absent or lapsed proof exactly as
///   before, typed);
/// - the act is recorded BEFORE the proof is presented — one
///   `host.proof.renewal.operator` journal record naming the operator, the
///   reason, the superseded proof (or its absence) and the measurement — so
///   the proof-producing control is auditable without reading a daemon log.
///
/// Nothing else moves: the freshness bound, the caps, the occupancy, the
/// overlap and every other admission decision stay the gate's own.
fn operator_measured_proof(
    shared: &Arc<Shared>,
    material: &mut DispatchMaterial,
    step_id: &str,
    key: &str,
    operator: &str,
    reason: &str,
) -> bool {
    let Some(step) = material
        .steps
        .iter()
        .find(|step| step.get("id").and_then(Val::as_str) == Some(step_id))
    else {
        return false;
    };
    // Only a fan-out step owes a proof at all.
    if !fanout_step_kind(step) {
        return false;
    }
    let instance = &material.instance;
    // The measurement is the run's own act on the operator's behalf: only a
    // live run is measured (never a paused, held, blocked or finished one).
    let live = matches!(instance.status.as_str(), "new" | "running")
        && !instance.paused
        && !instance.pause_requested
        && !instance.human_queue
        && instance.terminal_blockers == 0;
    if !live {
        return false;
    }
    // The run recorded no admission document at all: there is nothing to
    // bind a measurement into (the caps are the caller's own attestation), so
    // nothing is measured and the gate keeps refusing `proof_missing`.
    let Some(admission) = material.admission.clone() else {
        return false;
    };
    let Some(lane_root) = material
        .topology
        .get("worktrees_root")
        .and_then(Val::as_str)
        .map(PathBuf::from)
    else {
        return false;
    };
    let measurement = measure_host(&lane_root);
    let crate::lifecycle::HostMeasurement::Measured {
        measured_at_unix,
        available_bytes,
    } = measurement
    else {
        if let crate::lifecycle::HostMeasurement::Unmeasurable { reason } = &measurement {
            shared.log.write(
                "warn",
                "run.host_proof.unmeasurable",
                &format!(
                    "run {} step {step_id}: the operator-authorized measurement produced nothing \
                     ({reason}); the recorded admission is presented unchanged and the admission \
                     gate decides",
                    instance.instance_id
                ),
            );
        }
        return false;
    };
    let presented = admission
        .get("host_proof")
        .and_then(|proof| proof.get("measured_at"))
        .and_then(Val::as_str)
        .and_then(time::unix_from_rfc3339);
    let now = time::unix_now();
    if presented.is_some_and(|measured_at_unix| {
        crate::lifecycle::HostProof::at(measured_at_unix).fresh_at(now)
    }) {
        // The recorded proof is still fresh: it is presented as recorded and
        // no measurement is taken.
        return false;
    }
    let measured_at = time::rfc3339_from_unix(measured_at_unix);
    let superseded_at = presented
        .map(time::rfc3339_from_unix)
        .unwrap_or_else(|| "none".to_string());
    let Some(bound) = admission_with_renewed_proof(&admission, &measured_at, available_bytes)
    else {
        return false;
    };
    // The audit record comes first: an act that cannot be recorded is never
    // presented.
    let recorded = match shared.lock_state() {
        Ok(state) => state.record_operator_host_proof_renewal(
            &instance.instance_id,
            key,
            operator,
            reason,
            &superseded_at,
            &measured_at,
            available_bytes,
        ),
        Err(message) => Err(crate::state::StateError {
            code: "state.unavailable",
            message,
        }),
    };
    if let Err(err) = recorded {
        shared.log.write(
            "error",
            "run.host_proof.renewal_failed",
            &format!(
                "run {} step {step_id}: the operator-authorized measurement could not be recorded \
                 ({err:?}); it is not presented",
                instance.instance_id
            ),
        );
        return false;
    }
    material.admission = Some(bound);
    shared.log.write(
        "info",
        "run.host_proof.renewed_by_operator",
        &format!(
            "run {} produced a host-resource proof for step {step_id} on the recorded operator's \
             behalf: superseded {superseded_at}, measured {measured_at} at dispatch time \
             ({available_bytes} bytes available at the lane root)",
            instance.instance_id
        ),
    );
    true
}

/// The `hf-plan/v1` document one committed-spine dispatch binds (issue #92
/// F4 and the operator dispatch surface): the run's OWN reviewed inputs —
/// repository, issue identity/revision, the workflow pins the run was
/// admitted under, the live state epoch and the committed step spine. The
/// content-addressed plan id follows the documented derivation
/// (docs/contracts/spec-plans.md); the engine's own `bind_plan` re-derives and
/// verifies it.
///
/// `step_params` (when presented) replace the named step's params — the
/// operator's corrected inputs — so the derived plan carries exactly what the
/// dispatch presents; every other step stays verbatim.
fn dispatch_plan_doc(
    instance: &crate::state::InstanceRow,
    steps: &[Val],
    step_id: &str,
    step_params: Option<&Val>,
) -> Val {
    let steps: Vec<Val> = steps
        .iter()
        .map(|step| {
            match (
                step_params,
                step.get("id").and_then(Val::as_str) == Some(step_id),
            ) {
                (Some(params), true) => step_with_params(step, params),
                _ => step.clone(),
            }
        })
        .collect();
    let placeholder = object(vec![
        ("schema", string("hf-plan/v1")),
        ("plan_id", string("hf_plan_0000000000000000")),
        ("workflow_id", string(&instance.workflow_id)),
        ("workflow_hash", string(&instance.workflow_hash)),
        ("state_epoch", integer(instance.state_epoch)),
        ("repository", string(&instance.repository)),
        (
            "issue",
            object(vec![
                ("number", integer(instance.issue_number)),
                ("revision", string(&instance.issue_revision)),
            ]),
        ),
        ("steps", Val::Arr(steps)),
    ]);
    let digest = crate::canonical::sha256_hex(&crate::canonical::canonical_bytes(&placeholder));
    let plan_id = format!("hf_plan_{}", &digest[..16]);
    match placeholder {
        Val::Obj(mut map) => {
            map.insert("plan_id".to_string(), string(&plan_id));
            Val::Obj(map)
        }
        _ => unreachable!("the plan seed is an object"),
    }
}

/// One plan step document with its `params` replaced by the presented ones
/// (every other field preserved verbatim).
fn step_with_params(step: &Val, params: &Val) -> Val {
    match step {
        Val::Obj(map) => {
            let mut map = map.clone();
            map.insert("params".to_string(), params.clone());
            Val::Obj(map)
        }
        other => other.clone(),
    }
}

/// The merged step params of one dispatch: the run's committed step params
/// with the operator's step-specific inputs applied on top (issue #92: a
/// re-dispatch carries the CORRECTED params, never a silent reconstruction of
/// the stale ones). `None` when neither side declares any.
fn merged_step_params(committed: Option<&Val>, supplied: Option<&Val>) -> Option<Val> {
    let Some(supplied) = supplied else {
        return committed.cloned();
    };
    let mut merged = match committed {
        Some(Val::Obj(map)) => map.clone(),
        _ => std::collections::BTreeMap::new(),
    };
    if let Val::Obj(overrides) = supplied {
        for (key, value) in overrides {
            merged.insert(key.clone(), value.clone());
        }
    }
    Some(Val::Obj(merged))
}

/// One dispatch idempotency key: `ik_` + the run-local step identity + the
/// current second, so the driver's continuation dispatch of a step is a FRESH
/// claim while a same-second duplicate can never double-dispatch.
fn dispatch_key(target: String, now_unix: i64) -> String {
    let sanitized: String = target
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    let tail = format!("{sanitized}-{now_unix}");
    format!("ik_{}", &tail[..tail.len().min(64)])
}

/// Purely validate the addressed step's own input contract. This runs before
/// journaling, so a request that was never executable cannot become a failed
/// effect attempt or consume a bounded retry.
fn check_apply_step_contract(
    kind: &str,
    params: Option<&Val>,
    parsed: &ApplyParams,
) -> Result<(), (String, String)> {
    crate::mutation::check_step_params(
        kind,
        params,
        &crate::mutation::ParamContract {
            integration_branch: &parsed.integration_branch,
            production_branches: &parsed.production_branches,
            publish_route: &parsed.integration_publish,
            observed_feature_head: parsed.feature_head.as_deref(),
            observed_integration_base: parsed.integration_base.as_deref(),
            has_archive_root: parsed.archive_root.is_some(),
            worktrees_root: Some(parsed.worktrees_root.as_path()),
        },
    )
}

/// Pure preflight used by autonomous supervision before it hands a request to
/// `method_apply`. The apply path repeats the same shared contract check as a
/// boundary defense; neither path invents missing step parameters.
fn preflight_apply_request(request: &Request) -> Result<(), (String, String)> {
    let parsed = apply_params(request)?;
    let plan = crate::mutation::bind_plan(&parsed.plan)
        .map_err(|err| (err.code.to_string(), err.message))?;
    let step = crate::mutation::plan_step(&plan, &parsed.step)
        .map_err(|err| (err.code.to_string(), err.message))?;
    let kind =
        crate::mutation::step_kind(step).map_err(|err| (err.code.to_string(), err.message))?;
    let params = match step.get("params") {
        Some(value @ Val::Obj(_)) => Some(value),
        None | Some(Val::Null) => None,
        _ => {
            return Err((
                "refusal.request.malformed".to_string(),
                "plan step params must be an object or null".to_string(),
            ));
        }
    };
    check_apply_step_contract(&kind, params, &parsed)
}

/// Executor-owned claim reaper. Created only after a NEW claim commits, before
/// any later state guard: unwinding/early returns release those guards first.
/// Client disconnects do not own execution: the daemon finishes the already
/// bounded effect and records its outcome even when nobody reads the response.
/// Never expire a live executor by age (that could admit a duplicate effect).
struct ApplyClaim<'a> {
    shared: &'a Arc<Shared>,
    request: &'a Request,
    key: &'a str,
}

impl Drop for ApplyClaim<'_> {
    fn drop(&mut self) {
        let result = (|| -> Result<bool, StateError> {
            let state = self.shared.lock_state().map_err(|message| StateError {
                code: "state.unavailable",
                message,
            })?;
            let Some(claim) = state.claim(self.key)? else {
                return Ok(false);
            };
            if claim.status != "claimed" || claim.request_id != self.request.id {
                return Ok(false);
            }
            let message = "apply executor exited before recording an outcome; external review is required before retrying with a new key";
            let params = self.request.params.as_ref();
            let plan_id = params
                .and_then(|p| p.get("plan"))
                .and_then(|p| p.get("plan_id"))
                .and_then(Val::as_str)
                .unwrap_or(DAEMON_PLAN_ID);
            let step_id = params
                .and_then(|p| p.get("step"))
                .and_then(Val::as_str)
                .unwrap_or(DAEMON_STEP_ID);
            let outcome = apply_outcome(
                plan_id,
                step_id,
                self.key,
                "ambiguous",
                null(),
                Some(("state.interrupted", message.to_string())),
            );
            let response = err_response(&self.request.id, "state.interrupted", message);
            state.resolve_claim(
                self.key,
                "apply",
                "ambiguous",
                &canonical_text(&outcome),
                Some(&response),
            )?;
            if let Some(instance) = self
                .request
                .params
                .as_ref()
                .and_then(|p| p.get("instance_id"))
                .and_then(Val::as_str)
            {
                state.complete_run_pause_boundary(instance, &time::rfc3339_now())?;
            }
            Ok(true)
        })();
        match result {
            Ok(true) => publish_after_state_change(self.shared, None),
            Ok(false) => {}
            Err(err) => self.shared.log.write(
                "error",
                "apply.reap_failed",
                &format!("{}: {}", err.code, err.message),
            ),
        }
    }
}

fn method_apply(shared: &Arc<Shared>, request: &Request) -> String {
    method_apply_from(shared, request, false)
}

// Origin is an internal capability, never a caller-controlled RPC field/key.
fn method_apply_from(shared: &Arc<Shared>, request: &Request, supervised: bool) -> String {
    let mut parsed = match apply_params(request) {
        Ok(parsed) => parsed,
        Err((code, message)) => return err_response(&request.id, &code, message),
    };
    // Bind the plan digest + content identity BEFORE any journaling
    // (malformed/tampered plans never leave a claim behind).
    let plan = match crate::mutation::bind_plan(&parsed.plan) {
        Ok(plan) => plan,
        Err(err) => return err_response(&request.id, err.code, err.message),
    };
    let step = match crate::mutation::plan_step(&plan, &parsed.step) {
        Ok(step) => step,
        Err(err) => return err_response(&request.id, err.code, err.message),
    };
    let kind = match crate::mutation::step_kind(step) {
        Ok(kind) => kind,
        Err(err) => return err_response(&request.id, err.code, err.message),
    };
    let params = match step.get("params") {
        Some(Val::Obj(_)) => step.get("params"),
        None | Some(Val::Null) => None,
        _ => {
            return err_response(
                &request.id,
                "refusal.malformed",
                "plan step params must be an object or null",
            );
        }
    };
    if let Err((code, message)) = check_apply_step_contract(&kind, params, &parsed) {
        return err_response(&request.id, &code, message);
    }
    // Daemon-level risk gates that need no state: destructive/production
    // effects are never schedulable; production-branch effects require a
    // fresh interactive TTY-confirmed digest; real-external effects require
    // the recorded first-write approval (AC10 plumbing).
    let risk = crate::mutation::risk_class(&kind).unwrap_or("production");
    let branch_target = params
        .and_then(|p| p.get("branch").or_else(|| p.get("base")))
        .and_then(Val::as_str)
        .unwrap_or("");
    if crate::mutation::classify_branch(
        branch_target,
        &parsed.integration_branch,
        &parsed.production_branches,
    ) == crate::mutation::BranchKind::Production
        && let Err(err) = crate::mutation::check_production_confirmation(
            parsed.production_confirmation.as_deref(),
            parsed.interactive,
            parsed.digest_confirmed,
            parsed.scheduled,
        )
    {
        return err_response(&request.id, err.code, err.message);
    }
    if parsed.scheduled && matches!(risk, "production" | "destructive") {
        return err_response(
            &request.id,
            "refusal.policy.scheduled",
            "schedules and automation can never carry production or destructive effects",
        );
    }
    let _ = &risk;
    // Issue #9 AC1 fan-out admission: harness_start/prompt spawn lane work,
    // and so does a self-dispatching review step (issue #193: it starts the
    // run's own reviewer lane) — the same caps, the same host-resource proof,
    // the same overlap fence, never a bypass.
    if (matches!(kind.as_str(), "harness_start" | "prompt")
        || (kind == "review_evidence" && crate::mutation::declares_reviewer_leg(params)))
        && let Err(response) = admission_gate(shared, request, &plan, &parsed, params)
    {
        return response;
    }
    // Issue #86 safe-boundary completion: this apply arrives at the run
    // BEFORE its own claim, so a recorded pause request whose previous
    // in-flight step has already resolved has reached its safe boundary
    // here — the pause commits `paused` first, and this new dispatch is
    // then refused as paused (stop-admitting takes effect before any
    // further step is dispatched).
    {
        let state = match shared.lock_state() {
            Ok(state) => state,
            Err(message) => {
                return err_response(&request.id, "state.unavailable", message);
            }
        };
        if let Err(err) =
            state.complete_run_pause_boundary(&parsed.instance_id, &time::rfc3339_now())
        {
            shared.log.write(
                "error",
                "run.pause.boundary_failed",
                &format!("{}: {}", err.code, err.message),
            );
        }
    }
    // Journal the durable intent (pre-action audit record + idempotency
    // claim; action mutate.<kind>, target repo:instance:step).
    let action = format!("mutate.{kind}");
    let target = format!("{}:{}:{}", plan.repository, parsed.instance_id, parsed.step);
    let key = match request
        .params
        .as_ref()
        .and_then(|params| params.get("idempotency_key"))
        .and_then(Val::as_str)
        .map(str::to_string)
    {
        Some(key) => key,
        None => {
            return err_response(
                &request.id,
                "refusal.malformed",
                "apply requires params.idempotency_key",
            );
        }
    };
    let grant_id = parsed.grant_id.clone();
    let mut automatic_retry = false;
    let journaled = {
        let state = match shared.lock_state() {
            Ok(state) => state,
            Err(message) => {
                return err_response(&request.id, "state.unavailable", message);
            }
        };
        // Recheck under the same guard as the claim: operator reservations,
        // holds, authorization and the frontier may have moved since the tick.
        if supervised {
            let eligible = (|| -> Result<bool, StateError> {
                let Some(row) = state.supervision_by_id(&parsed.instance_id)? else {
                    return Ok(false);
                };
                let Some(evidence) = state.supervision_evidence(&parsed.instance_id)? else {
                    return Ok(false);
                };
                // Issue #272: the driver derives its one continuation from the
                // repair leg's OWN observable checkout (the observed delivery
                // of its fix round), so the SAME read is taken here before the
                // intent is re-derived: a dispatch the driver derived is never
                // refused for a fact the driver read.
                let mut evidence = evidence;
                let records = state.run_records(&parsed.instance_id)?;
                let worktrees_root = crate::supervision::recorded_worktrees_root_of(&records);
                crate::supervision::observe_fix_leg(&mut evidence, worktrees_root.as_deref());
                // Issue #184: only a DIAGNOSED step attempt reserves and
                // consumes supervision's own bounded retry. A recorded
                // refusal of the run's OWN lapsed window is not a step
                // diagnosis (the step never ran), so a lapse burns nothing.
                // Issue #241: an authorization the run already HOLDS — the
                // operator's `run.retry` — is consumed by this dispatch, the
                // re-dispatch it authorized, instead of refusing it
                // `refusal.run.retry_pending`; a consumed authorization is
                // spent exactly once (the row is single use).
                // Issue #272: the driver's re-collect of the run's own fix
                // delivery is a re-dispatch of a step that already SUCCEEDED,
                // so no attempt diagnoses it; it is counted against the same
                // per-(run, step) budget, which is what bounds how many times
                // the collector may be re-dispatched. It is the ONE
                // non-diagnosed re-dispatch that spends a bounded
                // authorization, and only while the driven intent is that
                // re-collect.
                let driven = crate::supervision::dispatch_intent(&row, &evidence);
                automatic_retry = evidence.attempts.iter().any(|(step, status, code)| {
                    step == &parsed.step && crate::state::step_attempt_diagnosed(status, code)
                }) || evidence
                    .retries
                    .iter()
                    .any(|retry| retry.step_id == parsed.step && retry.consumed_at.is_empty())
                    || driven.as_ref().is_some_and(|intent| {
                        intent.reason == crate::supervision::codes::RECOLLECT
                            && intent.step_id == parsed.step
                    });
                Ok(driven.is_some_and(|intent| intent.step_id == parsed.step))
            })();
            match eligible {
                Ok(true) => {}
                Ok(false) => {
                    return err_response(
                        &request.id,
                        crate::mutation::code::RETRY_REQUIRED,
                        "the supervised frontier is held, reserved or exhausted",
                    );
                }
                Err(err) => return err_response(&request.id, err.code, err.message),
            }
        }
        match state.journal_intent(
            &action,
            &target,
            &key,
            &request.id,
            &request.method,
            Some(&plan.digest),
            Some(&grant_id),
            &request.line,
        ) {
            Ok((ClaimAttempt::Claimed, _)) => {
                if automatic_retry
                    && let Err(err) = state.consume_supervised_retry(
                        &parsed.instance_id,
                        &parsed.step,
                        &time::rfc3339_now(),
                        &key,
                    )
                {
                    drop(state);
                    return resolve_apply_refusal(shared, request, &key, err.code, err.message);
                }
                true
            }
            Ok((ClaimAttempt::Replay { response }, _)) => return replay(shared, &response),
            Ok((ClaimAttempt::Reused { owner_request_id }, _)) => {
                return err_response(
                    &request.id,
                    "refusal.idempotency",
                    format!(
                        "idempotency key {key:?} already belongs to request {owner_request_id}"
                    ),
                );
            }
            Err(err) => return err_response(&request.id, err.code, err.message),
        }
    };
    let _ = journaled;
    let _claim = ApplyClaim {
        shared,
        request,
        key: &key,
    };
    // No publish here: every post-journal terminal path below publishes
    // once after its state change (hub-lock ordering rule).

    // Issue #184: a live run whose OWN authorization window lapsed mid-spine
    // renews it HERE — an audited `grant.rotation`-class successor sized from
    // the run's remaining committed spine — before any effect gate reads the
    // window, so a lapse can never strand the frontier behind
    // `refusal.run.retry_required` or burn a bounded retry the step never
    // spent. The renewal is the RUN's own act, gated on its own live binding
    // (own grant, same revision, live epoch, still owning its issue) and it
    // never widens caps, phase or scope; every foreign, revoked, stale-epoch,
    // released, paused, held or exhausted continuation is left to refuse
    // downstream exactly as before.
    let renewal = {
        let state = match shared.lock_state() {
            Ok(state) => state,
            Err(message) => {
                return resolve_apply_refusal(shared, request, &key, "state.unavailable", message);
            }
        };
        match state.renew_lapsed_run_grant(&parsed.instance_id, &grant_id, &time::rfc3339_now()) {
            Ok(renewal) => renewal,
            Err(err) => {
                drop(state);
                return resolve_apply_refusal(shared, request, &key, err.code, err.message);
            }
        }
    };
    if let Some(renewal) = &renewal {
        // The successor window is the run's own authorization from here on:
        // this dispatch, and the effect below it, read the renewed grant.
        parsed.grant_id = renewal.successor.grant_id.clone();
        shared.log.write(
            "info",
            "run.grant.renewed",
            &format!(
                "run {} renewed its own lapsed window: grant {} superseded by {} ({}s derived \
                 from the committed spine), expires {}",
                parsed.instance_id,
                renewal.superseded.grant_id,
                renewal.successor.grant_id,
                renewal.window_secs,
                renewal.successor.expires_at
            ),
        );
    }

    // Revalidate plan/grant/instance/epoch against FRESH state, then run
    // kind-specific gates that need durable state (evidence, closure).
    // Everything runs inside one state-guard scope; refusals are returned
    // as values and resolved only AFTER the guard drops (re-locking while
    // the guard is held would self-deadlock).
    type SnapshotOutcome = Result<
        (
            crate::mutation::GrantSnapshot,
            crate::mutation::InstanceSnapshot,
            Option<crate::mutation::EvidenceView>,
            Option<crate::state::ApprovalRow>,
        ),
        (String, String),
    >;
    let snapshot_outcome = (|| -> SnapshotOutcome {
        let state = shared
            .lock_state()
            .map_err(|message| ("state.unavailable".to_string(), message))?;
        let epoch = state
            .current_epoch()
            .map_err(|err| (err.code.to_string(), err.message))?;
        let grant = state
            .grant_by_id(&parsed.grant_id)
            .map_err(|err| (err.code.to_string(), err.message))?
            .ok_or_else(|| {
                (
                    "refusal.grant.inactive".to_string(),
                    format!("no grant {} exists", parsed.grant_id),
                )
            })?;
        let instance = state
            .instance_by_id(&parsed.instance_id)
            .map_err(|err| (err.code.to_string(), err.message))?
            .ok_or_else(|| {
                (
                    "refusal.instance.state".to_string(),
                    format!("no instance {} exists", parsed.instance_id),
                )
            })?;
        let caps = |text: &str| -> Vec<String> {
            Val::parse_json(text)
                .ok()
                .and_then(|value| value.as_array().cloned())
                .map(|items| {
                    items
                        .iter()
                        .filter_map(Val::as_str)
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default()
        };
        let grant_snapshot = crate::mutation::GrantSnapshot {
            grant_id: grant.grant_id.clone(),
            repository: grant.repository.clone(),
            issue_number: grant.issue_number,
            issue_revision: grant.issue_revision.clone(),
            workflow_hash: grant.workflow_hash.clone(),
            policy_hash: grant.policy_hash.clone(),
            phase: grant.phase.clone(),
            scope: grant.scope.clone(),
            caps: caps(&grant.caps),
            expires_at: grant.expires_at.clone(),
            status: grant.status.clone(),
            state_epoch: grant.state_epoch,
        };
        let instance_snapshot = crate::mutation::InstanceSnapshot {
            instance_id: instance.instance_id.clone(),
            repository: instance.repository.clone(),
            workflow_id: instance.workflow_id.clone(),
            workflow_hash: instance.workflow_hash.clone(),
            policy_hash: instance.policy_hash.clone(),
            grant_id: instance.grant_id.clone(),
            issue_number: instance.issue_number,
            issue_revision: instance.issue_revision.clone(),
            phase: instance.phase.clone(),
            scope: instance.scope.clone(),
            caps: caps(&instance.caps),
            current_node: instance.current_node.clone(),
            paused: instance.paused,
            pause_requested: instance.pause_requested,
            status: instance.status.clone(),
            state_epoch: instance.state_epoch,
        };
        let observed = crate::mutation::Observed {
            issue_revision: parsed.issue_revision.clone(),
            policy_hash: parsed.policy_hash.clone(),
            state_epoch: epoch,
            now: time::rfc3339_now(),
        };
        let evidence = state
            .evidence_for_instance(&parsed.instance_id)
            .ok()
            .and_then(|rows| rows.into_iter().next())
            .map(|row| crate::mutation::EvidenceView {
                evidence_id: row.evidence_id,
                feature_head: row.feature_head,
                integration_base: row.integration_base,
                workflow_hash: row.workflow_hash,
                policy_hash: row.policy_hash,
                verdict: row.verdict,
                reviewer: row.reviewer,
                checks: row.checks,
                created_at: row.created_at,
            });
        let approval = state
            .approval_for_scope("first-write-canary")
            .map_err(|err| (err.code.to_string(), err.message))?;
        crate::mutation::revalidate_effect(
            &plan,
            &kind,
            &grant_snapshot,
            &instance_snapshot,
            &observed,
        )
        .map_err(|err| (err.code.to_string(), err.message))?;
        // Kind-specific durable gates.
        match kind.as_str() {
            "merge" => {
                let Some(feature_head) = parsed.feature_head.clone() else {
                    return Err((
                        "refusal.malformed".to_string(),
                        "merge requires observed.feature_head".to_string(),
                    ));
                };
                let Some(integration_base) = parsed.integration_base.clone() else {
                    return Err((
                        "refusal.malformed".to_string(),
                        "merge requires observed.integration_base".to_string(),
                    ));
                };
                crate::mutation::check_merge_evidence(
                    evidence.as_ref(),
                    &feature_head,
                    &integration_base,
                    &instance_snapshot.workflow_hash,
                    &parsed.policy_hash,
                )
                .map_err(|err| (err.code.to_string(), err.message))?;
                check_certified_consumption(&state, &parsed.instance_id, &feature_head, "merge")?;
            }
            "review_evidence" => {
                // Issue #202 (AC2): the review step consumes a head too, and a
                // run may only ever review the head its OWN collection
                // certified. A review for a head no collection observed is a
                // typed refusal here, BEFORE the reviewer is started — never a
                // silent review of a head the run never bound, and never a
                // frontier that parks on an unconsumable verdict.
                if let Some(feature_head) = parsed.feature_head.clone() {
                    check_certified_consumption(
                        &state,
                        &parsed.instance_id,
                        &feature_head,
                        "review_evidence",
                    )?;
                }
            }
            "issue_update" => {
                let closing =
                    params.and_then(|p| p.get("action")).and_then(Val::as_str) == Some("close");
                if closing {
                    // The closure gate keys on the post-merge-verify STEP of
                    // THIS plan (step ids are plan-local slugs; the engine
                    // persists the achieved step id as current_node). The
                    // refusal decision itself is the single unit-tested
                    // gate in mutation.rs (check_issue_closure) — the daemon
                    // calls it here and nowhere else.
                    let verify_step = plan
                        .doc
                        .get("steps")
                        .and_then(Val::as_array)
                        .and_then(|steps| {
                            steps.iter().find(|step| {
                                step.get("kind").and_then(Val::as_str) == Some("post_merge_verify")
                            })
                        })
                        .and_then(|step| step.get("id").and_then(Val::as_str))
                        .unwrap_or("")
                        .to_string();
                    if verify_step.is_empty() {
                        return Err((
                            "refusal.malformed".to_string(),
                            "the plan has no post_merge_verify step; closure is not routable"
                                .to_string(),
                        ));
                    }
                    crate::mutation::check_issue_closure(
                        evidence.as_ref(),
                        &instance_snapshot.current_node,
                        &verify_step,
                    )
                    .map_err(|err| (err.code.to_string(), err.message))?;
                }
            }
            _ => {}
        }
        Ok((grant_snapshot, instance_snapshot, evidence, approval))
    })();
    let (grant_snapshot, instance_snapshot, latest_evidence, approval) = match snapshot_outcome {
        Ok(bundle) => bundle,
        Err((code, message)) => {
            return resolve_apply_refusal(shared, request, &key, &code, message);
        }
    };

    // The AC10 gate runs before any effect that declares a real external
    // target scope (fakes only in this slice; the real canary is a later
    // separately approved step).
    if matches!(risk, "production" | "destructive")
        && let Err(err) = crate::mutation::check_first_write_approval(
            approval.as_ref(),
            parsed.target_scope.as_deref(),
        )
    {
        return resolve_apply_refusal(shared, request, &key, err.code, err.message);
    }
    let _ = latest_evidence;

    // Bounded retry fence (issue #86), queue runs only: a re-dispatch of a
    // step whose recorded outcome was a terminal non-success requires (and
    // consumes) exactly one recorded retry authorization; a first dispatch
    // is never fenced. A missing authorization refuses BEFORE the effect.
    let bounded_step = {
        let state = match shared.lock_state() {
            Ok(state) => state,
            Err(message) => {
                return resolve_apply_refusal(shared, request, &key, "state.unavailable", message);
            }
        };
        match state.run_step_spine(&parsed.instance_id) {
            Ok(spine) => spine
                .map(|steps| steps.iter().any(|step| step == &parsed.step))
                .unwrap_or(false),
            Err(err) => {
                drop(state);
                return resolve_apply_refusal(shared, request, &key, err.code, err.message);
            }
        }
    };
    if bounded_step {
        let claim = {
            let state = match shared.lock_state() {
                Ok(state) => state,
                Err(message) => {
                    return resolve_apply_refusal(
                        shared,
                        request,
                        &key,
                        "state.unavailable",
                        message,
                    );
                }
            };
            state.claim_run_retry(
                &parsed.instance_id,
                &parsed.step,
                &key,
                &time::rfc3339_now(),
            )
        };
        match claim {
            Ok(crate::state::RunRetryClaim::NotRequired)
            | Ok(crate::state::RunRetryClaim::Consumed(_)) => {}
            Ok(crate::state::RunRetryClaim::Missing) => {
                return resolve_apply_refusal(
                    shared,
                    request,
                    &key,
                    crate::mutation::code::RETRY_REQUIRED,
                    format!(
                        "step {:?} of run {} already has a recorded failed attempt; a re-dispatch \
                         needs an unconsumed bounded retry authorization (`run.retry`)",
                        parsed.step, parsed.instance_id
                    ),
                );
            }
            Err(err) => {
                return resolve_apply_refusal(shared, request, &key, err.code, err.message);
            }
        }
    }

    // Execute the effect OUTSIDE the state lock (bounded subprocesses never
    // stall other daemon work; the claim already journals the intent).
    let effect_env = crate::config::adapter_environment();
    // Issue #92 F2: a harness step of a run with a committed submission runs
    // the run's DECLARED role configuration and the session this run bound —
    // both resolved from durable state here, never from a step-param default
    // and never from a profile the caller names.
    let presented_profile = match presented_profile(request.params.as_ref()) {
        Ok(profile) => profile,
        Err((code, message)) => {
            return resolve_apply_refusal(shared, request, &key, code, message);
        }
    };
    let run_binding = match resolve_run_binding(
        shared,
        &parsed.instance_id,
        &kind,
        presented_profile.as_ref(),
    ) {
        Ok(binding) => binding,
        Err((code, message)) => {
            return resolve_apply_refusal(shared, request, &key, &code, message);
        }
    };
    // Issue #190: a lane workspace is part of a generation's residue, and the
    // RETIRED generations of this repository issue — resolved from the run
    // ledger here, never from the substrate — are what a bind step may
    // retire before it binds the new generation. A live lane is never in this
    // set (a run that is not terminal still holds its issue's ownership), so
    // the retire can never close a live generation's workspace. Only a bind
    // step can retire, so nothing else pays for the resolution.
    //
    // Issue #222: `worktree_create` resolves the SAME set — the same issue's
    // terminal generations also leave the lane checkout and the local lane
    // branch behind in the integration clone, and those are what block the
    // next run's lane creation. The resolution is scoped to this repository
    // issue, so a sibling issue's run can never be in it.
    //
    // Issue #224: `review_evidence` resolves it too — the reviewer leg BINDS
    // its own lane generation (`ensure_reviewer_lane`), and the 30 measured
    // p6 receipts' residue was exactly that leg's registration, pane and
    // checkout outliving its completed run, refusing the next run's bind with
    // `refusal.lane.name_collision`. One fact, one place: the closed set lives
    // in [`lane_binding_step_kind`].
    let retired_run_ids: Vec<String> = if lane_binding_step_kind(&kind) {
        let state = match shared.lock_state() {
            Ok(state) => state,
            Err(message) => {
                return resolve_apply_refusal(shared, request, &key, "state.unavailable", message);
            }
        };
        match resolved_lane_generations(&state, &plan.repository, plan.issue_number, &kind) {
            Ok(ids) => ids,
            Err(err) => {
                drop(state);
                return resolve_apply_refusal(shared, request, &key, err.code, err.message);
            }
        }
    } else {
        Vec::new()
    };
    // Issue #193: the reviewer's OWN written verdict is consumed from the
    // daemon-owned review root (outside every lane worktree, so a reviewer's
    // write never dirties the lane the cleanup step must remove).
    let review_root = shared.paths.state_dir.join("reviews");
    let ctx = crate::mutation::EffectContext {
        plan: &plan,
        step_id: &parsed.step,
        kind: &kind,
        params,
        repository: &plan.repository,
        integration_branch: &parsed.integration_branch,
        production_branches: &parsed.production_branches,
        publish_route: &parsed.integration_publish,
        worktrees_root: &parsed.worktrees_root,
        integration_repo: &parsed.integration_repo,
        archive_root: parsed.archive_root.as_deref(),
        review_root: Some(review_root.as_path()),
        observed_feature_head: parsed.feature_head.as_deref(),
        observed_integration_base: parsed.integration_base.as_deref(),
        env: &effect_env,
        role: run_binding.role.as_ref(),
        session: run_binding.session.as_ref(),
        retired_run_ids: &retired_run_ids,
    };
    let effect = crate::mutation::execute_step(&ctx);
    let mut result = effect.result;
    let effect_status = effect.status;
    let effect_code = effect.code.clone();
    let effect_message = effect.message.clone();
    if effect_status == "succeeded" {
        match kind.as_str() {
            "review_evidence" => {
                let state = match shared.lock_state() {
                    Ok(state) => state,
                    Err(message) => {
                        return finish_apply_refused(
                            shared,
                            request,
                            &key,
                            &action,
                            &plan.plan_id,
                            &parsed.step,
                            "state.unavailable",
                            message,
                        );
                    }
                };
                let checks = result.get("checks").cloned().unwrap_or_else(null);
                let repository = result
                    .get("repository")
                    .and_then(Val::as_str)
                    .unwrap_or("")
                    .to_string();
                let feature_head = result
                    .get("feature_head")
                    .and_then(Val::as_str)
                    .unwrap_or("")
                    .to_string();
                let integration_base = result
                    .get("integration_base")
                    .and_then(Val::as_str)
                    .unwrap_or("")
                    .to_string();
                let verdict = result
                    .get("verdict")
                    .and_then(Val::as_str)
                    .unwrap_or("")
                    .to_string();
                let reviewer = result
                    .get("reviewer")
                    .and_then(Val::as_str)
                    .unwrap_or("")
                    .to_string();
                match state.record_evidence(
                    &parsed.instance_id,
                    &repository,
                    &feature_head,
                    &integration_base,
                    &plan.workflow_hash,
                    &parsed.policy_hash,
                    &verdict,
                    &reviewer,
                    &checks,
                ) {
                    Ok(row) => {
                        let mut fields = match result {
                            Val::Obj(map) => map,
                            _ => unreachable!(),
                        };
                        fields.insert("evidence_id".to_string(), string(&row.evidence_id));
                        fields.insert("recorded_at".to_string(), string(&row.created_at));
                        result = Val::Obj(fields);
                    }
                    Err(err) => {
                        drop(state);
                        return finish_apply_refused(
                            shared,
                            request,
                            &key,
                            &action,
                            &plan.plan_id,
                            &parsed.step,
                            err.code,
                            err.message,
                        );
                    }
                }
            }
            "cleanup" => {
                // AC8: after the destructive effect succeeded, preserve the
                // required salvage evidence as a post-deletion audit record
                // (the mutate.cleanup intent is the pre-effect record).
                let state = match shared.lock_state() {
                    Ok(state) => state,
                    Err(message) => {
                        return finish_apply_refused(
                            shared,
                            request,
                            &key,
                            &action,
                            &plan.plan_id,
                            &parsed.step,
                            "state.unavailable",
                            message,
                        );
                    }
                };
                let salvage_target = params
                    .and_then(|p| p.get("worktree"))
                    .and_then(Val::as_str)
                    .unwrap_or("");
                if let Err(err) = state.journal_salvage(
                    &format!("{}:{}", plan.repository, salvage_target),
                    &parsed.instance_id,
                ) {
                    drop(state);
                    return finish_apply_refused(
                        shared,
                        request,
                        &key,
                        &action,
                        &plan.plan_id,
                        &parsed.step,
                        err.code,
                        err.message,
                    );
                }
            }
            "approve" => {
                let state = match shared.lock_state() {
                    Ok(state) => state,
                    Err(message) => {
                        return finish_apply_refused(
                            shared,
                            request,
                            &key,
                            &action,
                            &plan.plan_id,
                            &parsed.step,
                            "state.unavailable",
                            message,
                        );
                    }
                };
                let digest = result
                    .get("digest")
                    .and_then(Val::as_str)
                    .unwrap_or("")
                    .to_string();
                let interactive = matches!(result.get("interactive"), Some(Val::Bool(true)));
                match state.record_approval("first-write-canary", &digest, interactive) {
                    Ok(row) => {
                        let mut fields = match result {
                            Val::Obj(map) => map,
                            _ => unreachable!(),
                        };
                        fields.insert("approval_id".to_string(), string(&row.approval_id));
                        fields.insert("recorded_at".to_string(), string(&row.recorded_at));
                        result = Val::Obj(fields);
                    }
                    Err(err) => {
                        drop(state);
                        return finish_apply_refused(
                            shared,
                            request,
                            &key,
                            &action,
                            &plan.plan_id,
                            &parsed.step,
                            err.code,
                            err.message,
                        );
                    }
                }
            }
            _ => {}
        }
    }
    drop(grant_snapshot);
    drop(instance_snapshot);

    // Note the achieved step on the instance (current_node), then resolve
    // the claim with the typed outcome (succeeded/failed/refused/ambiguous).
    let state = match shared.lock_state() {
        Ok(state) => state,
        Err(message) => {
            shared.log.write(
                "error",
                "outcome.journal_failed",
                &format!("state lock lost: {message}"),
            );
            return err_response(
                &request.id,
                "state.unavailable",
                "the mutation effect completed but its outcome could not be journaled (fail closed)",
            );
        }
    };
    if effect_status == "succeeded"
        && let Err(err) = state.advance_instance(
            &parsed.instance_id,
            &parsed.step,
            0,
            0,
            false,
            0,
            &time::rfc3339_now(),
        )
    {
        // The effect already landed; a failed node advance must never
        // silently succeed — journal the drift so the outcome stays
        // auditable (kind-gates re-derive most drift, but the record
        // must exist).
        shared.log.write(
            "error",
            "outcome.advance_failed",
            &format!(
                "instance {} did not advance to {} after a succeeded {}: {}",
                parsed.instance_id, parsed.step, action, err.message
            ),
        );
    }
    let response = resolve_apply_effect(
        &state,
        &shared.log,
        request,
        &key,
        &action,
        &plan.plan_id,
        &parsed.step,
        &crate::mutation::EffectOutcome {
            status: effect_status,
            code: effect_code,
            message: effect_message,
            result: null(),
        },
        result,
    );
    // Issue #86: the step resolved (the claim is no longer in flight) — a
    // recorded pause request reaches its safe boundary here and commits
    // `paused`. The in-flight work was never interrupted: the effect ran to
    // its recorded outcome with its worktree and dirty state untouched.
    if let Err(err) = state.complete_run_pause_boundary(&parsed.instance_id, &time::rfc3339_now()) {
        shared.log.write(
            "error",
            "run.pause.boundary_failed",
            &format!("{}: {}", err.code, err.message),
        );
    }
    drop(state);
    publish_after_state_change(shared, None);
    response
}

/// Resolve an apply whose preconditions refused before any effect ran.
fn resolve_apply_refusal(
    shared: &Arc<Shared>,
    request: &Request,
    key: &str,
    code: &str,
    message: String,
) -> String {
    let state = match shared.lock_state() {
        Ok(state) => state,
        Err(lock_message) => {
            return err_response(&request.id, "state.unavailable", lock_message);
        }
    };
    let outcome = apply_outcome(
        crate::daemon::DAEMON_PLAN_ID,
        crate::daemon::DAEMON_STEP_ID,
        key,
        "refused",
        null(),
        Some((code, message.clone())),
    );
    let response = err_response(&request.id, code, message);
    let resolved = match state.resolve_claim(
        key,
        &request.method,
        "spent",
        &canonical_text(&outcome),
        Some(&response),
    ) {
        Ok(_) => response,
        Err(err) => {
            shared.log.write(
                "error",
                "outcome.journal_failed",
                &format!("{}: {}", err.code, err.message),
            );
            err_response(
                &request.id,
                err.code,
                format!(
                    "the refusal could not be journaled (fail closed): {}",
                    err.message
                ),
            )
        }
    };
    drop(state);
    publish_after_state_change(shared, None);
    resolved
}

/// Resolve an apply whose post-effect durable record failed (the effect
/// itself must be treated as ambiguous: its external side effects may have
/// happened even though the record could not be stored).
#[allow(clippy::too_many_arguments)]
fn finish_apply_refused(
    shared: &Arc<Shared>,
    request: &Request,
    key: &str,
    action: &str,
    plan_id: &str,
    step_id: &str,
    code: &'static str,
    message: String,
) -> String {
    let state = match shared.lock_state() {
        Ok(state) => state,
        Err(lock_message) => {
            return err_response(&request.id, "state.unavailable", lock_message);
        }
    };
    let outcome = apply_outcome(
        plan_id,
        step_id,
        key,
        "ambiguous",
        null(),
        Some((code, message.clone())),
    );
    let response = err_response(&request.id, code, message);
    let resolved = match state.resolve_claim(
        key,
        action,
        "ambiguous",
        &canonical_text(&outcome),
        Some(&response),
    ) {
        Ok(_) => response,
        Err(err) => {
            shared.log.write(
                "error",
                "outcome.journal_failed",
                &format!("{}: {}", err.code, err.message),
            );
            err_response(
                &request.id,
                err.code,
                format!(
                    "the outcome could not be journaled (fail closed): {}",
                    err.message
                ),
            )
        }
    };
    drop(state);
    publish_after_state_change(shared, None);
    resolved
}

/// Resolve a claimed apply effect with its typed outcome (AC1): the outcome
/// status mirrors the effect status; the response records the exact
/// read-back result on success.
#[allow(clippy::too_many_arguments)]
fn resolve_apply_effect(
    state: &State,
    log: &DaemonLog,
    request: &Request,
    key: &str,
    action: &str,
    plan_id: &str,
    step_id: &str,
    effect: &crate::mutation::EffectOutcome,
    result: Val,
) -> String {
    let succeeded = effect.status == "succeeded";
    let (claim_status, response, outcome) = if succeeded {
        // Keep the read-back identity in BOTH the response and the durable
        // start outcome, so journal replay never loses the created agent.
        let journal_result = if action == "mutate.harness_start" {
            result.clone()
        } else {
            null()
        };
        let response = ok_response(&request.id, result);
        (
            "spent",
            response.clone(),
            apply_outcome(plan_id, step_id, key, "succeeded", journal_result, None),
        )
    } else {
        let code = effect
            .code
            .clone()
            .unwrap_or_else(|| "effect.failed".to_string());
        let message = effect
            .message
            .clone()
            .unwrap_or_else(|| "effect failed".to_string());
        let response = err_response(&request.id, &code, &message);
        let claim_status = if effect.status == "ambiguous" {
            "ambiguous"
        } else {
            "spent"
        };
        (
            claim_status,
            response.clone(),
            apply_outcome(
                plan_id,
                step_id,
                key,
                effect.status,
                null(),
                Some((code.as_str(), message)),
            ),
        )
    };
    match state.resolve_claim(
        key,
        action,
        claim_status,
        &canonical_text(&outcome),
        Some(&response),
    ) {
        Ok(_) => response,
        Err(err) => {
            log.write(
                "error",
                "outcome.journal_failed",
                &format!("{}: {}", err.code, err.message),
            );
            err_response(
                &request.id,
                err.code,
                format!(
                    "the mutation effect completed but its outcome could not be journaled \
                     (fail closed): {}",
                    err.message
                ),
            )
        }
    }
}

/// A typed hf-outcome/v1 document for one applied plan step.
fn apply_outcome(
    plan_id: &str,
    step_id: &str,
    key: &str,
    status: &str,
    result: Val,
    error: Option<(&str, String)>,
) -> Val {
    let failed = matches!(status, "failed" | "refused" | "ambiguous");
    object(vec![
        ("schema", string("hf-outcome/v1")),
        ("plan_id", string(plan_id)),
        ("step_id", string(step_id)),
        ("status", string(status)),
        ("idempotency_key", string(key)),
        ("observed_at", string(&time::rfc3339_now())),
        ("result", if failed { null() } else { result }),
        (
            "error",
            match error {
                Some((code, message)) => error_val(code, &message),
                None => null(),
            },
        ),
    ])
}

fn method_schedules(shared: &Arc<Shared>, request: &Request) -> String {
    match shared.lock_state() {
        Ok(state) => match state.list_schedules() {
            Ok(schedules) => ok_response(
                &request.id,
                object(vec![("schedules", Val::Arr(schedules))]),
            ),
            Err(err) => err_response(&request.id, err.code, err.message),
        },
        Err(message) => err_response(&request.id, "state.unavailable", message),
    }
}

/// `schedules.create`: upsert a validated hf-schedule/v1 document (issue
/// #9). Create (or re-arm) resets the cadence: enabled, due immediately,
/// one fresh evaluation — never a replay of missed windows. The durable
/// intent is journaled before the row write like every daemon mutation.
fn method_schedule_create(shared: &Arc<Shared>, request: &Request) -> String {
    let doc = match request
        .params
        .as_ref()
        .and_then(|params| params.get("schedule"))
    {
        Some(Val::Obj(_)) => request
            .params
            .as_ref()
            .and_then(|params| params.get("schedule"))
            .expect("checked")
            .clone(),
        _ => {
            return err_response(
                &request.id,
                "refusal.malformed",
                "schedules.create requires params.schedule (hf-schedule/v1 document)",
            );
        }
    };
    let verdict = crate::schema::validate_doc(crate::schema::Family::Schedule, &doc);
    if !verdict.is_accepted() {
        return err_response(
            &request.id,
            "refusal.malformed",
            format!("schedule document refused: {}", verdict.message()),
        );
    }
    let schedule_id = doc
        .get("schedule_id")
        .and_then(Val::as_str)
        .unwrap_or_default()
        .to_string();
    let target = format!("schedule:{schedule_id}");
    match journal_mutation(shared, request, "mutate.schedule.create", &target) {
        Intent::Claimed { key } => {
            let outcome = {
                let state = match shared.lock_state() {
                    Ok(state) => state,
                    Err(message) => {
                        return err_response(&request.id, "state.unavailable", message);
                    }
                };
                match state.upsert_schedule(&doc) {
                    Ok(row) => Ok(object(vec![("schedule", crate::state::schedule_val(&row))])),
                    Err(err) => Err((err.code, err.message)),
                }
            };
            match outcome {
                Ok(result) => {
                    finish_mutation(shared, request, &key, "schedule.create", true, result, None)
                }
                Err((code, message)) => finish_mutation(
                    shared,
                    request,
                    &key,
                    "schedule.create",
                    false,
                    null(),
                    Some((code, message)),
                ),
            }
        }
        Intent::Replay { response } => replay(shared, &response),
        Intent::Refused { code, message } => err_response(&request.id, code, message),
    }
}

/// `schedules.pause` / `schedules.resume`: durable pause/resume of a
/// schedule (issue #9 AC2/AC3). A paused schedule stays paused across
/// daemon/service/host restarts; nothing in the evaluation path ever
/// enables it (resume is an explicit human RPC that also resets the window
/// to due-now for one fresh evaluation).
fn method_schedule_pause(shared: &Arc<Shared>, request: &Request) -> String {
    method_schedule_set_enabled(shared, request, false)
}

fn method_schedule_resume(shared: &Arc<Shared>, request: &Request) -> String {
    method_schedule_set_enabled(shared, request, true)
}

fn method_schedule_set_enabled(shared: &Arc<Shared>, request: &Request, enabled: bool) -> String {
    let schedule_id = match request
        .params
        .as_ref()
        .and_then(|params| params.get("schedule_id"))
        .and_then(Val::as_str)
    {
        Some(text) if crate::formats::is_schedule_id(text) => text.to_string(),
        _ => {
            return err_response(
                &request.id,
                "refusal.malformed",
                "schedule_id must be an sd_ id",
            );
        }
    };
    let action = if enabled {
        "mutate.schedule.resume"
    } else {
        "mutate.schedule.pause"
    };
    let target = format!("schedule:{schedule_id}");
    match journal_mutation(shared, request, action, &target) {
        Intent::Claimed { key } => {
            let outcome = {
                let state = match shared.lock_state() {
                    Ok(state) => state,
                    Err(message) => {
                        return err_response(&request.id, "state.unavailable", message);
                    }
                };
                match state.set_schedule_enabled(&schedule_id, enabled, &time::rfc3339_now()) {
                    Ok(row) => Ok(object(vec![("schedule", crate::state::schedule_val(&row))])),
                    Err(err) => Err((err.code, err.message)),
                }
            };
            match outcome {
                Ok(result) => finish_mutation(
                    shared,
                    request,
                    &key,
                    if enabled {
                        "schedule.resume"
                    } else {
                        "schedule.pause"
                    },
                    true,
                    result,
                    None,
                ),
                Err((code, message)) => finish_mutation(
                    shared,
                    request,
                    &key,
                    if enabled {
                        "schedule.resume"
                    } else {
                        "schedule.pause"
                    },
                    false,
                    null(),
                    Some((code, message)),
                ),
            }
        }
        Intent::Replay { response } => replay(shared, &response),
        Intent::Refused { code, message } => err_response(&request.id, code, message),
    }
}

/// `schedules.delete`: delete a schedule row (daemon-mediated; the deletion
/// intent is journaled first — deleting schedule state is itself a
/// journaled destructive daemon-state operation).
fn method_schedule_delete(shared: &Arc<Shared>, request: &Request) -> String {
    let schedule_id = match request
        .params
        .as_ref()
        .and_then(|params| params.get("schedule_id"))
        .and_then(Val::as_str)
    {
        Some(text) if crate::formats::is_schedule_id(text) => text.to_string(),
        _ => {
            return err_response(
                &request.id,
                "refusal.malformed",
                "schedule_id must be an sd_ id",
            );
        }
    };
    let target = format!("schedule:{schedule_id}");
    match journal_mutation(shared, request, "mutate.schedule.delete", &target) {
        Intent::Claimed { key } => {
            let outcome = {
                let state = match shared.lock_state() {
                    Ok(state) => state,
                    Err(message) => {
                        return err_response(&request.id, "state.unavailable", message);
                    }
                };
                match state.delete_schedule(&schedule_id) {
                    Ok(()) => Ok(object(vec![
                        ("schedule_id", string(&schedule_id)),
                        ("deleted", bool_(true)),
                    ])),
                    Err(err) => Err((err.code, err.message)),
                }
            };
            match outcome {
                Ok(result) => {
                    finish_mutation(shared, request, &key, "schedule.delete", true, result, None)
                }
                Err((code, message)) => finish_mutation(
                    shared,
                    request,
                    &key,
                    "schedule.delete",
                    false,
                    null(),
                    Some((code, message)),
                ),
            }
        }
        Intent::Replay { response } => replay(shared, &response),
        Intent::Refused { code, message } => err_response(&request.id, code, message),
    }
}

/// `schedules.evaluate`: run one fresh evaluation tick (issue #9 AC2).
/// Each due schedule fires at most ONCE and persists its next window
/// atomically with its journal record; refused schedules park themselves;
/// a second evaluate in the same tick is a no-op (single-flight). The
/// optional `observed` params attest the live policy hash / issue revision
/// (same client-attestation boundary as apply); a mismatch parks the
/// schedule with `policy_changed`/`issue_changed`. Evaluations are not
/// idempotency-claimed: a crash between window advance and journal leaves
/// at most one extra fresh evaluation, never a backlog replay.
fn method_schedule_evaluate(shared: &Arc<Shared>, request: &Request) -> String {
    let params = request.params.as_ref();
    let schedule_id = match params
        .and_then(|params| params.get("schedule_id"))
        .and_then(Val::as_str)
    {
        Some(text) if crate::formats::is_schedule_id(text) => Some(text.to_string()),
        Some(_) => {
            return err_response(
                &request.id,
                "refusal.malformed",
                "schedule_id must be an sd_ id when present",
            );
        }
        None => None,
    };
    let attest = params
        .and_then(|params| params.get("observed"))
        .and_then(|observed| {
            let policy_hash = observed.get("policy_hash").and_then(Val::as_str);
            let issue_revision = observed.get("issue_revision").and_then(Val::as_str);
            match (policy_hash, issue_revision) {
                (Some(policy_hash), Some(issue_revision))
                    if crate::formats::is_hex64(policy_hash)
                        && crate::formats::is_hex40(issue_revision) =>
                {
                    Some(crate::lifecycle::ScheduleAttest {
                        policy_hash,
                        issue_revision,
                    })
                }
                _ => None,
            }
        });
    let state = match shared.lock_state() {
        Ok(state) => state,
        Err(message) => return err_response(&request.id, "state.unavailable", message),
    };
    let now_unix = time::unix_now();
    let summary = match &schedule_id {
        Some(id) => {
            match crate::lifecycle::reconcile_schedule(&state, id, now_unix, attest.as_ref()) {
                Ok(Some(summary)) => summary,
                Ok(None) => {
                    return err_response(
                        &request.id,
                        "refusal.schedule.not_found",
                        format!("no schedule {id:?} exists"),
                    );
                }
                Err(err) => return err_response(&request.id, err.code, err.message),
            }
        }
        None => match crate::lifecycle::reconcile_schedules(&state, now_unix, attest.as_ref()) {
            Ok(summary) => summary,
            Err(err) => return err_response(&request.id, err.code, err.message),
        },
    };
    drop(state);
    ok_response(
        &request.id,
        object(vec![
            ("evaluated", integer(summary.total() as i64)),
            (
                "ran",
                Val::Arr(summary.ran.iter().map(|id| string(id)).collect()),
            ),
            (
                "paused",
                Val::Arr(
                    summary
                        .paused
                        .iter()
                        .map(|(id, reason)| {
                            object(vec![
                                ("schedule_id", string(id)),
                                ("reason", string(reason)),
                            ])
                        })
                        .collect(),
                ),
            ),
            ("idle", integer(summary.idle.len() as i64)),
        ]),
    )
}

fn method_grants_list(shared: &Arc<Shared>, request: &Request) -> String {
    match shared.lock_state() {
        Ok(state) => match state.list_grants() {
            Ok(rows) => {
                let grants: Vec<Val> = rows.iter().map(grant_doc).collect();
                ok_response(&request.id, object(vec![("grants", Val::Arr(grants))]))
            }
            Err(err) => err_response(&request.id, err.code, err.message),
        },
        Err(message) => err_response(&request.id, "state.unavailable", message),
    }
}

// ---------------------------------------------------------------------------
// Queue executor (issue #85): the durable selected-run submission path
// ---------------------------------------------------------------------------

/// `queue.submit`: commit ONE approved selected-issue run — the executor
/// slice that consumes the #84 preview digest.
///
/// Every refusal happens BEFORE the claim (nothing is journaled and no
/// effect exists): malformed params, a digest that does not match the
/// freshly re-rendered preview, a stale epoch, a moved profile
/// configuration revision, an unsupported/unresolved step spine, a
/// production-class or protected completion boundary. After the claim, the
/// whole submission — the durable binding, the persisted membership with
/// per-issue admitted/waiting/refused outcomes, and every admitted run with
/// its unique ownership row — commits in ONE transaction that re-verifies
/// ownership, grant status/expiry, overlap and capacity under the guard.
/// The transaction NEVER spawns a process or executes a step: step
/// execution stays with the merged `apply` machinery.
fn method_queue_submit(shared: &Arc<Shared>, request: &Request) -> String {
    let Some(params) = request.params.as_ref() else {
        return err_response(
            &request.id,
            "refusal.malformed",
            "queue.submit requires params: digest, epoch, preview, binding, role_revision, caps, \
             observations[, grants, resume]",
        );
    };
    let material = match crate::queue_executor::parse_params(params) {
        Ok(material) => material,
        Err(err) => return err_response(&request.id, err.code, err.message),
    };
    let submission_id =
        crate::queue_executor::submission_id(&material.digest, &material.idempotency_key);
    let revalidated = {
        let state = match shared.lock_state() {
            Ok(state) => state,
            Err(message) => return err_response(&request.id, "state.unavailable", message),
        };
        crate::queue_executor::revalidate(&state, &material)
    };
    let revalidated = match revalidated {
        Ok(revalidated) => revalidated,
        Err(err) => return err_response(&request.id, err.code, err.message),
    };
    let target = format!("queue:{submission_id}");
    let key = match journal_mutation(shared, request, "mutate.queue.submit", &target) {
        Intent::Claimed { key } => key,
        Intent::Replay { response } => return replay(shared, &response),
        Intent::Refused { code, message } => return err_response(&request.id, code, &message),
    };
    crash_point("queue.after-intent");
    let request_line = canonical_text(
        &revalidated
            .preview
            .doc
            .get("request")
            .cloned()
            .unwrap_or_else(|| material.preview.clone()),
    );
    let plan = crate::state::QueueSubmissionPlan {
        submission_id: submission_id.clone(),
        repository: revalidated.request.repository.clone(),
        state_epoch: material.epoch,
        digest: material.digest.clone(),
        role_key: revalidated.request.harness_key.clone(),
        role_revision: material.role_revision.clone(),
        workflow_id: revalidated.request.workflow_id.clone(),
        workflow_hash: revalidated.request.workflow_hash.clone(),
        boundary_phase: revalidated.request.boundary.phase.clone(),
        integration_branch: revalidated.request.boundary.integration_branch.clone(),
        completion_branch: revalidated.request.boundary.completion_branch.clone(),
        boundary_caps: revalidated.request.boundary.caps.clone(),
        request_line,
        admission_caps: material.caps,
        harness_lanes: material.harness_lanes,
        // Issue #95: the supervision authorization rides with the approval;
        // absent means supervision stays disabled for every admitted run.
        supervision: material.supervision.as_ref().map(|authorization| {
            crate::state::SupervisionAuthorizationPlan {
                desired: authorization.desired.clone(),
                check_interval_secs: authorization.policy.check_interval_secs,
                progress_timeout_secs: authorization.policy.progress_timeout_secs,
            }
        }),
        items: revalidated
            .items
            .iter()
            .enumerate()
            .map(|(ordinal, item)| crate::state::QueueSubmissionItemPlan {
                ordinal: ordinal as i64,
                work_item: item.work_item.clone(),
                issue_number: item.issue_number,
                issue_revision: item.revision.clone(),
                grant_id: item.grant_id.clone(),
                resume_digest: item.resume_digest.clone(),
                verdict: item.verdict.clone(),
            })
            .collect(),
        at: time::rfc3339_now(),
    };
    let guard = match shared.lock_state() {
        Ok(guard) => guard,
        Err(message) => return err_response(&request.id, "state.unavailable", message),
    };
    let response = match guard.submit_queue_run(&plan) {
        Ok((row, items)) => {
            // The submission committed: an interrupt from here on is the
            // "committed, unresolved" restart window (reconciled from the
            // commit marker, never re-executed).
            crash_point("queue.after-commit");
            let advances = guard
                .queue_advance_rows(&row.submission_id)
                .unwrap_or_default();
            let doc = crate::queue_executor::submission_doc(&row, &items, &advances);
            resolve_mutation_on(
                &guard,
                &shared.log,
                request,
                &key,
                "queue.submit",
                true,
                doc,
                None,
            )
        }
        Err(err) => resolve_mutation_on(
            &guard,
            &shared.log,
            request,
            &key,
            "queue.submit",
            false,
            null(),
            Some((err.code, err.message)),
        ),
    };
    drop(guard);
    publish_after_state_change(shared, None);
    response
}

/// `queue.status`: read one committed submission back. The document is the
/// same pure projection of the committed rows the original submission
/// response carried, so the CLI/JSON readback and the daemon readback agree
/// by construction.
fn method_queue_status(shared: &Arc<Shared>, request: &Request) -> String {
    let Some(submission_id) = request
        .params
        .as_ref()
        .and_then(|params| params.get("submission_id"))
        .and_then(Val::as_str)
        .filter(|text| crate::formats::is_submission_id(text))
    else {
        return err_response(
            &request.id,
            "refusal.malformed",
            "queue.status requires params.submission_id (qs_ + 16 hex)",
        );
    };
    match shared.lock_state() {
        Ok(state) => match state.queue_submission_by_id(submission_id) {
            Ok(Some((row, items))) => {
                let advances = state
                    .queue_advance_rows(&row.submission_id)
                    .unwrap_or_default();
                ok_response(
                    &request.id,
                    crate::queue_executor::submission_doc(&row, &items, &advances),
                )
            }
            Ok(None) => err_response(
                &request.id,
                "state.not_found",
                format!("no submission {submission_id:?} exists"),
            ),
            Err(err) => err_response(&request.id, err.code, err.message),
        },
        Err(message) => err_response(&request.id, "state.unavailable", message),
    }
}

/// `queue.redrive`: re-evaluate ONE committed submission's parked items
/// against the live fan-out capacity (#236). The operator control that
/// recovers a submission stranded by a transient cap — the #96 cursor only
/// moves on a verified delivery, so a parked submission had no way back.
///
/// Bounded to exactly that submission and audited: only its own `waiting`
/// items are re-evaluated, through the SAME approved admission inputs and
/// the SAME guard-verifying helper the submission and the advance use;
/// nothing is spawned, nothing is killed, no lane is touched, and the request
/// journals one mutation claim like every other control on this surface.
fn method_queue_redrive(shared: &Arc<Shared>, request: &Request) -> String {
    let Some(submission_id) = request
        .params
        .as_ref()
        .and_then(|params| params.get("submission_id"))
        .and_then(Val::as_str)
        .filter(|text| crate::formats::is_submission_id(text))
    else {
        return err_response(
            &request.id,
            "refusal.malformed",
            "queue.redrive requires params.submission_id (qs_ + 16 hex)",
        );
    };
    let target = format!("queue-redrive:{submission_id}");
    let key = match journal_mutation(shared, request, "mutate.queue.redrive", &target) {
        Intent::Claimed { key } => key,
        Intent::Replay { response } => return replay(shared, &response),
        Intent::Refused { code, message } => return err_response(&request.id, code, &message),
    };
    let at = time::rfc3339_now();
    let state = match shared.lock_state() {
        Ok(state) => state,
        Err(message) => return err_response(&request.id, "state.unavailable", message),
    };
    if let Err(err) = state.redrive_queue_submission(submission_id, &key, &at) {
        return err_response(&request.id, err.code, err.message);
    }
    // The same pure projection `queue status` reads back, so the operator's
    // before/after read agree byte for byte.
    match state.queue_submission_by_id(submission_id) {
        Ok(Some((row, items))) => {
            let advances = state
                .queue_advance_rows(&row.submission_id)
                .unwrap_or_default();
            ok_response(
                &request.id,
                crate::queue_executor::submission_doc(&row, &items, &advances),
            )
        }
        Ok(None) => err_response(
            &request.id,
            "state.not_found",
            format!("no submission {submission_id:?} exists"),
        ),
        Err(err) => err_response(&request.id, err.code, err.message),
    }
}

// ---------------------------------------------------------------------------
// Run-scoped controls (issue #86): safe-boundary pause, resume and bounded
// retry for exactly ONE queue run. Every method journals its intent through
// the shared claim machinery; nothing on this surface spawns, kills, cleans
// up, mutates Git, clears a fleet/repository-level hold or bypasses a gate.
// ---------------------------------------------------------------------------
/// `run.pause`: record ONE durable pause request for exactly one run. The
/// request stops admitting new step dispatch for the run immediately; work
/// already in flight keeps running and the pause commits its reached
/// `paused` state at the run's next recorded step boundary. The response
/// carries the engine-minted resume digest (the operator's authorization)
/// and the live boundary state.
fn method_run_pause(shared: &Arc<Shared>, request: &Request) -> String {
    let Some(params) = request.params.as_ref() else {
        return err_response(
            &request.id,
            "refusal.malformed",
            "run.pause requires params: idempotency_key, instance_id, reason",
        );
    };
    let parsed = match crate::run_control::parse_pause_params(params) {
        Ok(parsed) => parsed,
        Err(err) => return err_response(&request.id, err.code, err.message),
    };
    let target = format!("run:{}", parsed.instance_id);
    let key = match journal_mutation(shared, request, "mutate.run.pause", &target) {
        Intent::Claimed { key } => key,
        Intent::Replay { response } => return replay(shared, &response),
        Intent::Refused { code, message } => return err_response(&request.id, code, &message),
    };
    crash_point("run.control.after-intent");
    let outcome = (|| -> Result<Val, (&'static str, String)> {
        let state = shared
            .lock_state()
            .map_err(|message| ("state.unavailable", message))?;
        let epoch = state
            .current_epoch()
            .map_err(|err| (err.code, err.message))?;
        // The digest binds the exact run, the pause-time epoch and this one
        // claim: one pause produces exactly one authorization.
        let digest = crate::engine::mint_resume_digest(&parsed.instance_id, epoch, &key);
        let row = state
            .request_run_pause(
                &parsed.instance_id,
                &parsed.reason,
                &digest,
                &time::rfc3339_now(),
            )
            .map_err(|err| (err.code, err.message))?;
        let in_flight = state
            .in_flight_run_step(&parsed.instance_id)
            .map_err(|err| (err.code, err.message))?;
        let last_failure = state
            .run_step_failure(&parsed.instance_id)
            .map_err(|err| (err.code, err.message))?;
        Ok(crate::run_control::control_doc(
            &row,
            in_flight.as_deref(),
            Some(&row.resume_digest),
            last_failure.as_ref(),
            None,
        ))
    })();
    match outcome {
        Ok(doc) => finish_mutation(shared, request, &key, "run.pause", true, doc, None),
        Err((code, message)) => finish_mutation(
            shared,
            request,
            &key,
            "run.pause",
            false,
            null(),
            Some((code, message)),
        ),
    }
}

/// `run.resume`: lift the pause of exactly ONE run. It requires the
/// engine-minted digest stored at pause time (an authorized operator), an
/// exact target and fresh eligibility (live, non-terminal, current epoch,
/// still owning its issue) — and the update is fenced on the exact
/// instance id, so no unrelated run's pause (or any fleet-level hold
/// expressed as paused runs) is ever cleared.
fn method_run_resume(shared: &Arc<Shared>, request: &Request) -> String {
    let Some(params) = request.params.as_ref() else {
        return err_response(
            &request.id,
            "refusal.malformed",
            "run.resume requires params: idempotency_key, instance_id, digest",
        );
    };
    let parsed = match crate::run_control::parse_resume_params(params) {
        Ok(parsed) => parsed,
        Err(err) => return err_response(&request.id, err.code, err.message),
    };
    let target = format!("run:{}", parsed.instance_id);
    let key = match journal_mutation(shared, request, "mutate.run.resume", &target) {
        Intent::Claimed { key } => key,
        Intent::Replay { response } => return replay(shared, &response),
        Intent::Refused { code, message } => return err_response(&request.id, code, &message),
    };
    crash_point("run.control.after-intent");
    let outcome = (|| -> Result<Val, (&'static str, String)> {
        let state = shared
            .lock_state()
            .map_err(|message| ("state.unavailable", message))?;
        let row = state
            .resume_run(&parsed.instance_id, &parsed.digest, &time::rfc3339_now())
            .map_err(|err| (err.code, err.message))?;
        let in_flight = state
            .in_flight_run_step(&parsed.instance_id)
            .map_err(|err| (err.code, err.message))?;
        let last_failure = state
            .run_step_failure(&parsed.instance_id)
            .map_err(|err| (err.code, err.message))?;
        Ok(crate::run_control::control_doc(
            &row,
            in_flight.as_deref(),
            None,
            last_failure.as_ref(),
            None,
        ))
    })();
    match outcome {
        Ok(doc) => finish_mutation(shared, request, &key, "run.resume", true, doc, None),
        Err((code, message)) => finish_mutation(
            shared,
            request,
            &key,
            "run.resume",
            false,
            null(),
            Some((code, message)),
        ),
    }
}

/// `run.retry`: authorize exactly ONE bounded re-dispatch of ONE diagnosed
/// step of one run. The step must be a step of the run's committed spine,
/// must be its current unachieved frontier step, must carry a recorded
/// terminal non-success attempt (the diagnosis), and the run must be live,
/// unpaused, at the current epoch, with an active grant. Invalid, revoked,
/// stale, already-succeeded and exhausted retries refuse; nothing is
/// spawned here — the authorization is consumed by the next dispatch of
/// that exact step.
fn method_run_retry(shared: &Arc<Shared>, request: &Request) -> String {
    let Some(params) = request.params.as_ref() else {
        return err_response(
            &request.id,
            "refusal.malformed",
            "run.retry requires params: idempotency_key, instance_id, step",
        );
    };
    let parsed = match crate::run_control::parse_retry_params(params) {
        Ok(parsed) => parsed,
        Err(err) => return err_response(&request.id, err.code, err.message),
    };
    let target = format!("run:{}:{}", parsed.instance_id, parsed.step);
    let key = match journal_mutation(shared, request, "mutate.run.retry", &target) {
        Intent::Claimed { key } => key,
        Intent::Replay { response } => return replay(shared, &response),
        Intent::Refused { code, message } => return err_response(&request.id, code, &message),
    };
    crash_point("run.control.after-intent");
    let outcome = (|| -> Result<Val, (&'static str, String)> {
        let state = shared
            .lock_state()
            .map_err(|message| ("state.unavailable", message))?;
        let run = state
            .instance_by_id(&parsed.instance_id)
            .map_err(|err| (err.code, err.message))?
            .ok_or_else(|| {
                (
                    "state.not_found",
                    format!("no instance {:?}", parsed.instance_id),
                )
            })?;
        if run.status == "done" || run.status == "invalidated" {
            return Err((
                crate::run_control::codes::TERMINAL,
                format!(
                    "run {} is {}; a terminal run is never retried",
                    parsed.instance_id, run.status
                ),
            ));
        }
        if run.paused || run.pause_requested {
            return Err((
                crate::run_control::codes::PAUSED,
                format!(
                    "run {} is {}; a paused run is resumed before any step is retried",
                    parsed.instance_id,
                    crate::run_control::control_state(&run)
                ),
            ));
        }
        let spine = state
            .run_step_spine(&parsed.instance_id)
            .map_err(|err| (err.code, err.message))?
            .ok_or_else(|| {
                (
                    crate::run_control::codes::SCOPE,
                    format!(
                        "run {} has no committed queue submission spine; retry addresses queue \
                         runs only",
                        parsed.instance_id
                    ),
                )
            })?;
        if crate::run_control::step_index_of(&spine, &parsed.step).is_none() {
            return Err((
                crate::run_control::codes::STEP_UNKNOWN,
                format!(
                    "step {:?} is not a step of run {} (spine {:?})",
                    parsed.step, parsed.instance_id, spine
                ),
            ));
        }
        // The diagnosis ledger, read BEFORE the frontier decision: issue #92
        // F3 derives the frontier from it (an `ambiguous` timed-out attempt
        // is the frontier), so a step that needs a retry is addressable.
        let attempts = state
            .run_step_attempts(&parsed.instance_id)
            .map_err(|err| (err.code, err.message))?;
        let latest_of = |step: &str| -> Option<String> {
            attempts
                .iter()
                .rfind(|(id, _)| id == step)
                .map(|(_, status)| status.clone())
        };
        let next_step = crate::run_control::frontier_of(&spine, &attempts, &run.current_node);
        let current_index = crate::run_control::step_index_of(&spine, &run.current_node);
        let named_index = crate::run_control::step_index_of(&spine, &parsed.step);
        if next_step.as_deref() != Some(parsed.step.as_str()) {
            let already_done = match (named_index, current_index) {
                (Some(named), Some(current)) => named <= current,
                _ => false,
            } || latest_of(&parsed.step).as_deref() == Some("succeeded");
            let (code, message) = if already_done {
                (
                    crate::run_control::codes::STEP_DONE,
                    format!(
                        "step {:?} of run {} already succeeded (current node {:?}); a \
                         terminal-success step is never retried",
                        parsed.step, parsed.instance_id, run.current_node
                    ),
                )
            } else {
                (
                    crate::run_control::codes::STEP_ORDER,
                    format!(
                        "step {:?} is not the current frontier step of run {} (next step {:?}); a \
                         retry names exactly the diagnosed frontier step",
                        parsed.step, parsed.instance_id, next_step
                    ),
                )
            };
            return Err((code, message));
        }
        // The diagnosis: a recorded terminal non-success attempt for THIS
        // run and THIS step. A step that never ran, or whose last attempt
        // succeeded, is never retried.
        let latest = latest_of(&parsed.step);
        match latest.as_deref() {
            Some("failed") | Some("refused") | Some("ambiguous") => {}
            Some("succeeded") => {
                return Err((
                    crate::run_control::codes::STEP_DONE,
                    format!(
                        "the recorded attempt of step {:?} of run {} succeeded; a terminal-success \
                         step is never retried",
                        parsed.step, parsed.instance_id
                    ),
                ));
            }
            Some(other) => {
                return Err((
                    crate::run_control::codes::STEP_UNDIAGNOSED,
                    format!(
                        "the recorded attempt of step {:?} of run {} ended {other:?}; a retry names \
                         a diagnosed failed step",
                        parsed.step, parsed.instance_id
                    ),
                ));
            }
            None => {
                return Err((
                    crate::run_control::codes::STEP_UNDIAGNOSED,
                    format!(
                        "step {:?} of run {} has no recorded attempt; an unattempted step is not \
                         retried",
                        parsed.step, parsed.instance_id
                    ),
                ));
            }
        }
        // Fresh eligibility: the run must still be at the live epoch and
        // its grant must still be active (a revoked authorization refuses).
        let epoch = state
            .current_epoch()
            .map_err(|err| (err.code, err.message))?;
        if epoch != run.state_epoch {
            return Err((
                crate::mutation::code::EPOCH_STALE,
                format!(
                    "run {} was pinned to epoch {}; the live epoch is {epoch}",
                    parsed.instance_id, run.state_epoch
                ),
            ));
        }
        let grant = state
            .grant_by_id(&run.grant_id)
            .map_err(|err| (err.code, err.message))?;
        match grant {
            Some(grant) if grant.status == "active" => {
                if crate::mutation::is_expired(&grant.expires_at, &time::rfc3339_now()) {
                    return Err((
                        crate::mutation::code::GRANT_EXPIRED,
                        format!(
                            "grant {} of run {} expired at {}; rotate it explicitly before retrying",
                            grant.grant_id, parsed.instance_id, grant.expires_at
                        ),
                    ));
                }
            }
            Some(grant) => {
                return Err((
                    crate::mutation::code::GRANT_INACTIVE,
                    format!(
                        "grant {} of run {} is {}; a revoked grant refuses the retry",
                        grant.grant_id, parsed.instance_id, grant.status
                    ),
                ));
            }
            None => {
                return Err((
                    crate::mutation::code::GRANT_INACTIVE,
                    format!(
                        "grant {:?} of run {} does not exist; a revoked grant refuses the retry",
                        run.grant_id, parsed.instance_id
                    ),
                ));
            }
        }
        let row = state
            .record_run_retry(&parsed.instance_id, &parsed.step, &time::rfc3339_now())
            .map_err(|err| (err.code, err.message))?;
        Ok(crate::run_control::retry_doc(
            &run,
            &row,
            &spine,
            &parsed.step,
            next_step.as_deref(),
        ))
    })();
    match outcome {
        Ok(doc) => finish_mutation(shared, request, &key, "run.retry", true, doc, None),
        Err((code, message)) => finish_mutation(
            shared,
            request,
            &key,
            "run.retry",
            false,
            null(),
            Some((code, message)),
        ),
    }
}

/// `run.release` (issue #146): release exactly ONE run that can never
/// progress. The release frees durable bookkeeping ONLY — the run's unique
/// ownership row is removed and the run goes terminal (`invalidated`) so it
/// stops counting against the occupancy, with the operator's reason, the
/// exact run identity and the authorization window it held recorded in the
/// audit. It refuses typed (`refusal.run.in_flight`) while a step of the run
/// is still dispatched and (`refusal.run.retry_pending`) while the run still
/// holds an unconsumed bounded retry authorization — nothing in flight is
/// killed or abandoned and no authorization is burned. An expired, revoked or
/// missing grant is NOT a fence: that run is exactly the case a release
/// exists for, and the release never presents or reuses the old window (a
/// continuation needs a freshly minted window).
fn method_run_release(shared: &Arc<Shared>, request: &Request) -> String {
    let Some(params) = request.params.as_ref() else {
        return err_response(
            &request.id,
            "refusal.malformed",
            "run.release requires params: idempotency_key, instance_id, reason",
        );
    };
    let parsed = match crate::run_control::parse_release_params(params) {
        Ok(parsed) => parsed,
        Err(err) => return err_response(&request.id, err.code, err.message),
    };
    let target = format!("run:{}", parsed.instance_id);
    let key = match journal_mutation(shared, request, "mutate.run.release", &target) {
        Intent::Claimed { key } => key,
        Intent::Replay { response } => return replay(shared, &response),
        Intent::Refused { code, message } => return err_response(&request.id, code, &message),
    };
    crash_point("run.release.after-intent");
    let outcome = (|| -> Result<Val, (&'static str, String)> {
        let state = shared
            .lock_state()
            .map_err(|message| ("state.unavailable", message))?;
        let at = time::rfc3339_now();
        let released = state
            .release_run(&parsed.instance_id, &parsed.reason, &key, &at)
            .map_err(|err| (err.code, err.message))?;
        Ok(crate::run_control::release_doc(
            &released,
            &parsed.reason,
            &at,
            &key,
        ))
    })();
    match outcome {
        Ok(doc) => finish_mutation(shared, request, &key, "run.release", true, doc, None),
        Err((code, message)) => finish_mutation(
            shared,
            request,
            &key,
            "run.release",
            false,
            null(),
            Some((code, message)),
        ),
    }
}

/// `run.retire-lane` (issue #236): retire the stale LANE RECORDS of ONE run
/// the ledger records as terminal, so a released run's residue is recoverable
/// by ONE bounded, audited operator control instead of hand-editing state.
///
/// The gate is the ledger and it comes FIRST: a run that is not terminal
/// refuses typed (`refusal.lane.live_run`) with nothing claimed, journaled or
/// touched — a live lane still holds its issue's unique ownership, so it is
/// never in the retired set. For a terminal run ONE audited claim commits:
///
/// - the durable lane records the run still holds (the leftover ownership
///   rows that name it the owner of its issue, removed in one transaction
///   with the `run.retire-lane` audit record), and
/// - its lane residue under the SAME #190/#222 policy a bind step applies —
///   the run's own linked lane workspace, its registered lane checkout, and
///   its local lane branch only when the published branch carries the same
///   tip (a local-only delivery is never deleted). The lane is the run's own
///   implementer leg (derived, never presented) and the integration clone is
///   the run's own recorded topology; a first-time topology can be presented
///   exactly as the dispatch surface accepts one.
fn method_run_retire_lane(shared: &Arc<Shared>, request: &Request) -> String {
    let Some(params) = request.params.as_ref() else {
        return err_response(
            &request.id,
            "refusal.malformed",
            "run.retire-lane requires params: idempotency_key, instance_id, reason",
        );
    };
    let parsed = match crate::run_control::parse_lane_retirement_params(params) {
        Ok(parsed) => parsed,
        Err(err) => return err_response(&request.id, err.code, err.message),
    };
    // The gate reads durable state only, before any claim exists: a live run
    // is refused here and the refusal is journaled by nobody.
    let (instance, recorded, siblings) = {
        let state = match shared.lock_state() {
            Ok(state) => state,
            Err(message) => return err_response(&request.id, "state.unavailable", message),
        };
        let instance = match state.instance_by_id(&parsed.instance_id) {
            Ok(Some(instance)) => instance,
            Ok(None) => {
                return err_response(
                    &request.id,
                    "state.not_found",
                    format!("no instance {}", parsed.instance_id),
                );
            }
            Err(err) => return err_response(&request.id, err.code, err.message),
        };
        let recorded = match state.run_dispatch_context(&parsed.instance_id) {
            Ok(recorded) => recorded,
            Err(err) => return err_response(&request.id, err.code, err.message),
        };
        // Issue #224 (AC5): the LIVE siblings of this run's issue. One issue
        // has ONE lane (the branch and the checkout are derived from the issue
        // number), so a non-terminal run of the same issue may hold — or still
        // need — exactly the refs this retirement would remove. Read with the
        // gate, before any claim exists, and refused on below.
        let siblings = match state.live_lane_siblings(
            &instance.repository,
            instance.issue_number,
            &parsed.instance_id,
        ) {
            Ok(siblings) => siblings,
            Err(err) => return err_response(&request.id, err.code, err.message),
        };
        (instance, recorded, siblings)
    };
    if !matches!(instance.status.as_str(), "done" | "invalidated") {
        return err_response(
            &request.id,
            crate::run_control::codes::LANE_LIVE,
            format!(
                "run {} is live (status {:?}); only a terminal run's lane records are retired — a \
                 live lane still holds its issue's unique ownership, so it is never in the retired \
                 set (a run that can never progress is retired with `run release` first)",
                parsed.instance_id, instance.status
            ),
        );
    }
    // Issue #224 (AC5): a retirement is scoped to the ADDRESSED run's own
    // residue. One issue has ONE lane — the branch and the checkout are
    // derived from the issue number (`crate::lane::lane_branch` /
    // `lane_checkout`) — so another run of the same issue that is still
    // NON-TERMINAL holds, or still needs, exactly the refs this retirement
    // would remove. The measured drive retired a DONE run's lane while a live
    // run of the same issue was mid-flight; the live run's own publish then
    // had no branch and no worktree to refresh. The refusal is typed, names
    // every live sibling, and touches nothing: no claim, no journal row, no
    // git call and no workspace close.
    if !siblings.is_empty() {
        let issue = instance.issue_number.max(0) as u64;
        return err_response(
            &request.id,
            crate::run_control::codes::LANE_LIVE,
            format!(
                "the lane of terminal run {} (branch {:?}, checkout {:?}) is referenced by {} \
                 NON-TERMINAL run(s) of the same issue — {} — whose own published delivery \
                 depends on it: a terminal run's retirement never removes a branch or checkout a \
                 live run still needs, so nothing was read, claimed or touched",
                parsed.instance_id,
                crate::lane::lane_branch(issue),
                crate::lane::lane_checkout(issue, "implementer", 1),
                siblings.len(),
                siblings.join(", ")
            ),
        );
    }
    // The lane paths: the run's OWN recorded topology (the same document its
    // dispatches re-present), else the presented one — never a mixture. A run
    // whose recorded topology is empty has none bound yet, exactly like the
    // dispatch surface's first-dispatch rule.
    let recorded_topology = recorded
        .as_ref()
        .map(|recorded| recorded.topology.clone())
        .filter(|topology| !topology.is_null());
    let topology = match (recorded_topology.as_ref(), parsed.topology.as_ref()) {
        (Some(recorded), Some(presented)) if recorded != presented => {
            return err_response(
                &request.id,
                crate::run_control::codes::SCOPE,
                format!(
                    "run {} already bound a different topology; a retire never changes its lane \
                     paths",
                    parsed.instance_id
                ),
            );
        }
        (Some(recorded), _) => recorded.clone(),
        (None, Some(presented)) => presented.clone(),
        (None, None) => {
            return err_response(
                &request.id,
                crate::run_control::codes::SCOPE,
                format!(
                    "run {} recorded no lane topology (its own applies recorded none); present \
                     --topology FILE with integration_repo and worktrees_root so the retire \
                     addresses the lane the run bound",
                    parsed.instance_id
                ),
            );
        }
    };
    let topology_path = |key: &str| -> Result<PathBuf, String> {
        let text = topology
            .get(key)
            .and_then(Val::as_str)
            .ok_or_else(|| format!("topology.{key} is required"))?;
        let path = PathBuf::from(text);
        if !path.is_absolute() {
            return Err(format!("topology.{key} must be an absolute path"));
        }
        Ok(path)
    };
    let integration_repo = match topology_path("integration_repo") {
        Ok(path) => path,
        Err(message) => {
            return err_response(&request.id, crate::run_control::codes::SCOPE, &message);
        }
    };
    let worktrees_root = match topology_path("worktrees_root") {
        Ok(path) => path,
        Err(message) => {
            return err_response(&request.id, crate::run_control::codes::SCOPE, &message);
        }
    };
    let target = format!("run-lane:{}", parsed.instance_id);
    let key = match journal_mutation(shared, request, "mutate.run.retire-lane", &target) {
        Intent::Claimed { key } => key,
        Intent::Replay { response } => return replay(shared, &response),
        Intent::Refused { code, message } => return err_response(&request.id, code, &message),
    };
    crash_point("run.retire-lane.after-intent");
    let outcome = (|| -> Result<Val, (&'static str, String)> {
        let at = time::rfc3339_now();
        let retired = {
            let state = shared
                .lock_state()
                .map_err(|message| ("state.unavailable", message))?;
            state
                .retire_run_lane_records(&parsed.instance_id, &parsed.reason, &key)
                .map_err(|err| (err.code, err.message))?
        };
        // The residue half runs OUTSIDE the state lock (bounded children never
        // stall other daemon work) and its outcome is RECORDED, never forced:
        // the durable half is already committed and audited.
        let env = crate::config::adapter_environment();
        let residue = crate::mutation::retire_run_lane(
            &integration_repo,
            &worktrees_root,
            &parsed.instance_id,
            retired.run.issue_number,
            &env,
        );
        let residue_doc = if residue.status == "succeeded" {
            residue.result.clone()
        } else {
            object(vec![
                ("status", string(residue.status)),
                (
                    "code",
                    match &residue.code {
                        Some(code) => string(code),
                        None => null(),
                    },
                ),
                (
                    "message",
                    match &residue.message {
                        Some(message) => string(message),
                        None => null(),
                    },
                ),
            ])
        };
        Ok(crate::run_control::lane_retirement_doc(
            &retired,
            &parsed.reason,
            &at,
            residue_doc,
            &key,
        ))
    })();
    match outcome {
        Ok(doc) => finish_mutation(shared, request, &key, "run.retire-lane", true, doc, None),
        Err((code, message)) => finish_mutation(
            shared,
            request,
            &key,
            "run.retire-lane",
            false,
            null(),
            Some((code, message)),
        ),
    }
}

/// `run.resolve`: record recorder-attributed artifact evidence for ONE
/// diagnosed prompt without invoking the prompt effect again. The resolved
/// journal row is the attempt-ledger transition; supervision's existing
/// diagnosed-step no-redispatch fence is unchanged.
fn method_run_resolve(shared: &Arc<Shared>, request: &Request) -> String {
    let Some(params) = request.params.as_ref() else {
        return err_response(
            &request.id,
            "refusal.malformed",
            "run.resolve requires params: idempotency_key, instance_id, step, recorder, evidence",
        );
    };
    let parsed = match crate::run_control::parse_resolution_params(params) {
        Ok(parsed) => parsed,
        Err(err) => return err_response(&request.id, err.code, err.message),
    };
    let target = format!("run:{}:{}", parsed.instance_id, parsed.step);
    let key = match journal_mutation(shared, request, "mutate.run.resolve", &target) {
        Intent::Claimed { key } => key,
        Intent::Replay { response } => return replay(shared, &response),
        Intent::Refused { code, message } => return err_response(&request.id, code, message),
    };
    crash_point("run.resolve.after-intent");
    let state = match shared.lock_state() {
        Ok(state) => state,
        Err(message) => {
            return finish_mutation(
                shared,
                request,
                &key,
                "run.resolve",
                false,
                null(),
                Some(("state.unavailable", message)),
            );
        }
    };
    let validated =
        (|| -> Result<(crate::state::InstanceRow, String, String), (&'static str, String)> {
            let run = state
                .instance_by_id(&parsed.instance_id)
                .map_err(|err| (err.code, err.message))?
                .ok_or_else(|| {
                    (
                        "state.not_found",
                        format!("no instance {}", parsed.instance_id),
                    )
                })?;
            if matches!(run.status.as_str(), "done" | "invalidated") {
                return Err((
                    crate::run_control::codes::TERMINAL,
                    format!(
                        "run {} is {}; a terminal run is never resolved",
                        run.instance_id, run.status
                    ),
                ));
            }
            if run.paused || run.pause_requested {
                return Err((
                    crate::run_control::codes::PAUSED,
                    format!(
                        "run {} is {}; resume it before resolution",
                        run.instance_id,
                        crate::run_control::control_state(&run)
                    ),
                ));
            }
            if let Some(step) = state
                .in_flight_run_step(&run.instance_id)
                .map_err(|err| (err.code, err.message))?
            {
                return Err((
                    crate::run_control::codes::IN_FLIGHT,
                    format!(
                        "run {} still has in-flight step {step:?}; evidence cannot resolve an effect that may still be running",
                        run.instance_id
                    ),
                ));
            }
            let spine = state
                .run_step_spine(&run.instance_id)
                .map_err(|err| (err.code, err.message))?
                .ok_or_else(|| {
                    (
                        crate::run_control::codes::SCOPE,
                        format!("run {} has no committed step spine", run.instance_id),
                    )
                })?;
            if !spine.iter().any(|step| step == &parsed.step) {
                return Err((
                    crate::run_control::codes::STEP_UNKNOWN,
                    format!("step {:?} is not in run {}", parsed.step, run.instance_id),
                ));
            }
            let steps = state
                .run_step_documents(&run.instance_id)
                .map_err(|err| (err.code, err.message))?
                .unwrap_or_default();
            let step = steps
                .iter()
                .find(|step| step.get("id").and_then(Val::as_str) == Some(parsed.step.as_str()))
                .ok_or_else(|| {
                    (
                        crate::run_control::codes::STEP_UNKNOWN,
                        format!("step {:?} has no committed document", parsed.step),
                    )
                })?;
            let kind = step.get("kind").and_then(Val::as_str).unwrap_or_default();
            if kind != "prompt" {
                return Err((
                    crate::run_control::codes::RESOLUTION_KIND,
                    format!(
                        "step {:?} is {kind:?}; evidence resolution supports diagnosed prompt effects only",
                        parsed.step
                    ),
                ));
            }
            let expected_branch = step
                .get("params")
                .and_then(|params| params.get("branch"))
                .and_then(Val::as_str)
                .ok_or_else(|| {
                    (
                        crate::run_control::codes::RESOLUTION_EVIDENCE,
                        format!(
                            "prompt step {:?} records no bound output branch",
                            parsed.step
                        ),
                    )
                })?;
            let evidence_branch = parsed
                .evidence
                .get("branch")
                .and_then(Val::as_str)
                .unwrap_or_default();
            if evidence_branch != expected_branch {
                return Err((
                    crate::run_control::codes::RESOLUTION_EVIDENCE,
                    format!(
                        "artifact branch {evidence_branch:?} is not the prompt's bound output branch {expected_branch:?}"
                    ),
                ));
            }
            let evidence_repository = parsed
                .evidence
                .get("pull_request")
                .and_then(|pull| pull.get("repository"))
                .and_then(Val::as_str)
                .unwrap_or_default();
            if evidence_repository != run.repository {
                return Err((
                    crate::run_control::codes::RESOLUTION_EVIDENCE,
                    format!(
                        "artifact PR repository {evidence_repository:?} is not run repository {:?}",
                        run.repository
                    ),
                ));
            }
            let attempts = state
                .run_step_attempts(&run.instance_id)
                .map_err(|err| (err.code, err.message))?;
            let frontier = crate::run_control::frontier_of(&spine, &attempts, &run.current_node);
            if frontier.as_deref() != Some(parsed.step.as_str()) {
                return Err((
                    crate::run_control::codes::STEP_ORDER,
                    format!(
                        "step {:?} is not run {}'s diagnosed frontier (next {:?})",
                        parsed.step, run.instance_id, frontier
                    ),
                ));
            }
            let prior = attempts
                .iter()
                .rfind(|(step, _)| step == &parsed.step)
                .map(|(_, status)| status.as_str());
            let prior = match prior {
                Some(status @ ("failed" | "ambiguous")) => status.to_string(),
                Some("succeeded") => {
                    return Err((
                        crate::run_control::codes::STEP_DONE,
                        format!("step {:?} already succeeded", parsed.step),
                    ));
                }
                _ => {
                    return Err((
                        crate::run_control::codes::STEP_UNDIAGNOSED,
                        format!(
                            "step {:?} has no failed/ambiguous effect to resolve",
                            parsed.step
                        ),
                    ));
                }
            };
            let epoch = state
                .current_epoch()
                .map_err(|err| (err.code, err.message))?;
            if run.state_epoch != epoch {
                return Err((
                    crate::mutation::code::EPOCH_STALE,
                    format!(
                        "run {} belongs to epoch {}, live epoch is {epoch}",
                        run.instance_id, run.state_epoch
                    ),
                ));
            }
            let grant = state
                .grant_by_id(&run.grant_id)
                .map_err(|err| (err.code, err.message))?
                .ok_or_else(|| {
                    (
                        crate::mutation::code::GRANT_INACTIVE,
                        format!("no grant {} exists", run.grant_id),
                    )
                })?;
            if grant.status != "active" {
                return Err((
                    crate::mutation::code::GRANT_INACTIVE,
                    format!("grant {} is {}", grant.grant_id, grant.status),
                ));
            }
            if crate::mutation::is_expired(&grant.expires_at, &time::rfc3339_now()) {
                return Err((
                    crate::mutation::code::GRANT_EXPIRED,
                    format!("grant {} expired at {}", grant.grant_id, grant.expires_at),
                ));
            }
            let owns = state
                .queue_ownership_rows()
                .map_err(|err| (err.code, err.message))?
                .iter()
                .any(|owner| owner.instance_id == run.instance_id);
            if !owns {
                return Err((
                    crate::run_control::codes::SUPERSEDED,
                    format!("run {} no longer owns its work item", run.instance_id),
                ));
            }
            Ok((run, kind.to_string(), prior))
        })();
    let response = match validated {
        Err((code, message)) => resolve_mutation_on(
            &state,
            &shared.log,
            request,
            &key,
            "run.resolve",
            false,
            null(),
            Some((code, message)),
        ),
        Ok((run, kind, prior)) => {
            let at = time::rfc3339_now();
            let resolution = crate::run_control::resolution_doc(
                &run,
                &parsed.step,
                &kind,
                &prior,
                &parsed.recorder,
                &parsed.evidence,
                &at,
                &key,
            );
            let response = ok_response(&request.id, resolution.clone());
            let outcome = apply_outcome(
                DAEMON_PLAN_ID,
                &parsed.step,
                &key,
                "succeeded",
                resolution,
                None,
            );
            match state.resolve_run_step_claim(
                &key,
                "run.resolve",
                &canonical_text(&outcome),
                &response,
                &parsed.instance_id,
                &parsed.step,
                &at,
            ) {
                Ok(_) => response,
                Err(err) => err_response(
                    &request.id,
                    err.code,
                    format!(
                        "the resolution could not be committed (fail closed): {}",
                        err.message
                    ),
                ),
            }
        }
    };
    drop(state);
    publish_after_state_change(shared, None);
    response
}

/// The gated facts one re-evaluation reads under a SINGLE state guard before it
/// dispatches anything (issue #230): the run row, its committed spine, the
/// derived re-evaluation plan, the evidence whose checks are recomputed, the
/// checks that are not passing and the next step the run has not achieved.
type ReevaluationGate = Result<
    (
        crate::state::InstanceRow,
        Vec<String>,
        crate::run_control::ReevaluationPlan,
        String,
        Vec<String>,
        Option<String>,
        // The reviewer lane checkout the re-dispatch re-binds for the round it
        // dispatches (issue #248); `None` leaves the committed binding alone.
        Option<String>,
    ),
    (&'static str, String),
>;

/// `run.reevaluate` (issue #230): re-dispatch the run's OWN terminal-success
/// check-producing step at the same certified head, on a FRESH lane round, so
/// the checks it recorded are RECOMPUTED instead of being trusted forever.
///
/// The deadlock this breaks is exact: a transient failure was recorded inside
/// the evidence of a step that SUCCEEDED, so its consumer refuses
/// (`refusal.evidence.failed`) and the producer can never be re-run
/// (`refusal.run.step_done`). The control neither waives nor adjudicates a
/// check — it re-runs the check PRODUCER, whose fresh verdict is recorded and
/// consumed exactly like the first one, so a genuinely failed, reproducible
/// check comes back failed and the consumer still refuses. It is bounded per
/// (run, step) from the durable journal, attributed (operator identity and
/// reason) and journaled BEFORE anything is dispatched.
fn method_run_reevaluate(shared: &Arc<Shared>, request: &Request) -> String {
    let Some(params) = request.params.as_ref() else {
        return err_response(
            &request.id,
            "refusal.malformed",
            "run.reevaluate requires params: idempotency_key, instance_id, step, operator, reason",
        );
    };
    let parsed = match crate::run_control::parse_reevaluation_params(params) {
        Ok(parsed) => parsed,
        Err(err) => return err_response(&request.id, err.code, err.message),
    };
    let target = format!("run:{}:{}", parsed.instance_id, parsed.step);
    let key = match journal_mutation(shared, request, "mutate.run.reevaluate", &target) {
        Intent::Claimed { key } => key,
        Intent::Replay { response } => return replay(shared, &response),
        Intent::Refused { code, message } => return err_response(&request.id, code, &message),
    };
    crash_point("run.control.after-intent");
    // The gated facts the re-dispatch needs, read under ONE guard and then
    // released: the dispatch itself must never run holding the state lock.
    let gated = (|| -> ReevaluationGate {
        let state = shared
            .lock_state()
            .map_err(|message| ("state.unavailable", message))?;
        let run = state
            .instance_by_id(&parsed.instance_id)
            .map_err(|err| (err.code, err.message))?
            .ok_or_else(|| {
                (
                    "state.not_found",
                    format!("no instance {:?}", parsed.instance_id),
                )
            })?;
        if run.status == "done" || run.status == "invalidated" {
            return Err((
                crate::run_control::codes::TERMINAL,
                format!(
                    "run {} is {}; a terminal run is never re-evaluated",
                    parsed.instance_id, run.status
                ),
            ));
        }
        if run.paused || run.pause_requested {
            return Err((
                crate::run_control::codes::PAUSED,
                format!(
                    "run {} is {}; a paused run is resumed before its checks are re-evaluated",
                    parsed.instance_id,
                    crate::run_control::control_state(&run)
                ),
            ));
        }
        let epoch = state
            .current_epoch()
            .map_err(|err| (err.code, err.message))?;
        if epoch != run.state_epoch {
            return Err((
                crate::mutation::code::EPOCH_STALE,
                format!(
                    "run {} was pinned to epoch {}; the live epoch is {epoch}",
                    parsed.instance_id, run.state_epoch
                ),
            ));
        }
        let grant = state
            .grant_by_id(&run.grant_id)
            .map_err(|err| (err.code, err.message))?;
        match grant {
            Some(grant) if grant.status == "active" => {
                if crate::mutation::is_expired(&grant.expires_at, &time::rfc3339_now()) {
                    return Err((
                        crate::mutation::code::GRANT_EXPIRED,
                        format!(
                            "grant {} of run {} expired at {}; rotate it explicitly before re-evaluating its checks",
                            grant.grant_id, parsed.instance_id, grant.expires_at
                        ),
                    ));
                }
            }
            Some(grant) => {
                return Err((
                    crate::mutation::code::GRANT_INACTIVE,
                    format!(
                        "grant {} of run {} is {}; a revoked grant refuses the re-evaluation",
                        grant.grant_id, parsed.instance_id, grant.status
                    ),
                ));
            }
            None => {
                return Err((
                    crate::mutation::code::GRANT_INACTIVE,
                    format!(
                        "grant {:?} of run {} does not exist; a revoked grant refuses the re-evaluation",
                        run.grant_id, parsed.instance_id
                    ),
                ));
            }
        }
        let spine = state
            .run_step_spine(&parsed.instance_id)
            .map_err(|err| (err.code, err.message))?
            .ok_or_else(|| {
                (
                    crate::run_control::codes::SCOPE,
                    format!(
                        "run {} has no committed queue submission spine; a re-evaluation addresses queue runs only",
                        parsed.instance_id
                    ),
                )
            })?;
        let step = spine
            .iter()
            .find(|step| *step == &parsed.step)
            .cloned()
            .ok_or_else(|| {
                (
                    crate::run_control::codes::STEP_UNKNOWN,
                    format!(
                        "step {:?} is not a step of run {} (spine {:?})",
                        parsed.step, parsed.instance_id, spine
                    ),
                )
            })?;
        // The step's own committed document (params included), from the run's
        // committed spine — the same documents the dispatch path derives its
        // plan from. ONE read: the kind, the declared shape and the lane
        // binding the re-dispatch re-binds all come from it.
        let documents = state
            .run_step_documents(&parsed.instance_id)
            .map_err(|err| (err.code, err.message))?
            .unwrap_or_default();
        let committed_params = documents
            .iter()
            .find(|step| step.get("id").and_then(Val::as_str) == Some(parsed.step.as_str()))
            .and_then(|step| step.get("params"))
            .cloned();
        // The step's OWN recorded kind.
        let kind = documents
            .iter()
            .find(|step| step.get("id").and_then(Val::as_str) == Some(parsed.step.as_str()))
            .and_then(|step| crate::mutation::step_kind(step).ok())
            .unwrap_or_default();
        let attempts = state
            .run_step_attempts(&parsed.instance_id)
            .map_err(|err| (err.code, err.message))?;
        // The step's own declared shape: only a reviewer LEG computes checks.
        let declares_reviewer_leg = committed_params
            .as_ref()
            .is_some_and(|params| crate::mutation::declares_reviewer_leg(Some(params)));
        let latest_attempt = attempts
            .iter()
            .rfind(|(id, _)| id == &step)
            .map(|(_, status)| status.clone());
        let successes = attempts
            .iter()
            .filter(|(id, status)| id == &step && status == "succeeded")
            .count() as i64;
        let next_step = crate::run_control::frontier_of(&spine, &attempts, &run.current_node);
        // The recorded check result the consumer refuses on: the run's newest
        // review-evidence row, read exactly as the merge gate reads it.
        let newest = state
            .evidence_for_instance(&parsed.instance_id)
            .map_err(|err| (err.code, err.message))?
            .into_iter()
            .next();
        let (evidence_id, failing) = match &newest {
            Some(row) => {
                let view = crate::mutation::EvidenceView {
                    evidence_id: row.evidence_id.clone(),
                    feature_head: row.feature_head.clone(),
                    integration_base: row.integration_base.clone(),
                    workflow_hash: row.workflow_hash.clone(),
                    policy_hash: row.policy_hash.clone(),
                    verdict: row.verdict.clone(),
                    reviewer: row.reviewer.clone(),
                    checks: row.checks.clone(),
                    created_at: row.created_at.clone(),
                };
                let failing = crate::mutation::non_passing_checks(&view)
                    .map_err(|err| (err.code, err.message))?;
                (row.evidence_id.clone(), failing)
            }
            None => (String::new(), Vec::new()),
        };
        let report = state
            .run_reevaluations(&parsed.instance_id, &parsed.step)
            .map_err(|err| (err.code, err.message))?;
        let recorded = report.len() as i64;
        // ONE pure gate over the recorded facts: a diagnosed step belongs to
        // the bounded-retry control, a step that never ran to nobody, and a
        // record whose checks all passed has nothing to recompute.
        let plan = crate::run_control::reevaluation_plan(
            &kind,
            declares_reviewer_leg,
            latest_attempt.as_deref(),
            &failing,
            recorded,
            successes,
        )
        .map_err(|err| (err.code, err.message))?;
        // The record is written BEFORE the re-dispatch (the mutate-intent
        // discipline): the operator's act, its attribution and its slot in
        // the bound exist durably even if the re-run that follows is refused.
        state
            .record_run_reevaluation(
                &parsed.instance_id,
                &parsed.step,
                &evidence_id,
                &parsed.operator,
                &parsed.reason,
                &key,
            )
            .map_err(|err| (err.code, err.message))?;
        // The lane checkout the re-dispatch RE-BINDS for the round it
        // dispatches (issue #248): the leg advanced to the plan's lane round
        // `plan.lane_round`, so the round the plan was rendered at is no
        // longer the checkout this dispatch may bind. `None` (a foreign
        // binding, the run's own lane, the bare-subprocess fallback) leaves
        // the committed params untouched and the effect's own refusal stands.
        let rebound_lane = crate::mutation::rebound_reviewer_lane(
            run.issue_number.max(0) as u64,
            committed_params.as_ref(),
            plan.lane_round.max(1) as u64,
        );
        Ok((
            run,
            spine,
            plan,
            evidence_id,
            failing,
            next_step,
            rebound_lane,
        ))
    })();
    let (run, spine, plan, evidence_id, failing, next_step, rebound_lane) = match gated {
        Ok(gated) => gated,
        Err((code, message)) => {
            return finish_mutation(
                shared,
                request,
                &key,
                "run.reevaluate",
                false,
                null(),
                Some((code, message)),
            );
        }
    };
    // The re-dispatch itself: the SAME dispatch path every other step uses,
    // with the fresh lane round the control derived merged over the step's
    // committed params — plus, for a reviewer leg whose plan binds a lane
    // checkout of an EARLIER round, that round's own checkout (issue #248):
    // the leg advanced past the round the plan was rendered at, and ONE lane
    // checkout belongs to exactly one leg, so binding the stale one would
    // refuse (`refusal.lane.identity`) forever. The control re-renders/
    // RE-BINDS the binding it dispatches; a genuinely foreign checkout is
    // never re-bound and is still refused by the effect. The control presents
    // no check status, no verdict and no head.
    let inner_key = {
        let mut inner = format!(
            "ik_{}-{}-r{}",
            parsed.instance_id.trim_start_matches("run-"),
            parsed.step,
            plan.lane_round
        );
        inner.truncate(64);
        inner
    };
    let step_params = match &rebound_lane {
        Some(lane) => object(vec![
            ("lane_round", integer(plan.lane_round)),
            ("worktree", string(lane)),
        ]),
        None => object(vec![("lane_round", integer(plan.lane_round))]),
    };
    let dispatch_params = crate::run_control::dispatch_params(
        &inner_key,
        &parsed.instance_id,
        &parsed.step,
        Some(step_params),
        None,
    );
    let dispatch_request = Request {
        id: request.id.clone(),
        method: "run.dispatch".to_string(),
        line: crate::canonical::canonical_text(&dispatch_params),
        params: Some(dispatch_params),
    };
    let response = run_dispatch(shared, &dispatch_request, Some(parsed.step.as_str()));
    let doc = match Val::parse_json(response.trim()) {
        Ok(doc) => doc,
        Err(message) => {
            return finish_mutation(
                shared,
                request,
                &key,
                "run.reevaluate",
                false,
                null(),
                Some(("refusal.malformed", message)),
            );
        }
    };
    if doc.get("ok").and_then(Val::as_bool) != Some(true) {
        let error = doc.get("error").cloned().unwrap_or_else(null);
        let code = error
            .get("code")
            .and_then(Val::as_str)
            .unwrap_or("refusal.malformed")
            .to_string();
        let message = error
            .get("message")
            .and_then(Val::as_str)
            .unwrap_or("the re-evaluation dispatch was refused")
            .to_string();
        // The re-evaluation RECORD stays (the operator's act, bounded and
        // attributed); the dispatch's own refusal is journaled by the
        // dispatch path exactly as any other refused dispatch, and the typed
        // code is carried VERBATIM — never remapped.
        return finish_control_refusal(shared, request, &key, "run.reevaluate", &code, message);
    }
    let dispatch_outcome = doc.get("result").cloned().unwrap_or_else(null);
    let document = crate::run_control::reevaluation_doc(
        &run,
        &parsed.step,
        &spine,
        &plan,
        &parsed.operator,
        &parsed.reason,
        &evidence_id,
        &failing,
        next_step.as_deref(),
        dispatch_outcome,
    );
    finish_mutation(
        shared,
        request,
        &key,
        "run.reevaluate",
        true,
        document,
        None,
    )
}

/// The supported step-dispatch surface (issue #92): the
/// caller presents the run, the committed-spine step and only that step's own
/// inputs; the plan document, the issue/grant/workflow pins, the topology and
/// the admission inputs are DERIVED from the run's committed submission and
/// its own recorded dispatch context (the same derivation the continuation
/// dispatch uses). The merged step params are validated against the step
/// kind's existing param contract BEFORE anything is journaled — a malformed
/// request refuses typed and consumes no bounded retry authorization — and
/// the resulting dispatch runs through the SAME apply engine as every other
/// apply, so every gate (grant, epoch, admission, pause fence, bounded-retry
/// fence, idempotency) re-derives there: a re-dispatch of a diagnosed step
/// consumes exactly one unconsumed authorization, and the operator's own
/// (corrected) params are what the effect receives.
///
/// `reevaluation` is the internal authorization ONE control derives (issue
/// #230: the plan-local step `run.reevaluate` gated, journaled and derived a
/// fresh lane round for). It is never presented by a caller and it relaxes
/// exactly ONE fence — the terminal-success frontier refusal below, for that
/// exact step, and only when it really is the run's own check producer.
fn method_run_dispatch(shared: &Arc<Shared>, request: &Request) -> String {
    run_dispatch(shared, request, None)
}

fn run_dispatch(shared: &Arc<Shared>, request: &Request, reevaluation: Option<&str>) -> String {
    let Some(params) = request.params.as_ref() else {
        return err_response(
            &request.id,
            "refusal.malformed",
            "run.dispatch requires params: idempotency_key, instance_id, step",
        );
    };
    let parsed = match crate::run_control::parse_dispatch_params(params) {
        Ok(parsed) => parsed,
        Err(err) => return err_response(&request.id, err.code, err.message),
    };
    let (mut material, kind, effective, integration_branch, production_branches, publish_route) = {
        let state = match shared.lock_state() {
            Ok(state) => state,
            Err(message) => return err_response(&request.id, "state.unavailable", message),
        };
        let mut material =
            match read_dispatch_material(&state, &parsed.instance_id, parsed.topology.as_ref()) {
                Ok(material) => material,
                Err((code, message)) => return err_response(&request.id, &code, message),
            };
        if parsed.admission.is_some() {
            material.admission = parsed.admission.clone();
        }
        if !material.spine.iter().any(|step| step == &parsed.step) {
            return err_response(
                &request.id,
                crate::run_control::codes::STEP_UNKNOWN,
                format!(
                    "step {:?} is not a step of run {} (spine {:?})",
                    parsed.step, parsed.instance_id, material.spine
                ),
            );
        }
        let attempts = match state.run_step_attempts(&parsed.instance_id) {
            Ok(attempts) => attempts,
            Err(err) => return err_response(&request.id, err.code, err.message),
        };
        let frontier = crate::run_control::frontier_of(
            &material.spine,
            &attempts,
            &material.instance.current_node,
        );
        if frontier.as_deref() != Some(parsed.step.as_str()) {
            let terminal = frontier.is_none()
                || attempts
                    .iter()
                    .rev()
                    .find(|(step, _)| step == &parsed.step)
                    .is_some_and(|(_, status)| status == "succeeded");
            // Issue #230: exactly ONE authorized case dispatches a step past
            // the frontier — the control's re-evaluation of the run's OWN
            // terminal-success check producer, whose recorded evidence
            // carries a non-passing check. The authorization is never
            // presented by a caller (the `run.reevaluate` control derives it
            // from recorded facts after journaling the operator, the reason
            // and the bound), the step must really be that producer, and the
            // re-run only ADDS a record: the frozen evidence is never edited.
            let reevaluated = reevaluation == Some(parsed.step.as_str())
                && terminal
                && material
                    .steps
                    .iter()
                    .find(|step| step.get("id").and_then(Val::as_str) == Some(parsed.step.as_str()))
                    .and_then(|step| crate::mutation::step_kind(step).ok())
                    .as_deref()
                    == Some(crate::run_control::REEVALUATION_KIND);
            if !reevaluated {
                let code = if terminal {
                    crate::run_control::codes::STEP_DONE
                } else {
                    crate::run_control::codes::STEP_ORDER
                };
                let message = if terminal {
                    format!(
                        "step {:?} of run {} has already succeeded; the effect is never repeated",
                        parsed.step, parsed.instance_id
                    )
                } else {
                    format!(
                        "step {:?} is not the current frontier step of run {} (next step {:?})",
                        parsed.step, parsed.instance_id, frontier
                    )
                };
                return err_response(&request.id, code, message);
            }
        }
        let step = match material
            .steps
            .iter()
            .find(|step| step.get("id").and_then(Val::as_str) == Some(parsed.step.as_str()))
        {
            Some(step) => step.clone(),
            None => {
                return err_response(
                    &request.id,
                    crate::run_control::codes::STEP_UNKNOWN,
                    format!(
                        "step {:?} is not a step of run {} (spine {:?})",
                        parsed.step, parsed.instance_id, material.spine
                    ),
                );
            }
        };
        let kind = match crate::mutation::step_kind(&step) {
            Ok(kind) => kind,
            Err(err) => return err_response(&request.id, err.code, err.message),
        };
        // The operator's inputs REPLACE/EXTEND the step's committed params:
        // the dispatch carries the corrected params, never a reconstruction.
        let effective = merged_step_params(step.get("params"), parsed.step_params.as_ref());
        // The step's param contract, read from the SAME topology the
        // dispatch re-presents (the run's own recorded one).
        let mut production_branches: Vec<String> = Vec::new();
        let mut integration_branch = String::new();
        if let Some(branches) = material
            .topology
            .get("production_branches")
            .and_then(Val::as_array)
        {
            production_branches = branches
                .iter()
                .filter_map(Val::as_str)
                .map(str::to_string)
                .collect();
        }
        if let Some(branch) = material
            .topology
            .get("integration_branch")
            .and_then(Val::as_str)
        {
            integration_branch = branch.to_string();
        }
        // Issue #219: the publish route is read from the SAME recorded
        // topology the dispatch re-presents, and only a route the closed set
        // admits is ever used (a topology that declared none keeps the
        // documented default).
        let publish_route = material
            .topology
            .get("integration_publish")
            .and_then(Val::as_str)
            .filter(|route| crate::mutation::is_publish_route(route))
            .unwrap_or(crate::mutation::INTEGRATION_PUBLISH_DEFAULT)
            .to_string();
        (
            material,
            kind,
            effective,
            integration_branch,
            production_branches,
            publish_route,
        )
    };
    // Issue #256: a REVIEW round binds the head the recorded handoff's OWN
    // repair leg delivered, when its lane checkout has advanced past the head
    // the FAIL was handed at. The recorded dispatch context names the stale
    // head (it never moves by itself), so without this read the round would
    // re-review the same head forever while the delivered repair sits
    // unreviewed. Read-only: the observation never writes, and a leg that did
    // not move leaves every input exactly as it was.
    if kind == crate::mutation::DELIVERY_STEP_KIND {
        bind_delivered_review_head(shared, &parsed.instance_id, &mut material.feature_head);
    }
    // Issue #243: the control that recomputes a recorded check is the RUN's own
    // act, exactly like the supervisor's continuation dispatch (issue #198), so
    // its inner re-dispatch presents a measurement taken at THIS dispatch when
    // the run's recorded proof has actually lapsed — bounded, audited and
    // recorded before it is presented (a host that cannot be measured renews
    // nothing and the admission gate refuses the recorded proof unchanged).
    // Nothing else moves: the control's own gates, the frontier authorization,
    // the caps and the freshness bound are untouched, and only the authorized
    // re-evaluation ever takes this path.
    if reevaluation.is_some() {
        renew_host_proof_for_dispatch(shared, &mut material, &parsed.step, &parsed.idempotency_key);
    }
    // Issue #250: the audited operator's own measurement. A parked run's
    // remedies used to name an `--admission FILE` no control could emit; when
    // the caller presents the operator pair, the daemon measures the host at
    // the run's lane root and binds the measurement as the proof this
    // dispatch presents (recorded before it is presented, `host.proof.renewal.
    // operator`). A host that cannot be measured produces nothing and the
    // admission gate keeps refusing the recorded proof, typed.
    if let (Some(operator), Some(reason)) = (&parsed.operator, &parsed.reason) {
        operator_measured_proof(
            shared,
            &mut material,
            &parsed.step,
            &parsed.idempotency_key,
            operator,
            reason,
        );
    }
    // Fail closed BEFORE anything is journaled or claimed: a request that is
    // not well-formed enough to be attempted refuses typed here, so the
    // operator's single-use retry authorization survives for the correction.
    // The contract is built from the SAME topology and durable worker-head
    // read-backs the derived dispatch presents, so the pre-screen and the
    // derived apply agree by construction.
    let has_archive_root = material
        .topology
        .get("archive_root")
        .is_some_and(|value| value.as_str().is_some());
    let worktrees_root = material
        .topology
        .get("worktrees_root")
        .and_then(Val::as_str)
        .map(std::path::PathBuf::from);
    if let Err((code, message)) = crate::mutation::check_step_params(
        &kind,
        effective.as_ref(),
        &crate::mutation::ParamContract {
            integration_branch: &integration_branch,
            production_branches: &production_branches,
            publish_route: &publish_route,
            observed_feature_head: material.feature_head.as_deref(),
            observed_integration_base: material.integration_base.as_deref(),
            has_archive_root,
            worktrees_root: worktrees_root.as_deref(),
        },
    ) {
        return err_response(&request.id, &code, message);
    }
    let key = parsed.idempotency_key.clone();
    let dispatch = match dispatch_request_from(&material, &parsed.step, effective.as_ref(), &key) {
        Ok(dispatch) => dispatch,
        Err((code, message)) => return err_response(&request.id, &code, message),
    };
    let response = method_apply(shared, &dispatch);
    let doc = match Val::parse_json(response.trim()) {
        Ok(doc) => doc,
        Err(message) => {
            return err_response(
                &request.id,
                "refusal.malformed",
                format!("the dispatch response is unreadable ({message})"),
            );
        }
    };
    if doc.get("ok").and_then(Val::as_bool) != Some(true) {
        let error = doc.get("error").cloned().unwrap_or_else(null);
        let code = error
            .get("code")
            .and_then(Val::as_str)
            .unwrap_or("refusal.malformed")
            .to_string();
        let message = error
            .get("message")
            .and_then(Val::as_str)
            .unwrap_or("the dispatch was refused")
            .to_string();
        return err_response(&request.id, &code, message);
    }
    let outcome = doc.get("result").cloned().unwrap_or_else(null);
    // Read back the authorization THIS dispatch consumed (the fence records
    // the presented key) so the document states the single use exactly.
    let retry = match shared.lock_state() {
        Ok(state) => state
            .run_retries(&parsed.instance_id)
            .unwrap_or_default()
            .into_iter()
            .filter(|row| row.step_id == parsed.step && row.consumed_key == key)
            .max_by_key(|row| row.attempt),
        Err(_) => None,
    };
    let document = crate::run_control::dispatch_doc(
        &material.instance,
        &material.spine,
        &parsed.step,
        &kind,
        effective.as_ref(),
        &outcome,
        retry.as_ref(),
    );
    ok_response(&request.id, document)
}

/// Issue #250: the remedy decision for ONE parked run, derived read-only from
/// the SAME durable facts each control's own gate reads.
///
/// The measured defect: a run parked by a refused dispatch named three
/// remedies and NONE could be satisfied — the retry budget was spent, the
/// re-evaluation does not address a diagnosed step, and the `--admission
/// FILE` the dispatch asked for was emitted by no control. An operator had to
/// try all three to discover that the run was immovable. This computes the
/// decision the operator should have been told: the ONE control that applies,
/// or the terminal typed escalation. Nothing is claimed, measured or written.
fn remedy_for_run(state: &crate::state::State, run: &crate::state::InstanceRow) -> Option<Val> {
    // Issue #250: a run can be parked by a dispatch that left NO attempt row
    // (the fan-out admission gate refuses before any intent is journaled,
    // issue #141), so the park is read from the recorded admission itself when
    // the ledger names nothing — the same facts the gate reads, and only when
    // the gate would really decide that dispatch.
    let (step, code, diagnosed) = match state.run_step_failure(&run.instance_id).ok().flatten() {
        Some(failure) => {
            // The diagnosis is the SAME fact the bounded-retry fence reads:
            // the step's newest recorded attempt is its own failure, never the
            // run's lapsed window.
            let diagnosed = state
                .run_step_diagnosed(&run.instance_id, &failure.step)
                .unwrap_or(false);
            (failure.step.clone(), failure.code.clone(), diagnosed)
        }
        None => {
            let (step, code) = recorded_proof_park(state, run)?;
            (step, code, false)
        }
    };
    let proof = code == crate::lifecycle::code::PROOF_STALE
        || code == crate::lifecycle::code::PROOF_MISSING;
    // Only a proof park turns on "can a proof be produced"; elsewhere the
    // question is moot and the answer is never consulted.
    let proof_producible = if proof {
        state
            .run_dispatch_context(&run.instance_id)
            .ok()
            .flatten()
            .is_some_and(|context| {
                let has_admission = context.admission.is_some();
                let lane_root = context.topology.get("worktrees_root").and_then(Val::as_str);
                has_admission
                    && lane_root.is_some_and(|root| {
                        matches!(
                            measure_host(&PathBuf::from(root)),
                            crate::lifecycle::HostMeasurement::Measured { .. }
                        )
                    })
            })
    } else {
        false
    };
    let retries = state.run_retries(&run.instance_id).ok()?;
    let retries_consumed = retries
        .iter()
        .filter(|row| row.step_id == step && !row.consumed_at.is_empty())
        .count() as i64;
    let retry_held = retries
        .iter()
        .any(|row| row.step_id == step && row.consumed_at.is_empty());
    let reevaluation_applies = reevaluation_applies_to(state, run, &step);
    Some(crate::run_control::remedy_doc(
        &crate::run_control::RemedyFacts {
            run: run.instance_id.clone(),
            step,
            code,
            diagnosed,
            retries_consumed,
            retry_held,
            reevaluation_applies,
            proof_producible,
        },
    ))
}

/// Issue #250: the park a run carries when NO attempt row names it — the
/// fan-out admission gate refuses BEFORE any intent is journaled (issue #141),
/// so a run whose dispatch was refused for its own recorded admission has
/// nothing for `run_step_failure` to read, while the refusal's own text points
/// the operator at `run status` for the ONE control that applies.
///
/// The decision is derived from the SAME durable facts the gate itself reads:
/// the run's frontier step, and only when its kind is one the gate DECIDES
/// (the fan-out kinds, and a self-dispatching review step), plus the recorded
/// dispatch context's admission and whether its proof is really past the
/// freshness bound the gate applies. `None` whenever the run is not parked
/// that way — a step the gate never decides, a fresh proof, a run with no
/// recorded admission to bind a measurement into, or a read that cannot
/// answer. Nothing is measured, claimed or written here.
fn recorded_proof_park(
    state: &crate::state::State,
    run: &crate::state::InstanceRow,
) -> Option<(String, String)> {
    let spine = state.run_step_spine(&run.instance_id).ok().flatten()?;
    let attempts = state.run_step_attempts(&run.instance_id).ok()?;
    let frontier = crate::run_control::frontier_of(&spine, &attempts, &run.current_node)?;
    let documents = state.run_step_documents(&run.instance_id).ok().flatten()?;
    let step = documents
        .iter()
        .find(|document| document.get("id").and_then(Val::as_str) == Some(frontier.as_str()))?;
    let kind = crate::mutation::step_kind(step).ok()?;
    let decided = matches!(kind.as_str(), "harness_start" | "prompt")
        || (kind == "review_evidence"
            && step
                .get("params")
                .is_some_and(|params| crate::mutation::declares_reviewer_leg(Some(params))));
    if !decided {
        return None;
    }
    // The context must carry the admission the gate would decide the NEXT
    // dispatch of that step on: without one there is nothing to bind a
    // measurement into, and the absent proof is never invented here. The proof
    // instant is read the SAME way the gate's own parser reads it
    // (`flags.admission.host_proof.measured_at`, RFC3339).
    let context = state
        .run_dispatch_context(&run.instance_id)
        .ok()
        .flatten()?;
    let admission = context.admission?;
    let measured_at = admission
        .get("host_proof")
        .and_then(|proof| proof.get("measured_at"))
        .and_then(Val::as_str)
        .and_then(crate::time::unix_from_rfc3339);
    let fresh = measured_at.is_some_and(|measured_at_unix| {
        crate::lifecycle::HostProof::at(measured_at_unix).fresh_at(crate::time::unix_now())
    });
    if fresh {
        return None;
    }
    // The same two codes the gate's own proof precondition returns.
    let code = if measured_at.is_some() {
        crate::lifecycle::code::PROOF_STALE
    } else {
        crate::lifecycle::code::PROOF_MISSING
    };
    Some((frontier, code.to_string()))
}

/// Whether `run.reevaluate` would be accepted for this (run, step) — the
/// SAME facts its own gate reads (`reevaluation_plan` over the recorded
/// attempt, the declared reviewer leg, the newest evidence's non-passing
/// checks and the recorded re-evaluations). A read that cannot answer is
/// `false`: the decision then refuses rather than naming a control that would
/// itself refuse.
fn reevaluation_applies_to(
    state: &crate::state::State,
    run: &crate::state::InstanceRow,
    step: &str,
) -> bool {
    let Ok(documents) = state.run_step_documents(&run.instance_id) else {
        return false;
    };
    let documents = documents.unwrap_or_default();
    let declared = documents
        .iter()
        .find(|document| document.get("id").and_then(Val::as_str) == Some(step));
    let kind = declared
        .and_then(|document| crate::mutation::step_kind(document).ok())
        .unwrap_or_default();
    let leg = declared
        .and_then(|document| document.get("params"))
        .is_some_and(|params| crate::mutation::declares_reviewer_leg(Some(params)));
    let Ok(attempts) = state.run_step_attempts(&run.instance_id) else {
        return false;
    };
    let latest = attempts
        .iter()
        .rfind(|(id, _)| id == step)
        .map(|(_, status)| status.clone());
    let successes = attempts
        .iter()
        .filter(|(id, status)| id == step && status == "succeeded")
        .count() as i64;
    let failing = state
        .evidence_for_instance(&run.instance_id)
        .ok()
        .and_then(|rows| rows.into_iter().next())
        .map(|row| {
            crate::mutation::non_passing_checks(&crate::mutation::EvidenceView {
                evidence_id: row.evidence_id.clone(),
                feature_head: row.feature_head.clone(),
                integration_base: row.integration_base.clone(),
                workflow_hash: row.workflow_hash.clone(),
                policy_hash: row.policy_hash.clone(),
                verdict: row.verdict.clone(),
                reviewer: row.reviewer.clone(),
                checks: row.checks.clone(),
                created_at: row.created_at.clone(),
            })
        })
        .transpose()
        .ok()
        .flatten()
        .unwrap_or_default();
    let recorded = state
        .run_reevaluations(&run.instance_id, step)
        .map(|rows| rows.len() as i64)
        .unwrap_or(0);
    crate::run_control::reevaluation_plan(
        &kind,
        leg,
        latest.as_deref(),
        &failing,
        recorded,
        successes,
    )
    .is_ok()
}

/// `run.status`: read the control state of exactly one run back read-only —
/// `pause_requested` (the request is durable, in-flight work still runs)
/// versus `paused` (the safe boundary has been reached) versus `active`,
/// plus the exact target and the scope block. No claim, no journal write.
fn method_run_status(shared: &Arc<Shared>, request: &Request) -> String {
    let Some(params) = request.params.as_ref() else {
        return err_response(
            &request.id,
            "refusal.malformed",
            "run.status requires params.instance_id (run- + 16 hex)",
        );
    };
    let instance_id = match crate::run_control::parse_status_target(params) {
        Ok(instance_id) => instance_id,
        Err(err) => return err_response(&request.id, err.code, err.message),
    };
    match shared.lock_state() {
        Ok(state) => match state.instance_by_id(&instance_id) {
            Ok(Some(row)) => {
                let in_flight = match state.in_flight_run_step(&instance_id) {
                    Ok(step) => step,
                    Err(err) => return err_response(&request.id, err.code, err.message),
                };
                let digest = if row.paused || row.pause_requested {
                    Some(row.resume_digest.clone())
                } else {
                    None
                };
                // Issue #219: the run's newest recorded failure WITH its raw
                // message rides the control document, so `run status` answers
                // "why is this run parked" without a daemon log.
                let last_failure = match state.run_step_failure(&instance_id) {
                    Ok(failure) => failure,
                    Err(err) => return err_response(&request.id, err.code, err.message),
                };
                // Issue #250: the remedy decision — the ONE control that
                // applies to the parked step, or the terminal typed
                // escalation. Derived from the same durable facts each
                // control's own gate reads (read-only; nothing is measured
                // into durable state, claimed or dispatched).
                let remedy = remedy_for_run(&state, &row);
                // Issue #267: the run's committed plan declares, per leg, the
                // role and the role skills the lane is given — a status read
                // shows them without re-reading the submission's raw line.
                let legs = match state.run_plan_legs(&instance_id) {
                    Ok(legs) => legs,
                    Err(err) => return err_response(&request.id, err.code, err.message),
                };
                let mut status = crate::run_control::control_doc(
                    &row,
                    in_flight.as_deref(),
                    digest.as_deref(),
                    last_failure.as_ref(),
                    remedy.as_ref(),
                );
                if let (Val::Obj(map), Some(legs)) = (&mut status, legs) {
                    map.insert("legs".to_string(), crate::state::plan_legs_doc(&legs));
                }
                ok_response(&request.id, status)
            }
            Ok(None) => err_response(
                &request.id,
                "state.not_found",
                format!("no run {instance_id:?} exists"),
            ),
            Err(err) => err_response(&request.id, err.code, err.message),
        },
        Err(message) => err_response(&request.id, "state.unavailable", message),
    }
}

/// `supervision.status`: read the versioned supervision status of exactly
/// ONE run back read-only — the recorded authorization, the class/reason the
/// driver last recorded, freshness, the last check, the next eligible check
/// with its reason, the observed meaningful-progress marker and the folded
/// pending wake. No claim, no journal write, and NO marker movement: a read
/// (or a rendered status) is never progress (issue #95 AC2/AC7).
/// `supervision.arm` (issue #261): arm exactly ONE already-admitted run that
/// carries no arming authorization — the bounded operator control that
/// recovers an inert run without release-and-resubmit. The authorization is
/// the exact one the run's OWN committed submission presented; nothing else
/// is invented, and the arm commits in ONE transaction with its
/// hash-chained audit row. A terminal run, an already-armed run, a run no
/// submission admitted and a submission that committed no `armed`
/// authorization all refuse typed.
fn method_supervision_arm(shared: &Arc<Shared>, request: &Request) -> String {
    let Some(params) = request.params.as_ref() else {
        return err_response(
            &request.id,
            "refusal.malformed",
            "supervision.arm requires params: idempotency_key, instance_id",
        );
    };
    let (instance_id, _) = match crate::supervision::parse_arm_params(params) {
        Ok(parsed) => parsed,
        Err(err) => return err_response(&request.id, err.code, err.message),
    };
    let target = format!("run:{instance_id}");
    let key = match journal_mutation(shared, request, "mutate.supervision.arm", &target) {
        Intent::Claimed { key } => key,
        Intent::Replay { response } => return replay(shared, &response),
        Intent::Refused { code, message } => return err_response(&request.id, code, &message),
    };
    crash_point("supervision.arm.after-intent");
    let outcome = (|| -> Result<Val, (&'static str, String)> {
        let state = shared
            .lock_state()
            .map_err(|message| ("state.unavailable", message))?;
        let at = time::rfc3339_now();
        let armed = state
            .arm_admitted_run(&instance_id, &key, &at)
            .map_err(|err| (err.code, err.message))?;
        Ok(crate::supervision::arm_doc(&armed, &at, &key))
    })();
    match outcome {
        Ok(doc) => finish_mutation(shared, request, &key, "supervision.arm", true, doc, None),
        Err((code, message)) => finish_mutation(
            shared,
            request,
            &key,
            "supervision.arm",
            false,
            null(),
            Some((code, message)),
        ),
    }
}

fn method_supervision_status(shared: &Arc<Shared>, request: &Request) -> String {
    let Some(params) = request.params.as_ref() else {
        return err_response(
            &request.id,
            "refusal.malformed",
            "supervision.status requires params.instance_id (run- + 16 hex)",
        );
    };
    let instance_id = match crate::supervision::parse_status_params(params) {
        Ok(instance_id) => instance_id,
        Err(err) => return err_response(&request.id, err.code, err.message),
    };
    match shared.lock_state() {
        Ok(state) => {
            let row = match state.supervision_by_id(&instance_id) {
                Ok(Some(row)) => row,
                Ok(None) => {
                    // Issue #261 AC4: an ADMITTED run with no supervision row
                    // at all is a readable state — "admitted, unarmed, nothing
                    // will drive it" — and not a bare not-found: a cap refusal
                    // must never be the only symptom. A run nobody admitted,
                    // a terminal run and an unknown run keep `state.not_found`.
                    let run = match state.instance_by_id(&instance_id) {
                        Ok(run) => run,
                        Err(err) => return err_response(&request.id, err.code, err.message),
                    };
                    let Some(run) = run else {
                        return err_response(
                            &request.id,
                            "state.not_found",
                            format!("no run {instance_id:?} exists"),
                        );
                    };
                    let submission = match state.admitted_submission_of(&instance_id) {
                        Ok(submission) => submission,
                        Err(err) => return err_response(&request.id, err.code, err.message),
                    };
                    if submission.is_none() {
                        return err_response(
                            &request.id,
                            "state.not_found",
                            format!(
                                "run {instance_id:?} was not admitted by a committed queue \
                                 submission (supervision is disabled by default and is armed \
                                 only by an explicit authorization committed with the run's \
                                 submission)"
                            ),
                        );
                    }
                    return ok_response(
                        &request.id,
                        crate::supervision::unarmed_doc(
                            &run,
                            submission.as_deref(),
                            &time::rfc3339_now(),
                        ),
                    );
                }
                Err(err) => return err_response(&request.id, err.code, err.message),
            };
            // Issue #268: one read of the run's recorded rows serves both the
            // evidence snapshot and the recorded worktrees root below.
            let records = match state.run_records(&instance_id) {
                Ok(records) => records,
                Err(err) => return err_response(&request.id, err.code, err.message),
            };
            let evidence = match state.supervision_evidence_from(&records) {
                Ok(Some(evidence)) => evidence,
                Ok(None) => {
                    return err_response(
                        &request.id,
                        "state.not_found",
                        format!("run {instance_id:?} no longer exists"),
                    );
                }
                Err(err) => return err_response(&request.id, err.code, err.message),
            };
            let trigger = match state.supervision_trigger(&instance_id) {
                Ok(trigger) => trigger,
                Err(err) => return err_response(&request.id, err.code, err.message),
            };
            let now_unix = time::unix_now();
            let policy = crate::supervision::Policy {
                check_interval_secs: row.check_interval_secs,
                progress_timeout_secs: row.progress_timeout_secs,
            };
            // Issue #256: the recorded handoff's OWN lane checkout is the root
            // the repair leg's delivered head is read from. The read is taken
            // AFTER the state guard is released, so a status read never holds
            // the state across a host read.
            let worktrees_root = crate::supervision::recorded_worktrees_root_of(&records);
            drop(state);
            let mut evidence = evidence;
            crate::supervision::observe_fix_leg(&mut evidence, worktrees_root.as_deref());
            let verdict = crate::supervision::classify(
                &evidence,
                &row.authorization_digest,
                &policy,
                now_unix,
            );
            // Issue #270: the driver's own pass progress rides on EVERY
            // supervision read: a stalled pass freezes every run's tick, so the
            // per-run read names the pass, its run/step and its age instead of
            // leaving the operator to notice frozen `last_check` stamps.
            let mut doc = crate::supervision::status_doc(
                &row,
                &evidence,
                trigger.as_ref(),
                &verdict,
                now_unix,
            );
            if let Val::Obj(fields) = &mut doc {
                fields.insert("driver".to_string(), shared.supervisor.pass_doc(now_unix));
            }
            ok_response(&request.id, doc)
        }
        Err(message) => err_response(&request.id, "state.unavailable", message),
    }
}

fn grant_doc(row: &crate::state::GrantRow) -> Val {
    object(vec![
        ("schema", string("hf-grant/v1")),
        ("grant_id", string(&row.grant_id)),
        ("repository", string(&row.repository)),
        (
            "issue",
            object(vec![
                ("number", integer(row.issue_number)),
                ("revision", string(&row.issue_revision)),
            ]),
        ),
        ("workflow_hash", string(&row.workflow_hash)),
        ("policy_hash", string(&row.policy_hash)),
        ("phase", string(&row.phase)),
        ("scope", string(&row.scope)),
        ("caps", string(&row.caps)),
        ("expires_at", string(&row.expires_at)),
        ("state_epoch", integer(row.state_epoch)),
        ("status", string(&row.status)),
        ("created_at", string(&row.created_at)),
    ])
}

// ---------------------------------------------------------------------------
// Lane replacement records (issue #73): request-only handoff surface.
// Every method on this surface persists daemon-owned state and journals its
// intent through the shared claim machinery; none of them spawns, kills, or
// touches Git, and none uplifts authority (no grants are required, issued,
// or consumed). An agent may *request* its own retirement; replacement
// phases are recorded, never executed.
// ---------------------------------------------------------------------------

/// Read one required string parameter (identity bindings refuse when they
/// are absent or the wrong type — never a defaulted value).
fn required_str<'a>(params: Option<&'a Val>, key: &str) -> Option<&'a str> {
    params
        .and_then(|params| params.get(key))
        .and_then(Val::as_str)
}

/// Parse one OPTIONAL presented `profile` target-profile binding (issue
/// #77). The document is validated and its revision recomputed at the
/// boundary (`config::ProfileBinding::from_doc`): a revision that does not
/// fingerprint the presented material refuses as `refusal.profile.revision`,
/// a malformed binding as `refusal.profile.binding`. Absent means the
/// request is unbound (allowed only where no plan exists).
fn presented_profile(
    params: Option<&Val>,
) -> Result<Option<crate::config::ProfileBinding>, (&'static str, String)> {
    match params.and_then(|params| params.get("profile")) {
        None | Some(Val::Null) => Ok(None),
        Some(doc) => crate::config::ProfileBinding::from_doc(doc)
            .map(Some)
            .map_err(|err| (err.code(), err.message().to_string())),
    }
}

/// Read the durable target-profile plan of one replacement record (issue
/// #77): `None` when the record was requested unbound. The stored canonical
/// document is re-validated and its revision re-derived, so a corrupted row
/// can never silently pass as a plan.
fn stored_profile(
    state: &crate::state::State,
    replacement_id: &str,
) -> Result<Option<crate::config::ProfileBinding>, (&'static str, String)> {
    let row = match state.lane_replacement_profile(replacement_id) {
        Ok(row) => row,
        Err(err) => return Err((err.code, err.message)),
    };
    let Some(row) = row else {
        return Ok(None);
    };
    let doc = Val::parse_json(&row.profile).map_err(|message| {
        (
            crate::config::CODE_PROFILE_BINDING,
            format!("the stored target-profile plan is unreadable: {message}"),
        )
    })?;
    let binding = crate::config::ProfileBinding::from_doc(&doc)
        .map_err(|err| (err.code(), err.message().to_string()))?;
    if binding.revision != row.revision {
        return Err((
            crate::config::CODE_PROFILE_REVISION,
            format!(
                "the stored target-profile plan revision {} does not match its fingerprint {}",
                row.revision, binding.revision
            ),
        ));
    }
    Ok(Some(binding))
}

/// `lane.replacement.request`: create the one replacement record for a
/// logical lane generation (phase `requested`). The request binds the
/// source session/process identity, role, worktree and reason; missing or
/// invalid identities refuse. This endpoint has no spawn/kill/Git effect
/// and no authority uplift — it never authorizes its own replacement
/// effects.
fn method_lane_replacement_request(shared: &Arc<Shared>, request: &Request) -> String {
    let params = request.params.as_ref();
    let lane_id = match required_str(params, "lane_id") {
        Some(text) if crate::formats::is_slug(text) => text.to_string(),
        _ => {
            return err_response(
                &request.id,
                "refusal.malformed",
                "lane.replacement.request requires params.lane_id (slug)",
            );
        }
    };
    let generation = match params
        .and_then(|params| params.get("generation"))
        .and_then(Val::as_int)
    {
        Some(generation) if generation >= 1 => generation,
        _ => {
            return err_response(
                &request.id,
                "refusal.malformed",
                "lane.replacement.request requires params.generation (positive integer)",
            );
        }
    };
    let source_session = match required_str(params, "source_session") {
        Some(text) if crate::formats::is_actor(text) => text.to_string(),
        _ => {
            return err_response(
                &request.id,
                "refusal.malformed",
                "lane.replacement.request requires params.source_session (session identity)",
            );
        }
    };
    let source_process = match required_str(params, "source_process") {
        Some(text) if crate::formats::is_actor(text) => text.to_string(),
        _ => {
            return err_response(
                &request.id,
                "refusal.malformed",
                "lane.replacement.request requires params.source_process (process identity)",
            );
        }
    };
    let role = match required_str(params, "role") {
        Some(text) if crate::state::LANE_REPLACEMENT_ROLES.contains(&text) => text.to_string(),
        _ => {
            return err_response(
                &request.id,
                "refusal.malformed",
                "lane.replacement.request requires params.role (one of the doctrine roles)",
            );
        }
    };
    let worktree = match required_str(params, "worktree") {
        Some(text) if crate::formats::is_worktree_ref(text) => text.to_string(),
        _ => {
            return err_response(
                &request.id,
                "refusal.malformed",
                "lane.replacement.request requires params.worktree (repository-relative path)",
            );
        }
    };
    let reason = match required_str(params, "reason") {
        Some(text)
            if !text.is_empty() && text.len() <= 300 && !text.chars().any(char::is_control) =>
        {
            text.to_string()
        }
        _ => {
            return err_response(
                &request.id,
                "refusal.malformed",
                "lane.replacement.request requires params.reason (1-300 printable characters)",
            );
        }
    };
    // Issue #77: an optional explicit target-profile binding plan (the
    // profile identity + configuration revision + intended provider/model
    // the human reviewed). It is validated and revision-checked BEFORE the
    // claim and bound into the replacement record in the same transaction.
    let profile = match presented_profile(params) {
        Ok(profile) => profile,
        Err((code, message)) => return err_response(&request.id, code, message),
    };
    let replacement_id = crate::state::replacement_id_for(&lane_id, generation);
    let target = format!("lane-replacement:{replacement_id}");
    match journal_mutation(shared, request, "mutate.lane-replacement.request", &target) {
        Intent::Claimed { key } => {
            let outcome = {
                let state = match shared.lock_state() {
                    Ok(state) => state,
                    Err(message) => {
                        return err_response(&request.id, "state.unavailable", message);
                    }
                };
                let profile_text = profile.as_ref().map(|binding| binding.to_canonical_text());
                match state.request_lane_replacement(
                    &lane_id,
                    generation,
                    &source_session,
                    &source_process,
                    &role,
                    &worktree,
                    &reason,
                    profile_text
                        .as_deref()
                        .zip(profile.as_ref().map(|binding| binding.revision.as_str())),
                    &time::rfc3339_now(),
                ) {
                    Ok(row) => Ok(object(vec![
                        ("replacement", crate::state::lane_replacement_val(&row)),
                        (
                            "profile",
                            profile
                                .as_ref()
                                .map(|binding| binding.to_doc())
                                .unwrap_or_else(null),
                        ),
                    ])),
                    Err(err) => Err((err.code, err.message)),
                }
            };
            match outcome {
                Ok(result) => finish_mutation(
                    shared,
                    request,
                    &key,
                    "lane.replacement.request",
                    true,
                    result,
                    None,
                ),
                Err((code, message)) => finish_mutation(
                    shared,
                    request,
                    &key,
                    "lane.replacement.request",
                    false,
                    null(),
                    Some((code, message)),
                ),
            }
        }
        Intent::Replay { response } => replay(shared, &response),
        Intent::Refused { code, message } => err_response(&request.id, code, message),
    }
}

/// `lane.replacement.advance`: transactional compare-and-set to the phase
/// that follows `expected_phase`. The presented generation fences stale
/// requests (and the update re-asserts it), so an invalid order, a stale
/// generation, or a replayed expectation can never advance state.
fn method_lane_replacement_advance(shared: &Arc<Shared>, request: &Request) -> String {
    let params = request.params.as_ref();
    let replacement_id = match required_str(params, "replacement_id") {
        Some(text) if crate::formats::is_replacement_id(text) => text.to_string(),
        _ => {
            return err_response(
                &request.id,
                "refusal.malformed",
                "lane.replacement.advance requires params.replacement_id (rp_ id)",
            );
        }
    };
    let expected_phase = match required_str(params, "expected_phase") {
        Some(text) if crate::state::LANE_REPLACEMENT_PHASES.contains(&text) => text.to_string(),
        _ => {
            return err_response(
                &request.id,
                "refusal.malformed",
                "lane.replacement.advance requires params.expected_phase (a lane replacement phase)",
            );
        }
    };
    let generation = match params
        .and_then(|params| params.get("generation"))
        .and_then(Val::as_int)
    {
        Some(generation) if generation >= 1 => generation,
        _ => {
            return err_response(
                &request.id,
                "refusal.malformed",
                "lane.replacement.advance requires params.generation (positive integer)",
            );
        }
    };
    let target = format!("lane-replacement:{replacement_id}");
    match journal_mutation(shared, request, "mutate.lane-replacement.advance", &target) {
        Intent::Claimed { key } => {
            crash_point("lane-replacement.after-intent");
            let outcome = {
                let state = match shared.lock_state() {
                    Ok(state) => state,
                    Err(message) => {
                        return err_response(&request.id, "state.unavailable", message);
                    }
                };
                match state.advance_lane_replacement(
                    &replacement_id,
                    &expected_phase,
                    generation,
                    &time::rfc3339_now(),
                ) {
                    Ok(row) => Ok(object(vec![(
                        "replacement",
                        crate::state::lane_replacement_val(&row),
                    )])),
                    Err(err) => Err((err.code, err.message)),
                }
            };
            match outcome {
                Ok(result) => finish_mutation(
                    shared,
                    request,
                    &key,
                    "lane.replacement.advance",
                    true,
                    result,
                    None,
                ),
                Err((code, message)) => finish_mutation(
                    shared,
                    request,
                    &key,
                    "lane.replacement.advance",
                    false,
                    null(),
                    Some((code, message)),
                ),
            }
        }
        Intent::Replay { response } => replay(shared, &response),
        Intent::Refused { code, message } => err_response(&request.id, code, message),
    }
}

/// `lane.replacement.hold`: park a pending replacement in the explicit
/// `held` outcome. Advancement is refused while held (the pause refusal),
/// and the held state is durable across daemon restarts.
fn method_lane_replacement_hold(shared: &Arc<Shared>, request: &Request) -> String {
    let params = request.params.as_ref();
    let replacement_id = match required_str(params, "replacement_id") {
        Some(text) if crate::formats::is_replacement_id(text) => text.to_string(),
        _ => {
            return err_response(
                &request.id,
                "refusal.malformed",
                "lane.replacement.hold requires params.replacement_id (rp_ id)",
            );
        }
    };
    let reason = match required_str(params, "reason") {
        Some(text)
            if !text.is_empty() && text.len() <= 300 && !text.chars().any(char::is_control) =>
        {
            text.to_string()
        }
        _ => {
            return err_response(
                &request.id,
                "refusal.malformed",
                "lane.replacement.hold requires params.reason (1-300 printable characters)",
            );
        }
    };
    let target = format!("lane-replacement:{replacement_id}");
    match journal_mutation(shared, request, "mutate.lane-replacement.hold", &target) {
        Intent::Claimed { key } => {
            let outcome = {
                let state = match shared.lock_state() {
                    Ok(state) => state,
                    Err(message) => {
                        return err_response(&request.id, "state.unavailable", message);
                    }
                };
                match state.hold_lane_replacement(&replacement_id, &reason, &time::rfc3339_now()) {
                    Ok(row) => Ok(object(vec![(
                        "replacement",
                        crate::state::lane_replacement_val(&row),
                    )])),
                    Err(err) => Err((err.code, err.message)),
                }
            };
            match outcome {
                Ok(result) => finish_mutation(
                    shared,
                    request,
                    &key,
                    "lane.replacement.hold",
                    true,
                    result,
                    None,
                ),
                Err((code, message)) => finish_mutation(
                    shared,
                    request,
                    &key,
                    "lane.replacement.hold",
                    false,
                    null(),
                    Some((code, message)),
                ),
            }
        }
        Intent::Replay { response } => replay(shared, &response),
        Intent::Refused { code, message } => err_response(&request.id, code, message),
    }
}

/// `lane.replacement.cancel`: invalidate a pending replacement before
/// retirement. The original lane is preserved untouched; the invalidated
/// record can never advance.
fn method_lane_replacement_cancel(shared: &Arc<Shared>, request: &Request) -> String {
    let params = request.params.as_ref();
    let replacement_id = match required_str(params, "replacement_id") {
        Some(text) if crate::formats::is_replacement_id(text) => text.to_string(),
        _ => {
            return err_response(
                &request.id,
                "refusal.malformed",
                "lane.replacement.cancel requires params.replacement_id (rp_ id)",
            );
        }
    };
    let reason = match params.and_then(|params| params.get("reason")) {
        None => String::new(),
        Some(Val::Str(text)) if text.len() <= 300 && !text.chars().any(char::is_control) => {
            text.clone()
        }
        _ => {
            return err_response(
                &request.id,
                "refusal.malformed",
                "lane.replacement.cancel reason must be <= 300 printable characters",
            );
        }
    };
    let target = format!("lane-replacement:{replacement_id}");
    match journal_mutation(shared, request, "mutate.lane-replacement.cancel", &target) {
        Intent::Claimed { key } => {
            let outcome = {
                let state = match shared.lock_state() {
                    Ok(state) => state,
                    Err(message) => {
                        return err_response(&request.id, "state.unavailable", message);
                    }
                };
                match state.cancel_lane_replacement(&replacement_id, &reason, &time::rfc3339_now())
                {
                    Ok(row) => Ok(object(vec![(
                        "replacement",
                        crate::state::lane_replacement_val(&row),
                    )])),
                    Err(err) => Err((err.code, err.message)),
                }
            };
            match outcome {
                Ok(result) => finish_mutation(
                    shared,
                    request,
                    &key,
                    "lane.replacement.cancel",
                    true,
                    result,
                    None,
                ),
                Err((code, message)) => finish_mutation(
                    shared,
                    request,
                    &key,
                    "lane.replacement.cancel",
                    false,
                    null(),
                    Some((code, message)),
                ),
            }
        }
        Intent::Replay { response } => replay(shared, &response),
        Intent::Refused { code, message } => err_response(&request.id, code, message),
    }
}

/// `lane.replacement.status`: read one replacement record with its exact
/// transition history and the precise next allowed transition. Read-only —
/// no claim, no journal write.
fn method_lane_replacement_status(shared: &Arc<Shared>, request: &Request) -> String {
    let replacement_id = match required_str(request.params.as_ref(), "replacement_id") {
        Some(text) if crate::formats::is_replacement_id(text) => text.to_string(),
        _ => {
            return err_response(
                &request.id,
                "refusal.malformed",
                "lane.replacement.status requires params.replacement_id (rp_ id)",
            );
        }
    };
    let state = match shared.lock_state() {
        Ok(state) => state,
        Err(message) => return err_response(&request.id, "state.unavailable", message),
    };
    let row = match state.lane_replacement_by_id(&replacement_id) {
        Ok(Some(row)) => row,
        Ok(None) => {
            return err_response(
                &request.id,
                "state.not_found",
                format!("no lane replacement {replacement_id:?}"),
            );
        }
        Err(err) => return err_response(&request.id, err.code, err.message),
    };
    let history = match state.lane_replacement_events(&replacement_id) {
        Ok(events) => events,
        Err(err) => return err_response(&request.id, err.code, err.message),
    };
    let history: Vec<Val> = history
        .iter()
        .map(crate::state::lane_replacement_event_val)
        .collect();
    // The committed successor boundary (issue #76) is part of the record's
    // status: null until a start commits it, then the durable successor row.
    let successor = match state.lane_successor_by_replacement(&replacement_id) {
        Ok(Some(row)) => crate::state::lane_successor_val(&row),
        Ok(None) => null(),
        Err(err) => return err_response(&request.id, err.code, err.message),
    };
    // The bound target-profile plan (issue #77), when the record was
    // requested under one: the reviewer-facing identity/fingerprint surface
    // (intended pair, authorized fallbacks, configured limits, credential
    // digests — never values).
    let profile = match state.lane_replacement_profile(&replacement_id) {
        Ok(Some(row)) => crate::state::lane_replacement_profile_val(&row),
        Ok(None) => null(),
        Err(err) => return err_response(&request.id, err.code, err.message),
    };
    ok_response(
        &request.id,
        object(vec![
            ("replacement", crate::state::lane_replacement_val(&row)),
            ("profile", profile),
            ("successor", successor),
            ("history", Val::Arr(history)),
        ]),
    )
}

/// `lane.checkpoint.create`: capture ONE atomic checkpoint at the quiescing
/// boundary (issue #74). The request carries the replacement identity, the
/// source-generation fence, and TWO observations of the lane; the capture
/// refuses (`refusal.checkpoint.changed`) when the two views disagree.
/// Active external harness execution requires a supported quiescence
/// acknowledgment AND a process/child observation (`refusal.checkpoint.ack`);
/// an observed active/ambiguous side-effecting child holds completion
/// (`refusal.checkpoint.held` — nothing is signalled, killed, or cleaned up
/// to obtain a snapshot); oversize required data is a typed hold
/// (`refusal.checkpoint.oversize`); missing evidence refuses
/// (`refusal.checkpoint.incomplete`). The checkpoint row and the record's
/// `quiescing` → `checkpointed` transition commit in ONE transaction (the
/// commit marker); the derived brief artifact is materialized after the
/// commit and a restart regenerates it from the durable row. No spawn, kill,
/// or Git effect exists on this path, and no grant is required, issued, or
/// consumed.
fn method_lane_checkpoint_create(shared: &Arc<Shared>, request: &Request) -> String {
    let params = request.params.as_ref();
    let replacement_id = match required_str(params, "replacement_id") {
        Some(text) if crate::formats::is_replacement_id(text) => text.to_string(),
        _ => {
            return err_response(
                &request.id,
                "refusal.malformed",
                "lane.checkpoint.create requires params.replacement_id (rp_ id)",
            );
        }
    };
    let generation = match params
        .and_then(|params| params.get("generation"))
        .and_then(Val::as_int)
    {
        Some(generation) if generation >= 1 => generation,
        _ => {
            return err_response(
                &request.id,
                "refusal.malformed",
                "lane.checkpoint.create requires params.generation (positive integer)",
            );
        }
    };
    let observation = match params.and_then(|params| params.get("observation")) {
        Some(value @ Val::Obj(_)) => value.clone(),
        _ => {
            return err_response(
                &request.id,
                "refusal.malformed",
                "lane.checkpoint.create requires params.observation (object)",
            );
        }
    };
    let reobservation = match params.and_then(|params| params.get("reobservation")) {
        Some(value @ Val::Obj(_)) => value.clone(),
        _ => {
            return err_response(
                &request.id,
                "refusal.malformed",
                "lane.checkpoint.create requires params.reobservation (object; the second \
                 observation of the same capture window)",
            );
        }
    };
    let target = format!("lane-checkpoint:{replacement_id}");
    match journal_mutation(shared, request, "mutate.lane-checkpoint.create", &target) {
        Intent::Claimed { key } => {
            crash_point("lane-checkpoint.after-intent");
            let outcome = {
                let state = match shared.lock_state() {
                    Ok(state) => state,
                    Err(message) => {
                        return err_response(&request.id, "state.unavailable", message);
                    }
                };
                state
                    .commit_lane_checkpoint(
                        &replacement_id,
                        generation,
                        &observation,
                        &reobservation,
                        &key,
                        &time::rfc3339_now(),
                    )
                    .map_err(|err| (err.code, err.message))
            };
            match outcome {
                Ok((checkpoint, replacement, brief)) => {
                    crash_point("lane-checkpoint.after-record");
                    let brief_path = match write_checkpoint_brief(
                        &shared.paths.checkpoints_dir,
                        &checkpoint.checkpoint_id,
                        &checkpoint.brief_digest,
                        &brief,
                    ) {
                        Ok(path) => path,
                        Err(message) => {
                            // The commit is the contract; the brief is a
                            // derivation. A failed materialization is
                            // logged and reconciled (regenerated) on the
                            // next daemon start — never a state rollback.
                            shared.log.write(
                                "warn",
                                "checkpoint.brief.deferred",
                                &format!(
                                    "checkpoint {} brief artifact not materialized ({}); \
                                     restart reconciliation regenerates it from the durable row",
                                    checkpoint.checkpoint_id, message
                                ),
                            );
                            checkpoint_brief_path(
                                &shared.paths.checkpoints_dir,
                                &checkpoint.checkpoint_id,
                            )
                        }
                    };
                    let mut checkpoint_val = crate::state::lane_checkpoint_val(&checkpoint);
                    if let Val::Obj(map) = &mut checkpoint_val {
                        map.insert(
                            "brief_path".to_string(),
                            string(brief_path.to_string_lossy().as_ref()),
                        );
                    }
                    finish_mutation(
                        shared,
                        request,
                        &key,
                        "lane.checkpoint.create",
                        true,
                        object(vec![
                            ("checkpoint", checkpoint_val),
                            ("brief", string(&brief)),
                            (
                                "replacement",
                                crate::state::lane_replacement_val(&replacement),
                            ),
                        ]),
                        None,
                    )
                }
                Err((code, message)) => finish_mutation(
                    shared,
                    request,
                    &key,
                    "lane.checkpoint.create",
                    false,
                    null(),
                    Some((code, message)),
                ),
            }
        }
        Intent::Replay { response } => replay(shared, &response),
        Intent::Refused { code, message } => err_response(&request.id, code, message),
    }
}

/// `lane.checkpoint.status`: read the durable checkpoint committed for one
/// replacement record (with its digest bindings and the derived brief
/// artifact pointer). Read-only — no claim, no journal write, and no
/// artifact materialization.
fn method_lane_checkpoint_status(shared: &Arc<Shared>, request: &Request) -> String {
    let replacement_id = match required_str(request.params.as_ref(), "replacement_id") {
        Some(text) if crate::formats::is_replacement_id(text) => text.to_string(),
        _ => {
            return err_response(
                &request.id,
                "refusal.malformed",
                "lane.checkpoint.status requires params.replacement_id (rp_ id)",
            );
        }
    };
    let state = match shared.lock_state() {
        Ok(state) => state,
        Err(message) => return err_response(&request.id, "state.unavailable", message),
    };
    let row = match state.lane_checkpoint_by_replacement(&replacement_id) {
        Ok(Some(row)) => row,
        Ok(None) => {
            return err_response(
                &request.id,
                "state.not_found",
                format!("no lane checkpoint for replacement {replacement_id:?}"),
            );
        }
        Err(err) => return err_response(&request.id, err.code, err.message),
    };
    let mut checkpoint_val = crate::state::lane_checkpoint_val(&row);
    if let Val::Obj(map) = &mut checkpoint_val {
        let path = checkpoint_brief_path(&shared.paths.checkpoints_dir, &row.checkpoint_id);
        map.insert(
            "brief_path".to_string(),
            string(path.to_string_lossy().as_ref()),
        );
    }
    ok_response(&request.id, object(vec![("checkpoint", checkpoint_val)]))
}

/// `lane.retire`: gracefully retire ONE checkpointed source session (issue
/// #75). The request binds the record's lane generation, source
/// session/process identity and the committed checkpoint digest (the
/// binding document); a changed identity, checkpoint or paused state refuses
/// BEFORE any effect (and before the claim). The retirement then re-validates
/// the immediate pre-stop quiescence recheck (unknown child activity or an
/// unknown process identity HOLDS), issues exactly ONE bounded graceful stop
/// through the workspace (Herdr) session adapter row, and confirms the
/// retirement from backend evidence — the process is absent AND the
/// ownership/registration is released for the bound session and generation —
/// never from pane text or a label. This path has no SIGKILL, no broad
/// pattern, no process-group signal and no authority escalation: a stop or a
/// confirmation that cannot prove the outcome holds and parks the record
/// `ambiguous` for external reconciliation. Child lanes are never addressed:
/// only the record's own bound session identity is.
fn method_lane_retire(shared: &Arc<Shared>, request: &Request) -> String {
    let Some(params) = request.params.as_ref() else {
        return err_response(
            &request.id,
            "refusal.malformed",
            "lane.retire requires params: replacement_id, binding, recheck, harness",
        );
    };
    let replacement_id = match required_str(Some(params), "replacement_id") {
        Some(text) if crate::formats::is_replacement_id(text) => text.to_string(),
        _ => {
            return err_response(
                &request.id,
                "refusal.malformed",
                "lane.retire requires params.replacement_id (rp_ id)",
            );
        }
    };
    if !matches!(params.get("binding"), Some(Val::Obj(_))) {
        return err_response(
            &request.id,
            crate::state::retirement_code::BINDING,
            "lane.retire requires params.binding (object: generation, session, process, \
             checkpoint_digest)",
        );
    }
    if !matches!(params.get("recheck"), Some(Val::Obj(_))) {
        return err_response(
            &request.id,
            crate::state::retirement_code::HELD,
            "lane.retire requires params.recheck (the immediate pre-stop quiescence recheck)",
        );
    }
    let harness = match params.get("harness") {
        Some(harness @ Val::Obj(_)) => harness,
        _ => {
            return err_response(
                &request.id,
                "refusal.malformed",
                "lane.retire requires params.harness (object: key, kind[, executable, \
                 capabilities])",
            );
        }
    };
    let profile = match retirement_profile(harness) {
        Ok(profile) => profile,
        Err((code, message)) => return err_response(&request.id, code, message),
    };
    // The retirement's only wired adapter path is the workspace/Herdr session
    // rows (the bounded stop and the confirmation read). A profile that does
    // not declare both required capabilities is an unsupported adapter and
    // refuses BEFORE the claim — no state changes and nothing is signalled.
    for capability in [
        crate::adapters::Op::Interrupt.capability(),
        crate::adapters::Op::Observe.capability(),
    ] {
        if !profile.supports(capability) {
            return err_response(
                &request.id,
                crate::adapters::CODE_UNKNOWN_CAPABILITY,
                format!(
                    "harness profile {:?} does not declare the {capability:?} capability that \
                     the retirement path requires; unsupported adapters are refused",
                    profile.key
                ),
            );
        }
    }
    let target = format!("lane-retire:{replacement_id}");
    match journal_mutation(shared, request, "mutate.lane.retire", &target) {
        Intent::Claimed { key } => {
            crash_point("lane-retire.after-intent");
            let bound = {
                let state = match shared.lock_state() {
                    Ok(state) => state,
                    Err(message) => {
                        return err_response(&request.id, "state.unavailable", message);
                    }
                };
                state
                    .begin_lane_retirement(params)
                    .map_err(|err| (err.code, err.message))
            };
            let plan = match bound {
                Ok(plan) => plan,
                Err((code, message)) => {
                    return finish_mutation(
                        shared,
                        request,
                        &key,
                        "lane.retire",
                        false,
                        null(),
                        Some((code, message)),
                    );
                }
            };
            let target = crate::adapters::RetirementTarget {
                session: plan.record.source_session.clone(),
                process: plan.record.source_process.clone(),
            };
            let env = crate::config::adapter_environment();
            // The ONE bounded graceful stop request this slice ever issues.
            let stop = crate::adapters::retirement_stop(
                &profile,
                &target,
                &env,
                crate::adapters::ADAPTER_TIMEOUT,
            );
            crash_point("lane-retire.after-stop");
            if stop.status != "succeeded" {
                let detail = stop
                    .message
                    .clone()
                    .or_else(|| stop.detail.clone())
                    .unwrap_or_else(|| "no diagnostic".to_string());
                if stop.code == Some(crate::adapters::CODE_UNAVAILABLE) {
                    // The stop row never ran: nothing was signalled and the
                    // record is untouched (a retry with a fresh key is safe).
                    return finish_mutation(
                        shared,
                        request,
                        &key,
                        "lane.retire",
                        false,
                        null(),
                        Some((crate::adapters::CODE_UNAVAILABLE, detail)),
                    );
                }
                return park_retirement(
                    shared,
                    request,
                    &key,
                    params,
                    &format!(
                        "the bounded graceful stop of session {:?} did not confirm ({}); the \
                         delivery is unknown and NO further signal is attempted",
                        target.session, detail
                    ),
                    crate::state::retirement_code::HELD,
                    format!(
                        "the graceful stop of session {:?} did not confirm ({}); the retirement \
                         holds (no SIGKILL, no broad pattern, no process-group signal) and \
                         external reconciliation is required",
                        target.session, detail
                    ),
                );
            }
            let evidence = crate::adapters::retirement_evidence(
                &profile,
                &target,
                plan.record.generation,
                &env,
                crate::adapters::ADAPTER_TIMEOUT,
            );
            match evidence {
                Ok(crate::adapters::RetirementEvidence::Retired) => {
                    let reason = format!(
                        "retired after one bounded graceful stop: backend process absent and \
                         registration released for session {:?} generation {} (checkpoint {} \
                         digest {}; recheck observed {})",
                        target.session,
                        plan.record.generation,
                        plan.checkpoint.checkpoint_id,
                        &plan.checkpoint.digest[..16],
                        plan.recheck_observed_at
                    );
                    let committed = {
                        let state = match shared.lock_state() {
                            Ok(state) => state,
                            Err(message) => {
                                return err_response(&request.id, "state.unavailable", message);
                            }
                        };
                        state
                            .commit_lane_retirement(
                                &plan.record.replacement_id,
                                plan.record.generation,
                                &plan.checkpoint.digest,
                                &reason,
                                &time::rfc3339_now(),
                            )
                            .map_err(|err| (err.code, err.message))
                    };
                    let row = match committed {
                        Ok(row) => row,
                        Err((code, message)) => {
                            // The stop happened but the transition could not
                            // commit: the record is parked for external
                            // reconciliation and NO signal is repeated.
                            return park_retirement(
                                shared,
                                request,
                                &key,
                                params,
                                &format!(
                                    "the retirement transition could not commit after the \
                                     graceful stop ({code}: {message}); no signal is repeated"
                                ),
                                crate::state::retirement_code::HELD,
                                format!(
                                    "the graceful stop of session {:?} was issued but the \
                                     retirement could not commit ({code}: {message}); external \
                                     reconciliation is required",
                                    target.session
                                ),
                            );
                        }
                    };
                    let retirement = object(vec![
                        ("replacement", crate::state::lane_replacement_val(&row)),
                        ("checkpoint_id", string(&plan.checkpoint.checkpoint_id)),
                        ("checkpoint_digest", string(&plan.checkpoint.digest)),
                        ("session", string(&plan.record.source_session)),
                        ("process", string(&plan.record.source_process)),
                        (
                            "stop",
                            object(vec![
                                ("status", string(stop.status)),
                                ("bounded", bool_(true)),
                                (
                                    "elapsed_ms",
                                    integer(stop.elapsed_ms.min(i64::MAX as u64) as i64),
                                ),
                            ]),
                        ),
                        (
                            "evidence",
                            object(vec![
                                ("process", string("absent")),
                                ("registration", string("released")),
                                ("generation", integer(plan.record.generation)),
                                ("observed_at", string(&time::rfc3339_now())),
                            ]),
                        ),
                    ]);
                    finish_mutation(
                        shared,
                        request,
                        &key,
                        "lane.retire",
                        true,
                        object(vec![("retirement", retirement)]),
                        None,
                    )
                }
                Ok(crate::adapters::RetirementEvidence::Held { detail }) => park_retirement(
                    shared,
                    request,
                    &key,
                    params,
                    &format!(
                        "the post-stop confirmation could not prove absence ({}); no signal is \
                         repeated",
                        detail
                    ),
                    crate::state::retirement_code::HELD,
                    format!(
                        "the retirement of session {:?} could not be confirmed ({}); nothing \
                         further is signalled and external reconciliation is required",
                        target.session, detail
                    ),
                ),
                Ok(crate::adapters::RetirementEvidence::Reused { detail }) => park_retirement(
                    shared,
                    request,
                    &key,
                    params,
                    &format!(
                        "the post-stop confirmation observed a reused identity ({}); no signal \
                         is repeated against it",
                        detail
                    ),
                    crate::state::retirement_code::REUSED,
                    format!(
                        "the retirement of session {:?} fails closed: backend evidence shows a \
                         reused identity ({}); no signal is repeated and external reconciliation \
                         is required",
                        target.session, detail
                    ),
                ),
                Err(err) => park_retirement(
                    shared,
                    request,
                    &key,
                    params,
                    &format!(
                        "the post-stop confirmation read-back failed ({}: {}); no signal is \
                         repeated",
                        err.code, err.message
                    ),
                    crate::state::retirement_code::HELD,
                    format!(
                        "the retirement of session {:?} could not be confirmed ({}: {}); nothing \
                         further is signalled and external reconciliation is required",
                        target.session, err.code, err.message
                    ),
                ),
            }
        }
        Intent::Replay { response } => replay(shared, &response),
        Intent::Refused { code, message } => err_response(&request.id, code, message),
    }
}

/// Park a record `ambiguous` after a retirement whose stop delivery or
/// confirmation is in doubt, then answer the typed refusal. The park is the
/// explicit "external reconciliation required" outcome; no further signal is
/// ever attempted (never against a reused identity).
fn park_retirement(
    shared: &Arc<Shared>,
    request: &Request,
    key: &str,
    params: &Val,
    park_reason: &str,
    code: &'static str,
    message: String,
) -> String {
    match shared.lock_state() {
        Ok(state) => {
            if let Err(err) =
                state.mark_replacement_ambiguous(params, park_reason, &time::rfc3339_now())
            {
                shared.log.write(
                    "error",
                    "lane.retire.park_failed",
                    &format!("{}: {}", err.code, err.message),
                );
                return err_response(&request.id, err.code, err.message);
            }
        }
        Err(lock_message) => {
            return err_response(&request.id, "state.unavailable", lock_message);
        }
    }
    finish_mutation(
        shared,
        request,
        key,
        "lane.retire",
        false,
        null(),
        Some((code, message)),
    )
}

/// Build the retirement adapter profile from the request's `harness` binding
/// (the planner shape: an official kind, or an explicit declarative `argv`
/// declaration carrying its own executable and closed capability set).
/// Unknown kinds and malformed declarations refuse; nothing is inferred.
fn retirement_profile(harness: &Val) -> Result<crate::adapters::Profile, (&'static str, String)> {
    use crate::adapters::{HarnessKind, Profile};
    let key = match harness.get("key").and_then(Val::as_str) {
        Some(key) if crate::formats::is_actor(key) => key.to_string(),
        _ => {
            return Err((
                "refusal.malformed",
                "lane.retire requires params.harness.key (actor identity)".to_string(),
            ));
        }
    };
    let kind_name = match harness.get("kind").and_then(Val::as_str) {
        Some(kind) => kind,
        _ => {
            return Err((
                "refusal.malformed",
                "lane.retire requires params.harness.kind (an adapter kind)".to_string(),
            ));
        }
    };
    let Some(kind) = HarnessKind::parse(kind_name) else {
        return Err((
            crate::adapters::CODE_UNKNOWN_HARNESS,
            format!(
                "unknown harness kind {kind_name:?}; supported kinds: {}",
                HarnessKind::OFFICIAL
                    .iter()
                    .map(|kind| kind.name())
                    .chain(std::iter::once("argv"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        ));
    };
    if kind == HarnessKind::Argv {
        let executable = match harness.get("executable").and_then(Val::as_str) {
            Some(executable) => executable,
            _ => {
                return Err((
                    "refusal.malformed",
                    "an argv harness binding requires params.harness.executable (a bare \
                     executable name)"
                        .to_string(),
                ));
            }
        };
        let capabilities: Vec<&str> = match harness.get("capabilities") {
            Some(Val::Arr(items)) => items.iter().filter_map(Val::as_str).collect(),
            _ => {
                return Err((
                    crate::adapters::CODE_UNKNOWN_CAPABILITY,
                    "an argv harness binding must declare params.harness.capabilities (an \
                     explicit capability set)"
                        .to_string(),
                ));
            }
        };
        return Profile::argv(
            key,
            executable,
            &capabilities,
            std::collections::BTreeMap::new(),
        )
        .map_err(|err| (err.code, err.message));
    }
    Profile::official(kind, key).map_err(|err| (err.code, err.message))
}

/// `lane.start`: commit ONE successor owner boundary and start a FRESH
/// successor session on the SAME logical lane/worktree (issue #76), then
/// verify it through the adapters before it can ever be adopted.
///
/// The request binds the record's lane generation, the committed checkpoint
/// digest and the ONE startup nonce (`binding`), the successor session and
/// kickoff receipt (`successor`) and the adapter profile (`harness`). The
/// record must have committed its verified retirement (`retired`); a
/// changed generation, checkpoint digest, paused/ambiguous/cancelled record
/// or missing evidence refuses BEFORE any effect. The existing admission
/// gate applies first: a capacity/resource/host-proof refusal is a typed
/// hold that spawns nothing and never disables admission.
///
/// One generation/nonce owns startup: the successor row and the
/// `retired` → `starting` transition commit in ONE transaction BEFORE any
/// spawn, so a simultaneous or replayed start can never create a second
/// successor. The spawn is ONE bounded `session start <session> --json`
/// row (no transcript replay, no reset, no cleanup); a start that never ran
/// leaves the boundary undelivered for a bounded same-nonce retry, and any
/// unconfirmed delivery parks the record for external reconciliation. The
/// follow-up `session show <session> --json` read-back must prove the fresh
/// session identity, role, harness profile, the SAME worktree, the kickoff
/// receipt and adapter-observed readiness — a spawned process alone is
/// never adopted. Only the closed verification verdict commits the
/// `starting` → `adopting` boundary.
fn method_lane_start(shared: &Arc<Shared>, request: &Request) -> String {
    let Some(params) = request.params.as_ref() else {
        return err_response(
            &request.id,
            "refusal.malformed",
            "lane.start requires params: replacement_id, binding, successor, harness[, \
             admission]",
        );
    };
    let replacement_id = match required_str(Some(params), "replacement_id") {
        Some(text) if crate::formats::is_replacement_id(text) => text.to_string(),
        _ => {
            return err_response(
                &request.id,
                "refusal.malformed",
                "lane.start requires params.replacement_id (rp_ id)",
            );
        }
    };
    if !matches!(params.get("binding"), Some(Val::Obj(_))) {
        return err_response(
            &request.id,
            crate::state::successor_code::BINDING,
            "lane.start requires params.binding (object: generation, checkpoint_digest, \
             nonce)",
        );
    }
    if !matches!(params.get("successor"), Some(Val::Obj(_))) {
        return err_response(
            &request.id,
            crate::state::successor_code::BINDING,
            "lane.start requires params.successor (object: session, kickoff_receipt)",
        );
    }
    let harness = match params.get("harness") {
        Some(harness @ Val::Obj(_)) => harness,
        _ => {
            return err_response(
                &request.id,
                "refusal.malformed",
                "lane.start requires params.harness (object: key, kind[, executable, \
                 capabilities])",
            );
        }
    };
    let profile = match retirement_profile(harness) {
        Ok(profile) => profile,
        Err((code, message)) => return err_response(&request.id, code, message),
    };
    // The start/verify path is the workspace (Herdr) session rows: the SAME
    // single adapter path the retirement uses. A profile that does not
    // declare both required capabilities is an unsupported adapter and
    // refuses BEFORE the claim.
    for capability in [
        crate::adapters::Op::Start.capability(),
        crate::adapters::Op::Observe.capability(),
    ] {
        if !profile.supports(capability) {
            return err_response(
                &request.id,
                crate::adapters::CODE_UNKNOWN_CAPABILITY,
                format!(
                    "harness profile {:?} does not declare the {capability:?} capability that \
                     the successor start path requires; unsupported adapters are refused",
                    profile.key
                ),
            );
        }
    }
    // Issue #77: when the replacement was requested under an explicit
    // profile-configuration revision, the start must present the SAME
    // reviewed target-profile binding (validated + revision-checked here;
    // the durable equality check lives in `begin_lane_successor`).
    let presented = match presented_profile(Some(params)) {
        Ok(profile) => profile,
        Err((code, message)) => return err_response(&request.id, code, message),
    };
    let target = format!("lane-start:{replacement_id}");
    match journal_mutation(shared, request, "mutate.lane.start", &target) {
        Intent::Claimed { key } => {
            crash_point("lane-start.after-intent");
            let bound = {
                let state = match shared.lock_state() {
                    Ok(state) => state,
                    Err(message) => {
                        return err_response(&request.id, "state.unavailable", message);
                    }
                };
                state
                    .begin_lane_successor(params)
                    .map_err(|err| (err.code, err.message))
            };
            let plan = match bound {
                Ok(plan) => plan,
                Err((code, message)) => {
                    return finish_mutation(
                        shared,
                        request,
                        &key,
                        "lane.start",
                        false,
                        null(),
                        Some((code, message)),
                    );
                }
            };
            // The durable planned target-profile binding (issue #77): the
            // successor read-back is verified against it. A stored plan that
            // no longer validates refuses here, before any effect.
            let target_binding = {
                let state = match shared.lock_state() {
                    Ok(state) => state,
                    Err(message) => {
                        return err_response(&request.id, "state.unavailable", message);
                    }
                };
                match stored_profile(&state, &plan.record.replacement_id) {
                    Ok(binding) => binding,
                    Err((code, message)) => {
                        drop(state);
                        return finish_mutation(
                            shared,
                            request,
                            &key,
                            "lane.start",
                            false,
                            null(),
                            Some((code, message)),
                        );
                    }
                }
            };
            // The spawn must run the profile the plan names (issue #77): a
            // start that runs another harness profile than the reviewed
            // target refuses before any effect.
            if let Some(planned) = &target_binding
                && (planned.key != profile.key || planned.kind != profile.kind.name())
            {
                return finish_mutation(
                    shared,
                    request,
                    &key,
                    "lane.start",
                    false,
                    null(),
                    Some((
                        crate::config::CODE_PROFILE_BINDING,
                        format!(
                            "replacement {} was reviewed for target profile {:?}/{:?} but \
                             the start runs harness profile {:?}/{:?}; the spawn must run \
                             the reviewed target profile",
                            plan.record.replacement_id,
                            planned.key,
                            planned.kind,
                            profile.key,
                            profile.kind.name()
                        ),
                    )),
                );
            }
            if let (Some(planned), Some(presented)) = (&target_binding, &presented)
                && planned.revision != presented.revision
            {
                // The changed-revision fence before any spawn (the durable
                // equality check re-asserts it in `begin_lane_successor`):
                // the profile configuration moved after the preview.
                return finish_mutation(
                    shared,
                    request,
                    &key,
                    "lane.start",
                    false,
                    null(),
                    Some((
                        crate::config::CODE_PROFILE_REVISION,
                        format!(
                            "replacement {} was reviewed under target profile revision {} \
                             but the start presents revision {}; the profile configuration \
                             changed after the preview and a newly reviewed plan is required",
                            plan.record.replacement_id, planned.revision, presented.revision
                        ),
                    )),
                );
            }
            // Existing concurrency/resource gates apply BEFORE anything is
            // committed or spawned: a capacity refusal is a typed hold, the
            // record is untouched and a bounded explicit retry stays legal.
            if let Err((code, message)) =
                successor_admission(params, &profile.key, &plan.record.worktree)
            {
                return finish_mutation(
                    shared,
                    request,
                    &key,
                    "lane.start",
                    false,
                    null(),
                    Some((code, message)),
                );
            }
            let env = crate::config::adapter_environment();
            // The source-absence recheck: source and successor must never
            // both be live/ambiguous (AC3). Refused BEFORE any successor
            // effect: nothing is spawned and no state changes.
            let source_target = crate::adapters::RetirementTarget {
                session: plan.record.source_session.clone(),
                process: plan.record.source_process.clone(),
            };
            match crate::adapters::retirement_evidence(
                &profile,
                &source_target,
                plan.record.generation,
                &env,
                crate::adapters::ADAPTER_TIMEOUT,
            ) {
                Ok(crate::adapters::RetirementEvidence::Retired) => {}
                Ok(crate::adapters::RetirementEvidence::Held { detail }) => {
                    return finish_mutation(
                        shared,
                        request,
                        &key,
                        "lane.start",
                        false,
                        null(),
                        Some((
                            crate::state::successor_code::SOURCE_LIVE,
                            format!(
                                "the bound source session {:?} is still present or its \
                                 absence cannot be proven ({}); source and successor must \
                                 never both be live — nothing was spawned",
                                source_target.session, detail
                            ),
                        )),
                    );
                }
                Ok(crate::adapters::RetirementEvidence::Reused { detail }) => {
                    return finish_mutation(
                        shared,
                        request,
                        &key,
                        "lane.start",
                        false,
                        null(),
                        Some((
                            crate::state::retirement_code::REUSED,
                            format!(
                                "the source-absence recheck observed a reused identity for \
                                 session {:?} ({}); nothing was spawned and external \
                                 reconciliation is required",
                                source_target.session, detail
                            ),
                        )),
                    );
                }
                Err(err) => {
                    // A read-back that never ran (the workspace executable is
                    // unavailable) signals nothing and changes nothing — the
                    // same refusal the retirement path uses. Every other
                    // unreadable/unknown source state holds.
                    let code = if err.code == crate::adapters::CODE_UNAVAILABLE {
                        crate::adapters::CODE_UNAVAILABLE
                    } else {
                        crate::state::successor_code::SOURCE_LIVE
                    };
                    return finish_mutation(
                        shared,
                        request,
                        &key,
                        "lane.start",
                        false,
                        null(),
                        Some((
                            code,
                            format!(
                                "the source-absence recheck could not read the source session \
                                 {:?} ({}: {}); nothing was spawned",
                                source_target.session, err.code, err.message
                            ),
                        )),
                    );
                }
            }
            // ONE generation/nonce owns startup: commit the owner boundary
            // BEFORE any spawn (a simultaneous/replayed start loses the
            // UNIQUE fence). An existing undelivered boundary is a bounded
            // same-nonce retry; an existing delivered one re-verifies only.
            let successor = match plan.existing.clone() {
                Some(existing) if existing.delivery == "delivered" => existing,
                Some(_) => {
                    let noted = {
                        let state = match shared.lock_state() {
                            Ok(state) => state,
                            Err(message) => {
                                return err_response(&request.id, "state.unavailable", message);
                            }
                        };
                        state
                            .note_lane_successor_attempt(
                                &plan.record.replacement_id,
                                &plan.nonce,
                                &time::rfc3339_now(),
                            )
                            .map_err(|err| (err.code, err.message))
                    };
                    match noted {
                        Ok(row) => row,
                        Err((code, message)) => {
                            return finish_mutation(
                                shared,
                                request,
                                &key,
                                "lane.start",
                                false,
                                null(),
                                Some((code, message)),
                            );
                        }
                    }
                }
                None => {
                    let committed = {
                        let state = match shared.lock_state() {
                            Ok(state) => state,
                            Err(message) => {
                                return err_response(&request.id, "state.unavailable", message);
                            }
                        };
                        state
                            .commit_lane_successor_start(
                                &plan.record.replacement_id,
                                plan.record.generation,
                                &plan.checkpoint.digest,
                                &plan.nonce,
                                &plan.session,
                                &plan.kickoff_receipt,
                                &profile.key,
                                profile.kind.name(),
                                &time::rfc3339_now(),
                            )
                            .map_err(|err| (err.code, err.message))
                    };
                    match committed {
                        Ok((successor, _record)) => successor,
                        Err((code, message)) => {
                            return finish_mutation(
                                shared,
                                request,
                                &key,
                                "lane.start",
                                false,
                                null(),
                                Some((code, message)),
                            );
                        }
                    }
                }
            };
            crash_point("lane-start.after-boundary");
            let successor_target = crate::adapters::SuccessorTarget {
                session: successor.session.clone(),
                role: successor.role.clone(),
                profile_key: successor.profile_key.clone(),
                profile_kind: successor.profile_kind.clone(),
                worktree: successor.worktree.clone(),
                kickoff_receipt: successor.kickoff_receipt.clone(),
                source_process: plan.record.source_process.clone(),
                binding: target_binding.clone(),
            };
            let mut spawn_evidence = null();
            if successor.delivery == "none" {
                let spawn = crate::adapters::successor_start(
                    &profile,
                    &successor_target,
                    &env,
                    crate::adapters::ADAPTER_TIMEOUT,
                );
                crash_point("lane-start.after-spawn");
                if spawn.status != "succeeded" {
                    let detail = spawn
                        .message
                        .clone()
                        .or_else(|| spawn.detail.clone())
                        .unwrap_or_else(|| "no diagnostic".to_string());
                    if spawn.code == Some(crate::adapters::CODE_UNAVAILABLE) {
                        // The start row never ran: nothing was delivered.
                        // The boundary stays undelivered for a bounded
                        // same-nonce retry.
                        return finish_mutation(
                            shared,
                            request,
                            &key,
                            "lane.start",
                            false,
                            null(),
                            Some((
                                crate::adapters::CODE_UNAVAILABLE,
                                format!(
                                    "the fresh successor start of session {:?} never ran \
                                     ({}); nothing was spawned and the boundary stays \
                                     undelivered for a bounded same-nonce retry",
                                    successor_target.session, detail
                                ),
                            )),
                        );
                    }
                    return park_successor(
                        shared,
                        request,
                        &key,
                        params,
                        &format!(
                            "the spawn of session {:?} did not confirm ({}); the delivery is \
                             unknown and NO further spawn is attempted",
                            successor_target.session, detail
                        ),
                        crate::state::successor_code::HELD,
                        format!(
                            "the successor start of session {:?} could not be confirmed \
                             ({}); the record holds and external reconciliation is required",
                            successor_target.session, detail
                        ),
                    );
                }
                spawn_evidence = object(vec![
                    ("status", string(spawn.status)),
                    ("bounded", bool_(true)),
                    (
                        "elapsed_ms",
                        integer(spawn.elapsed_ms.min(i64::MAX as u64) as i64),
                    ),
                ]);
                let marked = {
                    let state = match shared.lock_state() {
                        Ok(state) => state,
                        Err(message) => {
                            return err_response(&request.id, "state.unavailable", message);
                        }
                    };
                    state
                        .mark_lane_successor_delivered(
                            &plan.record.replacement_id,
                            &plan.nonce,
                            &time::rfc3339_now(),
                        )
                        .map_err(|err| (err.code, err.message))
                };
                match marked {
                    Ok(_) => {}
                    Err((code, message)) => {
                        return finish_mutation(
                            shared,
                            request,
                            &key,
                            "lane.start",
                            false,
                            null(),
                            Some((code, message)),
                        );
                    }
                }
            }
            // Adapter-observed verification: a spawned process alone is not
            // ADOPTED.
            let evidence = crate::adapters::successor_evidence(
                &profile,
                &successor_target,
                &env,
                crate::adapters::ADAPTER_TIMEOUT,
            );
            match evidence {
                Ok(crate::adapters::SuccessorEvidence::Verified {
                    process,
                    readiness,
                    binding,
                }) => {
                    let binding_doc = binding.to_doc(target_binding.as_ref());
                    let reason = format!(
                        "successor verified after one bounded spawn: fresh session {:?} \
                         process {} role {:?} profile {}/{} cwd {:?} kickoff receipt echoed, \
                         adapter-observed {readiness}, binding {} (nonce {})",
                        successor_target.session,
                        process,
                        successor_target.role,
                        successor_target.profile_key,
                        successor_target.profile_kind,
                        successor_target.worktree,
                        binding.status(),
                        plan.nonce
                    );
                    let committed = {
                        let state = match shared.lock_state() {
                            Ok(state) => state,
                            Err(message) => {
                                return err_response(&request.id, "state.unavailable", message);
                            }
                        };
                        state
                            .commit_lane_successor_verified(
                                &plan.record.replacement_id,
                                &plan.nonce,
                                &process,
                                &readiness,
                                &binding_doc,
                                &reason,
                                &time::rfc3339_now(),
                            )
                            .map_err(|err| (err.code, err.message))
                    };
                    let (successor_row, record) = match committed {
                        Ok(pair) => pair,
                        Err((code, message)) => {
                            return finish_mutation(
                                shared,
                                request,
                                &key,
                                "lane.start",
                                false,
                                null(),
                                Some((code, message)),
                            );
                        }
                    };
                    let start = object(vec![
                        (
                            "successor",
                            crate::state::lane_successor_val(&successor_row),
                        ),
                        ("replacement", crate::state::lane_replacement_val(&record)),
                        (
                            "verification",
                            object(vec![
                                ("session", string(&successor_target.session)),
                                ("process", string(&process)),
                                ("readiness", string(&readiness)),
                                ("same_worktree", string(&successor_target.worktree)),
                                ("binding", binding_doc.clone()),
                                ("observed_at", string(&time::rfc3339_now())),
                            ]),
                        ),
                        ("spawn", spawn_evidence),
                    ]);
                    finish_mutation(
                        shared,
                        request,
                        &key,
                        "lane.start",
                        true,
                        object(vec![("start", start)]),
                        None,
                    )
                }
                Ok(crate::adapters::SuccessorEvidence::Held { detail }) => finish_mutation(
                    shared,
                    request,
                    &key,
                    "lane.start",
                    false,
                    null(),
                    Some((
                        crate::state::successor_code::HELD,
                        format!(
                            "the successor of session {:?} is not yet verified ({}); the \
                                 boundary holds and a bounded same-nonce retry can re-verify \
                                 (nothing further is spawned blind)",
                            successor_target.session, detail
                        ),
                    )),
                ),
                Ok(crate::adapters::SuccessorEvidence::Reused { detail }) => park_successor(
                    shared,
                    request,
                    &key,
                    params,
                    &format!(
                        "the successor verification observed a reused or wrong identity \
                         ({}); no further spawn is attempted",
                        detail
                    ),
                    crate::state::successor_code::REUSED,
                    format!(
                        "the successor start of session {:?} fails closed: the adapter \
                         evidence contradicts the bound identity ({}); external \
                         reconciliation is required",
                        successor_target.session, detail
                    ),
                ),
                Err(err) => finish_mutation(
                    shared,
                    request,
                    &key,
                    "lane.start",
                    false,
                    null(),
                    Some((
                        crate::state::successor_code::HELD,
                        format!(
                            "the successor verification read-back failed ({}: {}); the \
                             boundary holds and nothing further is spawned",
                            err.code, err.message
                        ),
                    )),
                ),
            }
        }
        Intent::Replay { response } => replay(shared, &response),
        Intent::Refused { code, message } => err_response(&request.id, code, message),
    }
}

/// `lane.adopt`: verify and record ADOPTION of the committed successor
/// (issue #76). The adoption re-queries the lane and compares the fresh
/// result against the recorded handoff state before the `adopting` →
/// `adopted` transition can commit:
///
/// - the committed successor is re-verified through the adapter read-back
///   (a successor that is no longer observable holds; a reused identity
///   fails closed) and the source absence is rechecked (both live/ambiguous
///   blocks advancement);
/// - worktree heads, dirty/untracked inventory, reports, gates and live
///   children must match the recorded snapshot. ANY difference is the
///   RECONCILIATION verdict: the record is parked for external
///   reconciliation — never a blind replay, never a stale PASS reuse;
/// - the transition, the adoption evidence and (for orchestrator
///   replacements) the preserved worker/reviewer orchestration block commit
///   in ONE transaction. PAUSED (`held`) between transitions prevents the
///   activation: a booted successor stays fenced.
fn method_lane_adopt(shared: &Arc<Shared>, request: &Request) -> String {
    let Some(params) = request.params.as_ref() else {
        return err_response(
            &request.id,
            "refusal.malformed",
            "lane.adopt requires params: replacement_id, binding, observation, reobservation, \
             harness",
        );
    };
    let replacement_id = match required_str(Some(params), "replacement_id") {
        Some(text) if crate::formats::is_replacement_id(text) => text.to_string(),
        _ => {
            return err_response(
                &request.id,
                "refusal.malformed",
                "lane.adopt requires params.replacement_id (rp_ id)",
            );
        }
    };
    if !matches!(params.get("binding"), Some(Val::Obj(_))) {
        return err_response(
            &request.id,
            crate::state::successor_code::BINDING,
            "lane.adopt requires params.binding (object: generation, successor_id, session)",
        );
    }
    for key in ["observation", "reobservation"] {
        if !matches!(params.get(key), Some(Val::Obj(_))) {
            return err_response(
                &request.id,
                crate::state::successor_code::BINDING,
                format!("lane.adopt requires params.{key} (the fresh re-query of the lane)"),
            );
        }
    }
    let harness = match params.get("harness") {
        Some(harness @ Val::Obj(_)) => harness,
        _ => {
            return err_response(
                &request.id,
                "refusal.malformed",
                "lane.adopt requires params.harness (object: key, kind[, executable, \
                 capabilities])",
            );
        }
    };
    let profile = match retirement_profile(harness) {
        Ok(profile) => profile,
        Err((code, message)) => return err_response(&request.id, code, message),
    };
    if !profile.supports(crate::adapters::Op::Observe.capability()) {
        return err_response(
            &request.id,
            crate::adapters::CODE_UNKNOWN_CAPABILITY,
            format!(
                "harness profile {:?} does not declare the {:?} capability that the adoption \
                 path requires; unsupported adapters are refused",
                profile.key,
                crate::adapters::Op::Observe.capability()
            ),
        );
    }
    let target = format!("lane-adopt:{replacement_id}");
    match journal_mutation(shared, request, "mutate.lane.adopt", &target) {
        Intent::Claimed { key } => {
            crash_point("lane-adopt.after-intent");
            let bound = {
                let state = match shared.lock_state() {
                    Ok(state) => state,
                    Err(message) => {
                        return err_response(&request.id, "state.unavailable", message);
                    }
                };
                state
                    .begin_lane_adoption(params)
                    .map_err(|err| (err.code, err.message))
            };
            let plan = match bound {
                Ok(plan) => plan,
                Err((code, message)) => {
                    return finish_mutation(
                        shared,
                        request,
                        &key,
                        "lane.adopt",
                        false,
                        null(),
                        Some((code, message)),
                    );
                }
            };
            let env = crate::config::adapter_environment();
            // The durable planned target-profile binding (issue #77): the
            // adoption re-verification classifies the read-back against the
            // SAME reviewed plan the start was fenced on.
            let target_binding = {
                let state = match shared.lock_state() {
                    Ok(state) => state,
                    Err(message) => {
                        return err_response(&request.id, "state.unavailable", message);
                    }
                };
                match stored_profile(&state, &plan.record.replacement_id) {
                    Ok(binding) => binding,
                    Err((code, message)) => {
                        drop(state);
                        return finish_mutation(
                            shared,
                            request,
                            &key,
                            "lane.adopt",
                            false,
                            null(),
                            Some((code, message)),
                        );
                    }
                }
            };
            let successor_target = crate::adapters::SuccessorTarget {
                session: plan.successor.session.clone(),
                role: plan.successor.role.clone(),
                profile_key: plan.successor.profile_key.clone(),
                profile_kind: plan.successor.profile_kind.clone(),
                worktree: plan.successor.worktree.clone(),
                kickoff_receipt: plan.successor.kickoff_receipt.clone(),
                source_process: plan.record.source_process.clone(),
                binding: target_binding.clone(),
            };
            // The committed successor must still verify: a booted successor
            // that stopped answering holds; a reused identity fails closed.
            let observed_binding = match crate::adapters::successor_evidence(
                &profile,
                &successor_target,
                &env,
                crate::adapters::ADAPTER_TIMEOUT,
            ) {
                Ok(crate::adapters::SuccessorEvidence::Verified { binding, .. }) => binding,
                Ok(crate::adapters::SuccessorEvidence::Held { detail }) => {
                    return finish_mutation(
                        shared,
                        request,
                        &key,
                        "lane.adopt",
                        false,
                        null(),
                        Some((
                            crate::state::successor_code::HELD,
                            format!(
                                "the committed successor of session {:?} is not verifiable \
                                 now ({}); the adoption holds and the successor stays fenced",
                                successor_target.session, detail
                            ),
                        )),
                    );
                }
                Ok(crate::adapters::SuccessorEvidence::Reused { detail }) => {
                    return park_successor(
                        shared,
                        request,
                        &key,
                        params,
                        &format!(
                            "the adoption re-verification observed a reused or wrong identity \
                             ({}); no effect is attempted against it",
                            detail
                        ),
                        crate::state::successor_code::REUSED,
                        format!(
                            "the adoption of session {:?} fails closed: the adapter evidence \
                             contradicts the committed successor identity ({}); external \
                             reconciliation is required",
                            successor_target.session, detail
                        ),
                    );
                }
                Err(err) => {
                    return finish_mutation(
                        shared,
                        request,
                        &key,
                        "lane.adopt",
                        false,
                        null(),
                        Some((
                            crate::state::successor_code::HELD,
                            format!(
                                "the adoption re-verification read-back failed ({}: {}); the \
                                 adoption holds",
                                err.code, err.message
                            ),
                        )),
                    );
                }
            };
            // Source absence is rechecked: source and successor both
            // live/ambiguous blocks advancement.
            let source_target = crate::adapters::RetirementTarget {
                session: plan.record.source_session.clone(),
                process: plan.record.source_process.clone(),
            };
            match crate::adapters::retirement_evidence(
                &profile,
                &source_target,
                plan.record.generation,
                &env,
                crate::adapters::ADAPTER_TIMEOUT,
            ) {
                Ok(crate::adapters::RetirementEvidence::Retired) => {}
                Ok(crate::adapters::RetirementEvidence::Held { detail }) => {
                    return finish_mutation(
                        shared,
                        request,
                        &key,
                        "lane.adopt",
                        false,
                        null(),
                        Some((
                            crate::state::successor_code::SOURCE_LIVE,
                            format!(
                                "the bound source session {:?} is still present or its \
                                 absence cannot be proven ({}); source and successor must \
                                 never both be live — the adoption is blocked",
                                source_target.session, detail
                            ),
                        )),
                    );
                }
                Ok(crate::adapters::RetirementEvidence::Reused { detail }) => {
                    return finish_mutation(
                        shared,
                        request,
                        &key,
                        "lane.adopt",
                        false,
                        null(),
                        Some((
                            crate::state::retirement_code::REUSED,
                            format!(
                                "the adoption source recheck observed a reused identity for \
                                 session {:?} ({}); the adoption is blocked",
                                source_target.session, detail
                            ),
                        )),
                    );
                }
                Err(err) => {
                    let code = if err.code == crate::adapters::CODE_UNAVAILABLE {
                        crate::adapters::CODE_UNAVAILABLE
                    } else {
                        crate::state::successor_code::SOURCE_LIVE
                    };
                    return finish_mutation(
                        shared,
                        request,
                        &key,
                        "lane.adopt",
                        false,
                        null(),
                        Some((
                            code,
                            format!(
                                "the adoption source recheck could not read session {:?} \
                                 ({}: {}); the adoption is blocked",
                                source_target.session, err.code, err.message
                            ),
                        )),
                    );
                }
            }
            // The fresh re-query is compared against the recorded handoff
            // state: ANY difference is the reconciliation verdict.
            if !plan.differences.is_empty() {
                return park_successor(
                    shared,
                    request,
                    &key,
                    params,
                    &format!(
                        "the adoption re-query differs from the recorded handoff state in \
                         {}; reconciliation is required (a blind replay or a stale PASS is \
                         never adopted)",
                        plan.differences.join(", ")
                    ),
                    crate::state::successor_code::DIFFERS,
                    format!(
                        "the adoption of session {:?} found {} different from the recorded \
                         handoff state ({}); external reconciliation is required",
                        successor_target.session,
                        plan.differences.join(", "),
                        plan.differences.join(", ")
                    ),
                );
            }
            let reason = format!(
                "adopted successor {} (session {:?}, process {}) on the SAME worktree {:?}; \
                 the fresh re-query matched the recorded handoff state and the source \
                 absence was rechecked",
                plan.successor.successor_id,
                successor_target.session,
                plan.successor.process,
                plan.successor.worktree
            );
            let binding_doc = observed_binding.to_doc(target_binding.as_ref());
            let committed = {
                let state = match shared.lock_state() {
                    Ok(state) => state,
                    Err(message) => {
                        return err_response(&request.id, "state.unavailable", message);
                    }
                };
                state
                    .commit_lane_adoption(
                        &plan.record.replacement_id,
                        plan.record.generation,
                        &plan.successor.successor_id,
                        &plan.successor.session,
                        &plan.observation,
                        &plan.differences,
                        &binding_doc,
                        &reason,
                        &time::rfc3339_now(),
                    )
                    .map_err(|err| (err.code, err.message))
            };
            let (successor_row, record) = match committed {
                Ok(pair) => pair,
                Err((code, message)) => {
                    return finish_mutation(
                        shared,
                        request,
                        &key,
                        "lane.adopt",
                        false,
                        null(),
                        Some((code, message)),
                    );
                }
            };
            let adoption = object(vec![
                (
                    "successor",
                    crate::state::lane_successor_val(&successor_row),
                ),
                ("replacement", crate::state::lane_replacement_val(&record)),
                (
                    "adoption",
                    object(vec![
                        ("session", string(&successor_target.session)),
                        ("successor_id", string(&plan.successor.successor_id)),
                        ("worktree", string(&successor_target.worktree)),
                        ("observation_digest", string(&successor_row.adoption_digest)),
                        ("binding", binding_doc.clone()),
                        (
                            "differences",
                            Val::Arr(plan.differences.iter().map(|field| string(field)).collect()),
                        ),
                        ("observed_at", string(&time::rfc3339_now())),
                    ]),
                ),
            ]);
            finish_mutation(
                shared,
                request,
                &key,
                "lane.adopt",
                true,
                object(vec![("adoption", adoption)]),
                None,
            )
        }
        Intent::Replay { response } => replay(shared, &response),
        Intent::Refused { code, message } => err_response(&request.id, code, message),
    }
}

/// `lane.successor.consume`: consume recorded worker completions EXACTLY
/// ONCE after adoption (issue #76 AC6). Every event must be a recorded
/// pending completion of the replacement's orchestrator checkpoint and every
/// worker a referenced worker lane; the consumption is recorded durably on
/// the successor row atomically, so a restart replays the identical consumed
/// set. A replayed request returns the recorded response and a second
/// consumption of the same event refuses — a duplicate reviewer dispatch can
/// never be produced. This path records; it never dispatches, spawns, or
/// signals anything.
fn method_lane_successor_consume(shared: &Arc<Shared>, request: &Request) -> String {
    let Some(params) = request.params.as_ref() else {
        return err_response(
            &request.id,
            "refusal.malformed",
            "lane.successor.consume requires params: replacement_id, successor_id, \
             completions",
        );
    };
    let replacement_id = match required_str(Some(params), "replacement_id") {
        Some(text) if crate::formats::is_replacement_id(text) => text.to_string(),
        _ => {
            return err_response(
                &request.id,
                "refusal.malformed",
                "lane.successor.consume requires params.replacement_id (rp_ id)",
            );
        }
    };
    let successor_id = match required_str(Some(params), "successor_id") {
        Some(text) if crate::formats::is_successor_id(text) => text.to_string(),
        _ => {
            return err_response(
                &request.id,
                "refusal.malformed",
                "lane.successor.consume requires params.successor_id (su_ id)",
            );
        }
    };
    let completions = match params.get("completions") {
        Some(Val::Arr(items)) => {
            let mut pairs: Vec<(String, String)> = Vec::with_capacity(items.len());
            for (index, item) in items.iter().enumerate() {
                let event = item.get("event").and_then(Val::as_str);
                let worker = item.get("worker").and_then(Val::as_str);
                match (event, worker) {
                    (Some(event), Some(worker)) => {
                        pairs.push((event.to_string(), worker.to_string()));
                    }
                    _ => {
                        return err_response(
                            &request.id,
                            crate::state::successor_code::EVENT,
                            format!("completions[{index}] must be an object: {{event, worker}}"),
                        );
                    }
                }
            }
            pairs
        }
        _ => {
            return err_response(
                &request.id,
                crate::state::successor_code::EVENT,
                "lane.successor.consume requires params.completions (array of {event, \
                 worker})",
            );
        }
    };
    let target = format!("lane-successor:{replacement_id}");
    match journal_mutation(shared, request, "mutate.lane.successor.consume", &target) {
        Intent::Claimed { key } => {
            crash_point("lane-successor.after-intent");
            let consumed = {
                let state = match shared.lock_state() {
                    Ok(state) => state,
                    Err(message) => {
                        return err_response(&request.id, "state.unavailable", message);
                    }
                };
                state
                    .consume_lane_successor_completions(
                        &replacement_id,
                        &successor_id,
                        &completions,
                        &time::rfc3339_now(),
                    )
                    .map_err(|err| (err.code, err.message))
            };
            match consumed {
                Ok((successor_row, consumed_events)) => {
                    let record = {
                        let state = match shared.lock_state() {
                            Ok(state) => state,
                            Err(message) => {
                                return err_response(&request.id, "state.unavailable", message);
                            }
                        };
                        state.lane_replacement_by_id(&replacement_id)
                    };
                    let record = match record {
                        Ok(Some(record)) => crate::state::lane_replacement_val(&record),
                        _ => null(),
                    };
                    finish_mutation(
                        shared,
                        request,
                        &key,
                        "lane.successor.consume",
                        true,
                        object(vec![
                            (
                                "successor",
                                crate::state::lane_successor_val(&successor_row),
                            ),
                            ("replacement", record),
                            (
                                "consumed",
                                Val::Arr(
                                    consumed_events.iter().map(|event| string(event)).collect(),
                                ),
                            ),
                        ]),
                        None,
                    )
                }
                Err((code, message)) => finish_mutation(
                    shared,
                    request,
                    &key,
                    "lane.successor.consume",
                    false,
                    null(),
                    Some((code, message)),
                ),
            }
        }
        Intent::Replay { response } => replay(shared, &response),
        Intent::Refused { code, message } => err_response(&request.id, code, message),
    }
}

/// Park a successor record `ambiguous` after a start/adoption whose
/// delivery or evidence is in doubt, then answer the typed refusal. The
/// park is the explicit "external reconciliation required" outcome; no
/// further spawn is ever attempted (never against a reused identity).
fn park_successor(
    shared: &Arc<Shared>,
    request: &Request,
    key: &str,
    params: &Val,
    park_reason: &str,
    code: &'static str,
    message: String,
) -> String {
    match shared.lock_state() {
        Ok(state) => {
            if let Err(err) =
                state.mark_replacement_ambiguous(params, park_reason, &time::rfc3339_now())
            {
                shared.log.write(
                    "error",
                    "lane.successor.park_failed",
                    &format!("{}: {}", err.code, err.message),
                );
                return err_response(&request.id, err.code, err.message);
            }
        }
        Err(lock_message) => {
            return err_response(&request.id, "state.unavailable", lock_message);
        }
    }
    finish_mutation(
        shared,
        request,
        key,
        "lane.start",
        false,
        null(),
        Some((code, message)),
    )
}

/// The existing fan-out admission gate for one successor start (issue #9
/// AC1, reused verbatim through `check_fanout_admission`). A missing or
/// stale host-resource proof, a missing cap axis, an exhausted cap or a
/// monorepo overlap is a typed hold: NOTHING is committed, NOTHING is
/// spawned, admission is never disabled, and the bounded retry is an
/// explicit new request.
fn successor_admission(
    params: &Val,
    harness_key: &str,
    worktree: &str,
) -> Result<(), (&'static str, String)> {
    use crate::lifecycle::{ConcurrencyCaps, HostProof, LaneFootprint};
    let admission = match params.get("admission") {
        Some(Val::Obj(map)) => map,
        None => {
            return Err((
                crate::lifecycle::code::PROOF_MISSING,
                "lane.start requires params.admission with caps and a fresh host-resource \
                 proof (unknown measurements refuse new work); nothing was spawned and a \
                 bounded retry needs a fresh request"
                    .to_string(),
            ));
        }
        Some(_) => {
            return Err((
                "refusal.malformed",
                "lane.start params.admission must be an object".to_string(),
            ));
        }
    };
    let caps = match admission.get("caps") {
        Some(Val::Obj(map)) => map,
        _ => {
            return Err((
                crate::lifecycle::code::CAP_MISSING,
                "lane.start admission requires caps {global, repository, harness}".to_string(),
            ));
        }
    };
    let cap = |key: &str| -> Option<usize> {
        caps.get(key)
            .and_then(Val::as_int)
            .and_then(|value| usize::try_from(value).ok())
    };
    let (Some(global), Some(per_repository_cap), Some(harness)) =
        (cap("global"), cap("repository"), cap("harness"))
    else {
        return Err((
            crate::lifecycle::code::CAP_MISSING,
            "lane.start admission requires caps {global, repository, harness}".to_string(),
        ));
    };
    let host_proof = admission
        .get("host_proof")
        .and_then(|proof| proof.get("measured_at"))
        .and_then(Val::as_str)
        .and_then(crate::time::unix_from_rfc3339);
    // Issue #231: the free-byte observation the lane's start attestation
    // carries, when its caller measured one (the gate refuses below the
    // documented floor).
    let available_bytes = admission
        .get("host_proof")
        .and_then(|proof| proof.get("available_bytes"))
        .and_then(Val::as_int)
        .and_then(|bytes| u64::try_from(bytes).ok());
    let Some(measured_at_unix) = host_proof else {
        return Err((
            crate::lifecycle::code::PROOF_MISSING,
            "lane.start admission requires a fresh host-resource proof \
             (host_proof.measured_at)"
                .to_string(),
        ));
    };
    let repository = match admission.get("repository").and_then(Val::as_str) {
        Some(repository) if !repository.is_empty() => repository.to_string(),
        _ => {
            return Err((
                crate::lifecycle::code::CAP_MISSING,
                "lane.start admission requires the repository identity axis".to_string(),
            ));
        }
    };
    let mut running: Vec<LaneFootprint> = Vec::new();
    if let Some(items) = admission.get("running").and_then(Val::as_array) {
        for lane in items {
            let (Some(lane_repository), Some(scope)) = (
                lane.get("repository").and_then(Val::as_str),
                lane.get("scope").and_then(Val::as_str),
            ) else {
                return Err((
                    "refusal.malformed",
                    "admission.running entries must be objects: {repository, harness_key, \
                     scope}"
                        .to_string(),
                ));
            };
            running.push(LaneFootprint {
                repository: lane_repository.to_string(),
                harness_key: lane
                    .get("harness_key")
                    .and_then(Val::as_str)
                    .unwrap_or("")
                    .to_string(),
                scope: scope.to_string(),
                // The caller-attested lanes record repository, harness key and
                // declared scope (and nothing else): a cap refusal names what
                // it actually has — the declared worktree (#236).
                issue_number: 0,
                identity: String::new(),
            });
        }
    }
    let caps = ConcurrencyCaps {
        global,
        per_repository: per_repository_cap,
        per_harness: harness,
    };
    let proposed = LaneFootprint {
        repository,
        harness_key: harness_key.to_string(),
        scope: worktree.to_string(),
        issue_number: 0,
        identity: String::new(),
    };
    crate::lifecycle::check_fanout_admission(
        &proposed,
        &running,
        &caps,
        Some(match available_bytes {
            Some(available_bytes) => HostProof::measured(measured_at_unix, available_bytes),
            None => HostProof::at(measured_at_unix),
        }),
        time::unix_now(),
    )
    .map_err(|err| {
        (
            err.code,
            format!(
                "{}; nothing was spawned and the record is untouched (a bounded explicit \
                 retry stays legal)",
                err.message
            ),
        )
    })
}

fn method_journal_tail(shared: &Arc<Shared>, request: &Request) -> String {
    let params = request.params.as_ref();
    let after_seq = params
        .and_then(|params| params.get("after_seq"))
        .and_then(as_non_negative)
        .unwrap_or(-1);
    let limit = params
        .and_then(|params| params.get("limit"))
        .and_then(as_positive)
        .unwrap_or(100)
        .min(JOURNAL_TAIL_LIMIT);
    match shared.lock_state() {
        Ok(state) => match state.journal_tail(after_seq, limit) {
            Ok((first_retained, lines)) => {
                let records: Vec<Val> = lines
                    .iter()
                    .filter_map(|line| Val::parse_json(line).ok())
                    .collect();
                ok_response(
                    &request.id,
                    object(vec![
                        ("first_retained_seq", integer(first_retained)),
                        ("records", Val::Arr(records)),
                    ]),
                )
            }
            Err(err) => err_response(&request.id, err.code, err.message),
        },
        Err(message) => err_response(&request.id, "state.unavailable", message),
    }
}

fn as_non_negative(value: &Val) -> Option<i64> {
    match value {
        Val::Int(int) if *int >= 0 => Some(*int),
        _ => None,
    }
}

fn as_positive(value: &Val) -> Option<i64> {
    match value {
        Val::Int(int) if *int > 0 => Some(*int),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Mutation methods (journaled intent -> effect -> typed outcome; AC4/AC6)
// ---------------------------------------------------------------------------

/// The result of a journaled-intent attempt.
enum Intent {
    /// Claimed; the caller runs the effect with this key.
    Claimed { key: String },
    /// Same request already resolved: replay the recorded response.
    Replay { response: String },
    /// The key belongs to a different request: refuse.
    Refused { code: &'static str, message: String },
}

fn journal_mutation(shared: &Arc<Shared>, request: &Request, action: &str, target: &str) -> Intent {
    let state = match shared.lock_state() {
        Ok(state) => state,
        Err(message) => {
            return Intent::Refused {
                code: "state.unavailable",
                message,
            };
        }
    };
    let intent = journal_mutation_on(&state, request, action, target);
    drop(state);
    if matches!(intent, Intent::Claimed { .. }) {
        // Publish the intent event only after the state guard is dropped
        // (hub locking rule: never publish while holding the state mutex).
        publish_after_state_change(shared, None);
    }
    intent
}

/// Journal an intent on an ALREADY-LOCKED state handle. No locking and no
/// publishing: the restore path holds the state mutex across the whole
/// rename/reopen/swap sequence (review-5-daemon-r2 blocker) and publishes
/// once after dropping the guard.
fn journal_mutation_on(state: &State, request: &Request, action: &str, target: &str) -> Intent {
    let key = match request
        .params
        .as_ref()
        .and_then(|params| params.get("idempotency_key"))
        .and_then(Val::as_str)
    {
        Some(key) if crate::formats::is_idempotency_key(key) => key.to_string(),
        _ => {
            return Intent::Refused {
                code: "refusal.malformed",
                message: "mutating methods require params.idempotency_key (ik_ format)".into(),
            };
        }
    };
    match state.journal_intent(
        action,
        target,
        &key,
        &request.id,
        &request.method,
        None,
        None,
        &request.line,
    ) {
        Ok((ClaimAttempt::Claimed, _)) => Intent::Claimed { key },
        Ok((ClaimAttempt::Replay { response }, _)) => Intent::Replay { response },
        Ok((ClaimAttempt::Reused { owner_request_id }, _)) => Intent::Refused {
            code: "refusal.idempotency",
            message: format!(
                "idempotency key {key:?} already belongs to request {owner_request_id}"
            ),
        },
        Err(err) => Intent::Refused {
            code: err.code,
            message: err.message,
        },
    }
}

/// Publish journal events appended by one state change (called after the
/// state guard is dropped; see the hub locking rule). A committed mutation is
/// also a SEMANTIC wake for the supervision driver (issue #95): the driver
/// folds it from the durable event stream into the ONE pending trigger of
/// each affected run, so this only has to say "look now" — it never blocks
/// and it never touches the state guard.
fn publish_after_state_change(shared: &Arc<Shared>, audit: Option<AuditRow>) {
    let seq = audit.map(|audit| audit.event_seq);
    publish_events(shared);
    shared.wake_supervisor();
    let _ = seq; // the event seq is carried by the row itself
}

/// `grants.issue` (issue #92): the supported production mint path for route
/// grants — the caller that turns a reviewed binding into a `hf-grant/v1`
/// row. Until this method existed, `State::issue_grant` had test-only
/// callers, so no supported surface could produce a grant id for
/// `queue submit --grant` / `board --grant`.
///
/// The presented `params.grant` document is the exact `hf-grant/v1` binding
/// (repository, issue number + acceptance revision, workflow/policy hashes,
/// phase, scope, caps, expiry, state epoch): the daemon validates it BEFORE
/// any journaling (a refused document never leaves a claim behind), refuses
/// a document that is already expired at mint time and any production-class
/// binding, then journals `mutate.grant.issue` and inserts exactly ONE row
/// inside the claim window. Everything else is the shared mutation contract:
/// the key is spent per attempt (replay of the same request id + key returns
/// the recorded response), and an interrupt between intent and outcome
/// leaves no partial grant — the row is either absent (reconcile reports
/// `never committed`) or fully committed (reconcile re-reads it).
fn method_grants_issue(shared: &Arc<Shared>, request: &Request) -> String {
    let Some(grant) = request
        .params
        .as_ref()
        .and_then(|params| params.get("grant"))
    else {
        return err_response(
            &request.id,
            "refusal.malformed",
            "grants.issue requires params.grant (one hf-grant/v1 document)",
        );
    };
    if !matches!(grant, Val::Obj(_)) {
        return err_response(
            &request.id,
            "refusal.malformed",
            "grants.issue params.grant must be an hf-grant/v1 object",
        );
    }
    // Fail closed BEFORE the claim: the document must be a valid binding of
    // this family (the state layer re-validates as the inner fence).
    let verdict = validate_doc(Family::Grant, grant);
    if !verdict.is_accepted() {
        let code = verdict
            .refusal()
            .map(refusal_code)
            .unwrap_or("refusal.malformed");
        return err_response(&request.id, code, verdict.message());
    }
    let grant_id = grant
        .get("grant_id")
        .and_then(Val::as_str)
        .unwrap_or_default()
        .to_string();
    if !crate::formats::is_grant_id(&grant_id) {
        return err_response(
            &request.id,
            "refusal.malformed",
            "grants.issue requires params.grant.grant_id (gr_ + 16 lowercase hex)",
        );
    }
    // Production-class authority is never minted over the socket surface:
    // the operator path holds production boundaries, so a production-class
    // grant would be a capability nothing can authorize. This refuses
    // before the claim, with the same typed code the apply gate uses.
    let phase = grant.get("phase").and_then(Val::as_str).unwrap_or_default();
    let production_caps = grant
        .get("caps")
        .and_then(Val::as_array)
        .map(|caps| {
            caps.iter()
                .any(|cap| matches!(cap.as_str(), Some("production") | Some("release")))
        })
        .unwrap_or(false);
    if phase == "production" || production_caps {
        return err_response(
            &request.id,
            crate::mutation::code::PRODUCTION_CONFIRMATION,
            "a production-class grant is never minted from this surface (production authority \
             requires a fresh interactive TTY-confirmed digest, and grants.issue carries no \
             confirmation channel)",
        );
    }
    // An already-dead grant is never minted: the mint path refuses what the
    // consumers would refuse on their first read (refusal.grant.expired).
    let expires_at = grant
        .get("expires_at")
        .and_then(Val::as_str)
        .unwrap_or_default();
    let now = time::rfc3339_now();
    if crate::mutation::is_expired(expires_at, &now) {
        return err_response(
            &request.id,
            crate::mutation::code::GRANT_EXPIRED,
            format!(
                "grant {grant_id} expires at {expires_at}, which is not in the future; an expired grant is never minted"
            ),
        );
    }
    match journal_mutation(shared, request, "mutate.grant.issue", &grant_id) {
        Intent::Claimed { key } => {
            crash_point("grants.issue.after-intent");
            let guard = match shared.lock_state() {
                Ok(guard) => guard,
                Err(message) => {
                    return err_response(&request.id, "state.unavailable", message);
                }
            };
            let response = match guard.issue_grant(grant) {
                Ok(row) => {
                    // The row is committed from here on; an interrupt before
                    // the outcome resolves is the "committed, unresolved"
                    // window (restart reconciliation re-reads the row).
                    crash_point("grants.issue.after-commit");
                    resolve_mutation_on(
                        &guard,
                        &shared.log,
                        request,
                        &key,
                        "grants.issue",
                        true,
                        minted_grant_doc(&row),
                        None,
                    )
                }
                Err(err) => resolve_mutation_on(
                    &guard,
                    &shared.log,
                    request,
                    &key,
                    "grants.issue",
                    false,
                    null(),
                    Some((err.code, err.message)),
                ),
            };
            drop(guard);
            publish_after_state_change(shared, None);
            response
        }
        Intent::Replay { response } => replay(shared, &response),
        Intent::Refused { code, message } => err_response(&request.id, code, message),
    }
}

/// Render one minted grant row as the `hf-grant/v1` document that was
/// minted: the contract shape (caps is the JSON array the family validator
/// requires), never the `grants.list` projection.
fn minted_grant_doc(row: &crate::state::GrantRow) -> Val {
    let caps = Val::parse_json(&row.caps).unwrap_or(Val::Arr(Vec::new()));
    object(vec![
        ("schema", string("hf-grant/v1")),
        ("grant_id", string(&row.grant_id)),
        ("repository", string(&row.repository)),
        (
            "issue",
            object(vec![
                ("number", integer(row.issue_number)),
                ("revision", string(&row.issue_revision)),
            ]),
        ),
        ("workflow_hash", string(&row.workflow_hash)),
        ("policy_hash", string(&row.policy_hash)),
        ("phase", string(&row.phase)),
        ("scope", string(&row.scope)),
        ("caps", caps),
        ("expires_at", string(&row.expires_at)),
        ("state_epoch", integer(row.state_epoch)),
        ("created_at", string(&row.created_at)),
    ])
}

fn method_grants_revoke(shared: &Arc<Shared>, request: &Request) -> String {
    let Some(grant_id) = request
        .params
        .as_ref()
        .and_then(|params| params.get("grant_id"))
        .and_then(Val::as_str)
        .filter(|id| crate::formats::is_grant_id(id))
    else {
        return err_response(
            &request.id,
            "refusal.malformed",
            "grants.revoke requires params.grant_id (gr_ format)",
        );
    };
    match journal_mutation(shared, request, "mutate.grant.revoke", grant_id) {
        Intent::Claimed { key } => {
            crash_point("grants.after-intent");
            let guard = match shared.lock_state() {
                Ok(guard) => guard,
                Err(message) => {
                    return err_response(&request.id, "state.unavailable", message);
                }
            };
            let response = match guard.revoke_grant(grant_id, &time::rfc3339_now()) {
                Ok(()) => resolve_mutation_on(
                    &guard,
                    &shared.log,
                    request,
                    &key,
                    "grants.revoke",
                    true,
                    object(vec![
                        ("grant_id", string(grant_id)),
                        ("revoked", bool_(true)),
                    ]),
                    None,
                ),
                Err(err) => resolve_mutation_on(
                    &guard,
                    &shared.log,
                    request,
                    &key,
                    "grants.revoke",
                    false,
                    null(),
                    Some((err.code, err.message)),
                ),
            };
            drop(guard);
            publish_after_state_change(shared, None);
            response
        }
        Intent::Replay { response } => replay(shared, &response),
        Intent::Refused { code, message } => err_response(&request.id, code, message),
    }
}

/// Journaled bounded-retention prune of daemon-owned backups (issue #9
/// AC8): the pruning intent (`mutate.backup.prune`) is journaled with its
/// own derived idempotency key before any pair is removed, and the claim is
/// resolved after the prune. Returns the removed snapshot names.
fn prune_backups_with_journal(
    shared: &Arc<Shared>,
    request: &Request,
) -> Result<Vec<String>, (&'static str, String)> {
    let mut key = format!("ik_backup-prune-{}", request.id);
    key.truncate(64);
    {
        let state = shared
            .lock_state()
            .map_err(|message| ("state.unavailable", message))?;
        match state.journal_intent(
            "mutate.backup.prune",
            "backups:prune",
            &key,
            &request.id,
            &request.method,
            None,
            None,
            &request.line,
        ) {
            Ok((ClaimAttempt::Claimed, _)) => {}
            Ok((ClaimAttempt::Replay { response: _ }, _)) => {
                return Err((
                    "refusal.idempotency",
                    "the prune for this request was already recorded".to_string(),
                ));
            }
            Ok((ClaimAttempt::Reused { owner_request_id }, _)) => {
                return Err((
                    "refusal.idempotency",
                    format!("prune key {key:?} belongs to request {owner_request_id}"),
                ));
            }
            Err(err) => return Err((err.code, err.message)),
        }
    }
    let pruned = backup::prune_backups(&shared.paths.backups_dir, backup::BackupPolicy::default())
        .map_err(|err| (err.code, err.message))?;
    let outcome = daemon_outcome(&key, "succeeded", null());
    {
        let state = shared
            .lock_state()
            .map_err(|message| ("state.unavailable", message))?;
        state
            .resolve_claim(
                &key,
                &request.method,
                "spent",
                &canonical_text(&outcome),
                None,
            )
            .map_err(|err| (err.code, err.message))?;
    }
    publish_after_state_change(shared, None);
    Ok(pruned)
}

fn method_backup_create(shared: &Arc<Shared>, request: &Request) -> String {
    match journal_mutation(shared, request, "mutate.backup.create", "backups") {
        Intent::Claimed { key } => {
            crash_point("backup.after-intent");
            let state = match shared.lock_state() {
                Ok(state) => state,
                Err(message) => {
                    return err_response(&request.id, "state.unavailable", message);
                }
            };
            let epoch = match state.current_epoch() {
                Ok(epoch) => epoch,
                Err(err) => {
                    drop(state);
                    return finish_mutation(
                        shared,
                        request,
                        &key,
                        "backup.create",
                        false,
                        null(),
                        Some((err.code, err.message)),
                    );
                }
            };
            drop(state);
            let (snapshot_path, _manifest_path) =
                backup::new_backup_paths(&shared.paths.backups_dir, epoch);
            let (digest, bytes) =
                match backup::create_snapshot(&shared.paths.db_path, &snapshot_path) {
                    Ok(result) => result,
                    Err(err) => {
                        return finish_mutation(
                            shared,
                            request,
                            &key,
                            "backup.create",
                            false,
                            null(),
                            Some((err.code, err.message)),
                        );
                    }
                };
            crash_point("backup.after-snapshot");
            let (journal_seq, event_seq) = match summary_tuple(shared) {
                Ok(values) => values,
                Err(err) => {
                    return finish_mutation(
                        shared,
                        request,
                        &key,
                        "backup.create",
                        false,
                        null(),
                        Some((err.code, err.message)),
                    );
                }
            };
            let manifest =
                backup::manifest_for(epoch, journal_seq, event_seq, digest, bytes, &snapshot_path);
            if let Err(err) = backup::write_manifest(&snapshot_path, &manifest)
                .and_then(|()| backup::verify_backup(&snapshot_path, &manifest))
            {
                return finish_mutation(
                    shared,
                    request,
                    &key,
                    "backup.create",
                    false,
                    null(),
                    Some((err.code, err.message)),
                );
            }
            crash_point("backup.after-manifest");
            // Bounded retention (issue #9 AC8): prune verified backup pairs
            // outside the default policy. The pruning intent is journaled
            // with its own idempotency key before any pair is removed and
            // resolved after — deleting retention records is itself a
            // journaled daemon-state operation.
            let pruned = match prune_backups_with_journal(shared, request) {
                Ok(pruned) => pruned,
                Err((code, message)) => {
                    return finish_mutation(
                        shared,
                        request,
                        &key,
                        "backup.create",
                        false,
                        null(),
                        Some((code, message)),
                    );
                }
            };
            let pruned_names: Vec<Val> = pruned.iter().map(|name| string(name)).collect();
            let result = object(vec![(
                "backup",
                object(vec![
                    ("snapshot", string(&manifest.snapshot_name)),
                    ("epoch", integer(epoch)),
                    ("journal_seq", integer(journal_seq)),
                    ("event_seq", integer(event_seq)),
                    ("db_sha256", string(&manifest.db_sha256)),
                    ("db_bytes", integer(manifest.db_bytes)),
                    ("created_at", string(&manifest.created_at)),
                    ("pruned", Val::Arr(pruned_names)),
                ]),
            )]);
            finish_mutation(shared, request, &key, "backup.create", true, result, None)
        }
        Intent::Replay { response } => replay(shared, &response),
        Intent::Refused { code, message } => err_response(&request.id, code, message),
    }
}

fn summary_tuple(shared: &Arc<Shared>) -> Result<(i64, i64), StateError> {
    let state = shared.lock_state().map_err(|message| StateError {
        code: "state.unavailable",
        message,
    })?;
    let (_, journal_seq, event_seq, _) = state.summary()?;
    Ok((journal_seq, event_seq))
}

fn method_restore_begin(shared: &Arc<Shared>, request: &Request) -> String {
    let target = request
        .params
        .as_ref()
        .and_then(|params| params.get("backup"))
        .and_then(Val::as_str)
        .filter(|name| !name.is_empty())
        .unwrap_or("latest");
    let backups = match backup::list_backups(&shared.paths.backups_dir) {
        Ok(backups) => backups,
        Err(err) => return err_response(&request.id, err.code, err.message),
    };
    let selected = if target == "latest" {
        backups.last().cloned()
    } else {
        backups
            .into_iter()
            .find(|manifest| manifest.snapshot_name == target)
    };
    let Some(manifest) = selected else {
        return err_response(
            &request.id,
            "refusal.backup.not_found",
            format!("no verified backup {target:?} is available"),
        );
    };
    let snapshot_path = shared.paths.backups_dir.join(&manifest.snapshot_name);
    if let Err(err) = backup::verify_backup(&snapshot_path, &manifest) {
        return err_response(&request.id, err.code, err.message);
    }

    // EXCLUSIVE restore window (review-5-daemon-r2 blocker): the state
    // mutex is held across intent -> rename -> reopen -> rotate/void ->
    // swap -> re-journal -> resolve. No other handler can journal into the
    // unlinked old file or observe a half-swapped state, because every
    // state access (all mutation methods) takes this same mutex. Events
    // are published only after the guard is dropped (hub locking rule).
    let mut guard = match shared.lock_state() {
        Ok(guard) => guard,
        Err(message) => return err_response(&request.id, "state.unavailable", message),
    };
    // A restore touches the whole database; refuse while interrupted claims
    // are pending (they must reconcile through a restart first, AC4/AC6).
    match guard.claims_in_flight() {
        Ok(claims) if claims.is_empty() => {}
        Ok(_) => {
            return err_response(
                &request.id,
                "refusal.restore.pending_claims",
                "restore refused while interrupted claims are pending; restart the daemon to reconcile them first",
            );
        }
        Err(err) => return err_response(&request.id, err.code, err.message),
    }
    // Journal the durable intent on the CURRENT state handle (still under
    // the exclusive guard, so no other writer can interleave).
    let key = match request
        .params
        .as_ref()
        .and_then(|params| params.get("idempotency_key"))
        .and_then(Val::as_str)
    {
        Some(key) if crate::formats::is_idempotency_key(key) => key.to_string(),
        _ => {
            return err_response(
                &request.id,
                "refusal.malformed",
                "restore.begin requires params.idempotency_key (ik_ format)",
            );
        }
    };
    match guard.journal_intent(
        "mutate.restore.begin",
        &format!("restore:{}", manifest.snapshot_name),
        &key,
        &request.id,
        &request.method,
        None,
        None,
        &request.line,
    ) {
        Ok((ClaimAttempt::Claimed, _)) => {}
        Ok((ClaimAttempt::Replay { response }, _)) => return replay(shared, &response),
        Ok((ClaimAttempt::Reused { owner_request_id }, _)) => {
            return err_response(
                &request.id,
                "refusal.idempotency",
                format!("idempotency key {key:?} already belongs to request {owner_request_id}"),
            );
        }
        Err(err) => return err_response(&request.id, err.code, err.message),
    }
    crash_point("restore.after-intent");
    if let Err(err) = backup::restore_snapshot(&snapshot_path, &shared.paths.db_path) {
        // The live file was NOT replaced: resolve the failure on the current
        // state and publish after the guard drops.
        let response = resolve_mutation_on(
            &guard,
            &shared.log,
            request,
            &key,
            "restore.begin",
            false,
            null(),
            Some((err.code, err.message)),
        );
        drop(guard);
        publish_after_state_change(shared, None);
        return response;
    }
    crash_point("restore.after-rename");
    // The DB file was replaced under the old connection. Reopen the
    // restored database and swap the handle while the exclusive guard is
    // still held, so nothing can journal into the unlinked old file.
    let reopened = match State::open(&shared.paths.db_path, crate::state::Retention::default()) {
        Ok(state) => state,
        Err(err) => {
            shared.log.write(
                "error",
                "outcome.journal_failed",
                &format!("restore reopen failed: {}: {}", err.code, err.message),
            );
            drop(guard);
            publish_after_state_change(shared, None);
            return err_response(
                &request.id,
                err.code,
                format!(
                    "restore renamed the database but reopening it failed; restart the daemon: {}",
                    err.message
                ),
            );
        }
    };
    let rotated_epoch = reopened
        .rotate_epoch("restore")
        .and_then(|epoch| reopened.invalidate_grants_below_current().map(|_| epoch))
        .and_then(|epoch| {
            // The snapshot predates the resolutions of any claims that were
            // in flight when it was taken; void them so a resurrected claim
            // can never dispatch or replay.
            reopened.void_in_flight_claims("restore").map(|_| epoch)
        });
    // Swap unconditionally: the live file is the restored one now, so every
    // later state access (including the re-journal below) must target it.
    *guard = reopened;
    // The pre-effect claim was journaled into the *old* DB, which the rename
    // replaced. Journal the intent again in the restored DB so the outcome
    // resolves durably here (a crash between the rename and this re-journal
    // simply re-executes the same restore on retry — idempotent).
    let response = match journal_mutation_on(
        &guard,
        request,
        "mutate.restore.begin",
        &format!("restore:{}", manifest.snapshot_name),
    ) {
        Intent::Claimed { key } => match rotated_epoch {
            Ok(epoch) => {
                let outcome = object(vec![
                    ("restored_epoch", integer(epoch)),
                    ("snapshot", string(&manifest.snapshot_name)),
                    ("prior_epoch", integer(epoch - 1)),
                ]);
                resolve_mutation_on(
                    &guard,
                    &shared.log,
                    request,
                    &key,
                    "restore.begin",
                    true,
                    outcome,
                    None,
                )
            }
            Err(err) => resolve_mutation_on(
                &guard,
                &shared.log,
                request,
                &key,
                "restore.begin",
                false,
                null(),
                Some((err.code, err.message)),
            ),
        },
        Intent::Replay { response } => replay(shared, &response),
        Intent::Refused { code, message } => err_response(&request.id, code, message),
    };
    drop(guard);
    publish_after_state_change(shared, None);
    response
}

/// Finish a journaled mutation: lock the state, resolve the claim with a
/// typed outcome and the recorded response in one transaction, drop the
/// guard, then publish the outcome event and refresh the bounded event
/// mirror. Returns the response line.
fn finish_mutation(
    shared: &Arc<Shared>,
    request: &Request,
    key: &str,
    method: &str,
    success: bool,
    result: Val,
    error: Option<(&'static str, String)>,
) -> String {
    let response = match shared.lock_state() {
        Ok(state) => resolve_mutation_on(
            &state,
            &shared.log,
            request,
            key,
            method,
            success,
            result,
            error,
        ),
        Err(message) => {
            shared.log.write(
                "error",
                "outcome.journal_failed",
                &format!("state lock lost: {message}"),
            );
            return err_response(
                &request.id,
                "state.unavailable",
                format!(
                    "the mutation effect completed but its outcome could not be journaled \
                     (fail closed): {message}"
                ),
            );
        }
    };
    publish_after_state_change(shared, None);
    response
}

/// Resolve ONE run-control claim with an ALREADY-TYPED refusal an inner path
/// produced (issue #230): the code is carried VERBATIM — never remapped to a
/// generic one — and the control's own outcome row records it exactly as any
/// other refused control.
fn finish_control_refusal(
    shared: &Arc<Shared>,
    request: &Request,
    key: &str,
    method: &str,
    code: &str,
    message: String,
) -> String {
    let response = err_response(&request.id, code, &message);
    let state = match shared.lock_state() {
        Ok(state) => state,
        Err(lock_message) => {
            return err_response(
                &request.id,
                "state.unavailable",
                format!(
                    "the control was refused ({code}) and the state lock is lost: {lock_message}"
                ),
            );
        }
    };
    let outcome = daemon_outcome(key, "failed", error_val(code, &message));
    let resolved = match state.resolve_claim(
        key,
        method,
        "spent",
        &canonical_text(&outcome),
        Some(&response),
    ) {
        Ok(_) => response,
        Err(err) => {
            shared.log.write(
                "error",
                "outcome.journal_failed",
                &format!("{}: {}", err.code, err.message),
            );
            err_response(
                &request.id,
                err.code,
                format!(
                    "the refusal could not be journaled (fail closed): {}",
                    err.message
                ),
            )
        }
    };
    drop(state);
    publish_after_state_change(shared, None);
    resolved
}

/// Resolve a claim on an ALREADY-LOCKED state handle (no locking, no
/// publishing). Used by the restore path, which holds the state mutex
/// across the rename/reopen/swap sequence and publishes only after the
/// guard is dropped.
#[allow(clippy::too_many_arguments)]
fn resolve_mutation_on(
    state: &State,
    log: &DaemonLog,
    request: &Request,
    key: &str,
    method: &str,
    success: bool,
    result: Val,
    error: Option<(&'static str, String)>,
) -> String {
    let (status, response, outcome) = if success {
        let response = ok_response(&request.id, result);
        (
            "spent",
            response.clone(),
            daemon_outcome(key, "succeeded", null()),
        )
    } else {
        let (code, message) = error.unwrap_or(("state.unavailable", "effect failed".to_string()));
        let response = err_response(&request.id, code, &message);
        (
            "spent",
            response.clone(),
            daemon_outcome(key, "failed", error_val(code, &message)),
        )
    };
    match state.resolve_claim(
        key,
        method,
        status,
        &canonical_text(&outcome),
        Some(&response),
    ) {
        Ok(_audit) => response,
        Err(err) => {
            log.write(
                "error",
                "outcome.journal_failed",
                &format!("{}: {}", err.code, err.message),
            );
            err_response(
                &request.id,
                err.code,
                format!(
                    "the mutation effect completed but its outcome could not be journaled \
                     (fail closed): {}",
                    err.message
                ),
            )
        }
    }
}

/// Return a recorded replay response (the recorded line is canonical and was
/// schema-validated when stored).
fn replay(shared: &Arc<Shared>, response: &str) -> String {
    shared
        .log
        .write("info", "request.replay", "recorded response returned");
    response.to_string()
}

/// A typed hf-outcome/v1 document for daemon-owned operations.
fn daemon_outcome(key: &str, status: &str, error: Val) -> Val {
    let failed = status == "failed" || status == "refused";
    object(vec![
        ("schema", string("hf-outcome/v1")),
        ("plan_id", string(DAEMON_PLAN_ID)),
        ("step_id", string(DAEMON_STEP_ID)),
        ("status", string(status)),
        ("idempotency_key", string(key)),
        ("observed_at", string(&time::rfc3339_now())),
        ("result", if failed { null() } else { object(vec![]) }),
        ("error", if failed { error } else { null() }),
    ])
}

fn error_val(code: &str, message: &str) -> Val {
    object(vec![
        ("code", string(code)),
        ("message", string(message)),
        ("retryable", bool_(false)),
    ])
}

// ---------------------------------------------------------------------------
// Event fan-out (AC7: ordering, replay, snapshot, bounded backpressure)
// ---------------------------------------------------------------------------

/// Publish every journal event committed since the last fan-out. Runs after
/// the state guard is dropped (hub-lock ordering rule above); also refreshes
/// the bounded events mirror file when anything was published.
fn publish_events(shared: &Arc<Shared>) {
    let mut hub = match shared.hub.lock() {
        Ok(hub) => hub,
        Err(_) => return,
    };
    let state = match shared.lock_state() {
        Ok(state) => state,
        Err(_) => return,
    };
    let events = match state.events_after(hub.last_published, REPLAY_MAX_LINES) {
        Ok(events) => events,
        Err(_) => return,
    };
    let mut last = hub.last_published;
    for event in &events {
        let seq = event.get("seq").and_then(as_non_negative);
        if let Some(seq) = seq {
            if seq <= last {
                continue;
            }
            last = last.max(seq);
            hub.publish(&canonical_text(event));
        }
    }
    hub.last_published = last;
    drop(hub);
    drop(state);
    if last > 0
        && let Ok(state) = shared.lock_state()
        && let Err(err) = state.rebuild_events_mirror(&shared.paths.events_mirror_path)
    {
        shared.log.write(
            "warn",
            "events.mirror.write_failed",
            &format!("{}: {}", err.code, err.message),
        );
    }
}

fn subscribe_request(_shared: &Arc<Shared>, request: &Request) -> HandleOutcome {
    let cursor = request
        .params
        .as_ref()
        .and_then(|params| params.get("cursor"))
        .and_then(as_non_negative);
    let response = ok_response(
        &request.id,
        object(vec![
            ("event_stream", bool_(true)),
            ("schema", string("hf-event/v1")),
            ("cursor", cursor.map(integer).unwrap_or_else(null)),
        ]),
    );
    HandleOutcome::Subscribed { response, cursor }
}

/// Event-stream mode after the subscribe response: snapshot/replay first
/// (computed under the hub lock while registering), then live events from
/// the bounded queue. The client socket becomes push-only.
fn serve_event_stream(
    shared: &Arc<Shared>,
    writer: &mut UnixStream,
    cursor: Option<i64>,
) -> Result<(), String> {
    configure_event_writer(writer)?;
    let (receiver, snapshot_lines, replay_lines) = {
        let (sender, receiver) = sync_channel::<String>(SUBSCRIBER_QUEUE_CAP);
        let mut hub = shared.hub.lock().map_err(|_| "hub poisoned".to_string())?;
        let (snapshot, replay) = compute_replay(shared, cursor)?;
        hub.subscribers.push(Subscriber { sender });
        (receiver, snapshot, replay)
    };
    for line in snapshot_lines.iter().chain(replay_lines.iter()) {
        write_event_line(writer, line)?;
    }
    for line in receiver {
        write_event_line(writer, &line)?;
    }
    Ok(())
}

fn configure_event_writer(writer: &UnixStream) -> Result<(), String> {
    writer
        .set_write_timeout(Some(EVENT_STREAM_WRITE_TIMEOUT))
        .map_err(|err| format!("configure event write timeout: {err}"))
}

fn write_event_line(writer: &mut UnixStream, line: &str) -> Result<(), String> {
    writer
        .write_all(line.as_bytes())
        .and_then(|()| writer.write_all(b"\n"))
        .and_then(|()| writer.flush())
        .map_err(|err| format!("write event: {err}"))
}

/// Compute (snapshot lines, replay lines) for a subscriber cursor. Must be
/// called with the hub lock held so no event can fall between the replay
/// query and the registration (either it lands in the replay list or it is
/// queued after registration — never both, never neither).
fn compute_replay(
    shared: &Arc<Shared>,
    cursor: Option<i64>,
) -> Result<(Vec<String>, Vec<String>), String> {
    let state = shared.lock_state()?;
    let (max_seq, min_seq) = state
        .event_bounds()
        .map_err(|err| format!("{}: {}", err.code, err.message))?;
    let need_snapshot = match (cursor, max_seq) {
        (None, _) => true,
        (Some(_), None) => true,
        (Some(n), Some(max)) => {
            n > max
                || match min_seq {
                    Some(min) => n + 1 < min,
                    None => true,
                }
        }
    };
    let mut snapshot = Vec::new();
    let mut replay = Vec::new();
    if need_snapshot {
        let doc = state
            .snapshot_event()
            .map_err(|err| format!("{}: {}", err.code, err.message))?;
        snapshot.push(canonical_text(&doc));
    } else if let Some(n) = cursor {
        let events = state
            .events_after(n, REPLAY_MAX_LINES)
            .map_err(|err| format!("{}: {}", err.code, err.message))?;
        for event in events {
            replay.push(canonical_text(&event));
        }
    }
    Ok((snapshot, replay))
}

// ---------------------------------------------------------------------------
// Restart reconciliation (AC4: restart reconciles before retry)
// ---------------------------------------------------------------------------

/// Mark every claim left `claimed` by an interrupted run as ambiguous with a
/// typed outcome and a `reconcile.*` journal record. Returns the count.
fn reconcile_claims(
    state: &State,
    log: &DaemonLog,
    checkpoints_dir: &Path,
) -> Result<usize, DaemonError> {
    let pending = state.claims_in_flight()?;
    let mut reconciled = 0usize;
    for claim in pending {
        let outcome = daemon_outcome(
            &claim.key,
            "ambiguous",
            error_val(
                "state.interrupted",
                "the operation was interrupted before its outcome was journaled; \
                 restart reconciliation marks it ambiguous — external review is required \
                 before retrying with a new key",
            ),
        );
        match state.journal_reconcile(
            &claim.key,
            &claim.method,
            "ambiguous",
            &canonical_text(&outcome),
        ) {
            Ok(_) => {
                reconciled += 1;
                log.write(
                    "warn",
                    "reconcile.ambiguous",
                    &format!(
                        "claim {} (request {}) marked ambiguous",
                        claim.key, claim.request_id
                    ),
                );
                // Issue #73: an interrupted lane-replacement claim also
                // flips its record to the explicit `ambiguous` outcome, so
                // the record itself refuses advancement until external
                // reconciliation (the claim machinery and the record agree).
                if claim.method.starts_with("lane.replacement.")
                    && let Ok(doc) = Val::parse_json(&claim.request_line)
                    && let Some(params) = doc.get("params")
                {
                    match state.mark_replacement_ambiguous(
                        params,
                        &format!("interrupted {} claim ({})", claim.method, claim.key),
                        &time::rfc3339_now(),
                    ) {
                        Ok(true) => {
                            log.write(
                                "warn",
                                "reconcile.replacement",
                                &format!(
                                    "lane replacement for claim {} marked ambiguous",
                                    claim.key
                                ),
                            );
                        }
                        Ok(false) => {}
                        Err(err) => {
                            return Err(daemon_error(
                                "daemon.reconcile",
                                format!("{}: {}", err.code, err.message),
                            ));
                        }
                    }
                }
                // Issue #74: an interrupted checkpoint claim reconciles
                // against its commit marker (the committed checkpoint row;
                // see reconcile_lane_checkpoint) instead of blindly flipping
                // the record: the record's `quiescing` -> `checkpointed`
                // transition commits atomically with the row, so the record
                // is never in doubt.
                if claim.method == "lane.checkpoint.create"
                    && let Ok(doc) = Val::parse_json(&claim.request_line)
                    && let Some(params) = doc.get("params")
                {
                    reconcile_lane_checkpoint(state, log, checkpoints_dir, params)?;
                }
                // Issue #75: an interrupted lane.retire claim reconciles
                // EXACT ABSENCE through the confirmation read-back. The stop
                // is issued at most once: reconciliation never repeats a
                // signal — it either completes the retirement (absence
                // proven) or parks the record ambiguous. A reused identity is
                // never signalled.
                if claim.method == "lane.retire"
                    && let Ok(doc) = Val::parse_json(&claim.request_line)
                    && let Some(params) = doc.get("params")
                {
                    reconcile_lane_retire(state, log, params)?;
                }
                // Issue #76: an interrupted `lane.start` claim reconciles
                // the startup nonce AND the process evidence before any
                // retry: the committed (or observed) successor identity is
                // re-read from the backend. Verified evidence completes the
                // `starting` -> `adopting` boundary; every other outcome
                // parks the record ambiguous and never re-spawns.
                if claim.method == "lane.start"
                    && let Ok(doc) = Val::parse_json(&claim.request_line)
                    && let Some(params) = doc.get("params")
                {
                    reconcile_lane_successor(state, log, params)?;
                }
                // Issue #85: an interrupted `queue.submit` claim reconciles
                // against its commit marker (the committed submission row).
                // The row, the membership items, the admitted runs and the
                // ownership rows commit in ONE transaction, so a present row
                // means exactly the committed effects exist and a missing
                // row means none do: nothing is ever re-executed.
                if claim.method == "queue.submit"
                    && let Ok(doc) = Val::parse_json(&claim.request_line)
                    && let Some(params) = doc.get("params")
                {
                    reconcile_queue_submission(state, log, params)?;
                }
                // Issue #92: an interrupted `grants.issue` claim reconciles
                // against its commit marker — the grant row itself. The
                // insert is one statement, so a present row means the mint
                // committed and a missing row means no grant exists (no
                // partial grant can survive the interrupt). Nothing is ever
                // re-executed and the claim stays ambiguous: a retry needs a
                // fresh idempotency key.
                if claim.method == "grants.issue"
                    && let Ok(doc) = Val::parse_json(&claim.request_line)
                    && let Some(params) = doc.get("params")
                {
                    reconcile_grant_issue(state, log, params)?;
                }
                // Issue #86: an interrupted run-control claim reconciles
                // against its commit marker — the run's durable control
                // rows. The readback says whether the control committed;
                // nothing is ever repeated and nothing is ever signalled.
                if claim.method.starts_with("run.") {
                    reconcile_run_control(state, log, &claim)?;
                }
            }
            Err(err) => {
                return Err(daemon_error(
                    "daemon.reconcile",
                    format!("{}: {}", err.code, err.message),
                ));
            }
        }
    }
    Ok(reconciled)
}

// ---------------------------------------------------------------------------
// Checkpoint brief artifacts (issue #74)
// ---------------------------------------------------------------------------

/// The deterministic artifact path of one checkpoint brief (inside the
/// daemon-owned checkpoints directory).
fn checkpoint_brief_path(dir: &Path, checkpoint_id: &str) -> PathBuf {
    dir.join(format!("{checkpoint_id}.brief"))
}

/// Materialize one checkpoint brief artifact (atomic tmp + rename inside the
/// daemon-owned checkpoints directory) and verify the written bytes against
/// the committed brief digest before publishing the final name. The artifact
/// is a pure derivation of the durable row: a failure here is deferred to
/// restart reconciliation (which regenerates and verifies it), never a state
/// rollback.
fn write_checkpoint_brief(
    dir: &Path,
    checkpoint_id: &str,
    brief_digest: &str,
    brief: &str,
) -> Result<PathBuf, String> {
    let path = checkpoint_brief_path(dir, checkpoint_id);
    let tmp = dir.join(format!("{checkpoint_id}.brief.tmp"));
    std::fs::write(&tmp, brief.as_bytes())
        .map_err(|err| format!("write {}: {err}", tmp.display()))?;
    let written =
        std::fs::read(&tmp).map_err(|err| format!("read back {}: {err}", tmp.display()))?;
    let digest = crate::canonical::sha256_hex(&written);
    if digest != brief_digest {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!(
            "brief digest mismatch after write ({digest} != {brief_digest})"
        ));
    }
    std::fs::rename(&tmp, &path).map_err(|err| format!("rename {}: {err}", path.display()))?;
    Ok(path)
}

/// Restart reconciliation for one interrupted `lane.checkpoint.create` claim
/// (issue #74 AC7). The committed checkpoint row is the commit marker — the
/// row and the replacement record's `quiescing` → `checkpointed` transition
/// commit in one transaction, so:
///
/// - row present: the capture committed; the derived brief artifact is
///   (re)materialized from the durable row and verified against
///   `brief_digest` — the restart yields the NEW COMPLETE checkpoint.
/// - row absent and no artifact: the capture never committed; the record is
///   untouched (the previous complete state) and the standard ambiguous
///   claim reconciliation keeps the retry path honest.
/// - row absent but an artifact exists: inconsistent (only a non-atomic
///   implementation produces this); fail closed — the record is parked
///   `ambiguous` and the daemon logs it rather than adopting or silently
///   deleting an artifact no commit produced.
fn reconcile_lane_checkpoint(
    state: &State,
    log: &DaemonLog,
    checkpoints_dir: &Path,
    params: &Val,
) -> Result<(), DaemonError> {
    let Some(replacement_id) = params
        .get("replacement_id")
        .and_then(Val::as_str)
        .filter(|text| crate::formats::is_replacement_id(text))
    else {
        return Ok(());
    };
    let checkpoint_id = crate::state::checkpoint_id_for(replacement_id);
    let path = checkpoint_brief_path(checkpoints_dir, &checkpoint_id);
    let tmp = checkpoints_dir.join(format!("{checkpoint_id}.brief.tmp"));
    let row = state
        .lane_checkpoint_by_replacement(replacement_id)
        .map_err(|err| {
            daemon_error(
                "daemon.reconcile",
                format!("checkpoint reconciliation: {}: {}", err.code, err.message),
            )
        })?;
    let Some(row) = row else {
        if path.exists() || tmp.exists() {
            state
                .mark_replacement_ambiguous(
                    params,
                    "checkpoint artifact present without a committed checkpoint record; \
                     external reconciliation is required",
                    &time::rfc3339_now(),
                )
                .map_err(|err| {
                    daemon_error(
                        "daemon.reconcile",
                        format!("checkpoint reconciliation: {}: {}", err.code, err.message),
                    )
                })?;
            log.write(
                "warn",
                "reconcile.lane.checkpoint",
                &format!(
                    "checkpoint artifact {checkpoint_id}.brief exists without a committed \
                     record; replacement parked ambiguous"
                ),
            );
        }
        return Ok(());
    };
    let existing_ok = std::fs::read(&path)
        .map(|bytes| crate::canonical::sha256_hex(&bytes) == row.brief_digest)
        .unwrap_or(false);
    if existing_ok {
        log.write(
            "info",
            "reconcile.lane.checkpoint",
            &format!(
                "checkpoint {checkpoint_id} was committed before the interrupt; brief artifact \
                 reused (digest verified)"
            ),
        );
        return Ok(());
    }
    let brief = crate::state::lane_checkpoint_brief(&row).map_err(|err| {
        daemon_error(
            "daemon.reconcile",
            format!("checkpoint reconciliation: {}: {}", err.code, err.message),
        )
    })?;
    let digest = crate::canonical::sha256_hex(brief.as_bytes());
    if digest != row.brief_digest {
        state
            .mark_replacement_ambiguous(
                params,
                "regenerated checkpoint brief does not match the recorded digest; external \
                 reconciliation is required",
                &time::rfc3339_now(),
            )
            .map_err(|err| {
                daemon_error(
                    "daemon.reconcile",
                    format!("checkpoint reconciliation: {}: {}", err.code, err.message),
                )
            })?;
        log.write(
            "warn",
            "reconcile.lane.checkpoint",
            &format!(
                "checkpoint {checkpoint_id} brief regeneration drifted from the recorded \
                 digest; replacement parked ambiguous"
            ),
        );
        return Ok(());
    }
    write_checkpoint_brief(checkpoints_dir, &checkpoint_id, &row.brief_digest, &brief).map_err(
        |message| {
            daemon_error(
                "daemon.reconcile",
                format!("checkpoint reconciliation: {message}"),
            )
        },
    )?;
    log.write(
        "info",
        "reconcile.lane.checkpoint",
        &format!(
            "checkpoint {checkpoint_id} was committed before the interrupt; brief artifact \
             regenerated from the durable record (digest verified)"
        ),
    );
    Ok(())
}

/// Restart reconciliation for one interrupted `lane.retire` claim (issue #75
/// AC6). The retirement's graceful stop is issued AT MOST ONCE: this path
/// never repeats a signal — it reads the backend confirmation row and:
///
/// - absence proven (the process is absent AND the registration is released
///   for the bound session/generation): the interrupted retirement completed,
///   so the `checkpointed` → `retired` transition is committed with a
///   reconciled evidence summary.
/// - the bound session is still present, a reused identity owns it, or the
///   read-back is unavailable: the record is parked `ambiguous` for external
///   reconciliation (never a second signal, never against a reused identity).
///
/// A record that already committed its retirement (phase `retired`) needs no
/// reconciliation at all.
fn reconcile_lane_retire(state: &State, log: &DaemonLog, params: &Val) -> Result<(), DaemonError> {
    let Some(replacement_id) = params
        .get("replacement_id")
        .and_then(Val::as_str)
        .filter(|text| crate::formats::is_replacement_id(text))
    else {
        return Ok(());
    };
    let row = state
        .lane_replacement_by_id(replacement_id)
        .map_err(|err| {
            daemon_error(
                "daemon.reconcile",
                format!("retirement reconciliation: {}: {}", err.code, err.message),
            )
        })?;
    let Some(row) = row else {
        return Ok(());
    };
    if row.phase == "retired" {
        log.write(
            "warn",
            "reconcile.lane.retire",
            &format!(
                "replacement {replacement_id} committed its retirement before the interrupt; \
                 no signal was repeated and the claim stays ambiguous"
            ),
        );
        return Ok(());
    }
    if row.phase != "checkpointed" || row.outcome != "pending" {
        log.write(
            "info",
            "reconcile.lane.retire",
            &format!(
                "replacement {replacement_id} is at {}/{}; the interrupted retirement claim \
                 needs no retirement reconciliation",
                row.phase, row.outcome
            ),
        );
        return Ok(());
    }
    let park = |reason: String| -> Result<(), DaemonError> {
        state
            .mark_replacement_ambiguous(params, &reason, &time::rfc3339_now())
            .map_err(|err| {
                daemon_error(
                    "daemon.reconcile",
                    format!("retirement reconciliation: {}: {}", err.code, err.message),
                )
            })?;
        log.write("warn", "reconcile.lane.retire", &reason);
        Ok(())
    };
    let Some(harness) = params.get("harness") else {
        return park(format!(
            "interrupted retirement of {replacement_id} carries no harness binding; the record \
             is parked ambiguous (no signal was repeated)"
        ));
    };
    let profile = match retirement_profile(harness) {
        Ok(profile) => profile,
        Err((code, message)) => {
            return park(format!(
                "interrupted retirement of {replacement_id} cannot rebuild its harness profile \
                 ({code}: {message}); the record is parked ambiguous (no signal was repeated)"
            ));
        }
    };
    let checkpoint_digest = match state.lane_checkpoint_by_replacement(replacement_id) {
        Ok(Some(checkpoint)) if checkpoint.generation == row.generation => checkpoint.digest,
        Ok(_) => {
            return park(format!(
                "interrupted retirement of {replacement_id} has no committed checkpoint for its \
                 generation; the record is parked ambiguous (no signal was repeated)"
            ));
        }
        Err(err) => {
            return Err(daemon_error(
                "daemon.reconcile",
                format!("retirement reconciliation: {}: {}", err.code, err.message),
            ));
        }
    };
    let target = crate::adapters::RetirementTarget {
        session: row.source_session.clone(),
        process: row.source_process.clone(),
    };
    let env = crate::config::adapter_environment();
    let evidence = crate::adapters::retirement_evidence(
        &profile,
        &target,
        row.generation,
        &env,
        crate::adapters::ADAPTER_TIMEOUT,
    );
    match evidence {
        Ok(crate::adapters::RetirementEvidence::Retired) => {
            let reason = format!(
                "reconciled after an interrupted retirement: exact absence verified (backend \
                 process absent; registration released for session {:?} generation {}); no \
                 signal was repeated",
                target.session, row.generation
            );
            match state.commit_lane_retirement(
                replacement_id,
                row.generation,
                &checkpoint_digest,
                &reason,
                &time::rfc3339_now(),
            ) {
                Ok(_) => {
                    log.write("warn", "reconcile.lane.retire", &reason);
                    Ok(())
                }
                Err(err) => park(format!(
                    "interrupted retirement of {replacement_id} verified exact absence but the \
                     transition could not commit ({}: {}); the record is parked ambiguous (no \
                     signal was repeated)",
                    err.code, err.message
                )),
            }
        }
        Ok(crate::adapters::RetirementEvidence::Held { detail }) => park(format!(
            "interrupted retirement of {replacement_id} cannot prove exact absence ({detail}); \
             the record is parked ambiguous and no signal was repeated"
        )),
        Ok(crate::adapters::RetirementEvidence::Reused { detail }) => park(format!(
            "interrupted retirement of {replacement_id} observed a reused identity ({detail}); \
             the record is parked ambiguous and no signal was repeated against it"
        )),
        Err(err) => park(format!(
            "interrupted retirement of {replacement_id} could not read the backend confirmation \
             ({}: {}); the record is parked ambiguous and no signal was repeated",
            err.code, err.message
        )),
    }
}

/// Restart reconciliation for one interrupted `lane.start` claim (issue #76
/// AC7). The startup nonce AND the process evidence are reconciled BEFORE
/// any retry:
///
/// - the successor row is the commit marker (the row and the
///   `retired` → `starting` boundary commit in ONE transaction BEFORE any
///   spawn), so a present row means a spawn MAY have been issued. The
///   claim's nonce must own the row; a mismatch parks `ambiguous`.
/// - the committed successor is re-read from the backend
///   (`session show <session> --json`): verified evidence completes the
///   `starting` → `adopting` boundary with a reconciled summary; every
///   other outcome (not verifiable, reused identity, unreadable read-back)
///   parks the record `ambiguous`. The spawn is NEVER repeated.
/// - a row-absent claim never issued a spawn; the record is parked
///   `ambiguous` — external reconciliation is required before any retry,
///   so a replayed start can never duplicate a successor.
///
/// A record that already committed its successor boundary (phase `adopting`
/// or `adopted`) needs no reconciliation at all.
fn reconcile_lane_successor(
    state: &State,
    log: &DaemonLog,
    params: &Val,
) -> Result<(), DaemonError> {
    let Some(replacement_id) = params
        .get("replacement_id")
        .and_then(Val::as_str)
        .filter(|text| crate::formats::is_replacement_id(text))
    else {
        return Ok(());
    };
    let row = state
        .lane_replacement_by_id(replacement_id)
        .map_err(|err| {
            daemon_error(
                "daemon.reconcile",
                format!("successor reconciliation: {}: {}", err.code, err.message),
            )
        })?;
    let Some(record) = row else {
        return Ok(());
    };
    if record.phase == "adopting" || record.phase == "adopted" {
        log.write(
            "info",
            "reconcile.lane.start",
            &format!(
                "replacement {replacement_id} committed its successor boundary before the \
                 interrupt (phase {}); no spawn was repeated",
                record.phase
            ),
        );
        return Ok(());
    }
    if record.phase != "starting" || record.outcome != "pending" {
        log.write(
            "info",
            "reconcile.lane.start",
            &format!(
                "replacement {replacement_id} is at {}/{}; the interrupted start claim needs \
                 no successor reconciliation",
                record.phase, record.outcome
            ),
        );
        return Ok(());
    }
    let park = |reason: String| -> Result<(), DaemonError> {
        state
            .mark_replacement_ambiguous(params, &reason, &time::rfc3339_now())
            .map_err(|err| {
                daemon_error(
                    "daemon.reconcile",
                    format!("successor reconciliation: {}: {}", err.code, err.message),
                )
            })?;
        log.write("warn", "reconcile.lane.start", &reason);
        Ok(())
    };
    let nonce = params
        .get("binding")
        .and_then(|binding| binding.get("nonce"))
        .and_then(Val::as_str)
        .unwrap_or("")
        .to_string();
    let successor = state
        .lane_successor_by_replacement(replacement_id)
        .map_err(|err| {
            daemon_error(
                "daemon.reconcile",
                format!("successor reconciliation: {}: {}", err.code, err.message),
            )
        })?;
    let Some(successor) = successor else {
        // No row = the boundary never committed = no spawn was ever
        // issued. Fail closed anyway: an explicit external reconciliation
        // is required before any retry, so a replayed start can never
        // duplicate a successor.
        return park(format!(
            "interrupted successor start of {replacement_id} (nonce {nonce:?}) never committed \
             its successor boundary; no spawn is repeated and external reconciliation is \
             required before any retry"
        ));
    };
    if successor.nonce != nonce {
        return park(format!(
            "interrupted successor start of {replacement_id} carries nonce {nonce:?} but the \
             committed successor {} is owned by another startup nonce; external reconciliation \
             is required",
            successor.successor_id
        ));
    }
    let Some(harness) = params.get("harness") else {
        return park(format!(
            "interrupted successor start of {replacement_id} carries no harness binding; the \
             record is parked ambiguous (no spawn was repeated)"
        ));
    };
    let profile = match retirement_profile(harness) {
        Ok(profile) => profile,
        Err((code, message)) => {
            return park(format!(
                "interrupted successor start of {replacement_id} cannot rebuild its harness \
                 profile ({code}: {message}); the record is parked ambiguous (no spawn was \
                 repeated)"
            ));
        }
    };
    let target_binding = stored_profile(state, replacement_id).map_err(|(code, message)| {
        daemon_error(
            "daemon.reconcile",
            format!("successor reconciliation profile plan: {code}: {message}"),
        )
    })?;
    let target = crate::adapters::SuccessorTarget {
        session: successor.session.clone(),
        role: successor.role.clone(),
        profile_key: successor.profile_key.clone(),
        profile_kind: successor.profile_kind.clone(),
        worktree: successor.worktree.clone(),
        kickoff_receipt: successor.kickoff_receipt.clone(),
        source_process: record.source_process.clone(),
        binding: target_binding.clone(),
    };
    let env = crate::config::adapter_environment();
    match crate::adapters::successor_evidence(
        &profile,
        &target,
        &env,
        crate::adapters::ADAPTER_TIMEOUT,
    ) {
        Ok(crate::adapters::SuccessorEvidence::Verified {
            process,
            readiness,
            binding,
        }) => {
            let binding_doc = binding.to_doc(target_binding.as_ref());
            let reason = format!(
                "reconciled after an interrupted start: the adapter observed the committed \
                 successor {} process {} ({readiness}, binding {}) with the bound identity, \
                 the SAME worktree and the echoed kickoff receipt (nonce {nonce})",
                successor.successor_id,
                process,
                binding.status()
            );
            match state.commit_lane_successor_verified(
                replacement_id,
                &nonce,
                &process,
                &readiness,
                &binding_doc,
                &reason,
                &time::rfc3339_now(),
            ) {
                Ok(_) => {
                    log.write(
                        "info",
                        "reconcile.lane.start",
                        &format!(
                            "interrupted successor start of {replacement_id} reconciled: the \
                             committed successor {} is verified and the `starting` -> \
                             `adopting` boundary completed (no spawn was repeated)",
                            successor.successor_id
                        ),
                    );
                    Ok(())
                }
                Err(err) => park(format!(
                    "interrupted successor start of {replacement_id} verified the committed \
                     successor but the boundary could not commit ({}: {}); the record is \
                     parked ambiguous (no spawn was repeated)",
                    err.code, err.message
                )),
            }
        }
        Ok(crate::adapters::SuccessorEvidence::Held { detail }) => park(format!(
            "interrupted successor start of {replacement_id} cannot verify the committed \
             successor {} ({detail}); the record is parked ambiguous and no spawn was repeated",
            successor.successor_id
        )),
        Ok(crate::adapters::SuccessorEvidence::Reused { detail }) => park(format!(
            "interrupted successor start of {replacement_id} observed a reused or wrong \
             identity for the committed successor {} ({detail}); the record is parked \
             ambiguous and no spawn was repeated against it",
            successor.successor_id
        )),
        Err(err) => park(format!(
            "interrupted successor start of {replacement_id} could not read the successor \
             evidence ({}: {}); the record is parked ambiguous and no spawn was repeated",
            err.code, err.message
        )),
    }
}

/// Restart reconciliation for one interrupted `grants.issue` claim (issue
/// #92 AC4). The grant row is the commit marker: issuance is ONE insert, so
/// re-reading the row is enough to know whether the mint happened.
///
/// - Row present: the mint committed. The readback re-verifies the durable
///   binding against the presented document (repository, issue number +
///   revision, expiry, epoch) so a divergence is stated instead of assumed;
///   nothing is re-executed and no second grant is ever inserted.
/// - Row absent: the mint never committed. No partial grant exists — the
///   insert is all-or-nothing — and a retry (fresh idempotency key) mints
///   from live state.
///
/// Either way the claim itself stays ambiguous (the generic reconciliation
/// outcome): an operator decides what happens next.
fn reconcile_grant_issue(state: &State, log: &DaemonLog, params: &Val) -> Result<(), DaemonError> {
    let Some(grant) = params.get("grant") else {
        log.write(
            "warn",
            "reconcile.grants.issue",
            "interrupted grant issuance claim carries no params.grant; there is no commit \
             marker to read back",
        );
        return Ok(());
    };
    let grant_id = grant
        .get("grant_id")
        .and_then(Val::as_str)
        .unwrap_or_default();
    if !crate::formats::is_grant_id(grant_id) {
        log.write(
            "warn",
            "reconcile.grants.issue",
            "interrupted grant issuance claim carries no grant id; there is no commit marker to \
             read back",
        );
        return Ok(());
    }
    let read = state.grant_by_id(grant_id).map_err(|err| {
        daemon_error(
            "daemon.reconcile",
            format!(
                "grant issuance reconciliation: {}: {}",
                err.code, err.message
            ),
        )
    })?;
    let Some(row) = read else {
        log.write(
            "info",
            "reconcile.grants.issue",
            &format!(
                "interrupted grant issuance {grant_id} never committed; the mint is one insert, \
                 so no partial grant exists and a retry needs a fresh idempotency key"
            ),
        );
        return Ok(());
    };
    let presented_revision = grant
        .get("issue")
        .and_then(|issue| issue.get("revision"))
        .and_then(Val::as_str)
        .unwrap_or_default();
    let presented_expiry = grant
        .get("expires_at")
        .and_then(Val::as_str)
        .unwrap_or_default();
    if row.issue_revision != presented_revision
        || row.expires_at != presented_expiry
        || grant.get("repository").and_then(Val::as_str) != Some(row.repository.as_str())
    {
        log.write(
            "warn",
            "reconcile.grants.issue",
            &format!(
                "interrupted grant issuance {grant_id} committed a DIFFERENT binding than the \
                 interrupted request carried; the committed row stands and external \
                 reconciliation is required"
            ),
        );
        return Ok(());
    }
    log.write(
        "info",
        "reconcile.grants.issue",
        &format!(
            "grant issuance {grant_id} was committed before the interrupt (status {}, epoch {}); \
             the row stands, nothing is re-executed, and the claim needs a fresh idempotency key",
            row.status, row.state_epoch
        ),
    );
    Ok(())
}

/// Restart reconciliation for one interrupted `queue.submit` claim (issue
/// #85 AC6). The committed submission row is the commit marker: the row,
/// the membership items, the admitted run rows and the ownership rows
/// commit in ONE transaction, so re-reading the marker is enough to know
/// exactly which effects exist.
///
/// - Row present: the submission committed; the derived document is read
///   back from the durable rows and its digest binding is re-verified
///   against the persisted bound-input line. Nothing is re-executed and no
///   owner is created (the claim stays ambiguous: a retry needs a fresh
///   key).
/// - Row absent: the submission transaction never committed (all-or-
///   nothing), so no run and no ownership row exists; the claim stays
///   ambiguous with the generic reconciliation outcome, and a retry with a
///   fresh key re-evaluates live state.
fn reconcile_queue_submission(
    state: &State,
    log: &DaemonLog,
    params: &Val,
) -> Result<(), DaemonError> {
    let digest = params
        .get("digest")
        .and_then(Val::as_str)
        .unwrap_or_default();
    let key = params
        .get("idempotency_key")
        .and_then(Val::as_str)
        .unwrap_or_default();
    if digest.is_empty() || key.is_empty() {
        log.write(
            "warn",
            "reconcile.queue.submit",
            "interrupted submission claim carries no digest/key; there is no commit marker to \
             read back",
        );
        return Ok(());
    }
    let submission_id = crate::queue_executor::submission_id(digest, key);
    let read = state
        .queue_submission_by_id(&submission_id)
        .map_err(|err| {
            daemon_error(
                "daemon.reconcile",
                format!(
                    "queue submission reconciliation: {}: {}",
                    err.code, err.message
                ),
            )
        })?;
    let Some((row, items)) = read else {
        log.write(
            "info",
            "reconcile.queue.submit",
            &format!(
                "interrupted submission {submission_id} never committed; the submission \
                 transaction is all-or-nothing, so no owner or run exists and a retry needs a \
                 fresh idempotency key"
            ),
        );
        return Ok(());
    };
    let recomputed = Val::parse_json(&row.request_line)
        .map(|bound| crate::queue_executor::bound_digest(&bound).unwrap_or_default())
        .unwrap_or_default();
    if recomputed != row.digest {
        log.write(
            "warn",
            "reconcile.queue.submit",
            &format!(
                "committed submission {submission_id} carries a bound-input line that does not \
                 recompute to its recorded digest; the durable rows stay untouched (the \
                 submission is a read-only record, nothing to repair in place)"
            ),
        );
        return Ok(());
    }
    let advances = state
        .queue_advance_rows(&row.submission_id)
        .unwrap_or_default();
    let doc = crate::queue_executor::submission_doc(&row, &items, &advances);
    let mut admitted = 0i64;
    let mut waiting = 0i64;
    let mut refused = 0i64;
    if let Some(Val::Arr(items)) = doc.get("items") {
        for item in items {
            match item.get("status").and_then(Val::as_str) {
                Some("admitted") => admitted += 1,
                Some("waiting") => waiting += 1,
                _ => refused += 1,
            }
        }
    }
    let cursor = doc
        .get("advance")
        .and_then(|advance| advance.get("cursor_ordinal"))
        .and_then(Val::as_int)
        .unwrap_or(0);
    log.write(
        "info",
        "reconcile.queue.submit",
        &format!(
            "submission {submission_id} was committed before the interrupt ({admitted} admitted \
             / {waiting} waiting / {refused} refused, advance cursor {cursor}); the durable \
             readback is verified against its digest binding and no effect is repeated"
        ),
    );
    Ok(())
}

/// Read back one interrupted run-control claim (issue #86). The control's
/// effect is a durable row on the run (`pause_requested`/`paused` for
/// pause and resume, a `run_retries` row for retry), so the readback says
/// whether the control committed — nothing is ever re-executed, repeated
/// or signalled.
fn reconcile_run_control(
    state: &State,
    log: &DaemonLog,
    claim: &crate::state::ClaimRow,
) -> Result<(), DaemonError> {
    let doc = Val::parse_json(&claim.request_line).map_err(|message| {
        daemon_error(
            "daemon.reconcile",
            format!(
                "claim {} has an unreadable request line: {message}",
                claim.key
            ),
        )
    })?;
    let params = doc.get("params").cloned().unwrap_or_else(null);
    let instance_id = params
        .get("instance_id")
        .and_then(Val::as_str)
        .unwrap_or("")
        .to_string();
    if instance_id.is_empty() {
        log.write(
            "warn",
            "reconcile.run-control",
            &format!(
                "claim {} ({}) names no instance; the interrupted control committed nothing",
                claim.key, claim.method
            ),
        );
        return Ok(());
    }
    let run = state.instance_by_id(&instance_id).map_err(|err| {
        daemon_error("daemon.reconcile", format!("{}: {}", err.code, err.message))
    })?;
    let Some(run) = run else {
        log.write(
            "warn",
            "reconcile.run-control",
            &format!(
                "claim {} ({}) targeted run {instance_id}, which no longer exists; the \
                 interrupted control committed nothing",
                claim.key, claim.method
            ),
        );
        return Ok(());
    };
    let committed = match claim.method.as_str() {
        "run.pause" => run.paused || run.pause_requested,
        "run.resume" => !run.paused && !run.pause_requested,
        "run.retry" => state
            .run_retries(&instance_id)
            .map(|rows| !rows.is_empty())
            .unwrap_or(false),
        // The release's own commit marker is the terminal status (the
        // release transaction flips it together with the ownership removal
        // and its `run.release` audit record). A revision rebind sets the
        // same status, so the readback can over-report a release that never
        // committed — it never under-reports, and no control is repeated
        // either way.
        "run.release" => run.status == "invalidated",
        // The retire's own commit marker is the ownership ledger: the
        // retirement removes the leftover rows in the SAME transaction as its
        // `run.retire-lane` audit record, so a run that still holds one did
        // not commit. A terminal run that held none at all over-reports
        // exactly like the release readback — it never under-reports, and no
        // control is repeated either way.
        "run.retire-lane" => state
            .queue_ownership_rows()
            .map(|rows| !rows.iter().any(|row| row.instance_id == instance_id))
            .unwrap_or(false),
        _ => false,
    };
    log.write(
        "warn",
        "reconcile.run-control",
        &format!(
            "claim {} ({}) on run {instance_id}: {} (control state {}, paused {}, \
             pause_requested {}); no control is ever repeated",
            claim.key,
            claim.method,
            if committed {
                "committed before the interrupt"
            } else {
                "never committed"
            },
            crate::run_control::control_state(&run),
            run.paused,
            run.pause_requested
        ),
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Crash-point injection (debug builds only; release ignores the env var)
// ---------------------------------------------------------------------------
/// Canonical crash-point env var and its pre-rename alias (product rename,
/// issue #106): both names are honored so pre-rename test tooling keeps
/// working (docs/contracts/compatibility.md, "Product rename (issue #106)").
const CRASH_POINT_ENV: &str = "CANTER_CRASH_POINT";
const LEGACY_CRASH_POINT_ENV: &str = "HERDR_FLEET_CRASH_POINT";

/// Pick the requested crash point: the canonical env var wins, the
/// pre-rename name is honored as a fallback. Pure so the alias rule is
/// unit-testable without touching this process's environment.
fn crash_point_requested(canonical: Option<&str>, legacy: Option<&str>) -> Option<String> {
    canonical.or(legacy).map(str::to_string)
}

/// Abort the daemon at a named journal boundary. Honored only when
/// `cfg!(debug_assertions)` — release binaries never crash from this hook.
///
/// Reachable from every layer that performs durable fleet work (the daemon
/// handlers and, since issue #98, the queue-advance boundaries inside the
/// state transactions), so the restart/pause acceptance battery can kill the
/// process at an exact durable boundary.
pub(crate) fn crash_point(point: &str) {
    if !cfg!(debug_assertions) {
        return;
    }
    let canonical = std::env::var(CRASH_POINT_ENV).ok();
    let legacy = std::env::var(LEGACY_CRASH_POINT_ENV).ok();
    if crash_point_requested(canonical.as_deref(), legacy.as_deref()).as_deref() == Some(point) {
        eprintln!("canter: crash point {point:?} reached (debug-only test hook)");
        std::process::abort();
    }
}

#[cfg(test)]
#[path = "daemon_retry_tests.rs"]
mod retry_tests;

#[cfg(test)]
#[path = "daemon_renewal_tests.rs"]
mod renewal_tests;

#[cfg(test)]
mod tests {
    use super::*;

    /// Issue #170 (N5): the in-memory collection reservation is keyed by
    /// `(run, step)`. A SECOND collection step of the same run reserves its own
    /// slot — it is never silently answered `awaiting <the other step>` — while
    /// the same step twice is exactly the duplicate the slot exists for, and a
    /// finished collection releases only its own slot.
    #[test]
    fn the_collection_reservation_is_keyed_by_run_and_step() {
        let mut collecting = Collections::default();
        assert_eq!(collecting.begin("run-a", "p5"), Ok(()));
        assert_eq!(
            collecting.begin("run-a", "p5"),
            Err("p5".to_string()),
            "the SAME step twice is the duplicate the slot guards"
        );
        assert_eq!(
            collecting.begin("run-a", "p9"),
            Ok(()),
            "a second collection step of the same run is a different reservation"
        );
        assert_eq!(collecting.begin("run-b", "p5"), Ok(()));
        collecting.finish("run-a", "p5");
        assert_eq!(
            collecting.begin("run-a", "p5"),
            Ok(()),
            "a finished collection releases only its own slot"
        );
        assert_eq!(collecting.begin("run-a", "p9"), Err("p9".to_string()));
    }

    #[test]
    fn crash_point_env_alias_prefers_canonical_and_honors_legacy() {
        // Issue #106: the pre-rename crash-point env var keeps working.
        assert_eq!(crash_point_requested(Some("a"), None).as_deref(), Some("a"));
        assert_eq!(crash_point_requested(None, Some("b")).as_deref(), Some("b"));
        assert_eq!(
            crash_point_requested(Some("a"), Some("b")).as_deref(),
            Some("a"),
            "the canonical name wins when both are set"
        );
        assert_eq!(crash_point_requested(None, None), None);
        assert_eq!(
            CRASH_POINT_ENV, "CANTER_CRASH_POINT",
            "canonical env var name"
        );
        assert_eq!(
            LEGACY_CRASH_POINT_ENV, "HERDR_FLEET_CRASH_POINT",
            "pre-rename env var name"
        );
    }

    /// Issue #224: the kinds whose dispatch resolves the run's issue's
    /// ledger-TERMINAL lane generations are exactly the BIND kinds — the run's
    /// own lane create, the worker's bind in it, and the reviewer leg's own
    /// lane bind. The reviewer leg is the one the measured defect left behind:
    /// an excluded `review_evidence` resolved nothing, so the effect's own
    /// reclaim loop (`ensure_reviewer_lane`) could never retire the previous
    /// generation's registration and the next run of the same issue was
    /// refused `refusal.lane.name_collision` until an operator closed the
    /// workspace by hand. Nothing else resolves the set (a reclaim is a
    /// bind-time authority), so no other kind pays for the state read.
    #[test]
    fn the_bind_kinds_resolve_the_issues_terminal_lane_generations() {
        for kind in ["harness_start", "worktree_create", "review_evidence"] {
            assert!(lane_binding_step_kind(kind), "{kind}");
        }
        for kind in [
            "checkout",
            "prompt",
            "collect_outcome",
            "merge",
            "cleanup",
            "branch_delete",
            "approve",
            "",
        ] {
            assert!(!lane_binding_step_kind(kind), "{kind}");
        }
    }

    /// Issue #224 (AC2, the dispatch half): a reviewer-leg bind's step — and
    /// every other BIND kind — resolves the ledger-TERMINAL generations of the
    /// run's OWN repository issue before the effect runs, and no other kind
    /// resolves anything. This is the half that was missing: `review_evidence`
    /// presented an empty set, so the effect's own reclaim loop had no
    /// authority and the next run of the same issue was refused
    /// `refusal.lane.name_collision` until an operator closed the old
    /// workspace by hand. The live generation is never in the set, and neither
    /// is another issue's or another repository's run.
    #[test]
    fn a_review_steps_dispatch_resolves_the_issues_terminal_lane_generations() {
        use crate::state::{Retention, State};
        let path = std::env::temp_dir().join(format!(
            "canter-224-dispatch-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|elapsed| elapsed.as_nanos())
                .unwrap_or(0)
        ));
        let _ = std::fs::remove_file(&path);
        let state = State::open(&path, Retention::default()).expect("open state");
        let repository = "example-org/widgets";
        let at = "2026-09-25T00:00:00Z";
        let grant_id = "gr_0000000000000224";
        let doc = Val::parse_json(&format!(
            r#"{{"schema":"hf-grant/v1","grant_id":"{grant_id}","repository":"{repository}",
                "issue":{{"number":224,"revision":"{}"}},
                "workflow_hash":"{}","policy_hash":"{}","phase":"merge",
                "scope":"worktrees/issues/224","caps":["read","worktree","spawn","prompt"],
                "expires_at":"2999-01-01T00:00:00Z","state_epoch":1,
                "created_at":"2026-09-25T00:00:00Z"}}"#,
            "a".repeat(40),
            "b".repeat(64),
            "c".repeat(64),
        ))
        .expect("grant document");
        state.issue_grant(&doc).expect("issue grant");
        for run in ["run-0000000000000224a", "run-0000000000000224b"] {
            state
                .start_instance(run, grant_id, "fleet-doctrine-1", at)
                .expect("instance");
        }
        // ONE terminal generation of this issue — the run whose reviewer lane
        // was left behind — while the other run is still live.
        state
            .release_run(
                "run-0000000000000224a",
                "the generation whose reviewer lane was left behind",
                "ik_224-dispatch",
                at,
            )
            .expect("release");

        assert_eq!(
            resolved_lane_generations(&state, repository, 224, "review_evidence").expect("resolve"),
            vec!["run-0000000000000224a".to_string()],
            "the reviewer-leg bind resolves the terminal generation and never the live run"
        );
        assert_eq!(
            resolved_lane_generations(&state, repository, 224, "harness_start").expect("resolve"),
            vec!["run-0000000000000224a".to_string()],
            "the run's own bind resolves the same set"
        );
        assert!(
            resolved_lane_generations(&state, repository, 224, "cleanup")
                .expect("resolve")
                .is_empty(),
            "a step that binds no lane pays for no resolution"
        );
        assert!(
            resolved_lane_generations(&state, repository, 225, "review_evidence")
                .expect("resolve")
                .is_empty(),
            "another issue's runs are never in the set"
        );
        assert!(
            resolved_lane_generations(&state, "example-org/other", 224, "review_evidence")
                .expect("resolve")
                .is_empty(),
            "another repository's runs are never in the set"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn the_supervisor_measures_the_host_for_exactly_the_fanout_steps() {
        // Issue #198: the renewal is scoped to the steps the fan-out
        // admission gate guards (issue #9 AC1) — the spawn kinds plus the
        // reviewer leg of a self-dispatching review step (issue #193, the
        // live `p6-132` shape). Nothing else is measured.
        let step = |kind: &str, params: Val| {
            object(vec![
                ("id", string("s")),
                ("kind", string(kind)),
                ("params", params),
            ])
        };
        for kind in ["harness_start", "prompt"] {
            assert!(fanout_step_kind(&step(kind, Val::Null)), "{kind}");
        }
        assert!(fanout_step_kind(&step(
            "review_evidence",
            object(vec![("reviewer_profile", object(vec![]))])
        )));
        assert!(
            !fanout_step_kind(&step("review_evidence", object(vec![]))),
            "a review step that presents its own facts starts no lane"
        );
        for kind in [
            "checkout",
            "worktree_create",
            "collect_outcome",
            "merge",
            "cleanup",
        ] {
            assert!(!fanout_step_kind(&step(kind, Val::Null)), "{kind}");
        }
    }

    #[test]
    fn a_renewed_admission_supersedes_only_the_lapsed_proof() {
        // Issue #198: the presented admission keeps its caps and occupancy
        // verbatim; only the lapsed proof's instant is superseded.
        let admission = object(vec![
            (
                "caps",
                object(vec![
                    ("global", integer(8)),
                    ("repository", integer(2)),
                    ("harness", integer(2)),
                ]),
            ),
            ("harness_lanes", integer(1)),
            (
                "host_proof",
                object(vec![
                    ("measured_at", string("2026-09-18T08:38:54Z")),
                    ("source", string("operator")),
                ]),
            ),
        ]);
        let renewed = admission_with_renewed_proof(&admission, "2026-09-18T08:59:55Z", 987654321)
            .expect("an object");
        assert_eq!(
            renewed.get("caps"),
            admission.get("caps"),
            "the caps ride along verbatim"
        );
        assert_eq!(renewed.get("harness_lanes"), admission.get("harness_lanes"));
        assert_eq!(
            renewed
                .get("host_proof")
                .and_then(|proof| proof.get("measured_at"))
                .and_then(Val::as_str),
            Some("2026-09-18T08:59:55Z")
        );
        // Issue #231: the dispatch-time measurement supersedes the free-byte
        // observation too, so the gate decides the documented floor on THIS
        // dispatch's measurement (never on a stale attestation).
        assert_eq!(
            renewed
                .get("host_proof")
                .and_then(|proof| proof.get("available_bytes"))
                .and_then(Val::as_int),
            Some(987654321)
        );
        assert_eq!(
            renewed
                .get("host_proof")
                .and_then(|proof| proof.get("source"))
                .and_then(Val::as_str),
            Some("operator"),
            "unknown proof keys are preserved"
        );
        assert_eq!(
            admission_with_renewed_proof(&null(), "2026-09-18T08:59:55Z", 1),
            None,
            "a non-object admission is never rewritten"
        );
    }

    #[test]
    fn abandoned_apply_claim_is_reaped_on_executor_unwind() {
        let root = std::env::temp_dir().join(format!(
            "canter-reap-{}-{}",
            std::process::id(),
            time::unix_now()
        ));
        std::fs::create_dir(&root).unwrap();
        let paths = DaemonPaths {
            state_dir: root.clone(),
            runtime_dir: root.clone(),
            socket_path: root.join("sock"),
            lock_path: root.join("lock"),
            db_path: root.join("state.db"),
            audit_mirror_path: root.join("audit.jsonl"),
            events_mirror_path: root.join("events.jsonl"),
            backups_dir: root.join("backups"),
            checkpoints_dir: root.join("checkpoints"),
            log_path: root.join("daemon.log"),
        };
        let state = Arc::new(Mutex::new(
            State::open(&paths.db_path, crate::state::Retention::default()).unwrap(),
        ));
        let mut supervisor = crate::supervision::start(
            Arc::clone(&state),
            crate::supervision::SupervisorOptions::default(),
        );
        let wake = supervisor.wake_handle();
        wake.signal_stop();
        assert!(supervisor.join());
        let shared = Arc::new(Shared {
            state,
            hub: Mutex::new(Hub::new(0)),
            log: DaemonLog::open(&paths.log_path).unwrap(),
            paths,
            pid: std::process::id(),
            started_at: time::rfc3339_now(),
            running: AtomicBool::new(true),
            supervisor: wake,
        });
        let key = format!("ik_{}", "abandoned");
        let request = Request {
            id: "01234567".to_string(),
            method: "apply".to_string(),
            params: Some(object(vec![
                ("instance_id", string("run-1")),
                ("step", string("r1")),
            ])),
            line: String::new(),
        };
        shared
            .lock_state()
            .unwrap()
            .journal_intent(
                "mutate.review_evidence",
                "run-1:r1",
                &key,
                &request.id,
                &request.method,
                None,
                None,
                &request.line,
            )
            .unwrap();
        let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _claim = ApplyClaim {
                shared: &shared,
                request: &request,
                key: &key,
            };
            assert_eq!(
                shared
                    .lock_state()
                    .unwrap()
                    .claim(&key)
                    .unwrap()
                    .unwrap()
                    .status,
                "claimed",
                "a live executor's claim must not be reclaimed"
            );
            panic!("synthetic executor disappearance outside the state guard");
        }));
        assert!(unwind.is_err());
        let state = shared.lock_state().unwrap();
        let claim = state.claim(&key).unwrap().unwrap();
        assert_eq!(
            claim.status, "ambiguous",
            "abandoned executor must not leave an in-flight claim"
        );
        let outcome = Val::parse_json(claim.outcome.as_deref().unwrap()).unwrap();
        assert_eq!(
            outcome
                .get("error")
                .and_then(|e| e.get("code"))
                .and_then(Val::as_str),
            Some("state.interrupted")
        );
        assert!(state.claims_in_flight().unwrap().is_empty());
        drop(state);
        // A completed claim must remain byte-identical on a later scope exit.
        drop(ApplyClaim {
            shared: &shared,
            request: &request,
            key: &key,
        });
        assert_eq!(
            shared
                .lock_state()
                .unwrap()
                .claim(&key)
                .unwrap()
                .unwrap()
                .outcome,
            claim.outcome
        );
        drop(shared);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn bounded_summary_truncates_at_char_boundary() {
        assert_eq!(bounded("hello", 10), "hello");
        let text = "日本語の長いメッセージです";
        let cut = bounded(text, 10);
        assert!(cut.ends_with('…'));
        assert!(cut.len() <= 10 + "…".len(), "cap plus the ellipsis");
        assert!(text.starts_with(&cut[..cut.len() - "…".len()]));
        assert_eq!(bounded(text, 1000), text);
    }

    #[test]
    fn refusal_codes_are_stable() {
        assert_eq!(refusal_code(Refusal::Parse), "refusal.parse");
        assert_eq!(refusal_code(Refusal::Schema), "refusal.schema");
        assert_eq!(refusal_code(Refusal::Version), "refusal.version");
        assert_eq!(refusal_code(Refusal::Malformed), "refusal.malformed");
        assert_eq!(refusal_code(Refusal::Noncanonical), "refusal.noncanonical");
    }

    #[test]
    fn response_lines_validate_as_rpc_responses() {
        let line = ok_response("0123456789abcdef", object(vec![("ok", bool_(true))]));
        let parsed = Val::parse_json(&line).expect("parse ok response");
        assert!(validate_doc(Family::RpcResponse, &parsed).is_accepted());
        let line = err_response("0123456789abcdef", "refusal.test", "nope");
        let parsed = Val::parse_json(&line).expect("parse error response");
        assert!(validate_doc(Family::RpcResponse, &parsed).is_accepted());
    }

    #[test]
    fn daemon_outcome_docs_validate() {
        for (status, error) in [
            ("ambiguous", error_val("state.interrupted", "msg")),
            ("failed", error_val("refusal.effect", "msg")),
            ("succeeded", null()),
        ] {
            let doc = daemon_outcome("ik_outcome-00000001", status, error);
            let verdict = validate_doc(Family::Outcome, &doc);
            assert!(verdict.is_accepted(), "{status}: {}", verdict.message());
        }
    }

    #[test]
    fn fallback_request_id_is_schema_valid() {
        assert!(crate::formats::is_request_id(FALLBACK_REQUEST_ID));
    }

    fn f10_dispatch_material() -> DispatchMaterial {
        let instance = crate::state::InstanceRow {
            instance_id: "run-0123456789abcdef".to_string(),
            repository: "acme/widgets".to_string(),
            workflow_id: crate::plan::DOCTRINE_WORKFLOW_ID.to_string(),
            workflow_hash: "a".repeat(64),
            policy_hash: "b".repeat(64),
            grant_id: "gr_0123456789abcdef".to_string(),
            issue_number: 5,
            issue_revision: "c".repeat(40),
            phase: "implement".to_string(),
            scope: "worktrees/issues/5".to_string(),
            caps: "[]".to_string(),
            current_node: "p5-5".to_string(),
            normal_rounds: 0,
            recovery_rounds: 0,
            human_queue: false,
            terminal_blockers: 0,
            paused: false,
            resume_digest: String::new(),
            pause_requested: false,
            pause_reason: String::new(),
            pause_requested_at: String::new(),
            state_epoch: 1,
            status: "running".to_string(),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            updated_at: "2026-01-01T00:00:00Z".to_string(),
        };
        let steps: Vec<Val> = crate::plan::queue_run_steps(
            "acme/widgets",
            "staging",
            "worker",
            None,
            &[5],
            crate::adapters::ExecutionMode::HerdrPane,
        )
        .into_iter()
        .map(|step| {
            object(vec![
                ("id", string(&step.id)),
                ("kind", string(&step.kind)),
                ("params", step.params.unwrap_or_else(null)),
            ])
        })
        .collect();
        DispatchMaterial {
            instance,
            spine: steps
                .iter()
                .filter_map(|step| step.get("id").and_then(Val::as_str))
                .map(str::to_string)
                .collect(),
            steps,
            topology: object(vec![
                ("integration_branch", string("staging")),
                ("production_branches", Val::Arr(vec![string("main")])),
                ("integration_repo", string("/tmp/integration")),
                ("worktrees_root", string("/tmp/worktrees")),
            ]),
            profile: None,
            admission: None,
            feature_head: Some("d".repeat(40)),
            integration_base: Some("e".repeat(40)),
        }
    }

    #[test]
    fn f10_supervision_preflight_skips_incomplete_params_and_accepts_complete_params() {
        let material = f10_dispatch_material();
        let incomplete = dispatch_request_from(&material, "p6-5", None, "ik_f10-incomplete")
            .expect("incomplete request remains constructible");
        let (code, message) = preflight_apply_request(&incomplete).expect_err("must refuse");
        assert_eq!(code, "refusal.request.malformed");
        assert!(message.contains("reviewer"), "{message}");

        let complete_params = object(vec![
            ("reviewer", string("reviewer")),
            ("implementer", string("worker")),
            ("verdict", string("pass")),
            (
                "checks",
                Val::Arr(vec![object(vec![
                    ("name", string("focused")),
                    ("status", string("passed")),
                ])]),
            ),
        ]);
        let complete =
            dispatch_request_from(&material, "p6-5", Some(&complete_params), "ik_f10-complete")
                .expect("complete request");
        preflight_apply_request(&complete).expect("contracts-complete continuation");
    }

    #[test]
    fn event_stream_write_timeout_closes_a_stalled_socket() {
        use std::io::Read;

        let (mut writer, mut reader) = UnixStream::pair().expect("socket pair");
        let payload_bytes = 8 * 1024 * 1024;
        let payload = "x".repeat(payload_bytes);
        let (sender, receiver) = sync_channel(1);
        let worker = std::thread::spawn(move || {
            let result = configure_event_writer(&writer)
                .and_then(|()| write_event_line(&mut writer, &payload));
            sender.send(result).expect("report writer result");
        });

        let result = match receiver
            .recv_timeout(EVENT_STREAM_WRITE_TIMEOUT + std::time::Duration::from_secs(2))
        {
            Ok(result) => result,
            Err(error) => {
                drop(reader);
                worker.join().expect("join blocked writer after peer close");
                panic!("event-stream writer remained blocked beyond its bound: {error}");
            }
        };
        worker.join().expect("join bounded writer");
        let error = result.expect_err("a non-draining peer must time out the write");
        assert!(error.contains("write event:"), "{error}");

        let mut prefix = Vec::new();
        reader
            .read_to_end(&mut prefix)
            .expect("closed peer reaches EOF");
        assert!(!prefix.is_empty(), "the socket accepted a bounded prefix");
        assert!(
            prefix.len() < payload_bytes + 1,
            "the stalled socket unexpectedly accepted the whole event"
        );
    }

    #[test]
    fn event_queue_cap_is_bounded() {
        assert!((1..=256).contains(&SUBSCRIBER_QUEUE_CAP));
    }
}
