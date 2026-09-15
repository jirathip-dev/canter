//! Issue #97 acceptance tests: the compact supervision status and the guarded
//! continuation controls over the REAL daemon.
//!
//! Every test drives the real `canter::tui::operator` console (the surface the
//! `canter board` binary runs) against a spawned `canter daemon run` child on
//! an explicit socket, exactly like `tests/tui_operator.rs`:
//!
//! - the status read is the daemon's own typed `supervision.status` service and
//!   is compared against the SAME document an independent client reads;
//! - the controls send the CLI's own `run.pause`/`run.resume` params documents
//!   ([`canter::run_control::pause_params`]/[`resume_params`]) over the socket,
//!   and the durable rows are read back from the state store;
//! - a recording peer socket captures the EXACT method and params document of
//!   every keyboard path, so "no keyboard path arms supervision or advances a
//!   gated run" is proven at the wire, not by reading the source;
//! - a real pseudo-terminal runs the real `canter board` binary and holds a run
//!   with real key bytes.
//!
//! Synthetic identities only.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use canter::client::Connection;
use canter::config::Config;
use canter::lifecycle::ConcurrencyCaps;
use canter::plan::DOCTRINE_WORKFLOW_ID;
use canter::queue_executor as qx;
use canter::queue_preview as qp;
use canter::run_control;
use canter::state::{Retention, State};
use canter::supervision;
use canter::tui::operator::{AttemptOutcome, OperatorConsole, PresentedRun, Screen};
use canter::tui::supervision::{ControlEffect, PAUSE_REASON};
use canter::value::{Val, object, string};
use ratatui::Terminal;
use ratatui::backend::TestBackend;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyEventKind};

// ---------------------------------------------------------------------------
// Constants and builders (synthetic identities only)
// ---------------------------------------------------------------------------

const REPO: &str = "example-org/widgets";
const REVISION: &str = "1111111111111111111111111111111111111111";
const WORKFLOW_HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const POLICY_HASH: &str = "feedface01234567feedface01234567feedface01234567feedface01234567";

fn config() -> Config {
    Config {
        path: PathBuf::from("canter.toml"),
        daemon_enabled: None,
        daemon_socket: None,
        policy: None,
        repositories: Vec::new(),
        harnesses: vec![canter::config::Harness {
            key: "lane-1".to_string(),
            kind: "argv".to_string(),
            executable: "fixture-harness".to_string(),
            env_allow: Vec::new(),
            provider: Some("provider-a".to_string()),
            model: Some("model-a".to_string()),
            fallback: Vec::new(),
            secret_env: Vec::new(),
            limits: Vec::new(),
            binding_introspection: false,
        }],
        workflows: Vec::new(),
    }
}

fn caps() -> ConcurrencyCaps {
    ConcurrencyCaps {
        global: 4,
        per_repository: 2,
        per_harness: 2,
    }
}

/// The reviewed role binding exactly as the configuration re-observes it.
fn binding_doc() -> Val {
    canter::config::ProfileBinding::from_config(
        &config(),
        "lane-1",
        &std::collections::BTreeMap::new(),
    )
    .expect("binding re-observes")
    .to_doc()
}

fn role_revision() -> String {
    binding_doc()
        .get("revision")
        .and_then(Val::as_str)
        .expect("binding revision")
        .to_string()
}

fn request() -> qp::QueueRequest {
    qp::QueueRequest {
        repository: REPO.to_string(),
        host: "host-1".to_string(),
        host_available: Some(true),
        harness_key: "lane-1".to_string(),
        harness_lanes: Some(0),
        caps: caps(),
        workflow_id: DOCTRINE_WORKFLOW_ID.to_string(),
        workflow_hash: WORKFLOW_HASH.to_string(),
        role_config: binding_doc(),
        boundary: qp::Boundary {
            phase: "merge".to_string(),
            integration_branch: "staging".to_string(),
            completion_branch: "staging".to_string(),
            caps: vec!["read".to_string(), "merge".to_string()],
        },
        steps: vec![qp::PlannedStep {
            id: "p1".to_string(),
            kind: "checkout".to_string(),
            params: Some(object(vec![("ref", string("staging"))])),
        }],
        selected: vec![qp::SelectedIssue {
            id: "5".to_string(),
            title: None,
            revision: REVISION.to_string(),
            requires: Vec::new(),
        }],
    }
}

fn grant_id() -> String {
    format!(
        "gr_{}",
        &canter::canonical::sha256_hex(b"supervision-97-grant")[..16]
    )
}

fn grant_doc(epoch: i64) -> Val {
    Val::parse_json(&format!(
        r#"{{"schema":"hf-grant/v1","grant_id":"{id}","repository":"{REPO}",
            "issue":{{"number":5,"revision":"{REVISION}"}},
            "workflow_hash":"{WORKFLOW_HASH}","policy_hash":"{POLICY_HASH}",
            "phase":"merge","scope":"worktrees/issues/5",
            "caps":["read","worktree","spawn","review","merge"],
            "expires_at":"2999-01-01T00:00:00Z","state_epoch":{epoch},
            "created_at":"2026-09-06T00:00:00Z"}}"#,
        id = grant_id()
    ))
    .expect("grant document")
}

/// The reviewed bound-input document exactly as the preview service renders it.
fn bound(state: &State) -> Val {
    qp::preview_queue(state, &request())
        .expect("preview renders")
        .doc
        .get("request")
        .cloned()
        .expect("bound-input document")
}

/// The reported-done run the #91 fixture uses: the issue is free for a fresh
/// attempt while the board still shows a recorded row.
const SEEDED_RUN: &str = "run-seeded-0001";

/// The reviewed plan the operator console presents (the same material the CLI's
/// `queue submit --request` reads).
fn presented(state: &State) -> PresentedRun {
    let mut run = PresentedRun::new("reviewed-run-plan", bound(state), caps());
    run.host_available = Some(true);
    run.harness_lanes = Some(0);
    run.grants = vec![qx::ItemGrant {
        id: "5".to_string(),
        grant_id: grant_id(),
    }];
    run
}

/// The `queue.submit` params document with the ARMED supervision
/// authorization (the CLI's own `--supervise arm` shape, built by the shared
/// service — never hand-assembled).
fn submit_params_doc(key: &str, bound: &Val, digest: &str, interval: i64, timeout: i64) -> Val {
    let grants = vec![qx::ItemGrant {
        id: "#5".to_string(),
        grant_id: grant_id(),
    }];
    qx::submit_params(
        key,
        digest,
        1,
        bound,
        &binding_doc(),
        &role_revision(),
        caps(),
        Some(true),
        Some(0),
        &grants,
        &[],
        Some(&supervision::Authorization {
            desired: "armed".to_string(),
            policy: supervision::Policy {
                check_interval_secs: interval,
                progress_timeout_secs: timeout,
            },
        }),
    )
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("hf-supervision-97-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("fixture dir");
    dir
}

struct Fixture {
    dir: PathBuf,
    state_dir: PathBuf,
    socket: PathBuf,
}

impl Fixture {
    fn new(name: &str) -> Fixture {
        let dir = temp_dir(name);
        Fixture {
            state_dir: dir.join("state"),
            socket: dir.join("daemon.sock"),
            dir,
        }
    }

    fn db(&self) -> PathBuf {
        self.state_dir.join("canter").join("state.db")
    }

    fn seed(&self) -> State {
        std::fs::create_dir_all(self.state_dir.join("canter")).expect("state dir");
        let state = State::open(&self.db(), Retention::default()).expect("open state");
        let epoch = state.current_epoch().expect("epoch");
        state.issue_grant(&grant_doc(epoch)).expect("issue grant");
        state
    }

    fn open(&self) -> State {
        State::open(&self.db(), Retention::default()).expect("open state")
    }

    /// Seed the reported-done run the #91 fixture uses (no public API writes
    /// `done` yet), so the issue is free for a fresh attempt.
    fn seed_done_run(&self, state: &State) {
        state
            .start_instance(
                SEEDED_RUN,
                &grant_id(),
                DOCTRINE_WORKFLOW_ID,
                "2026-09-06T00:00:00Z",
            )
            .expect("start instance");
        let raw = rusqlite::Connection::open(self.db()).expect("raw open");
        raw.execute(
            "UPDATE instances SET status = 'done', current_node = 'merge', updated_at = ?2
              WHERE instance_id = ?1",
            rusqlite::params![SEEDED_RUN, "2026-09-06T00:00:05Z"],
        )
        .expect("seed reported done");
    }

    fn spawn(&self) -> Child {
        std::fs::create_dir_all(&self.state_dir).expect("state home");
        Command::new(env!("CARGO_BIN_EXE_canter"))
            .args(["daemon", "run", "--socket"])
            .arg(&self.socket)
            .env("XDG_STATE_HOME", &self.state_dir)
            .env("HOME", &self.dir)
            .stdout(Stdio::null())
            .stderr(Stdio::from(
                std::fs::File::create(self.dir.join("daemon.stderr.log")).expect("stderr log"),
            ))
            .spawn()
            .expect("spawn daemon")
    }

    /// Submit ONE armed run through the daemon's real `queue.submit` and return
    /// its admitted instance id.
    fn submit_armed(&self, state: &State, stem: &str, interval: i64, timeout: i64) -> String {
        let document = bound(state);
        let digest = qp::digest_of(&document);
        let submitted = rpc_ok(
            &self.socket,
            &format!("9{:07x}", 1),
            "queue.submit",
            Some(&submit_params_doc(
                &format!("ik_97-{stem}"),
                &document,
                &digest,
                interval,
                timeout,
            )),
        );
        item_of(&submitted, 5)
            .get("instance_id")
            .and_then(Val::as_str)
            .expect("the armed run was admitted")
            .to_string()
    }
}

fn wait_ready(fixture: &Fixture) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if canter::lock::socket_presence(&fixture.socket) == canter::lock::SocketPresence::Active {
            let ok = Connection::open(&fixture.socket)
                .and_then(|mut connection| {
                    connection.send_request("aaaaaaaaaaaaaaaa", "status", None)?;
                    connection.read_response()
                })
                .map(|response| response.ok)
                .unwrap_or(false);
            if ok {
                return;
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let stderr = std::fs::read_to_string(fixture.dir.join("daemon.stderr.log")).unwrap_or_default();
    panic!(
        "daemon did not become ready on {}; stderr:\n{stderr}",
        fixture.socket.display()
    );
}

fn shutdown(mut daemon: Child) {
    let _ = daemon.kill();
    let deadline = Instant::now() + Duration::from_secs(10);
    while daemon.try_wait().expect("try_wait").is_none() {
        assert!(Instant::now() < deadline, "daemon did not exit");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Wait until the daemon's OWN driver committed at least one check for `run`
/// and return that `supervision.status` document (read with an independent
/// client).
fn wait_for_committed_check(fixture: &Fixture, run: &str) -> Val {
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut last = None;
    while Instant::now() < deadline {
        let doc = rpc_ok(
            &fixture.socket,
            "b0000001",
            "supervision.status",
            Some(&supervision::status_params(run)),
        );
        let checks = int_at(&doc, &["evaluation", "checks"]);
        last = Some(doc);
        if checks.is_some_and(|checks| checks >= 1) {
            return last.expect("status doc");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("no committed check observed; last status: {last:?}");
}

// ---------------------------------------------------------------------------
// RPC helpers
// ---------------------------------------------------------------------------

fn rpc(socket: &Path, id: &str, method: &str, params: Option<&Val>) -> Val {
    let mut connection = Connection::open(socket).expect("connect");
    connection
        .send_request(id, method, params)
        .expect("send request");
    let response = connection.read_response().expect("read response");
    if response.ok {
        object(vec![("ok", Val::Bool(true)), ("result", response.result)])
    } else {
        let error = response.error.unwrap_or_else(|| canter::client::RpcError {
            code: "missing.error".to_string(),
            message: "no error doc".to_string(),
        });
        object(vec![
            ("ok", Val::Bool(false)),
            (
                "error",
                object(vec![
                    ("code", string(&error.code)),
                    ("message", string(&error.message)),
                ]),
            ),
        ])
    }
}

fn rpc_ok(socket: &Path, id: &str, method: &str, params: Option<&Val>) -> Val {
    let doc = rpc(socket, id, method, params);
    assert_eq!(
        doc.get("ok").and_then(Val::as_bool),
        Some(true),
        "expected ok for {method}: {}",
        canter::canonical::canonical_text(&doc)
    );
    doc.get("result").expect("result").clone()
}

fn item_of(doc: &Val, number: i64) -> Val {
    let target = format!("{REPO}#{number}");
    doc.get("items")
        .and_then(Val::as_array)
        .expect("items")
        .iter()
        .find(|item| item.get("id").and_then(Val::as_str) == Some(target.as_str()))
        .cloned()
        .unwrap_or_else(|| {
            panic!(
                "item {target} present: {}",
                canter::canonical::canonical_text(doc)
            )
        })
}

fn text_at(doc: &Val, keys: &[&str]) -> Option<String> {
    let mut current = doc;
    for key in keys {
        current = current.get(key)?;
    }
    current.as_str().map(str::to_string)
}

fn int_at(doc: &Val, keys: &[&str]) -> Option<i64> {
    let mut current = doc;
    for key in keys {
        current = current.get(key)?;
    }
    current.as_int()
}

fn bool_at(doc: &Val, keys: &[&str]) -> Option<bool> {
    let mut current = doc;
    for key in keys {
        current = current.get(key)?;
    }
    current.as_bool()
}

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::from(code)
}

/// The key set of one recorded params object (sorted by the BTreeMap).
fn object_keys(value: &Val) -> Vec<String> {
    match value {
        Val::Obj(map) => map.keys().cloned().collect(),
        other => panic!("expected a params object, got {other:?}"),
    }
}

fn key_of(code: KeyCode, kind: KeyEventKind) -> KeyEvent {
    let mut event = KeyEvent::from(code);
    event.kind = kind;
    event
}

fn lines_of(console: &OperatorConsole<'_>, width: usize) -> String {
    console
        .lines(width)
        .into_iter()
        .map(|line| line.text)
        .collect::<Vec<_>>()
        .join("\n")
}

fn render_text(console: &OperatorConsole<'_>, size: (u16, u16)) -> String {
    let mut terminal = Terminal::new(TestBackend::new(size.0, size.1)).expect("test terminal");
    terminal
        .draw(|frame| canter::tui::operator::draw(console, canter::tui::ColorMode::Mono, frame))
        .expect("draw");
    let buffer = terminal.backend().buffer();
    let area = *buffer.area();
    (0..area.height)
        .map(|y| {
            let line: String = (0..area.width)
                .map(|x| buffer[(x, y)].symbol().to_string())
                .collect();
            line.trim_end().to_string()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// A console over `fixture`, with the FIRST recorded run selected.
fn console_with_selection<'a>(fixture: &'a Fixture, state: &'a State) -> OperatorConsole<'a> {
    let mut console = OperatorConsole::new(state, fixture.socket.clone(), Some(config()), None);
    console.handle_key(key(KeyCode::Down));
    assert!(
        console.selected_run().is_some(),
        "a recorded run is selectable on the board"
    );
    console
}

// ---------------------------------------------------------------------------
// 1. The compact status reads the real recorded supervision state
// ---------------------------------------------------------------------------

#[test]
fn the_compact_status_reads_the_real_recorded_supervision_state() {
    let fixture = Fixture::new("status");
    let daemon = fixture.spawn();
    wait_ready(&fixture);
    let state = fixture.seed();
    let run = fixture.submit_armed(&state, "status", 5, 60);
    let daemon_doc = wait_for_committed_check(&fixture, &run);

    let mut console = console_with_selection(&fixture, &state);
    assert_eq!(console.selected_run().as_deref(), Some(run.as_str()));
    // THE keystroke path to the status: `s`.
    console.handle_key(key(KeyCode::Char('s')));
    assert_eq!(console.screen(), Screen::Supervision);
    let view = console
        .supervision()
        .view()
        .expect("status was read")
        .clone();
    assert!(view.read, "the daemon's typed service answered");
    assert_eq!(view.run, run);
    assert_eq!(view.desired, "armed");
    assert_eq!(
        view.class_code,
        text_at(&daemon_doc, &["evaluation", "class"]).expect("recorded class"),
        "the panel renders the daemon's recorded class verbatim"
    );
    assert_eq!(
        view.reason,
        text_at(&daemon_doc, &["evaluation", "reason"]).expect("recorded reason")
    );
    assert_eq!(
        view.checks,
        int_at(&daemon_doc, &["evaluation", "checks"]).expect("recorded checks")
    );
    assert_eq!(
        view.continuation.open,
        text_at(&daemon_doc, &["evaluation", "continuation", "state"]).as_deref() == Some("open")
    );
    assert_eq!(
        view.eligible,
        bool_at(&daemon_doc, &["evaluation", "eligible"]).expect("recorded eligible")
    );
    assert!(
        view.trusted(),
        "a committed check with fresh evidence is trusted: {view:?}"
    );
    assert_eq!(
        view.class_slot(),
        view.class.code(),
        "fresh committed evidence reads its recorded class"
    );
    // The compact status carries every field the brief names.
    let text = lines_of(&console, 220);
    for needle in [
        "SUPERVISION",
        "status: ",
        "reason: ",
        "blocked reason:",
        "evidence: ",
        "last check: ",
        "next eligible check: ",
        "continuation window: ",
        "authorization: armed",
        "run control: ",
        &format!("run: {run}"),
    ] {
        assert!(text.contains(needle), "{needle} missing from:\n{text}");
    }
    assert!(
        text.contains(&view.class_code),
        "the recorded class is displayed: {text}"
    );

    // Back to the board: the SAME selection now carries the compact strip (a
    // one-line status, never a second contradicting reading).
    console.handle_key(key(KeyCode::Esc));
    assert_eq!(console.screen(), Screen::Board);
    let strip = console
        .supervision()
        .strip(console.selected_run().as_deref(), 200);
    assert!(strip.text.starts_with("supervision: "), "{}", strip.text);
    assert!(strip.text.contains(&view.class_slot()), "{}", strip.text);
    let frame = render_text(&console, (120, 40));
    assert!(frame.contains("supervision: "), "{frame}");
    // Positive control for the no-arm test below: the CLI-armed submission
    // this fixture presents DOES record a supervision row through the same
    // services, so an empty table there is a real statement.
    assert!(
        !state
            .supervision_rows()
            .expect("supervision rows")
            .is_empty(),
        "the armed submission records the authorization"
    );

    shutdown(daemon);
}

// ---------------------------------------------------------------------------
// 1b. The operator submit path never arms supervision on the operator's behalf
// ---------------------------------------------------------------------------

#[test]
fn the_operator_submit_path_never_arms_supervision_on_the_operators_behalf() {
    let fixture = Fixture::new("no-arm");
    let daemon = fixture.spawn();
    wait_ready(&fixture);
    let state = fixture.seed();
    fixture.seed_done_run(&state);
    assert!(
        state
            .supervision_rows()
            .expect("supervision rows")
            .is_empty(),
        "no supervision exists before any submission"
    );

    let mut console = OperatorConsole::new(
        &state,
        fixture.socket.clone(),
        Some(config()),
        Some(presented(&state)),
    );
    console.handle_key(key(KeyCode::Down));
    console.handle_key(key(KeyCode::Char('p')));
    assert_eq!(console.screen(), Screen::Preview, "{:?}", console.notice());
    console.handle_key(key(KeyCode::Enter));
    assert_eq!(console.screen(), Screen::Authorize);
    console.handle_key(key(KeyCode::Char(' ')));
    console.handle_key(key(KeyCode::Enter));
    assert_eq!(console.screen(), Screen::Outcome, "{:?}", console.notice());
    let attempt = console.attempt().expect("the console submitted").clone();
    let doc = attempt
        .outcome
        .observed_doc()
        .expect("the daemon confirmed the submission")
        .clone();
    let admitted = item_of(&doc, 5)
        .get("instance_id")
        .and_then(Val::as_str)
        .expect("the submission admitted the run")
        .to_string();

    // The hard rule: the operator surface does not arm the supervised
    // reconciliation driver on the operator's behalf. The admitted run is
    // real, and its submission recorded NO supervision authorization — the
    // CLI's `--supervise arm` remains the only arming point.
    assert!(
        state
            .supervision_rows()
            .expect("supervision rows")
            .is_empty(),
        "the operator submission must not arm supervision"
    );
    assert!(
        state
            .supervision_by_id(&admitted)
            .expect("supervision read")
            .is_none(),
        "the admitted run carries no supervision record"
    );

    shutdown(daemon);
}

// ---------------------------------------------------------------------------
// 2. Each guarded control reaches the real typed service
// ---------------------------------------------------------------------------

#[test]
fn each_guarded_control_reaches_the_real_typed_service() {
    let fixture = Fixture::new("controls");
    let daemon = fixture.spawn();
    wait_ready(&fixture);
    let state = fixture.seed();
    let run = fixture.submit_armed(&state, "controls", 5, 60);
    wait_for_committed_check(&fixture, &run);

    let mut console = console_with_selection(&fixture, &state);
    console.handle_key(key(KeyCode::Char('s')));
    assert_eq!(console.screen(), Screen::Supervision);
    assert!(
        console.supervision().pause_availability().enabled(),
        "{:?}",
        console.supervision().pause_availability()
    );

    // --- the HOLD path: h (request) -> Space (box) -> Enter (commit) --------
    println!("keystroke path: j s h SPACE ENTER  (hold {run})");
    console.handle_key(key(KeyCode::Char('h')));
    assert!(console.supervision().confirming());
    assert!(!console.supervision().checked());
    console.handle_key(key(KeyCode::Char(' ')));
    assert!(console.supervision().checked());
    console.handle_key(key(KeyCode::Enter));
    let attempt = console
        .supervision()
        .attempt()
        .cloned()
        .expect("the boxed Enter reached run.pause");
    assert_eq!(attempt.requested.effect, ControlEffect::Pause);
    assert_eq!(attempt.requested.run, run);
    assert_eq!(attempt.requested.reason.as_deref(), Some(PAUSE_REASON));
    let doc = attempt
        .outcome
        .observed_doc()
        .expect("the daemon confirmed the pause")
        .clone();
    // The daemon commits the request immediately; when no step is in flight
    // the recorded boundary is already reached, so `paused` is legal too.
    let recorded = text_at(&doc, &["control", "state"]).unwrap_or_default();
    assert!(
        recorded == "pause_requested" || recorded == "paused",
        "the daemon recorded the hold: {}",
        canter::canonical::canonical_text(&doc)
    );
    // The durable row is the daemon's own: the request is recorded with the
    // surface's bounded reason.
    let row = state
        .instance_by_id(&run)
        .expect("instance read")
        .expect("the run exists");
    assert!(
        row.pause_requested || row.paused,
        "the hold is durable: {row:?}"
    );
    assert_eq!(row.pause_reason, PAUSE_REASON);
    // An INDEPENDENT client reads the same control state back.
    let control = rpc_ok(
        &fixture.socket,
        "b0000002",
        "run.status",
        Some(&run_control::status_params(&run)),
    );
    assert_eq!(
        text_at(&control, &["control", "state"]).as_deref(),
        Some(recorded.as_str())
    );

    // --- the CONTINUE path: u (request) -> Space (box) -> Enter (commit) ----
    let digest = console
        .supervision()
        .control()
        .and_then(|control| control.resume_digest.clone())
        .expect("the recorded resume digest is visible after the hold");
    assert!(
        console.supervision().resume_availability().enabled(),
        "{:?}",
        console.supervision().resume_availability()
    );
    println!("keystroke path: u SPACE ENTER  (continue {run} with digest {digest})");
    console.handle_key(key(KeyCode::Char('u')));
    assert!(console.supervision().confirming());
    console.handle_key(key(KeyCode::Char(' ')));
    console.handle_key(key(KeyCode::Enter));
    let attempt = console
        .supervision()
        .attempt()
        .cloned()
        .expect("the boxed Enter reached run.resume");
    assert_eq!(attempt.requested.effect, ControlEffect::Resume);
    assert_eq!(attempt.requested.digest.as_deref(), Some(digest.as_str()));
    let doc = attempt
        .outcome
        .observed_doc()
        .expect("the daemon confirmed the resume")
        .clone();
    assert_eq!(
        text_at(&doc, &["control", "state"]).as_deref(),
        Some("active"),
        "{}",
        canter::canonical::canonical_text(&doc)
    );
    let row = state
        .instance_by_id(&run)
        .expect("instance read")
        .expect("the run exists");
    assert!(!row.pause_requested && !row.paused, "the pause is lifted");
    assert!(row.resume_digest.is_empty(), "the digest is consumed");

    shutdown(daemon);
}

// ---------------------------------------------------------------------------
// 3. No keyboard path arms supervision or advances a gated run (wire proof)
// ---------------------------------------------------------------------------

/// A recording peer: replies to the two reads with the surface's own canned
/// documents and records every request line (method + params).
struct RecordingPeer {
    socket: PathBuf,
    records: Arc<Mutex<Vec<(String, Val)>>>,
    digest: String,
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl RecordingPeer {
    fn start(dir: &Path, drop_effects: bool) -> RecordingPeer {
        let socket = dir.join("peer.sock");
        let listener = UnixListener::bind(&socket).expect("bind peer socket");
        listener.set_nonblocking(true).expect("nonblocking");
        let records = Arc::new(Mutex::new(Vec::new()));
        let digest = "cd".repeat(32);
        let stop = Arc::new(AtomicBool::new(false));
        let paused = Arc::new(AtomicBool::new(false));
        let state = PeerState {
            records: records.clone(),
            digest: digest.clone(),
            paused: paused.clone(),
            drop_effects,
        };
        let stop_for_thread = stop.clone();
        let handle = std::thread::spawn(move || {
            while !stop_for_thread.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => peer_serve(stream, &state),
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        RecordingPeer {
            socket,
            records,
            digest,
            stop,
            handle: Some(handle),
        }
    }

    fn methods(&self) -> Vec<String> {
        self.records
            .lock()
            .expect("records")
            .iter()
            .map(|(method, _)| method.clone())
            .collect()
    }

    fn params_of(&self, method: &str) -> Vec<Val> {
        self.records
            .lock()
            .expect("records")
            .iter()
            .filter(|(recorded, _)| recorded == method)
            .map(|(_, params)| params.clone())
            .collect()
    }
}

impl Drop for RecordingPeer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

struct PeerState {
    records: Arc<Mutex<Vec<(String, Val)>>>,
    digest: String,
    paused: Arc<AtomicBool>,
    drop_effects: bool,
}

/// One request line in, one response line out (or a dropped connection for the
/// unconfirmed class).
fn peer_serve(stream: std::os::unix::net::UnixStream, state: &PeerState) {
    let mut reader = BufReader::new(stream.try_clone().expect("peer clone"));
    let mut line = String::new();
    if reader.read_line(&mut line).unwrap_or(0) == 0 {
        return;
    }
    let request = Val::parse_json(line.trim()).expect("peer parses the request line");
    let id = request
        .get("id")
        .and_then(Val::as_str)
        .unwrap_or("00000000")
        .to_string();
    let method = request
        .get("method")
        .and_then(Val::as_str)
        .unwrap_or("")
        .to_string();
    let params = request
        .get("params")
        .cloned()
        .unwrap_or_else(canter::value::null);
    state
        .records
        .lock()
        .expect("records")
        .push((method.clone(), params));
    if method == "run.pause" {
        state.paused.store(true, Ordering::SeqCst);
    }
    if method == "run.resume" {
        state.paused.store(false, Ordering::SeqCst);
    }
    if method == "run.pause" && state.drop_effects {
        // Accept and drop: the effect is unconfirmed by the peer.
        return;
    }
    let result = match method.as_str() {
        "run.status" => peer_control_doc("run-0011223344556677", &state.paused, &state.digest),
        "supervision.status" => peer_status_doc(),
        "run.pause" => peer_control_doc("run-0011223344556677", &state.paused, &state.digest),
        "run.resume" => peer_control_doc("run-0011223344556677", &state.paused, &state.digest),
        _ => object(vec![]),
    };
    let response = object(vec![
        ("schema", string("hf-rpc-response/v1")),
        ("id", string(&id)),
        ("ok", Val::Bool(true)),
        ("result", result),
        ("error", canter::value::null()),
    ]);
    let mut text = canter::canonical::canonical_text(&response);
    text.push('\n');
    let mut writer = &stream;
    let _ = writer.write_all(text.as_bytes());
    let _ = writer.flush();
}

fn peer_control_doc(run: &str, paused: &AtomicBool, digest: &str) -> Val {
    let paused = paused.load(Ordering::SeqCst);
    object(vec![
        ("schema", string("hf-run-control/v1")),
        (
            "run",
            object(vec![
                ("instance_id", string(run)),
                ("status", string("running")),
            ]),
        ),
        (
            "control",
            object(vec![
                (
                    "state",
                    string(if paused { "pause_requested" } else { "active" }),
                ),
                ("pause_requested", Val::Bool(paused)),
                ("paused", Val::Bool(false)),
                ("reason", string(if paused { "operator hold" } else { "" })),
                ("requested_at", string("2026-09-13T00:00:00Z")),
                (
                    "resume_digest",
                    if paused {
                        string(digest)
                    } else {
                        canter::value::null()
                    },
                ),
            ]),
        ),
        (
            "boundary",
            object(vec![
                ("reached", Val::Bool(false)),
                ("in_flight_step", canter::value::null()),
            ]),
        ),
    ])
}

fn peer_status_doc() -> Val {
    object(vec![
        ("schema", string("hf-supervision/v1")),
        (
            "run",
            object(vec![
                ("instance_id", string("run-0011223344556677")),
                ("status", string("running")),
            ]),
        ),
        (
            "supervision",
            object(vec![
                ("id", string("su_0011223344556677")),
                ("desired", string("armed")),
                (
                    "authorization",
                    object(vec![
                        ("approved_boundary", string("staging")),
                        ("bound", string("bound")),
                    ]),
                ),
                (
                    "policy",
                    object(vec![
                        ("check_interval_secs", canter::value::integer(60)),
                        ("progress_timeout_secs", canter::value::integer(900)),
                        ("freshness_secs", canter::value::integer(360)),
                    ]),
                ),
            ]),
        ),
        (
            "evaluation",
            object(vec![
                ("class", string("healthy")),
                ("reason", string("supervision.recent_progress")),
                ("eligible", Val::Bool(false)),
                ("detail", string("p2")),
                (
                    "observed",
                    object(vec![
                        ("class", string("healthy")),
                        ("reason", string("supervision.recent_progress")),
                        ("eligible", Val::Bool(false)),
                        ("detail", string("p2")),
                    ]),
                ),
                ("checks", canter::value::integer(2)),
                (
                    "last_check",
                    object(vec![
                        ("at", string("2026-09-13T00:00:00Z")),
                        ("class", string("healthy")),
                        ("reason", string("supervision.recent_progress")),
                        ("trigger", string("timer")),
                    ]),
                ),
                (
                    "next_check",
                    object(vec![
                        ("at", string("2026-09-13T00:01:00Z")),
                        ("reason", string("supervision.recent_progress")),
                        ("due_in_secs", canter::value::integer(30)),
                    ]),
                ),
                (
                    "freshness",
                    object(vec![
                        ("state", string("fresh")),
                        ("age_secs", canter::value::integer(3)),
                        ("max_age_secs", canter::value::integer(360)),
                    ]),
                ),
                (
                    "progress",
                    object(vec![
                        ("marker", string("marker")),
                        ("at", string("2026-09-13T00:00:00Z")),
                        ("source", string("state")),
                        ("age_secs", canter::value::integer(3)),
                    ]),
                ),
                (
                    "continuation",
                    object(vec![
                        ("state", string("closed")),
                        ("since", string("")),
                        ("reports", canter::value::integer(0)),
                    ]),
                ),
                (
                    "pending",
                    object(vec![
                        ("trigger", canter::value::null()),
                        ("seq", canter::value::null()),
                        ("folded", canter::value::null()),
                    ]),
                ),
            ]),
        ),
        ("statement", string("supervision only: peer fixture")),
    ])
}

/// Every method any keyboard path may ever reach from the supervision screen.
const ALLOWED_METHODS: [&str; 4] = [
    "run.status",
    "supervision.status",
    "run.pause",
    "run.resume",
];

#[test]
fn no_keyboard_path_arms_supervision_or_advances_a_gated_run() {
    let fixture = Fixture::new("wire");
    let peer = RecordingPeer::start(&fixture.dir, false);
    let state = fixture.open();
    let mut console = OperatorConsole::new(&state, peer.socket.clone(), Some(config()), None);
    // The canned run has no board row here; address it directly through the
    // same entry point the `s` key uses after resolving the selection.
    console.open_supervision_run("run-0011223344556677");
    assert_eq!(console.screen(), Screen::Supervision);
    assert!(console.supervision().view().is_some());

    // --- adversarial sequences: none of them may reach an effect -----------
    let sequences: Vec<Vec<KeyEvent>> = vec![
        vec![key(KeyCode::Enter)],
        vec![key(KeyCode::Char('h')), key(KeyCode::Enter)],
        vec![
            key(KeyCode::Char('h')),
            key(KeyCode::Esc),
            key(KeyCode::Enter),
        ],
        vec![
            key(KeyCode::Char('h')),
            key(KeyCode::Char(' ')),
            key(KeyCode::Esc),
            key(KeyCode::Enter),
        ],
        vec![
            key(KeyCode::Char('h')),
            key_of(KeyCode::Enter, KeyEventKind::Repeat),
        ],
        vec![
            key(KeyCode::Char('h')),
            key(KeyCode::Char(' ')),
            key_of(KeyCode::Enter, KeyEventKind::Repeat),
        ],
        vec![
            key(KeyCode::Char('h')),
            key(KeyCode::Char(' ')),
            key_of(KeyCode::Enter, KeyEventKind::Release),
        ],
        vec![key(KeyCode::Char('u')), key(KeyCode::Enter)],
        vec![
            key(KeyCode::Char('u')),
            key(KeyCode::Char(' ')),
            key(KeyCode::Esc),
            key(KeyCode::Enter),
        ],
        vec![
            key(KeyCode::Tab),
            key(KeyCode::BackTab),
            key(KeyCode::Up),
            key(KeyCode::Down),
            key(KeyCode::Left),
            key(KeyCode::Right),
            key(KeyCode::Home),
            key(KeyCode::End),
            key(KeyCode::Delete),
        ],
    ];
    for (index, sequence) in sequences.iter().enumerate() {
        // Every adversarial sequence is driven ON the supervision screen (the
        // screen the controls live on): the surface is re-opened read-only
        // before each one, so a sequence can never pass by never reaching the
        // panel at all.
        console.open_supervision_run("run-0011223344556677");
        for stroke in sequence {
            console.handle_key(*stroke);
        }
        assert!(
            console.supervision().attempt().is_none(),
            "sequence {index} must effect nothing"
        );
        console.handle_key(key(KeyCode::Esc));
    }
    assert_eq!(
        peer.params_of("run.pause").len(),
        0,
        "no adversarial sequence may request a hold: {:?}",
        peer.methods()
    );
    assert_eq!(peer.params_of("run.resume").len(), 0);

    // --- the ONE deliberate hold path, captured at the wire ---------------
    console.open_supervision_run("run-0011223344556677");
    console.handle_key(key(KeyCode::Char('h')));
    console.handle_key(key(KeyCode::Char(' ')));
    console.handle_key(key(KeyCode::Enter));
    let pauses = peer.params_of("run.pause");
    assert_eq!(
        pauses.len(),
        1,
        "exactly one run.pause: {:?}",
        peer.methods()
    );
    let mut keys = object_keys(&pauses[0]);
    keys.sort_unstable();
    assert_eq!(keys, ["idempotency_key", "instance_id", "reason"]);
    assert_eq!(
        pauses[0].get("instance_id").and_then(Val::as_str),
        Some("run-0011223344556677")
    );
    assert_eq!(
        pauses[0].get("reason").and_then(Val::as_str),
        Some(PAUSE_REASON)
    );

    // --- the ONE deliberate continue path, with the recorded digest -------
    console.handle_key(key(KeyCode::Char('u')));
    console.handle_key(key(KeyCode::Char(' ')));
    console.handle_key(key(KeyCode::Enter));
    let resumes = peer.params_of("run.resume");
    assert_eq!(
        resumes.len(),
        1,
        "exactly one run.resume: {:?}",
        peer.methods()
    );
    let mut keys = object_keys(&resumes[0]);
    keys.sort_unstable();
    assert_eq!(keys, ["digest", "idempotency_key", "instance_id"]);
    assert_eq!(
        resumes[0].get("digest").and_then(Val::as_str),
        Some(peer.digest.as_str()),
        "the resume binds the digest the pause recorded"
    );

    // --- the closed method set: nothing else was ever reached -------------
    for method in peer.methods() {
        assert!(
            ALLOWED_METHODS.contains(&method.as_str()),
            "a keyboard path reached {method:?}; allowed: {ALLOWED_METHODS:?}"
        );
    }
    assert!(
        !peer
            .methods()
            .iter()
            .any(|method| method.starts_with("supervision.") && method != "supervision.status"),
        "no keyboard path may arm or nudge supervision: {:?}",
        peer.methods()
    );
}

// ---------------------------------------------------------------------------
// 4. A pause holds across a TUI restart and is never replayed
// ---------------------------------------------------------------------------

#[test]
fn a_pause_holds_across_a_tui_restart_and_is_never_replayed() {
    let fixture = Fixture::new("restart");
    let daemon = fixture.spawn();
    wait_ready(&fixture);
    let state = fixture.seed();
    let run = fixture.submit_armed(&state, "restart", 5, 60);
    wait_for_committed_check(&fixture, &run);

    // --- first session: hold the run through the panel ---------------------
    {
        let mut console = console_with_selection(&fixture, &state);
        console.handle_key(key(KeyCode::Char('s')));
        console.handle_key(key(KeyCode::Char('h')));
        console.handle_key(key(KeyCode::Char(' ')));
        console.handle_key(key(KeyCode::Enter));
        let attempt = console.supervision().attempt().cloned().expect("attempt");
        assert!(
            attempt.outcome.observed_doc().is_some(),
            "the hold was confirmed before the terminal closed"
        );
    }
    let paused_row = state
        .instance_by_id(&run)
        .expect("instance read")
        .expect("the run exists");
    assert!(
        paused_row.pause_requested || paused_row.paused,
        "the hold is durable"
    );
    let attempts_before = state.run_step_attempts(&run).expect("attempts read").len();
    let instances_before = state.list_instances().expect("instances").len();

    // --- a fresh session (the TUI was closed and reopened) ----------------
    let mut reopened = console_with_selection(&fixture, &state);
    reopened.handle_key(key(KeyCode::Char('s')));
    assert_eq!(reopened.screen(), Screen::Supervision);
    let view = reopened.supervision().view().expect("status read").clone();
    assert!(view.read);
    let control = reopened
        .supervision()
        .control()
        .expect("control read")
        .clone();
    assert!(
        control.recorded_pause(),
        "the reopened surface reads the RECORDED hold: {control:?}"
    );
    assert!(
        !reopened.supervision().pause_availability().enabled(),
        "a second hold is refused with a reason"
    );
    assert!(
        reopened.supervision().resume_availability().enabled(),
        "the recorded digest survives the restart"
    );
    let text = lines_of(&reopened, 220);
    assert!(
        text.contains("hold (pause automatic continuation):  h  [disabled"),
        "{text}"
    );
    // The restart replays nothing: every benign key still effects nothing.
    for code in [
        KeyCode::Enter,
        KeyCode::Char('r'),
        KeyCode::Char('j'),
        KeyCode::Char('k'),
        KeyCode::Char('h'),
        KeyCode::Esc,
    ] {
        reopened.handle_key(key(code));
    }
    let paused_row = state
        .instance_by_id(&run)
        .expect("instance read")
        .expect("the run exists");
    assert!(
        paused_row.pause_requested || paused_row.paused,
        "the hold still holds"
    );
    assert_eq!(
        state.run_step_attempts(&run).expect("attempts read").len(),
        attempts_before,
        "a restart dispatches no step and replays no effect"
    );
    assert_eq!(
        state.list_instances().expect("instances").len(),
        instances_before,
        "no second run was ever submitted"
    );

    // --- the explicit continue lifts exactly this recorded pause -----------
    // (The benign sweep above ends on Esc, which is a back, so the screen is
    // re-opened the way an operator would: `s` on the selected run.)
    if reopened.screen() == Screen::Board {
        reopened.handle_key(key(KeyCode::Char('s')));
    }
    assert_eq!(reopened.screen(), Screen::Supervision);
    assert!(
        reopened.supervision().resume_availability().enabled(),
        "the recorded digest is still readable after the sweep"
    );
    reopened.handle_key(key(KeyCode::Char('u')));
    assert!(reopened.supervision().confirming());
    reopened.handle_key(key(KeyCode::Char(' ')));
    reopened.handle_key(key(KeyCode::Enter));
    let attempt = reopened
        .supervision()
        .attempt()
        .cloned()
        .expect("the boxed Enter reached run.resume");
    assert_eq!(attempt.requested.effect, ControlEffect::Resume);
    assert!(attempt.outcome.observed_doc().is_some());
    let lifted = state
        .instance_by_id(&run)
        .expect("instance read")
        .expect("the run exists");
    assert!(
        !lifted.pause_requested && !lifted.paused,
        "the pause is lifted"
    );
    assert!(
        reopened.attempt().is_none(),
        "the reopened surface never submitted and never advanced the run"
    );

    shutdown(daemon);
}

// ---------------------------------------------------------------------------
// 4b. Stale evidence reads held over the real daemon (never assumed healthy)
// ---------------------------------------------------------------------------

#[test]
fn stale_evidence_reads_held_and_never_healthy_over_the_real_daemon() {
    let fixture = Fixture::new("stale");
    let daemon = fixture.spawn();
    wait_ready(&fixture);
    let state = fixture.seed();
    // A long interval keeps the driver away from the row while the test
    // rewrites the recorded freshness marker.
    let run = fixture.submit_armed(&state, "stale-evidence", 300, 900);
    let fresh = wait_for_committed_check(&fixture, &run);
    assert_eq!(
        text_at(&fresh, &["evaluation", "freshness", "state"]).as_deref(),
        Some("fresh"),
        "sanity: the just-committed check is fresh"
    );
    // Age the recorded last check past the recorded freshness bound (the
    // integration fixture reaches into the same row the read services read;
    // nothing about the surface is faked).
    let raw = rusqlite::Connection::open(fixture.db()).expect("raw open");
    raw.execute(
        "UPDATE supervisions SET last_check_at = '2026-09-01T00:00:00Z' WHERE instance_id = ?1",
        rusqlite::params![run],
    )
    .expect("age the recorded check");

    let daemon_doc = rpc_ok(
        &fixture.socket,
        "b0000003",
        "supervision.status",
        Some(&supervision::status_params(&run)),
    );
    assert_eq!(
        text_at(&daemon_doc, &["evaluation", "freshness", "state"]).as_deref(),
        Some("stale"),
        "the daemon's own read reports the stale evidence"
    );
    assert_eq!(
        text_at(&daemon_doc, &["evaluation", "class"]).as_deref(),
        Some("needs-attention"),
        "the recorded class names the missing autonomous dispatch context"
    );
    assert_eq!(
        text_at(&daemon_doc, &["evaluation", "reason"]).as_deref(),
        Some(supervision::codes::DISPATCH_CONTEXT_MISSING)
    );

    let mut console = console_with_selection(&fixture, &state);
    console.handle_key(key(KeyCode::Char('s')));
    let view = console.supervision().view().expect("status read").clone();
    assert!(!view.trusted(), "stale evidence is never trusted: {view:?}");
    assert!(view.held());
    assert!(
        view.class_slot().starts_with("stale "),
        "the compact class slot leads with the staleness: {}",
        view.class_slot()
    );
    assert!(
        !view.class_slot().starts_with("healthy"),
        "stale evidence is never assumed healthy"
    );
    let text = lines_of(&console, 220);
    assert!(text.contains("evidence: stale"), "{text}");
    assert!(text.contains("(held)"), "{text}");

    shutdown(daemon);
}

// ---------------------------------------------------------------------------
// 5. An unconfirmed control is reported unknown and is never replayed
// ---------------------------------------------------------------------------

#[test]
fn an_unconfirmed_control_is_unknown_and_is_never_replayed() {
    let fixture = Fixture::new("uncertain");
    let peer = RecordingPeer::start(&fixture.dir, true);
    let state = fixture.open();
    let mut console = OperatorConsole::new(&state, peer.socket.clone(), Some(config()), None);
    console.open_supervision_run("run-0011223344556677");
    assert!(console.supervision().pause_availability().enabled());

    console.handle_key(key(KeyCode::Char('h')));
    console.handle_key(key(KeyCode::Char(' ')));
    console.handle_key(key(KeyCode::Enter));
    let attempt = console
        .supervision()
        .attempt()
        .cloned()
        .expect("the attempt is recorded even without a reply");
    match &attempt.outcome {
        AttemptOutcome::Uncertain { code, .. } => {
            assert!(code.starts_with("client."), "transport class: {code}");
        }
        other => panic!("expected the unconfirmed class, got {other:?}"),
    }
    let text = lines_of(&console, 220);
    assert!(text.contains("UNKNOWN"), "{text}");
    assert!(text.contains("will not replay"), "{text}");
    // The daemon was NOT called a second time: exactly one run.pause and no
    // automatic refresh after an unconfirmed effect.
    assert_eq!(peer.params_of("run.pause").len(), 1, "{:?}", peer.methods());
    assert_eq!(
        peer.methods().len(),
        3,
        "two reads and the one unconfirmed effect: {:?}",
        peer.methods()
    );
    // The operator's explicit read is read-only and never a replay: the
    // refresh issues exactly the read pair, and run.pause stays at one call.
    console.handle_key(key(KeyCode::Char('r')));
    let methods = peer.methods();
    assert_eq!(peer.params_of("run.pause").len(), 1, "{methods:?}");
    assert_eq!(
        &methods[3..],
        ["run.status", "supervision.status"],
        "the explicit read is the read pair only: {methods:?}"
    );
}

// ---------------------------------------------------------------------------
// 6. A real terminal: real key bytes hold a run through the supervision screen
// ---------------------------------------------------------------------------

#[test]
fn a_real_terminal_holds_a_run_through_the_supervision_screen() {
    let fixture = Fixture::new("pty");
    let daemon = fixture.spawn();
    wait_ready(&fixture);
    let state = fixture.seed();
    let run = fixture.submit_armed(&state, "terminal-pty", 5, 60);
    wait_for_committed_check(&fixture, &run);
    // The board reads the same state store the daemon owns: point the child at
    // the fixture through the documented config socket override.
    let config_path = fixture.dir.join("canter.toml");
    std::fs::write(
        &config_path,
        format!(
            "schema = \"hf-config/v1\"\n\n[daemon]\nsocket = \"{}\"\n",
            fixture.socket.display()
        ),
    )
    .expect("config file");

    let session = pty::run(
        env!("CARGO_BIN_EXE_canter"),
        &["board", "--config", config_path.to_str().expect("utf-8")],
        &[
            ("XDG_STATE_HOME", fixture.state_dir.to_str().expect("utf-8")),
            ("HOME", fixture.dir.to_str().expect("utf-8")),
            ("TERM", "xterm-256color"),
        ],
        // j (select the recorded run), s (compact supervision status),
        // h (open the hold confirmation), Space (set the box),
        // Enter (commit the hold), r (read back), q (quit).
        b"jsh \x0drq",
    )
    .expect("pty run");
    let text = pty::strip_ansi(&session.output);
    for line in text.lines().take(30) {
        println!("|{line}|");
    }
    assert_eq!(session.exit_code, 0, "captured frame:\n{text}");
    assert!(
        pty::contains_content(&text, "SUPERVISION"),
        "the supervision screen was rendered: {text}"
    );
    assert!(
        pty::contains_content(&text, "HOLD REQUEST"),
        "the hold confirmation was rendered: {text}"
    );
    assert!(
        pty::contains_content(&text, "hold (pause automatic continuation)"),
        "{text}"
    );
    // The real keystrokes reached the REAL typed service: the daemon's own
    // durable row records the hold the terminal requested.
    let row = state
        .instance_by_id(&run)
        .expect("instance read")
        .expect("the run exists");
    assert!(
        row.pause_requested || row.paused,
        "the terminal's hold is durable (frame: {text})"
    );
    assert_eq!(row.pause_reason, PAUSE_REASON);

    shutdown(daemon);
}

// ---------------------------------------------------------------------------
// Real pseudo-terminal harness (`tests/tui_operator.rs` shape)
// ---------------------------------------------------------------------------

mod pty {
    use std::ffi::CString;
    use std::io;
    use std::time::{Duration, Instant};

    /// Wall-clock budget for one child (bounded; a live child is killed).
    const DEADLINE: Duration = Duration::from_secs(45);
    /// Budget for the first frame before the child is treated as wedged.
    const FIRST_FRAME: Duration = Duration::from_secs(20);
    const WIN_ROWS: u16 = 40;
    const WIN_COLS: u16 = 120;
    const TITLE: &[u8] = b"Canter operator board";

    pub struct Run {
        pub output: Vec<u8>,
        pub exit_code: i32,
    }

    fn invalid(what: &str) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidInput, what.to_string())
    }

    pub fn run(exe: &str, argv: &[&str], env: &[(&str, &str)], keys: &[u8]) -> io::Result<Run> {
        let mut argv_strings = vec![CString::new(exe).map_err(|_| invalid("executable path"))?];
        for arg in argv {
            argv_strings.push(CString::new(*arg).map_err(|_| invalid("argument"))?);
        }
        let mut env_strings = Vec::with_capacity(env.len());
        for (key, value) in env {
            env_strings
                .push(CString::new(format!("{key}={value}")).map_err(|_| invalid("environment"))?);
        }
        let argv: Vec<*const libc::c_char> = argv_strings
            .iter()
            .map(|arg| arg.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect();
        let envp: Vec<*const libc::c_char> = env_strings
            .iter()
            .map(|value| value.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect();

        let mut winsize = libc::winsize {
            ws_row: WIN_ROWS,
            ws_col: WIN_COLS,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // The libc signature takes `*mut winsize` on BSD/macOS and
        // `*const winsize` on Linux; an explicit raw pointer satisfies both.
        let winsize_ptr: *mut libc::winsize = &raw mut winsize;
        let mut master: libc::c_int = -1;
        // SAFETY: `forkpty` is the POSIX pseudo-terminal fork; the child only
        // execve/_exit before replacing its image.
        let pid = unsafe {
            libc::forkpty(
                &mut master,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                winsize_ptr,
            )
        };
        if pid < 0 {
            return Err(io::Error::last_os_error());
        }
        if pid == 0 {
            // SAFETY: exec with the argv/envp built above; on failure the child
            // must not run the test harness, so it exits immediately.
            unsafe {
                libc::execve(argv[0], argv.as_ptr(), envp.as_ptr());
                libc::_exit(127);
            }
        }

        let started = Instant::now();
        let mut output: Vec<u8> = Vec::new();
        let mut keys_sent = false;
        let mut quiet = 0_u32;
        let mut status: Option<libc::c_int> = None;
        while started.elapsed() < DEADLINE {
            let mut pollfd = libc::pollfd {
                fd: master,
                events: libc::POLLIN,
                revents: 0,
            };
            let ready = unsafe { libc::poll(&mut pollfd, 1, 100) };
            let mut read_bytes = 0_usize;
            if ready > 0 && pollfd.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
                let mut buffer = [0_u8; 8192];
                let count = unsafe { libc::read(master, buffer.as_mut_ptr().cast(), buffer.len()) };
                if count > 0 {
                    read_bytes = count as usize;
                    output.extend_from_slice(&buffer[..read_bytes]);
                }
            }
            if !keys_sent && output.windows(TITLE.len()).any(|window| window == TITLE) {
                // The first frame is drawn, so the session is already in raw
                // mode: the keys arrive as keystrokes, without Enter.
                let written = unsafe { libc::write(master, keys.as_ptr().cast(), keys.len()) };
                if written < 0 {
                    return Err(io::Error::last_os_error());
                }
                keys_sent = true;
            }
            if !keys_sent && started.elapsed() > FIRST_FRAME {
                break;
            }
            quiet = if read_bytes > 0 { 0 } else { quiet + 1 };
            if status.is_none() {
                let mut raw: libc::c_int = 0;
                if unsafe { libc::waitpid(pid, &mut raw, libc::WNOHANG) } == pid {
                    status = Some(raw);
                }
            }
            if status.is_some() && quiet >= 2 {
                break;
            }
        }
        if status.is_none() {
            // Bounded: never leave a live child behind.
            unsafe {
                libc::kill(pid, libc::SIGKILL);
            }
            let mut raw: libc::c_int = 0;
            unsafe {
                libc::waitpid(pid, &mut raw, 0);
            }
            status = Some(raw);
        }
        unsafe {
            libc::close(master);
        }
        let raw = status.unwrap_or(-1);
        let exit_code = if libc::WIFEXITED(raw) {
            libc::WEXITSTATUS(raw)
        } else {
            -1
        };
        Ok(Run { output, exit_code })
    }

    /// Strip ANSI escape sequences from a captured terminal stream.
    pub fn strip_ansi(bytes: &[u8]) -> String {
        let mut text: Vec<u8> = Vec::with_capacity(bytes.len());
        let mut index = 0;
        while index < bytes.len() {
            if bytes[index] != 0x1b {
                text.push(bytes[index]);
                index += 1;
                continue;
            }
            index += 1;
            match bytes.get(index) {
                Some(b'[') => {
                    index += 1;
                    while index < bytes.len() && !(0x40..=0x7e).contains(&bytes[index]) {
                        index += 1;
                    }
                    index += 1;
                }
                Some(b']') => {
                    index += 1;
                    while index < bytes.len() && bytes[index] != 0x07 {
                        index += 1;
                    }
                    index += 1;
                }
                Some(b'(') | Some(b')') => index += 2,
                _ => index += 1,
            }
        }
        String::from_utf8_lossy(&text).into_owned()
    }

    /// Whether a captured frame carries `needle`, ignoring whitespace: a real
    /// terminal legitimately receives fewer bytes than the cell grid (Ratatui's
    /// diff skips blank default cells), so PTY assertions compare content.
    pub fn contains_content(text: &str, needle: &str) -> bool {
        let squash =
            |value: &str| -> String { value.chars().filter(|c| !c.is_whitespace()).collect() };
        squash(text).contains(&squash(needle))
    }
}
