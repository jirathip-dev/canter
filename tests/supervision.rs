//! Issue #95 acceptance tests: the daemon-owned supervised reconciliation
//! driver (armed with a run submission, evaluated from recorded evidence with
//! a bounded timer fallback, and read back through the versioned
//! `hf-supervision/v1` status).
//!
//! Two fixture layers, synthetic identities only:
//! - library-level `State` assertions for the durable authorization, the
//!   coalesced wake slot and the restart-surviving holds;
//! - a real `canter daemon run` child process over an explicit socket for the
//!   end-to-end acceptance: one armed run is evaluated WITHOUT another client
//!   request, reads never move the meaningful-progress marker, a restart
//!   yields exactly one fresh reconciliation, and nothing ever spawns,
//!   prompts or continues work.
//!
//! No fixed real sleeps: every wait is a bounded poll with a deadline.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use canter::client::Connection;
use canter::config::ProfileBinding;
use canter::lifecycle::ConcurrencyCaps;
use canter::plan::DOCTRINE_WORKFLOW_ID;
use canter::queue_executor as qx;
use canter::queue_preview as qp;
use canter::state::{Retention, State};
use canter::supervision;
use canter::value::{Val, integer, null, object, string};

// ---------------------------------------------------------------------------
// Constants and builders (the #84/#85 fixture shape, one selected issue)
// ---------------------------------------------------------------------------

const REPO: &str = "example-org/widgets";
const HOST: &str = "host-1";
const HARNESS: &str = "lane-1";
const REV_A: &str = "1111111111111111111111111111111111111111";
const WORKFLOW_HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const POLICY_HASH: &str = "feedface01234567feedface01234567feedface01234567feedface01234567";
const SECRET_DIGEST: &str = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

fn binding_doc() -> Val {
    let mut binding = ProfileBinding {
        key: HARNESS.to_string(),
        kind: "pi".to_string(),
        provider: "provider-a".to_string(),
        model: "model-a".to_string(),
        fallbacks: Vec::new(),
        configured_limits: Vec::new(),
        introspection: false,
        secrets: vec![("PROVIDER_TOKEN".to_string(), SECRET_DIGEST.to_string())],
        revision: String::new(),
    };
    binding.revision = binding.revision_of();
    binding.to_doc()
}

fn resolved() -> Val {
    object(vec![("ref", string("staging"))])
}

fn request_with(issues: Vec<qp::SelectedIssue>) -> qp::QueueRequest {
    qp::QueueRequest {
        repository: REPO.to_string(),
        host: HOST.to_string(),
        host_available: Some(true),
        harness_key: HARNESS.to_string(),
        harness_lanes: Some(0),
        caps: ConcurrencyCaps {
            global: 4,
            per_repository: 2,
            per_harness: 2,
        },
        workflow_id: DOCTRINE_WORKFLOW_ID.to_string(),
        workflow_hash: WORKFLOW_HASH.to_string(),
        role_config: binding_doc(),
        boundary: qp::Boundary {
            phase: "merge".to_string(),
            integration_branch: "staging".to_string(),
            completion_branch: "staging".to_string(),
            caps: vec![
                "read".to_string(),
                "worktree".to_string(),
                "spawn".to_string(),
                "prompt".to_string(),
                "merge".to_string(),
            ],
        },
        steps: vec![qp::PlannedStep {
            id: "p1".to_string(),
            kind: "checkout".to_string(),
            params: Some(resolved()),
        }],
        selected: issues,
    }
}

fn selected(id: &str, revision: &str) -> qp::SelectedIssue {
    qp::SelectedIssue {
        id: id.to_string(),
        title: None,
        revision: revision.to_string(),
        requires: Vec::new(),
    }
}

fn render_bound(state: &State, request: &qp::QueueRequest) -> (Val, String) {
    let preview = qp::preview_queue(state, request).expect("preview renders");
    let bound = preview
        .doc
        .get("request")
        .cloned()
        .expect("preview carries the bound-input document");
    (bound, preview.digest)
}

fn grant_doc_at(grant_id: &str, number: i64, revision: &str, epoch: i64) -> Val {
    Val::parse_json(&format!(
        r#"{{"schema":"hf-grant/v1","grant_id":"{grant_id}","repository":"{REPO}",
            "issue":{{"number":{number},"revision":"{revision}"}},
            "workflow_hash":"{WORKFLOW_HASH}","policy_hash":"{POLICY_HASH}",
            "phase":"merge","scope":"worktrees/issues/{number}",
            "caps":["read","worktree","spawn","prompt","merge"],
            "expires_at":"2999-01-01T00:00:00Z","state_epoch":{epoch},
            "created_at":"2026-09-06T00:00:00Z"}}"#
    ))
    .expect("grant document")
}

fn seed_grant(state: &State, grant_id: &str, number: i64) {
    let epoch = state.current_epoch().expect("epoch");
    state
        .issue_grant(&grant_doc_at(grant_id, number, REV_A, epoch))
        .expect("issue grant");
}

fn role_revision() -> String {
    binding_doc()
        .get("revision")
        .and_then(Val::as_str)
        .expect("binding revision")
        .to_string()
}

/// The `queue.submit` params document, with the optional supervision
/// authorization block (`None` = supervision disabled: the default).
#[allow(clippy::too_many_arguments)]
fn params_doc(
    key: &str,
    bound: &Val,
    digest: &str,
    role_revision: &str,
    grant_id: &str,
    supervision_block: Option<supervision::Authorization>,
) -> Val {
    let grants = vec![qx::ItemGrant {
        id: "#5".to_string(),
        grant_id: grant_id.to_string(),
    }];
    qx::submit_params(
        key,
        digest,
        1,
        bound,
        &binding_doc(),
        role_revision,
        ConcurrencyCaps {
            global: 4,
            per_repository: 2,
            per_harness: 2,
        },
        Some(true),
        Some(0),
        &grants,
        &[],
        supervision_block.as_ref(),
    )
}

fn armed(interval_secs: i64, timeout_secs: i64) -> supervision::Authorization {
    supervision::Authorization {
        desired: "armed".to_string(),
        policy: supervision::Policy {
            check_interval_secs: interval_secs,
            progress_timeout_secs: timeout_secs,
        },
    }
}

// ---------------------------------------------------------------------------
// Fixtures (the tests/queue_submit.rs daemon pattern)
// ---------------------------------------------------------------------------

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("hf-supervision-95-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
}

/// Runtime-assembled idempotency key (the tracked file never carries a
/// `key = "<literal>"` shape the secret scanners read as an API key).
fn idem_key(stem: &str) -> String {
    format!("ik_95-{stem}-{}", std::process::id())
}

fn fresh_id(seed: u64) -> String {
    format!("{seed:016x}")
}

struct DaemonFixture {
    dir: PathBuf,
    state_dir: PathBuf,
    socket: PathBuf,
}

impl DaemonFixture {
    fn new(name: &str) -> DaemonFixture {
        let dir = temp_dir(name);
        DaemonFixture {
            state_dir: dir.join("state"),
            socket: dir.join("daemon.sock"),
            dir,
        }
    }

    fn db(&self) -> PathBuf {
        self.state_dir.join("canter").join("state.db")
    }

    fn daemon_log(&self) -> PathBuf {
        self.state_dir.join("canter").join("daemon.log")
    }

    fn seed(&self) -> State {
        std::fs::create_dir_all(self.state_dir.join("canter")).expect("state dir");
        State::open(&self.db(), Retention::default()).expect("open state")
    }

    /// Spawn the daemon with an explicit `PATH` (the fake harness/forge
    /// executables the dispatched effects must resolve).
    fn spawn_with_path(&self, path: &str) -> Child {
        std::fs::create_dir_all(&self.state_dir).expect("state home");
        Command::new(env!("CARGO_BIN_EXE_canter"))
            .args(["daemon", "run", "--socket"])
            .arg(&self.socket)
            .env("XDG_STATE_HOME", &self.state_dir)
            .env("HOME", &self.dir)
            .env("PATH", path)
            .stdout(Stdio::null())
            .stderr(Stdio::from(
                std::fs::File::create(self.dir.join("daemon.stderr.log")).expect("stderr log"),
            ))
            .spawn()
            .expect("spawn daemon")
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
}

/// Run the real CLI binary against the fixture daemon (the product surface).
fn cli(fixture: &DaemonFixture, args: &[&str]) -> (i32, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_canter"))
        .args(args)
        .env("XDG_STATE_HOME", &fixture.state_dir)
        .env("HOME", &fixture.dir)
        .output()
        .expect("run cli");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

fn wait_ready(fixture: &DaemonFixture) {
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

fn rpc(socket: &Path, id: &str, method: &str, params: Option<Val>) -> Val {
    let mut connection = Connection::open(socket).expect("connect");
    connection
        .send_request(id, method, params.as_ref())
        .expect("send");
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

fn rpc_ok(socket: &Path, id: &str, method: &str, params: Option<Val>) -> Val {
    let doc = rpc(socket, id, method, params);
    assert_eq!(
        doc.get("ok").and_then(Val::as_bool),
        Some(true),
        "expected ok for {method}: {}",
        canter::canonical::canonical_text(&doc)
    );
    doc.get("result").expect("result").clone()
}

fn rpc_err(socket: &Path, id: &str, method: &str, params: Option<Val>) -> String {
    let doc = rpc(socket, id, method, params);
    assert_eq!(
        doc.get("ok").and_then(Val::as_bool),
        Some(false),
        "expected a refusal for {method}: {}",
        canter::canonical::canonical_text(&doc)
    );
    doc.get("error")
        .and_then(|error| error.get("code"))
        .and_then(Val::as_str)
        .unwrap_or_default()
        .to_string()
}

/// The refusal text of one RPC (`<code>: <message>`), for the F7 cases: the
/// pinned reason is the effect's OWN contract, not a generic refusal.
fn rpc_refusal(socket: &Path, id: &str, method: &str, params: Option<Val>) -> String {
    let doc = rpc(socket, id, method, params);
    assert_eq!(
        doc.get("ok").and_then(Val::as_bool),
        Some(false),
        "expected a refusal for {method}: {}",
        canter::canonical::canonical_text(&doc)
    );
    let error = doc.get("error").cloned().unwrap_or_else(null);
    format!(
        "{}: {}",
        error.get("code").and_then(Val::as_str).unwrap_or_default(),
        error
            .get("message")
            .and_then(Val::as_str)
            .unwrap_or_default()
    )
}

fn shutdown(mut daemon: Child) {
    let _ = daemon.kill();
    let deadline = Instant::now() + Duration::from_secs(10);
    while daemon.try_wait().expect("try_wait").is_none() {
        assert!(Instant::now() < deadline, "daemon did not exit");
        std::thread::sleep(Duration::from_millis(20));
    }
}

// ---------------------------------------------------------------------------
// Document readers
// ---------------------------------------------------------------------------

fn item_of(result: &Val, number: i64) -> Val {
    let wanted = format!("{REPO}#{number}");
    result
        .get("items")
        .and_then(Val::as_array)
        .and_then(|items| {
            items
                .iter()
                .find(|item| item.get("id").and_then(Val::as_str) == Some(wanted.as_str()))
                .cloned()
        })
        .unwrap_or_else(|| {
            panic!(
                "no item for issue {number}: {}",
                canter::canonical::canonical_text(result)
            )
        })
}

fn instance_of(result: &Val, number: i64) -> String {
    item_of(result, number)
        .get("instance_id")
        .and_then(Val::as_str)
        .expect("admitted item carries the run")
        .to_string()
}

fn status_doc(socket: &Path, id: &str, run: &str) -> Val {
    rpc_ok(
        socket,
        id,
        "supervision.status",
        Some(supervision::status_params(run)),
    )
}

fn evaluation(doc: &Val) -> Val {
    doc.get("evaluation").cloned().unwrap_or_else(|| {
        panic!(
            "no evaluation block: {}",
            canter::canonical::canonical_text(doc)
        )
    })
}

fn checks_of(doc: &Val) -> i64 {
    evaluation(doc)
        .get("checks")
        .and_then(Val::as_int)
        .unwrap_or(-1)
}

fn class_of(doc: &Val) -> String {
    evaluation(doc)
        .get("class")
        .and_then(Val::as_str)
        .unwrap_or_default()
        .to_string()
}

/// The DURABLE continuation report count recorded by the driver.
fn reports_of(doc: &Val) -> i64 {
    evaluation(doc)
        .get("continuation")
        .and_then(|continuation| continuation.get("reports"))
        .and_then(Val::as_int)
        .unwrap_or(-1)
}

/// The DURABLE continuation window state ("open"/"closed").
fn window_state(doc: &Val) -> String {
    evaluation(doc)
        .get("continuation")
        .and_then(|continuation| continuation.get("state"))
        .and_then(Val::as_str)
        .unwrap_or_default()
        .to_string()
}

/// Walk one document path (`Val::get` per key), `null` when absent.
fn path_of(doc: &Val, keys: &[&str]) -> Val {
    let mut cursor = doc.clone();
    for key in keys {
        cursor = cursor.get(key).cloned().unwrap_or_else(null);
    }
    cursor
}

/// Poll `supervision.status` until the recorded check count reaches `want`
/// (bounded; no fixed sleeps).
fn wait_for_checks(fixture: &DaemonFixture, run: &str, want: i64) -> Val {
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut last = String::new();
    let mut id = 100u64;
    while Instant::now() < deadline {
        id += 1;
        let doc = status_doc(&fixture.socket, &fresh_id(id), run);
        if checks_of(&doc) >= want {
            return doc;
        }
        last = canter::canonical::canonical_text(&doc);
        std::thread::sleep(Duration::from_millis(25));
    }
    panic!("run {run} never reached {want} recorded check(s); last: {last}");
}

// ---------------------------------------------------------------------------
// Acceptance: one armed run, evaluated without another client request
// ---------------------------------------------------------------------------

#[test]
fn armed_run_is_evaluated_without_another_client_request_and_reads_are_inert() {
    let fixture = DaemonFixture::new("armed");
    let (bound, digest) = {
        let state = fixture.seed();
        seed_grant(&state, "gr_0000000000000095", 5);
        render_bound(&state, &request_with(vec![selected("#5", REV_A)]))
    };
    let daemon = fixture.spawn();
    wait_ready(&fixture);

    let key = idem_key("armed");
    let params = params_doc(
        &key,
        &bound,
        &digest,
        &role_revision(),
        "gr_0000000000000095",
        Some(armed(10, 60)),
    );
    let result = rpc_ok(&fixture.socket, &fresh_id(1), "queue.submit", Some(params));
    let run = instance_of(&result, 5);

    // AC1: the armed run is evaluated with NO further client request — the
    // driver's own boot/wake path performs the reconciliation.
    let first = wait_for_checks(&fixture, &run, 1);
    assert_eq!(
        first
            .get("supervision")
            .and_then(|supervision| supervision.get("desired"))
            .and_then(Val::as_str),
        Some("armed")
    );
    assert_eq!(
        first
            .get("supervision")
            .and_then(|supervision| supervision.get("owner_generation"))
            .and_then(Val::as_int),
        Some(1)
    );
    assert_eq!(
        first
            .get("supervision")
            .and_then(|supervision| supervision.get("policy"))
            .and_then(|policy| policy.get("progress_timeout_secs"))
            .and_then(Val::as_int),
        Some(60)
    );
    // AC3: the FIRST reconciliation of a freshly armed run has no recorded
    // progress observation yet, so it is HELD (unknown), never eligible: an
    // unobserved run is not a timed-out one, and the durable continuation
    // counter must not move.
    assert_eq!(class_of(&first), "unknown");
    assert_eq!(
        evaluation(&first).get("reason").and_then(Val::as_str),
        Some(canter::supervision::codes::PROGRESS_UNOBSERVED)
    );
    assert_eq!(
        evaluation(&first).get("eligible").and_then(Val::as_bool),
        Some(false)
    );
    assert_eq!(
        evaluation(&first)
            .get("continuation")
            .and_then(|continuation| continuation.get("state"))
            .and_then(Val::as_str),
        Some("closed")
    );
    assert_eq!(
        evaluation(&first)
            .get("continuation")
            .and_then(|continuation| continuation.get("reports"))
            .and_then(Val::as_int),
        Some(0),
        "a fresh arm must never open a continuation window"
    );
    // ...and the read agrees with the recorded durable state, never with a
    // read-time re-classification that could hide a committed effect.
    assert_eq!(
        evaluation(&first).get("class"),
        evaluation(&first)
            .get("last_check")
            .and_then(|check| check.get("class")),
        "the reported class is the committed one"
    );
    assert!(
        evaluation(&first)
            .get("observed")
            .and_then(|observed| observed.get("class"))
            .and_then(Val::as_str)
            .is_some(),
        "the read-time observation is reported separately"
    );
    assert_eq!(
        evaluation(&first)
            .get("freshness")
            .and_then(|freshness| freshness.get("state"))
            .and_then(Val::as_str),
        Some("fresh")
    );
    // AC7: the versioned status carries the last check and the NEXT ELIGIBLE
    // CHECK with its reason.
    assert!(
        evaluation(&first)
            .get("last_check")
            .and_then(|check| check.get("at"))
            .and_then(Val::as_str)
            .is_some_and(|at| !at.is_empty())
    );
    assert!(
        evaluation(&first)
            .get("next_check")
            .and_then(|check| check.get("at"))
            .and_then(Val::as_str)
            .is_some_and(|at| !at.is_empty())
    );
    assert!(
        first
            .get("cursor")
            .and_then(|cursor| cursor.get("next_step"))
            .and_then(Val::as_str)
            == Some("p1")
    );

    // AC2: reads and a rendered status never reset the meaningful-progress
    // marker: three more reads leave the DURABLE observation (marker, at,
    // source) byte-identical and the check count untouched. The derived age
    // is not compared: it is a rendering of the clock, not recorded state.
    let durable_progress = |doc: &Val| {
        let progress = evaluation(doc)
            .get("progress")
            .cloned()
            .unwrap_or_else(null);
        object(vec![
            (
                "marker",
                progress.get("marker").cloned().unwrap_or_else(null),
            ),
            ("at", progress.get("at").cloned().unwrap_or_else(null)),
            (
                "source",
                progress.get("source").cloned().unwrap_or_else(null),
            ),
        ])
    };
    let durable_before = durable_progress(&first);
    let checks_before = checks_of(&first);
    for seed in 10..13 {
        let doc = status_doc(&fixture.socket, &fresh_id(seed), &run);
        assert_eq!(checks_of(&doc), checks_before, "a read is not a check");
        assert_eq!(
            durable_progress(&doc),
            durable_before,
            "a read must never move the progress marker"
        );
    }

    // AC7 / no-effect: the evaluation itself produced no journal action of
    // its own and the run stayed exactly where it was.
    let actions = rpc_ok(
        &fixture.socket,
        &fresh_id(20),
        "journal.tail",
        Some(object(vec![("limit", integer(50))])),
    );
    let text = canter::canonical::canonical_text(&actions);
    for banned in [
        "mutate.harness_start",
        "mutate.prompt",
        "mutate.merge",
        "mutate.branch_push",
    ] {
        assert!(
            !text.contains(banned),
            "supervision must never produce {banned}: {text}"
        );
    }
    let log = std::fs::read_to_string(fixture.daemon_log()).unwrap_or_default();
    assert!(
        !log.contains("supervision.continue") && !log.contains("spawn"),
        "no continuation effect may be logged: {log}"
    );

    // The default: a second, un-authorized run is never supervised at all.
    let unarmed_state = {
        shutdown(daemon);
        fixture.seed()
    };
    let unarmed_run = unarmed_state
        .list_instances()
        .expect("instances")
        .into_iter()
        .find(|row| row.instance_id == run)
        .expect("the armed run persists");
    assert_eq!(unarmed_run.status, "new");
    assert!(unarmed_run.current_node.is_empty(), "no node was advanced");
    assert!(
        unarmed_state
            .supervision_by_id("run-0000000000000000")
            .expect("read")
            .is_none(),
        "an absent supervision is never invented"
    );
}

#[test]
fn supervision_is_disabled_by_default_and_a_foreign_target_refuses() {
    let fixture = DaemonFixture::new("default-off");
    let (bound, digest) = {
        let state = fixture.seed();
        seed_grant(&state, "gr_0000000000000096", 5);
        render_bound(&state, &request_with(vec![selected("#5", REV_A)]))
    };
    let daemon = fixture.spawn();
    wait_ready(&fixture);
    let key = idem_key("default-off");
    let params = params_doc(
        &key,
        &bound,
        &digest,
        &role_revision(),
        "gr_0000000000000096",
        None,
    );
    let result = rpc_ok(&fixture.socket, &fresh_id(1), "queue.submit", Some(params));
    let run = instance_of(&result, 5);
    // AC1: absent authorization = disabled. There is no row to read, and the
    // run is never evaluated.
    let code = rpc_err(
        &fixture.socket,
        &fresh_id(2),
        "supervision.status",
        Some(supervision::status_params(&run)),
    );
    assert_eq!(code, "state.not_found");
    // Force a semantic wake on the run (a control mutation notifies the
    // driver) and settle on its committed result: the un-authorized run is
    // still never evaluated, because the driver has no authority over it.
    let pause = canter::run_control::pause_params(
        &idem_key("default-off-pause"),
        &run,
        "un-authorized runs stay un-evaluated",
    );
    let paused = rpc_ok(&fixture.socket, &fresh_id(3), "run.pause", Some(pause));
    assert_eq!(
        paused
            .get("control")
            .and_then(|control| control.get("state"))
            .and_then(Val::as_str),
        Some("paused"),
        "the pause reached its safe boundary"
    );
    let code = rpc_err(
        &fixture.socket,
        &fresh_id(4),
        "supervision.status",
        Some(supervision::status_params(&run)),
    );
    assert_eq!(
        code, "state.not_found",
        "a wake never evaluates a run without an authorization"
    );
    // The target is exactly one run identity.
    let code = rpc_err(
        &fixture.socket,
        &fresh_id(5),
        "supervision.status",
        Some(object(vec![("instance_id", string("run-nope"))])),
    );
    assert_eq!(code, "usage.supervision.target");
    shutdown(daemon);
    let state = fixture.seed();
    assert!(
        state.supervision_rows().expect("rows").is_empty(),
        "no supervision row is ever written without an explicit authorization"
    );
}

#[test]
fn restart_preserves_the_pause_hold_and_yields_one_fresh_reconciliation() {
    let fixture = DaemonFixture::new("restart");
    let (bound, digest) = {
        let state = fixture.seed();
        seed_grant(&state, "gr_0000000000000097", 5);
        render_bound(&state, &request_with(vec![selected("#5", REV_A)]))
    };
    let daemon = fixture.spawn();
    wait_ready(&fixture);
    let key = idem_key("restart");
    let params = params_doc(
        &key,
        &bound,
        &digest,
        &role_revision(),
        "gr_0000000000000097",
        // A long interval keeps the timer out of the test window: every check
        // after the first is a WAKE, never a timer tick.
        Some(armed(3600, 7200)),
    );
    let result = rpc_ok(&fixture.socket, &fresh_id(1), "queue.submit", Some(params));
    let run = instance_of(&result, 5);
    let first = wait_for_checks(&fixture, &run, 1);
    // The first check of a freshly armed run has no observation on file yet:
    // it is HELD (unknown), never eligible, and opens no window.
    assert_eq!(class_of(&first), "unknown");
    assert_eq!(reports_of(&first), 0);
    assert_eq!(window_state(&first), "closed");
    let checks_before_pause = checks_of(&first);

    // Pause the run through the control surface: the durable hold must be
    // classified as paused and must never be eligible.
    let pause_params = canter::run_control::pause_params(
        &idem_key("pause"),
        &run,
        "operator hold for the supervision acceptance case",
    );
    rpc_ok(
        &fixture.socket,
        &fresh_id(2),
        "run.pause",
        Some(pause_params),
    );
    // The pause is a semantic control wake: wait for the driver's OWN
    // reconciliation (a new recorded check), then read the recorded class.
    let paused = wait_for_checks(&fixture, &run, checks_before_pause + 1);
    assert_eq!(class_of(&paused), "paused");
    assert_eq!(
        evaluation(&paused)
            .get("last_check")
            .and_then(|check| check.get("class"))
            .and_then(Val::as_str),
        Some("paused"),
        "the recorded check itself classified the hold"
    );
    assert_eq!(
        evaluation(&paused)
            .get("last_check")
            .and_then(|check| check.get("trigger"))
            .and_then(Val::as_str),
        Some("control")
    );
    assert_eq!(
        evaluation(&paused).get("eligible").and_then(Val::as_bool),
        Some(false)
    );
    let checks_before_restart = checks_of(&paused);
    let progress_before = evaluation(&paused).get("progress").cloned();

    // AC5: the hold survives the restart, and the boot reconciliation is
    // exactly ONE fresh check (no catch-up storm).
    shutdown(daemon);
    let daemon = fixture.spawn();
    wait_ready(&fixture);
    let after = wait_for_checks(&fixture, &run, checks_before_restart + 1);
    assert_eq!(class_of(&after), "paused");
    assert_eq!(
        evaluation(&after).get("eligible").and_then(Val::as_bool),
        Some(false)
    );
    assert_eq!(
        checks_of(&after),
        checks_before_restart + 1,
        "a restart reconciles ONCE, never once per missed window"
    );
    assert_eq!(
        after
            .get("supervision")
            .and_then(|supervision| supervision.get("desired"))
            .and_then(Val::as_str),
        Some("armed")
    );
    assert_eq!(
        after
            .get("supervision")
            .and_then(|supervision| supervision.get("policy"))
            .and_then(|policy| policy.get("check_interval_secs"))
            .and_then(Val::as_int),
        Some(3600),
        "the recorded policy survives the restart"
    );
    // The pause is a recorded state change, so the marker moved with it; the
    // marker is never empty and its observation time is recorded.
    let progress_after = evaluation(&after)
        .get("progress")
        .cloned()
        .expect("progress block");
    let marker = progress_after
        .get("marker")
        .and_then(Val::as_str)
        .unwrap_or_default()
        .to_string();
    assert_eq!(marker.len(), 64, "the marker is a recorded sha256 digest");
    assert!(
        progress_after
            .get("at")
            .and_then(Val::as_str)
            .is_some_and(|at| !at.is_empty())
    );
    assert!(progress_before.is_some());

    // The retry cursor block reads back with the documented bound and no
    // invented attempts.
    let retries = after.get("retries").cloned().expect("retries block");
    assert_eq!(
        retries.get("bound").and_then(Val::as_int),
        Some(canter::state::RUN_RETRY_MAX)
    );
    assert!(
        retries
            .get("rows")
            .and_then(Val::as_array)
            .is_some_and(|rows| rows.is_empty())
    );
    shutdown(daemon);
}

#[test]
fn the_driver_never_reaches_an_effect_surface() {
    // AC7 (no effect): outside its own unit tests the driver module cannot
    // spawn a process, reach the network, the adapters or the filesystem, and
    // the only durable writer it names is its own run-scoped commit — there is
    // no path from an evaluation to a continuation.
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let source = std::fs::read_to_string(root.join("src/supervision.rs")).expect("read module");
    let production = source
        .split("#[cfg(test)]")
        .next()
        .expect("production half");
    for banned in [
        "std::process",
        "Command",
        "std::net",
        "TcpStream",
        "UnixStream",
        "std::fs",
        "adapters::",
        "client::",
        "daemon::",
        "start_instance",
        "pause_instance",
        "resume_instance",
        "record_evidence",
        "append_audit",
        "rotate_epoch",
        "issue_grant",
    ] {
        assert!(
            !production.contains(banned),
            "src/supervision.rs must not reference {banned}: evaluation has no effect"
        );
    }
    // ONE mutating writer, and it is the driver's own check commit.
    let without_commit = production.replace("commit_supervision_check", "");
    assert!(
        !without_commit.contains("commit_"),
        "the driver commits only its own reconciliation"
    );
    assert!(
        production.contains(canter::supervision::STATEMENT),
        "the no-effect statement rides on the module"
    );
}

#[test]
fn cli_supervision_status_reads_the_versioned_status_back_inert() {
    // AC7 (product surface): `canter supervision status` issues the closed
    // read-only `supervision.status` method through the real binary — one
    // hf-output/v1 envelope, a human rendering of the SAME document, and a
    // read that never moves the evaluation.
    let fixture = DaemonFixture::new("cli-status");
    let (bound, digest) = {
        let state = fixture.seed();
        seed_grant(&state, "gr_0000000000000095", 5);
        render_bound(&state, &request_with(vec![selected("#5", REV_A)]))
    };
    let daemon = fixture.spawn();
    wait_ready(&fixture);
    let key = idem_key("cli-status");
    let params = params_doc(
        &key,
        &bound,
        &digest,
        &role_revision(),
        "gr_0000000000000095",
        Some(armed(10, 60)),
    );
    let result = rpc_ok(&fixture.socket, &fresh_id(1), "queue.submit", Some(params));
    let run = instance_of(&result, 5);
    let first = wait_for_checks(&fixture, &run, 1);
    let checks_before = checks_of(&first);
    let socket = fixture.socket.display().to_string();

    let (exit, stdout, stderr) = cli(
        &fixture,
        &[
            "supervision",
            "status",
            "--run",
            &run,
            "--socket",
            &socket,
            "--json",
        ],
    );
    assert_eq!(exit, 0, "json exit; stderr: {stderr}");
    let doc = Val::parse_json(stdout.trim_end()).expect("one JSON envelope");
    let verdict = canter::schema::validate_doc(canter::schema::Family::Output, &doc);
    assert!(verdict.is_accepted(), "envelope: {}", verdict.message());
    let status = doc.get("data").cloned().expect("data");
    assert_eq!(
        status.get("schema").and_then(Val::as_str),
        Some(canter::supervision::SUPERVISION_SCHEMA)
    );
    assert_eq!(
        path_of(&status, &["evaluation", "class"]).as_str(),
        Some("unknown"),
        "the first check is held: no observation is recorded yet"
    );
    assert_eq!(
        path_of(&status, &["evaluation", "reason"]).as_str(),
        Some(supervision::codes::PROGRESS_UNOBSERVED)
    );
    assert_eq!(
        evaluation(&status).get("eligible").and_then(Val::as_bool),
        Some(false)
    );
    assert_eq!(
        reports_of(&status),
        0,
        "no continuation report on a fresh arm"
    );

    // The human rendering of the SAME document.
    let (exit, stdout, stderr) = cli(
        &fixture,
        &["supervision", "status", "--run", &run, "--socket", &socket],
    );
    assert_eq!(exit, 0, "human exit; stderr: {stderr}");
    assert!(stdout.contains("unknown"), "human rendering: {stdout}");
    assert!(stdout.contains(&run), "human rendering names the run");

    // Inert: the reads never moved the evaluation.
    let after = status_doc(&fixture.socket, &fresh_id(9), &run);
    assert_eq!(checks_of(&after), checks_before);
    assert_eq!(class_of(&after), "unknown");
    assert_eq!(reports_of(&after), 0);
    shutdown(daemon);
}

#[test]
fn freshly_armed_run_is_held_and_never_opens_a_continuation_window() {
    // AC3 (reviewer finding 95-R1): a freshly armed run has NO recorded
    // progress observation yet. The first reconciliations must classify it as
    // held (unknown) and must never advance the durable continuation counter,
    // and the read must report exactly what the driver committed.
    let fixture = DaemonFixture::new("fresh-arm");
    let (bound, digest) = {
        let state = fixture.seed();
        seed_grant(&state, "gr_0000000000000095", 5);
        render_bound(&state, &request_with(vec![selected("#5", REV_A)]))
    };
    let daemon = fixture.spawn();
    wait_ready(&fixture);
    let key = idem_key("fresh-arm");
    let params = params_doc(
        &key,
        &bound,
        &digest,
        &role_revision(),
        "gr_0000000000000095",
        Some(armed(10, 60)),
    );
    let result = rpc_ok(&fixture.socket, &fresh_id(1), "queue.submit", Some(params));
    let run = instance_of(&result, 5);

    // The FIRST committed check: held, and no window opened.
    let first = wait_for_checks(&fixture, &run, 1);
    assert_eq!(class_of(&first), "unknown");
    assert_eq!(
        evaluation(&first).get("reason").and_then(Val::as_str),
        Some(supervision::codes::PROGRESS_UNOBSERVED)
    );
    assert_eq!(
        evaluation(&first).get("eligible").and_then(Val::as_bool),
        Some(false)
    );
    assert_eq!(reports_of(&first), 0, "a fresh arm opens no window");
    assert_eq!(window_state(&first), "closed");

    // The read agrees with the committed record at every step, and the
    // counter stays at zero across several further reconciliations.
    let mut last = first;
    for want in 2..=4 {
        let doc = wait_for_checks(&fixture, &run, want);
        assert_eq!(reports_of(&doc), 0, "no check may open a window here");
        assert_eq!(window_state(&doc), "closed");
        assert_eq!(
            evaluation(&doc).get("class"),
            evaluation(&doc)
                .get("last_check")
                .and_then(|check| check.get("class")),
            "the reported class is the committed one"
        );
        assert_eq!(
            evaluation(&doc).get("eligible").and_then(Val::as_bool),
            Some(false),
            "the recorded window state is never eligible here"
        );
        last = doc;
    }
    // The marker is recorded (the run WAS observed), and the record says how
    // the first held check differed from the observation now on file.
    assert!(
        evaluation(&last)
            .get("progress")
            .and_then(|progress| progress.get("marker"))
            .and_then(Val::as_str)
            .is_some_and(|marker| marker.len() == 64)
    );
    assert_eq!(
        class_of(&last),
        "healthy",
        "the run is observed and healthy"
    );
    shutdown(daemon);
}

#[test]
fn a_genuine_deadline_reports_exactly_one_continuation() {
    // AC4 (the legitimate path): once an observation IS recorded and then
    // genuinely ages past the explicit policy deadline, the reader reports
    // continuation-eligible and the durable counter advances exactly once —
    // with the status surface showing that committed state.
    let fixture = DaemonFixture::new("deadline");
    let (bound, digest) = {
        let state = fixture.seed();
        seed_grant(&state, "gr_0000000000000095", 5);
        render_bound(&state, &request_with(vec![selected("#5", REV_A)]))
    };
    let daemon = fixture.spawn();
    wait_ready(&fixture);
    let key = idem_key("deadline");
    // The minimum legal window: a 5s check interval and a 60s deadline, so the
    // bounded poll below observes the REAL timeout path (~65s), never a
    // simulated one.
    let params = params_doc(
        &key,
        &bound,
        &digest,
        &role_revision(),
        "gr_0000000000000095",
        Some(armed(5, 60)),
    );
    let result = rpc_ok(&fixture.socket, &fresh_id(1), "queue.submit", Some(params));
    let run = instance_of(&result, 5);
    let first = wait_for_checks(&fixture, &run, 1);
    assert_eq!(reports_of(&first), 0, "the first check is held");
    let deadline = Instant::now() + Duration::from_secs(150);
    let mut eligible = None;
    let mut attempt = 0u64;
    while Instant::now() < deadline {
        attempt += 1;
        let doc = status_doc(&fixture.socket, &fresh_id(700 + attempt), &run);
        if class_of(&doc) == "continuation-eligible" {
            eligible = Some(doc);
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    let doc = eligible.expect("a genuinely aged observation must report a continuation");
    assert_eq!(
        evaluation(&doc).get("reason").and_then(Val::as_str),
        Some(supervision::codes::PROGRESS_TIMEOUT)
    );
    assert_eq!(
        evaluation(&doc).get("eligible").and_then(Val::as_bool),
        Some(true)
    );
    assert_eq!(reports_of(&doc), 1, "exactly one report per absence window");
    assert_eq!(window_state(&doc), "open");
    assert_eq!(
        evaluation(&doc).get("class"),
        evaluation(&doc)
            .get("last_check")
            .and_then(|check| check.get("class")),
        "the read reports the committed class"
    );
    // A later check within the same window never reports again.
    let after = wait_for_checks(&fixture, &run, checks_of(&doc) + 2);
    assert_eq!(
        reports_of(&after),
        1,
        "one report per window, never one per check"
    );
    shutdown(daemon);
}

#[test]
fn unapproved_plan_binding_is_held_and_never_eligible() {
    // The recorded authorization binds the approved preview digest: a
    // supervision row whose bound digest does not match the run's owning
    // submission (an unapproved/drifted plan) is held, never evaluated as
    // eligible. The state-level writer is the same one the submission
    // transaction calls, so this pins the fence itself.
    let fixture = DaemonFixture::new("unapproved");
    let state = fixture.seed();
    let mismatched = "9".repeat(64);
    state
        .arm_supervision(
            "run-0000000000000009",
            &canter::state::SupervisionAuthorizationPlan {
                desired: "armed".to_string(),
                check_interval_secs: 10,
                progress_timeout_secs: 60,
            },
            &mismatched,
            "merge",
            1,
            "2026-09-13T00:00:00Z",
        )
        .expect("arm");
    let row = state
        .supervision_by_id("run-0000000000000009")
        .expect("read")
        .expect("row");
    assert_eq!(row.authorization_digest, mismatched);
    assert_eq!(row.desired, "armed");
    // The run does not exist, so no evidence backs it: the driver's due set
    // may name it, but the reconciliation refuses to invent evidence and the
    // read surface reports the run as gone.
    let evidence = state
        .supervision_evidence("run-0000000000000009")
        .expect("read");
    assert!(evidence.is_none(), "no evidence, no evaluation");
}

// ---------------------------------------------------------------------------
// Issue #92 F4: the armed continuation dispatch
// ---------------------------------------------------------------------------

/// Two committed steps: the `checkout` the caller dispatches, plus the
/// `hosted_check` a continuation is expected to dispatch next (issue #92 F4).
fn request_two_steps(issues: Vec<qp::SelectedIssue>) -> qp::QueueRequest {
    let mut request = request_with(issues);
    request.steps.push(qp::PlannedStep {
        id: "p2".to_string(),
        kind: "hosted_check".to_string(),
        params: Some(object(vec![("repo", string(REPO)), ("number", integer(5))])),
    });
    request
}

/// Seed one recorded `apply` attempt of (run, step) into the durable claim
/// table with a terminal outcome (the shape the driver's evidence reads).
fn seed_attempt(state: &State, run: &str, step: &str, key: &str, status: &str) {
    let request_id = fresh_id(0x9200);
    let line = canter::canonical::canonical_text(&object(vec![
        ("schema", string("hf-rpc-request/v1")),
        ("id", string(&request_id)),
        ("method", string("apply")),
        (
            "params",
            object(vec![
                ("idempotency_key", string(key)),
                ("instance_id", string(run)),
                ("step", string(step)),
            ]),
        ),
    ]));
    state
        .journal_intent(
            "mutate.checkout",
            &format!("{REPO}:{run}:{step}"),
            key,
            &request_id,
            "apply",
            None,
            None,
            &line,
        )
        .expect("claim the attempt");
    let outcome = canter::canonical::canonical_text(&object(vec![
        ("schema", string("hf-outcome/v1")),
        ("plan_id", string("hf_plan_0000000000000000")),
        ("step_id", string(step)),
        ("status", string(status)),
        ("idempotency_key", string(key)),
        ("observed_at", string("2026-09-14T00:00:00Z")),
        ("result", Val::Null),
        ("error", Val::Null),
    ]));
    // The claim status is the closed claim vocabulary (the recorded OUTCOME
    // document carries the typed step status the evidence reads).
    let claim_status = if status == "ambiguous" {
        "ambiguous"
    } else {
        "spent"
    };
    state
        .resolve_claim(key, "apply", claim_status, &outcome, Some("{}"))
        .expect("resolve the attempt");
}

/// A library-level `State` fixture (no daemon): the F4 rule tests read and
/// write durable state directly, so nothing races their own writes.
struct Fixture {
    dir: PathBuf,
}

impl Fixture {
    fn new(name: &str) -> Fixture {
        let dir =
            std::env::temp_dir().join(format!("hf-supervision-95-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        Fixture { dir }
    }

    fn open(&self) -> State {
        std::fs::create_dir_all(self.dir.join("state").join("canter")).expect("state dir");
        State::open(
            &self.dir.join("state").join("canter").join("state.db"),
            Retention::default(),
        )
        .expect("open state")
    }
}

/// The admitted membership row of one issue.
fn item_row_of(
    items: &[canter::state::QueueSubmissionItemRow],
    number: i64,
) -> canter::state::QueueSubmissionItemRow {
    items
        .iter()
        .find(|item| item.issue_number == number)
        .cloned()
        .unwrap_or_else(|| panic!("no item for issue {number}"))
}

/// The durable submission plan for one fixture (the daemon builds the
/// identical plan from the presented params): lets the F4 rule tests drive
/// the armed row WITHOUT a live daemon, so nothing races their own writes.
fn submission_plan_for(
    state: &State,
    key: &str,
    bound: &Val,
    digest: &str,
    grant_id: &str,
    supervision_block: Option<supervision::Authorization>,
) -> canter::state::QueueSubmissionPlan {
    let material = qx::parse_params(&params_doc(
        key,
        bound,
        digest,
        &role_revision(),
        grant_id,
        supervision_block,
    ))
    .expect("params parse");
    let revalidated = qx::revalidate(state, &material).expect("revalidate");
    assert_eq!(revalidated.preview.digest, material.digest);
    let submission_id = qx::submission_id(&material.digest, &material.idempotency_key);
    let request_line = canter::canonical::canonical_text(
        &revalidated
            .preview
            .doc
            .get("request")
            .cloned()
            .unwrap_or_else(|| material.preview.clone()),
    );
    canter::state::QueueSubmissionPlan {
        submission_id,
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
        supervision: material.supervision.as_ref().map(|authorization| {
            canter::state::SupervisionAuthorizationPlan {
                desired: authorization.desired.clone(),
                check_interval_secs: authorization.policy.check_interval_secs,
                progress_timeout_secs: authorization.policy.progress_timeout_secs,
            }
        }),
        items: revalidated
            .items
            .iter()
            .enumerate()
            .map(|(ordinal, item)| canter::state::QueueSubmissionItemPlan {
                ordinal: ordinal as i64,
                work_item: item.work_item.clone(),
                issue_number: item.issue_number,
                issue_revision: item.revision.clone(),
                grant_id: item.grant_id.clone(),
                resume_digest: item.resume_digest.clone(),
                verdict: item.verdict.clone(),
            })
            .collect(),
        at: canter::time::rfc3339_now(),
    }
}

/// The pure dispatch intent of one run, read from its durable row + evidence.
fn dispatch_intent_of(state: &State, run: &str) -> Option<supervision::DispatchIntent> {
    let row = state
        .supervision_by_id(run)
        .expect("query row")
        .expect("supervision row");
    let evidence = state
        .supervision_evidence(run)
        .expect("query evidence")
        .expect("evidence");
    supervision::dispatch_intent(&row, &evidence)
}

#[test]
fn an_armed_run_is_dispatched_only_while_it_is_live_and_underway() {
    let fixture = Fixture::new("dispatch-rule");
    let state = fixture.open();
    seed_grant(&state, "gr_0000000000000095", 5);
    let (bound, digest) = render_bound(&state, &request_two_steps(vec![selected("#5", REV_A)]));
    let plan = submission_plan_for(
        &state,
        &idem_key("dispatch-rule"),
        &bound,
        &digest,
        "gr_0000000000000095",
        Some(armed(30, 60)),
    );
    let (_, items) = state.submit_queue_run(&plan).expect("submit");
    let run = item_row_of(&items, 5)
        .instance_id
        .expect("the admitted item carries its run");

    // A run that never dispatched a step has no durable dispatch context: its
    // FIRST dispatch belongs to the caller that holds the topology, so the
    // armed run is not advanced yet (and the driver never invents one).
    assert!(dispatch_intent_of(&state, &run).is_none());

    // Underway: one recorded attempt, and the armed run's continuation is the
    // next unachieved step of its own reviewed spine.
    seed_attempt(&state, &run, "p1", "ik_95-dispatch-0001", "succeeded");
    let intent = dispatch_intent_of(&state, &run).expect("armed continuation");
    assert_eq!(intent.step_id, "p2");
    assert_eq!(intent.reason, canter::supervision::codes::DISPATCH);
    assert_eq!(intent.kind, "hosted_check");

    // A paused run is never advanced by supervision.
    state
        .pause_instance(&run, "operator hold", "2026-09-14T00:00:00Z")
        .expect("pause");
    assert!(
        dispatch_intent_of(&state, &run).is_none(),
        "a held run keeps its hold: no dispatch"
    );
}

#[test]
fn a_run_without_armed_supervision_is_never_dispatched() {
    let fixture = Fixture::new("dispatch-off");
    let state = fixture.open();
    seed_grant(&state, "gr_0000000000000095", 5);
    let (bound, digest) = render_bound(&state, &request_two_steps(vec![selected("#5", REV_A)]));
    // No supervision authorization at all: the run is admitted unarmed.
    let plan = submission_plan_for(
        &state,
        &idem_key("dispatch-off"),
        &bound,
        &digest,
        "gr_0000000000000095",
        None,
    );
    let (_, items) = state.submit_queue_run(&plan).expect("submit");
    let run = item_row_of(&items, 5)
        .instance_id
        .expect("the admitted item carries its run");
    seed_attempt(&state, &run, "p1", "ik_95-dispatch-0002", "succeeded");
    // No authorization row exists at all: the driver reconciles ARMED rows
    // only, so an unarmed run is never even read, let alone advanced.
    assert!(
        state.supervision_by_id(&run).expect("query row").is_none(),
        "an unarmed run carries no supervision row"
    );
    // With no row, `dispatch_intent` has nothing to read: the classification
    // path itself refuses to name a continuation for an unauthorized run.
    assert!(
        state
            .supervision_evidence(&run)
            .expect("query evidence")
            .is_none(),
        "an unarmed run is never evaluated"
    );
}

/// A minimal REAL git repository: the integration checkout the dispatches
/// run their read effects against.
fn init_repo(path: &Path) {
    std::fs::create_dir_all(path).expect("repo dir");
    for args in [
        vec!["init", "-q", "-b", "staging"],
        vec!["config", "user.email", "lane@example.invalid"],
        vec!["config", "user.name", "lane"],
        vec!["commit", "--allow-empty", "-q", "-m", "base"],
    ] {
        let status = Command::new("git")
            .args(&args)
            .current_dir(path)
            .status()
            .expect("git runs");
        assert!(status.success(), "git {args:?}");
    }
}

/// A fake `gh` answering the hosted-check row with a green check set (the
/// continuation effect of the fixture spine).
fn write_fake_gh(dir: &Path) -> PathBuf {
    let bin = dir.join("fakebin");
    std::fs::create_dir_all(&bin).expect("bin dir");
    let path = bin.join("gh");
    std::fs::write(
        &path,
        "#!/bin/sh\n\
         if [ \"$1\" = \"pr\" ] && [ \"$2\" = \"checks\" ]; then\n\
           printf '[{\"name\":\"hosted-ci\",\"state\":\"SUCCESS\",\"conclusion\":\"SUCCESS\"}]'\n\
           exit 0\n\
         fi\n\
         echo \"unexpected argv: $*\" >&2\n\
         exit 9\n",
    )
    .expect("write fake gh");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = std::fs::metadata(&path).expect("metadata").permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&path, permissions).expect("chmod");
    }
    bin
}

/// The `hf-plan/v1` document for one committed spine (the derivation
/// docs/contracts/spec-plans.md documents; the daemon's `bind_plan`
/// re-verifies it, so a divergent derivation refuses rather than runs).
fn plan_doc_for_bound(bound: &Val, number: i64) -> Val {
    plan_doc_with_steps(bound.get("steps").cloned().unwrap_or_else(null), number)
}

/// [`plan_doc_for_bound`] over an explicit step spine (tamper cases).
fn plan_doc_with_steps(steps: Val, number: i64) -> Val {
    let placeholder = object(vec![
        ("schema", string("hf-plan/v1")),
        ("plan_id", string("hf_plan_0000000000000000")),
        ("workflow_id", string(DOCTRINE_WORKFLOW_ID)),
        ("workflow_hash", string(WORKFLOW_HASH)),
        ("state_epoch", integer(1)),
        ("repository", string(REPO)),
        (
            "issue",
            object(vec![
                ("number", integer(number)),
                ("revision", string(REV_A)),
            ]),
        ),
        ("steps", steps),
    ]);
    let digest = canter::canonical::sha256_hex(&canter::canonical::canonical_bytes(&placeholder));
    match placeholder {
        Val::Obj(mut map) => {
            map.insert(
                "plan_id".to_string(),
                string(&format!("hf_plan_{}", &digest[..16])),
            );
            Val::Obj(map)
        }
        _ => unreachable!("the plan seed is an object"),
    }
}

/// One caller-driven `apply` of a committed run step: the plan of the run's
/// own spine, the run's grant, the caller's topology and its admission
/// proof — exactly the dispatch the operator drives.
fn caller_apply_params(
    fixture: &DaemonFixture,
    integration: &Path,
    bound: &Val,
    run: &str,
    grant_id: &str,
    target: (&str, i64),
    key: &str,
) -> Val {
    let (step, number) = target;
    object(vec![
        ("idempotency_key", string(key)),
        ("plan", plan_doc_for_bound(bound, number)),
        ("step", string(step)),
        ("grant_id", string(grant_id)),
        ("instance_id", string(run)),
        (
            "observed",
            object(vec![
                ("issue_revision", string(REV_A)),
                ("policy_hash", string(POLICY_HASH)),
                ("feature_head", Val::Null),
                ("integration_base", Val::Null),
            ]),
        ),
        (
            "topology",
            object(vec![
                ("integration_branch", string("staging")),
                ("production_branches", Val::Arr(Vec::new())),
                (
                    "worktrees_root",
                    string(&fixture.dir.join("worktrees").to_string_lossy()),
                ),
                (
                    "archive_root",
                    string(&fixture.dir.join("archive").to_string_lossy()),
                ),
                ("integration_repo", string(&integration.to_string_lossy())),
            ]),
        ),
        (
            "flags",
            object(vec![
                ("interactive", canter::value::bool_(true)),
                ("digest_confirmed", canter::value::bool_(true)),
                ("scheduled", canter::value::bool_(false)),
                ("production_confirmation", string("tty")),
                (
                    "admission",
                    object(vec![
                        (
                            "caps",
                            object(vec![
                                ("global", integer(16)),
                                ("repository", integer(8)),
                                ("harness", integer(8)),
                            ]),
                        ),
                        ("harness_lanes", integer(0)),
                        (
                            "host_proof",
                            object(vec![("measured_at", string(&canter::time::rfc3339_now()))]),
                        ),
                    ]),
                ),
            ]),
        ),
    ])
}

#[test]
fn an_armed_run_is_advanced_by_the_drivers_own_dispatch() {
    let fixture = DaemonFixture::new("dispatch-live");
    let (bound, digest) = {
        let state = fixture.seed();
        seed_grant(&state, "gr_0000000000000095", 5);
        render_bound(&state, &request_two_steps(vec![selected("#5", REV_A)]))
    };
    let integration = fixture.dir.join("integration");
    init_repo(&integration);
    let fakebin = write_fake_gh(&fixture.dir);
    let host_path = std::env::var("PATH").unwrap_or_default();
    let daemon = fixture.spawn_with_path(&format!("{}:{host_path}", fakebin.display()));
    wait_ready(&fixture);

    let params = params_doc(
        &idem_key("dispatch-live"),
        &bound,
        &digest,
        &role_revision(),
        "gr_0000000000000095",
        Some(armed(5, 60)),
    );
    let result = rpc_ok(&fixture.socket, &fresh_id(1), "queue.submit", Some(params));
    let run = instance_of(&result, 5);

    // The caller dispatches the FIRST step (it holds the topology and the
    // admission proof); the armed run is then underway.
    let applied = rpc_ok(
        &fixture.socket,
        &fresh_id(2),
        "apply",
        Some(caller_apply_params(
            &fixture,
            &integration,
            &bound,
            &run,
            "gr_0000000000000095",
            ("p1", 5),
            &idem_key("dispatch-live-0001"),
        )),
    );
    assert!(
        applied.get("integration_base").is_some(),
        "the checkout step recorded its read-back: {}",
        canter::canonical::canonical_text(&applied)
    );

    // AC-F4: the driver dispatches the next unachieved step by itself — no
    // further client request — through the apply engine.
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut attempts = Vec::new();
    while Instant::now() < deadline {
        attempts = fixture.seed().run_step_attempts(&run).expect("attempts");
        if attempts.iter().any(|(step, _)| step == "p2") {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let p2 = attempts
        .iter()
        .find(|(step, _)| step == "p2")
        .unwrap_or_else(|| panic!("the driver never dispatched p2: {attempts:?}"));
    assert_eq!(p2.1, "succeeded", "the continuation ran: {attempts:?}");
    let log = std::fs::read_to_string(fixture.daemon_log()).unwrap_or_default();
    assert!(
        log.contains("\"event\":\"supervision.dispatch\""),
        "the dispatch is recorded in the daemon log:\n{log}"
    );

    shutdown(daemon);
}

// ---------------------------------------------------------------------------
// Issue #92 (consolidated): `run retry` authorizes ONLY, and the operator's
// own corrected dispatch — never a hand-built hf-plan/v1 — consumes the
// single-use authorization.
// ---------------------------------------------------------------------------

/// One committed spine with the REAL malformed shape: `p1` is the checkout
/// that records the run's dispatch context, `p2` is a `worktree_create`
/// whose committed params carry NO `branch` (the conductor's `p2-127`
/// refusal shape: `worktree_create requires a slug branch`).
fn request_lane_steps(issues: Vec<qp::SelectedIssue>) -> qp::QueueRequest {
    let mut request = request_with(issues);
    request.steps = vec![
        qp::PlannedStep {
            id: "p1".to_string(),
            kind: "checkout".to_string(),
            params: Some(object(vec![("ref", string("staging"))])),
        },
        qp::PlannedStep {
            id: "p2".to_string(),
            kind: "worktree_create".to_string(),
            params: Some(object(vec![("worktree", string("lane-p2"))])),
        },
    ];
    request
}

/// One `hf-output/v1` envelope from one CLI stdout (the documented shape).
fn cli_envelope(output: &str) -> Val {
    let doc = Val::parse_json(output.trim_end()).expect("one JSON envelope");
    let verdict = canter::schema::validate_doc(canter::schema::Family::Output, &doc);
    assert!(verdict.is_accepted(), "envelope: {}", verdict.message());
    doc
}

/// One nested key of a document, as text.
fn picked(document: &Val, path: &[&str]) -> String {
    let mut value = document.clone();
    for key in path {
        value = value.get(key).cloned().unwrap_or_else(null);
    }
    value.as_str().unwrap_or_default().to_string()
}

/// One `run <sub>` invocation of the real CLI against the fixture daemon.
fn run_cli(fixture: &DaemonFixture, args: &[&str]) -> (i32, String, String) {
    let socket = fixture.socket.display().to_string();
    let mut argv = vec!["run"];
    argv.extend_from_slice(args);
    argv.extend_from_slice(&["--socket", &socket, "--json"]);
    cli(fixture, &argv)
}

/// Recorded `p2` attempts of one run (the diagnosis ledger).
fn attempts_for(fixture: &DaemonFixture, run: &str, step: &str) -> usize {
    fixture
        .seed()
        .run_step_attempts(run)
        .expect("attempts")
        .iter()
        .filter(|(id, _)| id == step)
        .count()
}

/// The bounded quiet window every retry regression observes: the minted
/// authorization must still be unconsumed and no attempt row may appear for
/// the step. At 48e00df9 the armed driver re-dispatched the diagnosed step
/// from the reconstructed (stale) params within this window and consumed the
/// authorization (measured: authorized 14:13:17Z, consumed 14:13:22Z with the
/// dispatch key `ik_run-<run>-p2-<unix>`).
const RETRY_QUIET_WINDOW_SECS: u64 = 7;

/// Observe the quiet window after `run retry` and assert the authorization
/// survives it untouched.
fn assert_retry_authorization_survives(fixture: &DaemonFixture, run: &str, step: &str) {
    let before = attempts_for(fixture, run, step);
    let until = Instant::now() + Duration::from_secs(RETRY_QUIET_WINDOW_SECS);
    while Instant::now() < until {
        let retries = fixture.seed().run_retries(run).expect("retries");
        assert_eq!(retries.len(), 1, "one bounded authorization: {retries:?}");
        assert!(
            retries.iter().all(|retry| retry.consumed_at.is_empty()),
            "the retry consumes nothing by itself: {retries:?}"
        );
        assert_eq!(
            attempts_for(fixture, run, step),
            before,
            "the retry creates no attempt row of its own"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// The shared scenario of the three regressions: an armed run whose `p1`
/// succeeded (recording the durable dispatch context) and whose `p2` the
/// driver dispatched once by itself — refused `refusal.request.malformed`
/// because the committed params carry no `branch` — which is exactly the
/// diagnosis `run.retry` addresses.
fn retry_lane_scenario(name: &str) -> (DaemonFixture, Child, String) {
    let fixture = DaemonFixture::new(name);
    let (bound, digest) = {
        let state = fixture.seed();
        seed_grant(&state, "gr_0000000000000095", 5);
        render_bound(&state, &request_lane_steps(vec![selected("#5", REV_A)]))
    };
    let integration = fixture.dir.join("integration");
    init_repo(&integration);
    let fakebin = write_fake_gh(&fixture.dir);
    let host_path = std::env::var("PATH").unwrap_or_default();
    let daemon = fixture.spawn_with_path(&format!("{}:{host_path}", fakebin.display()));
    wait_ready(&fixture);

    let params = params_doc(
        &idem_key("lane-dispatch"),
        &bound,
        &digest,
        &role_revision(),
        "gr_0000000000000095",
        Some(armed(5, 60)),
    );
    let result = rpc_ok(&fixture.socket, &fresh_id(1), "queue.submit", Some(params));
    let run = instance_of(&result, 5);

    // The caller dispatches p1 (it holds the topology and the admission
    // proof): the run is underway and its dispatch context is durable.
    let applied = rpc_ok(
        &fixture.socket,
        &fresh_id(2),
        "apply",
        Some(caller_apply_params(
            &fixture,
            &integration,
            &bound,
            &run,
            "gr_0000000000000095",
            ("p1", 5),
            &idem_key("lane-apply-p1"),
        )),
    );
    assert!(
        applied.get("integration_base").is_some(),
        "the checkout read back: {}",
        canter::canonical::canonical_text(&applied)
    );

    // The driver continues by itself: `p2` was never dispatched, so its
    // COMMITTED (branch-less) params are presented — the real malformed shape
    // refuses and records the diagnosis.
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut attempts = Vec::new();
    while Instant::now() < deadline {
        attempts = fixture.seed().run_step_attempts(&run).expect("attempts");
        if attempts.iter().any(|(step, _)| step == "p2") {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let p2 = attempts
        .iter()
        .find(|(step, _)| step == "p2")
        .unwrap_or_else(|| panic!("the driver never dispatched p2: {attempts:?}"));
    assert_eq!(
        p2.1, "refused",
        "the committed malformed params are refused (the diagnosis): {attempts:?}"
    );
    (fixture, daemon, run)
}

#[test]
fn run_retry_authorizes_only_and_the_operators_dispatch_consumes_it_once() {
    let (fixture, daemon, run) = retry_lane_scenario("retry-only");

    // `run retry` mints the bounded authorization — and nothing else.
    let (exit, stdout, stderr) = run_cli(&fixture, &["retry", "--run", &run, "--step", "p2"]);
    assert_eq!(exit, 0, "retry exit; stdout: {stdout}; stderr: {stderr}");
    assert_eq!(
        picked(&cli_envelope(&stdout), &["data", "retry", "status"]),
        "authorized",
        "the minted authorization is unconsumed: {stdout}"
    );

    // Bounded quiet window: the armed driver must NOT re-dispatch the
    // diagnosed step (at 48e00df9 it consumed the authorization within the
    // window, with the stale reconstruction).
    assert_retry_authorization_survives(&fixture, &run, "p2");

    let log = std::fs::read_to_string(fixture.daemon_log()).unwrap_or_default();
    assert_eq!(
        log.matches("\"event\":\"supervision.dispatch_refused\"")
            .count(),
        1,
        "exactly the one continuation dispatch, none from the retry:\n{log}"
    );

    // The journal-timestamped probe of the confirmed mechanism: the retry's
    // own committed entries (`mutate.run.retry`) are the LAST thing it wrote,
    // so no `mutate.worktree_create` attempt follows in the same second. At
    // 48e00df9 the authorizing call was followed by seq57/58
    // `mutate.worktree_create` (the reconstruction with no branch slug),
    // which burned the authorization.
    let journal = rpc_ok(
        &fixture.socket,
        &fresh_id(21),
        "journal.tail",
        Some(object(vec![
            ("after_seq", integer(0)),
            ("limit", integer(500)),
        ])),
    );
    let records = journal
        .get("records")
        .and_then(Val::as_array)
        .cloned()
        .unwrap_or_default();
    let seq_of = |row: &Val, action: &str| -> Option<i64> {
        (row.get("action").and_then(Val::as_str) == Some(action))
            .then(|| row.get("seq").and_then(Val::as_int))
            .flatten()
    };
    let retry_seq = records
        .iter()
        .filter_map(|row| seq_of(row, "mutate.run.retry"))
        .max()
        .expect("the retry journaled its intent");
    let earlier_attempts: Vec<i64> = records
        .iter()
        .filter_map(|row| seq_of(row, "mutate.worktree_create"))
        .filter(|seq| *seq < retry_seq)
        .collect();
    assert!(
        !earlier_attempts.is_empty(),
        "the driver's one continuation attempt is on record BEFORE the retry (the \
         probe is not vacuous): {earlier_attempts:?} < {retry_seq}"
    );
    let later_attempts: Vec<i64> = records
        .iter()
        .filter_map(|row| seq_of(row, "mutate.worktree_create"))
        .filter(|seq| *seq > retry_seq)
        .collect();
    assert!(
        later_attempts.is_empty(),
        "the retry produces no same-second worktree_create attempt (retry seq \
         {retry_seq}, later worktree seqs {later_attempts:?})"
    );

    // A second retry while one authorization is pending refuses typed.
    let (exit, stdout, stderr) = run_cli(&fixture, &["retry", "--run", &run, "--step", "p2"]);
    assert_eq!(
        exit, 4,
        "second retry exit; stdout: {stdout}; stderr: {stderr}"
    );
    assert!(
        stderr.contains("refusal.run.retry_pending"),
        "the duplicate is refused typed: {stderr}"
    );

    // The operator's own corrected dispatch consumes exactly one.
    let (exit, stdout, stderr) = run_cli(
        &fixture,
        &[
            "dispatch",
            "--run",
            &run,
            "--step",
            "p2",
            "--param",
            "branch=issue-92-retry-lane",
        ],
    );
    assert_eq!(exit, 0, "dispatch exit; stdout: {stdout}; stderr: {stderr}");
    let retries = fixture.seed().run_retries(&run).expect("retries");
    assert_eq!(retries.len(), 1, "still exactly one authorization");
    assert!(
        !retries[0].consumed_at.is_empty(),
        "consumed by the operator's dispatch: {retries:?}"
    );

    // ...and a SECOND dispatch of the same step is refused: single use.
    let (exit, stdout, stderr) = run_cli(
        &fixture,
        &[
            "dispatch",
            "--run",
            &run,
            "--step",
            "p2",
            "--param",
            "branch=issue-92-again",
        ],
    );
    assert_eq!(
        exit, 4,
        "second dispatch exit; stdout: {stdout}; stderr: {stderr}"
    );
    assert!(
        stderr.contains("refusal.run.retry_required"),
        "the spent authorization refuses the re-dispatch: {stderr}"
    );

    shutdown(daemon);
}

#[test]
fn retry_redispatch_carries_the_operators_corrected_params() {
    let (fixture, daemon, run) = retry_lane_scenario("retry-fix");

    let (exit, stdout, stderr) = run_cli(&fixture, &["retry", "--run", &run, "--step", "p2"]);
    assert_eq!(exit, 0, "retry exit; stdout: {stdout}; stderr: {stderr}");
    assert_retry_authorization_survives(&fixture, &run, "p2");

    // The operator presents ONLY the corrected `branch`; the plan document,
    // the spine, the grant and the topology are derived daemon-side.
    let (exit, stdout, stderr) = run_cli(
        &fixture,
        &[
            "dispatch",
            "--run",
            &run,
            "--step",
            "p2",
            "--param",
            "branch=issue-92-retry-lane",
        ],
    );
    assert_eq!(exit, 0, "dispatch exit; stdout: {stdout}; stderr: {stderr}");
    let data = cli_envelope(&stdout)
        .get("data")
        .cloned()
        .expect("the dispatch document");
    assert_eq!(picked(&data, &["step", "kind"]), "worktree_create");
    assert_eq!(
        picked(&data, &["step", "params", "branch"]),
        "issue-92-retry-lane",
        "the presented step params are the merged ones: {stdout}"
    );
    assert_eq!(
        picked(&data, &["dispatch", "branch"]),
        "issue-92-retry-lane",
        "the EFFECT received the corrected branch: {stdout}"
    );
    // ...and the REAL worktree is on the corrected lane.
    let worktree = fixture.dir.join("worktrees").join("lane-p2");
    let head = Command::new("git")
        .args(["rev-parse", "--abbrev-ref", "HEAD"])
        .current_dir(&worktree)
        .output()
        .expect("git runs");
    assert!(head.status.success(), "the worktree exists: {worktree:?}");
    assert_eq!(
        String::from_utf8_lossy(&head.stdout).trim(),
        "issue-92-retry-lane",
        "the created worktree is on the operator's corrected branch"
    );

    shutdown(daemon);
}

#[test]
fn a_malformed_dispatch_refuses_typed_and_keeps_the_authorization_unconsumed() {
    let (fixture, daemon, run) = retry_lane_scenario("retry-bad");
    let before = attempts_for(&fixture, &run, "p2");

    let (exit, stdout, stderr) = run_cli(&fixture, &["retry", "--run", &run, "--step", "p2"]);
    assert_eq!(exit, 0, "retry exit; stdout: {stdout}; stderr: {stderr}");
    assert_retry_authorization_survives(&fixture, &run, "p2");

    // The malformed shape (no corrected `branch`) refuses typed BEFORE any
    // authorization is consumed and before any claim exists.
    let (exit, stdout, stderr) = run_cli(&fixture, &["dispatch", "--run", &run, "--step", "p2"]);
    assert_eq!(
        exit, 4,
        "malformed dispatch exit; stdout: {stdout}; stderr: {stderr}"
    );
    assert!(
        stderr.contains("refusal.request.malformed"),
        "the refusal is typed: {stderr}"
    );
    assert!(
        stderr.contains("worktree_create requires a slug branch"),
        "the reason is the effect's own contract: {stderr}"
    );
    let state = fixture.seed();
    let retries = state.run_retries(&run).expect("retries");
    assert!(
        retries.iter().all(|retry| retry.consumed_at.is_empty()),
        "the refused request burns nothing: {retries:?}"
    );
    assert_eq!(
        attempts_for(&fixture, &run, "p2"),
        before,
        "the refused request dispatches nothing"
    );

    // The corrected dispatch then succeeds and consumes exactly one — here
    // through the HUMAN rendering (no `--json`), so the non-JSON surface of
    // the new command is exercised as well.
    let socket_arg = fixture.socket.display().to_string();
    let (exit, stdout, stderr) = cli(
        &fixture,
        &[
            "run",
            "dispatch",
            "--run",
            &run,
            "--step",
            "p2",
            "--param",
            "branch=issue-92-retry-lane",
            "--socket",
            &socket_arg,
        ],
    );
    assert_eq!(exit, 0, "dispatch exit; stdout: {stdout}; stderr: {stderr}");
    assert!(
        stdout.contains("dispatch: step p2 (worktree_create)"),
        "the human rendering names the dispatched step: {stdout}"
    );
    let retries = fixture.seed().run_retries(&run).expect("retries");
    assert_eq!(
        retries
            .iter()
            .filter(|retry| !retry.consumed_at.is_empty())
            .count(),
        1,
        "exactly one authorization consumed: {retries:?}"
    );

    shutdown(daemon);
}

// ---------------------------------------------------------------------------
// Issue #92 F7: the fail-closed pre-screen is TOTAL over the step kinds
// ---------------------------------------------------------------------------

/// One parameterised case of the F7 regression: ONE fixture shape driven over
/// a different step kind, because the earlier suite pinned `worktree_create`
/// alone and the authorization burn survived on every other kind — the
/// reviewer's witness was `collect_outcome` with the required `worktree`
/// missing (`refusal.request.malformed`), whose single-use authorization was
/// burned by the malformed re-dispatch, making the operator's corrected
/// dispatch refuse `retry_required`.
struct ParamCase {
    /// The step kind under test (fixture label + assertion text).
    kind: &'static str,
    /// The run's committed spine: `p1` (well-formed, the caller dispatches it)
    /// plus `p2` (the malformed shape this case diagnoses).
    steps: Vec<qp::PlannedStep>,
    /// The effect's OWN reason for refusing the malformed shape.
    reason: &'static str,
    /// The operator's correction (`--param KEY=VALUE`).
    correction: Vec<&'static str>,
}

/// The parameterised cases: the reviewer's `collect_outcome` witness, the
/// pre-existing `worktree_create` shape, and the multi-key `hosted_check`
/// shape whose correction needs more than one `--param`.
fn param_cases() -> Vec<ParamCase> {
    let step = |id: &str, kind: &str, params: Val| qp::PlannedStep {
        id: id.to_string(),
        kind: kind.to_string(),
        params: Some(params),
    };
    vec![
        ParamCase {
            kind: "worktree_create",
            steps: vec![
                step("p1", "checkout", object(vec![("ref", string("staging"))])),
                // The required `branch` is missing (the committed shape).
                step(
                    "p2",
                    "worktree_create",
                    object(vec![("worktree", string("lane-p2"))]),
                ),
            ],
            reason: "worktree_create requires a slug branch",
            correction: vec!["branch=issue-92-f7-lane"],
        },
        ParamCase {
            kind: "collect_outcome",
            steps: vec![
                // `p1` creates the lane `p2` collects from, so the CORRECTED
                // dispatch has a real worktree to read.
                step(
                    "p1",
                    "worktree_create",
                    object(vec![
                        ("branch", string("issue-92-f7-lane")),
                        ("worktree", string("lane-p2")),
                    ]),
                ),
                // The witness shape: the required `worktree` is missing.
                step("p2", "collect_outcome", object(vec![])),
            ],
            reason: "step params missing \"worktree\"",
            correction: vec!["worktree=lane-p2"],
        },
        ParamCase {
            kind: "hosted_check",
            steps: vec![
                step("p1", "checkout", object(vec![("ref", string("staging"))])),
                // A multi-key correction: no repo, no number.
                step("p2", "hosted_check", object(vec![])),
            ],
            reason: "hosted_check requires an owner/name repo",
            correction: vec!["repo=example-org/widgets", "number=33"],
        },
    ]
}

/// Drive ONE case end to end with supervision OFF — every dispatch is the
/// operator's own:
///
///   1. the caller's first attempt at `p2` carries the committed malformed
///      params, refuses typed (`refusal.request.malformed`, the effect's own
///      reason) and records the diagnosis `run retry` addresses;
///   2. `canter run retry` mints the single-use authorization;
///   3. the SAME malformed dispatch through the supported surface refuses
///      typed and consumes NOTHING (at 43abbc9d only worktree_create was
///      screened, so this step burned the authorization for every other kind
///      and the operator's correction was refused `retry_required`);
///   4. the corrected dispatch succeeds and consumes the authorization
///      exactly once.
fn run_param_case(case: &ParamCase) {
    // One `ik_`-safe label per kind (the key vocabulary is [a-z0-9-] only).
    let label = format!("f7-{}", case.kind.replace('_', "-"));
    let fixture = DaemonFixture::new(&label);
    let (bound, digest) = {
        let state = fixture.seed();
        seed_grant(&state, "gr_0000000000000095", 5);
        let mut request = request_lane_steps(vec![selected("#5", REV_A)]);
        request.steps = case.steps.clone();
        render_bound(&state, &request)
    };
    let integration = fixture.dir.join("integration");
    init_repo(&integration);
    let fakebin = write_fake_gh(&fixture.dir);
    let host_path = std::env::var("PATH").unwrap_or_default();
    let daemon = fixture.spawn_with_path(&format!("{}:{host_path}", fakebin.display()));
    wait_ready(&fixture);

    // Supervision is OFF: nothing but the operator dispatches this run.
    let params = params_doc(
        &idem_key(&label),
        &bound,
        &digest,
        &role_revision(),
        "gr_0000000000000095",
        None,
    );
    let result = rpc_ok(&fixture.socket, &fresh_id(1), "queue.submit", Some(params));
    let run = instance_of(&result, 5);
    let applied = rpc_ok(
        &fixture.socket,
        &fresh_id(2),
        "apply",
        Some(caller_apply_params(
            &fixture,
            &integration,
            &bound,
            &run,
            "gr_0000000000000095",
            ("p1", 5),
            &idem_key(&format!("{label}-p1")),
        )),
    );
    assert!(
        applied.get("refused").is_none(),
        "p1 ({}) applied: {}",
        case.steps[0].kind,
        canter::canonical::canonical_text(&applied)
    );
    let p1 = fixture
        .seed()
        .run_step_attempts(&run)
        .expect("attempts")
        .into_iter()
        .find(|(step, _)| step == "p1")
        .unwrap_or_else(|| panic!("p1 recorded no attempt"));
    assert_eq!(p1.1, "succeeded", "p1 landed: {p1:?}");

    // (1) The operator's first attempt at p2 carries the malformed shape.
    let refusal = rpc_refusal(
        &fixture.socket,
        &fresh_id(3),
        "apply",
        Some(caller_apply_params(
            &fixture,
            &integration,
            &bound,
            &run,
            "gr_0000000000000095",
            ("p2", 5),
            &idem_key(&format!("{label}-p2-bad")),
        )),
    );
    assert!(
        refusal.contains("refusal.request.malformed"),
        "the first attempt refuses typed: {refusal}"
    );
    assert!(
        refusal.contains(case.reason),
        "the reason is the effect's own contract: {refusal}"
    );
    let attempts = fixture.seed().run_step_attempts(&run).expect("attempts");
    assert!(
        attempts
            .iter()
            .any(|(step, status)| step == "p2" && status == "refused"),
        "the first attempt is recorded as the diagnosis: {attempts:?}"
    );
    let diagnosed = attempts_for(&fixture, &run, "p2");

    // (2) `run retry` mints the bounded authorization — and nothing else.
    let (exit, stdout, stderr) = run_cli(&fixture, &["retry", "--run", &run, "--step", "p2"]);
    assert_eq!(exit, 0, "retry exit; stdout: {stdout}; stderr: {stderr}");
    assert_eq!(
        picked(&cli_envelope(&stdout), &["data", "retry", "status"]),
        "authorized",
        "the minted authorization is unconsumed: {stdout}"
    );

    // (3) The malformed dispatch through the supported surface: typed
    // refusal, no claim, no attempt, nothing burned.
    let (exit, stdout, stderr) = run_cli(&fixture, &["dispatch", "--run", &run, "--step", "p2"]);
    assert_eq!(
        exit, 4,
        "malformed {label} dispatch exit; stdout: {stdout}; stderr: {stderr}"
    );
    assert!(
        stderr.contains("refusal.request.malformed"),
        "the refusal is typed: {stderr}"
    );
    assert!(
        stderr.contains(case.reason),
        "the reason is the effect's own contract: {stderr}"
    );
    let retries = fixture.seed().run_retries(&run).expect("retries");
    assert!(
        retries.iter().all(|retry| retry.consumed_at.is_empty()),
        "the refused {label} dispatch burns nothing: {retries:?}"
    );
    assert_eq!(
        attempts_for(&fixture, &run, "p2"),
        diagnosed,
        "the refused {label} dispatch attempts nothing"
    );

    // (4) The corrected dispatch succeeds and consumes exactly once.
    let mut argv = vec!["dispatch", "--run", &run, "--step", "p2"];
    for correction in &case.correction {
        argv.push("--param");
        argv.push(correction);
    }
    let (exit, stdout, stderr) = run_cli(&fixture, &argv);
    assert_eq!(
        exit, 0,
        "corrected {label} dispatch exit; stdout: {stdout}; stderr: {stderr}"
    );
    let retries = fixture.seed().run_retries(&run).expect("retries");
    assert_eq!(
        retries
            .iter()
            .filter(|retry| !retry.consumed_at.is_empty())
            .count(),
        1,
        "exactly one {label} authorization consumed: {retries:?}"
    );
    let attempts = fixture.seed().run_step_attempts(&run).expect("attempts");
    assert!(
        attempts
            .iter()
            .any(|(step, status)| step == "p2" && status == "succeeded"),
        "the corrected {label} dispatch landed: {attempts:?}"
    );

    shutdown(daemon);
}

#[test]
fn every_kind_refuses_a_malformed_dispatch_before_the_authorization_is_burned() {
    for case in param_cases() {
        run_param_case(&case);
    }
}

// ---------------------------------------------------------------------------
// Issue #130: an uncontained worktree destination is refused BEFORE any git
// mutation by the same pre-fence screen — so it burns no bounded retry
// authorization, and no directory, worktree entry or branch is left behind.
// ---------------------------------------------------------------------------

/// The escape the review measured: resolved under the worktrees root,
/// `../escaped-lane` lands OUTSIDE it. The pre-fix check evaluated the
/// literal join, which cannot reveal the escape while the destination does
/// not exist yet, so `git worktree add` created the lane and the escape came
/// back as data (`contained: false`, exit 0).
const ESCAPING_WORKTREE: &str = "../escaped-lane";

/// One raw `git` invocation in a fixture repository.
fn git_output(repo: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .args(args)
        .current_dir(repo)
        .output()
        .expect("git runs");
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// The number of worktrees git reports for one repository.
fn worktree_count(repo: &Path) -> usize {
    git_output(repo, &["worktree", "list", "--porcelain"])
        .lines()
        .filter(|line| line.starts_with("worktree "))
        .count()
}

/// The branch names git reports for one repository.
fn branches_of(repo: &Path) -> String {
    git_output(
        repo,
        &["for-each-ref", "--format=%(refname:short)", "refs/heads"],
    )
}

#[test]
fn an_uncontained_worktree_dispatch_is_refused_before_any_git_mutation() {
    let fixture = DaemonFixture::new("uncontained-130");
    let (bound, digest) = {
        let state = fixture.seed();
        seed_grant(&state, "gr_0000000000000095", 5);
        render_bound(&state, &request_lane_steps(vec![selected("#5", REV_A)]))
    };
    let integration = fixture.dir.join("integration");
    init_repo(&integration);
    let fakebin = write_fake_gh(&fixture.dir);
    let host_path = std::env::var("PATH").unwrap_or_default();
    let daemon = fixture.spawn_with_path(&format!("{}:{host_path}", fakebin.display()));
    wait_ready(&fixture);

    // Supervision is OFF: every dispatch below is the operator's own.
    let params = params_doc(
        &idem_key("uncontained-130"),
        &bound,
        &digest,
        &role_revision(),
        "gr_0000000000000095",
        None,
    );
    let result = rpc_ok(&fixture.socket, &fresh_id(1), "queue.submit", Some(params));
    let run = instance_of(&result, 5);

    // `p1` (the checkout) records the run's durable dispatch context — the
    // topology every later dispatch is derived from.
    let applied = rpc_ok(
        &fixture.socket,
        &fresh_id(2),
        "apply",
        Some(caller_apply_params(
            &fixture,
            &integration,
            &bound,
            &run,
            "gr_0000000000000095",
            ("p1", 5),
            &idem_key("uncontained-130-p1"),
        )),
    );
    assert!(
        applied.get("integration_base").is_some(),
        "the checkout read back: {}",
        canter::canonical::canonical_text(&applied)
    );

    // The diagnosis a bounded retry authorization addresses: `p2`'s committed
    // params carry no `branch`, so the operator may authorize one re-dispatch.
    let refusal = rpc_refusal(
        &fixture.socket,
        &fresh_id(3),
        "apply",
        Some(caller_apply_params(
            &fixture,
            &integration,
            &bound,
            &run,
            "gr_0000000000000095",
            ("p2", 5),
            &idem_key("uncontained-130-p2-diagnosis"),
        )),
    );
    assert!(
        refusal.contains("worktree_create requires a slug branch"),
        "the diagnosis is the effect's own contract: {refusal}"
    );
    let diagnosed = attempts_for(&fixture, &run, "p2");
    assert!(diagnosed > 0, "the diagnosis is recorded: {diagnosed}");
    let (exit, stdout, stderr) = run_cli(&fixture, &["retry", "--run", &run, "--step", "p2"]);
    assert_eq!(exit, 0, "retry exit; stdout: {stdout}; stderr: {stderr}");

    // (1) The ESCAPING dispatch: refused typed BEFORE any git mutation, with
    // the operator's authorization left UNCONSUMED (the refusal is raised by
    // the pre-fence screen, not by the fence).
    let (exit, stdout, stderr) = run_cli(
        &fixture,
        &[
            "dispatch",
            "--run",
            &run,
            "--step",
            "p2",
            "--param",
            "branch=issue-130-escaped-lane",
            "--param",
            &format!("worktree={ESCAPING_WORKTREE}"),
        ],
    );
    assert_eq!(
        exit, 4,
        "escaping dispatch exit; stdout: {stdout}; stderr: {stderr}"
    );
    assert!(
        stderr.contains("refusal.path.uncontained"),
        "the refusal is the containment code: {stderr}"
    );

    // No directory, no worktree entry and no branch may be left behind.
    let escaped = fixture.dir.join("escaped-lane");
    assert!(
        !escaped.exists(),
        "nothing is created outside the worktrees root: {escaped:?}"
    );
    assert_eq!(
        worktree_count(&integration),
        1,
        "the integration checkout stays the only worktree: {}",
        git_output(&integration, &["worktree", "list", "--porcelain"])
    );
    let branches = branches_of(&integration);
    assert!(
        !branches.contains("issue-130-escaped-lane"),
        "no escaping branch exists: {branches}"
    );

    // Nothing burned, nothing attempted.
    let retries = fixture.seed().run_retries(&run).expect("retries");
    assert_eq!(retries.len(), 1, "still exactly one authorization");
    assert!(
        retries.iter().all(|retry| retry.consumed_at.is_empty()),
        "the refused dispatch consumes no authorization: {retries:?}"
    );
    assert_eq!(
        attempts_for(&fixture, &run, "p2"),
        diagnosed,
        "the refused dispatch attempts nothing"
    );

    // (2) The legitimate in-root shape still succeeds, reports
    // `contained: true`, and consumes exactly the one authorization.
    let (exit, stdout, stderr) = run_cli(
        &fixture,
        &[
            "dispatch",
            "--run",
            &run,
            "--step",
            "p2",
            "--param",
            "branch=issue-130-lane",
            "--param",
            "worktree=issues/130",
        ],
    );
    assert_eq!(
        exit, 0,
        "in-root dispatch exit; stdout: {stdout}; stderr: {stderr}"
    );
    let data = cli_envelope(&stdout)
        .get("data")
        .cloned()
        .expect("the dispatch document");
    assert_eq!(
        path_of(&data, &["dispatch", "contained"]),
        Val::Bool(true),
        "the in-root lane reports containment: {stdout}"
    );
    let lane = fixture.dir.join("worktrees").join("issues").join("130");
    assert!(lane.exists(), "the in-root lane exists: {lane:?}");
    assert_eq!(
        git_output(&lane, &["rev-parse", "--abbrev-ref", "HEAD"]).trim(),
        "issue-130-lane",
        "the lane carries the operator's branch"
    );
    assert_eq!(
        worktree_count(&integration),
        2,
        "the lane is a real worktree: {}",
        git_output(&integration, &["worktree", "list", "--porcelain"])
    );
    let retries = fixture.seed().run_retries(&run).expect("retries");
    assert_eq!(
        retries
            .iter()
            .filter(|retry| !retry.consumed_at.is_empty())
            .count(),
        1,
        "the corrected dispatch consumes exactly one: {retries:?}"
    );
    let attempts = fixture.seed().run_step_attempts(&run).expect("attempts");
    assert!(
        attempts
            .iter()
            .any(|(step, status)| step == "p2" && status == "succeeded"),
        "the corrected dispatch landed: {attempts:?}"
    );

    shutdown(daemon);
}

// ---------------------------------------------------------------------------
// Issue #92 F2: the role-bound session lifecycle on the run's own path
// ---------------------------------------------------------------------------

/// A fake `hermes` that refuses any row other than the documented role-bound
/// prompt row: the run's declared role key (`-p <key>`), the declared
/// provider/model binding, and the session the run's `harness_start` bound
/// (`chat --continue <session> --create-if-missing`), payload last. Its real
/// stdout carries the session it ran under, so the transcript proves which
/// session the child was given.
fn write_fake_hermes(dir: &Path) -> PathBuf {
    let bin = dir.join("fakebin-hermes");
    std::fs::create_dir_all(&bin).expect("bin dir");
    let path = bin.join("hermes");
    std::fs::write(
        &path,
        "#!/bin/sh\n\
         printf '%s\\n' \"$@\" > argv.txt\n\
         [ \"$1\" = \"-p\" ] && [ \"$2\" = \"lane-1\" ] || { echo \"bad role: $*\" >&2; exit 7; }\n\
         [ \"$3\" = \"--provider\" ] && [ \"$4\" = \"provider-a\" ] || { echo \"bad provider: $*\" >&2; exit 8; }\n\
         [ \"$5\" = \"-m\" ] && [ \"$6\" = \"model-a\" ] || { echo \"bad model: $*\" >&2; exit 9; }\n\
         [ \"$7\" = \"chat\" ] && [ \"$8\" = \"--continue\" ] || { echo \"bad row: $*\" >&2; exit 10; }\n\
         [ \"${10}\" = \"--create-if-missing\" ] && [ \"${11}\" = \"-q\" ] || { echo \"bad continue: $*\" >&2; exit 11; }\n\
         printf 'session:%s output:%s' \"$9\" \"${12}\"\n",
    )
    .expect("write fake hermes");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = std::fs::metadata(&path).expect("metadata").permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&path, permissions).expect("chmod");
    }
    bin
}

/// The reviewed role configuration of the harness-lifecycle fixture: a
/// `hermes` profile (the kind whose documented prompt row carries the role
/// key, the declared provider/model pair and the session continuation).
fn harness_binding_doc() -> Val {
    let mut binding = ProfileBinding {
        key: HARNESS.to_string(),
        kind: "hermes".to_string(),
        provider: "provider-a".to_string(),
        model: "model-a".to_string(),
        fallbacks: Vec::new(),
        configured_limits: Vec::new(),
        introspection: false,
        secrets: Vec::new(),
        revision: String::new(),
    };
    binding.revision = binding.revision_of();
    binding.to_doc()
}

fn harness_role_revision() -> String {
    harness_binding_doc()
        .get("revision")
        .and_then(Val::as_str)
        .expect("binding revision")
        .to_string()
}

/// `queue.submit` params under the fixture's own reviewed role configuration.
fn harness_submit_params(key: &str, bound: &Val, digest: &str, grant_id: &str) -> Val {
    let grants = vec![qx::ItemGrant {
        id: "#5".to_string(),
        grant_id: grant_id.to_string(),
    }];
    qx::submit_params(
        key,
        digest,
        1,
        bound,
        &harness_binding_doc(),
        &harness_role_revision(),
        ConcurrencyCaps {
            global: 4,
            per_repository: 2,
            per_harness: 2,
        },
        Some(true),
        Some(0),
        &grants,
        &[],
        None,
    )
}

/// The committed spine of the harness-lifecycle fixture: the lane worktree,
/// the run's session bind and the prompt that continues it.
fn harness_steps(harness_key: &str) -> Vec<qp::PlannedStep> {
    vec![
        qp::PlannedStep {
            id: "p1".to_string(),
            kind: "worktree_create".to_string(),
            params: Some(object(vec![
                ("branch", string("issue-5")),
                ("worktree", string("issues-5")),
            ])),
        },
        qp::PlannedStep {
            id: "p2".to_string(),
            kind: "harness_start".to_string(),
            params: Some(object(vec![
                ("harness_key", string(harness_key)),
                ("kind", string("hermes")),
            ])),
        },
        qp::PlannedStep {
            id: "p3".to_string(),
            kind: "prompt".to_string(),
            params: Some(object(vec![
                ("harness_key", string(harness_key)),
                ("kind", string("hermes")),
                ("worktree", string("issues-5")),
                ("payload", string("do the bounded work")),
            ])),
        },
        // A second bind step that names ANOTHER role: the run's committed role
        // configuration is the only profile any harness step runs under.
        qp::PlannedStep {
            id: "p4".to_string(),
            kind: "harness_start".to_string(),
            params: Some(object(vec![
                ("harness_key", string("lane-9")),
                ("kind", string("hermes")),
            ])),
        },
    ]
}

#[test]
fn the_prompt_runs_the_runs_declared_role_binding_and_continues_its_session() {
    let fixture = DaemonFixture::new("role-bound");
    let (bound, digest) = {
        let state = fixture.seed();
        seed_grant(&state, "gr_0000000000000095", 5);
        let request = qp::QueueRequest {
            steps: harness_steps("lane-1"),
            role_config: harness_binding_doc(),
            ..request_with(vec![selected("#5", REV_A)])
        };
        render_bound(&state, &request)
    };
    let integration = fixture.dir.join("integration");
    init_repo(&integration);
    let fakebin = write_fake_hermes(&fixture.dir);
    let host_path = std::env::var("PATH").unwrap_or_default();
    let daemon = fixture.spawn_with_path(&format!("{}:{host_path}", fakebin.display()));
    wait_ready(&fixture);

    let params = harness_submit_params(
        &idem_key("role-bound"),
        &bound,
        &digest,
        "gr_0000000000000095",
    );
    let result = rpc_ok(&fixture.socket, &fresh_id(1), "queue.submit", Some(params));
    let run = instance_of(&result, 5);
    let session = canter::mutation::run_session_handle(&run)
        .expect("the run session derives")
        .session_id;
    assert!(session.starts_with("lane-"), "{session}");

    let steps = bound.get("steps").cloned().unwrap_or_else(null);
    let apply = |seed: u64, step: &str, plan: Val, key: String| {
        rpc(
            &fixture.socket,
            &fresh_id(seed),
            "apply",
            Some({
                let mut params = caller_apply_params(
                    &fixture,
                    &integration,
                    &bound,
                    &run,
                    "gr_0000000000000095",
                    (step, 5),
                    &key,
                );
                if let Val::Obj(map) = &mut params {
                    map.insert("plan".to_string(), plan);
                    map.insert("profile".to_string(), harness_binding_doc());
                }
                params
            }),
        )
    };

    // The lane worktree first (the prompt's containment fence reads it).
    let lane = apply(
        2,
        "p1",
        plan_doc_with_steps(steps.clone(), 5),
        idem_key("role-lane-0001"),
    );
    assert_eq!(
        lane.get("ok").and_then(Val::as_bool),
        Some(true),
        "{}",
        canter::canonical::canonical_text(&lane)
    );

    // A prompt BEFORE the run bound a session is refused: the prompt
    // continues the session `harness_start` bound and never binds one.
    let early = apply(
        3,
        "p3",
        plan_doc_with_steps(steps.clone(), 5),
        idem_key("role-early-0001"),
    );
    assert_eq!(
        early
            .get("error")
            .and_then(|error| error.get("code"))
            .and_then(Val::as_str),
        Some("refusal.session.unbound"),
        "{}",
        canter::canonical::canonical_text(&early)
    );

    // A harness step naming another role binding is refused: the run's
    // committed role configuration is the only profile it runs under.
    let wrong = apply(
        4,
        "p4",
        plan_doc_with_steps(steps.clone(), 5),
        idem_key("role-wrong-0001"),
    );
    assert_eq!(
        wrong
            .get("error")
            .and_then(|error| error.get("code"))
            .and_then(Val::as_str),
        Some("refusal.profile.binding"),
        "{}",
        canter::canonical::canonical_text(&wrong)
    );

    // The session bind of the run's declared role configuration.
    let started = rpc_ok(
        &fixture.socket,
        &fresh_id(5),
        "apply",
        Some({
            let mut params = caller_apply_params(
                &fixture,
                &integration,
                &bound,
                &run,
                "gr_0000000000000095",
                ("p2", 5),
                &idem_key("role-bind-0001"),
            );
            if let Val::Obj(map) = &mut params {
                map.insert("plan".to_string(), plan_doc_with_steps(steps.clone(), 5));
                map.insert("profile".to_string(), harness_binding_doc());
            }
            params
        }),
    );
    assert_eq!(
        started.get("session_id").and_then(Val::as_str),
        Some(session.as_str()),
        "the start bound the run's session: {}",
        canter::canonical::canonical_text(&started)
    );
    assert_eq!(
        started.get("role_key").and_then(Val::as_str),
        Some("lane-1")
    );
    assert_eq!(
        started.get("role_revision").and_then(Val::as_str),
        Some(harness_role_revision().as_str())
    );

    // The prompt continues that exact session, runs the declared role
    // binding, and records the child's REAL stdout as the step result.
    let prompted = rpc_ok(
        &fixture.socket,
        &fresh_id(6),
        "apply",
        Some({
            let mut params = caller_apply_params(
                &fixture,
                &integration,
                &bound,
                &run,
                "gr_0000000000000095",
                ("p3", 5),
                &idem_key("role-prompt-0001"),
            );
            if let Val::Obj(map) = &mut params {
                map.insert("plan".to_string(), plan_doc_with_steps(steps.clone(), 5));
                map.insert("profile".to_string(), harness_binding_doc());
            }
            params
        }),
    );
    assert_eq!(
        prompted.get("session_id").and_then(Val::as_str),
        Some(session.as_str()),
        "the prompt continued the bound session"
    );
    assert_eq!(
        prompted.get("transcript").and_then(Val::as_str),
        Some(format!("session:{session} output:do the bounded work").as_str()),
        "the real child stdout is the step result: {}",
        canter::canonical::canonical_text(&prompted)
    );
    // AC-F1 (issue #92) visibility clause, pinned: the EFFECTIVE deadline
    // the effect used rides on the step outcome, so a step can never report
    // a result without the deadline it ran under. This prompt declares no
    // `deadline_secs`, so the documented per-kind default must be the value.
    assert_eq!(
        prompted.get("deadline_secs").and_then(Val::as_int),
        Some(canter::mutation::PROMPT_DEADLINE_DEFAULT_SECS as i64),
        "the effective deadline rides on the step outcome: {}",
        canter::canonical::canonical_text(&prompted)
    );

    shutdown(daemon);
}
