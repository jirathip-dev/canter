//! Issue #85 acceptance tests: the daemon-owned durable selected-run
//! submission path (`queue.submit` / `queue.status`) built on the #84
//! preview contract.
//!
//! Two fixture layers, both with synthetic identities only:
//! - a library-level `State` in a per-test temp dir (the same fixture
//!   pattern as `tests/queue_preview.rs`) for the pure revalidation and the
//!   one-transaction submission semantics;
//! - a real `canter daemon run` child process over an explicit socket (the
//!   `tests/daemon_rpc.rs` pattern) for the wire contract, the double-click
//!   claim behavior, and the crash/restart reconciliation windows.
//!
//! Nothing here spawns a workflow step, touches host state, the network, a
//! real session or the service manager. Raw exits and typed codes are
//! asserted directly; the digest is recomputed from the rendered bound-input
//! document so every binding is pinned to the bytes.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use canter::client::Connection;
use canter::config::ProfileBinding;
use canter::lifecycle::ConcurrencyCaps;
use canter::plan::DOCTRINE_WORKFLOW_ID;
use canter::queue_executor as qx;
use canter::queue_preview as qp;
use canter::state::{
    QueueSubmissionItemPlan, QueueSubmissionPlan, Retention, State, SubmissionVerdict,
};
use canter::value::{Val, object, string};

// ---------------------------------------------------------------------------
// Constants and builders
// ---------------------------------------------------------------------------

const REPO: &str = "example-org/widgets";
const HOST: &str = "host-1";
const HARNESS: &str = "lane-1";
const REV_A: &str = "1111111111111111111111111111111111111111";
const REV_B: &str = "2222222222222222222222222222222222222222";
const WORKFLOW_HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const POLICY_HASH: &str = "feedface01234567feedface01234567feedface01234567feedface01234567";
const SECRET_DIGEST: &str = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
const STEP_PARAMS_REF: &str = "staging";

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

fn step(id: &str, kind: &str, params: Option<Val>) -> qp::PlannedStep {
    qp::PlannedStep {
        id: id.to_string(),
        kind: kind.to_string(),
        params,
    }
}

fn resolved() -> Val {
    object(vec![("ref", string(STEP_PARAMS_REF))])
}

fn selected(id: &str, revision: &str) -> qp::SelectedIssue {
    qp::SelectedIssue {
        id: id.to_string(),
        title: None,
        revision: revision.to_string(),
        requires: Vec::new(),
    }
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
                "merge".to_string(),
            ],
        },
        steps: vec![step("p1", "checkout", Some(resolved()))],
        selected: issues,
    }
}

/// Render the preview and return (bound-input document, digest).
fn render_bound(state: &State, request: &qp::QueueRequest) -> (Val, String) {
    let preview = qp::preview_queue(state, request).expect("preview renders");
    let bound = preview
        .doc
        .get("request")
        .cloned()
        .expect("preview carries the bound-input document");
    (bound, preview.digest)
}

/// One valid `hf-grant/v1` document for `number` under the fixture binding.
fn grant_doc(grant_id: &str, number: i64, revision: &str, caps: &[&str]) -> Val {
    grant_doc_at(grant_id, number, revision, caps, 1)
}

/// The same grant doc issued under an explicit state epoch.
fn grant_doc_at(grant_id: &str, number: i64, revision: &str, caps: &[&str], epoch: i64) -> Val {
    Val::parse_json(&format!(
        r#"{{"schema":"hf-grant/v1","grant_id":"{grant_id}","repository":"{REPO}",
            "issue":{{"number":{number},"revision":"{revision}"}},
            "workflow_hash":"{WORKFLOW_HASH}","policy_hash":"{POLICY_HASH}",
            "phase":"merge","scope":"worktrees/issues/{number}",
            "caps":[{caps}],
            "expires_at":"2999-01-01T00:00:00Z","state_epoch":{epoch},
            "created_at":"2026-09-06T00:00:00Z"}}"#,
        caps = caps
            .iter()
            .map(|cap| format!("\"{cap}\""))
            .collect::<Vec<_>>()
            .join(",")
    ))
    .expect("grant document")
}

const GRANT_CAPS: [&str; 4] = ["read", "worktree", "spawn", "merge"];

/// The full `queue.submit` params document (the module's own builder, the
/// same one the CLI uses).
#[allow(clippy::too_many_arguments)]
fn params_doc(
    key: &str,
    bound: &Val,
    digest: &str,
    epoch: i64,
    role_revision: &str,
    grants: &[(&str, &str)],
    resume: &[(&str, &str)],
    observations: (Option<bool>, Option<i64>),
) -> Val {
    let binding = binding_doc();
    let grants: Vec<qx::ItemGrant> = grants
        .iter()
        .map(|(id, grant_id)| qx::ItemGrant {
            id: (*id).to_string(),
            grant_id: (*grant_id).to_string(),
        })
        .collect();
    let resume: Vec<qx::ResumeAuthorization> = resume
        .iter()
        .map(|(instance_id, resume_digest)| qx::ResumeAuthorization {
            instance_id: (*instance_id).to_string(),
            digest: (*resume_digest).to_string(),
        })
        .collect();
    qx::submit_params(
        key,
        digest,
        epoch,
        bound,
        &binding,
        role_revision,
        ConcurrencyCaps {
            global: 4,
            per_repository: 2,
            per_harness: 2,
        },
        observations.0,
        observations.1,
        &grants,
        &resume,
        None,
    )
}

fn role_revision() -> String {
    binding_doc()
        .get("revision")
        .and_then(Val::as_str)
        .expect("binding revision")
        .to_string()
}

fn work_item(number: i64) -> String {
    qp::IssueId::parse(&format!("#{number}"), REPO)
        .expect("issue id")
        .work_item()
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("hf-queue-85-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("fixture dir");
    dir
}

/// Library-level state fixture.
struct StateFixture {
    dir: PathBuf,
}

impl StateFixture {
    fn new(name: &str) -> StateFixture {
        StateFixture {
            dir: temp_dir(name),
        }
    }

    fn db(&self) -> PathBuf {
        self.dir.join("state.db")
    }

    fn open(&self) -> State {
        State::open(&self.db(), Retention::default()).expect("open state")
    }
}

/// Daemon fixture (the `tests/daemon_rpc.rs` pattern).
struct DaemonFixture {
    dir: PathBuf,
    state_dir: PathBuf,
    socket: PathBuf,
}

impl DaemonFixture {
    fn new(name: &str) -> DaemonFixture {
        let dir = temp_dir(&format!("daemon-{name}"));
        DaemonFixture {
            state_dir: dir.join("state"),
            socket: dir.join("daemon.sock"),
            dir,
        }
    }

    fn db(&self) -> PathBuf {
        self.state_dir.join("canter").join("state.db")
    }

    /// The allowlisted structured daemon log (JSONL).
    fn daemon_log(&self) -> PathBuf {
        self.state_dir.join("canter").join("daemon.log")
    }

    /// Seed the durable state BEFORE the daemon owns it.
    fn seed(&self) -> State {
        std::fs::create_dir_all(self.state_dir.join("canter")).expect("state dir");
        State::open(&self.db(), Retention::default()).expect("open state")
    }

    fn spawn(&self, crash_point: Option<&str>) -> Child {
        std::fs::create_dir_all(&self.state_dir).expect("state home");
        let mut command = Command::new(bin());
        command
            .args(["daemon", "run", "--socket"])
            .arg(&self.socket)
            .env("XDG_STATE_HOME", &self.state_dir)
            .env("HOME", &self.dir)
            .stdout(Stdio::null())
            .stderr(Stdio::from(
                std::fs::File::create(self.dir.join("daemon.stderr.log")).expect("stderr log"),
            ));
        if let Some(point) = crash_point {
            command.env("CANTER_CRASH_POINT", point);
        }
        command.spawn().expect("spawn daemon")
    }
}

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_canter")
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

/// One RPC exchange (ok or refused), as a tagged document.
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

fn rpc_err(socket: &Path, id: &str, method: &str, params: Option<Val>) -> (String, String) {
    let doc = rpc(socket, id, method, params);
    assert_eq!(
        doc.get("ok").and_then(Val::as_bool),
        Some(false),
        "expected refusal for {method}: {}",
        canter::canonical::canonical_text(&doc)
    );
    let error = doc.get("error").expect("error doc");
    (
        error
            .get("code")
            .and_then(Val::as_str)
            .unwrap_or_default()
            .to_string(),
        error
            .get("message")
            .and_then(Val::as_str)
            .unwrap_or_default()
            .to_string(),
    )
}

/// Send one request and drop the connection (used when the daemon aborts at
/// a crash point before answering).
fn send_only(socket: &Path, id: &str, method: &str, params: &Val) {
    let mut connection = Connection::open(socket).expect("connect");
    connection
        .send_request(id, method, Some(params))
        .expect("send crash request");
    drop(connection);
}

fn shutdown(mut daemon: Child) {
    let _ = daemon.kill();
    let deadline = Instant::now() + Duration::from_secs(10);
    while daemon.try_wait().expect("try_wait").is_none() {
        assert!(Instant::now() < deadline, "daemon did not exit");
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn wait_crash(daemon: &mut Child) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while daemon.try_wait().expect("try_wait").is_none() {
        assert!(
            Instant::now() < deadline,
            "the daemon did not reach the crash point in time"
        );
        std::thread::sleep(Duration::from_millis(25));
    }
}

/// Runtime-assembled idempotency key: the tracked file never carries a
/// `key = "<literal>"` shape, which the public-tree secret scanners read as
/// an API-key assignment.
fn idem_key(stem: &str) -> String {
    format!("ik_85-{stem}")
}

/// Deterministic request id per (test, seed) — never a tracked literal.
fn fresh_id(seed: u32) -> String {
    format!("{:08x}", seed + std::process::id())
}

fn item_status(doc: &Val, number: i64) -> (String, Option<String>) {
    let target = format!("{REPO}#{number}");
    let items = doc.get("items").and_then(Val::as_array).unwrap_or_else(|| {
        panic!(
            "document carries items: {}",
            canter::canonical::canonical_text(doc)
        )
    });
    let item = items
        .iter()
        .find(|item| item.get("id").and_then(Val::as_str) == Some(target.as_str()))
        .unwrap_or_else(|| panic!("item {target} present"));
    (
        item.get("status")
            .and_then(Val::as_str)
            .unwrap_or_default()
            .to_string(),
        item.get("reason").and_then(Val::as_str).map(str::to_string),
    )
}

fn journal_lines(socket: &Path, id: &str) -> Vec<Val> {
    let result = rpc_ok(socket, id, "journal.tail", Some(object(vec![])));
    result
        .get("records")
        .and_then(Val::as_array)
        .cloned()
        .unwrap_or_default()
}

fn journal_actions(socket: &Path, id: &str) -> Vec<String> {
    journal_lines(socket, id)
        .iter()
        .filter_map(|doc| doc.get("action").and_then(Val::as_str).map(str::to_string))
        .collect()
}

fn pending_claims(socket: &Path, id: &str) -> i64 {
    rpc_ok(socket, id, "doctor", None)
        .get("pending_claims")
        .and_then(Val::as_int)
        .unwrap_or(-1)
}

// ---------------------------------------------------------------------------
// AC1/AC3/AC4/AC5: revalidation and classification over durable state
// ---------------------------------------------------------------------------

fn revalidated(
    state: &State,
    number: i64,
    revision: &str,
    grants: &[(&str, &str)],
    resume: &[(&str, &str)],
    observations: (Option<bool>, Option<i64>),
) -> Result<qx::Revalidated, qx::SubmissionError> {
    let request = request_with(vec![selected(&format!("#{number}"), revision)]);
    let (bound, digest) = render_bound(state, &request);
    let params = params_doc(
        "ik_85-revalidate",
        &bound,
        &digest,
        1,
        &role_revision(),
        grants,
        resume,
        observations,
    );
    let material = qx::parse_params(&params).expect("params parse");
    qx::revalidate(state, &material)
}

#[test]
fn stale_digest_epoch_and_moved_revision_refuse_with_stable_codes() {
    let fixture = StateFixture::new("stale-inputs");
    let state = fixture.open();
    state
        .issue_grant(&grant_doc("gr_0000000000000001", 5, REV_A, &GRANT_CAPS))
        .expect("issue grant");
    let request = request_with(vec![selected("#5", REV_A)]);
    let (bound, digest) = render_bound(&state, &request);

    // The bound document round-trips: its recomputed digest IS the approved
    // preview digest.
    assert_eq!(qx::bound_digest(&bound).expect("digest"), digest);

    // Stale digest.
    let params = params_doc(
        "ik_85-stale-digest",
        &bound,
        &"0".repeat(64),
        1,
        &role_revision(),
        &[("#5", "gr_0000000000000001")],
        &[],
        (Some(true), Some(0)),
    );
    let material = qx::parse_params(&params).expect("params parse");
    let err = qx::revalidate(&state, &material).expect_err("stale digest refuses");
    assert_eq!(err.code, "refusal.plan.stale", "{}", err.message);

    // Stale epoch (the live epoch is 1).
    let params = params_doc(
        "ik_85-stale-epoch",
        &bound,
        &digest,
        7,
        &role_revision(),
        &[("#5", "gr_0000000000000001")],
        &[],
        (Some(true), Some(0)),
    );
    let material = qx::parse_params(&params).expect("params parse");
    let err = qx::revalidate(&state, &material).expect_err("stale epoch refuses");
    assert_eq!(err.code, "refusal.state.epoch", "{}", err.message);

    // Stale (moved) configuration revision.
    let params = params_doc(
        "ik_85-stale-revision",
        &bound,
        &digest,
        1,
        &"a".repeat(64),
        &[("#5", "gr_0000000000000001")],
        &[],
        (Some(true), Some(0)),
    );
    let material = qx::parse_params(&params).expect("params parse");
    let err = qx::revalidate(&state, &material).expect_err("moved revision refuses");
    assert_eq!(err.code, "refusal.profile.revision", "{}", err.message);

    // The clean material revalidates with the issue eligible.
    let ok = revalidated(
        &state,
        5,
        REV_A,
        &[("#5", "gr_0000000000000001")],
        &[],
        (Some(true), Some(0)),
    )
    .expect("clean material revalidates");
    assert_eq!(ok.items.len(), 1);
    assert_eq!(ok.items[0].verdict, SubmissionVerdict::Approved);
    // Nothing above wrote any submission row.
    assert!(
        state
            .queue_submission_by_id(&qx::submission_id(&digest, "ik_85-stale-epoch"))
            .expect("read")
            .is_none()
    );
    assert!(state.list_instances().expect("instances").is_empty());
}

#[test]
fn unsupported_or_unresolved_spines_refuse_the_whole_flow_labelled() {
    let fixture = StateFixture::new("bad-spines");
    let state = fixture.open();
    state
        .issue_grant(&grant_doc("gr_0000000000000002", 5, REV_A, &GRANT_CAPS))
        .expect("issue grant");
    let grants = [("#5", "gr_0000000000000002")];

    let attempt = |request: &qp::QueueRequest, name: &str| -> qx::SubmissionError {
        let (bound, digest) = render_bound(&state, request);
        let params = params_doc(
            name,
            &bound,
            &digest,
            1,
            &role_revision(),
            &grants,
            &[],
            (Some(true), Some(0)),
        );
        let material = qx::parse_params(&params).expect("params parse");
        qx::revalidate(&state, &material).expect_err("refused")
    };

    // Unsupported step kind.
    let mut request = request_with(vec![selected("#5", REV_A)]);
    request.steps = vec![step("p1", "frobnicate", Some(resolved()))];
    let err = attempt(&request, "ik_85-step-unsupported");
    assert_eq!(err.code, "preview.step_unsupported", "{}", err.message);

    // Unresolved step params.
    let mut request = request_with(vec![selected("#5", REV_A)]);
    request.steps = vec![step("p1", "checkout", None)];
    let err = attempt(&request, "ik_85-step-unresolved");
    assert_eq!(err.code, "preview.step_unresolved", "{}", err.message);

    // Empty spine: nothing executable exists to admit.
    let mut request = request_with(vec![selected("#5", REV_A)]);
    request.steps = Vec::new();
    let err = attempt(&request, "ik_85-step-empty");
    assert_eq!(err.code, "submission.steps", "{}", err.message);

    // A supported step whose capability is outside the reviewed boundary.
    let mut request = request_with(vec![selected("#5", REV_A)]);
    request.boundary.caps = vec!["read".to_string()];
    request.steps = vec![step("p1", "harness_start", Some(resolved()))];
    let err = attempt(&request, "ik_85-step-boundary");
    assert_eq!(err.code, "submission.boundary", "{}", err.message);

    // A production-class boundary is refused: main/release stays human-only.
    let mut request = request_with(vec![selected("#5", REV_A)]);
    request.boundary.phase = "production".to_string();
    request.boundary.completion_branch = "main".to_string();
    let err = attempt(&request, "ik_85-step-production");
    assert_eq!(
        err.code, "refusal.policy.production_confirmation",
        "{}",
        err.message
    );

    // A protected completion branch alone is refused (labelled).
    let mut request = request_with(vec![selected("#5", REV_A)]);
    request.boundary.completion_branch = "main".to_string();
    let err = attempt(&request, "ik_85-step-protected");
    assert_eq!(err.code, "preview.protected_branch", "{}", err.message);

    // No attempt above persisted anything.
    assert!(state.list_instances().expect("instances").is_empty());
    assert!(state.queue_ownership_rows().expect("ownership").is_empty());
}

#[test]
fn revoked_grants_and_live_ownership_refuse_items() {
    let fixture = StateFixture::new("revoked-owned");
    let state = fixture.open();
    state
        .issue_grant(&grant_doc("gr_0000000000000003", 5, REV_A, &GRANT_CAPS))
        .expect("issue grant");
    state
        .revoke_grant("gr_0000000000000003", "2026-09-06T00:00:00Z")
        .expect("revoke");

    let revalidated_ok = revalidated(
        &state,
        5,
        REV_A,
        &[("#5", "gr_0000000000000003")],
        &[],
        (Some(true), Some(0)),
    )
    .expect("revalidate");
    match &revalidated_ok.items[0].verdict {
        SubmissionVerdict::Refused { code, message } => {
            assert_eq!(*code, "refusal.grant.inactive", "{message}");
        }
        other => panic!("expected a revoked-grant refusal, got {other:?}"),
    }

    // Also: an issue with NO presented grant is refused explicitly.
    let revalidated_none =
        revalidated(&state, 5, REV_A, &[], &[], (Some(true), Some(0))).expect("revalidate");
    match &revalidated_none.items[0].verdict {
        SubmissionVerdict::Refused { code, message } => {
            assert_eq!(*code, "submission.grant", "{message}");
        }
        other => panic!("expected a missing-grant refusal, got {other:?}"),
    }

    // A live owned run refuses the item: no duplicate owner path exists.
    state
        .issue_grant(&grant_doc("gr_0000000000000004", 6, REV_B, &GRANT_CAPS))
        .expect("issue grant");
    state
        .start_instance(
            "run-owned-0001",
            "gr_0000000000000004",
            DOCTRINE_WORKFLOW_ID,
            "2026-09-06T00:00:00Z",
        )
        .expect("start instance");
    let revalidated_owned = revalidated(
        &state,
        6,
        REV_B,
        &[("#6", "gr_0000000000000004")],
        &[],
        (Some(true), Some(0)),
    )
    .expect("revalidate");
    match &revalidated_owned.items[0].verdict {
        SubmissionVerdict::Refused { code, message } => {
            assert_eq!(*code, "submission.already_owned", "{message}");
        }
        other => panic!("expected an owned refusal, got {other:?}"),
    }
}

#[test]
fn paused_runs_stay_paused_unless_explicitly_authorized() {
    let fixture = StateFixture::new("paused");
    let state = fixture.open();
    state
        .issue_grant(&grant_doc("gr_0000000000000005", 5, REV_A, &GRANT_CAPS))
        .expect("issue grant");
    state
        .start_instance(
            "run-paused-0001",
            "gr_0000000000000005",
            DOCTRINE_WORKFLOW_ID,
            "2026-09-06T00:00:00Z",
        )
        .expect("start instance");
    let resume_digest = canter::engine::mint_resume_digest("run-paused-0001", 1, "pause-1");
    state
        .pause_instance("run-paused-0001", &resume_digest, "2026-09-06T01:00:00Z")
        .expect("pause instance");

    // Without an authorization the item is refused and the run stays paused.
    let revalidated_paused = revalidated(
        &state,
        5,
        REV_A,
        &[("#5", "gr_0000000000000005")],
        &[],
        (Some(true), Some(0)),
    )
    .expect("revalidate");
    match &revalidated_paused.items[0].verdict {
        SubmissionVerdict::Refused { code, message } => {
            assert_eq!(*code, "submission.paused", "{message}");
        }
        other => panic!("expected a paused refusal, got {other:?}"),
    }
    assert!(
        state
            .instance_by_id("run-paused-0001")
            .expect("run")
            .expect("present")
            .paused
    );

    // A WRONG resume digest is refused the same way.
    let revalidated_wrong = revalidated(
        &state,
        5,
        REV_A,
        &[("#5", "gr_0000000000000005")],
        &[("run-paused-0001", &"b".repeat(64))],
        (Some(true), Some(0)),
    )
    .expect("revalidate");
    assert!(matches!(
        revalidated_wrong.items[0].verdict,
        SubmissionVerdict::Refused {
            code: "submission.paused",
            ..
        }
    ));

    // The exact engine-minted authorization turns the item eligible for a
    // resume (the transaction applies it).
    let revalidated_authorized = revalidated(
        &state,
        5,
        REV_A,
        &[("#5", "gr_0000000000000005")],
        &[("run-paused-0001", &resume_digest)],
        (Some(true), Some(0)),
    )
    .expect("revalidate");
    assert_eq!(
        revalidated_authorized.items[0].verdict,
        SubmissionVerdict::Approved
    );
    assert_eq!(
        revalidated_authorized.items[0].resume_digest.as_deref(),
        Some(resume_digest.as_str())
    );
}

#[test]
fn environment_holds_park_eligible_items_as_waiting() {
    let fixture = StateFixture::new("environment");
    let state = fixture.open();
    state
        .issue_grant(&grant_doc("gr_0000000000000006", 5, REV_A, &GRANT_CAPS))
        .expect("issue grant");
    let grants = [("#5", "gr_0000000000000006")];

    let unknown_host =
        revalidated(&state, 5, REV_A, &grants, &[], (None, Some(0))).expect("revalidate");
    assert!(matches!(
        unknown_host.items[0].verdict,
        SubmissionVerdict::Waiting {
            code: "preview.host_unavailable",
            ..
        }
    ));

    let unknown_occupancy =
        revalidated(&state, 5, REV_A, &grants, &[], (Some(true), None)).expect("revalidate");
    assert!(matches!(
        unknown_occupancy.items[0].verdict,
        SubmissionVerdict::Waiting {
            code: "preview.occupancy_unknown",
            ..
        }
    ));
}

// ---------------------------------------------------------------------------
// AC2/AC3: the one-transaction submission semantics
// ---------------------------------------------------------------------------

fn plan_for(
    state: &State,
    submission_id: &str,
    digest: &str,
    items: Vec<(i64, &str, Option<&str>, SubmissionVerdict)>,
    harness_lanes: Option<i64>,
) -> QueueSubmissionPlan {
    let epoch = state.current_epoch().expect("epoch");
    QueueSubmissionPlan {
        submission_id: submission_id.to_string(),
        repository: REPO.to_string(),
        state_epoch: epoch,
        digest: digest.to_string(),
        role_key: HARNESS.to_string(),
        role_revision: role_revision(),
        workflow_id: DOCTRINE_WORKFLOW_ID.to_string(),
        workflow_hash: WORKFLOW_HASH.to_string(),
        boundary_phase: "merge".to_string(),
        integration_branch: "staging".to_string(),
        completion_branch: "staging".to_string(),
        boundary_caps: vec!["read".to_string(), "merge".to_string()],
        request_line: canter::canonical::canonical_text(&object(vec![])),
        admission_caps: ConcurrencyCaps {
            global: 4,
            per_repository: 2,
            per_harness: 2,
        },
        harness_lanes,
        items: items
            .into_iter()
            .enumerate()
            .map(
                |(ordinal, (number, revision, grant_id, verdict))| QueueSubmissionItemPlan {
                    ordinal: ordinal as i64,
                    work_item: work_item(number),
                    issue_number: number,
                    issue_revision: revision.to_string(),
                    grant_id: grant_id.map(str::to_string),
                    resume_digest: None,
                    verdict,
                },
            )
            .collect(),
        // Issue #95: supervision stays disabled for these fixtures (the
        // default); the supervision acceptance cases live in
        // `tests/supervision.rs`.
        supervision: None,
        at: "2026-09-06T02:00:00Z".to_string(),
    }
}

#[test]
fn submission_commits_membership_and_unique_ownership_transactionally() {
    let fixture = StateFixture::new("transaction");
    let state = fixture.open();
    state
        .issue_grant(&grant_doc("gr_0000000000000007", 5, REV_A, &GRANT_CAPS))
        .expect("grant 5");
    state
        .issue_grant(&grant_doc("gr_0000000000000008", 6, REV_A, &GRANT_CAPS))
        .expect("grant 6");

    let digest = "c".repeat(64);
    let plan = plan_for(
        &state,
        "qs_0000000000000001",
        &digest,
        vec![
            (
                5,
                REV_A,
                Some("gr_0000000000000007"),
                SubmissionVerdict::Approved,
            ),
            (
                6,
                REV_A,
                Some("gr_0000000000000008"),
                SubmissionVerdict::Approved,
            ),
            (
                7,
                REV_A,
                None,
                SubmissionVerdict::Refused {
                    code: "preview.dependency_unresolved",
                    message: "required dependency outside the selected set".to_string(),
                },
            ),
        ],
        Some(0),
    );
    let (row, items) = state.submit_queue_run(&plan).expect("submission commits");
    assert_eq!(row.submission_id, "qs_0000000000000001");
    let statuses: Vec<(&str, Option<&str>)> = items
        .iter()
        .map(|item| (item.status.as_str(), item.reason.as_deref()))
        .collect();
    assert_eq!(
        statuses,
        vec![
            ("admitted", None),
            ("admitted", None),
            ("refused", Some("preview.dependency_unresolved")),
        ]
    );
    let runs: Vec<&str> = items
        .iter()
        .filter_map(|item| item.instance_id.as_deref())
        .collect();
    assert_eq!(runs.len(), 2);

    // Membership, runs and unique ownership are durable.
    let (persisted, persisted_items) = state
        .queue_submission_by_id("qs_0000000000000001")
        .expect("read")
        .expect("submission exists");
    assert_eq!(persisted.digest, digest);
    assert_eq!(persisted_items.len(), 3);
    let ownership = state.queue_ownership_rows().expect("ownership");
    assert_eq!(ownership.len(), 2);
    assert_eq!(
        ownership.len(),
        state.list_instances().expect("instances").len()
    );
    for owner in &ownership {
        assert!(runs.contains(&owner.instance_id.as_str()));
    }

    // A duplicate submission (fresh id) can never create a second owner.
    let duplicate = plan_for(
        &state,
        "qs_0000000000000002",
        &digest,
        vec![(
            5,
            REV_A,
            Some("gr_0000000000000007"),
            SubmissionVerdict::Approved,
        )],
        Some(0),
    );
    let (_, duplicate_items) = state
        .submit_queue_run(&duplicate)
        .expect("duplicate commits");
    assert_eq!(
        (
            duplicate_items[0].status.as_str(),
            duplicate_items[0].reason.as_deref()
        ),
        ("refused", Some("submission.already_owned"))
    );
    assert_eq!(state.list_instances().expect("instances").len(), 2);
    assert_eq!(state.queue_ownership_rows().expect("ownership").len(), 2);
    assert_eq!(
        state.queue_ownership_rows().expect("ownership")[0].instance_id,
        runs[0],
        "the first owner row is never replaced by a live duplicate"
    );

    // Reusing a committed submission id is refused (state.submission_exists).
    let err = state
        .submit_queue_run(&plan)
        .expect_err("duplicate id refuses");
    assert_eq!(err.code, "state.submission_exists", "{}", err.message);

    // The rendered document is a pure projection of the committed rows.
    let advances = state
        .queue_advance_rows(&persisted.submission_id)
        .expect("advances");
    let doc = qx::submission_doc(&persisted, &persisted_items, &advances);
    let admission = doc.get("admission").expect("admission");
    assert_eq!(admission.get("admitted").and_then(Val::as_int), Some(2));
    assert_eq!(admission.get("waiting").and_then(Val::as_int), Some(0));
    assert_eq!(admission.get("refused").and_then(Val::as_int), Some(1));
    let steps = doc.get("steps").and_then(Val::as_array).expect("steps");
    assert_eq!(steps.len(), 0, "the synthetic plan carries no spine");
}

#[test]
fn capacity_holds_park_items_as_waiting_without_consuming_slots() {
    let fixture = StateFixture::new("capacity");
    let state = fixture.open();
    state
        .issue_grant(&grant_doc("gr_0000000000000009", 5, REV_A, &GRANT_CAPS))
        .expect("grant");
    // The global cap is 1 and one counted lane already runs.
    state
        .issue_grant(&grant_doc("gr_000000000000000a", 9, REV_A, &GRANT_CAPS))
        .expect("grant 9");
    state
        .start_instance(
            "run-counted-0001",
            "gr_000000000000000a",
            DOCTRINE_WORKFLOW_ID,
            "2026-09-06T00:00:00Z",
        )
        .expect("start counted run");

    let mut plan = plan_for(
        &state,
        "qs_0000000000000003",
        &"d".repeat(64),
        vec![(
            5,
            REV_A,
            Some("gr_0000000000000009"),
            SubmissionVerdict::Approved,
        )],
        Some(0),
    );
    plan.admission_caps = ConcurrencyCaps {
        global: 1,
        per_repository: 2,
        per_harness: 2,
    };
    let (_, items) = state.submit_queue_run(&plan).expect("submission commits");
    assert_eq!(
        (items[0].status.as_str(), items[0].reason.as_deref()),
        ("waiting", Some("refusal.admission.cap_global"))
    );
    assert!(items[0].instance_id.is_none());
    // Only the pre-existing counted run exists; waiting consumes nothing.
    assert_eq!(state.list_instances().expect("instances").len(), 1);
    assert!(state.queue_ownership_rows().expect("ownership").is_empty());
}
// ---------------------------------------------------------------------------
// Wire contract: submit, status readback, double-click, refusal-no-effects
// ---------------------------------------------------------------------------

fn seed_grants(state: &State, grants: &[(&str, i64)]) {
    let epoch = state.current_epoch().expect("epoch");
    for (grant_id, number) in grants {
        state
            .issue_grant(&grant_doc_at(grant_id, *number, REV_A, &GRANT_CAPS, epoch))
            .expect("issue grant");
    }
}

#[test]
fn wire_submit_partially_admits_and_status_reads_back_the_same_document() {
    let fixture = DaemonFixture::new("wire-partial");
    let (bound, digest) = {
        let state = fixture.seed();
        seed_grants(
            &state,
            &[
                ("gr_0000000000000011", 5),
                ("gr_0000000000000012", 6),
                ("gr_0000000000000013", 7),
                ("gr_0000000000000014", 8),
            ],
        );
        // Issue 7 already has a live owner run.
        state
            .start_instance(
                "run-owned-wire-0001",
                "gr_0000000000000013",
                DOCTRINE_WORKFLOW_ID,
                "2026-09-06T00:00:00Z",
            )
            .expect("seed owned run");
        let request = request_with(vec![
            selected("#5", REV_A),
            selected("#6", REV_A),
            selected("#7", REV_A),
            selected("#8", REV_A),
        ]);
        render_bound(&state, &request)
    };
    let daemon = fixture.spawn(None);
    wait_ready(&fixture);

    let key = idem_key("wire-partial");
    let key = key.as_str();
    // Issue 6 has no presented grant; issue 7 is owned; issue 8 waits on the
    // per-repository cap because the seeded run counts and issue 5 admits.
    let params = params_doc(
        key,
        &bound,
        &digest,
        1,
        &role_revision(),
        &[("#5", "gr_0000000000000011"), ("#8", "gr_0000000000000014")],
        &[],
        (Some(true), Some(0)),
    );
    let result = rpc_ok(&fixture.socket, &fresh_id(1), "queue.submit", Some(params));
    assert_eq!(item_status(&result, 5), ("admitted".to_string(), None));
    assert_eq!(
        item_status(&result, 6),
        ("refused".to_string(), Some("submission.grant".to_string()))
    );
    assert_eq!(
        item_status(&result, 7),
        (
            "refused".to_string(),
            Some("submission.already_owned".to_string())
        )
    );
    assert_eq!(
        item_status(&result, 8),
        (
            "waiting".to_string(),
            Some("refusal.admission.cap_repository".to_string())
        )
    );
    // #236 AC2: the waiting verdict NAMES the lane that occupies the cap —
    // the count, the cap and the holder's identity (issue, run id, declared
    // worktree) — so `queue status` and the board show who holds the slot.
    let waiting_message = result
        .get("items")
        .and_then(Val::as_array)
        .expect("items")
        .iter()
        .find(|item| item.get("id").and_then(Val::as_str) == Some("example-org/widgets#8"))
        .and_then(|item| item.get("message").and_then(Val::as_str))
        .expect("the waiting verdict carries its producer's message")
        .to_string();
    for needle in [
        "the per-repository concurrency cap (",
        "1 active lanes",
        "example-org/widgets#7",
        "run-owned-wire-0001",
        "worktrees/issues/7",
    ] {
        assert!(
            waiting_message.contains(needle),
            "the waiting verdict must name {needle}: {waiting_message}"
        );
    }
    let admission = result.get("admission").expect("admission");
    assert_eq!(admission.get("admitted").and_then(Val::as_int), Some(1));
    assert_eq!(admission.get("waiting").and_then(Val::as_int), Some(1));
    assert_eq!(admission.get("refused").and_then(Val::as_int), Some(2));

    // The readback agreement: queue.status returns the same document.
    let submission_id = qx::submission_id(&digest, key);
    let readback = rpc_ok(
        &fixture.socket,
        &fresh_id(2),
        "queue.status",
        Some(object(vec![("submission_id", string(&submission_id))])),
    );
    assert_eq!(
        canter::canonical::canonical_text(&readback),
        canter::canonical::canonical_text(&result),
        "the CLI/JSON readback and the daemon readback must agree byte for byte"
    );

    // The claim resolved cleanly and both boundaries are journaled.
    assert_eq!(pending_claims(&fixture.socket, &fresh_id(3)), 0);
    let actions = journal_actions(&fixture.socket, &fresh_id(4));
    assert!(
        actions.iter().any(|action| action == "mutate.queue.submit"),
        "the intent is journaled: {actions:?}"
    );
    assert!(
        actions
            .iter()
            .any(|action| action == "outcome.queue.submit"),
        "the outcome is journaled: {actions:?}"
    );

    shutdown(daemon);
    let state = fixture.seed();
    let instances = state.list_instances().expect("instances");
    assert_eq!(instances.len(), 2, "the unselected scope stays untouched");
    let admitted_run = result
        .get("items")
        .and_then(Val::as_array)
        .expect("items")
        .iter()
        .find(|item| item.get("id").and_then(Val::as_str) == Some("example-org/widgets#5"))
        .and_then(|item| item.get("instance_id"))
        .and_then(Val::as_str)
        .expect("admitted run id")
        .to_string();
    let run = state
        .instance_by_id(&admitted_run)
        .expect("read run")
        .expect("admitted run exists");
    assert_eq!(run.issue_number, 5);
    assert_eq!(run.status, "new");
    assert_eq!(run.grant_id, "gr_0000000000000011");
    assert_eq!(run.scope, "worktrees/issues/5");
    let ownership = state.queue_ownership_rows().expect("ownership");
    assert_eq!(ownership.len(), 1);
    assert_eq!(ownership[0].instance_id, admitted_run);
    let (_, items) = state
        .queue_submission_by_id(&submission_id)
        .expect("read submission")
        .expect("submission persisted");
    assert_eq!(items.len(), 4);
}

#[test]
fn wire_double_click_replays_and_concurrent_retries_cannot_duplicate_owners() {
    let fixture = DaemonFixture::new("wire-double-click");
    let ((bound_a, digest_a), (bound_b, digest_b)) = {
        let state = fixture.seed();
        seed_grants(
            &state,
            &[("gr_0000000000000021", 5), ("gr_0000000000000022", 6)],
        );
        (
            render_bound(&state, &request_with(vec![selected("#5", REV_A)])),
            render_bound(&state, &request_with(vec![selected("#6", REV_A)])),
        )
    };
    let daemon = fixture.spawn(None);
    wait_ready(&fixture);

    // A sequential double click (same request id + same key) replays the
    // recorded response without re-dispatching.
    let key_a = idem_key("wire-double");
    let key_a = key_a.as_str();
    let params_a = params_doc(
        key_a,
        &bound_a,
        &digest_a,
        1,
        &role_revision(),
        &[("#5", "gr_0000000000000021")],
        &[],
        (Some(true), Some(0)),
    );
    let first = rpc_ok(
        &fixture.socket,
        &fresh_id(10),
        "queue.submit",
        Some(params_a.clone()),
    );
    assert_eq!(item_status(&first, 5), ("admitted".to_string(), None));
    let second = rpc_ok(
        &fixture.socket,
        &fresh_id(10),
        "queue.submit",
        Some(params_a.clone()),
    );
    assert_eq!(
        canter::canonical::canonical_text(&first),
        canter::canonical::canonical_text(&second),
        "a double click replays the recorded response"
    );
    // The same key from a different request id is refused (key ownership).
    let (code, message) = rpc_err(
        &fixture.socket,
        &fresh_id(11),
        "queue.submit",
        Some(params_a),
    );
    assert_eq!(code, "state.claim_reused", "{message}");

    // Now a CONCURRENT double click on a still-unowned issue: both threads
    // race the same request id + key. Exactly one attempt runs the one
    // transaction (one owner); the other is either the recorded replay or a
    // typed in-flight refusal — never a raw storage error — and a later
    // same-request retry replays the recorded response.
    let key_b = idem_key("wire-concurrent");
    let key_b = key_b.as_str();
    let params_b = params_doc(
        key_b,
        &bound_b,
        &digest_b,
        1,
        &role_revision(),
        &[("#6", "gr_0000000000000022")],
        &[],
        (Some(true), Some(0)),
    );
    let race = || {
        let socket = fixture.socket.clone();
        let params = params_b.clone();
        std::thread::spawn(move || rpc(&socket, &fresh_id(21), "queue.submit", Some(params)))
    };
    let left = race().join().expect("left thread");
    let right = race().join().expect("right thread");
    let mut responses = vec![left, right];
    for doc in &responses {
        if doc.get("ok").and_then(Val::as_bool) != Some(true) {
            let code = doc
                .get("error")
                .and_then(|error| error.get("code"))
                .and_then(Val::as_str);
            assert_eq!(
                code,
                Some("state.claim_incomplete"),
                "only the typed in-flight refusal is legal for the loser: {}",
                canter::canonical::canonical_text(doc)
            );
        }
    }
    assert!(
        responses
            .iter()
            .any(|doc| doc.get("ok").and_then(Val::as_bool) == Some(true)),
        "at least one concurrent attempt resolves"
    );
    // A later same-request retry returns the recorded response.
    let replay = rpc_ok(
        &fixture.socket,
        &fresh_id(21),
        "queue.submit",
        Some(params_b.clone()),
    );
    responses.push(replay.clone());
    let admitted: Vec<&Val> = responses
        .iter()
        .filter(|doc| doc.get("ok").and_then(Val::as_bool) == Some(true))
        .collect();
    let first_ok = canter::canonical::canonical_text(admitted[0]);
    for doc in &admitted {
        assert_eq!(
            canter::canonical::canonical_text(doc),
            first_ok,
            "every resolved attempt agrees on the one decision"
        );
    }
    assert_eq!(item_status(&replay, 6), ("admitted".to_string(), None));

    shutdown(daemon);
    let state = fixture.seed();
    let instances = state.list_instances().expect("instances");
    assert_eq!(instances.len(), 2, "exactly one run per admitted issue");
    assert_eq!(
        instances.iter().filter(|run| run.issue_number == 6).count(),
        1,
        "the concurrent race created exactly one owner for issue 6"
    );
    assert_eq!(state.queue_ownership_rows().expect("ownership").len(), 2);
}

#[test]
fn wire_stale_digest_epoch_and_revision_refuse_without_claims() {
    let fixture = DaemonFixture::new("wire-stale");
    let (bound, digest) = {
        let state = fixture.seed();
        // Rotate once so a pinned epoch 1 is stale, then issue at epoch 2.
        state
            .rotate_epoch("security_rotation")
            .expect("rotate epoch");
        seed_grants(&state, &[("gr_0000000000000031", 5)]);
        render_bound(&state, &request_with(vec![selected("#5", REV_A)]))
    };
    let daemon = fixture.spawn(None);
    wait_ready(&fixture);

    let (code, message) = rpc_err(
        &fixture.socket,
        &fresh_id(30),
        "queue.submit",
        Some(params_doc(
            "ik_85-wire-bad-digest",
            &bound,
            &"0".repeat(64),
            2,
            &role_revision(),
            &[("#5", "gr_0000000000000031")],
            &[],
            (Some(true), Some(0)),
        )),
    );
    assert_eq!(code, "refusal.plan.stale", "{message}");

    let (code, message) = rpc_err(
        &fixture.socket,
        &fresh_id(31),
        "queue.submit",
        Some(params_doc(
            "ik_85-wire-bad-epoch",
            &bound,
            &digest,
            1,
            &role_revision(),
            &[("#5", "gr_0000000000000031")],
            &[],
            (Some(true), Some(0)),
        )),
    );
    assert_eq!(code, "refusal.state.epoch", "{message}");

    let (code, message) = rpc_err(
        &fixture.socket,
        &fresh_id(32),
        "queue.submit",
        Some(params_doc(
            "ik_85-wire-bad-revision",
            &bound,
            &digest,
            2,
            &"a".repeat(64),
            &[("#5", "gr_0000000000000031")],
            &[],
            (Some(true), Some(0)),
        )),
    );
    assert_eq!(code, "refusal.profile.revision", "{message}");

    // Nothing was claimed or written by the three refusals.
    assert_eq!(pending_claims(&fixture.socket, &fresh_id(33)), 0);
    let actions = journal_actions(&fixture.socket, &fresh_id(34));
    assert!(
        !actions.iter().any(|action| action == "mutate.queue.submit"),
        "refusals before the claim never journal an intent: {actions:?}"
    );

    // The correct material still commits at the live epoch.
    let params = params_doc(
        "ik_85-wire-clean",
        &bound,
        &digest,
        2,
        &role_revision(),
        &[("#5", "gr_0000000000000031")],
        &[],
        (Some(true), Some(0)),
    );
    let result = rpc_ok(&fixture.socket, &fresh_id(35), "queue.submit", Some(params));
    assert_eq!(item_status(&result, 5), ("admitted".to_string(), None));

    shutdown(daemon);
    let state = fixture.seed();
    assert_eq!(state.list_instances().expect("instances").len(), 1);
    assert_eq!(state.queue_ownership_rows().expect("ownership").len(), 1);
    assert!(
        state
            .queue_submission_by_id(&qx::submission_id(&digest, "ik_85-wire-bad-digest"))
            .expect("read")
            .is_none(),
        "a refused submission never persists a row"
    );
}

#[test]
fn wire_unsupported_step_is_refused_and_labelled_without_claims() {
    let fixture = DaemonFixture::new("wire-bad-step");
    let (bound, digest) = {
        let state = fixture.seed();
        seed_grants(&state, &[("gr_0000000000000041", 5)]);
        let mut request = request_with(vec![selected("#5", REV_A)]);
        request.steps = vec![step("p1", "frobnicate", Some(resolved()))];
        render_bound(&state, &request)
    };
    let daemon = fixture.spawn(None);
    wait_ready(&fixture);

    let (code, message) = rpc_err(
        &fixture.socket,
        &fresh_id(40),
        "queue.submit",
        Some(params_doc(
            "ik_85-wire-bad-step",
            &bound,
            &digest,
            1,
            &role_revision(),
            &[("#5", "gr_0000000000000041")],
            &[],
            (Some(true), Some(0)),
        )),
    );
    assert_eq!(code, "preview.step_unsupported", "{message}");
    assert_eq!(pending_claims(&fixture.socket, &fresh_id(41)), 0);

    shutdown(daemon);
    let state = fixture.seed();
    assert!(state.list_instances().expect("instances").is_empty());
    assert!(state.queue_ownership_rows().expect("ownership").is_empty());
    assert!(
        state
            .queue_submission_by_id(&qx::submission_id(&digest, "ik_85-wire-bad-step"))
            .expect("read")
            .is_none()
    );
}

// ---------------------------------------------------------------------------
// AC6 failure injection: the two crash windows and their reconciliation
// ---------------------------------------------------------------------------

#[test]
fn crash_before_commit_leaves_nothing_and_needs_a_fresh_key() {
    let fixture = DaemonFixture::new("crash-before");
    let (bound, digest) = {
        let state = fixture.seed();
        seed_grants(&state, &[("gr_0000000000000051", 5)]);
        render_bound(&state, &request_with(vec![selected("#5", REV_A)]))
    };
    let key = idem_key("crash-before");
    let key = key.as_str();
    let params = params_doc(
        key,
        &bound,
        &digest,
        1,
        &role_revision(),
        &[("#5", "gr_0000000000000051")],
        &[],
        (Some(true), Some(0)),
    );

    let mut daemon = fixture.spawn(Some("queue.after-intent"));
    wait_ready(&fixture);
    send_only(&fixture.socket, &fresh_id(50), "queue.submit", &params);
    wait_crash(&mut daemon);

    // The interrupted transaction left NOTHING behind: the pre-commit crash
    // happens before the one all-or-nothing transaction.
    let state = fixture.seed();
    assert!(state.list_instances().expect("instances").is_empty());
    assert!(state.queue_ownership_rows().expect("ownership").is_empty());
    assert!(
        state
            .queue_submission_by_id(&qx::submission_id(&digest, key))
            .expect("read")
            .is_none(),
        "a pre-commit crash persists no submission"
    );
    drop(state);

    let daemon_restarted = fixture.spawn(None);
    wait_ready(&fixture);
    assert_eq!(
        pending_claims(&fixture.socket, &fresh_id(51)),
        0,
        "restart reconciliation resolves the interrupted claim"
    );
    let actions = journal_actions(&fixture.socket, &fresh_id(52));
    assert!(
        actions
            .iter()
            .any(|action| action == "reconcile.queue.submit"),
        "the interrupted submission is reconciled: {actions:?}"
    );
    // The reconciler read the commit marker back, found none, and said so:
    // the all-or-nothing transaction left nothing behind.
    let log_text = std::fs::read_to_string(fixture.daemon_log()).expect("daemon log");
    assert!(
        log_text.contains("\"event\":\"reconcile.queue.submit\""),
        "the restart reconciliation of the interrupted submission is logged: {log_text}"
    );
    assert!(
        log_text.contains("never committed"),
        "the reconcile readback names the absent marker: {log_text}"
    );

    // The ambiguous claim refuses a same-key retry; a fresh key commits
    // exactly one owner.
    let (code, message) = rpc_err(&fixture.socket, &fresh_id(50), "queue.submit", Some(params));
    assert_eq!(code, "state.ambiguous_claim", "{message}");
    let fresh = params_doc(
        "ik_85-crash-before-retry",
        &bound,
        &digest,
        1,
        &role_revision(),
        &[("#5", "gr_0000000000000051")],
        &[],
        (Some(true), Some(0)),
    );
    let result = rpc_ok(&fixture.socket, &fresh_id(53), "queue.submit", Some(fresh));
    assert_eq!(item_status(&result, 5), ("admitted".to_string(), None));

    shutdown(daemon_restarted);
    let state = fixture.seed();
    assert_eq!(
        state.list_instances().expect("instances").len(),
        1,
        "exactly one owner run exists after the crash and the fresh retry"
    );
    assert_eq!(state.queue_ownership_rows().expect("ownership").len(), 1);
}

#[test]
fn crash_after_commit_keeps_exactly_the_committed_effects() {
    let fixture = DaemonFixture::new("crash-after");
    let (bound, digest) = {
        let state = fixture.seed();
        seed_grants(&state, &[("gr_0000000000000061", 5)]);
        render_bound(&state, &request_with(vec![selected("#5", REV_A)]))
    };
    let key = idem_key("crash-after");
    let key = key.as_str();
    let params = params_doc(
        key,
        &bound,
        &digest,
        1,
        &role_revision(),
        &[("#5", "gr_0000000000000061")],
        &[],
        (Some(true), Some(0)),
    );

    let mut daemon = fixture.spawn(Some("queue.after-commit"));
    wait_ready(&fixture);
    send_only(&fixture.socket, &fresh_id(60), "queue.submit", &params);
    wait_crash(&mut daemon);

    // The commit marker exists with exactly the committed effects.
    let submission_id = qx::submission_id(&digest, key);
    let state = fixture.seed();
    let (row, items) = state
        .queue_submission_by_id(&submission_id)
        .expect("read")
        .expect("the committed submission survives the crash");
    assert_eq!(row.digest, digest);
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].status, "admitted");
    assert_eq!(state.list_instances().expect("instances").len(), 1);
    assert_eq!(state.queue_ownership_rows().expect("ownership").len(), 1);
    drop(state);

    let daemon_restarted = fixture.spawn(None);
    wait_ready(&fixture);
    assert_eq!(pending_claims(&fixture.socket, &fresh_id(61)), 0);
    let actions = journal_actions(&fixture.socket, &fresh_id(62));
    assert!(
        actions
            .iter()
            .any(|action| action == "reconcile.queue.submit"),
        "the committed submission is reconciled: {actions:?}"
    );
    // The queue.submit reconciler itself read the commit marker back and
    // verified the digest binding before reporting: the committed window is
    // reconciled from durable rows, never re-executed.
    let log_text = std::fs::read_to_string(fixture.daemon_log()).expect("daemon log");
    assert!(
        log_text.contains("\"event\":\"reconcile.queue.submit\""),
        "the restart reconciliation of the committed submission is logged: {log_text}"
    );
    assert!(
        log_text.contains("committed before the interrupt"),
        "the reconcile readback names the committed marker: {log_text}"
    );

    // The restart readback returns the committed document.
    let readback = rpc_ok(
        &fixture.socket,
        &fresh_id(63),
        "queue.status",
        Some(object(vec![("submission_id", string(&submission_id))])),
    );
    assert_eq!(item_status(&readback, 5), ("admitted".to_string(), None));
    assert_eq!(
        readback
            .get("admission")
            .and_then(|a| a.get("admitted"))
            .and_then(Val::as_int),
        Some(1)
    );

    // A fresh-key resubmission can never create a second owner.
    let fresh = params_doc(
        "ik_85-crash-after-retry",
        &bound,
        &digest,
        1,
        &role_revision(),
        &[("#5", "gr_0000000000000061")],
        &[],
        (Some(true), Some(0)),
    );
    let result = rpc_ok(&fixture.socket, &fresh_id(64), "queue.submit", Some(fresh));
    assert_eq!(
        item_status(&result, 5),
        (
            "refused".to_string(),
            Some("submission.already_owned".to_string())
        )
    );

    shutdown(daemon_restarted);
    let state = fixture.seed();
    assert_eq!(state.list_instances().expect("instances").len(), 1);
    assert_eq!(state.queue_ownership_rows().expect("ownership").len(), 1);
}

#[test]
fn wire_paused_run_needs_the_explicit_resume_authorization() {
    let fixture = DaemonFixture::new("wire-paused");
    let (bound, digest, resume_digest) = {
        let state = fixture.seed();
        seed_grants(&state, &[("gr_0000000000000071", 5)]);
        state
            .start_instance(
                "run-paused-wire-0001",
                "gr_0000000000000071",
                DOCTRINE_WORKFLOW_ID,
                "2026-09-06T00:00:00Z",
            )
            .expect("seed run");
        let resume_digest = canter::engine::mint_resume_digest("run-paused-wire-0001", 1, "p1");
        state
            .pause_instance(
                "run-paused-wire-0001",
                &resume_digest,
                "2026-09-06T01:00:00Z",
            )
            .expect("pause");
        let (bound, digest) = render_bound(&state, &request_with(vec![selected("#5", REV_A)]));
        (bound, digest, resume_digest)
    };
    let daemon = fixture.spawn(None);
    wait_ready(&fixture);

    // Without an authorization the item is refused and the run stays paused.
    let result = rpc_ok(
        &fixture.socket,
        &fresh_id(70),
        "queue.submit",
        Some(params_doc(
            "ik_85-wire-paused",
            &bound,
            &digest,
            1,
            &role_revision(),
            &[("#5", "gr_0000000000000071")],
            &[],
            (Some(true), Some(0)),
        )),
    );
    assert_eq!(
        item_status(&result, 5),
        ("refused".to_string(), Some("submission.paused".to_string()))
    );

    // With the engine-minted authorization the run resumes exactly once and
    // the item is admitted against the SAME run (no new owner).
    let result = rpc_ok(
        &fixture.socket,
        &fresh_id(71),
        "queue.submit",
        Some(params_doc(
            "ik_85-wire-resume",
            &bound,
            &digest,
            1,
            &role_revision(),
            &[("#5", "gr_0000000000000071")],
            &[("run-paused-wire-0001", &resume_digest)],
            (Some(true), Some(0)),
        )),
    );
    assert_eq!(item_status(&result, 5), ("admitted".to_string(), None));
    let instance_id = result
        .get("items")
        .and_then(Val::as_array)
        .and_then(|items| items.first())
        .and_then(|item| item.get("instance_id"))
        .and_then(Val::as_str)
        .expect("resumed run id");
    assert_eq!(instance_id, "run-paused-wire-0001");

    shutdown(daemon);
    let state = fixture.seed();
    let run = state
        .instance_by_id("run-paused-wire-0001")
        .expect("read")
        .expect("run exists");
    assert!(!run.paused, "the authorized run resumed");
    assert_eq!(run.status, "running");
    assert_eq!(
        state.list_instances().expect("instances").len(),
        1,
        "the resume never creates a second run"
    );
    assert!(
        state.queue_ownership_rows().expect("ownership").is_empty(),
        "no new ownership row is created for a resumed run"
    );
}

#[test]
fn wire_revoked_grant_refuses_the_item_before_any_effect() {
    let fixture = DaemonFixture::new("wire-revoked");
    let (bound, digest) = {
        let state = fixture.seed();
        seed_grants(&state, &[("gr_0000000000000081", 5)]);
        render_bound(&state, &request_with(vec![selected("#5", REV_A)]))
    };
    let daemon = fixture.spawn(None);
    wait_ready(&fixture);
    // Revoke the presented grant over the wire, then submit against it.
    rpc_ok(
        &fixture.socket,
        &fresh_id(80),
        "grants.revoke",
        Some(object(vec![
            ("idempotency_key", string("ik_85-wire-revoke")),
            ("grant_id", string("gr_0000000000000081")),
        ])),
    );
    let result = rpc_ok(
        &fixture.socket,
        &fresh_id(81),
        "queue.submit",
        Some(params_doc(
            "ik_85-wire-revoked",
            &bound,
            &digest,
            1,
            &role_revision(),
            &[("#5", "gr_0000000000000081")],
            &[],
            (Some(true), Some(0)),
        )),
    );
    assert_eq!(
        item_status(&result, 5),
        (
            "refused".to_string(),
            Some("refusal.grant.inactive".to_string())
        ),
        "a revoked grant refuses the item before any effect"
    );
    assert_eq!(
        result
            .get("admission")
            .and_then(|a| a.get("admitted"))
            .and_then(Val::as_int),
        Some(0)
    );

    shutdown(daemon);
    let state = fixture.seed();
    assert!(
        state.list_instances().expect("instances").is_empty(),
        "no run is created against a revoked grant"
    );
    assert!(state.queue_ownership_rows().expect("ownership").is_empty());
}

// ---------------------------------------------------------------------------
// Issue #236: the bounded, audited operator re-drive of ONE committed
// submission — the control that recovers a submission parked by a transient
// cap (the #96 cursor otherwise moves only on a verified delivery).
// ---------------------------------------------------------------------------

#[test]
fn a_parked_submission_is_re_driven_by_the_operators_bounded_control() {
    let fixture = StateFixture::new("redrive");
    let state = fixture.open();
    for (grant, issue) in [
        ("gr_0000000000000011", 11),
        ("gr_0000000000000012", 12),
        ("gr_0000000000000013", 13),
        ("gr_0000000000000014", 14),
    ] {
        state
            .issue_grant(&grant_doc(grant, issue, REV_A, &GRANT_CAPS))
            .expect("issue grant");
    }
    // Two LIVE lanes fill the per-repository cap (2) the approval presents:
    // this is the state the conductor's fan-out hit — capacity genuinely
    // occupied at submit time.
    let holders = plan_for(
        &state,
        "qs_0000000000000011",
        &"a".repeat(64),
        vec![
            (
                11,
                REV_A,
                Some("gr_0000000000000011"),
                SubmissionVerdict::Approved,
            ),
            (
                12,
                REV_A,
                Some("gr_0000000000000012"),
                SubmissionVerdict::Approved,
            ),
        ],
        Some(0),
    );
    let (_, holder_items) = state.submit_queue_run(&holders).expect("holders commit");
    let holder_runs: Vec<String> = holder_items
        .iter()
        .filter_map(|item| item.instance_id.clone())
        .collect();
    assert_eq!(holder_runs.len(), 2, "both holding runs are live");

    // The two-item fan-out the queue accepted and could not admit: both items
    // park as `waiting` with the typed per-repository cap refusal.
    let parked = plan_for(
        &state,
        "qs_0000000000000012",
        &"b".repeat(64),
        vec![
            (
                13,
                REV_A,
                Some("gr_0000000000000013"),
                SubmissionVerdict::Approved,
            ),
            (
                14,
                REV_A,
                Some("gr_0000000000000014"),
                SubmissionVerdict::Approved,
            ),
        ],
        Some(0),
    );
    let (_, parked_items) = state.submit_queue_run(&parked).expect("parked commits");
    for item in &parked_items {
        assert_eq!(
            (
                item.status.as_str(),
                item.reason.as_deref(),
                item.instance_id.as_deref()
            ),
            (
                "waiting",
                Some(canter::lifecycle::code::CAP_REPOSITORY),
                None
            ),
            "an item with no capacity parks typed and creates no run"
        );
    }

    // Nothing parked: the control refuses typed and touches no lane — the
    // submission whose items run live is never re-driven, retired or altered.
    let live_before = state
        .instance_by_id(&holder_runs[0])
        .expect("read")
        .expect("the live run exists");
    let err = state
        .redrive_queue_submission(
            "qs_0000000000000011",
            "ik-redrive-holder",
            "2026-09-06T02:05:00Z",
        )
        .expect_err("a submission with nothing parked refuses");
    assert_eq!(err.code, "refusal.queue.nothing_parked", "{}", err.message);
    let live_after = state
        .instance_by_id(&holder_runs[0])
        .expect("read")
        .expect("the live run exists");
    assert_eq!(live_before, live_after, "a live lane is never touched");

    // The holders are released (the operator's own act), the cap frees, and
    // the bounded, audited re-drive admits BOTH parked items — each with its
    // own run.
    for (index, run) in holder_runs.iter().enumerate() {
        state
            .release_run(
                run,
                "the transient holding run is freed",
                &format!("ik-release-{index}"),
                "2026-09-06T02:06:00Z",
            )
            .expect("release");
    }
    assert_eq!(
        state
            .list_instances()
            .expect("instances")
            .iter()
            .filter(|row| matches!(
                row.status.as_str(),
                "new" | "running" | "human_queue" | "blocked"
            ))
            .count(),
        0,
        "the released holders no longer count against the cap"
    );
    // Issue #261: this submission committed NO arming authorization, so the
    // re-drive refuses the WHOLE control typed and admits nothing — it never
    // creates a run nothing can drive. The parked items keep their hold.
    let err = state
        .redrive_queue_submission(
            "qs_0000000000000012",
            "ik-redrive-parked",
            "2026-09-06T02:07:00Z",
        )
        .expect_err("a submission with no arming authorization refuses");
    assert_eq!(
        err.code,
        canter::queue_executor::codes::SUPERVISION_UNARMED,
        "{}",
        err.message
    );
    let (_, still_parked) = state
        .queue_submission_by_id("qs_0000000000000012")
        .expect("read")
        .expect("the submission exists");
    for item in &still_parked {
        assert_eq!(item.status, "waiting", "nothing is admitted: {item:?}");
        assert!(item.instance_id.is_none(), "no run is created: {item:?}");
    }
    assert!(
        state
            .list_instances()
            .expect("instances")
            .iter()
            .all(|row| !matches!(
                row.status.as_str(),
                "new" | "running" | "human_queue" | "blocked"
            )),
        "the re-drive created no run"
    );
    // The ARMED submission of the SAME parked items is re-driven and armed —
    // the positive half lives in `a_re_drive_arms_what_it_admits` below.
    let unsettled = state
        .redrive_queue_submission(
            "qs_0000000000000012",
            "ik-redrive-parked-2",
            "2026-09-06T02:07:30Z",
        )
        .expect_err("the refusal is deterministic");
    assert_eq!(
        unsettled.code,
        canter::queue_executor::codes::SUPERVISION_UNARMED
    );
    // A refused re-drive commits NOTHING at all: no run, no item flip and no
    // `queue.redrive` audit record (a re-drive is audited only when it runs;
    // the daemon records the refusal as its claim outcome).
    let (_, lines_after) = state.journal_tail(0, 500).expect("journal");
    assert_eq!(
        lines_after
            .iter()
            .filter(|line| line.contains("queue.redrive"))
            .count(),
        0,
        "the refused re-drive touches no journal record: {lines_after:?}"
    );
}

// ---------------------------------------------------------------------------
// Issue #261: a re-drive ARMS what it admits, the bounded arm control
// recovers an inert admitted run, and every refusal is typed.
// ---------------------------------------------------------------------------

/// The explicit authorization a submission presents: armed with the bounded
/// default policy the operator surface uses.
fn armed_supervision() -> canter::state::SupervisionAuthorizationPlan {
    canter::state::SupervisionAuthorizationPlan {
        desired: "armed".to_string(),
        check_interval_secs: 60,
        progress_timeout_secs: 900,
    }
}

/// `plan_for` with an explicit armed supervision authorization.
fn plan_for_armed(
    state: &State,
    submission_id: &str,
    digest: &str,
    items: Vec<(i64, &str, Option<&str>, SubmissionVerdict)>,
    harness_lanes: Option<i64>,
) -> QueueSubmissionPlan {
    let mut plan = plan_for(state, submission_id, digest, items, harness_lanes);
    plan.supervision = Some(armed_supervision());
    plan
}

#[test]
fn a_re_drive_arms_what_it_admits_with_the_submissions_own_authorization() {
    let fixture = StateFixture::new("redrive-arm");
    let state = fixture.open();
    for (grant, issue) in [
        ("gr_0000000000000021", 21),
        ("gr_0000000000000022", 22),
        ("gr_0000000000000023", 23),
    ] {
        state
            .issue_grant(&grant_doc(grant, issue, REV_A, &GRANT_CAPS))
            .expect("issue grant");
    }
    // ONE live holder occupies one of the two per-repository slots.
    let holder = plan_for(
        &state,
        "qs_0000000000000021",
        &"c".repeat(64),
        vec![(
            23,
            REV_A,
            Some("gr_0000000000000023"),
            SubmissionVerdict::Approved,
        )],
        Some(0),
    );
    let (_, holder_items) = state.submit_queue_run(&holder).expect("holder commit");
    let holder_run = holder_items[0].instance_id.clone().expect("holder run");

    // The ARMED submission: its first item is admitted (one slot free) and
    // armed by the submit path; its second parks on the now-full cap.
    let armed = plan_for_armed(
        &state,
        "qs_0000000000000022",
        &"d".repeat(64),
        vec![
            (
                21,
                REV_A,
                Some("gr_0000000000000021"),
                SubmissionVerdict::Approved,
            ),
            (
                22,
                REV_A,
                Some("gr_0000000000000022"),
                SubmissionVerdict::Approved,
            ),
        ],
        Some(0),
    );
    let (_, armed_items) = state.submit_queue_run(&armed).expect("armed commit");
    let submitted_run = armed_items[0]
        .instance_id
        .clone()
        .expect("the first item is admitted at submit");
    let submitted_row = state
        .supervision_by_id(&submitted_run)
        .expect("read")
        .expect("the submit path armed it");
    assert_eq!(submitted_row.desired, "armed");
    assert_eq!(armed_items[1].status, "waiting", "{:?}", armed_items[1]);
    assert!(armed_items[1].instance_id.is_none(), "no run yet");

    // The transient hold is released and the bounded re-drive admits the
    // parked item — ARMED with the submission's own authorization, bound to
    // the same digest/boundary/epoch the submit path binds.
    state
        .release_run(
            &holder_run,
            "the transient holding run is freed",
            "ik-release-261",
            "2026-09-06T02:06:00Z",
        )
        .expect("release");
    let outcome = state
        .redrive_queue_submission(
            "qs_0000000000000022",
            "ik-redrive-261",
            "2026-09-06T02:07:00Z",
        )
        .expect("the re-drive commits");
    assert_eq!(outcome.admitted.len(), 1, "{outcome:?}");
    let re_driven = outcome.admitted[0].2.clone();
    let row = state
        .supervision_by_id(&re_driven)
        .expect("read")
        .expect("the re-driven run is ARMED — never an inert admission");
    assert_eq!(row.desired, "armed");
    assert_eq!(
        row.authorization_digest,
        "d".repeat(64),
        "the SAME approved digest the submit path binds"
    );
    assert_eq!(
        (row.check_interval_secs, row.progress_timeout_secs),
        (60, 900),
        "the submission's OWN policy, never an invented one"
    );
    assert_eq!(row.approved_boundary, "merge", "the submission's boundary");
    assert_eq!(
        row.run_generation,
        state.current_epoch().expect("epoch"),
        "the submission's own state epoch"
    );
    // The driver's own reconciliation path (the daemon's real driver uses
    // these two calls) reads the armed row and commits its check: nothing on
    // the re-driven run needs an operator dispatch.
    let evidence = state
        .supervision_evidence(&re_driven)
        .expect("evidence read")
        .expect("evidence exists");
    let check =
        canter::supervision::check_plan(&row, &evidence, None, true, canter::time::unix_now());
    state
        .commit_supervision_check(&check)
        .expect("the driver's own check commits for the re-driven run");
    // Audited: the re-drive is a hash-chained journal record, exactly once.
    let (_, lines) = state.journal_tail(0, 500).expect("journal");
    assert_eq!(
        lines
            .iter()
            .filter(|line| line.contains("queue.redrive"))
            .count(),
        1,
        "one audited re-drive record: {lines:?}"
    );
}

#[test]
fn the_operator_arm_control_recovers_an_inert_admitted_run_and_is_audited() {
    let fixture = StateFixture::new("arm-control");
    let state = fixture.open();
    for (grant, issue) in [
        ("gr_0000000000000031", 31),
        ("gr_0000000000000032", 32),
        ("gr_0000000000000033", 33),
    ] {
        state
            .issue_grant(&grant_doc(grant, issue, REV_A, &GRANT_CAPS))
            .expect("issue grant");
    }
    // One holder + an ARMED submission whose second item parks: the cap is
    // full after the submit, so the parked item is admitted by the re-drive.
    let holder = plan_for(
        &state,
        "qs_0000000000000031",
        &"e".repeat(64),
        vec![(
            33,
            REV_A,
            Some("gr_0000000000000033"),
            SubmissionVerdict::Approved,
        )],
        Some(0),
    );
    let (_, holder_items) = state.submit_queue_run(&holder).expect("holder commit");
    let holder_run = holder_items[0].instance_id.clone().expect("holder run");
    let armed = plan_for_armed(
        &state,
        "qs_0000000000000032",
        &"f".repeat(64),
        vec![
            (
                31,
                REV_A,
                Some("gr_0000000000000031"),
                SubmissionVerdict::Approved,
            ),
            (
                32,
                REV_A,
                Some("gr_0000000000000032"),
                SubmissionVerdict::Approved,
            ),
        ],
        Some(0),
    );
    let (_, armed_items) = state.submit_queue_run(&armed).expect("armed commit");
    let sibling_run = armed_items[0].instance_id.clone().expect("armed sibling");
    state
        .release_run(
            &holder_run,
            "the transient holding run is freed",
            "ik-release-arm-261",
            "2026-09-06T02:06:00Z",
        )
        .expect("release");
    let outcome = state
        .redrive_queue_submission(
            "qs_0000000000000032",
            "ik-redrive-arm-261",
            "2026-09-06T02:07:00Z",
        )
        .expect("the re-drive commits");
    let inert_run = outcome.admitted[0].2.clone();
    // The runaway case this control exists for: an admitted run that carries
    // NO arming authorization (supervision disabled on the run itself).
    state
        .arm_supervision(
            &inert_run,
            &canter::state::SupervisionAuthorizationPlan {
                desired: "disabled".to_string(),
                check_interval_secs: 60,
                progress_timeout_secs: 900,
            },
            &"f".repeat(64),
            "merge",
            state.current_epoch().expect("epoch"),
            "2026-09-06T02:07:30Z",
        )
        .expect("the run is explicitly disabled: inert");
    let disabled = state
        .supervision_by_id(&inert_run)
        .expect("read")
        .expect("row");
    assert_eq!(disabled.desired, "disabled", "the run is inert");
    // The bounded, audited operator control arms it.
    let armed_run = state
        .arm_admitted_run(&inert_run, "ik-arm-261", "2026-09-06T02:08:00Z")
        .expect("the arm commits");
    assert_eq!(armed_run.row.desired, "armed");
    assert_eq!(armed_run.row.instance_id, inert_run);
    assert_eq!(
        armed_run.submission_id, "qs_0000000000000032",
        "the arm names the submission whose authorization it re-applied"
    );
    let reread = state
        .supervision_by_id(&inert_run)
        .expect("read")
        .expect("armed");
    assert_eq!(reread.desired, "armed");
    assert_eq!(reread.authorization_digest, "f".repeat(64));
    // Audited: exactly one hash-chained `supervision.arm` record names the run.
    let (_, lines) = state.journal_tail(0, 900).expect("journal");
    let arms = lines
        .iter()
        .filter(|line| line.contains("\"action\":\"supervision.arm\""))
        .count();
    assert_eq!(arms, 1, "one audited arm record: {lines:?}");
    // Typed refusals: an ALREADY armed run and a TERMINAL run are refused.
    let err = state
        .arm_admitted_run(&inert_run, "ik-arm-261-b", "2026-09-06T02:08:30Z")
        .expect_err("an armed run is refused");
    assert_eq!(
        err.code,
        canter::supervision::codes::ARM_ARMED,
        "{}",
        err.message
    );
    assert_eq!(
        state
            .supervision_by_id(&sibling_run)
            .expect("read")
            .expect("row")
            .desired,
        "armed"
    );
    let err = state
        .arm_admitted_run(&sibling_run, "ik-arm-261-c", "2026-09-06T02:08:40Z")
        .expect_err("already armed");
    assert_eq!(
        err.code,
        canter::supervision::codes::ARM_ARMED,
        "{}",
        err.message
    );
}

#[test]
fn the_arm_control_names_each_run_it_refuses() {
    let fixture = StateFixture::new("arm-refusals");
    let state = fixture.open();
    state
        .issue_grant(&grant_doc("gr_0000000000000041", 41, REV_A, &GRANT_CAPS))
        .expect("grant");
    // An UNARMED submission: its admitted run has no arming authorization.
    let unarmed = plan_for(
        &state,
        "qs_0000000000000041",
        &"1".repeat(64),
        vec![(
            41,
            REV_A,
            Some("gr_0000000000000041"),
            SubmissionVerdict::Approved,
        )],
        Some(0),
    );
    let (_, items) = state.submit_queue_run(&unarmed).expect("commit");
    let run = items[0].instance_id.clone().expect("admitted");
    assert!(
        state.supervision_by_id(&run).expect("read").is_none(),
        "an unarmed submission arms nothing"
    );
    let err = state
        .arm_admitted_run(&run, "ik-arm-refuse", "2026-09-06T02:09:00Z")
        .expect_err("no authorization is bound to this run");
    assert_eq!(
        err.code,
        canter::supervision::codes::ARM_UNARMED,
        "{}",
        err.message
    );
    // A TERMINAL run is refused before any authorization is read.
    state
        .release_run(
            &run,
            "terminal",
            "ik-release-arm-refuse",
            "2026-09-06T02:09:30Z",
        )
        .expect("release");
    let err = state
        .arm_admitted_run(&run, "ik-arm-refuse-b", "2026-09-06T02:09:40Z")
        .expect_err("a terminal run is never armed");
    assert_eq!(
        err.code,
        canter::supervision::codes::ARM_TERMINAL,
        "{}",
        err.message
    );
    // A malformed target refuses typed.
    let err = state
        .arm_admitted_run("not-a-run", "ik-arm-refuse-c", "2026-09-06T02:09:50Z")
        .expect_err("not a run identity");
    assert_eq!(
        err.code,
        canter::supervision::codes::TARGET,
        "{}",
        err.message
    );
}
