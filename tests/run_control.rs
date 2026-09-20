//! Issue #86 acceptance tests: run-scoped safe-boundary pause, resume and
//! bounded retry over the REAL daemon and the durable instance rows.
//!
//! The queue run under control is the exact `run-` row the #85 executor
//! commits for an admitted issue (`State::submit_queue_run`), so the
//! stimulus, the diagnosis inputs (`run_step_spine`, `run_step_attempts`)
//! and the fences all read the same durable facts production does. All
//! identities are synthetic; nothing here seeds a provider or a model.
//!
//! Evidence rules: raw RPC outcomes are asserted directly (never a `grep`
//! over a stream), the documents are the documented `hf-run-control/v1` /
//! `hf-run-retry/v1` projections, and every refusal is pinned to its
//! stable code.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use canter::canonical::{canonical_bytes, canonical_text, sha256_hex};
use canter::client::Connection;
use canter::config::ProfileBinding;
use canter::lifecycle::ConcurrencyCaps;
use canter::plan::DOCTRINE_WORKFLOW_ID;
use canter::queue_preview as qp;
use canter::state::{
    QueueSubmissionItemPlan, QueueSubmissionItemRow, QueueSubmissionPlan, Retention, RunRetryClaim,
    State, SubmissionVerdict,
};
use canter::value::{Val, integer, object, string};

#[path = "support/wait_bounds.rs"]
// The ceilings are shared by every driver-driven wait; a crate uses a
// subset, so the module's unused half is not a defect here.
#[allow(dead_code)]
mod wait_bounds;

const REPO: &str = "example-org/widgets";
const HOST: &str = "host-1";
const HARNESS: &str = "lane-1";
const REV_A: &str = "1111111111111111111111111111111111111111";
const WORKFLOW_HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const POLICY_HASH: &str = "feedface01234567feedface01234567feedface01234567feedface01234567";
const GRANT_5: &str = "gr_0000000000000091";
const GRANT_6: &str = "gr_0000000000000092";
/// A FRESHLY issued window for issue #5's binding (issue #146: a released
/// run's expired window is never silently reused — the fresh submission
/// presents a new issuance for the same binding).
const GRANT_5B: &str = "gr_0000000000000093";
/// Windows for the issues a release frees capacity for (issue #146).
const GRANT_7: &str = "gr_0000000000000094";
const GRANT_8: &str = "gr_0000000000000095";
const AT: &str = "2026-09-12T00:00:00Z";

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_canter")
}

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("hf-run-86-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("fixture dir");
    dir
}

/// Runtime-assembled idempotency key (never a tracked literal).
fn idem_key(stem: &str) -> String {
    format!("ik_86-{stem}")
}

/// Deterministic request id per (test, seed) — never a tracked literal.
fn fresh_id(seed: u32) -> String {
    format!("{:08x}", seed + std::process::id())
}

// ---------------------------------------------------------------------------
// Builders (synthetic identities only)
// ---------------------------------------------------------------------------

fn binding_doc() -> Val {
    let mut binding = ProfileBinding {
        key: HARNESS.to_string(),
        kind: "pi".to_string(),
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

fn role_revision() -> String {
    binding_doc()
        .get("revision")
        .and_then(Val::as_str)
        .expect("binding revision")
        .to_string()
}

fn step(id: &str, kind: &str) -> qp::PlannedStep {
    qp::PlannedStep {
        id: id.to_string(),
        kind: kind.to_string(),
        params: Some(object(vec![("ref", string("staging"))])),
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
        steps: vec![step("p1", "checkout"), step("p2", "checkout")],
        selected: issues,
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

fn grant_doc(grant_id: &str, number: i64) -> Val {
    Val::parse_json(&format!(
        r#"{{"schema":"hf-grant/v1","grant_id":"{grant_id}","repository":"{REPO}",
            "issue":{{"number":{number},"revision":"{REV_A}"}},
            "workflow_hash":"{WORKFLOW_HASH}","policy_hash":"{POLICY_HASH}",
            "phase":"merge","scope":"worktrees/issues/{number}",
            "caps":["read","worktree","spawn","merge"],
            "expires_at":"2999-01-01T00:00:00Z","state_epoch":1,
            "created_at":"2026-09-06T00:00:00Z"}}"#
    ))
    .expect("grant document")
}

fn work_item(number: i64) -> String {
    qp::IssueId::parse(&format!("#{number}"), REPO)
        .expect("issue id")
        .work_item()
}

/// Commit one submission for the given (issue, grant) pairs and return the
/// admitted run ids in membership order. The bound-input line is the REAL
/// preview document, so the run's step spine is exactly the reviewed spine.
fn seed_submission(state: &State, issues: &[(i64, &str)]) -> Vec<String> {
    submit_with_id(
        state,
        &format!("qs_{:016x}", 0x86u64 + std::process::id() as u64),
        issues,
    )
    .iter()
    .filter_map(|item| item.instance_id.clone())
    .collect()
}

/// Commit ONE submission under an EXPLICIT submission id and return its
/// recorded item rows (issue #146: the release witnesses submit the same
/// issue more than once inside one fixture, so the derived submission id
/// cannot be reused). Presenting a grant id that is already issued reuses
/// that exact row (a rotation/re-presentation never mints a second grant).
fn submit_with_id(
    state: &State,
    submission_id: &str,
    issues: &[(i64, &str)],
) -> Vec<QueueSubmissionItemRow> {
    for (number, grant_id) in issues {
        if state.grant_by_id(grant_id).expect("grant read").is_none() {
            state
                .issue_grant(&grant_doc(grant_id, *number))
                .expect("issue grant");
        }
    }
    let request = request_with(
        issues
            .iter()
            .map(|(number, _)| selected(&format!("#{number}"), REV_A))
            .collect(),
    );
    let (bound, digest) = render_bound(state, &request);
    let epoch = state.current_epoch().expect("epoch");
    let plan = QueueSubmissionPlan {
        submission_id: submission_id.to_string(),
        repository: REPO.to_string(),
        state_epoch: epoch,
        digest: digest.clone(),
        role_key: HARNESS.to_string(),
        role_revision: role_revision(),
        workflow_id: DOCTRINE_WORKFLOW_ID.to_string(),
        workflow_hash: WORKFLOW_HASH.to_string(),
        boundary_phase: "merge".to_string(),
        integration_branch: "staging".to_string(),
        completion_branch: "staging".to_string(),
        boundary_caps: vec!["read".to_string(), "merge".to_string()],
        request_line: canonical_text(&bound),
        admission_caps: ConcurrencyCaps {
            global: 4,
            per_repository: 2,
            per_harness: 2,
        },
        harness_lanes: Some(0),
        items: issues
            .iter()
            .enumerate()
            .map(|(ordinal, (number, grant_id))| QueueSubmissionItemPlan {
                ordinal: ordinal as i64,
                work_item: work_item(*number),
                issue_number: *number,
                issue_revision: REV_A.to_string(),
                grant_id: Some((*grant_id).to_string()),
                resume_digest: None,
                verdict: SubmissionVerdict::Approved,
            })
            .collect(),
        // Issue #95: no supervision authorization is presented here.
        supervision: None,
        at: AT.to_string(),
    };
    let (_, items) = state.submit_queue_run(&plan).expect("submission commits");
    items
}

/// The canonical request line of one recorded `apply` attempt.
fn apply_request_line(instance_id: &str, step: &str, key: &str) -> String {
    canonical_text(&object(vec![
        ("schema", string("hf-rpc-request/v1")),
        ("id", string(&fresh_id(7))),
        ("method", string("apply")),
        (
            "params",
            object(vec![
                ("idempotency_key", string(key)),
                ("instance_id", string(instance_id)),
                ("step", string(step)),
            ]),
        ),
    ]))
}

/// Seed one recorded `apply` attempt of (run, step) into the durable claim
/// table: `outcome = None` leaves it IN FLIGHT (`claimed`), otherwise the
/// claim resolves with that typed outcome status.
fn seed_attempt(state: &State, instance_id: &str, step: &str, key: &str, outcome: Option<&str>) {
    let line = apply_request_line(instance_id, step, key);
    let request_id = fresh_id(9);
    state
        .journal_intent(
            "mutate.checkout",
            &format!("{REPO}:{instance_id}:{step}"),
            key,
            &request_id,
            "apply",
            None,
            None,
            &line,
        )
        .expect("claim the attempt");
    if let Some(status) = outcome {
        let outcome_line = canonical_text(&object(vec![
            ("schema", string("hf-outcome/v1")),
            ("plan_id", string("hf_plan_0000000000000000")),
            ("step_id", string(step)),
            ("status", string(status)),
            ("idempotency_key", string(key)),
            ("observed_at", string(AT)),
            ("result", Val::Null),
            ("error", Val::Null),
        ]));
        state
            .resolve_claim(key, "apply", "spent", &outcome_line, Some("{}"))
            .expect("resolve the attempt");
    }
}

/// The wire parameters of one REAL `apply` for the seeded run. The
/// integration repo path exists but a fixture `git` shim on PATH makes the
/// checkout effect fail SLOWLY — the claim is in flight for ~a second, so
/// the pause request can land while a step is genuinely executing.
fn apply_params(instance_id: &str, step: &str, key: &str, issue_number: i64) -> Val {
    let seed = object(vec![
        ("schema", string("hf-plan/v1")),
        ("plan_id", string("hf_plan_0000000000000000")),
        ("workflow_id", string(DOCTRINE_WORKFLOW_ID)),
        ("workflow_hash", string(WORKFLOW_HASH)),
        ("state_epoch", integer(1)),
        ("repository", string(REPO)),
        (
            "issue",
            object(vec![
                ("number", integer(issue_number)),
                ("revision", string(REV_A)),
            ]),
        ),
        (
            "steps",
            Val::Arr(vec![
                object(vec![
                    ("id", string("p1")),
                    ("kind", string("checkout")),
                    ("params", object(vec![("ref", string("staging"))])),
                ]),
                object(vec![
                    ("id", string("p2")),
                    ("kind", string("checkout")),
                    ("params", object(vec![("ref", string("staging"))])),
                ]),
            ]),
        ),
    ]);
    let digest = sha256_hex(&canonical_bytes(&seed));
    let plan_id = format!("hf_plan_{}", &digest[..16]);
    let mut map = match seed {
        Val::Obj(map) => map,
        _ => unreachable!(),
    };
    map.insert("plan_id".to_string(), string(&plan_id));
    let plan = Val::Obj(map);
    let integration_repo = std::env::temp_dir().join("hf-run-86-integration-repo");
    std::fs::create_dir_all(&integration_repo).expect("integration repo dir");
    let worktrees_root = std::env::temp_dir().join("hf-run-86-worktrees");
    std::fs::create_dir_all(&worktrees_root).expect("worktrees dir");
    object(vec![
        ("idempotency_key", string(key)),
        ("plan", plan),
        ("step", string(step)),
        ("grant_id", string(GRANT_5)),
        ("instance_id", string(instance_id)),
        (
            "observed",
            object(vec![
                ("issue_revision", string(REV_A)),
                ("policy_hash", string(POLICY_HASH)),
                (
                    "integration_base",
                    string("3333333333333333333333333333333333333333"),
                ),
            ]),
        ),
        (
            "topology",
            object(vec![
                ("integration_branch", string("staging")),
                (
                    "worktrees_root",
                    string(&worktrees_root.display().to_string()),
                ),
                (
                    "integration_repo",
                    string(&integration_repo.display().to_string()),
                ),
            ]),
        ),
    ])
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

struct StateFixture {
    dir: PathBuf,
}

impl StateFixture {
    fn new(name: &str) -> StateFixture {
        StateFixture {
            dir: temp_dir(name),
        }
    }

    fn open(&self) -> State {
        State::open(&self.dir.join("state.db"), Retention::default()).expect("open state")
    }
}

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

    fn seed(&self) -> State {
        std::fs::create_dir_all(self.state_dir.join("canter")).expect("state dir");
        State::open(&self.db(), Retention::default()).expect("open state")
    }

    fn spawn(&self, crash_point: Option<&str>) -> Child {
        self.spawn_with_path(crash_point, None)
    }

    /// Spawn the daemon with an optional PATH prefix (the fixture shims).
    fn spawn_with_path(&self, crash_point: Option<&str>, path_prefix: Option<&Path>) -> Child {
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
        if let Some(prefix) = path_prefix {
            let current = std::env::var("PATH").unwrap_or_default();
            command.env("PATH", format!("{}:{current}", prefix.display()));
        }
        if let Some(point) = crash_point {
            command.env("CANTER_CRASH_POINT", point);
        }
        command.spawn().expect("spawn daemon")
    }
}

/// A `git` shim that keeps one checkout effect genuinely in flight for ~a
/// second and then fails: the pause request can land while a step executes.
fn write_slow_failing_git(fixture: &DaemonFixture) -> PathBuf {
    let bin = fixture.dir.join("fakebin");
    std::fs::create_dir_all(&bin).expect("fakebin dir");
    let git = bin.join("git");
    std::fs::write(&git, "#!/bin/sh\nsleep 1\nexit 1\n").expect("write git shim");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&git, std::fs::Permissions::from_mode(0o755))
            .expect("chmod git shim");
    }
    bin
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

fn shutdown(mut daemon: Child) {
    let _ = daemon.kill();
    let deadline = Instant::now() + Duration::from_secs(10);
    while daemon.try_wait().expect("try_wait").is_none() {
        assert!(Instant::now() < deadline, "daemon did not exit");
        std::thread::sleep(Duration::from_millis(20));
    }
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
        canonical_text(&doc)
    );
    doc.get("result").expect("result").clone()
}

/// The no-progress ceiling of a recorded-state wait, in seconds (issue #232).
///
/// Progress-driven, never a fixed wall-clock bound: the driver wakes
/// semantically on each committed step and otherwise re-checks on its bounded
/// timer fallback (`canter::supervision::DEFAULT_CHECK_INTERVAL_SECS`, 60 s),
/// so one starved wake legitimately leaves a run's recorded control/boundary
/// state unchanged for a little over a minute on a loaded host. The wait below
/// therefore fails only after this much time with NO durable change — any new
/// recorded claim, control transition or boundary move resets the ceiling —
/// and it names the progress observed and the elapsed time. Two driver ticks,
/// so a single starved wake can never fail a witness, and it stays inside the
/// CI test driver's per-suite budget (`scripts/ci-test-driver.py`,
/// `PER_SUITE_SECONDS = 300`).
const NO_PROGRESS_SECS: u64 = wait_bounds::STATE_NO_PROGRESS_SECS;

/// The durable progress a recorded-state wait tracks: the run's control state
/// and boundary, canonically rendered, so any recorded transition counts as
/// progress while a re-read of an unchanged record does not.
fn recorded_progress(status: &Val) -> String {
    canonical_text(&object(vec![
        (
            "control",
            status.get("control").cloned().unwrap_or(Val::Null),
        ),
        (
            "boundary",
            status.get("boundary").cloned().unwrap_or(Val::Null),
        ),
    ]))
}

/// Wait until the run's recorded boundary names `step` as its in-flight step,
/// failing only after `NO_PROGRESS_SECS` with no NEW recorded state (issue
/// #232) and naming the progress observed and the elapsed time.
fn wait_for_in_flight_step(fixture: &DaemonFixture, run: &str, step: &str) -> Val {
    let started = Instant::now();
    let mut last_progress = started;
    let mut progress = String::new();
    let mut seed = 0x200u32;
    loop {
        seed += 1;
        let status = rpc_ok(
            &fixture.socket,
            &fresh_id(seed),
            "run.status",
            Some(canter::run_control::status_params(run)),
        );
        if status
            .get("boundary")
            .and_then(|boundary| boundary.get("in_flight_step"))
            .and_then(Val::as_str)
            == Some(step)
        {
            return status;
        }
        let observed = recorded_progress(&status);
        if observed != progress {
            progress = observed;
            last_progress = Instant::now();
        }
        let stalled = last_progress.elapsed().as_secs();
        assert!(
            stalled < NO_PROGRESS_SECS,
            "the step dispatch never became in flight: no progress for {stalled}s of {}s waited \
             ({})",
            started.elapsed().as_secs(),
            canonical_text(&status)
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn rpc_quiet(socket: &Path, id: &str, method: &str, params: Option<Val>) -> Option<Val> {
    let mut connection = Connection::open(socket).ok()?;
    connection.send_request(id, method, params.as_ref()).ok()?;
    let response = connection.read_response().ok()?;
    Some(if response.ok {
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
    })
}

fn rpc_err(socket: &Path, id: &str, method: &str, params: Option<Val>) -> (String, String) {
    let doc = rpc(socket, id, method, params);
    assert_eq!(
        doc.get("ok").and_then(Val::as_bool),
        Some(false),
        "expected a refusal for {method}: {}",
        canonical_text(&doc)
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

fn pause_params(key: &str, instance_id: &str, reason: &str) -> Val {
    canter::run_control::pause_params(key, instance_id, reason)
}

fn resume_params(key: &str, instance_id: &str, digest: &str) -> Val {
    canter::run_control::resume_params(key, instance_id, digest)
}

fn retry_params(key: &str, instance_id: &str, step: &str) -> Val {
    canter::run_control::retry_params(key, instance_id, step)
}

fn text<'a>(doc: &'a Val, path: &[&str]) -> &'a str {
    let mut current = doc;
    for key in path {
        current = current
            .get(key)
            .unwrap_or_else(|| panic!("missing {key} in {}", canonical_text(doc)));
    }
    current.as_str().unwrap_or_else(|| {
        panic!(
            "{} is not a string: {}",
            path.join("."),
            canonical_text(doc)
        )
    })
}

fn control_state(doc: &Val) -> String {
    text(doc, &["control", "state"]).to_string()
}

fn boundary_reached(doc: &Val) -> bool {
    doc.get("boundary")
        .and_then(|boundary| boundary.get("reached"))
        .and_then(Val::as_bool)
        .unwrap_or(false)
}

fn resume_digest(doc: &Val) -> String {
    text(doc, &["control", "resume_digest"]).to_string()
}

// ---------------------------------------------------------------------------
// AC1/AC4 (durable state machine): requested vs reached, exact-target
// resume, bounded single-use retries — library level, no daemon
// ---------------------------------------------------------------------------

#[test]
fn state_pause_is_immediate_at_the_boundary_durable_and_exact_targeted() {
    let fixture = StateFixture::new("pause-state");
    let state = fixture.open();
    let runs = seed_submission(&state, &[(5, GRANT_5), (6, GRANT_6)]);
    let (run_a, run_b) = (runs[0].clone(), runs[1].clone());

    // No step in flight: the safe boundary is already reached and the pause
    // commits immediately from the request.
    let row = state
        .request_run_pause(&run_a, "operator hold", &"d".repeat(64), AT)
        .expect("pause commits");
    assert!(row.paused, "no in-flight step: the boundary is reached");
    assert!(!row.pause_requested);
    assert_eq!(row.status, "paused");
    assert_eq!(row.pause_reason, "operator hold");
    assert_eq!(row.pause_requested_at, AT);
    assert_eq!(row.resume_digest, "d".repeat(64));

    // A duplicate pause (fresh key) is refused typed and changes NOTHING.
    let err = state
        .request_run_pause(&run_a, "again", &"e".repeat(64), "2026-09-12T00:01:00Z")
        .expect_err("a duplicate pause is refused");
    assert_eq!(err.code, "refusal.run.control");
    let row = state.instance_by_id(&run_a).unwrap().unwrap();
    assert_eq!(row.pause_reason, "operator hold");
    assert_eq!(row.resume_digest, "d".repeat(64));

    // The intent is durable across a reopen.
    drop(state);
    let state = fixture.open();
    let row = state.instance_by_id(&run_a).unwrap().unwrap();
    assert!(row.paused && !row.pause_requested);
    assert_eq!(row.resume_digest, "d".repeat(64));

    // Wrong digest, and the OTHER run's digest, can never resume this run.
    let err = state
        .resume_run(&run_a, &"f".repeat(64), AT)
        .expect_err("a wrong digest refuses");
    assert_eq!(err.code, "state.stale_resume");
    let err = state
        .resume_run(&run_b, &"d".repeat(64), AT)
        .expect_err("run A's digest never resumes run B");
    assert_eq!(err.code, "refusal.run.control", "run B is not paused");
    let row_b = state.instance_by_id(&run_b).unwrap().unwrap();
    assert!(
        !row_b.paused && row_b.resume_digest.is_empty(),
        "an unrelated run's pause state is untouched"
    );

    // The exact digest resumes exactly this run and is consumed (single use).
    let row = state
        .resume_run(&run_a, &"d".repeat(64), "2026-09-12T00:02:00Z")
        .expect("resume commits");
    assert_eq!(row.status, "running");
    assert!(!row.paused && !row.pause_requested);
    assert!(row.resume_digest.is_empty(), "the digest is consumed");
    assert_eq!(row.pause_reason, "");
    let err = state
        .resume_run(&run_a, &"d".repeat(64), AT)
        .expect_err("a consumed digest never resumes twice");
    assert_eq!(err.code, "refusal.run.control");
}

#[test]
fn state_pause_request_waits_for_the_recorded_boundary_then_commits() {
    let fixture = StateFixture::new("pause-boundary");
    let state = fixture.open();
    let runs = seed_submission(&state, &[(5, GRANT_5)]);
    let run = runs[0].clone();

    // One step is IN FLIGHT: the request is durable but the boundary is not
    // reached yet.
    seed_attempt(&state, &run, "p1", &idem_key("inflight-0001"), None);
    assert_eq!(
        state.in_flight_run_step(&run).unwrap().as_deref(),
        Some("p1")
    );
    let row = state
        .request_run_pause(&run, "in-flight hold", &"a".repeat(64), AT)
        .expect("pause request commits");
    assert!(row.pause_requested && !row.paused, "still in flight");
    assert_ne!(row.status, "paused", "the run keeps its running state");
    let err = state
        .request_run_pause(&run, "again", &"b".repeat(64), AT)
        .expect_err("the intent is retained once");
    assert_eq!(err.code, "refusal.run.control");

    // The boundary does NOT commit while the step is claimed…
    assert!(!state.complete_run_pause_boundary(&run, AT).unwrap());
    let row = state.instance_by_id(&run).unwrap().unwrap();
    assert!(row.pause_requested && !row.paused);

    // …and commits as soon as the recorded step resolves.
    seed_attempt_resolution(&state, &idem_key("inflight-0001"), "failed");
    assert!(state.complete_run_pause_boundary(&run, AT).unwrap());
    let row = state.instance_by_id(&run).unwrap().unwrap();
    assert!(row.paused && !row.pause_requested);
    assert_eq!(row.status, "paused");
    assert!(
        !state.complete_run_pause_boundary(&run, AT).unwrap(),
        "idempotent"
    );
    assert_eq!(
        state.reconcile_run_pause_boundaries(AT).unwrap(),
        0,
        "nothing left to reconcile"
    );
}

#[test]
fn state_resume_refuses_a_stale_epoch_and_never_touches_a_second_run() {
    let fixture = StateFixture::new("resume-epoch");
    let state = fixture.open();
    let runs = seed_submission(&state, &[(5, GRANT_5), (6, GRANT_6)]);
    let (run_a, run_b) = (runs[0].clone(), runs[1].clone());
    state
        .request_run_pause(&run_a, "hold A", &"a".repeat(64), AT)
        .expect("pause A");
    state
        .request_run_pause(&run_b, "hold B", &"b".repeat(64), AT)
        .expect("pause B");

    // The run's epoch moved: fresh eligibility refuses the resume and
    // changes nothing.
    state.rotate_epoch("security_rotation").expect("rotate");
    let err = state
        .resume_run(&run_a, &"a".repeat(64), AT)
        .expect_err("a moved epoch refuses");
    assert_eq!(err.code, "refusal.state.epoch");
    let row_a = state.instance_by_id(&run_a).unwrap().unwrap();
    let row_b = state.instance_by_id(&run_b).unwrap().unwrap();
    assert!(row_a.paused && row_b.paused, "both stays paused");
    assert_eq!(row_b.resume_digest, "b".repeat(64));
}

#[test]
fn state_bounded_retry_is_single_use_and_bounded() {
    let fixture = StateFixture::new("retry-state");
    let state = fixture.open();
    let runs = seed_submission(&state, &[(5, GRANT_5)]);
    let run = runs[0].clone();

    // The spine is read back from the committed submission.
    assert_eq!(
        state.run_step_spine(&run).unwrap(),
        Some(vec!["p1".to_string(), "p2".to_string()])
    );
    // A run without a committed submission has no spine (retry is scoped to
    // queue runs; its dispatch is never fenced).
    let engine_run = state
        .start_instance("run-0000000000000001", GRANT_5, DOCTRINE_WORKFLOW_ID, AT)
        .expect("engine run");
    assert_eq!(state.run_step_spine(&engine_run.instance_id).unwrap(), None);
    assert_eq!(
        state
            .claim_run_retry(&engine_run.instance_id, "p1", &idem_key("engine-0001"), AT)
            .unwrap(),
        RunRetryClaim::NotRequired
    );

    // A recorded terminal failure is the diagnosis; without one nothing is
    // required (not a fence) and nothing is retried by the control surface.
    seed_attempt(
        &state,
        &run,
        "p1",
        &idem_key("attempt-0001"),
        Some("failed"),
    );
    assert_eq!(
        state
            .claim_run_retry(&run, "p2", &idem_key("dispatch-0000"), AT)
            .unwrap(),
        RunRetryClaim::NotRequired,
        "a step with no recorded failure is never fenced"
    );

    // First authorization: bounded, single use.
    let first = state.record_run_retry(&run, "p1", AT).expect("authorized");
    assert_eq!(first.attempt, 1);
    assert!(first.consumed_at.is_empty());
    let err = state
        .record_run_retry(&run, "p1", AT)
        .expect_err("an unconsumed authorization refuses a duplicate");
    assert_eq!(err.code, "refusal.run.retry_pending");
    assert_eq!(
        state
            .claim_run_retry(&run, "p1", &idem_key("dispatch-0001"), AT)
            .unwrap(),
        RunRetryClaim::Consumed(first.retry_id.clone())
    );
    assert_eq!(
        state
            .claim_run_retry(&run, "p1", &idem_key("dispatch-0002"), AT)
            .unwrap(),
        RunRetryClaim::Missing,
        "the authorization was spent exactly once"
    );

    // Bounded: three authorizations total, each consumed by one dispatch.
    for attempt in 2..=3 {
        let row = state
            .record_run_retry(&run, "p1", AT)
            .unwrap_or_else(|err| panic!("attempt {attempt}: {}", err.message));
        assert_eq!(row.attempt, attempt);
        assert!(matches!(
            state
                .claim_run_retry(&run, "p1", &idem_key(&format!("dispatch-100{attempt}")), AT)
                .unwrap(),
            RunRetryClaim::Consumed(_)
        ));
    }
    let err = state
        .record_run_retry(&run, "p1", AT)
        .expect_err("the bound refuses a fourth retry");
    assert_eq!(err.code, "refusal.run.retry_bound");
    assert_eq!(state.run_retries(&run).unwrap().len(), 3);
}

/// Resolve an already-claimed seeded attempt with a typed outcome.
fn seed_attempt_resolution(state: &State, key: &str, status: &str) {
    let outcome_line = canonical_text(&object(vec![
        ("schema", string("hf-outcome/v1")),
        ("plan_id", string("hf_plan_0000000000000000")),
        ("step_id", string("p1")),
        ("status", string(status)),
        ("idempotency_key", string(key)),
        ("observed_at", string(AT)),
        ("result", Val::Null),
        ("error", Val::Null),
    ]));
    state
        .resolve_claim(key, "apply", "spent", &outcome_line, Some("{}"))
        .expect("resolve the seeded attempt");
}

// ---------------------------------------------------------------------------
// AC1/AC4 (wire): stop-admitting before the next dispatch, requested vs
// reached across a restart, duplicate/concurrent controls
// ---------------------------------------------------------------------------

#[test]
fn wire_pause_stops_dispatch_before_the_boundary_and_reaches_it_when_the_step_resolves() {
    let fixture = DaemonFixture::new("pause-wire");
    let run = {
        let state = fixture.seed();
        let runs = seed_submission(&state, &[(5, GRANT_5)]);
        runs[0].clone()
    };
    // The fixture `git` shim keeps one checkout effect in flight for ~a
    // second, so the pause request lands while a step is genuinely executing.
    let fakebin = write_slow_failing_git(&fixture);
    let daemon = fixture.spawn_with_path(None, Some(&fakebin));
    wait_ready(&fixture);

    // One REAL step dispatch is in flight.
    let socket = fixture.socket.clone();
    let run_thread = run.clone();
    let dispatch = std::thread::spawn(move || {
        rpc(
            &socket,
            &fresh_id(1),
            "apply",
            Some(apply_params(
                &run_thread,
                "p1",
                &idem_key("wire-inflight-0001"),
                5,
            )),
        )
    });
    wait_for_in_flight_step(&fixture, &run, "p1");

    // The pause request stops admitting IMMEDIATELY: it is durable as
    // `pause_requested` and the boundary is honestly not reached yet.
    let paused = rpc_ok(
        &fixture.socket,
        &fresh_id(3),
        "run.pause",
        Some(pause_params(
            &idem_key("wire-pause-0001"),
            &run,
            "operator hold",
        )),
    );
    assert_eq!(
        paused.get("schema").and_then(Val::as_str),
        Some(canter::run_control::RUN_CONTROL_SCHEMA)
    );
    assert_eq!(control_state(&paused), "pause_requested");
    assert!(!boundary_reached(&paused));
    assert_eq!(
        text(&paused, &["boundary", "in_flight_step"]),
        "p1",
        "the in-flight step is reported, never cancelled"
    );
    assert_eq!(
        paused
            .get("control")
            .and_then(|c| c.get("pause_requested"))
            .and_then(Val::as_bool),
        Some(true)
    );
    let digest = resume_digest(&paused);
    assert_eq!(digest.len(), 64);
    // The scope block is the normative run/fleet/lane matrix.
    assert_eq!(text(&paused, &["scope", "level"]), "run");
    assert_eq!(text(&paused, &["scope", "run"]), run);
    assert_eq!(text(&paused, &["scope", "fleet_effect"]), "none");
    assert_eq!(text(&paused, &["scope", "lane_effect"]), "none");

    // Another step dispatch is refused BEFORE any effect, while the
    // in-flight step keeps running.
    let (code, _) = rpc_err(
        &fixture.socket,
        &fresh_id(4),
        "apply",
        Some(apply_params(&run, "p2", &idem_key("wire-dispatch-0001"), 5)),
    );
    assert_eq!(
        code, "refusal.run.paused",
        "stop-admitting precedes dispatch"
    );

    // A duplicate pause (fresh key) never creates a second intent.
    let (code, _) = rpc_err(
        &fixture.socket,
        &fresh_id(5),
        "run.pause",
        Some(pause_params(&idem_key("wire-pause-0002"), &run, "again")),
    );
    assert_eq!(code, "refusal.run.control");

    // The in-flight step reaches its recorded outcome (the shimmed checkout
    // fails); the pause then commits the reached boundary on the daemon's
    // own path — requested -> paused without anything being cancelled.
    let dispatch_doc = dispatch.join().expect("join the in-flight dispatch");
    assert_eq!(
        dispatch_doc.get("ok").and_then(Val::as_bool),
        Some(false),
        "the shimmed checkout fails: {}",
        canonical_text(&dispatch_doc)
    );
    let status = rpc_ok(
        &fixture.socket,
        &fresh_id(6),
        "run.status",
        Some(canter::run_control::status_params(&run)),
    );
    assert_eq!(
        control_state(&status),
        "paused",
        "the boundary is reached once the step resolves: {}",
        canonical_text(&status)
    );
    assert!(boundary_reached(&status));
    assert_eq!(text(&status, &["run", "status"]), "paused");

    // The reached pause survives a restart, dispatch stays refused and the
    // digest resumes exactly this run.
    shutdown(daemon);
    let daemon = fixture.spawn_with_path(None, Some(&fakebin));
    wait_ready(&fixture);
    let status = rpc_ok(
        &fixture.socket,
        &fresh_id(7),
        "run.status",
        Some(canter::run_control::status_params(&run)),
    );
    assert_eq!(control_state(&status), "paused", "durable across a restart");
    assert_eq!(
        resume_digest(&status),
        digest,
        "the digest survives the restart"
    );
    let (code, _) = rpc_err(
        &fixture.socket,
        &fresh_id(8),
        "apply",
        Some(apply_params(&run, "p2", &idem_key("wire-dispatch-0002"), 5)),
    );
    assert_eq!(code, "refusal.instance.state");
    let (code, _) = rpc_err(
        &fixture.socket,
        &fresh_id(9),
        "run.resume",
        Some(resume_params(
            &idem_key("wire-resume-0001"),
            &run,
            &"0".repeat(64),
        )),
    );
    assert_eq!(code, "state.stale_resume");
    let resumed = rpc_ok(
        &fixture.socket,
        &fresh_id(10),
        "run.resume",
        Some(resume_params(&idem_key("wire-resume-0002"), &run, &digest)),
    );
    assert_eq!(control_state(&resumed), "active");
    // The dispatch is no longer fenced by the pause: it reaches the effect
    // (which fails on the shimmed git — a recorded failed attempt, never a
    // pause refusal).
    let (code, _) = rpc_err(
        &fixture.socket,
        &fresh_id(11),
        "apply",
        Some(apply_params(&run, "p2", &idem_key("wire-dispatch-0003"), 5)),
    );
    assert_ne!(code, "refusal.run.paused");
    assert_ne!(code, "refusal.instance.state");

    shutdown(daemon);
}

// ---------------------------------------------------------------------------
// AC2 (wire): exact target, fresh eligibility, fleet/lane scope
// ---------------------------------------------------------------------------

#[test]
fn wire_resume_is_exact_target_and_never_clears_an_unrelated_pause() {
    let fixture = DaemonFixture::new("resume-wire");
    let runs = {
        let state = fixture.seed();
        seed_submission(&state, &[(5, GRANT_5), (6, GRANT_6)])
    };
    let (run_a, run_b) = (runs[0].clone(), runs[1].clone());
    let daemon = fixture.spawn(None);
    wait_ready(&fixture);

    // Both runs pause (no in-flight work: the boundary is reached at once).
    let paused_a = rpc_ok(
        &fixture.socket,
        &fresh_id(1),
        "run.pause",
        Some(pause_params(&idem_key("wire-a-0001"), &run_a, "hold A")),
    );
    let paused_b = rpc_ok(
        &fixture.socket,
        &fresh_id(2),
        "run.pause",
        Some(pause_params(&idem_key("wire-b-0001"), &run_b, "hold B")),
    );
    assert_eq!(control_state(&paused_a), "paused");
    assert_eq!(control_state(&paused_b), "paused");
    let digest_a = resume_digest(&paused_a);
    let digest_b = resume_digest(&paused_b);
    assert_ne!(digest_a, digest_b);

    // A foreign digest never resumes this run.
    let (code, _) = rpc_err(
        &fixture.socket,
        &fresh_id(3),
        "run.resume",
        Some(resume_params(&idem_key("wire-a-0002"), &run_a, &digest_b)),
    );
    assert_eq!(code, "state.stale_resume");

    // Resume A: exactly A changes. B's pause (the unrelated hold) stays.
    let resumed = rpc_ok(
        &fixture.socket,
        &fresh_id(4),
        "run.resume",
        Some(resume_params(&idem_key("wire-a-0003"), &run_a, &digest_a)),
    );
    assert_eq!(control_state(&resumed), "active");
    let status_b = rpc_ok(
        &fixture.socket,
        &fresh_id(5),
        "run.status",
        Some(canter::run_control::status_params(&run_b)),
    );
    assert_eq!(control_state(&status_b), "paused");
    assert_eq!(
        resume_digest(&status_b),
        digest_b,
        "B's authorization is intact"
    );
    // …and B can still be resumed with ITS digest (nothing was clobbered).
    let resumed_b = rpc_ok(
        &fixture.socket,
        &fresh_id(6),
        "run.resume",
        Some(resume_params(&idem_key("wire-b-0002"), &run_b, &digest_b)),
    );
    assert_eq!(control_state(&resumed_b), "active");

    // There is NO fleet-scoped control: the closed method set refuses it
    // (before any dispatch), and no fleet scope exists in the surface.
    for method in ["fleet.pause", "fleet.resume", "fleet.unpause"] {
        let doc = rpc(&fixture.socket, &fresh_id(7), method, None);
        assert_eq!(
            text(&doc, &["error", "code"]),
            "refusal.malformed",
            "{method} must not exist: {}",
            canonical_text(&doc)
        );
        assert!(
            text(&doc, &["error", "message"]).contains("closed method set"),
            "{method}: {}",
            canonical_text(&doc)
        );
    }
    // …and a non-run identity (a lane id, or free text) never addresses a run.
    for target in ["rp_0000000000000001", "run-not-hex", "lane-1"] {
        let (code, _) = rpc_err(
            &fixture.socket,
            &fresh_id(8),
            "run.pause",
            Some(pause_params(&idem_key("wire-target-0001"), target, "hold")),
        );
        assert_eq!(code, "refusal.run.target", "{target} must refuse typed");
    }

    shutdown(daemon);
}

// ---------------------------------------------------------------------------
// AC3 (wire): one diagnosed step, invalid/revoked/stale/success refusals
// ---------------------------------------------------------------------------

#[test]
fn wire_retry_names_one_diagnosed_step_and_refuses_every_ineligible_one() {
    let fixture = DaemonFixture::new("retry-wire");
    let run = {
        let state = fixture.seed();
        let runs = seed_submission(&state, &[(5, GRANT_5)]);
        runs[0].clone()
    };
    let daemon = fixture.spawn(None);
    wait_ready(&fixture);

    // Invalid: a step outside the bound spine.
    let (code, _) = rpc_err(
        &fixture.socket,
        &fresh_id(1),
        "run.retry",
        Some(retry_params(&idem_key("wire-unknown-0001"), &run, "nope")),
    );
    assert_eq!(code, "refusal.run.step_unknown");
    // Invalid: a spine step that is not the frontier.
    let (code, _) = rpc_err(
        &fixture.socket,
        &fresh_id(2),
        "run.retry",
        Some(retry_params(&idem_key("wire-order-0001"), &run, "p2")),
    );
    assert_eq!(code, "refusal.run.step_order");
    // Invalid: the frontier step has no recorded attempt at all.
    let (code, _) = rpc_err(
        &fixture.socket,
        &fresh_id(3),
        "run.retry",
        Some(retry_params(&idem_key("wire-undiagnosed-0001"), &run, "p1")),
    );
    assert_eq!(code, "refusal.run.step_undiagnosed");

    // One REAL dispatch records the failure the retry must diagnose (the
    // effect fails on the missing integration repo, so the attempt ends
    // non-success; a first dispatch is never fenced).
    let (code, _) = rpc_err(
        &fixture.socket,
        &fresh_id(4),
        "apply",
        Some(apply_params(&run, "p1", &idem_key("wire-apply-0001"), 5)),
    );
    assert_ne!(code, "refusal.run.retry_required");

    // Now the step is diagnosed and the bounded retry is authorized.
    let retry = rpc_ok(
        &fixture.socket,
        &fresh_id(5),
        "run.retry",
        Some(retry_params(&idem_key("wire-retry-0001"), &run, "p1")),
    );
    assert_eq!(
        retry.get("schema").and_then(Val::as_str),
        Some(canter::run_control::RUN_RETRY_SCHEMA)
    );
    assert_eq!(text(&retry, &["retry", "step_id"]), "p1");
    assert_eq!(
        retry
            .get("retry")
            .and_then(|r| r.get("attempt"))
            .and_then(Val::as_int),
        Some(1)
    );
    assert_eq!(
        retry
            .get("retry")
            .and_then(|r| r.get("bound"))
            .and_then(Val::as_int),
        Some(3)
    );
    assert_eq!(text(&retry, &["retry", "status"]), "authorized");
    // A duplicate while the authorization is unconsumed is refused.
    let (code, _) = rpc_err(
        &fixture.socket,
        &fresh_id(6),
        "run.retry",
        Some(retry_params(&idem_key("wire-retry-0002"), &run, "p1")),
    );
    assert_eq!(code, "refusal.run.retry_pending");

    // A re-dispatch consumes the authorization; a SECOND re-dispatch without
    // one is refused BEFORE any effect.
    let (code, _) = rpc_err(
        &fixture.socket,
        &fresh_id(7),
        "apply",
        Some(apply_params(&run, "p1", &idem_key("wire-apply-0002"), 5)),
    );
    assert_ne!(
        code, "refusal.run.retry_required",
        "the authorization was consumed"
    );
    let (code, _) = rpc_err(
        &fixture.socket,
        &fresh_id(8),
        "apply",
        Some(apply_params(&run, "p1", &idem_key("wire-apply-0003"), 5)),
    );
    assert_eq!(code, "refusal.run.retry_required");

    shutdown(daemon);
}

#[test]
fn wire_retry_refuses_a_revoked_grant_and_a_succeeded_step() {
    let fixture = DaemonFixture::new("retry-fences");
    let (revoked_run, done_run) = {
        let state = fixture.seed();
        let runs = seed_submission(&state, &[(5, GRANT_5), (6, GRANT_6)]);
        // Run A: the frontier step is diagnosed, but its grant is revoked
        // BEFORE the daemon starts (a revoked authorization).
        seed_attempt(
            &state,
            &runs[0],
            "p1",
            &idem_key("fences-0001"),
            Some("failed"),
        );
        state.revoke_grant(GRANT_5, AT).expect("revoke");
        // Run B: its frontier step already succeeded (a terminal success);
        // B's grant stays active.
        state
            .advance_instance(&runs[1], "p1", 0, 0, false, 0, "2026-09-12T00:00:30Z")
            .expect("advance B");
        (runs[0].clone(), runs[1].clone())
    };
    let daemon = fixture.spawn(None);
    wait_ready(&fixture);

    // Revoked: the run's grant is inactive.
    let (code, _) = rpc_err(
        &fixture.socket,
        &fresh_id(1),
        "run.retry",
        Some(retry_params(
            &idem_key("wire-revoked-0001"),
            &revoked_run,
            "p1",
        )),
    );
    assert_eq!(code, "refusal.grant.inactive");

    // Terminal success: the named step already succeeded.
    let (code, _) = rpc_err(
        &fixture.socket,
        &fresh_id(2),
        "run.retry",
        Some(retry_params(&idem_key("wire-done-0001"), &done_run, "p1")),
    );
    assert_eq!(code, "refusal.run.step_done");

    shutdown(daemon);
}

#[test]
fn wire_retry_refuses_a_stale_epoch() {
    // The epoch moved after the run was pinned: the retry authorization
    // dies with its epoch (fresh eligibility is re-derived, never assumed).
    let fixture = DaemonFixture::new("retry-stale");
    let run = {
        let state = fixture.seed();
        let runs = seed_submission(&state, &[(5, GRANT_5)]);
        seed_attempt(
            &state,
            &runs[0],
            "p1",
            &idem_key("fences-0002"),
            Some("failed"),
        );
        state.rotate_epoch("security_rotation").expect("rotate");
        runs[0].clone()
    };
    let daemon = fixture.spawn(None);
    wait_ready(&fixture);
    let (code, _) = rpc_err(
        &fixture.socket,
        &fresh_id(3),
        "run.retry",
        Some(retry_params(&idem_key("wire-stale-0001"), &run, "p1")),
    );
    assert_eq!(code, "refusal.state.epoch");
    shutdown(daemon);
}

// ---------------------------------------------------------------------------
// AC4 (wire): duplicate/concurrent controls, crash window, restart
// ---------------------------------------------------------------------------

#[test]
fn wire_duplicate_and_concurrent_controls_serialize_to_one_effect() {
    let fixture = DaemonFixture::new("control-serialize");
    let (run, race_run) = {
        let state = fixture.seed();
        let runs = seed_submission(&state, &[(5, GRANT_5), (6, GRANT_6)]);
        assert_eq!(runs.len(), 2);
        (runs[0].clone(), runs[1].clone())
    };
    let daemon = fixture.spawn(None);
    wait_ready(&fixture);

    // Same key, same request id: the recorded response replays byte-for-byte.
    let key = idem_key("wire-same-0001");
    let request_id = fresh_id(1);
    let first = rpc_ok(
        &fixture.socket,
        &request_id,
        "run.pause",
        Some(pause_params(&key, &run, "hold")),
    );
    let replay = rpc_ok(
        &fixture.socket,
        &request_id,
        "run.pause",
        Some(pause_params(&key, &run, "hold")),
    );
    assert_eq!(
        canonical_text(&first),
        canonical_text(&replay),
        "a duplicate request replays its recorded response"
    );

    // Concurrent controls with DIFFERENT keys on a run that carries no pause
    // yet: exactly one effect, the other is refused typed (never two pauses,
    // never a raw storage error).
    let socket = fixture.socket.clone();
    let run_thread = race_run.clone();
    let other = std::thread::spawn(move || {
        rpc(
            &socket,
            &fresh_id(2),
            "run.pause",
            Some(pause_params(
                &idem_key("wire-c1-0001"),
                &run_thread,
                "race 1",
            )),
        )
    });
    let mine = rpc(
        &fixture.socket,
        &fresh_id(3),
        "run.pause",
        Some(pause_params(&idem_key("wire-c2-0001"), &race_run, "race 2")),
    );
    let other = other.join().expect("join the racing control");
    let mine_ok = mine.get("ok").and_then(Val::as_bool) == Some(true);
    let other_ok = other.get("ok").and_then(Val::as_bool) == Some(true);
    assert!(
        mine_ok ^ other_ok,
        "exactly one concurrent control commits: mine={} other={}",
        canonical_text(&mine),
        canonical_text(&other)
    );
    let refused = if mine_ok { other } else { mine };
    assert_eq!(
        refused
            .get("error")
            .and_then(|e| e.get("code"))
            .and_then(Val::as_str),
        Some("refusal.run.control"),
        "the loser is refused typed: {}",
        canonical_text(&refused)
    );

    shutdown(daemon);
    let state = fixture.seed();
    // Both runs ended paused, each from exactly ONE intent: the replay never
    // doubled the first run's pause and the race never doubled the other's.
    for (label, target) in [("replay", &run), ("race", &race_run)] {
        let row = state.instance_by_id(target).unwrap().unwrap();
        assert!(
            row.paused && !row.pause_requested,
            "{label}: exactly one committed pause"
        );
        assert!(!row.resume_digest.is_empty(), "{label}: digest recorded");
        let retries = state.run_retries(target).unwrap();
        assert!(retries.is_empty(), "{label}: no retry side effects");
    }
    let rows = state.list_instances().unwrap();
    assert_eq!(
        rows.iter().filter(|row| row.paused).count(),
        2,
        "exactly the two controlled runs are paused"
    );
}

#[test]
fn wire_pause_intent_survives_a_daemon_death_and_commits_on_restart() {
    let fixture = DaemonFixture::new("pintent");
    let run = {
        let state = fixture.seed();
        let runs = seed_submission(&state, &[(5, GRANT_5)]);
        runs[0].clone()
    };
    let fakebin = write_slow_failing_git(&fixture);
    let mut daemon = fixture.spawn_with_path(None, Some(&fakebin));
    wait_ready(&fixture);

    // A real step is in flight when the pause request arrives.
    let socket = fixture.socket.clone();
    let run_thread = run.clone();
    let dispatch = std::thread::spawn(move || {
        rpc_quiet(
            &socket,
            &fresh_id(1),
            "apply",
            Some(apply_params(
                &run_thread,
                "p1",
                &idem_key("wire-intent-0001"),
                5,
            )),
        )
    });
    wait_for_in_flight_step(&fixture, &run, "p1");
    let paused = rpc_ok(
        &fixture.socket,
        &fresh_id(3),
        "run.pause",
        Some(pause_params(
            &idem_key("wire-intent-0002"),
            &run,
            "durable hold",
        )),
    );
    assert_eq!(control_state(&paused), "pause_requested");
    let digest = resume_digest(&paused);

    // The daemon DIES HARD with the step still in flight (SIGKILL, no
    // shutdown path). Only the durable intent is left behind.
    daemon.kill().expect("kill the daemon");
    let _ = daemon.wait();
    let _ = dispatch.join();
    let state = fixture.seed();
    let row = state.instance_by_id(&run).unwrap().unwrap();
    assert!(
        row.pause_requested && !row.paused,
        "the intent is durable independent of the process: paused={} requested={}",
        row.paused,
        row.pause_requested
    );
    assert_eq!(row.pause_reason, "durable hold");
    drop(state);

    // Restart reaches the boundary from the recorded intent: the pause is
    // NOT lost and never silently dropped.
    let daemon = fixture.spawn_with_path(None, Some(&fakebin));
    wait_ready(&fixture);
    let status = rpc_ok(
        &fixture.socket,
        &fresh_id(4),
        "run.status",
        Some(canter::run_control::status_params(&run)),
    );
    assert_eq!(
        control_state(&status),
        "paused",
        "the restart commits the recorded intent: {}",
        canonical_text(&status)
    );
    assert!(boundary_reached(&status));
    assert_eq!(resume_digest(&status), digest);
    let (code, _) = rpc_err(
        &fixture.socket,
        &fresh_id(5),
        "apply",
        Some(apply_params(&run, "p2", &idem_key("wire-intent-0003"), 5)),
    );
    assert_eq!(code, "refusal.instance.state");

    shutdown(daemon);
}

#[test]
fn wire_interrupted_control_claim_commits_nothing_and_reconciles_on_restart() {
    let fixture = DaemonFixture::new("control-crash");
    let run = {
        let state = fixture.seed();
        let runs = seed_submission(&state, &[(5, GRANT_5)]);
        runs[0].clone()
    };
    let mut daemon = fixture.spawn(Some("run.control.after-intent"));
    wait_ready(&fixture);

    // The daemon dies between the claim and the control commit.
    let mut connection = Connection::open(&fixture.socket).expect("connect");
    connection
        .send_request(
            &fresh_id(1),
            "run.pause",
            Some(&pause_params(
                &idem_key("wire-crash-0001"),
                &run,
                "interrupted hold",
            )),
        )
        .expect("send");
    drop(connection);
    let deadline = Instant::now() + Duration::from_secs(15);
    while daemon.try_wait().expect("try_wait").is_none() {
        assert!(Instant::now() < deadline, "the daemon did not crash");
        std::thread::sleep(Duration::from_millis(25));
    }

    // The interrupted request committed NOTHING …
    let row = {
        let state = fixture.seed();
        let row = state.instance_by_id(&run).unwrap().unwrap();
        assert!(
            !row.paused && !row.pause_requested && row.resume_digest.is_empty(),
            "an interrupted control leaves nothing behind"
        );
        row
    };
    assert_eq!(row.pause_reason, "");

    // …and the restart reconciles the claim as a readback (never a replay).
    let daemon = fixture.spawn(None);
    wait_ready(&fixture);
    let log = std::fs::read_to_string(fixture.state_dir.join("canter").join("daemon.log"))
        .expect("daemon log");
    assert!(
        log.contains("reconcile.run-control"),
        "the restart reconciles the interrupted control: {log}"
    );
    let doctor = rpc_ok(&fixture.socket, &fresh_id(2), "doctor", None);
    assert_eq!(
        doctor.get("pending_claims").and_then(Val::as_int),
        Some(0),
        "no claim left in flight"
    );

    // A fresh key records the pause durably.
    let paused = rpc_ok(
        &fixture.socket,
        &fresh_id(3),
        "run.pause",
        Some(pause_params(
            &idem_key("wire-crash-0002"),
            &run,
            "fresh hold",
        )),
    );
    assert_eq!(control_state(&paused), "paused");

    shutdown(daemon);
}

// ---------------------------------------------------------------------------
// Issue #92 F3 (wire): the retry frontier derives from the recorded attempt
// ledger, so an `ambiguous` timed-out attempt whose node fell behind is
// addressable — and the authorization is still consumed exactly once.
// ---------------------------------------------------------------------------

#[test]
fn wire_retry_addresses_the_ledger_frontier_not_a_stale_node() {
    let fixture = DaemonFixture::new("retry-ledger");
    let run = {
        let state = fixture.seed();
        let runs = seed_submission(&state, &[(5, GRANT_5)]);
        // The F3 defect shape, recorded durably: `p1` succeeded, `p2` was
        // dispatched and timed out (`ambiguous`), and the run's recorded
        // node never left the start (a stale node). The node-derived
        // frontier would name `p1` (already succeeded) and refuse the step
        // that actually needs the retry.
        seed_attempt(
            &state,
            &runs[0],
            "p1",
            &idem_key("ledger-0001"),
            Some("succeeded"),
        );
        seed_attempt(
            &state,
            &runs[0],
            "p2",
            &idem_key("ledger-0002"),
            Some("ambiguous"),
        );
        runs[0].clone()
    };
    let daemon = fixture.spawn(None);
    wait_ready(&fixture);

    // A step already recorded succeeded stays a terminal-success refusal.
    let (code, _) = rpc_err(
        &fixture.socket,
        &fresh_id(1),
        "run.retry",
        Some(retry_params(&idem_key("ledger-done-0001"), &run, "p1")),
    );
    assert_eq!(code, "refusal.run.step_done");

    // The diagnosed `ambiguous` attempt IS the frontier and is addressable.
    let retry = rpc_ok(
        &fixture.socket,
        &fresh_id(2),
        "run.retry",
        Some(retry_params(&idem_key("ledger-retry-0001"), &run, "p2")),
    );
    assert_eq!(text(&retry, &["retry", "step_id"]), "p2");
    assert_eq!(text(&retry, &["retry", "status"]), "authorized");
    assert_eq!(
        retry
            .get("spine")
            .and_then(|spine| spine.get("next_step"))
            .and_then(Val::as_str),
        Some("p2"),
        "the rendered frontier is the ledger frontier"
    );
    // The duplicate stays refused while the authorization is unconsumed.
    let (code, _) = rpc_err(
        &fixture.socket,
        &fresh_id(3),
        "run.retry",
        Some(retry_params(&idem_key("ledger-retry-0002"), &run, "p2")),
    );
    assert_eq!(code, "refusal.run.retry_pending");

    // ONE re-dispatch consumes it (the effect itself fails on the missing
    // integration repo — the attempt is what matters).
    let (code, _) = rpc_err(
        &fixture.socket,
        &fresh_id(4),
        "apply",
        Some(apply_params(&run, "p2", &idem_key("ledger-apply-0001"), 5)),
    );
    assert_ne!(code, "refusal.run.retry_required");
    // ...and the SECOND re-dispatch without one is refused BEFORE any effect.
    let (code, _) = rpc_err(
        &fixture.socket,
        &fresh_id(5),
        "apply",
        Some(apply_params(&run, "p2", &idem_key("ledger-apply-0002"), 5)),
    );
    assert_eq!(code, "refusal.run.retry_required");
    // Replaying the FIRST dispatch (same request id + same key) replays the
    // recorded claim: no further attempt row appears (no duplicate effect).
    let before = {
        let state = fixture.seed();
        state
            .run_step_attempts(&run)
            .expect("attempts")
            .iter()
            .filter(|(step, _)| step == "p2")
            .count()
    };
    let _ = rpc(
        &fixture.socket,
        &fresh_id(4),
        "apply",
        Some(apply_params(&run, "p2", &idem_key("ledger-apply-0001"), 5)),
    );
    // Exactly one authorization row exists, and it is consumed once.
    let state = fixture.seed();
    let attempts = state.run_step_attempts(&run).expect("attempts");
    assert_eq!(
        attempts.iter().filter(|(step, _)| step == "p2").count(),
        before,
        "the replay never adds an attempt: {attempts:?}"
    );
    let retries = state.run_retries(&run).expect("retry rows");
    assert_eq!(retries.len(), 1, "one bounded authorization per request");
    assert!(
        !retries[0].consumed_at.is_empty(),
        "the authorization was consumed by the single re-dispatch"
    );

    shutdown(daemon);
}

// ---------------------------------------------------------------------------
// Issue #146: the explicit release of a run that can never progress —
// ownership/occupancy freed, the reason and the run identity audited, and
// every genuinely live run still fenced.
// ---------------------------------------------------------------------------

/// The recorded `run.release` audit records of one state store, oldest
/// first (the release transaction appends its record with the effect).
fn release_records(state: &State) -> Vec<Val> {
    let (_, lines) = state.journal_tail(0, 10_000).expect("journal tail");
    lines
        .iter()
        .filter_map(|line| Val::parse_json(line).ok())
        .filter(|doc| doc.get("action").and_then(Val::as_str) == Some("run.release"))
        .collect()
}

fn release_params(key: &str, instance_id: &str, reason: &str) -> Val {
    canter::run_control::release_params(key, instance_id, reason)
}

/// The `(status, reason)` of the only item of one recorded submission.
fn item_outcome(item: &QueueSubmissionItemRow) -> (&str, &str) {
    (
        item.status.as_str(),
        item.reason.as_deref().unwrap_or_default(),
    )
}

#[test]
fn state_release_frees_the_issue_for_a_fresh_submission() {
    let fixture = StateFixture::new("release-state");
    let state = fixture.open();
    let runs = seed_submission(&state, &[(5, GRANT_5), (6, GRANT_6)]);
    let victim = runs[0].clone();
    let other = runs[1].clone();
    assert_eq!(state.queue_ownership_rows().expect("ownership").len(), 2);

    // Control (the reported symptom): while the predecessor owns #5, a fresh
    // submission for that issue is refused outright.
    let owned = submit_with_id(&state, "qs_0000000000000101", &[(5, GRANT_5)]);
    assert_eq!(
        item_outcome(&owned[0]),
        ("refused", "submission.already_owned")
    );

    // The release: ONE transaction that frees the ownership row and the run
    // itself, and records why.
    let outcome = state
        .release_run(
            &victim,
            "dead predecessor kept permanent ownership",
            "ik_release-146-0001",
            AT,
        )
        .expect("release commits");
    assert!(outcome.ownership_freed);
    assert_eq!(outcome.run.status, "invalidated");
    assert!(outcome.grant_usable, "the window it held is recorded");

    // Ownership is free: only the unrelated lane remains, and the released
    // run keeps its committed spine (a release is not a rewrite).
    let owners = state.queue_ownership_rows().expect("ownership");
    assert_eq!(owners.len(), 1);
    assert_eq!(owners[0].instance_id, other);
    assert!(state.run_step_spine(&victim).expect("spine").is_some());

    // A fresh-key release of an already freed terminal run is an audited no-op.
    let again = state
        .release_run(&victim, "again", "ik_release-146-0002", AT)
        .expect("terminal release is safe to repeat");
    assert!(!again.ownership_freed);
    assert_eq!(again.run.status, "invalidated");

    // The audit carries the reason, the exact run identity and the window.
    let records = release_records(&state);
    assert_eq!(records.len(), 2, "one record per fresh key: {records:?}");
    assert!(
        records[1]
            .get("target")
            .and_then(Val::as_str)
            .expect("target")
            .contains("ownership:absent")
    );
    let target = records[0]
        .get("target")
        .and_then(Val::as_str)
        .expect("recorded target");
    assert!(target.starts_with(&format!("run:{victim}:")), "{target}");
    assert!(
        target.contains(&format!("repository:{REPO}#5@{REV_A}")),
        "{target}"
    );
    assert!(target.contains("ownership:freed"), "{target}");
    assert!(target.contains(&format!("grant:{GRANT_5}")), "{target}");
    assert!(target.contains("grant_usable:true"), "{target}");
    assert!(
        target.ends_with("reason:dead predecessor kept permanent ownership"),
        "{target}"
    );
    assert_eq!(
        records[0].get("idempotency_key").and_then(Val::as_str),
        Some("ik_release-146-0001")
    );

    // The freed issue is admitted again on its own merits, as a NEW run that
    // uniquely owns it.
    let readmitted = submit_with_id(&state, "qs_0000000000000103", &[(5, GRANT_5)]);
    assert_eq!(item_outcome(&readmitted[0]), ("admitted", ""));
    let new_run = readmitted[0].instance_id.clone().expect("new run");
    assert_ne!(new_run, victim);
    let owners = state.queue_ownership_rows().expect("ownership");
    assert_eq!(owners.len(), 2);
    assert!(
        owners
            .iter()
            .any(|owner| owner.issue_number == 5 && owner.instance_id == new_run),
        "the unique ownership row names the fresh run: {owners:?}"
    );
}

#[test]
fn state_release_frees_the_occupancy_the_run_held() {
    let fixture = StateFixture::new("release-capacity");
    let state = fixture.open();
    // The per-repository cap (2) is spent on two live runs and the freed run
    // is the one that can never progress.
    let runs = seed_submission(&state, &[(5, GRANT_5), (6, GRANT_6)]);
    let victim = runs[0].clone();
    let held = submit_with_id(&state, "qs_0000000000000201", &[(7, GRANT_7)]);
    assert_eq!(
        item_outcome(&held[0]),
        ("waiting", "refusal.admission.cap_repository")
    );

    // Releasing the dead run frees the slot it held...
    let outcome = state
        .release_run(
            &victim,
            "dead run held a capacity slot it could never use",
            "ik_release-146-0006",
            AT,
        )
        .expect("release commits");
    assert!(outcome.ownership_freed);

    // ... so the issue that was waiting for capacity is admitted...
    let admitted = submit_with_id(&state, "qs_0000000000000202", &[(7, GRANT_7)]);
    assert_eq!(item_outcome(&admitted[0]), ("admitted", ""));
    // ... and exactly ONE slot was freed: a further issue still waits for it.
    let still_held = submit_with_id(&state, "qs_0000000000000203", &[(8, GRANT_8)]);
    assert_eq!(
        item_outcome(&still_held[0]),
        ("waiting", "refusal.admission.cap_repository")
    );
}

#[test]
fn state_release_of_a_paused_predecessor_clears_the_pause_and_admits_a_fresh_submission() {
    let fixture = StateFixture::new("release-paused");
    let state = fixture.open();
    let run = seed_submission(&state, &[(5, GRANT_5)])[0].clone();
    let digest = sha256_hex(b"release-paused-witness");
    let paused = state
        .request_run_pause(&run, "operator hold", &digest, AT)
        .expect("pause commits at the boundary");
    assert!(paused.paused);

    // The reported case 1: a paused predecessor refuses every fresh
    // submission for its issue, forever.
    let refused = submit_with_id(&state, "qs_0000000000000201", &[(5, GRANT_5)]);
    assert_eq!(item_outcome(&refused[0]), ("refused", "submission.paused"));

    // A release is the supported path out, and it clears the pause state so
    // no stale resume digest survives a terminal run.
    let outcome = state
        .release_run(
            &run,
            "paused predecessor blocked a zero-operator redrive",
            "ik_release-146-0003",
            AT,
        )
        .expect("a paused run is releasable");
    assert!(outcome.ownership_freed);
    assert_eq!(outcome.run.status, "invalidated");
    assert!(!outcome.run.paused && !outcome.run.pause_requested);
    assert!(outcome.run.resume_digest.is_empty());
    let err = state
        .resume_run(&run, &digest, AT)
        .expect_err("a released run is never resumed");
    assert_eq!(err.code, "refusal.run.terminal");

    let readmitted = submit_with_id(&state, "qs_0000000000000202", &[(5, GRANT_5)]);
    assert_eq!(readmitted[0].status, "admitted");
    assert_ne!(readmitted[0].instance_id.clone().expect("run"), run);
}

#[test]
fn state_release_refuses_while_an_unconsumed_authorization_exists() {
    let fixture = StateFixture::new("release-authorized");
    let state = fixture.open();
    let run = seed_submission(&state, &[(5, GRANT_5)])[0].clone();
    // A diagnosed failed attempt plus ONE bounded retry authorization: the
    // run still HOLDS an authorization, so it is not releasable.
    seed_attempt(
        &state,
        &run,
        "p1",
        &idem_key("release-attempt-0001"),
        Some("failed"),
    );
    let retry = state
        .record_run_retry(&run, "p1", AT)
        .expect("authorization recorded");
    assert!(retry.consumed_at.is_empty());

    let err = state
        .release_run(&run, "dead predecessor", "ik_release-146-0004", AT)
        .expect_err("a live authorization fences the release");
    println!("LIVE retry authorization release: {err:?}");
    assert_eq!(err.code, "refusal.run.retry_pending");
    assert!(err.message.contains(&retry.retry_id), "{}", err.message);

    // Nothing was burned and nothing was freed: the run is untouched, its
    // ownership row is intact and the authorization is still unconsumed.
    assert_eq!(
        state
            .instance_by_id(&run)
            .expect("run")
            .expect("row")
            .status,
        "new"
    );
    assert_eq!(state.queue_ownership_rows().expect("ownership").len(), 1);
    let rows = state.run_retries(&run).expect("retries");
    assert_eq!(rows.len(), 1);
    assert!(
        rows[0].consumed_at.is_empty(),
        "the authorization is never burned by a refused release"
    );
    assert!(release_records(&state).is_empty());
}

#[test]
fn state_release_of_a_run_whose_grant_expired_is_the_same_supported_path() {
    let fixture = StateFixture::new("release-expired");
    let state = fixture.open();
    let run = seed_submission(&state, &[(5, GRANT_5)])[0].clone();
    // The predecessor's window expires (the reported case 3: the run is dead
    // with no path forward).
    {
        let conn =
            rusqlite::Connection::open(fixture.dir.join("state.db")).expect("raw connection");
        let affected = conn
            .execute(
                "UPDATE grants SET expires_at = ?2 WHERE grant_id = ?1",
                rusqlite::params![GRANT_5, "2000-01-01T00:00:00Z"],
            )
            .expect("expire the window");
        assert_eq!(affected, 1);
    }
    // It still owns its issue: a fresh submission for that issue is refused.
    let owned = submit_with_id(&state, "qs_0000000000000301", &[(5, GRANT_5)]);
    assert_eq!(
        item_outcome(&owned[0]),
        ("refused", "submission.already_owned")
    );

    // The SAME release path reaches it, and the record states the window it
    // held without ever presenting or reusing it.
    let outcome = state
        .release_run(
            &run,
            "predecessor grant expired; no path forward",
            "ik_release-146-0005",
            AT,
        )
        .expect("an expired-grant run is releasable");
    assert!(outcome.ownership_freed);
    assert!(!outcome.grant_usable, "the window was honestly expired");
    let window = outcome.grant.expect("the recorded window");
    assert_eq!(window.grant_id, GRANT_5);
    assert_eq!(window.expires_at, "2000-01-01T00:00:00Z");
    let records = release_records(&state);
    assert_eq!(records.len(), 1);
    let target = records[0]
        .get("target")
        .and_then(Val::as_str)
        .expect("recorded target");
    assert!(target.contains("grant_usable:false"), "{target}");
    assert!(target.contains(&format!("grant:{GRANT_5}")), "{target}");
    assert!(
        target.ends_with("reason:predecessor grant expired; no path forward"),
        "{target}"
    );

    // The expired window is never silently reused ...
    let stale = submit_with_id(&state, "qs_0000000000000302", &[(5, GRANT_5)]);
    assert_eq!(
        item_outcome(&stale[0]),
        ("refused", "refusal.grant.expired")
    );
    // ... a freshly issued window for the same binding is admitted.
    let fresh = submit_with_id(&state, "qs_0000000000000303", &[(5, GRANT_5B)]);
    assert_eq!(fresh[0].status, "admitted");
    assert_ne!(fresh[0].instance_id.as_deref(), Some(run.as_str()));
}

#[test]
fn wire_release_refuses_a_run_with_a_step_in_flight_then_frees_it_once_settled() {
    let fixture = DaemonFixture::new("release-wire");
    let run = {
        let state = fixture.seed();
        seed_submission(&state, &[(5, GRANT_5)])[0].clone()
    };
    // The fixture `git` shim keeps one checkout effect in flight for ~a
    // second, so the release lands while a step is genuinely executing.
    let fakebin = write_slow_failing_git(&fixture);
    let daemon = fixture.spawn_with_path(None, Some(&fakebin));
    wait_ready(&fixture);

    let socket = fixture.socket.clone();
    let run_thread = run.clone();
    let dispatch = std::thread::spawn(move || {
        rpc(
            &socket,
            &fresh_id(1),
            "apply",
            Some(apply_params(
                &run_thread,
                "p1",
                &idem_key("release-inflight-0001"),
                5,
            )),
        )
    });
    wait_for_in_flight_step(&fixture, &run, "p1");

    // A run with work in flight is genuinely live: the release refuses typed
    // and changes NOTHING (no ownership freed, no audit record, no kill).
    let (code, message) = rpc_err(
        &fixture.socket,
        &fresh_id(3),
        "run.release",
        Some(release_params(
            &idem_key("release-live-0001"),
            &run,
            "predecessor is dead",
        )),
    );
    assert_eq!(code, "refusal.run.in_flight", "{message}");
    println!("LIVE in-flight release: {code}: {message}");
    {
        let state = fixture.seed();
        assert_eq!(state.queue_ownership_rows().expect("ownership").len(), 1);
        assert_eq!(
            state
                .instance_by_id(&run)
                .expect("run")
                .expect("row")
                .status,
            "new"
        );
        assert!(
            release_records(&state).is_empty(),
            "a refused release records no release"
        );
    }

    // The in-flight step reaches its recorded outcome (the shimmed checkout
    // fails); nothing was cancelled by the refusal.
    let dispatch_doc = dispatch.join().expect("join the in-flight dispatch");
    assert_eq!(
        dispatch_doc.get("ok").and_then(Val::as_bool),
        Some(false),
        "the shimmed checkout fails: {}",
        canonical_text(&dispatch_doc)
    );

    // Now the same release commits: the ownership and the occupancy are
    // freed and the run goes terminal.
    let released = rpc_ok(
        &fixture.socket,
        &fresh_id(4),
        "run.release",
        Some(release_params(
            &idem_key("release-ok-0001"),
            &run,
            "predecessor can never progress",
        )),
    );
    assert_eq!(
        text(&released, &["schema"]),
        canter::run_control::RUN_RELEASE_SCHEMA
    );
    assert_eq!(text(&released, &["release", "ownership"]), "freed");
    assert_eq!(text(&released, &["run", "status"]), "invalidated");
    assert_eq!(text(&released, &["release", "status"]), "invalidated");
    assert_eq!(
        text(&released, &["release", "reason"]),
        "predecessor can never progress"
    );
    assert_eq!(
        text(&released, &["release", "authorization", "grant_id"]),
        GRANT_5
    );
    assert_eq!(
        released
            .get("release")
            .and_then(|release| release.get("authorization"))
            .and_then(|authorization| authorization.get("usable"))
            .and_then(Val::as_bool),
        Some(true)
    );
    assert_eq!(text(&released, &["scope", "level"]), "run");
    assert_eq!(text(&released, &["scope", "run"]), run);
    let release_id = text(&released, &["release_id"]).to_string();
    assert!(
        release_id.starts_with("rl_") && release_id.len() == 19,
        "{release_id}"
    );

    // Idempotency: the SAME request id + key replays the recorded response
    // byte for byte (a retry never releases twice).
    let replay = rpc_ok(
        &fixture.socket,
        &fresh_id(4),
        "run.release",
        Some(release_params(
            &idem_key("release-ok-0001"),
            &run,
            "predecessor can never progress",
        )),
    );
    assert_eq!(
        canonical_text(&replay),
        canonical_text(&released),
        "the recorded release response is replayed"
    );
    // A FRESH key records an ownership-absent no-op, never another deletion.
    let again = rpc_ok(
        &fixture.socket,
        &fresh_id(5),
        "run.release",
        Some(release_params(
            &idem_key("release-again-0001"),
            &run,
            "again",
        )),
    );
    assert_eq!(text(&again, &["release", "ownership"]), "absent");
    assert_eq!(text(&again, &["run", "status"]), "invalidated");

    // The released run is inert: the daemon refuses every effect for it ...
    let (code, _) = rpc_err(
        &fixture.socket,
        &fresh_id(6),
        "apply",
        Some(apply_params(&run, "p1", &idem_key("release-after-0001"), 5)),
    );
    assert_eq!(code, "refusal.instance.state");
    // ... one release record per fresh key exists, and the issue is free again.
    let state = fixture.seed();
    assert_eq!(release_records(&state).len(), 2);
    assert!(state.queue_ownership_rows().expect("ownership").is_empty());
    let readmitted = submit_with_id(&state, "qs_0000000000000401", &[(5, GRANT_5)]);
    assert_eq!(readmitted[0].status, "admitted");
    assert_ne!(readmitted[0].instance_id.as_deref(), Some(run.as_str()));

    shutdown(daemon);
}
