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
        skills: Vec::new(),
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
    request_with_steps(issues, vec![step("p1", "checkout"), step("p2", "checkout")])
}

/// The same request over the caller's OWN reviewed steps: the bound document IS
/// the run's spine, so a witness can commit a check-producing review step and
/// the merge frontier that consumes it.
fn request_with_steps(
    issues: Vec<qp::SelectedIssue>,
    steps: Vec<qp::PlannedStep>,
) -> qp::QueueRequest {
    let mut request = request_with_default_steps(issues);
    request.steps = steps;
    request
}

/// The base request (steps replaced by [`request_with_steps`]).
fn request_with_default_steps(issues: Vec<qp::SelectedIssue>) -> qp::QueueRequest {
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
const NO_PROGRESS_SECS: u64 = 120;

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

// ---------------------------------------------------------------------------
// Issue #230: the recorded check failure is RE-EVALUATED, never adjudicated
// ---------------------------------------------------------------------------

/// One committed submission over the caller's OWN reviewed steps (the run's
/// spine IS the committed bound-input document).
fn submit_with_steps(
    state: &State,
    submission_id: &str,
    issues: &[(i64, &str)],
    steps: Vec<qp::PlannedStep>,
) -> Vec<QueueSubmissionItemRow> {
    for (number, grant_id) in issues {
        if state.grant_by_id(grant_id).expect("grant read").is_none() {
            state
                .issue_grant(&grant_with_review(grant_id, *number))
                .expect("issue grant");
        }
    }
    let request = request_with_steps(
        issues
            .iter()
            .map(|(number, _)| selected(&format!("#{number}"), REV_A))
            .collect(),
        steps,
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
        boundary_caps: vec![
            "read".to_string(),
            "review".to_string(),
            "merge".to_string(),
        ],
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
        supervision: None,
        at: AT.to_string(),
    };
    let (_, items) = state.submit_queue_run(&plan).expect("submission commits");
    items
}

/// [`grant_doc`] with the `review` capability the check-producing step needs.
fn grant_with_review(grant_id: &str, number: i64) -> Val {
    Val::parse_json(&format!(
        r#"{{"schema":"hf-grant/v1","grant_id":"{grant_id}","repository":"{REPO}",
            "issue":{{"number":{number},"revision":"{REV_A}"}},
            "workflow_hash":"{WORKFLOW_HASH}","policy_hash":"{POLICY_HASH}",
            "phase":"merge","scope":"worktrees/issues/{number}",
            "caps":["read","worktree","spawn","review","merge"],
            "expires_at":"2999-01-01T00:00:00Z","state_epoch":1,
            "created_at":"2026-09-06T00:00:00Z"}}"#
    ))
    .expect("grant document")
}

/// One check-producing review step that declares its reviewer LEG (the only
/// shape that computes checks; a presented-facts step is refused by the
/// control because there is nothing to recompute).
fn review_leg_step(id: &str, worktree: &str, deadline: i64) -> qp::PlannedStep {
    qp::PlannedStep {
        id: id.to_string(),
        kind: "review_evidence".to_string(),
        params: Some(object(vec![
            ("execution", string("headless")),
            ("harness_key", string(HARNESS)),
            ("kind", string("pi")),
            ("reviewer_profile", binding_doc()),
            ("worktree", string(worktree)),
            ("deadline_secs", integer(deadline)),
        ])),
    }
}

/// One `checks` array as a reviewer records it.
fn checks(items: &[(&str, &str)]) -> Val {
    Val::Arr(
        items
            .iter()
            .map(|(name, status)| object(vec![("name", string(name)), ("status", string(status))]))
            .collect(),
    )
}

fn reevaluation_params(key: &str, run: &str, step: &str, operator: &str, reason: &str) -> Val {
    canter::run_control::reevaluation_params(key, run, step, operator, reason)
}

/// Seed one recorded `apply` attempt of (run, step) that carries the run's
/// dispatch TOPOLOGY (the immutable context a real first dispatch records, and
/// the one a re-evaluation's own dispatch re-presents).
fn seed_topology(state: &State, run: &str, step: &str, key: &str) {
    let integration_repo = std::env::temp_dir().join("hf-run-86-integration-repo");
    let worktrees_root = std::env::temp_dir().join("hf-run-86-worktrees");
    std::fs::create_dir_all(&integration_repo).expect("integration repo dir");
    std::fs::create_dir_all(&worktrees_root).expect("worktrees dir");
    let line = canonical_text(&object(vec![
        ("schema", string("hf-rpc-request/v1")),
        ("id", string(&fresh_id(31))),
        ("method", string("apply")),
        (
            "params",
            object(vec![
                ("idempotency_key", string(key)),
                ("instance_id", string(run)),
                ("step", string(step)),
                (
                    "topology",
                    object(vec![
                        ("integration_branch", string("staging")),
                        ("production_branches", Val::Arr(Vec::new())),
                        (
                            "integration_repo",
                            string(&integration_repo.display().to_string()),
                        ),
                        (
                            "worktrees_root",
                            string(&worktrees_root.display().to_string()),
                        ),
                    ]),
                ),
            ]),
        ),
    ]));
    let request_id = fresh_id(32);
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
        .expect("claim the topology-carrying attempt");
    let outcome_line = canonical_text(&object(vec![
        ("schema", string("hf-outcome/v1")),
        ("plan_id", string("hf_plan_0000000000000000")),
        ("step_id", string(step)),
        ("status", string("succeeded")),
        ("idempotency_key", string(key)),
        ("observed_at", string(AT)),
        ("result", Val::Null),
        ("error", Val::Null),
    ]));
    state
        .resolve_claim(key, "apply", "spent", &outcome_line, Some("{}"))
        .expect("resolve the attempt");
}

/// Seed ONE succeeded `collect_outcome` attempt whose recorded RESPONSE
/// certifies the run's delivery head (issue #202: the certificate is read
/// from the `response` column, never the outcome's `result`).
fn seed_collection(
    state: &State,
    run: &str,
    step: &str,
    key: &str,
    head: &str,
    base: &str,
    branch: &str,
) {
    let plan = object(vec![
        ("schema", string("hf-plan/v1")),
        ("plan_id", string("hf_plan_0000000000000000")),
        ("workflow_id", string(DOCTRINE_WORKFLOW_ID)),
        ("workflow_hash", string(WORKFLOW_HASH)),
        ("state_epoch", integer(1)),
        ("repository", string(REPO)),
        (
            "issue",
            object(vec![("number", integer(6)), ("revision", string(REV_A))]),
        ),
        (
            "steps",
            Val::Arr(vec![object(vec![
                ("id", string(step)),
                ("kind", string("collect_outcome")),
                (
                    "params",
                    object(vec![
                        ("worktree", string("issues/6")),
                        ("branch", string(branch)),
                        ("requires_delta", Val::Bool(true)),
                    ]),
                ),
            ])]),
        ),
    ]);
    let line = canonical_text(&object(vec![
        ("schema", string("hf-rpc-request/v1")),
        ("id", string(&fresh_id(41))),
        ("method", string("apply")),
        (
            "params",
            object(vec![
                ("idempotency_key", string(key)),
                ("instance_id", string(run)),
                ("step", string(step)),
                ("plan", plan),
            ]),
        ),
    ]));
    let request_id = fresh_id(42);
    state
        .journal_intent(
            "mutate.collect_outcome",
            &format!("{REPO}:{run}:{step}"),
            key,
            &request_id,
            "apply",
            None,
            None,
            &line,
        )
        .expect("claim the collection attempt");
    let outcome_line = canonical_text(&object(vec![
        ("schema", string("hf-outcome/v1")),
        ("plan_id", string("hf_plan_0000000000000000")),
        ("step_id", string(step)),
        ("status", string("succeeded")),
        ("idempotency_key", string(key)),
        ("observed_at", string(AT)),
        ("result", Val::Null),
        ("error", Val::Null),
    ]));
    let response = canonical_text(&object(vec![
        ("ok", Val::Bool(true)),
        (
            "result",
            object(vec![
                ("head", string(head)),
                ("branch", string(branch)),
                // The collection also records the integration base it observed:
                // the run's dispatch context reads it back for the steps that
                // consume an exact-head/base binding.
                ("integration_base", string(base)),
            ]),
        ),
    ]));
    state
        .resolve_claim(key, "apply", "spent", &outcome_line, Some(&response))
        .expect("resolve the collection attempt");
}

/// Issue #230: a check recorded non-`passed` inside the evidence of a step
/// that SUCCEEDED is re-evaluated by that step's OWN producer — never
/// adjudicated. The witness drives the shipped RPC over a real daemon and
/// reads the durable records the control leaves behind: the attributed journal
/// record and the re-dispatched attempt at a FRESH lane round. What it does
/// NOT do is run a reviewer leg to a written verdict (the lane's disclosed
/// gap): the recomputation's own verdict is recorded by the ordinary review
/// path either way.
#[test]
fn a_recorded_check_failure_is_re_evaluated_by_its_producer_never_adjudicated() {
    let head = "aa".repeat(20);
    let base = "bb".repeat(20);
    let fixture = DaemonFixture::new("reevaluate230");
    let state = fixture.seed();
    let items = submit_with_steps(
        &state,
        "qs_0000000000000230",
        &[(5, GRANT_5), (6, GRANT_6)],
        vec![
            step("p1", "checkout"),
            step("p5", "collect_outcome"),
            review_leg_step("p6", "issues/5", 1),
            step("p7", "merge"),
        ],
    );
    assert_eq!(items.len(), 2, "two runs in membership order");
    let clean = items[0].instance_id.clone().expect("admitted");
    let deadlocked = items[1].instance_id.clone().expect("admitted");
    for run in [&clean, &deadlocked] {
        seed_attempt(
            &state,
            run,
            "p6",
            &idem_key(&format!("230-p6-{}", &run[4..12])),
            Some("succeeded"),
        );
        // The run's recorded dispatch context (the topology its own first
        // dispatch presented): the re-evaluation re-dispatches through the
        // SAME derived path, so it presents the same immutable context.
        seed_topology(
            &state,
            run,
            "p1",
            &idem_key(&format!("230-p1-{}", &run[4..12])),
        );
        // The run's own collection certified its delivery head (issue #202).
        seed_collection(
            &state,
            run,
            "p5",
            &idem_key(&format!("230-p5-{}", &run[4..12])),
            &head,
            &base,
            &format!("issue-{}", if run == &clean { 5 } else { 6 }),
        );
    }
    // The clean run's newest evidence passes every check...
    state
        .record_evidence(
            &clean,
            REPO,
            &head,
            &base,
            WORKFLOW_HASH,
            POLICY_HASH,
            "pass",
            "rev-5-r1",
            &checks(&[("hosted-ci", "passed")]),
        )
        .expect("clean evidence");
    // ...while the deadlocked run carries the transient failure the live run
    // hit: a `pass` verdict whose own check list names the blocker.
    let failed = state
        .record_evidence(
            &deadlocked,
            REPO,
            &head,
            &base,
            WORKFLOW_HASH,
            POLICY_HASH,
            "pass",
            "rev-6-r1",
            &checks(&[
                ("hosted-ci", "passed"),
                ("local_cargo_test_aggregate", "failed"),
            ]),
        )
        .expect("deadlocked evidence");
    let daemon = fixture.spawn(None);
    wait_ready(&fixture);

    // 1. A step that produces no check refuses: the merge frontier is not the
    //    producer, so nothing about it can be re-evaluated.
    let (code, message) = rpc_err(
        &fixture.socket,
        &fresh_id(11),
        "run.reevaluate",
        Some(reevaluation_params(
            &idem_key("230-merge-step"),
            &deadlocked,
            "p7",
            "operator-a",
            "the aggregate hit a transient harness failure",
        )),
    );
    assert_eq!(code, "refusal.run.reevaluation_step");
    assert!(
        message.contains("review_evidence"),
        "the refusal names the producer kind: {message}"
    );

    // 2. A record whose checks all passed has nothing to recompute.
    let (code, _) = rpc_err(
        &fixture.socket,
        &fresh_id(12),
        "run.reevaluate",
        Some(reevaluation_params(
            &idem_key("230-clean-record"),
            &clean,
            "p6",
            "operator-a",
            "the aggregate hit a transient harness failure",
        )),
    );
    assert_eq!(code, "refusal.run.reevaluation_shape");

    // 3. The recorded deadlock IS re-evaluable: the control passes its own
    //    gates, records the operator's act, and re-dispatches the producer.
    //    The re-dispatch then meets the run's OWN remaining gates, whose typed
    //    refusal is carried verbatim — never a control-level one.
    //
    //    This fixture cannot go further, and the assertion NAMES where it
    //    stops: the re-dispatched review step is a fan-out step, so the run's
    //    own admission gate refuses for want of a fresh host-resource proof,
    //    and a synthetic fixture must never fabricate that measurement. The
    //    observed code is therefore EXACTLY `refusal.admission.proof_missing`
    //    (fix round F1, finding B3: ruling out the control's own codes is not
    //    AC1 evidence). The publish-step half is witnessed over the run's own
    //    durable rows by
    //    `a_recomputed_record_carries_the_run_to_its_publish_step`.
    let reason = "the local aggregate hit the transient scratch-repo failure filed as #226";
    let (code, message) = rpc_err(
        &fixture.socket,
        &fresh_id(13),
        "run.reevaluate",
        Some(reevaluation_params(
            &idem_key("230-deadlock"),
            &deadlocked,
            "p6",
            "operator-a",
            reason,
        )),
    );
    assert_eq!(
        code, "refusal.admission.proof_missing",
        "the control authorized the re-evaluation and the re-dispatch stopped at the run's OWN \
         fan-out admission gate, never at a control-level code: {message}"
    );

    // The durable records the control left: the attributed journal record
    // (AC4) naming the operator, the reason and the evidence whose checks are
    // recomputed.
    let state = fixture.seed();
    let records = state
        .run_reevaluations(&deadlocked, "p6")
        .expect("journal read");
    assert_eq!(records.len(), 1, "one record per authorized re-evaluation");
    assert_eq!(records[0].operator, "operator-a");
    assert_eq!(records[0].reason, reason);
    assert_eq!(records[0].evidence_id, failed.evidence_id);
    assert!(
        !records[0].at.is_empty(),
        "the record carries its own instant"
    );
    // The documented derivation the re-dispatch binds: the NEXT reviewer lane
    // round after the evaluations already recorded successful (the fresh round
    // is what makes a re-run a real recomputation — the superseded verdict
    // path is never re-read).
    assert_eq!(
        canter::run_control::reevaluation_lane_round(1),
        2,
        "the first re-evaluation of a succeeded producer binds lane round 2"
    );
    // Nothing was adjudicated: the recorded check statuses are untouched, and
    // the run's newest evidence still carries the non-passing check.
    let newest = state
        .evidence_for_instance(&deadlocked)
        .expect("evidence read")
        .into_iter()
        .next()
        .expect("the recorded evidence");
    assert_eq!(newest.evidence_id, failed.evidence_id);
    assert!(
        newest.checks.contains("local_cargo_test_aggregate"),
        "the record the control recomputes is still the recorded one: {}",
        newest.checks
    );

    shutdown(daemon);
}

/// [`seed_topology`] with the run's recorded ADMISSION: the dispatch context a
/// real first dispatch records carries the occupancy attestation AND the
/// host-resource proof the run presented, so a later dispatch re-presents
/// exactly that (issue #198) — and a LAPSED one is renewed at dispatch time
/// (issue #243). `worktrees_root` is the lane root the daemon measures.
fn seed_topology_with_admission(
    state: &State,
    run: &str,
    step: &str,
    key: &str,
    proof_at: &str,
    worktrees_root: &Path,
) {
    let integration_repo = std::env::temp_dir().join("hf-run-86-integration-repo");
    std::fs::create_dir_all(&integration_repo).expect("integration repo dir");
    let line = canonical_text(&object(vec![
        ("schema", string("hf-rpc-request/v1")),
        ("id", string(&fresh_id(41))),
        ("method", string("apply")),
        (
            "params",
            object(vec![
                ("idempotency_key", string(key)),
                ("instance_id", string(run)),
                ("step", string(step)),
                (
                    "topology",
                    object(vec![
                        ("integration_branch", string("staging")),
                        ("production_branches", Val::Arr(Vec::new())),
                        (
                            "integration_repo",
                            string(&integration_repo.display().to_string()),
                        ),
                        (
                            "worktrees_root",
                            string(&worktrees_root.display().to_string()),
                        ),
                    ]),
                ),
                (
                    "flags",
                    object(vec![(
                        "admission",
                        object(vec![
                            (
                                "caps",
                                object(vec![
                                    ("global", integer(4)),
                                    ("repository", integer(2)),
                                    ("harness", integer(2)),
                                ]),
                            ),
                            ("harness_lanes", integer(0)),
                            (
                                "host_proof",
                                object(vec![("measured_at", string(proof_at))]),
                            ),
                        ]),
                    )]),
                ),
            ]),
        ),
    ]));
    let request_id = fresh_id(42);
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
        .expect("claim the topology-carrying attempt");
    let outcome_line = canonical_text(&object(vec![
        ("schema", string("hf-outcome/v1")),
        ("plan_id", string("hf_plan_0000000000000000")),
        ("step_id", string(step)),
        ("status", string("succeeded")),
        ("idempotency_key", string(key)),
        ("observed_at", string(AT)),
        ("result", Val::Null),
        ("error", Val::Null),
    ]));
    state
        .resolve_claim(key, "apply", "spent", &outcome_line, Some("{}"))
        .expect("resolve the attempt");
}

/// One recorded check re-evaluation of (run, step), as the durable journal
/// keeps it.
fn reevaluation_records(
    state: &State,
    run: &str,
    step: &str,
) -> Vec<canter::state::RunReevaluationRow> {
    state.run_reevaluations(run, step).expect("journal read")
}

/// Seed ONE succeeded `review_evidence` attempt whose recorded RESPONSE carries
/// a recorded FAIL handoff — the LIVE row shape of issue #254: the effect's
/// facts (`feature_head`, `verdict`, `fix_round`) are in the response document
/// (`hf-rpc-response/v1`) while `outcome.result` is null. The row IS the
/// review step's own attempt (`succeeded`), exactly as the daemon wrote it for
/// the reported acceptance run, so an attempt read and a handoff read see the
/// same record.
fn seed_fix_round_response(
    state: &State,
    run: &str,
    step: &str,
    key: &str,
    fix: (&str, &str, i64, i64),
    worktree: &str,
) {
    let (head, lane, round, bound) = fix;
    let line = canonical_text(&object(vec![
        ("schema", string("hf-rpc-request/v1")),
        ("id", string(&fresh_id(51))),
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
    let request_id = fresh_id(52);
    state
        .journal_intent(
            "mutate.review_evidence",
            &format!("{REPO}:{run}:{step}"),
            key,
            &request_id,
            "apply",
            None,
            None,
            &line,
        )
        .expect("claim the fix-round attempt");
    let outcome_line = canonical_text(&object(vec![
        ("schema", string("hf-outcome/v1")),
        ("plan_id", string("hf_plan_0000000000000000")),
        ("step_id", string(step)),
        ("status", string("succeeded")),
        ("idempotency_key", string(key)),
        ("observed_at", string(AT)),
        ("result", Val::Null),
        ("error", Val::Null),
    ]));
    let response_line = canonical_text(&object(vec![
        ("ok", Val::Bool(true)),
        (
            "result",
            object(vec![
                ("feature_head", string(head)),
                ("verdict", string("fail")),
                (
                    "fix_round",
                    object(vec![
                        ("schema", string("hf-fix-round/v1")),
                        ("round", integer(round)),
                        ("bound", integer(bound)),
                        ("feature_head", string(head)),
                        ("lane", string(lane)),
                        // Issue #256: the repair leg's OWN lane checkout, written
                        // the way the engine writes it ('' when the recorded
                        // handoff names none).
                        ("worktree", string(worktree)),
                    ]),
                ),
            ]),
        ),
    ]));
    state
        .resolve_claim(key, "apply", "spent", &outcome_line, Some(&response_line))
        .expect("resolve the fix-round attempt");
}

/// Every `host.proof.renewal` line of the fixture's durable journal, parsed.
fn recorded_renewals(state: &State) -> Vec<Val> {
    let (_, journal) = state.journal_tail(0, 2000).expect("journal read");
    journal
        .iter()
        .filter(|line| line.contains("\"action\":\"host.proof.renewal\""))
        .filter_map(|line| Val::parse_json(line).ok())
        .collect()
}

/// Issue #243, witness (a): the control that recomputes a recorded check is
/// REACHABLE in the case it exists for.
///
/// The measured shape: the run's own recorded admission carries a host-resource
/// proof measured before the freshness window, the producer (`p6`) already
/// SUCCEEDED and the run's newest recorded review evidence names a non-passing
/// check — so the publish frontier refuses `refusal.evidence.failed` while the
/// producer can never be re-run. Before this slice the operator's own
/// `run reevaluate` was refused `refusal.admission.proof_stale` (the inner
/// re-dispatch is a fan-out and only a DISPATCH renewed a proof), which is the
/// deadlock: the one control that could recompute the leg could not obtain the
/// admission it needs.
///
/// The witness: the control passes its own gates, the run's OWN lapsed proof is
/// renewed at dispatch time (audited `host.proof.renewal`: the exact stale
/// instant superseded, the dispatch-time replacement and the free bytes the
/// host exposed at the lane root), and the producer is RE-DISPATCHED at the
/// next reviewer lane round under the control's own inner key. What it does NOT
/// do (the lane's disclosed gap, as in issue #230's witness): run a live
/// reviewer leg to a written verdict — a synthetic fixture owns no harness.
#[test]
fn the_re_evaluation_renews_the_lapsed_proof_and_re_dispatches_the_producer() {
    let head = "aa".repeat(20);
    let base = "bb".repeat(20);
    let fixture = DaemonFixture::new("reevaluate243");
    let state = fixture.seed();
    let items = submit_with_steps(
        &state,
        "qs_0000000000000243",
        &[(6, GRANT_6)],
        vec![
            step("p1", "checkout"),
            step("p5", "collect_outcome"),
            review_leg_step("p6", "issues/6", 1),
            step("p7", "merge"),
        ],
    );
    let run = items[0].instance_id.clone().expect("admitted");
    // The lane root the daemon measures: a REAL directory (the host exposes
    // it), exactly as a live run's worktrees root is.
    let lane_root =
        std::env::temp_dir().join(format!("hf-run-243-lane-root-{}", std::process::id()));
    std::fs::create_dir_all(&lane_root).expect("lane root");
    let stale = canter::time::rfc3339_from_unix(
        canter::time::unix_now() - canter::lifecycle::HOST_PROOF_FRESHNESS_SECS - 1,
    );
    seed_topology_with_admission(&state, &run, "p1", &idem_key("243-p1"), &stale, &lane_root);
    seed_attempt(&state, &run, "p6", &idem_key("243-p6"), Some("succeeded"));
    seed_collection(
        &state,
        &run,
        "p5",
        &idem_key("243-p5"),
        &head,
        &base,
        "issue-6",
    );
    state
        .record_evidence(
            &run,
            REPO,
            &head,
            &base,
            WORKFLOW_HASH,
            POLICY_HASH,
            "pass",
            "rev-6-r1",
            &checks(&[
                ("hosted-ci", "passed"),
                ("local_full_suite_raw_101", "failed"),
            ]),
        )
        .expect("deadlocked evidence");
    let daemon = fixture.spawn(None);
    wait_ready(&fixture);

    // The control the deadlock was made of: the run's own check producer is
    // re-evaluated by the operator's own attributed act.
    let reason = "the local aggregate hit the transient scratch-repo failure";
    let response = rpc(
        &fixture.socket,
        &fresh_id(21),
        "run.reevaluate",
        Some(reevaluation_params(
            &idem_key("243-deadlock"),
            &run,
            "p6",
            "operator-a",
            reason,
        )),
    );
    eprintln!(
        "run.reevaluate => {}",
        canter::canonical::canonical_text(&response)
    );

    // The control authorized the re-evaluation and left its attributed record
    // in the durable journal (AC1's recovery).
    let state = fixture.seed();
    let records = reevaluation_records(&state, &run, "p6");
    assert_eq!(records.len(), 1, "one record per authorized re-evaluation");
    assert_eq!(records[0].operator, "operator-a");
    assert_eq!(records[0].reason, reason);

    // The run's OWN lapsed proof was renewed at dispatch time: the audit names
    // the exact stale instant it superseded and the measurement it presented.
    let renewals = recorded_renewals(&state);
    assert_eq!(renewals.len(), 1, "exactly one renewal: {renewals:?}");
    let target = renewals[0]
        .get("target")
        .and_then(Val::as_str)
        .unwrap_or_default();
    assert!(
        target.contains(&format!("superseded:{stale}")),
        "the superseded proof is the run's own recorded one: {target}"
    );
    let key = renewals[0]
        .get("idempotency_key")
        .and_then(Val::as_str)
        .unwrap_or_default();
    let inner_key = format!("ik_{}-p6-r2", run.trim_start_matches("run-"));
    assert_eq!(
        key, inner_key,
        "the renewal rode the re-evaluation's own inner dispatch key: {target}"
    );
    let replacement = target
        .split_once(":replacement:")
        .and_then(|(_, rest)| rest.split_once(":available_bytes:"))
        .map(|(at, _)| at)
        .unwrap_or_else(|| panic!("a dispatch-time measurement: {target}"));
    assert_ne!(
        replacement, stale,
        "the recorded attestation is never echoed back as a fresh measurement"
    );
    let replacement_unix = canter::time::unix_from_rfc3339(replacement).expect("rfc3339");
    let stale_unix = canter::time::unix_from_rfc3339(&stale).expect("rfc3339");
    assert!(
        replacement_unix > stale_unix,
        "the presented proof is a measurement taken at THIS dispatch ({replacement} vs {stale})"
    );

    // ...and the producer was really re-dispatched: the control's inner claim
    // exists and carries the FRESH reviewer lane round.
    let claim = state
        .claim(&inner_key)
        .expect("claim read")
        .expect("the re-dispatched producer was claimed");
    assert!(
        claim.request_line.contains("\"lane_round\":2"),
        "the re-run binds the next reviewer lane round: {}",
        claim.request_line
    );
    assert!(
        claim.request_line.contains("\"step\":\"p6\""),
        "the re-run addresses the producer: {}",
        claim.request_line
    );
    // The deadlock's own refusal is gone: whatever the reviewer-leg EFFECT then
    // records in a synthetic fixture, the admission gate no longer refuses the
    // recorded proof.
    let code = response
        .get("error")
        .and_then(|error| error.get("code"))
        .and_then(Val::as_str)
        .unwrap_or_default();
    assert_ne!(
        code, "refusal.admission.proof_stale",
        "the control is never refused the stale proof it renews: {response:?}"
    );
    assert_ne!(code, "refusal.admission.proof_missing");

    shutdown(daemon);
    let _ = std::fs::remove_dir_all(&lane_root);
}

/// Issue #243, witness (b): when the proof is GENUINELY unsatisfiable (the host
/// does not expose the lane root the run's topology names, so no measurement
/// can be produced) the refusal names the failing precondition AND the remedy —
/// the exact commands that renew a proof — instead of a bare code.
#[test]
fn an_unsatisfiable_proof_refusal_names_the_precondition_and_the_remedy() {
    let head = "aa".repeat(20);
    let base = "bb".repeat(20);
    let fixture = DaemonFixture::new("reev243-b");
    let state = fixture.seed();
    let items = submit_with_steps(
        &state,
        "qs_0000000000000244",
        &[(6, GRANT_6)],
        vec![
            step("p1", "checkout"),
            step("p5", "collect_outcome"),
            review_leg_step("p6", "issues/6", 1),
            step("p7", "merge"),
        ],
    );
    let run = items[0].instance_id.clone().expect("admitted");
    // The lane root the topology names does not exist: the daemon cannot
    // measure it, so no renewal is possible (`run.host_proof.unmeasurable`).
    let missing_root = std::env::temp_dir().join(format!(
        "hf-run-243-absent-lane-root-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&missing_root);
    let stale = canter::time::rfc3339_from_unix(
        canter::time::unix_now() - canter::lifecycle::HOST_PROOF_FRESHNESS_SECS - 1,
    );
    seed_topology_with_admission(
        &state,
        &run,
        "p1",
        &idem_key("244-p1"),
        &stale,
        &missing_root,
    );
    seed_attempt(&state, &run, "p6", &idem_key("244-p6"), Some("succeeded"));
    seed_collection(
        &state,
        &run,
        "p5",
        &idem_key("244-p5"),
        &head,
        &base,
        "issue-6",
    );
    state
        .record_evidence(
            &run,
            REPO,
            &head,
            &base,
            WORKFLOW_HASH,
            POLICY_HASH,
            "pass",
            "rev-6-r1",
            &checks(&[("hosted-ci", "passed"), ("local_suite", "failed")]),
        )
        .expect("deadlocked evidence");
    let daemon = fixture.spawn(None);
    wait_ready(&fixture);

    let (code, message) = rpc_err(
        &fixture.socket,
        &fresh_id(22),
        "run.reevaluate",
        Some(reevaluation_params(
            &idem_key("244-deadlock"),
            &run,
            "p6",
            "operator-a",
            "the local aggregate hit a transient failure",
        )),
    );
    eprintln!("run.reevaluate (unmeasurable host) => {code}: {message}");
    assert_eq!(
        code, "refusal.admission.proof_stale",
        "the unmeasurable host still refuses the recorded proof: {message}"
    );
    assert!(
        message.contains("the host-resource proof is stale"),
        "the refusal names the failing precondition: {message}"
    );
    assert!(
        message.contains(&format!(
            "canter run reevaluate --run {run} --step p6 --operator IDENTITY --reason TEXT"
        )),
        "the refusal names the renewal path: {message}"
    );
    assert!(
        message.contains(&format!(
            "canter run dispatch --run {run} --step p6 --operator IDENTITY --reason TEXT"
        )),
        "the refusal names the audited operator measurement that produces the proof (issue #250): \
         {message}"
    );
    // Nothing was fabricated: no renewal is recorded for an unmeasurable host.
    let state = fixture.seed();
    assert!(
        recorded_renewals(&state).is_empty(),
        "an unmeasurable host renews nothing"
    );

    shutdown(daemon);
}

/// Issue #243, requirement 2: the driver drives the run's OWN bounded,
/// attributed recovery control — never the tail behind an unverified delivery,
/// and never once the control's own recorded bound is spent.
#[test]
fn the_driver_drives_the_runs_own_bounded_recovery_control_never_the_tail() {
    let fixture = StateFixture::new("reevaluate-driver-243");
    let state = fixture.open();
    let head = "aa".repeat(20);
    let base = "bb".repeat(20);
    let steps = vec![
        step("p1", "checkout"),
        step("p5", "collect_outcome"),
        review_leg_step("p6", "issues/6", 1),
        step("p7", "merge"),
    ];
    let (_, digest) = render_bound(
        &state,
        &request_with_steps(vec![selected("#6", REV_A)], steps.clone()),
    );
    let items = submit_with_steps(&state, "qs_0000000000000245", &[(6, GRANT_6)], steps);
    let run = items[0].instance_id.clone().expect("admitted");
    state
        .arm_supervision(
            &run,
            &canter::state::SupervisionAuthorizationPlan {
                desired: "armed".to_string(),
                check_interval_secs: 10,
                progress_timeout_secs: 60,
            },
            &digest,
            "merge",
            1,
            AT,
        )
        .expect("arm");
    seed_attempt(&state, &run, "p6", &idem_key("245-p6"), Some("succeeded"));
    seed_topology(&state, &run, "p1", &idem_key("245-p1"));
    seed_collection(
        &state,
        &run,
        "p5",
        &idem_key("245-p5"),
        &head,
        &base,
        "issue-6",
    );
    state
        .record_evidence(
            &run,
            REPO,
            &head,
            &base,
            WORKFLOW_HASH,
            POLICY_HASH,
            "pass",
            "rev-6-r1",
            &checks(&[
                ("hosted-ci", "passed"),
                ("local_full_suite_raw_101", "failed"),
            ]),
        )
        .expect("deadlocked evidence");
    let row = state
        .supervision_rows()
        .expect("rows")
        .into_iter()
        .find(|row| row.instance_id == run)
        .expect("the armed row");
    let policy = canter::supervision::Policy {
        check_interval_secs: row.check_interval_secs,
        progress_timeout_secs: row.progress_timeout_secs,
    };
    let now_unix = canter::time::unix_now();
    let evidence = state
        .supervision_evidence(&run)
        .expect("evidence read")
        .expect("supervised run");

    // The park is UNCHANGED: needs-attention, the engine's own code as the
    // detail, never eligible — the tail is never driven behind an unverified
    // delivery.
    let verdict = canter::supervision::classify(&evidence, &digest, &policy, now_unix);
    assert_eq!(verdict.class, "needs-attention");
    assert_eq!(
        verdict.reason,
        canter::supervision::codes::DELIVERY_UNVERIFIED
    );
    assert!(!verdict.eligible);

    // ...and the driver's ONE act is the run's own recovery control: the check
    // PRODUCER, at the recovery reason, never the frontier.
    let intent = canter::supervision::dispatch_intent(&row, &evidence)
        .expect("the engine's own typed recovery control is driven");
    assert_eq!(intent.step_id, "p6", "the producer, never the tail");
    assert_eq!(intent.kind, "review_evidence");
    assert_eq!(intent.reason, canter::supervision::codes::REEVALUATION);
    assert_ne!(intent.step_id, "p7");

    // The bound is the control's own, read from the durable journal: once it is
    // spent, no intent is minted at all (a guaranteed refusal is never
    // re-attempted forever).
    for attempt in 1..=canter::run_control::RUN_REEVALUATION_MAX {
        state
            .record_run_reevaluation(
                &run,
                "p6",
                "ev_0123456789abcdef",
                "supervision",
                "a bounded re-evaluation",
                &idem_key(&format!("245-bound-{attempt}")),
            )
            .expect("record a spent re-evaluation");
    }
    let evidence = state
        .supervision_evidence(&run)
        .expect("evidence read")
        .expect("supervised run");
    assert_eq!(
        evidence.reevaluations,
        vec![(
            "p6".to_string(),
            canter::run_control::RUN_REEVALUATION_MAX,
            "ev_0123456789abcdef".to_string()
        )],
        "the durable bound is read back per step, with the verdict the newest re-entry was taken from"
    );
    assert!(
        canter::supervision::dispatch_intent(&row, &evidence).is_none(),
        "a spent bound mints no intent"
    );
    // The classification is untouched by the spent bound: the run is still
    // reported exactly as parked, never eligible.
    let verdict = canter::supervision::classify(&evidence, &digest, &policy, now_unix);
    assert_eq!(verdict.class, "needs-attention");
    assert!(!verdict.eligible);
}

/// Issue #254 (AC1/AC3): the recorded FAIL handoff — read from where the daemon
/// ACTUALLY persists it — is reported as the fix-round disposition naming the
/// fix leg's lane, and the driver drives the run's OWN bounded check
/// re-evaluation for that recorded FAIL instead of parking on it. Once the
/// producer's re-run has recorded a passing record for the same certified head
/// (the repair landed and the re-evaluation recomputed), the run's cursor is
/// PAST the fail: its frontier is the committed publish step and the driver
/// dispatches it.
///
/// The rows are the LIVE shapes: the review step's own apply row keeps the
/// handoff in its RESPONSE document (`result.fix_round`, `outcome.result` null)
/// and the run's newest recorded review evidence is the `fail` at the head that
/// handoff names.
///
/// What this does NOT prove, and the round report states plainly: a live
/// reviewer leg to a written verdict (a synthetic fixture owns no harness) and
/// the effect's own lane re-binding (the unchanged #248 slice).
#[test]
fn a_recorded_fail_handoff_is_named_and_drives_the_run_past_the_fail() {
    let fixture = StateFixture::new("fix-round-driver-254");
    let state = fixture.open();
    let head = "aa".repeat(20);
    let base = "bb".repeat(20);
    let fix_lane = "lane-0123456789abcdef";
    let steps = vec![
        step("p1", "checkout"),
        step("p5", "collect_outcome"),
        review_leg_step("p6", "issues/6", 1),
        step("p7", "merge"),
    ];
    // The digest the run is authorized under IS the committed submission's own
    // bound-input digest, so the armed authorization is the real one.
    let (_, digest) = render_bound(
        &state,
        &request_with_steps(vec![selected("#6", REV_A)], steps.clone()),
    );
    let items = submit_with_steps(&state, "qs_0000000000000254", &[(6, GRANT_6)], steps);
    let run = items[0].instance_id.clone().expect("admitted");
    state
        .arm_supervision(
            &run,
            &canter::state::SupervisionAuthorizationPlan {
                desired: "armed".to_string(),
                check_interval_secs: 10,
                progress_timeout_secs: 60,
            },
            &digest,
            "merge",
            1,
            AT,
        )
        .expect("arm");
    seed_topology(&state, &run, "p1", &idem_key("254-p1"));
    seed_collection(
        &state,
        &run,
        "p5",
        &idem_key("254-p5"),
        &head,
        &base,
        "issue-6",
    );
    // The review step's OWN apply row, written the way the daemon writes it:
    // the FAIL handoff is in the RESPONSE column, and the same row is the
    // step's recorded attempt.
    seed_fix_round_response(
        &state,
        &run,
        "p6",
        &idem_key("254-p6"),
        (&head, fix_lane, 1, 3),
        "",
    );
    state
        .record_evidence(
            &run,
            REPO,
            &head,
            &base,
            WORKFLOW_HASH,
            POLICY_HASH,
            "fail",
            "rev-6-r1",
            &checks(&[
                ("hosted-ci", "passed"),
                ("local_full_suite_raw_101", "failed"),
            ]),
        )
        .expect("the recorded FAIL");
    let row = state
        .supervision_rows()
        .expect("rows")
        .into_iter()
        .find(|row| row.instance_id == run)
        .expect("the armed row");
    let policy = canter::supervision::Policy {
        check_interval_secs: row.check_interval_secs,
        progress_timeout_secs: row.progress_timeout_secs,
    };
    let now_unix = canter::time::unix_now();
    let evidence = state
        .supervision_evidence(&run)
        .expect("evidence read")
        .expect("supervised run");

    // (1) The classification reports the fix-round disposition naming the lane
    //     — never `supervision.review_failed` with an empty remedy. THIS is the
    //     read the reported defect got wrong: with the handoff unread, the raw
    //     output below is `needs-attention` / `supervision.review_failed`.
    let verdict = canter::supervision::classify(&evidence, &digest, &policy, now_unix);
    println!(
        "CLASSIFY class={} reason={} detail={} eligible={}",
        verdict.class, verdict.reason, verdict.detail, verdict.eligible
    );
    assert_eq!(verdict.class, "waiting-workers");
    assert_eq!(verdict.reason, canter::supervision::codes::FIX_DISPATCHED);
    assert_eq!(verdict.detail, fix_lane);
    assert_ne!(verdict.reason, canter::supervision::codes::REVIEW_FAILED);
    assert!(!verdict.eligible);

    // (2) The handoff the response document carries IS read back — the reader
    //     that only looked at `outcome.result` saw nothing at all here.
    let fix = evidence
        .fix_round
        .as_ref()
        .expect("the response-carried handoff is read back");
    assert_eq!(fix.lane, fix_lane);
    assert_eq!(fix.step, "p6");
    assert_eq!(fix.feature_head, head);
    assert_eq!((fix.round, fix.bound), (1, 3));
    println!(
        "READ BACK handoff round={} bound={} lane={} head={}",
        fix.round, fix.bound, fix.lane, fix.feature_head
    );

    // (3) The driver's ONE act is the run's own bounded recovery control: the
    //     check PRODUCER, never the tail behind the unverified delivery.
    let intent = canter::supervision::dispatch_intent(&row, &evidence)
        .expect("the recorded FAIL drives the run's own recovery control");
    println!(
        "DRIVER step={} kind={} reason={}",
        intent.step_id, intent.kind, intent.reason
    );
    assert_eq!(intent.step_id, "p6", "the producer, never the tail");
    assert_eq!(intent.kind, "review_evidence");
    assert_eq!(intent.reason, canter::supervision::codes::REEVALUATION);
    assert_ne!(intent.step_id, "p7");

    // (4) The producer's re-run records a PASSING record for the same certified
    //     head (the repair landed and the re-evaluation recomputed): the run's
    //     cursor is PAST the fail — its frontier is the committed publish step
    //     and the driver dispatches it.
    //
    //     Two records written inside the SAME wall-clock second share a
    //     `created_at`, and the read path breaks that tie on the (random)
    //     `evidence_id`, so the fixture waits for the next second before
    //     writing the recomputation: the ordering this witness asserts on is
    //     then a total order on write time. The tie itself is disclosed as a
    //     residual uncertainty in the round report (in production the
    //     recomputation is a reviewer leg, minutes later).
    let failed_at = evidence
        .newest_evidence
        .as_ref()
        .expect("the recorded FAIL is the newest record")
        .created_at
        .clone();
    let deadline = Instant::now() + Duration::from_secs(5);
    while canter::time::rfc3339_now() == failed_at {
        assert!(
            Instant::now() < deadline,
            "the fixture clock never left {failed_at}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    state
        .record_evidence(
            &run,
            REPO,
            &head,
            &base,
            WORKFLOW_HASH,
            POLICY_HASH,
            "pass",
            "rev-6-r2",
            &checks(&[
                ("hosted-ci", "passed"),
                ("local_full_suite_raw_101", "passed"),
            ]),
        )
        .expect("the recomputed record");
    let evidence = state
        .supervision_evidence(&run)
        .expect("evidence read")
        .expect("supervised run");
    assert_eq!(
        canter::supervision::next_unachieved_step(&evidence),
        Some(("p7".to_string(), "merge".to_string())),
        "the recomputed record carries the run's cursor past the FAIL"
    );
    let intent = canter::supervision::dispatch_intent(&row, &evidence)
        .expect("the run's own publish step is dispatched");
    println!(
        "CURSOR PAST THE FAIL step={} kind={} reason={}",
        intent.step_id, intent.kind, intent.reason
    );
    assert_eq!(intent.step_id, "p7");
    assert_eq!(intent.kind, "merge");
}

/// Issue #254 (AC2): a recorded handoff whose head the run's newest recorded
/// review evidence does NOT name is still a typed fix-round disposition naming
/// the remedy — and the driver STILL drives the run's own bounded
/// re-evaluation, so the shape is never a silent park either way.
#[test]
fn a_recorded_handoff_for_another_head_is_named_and_still_drives_the_run() {
    let fixture = StateFixture::new("fix-round-moved-254");
    let state = fixture.open();
    let head = "aa".repeat(20);
    let recorded_at = "cc".repeat(20);
    let base = "bb".repeat(20);
    let fix_lane = "lane-0123456789abcdef";
    let steps = vec![
        step("p1", "checkout"),
        step("p5", "collect_outcome"),
        review_leg_step("p6", "issues/6", 1),
        step("p7", "merge"),
    ];
    let (_, digest) = render_bound(
        &state,
        &request_with_steps(vec![selected("#6", REV_A)], steps.clone()),
    );
    let items = submit_with_steps(&state, "qs_0000000000000255", &[(6, GRANT_6)], steps);
    let run = items[0].instance_id.clone().expect("admitted");
    state
        .arm_supervision(
            &run,
            &canter::state::SupervisionAuthorizationPlan {
                desired: "armed".to_string(),
                check_interval_secs: 10,
                progress_timeout_secs: 60,
            },
            &digest,
            "merge",
            1,
            AT,
        )
        .expect("arm");
    seed_topology(&state, &run, "p1", &idem_key("255-p1"));
    seed_collection(
        &state,
        &run,
        "p5",
        &idem_key("255-p5"),
        &head,
        &base,
        "issue-6",
    );
    // The repair leg advanced the branch: the handoff was recorded at the head
    // the FAIL was handed at, and the run's newest recorded review evidence
    // names a DIFFERENT head.
    seed_fix_round_response(
        &state,
        &run,
        "p6",
        &idem_key("255-p6"),
        (&recorded_at, fix_lane, 1, 3),
        "",
    );
    state
        .record_evidence(
            &run,
            REPO,
            &head,
            &base,
            WORKFLOW_HASH,
            POLICY_HASH,
            "fail",
            "rev-6-r1",
            &checks(&[
                ("hosted-ci", "passed"),
                ("local_full_suite_raw_101", "failed"),
            ]),
        )
        .expect("the recorded FAIL");
    let row = state
        .supervision_rows()
        .expect("rows")
        .into_iter()
        .find(|row| row.instance_id == run)
        .expect("the armed row");
    let policy = canter::supervision::Policy {
        check_interval_secs: row.check_interval_secs,
        progress_timeout_secs: row.progress_timeout_secs,
    };
    let now_unix = canter::time::unix_now();
    let evidence = state
        .supervision_evidence(&run)
        .expect("evidence read")
        .expect("supervised run");

    let verdict = canter::supervision::classify(&evidence, &digest, &policy, now_unix);
    println!(
        "CLASSIFY (moved) class={} reason={} detail={} eligible={}",
        verdict.class, verdict.reason, verdict.detail, verdict.eligible
    );
    assert_eq!(verdict.class, "needs-attention");
    assert_eq!(verdict.reason, canter::supervision::codes::FIX_HEAD_MOVED);
    assert_ne!(verdict.reason, canter::supervision::codes::REVIEW_FAILED);
    assert!(
        verdict.detail.starts_with(fix_lane),
        "the remedy (the recorded lane) is named FIRST: {}",
        verdict.detail
    );
    assert!(
        verdict.detail.contains(&recorded_at[..12]) && verdict.detail.contains(&head[..12]),
        "both heads are named: {}",
        verdict.detail
    );
    assert!(!verdict.eligible);

    let intent = canter::supervision::dispatch_intent(&row, &evidence)
        .expect("a handoff for another head still drives the run's own control");
    println!(
        "DRIVER (moved) step={} kind={} reason={}",
        intent.step_id, intent.kind, intent.reason
    );
    assert_eq!(intent.step_id, "p6");
    assert_eq!(intent.reason, canter::supervision::codes::REEVALUATION);
}

/// B3 (fix round F1): AC1's LINK, witnessed over the run's OWN durable rows
/// rather than a hand-built `EvidenceView`. A run whose newest recorded
/// evidence carries a non-passing check is REFUSED and NAMED — never reported
/// an eligible continuation, and never dispatched — and once the cause is gone
/// (a RECOMPUTED record at the SAME certified head, written by the production
/// writer) the run's frontier IS its publish step and the driver's own
/// producer yields the dispatch intent for it.
///
/// What this does NOT prove, and the round report states plainly: the publish
/// EFFECT itself (the unchanged #240 slice, proven by
/// `tests/mutation_engine.rs::p7_computes_hosted_ci_at_the_certified_head_and_
/// never_publishes_over_red`) and a live reviewer leg (human-gated).
#[test]
fn a_recomputed_record_carries_the_run_to_its_publish_step() {
    let fixture = StateFixture::new("reevaluate-durable-230");
    let state = fixture.open();
    let head = "aa".repeat(20);
    let base = "bb".repeat(20);
    let steps = vec![
        step("p1", "checkout"),
        step("p5", "collect_outcome"),
        review_leg_step("p6", "issues/6", 1),
        step("p7", "merge"),
    ];
    // The digest the run is authorized under IS the committed submission's own
    // bound-input digest, so the armed authorization is the real one.
    let (_, digest) = render_bound(
        &state,
        &request_with_steps(vec![selected("#6", REV_A)], steps.clone()),
    );
    let items = submit_with_steps(&state, "qs_0000000000000301", &[(6, GRANT_6)], steps);
    let run = items[0].instance_id.clone().expect("admitted");
    state
        .arm_supervision(
            &run,
            &canter::state::SupervisionAuthorizationPlan {
                desired: "armed".to_string(),
                check_interval_secs: 10,
                progress_timeout_secs: 60,
            },
            &digest,
            "merge",
            1,
            AT,
        )
        .expect("arm");
    // The run reached its review frontier: the review step SUCCEEDED, the run's
    // own dispatch context is recorded, and its collection certified the
    // delivery head.
    seed_attempt(
        &state,
        &run,
        "p6",
        &idem_key("230-durable-p6"),
        Some("succeeded"),
    );
    seed_topology(&state, &run, "p1", &idem_key("230-durable-p1"));
    seed_collection(
        &state,
        &run,
        "p5",
        &idem_key("230-durable-p5"),
        &head,
        &base,
        "issue-6",
    );
    // The recorded deadlock, exactly as the live run recorded it: a `pass`
    // verdict whose own check list names the transient failure.
    let failed = state
        .record_evidence(
            &run,
            REPO,
            &head,
            &base,
            WORKFLOW_HASH,
            POLICY_HASH,
            "pass",
            "rev-6-r1",
            &checks(&[
                ("hosted-ci", "passed"),
                ("local_full_suite_raw_101", "failed"),
            ]),
        )
        .expect("deadlocked evidence");
    let row = state
        .supervision_rows()
        .expect("rows")
        .into_iter()
        .find(|row| row.instance_id == run)
        .expect("the armed row");
    let policy = canter::supervision::Policy {
        check_interval_secs: row.check_interval_secs,
        progress_timeout_secs: row.progress_timeout_secs,
    };
    let now_unix = canter::time::unix_now();

    // (1) The deadlock is NAMED from the run's own rows — never an eligible
    //     continuation, and never dispatched.
    let evidence = state
        .supervision_evidence(&run)
        .expect("evidence read")
        .expect("supervised run");
    let verdict = canter::supervision::classify(&evidence, &digest, &policy, now_unix);
    assert_eq!(verdict.class, "needs-attention");
    assert_eq!(
        verdict.reason,
        canter::supervision::codes::DELIVERY_UNVERIFIED
    );
    assert_eq!(verdict.detail, canter::mutation::code::EVIDENCE_FAILED);
    assert!(
        !verdict.eligible,
        "a run whose checks are not all passed is never eligible"
    );
    // The unverified delivery is still never driven: the driver's ONE act in
    // this shape is the run's own bounded, audited recovery control — the check
    // PRODUCER re-evaluated on a fresh lane round (issue #243) — and never the
    // tail behind it.
    let intent = canter::supervision::dispatch_intent(&row, &evidence)
        .expect("the engine's own typed recovery control is driven");
    assert_eq!(intent.step_id, "p6", "the producer, never the tail");
    assert_eq!(intent.reason, canter::supervision::codes::REEVALUATION);
    assert_ne!(
        intent.step_id, "p7",
        "an unverified delivery is never driven"
    );

    // (2) The cause is gone: the producer's RECOMPUTED record at the SAME
    //     certified head, written by the production writer. A re-evaluation
    //     ADDS a record; it never edits the frozen one.
    //
    //     Two records written inside the SAME wall-clock second share a
    //     `created_at`, and the read path breaks that tie on the (random)
    //     `evidence_id`, so the fixture waits for the next second before
    //     writing the recomputation: the ordering this witness asserts on is
    //     then a total order on write time. The tie itself is disclosed as a
    //     residual uncertainty in the round report (in production the
    //     recomputation is a reviewer leg, minutes later).
    let wrote_at = failed.created_at.clone();
    let deadline = Instant::now() + Duration::from_secs(5);
    while canter::time::rfc3339_now() == wrote_at {
        assert!(
            Instant::now() < deadline,
            "the fixture clock never left {wrote_at}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let recomputed = state
        .record_evidence(
            &run,
            REPO,
            &head,
            &base,
            WORKFLOW_HASH,
            POLICY_HASH,
            "pass",
            "rev-6-r2",
            &checks(&[
                ("hosted-ci", "passed"),
                ("local_full_suite_raw_101", "passed"),
            ]),
        )
        .expect("recomputed evidence");
    assert_ne!(
        recomputed.evidence_id, failed.evidence_id,
        "the recomputation is a NEW record, never an edit of the frozen one"
    );

    // (3) ...and the run REACHES ITS PUBLISH STEP: the frontier is the merge
    //     step and the driver's own producer yields its dispatch intent.
    let evidence = state
        .supervision_evidence(&run)
        .expect("evidence read")
        .expect("supervised run");
    let verdict = canter::supervision::classify(&evidence, &digest, &policy, now_unix);
    assert_eq!(
        verdict.class, "healthy",
        "class={} reason={} detail={} eligible={} — the recomputed record must be the \
         NEWEST recorded one",
        verdict.class, verdict.reason, verdict.detail, verdict.eligible
    );
    assert_eq!(verdict.reason, canter::supervision::codes::DISPATCH);
    assert!(verdict.eligible);
    assert_eq!(verdict.detail, "p7", "the frontier IS the publish step");
    let intent = canter::supervision::dispatch_intent(&row, &evidence)
        .expect("the publish step is dispatched by the driver");
    assert_eq!(intent.step_id, "p7");
    assert_eq!(intent.kind, "merge");
}

// ---------------------------------------------------------------------------
// Issue #250 — the audited operator's own host-resource measurement
// ---------------------------------------------------------------------------

/// Every `host.proof.renewal.operator` line of the fixture's durable journal,
/// parsed (the audit record of the proof-producing control).
fn recorded_operator_renewals(state: &State) -> Vec<Val> {
    let (_, journal) = state.journal_tail(0, 2000).expect("journal read");
    journal
        .iter()
        .filter(|line| line.contains("\"action\":\"host.proof.renewal.operator\""))
        .filter_map(|line| Val::parse_json(line).ok())
        .collect()
}

/// One recorded REFUSED attempt of (run, step) carrying `code`: the durable
/// record `run.status` reads back. A live admission refusal happens before any
/// intent is journaled, so a witness that must READ the park seeds the very
/// outcome the engine records when its own continuation refusal lands.
fn seed_refused_attempt(state: &State, instance_id: &str, step: &str, key: &str, code: &str) {
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
        .expect("claim the refused attempt");
    let outcome_line = canonical_text(&object(vec![
        ("schema", string("hf-outcome/v1")),
        ("plan_id", string("hf_plan_0000000000000000")),
        ("step_id", string(step)),
        ("status", string("refused")),
        ("idempotency_key", string(key)),
        ("observed_at", string(AT)),
        ("result", Val::Null),
        (
            "error",
            object(vec![
                ("code", string(code)),
                ("message", string("the host-resource proof is stale")),
            ]),
        ),
    ]));
    state
        .resolve_claim(key, "apply", "spent", &outcome_line, Some("{}"))
        .expect("resolve the refused attempt");
}

/// Issue #250, the whole slice: the artifact every named remedy for a parked
/// run needed is PRODUCED by an exposed control, the act is audited, and a
/// park no control can move escalates terminally instead of looking eligible.
///
/// Three runs of ONE fixture daemon, each parked at the same fan-out frontier
/// (`p6`, a review leg) with a proof measured before the freshness window:
/// (A) the ordinary dispatch refuses `refusal.admission.proof_stale` — the
/// measured defect; (B) the audited operator pair makes the daemon MEASURE the
/// host at the run's lane root and bind the measurement, recording the
/// identity, the reason and the superseded instant in the hash-chained journal
/// BEFORE presenting it, so the gate no longer decides on the lapsed proof;
/// (C) a host that cannot be measured (the lane root does not exist) produces
/// NOTHING and the same refusal stays typed — and once the retry budget is
/// spent with no re-evaluable producer, `run status` names the terminal
/// `escalation.run.owner_decision` instead of an eligible-looking park.
#[test]
fn the_audited_operator_measurement_produces_the_proof_a_parked_run_needs() {
    let head = "aa".repeat(20);
    let base = "bb".repeat(20);
    let fixture = DaemonFixture::new("operator250");
    let state = fixture.seed();
    let steps = |issue: i64| {
        vec![
            step("p1", "checkout"),
            step("p5", "collect_outcome"),
            review_leg_step("p6", &format!("issues/{issue}"), 1),
            step("p7", "merge"),
        ]
    };
    // TWO runs: the fixture's admission caps admit two per repository, and the
    // second carries every refusal leg.
    let runs: Vec<String> = [(6, GRANT_6), (7, GRANT_7)]
        .iter()
        .map(|(number, grant)| {
            let items = submit_with_steps(
                &state,
                &format!("qs_000000000000{number:04}"),
                &[(*number, grant)],
                steps(*number),
            );
            items[0].instance_id.clone().expect("admitted")
        })
        .collect();
    let (plain, unmeasurable) = (runs[0].clone(), runs[1].clone());
    // The audited leg addresses the SAME run as the plain leg: the plain
    // dispatch refuses BEFORE any intent is journaled, so nothing is burned.
    let audited = plain.clone();
    // The lane root the daemon measures: a REAL directory for (A) and (B); its
    // path is never created for (C), so the host cannot be observed there.
    let lane_root =
        std::env::temp_dir().join(format!("hf-run-250-lane-root-{}", std::process::id()));
    std::fs::create_dir_all(&lane_root).expect("lane root");
    let missing_root = std::env::temp_dir().join(format!(
        "hf-run-250-absent-lane-root-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&missing_root);
    let stale = canter::time::rfc3339_from_unix(
        canter::time::unix_now() - canter::lifecycle::HOST_PROOF_FRESHNESS_SECS - 1,
    );
    for (run, root) in [(&plain, &lane_root), (&unmeasurable, &missing_root)] {
        let stem = run.trim_start_matches("run-");
        seed_topology_with_admission(
            &state,
            run,
            "p1",
            &format!("ik_{stem}-p1-250"),
            &stale,
            root,
        );
        seed_collection(
            &state,
            run,
            "p5",
            &format!("ik_{stem}-p5-250"),
            &head,
            &base,
            "issue-6",
        );
    }
    let daemon = fixture.spawn(None);
    wait_ready(&fixture);

    // (A) The measured defect: the frontier fan-out refuses the lapsed proof,
    // and its remedy names an artifact no control emits.
    let refused = rpc(
        &fixture.socket,
        &fresh_id(31),
        "run.dispatch",
        Some(canter::run_control::dispatch_params(
            &idem_key("250-plain"),
            &plain,
            "p6",
            None,
            None,
        )),
    );
    eprintln!(
        "plain dispatch => {}",
        canter::canonical::canonical_text(&refused)
    );
    let code = refused
        .get("error")
        .and_then(|error| error.get("code"))
        .and_then(Val::as_str)
        .unwrap_or_default()
        .to_string();
    assert_eq!(
        code,
        canter::lifecycle::code::PROOF_STALE,
        "the ordinary dispatch refuses the lapsed proof: {}",
        canter::canonical::canonical_text(&refused)
    );

    // (D) The park the ledger cannot see: the fan-out admission gate refuses
    // BEFORE any intent is journaled, so the run carries no attempt row while
    // the refusal's own text points the operator at `run status`. The decision
    // is read from the run's OWN recorded admission — the same facts the gate
    // reads — and names the ONE control that reaches the step: the audited
    // operator dispatch, with its exact documented command for THIS run and
    // step. A run whose proof is fresh is not parked this way and the block
    // stays quiet (proved below, after the same run is re-measured).
    let live_status = rpc(
        &fixture.socket,
        &fresh_id(37),
        "run.status",
        Some(canter::run_control::status_params(&plain)),
    );
    eprintln!(
        "run.status (live admission park) => {}",
        canter::canonical::canonical_text(&live_status)
    );
    let live_remedy = live_status
        .get("result")
        .and_then(|result| result.get("remedy"))
        .cloned()
        .expect("the control document carries the remedy decision");
    assert_eq!(
        live_remedy.get("state").and_then(Val::as_str),
        Some("applicable"),
        "a live proof park still names its control: {live_remedy:?}"
    );
    assert_eq!(
        live_remedy.get("control").and_then(Val::as_str),
        Some("run.dispatch"),
        "{live_remedy:?}"
    );
    assert_eq!(
        live_remedy.get("command").and_then(Val::as_str),
        Some(
            format!(
                "canter run dispatch --run {plain} --step p6 --operator IDENTITY --reason TEXT"
            )
            .as_str()
        ),
        "the decision carries the documented command (issue #250): {live_remedy:?}"
    );
    // The decision names the SAME park the gate refused (the recorded
    // admission's lapsed proof), read the way the gate's own parser reads it.
    assert!(
        live_remedy
            .get("because")
            .and_then(Val::as_str)
            .unwrap_or_default()
            .contains(&format!("code {}", canter::lifecycle::code::PROOF_STALE)),
        "the decision names the refused precondition: {live_remedy:?}"
    );

    // (B) The audited operator pair: the proof is PRODUCED (measured at
    // dispatch time at the run's lane root) and the act is recorded.
    let operator = "operator-a";
    let reason = "the named remedy needed a proof no control emitted";
    let dispatch = rpc(
        &fixture.socket,
        &fresh_id(32),
        "run.dispatch",
        Some(canter::run_control::dispatch_params(
            &idem_key("250-operator"),
            &audited,
            "p6",
            None,
            Some((operator, reason)),
        )),
    );
    eprintln!(
        "audited dispatch => {}",
        canter::canonical::canonical_text(&dispatch)
    );
    let renewals = recorded_operator_renewals(&state);
    assert_eq!(
        renewals.len(),
        1,
        "exactly one operator-authorized measurement: {renewals:?}"
    );
    let target = renewals[0]
        .get("target")
        .and_then(Val::as_str)
        .unwrap_or_default();
    for needle in [
        format!("operator:{operator}"),
        format!("reason:{reason}"),
        format!("superseded:{stale}"),
    ] {
        assert!(
            target.contains(&needle),
            "the audit names {needle:?} in {target}"
        );
    }
    let key = renewals[0]
        .get("idempotency_key")
        .and_then(Val::as_str)
        .unwrap_or_default()
        .to_string();
    assert_eq!(
        key,
        idem_key("250-operator"),
        "the measurement is attributed to the dispatch that authorized it"
    );
    let dispatch_code = dispatch
        .get("error")
        .and_then(|error| error.get("code"))
        .and_then(Val::as_str)
        .unwrap_or_default();
    assert_ne!(
        dispatch_code,
        canter::lifecycle::code::PROOF_STALE,
        "the produced proof is what the gate decides on now: {}",
        canter::canonical::canonical_text(&dispatch)
    );

    // (C) A host that cannot be measured produces nothing: the same refusal
    // stays typed, and no measurement is invented.
    let refused_unmeasurable = rpc(
        &fixture.socket,
        &fresh_id(33),
        "run.dispatch",
        Some(canter::run_control::dispatch_params(
            &idem_key("250-unmeasurable"),
            &unmeasurable,
            "p6",
            None,
            Some(("operator-b", "the lane root is not there")),
        )),
    );
    eprintln!(
        "unmeasurable dispatch => {}",
        canter::canonical::canonical_text(&refused_unmeasurable)
    );
    assert_eq!(
        refused_unmeasurable
            .get("error")
            .and_then(|error| error.get("code"))
            .and_then(Val::as_str)
            .unwrap_or_default(),
        canter::lifecycle::code::PROOF_STALE,
        "an unmeasurable host keeps the typed refusal: {}",
        canter::canonical::canonical_text(&refused_unmeasurable)
    );
    assert_eq!(
        recorded_operator_renewals(&state).len(),
        1,
        "nothing was measured for the run whose lane root is absent"
    );

    // (E) Branch (3) exactly as the measured scenario reaches it: the ledger
    // records the proof park, the bounded-retry budget is spent, and the host
    // is measurable. The decision names the audited operator dispatch — and the
    // NAMED control is EXECUTABLE: the run's own lapsed window is not a step
    // diagnosis, so no bounded-retry authorization is demanded of the
    // re-dispatch, and the measurement is bound BEFORE the admission gate
    // decides (the fence refuses nothing, and the gate never decides on the
    // lapsed proof).
    seed_refused_attempt(
        &state,
        &plain,
        "p6",
        &idem_key("250-journaled-park"),
        canter::lifecycle::code::PROOF_STALE,
    );
    for consumed in ["250-spent-1", "250-spent-2", "250-spent-3"] {
        state
            .record_run_retry(&plain, "p6", AT)
            .expect("bounded retry authorization");
        state
            .claim_run_retry(&plain, "p6", &idem_key(consumed), AT)
            .expect("consume the authorization");
    }
    let parked = rpc(
        &fixture.socket,
        &fresh_id(38),
        "run.status",
        Some(canter::run_control::status_params(&plain)),
    );
    eprintln!(
        "run.status (journaled proof park, budget spent) => {}",
        canter::canonical::canonical_text(&parked)
    );
    let remedy = parked
        .get("result")
        .and_then(|result| result.get("remedy"))
        .cloned()
        .expect("the control document carries the remedy decision");
    assert_eq!(
        remedy.get("state").and_then(Val::as_str),
        Some("applicable"),
        "{remedy:?}"
    );
    assert_eq!(
        remedy.get("control").and_then(Val::as_str),
        Some("run.dispatch"),
        "the audited operator dispatch is the ONE control for a proof park: {remedy:?}"
    );
    assert_eq!(
        remedy.get("command").and_then(Val::as_str),
        Some(
            format!(
                "canter run dispatch --run {plain} --step p6 --operator IDENTITY --reason TEXT"
            )
            .as_str()
        ),
        "{remedy:?}"
    );
    // The NAMED control, executed through the real daemon: nothing fences it
    // and the measurement it binds is what the gate decides on.
    let executed = rpc(
        &fixture.socket,
        &fresh_id(39),
        "run.dispatch",
        Some(canter::run_control::dispatch_params(
            &idem_key("250-named-control"),
            &plain,
            "p6",
            None,
            Some((operator, reason)),
        )),
    );
    eprintln!(
        "the NAMED control, executed => {}",
        canter::canonical::canonical_text(&executed)
    );
    let executed_code = executed
        .get("error")
        .and_then(|error| error.get("code"))
        .and_then(Val::as_str)
        .unwrap_or_default();
    assert_ne!(
        executed_code,
        "refusal.run.retry_required",
        "the named control is not fenced by the bounded retry: {}",
        canter::canonical::canonical_text(&executed)
    );
    assert_ne!(
        executed_code,
        canter::lifecycle::code::PROOF_STALE,
        "the named control reaches the gate with a fresh measurement: {}",
        canter::canonical::canonical_text(&executed)
    );
    assert_eq!(
        executed_code,
        "refusal.session.unbound",
        "the named control reached the NEXT, unrelated refusal past both fences: {}",
        canter::canonical::canonical_text(&executed)
    );

    // The decision: while the bounded-retry budget is unspent, `run status`
    // names the retry — ONE control, with its command; once it is spent and
    // nothing else applies, the same read escalates terminally.
    seed_refused_attempt(
        &state,
        &unmeasurable,
        "p6",
        &idem_key("250-refused"),
        canter::mutation::code::WORKER_TIMEOUT,
    );
    state
        .record_run_retry(&unmeasurable, "p6", AT)
        .expect("first bounded retry");
    // A HELD authorization is itself the applicable control: minting another
    // refuses, and the ONE re-dispatch consumes it.
    let status = rpc(
        &fixture.socket,
        &fresh_id(34),
        "run.status",
        Some(canter::run_control::status_params(&unmeasurable)),
    );
    eprintln!(
        "run.status (authorization held) => {}",
        canter::canonical::canonical_text(&status)
    );
    let remedy = status
        .get("result")
        .and_then(|result| result.get("remedy"))
        .cloned()
        .expect("the control document carries the remedy decision");
    assert_eq!(
        remedy.get("control").and_then(Val::as_str),
        Some("run.dispatch"),
        "the held authorization is consumed by the dispatch: {remedy:?}"
    );
    assert!(
        remedy
            .get("because")
            .and_then(Val::as_str)
            .unwrap_or_default()
            .contains("HOLDS an unconsumed bounded-retry authorization"),
        "the decision names WHY the others do not apply: {remedy:?}"
    );
    // Consume it: with budget left and nothing held, the retry is the ONE
    // control, carrying the documented command.
    state
        .claim_run_retry(&unmeasurable, "p6", &idem_key("250-consumed-1"), AT)
        .expect("consume the authorization");
    let status = rpc(
        &fixture.socket,
        &fresh_id(35),
        "run.status",
        Some(canter::run_control::status_params(&unmeasurable)),
    );
    let remedy = status
        .get("result")
        .and_then(|result| result.get("remedy"))
        .cloned()
        .expect("the control document carries the remedy decision");
    assert_eq!(
        remedy.get("state").and_then(Val::as_str),
        Some("applicable"),
        "{remedy:?}"
    );
    assert_eq!(
        remedy.get("control").and_then(Val::as_str),
        Some("run.retry"),
        "{remedy:?}"
    );
    assert_eq!(
        remedy.get("command").and_then(Val::as_str),
        Some(format!("canter run retry --run {unmeasurable} --step p6").as_str()),
        "the decision carries the command `canter run retry` itself accepts (issue #250): \
         {remedy:?}"
    );
    // Spend the rest of the bound: each authorization is CONSUMED by the ONE
    // re-dispatch it authorizes before the next can be minted.
    state
        .record_run_retry(&unmeasurable, "p6", AT)
        .expect("second bounded retry");
    state
        .claim_run_retry(&unmeasurable, "p6", &idem_key("250-consumed-2"), AT)
        .expect("consume the second authorization");
    state
        .record_run_retry(&unmeasurable, "p6", AT)
        .expect("third bounded retry");
    state
        .claim_run_retry(&unmeasurable, "p6", &idem_key("250-consumed-3"), AT)
        .expect("consume the last authorization");
    let escalated = rpc(
        &fixture.socket,
        &fresh_id(36),
        "run.status",
        Some(canter::run_control::status_params(&unmeasurable)),
    );
    eprintln!(
        "run.status (budget spent) => {}",
        canter::canonical::canonical_text(&escalated)
    );
    let remedy = escalated
        .get("result")
        .and_then(|result| result.get("remedy"))
        .cloned()
        .expect("the control document carries the remedy decision");
    assert_eq!(
        remedy.get("state").and_then(Val::as_str),
        Some("terminal-escalation"),
        "no control applies: {remedy:?}"
    );
    assert_eq!(
        remedy.get("code").and_then(Val::as_str),
        Some(canter::run_control::codes::ESCALATION),
        "the escalation is TYPED: {remedy:?}"
    );
    assert!(remedy.get("control").is_some_and(Val::is_null));
    shutdown(daemon);
}

// ---------------------------------------------------------------------------
// Issue #256: the fix-round handoff is read against the repair leg's OWN state
// ---------------------------------------------------------------------------

/// One `git` invocation in `cwd` (synthetic fixture checkouts only).
fn git(cwd: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .args(args)
        .current_dir(cwd)
        // #226: copy nothing from the host's shared git templates.
        .env("GIT_TEMPLATE_DIR", "")
        .output()
        .expect("git runs");
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).to_string()
}

/// Issue #256 fixture: a supervised run parked on a recorded review FAIL whose
/// handoff names the run's own repair leg, plus that leg's OWN lane checkout —
/// a REAL git checkout under the run's recorded `worktrees_root`, holding the
/// certified head and (with `advance`) the repair commit the leg delivered one
/// commit later.
///
/// The handoff shape is the LIVE one: the review step's own apply row keeps
/// `result.fix_round` in its RESPONSE document (`outcome.result` null), and the
/// handoff names both the leg's lane session and the lane checkout its own
/// state lives in.
struct FixLegFixture {
    fixture: DaemonFixture,
    run: String,
    lane_root: PathBuf,
    /// The head the FAIL was handed at (the head the handoff names).
    certified: String,
    /// The head the leg's own checkout holds after its repair commit.
    delivered: String,
    /// The fix leg's lane session the handoff records.
    lane: String,
    /// The control's inner re-dispatch key (`ik_<run>-<step>-r<round>`).
    inner_key: String,
}

fn fix_leg_fixture(name: &str, submission: &str, advance: bool) -> FixLegFixture {
    let fixture = DaemonFixture::new(name);
    let state = fixture.seed();
    let steps = vec![
        step("p1", "checkout"),
        step("p5", "collect_outcome"),
        review_leg_step("p6", "issues/6", 1),
        step("p7", "merge"),
    ];
    let (_, digest) = render_bound(
        &state,
        &request_with_steps(vec![selected("#6", REV_A)], steps.clone()),
    );
    let items = submit_with_steps(&state, submission, &[(6, GRANT_6)], steps);
    let run = items[0].instance_id.clone().expect("admitted");
    state
        .arm_supervision(
            &run,
            &canter::state::SupervisionAuthorizationPlan {
                desired: "armed".to_string(),
                check_interval_secs: 10,
                progress_timeout_secs: 900,
            },
            &digest,
            "merge",
            1,
            AT,
        )
        .expect("arm");
    // The lane root the run's own topology declares: a REAL directory, exactly
    // as a live run's worktrees root is.
    let lane_root = std::env::temp_dir().join(format!(
        "hf-run-256-{name}-lane-root-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&lane_root);
    let lane_relative = canter::lane::lane_checkout(6, "implementer", 2);
    let lane = lane_root.join(&lane_relative);
    std::fs::create_dir_all(&lane).expect("lane dir");
    git(&lane, &["init", "-q", "-b", "issue-6"]);
    git(&lane, &["config", "user.email", "fixture@example.test"]);
    git(&lane, &["config", "user.name", "fixture"]);
    std::fs::write(lane.join("delivery.txt"), "the reviewed delivery\n").expect("delivery");
    git(&lane, &["add", "-A"]);
    git(&lane, &["commit", "-qm", "the reviewed delivery"]);
    let certified = git(&lane, &["rev-parse", "HEAD"]).trim().to_string();
    // The repair the leg commits in its OWN checkout: a DESCENDANT of the
    // certified head, never the head the FAIL was handed at.
    std::fs::write(lane.join("repair.txt"), "the repair round 1\n").expect("repair");
    git(&lane, &["add", "-A"]);
    git(
        &lane,
        &["commit", "-qm", "queue intake: the repair (Refs #245)"],
    );
    let delivered = git(&lane, &["rev-parse", "HEAD"]).trim().to_string();
    if !advance {
        // The leg has delivered NOTHING: its own checkout is left exactly at
        // the certified head, so the run is genuinely waiting on it.
        git(&lane, &["reset", "-q", "--hard", &certified]);
    }
    // The run's own recorded COLLECTION base: the commit this checkout held
    // when the run's collection certified it — a REAL commit, so the #272
    // re-collect (which measures its delta over exactly this base) can land.
    // The pre-#272 path read no base at all and this fixture carried a
    // synthetic sha; a base no checkout holds parks the run on the collection's
    // own typed refusal instead of proving the re-bind.
    let base = certified.clone();
    let fix_lane = "lane-0123456789abcdef";
    seed_topology_with_admission(
        &state,
        &run,
        "p1",
        &idem_key(&format!("256-p1-{name}")),
        &canter::time::rfc3339_now(),
        &lane_root,
    );
    seed_collection(
        &state,
        &run,
        "p5",
        &idem_key(&format!("256-p5-{name}")),
        &certified,
        &base,
        "issue-6",
    );
    // The review step's OWN apply row, written the way the daemon writes it.
    seed_fix_round_response(
        &state,
        &run,
        "p6",
        &idem_key(&format!("256-p6-{name}")),
        (&certified, fix_lane, 1, 3),
        &lane_relative,
    );
    state
        .record_evidence(
            &run,
            REPO,
            &certified,
            &base,
            WORKFLOW_HASH,
            POLICY_HASH,
            "fail",
            "rev-6-r1",
            &checks(&[
                ("hosted-ci", "passed"),
                ("local_full_suite_raw_101", "failed"),
            ]),
        )
        .expect("the recorded FAIL");
    let inner_key = format!(
        "ik_{}-p6-r{}",
        run.trim_start_matches("run-"),
        canter::run_control::reevaluation_lane_round(1)
    );
    FixLegFixture {
        fixture,
        run,
        lane_root,
        certified,
        delivered,
        lane: fix_lane.to_string(),
        inner_key,
    }
}

/// Read the live observation the daemon's own `supervision.status` reports for
/// one run (`evaluation.observed`: the read-time classification and its detail).
fn status_observation(fixture: &DaemonFixture, run: &str, seed: u32) -> Val {
    let status = rpc_ok(
        &fixture.socket,
        &fresh_id(seed),
        "supervision.status",
        Some(object(vec![("instance_id", string(run))])),
    );
    status
        .get("evaluation")
        .and_then(|evaluation| evaluation.get("observed"))
        .cloned()
        .expect("the status document carries the read-time observation")
}

/// Issue #256 (AC1, AC2, AC4): the fix-round disposition is derived from the
/// repair leg's OWN recorded state — its own lane checkout — and the next
/// review round is bound to the head that leg DELIVERED.
///
/// Witnessed over the LIVE daemon: the same recorded handoff (naming the head
/// the FAIL was handed at) is read (0) the pre-#256 way — the stale wait the
/// defect is made of, with no leg observation — and then (1) through the
/// daemon's own observation of the leg's checkout, where the delivered
/// descendant head is named. (2) The control's inner re-dispatch of the review
/// producer — the SAME `run_dispatch` the driver's own bounded re-evaluation
/// calls (the driver's thread-level drive is the unchanged #243/#254 slice) —
/// records the DELIVERED head as the head the next round binds.
///
/// What this does NOT prove, and the round report states plainly: a live
/// reviewer leg consuming a verdict at the delivered head (a synthetic fixture
/// owns no harness) — the effect-side materialization of the bound head is the
/// reviewer-lane creation the #210/#238 slices already prove.
#[test]
fn a_delivered_repair_leg_is_named_and_the_next_round_binds_the_delivered_head() {
    let f = fix_leg_fixture("fr256d", "qs_0000000000000256", true);
    assert_ne!(f.delivered, f.certified, "the fixture really advanced");

    // (0) The pre-#256 read over the SAME recorded facts: the handoff names the
    //     head the FAIL was handed at, so the run is reported as waiting on a
    //     repair leg that has already delivered — never as moved.
    let state = f.fixture.seed();
    let evidence = state
        .supervision_evidence(&f.run)
        .expect("evidence read")
        .expect("supervised run");
    let row = state
        .supervision_rows()
        .expect("rows")
        .into_iter()
        .find(|row| row.instance_id == f.run)
        .expect("the armed row");
    let policy = canter::supervision::Policy {
        check_interval_secs: row.check_interval_secs,
        progress_timeout_secs: row.progress_timeout_secs,
    };
    let digest = evidence
        .submission_digest
        .clone()
        .expect("the run is authorized");
    let stale =
        canter::supervision::classify(&evidence, &digest, &policy, canter::time::unix_now());
    println!(
        "PRE-#256 READ class={} reason={} detail={} eligible={}",
        stale.class, stale.reason, stale.detail, stale.eligible
    );
    assert_eq!(stale.class, "waiting-workers");
    assert_eq!(stale.reason, canter::supervision::codes::FIX_DISPATCHED);
    assert_eq!(
        stale.detail, f.lane,
        "the unobserved read can only name the lane it recorded"
    );

    // (1) The daemon reads the recorded handoff's lane checkout: the leg's own
    //     state holds a DESCENDANT head, so the disposition names the movement
    //     — the remedy first, then both head prefixes.
    let daemon = f.fixture.spawn(None);
    wait_ready(&f.fixture);
    let observed = status_observation(&f.fixture, &f.run, 61);
    println!(
        "supervision.status.observed => {}",
        canonical_text(&observed)
    );
    assert_eq!(
        observed.get("class").and_then(Val::as_str),
        Some("needs-attention")
    );
    assert_eq!(
        observed.get("reason").and_then(Val::as_str),
        Some("supervision.fix_round_head_moved")
    );
    assert_ne!(
        observed.get("reason").and_then(Val::as_str),
        Some("supervision.fix_round_dispatched"),
        "a leg that delivered is never reported as work in flight"
    );
    let detail = observed
        .get("detail")
        .and_then(Val::as_str)
        .unwrap_or_default();
    assert!(
        detail.starts_with(&f.lane),
        "the remedy (the recorded lane) is named first: {detail}"
    );
    assert!(
        detail.contains(&f.certified[..12]) && detail.contains(&f.delivered[..12]),
        "both heads are named: {detail}"
    );
    assert_eq!(observed.get("eligible").and_then(Val::as_bool), Some(false));

    // (2) The delivered head is RE-BOUND by the run's OWN machinery before any
    //     review consumes it (issue #272), and the next review round binds the
    //     DELIVERED head — driven with ZERO operator control.
    //
    //     (2a) The armed driver first re-collects the repair leg's delivered
    //     head into the run's own certificate: the run's own collection is the
    //     only thing that may observe a head its own consumer then reads
    //     (#202 AC2), so the re-bind is a collection over the leg's checkout —
    //     never a consumption of a head no collection saw.
    let deadline = Instant::now() + Duration::from_secs(60);
    let certificate = loop {
        let state = f.fixture.seed();
        let certificate = state
            .run_delivery_certificate(&f.run)
            .expect("certificate read");
        if let Some(certificate) = certificate
            && certificate.head == f.delivered
        {
            break certificate;
        }
        assert!(
            Instant::now() < deadline,
            "the armed driver never re-collected the delivered head into the run's own certificate"
        );
        std::thread::sleep(Duration::from_millis(100));
    };
    println!(
        "CERTIFIED => step={} head={}",
        certificate.step_id, certificate.head
    );
    //     (2b) ... and THEN the driver re-evaluates the recorded FAIL's check
    //     producer (the unchanged #243/#254 control), whose `run_dispatch`
    //     records the delivered head as the observed head the reviewer leg's
    //     derived checkout materializes. Nothing is asked of an operator here:
    //     the claim is polled for.
    let claim = loop {
        let state = f.fixture.seed();
        if let Some(claim) = state.claim(&f.inner_key).expect("claim read") {
            break claim;
        }
        assert!(
            Instant::now() < deadline,
            "the armed driver never re-dispatched the run's own review producer"
        );
        std::thread::sleep(Duration::from_millis(100));
    };
    println!("INNER DISPATCH request => {}", claim.request_line);
    assert!(
        claim
            .request_line
            .contains(&format!("\"feature_head\":\"{}\"", f.delivered)),
        "the round binds the DELIVERED head: {}",
        claim.request_line
    );
    assert!(
        !claim
            .request_line
            .contains(&format!("\"feature_head\":\"{}\"", f.certified)),
        "the round never rebinds the head the FAIL was handed at: {}",
        claim.request_line
    );
    // ...and the same recorded evidence still drives that ONE recovery act:
    // the producer, never the tail behind the FAIL. (Asserted on the
    // PRE-dispatch shape by the #254 witness; here the driver has already
    // taken the act, so the control's own gate has moved on.)

    shutdown(daemon);
    let _ = std::fs::remove_dir_all(&f.lane_root);
}

/// Issue #256 (AC3, AC4): the in-flight disposition keeps its current meaning.
/// A handoff whose repair leg's OWN checkout has NOT advanced is still
/// `waiting-workers` / `supervision.fix_round_dispatched` naming the leg's lane
/// — the observation only ever reports a movement that is really there.
#[test]
fn a_repair_leg_that_did_not_advance_keeps_the_waiting_workers_disposition() {
    let f = fix_leg_fixture("fr256w", "qs_0000000000000257", false);
    let daemon = f.fixture.spawn(None);
    wait_ready(&f.fixture);
    let observed = status_observation(&f.fixture, &f.run, 63);
    println!(
        "supervision.status.observed => {}",
        canonical_text(&observed)
    );
    assert_eq!(
        observed.get("class").and_then(Val::as_str),
        Some("waiting-workers")
    );
    assert_eq!(
        observed.get("reason").and_then(Val::as_str),
        Some("supervision.fix_round_dispatched")
    );
    assert_eq!(
        observed.get("detail").and_then(Val::as_str),
        Some(f.lane.as_str()),
        "the wait still names the leg's recorded lane"
    );
    assert_eq!(observed.get("eligible").and_then(Val::as_bool), Some(false));
    shutdown(daemon);
    let _ = std::fs::remove_dir_all(&f.lane_root);
}
