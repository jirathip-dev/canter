//! Issue #141 acceptance: supervision's classification of a continuation
//! dispatch the apply engine REFUSED.
//!
//! The daemon-level witnesses of the measured defect live in their own suite
//! on purpose: the hosted runner bounds EVERY `tests/*.rs` file as its own
//! suite (150 s serial, `--test-threads=1 --nocapture`), and `tests/supervision.rs`
//! already consumes 148.6 s of that bound on a 10-core host — a suite with its
//! own budget is the only place real daemon scenarios of this length can run
//! without cutting a pre-existing test's wait. Nothing is skipped: the hosted
//! matrix (which `scripts/test-ci-test-driver.py` requires to enumerate every
//! `tests/*.rs`) runs this file with the same bound as every other suite.
//!
//! Self-contained fixture: each suite carries its own daemon fixture in this
//! repo (`tests/run_control.rs`, `tests/queue_submit.rs`,
//! `tests/restart_pause_continuity.rs`, `tests/queue_advance.rs`).
//!
//! No fixed real sleeps: every wait is a bounded poll with a deadline.
#[path = "support/process_group.rs"]
mod process_group;

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
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
use process_group::{GroupChild, assert_no_process_for_socket};

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
    fn spawn_with_path(&self, path: &str) -> GroupChild {
        std::fs::create_dir_all(&self.state_dir).expect("state home");
        let mut command = Command::new(env!("CARGO_BIN_EXE_canter"));
        command
            .args(["daemon", "run", "--socket"])
            .arg(&self.socket)
            .env("XDG_STATE_HOME", &self.state_dir)
            .env("HOME", &self.dir)
            .env("PATH", path)
            .stdout(Stdio::null())
            .stderr(Stdio::from(
                std::fs::File::create(self.dir.join("daemon.stderr.log")).expect("stderr log"),
            ));
        GroupChild::spawn(&mut command, &self.socket).expect("spawn daemon")
    }

    fn spawn(&self) -> GroupChild {
        std::fs::create_dir_all(&self.state_dir).expect("state home");
        let mut command = Command::new(env!("CARGO_BIN_EXE_canter"));
        command
            .args(["daemon", "run", "--socket"])
            .arg(&self.socket)
            .env("XDG_STATE_HOME", &self.state_dir)
            .env("HOME", &self.dir)
            .stdout(Stdio::null())
            .stderr(Stdio::from(
                std::fs::File::create(self.dir.join("daemon.stderr.log")).expect("stderr log"),
            ));
        GroupChild::spawn(&mut command, &self.socket).expect("spawn daemon")
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

fn shutdown(mut daemon: GroupChild) {
    daemon.terminate("supervision dispatch-refusal fixture daemon");
}

/// This suite's own containment witness: the fixture's daemon child is reaped
/// WITH its process group, so the appended suite can never leak a runner.
#[test]
fn supervision_dispatch_refusal_fixture_reaps_its_daemon_group() {
    let fixture = DaemonFixture::new("refusal-leak");
    fixture.seed();
    let socket = fixture.socket.clone();
    let daemon = fixture.spawn();
    wait_ready(&fixture);
    shutdown(daemon);
    assert_no_process_for_socket(&socket);
}

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

fn class_of(doc: &Val) -> String {
    evaluation(doc)
        .get("class")
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

/// One committed spine for retry behavior: `p1` is the checkout that records
/// the run's dispatch context, and `p2` is a contract-complete
/// `worktree_create`. The fixture pre-creates its branch so the autonomous
/// effect fails and leaves a real diagnosed attempt; malformed parameters are
/// covered separately and never become attempts.
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
            params: Some(object(vec![
                ("worktree", string("lane-p2")),
                ("branch", string("issue-92-original")),
            ])),
        },
    ];
    request
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

/// [`caller_apply_params`] with an explicitly OLD host-resource proof.
///
/// The admission block a run's recorded dispatch context keeps is what every
/// later fan-out dispatch re-presents — the daemon deliberately never
/// fabricates a fresh measurement — so a stale recorded proof is exactly the
/// measured environment of issue #141: the run's proof was recorded at
/// 11:41:42Z, and from 11:51:12Z on its `p3 harness_start` dispatch was
/// refused `refusal.admission.proof_stale` once per check for sixteen
/// minutes, while the status kept reporting the step eligible.
#[allow(clippy::too_many_arguments)]
fn caller_apply_params_with_proof(
    fixture: &DaemonFixture,
    integration: &Path,
    bound: &Val,
    run: &str,
    grant_id: &str,
    target: (&str, i64),
    key: &str,
    measured_at: &str,
) -> Val {
    let params = caller_apply_params(fixture, integration, bound, run, grant_id, target, key);
    let Val::Obj(mut outer) = params else {
        panic!("the caller's apply params are an object");
    };
    let flags = outer.get_mut("flags").expect("flags");
    let Val::Obj(flags) = flags else {
        panic!("flags is an object");
    };
    let admission = flags.get_mut("admission").expect("admission");
    let Val::Obj(admission) = admission else {
        panic!("admission is an object");
    };
    admission.insert(
        "host_proof".to_string(),
        object(vec![("measured_at", string(measured_at))]),
    );
    Val::Obj(outer)
}

/// The measured spine: the caller's `checkout` (which records the run's
/// dispatch context), the obstructed lane step the operator repairs, and the
/// frontier the repaired run must dispatch — a fan-out step whose
/// contract-complete params come from the run's own reviewed role binding,
/// exactly as in the acceptance run.
fn request_repaired_frontier(
    issues: Vec<qp::SelectedIssue>,
    third: qp::PlannedStep,
) -> qp::QueueRequest {
    let mut request = request_lane_steps(issues);
    request.steps.push(third);
    request
}

/// Poll one `supervision.status` read until `predicate` holds (bounded).
fn wait_for_status(
    fixture: &DaemonFixture,
    run: &str,
    label: &str,
    predicate: impl Fn(&Val) -> bool,
) -> Val {
    let deadline = Instant::now() + Duration::from_secs(45);
    let mut seed = 0x1410u64;
    let mut last = status_doc(&fixture.socket, &fresh_id(seed), run);
    while Instant::now() < deadline {
        seed += 1;
        last = status_doc(&fixture.socket, &fresh_id(seed), run);
        if predicate(&last) {
            return last;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!(
        "{label} never held: {}",
        canter::canonical::canonical_text(&last)
    );
}

/// The recorded `supervision.dispatch_refused` journal records of one run
/// (`(target, at)`), read through the operator's own journal surface.
fn dispatch_refusals(fixture: &DaemonFixture, run: &str) -> Vec<(String, String)> {
    let journal = rpc_ok(
        &fixture.socket,
        &fresh_id(0x1411),
        "journal.tail",
        Some(object(vec![
            ("after_seq", integer(0)),
            ("limit", integer(500)),
        ])),
    );
    journal
        .get("records")
        .and_then(Val::as_array)
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter(|row| {
            row.get("action").and_then(Val::as_str) == Some("supervision.dispatch_refused")
        })
        .map(|row| {
            (
                row.get("target")
                    .and_then(Val::as_str)
                    .unwrap_or_default()
                    .to_string(),
                row.get("at")
                    .and_then(Val::as_str)
                    .unwrap_or_default()
                    .to_string(),
            )
        })
        .filter(|(target, _)| target.starts_with(&format!("{run}:")))
        .collect()
}

/// The measured scenario driven to the operator repair: an armed run whose
/// `p1` the caller dispatched with a STALE host-resource proof (so the run's
/// recorded dispatch context no longer admits a fan-out step, exactly as in
/// the acceptance run), whose `p2` the driver dispatched once by itself and
/// the duplicate-lane guard diagnosed, and whose `p2` the operator then
/// repaired through the supported surfaces (`run retry` + `run dispatch`).
/// On return the frontier is the scenario's third step.
fn repaired_lane_scenario(
    name: &str,
    third: qp::PlannedStep,
) -> (DaemonFixture, GroupChild, String) {
    let fixture = DaemonFixture::new(name);
    let (bound, digest) = {
        let state = fixture.seed();
        seed_grant(&state, "gr_0000000000000095", 5);
        render_bound(
            &state,
            &request_repaired_frontier(vec![selected("#5", REV_A)], third),
        )
    };
    let integration = fixture.dir.join("integration");
    init_repo(&integration);
    // The diagnosed obstruction of the measured run: the lane's worktree and
    // branch already exist, so the duplicate-lane guard fires correctly.
    std::fs::create_dir_all(fixture.dir.join("worktrees/lane-p2")).expect("existing worktree");
    let status = Command::new("git")
        .args(["branch", "issue-141-original", "staging"])
        .current_dir(&integration)
        .status()
        .expect("git creates the conflicting branch");
    assert!(status.success(), "the diagnosed fixture branch exists");
    let fakebin = write_fake_gh(&fixture.dir);
    let host_path = std::env::var("PATH").unwrap_or_default();
    let daemon = fixture.spawn_with_path(&format!("{}:{host_path}", fakebin.display()));
    wait_ready(&fixture);

    let params = params_doc(
        &idem_key(name),
        &bound,
        &digest,
        &role_revision(),
        "gr_0000000000000095",
        Some(armed(5, 60)),
    );
    let result = rpc_ok(&fixture.socket, &fresh_id(1), "queue.submit", Some(params));
    let run = instance_of(&result, 5);

    // The caller dispatches p1 with a proof measured BEFORE the freshness
    // window: the run's recorded dispatch context is stale from the start,
    // exactly as it was in the measured run.
    let stale = canter::time::rfc3339_from_unix(
        canter::time::unix_now() - canter::lifecycle::HOST_PROOF_FRESHNESS_SECS - 1,
    );
    let applied = rpc_ok(
        &fixture.socket,
        &fresh_id(2),
        "apply",
        Some(caller_apply_params_with_proof(
            &fixture,
            &integration,
            &bound,
            &run,
            "gr_0000000000000095",
            ("p1", 5),
            &idem_key("repaired-p1"),
            &stale,
        )),
    );
    assert!(
        applied.get("integration_base").is_some(),
        "the checkout step recorded its read-back: {}",
        canter::canonical::canonical_text(&applied)
    );

    // The driver continues by itself and the duplicate lane diagnoses p2.
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
    assert_eq!(p2.1, "failed", "the diagnosis is recorded: {attempts:?}");

    // The operator repair, through the supported surfaces only.
    std::fs::remove_dir(fixture.dir.join("worktrees/lane-p2"))
        .expect("remove the fixture obstruction");
    let (exit, stdout, stderr) = run_cli(&fixture, &["retry", "--run", &run, "--step", "p2"]);
    assert_eq!(exit, 0, "retry exit; stdout: {stdout}; stderr: {stderr}");
    let (exit, stdout, stderr) = run_cli(
        &fixture,
        &[
            "dispatch",
            "--run",
            &run,
            "--step",
            "p2",
            "--param",
            "branch=issue-141-repaired",
        ],
    );
    assert_eq!(exit, 0, "dispatch exit; stdout: {stdout}; stderr: {stderr}");
    (fixture, daemon, run)
}

/// The measured defect, end to end: an armed run dispatches its first steps
/// itself, its lane step is DIAGNOSED (the duplicate-lane guard), the operator
/// repairs it through the supported surfaces, the frontier advances to the
/// fan-out step — and the run's recorded admission no longer admits that step.
///
/// The defect was that supervision kept reporting the frontier
/// `eligible: true` with `supervision.dispatch.next_step` while its own
/// dispatch was refused before any attempt existed: nothing named the refusal
/// on any product surface. The repaired frontier must therefore either run (it
/// cannot: the engine's admission gate refuses, unchanged) or be classified
/// concretely — class `needs-attention`, reason `supervision.dispatch_refused`
/// and the engine's own code as the named blocker, never eligible — and the
/// refusal must be auditable in the run's own journal.
#[test]
fn a_repaired_frontier_refused_by_the_engine_is_named_and_never_reported_eligible() {
    let (fixture, daemon, run) = repaired_lane_scenario(
        "repaired-refused",
        qp::PlannedStep {
            id: "p3".to_string(),
            kind: "harness_start".to_string(),
            params: Some(object(vec![("harness_key", string(HARNESS))])),
        },
    );

    // The frontier is now p3. The supervisor dispatches it on its own — and
    // THAT dispatch is the one the engine refuses, so the run's own status
    // must name the refusal instead of claiming the step is an eligible
    // continuation.
    let doc = wait_for_status(&fixture, &run, "the refusal is classified", |doc| {
        class_of(doc) == "needs-attention"
    });
    assert_eq!(
        picked(&doc, &["evaluation", "reason"]),
        "supervision.dispatch_refused"
    );
    assert_eq!(
        picked(&doc, &["evaluation", "detail"]),
        "refusal.admission.proof_stale",
        "the engine's own refusal code is the named blocker"
    );
    assert_eq!(picked(&doc, &["evaluation", "class"]), "needs-attention");
    assert_eq!(
        path_of(&doc, &["evaluation", "eligible"]).as_bool(),
        Some(false),
        "a step whose dispatch is refused is NEVER reported eligible: {}",
        canter::canonical::canonical_text(&doc)
    );
    assert_eq!(
        path_of(&doc, &["evaluation", "observed", "reason"])
            .as_str()
            .unwrap_or_default(),
        "supervision.dispatch_refused"
    );
    assert_eq!(
        path_of(&doc, &["evaluation", "observed", "eligible"]).as_bool(),
        Some(false)
    );
    // The measured lie is gone: the run is never reported as an eligible
    // continuation while the dispatch it names is refused.
    assert_ne!(
        picked(&doc, &["evaluation", "reason"]),
        "supervision.dispatch.next_step"
    );
    // The frontier stays parked at p3: the refusal is not progress.
    assert_eq!(picked(&doc, &["cursor", "next_step"]), "p3");

    // ...and the refusal the status names is on the run's own journal: the
    // operator can audit which engine gate refused the supervisor.
    let refusal_deadline = Instant::now() + Duration::from_secs(45);
    let mut refusals = Vec::new();
    let frontier_refusal = format!("{run}:p3:refusal.admission.proof_stale");
    while Instant::now() < refusal_deadline {
        refusals = dispatch_refusals(&fixture, &run);
        if refusals
            .iter()
            .any(|(target, _)| target == &frontier_refusal)
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(
        refusals
            .iter()
            .any(|(target, _)| target == &frontier_refusal),
        "the supervisor's refused continuation is recorded against the run: {refusals:?}"
    );
    assert_eq!(
        attempts_for(&fixture, &run, "p3"),
        0,
        "a refusal before any claim is never an attempt: nothing ran"
    );

    // The measured window (issue #141's extended measurement): for forty
    // consecutive minutes every tick reported
    // `next=p3 kind=harness_start in_flight='' attempts=3 elig=True` with the
    // run's claim rows frozen and NOTHING dispatched. The same invariant is
    // observed here over three check intervals (15s at the 5s interval): the
    // frontier stays pinned, the run is never eligible, the refusal is named
    // on every tick, the ledger does not move and no claim is left behind.
    let ledger_before = fixture.seed().run_step_attempts(&run).expect("attempts");
    assert_eq!(
        ledger_before.len(),
        3,
        "the measured ledger: {ledger_before:?}"
    );
    let window_end = Instant::now() + Duration::from_secs(15);
    let mut samples = 0u64;
    let mut seen = Vec::new();
    while Instant::now() < window_end {
        let sample = status_doc(&fixture.socket, &fresh_id(0x141a + samples), &run);
        seen.push(picked(&sample, &["evaluation", "reason"]));
        assert_eq!(picked(&sample, &["cursor", "next_step"]), "p3");
        assert_eq!(
            picked(&sample, &["cursor", "next_step_kind"]),
            "harness_start"
        );
        assert_eq!(picked(&sample, &["cursor", "in_flight"]), "");
        assert_eq!(
            picked(&sample, &["evaluation", "reason"]),
            "supervision.dispatch_refused"
        );
        assert_eq!(
            path_of(&sample, &["evaluation", "eligible"]).as_bool(),
            Some(false)
        );
        assert_eq!(
            attempts_for(&fixture, &run, "p3"),
            0,
            "the window never dispatches the refused frontier"
        );
        samples += 1;
        std::thread::sleep(Duration::from_millis(300));
    }
    assert!(samples > 1, "the window was observed: {seen:?}");
    let state = fixture.seed();
    assert_eq!(
        state.run_step_attempts(&run).expect("attempts").len(),
        3,
        "the ledger is frozen across the window: {seen:?}"
    );
    assert!(
        state.claims_in_flight().expect("claims").is_empty(),
        "a refused dispatch leaves no claim behind"
    );

    // The engine's refusal is ALSO on the daemon's own log: the driver really
    // did attempt this continuation (the defect's only trace before #141).
    let log = std::fs::read_to_string(fixture.daemon_log()).expect("daemon log");
    assert!(
        log.contains("supervision.dispatch_refused")
            && log.contains("step p3: refusal.admission.proof_stale"),
        "the daemon log carries the refused continuation: {log}"
    );

    let socket = fixture.socket.clone();
    shutdown(daemon);
    assert_no_process_for_socket(&socket);
}

/// The CONTROL for issue #141's own suspicion (the fence "computed over the
/// attempts list rather than the current frontier"): with an environment that
/// still admits the frontier, the driver dispatches the repaired frontier's
/// step by ITSELF — no operator dispatch — so the repair never fences the
/// frontier that follows it. The refused case above is the engine's admission
/// gate, not a frontier bookkeeping fence.
#[test]
fn a_repaired_frontier_is_dispatched_by_the_driver_without_any_operator_dispatch() {
    let (fixture, daemon, run) = repaired_lane_scenario(
        "repaired-advanced",
        qp::PlannedStep {
            id: "p3".to_string(),
            kind: "checkout".to_string(),
            params: Some(resolved()),
        },
    );

    // Nothing else dispatches p3: the driver's own continuation reaches the
    // apply engine and runs.
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut attempts = Vec::new();
    while Instant::now() < deadline {
        attempts = fixture.seed().run_step_attempts(&run).expect("attempts");
        if attempts.iter().any(|(step, _)| step == "p3") {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let p3 = attempts
        .iter()
        .find(|(step, _)| step == "p3")
        .unwrap_or_else(|| panic!("the driver never dispatched p3: {attempts:?}"));
    assert_eq!(
        p3.1, "succeeded",
        "the repaired frontier advanced by the driver alone: {attempts:?}"
    );
    let doc = status_doc(&fixture.socket, &fresh_id(0x1420), &run);
    assert_eq!(
        picked(&doc, &["cursor", "next_step"]),
        "",
        "the repaired spine advanced past p3 by the driver alone: {}",
        canter::canonical::canonical_text(&doc)
    );
    assert_eq!(
        path_of(&doc, &["evaluation", "eligible"]).as_bool(),
        Some(false),
        "an exhausted spine is not an eligible continuation"
    );

    let socket = fixture.socket.clone();
    shutdown(daemon);
    assert_no_process_for_socket(&socket);
}
