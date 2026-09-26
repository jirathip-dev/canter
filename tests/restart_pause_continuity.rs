//! Issue #98 acceptance tests: restart/pause and continuation integrity for
//! the native queue.
//!
//! Three layers, synthetic identities only:
//! - the **restart matrix** over the REAL `canter daemon run` child: the
//!   process is killed at each defined durable boundary of one queue advance
//!   (the debug-only `CANTER_CRASH_POINT` hook), and every resumed daemon must
//!   show no duplicate dispatch, no lost queued item, an exactly-once cursor
//!   and a state consistent with the recorded delivery evidence;
//! - the **pause matrix**: pause mid-run through the product's control
//!   surface, restart, still paused with nothing advanced, then one explicit
//!   resume advances exactly once;
//! - the **library-level deterministic harness** (explicit `now_unix`, no
//!   sleeps) for the same properties at the state boundary, including a check
//!   whose progress window has fully elapsed.
//!
//! Every wait on recorded canter state is a poll that fails only after a
//! documented no-progress ceiling (issue #232); there are no fixed real
//! sleeps anywhere in this file.

use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use canter::client::Connection;
use canter::config::ProfileBinding;
use canter::lifecycle::ConcurrencyCaps;
use canter::plan::DOCTRINE_WORKFLOW_ID;
use canter::queue_executor as qx;
use canter::queue_preview as qp;
use canter::state::{QueueSubmissionPlan, Retention, State};
use canter::supervision;
use canter::value::{Val, integer, object, string};

// ---------------------------------------------------------------------------
// Constants and the #84/#85/#95/#96 fixture shape
// ---------------------------------------------------------------------------

const REPO: &str = "example-org/widgets";
const HOST: &str = "host-1";
const HARNESS: &str = "lane-1";
const REV_A: &str = "1111111111111111111111111111111111111111";
const WORKFLOW_HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const POLICY_HASH: &str = "feedface01234567feedface01234567feedface01234567feedface01234567";
const SECRET_DIGEST: &str = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
const HEAD_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const BASE_A: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const GRANT_5: &str = "gr_0000000000000005";
const GRANT_6: &str = "gr_0000000000000006";

/// The crash points this battery kills the daemon at (issue #98). Each one
/// names a durable boundary of ONE queue advance; the transaction that holds
/// the cursor row and the dispatched run decides what a resumed daemon may
/// still do.
const CRASH_AFTER_DELIVERY: &str = "queue.advance.after-delivery";
const CRASH_DURING_DISPATCH: &str = "queue.advance.during-dispatch";
const CRASH_AFTER_DISPATCH: &str = "queue.advance.after-dispatch";
const CRASH_AFTER_CURSOR: &str = "queue.advance.after-cursor";
const CRASH_AFTER_COMMIT: &str = "queue.advance.after-commit";

/// The production-default timer fallback cadence (the pause matrix runs the
/// DEFAULT policy, so a delayed wake is bounded by the same interval a live
/// daemon would use).
const DEFAULT_INTERVAL_SECS: i64 = 60;
const DEFAULT_TIMEOUT_SECS: i64 = 7200;

/// A long check interval keeps the timer fallback out of the test window for
/// the restart-matrix rows: every check after the boot pass is a WAKE or
/// another boot pass.
const QUIET_INTERVAL_SECS: i64 = 3600;
const QUIET_TIMEOUT_SECS: i64 = 7200;

/// The bound the pause matrix allows for a continuation whose wake was
/// delayed: the recorded policy interval plus slack — the documented bounded
/// timer fallback, never a fixed sleep.
const POLICY_BOUND_SECS: u64 = (DEFAULT_INTERVAL_SECS as u64) + 30;

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
        skills: Vec::new(),
        revision: String::new(),
    };
    binding.revision = binding.revision_of();
    binding.to_doc()
}

fn selected(id: &str) -> qp::SelectedIssue {
    qp::SelectedIssue {
        id: id.to_string(),
        title: None,
        revision: REV_A.to_string(),
        requires: Vec::new(),
    }
}

/// One request with the queue's executable spine: a `review_evidence` step
/// (the delivery record the real mutation path applies).
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
            phase: "review".to_string(),
            integration_branch: "staging".to_string(),
            completion_branch: "staging".to_string(),
            caps: vec![
                "read".to_string(),
                "worktree".to_string(),
                "spawn".to_string(),
                "review".to_string(),
                "merge".to_string(),
            ],
        },
        steps: vec![qp::PlannedStep {
            id: "r1".to_string(),
            kind: "review_evidence".to_string(),
            params: Some(object(vec![
                ("reviewer", string("reviewer-1")),
                ("implementer", string("implementer-1")),
                ("verdict", string("pass")),
                (
                    "checks",
                    Val::Arr(vec![object(vec![
                        ("name", string("hosted-ci")),
                        ("status", string("passed")),
                    ])]),
                ),
            ])),
        }],
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

fn grant_doc_at(grant_id: &str, number: i64, revision: &str, epoch: i64) -> Val {
    Val::parse_json(&format!(
        r#"{{"schema":"hf-grant/v1","grant_id":"{grant_id}","repository":"{REPO}",
            "issue":{{"number":{number},"revision":"{revision}"}},
            "workflow_hash":"{WORKFLOW_HASH}","policy_hash":"{POLICY_HASH}",
            "phase":"review","scope":"worktrees/issues/{number}",
            "caps":["read","worktree","spawn","review","merge"],
            "expires_at":"2999-01-01T00:00:00Z","state_epoch":{epoch},
            "created_at":"2026-09-13T00:00:00Z"}}"#
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

fn item_grants(grants: &[(&str, &str)]) -> Vec<qx::ItemGrant> {
    grants
        .iter()
        .map(|(id, grant_id)| qx::ItemGrant {
            id: id.to_string(),
            grant_id: grant_id.to_string(),
        })
        .collect()
}

/// The `queue.submit` params document with grants for every selected issue
/// and the armed supervision authorization for the queue.
fn submit_params_doc(
    key: &str,
    bound: &Val,
    digest: &str,
    grants: &[(&str, &str)],
    caps: ConcurrencyCaps,
    interval: i64,
    timeout: i64,
) -> Val {
    let grants = item_grants(grants);
    qx::submit_params(
        key,
        digest,
        1,
        bound,
        &binding_doc(),
        &role_revision(),
        caps,
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

/// The durable submission plan for the same material (the library-level
/// fixture; the daemon builds the identical plan inline from the presented
/// params).
fn submission_plan(
    state: &State,
    key: &str,
    bound: &Val,
    digest: &str,
    grants: &[(&str, &str)],
    caps: ConcurrencyCaps,
    policy: supervision::Policy,
) -> QueueSubmissionPlan {
    let material = qx::parse_params(&submit_params_doc(
        key,
        bound,
        digest,
        grants,
        caps,
        policy.check_interval_secs,
        policy.progress_timeout_secs,
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
    QueueSubmissionPlan {
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

// ---------------------------------------------------------------------------
// The delivered queue fixture (shared by both layers)
// ---------------------------------------------------------------------------

/// One committed two-issue queue whose first run carries a recorded verified
/// delivery, plus the deterministic identity issue 6 must be dispatched under.
struct Seeded {
    submission_id: String,
    run5: String,
    expected_run6: String,
}

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

/// The dispatch identity of one membership item: `run-` + first 16 hex of the
/// sha256 over the domain-separated (submission, work item) pair. A second
/// dispatch of the same item can therefore never mint a second run.
fn dispatch_identity(submission_id: &str, work_item: &str) -> String {
    let preimage = format!("hf-queue-run/v1|{submission_id}|{work_item}");
    format!(
        "run-{}",
        &canter::canonical::sha256_hex(preimage.as_bytes())[..16]
    )
}

/// Seed the EXACT durable state a restart meets at every crash point of the
/// advance: one committed submission with the next approved issue `waiting`,
/// its delivering run supervised and its reviewed PASS + green checks
/// recorded. Everything goes through the real state API the daemon's own
/// `queue.submit` transaction calls.
fn seed_delivered_queue(
    state: &State,
    name: &str,
    interval_secs: i64,
    timeout_secs: i64,
) -> Seeded {
    seed_grant(state, GRANT_5, 5);
    seed_grant(state, GRANT_6, 6);
    let (bound, digest) = render_bound(state, &request_with(vec![selected("#5"), selected("#6")]));
    // ONE per-repository slot: issue 6 is approved and must wait for the
    // completion-to-next-work continuation to free the slot.
    let caps = ConcurrencyCaps {
        global: 4,
        per_repository: 1,
        per_harness: 2,
    };
    let plan = submission_plan(
        state,
        &idem_key(&format!("{name}-queue")),
        &bound,
        &digest,
        &[("#5", GRANT_5), ("#6", GRANT_6)],
        caps,
        supervision::Policy {
            check_interval_secs: interval_secs,
            progress_timeout_secs: timeout_secs,
        },
    );
    let (submission, items) = state.submit_queue_run(&plan).expect("submit");
    let run5 = item_row_of(&items, 5)
        .instance_id
        .clone()
        .expect("issue 5 admitted");
    assert_eq!(item_row_of(&items, 5).status, "admitted");
    assert_eq!(item_row_of(&items, 6).status, "waiting");
    assert_eq!(item_row_of(&items, 6).instance_id, None);
    let expected_run6 =
        dispatch_identity(&submission.submission_id, &item_row_of(&items, 6).work_item);
    // Issue 5 is delivered: reviewed PASS + required checks green at the
    // exact head, bound to the run's own pins.
    record_delivery(state, &run5, HEAD_A);
    Seeded {
        submission_id: submission.submission_id,
        run5,
        expected_run6,
    }
}

/// Record the reviewed PASS + green checks delivery of one run through the
/// durable state API (the same row shape the daemon's `review_evidence`
/// effect records).
fn record_delivery(state: &State, run: &str, head: &str) -> String {
    let row = state
        .record_evidence(
            run,
            REPO,
            head,
            BASE_A,
            WORKFLOW_HASH,
            POLICY_HASH,
            "pass",
            "reviewer-1",
            &Val::parse_json(r#"[{"name":"hosted-ci","status":"passed"}]"#).expect("checks"),
        )
        .expect("record evidence");
    row.evidence_id
}

/// Drive ONE reconciliation exactly like the driver does: read the snapshot,
/// build the plan from the pure function at the EXPLICIT instant, commit it.
fn reconcile_at(
    state: &State,
    run: &str,
    boot: bool,
    now_unix: i64,
) -> Option<supervision::VerifiedDelivery> {
    let row = state
        .supervision_by_id(run)
        .expect("supervision read")
        .expect("armed run");
    // Issue #311: a run the engine's own record has made terminal is RETIRED —
    // its supervision is never scheduled again, so a replay of a finished run
    // reaches no check at all and answers `None` (no fresh verified delivery).
    if row.desired != "armed" {
        return None;
    }
    let evidence = state
        .supervision_evidence(run)
        .expect("evidence read")
        .expect("supervision exists");
    let plan = supervision::check_plan(&row, &evidence, None, boot, now_unix);
    let advance = plan.advance.clone();
    state.commit_supervision_check(&plan).expect("commit check");
    advance
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

fn status_of(result: &Val, number: i64) -> String {
    item_of(result, number)
        .get("status")
        .and_then(Val::as_str)
        .unwrap_or_default()
        .to_string()
}

fn instance_of(result: &Val, number: i64) -> String {
    item_of(result, number)
        .get("instance_id")
        .and_then(Val::as_str)
        .unwrap_or_default()
        .to_string()
}

fn advance_of(result: &Val) -> Val {
    result.get("advance").cloned().unwrap_or_else(|| {
        panic!(
            "no advance block: {}",
            canter::canonical::canonical_text(result)
        )
    })
}

fn consumed_of(result: &Val) -> i64 {
    advance_of(result)
        .get("consumed")
        .and_then(Val::as_int)
        .unwrap_or(-1)
}

fn dispatched_of(result: &Val) -> i64 {
    advance_of(result)
        .get("dispatched")
        .and_then(Val::as_int)
        .unwrap_or(-1)
}

fn advance_rows_of(result: &Val) -> Vec<Val> {
    advance_of(result)
        .get("rows")
        .and_then(Val::as_array)
        .cloned()
        .unwrap_or_default()
}

/// The rendered `advance` block of ONE consumed delivery: exactly one cursor
/// row carrying the delivered issue and its single dispatched successor, no
/// hold and no second dispatch — the live readback agrees with the durable
/// rows.
fn assert_advance_doc_exactly_once(result: &Val, seeded: &Seeded) {
    assert_eq!(consumed_of(result), 1, "exactly one consumed delivery");
    assert_eq!(dispatched_of(result), 1, "exactly one dispatched run");
    let rows = advance_rows_of(result);
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].get("delivered_ordinal").and_then(Val::as_int),
        Some(0)
    );
    assert_eq!(rows[0].get("next_ordinal").and_then(Val::as_int), Some(1));
    assert_eq!(
        rows[0].get("next_instance_id").and_then(Val::as_str),
        Some(seeded.expected_run6.as_str())
    );
    assert!(matches!(rows[0].get("reason"), Some(Val::Null)));
    assert!(
        matches!(advance_of(result).get("held"), Some(Val::Null)),
        "no hold is reported for a consumed delivery"
    );
    assert_eq!(instance_of(result, 6), seeded.expected_run6);
}

/// The resumed continuation never reached an effect surface: the journal of
/// the whole run carries no harness start, prompt or merge, and the daemon
/// log never records a spawn. The continuation records the next durable run
/// row only — there is no blind spawn and no LLM/polling step anywhere.
fn assert_no_effect_surface(fixture: &DaemonFixture) {
    let actions = rpc_ok(
        &fixture.socket,
        &fresh_id(970),
        "journal.tail",
        Some(object(vec![("limit", integer(200))])),
    );
    let text = canter::canonical::canonical_text(&actions);
    for banned in ["mutate.harness_start", "mutate.prompt", "mutate.merge"] {
        assert!(
            !text.contains(banned),
            "the continuation must never produce {banned}: {text}"
        );
    }
    let log = std::fs::read_to_string(fixture.daemon_log()).unwrap_or_default();
    assert!(
        !log.contains("supervision.continue") && !log.contains("spawn"),
        "no continuation effect may be logged: {log}"
    );
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

/// The recorded retirement of one supervision (issue #311): the terminal run
/// state that retired it, `""` while it is still supervised.
fn retirement_of(doc: &Val) -> String {
    doc.get("supervision")
        .and_then(|supervision| supervision.get("retired_state"))
        .and_then(Val::as_str)
        .unwrap_or_default()
        .to_string()
}

fn eligible_of(doc: &Val) -> Option<bool> {
    evaluation(doc).get("eligible").and_then(Val::as_bool)
}

fn control_state(doc: &Val) -> String {
    doc.get("control")
        .and_then(|control| control.get("state"))
        .and_then(Val::as_str)
        .unwrap_or_default()
        .to_string()
}

fn resume_digest_of(doc: &Val) -> String {
    doc.get("control")
        .and_then(|control| control.get("resume_digest"))
        .and_then(Val::as_str)
        .unwrap_or_default()
        .to_string()
}

// ---------------------------------------------------------------------------
// Library fixture
// ---------------------------------------------------------------------------

struct Fixture {
    dir: PathBuf,
}

impl Fixture {
    fn new(name: &str) -> Fixture {
        let dir = temp_dir(name);
        Fixture { dir }
    }

    fn db(&self) -> PathBuf {
        self.dir.join("state").join("canter").join("state.db")
    }

    fn open(&self) -> State {
        std::fs::create_dir_all(self.dir.join("state").join("canter")).expect("state dir");
        State::open(&self.db(), Retention::default()).expect("open state")
    }
}

// ---------------------------------------------------------------------------
// Daemon fixture
// ---------------------------------------------------------------------------

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("hf98-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
}

/// Runtime-assembled idempotency key (the tracked file never carries a
/// `key = "<literal>"` shape the secret scanners read as an API key).
fn idem_key(stem: &str) -> String {
    format!("ik_98-{stem}-{}", std::process::id())
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

    fn stderr_log(&self) -> PathBuf {
        self.dir.join("daemon.stderr.log")
    }

    fn daemon_log(&self) -> PathBuf {
        self.state_dir.join("canter").join("daemon.log")
    }

    fn seed(&self) -> State {
        std::fs::create_dir_all(self.state_dir.join("canter")).expect("state dir");
        State::open(&self.db(), Retention::default()).expect("open state")
    }

    fn spawn(&self) -> Child {
        self.spawn_with_crash(None)
    }

    /// Spawn the real daemon, optionally arming the debug-only crash hook at
    /// one named durable boundary.
    fn spawn_with_crash(&self, crash_point: Option<&str>) -> Child {
        std::fs::create_dir_all(&self.state_dir).expect("state home");
        let mut command = Command::new(env!("CARGO_BIN_EXE_canter"));
        command
            .args(["daemon", "run", "--socket"])
            .arg(&self.socket)
            .env("XDG_STATE_HOME", &self.state_dir)
            .env("HOME", &self.dir)
            .stdout(Stdio::null())
            .stderr(Stdio::from(
                std::fs::File::create(self.stderr_log()).expect("stderr log"),
            ));
        if let Some(point) = crash_point {
            command.env("CANTER_CRASH_POINT", point);
        }
        command.spawn().expect("spawn daemon")
    }
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
        std::thread::sleep(Duration::from_millis(25));
    }
    let stderr = std::fs::read_to_string(fixture.stderr_log()).unwrap_or_default();
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

/// Send one request and require a typed refusal; returns the stable code.
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

fn shutdown(mut daemon: Child) {
    let _ = daemon.kill();
    let deadline = Instant::now() + Duration::from_secs(10);
    while daemon.try_wait().expect("try_wait").is_none() {
        assert!(Instant::now() < deadline, "daemon did not exit");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Wait for the child to die on its own (the crash hook) and return its raw
/// exit status.
fn wait_for_exit(daemon: &mut Child) -> ExitStatus {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = daemon.try_wait().expect("try_wait") {
            return status;
        }
        assert!(
            Instant::now() < deadline,
            "the daemon never reached its crash point"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn queue_status(fixture: &DaemonFixture, submission_id: &str, id: u64) -> Val {
    rpc_ok(
        &fixture.socket,
        &fresh_id(id),
        "queue.status",
        Some(object(vec![("submission_id", string(submission_id))])),
    )
}

fn supervision_status(fixture: &DaemonFixture, run: &str, id: u64) -> Val {
    rpc_ok(
        &fixture.socket,
        &fresh_id(id),
        "supervision.status",
        Some(supervision::status_params(run)),
    )
}

/// Poll `queue.status` until issue `number` reports `want`.
///
/// `POLICY_BOUND_SECS` is the no-progress ceiling: the recorded policy
/// interval (one driver tick) plus slack.
fn wait_for_item_status(
    fixture: &DaemonFixture,
    submission_id: &str,
    number: i64,
    want: &str,
) -> Val {
    wait_for_item_status_within(fixture, submission_id, number, want, POLICY_BOUND_SECS)
}

/// The same, with an explicit NO-PROGRESS ceiling (issue #232): the wait is
/// progress-driven, never a fixed wall-clock bound — the item's own status is
/// the progress signature, so a status that keeps moving (however slowly on a
/// loaded host) can never exhaust the ceiling, while a genuinely stuck item
/// still fails, naming the progress observed and the elapsed time. The pause
/// matrix passes the recorded policy interval (plus slack) for a continuation
/// whose wake was delayed.
fn wait_for_item_status_within(
    fixture: &DaemonFixture,
    submission_id: &str,
    number: i64,
    want: &str,
    within_secs: u64,
) -> Val {
    let started = Instant::now();
    let mut last_progress = started;
    let mut progress = String::new();
    let mut id = 500u64;
    loop {
        id += 1;
        let doc = queue_status(fixture, submission_id, id);
        let status = status_of(&doc, number);
        if status == want {
            return doc;
        }
        if status != progress {
            progress = status.clone();
            last_progress = Instant::now();
        }
        let stalled = last_progress.elapsed().as_secs();
        assert!(
            stalled < within_secs,
            "issue {number} never reached {want}: no progress for {stalled}s of {}s waited \
             (status {status:?}): {}",
            started.elapsed().as_secs(),
            canter::canonical::canonical_text(&doc)
        );
        std::thread::sleep(Duration::from_millis(25));
    }
}

/// Poll `supervision.status` until the run has committed `want` checks, with an
/// explicit NO-PROGRESS ceiling (issue #232): the recorded check count is the
/// progress signature, so a newly committed check resets the ceiling and a
/// genuinely stalled driver still fails, naming the progress observed and the
/// elapsed time. (Issue #311 removed the last caller that waited for a SECOND
/// check of a run the engine had already made terminal — a retired run is never
/// checked again.)
fn wait_for_checks_within(fixture: &DaemonFixture, run: &str, want: i64, within_secs: u64) -> Val {
    let started = Instant::now();
    let mut last_progress = started;
    let mut progress = -1i64;
    let mut id = 900u64;
    loop {
        id += 1;
        let doc = supervision_status(fixture, run, id);
        let checks = checks_of(&doc);
        if checks >= want {
            return doc;
        }
        if checks != progress {
            progress = checks;
            last_progress = Instant::now();
        }
        let last = canter::canonical::canonical_text(&doc);
        let stalled = last_progress.elapsed().as_secs();
        assert!(
            stalled < within_secs,
            "run {run} never reached {want} recorded check(s): no progress for {stalled}s of {}s \
             waited (recorded {checks}); last: {last}",
            started.elapsed().as_secs()
        );
        std::thread::sleep(Duration::from_millis(25));
    }
}

/// Poll `supervision.status` until the run's supervision reads RETIRED (issue
/// #311: a run the engine recorded terminal is retired, so it is never
/// scheduled a pass again), with the same `POLICY_BOUND_SECS` ceiling as the
/// check waits.
fn wait_for_retirement(fixture: &DaemonFixture, run: &str) -> Val {
    let started = Instant::now();
    let mut id = 800u64;
    loop {
        id += 1;
        let doc = supervision_status(fixture, run, id);
        if !retirement_of(&doc).is_empty() {
            return doc;
        }
        assert!(
            started.elapsed().as_secs() < POLICY_BOUND_SECS,
            "run {run} was never retired within {POLICY_BOUND_SECS}s: {}",
            canter::canonical::canonical_text(&doc)
        );
        std::thread::sleep(Duration::from_millis(25));
    }
}

/// The durable recorded check count of one run (read straight from the state,
/// so it works while no daemon is alive).
fn durable_checks(fixture: &DaemonFixture, run: &str) -> i64 {
    fixture
        .seed()
        .supervision_by_id(run)
        .expect("supervision read")
        .map(|row| row.checks)
        .unwrap_or(-1)
}

/// The durable committed outcome of ONE consumed delivery: exactly one cursor
/// row, exactly one dispatched run, the queued item admitted exactly once.
fn assert_advanced_exactly_once(fixture: &DaemonFixture, seeded: &Seeded) {
    let state = fixture.seed();
    let advances = state
        .queue_advance_rows(&seeded.submission_id)
        .expect("advances");
    assert_eq!(
        advances.len(),
        1,
        "exactly ONE consumed delivery, never a second cursor move"
    );
    assert_eq!(advances[0].delivered_ordinal, 0);
    assert_eq!(advances[0].delivered_head, HEAD_A);
    assert_eq!(advances[0].reason, None);
    assert_eq!(
        advances[0].next_instance_id.as_deref(),
        Some(seeded.expected_run6.as_str()),
        "the dispatched run is the delivered issue's successor"
    );
    let (_, items) = state
        .queue_submission_by_id(&seeded.submission_id)
        .expect("read")
        .expect("submission");
    assert_eq!(item_row_of(&items, 5).status, "admitted");
    assert_eq!(
        item_row_of(&items, 6).status,
        "admitted",
        "the approved waiting item is never lost"
    );
    assert_eq!(
        item_row_of(&items, 6).instance_id.as_deref(),
        Some(seeded.expected_run6.as_str()),
        "the queued item is dispatched under its deterministic identity"
    );
    let instances = state.list_instances().expect("instances");
    assert_eq!(
        instances.len(),
        2,
        "exactly one dispatch, never a duplicate"
    );
    let ownership = state.queue_ownership_rows().expect("ownership");
    assert_eq!(ownership.len(), 1);
    assert!(!ownership.iter().any(|row| row.instance_id == seeded.run5));
    assert!(
        ownership
            .iter()
            .any(|row| row.issue_number == 6 && row.instance_id == seeded.expected_run6),
        "the dispatched issue owns its row exactly once"
    );
    let delivering = instances
        .iter()
        .find(|row| row.instance_id == seeded.run5)
        .expect("the delivering run");
    assert_eq!(
        delivering.status, "done",
        "the consumed delivery completed its run (the slot is freed)"
    );
}

// ---------------------------------------------------------------------------
// Restart matrix: kill the process at each defined durable boundary of ONE
// queue advance and prove the resumed run reconciles exactly once.
// ---------------------------------------------------------------------------

/// Rows (a)-(c) of the restart matrix: the crash lands inside (or before) the
/// advance transaction, so the abort leaves the delivery evidence recorded and
/// the whole advance rolled back. The resumed daemon re-derives the advance
/// from that recorded evidence and applies it exactly once.
fn crash_before_commit_row(point: &str, name: &str) {
    let fixture = DaemonFixture::new(name);
    let seeded = {
        let state = fixture.seed();
        let seeded = seed_delivered_queue(&state, name, QUIET_INTERVAL_SECS, QUIET_TIMEOUT_SECS);
        drop(state);
        seeded
    };

    // 1. The kill: the daemon's own boot reconciliation meets the recorded
    //    delivery and dies at the NAMED boundary.
    let mut daemon = fixture.spawn_with_crash(Some(point));
    let status = wait_for_exit(&mut daemon);
    assert_eq!(
        status.signal(),
        Some(6),
        "the process must be killed at {point}, not exit normally: {status:?}"
    );
    let stderr = std::fs::read_to_string(fixture.stderr_log()).unwrap_or_default();
    assert!(
        stderr.contains(&format!("crash point {point:?} reached")),
        "the kill must land at {point}: {stderr}"
    );

    // 2. What the abort left durable: the delivery evidence, no cursor row, no
    //    second run, the queued item still waiting.
    let crashed = fixture.seed();
    assert_eq!(
        crashed
            .queue_advance_rows(&seeded.submission_id)
            .expect("advances")
            .len(),
        0,
        "nothing of the advance transaction survived the abort"
    );
    let (_, items) = crashed
        .queue_submission_by_id(&seeded.submission_id)
        .expect("read")
        .expect("submission");
    assert_eq!(item_row_of(&items, 5).status, "admitted");
    assert_eq!(
        item_row_of(&items, 6).status,
        "waiting",
        "the queued item is never lost by a crash"
    );
    assert_eq!(item_row_of(&items, 6).instance_id, None);
    assert_eq!(
        crashed.list_instances().expect("instances").len(),
        1,
        "no partial dispatch row survived"
    );
    assert!(
        !crashed
            .list_instances()
            .expect("instances")
            .iter()
            .any(|row| row.status == "done"),
        "the delivering run is not completed without its cursor move"
    );
    drop(crashed);

    // 3. The resumed daemon reconciles from recorded durable state: the
    //    delivery is consumed once and the next approved issue is dispatched.
    let daemon = fixture.spawn();
    wait_ready(&fixture);
    let advanced = wait_for_item_status(&fixture, &seeded.submission_id, 6, "admitted");
    assert_advance_doc_exactly_once(&advanced, &seeded);
    assert_advanced_exactly_once(&fixture, &seeded);
    assert_no_effect_surface(&fixture);

    // 4. A second restart replays nothing: the consumed delivery is durable,
    //    and the delivering run is RETIRED by its own completion (issue #311),
    //    so the boot pass commits NO further check of it.
    let checks_before = checks_of(&supervision_status(&fixture, &seeded.run5, 650));
    shutdown(daemon);
    let daemon = fixture.spawn();
    wait_ready(&fixture);
    let after = wait_for_retirement(&fixture, &seeded.run5);
    assert_eq!(
        retirement_of(&after),
        "done",
        "the delivering run completed"
    );
    assert_eq!(
        checks_of(&after),
        checks_before,
        "a retired run is never checked again"
    );
    let settled = queue_status(&fixture, &seeded.submission_id, 700);
    assert_advance_doc_exactly_once(&settled, &seeded);
    assert_advanced_exactly_once(&fixture, &seeded);
    shutdown(daemon);
}

#[test]
fn restart_matrix_after_delivery_verification_before_cursor_advance_redoes_advance_once() {
    crash_before_commit_row(CRASH_AFTER_DELIVERY, "matrix-a");
}

#[test]
fn restart_matrix_during_dispatch_rolls_back_and_redoes_the_dispatch_once() {
    crash_before_commit_row(CRASH_DURING_DISPATCH, "matrix-b");
}

#[test]
fn restart_matrix_after_dispatch_before_cursor_rolls_back_and_redoes_once() {
    crash_before_commit_row(CRASH_AFTER_DISPATCH, "matrix-c1");
}

#[test]
fn restart_matrix_after_cursor_before_commit_rolls_back_and_redoes_once() {
    crash_before_commit_row(CRASH_AFTER_CURSOR, "matrix-c2");
}

/// Row (d): the crash lands AFTER the advance committed. Everything the
/// advance wrote is durable, and the resumed daemon must neither re-consume
/// the delivery nor dispatch a second run.
#[test]
fn restart_matrix_after_commit_replays_nothing_and_keeps_one_dispatch() {
    let fixture = DaemonFixture::new("matrix-d");
    let seeded = {
        let state = fixture.seed();
        let seeded =
            seed_delivered_queue(&state, "matrix-d", QUIET_INTERVAL_SECS, QUIET_TIMEOUT_SECS);
        drop(state);
        seeded
    };

    // 1. The kill: the boot reconciliation consumed the delivery and died
    //    immediately after the commit.
    let mut daemon = fixture.spawn_with_crash(Some(CRASH_AFTER_COMMIT));
    let status = wait_for_exit(&mut daemon);
    assert_eq!(
        status.signal(),
        Some(6),
        "killed after the commit: {status:?}"
    );
    let stderr = std::fs::read_to_string(fixture.stderr_log()).unwrap_or_default();
    assert!(
        stderr.contains("crash point \"queue.advance.after-commit\" reached"),
        "the kill must land after the commit: {stderr}"
    );

    // 2. The whole advance is durable BEFORE the restart: one consumed
    //    delivery, one cursor row, one dispatched run.
    assert_advanced_exactly_once(&fixture, &seeded);

    // 3. The restart must not repeat any of it. The delivering run is RETIRED
    //    by its own completion (issue #311), so the boot pass commits NO
    //    further check of it and the durable read replays nothing.
    let checks_before = durable_checks(&fixture, &seeded.run5);
    assert!(
        checks_before >= 1,
        "the crash landed after a committed check: {checks_before}"
    );
    let daemon = fixture.spawn();
    wait_ready(&fixture);
    let after = wait_for_retirement(&fixture, &seeded.run5);
    assert_eq!(retirement_of(&after), "done");
    assert_eq!(
        checks_of(&after),
        checks_before,
        "a retired run is never checked again"
    );
    let settled = queue_status(&fixture, &seeded.submission_id, 710);
    assert_advance_doc_exactly_once(&settled, &seeded);
    assert_advanced_exactly_once(&fixture, &seeded);
    assert_no_effect_surface(&fixture);
    shutdown(daemon);
}

// ---------------------------------------------------------------------------
// Pause matrix: pause mid-run, restart, still paused and nothing advanced,
// then one explicit resume advances exactly once.
// ---------------------------------------------------------------------------

#[test]
fn pause_matrix_holds_across_restart_and_resumes_exactly_once() {
    let fixture = DaemonFixture::new("pause");
    let digest = "d".repeat(64);
    let seeded = {
        let state = fixture.seed();
        let seeded =
            seed_delivered_queue(&state, "pause", DEFAULT_INTERVAL_SECS, DEFAULT_TIMEOUT_SECS);
        // The operator pause lands mid-flight (phase `review`, no step in
        // flight): the request is durable immediately and the safe boundary
        // commits — exactly the rows `run.pause` leaves behind. The pending
        // verified delivery must then wait for an explicit resume.
        state
            .request_run_pause(
                &seeded.run5,
                "operator hold for the restart/pause acceptance case",
                &digest,
                &canter::time::rfc3339_now(),
            )
            .expect("pause request");
        state
            .complete_run_pause_boundary(&seeded.run5, &canter::time::rfc3339_now())
            .expect("pause boundary");
        drop(state);
        seeded
    };
    let daemon = fixture.spawn();
    wait_ready(&fixture);

    // The boot pass is the driver's OWN reconciliation: the recorded check
    // classifies the hold and never opens a continuation.
    let held = wait_for_checks_within(&fixture, &seeded.run5, 1, POLICY_BOUND_SECS);
    assert_eq!(class_of(&held), "paused");
    assert_eq!(eligible_of(&held), Some(false));
    assert_eq!(
        evaluation(&held)
            .get("last_check")
            .and_then(|check| check.get("trigger"))
            .and_then(Val::as_str),
        Some("boot")
    );
    // The hold is authoritative on the daemon side too: a second pause over
    // the control surface never creates a second intent.
    let code = rpc_err(
        &fixture.socket,
        &fresh_id(3),
        "run.pause",
        Some(canter::run_control::pause_params(
            &idem_key("pause-again"),
            &seeded.run5,
            "duplicate hold",
        )),
    );
    assert_eq!(code, "refusal.run.control");
    // Baseline for the post-restart reconciliation: read the recorded check
    // count immediately before the restart (the duplicate-pause wake above may
    // legitimately have added a check).
    let checks_before_restart = checks_of(&supervision_status(&fixture, &seeded.run5, 640));

    // Nothing advanced while paused (live readback + durable proof).
    let quiet = queue_status(&fixture, &seeded.submission_id, 10);
    assert_eq!(consumed_of(&quiet), 0);
    assert_eq!(dispatched_of(&quiet), 0);
    assert_eq!(status_of(&quiet, 6), "waiting");
    assert_eq!(instance_of(&quiet, 6), "");
    let state = fixture.seed();
    assert!(
        state
            .queue_advance_rows(&seeded.submission_id)
            .expect("advances")
            .is_empty(),
        "a paused run never advances its queue"
    );
    drop(state);

    // 2. Restart: the hold sticks, the boot pass reconciles exactly once, and
    //    nothing may advance.
    shutdown(daemon);
    let daemon = fixture.spawn();
    wait_ready(&fixture);
    let after = wait_for_checks_within(
        &fixture,
        &seeded.run5,
        checks_before_restart + 1,
        POLICY_BOUND_SECS,
    );
    assert_eq!(class_of(&after), "paused", "the pause survives the restart");
    assert_eq!(eligible_of(&after), Some(false));
    let quiet = queue_status(&fixture, &seeded.submission_id, 20);
    assert_eq!(
        consumed_of(&quiet),
        0,
        "a restart never advances a paused run"
    );
    assert_eq!(status_of(&quiet, 6), "waiting");
    let state = fixture.seed();
    assert!(
        state
            .queue_advance_rows(&seeded.submission_id)
            .expect("advances")
            .is_empty()
    );
    assert!(
        state
            .list_instances()
            .expect("instances")
            .iter()
            .all(|row| row.status != "done")
    );
    drop(state);

    // 3. One explicit resume (with the digest the durable hold carries)
    //    advances exactly once.
    let status = rpc_ok(
        &fixture.socket,
        &fresh_id(25),
        "run.status",
        Some(canter::run_control::status_params(&seeded.run5)),
    );
    assert_eq!(control_state(&status), "paused");
    assert_eq!(
        resume_digest_of(&status),
        digest,
        "the hold keeps its digest across the restart"
    );
    let checks_before_resume = checks_of(&after);
    let resumed = rpc_ok(
        &fixture.socket,
        &fresh_id(30),
        "run.resume",
        Some(canter::run_control::resume_params(
            &idem_key("resume-once"),
            &seeded.run5,
            &digest,
        )),
    );
    assert_eq!(control_state(&resumed), "active");
    let advanced = wait_for_item_status_within(
        &fixture,
        &seeded.submission_id,
        6,
        "admitted",
        POLICY_BOUND_SECS,
    );
    assert_advance_doc_exactly_once(&advanced, &seeded);
    let _ = wait_for_checks_within(
        &fixture,
        &seeded.run5,
        checks_before_resume + 1,
        POLICY_BOUND_SECS,
    );
    assert_advanced_exactly_once(&fixture, &seeded);
    assert_no_effect_surface(&fixture);

    // 4. A further restart replays nothing.
    shutdown(daemon);
    let daemon = fixture.spawn();
    wait_ready(&fixture);
    let settled = queue_status(&fixture, &seeded.submission_id, 40);
    assert_advance_doc_exactly_once(&settled, &seeded);
    assert_advanced_exactly_once(&fixture, &seeded);
    shutdown(daemon);
}

// ---------------------------------------------------------------------------
// Library-level deterministic harness (explicit clock, no sleeps)
// ---------------------------------------------------------------------------

#[test]
fn state_harness_consumes_the_delivery_exactly_once_across_restart_and_a_moved_clock() {
    let fixture = Fixture::new("state-once");
    let state = fixture.open();
    let seeded = seed_delivered_queue(
        &state,
        "state-once",
        QUIET_INTERVAL_SECS,
        QUIET_TIMEOUT_SECS,
    );
    let now = canter::time::unix_now();

    // The crash window itself: the delivery is durable and no advance ran yet.
    let (_, items) = state
        .queue_submission_by_id(&seeded.submission_id)
        .expect("read")
        .expect("submission");
    assert_eq!(item_row_of(&items, 6).status, "waiting");
    assert!(
        state
            .queue_advance_rows(&seeded.submission_id)
            .expect("advances")
            .is_empty()
    );

    // The reconciliation recognizes the fresh delivery and consumes it once.
    let delivery = reconcile_at(&state, &seeded.run5, false, now).expect("a fresh delivery");
    assert_eq!(
        delivery.work_item,
        item_row_of(&items, 5).work_item,
        "the delivery is bound to the delivering run's own membership item"
    );
    let advances = state
        .queue_advance_rows(&seeded.submission_id)
        .expect("advances");
    assert_eq!(advances.len(), 1);
    assert_eq!(
        advances[0].next_instance_id.as_deref(),
        Some(seeded.expected_run6.as_str())
    );
    let consumed = advances[0].clone();

    // Duplicate events and a fully elapsed progress window (the explicit
    // clock jumps past the whole policy) still never move the cursor twice —
    // and the run is RETIRED by its own completion (issue #311), so a replay
    // reaches no check at all while the recorded delivery stays readable.
    for offset in [0, 1, 30, 3600, 86_400] {
        assert_eq!(
            reconcile_at(&state, &seeded.run5, false, now + offset),
            None,
            "a finished run is never scheduled a check again"
        );
    }
    let recorded = state
        .supervision_evidence(&seeded.run5)
        .expect("evidence read")
        .expect("evidence");
    assert_eq!(
        supervision::verified_delivery(&recorded).map(|row| row.evidence_id),
        Some(delivery.evidence_id.clone()),
        "the recorded delivery is still recognized"
    );
    assert_eq!(
        state
            .queue_advance_rows(&seeded.submission_id)
            .expect("advances"),
        vec![consumed.clone()],
        "the consumed delivery record is immutable"
    );
    assert_eq!(state.list_instances().expect("instances").len(), 2);
    drop(state);

    // Restart: the fence is durable, so the boot reconciliation replays
    // nothing (the delivering run is RETIRED — issue #311) and the dispatched
    // item keeps its single deterministic identity.
    let restarted = fixture.open();
    assert_eq!(
        reconcile_at(&restarted, &seeded.run5, true, now + 172_800),
        None,
        "a finished run is never scheduled a check again"
    );
    assert_eq!(
        restarted
            .queue_advance_rows(&seeded.submission_id)
            .expect("advances")
            .len(),
        1
    );
    assert_eq!(restarted.list_instances().expect("instances").len(), 2);
    let (_, after) = restarted
        .queue_submission_by_id(&seeded.submission_id)
        .expect("read")
        .expect("submission");
    assert_eq!(item_row_of(&after, 6).status, "admitted");
    assert_eq!(
        item_row_of(&after, 6).instance_id.as_deref(),
        Some(seeded.expected_run6.as_str())
    );
}

#[test]
fn state_harness_paused_hold_survives_reopen_and_the_resume_advances_once() {
    let fixture = Fixture::new("state-pause");
    let state = fixture.open();
    let seeded = seed_delivered_queue(
        &state,
        "state-pause",
        QUIET_INTERVAL_SECS,
        QUIET_TIMEOUT_SECS,
    );
    let now = canter::time::unix_now();
    let digest = "d".repeat(64);

    // The operator pauses mid-run: the request is durable immediately and the
    // safe boundary commits (no step is in flight).
    state
        .request_run_pause(
            &seeded.run5,
            "operator hold",
            &digest,
            &canter::time::rfc3339_from_unix(now),
        )
        .expect("pause request");
    state
        .complete_run_pause_boundary(&seeded.run5, &canter::time::rfc3339_from_unix(now + 1))
        .expect("pause boundary");

    // While paused: no continuation, no cursor row, and the check reports the
    // hold with the explicit clock moved past the whole policy window.
    let held = state
        .supervision_by_id(&seeded.run5)
        .expect("read")
        .expect("armed");
    let evidence = state
        .supervision_evidence(&seeded.run5)
        .expect("evidence")
        .expect("armed");
    let plan = supervision::check_plan(&held, &evidence, None, false, now + 86_400);
    assert_eq!(plan.class, "paused");
    assert!(!plan.eligible);
    assert!(plan.advance.is_none(), "a paused run is never a delivery");
    state.commit_supervision_check(&plan).expect("commit");
    assert!(
        state
            .queue_advance_rows(&seeded.submission_id)
            .expect("advances")
            .is_empty()
    );
    drop(state);

    // Reopen (restart): the hold sticks and the boot reconciliation still
    // never advances.
    let restarted = fixture.open();
    assert_eq!(
        reconcile_at(&restarted, &seeded.run5, true, now + 172_800),
        None
    );
    assert!(
        restarted
            .queue_advance_rows(&seeded.submission_id)
            .expect("advances")
            .is_empty(),
        "a restart never advances a paused run"
    );
    let (_, items) = restarted
        .queue_submission_by_id(&seeded.submission_id)
        .expect("read")
        .expect("submission");
    assert_eq!(item_row_of(&items, 6).status, "waiting");

    // ONE explicit resume: the delivery is then consumed exactly once.
    restarted
        .resume_run(
            &seeded.run5,
            &digest,
            &canter::time::rfc3339_from_unix(now + 172_801),
        )
        .expect("resume");
    let delivery = reconcile_at(&restarted, &seeded.run5, false, now + 172_802)
        .expect("the delivery after the resume");
    assert_eq!(delivery.feature_head, HEAD_A);
    let advances = restarted
        .queue_advance_rows(&seeded.submission_id)
        .expect("advances");
    assert_eq!(advances.len(), 1);
    assert_eq!(
        advances[0].next_instance_id.as_deref(),
        Some(seeded.expected_run6.as_str())
    );
    // The resume advanced exactly once; the run is retired by that delivery
    // (issue #311), so a further replay reaches no check at all.
    assert_eq!(
        reconcile_at(&restarted, &seeded.run5, false, now + 200_000),
        None,
        "a finished run is never scheduled a check again"
    );
    assert_eq!(
        restarted
            .queue_advance_rows(&seeded.submission_id)
            .expect("advances")
            .len(),
        1,
        "the resume advances exactly once"
    );
    assert_eq!(restarted.list_instances().expect("instances").len(), 2);
}
