//! Issue #96 acceptance tests: bounded continuation from a verified delivery
//! to the next eligible issue of the SAME already-authorized queue.
//!
//! Three fixture layers, synthetic identities only:
//! - library-level `State` assertions driving the REAL driver path
//!   (`supervision::check_plan` -> `State::commit_supervision_check`) for the
//!   two-issue auto-advance, the duplicate-event / restart replay fence and
//!   the dependency hold;
//! - the real `canter daemon run` child over an explicit socket for the live
//!   end-to-end continuation: the queue is submitted through the product
//!   surface, the delivery evidence is recorded through the product's own
//!   `apply` mutation path, and the daemon's own reconciliation admits the
//!   next issue with NO further client request and no conductor prompt.
//!
//! No fixed real sleeps in a wait: every wait on recorded canter state fails
//! only after a documented no-progress ceiling (issue #232).

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
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

const REPO: &str = "example-org/widgets";
const HOST: &str = "host-1";
const HARNESS: &str = "lane-1";
const REV_A: &str = "1111111111111111111111111111111111111111";
const REV_B: &str = "2222222222222222222222222222222222222222";
const WORKFLOW_HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const POLICY_HASH: &str = "feedface01234567feedface01234567feedface01234567feedface01234567";
const SECRET_DIGEST: &str = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
const HEAD_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const BASE_A: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

/// The no-progress ceiling of a recorded-state wait, in seconds (issue #232).
///
/// Progress-driven, never a fixed wall-clock bound: the driver wakes
/// semantically on each committed step and otherwise re-checks on its bounded
/// timer fallback (`canter::supervision::DEFAULT_CHECK_INTERVAL_SECS`, 60 s),
/// so one starved wake legitimately leaves the recorded frontier, the attempt
/// ledger or a queue item's status unchanged for a little over a minute on a
/// loaded host. Every wait below that observes one of those records therefore
/// fails only after this much time with NO durable change — any new recorded
/// attempt, committed check or frontier move resets the ceiling — and names
/// the progress observed and the elapsed time. Two driver ticks, so a single
/// starved wake can never fail a witness, and it stays inside the CI test
/// driver's per-suite budget (`scripts/ci-test-driver.py`,
/// `PER_SUITE_SECONDS = 300`).
const NO_PROGRESS_SECS: u64 = 120;

// ---------------------------------------------------------------------------
// Builders (the #84/#85/#95 fixture shape)
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
        secrets: vec![("PROVIDER_TOKEN".to_string(), SECRET_DIGEST.to_string())],
        skills: Vec::new(),
        revision: String::new(),
    };
    binding.revision = binding.revision_of();
    binding.to_doc()
}

fn resolved() -> Val {
    object(vec![("ref", string("staging"))])
}

fn selected(id: &str, requires: &[&str]) -> qp::SelectedIssue {
    qp::SelectedIssue {
        id: id.to_string(),
        title: None,
        revision: REV_A.to_string(),
        requires: requires.iter().map(|text| text.to_string()).collect(),
    }
}

/// One request with the queue's executable spine: a `review_evidence` step
/// (the delivery record the real mutation path can apply) plus a read step.
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
        steps: vec![
            qp::PlannedStep {
                id: "p1".to_string(),
                kind: "checkout".to_string(),
                params: Some(resolved()),
            },
            qp::PlannedStep {
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
            },
        ],
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
    // REV_A and REV_B bind the same issue identity in different runs; the
    // submission binds REV_A for every selected issue.
    let _ = REV_B;
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
) -> QueueSubmissionPlan {
    let material = qx::parse_params(&submit_params_doc(key, bound, digest, grants, caps, 10, 60))
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
// Library fixture
// ---------------------------------------------------------------------------

struct Fixture {
    dir: PathBuf,
}

impl Fixture {
    fn new(name: &str) -> Fixture {
        let dir =
            std::env::temp_dir().join(format!("hf-queue-advance-96-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
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
// Document readers
// ---------------------------------------------------------------------------

fn item_of(
    items: &[canter::state::QueueSubmissionItemRow],
    number: i64,
) -> canter::state::QueueSubmissionItemRow {
    items
        .iter()
        .find(|item| item.issue_number == number)
        .cloned()
        .unwrap_or_else(|| panic!("no item for issue {number}"))
}

fn item_ordinal(items: &[canter::state::QueueSubmissionItemRow], number: i64) -> i64 {
    item_of(items, number).ordinal
}

/// Drive ONE reconciliation exactly like the driver does: read the snapshot,
/// build the plan from the pure function, commit it.
fn reconcile(state: &State, run: &str, boot: bool) -> Option<supervision::VerifiedDelivery> {
    let row = state
        .supervision_by_id(run)
        .expect("supervision read")
        .expect("armed run");
    let evidence = state
        .supervision_evidence(run)
        .expect("evidence read")
        .expect("supervision exists");
    let plan = supervision::check_plan(&row, &evidence, None, boot, canter::time::unix_now());
    let advance = plan.advance.clone();
    state.commit_supervision_check(&plan).expect("commit check");
    advance
}

/// Record the reviewed PASS + green checks delivery of one run through the
/// durable state API (the same row shape the daemon's `review_evidence`
/// effect records: exact head, workflow/policy pins, pass + all checks
/// passed).
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

// ---------------------------------------------------------------------------
// Issue #202 AC2: the run's certified delivery head is the head its OWN
// collection observed — never a neighbouring effect's echo
// ---------------------------------------------------------------------------

/// Record ONE `apply` step claim with an explicit committed plan document, its
/// success outcome and its RPC response through the SAME durable ledger the
/// daemon writes (pre-effect claim -> recorded outcome + response). No effect
/// runs here: the witnesses below read the recorded rows exactly as the
/// product's own dispatch-context and certificate reads do.
fn record_step_response(
    state: &State,
    run: &str,
    step: &str,
    kind: &str,
    seed: u64,
    result: Val,
) -> String {
    let key = idem_key(&format!("recorded-{step}-{seed}"));
    let request_line = canter::canonical::canonical_text(&object(vec![
        ("method", string("apply")),
        (
            "params",
            object(vec![
                ("instance_id", string(run)),
                ("step", string(step)),
                (
                    "plan",
                    object(vec![(
                        "steps",
                        Val::Arr(vec![object(vec![
                            ("id", string(step)),
                            ("kind", string(kind)),
                        ])]),
                    )]),
                ),
                (
                    "topology",
                    object(vec![("integration_branch", string("staging"))]),
                ),
            ]),
        ),
    ]));
    let (claim, _) = state
        .journal_intent(
            &format!("apply.{step}"),
            &format!("{REPO}:{run}:{step}"),
            &key,
            &format!("request-{seed:016x}"),
            "apply",
            None,
            None,
            &request_line,
        )
        .expect("step intent");
    assert!(
        matches!(claim, canter::state::ClaimAttempt::Claimed),
        "the step claim must be fresh: {claim:?}"
    );
    let outcome = canter::canonical::canonical_text(&object(vec![("status", string("succeeded"))]));
    let response = canter::canonical::canonical_text(&object(vec![
        ("ok", canter::value::bool_(true)),
        ("result", result),
    ]));
    state
        .resolve_run_step_claim(
            &key,
            "apply",
            &outcome,
            &response,
            run,
            step,
            &canter::time::rfc3339_now(),
        )
        .expect("step outcome");
    key
}

/// One admitted run of its own fresh state directory, ready to have recorded
/// step rows seeded against it.
fn admitted_run(fixture: &Fixture, key: &str) -> String {
    let state = fixture.open();
    seed_grant(&state, "gr_0000000000000005", 5);
    let (bound, digest) = render_bound(&state, &request_with(vec![selected("#5", &[])]));
    let caps = ConcurrencyCaps {
        global: 4,
        per_repository: 2,
        per_harness: 2,
    };
    let plan = submission_plan(
        &state,
        key,
        &bound,
        &digest,
        &[("#5", "gr_0000000000000005")],
        caps,
    );
    let (_, items) = state.submit_queue_run(&plan).expect("submit");
    item_of(&items, 5)
        .instance_id
        .clone()
        .expect("issue 5 admitted")
}

/// Issue #202 (AC2). The run's certified delivery binding is the head its OWN
/// `collect_outcome` step observed — recorded, attributed and readable
/// (`run_delivery_certificate`) — and it is the ONLY source of that run's
/// `feature_head`; a `head` echoed by another effect (the base a
/// `worktree_create` response carries) is never a certified delivery head, so
/// a run whose collection never observed a delivery binds NOTHING.
#[test]
fn a_run_binds_only_the_delivery_head_its_own_collection_certified() {
    // The delivering run: an echo row followed by the run's own collection.
    let delivering = Fixture::new("certified-delivery");
    let run = admitted_run(&delivering, "ik_202-certified");
    let state = delivering.open();
    record_step_response(
        &state,
        &run,
        "w1",
        "worktree_create",
        1,
        object(vec![
            ("head", string(BASE_A)),
            ("branch", string("issue-5")),
        ]),
    );
    let key = record_step_response(
        &state,
        &run,
        "o1",
        "collect_outcome",
        2,
        object(vec![
            ("head", string(HEAD_A)),
            ("base_head", string(BASE_A)),
            ("branch", string("issue-5")),
            ("commits", Val::Arr(vec![string(HEAD_A)])),
            ("changed_files", Val::Arr(vec![string("src/lib.rs")])),
        ]),
    );
    let certificate = state
        .run_delivery_certificate(&run)
        .expect("certificate read")
        .expect("the run's own collection certified a delivery");
    assert_eq!(certificate.step_id, "o1", "{certificate:?}");
    assert_eq!(certificate.key, key, "{certificate:?}");
    assert_eq!(certificate.branch, "issue-5", "{certificate:?}");
    assert_eq!(certificate.head, HEAD_A, "{certificate:?}");
    assert_eq!(certificate.base_head, BASE_A, "{certificate:?}");
    let context = state
        .run_dispatch_context(&run)
        .expect("context read")
        .expect("a recorded dispatch context");
    assert_eq!(
        context.feature_head.as_deref(),
        Some(HEAD_A),
        "the run's feature head IS the head its own collection observed: {context:?}"
    );
    assert_eq!(
        context
            .delivery
            .as_ref()
            .map(|certificate| certificate.head.as_str()),
        Some(HEAD_A),
        "the certified delivery binding is readable on the context: {context:?}"
    );

    // The unbound run: the SAME echo row, and no collection at all. The base
    // the echo names is never bound as this run's certified feature head.
    let unbound = Fixture::new("unbound-delivery");
    let run = admitted_run(&unbound, "ik_202-unbound");
    let state = unbound.open();
    record_step_response(
        &state,
        &run,
        "w1",
        "worktree_create",
        1,
        object(vec![
            ("head", string(BASE_A)),
            ("branch", string("issue-5")),
        ]),
    );
    assert_eq!(
        state.run_delivery_certificate(&run).expect("read"),
        None,
        "no collection of this run has certified a delivery"
    );
    let context = state
        .run_dispatch_context(&run)
        .expect("context read")
        .expect("a recorded dispatch context");
    assert_eq!(
        context.feature_head, None,
        "a head no collection of this run observed is never bound as its certified feature head: {context:?}"
    );
    assert_eq!(context.delivery, None, "{context:?}");
}

// ---------------------------------------------------------------------------
// Issue #202 AC2 through the product surface: the daemon consumes only the
// head the run's OWN collection certified
// ---------------------------------------------------------------------------

/// The spine shape of issue #202: the run's own `collect_outcome` (the head it
/// certifies), the reviewed-evidence step, then the committed tail.
fn committed_spine_with_collection() -> Vec<qp::PlannedStep> {
    vec![
        qp::PlannedStep {
            id: "p1".to_string(),
            kind: "checkout".to_string(),
            params: Some(resolved()),
        },
        qp::PlannedStep {
            id: "o1".to_string(),
            kind: "collect_outcome".to_string(),
            params: Some(object(vec![
                ("worktree", string("issues-5")),
                ("branch", string("issue-5")),
                ("requires_delta", canter::value::bool_(true)),
            ])),
        },
        qp::PlannedStep {
            id: "r1".to_string(),
            kind: "review_evidence".to_string(),
            params: Some(review_params()),
        },
        qp::PlannedStep {
            id: "m1".to_string(),
            kind: "merge".to_string(),
            params: Some(object(vec![
                ("branch", string("issue-5")),
                ("merge_policy", string("squash")),
            ])),
        },
        qp::PlannedStep {
            id: "c1".to_string(),
            kind: "cleanup".to_string(),
            params: Some(object(vec![
                ("branch", string("issue-5")),
                ("worktree", string("issues-5")),
            ])),
        },
    ]
}

/// Issue #202 (AC2) through the PRODUCT surface (the real daemon + the real
/// effects): the run's own `collect_outcome` is the only certifier of the
/// delivery head its later steps may consume. The review consumes the head the
/// collection observed, and the SAME review step consuming any OTHER head
/// refuses typed (`refusal.delivery.unbound`, naming the head the run's own
/// collection certified) BEFORE anything runs. Supervision is submitted
/// `disabled`: nothing here is a presentation the driver could have made for
/// us, and no operator retry authorization is minted anywhere.
#[test]
fn the_daemon_consumes_only_the_head_the_runs_own_collection_certified() {
    let fixture = DaemonFixture::new("cert");
    let base = repos_with_lane_branch(&fixture);
    let caps_for_tail = tail_boundary_caps();
    let tail_caps: Vec<&str> = caps_for_tail.iter().map(|cap| cap.as_str()).collect();
    let (bound, digest) = {
        let state = fixture.seed();
        seed_grant_with_caps(&state, "gr_0000000000000005", 5, &tail_caps);
        let mut request = request_with(vec![selected("#5", &[])]);
        request.steps = committed_spine_with_collection();
        request.boundary.caps = tail_boundary_caps();
        render_bound(&state, &request)
    };
    let daemon = fixture.spawn();
    wait_ready(&fixture);
    let submitted = rpc_ok(
        &fixture.socket,
        &fresh_id(1),
        "queue.submit",
        Some(qx::submit_params(
            &idem_key("certified-consumption-submit"),
            &digest,
            1,
            &bound,
            &binding_doc(),
            &role_revision(),
            ConcurrencyCaps {
                global: 4,
                per_repository: 2,
                per_harness: 2,
            },
            Some(true),
            Some(0),
            &item_grants(&[("#5", "gr_0000000000000005")]),
            &[],
            Some(&supervision::Authorization {
                desired: "disabled".to_string(),
                policy: supervision::Policy {
                    check_interval_secs: 10,
                    progress_timeout_secs: 60,
                },
            }),
        )),
    );
    let run = live_item(&submitted, 5)
        .get("instance_id")
        .and_then(Val::as_str)
        .expect("issue 5 admitted")
        .to_string();

    // The lane's own delivery: the delivery branch moves past the base.
    let lane = fixture.dir.join("worktrees/issues-5");
    std::fs::write(lane.join("delivered.txt"), "delivered\n").expect("write");
    git(&lane, &["add", "delivered.txt"]);
    git(&lane, &["commit", "-q", "-m", "lane delivery (synthetic)"]);
    let delivered = git(&lane, &["rev-parse", "HEAD"]);
    assert_ne!(delivered, base, "the lane delivered content");
    assert_eq!(git(&lane, &["branch", "--show-current"]), "issue-5");

    // The run's OWN collection certifies the head it observed.
    let collected = rpc_ok(
        &fixture.socket,
        &fresh_id(31),
        "apply",
        Some(step_apply_params(
            31,
            &fixture,
            &run,
            5,
            "gr_0000000000000005",
            "o1",
            "collect_outcome",
            object(vec![
                ("worktree", string("issues-5")),
                ("branch", string("issue-5")),
                ("requires_delta", canter::value::bool_(true)),
            ]),
            &delivered,
            &base,
        )),
    );
    assert_eq!(
        collected.get("head").and_then(Val::as_str),
        Some(delivered.as_str()),
        "the collection certified the head it observed: {}",
        canter::canonical::canonical_text(&collected)
    );

    // The reviewed-evidence step consumes the certified head.
    let reviewed = rpc_ok(
        &fixture.socket,
        &fresh_id(32),
        "apply",
        Some(step_apply_params(
            32,
            &fixture,
            &run,
            5,
            "gr_0000000000000005",
            "r1",
            "review_evidence",
            review_params(),
            &delivered,
            &base,
        )),
    );
    assert_eq!(
        reviewed.get("feature_head").and_then(Val::as_str),
        Some(delivered.as_str()),
        "the certified head is reviewable: {}",
        canter::canonical::canonical_text(&reviewed)
    );
    assert_eq!(reviewed.get("verdict").and_then(Val::as_str), Some("pass"));

    // Any OTHER head is never consumed: the same step refuses typed, naming
    // the head the run's own collection certified.
    let uncertified = "9".repeat(40);
    let refused = rpc(
        &fixture.socket,
        &fresh_id(33),
        "apply",
        Some(step_apply_params(
            33,
            &fixture,
            &run,
            5,
            "gr_0000000000000005",
            "r1",
            "review_evidence",
            review_params(),
            &uncertified,
            &base,
        )),
    );
    assert_eq!(
        refused.get("ok").and_then(Val::as_bool),
        Some(false),
        "a head no collection observed must refuse: {}",
        canter::canonical::canonical_text(&refused)
    );
    let error = refused.get("error").expect("error doc");
    assert_eq!(
        error.get("code").and_then(Val::as_str),
        Some("refusal.delivery.unbound")
    );
    let message = error
        .get("message")
        .and_then(Val::as_str)
        .unwrap_or_default()
        .to_string();
    assert!(
        message.contains(&delivered),
        "the refusal names the head the run's own collection certified: {message}"
    );
    shutdown(daemon);
}

// ---------------------------------------------------------------------------
// Issue #207 (AC1): the run's OWN reviewer fires at p6, against the head its
// OWN collection certified — driven by the run's own supervisor, with ZERO
// operator dispatches anywhere in the spine
// ---------------------------------------------------------------------------

/// The registry reviewer row of the self-dispatch witness (synthetic): its
/// OWN key, provider and model — resolved from the reviewed profile binding,
/// never a literal in the engine.
const REVIEW_HARNESS: &str = "harness-rev";
const REVIEW_PROVIDER: &str = "provider-rev";
const REVIEW_MODEL: &str = "model-rev";

/// The reviewer's registry-resolved `hf-profile-binding/v1` document (exactly
/// what `canter queue preview --reviewer-harness KEY` resolves for the row).
fn reviewer_binding_doc() -> Val {
    let mut binding = ProfileBinding {
        key: REVIEW_HARNESS.to_string(),
        kind: "hermes".to_string(),
        provider: REVIEW_PROVIDER.to_string(),
        model: REVIEW_MODEL.to_string(),
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

/// The review step's params (issue #193/#207): the run dispatches its OWN
/// reviewer through the registry-resolved role binding, in the run's lane.
fn reviewer_leg_params() -> Val {
    object(vec![
        ("execution", string("headless")),
        ("harness_key", string(REVIEW_HARNESS)),
        ("kind", string("hermes")),
        ("executable", string("hermes")),
        ("reviewer_profile", reviewer_binding_doc()),
        ("worktree", string("issues-5")),
        ("deadline_secs", integer(60)),
    ])
}

/// The committed spine of the self-dispatch witness: the read step, the
/// run's own harness_start (it binds the implementer session the reviewer
/// identity is derived from), the run's OWN collection (the certified head)
/// and the self-dispatching review step. Every step is driven by the run's
/// own supervisor: this witness dispatches none of them.
fn self_dispatch_spine() -> Vec<qp::PlannedStep> {
    vec![
        qp::PlannedStep {
            id: "p1".to_string(),
            kind: "checkout".to_string(),
            params: Some(resolved()),
        },
        qp::PlannedStep {
            id: "s1".to_string(),
            kind: "harness_start".to_string(),
            params: Some(object(vec![
                ("execution", string("headless")),
                ("harness_key", string(HARNESS)),
            ])),
        },
        qp::PlannedStep {
            id: "o1".to_string(),
            kind: "collect_outcome".to_string(),
            params: Some(object(vec![
                ("worktree", string("issues-5")),
                ("branch", string("issue-5")),
                ("requires_delta", canter::value::bool_(true)),
            ])),
        },
        qp::PlannedStep {
            id: "r1".to_string(),
            kind: "review_evidence".to_string(),
            params: Some(reviewer_leg_params()),
        },
    ]
}

/// The submitted dispatch bundle of a supervised run (issues #92/#95): the
/// topology its steps bind and the host-resource admission its fan-out steps
/// re-present. It IS the run's own first dispatch material — this witness
/// issues no operator `apply` at all.
fn dispatch_bundle(fixture: &DaemonFixture) -> Val {
    object(vec![
        (
            "topology",
            object(vec![
                ("integration_branch", string("staging")),
                (
                    "worktrees_root",
                    string(&format!("{}/worktrees", fixture.dir.display())),
                ),
                (
                    "integration_repo",
                    string(&format!("{}/repo", fixture.dir.display())),
                ),
            ]),
        ),
        (
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
                    object(vec![("measured_at", string(&canter::time::rfc3339_now()))]),
                ),
            ]),
        ),
    ])
}

/// The fake reviewer harness (the `hermes` executable the registry-resolved
/// reviewer role runs, headless): it records its argv and the review brief it
/// was prompted with, then plays the REVIEWER — it writes the verdict
/// document the brief names, naming exactly the head the brief named. The
/// engine never writes a verdict.
fn write_fake_reviewer_harness(fixture: &DaemonFixture) -> PathBuf {
    let bin = fixture.dir.join("fakebin");
    std::fs::create_dir_all(&bin).expect("fake bin dir");
    let path = bin.join("hermes");
    std::fs::write(
        &path,
        r#"#!/bin/sh
set -eu
last=""
for arg in "$@"; do last="$arg"; done
printf '%s\n' "$last" > "$HOME/reviewer-payload.txt"
printf '%s\n' "$@" > "$HOME/reviewer-argv.txt"
flat=$(printf '%s' "$last" | tr -d '\n')
verdict_path=$(printf '%s' "$flat" | sed -n 's/.*"\([^"]*\.json\)".*/\1/p')
head=$(printf '%s' "$flat" | sed -n 's/.*"feature_head":"\([0-9a-f]\{40\}\)".*/\1/p')
base=$(printf '%s' "$flat" | sed -n 's/.*"integration_base":"\([0-9a-f]\{40\}\)".*/\1/p')
test -n "$verdict_path"
test -n "$head"
test -n "$base"
mkdir -p "$(dirname "$verdict_path")"
printf '%s' "{\"schema\":\"hf-evidence/v1\",\"feature_head\":\"$head\",\"integration_base\":\"$base\",\"verdict\":\"pass\",\"checks\":[{\"name\":\"exact-head-review\",\"status\":\"passed\"}]}" > "$verdict_path"
"#,
    )
    .expect("write fake reviewer");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = std::fs::metadata(&path).expect("metadata").permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&path, permissions).expect("chmod");
    }
    bin
}

/// The ONE apply row that dispatched step `r1` of this fixture's daemon, read
/// from the durable ledger exactly as the driver's own dispatch key records
/// it (`ik_<run>-<step>-<second>`).
fn r1_dispatch_key(fixture: &DaemonFixture) -> String {
    let conn = rusqlite::Connection::open_with_flags(
        fixture.db(),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .expect("read-only connection");
    let mut statement = conn
        .prepare("SELECT key FROM idempotency WHERE method = 'apply' AND request_line LIKE '%\"step\":\"r1\"%'")
        .expect("prepare r1 dispatch read");
    let rows = statement
        .query_map([], |row| row.get::<_, String>(0))
        .expect("read r1 dispatch rows")
        .collect::<Result<Vec<_>, _>>()
        .expect("r1 dispatch rows");
    assert_eq!(rows.len(), 1, "exactly ONE dispatch of r1 exists: {rows:?}");
    rows.into_iter().next().expect("one row")
}

/// Issue #207 (AC1). The run's OWN reviewer fires at `p6` against the head
/// the run's OWN collection certified — through the run's own supervisor,
/// with ZERO operator dispatches anywhere in the spine. The witness proves
/// the firing (not merely that the code path exists): the daemon's driver
/// drives `p1..r1`, the registry-resolved reviewer role really runs (its
/// recorded argv carries the reviewer's own binding), the written verdict is
/// consumed as the run's recorded evidence at the certified head, and the
/// run completes — exactly the ordering the measured `p6-132` park lacked.
#[test]
fn the_run_dispatches_its_own_reviewer_at_the_certified_head() {
    let fixture = DaemonFixture::new("self-review");
    let base = repos_with_lane_branch(&fixture);
    let lane = fixture.dir.join("worktrees/issues-5");
    std::fs::write(lane.join("delivered.txt"), "the reviewed delivery\n").expect("write");
    git(&lane, &["add", "delivered.txt"]);
    git(
        &lane,
        &["commit", "-q", "-m", "the lane delivery (synthetic)"],
    );
    let certified = git(&lane, &["rev-parse", "HEAD"]);
    assert_ne!(certified, base, "the lane delivered content");
    let fakebin = write_fake_reviewer_harness(&fixture);
    let (bound, digest) = {
        let state = fixture.seed();
        let caps_for_tail = tail_boundary_caps();
        let tail_caps: Vec<&str> = caps_for_tail.iter().map(|cap| cap.as_str()).collect();
        seed_grant_with_caps(&state, "gr_0000000000000005", 5, &tail_caps);
        let mut request = request_with(vec![selected("#5", &[])]);
        request.steps = self_dispatch_spine();
        request.boundary.caps = tail_boundary_caps();
        render_bound(&state, &request)
    };
    let daemon = fixture.spawn_with_path(&fakebin);
    wait_ready(&fixture);
    let mut submit = submit_params_doc(
        &idem_key("self-review-submit"),
        &bound,
        &digest,
        &[("#5", "gr_0000000000000005")],
        ConcurrencyCaps {
            global: 4,
            per_repository: 2,
            per_harness: 2,
        },
        5,
        60,
    );
    match &mut submit {
        Val::Obj(map) => {
            map.insert("dispatch".to_string(), dispatch_bundle(&fixture));
        }
        _ => unreachable!("submit params are an object"),
    }
    let submitted = rpc_ok(&fixture.socket, &fresh_id(1), "queue.submit", Some(submit));
    let run = live_item(&submitted, 5)
        .get("instance_id")
        .and_then(Val::as_str)
        .expect("issue 5 admitted")
        .to_string();

    // NO client dispatch of any step happens from here on: the run's own
    // supervisor owns the committed spine. Poll its own status surface
    // (bounded, no fixed sleep) until the delivery completes the run.
    let mut timeline: Vec<String> = Vec::new();
    let mut id = 700u64;
    let deadline = Instant::now() + Duration::from_secs(120);
    let attempts = loop {
        id += 1;
        let (status, step, kind, attempts) = cursor_sample(&fixture.socket, &run, id);
        timeline.push(format!(
            "t{} status={status} next={step}/{kind} attempts={attempts:?}",
            id - 700
        ));
        if status == "done" {
            break attempts;
        }
        assert!(
            Instant::now() < deadline,
            "the supervisor never drove the spine:\n{}",
            timeline.join("\n")
        );
        std::thread::sleep(Duration::from_millis(250));
    };
    for step in ["p1", "s1", "o1", "r1"] {
        assert!(
            achieved(&attempts, step),
            "the supervisor itself drove {step}: {attempts:?}\n{}",
            timeline.join("\n")
        );
    }
    shutdown(daemon);

    // The r1 dispatch is the DRIVER's own: the only apply row for it carries
    // the driver's dispatch key (no operator key exists in this test), and
    // the run's own log records the supervisor dispatching it.
    let driver_key = r1_dispatch_key(&fixture);
    assert!(
        driver_key.starts_with(&format!("ik_{run}-r1-")),
        "r1 was dispatched by the run's own supervisor: {driver_key:?}"
    );
    let log = std::fs::read_to_string(fixture.daemon_log()).expect("daemon log");
    assert!(
        log.contains("supervision.dispatch") && log.contains("dispatched step r1"),
        "the supervisor dispatched the review step itself: {log}"
    );

    // The reviewer RAN under the registry-resolved binding — its own argv
    // carries the binding pair the registry resolved — against the certified
    // head (the brief the reviewer was prompted with names it).
    let payload = std::fs::read_to_string(fixture.dir.join("reviewer-payload.txt"))
        .expect("the reviewer ran");
    let argv = std::fs::read_to_string(fixture.dir.join("reviewer-argv.txt"))
        .expect("the reviewer's argv");
    assert!(
        argv.contains(REVIEW_HARNESS)
            && argv.contains(REVIEW_PROVIDER)
            && argv.contains(REVIEW_MODEL),
        "the reviewer ran under the registry-resolved binding: {argv}"
    );
    assert!(
        payload.contains(&certified),
        "the reviewer was started against the certified head: {payload}"
    );

    // The recorded evidence IS the verdict the run's own reviewer wrote, at
    // the head the run's own collection certified — and the reviewer is the
    // lane reviewer identity, never the implementer's session.
    let state = fixture.seed();
    let certificate = state
        .run_delivery_certificate(&run)
        .expect("certificate read")
        .expect("the run's own collection certified a delivery");
    assert_eq!(certificate.head, certified, "{certificate:?}");
    assert_eq!(certificate.branch, "issue-5", "{certificate:?}");
    let evidence = state.evidence_for_instance(&run).expect("evidence read");
    let newest = evidence
        .first()
        .expect("the run's own reviewer recorded evidence");
    assert_eq!(
        newest.feature_head, certified,
        "the evidence names the certified head: {newest:?}"
    );
    assert_eq!(newest.verdict, "pass");
    assert!(
        newest.checks.contains("exact-head-review"),
        "the reviewer's own check is recorded: {}",
        newest.checks
    );
    assert_eq!(
        newest.reviewer, "rev-5-r1",
        "the reviewer is the lane reviewer identity, not the implementer's session"
    );
}

// ---------------------------------------------------------------------------
// AC: two-issue auto-advance, once, and never twice (duplicate + restart)
// ---------------------------------------------------------------------------

#[test]
fn a_verified_delivery_advances_the_cursor_once_and_never_twice_across_restart() {
    let fixture = Fixture::new("advance");
    let state = fixture.open();
    seed_grant(&state, "gr_0000000000000005", 5);
    seed_grant(&state, "gr_0000000000000006", 6);
    let (bound, digest) = render_bound(
        &state,
        &request_with(vec![selected("#5", &[]), selected("#6", &[])]),
    );
    // ONE per-repository slot: the second approved issue must wait.
    let caps = ConcurrencyCaps {
        global: 4,
        per_repository: 1,
        per_harness: 2,
    };
    let plan = submission_plan(
        &state,
        "ik_96-advance",
        &bound,
        &digest,
        &[("#5", "gr_0000000000000005"), ("#6", "gr_0000000000000006")],
        caps,
    );
    let (submission, items) = state.submit_queue_run(&plan).expect("submit");
    let run5 = item_of(&items, 5)
        .instance_id
        .clone()
        .expect("issue 5 admitted");
    assert_eq!(item_of(&items, 5).status, "admitted");
    assert_eq!(item_of(&items, 6).status, "waiting");
    assert_eq!(item_of(&items, 6).instance_id, None);

    // Issue 5 is delivered: reviewed PASS + required checks green at the
    // exact head, bound to the run's own pins.
    let evidence_id = record_delivery(&state, &run5, HEAD_A);

    // The driver's REAL path recognizes the delivery and advances the cursor
    // exactly once; the dispatched issue 6 run is created with its own armed
    // supervision so the queue keeps continuing.
    let delivery = reconcile(&state, &run5, true).expect("a fresh verified delivery");
    assert_eq!(delivery.submission_id, submission.submission_id);
    assert_eq!(delivery.item_ordinal, item_ordinal(&items, 5));
    assert_eq!(delivery.work_item, item_of(&items, 5).work_item);
    assert_eq!(delivery.feature_head, HEAD_A);
    assert_eq!(delivery.evidence_id, evidence_id);

    let (_, after) = state
        .queue_submission_by_id(&submission.submission_id)
        .expect("read")
        .expect("submission");
    assert_eq!(item_of(&after, 5).status, "admitted");
    assert_eq!(after.len(), 2, "no new membership item was created");
    assert_eq!(
        item_of(&after, 6).status,
        "admitted",
        "the next eligible approved issue is admitted"
    );
    let run6 = item_of(&after, 6)
        .instance_id
        .clone()
        .expect("issue 6 admitted");
    assert_ne!(run6, run5);
    assert_eq!(state.list_instances().expect("instances").len(), 2);
    let ownership = state.queue_ownership_rows().expect("ownership");
    assert_eq!(ownership.len(), 1);
    assert!(!ownership.iter().any(|row| row.instance_id == run5));
    assert!(
        ownership
            .iter()
            .any(|row| row.issue_number == 6 && row.instance_id == run6),
        "the dispatched issue owns its row"
    );
    // The dispatched run inherits the queue's authorization: armed with the
    // same policy, bound to the same approved digest.
    let armed6 = state
        .supervision_by_id(&run6)
        .expect("supervision read")
        .expect("the dispatched run is supervised");
    assert_eq!(armed6.desired, "armed");
    assert_eq!(armed6.check_interval_secs, 10);
    assert_eq!(armed6.progress_timeout_secs, 60);
    assert_eq!(armed6.authorization_digest, submission.digest);
    let armed5 = state
        .supervision_by_id(&run5)
        .expect("supervision read")
        .expect("run 5 supervised");
    assert!(armed5.checks >= 1, "the reconciliation committed");

    // The durable cursor: ONE consumed delivery, ONE dispatch.
    let advances = state
        .queue_advance_rows(&submission.submission_id)
        .expect("advances");
    assert_eq!(advances.len(), 1);
    assert_eq!(advances[0].delivered_ordinal, delivery.item_ordinal);
    assert_eq!(advances[0].delivered_head, HEAD_A);
    assert_eq!(advances[0].next_instance_id.as_deref(), Some(run6.as_str()));
    assert_eq!(advances[0].reason, None);
    // The rendered submission document reports the committed cursor.
    let doc = qx::submission_doc(&submission, &after, &advances);
    let advance = doc.get("advance").expect("advance block");
    assert_eq!(
        advance.get("cursor_ordinal").and_then(Val::as_int),
        Some(delivery.item_ordinal),
        "the cursor is the consumed delivery's membership position"
    );
    assert_eq!(advance.get("consumed").and_then(Val::as_int), Some(1));
    assert_eq!(advance.get("dispatched").and_then(Val::as_int), Some(1));
    assert!(matches!(advance.get("held"), Some(Val::Null)));

    // DUPLICATE EVENT: the same delivery replayed five more times (and the
    // next run's own reconciliations, which see no evidence) dispatch
    // nothing and never rewrite the consumed record.
    let consumed_before = advances[0].clone();
    for _ in 0..5 {
        let replayed = reconcile(&state, &run5, false);
        assert_eq!(
            replayed,
            Some(delivery.clone()),
            "the delivery is still recognized"
        );
    }
    for _ in 0..2 {
        assert_eq!(reconcile(&state, &run6, false), None);
    }
    let consumed_after = state
        .queue_advance_rows(&submission.submission_id)
        .expect("advances");
    assert_eq!(
        consumed_after.len(),
        1,
        "a duplicate delivery event never consumes a second cursor move"
    );
    assert_eq!(
        consumed_after[0], consumed_before,
        "the consumed delivery record is immutable: a replay never rewrites the cursor"
    );
    assert_eq!(state.list_instances().expect("instances").len(), 2);
    let (_, replayed_items) = state
        .queue_submission_by_id(&submission.submission_id)
        .expect("read")
        .expect("submission");
    assert_eq!(
        item_of(&replayed_items, 5).instance_id.as_deref(),
        Some(run5.as_str())
    );
    assert_eq!(
        item_of(&replayed_items, 6).instance_id.as_deref(),
        Some(run6.as_str())
    );
    drop(state);

    // RESTART / REPLAY: the fence is durable, not in-memory.
    let restarted = fixture.open();
    let delivery_again = reconcile(&restarted, &run5, true).expect("delivery survives restart");
    assert_eq!(delivery_again, delivery);
    assert_eq!(
        restarted
            .queue_advance_rows(&submission.submission_id)
            .expect("advances")
            .len(),
        1
    );
    assert_eq!(restarted.list_instances().expect("instances").len(), 2);
    let (_, after_restart) = restarted
        .queue_submission_by_id(&submission.submission_id)
        .expect("read")
        .expect("submission");
    assert_eq!(item_of(&after_restart, 6).status, "admitted");
}

// ---------------------------------------------------------------------------
// AC: dependency holds never fabricate completion
// ---------------------------------------------------------------------------

#[test]
fn an_unmet_dependency_holds_the_next_issue_with_a_reason_and_never_marks_it_done() {
    let fixture = Fixture::new("dependency");
    let state = fixture.open();
    seed_grant(&state, "gr_0000000000000005", 5);
    seed_grant(&state, "gr_0000000000000006", 6);
    seed_grant(&state, "gr_0000000000000007", 7);
    // Issue 7 requires issue 6; issues 5 and 6 occupy the two slots, so 7
    // waits (and its declared dependency is NOT delivered yet).
    let (bound, digest) = render_bound(
        &state,
        &request_with(vec![
            selected("#5", &[]),
            selected("#6", &[]),
            selected("#7", &["#6"]),
        ]),
    );
    let caps = ConcurrencyCaps {
        global: 4,
        per_repository: 2,
        per_harness: 2,
    };
    let plan = submission_plan(
        &state,
        "ik_96-dependency",
        &bound,
        &digest,
        &[
            ("#5", "gr_0000000000000005"),
            ("#6", "gr_0000000000000006"),
            ("#7", "gr_0000000000000007"),
        ],
        caps,
    );
    let (submission, items) = state.submit_queue_run(&plan).expect("submit");
    let run5 = item_of(&items, 5).instance_id.clone().expect("5 admitted");
    let run6 = item_of(&items, 6).instance_id.clone().expect("6 admitted");
    assert_eq!(item_of(&items, 7).status, "waiting");

    // Issue 5 is delivered. The next candidate is issue 7, whose dependency
    // (issue 6) is admitted but NOT delivered: it must be HELD with the
    // reason recorded, never dispatched and never marked done.
    record_delivery(&state, &run5, HEAD_A);
    let delivery = reconcile(&state, &run5, true).expect("delivery of issue 5");
    let advances = state
        .queue_advance_rows(&submission.submission_id)
        .expect("advances");
    assert_eq!(advances.len(), 1);
    assert_eq!(advances[0].next_ordinal, Some(item_ordinal(&items, 7)));
    assert_eq!(
        advances[0].next_work_item.as_deref(),
        Some(item_of(&items, 7).work_item.as_str())
    );
    assert_eq!(advances[0].next_instance_id, None, "nothing was dispatched");
    assert_eq!(
        advances[0].reason.as_deref(),
        Some(qx::advance::DEPENDENCY_UNSETTLED)
    );
    assert!(
        advances[0]
            .message
            .as_deref()
            .unwrap_or_default()
            .contains("#6"),
        "the hold names the unmet dependency: {:?}",
        advances[0].message
    );
    let (_, held_items) = state
        .queue_submission_by_id(&submission.submission_id)
        .expect("read")
        .expect("submission");
    assert_eq!(
        item_of(&held_items, 7).status,
        "waiting",
        "an unmet dependency never admits the dependent"
    );
    assert_eq!(item_of(&held_items, 7).instance_id, None);
    // ...and it never fabricates the completion of the dependency either.
    let dep_run = state
        .instance_by_id(&run6)
        .expect("read")
        .expect("dependency run")
        .status;
    assert_ne!(dep_run, "done", "an unmet dependency is not marked done");
    assert_eq!(state.list_instances().expect("instances").len(), 2);
    assert_eq!(delivery.item_ordinal, item_ordinal(&items, 5));

    // A replayed delivery while the dependency is still unmet re-records the
    // SAME hold (never a dispatch).
    reconcile(&state, &run5, false);
    let advances = state
        .queue_advance_rows(&submission.submission_id)
        .expect("advances");
    assert_eq!(advances.len(), 1);
    assert_eq!(advances[0].next_instance_id, None);

    // The dependency delivers: the SAME delivery row settles and the held
    // issue is admitted — the cursor never skipped it.
    record_delivery(&state, &run6, HEAD_A);
    reconcile(&state, &run6, false).expect("delivery of issue 6");
    let (_, settled) = state
        .queue_submission_by_id(&submission.submission_id)
        .expect("read")
        .expect("submission");
    assert_eq!(item_of(&settled, 7).status, "admitted");
    let run7 = item_of(&settled, 7)
        .instance_id
        .clone()
        .expect("issue 7 admitted");
    assert_eq!(state.list_instances().expect("instances").len(), 3);
    let advances = state
        .queue_advance_rows(&submission.submission_id)
        .expect("advances");
    assert_eq!(
        advances.len(),
        2,
        "one consumed delivery per delivered issue"
    );
    assert_eq!(
        advances[0].reason, None,
        "the settled hold records the dispatch"
    );
    assert_eq!(advances[0].next_instance_id.as_deref(), Some(run7.as_str()));
    assert_eq!(
        advances[1].next_instance_id.as_deref(),
        Some(run7.as_str()),
        "issue 7's dispatch is keyed to the dependency's delivery"
    );
    assert_eq!(
        state
            .supervision_by_id(&run7)
            .expect("read")
            .expect("supervised")
            .desired,
        "armed"
    );
}

// ---------------------------------------------------------------------------
// AC: a paused run does not auto-advance (existing safeguards stay
// authoritative)
// ---------------------------------------------------------------------------

#[test]
fn a_paused_or_invalidated_run_never_advances_its_queue() {
    let fixture = Fixture::new("hold");
    let state = fixture.open();
    seed_grant(&state, "gr_0000000000000005", 5);
    seed_grant(&state, "gr_0000000000000006", 6);
    let (bound, digest) = render_bound(
        &state,
        &request_with(vec![selected("#5", &[]), selected("#6", &[])]),
    );
    let caps = ConcurrencyCaps {
        global: 4,
        per_repository: 1,
        per_harness: 2,
    };
    let plan = submission_plan(
        &state,
        "ik_96-hold-run",
        &bound,
        &digest,
        &[("#5", "gr_0000000000000005"), ("#6", "gr_0000000000000006")],
        caps,
    );
    let (submission, items) = state.submit_queue_run(&plan).expect("submit");
    let run5 = item_of(&items, 5).instance_id.clone().expect("5 admitted");
    record_delivery(&state, &run5, HEAD_A);

    // The safe-boundary pause commits before any continuation.
    state
        .request_run_pause(
            &run5,
            "operator pause",
            &"d".repeat(64),
            "2026-09-13T00:01:00Z",
        )
        .expect("pause request");
    state
        .complete_run_pause_boundary(&run5, "2026-09-13T00:01:01Z")
        .expect("pause boundary");
    assert_eq!(
        reconcile(&state, &run5, false),
        None,
        "a paused run never advances"
    );
    assert_eq!(
        state
            .queue_advance_rows(&submission.submission_id)
            .expect("advances")
            .len(),
        0,
        "no cursor row is written for a held run"
    );

    // Resume, deliver, advance — then invalidate the dispatching run: the
    // recorded dispatch stays, and no further delivery can move it.
    state
        .resume_run(&run5, &"d".repeat(64), "2026-09-13T00:02:00Z")
        .expect("resume");
    reconcile(&state, &run5, false).expect("delivery after resume");
    let (_, advanced) = state
        .queue_submission_by_id(&submission.submission_id)
        .expect("read")
        .expect("submission");
    assert_eq!(item_of(&advanced, 6).status, "admitted");
    let run6 = item_of(&advanced, 6)
        .instance_id
        .clone()
        .expect("6 admitted");
    // A failure verdict is a terminal hold: the newest row is a fail, so the
    // second issue's run is never a delivery.
    state
        .record_evidence(
            &run6,
            REPO,
            HEAD_A,
            BASE_A,
            WORKFLOW_HASH,
            POLICY_HASH,
            "fail",
            "reviewer-1",
            &Val::parse_json(r#"[{"name":"hosted-ci","status":"failed"}]"#).expect("checks"),
        )
        .expect("record fail");
    assert_eq!(reconcile(&state, &run6, false), None);
    assert_eq!(state.list_instances().expect("instances").len(), 2);
}

// ---------------------------------------------------------------------------
// Issue #152: a delivering run completes only AFTER its LAST committed step
// ---------------------------------------------------------------------------

/// The queue spine prefix shared by every fixture: a resolved read step plus
/// the reviewed-evidence step whose committed record IS the delivery.
fn delivery_spine() -> Vec<qp::PlannedStep> {
    vec![
        qp::PlannedStep {
            id: "p1".to_string(),
            kind: "checkout".to_string(),
            params: Some(resolved()),
        },
        qp::PlannedStep {
            id: "r1".to_string(),
            kind: "review_evidence".to_string(),
            params: Some(review_params()),
        },
    ]
}

/// The `review_evidence` step params of the passing reviewed delivery.
fn review_params() -> Val {
    object(vec![
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
    ])
}

/// The spine shape of issue #152 (the #146 plan): committed steps AFTER the
/// reviewed delivery — the merge, then the cleanup.
fn committed_tail_steps() -> Vec<qp::PlannedStep> {
    let mut steps = delivery_spine();
    steps.push(qp::PlannedStep {
        id: "m1".to_string(),
        kind: "merge".to_string(),
        params: Some(object(vec![
            ("branch", string("issue-5")),
            ("merge_policy", string("squash")),
        ])),
    });
    steps.push(qp::PlannedStep {
        id: "c1".to_string(),
        kind: "cleanup".to_string(),
        params: Some(object(vec![
            ("branch", string("issue-5")),
            ("worktree", string("issues-5")),
        ])),
    });
    steps
}

/// The boundary caps that cover the committed tail (merge + cleanup).
fn tail_boundary_caps() -> Vec<String> {
    ["read", "worktree", "spawn", "review", "merge", "cleanup"]
        .iter()
        .map(|cap| cap.to_string())
        .collect()
}

/// Record ONE achieved step of a run through the SAME durable ledger the
/// apply engine writes (pre-effect claim -> recorded outcome), so the
/// frontier and the completion timing read one fact. No external effect runs
/// here: the daemon-level witnesses drive the real effects.
fn record_achieved_step(state: &State, run: &str, step: &str, action: &str, seed: u64) {
    let key = idem_key(&format!("achieved-{step}-{seed}"));
    let request_line = canter::canonical::canonical_text(&object(vec![
        ("method", string("apply")),
        (
            "params",
            object(vec![("instance_id", string(run)), ("step", string(step))]),
        ),
    ]));
    let (claim, _) = state
        .journal_intent(
            action,
            &format!("{REPO}:{run}:{step}"),
            &key,
            &format!("request-{seed:016x}"),
            "apply",
            None,
            None,
            &request_line,
        )
        .expect("step intent");
    assert!(
        matches!(claim, canter::state::ClaimAttempt::Claimed),
        "the step claim must be fresh: {claim:?}"
    );
    let outcome = canter::canonical::canonical_text(&object(vec![("status", string("succeeded"))]));
    state
        .resolve_run_step_claim(
            &key,
            "apply",
            &outcome,
            "{}",
            run,
            step,
            &canter::time::rfc3339_now(),
        )
        .expect("step outcome");
}

fn run_status(state: &State, run: &str) -> String {
    state
        .instance_by_id(run)
        .expect("instance read")
        .expect("instance row")
        .status
}

fn read_ownership(db: &Path) -> Vec<(i64, String)> {
    let conn =
        rusqlite::Connection::open_with_flags(db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("read-only connection");
    let sql = "SELECT issue_number, instance_id FROM queue_ownership ORDER BY issue_number";
    let rows = conn
        .prepare(sql)
        .expect("prepare ownership read")
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .expect("read ownership")
        .collect::<Result<Vec<_>, _>>()
        .expect("ownership rows");
    println!("{sql}: {rows:?}");
    rows
}

fn submission_items(state: &State, submission: &str) -> Vec<canter::state::QueueSubmissionItemRow> {
    state
        .queue_submission_by_id(submission)
        .expect("read")
        .expect("submission")
        .1
}

#[test]
fn a_delivering_run_with_committed_steps_after_the_delivery_stays_live_until_its_last_step() {
    let fixture = Fixture::new("committed-tail");
    let state = fixture.open();
    seed_grant(&state, "gr_0000000000000005", 5);
    seed_grant(&state, "gr_0000000000000006", 6);
    let mut request = request_with(vec![selected("#5", &[]), selected("#6", &[])]);
    request.steps = committed_tail_steps();
    request.boundary.caps = tail_boundary_caps();
    let (bound, digest) = render_bound(&state, &request);
    // ONE per-repository slot: the second approved issue waits.
    let caps = ConcurrencyCaps {
        global: 4,
        per_repository: 1,
        per_harness: 2,
    };
    let plan = submission_plan(
        &state,
        "ik_152-committed-tail",
        &bound,
        &digest,
        &[("#5", "gr_0000000000000005"), ("#6", "gr_0000000000000006")],
        caps,
    );
    let (submission, items) = state.submit_queue_run(&plan).expect("submit");
    let run5 = item_of(&items, 5)
        .instance_id
        .clone()
        .expect("issue 5 admitted");
    assert_eq!(item_of(&items, 6).status, "waiting");

    // Issue 5 is delivered: reviewed PASS + green checks at the exact head.
    // The steps the run already executed (the read + its own reviewed
    // evidence) are on the ledger, as a real run leaves them.
    record_achieved_step(&state, &run5, "p1", "mutate.checkout", 11);
    record_achieved_step(&state, &run5, "r1", "mutate.review_evidence", 12);
    record_delivery(&state, &run5, HEAD_A);
    let delivery = reconcile(&state, &run5, true).expect("a fresh verified delivery");

    // The run's record NAMES the committed steps it still owes, so the
    // delivery can never read as a bare `done`.
    let evidence = state
        .supervision_evidence(&run5)
        .expect("evidence read")
        .expect("supervised run");
    assert_eq!(
        supervision::next_unachieved_step(&evidence),
        Some(("m1".to_string(), "merge".to_string())),
        "the delivering run's frontier is its own committed merge step"
    );
    let spine: Vec<String> = evidence.steps.iter().map(|(id, _)| id.clone()).collect();
    assert_eq!(spine, vec!["p1", "r1", "m1", "c1"]);
    // The delivering run is NOT completed at delivery verification ...
    assert_ne!(
        run_status(&state, &run5),
        "done",
        "a run whose committed spine still owes the merge and the cleanup stays live"
    );
    // ... and the slot it still holds is reported as a HOLD, never a dispatch.
    let advances = state
        .queue_advance_rows(&submission.submission_id)
        .expect("advances");
    assert_eq!(advances.len(), 1);
    assert_eq!(advances[0].next_instance_id, None);
    assert!(
        advances[0].reason.is_some(),
        "the waiting issue is held while the delivering run has not finished: {:?}",
        advances[0].reason
    );
    assert_eq!(
        item_of(&submission_items(&state, &submission.submission_id), 6).status,
        "waiting"
    );

    // The run's own committed merge step executes (its attempt is recorded
    // on the same ledger the frontier reads).
    record_achieved_step(&state, &run5, "m1", "mutate.merge", 1);
    assert_eq!(reconcile(&state, &run5, false), Some(delivery.clone()));
    assert_ne!(
        run_status(&state, &run5),
        "done",
        "the cleanup is still owed: the run stays live after the merge"
    );
    assert!(read_ownership(&fixture.db()).contains(&(5, run5.clone())));

    // The LAST committed step executes: the run completes only NOW, and the
    // freed slot admits the waiting issue in the same transaction.
    record_achieved_step(&state, &run5, "c1", "mutate.cleanup", 2);
    reconcile(&state, &run5, false);
    assert_eq!(
        run_status(&state, &run5),
        "done",
        "the delivering run completes after its LAST committed step"
    );
    assert!(
        !read_ownership(&fixture.db())
            .iter()
            .any(|(issue, _)| *issue == 5)
    );
    let after = submission_items(&state, &submission.submission_id);
    assert_eq!(item_of(&after, 6).status, "admitted");
    let run6 = item_of(&after, 6)
        .instance_id
        .clone()
        .expect("issue 6 admitted");
    assert_ne!(run6, run5);
    let advances = state
        .queue_advance_rows(&submission.submission_id)
        .expect("advances");
    assert_eq!(advances.len(), 1, "one delivery, one cursor move");
    assert_eq!(advances[0].next_instance_id.as_deref(), Some(run6.as_str()));
    assert_eq!(advances[0].reason, None, "the hold settled");
    assert_eq!(state.list_instances().expect("instances").len(), 2);
    reconcile(&state, &run5, false);
    let completed = state.supervision_by_id(&run5).unwrap().unwrap();
    assert_eq!(completed.last_check_class, "completed");
    assert_eq!(completed.last_check_reason, supervision::codes::COMPLETED);
    let evidence = state.supervision_evidence(&run5).unwrap().unwrap();
    assert_eq!(supervision::next_unachieved_step(&evidence), None);
    println!(
        "FINISHED status={} reason={} attempts={:?}",
        evidence.run.status, completed.last_check_reason, evidence.attempts
    );
}

#[test]
fn releasing_a_verified_delivery_with_an_unexecuted_tail_never_reports_completed() {
    let fixture = Fixture::new("release-tail");
    let state = fixture.open();
    seed_grant(&state, "gr_0000000000000005", 5);
    let mut request = request_with(vec![selected("#5", &[])]);
    request.steps = committed_tail_steps();
    request.boundary.caps = tail_boundary_caps();
    let (bound, digest) = render_bound(&state, &request);
    let plan = submission_plan(
        &state,
        "ik_152-release-tail",
        &bound,
        &digest,
        &[("#5", "gr_0000000000000005")],
        request.caps,
    );
    let (_, items) = state.submit_queue_run(&plan).expect("submit");
    let run = items[0].instance_id.as_deref().expect("admitted run");
    record_achieved_step(&state, run, "p1", "mutate.checkout", 11);
    record_achieved_step(&state, run, "r1", "mutate.review_evidence", 12);
    record_delivery(&state, run, HEAD_A);
    reconcile(&state, run, true).expect("verified delivery");
    assert_ne!(run_status(&state, run), "done", "the tail is still owed");

    state
        .release_run(
            run,
            "stop before committed merge and cleanup",
            "ik_152-release-unfinished",
            &canter::time::rfc3339_now(),
        )
        .expect("release unfinished run");
    drop(state);
    let state = fixture.open();
    assert_eq!(reconcile(&state, run, true), None);
    let row = state.supervision_by_id(run).unwrap().unwrap();
    assert_eq!(row.last_check_class, "needs-attention");
    assert_eq!(row.last_check_reason, supervision::codes::INVALIDATED);
    let evidence = state.supervision_evidence(run).unwrap().unwrap();
    assert_eq!(evidence.run.status, "invalidated");
    assert_eq!(
        supervision::next_unachieved_step(&evidence),
        Some(("m1".to_string(), "merge".to_string()))
    );
    let unexecuted: Vec<_> = evidence
        .steps
        .iter()
        .filter(|(id, _)| !evidence.attempts.iter().any(|(step, _, _)| step == id))
        .cloned()
        .collect();
    assert_eq!(
        unexecuted,
        vec![
            ("m1".to_string(), "merge".to_string()),
            ("c1".to_string(), "cleanup".to_string()),
        ]
    );
    assert!(supervision::dispatch_intent(&row, &evidence).is_none());
    println!(
        "RELEASED status={} reason={} unexecuted={unexecuted:?}",
        evidence.run.status, row.last_check_reason
    );
}

#[test]
fn a_plan_that_ends_at_the_delivery_still_completes_at_the_delivery() {
    let fixture = Fixture::new("delivery-last");
    let state = fixture.open();
    seed_grant(&state, "gr_0000000000000005", 5);
    seed_grant(&state, "gr_0000000000000006", 6);
    let (bound, digest) = render_bound(
        &state,
        &request_with(vec![selected("#5", &[]), selected("#6", &[])]),
    );
    let caps = ConcurrencyCaps {
        global: 4,
        per_repository: 1,
        per_harness: 2,
    };
    let plan = submission_plan(
        &state,
        "ik_152-delivery-last",
        &bound,
        &digest,
        &[("#5", "gr_0000000000000005"), ("#6", "gr_0000000000000006")],
        caps,
    );
    let (submission, items) = state.submit_queue_run(&plan).expect("submit");
    let run5 = item_of(&items, 5)
        .instance_id
        .clone()
        .expect("issue 5 admitted");
    println!("BEFORE completing advance: {}", run_status(&state, &run5));
    assert_eq!(read_ownership(&fixture.db()), vec![(5, run5.clone())]);
    record_delivery(&state, &run5, HEAD_A);

    // ONE reconciliation: the delivery IS the run's last committed spine
    // step, so completion (and the freed slot) stays exactly where it was
    // before the #152 rule.
    let delivery = reconcile(&state, &run5, true).expect("a fresh verified delivery");
    assert_eq!(
        run_status(&state, &run5),
        "done",
        "a plan that ends at the delivery completes at the delivery"
    );
    let after = submission_items(&state, &submission.submission_id);
    assert_eq!(item_of(&after, 6).status, "admitted");
    let run6 = item_of(&after, 6)
        .instance_id
        .clone()
        .expect("issue 6 admitted");
    let advances = state
        .queue_advance_rows(&submission.submission_id)
        .expect("advances");
    assert_eq!(advances.len(), 1);
    assert_eq!(advances[0].delivered_ordinal, delivery.item_ordinal);
    assert_eq!(advances[0].next_instance_id.as_deref(), Some(run6.as_str()));
    assert_eq!(advances[0].reason, None);

    println!("AFTER completing advance: {}", run_status(&state, &run5));
    assert_eq!(read_ownership(&fixture.db()), vec![(6, run6.clone())]);
    // A fresh submission for the SAME issue is admitted on its own merits.
    let request = request_with(vec![selected("#5", &[])]);
    let (bound, digest) = render_bound(&state, &request);
    let fresh_plan = submission_plan(
        &state,
        "ik_146-fresh-completed",
        &bound,
        &digest,
        &[("#5", "gr_0000000000000005")],
        request.caps,
    );
    let (_, fresh) = state
        .submit_queue_run(&fresh_plan)
        .expect("fresh submission");
    println!("FRESH submission: {fresh:?}");
    assert_eq!(fresh[0].status, "admitted");
    let new_run = fresh[0].instance_id.clone().expect("fresh run");
    assert_ne!(new_run, run5);

    // Reconciliation and release of the old terminal run must not steal its
    // successor's ownership, nor turn the completed run back into a live one.
    reconcile(&state, &run5, true);
    let released = state
        .release_run(
            &run5,
            "completed predecessor",
            "ik_146-release-done",
            &canter::time::rfc3339_now(),
        )
        .expect("done runs can be released");
    println!("RELEASE completed run: {released:?}");
    assert!(!released.ownership_freed);
    assert_eq!(released.run.status, "done");
    assert_eq!(read_ownership(&fixture.db()), vec![(5, new_run), (6, run6)]);
}

#[test]
fn release_frees_an_invalidated_owner_without_state_forgery() {
    let fixture = Fixture::new("release-invalidated");
    let state = fixture.open();
    seed_grant(&state, "gr_0000000000000005", 5);
    let request = request_with(vec![selected("#5", &[])]);
    let (bound, digest) = render_bound(&state, &request);
    let plan = submission_plan(
        &state,
        "ik_146-invalidated",
        &bound,
        &digest,
        &[("#5", "gr_0000000000000005")],
        request.caps,
    );
    let (_, items) = state.submit_queue_run(&plan).expect("submit");
    let run = items[0].instance_id.clone().expect("admitted run");
    // The product's epoch rotation invalidates the run; no SQL writes or
    // operator-assigned status is needed to reach this terminal owner.
    state.rotate_epoch("security_rotation").expect("rotate");
    state.invalidate_grants_below_current().expect("invalidate");
    assert_eq!(run_status(&state, &run), "invalidated");
    println!("BEFORE release: invalidated");
    assert_eq!(read_ownership(&fixture.db()), vec![(5, run.clone())]);
    let released = state
        .release_run(
            &run,
            "epoch invalidated predecessor",
            "ik_146-release-invalidated",
            &canter::time::rfc3339_now(),
        )
        .expect("terminal owner can be released");
    println!("RELEASE: {released:?}");
    assert!(released.ownership_freed);
    assert_eq!(released.run.status, "invalidated");
    println!("AFTER release: invalidated");
    assert!(read_ownership(&fixture.db()).is_empty());
}

// ---------------------------------------------------------------------------
// Live end-to-end: the real daemon advances the queue through its own
// mutation path with no conductor in the loop
// ---------------------------------------------------------------------------

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "hf-queue-advance-96-live-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
}

/// Runtime-assembled idempotency key (the tracked file never carries a
/// `key = "<literal>"` shape the secret scanners read as an API key).
fn idem_key(stem: &str) -> String {
    format!("ik_96-{stem}-{}", std::process::id())
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

    fn spawn(&self) -> Child {
        std::fs::create_dir_all(&self.state_dir).expect("state home");
        // Issue #225: the publish path COMPUTES the hosted CI conclusion at the
        // certified head through the forge CLI, so the fixture provides the
        // deterministic green check its own fixture head carries.
        let bin = self.dir.join("fakebin");
        std::fs::create_dir_all(&bin).expect("fakebin dir");
        let gh = bin.join("gh");
        std::fs::write(
            &gh,
            "#!/bin/sh\ncase \"$1\" in\n  run)\n    case \"$2\" in\n      list) printf '[{\"databaseId\":4242,\"workflowName\":\"ci\",\"status\":\"completed\",\"conclusion\":\"success\"}]'; exit 0 ;;\n    esac ;;\nesac\nexit 1\n",
        )
        .expect("fake gh");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&gh, std::fs::Permissions::from_mode(0o755))
                .expect("chmod +x");
        }
        Command::new(env!("CARGO_BIN_EXE_canter"))
            .args(["daemon", "run", "--socket"])
            .arg(&self.socket)
            .env(
                "PATH",
                format!(
                    "{}:{}",
                    bin.display(),
                    std::env::var("PATH").unwrap_or_default()
                ),
            )
            .env("XDG_STATE_HOME", &self.state_dir)
            .env("HOME", &self.dir)
            .stdout(Stdio::null())
            .stderr(Stdio::from(
                std::fs::File::create(self.dir.join("daemon.stderr.log")).expect("stderr log"),
            ))
            .spawn()
            .expect("spawn daemon")
    }

    /// The same daemon, spawned with `path` PREPENDED to the child's `PATH`:
    /// the self-dispatching review step's reviewer role runs the harness
    /// executable the effect resolves from the daemon's own environment, so
    /// the witness puts its fake reviewer where that resolution looks.
    fn spawn_with_path(&self, path: &Path) -> Child {
        std::fs::create_dir_all(&self.state_dir).expect("state home");
        let mut child_path = path.to_string_lossy().to_string();
        if let Ok(existing) = std::env::var("PATH") {
            child_path.push(':');
            child_path.push_str(&existing);
        }
        Command::new(env!("CARGO_BIN_EXE_canter"))
            .args(["daemon", "run", "--socket"])
            .arg(&self.socket)
            .env("XDG_STATE_HOME", &self.state_dir)
            .env("HOME", &self.dir)
            .env("PATH", child_path)
            .stdout(Stdio::null())
            .stderr(Stdio::from(
                std::fs::File::create(self.dir.join("daemon.stderr.log")).expect("stderr log"),
            ))
            .spawn()
            .expect("spawn daemon")
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
        std::thread::sleep(Duration::from_millis(50));
    }
    let stderr = std::fs::read_to_string(fixture.dir.join("daemon.stderr.log")).unwrap_or_default();
    panic!(
        "daemon did not become ready on {}; stderr:
{stderr}",
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

fn shutdown(mut daemon: Child) {
    let _ = daemon.kill();
    let deadline = Instant::now() + Duration::from_secs(10);
    while daemon.try_wait().expect("try_wait").is_none() {
        assert!(Instant::now() < deadline, "daemon did not exit");
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn fresh_id(seed: u64) -> String {
    format!("{seed:016x}")
}

fn live_item(result: &Val, number: i64) -> Val {
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

/// The `apply` params that run ONE step of one run through the real mutation
/// surface: a plan whose single step names the effect, the grant the run was
/// admitted against, the exact observed head/base and the topology the daemon
/// requires.
#[allow(clippy::too_many_arguments)]
fn step_apply_params(
    seed: u64,
    fixture: &DaemonFixture,
    run: &str,
    number: i64,
    grant_id: &str,
    step: &str,
    kind: &str,
    step_params: Val,
    feature_head: &str,
    integration_base: &str,
) -> Val {
    let seed_doc = object(vec![
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
        (
            "steps",
            Val::Arr(vec![object(vec![
                ("id", string(step)),
                ("kind", string(kind)),
                ("params", step_params),
            ])]),
        ),
    ]);
    let digest = canter::canonical::sha256_hex(&canter::canonical::canonical_bytes(&seed_doc));
    let plan_id = format!("hf_plan_{}", &digest[..16]);
    let mut map = match seed_doc {
        Val::Obj(map) => map,
        _ => unreachable!(),
    };
    map.insert("plan_id".to_string(), string(&plan_id));
    let plan = Val::Obj(map);
    object(vec![
        ("plan", plan),
        ("step", string(step)),
        ("grant_id", string(grant_id)),
        ("instance_id", string(run)),
        (
            "observed",
            object(vec![
                ("issue_revision", string(REV_A)),
                ("policy_hash", string(POLICY_HASH)),
                ("feature_head", string(feature_head)),
                ("integration_base", string(integration_base)),
            ]),
        ),
        (
            "topology",
            object(vec![
                ("integration_branch", string("staging")),
                (
                    "worktrees_root",
                    string(&format!("{}/worktrees", fixture.dir.display())),
                ),
                (
                    "integration_repo",
                    string(&format!("{}/repo", fixture.dir.display())),
                ),
            ]),
        ),
        (
            "idempotency_key",
            string(&idem_key(&format!("apply-{seed}"))),
        ),
    ])
}

/// The `apply` params that record the delivery of one run through the real
/// mutation surface: the reviewed `pass` verdict with its checks.
fn delivery_apply_params(
    seed: u64,
    fixture: &DaemonFixture,
    run: &str,
    number: i64,
    grant_id: &str,
) -> Val {
    step_apply_params(
        seed,
        fixture,
        run,
        number,
        grant_id,
        "r1",
        "review_evidence",
        review_params(),
        HEAD_A,
        BASE_A,
    )
}

#[test]
fn the_real_daemon_advances_the_queue_to_the_next_issue_without_another_request() {
    let fixture = DaemonFixture::new("auto");
    let (bound, digest) = {
        let state = fixture.seed();
        seed_grant(&state, "gr_0000000000000005", 5);
        seed_grant(&state, "gr_0000000000000006", 6);
        render_bound(
            &state,
            &request_with(vec![selected("#5", &[]), selected("#6", &[])]),
        )
    };
    let daemon = fixture.spawn();
    wait_ready(&fixture);

    let caps = ConcurrencyCaps {
        global: 4,
        per_repository: 1,
        per_harness: 2,
    };
    let submitted = rpc_ok(
        &fixture.socket,
        &fresh_id(1),
        "queue.submit",
        Some(submit_params_doc(
            &idem_key("auto-submit"),
            &bound,
            &digest,
            &[("#5", "gr_0000000000000005"), ("#6", "gr_0000000000000006")],
            caps,
            5,
            60,
        )),
    );
    let submission_id = submitted
        .get("submission_id")
        .and_then(Val::as_str)
        .expect("submission id")
        .to_string();
    let run5 = live_item(&submitted, 5)
        .get("instance_id")
        .and_then(Val::as_str)
        .expect("issue 5 admitted")
        .to_string();
    assert_eq!(
        live_item(&submitted, 6).get("status").and_then(Val::as_str),
        Some("waiting")
    );

    // The delivery is recorded through the daemon's OWN mutation path.
    let applied = rpc_ok(
        &fixture.socket,
        &fresh_id(2),
        "apply",
        Some(delivery_apply_params(
            2,
            &fixture,
            &run5,
            5,
            "gr_0000000000000005",
        )),
    );
    assert!(
        applied.get("evidence_id").and_then(Val::as_str).is_some(),
        "the review evidence committed: {}",
        canter::canonical::canonical_text(&applied)
    );

    // NO further client request: the daemon's own reconciliation (event wake
    // or the bounded timer fallback) admits the next issue.
    let started = Instant::now();
    let mut last_progress = started;
    let mut progress = String::new();
    let mut id = 100u64;
    let status = loop {
        id += 1;
        let doc = rpc_ok(
            &fixture.socket,
            &fresh_id(id),
            "queue.status",
            Some(object(vec![("submission_id", string(&submission_id))])),
        );
        let advanced = live_item(&doc, 6)
            .get("status")
            .and_then(Val::as_str)
            .unwrap_or_default()
            .to_string();
        if advanced == "admitted" {
            break doc;
        }
        if advanced != progress {
            progress = advanced.clone();
            last_progress = Instant::now();
        }
        let stalled = last_progress.elapsed().as_secs();
        assert!(
            stalled < NO_PROGRESS_SECS,
            "the queue never advanced to issue 6: no progress for {stalled}s of {}s waited \
             (status {advanced:?}); last: {}",
            started.elapsed().as_secs(),
            canter::canonical::canonical_text(&doc)
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    let run6 = live_item(&status, 6)
        .get("instance_id")
        .and_then(Val::as_str)
        .expect("issue 6 admitted")
        .to_string();
    assert_ne!(run6, run5);
    let advance = status.get("advance").expect("advance block");
    assert_eq!(advance.get("consumed").and_then(Val::as_int), Some(1));
    assert_eq!(advance.get("dispatched").and_then(Val::as_int), Some(1));
    assert_eq!(
        advance.get("cursor_ordinal").and_then(Val::as_int),
        Some(0),
        "issue 5 is the first membership item"
    );
    let rows = advance
        .get("rows")
        .and_then(Val::as_array)
        .expect("advance rows");
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].get("delivered_head").and_then(Val::as_str),
        Some(HEAD_A)
    );
    assert_eq!(
        rows[0].get("next_instance_id").and_then(Val::as_str),
        Some(run6.as_str())
    );
    assert!(matches!(rows[0].get("reason"), Some(Val::Null)));

    // The dispatched issue is now supervised by the daemon (the queue keeps
    // continuing) and the run it delivered reads as the recorded state.
    let supervised = rpc_ok(
        &fixture.socket,
        &fresh_id(200),
        "supervision.status",
        Some(supervision::status_params(&run6)),
    );
    assert_eq!(
        supervised
            .get("supervision")
            .and_then(|supervision| supervision.get("desired"))
            .and_then(Val::as_str),
        Some("armed")
    );
    // Duplicate-event leg on the live surface: many further ticks while the
    // delivery stays verified never dispatch a second run.
    std::thread::sleep(Duration::from_secs(6));
    let settled = rpc_ok(
        &fixture.socket,
        &fresh_id(300),
        "queue.status",
        Some(object(vec![("submission_id", string(&submission_id))])),
    );
    assert_eq!(
        settled
            .get("advance")
            .and_then(|advance| advance.get("consumed"))
            .and_then(Val::as_int),
        Some(1)
    );
    assert_eq!(
        live_item(&settled, 6)
            .get("instance_id")
            .and_then(Val::as_str),
        Some(run6.as_str())
    );
    // No harness/process effect exists anywhere in this loop.
    let actions = rpc_ok(
        &fixture.socket,
        &fresh_id(400),
        "journal.tail",
        Some(object(vec![("limit", integer(200))])),
    );
    let text = canter::canonical::canonical_text(&actions);
    for banned in ["mutate.harness_start", "mutate.prompt", "mutate.merge"] {
        assert!(
            !text.contains(banned),
            "continuation must never produce {banned}: {text}"
        );
    }
    let log = std::fs::read_to_string(fixture.daemon_log()).unwrap_or_default();
    assert!(
        !log.contains("supervision.continue") && !log.contains("spawn"),
        "no continuation effect may be logged: {log}"
    );

    // Issue #146: completion frees the issue, not just its capacity slot.
    println!("AFTER daemon completion:");
    assert_eq!(read_ownership(&fixture.db()), vec![(6, run6.clone())]);
    let (bound, digest) = render_bound(&fixture.seed(), &request_with(vec![selected("#5", &[])]));
    let fresh = rpc_ok(
        &fixture.socket,
        &fresh_id(401),
        "queue.submit",
        Some(submit_params_doc(
            &idem_key("fresh-completed"),
            &bound,
            &digest,
            &[("#5", "gr_0000000000000005")],
            ConcurrencyCaps {
                global: 4,
                per_repository: 2,
                per_harness: 2,
            },
            5,
            60,
        )),
    );
    println!(
        "FRESH queue.submit: {}",
        canter::canonical::canonical_text(&fresh)
    );
    assert_eq!(
        live_item(&fresh, 5).get("status").and_then(Val::as_str),
        Some("admitted")
    );
    assert_ne!(
        live_item(&fresh, 5)
            .get("instance_id")
            .and_then(Val::as_str),
        Some(run5.as_str())
    );
    shutdown(daemon);
}

// ---------------------------------------------------------------------------
// Live end-to-end (issue #152): the delivering run stays live for its own
// committed merge and cleanup, and the queue continues only after them
// ---------------------------------------------------------------------------

/// One issue grant with an explicit capability set (the #152 fixture needs
/// the `cleanup` capability the queue spine's last step requires).
fn seed_grant_with_caps(state: &State, grant_id: &str, number: i64, caps: &[&str]) {
    let epoch = state.current_epoch().expect("epoch");
    let mut doc = grant_doc_at(grant_id, number, REV_A, epoch);
    match &mut doc {
        Val::Obj(map) => {
            map.insert(
                "caps".to_string(),
                Val::Arr(caps.iter().map(|cap| string(cap)).collect()),
            );
        }
        _ => unreachable!("grant document"),
    }
    state.issue_grant(&doc).expect("issue grant");
}

/// Run one git command in `dir`, asserting success. Disposable LOCAL
/// repositories only — never a network remote.
fn git(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .args(args)
        .current_dir(dir)
        // #226: copy nothing from the host's shared git templates.
        .env("GIT_TEMPLATE_DIR", "")
        .env("GIT_AUTHOR_NAME", "canter test")
        .env("GIT_AUTHOR_EMAIL", "test@example.invalid")
        .env("GIT_COMMITTER_NAME", "canter test")
        .env("GIT_COMMITTER_EMAIL", "test@example.invalid")
        .output()
        .expect("spawn git");
    assert!(
        out.status.success(),
        "git {args:?} in {} failed: {}",
        dir.display(),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// A disposable integration repo, local bare origin and the run's lane
/// worktree. The lane branch sits AT the published integration head, so the
/// reviewed base is current and the branch is provably merged: the merge step
/// is a read-only REHEARSAL and cleanup may only delete a verified branch.
fn repos_with_lane_branch(fixture: &DaemonFixture) -> String {
    let repo = fixture.dir.join("repo");
    std::fs::create_dir_all(&repo).expect("repo dir");
    git(&repo, &["init", "-q", "-b", "staging"]);
    git(&repo, &["config", "user.name", "canter test"]);
    git(&repo, &["config", "user.email", "test@example.invalid"]);
    std::fs::write(repo.join("base.txt"), "base\n").expect("base file");
    git(&repo, &["add", "base.txt"]);
    git(&repo, &["commit", "-q", "-m", "fixture base"]);
    let head = git(&repo, &["rev-parse", "HEAD"]);
    // The merge step certifies origin's published ref, not merely the
    // checkout's local head. Keep that prerequisite real and network-free.
    git(&fixture.dir, &["init", "-q", "--bare", "origin.git"]);
    git(&repo, &["remote", "add", "origin", "../origin.git"]);
    git(&repo, &["push", "-q", "origin", "staging"]);
    git(&repo, &["branch", "issue-5"]);
    std::fs::create_dir_all(fixture.dir.join("worktrees")).expect("worktrees root");
    git(
        &repo,
        &[
            "worktree",
            "add",
            &format!("{}/worktrees/issues-5", fixture.dir.display()),
            "issue-5",
        ],
    );
    head
}

/// ONE recorded cursor sample of a supervised run, read on the product's own
/// read-only surface: `(run status, next step, next step kind, attempts)`.
fn cursor_sample(
    socket: &Path,
    run: &str,
    id: u64,
) -> (String, String, String, Vec<(String, String)>) {
    let doc = rpc_ok(
        socket,
        &fresh_id(id),
        "supervision.status",
        Some(supervision::status_params(run)),
    );
    let attempts = doc
        .get("cursor")
        .and_then(|cursor| cursor.get("attempts"))
        .and_then(Val::as_array)
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|attempt| {
            (
                attempt
                    .get("step")
                    .and_then(Val::as_str)
                    .unwrap_or("")
                    .to_string(),
                attempt
                    .get("status")
                    .and_then(Val::as_str)
                    .unwrap_or("")
                    .to_string(),
            )
        })
        .collect();
    (
        doc.get("run")
            .and_then(|run| run.get("status"))
            .and_then(Val::as_str)
            .unwrap_or("unknown")
            .to_string(),
        doc.get("cursor")
            .and_then(|cursor| cursor.get("next_step"))
            .and_then(Val::as_str)
            .unwrap_or("")
            .to_string(),
        doc.get("cursor")
            .and_then(|cursor| cursor.get("next_step_kind"))
            .and_then(Val::as_str)
            .unwrap_or("")
            .to_string(),
        attempts,
    )
}

fn achieved(attempts: &[(String, String)], step: &str) -> bool {
    attempts
        .iter()
        .any(|(id, status)| id == step && status == "succeeded")
}

/// Issue #152, supervisor half: the DRIVER — not an operator `apply` — drives
/// the delivering run's own committed merge and then its cleanup, and the run
/// completes only after that last committed step. No operator dispatch of m1
/// or c1 exists in this test.
#[test]
fn the_supervisor_itself_drives_the_committed_merge_and_cleanup_to_the_last_step() {
    let fixture = DaemonFixture::new("drive");
    let head = repos_with_lane_branch(&fixture);
    let caps_for_tail = tail_boundary_caps();
    let tail_caps: Vec<&str> = caps_for_tail.iter().map(|cap| cap.as_str()).collect();
    let (bound, digest) = {
        let state = fixture.seed();
        seed_grant_with_caps(&state, "gr_0000000000000005", 5, &tail_caps);
        seed_grant_with_caps(&state, "gr_0000000000000006", 6, &tail_caps);
        let mut request = request_with(vec![selected("#5", &[]), selected("#6", &[])]);
        request.steps = committed_tail_steps();
        request.boundary.caps = tail_boundary_caps();
        render_bound(&state, &request)
    };
    let daemon = fixture.spawn();
    wait_ready(&fixture);
    let caps = ConcurrencyCaps {
        global: 4,
        per_repository: 1,
        per_harness: 2,
    };
    let submitted = rpc_ok(
        &fixture.socket,
        &fresh_id(1),
        "queue.submit",
        Some(submit_params_doc(
            &idem_key("drive-submit"),
            &bound,
            &digest,
            &[("#5", "gr_0000000000000005"), ("#6", "gr_0000000000000006")],
            caps,
            5,
            60,
        )),
    );
    let submission_id = submitted
        .get("submission_id")
        .and_then(Val::as_str)
        .expect("submission id")
        .to_string();
    let run5 = live_item(&submitted, 5)
        .get("instance_id")
        .and_then(Val::as_str)
        .expect("issue 5 admitted")
        .to_string();

    // The reviewed delivery is recorded through the daemon's own mutation
    // path (the reviewer's own record — NOT a continuation dispatch).
    let applied = rpc_ok(
        &fixture.socket,
        &fresh_id(2),
        "apply",
        Some(step_apply_params(
            2,
            &fixture,
            &run5,
            5,
            "gr_0000000000000005",
            "r1",
            "review_evidence",
            review_params(),
            &head,
            &head,
        )),
    );
    assert!(
        applied.get("evidence_id").and_then(Val::as_str).is_some(),
        "the review evidence committed: {}",
        canter::canonical::canonical_text(&applied)
    );

    // From here on NO client dispatch of m1/c1 happens: the driver owns the
    // committed tail. Poll the product's own status surface (bounded, no
    // fixed sleep) until the driver has driven the WHOLE tail, and record
    // every sample: the driver may finish both tail steps between two
    // samples, so the ORDER of its dispatches and of the recorded attempts —
    // not one transient cursor value — is what proves the progression.
    let mut timeline: Vec<String> = Vec::new();
    let mut id = 700u64;
    let started = Instant::now();
    let mut last_progress = started;
    let mut progress = String::new();
    let (next_step, next_kind, attempts) = loop {
        id += 1;
        let (status, step, kind, attempts) = cursor_sample(&fixture.socket, &run5, id);
        timeline.push(format!(
            "t{} status={status} next={step}/{kind} attempts={attempts:?}",
            id - 700
        ));
        if status == "done" {
            break (step, kind, attempts);
        }
        let observed = format!("{status}/{step}/{kind}/{attempts:?}");
        if observed != progress {
            progress = observed;
            last_progress = Instant::now();
        }
        let stalled = last_progress.elapsed().as_secs();
        assert!(
            stalled < NO_PROGRESS_SECS,
            "the driver never drove the run's committed tail to its last step: no progress for \
             {stalled}s of {}s waited; observed: {timeline:?}",
            started.elapsed().as_secs()
        );
        std::thread::sleep(Duration::from_millis(250));
    };
    eprintln!("SUPERVISOR_TAIL_TIMELINE={timeline:?}");
    assert!(
        achieved(&attempts, "m1"),
        "the driver's merge attempt must be recorded achieved: {attempts:?}"
    );
    assert!(
        achieved(&attempts, "c1"),
        "the driver's cleanup attempt must be recorded achieved: {attempts:?}"
    );
    // The merge was achieved BEFORE the cleanup was attempted: the ledger is
    // in claim order.
    let merge_at = attempts
        .iter()
        .position(|(step, _)| step == "m1")
        .expect("m1 in the ledger");
    let cleanup_at = attempts
        .iter()
        .position(|(step, _)| step == "c1")
        .expect("c1 in the ledger");
    assert!(
        merge_at < cleanup_at,
        "the tail runs IN ORDER (merge, then cleanup): {attempts:?}"
    );
    // The run completed only after its LAST committed step: the frontier is
    // EXHAUSTED (nothing owed), never parked on the merge.
    assert_ne!(
        next_step, "m1",
        "the frontier must not still be the merge: {next_step}/{next_kind}"
    );
    assert_eq!(
        next_step, "",
        "a completed run owes nothing: the committed spine is fully achieved"
    );
    assert_eq!(next_kind, "");
    // The daemon's OWN log names the driver's dispatch of the merge step and
    // never a refusal of it.
    let log = std::fs::read_to_string(fixture.daemon_log()).unwrap_or_default();
    assert!(
        log.contains("dispatched step m1"),
        "the driver's own dispatch record must name the merge step:\n{log}"
    );
    // The driver drove the tail IN ORDER: its own records name the merge
    // first and the cleanup after it (the frontier advanced past the merge).
    let merge_dispatch = log.find("dispatched step m1").expect("merge dispatch");
    let cleanup_dispatch = log
        .find("dispatched step c1")
        .unwrap_or_else(|| panic!("the driver must dispatch the cleanup too:\n{log}"));
    assert!(
        merge_dispatch < cleanup_dispatch,
        "the driver's own dispatch records must be ordered merge -> cleanup:\n{log}"
    );
    assert!(
        !log.contains("step m1: refusal.") && !log.contains("supervision.dispatch_refused"),
        "no refusal may stand between the driver and its committed tail:\n{log}"
    );

    // The freed slot admits the waiting issue only now — after the run reached
    // its last committed step.
    let queue = rpc_ok(
        &fixture.socket,
        &fresh_id(900),
        "queue.status",
        Some(object(vec![("submission_id", string(&submission_id))])),
    );
    assert_eq!(
        live_item(&queue, 6).get("status").and_then(Val::as_str),
        Some("admitted"),
        "the completion after the last committed step frees the slot: {}",
        canter::canonical::canonical_text(&queue)
    );
    assert!(
        !fixture.dir.join("worktrees/issues-5").exists(),
        "the driver's cleanup removed the run's own worktree"
    );
    assert_eq!(
        git(&fixture.dir.join("repo"), &["rev-parse", "staging"]),
        head,
        "a delivery with no content beyond the base publishes nothing"
    );
    assert_eq!(
        git(&fixture.dir.join("origin.git"), &["rev-parse", "staging"]),
        head,
        "the published integration head is unchanged (nothing to land)"
    );
    shutdown(daemon);
}

// ---------------------------------------------------------------------------
// Issue #272: a fix round's delivered head is re-bound by the run's OWN
// machinery — the bounded re-collect of the repair leg's checkout and its own
// review re-entry — with ZERO operator step-dispatches
// ---------------------------------------------------------------------------

/// The fake reviewer harness of the fix-rebind witness: it plays the run's
/// reviewer leg and its verdict is HEAD-AWARE — it records `fail` at the head
/// the run's evidence already stands at (the recorded pre-fix head, written
/// into its own read-back file by the witness), and `pass` at any OTHER head
/// the brief names.
///
/// That is what makes the witness discriminating: the run can only reach its
/// tail if the review really re-entered at the head its own handoff delivered,
/// because a re-review of the unchanged head records the SAME FAIL.
fn write_fake_head_aware_reviewer(fixture: &DaemonFixture) -> PathBuf {
    let bin = fixture.dir.join("fakebin");
    std::fs::create_dir_all(&bin).expect("fake bin dir");
    let path = bin.join("hermes");
    std::fs::write(
        &path,
        r#"#!/bin/sh
set -eu
PATH=/usr/bin:/bin
export PATH
last=""
for arg in "$@"; do last="$arg"; done
flat=$(printf '%s' "$last" | tr -d '\n')
verdict_path=$(printf '%s' "$flat" | sed -n 's/.*"\([^"]*\.json\)".*/\1/p')
test -n "$verdict_path"
head=$(printf '%s' "$flat" | sed -n 's/.*"feature_head":"\([0-9a-f]\{40\}\)".*/\1/p')
base=$(printf '%s' "$flat" | sed -n 's/.*"integration_base":"\([0-9a-f]\{40\}\)".*/\1/p')
test -n "$head"
test -n "$base"
test -f "$HOME/reviewed-head"
printf '%s\n' "$head" >> "$HOME/review-heads.txt"
mkdir -p "$(dirname "$verdict_path")"
if [ "$head" = "$(cat "$HOME/reviewed-head")" ]; then
  verdict=fail
  checks='[{"name":"exact-head-review","status":"failed"}]'
else
  verdict=pass
  checks='[{"name":"exact-head-review","status":"passed"}]'
fi
printf '%s' "{\"schema\":\"hf-evidence/v1\",\"feature_head\":\"$head\",\"integration_base\":\"$base\",\"verdict\":\"$verdict\",\"checks\":$checks}" > "$verdict_path"
"#,
    )
    .expect("write fake reviewer");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = std::fs::metadata(&path).expect("metadata").permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&path, permissions).expect("chmod");
    }
    bin
}

/// The repair leg's OWN lane checkout of the fix-rebind witness — the
/// `(role, round)` derivation the engine creates it by, never a literal.
fn fix_rebind_lane(fixture: &DaemonFixture) -> PathBuf {
    fixture
        .dir
        .join("worktrees")
        .join(canter::lane::lane_checkout(5, "implementer", 2))
}

/// The committed spine of the fix-rebind witness: the run's own read step, the
/// harness step that binds its implementer session, its OWN collection, the
/// self-dispatching review step, and the committed merge TAIL the run may only
/// reach behind a verified delivery.
fn fix_rebind_spine() -> Vec<qp::PlannedStep> {
    let mut steps = self_dispatch_spine();
    steps.push(qp::PlannedStep {
        id: "m1".to_string(),
        kind: "merge".to_string(),
        params: Some(object(vec![
            ("branch", string("issue-5")),
            ("merge_policy", string("squash")),
        ])),
    });
    steps
}

/// Record ONE `apply` claim of a run with the run's OWN dispatch material
/// (topology + admission) and its recorded RESULT, through the same durable
/// writers the apply path uses — the handoff facts `run_control`'s own
/// witnesses read back (`seed_fix_round_response`).
///
/// This is the ONLY place the witness stands in for an effect: the fix round's
/// own prompt cannot be delivered in a HEADLESS lane (the fix leg inherits the
/// implementer leg's profile, which carries no provider/model pair outside its
/// own `harness_start` dispatch), so the handoff it produces is recorded here
/// and everything the run does with it is the real machinery.
fn seed_fix_handoff_row(
    fixture: &DaemonFixture,
    state: &State,
    run: &str,
    step: &str,
    kind: &str,
    seed: u64,
    result: Val,
) -> String {
    let key = idem_key(&format!("seeded-{step}-{seed}"));
    let steps: Vec<Val> = fix_rebind_spine()
        .iter()
        .map(|step| object(vec![("id", string(&step.id)), ("kind", string(&step.kind))]))
        .collect();
    let line = canter::canonical::canonical_text(&object(vec![
        ("schema", string("hf-rpc-request/v1")),
        ("id", string(&format!("seeded-{seed}"))),
        ("method", string("apply")),
        (
            "params",
            object(vec![
                ("idempotency_key", string(&key)),
                ("instance_id", string(run)),
                ("step", string(step)),
                (
                    "plan",
                    object(vec![
                        ("steps", Val::Arr(steps)),
                        ("repository", string(REPO)),
                    ]),
                ),
                (
                    "topology",
                    dispatch_bundle(fixture)
                        .get("topology")
                        .cloned()
                        .unwrap_or(Val::Null),
                ),
                (
                    "flags",
                    object(vec![(
                        "admission",
                        dispatch_bundle(fixture)
                            .get("admission")
                            .cloned()
                            .unwrap_or(Val::Null),
                    )]),
                ),
            ]),
        ),
    ]));
    let (claim, _) = state
        .journal_intent(
            &format!("mutate.{kind}"),
            &format!("{REPO}:{run}:{step}"),
            &key,
            &format!("request-{seed:016x}"),
            "apply",
            None,
            None,
            &line,
        )
        .expect("step intent");
    assert!(
        matches!(claim, canter::state::ClaimAttempt::Claimed),
        "the seeded claim must be fresh: {claim:?}"
    );
    let outcome = canter::canonical::canonical_text(&object(vec![("status", string("succeeded"))]));
    let response = canter::canonical::canonical_text(&object(vec![
        ("ok", canter::value::bool_(true)),
        ("result", result),
    ]));
    state
        .resolve_run_step_claim(
            &key,
            "apply",
            &outcome,
            &response,
            run,
            step,
            &canter::time::rfc3339_now(),
        )
        .expect("step outcome");
    key
}

/// Every durable `apply` claim of ONE run, `(key, request_line)`, in claim
/// order — the ledger a dispatch witness reads read-only.
fn apply_claims(db: &Path, run: &str) -> Vec<(String, String)> {
    let conn =
        rusqlite::Connection::open_with_flags(db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("read-only connection");
    let mut statement = conn
        .prepare("SELECT key, request_line FROM idempotency WHERE method = 'apply' ORDER BY rowid")
        .expect("prepare apply read");
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .expect("read apply rows")
        .collect::<Result<Vec<_>, _>>()
        .expect("apply rows");
    rows.into_iter()
        .filter(|(_, line)| line.contains(run))
        .collect()
}

/// Every hash-chained journal record of ONE run, `(action, target)`, oldest
/// first — the audit rows a control witness cites.
fn audit_rows(db: &Path, run: &str) -> Vec<(String, String)> {
    let conn =
        rusqlite::Connection::open_with_flags(db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("read-only connection");
    let mut statement = conn
        .prepare("SELECT action, target FROM audit ORDER BY seq")
        .expect("prepare audit read");
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .expect("read audit rows")
        .collect::<Result<Vec<_>, _>>()
        .expect("audit rows");
    rows.into_iter()
        .filter(|(_, target)| target.contains(run))
        .collect()
}

/// Issue #272 (AC1–AC4). A run whose own fix round delivered a moved head
/// re-enters review AT THAT HEAD and advances to its committed tail through the
/// run's OWN machinery: the driver re-collects the repair leg's own recorded
/// checkout — the certificate binding is re-established by the run's own
/// collection — the review re-entry runs on the run's own bounded
/// re-evaluation, the head-aware reviewer's PASS is RECORDED, and the merge
/// tail is dispatched. No operator step is dispatched anywhere: every `apply`
/// claim of the run is the driver's own.
///
/// The reviewer is head-aware on purpose: it records the SAME `fail` at the
/// head the run's evidence already stands at, so a re-review of an unchanged
/// head can never complete the run.
#[test]
fn a_fix_rounds_delivered_head_is_re_bound_by_the_runs_own_machinery() {
    let fixture = DaemonFixture::new("fix-rebind");
    let base = repos_with_lane_branch(&fixture);
    let repo = fixture.dir.join("repo");
    let lane = fixture.dir.join("worktrees/issues-5");
    std::fs::write(lane.join("delivered.txt"), "the reviewed delivery\n").expect("write");
    git(&lane, &["add", "delivered.txt"]);
    git(
        &lane,
        &["commit", "-q", "-m", "the lane delivery (synthetic)"],
    );
    let reviewed = git(&lane, &["rev-parse", "HEAD"]);
    assert_ne!(reviewed, base, "the lane delivered content");
    // The repair leg's OWN checkout (issue #256): the engine creates it as a
    // DETACHED `worktree add` at the certified head, and the leg lands its
    // repair there — the state the run's own collector re-observes.
    let fix_lane = fix_rebind_lane(&fixture);
    let repair_branch = canter::lane::lane_checkout(5, "implementer", 2);
    git(
        &repo,
        &[
            "worktree",
            "add",
            "--detach",
            &fix_lane.display().to_string(),
            &reviewed,
        ],
    );
    git(&fix_lane, &["checkout", "-q", "-b", &repair_branch]);
    std::fs::write(fix_lane.join("repair.txt"), "the repair\n").expect("write repair");
    git(&fix_lane, &["add", "repair.txt"]);
    git(
        &fix_lane,
        &["commit", "-q", "-m", "the fix leg's repair (synthetic)"],
    );
    let delivered = git(&fix_lane, &["rev-parse", "HEAD"]);
    assert_ne!(delivered, reviewed, "the repair leg delivered a moved head");
    // The repair reached the run's OWN feature branch — the instruction asks
    // the leg to push it there, and the push is a fast-forward: the run's lane
    // checkout holds the delivered head, which is the head a review re-enters
    // at (a reviewer is never started on a moved checkout).
    git(&lane, &["merge", "--ff-only", &delivered]);
    assert_eq!(
        git(&lane, &["rev-parse", "HEAD"]),
        delivered,
        "the delivered head is on the run's own feature branch"
    );
    // The reviewer's own read-back file: the head its recorded FAIL stands at.
    std::fs::write(fixture.dir.join("reviewed-head"), &reviewed).expect("reviewed head");
    let fakebin = write_fake_head_aware_reviewer(&fixture);

    // Admission and the recorded rows of the FAIL handoff — written through the
    // production writers BEFORE the daemon serves the run, so the driver's own
    // boot reconciliation starts from exactly this recorded evidence.
    let run = {
        let state = fixture.seed();
        let caps_for_tail = tail_boundary_caps();
        let tail_caps: Vec<&str> = caps_for_tail.iter().map(|cap| cap.as_str()).collect();
        seed_grant_with_caps(&state, "gr_0000000000000005", 5, &tail_caps);
        let mut request = request_with(vec![selected("#5", &[])]);
        request.steps = fix_rebind_spine();
        request.boundary.caps = tail_boundary_caps();
        let (bound, digest) = render_bound(&state, &request);
        let material = qx::parse_params(&submit_params_doc(
            &idem_key("fix-rebind-submit"),
            &bound,
            &digest,
            &[("#5", "gr_0000000000000005")],
            ConcurrencyCaps {
                global: 4,
                per_repository: 2,
                per_harness: 2,
            },
            5,
            60,
        ))
        .expect("params parse");
        let revalidated = qx::revalidate(&state, &material).expect("revalidate");
        let submission_id = qx::submission_id(&material.digest, &material.idempotency_key);
        let plan = QueueSubmissionPlan {
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
            request_line: canter::canonical::canonical_text(
                &revalidated
                    .preview
                    .doc
                    .get("request")
                    .cloned()
                    .unwrap_or_else(|| material.preview.clone()),
            ),
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
        };
        let (_, items) = state.submit_queue_run(&plan).expect("submit");
        let run = item_of(&items, 5)
            .instance_id
            .clone()
            .expect("issue 5 admitted");
        // The run's OWN collection certified the reviewed head.
        seed_fix_handoff_row(
            &fixture,
            &state,
            &run,
            "p1",
            "checkout",
            1,
            object(vec![("integration_base", string(&base))]),
        );
        seed_fix_handoff_row(
            &fixture,
            &state,
            &run,
            "s1",
            "harness_start",
            2,
            object(vec![("session_id", string(&run))]),
        );
        seed_fix_handoff_row(
            &fixture,
            &state,
            &run,
            "o1",
            "collect_outcome",
            3,
            object(vec![
                ("head", string(&reviewed)),
                ("base_head", string(&base)),
                ("branch", string("issue-5")),
                ("commits", Val::Arr(vec![string(&reviewed)])),
                ("changed_files", Val::Arr(vec![string("delivered.txt")])),
            ]),
        );
        // The recorded FAIL the review step handed to the run's own fix round
        // (issue #238/#256): the round, its lane and the leg's OWN checkout.
        seed_fix_handoff_row(
            &fixture,
            &state,
            &run,
            "r1",
            "review_evidence",
            4,
            object(vec![
                ("feature_head", string(&reviewed)),
                ("integration_base", string(&base)),
                ("verdict", string("fail")),
                (
                    "checks",
                    Val::Arr(vec![object(vec![
                        ("name", string("exact-head-review")),
                        ("status", string("failed")),
                    ])]),
                ),
                (
                    "fix_round",
                    object(vec![
                        ("schema", string("hf-fix-round/v1")),
                        ("round", integer(1)),
                        ("bound", integer(canter::mutation::FIX_ROUNDS_MAX as i64)),
                        ("feature_head", string(&reviewed)),
                        ("lane", string("lane-0123456789abcdef")),
                        ("agent", string("")),
                        ("workspace", string("")),
                        ("pane", string("")),
                        ("worktree", string(&repair_branch)),
                        ("delivery_attempts", integer(1)),
                    ]),
                ),
            ]),
        );
        state
            .record_evidence(
                &run,
                REPO,
                &reviewed,
                &base,
                WORKFLOW_HASH,
                POLICY_HASH,
                "fail",
                "lane-reviewer",
                &Val::Arr(vec![object(vec![
                    ("name", string("exact-head-review")),
                    ("status", string("failed")),
                ])]),
            )
            .expect("record the FAIL evidence");
        run
    };

    // The BEFORE read: the run's own evidence stands at the reviewed head, its
    // collection certified exactly that head, and the merge tail is unachieved.
    let state = fixture.seed();
    let before = state
        .run_delivery_certificate(&run)
        .expect("certificate read")
        .expect("certified");
    assert_eq!(before.head, reviewed, "{before:?}");

    // From here on NO client dispatch of any step happens: the daemon's own
    // boot reconciliation serves the armed run.
    let daemon = fixture.spawn_with_path(&fakebin);
    wait_ready(&fixture);
    let mut timeline: Vec<String> = Vec::new();
    let mut id = 700u64;
    let started = Instant::now();
    let mut last_progress = started;
    let mut progress = String::new();
    let mut settled;
    loop {
        id += 1;
        let (status, step, kind, attempts) = cursor_sample(&fixture.socket, &run, id);
        timeline.push(format!(
            "t{} status={status} next={step}/{kind} attempts={attempts:?}",
            id - 700
        ));
        // The driver's own acts, read from the run's live surfaces: the
        // certificate moved to the DELIVERED head and the reviewer recorded its
        // verdict there, so the run's own delivery is verified again.
        let sample_state = fixture.seed();
        let certificate = sample_state
            .run_delivery_certificate(&run)
            .expect("certificate read");
        let evidence = sample_state
            .evidence_for_instance(&run)
            .expect("evidence read");
        let recorded = evidence.first().cloned();
        settled = attempts.clone();
        if let (Some(certificate), Some(recorded)) = (&certificate, &recorded)
            && certificate.head == delivered
            && recorded.feature_head == delivered
            && recorded.verdict == "pass"
        {
            break;
        }
        let observed = format!("{status}/{step}/{kind}/{attempts:?}");
        if observed != progress {
            progress = observed;
            last_progress = Instant::now();
        }
        let stalled = last_progress.elapsed().as_secs();
        assert!(
            stalled < NO_PROGRESS_SECS,
            "the run never re-bound its fix delivery: no progress for {stalled}s of {}s waited; \
             observed: {timeline:?}",
            started.elapsed().as_secs()
        );
        std::thread::sleep(Duration::from_millis(250));
    }
    eprintln!("FIX_REBIND_TIMELINE={timeline:?}");
    // The loop above only leaves once the run's own machinery re-bound the
    // delivery: the certificate and the recorded verdict both name it.

    // (2) AC2: the binding was re-established by the run's OWN collection — the
    //     delivered head is what the run's own collector observed, at the LEG's
    //     own checkout.
    let certificate = state
        .run_delivery_certificate(&run)
        .expect("certificate read")
        .expect("the run's own collection certified a delivery");
    assert_eq!(
        certificate.head, delivered,
        "the run's own collection certified the head its handoff delivered: {certificate:?}"
    );
    assert_eq!(certificate.step_id, "o1", "the run's own collector step");

    // (3) AC4: the reviewer's verdict IS recorded at the delivered head, so the
    //     run's durable evidence no longer reads `FAIL at the pre-fix head`
    //     while a later PASS sits on disk.
    let evidence = state.evidence_for_instance(&run).expect("evidence read");
    let newest = evidence.first().expect("the re-entry recorded evidence");
    assert_eq!(
        newest.feature_head, delivered,
        "the recorded verdict names the delivered head: {newest:?}"
    );
    assert_eq!(newest.verdict, "pass", "{newest:?}");

    // (4) AC1: the audit rows of the whole path, read from the run's own
    //     durable ledger and hash-chained journal. The collector was dispatched
    //     TWICE (the run's own collection, then the re-collect of the repair
    //     leg's checkout, which is the row that moved the certificate), the
    //     review re-entry is the run's own bounded, attributed re-evaluation,
    //     and every `apply` claim is the DRIVER's own key — no operator
    //     step-dispatch exists anywhere.
    let claims = apply_claims(&fixture.db(), &run);
    let collects: Vec<&(String, String)> = claims
        .iter()
        .filter(|(_, line)| line.contains(r#""step":"o1""#))
        .collect();
    assert_eq!(
        collects.len(),
        2,
        "the seeded collection and the driver's own re-collect are the only ones: {collects:?}"
    );
    let recollect = collects.last().expect("the re-collect row").1.clone();
    assert!(
        recollect.contains(&repair_branch),
        "the re-collect observed the repair leg's OWN checkout: {recollect}"
    );
    // The driver's own dispatch keys are `<run>-<step>-<second>`; the run's own
    // re-evaluation re-dispatches on its fresh lane round under the same
    // run identity. Nothing else dispatches a step of this run.
    let run_tail = run.trim_start_matches("run-");
    for (key, _) in claims.iter().skip(4) {
        assert!(
            key.starts_with(&format!("ik_{run}-")) || key.starts_with(&format!("ik_{run_tail}-")),
            "every dispatch after the seeded handoff is the driver's own (no operator \
             dispatch): {key:?}\n{claims:?}"
        );
    }
    let reviews: Vec<&(String, String)> = claims
        .iter()
        .filter(|(_, line)| line.contains(r#""step":"r1""#))
        .collect();
    assert!(
        reviews.len() >= 2,
        "the review was re-dispatched for the delivered head: {reviews:?}"
    );
    let audit = audit_rows(&fixture.db(), &run);
    let recollects = audit
        .iter()
        .filter(|(action, target)| action == "mutate.collect_outcome" && target.contains(":o1"))
        .count();
    assert_eq!(
        recollects, 2,
        "the re-collect is journaled like every other apply: {audit:?}"
    );
    let reevaluations = audit
        .iter()
        .filter(|(action, _)| action == "mutate.run.reevaluate")
        .count();
    assert_eq!(
        reevaluations, 1,
        "the review re-entry is the run's own bounded, recorded control: {audit:?}"
    );

    // (5) The run ADVANCED to its committed tail by the driver's own acts, and
    //     the daemon's own log names them.
    let log = std::fs::read_to_string(fixture.daemon_log()).unwrap_or_default();
    assert!(
        log.contains("dispatched step o1"),
        "the driver dispatched the re-collect itself:\n{log}"
    );
    assert!(
        log.contains("re-evaluated step r1"),
        "the driver drove the review re-entry through the run's own control:\n{log}"
    );
    assert!(
        !log.contains("step o1: refusal."),
        "the re-collect was never refused:\n{log}"
    );
    assert!(
        settled
            .iter()
            .any(|(step, status)| step == "r1" && status == "succeeded"),
        "the review step is achieved at the delivered head: {settled:?}"
    );
    let socket = fixture.socket.clone();
    shutdown(daemon);
    assert!(
        !matches!(
            canter::lock::socket_presence(&socket),
            canter::lock::SocketPresence::Active
        ),
        "the witness's own daemon is gone"
    );
}

// ---------------------------------------------------------------------------
// The supervised committed-tail dispatch capability (issue #152, supervisor
// half): typed and closed, never a blanket allow-list entry
// ---------------------------------------------------------------------------

#[test]
fn the_supervisor_dispatch_capability_for_the_committed_tail_is_typed_and_closed() {
    use canter::state::{EvidenceRow, InstanceRow, QueueItemRef, SupervisionEvidence};

    const RUN_ID: &str = "run-0123456789abcdef";
    const TAIL_CAPS: &str = "[\"read\",\"worktree\",\"spawn\",\"review\",\"merge\",\"cleanup\"]";
    const NO_CLEANUP_CAPS: &str = "[\"read\",\"worktree\",\"spawn\",\"review\",\"merge\"]";
    const DIGEST: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    const NOW: i64 = 1_800_000_000;
    const AT: &str = "2026-09-13T00:00:10Z";

    fn run_row(caps: &str, status: &str) -> InstanceRow {
        InstanceRow {
            instance_id: RUN_ID.to_string(),
            repository: REPO.to_string(),
            workflow_id: DOCTRINE_WORKFLOW_ID.to_string(),
            workflow_hash: WORKFLOW_HASH.to_string(),
            policy_hash: POLICY_HASH.to_string(),
            grant_id: "gr_0000000000000005".to_string(),
            issue_number: 5,
            issue_revision: REV_A.to_string(),
            phase: "review".to_string(),
            scope: "worktrees/issues/5".to_string(),
            caps: caps.to_string(),
            current_node: String::new(),
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
            status: status.to_string(),
            created_at: "2026-09-13T00:00:00Z".to_string(),
            updated_at: "2026-09-13T00:00:00Z".to_string(),
        }
    }

    fn evidence_row() -> EvidenceRow {
        EvidenceRow {
            evidence_id: "ev_0123456789abcdef".to_string(),
            instance_id: RUN_ID.to_string(),
            repository: REPO.to_string(),
            feature_head: HEAD_A.to_string(),
            integration_base: BASE_A.to_string(),
            workflow_hash: WORKFLOW_HASH.to_string(),
            policy_hash: POLICY_HASH.to_string(),
            verdict: "pass".to_string(),
            reviewer: "reviewer-1".to_string(),
            checks: r#"[{"name":"hosted-ci","status":"passed"}]"#.to_string(),
            created_at: AT.to_string(),
        }
    }

    fn item() -> QueueItemRef {
        QueueItemRef {
            submission_id: "qs_0123456789abcdef".to_string(),
            ordinal: 0,
            work_item: "wi_0123456789abcdef".to_string(),
            issue_number: 5,
            status: "admitted".to_string(),
        }
    }

    fn snapshot(
        steps: &[(&str, &str)],
        caps: &str,
        has_dispatch_context: bool,
        membership: bool,
        newest: bool,
        status: &str,
    ) -> SupervisionEvidence {
        SupervisionEvidence {
            run: run_row(caps, status),
            has_dispatch_context,
            ownership_instance: Some(RUN_ID.to_string()),
            submission_id: Some("qs_0123456789abcdef".to_string()),
            submission_digest: Some(DIGEST.to_string()),
            steps: steps
                .iter()
                .map(|(id, kind)| (id.to_string(), kind.to_string()))
                .collect(),
            reviewer_leg_steps: Vec::new(),
            attempts: vec![
                ("p1".to_string(), "succeeded".to_string(), String::new()),
                ("r1".to_string(), "succeeded".to_string(), String::new()),
            ],
            last_failure: None,
            retries: Vec::new(),
            verdicts: Vec::new(),
            in_flight: None,
            progress_at: AT.to_string(),
            item: if membership { Some(item()) } else { None },
            newest_evidence: if newest { Some(evidence_row()) } else { None },
            dispatch_refusal: None,
            fix_round: None,
            fix_leg: None,
            reevaluations: Vec::new(),
            delivery: None,
        }
    }

    // The spine of the delivering run: the reviewed delivery, then the
    // committed tail.
    let tail_spine = [
        ("p1", "checkout"),
        ("r1", "review_evidence"),
        ("m1", "merge"),
        ("c1", "cleanup"),
    ];
    let delivering = snapshot(&tail_spine, TAIL_CAPS, true, true, true, "running");

    // 1. The run's OWN committed merge and cleanup are dispatchable, and the
    //    classification reports exactly that dispatchable frontier.
    assert!(supervision::driver_dispatchable_kind(
        &delivering,
        "m1",
        "merge"
    ));
    assert!(supervision::driver_dispatchable_kind(
        &delivering,
        "c1",
        "cleanup"
    ));
    let policy = supervision::Policy {
        check_interval_secs: 10,
        progress_timeout_secs: 60,
    };
    let verdict = supervision::classify(&delivering, DIGEST, &policy, NOW);
    assert_eq!(verdict.class, "healthy");
    assert_eq!(verdict.reason, supervision::codes::DISPATCH);
    assert!(
        verdict.eligible,
        "the committed tail is an eligible frontier"
    );
    assert_eq!(verdict.detail, "m1");

    // An eligible kind is not permission to replay an attempted tail step,
    // even with a pending operator retry. Pin the dispatch producer itself.
    let fixture = Fixture::new("tail-dispatch-fence");
    let state = fixture.open();
    let row = state
        .arm_supervision(
            RUN_ID,
            &canter::state::SupervisionAuthorizationPlan {
                desired: "armed".to_string(),
                check_interval_secs: policy.check_interval_secs,
                progress_timeout_secs: policy.progress_timeout_secs,
            },
            DIGEST,
            "review",
            1,
            AT,
        )
        .expect("arm");
    for (step, kind) in [("m1", "merge"), ("c1", "cleanup")] {
        let mut evidence = snapshot(&tail_spine, TAIL_CAPS, true, true, true, "running");
        if step == "c1" {
            evidence
                .attempts
                .push(("m1".to_string(), "succeeded".to_string(), String::new()));
        }
        let intent = supervision::dispatch_intent(&row, &evidence).expect("unattempted tail");
        assert_eq!(
            (intent.step_id.as_str(), intent.kind.as_str()),
            (step, kind)
        );
        evidence.retries.push(canter::state::RunRetryRow {
            retry_id: "retry-tail".to_string(),
            instance_id: RUN_ID.to_string(),
            step_id: step.to_string(),
            attempt: 1,
            authorized_at: AT.to_string(),
            consumed_at: String::new(),
            consumed_key: String::new(),
        });
        for status in ["failed", "refused", "ambiguous"] {
            evidence
                .attempts
                .push((step.to_string(), status.to_string(), String::new()));
            assert_eq!(
                supervision::dispatch_intent(&row, &evidence),
                None,
                "an attempted {kind} ({status}) belongs to the operator, never the driver"
            );
            evidence.attempts.pop();
        }
    }

    // 2. NOT for a run that is not an admitted member of a committed
    //    submission: an ad-hoc run's merge is never driven.
    let ad_hoc = snapshot(&tail_spine, TAIL_CAPS, true, false, true, "running");
    assert!(!supervision::driver_dispatchable_kind(
        &ad_hoc, "m1", "merge"
    ));
    // ... and the ordinary autonomous kinds are unaffected by that.
    assert!(supervision::driver_dispatchable_kind(
        &ad_hoc, "p1", "checkout"
    ));

    // 3. NOT without the run's own approved capability for the kind.
    let no_cleanup = snapshot(&tail_spine, NO_CLEANUP_CAPS, true, true, true, "running");
    assert!(!supervision::driver_dispatchable_kind(
        &no_cleanup,
        "c1",
        "cleanup"
    ));
    assert!(supervision::driver_dispatchable_kind(
        &no_cleanup,
        "m1",
        "merge"
    ));

    // 4. NOT without a fresh verified delivery: the tail exists only behind
    //    the delivery it completes.
    let undelivered = snapshot(&tail_spine, TAIL_CAPS, true, true, false, "running");
    assert!(!supervision::driver_dispatchable_kind(
        &undelivered,
        "m1",
        "merge"
    ));
    assert!(!supervision::driver_dispatchable_kind(
        &undelivered,
        "c1",
        "cleanup"
    ));

    // 5. NOT for a step that does not come AFTER the reviewed delivery.
    let merge_before = [
        ("p1", "checkout"),
        ("m1", "merge"),
        ("r1", "review_evidence"),
        ("c1", "cleanup"),
    ];
    let early = snapshot(&merge_before, TAIL_CAPS, true, true, true, "running");
    assert!(!supervision::driver_dispatchable_kind(
        &early, "m1", "merge"
    ));
    let early_verdict = supervision::classify(&early, DIGEST, &policy, NOW);
    assert_ne!(early_verdict.reason, supervision::codes::DISPATCH);
    assert_eq!(
        early_verdict.reason,
        supervision::codes::PROGRESS_TIMEOUT,
        "a non-drivable frontier keeps the pre-existing report: {early_verdict:?}"
    );

    // 6. The driven set stays CLOSED: other risk-classed kinds that share the
    //    merge/cleanup capability are not tail kinds.
    assert!(!supervision::driver_dispatchable_kind(
        &delivering,
        "x1",
        "branch_delete"
    ));
    assert!(!supervision::driver_dispatchable_kind(
        &delivering,
        "x1",
        "publish"
    ));
    assert!(!supervision::driver_dispatchable_kind(
        &delivering,
        "x1",
        "branch_push"
    ));
    assert!(!supervision::driver_dispatchable_kind(
        &delivering,
        "x1",
        "approve"
    ));

    // 7. A TERMINAL run is never a dispatch frontier, however eligible the
    //    kind is: the run-status fence is composed with this gate by the
    //    dispatch producer, and the classification reports completion.
    let mut done = snapshot(&tail_spine, TAIL_CAPS, true, true, true, "done");
    done.verdicts = vec![(
        "ev_0123456789abcdef".to_string(),
        "pass".to_string(),
        AT.to_string(),
    )];
    assert!(supervision::driver_dispatchable_kind(&done, "m1", "merge"));
    let done_verdict = supervision::classify(&done, DIGEST, &policy, NOW);
    assert_eq!(done_verdict.class, "completed");
    assert!(!done_verdict.eligible);
}

// ---------------------------------------------------------------------------
// The delivery predicate itself (the trigger contract)
// ---------------------------------------------------------------------------

#[test]
fn only_a_reviewed_pass_with_green_checks_at_the_run_pins_is_a_delivery() {
    use canter::state::{EvidenceRow, InstanceRow, QueueItemRef, SupervisionEvidence};

    const RUN_ID: &str = "run-0123456789abcdef";
    fn run_row() -> InstanceRow {
        InstanceRow {
            instance_id: RUN_ID.to_string(),
            repository: REPO.to_string(),
            workflow_id: DOCTRINE_WORKFLOW_ID.to_string(),
            workflow_hash: WORKFLOW_HASH.to_string(),
            policy_hash: POLICY_HASH.to_string(),
            grant_id: "gr_0000000000000005".to_string(),
            issue_number: 5,
            issue_revision: REV_A.to_string(),
            phase: "review".to_string(),
            scope: "worktrees/issues/5".to_string(),
            caps: "[\"read\"]".to_string(),
            current_node: String::new(),
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
            status: "new".to_string(),
            created_at: "2026-09-13T00:00:00Z".to_string(),
            updated_at: "2026-09-13T00:00:00Z".to_string(),
        }
    }
    fn evidence_row(verdict: &str, checks: &str, workflow: &str) -> EvidenceRow {
        EvidenceRow {
            evidence_id: "ev_0123456789abcdef".to_string(),
            instance_id: RUN_ID.to_string(),
            repository: REPO.to_string(),
            feature_head: HEAD_A.to_string(),
            integration_base: BASE_A.to_string(),
            workflow_hash: workflow.to_string(),
            policy_hash: POLICY_HASH.to_string(),
            verdict: verdict.to_string(),
            reviewer: "reviewer-1".to_string(),
            checks: checks.to_string(),
            created_at: "2026-09-13T00:00:10Z".to_string(),
        }
    }
    fn snapshot(run: InstanceRow, newest: Option<EvidenceRow>) -> SupervisionEvidence {
        SupervisionEvidence {
            run,
            has_dispatch_context: false,
            ownership_instance: Some(RUN_ID.to_string()),
            submission_id: Some("qs_0123456789abcdef".to_string()),
            submission_digest: Some("d".repeat(64)),
            steps: vec![("p1".to_string(), "checkout".to_string())],
            reviewer_leg_steps: Vec::new(),
            attempts: Vec::new(),
            last_failure: None,
            retries: Vec::new(),
            verdicts: Vec::new(),
            in_flight: None,
            progress_at: "2026-09-13T00:00:10Z".to_string(),
            item: Some(QueueItemRef {
                submission_id: "qs_0123456789abcdef".to_string(),
                ordinal: 0,
                work_item: "wi_0123456789abcdef".to_string(),
                issue_number: 5,
                status: "admitted".to_string(),
            }),
            newest_evidence: newest,
            dispatch_refusal: None,
            fix_round: None,
            fix_leg: None,
            reevaluations: Vec::new(),
            delivery: None,
        }
    }
    let green = r#"[{"name":"hosted-ci","status":"passed"}]"#;
    // A pass with every check passed at the run's own pins is a delivery.
    let delivery = supervision::verified_delivery(&snapshot(
        run_row(),
        Some(evidence_row("pass", green, WORKFLOW_HASH)),
    ))
    .expect("verified delivery");
    assert_eq!(delivery.feature_head, HEAD_A);
    assert_eq!(delivery.item_ordinal, 0);
    // No evidence, a failure verdict and a pending check are NOT deliveries.
    assert_eq!(
        supervision::verified_delivery(&snapshot(run_row(), None)),
        None
    );
    assert_eq!(
        supervision::verified_delivery(&snapshot(
            run_row(),
            Some(evidence_row("fail", green, WORKFLOW_HASH))
        )),
        None
    );
    assert_eq!(
        supervision::verified_delivery(&snapshot(
            run_row(),
            Some(evidence_row(
                "pass",
                r#"[{"name":"hosted-ci","status":"pending"}]"#,
                WORKFLOW_HASH
            ))
        )),
        None
    );
    // Evidence bound to a DIFFERENT workflow pin is not this run's delivery.
    assert_eq!(
        supervision::verified_delivery(&snapshot(
            run_row(),
            Some(evidence_row("pass", green, &"f".repeat(64)))
        )),
        None
    );
    // A run with no committed membership is never a delivery.
    let mut orphan = snapshot(run_row(), Some(evidence_row("pass", green, WORKFLOW_HASH)));
    orphan.item = None;
    assert_eq!(supervision::verified_delivery(&orphan), None);
    // A held run is never a delivery, whatever the evidence says.
    let mut paused = run_row();
    paused.pause_requested = true;
    assert_eq!(
        supervision::verified_delivery(&snapshot(
            paused,
            Some(evidence_row("pass", green, WORKFLOW_HASH))
        )),
        None
    );
    let mut blocked = run_row();
    blocked.status = "blocked".to_string();
    assert_eq!(
        supervision::verified_delivery(&snapshot(
            blocked,
            Some(evidence_row("pass", green, WORKFLOW_HASH))
        )),
        None
    );
    // A run that is merely 'new' with green evidence IS a delivery (the
    // board/merge evidence contract is evidence-based, never label-based).
    assert!(
        supervision::verified_delivery(&snapshot(
            run_row(),
            Some(evidence_row("pass", green, WORKFLOW_HASH))
        ))
        .is_some()
    );
}
