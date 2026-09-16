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
    assert_eq!(ownership.len(), 2);
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

    // The LAST committed step executes: the run completes only NOW, and the
    // freed slot admits the waiting issue in the same transaction.
    record_achieved_step(&state, &run5, "c1", "mutate.cleanup", 2);
    reconcile(&state, &run5, false);
    assert_eq!(
        run_status(&state, &run5),
        "done",
        "the delivering run completes after its LAST committed step"
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
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut id = 100u64;
    let status = loop {
        id += 1;
        let doc = rpc_ok(
            &fixture.socket,
            &fresh_id(id),
            "queue.status",
            Some(object(vec![("submission_id", string(&submission_id))])),
        );
        if live_item(&doc, 6).get("status").and_then(Val::as_str) == Some("admitted") {
            break doc;
        }
        if Instant::now() >= deadline {
            panic!(
                "the queue never advanced to issue 6; last: {}",
                canter::canonical::canonical_text(&doc)
            );
        }
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

/// A disposable integration repo plus the run's own lane worktree. The lane
/// branch sits AT the integration head, so the reviewed base is current and
/// the branch is provably merged: the merge step is a read-only REHEARSAL
/// (it never lands) and the cleanup may only delete a verified branch.
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

fn merge_params() -> Val {
    object(vec![
        ("branch", string("issue-5")),
        ("merge_policy", string("squash")),
    ])
}

fn cleanup_params() -> Val {
    object(vec![
        ("branch", string("issue-5")),
        ("worktree", string("issues-5")),
    ])
}

fn attempt_status(doc: &Val, step: &str) -> Option<String> {
    doc.get("cursor")
        .and_then(|cursor| cursor.get("attempts"))
        .and_then(Val::as_array)
        .and_then(|attempts| {
            attempts
                .iter()
                .find(|attempt| attempt.get("step").and_then(Val::as_str) == Some(step))
        })
        .and_then(|attempt| attempt.get("status"))
        .and_then(Val::as_str)
        .map(str::to_string)
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
    let deadline = Instant::now() + Duration::from_secs(90);
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
        assert!(
            Instant::now() < deadline,
            "the driver never drove the run's committed tail to its last step; observed: {timeline:?}"
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
        "the rehearsal never lands in the integration checkout"
    );
    shutdown(daemon);
}

#[test]
fn a_delivering_run_stays_live_for_its_committed_merge_and_cleanup_then_the_queue_continues() {
    let fixture = DaemonFixture::new("tail");
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

    // ONE per-repository slot: issue 6 waits while issue 5 owns the run.
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
            &idem_key("tail-submit"),
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

    // The delivery is recorded through the daemon's OWN mutation path, at the
    // reviewed head (the lane branch) and integration base.
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

    // The driver's OWN reconciliation consumes the delivery (bounded poll, no
    // fixed sleep): from here on the delivering run's status is committed.
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut consumed_id = 10u64;
    loop {
        consumed_id += 1;
        let doc = rpc_ok(
            &fixture.socket,
            &fresh_id(consumed_id),
            "queue.status",
            Some(object(vec![("submission_id", string(&submission_id))])),
        );
        if doc
            .get("advance")
            .and_then(|advance| advance.get("consumed"))
            .and_then(Val::as_int)
            == Some(1)
        {
            break;
        }
        if Instant::now() >= deadline {
            panic!(
                "the verified delivery was never consumed; last: {}",
                canter::canonical::canonical_text(&doc)
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    // The run's OWN committed merge step (p7 of the #146 plan) is dispatched
    // and EXECUTES. Before #152 the instance was already terminal here and
    // this is where `refusal.instance.state` refused it.
    let merge = rpc(
        &fixture.socket,
        &fresh_id(3),
        "apply",
        Some(step_apply_params(
            3,
            &fixture,
            &run5,
            5,
            "gr_0000000000000005",
            "m1",
            "merge",
            merge_params(),
            &head,
            &head,
        )),
    );
    assert_eq!(
        merge.get("ok").and_then(Val::as_bool),
        Some(true),
        "the delivering run's committed merge step must be dispatchable: {}",
        canter::canonical::canonical_text(&merge)
    );
    let merged = merge.get("result").cloned().expect("merge result");
    assert_eq!(
        merged.get("mode").and_then(Val::as_str),
        Some("rehearsal"),
        "{}",
        canter::canonical::canonical_text(&merged)
    );
    assert_eq!(
        merged.get("merge_policy").and_then(Val::as_str),
        Some("squash")
    );
    assert_eq!(merged.get("landed").and_then(Val::as_bool), Some(false));
    assert_eq!(
        git(&fixture.dir.join("repo"), &["rev-parse", "staging"]),
        head,
        "the rehearsal never lands in the integration checkout"
    );

    // The delivery alone does NOT complete the run: the cleanup is still owed
    // and the record NAMES it instead of reading as a bare `done`.
    let live = rpc_ok(
        &fixture.socket,
        &fresh_id(4),
        "supervision.status",
        Some(supervision::status_params(&run5)),
    );
    assert_ne!(
        live.get("run")
            .and_then(|run| run.get("status"))
            .and_then(Val::as_str),
        Some("done"),
        "a run that still owes its cleanup stays live: {}",
        canter::canonical::canonical_text(&live)
    );
    assert_eq!(
        live.get("cursor")
            .and_then(|cursor| cursor.get("next_step"))
            .and_then(Val::as_str),
        Some("c1")
    );
    assert_eq!(
        live.get("cursor")
            .and_then(|cursor| cursor.get("next_step_kind"))
            .and_then(Val::as_str),
        Some("cleanup")
    );
    assert_eq!(
        attempt_status(&live, "r1").as_deref(),
        Some("succeeded"),
        "the attempt list names the steps that actually ran"
    );
    assert_eq!(attempt_status(&live, "m1").as_deref(), Some("succeeded"));
    // The slot the delivering run still owns keeps issue 6 waiting.
    let waiting = rpc_ok(
        &fixture.socket,
        &fresh_id(5),
        "queue.status",
        Some(object(vec![("submission_id", string(&submission_id))])),
    );
    assert_eq!(
        live_item(&waiting, 6).get("status").and_then(Val::as_str),
        Some("waiting")
    );

    // The LAST committed step (p8 cleanup) executes. The run completes only
    // now, and the freed slot admits the waiting issue with NO further
    // operator request.
    let cleanup = rpc(
        &fixture.socket,
        &fresh_id(6),
        "apply",
        Some(step_apply_params(
            6,
            &fixture,
            &run5,
            5,
            "gr_0000000000000005",
            "c1",
            "cleanup",
            cleanup_params(),
            &head,
            &head,
        )),
    );
    assert_eq!(
        cleanup.get("ok").and_then(Val::as_bool),
        Some(true),
        "the delivering run's committed cleanup step must be dispatchable: {}",
        canter::canonical::canonical_text(&cleanup)
    );
    assert!(
        !fixture.dir.join("worktrees/issues-5").exists(),
        "the cleanup removed the run's own worktree"
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut id = 100u64;
    let settled = loop {
        id += 1;
        let doc = rpc_ok(
            &fixture.socket,
            &fresh_id(id),
            "queue.status",
            Some(object(vec![("submission_id", string(&submission_id))])),
        );
        if live_item(&doc, 6).get("status").and_then(Val::as_str) == Some("admitted") {
            break doc;
        }
        if Instant::now() >= deadline {
            panic!(
                "the queue never advanced after the delivering run's last step; last: {}",
                canter::canonical::canonical_text(&doc)
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    assert_ne!(
        live_item(&settled, 6)
            .get("instance_id")
            .and_then(Val::as_str),
        Some(run5.as_str())
    );
    let done = rpc_ok(
        &fixture.socket,
        &fresh_id(500),
        "supervision.status",
        Some(supervision::status_params(&run5)),
    );
    assert_eq!(
        done.get("run")
            .and_then(|run| run.get("status"))
            .and_then(Val::as_str),
        Some("done"),
        "the delivering run completed after its LAST committed step: {}",
        canter::canonical::canonical_text(&done)
    );
    assert_eq!(
        git(&fixture.dir.join("repo"), &["rev-parse", "staging"]),
        head,
        "no step ever landed in the integration checkout"
    );
    shutdown(daemon);
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
            attempts: vec![
                ("p1".to_string(), "succeeded".to_string(), String::new()),
                ("r1".to_string(), "succeeded".to_string(), String::new()),
            ],
            retries: Vec::new(),
            verdicts: Vec::new(),
            in_flight: None,
            progress_at: AT.to_string(),
            item: if membership { Some(item()) } else { None },
            newest_evidence: if newest { Some(evidence_row()) } else { None },
            dispatch_refusal: None,
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
            attempts: Vec::new(),
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
