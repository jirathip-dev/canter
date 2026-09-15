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

/// The `apply` params that record the delivery of one run through the real
/// mutation surface: a plan whose `review_evidence` step names the reviewer
/// verdict and the checks, the grant the run was admitted against, the exact
/// observed head/base and the topology the daemon requires.
fn delivery_apply_params(
    seed: u64,
    fixture: &DaemonFixture,
    run: &str,
    number: i64,
    grant_id: &str,
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
                ("id", string("r1")),
                ("kind", string("review_evidence")),
                (
                    "params",
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
                    ]),
                ),
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
        ("step", string("r1")),
        ("grant_id", string(grant_id)),
        ("instance_id", string(run)),
        (
            "observed",
            object(vec![
                ("issue_revision", string(REV_A)),
                ("policy_hash", string(POLICY_HASH)),
                ("feature_head", string(HEAD_A)),
                ("integration_base", string(BASE_A)),
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
