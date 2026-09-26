//! Issue #311 acceptance: a run the engine's own record has made TERMINAL
//! (`done` / `invalidated`) stops being supervised.
//!
//! Armed supervision was never retired for a finished run: every supervised
//! run kept `desired = armed` forever and the driver kept owing each dead run a
//! classification pass on its cadence (measured on the fleet: 75 of 80 armed
//! rows belonged to done/invalidated runs). The fix retires the row on the
//! transition the engine ALREADY records:
//!
//! - the release / completion / invalidation transaction that makes the run
//!   terminal retires its supervision in the SAME transaction (no operator
//!   action, no later pass);
//! - a run that was already terminal when this landed is retired by the ONE
//!   check that observes it (the boot sweep), and never again;
//! - the row records the run identity (its own key), the terminal state that
//!   caused the retirement and the instant, so a reader tells a
//!   retired-and-finished run from a never-supervised one;
//! - a LIVE state (paused here, running elsewhere) keeps its row untouched —
//!   removing the wrong rows is worse than the defect.
//!
//! Library-level witnesses only: the REAL driver path (`check_plan` ->
//! `commit_supervision_check`, the same two calls `SupervisorCore::reconcile`
//! makes) over the fixture's durable state, plus the row-level reads the
//! daemon's `supervision.status` uses. No fixed real sleeps.
#[path = "support/pane_fixture.rs"]
mod pane_fixture;

use std::path::{Path, PathBuf};

use canter::lifecycle::ConcurrencyCaps;
use canter::plan::DOCTRINE_WORKFLOW_ID;
use canter::queue_executor as qx;
use canter::queue_preview as qp;
use canter::state::{QueueSubmissionPlan, Retention, State, SupervisionRow};
use canter::supervision;
use canter::value::{Val, object, string};
use pane_fixture::{
    HARNESS, HOST, POLICY_HASH, REPO, REV_A, WORKFLOW_HASH, binding_doc, idem_key, render_bound,
    resolved, seed_grant, selected,
};

/// The certified head one recorded delivery names (synthetic hex).
const HEAD_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
/// The integration base one recorded delivery names (synthetic hex).
const BASE_A: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

// ---------------------------------------------------------------------------
// Fixture (a private state directory per scenario, the #95/#96 shape)
// ---------------------------------------------------------------------------

struct Fixture {
    dir: PathBuf,
}

impl Fixture {
    fn new(name: &str) -> Fixture {
        let dir =
            std::env::temp_dir().join(format!("hf-supervision-311-{name}-{}", std::process::id()));
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

/// A raw connection to the fixture's state file, for the ONE fixture a
/// pre-fix fleet is: a run the engine recorded terminal while its supervision
/// row was still armed (the row state this issue measured).
fn raw(db: &Path) -> rusqlite::Connection {
    rusqlite::Connection::open(db).expect("raw open")
}

fn instance_status(state: &State, run: &str) -> String {
    state
        .instance_by_id(run)
        .expect("instance read")
        .expect("instance")
        .status
}

fn supervision_row(state: &State, run: &str) -> SupervisionRow {
    state
        .supervision_by_id(run)
        .expect("supervision read")
        .expect("supervision row")
}

// ---------------------------------------------------------------------------
// Builders (the queue-spine fixture: a delivery ends the run's committed work)
// ---------------------------------------------------------------------------

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
            caps: ["read", "worktree", "spawn", "review", "merge"]
                .iter()
                .map(|cap| cap.to_string())
                .collect(),
        },
        steps: vec![
            qp::PlannedStep {
                id: "p1".to_string(),
                kind: "checkout".to_string(),
                params: Some(resolved()),
            },
            // The run's LAST committed spine step is its delivery: a verified
            // delivery of it completes the run (issue #152).
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

fn params_doc(
    key: &str,
    bound: &Val,
    digest: &str,
    grants: &[(&str, &str)],
    supervision_block: Option<supervision::Authorization>,
) -> Val {
    let grants: Vec<qx::ItemGrant> = grants
        .iter()
        .map(|(id, grant_id)| qx::ItemGrant {
            id: id.to_string(),
            grant_id: grant_id.to_string(),
        })
        .collect();
    qx::submit_params(
        key,
        digest,
        1,
        bound,
        &binding_doc(),
        binding_doc()
            .get("revision")
            .and_then(Val::as_str)
            .expect("binding revision"),
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

fn submission_plan_for(
    state: &State,
    key: &str,
    bound: &Val,
    digest: &str,
    grants: &[(&str, &str)],
    supervision_block: Option<supervision::Authorization>,
) -> QueueSubmissionPlan {
    let material = qx::parse_params(&params_doc(key, bound, digest, grants, supervision_block))
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

fn armed(interval_secs: i64, timeout_secs: i64) -> supervision::Authorization {
    supervision::Authorization {
        desired: "armed".to_string(),
        policy: supervision::Policy {
            check_interval_secs: interval_secs,
            progress_timeout_secs: timeout_secs,
        },
    }
}

/// Submit ONE issue as an explicitly supervised (armed) run and return its
/// admitted identity.
fn submit_armed_run(state: &State, name: &str, issues: &[(&str, i64)]) -> Vec<String> {
    let grants: Vec<(&str, String)> = issues
        .iter()
        .map(|(id, number)| (*id, format!("gr_{number:016}")))
        .collect();
    for (_, grant_id) in &grants {
        let number: i64 = issues
            .iter()
            .find(|(_, number)| grant_id.ends_with(&format!("{number:016}")))
            .map(|(_, number)| *number)
            .expect("grant owner");
        seed_grant(state, grant_id, number);
    }
    let request = request_with(
        issues
            .iter()
            .map(|(id, _)| selected(id, REV_A))
            .collect::<Vec<_>>(),
    );
    let (bound, digest) = render_bound(state, &request);
    let pairs: Vec<(&str, &str)> = grants
        .iter()
        .map(|(id, grant_id)| (*id, grant_id.as_str()))
        .collect();
    let plan = submission_plan_for(
        state,
        &idem_key(name),
        &bound,
        &digest,
        &pairs,
        Some(armed(10, 60)),
    );
    let (_, items) = state.submit_queue_run(&plan).expect("submit");
    items
        .iter()
        .map(|item| item.instance_id.clone().expect("admitted run"))
        .collect()
}

/// Drive ONE reconciliation exactly like the driver does: read the snapshot,
/// build the plan from the pure function, commit it (the two calls
/// `SupervisorCore::reconcile` makes).
fn reconcile(state: &State, run: &str, boot: bool) -> canter::state::SupervisionCheckPlan {
    let row = supervision_row(state, run);
    let evidence = state
        .supervision_evidence(run)
        .expect("evidence read")
        .expect("supervision exists");
    let plan = supervision::check_plan(&row, &evidence, None, boot, canter::time::unix_now());
    state.commit_supervision_check(&plan).expect("commit check");
    plan
}

/// The reviewed PASS delivery of one run (the row shape the daemon's
/// `review_evidence` effect records).
fn record_delivery(state: &State, run: &str) {
    state
        .record_evidence(
            run,
            REPO,
            HEAD_A,
            BASE_A,
            WORKFLOW_HASH,
            POLICY_HASH,
            "pass",
            "reviewer-1",
            &Val::parse_json(r#"[{"name":"hosted-ci","status":"passed"}]"#).expect("checks"),
        )
        .expect("record evidence");
}

// ---------------------------------------------------------------------------
// AC1/AC4: the transition the engine already records retires the supervision
// ---------------------------------------------------------------------------

#[test]
fn a_released_run_is_retired_in_the_transaction_that_records_the_release() {
    // The release is an operator control, but the RETIREMENT is not: the row
    // stops being armed inside the release's own transaction — no later pass
    // is needed and no operator action beyond the release itself.
    let fixture = Fixture::new("release-retires");
    let state = fixture.open();
    let runs = submit_armed_run(&state, "311-release", &[("#5", 5), ("#6", 6)]);
    let (released_run, live_run) = (runs[0].clone(), runs[1].clone());
    assert_eq!(supervision_row(&state, &released_run).desired, "armed");
    assert_eq!(supervision_row(&state, &live_run).desired, "armed");
    let now = canter::time::unix_now();
    assert!(
        state
            .supervision_due_runs(now)
            .expect("due")
            .contains(&released_run),
        "the released run is still supervised before the release"
    );

    let at = canter::time::rfc3339_now();
    let outcome = state
        .release_run(
            &released_run,
            "superseded by a fresh delivery",
            "ik_311-release",
            &at,
        )
        .expect("release");
    assert_eq!(outcome.run.status, "invalidated");

    // The retirement record: the run identity is the row's own key, the
    // terminal state that caused it and the instant are on the row.
    let retired = supervision_row(&state, &released_run);
    assert_eq!(retired.desired, "disabled", "a retired row is never armed");
    assert_eq!(retired.retired_state, "invalidated");
    assert_eq!(retired.retired_at, at);
    // ... and the LIVE sibling keeps its supervision untouched (AC3).
    assert_eq!(supervision_row(&state, &live_run).desired, "armed");
    assert_eq!(supervision_row(&state, &live_run).retired_state, "");
    // AC5, by the rows the driver CONSIDERS: the due set no longer names it.
    assert_eq!(
        state.supervision_due_runs(now).expect("due"),
        vec![live_run.clone()],
        "a retired run is never scheduled a pass again"
    );
    // ... and the surface reports the retirement instead of a bare disabled
    // row: a reader tells it from a never-supervised run.
    let row = supervision_row(&state, &released_run);
    let evidence = state
        .supervision_evidence(&released_run)
        .expect("evidence read")
        .expect("evidence");
    let policy = supervision::Policy {
        check_interval_secs: row.check_interval_secs,
        progress_timeout_secs: row.progress_timeout_secs,
    };
    let verdict = supervision::classify(&evidence, &row.authorization_digest, &policy, now);
    let doc = supervision::status_doc(&row, &evidence, None, &verdict, now);
    let block = doc.get("supervision").cloned().expect("supervision block");
    assert_eq!(
        block.get("retired_state").and_then(Val::as_str),
        Some("invalidated")
    );
    assert_eq!(
        block.get("retired_at").and_then(Val::as_str),
        Some(at.as_str())
    );
    let human = supervision::render_human(&doc);
    assert!(
        human.contains("retired "),
        "the human read names the retirement: {human}"
    );
}

#[test]
fn a_delivery_that_completes_its_run_retires_that_run_s_supervision() {
    // The completion path: the run's OWN reconciliation advances the queue
    // cursor and writes `status = done` — the retirement rides that same
    // transaction, so a finished run is never left armed for even one pass.
    let fixture = Fixture::new("completion-retires");
    let state = fixture.open();
    let run = submit_armed_run(&state, "311-complete", &[("#5", 5)]).remove(0);
    assert_eq!(supervision_row(&state, &run).desired, "armed");
    record_delivery(&state, &run);

    let plan = reconcile(&state, &run, true);
    assert!(
        plan.advance.is_some(),
        "the check consumed the fresh verified delivery"
    );
    assert_eq!(
        instance_status(&state, &run),
        "done",
        "a spine that ends at the delivery completes at the delivery"
    );
    let retired = supervision_row(&state, &run);
    assert_eq!(retired.desired, "disabled");
    assert_eq!(retired.retired_state, "done");
    assert_eq!(retired.retired_at, plan.at);
    assert!(
        !state
            .supervision_due_runs(canter::time::unix_now())
            .expect("due")
            .contains(&run),
        "a completed run is never scheduled a pass again"
    );
}

// ---------------------------------------------------------------------------
// AC2/AC5: the rows a pre-fix fleet still carries — a terminal run whose
// supervision is armed — are retired by the ONE check that observes them
// ---------------------------------------------------------------------------

#[test]
fn a_run_that_was_already_terminal_is_retired_by_the_one_check_that_sees_it() {
    // The measured shape: the engine recorded the terminal transition BEFORE
    // any retirement existed, so the row is still armed and the driver owes it
    // a pass on every tick. ONE observation retires it; no pass after that one
    // ever considers it again.
    let fixture = Fixture::new("legacy-terminal");
    let state = fixture.open();
    let run = submit_armed_run(&state, "311-legacy", &[("#5", 5)]).remove(0);
    let now = canter::time::unix_now();
    assert_eq!(supervision_row(&state, &run).desired, "armed");
    // The recorded transition this fleet already carries (a state file written
    // before this fix): terminal run, armed supervision.
    {
        let conn = raw(&fixture.db());
        conn.execute(
            "UPDATE instances SET status = 'done', paused = 0, updated_at = ?2 WHERE instance_id = ?1",
            rusqlite::params![run, canter::time::rfc3339_now()],
        )
        .expect("the pre-fix terminal state");
    }
    assert_eq!(instance_status(&state, &run), "done");
    assert_eq!(
        state.supervision_due_runs(now).expect("due"),
        vec![run.clone()],
        "before the fix's pass, a dead run is still on the due list"
    );

    let row = supervision_row(&state, &run);
    let evidence = state
        .supervision_evidence(&run)
        .expect("evidence")
        .expect("evidence");
    let plan = supervision::check_plan(&row, &evidence, None, true, now);
    // The committed check is what retires it: the recorded status the check
    // reads is terminal, so the SAME transaction that commits the check stops
    // the row being armed.
    state.commit_supervision_check(&plan).expect("commit");

    let retired = supervision_row(&state, &run);
    assert_eq!(retired.desired, "disabled");
    assert_eq!(retired.retired_state, "done");
    assert_eq!(retired.retired_at, plan.at);
    assert_eq!(
        state
            .supervision_due_runs(canter::time::unix_now())
            .expect("due"),
        Vec::<String>::new(),
        "after the retiring pass, the driver considers no terminal row at all"
    );
    // A second pass is not even possible for the retired row: the committed
    // check path refuses a row that is no longer armed instead of re-writing
    // it, so the retirement is durable, not a re-derived read.
    let err = state
        .commit_supervision_check(&plan)
        .expect_err("a retired row is never checked again");
    assert_eq!(err.code, "state.supervision_disabled");
}

// ---------------------------------------------------------------------------
// AC1: the invalidation paths retire the runs they make terminal
// ---------------------------------------------------------------------------

#[test]
fn an_invalidation_retires_exactly_the_runs_it_invalidates() {
    // The two invalidation paths that make a run terminal with no action on
    // the run itself — an invalidated grant (a material issue edit) and an
    // epoch rotation (restore semantics) — retire the supervision of exactly
    // the runs they invalidate, in their own step, and touch no other run.
    let fixture = Fixture::new("invalidation-retires");
    let state = fixture.open();
    let runs = submit_armed_run(&state, "311-invalidation", &[("#5", 5), ("#6", 6)]);
    let (edited_run, rotated_run) = (runs[0].clone(), runs[1].clone());
    assert_eq!(supervision_row(&state, &edited_run).desired, "armed");
    assert_eq!(supervision_row(&state, &rotated_run).desired, "armed");

    // Leg 1: the issue's grant is invalidated (a material edit); the run bound
    // to it goes terminal and its supervision is retired with the same step.
    let at = canter::time::rfc3339_now();
    state
        .invalidate_grant("gr_0000000000000005", &at)
        .expect("grant invalidation");
    assert_eq!(instance_status(&state, &edited_run), "invalidated");
    let edited = supervision_row(&state, &edited_run);
    assert_eq!(edited.desired, "disabled");
    assert_eq!(edited.retired_state, "invalidated");
    assert_eq!(edited.retired_at, at);
    // ... and the run bound to the OTHER grant is untouched (AC3).
    assert_eq!(supervision_row(&state, &rotated_run).desired, "armed");

    // Leg 2: an epoch rotation invalidates every run bound to the older epoch
    // (restore semantics) — its supervision is retired in the same step.
    let rotated_at = canter::time::rfc3339_now();
    state.rotate_epoch("restore").expect("rotate");
    state
        .invalidate_grants_below_current()
        .expect("invalidate below current");
    assert_eq!(instance_status(&state, &rotated_run), "invalidated");
    let rotated = supervision_row(&state, &rotated_run);
    assert_eq!(rotated.desired, "disabled");
    assert_eq!(rotated.retired_state, "invalidated");
    assert_eq!(rotated.retired_at, rotated_at);
    assert_eq!(
        state
            .supervision_due_runs(canter::time::unix_now())
            .expect("due"),
        Vec::<String>::new(),
        "no terminal run is left on the due list"
    );
}

// ---------------------------------------------------------------------------
// AC3: live states keep their supervision exactly as before
// ---------------------------------------------------------------------------

#[test]
fn a_paused_run_keeps_its_row_and_stays_ineligible() {
    let fixture = Fixture::new("paused-keeps");
    let state = fixture.open();
    let run = submit_armed_run(&state, "311-paused", &[("#5", 5)]).remove(0);
    state
        .pause_instance(&run, &"d".repeat(64), &canter::time::rfc3339_now())
        .expect("pause");
    assert_eq!(instance_status(&state, &run), "paused");

    // A pass over the paused run classifies it exactly as before and retires
    // NOTHING: the row keeps its arm and its (empty) retirement record.
    let plan = reconcile(&state, &run, true);
    assert_eq!(plan.class, "paused");
    assert!(!plan.eligible);
    let row = supervision_row(&state, &run);
    assert_eq!(row.desired, "armed", "a paused run keeps its supervision");
    assert_eq!(row.retired_state, "");
    assert_eq!(row.retired_at, "");
    assert!(
        state
            .supervision_armed_runs()
            .expect("armed")
            .contains(&run),
        "a paused run keeps being classified, as the contract states"
    );
    assert!(
        state
            .supervision_due_runs(row.next_check_unix)
            .expect("due")
            .contains(&run),
        "and it stays on the supervised set at its own cadence"
    );
}
