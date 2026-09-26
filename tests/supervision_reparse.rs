//! Issue #268 witnesses: a supervision pass reads the runs it names, parses
//! each run's recorded rows once, and classifies from the evidence recorded
//! SINCE the last tick — never from a cached read, and never from another
//! run's rows.
//!
//! The pass is driven through the REAL driver (`supervision::start` over a real
//! state and real supervision rows), and every observation is a durable row the
//! pass itself committed (`last_check_class` / `last_check_reason` /
//! `last_check_trigger` / `checks`) or the dispatch intent the check handed the
//! daemon's dispatch hook. Identities are synthetic; nothing here seeds a
//! provider, a model or a project.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use canter::canonical::canonical_text;
use canter::config::ProfileBinding;
use canter::lifecycle::ConcurrencyCaps;
use canter::plan::DOCTRINE_WORKFLOW_ID;
use canter::queue_preview as qp;
use canter::state::{
    QueueSubmissionItemPlan, QueueSubmissionPlan, Retention, State, SubmissionVerdict,
    SupervisionAuthorizationPlan, SupervisionRow,
};
use canter::supervision::{
    DispatchIntent, PASS_DEADLINE_SECS, SupervisedDispatch, SupervisorHandle, SupervisorOptions,
    SupervisorWake, codes, start,
};
use canter::value::{Val, integer, object, string};

const REPO: &str = "example-org/widgets";
const REV: &str = "1111111111111111111111111111111111111111";
const WORKFLOW_HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const POLICY_HASH: &str = "feedface01234567feedface01234567feedface01234567feedface01234567";
const AT: &str = "2026-09-24T00:00:00Z";
const FOREIGN: &str = "run-00000000000000ff";
/// A bounded wait for a driver tick. The fixture's check interval is one
/// second, so a tick is due almost immediately; the deadline only bounds a
/// saturated host.
const TICK_DEADLINE: Duration = Duration::from_secs(30);

/// Records the dispatch intents a committed check handed the dispatch hook:
/// the check's own frontier, read from the record the driver produced.
#[derive(Default)]
struct RecordingDispatch {
    intents: Mutex<Vec<DispatchIntent>>,
}

impl RecordingDispatch {
    fn steps(&self) -> Vec<String> {
        self.intents
            .lock()
            .expect("intents")
            .iter()
            .map(|intent| intent.step_id.clone())
            .collect()
    }

    /// The successive FRONTIERS the driver acted on: consecutive re-dispatches
    /// of the step that is still the frontier collapse into one entry, so only
    /// a step the evidence MOVED the frontier to adds one. A tick that lands
    /// between a check's commit and a read legitimately re-dispatches the
    /// still-current frontier (issue #295), so the live intent COUNT is never
    /// the observation — the frontier the evidence moved to is.
    fn frontiers(&self) -> Vec<String> {
        let mut moved: Vec<String> = Vec::new();
        for step in self.steps() {
            if moved.last() != Some(&step) {
                moved.push(step);
            }
        }
        moved
    }
}

impl SupervisedDispatch for RecordingDispatch {
    fn dispatch(&self, intent: &DispatchIntent) -> Result<String, String> {
        self.intents.lock().expect("intents").push(intent.clone());
        Ok("recorded".to_string())
    }
}

/// One armed run over a real committed submission, with the run's recorded
/// dispatch context journaled before any driver starts.
struct Fixture {
    dir: PathBuf,
    state: Arc<Mutex<State>>,
    run: String,
}

impl Fixture {
    fn new(name: &str, steps: &[(&str, &str)], admission: &Val) -> Fixture {
        let dir =
            std::env::temp_dir().join(format!("canter-reparse-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("fixture dir");
        let state = Arc::new(Mutex::new(
            State::open(&dir.join("state.db"), Retention::default()).expect("state open"),
        ));
        let worktrees_root = dir.join("worktrees");
        std::fs::create_dir_all(&worktrees_root).expect("worktrees root");
        let topology = object(vec![
            ("integration_branch", string("staging")),
            (
                "integration_repo",
                string(&dir.join("integration").display().to_string()),
            ),
            ("production_branches", Val::Arr(Vec::new())),
            (
                "worktrees_root",
                string(&worktrees_root.display().to_string()),
            ),
        ]);
        let run = {
            let guard = state.lock().expect("state");
            let number = 268;
            let grant_id = "gr_0000000000000268";
            guard
                .issue_grant(
                    &Val::parse_json(&format!(
                        r#"{{"schema":"hf-grant/v1","grant_id":"{grant_id}","repository":"{REPO}",
                            "issue":{{"number":{number},"revision":"{REV}"}},
                            "workflow_hash":"{WORKFLOW_HASH}","policy_hash":"{POLICY_HASH}",
                            "phase":"merge","scope":"worktrees/issues/{number}",
                            "caps":["read","worktree","spawn","review","merge"],
                            "expires_at":"2999-01-01T00:00:00Z","state_epoch":1,
                            "created_at":"2026-09-06T00:00:00Z"}}"#
                    ))
                    .expect("grant json"),
                )
                .expect("grant");
            let planned: Vec<qp::PlannedStep> = steps
                .iter()
                .map(|(id, kind)| qp::PlannedStep {
                    id: (*id).to_string(),
                    kind: (*kind).to_string(),
                    params: Some(object(vec![("ref", string("staging"))])),
                })
                .collect();
            let request = qp::QueueRequest {
                repository: REPO.to_string(),
                host: "host-1".to_string(),
                host_available: Some(true),
                harness_key: "lane-1".to_string(),
                harness_lanes: Some(0),
                caps: ConcurrencyCaps {
                    global: 16,
                    per_repository: 16,
                    per_harness: 16,
                },
                workflow_id: DOCTRINE_WORKFLOW_ID.to_string(),
                workflow_hash: WORKFLOW_HASH.to_string(),
                role_config: binding_doc(),
                boundary: qp::Boundary {
                    phase: "merge".to_string(),
                    integration_branch: "staging".to_string(),
                    completion_branch: "staging".to_string(),
                    caps: vec!["read".into(), "worktree".into(), "merge".into()],
                },
                steps: planned,
                selected: vec![qp::SelectedIssue {
                    id: format!("#{number}"),
                    title: None,
                    revision: REV.to_string(),
                    requires: Vec::new(),
                }],
            };
            let preview = qp::preview_queue(&guard, &request).expect("preview");
            let bound = preview.doc.get("request").cloned().expect("bound");
            let submit_key = "ik-268-submit".to_string();
            let plan = QueueSubmissionPlan {
                submission_id: canter::queue_executor::submission_id(&preview.digest, &submit_key),
                repository: REPO.to_string(),
                state_epoch: guard.current_epoch().expect("epoch"),
                digest: preview.digest.clone(),
                role_key: "lane-1".to_string(),
                role_revision: "e".repeat(64),
                workflow_id: DOCTRINE_WORKFLOW_ID.to_string(),
                workflow_hash: WORKFLOW_HASH.to_string(),
                boundary_phase: "merge".to_string(),
                integration_branch: "staging".to_string(),
                completion_branch: "staging".to_string(),
                boundary_caps: vec!["read".into(), "worktree".into(), "merge".into()],
                request_line: canonical_text(&bound),
                admission_caps: ConcurrencyCaps {
                    global: 16,
                    per_repository: 16,
                    per_harness: 16,
                },
                harness_lanes: Some(0),
                items: vec![QueueSubmissionItemPlan {
                    ordinal: 0,
                    work_item: format!("{REPO}#268"),
                    issue_number: number,
                    issue_revision: REV.to_string(),
                    grant_id: Some(grant_id.to_string()),
                    resume_digest: None,
                    verdict: SubmissionVerdict::Approved,
                }],
                supervision: None,
                at: AT.to_string(),
            };
            let (_, items) = guard.submit_queue_run(&plan).expect("submission commits");
            let run = items[0].instance_id.clone().expect("admitted run");
            guard
                .arm_supervision(
                    &run,
                    &SupervisionAuthorizationPlan {
                        desired: "armed".to_string(),
                        check_interval_secs: 1,
                        progress_timeout_secs: 900,
                    },
                    &preview.digest,
                    "merge",
                    1,
                    AT,
                )
                .expect("arm");
            // The run's recorded dispatch context: the queue.submit row whose
            // digest + idempotency key derive exactly the admitted submission
            // id, so the frontier is a dispatchable continuation and NOT a run
            // parked for a missing context.
            let line = canonical_text(&object(vec![
                ("schema", string("hf-rpc-request/v1")),
                ("id", string("sub_268")),
                ("method", string("queue.submit")),
                (
                    "params",
                    object(vec![
                        ("digest", string(&preview.digest)),
                        (
                            "dispatch",
                            object(vec![
                                ("topology", topology.clone()),
                                ("admission", admission.clone()),
                            ]),
                        ),
                    ]),
                ),
            ]));
            record_row(
                &guard,
                "queue.submit",
                &submit_key,
                &line,
                &ok_response("sub_268", &object(vec![("admitted", integer(1))])),
            );
            run
        };
        Fixture { dir, state, run }
    }
}

fn binding_doc() -> Val {
    let mut binding = ProfileBinding {
        key: "lane-1".to_string(),
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

fn admission_doc() -> Val {
    object(vec![
        ("harness_lanes", integer(0)),
        ("host_available", Val::Bool(true)),
        (
            "caps",
            object(vec![
                ("global", integer(4)),
                ("per_repository", integer(2)),
                ("per_harness", integer(1)),
            ]),
        ),
    ])
}

fn ok_response(id: &str, result: &Val) -> String {
    canonical_text(&object(vec![
        ("schema", string("hf-rpc-response/v1")),
        ("id", string(id)),
        ("ok", Val::Bool(true)),
        ("result", result.clone()),
    ]))
}

/// Journal one claim and resolve it with the caller's outcome document.
fn record_row_with_outcome(
    state: &State,
    method: &str,
    key: &str,
    request_line: &str,
    outcome: &str,
    response: &str,
) {
    state
        .journal_intent(
            "mutate.checkout",
            key,
            key,
            &format!("{key}-req"),
            method,
            None,
            None,
            request_line,
        )
        .expect("claim");
    state
        .resolve_claim(key, method, "spent", outcome, Some(response))
        .expect("resolve");
}

/// Journal one claim and resolve it with a succeeded outcome.
fn record_row(state: &State, method: &str, key: &str, request_line: &str, response: &str) {
    record_row_with_outcome(
        state,
        method,
        key,
        request_line,
        &outcome_line(key, "p1", "succeeded", "", ""),
        response,
    );
}

fn outcome_line(key: &str, step: &str, status: &str, code: &str, message: &str) -> String {
    canonical_text(&object(vec![
        ("schema", string("hf-outcome/v1")),
        ("plan_id", string("hf_plan_0000000000000000")),
        ("step_id", string(step)),
        ("status", string(status)),
        ("idempotency_key", string(key)),
        ("observed_at", string(AT)),
        ("result", Val::Null),
        (
            "error",
            if code.is_empty() {
                Val::Null
            } else {
                object(vec![("code", string(code)), ("message", string(message))])
            },
        ),
    ]))
}

/// Record one `apply` attempt of (run, step) with the caller's outcome.
#[allow(clippy::too_many_arguments)]
fn record_attempt(
    state: &State,
    run: &str,
    step: &str,
    kind: &str,
    key: &str,
    status: &str,
    code: &str,
    message: &str,
) {
    record_row_with_outcome(
        state,
        "apply",
        key,
        &apply_request(run, step, kind, key),
        &outcome_line(key, step, status, code, message),
        &ok_response(
            &format!("disp_{step}"),
            &object(vec![("status", string(status))]),
        ),
    );
}

/// The canonical `hf-rpc-request/v1` line of one step dispatch (the shape the
/// daemon journals).
fn apply_request(run: &str, step: &str, kind: &str, key: &str) -> String {
    canonical_text(&object(vec![
        ("schema", string("hf-rpc-request/v1")),
        ("id", string(&format!("disp_{step}"))),
        ("method", string("apply")),
        (
            "params",
            object(vec![
                ("idempotency_key", string(key)),
                ("instance_id", string(run)),
                ("step", string(step)),
                (
                    "observed",
                    object(vec![
                        ("issue_revision", string(REV)),
                        ("policy_hash", string(POLICY_HASH)),
                    ]),
                ),
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
                ("profile", Val::Null),
            ]),
        ),
    ]))
}

/// Poll the durable supervision row until `predicate` holds or the deadline
/// passes. Returns the row it held plus how long it waited.
fn wait_for<F>(
    state: &Arc<Mutex<State>>,
    run: &str,
    predicate: F,
    deadline: Duration,
) -> Result<(SupervisionRow, Duration), String>
where
    F: Fn(&SupervisionRow) -> bool,
{
    let started = Instant::now();
    loop {
        {
            let guard = state.lock().expect("state");
            if let Some(row) = guard.supervision_by_id(run).expect("supervision read")
                && predicate(&row)
            {
                return Ok((row, started.elapsed()));
            }
        }
        if started.elapsed() >= deadline {
            let guard = state.lock().expect("state");
            return Err(format!(
                "no tick held the expected evidence within {deadline:?}; last row: {:?}",
                guard.supervision_by_id(run).expect("supervision read")
            ));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Wait until `count` successive frontiers have been recorded, then return
/// that fixed, counted prefix. A re-dispatch of the step that is STILL the
/// frontier adds no entry, so the read observes the evidence the driver
/// classified (which frontier it moved to), never how many ticks happened to
/// land inside one 50 ms sampling window (issue #295). When the deadline
/// passes first the caller gets the short prefix it holds, and its assertion
/// reports the frontier that never arrived.
fn wait_for_frontiers(
    dispatcher: &Arc<RecordingDispatch>,
    count: usize,
    deadline: Duration,
) -> Vec<String> {
    let started = Instant::now();
    loop {
        let mut frontiers = dispatcher.frontiers();
        if frontiers.len() >= count || started.elapsed() >= deadline {
            frontiers.truncate(count);
            return frontiers;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// The real driver over the fixture state, with the recording dispatch hook.
fn start_driver(
    state: &Arc<Mutex<State>>,
    dispatcher: &Arc<RecordingDispatch>,
) -> (SupervisorHandle, Arc<SupervisorWake>) {
    let handle = start(
        Arc::clone(state),
        SupervisorOptions {
            max_wait_secs: 1,
            pass_deadline_secs: PASS_DEADLINE_SECS,
            dispatch: Some(Arc::clone(dispatcher) as Arc<dyn SupervisedDispatch>),
        },
    );
    let wake = handle.wake_handle();
    (handle, wake)
}

/// AC2 (#268): the evidence recorded BETWEEN ticks is what the next tick
/// classifies from — read and parsed by the later pass, never a cache of the
/// earlier one.
#[test]
fn the_next_tick_classifies_the_evidence_recorded_since_the_last_one() {
    let fixture = Fixture::new(
        "new-evidence",
        &[("p1", "collect_outcome"), ("p2", "checkout")],
        &admission_doc(),
    );
    let dispatcher = Arc::new(RecordingDispatch::default());
    let (mut supervisor, wake) = start_driver(&fixture.state, &dispatcher);

    let (boot, boot_wait) = wait_for(
        &fixture.state,
        &fixture.run,
        |row| row.checks >= 1 && row.last_check_trigger == "boot",
        TICK_DEADLINE,
    )
    .expect("the boot pass commits a check");
    assert_eq!(
        boot.last_check_class, "healthy",
        "the untouched frontier is live"
    );
    assert_eq!(boot.last_check_reason, codes::DISPATCH);
    assert_eq!(
        dispatcher.steps(),
        vec!["p1".to_string()],
        "the boot check dispatches the frontier it classified"
    );

    // The evidence MOVES between ticks: the frontier step now has a recorded
    // non-succeeded attempt.
    {
        let state = fixture.state.lock().expect("state");
        record_attempt(
            &state,
            &fixture.run,
            "p1",
            "collect_outcome",
            "ik-268-new-evidence",
            "failed",
            canter::mutation::code::WORKER_TIMEOUT,
            "the worker did not report within its bound",
        );
    }

    let (later, later_wait) = wait_for(
        &fixture.state,
        &fixture.run,
        |row| row.checks > boot.checks && row.last_check_class == "worker-timeout",
        TICK_DEADLINE,
    )
    .expect("a LATER tick classifies the new evidence");
    assert_eq!(later.last_check_reason, codes::WORKER_TIMEOUT);
    assert_ne!(
        later.last_check_trigger, "boot",
        "the new evidence is classified by a later tick, not by a cache of the first"
    );
    assert_eq!(
        dispatcher.steps(),
        vec!["p1".to_string()],
        "a diagnosed frontier is never re-dispatched"
    );
    println!(
        "boot: class={} reason={} checks={} waited={:?}; later: class={} reason={} trigger={} \
         checks={} waited={:?}",
        boot.last_check_class,
        boot.last_check_reason,
        boot.checks,
        boot_wait,
        later.last_check_class,
        later.last_check_reason,
        later.last_check_trigger,
        later.checks,
        later_wait
    );

    // The read the classification used carries the row recorded between the
    // ticks, with its raw message (the durable evidence, not a cached verdict).
    let evidence = {
        let state = fixture.state.lock().expect("state");
        state
            .supervision_evidence(&fixture.run)
            .expect("evidence read")
            .expect("supervised run")
    };
    let failure = evidence
        .last_failure
        .as_ref()
        .expect("the run's newest recorded attempt is the standing failure");
    assert_eq!(failure.step, "p1");
    assert_eq!(failure.code, canter::mutation::code::WORKER_TIMEOUT);
    assert_eq!(
        failure.message,
        "the worker did not report within its bound"
    );
    assert!(
        evidence
            .attempts
            .iter()
            .any(|(step, status, code)| step == "p1"
                && status == "failed"
                && code == canter::mutation::code::WORKER_TIMEOUT),
        "the attempt ledger carries the row recorded between the ticks"
    );

    wake.signal_stop();
    assert!(supervisor.join(), "the driver stops cleanly");
}

/// AC3 (#268): a run whose worker SETTLES is still classified on the next tick
/// — the frontier moves with the evidence, in the driver's own dispatch intent.
#[test]
fn a_settled_worker_moves_the_frontier_on_the_next_tick() {
    let fixture = Fixture::new(
        "settled-worker",
        &[("p1", "prompt"), ("p2", "collect_outcome")],
        &admission_doc(),
    );
    let dispatcher = Arc::new(RecordingDispatch::default());
    let (mut supervisor, wake) = start_driver(&fixture.state, &dispatcher);

    let (boot, _) = wait_for(
        &fixture.state,
        &fixture.run,
        |row| row.checks >= 1,
        TICK_DEADLINE,
    )
    .expect("the boot pass commits a check");
    // The BOOT check dispatches the frontier it classified: the read is the
    // FIRST frontier the driver acted on (the fixed prefix of length 1), not
    // the whole recording — a later tick that lands before this read
    // re-dispatches the same live frontier, which is not what this assertion
    // observes (issue #295).
    assert_eq!(
        wait_for_frontiers(&dispatcher, 1, TICK_DEADLINE),
        vec!["p1".to_string()],
        "the boot check dispatches the frontier"
    );

    // The worker settles between ticks: p1 is recorded succeeded.
    {
        let state = fixture.state.lock().expect("state");
        record_attempt(
            &state,
            &fixture.run,
            "p1",
            "prompt",
            "ik-268-settled",
            "succeeded",
            "",
            "",
        );
    }

    let (advanced, waited) = wait_for(
        &fixture.state,
        &fixture.run,
        |row| row.checks > boot.checks,
        TICK_DEADLINE,
    )
    .expect("the next tick classifies the advanced frontier");
    assert_eq!(advanced.last_check_reason, codes::DISPATCH);
    // The frontier the NEXT check dispatched is the step the settled worker
    // moved the run to: read as the fixed, counted prefix of the frontiers
    // (p1 then p2) — the settled step is not re-dispatched and the next step
    // is, however many ticks re-dispatched the current frontier meanwhile
    // (issue #295).
    let frontiers = wait_for_frontiers(&dispatcher, 2, TICK_DEADLINE);
    assert_eq!(
        frontiers,
        vec!["p1".to_string(), "p2".to_string()],
        "the settled frontier step is not re-dispatched and the next step is"
    );
    println!(
        "frontier: boot intent={} next intent={} checks={} waited={:?}",
        frontiers[0], frontiers[1], advanced.checks, waited
    );

    wake.signal_stop();
    assert!(supervisor.join(), "the driver stops cleanly");
}

/// AC2 (#268): the read takes the run's OWN rows — a foreign run's rows (even
/// one presenting a conflicting topology and its own failure code) are never
/// read as this run's, and a recorded row this run owns is read whatever the
/// formatting of its line.
#[test]
fn the_read_takes_the_runs_own_rows_and_nothing_else() {
    let admission = admission_doc();
    let fixture = Fixture::new(
        "own-rows",
        &[("p1", "prompt"), ("p2", "collect_outcome")],
        &admission,
    );
    let head = "c".repeat(40);
    let base = "a".repeat(40);
    let foreign_root = fixture.dir.join("foreign-worktrees");
    std::fs::create_dir_all(&foreign_root).expect("foreign root");
    {
        let state = fixture.state.lock().expect("state");
        // (a) This run's OWN certified collection: the response binds the head,
        //     the branch and the base of its delivery.
        record_row_with_outcome(
            &state,
            "apply",
            "ik-268-collect",
            &apply_request(&fixture.run, "p2", "collect_outcome", "ik-268-collect"),
            &outcome_line("ik-268-collect", "p2", "succeeded", "", ""),
            &ok_response(
                "disp_p2",
                &object(vec![
                    ("head", string(&head)),
                    ("branch", string("issue-268-lane")),
                    ("base_head", string(&base)),
                ]),
            ),
        );
        // (b) An own row whose LINE is not canonically formatted (reordered
        //     keys, spaces around the separators): the same JSON the parsed
        //     readers always accepted, and the one a text-shaped identity
        //     predicate would miss.
        let hand_written = format!(
            r#"{{ "id" : "disp_p2", "method" : "apply",
                 "params" : {{ "step" : "p2", "idempotency_key" : "ik-268-hand-written",
                               "instance_id" : "{}" }},
                 "schema" : "hf-rpc-request/v1" }}"#,
            fixture.run
        );
        record_row_with_outcome(
            &state,
            "apply",
            "ik-268-hand-written",
            &hand_written,
            &outcome_line(
                "ik-268-hand-written",
                "p2",
                "failed",
                "hand.written.evidence",
                "recorded by a non-canonical writer",
            ),
            &ok_response("disp_p2", &object(vec![("status", string("failed"))])),
        );
        // (c) A FOREIGN run's rows: its own instance id, its own topology, its
        //     own failure code. Never this run's evidence.
        record_foreign(&state, &foreign_root);
        // (d) An own row whose line is not JSON at all: the parsed readers
        //     skipped such a line, and the identity predicate must not turn
        //     the whole read into an error on it (the query guards the JSON
        //     evaluation with `json_valid`).
        record_row(
            &state,
            "apply",
            "ik-268-unreadable",
            "not json at all",
            "{}",
        );
    }
    let state = fixture.state.lock().expect("state");

    let context = state
        .run_dispatch_context(&fixture.run)
        .expect("the run's own rows read without a conflict")
        .expect("the run recorded a topology");
    assert_eq!(
        context
            .topology
            .get("worktrees_root")
            .and_then(Val::as_str)
            .map(str::to_string),
        Some(fixture.dir.join("worktrees").display().to_string()),
        "the run's OWN topology is read, never the foreign run's conflicting one"
    );
    assert_eq!(
        context.admission.as_ref(),
        Some(&admission),
        "the run's own admission attestation is read"
    );
    assert_eq!(
        context.integration_base.as_deref(),
        Some(base.as_str()),
        "the run's own recorded integration base is read"
    );
    assert_eq!(
        context.feature_head.as_deref(),
        Some(head.as_str()),
        "the certified head is the run's own collection's"
    );
    let certificate = state
        .run_delivery_certificate(&fixture.run)
        .expect("certificate read")
        .expect("the run's collection certified a delivery");
    assert_eq!(certificate.step_id, "p2");
    assert_eq!(certificate.head, head);
    assert_eq!(certificate.branch, "issue-268-lane");

    let evidence = state
        .supervision_evidence(&fixture.run)
        .expect("evidence read")
        .expect("supervised run");
    assert!(
        evidence.has_dispatch_context,
        "the run's own recorded dispatch context is read"
    );
    assert!(
        evidence
            .attempts
            .iter()
            .any(|(step, status, code)| step == "p2" && status == "succeeded" && code.is_empty()),
        "the canonical own row is read: {:?}",
        evidence.attempts
    );
    assert!(
        evidence
            .attempts
            .iter()
            .any(|(step, status, code)| step == "p2"
                && status == "failed"
                && code == "hand.written.evidence"),
        "the non-canonically formatted own row is read too: {:?}",
        evidence.attempts
    );
    assert!(
        !evidence
            .attempts
            .iter()
            .any(|(_, _, code)| code == "foreign.evidence"),
        "the foreign run's rows are never read as this run's evidence: {:?}",
        evidence.attempts
    );

    // Positive control: the foreign rows ARE the foreign run's own evidence —
    // the read is per run, not a blanket exclusion.
    let foreign = state
        .run_dispatch_context(FOREIGN)
        .expect("foreign read")
        .expect("the foreign run recorded a topology");
    assert_eq!(
        foreign
            .topology
            .get("worktrees_root")
            .and_then(Val::as_str)
            .map(str::to_string),
        Some(foreign_root.display().to_string()),
        "the foreign rows are read as the FOREIGN run's own"
    );
}

/// Journal a foreign run's rows: its own instance id, its own topology and its
/// own recorded failure code.
fn record_foreign(state: &State, foreign_root: &Path) {
    let line = canonical_text(&object(vec![
        ("schema", string("hf-rpc-request/v1")),
        ("id", string("disp_p1")),
        ("method", string("apply")),
        (
            "params",
            object(vec![
                ("idempotency_key", string("ik-268-foreign")),
                ("instance_id", string(FOREIGN)),
                ("step", string("p1")),
                (
                    "topology",
                    object(vec![
                        ("integration_branch", string("staging")),
                        (
                            "worktrees_root",
                            string(&foreign_root.display().to_string()),
                        ),
                    ]),
                ),
            ]),
        ),
    ]));
    record_row_with_outcome(
        state,
        "apply",
        "ik-268-foreign",
        &line,
        &outcome_line(
            "ik-268-foreign",
            "p1",
            "failed",
            "foreign.evidence",
            "recorded by another run",
        ),
        &ok_response("disp_p1", &object(vec![("status", string("failed"))])),
    );
}
