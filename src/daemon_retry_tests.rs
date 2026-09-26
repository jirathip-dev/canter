//! Real apply/driver witnesses with a controlled backoff clock, no timer sleeps.
use super::*;
use crate::state::{QueueSubmissionItemPlan, QueueSubmissionPlan, SubmissionVerdict};
use crate::supervision::{check_plan, dispatch_intent};
use std::process::Command;

struct Fixture {
    shared: Arc<Shared>,
    driver: DaemonDispatch,
    run: String,
    root: PathBuf,
}

impl Fixture {
    fn new(name: &str) -> Self {
        let root =
            std::env::temp_dir().join(format!("canter-auto-retry-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let paths = DaemonPaths {
            state_dir: root.clone(),
            runtime_dir: root.clone(),
            socket_path: root.join("sock"),
            lock_path: root.join("lock"),
            db_path: root.join("state.db"),
            audit_mirror_path: root.join("audit.jsonl"),
            events_mirror_path: root.join("events.jsonl"),
            backups_dir: root.join("backups"),
            checkpoints_dir: root.join("checkpoints"),
            log_path: root.join("daemon.log"),
        };
        let state = Arc::new(Mutex::new(
            State::open(&paths.db_path, crate::state::Retention::default()).unwrap(),
        ));
        let mut supervisor = crate::supervision::start(Arc::clone(&state), Default::default());
        let wake = supervisor.wake_handle();
        wake.signal_stop();
        assert!(supervisor.join());
        let shared = Arc::new(Shared {
            state,
            hub: Mutex::new(Hub::new(0)),
            log: DaemonLog::open(&paths.log_path).unwrap(),
            paths,
            pid: std::process::id(),
            started_at: time::rfc3339_now(),
            running: AtomicBool::new(true),
            supervisor: wake,
        });
        let steps = Val::Arr(vec![
            object(vec![
                ("id", string("p1")),
                ("kind", string("checkout")),
                ("params", object(vec![("ref", string("staging"))])),
            ]),
            object(vec![
                ("id", string("p2")),
                ("kind", string("worktree_create")),
                (
                    "params",
                    object(vec![
                        ("worktree", string("lane")),
                        ("branch", string("retry-lane")),
                    ]),
                ),
            ]),
            object(vec![
                ("id", string("p3")),
                ("kind", string("checkout")),
                ("params", object(vec![("ref", string("staging"))])),
            ]),
        ]);
        let run = {
            let state = shared.lock_state().unwrap();
            let epoch = state.current_epoch().unwrap();
            let grant = object(vec![
                ("schema", string("hf-grant/v1")),
                ("grant_id", string("gr_0123456789abcdef")),
                ("repository", string("example-org/widgets")),
                (
                    "issue",
                    object(vec![
                        ("number", integer(5)),
                        ("revision", string(&"c".repeat(40))),
                    ]),
                ),
                ("workflow_hash", string(&"a".repeat(64))),
                ("policy_hash", string(&"b".repeat(64))),
                ("phase", string("merge")),
                ("scope", string("worktrees/issues/5")),
                ("caps", Val::Arr(vec![string("read"), string("worktree")])),
                ("expires_at", string("2999-01-01T00:00:00Z")),
                ("state_epoch", integer(epoch)),
                ("created_at", string("2026-01-01T00:00:00Z")),
            ]);
            state.issue_grant(&grant).unwrap();
            let (_, items) = state
                .submit_queue_run(&QueueSubmissionPlan {
                    submission_id: "qs_0123456789abcdef".into(),
                    repository: "example-org/widgets".into(),
                    state_epoch: epoch,
                    digest: "d".repeat(64),
                    role_key: "worker".into(),
                    role_revision: "e".repeat(64),
                    workflow_id: crate::plan::DOCTRINE_WORKFLOW_ID.into(),
                    workflow_hash: "a".repeat(64),
                    boundary_phase: "merge".into(),
                    integration_branch: "staging".into(),
                    completion_branch: "staging".into(),
                    boundary_caps: vec!["read".into(), "worktree".into()],
                    request_line: canonical_text(&object(vec![("steps", steps)])),
                    admission_caps: crate::lifecycle::ConcurrencyCaps {
                        global: 4,
                        per_repository: 2,
                        per_harness: 2,
                    },
                    harness_lanes: Some(0),
                    items: vec![QueueSubmissionItemPlan {
                        ordinal: 0,
                        work_item: "#5".into(),
                        issue_number: 5,
                        issue_revision: "c".repeat(40),
                        grant_id: Some("gr_0123456789abcdef".into()),
                        resume_digest: None,
                        verdict: SubmissionVerdict::Approved,
                    }],
                    supervision: Some(crate::state::SupervisionAuthorizationPlan {
                        desired: "armed".into(),
                        check_interval_secs: 5,
                        progress_timeout_secs: 60,
                    }),
                    at: time::rfc3339_now(),
                })
                .unwrap();
            items[0].instance_id.clone().unwrap()
        };
        let repo = root.join("integration");
        std::fs::create_dir_all(&repo).unwrap();
        for args in [
            vec!["init", "-q", "-b", "staging"],
            vec!["remote", "add", "origin", "."],
            vec!["config", "user.email", "test@example.invalid"],
            vec!["config", "user.name", "test"],
            vec!["commit", "--allow-empty", "-q", "-m", "base"],
        ] {
            assert!(
                Command::new("git")
                    .args(args)
                    .current_dir(&repo)
                    // #226: copy nothing from the host's shared git templates.
                    .env("GIT_TEMPLATE_DIR", "")
                    .status()
                    .unwrap()
                    .success()
            );
        }
        let topology = object(vec![
            ("integration_branch", string("staging")),
            ("production_branches", Val::Arr(vec![string("main")])),
            ("integration_repo", string(&repo.display().to_string())),
            (
                "worktrees_root",
                string(&root.join("worktrees").display().to_string()),
            ),
        ]);
        let material =
            read_dispatch_material(&shared.lock_state().unwrap(), &run, Some(&topology)).unwrap();
        let first = dispatch_request_from(&material, "p1", None, "ik_fixture-first").unwrap();
        let response = method_apply(&shared, &first);
        assert_eq!(
            Val::parse_json(&response)
                .unwrap()
                .get("ok")
                .and_then(Val::as_bool),
            Some(true),
            "{response}"
        );
        let driver = DaemonDispatch {
            shared: std::sync::OnceLock::from(Arc::clone(&shared)),
            refusals: Default::default(),
            collecting: Default::default(),
        };
        // A complete but obstructed effect returns a real typed refusal.
        std::fs::create_dir_all(root.join("worktrees/lane")).unwrap();
        Self {
            shared,
            driver,
            run,
            root,
        }
    }

    fn intent(&self) -> Option<crate::supervision::DispatchIntent> {
        let state = self.shared.lock_state().unwrap();
        let row = state.supervision_by_id(&self.run).unwrap().unwrap();
        let evidence = state.supervision_evidence(&self.run).unwrap().unwrap();
        dispatch_intent(&row, &evidence)
    }

    fn tick(&self, now: i64) -> Result<String, String> {
        let intent = {
            let state = self.shared.lock_state().unwrap();
            let row = state.supervision_by_id(&self.run).unwrap().unwrap();
            let evidence = state.supervision_evidence(&self.run).unwrap().unwrap();
            let plan = check_plan(&row, &evidence, None, false, now);
            let intent = plan
                .dispatch
                .clone()
                .expect("armed frontier has a dispatch");
            state.commit_supervision_check(&plan).unwrap();
            intent
        };
        self.driver.dispatch_at(&intent, now)
    }

    fn retries(&self) -> Vec<crate::state::RunRetryRow> {
        self.shared
            .lock_state()
            .unwrap()
            .run_retries(&self.run)
            .unwrap()
    }

    fn attempts(&self) -> Vec<(String, String)> {
        self.shared
            .lock_state()
            .unwrap()
            .run_step_attempts(&self.run)
            .unwrap()
    }

    /// Record one further TERMINAL attempt of (run, step) with an outcome
    /// status and code (the shape the driver's evidence reads as the step's
    /// own diagnosis).
    fn seed_attempt(&self, step: &str, status: &str, code: &str) {
        let key = format!("ik_seed-{step}-{}", code.rsplit('.').next().unwrap());
        let request_id = "f00dfeed".to_string();
        let line = canonical_text(&object(vec![
            ("schema", string("hf-rpc-request/v1")),
            ("id", string(&request_id)),
            ("method", string("apply")),
            (
                "params",
                object(vec![
                    ("idempotency_key", string(&key)),
                    ("instance_id", string(&self.run)),
                    ("step", string(step)),
                ]),
            ),
        ]));
        let state = self.shared.lock_state().unwrap();
        state
            .journal_intent(
                "mutate.checkout",
                &format!("canter:{}:{step}", self.run),
                &key,
                &request_id,
                "apply",
                None,
                None,
                &line,
            )
            .expect("claim the seeded attempt");
        let outcome = canonical_text(&object(vec![
            ("schema", string("hf-outcome/v1")),
            ("plan_id", string("hf_plan_0000000000000000")),
            ("step_id", string(step)),
            ("status", string(status)),
            ("idempotency_key", string(&key)),
            ("observed_at", string("2026-09-18T13:04:41Z")),
            ("result", Val::Null),
            (
                "error",
                object(vec![
                    ("schema", string("hf-error/v1")),
                    ("code", string(code)),
                    ("message", string("recorded fixture diagnosis")),
                    ("retryable", Val::Bool(false)),
                ]),
            ),
        ]));
        state
            .resolve_claim(&key, "apply", "spent", &outcome, Some("{}"))
            .expect("resolve the seeded attempt");
    }

    /// Journal ONE apply claim for (run, step) and leave it IN FLIGHT — the
    /// exact durable state a daemon killed with the effect unresolved leaves
    /// behind (issue #307: "the first attempt simply never resolved").
    /// Returns the claim key.
    fn seed_inflight_attempt(&self, step: &str, stem: &str) -> String {
        let key = format!("ik_seed-{step}-{stem}");
        let request_id = "f00dfeed".to_string();
        let line = canonical_text(&object(vec![
            ("schema", string("hf-rpc-request/v1")),
            ("id", string(&request_id)),
            ("method", string("apply")),
            (
                "params",
                object(vec![
                    ("idempotency_key", string(&key)),
                    ("instance_id", string(&self.run)),
                    ("step", string(step)),
                ]),
            ),
        ]));
        let state = self.shared.lock_state().unwrap();
        state
            .journal_intent(
                "mutate.checkout",
                &format!("canter:{}:{step}", self.run),
                &key,
                &request_id,
                "apply",
                None,
                None,
                &line,
            )
            .expect("journal the in-flight claim");
        key
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.root).unwrap();
    }
}

#[test]
fn armed_refused_step_retries_itself_and_advances_without_operator_keys() {
    let fixture = Fixture::new("advance");
    let now = time::unix_now();
    assert!(fixture.tick(now).is_err());
    assert_eq!(
        fixture.attempts().last().unwrap(),
        &("p2".into(), "refused".into())
    );
    assert!(fixture.retries().is_empty());
    std::fs::remove_dir(fixture.root.join("worktrees/lane")).unwrap();
    assert!(fixture.tick(now + 4).unwrap_err().contains("backoff"));
    assert!(fixture.retries().is_empty(), "backoff cannot burn a retry");
    fixture
        .tick(now + 5)
        .expect("automatic retry advances the refused step");
    assert_eq!(fixture.intent().unwrap().step_id, "p3");
    fixture.tick(now + 6).unwrap();
    let retries = fixture.retries();
    assert_eq!(retries.len(), 1);
    assert_eq!(retries[0].attempt, 1);
    assert!(!retries[0].consumed_at.is_empty());
    assert!(retries[0].consumed_key.starts_with("ik_run-"));
    let state = fixture.shared.lock_state().unwrap();
    let claim = state.claim(&retries[0].consumed_key).unwrap().unwrap();
    assert_eq!(claim.method, "apply");
    assert!(claim.request_line.contains("p2"));
    let (_, journal) = state.journal_tail(0, 1000).unwrap();
    assert!(
        !journal.iter().any(|line| line.contains("mutate.run.retry")),
        "zero operator keys"
    );
    assert_eq!(
        state
            .instance_by_id(&fixture.run)
            .unwrap()
            .unwrap()
            .current_node,
        "p3"
    );
}

#[test]
fn repeated_refusal_exhausts_three_retries_and_fences_the_frontier() {
    let fixture = Fixture::new("exhaust");
    let now = time::unix_now();
    for (offset, count) in [(0, 0), (5, 1), (15, 2), (35, 3)] {
        assert!(
            fixture
                .tick(now + offset)
                .unwrap_err()
                .contains("refusal.worktree.exists")
        );
        assert_eq!(fixture.retries().len(), count);
        if count < 3 {
            assert!(
                fixture
                    .tick(now + offset + 1)
                    .unwrap_err()
                    .contains("backoff")
            );
            assert_eq!(fixture.retries().len(), count);
        }
    }
    let before = fixture.attempts();
    assert_eq!(before.iter().filter(|(step, _)| step == "p2").count(), 4);
    assert!(fixture.intent().is_none());
    let state = fixture.shared.lock_state().unwrap();
    let row = state.supervision_by_id(&fixture.run).unwrap().unwrap();
    let evidence = state.supervision_evidence(&fixture.run).unwrap().unwrap();
    for offset in [100, 1000, 10000] {
        let plan = check_plan(&row, &evidence, None, false, now + offset);
        assert!(plan.dispatch.is_none());
        assert_eq!(plan.class, "needs-attention");
        assert_eq!(plan.reason, crate::supervision::codes::STEP_DIAGNOSED);
        assert!(!plan.eligible);
        state.commit_supervision_check(&plan).unwrap();
    }
    let verdict = crate::supervision::classify(
        &evidence,
        &row.authorization_digest,
        &crate::supervision::Policy {
            check_interval_secs: 5,
            progress_timeout_secs: 60,
        },
        now + 10000,
    );
    assert_eq!(verdict.detail, "refusal.worktree.exists");
    assert_eq!(state.run_step_attempts(&fixture.run).unwrap(), before);
    assert_eq!(
        state
            .run_retries(&fixture.run)
            .unwrap()
            .iter()
            .map(|row| row.attempt)
            .collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
}

/// Issue #241: an authorization the run already HOLDS is not a park. The
/// armed driver derives its dispatch for that exact step, and the FIRST
/// dispatch to reach the engine spends it — exactly once, recorded under the
/// automatic dispatch's own journaled key. (Before the change the reservation
/// blocked the driver: the run stayed parked until an operator dispatched by
/// hand.)
#[test]
fn a_held_authorization_is_consumed_by_supervision_exactly_once() {
    let fixture = Fixture::new("held-consumed");
    let now = time::unix_now();
    // One real dispatch records the diagnosis (the obstructed worktree).
    assert!(fixture.tick(now).is_err());
    // The operator authorizes ONE bounded retry — the issue's exact control —
    // and nothing else.
    let params = crate::run_control::retry_params("ik_fixture-held-retry", &fixture.run, "p2");
    let request = Request {
        id: "01234567".into(),
        method: "run.retry".into(),
        params: Some(params),
        line: String::new(),
    };
    let response = method_run_retry(&fixture.shared, &request);
    assert_eq!(
        Val::parse_json(&response)
            .unwrap()
            .get("ok")
            .and_then(Val::as_bool),
        Some(true),
        "{response}"
    );
    let reserved = fixture.retries();
    assert_eq!(reserved.len(), 1);
    assert!(
        reserved[0].consumed_key.is_empty(),
        "minting the authorization consumes nothing"
    );
    // The held authorization IS dispatchable: the driver derives the
    // continuation of exactly that step.
    let held = fixture
        .intent()
        .expect("a held authorization is not a park");
    assert_eq!(held.step_id, "p2");
    // The re-dispatch the authorization pays for reaches the engine (the
    // obstruction still refuses the effect) and spends it exactly once.
    assert!(
        fixture
            .driver
            .dispatch_at(&held, now + 5)
            .unwrap_err()
            .contains("refusal.worktree.exists")
    );
    let spent = fixture.retries();
    assert_eq!(spent.len(), 1, "one authorization, never a second row");
    assert_eq!(spent[0].attempt, 1);
    assert!(!spent[0].consumed_at.is_empty());
    assert!(spent[0].consumed_key.starts_with("ik_run-"), "{spent:?}");
    let state = fixture.shared.lock_state().unwrap();
    let claim = state.claim(&spent[0].consumed_key).unwrap().unwrap();
    assert_eq!(claim.method, "apply");
    assert!(claim.request_line.contains("p2"));
    drop(state);
    // A SECOND re-dispatch of the same step, with no fresh authorization,
    // refuses the engine's own typed code before any effect — and spends
    // nothing: a consumed authorization is never spent twice.
    let material =
        read_dispatch_material(&fixture.shared.lock_state().unwrap(), &fixture.run, None).unwrap();
    let second =
        dispatch_request_from(&material, "p2", None, "ik_fixture-second-dispatch").unwrap();
    let response = method_apply(&fixture.shared, &second);
    assert!(
        response.contains(crate::mutation::code::RETRY_REQUIRED),
        "{response}"
    );
    assert_eq!(
        fixture.retries(),
        spent,
        "a consumed authorization is never spent twice"
    );
}

/// Issue #241 (AC1) in the issue's OWN shape: a recorded AMBIGUOUS effect
/// (`effect.review_timeout`) plus an authorized bounded retry. The held
/// authorization is consumed by supervision's own re-dispatch — no operator
/// dispatch exists anywhere — and the run advances.
#[test]
fn an_authorized_retry_advances_an_ambiguous_review_timeout_without_an_operator() {
    let fixture = Fixture::new("ambiguous-held");
    let now = time::unix_now();
    assert!(fixture.tick(now).is_err());
    fixture.seed_attempt("p2", "ambiguous", crate::mutation::code::REVIEW_TIMEOUT);
    // The operator authorizes the bounded retry (and dispatches nothing).
    let params = crate::run_control::retry_params("ik_fixture-ambiguous-retry", &fixture.run, "p2");
    let request = Request {
        id: "01234567".into(),
        method: "run.retry".into(),
        params: Some(params),
        line: String::new(),
    };
    let response = method_run_retry(&fixture.shared, &request);
    assert_eq!(
        Val::parse_json(&response)
            .unwrap()
            .get("ok")
            .and_then(Val::as_bool),
        Some(true),
        "{response}"
    );
    // Supervision consumes the authorization itself, and the step lands.
    let intent = fixture
        .intent()
        .expect("the held authorization is dispatchable");
    assert_eq!(intent.step_id, "p2");
    std::fs::remove_dir(fixture.root.join("worktrees/lane")).unwrap();
    fixture
        .driver
        .dispatch_at(&intent, now + 5)
        .expect("the authorized re-dispatch lands the step");
    let retries = fixture.retries();
    assert_eq!(retries.len(), 1, "the HELD authorization was the one spent");
    assert!(
        retries[0].consumed_key.starts_with("ik_run-"),
        "{retries:?}"
    );
    assert_eq!(
        fixture.intent().unwrap().step_id,
        "p3",
        "the frontier moved on"
    );
    // Zero operator dispatch: the run's own supervision performed the act.
    let state = fixture.shared.lock_state().unwrap();
    let (_, journal) = state.journal_tail(0, 1000).unwrap();
    assert!(
        !journal
            .iter()
            .any(|line| line.contains("mutate.run.dispatch")),
        "no operator dispatch exists"
    );
}

/// Issue #241: the SAME act for the class the issue names — a worker timeout
/// is a park for supervision's own retries, and an explicitly authorized
/// bounded retry is exactly the act that unparks it.
#[test]
fn an_authorized_retry_unparks_a_worker_timeout_frontier() {
    let fixture = Fixture::new("worker-timeout-held");
    let now = time::unix_now();
    assert!(fixture.tick(now).is_err());
    fixture.seed_attempt("p2", "ambiguous", crate::mutation::code::WORKER_TIMEOUT);
    assert!(
        fixture.intent().is_none(),
        "a worker timeout is a park for supervision's own retries"
    );
    let params = crate::run_control::retry_params("ik_fixture-timeout-retry", &fixture.run, "p2");
    let request = Request {
        id: "01234567".into(),
        method: "run.retry".into(),
        params: Some(params),
        line: String::new(),
    };
    let response = method_run_retry(&fixture.shared, &request);
    assert_eq!(
        Val::parse_json(&response)
            .unwrap()
            .get("ok")
            .and_then(Val::as_bool),
        Some(true),
        "{response}"
    );
    // The authorization is the act that makes the frontier dispatchable...
    let intent = fixture
        .intent()
        .expect("the held authorization is dispatchable");
    assert_eq!(intent.step_id, "p2");
    // ...and the re-dispatch it pays for spends it exactly once.
    std::fs::remove_dir(fixture.root.join("worktrees/lane")).unwrap();
    fixture
        .driver
        .dispatch_at(&intent, now + 5)
        .expect("the authorized re-dispatch lands the step");
    let retries = fixture.retries();
    assert_eq!(retries.len(), 1);
    assert!(
        retries[0].consumed_key.starts_with("ik_run-"),
        "{retries:?}"
    );
    assert_eq!(fixture.intent().unwrap().step_id, "p3");
}

/// Issue #200 (AC2): a frontier whose recorded diagnosis is a MOVED certified
/// head (`refusal.evidence.verdict_stale`) is an impossible step. However
/// often the supervision check runs, it is never re-dispatched and the run's
/// bounded retries stay UNSPENT; a stale dispatch intent of that step (minted
/// before the refusal was recorded) cannot make the daemon spend one either.
#[test]
fn a_moved_head_diagnosis_never_spends_a_bounded_retry() {
    let fixture = Fixture::new("moved-head-park");
    let now = time::unix_now();
    // One real dispatch records the run's own dispatch context (topology).
    assert!(fixture.tick(now).is_err());
    let before_tick = fixture.attempts();
    fixture.seed_attempt("p2", "refused", crate::mutation::code::VERDICT_STALE);
    assert!(
        fixture.intent().is_none(),
        "the recorded moved-head refusal parks the frontier"
    );
    let before = fixture.attempts();
    assert_eq!(
        before.len(),
        before_tick.len() + 1,
        "the fixture recorded exactly one further attempt"
    );
    let state = fixture.shared.lock_state().unwrap();
    let row = state.supervision_by_id(&fixture.run).unwrap().unwrap();
    let evidence = state.supervision_evidence(&fixture.run).unwrap().unwrap();
    for offset in [1, 5, 15, 35, 100, 1000, 10000] {
        let plan = check_plan(&row, &evidence, None, false, now + offset);
        assert!(plan.dispatch.is_none(), "no re-dispatch is ever authorized");
        assert_eq!(plan.class, "needs-attention");
        assert_eq!(
            plan.reason,
            crate::supervision::codes::STEP_DIAGNOSED,
            "the recorded code is named as the frontier's own diagnosis"
        );
        assert!(!plan.eligible);
        state.commit_supervision_check(&plan).unwrap();
    }
    drop(state);
    assert_eq!(fixture.attempts(), before, "no further attempt is made");
    assert!(
        fixture.retries().is_empty(),
        "an impossible step never spends a bounded retry"
    );
    // A stale intent of the same step cannot make the daemon spend one either:
    // the supervised recheck refuses it and records no new attempt.
    let stale = crate::supervision::DispatchIntent {
        instance_id: fixture.run.clone(),
        step_id: "p2".into(),
        kind: "worktree_create".into(),
        reason: crate::supervision::codes::DISPATCH,
    };
    let refused = fixture
        .driver
        .dispatch_at(&stale, now + 20000)
        .expect_err("the supervised frontier is held");
    assert!(
        refused.contains(crate::mutation::code::RETRY_REQUIRED),
        "{refused}"
    );
    assert!(
        fixture.retries().is_empty(),
        "the daemon spends nothing on an impossible step"
    );
    assert_eq!(fixture.attempts(), before, "and records no new attempt");
}

/// One git invocation inside `dir` (the fixture's own repositories).
fn git_in(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .args(args)
        .current_dir(dir)
        // #226: copy nothing from the host's shared git templates.
        .env("GIT_TEMPLATE_DIR", "")
        .output()
        .expect("spawn git");
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Issue #282: the lane the step is about to materialize is still REGISTERED
/// by the integration clone while its directory is GONE — the host state a
/// re-dispatch died on, and each death was charged to the run's bounded retry
/// budget (three of them wedged the run at `refusal.run.retry_bound`, so it
/// could neither re-dispatch nor terminate while still holding its counted
/// per-repository slot). The cause is stale host state with a mechanical
/// remedy, so the run's own dispatch clears the registration for exactly that
/// path and the step LANDS: the raw retry rows are empty BEFORE and AFTER, the
/// run advances, and no operator key was used.
#[test]
fn a_missing_but_registered_lane_is_repaired_without_spending_a_bounded_retry() {
    let fixture = Fixture::new("stale-registration");
    let now = time::unix_now();
    let lane = fixture.root.join("worktrees/lane");
    let integration = fixture.root.join("integration");
    // The measured host state: git still registers the lane checkout, its
    // directory has been deleted from under the registration.
    std::fs::remove_dir(&lane).expect("the obstruction is replaced by the measurement");
    git_in(
        &integration,
        &[
            "worktree",
            "add",
            "--detach",
            lane.to_str().unwrap(),
            "staging",
        ],
    );
    std::fs::remove_dir_all(&lane).expect("deleted by hand, exactly as measured");
    assert!(!lane.exists(), "the checkout is gone");
    assert!(
        git_in(&integration, &["worktree", "list"]).contains("worktrees/lane"),
        "the registration is still there, and git calls it prunable"
    );

    // Raw retry rows BEFORE the dispatch: the run has spent nothing.
    assert!(fixture.retries().is_empty(), "before: no retry row exists");

    // The run's own supervision dispatches the step with zero operator keys.
    fixture
        .tick(now)
        .expect("the run's own dispatch repairs the stale registration and lands p2");
    assert_eq!(
        fixture.attempts().last().unwrap(),
        &("p2".into(), "succeeded".into())
    );

    // Raw retry rows AFTER: still none — a mechanical host-state repair is
    // never charged to the run's bounded retry budget.
    assert!(
        fixture.retries().is_empty(),
        "after: the repairable host condition spent no bounded retry"
    );

    // The run ADVANCED under its own machinery — the recorded attempt ledger
    // is authoritative, so the frontier is the step AFTER the one the stale
    // registration blocked — and the same supervision drives that next step to
    // its own success: nothing here is wedged at a bound.
    assert_eq!(
        fixture.intent().unwrap().step_id,
        "p3",
        "the frontier moved past the step the stale registration blocked"
    );
    fixture
        .tick(now + 6)
        .expect("the run's own supervision drives the next step");
    assert_eq!(
        fixture.attempts().last().unwrap(),
        &("p3".into(), "succeeded".into())
    );
    assert!(
        fixture.retries().is_empty(),
        "the whole advance spent no bounded retry"
    );
    let (_, journal) = fixture
        .shared
        .lock_state()
        .unwrap()
        .journal_tail(0, 1000)
        .unwrap();
    assert!(
        !journal.iter().any(|line| line.contains("retry_bound")),
        "nothing was charged to the bound: {journal:?}"
    );

    // The lane exists again at the recorded base, and its registration is
    // coherent: it is the linked worktree of the integration clone.
    assert!(lane.is_dir(), "the lane was created");
    assert_eq!(
        git_in(&lane, &["rev-parse", "--verify", "HEAD"]).trim(),
        git_in(&integration, &["rev-parse", "--verify", "staging"]).trim(),
        "the re-created lane is at the recorded base"
    );
    let listed = git_in(&integration, &["worktree", "list"]);
    assert!(
        !listed.contains("prunable"),
        "no stale registration is left behind: {listed}"
    );
}

/// Issue #282 (AC4 — no over-broadening): the repair addresses ONE host
/// condition and nothing else. A lane whose checkout is PRESENT — the
/// obstruction the retry witnesses above use — is never touched by it: the
/// step still refuses `refusal.worktree.exists`, a genuine failure still
/// consumes its bounded retry exactly as before, and the budget still fences
/// the frontier when it is spent.
#[test]
fn a_present_lane_is_never_repaired_and_still_consumes_its_bounded_retries() {
    let fixture = Fixture::new("present-control");
    let now = time::unix_now();
    let lane = fixture.root.join("worktrees/lane");
    assert!(lane.is_dir(), "the fixture's obstructed lane is present");
    for (offset, count) in [(0, 0), (5, 1), (15, 2), (35, 3)] {
        assert!(
            fixture
                .tick(now + offset)
                .unwrap_err()
                .contains("refusal.worktree.exists"),
            "a genuine obstruction is still refused typed"
        );
        assert_eq!(fixture.retries().len(), count, "charged exactly as today");
        assert!(
            lane.is_dir(),
            "a present checkout is never addressed by the repair"
        );
    }
    assert!(
        fixture.intent().is_none(),
        "the frontier is still fenced once the budget is spent on real failures"
    );
}

/// Issue #307: a daemon restart (or any interrupted-claim reconciliation)
/// re-dispatched a mid-flight step and charged the RUN a bounded retry for a
/// cause the run does not own. The in-flight claim's interruption is the
/// daemon's own lifecycle event — nothing about the work changed and nothing
/// was refused typed — so the run's ledger shows it separately (the
/// reconciled claim outcome + the `reconcile.*` journal record) and charges
/// ZERO retries, while the run's own next diagnosis still spends exactly one.
#[test]
fn a_restart_interrupted_claim_reconciles_without_charging_the_runs_bounded_retry() {
    let fixture = Fixture::new("restart-interrupted");
    let now = time::unix_now();
    // The daemon died with p2's effect in flight: the claim is journaled and
    // never resolved (the measured shape — "NO outcome row ever").
    let interrupted_key = fixture.seed_inflight_attempt("p2", "307-inflight");
    assert_eq!(
        fixture
            .shared
            .lock_state()
            .unwrap()
            .claims_in_flight()
            .unwrap()
            .len(),
        1,
        "exactly the interrupted claim is in flight when the process died"
    );
    // The next boot reconciles BEFORE it serves, through the daemon's OWN
    // restart-reconciliation function.
    let reconciled = {
        let state = fixture.shared.lock_state().unwrap();
        reconcile_claims(
            &state,
            &fixture.shared.log,
            &fixture.shared.paths.checkpoints_dir,
        )
        .unwrap()
    };
    assert_eq!(reconciled, 1, "the in-flight claim is the one reconciled");
    // The interruption is its OWN recorded fact: the reconciled claim outcome
    // carries the daemon's interruption code, the journal carries the
    // reconcile record, and the run's retry ledger carries NOTHING.
    {
        let state = fixture.shared.lock_state().unwrap();
        let claim = state.claim(&interrupted_key).unwrap().unwrap();
        assert_eq!(claim.status, "ambiguous");
        let outcome = Val::parse_json(claim.outcome.as_deref().unwrap()).unwrap();
        assert_eq!(
            outcome
                .get("error")
                .and_then(|error| error.get("code"))
                .and_then(Val::as_str),
            Some(crate::state::INTERRUPTED_CODE)
        );
        let (_, journal) = state.journal_tail(0, 1000).unwrap();
        assert!(
            journal.iter().any(|line| line.contains("reconcile.apply")),
            "the reconcile record is its own journal row"
        );
        assert_eq!(
            state
                .run_step_attempts(&fixture.run)
                .unwrap()
                .last()
                .unwrap(),
            &("p2".to_string(), "ambiguous".to_string()),
            "the interruption is the step's newest recorded attempt"
        );
    }
    assert!(
        fixture.retries().is_empty(),
        "reconciliation charges nothing: {:?}",
        fixture.retries()
    );
    // The driver's continuation of the interrupted step is a plain dispatch —
    // no park, and no authorization demanded for a daemon lifecycle event.
    let intent = fixture
        .intent()
        .expect("the interrupted step's continuation is dispatchable");
    assert_eq!(intent.step_id, "p2");
    assert_eq!(intent.reason, crate::supervision::codes::DISPATCH);
    // The resumed step resolves through the REAL apply engine: un-obstruct the
    // effect, let the driver re-dispatch it, and watch it land.
    std::fs::remove_dir(fixture.root.join("worktrees/lane")).unwrap();
    fixture
        .tick(now)
        .expect("the interrupted step resolves on its own re-dispatch");
    assert!(
        fixture.retries().is_empty(),
        "an interrupted in-flight effect charges the run NOTHING: {:?}",
        fixture.retries()
    );
    let attempts = fixture.attempts();
    assert_eq!(
        attempts
            .iter()
            .filter(|(step, status)| step == "p2" && status == "ambiguous")
            .count(),
        1,
        "the interruption stays visible as its own attempt: {attempts:?}"
    );
    assert_eq!(
        attempts.last().unwrap(),
        &("p2".to_string(), "succeeded".to_string()),
        "the step's effect resolves once, typed and journaled"
    );
    {
        let state = fixture.shared.lock_state().unwrap();
        assert_eq!(
            state
                .instance_by_id(&fixture.run)
                .unwrap()
                .unwrap()
                .current_node,
            "p2",
            "the run's last achieved step is the interrupted one, resolved exactly once"
        );
        let (_, journal) = state.journal_tail(0, 1000).unwrap();
        assert!(
            !journal.iter().any(|line| line.contains("mutate.run.retry")),
            "zero operator keys anywhere in the drive"
        );
    }
    // Control: the SAME fixture, one diagnosis the run owns. The fence is
    // exactly as tight as before — one bounded retry, minted and consumed by
    // the dispatch it pays for — and the interruption never counted against
    // the budget (this is attempt 1, not 2).
    fixture.seed_attempt("p3", "ambiguous", crate::mutation::code::REVIEW_TIMEOUT);
    fixture
        .tick(now + 5)
        .expect("a diagnosed step is re-dispatched within the budget");
    let retries = fixture.retries();
    assert_eq!(retries.len(), 1, "exactly one bounded retry: {retries:?}");
    assert_eq!(retries[0].step_id, "p3");
    assert_eq!(retries[0].attempt, 1);
    assert!(
        !retries[0].consumed_at.is_empty(),
        "the retry is consumed by the dispatch it pays for"
    );
    assert!(
        retries[0].consumed_key.starts_with("ik_run-"),
        "{retries:?}"
    );
}
