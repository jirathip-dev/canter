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

    /// Record one further TERMINAL attempt of (run, step) with an outcome code
    /// (the shape the driver's evidence reads as the step's own diagnosis).
    fn seed_attempt(&self, step: &str, code: &str) {
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
            ("status", string("refused")),
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

#[test]
fn operator_reservation_wins_even_over_a_stale_automatic_intent() {
    let fixture = Fixture::new("operator");
    let now = time::unix_now();
    assert!(fixture.tick(now).is_err());
    let stale = fixture.intent().unwrap();
    let params = crate::run_control::retry_params("ik_fixture-operator-retry", &fixture.run, "p2");
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
    assert!(reserved[0].consumed_key.is_empty());
    assert!(fixture.intent().is_none());
    assert!(fixture.driver.dispatch_at(&stale, now + 5).is_err());
    assert_eq!(fixture.retries(), reserved);
    assert_eq!(fixture.attempts().len(), 2);
    std::fs::remove_dir(fixture.root.join("worktrees/lane")).unwrap();
    let material =
        read_dispatch_material(&fixture.shared.lock_state().unwrap(), &fixture.run, None).unwrap();
    let dispatch =
        dispatch_request_from(&material, "p2", None, "ik_fixture-operator-dispatch").unwrap();
    let response = method_apply(&fixture.shared, &dispatch);
    assert_eq!(
        Val::parse_json(&response)
            .unwrap()
            .get("ok")
            .and_then(Val::as_bool),
        Some(true),
        "{response}"
    );
    assert_eq!(
        fixture.retries()[0].consumed_key,
        "ik_fixture-operator-dispatch"
    );
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
    fixture.seed_attempt("p2", crate::mutation::code::VERDICT_STALE);
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
