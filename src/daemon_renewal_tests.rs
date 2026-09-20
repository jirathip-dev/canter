//! Issue #184 witnesses: a live run renews its OWN lapsed authorization
//! window, a lapse is never a step diagnosis, and a genuinely unauthorized
//! continuation still refuses.
//!
//! Real git effects, the durable State APIs and the daemon's own
//! apply/dispatch code. The engine only ever mints window INSIDE the future,
//! so a lapse is staged the way the live window actually lapsed: the window
//! was minted live and then expired (one raw update on the fixture's OWN
//! disposable state database, never on live state).
use super::*;
use crate::state::{QueueSubmissionItemPlan, QueueSubmissionPlan, SubmissionVerdict};
use crate::supervision::{check_plan, dispatch_intent};
use std::process::Command;

/// The instant a lapsed fixture window expires at: unambiguously past.
const LAPSED: &str = "2000-01-01T00:00:00Z";

struct Fixture {
    shared: Arc<Shared>,
    driver: DaemonDispatch,
    run: String,
    grant: String,
    root: PathBuf,
    repo: PathBuf,
}

/// The ordinary engine-driven spine of the fixture: one checkout (the
/// prefix), the lane's own worktree round trip, and the closing checkout.
fn three_steps() -> Vec<Val> {
    vec![
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
                    ("branch", string("impl-184-lane")),
                ]),
            ),
        ]),
        object(vec![
            ("id", string("p3")),
            ("kind", string("checkout")),
            ("params", object(vec![("ref", string("staging"))])),
        ]),
    ]
}

impl Fixture {
    /// One admitted run under `steps`, one live grant and (when `arm`) an
    /// armed supervision row. `start` also dispatches the spine's first step
    /// with the caller's topology, exactly as the operator/binding path does
    /// it: the recorded topology is what every later dispatch derives from.
    fn new(name: &str, steps: Vec<Val>, start: bool) -> Self {
        let root = std::env::temp_dir().join(format!(
            "canter-grant-renewal-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
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
        let grant_id = "gr_0000000000000184";
        let run = {
            let state = shared.lock_state().unwrap();
            let epoch = state.current_epoch().unwrap();
            let grant = object(vec![
                ("schema", string("hf-grant/v1")),
                ("grant_id", string(grant_id)),
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
                (
                    "expires_at",
                    string(&time::rfc3339_from_unix(time::unix_now() + 3600)),
                ),
                ("state_epoch", integer(epoch)),
                ("created_at", string("2026-01-01T00:00:00Z")),
            ]);
            state.issue_grant(&grant).unwrap();
            let (_, items) = state
                .submit_queue_run(&QueueSubmissionPlan {
                    submission_id: "qs_0000000000000184".into(),
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
                    request_line: canonical_text(&object(vec![("steps", Val::Arr(steps.clone()))])),
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
                        grant_id: Some(grant_id.into()),
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
        let driver = DaemonDispatch {
            shared: std::sync::OnceLock::from(Arc::clone(&shared)),
            refusals: Default::default(),
            collecting: Default::default(),
        };
        let fixture = Self {
            shared,
            driver,
            run,
            grant: grant_id.to_string(),
            root,
            repo,
        };
        // The caller's topology is recorded by the run's FIRST dispatch.
        if start {
            let first = steps
                .first()
                .and_then(|step| step.get("id"))
                .and_then(Val::as_str)
                .expect("a first spine step")
                .to_string();
            fixture.apply_ok(&first, "ik_fixture-renewal-first");
        }
        fixture
    }

    fn topology(&self) -> Val {
        object(vec![
            ("integration_branch", string("staging")),
            ("production_branches", Val::Arr(vec![string("main")])),
            ("integration_repo", string(&self.repo.display().to_string())),
            (
                "worktrees_root",
                string(&self.root.join("worktrees").display().to_string()),
            ),
        ])
    }

    /// Dispatch ONE step through the daemon's own apply route (the operator
    /// and supervision routes share it).
    fn apply(&self, step: &str, key: &str) -> Result<Val, (String, String)> {
        let material = {
            let state = self.shared.lock_state().unwrap();
            match state
                .run_dispatch_context(&self.run)
                .unwrap()
                .map(|_| read_dispatch_material(&state, &self.run, None))
            {
                Some(Ok(material)) => material,
                Some(Err(err)) => return Err(err),
                None => read_dispatch_material(&state, &self.run, Some(&self.topology()))
                    .expect("topology"),
            }
        };
        let request = dispatch_request_from(&material, step, None, key).expect("request");
        let response = method_apply(&self.shared, &request);
        let doc = Val::parse_json(&response).expect("response document");
        if doc.get("ok").and_then(Val::as_bool) == Some(true) {
            Ok(doc)
        } else {
            Err((
                doc.get("error")
                    .and_then(|error| error.get("code"))
                    .and_then(Val::as_str)
                    .unwrap_or("error")
                    .to_string(),
                doc.get("error")
                    .and_then(|error| error.get("message"))
                    .and_then(Val::as_str)
                    .unwrap_or_default()
                    .to_string(),
            ))
        }
    }

    fn apply_ok(&self, step: &str, key: &str) -> Val {
        match self.apply(step, key) {
            Ok(doc) => doc,
            Err((code, message)) => panic!("apply {step} failed: {code}: {message}"),
        }
    }

    /// ONE supervised check + dispatch at the given clock, exactly as the
    /// driver runs it (`check_plan` → commit → dispatch).
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

    /// Make this fixture run's window LAPSE, and record the instant it did.
    fn lapse(&self) {
        let conn = rusqlite::Connection::open(&self.shared.paths.db_path).unwrap();
        let affected = conn
            .execute(
                "UPDATE grants SET expires_at = ?2 WHERE grant_id = ?1",
                rusqlite::params![self.grant, LAPSED],
            )
            .unwrap();
        assert_eq!(affected, 1, "the fixture window lapsed");
    }

    /// A LATER issuance for the same binding plus the same-item submission:
    /// the supported explicit rotation of a run whose window lapsed.
    fn reissue(&self, new_grant: &str) -> String {
        let state = self.shared.lock_state().unwrap();
        let epoch = state.current_epoch().unwrap();
        let doc = object(vec![
            ("schema", string("hf-grant/v1")),
            ("grant_id", string(new_grant)),
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
            (
                "expires_at",
                string(&time::rfc3339_from_unix(time::unix_now() + 3600)),
            ),
            ("state_epoch", integer(epoch)),
            ("created_at", string("2026-01-01T00:00:01Z")),
        ]);
        state.issue_grant(&doc).unwrap();
        let (_, items) = state
            .submit_queue_run(&QueueSubmissionPlan {
                submission_id: format!("qs_{}", &new_grant[3..]),
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
                request_line: canonical_text(&object(vec![("steps", Val::Arr(three_steps()))])),
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
                    grant_id: Some(new_grant.into()),
                    resume_digest: None,
                    verdict: SubmissionVerdict::Approved,
                }],
                supervision: None,
                at: time::rfc3339_now(),
            })
            .unwrap();
        assert_eq!(items[0].status, "admitted");
        items[0].instance_id.clone().unwrap()
    }

    fn attempts(&self) -> Vec<(String, String)> {
        self.shared
            .lock_state()
            .unwrap()
            .run_step_attempts(&self.run)
            .unwrap()
    }

    fn retries(&self) -> Vec<crate::state::RunRetryRow> {
        self.shared
            .lock_state()
            .unwrap()
            .run_retries(&self.run)
            .unwrap()
    }

    /// Every recorded `grant.rotation` record (superseded, replacement,
    /// recorded expiry) in journal order.
    fn rotations(&self) -> Vec<Val> {
        let state = self.shared.lock_state().unwrap();
        let (_, lines) = state.journal_tail(0, 1000).unwrap();
        lines
            .iter()
            .filter(|line| line.contains("\"action\":\"grant.rotation\""))
            .filter_map(|line| Val::parse_json(line).ok())
            .collect()
    }

    fn run_row(&self) -> crate::state::InstanceRow {
        self.shared
            .lock_state()
            .unwrap()
            .instance_by_id(&self.run)
            .unwrap()
            .unwrap()
    }

    fn grant_row(&self, grant_id: &str) -> crate::state::GrantRow {
        self.shared
            .lock_state()
            .unwrap()
            .grant_by_id(grant_id)
            .unwrap()
            .unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// (a) A lapse mid-spine renews the run's OWN window — one audited
/// `grant.rotation` naming both grants and the derived expiry — and the run
/// then reaches the last step of its committed spine with `run_retries`
/// EMPTY and no operator/interactive key anywhere.
#[test]
fn a_lapse_renews_the_runs_own_window_and_the_frontier_reaches_the_tail() {
    let fixture = Fixture::new("tail", three_steps(), true);
    fixture.lapse();
    let now = time::unix_now();
    let renewed = fixture.tick(now);
    assert!(renewed.is_ok(), "the lapsed frontier renews: {renewed:?}");
    // Nothing was asked of an operator and no bounded retry was spent.
    assert!(fixture.retries().is_empty(), "run_retries stays EMPTY");
    let rotations = fixture.rotations();
    assert_eq!(rotations.len(), 1, "exactly one renewal record");
    let target = rotations[0]
        .get("target")
        .and_then(Val::as_str)
        .expect("rotation target");
    let run_row = fixture.run_row();
    let successor = run_row.grant_id.clone();
    assert_ne!(successor, fixture.grant, "the run holds a NEW window");
    assert!(
        target.contains(&format!("superseded:{}", fixture.grant)),
        "{target}"
    );
    assert!(
        target.contains(&format!("replacement:{successor}")),
        "{target}"
    );
    let grant = fixture.grant_row(&successor);
    assert_eq!(grant.status, "active");
    assert!(
        target.contains(&format!("expires:{}", grant.expires_at)),
        "{target}"
    );
    // The window is DERIVED from the remaining committed spine: the lane
    // worktree round trip plus the closing checkout, never a fixed default.
    assert!(target.contains("window_secs:120"), "{target}");
    let created = time::unix_from_rfc3339(&grant.created_at).expect("recorded at");
    let expires = time::unix_from_rfc3339(&grant.expires_at).expect("recorded expiry");
    assert_eq!(expires - created, 120, "expiry == instant + derived window");
    assert_ne!(expires - created, 7200, "never the fixed 2 h default");
    let journal = {
        let state = fixture.shared.lock_state().unwrap();
        state.journal_tail(0, 1000).unwrap().1
    };
    assert!(
        !journal.iter().any(|line| line.contains("mutate.run.retry")),
        "no operator retry key exists in the run"
    );
    // The frontier walks the REST of the committed spine with no operator
    // input: the lane worktree round trip (renewed above) and the closing
    // step, both dispatched by the driver's own continuation intent.
    assert!(fixture.tick(now + 2).is_ok(), "the closing step runs");
    let attempts = fixture.attempts();
    for step in ["p1", "p2", "p3"] {
        assert!(
            attempts
                .iter()
                .any(|(id, st)| id == step && st == "succeeded"),
            "the committed tail is reached: {attempts:?}"
        );
    }
    assert_eq!(
        fixture.run_row().grant_id,
        successor,
        "same run, same binding"
    );
    assert!(fixture.retries().is_empty(), "still EMPTY at the tail");
    // The committed tail is the END of the spine: nothing is owed any more.
    let (row, evidence) = {
        let state = fixture.shared.lock_state().unwrap();
        (
            state.supervision_by_id(&fixture.run).unwrap().unwrap(),
            state.supervision_evidence(&fixture.run).unwrap().unwrap(),
        )
    };
    assert!(
        crate::run_control::frontier_of(
            &evidence
                .steps
                .iter()
                .map(|(id, _)| id.clone())
                .collect::<Vec<_>>(),
            &attempts,
            &fixture.run_row().current_node,
        )
        .is_none(),
        "the committed spine is fully achieved"
    );
    assert!(crate::supervision::dispatch_intent(&row, &evidence).is_none());
}

/// (b) The renewed window is the sum of the REMAINING committed spine's own
/// documented deadlines: two heads end in two different derived values, and
/// neither is the 7200 s fixed default the finding names.
#[test]
fn the_renewed_window_is_derived_from_the_remaining_committed_spine() {
    let short = Fixture::new("derived-short", three_steps(), false);
    let long = Fixture::new(
        "derived-long",
        vec![
            object(vec![
                ("id", string("h1")),
                ("kind", string("harness_start")),
                ("params", object(vec![("session_id", string("sess-1"))])),
            ]),
            object(vec![
                ("id", string("w1")),
                ("kind", string("prompt")),
                ("params", object(vec![("session_id", string("sess-1"))])),
            ]),
            object(vec![
                ("id", string("c1")),
                ("kind", string("collect_outcome")),
                ("params", object(vec![("session_id", string("sess-1"))])),
            ]),
            object(vec![
                ("id", string("r1")),
                ("kind", string("review_evidence")),
                ("params", Val::Null),
            ]),
        ],
        false,
    );
    // The long head's remaining spine is rendered with the DOCUMENTED
    // deadlines, one per kind: 300 s (`harness_start`) + 1800 s (`prompt`) +
    // 1800 s (`collect_outcome`) + 1800 s (`review_evidence`, issue #217: the
    // review verdict wait carries the prompt tier's documented bound, never
    // the generic 60 s I/O default).
    for (fixture, window) in [(&short, 180_i64), (&long, 5700)] {
        fixture.lapse();
        let at = time::rfc3339_now();
        let state = fixture.shared.lock_state().unwrap();
        let renewal = state
            .renew_lapsed_run_grant(&fixture.run, &fixture.grant, &at)
            .unwrap()
            .expect("a live run renews its own lapsed window");
        assert_eq!(renewal.window_secs, window, "derived from the spine");
        assert_eq!(renewal.superseded.grant_id, fixture.grant);
        let created = time::unix_from_rfc3339(&renewal.successor.created_at).unwrap();
        let expires = time::unix_from_rfc3339(&renewal.successor.expires_at).unwrap();
        assert_eq!(expires - created, window);
        assert_ne!(window, 7200, "never the fixed default");
        // Exactly one renewal: the successor's LIVE window is never re-minted.
        assert!(
            state
                .renew_lapsed_run_grant(&fixture.run, &renewal.successor.grant_id, &at)
                .unwrap()
                .is_none(),
            "a live window is never renewed"
        );
        // A window the run no longer holds is never renewed either.
        assert!(
            state
                .renew_lapsed_run_grant(&fixture.run, &fixture.grant, &at)
                .unwrap()
                .is_none(),
            "the superseded grant is never renewed again"
        );
    }
    assert_ne!(180, 5700);
}

/// The negative witnesses: a FOREIGN, REVOKED, STALE-EPOCH or RELEASED
/// continuation still refuses, and never mints a successor.
#[test]
fn a_foreign_grant_continuation_still_refuses() {
    let fixture = Fixture::new("foreign", three_steps(), true);
    fixture.lapse();
    let state = fixture.shared.lock_state().unwrap();
    let epoch = state.current_epoch().unwrap();
    let foreign = object(vec![
        ("schema", string("hf-grant/v1")),
        ("grant_id", string("gr_ffffffffffff0184")),
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
        (
            "expires_at",
            string(&time::rfc3339_from_unix(time::unix_now() + 3600)),
        ),
        ("state_epoch", integer(epoch)),
        ("created_at", string("2026-01-01T00:00:02Z")),
    ]);
    state.issue_grant(&foreign).unwrap();
    drop(state);
    let material = {
        let state = fixture.shared.lock_state().unwrap();
        read_dispatch_material(&state, &fixture.run, None).unwrap()
    };
    let mut request = dispatch_request_from(&material, "p2", None, "ik_fixture-foreign").unwrap();
    {
        let Some(Val::Obj(params)) = &mut request.params else {
            unreachable!("the derived request carries params")
        };
        params.insert("grant_id".to_string(), string("gr_ffffffffffff0184"));
    }
    let response = method_apply(&fixture.shared, &request);
    let doc = Val::parse_json(&response).unwrap();
    assert_eq!(
        doc.get("error")
            .and_then(|error| error.get("code"))
            .and_then(Val::as_str),
        Some("refusal.request.malformed"),
        "{response}"
    );
    assert!(fixture.rotations().is_empty(), "no successor is minted");
    assert_eq!(
        fixture.run_row().grant_id,
        fixture.grant,
        "the binding stands"
    );
    assert!(
        fixture
            .attempts()
            .iter()
            .all(|(step, status)| step != "p2" || status != "succeeded"),
        "the foreign step never ran"
    );
}

#[test]
fn a_revoked_window_continuation_still_refuses() {
    let fixture = Fixture::new("revoked", three_steps(), true);
    {
        let state = fixture.shared.lock_state().unwrap();
        state
            .revoke_grant(&fixture.grant, &time::rfc3339_now())
            .unwrap();
    }
    let error = fixture.apply("p2", "ik_fixture-revoked").unwrap_err();
    assert_eq!(error.0, "refusal.grant.inactive", "{error:?}");
    assert!(fixture.rotations().is_empty(), "no successor is minted");
    assert_eq!(
        fixture.run_row().grant_id,
        fixture.grant,
        "the binding stands"
    );
}

#[test]
fn a_stale_epoch_continuation_still_refuses() {
    let fixture = Fixture::new("epoch", three_steps(), true);
    fixture.lapse();
    {
        let state = fixture.shared.lock_state().unwrap();
        assert_eq!(state.rotate_epoch("security_rotation").unwrap(), 2);
    }
    let error = fixture.apply("p2", "ik_fixture-epoch").unwrap_err();
    assert_eq!(error.0, "refusal.state.epoch", "{error:?}");
    assert!(fixture.rotations().is_empty(), "no successor is minted");
    assert_eq!(
        fixture.run_row().grant_id,
        fixture.grant,
        "the binding stands"
    );
}

#[test]
fn a_released_run_that_no_longer_owns_its_issue_still_refuses() {
    let fixture = Fixture::new("released", three_steps(), true);
    let released = {
        let state = fixture.shared.lock_state().unwrap();
        state
            .release_run(
                &fixture.run,
                "witness: no longer owns its issue",
                "ik_fixture-release-184",
                &time::rfc3339_now(),
            )
            .unwrap()
    };
    assert!(released.ownership_freed, "the ownership row is gone");
    // The issue is owned by a FRESH run from here on; the released run is
    // neither live nor an owner, so its continuation refuses and nothing is
    // ever renewed for it.
    let replacement = fixture.reissue("gr_0000000000000186");
    assert_ne!(replacement, fixture.run, "a fresh run owns the issue now");
    let error = fixture.apply("p2", "ik_fixture-released").unwrap_err();
    assert_eq!(error.0, "refusal.instance.state", "{error:?}");
    assert!(fixture.rotations().is_empty(), "no successor is minted");
    assert_eq!(
        fixture.run_row().grant_id,
        fixture.grant,
        "the binding stands"
    );
}

/// (c) The finding's exact durable state: the run's frontier step already
/// carries a recorded pre-effect refusal of the run's OWN lapsed window, and
/// the window was restored explicitly afterwards. The recorded lapse is NOT
/// a step diagnosis, so the frontier continues without consuming a bounded
/// retry — with the carve-out removed this same route refuses
/// `refusal.run.retry_required`.
#[test]
fn a_recorded_lapse_refusal_never_demands_a_bounded_retry() {
    let fixture = Fixture::new("recorded-lapse", three_steps(), true);
    fixture.apply_ok("p2", "ik_fixture-lapse-p2");
    fixture.apply_ok("p3", "ik_fixture-lapse-p3");
    // The whole committed spine is achieved, so NO renewal is owed; the
    // lapsed re-dispatch is refused and recorded exactly as the finding's
    // raw refusal shows (the step never ran).
    fixture.lapse();
    let error = fixture.apply("p3", "ik_fixture-lapse-refused").unwrap_err();
    assert_eq!(error.0, "refusal.grant.expired", "{error:?}");
    assert_eq!(
        fixture.attempts().last().unwrap(),
        &("p3".to_string(), "refused".to_string())
    );
    assert!(fixture.retries().is_empty(), "a lapse consumes nothing");
    // The supported explicit rotation restores the run's window ...
    let rotated = fixture.reissue("gr_0000000000000185");
    assert_eq!(rotated, fixture.run, "the same run is re-windowed");
    assert_eq!(fixture.run_row().grant_id, "gr_0000000000000185");
    // ... and the recorded LAPSE still never demands a retry.
    fixture.apply_ok("p3", "ik_fixture-lapse-continue");
    assert!(fixture.retries().is_empty(), "still nothing consumed");
}

/// The same fact inside the driver's own eligibility: a recorded lapse
/// refusal is a plain continuation (never a bounded retry), while a real
/// step diagnosis and a fresh review failure still hold exactly as before.
#[test]
fn a_lapse_refusal_is_a_continuation_not_a_bounded_retry() {
    let fixture = Fixture::new("intent", three_steps(), true);
    let (row, template) = {
        let state = fixture.shared.lock_state().unwrap();
        (
            state.supervision_by_id(&fixture.run).unwrap().unwrap(),
            state.supervision_evidence(&fixture.run).unwrap().unwrap(),
        )
    };
    let consumed_retries = |step: &str| -> Vec<crate::state::RunRetryRow> {
        (1..=crate::state::RUN_RETRY_MAX)
            .map(|attempt| crate::state::RunRetryRow {
                retry_id: format!("rt_{attempt:016x}"),
                instance_id: fixture.run.clone(),
                step_id: step.to_string(),
                attempt,
                authorized_at: "2026-01-01T00:00:00Z".to_string(),
                consumed_at: "2026-01-01T00:00:01Z".to_string(),
                consumed_key: format!("ik_fixture-{attempt}"),
            })
            .collect()
    };
    let evidence_with =
        |code: &str, retries: Vec<crate::state::RunRetryRow>, verdict: Option<&str>| {
            let mut evidence = template.clone();
            evidence.attempts = vec![
                ("p1".to_string(), "succeeded".to_string(), String::new()),
                ("p2".to_string(), "refused".to_string(), code.to_string()),
            ];
            evidence.retries = retries;
            evidence.verdicts = verdict
                .map(|verdict| {
                    vec![(
                        "ev_0000000000000184".to_string(),
                        verdict.to_string(),
                        "2026-01-01T00:00:00Z".to_string(),
                    )]
                })
                .unwrap_or_default();
            evidence
        };
    // A lapse refusal whose step already burned the whole retirement budget
    // is still the SAME plain continuation: the lapse consumed nothing.
    let lapse = evidence_with(
        crate::mutation::code::GRANT_EXPIRED,
        consumed_retries("p2"),
        None,
    );
    let intent = dispatch_intent(&row, &lapse).expect("the lapsed frontier continues");
    assert_eq!(intent.step_id, "p2");
    // A REAL diagnosis still holds once its bounded budget is spent (#179).
    let diagnosed = evidence_with("refusal.worktree.exists", consumed_retries("p2"), None);
    assert!(dispatch_intent(&row, &diagnosed).is_none());
    // A fresh review failure still holds the frontier.
    let failed = evidence_with(
        crate::mutation::code::GRANT_EXPIRED,
        Vec::new(),
        Some("fail"),
    );
    assert!(dispatch_intent(&row, &failed).is_none());
}
