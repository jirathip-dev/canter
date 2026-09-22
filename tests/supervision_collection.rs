//! Issue #170 (N7/N8) end-to-end acceptance: the pane-collection wait.
//!
//! The six collection witnesses live in their own suite on purpose (the same
//! reason `tests/supervision_dispatch_refusal.rs` exists): the hosted runner
//! bounds EVERY `tests/*.rs` file as its own suite (150 s serial,
//! `--test-threads=1 --nocapture`), and each witness drives a real daemon
//! through the product's own 5 s sample cadence, so their walls add. Split
//! from `tests/supervision.rs` without changing a single assertion; the
//! shared fixture lives in `tests/support/pane_fixture.rs`.
//!
//! No fixed real sleeps: every wait on recorded canter state is a poll that
//! fails only after a documented no-progress ceiling (issue #232).
#[path = "support/pane_fixture.rs"]
mod pane_fixture;

use std::time::{Duration, Instant};

use canter::queue_preview as qp;
use canter::value::{Val, integer, object, string};
use pane_fixture::{
    DaemonFixture, HARNESS, NO_PROGRESS_SECS, REV_A, caller_apply_params, checks_of, class_of,
    evaluation, fresh_id, git_output, harness_binding_doc, harness_pane_steps,
    harness_submit_params, idem_key, init_repo, instance_of, plan_doc_with_steps, render_bound,
    request_with, resolved, rpc_ok, seed_grant, selected, shutdown, status_doc, wait_for_checks,
    wait_ready, write_fake_herdr,
};
fn supervised_collection(mode: &str) {
    let fixture = DaemonFixture::new(&format!("collect-{mode}"));
    let integration = fixture.dir.join("integration");
    init_repo(&integration);
    let old = git_output(&integration, &["rev-parse", "HEAD"])
        .trim()
        .to_string();
    for _ in 0..3 {
        git_output(
            &integration,
            &["commit", "--allow-empty", "-qm", "published progress"],
        );
    }
    let published = git_output(&integration, &["rev-parse", "HEAD"])
        .trim()
        .to_string();
    let origin = fixture.dir.join("origin.git");
    git_output(
        &integration,
        &["clone", "--bare", ".", origin.to_str().unwrap()],
    );
    git_output(
        &integration,
        &["remote", "set-url", "origin", origin.to_str().unwrap()],
    );
    git_output(&integration, &["checkout", "--detach", &published]);
    git_output(&integration, &["branch", "-f", "staging", &old]);
    assert_ne!(old, published);
    let (bound, digest) = {
        let state = fixture.seed();
        seed_grant(&state, "gr_0000000000000095", 5);
        let mut steps = harness_pane_steps(HARNESS);
        steps.pop(); // The witness stops after collection, before review/merge.
        steps.insert(
            0,
            qp::PlannedStep {
                id: "checkout".to_string(),
                kind: "checkout".to_string(),
                params: Some(resolved()),
            },
        );
        steps.push(qp::PlannedStep {
            id: "collect".to_string(),
            kind: "collect_outcome".to_string(),
            params: Some(object(vec![
                ("worktree", string("issues-5")),
                ("branch", string("issue-5")),
                ("requires_delta", Val::Bool(true)),
                (
                    "deadline_secs",
                    // Issue #170 N8: `deadline_secs` is the wait's NO-PROGRESS
                    // window. `timeout` declares a 3 s window (the lane's
                    // read-backs carry NO progress, so the wait parks — and 3 s
                    // keeps the read itself above a slow runner's subprocess
                    // cost); `extend` declares an 11 s window — just past the
                    // (N-1) × interval confirmation span — while the fixture
                    // keeps the worker demonstrably working past it and
                    // delivers later still, so the wait must EXTEND on recorded
                    // progress instead of parking on a wall clock. The other
                    // modes' windows are failure-path headroom only: their
                    // happy paths end at the confirmed stop, never at a window.
                    integer(match mode {
                        "timeout" => 3,
                        "extend" => 11,
                        _ => 20,
                    }),
                ),
            ])),
        });
        render_bound(
            &state,
            &qp::QueueRequest {
                steps,
                role_config: harness_binding_doc(),
                ..request_with(vec![selected("#5", REV_A)])
            },
        )
    };
    std::fs::write(fixture.dir.join("collect-mode"), mode).unwrap();
    let fakebin = write_fake_herdr(&fixture.dir);
    let daemon = fixture.spawn_with_path(&format!(
        "{}:{}",
        fakebin.display(),
        std::env::var("PATH").unwrap()
    ));
    wait_ready(&fixture);
    let mut params = harness_submit_params(&idem_key(mode), &bound, &digest, "gr_0000000000000095");
    let topology = caller_apply_params(
        &fixture,
        &integration,
        &bound,
        "unused",
        "gr_0000000000000095",
        ("checkout", 5),
        "unused",
    );
    if let Val::Obj(fields) = &mut params {
        fields.insert(
            "supervision".to_string(),
            object(vec![
                ("schema", string("hf-supervision-authorization/v1")),
                ("desired", string("armed")),
                (
                    "policy",
                    object(vec![
                        ("check_interval_secs", integer(5)),
                        ("progress_timeout_secs", integer(60)),
                    ]),
                ),
            ]),
        );
        fields.insert(
            "dispatch".to_string(),
            object(vec![
                ("topology", topology.get("topology").unwrap().clone()),
                (
                    "admission",
                    topology
                        .get("flags")
                        .unwrap()
                        .get("admission")
                        .unwrap()
                        .clone(),
                ),
            ]),
        );
    }
    let submitted = rpc_ok(&fixture.socket, &fresh_id(1), "queue.submit", Some(params));
    let run = instance_of(&submitted, 5);
    let lane = fixture.dir.join("worktrees/issues-5");
    let started = Instant::now();
    let mut last_progress = started;
    let mut progress = String::new();
    let mut waiting_checks = None;
    let mut flap_armed = false;
    loop {
        let doc = status_doc(&fixture.socket, &fresh_id(2), &run);
        let attempts = fixture
            .seed()
            .supervision_evidence(&run)
            .unwrap()
            .unwrap()
            .attempts;
        if attempts.iter().any(|(step, _, _)| step == "collect") {
            break;
        }
        let observed = format!("{attempts:?}");
        if observed != progress {
            progress = observed;
            last_progress = Instant::now();
        }
        if class_of(&doc) == "waiting-workers" {
            assert_eq!(evaluation(&doc).get("eligible"), Some(&Val::Bool(true)));
            if !fixture.dir.join("allow-stop").exists() {
                assert_eq!(
                    git_output(&lane, &["rev-parse", "HEAD"]).trim(),
                    published,
                    "the lane uses the published base, not stale staging"
                );
            }
            // Issue #170 N7: the flap is armed only while THIS collection step
            // holds the live claim, so the measured mid-turn flap lands on the
            // collector's own read-backs — while the worker is genuinely
            // unstopped and nothing is committed.
            if mode == "flap"
                && !flap_armed
                && doc
                    .get("cursor")
                    .and_then(|cursor| cursor.get("in_flight"))
                    .and_then(Val::as_str)
                    == Some("collect")
            {
                std::fs::write(fixture.dir.join("flap-now"), "flap").unwrap();
                flap_armed = true;
            }
            waiting_checks.get_or_insert(checks_of(&doc));
            // Issue #170: the stop is marked as soon as the collection step
            // holds its live claim — the wait is what the witnesses prove, and
            // the collector's own 5 s sample cadence is the clock this suite
            // must fit inside (the CI driver allows it 150 s per suite).
            if mode != "timeout" && !fixture.dir.join("flap-now").exists() {
                std::fs::write(fixture.dir.join("allow-stop"), "stop").unwrap();
            }
        }
        let stalled = last_progress.elapsed().as_secs();
        assert!(
            stalled < NO_PROGRESS_SECS,
            "collection never settled: no progress for {stalled}s of {}s waited \
             ({} recorded attempt(s)): {}\n{}",
            started.elapsed().as_secs(),
            attempts.len(),
            canter::canonical::canonical_text(&doc),
            std::fs::read_to_string(fixture.daemon_log()).unwrap_or_default()
        );
        std::thread::sleep(Duration::from_millis(25));
    }
    let attempts = fixture
        .seed()
        .supervision_evidence(&run)
        .unwrap()
        .unwrap()
        .attempts;
    let collected: Vec<_> = attempts
        .iter()
        .filter(|(step, _, _)| step == "collect")
        .collect();
    assert_eq!(collected.len(), 1, "one collection attempt, never a retry");
    match mode {
        "delta" | "flap" | "extend" => {
            assert!(
                waiting_checks.is_some(),
                "the worker must WAIT before collection"
            );
            assert_eq!(collected[0].1, "succeeded", "{attempts:?}");
            assert_eq!(
                std::fs::read_to_string(fixture.dir.join("herdr-state/state")).unwrap(),
                "done",
                "issue #200: the delta is certified only at the worker's SETTLED turn"
            );
            // The delivery landed MID-TURN. The poll log proves the collector
            // read the lane while the worker was still live and did NOT
            // certify there — the measured p4→p5 defect was exactly that read.
            let reads = std::fs::read_to_string(fixture.dir.join("herdr-argv.txt")).unwrap();
            let landed = reads
                .find("worker-delivery-committed")
                .expect("the fixture delivery landed");
            if mode == "flap" {
                // Issue #170 N7 witness (a): the fixture flapped the lane's own
                // status to `done` for two read-backs BEFORE any delivery
                // existed — the pre-change wait judged exactly that a stopped
                // worker and refused `refusal.collect.empty_delta` four minutes
                // into a 93-minute turn. The flap is a wait now: the delivery
                // lands afterwards and is certified.
                assert!(
                    reads[..landed].matches("worker-poll done").count() >= 2,
                    "the flap must precede the delivery: {reads}"
                );
                assert!(
                    !fixture.dir.join("flap-now").exists(),
                    "the fixture flap was consumed by the collector's read-backs"
                );
            }
            if mode == "extend" {
                // Issue #170 N8 witness (c) end to end: the step declared an
                // 11 s no-progress window and the fixture withheld the delivery
                // for longer than that while the lane kept reporting it was
                // working — the wait EXTENDED on recorded progress and
                // certified the delivery; a wall clock would have parked the
                // run at 11 s.
                let delivered_after: u64 =
                    std::fs::read_to_string(fixture.dir.join("herdr-state/delivered_after_secs"))
                        .expect("the fixture records when it delivered")
                        .trim()
                        .parse()
                        .expect("the delivery time in seconds");
                assert!(
                    delivered_after >= 11,
                    "the delivery must land past the declared 11 s window: {delivered_after}s"
                );
                assert!(
                    reads.matches("worker-poll working").count() >= 4,
                    "the wait must have sampled the working lane past the window: {reads}"
                );
            }
            assert!(
                reads[landed..].matches("worker-poll working").count() >= 1,
                "a delivery read while the worker is still live is a WAIT, not a \
                 certification: {reads}"
            );
            // ...and the certified head IS the final settled head: the
            // recorded collection outcome names the lane's settled commit.
            let head = git_output(&lane, &["rev-parse", "HEAD"]).trim().to_string();
            assert_ne!(head, published);
            let response: String = rusqlite::Connection::open(fixture.db())
                .unwrap()
                .query_row(
                    "SELECT response FROM idempotency
                      WHERE method = 'apply' AND request_line LIKE '%\"step\":\"collect\"%'
                      ORDER BY rowid DESC LIMIT 1",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            let response = Val::parse_json(&response).expect("the collection response parses");
            assert_eq!(
                response
                    .get("result")
                    .and_then(|result| result.get("head"))
                    .and_then(Val::as_str),
                Some(head.as_str()),
                "the certified head is the FINAL settled head"
            );
            assert_eq!(
                std::fs::read_to_string(lane.join("delivery.txt")).unwrap(),
                "worker delivery\n"
            );
        }
        "empty" => {
            assert!(
                waiting_checks.is_some(),
                "empty delta cannot diagnose a live worker"
            );
            assert_eq!(collected[0].1, "refused");
            assert_eq!(collected[0].2, "refusal.collect.empty_delta");
        }
        "timeout" => {
            assert_eq!(collected[0].1, "ambiguous");
            assert_eq!(collected[0].2, "effect.worker_timeout");
            let first = status_doc(&fixture.socket, &fresh_id(3), &run);
            let settled = wait_for_checks(&fixture, &run, checks_of(&first) + 2);
            assert_eq!(class_of(&settled), "worker-timeout");
            assert_eq!(
                evaluation(&settled).get("eligible"),
                Some(&Val::Bool(false))
            );
            assert_eq!(
                fixture
                    .seed()
                    .supervision_evidence(&run)
                    .unwrap()
                    .unwrap()
                    .attempts,
                attempts,
                "timeout is never redispatched"
            );
        }
        _ => unreachable!(),
    }
    let conn = rusqlite::Connection::open(fixture.db()).unwrap();
    let keys: Vec<String> = conn
        .prepare("SELECT key FROM idempotency WHERE method = 'apply' ORDER BY rowid")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    // One dispatch per spine step — plus, for the mode whose collection is
    // REFUSED (`empty`), at most one bounded retry per dispatch: a refused
    // step that is not a wait/park is retryable, and the run's OWN supervision
    // consumes the bounded retry (issue #241; the refused collect is re-driven
    // with the retry budget `state::RUN_RETRY_MAX`). Every key is
    // driver-issued either way.
    assert!(
        keys.len() >= 5 && keys.len() <= 5 + canter::state::RUN_RETRY_MAX as usize,
        "one dispatch per spine step, plus at most the bounded retries of a refused step: {keys:?}"
    );
    assert!(
        keys.iter()
            .all(|key| key.starts_with(&format!("ik_{run}-"))),
        "zero operator keys: {keys:?}"
    );
    let retries = fixture.seed().run_retries(&run).unwrap();
    if mode == "empty" {
        assert!(
            retries.len() <= canter::state::RUN_RETRY_MAX as usize,
            "the refused collection is retried by the run's own supervision, bounded: {retries:?}"
        );
    } else {
        assert!(
            retries.is_empty(),
            "a spine that never refuses consumes no retry: {retries:?}"
        );
    }
    shutdown(daemon);
}

#[test]
fn collection_invalid_base_refuses_before_any_worker_poll() {
    use canter::mutation::{EffectContext, bind_plan, execute_step, run_session_handle};
    let fixture = DaemonFixture::new("collect-base-refusal");
    let root = fixture.dir.join("worktrees");
    std::fs::create_dir_all(&root).unwrap();
    let lane = root.join("issues-5");
    init_repo(&lane);
    git_output(&lane, &["remote", "remove", "origin"]);
    let base = git_output(&lane, &["rev-parse", "HEAD"]).trim().to_string();
    let session = run_session_handle("run-0000000000000005").unwrap();
    let bin = write_fake_herdr(&fixture.dir);
    let worker = fixture.dir.join("herdr-state");
    std::fs::create_dir_all(&worker).unwrap();
    for (name, value) in [
        ("name", "impl-5".to_string()),
        ("pane", "w1:p1".to_string()),
        ("cwd", lane.to_string_lossy().to_string()),
        ("lane", session.session_id.clone()),
        ("generation", session.identity.generation.to_string()),
        ("state", "unknown".to_string()),
    ] {
        std::fs::write(worker.join(name), value).unwrap();
    }
    let env = std::collections::BTreeMap::from([
        (
            "PATH".to_string(),
            format!("{}:{}", bin.display(), std::env::var("PATH").unwrap()),
        ),
        (
            "HOME".to_string(),
            fixture.dir.to_string_lossy().to_string(),
        ),
    ]);
    let steps = Val::Arr(vec![
        object(vec![
            ("id", string("prompt")),
            ("kind", string("prompt")),
            (
                "params",
                object(vec![
                    ("harness_key", string(HARNESS)),
                    ("kind", string("hermes")),
                    ("worktree", string("issues-5")),
                    ("payload", string("bounded work")),
                ]),
            ),
        ]),
        object(vec![
            ("id", string("collect")),
            ("kind", string("collect_outcome")),
        ]),
    ]);
    let plan = bind_plan(&plan_doc_with_steps(steps, 5)).unwrap();
    let collect = |base: Option<&str>| {
        let mut params = object(vec![
            ("worktree", string("issues-5")),
            // A 3 s no-progress window: short enough to park the positive
            // control fast, long enough that the fake live worker's own row is
            // never racing a one-second subprocess budget under load.
            ("deadline_secs", integer(3)),
        ]);
        if let (Some(base), Val::Obj(fields)) = (base, &mut params) {
            fields.insert("base_head".to_string(), string(base));
        }
        execute_step(&EffectContext {
            plan: &plan,
            step_id: "collect",
            kind: "collect_outcome",
            params: Some(&params),
            repository: "example-org/widgets",
            integration_branch: "staging",
            production_branches: &[],
            publish_route: "push",
            worktrees_root: &root,
            integration_repo: &lane,
            observed_feature_head: None,
            observed_integration_base: None,
            env: &env,
            role: None,
            session: Some(&session),
            archive_root: None,
            review_root: None,
            retired_run_ids: &[],
        })
    };
    let log = fixture.dir.join("herdr-argv.txt");
    let absent = "0".repeat(40);
    // Same typed refusal on an attached no-origin checkout, a detached one,
    // and a fresh repository without a HEAD. None may observe the live worker.
    for layout in ["no-origin", "detached", "fresh"] {
        if layout == "detached" {
            git_output(&lane, &["checkout", "--detach", &base]);
        } else if layout == "fresh" {
            std::fs::remove_dir_all(lane.join(".git")).unwrap();
            git_output(&lane, &["init", "-b", "staging"]);
        }
        for (head, code) in [
            (None, "refusal.request.malformed"),
            (Some("not-a-commit"), "refusal.request.malformed"),
            (Some(absent.as_str()), "refusal.worker.output_location"),
        ] {
            let outcome = collect(head);
            assert_eq!(outcome.status, "refused", "{layout}: {outcome:?}");
            assert_eq!(outcome.code.as_deref(), Some(code), "{layout}: {outcome:?}");
            assert!(
                !log.exists(),
                "invalid base must never poll a worker: {layout}"
            );
        }
        if layout == "detached" {
            let outcome = collect(Some(&base));
            assert_eq!(
                outcome.code.as_deref(),
                Some("refusal.worker.output_location")
            );
            assert!(
                !log.exists(),
                "a detached checkout must refuse before polling"
            );
        }
        if layout == "no-origin" {
            // Positive control: identical binding, valid base -> the fake live
            // worker IS read, and the injected three-second no-progress window
            // parks it (the lane reads back no progress at all).
            let outcome = collect(Some(&base));
            assert_eq!(outcome.code.as_deref(), Some("effect.worker_timeout"));
            assert!(
                std::fs::read_to_string(&log)
                    .unwrap()
                    .contains("agent get impl-5")
            );
            std::fs::remove_file(&log).unwrap();
        }
    }
}

#[test]
fn collection_waits_for_pane_delivery_without_operator_dispatch() {
    supervised_collection("delta");
}

#[test]
fn collection_stopped_without_delta_is_still_refused() {
    supervised_collection("empty");
}

#[test]
fn collection_deadline_parks_worker_timeout_without_redispatch() {
    supervised_collection("timeout");
}

/// Issue #170 N7 witness (a), end to end: a worker that is STILL WORKING but
/// whose reported status flaps to `done` twice is not a stopped worker. The
/// pre-change wait read exactly that flap as a stop and refused
/// `refusal.collect.empty_delta` (the live `p5-101` refusal came four minutes
/// into a 93-minute turn and consumed the run's retry); the delivered wait
/// keeps reading, the delivery that lands later is certified, and no emptiness
/// refusal exists for this run.
#[test]
fn collection_status_flap_mid_turn_is_never_an_empty_refusal() {
    supervised_collection("flap");
}

/// Issue #170 N8 witness (c), end to end: the collection's `deadline_secs` is
/// the wait's NO-PROGRESS WINDOW, not a wall. This step declares 10 s while
/// the lane keeps reporting it is working (and commits its delivery) well past
/// that — the wait EXTENDS and the run collects, instead of the pre-change
/// `effect.worker_timeout` park at the declared wall.
#[test]
fn collection_still_working_past_the_declared_wall_is_not_parked() {
    supervised_collection("extend");
}
