//! Issue #270 acceptance: a supervision pass that cannot finish its effect work
//! must not hold the fleet's only driver.
//!
//! One scenario, its own suite budget: a REAL `canter daemon run` child whose
//! armed driver dispatches run A's Herdr lane registration while the substrate
//! sleeps well past the pass deadline. The pass must release the wait — the
//! other armed run keeps being classified while run A's lane call is still
//! stuck — the stall must be named on the product surface (`daemon status` /
//! `supervision status`) instead of reading `freshness: fresh`, and the effect
//! must still resolve exactly once.
//!
//! The fixture's fake `herdr` sleeps on purpose: that sleep IS the defect (the
//! measured wedge was `SupervisorCore::pass` → `…close_lane_workspace` →
//! `herdr` → `process::run` → sleep, holding the driver thread for 17 minutes).
//!
//! No fixed real sleeps on canter state: every wait on recorded evidence is a
//! poll that fails only after a documented no-progress ceiling (issue #232).
#[path = "support/pane_fixture.rs"]
mod pane_fixture;

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use canter::lifecycle::ConcurrencyCaps;
use canter::queue_executor as qx;
use canter::queue_preview as qp;
use canter::supervision;
use canter::value::{Val, null, object, string};
use pane_fixture::{
    DaemonFixture, FAKE_HERDR_BODY, HARNESS, NO_PROGRESS_SECS, REV_A, binding_doc,
    caller_apply_params, fresh_id, harness_binding_doc, harness_pane_steps, harness_role_revision,
    idem_key, init_repo, instance_of, plan_doc_with_steps, render_bound, request_with, rpc_ok,
    seed_grant, selected, shutdown, status_doc, wait_ready,
};

/// The sleep of the fake `herdr`'s lane-registration row (seconds): longer than
/// the run's own 5 s cadence (the pass's per-effect bound), short enough that
/// the effect still resolves inside its own step deadline (the bind's step
/// deadline is the documented 300 s).
const SUBSTRATE_SLEEP_SECS: u64 = 8;
/// The armed cadence of both runs: the fastest the policy supports, so the
/// driver's per-effect bound is 5 s and the stall is reached quickly.
const CADENCE_SECS: i64 = 5;

fn armed(cadence_secs: i64) -> supervision::Authorization {
    supervision::Authorization {
        desired: "armed".to_string(),
        policy: supervision::Policy {
            check_interval_secs: cadence_secs,
            progress_timeout_secs: 60,
        },
    }
}

/// The fixture's own fake `herdr`, with ONE row that SLEEPS: the lane
/// registration the pane substrate performs for a run's lane worktree. Every
/// sleeping invocation is recorded, so "exactly once" is read back from the
/// substrate itself rather than assumed.
fn write_sleeping_fake_herdr(dir: &Path, slow_row: &str, sleep_secs: u64) -> PathBuf {
    let bin = dir.join("fakebin-herdr-slow");
    std::fs::create_dir_all(&bin).expect("bin dir");
    let path = bin.join("herdr");
    let body = FAKE_HERDR_BODY.replace(
        "log() { printf '%s\\n' \"$*\" >> \"$LOG\"; }",
        &format!(
            "log() {{ printf '%s\\n' \"$*\" >> \"$LOG\"; }}\n\
             # Issue #270: the lane registration row sleeps before it answers.\n\
             case \"$1 $2\" in\n\
             \x20 \"{slow_row}\")\n\
             \x20   printf 'started\\n' >> \"$HOME/herdr-slow.txt\"\n\
             \x20   sleep {sleep_secs}\n\
             \x20   ;;\n\
             esac"
        ),
    );
    assert_ne!(
        body, FAKE_HERDR_BODY,
        "the sleep stanza was injected into the fake substrate"
    );
    std::fs::write(&path, body).expect("write fake herdr");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = std::fs::metadata(&path).expect("metadata").permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&path, permissions).expect("chmod");
    }
    bin
}

/// A frontier the driver never dispatches (a `merge` step without a verified
/// delivery is not a driver-dispatchable kind): the run only TICKS, which is
/// exactly the "other run" the issue's freeze was measured on.
fn merge_frontier_request(issue: &str) -> qp::QueueRequest {
    let mut request = request_with(vec![selected(issue, REV_A)]);
    request.steps = vec![qp::PlannedStep {
        id: "p1".to_string(),
        kind: "merge".to_string(),
        params: Some(object(vec![
            ("branch", string("issue-5")),
            ("merge_policy", string("squash")),
        ])),
    }];
    request
}

#[allow(clippy::too_many_arguments)]
fn armed_submit_params(
    issue: &str,
    key: &str,
    bound: &Val,
    digest: &str,
    binding: &Val,
    revision: &str,
    grant_id: &str,
) -> Val {
    qx::submit_params(
        key,
        digest,
        1,
        bound,
        binding,
        revision,
        ConcurrencyCaps {
            global: 4,
            per_repository: 2,
            per_harness: 2,
        },
        Some(true),
        Some(0),
        &[qx::ItemGrant {
            id: issue.to_string(),
            grant_id: grant_id.to_string(),
        }],
        &[],
        Some(&armed(CADENCE_SECS)),
    )
}

fn role_revision() -> String {
    binding_doc()
        .get("revision")
        .and_then(Val::as_str)
        .expect("binding revision")
        .to_string()
}

/// Walk one document path (`Val::get` per key), `null` when absent.
fn path_of(doc: &Val, keys: &[&str]) -> Val {
    let mut cursor = doc.clone();
    for key in keys {
        cursor = cursor.get(key).cloned().unwrap_or_else(null);
    }
    cursor
}

#[test]
fn a_lane_call_that_sleeps_past_the_pass_deadline_is_named_and_the_other_run_ticks() {
    let fixture = DaemonFixture::new("pass-deadline");
    let integration = fixture.dir.join("integration");
    init_repo(&integration);
    let fakebin_herdr =
        write_sleeping_fake_herdr(&fixture.dir, "worktree open", SUBSTRATE_SLEEP_SECS);
    let host_path = std::env::var("PATH").unwrap_or_default();
    let daemon = fixture.spawn_with_path(&format!("{}:{host_path}", fakebin_herdr.display()));
    wait_ready(&fixture);

    // Run A: the pane substrate's lane registration (p1 worktree, p2 the lane
    // bind), armed at the fastest supported cadence.
    let (bound_a, digest_a) = {
        let state = fixture.seed();
        seed_grant(&state, "gr_0000000000000095", 5);
        let mut steps = harness_pane_steps(HARNESS);
        steps.truncate(2);
        let request = qp::QueueRequest {
            steps,
            role_config: harness_binding_doc(),
            ..merge_frontier_request("#5")
        };
        render_bound(&state, &request)
    };
    // Run B: armed, but with no driver-dispatchable frontier — it only ticks.
    let (bound_b, digest_b) = {
        let state = fixture.seed();
        seed_grant(&state, "gr_0000000000000097", 7);
        render_bound(&state, &merge_frontier_request("#7"))
    };

    let run_a = instance_of(
        &rpc_ok(
            &fixture.socket,
            &fresh_id(1),
            "queue.submit",
            Some(armed_submit_params(
                "#5",
                &idem_key("pass-deadline-pane"),
                &bound_a,
                &digest_a,
                &harness_binding_doc(),
                &harness_role_revision(),
                "gr_0000000000000095",
            )),
        ),
        5,
    );
    let run_b = instance_of(
        &rpc_ok(
            &fixture.socket,
            &fresh_id(2),
            "queue.submit",
            Some(armed_submit_params(
                "#7",
                &idem_key("pass-deadline-ticker"),
                &bound_b,
                &digest_b,
                &binding_doc(),
                &role_revision(),
                "gr_0000000000000097",
            )),
        ),
        7,
    );

    // The operator dispatches run A's FIRST step (it holds the topology and the
    // admission proof), so the driver's own frontier is the lane bind (`p2`) —
    // the step whose effect registers the lane workspace in the substrate.
    let steps = bound_a.get("steps").cloned().unwrap_or_else(null);
    rpc_ok(
        &fixture.socket,
        &fresh_id(3),
        "apply",
        Some({
            let mut params = caller_apply_params(
                &fixture,
                &integration,
                &bound_a,
                &run_a,
                "gr_0000000000000095",
                ("p1", 5),
                &idem_key("pass-deadline-lane-0001"),
            );
            if let Val::Obj(map) = &mut params {
                map.insert("plan".to_string(), plan_doc_with_steps(steps.clone(), 5));
                map.insert("profile".to_string(), harness_binding_doc());
            }
            params
        }),
    );

    // Wait for the driver's own dispatch to be stuck in the sleeping lane row.
    // The stall is only ever reported WHILE the effect is unresolved, so every
    // fact read in this window is a fact about the stuck pass.
    let mut seed = 10u64;
    let mut progress = String::new();
    let mut last_progress = Instant::now();
    let started = Instant::now();
    let stalled = loop {
        let doc_a = status_doc(&fixture.socket, &fresh_id(seed), &run_a);
        let doc_b = status_doc(&fixture.socket, &fresh_id(seed + 1), &run_b);
        seed += 2;
        let stalled_now = path_of(&doc_a, &["driver", "state"]).as_str() == Some("stalled");
        if stalled_now {
            let status = rpc_ok(&fixture.socket, &fresh_id(seed), "status", None);
            seed += 1;
            if path_of(&status, &["freshness"]).as_str() == Some("stalled") {
                break (doc_a, doc_b, status);
            }
        }
        let observed = format!(
            "{} | {}",
            canter::canonical::canonical_text(&doc_a),
            canter::canonical::canonical_text(&doc_b)
        );
        if observed != progress {
            progress = observed;
            last_progress = Instant::now();
        }
        assert!(
            last_progress.elapsed().as_secs() < NO_PROGRESS_SECS,
            "the pass never read stalled: {}s waited\n{}",
            started.elapsed().as_secs(),
            std::fs::read_to_string(fixture.daemon_log()).unwrap_or_default()
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    let (doc_a, doc_b, status) = stalled;

    // AC2 — the product surface names the stalled pass, its run/step and its
    // age, instead of `freshness: fresh` over frozen `last_check` stamps.
    assert_eq!(
        path_of(&status, &["freshness"]).as_str(),
        Some("stalled"),
        "daemon status stops reading fresh while a pass is stalled"
    );
    assert_eq!(
        path_of(&status, &["supervision", "state"]).as_str(),
        Some("stalled")
    );
    assert_eq!(
        path_of(&status, &["supervision", "pass", "run"]).as_str(),
        Some(run_a.as_str())
    );
    assert_eq!(
        path_of(&status, &["supervision", "pass", "step"]).as_str(),
        Some("p2"),
        "the stalled pass names the step it is on"
    );
    assert!(
        path_of(&status, &["supervision", "pass", "age_secs"])
            .as_int()
            .unwrap_or(0)
            >= CADENCE_SECS,
        "the age of the oldest unfinished pass is reported"
    );
    assert!(
        path_of(&status, &["supervision", "abandoned_passes"])
            .as_int()
            .unwrap_or(0)
            >= 1
    );
    assert_eq!(
        path_of(&doc_a, &["driver", "pass", "run"]).as_str(),
        Some(run_a.as_str()),
        "the per-run read names the same stalled pass"
    );

    // AC1 — the OTHER armed run kept being classified while run A's lane call
    // was still unresolved: its committed check count ADVANCES while the stall
    // is still reported (the stall only ever reads `stalled` while the effect is
    // unresolved, so a tick observed under it landed on the stuck pass).
    let checks_b_at_stall = path_of(&doc_b, &["evaluation", "checks"])
        .as_int()
        .unwrap_or(0);
    let tick_deadline = Instant::now() + Duration::from_secs(NO_PROGRESS_SECS);
    let (doc_b, checks_b) = loop {
        let doc_a_now = status_doc(&fixture.socket, &fresh_id(seed), &run_a);
        let doc_b_now = status_doc(&fixture.socket, &fresh_id(seed + 1), &run_b);
        seed += 2;
        let checks_b_now = path_of(&doc_b_now, &["evaluation", "checks"])
            .as_int()
            .unwrap_or(0);
        if path_of(&doc_a_now, &["driver", "state"]).as_str() == Some("stalled")
            && checks_b_now > checks_b_at_stall
        {
            break (doc_b_now, checks_b_now);
        }
        assert!(
            Instant::now() < tick_deadline,
            "the other run's tick never landed while the pass was stalled \
             ({checks_b_at_stall} checks, then {}s waited)\n{}",
            NO_PROGRESS_SECS,
            std::fs::read_to_string(fixture.daemon_log()).unwrap_or_default()
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    assert!(
        checks_b > checks_b_at_stall,
        "the other run was not classified while the pass was stalled: {}",
        canter::canonical::canonical_text(&doc_b)
    );
    let last_check_b = path_of(&doc_b, &["evaluation", "last_check", "at"])
        .as_str()
        .unwrap_or_default()
        .to_string();
    let pass_started = path_of(&doc_a, &["driver", "pass", "started_at"])
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert!(
        !last_check_b.is_empty() && last_check_b.as_str() >= pass_started.as_str(),
        "the other run's tick landed while the pass was on the unresolved effect: \
         last_check {last_check_b} vs pass {pass_started}"
    );

    // AC3 — the abandoned effect resolves exactly once: the substrate ran the
    // sleeping lane row once, and the stall clears when that effect finishes.
    let slept = std::fs::read_to_string(fixture.dir.join("herdr-slow.txt"))
        .expect("the sleeping lane row ran");
    assert_eq!(
        slept.lines().count(),
        1,
        "the lane call ran exactly once: {slept}\n{}",
        std::fs::read_to_string(fixture.daemon_log()).unwrap_or_default()
    );
    let deadline = Instant::now() + Duration::from_secs(NO_PROGRESS_SECS);
    loop {
        let doc = status_doc(&fixture.socket, &fresh_id(seed), &run_a);
        seed += 1;
        if path_of(&doc, &["driver", "state"]).as_str() != Some("stalled") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the abandoned lane call never resolved:\n{}",
            std::fs::read_to_string(fixture.daemon_log()).unwrap_or_default()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let attempts = fixture.seed().run_step_attempts(&run_a).expect("attempts");
    assert_eq!(
        attempts.iter().filter(|(step, _)| step == "p2").count(),
        1,
        "the dispatch resolved exactly once — no double close: {attempts:?}"
    );

    shutdown(daemon);
}
