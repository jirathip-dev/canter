//! Issue #268 cost harness: the CPU and wall cost of ONE supervision pass.
//!
//! The supervisor re-reads a run's recorded evidence once per tick and decides
//! from it, so the cost of that read has to be bounded by the runs the pass
//! names — not by the whole journal the daemon has accumulated. This harness
//! builds a synthetic state of that shape (N armed runs plus a recorded
//! journal of historical runs), starts the REAL supervision driver over it, and
//! samples this process' cumulative CPU across an idle window and across every
//! pass window: the sampling shape the issue measured a live daemon with.
//!
//! ```text
//! CARGO_TARGET_DIR=<warm target dir> cargo run --release --locked \
//!   --example supervision_pass_cost -- --armed 3 --history 12 --rows 48
//! ```
//!
//! Everything is a synthetic fixture in a temporary directory: no live state,
//! no daemon socket, no network, no credentials. The counter it samples is
//! this process' own CPU time (`getrusage`), which is the pass thread's cost
//! here exactly as the daemon's process CPU is the driver's cost live.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use canter::canonical::canonical_text;
use canter::config::ProfileBinding;
use canter::lifecycle::ConcurrencyCaps;
use canter::plan::DOCTRINE_WORKFLOW_ID;
use canter::queue_preview as qp;
use canter::state::{
    QueueSubmissionItemPlan, QueueSubmissionItemRow, QueueSubmissionPlan, Retention, State,
    SubmissionVerdict, SupervisionAuthorizationPlan,
};
use canter::supervision::{SupervisorOptions, start};
use canter::value::{Val, integer, null, object, string};

const REPO: &str = "example-org/widgets";
const REV: &str = "1111111111111111111111111111111111111111";
const WORKFLOW_HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const POLICY_HASH: &str = "feedface01234567feedface01234567feedface01234567feedface01234567";
const AT: &str = "2026-09-24T00:00:00Z";
/// The step kinds a representative recorded spine is built from.
const KINDS: [&str; 8] = [
    "checkout",
    "worktree_create",
    "harness_start",
    "prompt",
    "collect_outcome",
    "review_evidence",
    "merge",
    "cleanup",
];

fn main() {
    let options = Options::parse();
    println!(
        "supervision pass cost harness (issue #268) [{}]",
        options.label
    );
    println!(
        "fixture: armed_runs={} history_runs={} rows_per_run={} steps_per_spine={} \
         step_param_bytes={} check_interval_secs={} passes_to_sample={} timeout_secs={}",
        options.armed,
        options.history,
        options.rows,
        options.steps,
        options.step_param_bytes,
        options.interval_secs,
        options.passes,
        options.timeout_secs
    );

    let root = fixture_root(&options.label);
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("fixture root");
    let state = Arc::new(Mutex::new(
        State::open(&root.join("state.db"), Retention::default()).expect("open fixture state"),
    ));
    let facts = build_fixture(&state, &root, &options);
    println!(
        "corpus: rows={} bytes={} (armed_runs_rows={} armed_runs_bytes={} other_runs_rows={})",
        facts.total_rows,
        facts.total_bytes,
        facts.named_rows,
        facts.named_bytes,
        facts.total_rows - facts.named_rows
    );

    // The real driver over the real state: a boot pass (one reconciliation per
    // armed run), then one coalesced pass per wake/deadline.
    let mut supervisor = start(
        Arc::clone(&state),
        SupervisorOptions {
            max_wait_secs: options.interval_secs.clamp(1, 30),
            dispatch: None,
        },
    );
    let wake = supervisor.wake_handle();

    let started = Instant::now();
    let mut samples: Vec<(f64, f64)> = vec![(0.0, cpu_seconds())];
    let mut passes: Vec<Pass> = Vec::new();
    let mut observed = wake.ticks();
    let mut window_start = 0.0;
    let mut window_cpu = samples[0].1;
    let mut timed_out = false;
    while passes.len() < options.passes {
        std::thread::sleep(Duration::from_millis(200));
        let at = started.elapsed().as_secs_f64();
        let cpu = cpu_seconds();
        samples.push((at, cpu));
        let ticks = wake.ticks();
        if ticks > observed {
            passes.push(Pass {
                ticks: ticks - observed,
                start: window_start,
                wall: at - window_start,
                cpu: cpu - window_cpu,
            });
            observed = ticks;
            window_start = at;
            window_cpu = cpu;
        }
        if started.elapsed() >= Duration::from_secs(options.timeout_secs) {
            timed_out = true;
            break;
        }
    }
    let checks = wake.checks();
    wake.signal_stop();
    let _ = supervisor.join();

    print_samples(&samples, &passes, options.max_lines);
    for (index, pass) in passes.iter().enumerate() {
        println!(
            "pass {}: start={:.2}s end={:.2}s cpu={:.3}s wall={:.3}s ticks={}",
            index + 1,
            pass.start,
            pass.start + pass.wall,
            pass.cpu,
            pass.wall,
            pass.ticks
        );
    }
    let sampled = started.elapsed().as_secs_f64();
    if passes.is_empty() {
        println!(
            "SUMMARY: no pass completed within {}s (sampled {:.2}s wall)",
            options.timeout_secs, sampled
        );
        return;
    }
    let pass_cpu: f64 = passes.iter().map(|pass| pass.cpu).sum();
    let pass_wall: f64 = passes.iter().map(|pass| pass.wall).sum();
    let last_cpu = samples.last().map(|sample| sample.1).unwrap_or(0.0);
    println!(
        "SUMMARY: passes={} armed_runs={} history_runs={} rows={} corpus_bytes={} \
         mean_pass_cpu_s={:.3} mean_pass_wall_s={:.3} min_pass_cpu_s={:.3} total_sampled_s={:.2} \
         idle_cpu_s_per_s={:.4} checks={} timed_out={}",
        passes.len(),
        options.armed,
        options.history,
        facts.total_rows,
        facts.total_bytes,
        pass_cpu / passes.len() as f64,
        pass_wall / passes.len() as f64,
        passes
            .iter()
            .map(|pass| pass.cpu)
            .fold(f64::INFINITY, f64::min),
        sampled,
        ((last_cpu - samples[0].1 - pass_cpu).max(0.0)) / sampled.max(0.001),
        checks,
        timed_out
    );
}

/// One measured pass window: the CPU and wall between two driver ticks.
struct Pass {
    ticks: u64,
    start: f64,
    wall: f64,
    cpu: f64,
}

/// Cumulative CPU seconds of THIS process: the pass thread is the only busy
/// one, so the delta across a pass window is that pass' CPU cost.
fn cpu_seconds() -> f64 {
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    // SAFETY: `getrusage` writes into a live, correctly sized `rusage`.
    let status = unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) };
    assert_eq!(status, 0, "getrusage");
    let user = usage.ru_utime.tv_sec as f64 + usage.ru_utime.tv_usec as f64 / 1_000_000.0;
    let system = usage.ru_stime.tv_sec as f64 + usage.ru_stime.tv_usec as f64 / 1_000_000.0;
    user + system
}

/// One line per second, plus one at every pass boundary: the issue's shape.
fn print_samples(samples: &[(f64, f64)], passes: &[Pass], max_lines: usize) {
    println!("samples (cumulative process CPU, sampled every 200 ms, printed per second):");
    println!("{:>8}  {:>10}  {:>9}  window", "t(s)", "cpu(s)", "delta(s)");
    let ends: Vec<f64> = passes.iter().map(|pass| pass.start + pass.wall).collect();
    let mut previous = samples.first().map(|sample| sample.1).unwrap_or(0.0);
    let mut previous_at = 0.0;
    let mut printed = 0;
    for (index, (at, cpu)) in samples.iter().enumerate() {
        let boundary = ends
            .iter()
            .position(|end| *end <= *at && *end > previous_at);
        let second = at.floor() > previous_at.floor();
        let last = index + 1 == samples.len();
        if !(boundary.is_some() || second || last) {
            continue;
        }
        printed += 1;
        if printed > max_lines {
            println!("... ({} further samples suppressed)", samples.len() - index);
            break;
        }
        let label = match boundary {
            Some(pass) => format!("PASS {} window end", pass + 1),
            None => "idle/between passes".to_string(),
        };
        println!(
            "{:>8.2}  {:>10.3}  {:>9.3}  {}",
            at,
            cpu,
            cpu - previous,
            label
        );
        previous = *cpu;
        previous_at = *at;
    }
}

/// The synthetic journal one fixture writes: how many arms and how many bytes.
struct FixtureFacts {
    total_rows: usize,
    total_bytes: usize,
    /// Rows and bytes belonging to the runs THIS pass names (the armed runs).
    named_rows: usize,
    named_bytes: usize,
}

fn build_fixture(state: &Arc<Mutex<State>>, root: &Path, options: &Options) -> FixtureFacts {
    let mut facts = FixtureFacts {
        total_rows: 0,
        total_bytes: 0,
        named_rows: 0,
        named_bytes: 0,
    };
    let worktrees_root = root.join("worktrees");
    let integration_root = root.join("integration");
    std::fs::create_dir_all(&worktrees_root).expect("worktrees root");
    std::fs::create_dir_all(&integration_root).expect("integration root");
    let topology = object(vec![
        ("integration_branch", string("staging")),
        (
            "integration_repo",
            string(&integration_root.display().to_string()),
        ),
        ("production_branches", Val::Arr(Vec::new())),
        (
            "worktrees_root",
            string(&worktrees_root.display().to_string()),
        ),
    ]);

    // The armed runs: real committed submissions, real supervision rows.
    for index in 0..options.armed {
        let guard = state.lock().expect("state");
        let number = 5 + index as i64;
        let steps = spine_steps(options);
        let (bound, digest) = bound_submission(&guard, number, &steps);
        let submit_key = format!("ik_{index}-submit");
        let submission_id = canter::queue_executor::submission_id(&digest, &submit_key);
        let items = submit_run(&guard, number, &digest, &bound, &submission_id);
        let run = items[0].instance_id.clone().expect("admitted run");
        guard
            .arm_supervision(
                &run,
                &SupervisionAuthorizationPlan {
                    desired: "armed".to_string(),
                    check_interval_secs: options.interval_secs,
                    progress_timeout_secs: 900,
                },
                &digest,
                "merge",
                1,
                AT,
            )
            .expect("arm supervision");
        facts.named_bytes += seed_journal(
            &guard,
            &run,
            number,
            &steps,
            &topology,
            &digest,
            &submit_key,
            index as i64,
            options,
        );
        facts.named_rows += options.rows + 1;
    }

    // The historical journal: the same row shapes for runs this pass does NOT
    // name (finished runs whose records remain recorded in the journal).
    for index in 0..options.history {
        let guard = state.lock().expect("state");
        let number = 500 + index as i64;
        let run = format!("run-{:016x}", (index as u64) + 1);
        let steps = spine_steps(options);
        let digest = format!("{:064x}", index + 1);
        facts.total_bytes += seed_journal(
            &guard,
            &run,
            number,
            &steps,
            &topology,
            &digest,
            &format!("ik_hist{index}-submit"),
            (options.armed + index) as i64,
            options,
        );
        facts.total_rows += options.rows + 1;
    }
    facts.total_rows += facts.named_rows;
    facts.total_bytes += facts.named_bytes;
    facts
}

/// One recorded spine: `options.steps` declared steps over `KINDS`.
fn spine_steps(options: &Options) -> Vec<qp::PlannedStep> {
    (0..options.steps)
        .map(|index| {
            let kind = KINDS[index % KINDS.len()];
            let mut params = vec![("ref", string("staging"))];
            if kind == "prompt" || kind == "harness_start" {
                // A realistic step param: the lane's prompt text.
                params.push((
                    "prompt",
                    string(
                        &"describe the bounded change "
                            .repeat(options.step_param_bytes.max(1) / 28),
                    ),
                ));
            }
            qp::PlannedStep {
                id: format!("p{}", index + 1),
                kind: kind.to_string(),
                params: Some(object(params)),
            }
        })
        .collect()
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

fn bound_submission(state: &State, number: i64, steps: &[qp::PlannedStep]) -> (Val, String) {
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
        steps: steps.to_vec(),
        selected: vec![qp::SelectedIssue {
            id: format!("#{number}"),
            title: None,
            revision: REV.to_string(),
            requires: Vec::new(),
        }],
    };
    let preview = qp::preview_queue(state, &request).expect("preview renders");
    let bound = preview.doc.get("request").cloned().expect("bound document");
    (bound, preview.digest)
}

fn submit_run(
    state: &State,
    number: i64,
    digest: &str,
    bound: &Val,
    submission_id: &str,
) -> Vec<QueueSubmissionItemRow> {
    let grant_id = format!("gr_{:016x}", number);
    if state.grant_by_id(&grant_id).expect("grant read").is_none() {
        state
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
            .expect("grant document");
    }
    let plan = QueueSubmissionPlan {
        submission_id: submission_id.to_string(),
        repository: REPO.to_string(),
        state_epoch: state.current_epoch().expect("epoch"),
        digest: digest.to_string(),
        role_key: "lane-1".to_string(),
        role_revision: "e".repeat(64),
        workflow_id: DOCTRINE_WORKFLOW_ID.to_string(),
        workflow_hash: WORKFLOW_HASH.to_string(),
        boundary_phase: "merge".to_string(),
        integration_branch: "staging".to_string(),
        completion_branch: "staging".to_string(),
        boundary_caps: vec!["read".into(), "worktree".into(), "merge".into()],
        request_line: canonical_text(bound),
        admission_caps: ConcurrencyCaps {
            global: 16,
            per_repository: 16,
            per_harness: 16,
        },
        harness_lanes: Some(0),
        items: vec![QueueSubmissionItemPlan {
            ordinal: 0,
            work_item: format!("{REPO}#{number}"),
            issue_number: number,
            issue_revision: REV.to_string(),
            grant_id: Some(grant_id),
            resume_digest: None,
            verdict: SubmissionVerdict::Approved,
        }],
        supervision: None,
        at: AT.to_string(),
    };
    let (_, items) = state.submit_queue_run(&plan).expect("submission commits");
    items
}

/// Write one run's recorded journal: a `queue.submit` row plus `options.rows`
/// `apply` rows, each presenting the run's WHOLE plan (the shape the daemon
/// records) and most of them a response — the documents the read path parses.
#[allow(clippy::too_many_arguments)]
fn seed_journal(
    state: &State,
    run: &str,
    number: i64,
    steps: &[qp::PlannedStep],
    topology: &Val,
    digest: &str,
    submit_key: &str,
    salt: i64,
    options: &Options,
) -> usize {
    let step_docs: Vec<Val> = steps
        .iter()
        .map(|step| {
            object(vec![
                ("id", string(&step.id)),
                ("kind", string(&step.kind)),
                (
                    "params",
                    step.params
                        .clone()
                        .unwrap_or_else(canter::value::object_empty),
                ),
            ])
        })
        .collect();
    let submit_request = canonical_text(&object(vec![
        ("schema", string("hf-rpc-request/v1")),
        ("id", string(&format!("sub_{salt}"))),
        ("method", string("queue.submit")),
        (
            "params",
            object(vec![
                ("digest", string(digest)),
                (
                    "dispatch",
                    object(vec![
                        ("topology", topology.clone()),
                        (
                            "admission",
                            object(vec![
                                ("harness_lanes", integer(0)),
                                ("host_available", Val::Bool(true)),
                                ("caps", object(vec![("global", integer(4))])),
                            ]),
                        ),
                    ]),
                ),
            ]),
        ),
    ]));
    let submit_response = canonical_text(&object(vec![
        ("schema", string("hf-rpc-response/v1")),
        ("id", string(&format!("sub_{salt}"))),
        ("ok", Val::Bool(true)),
        (
            "result",
            object(vec![
                ("admitted", integer(1)),
                ("integration_base", string(&"a".repeat(40))),
            ]),
        ),
    ]));
    let mut bytes = write_row(
        state,
        "queue.submit",
        &format!("{submit_key}-submit"),
        &submit_request,
        &submit_response,
    );
    for index in 0..options.rows {
        let step = &steps[index % steps.len()];
        let key = format!("ik_{salt}-{}", index + 1);
        let succeeded = index + 3 < options.rows;
        let request = canonical_text(&object(vec![
            ("schema", string("hf-rpc-request/v1")),
            ("id", string(&format!("disp_{}", step.id))),
            ("method", string("apply")),
            (
                "params",
                object(vec![
                    ("idempotency_key", string(&key)),
                    ("instance_id", string(run)),
                    ("step", string(&step.id)),
                    ("grant_id", string(&format!("gr_{:016x}", number))),
                    (
                        "observed",
                        object(vec![
                            ("issue_revision", string(REV)),
                            ("policy_hash", string(POLICY_HASH)),
                            (
                                "feature_head",
                                if index % 7 == 0 {
                                    string(&"b".repeat(40))
                                } else {
                                    null()
                                },
                            ),
                            ("integration_base", null()),
                        ]),
                    ),
                    (
                        "plan",
                        object(vec![
                            ("schema", string("hf-plan/v1")),
                            ("id", string(&format!("hf_plan_{salt:016x}"))),
                            ("steps", Val::Arr(step_docs.clone())),
                        ]),
                    ),
                    ("topology", topology.clone()),
                    ("profile", null()),
                    (
                        "flags",
                        object(vec![
                            ("interactive", Val::Bool(false)),
                            ("digest_confirmed", Val::Bool(false)),
                            ("scheduled", Val::Bool(false)),
                        ]),
                    ),
                ]),
            ),
        ]));
        let outcome = canonical_text(&object(vec![
            ("schema", string("hf-outcome/v1")),
            ("plan_id", string(&format!("hf_plan_{salt:016x}"))),
            ("step_id", string(&step.id)),
            (
                "status",
                string(if succeeded { "succeeded" } else { "failed" }),
            ),
            ("idempotency_key", string(&key)),
            ("observed_at", string(AT)),
            ("result", null()),
            (
                "error",
                if succeeded {
                    null()
                } else {
                    object(vec![
                        ("code", string("effect.command_failed")),
                        (
                            "message",
                            string("the recorded effect reported a non-zero exit"),
                        ),
                    ])
                },
            ),
        ]));
        let response = canonical_text(&object(vec![
            ("schema", string("hf-rpc-response/v1")),
            ("id", string(&format!("disp_{}", step.id))),
            ("ok", Val::Bool(true)),
            (
                "result",
                object(vec![
                    (
                        "status",
                        string(if succeeded { "succeeded" } else { "failed" }),
                    ),
                    ("branch", string(&format!("issues/{number}"))),
                    ("head", string(&"c".repeat(40))),
                    ("base_head", string(&"a".repeat(40))),
                ]),
            ),
        ]));
        bytes += write_row(state, "apply", &key, &request, &response) + outcome.len();
    }
    bytes
}

/// Journal one claim and resolve it: the durable shape every reader parses.
fn write_row(state: &State, method: &str, key: &str, request_line: &str, response: &str) -> usize {
    let request_id = format!("{key}-req");
    state
        .journal_intent(
            "mutate.checkout",
            key,
            key,
            &request_id,
            method,
            None,
            None,
            request_line,
        )
        .expect("claim the recorded row");
    let outcome = canonical_text(&object(vec![
        ("plan_id", string("hf_plan_0000000000000000")),
        ("step_id", string("p1")),
        ("status", string("succeeded")),
        ("idempotency_key", string(key)),
    ]));
    state
        .resolve_claim(key, method, "spent", &outcome, Some(response))
        .expect("resolve the recorded row");
    request_line.len() + response.len() + outcome.len()
}

struct Options {
    armed: usize,
    history: usize,
    rows: usize,
    steps: usize,
    step_param_bytes: usize,
    interval_secs: i64,
    passes: usize,
    timeout_secs: u64,
    max_lines: usize,
    label: String,
}

impl Options {
    fn parse() -> Options {
        let mut options = Options {
            armed: 3,
            history: 12,
            rows: 48,
            steps: 20,
            step_param_bytes: 300,
            interval_secs: 2,
            passes: 3,
            timeout_secs: 900,
            max_lines: 60,
            label: "run".to_string(),
        };
        let args: Vec<String> = std::env::args().skip(1).collect();
        let mut index = 0;
        while index < args.len() {
            let flag = args[index].clone();
            let value = |index: &mut usize| {
                *index += 1;
                args.get(*index)
                    .cloned()
                    .unwrap_or_else(|| panic!("{flag} needs a value"))
            };
            match flag.as_str() {
                "--armed" => options.armed = number(&value(&mut index), &flag),
                "--history" => options.history = number(&value(&mut index), &flag),
                "--rows" => options.rows = number(&value(&mut index), &flag),
                "--steps" => options.steps = number(&value(&mut index), &flag),
                "--step-param-bytes" => {
                    options.step_param_bytes = number(&value(&mut index), &flag)
                }
                "--interval" => options.interval_secs = number(&value(&mut index), &flag) as i64,
                "--passes" => options.passes = number(&value(&mut index), &flag),
                "--timeout" => options.timeout_secs = number(&value(&mut index), &flag) as u64,
                "--max-lines" => options.max_lines = number(&value(&mut index), &flag),
                "--label" => options.label = value(&mut index),
                other => panic!("unknown flag {other}"),
            }
            index += 1;
        }
        options
    }
}

fn number(text: &str, flag: &str) -> usize {
    text.parse()
        .unwrap_or_else(|_| panic!("{flag} needs a number, got {text:?}"))
}

/// The fixture root this run uses (removed and rebuilt at startup).
fn fixture_root(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!("canter-pass-cost-{}-{label}", std::process::id()))
}
