//! Issue #86 acceptance tests: the CLI parity surface of the run-scoped
//! controls (`canter run pause|resume|retry|status`) over the REAL binary and
//! a real daemon child.
//!
//! The controlled run is the durable `run-` row the queue executor commits
//! for one admitted issue (synthetic identities only; the reviewed binding is
//! derived from the same config shape the CLI loads). Evidence rules: raw
//! process exits are asserted directly, the JSON assertions parse the
//! documented `hf-output/v1` envelope, and the CLI/daemon readback agreement
//! is a byte-level canonical comparison.

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use canter::canonical::canonical_text;
use canter::client::Connection;
use canter::config::ProfileBinding;
use canter::lifecycle::ConcurrencyCaps;
use canter::plan::DOCTRINE_WORKFLOW_ID;
use canter::queue_preview as qp;
use canter::state::{
    QueueSubmissionItemPlan, QueueSubmissionPlan, Retention, State, SubmissionVerdict,
};
use canter::value::{Val, object, string};

const REPO: &str = "example-org/widgets";
const HOST: &str = "host-1";
const HARNESS: &str = "lane-1";
const REV_A: &str = "1111111111111111111111111111111111111111";
const WORKFLOW_HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const POLICY_HASH: &str = "feedface01234567feedface01234567feedface01234567feedface01234567";
const GRANT_5: &str = "gr_0000000000000093";
const AT: &str = "2026-09-12T00:00:00Z";

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_canter")
}

fn binding_doc() -> Val {
    let mut binding = ProfileBinding {
        key: HARNESS.to_string(),
        kind: "pi".to_string(),
        provider: "provider-a".to_string(),
        model: "model-a".to_string(),
        fallbacks: Vec::new(),
        configured_limits: Vec::new(),
        introspection: false,
        secrets: Vec::new(),
        revision: String::new(),
    };
    binding.revision = binding.revision_of();
    binding.to_doc()
}

fn role_revision() -> String {
    binding_doc()
        .get("revision")
        .and_then(Val::as_str)
        .expect("binding revision")
        .to_string()
}

fn request_with(issue_number: i64) -> qp::QueueRequest {
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
            phase: "merge".to_string(),
            integration_branch: "staging".to_string(),
            completion_branch: "staging".to_string(),
            caps: vec!["read".to_string(), "merge".to_string()],
        },
        steps: vec![
            qp::PlannedStep {
                id: "p1".to_string(),
                kind: "checkout".to_string(),
                params: Some(object(vec![("ref", string("staging"))])),
            },
            qp::PlannedStep {
                id: "p2".to_string(),
                kind: "checkout".to_string(),
                params: Some(object(vec![("ref", string("staging"))])),
            },
        ],
        selected: vec![qp::SelectedIssue {
            id: format!("#{issue_number}"),
            title: None,
            revision: REV_A.to_string(),
            requires: Vec::new(),
        }],
    }
}

fn work_item(number: i64) -> String {
    qp::IssueId::parse(&format!("#{number}"), REPO)
        .expect("issue id")
        .work_item()
}

/// Commit one submission directly into the fixture's state store (the same
/// path the daemon's `queue.submit` commits) and return the admitted run id.
fn seed_run(state: &State) -> String {
    let grant: Val = Val::parse_json(&format!(
        r#"{{"schema":"hf-grant/v1","grant_id":"{GRANT_5}","repository":"{REPO}",
            "issue":{{"number":5,"revision":"{REV_A}"}},
            "workflow_hash":"{WORKFLOW_HASH}","policy_hash":"{POLICY_HASH}",
            "phase":"merge","scope":"worktrees/issues/5",
            "caps":["read","worktree","spawn","merge"],
            "expires_at":"2999-01-01T00:00:00Z","state_epoch":1,
            "created_at":"2026-09-06T00:00:00Z"}}"#
    ))
    .expect("grant doc");
    state.issue_grant(&grant).expect("issue grant");
    let preview = qp::preview_queue(state, &request_with(5)).expect("preview");
    let bound = preview
        .doc
        .get("request")
        .cloned()
        .expect("bound-input document");
    let epoch = state.current_epoch().expect("epoch");
    let plan = QueueSubmissionPlan {
        submission_id: format!("qs_{:016x}", 0x86u64),
        repository: REPO.to_string(),
        state_epoch: epoch,
        digest: preview.digest.clone(),
        role_key: HARNESS.to_string(),
        role_revision: role_revision(),
        workflow_id: DOCTRINE_WORKFLOW_ID.to_string(),
        workflow_hash: WORKFLOW_HASH.to_string(),
        boundary_phase: "merge".to_string(),
        integration_branch: "staging".to_string(),
        completion_branch: "staging".to_string(),
        boundary_caps: vec!["read".to_string(), "merge".to_string()],
        request_line: canonical_text(&bound),
        admission_caps: ConcurrencyCaps {
            global: 4,
            per_repository: 2,
            per_harness: 2,
        },
        harness_lanes: Some(0),
        items: vec![QueueSubmissionItemPlan {
            ordinal: 0,
            work_item: work_item(5),
            issue_number: 5,
            issue_revision: REV_A.to_string(),
            grant_id: Some(GRANT_5.to_string()),
            resume_digest: None,
            verdict: SubmissionVerdict::Approved,
        }],
        // Issue #95: no supervision authorization is presented here.
        supervision: None,
        at: AT.to_string(),
    };
    let (_, items) = state.submit_queue_run(&plan).expect("submission commits");
    items[0].instance_id.clone().expect("admitted run id")
}

struct Fixture {
    dir: PathBuf,
    state_dir: PathBuf,
    socket: PathBuf,
    config_path: PathBuf,
}

impl Fixture {
    fn new(name: &str) -> Fixture {
        let dir = std::env::temp_dir().join(format!("hf-run-cli-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("fixture dir");
        let fixture = Fixture {
            state_dir: dir.join("state"),
            socket: dir.join("daemon.sock"),
            config_path: dir.join("config.toml"),
            dir,
        };
        std::fs::write(
            &fixture.config_path,
            format!(
                "schema = \"hf-config/v1\"\n\
                 \n\
                 [daemon]\n\
                 enabled = true\n\
                 socket = \"{}\"\n\
                 \n\
                 [repository.widgets]\n\
                 origin = \"https://example.invalid/{REPO}\"\n\
                 \n\
                 [harness.{HARNESS}]\n\
                 kind = \"pi\"\n\
                 executable = \"herdr\"\n\
                 env_allow = []\n\
                 provider = \"provider-a\"\n\
                 model = \"model-a\"\n\
                 binding_introspection = false\n",
                fixture.socket.display()
            ),
        )
        .expect("write config");
        fixture
    }

    fn db(&self) -> PathBuf {
        self.state_dir.join("canter").join("state.db")
    }

    fn seed(&self) -> State {
        std::fs::create_dir_all(self.state_dir.join("canter")).expect("state dir");
        State::open(&self.db(), Retention::default()).expect("open state")
    }

    fn spawn(&self) -> Child {
        std::fs::create_dir_all(&self.state_dir).expect("state home");
        let mut command = Command::new(bin());
        command
            .args(["daemon", "run", "--socket"])
            .arg(&self.socket)
            .env("XDG_STATE_HOME", &self.state_dir)
            .env("HOME", &self.dir)
            .stdout(Stdio::null())
            .stderr(Stdio::from(
                std::fs::File::create(self.dir.join("daemon.stderr.log")).expect("stderr log"),
            ));
        command.spawn().expect("spawn daemon")
    }

    /// Run the CLI with the fixture environment and return (exit, stdout,
    /// stderr).
    fn cli(&self, args: &[&str]) -> (i32, String, String) {
        let mut command = Command::new(bin());
        command
            .args(args)
            .env("XDG_STATE_HOME", &self.state_dir)
            .env("HOME", &self.dir);
        let output = command.output().expect("run cli");
        (
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stdout).into_owned(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        )
    }
}

fn wait_ready(fixture: &Fixture) {
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
        "daemon did not become ready on {}; stderr:\n{stderr}",
        fixture.socket.display()
    );
}

fn shutdown(mut daemon: Child) {
    let _ = daemon.kill();
    let deadline = Instant::now() + Duration::from_secs(10);
    while daemon.try_wait().expect("try_wait").is_none() {
        assert!(Instant::now() < deadline, "daemon did not exit");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Parse one `hf-output/v1` envelope from the CLI stdout.
fn envelope(output: &str) -> Val {
    let doc = Val::parse_json(output.trim_end()).expect("one JSON envelope");
    let verdict = canter::schema::validate_doc(canter::schema::Family::Output, &doc);
    assert!(verdict.is_accepted(), "envelope: {}", verdict.message());
    doc
}

fn data_of(envelope: &Val) -> Val {
    envelope.get("data").cloned().expect("data")
}

fn error_code(envelope: &Val) -> String {
    envelope
        .get("error")
        .and_then(|error| error.get("code"))
        .and_then(Val::as_str)
        .unwrap_or_default()
        .to_string()
}

fn control_state(doc: &Val) -> String {
    doc.get("control")
        .and_then(|control| control.get("state"))
        .and_then(Val::as_str)
        .unwrap_or_default()
        .to_string()
}

fn resume_digest(doc: &Val) -> String {
    doc.get("control")
        .and_then(|control| control.get("resume_digest"))
        .and_then(Val::as_str)
        .unwrap_or_default()
        .to_string()
}

#[test]
fn cli_run_controls_round_trip_through_the_real_daemon() {
    let fixture = Fixture::new("round-trip");
    let run = {
        let state = fixture.seed();
        seed_run(&state)
    };
    let daemon = fixture.spawn();
    wait_ready(&fixture);
    let socket_arg = fixture.socket.display().to_string();
    let config_arg = fixture.config_path.display().to_string();

    // The fresh run is active and its document is the documented schema.
    let (exit, stdout, stderr) = fixture.cli(&[
        "run",
        "status",
        "--run",
        &run,
        "--socket",
        &socket_arg,
        "--config",
        &config_arg,
        "--json",
    ]);
    assert_eq!(exit, 0, "status exit; stderr: {stderr}");
    let status = data_of(&envelope(&stdout));
    assert_eq!(
        status.get("schema").and_then(Val::as_str),
        Some(canter::run_control::RUN_CONTROL_SCHEMA)
    );
    assert_eq!(control_state(&status), "active");

    // Pause: no in-flight step, so the safe boundary is reached at once.
    let (exit, stdout, stderr) = fixture.cli(&[
        "run",
        "pause",
        "--run",
        &run,
        "--reason",
        "operator hold",
        "--socket",
        &socket_arg,
        "--config",
        &config_arg,
        "--json",
    ]);
    assert_eq!(exit, 0, "pause exit; stderr: {stderr}");
    let paused = data_of(&envelope(&stdout));
    assert_eq!(control_state(&paused), "paused");
    assert_eq!(
        paused
            .get("boundary")
            .and_then(|boundary| boundary.get("reached"))
            .and_then(Val::as_bool),
        Some(true)
    );
    let digest = resume_digest(&paused);
    assert_eq!(digest.len(), 64);

    // Human mode renders the same state.
    let (exit, stdout, stderr) = fixture.cli(&[
        "run",
        "status",
        "--run",
        &run,
        "--socket",
        &socket_arg,
        "--config",
        &config_arg,
    ]);
    assert_eq!(exit, 0, "human status exit; stderr: {stderr}");
    assert!(stdout.contains("paused"), "human rendering: {stdout}");

    // A wrong digest is refused typed (exit 1: the engine's stale-resume
    // code is not a `refusal.*` code — the same mapping `queue submit`
    // already uses for a stale resume authorization).
    let (exit, stdout, stderr) = fixture.cli(&[
        "run",
        "resume",
        "--run",
        &run,
        "--digest",
        &"0".repeat(64),
        "--socket",
        &socket_arg,
        "--config",
        &config_arg,
        "--json",
    ]);
    assert_eq!(exit, 1, "wrong digest exit; stderr: {stderr}");
    assert_eq!(error_code(&envelope(&stdout)), "state.stale_resume");

    // A retry is REFUSED while the pause holds the run (stop-admitting
    // precedes every control), then the exact digest resumes the run.
    let (exit, stdout, stderr) = fixture.cli(&[
        "run",
        "retry",
        "--run",
        &run,
        "--step",
        "p1",
        "--socket",
        &socket_arg,
        "--config",
        &config_arg,
        "--json",
    ]);
    assert_eq!(exit, 4, "retry-while-paused exit; stderr: {stderr}");
    assert_eq!(
        error_code(&envelope(&stdout)),
        "refusal.run.paused",
        "the pause precedes the retry surface"
    );

    // The exact digest resumes the run.
    let (exit, stdout, stderr) = fixture.cli(&[
        "run",
        "resume",
        "--run",
        &run,
        "--digest",
        &digest,
        "--socket",
        &socket_arg,
        "--config",
        &config_arg,
        "--json",
    ]);
    assert_eq!(exit, 0, "resume exit; stderr: {stderr}");
    assert_eq!(control_state(&data_of(&envelope(&stdout))), "active");

    // A retry of a step with no recorded failure refuses typed (exit 4).
    let (exit, stdout, stderr) = fixture.cli(&[
        "run",
        "retry",
        "--run",
        &run,
        "--step",
        "p1",
        "--socket",
        &socket_arg,
        "--config",
        &config_arg,
        "--json",
    ]);
    assert_eq!(exit, 4, "undiagnosed retry exit; stderr: {stderr}");
    assert_eq!(
        error_code(&envelope(&stdout)),
        "refusal.run.step_undiagnosed"
    );

    // A step outside the bound spine refuses typed (exit 4).
    let (exit, stdout, stderr) = fixture.cli(&[
        "run",
        "retry",
        "--run",
        &run,
        "--step",
        "nope",
        "--socket",
        &socket_arg,
        "--config",
        &config_arg,
        "--json",
    ]);
    assert_eq!(exit, 4, "unknown step exit; stderr: {stderr}");
    assert_eq!(error_code(&envelope(&stdout)), "refusal.run.step_unknown");

    // The daemon-side readback of the same run agrees with the CLI document.
    let mut connection = Connection::open(&fixture.socket).expect("connect");
    connection
        .send_request(
            "abcdef01",
            "run.status",
            Some(&canter::run_control::status_params(&run)),
        )
        .expect("send");
    let response = connection.read_response().expect("read");
    assert!(response.ok, "daemon readback is ok");
    let (exit, stdout, stderr) = fixture.cli(&[
        "run",
        "status",
        "--run",
        &run,
        "--socket",
        &socket_arg,
        "--config",
        &config_arg,
        "--json",
    ]);
    assert_eq!(exit, 0, "status exit; stderr: {stderr}");
    assert_eq!(
        canonical_text(&response.result),
        canonical_text(&data_of(&envelope(&stdout))),
        "CLI/JSON and daemon readback must agree"
    );

    shutdown(daemon);
}

#[test]
fn cli_run_duplicate_key_refuses_a_reused_key_and_usage_errors_exit_two() {
    let fixture = Fixture::new("usage");
    let run = {
        let state = fixture.seed();
        seed_run(&state)
    };
    let daemon = fixture.spawn();
    wait_ready(&fixture);
    let socket_arg = fixture.socket.display().to_string();
    let config_arg = fixture.config_path.display().to_string();

    // A key belongs to exactly ONE request: replaying it from a fresh
    // invocation (a new request id) is refused typed, never silently
    // re-driven — the CLI surface can never re-commit a recorded control.
    let key = "ik_86-cli-replay-0001";
    let first = fixture.cli(&[
        "run",
        "pause",
        "--run",
        &run,
        "--reason",
        "hold",
        "--idempotency-key",
        key,
        "--socket",
        &socket_arg,
        "--config",
        &config_arg,
        "--json",
    ]);
    assert_eq!(first.0, 0, "pause exit; stderr: {}", first.2);
    assert_eq!(control_state(&data_of(&envelope(&first.1))), "paused");
    let second = fixture.cli(&[
        "run",
        "pause",
        "--run",
        &run,
        "--reason",
        "hold",
        "--idempotency-key",
        key,
        "--socket",
        &socket_arg,
        "--config",
        &config_arg,
        "--json",
    ]);
    assert_eq!(second.0, 1, "replayed key exit; stderr: {}", second.2);
    assert_eq!(error_code(&envelope(&second.1)), "state.claim_reused");

    // Usage errors never reach the daemon (exit 2, stdout stays empty).
    for args in [
        &["run", "pause", "--run", "not-a-run", "--reason", "hold"][..],
        &["run", "pause", "--run", &run][..],
        &["run", "resume", "--run", &run, "--digest", "short"][..],
        &["run", "status", "--run", &run, "--step", "p1"][..],
        &["run", "retry", "--run", &run, "--step", "not a slug"][..],
        &["run", "release", "--run", &run][..],
        &[
            "run",
            "pause",
            "--run",
            &run,
            "--reason",
            "hold",
            "--idempotency-key",
            "bad",
        ][..],
    ] {
        let (exit, stdout, stderr) = fixture.cli(args);
        assert_eq!(exit, 2, "{args:?} must be a usage error; stderr: {stderr}");
        assert!(stdout.is_empty(), "{args:?}: stdout stays empty");
        assert!(
            stderr.contains("run"),
            "{args:?}: the usage error names the command: {stderr}"
        );
    }

    // The help surface documents the subcommands.
    let (exit, stdout, stderr) = fixture.cli(&["run", "--help"]);
    assert_eq!(exit, 0, "run --help exit; stderr: {stderr}");
    for needle in [
        "run pause",
        "run resume",
        "run retry",
        "run release",
        "run dispatch",
        "run status",
    ] {
        assert!(
            stdout.contains(needle),
            "help must document {needle}: {stdout}"
        );
    }

    shutdown(daemon);
}

#[test]
fn cli_run_controls_refuse_a_stale_daemon_and_absent_daemon_typed() {
    // No daemon: the socket is absent and every control (including the
    // read-only status) reports the absent daemon typed — never a crash.
    let fixture = Fixture::new("absent");
    let _ = fixture.seed(); // the state store exists; the daemon does not.
    let socket_arg = fixture.socket.display().to_string();
    let config_arg = fixture.config_path.display().to_string();
    let (exit, _stdout, stderr) = fixture.cli(&[
        "run",
        "status",
        "--run",
        "run-0000000000000001",
        "--socket",
        &socket_arg,
        "--config",
        &config_arg,
        "--json",
    ]);
    assert_eq!(exit, 1, "absent daemon exit; stderr: {stderr}");
    assert!(
        stderr.contains("daemon.absent"),
        "the refusal is typed: {stderr}"
    );
}

/// The CLI helper's read of the state store is never used while the daemon
/// runs; this pins that the seed path yields exactly one run (fixture sanity).
#[test]
fn fixture_seed_yields_exactly_one_run() {
    let fixture = Fixture::new("seed");
    let state = fixture.seed();
    let run = seed_run(&state);
    assert!(run.starts_with("run-"), "run id: {run}");
    assert_eq!(state.list_instances().expect("instances").len(), 1);
}

/// Issue #146: releasing one run that can never progress through the public
/// entry point — two separate invocations against one daemon, raw exits, and
/// the daemon's own readback.
#[test]
fn cli_run_release_frees_the_run_and_records_a_second_release_as_absent() {
    let fixture = Fixture::new("release");
    let run = {
        let state = fixture.seed();
        seed_run(&state)
    };
    let daemon = fixture.spawn();
    wait_ready(&fixture);
    let socket_arg = fixture.socket.display().to_string();
    let config_arg = fixture.config_path.display().to_string();

    // The release renders the documented facts in human mode.
    let (exit, stdout, stderr) = fixture.cli(&[
        "run",
        "release",
        "--run",
        &run,
        "--reason",
        "predecessor is dead",
        "--socket",
        &socket_arg,
        "--config",
        &config_arg,
    ]);
    assert_eq!(exit, 0, "release exit; stderr: {stderr}");
    assert!(
        stdout.contains(&format!(
            "run {run} released: status invalidated, ownership freed"
        )),
        "{stdout}"
    );
    assert!(stdout.contains("reason: predecessor is dead"), "{stdout}");
    assert!(
        stdout.contains(&format!(
            "authorization window at release: {GRANT_5} (active, expires 2999-01-01T00:00:00Z, usable true)"
        )),
        "{stdout}"
    );
    assert!(
        stdout.contains(&format!(
            "scope: run {run} only; no fleet-level or lane effect"
        )),
        "{stdout}"
    );

    // The daemon's own readback (its own invocation) agrees.
    let (exit, stdout, stderr) = fixture.cli(&[
        "run",
        "status",
        "--run",
        &run,
        "--socket",
        &socket_arg,
        "--config",
        &config_arg,
        "--json",
    ]);
    assert_eq!(exit, 0, "status exit; stderr: {stderr}");
    let status = data_of(&envelope(&stdout));
    assert_eq!(
        status
            .get("run")
            .and_then(|run| run.get("status"))
            .and_then(Val::as_str),
        Some("invalidated")
    );

    // A SECOND release with a fresh key is an audited ownership-absent no-op.
    let (exit, stdout, stderr) = fixture.cli(&[
        "run",
        "release",
        "--run",
        &run,
        "--reason",
        "again",
        "--socket",
        &socket_arg,
        "--config",
        &config_arg,
        "--json",
    ]);
    assert_eq!(exit, 0, "terminal release: {stdout} {stderr}");
    assert_eq!(
        data_of(&envelope(&stdout))
            .get("release")
            .and_then(|release| release.get("ownership"))
            .and_then(Val::as_str),
        Some("absent")
    );

    shutdown(daemon);
}
