//! Issue #85 acceptance tests: the CLI parity surface of the queue
//! executor (`canter queue submit` / `canter queue status`) over the REAL
//! binary and a real daemon child.
//!
//! The configuration is written per-test with synthetic identities only; the
//! reviewed binding is derived from the SAME config the CLI re-observes, so
//! the digest/epoch/revision checks are exercised against real dynamic
//! configuration (never a hard-coded provider/model pair).
//!
//! Evidence rules: raw process exits are asserted directly, the JSON
//! assertions parse the documented `hf-output/v1` envelope, and the
//! CLI/daemon readback agreement is a byte-level canonical comparison.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use canter::client::Connection;
use canter::config::{ProfileBinding, credential_environment, load_config};
use canter::lifecycle::ConcurrencyCaps;
use canter::plan::DOCTRINE_WORKFLOW_ID;
use canter::queue_executor as qx;
use canter::queue_preview as qp;
use canter::state::{Retention, State};
use canter::value::{Val, object, string};

const REPO: &str = "example-org/widgets";
const HARNESS: &str = "lane-1";
const REV_A: &str = "1111111111111111111111111111111111111111";
const WORKFLOW_HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const POLICY_HASH: &str = "feedface01234567feedface01234567feedface01234567feedface01234567";

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_canter")
}

struct Fixture {
    dir: PathBuf,
    state_dir: PathBuf,
    socket: PathBuf,
    config_path: PathBuf,
}

impl Fixture {
    fn new(name: &str) -> Fixture {
        let dir = std::env::temp_dir().join(format!("hf-queue-cli-{name}-{}", std::process::id()));
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
    assert_eq!(
        doc.get("schema").and_then(Val::as_str),
        Some("hf-output/v1")
    );
    doc
}

/// The reviewed role binding derived from the SAME config the CLI loads.
fn config_binding(config_path: &Path) -> Val {
    let config = load_config(config_path).expect("load config");
    let harness = config
        .harnesses
        .iter()
        .find(|harness| harness.key == HARNESS)
        .expect("harness");
    let env = credential_environment(harness);
    ProfileBinding::from_config(&config, HARNESS, &env)
        .expect("binding")
        .to_doc()
}

fn request_with(version_binding: &Val, issues: &[(&str, &str)]) -> qp::QueueRequest {
    qp::QueueRequest {
        repository: REPO.to_string(),
        host: "host-1".to_string(),
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
        role_config: version_binding.clone(),
        boundary: qp::Boundary {
            phase: "merge".to_string(),
            integration_branch: "staging".to_string(),
            completion_branch: "staging".to_string(),
            caps: vec!["read".to_string(), "merge".to_string()],
        },
        steps: vec![qp::PlannedStep {
            id: "p1".to_string(),
            kind: "checkout".to_string(),
            params: Some(object(vec![("ref", string("staging"))])),
        }],
        selected: issues
            .iter()
            .map(|(id, revision)| qp::SelectedIssue {
                id: (*id).to_string(),
                title: None,
                revision: (*revision).to_string(),
                requires: Vec::new(),
            })
            .collect(),
    }
}

fn grant_doc(grant_id: &str, number: i64) -> Val {
    Val::parse_json(&format!(
        r#"{{"schema":"hf-grant/v1","grant_id":"{grant_id}","repository":"{REPO}",
            "issue":{{"number":{number},"revision":"{REV_A}"}},
            "workflow_hash":"{WORKFLOW_HASH}","policy_hash":"{POLICY_HASH}",
            "phase":"merge","scope":"worktrees/issues/{number}",
            "caps":["read","worktree","spawn","merge"],
            "expires_at":"2999-01-01T00:00:00Z","state_epoch":1,
            "created_at":"2026-09-06T00:00:00Z"}}"#
    ))
    .expect("grant document")
}

#[test]
fn cli_submit_and_status_agree_with_the_daemon_readback() {
    let fixture = Fixture::new("agree");
    let (bound_path, digest) = {
        let state = fixture.seed();
        state
            .issue_grant(&grant_doc("gr_0000000000000101", 5))
            .expect("grant 5");
        // Issue 6 is selected without a presented grant: refused, labelled.
        let request = request_with(
            &config_binding(&fixture.config_path),
            &[("#5", REV_A), ("#6", REV_A)],
        );
        let preview = qp::preview_queue(&state, &request).expect("preview");
        let bound = preview
            .doc
            .get("request")
            .cloned()
            .expect("bound-input document");
        let path = fixture.dir.join("request.json");
        std::fs::write(&path, canter::canonical::canonical_text(&bound)).expect("write request");
        (path, preview.digest)
    };
    let daemon = fixture.spawn();
    wait_ready(&fixture);

    let request_arg = bound_path.display().to_string();
    let config_arg = fixture.config_path.display().to_string();
    let socket_arg = fixture.socket.display().to_string();
    let (exit, stdout, stderr) = fixture.cli(&[
        "queue",
        "submit",
        "--request",
        &request_arg,
        "--confirm-digest",
        &digest,
        "--epoch",
        "1",
        "--caps",
        "4/2/2",
        "--grant",
        "example-org/widgets#5=gr_0000000000000101",
        "--host-available",
        "yes",
        "--harness-lanes",
        "0",
        "--socket",
        &socket_arg,
        "--config",
        &config_arg,
        "--json",
    ]);
    assert_eq!(exit, 0, "submit exit; stderr: {stderr}");
    let submitted_envelope = envelope(&stdout);
    assert_eq!(
        submitted_envelope.get("command").and_then(Val::as_str),
        Some("queue submit")
    );
    let submitted = submitted_envelope.get("data").cloned().expect("data");
    let submission_id = submitted
        .get("submission_id")
        .and_then(Val::as_str)
        .expect("submission id")
        .to_string();
    assert_eq!(
        submitted.get("schema").and_then(Val::as_str),
        Some(qx::QUEUE_SUBMISSION_SCHEMA)
    );
    let items = submitted
        .get("items")
        .and_then(Val::as_array)
        .expect("items");
    assert_eq!(items.len(), 2);
    let status_of = |id: &str| -> (String, Option<String>) {
        let item = items
            .iter()
            .find(|item| item.get("id").and_then(Val::as_str) == Some(id))
            .unwrap_or_else(|| panic!("item {id}"));
        (
            item.get("status")
                .and_then(Val::as_str)
                .unwrap_or_default()
                .to_string(),
            item.get("reason").and_then(Val::as_str).map(str::to_string),
        )
    };
    assert_eq!(
        status_of("example-org/widgets#5"),
        ("admitted".to_string(), None)
    );
    assert_eq!(
        status_of("example-org/widgets#6"),
        ("refused".to_string(), Some("submission.grant".to_string()))
    );

    // CLI status readback agrees with the submit response, byte for byte.
    let (exit, stdout, stderr) = fixture.cli(&[
        "queue",
        "status",
        "--submission",
        &submission_id,
        "--socket",
        &socket_arg,
        "--config",
        &config_arg,
        "--json",
    ]);
    assert_eq!(exit, 0, "status exit; stderr: {stderr}");
    let status_envelope = envelope(&stdout);
    let readback = status_envelope.get("data").cloned().expect("data");
    assert_eq!(
        canter::canonical::canonical_text(&readback),
        canter::canonical::canonical_text(&submitted),
        "CLI/JSON and daemon readback must agree"
    );

    // Human mode renders the same admission facts.
    let (exit, stdout, stderr) = fixture.cli(&[
        "queue",
        "status",
        "--submission",
        &submission_id,
        "--socket",
        &socket_arg,
        "--config",
        &config_arg,
    ]);
    assert_eq!(exit, 0, "human status exit; stderr: {stderr}");
    assert!(stdout.contains("admitted 1"), "human rendering: {stdout}");
    assert!(stdout.contains("refused 1"), "human rendering: {stdout}");
    // #236: the human text carries the producer's own message for each item,
    // so the CLI text — not only `--json` — shows the fact a refusal names.
    let messages: Vec<String> = items
        .iter()
        .filter_map(|item| item.get("message").and_then(Val::as_str))
        .map(str::to_string)
        .collect();
    assert!(!messages.is_empty(), "the readback carries item messages");
    for message in &messages {
        assert!(
            stdout.contains(message),
            "the human rendering must carry {message:?}: {stdout}"
        );
    }

    // The daemon-side readback returns the same document again.
    let mut connection = Connection::open(&fixture.socket).expect("connect");
    connection
        .send_request(
            "abcdef01",
            "queue.status",
            Some(&object(vec![("submission_id", string(&submission_id))])),
        )
        .expect("send");
    let response = connection.read_response().expect("read");
    assert!(response.ok, "daemon readback is ok");
    assert_eq!(
        canter::canonical::canonical_text(&response.result),
        canter::canonical::canonical_text(&submitted)
    );

    shutdown(daemon);
    let state = fixture.seed();
    assert_eq!(state.list_instances().expect("instances").len(), 1);
    assert_eq!(state.queue_ownership_rows().expect("ownership").len(), 1);
}

#[test]
fn cli_stale_digest_epoch_and_unknown_submission_refuse_with_typed_exits() {
    let fixture = Fixture::new("refusals");
    let (bound_path, digest) = {
        let state = fixture.seed();
        state
            .issue_grant(&grant_doc("gr_0000000000000102", 5))
            .expect("grant");
        let request = request_with(&config_binding(&fixture.config_path), &[("#5", REV_A)]);
        let preview = qp::preview_queue(&state, &request).expect("preview");
        let bound = preview
            .doc
            .get("request")
            .cloned()
            .expect("bound-input document");
        let path = fixture.dir.join("request.json");
        std::fs::write(&path, canter::canonical::canonical_text(&bound)).expect("write request");
        (path, preview.digest)
    };
    let daemon = fixture.spawn();
    wait_ready(&fixture);
    let request_arg = bound_path.display().to_string();
    let config_arg = fixture.config_path.display().to_string();
    let socket_arg = fixture.socket.display().to_string();

    // A stale digest is refused locally (exit 4) before any daemon call.
    let (exit, stdout, stderr) = fixture.cli(&[
        "queue",
        "submit",
        "--request",
        &request_arg,
        "--confirm-digest",
        &"0".repeat(64),
        "--epoch",
        "1",
        "--caps",
        "4/2/2",
        "--grant",
        "example-org/widgets#5=gr_0000000000000102",
        "--socket",
        &socket_arg,
        "--config",
        &config_arg,
        "--json",
    ]);
    assert_eq!(exit, 4, "stale digest exit; stderr: {stderr}");
    let refused_envelope = envelope(&stdout);
    assert_eq!(
        refused_envelope
            .get("error")
            .and_then(|error| error.get("code"))
            .and_then(Val::as_str),
        Some("refusal.plan.stale")
    );

    // A pinned stale epoch is refused by the daemon (exit 4).
    let (exit, stdout, stderr) = fixture.cli(&[
        "queue",
        "submit",
        "--request",
        &request_arg,
        "--confirm-digest",
        &digest,
        "--epoch",
        "999",
        "--caps",
        "4/2/2",
        "--grant",
        "example-org/widgets#5=gr_0000000000000102",
        "--host-available",
        "yes",
        "--harness-lanes",
        "0",
        "--socket",
        &socket_arg,
        "--config",
        &config_arg,
        "--json",
    ]);
    assert_eq!(exit, 4, "stale epoch exit; stderr: {stderr}");
    let refused_envelope = envelope(&stdout);
    assert_eq!(
        refused_envelope
            .get("error")
            .and_then(|error| error.get("code"))
            .and_then(Val::as_str),
        Some("refusal.state.epoch")
    );
    // The two refusals left no claim and no durable submission behind.
    let mut connection = Connection::open(&fixture.socket).expect("connect");
    connection
        .send_request("abcdef02", "doctor", None)
        .expect("send");
    let doctor = connection.read_response().expect("read").result;
    assert_eq!(doctor.get("pending_claims").and_then(Val::as_int), Some(0));

    // An unknown submission read is a typed refusal (exit 4).
    let (exit, _stdout, stderr) = fixture.cli(&[
        "queue",
        "status",
        "--submission",
        "qs_0000000000000000",
        "--socket",
        &socket_arg,
        "--config",
        &config_arg,
        "--json",
    ]);
    assert_eq!(exit, 4, "unknown submission exit; stderr: {stderr}");

    // A malformed submission id is a usage error (exit 2) at parse time.
    let (exit, _stdout, stderr) = fixture.cli(&[
        "queue",
        "status",
        "--submission",
        "not-a-submission",
        "--socket",
        &socket_arg,
        "--config",
        &config_arg,
        "--json",
    ]);
    assert_eq!(exit, 2, "usage exit; stderr: {stderr}");
    assert!(
        stderr.contains("qs_"),
        "usage error names the shape: {stderr}"
    );

    shutdown(daemon);
    let state = fixture.seed();
    assert!(state.list_instances().expect("instances").is_empty());
    assert!(state.queue_ownership_rows().expect("ownership").is_empty());
}
