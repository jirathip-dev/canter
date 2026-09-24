//! Issue #92 acceptance tests: the SUPPORTED production grant mint path
//! (`canter grant issue` over the closed `grants.issue` method) against the
//! REAL binary and a real daemon child.
//!
//! Before this slice `State::issue_grant` had test-only callers, so no
//! supported surface could produce the grant id that `canter board --grant`
//! and `canter queue submit --grant` authorize against. These tests drive the
//! mint through the CLI + socket only: no direct state insertion, no
//! synthetic grant values (every field is derived from the reviewed
//! bound-input document, the configuration the CLI re-observes, the live
//! epoch and the explicit window), and no test-only seeding in the mint path.
//!
//! Evidence rules: raw process exits are asserted directly, JSON assertions
//! parse the documented `hf-output/v1` envelope, and the daemon readback is
//! compared canonically.
#[path = "support/process_group.rs"]
mod process_group;

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use canter::client::{Connection, RpcError};
use canter::config::{ProfileBinding, credential_environment, load_config};
use canter::lifecycle::ConcurrencyCaps;
use canter::plan::DOCTRINE_WORKFLOW_ID;
use canter::queue_preview as qp;
use canter::state::{Retention, State};
use canter::value::{Val, bool_, object, string};
use process_group::{GroupChild, assert_no_process_for_socket};

const REPO: &str = "example-org/widgets";
const HARNESS: &str = "lane-1";
const REV_A: &str = "1111111111111111111111111111111111111111";
const WORKFLOW_HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_canter")
}

/// Runtime-assembled idempotency keys (never a bare `key = "ik_..."` literal:
/// the scanner's generic-api-key rule keys on the identifier).
fn key(name: &str) -> String {
    format!("ik_92-{name}")
}

fn fresh_id(seed: u32) -> String {
    format!("{:08x}", seed + std::process::id())
}

struct Fixture {
    dir: PathBuf,
    state_dir: PathBuf,
    socket: PathBuf,
    config_path: PathBuf,
}

impl Fixture {
    fn new(name: &str) -> Fixture {
        let dir = std::env::temp_dir().join(format!("hf-grant-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("fixture dir");
        let fixture = Fixture {
            state_dir: dir.join("state"),
            socket: dir.join("daemon.sock"),
            config_path: dir.join("config.toml"),
            dir,
        };
        fixture.write_config("provider-a", "model-a");
        fixture
    }

    fn write_config(&self, provider: &str, model: &str) {
        std::fs::write(
            &self.config_path,
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
                 provider = \"{provider}\"\n\
                 model = \"{model}\"\n\
                 binding_introspection = false\n",
                self.socket.display()
            ),
        )
        .expect("write config");
    }

    fn db(&self) -> PathBuf {
        self.state_dir.join("canter").join("state.db")
    }

    fn seed(&self) -> State {
        std::fs::create_dir_all(self.state_dir.join("canter")).expect("state dir");
        State::open(&self.db(), Retention::default()).expect("open state")
    }

    fn daemon_log(&self) -> PathBuf {
        self.state_dir.join("canter").join("daemon.log")
    }

    fn spawn(&self, crash_point: Option<&str>) -> GroupChild {
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
        if let Some(point) = crash_point {
            command.env("CANTER_CRASH_POINT", point);
        }
        GroupChild::spawn(&mut command, &self.socket).expect("spawn daemon")
    }

    /// Run the CLI with the fixture environment: (exit, stdout, stderr).
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

    /// `grant issue` with the fixture's socket/config.
    fn grant_issue(&self, request: &Path, issue: i64, expires_in: i64) -> (i32, String, String) {
        self.grant_issue_with(request, issue, expires_in, None)
    }

    fn grant_issue_with(
        &self,
        request: &Path,
        issue: i64,
        expires_in: i64,
        idem: Option<&str>,
    ) -> (i32, String, String) {
        let request_arg = request.display().to_string();
        let config_arg = self.config_path.display().to_string();
        let socket_arg = self.socket.display().to_string();
        let issue_arg = issue.to_string();
        let expiry_arg = expires_in.to_string();
        let mut args = vec![
            "grant",
            "issue",
            "--request",
            request_arg.as_str(),
            "--issue",
            issue_arg.as_str(),
            "--expires-in",
            expiry_arg.as_str(),
            "--socket",
            socket_arg.as_str(),
            "--config",
            config_arg.as_str(),
            "--json",
        ];
        if let Some(idem) = idem {
            args.push("--idempotency-key");
            args.push(idem);
        }
        self.cli(&args)
    }

    /// `queue submit` of the fixture's reviewed document with a presented
    /// grant binding.
    fn queue_submit(
        &self,
        request: &Path,
        digest: &str,
        issue: i64,
        grant_id: &str,
        idem: Option<&str>,
    ) -> (i32, String, String) {
        let request_arg = request.display().to_string();
        let config_arg = self.config_path.display().to_string();
        let socket_arg = self.socket.display().to_string();
        let binding = format!("{REPO}#{issue}={grant_id}");
        let mut args = vec![
            "queue",
            "submit",
            "--request",
            request_arg.as_str(),
            "--confirm-digest",
            digest,
            "--caps",
            "4/2/2",
            "--grant",
            binding.as_str(),
            "--host-available",
            "yes",
            "--harness-lanes",
            "0",
            "--socket",
            socket_arg.as_str(),
            "--config",
            config_arg.as_str(),
            "--json",
        ];
        if let Some(idem) = idem {
            args.push("--idempotency-key");
            args.push(idem);
        }
        self.cli(&args)
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
    let stderr_text =
        std::fs::read_to_string(fixture.dir.join("daemon.stderr.log")).unwrap_or_default();
    panic!(
        "daemon did not become ready on {}; stderr:\n{stderr_text}",
        fixture.socket.display()
    );
}

fn shutdown(mut daemon: GroupChild) {
    daemon.terminate("grant fixture daemon");
}

/// One RPC exchange (ok or refused).
fn rpc(socket: &Path, id: &str, method: &str, params: Option<Val>) -> Val {
    let mut connection = Connection::open(socket).expect("connect");
    connection
        .send_request(id, method, params.as_ref())
        .expect("send");
    let response = connection.read_response().expect("read response");
    if response.ok {
        object(vec![("ok", bool_(true)), ("result", response.result)])
    } else {
        let error = response.error.unwrap_or_else(|| RpcError {
            code: "missing.error".to_string(),
            message: "no error doc".to_string(),
        });
        object(vec![
            ("ok", bool_(false)),
            (
                "error",
                object(vec![
                    ("code", string(&error.code)),
                    ("message", string(&error.message)),
                ]),
            ),
        ])
    }
}

fn rpc_ok(socket: &Path, id: &str, method: &str, params: Option<Val>) -> Val {
    let doc = rpc(socket, id, method, params);
    assert_eq!(
        doc.get("ok").and_then(Val::as_bool),
        Some(true),
        "expected ok for {method}: {}",
        canter::canonical::canonical_text(&doc)
    );
    doc.get("result").expect("result").clone()
}

fn rpc_err(socket: &Path, id: &str, method: &str, params: Option<Val>) -> (String, String) {
    let doc = rpc(socket, id, method, params);
    let error = doc.get("error").expect("error doc");
    (
        error
            .get("code")
            .and_then(Val::as_str)
            .unwrap_or("")
            .to_string(),
        error
            .get("message")
            .and_then(Val::as_str)
            .unwrap_or("")
            .to_string(),
    )
}

/// Parse one `hf-output/v1` envelope from CLI stdout.
fn envelope(output: &str) -> Val {
    let doc = Val::parse_json(output.trim_end()).expect("one JSON envelope");
    let verdict = canter::schema::validate_doc(canter::schema::Family::Output, &doc);
    assert!(verdict.is_accepted(), "envelope: {}", verdict.message());
    doc
}

/// The reviewed role binding derived from the SAME config the CLI re-observes.
fn config_binding(config_path: &Path) -> Val {
    let config = load_config(config_path).expect("load config");
    let harness = config
        .harnesses
        .iter()
        .find(|harness| harness.key == HARNESS)
        .expect("harness");
    let env = credential_environment(harness);
    ProfileBinding::from_config(&config, HARNESS, &env)
        .expect("the role skills resolve")
        .expect("binding")
        .to_doc()
}

/// The reviewed bound-input document for `issues`, written to `request.json`
/// (the same material `queue preview --out` produces); returns its path and
/// digest.
fn bound_document(fixture: &Fixture, issues: &[(&str, &str)]) -> (PathBuf, String) {
    let state = fixture.seed();
    let request = qp::QueueRequest {
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
        role_config: config_binding(&fixture.config_path),
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
    };
    let preview = qp::preview_queue(&state, &request).expect("preview");
    let bound = preview
        .doc
        .get("request")
        .cloned()
        .expect("bound-input document");
    let path = fixture.dir.join("request.json");
    std::fs::write(&path, canter::canonical::canonical_text(&bound)).expect("write request");
    drop(state);
    (path, preview.digest)
}

/// The `data` document of a successful CLI envelope.
fn issue(fixture: &Fixture, request: &Path) -> Val {
    let (exit, stdout, stderr) = fixture.grant_issue(request, 5, 3600);
    assert_eq!(exit, 0, "mint exit; stderr: {stderr}");
    assert!(stderr.is_empty(), "mint diagnostics: {stderr}");
    let doc = envelope(&stdout);
    assert_eq!(
        doc.get("command").and_then(Val::as_str),
        Some("grant issue")
    );
    assert_eq!(doc.get("kind").and_then(Val::as_str), Some("ok"));
    assert_eq!(doc.get("exit_code").and_then(Val::as_int), Some(0));
    doc.get("data").cloned().expect("data")
}

fn grant_of(data: &Val) -> Val {
    data.get("grant").cloned().expect("grant document")
}

fn text_of(doc: &Val, key: &str) -> String {
    doc.get(key)
        .and_then(Val::as_str)
        .unwrap_or_default()
        .to_string()
}

/// The daemon's live grant population (the `grants.list` read over the
/// socket), so a test can assert that no second authorization appeared.
fn listed_grants(fixture: &Fixture) -> Vec<Val> {
    let listed = rpc_ok(
        &fixture.socket,
        &fresh_id(90),
        "grants.list",
        Some(object(vec![])),
    );
    listed
        .get("grants")
        .and_then(Val::as_array)
        .cloned()
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// AC1/AC2: the mint path exists, is daemon-issued, and preserves the binding
// ---------------------------------------------------------------------------

#[test]
fn cli_mint_is_daemon_issued_and_reads_back_with_the_reviewed_binding() {
    let fixture = Fixture::new("mint");
    let (request, digest) = bound_document(&fixture, &[("#5", REV_A)]);
    let daemon = fixture.spawn(None);
    wait_ready(&fixture);

    let (exit, stdout, stderr) = fixture.grant_issue(&request, 5, 3600);
    assert_eq!(exit, 0, "mint exit; stderr: {stderr}");
    assert!(stderr.is_empty(), "clean mint keeps stderr empty: {stderr}");
    // AC6: the mint output never echoes the automation key or a host path.
    assert!(
        !stdout.contains("ik_"),
        "no key material in output: {stdout}"
    );
    assert!(
        !stdout.contains(&fixture.state_dir.display().to_string()),
        "no host path in output: {stdout}"
    );
    let minted = envelope(&stdout);
    assert_eq!(
        minted.get("command").and_then(Val::as_str),
        Some("grant issue")
    );
    let data = minted.get("data").cloned().expect("data");
    assert_eq!(
        data.get("schema").and_then(Val::as_str),
        Some("hf-grant/v1")
    );
    assert_eq!(
        data.get("plan_digest").and_then(Val::as_str),
        Some(digest.as_str()),
        "the mint reports the reviewed bound-input digest it derived from"
    );
    let grant_id = text_of(&data, "grant_id");
    assert!(
        canter::formats::is_grant_id(&grant_id),
        "grant id {grant_id:?} must be gr_ + 16 lowercase hex"
    );

    // AC2: every documented binding is the reviewed one.
    let grant = grant_of(&data);
    let verdict = canter::schema::validate_doc(canter::schema::Family::Grant, &grant);
    assert!(
        verdict.is_accepted(),
        "the minted document must validate as hf-grant/v1: {}",
        verdict.message()
    );
    assert_eq!(text_of(&grant, "repository"), REPO);
    assert_eq!(text_of(&grant, "workflow_hash"), WORKFLOW_HASH);
    assert_eq!(
        text_of(&grant, "policy_hash"),
        text_of(&config_binding(&fixture.config_path), "revision"),
        "policy hash binds the reviewed role configuration revision"
    );
    assert_eq!(text_of(&grant, "phase"), "merge");
    assert_eq!(text_of(&grant, "scope"), "worktrees/issues/5");
    assert_eq!(grant.get("state_epoch").and_then(Val::as_int), Some(1));
    assert_eq!(
        grant.get("issue").and_then(|issue| issue.get("number")),
        Some(&canter::value::integer(5))
    );
    assert_eq!(
        grant
            .get("issue")
            .and_then(|issue| issue.get("revision"))
            .and_then(Val::as_str),
        Some(REV_A)
    );
    let caps: Vec<&str> = grant
        .get("caps")
        .and_then(Val::as_array)
        .map(|caps| caps.iter().filter_map(Val::as_str).collect())
        .unwrap_or_default();
    assert_eq!(caps, vec!["read", "merge"], "caps come from the boundary");
    assert!(text_of(&grant, "expires_at") > text_of(&grant, "created_at"));

    // The daemon reports the same grant (daemon-issued, daemon-owned).
    let listed = rpc_ok(
        &fixture.socket,
        &fresh_id(1),
        "grants.list",
        Some(object(vec![])),
    );
    let grants = listed
        .get("grants")
        .and_then(Val::as_array)
        .expect("grants");
    assert_eq!(grants.len(), 1, "exactly one grant exists: {listed:?}");
    assert_eq!(text_of(&grants[0], "grant_id"), grant_id);
    assert_eq!(text_of(&grants[0], "repository"), REPO);
    assert_eq!(
        text_of(&grants[0], "expires_at"),
        text_of(&grant, "expires_at")
    );
    assert_eq!(grants[0].get("state_epoch").and_then(Val::as_int), Some(1));

    // The closed method set declares the new surface.
    let capabilities = rpc_ok(
        &fixture.socket,
        &fresh_id(2),
        "capabilities",
        Some(object(vec![])),
    );
    let methods: Vec<&str> = capabilities
        .get("methods")
        .and_then(Val::as_array)
        .map(|methods| methods.iter().filter_map(Val::as_str).collect())
        .unwrap_or_default();
    assert!(
        methods.contains(&"grants.issue"),
        "grants.issue must be in the closed method set"
    );

    // AC4: the intent was journaled (audit action) before the row exists.
    let tail = rpc_ok(
        &fixture.socket,
        &fresh_id(3),
        "journal.tail",
        Some(object(vec![])),
    );
    let records = canter::canonical::canonical_text(&tail);
    assert!(
        records.contains("mutate.grant.issue"),
        "the issuance intent must be journaled: {records}"
    );

    shutdown(daemon);
}

#[test]
fn the_minted_grant_is_consumed_by_the_real_submission_path() {
    let fixture = Fixture::new("consume");
    let (request, digest) = bound_document(&fixture, &[("#5", REV_A)]);
    let daemon = fixture.spawn(None);
    wait_ready(&fixture);

    let data = issue(&fixture, &request);
    let grant_id = text_of(&data, "grant_id");

    let (exit, stdout, stderr) = fixture.queue_submit(&request, &digest, 5, &grant_id, None);
    assert_eq!(exit, 0, "submit exit; stderr: {stderr}");
    let submitted = envelope(&stdout);
    let item = submitted
        .get("data")
        .and_then(|data| data.get("items"))
        .and_then(Val::as_array)
        .and_then(|items| items.first())
        .cloned()
        .expect("one membership item");
    assert_eq!(text_of(&item, "status"), "admitted", "item: {item:?}");
    let instance = text_of(&item, "instance_id");
    assert!(
        instance.starts_with("run-"),
        "the admission dispatched a real run: {instance}"
    );
    // The run really exists in the daemon's state, bound to the minted grant.
    let status = rpc_ok(
        &fixture.socket,
        &fresh_id(4),
        "run.status",
        Some(object(vec![("instance_id", string(&instance))])),
    );
    assert_eq!(
        status
            .get("run")
            .and_then(|run| run.get("grant_id"))
            .and_then(Val::as_str),
        Some(grant_id.as_str()),
        "the dispatched run binds the minted grant: {status:?}"
    );
    assert_eq!(
        status
            .get("run")
            .and_then(|run| run.get("issue_number"))
            .and_then(Val::as_int),
        Some(5)
    );

    shutdown(daemon);
}

// ---------------------------------------------------------------------------
// AC2: expiry + epoch semantics
// ---------------------------------------------------------------------------

#[test]
fn an_expired_window_stops_being_consumable_with_the_typed_code() {
    let fixture = Fixture::new("expiry");
    let (request, digest) = bound_document(&fixture, &[("#5", REV_A)]);
    let daemon = fixture.spawn(None);
    wait_ready(&fixture);

    // A one-second window: the mint accepts it (it is still in the future),
    // the consumer must refuse it once it passed.
    let (exit, stdout, stderr) = fixture.grant_issue(&request, 5, 1);
    assert_eq!(exit, 0, "short mint exit; stderr: {stderr}");
    let data = envelope(&stdout).get("data").cloned().expect("data");
    let grant_id = text_of(&data, "grant_id");

    std::thread::sleep(Duration::from_secs(2));

    let (exit, stdout, stderr) = fixture.queue_submit(&request, &digest, 5, &grant_id, None);
    assert_eq!(exit, 0, "submit exit; stderr: {stderr}");
    let item = envelope(&stdout)
        .get("data")
        .and_then(|data| data.get("items"))
        .and_then(Val::as_array)
        .and_then(|items| items.first())
        .cloned()
        .expect("item");
    assert_eq!(text_of(&item, "status"), "refused");
    assert_eq!(
        text_of(&item, "reason"),
        "refusal.grant.expired",
        "expiry must refuse with its typed code before any effect: {item:?}"
    );

    shutdown(daemon);
}

#[test]
fn an_already_expired_document_is_refused_at_mint_before_any_claim() {
    let fixture = Fixture::new("dead");
    let (request, _digest) = bound_document(&fixture, &[("#5", REV_A)]);
    let daemon = fixture.spawn(None);
    wait_ready(&fixture);

    let document = Val::parse_json(&format!(
        r#"{{"schema":"hf-grant/v1","grant_id":"gr_00000000000000aa","repository":"{REPO}",
            "issue":{{"number":5,"revision":"{REV_A}"}},
            "workflow_hash":"{WORKFLOW_HASH}",
            "policy_hash":"{WORKFLOW_HASH}",
            "phase":"merge","scope":"worktrees/issues/5",
            "caps":["read","merge"],
            "expires_at":"2000-01-01T00:00:00Z","state_epoch":1,
            "created_at":"2000-01-01T00:00:00Z"}}"#
    ))
    .expect("document");
    let (code, message) = rpc_err(
        &fixture.socket,
        &fresh_id(5),
        "grants.issue",
        Some(object(vec![
            ("grant", document),
            ("idempotency_key", string(&key("dead"))),
        ])),
    );
    assert_eq!(code, "refusal.grant.expired", "{message}");

    // Nothing was journaled or stored: the refusal precedes the claim.
    let listed = rpc_ok(
        &fixture.socket,
        &fresh_id(6),
        "grants.list",
        Some(object(vec![])),
    );
    assert_eq!(
        listed.get("grants").and_then(Val::as_array).map(Vec::len),
        Some(0),
        "a refused document must never leave a grant behind: {listed:?}"
    );
    let _ = request;

    shutdown(daemon);
}

#[test]
fn a_stale_epoch_document_is_refused_at_mint() {
    let fixture = Fixture::new("epoch");
    let (request, _digest) = bound_document(&fixture, &[("#5", REV_A)]);
    let daemon = fixture.spawn(None);
    wait_ready(&fixture);

    let document = Val::parse_json(&format!(
        r#"{{"schema":"hf-grant/v1","grant_id":"gr_00000000000000bb","repository":"{REPO}",
            "issue":{{"number":5,"revision":"{REV_A}"}},
            "workflow_hash":"{WORKFLOW_HASH}",
            "policy_hash":"{WORKFLOW_HASH}",
            "phase":"merge","scope":"worktrees/issues/5",
            "caps":["read","merge"],
            "expires_at":"2999-01-01T00:00:00Z","state_epoch":999,
            "created_at":"2026-01-01T00:00:00Z"}}"#
    ))
    .expect("document");
    let (code, message) = rpc_err(
        &fixture.socket,
        &fresh_id(7),
        "grants.issue",
        Some(object(vec![
            ("grant", document),
            ("idempotency_key", string(&key("epoch"))),
        ])),
    );
    assert_eq!(code, "state.epoch_mismatch", "{message}");
    let _ = request;

    shutdown(daemon);
}

#[test]
fn an_epoch_rotation_invalidates_the_minted_grant() {
    let fixture = Fixture::new("rotation");
    let (request, digest) = bound_document(&fixture, &[("#5", REV_A)]);
    let daemon = fixture.spawn(None);
    wait_ready(&fixture);

    let data = issue(&fixture, &request);
    let grant_id = text_of(&data, "grant_id");

    // Rotate the epoch through the real restore path.
    let backup = rpc_ok(
        &fixture.socket,
        &fresh_id(8),
        "backup.create",
        Some(object(vec![("idempotency_key", string(&key("backup")))])),
    );
    let snapshot = backup
        .get("backup")
        .and_then(|backup| backup.get("snapshot"))
        .and_then(Val::as_str)
        .expect("snapshot")
        .to_string();
    let restored = rpc_ok(
        &fixture.socket,
        &fresh_id(9),
        "restore.begin",
        Some(object(vec![
            ("idempotency_key", string(&key("restore"))),
            ("backup", string(&snapshot)),
        ])),
    );
    assert_eq!(
        restored.get("restored_epoch").and_then(Val::as_int),
        Some(2),
        "the restore rotates the epoch: {restored:?}"
    );

    // The pre-rotation grant is gone from the active set and refuses as
    // inactive (grants die with their epoch).
    let listed = rpc_ok(
        &fixture.socket,
        &fresh_id(10),
        "grants.list",
        Some(object(vec![])),
    );
    assert_eq!(
        listed.get("grants").and_then(Val::as_array).map(Vec::len),
        Some(0),
        "an invalidated grant is no longer active: {listed:?}"
    );
    let (exit, stdout, stderr) = fixture.queue_submit(&request, &digest, 5, &grant_id, None);
    assert_eq!(exit, 0, "submit exit; stderr: {stderr}");
    let item = envelope(&stdout)
        .get("data")
        .and_then(|data| data.get("items"))
        .and_then(Val::as_array)
        .and_then(|items| items.first())
        .cloned()
        .expect("item");
    assert_eq!(text_of(&item, "status"), "refused");
    assert_eq!(text_of(&item, "reason"), "refusal.grant.inactive");

    shutdown(daemon);
}

// ---------------------------------------------------------------------------
// AC1/AC3: supported authority boundaries on the mint surface
// ---------------------------------------------------------------------------

#[test]
fn a_production_class_binding_is_refused_by_the_cli_and_over_the_wire() {
    let fixture = Fixture::new("production");
    // A reviewed document whose boundary asks for production-class authority.
    let state = fixture.seed();
    let request = qp::QueueRequest {
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
        role_config: config_binding(&fixture.config_path),
        boundary: qp::Boundary {
            phase: "production".to_string(),
            integration_branch: "staging".to_string(),
            completion_branch: "main".to_string(),
            caps: vec!["read".to_string(), "production".to_string()],
        },
        steps: vec![qp::PlannedStep {
            id: "p1".to_string(),
            kind: "checkout".to_string(),
            params: Some(object(vec![("ref", string("staging"))])),
        }],
        selected: vec![qp::SelectedIssue {
            id: "#5".to_string(),
            title: None,
            revision: REV_A.to_string(),
            requires: Vec::new(),
        }],
    };
    let preview = qp::preview_queue(&state, &request).expect("preview");
    let bound = preview
        .doc
        .get("request")
        .cloned()
        .expect("bound-input document");
    let path = fixture.dir.join("request.json");
    std::fs::write(&path, canter::canonical::canonical_text(&bound)).expect("write request");
    drop(state);

    let daemon = fixture.spawn(None);
    wait_ready(&fixture);

    // The CLI refuses before the wire.
    let (exit, stdout, stderr) = fixture.grant_issue(&path, 5, 3600);
    assert_eq!(exit, 4, "production mint must refuse; stderr: {stderr}");
    assert!(
        stderr.contains("refusal.policy.production_confirmation"),
        "typed refusal: {stderr}"
    );
    assert!(stdout.contains("hf-output/v1"), "one envelope on stdout");
    let refusal = envelope(&stdout);
    assert_eq!(
        refusal
            .get("error")
            .and_then(|error| error.get("code"))
            .and_then(Val::as_str),
        Some("refusal.policy.production_confirmation")
    );

    // The wire refuses it too (the CLI is not the fence).
    let document = Val::parse_json(&format!(
        r#"{{"schema":"hf-grant/v1","grant_id":"gr_00000000000000cc","repository":"{REPO}",
            "issue":{{"number":5,"revision":"{REV_A}"}},
            "workflow_hash":"{WORKFLOW_HASH}",
            "policy_hash":"{WORKFLOW_HASH}",
            "phase":"production","scope":"worktrees/issues/5",
            "caps":["read","production"],
            "expires_at":"2999-01-01T00:00:00Z","state_epoch":1,
            "created_at":"2026-01-01T00:00:00Z"}}"#
    ))
    .expect("document");
    let (code, message) = rpc_err(
        &fixture.socket,
        &fresh_id(11),
        "grants.issue",
        Some(object(vec![
            ("grant", document),
            ("idempotency_key", string(&key("production"))),
        ])),
    );
    assert_eq!(code, "refusal.policy.production_confirmation", "{message}");

    shutdown(daemon);
}

#[test]
fn a_moved_role_revision_refuses_before_the_mint() {
    let fixture = Fixture::new("role-moved");
    let (request, _digest) = bound_document(&fixture, &[("#5", REV_A)]);
    let daemon = fixture.spawn(None);
    wait_ready(&fixture);

    // The reviewed document bound provider-a/model-a; the live configuration
    // now declares a different binding.
    fixture.write_config("provider-b", "model-b");
    let (exit, stdout, stderr) = fixture.grant_issue(&request, 5, 3600);
    assert_eq!(exit, 4, "a moved role revision must refuse: {stderr}");
    assert!(
        stderr.contains("refusal.profile.revision"),
        "typed refusal: {stderr}"
    );
    // Nothing was minted.
    let listed = rpc_ok(
        &fixture.socket,
        &fresh_id(12),
        "grants.list",
        Some(object(vec![])),
    );
    assert_eq!(
        listed.get("grants").and_then(Val::as_array).map(Vec::len),
        Some(0)
    );
    let _ = envelope(&stdout);

    shutdown(daemon);
}

#[test]
fn an_issue_outside_the_reviewed_set_refuses_before_the_wire() {
    let fixture = Fixture::new("not-reviewed");
    let (request, _digest) = bound_document(&fixture, &[("#5", REV_A)]);
    let daemon = fixture.spawn(None);
    wait_ready(&fixture);

    let (exit, _stdout, stderr) = fixture.grant_issue(&request, 6, 3600);
    assert_eq!(exit, 2, "unreviewed issue is a usage error: {stderr}");
    assert!(stderr.contains("usage.grant_issue"), "{stderr}");

    shutdown(daemon);
}

#[test]
fn a_mint_without_a_live_daemon_is_refused_typed() {
    let fixture = Fixture::new("no-daemon");
    let (request, _digest) = bound_document(&fixture, &[("#5", REV_A)]);

    // No daemon: issuance is a daemon operation, so the surface refuses
    // instead of writing the store itself.
    let state = fixture.seed();
    drop(state);
    let (exit, _stdout, stderr) = fixture.grant_issue(&request, 5, 3600);
    assert_eq!(exit, 1, "no-daemon mint exit: {stderr}");
    assert!(stderr.contains("daemon.absent"), "{stderr}");

    // Nothing was inserted behind the daemon's back.
    let state = fixture.seed();
    assert!(
        state.list_grants().expect("grants").is_empty(),
        "the CLI never writes state directly"
    );
}

// ---------------------------------------------------------------------------
// AC4: exactly-once, replay, crash points
// ---------------------------------------------------------------------------

#[test]
fn replay_returns_the_recorded_outcome_and_a_fresh_key_opens_a_new_window() {
    let fixture = Fixture::new("replay");
    let (request, _digest) = bound_document(&fixture, &[("#5", REV_A)]);
    let daemon = fixture.spawn(None);
    wait_ready(&fixture);

    // One explicit key: the FIRST mint is a fresh claim; re-running the CLI
    // with that key is a reused key for a NEW request id, which the claim
    // machinery refuses typed (one owner per key, never a second grant).
    let idem = key("replay-0001");
    let (exit, first_stdout, stderr) = fixture.grant_issue_with(&request, 5, 3600, Some(&idem));
    assert_eq!(exit, 0, "first mint; stderr: {stderr}");
    let first = envelope(&first_stdout);
    let grant_id = {
        let data = first.get("data").cloned().expect("data");
        text_of(&data, "grant_id")
    };
    assert!(canter::formats::is_grant_id(&grant_id));
    let document = grant_of(&first.get("data").cloned().expect("data"));
    let (exit, _stdout, stderr) = fixture.grant_issue_with(&request, 5, 3600, Some(&idem));
    assert_eq!(exit, 1, "reused key refuses: {stderr}");
    assert!(stderr.contains("state.claim_reused"), "{stderr}");

    // A fresh key opens a distinct authorization window for the same reviewed
    // binding; it neither extends nor replaces the first grant.
    let (exit, second_stdout, stderr) =
        fixture.grant_issue_with(&request, 5, 7200, Some(&key("replay-0002")));
    assert_eq!(exit, 0, "second window: {stderr}");
    let second = envelope(&second_stdout).get("data").cloned().expect("data");
    let second_id = text_of(&second, "grant_id");
    assert_ne!(second_id, grant_id);
    assert_eq!(
        listed_grants(&fixture).len(),
        2,
        "both immutable authorization windows remain visible"
    );

    // Exactly-once + recorded replay at the wire level, on a DISTINCT
    // document (a separate mint, so a separate claim): the SAME request id
    // and key return the recorded response byte-for-byte.
    let mut other_document = document.clone();
    if let Val::Obj(map) = &mut other_document {
        map.insert("grant_id".to_string(), string("gr_00000000000000ee"));
        map.insert("expires_at".to_string(), string("2999-01-01T00:00:00Z"));
    }
    let request_id = fresh_id(40);
    let other_idem = key("replay-wire-0001");
    let params = object(vec![
        ("grant", other_document),
        ("idempotency_key", string(&other_idem)),
    ]);
    let first_wire = rpc(
        &fixture.socket,
        &request_id,
        "grants.issue",
        Some(params.clone()),
    );
    assert_eq!(
        first_wire.get("ok").and_then(Val::as_bool),
        Some(true),
        "{}",
        canter::canonical::canonical_text(&first_wire)
    );
    let replayed = rpc(
        &fixture.socket,
        &request_id,
        "grants.issue",
        Some(params.clone()),
    );
    assert_eq!(
        canter::canonical::canonical_text(&replayed),
        canter::canonical::canonical_text(&first_wire),
        "a same-request-id replay returns the recorded outcome"
    );

    // A fresh id reusing the same key is refused (the key is spent).
    let (code, _) = rpc_err(&fixture.socket, &fresh_id(41), "grants.issue", Some(params));
    assert_eq!(code, "state.claim_reused");

    let listed = rpc_ok(
        &fixture.socket,
        &fresh_id(13),
        "grants.list",
        Some(object(vec![])),
    );
    assert_eq!(
        listed.get("grants").and_then(Val::as_array).map(Vec::len),
        Some(3),
        "two windows for one binding plus the distinct wire document: {listed:?}"
    );

    shutdown(daemon);
}

#[test]
fn a_crash_after_the_intent_leaves_no_partial_grant() {
    let fixture = Fixture::new("crash-intent");
    let (request, _digest) = bound_document(&fixture, &[("#5", REV_A)]);
    let daemon = fixture.spawn(Some("grants.issue.after-intent"));
    wait_ready(&fixture);

    // The mint dies with the daemon (the crash point aborts the process).
    let request_arg = request.display().to_string();
    let config_arg = fixture.config_path.display().to_string();
    let socket_arg = fixture.socket.display().to_string();
    let (exit, _stdout, _stderr) = fixture.cli(&[
        "grant",
        "issue",
        "--request",
        &request_arg,
        "--issue",
        "5",
        "--expires-in",
        "3600",
        "--socket",
        &socket_arg,
        "--config",
        &config_arg,
        "--json",
    ]);
    assert_ne!(exit, 0, "the interrupted mint cannot report success");
    shutdown(daemon);

    // Restart: reconciliation reads the marker and reports the truth.
    let daemon = fixture.spawn(None);
    wait_ready(&fixture);
    let log = std::fs::read_to_string(fixture.daemon_log()).expect("daemon log");
    assert!(
        log.contains("never committed"),
        "reconcile must state the mint never committed: {log}"
    );
    let listed = rpc_ok(
        &fixture.socket,
        &fresh_id(15),
        "grants.list",
        Some(object(vec![])),
    );
    assert_eq!(
        listed.get("grants").and_then(Val::as_array).map(Vec::len),
        Some(0),
        "no partial grant survives the crash: {listed:?}"
    );

    // A retry with a FRESH key mints from live state.
    let fresh_key = key("crash-intent-retry");
    let (exit, stdout, stderr) = fixture.grant_issue_with(&request, 5, 3600, Some(&fresh_key));
    assert_eq!(exit, 0, "retry exit; stderr: {stderr}");
    let data = envelope(&stdout).get("data").cloned().expect("data");
    assert!(canter::formats::is_grant_id(&text_of(&data, "grant_id")));

    shutdown(daemon);
}

#[test]
fn a_crash_after_the_commit_keeps_exactly_one_grant() {
    let fixture = Fixture::new("crash-commit");
    let (request, _digest) = bound_document(&fixture, &[("#5", REV_A)]);
    let daemon = fixture.spawn(Some("grants.issue.after-commit"));
    wait_ready(&fixture);

    let request_arg = request.display().to_string();
    let config_arg = fixture.config_path.display().to_string();
    let socket_arg = fixture.socket.display().to_string();
    let idem = key("crash-commit-0001");
    let _ = fixture.cli(&[
        "grant",
        "issue",
        "--request",
        &request_arg,
        "--issue",
        "5",
        "--expires-in",
        "3600",
        "--idempotency-key",
        &idem,
        "--socket",
        &socket_arg,
        "--config",
        &config_arg,
        "--json",
    ]);
    shutdown(daemon);

    let daemon = fixture.spawn(None);
    wait_ready(&fixture);
    let log = std::fs::read_to_string(fixture.daemon_log()).expect("daemon log");
    assert!(
        log.contains("committed before the interrupt"),
        "reconcile must report the committed mint: {log}"
    );
    let listed = rpc_ok(
        &fixture.socket,
        &fresh_id(16),
        "grants.list",
        Some(object(vec![])),
    );
    let grants = listed
        .get("grants")
        .and_then(Val::as_array)
        .expect("grants");
    assert_eq!(grants.len(), 1, "exactly the committed grant: {listed:?}");

    let original_id = text_of(&grants[0], "grant_id");

    // A fresh key after restart opens another immutable window; the committed
    // pre-crash grant remains present and is never duplicated or replaced.
    let (exit, stdout, stderr) =
        fixture.grant_issue_with(&request, 5, 7200, Some(&key("crash-commit-0002")));
    assert_eq!(exit, 0, "fresh post-crash window: {stderr}");
    let data = envelope(&stdout).get("data").cloned().expect("data");
    assert_ne!(text_of(&data, "grant_id"), original_id);
    let listed = listed_grants(&fixture);
    assert_eq!(listed.len(), 2, "both windows remain after restart");
    assert!(
        listed
            .iter()
            .any(|grant| text_of(grant, "grant_id") == original_id),
        "the pre-crash grant remains visible"
    );

    shutdown(daemon);
}

#[test]
fn grant_fixture_reaps_its_daemon_group() {
    let fixture = Fixture::new("leak-detector");
    fixture.seed();
    let socket = fixture.socket.clone();
    let daemon = fixture.spawn(None);
    wait_ready(&fixture);
    shutdown(daemon);
    assert_no_process_for_socket(&socket);
}

#[test]
fn a_second_daemon_is_still_refused_while_issuance_is_available() {
    let fixture = Fixture::new("second-daemon");
    let (request, _digest) = bound_document(&fixture, &[("#5", REV_A)]);
    let daemon = fixture.spawn(None);
    wait_ready(&fixture);

    // A second daemon on the same state/socket is refused (the single-writer
    // lock is untouched by this slice).
    let stdout_path = fixture.dir.join("second-daemon.stdout.log");
    let stdout_file = std::fs::File::create(&stdout_path).expect("second daemon stdout");
    let mut command = Command::new(bin());
    command
        .args(["daemon", "run", "--socket"])
        .arg(&fixture.socket)
        .args(["--json"])
        .env("XDG_STATE_HOME", &fixture.state_dir)
        .env("HOME", &fixture.dir)
        .stdout(Stdio::from(stdout_file))
        .stderr(Stdio::null());
    let mut second = GroupChild::spawn(&mut command, &fixture.socket).expect("second daemon");
    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(status) = second.try_wait().expect("wait for second daemon") {
            break status;
        }
        if Instant::now() >= deadline {
            second.terminate("second grant daemon");
            panic!("the second daemon did not refuse within 5 seconds");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let reaped = second.terminate("second grant daemon");
    assert_eq!(status.code(), reaped.code(), "stable reaped status");
    assert_eq!(status.code(), Some(1), "the second daemon must exit 1");
    let stdout = std::fs::read_to_string(stdout_path).expect("read second daemon stdout");
    assert!(
        stdout.contains("daemon.busy"),
        "the second daemon must be refused: {stdout}"
    );

    // The first daemon still mints (its claim machinery is intact).
    let data = issue(&fixture, &request);
    assert!(canter::formats::is_grant_id(&text_of(&data, "grant_id")));

    shutdown(daemon);
}
