//! Issue #91 wiring acceptance tests: the reachable product command path.
//!
//! The operator authority path is only delivered when a real user command
//! reaches it: `canter queue preview` produces the reviewed bound-input
//! document (the plan producer), and `canter board --plan FILE` runs the
//! operator console over it — selection, exact preview, explicit
//! authorization and a daemon-owned run.
//!
//! Every test here drives the REAL compiled binary
//! (`CARGO_BIN_EXE_canter`), never a library stand-in: the plan producer and
//! its typed refusals run as child processes, and the board runs under a
//! real pseudo-terminal against a real `canter daemon run` child. The
//! library is used only to seed the fixture state store (one active grant,
//! one recorded run) and to cross-check the emitted document through the
//! production consumer path (`queue_executor::presented_request` +
//! `revalidate`), never to stand in for the command.
//!
//! Fixture discipline: synthetic identities only (`example-org/widgets`,
//! `host-1`, `lane-1`, `run-seeded-0001`), all state under a per-test temp
//! directory. The submission is admission only: no workflow step executes
//! and no harness process is spawned.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use canter::client::Connection;
use canter::config::{ProfileBinding, credential_environment, load_config};
use canter::lifecycle::ConcurrencyCaps;
use canter::plan::DOCTRINE_WORKFLOW_ID;
use canter::queue_executor as qx;
use canter::state::{Retention, State};
use canter::value::Val;

const REPO: &str = "example-org/widgets";
const HARNESS: &str = "lane-1";
const REVISION: &str = "1111111111111111111111111111111111111111";
const WORKFLOW_HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const POLICY_HASH: &str = "feedface01234567feedface01234567feedface01234567feedface01234567";
const SEEDED_RUN: &str = "run-seeded-0001";

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_canter")
}

// ---------------------------------------------------------------------------
// Fixture (the `tests/queue_cli.rs` / `tests/tui_operator.rs` shape)
// ---------------------------------------------------------------------------

struct Fixture {
    dir: PathBuf,
    state_dir: PathBuf,
    socket: PathBuf,
    config_path: PathBuf,
}

impl Fixture {
    fn new(name: &str) -> Fixture {
        let dir = std::env::temp_dir().join(format!("hf-commands-{name}-{}", std::process::id()));
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
                 branch = \"staging\"\n\
                 \n\
                 [harness.{HARNESS}]\n\
                 kind = \"pi\"\n\
                 executable = \"herdr\"\n\
                 env_allow = []\n\
                 provider = \"provider-a\"\n\
                 model = \"model-a\"\n\
                 binding_introspection = false\n\
                 \n\
                 [workflow.bundle]\n\
                 id = \"{DOCTRINE_WORKFLOW_ID}\"\n\
                 hash = \"{WORKFLOW_HASH}\"\n",
                fixture.socket.display()
            ),
        )
        .expect("write config");
        fixture
    }

    fn config(&self) -> String {
        self.config_path
            .to_str()
            .expect("utf-8 config path")
            .to_string()
    }

    fn db(&self) -> PathBuf {
        self.state_dir.join("canter").join("state.db")
    }

    /// Open (creating when needed) the fixture state store.
    fn seed(&self) -> State {
        std::fs::create_dir_all(self.state_dir.join("canter")).expect("state dir");
        State::open(&self.db(), Retention::default()).expect("open state")
    }

    /// The fixture the operator path needs: one active grant AND one
    /// recorded run for issue 5 that already left the owned set (`done`),
    /// so the issue is free for a fresh attempt (the `tests/tui_operator.rs`
    /// seed).
    fn seed_operator_state(&self) {
        let state = self.seed();
        let epoch = state.current_epoch().expect("epoch");
        state.issue_grant(&grant_doc(epoch)).expect("issue grant");
        state
            .start_instance(
                SEEDED_RUN,
                &grant_id(),
                DOCTRINE_WORKFLOW_ID,
                "2026-09-06T00:00:00Z",
            )
            .expect("start instance");
        // No public API writes `done` yet (the seed `tests/board_read_model.rs`
        // uses as well).
        let raw = rusqlite::Connection::open(self.db()).expect("raw open");
        raw.execute(
            "UPDATE instances SET status = 'done', current_node = 'merge', updated_at = ?2
              WHERE instance_id = ?1",
            rusqlite::params![SEEDED_RUN, "2026-09-06T00:00:05Z"],
        )
        .expect("seed reported done");
    }

    fn spawn_daemon(&self) -> Child {
        std::fs::create_dir_all(&self.state_dir).expect("state home");
        Command::new(bin())
            .args(["daemon", "run", "--socket"])
            .arg(&self.socket)
            .env("XDG_STATE_HOME", &self.state_dir)
            .env("HOME", &self.dir)
            .stdout(Stdio::null())
            .stderr(Stdio::from(
                std::fs::File::create(self.dir.join("daemon.stderr.log")).expect("stderr log"),
            ))
            .spawn()
            .expect("spawn daemon")
    }

    /// Run the CLI as a child process with the fixture environment.
    fn cli(&self, args: &[&str]) -> (i32, String, String) {
        let output = Command::new(bin())
            .args(args)
            .env("XDG_STATE_HOME", &self.state_dir)
            .env("HOME", &self.dir)
            .output()
            .expect("run cli");
        (
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stdout).into_owned(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        )
    }

    /// Run the CLI in JSON mode and parse the `hf-output/v1` envelope.
    fn cli_json(&self, args: &[&str]) -> (i32, Val, String) {
        let (code, stdout, stderr) = self.cli(args);
        let doc = Val::parse_json(stdout.trim_end()).unwrap_or_else(|err| {
            panic!("stdout is not one JSON envelope ({err}): {stdout:?} stderr: {stderr:?}")
        });
        (code, doc, stderr)
    }

    /// The child environment of the real binary: the fixture state dir, a
    /// home, the invoking PATH and an explicit terminal.
    fn child_env(&self) -> Vec<(String, String)> {
        vec![
            (
                "XDG_STATE_HOME".to_string(),
                self.state_dir.display().to_string(),
            ),
            ("HOME".to_string(), self.dir.display().to_string()),
            (
                "PATH".to_string(),
                std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".to_string()),
            ),
            ("TERM".to_string(), "xterm-256color".to_string()),
        ]
    }
}

fn grant_id() -> String {
    format!(
        "gr_{}",
        &canter::canonical::sha256_hex(b"commands-91-grant")[..16]
    )
}

fn grant_doc(epoch: i64) -> Val {
    Val::parse_json(&format!(
        r#"{{"schema":"hf-grant/v1","grant_id":"{id}","repository":"{REPO}",
            "issue":{{"number":5,"revision":"{REVISION}"}},
            "workflow_hash":"{WORKFLOW_HASH}","policy_hash":"{POLICY_HASH}",
            "phase":"merge","scope":"worktrees/issues/5",
            "caps":["read","worktree","spawn","prompt","review","merge","cleanup"],
            "expires_at":"2999-01-01T00:00:00Z","state_epoch":{epoch},
            "created_at":"2026-09-06T00:00:00Z"}}"#,
        id = grant_id()
    ))
    .expect("grant document")
}

fn caps() -> ConcurrencyCaps {
    ConcurrencyCaps {
        global: 4,
        per_repository: 2,
        per_harness: 2,
    }
}

/// The reviewed role binding the CLI re-observes (from the fixture config).
fn binding_doc(fixture: &Fixture) -> Val {
    let config = load_config(Path::new(&fixture.config_path)).expect("fixture config loads");
    let harness = config
        .harnesses
        .iter()
        .find(|harness| harness.key == HARNESS)
        .expect("fixture harness");
    let env = credential_environment(harness);
    ProfileBinding::from_config(&config, HARNESS, &env)
        .expect("fixture binding")
        .to_doc()
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

/// The exact `queue preview` argv the plan-producer tests drive (the real
/// product command, printed by the demonstration run), in JSON mode.
fn preview_args(fixture: &Fixture, out: &Path) -> Vec<String> {
    let mut args = preview_invocation(fixture, "widgets", &[format!("5={REVISION}")], &[], out);
    args.push("--json".to_string());
    args
}

/// One `queue preview` invocation with overridable pieces (the refusal
/// tests drive the same command with one deliberately wrong input). The
/// caller appends `--json` when it wants the envelope; the human path is
/// what the refusals assert.
fn preview_invocation(
    fixture: &Fixture,
    repository: &str,
    issues: &[String],
    extra: &[&str],
    out: &Path,
) -> Vec<String> {
    let mut args: Vec<String> = [
        "queue",
        "preview",
        "--config",
        &fixture.config(),
        "--repository",
        repository,
        "--harness",
        HARNESS,
        "--host",
        "host-1",
        "--caps",
        "4/2/2",
        "--host-available",
        "yes",
        "--harness-lanes",
        "0",
        "--out",
        out.to_str().expect("utf-8 out path"),
    ]
    .iter()
    .map(|value| value.to_string())
    .collect();
    for issue in issues {
        args.push("--issue".to_string());
        args.push(issue.clone());
    }
    for value in extra {
        args.push(value.to_string());
    }
    args
}

/// Produce the reviewed bound-input document through the REAL command and
/// return (path, digest, canonical document text).
fn produce_plan(fixture: &Fixture, out: &Path) -> (String, String, Val) {
    let owned = preview_args(fixture, out);
    println!("command line: canter {}", owned.join(" "));
    let refs: Vec<&str> = owned.iter().map(String::as_str).collect();
    let (code, envelope, stderr) = fixture.cli_json(&refs);
    assert_eq!(code, 0, "queue preview must succeed: {stderr}");
    assert_eq!(
        envelope.get("schema").and_then(Val::as_str),
        Some("hf-output/v1")
    );
    let data = envelope.get("data").expect("data");
    let digest = data
        .get("digest")
        .and_then(Val::as_str)
        .expect("digest")
        .to_string();
    let request = data.get("request").expect("bound-input document").clone();
    let text = std::fs::read_to_string(out).expect("written plan");
    (digest, text, request)
}

// ---------------------------------------------------------------------------
// 1. The plan producer: `canter queue preview`
// ---------------------------------------------------------------------------

/// Issue #139: the operator selects the execution substrate explicitly, and
/// the authored spine carries it on EVERY harness step (so the reviewed plan
/// — and the digest an approval binds — names the substrate instead of
/// relying on an implicit default). The default is the Herdr pane.
#[test]
fn queue_preview_binds_the_selected_execution_substrate_into_every_harness_step() {
    let fixture = Fixture::new("preview-substrate");
    fixture.seed_operator_state();
    let harness_params = |request: &Val| -> Vec<String> {
        request
            .get("steps")
            .and_then(Val::as_array)
            .expect("steps")
            .iter()
            .filter(|step| {
                matches!(
                    step.get("kind").and_then(Val::as_str),
                    Some("harness_start") | Some("prompt")
                )
            })
            .map(|step| {
                step.get("params")
                    .and_then(|params| params.get("execution"))
                    .and_then(Val::as_str)
                    .expect("every harness step names its substrate")
                    .to_string()
            })
            .collect()
    };

    // Default: the Herdr pane substrate, stated explicitly on both steps.
    let plan_path = fixture.dir.join("default-plan.json");
    let (_, _, request) = produce_plan(&fixture, &plan_path);
    assert_eq!(
        harness_params(&request),
        vec!["herdr".to_string(), "herdr".to_string()],
        "the default substrate is the Herdr pane: {}",
        canter::canonical::canonical_text(&request)
    );

    // The documented fallback is selectable, and only explicitly.
    let headless_path = fixture.dir.join("headless-plan.json");
    let mut owned = preview_invocation(
        &fixture,
        "widgets",
        &[format!("5={REVISION}")],
        &["--execution", "headless"],
        &headless_path,
    );
    owned.push("--json".to_string());
    let refs: Vec<&str> = owned.iter().map(String::as_str).collect();
    let (code, envelope, stderr) = fixture.cli_json(&refs);
    assert_eq!(code, 0, "{stderr}");
    let request = envelope
        .get("data")
        .and_then(|data| data.get("request"))
        .expect("bound-input document");
    assert_eq!(
        harness_params(request),
        vec!["headless".to_string(), "headless".to_string()],
        "the operator's explicit selection is what the plan binds"
    );

    // An unknown substrate is a usage refusal, never a default.
    let mut bad = preview_invocation(
        &fixture,
        "widgets",
        &[format!("5={REVISION}")],
        &["--execution", "ssh"],
        &fixture.dir.join("bad-plan.json"),
    );
    bad.push("--json".to_string());
    let refs: Vec<&str> = bad.iter().map(String::as_str).collect();
    let (code, _stdout, stderr) = fixture.cli(&refs);
    assert_eq!(code, 2, "an unknown substrate is a usage error: {stderr}");
    assert!(
        stderr.contains("--execution takes herdr|headless"),
        "the usage refusal names the closed set: {stderr}"
    );
    assert!(
        !fixture.dir.join("bad-plan.json").exists(),
        "a refused invocation writes no bound-input document"
    );
}

#[test]
fn queue_preview_produces_the_bound_input_document_the_operator_path_consumes() {
    let fixture = Fixture::new("preview-produces");
    fixture.seed_operator_state();
    let plan_path = fixture.dir.join("reviewed-plan.json");
    let (digest, text, request) = produce_plan(&fixture, &plan_path);

    // The emitted digest IS the digest of the emitted document, and the
    // file is that document in canonical form (the material
    // `queue submit --request` and `board --plan` read).
    assert_eq!(qx::bound_digest(&request).expect("digest"), digest);
    let file_doc = Val::parse_json(text.trim_end()).expect("plan file parses");
    assert_eq!(
        canter::canonical::canonical_bytes(&file_doc),
        canter::canonical::canonical_bytes(&request),
        "the written document is the emitted one, canonically"
    );
    assert!(
        text.ends_with('\n'),
        "the written document ends with a newline"
    );
    // The reviewed bindings the document carries: the documented repository
    // identity, the configured workflow pin, the selected revision, the
    // declared spine and the boundary derived from it (never free-form).
    assert_eq!(request.get("repository").and_then(Val::as_str), Some(REPO));
    assert_eq!(
        request
            .get("workflow")
            .and_then(|workflow| workflow.get("id"))
            .and_then(Val::as_str),
        Some(DOCTRINE_WORKFLOW_ID)
    );
    assert_eq!(
        request
            .get("workflow")
            .and_then(|workflow| workflow.get("hash"))
            .and_then(Val::as_str),
        Some(WORKFLOW_HASH),
        "the configured doctrine pin's hash is what the plan binds"
    );
    let boundary_caps: Vec<&str> = request
        .get("boundary")
        .and_then(|boundary| boundary.get("caps"))
        .and_then(Val::as_array)
        .expect("boundary caps")
        .iter()
        .filter_map(Val::as_str)
        .collect();
    assert_eq!(
        boundary_caps,
        vec![
            "read", "worktree", "spawn", "prompt", "review", "merge", "cleanup"
        ],
        "the boundary carries exactly the capabilities its declared spine requires"
    );

    // The production consumer path accepts it: rebuilding the presented
    // request and revalidating it (the operator surface's preview, the
    // daemon's submit preflight) yields an APPROVED item for the selected
    // issue — no unresolved step, no boundary gap, no stale digest.
    let state = fixture.seed();
    let epoch = state.current_epoch().expect("epoch");
    let material = qx::SubmissionMaterial {
        idempotency_key: "ik_commands-91-preview".to_string(),
        preview: request.clone(),
        binding: binding_doc(&fixture),
        digest: digest.clone(),
        epoch,
        role_revision: binding_revision(&fixture),
        caps: caps(),
        host_available: Some(true),
        harness_lanes: Some(0),
        grants: vec![qx::ItemGrant {
            id: "5".to_string(),
            grant_id: grant_id(),
        }],
        resume: Vec::new(),
        supervision: None,
    };
    let rebuilt = qx::presented_request(&material).expect("the bound document rebuilds");
    assert_eq!(rebuilt.repository, REPO.to_ascii_lowercase());
    assert_eq!(rebuilt.harness_key, HARNESS);
    assert_eq!(rebuilt.workflow_id, DOCTRINE_WORKFLOW_ID);
    assert_eq!(rebuilt.selected.len(), 1);
    assert_eq!(rebuilt.selected[0].revision, REVISION);
    assert!(
        rebuilt.steps.iter().all(|step| step.params.is_some()),
        "every declared step carries its resolved parameters"
    );
    let revalidated = qx::revalidate(&state, &material).expect("the preview revalidates");
    assert_eq!(
        revalidated.preview.digest, digest,
        "the service re-derives the very digest the command printed"
    );
    assert_eq!(revalidated.items.len(), 1, "one item per selected issue");
    assert_eq!(
        revalidated.items[0].verdict,
        canter::state::SubmissionVerdict::Approved,
        "the selected issue is authorizable against the seeded grant"
    );

    // A preview with an unconsumable prerequisite stays honest: no step is
    // emitted unresolved and the render proves zero holds.
    let ready = revalidated.preview.ready;
    assert!(ready, "the fixture environment carries no holds");
}

#[test]
fn queue_preview_derives_the_workflow_hash_when_no_pin_is_configured() {
    let fixture = Fixture::new("preview-derived-hash");
    fixture.seed_operator_state();
    // The same fixture config without the workflow pin: the producer derives
    // the doctrine workflow hash from its own declared spine (the
    // documented `canter plan` rule), through the same public derivation.
    let unpinned_text = std::fs::read_to_string(&fixture.config_path)
        .expect("fixture config")
        .split("\n[workflow.bundle]")
        .next()
        .expect("config head")
        .to_string();
    let unpinned = fixture.dir.join("config-unpinned.toml");
    std::fs::write(&unpinned, unpinned_text).expect("write unpinned config");
    let plan_path = fixture.dir.join("derived-plan.json");
    let mut owned = preview_invocation(
        &fixture,
        "widgets",
        &[format!("5={REVISION}")],
        &[],
        &plan_path,
    );
    owned.push("--json".to_string());
    // Point the invocation at the unpinned config.
    if let Some(position) = owned.iter().position(|value| value == "--config") {
        owned[position + 1] = unpinned.to_str().expect("utf-8").to_string();
    }
    let refs: Vec<&str> = owned.iter().map(String::as_str).collect();
    let (code, envelope, stderr) = fixture.cli_json(&refs);
    assert_eq!(code, 0, "{stderr}");
    let request = envelope
        .get("data")
        .and_then(|data| data.get("request"))
        .expect("bound-input document");
    let emitted = request
        .get("workflow")
        .and_then(|workflow| workflow.get("hash"))
        .and_then(Val::as_str)
        .expect("workflow hash");
    let expected = canter::plan::doctrine_workflow_hash(&canter::plan::queue_run_steps(
        REPO,
        "staging",
        HARNESS,
        None,
        &[5],
        canter::adapters::ExecutionMode::HerdrPane,
    ));
    assert_eq!(
        emitted, expected,
        "the derived binding is the documented doctrine derivation over the declared spine"
    );
}

#[test]
fn queue_preview_renders_the_service_preview_document_and_its_holds() {
    let fixture = Fixture::new("preview-holds");
    fixture.seed_operator_state();
    let plan_path = fixture.dir.join("reviewed-plan.json");
    let owned = preview_args(&fixture, &plan_path);
    let mut held: Vec<String> = owned.clone();
    // An unattested host is never a yes: the render shows the named hold.
    let position = held
        .iter()
        .position(|value| value == "yes")
        .expect("--host-available value");
    held[position] = "unknown".to_string();
    let refs: Vec<&str> = held.iter().map(String::as_str).collect();
    let (code, envelope, stderr) = fixture.cli_json(&refs);
    assert_eq!(
        code, 0,
        "an unattested host renders holds, not a refusal: {stderr}"
    );
    let data = envelope.get("data").expect("data");
    assert_eq!(
        data.get("ready").and_then(Val::as_bool),
        Some(false),
        "unknown host availability is a hold, never readiness"
    );
    let preview = data.get("preview").expect("preview document");
    assert_eq!(
        preview.get("schema").and_then(Val::as_str),
        Some("hf-queue-preview/v1")
    );
    let holds = preview
        .get("holds")
        .and_then(Val::as_array)
        .expect("holds array");
    assert!(
        holds.iter().any(|hold| {
            hold.get("code").and_then(Val::as_str) == Some("preview.host_unavailable")
        }),
        "the render names the host hold: {}",
        canter::canonical::canonical_text(preview)
    );
    assert_eq!(
        preview
            .get("boundaries")
            .and_then(|boundaries| boundaries.get("mutates"))
            .and_then(Val::as_bool),
        Some(false),
        "the preview declares itself effect-free"
    );
}

#[test]
fn queue_preview_refuses_typed_and_never_creates_a_state_store() {
    let fixture = Fixture::new("preview-refusals");
    let plan_path = fixture.dir.join("unused-plan.json");

    // No state store: a typed operational refusal that creates nothing.
    let owned = preview_args(&fixture, &plan_path);
    let refs: Vec<&str> = owned.iter().map(String::as_str).collect();
    let (code, envelope, _stderr) = fixture.cli_json(&refs);
    assert_eq!(code, 1);
    assert_eq!(
        envelope
            .get("error")
            .and_then(|error| error.get("code"))
            .and_then(Val::as_str),
        Some("queue.no_state")
    );
    assert!(
        !fixture.db().exists(),
        "the preview never creates a state store"
    );
    assert!(!plan_path.exists(), "a refused preview writes no document");

    fixture.seed_operator_state();

    // An unknown repository, a submission flag, a malformed revision, a
    // conflicting duplicate selection and an empty selection are all typed
    // usage refusals (exit 2) that write nothing.
    let cases: Vec<(Vec<String>, &str)> = vec![
        (
            preview_invocation(
                &fixture,
                "nope",
                &[format!("5={REVISION}")],
                &[],
                &plan_path,
            ),
            "an unknown repository key",
        ),
        (
            preview_invocation(
                &fixture,
                "widgets",
                &[format!("5={REVISION}")],
                &["--grant", "5=gr_0123456789abcdef"],
                &plan_path,
            ),
            "a submission flag on the preview",
        ),
        (
            preview_invocation(
                &fixture,
                "widgets",
                &["5=not-hex".to_string()],
                &[],
                &plan_path,
            ),
            "a malformed spec revision",
        ),
        (
            preview_invocation(
                &fixture,
                "widgets",
                &[
                    format!("5={REVISION}"),
                    "5=2222222222222222222222222222222222222222".to_string(),
                ],
                &[],
                &plan_path,
            ),
            "a conflicting duplicate selection",
        ),
        (
            preview_invocation(&fixture, "widgets", &[], &[], &plan_path),
            "an empty selection",
        ),
    ];
    for (owned, what) in &cases {
        let refs: Vec<&str> = owned.iter().map(String::as_str).collect();
        let (code, stdout, stderr) = fixture.cli(&refs);
        assert_eq!(code, 2, "{what} must be a usage refusal: {stderr}");
        assert!(stdout.is_empty(), "{what}: stdout stays empty");
    }
    assert!(
        !plan_path.exists(),
        "no refused invocation wrote a document"
    );
    let state = fixture.seed();
    assert_eq!(
        state.list_instances().expect("instances").len(),
        1,
        "the refusals wrote nothing to the state store"
    );

    // A configured workflow pin naming a workflow this read-only core cannot
    // render refuses typed (exit 4), exactly like `canter plan` — the plan
    // producer never emits a document the preview engine cannot execute.
    let foreign = fixture.dir.join("config-foreign.toml");
    let foreign_text = std::fs::read_to_string(&fixture.config_path)
        .expect("fixture config")
        .replace(DOCTRINE_WORKFLOW_ID, "some-other-engine");
    std::fs::write(&foreign, foreign_text).expect("write foreign config");
    let foreign_args = [
        "queue",
        "preview",
        "--config",
        foreign.to_str().expect("utf-8"),
        "--repository",
        "widgets",
        "--harness",
        HARNESS,
        "--host",
        "host-1",
        "--issue",
        &format!("5={REVISION}"),
        "--caps",
        "4/2/2",
        "--json",
    ];
    let (code, envelope, _stderr) = fixture.cli_json(&foreign_args);
    assert_eq!(code, 4, "an unsupported workflow pin is a typed refusal");
    assert_eq!(
        envelope
            .get("error")
            .and_then(|error| error.get("code"))
            .and_then(Val::as_str),
        Some("refusal.workflow.unsupported")
    );
    assert!(!plan_path.exists(), "the refusal wrote no document");
}

// ---------------------------------------------------------------------------
// 2. The operator command path: `canter board --plan FILE`
// ---------------------------------------------------------------------------

#[test]
fn the_board_command_selects_previews_authorizes_and_starts_a_daemon_owned_run() {
    let fixture = Fixture::new("board-end-to-end");
    fixture.seed_operator_state();
    let daemon = fixture.spawn_daemon();
    wait_ready(&fixture);

    // The reviewed plan is produced by the REAL command (the plan producer),
    // never hand-assembled.
    let plan_path = fixture.dir.join("reviewed-plan.json");
    let (digest, _text, _request) = produce_plan(&fixture, &plan_path);

    let grant = format!("5={}", grant_id());
    let args = [
        "board",
        "--config",
        &fixture.config(),
        "--plan",
        plan_path.to_str().expect("utf-8 plan path"),
        "--caps",
        "4/2/2",
        "--host-available",
        "yes",
        "--harness-lanes",
        "0",
        "--grant",
        &grant,
    ];
    println!("command line: canter {}", args.join(" "));
    // j (select the recorded run), p (exact preview), Enter (continue),
    // Space (explicit authorization), Enter (authorize), q (quit).
    let run = pty::run(bin(), &args, &fixture.child_env(), b"jp\r \rq").expect("pty run");
    let text = strip_ansi(&run.output);
    for line in text.lines().take(40) {
        println!("|{line}|");
    }
    assert_eq!(run.exit_code, 0, "captured frame:\n{text}");
    for expected in [
        "Canter operator board",
        "PREVIEW",
        "AUTHORIZATION",
        "OBSERVED (what the daemon reports)",
        "committed under epoch",
    ] {
        assert!(
            contains_content(&text, expected),
            "the captured operator path must show {expected:?}:\n{text}"
        );
    }
    assert!(
        contains_content(&text, &format!("digest {digest}")),
        "the outcome screen binds the exact approved digest:\n{text}"
    );
    let submission_id = find_submission_id(&text).unwrap_or_else(|| {
        panic!("the outcome screen carries the committed submission id:\n{text}")
    });

    // The terminal is gone (the child exited): the daemon-owned run survives
    // it. A SEPARATE CLI invocation reads the real committed state back —
    // nothing is replayed by the board.
    let (code, envelope, stderr) = fixture.cli_json(&[
        "queue",
        "status",
        "--submission",
        &submission_id,
        "--config",
        &fixture.config(),
        "--json",
    ]);
    assert_eq!(code, 0, "queue status readback: {stderr}");
    let status = envelope.get("data").expect("status data");
    assert_eq!(
        status.get("submission_id").and_then(Val::as_str),
        Some(submission_id.as_str()),
        "the readback is the same committed submission"
    );
    let item = status
        .get("items")
        .and_then(Val::as_array)
        .expect("items")
        .iter()
        .find(|item| item.get("id").and_then(Val::as_str) == Some("example-org/widgets#5"))
        .expect("the selected issue is in the committed submission")
        .clone();
    assert_eq!(item.get("status").and_then(Val::as_str), Some("admitted"));
    assert!(
        item.get("instance_id").and_then(Val::as_str).is_some(),
        "the admitted item owns a run record: {}",
        canter::canonical::canonical_text(&item)
    );

    // One durable submission and two recorded runs (the seed plus the
    // admitted one): the board's authorization committed ONCE.
    let state = fixture.seed();
    assert_eq!(
        state.list_instances().expect("instances").len(),
        2,
        "the seed run plus the one admitted run"
    );
    assert_eq!(
        state.queue_ownership_rows().expect("ownership").len(),
        1,
        "exactly one ownership row"
    );

    shutdown(daemon);
}

#[test]
fn the_board_without_a_plan_presents_no_run_and_authorizes_nothing() {
    let fixture = Fixture::new("board-no-plan");
    fixture.seed_operator_state();
    let daemon = fixture.spawn_daemon();
    wait_ready(&fixture);

    let args = ["board", "--config", &fixture.config()];
    println!("command line: canter {}", args.join(" "));
    // j selects the recorded run, p asks for a preview (there is no
    // presented run), q quits.
    let run = pty::run(bin(), &args, &fixture.child_env(), b"jpq").expect("pty run");
    let text = strip_ansi(&run.output);
    assert_eq!(run.exit_code, 0, "captured frame:\n{text}");
    assert!(
        contains_content(&text, "operator.plan"),
        "the read-only board states that no reviewed run is presented:\n{text}"
    );

    // Nothing was authorized and nothing was written.
    let state = fixture.seed();
    assert_eq!(state.list_instances().expect("instances").len(), 1);
    assert_eq!(state.queue_ownership_rows().expect("ownership").len(), 0);
    shutdown(daemon);
}

#[test]
fn board_plan_errors_are_typed_before_the_terminal_is_touched() {
    let fixture = Fixture::new("board-plan-refusals");

    // No state store: the read-only preflight refuses typed and creates
    // nothing (the board never creates the store it reads). The human path
    // carries the message; the typed code stays in the JSON surface, which
    // this interactive command deliberately does not have.
    let (code, stdout, stderr) = fixture.cli(&["board", "--config", &fixture.config()]);
    assert_eq!(code, 1, "{stderr}");
    assert!(stdout.is_empty());
    assert!(stderr.contains("no daemon state store"), "{stderr}");
    assert!(!fixture.db().exists(), "the board creates no state store");

    fixture.seed_operator_state();

    // A missing plan file, a non-object document and a directory are typed
    // usage refusals (exit 2) that never reach the terminal or the daemon.
    let missing = fixture.dir.join("missing-plan.json");
    let (code, _stdout, stderr) = fixture.cli(&[
        "board",
        "--config",
        &fixture.config(),
        "--plan",
        missing.to_str().expect("utf-8"),
        "--caps",
        "4/2/2",
    ]);
    assert_eq!(code, 2, "{stderr}");
    assert!(
        stderr.contains("cannot read") && stderr.contains("bound-input document"),
        "the unreadable plan is refused with its own message: {stderr}"
    );

    let malformed = fixture.dir.join("malformed-plan.json");
    std::fs::write(&malformed, "[1, 2, 3]\n").expect("write malformed plan");
    let (code, _stdout, stderr) = fixture.cli(&[
        "board",
        "--config",
        &fixture.config(),
        "--plan",
        malformed.to_str().expect("utf-8"),
        "--caps",
        "4/2/2",
    ]);
    assert_eq!(code, 2, "{stderr}");
    assert!(
        stderr.contains("must carry one bound-input document"),
        "a non-object plan is refused with its own message: {stderr}"
    );
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// The bound role revision of the fixture config (what the CLI re-observes).
fn binding_revision(fixture: &Fixture) -> String {
    let binding = binding_doc(fixture);
    binding
        .get("revision")
        .and_then(Val::as_str)
        .unwrap_or_default()
        .to_string()
}

/// Scan captured terminal text for the first `qs_` submission identity.
fn find_submission_id(text: &str) -> Option<String> {
    let bytes: Vec<char> = text.chars().collect();
    let needle: Vec<char> = "qs_".chars().collect();
    for start in 0..bytes.len().saturating_sub(19) {
        if bytes[start..start + 3] != needle[..] {
            continue;
        }
        let candidate: String = bytes[start..start + 19].iter().collect();
        if candidate
            .chars()
            .skip(3)
            .all(|character| character.is_ascii_hexdigit())
        {
            return Some(candidate);
        }
    }
    None
}

/// Strip ANSI escape sequences from a captured terminal stream (the
/// `tests/tui_operator.rs` helper).
fn strip_ansi(bytes: &[u8]) -> String {
    let mut text: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != 0x1b {
            text.push(bytes[index]);
            index += 1;
            continue;
        }
        index += 1;
        match bytes.get(index) {
            Some(b'[') => {
                index += 1;
                while index < bytes.len() && !(0x40..=0x7e).contains(&bytes[index]) {
                    index += 1;
                }
                index += 1;
            }
            Some(b']') => {
                index += 1;
                while index < bytes.len() && bytes[index] != 0x07 {
                    index += 1;
                }
                index += 1;
            }
            Some(b'(') | Some(b')') => index += 2,
            _ => index += 1,
        }
    }
    String::from_utf8_lossy(&text).into_owned()
}

/// Whether a captured frame carries `needle`, ignoring whitespace: a real
/// terminal legitimately receives fewer bytes than the cell grid, so PTY
/// assertions compare content.
fn contains_content(text: &str, needle: &str) -> bool {
    let squash = |value: &str| -> String { value.chars().filter(|c| !c.is_whitespace()).collect() };
    squash(text).contains(&squash(needle))
}

/// Minimal real pseudo-terminal harness (the `tests/tui_operator.rs` shape):
/// `forkpty` gives the child a genuine controlling terminal, which is what
/// Crossterm's raw-mode path needs; the parent captures every byte the
/// terminal emits and writes the key bytes back once the first frame is
/// drawn. Unlike the operator-surface tests, the child here is the REAL
/// `canter` binary with the product argv.
mod pty {
    use std::ffi::CString;
    use std::io;
    use std::time::{Duration, Instant};

    /// Wall-clock budget for one child (bounded; a live child is killed).
    const DEADLINE: Duration = Duration::from_secs(60);
    /// Budget for the first frame before the child is treated as wedged.
    const FIRST_FRAME: Duration = Duration::from_secs(30);
    const WIN_ROWS: u16 = 40;
    const WIN_COLS: u16 = 120;
    const TITLE: &[u8] = b"Canter operator board";

    pub struct Run {
        pub output: Vec<u8>,
        pub exit_code: i32,
    }

    fn invalid(what: &str) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidInput, what.to_string())
    }

    pub fn run(
        program: &str,
        args: &[&str],
        env: &[(String, String)],
        keys: &[u8],
    ) -> io::Result<Run> {
        let mut argv_strings = vec![CString::new(program).map_err(|_| invalid("program"))?];
        for arg in args {
            argv_strings.push(CString::new(*arg).map_err(|_| invalid("argument"))?);
        }
        let mut env_strings = Vec::with_capacity(env.len());
        for (key, value) in env {
            env_strings
                .push(CString::new(format!("{key}={value}")).map_err(|_| invalid("environment"))?);
        }
        let argv: Vec<*const libc::c_char> = argv_strings
            .iter()
            .map(|arg| arg.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect();
        let envp: Vec<*const libc::c_char> = env_strings
            .iter()
            .map(|value| value.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect();

        let mut winsize = libc::winsize {
            ws_row: WIN_ROWS,
            ws_col: WIN_COLS,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // The libc signature takes `*mut winsize` on BSD/macOS and
        // `*const winsize` on Linux; an explicit raw pointer satisfies both.
        let winsize_ptr: *mut libc::winsize = &raw mut winsize;
        let mut master: libc::c_int = -1;
        // SAFETY: `forkpty` is the POSIX pseudo-terminal fork; the child only
        // execve/_exit before replacing its image.
        let pid = unsafe {
            libc::forkpty(
                &mut master,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                winsize_ptr,
            )
        };
        if pid < 0 {
            return Err(io::Error::last_os_error());
        }
        if pid == 0 {
            // SAFETY: exec with the argv/envp built above; on failure the
            // child must not run the test harness, so it exits immediately.
            unsafe {
                libc::execve(argv[0], argv.as_ptr(), envp.as_ptr());
                libc::_exit(127);
            }
        }

        let started = Instant::now();
        let mut output: Vec<u8> = Vec::new();
        let mut keys_sent = false;
        let mut quiet = 0_u32;
        let mut status: Option<libc::c_int> = None;
        while started.elapsed() < DEADLINE {
            let mut pollfd = libc::pollfd {
                fd: master,
                events: libc::POLLIN,
                revents: 0,
            };
            let ready = unsafe { libc::poll(&mut pollfd, 1, 100) };
            let mut read_bytes = 0_usize;
            if ready > 0 && pollfd.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
                let mut buffer = [0_u8; 8192];
                let count = unsafe { libc::read(master, buffer.as_mut_ptr().cast(), buffer.len()) };
                if count > 0 {
                    read_bytes = count as usize;
                    output.extend_from_slice(&buffer[..read_bytes]);
                }
            }
            if !keys_sent && output.windows(TITLE.len()).any(|window| window == TITLE) {
                // The first frame is drawn, so the session is already in raw
                // mode: the keys arrive as keystrokes, without Enter.
                let written = unsafe { libc::write(master, keys.as_ptr().cast(), keys.len()) };
                if written < 0 {
                    return Err(io::Error::last_os_error());
                }
                keys_sent = true;
            }
            if !keys_sent && started.elapsed() > FIRST_FRAME {
                break;
            }
            quiet = if read_bytes > 0 { 0 } else { quiet + 1 };
            if status.is_none() {
                let mut raw: libc::c_int = 0;
                if unsafe { libc::waitpid(pid, &mut raw, libc::WNOHANG) } == pid {
                    status = Some(raw);
                }
            }
            if status.is_some() && quiet >= 2 {
                break;
            }
        }
        if status.is_none() {
            // Bounded: never leave a live child behind.
            unsafe {
                libc::kill(pid, libc::SIGKILL);
            }
            let mut raw: libc::c_int = 0;
            unsafe {
                libc::waitpid(pid, &mut raw, 0);
            }
            status = Some(raw);
        }
        unsafe {
            libc::close(master);
        }
        let raw = status.unwrap_or(-1);
        let exit_code = if libc::WIFEXITED(raw) {
            libc::WEXITSTATUS(raw)
        } else {
            -1
        };
        Ok(Run { output, exit_code })
    }
}
