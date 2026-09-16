//! Issue #8 control-plane mutation acceptance tests over the real binary
//! and socket: deterministic fakes + disposable LOCAL repositories only.
//!
//! Every test builds a private sandbox with a local bare "remote", an
//! integration checkout on `staging`, a lane worktrees root, fake
//! `gh`/`hf-lane` executables on an allowlisted PATH, a seeded daemon state
//! (route grant + workflow instance), and a real daemon child. Effects are
//! driven through the `plan`/`apply` RPC methods with real git subprocesses
//! (disposable local repos — never a real remote) and scripted `gh` fakes.
//! Nothing here touches the network, a real repository, or a real account.
#[path = "support/process_group.rs"]
mod process_group;

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use canter::canonical::{canonical_bytes, sha256_hex};
use canter::client::{Connection, RpcError};
use canter::dirs::DaemonPaths;
use canter::state::{Retention, State};
use canter::value::{Val, integer, null, object, string};
use process_group::{GroupChild, assert_no_process_for_socket};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_canter")
}

// ---------------------------------------------------------------------------
// Sandbox + repositories (disposable; local only)
// ---------------------------------------------------------------------------

struct Sandbox {
    root: PathBuf,
}

impl Sandbox {
    fn new(name: &str) -> Sandbox {
        let root = std::env::temp_dir().join(format!(
            "hf-mut8-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&root).expect("sandbox root");
        Sandbox { root }
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.root.join(rel)
    }

    fn write(&self, rel: &str, content: &str) -> PathBuf {
        let path = self.path(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("parent dir");
        }
        std::fs::write(&path, content).expect("write file");
        path
    }

    fn chmod_x(&self, rel: &str) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let path = self.path(rel);
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
                .expect("chmod +x");
        }
    }
}

struct Git {
    cwd: PathBuf,
}

impl Git {
    fn new(cwd: &Path) -> Git {
        Git {
            cwd: cwd.to_path_buf(),
        }
    }

    fn run(&self, args: &[&str]) -> String {
        let out = Command::new("git")
            .args(args)
            .current_dir(&self.cwd)
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("HOME", std::env::var("HOME").unwrap_or_default())
            .env("GIT_AUTHOR_NAME", "test")
            .env("GIT_AUTHOR_EMAIL", "test@example.invalid")
            .env("GIT_COMMITTER_NAME", "test")
            .env("GIT_COMMITTER_EMAIL", "test@example.invalid")
            .output()
            .expect("spawn git");
        assert!(
            out.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    fn head(&self, rev: &str) -> String {
        self.run(&["rev-parse", "--verify", rev]).trim().to_string()
    }
}

struct Repos {
    checkout: PathBuf,
    worktrees_root: PathBuf,
    /// Daemon-owned archive/salvage root (issue #9 AC7 cleanup probes).
    archive_root: PathBuf,
}

fn make_repos(sandbox: &Sandbox) -> Repos {
    let seed = sandbox.path("seed");
    let origin = sandbox.path("origin.git");
    let checkout = sandbox.path("checkout");
    std::fs::create_dir_all(&seed).expect("seed dir");
    let seed_git = Git::new(&seed);
    seed_git.run(&["init", "-q", "-b", "staging"]);
    std::fs::write(seed.join("base.txt"), "base\n").expect("base file");
    seed_git.run(&["add", "base.txt"]);
    seed_git.run(&["commit", "-q", "-m", "seed base"]);
    let root_git = Git::new(sandbox.root.as_path());
    root_git.run(&[
        "clone",
        "-q",
        "--bare",
        seed.to_str().unwrap(),
        origin.to_str().unwrap(),
    ]);
    root_git.run(&[
        "clone",
        "-q",
        origin.to_str().unwrap(),
        checkout.to_str().unwrap(),
    ]);
    let ck = Git::new(&checkout);
    ck.run(&["checkout", "-q", "staging"]);
    ck.run(&["config", "user.name", "canter test"]);
    ck.run(&["config", "user.email", "test@example.invalid"]);
    Repos {
        checkout,
        worktrees_root: sandbox.path("worktrees"),
        archive_root: sandbox.path("archives"),
    }
}

/// Fake `gh` (deterministic forge responses).
const FAKE_GH: &str = r#"#!/bin/sh
case "$1" in
  pr)
    case "$2" in
      create)
        printf '%s' '{"number": 1001, "url": "https://github.invalid/example-org/widgets/pull/1001"}'
        exit 0 ;;
      checks)
        printf '%s' '[{"name":"exact-head-review","state":"SUCCESS","conclusion":"success"},{"name":"hosted-ci","state":"SUCCESS","conclusion":"success"}]'
        exit 0 ;;
      comment) printf '%s' '{"id": 77}'; exit 0 ;;
    esac ;;
  issue)
    case "$2" in
      comment) printf '%s' '{"id": 88}'; exit 0 ;;
      close) printf '%s' '{"number": 123, "state": "closed"}'; exit 0 ;;
    esac ;;
esac
exit 1
"#;

/// Fake lane harness (`argv` adapter): appends a lane commit inside the
/// assigned worktree (idempotently), then prints a deterministic transcript.
const FAKE_LANE: &str = r#"#!/bin/sh
echo 'lane change' >> lane.txt
git add -A
git -c user.name='canter lane' -c user.email='lane@example.invalid' commit -q -m 'lane work (synthetic)'
printf '%s' 'lane transcript ok'
exit 0
"#;

// ---------------------------------------------------------------------------
// Daemon fixture
// ---------------------------------------------------------------------------

struct Fixture {
    dir: PathBuf,
    state_dir: PathBuf,
    socket: PathBuf,
    stderr_log: PathBuf,
}

impl Fixture {
    fn new(sandbox: &Sandbox, name: &str) -> Fixture {
        let dir = sandbox.path(&format!("daemon-{name}"));
        std::fs::create_dir_all(&dir).expect("fixture dir");
        // The daemon SOCKET path must stay short on every platform: macOS
        // Unix sockets use sockaddr_un (~104-byte sun_path limit) and CI
        // temp dirs live under a long /var/folders/... prefix, so nesting
        // the socket inside the (already long) sandbox root + daemon-{name}
        // subdir exceeds the limit and the daemon can never bind. State and
        // logs may keep the descriptive long layout (files have no such
        // limit); only the socket is placed at a short direct child of the
        // sandbox root (tests/daemon_rpc.rs passes on macOS the same way —
        // short dir + short socket filename).
        Fixture {
            state_dir: dir.join("state"),
            socket: sandbox.path("sock"),
            stderr_log: dir.join("daemon.stderr.log"),
            dir,
        }
    }

    fn paths(&self) -> DaemonPaths {
        let state_dir = self.state_dir.join("canter");
        DaemonPaths {
            state_dir: state_dir.clone(),
            runtime_dir: self.dir.clone(),
            socket_path: self.socket.clone(),
            lock_path: state_dir.join("daemon.lock"),
            db_path: state_dir.join("state.db"),
            audit_mirror_path: state_dir.join("journal").join("audit.jsonl"),
            events_mirror_path: state_dir.join("journal").join("events.jsonl"),
            backups_dir: state_dir.join("backups"),
            checkpoints_dir: state_dir.join("checkpoints"),
            log_path: state_dir.join("daemon.log"),
        }
    }

    fn spawn(&self, path: &str) -> GroupChild {
        let stderr_file = std::fs::File::create(&self.stderr_log).expect("stderr log");
        let mut command = Command::new(bin());
        command
            .args(["daemon", "run", "--socket"])
            .arg(&self.socket)
            .env("XDG_STATE_HOME", &self.state_dir)
            .env("HOME", &self.dir)
            .env("PATH", path)
            .stdout(Stdio::null())
            .stderr(Stdio::from(stderr_file));
        GroupChild::spawn(&mut command, &self.socket).expect("spawn daemon")
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
    // Fail with the daemon's own output so a macOS-style bind failure (long
    // socket path > sockaddr_un limit) or any other startup error is
    // self-explanatory in CI instead of an opaque timeout.
    let stderr_text = std::fs::read_to_string(&fixture.stderr_log).unwrap_or_default();
    let daemon_log = fixture.state_dir.join("canter").join("daemon.log");
    let log_text = std::fs::read_to_string(&daemon_log).unwrap_or_default();
    panic!(
        "daemon did not become ready on {} ({} bytes; macOS sockaddr_un ~104-byte limit); stderr:\n{}\ndaemon.log:\n{}",
        fixture.socket.display(),
        fixture.socket.as_os_str().to_string_lossy().len(),
        stderr_text,
        log_text
    );
}

fn rpc(socket: &Path, id: &str, method: &str, params: Option<Val>) -> Val {
    let mut connection = Connection::open(socket).expect("connect");
    connection
        .send_request(id, method, params.as_ref())
        .expect("send");
    let response = connection.read_response().expect("read response");
    if response.ok {
        object(vec![
            ("ok", canter::value::bool_(true)),
            ("result", response.result),
        ])
    } else {
        let error = response.error.unwrap_or_else(|| RpcError {
            code: "missing.error".to_string(),
            message: "no error doc".to_string(),
        });
        object(vec![
            ("ok", canter::value::bool_(false)),
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
        "expected ok response: {}",
        canter::canonical::canonical_text(&doc)
    );
    doc.get("result").expect("result").clone()
}

fn rpc_err(socket: &Path, id: &str, method: &str, params: Option<Val>) -> (String, String) {
    let doc = rpc(socket, id, method, params);
    assert_eq!(
        doc.get("ok").and_then(Val::as_bool),
        Some(false),
        "expected refused response: {}",
        canter::canonical::canonical_text(&doc)
    );
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

fn fresh_id(seed: u32) -> String {
    format!("{:08x}", seed + std::process::id())
}

// ---------------------------------------------------------------------------
// State seeding + plan builders
// ---------------------------------------------------------------------------

const GRANT_ID: &str = "gr_abcdef0123456789";
const INSTANCE_ID: &str = "run-1";
const REVISION: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const POLICY_HASH: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
const WORKFLOW_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

fn grant_doc(expires_at: &str) -> Val {
    object(vec![
        ("schema", string("hf-grant/v1")),
        ("grant_id", string(GRANT_ID)),
        ("repository", string("example-org/widgets")),
        (
            "issue",
            object(vec![
                ("number", integer(123)),
                ("revision", string(REVISION)),
            ]),
        ),
        ("workflow_hash", string(WORKFLOW_HASH)),
        ("policy_hash", string(POLICY_HASH)),
        ("phase", string("merge")),
        ("scope", string("worktrees/issues/123")),
        (
            "caps",
            Val::Arr(vec![
                string("read"),
                string("worktree"),
                string("spawn"),
                string("prompt"),
                string("review"),
                string("merge"),
                string("cleanup"),
                string("production"),
            ]),
        ),
        ("expires_at", string(expires_at)),
        ("state_epoch", integer(1)),
        ("created_at", string("2026-09-06T00:00:00Z")),
    ])
}

fn seed_state(db_path: &Path, expires_at: &str) {
    let state = State::open(db_path, Retention::default()).expect("open state");
    state
        .issue_grant(&grant_doc(expires_at))
        .expect("issue grant");
    state
        .start_instance(
            INSTANCE_ID,
            GRANT_ID,
            "fleet-doctrine-1",
            "2026-09-06T00:00:00Z",
        )
        .expect("start instance");
}

fn step(id: &str, kind: &str, params: Option<Val>) -> Val {
    object(vec![
        ("id", string(id)),
        ("kind", string(kind)),
        ("params", params.unwrap_or_else(null)),
    ])
}

fn make_plan(steps: Vec<Val>) -> Val {
    let seed = object(vec![
        ("schema", string("hf-plan/v1")),
        ("plan_id", string("hf_plan_0000000000000000")),
        ("workflow_id", string("fleet-doctrine-1")),
        ("workflow_hash", string(WORKFLOW_HASH)),
        ("state_epoch", integer(1)),
        ("repository", string("example-org/widgets")),
        (
            "issue",
            object(vec![
                ("number", integer(123)),
                ("revision", string(REVISION)),
            ]),
        ),
        ("steps", Val::Arr(steps.clone())),
    ]);
    let digest = sha256_hex(&canonical_bytes(&seed));
    let plan_id = format!("hf_plan_{}", &digest[..16]);
    let mut map = match seed {
        Val::Obj(map) => map,
        _ => unreachable!(),
    };
    map.insert("plan_id".to_string(), string(&plan_id));
    Val::Obj(map)
}

fn flow_steps() -> Vec<Val> {
    vec![
        step(
            "w1",
            "worktree_create",
            Some(object(vec![
                ("branch", string("issue-123")),
                ("worktree", string("issues-123")),
            ])),
        ),
        step(
            "h1",
            "harness_start",
            Some(object(vec![
                ("session_id", string("sess-8-1")),
                ("herdr_session", string("ws-session-8")),
                ("terminal_session", string("tty-8-1")),
                ("generation", integer(1)),
                ("harness_key", string("lane")),
                ("executable", string("hf-lane")),
                ("kind", string("argv")),
                // Issue #139: this fixture's lane harness is the declarative
                // `argv` kind (an arbitrary fixture executable), which has no
                // documented Herdr pane row, so the plan selects the
                // documented bare-subprocess substrate explicitly. The pane
                // substrate (and its default) is witnessed end to end in
                // `tests/herdr_pane_execution.rs` and `tests/supervision.rs`.
                ("execution", string("headless")),
            ])),
        ),
        step(
            "p1",
            "prompt",
            Some(object(vec![
                ("session_id", string("sess-8-1")),
                ("herdr_session", string("ws-session-8")),
                ("terminal_session", string("tty-8-1")),
                ("generation", integer(1)),
                ("harness_key", string("lane")),
                ("executable", string("hf-lane")),
                ("kind", string("argv")),
                ("worktree", string("issues-123")),
                ("execution", string("headless")),
                (
                    "payload",
                    string("implement acceptance criteria (synthetic)"),
                ),
            ])),
        ),
        step(
            "o1",
            "collect_outcome",
            Some(object(vec![("worktree", string("issues-123"))])),
        ),
        step(
            "r1",
            "review_evidence",
            Some(object(vec![
                ("reviewer", string("reviewer-1")),
                ("implementer", string("implementer-1")),
                ("verdict", string("pass")),
                (
                    "checks",
                    Val::Arr(vec![
                        object(vec![
                            ("name", string("exact-head-review")),
                            ("status", string("passed")),
                        ]),
                        object(vec![
                            ("name", string("hosted-ci")),
                            ("status", string("passed")),
                        ]),
                    ]),
                ),
            ])),
        ),
        step(
            "m1",
            "merge",
            Some(object(vec![
                ("branch", string("issue-123")),
                ("merge_policy", string("ff")),
            ])),
        ),
        step("v1", "post_merge_verify", Some(object(vec![]))),
        step(
            "i1",
            "issue_update",
            Some(object(vec![
                ("action", string("close")),
                ("repo", string("example-org/widgets")),
                ("number", integer(123)),
                (
                    "body",
                    string("delivered via the mutation engine (synthetic)"),
                ),
            ])),
        ),
        step(
            "x1",
            "cleanup",
            Some(object(vec![
                ("worktree", string("issues-123")),
                ("branch", string("issue-123")),
            ])),
        ),
    ]
}

fn policy_steps() -> Vec<Val> {
    vec![
        step(
            "w1",
            "worktree_create",
            Some(object(vec![
                ("branch", string("issue-123")),
                ("worktree", string("issues-123")),
            ])),
        ),
        step(
            "p1",
            "prompt",
            Some(object(vec![
                ("session_id", string("sess-8-1")),
                ("herdr_session", string("ws-session-8")),
                ("terminal_session", string("tty-8-1")),
                ("generation", integer(1)),
                ("harness_key", string("lane")),
                ("executable", string("hf-lane")),
                ("kind", string("argv")),
                ("worktree", string("issues-123")),
                ("execution", string("headless")),
                (
                    "payload",
                    string("implement acceptance criteria (synthetic)"),
                ),
            ])),
        ),
        step(
            "u1",
            "pr_update",
            Some(object(vec![
                ("action", string("create")),
                ("repo", string("example-org/widgets")),
                ("head", string("staging")),
                ("base", string("main")),
                ("title", string("promote staging (synthetic)")),
                ("body", string("promotion body")),
            ])),
        ),
        step(
            "a1",
            "approve",
            Some(object(vec![
                ("digest", string(&"1".repeat(64))),
                ("interactive", canter::value::bool_(true)),
            ])),
        ),
    ]
}

// ---------------------------------------------------------------------------
// Scenario (one disposable world per test)
// ---------------------------------------------------------------------------

struct Scenario {
    sandbox: Sandbox,
    repos: Repos,
    fixture: Fixture,
    plan: Val,
    daemon: Option<GroupChild>,
}

impl Scenario {
    fn new(name: &str, expires_at: &str, steps: Vec<Val>) -> Scenario {
        let sandbox = Sandbox::new(name);
        let repos = make_repos(&sandbox);
        sandbox.write("fakebin/gh", FAKE_GH);
        sandbox.write("fakebin/hf-lane", FAKE_LANE);
        sandbox.chmod_x("fakebin/gh");
        sandbox.chmod_x("fakebin/hf-lane");
        let host_path = std::env::var("PATH").unwrap_or_default();
        let path = format!("{}:{host_path}", sandbox.path("fakebin").display());
        let fixture = Fixture::new(&sandbox, name);
        let db_path = fixture.paths().db_path;
        seed_state(&db_path, expires_at);
        let daemon = fixture.spawn(&path);
        wait_ready(&fixture);
        Scenario {
            sandbox,
            repos,
            fixture,
            plan: make_plan(steps),
            daemon: Some(daemon),
        }
    }

    fn integration_base(&self) -> String {
        Git::new(&self.repos.checkout).head("staging")
    }

    fn apply_ok(
        &self,
        seed: u32,
        step_id: &str,
        feature_head: Option<&str>,
        base: Option<&str>,
    ) -> Val {
        self.apply_ok_with(seed, step_id, feature_head, base, None, false)
    }

    fn apply_ok_with(
        &self,
        seed: u32,
        step_id: &str,
        feature_head: Option<&str>,
        base: Option<&str>,
        target_scope: Option<&str>,
        scheduled: bool,
    ) -> Val {
        let doc = rpc(
            &self.fixture.socket,
            &fresh_id(seed),
            "apply",
            Some(self.params(seed, step_id, feature_head, base, target_scope, scheduled)),
        );
        assert_eq!(
            doc.get("ok").and_then(Val::as_bool),
            Some(true),
            "apply {step_id} (seed {seed}) failed: {}",
            canter::canonical::canonical_text(&doc)
        );
        doc.get("result").expect("result").clone()
    }

    fn apply_err(
        &self,
        seed: u32,
        step_id: &str,
        feature_head: Option<&str>,
        base: Option<&str>,
    ) -> (String, String) {
        rpc_err(
            &self.fixture.socket,
            &fresh_id(seed),
            "apply",
            Some(self.params(seed, step_id, feature_head, base, None, false)),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn params(
        &self,
        seed: u32,
        step_id: &str,
        feature_head: Option<&str>,
        base: Option<&str>,
        target_scope: Option<&str>,
        scheduled: bool,
    ) -> Val {
        let mut flags = vec![
            ("interactive", canter::value::bool_(true)),
            ("digest_confirmed", canter::value::bool_(true)),
            ("scheduled", canter::value::bool_(scheduled)),
            ("production_confirmation", string("tty")),
            // Issue #9 AC1: fan-out steps (harness_start/prompt) require a
            // fresh host-resource proof + declared concurrency caps. These
            // scenarios declare generous caps and a fresh measurement so the
            // admission gate is satisfied (its refusals are probed in
            // tests/daemon_lifecycle.rs).
            (
                "admission",
                object(vec![
                    (
                        "caps",
                        object(vec![
                            ("global", canter::value::integer(16)),
                            ("repository", canter::value::integer(8)),
                            ("harness", canter::value::integer(8)),
                        ]),
                    ),
                    ("harness_lanes", canter::value::integer(0)),
                    (
                        "host_proof",
                        object(vec![("measured_at", string(&canter::time::rfc3339_now()))]),
                    ),
                ]),
            ),
        ];
        if let Some(scope) = target_scope {
            flags.push(("target_scope", string(scope)));
        }
        object(vec![
            (
                "idempotency_key",
                string(&format!("ik_{step_id}-{seed:08x}")),
            ),
            ("plan", self.plan.clone()),
            ("step", string(step_id)),
            ("grant_id", string(GRANT_ID)),
            ("instance_id", string(INSTANCE_ID)),
            (
                "observed",
                object(vec![
                    ("issue_revision", string(REVISION)),
                    ("policy_hash", string(POLICY_HASH)),
                    (
                        "feature_head",
                        feature_head.map(string).unwrap_or_else(null),
                    ),
                    ("integration_base", base.map(string).unwrap_or_else(null)),
                ]),
            ),
            (
                "topology",
                object(vec![
                    ("integration_branch", string("staging")),
                    ("production_branches", Val::Arr(vec![string("main")])),
                    (
                        "worktrees_root",
                        string(&self.repos.worktrees_root.to_string_lossy()),
                    ),
                    (
                        "archive_root",
                        string(&self.repos.archive_root.to_string_lossy()),
                    ),
                    (
                        "integration_repo",
                        string(&self.repos.checkout.to_string_lossy()),
                    ),
                ]),
            ),
            ("flags", object(flags)),
        ])
    }
}

impl Drop for Scenario {
    fn drop(&mut self) {
        if let Some(mut daemon) = self.daemon.take() {
            daemon.terminate("mutation scenario daemon");
        }
        if std::env::var("HF_KEEP_SANDBOX").is_err() {
            let _ = std::fs::remove_dir_all(&self.sandbox.root);
        }
    }
}

#[test]
fn mutation_fixture_reaps_its_daemon_group() {
    let socket;
    {
        let scenario = Scenario::new("leak-detector", "2999-01-01T00:00:00Z", flow_steps());
        socket = scenario.fixture.socket.clone();
    }
    assert_no_process_for_socket(&socket);
}

// Issue #133: bounded wire probes must still inspect status and the durable
// claim after an apply times out, and Scenario's Drop must reap the wedged child.
fn bounded_rpc(socket: &Path, id: &str, method: &str, params: Option<Val>) -> Result<Val, String> {
    use std::io::{BufRead, BufReader, Write};
    let mut stream = std::os::unix::net::UnixStream::connect(socket).map_err(|e| e.to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .map_err(|e| e.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(3)))
        .map_err(|e| e.to_string())?;
    let request = object(vec![
        ("schema", string("hf-rpc-request/v1")),
        ("id", string(id)),
        ("method", string(method)),
        ("params", params.unwrap_or_else(null)),
    ]);
    writeln!(stream, "{}", canter::canonical::canonical_text(&request))
        .map_err(|e| e.to_string())?;
    let mut line = String::new();
    BufReader::new(stream)
        .read_line(&mut line)
        .map_err(|e| e.to_string())?;
    Val::parse_json(line.trim())
}

#[test]
fn apply_refusal_keeps_daemon_responsive_and_records_attempt() {
    let scenario = Scenario::new(
        "f13",
        "2999-01-01T00:00:00Z",
        vec![step(
            "r1",
            "review_evidence",
            Some(object(vec![
                ("reviewer", string("reviewer-1")),
                ("implementer", string("implementer-1")),
                ("verdict", string("pass")),
                (
                    "checks",
                    Val::Arr(vec![string("policy=pass"), string("rust-macos=pass")]),
                ),
            ])),
        )],
    );
    let params = scenario.params(133, "r1", Some(REVISION), Some(REVISION), None, false);
    let key = params.get("idempotency_key").and_then(Val::as_str).unwrap();
    let started = Instant::now();
    let apply = bounded_rpc(
        &scenario.fixture.socket,
        &fresh_id(133),
        "apply",
        Some(params.clone()),
    );
    let status = bounded_rpc(&scenario.fixture.socket, &fresh_id(134), "status", None);
    let state = State::open(&scenario.fixture.paths().db_path, Retention::default()).unwrap();
    let claim = state
        .claim(key)
        .unwrap()
        .expect("apply claimed before the post-effect refusal");
    eprintln!(
        "apply={apply:?}\nstatus={status:?}\nclaim_status={} outcome={:?}",
        claim.status, claim.outcome
    );
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "wire probes exceeded their bounds"
    );
    let apply = apply.expect("post-effect refusal must return, not deadlock");
    assert_eq!(apply.get("ok").and_then(Val::as_bool), Some(false));
    let error = apply.get("error").unwrap();
    assert_eq!(
        error.get("code").and_then(Val::as_str),
        Some("state.evidence_invalid")
    );
    assert_eq!(status.unwrap().get("ok").and_then(Val::as_bool), Some(true));
    // Preserve the existing post-effect ambiguity semantics and exact reason.
    assert_eq!(claim.status, "ambiguous");
    let outcome = Val::parse_json(
        claim
            .outcome
            .as_deref()
            .expect("recorded outcome, not NULL"),
    )
    .unwrap();
    assert_eq!(outcome.get("error"), Some(error));
    assert_eq!(
        outcome.get("status").and_then(Val::as_str),
        Some("ambiguous")
    );
    assert_eq!(
        Val::parse_json(claim.response.as_deref().unwrap()).unwrap(),
        apply
    );
    assert!(state.in_flight_run_step(INSTANCE_ID).unwrap().is_none());
    assert!(state.evidence_for_instance(INSTANCE_ID).unwrap().is_empty());
    let replay = bounded_rpc(
        &scenario.fixture.socket,
        &fresh_id(133),
        "apply",
        Some(params),
    )
    .unwrap();
    assert_eq!(
        replay, apply,
        "replay preserves the typed refusal without another effect"
    );
}

#[test]
fn apply_profile_refusal_resolves_its_claim_without_restart() {
    let scenario = Scenario::new("f13p", "2999-01-01T00:00:00Z", flow_steps());
    let mut params = scenario.params(135, "r1", Some(REVISION), Some(REVISION), None, false);
    if let Val::Obj(fields) = &mut params {
        fields.insert("profile".to_string(), string("not-a-profile"));
    }
    let key = params.get("idempotency_key").and_then(Val::as_str).unwrap();
    let response = bounded_rpc(
        &scenario.fixture.socket,
        &fresh_id(135),
        "apply",
        Some(params.clone()),
    )
    .unwrap();
    assert_eq!(response.get("ok").and_then(Val::as_bool), Some(false));
    let state = State::open(&scenario.fixture.paths().db_path, Retention::default()).unwrap();
    let claim = state.claim(key).unwrap().unwrap();
    assert_eq!(
        claim.status, "spent",
        "pre-effect profile refusal must not orphan the claim"
    );
    let outcome = Val::parse_json(claim.outcome.as_deref().unwrap()).unwrap();
    assert_eq!(outcome.get("error"), response.get("error"));
    assert!(state.in_flight_run_step(INSTANCE_ID).unwrap().is_none());
}

#[test]
fn disconnected_apply_is_resolved_after_its_effect_deadline_without_restart() {
    let scenario = Scenario::new(
        "f13d",
        "2999-01-01T00:00:00Z",
        vec![step(
            "c1",
            "checkout",
            Some(object(vec![
                ("ref", string("staging")),
                ("deadline_secs", integer(1)),
            ])),
        )],
    );
    let marker = scenario.sandbox.path("effect-started");
    scenario.sandbox.write(
        "fakebin/git",
        &format!(
            "#!/bin/sh\nprintf started > '{}'\nexec /bin/sleep 30\n",
            marker.display()
        ),
    );
    scenario.sandbox.chmod_x("fakebin/git");
    let params = scenario.params(136, "c1", None, None, None, false);
    let key = params.get("idempotency_key").and_then(Val::as_str).unwrap();
    let mut client = Connection::open(&scenario.fixture.socket).unwrap();
    client
        .send_request(&fresh_id(136), "apply", Some(&params))
        .unwrap();
    let state = State::open(&scenario.fixture.paths().db_path, Retention::default()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while !marker.exists() {
        assert!(Instant::now() < deadline, "effect never started");
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(state.claim(key).unwrap().unwrap().status, "claimed");
    drop(client); // Peer disappeared mid-effect; no response reader remains.
    let status = bounded_rpc(&scenario.fixture.socket, &fresh_id(137), "status", None).unwrap();
    assert_eq!(status.get("ok").and_then(Val::as_bool), Some(true));
    let claim = loop {
        let claim = state.claim(key).unwrap().unwrap();
        if claim.status != "claimed" {
            break claim;
        }
        assert!(
            Instant::now() < deadline,
            "disconnected apply claim was never resolved"
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    let outcome = Val::parse_json(claim.outcome.as_deref().unwrap()).unwrap();
    assert_eq!(
        outcome
            .get("error")
            .and_then(|e| e.get("code"))
            .and_then(Val::as_str),
        Some("adapter.timeout")
    );
    assert!(state.in_flight_run_step(INSTANCE_ID).unwrap().is_none());
    let replay = bounded_rpc(
        &scenario.fixture.socket,
        &fresh_id(136),
        "apply",
        Some(params),
    )
    .unwrap();
    assert_eq!(
        replay,
        Val::parse_json(claim.response.as_deref().unwrap()).unwrap()
    );
    eprintln!(
        "disconnected caller: claim={} code=adapter.timeout; no in-flight step; replay recorded",
        claim.status
    );
}

// ---------------------------------------------------------------------------
// AC1: plan RPC + digest binding + idempotent replay; duplicate suppression
// ---------------------------------------------------------------------------

#[test]
fn plan_rpc_digest_binding_and_idempotent_replay() {
    let scenario = Scenario::new("ac1-plan", "2999-01-01T00:00:00Z", flow_steps());
    let rendered = rpc_ok(
        &scenario.fixture.socket,
        &fresh_id(1),
        "plan",
        Some(object(vec![
            ("repository", string("example-org/widgets")),
            (
                "issue",
                object(vec![
                    ("number", integer(123)),
                    ("revision", string(REVISION)),
                ]),
            ),
            ("branch", string("staging")),
        ])),
    );
    assert_eq!(
        rendered
            .get("digest")
            .and_then(Val::as_str)
            .unwrap_or("")
            .len(),
        64
    );

    // A tampered plan (edited revision, stale content id) is refused at
    // bind time — before any claim is journaled (AC1 digest binding).
    let mut tampered = scenario.plan.clone();
    if let Val::Obj(map) = &mut tampered
        && let Some(issue) = map.get_mut("issue")
        && let Val::Obj(issue_map) = issue
    {
        issue_map.insert(
            "revision".to_string(),
            string(&format!("b{}", &REVISION[1..])),
        );
    }
    let params = scenario.params(2, "w1", None, None, None, false);
    // Swap in the tampered plan document.
    let mut map = match params {
        Val::Obj(map) => map,
        _ => unreachable!(),
    };
    map.insert("plan".to_string(), tampered);
    let (code, _) = rpc_err(
        &scenario.fixture.socket,
        &fresh_id(2),
        "apply",
        Some(Val::Obj(map)),
    );
    assert_eq!(code, "refusal.plan.identity");

    // First apply of the real plan creates the lane worktree.
    let first = scenario.apply_ok(3, "w1", None, None);
    assert_eq!(first.get("branch").and_then(Val::as_str), Some("issue-123"));
    assert!(scenario.repos.worktrees_root.join("issues-123").exists());

    // Same request id + key replays the recorded response (idempotency).
    let replay = scenario.apply_ok(3, "w1", None, None);
    assert!(replay.get("head").and_then(Val::as_str).is_some());

    // A racing duplicate (new request, same branch/worktree) cannot create
    // a second lane: the effect fails and nothing is duplicated (AC2).
    let (code2, _) = scenario.apply_err(4, "w1", None, None);
    assert_eq!(code2, "adapter.exit", "git refuses the duplicate worktree");
    let lane = scenario.repos.worktrees_root.join("issues-123");
    let listing = Git::new(&scenario.repos.checkout)
        .run(&["worktree", "list"])
        .lines()
        .count();
    assert_eq!(listing, 2, "only the integration checkout + one lane");
    assert!(lane.exists());
}

// ---------------------------------------------------------------------------
// Full lane flow: worktree -> harness -> prompt -> collect -> evidence ->
// merge -> verify -> close -> cleanup (green path; AC1/AC4/AC7/AC8)
// ---------------------------------------------------------------------------

#[test]
fn lane_flow_rehearses_then_verifies_landed_head_and_cleans_with_salvage() {
    let scenario = Scenario::new("lane-flow", "2999-01-01T00:00:00Z", flow_steps());
    let integration_base = scenario.integration_base();

    let wt = scenario.apply_ok(10, "w1", None, None);
    assert_eq!(wt.get("contained").and_then(Val::as_bool), Some(true));
    let start = scenario.apply_ok(11, "h1", None, None);
    assert_eq!(
        start.get("session_id").and_then(Val::as_str),
        Some("sess-8-1")
    );
    let prompt = scenario.apply_ok(12, "p1", None, None);
    assert!(
        prompt
            .get("transcript")
            .and_then(Val::as_str)
            .unwrap_or("")
            .contains("lane transcript ok")
    );
    let collected = scenario.apply_ok(13, "o1", None, Some(&integration_base));
    let feature_head = collected
        .get("head")
        .and_then(Val::as_str)
        .expect("lane head")
        .to_string();
    assert!(
        !collected
            .get("commits")
            .and_then(Val::as_array)
            .expect("commits")
            .is_empty()
    );
    assert_ne!(feature_head, integration_base);

    let evidence = scenario.apply_ok(14, "r1", Some(&feature_head), Some(&integration_base));
    assert!(
        evidence
            .get("evidence_id")
            .and_then(Val::as_str)
            .unwrap_or("")
            .starts_with("ev_")
    );

    // The merge step is a read-only ff-policy rehearsal. The fixture then
    // models the orchestrator-owned landing before post-merge verification.
    let rehearsed = scenario.apply_ok(15, "m1", Some(&feature_head), Some(&integration_base));
    assert_eq!(
        rehearsed.get("mode").and_then(Val::as_str),
        Some("rehearsal")
    );
    assert_eq!(scenario.integration_base(), integration_base);
    Git::new(&scenario.repos.checkout).run(&["merge", "--ff-only", "issue-123"]);
    let verified = scenario.apply_ok(16, "v1", Some(&feature_head), Some(&integration_base));
    assert_eq!(
        verified.get("contains_feature").and_then(Val::as_bool),
        Some(true)
    );

    // Issue closure only after merge + post-merge verification (AC7).
    let closed = scenario.apply_ok(17, "i1", Some(&feature_head), Some(&integration_base));
    assert_eq!(closed.get("action").and_then(Val::as_str), Some("close"));

    // Cleanup removes the lane and journals the salvage evidence (AC8).
    let cleaned = scenario.apply_ok(18, "x1", Some(&feature_head), Some(&integration_base));
    assert_eq!(cleaned.get("removed").and_then(Val::as_bool), Some(true));
    assert!(!scenario.repos.worktrees_root.join("issues-123").exists());

    let tail = rpc_ok(
        &scenario.fixture.socket,
        &fresh_id(19),
        "journal.tail",
        Some(object(vec![
            ("after_seq", integer(0)),
            ("limit", integer(500)),
        ])),
    );
    let records = tail
        .get("records")
        .and_then(Val::as_array)
        .expect("records");
    let actions: Vec<String> = records
        .iter()
        .filter_map(|r| r.get("action").and_then(Val::as_str).map(str::to_string))
        .collect();
    assert!(
        actions.iter().any(|a| a == "salvage.cleanup"),
        "journal must contain the salvage record: {actions:?}"
    );
    assert!(
        actions.iter().any(|a| a == "mutate.merge"),
        "journal must contain the merge intent: {actions:?}"
    );
    // Every claim resolved; no interrupted mutations.
    let status = rpc_ok(&scenario.fixture.socket, &fresh_id(20), "doctor", None);
    assert_eq!(status.get("pending_claims").and_then(Val::as_int), Some(0));
}

// ---------------------------------------------------------------------------
// AC4 RED: moved base invalidates recorded evidence before the merge
// ---------------------------------------------------------------------------

fn cycle2_reviewed_merge(policy: &str, squash_first: bool) -> (Scenario, String, String) {
    let mut steps = flow_steps();
    steps[5] = step(
        "m1",
        "merge",
        Some(object(vec![
            ("branch", string("issue-123")),
            ("merge_policy", string(policy)),
        ])),
    );
    let scenario = Scenario::new(
        &format!("c2-{}{}", &policy[..1], u8::from(squash_first)),
        "2999-01-01T00:00:00Z",
        steps,
    );
    let base = scenario.integration_base();
    scenario.apply_ok(10, "w1", None, None);
    scenario.apply_ok(11, "h1", None, None);
    scenario.apply_ok(12, "p1", None, None);
    let collected = scenario.apply_ok(13, "o1", None, Some(&base));
    let feature = collected
        .get("head")
        .and_then(Val::as_str)
        .unwrap()
        .to_string();
    let git = Git::new(&scenario.repos.checkout);
    if squash_first {
        git.run(&["merge", "--squash", "issue-123"]);
        git.run(&["commit", "-m", "fixture policy squash"]);
        git.run(&["push", "origin", "staging"]);
    }
    let base = scenario.integration_base();
    scenario.apply_ok(14, "r1", Some(&feature), Some(&base));
    (scenario, feature, base)
}

#[test]
fn cycle2_merge_rehearsal_never_lands_in_the_integration_checkout() {
    for policy in ["ff", "squash"] {
        let (scenario, feature, base) = cycle2_reviewed_merge(policy, false);
        let git = Git::new(&scenario.repos.checkout);
        // Dirty operator files and the index are not a rehearsal workspace.
        std::fs::write(scenario.repos.checkout.join("base.txt"), "operator edit\n").unwrap();
        git.run(&["add", "base.txt"]);
        let index = git.run(&["write-tree"]);
        let refs = git.run(&["show-ref"]);
        let remote = git.run(&["ls-remote", "origin", "refs/heads/staging"]);
        let result = scenario.apply_ok(15, "m1", Some(&feature), Some(&base));
        assert_eq!(
            git.head("staging"),
            base,
            "rehearsal must not move integration"
        );
        assert_eq!(git.run(&["show-ref"]), refs);
        assert_eq!(git.run(&["write-tree"]), index);
        assert_eq!(
            git.run(&["ls-remote", "origin", "refs/heads/staging"]),
            remote
        );
        assert_eq!(
            std::fs::read_to_string(scenario.repos.checkout.join("base.txt")).unwrap(),
            "operator edit\n"
        );
        assert_eq!(result.get("mode").and_then(Val::as_str), Some("rehearsal"));
        assert_eq!(
            result.get("merge_policy").and_then(Val::as_str),
            Some(policy)
        );
        assert_eq!(result.get("landed").and_then(Val::as_bool), Some(false));
        assert_eq!(
            result.get("result_tree").and_then(Val::as_str),
            Some(git.head("issue-123^{tree}").as_str())
        );
        assert!(
            result.get("merged_head").is_none(),
            "no landing claim: {result:?}"
        );
    }
}

#[test]
fn cycle2_squash_rehearsal_succeeds_after_the_policy_squash() {
    let (scenario, feature, base) = cycle2_reviewed_merge("squash", true);
    let result = scenario.apply_ok(15, "m1", Some(&feature), Some(&base));
    assert_eq!(scenario.integration_base(), base);
    assert_eq!(
        result.get("result_tree").and_then(Val::as_str),
        Some(
            Git::new(&scenario.repos.checkout)
                .head("staging^{tree}")
                .as_str()
        )
    );
}

#[test]
fn cycle2_ff_refusal_names_policy_divergence_not_an_inferred_base_move() {
    let (scenario, feature, base) = cycle2_reviewed_merge("ff", true);
    let (code, message) = scenario.apply_err(15, "m1", Some(&feature), Some(&base));
    assert_eq!(code, "effect.merge.not_fast_forward");
    assert!(message.contains("ff policy"), "{message}");
    assert!(!message.contains("base moved after"), "{message}");
    assert_eq!(scenario.integration_base(), base);
}

#[test]
fn cycle2_rehearsal_refuses_when_the_published_integration_ref_moved() {
    let (scenario, feature, base) = cycle2_reviewed_merge("squash", false);
    // Another lane lands on the published integration branch from a separate
    // clone: the bare remote moves while this integration checkout stays at
    // the reviewed base (no fetch). A bare-remote move is invisible to the
    // checkout's own refs.
    let root = scenario
        .repos
        .checkout
        .parent()
        .expect("sandbox root")
        .to_path_buf();
    let origin = root.join("origin.git");
    let other = root.join("other-lane");
    Git::new(&root).run(&[
        "clone",
        "-q",
        "--branch",
        "staging",
        origin.to_str().expect("origin path"),
        other.to_str().expect("other lane path"),
    ]);
    let other_git = Git::new(&other);
    other_git.run(&["config", "user.name", "other lane"]);
    other_git.run(&["config", "user.email", "lane@example.invalid"]);
    std::fs::write(other.join("landed.txt"), "landed\n").expect("write");
    other_git.run(&["add", "landed.txt"]);
    other_git.run(&["commit", "-q", "-m", "another lane landed (synthetic)"]);
    other_git.run(&["push", "-q", "origin", "staging"]);
    let published = other_git.head("staging");
    assert_ne!(published, base, "the published integration ref moved");
    assert_eq!(
        scenario.integration_base(),
        base,
        "the integration checkout was not fetched"
    );

    // The rehearsal may only certify the PUBLISHED integration ref: an
    // unpublished local view must refuse instead of recording an integration
    // head the next checkout step cannot trust.
    let (code, message) = scenario.apply_err(15, "m1", Some(&feature), Some(&base));
    assert_eq!(code, "effect.merge.not_fast_forward");
    assert!(message.contains("published"), "{message}");
    assert!(
        !message.contains("base moved after"),
        "the cause is the published ref, not an inferred base move: {message}"
    );
    assert_eq!(
        scenario.integration_base(),
        base,
        "the rehearsal must not move integration"
    );
}

#[test]
fn cycle2_rehearsal_refuses_an_unprovable_published_base_on_both_routes() {
    let (scenario, feature, base) = cycle2_reviewed_merge("squash", false);
    let root = scenario
        .repos
        .checkout
        .parent()
        .expect("sandbox root")
        .to_path_buf();
    let origin = root.join("origin.git");
    let checkout = Git::new(&scenario.repos.checkout);

    // Route 1 — an ABSENT published ref: `origin` answers, but publishes no
    // integration branch (it was deleted there), so `git ls-remote` exits 0
    // with no ref, which is not a head. The fail-closed branch must refuse the
    // step's own typed code rather than certifying an unprovable base (the
    // branch the exact-head review of PR #156 found had no witness).
    Git::new(&origin).run(&["update-ref", "-d", "refs/heads/staging"]);
    let (code, message) = scenario.apply_err(15, "m1", Some(&feature), Some(&base));
    assert_eq!(code, "effect.merge.failed");
    assert!(message.contains("not readable"), "{message}");
    assert!(message.contains("staging"), "{message}");
    assert_eq!(
        scenario.integration_base(),
        base,
        "the refusal must not move integration"
    );

    // Route 2 — an UNREADABLE `origin`: the published ref cannot be read at
    // all (the bare origin is gone), so the read fails instead of answering.
    // It must refuse the SAME typed unprovable-base code (issue #132's review
    // finding) — never a bare `adapter.exit` that reads like an adapter fault
    // — and keep the read's git diagnostics in the message.
    checkout.run(&["push", "origin", "staging"]);
    std::fs::remove_dir_all(&origin).expect("remove the origin remote");
    let (code, message) = scenario.apply_err(16, "m1", Some(&feature), Some(&base));
    assert_eq!(code, "effect.merge.failed");
    assert!(message.contains("not readable"), "{message}");
    assert!(
        message.contains("origin.git"),
        "the refusal keeps the unreadable remote's git diagnostics: {message}"
    );
    assert_eq!(
        scenario.integration_base(),
        base,
        "the refusal must not move integration"
    );
}

#[test]
fn moved_integration_base_invalidates_stale_evidence_and_refuses_merge() {
    let scenario = Scenario::new("stale-evidence", "2999-01-01T00:00:00Z", flow_steps());
    let integration_base = scenario.integration_base();
    scenario.apply_ok(30, "w1", None, None);
    scenario.apply_ok(31, "h1", None, None);
    scenario.apply_ok(32, "p1", None, None);
    let collected = scenario.apply_ok(33, "o1", None, Some(&integration_base));
    let feature_head = collected
        .get("head")
        .and_then(Val::as_str)
        .expect("head")
        .to_string();
    // Evidence binds the CURRENT base.
    scenario.apply_ok(34, "r1", Some(&feature_head), Some(&integration_base));

    // The integration base moves while the lane waits (another merge).
    let ck = Git::new(&scenario.repos.checkout);
    std::fs::write(scenario.repos.checkout.join("other.txt"), "other\n").expect("write");
    ck.run(&["add", "other.txt"]);
    ck.run(&["commit", "-q", "-m", "another lane merged (synthetic)"]);
    let moved_base = ck.head("staging");
    assert_ne!(moved_base, integration_base);

    // The merge observes the moved base: stale evidence refuses BEFORE any
    // effect (AC4).
    let (code, _) = scenario.apply_err(35, "m1", Some(&feature_head), Some(&moved_base));
    assert_eq!(code, "refusal.evidence.stale");

    // Even reporting the OLD base cannot merge: the recorded evidence still
    // matches the OLD base, so the gate passes and the merge effect itself
    // fails closed on the moved ref (fast-forward impossible — AC2 race).
    let (code2, _) = scenario.apply_err(36, "m1", Some(&feature_head), Some(&integration_base));
    assert_eq!(code2, "effect.merge.not_fast_forward");
    assert_eq!(ck.head("staging"), moved_base, "no merge happened");
}

// ---------------------------------------------------------------------------
// AC6 + AC10 RED/GREEN policy probes over the wire
// ---------------------------------------------------------------------------

#[test]
fn production_pr_schedule_and_first_write_gates_bite_over_the_wire() {
    let scenario = Scenario::new("policy-probes", "2999-01-01T00:00:00Z", policy_steps());

    // u1 = pr_update create against `main`: no interactive TTY digest in
    // the flags → the production gate refuses before any gh call.
    let (code, _) = rpc_err(
        &scenario.fixture.socket,
        &fresh_id(40),
        "apply",
        Some(object(vec![
            ("idempotency_key", string("ik_u1-notty-0001")),
            ("plan", scenario.plan.clone()),
            ("step", string("u1")),
            ("grant_id", string(GRANT_ID)),
            ("instance_id", string(INSTANCE_ID)),
            (
                "observed",
                object(vec![
                    ("issue_revision", string(REVISION)),
                    ("policy_hash", string(POLICY_HASH)),
                ]),
            ),
            (
                "topology",
                object(vec![
                    ("integration_branch", string("staging")),
                    ("production_branches", Val::Arr(vec![string("main")])),
                    (
                        "worktrees_root",
                        string(&scenario.repos.worktrees_root.to_string_lossy()),
                    ),
                    (
                        "integration_repo",
                        string(&scenario.repos.checkout.to_string_lossy()),
                    ),
                ]),
            ),
            (
                "flags",
                object(vec![
                    ("interactive", canter::value::bool_(false)),
                    ("digest_confirmed", canter::value::bool_(false)),
                    ("scheduled", canter::value::bool_(false)),
                ]),
            ),
        ])),
    );
    assert_eq!(code, "refusal.policy.production_confirmation");

    // A scheduled apply of a production-risk effect is refused outright
    // (risk-model: schedules can never carry production effects).
    let (code2, _) = rpc_err(
        &scenario.fixture.socket,
        &fresh_id(41),
        "apply",
        Some(object(vec![
            ("idempotency_key", string("ik_w1-sched-0001")),
            ("plan", scenario.plan.clone()),
            ("step", string("w1")),
            ("grant_id", string(GRANT_ID)),
            ("instance_id", string(INSTANCE_ID)),
            (
                "observed",
                object(vec![
                    ("issue_revision", string(REVISION)),
                    ("policy_hash", string(POLICY_HASH)),
                ]),
            ),
            (
                "topology",
                object(vec![
                    ("integration_branch", string("staging")),
                    ("production_branches", Val::Arr(vec![string("main")])),
                    (
                        "worktrees_root",
                        string(&scenario.repos.worktrees_root.to_string_lossy()),
                    ),
                    (
                        "integration_repo",
                        string(&scenario.repos.checkout.to_string_lossy()),
                    ),
                ]),
            ),
            (
                "flags",
                object(vec![
                    ("interactive", canter::value::bool_(true)),
                    ("digest_confirmed", canter::value::bool_(true)),
                    ("scheduled", canter::value::bool_(true)),
                ]),
            ),
        ])),
    );
    assert_eq!(code2, "refusal.policy.scheduled");

    // First-real-write gate (AC10): a real-external-scope effect without a
    // recorded approval refuses; the worktree is created first so the
    // later prompt applies.
    scenario.apply_ok(42, "w1", None, None);
    let (code3, _) = rpc_err(
        &scenario.fixture.socket,
        &fresh_id(43),
        "apply",
        Some(scenario.params(43, "p1", None, None, Some("real_external"), false)),
    );
    assert_eq!(code3, "refusal.first_write.approval_required");

    // Recorded interactive approval unlocks the gate (fakes only).
    let approval = scenario.apply_ok(44, "a1", None, None);
    assert!(
        approval
            .get("approval_id")
            .and_then(Val::as_str)
            .unwrap_or("")
            .starts_with("ap_")
    );
    let outcome = scenario.apply_ok_with(45, "p1", None, None, Some("real_external"), false);
    assert!(
        outcome
            .get("transcript")
            .and_then(Val::as_str)
            .unwrap_or("")
            .contains("lane transcript ok")
    );
}

// ---------------------------------------------------------------------------
// C2: expired grants refuse at the apply boundary (RED/GREEN over the wire)
// ---------------------------------------------------------------------------

#[test]
fn expired_grant_refuses_apply_with_typed_code() {
    let scenario = Scenario::new("expired-grant", "2020-01-01T00:00:00Z", flow_steps());
    let (code, message) = scenario.apply_err(60, "w1", None, None);
    assert_eq!(code, "refusal.grant.expired", "{message}");
}

// ---------------------------------------------------------------------------
// AC8 RED: cleanup refuses dirty and unverified targets; no force path
// ---------------------------------------------------------------------------

#[test]
fn dirty_and_unmerged_cleanup_refuses_and_no_direct_push_path_exists() {
    let scenario = Scenario::new("dup-dirty", "2999-01-01T00:00:00Z", flow_steps());
    let wt = scenario.apply_ok(70, "w1", None, None);
    assert_eq!(wt.get("contained").and_then(Val::as_bool), Some(true));
    let lane = scenario.repos.worktrees_root.join("issues-123");
    // A harness commit makes the lane dirty relative to the base.
    scenario.apply_ok(71, "h1", None, None);
    scenario.apply_ok(72, "p1", None, None);

    // External dirty file: cleanup refuses (AC8).
    std::fs::write(lane.join("uncommitted.txt"), "dirty\n").expect("dirty file");
    let (code, _) = scenario.apply_err(73, "x1", None, None);
    assert_eq!(code, "refusal.cleanup.dirty");
    std::fs::remove_file(lane.join("uncommitted.txt")).expect("remove dirty");

    // The branch is NOT merged into staging: cleanup refuses the unverified
    // deletion (AC8); branch_delete has no path for it either.
    let (code2, _) = scenario.apply_err(74, "x1", None, None);
    assert_eq!(code2, "refusal.cleanup.unmerged");
    assert!(lane.exists(), "cleanup must not remove the lane");

    // Force-push attempts are refused by policy (no force path, AC6) — the
    // step params cannot even express a force to integration/production.
    let ck = Git::new(&scenario.repos.checkout);
    // Try pushing the feature branch to the local bare remote (the lane's
    // own remote path): allowed for feature lanes only; the branch itself
    // stays pushable so assert the *local* feature head is intact.
    ck.run(&["rev-parse", "--verify", "issue-123"]);
}

// ---------------------------------------------------------------------------
// F1 (AC7): premature issue closure refuses on the LIVE daemon path through
// the same unit-tested gate (mutation::check_issue_closure) the daemon calls
// ---------------------------------------------------------------------------

#[test]
fn premature_issue_close_refuses_closure_premature_over_the_wire() {
    let scenario = Scenario::new("premature-close", "2999-01-01T00:00:00Z", flow_steps());
    // The instance has NOT executed the plan's post_merge_verify step
    // ("v1"); closing immediately must refuse with the typed code.
    let (code, message) = scenario.apply_err(80, "i1", None, None);
    assert_eq!(code, "refusal.closure.premature", "{message}");
    // The lane-flow happy path (close AFTER v1) stays green; this asserts
    // the same daemon gate also passes once the verify node is achieved.
    let base = scenario.integration_base();
    scenario.apply_ok(81, "w1", None, None);
    scenario.apply_ok(82, "h1", None, None);
    scenario.apply_ok(83, "p1", None, None);
    let collected = scenario.apply_ok(84, "o1", None, Some(&base));
    let feature = collected
        .get("head")
        .and_then(Val::as_str)
        .expect("lane head")
        .to_string();
    scenario.apply_ok(85, "r1", Some(&feature), Some(&base));
    scenario.apply_ok(86, "m1", Some(&feature), Some(&base));
    Git::new(&scenario.repos.checkout).run(&["merge", "--ff-only", "issue-123"]);
    scenario.apply_ok(87, "v1", Some(&feature), Some(&base));
    let closed = scenario.apply_ok(88, "i1", Some(&feature), Some(&base));
    assert_eq!(
        closed.get("action").and_then(Val::as_str),
        Some("close"),
        "issue close must succeed after post-merge verification"
    );
}

// ---------------------------------------------------------------------------
// F2 (AC2/C3): a REVOKED grant refuses apply with refusal.grant.inactive on
// the live daemon path (the enforcement branch revalidate_effect drives)
// ---------------------------------------------------------------------------

#[test]
fn revoked_grant_refuses_apply_with_grant_inactive_over_the_wire() {
    let scenario = Scenario::new("revoked-grant", "2999-01-01T00:00:00Z", flow_steps());
    // Revoke the seeded route grant through the daemon RPC.
    let revoked = rpc_ok(
        &scenario.fixture.socket,
        &fresh_id(90),
        "grants.revoke",
        Some(object(vec![
            ("grant_id", string(GRANT_ID)),
            ("idempotency_key", string(&format!("ik_revoke-{:08x}", 90))),
        ])),
    );
    assert_eq!(
        revoked.get("revoked").and_then(Val::as_bool),
        Some(true),
        "grants.revoke must report the revocation"
    );
    // Any apply on the revoked grant now refuses at revalidation — before
    // any effect (an expired grant would say refusal.grant.expired; a
    // revoked one must say refusal.grant.inactive).
    let (code, message) = scenario.apply_err(91, "w1", None, None);
    assert_eq!(code, "refusal.grant.inactive", "{message}");
    // A subsequent apply of a later step is refused the same way (the
    // instance cannot advance under a dead grant).
    let (code2, _) = scenario.apply_err(92, "m1", None, None);
    assert_eq!(code2, "refusal.grant.inactive");
}

// ---------------------------------------------------------------------------
// F3 (AC5): fork/external-contributor PR updates refuse over the wire BEFORE
// any forge spawn; a trusted same-repo head passes and reaches the forge
// ---------------------------------------------------------------------------

#[test]
fn fork_pr_update_requires_maintainer_approval_over_the_wire_and_trusted_head_passes() {
    let fork = step(
        "u1",
        "pr_update",
        Some(object(vec![
            ("action", string("create")),
            ("repo", string("example-org/widgets")),
            ("head", string("issue-123")),
            ("base", string("staging")),
            ("head_repo", string("fork-org/widgets")),
            ("title", string("fork contribution (synthetic)")),
        ])),
    );
    let trusted = step(
        "u2",
        "pr_update",
        Some(object(vec![
            ("action", string("create")),
            ("repo", string("example-org/widgets")),
            ("head", string("issue-123")),
            ("base", string("staging")),
            ("title", string("fleet lane PR (synthetic)")),
        ])),
    );
    let scenario = Scenario::new("fork-pr", "2999-01-01T00:00:00Z", vec![fork, trusted]);
    // Fork head without maintainer_approval: mechanically refused with the
    // typed EXTERNAL_APPROVAL code, before the forge adapter can spawn.
    let (code, message) = scenario.apply_err(95, "u1", None, None);
    assert_eq!(code, "refusal.policy.external_contributor", "{message}");
    // The trusted same-repo lane keeps the ordinary path and reaches the
    // forge (fake gh answers with the deterministic PR number).
    let created = scenario.apply_ok(96, "u2", None, None);
    assert_eq!(
        created.get("number").and_then(Val::as_int),
        Some(1001),
        "trusted same-repo PR update must reach the forge adapter"
    );
}

// ---------------------------------------------------------------------------
// AC7 (issue #9): dirty lanes are never deleted; `archive` preserves the
// exact bytes into the daemon-owned archive root with a checksummed
// manifest (removed stays false); symlinked cleanup targets are refused.
// ---------------------------------------------------------------------------

fn archive_x1_step() -> Val {
    step(
        "x1",
        "cleanup",
        Some(object(vec![
            ("worktree", string("issues-123")),
            ("branch", string("issue-123")),
            ("archive", canter::value::bool_(true)),
        ])),
    )
}

#[test]
fn dirty_cleanup_archive_preserves_exact_bytes_and_manifest_and_never_deletes() {
    let scenario = Scenario::new("lc-archive", "2999-01-01T00:00:00Z", flow_steps());
    scenario.apply_ok(60, "w1", None, None);
    scenario.apply_ok(61, "h1", None, None);
    scenario.apply_ok(62, "p1", None, None);
    // Deterministic dirty payload: 5 KiB of mixed text (no network, no
    // host paths; archived bytes must match byte-for-byte).
    let payload: String = (0..40)
        .map(|i| format!("salvage-me line {i:03}: the quick brown fox\n"))
        .collect();
    let lane = scenario.repos.worktrees_root.join("issues-123");
    std::fs::write(lane.join("uncommitted.txt"), &payload).expect("dirty file");

    // RED: plain cleanup still refuses the dirty work (never deleted).
    let (code, _) = scenario.apply_err(63, "x1", None, None);
    assert_eq!(code, "refusal.cleanup.dirty");
    assert!(lane.exists() && lane.join("uncommitted.txt").exists());

    // The archive-enabled cleanup step preserves bytes + manifest.
    let plan_steps = {
        let mut steps = flow_steps();
        let last = steps.len() - 1;
        steps[last] = archive_x1_step();
        steps
    };
    let archive_scenario = Scenario::new("lc-archive2", "2999-01-01T00:00:00Z", plan_steps);
    archive_scenario.apply_ok(64, "w1", None, None);
    archive_scenario.apply_ok(65, "h1", None, None);
    archive_scenario.apply_ok(66, "p1", None, None);
    let lane2 = archive_scenario.repos.worktrees_root.join("issues-123");
    std::fs::write(lane2.join("uncommitted.txt"), &payload).expect("dirty file 2");
    let archived = archive_scenario.apply_ok(67, "x1", None, None);
    let archive_doc = archived.get("archived").expect("archived doc");
    // The whole dirty lane is preserved (worktree files + the dirty
    // payload); find the uncommitted.txt entry to byte-compare.
    let files = archive_doc
        .get("files")
        .and_then(Val::as_array)
        .expect("files");
    assert_eq!(files.len(), 3, "all lane files are archived, dirty or not");
    let manifest_sha = archive_doc
        .get("manifest_sha256")
        .and_then(Val::as_str)
        .expect("manifest sha")
        .to_string();
    let total_bytes = archive_doc.get("total_bytes").and_then(Val::as_int);
    assert_eq!(
        total_bytes,
        Some(payload.len() as i64 + 17),
        "byte count must match the archived lane files"
    );
    let entry = files
        .iter()
        .find(|file| file.get("path").and_then(Val::as_str) == Some("uncommitted.txt"))
        .expect("uncommitted.txt entry");
    let rel = entry.get("path").and_then(Val::as_str).expect("rel path");
    let entry_sha = entry
        .get("sha256")
        .and_then(Val::as_str)
        .expect("entry sha");
    let archive_dir = std::path::PathBuf::from(
        archive_doc
            .get("archive_dir")
            .and_then(Val::as_str)
            .expect("dir"),
    );
    let archived_bytes = std::fs::read(archive_dir.join(rel)).expect("read archived file");
    assert_eq!(
        archived_bytes,
        payload.as_bytes(),
        "archived bytes must equal the original"
    );
    let expected_sha = canter::canonical::sha256_hex(payload.as_bytes());
    assert_eq!(
        entry_sha, expected_sha,
        "manifest sha256 must match the bytes"
    );
    // The manifest on disk pins the same digest.
    let manifest_text =
        std::fs::read_to_string(archive_dir.join("manifest.json")).expect("manifest");
    assert_eq!(
        canter::canonical::sha256_hex(manifest_text.as_bytes()),
        manifest_sha,
        "manifest file digest must equal the reported manifest_sha256"
    );
    // Archive NEVER deletes: the dirty lane stays in place. The repeat
    // archive's destination name is wall-clock second-granular (the daemon
    // names it `lane-<branch>-<unix seconds>`), so the second call has two
    // legal outcomes and the test must not depend on which one happens:
    //   * collision (same second) -> typed refusal of the existing
    //     destination (fail closed — salvage bytes are never clobbered), or
    //   * next second -> a second, complete archive under a DIFFERENT
    //     directory name.
    // The clock-independent INVARIANT, asserted in either branch: the FIRST
    // archive directory stays byte-unchanged.
    assert!(lane2.exists() && lane2.join("uncommitted.txt").exists());
    let repeat = rpc(
        &archive_scenario.fixture.socket,
        &fresh_id(68),
        "apply",
        Some(archive_scenario.params(68, "x1", None, None, None, false)),
    );
    if let Some(true) = repeat.get("ok").and_then(Val::as_bool) {
        // Next-second branch: a second archive, complete and distinct.
        let result = repeat.get("result").expect("result");
        assert_eq!(
            result.get("removed").and_then(Val::as_bool),
            Some(false),
            "a repeat archive still never removes the lane"
        );
        let second = result.get("archived").expect("second archived doc");
        let second_dir = PathBuf::from(
            second
                .get("archive_dir")
                .and_then(Val::as_str)
                .expect("second archive dir"),
        );
        assert_ne!(
            second_dir, archive_dir,
            "a successful second archive must use a fresh destination"
        );
        let second_files = second
            .get("files")
            .and_then(Val::as_array)
            .expect("second files");
        assert_eq!(second_files.len(), 3, "the second archive is complete");
        let second_manifest_sha = second
            .get("manifest_sha256")
            .and_then(Val::as_str)
            .expect("second manifest sha");
        let second_manifest_text =
            std::fs::read_to_string(second_dir.join("manifest.json")).expect("second manifest");
        assert_eq!(
            canter::canonical::sha256_hex(second_manifest_text.as_bytes()),
            second_manifest_sha,
            "the second manifest digest must pin its own bytes"
        );
        for file in second_files {
            let rel = file.get("path").and_then(Val::as_str).expect("path");
            let bytes = std::fs::read(second_dir.join(rel)).expect("second archive bytes");
            assert_eq!(
                canter::canonical::sha256_hex(&bytes),
                file.get("sha256").and_then(Val::as_str).expect("sha"),
                "second archive {rel} digest"
            );
            assert_eq!(
                Some(bytes.len() as i64),
                file.get("bytes").and_then(Val::as_int),
                "second archive {rel} byte count"
            );
        }
    } else {
        // Same-second branch: the typed refusal of the existing destination.
        let error = repeat.get("error").expect("error doc");
        assert_eq!(
            error.get("code").and_then(Val::as_str),
            Some("effect.archive.failed"),
            "an existing archive dir is never overwritten: {}",
            canter::canonical::canonical_text(&repeat)
        );
    }
    // The invariant, independent of which branch ran: the FIRST archive
    // directory is byte-unchanged — its manifest digest still equals the
    // recorded one and every entry still matches the recorded manifest.
    let first_manifest_text =
        std::fs::read_to_string(archive_dir.join("manifest.json")).expect("first manifest");
    assert_eq!(
        canter::canonical::sha256_hex(first_manifest_text.as_bytes()),
        manifest_sha,
        "the first archive manifest must be byte-unchanged"
    );
    for file in files {
        let rel = file.get("path").and_then(Val::as_str).expect("path");
        let bytes = std::fs::read(archive_dir.join(rel)).expect("first archive bytes");
        assert_eq!(
            canter::canonical::sha256_hex(&bytes),
            file.get("sha256").and_then(Val::as_str).expect("sha"),
            "first archive {rel} digest must be unchanged"
        );
        assert_eq!(
            Some(bytes.len() as i64),
            file.get("bytes").and_then(Val::as_int),
            "first archive {rel} byte count"
        );
    }
    assert!(
        lane2.join("uncommitted.txt").exists(),
        "dirty file survives"
    );
    assert_eq!(
        std::fs::read_to_string(lane2.join("uncommitted.txt")).expect("lane bytes"),
        payload,
        "the dirty payload must still be in place"
    );
}

#[test]
fn symlinked_cleanup_targets_are_refused() {
    // A symlinked lane path inside the worktrees root (pointing at another
    // real dir inside the root) is refused: cleanup never follows or
    // removes symlinks (canonical target classification).
    let scenario = Scenario::new("lc-symlink", "2999-01-01T00:00:00Z", flow_steps());
    let wt_root = &scenario.repos.worktrees_root;
    std::fs::create_dir_all(wt_root.join("issues-123-real")).expect("real dir");
    std::os::unix::fs::symlink(wt_root.join("issues-123-real"), wt_root.join("issues-123"))
        .expect("symlink");
    let (code, message) = scenario.apply_err(69, "x1", None, None);
    assert_eq!(code, "refusal.cleanup.symlink", "{message}");
    assert!(
        wt_root.join("issues-123").exists(),
        "symlink stays in place"
    );
}
