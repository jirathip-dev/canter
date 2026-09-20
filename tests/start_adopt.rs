//! Issue #76 acceptance integration tests over the real binary and socket:
//! ONE bounded daemon-coordinated start/adopt transition through the
//! existing adapter and admission paths — a FRESH successor session on the
//! SAME logical lane/worktree (never a transcript replay), one
//! generation/nonce owning startup, adapter-observed verification of the
//! fresh session identity/role/profile/cwd/kickoff receipt/readiness, an
//! adoption re-query compared against the recorded handoff state
//! (differences reconcile, they are never blind-replayed or stale
//! PASS-reused), exactly-once completion consumption after adoption, the
//! PAUSED fence between transitions, and the restart reconciliation that
//! re-derives the startup nonce and the process evidence before any retry.
//!
//! Every test spawns `canter daemon run` as a child process with
//! isolated XDG state and an explicit socket under a per-test temp dir. The
//! workspace executable the start/adopt paths drive is a fake `herdr`
//! recorded in a per-fixture invocation log, on a PATH that contains
//! nothing else (the allowlisted adapter environment is the only channel).
//! Nothing here touches the real host state, a real session, the service
//! manager, or the network; all identities are synthetic.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use canter::client::{Connection, RpcError};
use canter::value::{Val, bool_, integer, null, object, string};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_canter")
}

/// Default per-test daemon readiness deadline.
const READY_TIMEOUT: Duration = Duration::from_secs(20);

/// The fake workspace executable's session rows need a shell utility path of
/// their own: the daemon passes an allowlisted environment, so the script
/// sets PATH explicitly and only ever uses /usr/bin and /bin tools.
///
/// `$HOME/workspace-mode` selects the successor behavior; `$HOME/source-mode`
/// selects the source session behavior. The successor confirmation document
/// is the closed verification grammar the new path reads.
const FAKE_WORKSPACE: &str = r#"#!/bin/sh
PATH=/usr/bin:/bin
log="$HOME/workspace-invocations.log"
printf '%s\n' "$*" >> "$log"
mode="$(cat "$HOME/workspace-mode" 2>/dev/null || echo ready)"
case "$1 $2" in
  "session interrupt")
    printf '%s\n' '{"interrupted":true}' ;;
  "session start")
    case "$mode" in
      start-fail) echo '{"error":"refused"}' >&2; exit 3 ;;
      *) printf '%s\n' '{"started":true}' ;;
    esac ;;
  "session show")
    if [ "$mode" = "vanish-after-show" ]; then
      rm -f "$0"
    fi
    if [ "$3" = "sess-0001" ]; then
      src="$(cat "$HOME/source-mode" 2>/dev/null || echo retired)"
      case "$src" in
        live) doc='{"session_id":"sess-0001","state":"working","process":"proc-0001","registration":{"state":"active","session":"sess-0001","generation":1}}' ;;
        reused-source) doc='{"session_id":"sess-0001","state":"working","process":"proc-0009","registration":{"state":"released","session":"sess-0001","generation":1}}' ;;
        *) doc='{"session_id":"sess-0001","state":"retired","process":null,"registration":{"state":"released","session":"sess-0001","generation":1}}' ;;
      esac
    else
      case "$mode" in
        ready) doc='{"session_id":"sess-0002","state":"working","process":"proc-0002","role":"implementer","profile":{"key":"lane-orch-1","kind":"pi"},"cwd":"worktrees/issues/76","kickoff_receipt":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","readiness":"ready"}' ;;
        orchestrator) doc='{"session_id":"sess-0002","state":"working","process":"proc-0002","role":"orchestrator","profile":{"key":"lane-orch-1","kind":"pi"},"cwd":"worktrees/issues/76","kickoff_receipt":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","readiness":"ready"}' ;;
        not-ready) doc='{"session_id":"sess-0002","state":"starting","process":"proc-0002","role":"implementer","profile":{"key":"lane-orch-1","kind":"pi"},"cwd":"worktrees/issues/76","kickoff_receipt":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","readiness":"starting"}' ;;
        no-role) doc='{"session_id":"sess-0002","process":"proc-0002","profile":{"key":"lane-orch-1","kind":"pi"},"cwd":"worktrees/issues/76","kickoff_receipt":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","readiness":"ready"}' ;;
        no-cwd) doc='{"session_id":"sess-0002","process":"proc-0002","role":"implementer","profile":{"key":"lane-orch-1","kind":"pi"},"kickoff_receipt":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","readiness":"ready"}' ;;
        wrong-cwd) doc='{"session_id":"sess-0002","process":"proc-0002","role":"implementer","profile":{"key":"lane-orch-1","kind":"pi"},"cwd":"worktrees/issues/96","kickoff_receipt":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","readiness":"ready"}' ;;
        no-kickoff) doc='{"session_id":"sess-0002","process":"proc-0002","role":"implementer","profile":{"key":"lane-orch-1","kind":"pi"},"cwd":"worktrees/issues/76","readiness":"ready"}' ;;
        no-process) doc='{"session_id":"sess-0002","role":"implementer","profile":{"key":"lane-orch-1","kind":"pi"},"cwd":"worktrees/issues/76","kickoff_receipt":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","readiness":"ready"}' ;;
        proc-only) doc='{"session_id":"sess-0002","process":"proc-0002"}' ;;
        reused-process) doc='{"session_id":"sess-0002","process":"proc-0001","role":"implementer","profile":{"key":"lane-orch-1","kind":"pi"},"cwd":"worktrees/issues/76","kickoff_receipt":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","readiness":"ready"}' ;;
        malformed) doc='not-json' ;;
        *) doc='{"session_id":"sess-0002","state":"working","process":"proc-0002","role":"implementer","profile":{"key":"lane-orch-1","kind":"pi"},"cwd":"worktrees/issues/76","kickoff_receipt":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","readiness":"ready"}' ;;
      esac
    fi
    printf '%s\n' "$doc" ;;
  *) echo '{"error":"unknown row"}' >&2; exit 4 ;;
esac
"#;

struct Fixture {
    dir: PathBuf,
    state_dir: PathBuf,
    socket: PathBuf,
}

impl Fixture {
    fn new(name: &str) -> Fixture {
        let dir = std::env::temp_dir().join(format!("hf-sa-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("fixture dir");
        Fixture {
            state_dir: dir.join("state"),
            socket: dir.join("daemon.sock"),
            dir,
        }
    }

    fn daemon_log(&self) -> PathBuf {
        self.state_dir.join("canter").join("daemon.log")
    }

    fn bin_dir(&self) -> PathBuf {
        self.dir.join("bin")
    }

    fn invocations_log(&self) -> PathBuf {
        self.dir.join("workspace-invocations.log")
    }

    /// Every workspace (fake `herdr`) invocation recorded so far, in order.
    fn invocations(&self) -> Vec<String> {
        std::fs::read_to_string(self.invocations_log())
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect()
    }

    /// Select the fake workspace behavior (and let the test switch it
    /// between a crash and the restart that reconciles it).
    fn set_mode(&self, mode: &str) {
        std::fs::write(self.dir.join("workspace-mode"), format!("{mode}\n"))
            .expect("write workspace mode");
    }

    fn set_source_mode(&self, mode: &str) {
        std::fs::write(self.dir.join("source-mode"), format!("{mode}\n"))
            .expect("write source mode");
    }

    fn write_fake_workspace(&self) {
        let bin_dir = self.bin_dir();
        std::fs::create_dir_all(&bin_dir).expect("bin dir");
        let path = bin_dir.join("herdr");
        std::fs::write(&path, FAKE_WORKSPACE).expect("write fake workspace");
        let mut permissions = std::fs::metadata(&path).expect("metadata").permissions();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            permissions.set_mode(0o755);
        }
        std::fs::set_permissions(&path, permissions).expect("chmod");
    }

    /// Spawn the daemon with the fake workspace executable as the only
    /// `herdr` on PATH.
    fn spawn(&self, crash_point: Option<&str>) -> Child {
        let mut command = Command::new(bin());
        let stderr_path = self.dir.join("daemon.stderr.log");
        let stderr_file = std::fs::File::create(&stderr_path).expect("stderr log");
        command
            .args(["daemon", "run", "--socket"])
            .arg(&self.socket)
            .env("XDG_STATE_HOME", &self.state_dir)
            .env("HOME", &self.dir)
            .env("PATH", self.bin_dir())
            .stdout(Stdio::null())
            .stderr(Stdio::from(stderr_file));
        if let Some(point) = crash_point {
            command.env("CANTER_CRASH_POINT", point);
        }
        command.spawn().expect("spawn daemon")
    }
}

fn wait_ready(fixture: &Fixture) {
    let deadline = Instant::now() + READY_TIMEOUT;
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
        "daemon did not become ready on {}; stderr:\n{}",
        fixture.socket.display(),
        stderr_text
    );
}

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

/// Issue one request that may be cut short by an injected daemon crash:
/// connection failures are tolerated (the crash point aborts the daemon
/// before a response).
fn rpc_unchecked(socket: &Path, id: &str, method: &str, params: Option<Val>) {
    let Ok(mut connection) = Connection::open(socket) else {
        return;
    };
    if connection
        .send_request(id, method, params.as_ref())
        .is_err()
    {
        return;
    }
    let _ = connection.read_response();
}

fn rpc_ok(socket: &Path, id: &str, method: &str, params: Option<Val>) -> Val {
    let doc = rpc(socket, id, method, params);
    assert_eq!(
        doc.get("ok").and_then(Val::as_bool),
        Some(true),
        "expected ok response for {method}: {}",
        canter::canonical::canonical_text(&doc)
    );
    doc.get("result").expect("result").clone()
}

fn rpc_err(socket: &Path, id: &str, method: &str, params: Option<Val>) -> (String, String) {
    let doc = rpc(socket, id, method, params);
    assert_eq!(
        doc.get("ok").and_then(Val::as_bool),
        Some(false),
        "expected refused response for {method}: {}",
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

fn wait_exit(mut child: Child, label: &str) {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if child.try_wait().expect("try_wait").is_some() {
            return;
        }
        assert!(Instant::now() < deadline, "{label} did not exit in time");
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn shutdown(mut daemon: Child) {
    let _ = daemon.kill();
    wait_exit(daemon, "daemon");
}

/// Wait until the daemon process exits (the crash point abort).
fn wait_crash(daemon: &mut Child) {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Some(_status) = daemon.try_wait().expect("try_wait") {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "the daemon did not reach the crash point in time"
        );
        std::thread::sleep(Duration::from_millis(25));
    }
}

// ---------------------------------------------------------------------------
// Synthetic request builders (public-data boundary: no host paths)
// ---------------------------------------------------------------------------

const WORKTREE: &str = "worktrees/issues/76";
const SOURCE_SESSION: &str = "sess-0001";
const SOURCE_PROCESS: &str = "proc-0001";
const SUCCESSOR_SESSION: &str = "sess-0002";
const HEAD: &str = "1111111111111111111111111111111111111111";
const BASE: &str = "2222222222222222222222222222222222222222";
const REVIEWED_SHA: &str = "5555555555555555555555555555555555555555";

fn kickoff_receipt() -> String {
    "a".repeat(64)
}

fn replacement_params(lane: &str, role: &str, key: &str) -> Val {
    object(vec![
        ("idempotency_key", string(key)),
        ("lane_id", string(lane)),
        ("generation", integer(1)),
        ("source_session", string(SOURCE_SESSION)),
        ("source_process", string(SOURCE_PROCESS)),
        ("role", string(role)),
        ("worktree", string(WORKTREE)),
        ("reason", string("handoff start/adopt window")),
    ])
}

/// A valid synthetic checkpoint observation for one lane; `orchestration`
/// adds the orchestrator reference block when supplied.
fn observation(role: &str, orchestration: Option<Val>) -> Val {
    let mut fields = vec![
        ("role", string(role)),
        ("task", string("issue-76 start adoption capture")),
        ("worktree", string(WORKTREE)),
        ("branch", string("issue-76-start-adopt")),
        ("head", string(HEAD)),
        ("base", string(BASE)),
        (
            "dirty",
            object(vec![
                ("count", integer(1)),
                ("digest", string(&"c".repeat(64))),
            ]),
        ),
        (
            "untracked",
            object(vec![
                ("count", integer(0)),
                ("digest", string(&"d".repeat(64))),
            ]),
        ),
        (
            "report",
            object(vec![
                ("round", integer(1)),
                ("reviewed_sha", string(REVIEWED_SHA)),
            ]),
        ),
        (
            "gates",
            Val::Arr(vec![object(vec![
                ("name", string("focused")),
                ("status", string("passed")),
            ])]),
        ),
        (
            "children",
            Val::Arr(vec![object(vec![
                ("command", string("cargo test --locked")),
                ("state", string("exited")),
            ])]),
        ),
        (
            "execution",
            object(vec![("active", bool_(false)), ("ack", null())]),
        ),
    ];
    if let Some(orchestration) = orchestration {
        fields.push(("orchestration", orchestration));
    }
    object(fields)
}

/// The fresh adoption re-query: the closed comparison contract (the
/// capture-only `execution`/`orchestration` blocks are not part of it).
fn adoption_fields(role: &str) -> Vec<(&'static str, Val)> {
    let capture = observation(role, None);
    let mut fields: Vec<(&'static str, Val)> = vec![];
    for key in [
        "role",
        "task",
        "worktree",
        "branch",
        "head",
        "base",
        "dirty",
        "untracked",
        "report",
        "gates",
        "children",
    ] {
        fields.push((key, capture.get(key).expect("field").clone()));
    }
    fields
}

fn adoption_observation(role: &str) -> Val {
    object(adoption_fields(role))
}

fn with_field(role: &str, key: &str, value: Val) -> Val {
    let mut fields = adoption_fields(role);
    let mut replaced = false;
    for (existing, current) in fields.iter_mut() {
        if *existing == key {
            *current = value.clone();
            replaced = true;
        }
    }
    assert!(
        replaced,
        "the variant field {key} must exist in the re-query"
    );
    object(fields)
}

fn orchestration(workers: &[&str], reviewers: &[&str]) -> Val {
    object(vec![
        (
            "workers",
            Val::Arr(workers.iter().map(|id| string(id)).collect()),
        ),
        (
            "reviewers",
            Val::Arr(reviewers.iter().map(|id| string(id)).collect()),
        ),
        (
            "pending_events",
            Val::Arr(vec![string("worker-finished:lane-8")]),
        ),
    ])
}

fn replacement_of(result: &Val) -> &Val {
    result.get("replacement").expect("replacement")
}

fn retirement_of(result: &Val) -> &Val {
    result.get("retirement").expect("retirement")
}

fn start_of(result: &Val) -> &Val {
    result.get("start").expect("start")
}

fn adoption_of(result: &Val) -> &Val {
    result.get("adoption").expect("adoption")
}

fn successor_of(result: &Val) -> &Val {
    result.get("successor").expect("successor")
}

fn field_str<'a>(val: &'a Val, key: &str) -> &'a str {
    val.get(key).and_then(Val::as_str).expect(key)
}

fn field_int(val: &Val, key: &str) -> i64 {
    val.get(key).and_then(Val::as_int).expect(key)
}

fn request_replacement(socket: &Path, id_seed: u32, lane: &str, role: &str, key: &str) -> String {
    let result = rpc_ok(
        socket,
        &fresh_id(id_seed),
        "lane.replacement.request",
        Some(replacement_params(lane, role, key)),
    );
    field_str(replacement_of(&result), "replacement_id").to_string()
}

fn advance_to_quiescing(socket: &Path, id_seed: u32, replacement_id: &str, key: &str) -> Val {
    rpc_ok(
        socket,
        &fresh_id(id_seed),
        "lane.replacement.advance",
        Some(object(vec![
            ("idempotency_key", string(key)),
            ("replacement_id", string(replacement_id)),
            ("expected_phase", string("requested")),
            ("generation", integer(1)),
        ])),
    )
}

fn capture_checkpoint(
    socket: &Path,
    id_seed: u32,
    replacement_id: &str,
    role: &str,
    orchestration: Option<Val>,
    key: &str,
) -> String {
    let observation = observation(role, orchestration);
    let result = rpc_ok(
        socket,
        &fresh_id(id_seed),
        "lane.checkpoint.create",
        Some(object(vec![
            ("idempotency_key", string(key)),
            ("replacement_id", string(replacement_id)),
            ("generation", integer(1)),
            ("observation", observation.clone()),
            ("reobservation", observation),
        ])),
    );
    field_str(result.get("checkpoint").expect("checkpoint"), "digest").to_string()
}

fn status_of(socket: &Path, id_seed: u32, replacement_id: &str) -> Val {
    rpc_ok(
        socket,
        &fresh_id(id_seed),
        "lane.replacement.status",
        Some(object(vec![("replacement_id", string(replacement_id))])),
    )
}

/// Request, advance and checkpoint one replacement through the socket;
/// returns `(replacement_id, checkpoint_digest)`.
fn checkpointed_record(
    fixture: &Fixture,
    id_seed: u32,
    lane: &str,
    role: &str,
    orchestration: Option<Val>,
    key_prefix: &str,
) -> (String, String) {
    let replacement_id = request_replacement(
        &fixture.socket,
        id_seed,
        lane,
        role,
        &format!("ik_{key_prefix}-request"),
    );
    advance_to_quiescing(
        &fixture.socket,
        id_seed + 1,
        &replacement_id,
        &format!("ik_{key_prefix}-advance"),
    );
    let digest = capture_checkpoint(
        &fixture.socket,
        id_seed + 2,
        &replacement_id,
        role,
        orchestration,
        &format!("ik_{key_prefix}-capture"),
    );
    (replacement_id, digest)
}

fn retirement_binding(
    generation: i64,
    session: &str,
    process: &str,
    checkpoint_digest: &str,
) -> Val {
    object(vec![
        ("generation", integer(generation)),
        ("session", string(session)),
        ("process", string(process)),
        ("checkpoint_digest", string(checkpoint_digest)),
    ])
}

fn retirement_recheck(
    session: &str,
    process: Option<&str>,
    children: &[(&str, &str)],
    active: bool,
) -> Val {
    object(vec![
        ("observed_at", string("2026-09-12T00:00:00Z")),
        ("session", string(session)),
        ("process", process.map(string).unwrap_or_else(null)),
        (
            "children",
            Val::Arr(
                children
                    .iter()
                    .map(|(command, state)| {
                        object(vec![("command", string(command)), ("state", string(state))])
                    })
                    .collect(),
            ),
        ),
        ("active", bool_(active)),
    ])
}

fn harness_pi() -> Val {
    object(vec![("key", string("lane-orch-1")), ("kind", string("pi"))])
}

fn retire(socket: &Path, id: &str, replacement_id: &str, digest: &str) -> Val {
    rpc_ok(
        socket,
        id,
        "lane.retire",
        Some(object(vec![
            ("idempotency_key", string(&format!("ik_retire-{id}"))),
            ("replacement_id", string(replacement_id)),
            (
                "binding",
                retirement_binding(1, SOURCE_SESSION, SOURCE_PROCESS, digest),
            ),
            (
                "recheck",
                retirement_recheck(SOURCE_SESSION, Some(SOURCE_PROCESS), &[], false),
            ),
            ("harness", harness_pi()),
        ])),
    )
}

/// Drive the full retirement transition: replacement → advance → checkpoint
/// → retire. Returns `(replacement_id, checkpoint_digest)` at `retired`.
fn retired_record(
    fixture: &Fixture,
    id_seed: u32,
    lane: &str,
    role: &str,
    orchestration: Option<Val>,
    key_prefix: &str,
) -> (String, String) {
    let (replacement_id, digest) =
        checkpointed_record(fixture, id_seed, lane, role, orchestration, key_prefix);
    let result = retire(
        &fixture.socket,
        &fresh_id(id_seed + 3),
        &replacement_id,
        &digest,
    );
    assert_eq!(
        field_str(
            retirement_of(&result)
                .get("replacement")
                .expect("replacement"),
            "phase"
        ),
        "retired",
        "the source retirement must commit before the start"
    );
    (replacement_id, digest)
}

fn admission(caps: (i64, i64, i64), measured_at: &str) -> Val {
    object(vec![
        ("repository", string("example-org/canter")),
        (
            "caps",
            object(vec![
                ("global", integer(caps.0)),
                ("repository", integer(caps.1)),
                ("harness", integer(caps.2)),
            ]),
        ),
        (
            "host_proof",
            object(vec![("measured_at", string(measured_at))]),
        ),
        ("running", Val::Arr(vec![])),
    ])
}

fn live_admission() -> Val {
    admission((8, 4, 4), &canter::time::rfc3339_now())
}

fn start_params(
    id: &str,
    replacement_id: &str,
    digest: &str,
    nonce: &str,
    session: &str,
    admission_block: Val,
) -> Val {
    object(vec![
        ("idempotency_key", string(&format!("ik_start-{id}"))),
        ("replacement_id", string(replacement_id)),
        (
            "binding",
            object(vec![
                ("generation", integer(1)),
                ("checkpoint_digest", string(digest)),
                ("nonce", string(nonce)),
            ]),
        ),
        (
            "successor",
            object(vec![
                ("session", string(session)),
                ("kickoff_receipt", string(&kickoff_receipt())),
            ]),
        ),
        ("harness", harness_pi()),
        ("admission", admission_block),
    ])
}

fn start(
    socket: &Path,
    id: &str,
    replacement_id: &str,
    digest: &str,
    nonce: &str,
    session: &str,
) -> Val {
    rpc_ok(
        socket,
        id,
        "lane.start",
        Some(start_params(
            id,
            replacement_id,
            digest,
            nonce,
            session,
            live_admission(),
        )),
    )
}

fn adopt_params(id: &str, replacement_id: &str, successor_id: &str, observation: Val) -> Val {
    object(vec![
        ("idempotency_key", string(&format!("ik_adopt-{id}"))),
        ("replacement_id", string(replacement_id)),
        (
            "binding",
            object(vec![
                ("generation", integer(1)),
                ("successor_id", string(successor_id)),
                ("session", string(SUCCESSOR_SESSION)),
            ]),
        ),
        ("observation", observation.clone()),
        ("reobservation", observation),
        ("harness", harness_pi()),
    ])
}

/// One started (adopting) record whose successor is committed and verified.
fn started_record(
    fixture: &Fixture,
    id_seed: u32,
    lane: &str,
    role: &str,
    orchestration: Option<Val>,
    key_prefix: &str,
) -> (String, String) {
    let (replacement_id, digest) =
        retired_record(fixture, id_seed, lane, role, orchestration, key_prefix);
    let result = start(
        &fixture.socket,
        &fresh_id(id_seed + 10),
        &replacement_id,
        &digest,
        "nonce-0001",
        SUCCESSOR_SESSION,
    );
    assert_eq!(
        field_str(replacement_of(start_of(&result)), "phase"),
        "adopting",
        "the verified start commits the `adopting` boundary"
    );
    (replacement_id, digest)
}

// ---------------------------------------------------------------------------
// AC1 (+ probe P1): the start requires the verified retirement boundary and
// checkpoint integrity; one generation/nonce owns startup.
// ---------------------------------------------------------------------------

#[test]
fn start_requires_the_retired_boundary_and_checkpoint_integrity() {
    let fixture = Fixture::new("start-guard");
    fixture.set_mode("ready");
    fixture.write_fake_workspace();
    let daemon = fixture.spawn(None);
    wait_ready(&fixture);

    // A record that has not retired cannot start a successor.
    let (not_retired, not_retired_digest) =
        checkpointed_record(&fixture, 1, "lane-orch-3", "implementer", None, "sa-guard");
    let id = fresh_id(20);
    let (code, message) = rpc_err(
        &fixture.socket,
        &id,
        "lane.start",
        Some(start_params(
            &id,
            &not_retired,
            &not_retired_digest,
            "nonce-0001",
            SUCCESSOR_SESSION,
            live_admission(),
        )),
    );
    assert_eq!(code, "refusal.replacement.order", "{message}");
    assert!(
        fixture.invocations().is_empty(),
        "a record that never retired invoked nothing: {:?}",
        fixture.invocations()
    );

    // The verified retirement + committed checkpoint digest is the boundary.
    let (replacement_id, digest) = retired_record(
        &fixture,
        30,
        "lane-orch-4",
        "implementer",
        None,
        "sa-boundary",
    );
    let before = status_of(&fixture.socket, 40, &replacement_id);
    assert_eq!(field_str(replacement_of(&before), "phase"), "retired");
    let invocations_before = fixture.invocations();

    // Changed evidence refuses typed and invokes NOTHING: no source
    // recheck, no spawn, no read-back.
    let cases: Vec<(&str, Val)> = vec![
        (
            "changed checkpoint digest",
            start_params(
                "x1",
                &replacement_id,
                &"f".repeat(64),
                "nonce-0001",
                SUCCESSOR_SESSION,
                live_admission(),
            ),
        ),
        (
            "stale lane generation",
            object(vec![
                ("idempotency_key", string("ik_start-x2")),
                ("replacement_id", string(&replacement_id)),
                (
                    "binding",
                    object(vec![
                        ("generation", integer(2)),
                        ("checkpoint_digest", string(&digest)),
                        ("nonce", string("nonce-0001")),
                    ]),
                ),
                (
                    "successor",
                    object(vec![
                        ("session", string(SUCCESSOR_SESSION)),
                        ("kickoff_receipt", string(&kickoff_receipt())),
                    ]),
                ),
                ("harness", harness_pi()),
                ("admission", live_admission()),
            ]),
        ),
        (
            "empty startup nonce",
            start_params(
                "x3",
                &replacement_id,
                &digest,
                "",
                SUCCESSOR_SESSION,
                live_admission(),
            ),
        ),
    ];
    for (index, (what, params)) in cases.into_iter().enumerate() {
        let id = fresh_id(50 + index as u32);
        let (code, message) = rpc_err(&fixture.socket, &id, "lane.start", Some(params));
        assert_eq!(code, "refusal.successor.binding", "{what}: {message}");
        assert_eq!(
            fixture.invocations(),
            invocations_before,
            "{what}: no effect was invoked"
        );
    }
    assert_eq!(
        status_of(&fixture.socket, 60, &replacement_id),
        before,
        "refused starts leave the record and its history untouched"
    );

    // The exact start commits: the source absence is rechecked, ONE bounded
    // fresh session start is issued, and ONE read-back verifies it.
    let id = fresh_id(70);
    let result = start(
        &fixture.socket,
        &id,
        &replacement_id,
        &digest,
        "nonce-0001",
        SUCCESSOR_SESSION,
    );
    let start_doc = start_of(&result);
    assert_eq!(
        field_str(replacement_of(start_doc), "phase"),
        "adopting",
        "the verified start commits the `adopting` boundary"
    );
    let successor = successor_of(start_doc);
    assert_eq!(
        field_str(successor, "session"),
        SUCCESSOR_SESSION,
        "the successor continues the SAME logical lane"
    );
    assert_eq!(field_str(successor, "worktree"), WORKTREE);
    assert_eq!(field_str(successor, "role"), "implementer");
    assert_eq!(field_str(successor, "delivery"), "delivered");
    assert_eq!(field_str(successor, "nonce"), "nonce-0001");
    assert_eq!(
        field_str(successor, "process"),
        "proc-0002",
        "the adapter-observed process is durable on the successor row"
    );
    assert_eq!(
        field_str(successor, "evidence_digest").len(),
        64,
        "the verification evidence is digest-bound"
    );
    assert_eq!(
        field_int(successor, "attempts"),
        1,
        "one bounded spawn attempt"
    );
    let verification = start_doc.get("verification").expect("verification");
    assert_eq!(field_str(verification, "readiness"), "ready");
    assert_eq!(field_str(verification, "process"), "proc-0002");
    assert_eq!(field_str(verification, "session"), SUCCESSOR_SESSION);
    let invocations = fixture.invocations();
    assert_eq!(
        &invocations[invocations.len() - 3..],
        &[
            format!("session show {SOURCE_SESSION} --json").as_str(),
            format!("session start {SUCCESSOR_SESSION} --json").as_str(),
            format!("session show {SUCCESSOR_SESSION} --json").as_str(),
        ],
        "one source recheck, ONE bounded fresh start, ONE read-back: {invocations:?}"
    );

    // The replay returns the recorded response and never repeats the spawn.
    let replay = rpc_ok(
        &fixture.socket,
        &id,
        "lane.start",
        Some(start_params(
            &id,
            &replacement_id,
            &digest,
            "nonce-0001",
            SUCCESSOR_SESSION,
            live_admission(),
        )),
    );
    assert_eq!(replay, result, "the recorded response is returned verbatim");
    assert_eq!(
        fixture.invocations().len(),
        invocations.len(),
        "a replay invokes nothing"
    );

    shutdown(daemon);
}

#[test]
fn duplicate_starts_cannot_create_a_second_successor() {
    let fixture = Fixture::new("start-duplicate");
    fixture.set_mode("ready");
    fixture.write_fake_workspace();
    let daemon = fixture.spawn(None);
    wait_ready(&fixture);

    let (replacement_id, digest) =
        retired_record(&fixture, 100, "lane-orch-5", "implementer", None, "sa-dup");
    let result = start(
        &fixture.socket,
        &fresh_id(110),
        &replacement_id,
        &digest,
        "nonce-0001",
        SUCCESSOR_SESSION,
    );
    let first_successor = field_str(successor_of(start_of(&result)), "successor_id").to_string();
    let spawns = fixture
        .invocations()
        .iter()
        .filter(|line| line.starts_with("session start"))
        .count();
    assert_eq!(spawns, 1, "exactly one fresh session start");

    // A second start (new idempotency key, same nonce) cannot create a
    // second successor: the committed boundary refuses, nothing is spawned.
    let (code, message) = rpc_err(
        &fixture.socket,
        &fresh_id(120),
        "lane.start",
        Some(start_params(
            "dup-1",
            &replacement_id,
            &digest,
            "nonce-0001",
            SUCCESSOR_SESSION,
            live_admission(),
        )),
    );
    assert_eq!(code, "refusal.successor.exists", "{message}");
    // A different nonce can never take over a started successor.
    let (code, message) = rpc_err(
        &fixture.socket,
        &fresh_id(121),
        "lane.start",
        Some(start_params(
            "dup-2",
            &replacement_id,
            &digest,
            "nonce-9999",
            SUCCESSOR_SESSION,
            live_admission(),
        )),
    );
    assert!(
        code == "refusal.successor.nonce" || code == "refusal.successor.exists",
        "a second nonce is refused: {code}: {message}"
    );
    assert_eq!(
        fixture
            .invocations()
            .iter()
            .filter(|line| line.starts_with("session start"))
            .count(),
        1,
        "no second spawn was issued"
    );
    assert_eq!(
        field_str(
            successor_of(&status_of(&fixture.socket, 130, &replacement_id)),
            "successor_id"
        ),
        first_successor,
        "the ONE successor is unchanged"
    );

    // Simultaneous starts: exactly one winner, exactly one spawn.
    let (parallel_id, parallel_digest) =
        retired_record(&fixture, 140, "lane-orch-6", "implementer", None, "sa-race");
    let before = fixture
        .invocations()
        .iter()
        .filter(|line| line.starts_with("session start"))
        .count();
    let socket = fixture.socket.clone();
    let mut handles = Vec::new();
    for (index, nonce) in ["nonce-race-a", "nonce-race-b"].iter().enumerate() {
        let socket = socket.clone();
        let replacement_id = parallel_id.clone();
        let digest = parallel_digest.clone();
        let seed = 150 + index as u32 * 2;
        let nonce = nonce.to_string();
        handles.push(std::thread::spawn(move || {
            let id = fresh_id(seed);
            let doc = rpc(
                &socket,
                &id,
                "lane.start",
                Some(start_params(
                    &id,
                    &replacement_id,
                    &digest,
                    &nonce,
                    SUCCESSOR_SESSION,
                    live_admission(),
                )),
            );
            doc.get("ok").and_then(Val::as_bool).unwrap_or(false)
        }));
    }
    let wins = handles
        .into_iter()
        .map(|handle| handle.join().expect("join"))
        .filter(|ok| *ok)
        .count();
    assert_eq!(wins, 1, "exactly one simultaneous start may win");
    let after = fixture
        .invocations()
        .iter()
        .filter(|line| line.starts_with("session start"))
        .count();
    assert_eq!(
        after,
        before + 1,
        "exactly one spawn was issued by the race"
    );

    shutdown(daemon);
}

// ---------------------------------------------------------------------------
// AC2: the existing admission gate applies; a capacity refusal is a typed
// hold that spawns nothing and never disables admission; the retry stays
// bounded and explicit (no scheduler).
// ---------------------------------------------------------------------------

#[test]
fn capacity_refusal_is_a_held_typed_refusal_with_a_bounded_retry() {
    let fixture = Fixture::new("start-capacity");
    fixture.set_mode("ready");
    fixture.write_fake_workspace();
    let daemon = fixture.spawn(None);
    wait_ready(&fixture);

    let (replacement_id, digest) =
        retired_record(&fixture, 200, "lane-orch-7", "implementer", None, "sa-cap");
    let before = status_of(&fixture.socket, 210, &replacement_id);
    let invocations_before = fixture.invocations();

    // Missing admission bundle: typed hold, nothing spawned.
    let id = fresh_id(220);
    let mut missing = start_params(
        &id,
        &replacement_id,
        &digest,
        "nonce-0001",
        SUCCESSOR_SESSION,
        live_admission(),
    );
    if let Val::Obj(map) = &mut missing {
        map.remove("admission");
    }
    let (code, message) = rpc_err(&fixture.socket, &id, "lane.start", Some(missing));
    assert_eq!(code, "refusal.admission.proof_missing", "{message}");

    // Stale host-resource proof: unknown/stale measurements refuse.
    let stale_at = canter::time::rfc3339_from_unix(canter::time::unix_now() - 3600);
    let id = fresh_id(221);
    let (code, message) = rpc_err(
        &fixture.socket,
        &id,
        "lane.start",
        Some(start_params(
            &id,
            &replacement_id,
            &digest,
            "nonce-0001",
            SUCCESSOR_SESSION,
            admission((8, 4, 4), &stale_at),
        )),
    );
    assert_eq!(code, "refusal.admission.proof_stale", "{message}");

    // Exhausted global cap: typed hold.
    let id = fresh_id(222);
    let (code, message) = rpc_err(
        &fixture.socket,
        &id,
        "lane.start",
        Some(start_params(
            &id,
            &replacement_id,
            &digest,
            "nonce-0001",
            SUCCESSOR_SESSION,
            admission((0, 4, 4), &canter::time::rfc3339_now()),
        )),
    );
    assert_eq!(code, "refusal.admission.cap_global", "{message}");

    // #236 AC2: the refusal the gate raises NAMES the lanes that occupy the
    // cap — the count, the cap and the identities (declared worktree here;
    // the daemon's own durable path names the run id) — never a bare count.
    let id = fresh_id(223);
    let mut occupied = admission((2, 4, 4), &canter::time::rfc3339_now());
    if let Val::Obj(map) = &mut occupied {
        map.insert(
            "running".to_string(),
            Val::Arr(vec![
                object(vec![
                    ("repository", string("example-org/other")),
                    ("harness_key", string("lane-1")),
                    ("scope", string("worktrees/issues/71")),
                ]),
                object(vec![
                    ("repository", string("example-org/other")),
                    ("harness_key", string("lane-1")),
                    ("scope", string("worktrees/issues/72")),
                ]),
            ]),
        );
    }
    let (code, message) = rpc_err(
        &fixture.socket,
        &id,
        "lane.start",
        Some(start_params(
            &id,
            &replacement_id,
            &digest,
            "nonce-0001",
            SUCCESSOR_SESSION,
            occupied,
        )),
    );
    assert_eq!(code, "refusal.admission.cap_global", "{message}");
    for needle in [
        "the global concurrency cap (2)",
        "2 active lanes",
        "example-org/other (worktrees/issues/71)",
        "example-org/other (worktrees/issues/72)",
    ] {
        assert!(
            message.contains(needle),
            "the daemon's refusal must name {needle}: {message}"
        );
    }
    assert_eq!(
        fixture.invocations(),
        invocations_before,
        "capacity refusals spawn nothing"
    );
    assert_eq!(
        status_of(&fixture.socket, 230, &replacement_id),
        before,
        "a capacity refusal leaves the record untouched"
    );
    let result = start(
        &fixture.socket,
        &fresh_id(240),
        &replacement_id,
        &digest,
        "nonce-0001",
        SUCCESSOR_SESSION,
    );
    assert_eq!(
        field_str(replacement_of(start_of(&result)), "phase"),
        "adopting",
        "admission was never disabled by the refusal"
    );

    shutdown(daemon);
}

// ---------------------------------------------------------------------------
// AC3: the successor continues the SAME worktree/logical task; source and
// successor both live/ambiguous blocks advancement.
// ---------------------------------------------------------------------------

#[test]
fn successor_uses_the_same_worktree_and_blocks_when_the_source_is_live() {
    let fixture = Fixture::new("start-worktree");
    fixture.set_mode("ready");
    fixture.write_fake_workspace();
    let daemon = fixture.spawn(None);
    wait_ready(&fixture);

    // A successor observed in another worktree fails closed: no adoption,
    // the record parks for reconciliation.
    let (wrong_cwd, digest) =
        retired_record(&fixture, 300, "lane-orch-8", "implementer", None, "sa-cwd");
    fixture.set_mode("wrong-cwd");
    let id = fresh_id(310);
    let (code, message) = rpc_err(
        &fixture.socket,
        &id,
        "lane.start",
        Some(start_params(
            &id,
            &wrong_cwd,
            &digest,
            "nonce-0001",
            SUCCESSOR_SESSION,
            live_admission(),
        )),
    );
    assert_eq!(code, "refusal.successor.reused", "{message}");
    let parked = status_of(&fixture.socket, 320, &wrong_cwd);
    assert_eq!(
        field_str(replacement_of(&parked), "outcome"),
        "ambiguous",
        "a wrong-worktree successor parks for external reconciliation"
    );

    // A live source session blocks the advancement BEFORE any spawn.
    let (source_live, digest) =
        retired_record(&fixture, 330, "lane-orch-9", "implementer", None, "sa-live");
    fixture.set_mode("ready");
    fixture.set_source_mode("live");
    let spawns_before = fixture
        .invocations()
        .iter()
        .filter(|line| line.starts_with("session start"))
        .count();
    let id = fresh_id(340);
    let (code, message) = rpc_err(
        &fixture.socket,
        &id,
        "lane.start",
        Some(start_params(
            &id,
            &source_live,
            &digest,
            "nonce-0001",
            SUCCESSOR_SESSION,
            live_admission(),
        )),
    );
    assert_eq!(code, "refusal.successor.source_live", "{message}");
    assert_eq!(
        fixture
            .invocations()
            .iter()
            .filter(|line| line.starts_with("session start"))
            .count(),
        spawns_before,
        "a live source blocks the advancement before any spawn"
    );
    assert_eq!(
        field_str(
            replacement_of(&status_of(&fixture.socket, 350, &source_live)),
            "phase"
        ),
        "retired",
        "the blocked start leaves the record at the retired boundary"
    );

    // Once the source absence is proven, the same boundary starts.
    fixture.set_source_mode("retired");
    let result = start(
        &fixture.socket,
        &fresh_id(360),
        &source_live,
        &digest,
        "nonce-0001",
        SUCCESSOR_SESSION,
    );
    assert_eq!(
        field_str(successor_of(start_of(&result)), "worktree"),
        WORKTREE,
        "the successor continues the SAME worktree"
    );

    shutdown(daemon);
}

// ---------------------------------------------------------------------------
// AC4 (+ probe P3): adapter-observed verification — a spawned process alone
// is never adopted.
// ---------------------------------------------------------------------------

#[test]
fn a_spawned_process_alone_is_not_adopted() {
    let fixture = Fixture::new("start-verify");
    fixture.set_mode("ready");
    fixture.write_fake_workspace();
    let daemon = fixture.spawn(None);
    wait_ready(&fixture);

    let (replacement_id, digest) = retired_record(
        &fixture,
        400,
        "lane-orch-10",
        "implementer",
        None,
        "sa-verify",
    );
    // The first attempt spawns; the successor is NOT verifiable (it reports
    // a process only). Every incomplete/wrong verification HOLDS at the
    // `starting` boundary: a spawned process alone (or a process plus a
    // subset of the evidence) is never adopted. Every retry re-verifies
    // only — it never re-spawns.
    fixture.set_mode("proc-only");
    let cases = [
        "proc-only",
        "no-role",
        "no-cwd",
        "no-kickoff",
        "no-process",
        "not-ready",
        "malformed",
    ];
    let mut spawns = 0;
    for (index, mode) in cases.iter().enumerate() {
        fixture.set_mode(mode);
        let id = fresh_id(410 + index as u32);
        let (code, message) = rpc_err(
            &fixture.socket,
            &id,
            "lane.start",
            Some(start_params(
                &id,
                &replacement_id,
                &digest,
                "nonce-0001",
                SUCCESSOR_SESSION,
                live_admission(),
            )),
        );
        assert_eq!(code, "refusal.successor.held", "{mode}: {message}");
        let status = status_of(&fixture.socket, 500 + index as u32, &replacement_id);
        assert_eq!(
            field_str(replacement_of(&status), "phase"),
            "starting",
            "{mode}: the boundary holds at `starting` (never `adopting`)"
        );
        assert_ne!(
            field_str(replacement_of(&status), "phase"),
            "adopted",
            "{mode}: a spawned process alone is not ADOPTED"
        );
        spawns = fixture
            .invocations()
            .iter()
            .filter(|line| line.starts_with("session start"))
            .count();
    }
    assert_eq!(spawns, 1, "verification retries never re-spawn");

    // The reused source process identity answers for the successor: fail
    // closed (parked for reconciliation, never adopted).
    fixture.set_mode("reused-process");
    let id = fresh_id(520);
    let (code, message) = rpc_err(
        &fixture.socket,
        &id,
        "lane.start",
        Some(start_params(
            &id,
            &replacement_id,
            &digest,
            "nonce-0001",
            SUCCESSOR_SESSION,
            live_admission(),
        )),
    );
    assert_eq!(code, "refusal.successor.reused", "{message}");
    assert_eq!(
        field_str(
            replacement_of(&status_of(&fixture.socket, 530, &replacement_id)),
            "outcome"
        ),
        "ambiguous",
        "a reused identity fails closed"
    );

    shutdown(daemon);
}

// ---------------------------------------------------------------------------
// AC5 (+ probe P4): the adoption re-query is compared against the recorded
// handoff state; differences reconcile instead of blind-replaying.
// ---------------------------------------------------------------------------

#[test]
fn adoption_reconciles_instead_of_replaying_a_difference() {
    let fixture = Fixture::new("start-adopt-diff");
    fixture.set_mode("ready");
    fixture.write_fake_workspace();
    let daemon = fixture.spawn(None);
    wait_ready(&fixture);

    let cases: Vec<(&str, Val)> = vec![
        ("head", string(&"9".repeat(40))),
        ("base", string(&"8".repeat(40))),
        (
            "dirty",
            object(vec![
                ("count", integer(3)),
                ("digest", string(&"e".repeat(64))),
            ]),
        ),
        (
            "untracked",
            object(vec![
                ("count", integer(2)),
                ("digest", string(&"f".repeat(64))),
            ]),
        ),
        (
            "report",
            object(vec![
                ("round", integer(2)),
                ("reviewed_sha", string(&"7".repeat(40))),
            ]),
        ),
        (
            "gates",
            Val::Arr(vec![object(vec![
                ("name", string("focused")),
                ("status", string("pending")),
            ])]),
        ),
        (
            "children",
            Val::Arr(vec![object(vec![
                ("command", string("cargo test --locked")),
                ("state", string("active")),
            ])]),
        ),
    ];
    for (index, (field, value)) in cases.into_iter().enumerate() {
        let (replacement_id, _digest) = started_record(
            &fixture,
            600 + index as u32 * 20,
            &format!("lane-orch-diff-{index}"),
            "implementer",
            None,
            &format!("sa-diff-{index}"),
        );
        let successor_id = field_str(
            successor_of(&status_of(
                &fixture.socket,
                990 + index as u32,
                &replacement_id,
            )),
            "successor_id",
        )
        .to_string();
        let observation = with_field("implementer", field, value);
        let id = fresh_id(700 + index as u32);
        let (code, message) = rpc_err(
            &fixture.socket,
            &id,
            "lane.adopt",
            Some(adopt_params(
                &id,
                &replacement_id,
                &successor_id,
                observation,
            )),
        );
        assert_eq!(code, "refusal.successor.differs", "{field}: {message}");
        assert!(
            message.contains(field),
            "{field}: the reconciliation verdict names the differing field: {message}"
        );
        assert_eq!(
            field_str(
                replacement_of(&status_of(
                    &fixture.socket,
                    800 + index as u32,
                    &replacement_id
                )),
                "outcome"
            ),
            "ambiguous",
            "{field}: a difference parks for external reconciliation"
        );
    }

    // The matching re-query adopts: the transition commits with evidence.
    let (replacement_id, _digest) = started_record(
        &fixture,
        900,
        "lane-orch-adopt-ok",
        "implementer",
        None,
        "sa-adopt-ok",
    );
    let status = status_of(&fixture.socket, 910, &replacement_id);
    let successor_id = field_str(successor_of(&status), "successor_id").to_string();
    let id = fresh_id(920);
    let result = rpc_ok(
        &fixture.socket,
        &id,
        "lane.adopt",
        Some(adopt_params(
            &id,
            &replacement_id,
            &successor_id,
            adoption_observation("implementer"),
        )),
    );
    let adoption = adoption_of(&result);
    assert_eq!(
        field_str(replacement_of(adoption), "phase"),
        "adopted",
        "the matching re-query adopts"
    );
    let successor = successor_of(adoption);
    assert_eq!(field_str(successor, "successor_id"), successor_id);
    assert_eq!(field_str(successor, "worktree"), WORKTREE);
    assert_eq!(
        field_str(successor, "adoption_digest").len(),
        64,
        "the adoption evidence is digest-bound"
    );
    assert_ne!(field_str(successor, "adopted_at"), "");
    let invocations = fixture.invocations().len();

    // The replay returns the recorded response; a second adoption (new key)
    // refuses the phase order and changes nothing.
    let replay = rpc_ok(
        &fixture.socket,
        &id,
        "lane.adopt",
        Some(adopt_params(
            &id,
            &replacement_id,
            &successor_id,
            adoption_observation("implementer"),
        )),
    );
    assert_eq!(replay, result, "the recorded adoption response is replayed");
    let id = fresh_id(930);
    let (code, message) = rpc_err(
        &fixture.socket,
        &id,
        "lane.adopt",
        Some(adopt_params(
            &id,
            &replacement_id,
            &successor_id,
            adoption_observation("implementer"),
        )),
    );
    assert_eq!(code, "refusal.replacement.order", "{message}");
    assert_eq!(
        fixture.invocations().len(),
        invocations,
        "replays and refusals invoke nothing"
    );

    shutdown(daemon);
}

// ---------------------------------------------------------------------------
// AC6: orchestrator replacement preserves worker/reviewer identity; a
// worker completion during the handoff is consumed idempotently after
// adoption with NO duplicate reviewer dispatch.
// ---------------------------------------------------------------------------

#[test]
fn orchestrator_identity_is_preserved_and_completions_consume_once() {
    let fixture = Fixture::new("start-orchestrator");
    fixture.set_mode("ready");
    fixture.write_fake_workspace();
    let daemon = fixture.spawn(None);
    wait_ready(&fixture);

    // The referenced worker/reviewer lanes exist and stay untouched.
    let worker = request_replacement(
        &fixture.socket,
        1000,
        "lane-20",
        "implementer",
        "ik_sa-worker-01",
    );
    let reviewer = request_replacement(
        &fixture.socket,
        1001,
        "lane-21",
        "reviewer",
        "ik_sa-reviewer-01",
    );
    let worker_before = status_of(&fixture.socket, 1002, &worker);
    let reviewer_before = status_of(&fixture.socket, 1003, &reviewer);

    // The orchestrator successor runs the orchestrator role from the start.
    fixture.set_mode("orchestrator");
    let (replacement_id, _digest) = started_record(
        &fixture,
        1010,
        "lane-orch-22",
        "orchestrator",
        Some(orchestration(&[&worker], &[&reviewer])),
        "sa-orch",
    );
    let status = status_of(&fixture.socket, 1020, &replacement_id);
    let successor_id = field_str(successor_of(&status), "successor_id").to_string();

    // The adoption re-verifies the orchestrator successor and preserves the
    // worker/reviewer identity.
    let id = fresh_id(1030);
    let result = rpc_ok(
        &fixture.socket,
        &id,
        "lane.adopt",
        Some(adopt_params(
            &id,
            &replacement_id,
            &successor_id,
            adoption_observation("orchestrator"),
        )),
    );
    let successor = successor_of(adoption_of(&result));
    let preserved = successor.get("orchestration").expect("orchestration");
    assert_eq!(
        preserved
            .get("workers")
            .and_then(Val::as_array)
            .map(|items| items.len()),
        Some(1),
        "the worker identity is preserved"
    );
    assert_eq!(
        preserved
            .get("reviewers")
            .and_then(Val::as_array)
            .map(|items| items.len()),
        Some(1),
        "the reviewer identity is preserved"
    );
    assert_eq!(
        preserved
            .get("pending_events")
            .and_then(Val::as_array)
            .map(|items| items.iter().filter_map(Val::as_str).collect::<Vec<_>>()),
        Some(vec!["worker-finished:lane-8"]),
        "the worker completion observed during the handoff is recorded"
    );

    // Consumption is exactly once and never dispatches anything.
    let invocations = fixture.invocations().len();
    let id = fresh_id(1040);
    let consumed_params = object(vec![
        ("idempotency_key", string(&format!("ik_consume-{id}"))),
        ("replacement_id", string(&replacement_id)),
        ("successor_id", string(&successor_id)),
        (
            "completions",
            Val::Arr(vec![object(vec![
                ("event", string("worker-finished:lane-8")),
                ("worker", string(&worker)),
            ])]),
        ),
    ]);
    let result = rpc_ok(
        &fixture.socket,
        &id,
        "lane.successor.consume",
        Some(consumed_params.clone()),
    );
    assert_eq!(
        result
            .get("consumed")
            .and_then(Val::as_array)
            .map(|items| items.iter().filter_map(Val::as_str).collect::<Vec<_>>()),
        Some(vec!["worker-finished:lane-8"]),
        "the completion is durably consumed once"
    );
    assert_eq!(
        fixture.invocations().len(),
        invocations,
        "consumption dispatches nothing (no duplicate reviewer dispatch)"
    );

    // A replay returns the recorded response; a second consumption of the
    // same event refuses (never a duplicate reviewer dispatch).
    let replay = rpc_ok(
        &fixture.socket,
        &id,
        "lane.successor.consume",
        Some(consumed_params),
    );
    assert_eq!(replay, result);
    let id = fresh_id(1050);
    let (code, message) = rpc_err(
        &fixture.socket,
        &id,
        "lane.successor.consume",
        Some(object(vec![
            ("idempotency_key", string(&format!("ik_consume-{id}"))),
            ("replacement_id", string(&replacement_id)),
            ("successor_id", string(&successor_id)),
            (
                "completions",
                Val::Arr(vec![object(vec![
                    ("event", string("worker-finished:lane-8")),
                    ("worker", string(&worker)),
                ])]),
            ),
        ])),
    );
    assert_eq!(code, "refusal.successor.event_consumed", "{message}");
    // A completion that was never recorded is never consumed.
    let id = fresh_id(1060);
    let (code, message) = rpc_err(
        &fixture.socket,
        &id,
        "lane.successor.consume",
        Some(object(vec![
            ("idempotency_key", string(&format!("ik_consume-{id}"))),
            ("replacement_id", string(&replacement_id)),
            ("successor_id", string(&successor_id)),
            (
                "completions",
                Val::Arr(vec![object(vec![
                    ("event", string("worker-finished:lane-99")),
                    ("worker", string(&worker)),
                ])]),
            ),
        ])),
    );
    assert_eq!(code, "refusal.successor.event", "{message}");

    // The referenced child records are untouched, and no child identity was
    // ever addressed through the adapter.
    assert_eq!(status_of(&fixture.socket, 1070, &worker), worker_before);
    assert_eq!(status_of(&fixture.socket, 1071, &reviewer), reviewer_before);
    assert_eq!(
        fixture.invocations().len(),
        invocations,
        "the whole consumption surface invokes nothing"
    );

    shutdown(daemon);
}

// ---------------------------------------------------------------------------
// AC7 (+ probe P5): PAUSED between transitions prevents launch/activation; a
// booted successor remains fenced; the restart reconciles the startup nonce
// and the process evidence before any retry.
// ---------------------------------------------------------------------------

#[test]
fn paused_between_transitions_fences_the_successor() {
    let fixture = Fixture::new("start-paused");
    fixture.set_mode("ready");
    fixture.write_fake_workspace();
    let daemon = fixture.spawn(None);
    wait_ready(&fixture);

    // PAUSED before the launch: the start is prevented and nothing spawns.
    let (paused_before, digest) = retired_record(
        &fixture,
        1100,
        "lane-orch-30",
        "implementer",
        None,
        "sa-paused-a",
    );
    rpc_ok(
        &fixture.socket,
        &fresh_id(1110),
        "lane.replacement.hold",
        Some(object(vec![
            ("idempotency_key", string("ik_sa-paused-a-hold")),
            ("replacement_id", string(&paused_before)),
            ("reason", string("human decision pending")),
        ])),
    );
    let id = fresh_id(1111);
    let (code, message) = rpc_err(
        &fixture.socket,
        &id,
        "lane.start",
        Some(start_params(
            &id,
            &paused_before,
            &digest,
            "nonce-0001",
            SUCCESSOR_SESSION,
            live_admission(),
        )),
    );
    assert_eq!(code, "refusal.replacement.held", "{message}");
    assert!(
        fixture
            .invocations()
            .iter()
            .all(|line| !line.starts_with("session start")),
        "a paused lane launches nothing: {:?}",
        fixture.invocations()
    );

    // PAUSED between start and adoption: the booted successor stays fenced.
    let (replacement_id, digest) = retired_record(
        &fixture,
        1120,
        "lane-orch-31",
        "implementer",
        None,
        "sa-paused-b",
    );
    let result = start(
        &fixture.socket,
        &fresh_id(1130),
        &replacement_id,
        &digest,
        "nonce-0001",
        SUCCESSOR_SESSION,
    );
    let successor_id = field_str(successor_of(start_of(&result)), "successor_id").to_string();
    let invocations = fixture.invocations().len();
    rpc_ok(
        &fixture.socket,
        &fresh_id(1140),
        "lane.replacement.hold",
        Some(object(vec![
            ("idempotency_key", string("ik_sa-paused-b-hold")),
            ("replacement_id", string(&replacement_id)),
            ("reason", string("human decision pending")),
        ])),
    );
    let id = fresh_id(1141);
    let (code, message) = rpc_err(
        &fixture.socket,
        &id,
        "lane.adopt",
        Some(adopt_params(
            &id,
            &replacement_id,
            &successor_id,
            adoption_observation("implementer"),
        )),
    );
    assert_eq!(code, "refusal.replacement.held", "{message}");
    let parked = status_of(&fixture.socket, 1150, &replacement_id);
    let successor = successor_of(&parked);
    assert_eq!(
        field_str(successor, "adopted_at"),
        "",
        "the booted successor remains fenced (never activated)"
    );
    assert_eq!(
        fixture.invocations().len(),
        invocations,
        "a paused activation invokes nothing"
    );

    shutdown(daemon);
}

#[test]
fn restart_reconciles_the_startup_nonce_and_process_evidence_before_any_retry() {
    // Case A: the boundary committed, the verification was interrupted and
    // the successor is observable: reconciliation completes the boundary.
    let fixture = Fixture::new("start-restart-ready");
    fixture.set_mode("ready");
    fixture.write_fake_workspace();
    let mut daemon = fixture.spawn(Some("lane-start.after-boundary"));
    wait_ready(&fixture);

    let (replacement_id, digest) = retired_record(
        &fixture,
        1200,
        "lane-orch-32",
        "implementer",
        None,
        "sa-restart-a",
    );
    let id = fresh_id(1210);
    rpc_unchecked(
        &fixture.socket,
        &id,
        "lane.start",
        Some(start_params(
            &id,
            &replacement_id,
            &digest,
            "nonce-0001",
            SUCCESSOR_SESSION,
            live_admission(),
        )),
    );
    wait_crash(&mut daemon);
    assert!(
        fixture
            .invocations()
            .iter()
            .all(|line| !line.starts_with("session start")),
        "the crash landed before the spawn: {:?}",
        fixture.invocations()
    );

    let daemon = fixture.spawn(None);
    wait_ready(&fixture);
    let reconciled = status_of(&fixture.socket, 1220, &replacement_id);
    assert_eq!(
        field_str(replacement_of(&reconciled), "phase"),
        "adopting",
        "restart reconciliation completed the verified boundary"
    );
    assert_eq!(
        field_str(
            successor_of(&status_of(&fixture.socket, 1230, &replacement_id)),
            "process"
        ),
        "proc-0002",
        "the reconciled process evidence is durable"
    );
    let log = std::fs::read_to_string(fixture.daemon_log()).expect("daemon log");
    assert!(
        log.contains("reconcile.lane.start"),
        "the restart records the successor reconciliation: {log}"
    );
    // The adoption path continues on the reconciled boundary.
    let successor_id = field_str(
        successor_of(&status_of(&fixture.socket, 1240, &replacement_id)),
        "successor_id",
    )
    .to_string();
    let id = fresh_id(1250);
    let adopted = rpc_ok(
        &fixture.socket,
        &id,
        "lane.adopt",
        Some(adopt_params(
            &id,
            &replacement_id,
            &successor_id,
            adoption_observation("implementer"),
        )),
    );
    assert_eq!(
        field_str(replacement_of(adoption_of(&adopted)), "phase"),
        "adopted"
    );
    shutdown(daemon);

    // Case B: the boundary committed, the verification was interrupted and
    // the successor is NOT verifiable: the retry is refused and no second
    // spawn is ever issued.
    let fixture = Fixture::new("start-restart-held");
    fixture.set_mode("no-process");
    fixture.write_fake_workspace();
    let mut daemon = fixture.spawn(Some("lane-start.after-boundary"));
    wait_ready(&fixture);

    let (replacement_id, digest) = retired_record(
        &fixture,
        1300,
        "lane-orch-33",
        "implementer",
        None,
        "sa-restart-b",
    );
    let id = fresh_id(1310);
    rpc_unchecked(
        &fixture.socket,
        &id,
        "lane.start",
        Some(start_params(
            &id,
            &replacement_id,
            &digest,
            "nonce-0001",
            SUCCESSOR_SESSION,
            live_admission(),
        )),
    );
    wait_crash(&mut daemon);
    let spawns = fixture
        .invocations()
        .iter()
        .filter(|line| line.starts_with("session start"))
        .count();
    assert_eq!(spawns, 0, "the crash landed before the spawn");

    let daemon = fixture.spawn(None);
    wait_ready(&fixture);
    let parked = status_of(&fixture.socket, 1320, &replacement_id);
    assert_eq!(
        field_str(replacement_of(&parked), "outcome"),
        "ambiguous",
        "unprovable process evidence parks the record for reconciliation"
    );
    // The retry (a fresh key) is refused and issues no spawn: the restart
    // reconciled the nonce and the process evidence BEFORE the retry.
    let id = fresh_id(1330);
    let (code, message) = rpc_err(
        &fixture.socket,
        &id,
        "lane.start",
        Some(start_params(
            &id,
            &replacement_id,
            &digest,
            "nonce-0001",
            SUCCESSOR_SESSION,
            live_admission(),
        )),
    );
    assert_eq!(code, "refusal.replacement.ambiguous", "{message}");
    assert_eq!(
        fixture
            .invocations()
            .iter()
            .filter(|line| line.starts_with("session start"))
            .count(),
        0,
        "no retry may spawn before the reconciliation resolves"
    );
    shutdown(daemon);
}

// ---------------------------------------------------------------------------
// AC8: absent successor / missing ack / restart reuse boundaries.
// ---------------------------------------------------------------------------

#[test]
fn absent_successor_and_missing_ack_are_typed_refusals() {
    let fixture = Fixture::new("start-absent");
    fixture.set_mode("ready");
    fixture.write_fake_workspace();
    let daemon = fixture.spawn(None);
    wait_ready(&fixture);

    // An absent successor boundary cannot be adopted: the record has not
    // reached the `adopting` boundary at all.
    let (replacement_id, _digest) = retired_record(
        &fixture,
        1400,
        "lane-orch-34",
        "implementer",
        None,
        "sa-absent",
    );
    let id = fresh_id(1410);
    let (code, message) = rpc_err(
        &fixture.socket,
        &id,
        "lane.adopt",
        Some(object(vec![
            ("idempotency_key", string(&format!("ik_adopt-{id}"))),
            ("replacement_id", string(&replacement_id)),
            (
                "binding",
                object(vec![
                    ("generation", integer(1)),
                    ("successor_id", string(&format!("su_{}", "0".repeat(16)))),
                    ("session", string(SUCCESSOR_SESSION)),
                ]),
            ),
            ("observation", adoption_observation("implementer")),
            ("reobservation", adoption_observation("implementer")),
            ("harness", harness_pi()),
        ])),
    );
    assert_eq!(code, "refusal.replacement.order", "{message}");
    assert!(
        fixture
            .invocations()
            .iter()
            .all(|line| !line.starts_with("session start")),
        "an absent successor invokes nothing: {:?}",
        fixture.invocations()
    );

    // The successor session never confirms: a missing read-back holds (the
    // record stays at the committed `starting` boundary, never adopted).
    let (replacement_id, digest) = retired_record(
        &fixture,
        1420,
        "lane-orch-35",
        "implementer",
        None,
        "sa-absent-2",
    );
    fixture.set_mode("malformed");
    let id = fresh_id(1430);
    let (code, message) = rpc_err(
        &fixture.socket,
        &id,
        "lane.start",
        Some(start_params(
            &id,
            &replacement_id,
            &digest,
            "nonce-0001",
            SUCCESSOR_SESSION,
            live_admission(),
        )),
    );
    assert_eq!(code, "refusal.successor.held", "{message}");
    assert_eq!(
        field_str(
            replacement_of(&status_of(&fixture.socket, 1440, &replacement_id)),
            "phase"
        ),
        "starting"
    );

    // The spawn row cannot resolve the workspace executable: the start row
    // never ran, the boundary stays undelivered for a bounded same-nonce
    // retry, and the retry re-attempts exactly once.
    let (replacement_id, digest) = retired_record(
        &fixture,
        1500,
        "lane-orch-36",
        "implementer",
        None,
        "sa-absent-3",
    );
    // The fake workspace vanishes right after answering the source
    // recheck: the boundary commits, the spawn cannot resolve the
    // executable.
    fixture.set_mode("vanish-after-show");
    let id = fresh_id(1510);
    let (code, message) = rpc_err(
        &fixture.socket,
        &id,
        "lane.start",
        Some(start_params(
            &id,
            &replacement_id,
            &digest,
            "nonce-0001",
            SUCCESSOR_SESSION,
            live_admission(),
        )),
    );
    assert_eq!(code, "refusal.unavailable.harness", "{message}");
    let status = status_of(&fixture.socket, 1520, &replacement_id);
    assert_eq!(
        field_str(successor_of(&status), "delivery"),
        "none",
        "the undelivered boundary stays retryable"
    );
    assert_eq!(
        field_int(successor_of(&status), "attempts"),
        1,
        "the undelivered attempt is counted"
    );
    fixture.write_fake_workspace();
    fixture.set_mode("ready");
    let result = start(
        &fixture.socket,
        &fresh_id(1530),
        &replacement_id,
        &digest,
        "nonce-0001",
        SUCCESSOR_SESSION,
    );
    assert_eq!(
        field_str(replacement_of(start_of(&result)), "phase"),
        "adopting",
        "the bounded same-nonce retry re-attempted the spawn"
    );
    assert_eq!(
        field_int(successor_of(start_of(&result)), "attempts"),
        2,
        "the bounded retry policy counted exactly one more attempt"
    );

    shutdown(daemon);
}

/// AC7 (adoption half): an interrupted `lane.adopt` claim commits nothing and
/// repeats nothing; a fresh request reconciles the same evidence and adopts
/// exactly once (the adoption carries no spawn).
#[test]
fn adopt_crash_and_fresh_retry_after_restart() {
    let fixture = Fixture::new("start-adopt-crash");
    fixture.set_mode("ready");
    fixture.write_fake_workspace();
    // Only the adoption crashes; the start is unaffected by this point.
    let mut daemon = fixture.spawn(Some("lane-adopt.after-intent"));
    wait_ready(&fixture);

    let (replacement_id, _digest) = started_record(
        &fixture,
        1800,
        "lane-orch-40",
        "implementer",
        None,
        "sa-acrash",
    );
    let status = status_of(&fixture.socket, 1815, &replacement_id);
    let successor_id = field_str(successor_of(&status), "successor_id").to_string();
    let invocations_before = fixture.invocations();

    let id = fresh_id(1820);
    rpc_unchecked(
        &fixture.socket,
        &id,
        "lane.adopt",
        Some(adopt_params(
            &id,
            &replacement_id,
            &successor_id,
            adoption_observation("implementer"),
        )),
    );
    wait_crash(&mut daemon);

    let daemon = fixture.spawn(None);
    wait_ready(&fixture);

    // The interrupted adoption committed nothing and invoked nothing.
    assert_eq!(
        fixture.invocations(),
        invocations_before,
        "the interrupted adoption spawned nothing"
    );
    let parked = status_of(&fixture.socket, 1830, &replacement_id);
    assert_eq!(
        field_str(replacement_of(&parked), "phase"),
        "adopting",
        "the interrupted adoption committed no phase transition"
    );
    assert_eq!(
        field_str(successor_of(&parked), "adopted_at"),
        "",
        "the successor is never adopted by a crashed claim"
    );

    // A FRESH request (the interrupted claim stays parked) adopts once.
    let id = fresh_id(1845);
    let result = rpc_ok(
        &fixture.socket,
        &id,
        "lane.adopt",
        Some(adopt_params(
            &id,
            &replacement_id,
            &successor_id,
            adoption_observation("implementer"),
        )),
    );
    assert_eq!(
        field_str(replacement_of(adoption_of(&result)), "phase"),
        "adopted",
        "the fresh request reconciles the same evidence and adopts"
    );
    assert_eq!(
        fixture
            .invocations()
            .iter()
            .filter(|line| line.starts_with("session start"))
            .count(),
        1,
        "the fresh adoption re-verifies (read-back) and never spawns a second session"
    );

    shutdown(daemon);
}
