//! Issue #5 acceptance integration tests over the real binary and socket
//! (AC1 single writer/containment, AC4 crash boundaries + restart
//! reconcile, AC5 fail closed, AC6 spent claims, AC7 events).
//!
//! Every test spawns `canter daemon run` as a child process with
//! isolated XDG state and an explicit socket under a per-test temp dir;
//! nothing here touches the real host state or the service manager.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use canter::client::{Connection, RpcError};
use canter::dirs::DaemonPaths;
use canter::value::{Val, integer, object, string};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_canter")
}

struct Fixture {
    dir: PathBuf,
    state_dir: PathBuf,
    socket: PathBuf,
}

impl Fixture {
    fn new(name: &str) -> Fixture {
        let dir = std::env::temp_dir().join(format!("hf-it-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("fixture dir");
        Fixture {
            state_dir: dir.join("state"),
            socket: dir.join("daemon.sock"),
            dir,
        }
    }

    fn paths(&self) -> DaemonPaths {
        // The daemon child runs with XDG_STATE_HOME=fixture.state_dir, so the
        // daemon state root is state_dir/canter (do not derive from the
        // test process environment).
        let state_dir = self.state_dir.join("canter");
        DaemonPaths {
            state_dir: state_dir.clone(),
            runtime_dir: self.dir.clone(),
            socket_path: self.socket.clone(),
            // The single-writer lock lives in the STATE dir (AC1: one writer
            // per state dir regardless of socket path).
            lock_path: state_dir.join("daemon.lock"),
            db_path: state_dir.join("state.db"),
            audit_mirror_path: state_dir.join("journal").join("audit.jsonl"),
            events_mirror_path: state_dir.join("journal").join("events.jsonl"),
            backups_dir: state_dir.join("backups"),
            checkpoints_dir: state_dir.join("checkpoints"),
            log_path: state_dir.join("daemon.log"),
        }
    }

    fn spawn(&self, crash_point: Option<&str>) -> Child {
        self.spawn_with(&self.socket, &self.state_dir, crash_point)
    }

    /// Spawn a daemon with an explicit socket path and state home (used to
    /// prove the writer lock binds the state dir, not the socket dir).
    fn spawn_with(&self, socket: &Path, state_home: &Path, crash_point: Option<&str>) -> Child {
        let mut command = Command::new(bin());
        let socket_name = socket
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| "daemon".to_string());
        let stderr_path = self.dir.join(format!("{socket_name}.stderr.log"));
        let stderr_file = std::fs::File::create(&stderr_path).expect("stderr log");
        command
            .args(["daemon", "run", "--socket"])
            .arg(socket)
            .env("XDG_STATE_HOME", state_home)
            .env("HOME", &self.dir)
            .stdout(Stdio::null())
            .stderr(Stdio::from(stderr_file));
        if let Some(point) = crash_point {
            command.env("CANTER_CRASH_POINT", point);
        }
        command.spawn().expect("spawn daemon")
    }
}

/// Wait until the daemon answers `status` on the socket (bounded).
fn wait_ready(fixture: &Fixture) {
    let deadline = Instant::now() + Duration::from_secs(15);
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
    let stderr_log = fixture.dir.join("daemon.stderr.log");
    let stderr_text = std::fs::read_to_string(&stderr_log).unwrap_or_default();
    panic!(
        "daemon did not become ready on {}; stderr:\n{}",
        fixture.socket.display(),
        stderr_text
    );
}

/// A single RPC exchange returning the response (ok or refused).
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
        "expected ok response for {method}: {}",
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

fn fresh_id(seed: u32) -> String {
    format!("{:08x}", seed + std::process::id())
}

/// Send one request and drop the connection without reading the response
/// (used when the daemon aborts mid-handling at a crash point).
fn send_only(socket: &Path, id: &str, method: &str, params: Val) {
    let mut connection = Connection::open(socket).expect("connect");
    connection
        .send_request(id, method, Some(&params))
        .expect("send crash request");
    drop(connection);
}

fn backup_params(key: &str) -> Val {
    object(vec![("idempotency_key", string(key))])
}

fn wait_exit(mut child: Child, label: &str) -> i32 {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            return status.code().unwrap_or(-1);
        }
        assert!(Instant::now() < deadline, "{label} did not exit in time");
        std::thread::sleep(Duration::from_millis(25));
    }
}

// ---------------------------------------------------------------------------
// AC1: single writer, socket perms, symlink containment, stale recovery
// ---------------------------------------------------------------------------

#[test]
fn second_daemon_is_refused_while_first_runs() {
    let fixture = Fixture::new("ac1-busy");
    let first = fixture.spawn(None);
    wait_ready(&fixture);

    // A second daemon on the same socket must fail with daemon.busy (exit 1).
    let output = Command::new(bin())
        .args([
            "daemon",
            "run",
            "--socket",
            fixture.socket.to_str().unwrap(),
            "--json",
        ])
        .env("XDG_STATE_HOME", &fixture.state_dir)
        .output()
        .expect("second daemon");
    assert_eq!(output.status.code(), Some(1), "second daemon must exit 1");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(stdout.contains("daemon.busy"), "stdout: {stdout}");

    let mut first = first;
    let _ = first.kill();
    wait_exit(first, "first daemon");
}

// The child is bounded on every path: the try_wait loop reaps a refused
// daemon; the fallback kills and wait()s it before panicking.
#[allow(clippy::zombie_processes)]
#[test]
fn two_daemons_with_different_sockets_but_shared_state_cannot_both_write() {
    // AC1 hole regression: the writer lock must be bound to the STATE dir.
    // Two daemons with different --socket paths but the same XDG_STATE_HOME
    // must not both run: the second refuses with daemon.busy.
    let fixture = Fixture::new("ac1-shared-state");
    let first = fixture.spawn(None);
    wait_ready(&fixture);

    let other_socket = fixture.dir.join("other.sock");
    let mut second = Command::new(bin())
        .args([
            "daemon",
            "run",
            "--socket",
            other_socket.to_str().unwrap(),
            "--json",
        ])
        .env("XDG_STATE_HOME", &fixture.state_dir)
        .env("HOME", &fixture.dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("second daemon (different socket, same state)");

    // Bounded wait: a correct lock refuses quickly (exit 1, daemon.busy);
    // the pre-fix behavior (socket-scoped lock) would keep serving forever.
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut refused = false;
    while Instant::now() < deadline {
        if let Some(status) = second.try_wait().expect("try_wait") {
            assert_eq!(
                status.code(),
                Some(1),
                "shared-state second daemon must exit 1"
            );
            refused = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    if !refused {
        let _ = second.kill();
        wait_exit(second, "second daemon");
        panic!(
            "second daemon with a DIFFERENT socket and the SAME state dir must be refused (writer lock must bind the state dir)"
        );
    }
    let mut stdout = String::new();
    use std::io::Read;
    second
        .stdout
        .take()
        .expect("stdout")
        .read_to_string(&mut stdout)
        .expect("read stdout");
    assert!(stdout.contains("daemon.busy"), "stdout: {stdout}");

    // The first daemon is unaffected and still serves its socket.
    let status = rpc_ok(&fixture.socket, &fresh_id(3), "status", None);
    assert!(status.get("state").and_then(|s| s.get("epoch")).is_some());

    let mut first = first;
    let _ = first.kill();
    wait_exit(first, "first daemon");
}

#[test]
fn daemons_with_distinct_state_dirs_coexist() {
    // The lock is per STATE dir: a second daemon on its own state dir (even
    // in the same temp tree) must start and serve concurrently.
    let fixture_a = Fixture::new("ac1-coexist-a");
    let daemon_a = fixture_a.spawn(None);
    wait_ready(&fixture_a);

    let fixture_b = Fixture::new("ac1-coexist-b");
    let daemon_b = fixture_b.spawn(None);
    wait_ready(&fixture_b);

    let status_a = rpc_ok(&fixture_a.socket, &fresh_id(4), "status", None);
    let status_b = rpc_ok(&fixture_b.socket, &fresh_id(5), "status", None);
    assert!(status_a.get("state").and_then(|s| s.get("epoch")).is_some());
    assert!(status_b.get("state").and_then(|s| s.get("epoch")).is_some());

    let mut daemon_a = daemon_a;
    let mut daemon_b = daemon_b;
    let _ = daemon_a.kill();
    let _ = daemon_b.kill();
    wait_exit(daemon_a, "daemon a");
    wait_exit(daemon_b, "daemon b");
}

/// r2 blocker regression: a restore.begin must hold the state mutex across
/// the DB-file rename/reopen/swap so no handler can journal into the
/// unlinked old file or observe a half-swapped state. The reviewer's live
/// probe witnesses were: (1) plain mutations refused with state.readonly
/// mid-window, (2) duplicate restored_epoch across successful restores,
/// (3) ok:true mutations absent from the final journal. This test asserts
/// (1) every racing mutation is acknowledged (never a state.* write
/// failure), (2) restored epochs are strictly increasing (never repeated),
/// and (3) mutations acknowledged after a restore response survive every
/// later restore in the final journal. (A mutation acknowledged BEFORE a
/// restore acquires the state lock is legitimately rolled back by that
/// restore — epoch rotation is the visible rollback signal; the race
/// window itself must never lose an ack.)
#[test]
fn restore_racing_acknowledged_mutations_never_loses_acked_intents() {
    let fixture = Fixture::new("ac1-restore-race");
    let daemon = fixture.spawn(None);
    wait_ready(&fixture);

    let mut restored_epochs: Vec<i64> = Vec::new();
    let mut surviving_keys: Vec<String> = Vec::new();

    for round in 0..6u32 {
        // A verified snapshot to restore from.
        let snapshot_key = format!("ik_race-snap-{round:08}");
        let snapshot_doc = rpc_ok(
            &fixture.socket,
            &fresh_id(800 + round),
            "backup.create",
            Some(backup_params(&snapshot_key)),
        );
        let snapshot_name = snapshot_doc
            .get("backup")
            .and_then(|backup| backup.get("snapshot"))
            .and_then(Val::as_str)
            .expect("snapshot")
            .to_string();

        // Fire restore.begin and an acknowledged backup.create mutation at
        // the same time (own connections, two threads).
        let socket_for_restore = fixture.socket.clone();
        let restore_id = fresh_id(900 + round * 2);
        let restore_key = format!("ik_race-restore-{round:08}");
        let restore_params = object(vec![
            ("idempotency_key", string(&restore_key)),
            ("backup", string(&snapshot_name)),
        ]);
        let restore_thread = std::thread::spawn(move || {
            rpc(
                &socket_for_restore,
                &restore_id,
                "restore.begin",
                Some(restore_params),
            )
        });

        let ack_key = format!("ik_race-ack-{round:08}");
        let ack_doc = rpc(
            &fixture.socket,
            &fresh_id(901 + round * 2),
            "backup.create",
            Some(backup_params(&ack_key)),
        );
        // Witness (1): the racing mutation must be acknowledged — never a
        // state.readonly/busy/write failure that only existed inside the
        // unlinked-file window (the reviewer saw 8 of those in 100 rounds).
        assert_eq!(
            ack_doc.get("ok").and_then(Val::as_bool),
            Some(true),
            "racing mutation must be acknowledged, got: {}",
            canter::canonical::canonical_text(&ack_doc)
        );
        // A mutation acknowledged while the restore is in flight must not be
        // lost by THIS restore: it either journaled before the rename (and
        // is rolled back — epoch rotation visible) or after it (survives).
        // Keys acked after the restore response are unconditionally durable
        // across all later rounds; assert them at the end.
        let post_restore_key = format!("ik_race-after-{round:08}");
        let mut restore_doc = restore_thread.join().expect("restore thread joined");
        let mut attempt = 0u32;
        while restore_doc.get("ok").and_then(Val::as_bool) != Some(true) && attempt < 5 {
            attempt += 1;
            std::thread::sleep(Duration::from_millis(25));
            restore_doc = rpc(
                &fixture.socket,
                &fresh_id(920 + round * 2),
                "restore.begin",
                Some(object(vec![
                    ("idempotency_key", string(&restore_key)),
                    ("backup", string(&snapshot_name)),
                ])),
            );
        }
        if restore_doc.get("ok").and_then(Val::as_bool) == Some(true) {
            // Witness (2): each successful restore rotates to a NEW epoch.
            let epoch = restore_doc
                .get("result")
                .and_then(|result| result.get("restored_epoch"))
                .and_then(Val::as_int)
                .expect("restored_epoch");
            if let Some(previous) = restored_epochs.last() {
                assert!(
                    epoch > *previous,
                    "restored epochs must be strictly increasing: {epoch} after {previous}"
                );
            }
            restored_epochs.push(epoch);
            // Ack a mutation AFTER the restore completed; it must survive
            // every later restore (it precedes the next snapshot).
            rpc_ok(
                &fixture.socket,
                &fresh_id(950 + round * 2),
                "backup.create",
                Some(backup_params(&post_restore_key)),
            );
            surviving_keys.push(post_restore_key);
        }
    }

    // Witness (3): mutations acknowledged after a restore response are in
    // the FINAL journal (no later restore may lose them).
    assert!(
        !surviving_keys.is_empty(),
        "at least one post-restore acknowledgement must exist"
    );
    let tail = rpc_ok(
        &fixture.socket,
        &fresh_id(998),
        "journal.tail",
        Some(object(vec![
            ("after_seq", integer(0)),
            ("limit", integer(5000)),
        ])),
    );
    let serialized = canter::canonical::canonical_text(&tail);
    for key in &surviving_keys {
        assert!(
            serialized.contains(key),
            "post-restore acknowledged intent {key} must survive in the final journal (lost-commit regression)"
        );
    }
    assert!(
        !restored_epochs.is_empty(),
        "at least one racing restore must succeed"
    );

    // Clean-shutdown ordering (r2 verdict residual caveat): terminate the
    // daemon with SIGTERM (not SIGKILL), restart it, and confirm the same
    // post-restore acknowledgements are still journaled in the database the
    // restarted daemon opens — i.e. nothing acked after a restore response
    // is lost at the shutdown boundary, and startup reconcile keeps the
    // daemon serving.
    let daemon = daemon;
    let term = Command::new("kill")
        .args(["-TERM", &daemon.id().to_string()])
        .status()
        .expect("kill -TERM");
    assert!(term.success(), "kill -TERM must succeed");
    wait_exit(daemon, "terminated daemon");

    let restarted = fixture.spawn(None);
    wait_ready(&fixture);
    let tail_after_restart = rpc_ok(
        &fixture.socket,
        &fresh_id(997),
        "journal.tail",
        Some(object(vec![
            ("after_seq", integer(0)),
            ("limit", integer(5000)),
        ])),
    );
    let serialized_after_restart = canter::canonical::canonical_text(&tail_after_restart);
    for key in &surviving_keys {
        assert!(
            serialized_after_restart.contains(key),
            "post-restore acknowledged intent {key} must survive a clean shutdown/restart"
        );
    }

    let mut restarted = restarted;
    let _ = restarted.kill();
    wait_exit(restarted, "restarted daemon");
}

#[test]
fn stale_socket_is_reclaimed_and_status_recovers() {
    let fixture = Fixture::new("ac1-stale");
    let daemon = fixture.spawn(None);
    wait_ready(&fixture);

    // Kill -9: the flock dies with the process; the socket file remains.
    let daemon = daemon;
    let kill_status = Command::new("kill")
        .args(["-9", &daemon.id().to_string()])
        .status()
        .expect("kill -9");
    assert!(kill_status.success(), "kill -9 must succeed");
    wait_exit(daemon, "killed daemon");

    // The orphaned socket classifies as stale, and a fresh run reclaims it.
    let (code, _) = daemon_status(&fixture);
    assert_eq!(code, "daemon.stale", "orphaned socket must read stale");

    let second = fixture.spawn(None);
    wait_ready(&fixture);
    let status = rpc_ok(&fixture.socket, &fresh_id(2), "status", None);
    assert!(status.get("state").and_then(|s| s.get("epoch")).is_some());
    let mut second = second;
    let _ = second.kill();
    wait_exit(second, "second daemon");
}

fn daemon_status(fixture: &Fixture) -> (String, String) {
    let output = Command::new(bin())
        .args([
            "daemon",
            "status",
            "--socket",
            fixture.socket.to_str().unwrap(),
            "--json",
        ])
        .env("XDG_STATE_HOME", &fixture.state_dir)
        .output()
        .expect("daemon status");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    if stdout.contains("daemon.stale") {
        ("daemon.stale".to_string(), stdout)
    } else if stdout.contains("daemon.absent") {
        ("daemon.absent".to_string(), stdout)
    } else {
        ("ok".to_string(), stdout)
    }
}

#[test]
fn symlink_socket_is_refused_and_socket_perms_are_private() {
    let fixture = Fixture::new("ac1-symlink");
    // A symlink at the socket path must be refused (containment).
    let target = fixture.dir.join("elsewhere.sock");
    std::fs::write(&target, "x").expect("target");
    std::os::unix::fs::symlink(&target, &fixture.socket).expect("symlink");
    let output = Command::new(bin())
        .args([
            "daemon",
            "run",
            "--socket",
            fixture.socket.to_str().unwrap(),
            "--json",
        ])
        .env("XDG_STATE_HOME", &fixture.state_dir)
        .output()
        .expect("run over symlink");
    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        stdout.contains("daemon.bind") || stdout.contains("lock.unsafe_path"),
        "symlink must be refused: {stdout}"
    );
    assert_eq!(
        std::fs::read_to_string(&target).expect("target intact"),
        "x"
    );

    // Clean run: socket mode is 0600 and the state dir is 0700.
    let _ = std::fs::remove_file(&fixture.socket);
    let daemon = fixture.spawn(None);
    wait_ready(&fixture);
    use std::os::unix::fs::PermissionsExt;
    let socket_mode = std::fs::metadata(&fixture.socket)
        .expect("socket meta")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(socket_mode, 0o600, "socket must be 0600");
    let daemon_state_dir = fixture.paths().state_dir;
    let state_mode = std::fs::metadata(&daemon_state_dir)
        .expect("state meta")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(state_mode, 0o700, "daemon state dir must be 0700");
    let mut daemon = daemon;
    let _ = daemon.kill();
    wait_exit(daemon, "daemon");
}

// ---------------------------------------------------------------------------
// RPC basics + closed methods (parse-time refusals stay typed)
// ---------------------------------------------------------------------------

#[test]
fn closed_method_surface_and_typed_refusals() {
    let fixture = Fixture::new("rpc-surface");
    let daemon = fixture.spawn(None);
    wait_ready(&fixture);

    let capabilities = rpc_ok(&fixture.socket, &fresh_id(1), "capabilities", None);
    let methods: Vec<&str> = capabilities
        .get("methods")
        .and_then(|m| m.as_array())
        .map(|items| items.iter().filter_map(Val::as_str).collect())
        .unwrap_or_default();
    for expected in [
        "capabilities",
        "doctor",
        "status",
        "plan",
        "apply",
        "grants.list",
        "grants.revoke",
        "schedules.list",
        "state.epoch",
        "backup.create",
        "restore.begin",
        "journal.tail",
        "events.subscribe",
    ] {
        assert!(
            methods.contains(&expected),
            "{expected} missing from capabilities"
        );
    }

    // An apply without an idempotency key is refused at parse time.
    let (code, _) = rpc_err(&fixture.socket, &fresh_id(2), "apply", None);
    assert!(code.starts_with("refusal."), "apply w/o key: {code}");

    // An apply with a key reaches the handler; without the full typed
    // params (plan/grant/instance/observed/topology) it is refused with a
    // parse-time refusal and never journals a claim (issue #8 apply).
    let (code, _) = rpc_err(
        &fixture.socket,
        &fresh_id(3),
        "apply",
        Some(object(vec![(
            "idempotency_key",
            string("ik_apply-it-00000001"),
        )])),
    );
    assert_eq!(code, "refusal.malformed");

    // Unknown methods are never guessed.
    let (code, message) = rpc_err(&fixture.socket, &fresh_id(4), "no.such.method", None);
    assert!(
        code.starts_with("refusal.") || message.contains("no.such.method"),
        "{code} {message}"
    );

    let mut daemon = daemon;
    let _ = daemon.kill();
    wait_exit(daemon, "daemon");
}

// ---------------------------------------------------------------------------
// AC4: crash boundaries around backup.create, restart reconcile before retry
// ---------------------------------------------------------------------------

#[test]
fn crash_after_intent_reconciles_ambiguous_and_refuses_replay_until_new_key() {
    let fixture = Fixture::new("ac4-after-intent");
    let key = "ik_crash-intent-00000001";
    let request_id = fresh_id(10);

    let crashed = fixture.spawn(Some("backup.after-intent"));
    wait_ready(&fixture);
    send_only(
        &fixture.socket,
        &request_id,
        "backup.create",
        backup_params(key),
    );
    wait_exit(crashed, "crash at after-intent");

    // Restart: the claim is reconciled as ambiguous BEFORE any retry works.
    let daemon = fixture.spawn(None);
    wait_ready(&fixture);
    let (code, message) = rpc_err(
        &fixture.socket,
        &request_id,
        "backup.create",
        Some(backup_params(key)),
    );
    assert_eq!(code, "state.ambiguous_claim", "{message}");

    // The reconcile is journaled (action reconcile.backup.create).
    let tail = rpc_ok(
        &fixture.socket,
        &fresh_id(11),
        "journal.tail",
        Some(object(vec![
            ("after_seq", integer(0)),
            ("limit", integer(200)),
        ])),
    );
    let records = tail
        .get("records")
        .and_then(|r| r.as_array())
        .expect("records");
    let actions: Vec<String> = records
        .iter()
        .filter_map(|record| {
            record
                .get("action")
                .and_then(Val::as_str)
                .map(str::to_string)
        })
        .collect();
    assert!(
        actions
            .iter()
            .any(|action| action == "reconcile.backup.create"),
        "journal must contain reconcile.backup.create: {actions:?}"
    );

    // A NEW key is accepted after restart reconcile.
    let second_key = "ik_crash-intent-00000002";
    let backup = rpc_ok(
        &fixture.socket,
        &fresh_id(12),
        "backup.create",
        Some(backup_params(second_key)),
    );
    let snapshot = backup
        .get("backup")
        .and_then(|b| b.get("snapshot"))
        .and_then(Val::as_str)
        .expect("snapshot name");
    assert!(
        fixture.paths().backups_dir.join(snapshot).exists(),
        "snapshot artifact must exist"
    );

    let mut daemon = daemon;
    let _ = daemon.kill();
    wait_exit(daemon, "daemon");
}

#[test]
fn crash_after_manifest_leaves_no_claim_and_new_key_converges() {
    let fixture = Fixture::new("ac4-after-manifest");
    let key = "ik_crash-manifest-00000001";
    let request_id = fresh_id(20);

    let crashed = fixture.spawn(Some("backup.after-manifest"));
    wait_ready(&fixture);
    send_only(
        &fixture.socket,
        &request_id,
        "backup.create",
        backup_params(key),
    );
    wait_exit(crashed, "crash at after-manifest");

    // The artifact pair is complete (manifest written before the crash) but
    // the outcome never resolved; restart reconciles the pending claim as
    // ambiguous, then a new key completes a fresh backup.
    let daemon = fixture.spawn(None);
    wait_ready(&fixture);
    let (code, message) = rpc_err(
        &fixture.socket,
        &request_id,
        "backup.create",
        Some(backup_params(key)),
    );
    assert_eq!(code, "state.ambiguous_claim", "{message}");

    let new_key = "ik_crash-manifest-00000002";
    let backup = rpc_ok(
        &fixture.socket,
        &fresh_id(21),
        "backup.create",
        Some(backup_params(new_key)),
    );
    assert!(backup.get("backup").is_some());

    let mut daemon = daemon;
    let _ = daemon.kill();
    wait_exit(daemon, "daemon");
}

// ---------------------------------------------------------------------------
// AC6: spent claims replay; restore rotates the epoch and keeps claims spent
// ---------------------------------------------------------------------------

#[test]
fn spent_claims_replay_and_restore_rotates_epoch() {
    let fixture = Fixture::new("ac6-restore");
    let daemon = fixture.spawn(None);
    wait_ready(&fixture);

    let key_a = "ik_ac6-backup-a-000001";
    let id_a = fresh_id(30);
    let first = rpc_ok(
        &fixture.socket,
        &id_a,
        "backup.create",
        Some(backup_params(key_a)),
    );
    let snapshot_a = first
        .get("backup")
        .and_then(|b| b.get("snapshot"))
        .and_then(Val::as_str)
        .expect("snapshot a")
        .to_string();
    let epoch_before = first
        .get("backup")
        .and_then(|b| b.get("epoch"))
        .and_then(Val::as_int)
        .expect("epoch");

    // Replaying the SAME request returns the recorded response and does not
    // create a second artifact.
    let replay = rpc_ok(
        &fixture.socket,
        &id_a,
        "backup.create",
        Some(backup_params(key_a)),
    );
    let replay_snapshot = replay
        .get("backup")
        .and_then(|b| b.get("snapshot"))
        .and_then(Val::as_str)
        .expect("replay snapshot");
    assert_eq!(replay_snapshot, snapshot_a, "replay must not re-dispatch");

    // A second request with the same key but a different id is refused.
    let (code, _) = rpc_err(
        &fixture.socket,
        &fresh_id(31),
        "backup.create",
        Some(backup_params(key_a)),
    );
    assert_eq!(code, "state.claim_reused", "key reuse must be refused");

    // Restore the latest verified backup: new epoch, replay-safe.
    let restore_key = "ik_ac6-restore-00000001";
    let restore_id = fresh_id(32);
    let restore = rpc_ok(
        &fixture.socket,
        &restore_id,
        "restore.begin",
        Some(object(vec![
            ("idempotency_key", string(restore_key)),
            ("backup", string(&snapshot_a)),
        ])),
    );
    let restored_epoch = restore
        .get("restored_epoch")
        .and_then(Val::as_int)
        .expect("epoch");
    assert_eq!(
        restored_epoch,
        epoch_before + 1,
        "restore must rotate the epoch"
    );

    // The spent backup.create claim still replays (never runnable again).
    // The spent backup.create claim predates the restored snapshot: the
    // restore voids it (the snapshot captured it mid-flight), so the same
    // request is refused as ambiguous instead of replaying or re-dispatching.
    let (code, message) = rpc_err(
        &fixture.socket,
        &id_a,
        "backup.create",
        Some(backup_params(key_a)),
    );
    assert_eq!(
        code, "state.ambiguous_claim",
        "restored claim must be voided: {message}"
    );

    // A fresh key works in the restored epoch.
    let key_b = "ik_ac6-backup-b-000002";
    let fresh = rpc_ok(
        &fixture.socket,
        &fresh_id(33),
        "backup.create",
        Some(backup_params(key_b)),
    );
    let fresh_epoch = fresh
        .get("backup")
        .and_then(|b| b.get("epoch"))
        .and_then(Val::as_int);
    assert_eq!(
        fresh_epoch,
        Some(restored_epoch),
        "fresh backup journals in the restored epoch"
    );

    // Replaying the restore itself returns the recorded response and does
    // not rotate the epoch twice.
    let replay3 = rpc_ok(
        &fixture.socket,
        &restore_id,
        "restore.begin",
        Some(object(vec![
            ("idempotency_key", string(restore_key)),
            ("backup", string(&snapshot_a)),
        ])),
    );
    assert_eq!(
        replay3.get("restored_epoch").and_then(Val::as_int),
        Some(restored_epoch),
        "replayed restore must not rotate again"
    );

    let mut daemon = daemon;
    let _ = daemon.kill();
    wait_exit(daemon, "daemon");
}

// ---------------------------------------------------------------------------
// AC7: subscribe snapshot/replay ordering, future cursor resnapshot, and
// bounded backpressure disconnect
// ---------------------------------------------------------------------------

#[test]
fn subscribe_resnapshots_future_cursors_and_replays_contiguously() {
    let fixture = Fixture::new("ac7-events");
    let daemon = fixture.spawn(None);
    wait_ready(&fixture);

    // Produce some events: two successful backup.create mutations.
    for index in 0..2 {
        let key = format!("ik_ac7-ev-{index:08}");
        rpc_ok(
            &fixture.socket,
            &fresh_id(40 + index),
            "backup.create",
            Some(backup_params(&key)),
        );
    }
    let max_seq = rpc_ok(&fixture.socket, &fresh_id(42), "state.epoch", None)
        .get("epoch")
        .map(|_| 0i64)
        .unwrap_or(0);

    // Fresh subscribe (no cursor): ok response, then a snapshot line.
    let mut subscription =
        canter::client::EventSubscription::open(&fixture.socket, None).expect("subscribe");
    let snapshot_line = subscription
        .next_line()
        .expect("snapshot")
        .expect("daemon closed early");
    let snapshot = Val::parse_json(&snapshot_line).expect("snapshot parses");
    assert_eq!(
        snapshot.get("event").and_then(Val::as_str),
        Some("state.snapshot")
    );
    let _ = max_seq;
    drop(subscription);

    // A future cursor is answered with a fresh snapshot (gap detection).
    let mut future = canter::client::EventSubscription::open(&fixture.socket, Some(1 << 30))
        .expect("subscribe future");
    let future_line = future.next_line().expect("line").expect("closed");
    let future_doc = Val::parse_json(&future_line).expect("parse");
    assert_eq!(
        future_doc.get("event").and_then(Val::as_str),
        Some("state.snapshot"),
        "a future cursor must be answered with a resnapshot"
    );
    drop(future);

    // Live events stream in strictly increasing seq order while subscribed.
    let mut live =
        canter::client::EventSubscription::open(&fixture.socket, None).expect("subscribe live");
    let _snapshot = live.next_line().expect("snapshot").expect("closed");
    let mut last_seq = 0i64;
    for index in 3..6 {
        let key = format!("ik_ac7-live-{index:08}");
        rpc_ok(
            &fixture.socket,
            &fresh_id(50 + index),
            "backup.create",
            Some(backup_params(&key)),
        );
        let line = live
            .next_line()
            .expect("live event")
            .expect("daemon closed the stream early");
        let doc = Val::parse_json(&line).expect("event parses");
        let seq = doc.get("seq").and_then(Val::as_int).expect("seq");
        assert!(
            seq > last_seq,
            "seqs must be strictly increasing: {seq} after {last_seq}"
        );
        last_seq = seq;
    }

    // A contiguous replay resumes from a real cursor without a snapshot.
    let mut replay = canter::client::EventSubscription::open(&fixture.socket, Some(last_seq))
        .expect("subscribe replay");
    let replay_line = replay
        .next_line()
        .expect("replay event")
        .expect("closed early");
    let replay_doc = Val::parse_json(&replay_line).expect("parse");
    let replay_seq = replay_doc
        .get("seq")
        .and_then(Val::as_int)
        .expect("replay seq");
    assert!(replay_seq > last_seq, "replay resumes after the cursor");

    let mut daemon = daemon;
    let _ = daemon.kill();
    wait_exit(daemon, "daemon");
}

#[test]
fn non_draining_subscriber_is_disconnected_under_backpressure() {
    let fixture = Fixture::new("ac7-backpressure");
    let daemon = fixture.spawn(None);
    wait_ready(&fixture);

    // Subscribe but never read the socket: the queue fills and the daemon
    // drops the subscriber (bounded backpressure) while mutations still
    // succeed.
    let socket_path = fixture.socket.clone();
    let mut stream = UnixStream::connect(&socket_path).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("bound subscriber reads");
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .expect("bound subscriber writes");
    let mut reader = BufReader::new(stream.try_clone().expect("clone"));
    let request = format!(
        "{}\n",
        canter::canonical::canonical_text(&object(vec![
            ("schema", string("hf-rpc-request/v1")),
            ("id", string(&fresh_id(60))),
            ("method", string("events.subscribe")),
            ("params", canter::value::null()),
        ]))
    );
    stream
        .write_all(request.as_bytes())
        .expect("subscribe request");
    let mut response = String::new();
    reader.read_line(&mut response).expect("subscribe response");
    assert!(response.contains("event_stream"), "{response}");

    let cap = canter::daemon::SUBSCRIBER_QUEUE_CAP;
    let storm_requests = cap + 64;
    for index in 0..storm_requests {
        let key = format!("ik_ac7-bp-{index:08}");
        let doc = rpc(
            &fixture.socket,
            &fresh_id(70u32 + index as u32),
            "backup.create",
            Some(backup_params(&key)),
        );
        assert_eq!(
            doc.get("ok").and_then(Val::as_bool),
            Some(true),
            "mutations must keep succeeding under a stalled subscriber"
        );
    }
    // Each mutation journals two events (intent + outcome).
    let storm_events = storm_requests * 2;

    // Drain under the read bound configured before subscription: the daemon
    // must disconnect the stalled subscriber (bounded queue + socket buffer)
    // instead of delivering the whole storm, while the mutations themselves
    // all succeeded.
    let mut saw_lines = 0usize;
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let mut line = String::new();
        let read = match reader.read_line(&mut line) {
            Ok(read) => read,
            Err(err)
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                assert!(Instant::now() < deadline, "subscriber never disconnected");
                continue;
            }
            Err(err) => panic!("read from stalled subscription: {err}"),
        };
        if read == 0 {
            break; // daemon dropped us (EOF)
        }
        saw_lines += 1;
        assert!(Instant::now() < deadline, "subscriber never disconnected");
    }
    assert!(
        saw_lines >= 1,
        "the subscriber must have received at least the queued prefix"
    );
    assert!(
        saw_lines < storm_events,
        "bounded backpressure must drop events (saw {saw_lines} of {storm_events})"
    );

    let mut daemon = daemon;
    let _ = daemon.kill();
    wait_exit(daemon, "daemon");
}

// ---------------------------------------------------------------------------
// AC5: fail closed when state writes cannot proceed
// ---------------------------------------------------------------------------

#[test]
fn readonly_state_dir_fails_closed_and_poisons_mutations() {
    let fixture = Fixture::new("ac5-failclosed");
    let daemon = fixture.spawn(None);
    wait_ready(&fixture);

    use std::os::unix::fs::PermissionsExt;
    let state_dir = fixture.paths().state_dir.clone();
    let dir_mode = std::fs::metadata(&state_dir).expect("meta").permissions();
    std::fs::set_permissions(&state_dir, std::fs::Permissions::from_mode(0o500))
        .expect("make readonly");

    // A mutation that cannot journal fails closed with a write error...
    let key = "ik_ac5-ro-00000001";
    let (code, _) = rpc_err(
        &fixture.socket,
        &fresh_id(80),
        "backup.create",
        Some(backup_params(key)),
    );
    assert!(
        code.starts_with("state.write_")
            || code.starts_with("state.readonly")
            || code.starts_with("state.busy"),
        "expected a fail-closed write error, got {code}"
    );

    // ...and the daemon poisons itself: even after the dir is writable
    // again, later mutations are refused until a restart.
    std::fs::set_permissions(&state_dir, dir_mode).expect("restore perms");
    let key2 = "ik_ac5-ro-00000002";
    let (code2, _) = rpc_err(
        &fixture.socket,
        &fresh_id(81),
        "backup.create",
        Some(backup_params(key2)),
    );
    assert_eq!(
        code2, "state.poisoned",
        "fail-closed poison must hold: {code2}"
    );

    let mut daemon = daemon;
    let _ = daemon.kill();
    wait_exit(daemon, "daemon");
}
