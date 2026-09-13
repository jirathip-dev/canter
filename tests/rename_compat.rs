//! Issue #106 product-rename compatibility, exercised against the REAL
//! built binaries:
//!
//! 1. the pre-rename `herdr-fleet` alias binary runs the identical CLI
//!    (canonical `canter` identity + deprecation warning);
//! 2. a pre-existing pre-rename state/runtime tree is adopted **in place**
//!    and reused across processes (state continuity; nothing copied, moved,
//!    or deleted);
//! 3. a pre-rename config path is still discovered, and the new path wins
//!    when both exist.
//!
//! Normative rule: docs/contracts/compatibility.md, "Product rename
//! (issue #106)". Every path here is a per-test temp fixture: nothing
//! touches host state, the service manager, or the network.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use canter::client::Connection;
use canter::dirs::{DIR_NAME, LEGACY_DIR_NAME};
use canter::value::Val;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_canter")
}

/// The pre-rename alias binary built from `src/bin/herdr-fleet.rs`.
fn legacy_bin() -> &'static str {
    env!("CARGO_BIN_EXE_herdr-fleet")
}

/// The pre-rename config directory name (docs/contracts/compatibility.md).
const LEGACY_CONFIG_DIR: &str = "herdr-fleet";

const PRE_RENAME_CONFIG: &str = r#"schema = "hf-config/v1"
[repository.widgets]
origin = "https://github.com/example-org/widgets"
branch = "staging"
"#;

#[test]
fn pre_rename_alias_binary_runs_the_identical_cli() {
    let version = Command::new(legacy_bin())
        .arg("--version")
        .output()
        .expect("spawn the pre-rename alias binary");
    assert!(
        version.status.success(),
        "--version through the alias must exit 0"
    );
    let stdout = String::from_utf8_lossy(&version.stdout);
    let stderr = String::from_utf8_lossy(&version.stderr);
    assert!(
        stdout.starts_with(concat!("canter ", env!("CARGO_PKG_VERSION"))),
        "the alias must print the canonical identity, got: {stdout}"
    );
    assert!(
        stdout.contains(&format!(
            "state schema version: {}",
            canter::state::SCHEMA_VERSION
        )),
        "the alias must keep printing the schema facts, got: {stdout}"
    );
    assert!(
        stderr.contains("`herdr-fleet` is the pre-rename name of `canter`"),
        "the alias must warn on stderr, got: {stderr}"
    );

    // The alias delegates to the same CLI surface, not a stale copy of it.
    let help = Command::new(legacy_bin())
        .arg("--help")
        .output()
        .expect("spawn the pre-rename alias binary");
    assert!(
        help.status.success(),
        "--help through the alias must exit 0"
    );
    let usage = String::from_utf8_lossy(&help.stdout);
    for needle in [
        "canter --version",
        "canter daemon run",
        "canter service install-plan",
    ] {
        assert!(
            usage.contains(needle),
            "alias --help must document `{needle}`, got: {usage}"
        );
    }
}

struct Fixture {
    dir: PathBuf,
}

impl Fixture {
    fn new() -> Fixture {
        // Short runtime-derived base: the derived per-user socket must fit
        // the Unix socket path limit (SUN_LEN), so the fixture directory
        // name stays compact.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() % 1_000_000_000)
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!("hf106-{}-{nanos}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("fixture dir");
        Fixture { dir }
    }

    fn state_home(&self) -> PathBuf {
        self.dir.join("s")
    }

    fn runtime_dir(&self) -> PathBuf {
        self.dir.join("r")
    }

    /// The fixture's own (empty) config home. Discovery must never read the
    /// developer's ambient `$XDG_CONFIG_HOME`/`~/.config/canter/config.toml`:
    /// an ambient `[daemon] socket` would replace the derived socket this
    /// test exists to pin.
    fn config_home(&self) -> PathBuf {
        self.dir.join("c")
    }

    /// Spawn `canter daemon run` WITHOUT a socket override: both the state
    /// tree and the socket directory must derive from the fixture XDG homes,
    /// which is exactly what proves the adoption rule.
    fn spawn_daemon(&self) -> Child {
        let stderr = std::fs::File::create(self.dir.join("daemon.stderr.log")).expect("stderr log");
        Command::new(bin())
            .args(["daemon", "run"])
            .env("XDG_STATE_HOME", self.state_home())
            .env("XDG_RUNTIME_DIR", self.runtime_dir())
            .env("XDG_CONFIG_HOME", self.config_home())
            .env("HOME", &self.dir)
            .stdout(Stdio::null())
            .stderr(Stdio::from(stderr))
            .spawn()
            .expect("spawn daemon")
    }
}

fn stop(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn wait_ready(fixture: &Fixture, socket: &Path) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if canter::lock::socket_presence(socket) == canter::lock::SocketPresence::Active {
            let ok = Connection::open(socket)
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
        socket.display()
    );
}

/// The `state` object of a live `status` RPC response.
fn status_state(socket: &Path) -> Val {
    let mut connection = Connection::open(socket).expect("connect to the daemon");
    connection
        .send_request("aaaaaaaaaaaaaaab", "status", None)
        .expect("send status");
    let response = connection.read_response().expect("read status response");
    assert!(response.ok, "status must be ok");
    response.result.get("state").expect("status.state").clone()
}

#[test]
fn pre_rename_state_tree_is_adopted_in_place_and_reused() {
    let fixture = Fixture::new();
    let legacy_state = fixture.state_home().join(LEGACY_DIR_NAME);
    std::fs::create_dir_all(&legacy_state).expect("pre-create the pre-rename state dir");
    // A pre-existing user file: it must survive untouched (no destructive
    // migration, no wipe, no rewrite).
    let marker = legacy_state.join("pre-rename-marker.txt");
    let marker_bytes = b"pre-existing state written before the rename\n";
    std::fs::write(&marker, marker_bytes).expect("marker");

    // Phase 1: a fresh process opens the pre-rename tree in place and serves
    // on the pre-rename socket directory.
    let socket = fixture
        .runtime_dir()
        .join(LEGACY_DIR_NAME)
        .join("daemon.sock");
    let mut child = fixture.spawn_daemon();
    wait_ready(&fixture, &socket);
    let state = status_state(&socket);
    let epoch_first = state.get("epoch").and_then(Val::as_int).expect("epoch");
    assert_eq!(
        state.get("schema_version").and_then(Val::as_int),
        Some(canter::state::SCHEMA_VERSION),
        "the adopted tree must migrate/read at the delivered schema version"
    );
    assert!(
        legacy_state.join("state.db").is_file(),
        "the daemon must open its state in the pre-rename tree"
    );
    assert!(
        !fixture.state_home().join(DIR_NAME).exists(),
        "the new-name tree must not be created while the old one is adopted"
    );
    stop(&mut child);

    // The pre-existing fixture survived byte-for-byte.
    assert_eq!(
        std::fs::read(&marker).expect("marker readable"),
        marker_bytes,
        "a pre-existing file in the adopted tree must be untouched"
    );
    assert!(
        legacy_state.join("daemon.log").is_file(),
        "the daemon log stays in the adopted tree"
    );

    // Phase 2: a later process (an upgrade) keeps using the same tree —
    // continuity, not a fresh state.
    let mut child = fixture.spawn_daemon();
    wait_ready(&fixture, &socket);
    let state = status_state(&socket);
    assert_eq!(
        state.get("epoch").and_then(Val::as_int),
        Some(epoch_first),
        "the same state epoch must persist across processes"
    );
    stop(&mut child);
    assert_eq!(
        std::fs::read(&marker).expect("marker readable"),
        marker_bytes
    );
    assert!(!fixture.state_home().join(DIR_NAME).exists());
}

#[test]
fn pre_rename_config_path_is_discovered_and_the_new_path_wins() {
    let fixture = Fixture::new();
    let home = fixture.dir.join("home");
    let legacy_config = home.join(".config").join(LEGACY_CONFIG_DIR);
    std::fs::create_dir_all(&legacy_config).expect("pre-rename config dir");
    std::fs::write(legacy_config.join("config.toml"), PRE_RENAME_CONFIG).expect("config");

    let run_validate = || {
        Command::new(bin())
            .args(["config", "validate"])
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("LANG", "C")
            .env("HOME", &home)
            .output()
            .expect("spawn canter")
    };

    // Only the pre-rename config exists: it must be discovered and read in
    // place (no copy, no rewrite).
    let out = run_validate();
    assert!(
        out.status.success(),
        "a pre-rename config must validate; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains(&format!(".config/{LEGACY_CONFIG_DIR}/config.toml")),
        "the pre-rename config path must be the one reported, got: {stdout}"
    );

    // Both exist: the new path is authoritative.
    let new_config = home.join(".config").join(DIR_NAME);
    std::fs::create_dir_all(&new_config).expect("new config dir");
    std::fs::write(new_config.join("config.toml"), PRE_RENAME_CONFIG).expect("config");
    let out = run_validate();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains(&format!(".config/{DIR_NAME}/config.toml")),
        "the new config path must win when both exist, got: {stdout}"
    );
}
