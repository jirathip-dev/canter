//! Issue #5 AC9: service doctor/install/status/uninstall PLANS are pure
//! fixtures — no launchd/systemd activation happens on the host. The
//! rendered unit and the step commands are asserted here; the same plans
//! are what a clean-host fixture runner executes (see .report-5.md for the
//! documented fixture-host commands).
//!
//! No test in this file loads, starts, or touches a real service.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_canter")
}

/// A fixture home/config layout: nothing outside this dir is read or
/// written by the commands under test.
struct ServiceFixture {
    dir: PathBuf,
}

impl ServiceFixture {
    fn new(name: &str) -> ServiceFixture {
        let dir = std::env::temp_dir().join(format!("hf-svc-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("config")).expect("fixture config dir");
        std::fs::create_dir_all(dir.join("state")).expect("fixture state dir");
        std::fs::create_dir_all(dir.join("runtime")).expect("fixture runtime dir");
        ServiceFixture { dir }
    }

    fn command(&self) -> Command {
        let mut command = Command::new(binary());
        command
            .env("HOME", &self.dir)
            .env("XDG_CONFIG_HOME", self.dir.join("config"))
            .env("XDG_STATE_HOME", self.dir.join("state"))
            .env("XDG_RUNTIME_DIR", self.dir.join("runtime"))
            .env_remove("CANTER_CRASH_POINT");
        command
    }

    /// Run a command, returning (exit_code, stdout, stderr).
    fn run(&self, args: &[&str]) -> (i32, String, String) {
        self.run_with_env(args, &[])
    }

    /// Run a command with explicit environment pairs on top of the fixture
    /// environment — e.g. the invoking PATH a rendered unit's PATH derives
    /// from (issue #266).
    fn run_with_env(&self, args: &[&str], env: &[(&str, &str)]) -> (i32, String, String) {
        let mut command = self.command();
        command.args(args);
        for (name, value) in env {
            command.env(name, value);
        }
        let mut child = command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn canter");
        let mut stdout = String::new();
        let mut stderr = String::new();
        use std::io::Read;
        child
            .stdout
            .take()
            .expect("stdout")
            .read_to_string(&mut stdout)
            .expect("read stdout");
        child
            .stderr
            .take()
            .expect("stderr")
            .read_to_string(&mut stderr)
            .expect("read stderr");
        let status = child.wait().expect("wait");
        (status.code().unwrap_or(-1), stdout, stderr)
    }
}

impl Drop for ServiceFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Write a minimal config under the fixture XDG dirs.
fn write_config(fixture: &ServiceFixture, socket: &Path) {
    let config_dir = fixture.dir.join("config").join("canter");
    std::fs::create_dir_all(&config_dir).expect("config dir");
    let mut file = std::fs::File::create(config_dir.join("config.toml")).expect("config file");
    write!(
        file,
        "schema = \"hf-config/v1\"\n[daemon]\nsocket = \"{}\"\n",
        socket.display()
    )
    .expect("write config");
}

/// Write a config that also declares ONE harness entry whose executable the
/// rendered unit's PATH must be able to resolve (issue #266).
fn write_config_with_harness(fixture: &ServiceFixture, socket: &Path, key: &str, executable: &str) {
    let config_dir = fixture.dir.join("config").join("canter");
    std::fs::create_dir_all(&config_dir).expect("config dir");
    let mut file = std::fs::File::create(config_dir.join("config.toml")).expect("config file");
    write!(
        file,
        "schema = \"hf-config/v1\"\n[daemon]\nsocket = \"{}\"\n[harness.{}]\nkind = \"hermes\"\n\
         executable = \"{}\"\nenv_allow = [\"PATH\", \"HOME\"]\n",
        socket.display(),
        key,
        executable
    )
    .expect("write config");
}

/// Install a fake harness executable under the fixture's own bin dir (which
/// is NOT any service-manager default PATH) and return that bin dir.
fn install_fake_harness(fixture: &ServiceFixture, name: &str) -> PathBuf {
    let bin_dir = fixture.dir.join("bin");
    std::fs::create_dir_all(&bin_dir).expect("bin dir");
    let executable = bin_dir.join(name);
    let mut file = std::fs::File::create(&executable).expect("harness file");
    write!(file, "#!/bin/sh\nexit 0\n").expect("write harness");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755))
            .expect("chmod harness");
    }
    bin_dir
}

#[test]
fn service_doctor_reports_platform_and_read_only_rows() {
    let fixture = ServiceFixture::new("doctor");
    let (exit, stdout, _stderr) = fixture.run(&["service", "doctor", "--json"]);
    assert_eq!(exit, 0, "doctor exits 0 on a clean fixture: {stdout}");
    assert!(stdout.contains("\"kind\":\"ok\""), "{stdout}");
    // Platform is one of the supported unit families; no activation happened.
    let platform = if cfg!(target_os = "macos") {
        "launchd"
    } else if cfg!(target_os = "linux") {
        "systemd"
    } else {
        "unsupported"
    };
    assert!(
        stdout.contains(&format!("\"platform\":\"{platform}\"")),
        "{stdout}"
    );
    assert!(stdout.contains("doctor"), "{stdout}");
}

#[test]
fn service_install_plan_renders_a_fixture_unit_with_steps() {
    let fixture = ServiceFixture::new("install-plan");
    let socket = fixture.dir.join("runtime").join("daemon.sock");
    write_config(&fixture, &socket);

    let (exit, stdout, _stderr) = fixture.run(&["service", "install-plan", "--json"]);
    assert_eq!(exit, 0, "install-plan exits 0: {stdout}");

    let platform = if cfg!(target_os = "macos") {
        "launchd"
    } else if cfg!(target_os = "linux") {
        "systemd"
    } else {
        "unsupported"
    };
    assert!(
        stdout.contains(&format!("\"platform\":\"{platform}\"")),
        "{stdout}"
    );
    // The unit text and the concrete install steps are part of the plan.
    let unit = if cfg!(target_os = "macos") {
        "<key>Label</key>"
    } else {
        "ExecStart="
    };
    assert!(stdout.contains(unit), "unit content missing: {stdout}");
    assert!(stdout.contains("\"steps\""), "{stdout}");
    if cfg!(target_os = "macos") {
        assert!(stdout.contains("<key>ProgramArguments</key>"), "{stdout}");
    } else {
        assert!(stdout.contains("canter daemon run"), "{stdout}");
    }
    // The plan *documents* the fixture-host activation command (install
    // plans are executed on clean supported hosts, never on this one); the
    // unit and every step target the fixture socket path.
    let activation = if cfg!(target_os = "macos") {
        "launchctl bootstrap"
    } else {
        "systemctl --user enable"
    };
    assert!(stdout.contains(activation), "{stdout}");
    assert!(
        stdout.contains("daemon.sock"),
        "plan targets the fixture socket: {stdout}"
    );
}

#[test]
fn service_status_and_uninstall_plans_are_consistent() {
    let fixture = ServiceFixture::new("status-plan");
    let socket = fixture.dir.join("runtime").join("daemon.sock");
    write_config(&fixture, &socket);

    let (exit_status, stdout_status, _) = fixture.run(&["service", "status-plan", "--json"]);
    assert_eq!(exit_status, 0, "{stdout_status}");
    assert!(stdout_status.contains("\"steps\""), "{stdout_status}");

    let (exit_uninstall, stdout_uninstall, _) =
        fixture.run(&["service", "uninstall-plan", "--json"]);
    assert_eq!(exit_uninstall, 0, "{stdout_uninstall}");
    assert!(stdout_uninstall.contains("\"steps\""), "{stdout_uninstall}");

    // Both plans reference the same unit target so a fixture runner can
    // install and uninstall symmetrically.
    let target_marker = if cfg!(target_os = "macos") {
        "Library/LaunchAgents"
    } else {
        "systemd/user"
    };
    assert!(stdout_status.contains(target_marker), "{stdout_status}");
    assert!(
        stdout_uninstall.contains(target_marker),
        "{stdout_uninstall}"
    );
}

/// Issue #266 AC1 (render leg): on a host where the configured harness
/// executable lives OUTSIDE the service-manager default PATH, the install
/// plan renders a unit that declares the invoking PATH (and HOME), so the
/// daemon the unit starts can resolve its harnesses — plus a log capture the
/// operator can find from the plan output.
#[test]
fn install_plan_declares_the_unit_environment_and_log_capture() {
    let fixture = ServiceFixture::new("install-env");
    let socket = fixture.dir.join("runtime").join("daemon.sock");
    write_config_with_harness(&fixture, &socket, "fixture-impl", "hf-fixture-harness");
    // The executable exists only in the fixture's bin dir: the service
    // manager's default PATH does not carry it.
    let bin_dir = install_fake_harness(&fixture, "hf-fixture-harness");
    let path = bin_dir.display().to_string();
    let home = fixture.dir.display().to_string();
    let state_dir = fixture.dir.join("state").join("canter");

    let (exit, stdout, stderr) = fixture.run_with_env(
        &["service", "install-plan", "--json"],
        &[("PATH", path.as_str())],
    );
    assert_eq!(exit, 0, "install-plan exits 0: {stdout} {stderr}");

    // The plan output names the environment the unit declares and the log
    // capture, so the operator can read both without opening the plist.
    assert!(
        stdout.contains("\"environment\""),
        "plan data carries the declared environment: {stdout}"
    );
    assert!(
        stdout.contains(&format!("\"PATH\":\"{path}\"")),
        "the unit's PATH is the invoking PATH: {stdout}"
    );
    assert!(
        stdout.contains(&format!("\"HOME\":\"{home}\"")),
        "the unit's HOME is the invoking HOME: {stdout}"
    );
    assert!(
        stdout.contains(&format!(
            "\"stdout\":\"{}/daemon.out.log\"",
            state_dir.display()
        )),
        "the plan names the captured stdout log: {stdout}"
    );
    assert!(
        stdout.contains(&format!(
            "\"stderr\":\"{}/daemon.err.log\"",
            state_dir.display()
        )),
        "the plan names the captured stderr log: {stdout}"
    );

    if cfg!(target_os = "macos") {
        assert!(
            stdout.contains("<key>EnvironmentVariables</key>"),
            "the plist declares EnvironmentVariables: {stdout}"
        );
        assert!(
            stdout.contains(&format!("<string>{path}</string>")),
            "the plist declares the invoking PATH: {stdout}"
        );
        assert!(
            stdout.contains("<key>StandardOutPath</key>")
                && stdout.contains("<key>StandardErrorPath</key>"),
            "the plist captures stdout/stderr: {stdout}"
        );
    } else {
        assert!(
            stdout.contains(&format!("Environment=\"PATH={path}\"")),
            "the unit declares the invoking PATH: {stdout}"
        );
        assert!(
            stdout.contains("StandardOutput=append:") && stdout.contains("StandardError=append:"),
            "the unit captures stdout/stderr: {stdout}"
        );
    }

    // The install steps name the state dir and the log capture, so a failed
    // start is diagnosable from the plan alone.
    assert!(
        stdout.contains(&format!("mkdir -p {}", state_dir.display())),
        "the install steps prepare the state dir the logs live in: {stdout}"
    );
    assert!(
        stdout.contains("daemon.out.log") && stdout.contains("daemon.err.log"),
        "the install steps name the captured logs: {stdout}"
    );
}

/// Issue #266 AC1 (refusal leg) + the gating scope: when a configured
/// harness executable cannot be resolved under the environment the unit
/// would declare, `install-plan` refuses typed NAMING the executable (no
/// unit is rendered), while the inspection/removal plans keep rendering so a
/// bad install stays inspectable and removable.
#[test]
fn install_plan_refuses_typed_when_a_configured_harness_executable_is_unresolvable() {
    let fixture = ServiceFixture::new("install-unresolved");
    let socket = fixture.dir.join("runtime").join("daemon.sock");
    write_config_with_harness(&fixture, &socket, "fixture-impl", "hf-missing-harness");
    // An empty bin dir stands in for a host PATH the executable is absent
    // from (the service-manager default PATH never carries it either).
    let bin_dir = fixture.dir.join("bin");
    std::fs::create_dir_all(&bin_dir).expect("bin dir");
    let path = bin_dir.display().to_string();

    let (exit, stdout, _stderr) = fixture.run_with_env(
        &["service", "install-plan", "--json"],
        &[("PATH", path.as_str())],
    );
    assert_eq!(
        exit, 4,
        "an unresolvable harness is a typed refusal: {stdout}"
    );
    assert!(
        stdout.contains("\"code\":\"refusal.service.harness_unresolved\""),
        "the refusal is typed: {stdout}"
    );
    assert!(
        stdout.contains("hf-missing-harness"),
        "the refusal names the unresolvable executable: {stdout}"
    );
    assert!(
        stdout.contains(&path),
        "the refusal names the PATH it checked: {stdout}"
    );
    assert!(
        !stdout.contains("\"unit\":"),
        "no unit is rendered for a refused install: {stdout}"
    );

    // The check gates the INSTALL only.
    let (exit_status, stdout_status, _) = fixture.run_with_env(
        &["service", "status-plan", "--json"],
        &[("PATH", path.as_str())],
    );
    assert_eq!(
        exit_status, 0,
        "status-plan keeps rendering: {stdout_status}"
    );
    assert!(
        stdout_status.contains("\"unit\""),
        "status-plan still shows the unit text: {stdout_status}"
    );
    let (exit_uninstall, stdout_uninstall, _) = fixture.run_with_env(
        &["service", "uninstall-plan", "--json"],
        &[("PATH", path.as_str())],
    );
    assert_eq!(
        exit_uninstall, 0,
        "uninstall-plan keeps rendering: {stdout_uninstall}"
    );
}

/// Issue #266 AC1 (positive control): a resolvable harness keeps the install
/// plan green — the refusal names an ABSENT executable, never a present one.
#[test]
fn install_plan_with_a_resolvable_harness_renders_instead_of_refusing() {
    let fixture = ServiceFixture::new("install-resolvable");
    let socket = fixture.dir.join("runtime").join("daemon.sock");
    write_config_with_harness(&fixture, &socket, "fixture-impl", "hf-present-harness");
    let bin_dir = install_fake_harness(&fixture, "hf-present-harness");
    let (exit, stdout, _stderr) = fixture.run_with_env(
        &["service", "install-plan", "--json"],
        &[("PATH", bin_dir.display().to_string().as_str())],
    );
    assert_eq!(exit, 0, "a resolvable harness never refuses: {stdout}");
    assert!(stdout.contains("\"unit\":"), "{stdout}");
    assert!(
        !stdout.contains("harness_unresolved"),
        "no refusal is emitted: {stdout}"
    );
}
