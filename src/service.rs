//! First-party per-user service units: launchd (macOS) and systemd (Linux)
//! rendering plus install/status/uninstall *plans* (issue #5, AC9; the unit
//! environment and log capture are issue #266).
//!
//! Nothing in this module installs, starts, stops, or queries the host
//! service manager: it renders unit text and command steps so operators can
//! review and run them on clean supported hosts. The daemon itself never
//! activates a service. All renderers take explicit paths and an explicit
//! environment so fixtures and tests never depend on this host's layout.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::adapters::resolve_executable;
use crate::config::Harness;

/// LaunchAgent label (one per user; synthetic and stable).
pub const LAUNCHD_LABEL: &str = "com.canter.daemon";
/// systemd user unit file name.
pub const SYSTEMD_UNIT_NAME: &str = "canter.service";

/// The service-manager platform this binary targets.
pub fn detect_platform() -> &'static str {
    if cfg!(target_os = "macos") {
        "launchd"
    } else if cfg!(target_os = "linux") {
        "systemd"
    } else {
        "unsupported"
    }
}

/// The per-user LaunchAgent plist path (`~/Library/LaunchAgents/…plist`).
pub fn launchd_plist_path(home: &Path) -> PathBuf {
    home.join("Library")
        .join("LaunchAgents")
        .join(format!("{LAUNCHD_LABEL}.plist"))
}

/// The per-user systemd unit path under the config home.
pub fn systemd_unit_path(config_home: &Path) -> PathBuf {
    config_home
        .join("systemd")
        .join("user")
        .join(SYSTEMD_UNIT_NAME)
}

/// Typed refusal code: a configured harness executable cannot be resolved
/// under the environment a rendered unit would declare (issue #266).
pub const CODE_HARNESS_UNRESOLVED: &str = "refusal.service.harness_unresolved";

/// One typed refusal from the unit-environment derivation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnitRefusal {
    /// Stable dotted code (see [`CODE_HARNESS_UNRESOLVED`]).
    pub code: &'static str,
    /// Human message; names the harness and the executable it could not
    /// resolve, and the PATH that was checked.
    pub message: String,
}

/// Captured daemon stdout file name under the state dir (issue #266, item 3).
pub const STDOUT_LOG_NAME: &str = "daemon.out.log";
/// Captured daemon stderr file name under the state dir (issue #266, item 3).
pub const STDERR_LOG_NAME: &str = "daemon.err.log";

/// The environment a rendered unit declares plus the daemon log paths it
/// binds (issue #266).
///
/// RULE: a service manager gives the job only the unit's declared
/// environment — launchd supplies `PATH=/usr/bin:/bin:/usr/sbin:/sbin` and
/// no `HOME` — while every subprocess the daemon spawns resolves its
/// executable through the daemon's OWN environment (the trust-model T5
/// allowlist, [`crate::config::adapter_environment`]). A unit that declares
/// no environment therefore starts healthy and then fails at the first
/// harness spawn. The rendered unit carries, at minimum, the invoking
/// environment's `PATH` and `HOME`; the derivation is never a hardcoded host
/// path list. The daemon's stdout/stderr are captured under the state dir so
/// a failed start leaves a readable log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnitEnvironment {
    /// The `PATH` the unit declares (`None` when the invoking environment
    /// carries none; the service manager default then applies).
    pub path: Option<String>,
    /// The `HOME` the unit declares.
    pub home: Option<String>,
    /// Captured daemon stdout (`StandardOutPath` / `StandardOutput=append:`).
    pub stdout_log: PathBuf,
    /// Captured daemon stderr (`StandardErrorPath` / `StandardError=append:`).
    pub stderr_log: PathBuf,
}

impl UnitEnvironment {
    /// The declared variables in declaration order.
    pub fn vars(&self) -> Vec<(&'static str, &str)> {
        let mut vars = Vec::new();
        if let Some(path) = &self.path {
            vars.push(("PATH", path.as_str()));
        }
        if let Some(home) = &self.home {
            vars.push(("HOME", home.as_str()));
        }
        vars
    }
}

/// Derive the unit environment from the invoking environment: its `PATH`
/// and `HOME`, plus the log capture paths under `state_dir` (issue #266).
/// Pure — the caller supplies the environment (no hidden process reads).
pub fn unit_environment(invoking: &BTreeMap<String, String>, state_dir: &Path) -> UnitEnvironment {
    UnitEnvironment {
        path: invoking.get("PATH").cloned(),
        home: invoking.get("HOME").cloned(),
        stdout_log: state_dir.join(STDOUT_LOG_NAME),
        stderr_log: state_dir.join(STDERR_LOG_NAME),
    }
}

/// Derive the unit environment and verify that EVERY configured harness
/// executable resolves under it, refusing typed (naming the harness and its
/// executable) at the first one that does not (issue #266): the rendered
/// unit would otherwise start a daemon that cannot spawn that harness's
/// lanes. Resolution uses the daemon's own rule
/// ([`resolve_executable`] over the declared `PATH`).
pub fn checked_unit_environment(
    invoking: &BTreeMap<String, String>,
    state_dir: &Path,
    harnesses: &[Harness],
) -> Result<UnitEnvironment, UnitRefusal> {
    let environment = unit_environment(invoking, state_dir);
    for harness in harnesses {
        if resolve_executable(&harness.executable, invoking).is_err() {
            return Err(UnitRefusal {
                code: CODE_HARNESS_UNRESOLVED,
                message: format!(
                    "configured harness {:?} executable {:?} does not resolve on the PATH the \
                     rendered unit would declare (PATH={}); an install from this plan would start \
                     a daemon that cannot spawn that harness's lanes — extend the invoking PATH \
                     and re-run",
                    harness.key,
                    harness.executable,
                    environment.path.as_deref().unwrap_or("(none)"),
                ),
            });
        }
    }
    Ok(environment)
}

/// Escape one XML text value for the plist renderer (`&` first).
fn xml_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// One systemd `Environment=` value: always double-quoted, so a `PATH` entry
/// (or a home dir) containing spaces stays ONE assignment.
fn systemd_environment_assignment(name: &str, value: &str) -> String {
    format!(
        "\"{name}={value}\"",
        name = name,
        value = value.replace('\\', "\\\\").replace('"', "\\\"")
    )
}

/// Render the per-user LaunchAgent plist for `bin` serving `socket`, with
/// the declared unit `environment` and its log capture (issue #266).
pub fn launchd_unit(bin: &Path, socket: &Path, environment: &UnitEnvironment) -> String {
    let mut variables = String::new();
    for (name, value) in environment.vars() {
        variables.push_str(&format!(
            "        <key>{name}</key>\n        <string>{value}</string>\n",
            name = xml_escape(name),
            value = xml_escape(value),
        ));
    }
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
<plist version=\"1.0\">\n\
<dict>\n\
    <key>Label</key>\n\
    <string>{LAUNCHD_LABEL}</string>\n\
    <key>ProgramArguments</key>\n\
    <array>\n\
        <string>{bin}</string>\n\
        <string>daemon</string>\n\
        <string>run</string>\n\
        <string>--socket</string>\n\
        <string>{socket}</string>\n\
    </array>\n\
    <key>RunAtLoad</key>\n\
    <true/>\n\
    <key>KeepAlive</key>\n\
    <dict>\n\
        <key>SuccessfulExit</key>\n\
        <false/>\n\
    </dict>\n\
    <key>ThrottleInterval</key>\n\
    <integer>10</integer>\n\
    <key>ProcessType</key>\n\
    <string>Background</string>\n\
    <key>EnvironmentVariables</key>\n\
    <dict>\n\
{variables}    </dict>\n\
    <key>StandardOutPath</key>\n\
    <string>{stdout_log}</string>\n\
    <key>StandardErrorPath</key>\n\
    <string>{stderr_log}</string>\n\
</dict>\n\
</plist>\n",
        bin = xml_escape(&bin.display().to_string()),
        socket = xml_escape(&socket.display().to_string()),
        variables = variables,
        stdout_log = xml_escape(&environment.stdout_log.display().to_string()),
        stderr_log = xml_escape(&environment.stderr_log.display().to_string()),
    )
}

/// Render the per-user systemd unit for `bin` serving `socket`, with the
/// declared unit `environment` and its log capture (issue #266).
pub fn systemd_unit(bin: &Path, socket: &Path, environment: &UnitEnvironment) -> String {
    let mut environment_lines = String::new();
    for (name, value) in environment.vars() {
        environment_lines.push_str(&format!(
            "Environment={assignment}\n",
            assignment = systemd_environment_assignment(name, value)
        ));
    }
    format!(
        "# canter per-user daemon unit (issue #5; rendered, not activated)\n\
[Unit]\n\
Description=canter state daemon (single writer per user)\n\
After=default.target\n\
\n\
[Service]\n\
Type=simple\n\
ExecStart={bin} daemon run --socket {socket}\n\
Restart=on-failure\n\
RestartSec=5\n\
NoNewPrivileges=true\n\
{environment_lines}\
StandardOutput=append:{stdout_log}\n\
StandardError=append:{stderr_log}\n\
\n\
[Install]\n\
WantedBy=default.target\n",
        bin = bin.display(),
        socket = socket.display(),
        environment_lines = environment_lines,
        stdout_log = environment.stdout_log.display(),
        stderr_log = environment.stderr_log.display(),
    )
}

/// Render the numbered command steps for installing the service on this
/// platform (a plan: nothing here executes the steps). `state_dir` is the
/// daemon state dir the log capture needs to exist (issue #266).
pub fn install_plan_steps(
    platform: &str,
    bin: &Path,
    socket: &Path,
    home: &Path,
    config_home: &Path,
    state_dir: &Path,
    environment: &UnitEnvironment,
) -> Vec<String> {
    match platform {
        "launchd" => {
            let plist = launchd_plist_path(home);
            vec![
                format!(
                    "prepare the daemon state directory (private 0700): mkdir -p {state} && chmod 700 {state}",
                    state = state_dir.display()
                ),
                format!(
                    "write the rendered plist to {} (per-user; content printed by the install command)",
                    plist.display()
                ),
                format!("launchctl bootstrap gui/$(id -u) {}", plist.display()),
                format!(
                    "verify: launchctl print gui/$(id -u)/{LAUNCHD_LABEL} (expect the daemon pid serving {})",
                    socket.display()
                ),
                format!(
                    "if the job fails to start, read the captured daemon logs at {} (stdout) and {} (stderr)",
                    environment.stdout_log.display(),
                    environment.stderr_log.display()
                ),
            ]
        }
        "systemd" => {
            let unit = systemd_unit_path(config_home);
            let _ = (bin, socket);
            vec![
                format!(
                    "prepare the daemon state directory (private 0700): mkdir -p {state} && chmod 700 {state}",
                    state = state_dir.display()
                ),
                format!(
                    "write the rendered unit to {} (content printed by the install command)",
                    unit.display()
                ),
                "run: systemctl --user daemon-reload".to_string(),
                "run: systemctl --user enable --now canter.service".to_string(),
                "verify: systemctl --user --no-pager status canter.service".to_string(),
                format!(
                    "if the service fails to start, read the captured daemon logs at {} (stdout) and {} (stderr)",
                    environment.stdout_log.display(),
                    environment.stderr_log.display()
                ),
            ]
        }
        other => vec![format!(
            "no first-party unit exists for platform {other:?}; run the daemon directly with `canter daemon run`"
        )],
    }
}

/// Render the command steps for checking service status on this platform.
pub fn status_plan_steps(platform: &str) -> Vec<String> {
    match platform {
        "launchd" => vec![
            format!("launchctl print gui/$(id -u)/{LAUNCHD_LABEL}"),
            "canter daemon status --json".to_string(),
        ],
        "systemd" => vec![
            "systemctl --user --no-pager status canter.service".to_string(),
            "canter daemon status --json".to_string(),
        ],
        other => vec![format!(
            "no first-party service exists for platform {other:?}"
        )],
    }
}

/// Render the command steps for uninstalling the service on this platform.
pub fn uninstall_plan_steps(platform: &str, home: &Path, config_home: &Path) -> Vec<String> {
    match platform {
        "launchd" => vec![
            format!("launchctl bootout gui/$(id -u)/{LAUNCHD_LABEL}"),
            format!("rm -f {}", launchd_plist_path(home).display()),
        ],
        "systemd" => vec![
            "systemctl --user --no-pager disable --now canter.service".to_string(),
            format!("rm -f {}", systemd_unit_path(config_home).display()),
            "systemctl --user daemon-reload".to_string(),
        ],
        other => vec![format!(
            "no first-party service exists for platform {other:?}"
        )],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Runtime-derived fixture paths: the tracked tree must never carry an
    /// absolute-path literal (public-tree scanner).
    fn fixture_paths() -> (PathBuf, PathBuf, PathBuf, PathBuf) {
        let base = std::env::temp_dir().join(format!("hf-service-{}", std::process::id()));
        (
            base.join("fixture-user"),
            base.join("fixture-user").join(".config"),
            base.join("fixture-user")
                .join(".local")
                .join("bin")
                .join("canter"),
            base.join("run-user-1000").join("daemon.sock"),
        )
    }

    /// One plain unit environment for renderer tests (pure — no process
    /// environment is read).
    fn fixture_environment(path: &str, home: &str) -> UnitEnvironment {
        let state_dir =
            std::env::temp_dir().join(format!("hf-service-state-{}", std::process::id()));
        UnitEnvironment {
            path: Some(path.to_string()),
            home: Some(home.to_string()),
            stdout_log: state_dir.join(STDOUT_LOG_NAME),
            stderr_log: state_dir.join(STDERR_LOG_NAME),
        }
    }

    /// One configured harness entry for the derivation tests.
    fn harness(key: &str, executable: &str) -> Harness {
        Harness {
            key: key.to_string(),
            kind: "hermes".to_string(),
            executable: executable.to_string(),
            env_allow: vec!["PATH".to_string(), "HOME".to_string()],
            skills: Vec::new(),
            provider: None,
            model: None,
            fallback: Vec::new(),
            secret_env: Vec::new(),
            limits: Vec::new(),
            binding_introspection: false,
        }
    }

    #[test]
    fn launchd_unit_is_a_complete_plist() {
        let (_, _, bin, socket) = fixture_paths();
        let unit = launchd_unit(&bin, &socket, &fixture_environment("bin-a:bin-b", "home-a"));
        assert!(unit.contains(LAUNCHD_LABEL));
        assert!(unit.contains("<key>KeepAlive</key>"));
        assert!(unit.contains("<key>RunAtLoad</key>"));
        assert!(unit.contains(&bin.display().to_string()));
        assert!(unit.contains(&socket.display().to_string()));
        assert!(unit.ends_with("</plist>\n"));
        // The daemon must run in the foreground under launchd: no & anywhere.
        assert!(!unit.contains('&'), "plist must not background the daemon");
    }

    #[test]
    fn launchd_unit_declares_the_environment_and_log_capture() {
        // `&`/`<`/`>` in a declared value are escaped: the plist must stay
        // well-formed for any PATH or home the invoking user has.
        let environment = fixture_environment("fixture&bin:fixture-two", "fixture<home>");
        let (_, _, bin, socket) = fixture_paths();
        let unit = launchd_unit(&bin, &socket, &environment);
        assert!(unit.contains("<key>EnvironmentVariables</key>"), "{unit}");
        assert!(
            unit.contains("<string>fixture&amp;bin:fixture-two</string>"),
            "{unit}"
        );
        assert!(
            unit.contains("<string>fixture&lt;home&gt;</string>"),
            "{unit}"
        );
        assert!(unit.contains("<key>StandardOutPath</key>"), "{unit}");
        assert!(
            unit.contains(&format!(
                "<string>{}</string>",
                environment.stdout_log.display()
            )),
            "{unit}"
        );
        assert!(unit.contains("<key>StandardErrorPath</key>"), "{unit}");
        assert!(
            unit.contains(&format!(
                "<string>{}</string>",
                environment.stderr_log.display()
            )),
            "{unit}"
        );
    }

    #[test]
    fn systemd_unit_declares_the_environment_and_log_capture() {
        // A PATH entry with a space stays ONE quoted assignment.
        let environment = fixture_environment("fixture bin:two", "fixture-home");
        let (_, _, bin, socket) = fixture_paths();
        let unit = systemd_unit(&bin, &socket, &environment);
        assert!(
            unit.contains("Environment=\"PATH=fixture bin:two\"\n"),
            "{unit}"
        );
        assert!(
            unit.contains("Environment=\"HOME=fixture-home\"\n"),
            "{unit}"
        );
        assert!(unit.contains("StandardOutput=append:"), "{unit}");
        assert!(
            unit.contains(&format!(
                "StandardOutput=append:{}",
                environment.stdout_log.display()
            )),
            "{unit}"
        );
        assert!(
            unit.contains(&format!(
                "StandardError=append:{}",
                environment.stderr_log.display()
            )),
            "{unit}"
        );
    }

    #[test]
    fn unit_environment_derives_path_home_and_log_capture() {
        let state_dir = std::env::temp_dir().join(format!("hf-svc-env-{}", std::process::id()));
        let invoking: BTreeMap<String, String> = [
            ("PATH".to_string(), "fixture-bin:fixture-two".to_string()),
            ("HOME".to_string(), "fixture-home".to_string()),
        ]
        .into_iter()
        .collect();
        let environment = unit_environment(&invoking, &state_dir);
        assert_eq!(environment.path.as_deref(), Some("fixture-bin:fixture-two"));
        assert_eq!(environment.home.as_deref(), Some("fixture-home"));
        assert_eq!(environment.stdout_log, state_dir.join(STDOUT_LOG_NAME));
        assert_eq!(environment.stderr_log, state_dir.join(STDERR_LOG_NAME));
        assert_eq!(
            environment.vars(),
            vec![
                ("PATH", "fixture-bin:fixture-two"),
                ("HOME", "fixture-home")
            ]
        );
        // No invoking PATH: no PATH is declared (the service manager default
        // applies) — the derivation never invents one.
        let bare = unit_environment(&BTreeMap::new(), &state_dir);
        assert_eq!(bare.path, None);
        assert_eq!(bare.vars(), Vec::<(&'static str, &str)>::new());
    }

    #[test]
    fn checked_unit_environment_refuses_an_unresolvable_harness() {
        let base = std::env::temp_dir().join(format!("hf-svc-check-{}", std::process::id()));
        let bin_dir = base.join("bin");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&bin_dir).expect("bin dir");
        let executable = bin_dir.join("hf-fixture-harness");
        std::fs::write(&executable, "#!/bin/sh\nexit 0\n").expect("write harness");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755))
                .expect("chmod");
        }
        let invoking: BTreeMap<String, String> =
            [("PATH".to_string(), bin_dir.display().to_string())]
                .into_iter()
                .collect();

        // Every configured harness is checked, not just the first: the
        // resolvable one passes and the absent one refuses, named.
        let harnesses = vec![
            harness("fixture-impl", "hf-fixture-harness"),
            harness("fixture-rev", "hf-absent-harness"),
        ];
        let refusal = checked_unit_environment(&invoking, &base, &harnesses)
            .expect_err("an unresolvable executable must refuse");
        assert_eq!(refusal.code, CODE_HARNESS_UNRESOLVED);
        assert!(
            refusal.message.contains("hf-absent-harness"),
            "{}",
            refusal.message
        );
        assert!(
            refusal.message.contains(&bin_dir.display().to_string()),
            "the refusal names the PATH it checked: {}",
            refusal.message
        );

        // The same derivation passes when every executable resolves.
        let environment =
            checked_unit_environment(&invoking, &base, &harnesses[..1]).expect("resolvable");
        assert_eq!(
            environment.path.as_deref(),
            Some(bin_dir.display().to_string().as_str())
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn install_steps_name_the_state_dir_and_captured_logs() {
        let (home, config_home, bin, socket) = fixture_paths();
        let state_dir = home.join("state").join("canter");
        let environment = unit_environment(&BTreeMap::new(), &state_dir);
        for platform in ["launchd", "systemd"] {
            let steps = install_plan_steps(
                platform,
                &bin,
                &socket,
                &home,
                &config_home,
                &state_dir,
                &environment,
            );
            assert!(
                steps
                    .iter()
                    .any(|step| step.contains("daemon.out.log") && step.contains("daemon.err.log")),
                "{platform} install steps name the captured logs: {steps:?}"
            );
            assert!(
                steps
                    .iter()
                    .any(|step| step.contains(&state_dir.display().to_string())),
                "{platform} install steps name the state dir: {steps:?}"
            );
        }
    }

    #[test]
    fn systemd_unit_is_a_complete_user_unit() {
        let (_, _, bin, socket) = fixture_paths();
        let unit = systemd_unit(&bin, &socket, &fixture_environment("bin-a:bin-b", "home-a"));
        assert!(unit.contains("[Unit]"));
        assert!(unit.contains("[Service]"));
        assert!(unit.contains("[Install]"));
        assert!(unit.contains(&format!(
            "ExecStart={} daemon run --socket {}",
            bin.display(),
            socket.display()
        )));
        assert!(unit.contains("Restart=on-failure"));
        assert!(unit.contains("WantedBy=default.target"));
        assert!(unit.contains("NoNewPrivileges=true"));
    }

    #[test]
    fn paths_are_per_user_and_synthetic_safe() {
        let (home, config_home, _, _) = fixture_paths();
        let plist = launchd_plist_path(&home);
        assert_eq!(
            plist,
            home.join("Library")
                .join("LaunchAgents")
                .join(format!("{LAUNCHD_LABEL}.plist"))
        );
        let unit = systemd_unit_path(&config_home);
        assert_eq!(
            unit,
            config_home
                .join("systemd")
                .join("user")
                .join("canter.service")
        );
    }

    #[test]
    fn plans_are_steps_only_and_platform_scoped() {
        let (home, config_home, bin, socket) = fixture_paths();
        let state_dir = home.join("state").join("canter");
        let environment = unit_environment(&BTreeMap::new(), &state_dir);
        for platform in ["launchd", "systemd", "plan9"] {
            let install = install_plan_steps(
                platform,
                &bin,
                &socket,
                &home,
                &config_home,
                &state_dir,
                &environment,
            );
            assert!(!install.is_empty());
            let uninstall = uninstall_plan_steps(platform, &home, &config_home);
            assert!(!uninstall.is_empty());
        }
        let launchd_steps = install_plan_steps(
            "launchd",
            &bin,
            &socket,
            &home,
            &config_home,
            &state_dir,
            &environment,
        );
        assert!(
            launchd_steps
                .iter()
                .any(|step| step.contains("launchctl bootstrap")),
            "launchd install plan documents the bootstrap command"
        );
        let systemd_steps = install_plan_steps(
            "systemd",
            &bin,
            &socket,
            &home,
            &config_home,
            &state_dir,
            &environment,
        );
        assert!(
            systemd_steps
                .iter()
                .any(|step| step.contains("systemctl --user enable")),
            "systemd install plan documents the enable command"
        );
        // Unsupported platforms produce a plan that says so (never silence).
        assert!(uninstall_plan_steps("plan9", &home, &config_home)[0].contains("no first-party"));
    }

    #[test]
    fn platform_is_one_of_the_known_kinds() {
        assert!(matches!(
            detect_platform(),
            "launchd" | "systemd" | "unsupported"
        ));
    }

    #[test]
    fn rendered_units_never_leak_private_path_markers() {
        let (home, config_home, bin, socket) = fixture_paths();
        let environment = fixture_environment("bin-a:bin-b", "home-a");
        // Unit text may legitimately carry URLs (the plist DOCTYPE), but
        // never a private-machine absolute-path marker.
        for unit in [
            launchd_unit(&bin, &socket, &environment),
            systemd_unit(&bin, &socket, &environment),
        ] {
            // The marker strings are assembled so the tracked tree itself
            // never carries an absolute-path literal (public-tree scanner).
            let user_home_marker = ["/Us", "ers/"].concat();
            let posix_home_marker = ["/ho", "me/"].concat();
            assert!(
                !unit.contains(&user_home_marker),
                "unit leaked a host path marker"
            );
            assert!(
                !unit.contains(&posix_home_marker),
                "unit leaked a host path marker"
            );
        }
        assert!(
            launchd_plist_path(&home)
                .display()
                .to_string()
                .contains("Library")
        );
        assert!(
            systemd_unit_path(&config_home)
                .display()
                .to_string()
                .contains("systemd")
        );
    }
}
