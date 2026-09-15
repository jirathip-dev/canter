//! CLI smoke tests against the REAL compiled binary.
//!
//! `env!(\"CARGO_BIN_EXE_canter\")` is provided by Cargo for integration
//! tests and points at the built binary of this package.

use std::process::Command;

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_canter"))
        .args(args)
        .output()
        .expect("failed to spawn the canter binary")
}

fn stdout_of(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr_of(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn help_exits_zero_and_prints_usage() {
    for flag in ["--help", "-h"] {
        let out = run(&[flag]);
        assert!(out.status.success(), "{flag} should exit 0");
        let stdout = stdout_of(&out);
        assert!(
            stdout.contains("canter"),
            "{flag} stdout should name the program"
        );
        assert!(
            stdout.contains("USAGE"),
            "{flag} stdout should contain usage text"
        );
        assert!(out.stderr.is_empty(), "{flag} stderr should be empty");
    }
}

#[test]
fn version_exits_zero_and_prints_package_identity() {
    for flag in ["--version", "-V"] {
        let out = run(&[flag]);
        assert!(out.status.success(), "{flag} should exit 0");
        let stdout = stdout_of(&out);
        assert!(
            stdout.contains(env!("CARGO_PKG_NAME")),
            "{flag} stdout should contain the package name"
        );
        assert!(
            stdout.contains(env!("CARGO_PKG_VERSION")),
            "{flag} stdout should contain the package version"
        );
        // Issue #10: the release provenance chain reads schema facts from
        // `--version`; the printed state schema version must equal the
        // library constant of the same binary.
        assert!(
            stdout.contains(&format!(
                "state schema version: {}",
                canter::state::SCHEMA_VERSION
            )),
            "{flag} stdout should contain the state schema version fact"
        );
        assert!(
            stdout.contains("document schema families: hf-config/v1")
                && stdout.contains("hf-schedule/v1"),
            "{flag} stdout should list the document schema families"
        );
        assert!(out.stderr.is_empty(), "{flag} stderr should be empty");
    }
}

#[test]
fn no_arguments_exits_nonzero_with_usage_on_stderr() {
    let out = run(&[]);
    assert!(!out.status.success(), "no arguments should exit non-zero");
    assert_eq!(out.status.code(), Some(2));
    let stderr = stderr_of(&out);
    assert!(stderr.contains("USAGE"), "stderr should contain usage text");
    assert!(
        out.stdout.is_empty(),
        "stdout should be empty for the error path"
    );
}

#[test]
fn unknown_argument_exits_nonzero_with_usage_on_stderr() {
    for args in [&["--definitely-not-a-command"][..], &["frobnicate"][..]] {
        let out = run(args);
        assert!(!out.status.success(), "{args:?} should exit non-zero");
        assert_eq!(out.status.code(), Some(2));
        let stderr = stderr_of(&out);
        assert!(stderr.contains("error"), "stderr should explain the error");
        assert!(
            out.stdout.is_empty(),
            "stdout should be empty for the error path"
        );
    }
}

#[test]
fn every_documented_command_has_working_help() {
    // The skill and README may only document commands that exist; this test
    // keeps the USAGE text honest by exercising each documented form.
    let out = run(&["--help"]);
    let usage = stdout_of(&out);
    for command in [
        "config init",
        "config validate",
        "config show",
        "doctor",
        "status",
        "plan",
        "capabilities",
        "lane preview",
        "lane request",
        "lane status",
        "queue submit",
        "queue status",
        "run pause",
        "run resume",
        "run retry",
        "run resolve",
        "run dispatch",
        "run status",
        "supervision status",
        "board",
        "grant issue",
    ] {
        assert!(usage.contains(command), "USAGE must document `{command}`");
    }
    for args in [
        &["config", "--help"][..],
        &["doctor", "--help"][..],
        &["status", "--help"][..],
        &["plan", "--help"][..],
        &["capabilities", "--help"][..],
        &["queue", "--help"][..],
        &["run", "--help"][..],
        &["run", "resolve", "--help"][..],
        &["run", "dispatch", "--help"][..],
        &["run", "status", "--help"][..],
        &["supervision", "--help"][..],
        &["supervision", "status", "--help"][..],
        &["board", "--help"][..],
        &["grant", "--help"][..],
        &["grant", "issue", "--help"][..],
    ] {
        let out = run(args);
        assert!(out.status.success(), "{args:?} --help should exit 0");
        assert!(
            stdout_of(&out).contains("USAGE"),
            "{args:?} --help should print usage"
        );
    }
}

#[test]
fn f11_misplaced_global_flags_get_a_targeted_error_without_the_usage_dump() {
    for args in [
        &["--config", "config.toml", "status"][..],
        &[
            "--socket",
            "daemon.sock",
            "run",
            "status",
            "--run",
            "run-0123456789abcdef",
        ][..],
        &["--json", "status"][..],
        &["--config=config.toml", "status"][..],
    ] {
        let out = run(args);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(out.stdout.is_empty(), "{args:?}: stdout stays empty");
        let stderr = stderr_of(&out);
        assert!(
            stderr.contains("--config/--socket/--json belong after the subcommand"),
            "{args:?}: {stderr}"
        );
        assert!(
            !stderr.contains("USAGE:"),
            "{args:?}: targeted error must not dump global usage: {stderr}"
        );
    }
}

#[test]
fn board_is_refused_typed_before_anything_is_touched() {
    // `board` is an interactive terminal surface: it never accepts --json and
    // never reaches the state store or the terminal on a malformed
    // invocation (the refusal is a typed usage error, exit 2).
    let out = run(&["board", "--json"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty(), "stdout stays empty");
    let stderr = stderr_of(&out);
    assert!(
        stderr.contains("board") && stderr.contains("--json"),
        "the refusal must name the command and the flag: {stderr}"
    );

    for args in [
        &["board", "--frobnicate"][..],
        &["board", "extra"][..],
        &["board", "--config"][..],
    ] {
        let out = run(args);
        assert_eq!(
            out.status.code(),
            Some(2),
            "{args:?} should be a usage error"
        );
        assert!(out.stdout.is_empty(), "{args:?}: stdout stays empty");
        assert!(
            stderr_of(&out).contains("board"),
            "{args:?}: the usage error must name the command"
        );
    }
}

#[test]
fn json_mode_writes_only_json_to_stdout_and_never_prompts() {
    // stdin is closed (Stdio::null is default via output()); JSON mode must
    // still complete and stdout must be exactly one envelope document.
    let out = run(&["capabilities", "--json"]);
    assert!(out.status.success());
    let stdout = stdout_of(&out);
    assert!(
        stdout.trim_start().starts_with('{'),
        "stdout must be a JSON document"
    );
    assert!(
        stdout.trim_end().ends_with('}'),
        "stdout must end with the JSON document"
    );
    assert_eq!(
        stdout.matches("hf-output/v1").count(),
        1,
        "exactly one envelope"
    );
    assert!(stderr_of(&out).is_empty(), "no diagnostics on a clean run");
}
