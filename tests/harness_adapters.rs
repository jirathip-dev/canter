//! Harness adapter contract tests (issue #7) with fake executables.
//!
//! Every test builds its own temporary bin directory on PATH (the
//! allowlisted environment map points at it) containing fake `hermes` /
//! `claude` / `codex` / `pi` / `jcode` / `hf-argv` / `herdr` executables.
//! Executables are
//! resolved through the allowlisted PATH only, so a real harness on the
//! host can never be reached by these tests (AC7: public CI needs no
//! harness credentials — every case is a fake/synthetic contract test).
//! The fakes pin the exact adapter invocation rows: a fake exits non-zero
//! when the argv it received differs from the documented contract, which
//! makes the process-level assertions bite.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use canter::adapters::{
    ADAPTER_TIMEOUT, AgentIdentity, CODE_BINDING, CODE_CREDENTIALS, CODE_EXIT, CODE_MALFORMED,
    CODE_PROCESS_DEATH, CODE_STALE_IDENTITY, CODE_TIMEOUT, CODE_UNAVAILABLE,
    CODE_UNKNOWN_CAPABILITY, CODE_UNKNOWN_HARNESS, ExecutionMode, HarnessKind, Op, OpRequest,
    Profile, bind_identity, execute_named, execute_op, new_session, probe_profile,
};
use canter::canonical::canonical_bytes;
use canter::config::Harness as ConfigHarness;
use canter::schema::{Family, validate_bytes};
use canter::value::Val;

static DIR_COUNTER: AtomicUsize = AtomicUsize::new(0);

/// A temporary bin directory holding fake executables; removed on drop.
struct FakeBins {
    path: PathBuf,
}

impl FakeBins {
    fn new() -> FakeBins {
        let n = DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
        // Prefer the per-test-binary tmp dir cargo provides (target/tmp, on
        // the build filesystem) over the shared OS temp dir: fake
        // executables must be spawned while other tests write theirs, and a
        // quota-tracked shared temp filesystem can transiently refuse
        // script execs (observed ETXTBSY on this host).
        let base = std::env::var_os("CARGO_TARGET_TMPDIR")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let path = base.join(format!("hf-adapters-contract-{}-{}", std::process::id(), n));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("create fake bin dir");
        FakeBins { path }
    }

    /// Write an executable `name` with a `/bin/sh` body and return its
    /// path. `body` is trusted test code (never untrusted payload text).
    fn bin(&self, name: &str, body: &str) -> PathBuf {
        let path = self.path.join(name);
        fs::write(&path, format!("#!/bin/sh\n{body}\n")).expect("write fake executable");
        // btrfs copy-on-write can transiently refuse exec of a just-written
        // file ("Text file busy") when writeback races the first spawn;
        // fsync before returning keeps the execs deterministic.
        let file = fs::File::open(&path).expect("open fake executable");
        file.sync_all().expect("fsync fake executable");
        set_executable(&path);
        path
    }

    /// The allowlisted environment: PATH points at the fake bin dir only.
    /// Nothing else is present — the child must never see host variables
    /// (process.rs `env_clear` + this allowlist is the only channel).
    fn env(&self) -> BTreeMap<String, String> {
        let mut env = BTreeMap::new();
        env.insert("PATH".to_string(), self.path.to_string_lossy().into_owned());
        env
    }

    /// The allowlisted environment plus herdr pane markers (`HERDR_ENV=1`,
    /// `HERDR_PANE_ID`), simulating an adapter-driven lane running inside a
    /// herdr pane (issue #33 A2).
    fn env_herdr(&self) -> BTreeMap<String, String> {
        let mut env = self.env();
        env.insert("HERDR_ENV".to_string(), "1".to_string());
        env.insert("HERDR_PANE_ID".to_string(), "w33:p1".to_string());
        env
    }
}

impl Drop for FakeBins {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[cfg(unix)]
fn set_executable(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = fs::metadata(path).expect("metadata").permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).expect("chmod");
}

/// Whether a failure is a transient spawn/exec error of the host filesystem
/// (observed on this host: exec of a just-written script transiently fails
/// with `Text file busy` under concurrent test spawns on a degraded btrfs
/// mount; `Resource temporarily unavailable` is fork contention). The
/// adapter classification is correct either way (`refusal.unavailable`); the
/// tests assert the *classification*, so they retry transient spawn errors
/// a bounded number of times instead of flaking on the environment.
fn is_transient_spawn_failure(result: &canter::adapters::OpResult) -> bool {
    if result.code != Some(CODE_UNAVAILABLE) {
        return false;
    }
    let text = format!(
        "{:?} {:?}",
        result.detail.as_deref().unwrap_or(""),
        result.message.as_deref().unwrap_or("")
    );
    text.contains("Text file busy") || text.contains("Resource temporarily unavailable")
}

/// `execute_op` with a bounded retry on transient spawn failures.
fn run_op_retry(
    profile: &Profile,
    request: &OpRequest<'_>,
    env: &BTreeMap<String, String>,
) -> canter::adapters::OpResult {
    let mut result = execute_op(profile, request, env);
    let mut attempts = 0;
    while is_transient_spawn_failure(&result) && attempts < 4 {
        std::thread::sleep(Duration::from_millis(25));
        result = execute_op(profile, request, env);
        attempts += 1;
    }
    result
}

/// `execute_named` with a bounded retry on transient spawn failures.
fn run_named_retry(
    profile: &Profile,
    op_name: &str,
    session: &canter::adapters::SessionHandle,
    payload: Option<&str>,
    timeout: Duration,
    env: &BTreeMap<String, String>,
) -> canter::adapters::OpResult {
    let mut result = execute_named(profile, op_name, session, payload, timeout, env);
    let mut attempts = 0;
    while is_transient_spawn_failure(&result) && attempts < 4 {
        std::thread::sleep(Duration::from_millis(25));
        result = execute_named(profile, op_name, session, payload, timeout, env);
        attempts += 1;
    }
    result
}

/// `probe_profile` with a bounded retry on transient spawn failures.
fn probe_retry(profile: &Profile, env: &BTreeMap<String, String>) -> canter::adapters::ProbeResult {
    let mut probe = probe_profile(profile, env);
    let mut attempts = 0;
    while probe.code == Some(CODE_UNAVAILABLE)
        && probe.detail.as_deref().is_some_and(|d| {
            d.contains("Text file busy") || d.contains("Resource temporarily unavailable")
        })
        && attempts < 4
    {
        std::thread::sleep(Duration::from_millis(25));
        probe = probe_profile(profile, env);
        attempts += 1;
    }
    probe
}

/// The official kinds under test.
fn official_kinds() -> [HarnessKind; 5] {
    HarnessKind::OFFICIAL
}

/// Synthetic provider/model binding values for the fake contract tests
/// (issue #80): deliberately different from the historical code literals,
/// so a reintroduced literal in the Pi/Jcode prompt row fails the
/// exact-argv fakes (AC1 RED mutation probe). Never real provider policy.
const TEST_PROVIDER: &str = "example-provider";
const TEST_MODEL: &str = "example-model";

/// An official profile carrying the explicit provider/model binding the
/// Pi/Jcode prompt rows require (issue #80). Kinds whose prompt row does
/// not carry the pair are returned unchanged.
///
/// Issue #139: these fake-executable fixtures pin the BARE-SUBPROCESS rows
/// (the pre-#139 adapter contract), which are now the explicitly selected
/// headless substrate — so the fixture selects it explicitly. The default
/// substrate is the Herdr pane (pinned in `tests/herdr_pane_execution.rs`);
/// nothing here falls back to it or from it.
fn official_profile(kind: HarnessKind) -> Profile {
    let profile = Profile::official(kind, kind.name())
        .expect("profile")
        .with_execution(ExecutionMode::Headless);
    if matches!(kind, HarnessKind::Pi | HarnessKind::Jcode) {
        profile
            .with_binding(TEST_PROVIDER, TEST_MODEL)
            .expect("binding")
    } else {
        profile
    }
}

/// Declared current version for a kind (mirrors the metadata table in
/// src/adapters.rs / docs/contracts/compatibility.md).
fn declared_current(kind: HarnessKind) -> &'static str {
    match kind {
        HarnessKind::Hermes => "0.21.0",
        HarnessKind::ClaudeCode => "2.1.263",
        HarnessKind::Codex => "0.153.4",
        HarnessKind::Pi => "0.85.1",
        HarnessKind::Jcode => "0.84.0",
        HarnessKind::Argv => "",
    }
}

/// The executable name each kind spawns (the fake bin name must match the
/// executable the profile resolves, not the kind name — claude-code is the
/// official adapter name, `claude` is the binary).
fn executable_name(kind: HarnessKind) -> &'static str {
    match kind {
        HarnessKind::Hermes => "hermes",
        HarnessKind::ClaudeCode => "claude",
        HarnessKind::Codex => "codex",
        HarnessKind::Pi => "pi",
        HarnessKind::Jcode => "jcode",
        HarnessKind::Argv => "hf-argv",
    }
}

/// The fake harness executable body for `kind` whose prompt invocation
/// verifies the exact documented argv shape, then runs `action`:
/// - `echo`: prints the payload back (transcript = payload);
/// - `hang`: busy-loops until the adapter deadline kills it;
/// - `auth`: prints an authentication failure and exits 1;
/// - `die`: kills itself with SIGKILL (process death);
/// - `exit-n`: exits with a plain non-zero code.
fn harness_body(kind: HarnessKind, action: &str, version: &str) -> String {
    let prompt_check = match kind {
        // Issue #92 F2: the prompt row runs the declared role binding (the
        // profile key on the documented global flag) and continues the
        // session `harness_start` bound (`chat --continue <session>
        // --create-if-missing`), with the payload as the final data element.
        HarnessKind::Hermes => format!(
            "[ \"$1\" = \"-p\" ] && [ \"$2\" = \"{}\" ] && [ \"$3\" = \"chat\" ] && [ \"$4\" = \"--continue\" ] && [ \"$5\" = \"{SESSION_ID}\" ] && [ \"$6\" = \"--create-if-missing\" ] && [ \"$7\" = \"-q\" ]",
            HarnessKind::Hermes.name()
        ),
        HarnessKind::ClaudeCode => "[ \"$1\" = \"-p\" ]".to_string(),
        HarnessKind::Codex => "[ \"$1\" = \"exec\" ]".to_string(),
        // The pinned one-shot row: the provider/model pair comes from the
        // profile binding (issue #80), then `--print`, the end-of-options
        // guard, and the payload as the final data element.
        HarnessKind::Pi => format!(
            "[ \"$1\" = \"--provider\" ] && [ \"$2\" = \"{TEST_PROVIDER}\" ] && [ \"$3\" = \"--model\" ] && [ \"$4\" = \"{TEST_MODEL}\" ] && [ \"$5\" = \"--print\" ] && [ \"$6\" = \"--\" ]"
        ),
        // The pinned one-shot row: `run`, the bound provider/model pair
        // (issue #80), `--json`, the end-of-options guard, then the payload
        // as the final data element (issue #37; the real jcode v0.84.0
        // binary accepts this row — verified 2026-09-08 — and exits 1 with
        // the measured missing-key text when no provider key is present).
        HarnessKind::Jcode => format!(
            "[ \"$1\" = \"run\" ] && [ \"$2\" = \"--provider\" ] && [ \"$3\" = \"{TEST_PROVIDER}\" ] && [ \"$4\" = \"--model\" ] && [ \"$5\" = \"{TEST_MODEL}\" ] && [ \"$6\" = \"--json\" ] && [ \"$7\" = \"--\" ]"
        ),
        HarnessKind::Argv => "true".to_string(),
    };
    let payload = match kind {
        HarnessKind::Hermes => "\"$8\"",
        HarnessKind::ClaudeCode => "\"$2\"",
        HarnessKind::Codex => "\"$2\"",
        HarnessKind::Pi => "\"$7\"",
        HarnessKind::Jcode => "\"$8\"",
        HarnessKind::Argv => "\"$1\"",
    };
    let action_body = match action {
        "echo" => format!("printf '%s' {payload}\nexit 0"),
        "hang" => "while :; do :; done".to_string(),
        "auth" => {
            "echo 'Authentication failed: sign in with your account first' >&2\nexit 1".to_string()
        }
        "die" => "kill -9 $$".to_string(),
        other => format!("exit {}", other.trim_start_matches("exit-")),
    };
    format!(
        "if [ \"$1\" = \"--version\" ]; then echo \"{version}\"; exit 0; fi\nif {prompt_check}; then {action_body}\nfi\necho \"unexpected argv: $*\" >&2\nexit 9\n"
    )
}

/// A fake `herdr` answering the workspace session read-back rows. `show`
/// returns the given session doc (identity read-back/observe source);
/// `outcome` returns a terminal outcome; `interrupt` confirms interruption.
fn workspace_body(show_json: &str) -> String {
    format!(
        r#"if [ "$1" != "session" ]; then echo "unexpected argv: $*" >&2; exit 9; fi
case "$2" in
  show) echo '{show_json}'; exit 0 ;;
  outcome) echo '{{"state":"exited","outcome":"succeeded"}}'; exit 0 ;;
  interrupt) echo '{{"state":"exited","outcome":"ambiguous"}}'; exit 0 ;;
  *) echo "unexpected argv: $*" >&2; exit 9 ;;
esac
"#
    )
}

/// The workspace session doc that matches a bound identity
/// (herdr_session `ws-7`, terminal `tty-7`, generation 3).
fn matching_show_json() -> &'static str {
    r#"{"session_id":"ws-7","generation":3,"terminal_session":"tty-7","state":"running"}"#
}

fn sample_identity() -> AgentIdentity {
    bind_identity("ws-7", "tty-7", 3).expect("bound identity")
}

/// A leaked static session handle for request helpers. Test helpers only:
/// the handle is intentionally immutable and the leak is negligible for the
/// lifetime of one test binary.
fn session_ref() -> &'static canter::adapters::SessionHandle {
    Box::leak(Box::new(
        new_session(SESSION_ID, sample_identity()).expect("session handle"),
    ))
}

/// The session id the fake prompt rows pin (the session the bound identity
/// belongs to; issue #92 F2).
const SESSION_ID: &str = "sess-20260906-0001";

fn prompt_request<'a>(payload: &'a str, timeout: Duration) -> OpRequest<'a> {
    OpRequest {
        op: Op::Prompt,
        session: session_ref(),
        payload: Some(payload),
        timeout,
    }
}

fn workspace_request(op: Op) -> OpRequest<'static> {
    OpRequest {
        op,
        session: session_ref(),
        payload: None,
        timeout: ADAPTER_TIMEOUT,
    }
}

// ---------------------------------------------------------------------------
// Exact-version probes (AC2: exact-version contract tests)
// ---------------------------------------------------------------------------

#[test]
fn official_exact_version_probes_accept_declared_current_and_refuse_below_minimum() {
    for kind in official_kinds() {
        let bins = FakeBins::new();
        let current = declared_current(kind);
        bins.bin(executable_name(kind), &harness_body(kind, "echo", current));
        let profile = official_profile(kind);
        let env = bins.env();

        let probe = probe_retry(&profile, &env);
        assert!(probe.present, "{} detail: {:?}", kind.name(), probe.detail);
        assert_eq!(
            probe.version.as_deref(),
            Some(current),
            "{} detail: {:?}",
            kind.name(),
            probe.detail
        );
        assert_eq!(
            probe.compatible,
            Some(true),
            "{} detail: {:?}",
            kind.name(),
            probe.detail
        );

        // Below the declared minimum: typed refusal signal in the probe.
        let bins_low = FakeBins::new();
        bins_low.bin(executable_name(kind), &harness_body(kind, "echo", "0.0.1"));
        let env_low = bins_low.env();
        let probe = probe_retry(&profile, &env_low);
        assert!(probe.present);
        assert_eq!(probe.compatible, Some(false));
    }
}

#[test]
fn probe_of_a_missing_executable_is_a_typed_unavailable_result() {
    for kind in official_kinds() {
        let bins = FakeBins::new();
        let profile = official_profile(kind);
        let env = bins.env();
        let probe = probe_retry(&profile, &env);
        assert!(!probe.present);
        assert_eq!(probe.code, Some(CODE_UNAVAILABLE));
    }
}

// ---------------------------------------------------------------------------
// AC2 behavior matrix (each official adapter; fake executables)
// ---------------------------------------------------------------------------

#[test]
fn success_prompt_delivers_the_payload_as_data_and_returns_the_transcript() {
    for kind in official_kinds() {
        let bins = FakeBins::new();
        bins.bin(
            executable_name(kind),
            &harness_body(kind, "echo", declared_current(kind)),
        );
        bins.bin("herdr", &workspace_body(matching_show_json()));
        let profile = official_profile(kind);
        let payload = "implement the typed adapter contract for issue 7";
        let result = run_op_retry(
            &profile,
            &prompt_request(payload, ADAPTER_TIMEOUT),
            &bins.env(),
        );
        assert_eq!(result.status, "succeeded", "{}", kind.name());
        assert_eq!(result.code, None);
        let transcript = result
            .payload
            .as_ref()
            .and_then(|p| p.get("transcript"))
            .and_then(Val::as_str)
            .expect("transcript");
        assert_eq!(
            transcript,
            payload,
            "payload round-trips as data ({})",
            kind.name()
        );
    }
}

#[test]
fn missing_executable_is_a_typed_unavailable_refusal_and_independent_ops_survive() {
    for kind in official_kinds() {
        let bins = FakeBins::new();
        // No harness executable is installed in the fake dir; herdr exists.
        bins.bin("herdr", &workspace_body(matching_show_json()));
        let profile = official_profile(kind);
        let env = bins.env();

        let result = run_op_retry(&profile, &prompt_request("hello", ADAPTER_TIMEOUT), &env);
        assert_eq!(result.status, "refused", "{}", kind.name());
        assert_eq!(result.code, Some(CODE_UNAVAILABLE));

        // Independent read-only workspace ops still succeed: the harness
        // absence never breaks other adapter operations.
        let observe = run_op_retry(&profile, &workspace_request(Op::Observe), &env);
        assert_eq!(observe.status, "succeeded");
        assert_eq!(
            observe
                .payload
                .as_ref()
                .and_then(|p| p.get("state"))
                .and_then(Val::as_str),
            Some("running")
        );
    }
}

#[test]
fn auth_failure_is_a_typed_credentials_refusal() {
    for kind in official_kinds() {
        let bins = FakeBins::new();
        bins.bin(
            executable_name(kind),
            &harness_body(kind, "auth", declared_current(kind)),
        );
        let profile = official_profile(kind);
        let result = run_op_retry(
            &profile,
            &prompt_request("do the thing", ADAPTER_TIMEOUT),
            &bins.env(),
        );
        assert_eq!(result.status, "refused", "{}", kind.name());
        assert_eq!(result.code, Some(CODE_CREDENTIALS));
        assert!(!result.message.unwrap_or_default().contains("secret"));
    }
}

#[test]
fn unsupported_capability_is_a_typed_refusal_at_the_named_boundary() {
    for kind in official_kinds() {
        let bins = FakeBins::new();
        bins.bin(
            executable_name(kind),
            &harness_body(kind, "echo", declared_current(kind)),
        );
        let profile = official_profile(kind);
        let result = run_named_retry(
            &profile,
            "teleport",
            session_ref(),
            None,
            ADAPTER_TIMEOUT,
            &bins.env(),
        );
        assert_eq!(result.status, "refused", "{}", kind.name());
        assert_eq!(result.code, Some(CODE_UNKNOWN_CAPABILITY));
    }
}

#[test]
fn hanging_prompt_is_deadline_cancelled_and_ambiguous() {
    for kind in official_kinds() {
        let bins = FakeBins::new();
        bins.bin(
            executable_name(kind),
            &harness_body(kind, "hang", declared_current(kind)),
        );
        let profile = official_profile(kind);
        let started = std::time::Instant::now();
        let result = run_op_retry(
            &profile,
            &prompt_request("please hang forever", Duration::from_millis(200)),
            &bins.env(),
        );
        let elapsed = started.elapsed();
        assert_eq!(result.status, "ambiguous", "{}", kind.name());
        assert_eq!(result.code, Some(CODE_TIMEOUT));
        assert!(
            elapsed < Duration::from_secs(5),
            "deadline enforced for {}",
            kind.name()
        );
    }
}

#[test]
fn interrupt_operation_is_accepted_and_terminal_state_is_observable() {
    for kind in official_kinds() {
        let bins = FakeBins::new();
        bins.bin(
            executable_name(kind),
            &harness_body(kind, "echo", declared_current(kind)),
        );
        bins.bin("herdr", &workspace_body(matching_show_json()));
        let profile = official_profile(kind);
        let env = bins.env();

        let interrupt = run_op_retry(&profile, &workspace_request(Op::Interrupt), &env);
        assert_eq!(interrupt.status, "succeeded", "{}", kind.name());
        assert_eq!(
            interrupt
                .payload
                .as_ref()
                .and_then(|p| p.get("interrupted")),
            Some(&Val::Bool(true))
        );
        // The session observed after cancellation reports the exited state.
        let observe = run_op_retry(&profile, &workspace_request(Op::Observe), &env);
        assert_eq!(observe.status, "succeeded");
    }
}

#[test]
fn malformed_workspace_output_is_a_typed_malformed_refusal() {
    for kind in official_kinds() {
        let bins = FakeBins::new();
        bins.bin(
            executable_name(kind),
            &harness_body(kind, "echo", declared_current(kind)),
        );
        bins.bin(
            "herdr",
            r#"echo 'this is definitely not json {{{' ; exit 0"#,
        );
        let profile = official_profile(kind);
        let result = run_op_retry(&profile, &workspace_request(Op::Observe), &bins.env());
        assert_eq!(
            result.code,
            Some(CODE_MALFORMED),
            "detail: {:?} message: {:?}",
            result.detail,
            result.message
        );
    }
}

#[test]
fn process_death_is_a_typed_ambiguous_outcome() {
    for kind in official_kinds() {
        let bins = FakeBins::new();
        bins.bin(
            executable_name(kind),
            &harness_body(kind, "die", declared_current(kind)),
        );
        let profile = official_profile(kind);
        let result = run_op_retry(
            &profile,
            &prompt_request("do not survive this", ADAPTER_TIMEOUT),
            &bins.env(),
        );
        assert_eq!(result.status, "ambiguous", "{}", kind.name());
        assert_eq!(result.code, Some(CODE_PROCESS_DEATH));
    }
}

#[test]
fn plain_nonzero_exit_is_a_typed_failed_outcome() {
    for kind in official_kinds() {
        let bins = FakeBins::new();
        bins.bin(
            executable_name(kind),
            &harness_body(kind, "exit-3", declared_current(kind)),
        );
        let profile = official_profile(kind);
        let result = run_op_retry(
            &profile,
            &prompt_request("make it fail", ADAPTER_TIMEOUT),
            &bins.env(),
        );
        assert_eq!(
            result.status,
            "failed",
            "{} code={:?} message={:?} detail={:?}",
            kind.name(),
            result.code,
            result.message,
            result.detail
        );
        assert_eq!(
            result.code,
            Some(CODE_EXIT),
            "{} message={:?} detail={:?}",
            kind.name(),
            result.message,
            result.detail
        );
    }
}

// ---------------------------------------------------------------------------
// Issue #33: Pi-specific contract rows (the shared AC2 matrix above already
// loops the pi fake for success/missing-executable/auth/unsupported/
// timeout/interrupt/malformed/process-death/identity; these rows pin the
// pi one-shot invocation shape, its measured missing-key refusal, and the
// data/env/cwd witnesses for the pi row).
// ---------------------------------------------------------------------------

#[test]
fn pi_missing_provider_key_env_is_a_typed_credentials_refusal() {
    // Real pi v0.85.1 with no provider key exits 1 with exactly this
    // measured text (2026-09-08); the closed auth markers classify it as a
    // credentials refusal. The fake's allowlisted env (PATH only) carries
    // no key, mirroring a lane whose provider env is absent.
    let bins = FakeBins::new();
    bins.bin(
        "pi",
        "if [ \"$1\" = \"--version\" ]; then echo '0.85.1'; exit 0; fi\nif [ \"$1\" = \"--provider\" ] && [ \"$6\" = \"--\" ]; then echo 'No API key found for deepseek.' >&2; echo 'Use /login to log into a provider via OAuth or API key.' >&2; exit 1; fi\necho \"unexpected argv: $*\" >&2\nexit 9\n",
    );
    let profile = pi_profile();
    let result = run_op_retry(
        &profile,
        &prompt_request("do the thing", ADAPTER_TIMEOUT),
        &bins.env(),
    );
    assert_eq!(result.status, "refused");
    assert_eq!(result.code, Some(CODE_CREDENTIALS));
    assert!(!result.message.unwrap_or_default().contains("secret"));
}

#[test]
fn pi_hostile_payload_is_data_and_environment_stays_allowlisted() {
    let bins = FakeBins::new();
    // The fake pins the exact documented pi row (provider/model flags,
    // `--print`, the `--` end-of-options guard) and echoes back the payload
    // plus the environment it actually saw.
    bins.bin(
        "pi",
        &format!(
            r#"if [ "$1" = "--provider" ] && [ "$2" = "{TEST_PROVIDER}" ] && [ "$3" = "--model" ] && [ "$4" = "{TEST_MODEL}" ] && [ "$5" = "--print" ] && [ "$6" = "--" ]; then printf 'argv_ok payload=[%s] path=[%s] secret=[%s]' "$7" "$PATH" "${{HF_TEST_SECRET_VAR:-unset}}"; exit 0; fi
echo "unexpected argv: $*" >&2
exit 9
"#
        ),
    );
    let profile = pi_profile();
    let hostile = "a; rm -rf /tmp/x; $(touch /tmp/pwned33); `echo injected`; \"quoted\"; && || | > < & newline\nhere; s/ed/; -leading --flag-like";
    let result = run_op_retry(
        &profile,
        &prompt_request(hostile, ADAPTER_TIMEOUT),
        &bins.env(),
    );
    assert_eq!(result.status, "succeeded");
    let transcript = result
        .payload
        .as_ref()
        .and_then(|p| p.get("transcript"))
        .and_then(Val::as_str)
        .expect("transcript");
    assert!(
        transcript.starts_with("argv_ok"),
        "fake saw the documented pi argv"
    );
    assert!(
        transcript.contains(&format!("payload=[{hostile}]")),
        "payload arrived verbatim as one data element"
    );
    assert!(
        transcript.contains("secret=[unset]"),
        "host variables never reach the child (AC8)"
    );
    assert!(
        transcript.contains(&format!("path=[{}]", bins.path.display())),
        "PATH is the allowlisted one"
    );
    assert!(
        !std::path::Path::new("/tmp/pwned33").exists(),
        "no injection happened"
    );
}

/// The pi fake executable body whose stdout is its own `$0` on the pinned
/// prompt row (the absolute-$0 C1 witness, issue #8) — mirrors the argv
/// fake witness for the pi invocation row.
#[test]
fn pi_spawned_identity_is_the_resolved_absolute_path_witness() {
    let bins = FakeBins::new();
    let fake = bins.bin(
        "pi",
        "if [ \"$1\" = \"--provider\" ] && [ \"$6\" = \"--\" ]; then printf '%s' \"$0\"; exit 0; fi\nexit 9\n",
    );
    let profile = pi_profile();
    let identity = bind_identity("ws-session-33", "tty-33-pi", 1).expect("identity");
    let session = new_session("sess-pi-c1-witness", identity).expect("session");
    let result = run_op_retry(
        &profile,
        &OpRequest {
            op: Op::Prompt,
            session: &session,
            payload: Some("synthetic payload"),
            timeout: ADAPTER_TIMEOUT,
        },
        &bins.env(),
    );
    assert_eq!(result.status, "succeeded");
    let transcript = result
        .payload
        .as_ref()
        .and_then(|payload| payload.get("transcript"))
        .and_then(Val::as_str)
        .expect("transcript");
    // $0 must be the absolute resolved location of the fake executable.
    assert!(
        PathBuf::from(transcript).is_absolute(),
        "spawned identity must be absolute: {transcript}"
    );
    // Compare canonical forms on BOTH sides (macOS temp-dir symlinks).
    let canonical_fake = fs::canonicalize(&fake).expect("canonical fake");
    let spawned =
        fs::canonicalize(Path::new(transcript)).unwrap_or_else(|_| PathBuf::from(transcript));
    assert_eq!(
        spawned, canonical_fake,
        "the spawned $0 must equal the resolved absolute executable"
    );
}

/// Lane pi harness work is confined to the assigned worktree: the child's
/// cwd must be the worktree path passed through `execute_op_in_worktree`.
#[test]
fn pi_prompt_runs_confined_to_the_assigned_worktree() {
    let bins = FakeBins::new();
    bins.bin(
        "pi",
        "if [ \"$1\" = \"--provider\" ] && [ \"$6\" = \"--\" ]; then pwd; exit 0; fi\nexit 9\n",
    );
    let profile = pi_profile();
    let identity = bind_identity("ws-session-33", "tty-33-pi", 1).expect("identity");
    let session = new_session("sess-pi-confinement", identity).expect("session");
    // A fake "worktree" directory (the test stands in for the lane root).
    let base = std::env::var_os("CARGO_TARGET_TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let worktree = base.join(format!("hf-adapters-pi-wt-{}", std::process::id()));
    let _ = fs::remove_dir_all(&worktree);
    fs::create_dir_all(&worktree).expect("worktree dir");
    // Capture the canonical expectation WHILE the directory exists (macOS
    // temp-dir symlink spelling; see the argv witness test).
    let expected_cwd = fs::canonicalize(&worktree).unwrap_or_else(|_| worktree.clone());

    let result = canter::adapters::execute_op_in_worktree(
        &profile,
        &OpRequest {
            op: Op::Prompt,
            session: &session,
            payload: Some("synthetic payload"),
            timeout: ADAPTER_TIMEOUT,
        },
        &bins.env(),
        &worktree,
    );
    let _ = fs::remove_dir_all(&worktree);
    assert_eq!(result.status, "succeeded");
    let transcript = result
        .payload
        .as_ref()
        .and_then(|payload| payload.get("transcript"))
        .and_then(Val::as_str)
        .expect("transcript");
    assert_eq!(
        PathBuf::from(transcript.trim()),
        expected_cwd,
        "pi child must run inside the assigned worktree"
    );
}

// ---------------------------------------------------------------------------
// AC3: identity read-back and stale-identity refusals
// ---------------------------------------------------------------------------

#[test]
fn identity_read_back_matches_the_bound_triple_and_stale_read_backs_are_refused() {
    for kind in official_kinds() {
        let bins = FakeBins::new();
        bins.bin(
            executable_name(kind),
            &harness_body(kind, "echo", declared_current(kind)),
        );
        bins.bin("herdr", &workspace_body(matching_show_json()));
        let profile = official_profile(kind);
        let env = bins.env();

        // Fresh identity read-back: all three parts match.
        let identity = run_op_retry(&profile, &workspace_request(Op::Identity), &env);
        assert_eq!(identity.status, "succeeded", "{}", kind.name());
        let payload = identity.payload.expect("identity payload");
        assert_eq!(
            payload.get("herdr_session"),
            Some(&Val::Str("ws-7".to_string()))
        );
        assert_eq!(payload.get("generation"), Some(&Val::Int(3)));

        // Stale generation read-back: the workspace session was recreated
        // (generation 4) while the handle is still bound to generation 3.
        let bins_stale = FakeBins::new();
        bins_stale.bin(
            executable_name(kind),
            &harness_body(kind, "echo", declared_current(kind)),
        );
        bins_stale.bin(
            "herdr",
            &workspace_body(r#"{"session_id":"ws-7","generation":4,"terminal_session":"tty-7","state":"running"}"#),
        );
        let result = run_op_retry(
            &profile,
            &workspace_request(Op::Identity),
            &bins_stale.env(),
        );
        assert_eq!(result.status, "refused", "{}", kind.name());
        assert_eq!(result.code, Some(CODE_STALE_IDENTITY));
        assert!(result.message.unwrap().contains("generation"));

        // A terminal-session swap is stale the same way.
        let bins_swap = FakeBins::new();
        bins_swap.bin(
            executable_name(kind),
            &harness_body(kind, "echo", declared_current(kind)),
        );
        bins_swap.bin(
            "herdr",
            &workspace_body(r#"{"session_id":"ws-7","generation":3,"terminal_session":"tty-OTHER","state":"running"}"#),
        );
        let result = run_op_retry(&profile, &workspace_request(Op::Identity), &bins_swap.env());
        assert_eq!(result.code, Some(CODE_STALE_IDENTITY));
    }
}

// ---------------------------------------------------------------------------
// AC1: the same plan fixture drives every fake adapter implementation
// ---------------------------------------------------------------------------

/// The canonical plan fixture (data, never code): the ops the adapter
/// contract must serve are derived from its typed steps.
const PLAN_FIXTURE: &str = include_str!("../schemas/fixtures/plan/plan.valid.json");
const DOCTRINE_FIXTURE: &str = include_str!("../schemas/fixtures/workflow/workflow.doctrine.json");

#[test]
fn same_plan_fixture_passes_against_fake_implementations_of_every_adapter_contract() {
    // The fixture documents validate as the closed families first.
    let plan_doc = Val::parse_json(PLAN_FIXTURE).expect("plan fixture parses");
    let plan_bytes = canonical_bytes(&plan_doc);
    assert!(validate_bytes(Family::Plan, &plan_bytes).is_accepted());
    let doctrine_doc = Val::parse_json(DOCTRINE_FIXTURE).expect("doctrine fixture parses");
    assert!(validate_bytes(Family::Workflow, &canonical_bytes(&doctrine_doc)).is_accepted());

    // Derive the typed operation sequence: harness-relevant plan step kinds
    // map to contract ops; other step kinds are not harness operations
    // (engine/daemon territory). The payload for prompt delivery is derived
    // from the plan's own typed issue binding (data in, data out).
    let issue_number = plan_doc
        .get("issue")
        .and_then(|i| i.get("number"))
        .and_then(Val::as_int)
        .unwrap_or(0);
    let issue_revision = plan_doc
        .get("issue")
        .and_then(|i| i.get("revision"))
        .and_then(Val::as_str)
        .unwrap_or("")
        .to_string();
    let steps = plan_doc
        .get("steps")
        .and_then(Val::as_array)
        .expect("steps");
    let mut sequence: Vec<(&'static str, Option<String>)> = Vec::new();
    for step in steps {
        let kind = step.get("kind").and_then(Val::as_str).unwrap_or("");
        match kind {
            "harness_start" => sequence.push(("start", None)),
            "prompt" => sequence.push((
                "prompt",
                Some(format!(
                    "issue {issue_number} revision {issue_revision}: implement per the acceptance text"
                )),
            )),
            "collect_outcome" => sequence.push(("outcome", None)),
            "review_evidence" => sequence.push(("identity", None)),
            _ => {}
        }
    }
    assert_eq!(sequence.len(), 4, "fixture-derived scenario has 4 ops");

    // Every adapter contract implementation (fake hermes, fake claude-code,
    // fake codex, and the declarative argv fake) runs the SAME sequence
    // with the SAME typed payloads and must reach the SAME terminal
    // outcomes.
    let mut status_sets: Vec<Vec<&'static str>> = Vec::new();
    for kind in official_kinds() {
        let bins = FakeBins::new();
        bins.bin(
            executable_name(kind),
            &harness_body(kind, "echo", declared_current(kind)),
        );
        bins.bin("herdr", &workspace_body(matching_show_json()));
        let profile = official_profile(kind);
        let statuses = run_scenario(&profile, &sequence, &bins.env(), kind.name());
        status_sets.push(statuses);
    }

    // Declarative argv adapter with the full closed capability set.
    let bins = FakeBins::new();
    bins.bin("hf-argv", &harness_body(HarnessKind::Argv, "echo", ""));
    bins.bin("herdr", &workspace_body(matching_show_json()));
    let profile = Profile::argv(
        "cli-fake",
        "hf-argv",
        &[
            "discover",
            "start",
            "prompt",
            "observe",
            "interrupt",
            "outcome",
            "identity",
        ],
        BTreeMap::new(),
    )
    .expect("argv profile")
    .with_execution(ExecutionMode::Headless);
    let statuses = run_scenario(&profile, &sequence, &bins.env(), "argv");
    status_sets.push(statuses);

    let reference = status_sets[0].clone();
    for (index, statuses) in status_sets.iter().enumerate() {
        assert_eq!(
            *statuses, reference,
            "implementation {index} diverged from the shared fixture outcome"
        );
    }
    assert_eq!(reference, vec!["succeeded"; 4]);
}

/// Run the fixture-derived scenario against one profile; every step must
/// produce a validated `hf-outcome/v1` document.
fn run_scenario(
    profile: &Profile,
    sequence: &[(&'static str, Option<String>)],
    env: &BTreeMap<String, String>,
    label: &str,
) -> Vec<&'static str> {
    let handle = session_ref();
    let mut statuses = Vec::new();
    let mut step_index = 0;
    for (op_name, payload) in sequence {
        step_index += 1;
        let timeout = if *op_name == "prompt" {
            Duration::from_secs(5)
        } else {
            ADAPTER_TIMEOUT
        };
        let result = run_named_retry(profile, op_name, handle, payload.as_deref(), timeout, env);
        let step_id = format!("p{step_index}");
        let doc = result.to_outcome_doc(
            "hf_plan_0123456789abcdef",
            &step_id,
            &format!("ik_scenario-{step_index}"),
            "2026-09-06T00:00:00Z",
        );
        let verdict = validate_bytes(Family::Outcome, &canonical_bytes(&doc));
        assert!(
            verdict.is_accepted(),
            "{label} step {step_id} outcome invalid: {}",
            verdict.message()
        );
        statuses.push(result.status);
    }
    statuses
}

// ---------------------------------------------------------------------------
// AC5: prompts and untrusted issue text are data; argv and policy never
// change; environment stays allowlisted (AC8)
// ---------------------------------------------------------------------------

#[test]
fn hostile_payload_text_is_data_and_cannot_alter_argv_or_environment() {
    let bins = FakeBins::new();
    // The fake verifies the exact documented argv shape and echoes back
    // the payload plus the environment it actually saw.
    bins.bin(
        "claude",
        r#"if [ "$1" = "-p" ]; then printf 'argv_ok payload=[%s] path=[%s] secret=[%s]' "$2" "$PATH" "${HF_TEST_SECRET_VAR:-unset}"; exit 0; fi
echo "unexpected argv: $*" >&2
exit 9
"#,
    );
    let profile = Profile::official(HarnessKind::ClaudeCode, "claude-code")
        .expect("profile")
        .with_execution(ExecutionMode::Headless);
    let hostile = "a; rm -rf /tmp/x; $(touch /tmp/pwned); `echo injected`; \"quoted\"; && || | > < & newline\nhere; s/ed/";
    let result = run_op_retry(
        &profile,
        &prompt_request(hostile, ADAPTER_TIMEOUT),
        &bins.env(),
    );
    assert_eq!(result.status, "succeeded");
    let transcript = result
        .payload
        .as_ref()
        .and_then(|p| p.get("transcript"))
        .and_then(Val::as_str)
        .expect("transcript");
    assert!(
        transcript.starts_with("argv_ok"),
        "fake saw the documented argv"
    );
    assert!(
        transcript.contains(&format!("payload=[{hostile}]")),
        "payload arrived verbatim as one data element"
    );
    assert!(
        transcript.contains("secret=[unset]"),
        "host variables never reach the child (AC8)"
    );
    assert!(
        transcript.contains(&format!("path=[{}]", bins.path.display())),
        "PATH is the allowlisted one"
    );
    assert!(
        !std::path::Path::new("/tmp/pwned").exists(),
        "no injection happened"
    );
}

// ---------------------------------------------------------------------------
// AC4: unknown harness kinds fail typed without breaking independent
// read-only operations
// ---------------------------------------------------------------------------

#[test]
fn unknown_harness_kind_fails_typed_and_independent_probes_keep_working() {
    let bins = FakeBins::new();
    bins.bin(
        "hermes",
        &harness_body(
            HarnessKind::Hermes,
            "echo",
            declared_current(HarnessKind::Hermes),
        ),
    );
    bins.bin("herdr", &workspace_body(matching_show_json()));

    // An unknown configured kind is refused at profile construction...
    let unknown = ConfigHarness {
        key: "teleporter".to_string(),
        kind: "teleport".to_string(),
        executable: "teleport".to_string(),
        env_allow: vec!["PATH".to_string()],
        provider: None,
        model: None,
        fallback: vec![],
        secret_env: vec![],
        limits: vec![],
        binding_introspection: false,
        skills: Vec::new(),
    };
    let err = Profile::from_config(&unknown).expect_err("unknown kind refused");
    assert_eq!(err.code, CODE_UNKNOWN_HARNESS);
    assert!(err.message.contains("teleport"));

    // ...while an unrelated configured adapter and its read-only ops keep
    // working (observe.rs pattern: per-surface degradation, never global).
    let known = ConfigHarness {
        key: "hermes-a".to_string(),
        kind: "hermes".to_string(),
        executable: "hermes".to_string(),
        env_allow: vec!["PATH".to_string()],
        provider: None,
        model: None,
        fallback: vec![],
        secret_env: vec![],
        limits: vec![],
        binding_introspection: false,
        skills: Vec::new(),
    };
    let profile = Profile::from_config(&known)
        .expect("known kind parses")
        .with_execution(ExecutionMode::Headless);
    let probe = probe_retry(&profile, &bins.env());
    assert!(probe.present);
    let observe = run_op_retry(&profile, &workspace_request(Op::Observe), &bins.env());
    assert_eq!(observe.status, "succeeded");
}

// ---------------------------------------------------------------------------
// Issue #8 C1: the "verified absolute identity is spawned" layer is
// WITNESSED — a fake asserts $0 (its own argv[0]) equals the absolute
// resolved location, and lane ops can be confined to an assigned worktree.
// ---------------------------------------------------------------------------

/// A fake harness whose stdout is its own `$0` — the path the kernel used
/// to exec the script. The adapter contract resolves the bare executable
/// through the allowlisted PATH and spawns the resolved absolute path, so a
/// prompt's transcript must equal that absolute location (never a bare
/// name, never a relative resolution).
#[test]
fn spawned_identity_is_the_resolved_absolute_path_witness() {
    let bins = FakeBins::new();
    let fake = bins.bin("hf-argv", "printf '%s' \"$0\"\n");
    let profile = Profile::argv(
        "lane",
        "hf-argv",
        &[
            "start",
            "prompt",
            "observe",
            "interrupt",
            "outcome",
            "identity",
        ],
        BTreeMap::new(),
    )
    .expect("argv profile")
    .with_execution(ExecutionMode::Headless);
    let identity = bind_identity("ws-session-8", "tty-8-c1", 1).expect("identity");
    let session = new_session("sess-c1-witness", identity).expect("session");
    let result = run_op_retry(
        &profile,
        &OpRequest {
            op: Op::Prompt,
            session: &session,
            payload: Some("synthetic payload"),
            timeout: ADAPTER_TIMEOUT,
        },
        &bins.env(),
    );
    assert_eq!(result.status, "succeeded");
    let transcript = result
        .payload
        .as_ref()
        .and_then(|payload| payload.get("transcript"))
        .and_then(Val::as_str)
        .expect("transcript");
    // $0 must be the absolute resolved location of the fake executable.
    assert!(
        PathBuf::from(transcript).is_absolute(),
        "spawned identity must be absolute: {transcript}"
    );
    // Compare canonical forms on BOTH sides: on macOS the temp dir is
    // reached through a symlink (/var/folders -> /private/var/folders),
    // so the spawned argv[0] literal and the canonicalized expectation
    // must not be compared byte-wise across that boundary.
    let canonical_fake = fs::canonicalize(&fake).expect("canonical fake");
    let spawned =
        fs::canonicalize(Path::new(transcript)).unwrap_or_else(|_| PathBuf::from(transcript));
    assert_eq!(
        spawned, canonical_fake,
        "the spawned $0 must equal the resolved absolute executable"
    );
}

/// Lane harness work is confined to the assigned worktree: the child's cwd
/// must be the worktree path passed through `execute_op_in_worktree`.
#[test]
fn harness_prompt_runs_confined_to_the_assigned_worktree() {
    let bins = FakeBins::new();
    bins.bin("hf-argv", "pwd\n");
    let profile = Profile::argv(
        "lane",
        "hf-argv",
        &[
            "start",
            "prompt",
            "observe",
            "interrupt",
            "outcome",
            "identity",
        ],
        BTreeMap::new(),
    )
    .expect("argv profile")
    .with_execution(ExecutionMode::Headless);
    let identity = bind_identity("ws-session-8", "tty-8-c1", 1).expect("identity");
    let session = new_session("sess-c1-confinement", identity).expect("session");
    // A fake "worktree" directory (the test stands in for the lane root).
    let base = std::env::var_os("CARGO_TARGET_TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let worktree = base.join(format!("hf-adapters-wt-{}", std::process::id()));
    let _ = fs::remove_dir_all(&worktree);
    fs::create_dir_all(&worktree).expect("worktree dir");
    // Capture the canonical expectation WHILE the directory exists: on
    // macOS the temp dir is reached through a symlink (/var/folders ->
    // /private/var/folders) and a child's getcwd/pwd reports the canonical
    // form, while the assigned (spawn) path may be the non-canonical one.
    // The directory is removed below before the transcript is compared, so
    // canonicalization after the run would fall back to the raw literal and
    // byte-compare two different spellings of the same directory.
    let expected_cwd = fs::canonicalize(&worktree).unwrap_or_else(|_| worktree.clone());

    let result = canter::adapters::execute_op_in_worktree(
        &profile,
        &OpRequest {
            op: Op::Prompt,
            session: &session,
            payload: Some("synthetic payload"),
            timeout: ADAPTER_TIMEOUT,
        },
        &bins.env(),
        &worktree,
    );
    let _ = fs::remove_dir_all(&worktree);
    assert_eq!(result.status, "succeeded");
    let transcript = result
        .payload
        .as_ref()
        .and_then(|payload| payload.get("transcript"))
        .and_then(Val::as_str)
        .expect("transcript");
    assert_eq!(
        PathBuf::from(transcript.trim()),
        expected_cwd,
        "harness child must run inside the assigned worktree"
    );
}

// ---------------------------------------------------------------------------
// Issue #33 A2: herdr lifecycle reporting rows (pi adapter under herdr)
//
// herdr's custom-integration contract (verified at 0.8.2 and 0.9.0): an
// agent running in a herdr pane inherits HERDR_ENV/HERDR_PANE_ID; reports
// go through `pane report-agent <pane> --source <id> --agent <label>
// --state <state>`; the source must be stable and unique; reporting is a
// no-op outside herdr. The fake `herdr` below logs the exact argv it
// receives to `$HF_FAKE_LOG` (allowlisted in the test env) so the tests
// pin the documented rows byte-for-byte.
// ---------------------------------------------------------------------------

/// A fake `herdr` that logs every invocation's argv to `$HF_FAKE_LOG` and
/// exits 0 (report accepted). The log path travels in the allowlisted env.
fn herdr_logger_body() -> &'static str {
    "echo \"$*\" >> \"$HF_FAKE_LOG\"\nexit 0\n"
}

fn pi_profile() -> Profile {
    official_profile(HarnessKind::Pi)
}

/// Read the fake-herdr argv log written by the last run.
fn read_fake_log(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_default()
}

/// The settled (last) lifecycle report row in the fake-herdr argv log. A
/// bounded spawn retry can re-run the prompt operation, so the log may
/// carry more than one report row; the final row is the settled report.
fn last_fake_log_line(path: &Path) -> String {
    read_fake_log(path)
        .lines()
        .last()
        .unwrap_or_default()
        .to_string()
}

#[test]
fn pi_start_under_herdr_reports_working_with_the_documented_row() {
    let bins = FakeBins::new();
    let log = bins.path.join("herdr-argv.log");
    bins.bin("herdr", herdr_logger_body());
    let profile = pi_profile();
    let mut env = bins.env_herdr();
    env.insert(
        "HF_FAKE_LOG".to_string(),
        log.to_string_lossy().into_owned(),
    );
    let result = run_op_retry(
        &profile,
        &OpRequest {
            op: Op::Start,
            session: session_ref(),
            payload: None,
            timeout: ADAPTER_TIMEOUT,
        },
        &env,
    );
    assert_eq!(result.status, "succeeded");
    assert_eq!(
        read_fake_log(&log),
        "pane report-agent w33:p1 --source custom:herdr-fleet-pi --agent pi --state working\n"
    );
}

#[test]
fn pi_prompt_under_herdr_reports_idle_after_a_successful_one_shot() {
    let bins = FakeBins::new();
    let log = bins.path.join("herdr-argv.log");
    bins.bin("herdr", herdr_logger_body());
    bins.bin("pi", &harness_body(HarnessKind::Pi, "echo", "0.85.1"));
    let profile = pi_profile();
    let mut env = bins.env_herdr();
    env.insert(
        "HF_FAKE_LOG".to_string(),
        log.to_string_lossy().into_owned(),
    );
    let result = run_op_retry(
        &profile,
        &prompt_request("implement the thing", ADAPTER_TIMEOUT),
        &env,
    );
    assert_eq!(result.status, "succeeded", "report must not change the op");
    assert_eq!(
        last_fake_log_line(&log),
        "pane report-agent w33:p1 --source custom:herdr-fleet-pi --agent pi --state idle"
    );
}

#[test]
fn pi_prompt_credentials_under_herdr_reports_blocked_with_a_static_message() {
    let bins = FakeBins::new();
    let log = bins.path.join("herdr-argv.log");
    bins.bin("herdr", herdr_logger_body());
    bins.bin(
        "pi",
        "if [ \"$1\" = \"--version\" ]; then echo '0.85.1'; exit 0; fi\nif [ \"$1\" = \"--provider\" ] && [ \"$6\" = \"--\" ]; then echo 'No API key found for deepseek.' >&2; exit 1; fi\nexit 9\n",
    );
    let profile = pi_profile();
    let mut env = bins.env_herdr();
    env.insert(
        "HF_FAKE_LOG".to_string(),
        log.to_string_lossy().into_owned(),
    );
    let result = run_op_retry(
        &profile,
        &prompt_request("do the thing", ADAPTER_TIMEOUT),
        &env,
    );
    assert_eq!(result.status, "refused");
    assert_eq!(result.code, Some(CODE_CREDENTIALS));
    assert_eq!(
        last_fake_log_line(&log),
        "pane report-agent w33:p1 --source custom:herdr-fleet-pi --agent pi --state blocked --message harness credentials required"
    );
}

#[test]
fn pi_prompt_timeout_under_herdr_reports_idle_after_the_deadline_kill() {
    let bins = FakeBins::new();
    let log = bins.path.join("herdr-argv.log");
    bins.bin("herdr", herdr_logger_body());
    bins.bin("pi", &harness_body(HarnessKind::Pi, "hang", "0.85.1"));
    let profile = pi_profile();
    let mut env = bins.env_herdr();
    env.insert(
        "HF_FAKE_LOG".to_string(),
        log.to_string_lossy().into_owned(),
    );
    let result = run_op_retry(
        &profile,
        &prompt_request("please hang", Duration::from_millis(200)),
        &env,
    );
    assert_eq!(result.status, "ambiguous");
    assert_eq!(result.code, Some(CODE_TIMEOUT));
    assert_eq!(
        last_fake_log_line(&log),
        "pane report-agent w33:p1 --source custom:herdr-fleet-pi --agent pi --state idle"
    );
}

#[test]
fn pi_operations_outside_herdr_never_report_lifecycle() {
    // No HERDR_* markers in the allowlisted env: the workspace executable
    // must never be invoked for lifecycle reporting. The fake herdr would
    // log any invocation, and would also fail workspace rows it must not
    // receive; pi start/prompt still succeed (pure mode).
    let bins = FakeBins::new();
    let log = bins.path.join("herdr-argv.log");
    bins.bin("herdr", herdr_logger_body());
    bins.bin("pi", &harness_body(HarnessKind::Pi, "echo", "0.85.1"));
    let profile = pi_profile();
    let mut env = bins.env(); // no herdr markers
    env.insert(
        "HF_FAKE_LOG".to_string(),
        log.to_string_lossy().into_owned(),
    );
    let start = run_op_retry(
        &profile,
        &OpRequest {
            op: Op::Start,
            session: session_ref(),
            payload: None,
            timeout: ADAPTER_TIMEOUT,
        },
        &env,
    );
    assert_eq!(start.status, "succeeded");
    let prompt = run_op_retry(&profile, &prompt_request("hello", ADAPTER_TIMEOUT), &env);
    assert_eq!(prompt.status, "succeeded");
    assert_eq!(
        read_fake_log(&log),
        "",
        "no lifecycle reports outside a herdr pane"
    );
}

#[test]
fn pi_herdr_report_failure_never_changes_the_typed_op_result() {
    // The workspace executable fails every report row: the op result is
    // unchanged (lifecycle reporting is best-effort sideband).
    let bins = FakeBins::new();
    bins.bin("herdr", "exit 1\n");
    let profile = pi_profile();
    let env = bins.env_herdr();
    let result = run_op_retry(
        &profile,
        &OpRequest {
            op: Op::Start,
            session: session_ref(),
            payload: None,
            timeout: ADAPTER_TIMEOUT,
        },
        &env,
    );
    assert_eq!(result.status, "succeeded");
    assert_eq!(result.code, None);
    let prompt = run_op_retry(&profile, &prompt_request("hello", ADAPTER_TIMEOUT), &env);
    assert_eq!(prompt.status, "refused");
    assert_eq!(prompt.code, Some(CODE_UNAVAILABLE));
}

// ---------------------------------------------------------------------------
// Issue #37: Jcode-specific contract rows (the shared AC2 matrix above
// already loops the jcode fake for success/missing-executable/auth/
// unsupported/timeout/interrupt/malformed/process-death/identity; these
// rows pin the jcode one-shot invocation shape, its measured missing-key
// refusal, the real `--version` output shape, the `--json` envelope
// transcript, and the data/env/cwd witnesses for the jcode row).
// ---------------------------------------------------------------------------

/// The jcode fake whose prompt invocation verifies the exact documented
/// row (`run --provider <binding> --model <binding> --json --`; the pair
/// comes from the profile binding, issue #80) and then prints `line`
/// (plus the version branch).
fn jcode_row_body(line: &str) -> String {
    format!(
        "if [ \"$1\" = \"--version\" ]; then echo '0.84.0'; exit 0; fi\nif [ \"$1\" = \"run\" ] && [ \"$2\" = \"--provider\" ] && [ \"$3\" = \"{TEST_PROVIDER}\" ] && [ \"$4\" = \"--model\" ] && [ \"$5\" = \"{TEST_MODEL}\" ] && [ \"$6\" = \"--json\" ] && [ \"$7\" = \"--\" ]; then {line}\nfi\necho \"unexpected argv: $*\" >&2\nexit 9\n"
    )
}

#[test]
fn jcode_missing_provider_key_env_is_a_typed_credentials_refusal() {
    // Real jcode v0.84.0 with no provider key exits 1 with exactly this
    // measured text (2026-09-08); the closed auth markers classify it as a
    // credentials refusal. The fake's allowlisted env (PATH only) carries
    // no key, mirroring a lane whose provider env is absent.
    let bins = FakeBins::new();
    bins.bin(
        "jcode",
        &jcode_row_body(
            "echo 'Error: DEEPSEEK_API_KEY not found in environment or ~/.config/jcode/deepseek.env' >&2\nexit 1",
        ),
    );
    let profile = jcode_profile();
    let result = run_op_retry(
        &profile,
        &prompt_request("do the thing", ADAPTER_TIMEOUT),
        &bins.env(),
    );
    assert_eq!(result.status, "refused");
    assert_eq!(result.code, Some(CODE_CREDENTIALS));
    assert!(!result.message.unwrap_or_default().contains("secret"));
}

#[test]
fn jcode_real_version_output_shape_is_parsed_by_the_probe() {
    // The real binary prints `jcode v0.84.0 (57d587899)` (measured
    // 2026-09-08): the version token carries a leading `v` and the line
    // has a trailing build id. The probe must strip the `v` and find the
    // semver token (fake executables in the shared loop echo the bare
    // version; this row pins the real-world output shape).
    let bins = FakeBins::new();
    bins.bin(
        "jcode",
        "if [ \"$1\" = \"--version\" ]; then echo 'jcode v0.84.0 (57d587899)'; exit 0; fi\nexit 9\n",
    );
    let profile = jcode_profile();
    let probe = probe_retry(&profile, &bins.env());
    assert!(probe.present, "detail: {:?}", probe.detail);
    assert_eq!(probe.version.as_deref(), Some("0.84.0"));
    assert_eq!(probe.compatible, Some(true));
}

#[test]
fn jcode_json_envelope_transcript_and_returned_identity_are_surfaced() {
    // jcode's `--json` row prints one top-level JSON object on stdout
    // whose `text` field carries the final answer and whose
    // `provider`/`model` fields carry the identity the harness actually
    // used (shape measured against the real jcode v0.84.0 binary on
    // 2026-09-08; issue #80). The adapter parses the envelope so the typed
    // transcript is the model text and the requested/returned identity
    // pair is observable on the typed result.
    let bins = FakeBins::new();
    let envelope = format!(
        "{{\n  \"session_id\": \"session_kangaroo_1788883711941_a3cc1cf55178c963\",\n  \"provider\": \"{TEST_PROVIDER}\",\n  \"model\": \"{TEST_MODEL}\",\n  \"text\": \"implemented the ini parser; 12 tests pass\",\n  \"usage\": {{\"input_tokens\": 123, \"output_tokens\": 45}}\n}}"
    );
    bins.bin(
        "jcode",
        &jcode_row_body(&format!("printf '%s' '{envelope}'\nexit 0")),
    );
    let profile = jcode_profile();
    let result = run_op_retry(
        &profile,
        &prompt_request("implement the ini parser", ADAPTER_TIMEOUT),
        &bins.env(),
    );
    assert_eq!(result.status, "succeeded");
    let payload = result.payload.as_ref().expect("payload");
    assert_eq!(
        payload.get("transcript").and_then(Val::as_str),
        Some("implemented the ini parser; 12 tests pass")
    );
    let requested = payload.get("requested").expect("requested identity");
    assert_eq!(
        requested.get("provider").and_then(Val::as_str),
        Some(TEST_PROVIDER)
    );
    assert_eq!(
        requested.get("model").and_then(Val::as_str),
        Some(TEST_MODEL)
    );
    let returned = payload.get("returned").expect("returned identity");
    assert_eq!(
        returned.get("provider").and_then(Val::as_str),
        Some(TEST_PROVIDER)
    );
    assert_eq!(
        returned.get("model").and_then(Val::as_str),
        Some(TEST_MODEL)
    );
}

#[test]
fn jcode_returned_identity_mismatch_is_observable_and_never_coerced() {
    // The envelope reports a different provider/model than the requested
    // binding: both are surfaced verbatim — the returned identity is never
    // overwritten with the requested pair (issue #80 AC4).
    let bins = FakeBins::new();
    let envelope = "{\n  \"provider\": \"other-provider-9\",\n  \"model\": \"other-model-9\",\n  \"text\": \"mismatch transcript\"\n}";
    bins.bin(
        "jcode",
        &jcode_row_body(&format!("printf '%s' '{envelope}'\nexit 0")),
    );
    let profile = jcode_profile();
    let result = run_op_retry(
        &profile,
        &prompt_request("payload", ADAPTER_TIMEOUT),
        &bins.env(),
    );
    assert_eq!(result.status, "succeeded");
    let payload = result.payload.as_ref().expect("payload");
    assert_eq!(
        payload.get("transcript").and_then(Val::as_str),
        Some("mismatch transcript")
    );
    assert_eq!(
        payload
            .get("requested")
            .and_then(|identity| identity.get("provider"))
            .and_then(Val::as_str),
        Some(TEST_PROVIDER)
    );
    assert_eq!(
        payload
            .get("returned")
            .and_then(|identity| identity.get("provider"))
            .and_then(Val::as_str),
        Some("other-provider-9")
    );
    assert_eq!(
        payload
            .get("returned")
            .and_then(|identity| identity.get("model"))
            .and_then(Val::as_str),
        Some("other-model-9")
    );
}

#[test]
fn jcode_non_envelope_stdout_keeps_the_raw_transcript() {
    // Non-envelope stdout falls back to the raw transcript with no content
    // loss; no returned identity is observable, while the requested
    // binding is still surfaced (issue #80 AC4).
    let bins = FakeBins::new();
    bins.bin(
        "jcode",
        &jcode_row_body("printf '%s' 'plain model output; no envelope'\nexit 0"),
    );
    let profile = jcode_profile();
    let result = run_op_retry(
        &profile,
        &prompt_request("payload", ADAPTER_TIMEOUT),
        &bins.env(),
    );
    assert_eq!(result.status, "succeeded");
    let payload = result.payload.as_ref().expect("payload");
    assert_eq!(
        payload.get("transcript").and_then(Val::as_str),
        Some("plain model output; no envelope")
    );
    assert_eq!(payload.get("returned"), Some(&Val::Null));
    assert!(
        payload.get("requested").is_some(),
        "the requested binding stays observable"
    );
}

#[test]
fn jcode_hostile_payload_is_data_and_environment_stays_allowlisted() {
    let bins = FakeBins::new();
    // The fake pins the exact documented jcode row (`run`, provider/model
    // flags, `--json`, the `--` end-of-options guard) and echoes back the
    // payload plus the environment it actually saw.
    bins.bin(
        "jcode",
        &jcode_row_body(
            "printf 'argv_ok payload=[%s] path=[%s] secret=[%s]' \"$8\" \"$PATH\" \"${HF_TEST_SECRET_VAR:-unset}\"\nexit 0",
        ),
    );
    let profile = jcode_profile();
    let hostile = "a; rm -rf /tmp/x; $(touch /tmp/pwned37); `echo injected`; \"quoted\"; && || | > < & newline\nhere; s/ed/; -leading --flag-like";
    let result = run_op_retry(
        &profile,
        &prompt_request(hostile, ADAPTER_TIMEOUT),
        &bins.env(),
    );
    assert_eq!(result.status, "succeeded");
    let transcript = result
        .payload
        .as_ref()
        .and_then(|p| p.get("transcript"))
        .and_then(Val::as_str)
        .expect("transcript");
    assert!(
        transcript.starts_with("argv_ok"),
        "fake saw the documented jcode argv"
    );
    assert!(
        transcript.contains(&format!("payload=[{hostile}]")),
        "payload arrived verbatim as one data element"
    );
    assert!(
        transcript.contains("secret=[unset]"),
        "host variables never reach the child (AC8)"
    );
    assert!(
        transcript.contains(&format!("path=[{}]", bins.path.display())),
        "PATH is the allowlisted one"
    );
    assert!(
        !std::path::Path::new("/tmp/pwned37").exists(),
        "no injection happened"
    );
}

/// The jcode fake executable body whose stdout is its own `$0` on the
/// pinned prompt row (the absolute-$0 C1 witness, issue #8/#37).
#[test]
fn jcode_spawned_identity_is_the_resolved_absolute_path_witness() {
    let bins = FakeBins::new();
    let fake = bins.bin("jcode", &jcode_row_body("printf '%s' \"$0\"\nexit 0"));
    let profile = jcode_profile();
    let identity = bind_identity("ws-session-37", "tty-37-jcode", 1).expect("identity");
    let session = new_session("sess-jcode-c1-witness", identity).expect("session");
    let result = run_op_retry(
        &profile,
        &OpRequest {
            op: Op::Prompt,
            session: &session,
            payload: Some("synthetic payload"),
            timeout: ADAPTER_TIMEOUT,
        },
        &bins.env(),
    );
    assert_eq!(result.status, "succeeded");
    let transcript = result
        .payload
        .as_ref()
        .and_then(|payload| payload.get("transcript"))
        .and_then(Val::as_str)
        .expect("transcript");
    assert!(
        PathBuf::from(transcript).is_absolute(),
        "spawned identity must be absolute: {transcript}"
    );
    let canonical_fake = fs::canonicalize(&fake).expect("canonical fake");
    let spawned =
        fs::canonicalize(Path::new(transcript)).unwrap_or_else(|_| PathBuf::from(transcript));
    assert_eq!(
        spawned, canonical_fake,
        "the spawned $0 must equal the resolved absolute executable"
    );
}

/// Lane jcode harness work is confined to the assigned worktree: the
/// child's cwd must be the worktree path passed through
/// `execute_op_in_worktree`.
#[test]
fn jcode_prompt_runs_confined_to_the_assigned_worktree() {
    let bins = FakeBins::new();
    bins.bin("jcode", &jcode_row_body("pwd\nexit 0"));
    let profile = jcode_profile();
    let identity = bind_identity("ws-session-37", "tty-37-jcode", 1).expect("identity");
    let session = new_session("sess-jcode-confinement", identity).expect("session");
    let base = std::env::var_os("CARGO_TARGET_TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let worktree = base.join(format!("hf-adapters-jcode-wt-{}", std::process::id()));
    let _ = fs::remove_dir_all(&worktree);
    fs::create_dir_all(&worktree).expect("worktree dir");
    let expected_cwd = fs::canonicalize(&worktree).unwrap_or_else(|_| worktree.clone());

    let result = canter::adapters::execute_op_in_worktree(
        &profile,
        &OpRequest {
            op: Op::Prompt,
            session: &session,
            payload: Some("synthetic payload"),
            timeout: ADAPTER_TIMEOUT,
        },
        &bins.env(),
        &worktree,
    );
    let _ = fs::remove_dir_all(&worktree);
    assert_eq!(result.status, "succeeded");
    let transcript = result
        .payload
        .as_ref()
        .and_then(|payload| payload.get("transcript"))
        .and_then(Val::as_str)
        .expect("transcript");
    assert_eq!(
        PathBuf::from(transcript.trim()),
        expected_cwd,
        "jcode child must run inside the assigned worktree"
    );
}

// ---------------------------------------------------------------------------
// Issue #37 A2: herdr lifecycle reporting rows (jcode adapter under herdr)
//
// Same custom-integration contract as the pi rows above, with the jcode
// source/agent identity (`--source custom:herdr-fleet-jcode --agent
// jcode`). The fake `herdr` logs the exact argv to `$HF_FAKE_LOG`.
// ---------------------------------------------------------------------------

fn jcode_profile() -> Profile {
    official_profile(HarnessKind::Jcode)
}

fn jcode_env_with_log(bins: &FakeBins, log: &Path) -> BTreeMap<String, String> {
    let mut env = bins.env_herdr();
    env.insert(
        "HF_FAKE_LOG".to_string(),
        log.to_string_lossy().into_owned(),
    );
    env
}

#[test]
fn jcode_start_under_herdr_reports_working_with_the_documented_row() {
    let bins = FakeBins::new();
    let log = bins.path.join("herdr-argv.log");
    bins.bin("herdr", herdr_logger_body());
    let profile = jcode_profile();
    let env = jcode_env_with_log(&bins, &log);
    let result = run_op_retry(
        &profile,
        &OpRequest {
            op: Op::Start,
            session: session_ref(),
            payload: None,
            timeout: ADAPTER_TIMEOUT,
        },
        &env,
    );
    assert_eq!(result.status, "succeeded");
    assert_eq!(
        read_fake_log(&log),
        "pane report-agent w33:p1 --source custom:herdr-fleet-jcode --agent jcode --state working\n"
    );
}

#[test]
fn jcode_prompt_under_herdr_reports_idle_after_a_successful_one_shot() {
    let bins = FakeBins::new();
    let log = bins.path.join("herdr-argv.log");
    bins.bin("herdr", herdr_logger_body());
    bins.bin("jcode", &jcode_row_body("printf '%s' done\nexit 0"));
    let profile = jcode_profile();
    let env = jcode_env_with_log(&bins, &log);
    let result = run_op_retry(
        &profile,
        &prompt_request("implement the thing", ADAPTER_TIMEOUT),
        &env,
    );
    assert_eq!(result.status, "succeeded", "report must not change the op");
    assert_eq!(
        last_fake_log_line(&log),
        "pane report-agent w33:p1 --source custom:herdr-fleet-jcode --agent jcode --state idle"
    );
}

#[test]
fn jcode_prompt_credentials_under_herdr_reports_blocked_with_a_static_message() {
    let bins = FakeBins::new();
    let log = bins.path.join("herdr-argv.log");
    bins.bin("herdr", herdr_logger_body());
    bins.bin(
        "jcode",
        &jcode_row_body(
            "echo 'Error: DEEPSEEK_API_KEY not found in environment or ~/.config/jcode/deepseek.env' >&2\nexit 1",
        ),
    );
    let profile = jcode_profile();
    let env = jcode_env_with_log(&bins, &log);
    let result = run_op_retry(
        &profile,
        &prompt_request("do the thing", ADAPTER_TIMEOUT),
        &env,
    );
    assert_eq!(result.status, "refused");
    assert_eq!(result.code, Some(CODE_CREDENTIALS));
    assert_eq!(
        last_fake_log_line(&log),
        "pane report-agent w33:p1 --source custom:herdr-fleet-jcode --agent jcode --state blocked --message harness credentials required"
    );
}

#[test]
fn jcode_prompt_timeout_under_herdr_reports_idle_after_the_deadline_kill() {
    let bins = FakeBins::new();
    let log = bins.path.join("herdr-argv.log");
    bins.bin("herdr", herdr_logger_body());
    bins.bin("jcode", &harness_body(HarnessKind::Jcode, "hang", "0.84.0"));
    let profile = jcode_profile();
    let env = jcode_env_with_log(&bins, &log);
    let result = run_op_retry(
        &profile,
        &prompt_request("please hang", Duration::from_millis(200)),
        &env,
    );
    assert_eq!(result.status, "ambiguous");
    assert_eq!(result.code, Some(CODE_TIMEOUT));
    assert_eq!(
        last_fake_log_line(&log),
        "pane report-agent w33:p1 --source custom:herdr-fleet-jcode --agent jcode --state idle"
    );
}

#[test]
fn jcode_operations_outside_herdr_never_report_lifecycle() {
    let bins = FakeBins::new();
    let log = bins.path.join("herdr-argv.log");
    bins.bin("herdr", herdr_logger_body());
    bins.bin("jcode", &jcode_row_body("printf '%s' done\nexit 0"));
    let profile = jcode_profile();
    let mut env = bins.env(); // no herdr markers
    env.insert(
        "HF_FAKE_LOG".to_string(),
        log.to_string_lossy().into_owned(),
    );
    let start = run_op_retry(
        &profile,
        &OpRequest {
            op: Op::Start,
            session: session_ref(),
            payload: None,
            timeout: ADAPTER_TIMEOUT,
        },
        &env,
    );
    assert_eq!(start.status, "succeeded");
    let prompt = run_op_retry(&profile, &prompt_request("hello", ADAPTER_TIMEOUT), &env);
    assert_eq!(prompt.status, "succeeded");
    assert_eq!(
        read_fake_log(&log),
        "",
        "no lifecycle reports outside a herdr pane"
    );
}

#[test]
fn jcode_herdr_report_failure_never_changes_the_typed_op_result() {
    let bins = FakeBins::new();
    bins.bin("herdr", "exit 1\n");
    let profile = jcode_profile();
    let env = bins.env_herdr();
    let result = run_op_retry(
        &profile,
        &OpRequest {
            op: Op::Start,
            session: session_ref(),
            payload: None,
            timeout: ADAPTER_TIMEOUT,
        },
        &env,
    );
    assert_eq!(result.status, "succeeded");
    assert_eq!(result.code, None);
    let prompt = run_op_retry(&profile, &prompt_request("hello", ADAPTER_TIMEOUT), &env);
    assert_eq!(prompt.status, "refused");
    assert_eq!(prompt.code, Some(CODE_UNAVAILABLE));
}

// ---------------------------------------------------------------------------
// Issue #80: explicit provider/model binding (AC1/AC3). The fakes pin the
// exact argv, so the pair must come from the profile binding (a
// reintroduced literal fails these); an unbound profile refuses with the
// documented typed code without spawning anything, and reports `blocked`
// under herdr.
// ---------------------------------------------------------------------------

#[test]
fn prompt_rows_source_the_pair_from_the_declared_binding_not_a_literal() {
    // A second, different declared pair (the shared matrix fakes pin the
    // first): the row follows the binding, never a hardcoded literal.
    for kind in [HarnessKind::Pi, HarnessKind::Jcode] {
        let bins = FakeBins::new();
        let prompt_check = match kind {
            HarnessKind::Pi => {
                "[ \"$1\" = \"--provider\" ] && [ \"$2\" = \"alt-provider\" ] && [ \"$3\" = \"--model\" ] && [ \"$4\" = \"alt-model\" ] && [ \"$5\" = \"--print\" ] && [ \"$6\" = \"--\" ]"
            }
            HarnessKind::Jcode => {
                "[ \"$1\" = \"run\" ] && [ \"$2\" = \"--provider\" ] && [ \"$3\" = \"alt-provider\" ] && [ \"$4\" = \"--model\" ] && [ \"$5\" = \"alt-model\" ] && [ \"$6\" = \"--json\" ] && [ \"$7\" = \"--\" ]"
            }
            _ => unreachable!("binding test covers the official pair rows only"),
        };
        bins.bin(
            executable_name(kind),
            &format!(
                "if {prompt_check}; then printf '%s' bound_ok; exit 0; fi\necho \"unexpected argv: $*\" >&2\nexit 9\n"
            ),
        );
        let profile = Profile::official(kind, kind.name())
            .expect("profile")
            .with_binding("alt-provider", "alt-model")
            .expect("binding")
            .with_execution(ExecutionMode::Headless);
        let result = run_op_retry(
            &profile,
            &prompt_request("payload", ADAPTER_TIMEOUT),
            &bins.env(),
        );
        assert_eq!(
            result.status,
            "succeeded",
            "{}: code={:?} detail={:?}",
            kind.name(),
            result.code,
            result.detail
        );
        assert_eq!(
            result
                .payload
                .as_ref()
                .and_then(|payload| payload.get("transcript"))
                .and_then(Val::as_str),
            Some("bound_ok"),
            "{}",
            kind.name()
        );
    }
}

#[test]
fn unbound_prompt_is_a_typed_refusal_without_spawning_the_harness() {
    // AC3 (issue #80): with no declared binding the terminal prompt refuses
    // with the documented code and nothing is spawned — the fake dir holds
    // no harness executable, so a spawn attempt would classify as
    // `refusal.unavailable.harness` instead. No default, no substitution.
    for kind in [HarnessKind::Pi, HarnessKind::Jcode] {
        let bins = FakeBins::new();
        let profile = Profile::official(kind, kind.name())
            .expect("profile")
            .with_execution(ExecutionMode::Headless);
        let result = run_op_retry(
            &profile,
            &prompt_request("do the thing", ADAPTER_TIMEOUT),
            &bins.env(),
        );
        assert_eq!(result.status, "refused", "{}", kind.name());
        assert_eq!(result.code, Some(CODE_BINDING), "{}", kind.name());
        assert!(
            result
                .message
                .as_deref()
                .unwrap_or_default()
                .contains("binding"),
            "{}: message names the missing binding: {:?}",
            kind.name(),
            result.message
        );
    }
}

#[test]
fn unbound_prompt_under_herdr_reports_blocked_with_a_static_message() {
    // The typed binding refusal maps to the documented `blocked` lifecycle
    // report (declaring the provider/model pair is a user decision). No pi
    // executable exists, so a spawn attempt would be `refusal.unavailable`;
    // the report row must still fire with the static message.
    let bins = FakeBins::new();
    let log = bins.path.join("herdr-argv.log");
    bins.bin("herdr", herdr_logger_body());
    let profile = Profile::official(HarnessKind::Pi, "pi")
        .expect("profile")
        .with_execution(ExecutionMode::Headless);
    let mut env = bins.env_herdr();
    env.insert(
        "HF_FAKE_LOG".to_string(),
        log.to_string_lossy().into_owned(),
    );
    let result = run_op_retry(
        &profile,
        &prompt_request("do the thing", ADAPTER_TIMEOUT),
        &env,
    );
    assert_eq!(result.status, "refused");
    assert_eq!(result.code, Some(CODE_BINDING));
    assert_eq!(
        last_fake_log_line(&log),
        "pane report-agent w33:p1 --source custom:herdr-fleet-pi --agent pi --state blocked --message harness provider/model binding required"
    );
}
