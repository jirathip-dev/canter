//! Read-only CLI behavior tests: fake adapters, synthetic git repositories,
//! deterministic plans, discrimination, and envelope conformance.
//!
//! These tests need no credentials and no network: `gh`/`herdr` are fake
//! executables placed on a controlled PATH, git reads run against synthetic
//! local repositories, and every JSON document is validated against the #3
//! family rules implemented in the library.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use canter::canonical::canonical_bytes;
use canter::formats::{is_hex40, is_hex64};
use canter::redact::redact;
use canter::schema::{Family, validate_doc};
use canter::value::{Val, object, string};
use sha2::{Digest, Sha256};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_canter")
}

/// A private scratch area for one test (unique per test name + process).
struct Sandbox {
    root: PathBuf,
}

impl Sandbox {
    fn new(name: &str) -> Sandbox {
        let root = std::env::temp_dir().join(format!(
            "hf-it-{name}-{}-{}",
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

const FAKE_GH: &str = r#"#!/bin/sh
case "$1" in
  --version) echo "gh version 9.9.9 (fake)"; exit 0 ;;
  auth)
    printf 'github.com\n  - Token scopes: '\''repo'\'', '\''read:org'\''\n'
    exit 0 ;;
  api)
    hfhex='01234567''89abcdef0123456789abcdef012345'
    path="$2"
    case "$path" in
      repos/example-org/widgets)
        printf '%s' '{"full_name":"example-org/widgets","default_branch":"staging","archived":false}'
        exit 0 ;;
      repos/example-org/widgets/issues/7)
        printf '%s' '{"title":"Add hostile ; rm -rf --no-preserve-root $HOME \u2603","body":"Acceptance: tests pass ghp_'$hfhex'\n\u2022 item"}'
        exit 0 ;;
      *)
        printf '%s' '{"message":"Not Found"}'
        exit 1 ;;
    esac ;;
esac
exit 1
"#;

const FAKE_HERDR: &str = r#"#!/bin/sh
if [ "$1" = "--version" ]; then
  echo "herdr 0.8.2"
  exit 0
fi
exit 1
"#;

/// Install the fake `gh`/`herdr` scripts and return a PATH with the fake dir
/// first and the real host PATH after (so `git` still resolves).
fn fakebin(sandbox: &Sandbox) -> String {
    let fake_dir = sandbox.path("fakebin");
    std::fs::create_dir_all(&fake_dir).expect("fakebin dir");
    std::fs::write(fake_dir.join("gh"), FAKE_GH).expect("fake gh");
    std::fs::write(fake_dir.join("herdr"), FAKE_HERDR).expect("fake herdr");
    sandbox.chmod_x("fakebin/gh");
    sandbox.chmod_x("fakebin/herdr");
    let host_path = std::env::var("PATH").unwrap_or_default();
    format!("{}:{}", fake_dir.display(), host_path)
}

/// Run the real binary with a controlled environment.
fn run_cli(
    _sandbox: &Sandbox,
    args: &[&str],
    path: &str,
    home: Option<&Path>,
    cwd: Option<&Path>,
) -> Output {
    let mut command = Command::new(bin());
    command
        .args(args)
        .env_clear()
        .env("PATH", path)
        .env("LANG", "C");
    if let Some(home) = home {
        command.env("HOME", home);
    }
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }
    command.output().expect("spawn canter")
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn parse_envelope(out: &Output) -> Val {
    let text = stdout(out);
    Val::parse_json(text.trim()).unwrap_or_else(|err| panic!("envelope parse: {err}\n{text}"))
}

fn assert_envelope_valid(command: &str, out: &Output) -> Val {
    let doc = parse_envelope(out);
    let verdict = validate_doc(Family::Output, &doc);
    assert!(
        verdict.is_accepted(),
        "envelope for {command}: {}",
        verdict.message()
    );
    let exit_code = match doc.get("exit_code") {
        Some(Val::Int(code)) => *code as i32,
        _ => -1,
    };
    assert_eq!(
        out.status.code(),
        Some(exit_code),
        "process exit code must match the envelope exit_code for {command}"
    );
    if let Some(data) = doc.get("data") {
        let _ = data;
    }
    doc
}

const VALID_CONFIG: &str = r#"schema = "hf-config/v1"
[repository.widgets]
origin = "https://github.com/example-org/widgets"
branch = "staging"
"#;

fn write_valid_config(sandbox: &Sandbox) -> PathBuf {
    sandbox.write("home/.config/canter/config.toml", VALID_CONFIG)
}

fn home_dir(sandbox: &Sandbox) -> PathBuf {
    sandbox.path("home")
}

/// Create a synthetic git repository for example-org/widgets with a `staging`
/// branch and an origin URL matching the config above.
fn make_widgets_repo(sandbox: &Sandbox) -> PathBuf {
    let repo = sandbox.path("widgets-checkout");
    let git = |args: &[&str]| {
        let status = Command::new("git")
            .args(args)
            .current_dir(&repo)
            .env_clear()
            // #226: copy nothing from the host's shared git templates.
            .env("GIT_TEMPLATE_DIR", "")
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("GIT_AUTHOR_NAME", "test")
            .env("GIT_AUTHOR_EMAIL", "test@example.invalid")
            .env("GIT_COMMITTER_NAME", "test")
            .env("GIT_COMMITTER_EMAIL", "test@example.invalid")
            .status()
            .expect("spawn git");
        assert!(status.success(), "git {args:?} failed");
    };
    std::fs::create_dir_all(&repo).expect("repo dir");
    git(&["init", "-q"]);
    git(&["config", "user.email", "test@example.invalid"]);
    git(&["config", "user.name", "test"]);
    git(&["checkout", "-q", "-b", "staging"]);
    git(&["commit", "-q", "--allow-empty", "-m", "init"]);
    git(&[
        "remote",
        "add",
        "origin",
        "https://github.com/example-org/widgets.git",
    ]);
    repo
}

fn sha256_prefix_hex(text: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(text.as_bytes());
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for byte in digest {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex[..40].to_string()
}

fn canonical_hash_of(title: &str, body: &str) -> String {
    let doc = object(vec![
        ("title", string(&redact(title))),
        ("body", string(&redact(body))),
    ]);
    sha256_prefix_hex(&String::from_utf8(canonical_bytes(&doc)).expect("ascii"))
}

// ---------------------------------------------------------------------------
// doctor
// ---------------------------------------------------------------------------

#[test]
fn doctor_all_ok_with_fake_herdr_and_gh() {
    let sandbox = Sandbox::new("doctor-ok");
    let home = home_dir(&sandbox);
    let config_path = write_valid_config(&sandbox);
    let path = fakebin(&sandbox);

    let out = run_cli(&sandbox, &["doctor", "--json"], &path, Some(&home), None);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr(&out));
    let doc = assert_envelope_valid("doctor", &out);
    assert_eq!(doc.get("kind").and_then(Val::as_str), Some("ok"));
    let data = doc.get("data").expect("data");
    let checks = data.get("checks").expect("checks");
    let Val::Arr(items) = checks else {
        panic!("checks array")
    };
    let names: Vec<&str> = items
        .iter()
        .filter_map(|check| check.get("name").and_then(Val::as_str))
        .collect();
    assert_eq!(names, vec!["git", "herdr", "gh"]);
    for check in items {
        let status = check.get("status").and_then(Val::as_str).unwrap_or("?");
        assert_eq!(status, "ok", "check {check:?} must be ok");
    }
    // herdr detail names the declared minimum and the config row shows ok.
    let herdr = items
        .iter()
        .find(|check| check.get("name").and_then(Val::as_str) == Some("herdr"))
        .expect("herdr row");
    let detail = herdr
        .get("detail")
        .and_then(Val::as_str)
        .expect("herdr detail");
    assert!(detail.contains("0.8.2"), "herdr detail: {detail}");
    assert!(detail.contains("0.8.2"));
    let config = data.get("config").expect("config row");
    assert_eq!(config.get("status").and_then(Val::as_str), Some("ok"));
    assert_eq!(
        config.get("path").and_then(Val::as_str),
        config_path.to_str(),
        "doctor config row must name the discovered config path"
    );
}

#[test]
fn doctor_accepts_current_herdr_090_while_retaining_the_measured_floor() {
    let sandbox = Sandbox::new("doctor-herdr-090");
    let home = home_dir(&sandbox);
    write_valid_config(&sandbox);
    let path = fakebin(&sandbox);
    sandbox.write(
        "fakebin/herdr",
        "#!/bin/sh\n[ \"$1\" = \"--version\" ] && echo 'herdr 0.9.0' && exit 0\nexit 1\n",
    );
    sandbox.chmod_x("fakebin/herdr");

    let out = run_cli(&sandbox, &["doctor", "--json"], &path, Some(&home), None);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr(&out));
    let doc = assert_envelope_valid("doctor", &out);
    let Val::Arr(checks) = doc
        .get("data")
        .and_then(|data| data.get("checks"))
        .expect("doctor checks")
    else {
        panic!("checks array")
    };
    let detail = checks
        .iter()
        .find(|check| check.get("name").and_then(Val::as_str) == Some("herdr"))
        .and_then(|check| check.get("detail"))
        .and_then(Val::as_str)
        .expect("herdr detail");
    assert!(detail.contains("herdr 0.9.0"), "{detail}");
    assert!(detail.contains("declared minimum 0.8.2"), "{detail}");
}

#[test]
fn doctor_reports_missing_prerequisites_as_partial() {
    let sandbox = Sandbox::new("doctor-missing");
    let home = home_dir(&sandbox);
    // An empty PATH dir: git, herdr, gh all unresolvable.
    let empty_bin = sandbox.path("emptybin");
    std::fs::create_dir_all(&empty_bin).expect("emptybin");

    let out = run_cli(
        &sandbox,
        &["doctor", "--json"],
        &empty_bin.display().to_string(),
        Some(&home),
        None,
    );
    assert_eq!(
        out.status.code(),
        Some(3),
        "missing prerequisites are partial"
    );
    let doc = assert_envelope_valid("doctor", &out);
    assert_eq!(doc.get("kind").and_then(Val::as_str), Some("partial"));
    let data = doc.get("data").expect("data");
    let checks = data.get("checks").expect("checks");
    let Val::Arr(items) = checks else {
        panic!("checks")
    };
    for check in items {
        let name = check.get("name").and_then(Val::as_str).unwrap_or("?");
        let status = check.get("status").and_then(Val::as_str).unwrap_or("?");
        assert_eq!(status, "missing", "{name} must be missing on an empty PATH");
    }
}

#[test]
fn doctor_degrades_on_mid_char_adapter_version_output() {
    // Regression (review r1-1): hostile adapter text whose byte 200 falls
    // mid-char (here: "herdr " + 67 x U+3042 = 207 bytes) must degrade into
    // a typed result with a valid hf-output/v1 envelope and a closed 0-5
    // exit code — never a String::truncate panic / exit 101.
    let sandbox = Sandbox::new("doctor-midchar");
    let home = home_dir(&sandbox);
    let fake_dir = sandbox.path("fakebin-midchar");
    std::fs::create_dir_all(&fake_dir).expect("fake dir");
    let mut script = b"#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then printf '%s' 'herdr ".to_vec();
    for _ in 0..67 {
        script.extend_from_slice(&[0xE3, 0x81, 0x82]); // U+3042, 3 bytes each
    }
    script.extend_from_slice(b"'\nexit 0\nfi\nexit 1\n");
    std::fs::write(fake_dir.join("herdr"), &script).expect("hostile herdr");
    sandbox.chmod_x("fakebin-midchar/herdr");
    let host_path = std::env::var("PATH").unwrap_or_default();
    let path = format!("{}:{}", fake_dir.display(), host_path);

    let out = run_cli(&sandbox, &["doctor", "--json"], &path, Some(&home), None);
    let code = out.status.code().expect("process exit code");
    assert!(
        (0..=5).contains(&code),
        "hostile adapter text must stay inside the closed 0-5 exit codes, got {code} (panic: {})",
        stderr(&out)
    );
    assert_eq!(
        code, 3,
        "unparsable herdr version degrades doctor to partial"
    );
    let doc = assert_envelope_valid("doctor", &out);
    assert_eq!(doc.get("kind").and_then(Val::as_str), Some("partial"));
    let data = doc.get("data").expect("data");
    let checks = data.get("checks").expect("checks");
    let Val::Arr(items) = checks else {
        panic!("checks array")
    };
    let herdr = items
        .iter()
        .find(|check| check.get("name").and_then(Val::as_str) == Some("herdr"))
        .expect("herdr row");
    assert_eq!(herdr.get("status").and_then(Val::as_str), Some("degraded"));
    let detail = herdr
        .get("detail")
        .and_then(Val::as_str)
        .expect("herdr detail");
    assert!(
        detail.contains("unparsable version output"),
        "degradation must name the cause: {detail}"
    );
}

#[test]
fn doctor_refuses_an_invalid_config_with_exit_5() {
    let sandbox = Sandbox::new("doctor-invalid-config");
    let home = home_dir(&sandbox);
    let path = fakebin(&sandbox);
    let config = sandbox.write(
        "home/.config/canter/config.toml",
        "schema = \"hf-config/v2\"\n",
    );
    let out = run_cli(&sandbox, &["doctor", "--json"], &path, Some(&home), None);
    assert_eq!(out.status.code(), Some(5), "stderr: {}", stderr(&out));
    let doc = assert_envelope_valid("doctor", &out);
    assert_eq!(doc.get("kind").and_then(Val::as_str), Some("error"));
    let error = doc.get("error").expect("error");
    assert_eq!(
        error.get("code").and_then(Val::as_str),
        Some("config.invalid")
    );
    assert_eq!(
        error
            .get("details")
            .and_then(|d| d.get("refusal"))
            .and_then(Val::as_str),
        Some("refuse-version")
    );
    let _ = config;
}

// ---------------------------------------------------------------------------
// status
// ---------------------------------------------------------------------------

#[test]
fn status_observes_a_synthetic_checkout_completely() {
    let sandbox = Sandbox::new("status-ok");
    let home = home_dir(&sandbox);
    let _config = write_valid_config(&sandbox);
    let repo = make_widgets_repo(&sandbox);
    let path = fakebin(&sandbox);

    let out = run_cli(
        &sandbox,
        &["status", "--json"],
        &path,
        Some(&home),
        Some(&repo),
    );
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr(&out));
    let doc = assert_envelope_valid("status", &out);
    assert_eq!(doc.get("kind").and_then(Val::as_str), Some("ok"));
    let data = doc.get("data").expect("data");
    assert_eq!(data.get("expected_repositories").and_then(as_int), Some(1));
    assert_eq!(
        data.get("observed_repositories").and_then(as_int),
        Some(1),
        "widgets observed completely (local checkout matches + gh api)"
    );
    assert_eq!(data.get("freshness").and_then(Val::as_str), Some("fresh"));

    let observations = data.get("observations").expect("observations");
    let Val::Arr(docs) = observations else {
        panic!("observations array")
    };
    assert_eq!(docs.len(), 2, "herdr + widgets observations");
    for observation in docs {
        let verdict = validate_doc(Family::Observation, observation);
        assert!(verdict.is_accepted(), "observation: {}", verdict.message());
    }
    // The widgets observation carries the exact local identity.
    let widgets = docs
        .iter()
        .find(|doc| {
            doc.get("subject")
                .and_then(|s| s.get("id"))
                .and_then(Val::as_str)
                == Some("example-org/widgets")
        })
        .expect("widgets observation");
    assert_eq!(
        widgets.get("completeness").and_then(Val::as_str),
        Some("complete")
    );
    let payload = widgets.get("payload").expect("payload");
    let git_payload = payload.get("git").expect("git payload");
    assert_eq!(
        git_payload.get("available"),
        Some(&Val::Bool(true)),
        "git available is a boolean"
    );
    assert_eq!(
        git_payload.get("origin_matches"),
        Some(&Val::Bool(true)),
        "synthetic origin must match the configured origin"
    );
    let head = git_payload.get("head").and_then(Val::as_str).expect("head");
    assert!(is_hex40(head), "head must be a 40-hex sha1: {head}");
    let github_payload = payload.get("github").expect("github payload");
    assert_eq!(
        github_payload.get("available"),
        Some(&Val::Bool(true)),
        "fake gh answered the repo probe"
    );
    // Timings evidence exists with measured values.
    let timings = data.get("timings_ms").expect("timings");
    assert!(timings.get("p50_ms").is_some() && timings.get("p95_ms").is_some());
    assert_eq!(timings.get("requests").and_then(as_int), Some(3));
    assert_eq!(timings.get("partial_failures").and_then(as_int), Some(0));
}

fn as_int(value: &Val) -> Option<i64> {
    match value {
        Val::Int(n) => Some(*n),
        _ => None,
    }
}

#[test]
fn status_without_gh_still_observes_the_local_checkout() {
    let sandbox = Sandbox::new("status-no-gh");
    let home = home_dir(&sandbox);
    let _config = write_valid_config(&sandbox);
    let repo = make_widgets_repo(&sandbox);
    // Fake herdr only: no gh anywhere on PATH.
    let fake_dir = sandbox.path("fakebin-herdr");
    std::fs::create_dir_all(&fake_dir).expect("fake dir");
    std::fs::write(fake_dir.join("herdr"), FAKE_HERDR).expect("fake herdr");
    sandbox.chmod_x("fakebin-herdr/herdr");
    let host_path = std::env::var("PATH").unwrap_or_default();
    let path = format!("{}:{}", fake_dir.display(), host_path);

    let out = run_cli(
        &sandbox,
        &["status", "--json"],
        &path,
        Some(&home),
        Some(&repo),
    );
    // widgets: local git matches → complete → a fully observed single-repo
    // status even though gh is entirely absent.
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr(&out));
    let doc = assert_envelope_valid("status", &out);
    assert_eq!(doc.get("kind").and_then(Val::as_str), Some("ok"));
    let data = doc.get("data").expect("data");
    assert_eq!(data.get("observed_repositories").and_then(as_int), Some(1));
    let observations = data.get("observations").expect("observations");
    let Val::Arr(docs) = observations else {
        panic!("array")
    };
    let widgets = docs
        .iter()
        .find(|doc| {
            doc.get("subject")
                .and_then(|s| s.get("id"))
                .and_then(Val::as_str)
                == Some("example-org/widgets")
        })
        .expect("widgets");
    assert_eq!(
        widgets.get("completeness").and_then(Val::as_str),
        Some("complete")
    );
    let github = widgets
        .get("payload")
        .and_then(|p| p.get("github"))
        .expect("github");
    assert_eq!(
        github.get("available"),
        Some(&Val::Bool(false)),
        "gh absence degrades explicitly"
    );
    // The degraded surface is reported, never hidden.
    assert_eq!(
        widgets.get("freshness").and_then(Val::as_str),
        Some("fresh")
    );
    assert_eq!(data.get("freshness").and_then(Val::as_str), Some("fresh"));
}

// ---------------------------------------------------------------------------
// plan
// ---------------------------------------------------------------------------

#[test]
fn plan_offline_with_revision_is_deterministic_and_validates() {
    let sandbox = Sandbox::new("plan-offline");
    let home = home_dir(&sandbox);
    let _config = write_valid_config(&sandbox);
    let path = fakebin(&sandbox);
    let revision = "0".repeat(40);

    let run_plan = || {
        run_cli(
            &sandbox,
            &["plan", "widgets", "7", "--revision", &revision, "--json"],
            &path,
            Some(&home),
            None,
        )
    };

    let first = run_plan();
    assert_eq!(first.status.code(), Some(0), "stderr: {}", stderr(&first));
    let second = run_plan();
    assert_eq!(
        stdout(&first),
        stdout(&second),
        "plan rendering is deterministic"
    );
    assert!(stderr(&first).is_empty());

    let doc = assert_envelope_valid("plan", &first);
    let data = doc.get("data").expect("data");
    let plan = data.get("plan").expect("plan doc");
    let verdict = validate_doc(Family::Plan, plan);
    assert!(verdict.is_accepted(), "plan doc: {}", verdict.message());
    let digest = data.get("digest").and_then(Val::as_str).expect("digest");
    assert!(is_hex64(digest));
    // The digest must equal sha256 over the canonical bytes of the plan.
    let recomputed = {
        let mut hasher = Sha256::new();
        hasher.update(canonical_bytes(plan));
        let bytes = hasher.finalize();
        let mut hex = String::with_capacity(64);
        for byte in bytes {
            hex.push_str(&format!("{byte:02x}"));
        }
        hex
    };
    assert_eq!(
        digest, recomputed,
        "digest is over the canonical plan bytes"
    );
    assert_eq!(plan.get("state_epoch").and_then(as_int), Some(0));
    assert_eq!(
        plan.get("repository").and_then(Val::as_str),
        Some("example-org/widgets")
    );
    let steps = plan.get("steps").expect("steps");
    let Val::Arr(items) = steps else {
        panic!("steps")
    };
    assert_eq!(items.len(), 8, "doctrine spine has eight steps");
}

#[test]
fn plan_binds_the_redacted_acceptance_revision_from_gh() {
    let sandbox = Sandbox::new("plan-gh");
    let home = home_dir(&sandbox);
    let _config = write_valid_config(&sandbox);
    let path = fakebin(&sandbox);

    let out = run_cli(
        &sandbox,
        &["plan", "widgets", "7", "--json"],
        &path,
        Some(&home),
        None,
    );
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr(&out));
    let doc = assert_envelope_valid("plan", &out);
    let data = doc.get("data").expect("data");
    assert_eq!(
        data.get("issue_source").and_then(Val::as_str),
        Some("github")
    );
    let plan = data.get("plan").expect("plan");
    let issue = plan.get("issue").expect("issue");
    let revision = issue
        .get("revision")
        .and_then(Val::as_str)
        .expect("revision");
    assert!(is_hex40(revision));

    // The fake issue carries hostile text and a secret-shaped token. The
    // revision must equal the hash over the REDACTED acceptance text, and
    // must differ from the hash over the raw text (proves redaction happens
    // before the canonical binding).
    let title = "Add hostile ; rm -rf --no-preserve-root $HOME \u{2603}";
    let body = concat!(
        "Acceptance: tests pass ",
        "ghp_",
        "0123456789abcdef0123456789abcdef012345\n\u{2022} item"
    );
    assert_eq!(revision, canonical_hash_of(title, body));
    assert_ne!(revision, canonical_hash_of_raw(title, body));
}

/// Hash over the raw (unredacted) acceptance text — must differ from the
/// redacted binding whenever the text contains secret shapes.
fn canonical_hash_of_raw(title: &str, body: &str) -> String {
    let doc = object(vec![("title", string(title)), ("body", string(body))]);
    sha256_prefix_hex(&String::from_utf8(canonical_bytes(&doc)).expect("ascii"))
}

#[test]
fn plan_degrades_explicitly_without_gh_and_without_revision() {
    let sandbox = Sandbox::new("plan-no-gh");
    let home = home_dir(&sandbox);
    let _config = write_valid_config(&sandbox);
    let empty_bin = sandbox.path("emptybin2");
    std::fs::create_dir_all(&empty_bin).expect("emptybin");

    let out = run_cli(
        &sandbox,
        &["plan", "widgets", "7", "--json"],
        &empty_bin.display().to_string(),
        Some(&home),
        None,
    );
    assert_eq!(out.status.code(), Some(1), "operational error expected");
    let doc = assert_envelope_valid("plan", &out);
    assert_eq!(doc.get("kind").and_then(Val::as_str), Some("error"));
    let error = doc.get("error").expect("error");
    assert_eq!(
        error.get("code").and_then(Val::as_str),
        Some("forge.unavailable")
    );
    let message = error.get("message").and_then(Val::as_str).unwrap_or("");
    assert!(
        message.contains("--revision"),
        "message must suggest offline mode: {message}"
    );
}

#[test]
fn plan_refuses_unconfigured_repositories_and_bad_argv() {
    let sandbox = Sandbox::new("plan-refusals");
    let home = home_dir(&sandbox);
    let _config = write_valid_config(&sandbox);
    let path = fakebin(&sandbox);

    let out = run_cli(
        &sandbox,
        &["plan", "not-configured", "1"],
        &path,
        Some(&home),
        None,
    );
    assert_eq!(
        out.status.code(),
        Some(2),
        "unconfigured repository is a usage error"
    );
    assert!(out.stdout.is_empty());
    assert!(stderr(&out).contains("no configured repository"));

    let out = run_cli(
        &sandbox,
        &["plan", "widgets", "abc"],
        &path,
        Some(&home),
        None,
    );
    assert_eq!(out.status.code(), Some(2));

    let out = run_cli(
        &sandbox,
        &["plan", "widgets", "7", "--revision", "not-hex"],
        &path,
        Some(&home),
        None,
    );
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn plan_requires_a_config_document() {
    let sandbox = Sandbox::new("plan-no-config");
    let home = home_dir(&sandbox);
    let path = fakebin(&sandbox);
    let out = run_cli(
        &sandbox,
        &["plan", "widgets", "1", "--json"],
        &path,
        Some(&home),
        None,
    );
    assert_eq!(out.status.code(), Some(5), "config error");
    let doc = assert_envelope_valid("plan", &out);
    let error = doc.get("error").expect("error");
    assert_eq!(
        error.get("code").and_then(Val::as_str),
        Some("config.not_found")
    );
}

// ---------------------------------------------------------------------------
// config
// ---------------------------------------------------------------------------

#[test]
fn config_lifecycle_validate_show_init() {
    let sandbox = Sandbox::new("config-lifecycle");
    let home = home_dir(&sandbox);
    let path = fakebin(&sandbox);
    let config_path = write_valid_config(&sandbox);

    // validate: ok with path, no overlay.
    let out = run_cli(
        &sandbox,
        &["config", "validate", "--json"],
        &path,
        Some(&home),
        None,
    );
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr(&out));
    let doc = assert_envelope_valid("config validate", &out);
    let data = doc.get("data").expect("data");
    assert_eq!(
        data.get("valid"),
        Some(&Val::Bool(true)),
        "valid is a JSON boolean"
    );
    assert_eq!(
        data.get("config_path").and_then(Val::as_str),
        config_path.to_str()
    );

    // show: repositories rendered with identities derived from origins.
    let out = run_cli(
        &sandbox,
        &["config", "show", "--json"],
        &path,
        Some(&home),
        None,
    );
    assert_eq!(out.status.code(), Some(0));
    let doc = assert_envelope_valid("config show", &out);
    let data = doc.get("data").expect("data");
    let repos = data.get("repositories").expect("repositories");
    let Val::Arr(items) = repos else {
        panic!("repos")
    };
    assert_eq!(items.len(), 1);
    let widgets = items
        .iter()
        .find(|repo| repo.get("identity").and_then(Val::as_str) == Some("example-org/widgets"))
        .expect("widgets repo row");
    assert_eq!(
        widgets.get("enabled"),
        Some(&Val::Bool(true)),
        "enabled is a JSON boolean"
    );
    assert_eq!(widgets.get("branch").and_then(Val::as_str), Some("staging"));

    // init: template is itself a valid config document.
    let out = run_cli(&sandbox, &["config", "init"], &path, Some(&home), None);
    assert_eq!(out.status.code(), Some(0));
    let template = stdout(&out);
    assert!(
        template.contains("hf-config/v1"),
        "template names the schema"
    );
    let verdict = validate_doc(
        Family::Config,
        &Val::parse_toml(&template).expect("template toml"),
    );
    assert!(
        verdict.is_accepted(),
        "init template validates: {}",
        verdict.message()
    );
}

#[test]
fn config_validate_refuses_malformed_and_unknown_versions() {
    let sandbox = Sandbox::new("config-refusals");
    let home = home_dir(&sandbox);
    let path = fakebin(&sandbox);
    let bad = sandbox.write(
        "home/.config/canter/config.toml",
        "schema = \"hf-config/v1\"\n[schedules]\ndaily = \"09:00\"\n",
    );
    let out = run_cli(
        &sandbox,
        &["config", "validate", "--json"],
        &path,
        Some(&home),
        None,
    );
    assert_eq!(out.status.code(), Some(5));
    let doc = assert_envelope_valid("config validate", &out);
    let error = doc.get("error").expect("error");
    assert_eq!(
        error.get("code").and_then(Val::as_str),
        Some("config.invalid")
    );
    assert_eq!(
        error
            .get("details")
            .and_then(|d| d.get("refusal"))
            .and_then(Val::as_str),
        Some("refuse-malformed"),
        "unknown top-level table must refuse as malformed"
    );
    let _ = bad;

    let unknown = sandbox.write(
        "home/.config/canter/config.toml",
        "schema = \"hf-config/v2\"\n",
    );
    let out = run_cli(
        &sandbox,
        &["config", "validate", "--json"],
        &path,
        Some(&home),
        None,
    );
    assert_eq!(out.status.code(), Some(5));
    let doc = parse_envelope(&out);
    let error = doc.get("error").expect("error");
    assert_eq!(
        error
            .get("details")
            .and_then(|d| d.get("refusal"))
            .and_then(Val::as_str),
        Some("refuse-version"),
        "unknown version must refuse as refuse-version"
    );
    let _ = unknown;
}

// ---------------------------------------------------------------------------
// untrusted input / framing
// ---------------------------------------------------------------------------

#[test]
fn output_framing_survives_hostile_config_paths_and_issue_text() {
    let sandbox = Sandbox::new("framing");
    let home = home_dir(&sandbox);
    let path = fakebin(&sandbox);
    // Hostile names must never break argv handling or JSON framing.
    let hostile = "weird;name 'quote\"back\\slash $(touch /tmp/pwned)";
    let config = sandbox.write(&format!("home/.config/canter/{hostile}"), VALID_CONFIG);

    let out = run_cli(
        &sandbox,
        &[
            "config",
            "validate",
            "--config",
            config.to_str().expect("utf8"),
            "--json",
        ],
        &path,
        Some(&home),
        None,
    );
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr(&out));
    let doc = parse_envelope(&out);
    assert_eq!(doc.get("kind").and_then(Val::as_str), Some("ok"));
    assert!(
        !std::path::Path::new("/tmp/pwned").exists(),
        "hostile text must never reach a shell"
    );

    // Plan through the fake gh with hostile issue text: JSON framing escapes,
    // argv untouched, stdout is exactly one envelope.
    let out = run_cli(
        &sandbox,
        &[
            "plan",
            "widgets",
            "7",
            "--config",
            config.to_str().expect("utf8"),
            "--json",
        ],
        &path,
        Some(&home),
        None,
    );
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr(&out));
    let text = stdout(&out);
    let doc = Val::parse_json(text.trim()).expect("single envelope on stdout");
    assert_eq!(
        doc.get("schema").and_then(Val::as_str),
        Some("hf-output/v1")
    );
    // canonical JSON output is ASCII-only (escape proofing)
    assert!(text.is_ascii(), "JSON output must be ASCII-escaped");
}

// ---------------------------------------------------------------------------
// capabilities
// ---------------------------------------------------------------------------

#[test]
fn capabilities_declare_the_read_only_forge_set() {
    let sandbox = Sandbox::new("capabilities");
    let home = home_dir(&sandbox);
    let path = fakebin(&sandbox);
    let out = run_cli(
        &sandbox,
        &["capabilities", "--json"],
        &path,
        Some(&home),
        None,
    );
    assert_eq!(out.status.code(), Some(0));
    let doc = assert_envelope_valid("capabilities", &out);
    let capability = doc
        .get("data")
        .and_then(|d| d.get("capability"))
        .expect("capability");
    let verdict = validate_doc(Family::Capability, capability);
    assert!(verdict.is_accepted(), "{}", verdict.message());
    assert_eq!(capability.get("axis").and_then(Val::as_str), Some("forge"));
    assert_eq!(
        capability.get("actor").and_then(Val::as_str),
        Some("canter")
    );
}
