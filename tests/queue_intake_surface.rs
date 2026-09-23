//! Issue #258 acceptance tests: the issue surface of a REAL repository is
//! larger than one pipe buffer, and reading it must not deadlock the child.
//!
//! The first live use of `canter queue intake` refused on a non-empty issue
//! surface while the same `gh api` invocation succeeded standalone: the
//! bounded runner waited for the child to exit before draining its pipes, so
//! any payload larger than the pipe buffer blocked the child, expired the
//! deadline, and killed a complete result — then reported it as
//! `refusal.intake.issues` with the captured payload as the "cause".
//!
//! These tests drive the SHIPPED entry point with a fake `gh` whose issue
//! surface is ~200 KB (three orders of magnitude past the 64 KB pipe buffer),
//! a local bare origin carrying `staging`, and a real recorded state store.
//!
//! Evidence rules: raw process exits are asserted directly; the refusal leg
//! asserts the named cause (status, program and argv, first stderr line) and
//! that the captured payload is NOT what the operator is shown; every leg
//! hashes the recorded store to prove `--dry-run` mutates nothing.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use canter::canonical::sha256_hex;
use canter::state::{Retention, State};
use canter::value::Val;

const HARNESS: &str = "lane-1";

/// Bytes of issue `body` in the synthetic surface: far past the pipe buffer a
/// bounded runner must keep drained (macOS/iOS default 64 KB).
const BODY_BYTES: usize = 200_000;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_canter")
}

/// The fake issue surface: `$HOME/surface.json` is the payload (so the
/// fixture can add a labelled issue between runs), and `$HOME/surface.fail`
/// makes the surface genuinely unreadable with a first stderr line.
const FAKE_GH: &str = r#"#!/bin/sh
case "$1" in
  --version) echo "gh version 9.9.9 (fake)"; exit 0 ;;
  auth)
    printf 'github.com\n  - Token scopes: '\''repo'\''\n'
    exit 0 ;;
  api)
    if [ -f "$HOME/surface.fail" ]; then
      printf '%s\n' 'gh: API rate limit exceeded for user ID 1' >&2
      exit 4
    fi
    cat "$HOME/surface.json"
    exit 0 ;;
esac
exit 1
"#;

struct Fixture {
    dir: PathBuf,
    state_dir: PathBuf,
    config_path: PathBuf,
    checkout: PathBuf,
}

impl Fixture {
    fn new(name: &str) -> Fixture {
        let dir = std::env::temp_dir().join(format!("hf-intake-s{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("fixture dir");
        let fixture = Fixture {
            state_dir: dir.join("state"),
            config_path: dir.join("config.toml"),
            checkout: dir.join("checkout"),
            dir,
        };
        fixture.write_fakebin();
        fixture.write_remote();
        fixture.write_config();
        fixture
    }

    fn write_fakebin(&self) {
        let fake_dir = self.dir.join("fakebin");
        std::fs::create_dir_all(&fake_dir).expect("fakebin");
        let path = fake_dir.join("gh");
        std::fs::write(&path, FAKE_GH).expect("fake gh");
        let mut permissions = std::fs::metadata(&path).expect("stat").permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut permissions, 0o755);
        std::fs::set_permissions(&path, permissions).expect("chmod");
    }

    fn write_remote(&self) {
        let origin = self.dir.join("origin.git");
        git(
            self.dir.as_path(),
            &["init", "-q", "--bare", origin.to_str().expect("utf8")],
        );
        std::fs::create_dir_all(&self.checkout).expect("checkout");
        git(&self.checkout, &["init", "-q"]);
        git(
            &self.checkout,
            &["config", "user.email", "test@example.invalid"],
        );
        git(&self.checkout, &["config", "user.name", "test"]);
        git(&self.checkout, &["checkout", "-q", "-b", "staging"]);
        git(
            &self.checkout,
            &["commit", "-q", "--allow-empty", "-m", "init"],
        );
        git(
            &self.checkout,
            &["remote", "add", "origin", origin.to_str().expect("utf8")],
        );
        git(&self.checkout, &["push", "-q", "origin", "staging"]);
    }

    fn write_config(&self) {
        std::fs::write(
            &self.config_path,
            format!(
                "schema = \"hf-config/v1\"\n\
                 \n\
                 [daemon]\n\
                 enabled = true\n\
                 socket = \"{socket}\"\n\
                 \n\
                 [repository.widgets]\n\
                 origin = \"https://example.invalid/example-org/widgets\"\n\
                 \n\
                 [harness.{HARNESS}]\n\
                 kind = \"pi\"\n\
                 executable = \"herdr\"\n\
                 env_allow = []\n\
                 provider = \"provider-a\"\n\
                 model = \"model-a\"\n\
                 binding_introspection = false\n",
                socket = self.dir.join("daemon.sock").display()
            ),
        )
        .expect("write config");
    }

    /// The issue surface the fake `gh` serves: `labelled` are the extra open
    /// ready-labelled issues; one open ready issue always carries a
    /// [`BODY_BYTES`] body, and a closed issue, an unlabelled issue and a
    /// pull request are always present and never selectable (AC3).
    fn write_surface(&self, labelled: &[u64]) {
        self.write_surface_labelled("canter:ready", labelled)
    }

    /// The same surface under a repository's OWN ready label — the intake
    /// contract's `--label` override (only `label` marks work ready).
    fn write_surface_labelled(&self, label: &str, labelled: &[u64]) {
        let body = "x".repeat(BODY_BYTES);
        let mut entries: Vec<String> = vec![format!(
            "{{\"number\":7,\"state\":\"open\",\"labels\":[{{\"name\":\"{label}\"}}],\
             \"body\":\"{body}\"}}"
        )];
        entries.push(format!(
            "{{\"number\":3,\"state\":\"open\",\"labels\":[{{\"name\":\"{label}\"}}]}}"
        ));
        for number in labelled {
            entries.push(format!(
                "{{\"number\":{number},\"state\":\"open\",\"labels\":[{{\"name\":\"{label}\"}}]}}"
            ));
        }
        entries.push(format!(
            "{{\"number\":5,\"state\":\"closed\",\"labels\":[{{\"name\":\"{label}\"}}]}}"
        ));
        entries.push(
            "{\"number\":9,\"state\":\"open\",\"labels\":[{\"name\":\"other\"}]}".to_string(),
        );
        entries.push(format!(
            "{{\"number\":11,\"state\":\"open\",\"labels\":[{{\"name\":\"{label}\"}}],\
             \"pull_request\":{{\"url\":\"https://example.invalid/pull/11\"}}}}"
        ));
        std::fs::write(
            self.dir.join("surface.json"),
            format!("[{}]", entries.join(",")),
        )
        .expect("write surface");
    }

    fn db(&self) -> PathBuf {
        self.state_dir.join("canter").join("state.db")
    }

    /// Create the recorded state store the way the daemon would (real
    /// migrations). Returns the store path.
    fn seed(&self) -> PathBuf {
        std::fs::create_dir_all(self.state_dir.join("canter")).expect("state dir");
        let _store = State::open(&self.db(), Retention::default()).expect("open state");
        self.db()
    }

    /// Run the CLI with the controlled environment: fake `gh` first on PATH,
    /// the fixture HOME/XDG_STATE_HOME, and the checkout as the working
    /// directory (so `git ls-remote origin` reads THIS repository's remote).
    fn cli(&self, args: &[String]) -> Output {
        let host_path = std::env::var("PATH").unwrap_or_default();
        let path = format!("{}:{host_path}", self.dir.join("fakebin").display());
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        Command::new(bin())
            .args(&refs)
            .current_dir(&self.checkout)
            .env_clear()
            .env("PATH", path)
            .env("HOME", &self.dir)
            .env("XDG_STATE_HOME", &self.state_dir)
            .env("LANG", "C")
            .output()
            .expect("run cli")
    }
}

fn git(dir: &Path, args: &[&str]) {
    let status = Command::new("git")
        .args(args)
        .current_dir(dir)
        .env_clear()
        .env("GIT_TEMPLATE_DIR", "")
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("GIT_AUTHOR_NAME", "test")
        .env("GIT_AUTHOR_EMAIL", "test@example.invalid")
        .env("GIT_COMMITTER_NAME", "test")
        .env("GIT_COMMITTER_EMAIL", "test@example.invalid")
        .status()
        .expect("spawn git");
    assert!(status.success(), "git {args:?} failed");
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn envelope(out: &Output) -> Val {
    let text = stdout(out);
    Val::parse_json(text.trim()).unwrap_or_else(|err| panic!("envelope: {err}\n{text}"))
}

fn data_field(out: &Output, field: &str) -> Val {
    envelope(out)
        .get("data")
        .and_then(|data| data.get(field))
        .cloned()
        .unwrap_or_else(|| panic!("data.{field} missing in {}", stdout(out)))
}

fn error_message(out: &Output) -> String {
    envelope(out)
        .get("error")
        .and_then(|error| error.get("message"))
        .and_then(Val::as_str)
        .unwrap_or_else(|| panic!("error.message missing in {}", stdout(out)))
        .to_string()
}

fn hash_of(path: &Path) -> String {
    sha256_hex(&std::fs::read(path).expect("read store"))
}

fn intake_args(fixture: &Fixture, extra: &[&str]) -> Vec<String> {
    let mut args: Vec<String> = vec![
        "queue".to_string(),
        "intake".to_string(),
        "--repository".to_string(),
        "widgets".to_string(),
        "--harness".to_string(),
        HARNESS.to_string(),
        "--host".to_string(),
        "mac".to_string(),
        "--caps".to_string(),
        "8/4/4".to_string(),
        "--config".to_string(),
        fixture.config_path.display().to_string(),
        "--socket".to_string(),
        fixture.dir.join("daemon.sock").display().to_string(),
        "--json".to_string(),
    ];
    for value in extra {
        args.push((*value).to_string());
    }
    args
}

fn numbers_of(run: &Output) -> Vec<i64> {
    let items = data_field(run, "items");
    let Some(Val::Arr(items)) = Some(items) else {
        panic!("items must be an array");
    };
    items
        .iter()
        .map(|item| item.get("number").and_then(Val::as_int).unwrap_or(-1))
        .collect()
}

fn digest_of(run: &Output) -> String {
    data_field(run, "digest")
        .as_str()
        .unwrap_or_else(|| panic!("digest must be a string: {}", stdout(run)))
        .to_string()
}

fn label_of(run: &Output) -> String {
    data_field(run, "label")
        .as_str()
        .unwrap_or_else(|| panic!("label must be a string: {}", stdout(run)))
        .to_string()
}

/// AC1 + AC3: a surface larger than one pipe buffer is read in full, the
/// open ready-labelled issues are selected in ascending order and printed,
/// the digest is stable over unchanged facts and changes exactly when a
/// label is added, and the dry run mutates nothing.
#[test]
fn a_surface_larger_than_one_pipe_buffer_is_selected_and_printed() {
    let fixture = Fixture::new("big");
    let db = fixture.seed();
    fixture.write_surface(&[]);
    let surface = std::fs::read(fixture.dir.join("surface.json")).expect("surface");
    assert!(
        surface.len() > 64 * 1024,
        "the fixture surface must exceed one pipe buffer, got {} bytes",
        surface.len()
    );
    let before = hash_of(&db);

    let first = fixture.cli(&intake_args(&fixture, &["--dry-run", "--max-items", "1"]));
    assert_eq!(
        first.status.code(),
        Some(0),
        "the issue surface is readable and must be read in full; stderr: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert_eq!(
        numbers_of(&first),
        vec![3, 7],
        "ascending issue number; the closed, unlabelled and pull-request \
         entries are never selectable (AC3): {}",
        stdout(&first)
    );
    let first_digest = digest_of(&first);
    assert_eq!(
        label_of(&first),
        "canter:ready",
        "the decision reports the ready label in force (the compiled-in default)"
    );

    // Unchanged facts: one unchanged decision, one unchanged digest.
    let again = fixture.cli(&intake_args(&fixture, &["--dry-run", "--max-items", "1"]));
    assert_eq!(again.status.code(), Some(0));
    assert_eq!(
        first_digest,
        digest_of(&again),
        "two invocations over unchanged facts must render one digest"
    );

    // Adding a label changes the selection and nothing else: the new issue
    // enters the ordered decision and the digest moves.
    fixture.write_surface(&[2]);
    let after_label = fixture.cli(&intake_args(&fixture, &["--dry-run", "--max-items", "1"]));
    assert_eq!(
        after_label.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&after_label.stderr)
    );
    assert_eq!(
        numbers_of(&after_label),
        vec![2, 3, 7],
        "one added label adds exactly one candidate, in order"
    );
    let labelled_digest = digest_of(&after_label);
    assert_ne!(
        first_digest, labelled_digest,
        "a changed selection must render a different digest"
    );
    assert_eq!(labelled_digest.len(), 64, "the digest is a sha256 hex");

    assert_eq!(
        before,
        hash_of(&db),
        "--dry-run must not write the recorded store (or its journal)"
    );
    assert!(
        !fixture.dir.join("request.json").exists(),
        "--dry-run must not write a document"
    );
}

/// AC2: a genuinely unreadable surface still refuses typed, and the refusal
/// names the cause — the exit status, the program and the argv as recorded,
/// and the first stderr line — never the captured payload. RAW exit and
/// refusal text are asserted, and nothing is written.
#[test]
fn an_unreadable_surface_refuses_typed_and_names_the_cause() {
    let fixture = Fixture::new("fail");
    let db = fixture.seed();
    fixture.write_surface(&[]);
    std::fs::write(fixture.dir.join("surface.fail"), "").expect("surface.fail");
    let before = hash_of(&db);

    let refused = fixture.cli(&intake_args(&fixture, &["--dry-run"]));
    assert_eq!(
        refused.status.code(),
        Some(4),
        "raw exit for a typed refusal; stdout: {}",
        stdout(&refused)
    );
    let envelope = envelope(&refused);
    let code = envelope
        .get("error")
        .and_then(|error| error.get("code"))
        .and_then(Val::as_str)
        .unwrap_or("");
    assert_eq!(code, "refusal.intake.issues", "{}", stdout(&refused));
    let message = error_message(&refused);
    assert!(
        message.contains("exited with code 4"),
        "the refusal names the status: {message}"
    );
    assert!(
        message.contains(
            "gh api repos/example-org/widgets/issues?state=open&labels=canter:ready&per_page=100"
        ),
        "the refusal names the program and the argv as recorded: {message}"
    );
    assert!(
        message.contains("first stderr line: gh: API rate limit exceeded for user ID 1"),
        "the refusal names the first stderr line: {message}"
    );
    assert!(
        !message.contains("\"labels_url\""),
        "the refusal must not quote the captured payload: {message}"
    );
    assert_eq!(
        before,
        hash_of(&db),
        "a refusal must not write the recorded store"
    );
}

/// AC (the label contract, #258): the decision reports the ready label IN
/// FORCE, and only that label marks work ready — a repository whose own
/// convention differs from the compiled-in default selects nothing until
/// `--label` names its label, and the document then says which one decided.
#[test]
fn only_the_label_in_force_marks_work_ready_and_the_decision_reports_it() {
    let fixture = Fixture::new("label");
    fixture.seed();
    // Nothing carries the compiled-in default: the default invocation reads
    // an empty ready set (it never invents work).
    fixture.write_surface_labelled("ready-to-work", &[]);
    let by_default = fixture.cli(&intake_args(&fixture, &["--dry-run"]));
    assert_eq!(by_default.status.code(), Some(0), "{}", stdout(&by_default));
    assert_eq!(
        numbers_of(&by_default),
        Vec::<i64>::new(),
        "an unlabelled (for this label) surface selects nothing: {}",
        stdout(&by_default)
    );
    assert_eq!(label_of(&by_default), "canter:ready");

    // The repository's own label, presented: the same surface now decides.
    let presented = fixture.cli(&intake_args(
        &fixture,
        &["--dry-run", "--label", "ready-to-work", "--max-items", "1"],
    ));
    assert_eq!(presented.status.code(), Some(0), "{}", stdout(&presented));
    assert_eq!(numbers_of(&presented), vec![3, 7]);
    assert_eq!(
        label_of(&presented),
        "ready-to-work",
        "the decision reports the label it actually used"
    );
    let Some(Val::Str(digest)) = Some(data_field(&presented, "digest")) else {
        panic!("digest must be a string");
    };
    assert_eq!(digest.len(), 64);
}
