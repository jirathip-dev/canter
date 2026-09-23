//! Issue #245 acceptance tests: `canter queue intake` at the SHIPPED entry
//! point, with a controlled environment — a fake `gh` on PATH (the
//! repository's own issue surface), a local bare origin carrying `staging`
//! (the remote's own integration head), and a real recorded state store.
//!
//! The commit leg (`--out`, no `--dry-run`) is exercised end to end against a
//! REAL daemon child: the document is rendered, one grant is minted per
//! selected item through the same surface the operator path uses, and the
//! daemon commits one admitted run per selected item (AC1).
//!
//! Evidence rules: raw process exits are asserted directly, the JSON envelope
//! is parsed as documented, and the mutation-free claim of `--dry-run` is
//! proven by hashing the state store before and after the run (the journal
//! lives in that store, so an unchanged store is an unchanged journal).

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use canter::canonical::sha256_hex;
use canter::client::Connection;
use canter::state::{Retention, State};
use canter::value::Val;

const HARNESS: &str = "lane-1";

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_canter")
}

/// The fake issue surface: two ready open issues, one closed ready issue, one
/// open unlabelled issue and one pull request (the issues surface carries
/// both, and intake must never select a pull request).
const FAKE_GH: &str = r#"#!/bin/sh
case "$1" in
  --version) echo "gh version 9.9.9 (fake)"; exit 0 ;;
  auth)
    printf 'github.com\n  - Token scopes: '"'"'repo'"'"'\n'
    exit 0 ;;
  api)
    printf '%s' '[
      {"number":7,"state":"open","labels":[{"name":"canter:ready"}]},
      {"number":3,"state":"open","labels":[{"name":"canter:ready"}]},
      {"number":5,"state":"closed","labels":[{"name":"canter:ready"}]},
      {"number":9,"state":"open","labels":[{"name":"other"}]},
      {"number":11,"state":"open","labels":[{"name":"canter:ready"}],"pull_request":{"url":"https://example.invalid/pull/11"}}
    ]'
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

/// The real daemon child, killed and reaped on drop: a failing assertion can
/// never leak a fixture daemon into the driver's survivor sweep.
struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl Fixture {
    fn new(name: &str, publish_staging: bool) -> Fixture {
        let dir = std::env::temp_dir().join(format!("hf-intake-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("fixture dir");
        let fixture = Fixture {
            state_dir: dir.join("state"),
            config_path: dir.join("config.toml"),
            checkout: dir.join("checkout"),
            dir,
        };
        fixture.write_fakebin();
        fixture.write_remote(publish_staging);
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

    /// A local bare origin plus a checkout whose `origin` is that bare repo
    /// (the real `git ls-remote` read the revision rule depends on).
    fn write_remote(&self, publish_staging: bool) {
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
        if publish_staging {
            git(&self.checkout, &["push", "-q", "origin", "staging"]);
        }
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

    fn db(&self) -> PathBuf {
        self.state_dir.join("canter").join("state.db")
    }

    fn socket(&self) -> PathBuf {
        self.dir.join("daemon.sock")
    }

    /// Create the recorded state store the way the daemon would (real
    /// migrations). Returns the store path.
    fn seed(&self) -> PathBuf {
        std::fs::create_dir_all(self.state_dir.join("canter")).expect("state dir");
        let _store = State::open(&self.db(), Retention::default()).expect("open state");
        self.db()
    }

    /// Spawn the real daemon child over the fixture socket and state home
    /// (the `daemon_rpc`/`queue_cli` pattern), under the same controlled
    /// environment the CLI sees.
    fn spawn(&self) -> Daemon {
        std::fs::create_dir_all(&self.state_dir).expect("state home");
        let host_path = std::env::var("PATH").unwrap_or_default();
        let path = format!("{}:{host_path}", self.dir.join("fakebin").display());
        let mut command = Command::new(bin());
        command
            .args(["daemon", "run", "--socket"])
            .arg(self.socket())
            .current_dir(&self.checkout)
            .env_clear()
            .env("PATH", path)
            .env("HOME", &self.dir)
            .env("XDG_STATE_HOME", &self.state_dir)
            .env("LANG", "C")
            .stdout(Stdio::null())
            .stderr(Stdio::from(
                std::fs::File::create(self.dir.join("daemon.stderr.log")).expect("stderr log"),
            ));
        Daemon(command.spawn().expect("spawn daemon"))
    }

    /// Wait (bounded) until the daemon answers `status` on the socket.
    fn wait_ready(&self) {
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            if canter::lock::socket_presence(&self.socket()) == canter::lock::SocketPresence::Active
            {
                let ok = Connection::open(&self.socket())
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
        let stderr =
            std::fs::read_to_string(self.dir.join("daemon.stderr.log")).unwrap_or_default();
        panic!(
            "daemon did not become ready on {}; stderr:\n{stderr}",
            self.socket().display()
        );
    }

    /// Terminate the daemon child and wait (bounded) for it to exit, so the
    /// store can be reopened. The [`Daemon`] guard repeats this on drop.
    fn shutdown(&self, mut daemon: Daemon) {
        let _ = daemon.0.kill();
        let deadline = Instant::now() + Duration::from_secs(10);
        while daemon.0.try_wait().expect("try_wait").is_none() {
            assert!(Instant::now() < deadline, "daemon did not exit");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Run the CLI with the controlled environment: fake `gh` first on PATH,
    /// the fixture HOME/XDG_STATE_HOME, and the checkout as the working
    /// directory (so `git ls-remote origin` reads THIS repository's remote).
    fn cli(&self, args: &[&str]) -> Output {
        let host_path = std::env::var("PATH").unwrap_or_default();
        let path = format!("{}:{host_path}", self.dir.join("fakebin").display());
        Command::new(bin())
            .args(args)
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

fn hash_of(path: &Path) -> String {
    let bytes = std::fs::read(path).expect("read store");
    sha256_hex(&bytes)
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

fn run(fixture: &Fixture, args: &[String]) -> Output {
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    fixture.cli(&refs)
}

/// AC3 + AC6 + AC7: the dry run is mutation-free and two invocations over
/// unchanged state render ONE digest, over the repository's own issue state.
#[test]
fn dry_run_is_mutation_free_and_deterministic_over_the_repository_issue_state() {
    let fixture = Fixture::new("dryrun", true);
    let db = fixture.seed();
    let before = hash_of(&db);
    let out_path = fixture.dir.join("request.json");

    let first = run(
        &fixture,
        &intake_args(&fixture, &["--dry-run", "--max-items", "1"]),
    );
    assert_eq!(
        first.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    let first_digest = data_field(&first, "digest");
    let second = run(
        &fixture,
        &intake_args(&fixture, &["--dry-run", "--max-items", "1"]),
    );
    assert_eq!(
        second.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&second.stderr)
    );
    let second_digest = data_field(&second, "digest");
    assert_eq!(
        first_digest, second_digest,
        "two invocations over unchanged facts must render one digest"
    );
    let Some(Val::Str(digest)) = Some(first_digest.clone()) else {
        panic!("digest must be a string: {first_digest:?}");
    };
    assert_eq!(digest.len(), 64, "digest is a sha256 hex");

    // The decision itself: ascending order, the closed issue and the pull
    // request absent, the over-bound item waiting rather than selected.
    let items = data_field(&first, "items");
    let Some(Val::Arr(items)) = Some(items) else {
        panic!("items must be an array");
    };
    let numbers: Vec<i64> = items
        .iter()
        .map(|item| item.get("number").and_then(Val::as_int).unwrap_or(-1))
        .collect();
    assert_eq!(
        numbers,
        vec![3, 7],
        "ascending issue number, closed/unlabelled/PR excluded"
    );
    let statuses: Vec<String> = items
        .iter()
        .map(|item| {
            item.get("status")
                .and_then(Val::as_str)
                .unwrap_or("")
                .to_string()
        })
        .collect();
    assert_eq!(
        statuses,
        vec!["selected", "waiting"],
        "the item beyond the declared bound waits with the typed reason"
    );

    // Mutation-free: the recorded store (and therefore the journal inside it)
    // is byte-identical, and no document was written.
    assert_eq!(
        before,
        hash_of(&db),
        "--dry-run must not write the state store"
    );
    assert!(!out_path.exists(), "--dry-run must not write a document");
}

/// AC (required behaviour 2) + AC4: the integration head is the default
/// revision rule, and an unresolvable revision refuses typed with nothing
/// submitted.
#[test]
fn the_integration_head_is_the_default_revision_and_an_unresolvable_one_refuses_typed() {
    let resolved = Fixture::new("resolved", true);
    resolved.seed();
    let ok = run(&resolved, &intake_args(&resolved, &["--dry-run"]));
    assert_eq!(
        ok.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&ok.stderr)
    );
    let selected = data_field(&ok, "selected");
    let Some(Val::Obj(_)) = Some(selected.clone()) else {
        panic!("selected must be an object: {selected:?}");
    };
    let selected_items = selected
        .get("selected")
        .and_then(Val::as_array)
        .cloned()
        .unwrap_or_default();
    let revisions: Vec<String> = selected_items
        .iter()
        .map(|item| {
            item.get("revision")
                .and_then(Val::as_str)
                .unwrap_or("")
                .to_string()
        })
        .collect();
    assert_eq!(
        revisions.len(),
        2,
        "both ready open issues are selected by default"
    );
    assert!(
        revisions.iter().all(|revision| revision.len() == 40),
        "every selected item binds a 40-hex revision: {revisions:?}"
    );

    // No published integration branch: the default rule cannot resolve, and
    // intake refuses typed instead of submitting a partial document.
    let unresolved = Fixture::new("unresolved", false);
    let db = unresolved.seed();
    let before = hash_of(&db);
    let out_path = unresolved.dir.join("request.json");
    let refused = run(&unresolved, &intake_args(&unresolved, &["--dry-run"]));
    assert_ne!(
        refused.status.code(),
        Some(0),
        "an unresolvable revision must refuse"
    );
    let envelope = envelope(&refused);
    let code = envelope
        .get("error")
        .and_then(|error| error.get("code"))
        .and_then(Val::as_str)
        .unwrap_or("");
    assert_eq!(
        code,
        "refusal.intake.revision",
        "typed refusal: {}",
        stdout(&refused)
    );
    assert_eq!(
        before,
        hash_of(&db),
        "a refusal must not write the state store"
    );
    assert!(!out_path.exists(), "a refusal must not write a document");
}

/// AC1 (the commit leg, end to end): one non-`--dry-run` invocation turns the
/// repository's own issue state into ONE bound-input submission over a REAL
/// daemon — the document is written to `--out`, one grant is minted per
/// selected item through the same surface the operator path uses, and the
/// daemon commits ONE admitted run per selected item.
#[test]
fn the_commit_leg_commits_one_run_per_admitted_item_over_a_live_daemon() {
    let fixture = Fixture::new("commit", true);
    fixture.seed();
    let daemon = fixture.spawn();
    fixture.wait_ready();

    let out_path = fixture.dir.join("request.json");
    let out_arg = out_path.display().to_string();
    let submitted = run(
        &fixture,
        &intake_args(
            &fixture,
            &[
                "--out",
                &out_arg,
                "--host-available",
                "yes",
                "--harness-lanes",
                "0",
            ],
        ),
    );
    assert_eq!(
        submitted.status.code(),
        Some(0),
        "intake commit exit; stderr: {}",
        String::from_utf8_lossy(&submitted.stderr)
    );
    let envelope = envelope(&submitted);
    let data = envelope.get("data").cloned().expect("data");
    // The committed submission document, not a dry-run render.
    assert_eq!(
        data.get("schema").and_then(Val::as_str),
        Some("hf-queue-submission/v1"),
        "the commit leg answers with the committed submission: {}",
        stdout(&submitted)
    );
    assert_eq!(
        data.get("intake")
            .and_then(|intake| intake.get("schema"))
            .and_then(Val::as_str),
        Some("hf-intake/v1"),
        "the decision rides with the submission: {}",
        stdout(&submitted)
    );
    assert_eq!(
        data.get("out").and_then(Val::as_str),
        Some(out_arg.as_str()),
        "the submission names the written document"
    );
    let admission = data.get("admission").cloned().expect("admission");
    assert_eq!(
        admission.get("admitted").and_then(Val::as_int),
        Some(2),
        "both ready issues are admitted: {}",
        stdout(&submitted)
    );
    assert_eq!(
        admission.get("refused").and_then(Val::as_int),
        Some(0),
        "nothing is refused: {}",
        stdout(&submitted)
    );
    assert_eq!(
        admission.get("waiting").and_then(Val::as_int),
        Some(0),
        "nothing waits: {}",
        stdout(&submitted)
    );
    // ONE run per admitted item: each admitted issue carries its own run id.
    let items = data
        .get("items")
        .and_then(Val::as_array)
        .cloned()
        .unwrap_or_default();
    let runs: Vec<String> = items
        .iter()
        .map(|item| {
            assert_eq!(
                item.get("status").and_then(Val::as_str),
                Some("admitted"),
                "every selected item is admitted: {item:?}"
            );
            item.get("instance_id")
                .and_then(Val::as_str)
                .expect("an admitted item names its run")
                .to_string()
        })
        .collect();
    assert_eq!(runs.len(), 2, "one run per admitted item");
    let unique: std::collections::BTreeSet<&String> = runs.iter().collect();
    assert_eq!(
        unique.len(),
        2,
        "each admitted item gets its OWN run: {runs:?}"
    );
    // The bound-input document the submission confirmed is on disk.
    let written = std::fs::read_to_string(&out_path).expect("written document");
    let bound = Val::parse_json(written.trim()).expect("bound-input document");
    assert_eq!(
        bound.get("schema").and_then(Val::as_str),
        Some(canter::queue_preview::QUEUE_PREVIEW_SCHEMA),
        "the written document is the operator path's bound-input document"
    );

    fixture.shutdown(daemon);
    // The daemon committed durable rows: one run (instance) per admitted item,
    // and one ownership row per admitted item.
    let db = fixture.seed();
    let state = State::open(&db, Retention::default()).expect("reopen state");
    let instances = state.list_instances().expect("instances");
    assert_eq!(
        instances.len(),
        2,
        "the daemon committed one run per admitted item: {instances:?}"
    );
    let recorded: std::collections::BTreeSet<String> = instances
        .iter()
        .map(|row| row.instance_id.clone())
        .collect();
    for run in &runs {
        assert!(
            recorded.contains(run),
            "run {run} is the committed row the submission named: {recorded:?}"
        );
    }
    assert_eq!(
        state.queue_ownership_rows().expect("ownership").len(),
        2,
        "one ownership row per admitted item"
    );
}
