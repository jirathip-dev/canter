//! Issue #209: a `queue submit` for an issue whose run is LIVE and not
//! terminal is refused typed — naming the live run and its recorded frontier
//! (step, kind, supervision class) — instead of invalidating the incumbent as
//! a side effect of admission. The incumbent keeps its unique ownership, its
//! own authorization window and its frontier, and supersession stays the
//! explicit, recorded `run.release` control.
//!
//! One real daemon per fixture over a temp state dir, real CLI calls, real git
//! repositories: no direct DB writes, no live services, no network.
#[path = "support/process_group.rs"]
mod process_group;

use canter::canonical::canonical_text;
use canter::supervision::CLASSES;
use canter::value::{Val, integer, object, string};
use process_group::{GroupChild, assert_no_process_for_socket};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

static NEXT: AtomicUsize = AtomicUsize::new(0);
const REV_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const REV_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const LIVE_RUN: &str = "submission.live_run";
const PREVIEW_LIVE_RUN: &str = "preview.live_run";

fn field<'a>(doc: &'a Val, path: &[&str]) -> &'a Val {
    path.iter().fold(doc, |value, key| {
        value
            .get(key)
            .unwrap_or_else(|| panic!("missing {key}: {doc:?}"))
    })
}

fn text<'a>(doc: &'a Val, path: &[&str]) -> &'a str {
    field(doc, path).as_str().expect("string field")
}

fn item_of<'a>(doc: &'a Val, id: &str) -> &'a Val {
    field(doc, &["items"])
        .as_array()
        .expect("items")
        .iter()
        .find(|item| item.get("id").and_then(Val::as_str) == Some(id))
        .unwrap_or_else(|| panic!("item {id} in {doc:?}"))
}

/// The no-progress ceiling of a frontier wait, in seconds (issue #232).
///
/// Progress-driven, never a fixed wall-clock bound: the driver wakes
/// semantically on each committed step and otherwise re-checks on its
/// bounded timer fallback (`canter::supervision::DEFAULT_CHECK_INTERVAL_SECS`,
/// 60 s), so one starved wake legitimately holds the frontier for a little
/// over a minute on a loaded host. Four ticks is the ceiling — a starved
/// wake can never fail the witness — and it stays comfortably inside the CI
/// test driver's per-suite budget (`scripts/ci-test-driver.py`,
/// `PER_SUITE_SECONDS = 300`), so a genuinely stuck frontier still reports
/// itself instead of being killed by the driver.
const FRONTIER_NO_PROGRESS_SECS: u64 = 240;

/// The durable progress a frontier wait tracks: the whole recorded cursor —
/// frontier, attempt ledger, in-flight step — canonically rendered, so any
/// new attempt, settlement or frontier move counts as progress while a
/// re-read of an unchanged cursor does not.
fn frontier_progress(sup: &Val) -> String {
    canonical_text(field(sup, &["cursor"]))
}

/// The durable progress a recorded-CLASS wait tracks: the cursor plus the
/// committed check ledger (count, last check, continuation) of the recorded
/// evaluation, canonically rendered. A committed check, a settlement or a
/// frontier move counts as progress; the read-time fields that change on
/// every read (`freshness.age_secs`, `progress.age_secs`,
/// `next_check.due_in_secs`) are deliberately excluded, so re-reading an
/// unchanged record can never pass for progress.
fn recorded_progress(sup: &Val) -> String {
    canonical_text(&object(vec![
        ("cursor", field(sup, &["cursor"]).clone()),
        ("checks", field(sup, &["evaluation", "checks"]).clone()),
        (
            "last_check",
            field(sup, &["evaluation", "last_check"]).clone(),
        ),
        (
            "continuation",
            field(sup, &["evaluation", "continuation"]).clone(),
        ),
    ]))
}

fn hold_codes(item: &Val) -> Vec<String> {
    field(item, &["holds"])
        .as_array()
        .expect("holds")
        .iter()
        .map(|hold| {
            hold.get("code")
                .and_then(Val::as_str)
                .unwrap_or("")
                .to_string()
        })
        .collect()
}

/// The message of one item's hold with `code`.
fn hold_message(item: &Val, code: &str) -> String {
    field(item, &["holds"])
        .as_array()
        .expect("holds")
        .iter()
        .find(|hold| hold.get("code").and_then(Val::as_str) == Some(code))
        .unwrap_or_else(|| panic!("hold {code} in {item:?}"))
        .get("message")
        .and_then(Val::as_str)
        .unwrap_or_default()
        .to_string()
}

struct Fixture {
    root: PathBuf,
    daemon: Option<GroupChild>,
}

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "lrg-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).expect("exclusive fixture root");
        let mut fixture = Self { root, daemon: None };
        std::fs::create_dir(fixture.path("bin")).unwrap();
        std::fs::create_dir(fixture.path("repo")).unwrap();
        std::fs::create_dir(fixture.path("trees")).unwrap();
        let worktrees_root = std::fs::canonicalize(fixture.path("trees")).unwrap();
        fixture.git(&["init", "-b", "staging"]);
        fixture.git(&["remote", "add", "origin", "."]);
        fixture.git(&[
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "--allow-empty",
            "-m",
            "initial",
        ]);
        fixture.write("config.toml", &format!(
            "schema = \"hf-config/v1\"\n[daemon]\nenabled = true\nsocket = {:?}\n[repository.widgets]\norigin = \"https://example.invalid/acme/widgets\"\nbranch = \"staging\"\n[harness.worker]\nkind = \"hermes\"\nexecutable = \"hermes\"\nenv_allow = []\nprovider = \"provider-a\"\nmodel = \"model-a\"\nbinding_introspection = false\n",
            fixture.path("d.sock").to_str().unwrap()));
        // The wedge: this worker runs and leaves NOTHING behind, so the run's
        // own collect step refuses the empty delta and the run stays live with
        // `p5` as its recorded frontier.
        fixture.write(
            "bin/hermes",
            "#!/bin/sh\nprintf 'x\\n' >> \"$HOME/prompt-count\"\nprintf '%s\\n' \"$@\" > \"$HOME/prompt-argv\"\nprintf 'fixture output\\n'\n",
        );
        std::fs::set_permissions(
            fixture.path("bin/hermes"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        fixture.write(
            "topology.json",
            &canonical_text(&object(vec![
                ("integration_branch", string("staging")),
                ("production_branches", Val::Arr(vec![string("main")])),
                (
                    "integration_repo",
                    string(fixture.path("repo").to_str().unwrap()),
                ),
                ("worktrees_root", string(worktrees_root.to_str().unwrap())),
            ])),
        );
        fixture.restart();
        fixture
    }

    fn path(&self, path: &str) -> PathBuf {
        self.root.join(path)
    }

    fn write(&self, name: &str, contents: &str) {
        std::fs::write(self.path(name), contents).unwrap();
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_canter"));
        command
            .env_clear()
            .env("HOME", &self.root)
            .env("XDG_STATE_HOME", self.path("state"))
            .env("XDG_CONFIG_HOME", self.path("config"))
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin", self.path("bin").display()),
            );
        command
    }

    fn cli(&self, args: &[&str]) -> (i32, Val) {
        let out = self
            .command()
            .args(args)
            .args([
                "--config",
                self.path("config.toml").to_str().unwrap(),
                "--json",
            ])
            .output()
            .expect("CLI output");
        let exit = out.status.code().unwrap_or(-1);
        let stdout = String::from_utf8_lossy(&out.stdout);
        let doc = Val::parse_json(stdout.trim()).unwrap_or_else(|_| {
            object(vec![(
                "stderr",
                string(&String::from_utf8_lossy(&out.stderr)),
            )])
        });
        eprintln!("{} => exit={exit} {}", args.join(" "), canonical_text(&doc));
        (exit, doc)
    }

    fn ok(&self, args: &[&str]) -> Val {
        let (exit, doc) = self.cli(args);
        assert_eq!(exit, 0, "{doc:?}");
        field(&doc, &["data"]).clone()
    }

    fn git(&self, args: &[&str]) -> String {
        let out = Command::new("/usr/bin/git")
            .arg("-C")
            .arg(self.path("repo"))
            .args(args)
            .env("HOME", &self.root)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            // #226: copy nothing from the host's shared git templates.
            .env("GIT_TEMPLATE_DIR", "")
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap().trim().to_string()
    }

    fn stop(&mut self) {
        if let Some(mut child) = self.daemon.take() {
            child.terminate("live-run-guard daemon");
        }
    }

    fn restart(&mut self) {
        self.stop();
        let socket = self.path("d.sock");
        let mut command = self.command();
        command
            .args(["daemon", "run", "--socket"])
            .arg(&socket)
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        self.daemon = Some(GroupChild::spawn(&mut command, &socket).expect("spawn daemon"));
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if canter::client::call(&self.path("d.sock"), "state.epoch", Some(&object(vec![])))
                .is_ok()
            {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!("fixture daemon did not become ready");
    }

    /// Render one queue preview for issue 5 at `revision` and return
    /// `(digest, preview document)`. The preview writes the bound request the
    /// grant and the submission consume.
    fn preview(&self, revision: &str) -> (String, Val) {
        let doc = self.ok(&[
            "queue",
            "preview",
            "--repository",
            "widgets",
            "--harness",
            "worker",
            "--execution",
            "headless",
            "--host",
            "host-1",
            "--issue",
            &format!("5={revision}"),
            "--caps",
            "4/2/2",
            "--host-available",
            "yes",
            "--harness-lanes",
            "0",
            "--out",
            self.path("request.json").to_str().unwrap(),
        ]);
        let bound =
            Val::parse_json(&std::fs::read_to_string(self.path("request.json")).unwrap()).unwrap();
        let digest = canter::queue_executor::bound_digest(&bound).unwrap();
        (digest, field(&doc, &["preview"]).clone())
    }

    fn grant(&self, seconds: &str) -> Val {
        self.ok(&[
            "grant",
            "issue",
            "--request",
            self.path("request.json").to_str().unwrap(),
            "--issue",
            "5",
            "--expires-in",
            seconds,
        ])
    }

    fn submit(&self, digest: &str, grant: &str) -> Val {
        self.ok(&[
            "queue",
            "submit",
            "--request",
            self.path("request.json").to_str().unwrap(),
            "--confirm-digest",
            digest,
            "--grant",
            &format!("5={grant}"),
            "--caps",
            "4/2/2",
            "--host-available",
            "yes",
            "--harness-lanes",
            "0",
        ])
    }

    /// Submit with the run's own supervision ARMED: its armed driver then
    /// drives every autonomous step of the committed spine.
    fn submit_supervised(&self, digest: &str, grant: &str) -> Val {
        self.ok(&[
            "queue",
            "submit",
            "--request",
            self.path("request.json").to_str().unwrap(),
            "--confirm-digest",
            digest,
            "--grant",
            &format!("5={grant}"),
            "--caps",
            "4/2/2",
            "--host-available",
            "yes",
            "--harness-lanes",
            "0",
            "--supervise",
            "arm",
            "--topology",
            self.path("topology.json").to_str().unwrap(),
        ])
    }

    fn admission(&self) {
        self.write(
            "admission.json",
            &canonical_text(&object(vec![
                (
                    "caps",
                    object(vec![
                        ("global", integer(4)),
                        ("repository", integer(2)),
                        ("harness", integer(2)),
                    ]),
                ),
                ("harness_lanes", integer(0)),
                (
                    "host_proof",
                    object(vec![("measured_at", string(&canter::time::rfc3339_now()))]),
                ),
            ])),
        );
    }

    /// The FIRST dispatch of a run belongs to the caller that holds it: it
    /// carries the topology the run binds and a fresh host-resource proof the
    /// run's own later fan-out dispatches re-present.
    fn first(&self, run: &str) -> Val {
        self.admission();
        self.ok(&[
            "run",
            "dispatch",
            "--run",
            run,
            "--step",
            "p1",
            "--topology",
            self.path("topology.json").to_str().unwrap(),
            "--admission",
            self.path("admission.json").to_str().unwrap(),
        ])
    }

    fn status(&self, run: &str) -> Val {
        self.ok(&["run", "status", "--run", run])
    }

    fn supervision(&self, run: &str) -> Val {
        self.ok(&["supervision", "status", "--run", run])
    }

    /// The hash-chained audit journal, freshly projected: the mirror file is
    /// rebuilt at daemon START (it is never appended per mutation), so a
    /// restart refreshes it before this read.
    fn refreshed_audit(&mut self) -> String {
        self.restart();
        std::fs::read_to_string(self.path("state/canter/journal/audit.jsonl")).unwrap()
    }

    /// Wait until the run's recorded frontier is `step`, and return the
    /// supervision status document that shows it.
    ///
    /// PROGRESS-DRIVEN, never a fixed wall-clock bound (issue #232): the
    /// ceiling is `FRONTIER_NO_PROGRESS_SECS` of NO durable progress, and any
    /// new recorded attempt, settlement or frontier move resets it. A
    /// genuinely stuck frontier still fails, naming the progress observed and
    /// the elapsed time.
    fn wait_for_frontier(&self, run: &str, step: &str) -> Val {
        let started = Instant::now();
        let mut last_progress = started;
        let mut progress = String::new();
        loop {
            let sup = self.supervision(run);
            if text(&sup, &["cursor", "next_step"]) == step {
                return sup;
            }
            let observed = frontier_progress(&sup);
            if observed != progress {
                progress = observed;
                last_progress = Instant::now();
            }
            let stalled = last_progress.elapsed().as_secs();
            if stalled >= FRONTIER_NO_PROGRESS_SECS {
                panic!(
                    "the frontier never reached {step}: no progress for {stalled}s of {}s \
                     waited (frontier {:?}, {} recorded attempt(s), in_flight {:?}): {sup:?}",
                    started.elapsed().as_secs(),
                    text(&sup, &["cursor", "next_step"]),
                    field(&sup, &["cursor", "attempts"])
                        .as_array()
                        .map_or(0, Vec::len),
                    text(&sup, &["cursor", "in_flight"]),
                );
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// Wedge one supervised run at `p5`: the run's own driver drives `p1..p4`
    /// and its `p5` collect step is refused (the worker left no delta), so the
    /// run is LIVE with `p5-5` as its recorded frontier — the pre-condition
    /// the issue measures. Returns the status document and the run's RECORDED
    /// supervision class, held stable across three consecutive reads so the
    /// class the refusal must name is not racing the driver.
    fn wedge_at_p5(&self, run: &str) -> (Val, String) {
        self.first(run);
        let sup = self.wait_for_frontier(run, "p5-5");
        assert_eq!(text(&sup, &["cursor", "next_step_kind"]), "collect_outcome");
        let deadline_free_start = Instant::now();
        let mut last_progress = deadline_free_start;
        let mut progress = String::new();
        let mut stable = String::new();
        let mut reads = 0usize;
        loop {
            let sup = self.supervision(run);
            let class = text(&sup, &["evaluation", "class"]).to_string();
            assert!(
                CLASSES.contains(&class.as_str()),
                "the recorded class is a closed-vocabulary member: {sup:?}"
            );
            if class == stable {
                reads += 1;
                if reads >= 3 {
                    assert_ne!(class, "unknown", "the run recorded a real check: {sup:?}");
                    assert_eq!(
                        text(&sup, &["cursor", "next_step"]),
                        "p5-5",
                        "the frontier is still p5: {sup:?}"
                    );
                    return (sup, class);
                }
            } else {
                stable = class.clone();
                reads = 1;
            }
            let observed = recorded_progress(&sup);
            if observed != progress {
                progress = observed;
                last_progress = Instant::now();
            }
            let stalled = last_progress.elapsed().as_secs();
            assert!(
                stalled < FRONTIER_NO_PROGRESS_SECS,
                "the recorded class never settled at p5-5: no progress for {stalled}s of {}s \
                 waited (class {class:?}, frontier {:?}, {} recorded check(s)): {sup:?}",
                deadline_free_start.elapsed().as_secs(),
                text(&sup, &["cursor", "next_step"]),
                field(&sup, &["evaluation", "checks"])
                    .as_int()
                    .unwrap_or(-1),
            );
            std::thread::sleep(Duration::from_millis(700));
        }
    }

    /// `run release` with a bounded retry: the run's own driver may hold a
    /// dispatch claim for an instant, and a release never abandons live work —
    /// the operator's release is retried under the SAME reason until the run
    /// is quiescent, and only a typed in-flight refusal is retried.
    fn release(&self, run: &str, reason: &str) -> Val {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let (exit, doc) = self.cli(&["run", "release", "--run", run, "--reason", reason]);
            if exit == 0 {
                return field(&doc, &["data"]).clone();
            }
            let code = doc
                .get("error")
                .and_then(|error| error.get("code"))
                .and_then(Val::as_str)
                .unwrap_or_default();
            assert_eq!(
                code, "refusal.run.in_flight",
                "only an in-flight refusal is retried: {doc:?}"
            );
            assert!(
                Instant::now() < deadline,
                "the run never became quiescent for its release: {doc:?}"
            );
            std::thread::sleep(Duration::from_millis(200));
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop();
        if std::thread::panicking() {
            // Keep a failed fixture's state + logs for diagnosis; the test
            // harness prints the path.
            eprintln!("fixture kept at {}", self.root.display());
            return;
        }
        std::fs::remove_dir_all(&self.root).expect("remove own fixture");
    }
}

/// The fixture's own containment witness: every daemon owns one process group
/// and is reaped, so a lane never leaks a daemon behind a socket.
#[test]
fn fixture_daemon_group_is_reaped() {
    let socket;
    {
        let fixture = Fixture::new();
        socket = fixture.path("d.sock");
    }
    assert_no_process_for_socket(&socket);
}

/// W1 + W2 (issue #209): with the issue's run LIVE at `p5`, a second
/// submission — a moved spec revision under a LATER authorization window, the
/// exact shape the acceptance spine lost a frontier to — is REFUSED with the
/// typed code `submission.live_run`, naming the live run and its recorded
/// frontier (step, kind and supervision class). The incumbent survives with
/// its frontier intact, keeps its own window, and no successor is bound.
/// Removing the guard reddens this witness (the item is admitted and the
/// incumbent is invalidated).
#[test]
fn a_submission_for_a_live_run_is_refused_typed_and_never_invalidates_it() {
    let fixture = Fixture::new();
    let (digest_a, preview_a) = fixture.preview(REV_A);
    assert!(
        hold_codes(item_of(&preview_a, "acme/widgets#5")).is_empty(),
        "the fresh selection is selectable: {preview_a:?}"
    );
    let grant_a = fixture.grant("3600");
    let admitted = fixture.submit_supervised(&digest_a, text(&grant_a, &["grant_id"]));
    let run = text(item_of(&admitted, "acme/widgets#5"), &["instance_id"]).to_string();

    // The run's own driver reaches `p5`; its collect step is the frontier it
    // is parked on, the run is live and it recorded a real class.
    let (sup, class) = fixture.wedge_at_p5(&run);
    assert_eq!(text(&sup, &["cursor", "next_step"]), "p5-5", "{sup:?}");
    assert!(
        fixture.path("trees/issues-5").exists(),
        "the lane worktree is live at the frontier"
    );
    let status = fixture.status(&run);
    assert_eq!(text(&status, &["run", "status"]), "running", "{status:?}");

    // The candidate rebuild: the operator re-selects the issue at a NEW
    // revision and mints the LATER authorization window.
    let (digest_b, _) = fixture.preview(REV_B);
    let grant_b = fixture.grant("3600");
    let rebuilt = fixture.submit(&digest_b, text(&grant_b, &["grant_id"]));
    let item = item_of(&rebuilt, "acme/widgets#5");
    assert_eq!(
        text(item, &["status"]),
        "refused",
        "a submission never binds a second run over a live one: {rebuilt:?}"
    );
    assert_eq!(text(item, &["reason"]), LIVE_RUN, "{rebuilt:?}");
    let message = text(item, &["message"]).to_string();
    assert!(
        message.contains(&run),
        "the refusal names the live run: {rebuilt:?}"
    );
    assert!(
        message.contains("p5-5 (collect_outcome"),
        "the refusal names the frontier step and its kind: {rebuilt:?}"
    );
    assert!(
        message.contains(&format!("supervision class {class}")),
        "the refusal names the run's recorded class: {rebuilt:?}"
    );
    assert!(
        matches!(field(item, &["instance_id"]), Val::Null),
        "no successor run is bound: {rebuilt:?}"
    );

    // The incumbent survived the submission attempt: still live, still the
    // unique owner, still holding its OWN authorization window, frontier
    // untouched.
    let status = fixture.status(&run);
    assert_eq!(text(&status, &["run", "status"]), "running", "{status:?}");
    assert_eq!(
        text(&status, &["run", "grant_id"]),
        text(&grant_a, &["grant_id"]),
        "the run keeps its own window: {status:?}"
    );
    let sup = fixture.supervision(&run);
    assert_eq!(
        text(&sup, &["cursor", "next_step"]),
        "p5-5",
        "the frontier is untouched (never reset to p1): {sup:?}"
    );

    // The same-revision duplicate names the live incumbent and its frontier
    // too — never a bare "already owned".
    fixture.preview(REV_A);
    let duplicate_grant = fixture.grant("3600");
    let duplicate = fixture.submit(&digest_a, text(&duplicate_grant, &["grant_id"]));
    let item = item_of(&duplicate, "acme/widgets#5");
    assert_eq!(text(item, &["status"]), "refused", "{duplicate:?}");
    assert_eq!(
        text(item, &["reason"]),
        "submission.already_owned",
        "{duplicate:?}"
    );
    let message = text(item, &["message"]).to_string();
    assert!(
        message.contains(&run) && message.contains("p5-5 (collect_outcome"),
        "the duplicate refusal names the live run and its frontier: {duplicate:?}"
    );

    // The preview agrees with the admission: the item is presented with its
    // live run and that run's frontier, never as an authorized rebind, and the
    // request is not reported ready.
    let (repreview, preview_b) = fixture.preview(REV_B);
    assert_eq!(repreview, digest_b, "the bound request did not change");
    let held = item_of(&preview_b, "acme/widgets#5");
    assert_eq!(text(held, &["status"]), "already_owned", "{preview_b:?}");
    assert_eq!(
        hold_codes(held),
        vec![PREVIEW_LIVE_RUN.to_string()],
        "{preview_b:?}"
    );
    let held_message = hold_message(held, PREVIEW_LIVE_RUN);
    assert!(
        held_message.contains(&run) && held_message.contains("p5-5 (collect_outcome"),
        "the preview hold names the live run and its frontier: {preview_b:?}"
    );
    assert!(
        matches!(field(&preview_b, &["ready"]), Val::Bool(false)),
        "a preview over a live incumbent is never ready: {preview_b:?}"
    );
}

/// W3 (issue #209): the incumbent is still DELIBERATELY replaceable through
/// the sanctioned route — the explicit, recorded `run.release` — and the
/// release is visible in the audit trail with its reason, after which a fresh
/// submission admits a new run. Runs never become un-replaceable.
#[test]
fn an_explicit_release_still_permits_a_fresh_submission() {
    let mut fixture = Fixture::new();
    let (digest_a, _) = fixture.preview(REV_A);
    let grant_a = fixture.grant("3600");
    let admitted = fixture.submit_supervised(&digest_a, text(&grant_a, &["grant_id"]));
    let run = text(item_of(&admitted, "acme/widgets#5"), &["instance_id"]).to_string();
    fixture.wedge_at_p5(&run);

    // The automatic route is refused: the live incumbent keeps its frontier.
    let (digest_b, _) = fixture.preview(REV_B);
    let grant_b = fixture.grant("3600");
    let rebuilt = fixture.submit(&digest_b, text(&grant_b, &["grant_id"]));
    assert_eq!(
        text(item_of(&rebuilt, "acme/widgets#5"), &["reason"]),
        LIVE_RUN,
        "{rebuilt:?}"
    );

    // The DELIBERATE replacement: the explicit, audited release. Its record
    // names the reason and the freed ownership.
    let reason = "a wedged p5 frontier: deliberately released to rebuild the spec";
    let released = fixture.release(&run, reason);
    assert_eq!(
        text(&released, &["release", "status"]),
        "invalidated",
        "{released:?}"
    );
    assert_eq!(
        text(&released, &["release", "reason"]),
        reason,
        "{released:?}"
    );
    assert_eq!(
        text(&released, &["release", "ownership"]),
        "freed",
        "{released:?}"
    );
    let audit = fixture.refreshed_audit();
    assert!(
        audit.contains("\"action\":\"run.release\""),
        "the release is audited: {audit}"
    );
    assert!(
        audit.contains(reason),
        "the release record carries the operator's reason: {audit}"
    );
    assert!(
        audit.contains("ownership:freed"),
        "the release record states the freed ownership: {audit}"
    );

    // A fresh submission then binds a NEW run for the issue: the released run
    // was never un-replaceable.
    let (digest_c, preview_c) = fixture.preview(REV_B);
    assert!(
        hold_codes(item_of(&preview_c, "acme/widgets#5")).is_empty(),
        "the released issue is selectable again: {preview_c:?}"
    );
    let grant_c = fixture.grant("3600");
    let replaced = fixture.submit(&digest_c, text(&grant_c, &["grant_id"]));
    let item = item_of(&replaced, "acme/widgets#5");
    assert_eq!(text(item, &["status"]), "admitted", "{replaced:?}");
    let successor = text(item, &["instance_id"]).to_string();
    assert_ne!(successor, run, "{replaced:?}");
    assert_eq!(
        text(&fixture.status(&successor), &["run", "status"]),
        "new",
        "the successor starts its own fresh spine"
    );
    assert_eq!(
        text(&fixture.status(&run), &["run", "status"]),
        "invalidated",
        "the released run stays terminal"
    );
}
