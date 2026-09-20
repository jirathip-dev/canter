//! Issue #192: a run at its `review_evidence` frontier is CARRIED FORWARD —
//! a candidate rebuild (a moved spec revision plus a later authorization
//! window) never silently supersedes it, and the run's own committed tail
//! (merge, cleanup) is still reached. A genuinely dead run stays deliberately
//! replaceable through the explicit, audited `run.release` control.
//!
//! One real daemon per fixture over a temp state dir, real CLI calls, real
//! git repositories: no direct DB writes, no live services, no network.
#[path = "support/process_group.rs"]
mod process_group;
#[path = "support/wait_bounds.rs"]
// The ceilings are shared by every driver-driven wait; a crate uses a subset,
// so the module's unused half is not a defect here.
#[allow(dead_code)]
mod wait_bounds;

use canter::canonical::canonical_text;
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
const PRESERVED: &str = "submission.frontier_preserved";
const PREVIEW_PRESERVED: &str = "preview.frontier_preserved";

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

/// One recorded attempt of a step: its status and its typed code.
fn attempt(sup: &Val, step: &str) -> Option<(String, String)> {
    field(sup, &["cursor", "attempts"])
        .as_array()
        .expect("attempts")
        .iter()
        .rfind(|row| row.get("step").and_then(Val::as_str) == Some(step))
        .map(|row| {
            (
                row.get("status")
                    .and_then(Val::as_str)
                    .unwrap_or("")
                    .to_string(),
                row.get("code")
                    .and_then(Val::as_str)
                    .unwrap_or("")
                    .to_string(),
            )
        })
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
const FRONTIER_NO_PROGRESS_SECS: u64 = wait_bounds::FRONTIER_NO_PROGRESS_SECS;

/// The durable progress a frontier wait tracks: the whole recorded cursor —
/// frontier, attempt ledger, in-flight step — canonically rendered, so any
/// new attempt, settlement or frontier move counts as progress while a
/// re-read of an unchanged cursor does not.
fn frontier_progress(sup: &Val) -> String {
    canonical_text(field(sup, &["cursor"]))
}

struct Fixture {
    root: PathBuf,
    daemon: Option<GroupChild>,
}

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "fc-{}-{}",
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
        fixture.write(
            "bin/hermes",
            "#!/bin/sh\nprintf 'x\\n' >> \"$HOME/prompt-count\"\nprintf 'worker delta\\n' > autonomous.txt\ngit add autonomous.txt\ngit -c user.name=Worker -c user.email=worker@example.invalid commit -m 'worker delivery'\nprintf '%s\\n' \"$@\" > \"$HOME/prompt-argv\"\nprintf 'fixture output\\n'\n",
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
        self.git_at(&self.path("repo"), args)
    }

    fn git_at(&self, directory: &std::path::Path, args: &[&str]) -> String {
        let out = Command::new("/usr/bin/git")
            .arg("-C")
            .arg(directory)
            .args(args)
            .env("HOME", &self.root)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            // #226: copy nothing from the host's shared git templates.
            .env("GIT_TEMPLATE_DIR", "")
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "git at {} {args:?}: {}",
            directory.display(),
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap().trim().to_string()
    }

    fn stop(&mut self) {
        if let Some(mut child) = self.daemon.take() {
            child.terminate("frontier-carry-forward daemon");
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

    /// Submit with the run's own supervision ARMED, so its committed tail is
    /// driven by the daemon's driver, never by an operator dispatch.
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

    fn admission_path(&self) -> String {
        self.path("admission.json").to_str().unwrap().to_string()
    }

    /// The FIRST dispatch of a run belongs to the caller that holds it: it
    /// carries the topology the run binds and a fresh host-resource proof the
    /// run's own later fan-out dispatches re-present.
    fn first(&self, run: &str) -> Val {
        let admission = self.admission_path();
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
            &admission,
        ])
    }

    /// Dispatch ONE step through the operator surface with extra raw args
    /// (already formed: `--param KEY=VALUE`, `--admission FILE`).
    fn dispatch(&self, run: &str, step: &str, extra: &[&str]) -> Val {
        let mut args = vec!["run", "dispatch", "--run", run, "--step", step];
        args.extend_from_slice(extra);
        self.ok(&args)
    }

    /// The review verdict of the run's `review_evidence` step: the operator's
    /// own inputs (the driver never dispatches an approval step).
    fn record_review(&self, run: &str, verdict: &str, check: &str) -> Val {
        let reviewer = "reviewer=reviewer-1".to_string();
        let implementer = "implementer=implementer-1".to_string();
        let verdict_arg = format!("verdict={verdict}");
        let checks = format!("checks=[{{\"name\":\"hosted-ci\",\"status\":\"{check}\"}}]");
        self.dispatch(
            run,
            "p6-5",
            &[
                "--param",
                &reviewer,
                "--param",
                &implementer,
                "--param",
                &verdict_arg,
                "--param",
                &checks,
            ],
        )
    }

    fn status(&self, run: &str) -> Val {
        self.ok(&["run", "status", "--run", run])
    }

    fn supervision(&self, run: &str) -> Val {
        self.ok(&["supervision", "status", "--run", run])
    }

    fn journal(&self, name: &str) -> String {
        std::fs::read_to_string(self.path(&format!("state/canter/journal/{name}"))).unwrap()
    }

    /// The hash-chained audit journal, freshly projected: the mirror file is
    /// rebuilt at daemon START (it is never appended per mutation), so a
    /// restart refreshes it before this read.
    fn refreshed_audit(&mut self) -> String {
        self.restart();
        self.journal("audit.jsonl")
    }

    fn daemon_log(&self) -> String {
        std::fs::read_to_string(self.path("state/canter/daemon.log")).unwrap()
    }

    /// Drive one supervised run to its `review_evidence` frontier. The FIRST
    /// dispatch is the operator's (it carries the topology + a fresh proof);
    /// every later autonomous worker step is dispatched by the run's OWN
    /// driver, whose semantic wake fires after each committed step. The
    /// review step itself is the operator's again (an approval step the
    /// driver never dispatches).
    fn drive_to_review_frontier(&self, run: &str) {
        self.admission();
        self.first(run);
        let sup = self.wait_for_frontier(run, "p6-5");
        for step in ["p1", "p2-5", "p3", "p4-5", "p5-5"] {
            let recorded = attempt(&sup, step);
            assert_eq!(
                recorded,
                Some(("succeeded".to_string(), String::new())),
                "the driver drove {step}: {sup:?}"
            );
        }
    }

    /// Poll the run's supervision status until `done` accepts it, failing
    /// only after `FRONTIER_NO_PROGRESS_SECS` of NO durable progress — any
    /// new recorded attempt, settlement or frontier move resets the ceiling
    /// (issue #232) — and naming the observed progress and the elapsed time.
    fn wait_for_durable<F>(&self, run: &str, want: &str, done: F) -> Val
    where
        F: Fn(&Val) -> bool,
    {
        let started = Instant::now();
        let mut last_progress = started;
        let mut progress = String::new();
        loop {
            let sup = self.supervision(run);
            if done(&sup) {
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
                    "the run never reached {want}: no progress for {stalled}s of {}s waited \
                     (frontier {:?}, {} recorded attempt(s), in_flight {:?}): {sup:?}",
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

    /// Wait until the run's recorded frontier is `step`, and return the
    /// supervision status document that shows it.
    fn wait_for_frontier(&self, run: &str, step: &str) -> Val {
        self.wait_for_durable(run, &format!("frontier {step}"), |sup| {
            text(sup, &["cursor", "next_step"]) == step
        })
    }

    /// Wait until one step's LATEST recorded attempt reaches `status`, and
    /// return the supervision status document that shows it.
    fn wait_for_attempt(&self, run: &str, step: &str, status: &str) -> Val {
        self.wait_for_durable(run, &format!("step {step} {status}"), |sup| {
            attempt(sup, step).is_some_and(|(recorded, _)| recorded == status)
        })
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

/// The fixture's own containment witness: every daemon owns one process
/// group and is reaped, so a lane never leaks a daemon behind a socket.
#[test]
fn fixture_daemon_group_is_reaped() {
    let socket;
    {
        let fixture = Fixture::new();
        socket = fixture.path("d.sock");
    }
    assert_no_process_for_socket(&socket);
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

/// The fix witness (issue #192): a run at its `review_evidence` frontier
/// survives a candidate rebuild — a moved revision under a later
/// authorization window is REFUSED, never a silent p1 restart — and the run
/// then reaches its own committed `p7` merge and `p8` cleanup through the
/// driver, with zero operator dispatch and an empty retry ledger.
#[test]
fn candidate_rebuild_at_the_review_frontier_is_carried_forward() {
    let mut fixture = Fixture::new();
    let (digest_a, preview_a) = fixture.preview(REV_A);
    assert!(hold_codes(item_of(&preview_a, "acme/widgets#5")).is_empty());
    let grant_a = fixture.grant("3600");
    let admitted = fixture.submit_supervised(&digest_a, text(&grant_a, &["grant_id"]));
    let run = text(item_of(&admitted, "acme/widgets#5"), &["instance_id"]).to_string();

    // The run reaches its review_evidence frontier: the run's own driver drove
    // every autonomous worker step (its semantic wake fires after each
    // committed step) and the recorded delivery is in place.
    fixture.drive_to_review_frontier(&run);
    assert!(
        fixture.path("trees/issues-5").exists(),
        "the lane worktree is live at the review frontier"
    );
    // The real forge merge is the orchestrator's own act (the run's `p7` is a
    // read-only rehearsal): the delivered head lands on the integration ref
    // before the tail, exactly as the cleanup content proof needs it.
    fixture.git(&["merge", "--ff-only", "issue-5"]);

    // The operator's own review verdict (an approval step the driver never
    // dispatches): the delivery the committed tail hangs on.
    let reviewed = fixture.record_review(&run, "pass", "passed");
    assert_eq!(
        text(&reviewed, &["dispatch", "verdict"]),
        "pass",
        "{reviewed:?}"
    );
    assert!(
        text(&reviewed, &["dispatch", "evidence_id"]).starts_with("ev_"),
        "the review-evidence row is recorded: {reviewed:?}"
    );

    // The frontier is the merge step; no retry was ever needed.
    let sup = fixture.supervision(&run);
    assert_eq!(text(&sup, &["cursor", "next_step"]), "p7-5", "{sup:?}");
    assert_eq!(
        text(&sup, &["cursor", "next_step_kind"]),
        "merge",
        "{sup:?}"
    );
    assert!(
        field(&sup, &["retries", "rows"])
            .as_array()
            .unwrap()
            .is_empty(),
        "no retry was ever needed: {sup:?}"
    );
    assert_eq!(text(&fixture.status(&run), &["run", "status"]), "running");

    // The candidate rebuild: the published ref moved, so the operator
    // re-selects the issue at a NEW revision and mints the LATER
    // authorization window.
    let (digest_b, _) = fixture.preview(REV_B);
    let grant_b = fixture.grant("3600");
    let rebuilt = fixture.submit(&digest_b, text(&grant_b, &["grant_id"]));
    let item = item_of(&rebuilt, "acme/widgets#5");
    assert_eq!(
        text(item, &["status"]),
        "refused",
        "a candidate rebuild must not bind a fresh run over a preserved frontier: {rebuilt:?}"
    );
    assert_eq!(text(item, &["reason"]), PRESERVED, "{rebuilt:?}");
    assert!(
        text(item, &["message"]).contains(&run),
        "the refusal names the preserved run: {rebuilt:?}"
    );
    assert!(
        matches!(field(item, &["instance_id"]), Val::Null),
        "no successor run is bound: {rebuilt:?}"
    );

    // The owner survived the rebuild attempt: still live, still the unique
    // owner, and still holding its OWN authorization window (a supersession
    // would have moved the ownership row and the grant).
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
        "p7-5",
        "the frontier is untouched (never reset to p1): {sup:?}"
    );

    // The re-preview (now that the later window exists) names the preserved
    // frontier up front: the preview and the admission agree, and the
    // operator is told the deliberate path.
    let (repreview, preview_b) = fixture.preview(REV_B);
    assert_eq!(repreview, digest_b, "the bound request did not change");
    let held = item_of(&preview_b, "acme/widgets#5");
    assert_eq!(text(held, &["status"]), "already_owned", "{preview_b:?}");
    assert_eq!(
        hold_codes(held),
        vec![PREVIEW_PRESERVED.to_string()],
        "{preview_b:?}"
    );

    // The run's OWN driver drives the committed tail — zero operator
    // dispatch: its semantic wake after the recorded review dispatches the
    // merge, and its wake after the merge dispatches the cleanup.
    fixture.wait_for_attempt(&run, "p7-5", "succeeded");
    let sup = fixture.wait_for_attempt(&run, "p8-5", "succeeded");
    assert_eq!(
        text(&sup, &["cursor", "next_step"]),
        "",
        "the committed spine is exhausted: {sup:?}"
    );
    assert!(
        field(&sup, &["retries", "rows"])
            .as_array()
            .unwrap()
            .is_empty(),
        "the tail needed no retry: {sup:?}"
    );
    assert!(
        !fixture.path("trees/issues-5").exists(),
        "cleanup removed the lane worktree"
    );

    // Zero operator dispatch for the tail: both tail claims carry the
    // DRIVER's own derived dispatch key (`ik_<run>-<step>-<unix>`), never a
    // CLI-minted control key, and the driver's own log names both dispatches.
    let audit = fixture.refreshed_audit();
    for step in ["p7-5", "p8-5"] {
        assert!(
            audit.contains(&format!("\"target\":\"acme/widgets:{run}:{step}\"")),
            "the {step} effect is recorded: {audit}"
        );
        assert!(
            audit.contains(&format!("ik_{run}-{step}-")),
            "the {step} dispatch carries the driver's derived key: {audit}"
        );
    }
    assert!(audit.contains("\"action\":\"mutate.merge\""), "{audit}");
    assert!(audit.contains("\"action\":\"mutate.cleanup\""), "{audit}");
    let log = fixture.daemon_log();
    for step in ["p7-5", "p8-5"] {
        assert!(
            log.contains(&format!(
                "dispatched step {step} (supervision.dispatch.next_step)"
            )),
            "the driver dispatched {step}: {log}"
        );
    }
}

/// The negative witness (issue #192): a run whose recorded evidence can never
/// pass is genuinely dead, and it stays DELIBERATELY replaceable. The
/// automatic rebuild is still refused (the frontier is preserved), the
/// explicit, audited `run.release` frees its ownership, and a fresh
/// submission then binds a new run. Runs never become un-replaceable.
#[test]
fn a_dead_run_is_still_deliberately_replaceable() {
    let mut fixture = Fixture::new();
    let (digest_a, _) = fixture.preview(REV_A);
    let grant_a = fixture.grant("3600");
    let admitted = fixture.submit_supervised(&digest_a, text(&grant_a, &["grant_id"]));
    let run = text(item_of(&admitted, "acme/widgets#5"), &["instance_id"]).to_string();

    // A FAILED review verdict at the review frontier: recorded, and never
    // dispatchable past (the driver refuses to continue a failed review).
    fixture.drive_to_review_frontier(&run);
    fixture.record_review(&run, "fail", "failed");
    let sup = fixture.supervision(&run);
    assert_eq!(
        text(&sup, &["evaluation", "observed", "reason"]),
        "supervision.review_failed",
        "the run is classified as a failed review: {sup:?}"
    );
    assert_eq!(
        field(&sup, &["evaluation", "observed", "eligible"]),
        &Val::Bool(false),
        "a failed review is never an eligible continuation: {sup:?}"
    );

    // The automatic rebuild is still refused: preserving the frontier is not
    // a judgement about the evidence, it is the deliberate act that decides.
    let (digest_b, _) = fixture.preview(REV_B);
    let grant_b = fixture.grant("3600");
    let (_, preview_b) = fixture.preview(REV_B);
    assert_eq!(
        hold_codes(item_of(&preview_b, "acme/widgets#5")),
        vec![PREVIEW_PRESERVED.to_string()],
        "{preview_b:?}"
    );
    let rebuilt = fixture.submit(&digest_b, text(&grant_b, &["grant_id"]));
    let item = item_of(&rebuilt, "acme/widgets#5");
    assert_eq!(text(item, &["status"]), "refused", "{rebuilt:?}");
    assert_eq!(text(item, &["reason"]), PRESERVED, "{rebuilt:?}");
    assert_eq!(text(&fixture.status(&run), &["run", "status"]), "running");

    // The DELIBERATE replacement: the explicit, audited release. Its record
    // names the reason, the freed ownership and the window the run held.
    let reason = "review evidence failed; the dead run is deliberately replaced";
    let released = fixture.ok(&["run", "release", "--run", &run, "--reason", reason]);
    assert_eq!(
        text(&released, &["run", "instance_id"]),
        run,
        "{released:?}"
    );
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
    assert_eq!(
        hold_codes(item_of(&preview_c, "acme/widgets#5")),
        Vec::<String>::new(),
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
