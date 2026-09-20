//! Issue #198: the supervisor presents a host-resource proof MEASURED at
//! dispatch time, never the submit-time attestation echoed back.
//!
//! The measured defect (`run-85a856d6b9e9e7d0`, issue 132): the run's
//! committed topology carried a host proof measured at SUBMISSION, the
//! worker's turn outlived the freshness bound, and the supervisor's
//! `p6-132` dispatch was refused `refusal.admission.proof_stale` forever
//! ("re-measure before fan-out") with no re-measure path anywhere.
//!
//! Here the same shape runs end to end over a real daemon and real CLI
//! calls: the submission's proof is measured BEFORE the freshness window,
//! the run's OWN driver then drives the fan-out steps (`p3` harness_start,
//! `p4-5` prompt) with zero operator dispatch, and the run reaches its
//! review frontier with `run_retries` EMPTY. The renewal is recorded (one
//! `host.proof.renewal` journal record naming the superseded instant, the
//! dispatch-time measurement and the observed free bytes) and the run's own
//! recorded dispatch context carries the MEASUREMENT — never the stale
//! value echoed back.
//!
//! One real daemon per fixture over a temp state dir, real CLI calls, real
//! git repositories, a fake harness on PATH (the headless substrate): no
//! live services, no network.
#[path = "support/process_group.rs"]
mod process_group;
#[path = "support/wait_bounds.rs"]
// The ceilings are shared by every driver-driven wait; a crate uses a subset,
// so the module's unused half is not a defect here.
#[allow(dead_code)]
mod wait_bounds;

use canter::canonical::canonical_text;
use canter::state::{Retention, State};
use canter::value::{Val, integer, object, string};
use process_group::{GroupChild, assert_no_process_for_socket};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

static NEXT: AtomicUsize = AtomicUsize::new(0);
const REV_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

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
/// A fixed wall-clock bound turns the run driver's own cadence into a
/// margin-of-a-second merge blocker: the driver wakes semantically on each
/// committed step, and otherwise re-checks on its bounded timer fallback
/// (`canter::supervision::DEFAULT_CHECK_INTERVAL_SECS`, 60 s), so a starved
/// wake legitimately leaves the recorded frontier unchanged for a little
/// over a minute on a loaded host — the measured red (`61.17s` against a
/// 60 s bound) was exactly one fallback tick.
///
/// The wait therefore fails only after this much time with NO durable
/// progress: four driver ticks, so one (or three) starved wakes can never
/// fail the witness, and it stays comfortably inside the CI test driver's
/// per-suite budget (`scripts/ci-test-driver.py` runs every suite with
/// `PER_SUITE_SECONDS = 300`, serial) so a genuinely stuck frontier still
/// reports itself instead of being killed by the driver.
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
            "hp-{}-{}",
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
            "git {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap().trim().to_string()
    }

    fn stop(&mut self) {
        if let Some(mut child) = self.daemon.take() {
            child.terminate("host-proof-renewal daemon");
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
    /// `(digest, preview document)`. The preview writes the bound request
    /// the grant and the submission consume.
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

    /// Submit with the run's own supervision ARMED, so its committed spine is
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

    /// The instant the fixture's SUBMIT-TIME proof was measured: unambiguously
    /// older than the freshness bound, exactly the shape of a submission
    /// whose later fan-out step is reached after a slow worker's turn.
    fn stale_proof_at(&self) -> String {
        canter::time::rfc3339_from_unix(
            canter::time::unix_now() - canter::lifecycle::HOST_PROOF_FRESHNESS_SECS - 1,
        )
    }

    fn write_admission(&self, measured_at: &str) {
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
                    object(vec![("measured_at", string(measured_at))]),
                ),
            ])),
        );
    }

    /// The FIRST dispatch of a run belongs to the caller that holds it: it
    /// carries the topology the run binds and the SUBMIT-TIME host-resource
    /// proof the run's own later fan-out dispatches re-present (issue #198's
    /// measured shape).
    fn first(&self, run: &str, proof_at: &str) -> Val {
        self.write_admission(proof_at);
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

    fn daemon_log(&self) -> String {
        std::fs::read_to_string(self.path("state/canter/daemon.log")).unwrap()
    }

    /// The run's own durable record: its committed spine plus the newest
    /// presented admission (the proof a later dispatch re-presents).
    fn recorded_dispatch(&self, run: &str) -> Val {
        let state = State::open(&self.path("state/canter/state.db"), Retention::default())
            .expect("open the fixture's own state store");
        let recorded = state
            .run_dispatch_context(run)
            .expect("dispatch context")
            .expect("a recorded dispatch context");
        recorded
            .admission
            .unwrap_or_else(|| panic!("a recorded admission"))
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

/// Every recorded `host.proof.renewal` record (superseded instant,
/// replacement instant, observed free bytes) in journal order.
fn renewals(audit: &str) -> Vec<Val> {
    audit
        .lines()
        .filter(|line| line.contains("\"action\":\"host.proof.renewal\""))
        .filter_map(|line| Val::parse_json(line).ok())
        .collect()
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

/// Issue #198's measured shape, end to end: the submission's host-resource
/// proof was measured at SUBMIT time, the fan-out steps (`p3`
/// harness_start, `p4-5` prompt) are reached by the run's OWN driver well
/// after the freshness window, with ZERO operator dispatch and
/// `run_retries` EMPTY — and the run reaches its review frontier.
///
/// The witness that bites: the run's recorded dispatch context carries the
/// MEASUREMENT taken at dispatch time, never the submit-time attestation
/// echoed back, and the renewal is audited (`host.proof.renewal`) against
/// the supervisor's own dispatch key.
#[test]
fn a_submit_time_proof_renews_at_dispatch_time_and_the_fanout_steps_are_reached() {
    let started = canter::time::unix_now();
    let mut fixture = Fixture::new();
    let (digest, _preview) = fixture.preview(REV_A);
    let grant = fixture.grant("3600");
    let admitted = fixture.submit_supervised(&digest, text(&grant, &["grant_id"]));
    let run = text(item_of(&admitted, "acme/widgets#5"), &["instance_id"]).to_string();

    // The caller's own first dispatch (a checkout, not fan-out) presents the
    // proof measured at SUBMISSION. From here on the run's recorded
    // admission is stale — the exact shape of the measured run whose worker
    // turn outlived the bound.
    let stale = fixture.stale_proof_at();
    fixture.first(&run, &stale);

    // The run's own driver drives the committed spine: the fan-out steps
    // `p3` (harness_start) and `p4-5` (prompt) are reached with no operator
    // dispatch at all.
    let sup = fixture.wait_for_frontier(&run, "p6-5");
    for step in ["p1", "p2-5", "p3", "p4-5", "p5-5"] {
        assert_eq!(
            attempt(&sup, step),
            Some(("succeeded".to_string(), String::new())),
            "the driver drove {step}: {sup:?}"
        );
    }
    assert!(
        fixture.path("trees/issues-5").exists(),
        "the lane worktree is live at the review frontier"
    );
    // Zero operator keys: the bounded retry ledger is EMPTY, and no retry
    // authorization was ever recorded.
    assert!(
        field(&sup, &["retries", "rows"])
            .as_array()
            .expect("retry rows")
            .is_empty(),
        "run_retries stays EMPTY: {sup:?}"
    );

    // The renewal is audited: ONE `host.proof.renewal` record naming the
    // superseded (submit-time) instant, the dispatch-time measurement and
    // the free bytes the host exposed at the lane root.
    let audit = fixture.refreshed_audit();
    let records = renewals(&audit);
    assert_eq!(records.len(), 1, "exactly one renewal record: {records:?}");
    let record = &records[0];
    let target = text(record, &["target"]);
    let (superseded_part, rest) = target
        .split_once(":replacement:")
        .unwrap_or_else(|| panic!("a replacement instant: {target}"));
    assert_eq!(
        superseded_part.split("superseded:").nth(1),
        Some(stale.as_str()),
        "the superseded proof is the submit-time attestation: {target}"
    );
    let (replacement, bytes_part) = rest
        .split_once(":available_bytes:")
        .unwrap_or_else(|| panic!("an observation: {target}"));
    let available: u64 = bytes_part.parse().expect("observed free bytes");
    assert!(available > 0, "the host exposed its lane root: {target}");
    let key = text(record, &["idempotency_key"]);
    assert!(
        key.starts_with(&format!("ik_{run}-p3-")),
        "the renewal rode the supervisor's OWN dispatch key, never an operator key: {key}"
    );
    assert!(
        !audit.contains("mutate.run.retry"),
        "no operator retry key exists in the run"
    );

    // ANTI-FABRICATION: the run's recorded dispatch context carries the
    // MEASUREMENT taken at dispatch time — never the submit-time value
    // echoed back.
    let recorded = fixture.recorded_dispatch(&run);
    let recorded_proof = text(&recorded, &["host_proof", "measured_at"]);
    assert_ne!(
        recorded_proof, stale,
        "the submit-time attestation is never echoed back"
    );
    assert_eq!(
        recorded_proof, replacement,
        "the presented proof IS the dispatch-time measurement: {recorded:?}"
    );
    let renewed_unix = canter::time::unix_from_rfc3339(replacement).expect("rfc3339");
    let stale_unix = canter::time::unix_from_rfc3339(&stale).expect("rfc3339");
    assert!(
        renewed_unix > stale_unix && renewed_unix >= started,
        "the measurement was taken at dispatch time ({replacement} vs {stale})"
    );

    // The defect's own symptom is gone: the fan-out steps were never refused
    // for a stale proof, and the renewal is on the daemon log.
    let log = fixture.daemon_log();
    assert!(
        !log.contains("step p3: refusal.admission.proof_stale"),
        "a fan-out step reached after the freshness window is never refused a stale proof"
    );
    assert!(
        log.contains("run.host_proof.renewed"),
        "the renewal is logged: {:?}",
        log.lines()
            .filter(|line| line.contains("host_proof"))
            .collect::<Vec<_>>()
    );
    assert!(
        !log.contains("run.host_proof.unmeasurable"),
        "the host was measurable: {:?}",
        log.lines()
            .filter(|line| line.contains("host_proof"))
            .collect::<Vec<_>>()
    );

    let socket = fixture.path("d.sock");
    fixture.stop();
    assert_no_process_for_socket(&socket);
}

/// Issue #226: the harness initialises scratch repositories itself — never
/// from the HOST's shared git template directory.
///
/// `git init` copies that directory by default (git's compiled-in default,
/// `$GIT_TEMPLATE_DIR`, or `init.templateDir`). Under CI the shared copy
/// fails intermittently (`fatal: cannot copy .../hooks/fsmonitor-watchman.sample`)
/// and reddens a suite that owns no defect, so every fixture `git` command
/// points git at an EMPTY template directory instead.
#[test]
fn scratch_repositories_never_read_the_host_git_templates() {
    let fixture = Fixture::new();
    // The "host" here is the fixture's own `HOME`: a template directory
    // configured the way a machine or CI image configures one, holding a hook
    // that cannot be read — exactly the copy that reddened staging.
    let templates = fixture.path("host-templates");
    let hooks = templates.join("hooks");
    std::fs::create_dir_all(&hooks).unwrap();
    std::fs::write(hooks.join("host-marker.sample"), "host hook\n").unwrap();
    let unreadable = hooks.join("unreadable.sample");
    std::fs::write(&unreadable, "host hook\n").unwrap();
    std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o000)).unwrap();
    fixture.write(
        ".gitconfig",
        &format!("[init]\n\ttemplateDir = {}\n", templates.display()),
    );

    // Positive control: a raw `git init` in this very environment DOES depend
    // on the host template and dies on the copy, so a harness init that still
    // consulted the host could not pass by accident.
    let control_dir = fixture.path("control");
    std::fs::create_dir_all(&control_dir).unwrap();
    let control = Command::new("/usr/bin/git")
        .arg("-C")
        .arg(&control_dir)
        .args(["init", "-q", "-b", "staging"])
        .env("HOME", &fixture.root)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .expect("control init");
    let control_err = String::from_utf8_lossy(&control.stderr).into_owned();
    assert!(
        !control.status.success() && control_err.contains("cannot copy"),
        "the host template must be the one CI died on: {control_err}"
    );

    // The witness: N scratch repositories initialised CONCURRENTLY through the
    // harness path every fixture uses.
    const SCRATCH: usize = 8;
    std::thread::scope(|scope| {
        let inits: Vec<_> = (0..SCRATCH)
            .map(|index| {
                let directory = fixture.path(&format!("scratch-{index}"));
                std::fs::create_dir_all(&directory).unwrap();
                let harness = &fixture;
                scope.spawn(move || harness.git_at(&directory, &["init", "-q", "-b", "staging"]))
            })
            .collect();
        for init in inits {
            init.join().expect("every harness scratch init succeeds");
        }
    });
    for index in 0..SCRATCH {
        let directory = fixture.path(&format!("scratch-{index}"));
        assert!(
            !directory.join(".git/hooks/host-marker.sample").exists(),
            "the host's hook was imported into {}",
            directory.display()
        );
    }
}
