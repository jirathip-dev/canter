//! Isolated supported-surface executor proofs. No live services or direct DB writes.
#[path = "support/process_group.rs"]
mod process_group;

use canter::canonical::canonical_text;
use canter::value::{Val, integer, object, string};
use process_group::{GroupChild, assert_no_process_for_socket};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

static NEXT: AtomicUsize = AtomicUsize::new(0);
const REV: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const REV_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

struct Fixture {
    root: PathBuf,
    daemon: Option<GroupChild>,
}

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

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "ea-{}-{}",
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
            "#!/bin/sh\nprintf 'x\\n' >> \"$HOME/prompt-count\"\ncase \"$*\" in\n  *persist-me*) test -f \"$HOME/allow-prompt\" || exit 9 ;;\n  *\"Implement acme/widgets#5\"*) printf 'autonomous worker change\\n' > autonomous.txt; git add autonomous.txt; git -c user.name=Worker -c user.email=worker@example.invalid commit -m 'worker delivery' ;;\nesac\nprintf '%s\\n' \"$@\" > prompt-argv\nprintf 'fixture output\\n'\n",
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
    fn worktree_git(&self, args: &[&str]) -> String {
        self.git_at(&self.path("trees/issues-5"), args)
    }
    fn git_at(&self, directory: &std::path::Path, args: &[&str]) -> String {
        let out = Command::new("/usr/bin/git")
            .arg("-C")
            .arg(directory)
            .args(args)
            .env("HOME", &self.root)
            .env("GIT_CONFIG_NOSYSTEM", "1")
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
            child.terminate("executor-authoring daemon");
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
    /// The authored spine of this fixture, rendered with the EXPLICIT
    /// bare-subprocess substrate (issue #139): this fixture certifies the
    /// authored-spine semantics (durable step inputs, grant windows, the
    /// collection/retry frontier) against a direct-subprocess worker, so it
    /// selects the documented fallback explicitly instead of standing up a
    /// pane substrate. The default (Herdr pane) path is witnessed end to end
    /// in `tests/herdr_pane_execution.rs` and `tests/supervision.rs`.
    fn preview(&self, revision: &str) -> String {
        self.ok(&[
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
        canter::queue_executor::bound_digest(&bound).unwrap()
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
    fn run(&self) -> String {
        let digest = self.preview(REV);
        let grant = self.grant("3600");
        let submitted = self.submit(&digest, text(&grant, &["grant_id"]));
        submitted.get("items").and_then(Val::as_array).unwrap()[0]
            .get("instance_id")
            .and_then(Val::as_str)
            .unwrap()
            .to_string()
    }
    fn first(&self, run: &str) -> Val {
        self.ok(&[
            "run",
            "dispatch",
            "--run",
            run,
            "--step",
            "p1",
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
    fn through_prompt(&self, run: &str, payload: &str, requires_delta: bool) {
        self.admission();
        self.ok(&[
            "run",
            "dispatch",
            "--run",
            run,
            "--step",
            "p3",
            "--admission",
            self.path("admission.json").to_str().unwrap(),
        ]);
        let expectation = format!("requires_delta={requires_delta}");
        self.ok(&[
            "run",
            "dispatch",
            "--run",
            run,
            "--step",
            "p4-5",
            "--admission",
            self.path("admission.json").to_str().unwrap(),
            "--param",
            &format!("payload={payload}"),
            "--param",
            &expectation,
        ]);
    }
    fn failed_prompt(&self) -> String {
        let run = self.run();
        self.first(&run);
        self.ok(&["run", "dispatch", "--run", &run, "--step", "p2-5"]);
        self.admission();
        self.ok(&[
            "run",
            "dispatch",
            "--run",
            &run,
            "--step",
            "p3",
            "--admission",
            self.path("admission.json").to_str().unwrap(),
        ]);
        let (exit, failed) = self.cli(&[
            "run",
            "dispatch",
            "--run",
            &run,
            "--step",
            "p4-5",
            "--admission",
            self.path("admission.json").to_str().unwrap(),
            "--param",
            "payload=persist-me",
        ]);
        assert_eq!(exit, 1, "{failed:?}");
        assert_eq!(text(&failed, &["error", "code"]), "adapter.exit");
        run
    }
    fn prompt_invocations(&self) -> usize {
        std::fs::read_to_string(self.path("prompt-count"))
            .expect("prompt argv")
            .lines()
            .count()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop();
        std::fs::remove_dir_all(&self.root).expect("remove own fixture");
    }
}
fn succeeded(doc: &Val) {
    assert!(matches!(field(doc, &["dispatch"]), Val::Obj(_)), "{doc:?}");
}

#[test]
fn executor_fixture_reaps_its_daemon_group() {
    let socket;
    {
        let fixture = Fixture::new();
        socket = fixture.path("d.sock");
    }
    assert_no_process_for_socket(&socket);
}

#[test]
fn cycle2_supervision_dispatches_the_authored_spine_through_collection() {
    let mut fixture = Fixture::new();
    let digest = fixture.preview(REV);
    let grant = fixture.grant("3600");
    let submitted = fixture.submit_supervised(&digest, text(&grant, &["grant_id"]));
    let run = text(
        &field(&submitted, &["items"]).as_array().unwrap()[0],
        &["instance_id"],
    )
    .to_string();

    // No `run dispatch` call occurs in this test. The daemon-owned supervisor
    // must use the topology/admission committed by `queue submit` and advance
    // each successful outcome on its own wake.
    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        let status = fixture.ok(&["supervision", "status", "--run", &run]);
        if text(&status, &["cursor", "next_step"]) == "p6-5"
            && text(&status, &["evaluation", "reason"]) == "supervision.waiting_approval"
        {
            break status;
        }
        assert!(Instant::now() < deadline, "supervisor stalled: {status:?}");
        std::thread::sleep(Duration::from_millis(50));
    };
    let attempts = field(&status, &["cursor", "attempts"])
        .as_array()
        .expect("attempts")
        .clone();
    assert_eq!(
        attempts.len(),
        5,
        "p1 through p5 each ran once: {attempts:?}"
    );
    assert!(
        attempts
            .iter()
            .all(|attempt| { attempt.get("status").and_then(Val::as_str) == Some("succeeded") })
    );
    assert_eq!(
        text(&status, &["evaluation", "reason"]),
        "supervision.waiting_approval"
    );
    assert_eq!(
        field(&status, &["evaluation", "eligible"]).as_bool(),
        Some(false),
        "p6 names its concrete independent-review blocker"
    );
    assert_eq!(
        fixture.worktree_git(&["branch", "--show-current"]),
        "issue-5"
    );
    assert_eq!(fixture.prompt_invocations(), 1);
    assert_eq!(
        std::fs::read_to_string(fixture.path("trees/issues-5/autonomous.txt")).unwrap(),
        "autonomous worker change\n"
    );

    fixture.restart();
    let audit = std::fs::read_to_string(fixture.path("state/canter/journal/audit.jsonl")).unwrap();
    let rows: Vec<Val> = audit
        .lines()
        .map(|line| Val::parse_json(line).expect("audit row"))
        .collect();
    let expected = [
        "mutate.checkout",
        "mutate.worktree_create",
        "mutate.harness_start",
        "mutate.prompt",
        "mutate.collect_outcome",
    ];
    let mut pairs = Vec::new();
    for action in expected {
        let position = rows
            .iter()
            .position(|row| row.get("action").and_then(Val::as_str) == Some(action))
            .unwrap_or_else(|| panic!("missing {action}: {rows:?}"));
        let outcome_action = format!("outcome.{action}");
        assert_eq!(
            rows.get(position + 1)
                .and_then(|row| row.get("action"))
                .and_then(Val::as_str),
            Some(outcome_action.as_str()),
            "{action} must be immediately followed by its outcome"
        );
        pairs.push((
            field(&rows[position], &["seq"]).as_int().unwrap(),
            field(&rows[position + 1], &["seq"]).as_int().unwrap(),
        ));
    }
    eprintln!("AUTONOMOUS_RUN={run} MUTATE_OUTCOME_SEQS={pairs:?} ATTEMPTS={attempts:?}");
}

#[test]
fn f6_first_dispatch_uses_supported_topology_input() {
    let fixture = Fixture::new();
    let run = fixture.run();
    let (exit, refused) = fixture.cli(&["run", "dispatch", "--run", &run, "--step", "p1"]);
    assert_eq!(exit, 4);
    assert!(text(&refused, &["error", "message"]).contains("--topology FILE"));
    succeeded(&fixture.first(&run));
}

#[test]
fn f7_contract_param_names_are_reachable_through_cli() {
    let fixture = Fixture::new();
    // Unknown run is intentional: parsing must accept the contract's own keys
    // and reach the daemon, not exit at the CLI's unrelated slug validator.
    for name in [
        "harness_key",
        "base_head",
        "session_id",
        "herdr_session",
        "terminal_session",
    ] {
        let (exit, doc) = fixture.cli(&[
            "run",
            "dispatch",
            "--run",
            "run-0000000000000000",
            "--step",
            "p1",
            "--param",
            &format!("{name}=value"),
        ]);
        assert_eq!(exit, 4, "{name}: {doc:?}");
        assert_eq!(text(&doc, &["error", "code"]), "state.not_found");
    }
}

#[test]
fn f5_fresh_issuance_opens_live_and_expired_binding_windows() {
    let mut fixture = Fixture::new();
    fixture.preview(REV);
    let first = fixture.grant("1");
    let second = fixture.grant("3600");
    assert_ne!(text(&first, &["grant_id"]), text(&second, &["grant_id"]));
    fixture.restart();
    let expiry = text(&first, &["grant", "expires_at"]);
    let deadline = Instant::now() + Duration::from_secs(3);
    while canter::time::rfc3339_now().as_str() < expiry && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(canter::time::rfc3339_now().as_str() >= expiry);
    let third = fixture.grant("3600");
    assert_ne!(text(&first, &["grant_id"]), text(&third, &["grant_id"]));
    let listed = canter::client::call(
        &fixture.path("d.sock"),
        "grants.list",
        Some(&object(vec![])),
    )
    .unwrap();
    let grants = field(&listed, &["grants"]).as_array().unwrap();
    assert_eq!(grants.len(), 3);
    assert_eq!(
        grants
            .iter()
            .find(|g| text(g, &["grant_id"]) == text(&first, &["grant_id"]))
            .unwrap()
            .get("expires_at"),
        Some(&string(expiry))
    );
}

#[test]
fn cycle2_a_lapsed_window_renews_itself_for_the_same_run_without_an_operator_key() {
    let mut fixture = Fixture::new();
    let digest = fixture.preview(REV);
    let old = fixture.grant("4");
    let old_id = text(&old, &["grant_id"]).to_string();
    let submitted = fixture.submit(&digest, &old_id);
    let run = text(
        &field(&submitted, &["items"]).as_array().unwrap()[0],
        &["instance_id"],
    )
    .to_string();
    succeeded(&fixture.first(&run));
    let expiry = text(&old, &["grant", "expires_at"]);
    let deadline = Instant::now() + Duration::from_secs(6);
    while !canter::mutation::is_expired(expiry, &canter::time::rfc3339_now())
        && Instant::now() < deadline
    {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(canter::mutation::is_expired(
        expiry,
        &canter::time::rfc3339_now()
    ));
    // Issue #184: the lapsed frontier is dispatched by the RUN's own renewal
    // — no operator issuance and no operator retry key — and the SAME run
    // continues along its committed spine.
    succeeded(&fixture.ok(&["run", "dispatch", "--run", &run, "--step", "p2-5"]));
    fixture.restart();
    let journal =
        std::fs::read_to_string(fixture.path("state/canter/journal/audit.jsonl")).unwrap();
    let rotations: Vec<&str> = journal
        .lines()
        .filter(|line| line.contains("\"action\":\"grant.rotation\""))
        .collect();
    assert_eq!(
        rotations.len(),
        1,
        "exactly one renewal record: {rotations:?}"
    );
    eprintln!("RENEWAL_RECORD={}", rotations[0]);
    let record = Val::parse_json(rotations[0]).expect("renewal record");
    let target = text(&record, &["target"]).to_string();
    let rest = target
        .strip_prefix(&format!("run:{run}:superseded:{old_id}:replacement:"))
        .unwrap_or_else(|| panic!("both grants are named in the record: {target}"));
    let (replacement, rest) = rest
        .split_once(":expires:")
        .unwrap_or_else(|| panic!("the recorded expiry is named: {target}"));
    let (replacement_expiry, rest) = rest
        .split_once(":window_secs:")
        .unwrap_or_else(|| panic!("the derived window is named: {target}"));
    // The renewed window is SIZED FROM THE REMAINING COMMITTED SPINE, so it
    // covers the worker round trip the run still owes — and it is honest
    // about its instant.
    let window: i64 = rest.parse().expect("window seconds");
    assert!(
        window >= 1800,
        "the window covers the owed round trip: {window}"
    );
    assert_ne!(window, 7200, "never the fixed 2 h default");
    assert!(
        !canter::mutation::is_expired(replacement_expiry, &canter::time::rfc3339_now()),
        "the recorded expiry is live: {replacement_expiry}"
    );
    assert!(
        !journal.contains("mutate.run.retry"),
        "zero operator retry keys"
    );
    let status = fixture.ok(&["run", "status", "--run", &run]);
    let status_text = canonical_text(&status);
    assert!(
        status_text.contains(replacement),
        "the same run holds the replacement window: {status_text}"
    );
    assert!(
        !status_text.contains(&old_id),
        "the lapsed window is superseded: {status_text}"
    );
    // A fresh issuance for the same binding is refused: the run is live and
    // its own window is live too — the renewal restored real authorization,
    // it did not open a bypass.
    let new = fixture.grant("3600");
    assert_ne!(text(&new, &["grant_id"]), old_id);
    let replay = fixture.submit(&digest, text(&new, &["grant_id"]));
    assert_eq!(
        text(
            &field(&replay, &["items"]).as_array().unwrap()[0],
            &["status"]
        ),
        "refused",
        "an owned run with a live window is never re-bound: {replay:?}"
    );
}

#[test]
fn cycle2_live_grant_is_not_rotated_by_another_issuance() {
    let fixture = Fixture::new();
    let digest = fixture.preview(REV);
    let old = fixture.grant("3600");
    let submitted = fixture.submit(&digest, text(&old, &["grant_id"]));
    let run = text(
        &field(&submitted, &["items"]).as_array().unwrap()[0],
        &["instance_id"],
    );
    let new = fixture.grant("3600");
    let refused = fixture.submit(&digest, text(&new, &["grant_id"]));
    assert_eq!(
        text(
            &field(&refused, &["items"]).as_array().unwrap()[0],
            &["reason"]
        ),
        "submission.already_owned"
    );
    succeeded(&fixture.first(run));
    let status = fixture.ok(&["run", "status", "--run", run]);
    assert!(canonical_text(&status).contains(text(&old, &["grant_id"])));
    assert!(!canonical_text(&status).contains(text(&new, &["grant_id"])));
    let journal =
        std::fs::read_to_string(fixture.path("state/canter/journal/events.jsonl")).unwrap();
    assert!(!journal.contains("grant.rotation"));
}

#[test]
fn f4_a_later_window_never_invalidates_a_live_owner_and_an_older_one_stays_stale() {
    let fixture = Fixture::new();

    // The OLDER authorization window, minted first for the REV binding.
    fixture.preview(REV);
    let grant_a = fixture.grant("3600");

    // The owner: a run admitted at REV_B under the LATER window.
    let digest_b = fixture.preview(REV_B);
    let grant_b = fixture.grant("3600");
    let admitted_b = fixture.submit(&digest_b, text(&grant_b, &["grant_id"]));
    let owner = admitted_b.get("items").and_then(Val::as_array).unwrap()[0]
        .get("instance_id")
        .and_then(Val::as_str)
        .unwrap()
        .to_string();

    // A later window for the moved selection is rebindable — and only
    // rebindable (issue #209): it never invalidates the live owner. The item
    // is refused typed, naming the live run and its recorded frontier, and the
    // incumbent keeps its ownership and its own authorization window.
    let digest_a = fixture.preview(REV);
    let later = fixture.grant("3600");
    let rebound = fixture.submit(&digest_a, text(&later, &["grant_id"]));
    let rebound_item = &rebound.get("items").and_then(Val::as_array).unwrap()[0];
    assert_eq!(text(rebound_item, &["status"]), "refused");
    assert_eq!(text(rebound_item, &["reason"]), "submission.live_run");
    assert!(
        text(rebound_item, &["message"]).contains(&owner),
        "the refusal names the live owner: {rebound:?}"
    );
    let owner_status = fixture.ok(&["run", "status", "--run", &owner]);
    assert_eq!(
        text(&owner_status, &["run", "status"]),
        "new",
        "the incumbent is never invalidated by the submission (its own dispatch state is untouched)"
    );
    assert_eq!(
        text(&owner_status, &["run", "grant_id"]),
        text(&grant_b, &["grant_id"]),
        "the incumbent keeps its own authorization window"
    );

    // The FIRST window is not a LATER authorization than the owner's: the
    // moved selection stays stale and ownership never moves.
    let digest_a = fixture.preview(REV);
    let stale = fixture.submit(&digest_a, text(&grant_a, &["grant_id"]));
    let stale_item = &stale.get("items").and_then(Val::as_array).unwrap()[0];
    assert_eq!(text(stale_item, &["status"]), "refused");
    assert_eq!(text(stale_item, &["reason"]), "preview.revision_stale");
}

#[test]
fn f3_inputs_survive_restart_and_a_no_input_redispatch() {
    let mut fixture = Fixture::new();
    let run = fixture.run();
    succeeded(&fixture.first(&run));
    succeeded(&fixture.ok(&["run", "dispatch", "--run", &run, "--step", "p2-5"]));
    fixture.admission();
    succeeded(&fixture.ok(&[
        "run",
        "dispatch",
        "--run",
        &run,
        "--step",
        "p3",
        "--admission",
        fixture.path("admission.json").to_str().unwrap(),
    ]));
    // The effect really starts but the fixture adapter fails. Its addressed
    // payload is therefore durable attempt material, not a successful output.
    let (exit, failed) = fixture.cli(&[
        "run",
        "dispatch",
        "--run",
        &run,
        "--step",
        "p4-5",
        "--admission",
        fixture.path("admission.json").to_str().unwrap(),
        "--param",
        "payload=persist-me",
    ]);
    assert_ne!(exit, 0, "{failed:?}");
    assert_eq!(text(&failed, &["error", "code"]), "adapter.exit");
    fixture.write("allow-prompt", "ready\n");
    fixture.restart();
    fixture.ok(&["run", "retry", "--run", &run, "--step", "p4-5"]);
    let continued = fixture.ok(&["run", "dispatch", "--run", &run, "--step", "p4-5"]);
    succeeded(&continued);
    assert_eq!(
        text(&continued, &["step", "params", "payload"]),
        "persist-me"
    );
    assert!(fixture.path("trees/issues-5/.git").exists());
}

#[test]
fn f8_supported_surface_binds_reviewed_role_and_derived_session() {
    let mut fixture = Fixture::new();
    let run = fixture.run();
    succeeded(&fixture.first(&run));
    // The committed producer authored the branch/worktree contract; no raw
    // plan or topology is hand-built after the first documented dispatch.
    let created = fixture.ok(&["run", "dispatch", "--run", &run, "--step", "p2-5"]);
    succeeded(&created);
    fixture.admission();
    let started = fixture.ok(&[
        "run",
        "dispatch",
        "--run",
        &run,
        "--step",
        "p3",
        "--admission",
        fixture.path("admission.json").to_str().unwrap(),
    ]);
    succeeded(&started);
    assert_eq!(text(&started, &["step", "params", "harness_key"]), "worker");
    let expected = canter::mutation::run_session_handle(&run).unwrap();
    assert!(canonical_text(&started).contains(&expected.session_id));
    fixture.restart();
    fixture.admission();
    let prompted = fixture.ok(&[
        "run",
        "dispatch",
        "--run",
        &run,
        "--step",
        "p4-5",
        "--admission",
        fixture.path("admission.json").to_str().unwrap(),
    ]);
    succeeded(&prompted);
    assert!(
        text(&prompted, &["step", "params", "payload"]).contains("acme/widgets#5"),
        "the producer-authored prompt survives restart"
    );
    let argv = std::fs::read_to_string(fixture.path("trees/issues-5/prompt-argv")).unwrap();
    for required in [
        "worker",
        "provider-a",
        "model-a",
        &expected.session_id,
        "Implement acme/widgets#5",
    ] {
        assert!(argv.contains(required), "missing {required}: {argv}");
    }
}

#[test]
fn f9_collect_uses_recorded_base_and_requires_a_real_delta() {
    let fixture = Fixture::new();
    let run = fixture.run();
    let first = fixture.first(&run);
    let recorded_base = text(&first, &["dispatch", "integration_base"]).to_string();
    succeeded(&fixture.ok(&["run", "dispatch", "--run", &run, "--step", "p2-5"]));
    fixture.through_prompt(&run, "no-op worker", true);

    // Move the integration checkout after p1. Collection must retain p1's
    // recorded base rather than observing the clone's new branch head.
    fixture.write("repo/moved.txt", "new integration head\n");
    fixture.git(&["add", "moved.txt"]);
    fixture.git(&[
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.invalid",
        "commit",
        "-m",
        "move integration",
    ]);
    assert_ne!(fixture.git(&["rev-parse", "HEAD"]), recorded_base);

    let (exit, empty) = fixture.cli(&["run", "dispatch", "--run", &run, "--step", "p5-5"]);
    assert_eq!(exit, 4, "{empty:?}");
    assert_eq!(
        text(&empty, &["error", "code"]),
        "refusal.collect.empty_delta"
    );
    assert!(text(&empty, &["error", "message"]).contains(&recorded_base));

    fixture.write("trees/issues-5/change.txt", "worker delta\n");
    fixture.worktree_git(&["add", "change.txt"]);
    fixture.worktree_git(&[
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.invalid",
        "commit",
        "-m",
        "worker delta",
    ]);
    fixture.ok(&["run", "retry", "--run", &run, "--step", "p5-5"]);
    let collected = fixture.ok(&["run", "dispatch", "--run", &run, "--step", "p5-5"]);
    succeeded(&collected);
    assert_eq!(text(&collected, &["dispatch", "base_head"]), recorded_base);
    assert_eq!(
        field(&collected, &["dispatch", "changed_files"]),
        &Val::Arr(vec![string("change.txt")])
    );
}

#[test]
fn f9_explicit_no_delta_prompt_expectation_allows_a_no_op() {
    let fixture = Fixture::new();
    let run = fixture.run();
    let first = fixture.first(&run);
    let recorded_base = text(&first, &["dispatch", "integration_base"]).to_string();
    succeeded(&fixture.ok(&["run", "dispatch", "--run", &run, "--step", "p2-5"]));
    fixture.through_prompt(&run, "legitimate no-op", false);
    let collected = fixture.ok(&[
        "run",
        "dispatch",
        "--run",
        &run,
        "--step",
        "p5-5",
        "--param",
        "requires_delta=false",
    ]);
    succeeded(&collected);
    assert_eq!(text(&collected, &["dispatch", "base_head"]), recorded_base);
    assert_eq!(text(&collected, &["dispatch", "head"]), recorded_base);
    assert_eq!(
        field(&collected, &["dispatch", "requires_delta"]),
        &Val::Bool(false)
    );
}

#[test]
fn f9_collection_refuses_a_moved_worker_output_branch() {
    let fixture = Fixture::new();
    let run = fixture.run();
    fixture.first(&run);
    fixture.ok(&["run", "dispatch", "--run", &run, "--step", "p2-5"]);
    fixture.through_prompt(&run, "no-op", false);
    fixture.worktree_git(&["branch", "-m", "other-branch"]);
    let (exit, refused) = fixture.cli(&[
        "run",
        "dispatch",
        "--run",
        &run,
        "--step",
        "p5-5",
        "--param",
        "requires_delta=false",
    ]);
    assert_eq!(exit, 4, "{refused:?}");
    assert_eq!(
        text(&refused, &["error", "code"]),
        "refusal.worker.output_location"
    );
}

#[test]
fn f10_unresolved_prompt_stays_fenced_without_reexecuting_the_effect() {
    let fixture = Fixture::new();
    let run = fixture.failed_prompt();
    assert_eq!(fixture.prompt_invocations(), 1);

    let (exit, skipped) = fixture.cli(&[
        "run",
        "dispatch",
        "--run",
        &run,
        "--step",
        "p5-5",
        "--param",
        "requires_delta=false",
    ]);
    assert_eq!(exit, 4, "{skipped:?}");
    assert_eq!(text(&skipped, &["error", "code"]), "refusal.run.step_order");

    let (exit, repeated) = fixture.cli(&["run", "dispatch", "--run", &run, "--step", "p4-5"]);
    assert_eq!(exit, 4, "{repeated:?}");
    assert_eq!(
        text(&repeated, &["error", "code"]),
        "refusal.run.retry_required"
    );
    assert_eq!(
        fixture.prompt_invocations(),
        1,
        "the prompt effect ran once"
    );
}

#[test]
fn f10_resolution_advances_without_reexecuting_the_prompt_effect() {
    let fixture = Fixture::new();
    let run = fixture.failed_prompt();
    let feature_head = fixture.worktree_git(&["rev-parse", "HEAD"]);
    fixture.write(
        "resolution.json",
        &canonical_text(&object(vec![
            ("feature_head", string(&feature_head)),
            ("branch", string("issue-5")),
            (
                "pull_request",
                object(vec![
                    ("repository", string("acme/widgets")),
                    ("number", integer(131)),
                ]),
            ),
            (
                "checks",
                Val::Arr(vec![object(vec![
                    ("name", string("focused")),
                    ("status", string("passed")),
                ])]),
            ),
        ])),
    );

    let resolved = fixture.ok(&[
        "run",
        "resolve",
        "--run",
        &run,
        "--step",
        "p4-5",
        "--recorder",
        "operator",
        "--evidence",
        fixture.path("resolution.json").to_str().unwrap(),
    ]);
    assert_eq!(text(&resolved, &["schema"]), "hf-run-resolution/v1");
    assert_eq!(
        field(&resolved, &["resolution", "effect_reexecuted"]),
        &Val::Bool(false)
    );
    assert_eq!(text(&resolved, &["resolution", "prior_status"]), "failed");

    let collected = fixture.ok(&[
        "run",
        "dispatch",
        "--run",
        &run,
        "--step",
        "p5-5",
        "--param",
        "requires_delta=false",
    ]);
    succeeded(&collected);
    assert_eq!(fixture.prompt_invocations(), 1, "resolution is data-only");
    let status = fixture.ok(&["run", "status", "--run", &run]);
    assert_eq!(field(&status, &["boundary", "in_flight_step"]), &Val::Null);
}
