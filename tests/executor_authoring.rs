//! Isolated supported-surface executor proofs. No live services or direct DB writes.
use canter::canonical::canonical_text;
use canter::value::{Val, integer, object, string};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

static NEXT: AtomicUsize = AtomicUsize::new(0);
const REV: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const REV_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

struct Fixture {
    root: PathBuf,
    daemon: Option<Child>,
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
            "#!/bin/sh\ncase \"$*\" in\n  *persist-me*) test -f \"$HOME/allow-prompt\" || exit 9 ;;\nesac\nprintf '%s\\n' \"$@\" > prompt-argv\nprintf 'fixture output\\n'\n",
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
                (
                    "worktrees_root",
                    string(worktrees_root.to_str().unwrap()),
                ),
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
            child.kill().expect("stop own daemon");
            child.wait().expect("reap own daemon");
        }
    }
    fn restart(&mut self) {
        self.stop();
        self.daemon = Some(
            self.command()
                .args(["daemon", "run", "--socket"])
                .arg(self.path("d.sock"))
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
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
    fn preview(&self, revision: &str) -> String {
        self.ok(&[
            "queue",
            "preview",
            "--repository",
            "widgets",
            "--harness",
            "worker",
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
fn f4_later_authorization_rebinds_revision_but_older_window_is_stale() {
    let fixture = Fixture::new();

    let digest_a = fixture.preview(REV);
    let grant_a = fixture.grant("3600");
    let admitted_a = fixture.submit(&digest_a, text(&grant_a, &["grant_id"]));
    let old_run = admitted_a
        .get("items")
        .and_then(Val::as_array)
        .unwrap()[0]
        .get("instance_id")
        .and_then(Val::as_str)
        .unwrap()
        .to_string();

    // B has a distinct binding and a later grant window than A's owner. It
    // can therefore rebind ownership without depending on grant renewal.
    let digest_b = fixture.preview(REV_B);
    let grant_b = fixture.grant("3600");
    let rebound = fixture.submit(&digest_b, text(&grant_b, &["grant_id"]));
    let rebound_item = &rebound.get("items").and_then(Val::as_array).unwrap()[0];
    assert_eq!(text(rebound_item, &["status"]), "admitted");
    let new_run = text(rebound_item, &["instance_id"]);
    assert_ne!(new_run, old_run);
    let old_status = fixture.ok(&["run", "status", "--run", &old_run]);
    assert_eq!(text(&old_status, &["run", "status"]), "invalidated");

    // A's older authorization cannot move ownership back after B was bound.
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
    assert_eq!(text(&continued, &["step", "params", "payload"]), "persist-me");
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
    let (exit, refusal) = fixture.cli(&["run", "dispatch", "--run", &run, "--step", "p4-5"]);
    assert_eq!(exit, 4);
    assert!(text(&refusal, &["error", "message"]).contains("payload"));
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
        "--param",
        "payload=bounded fixture work",
    ]);
    succeeded(&prompted);
    let argv =
        std::fs::read_to_string(fixture.path("trees/issues-5/prompt-argv")).unwrap();
    for required in [
        "worker",
        "provider-a",
        "model-a",
        &expected.session_id,
        "bounded fixture work",
    ] {
        assert!(argv.contains(required), "missing {required}: {argv}");
    }
}
