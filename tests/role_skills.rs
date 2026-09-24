//! Issue #267 acceptance tests: the plan declares, per leg, the role skills a
//! lane is given; the role→skill binding is configuration whose resolution
//! rides the plan digest; an unresolvable skill refuses typed and creates no
//! lane; the committed role procedures state the rules the engine enforces,
//! and no worker lane receives — or needs — the control plane.
//!
//! Every test drives the REAL compiled binary (`CARGO_BIN_EXE_canter`) for the
//! plan surfaces, so the raw plan JSON, the digests and the typed refusals are
//! the process's own output. Fixture discipline: synthetic identities only
//! (`example-org/widgets`, `host-1`, `lane-1`/`lane-2`), all state under a
//! per-test temp directory, no daemon spawn and no harness process: the
//! preview refuses or plans, it never executes.

use std::path::{Path, PathBuf};
use std::process::Command;

use canter::config::{ADAPTER_ENV_ALLOW, ProfileBinding, adapter_environment, load_config};
use canter::state::{Retention, State};
use canter::value::Val;

const REPO: &str = "example-org/widgets";
const HARNESS: &str = "lane-1";
const REVIEWER_HARNESS: &str = "lane-2";
const REVISION: &str = "1111111111111111111111111111111111111111";
const IMPL_HASH: &str = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
const REV_HASH: &str = "b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2";
const EXTRA_HASH: &str = "c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3";

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_canter")
}

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

struct Fixture {
    dir: PathBuf,
    state_dir: PathBuf,
    socket: PathBuf,
    config_path: PathBuf,
}

impl Fixture {
    /// One fixture whose harness rows declare `impl_skills` / `rev_skills` and
    /// whose `skill.<key>` inventory declares exactly `inventory`.
    fn new(
        name: &str,
        impl_skills: &[&str],
        rev_skills: &[&str],
        inventory: &[(&str, &str)],
    ) -> Fixture {
        let dir =
            std::env::temp_dir().join(format!("hf-role-skills-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("fixture dir");
        let fixture = Fixture {
            state_dir: dir.join("state"),
            socket: dir.join("daemon.sock"),
            config_path: dir.join("config.toml"),
            dir,
        };
        let declarations = |key: &str, skills: &[&str]| -> String {
            if skills.is_empty() {
                format!(
                    "[harness.{key}]\nkind = \"pi\"\nexecutable = \"herdr\"\nenv_allow = []\nprovider = \"provider-a\"\nmodel = \"model-a\"\nbinding_introspection = false\n\n"
                )
            } else {
                format!(
                    "[harness.{key}]\nkind = \"pi\"\nexecutable = \"herdr\"\nenv_allow = []\nprovider = \"provider-a\"\nmodel = \"model-a\"\nbinding_introspection = false\nskills = [{}]\n\n",
                    skills
                        .iter()
                        .map(|skill| format!("\"{skill}\""))
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            }
        };
        let stock: String = inventory
            .iter()
            .map(|(key, hash)| format!("[skill.{key}]\nhash = \"{hash}\"\n\n"))
            .collect();
        std::fs::write(
            &fixture.config_path,
            format!(
                "schema = \"hf-config/v1\"\n\n[daemon]\nenabled = true\nsocket = \"{}\"\n\n[repository.widgets]\norigin = \"https://example.invalid/{REPO}\"\nbranch = \"staging\"\n\n{}{}{}",
                fixture.socket.display(),
                declarations(HARNESS, impl_skills),
                declarations(REVIEWER_HARNESS, rev_skills),
                stock,
            ),
        )
        .expect("write config");
        fixture
    }

    fn config(&self) -> String {
        self.config_path
            .to_str()
            .expect("utf-8 config path")
            .to_string()
    }

    fn plan_path(&self) -> PathBuf {
        self.dir.join("plan.json")
    }

    fn db(&self) -> PathBuf {
        self.state_dir.join("canter").join("state.db")
    }

    fn seed(&self) -> State {
        std::fs::create_dir_all(self.state_dir.join("canter")).expect("state dir");
        State::open(&self.db(), Retention::default()).expect("open state")
    }

    /// One `queue preview` invocation over the fixture (the reviewer leg is
    /// always declared, so `legs` carries both roles).
    fn preview(&self) -> (i32, String, String) {
        let out = self.plan_path();
        let args: Vec<String> = [
            "queue",
            "preview",
            "--config",
            &self.config(),
            "--repository",
            "widgets",
            "--harness",
            HARNESS,
            "--reviewer-harness",
            REVIEWER_HARNESS,
            "--host",
            "host-1",
            "--host-available",
            "yes",
            "--harness-lanes",
            "0",
            "--caps",
            "4/2/2",
            "--issue",
            &format!("5={REVISION}"),
            "--out",
            out.to_str().expect("utf-8 out path"),
            "--json",
        ]
        .iter()
        .map(|value| value.to_string())
        .collect();
        self.cli(&args)
    }

    fn cli(&self, args: &[String]) -> (i32, String, String) {
        let output = Command::new(bin())
            .args(args)
            .env("XDG_STATE_HOME", &self.state_dir)
            .env("HOME", &self.dir)
            .output()
            .expect("run cli");
        (
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stdout).into_owned(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        )
    }
}

fn envelope(output: &str) -> Val {
    let doc = Val::parse_json(output.trim_end()).expect("one JSON envelope");
    assert_eq!(
        doc.get("schema").and_then(Val::as_str),
        Some("hf-output/v1"),
        "the CLI answers in the documented envelope"
    );
    doc
}

/// The `data` object of one CLI envelope.
fn data(output: &str) -> Val {
    envelope(output).get("data").cloned().expect("data")
}

/// The skill NAMES of one leg entry of a plan document's `legs` array.
fn leg_skills(plan: &Val, role: &str) -> Vec<String> {
    for leg in plan
        .get("legs")
        .and_then(Val::as_array)
        .expect("the plan declares its legs")
    {
        if leg.get("role").and_then(Val::as_str) == Some(role) {
            return leg
                .get("skills")
                .and_then(Val::as_array)
                .expect("skills")
                .iter()
                .map(|skill| skill.as_str().expect("skill name").to_string())
                .collect();
        }
    }
    panic!("no {role} leg in the plan");
}

// ---------------------------------------------------------------------------
// AC1 + AC3: the plan names, per leg, the role skills — and the binding rides
// the digest
// ---------------------------------------------------------------------------

#[test]
fn the_plan_names_per_leg_the_role_skills_and_the_binding_rides_the_digest() {
    let fixture = Fixture::new(
        "named",
        &["lane-impl"],
        &["lane-rev"],
        &[("lane-impl", IMPL_HASH), ("lane-rev", REV_HASH)],
    );
    let _state = fixture.seed();
    let (exit, stdout, stderr) = fixture.preview();
    assert_eq!(exit, 0, "preview refuses: {stdout}{stderr}");
    let first = data(&stdout);
    let digest = first
        .get("digest")
        .and_then(Val::as_str)
        .expect("digest")
        .to_string();

    // AC1 witness: the RAW plan JSON the process wrote names, per leg, the
    // role skills — the implementer leg's on the run's reviewed role binding,
    // the reviewer leg's on the registry-resolved binding its review step
    // declares.
    let raw = std::fs::read_to_string(fixture.plan_path()).expect("the plan was written");
    assert!(
        raw.contains("\"skills\":[\"lane-impl\"]"),
        "the raw plan names the implementer leg's skills: {raw}"
    );
    assert!(
        raw.contains("\"skills\":[\"lane-rev\"]"),
        "the raw plan names the reviewer leg's skills: {raw}"
    );
    assert!(
        raw.contains(&format!("\"hash\":\"{IMPL_HASH}\"")),
        "the implementer leg's binding resolves the declared content identity: {raw}"
    );
    let plan = first.get("request").cloned().expect("request");
    assert_eq!(
        leg_skills(&plan, "implementer"),
        vec!["lane-impl".to_string()],
        "the plan's implementer legs are given the declared skill"
    );
    assert_eq!(
        leg_skills(&plan, "reviewer"),
        vec!["lane-rev".to_string()],
        "the plan's reviewer leg is given the declared skill"
    );
    // The role binding itself names the resolved pins (key + content
    // identity), so the digest binds the procedure, not just a name.
    let role_skills = plan
        .get("role_config")
        .and_then(|role| role.get("skills"))
        .and_then(Val::as_array)
        .expect("role_config.skills");
    assert_eq!(role_skills.len(), 1);
    assert_eq!(
        role_skills[0].get("key").and_then(Val::as_str),
        Some("lane-impl")
    );
    assert_eq!(
        role_skills[0].get("hash").and_then(Val::as_str),
        Some(IMPL_HASH)
    );

    // Determinism: unchanged inputs render one unchanged digest.
    let (again_exit, again_stdout, _) = fixture.preview();
    assert_eq!(again_exit, 0);
    assert_eq!(
        data(&again_stdout)
            .get("digest")
            .and_then(Val::as_str)
            .expect("digest"),
        digest,
        "unchanged configuration and selection render the same plan digest"
    );

    // AC3 witness: changing the role→skill binding (one more declared skill,
    // resolved by the inventory) moves the plan digest — the binding is
    // certifiable, not an accident of profile contents.
    let changed = Fixture::new(
        "named-changed",
        &["lane-impl", "lane-extra"],
        &["lane-rev"],
        &[
            ("lane-impl", IMPL_HASH),
            ("lane-rev", REV_HASH),
            ("lane-extra", EXTRA_HASH),
        ],
    );
    let _ = changed.seed();
    let (changed_exit, changed_stdout, changed_stderr) = changed.preview();
    assert_eq!(
        changed_exit, 0,
        "the changed binding previews: {changed_stdout}{changed_stderr}"
    );
    let moved = data(&changed_stdout)
        .get("digest")
        .and_then(Val::as_str)
        .expect("digest")
        .to_string();
    assert_ne!(
        digest, moved,
        "the role→skill binding is bound by the digest"
    );
    assert_eq!(moved.len(), 64);
}

// ---------------------------------------------------------------------------
// AC2: an unresolvable skill refuses typed and creates no lane
// ---------------------------------------------------------------------------

#[test]
fn an_unresolvable_role_skill_refuses_typed_and_creates_no_lane() {
    // The implementer role binding declares a skill the configuration's
    // inventory does not resolve: there is no plan to review.
    let fixture = Fixture::new(
        "impl-unresolved",
        &["lane-impl"],
        &[],
        &[("lane-rev", REV_HASH)],
    );
    let state = fixture.seed();
    let (exit, stdout, stderr) = fixture.preview();
    let output = format!("{stdout}{stderr}");
    assert_eq!(exit, 4, "a refusal exits 4: {output}");
    assert!(
        output.contains("refusal.skill.unresolved"),
        "the refusal is typed: {output}"
    );
    assert!(
        output.contains("lane-impl"),
        "the refusal names the unresolvable skill: {output}"
    );
    // Absence is witnessed, not assumed: no bound-input document was written
    // and no run, worktree or lane exists anywhere in the fixture.
    assert!(
        !fixture.plan_path().exists(),
        "a refused plan is never written"
    );
    assert!(
        state.list_instances().expect("instances").is_empty(),
        "a refused plan creates no run"
    );
    assert!(
        !fixture.dir.join("worktrees").exists(),
        "a refused plan creates no worktree"
    );
    assert!(
        !fixture.dir.join("lanes").exists(),
        "a refused plan creates no lane"
    );

    // The reviewer leg resolves through the SAME rule: one unresolvable
    // reviewer skill refuses the plan before the run's own reviewer could be
    // dispatched.
    let reviewer = Fixture::new(
        "rev-unresolved",
        &["lane-impl"],
        &["lane-rev"],
        &[("lane-impl", IMPL_HASH)],
    );
    let _ = reviewer.seed();
    let (exit, stdout, stderr) = reviewer.preview();
    let output = format!("{stdout}{stderr}");
    assert_eq!(exit, 4, "the reviewer binding refuses the plan: {output}");
    assert!(
        output.contains("refusal.skill.unresolved") && output.contains("lane-rev"),
        "the refusal names the reviewer skill: {output}"
    );
    assert!(!reviewer.plan_path().exists());
}

#[test]
fn the_role_skill_resolution_is_fail_closed_at_the_binding_boundary() {
    // The library boundary the CLI uses: one unresolvable key refuses the
    // whole binding (never a partial set, never a silent skip).
    let fixture = Fixture::new(
        "resolve",
        &["lane-impl", "lane-ghost"],
        &[],
        &[("lane-impl", IMPL_HASH)],
    );
    let config = load_config(Path::new(&fixture.config_path)).expect("config loads");
    let harness = config
        .harnesses
        .iter()
        .find(|harness| harness.key == HARNESS)
        .expect("harness");
    let err = canter::config::resolve_role_skills(&config, &harness.skills, &harness.key)
        .expect_err("the unresolvable skill refuses");
    assert_eq!(err.code(), "refusal.skill.unresolved");
    assert_eq!(err.code(), canter::config::CODE_SKILL_UNRESOLVED);
    let err = ProfileBinding::from_config(&config, HARNESS, &Default::default())
        .expect_err("the binding refuses");
    assert_eq!(err.code(), "refusal.skill.unresolved");
}

// ---------------------------------------------------------------------------
// R4: a repository unrelated to canter is never required to carry a
// canter-named skill
// ---------------------------------------------------------------------------

#[test]
fn an_unrelated_repository_resolves_its_own_skill_names() {
    let fixture = Fixture::new(
        "unrelated",
        &["widgets-lane-impl"],
        &["widgets-lane-rev"],
        &[
            ("widgets-lane-impl", IMPL_HASH),
            ("widgets-lane-rev", REV_HASH),
        ],
    );
    let _state = fixture.seed();
    let (exit, stdout, stderr) = fixture.preview();
    assert_eq!(exit, 0, "the plan previews: {stdout}{stderr}");
    let plan = data(&stdout).get("request").cloned().expect("request");
    for role in ["implementer", "reviewer"] {
        let skills = leg_skills(&plan, role);
        assert_eq!(skills.len(), 1);
        assert!(
            !skills[0].to_lowercase().contains("canter"),
            "no canter-named skill is required of this repository's lanes: {skills:?}"
        );
    }
    let raw = std::fs::read_to_string(fixture.plan_path()).expect("plan written");
    assert!(
        raw.contains("widgets-lane-impl") && raw.contains("widgets-lane-rev"),
        "the plan carries the repository's own skill names: {raw}"
    );
}

// ---------------------------------------------------------------------------
// AC4: the reviewer procedure states the rule the engine already enforces
// ---------------------------------------------------------------------------

/// The committed reviewer procedure states the certified-head rule, and the
/// refusal it names is the one the engine emits for a stale verdict. The
/// engine's witness for the refusal itself is the recorded review-dispatch
/// acceptance test
/// `a_commit_landing_while_the_review_is_open_forces_re_entry_not_consumption`
/// (`tests/review_dispatch.rs`), which consumes a verdict naming a head the
/// delivery has left and observes `refusal.evidence.verdict_stale`.
#[test]
fn the_reviewer_procedure_states_the_certified_head_rule_the_engine_enforces() {
    let text = std::fs::read_to_string(manifest_dir().join("skills/lane-reviewer/SKILL.md"))
        .expect("the reviewer procedure is committed");
    assert!(
        text.contains("certified head"),
        "the procedure states the certified-head rule"
    );
    assert!(
        text.contains("refusal.evidence.verdict_stale"),
        "the procedure names the engine's own stale-verdict refusal"
    );
    assert!(
        text.contains("refusal.evidence.reviewer_not_distinct")
            && text.contains("refusal.evidence.reviewer_unbound"),
        "the procedure states the no-self-approval rule and its typed refusals"
    );
    // Parity: the code the procedure names is the code the engine emits.
    assert_eq!(
        canter::mutation::code::VERDICT_STALE,
        "refusal.evidence.verdict_stale"
    );
    assert_eq!(
        canter::mutation::code::REVIEWER_NOT_DISTINCT,
        "refusal.evidence.reviewer_not_distinct"
    );
    assert_eq!(
        canter::mutation::code::REVIEWER_UNBOUND,
        "refusal.evidence.reviewer_unbound"
    );

    // The three role procedures are committed as installable sources.
    for (path, marker) in [
        ("skills/lane-implementer/SKILL.md", "Push the branch"),
        (
            "skills/lane-reviewer/SKILL.md",
            "Review the exact certified head",
        ),
        ("skills/lane-orchestrator/SKILL.md", "Typed operations only"),
    ] {
        let text = std::fs::read_to_string(manifest_dir().join(path))
            .unwrap_or_else(|err| panic!("{path} must be committed: {err}"));
        assert!(text.contains(marker), "{path} states its role contract");
    }
}

// ---------------------------------------------------------------------------
// AC5: no worker lane receives, or is required to use, the control plane
// ---------------------------------------------------------------------------

#[test]
fn no_worker_lane_receives_the_control_plane_socket_or_needs_it() {
    // The adapter environment is the CLOSED allowlist: a lane subprocess
    // inherits exactly these names, so no socket path (or any other host
    // variable) can ride into a worker lane.
    assert_eq!(
        ADAPTER_ENV_ALLOW,
        [
            "PATH",
            "HOME",
            "LANG",
            "LC_ALL",
            "XDG_CONFIG_HOME",
            "TMPDIR"
        ]
    );
    for (name, value) in adapter_environment() {
        assert!(
            ADAPTER_ENV_ALLOW.contains(&name.as_str()),
            "the adapter environment carries only allowlisted names, got {name:?}"
        );
        assert!(
            !name.to_lowercase().contains("canter") && !value.contains("canter.sock"),
            "no control-plane socket rides the lane environment: {name}"
        );
    }
    // The worker procedures themselves never require the control plane.
    for path in [
        "skills/lane-implementer/SKILL.md",
        "skills/lane-reviewer/SKILL.md",
    ] {
        let text = std::fs::read_to_string(manifest_dir().join(path))
            .unwrap_or_else(|err| panic!("{path} must be committed: {err}"));
        assert!(
            text.contains("Never touch the control plane"),
            "{path} states the worker's control-plane rule"
        );
        assert!(
            !text.contains("--socket") && !text.contains("canter.sock"),
            "{path} never asks a worker for the control plane"
        );
    }
}
