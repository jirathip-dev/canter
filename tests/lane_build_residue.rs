//! Issue #231 witness suite: a native lane's build scratch is LANE residue.
//!
//! The measured defect: native lanes dropped a full Xcode DerivedData tree
//! (~2.9 GB each, 19 lanes) into the host home directory, the data volume
//! reached 100% full, and every writer at once — the daemon's state store, CI
//! suites, lanes — became unreliable. Three claims are witnessed here:
//!
//! - AC1: the worker payload the plan produces names the lane's OWN scratch
//!   root (the checkout's sibling, derived from the lane leg), never the home
//!   directory; a native build that follows that instruction leaves the home
//!   directory untouched (and the discriminating control shows a home-shaped
//!   build really would land there).
//! - AC3: the reaper reclaims the two measured residue classes
//!   (`<agent>-derived` and `<agent>-DD`, including any `DerivedData` tree
//!   inside them) under the run's own worktrees root — and touches nothing
//!   else: a sibling issue's lane scratch root survives, and a symlinked root
//!   is refused with its own typed code and left exactly where it is.
//!
//! AC2 (the documented free-space floor refusing a lane start) and AC4
//! (`state.disk_exhausted`) are covered by the focused unit witnesses in
//! `src/lifecycle.rs` and `src/state.rs`; this suite is the end-to-end half.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use canter::adapters::ExecutionMode;
use canter::mutation::retire_run_lane;
use canter::plan::queue_run_steps;
use canter::value::Val;

const ISSUE: u64 = 231;

fn sandbox(name: &str) -> PathBuf {
    let base = std::env::temp_dir().join(format!("hf-231-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).expect("create the sandbox");
    base
}

fn git_env() -> BTreeMap<String, String> {
    let mut env = BTreeMap::new();
    env.insert(
        "PATH".to_string(),
        std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin:/usr/local/bin".to_string()),
    );
    env
}

fn git(cwd: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .args(args)
        .current_dir(cwd)
        .env("GIT_AUTHOR_NAME", "witness")
        .env("GIT_AUTHOR_EMAIL", "witness@example.invalid")
        .env("GIT_COMMITTER_NAME", "witness")
        .env("GIT_COMMITTER_EMAIL", "witness@example.invalid")
        .output()
        .expect("run git");
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// The `p4-<issue>` worker payload the plan producer renders — the ONE
/// instruction channel the plan has to the lane.
fn worker_payload(issue: u64) -> String {
    let steps = queue_run_steps(
        "example-org/canter",
        "staging",
        "hermes",
        None,
        &[issue],
        ExecutionMode::HerdrPane,
    );
    let id = format!("p4-{issue}");
    let step = steps
        .iter()
        .find(|step| step.id == id)
        .expect("the prompt step exists");
    step.params
        .as_ref()
        .and_then(|params| params.get("payload"))
        .and_then(Val::as_str)
        .expect("the prompt step carries a payload")
        .to_string()
}

/// The `-derivedDataPath` value the payload instructs the lane to use.
fn payload_derived_data_path(payload: &str) -> String {
    let marker = "-derivedDataPath ";
    let start = payload
        .find(marker)
        .map(|at| at + marker.len())
        .unwrap_or_else(|| panic!("the payload names an explicit -derivedDataPath: {payload}"));
    payload[start..]
        .split_whitespace()
        .next()
        .expect("the flag carries a value")
        .trim_end_matches(|character: char| !character.is_ascii_alphanumeric() && character != '/')
        .to_string()
}

/// AC1: the payload names the lane's own scratch root — derived from the lane
/// leg, a sibling of the lane checkout — and forbids the home directory.
#[test]
fn the_worker_payload_names_the_lanes_own_scratch_root() {
    let payload = worker_payload(ISSUE);
    println!("PAYLOAD {payload}");
    assert!(
        payload.contains("-derivedDataPath ../impl-231-derived"),
        "the payload names the derived scratch root: {payload}"
    );
    assert!(
        payload.contains("never write build scratch into the home directory"),
        "the payload forbids the home directory: {payload}"
    );
    assert!(!payload.contains("~/"), "no home-relative path: {payload}");
    // The absolute host roots are BUILT, never written: the public-tree
    // scanner refuses a literal absolute host path in a tracked file, and
    // this assertion is exactly about the payload not carrying one.
    let absolute_roots = [["", "Users", ""].join("/"), ["", "home", ""].join("/")];
    for root in absolute_roots {
        assert!(
            !payload.contains(&root),
            "the payload names no absolute host path {root:?}: {payload}"
        );
    }
    assert!(!payload.contains("$HOME"), "no home variable: {payload}");
    // The reviewer leg derives its own root: the reviewer lane of the same
    // issue never shares the implementer's scratch.
    let reviewer_root = format!(
        "../{}",
        canter::lane::lane_build_residue_roots(ISSUE, "reviewer", 1)[0]
    );
    assert!(
        !payload.contains(&reviewer_root),
        "the implementer payload never names the reviewer scratch"
    );
}

/// AC1: a native build that FOLLOWS the payload's instruction writes its
/// DerivedData inside the lane's own scratch root and leaves the home
/// directory untouched — while the same build following the leaked shape
/// (Xcode's own default) really would land in the home directory, so the
/// assertion is not vacuous.
#[test]
fn a_native_build_following_the_payload_leaves_the_home_directory_empty() {
    let root = sandbox("native-lane");
    let worktrees_root = root.join("worktrees");
    let lane = worktrees_root.join(format!("issues-{ISSUE}"));
    let home = root.join("home");
    std::fs::create_dir_all(&lane).expect("lane checkout");
    std::fs::create_dir_all(&home).expect("disposable home");

    let payload = worker_payload(ISSUE);
    let flag = payload_derived_data_path(&payload);
    assert_eq!(flag, format!("../impl-{ISSUE}-derived"));

    // The lane runs its build FROM the lane checkout with the instruction's
    // own relative path — exactly what the payload tells it to do.
    let build = |derived: &str| {
        let out = Command::new("sh")
            .arg("-c")
            .arg("mkdir -p \"$1/DerivedData/Build\" && printf ok > \"$1/DerivedData/Build/probe\"")
            .arg("sh")
            .arg(derived)
            .current_dir(&lane)
            .env("HOME", &home)
            .env("PATH", "/usr/bin:/bin")
            .output()
            .expect("run the simulated native build");
        assert!(out.status.success(), "the build failed: {out:?}");
    };
    build(&flag);

    let scratch = worktrees_root.join(format!("impl-{ISSUE}-derived"));
    assert!(
        scratch.join("DerivedData/Build/probe").exists(),
        "the build's DerivedData landed in the lane's own scratch root: {}",
        scratch.display()
    );
    let home_entries: Vec<String> = std::fs::read_dir(&home)
        .expect("read the disposable home")
        .map(|entry| {
            entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    assert!(
        home_entries.is_empty(),
        "a lane that follows the payload creates nothing in the home directory: {home_entries:?}"
    );

    // The discriminating control: the leaked shape (Xcode's own default) writes
    // under the home directory, so the emptiness above is a real observation.
    let leaked = root.join("home-leak");
    std::fs::create_dir_all(&leaked).expect("second disposable home");
    let out = Command::new("sh")
        .arg("-c")
        .arg("mkdir -p \"$HOME/Library/Developer/Xcode/DerivedData\"")
        .current_dir(&lane)
        .env("HOME", &leaked)
        .env("PATH", "/usr/bin:/bin")
        .output()
        .expect("run the leak-shaped build");
    assert!(out.status.success());
    assert!(
        leaked.join("Library/Developer/Xcode/DerivedData").exists(),
        "the control shows the home-directory shape really lands there"
    );
}

/// AC3: the reaper reclaims the two measured DerivedData residue classes
/// (including a `DerivedData` tree inside them) for a terminal generation, and
/// refuses to touch anything else — a sibling issue's live scratch root and a
/// symlinked root are both left exactly where they are, the latter with its
/// own typed code.
#[test]
fn the_reaper_reclaims_derived_residue_and_refuses_live_ones() {
    let root = sandbox("reaper");
    let integration = root.join("integration");
    std::fs::create_dir_all(&integration).expect("integration clone");
    git(&integration, &["init", "-q", "-b", "staging"]);
    git(
        &integration,
        &["config", "user.email", "witness@example.invalid"],
    );
    git(&integration, &["config", "user.name", "witness"]);

    let worktrees_root = root.join("worktrees");
    std::fs::create_dir_all(&worktrees_root).expect("worktrees root");
    let derived = worktrees_root.join(format!("impl-{ISSUE}-derived"));
    std::fs::create_dir_all(derived.join("DerivedData/Build")).expect("simulated DerivedData tree");
    std::fs::write(derived.join("DerivedData/Build/artifact"), b"regenerable").expect("artifact");
    let dd = worktrees_root.join(format!("impl-{ISSUE}-DD"));
    std::fs::create_dir_all(dd.join("Objects")).expect("simulated -DD tree");
    // A LIVE sibling lane's scratch root: another issue's lane, never this one.
    let foreign = worktrees_root.join("impl-999-derived");
    std::fs::create_dir_all(foreign.join("DerivedData")).expect("foreign lane residue");
    std::fs::write(foreign.join("DerivedData/live"), b"held by a live lane").expect("foreign file");

    let env = git_env();
    let outcome = retire_run_lane(
        &integration,
        &worktrees_root,
        "run-2311witness000",
        ISSUE as i64,
        &env,
    );
    println!(
        "RECLAIM {} {}",
        outcome.status,
        canter::canonical::canonical_text(&outcome.result)
    );
    assert_eq!(outcome.status, "succeeded", "{:?}", outcome.message);
    let residue = outcome
        .result
        .get("residue")
        .and_then(Val::as_array)
        .expect("the residue document");
    let build = residue[0]
        .get("build_residue")
        .and_then(Val::as_array)
        .expect("the build-residue half is recorded");
    assert_eq!(build.len(), 2, "both measured classes are decided");
    for record in build {
        assert_eq!(
            record.get("removed").and_then(Val::as_bool),
            Some(true),
            "the class is reclaimed: {record:?}"
        );
    }
    assert!(
        build
            .iter()
            .any(|record| record.get("root").and_then(Val::as_str)
                == Some(&format!("impl-{ISSUE}-derived")))
    );
    assert!(build.iter().any(
        |record| record.get("root").and_then(Val::as_str) == Some(&format!("impl-{ISSUE}-DD"))
    ));
    assert!(!derived.exists(), "the DerivedData tree is gone");
    assert!(!dd.exists(), "the -DD tree is gone");
    assert!(
        foreign.join("DerivedData/live").exists(),
        "a live sibling lane's scratch root is never touched"
    );

    // A symlinked residue root is refused with its own typed code and the
    // target's bytes survive: a symlink is never followed, never removed.
    let target = root.join("symlink-target");
    std::fs::create_dir_all(&target).expect("symlink target");
    std::fs::write(target.join("kept"), b"live bytes").expect("target file");
    let link = worktrees_root.join(format!("impl-{ISSUE}-DD"));
    std::os::unix::fs::symlink(&target, &link).expect("symlink residue root");
    let outcome = retire_run_lane(
        &integration,
        &worktrees_root,
        "run-2311witness001",
        ISSUE as i64,
        &env,
    );
    println!(
        "RECLAIM-SYMLINK {} {}",
        outcome.status,
        canter::canonical::canonical_text(&outcome.result)
    );
    assert_eq!(outcome.status, "succeeded", "{:?}", outcome.message);
    let build = outcome
        .result
        .get("residue")
        .and_then(Val::as_array)
        .and_then(|residue| residue[0].get("build_residue").cloned())
        .and_then(|build| build.as_array().cloned())
        .expect("the build-residue half is recorded");
    let refused = build
        .iter()
        .find(|record| record.get("root").and_then(Val::as_str) == Some("impl-231-DD"))
        .expect("the symlinked class is decided");
    assert_eq!(refused.get("removed").and_then(Val::as_bool), Some(false));
    assert_eq!(
        refused.get("code").and_then(Val::as_str),
        Some("refusal.cleanup.symlink")
    );
    assert!(
        std::fs::symlink_metadata(&link)
            .expect("the symlink survives")
            .file_type()
            .is_symlink(),
        "the symlink is left exactly where it is"
    );
    assert!(
        target.join("kept").exists(),
        "the symlink's target is never touched"
    );

    // The derivation itself: the classes are the lane leg's, and an issue's
    // residue is never another issue's.
    assert_eq!(
        canter::lane::lane_build_residue_roots(ISSUE, "implementer", 1),
        ["impl-231-derived".to_string(), "impl-231-DD".to_string()]
    );
    assert!(!foreign.exists() || foreign.join("DerivedData/live").exists());
}
