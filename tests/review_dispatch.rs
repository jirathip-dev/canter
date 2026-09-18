//! Issue #193 acceptance tests: `review_evidence` (p6) dispatches the run's
//! OWN reviewer through the role-bound adapter — resolving the reviewer's
//! harness + profile from the fleet registry, starting it in the run's lane
//! at the run's certified head — and consumes the verdict that reviewer
//! WRITES. The engine never synthesises a verdict: a missing, ill-formed,
//! wrong-head or `pending`-carrying verdict leaves the frontier parked with a
//! typed reason.
//!
//! Fixture layers, synthetic identities only:
//! - the REAL effect path (`mutation::execute_step`) over a real lane Git
//!   worktree and a fake `hermes` executable on PATH: the fake records the
//!   argv it was spawned with (proving the REGISTRY-resolved role binding,
//!   never a literal), and the test plays the reviewer's own write — the
//!   engine never writes a verdict.
//!
//! No fixed real sleeps: every wait is a bounded poll with a deadline.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use canter::adapters::{LaneNames, SessionHandle};
use canter::config::ProfileBinding;
use canter::mutation::{
    EffectContext, PlanBindings, bind_plan, execute_step, review_verdict_path,
    reviewer_session_handle, run_session_handle,
};
use canter::value::{Val, integer, object, string};

const REPO: &str = "example-org/widgets";
const ISSUE: i64 = 5;
const STEP: &str = "p6-5";
/// The run identity (the implementer's session derives from it).
const RUN: &str = "run-0000000000000193";
/// The registry reviewer row: its OWN key, provider and model — resolved from
/// the fleet registry, never a literal in the engine.
const REVIEWER_KEY: &str = "lane-rev";
const REVIEWER_PROVIDER: &str = "provider-rev";
const REVIEWER_MODEL: &str = "model-rev";
/// The implementer's registry row (the run's own committed role).
const IMPLEMENTER_KEY: &str = "lane-impl";
const IMPLEMENTER_PROVIDER: &str = "provider-impl";
const IMPLEMENTER_MODEL: &str = "model-impl";
const BASE: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const WORKFLOW_HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

fn git(cwd: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .args(args)
        .current_dir(cwd)
        .output()
        .expect("git runs");
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).to_string()
}

fn binding_doc(key: &str, provider: &str, model: &str) -> Val {
    let mut binding = ProfileBinding {
        key: key.to_string(),
        kind: "hermes".to_string(),
        provider: provider.to_string(),
        model: model.to_string(),
        fallbacks: Vec::new(),
        configured_limits: Vec::new(),
        introspection: false,
        secrets: Vec::new(),
        revision: String::new(),
    };
    binding.revision = binding.revision_of();
    binding.to_doc()
}

/// The reviewer's registry-resolved binding document (exactly what `canter
/// queue preview --reviewer-harness` resolves from the configured row).
fn reviewer_binding_doc() -> Val {
    binding_doc(REVIEWER_KEY, REVIEWER_PROVIDER, REVIEWER_MODEL)
}

/// The fake `hermes` executable: records its argv, then exits 0. It is the
/// reviewer's own harness — the VERDICT is written by the reviewer role, and
/// in this fixture that role is played by the test.
fn write_fake_hermes(dir: &Path) -> PathBuf {
    let bin = dir.join("fakebin-hermes");
    std::fs::create_dir_all(&bin).expect("bin dir");
    let path = bin.join("hermes");
    std::fs::write(
        &path,
        "#!/bin/sh\n\
         printf '%s\\n' \"$@\" > argv.txt\n\
         printf 'reviewed\\n'\n",
    )
    .expect("write fake hermes");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = std::fs::metadata(&path).expect("metadata").permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&path, permissions).expect("chmod");
    }
    bin
}

/// One fixture: a lane worktree at the certified head, a fake harness on
/// PATH, a daemon-owned review root and the run's bound implementer session.
struct Fixture {
    worktrees_root: PathBuf,
    lane: PathBuf,
    review_root: PathBuf,
    env: BTreeMap<String, String>,
    head: String,
    base: String,
    session: SessionHandle,
}

impl Fixture {
    fn new(name: &str) -> Fixture {
        let dir = std::env::temp_dir().join(format!("canter-review-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("fixture dir");
        let bin = write_fake_hermes(&dir);
        let env = BTreeMap::from([
            (
                "PATH".to_string(),
                format!(
                    "{}:{}",
                    bin.display(),
                    std::env::var("PATH").unwrap_or_default()
                ),
            ),
            ("HOME".to_string(), dir.to_string_lossy().to_string()),
        ]);
        let worktrees_root = dir.join("worktrees");
        std::fs::create_dir_all(&worktrees_root).expect("worktrees root");
        let lane = worktrees_root.join(format!("issues-{ISSUE}"));
        std::fs::create_dir_all(&lane).expect("lane");
        git(&lane, &["init", "-q", "-b", "issue-5"]);
        git(&lane, &["config", "user.email", "fixture@example.test"]);
        git(&lane, &["config", "user.name", "fixture"]);
        std::fs::write(lane.join("delivery.txt"), "reviewed delivery\n").expect("delivery");
        git(&lane, &["add", "-A"]);
        git(&lane, &["commit", "-qm", "the reviewed delivery"]);
        let head = git(&lane, &["rev-parse", "HEAD"]).trim().to_string();
        let review_root = dir.join("reviews");
        let session = run_session_handle(RUN).expect("the run session derives");
        Fixture {
            worktrees_root,
            lane,
            review_root,
            env,
            head,
            base: BASE.to_string(),
            session,
        }
    }

    /// The reviewer lane identity this run's review step addresses.
    fn reviewer_agent(&self) -> String {
        LaneNames::new(ISSUE as u64, "reviewer", 1)
            .expect("reviewer lane names")
            .agent
    }

    fn verdict_path(&self) -> PathBuf {
        review_verdict_path(&self.review_root, &self.session, STEP)
    }

    /// The fake harness records its argv in the directory the adapter spawned
    /// it in (the headless substrate runs in the integration checkout).
    fn fake_argv(&self) -> PathBuf {
        self.lane.join("argv.txt")
    }
}

/// One `hf-plan/v1` document whose spine carries the review step under test.
fn plan_with_review_step(params: Val) -> PlanBindings {
    let steps = Val::Arr(vec![object(vec![
        ("id", string(STEP)),
        ("kind", string("review_evidence")),
        ("params", params),
    ])]);
    let placeholder = object(vec![
        ("schema", string("hf-plan/v1")),
        ("plan_id", string("hf_plan_0000000000000000")),
        ("workflow_id", string("fleet-doctrine-1")),
        ("workflow_hash", string(WORKFLOW_HASH)),
        ("state_epoch", integer(1)),
        ("repository", string(REPO)),
        (
            "issue",
            object(vec![
                ("number", integer(ISSUE)),
                (
                    "revision",
                    string("1111111111111111111111111111111111111111"),
                ),
            ]),
        ),
        ("steps", steps),
    ]);
    // The plan id is content-addressed: the first 16 hex of the sha256 over
    // the canonical document with a placeholder id (spec-plans.md).
    let digest = canter::canonical::sha256_hex(&canter::canonical::canonical_bytes(&placeholder));
    let doc = match placeholder {
        Val::Obj(mut map) => {
            map.insert(
                "plan_id".to_string(),
                string(&format!("hf_plan_{}", &digest[..16])),
            );
            Val::Obj(map)
        }
        _ => unreachable!("the plan seed is an object"),
    };
    bind_plan(&doc).expect("plan binds")
}

/// The review step's params: the reviewer LEG (the registry-resolved role
/// binding the reviewed plan declares).
fn reviewer_leg_params(binding: &Val, deadline: i64) -> Val {
    object(vec![
        ("harness_key", string(REVIEWER_KEY)),
        ("kind", string("hermes")),
        ("execution", string("headless")),
        ("reviewer_profile", binding.clone()),
        ("worktree", string(&format!("issues-{ISSUE}"))),
        ("deadline_secs", integer(deadline)),
    ])
}

fn run_review_step(
    fixture: &Fixture,
    plan: &PlanBindings,
    params: &Val,
    certified_head: &str,
    observed_base: &str,
) -> canter::mutation::EffectOutcome {
    execute_step(&EffectContext {
        plan,
        step_id: STEP,
        kind: "review_evidence",
        params: Some(params),
        repository: REPO,
        integration_branch: "staging",
        production_branches: &[],
        worktrees_root: &fixture.worktrees_root,
        integration_repo: &fixture.lane,
        archive_root: None,
        review_root: Some(&fixture.review_root),
        observed_feature_head: Some(certified_head),
        observed_integration_base: Some(observed_base),
        env: &fixture.env,
        role: None,
        session: Some(&fixture.session),
        retired_run_ids: &[],
    })
}

/// One verdict document, exactly as the review brief asks the reviewer to
/// write it.
fn verdict_doc(head: &str, base: &str, verdict: &str, checks: Val) -> String {
    canter::canonical::canonical_text(&object(vec![
        ("schema", string("hf-evidence/v1")),
        ("feature_head", string(head)),
        ("integration_base", string(base)),
        ("verdict", string(verdict)),
        ("checks", checks),
    ]))
}

fn check(name: &str, status: &str) -> Val {
    object(vec![("name", string(name)), ("status", string(status))])
}

/// Run the review step while the REVIEWER (this test) writes `written` as its
/// verdict once the prompt has been delivered.
fn review_with_written_verdict(
    fixture: &Fixture,
    plan: &PlanBindings,
    params: &Val,
    written: String,
) -> canter::mutation::EffectOutcome {
    let verdict_path = fixture.verdict_path();
    let writer = std::thread::spawn({
        let argv = fixture.fake_argv();
        move || {
            let deadline = Instant::now() + Duration::from_secs(30);
            while Instant::now() < deadline && !argv.exists() {
                std::thread::sleep(Duration::from_millis(10));
            }
            assert!(argv.exists(), "the reviewer was never prompted");
            std::fs::write(&verdict_path, written).expect("the reviewer writes its verdict");
        }
    });
    let head = fixture.head.clone();
    let base = fixture.base.clone();
    let outcome = run_review_step(fixture, plan, params, &head, &base);
    writer.join().expect("the reviewer's write completes");
    outcome
}

// ---------------------------------------------------------------------------
// (a) the run dispatches its own reviewer and consumes the verdict it writes
// ---------------------------------------------------------------------------

#[test]
fn the_run_dispatches_its_own_reviewer_and_consumes_the_verdict_it_writes() {
    let fixture = Fixture::new("positive");
    let params = reviewer_leg_params(&reviewer_binding_doc(), 20);
    let plan = plan_with_review_step(params.clone());
    let written = verdict_doc(
        &fixture.head,
        &fixture.base,
        "pass",
        Val::Arr(vec![
            check("exact-head-review", "passed"),
            check("hosted-ci", "passed"),
        ]),
    );
    let outcome = review_with_written_verdict(&fixture, &plan, &params, written);
    assert_eq!(outcome.status, "succeeded", "{outcome:?}");
    let result = &outcome.result;
    assert_eq!(
        result.get("feature_head").and_then(Val::as_str),
        Some(fixture.head.as_str()),
        "the recorded evidence names the certified reviewed sha"
    );
    assert_eq!(result.get("verdict").and_then(Val::as_str), Some("pass"));
    assert_eq!(
        result.get("reviewer").and_then(Val::as_str),
        Some(fixture.reviewer_agent().as_str()),
        "the recorded reviewer is the lane identity the adapter started"
    );
    assert_eq!(
        result
            .get("checks")
            .and_then(Val::as_array)
            .map(|checks| checks.len()),
        Some(2)
    );
    // The registry-resolved role is recorded: key, kind and the intended
    // provider/model the registry declares (never a literal in the engine).
    let profile = result.get("reviewer_profile").expect("the role resolution");
    assert_eq!(profile.get("key").and_then(Val::as_str), Some(REVIEWER_KEY));
    assert_eq!(
        profile.get("provider").and_then(Val::as_str),
        Some(REVIEWER_PROVIDER)
    );
    assert_eq!(
        profile.get("model").and_then(Val::as_str),
        Some(REVIEWER_MODEL)
    );
    // The fake harness really ran as the reviewer role with the registry's
    // binding pair; the implementer's pair is nowhere in that argv.
    let argv = std::fs::read_to_string(fixture.fake_argv()).expect("the harness argv");
    assert!(
        argv.contains(REVIEWER_KEY)
            && argv.contains(REVIEWER_PROVIDER)
            && argv.contains(REVIEWER_MODEL),
        "the reviewer ran under the registry-resolved binding: {argv}"
    );
    assert!(
        !argv.contains(IMPLEMENTER_KEY)
            && !argv.contains(IMPLEMENTER_PROVIDER)
            && !argv.contains(IMPLEMENTER_MODEL),
        "the reviewer never runs the implementer's binding: {argv}"
    );
    // The reviewer identity is DERIVED and distinct from the implementer's.
    let reviewer = reviewer_session_handle(&fixture.session, 1).expect("reviewer session");
    assert_ne!(reviewer.session_id, fixture.session.session_id);
    assert_eq!(
        result.get("reviewer_lane").and_then(Val::as_str),
        Some(reviewer.session_id.as_str())
    );
    assert_ne!(
        fixture.reviewer_agent(),
        fixture.session.session_id,
        "the reviewer lane identity is not the implementer's session identity"
    );
}

// ---------------------------------------------------------------------------
// (b) negatives: no verdict / wrong sha / pending -> parked, typed, no advance
// ---------------------------------------------------------------------------

#[test]
fn a_reviewer_that_writes_no_verdict_parks_the_frontier_with_a_typed_timeout() {
    let fixture = Fixture::new("no-verdict");
    let params = reviewer_leg_params(&reviewer_binding_doc(), 1);
    let plan = plan_with_review_step(params.clone());
    let head = fixture.head.clone();
    let base = fixture.base.clone();
    let outcome = run_review_step(&fixture, &plan, &params, &head, &base);
    assert_eq!(outcome.status, "ambiguous", "{outcome:?}");
    assert_eq!(
        outcome.code.as_deref(),
        Some(canter::mutation::code::REVIEW_TIMEOUT)
    );
    assert!(
        fixture.fake_argv().exists(),
        "the reviewer WAS dispatched and prompted: the stall is the verdict, not the dispatch"
    );
    assert!(
        !fixture.verdict_path().exists(),
        "nothing was synthesised at the artifact path"
    );
}

#[test]
fn a_verdict_naming_another_sha_is_refused_and_never_consumed() {
    let fixture = Fixture::new("wrong-sha");
    let params = reviewer_leg_params(&reviewer_binding_doc(), 20);
    let plan = plan_with_review_step(params.clone());
    let other = "c".repeat(40);
    let written = verdict_doc(
        &other,
        &fixture.base,
        "pass",
        Val::Arr(vec![check("review", "passed")]),
    );
    let outcome = review_with_written_verdict(&fixture, &plan, &params, written);
    assert_eq!(outcome.status, "refused", "{outcome:?}");
    assert_eq!(
        outcome.code.as_deref(),
        Some(canter::mutation::code::VERDICT_STALE)
    );
}

#[test]
fn a_verdict_with_a_pending_check_is_refused_before_it_can_strand_the_tail() {
    let fixture = Fixture::new("pending");
    let params = reviewer_leg_params(&reviewer_binding_doc(), 20);
    let plan = plan_with_review_step(params.clone());
    let written = verdict_doc(
        &fixture.head,
        &fixture.base,
        "pass",
        Val::Arr(vec![
            check("exact-head-review", "passed"),
            check("hosted-ci", "pending"),
        ]),
    );
    let outcome = review_with_written_verdict(&fixture, &plan, &params, written);
    assert_eq!(outcome.status, "refused", "{outcome:?}");
    assert_eq!(
        outcome.code.as_deref(),
        Some(canter::mutation::code::VERDICT_PENDING)
    );
}

#[test]
fn an_ill_formed_verdict_is_refused_rather_than_repaired() {
    let fixture = Fixture::new("malformed");
    let params = reviewer_leg_params(&reviewer_binding_doc(), 20);
    let plan = plan_with_review_step(params.clone());
    let written = "{\"schema\":\"hf-evidence/v1\",\"feature_head\":\"nope\"}".to_string();
    let outcome = review_with_written_verdict(&fixture, &plan, &params, written);
    assert_eq!(outcome.status, "refused", "{outcome:?}");
    assert_eq!(
        outcome.code.as_deref(),
        Some(canter::mutation::code::VERDICT_STALE)
    );
}

// ---------------------------------------------------------------------------
// (c) the lane must BE the certified head, and the shape is exclusive
// ---------------------------------------------------------------------------

#[test]
fn a_review_step_never_starts_a_reviewer_on_a_moved_head() {
    let fixture = Fixture::new("moved-head");
    let params = reviewer_leg_params(&reviewer_binding_doc(), 5);
    let plan = plan_with_review_step(params.clone());
    let other = "d".repeat(40);
    // Issue #200: the refusal is DETERMINISTIC and typed — the certificate is
    // a recorded fact and the checkout's movement is external, so the SAME
    // moved head refuses identically on every dispatch. That determinism is
    // what makes a re-dispatch of this step impossible (see supervision's
    // parked-frontier rule) instead of a retryable failure.
    let mut seen = Vec::new();
    for _ in 0..2 {
        let outcome = run_review_step(&fixture, &plan, &params, &other, &fixture.base);
        assert_eq!(outcome.status, "refused", "{outcome:?}");
        assert_eq!(
            outcome.code.as_deref(),
            Some(canter::mutation::code::VERDICT_STALE)
        );
        seen.push((outcome.status, outcome.code, outcome.message.clone()));
    }
    assert_eq!(seen[0], seen[1], "the same moved head refuses identically");
    let message = seen[0].2.clone().unwrap_or_default();
    assert!(
        message.contains(&fixture.head) && message.contains(&other),
        "the refusal names the observed checkout head and the certified head: {message}"
    );
    assert!(
        !fixture.fake_argv().exists(),
        "a moved head never reaches the reviewer"
    );
}

#[test]
fn a_step_declaring_both_shapes_is_refused() {
    let fixture = Fixture::new("both-shapes");
    let mut params = match reviewer_leg_params(&reviewer_binding_doc(), 5) {
        Val::Obj(map) => map,
        _ => unreachable!("params are an object"),
    };
    params.insert("reviewer".to_string(), string("rev-5-r1"));
    let params = Val::Obj(params);
    let plan = plan_with_review_step(params.clone());
    let head = fixture.head.clone();
    let base = fixture.base.clone();
    let outcome = run_review_step(&fixture, &plan, &params, &head, &base);
    assert_eq!(outcome.status, "refused", "{outcome:?}");
    assert_eq!(
        outcome.code.as_deref(),
        Some(canter::mutation::code::BAD_PARAMS)
    );
}

#[test]
fn a_review_step_without_facts_or_a_reviewer_leg_is_still_refused() {
    let fixture = Fixture::new("no-shape");
    let params = object(vec![]);
    let plan = plan_with_review_step(params.clone());
    let head = fixture.head.clone();
    let base = fixture.base.clone();
    let outcome = run_review_step(&fixture, &plan, &params, &head, &base);
    assert_eq!(outcome.status, "refused", "{outcome:?}");
    assert_eq!(
        outcome.code.as_deref(),
        Some(canter::mutation::code::BAD_PARAMS),
        "the engine never invents a reviewer"
    );
    assert!(!fixture.fake_argv().exists(), "no reviewer was started");
}

#[test]
fn a_reviewer_leg_whose_binding_is_not_the_declared_role_is_refused() {
    let fixture = Fixture::new("foreign-binding");
    let foreign = binding_doc(IMPLEMENTER_KEY, IMPLEMENTER_PROVIDER, IMPLEMENTER_MODEL);
    let params = reviewer_leg_params(&foreign, 5);
    let plan = plan_with_review_step(params.clone());
    let head = fixture.head.clone();
    let base = fixture.base.clone();
    let outcome = run_review_step(&fixture, &plan, &params, &head, &base);
    assert_eq!(outcome.status, "refused", "{outcome:?}");
    assert_eq!(
        outcome.code.as_deref(),
        Some(canter::config::CODE_PROFILE_BINDING)
    );
    assert!(!fixture.fake_argv().exists());
}
