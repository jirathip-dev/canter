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

// ---------------------------------------------------------------------------
// Issue #210: the reviewer leg's OWN lane on the pane substrate
// ---------------------------------------------------------------------------

/// The fake Herdr substrate of the lane witnesses (issue #210): a
/// MULTI-workspace state, so the run's implementer lane stays registered while
/// the reviewer leg binds its own lane — the exact live shape whose collision
/// (`refusal.lane.name_collision` on run-a1eb1f68dc9f2976) this slice removes
/// by construction. One state directory per workspace id; every row is logged.
const FAKE_HERDR_LANES: &str = r#"
PATH=/usr/bin:/bin
export PATH
LOG="$HF_FAKE_HERDR_LOG"
STATE="$HF_FAKE_HERDR_STATE"
mkdir -p "$STATE"
log() { printf '%s\n' "$*" >> "$LOG"; }
field() { sed -n "s/^$1|\([^|]*\)|.*/\1/p" "$STATE/workspaces"; }
row_of_id() {
  label=$(field "$1"); cwd=$(sed -n "s/^$1|[^|]*|\([^|]*\)|.*/\1/p" "$STATE/workspaces")
  root=$(sed -n "s/^$1|[^|]*|[^|]*|\(.*\)$/\1/p" "$STATE/workspaces")
  printf '{"workspace_id":"%s","label":"%s","cwd":"%s","worktree":{"repo_root":"%s","checkout_path":"%s","is_linked_worktree":true,"repo_name":"widgets"}}' "$1" "$label" "$cwd" "$root" "$cwd"
}
agent_row() {
  printf '{"name":"%s","pane_id":"%s","cwd":"%s","agent_status":"%s","state_change_seq":%s,"tokens":{"canter_lane":"%s","canter_generation":"%s"}}' \
    "$(cat "$STATE/$1.agent")" "$(cat "$STATE/$1.pane")" "$(cat "$STATE/$1.cwd")" \
    "$(cat "$STATE/$1.state")" "$(cat "$STATE/$1.seq")" \
    "$(cat "$STATE/$1.lane" 2>/dev/null)" "$(cat "$STATE/$1.generation" 2>/dev/null)"
}
id_of_agent() {
  [ -f "$STATE/workspaces" ] || return 0
  while IFS='|' read -r id rest; do
    if [ -f "$STATE/$id.agent" ] && [ "$(cat "$STATE/$id.agent")" = "$1" ]; then printf '%s' "$id"; return 0; fi
  done < "$STATE/workspaces"
}
id_of_pane() { printf '%s' "${1%%:*}"; }
case "$1 $2" in
  "workspace list")
    log "$*"
    rows=""
    if [ -f "$STATE/workspaces" ]; then
      while IFS='|' read -r id rest; do
        row=$(row_of_id "$id"); [ -n "$rows" ] && rows="$rows,"; rows="$rows$row"
      done < "$STATE/workspaces"
    fi
    printf '{"id":"cli:workspace:list","result":{"workspaces":[%s],"type":"workspace_list"}}\n' "$rows"
    ;;
  "worktree open")
    log "$*"
    cwd=""; label=""; root=""
    shift 2
    while [ $# -gt 0 ]; do case "$1" in --cwd) root="$2"; shift 2;; --path) cwd="$2"; shift 2;; --label) label="$2"; shift 2;; *) shift;; esac; done
    n=1; [ -f "$STATE/next" ] && n=$(sed -n 1p "$STATE/next")
    printf '%s' "$((n + 1))" > "$STATE/next"
    id="w$n"
    printf '%s|%s|%s|%s\n' "$id" "$label" "$cwd" "$root" >> "$STATE/workspaces"
    printf '%s' "$id:p1" > "$STATE/$id.pane"
    printf '%s' "$cwd" > "$STATE/$id.cwd"
    printf '%s' "$root" > "$STATE/$id.root"
    printf 'idle' > "$STATE/$id.state"
    printf '0' > "$STATE/$id.seq"
    printf '{"id":"cli:worktree:open","result":{"workspace":%s,"root_pane":{"pane_id":"%s:p1","cwd":"%s"},"already_open":false,"type":"worktree_opened"}}\n' "$(row_of_id "$id")" "$id" "$cwd"
    ;;
  "pane list")
    log "$*"
    id=""
    shift 2
    while [ $# -gt 0 ]; do case "$1" in --workspace) id="$2"; shift 2;; *) shift;; esac; done
    printf '{"id":"cli:pane:list","result":{"panes":[{"pane_id":"%s:p1","cwd":"%s","tokens":{"canter_lane":"%s","canter_generation":"%s"}}],"type":"pane_list"}}\n' \
      "$id" "$(cat "$STATE/$id.cwd")" "$(cat "$STATE/$id.lane" 2>/dev/null)" "$(cat "$STATE/$id.generation" 2>/dev/null)"
    ;;
  "pane report-metadata")
    log "$*"
    id=$(id_of_pane "$3")
    shift 3
    while [ $# -gt 0 ]; do
      case "$1" in
        --token) case "$2" in
            canter_lane=*) printf '%s' "${2#canter_lane=}" > "$STATE/$id.lane" ;;
            canter_generation=*) printf '%s' "${2#canter_generation=}" > "$STATE/$id.generation" ;;
          esac; shift 2 ;;
        *) shift ;;
      esac
    done
    ;;
  "agent list")
    log "$*"
    rows=""
    if [ -f "$STATE/workspaces" ]; then
      while IFS='|' read -r id rest; do
        [ -f "$STATE/$id.agent" ] || continue
        row=$(agent_row "$id"); [ -n "$rows" ] && rows="$rows,"; rows="$rows$row"
      done < "$STATE/workspaces"
    fi
    printf '{"id":"cli:agent:list","result":{"agents":[%s],"type":"agent_list"}}\n' "$rows"
    ;;
  "agent start")
    log "$*"
    name="$3"; pane=""
    shift 3
    while [ $# -gt 0 ]; do case "$1" in --pane) pane="$2"; shift 2;; --) break;; *) shift;; esac; done
    id=$(id_of_pane "$pane")
    printf '%s' "$name" > "$STATE/$id.agent"
    # The lane checkout's HEAD at bind time: the witness reads it back to prove
    # the reviewer lane was materialized AT the certified head.
    cwd=$(cat "$STATE/$id.cwd")
    git -C "$cwd" rev-parse HEAD > "$STATE/$id.head" 2>/dev/null || printf '' > "$STATE/$id.head"
    printf '{"id":"cli:agent:start","result":{"agent":%s,"argv":["hermes"],"type":"agent_started"}}\n' "$(agent_row "$id")"
    ;;
  "agent get")
    log "$*"
    id=$(id_of_agent "$3")
    if [ -n "$id" ]; then
      printf '{"id":"cli:agent:get","result":{"agent":%s,"type":"agent_info"}}\n' "$(agent_row "$id")"
    else
      printf '{"id":"cli:agent:get","result":null,"type":"agent_info"}\n'
      exit 3
    fi
    ;;
  "agent prompt")
    log "$*"
    id=$(id_of_agent "$3")
    printf '%s' "$4" > "$STATE/$id.content"
    printf 'done' > "$STATE/$id.state"
    printf '%s' "$(( $(cat "$STATE/$id.seq") + 1 ))" > "$STATE/$id.seq"
    printf 'prompted' > "$STATE/$id.prompted"
    printf '{"id":"cli:agent:prompt","result":{"agent_status":"done","submitted":true},"type":"agent_prompt"}\n'
    ;;
  "agent read")
    log "$*"
    id=$(id_of_agent "$3")
    printf 'reviewer session\n'
    [ -f "$STATE/$id.content" ] && cat "$STATE/$id.content"
    printf '\n'
    ;;
  "workspace close")
    log "$*"
    id="$3"
    grep -v "^$id|" "$STATE/workspaces" > "$STATE/workspaces.tmp" 2>/dev/null || true
    mv "$STATE/workspaces.tmp" "$STATE/workspaces" 2>/dev/null || true
    rm -f "$STATE/$id.pane" "$STATE/$id.cwd" "$STATE/$id.root" "$STATE/$id.state" \
      "$STATE/$id.seq" "$STATE/$id.agent" "$STATE/$id.lane" "$STATE/$id.generation" \
      "$STATE/$id.content" "$STATE/$id.prompted" "$STATE/$id.head"
    printf '{"result":{}}\n'
    ;;
  *)
    log "UNEXPECTED $*"
    printf 'unexpected herdr row: %s\n' "$*" >&2
    exit 9
    ;;
esac
"#;

/// The pane-substrate fixture of the lane witnesses: one real integration
/// repository, the run's linked lane worktree at the certified head, the fake
/// Herdr on PATH, and the run's bound session.
struct LaneFixture {
    root: PathBuf,
    integration: PathBuf,
    worktrees_root: PathBuf,
    lane: PathBuf,
    reviewer_lane: PathBuf,
    review_root: PathBuf,
    env: BTreeMap<String, String>,
    state: PathBuf,
    log: PathBuf,
    seed_head: String,
    head: String,
    session: SessionHandle,
}

impl LaneFixture {
    fn new(name: &str) -> LaneFixture {
        let dir = std::env::temp_dir().join(format!("canter-lane-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("fixture dir");
        let root = dir.canonicalize().expect("canonical fixture root");
        let bin = root.join("fakebin");
        std::fs::create_dir_all(&bin).expect("bin dir");
        let herdr = bin.join("herdr");
        std::fs::write(&herdr, format!("#!/bin/sh\n{FAKE_HERDR_LANES}")).expect("fake herdr");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = std::fs::metadata(&herdr).expect("metadata").permissions();
            permissions.set_mode(0o755);
            std::fs::set_permissions(&herdr, permissions).expect("chmod");
        }
        let integration = root.join("integration");
        std::fs::create_dir_all(&integration).expect("integration");
        git(&integration, &["init", "-q", "-b", "staging"]);
        git(
            &integration,
            &["config", "user.email", "fixture@example.test"],
        );
        git(&integration, &["config", "user.name", "fixture"]);
        std::fs::write(integration.join("seed.txt"), "seed\n").expect("seed");
        git(&integration, &["add", "-A"]);
        git(&integration, &["commit", "-qm", "seed"]);
        let seed_head = git(&integration, &["rev-parse", "HEAD"]).trim().to_string();
        let worktrees_root = root.join("worktrees");
        std::fs::create_dir_all(&worktrees_root).expect("worktrees root");
        let lane = worktrees_root.join(format!("issues-{ISSUE}"));
        git(
            &integration,
            &[
                "worktree",
                "add",
                "-q",
                "-b",
                &format!("issue-{ISSUE}"),
                lane.to_str().expect("lane path"),
                "staging",
            ],
        );
        std::fs::write(lane.join("delivery.txt"), "reviewed delivery\n").expect("delivery");
        git(&lane, &["add", "-A"]);
        git(&lane, &["commit", "-qm", "the reviewed delivery"]);
        let head = git(&lane, &["rev-parse", "HEAD"]).trim().to_string();
        let state = root.join("herdr-state");
        let review_root = root.join("reviews");
        let env = BTreeMap::from([
            (
                "PATH".to_string(),
                format!(
                    "{}:{}",
                    bin.display(),
                    std::env::var("PATH").unwrap_or_default()
                ),
            ),
            ("HOME".to_string(), root.to_string_lossy().to_string()),
            (
                "HF_FAKE_HERDR_LOG".to_string(),
                root.join("herdr.log").to_string_lossy().to_string(),
            ),
            (
                "HF_FAKE_HERDR_STATE".to_string(),
                state.to_string_lossy().to_string(),
            ),
        ]);
        LaneFixture {
            root: root.clone(),
            integration,
            worktrees_root,
            lane,
            reviewer_lane: root.join("worktrees").join(format!("issues-{ISSUE}-rev1")),
            review_root,
            env,
            state,
            log: root.join("herdr.log"),
            seed_head,
            head,
            session: run_session_handle(RUN).expect("the run session derives"),
        }
    }

    /// Seed ONE workspace registration into the fake's state: the row plus the
    /// per-workspace files the substrate answers read-backs from.
    fn seed_workspace(
        &self,
        id: &str,
        label: &str,
        checkout: &Path,
        agent: &str,
        lane: &str,
        generation: u64,
    ) {
        std::fs::create_dir_all(&self.state).expect("state dir");
        let mut rows = std::fs::read_to_string(self.state.join("workspaces")).unwrap_or_default();
        rows.push_str(&format!(
            "{id}|{label}|{}|{}\n",
            checkout.display(),
            self.integration.display()
        ));
        std::fs::write(self.state.join("workspaces"), rows).expect("workspaces row");
        for (file, value) in [
            ("pane", format!("{id}:p1")),
            ("cwd", checkout.display().to_string()),
            ("root", self.integration.display().to_string()),
            ("state", "idle".to_string()),
            ("seq", "0".to_string()),
            ("agent", agent.to_string()),
            ("lane", lane.to_string()),
            ("generation", generation.to_string()),
        ] {
            std::fs::write(self.state.join(format!("{id}.{file}")), value).expect("workspace file");
        }
    }

    /// The run's own implementer lane, REGISTERED and live: `5-impl` at
    /// `worktrees/issues-5`, bound to the run's session.
    fn seed_run_lane(&self) {
        self.seed_workspace(
            "E1",
            &format!("{ISSUE}-impl"),
            &self.lane,
            &format!("impl-{ISSUE}"),
            &self.session.session_id,
            1,
        );
    }

    /// Register the reviewer's lane checkout as a DETACHED git worktree at the
    /// given head — the residue of a previous generation / the checkout of a
    /// retried attempt.
    fn register_reviewer_lane(&self, head: &str) {
        if let Some(parent) = self.reviewer_lane.parent() {
            std::fs::create_dir_all(parent).expect("worktrees root");
        }
        git(
            &self.integration,
            &[
                "worktree",
                "add",
                "-q",
                "--detach",
                self.reviewer_lane.to_str().expect("reviewer lane path"),
                head,
            ],
        );
    }

    fn rows(&self) -> Vec<String> {
        std::fs::read_to_string(&self.log)
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect()
    }

    /// Write the reviewer's verdict once the reviewer has been prompted —
    /// the test plays the reviewer role, the engine never writes a verdict.
    /// The review's lane is removed the moment the verdict is consumed, so the
    /// witness files (the prompted workspace and the lane checkout's HEAD at
    /// bind time) are captured HERE, while the lane still exists.
    fn write_verdict_when_prompted(&self, written: String) -> std::thread::JoinHandle<()> {
        let verdict_path = review_verdict_path(&self.review_root, &self.session, STEP);
        let state = self.state.clone();
        let root = self.root.clone();
        std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(30);
            while Instant::now() < deadline {
                if let Some(id) = prompted_id(&state) {
                    let head = std::fs::read_to_string(state.join(format!("{id}.head")))
                        .unwrap_or_default();
                    std::fs::write(root.join("observed-workspace"), &id).expect("observe ws");
                    std::fs::write(root.join("observed-head"), head.trim()).expect("observe head");
                    std::fs::write(&verdict_path, &written).expect("the reviewer writes");
                    return;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            panic!("the reviewer was never prompted");
        })
    }

    /// The prompted workspace id and the lane checkout's HEAD at bind time,
    /// captured by the reviewer's own verdict writer.
    fn observed_prompt(&self) -> (String, String) {
        let workspace = std::fs::read_to_string(self.root.join("observed-workspace"))
            .expect("the reviewer was prompted");
        let head =
            std::fs::read_to_string(self.root.join("observed-head")).expect("the lane's head");
        (workspace, head)
    }

    fn reviewer_ws_file(&self, id: &str, file: &str) -> Option<String> {
        std::fs::read_to_string(self.state.join(format!("{id}.{file}"))).ok()
    }

    /// The registered workspace ids in the fake's state.
    fn workspace_ids(&self) -> Vec<String> {
        std::fs::read_to_string(self.state.join("workspaces"))
            .unwrap_or_default()
            .lines()
            .filter_map(|line| line.split('|').next().map(str::to_string))
            .collect()
    }
}

/// The workspace the reviewer was prompted in (its `prompted` marker in the
/// fake's state).
fn prompted_id(state: &Path) -> Option<String> {
    let entries = std::fs::read_dir(state).ok()?;
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if let Some(id) = name.strip_suffix(".prompted") {
            return Some(id.to_string());
        }
    }
    None
}

/// The reviewer-leg params of the lane witnesses: the pane substrate, the
/// reviewer leg's OWN lane checkout and the registry-resolved binding.
fn lane_review_params(worktree: &str, deadline: i64) -> Val {
    object(vec![
        ("execution", string("herdr")),
        ("harness_key", string(REVIEWER_KEY)),
        ("kind", string("hermes")),
        ("reviewer_profile", reviewer_binding_doc()),
        ("worktree", string(worktree)),
        ("deadline_secs", integer(deadline)),
    ])
}

/// Run one review step on the pane substrate over the lane fixture.
fn run_lane_review_step(
    fixture: &LaneFixture,
    plan: &PlanBindings,
    params: &Val,
    retired_run_ids: &[String],
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
        integration_repo: &fixture.integration,
        archive_root: None,
        review_root: Some(&fixture.review_root),
        observed_feature_head: Some(&fixture.head),
        observed_integration_base: Some(BASE),
        env: &fixture.env,
        role: None,
        session: Some(&fixture.session),
        retired_run_ids,
    })
}

fn passing_verdict(fixture: &LaneFixture) -> String {
    verdict_doc(
        &fixture.head,
        BASE,
        "pass",
        Val::Arr(vec![
            check("exact-head-review", "passed"),
            check("hosted-ci", "passed"),
        ]),
    )
}

/// W1 (issue #210): with the run's implementer lane REGISTERED and live, the
/// reviewer leg dispatches without any collision — its identity is distinct by
/// construction, proven by the created record (its own lane checkout, label
/// and agent, bound at the certified head) and by the untouched run lane.
#[test]
fn the_reviewer_leg_binds_its_own_lane_while_the_run_lane_stays_registered() {
    let fixture = LaneFixture::new("own-lane");
    fixture.seed_run_lane();
    let params = lane_review_params(&format!("issues-{ISSUE}-rev1"), 30);
    let plan = plan_with_review_step(params.clone());
    let writer = fixture.write_verdict_when_prompted(passing_verdict(&fixture));
    let outcome = run_lane_review_step(&fixture, &plan, &params, &[]);
    writer.join().expect("the reviewer's write completes");

    assert_eq!(outcome.status, "succeeded", "{outcome:?}");
    let result = &outcome.result;
    assert_eq!(
        result.get("reviewer").and_then(Val::as_str),
        Some("rev-5-r1"),
        "the created record names the reviewer leg's own agent"
    );
    assert_eq!(
        result.get("reviewer_workspace").and_then(Val::as_str),
        Some("5-rev1"),
        "the created record names the reviewer leg's own workspace label"
    );
    assert_eq!(
        result.get("reviewer_worktree").and_then(Val::as_str),
        Some(fixture.reviewer_lane.to_string_lossy().as_ref()),
        "the created record names the reviewer leg's own lane checkout"
    );

    // The created record in the substrate: the pane was created at the
    // reviewer's OWN lane checkout — never at the implementer lane the run
    // holds — and the agent is the reviewer leg's own.
    let rows = fixture.rows();
    assert!(
        rows.iter().any(|row| row
            == &format!(
                "worktree open --cwd {} --path {} --label 5-rev1 --no-focus",
                fixture.integration.display(),
                fixture.reviewer_lane.display()
            )),
        "the reviewer lane is created at the reviewer's own checkout: {rows:?}"
    );
    assert!(
        rows.iter()
            .any(|row| row.starts_with("agent start rev-5-r1 ")),
        "the reviewer leg's own agent is started: {rows:?}"
    );
    assert!(
        !rows.iter().any(|row| row.contains("name_collision")),
        "no collision refused the dispatch: {rows:?}"
    );
    assert!(
        !rows.iter().any(|row| row == "workspace close E1"),
        "the run's implementer lane is never closed by the reviewer leg: {rows:?}"
    );
    let (ws, head) = fixture.observed_prompt();
    assert!(
        !ws.is_empty(),
        "the reviewer was prompted in its own workspace"
    );
    assert_eq!(
        head, fixture.head,
        "the reviewer lane's checkout was AT the certified head when the reviewer bound"
    );
    // The run's own lane registration is untouched.
    assert_eq!(
        fixture.reviewer_ws_file("E1", "lane").as_deref(),
        Some(fixture.session.session_id.as_str()),
        "the run's implementer lane still carries its own generation"
    );
    assert!(
        fixture.lane.is_dir(),
        "the run's implementer lane checkout is untouched"
    );

    // The lane exists FOR the review: once the verdict is consumed, the
    // reviewer lane is removed (no orphan workspace, no orphan checkout).
    assert!(
        !fixture.reviewer_lane.exists(),
        "the consumed review leaves no orphan checkout"
    );
    assert_eq!(
        fixture.workspace_ids(),
        vec!["E1".to_string()],
        "only the run's own lane stays registered"
    );
    let cleanup = result
        .get("reviewer_lane_cleanup")
        .expect("the lane cleanup receipt");
    assert_eq!(
        cleanup
            .get("workspace")
            .and_then(|workspace| workspace.get("closed"))
            .and_then(Val::as_bool),
        Some(true)
    );
    assert_eq!(
        cleanup
            .get("checkout")
            .and_then(|checkout| checkout.get("removed"))
            .and_then(Val::as_bool),
        Some(true)
    );
}

/// AC1 stability (issue #210): a retried review step reuses the reviewer
/// leg's OWN lane checkout — the identity is stable across attempts, and an
/// existing clean lane at the certified head is verified, not re-created.
#[test]
fn a_reviewer_lane_already_at_the_certified_head_is_reused_across_attempts() {
    let fixture = LaneFixture::new("lane-retry");
    fixture.seed_run_lane();
    fixture.register_reviewer_lane(&fixture.head);
    let params = lane_review_params(&format!("issues-{ISSUE}-rev1"), 30);
    let plan = plan_with_review_step(params.clone());
    let writer = fixture.write_verdict_when_prompted(passing_verdict(&fixture));
    let outcome = run_lane_review_step(&fixture, &plan, &params, &[]);
    writer.join().expect("the reviewer's write completes");
    assert_eq!(outcome.status, "succeeded", "{outcome:?}");
    let (_, head) = fixture.observed_prompt();
    assert_eq!(
        head, fixture.head,
        "the reused lane is the one AT the certified head"
    );
}

/// The reviewer lane is never started on a moved checkout (issue #210, the
/// #200 determinism rule): a lane at another head refuses typed BEFORE any
/// pane or agent exists, and the lane is left untouched — never repaired.
#[test]
fn a_moved_reviewer_lane_refuses_before_the_reviewer_starts() {
    let fixture = LaneFixture::new("lane-moved");
    fixture.seed_run_lane();
    fixture.register_reviewer_lane(&fixture.seed_head);
    let params = lane_review_params(&format!("issues-{ISSUE}-rev1"), 5);
    let plan = plan_with_review_step(params.clone());
    let outcome = run_lane_review_step(&fixture, &plan, &params, &[]);
    assert_eq!(outcome.status, "refused", "{outcome:?}");
    assert_eq!(
        outcome.code.as_deref(),
        Some(canter::mutation::code::VERDICT_STALE)
    );
    let message = outcome.message.clone().unwrap_or_default();
    assert!(
        message.contains(&fixture.seed_head) && message.contains(&fixture.head),
        "the refusal names the moved checkout's head and the certified head: {message}"
    );
    assert!(
        !fixture
            .rows()
            .iter()
            .any(|row| row.starts_with("worktree open")),
        "a moved lane never reaches the substrate: {:?}",
        fixture.rows()
    );
    assert!(
        fixture.reviewer_lane.is_dir(),
        "the moved lane is left untouched, never repaired"
    );
}

/// W3 (issue #210): a LEDGER-TERMINAL generation's reviewer lane is reclaimed
/// — its registration closed and its stale checkout cleared, both recorded on
/// the successor's outcome — while a LIVE holder is never adopted: its
/// registration is refused and left untouched.
#[test]
fn a_retired_generations_reviewer_lane_is_reclaimed_while_a_live_one_is_never_adopted() {
    // (a) the retired generation: its reviewer lane at an OLD head.
    let fixture = LaneFixture::new("lane-reclaim");
    fixture.seed_run_lane();
    fixture.register_reviewer_lane(&fixture.seed_head);
    let retired_run = "run-0000000000000209";
    let retired_reviewer = reviewer_session_handle(
        &run_session_handle(retired_run).expect("the retired run session derives"),
        1,
    )
    .expect("the retired reviewer session derives");
    fixture.seed_workspace(
        "R1",
        &format!("{ISSUE}-rev1"),
        &fixture.reviewer_lane,
        &format!("rev-{ISSUE}-r1"),
        &retired_reviewer.session_id,
        1,
    );
    let params = lane_review_params(&format!("issues-{ISSUE}-rev1"), 30);
    let plan = plan_with_review_step(params.clone());
    let writer = fixture.write_verdict_when_prompted(passing_verdict(&fixture));
    let outcome = run_lane_review_step(&fixture, &plan, &params, &[retired_run.to_string()]);
    writer.join().expect("the reviewer's write completes");
    assert_eq!(outcome.status, "succeeded", "{outcome:?}");
    let retired = outcome
        .result
        .get("retired_reviewer_lanes")
        .and_then(Val::as_array)
        .expect("the reclaim receipt");
    assert_eq!(retired.len(), 1, "{retired:?}");
    assert_eq!(
        retired[0].get("retired").and_then(Val::as_bool),
        Some(true),
        "the retired generation's registration is closed: {retired:?}"
    );
    assert_eq!(
        retired[0].get("lane").and_then(Val::as_str),
        Some(retired_reviewer.session_id.as_str()),
        "the reclaim names the retired generation's own reviewer lane"
    );
    assert_eq!(
        retired[0]
            .get("checkout_removal")
            .and_then(|removal| removal.get("removed"))
            .and_then(Val::as_bool),
        Some(true),
        "the retired generation's stale checkout is cleared: {retired:?}"
    );
    let rows = fixture.rows();
    let closed = rows
        .iter()
        .position(|row| row == "workspace close R1")
        .expect("the retired registration is closed");
    let opened = rows
        .iter()
        .rposition(|row| row.starts_with("worktree open"))
        .expect("the successor's lane is created");
    assert!(
        closed < opened,
        "the retired lane is reclaimed BEFORE the successor binds: {rows:?}"
    );
    assert!(
        !fixture.workspace_ids().contains(&"R1".to_string()),
        "the retired registration is gone"
    );

    // (b) a LIVE holder (not in the retired set) is never adopted: the
    // substrate refusal stands and nothing at the lane is touched.
    let live = LaneFixture::new("lane-live-holder");
    live.seed_run_lane();
    live.register_reviewer_lane(&live.head);
    let live_reviewer = reviewer_session_handle(
        &run_session_handle("run-0000000000000210").expect("the live run session derives"),
        1,
    )
    .expect("the live reviewer session derives");
    live.seed_workspace(
        "L1",
        &format!("{ISSUE}-rev1"),
        &live.reviewer_lane,
        &format!("rev-{ISSUE}-r1"),
        &live_reviewer.session_id,
        1,
    );
    let params = lane_review_params(&format!("issues-{ISSUE}-rev1"), 5);
    let plan = plan_with_review_step(params.clone());
    let outcome = run_lane_review_step(&live, &plan, &params, &[retired_run.to_string()]);
    assert_eq!(outcome.status, "refused", "{outcome:?}");
    assert_eq!(
        outcome.code.as_deref(),
        Some(canter::adapters::CODE_NAME_COLLISION),
        "a live holder is never adopted or closed: {outcome:?}"
    );
    let rows = live.rows();
    assert!(
        !rows.iter().any(|row| row.starts_with("workspace close")),
        "a live lane is never closed by a reclaim: {rows:?}"
    );
    assert_eq!(
        live.reviewer_ws_file("L1", "lane").as_deref(),
        Some(live_reviewer.session_id.as_str()),
        "the live holder's registration is untouched"
    );
    assert!(
        live.reviewer_lane.is_dir(),
        "the live checkout is preserved"
    );
}
