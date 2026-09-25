//! Queue preview (issue #84): the deterministic, effect-free preview of one
//! exact selected-issue run.
//!
//! The preview is a pure projection. It normalizes and deduplicates the
//! stable issue identities, binds the reviewable inputs into one
//! content-addressed digest, orders the selected work by its declared
//! dependencies, projects durable ownership and current occupancy, and
//! reports every unmet prerequisite as a NAMED hold — never as apparent
//! readiness.
//!
//! Contract rules (documented, stable surface):
//! - Identity is the stable `owner/name#number` form (repository identity +
//!   issue number, ASCII-lowercased) and nothing else: titles are display
//!   text that never identify, never dedupe and never enter the digest.
//! - `digest` is sha256 over the canonical bytes of the bound-input document
//!   (the rendered `request`): identical inputs always produce identical
//!   bytes and digest, and any input change (a selected spec revision, the
//!   host, the workflow pin, the role-configuration revision, the allowed
//!   completion boundary, the selected set, a dependency edge or a step
//!   binding) moves the digest — so an authorization given for the old
//!   digest is refused (`refusal.plan.stale`) before anything runs.
//! - Observed state (host availability, harness occupancy, credential
//!   presence, running lanes) never changes the digest: it produces holds.
//!   The authorization binds the plan; admission is revalidated at run time
//!   exactly like the existing fan-out gate.
//! - A required dependency that is not part of the selected set is shown as
//!   an unresolved requirement on its dependent and is never silently added
//!   to the selected scope; cross-repository references are linked
//!   dependencies only (one authoritative workflow per repository).
//! - Missing occupancy is never assumed to be spare capacity, and unknown
//!   host availability, missing credentials, unsupported executable steps,
//!   protected-branch boundaries and unsatisfiable concurrency all surface
//!   as named holds.
//! - The preview has NO effects: it spawns nothing, issues no grant, writes
//!   no external state and unpauses nothing. Its only read is the existing
//!   durable state-store read API.

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};

use crate::board::work_item_id;
use crate::canonical::{canonical_bytes, sha256_hex};
use crate::config::{PROFILE_SECRET_UNSET, ProfileBinding, is_bare_token};
use crate::formats;
use crate::lifecycle::{ConcurrencyCaps, code as admission, paths_overlap};
use crate::mutation::{
    BranchKind, check_production_confirmation, classify_branch, required_capability,
};
use crate::plan::DOCTRINE_WORKFLOW_ID;
use crate::schema::{GRANT_CAPS, GRANT_PHASES};
use crate::state::{InstanceRow, State};
use crate::value::{Val, bool_, integer, null, object, string};

/// The preview document schema id.
pub const QUEUE_PREVIEW_SCHEMA: &str = "hf-queue-preview/v1";

/// Bound on the selected-issue set (deterministic cost and render bound).
pub const SELECTED_MAX: usize = 64;

/// Bound on the declared executable step spine.
pub const STEPS_MAX: usize = 32;

/// Bound on the rendered same-repository running lanes (overflow is
/// reported explicitly, never silently dropped). The same window a cap
/// refusal names occupants through — one authority (#236).
pub const RUNNING_LANES_MAX: usize = crate::lifecycle::LANE_OCCUPANTS_MAX;

/// Closed item statuses (the acceptance vocabulary).
pub const ITEM_STATUSES: [&str; 3] = ["eligible", "blocked", "already_owned"];

/// Instance statuses that mean a durable run already owns the issue: a
/// paused run still owns its issue and declared scope (the ownership set is
/// a superset of the fan-out gate's counted set).
pub const OWNED_RUN_STATES: [&str; 5] = ["new", "running", "paused", "human_queue", "blocked"];

/// Instance statuses the fan-out admission gate counts as active lanes: the
/// gate's running-lane set (mirrors its counting filter — a paused instance
/// is not counted against the concurrency caps).
pub const COUNTED_RUN_STATES: [&str; 4] = ["new", "running", "human_queue", "blocked"];

/// The no-effects statement every preview renders (issue #84): nothing is
/// spawned, no grant is issued, no external state is written and nothing is
/// unpaused.
pub const NO_EFFECTS_STATEMENT: &str = "preview only: nothing is spawned, no grant is issued, no external state is written and nothing is unpaused";

/// Preview-local named-hold codes (stable surface). Admission holds reuse
/// the lifecycle refusal codes verbatim (`refusal.admission.*`).
pub mod holds {
    /// The workflow pin is not a workflow this slice can plan.
    pub const WORKFLOW_UNSUPPORTED: &str = "preview.workflow_unsupported";
    /// The target host is not attested available (unknown is never ready).
    pub const HOST_UNAVAILABLE: &str = "preview.host_unavailable";
    /// The harness occupancy attestation is missing (never assumed zero).
    pub const OCCUPANCY_UNKNOWN: &str = "preview.occupancy_unknown";
    /// A declared credential the bound profile needs is unset.
    pub const AUTH_MISSING: &str = "preview.auth_missing";
    /// A declared step kind is outside the closed executable effect set.
    pub const STEP_UNSUPPORTED: &str = "preview.step_unsupported";
    /// A declared step carries no resolved binding parameters.
    pub const STEP_UNRESOLVED: &str = "preview.step_unresolved";
    /// The completion boundary would land on a protected branch.
    pub const PROTECTED_BRANCH: &str = "preview.protected_branch";
    /// The selected spec revision moved past the recorded run revision.
    pub const REVISION_STALE: &str = "preview.revision_stale";
    /// The active owner has reached its reviewed-evidence frontier: its
    /// verified spine is carried forward and a fresh submission never
    /// supersedes it (issue #192); replacing it takes an explicit, audited
    /// release.
    pub const FRONTIER_PRESERVED: &str = "preview.frontier_preserved";
    /// The active owner is LIVE and not terminal, wherever its recorded
    /// frontier stands: a fresh submission never invalidates it, so the item
    /// is presented with its live run and that run's recorded frontier instead
    /// of as a rebind (issue #209); replacing it takes an explicit, audited
    /// release.
    pub const LIVE_RUN: &str = "preview.live_run";
    /// A required dependency is not part of the selected set.
    pub const DEPENDENCY_UNRESOLVED: &str = "preview.dependency_unresolved";
    /// A required dependency is selected but not settled (blocked or owned).
    pub const DEPENDENCY_UNSETTLED: &str = "preview.dependency_unsettled";
    /// A required dependency participates in a dependency cycle.
    pub const DEPENDENCY_CYCLE: &str = "preview.dependency_cycle";
}

/// A typed preview refusal (fail closed; stable codes).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreviewError {
    /// Stable dotted code (`usage.queue.*`, or a reused `refusal.*` code).
    pub code: &'static str,
    /// Bounded human message.
    pub message: String,
}

impl PreviewError {
    fn new(code: &'static str, message: impl Into<String>) -> PreviewError {
        PreviewError {
            code,
            message: message.into(),
        }
    }
}

/// One normalized stable issue identity: the repository identity plus the
/// issue number. Titles never participate.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct IssueId {
    /// Normalized repository identity (`owner/name`, ASCII-lowercased).
    pub repository: String,
    /// Issue number (>= 1).
    pub number: i64,
}

impl IssueId {
    /// Parse one explicit issue reference: `owner/name#123`, `#123` or
    /// `123` (the bare forms resolve against the explicit repository). The
    /// repository component is ASCII-lowercased before validation, so
    /// identities differing only in case are the same identity.
    pub fn parse(text: &str, default_repository: &str) -> Result<IssueId, PreviewError> {
        let text = text.trim();
        let (repository_text, number_text) = match text.rsplit_once('#') {
            Some((repository, number)) => (repository.trim(), number.trim()),
            None => ("", text),
        };
        let repository = if repository_text.is_empty() {
            default_repository.trim()
        } else {
            repository_text
        };
        let repository = repository.to_ascii_lowercase();
        if !formats::is_repository_identity(&repository) {
            return Err(PreviewError::new(
                "usage.queue_issue",
                format!(
                    "the issue reference {text:?} must carry a valid owner/name repository identity"
                ),
            ));
        }
        let number = number_text
            .parse::<i64>()
            .ok()
            .filter(|number| *number >= 1)
            .ok_or_else(|| {
                PreviewError::new(
                    "usage.queue_issue",
                    format!("the issue reference {text:?} must carry a positive issue number"),
                )
            })?;
        Ok(IssueId { repository, number })
    }

    /// The canonical `owner/name#number` text.
    pub fn display(&self) -> String {
        format!("{}#{}", self.repository, self.number)
    }

    /// The stable work-item id of this identity (the same derivation the
    /// board read model publishes over the same durable facts).
    pub fn work_item(&self) -> String {
        work_item_id(&self.repository, self.number)
    }
}

/// One presented selection entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelectedIssue {
    /// Issue reference text (`owner/name#123`, `#123` or `123`).
    pub id: String,
    /// Display title — never an identity, never a dedupe key, never bound.
    pub title: Option<String>,
    /// Exact spec/acceptance revision (40-hex).
    pub revision: String,
    /// Required dependencies (issue references). A reference outside the
    /// selected set is shown as unresolved, never added to scope.
    pub requires: Vec<String>,
}

/// One declared executable step of the planned run.
#[derive(Clone, Debug, PartialEq)]
pub struct PlannedStep {
    /// Step id (slug).
    pub id: String,
    /// Step kind (a member of the closed executable effect set).
    pub kind: String,
    /// Resolved binding parameters, or `None` when unresolved.
    pub params: Option<Val>,
}

/// The allowed completion boundary of the run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Boundary {
    /// The closed grant phase the run may reach.
    pub phase: String,
    /// The repository's integration branch (reviewed merges land here).
    pub integration_branch: String,
    /// The ref the allowed completion lands on.
    pub completion_branch: String,
    /// The closed capability subset the run may carry.
    pub caps: Vec<String>,
}

/// One presented preview request (validated by [`preview_queue`]).
#[derive(Clone, Debug)]
pub struct QueueRequest {
    /// Explicit repository identity, sourced from configuration (never
    /// free-form argv).
    pub repository: String,
    /// Explicit target host identity token (never inferred).
    pub host: String,
    /// Explicit host availability observation; `None` = unknown (a hold).
    pub host_available: Option<bool>,
    /// Harness key the run fans out on (the per-harness cap axis).
    pub harness_key: String,
    /// Attested active-lane count on that harness; `None` = unknown (a
    /// hold — missing occupancy is never assumed to be zero).
    pub harness_lanes: Option<i64>,
    /// Admitted concurrency caps for the fan-out.
    pub caps: ConcurrencyCaps,
    /// Workflow id bound by the run.
    pub workflow_id: String,
    /// 64-hex workflow hash bound by the run.
    pub workflow_hash: String,
    /// Presented `hf-profile-binding/v1` document: the role-configuration
    /// revision the human reviewed (credential digests ride along).
    pub role_config: Val,
    /// The allowed completion boundary.
    pub boundary: Boundary,
    /// The declared executable step spine.
    pub steps: Vec<PlannedStep>,
    /// The selected issue set.
    pub selected: Vec<SelectedIssue>,
}

/// One named hold: a prerequisite the preview refuses to treat as ready.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hold {
    /// Stable code (`preview.*` or a reused `refusal.*` code).
    pub code: &'static str,
    /// The subject the hold names (host, harness, credential, step id,
    /// boundary, or an issue identity).
    pub subject: String,
    /// Bounded human message.
    pub message: String,
}

/// One rendered preview.
#[derive(Clone, Debug)]
pub struct QueuePreview {
    /// The `hf-queue-preview/v1` document.
    pub doc: Val,
    /// sha256 (64-hex) over the canonical bytes of the bound-input document
    /// (the rendered `request`).
    pub digest: String,
    /// True only when no hold was recorded anywhere in the preview: host
    /// availability, occupancy, credentials, concurrency, boundary policy,
    /// workflow/steps and every item's dependency/revision checks passed. It
    /// never claims a start happened and never hides an active run.
    pub ready: bool,
}

/// The digest of one bound-input document (sha256 over canonical bytes).
pub fn digest_of(document: &Val) -> String {
    sha256_hex(&canonical_bytes(document))
}

/// Apply the exact-digest authorization rule to one presented digest: an
/// authorization binds the preview digest, so any input change moves the
/// digest and a stale authorization is refused before anything runs.
pub fn confirm(preview: &QueuePreview, presented: &str) -> Result<(), PreviewError> {
    if presented == preview.digest {
        return Ok(());
    }
    Err(PreviewError::new(
        "refusal.plan.stale",
        "the presented preview digest does not match the current preview: an input (a selected \
         spec revision, the host, the workflow pin, the role-configuration revision, the allowed \
         completion boundary, the selection or a dependency edge) moved; render a fresh preview \
         and authorize its digest",
    ))
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

struct ValidatedBoundary {
    phase: String,
    integration_branch: String,
    completion_branch: String,
    caps: Vec<String>,
}

struct ValidatedStep {
    id: String,
    kind: String,
    params: Option<Val>,
}

struct ValidatedIssue {
    id: IssueId,
    title: Option<String>,
    revision: String,
    requires: Vec<IssueId>,
}

/// One lane leg a plan binds (issue #210): the identity strings derived from
/// `(issue, role, round)` alone — never from a run, a generation or the
/// substrate — so the derivation is stable across retries, identical across
/// the generations that reclaim one issue, and visible in the rendered plan.
#[derive(Clone, Debug)]
pub struct LaneLeg {
    /// The issue number the leg belongs to.
    pub issue: u64,
    /// `implementer` | `reviewer`.
    pub role: String,
    /// Positive lane round.
    pub round: u64,
    /// Registered Herdr agent name (`impl-<N>`, `rev-<N>-r<R>`, …).
    pub agent: String,
    /// Workspace label (`<N>-impl`, `<N>-rev<R>`, …).
    pub workspace: String,
    /// Lane checkout relative to the worktrees root (`issues-<N>`, …).
    pub checkout: String,
}

fn lane_leg(issue: u64, role: &str, round: u64) -> Option<LaneLeg> {
    if issue == 0 || round == 0 || !matches!(role, "implementer" | "reviewer") {
        return None;
    }
    let (agent, workspace) = crate::lane::lane_names(issue, role, round);
    Some(LaneLeg {
        issue,
        role: role.to_string(),
        round,
        agent,
        workspace,
        checkout: crate::lane::lane_checkout(issue, role, round),
    })
}

fn lane_leg_doc(leg: &LaneLeg) -> Val {
    object(vec![
        ("issue", integer(leg.issue as i64)),
        ("role", string(&leg.role)),
        ("round", integer(leg.round as i64)),
        ("agent", string(&leg.agent)),
        ("workspace", string(&leg.workspace)),
        ("checkout", string(&leg.checkout)),
    ])
}

/// The declared lanes of one plan and the role skills each is given (issue
/// #267): the implementer leg of every selected issue (round 1 — the run's
/// own lane) and the reviewer leg of every self-dispatching review step. The
/// legs are derived from the SAME facts the per-step lane render uses, so a
/// rendered lane and a declared leg can never disagree about which lane a
/// leg holds; the skills are the leg's role binding's resolved pins (the
/// implementer leg's from the run's reviewed role binding, the reviewer
/// leg's from the registry-resolved binding its review step declares).
fn legs_doc(request: &Validated) -> Val {
    let mut legs: Vec<Val> = Vec::new();
    for issue in &request.selected {
        let Some(leg) = lane_leg(issue.id.number as u64, "implementer", 1) else {
            continue;
        };
        legs.push(object(vec![
            ("issue", integer(leg.issue as i64)),
            ("role", string(&leg.role)),
            ("round", integer(leg.round as i64)),
            ("agent", string(&leg.agent)),
            ("workspace", string(&leg.workspace)),
            ("checkout", string(&leg.checkout)),
            ("skills", skill_names(&request.role.skills)),
        ]));
    }
    for (step_id, leg) in &request.reviewer_lanes {
        let pins = request
            .reviewer_skills
            .iter()
            .find(|(id, _)| id == step_id)
            .map(|(_, pins)| pins.as_slice())
            .unwrap_or_default();
        legs.push(object(vec![
            ("issue", integer(leg.issue as i64)),
            ("role", string(&leg.role)),
            ("round", integer(leg.round as i64)),
            ("agent", string(&leg.agent)),
            ("workspace", string(&leg.workspace)),
            ("checkout", string(&leg.checkout)),
            ("skills", skill_names(pins)),
        ]));
    }
    Val::Arr(legs)
}

/// The plan-visible NAMES of one leg's role skills (issue #267).
fn skill_names(pins: &[crate::config::SkillPin]) -> Val {
    Val::Arr(pins.iter().map(|pin| string(&pin.key)).collect())
}

/// The lane leg one step binds, for the rendered plan (issue #210): the
/// validated reviewer lane of a self-dispatching review step, otherwise the
/// implementer leg whose checkout the step declares — or, for the bind step
/// itself (`harness_start`) of a single-issue run, the implementer leg that
/// step resolves. `None` renders as JSON null: a step that binds no lane.
fn step_lane(
    review_lanes: &[(String, LaneLeg)],
    step_id: &str,
    kind: &str,
    params: Option<&Val>,
    selected: &[ValidatedIssue],
) -> Option<LaneLeg> {
    if let Some((_, leg)) = review_lanes.iter().find(|(id, _)| id == step_id) {
        return Some(leg.clone());
    }
    let implementer_legs: Vec<LaneLeg> = selected
        .iter()
        .filter_map(|issue| lane_leg(issue.id.number as u64, "implementer", 1))
        .collect();
    if let Some(checkout) = params
        .and_then(|params| params.get("worktree"))
        .and_then(Val::as_str)
    {
        return implementer_legs
            .into_iter()
            .find(|leg| leg.checkout == checkout);
    }
    if kind == "harness_start" && step_is_pane_substrate(params) && implementer_legs.len() == 1 {
        return implementer_legs.into_iter().next();
    }
    None
}

/// Whether one step declares the pane substrate (which registers a lane
/// workspace): `herdr` unless the step selects the bare-subprocess fallback
/// explicitly. A token outside the closed set is left to the effect's own
/// typed refusal.
fn step_is_pane_substrate(params: Option<&Val>) -> bool {
    matches!(
        params
            .and_then(|params| params.get("execution"))
            .and_then(Val::as_str),
        None | Some("herdr")
    )
}

/// The positive `lane_round` a step declares (`None` when the step declares an
/// invalid one; the effect refuses that typed).
fn step_lane_round(params: &Val) -> Option<u64> {
    match params.get("lane_round") {
        None => Some(1),
        Some(Val::Int(round)) if *round > 0 => Some(*round as u64),
        Some(_) => None,
    }
}

/// The per-leg lane identity rule of the reviewed spine (issue #210).
///
/// ONE lane checkout belongs to exactly ONE leg. The derivation is
/// `(issue, role, round)` only, so distinct legs derive distinct checkouts by
/// construction — but a plan can still DECLARE a step that would bind a
/// sibling leg's checkout, and the measured live defect (`p6-132`'s reviewer
/// leg binding the implementer lane's `issues-132`) was exactly that shape:
/// the collision was only discovered at dispatch, by the substrate, as
/// `refusal.lane.name_collision`. That plan is refused HERE, at preview time,
/// with a typed code naming both identities.
///
/// Returns the reviewer lane each self-dispatching review step binds (the pane
/// substrate materializes the reviewer's OWN lane at that checkout; the
/// bare-subprocess fallback runs in the integration checkout and keeps the
/// run's lane checkout).
fn validate_lane_identities(
    steps: &[ValidatedStep],
    selected: &[ValidatedIssue],
) -> Result<Vec<(String, LaneLeg)>, PreviewError> {
    let issues: Vec<u64> = selected
        .iter()
        .map(|issue| issue.id.number as u64)
        .collect();
    // The legs this plan declares, for naming the owner of a checkout.
    let mut declared: Vec<LaneLeg> = Vec::new();
    for number in &issues {
        if let Some(leg) = lane_leg(*number, "implementer", 1) {
            declared.push(leg);
        }
    }
    for step in steps {
        let Some(params) = step.params.as_ref() else {
            continue;
        };
        if step.kind != "review_evidence"
            || params.get("reviewer_profile").is_none()
            || !step_is_pane_substrate(step.params.as_ref())
        {
            continue;
        }
        let Some(round) = step_lane_round(params) else {
            continue;
        };
        for number in &issues {
            if let Some(leg) = lane_leg(*number, "reviewer", round) {
                declared.push(leg);
            }
        }
    }
    let mut reviewer_lanes: Vec<(String, LaneLeg)> = Vec::new();
    for step in steps {
        let Some(params) = step.params.as_ref() else {
            continue;
        };
        if step.kind != "review_evidence"
            || params.get("reviewer_profile").is_none()
            || !step_is_pane_substrate(step.params.as_ref())
        {
            continue;
        }
        let Some(round) = step_lane_round(params) else {
            continue;
        };
        let Some(declared_checkout) = params.get("worktree").and_then(Val::as_str) else {
            continue;
        };
        let own = issues.iter().find_map(|number| {
            lane_leg(*number, "reviewer", round).filter(|leg| leg.checkout == declared_checkout)
        });
        if let Some(leg) = own {
            reviewer_lanes.push((step.id.clone(), leg));
            continue;
        }
        let owner = declared
            .iter()
            .find(|leg| leg.checkout == declared_checkout)
            .cloned();
        let own_identity = owner
            .as_ref()
            .and_then(|owner| lane_leg(owner.issue, "reviewer", round));
        return Err(PreviewError::new(
            "usage.queue_lane_identity",
            format!(
                "step {:?} would bind the lane checkout {declared_checkout:?} for its reviewer leg \
                 (lane_round {round}), which is {}; the reviewer leg of that run binds its own lane \
                 checkout {}. One lane checkout belongs to exactly one leg, so this plan is refused \
                 before submission instead of colliding at dispatch",
                step.id,
                match &owner {
                    Some(owner) => format!(
                        "the lane of the {} leg {:?} ({:?})",
                        owner.role, owner.agent, owner.workspace
                    ),
                    None => "not a lane checkout of any leg this plan selects".to_string(),
                },
                match &own_identity {
                    Some(leg) => format!(
                        "{:?} (agent {:?}, workspace {:?})",
                        leg.checkout, leg.agent, leg.workspace
                    ),
                    None => format!("issues-<N>-rev{round}"),
                },
            ),
        ));
    }
    Ok(reviewer_lanes)
}

struct Validated {
    repository: String,
    host: String,
    host_available: Option<bool>,
    harness_key: String,
    harness_lanes: Option<i64>,
    caps: ConcurrencyCaps,
    workflow_id: String,
    workflow_hash: String,
    role: ProfileBinding,
    boundary: ValidatedBoundary,
    steps: Vec<ValidatedStep>,
    selected: Vec<ValidatedIssue>,
    /// The reviewer lane each self-dispatching review step binds (issue #210),
    /// validated at preview time.
    reviewer_lanes: Vec<(String, LaneLeg)>,
    /// The reviewer leg's declared role skills (issue #267), read from the
    /// registry-resolved binding the review step declares: `(step id, pins)`.
    reviewer_skills: Vec<(String, Vec<crate::config::SkillPin>)>,
}

/// A bounded branch name: non-empty, no whitespace/control characters, no
/// leading/trailing separator and no `.`/`..` components.
fn is_branch_name(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 255
        && !text.starts_with('/')
        && !text.ends_with('/')
        && !text.contains("..")
        && text != "."
        && !text
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || c == '\\' || c == '~' || c == '^')
}

fn validate_boundary(boundary: &Boundary) -> Result<ValidatedBoundary, PreviewError> {
    if !GRANT_PHASES.contains(&boundary.phase.as_str()) {
        return Err(PreviewError::new(
            "usage.queue_boundary",
            "the allowed completion boundary phase must be one of the closed grant phases",
        ));
    }
    if !is_branch_name(&boundary.integration_branch) || !is_branch_name(&boundary.completion_branch)
    {
        return Err(PreviewError::new(
            "usage.queue_boundary",
            "the integration and completion branches must be bounded branch names",
        ));
    }
    let mut caps: Vec<String> = Vec::new();
    for cap in &boundary.caps {
        if !GRANT_CAPS.contains(&cap.as_str()) {
            return Err(PreviewError::new(
                "usage.queue_boundary",
                "every boundary capability must be one of the closed grant capabilities",
            ));
        }
        if !caps.contains(cap) {
            caps.push(cap.clone());
        }
    }
    Ok(ValidatedBoundary {
        phase: boundary.phase.clone(),
        integration_branch: boundary.integration_branch.clone(),
        completion_branch: boundary.completion_branch.clone(),
        caps,
    })
}

fn validate_request(request: &QueueRequest) -> Result<Validated, PreviewError> {
    if !formats::is_repository_identity(&request.repository) {
        return Err(PreviewError::new(
            "usage.queue_repository",
            "the explicit repository must be an owner/name identity sourced from configuration",
        ));
    }
    let repository = request.repository.to_ascii_lowercase();
    if !is_bare_token(&request.host) || request.host.chars().count() > 64 {
        return Err(PreviewError::new(
            "usage.queue_host",
            "the explicit host must be a bounded bare token (1-64 characters, no whitespace or \
             path separators)",
        ));
    }
    if !formats::is_slug(&request.harness_key) {
        return Err(PreviewError::new(
            "usage.queue_harness",
            "the harness key must be a lowercase slug (the per-harness cap axis)",
        ));
    }
    if let Some(lanes) = request.harness_lanes
        && lanes < 0
    {
        return Err(PreviewError::new(
            "usage.queue_occupancy",
            "the attested harness occupancy must be a non-negative lane count",
        ));
    }
    if !formats::is_slug(&request.workflow_id) || !formats::is_hex64(&request.workflow_hash) {
        return Err(PreviewError::new(
            "usage.queue_workflow",
            "the workflow binding requires a lowercase workflow id and a 64-hex content hash",
        ));
    }
    let role = ProfileBinding::from_doc(&request.role_config)
        .map_err(|err| PreviewError::new(err.code(), err.message().to_string()))?;
    if role.key != request.harness_key {
        return Err(PreviewError::new(
            "usage.queue_role_config",
            format!(
                "the presented role-configuration binding is for {:?}, not the declared harness \
                 {:?}",
                role.key, request.harness_key
            ),
        ));
    }
    let boundary = validate_boundary(&request.boundary)?;
    if request.steps.len() > STEPS_MAX {
        return Err(PreviewError::new(
            "usage.queue_steps",
            format!("the declared step spine carries more than {STEPS_MAX} steps"),
        ));
    }
    let mut step_ids: BTreeSet<&str> = BTreeSet::new();
    let mut reviewer_skills: Vec<(String, Vec<crate::config::SkillPin>)> = Vec::new();
    for step in &request.steps {
        if !formats::is_slug(&step.id) {
            return Err(PreviewError::new(
                "usage.queue_steps",
                "every declared step id must be a lowercase slug",
            ));
        }
        if !step_ids.insert(step.id.as_str()) {
            return Err(PreviewError::new(
                "usage.queue_steps",
                format!("the declared step id {:?} appears twice", step.id),
            ));
        }
        if let Some(Val::Obj(params)) = &step.params
            && !params.keys().all(|key| formats::is_step_param_name(key))
        {
            return Err(PreviewError::new(
                "usage.queue_steps",
                format!(
                    "step {:?} carries a param name outside [a-z][a-z0-9_-]*",
                    step.id
                ),
            ));
        }
        // Issue #193: a review step that declares the reviewer leg carries
        // the registry-resolved reviewer binding, and the preview validates
        // it here (the same closed `hf-profile-binding/v1` shape the daemon
        // re-validates at the boundary) so an ill-formed reviewer role
        // refuses before the plan is ever reviewed or submitted.
        if let Some(Val::Obj(params)) = &step.params
            && let Some(binding) = params.get("reviewer_profile")
        {
            if step.kind != "review_evidence" {
                return Err(PreviewError::new(
                    "usage.queue_steps",
                    format!(
                        "step {:?} declares params.reviewer_profile but its kind is {:?}; the \
                         reviewer leg belongs to a review_evidence step",
                        step.id, step.kind
                    ),
                ));
            }
            // Issue #267: the reviewer leg's declared role skills ride the
            // registry-resolved binding the step declares — the SAME document
            // the engine dispatches, so the plan names exactly what the lane
            // is given.
            match crate::config::ProfileBinding::from_doc(binding) {
                Ok(profile) => reviewer_skills.push((step.id.clone(), profile.skills)),
                Err(err) => {
                    return Err(PreviewError::new(
                        "usage.queue_reviewer",
                        format!(
                            "step {:?} presents a reviewer binding that is not a valid \
                             hf-profile-binding/v1 document: {}",
                            step.id,
                            err.message()
                        ),
                    ));
                }
            }
        }
    }
    if request.selected.is_empty() {
        return Err(PreviewError::new(
            "usage.queue_selected",
            "the preview requires an explicit non-empty selected-issue set",
        ));
    }
    if request.selected.len() > SELECTED_MAX {
        return Err(PreviewError::new(
            "usage.queue_selected",
            format!("the selected-issue set carries more than {SELECTED_MAX} entries"),
        ));
    }
    let mut merged: BTreeMap<IssueId, (Option<String>, String, BTreeSet<IssueId>)> =
        BTreeMap::new();
    for presented in &request.selected {
        let id = IssueId::parse(&presented.id, &repository)?;
        if id.repository != repository {
            return Err(PreviewError::new(
                "usage.queue_scope",
                format!(
                    "the selected issue {} is outside the explicit repository {:?}; \
                     cross-repository work is a linked dependency, never selected scope",
                    id.display(),
                    repository
                ),
            ));
        }
        if !formats::is_hex40(&presented.revision) {
            return Err(PreviewError::new(
                "usage.queue_issue",
                format!(
                    "the selected issue {} must carry an exact 40-hex spec revision",
                    id.display()
                ),
            ));
        }
        let requires: BTreeSet<IssueId> = presented
            .requires
            .iter()
            .map(|text| IssueId::parse(text, &repository))
            .collect::<Result<_, _>>()?;
        match merged.entry(id.clone()) {
            Entry::Vacant(slot) => {
                slot.insert((
                    presented.title.clone(),
                    presented.revision.clone(),
                    requires,
                ));
            }
            Entry::Occupied(mut slot) => {
                let (title, revision, dependencies) = slot.get_mut();
                if *revision != presented.revision {
                    return Err(PreviewError::new(
                        "usage.queue_issue",
                        format!(
                            "the selected issue {} is presented twice with conflicting spec \
                             revisions",
                            id.display()
                        ),
                    ));
                }
                if title.is_none() {
                    *title = presented.title.clone();
                }
                dependencies.extend(requires);
            }
        }
    }
    let selected: Vec<ValidatedIssue> = merged
        .into_iter()
        .map(|(id, (title, revision, requires))| ValidatedIssue {
            id,
            title,
            revision,
            requires: requires.into_iter().collect(),
        })
        .collect();
    let steps: Vec<ValidatedStep> = request
        .steps
        .iter()
        .map(|step| ValidatedStep {
            id: step.id.clone(),
            kind: step.kind.clone(),
            params: step.params.clone(),
        })
        .collect();
    // Issue #210: ONE lane checkout belongs to exactly ONE leg. The per-leg
    // derivation is visible in the rendered plan and a plan that would bind a
    // sibling leg's checkout is refused HERE, before submission, instead of
    // colliding at dispatch.
    let reviewer_lanes = validate_lane_identities(&steps, &selected)?;
    Ok(Validated {
        repository,
        host: request.host.clone(),
        host_available: request.host_available,
        harness_key: request.harness_key.clone(),
        harness_lanes: request.harness_lanes,
        caps: request.caps,
        workflow_id: request.workflow_id.clone(),
        workflow_hash: request.workflow_hash.clone(),
        role,
        boundary,
        steps,
        selected,
        reviewer_lanes,
        reviewer_skills,
    })
}

// ---------------------------------------------------------------------------
// Dependency ordering and classification
// ---------------------------------------------------------------------------

/// Whether `start` can reach itself through selected dependency edges
/// (a dependency cycle). Deterministic and bounded by the selected set.
fn reaches_itself(start: &IssueId, dependencies: &BTreeMap<IssueId, Vec<IssueId>>) -> bool {
    let Some(direct) = dependencies.get(start) else {
        return false;
    };
    let mut stack: Vec<&IssueId> = direct.iter().collect();
    let mut seen: BTreeSet<&IssueId> = BTreeSet::new();
    while let Some(node) = stack.pop() {
        if node == start {
            return true;
        }
        if !seen.insert(node) {
            continue;
        }
        if let Some(next) = dependencies.get(node) {
            stack.extend(next.iter());
        }
    }
    false
}

/// The dependency order (every required dependency precedes its dependent)
/// with the deterministic tie-break on the normalized identity. Nodes that
/// cannot be ordered (a cycle, or a node downstream of one) are appended in
/// identity order.
fn dependency_order(
    ids: &BTreeSet<IssueId>,
    dependencies: &BTreeMap<IssueId, Vec<IssueId>>,
) -> Vec<IssueId> {
    let mut indegree: BTreeMap<IssueId, usize> = ids.iter().map(|id| (id.clone(), 0)).collect();
    let mut dependents: BTreeMap<IssueId, Vec<IssueId>> = BTreeMap::new();
    for id in ids {
        for dependency in &dependencies[id] {
            *indegree.get_mut(id).expect("selected node") += 1;
            dependents
                .entry(dependency.clone())
                .or_default()
                .push(id.clone());
        }
    }
    let mut ready: BTreeSet<IssueId> = indegree
        .iter()
        .filter(|(_, count)| **count == 0)
        .map(|(id, _)| id.clone())
        .collect();
    let mut order: Vec<IssueId> = Vec::new();
    while let Some(id) = ready.iter().next().cloned() {
        ready.remove(&id);
        order.push(id.clone());
        for dependent in dependents.get(&id).into_iter().flatten() {
            let count = indegree.get_mut(dependent).expect("selected node");
            *count -= 1;
            if *count == 0 {
                ready.insert(dependent.clone());
            }
        }
    }
    let emitted: BTreeSet<IssueId> = order.iter().cloned().collect();
    order.extend(ids.difference(&emitted).cloned());
    order
}

/// Why one item cannot be eligible.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Block {
    /// A required dependency is not part of the selected set.
    Unresolved(IssueId),
    /// A required dependency is selected but not settled.
    Unsettled(IssueId),
    /// The item participates in a dependency cycle.
    Cycle,
}

/// One classified item after the ownership and dependency checks.
struct ClassifiedItem {
    id: IssueId,
    title: Option<String>,
    revision: String,
    requires: Vec<IssueId>,
    owned: Option<OwnedRun>,
    stale_revision: bool,
    /// The first declared requirement that is not part of the selected set
    /// (reported on every item that declares it, ownership included).
    unresolved: Option<IssueId>,
    /// Whether the item participates in a dependency cycle.
    cycle: bool,
    status: &'static str,
    block: Option<Block>,
}

/// The durable run facts an already-owned item reports (never a completion
/// claim: an active run's outcome is not known here).
struct OwnedRun {
    instance_id: String,
    status: String,
    revision: String,
    scope: String,
}

fn classify<F>(selected: &[ValidatedIssue], owned_of: F) -> Vec<ClassifiedItem>
where
    F: Fn(&IssueId, &str) -> Option<(OwnedRun, bool)>,
{
    let ids: BTreeSet<IssueId> = selected.iter().map(|issue| issue.id.clone()).collect();
    let dependencies: BTreeMap<IssueId, Vec<IssueId>> = selected
        .iter()
        .map(|issue| {
            (
                issue.id.clone(),
                issue
                    .requires
                    .iter()
                    .filter(|dependency| ids.contains(*dependency))
                    .cloned()
                    .collect(),
            )
        })
        .collect();
    let cyclic: BTreeSet<IssueId> = ids
        .iter()
        .filter(|id| reaches_itself(id, &dependencies))
        .cloned()
        .collect();

    let order = dependency_order(&ids, &dependencies);
    let mut items: BTreeMap<IssueId, ClassifiedItem> = BTreeMap::new();
    for issue in selected {
        let mut item = ClassifiedItem {
            id: issue.id.clone(),
            title: issue.title.clone(),
            revision: issue.revision.clone(),
            requires: issue.requires.clone(),
            owned: None,
            stale_revision: false,
            unresolved: issue
                .requires
                .iter()
                .find(|dependency| !ids.contains(*dependency))
                .cloned(),
            cycle: cyclic.contains(&issue.id),
            status: "eligible",
            block: None,
        };
        if let Some((run, fresh)) = owned_of(&issue.id, &issue.revision) {
            item.stale_revision = !fresh;
            item.owned = Some(run);
            item.status = "already_owned";
        } else if item.cycle {
            item.block = Some(Block::Cycle);
            item.status = "blocked";
        }
        items.insert(issue.id.clone(), item);
    }
    // Fixpoint over the dependency edges: a dependency is settled before its
    // dependent because the graph restricted to the acyclic nodes is a DAG;
    // an unsettled dependency blocks every dependent (the loop bound is the
    // selected-set size).
    for _ in 0..ids.len() + 1 {
        let mut changed = false;
        for issue in selected {
            let item = items.get(&issue.id).expect("classified");
            if item.owned.is_some() || item.block.is_some() {
                continue;
            }
            let unresolved = item.unresolved.clone();
            let block = match unresolved {
                Some(dependency) => Some(Block::Unresolved(dependency)),
                None => dependencies[&issue.id]
                    .iter()
                    .find(|dependency| items[*dependency].status != "eligible")
                    .map(|dependency| Block::Unsettled(dependency.clone())),
            };
            if let Some(block) = block {
                let item = items.get_mut(&issue.id).expect("classified");
                item.status = "blocked";
                item.block = Some(block);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    let mut classified: Vec<ClassifiedItem> = Vec::new();
    let mut emitted: BTreeSet<IssueId> = BTreeSet::new();
    for id in order {
        if emitted.insert(id.clone())
            && let Some(item) = items.remove(&id)
        {
            classified.push(item);
        }
    }
    // `dependency_order` covers every id; this guards the impossible leftover.
    for (_, item) in items {
        classified.push(item);
    }
    classified
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

fn item_scope(issue_number: i64) -> String {
    format!("worktrees/issues/{issue_number}")
}

fn hold_doc(hold: &Hold) -> Val {
    object(vec![
        ("code", string(hold.code)),
        ("subject", string(&hold.subject)),
        ("message", string(&hold.message)),
    ])
}

fn owned_doc(run: &OwnedRun) -> Val {
    object(vec![
        ("instance_id", string(&run.instance_id)),
        ("status", string(&run.status)),
        ("issue_revision", string(&run.revision)),
        ("scope", string(&run.scope)),
    ])
}

/// The bound-input document: exactly the fields the digest binds. Titles,
/// observed state and render-only derivations are deliberately absent.
fn digest_document(request: &Validated) -> Val {
    object(vec![
        ("schema", string(QUEUE_PREVIEW_SCHEMA)),
        ("repository", string(&request.repository)),
        ("host", string(&request.host)),
        (
            "workflow",
            object(vec![
                ("id", string(&request.workflow_id)),
                ("hash", string(&request.workflow_hash)),
            ]),
        ),
        (
            "role_config",
            object(vec![
                ("key", string(&request.role.key)),
                ("revision", string(&request.role.revision)),
                // Issue #267: the plan names, per leg, the role skills the
                // lane is given — the implementer leg's declared procedure
                // pins ride the run's reviewed role binding, resolved against
                // the installation's own inventory (the reviewer leg's ride
                // the review step's registry-resolved binding, which is part
                // of the step params in this same document).
                (
                    "skills",
                    Val::Arr(
                        request
                            .role
                            .skills
                            .iter()
                            .map(|pin| {
                                object(vec![("key", string(&pin.key)), ("hash", string(&pin.hash))])
                            })
                            .collect(),
                    ),
                ),
            ]),
        ),
        (
            "boundary",
            object(vec![
                ("phase", string(&request.boundary.phase)),
                (
                    "caps",
                    Val::Arr(
                        request
                            .boundary
                            .caps
                            .iter()
                            .map(|cap| string(cap))
                            .collect(),
                    ),
                ),
                (
                    "completion_branch",
                    string(&request.boundary.completion_branch),
                ),
                (
                    "integration_branch",
                    string(&request.boundary.integration_branch),
                ),
            ]),
        ),
        (
            "steps",
            Val::Arr(
                request
                    .steps
                    .iter()
                    .map(|step| {
                        object(vec![
                            ("id", string(&step.id)),
                            ("kind", string(&step.kind)),
                            ("params", step.params.clone().unwrap_or_else(null)),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            "selected",
            Val::Arr(
                request
                    .selected
                    .iter()
                    .map(|issue| {
                        object(vec![
                            ("id", string(&issue.id.display())),
                            ("work_item", string(&issue.id.work_item())),
                            ("revision", string(&issue.revision)),
                            (
                                "requires",
                                Val::Arr(
                                    issue
                                        .requires
                                        .iter()
                                        .map(|dependency| string(&dependency.display()))
                                        .collect(),
                                ),
                            ),
                        ])
                    })
                    .collect(),
            ),
        ),
        // Issue #267: the plan names, per leg, the role skills the lane is
        // given — the binding that decides a lane's procedure is
        // configuration, and its resolution rides the digest.
        ("legs", legs_doc(request)),
    ])
}

/// The counted durable lanes as the admission gate's footprints (#236): the
/// SAME rows the preview counts, so the one authoritative occupancy renderer
/// (`crate::lifecycle::lane_occupants`) names exactly them. Harness occupancy
/// is client-attested and not durable state, so the per-harness axis has no
/// rows to convert.
fn lane_footprints(lanes: &[&InstanceRow]) -> Vec<crate::lifecycle::LaneFootprint> {
    lanes
        .iter()
        .map(|row| crate::lifecycle::LaneFootprint {
            repository: row.repository.clone(),
            harness_key: String::new(),
            scope: row.scope.clone(),
            issue_number: row.issue_number,
            identity: row.instance_id.clone(),
        })
        .collect()
}

/// Render the deterministic, effect-free preview of one exact selected-issue
/// run. The only read is the existing durable state read API; nothing is
/// spawned, granted, written or unpaused.
pub fn preview_queue(state: &State, request: &QueueRequest) -> Result<QueuePreview, PreviewError> {
    let request = validate_request(request)?;
    let mut instances = state
        .list_instances()
        .map_err(|err| PreviewError::new(err.code, err.message))?;
    instances.sort_by(|left, right| left.instance_id.cmp(&right.instance_id));

    let mut holds: Vec<Hold> = Vec::new();

    // Workflow: only the workflow this slice can plan is supported.
    if request.workflow_id != DOCTRINE_WORKFLOW_ID {
        holds.push(Hold {
            code: holds::WORKFLOW_UNSUPPORTED,
            subject: "workflow".to_string(),
            message: format!(
                "the pinned workflow {:?} is not supported by this preview slice (only {DOCTRINE_WORKFLOW_ID} is representable); its executable steps cannot be planned",
                request.workflow_id
            ),
        });
    }
    // Host availability: unknown is never readiness.
    match request.host_available {
        Some(true) => {}
        Some(false) => holds.push(Hold {
            code: holds::HOST_UNAVAILABLE,
            subject: request.host.clone(),
            message: format!("the target host {:?} is attested unavailable", request.host),
        }),
        None => holds.push(Hold {
            code: holds::HOST_UNAVAILABLE,
            subject: request.host.clone(),
            message: format!(
                "the target host {:?} has no availability attestation; unknown host measurements never admit new work",
                request.host
            ),
        }),
    }
    // Occupancy: missing occupancy is never assumed to be spare capacity.
    if request.harness_lanes.is_none() {
        holds.push(Hold {
            code: holds::OCCUPANCY_UNKNOWN,
            subject: request.harness_key.clone(),
            message: format!(
                "the same-harness occupancy for {:?} is not attested; missing occupancy is never treated as spare capacity",
                request.harness_key
            ),
        });
    }
    // Credentials: a declared credential the reviewed profile binds as unset.
    for (name, digest) in &request.role.secrets {
        if digest.as_str() == PROFILE_SECRET_UNSET {
            holds.push(Hold {
                code: holds::AUTH_MISSING,
                subject: name.clone(),
                message: format!(
                    "the declared credential {name:?} is unset in the bound profile configuration; the harness cannot authenticate"
                ),
            });
        }
    }

    // Concurrency: the same capacity semantics the fan-out gate enforces
    // (the gate's counted-lane set against the declared caps; nothing is
    // proposed yet, so no lane is counted against itself).
    let owned_rows: Vec<&InstanceRow> = instances
        .iter()
        .filter(|row| OWNED_RUN_STATES.contains(&row.status.as_str()))
        .collect();
    // Issue #285: a run that is terminal by outcome (its diagnosed step's
    // bounded-retry budget is spent and nothing is held) can never be
    // dispatched again, so it occupies no slot here either — the SAME
    // exclusion the fan-out gate applies to its own counted set.
    let terminal: Vec<String> = state
        .retry_exhausted_run_ids()
        .map_err(|err| PreviewError::new(err.code, err.message))?;
    let counted: Vec<&InstanceRow> = instances
        .iter()
        .filter(|row| {
            COUNTED_RUN_STATES.contains(&row.status.as_str())
                && !terminal.contains(&row.instance_id)
        })
        .collect();
    let running_total = counted.len();
    let same_repository: Vec<&InstanceRow> = counted
        .iter()
        .copied()
        .filter(|row| row.repository == request.repository)
        .collect();
    let running_repository = same_repository.len();
    if running_total >= request.caps.global {
        holds.push(Hold {
            code: admission::CAP_GLOBAL,
            subject: "global".to_string(),
            message: format!(
                "the global concurrency cap ({}) is reached ({} active lanes: {}); fan-out refuses",
                request.caps.global,
                running_total,
                crate::lifecycle::lane_occupants(lane_footprints(&counted).iter())
            ),
        });
    }
    if running_repository >= request.caps.per_repository {
        holds.push(Hold {
            code: admission::CAP_REPOSITORY,
            subject: request.repository.clone(),
            message: format!(
                "the per-repository concurrency cap ({}) is reached for {:?} ({} active lanes: {}); fan-out refuses",
                request.caps.per_repository,
                request.repository,
                running_repository,
                crate::lifecycle::lane_occupants(lane_footprints(&same_repository).iter())
            ),
        });
    }
    if let Some(lanes) = request.harness_lanes
        && usize::try_from(lanes).unwrap_or(usize::MAX) >= request.caps.per_harness
    {
        holds.push(Hold {
            code: admission::CAP_HARNESS,
            subject: request.harness_key.clone(),
            message: format!(
                "the per-harness concurrency cap ({}) is reached ({lanes} attested lanes on harness {:?}); fan-out refuses",
                request.caps.per_harness, request.harness_key
            ),
        });
    }
    // Declared monorepo paths never overlap: an active lane already holding
    // the planned scope (other than the item's own run) refuses fan-out.
    for issue in &request.selected {
        let scope = item_scope(issue.id.number);
        for lane in &same_repository {
            if lane.issue_number == issue.id.number {
                continue;
            }
            if paths_overlap(&scope, &lane.scope) {
                holds.push(Hold {
                    code: admission::MONOREPO_OVERLAP,
                    subject: issue.id.display(),
                    message: format!(
                        "the planned scope {scope:?} overlaps the active lane scope {:?} on {}; concurrent lanes cannot overlap declared monorepo paths",
                        lane.scope, lane.instance_id
                    ),
                });
            }
        }
    }
    // Boundary policy: production-class completions stay human-only, and a
    // completion landing on a protected branch is never read as ready.
    let production_boundary = request.boundary.phase == "production"
        || request
            .boundary
            .caps
            .iter()
            .any(|cap| cap == "production" || cap == "release");
    if production_boundary
        && let Err(err) = check_production_confirmation(None, false, false, false)
    {
        holds.push(Hold {
            code: err.code,
            subject: "boundary".to_string(),
            message: err.message,
        });
    }
    if classify_branch(
        &request.boundary.completion_branch,
        &request.boundary.integration_branch,
        &[],
    ) == BranchKind::Production
    {
        holds.push(Hold {
            code: holds::PROTECTED_BRANCH,
            subject: request.boundary.completion_branch.clone(),
            message: format!(
                "the allowed completion would land on the protected branch {:?}; promotion to \
                 main/production is a human-only action this preview cannot authorize",
                request.boundary.completion_branch
            ),
        });
    }

    // Steps: the closed executable effect set and resolved bindings only.
    let mut steps_doc: Vec<Val> = Vec::new();
    for step in &request.steps {
        let supported = required_capability(&step.kind).is_some();
        let resolved = step.params.is_some();
        if !supported {
            holds.push(Hold {
                code: holds::STEP_UNSUPPORTED,
                subject: step.id.clone(),
                message: format!(
                    "step {:?} carries kind {:?}, which is outside the closed executable effect set",
                    step.id, step.kind
                ),
            });
        } else if !resolved {
            holds.push(Hold {
                code: holds::STEP_UNRESOLVED,
                subject: step.id.clone(),
                message: format!(
                    "step {:?} ({}) carries no resolved binding parameters; executing an unresolved step is not supported",
                    step.id, step.kind
                ),
            });
        }
        // Issue #210 legibility: the lane identity this step binds, derived
        // from (issue, role, round) — the reviewer leg's OWN lane included, so
        // `queue preview` shows every leg's lane before submission.
        let lane = step_lane(
            &request.reviewer_lanes,
            &step.id,
            &step.kind,
            step.params.as_ref(),
            &request.selected,
        );
        let lane_skills = match lane.as_ref().map(|leg| leg.role.as_str()) {
            Some("reviewer") => request
                .reviewer_skills
                .iter()
                .find(|(id, _)| id == &step.id)
                .map(|(_, pins)| skill_names(pins))
                .unwrap_or_else(|| skill_names(&[])),
            Some(_) => skill_names(&request.role.skills),
            None => skill_names(&[]),
        };
        steps_doc.push(object(vec![
            ("id", string(&step.id)),
            ("kind", string(&step.kind)),
            ("supported", bool_(supported)),
            ("resolved", bool_(resolved)),
            ("params", step.params.clone().unwrap_or_else(null)),
            ("lane", lane.as_ref().map(lane_leg_doc).unwrap_or_else(null)),
            ("skills", lane_skills),
        ]));
    }

    // Items: durable ownership first, then dependency readiness. A moved
    // revision is rebindable only when a later grant window explicitly binds
    // that exact selection; opaque revision hashes are never ordered — and a
    // live, non-terminal run is never presented as supersedable (issues #192,
    // #209): a run at its reviewed-evidence frontier is carried forward, and
    // every other live run keeps its ownership and its recorded frontier.
    let mut preserved: BTreeSet<(IssueId, String)> = BTreeSet::new();
    let mut live: BTreeSet<(IssueId, String)> = BTreeSet::new();
    for issue in &request.selected {
        if let Some(owner) = owned_rows.iter().copied().find(|row| {
            row.repository == issue.id.repository
                && row.issue_number == issue.id.number
                && row.issue_revision != issue.revision
        }) {
            let authorized = state
                .revision_has_newer_grant(
                    &issue.id.repository,
                    issue.id.number,
                    &issue.revision,
                    &owner.grant_id,
                )
                .map_err(|err| PreviewError::new(err.code, err.message))?;
            if authorized {
                // The later window alone never authorizes a supersession: the
                // frontier read below is the SAME durable fact the submission
                // transaction enforces, so the preview never presents a rebind
                // the admission would refuse.
                if state
                    .run_reached_review_frontier(&owner.instance_id)
                    .map_err(|err| PreviewError::new(err.code, err.message))?
                {
                    preserved.insert((issue.id.clone(), issue.revision.clone()));
                } else {
                    live.insert((issue.id.clone(), issue.revision.clone()));
                }
            }
        }
    }
    let owned_of = |id: &IssueId, revision: &str| -> Option<(OwnedRun, bool)> {
        let rows: Vec<&InstanceRow> = owned_rows
            .iter()
            .copied()
            .filter(|row| row.repository == id.repository && row.issue_number == id.number)
            .collect();
        let witness = rows.first()?;
        let settled = rows.iter().any(|row| row.issue_revision == revision);
        Some((
            OwnedRun {
                instance_id: witness.instance_id.clone(),
                status: witness.status.clone(),
                revision: witness.issue_revision.clone(),
                scope: witness.scope.clone(),
            },
            settled,
        ))
    };
    let classified = classify(&request.selected, owned_of);

    let mut items_doc: Vec<Val> = Vec::new();
    let mut item_holds = 0usize;
    for item in &classified {
        let mut item_level: Vec<Hold> = Vec::new();
        if let Some(run) = &item.owned
            && item.stale_revision
        {
            // Issues #192/#209: a later window may authorize a rebind, but a
            // live, non-terminal run is never presented as supersedable — a
            // run at its reviewed-evidence frontier is carried forward, and
            // every other live run keeps its ownership and its recorded
            // frontier. Each case is reported with its own code so the
            // operator is told the exact deliberate path (an audited release),
            // never a stale "no later window" claim.
            item_level.push(
                if preserved.contains(&(item.id.clone(), item.revision.clone())) {
                    Hold {
                        code: holds::FRONTIER_PRESERVED,
                        subject: item.id.display(),
                        message: format!(
                            "run {} has reached its review_evidence frontier; the verified spine is carried forward and a fresh submission never supersedes it — release the run explicitly to replace it",
                            run.instance_id
                        ),
                    }
                } else if live.contains(&(item.id.clone(), item.revision.clone())) {
                    Hold {
                        code: holds::LIVE_RUN,
                        subject: item.id.display(),
                        message: format!(
                            "run {} is live with frontier {}; a fresh submission never supersedes a live run — the incumbent keeps its ownership and its recorded frontier (release the run explicitly to replace it)",
                            run.instance_id,
                            state
                                .run_frontier_summary(&run.instance_id)
                                .map_err(|err| PreviewError::new(err.code, err.message))?
                        ),
                    }
                } else {
                    Hold {
                        code: holds::REVISION_STALE,
                        subject: item.id.display(),
                        message: format!(
                            "the selected spec revision {} differs from active run {} at {}; no later grant window authorizes this exact revision, so only the older authorization remains",
                            item.revision, run.instance_id, run.revision
                        ),
                    }
                },
            );
        }
        // Declared dependency facts are reported on every item that declares
        // them (ownership included): an unresolved reference or a cycle is
        // never hidden by an existing run's status.
        if let Some(dependency) = &item.unresolved {
            item_level.push(Hold {
                code: holds::DEPENDENCY_UNRESOLVED,
                subject: item.id.display(),
                message: format!(
                    "the required dependency {} is not part of the selected set; it is shown as an unresolved requirement and is never added to scope",
                    dependency.display()
                ),
            });
        } else if item.cycle {
            item_level.push(Hold {
                code: holds::DEPENDENCY_CYCLE,
                subject: item.id.display(),
                message: "the required dependencies form a cycle; the item cannot be ordered"
                    .to_string(),
            });
        } else if let Some(Block::Unsettled(dependency)) = &item.block {
            item_level.push(Hold {
                code: holds::DEPENDENCY_UNSETTLED,
                subject: item.id.display(),
                message: format!(
                    "the required dependency {} is selected but not settled (status {}); the dependent item stays blocked",
                    dependency.display(),
                    item_status(&classified, dependency)
                ),
            });
        }
        item_holds += item_level.len();
        items_doc.push(object(vec![
            ("id", string(&item.id.display())),
            ("work_item", string(&item.id.work_item())),
            (
                "title",
                item.title.as_deref().map(string).unwrap_or_else(null),
            ),
            ("revision", string(&item.revision)),
            (
                "requires",
                Val::Arr(
                    item.requires
                        .iter()
                        .map(|dependency| string(&dependency.display()))
                        .collect(),
                ),
            ),
            ("status", string(item.status)),
            (
                "owned",
                item.owned.as_ref().map(owned_doc).unwrap_or_else(null),
            ),
            ("holds", Val::Arr(item_level.iter().map(hold_doc).collect())),
        ]));
    }

    let lanes_doc: Vec<Val> = same_repository
        .iter()
        .take(RUNNING_LANES_MAX)
        .map(|row| {
            object(vec![
                ("instance_id", string(&row.instance_id)),
                (
                    "id",
                    string(&format!("{}#{}", row.repository, row.issue_number)),
                ),
                ("status", string(&row.status)),
                ("scope", string(&row.scope)),
            ])
        })
        .collect();
    let concurrency_doc = object(vec![
        ("harness", string(&request.harness_key)),
        (
            "caps",
            object(vec![
                ("global", integer(request.caps.global as i64)),
                ("repository", integer(request.caps.per_repository as i64)),
                ("harness", integer(request.caps.per_harness as i64)),
            ]),
        ),
        (
            "running",
            object(vec![
                ("total", integer(running_total as i64)),
                ("repository", integer(running_repository as i64)),
                (
                    "harness_lanes",
                    request.harness_lanes.map(integer).unwrap_or_else(null),
                ),
            ]),
        ),
        ("lanes", Val::Arr(lanes_doc)),
        (
            "overflow",
            integer(same_repository.len().saturating_sub(RUNNING_LANES_MAX) as i64),
        ),
    ]);

    let bound_inputs = digest_document(&request);
    let digest = digest_of(&bound_inputs);
    let ready = holds.is_empty() && item_holds == 0;
    let doc = object(vec![
        ("schema", string(QUEUE_PREVIEW_SCHEMA)),
        (
            "boundaries",
            object(vec![
                ("mutates", bool_(false)),
                ("spawns", bool_(false)),
                ("grants", bool_(false)),
                ("persists", bool_(false)),
                ("resumes", bool_(false)),
                ("statement", string(NO_EFFECTS_STATEMENT)),
            ]),
        ),
        ("request", bound_inputs),
        ("items", Val::Arr(items_doc)),
        ("steps", Val::Arr(steps_doc)),
        ("concurrency", concurrency_doc),
        ("holds", Val::Arr(holds.iter().map(hold_doc).collect())),
        ("ready", bool_(ready)),
        ("digest", string(&digest)),
    ]);
    Ok(QueuePreview { doc, digest, ready })
}

/// The status name of one classified dependency (for hold messages).
fn item_status(items: &[ClassifiedItem], id: &IssueId) -> &'static str {
    items
        .iter()
        .find(|item| &item.id == id)
        .map(|item| item.status)
        .unwrap_or("unknown")
}
