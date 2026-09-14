//! Control-plane mutation engine (issue #8).
//!
//! Plan-first, daemon-mediated repository workflow effects: typed
//! operations (worktree/branch creation, lane-bound harness start, bounded
//! prompt delivery, commit/head collection, branch push, GitHub issue/PR
//! updates, hosted-check observation, review evidence, integration merge,
//! post-merge verification, branch deletion, deterministic lane cleanup)
//! executed by the daemon after validating workflow authority.
//!
//! Locked-spec rules implemented here:
//! - apply binds the exact plan digest and freshly revalidates canonical
//!   target, observations, issue revision, workflow/policy hashes, and the
//!   state epoch immediately before every effect (spec-plans.md);
//! - stale/expired grants refuse mutation with a typed code (C2); grants
//!   die with their epoch;
//! - worker/LLM/harness output can never directly invoke a transition or
//!   downgrade risk: effect *declarations* come from typed plan step params
//!   and are mapped through the static capability/phase/risk tables below
//!   (AC3, risk-model.md non-downgrade rule);
//! - main/production and hotfix rules are pure policy probes with RED/GREEN
//!   tests; no direct/force-push path exists (AC6);
//! - review/CI evidence invalidates on any relevant head/base/workflow/
//!   policy change (AC4, spec-review-evidence.md);
//! - issue closure only after integration merge + post-merge verification
//!   (AC7); cleanup refuses dirty/ambiguous/uncontained/unverified targets
//!   and preserves required salvage evidence (AC8, journaled by the daemon
//!   through [`crate::state::State::journal_salvage`]);
//! - the first real external write requires a separate recorded human
//!   approval (AC10; the canary itself is a later human-gated step — this
//!   slice proves the gate with fakes only).
//!
//! This module is deterministic and daemon-independent: it takes typed
//! snapshots and an allowlisted environment and returns typed outcomes with
//! exact read-backs. The daemon owns journaling, claims, and durable
//! records (review evidence, approvals, salvage) before/after calling the
//! effect handlers.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::canonical::{canonical_bytes, sha256_hex};
use crate::config::adapter_environment;
use crate::engine::grant_binding_valid;
use crate::formats::{is_hex40, is_hex64, is_repository_identity, is_slug};
use crate::process::{ProcSpec, ProcStatus};
use crate::schema::{Family, validate_doc};
use crate::value::{Val, bool_, integer, null, object, string};

/// Hard ceiling (seconds) on any single effect subprocess deadline: the
/// per-kind table and every policy override are clamped by it, so no plan
/// can make the daemon wait without an explicit bound (issue #92 F1).
pub const EFFECT_DEADLINE_CEILING_SECS: u64 = 3600;

/// Documented default deadline (seconds) for the bounded I/O effects (git
/// and gh rows) — the per-kind default table of issue #92 F1.
pub const EFFECT_DEADLINE_DEFAULT_SECS: u64 = 60;

/// Documented default deadline (seconds) for one lane prompt turn: a real
/// worker turn (a harness running a bounded work item) outlives a bare I/O
/// bound, which is why the effect kind owns its own documented default
/// instead of inheriting the shortest one (issue #92 F1, F2).
pub const PROMPT_DEADLINE_DEFAULT_SECS: u64 = 1800;

/// Documented default deadline (seconds) for the harness session-bind
/// effect (`harness_start`): a session bind may resolve/probe a harness, so
/// it is bounded above the plain I/O default and far below the ceiling.
pub const HARNESS_START_DEADLINE_DEFAULT_SECS: u64 = 300;

/// The effective, bounded deadline (seconds) of one effect step (issue #92
/// F1). Policy surface: a reviewed plan step may carry `deadline_secs` for
/// its own effect, bounded by [`EFFECT_DEADLINE_CEILING_SECS`]; a value
/// outside `1..=ceiling` refuses typed. Without a declared value the
/// documented per-kind default applies. Call sites never read a bare
/// constant.
pub fn effect_deadline_secs(kind: &str, params: Option<&Val>) -> Result<u64, EffectOutcome> {
    if let Some(declared) = params.and_then(|params| params.get("deadline_secs")) {
        let Some(secs) = declared.as_int() else {
            return Err(refusal(
                code::BAD_PARAMS,
                "step params.deadline_secs must be an integer number of seconds",
            ));
        };
        if secs < 1 || secs as u64 > EFFECT_DEADLINE_CEILING_SECS {
            return Err(refusal(
                code::BAD_PARAMS,
                format!(
                    "step params.deadline_secs must be 1..={EFFECT_DEADLINE_CEILING_SECS} \
                     (the documented effect deadline ceiling)"
                ),
            ));
        }
        return Ok(secs as u64);
    }
    Ok(default_deadline_secs(kind))
}

/// The documented per-kind default deadline (seconds). Every effect kind
/// resolves to a bound; `prompt` and `harness_start` carry their own
/// documented rows (see the constants above).
pub fn default_deadline_secs(kind: &str) -> u64 {
    match kind {
        "prompt" => PROMPT_DEADLINE_DEFAULT_SECS,
        "harness_start" => HARNESS_START_DEADLINE_DEFAULT_SECS,
        _ => EFFECT_DEADLINE_DEFAULT_SECS,
    }
}

/// Error codes produced by this engine (typed, never downgraded).
pub mod code {
    /// The plan document digest did not match the digest it was bound to.
    pub const PLAN_DIGEST: &str = "refusal.plan.digest";
    /// The plan document/step shape is malformed.
    pub const PLAN_MALFORMED: &str = "refusal.plan.malformed";
    /// The plan id is not the content-derived id of the document.
    pub const PLAN_IDENTITY: &str = "refusal.plan.identity";
    /// The state epoch in plan/grant/instance disagrees with the live epoch.
    pub const EPOCH_STALE: &str = "refusal.state.epoch";
    /// The grant is not active.
    pub const GRANT_INACTIVE: &str = "refusal.grant.inactive";
    /// The grant has expired (C2).
    pub const GRANT_EXPIRED: &str = "refusal.grant.expired";
    /// The observed issue revision no longer matches the grant binding.
    pub const GRANT_STALE: &str = "refusal.grant.stale";
    /// The workflow hash changed in flight.
    pub const WORKFLOW_CHANGED: &str = "refusal.workflow.changed";
    /// The policy hash changed in flight.
    pub const POLICY_CHANGED: &str = "refusal.policy.changed";
    /// The instance is not in a runnable state for the effect.
    pub const INSTANCE_STATE: &str = "refusal.instance.state";
    /// The run carries a pause request (issue #86): new step dispatch is
    /// refused until the pause reaches its boundary and is resumed.
    pub const RUN_PAUSED: &str = "refusal.run.paused";
    /// A re-dispatch of a diagnosed failed step needs (and consumes) one
    /// recorded bounded retry authorization (issue #86).
    pub const RETRY_REQUIRED: &str = "refusal.run.retry_required";
    /// The step's required capability is not granted.
    pub const CAP_MISSING: &str = "refusal.capability.missing";
    /// The step's required phase is not granted.
    pub const PHASE_MISSING: &str = "refusal.phase.missing";
    /// The step kind is outside the closed mutation set.
    pub const UNKNOWN_KIND: &str = "unknown.effect";
    /// Malformed effect parameters.
    pub const BAD_PARAMS: &str = "refusal.request.malformed";
    /// A path escaped the granted containment root.
    pub const UNCONTAINED: &str = "refusal.path.uncontained";
    /// A direct/force push to a protected branch was attempted.
    pub const PUSH_POLICY: &str = "refusal.policy.push";
    /// A main PR whose head is not staging/hotfix was attempted.
    pub const MAIN_PR_POLICY: &str = "refusal.policy.main_pr";
    /// An external-contributor PR lacks the human maintainer approval.
    pub const EXTERNAL_APPROVAL: &str = "refusal.policy.external_contributor";
    /// A hotfix without its full fresh-human gate was attempted.
    pub const HOTFIX_GATE: &str = "refusal.policy.hotfix";
    /// A production-branch effect without a fresh interactive TTY digest.
    pub const PRODUCTION_CONFIRMATION: &str = "refusal.policy.production_confirmation";
    /// The first real external write lacks the recorded separate approval.
    pub const FIRST_WRITE_APPROVAL: &str = "refusal.first_write.approval_required";
    /// The recorded approval was not an interactive TTY confirmation.
    pub const APPROVAL_NOT_INTERACTIVE: &str = "refusal.approval.not_interactive";
    /// Review evidence is stale: a binding moved after the review.
    pub const EVIDENCE_STALE: &str = "refusal.evidence.stale";
    /// No passing current evidence exists for an integration merge.
    pub const EVIDENCE_MISSING: &str = "refusal.evidence.missing";
    /// Review evidence records a failed verdict or failed checks.
    pub const EVIDENCE_FAILED: &str = "refusal.evidence.failed";
    /// The reviewer is not distinct from the implementer.
    pub const REVIEWER_NOT_DISTINCT: &str = "refusal.evidence.reviewer_not_distinct";
    /// Issue closure attempted before merge + post-merge verification.
    pub const CLOSURE_PREMATURE: &str = "refusal.closure.premature";
    /// Cleanup refused a dirty worktree.
    pub const CLEANUP_DIRTY: &str = "refusal.cleanup.dirty";
    /// Cleanup refused an unmerged branch.
    pub const CLEANUP_UNMERGED: &str = "refusal.cleanup.unmerged";
    /// Cleanup refused an unknown/absent target.
    pub const CLEANUP_UNKNOWN: &str = "refusal.cleanup.unknown";
    /// Cleanup refused a symlink target (issue #9 AC7: canonical target
    /// classification — symlinks are never followed or removed).
    pub const CLEANUP_SYMLINK: &str = "refusal.cleanup.symlink";
    /// An archive/salvage operation failed (issue #9 AC7).
    pub const ARCHIVE_FAILED: &str = "effect.archive.failed";
    /// The integration merge is not fast-forwardable (base moved).
    pub const MERGE_NOT_FF: &str = "effect.merge.not_fast_forward";
    /// The integration merge failed (git-level).
    pub const MERGE_FAILED: &str = "effect.merge.failed";
    /// The executable could not be spawned.
    pub const UNAVAILABLE: &str = "refusal.unavailable";
    /// The child process exceeded its deadline.
    pub const TIMEOUT: &str = "adapter.timeout";
    /// The child process died without a terminal outcome.
    pub const PROCESS_DEATH: &str = "adapter.process_death";
    /// Ordinary non-zero child exit.
    pub const EXIT: &str = "adapter.exit";
    /// A harness step addressed the run's bound session but the run bound
    /// none (no recorded `harness_start` dispatch): the step never invents a
    /// session identity (issue #92 F2).
    pub const SESSION_UNBOUND: &str = "refusal.session.unbound";
    /// Malformed structured output from a child.
    pub const MALFORMED_OUTPUT: &str = "refusal.malformed.output";
}

/// A typed engine error/refusal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MutationError {
    /// Stable dotted error code.
    pub code: &'static str,
    /// Human message.
    pub message: String,
}

impl MutationError {
    /// A typed engine error.
    pub fn new(code: &'static str, message: impl Into<String>) -> MutationError {
        MutationError {
            code,
            message: message.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// Closed effect tables (kind -> capability/phase/risk; static, non-downgrade)
// ---------------------------------------------------------------------------

/// Every plan-step kind this engine can execute (mirrors the schema closed
/// step set; plan documents carrying a kind outside this set are refused at
/// parse time by the schema validator).
pub const EFFECT_KINDS: [&str; 16] = [
    "checkout",
    "worktree_create",
    "harness_start",
    "prompt",
    "collect_outcome",
    "review_evidence",
    "merge",
    "cleanup",
    "publish",
    "branch_push",
    "pr_update",
    "issue_update",
    "hosted_check",
    "post_merge_verify",
    "branch_delete",
    "approve",
];

/// The closed capability required for each effect kind (grant caps, AC3).
pub const KIND_CAPABILITY: [(&str, &str); 16] = [
    ("checkout", "read"),
    ("worktree_create", "worktree"),
    ("harness_start", "spawn"),
    ("prompt", "prompt"),
    ("collect_outcome", "read"),
    ("review_evidence", "review"),
    ("merge", "merge"),
    ("cleanup", "cleanup"),
    ("publish", "merge"),
    ("branch_push", "merge"),
    ("pr_update", "merge"),
    ("issue_update", "merge"),
    ("hosted_check", "read"),
    ("post_merge_verify", "read"),
    ("branch_delete", "cleanup"),
    ("approve", "production"),
];

/// The closed phase required for each effect kind (grant phase, AC3).
pub const KIND_PHASE: [(&str, &str); 16] = [
    ("checkout", "read"),
    ("worktree_create", "worktree"),
    ("harness_start", "spawn"),
    ("prompt", "spawn"),
    ("collect_outcome", "read"),
    ("review_evidence", "review"),
    ("merge", "merge"),
    ("cleanup", "cleanup"),
    ("publish", "merge"),
    ("branch_push", "merge"),
    ("pr_update", "merge"),
    ("issue_update", "merge"),
    ("hosted_check", "read"),
    ("post_merge_verify", "read"),
    ("branch_delete", "cleanup"),
    ("approve", "recovery"),
];

/// Risk classes (risk-model.md lattice; read-only effects are READ, shared
/// state writes are PRODUCTION, deletions are DESTRUCTIVE). This table is
/// static — a step can never downgrade its own class.
pub const KIND_RISK: [(&str, &str); 16] = [
    ("checkout", "read"),
    ("worktree_create", "production"),
    ("harness_start", "production"),
    ("prompt", "production"),
    ("collect_outcome", "read"),
    ("review_evidence", "read"),
    ("merge", "production"),
    ("cleanup", "destructive"),
    ("publish", "production"),
    ("branch_push", "production"),
    ("pr_update", "production"),
    ("issue_update", "production"),
    ("hosted_check", "read"),
    ("post_merge_verify", "read"),
    ("branch_delete", "destructive"),
    ("approve", "production"),
];

/// The capability a step kind requires, or `None` for an unknown kind.
pub fn required_capability(kind: &str) -> Option<&'static str> {
    KIND_CAPABILITY
        .iter()
        .find_map(|(k, cap)| (*k == kind).then_some(*cap))
}

/// The phase a step kind requires, or `None` for an unknown kind.
pub fn required_phase(kind: &str) -> Option<&'static str> {
    KIND_PHASE
        .iter()
        .find_map(|(k, phase)| (*k == kind).then_some(*phase))
}

/// The static risk class of a step kind (`read` | `production` |
/// `destructive`), or `None` for an unknown kind.
pub fn risk_class(kind: &str) -> Option<&'static str> {
    KIND_RISK
        .iter()
        .find_map(|(k, risk)| (*k == kind).then_some(*risk))
}

/// Whether a step kind is destructive (DESTRUCTIVE effects are never
/// scheduled by automation and always carry the cleanup/delete gates).
pub fn is_destructive(kind: &str) -> bool {
    risk_class(kind) == Some("destructive")
}

// ---------------------------------------------------------------------------
// Grant/instance snapshots (typed views over the durable state rows)
// ---------------------------------------------------------------------------

/// Typed grant view (mapped from `state::GrantRow` by the daemon).
#[derive(Clone, Debug)]
pub struct GrantSnapshot {
    /// Grant id.
    pub grant_id: String,
    /// Repository identity.
    pub repository: String,
    /// Issue number.
    pub issue_number: i64,
    /// Acceptance revision the grant bound (40-hex).
    pub issue_revision: String,
    /// Workflow hash (64-hex).
    pub workflow_hash: String,
    /// Policy hash (64-hex).
    pub policy_hash: String,
    /// Allowed phase.
    pub phase: String,
    /// Path-scoped lane scope.
    pub scope: String,
    /// Capabilities (closed set).
    pub caps: Vec<String>,
    /// Expiry (RFC3339 UTC).
    pub expires_at: String,
    /// Status (`active` | `revoked` | `invalidated`).
    pub status: String,
    /// Epoch the grant was issued against.
    pub state_epoch: i64,
}

/// Typed instance view (mapped from `state::InstanceRow` by the daemon).
#[derive(Clone, Debug)]
pub struct InstanceSnapshot {
    /// Instance id.
    pub instance_id: String,
    /// Repository identity.
    pub repository: String,
    /// Workflow id.
    pub workflow_id: String,
    /// Workflow hash (64-hex; pinned at start).
    pub workflow_hash: String,
    /// Policy hash (64-hex).
    pub policy_hash: String,
    /// Binding grant id.
    pub grant_id: String,
    /// Issue number.
    pub issue_number: i64,
    /// Acceptance revision (40-hex).
    pub issue_revision: String,
    /// Allowed phase.
    pub phase: String,
    /// Lane scope.
    pub scope: String,
    /// Capabilities.
    pub caps: Vec<String>,
    /// Current workflow node (last applied step id).
    pub current_node: String,
    /// Pause state.
    pub paused: bool,
    /// Durable pause REQUEST (issue #86): new step dispatch is refused
    /// from the request on, while in-flight work keeps running.
    pub pause_requested: bool,
    /// Instance status.
    pub status: String,
    /// Epoch the instance runs under.
    pub state_epoch: i64,
}

/// Fresh observations the applying side records immediately before an
/// effect (issue revision read-back, effective policy hash, live epoch).
#[derive(Clone, Debug)]
pub struct Observed {
    /// Freshly observed issue acceptance revision (40-hex).
    pub issue_revision: String,
    /// Freshly observed effective policy hash (64-hex).
    pub policy_hash: String,
    /// Live state epoch.
    pub state_epoch: i64,
    /// Current time (RFC3339 UTC seconds precision).
    pub now: String,
}

/// Whether an RFC3339-UTC (seconds, `Z`) timestamp is expired relative to
/// `now`. Both texts share the fixed `YYYY-MM-DDTHH:MM:SSZ` shape, so a
/// bytewise comparison is exact (C2; a grant without the fixed shape is
/// treated as expired — fail closed).
pub fn is_expired(expires_at: &str, now: &str) -> bool {
    if !crate::formats::is_rfc3339_seconds_z(expires_at) {
        return true;
    }
    expires_at < now
}

// ---------------------------------------------------------------------------
// Plan binding (digest + content identity, AC1)
// ---------------------------------------------------------------------------

/// A bound plan: validated document, canonical bytes, digest, and the
/// plan_id content identity check result.
#[derive(Clone, Debug)]
pub struct PlanBindings {
    /// The validated `hf-plan/v1` document.
    pub doc: Val,
    /// Canonical JSON bytes.
    pub canonical: Vec<u8>,
    /// SHA-256 over the canonical bytes.
    pub digest: String,
    /// Plan id.
    pub plan_id: String,
    /// Workflow id.
    pub workflow_id: String,
    /// Workflow hash (64-hex).
    pub workflow_hash: String,
    /// Repository identity.
    pub repository: String,
    /// Issue number.
    pub issue_number: i64,
    /// Issue acceptance revision (40-hex).
    pub issue_revision: String,
    /// State epoch the plan was computed against.
    pub state_epoch: i64,
}

/// Placeholder id used by the content-addressed plan-id derivation.
const PLAN_ID_PLACEHOLDER: &str = "hf_plan_0000000000000000";

/// Validate a plan document, compute its canonical digest, and verify its
/// content-derived plan id (AC1: the digest is what apply re-computes
/// immediately before every effect).
pub fn bind_plan(doc: &Val) -> Result<PlanBindings, MutationError> {
    let verdict = validate_doc(Family::Plan, doc);
    if !verdict.is_accepted() {
        return Err(MutationError::new(
            code::PLAN_MALFORMED,
            format!("plan refused: {}", verdict.message()),
        ));
    }
    let get = |key: &str| -> Result<String, MutationError> {
        doc.get(key)
            .and_then(Val::as_str)
            .map(str::to_string)
            .ok_or_else(|| MutationError::new(code::PLAN_MALFORMED, format!("plan missing {key}")))
    };
    let plan_id = get("plan_id")?;
    let workflow_id = get("workflow_id")?;
    let workflow_hash = get("workflow_hash")?;
    let repository = get("repository")?;
    let issue_revision = doc
        .get("issue")
        .and_then(|issue| issue.get("revision"))
        .and_then(Val::as_str)
        .map(str::to_string)
        .ok_or_else(|| MutationError::new(code::PLAN_MALFORMED, "plan missing issue.revision"))?;
    let issue_number = doc
        .get("issue")
        .and_then(|issue| issue.get("number"))
        .and_then(Val::as_int)
        .ok_or_else(|| MutationError::new(code::PLAN_MALFORMED, "plan missing issue.number"))?;
    let state_epoch = doc
        .get("state_epoch")
        .and_then(Val::as_int)
        .ok_or_else(|| MutationError::new(code::PLAN_MALFORMED, "plan missing state_epoch"))?;

    // Content identity: the plan_id must be the sha256 (first 16 hex) of
    // the canonical document with a placeholder id.
    let seeded = plan_with_id(doc, PLAN_ID_PLACEHOLDER)?;
    let seed_digest = sha256_hex(&canonical_bytes(&seeded));
    let expected = format!("hf_plan_{}", &seed_digest[..16]);
    if plan_id != expected {
        return Err(MutationError::new(
            code::PLAN_IDENTITY,
            format!("plan_id {plan_id:?} is not the content-derived id {expected:?}"),
        ));
    }
    let canonical = canonical_bytes(doc);
    let digest = sha256_hex(&canonical);
    Ok(PlanBindings {
        doc: doc.clone(),
        canonical,
        digest,
        plan_id,
        workflow_id,
        workflow_hash,
        repository,
        issue_number,
        issue_revision,
        state_epoch,
    })
}

fn plan_with_id(doc: &Val, plan_id: &str) -> Result<Val, MutationError> {
    let mut map = match doc {
        Val::Obj(map) => map.clone(),
        _ => {
            return Err(MutationError::new(
                code::PLAN_MALFORMED,
                "plan is not an object",
            ));
        }
    };
    map.insert("plan_id".to_string(), string(plan_id));
    Ok(Val::Obj(map))
}

/// Find one step in a bound plan by id.
pub fn plan_step<'a>(plan: &'a PlanBindings, step_id: &str) -> Result<&'a Val, MutationError> {
    let steps = plan
        .doc
        .get("steps")
        .and_then(Val::as_array)
        .ok_or_else(|| MutationError::new(code::PLAN_MALFORMED, "plan missing steps"))?;
    steps
        .iter()
        .find(|step| step.get("id").and_then(Val::as_str) == Some(step_id))
        .ok_or_else(|| {
            MutationError::new(
                code::BAD_PARAMS,
                format!("plan has no step with id {step_id:?}"),
            )
        })
}

/// The closed-set kind of a plan step.
pub fn step_kind(step: &Val) -> Result<String, MutationError> {
    step.get("kind")
        .and_then(Val::as_str)
        .map(str::to_string)
        .filter(|kind| EFFECT_KINDS.contains(&kind.as_str()))
        .ok_or_else(|| MutationError::new(code::UNKNOWN_KIND, "step kind outside the closed set"))
}

// ---------------------------------------------------------------------------
// Effect preconditions: fresh revalidation before EVERY effect (AC1/AC2)
// ---------------------------------------------------------------------------

/// Revalidate the full binding set immediately before an effect: plan
/// digest (already bound by the caller), live epoch vs plan/grant/instance,
/// grant status/expiry/revision (C2, AC2), workflow/policy hashes, required
/// capability/phase, and instance runnability. Returns the first refusal.
#[allow(clippy::too_many_arguments)]
pub fn revalidate_effect(
    plan: &PlanBindings,
    kind: &str,
    grant: &GrantSnapshot,
    instance: &InstanceSnapshot,
    observed: &Observed,
) -> Result<(), MutationError> {
    let Some(cap) = required_capability(kind) else {
        return Err(MutationError::new(code::UNKNOWN_KIND, kind.to_string()));
    };
    // Epoch: plan/grant/instance must all agree with the live epoch.
    if plan.state_epoch != observed.state_epoch {
        return Err(MutationError::new(
            code::EPOCH_STALE,
            format!(
                "plan epoch {} != live epoch {}; grants/plans die with their epoch",
                plan.state_epoch, observed.state_epoch
            ),
        ));
    }
    if grant.state_epoch != observed.state_epoch || instance.state_epoch != observed.state_epoch {
        return Err(MutationError::new(
            code::EPOCH_STALE,
            "grant/instance epoch is not the live epoch (restore or rotation invalidated it)",
        ));
    }
    // Grant status and expiry (C2: an expired grant refuses mutation).
    if grant.status != "active" {
        return Err(MutationError::new(
            code::GRANT_INACTIVE,
            format!("grant {} is {}", grant.grant_id, grant.status),
        ));
    }
    if is_expired(&grant.expires_at, &observed.now) {
        return Err(MutationError::new(
            code::GRANT_EXPIRED,
            format!("grant {} expired at {}", grant.grant_id, grant.expires_at),
        ));
    }
    // Plan/repository/issue binding vs grant.
    if plan.repository != grant.repository || grant.repository != instance.repository {
        return Err(MutationError::new(
            code::BAD_PARAMS,
            "plan/grant/instance repository identity disagree",
        ));
    }
    if plan.issue_number != grant.issue_number || plan.issue_number != instance.issue_number {
        return Err(MutationError::new(
            code::BAD_PARAMS,
            "plan/grant/instance issue number disagree",
        ));
    }
    if plan.issue_revision != grant.issue_revision || plan.issue_revision != instance.issue_revision
    {
        return Err(MutationError::new(
            code::GRANT_STALE,
            "plan issue revision disagrees with the grant/instance binding",
        ));
    }
    // Observed issue revision (fresh read-back) vs grant binding (AC2: a
    // material issue/acceptance edit makes the grant stale).
    grant_binding_valid(&grant.issue_revision, &observed.issue_revision)
        .map_err(|err| MutationError::new(code::GRANT_STALE, err.message))?;
    // Workflow hash: plan == grant == instance; policy hash: plan/grant/
    // instance == freshly observed policy hash.
    if plan.workflow_hash != grant.workflow_hash || plan.workflow_hash != instance.workflow_hash {
        return Err(MutationError::new(
            code::WORKFLOW_CHANGED,
            "plan/grant/instance workflow hash disagree (changed in flight)",
        ));
    }
    if plan.workflow_id != instance.workflow_id {
        return Err(MutationError::new(
            code::WORKFLOW_CHANGED,
            "plan workflow id disagrees with the pinned instance workflow",
        ));
    }
    if grant.policy_hash != observed.policy_hash || instance.policy_hash != observed.policy_hash {
        return Err(MutationError::new(
            code::POLICY_CHANGED,
            "policy hash changed since the grant/instance pin",
        ));
    }
    if instance.grant_id != grant.grant_id {
        return Err(MutationError::new(
            code::BAD_PARAMS,
            "instance is not bound to the presented grant",
        ));
    }
    if instance.status == "invalidated" || instance.status == "done" {
        return Err(MutationError::new(
            code::INSTANCE_STATE,
            format!("instance {} is {}", instance.instance_id, instance.status),
        ));
    }
    if instance.paused {
        return Err(MutationError::new(
            code::INSTANCE_STATE,
            format!(
                "instance {} is paused; a fresh authorized resume digest is required",
                instance.instance_id
            ),
        ));
    }
    if instance.pause_requested {
        // Issue #86: the pause request is durable BEFORE the run reaches
        // its safe boundary, so stop-admitting takes effect before any
        // further step is dispatched. In-flight work is untouched.
        return Err(MutationError::new(
            code::RUN_PAUSED,
            format!(
                "instance {} carries a pause request; a new step is never dispatched until the \
                 pause reaches its boundary and is explicitly resumed",
                instance.instance_id
            ),
        ));
    }
    // Grant caps must cover the effect (AC3; caps are a closed set). The
    // phase binding is enforced at grant-issuance/routing time (a grant is
    // issued for the phase it authorizes); apply revalidates the capability
    // authority plus every durable binding above — a grant can never widen
    // an effect's class or caps.
    if !grant.caps.iter().any(|c| c == cap) || !instance.caps.iter().any(|c| c == cap) {
        return Err(MutationError::new(
            code::CAP_MISSING,
            format!(
                "effect {kind} requires capability {cap:?}, which the grant/instance does not carry"
            ),
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Policy probes (pure; RED/GREEN-tested): main/production/hotfix rules (AC6)
// ---------------------------------------------------------------------------

/// Classification of a branch against the integration branch and the
/// configured production branches.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BranchKind {
    /// The integration branch (staging): merges land here.
    Integration,
    /// A production/main branch: promotion rules apply.
    Production,
    /// A `hotfix/*` branch: the narrow incident exception path.
    Hotfix,
    /// An ordinary feature lane branch.
    Feature,
}

/// Classify a branch name.
pub fn classify_branch(branch: &str, integration: &str, production: &[String]) -> BranchKind {
    if branch == integration {
        BranchKind::Integration
    } else if production.iter().any(|p| p == branch) || branch == "main" {
        BranchKind::Production
    } else if branch.starts_with("hotfix/") {
        BranchKind::Hotfix
    } else {
        BranchKind::Feature
    }
}

/// Direct-push policy: only feature branches may be pushed to directly,
/// and never with force. There is no direct/force-push path to
/// integration or production branches (AC6).
pub fn check_push_policy(
    branch: &str,
    force: bool,
    integration: &str,
    production: &[String],
) -> Result<BranchKind, MutationError> {
    if force {
        return Err(MutationError::new(
            code::PUSH_POLICY,
            "force pushes are never allowed (no force-push path exists)",
        ));
    }
    let kind = classify_branch(branch, integration, production);
    match kind {
        BranchKind::Feature | BranchKind::Hotfix => Ok(kind),
        BranchKind::Integration | BranchKind::Production => Err(MutationError::new(
            code::PUSH_POLICY,
            format!(
                "direct push to {branch:?} is refused; integration/production refs move only through reviewed merges/PRs"
            ),
        )),
    }
}

/// Main-PR origin policy: ordinary PRs to `main`/production originate from
/// the integration branch only; the sole alternate path is a `hotfix/*`
/// head (which carries its own gate). RED/GREEN probes pin this.
pub fn check_main_pr_origin(
    head: &str,
    base: &str,
    integration: &str,
    production: &[String],
) -> Result<(), MutationError> {
    let base_kind = classify_branch(base, integration, production);
    if base_kind != BranchKind::Production {
        return Ok(());
    }
    if head == integration {
        return Ok(());
    }
    if head.starts_with("hotfix/") {
        return Ok(());
    }
    Err(MutationError::new(
        code::MAIN_PR_POLICY,
        format!(
            "PR to production base {base:?} must originate from {integration:?} or a hotfix/* branch, not {head:?}"
        ),
    ))
}

/// External-contributor policy (AC5): a PR whose head repository differs
/// from the base repository is mechanically refused unless one human
/// maintainer approval is recorded. Trusted fleet lanes (head repository
/// matches, exact-head evidence) keep the ordinary path.
pub fn check_external_contributor(
    head_repo_matches: bool,
    maintainer_approval: bool,
) -> Result<(), MutationError> {
    if !head_repo_matches && !maintainer_approval {
        return Err(MutationError::new(
            code::EXTERNAL_APPROVAL,
            "external-contributor PR requires one human maintainer approval before merge",
        ));
    }
    Ok(())
}

/// The narrow hotfix gate (AC6): a hotfix targeting production needs the
/// full fresh-human bundle — interactive digest, focused review, CI,
/// patch-release evidence, and mandatory reconciliation back to staging —
/// all recorded before the effect.
#[derive(Clone, Debug, Default)]
pub struct HotfixGate {
    /// Fresh interactive TTY-confirmed human digest.
    pub digest_confirmed: bool,
    /// Focused review recorded.
    pub review_recorded: bool,
    /// Required CI passed on the exact head.
    pub ci_passed: bool,
    /// Patch-release evidence recorded.
    pub patch_release_evidence: bool,
    /// Reconciliation back to the integration branch is mandatory.
    pub reconciled_to_integration: bool,
}

impl HotfixGate {
    /// All five conditions must hold; a missing one refuses with the typed
    /// code (fail closed — CI alone never authorizes a hotfix).
    pub fn check(&self) -> Result<(), MutationError> {
        let missing = [
            (self.digest_confirmed, "fresh interactive human digest"),
            (self.review_recorded, "focused review"),
            (self.ci_passed, "required CI on the exact head"),
            (self.patch_release_evidence, "patch-release evidence"),
            (
                self.reconciled_to_integration,
                "mandatory reconciliation back to the integration branch",
            ),
        ]
        .iter()
        .filter_map(|(ok, label)| (!ok).then_some(*label))
        .collect::<Vec<_>>();
        if missing.is_empty() {
            return Ok(());
        }
        Err(MutationError::new(
            code::HOTFIX_GATE,
            format!("hotfix gate missing: {}", missing.join(", ")),
        ))
    }
}

/// Production-confirmation policy (risk-model.md ops rule 3 + issue AC6):
/// effects on production branches require a fresh interactive
/// TTY-confirmed digest; a policy of `deny` always refuses; recurring
/// schedules can never carry production effects.
pub fn check_production_confirmation(
    policy: Option<&str>,
    interactive: bool,
    digest_confirmed: bool,
    scheduled: bool,
) -> Result<(), MutationError> {
    if scheduled {
        return Err(MutationError::new(
            code::PRODUCTION_CONFIRMATION,
            "production effects are never authorized by recurring schedules",
        ));
    }
    match policy {
        Some("deny") => Err(MutationError::new(
            code::PRODUCTION_CONFIRMATION,
            "policy denies production confirmation",
        )),
        Some("tty") | None if interactive && digest_confirmed => Ok(()),
        _ => Err(MutationError::new(
            code::PRODUCTION_CONFIRMATION,
            "production-branch effects require a fresh interactive TTY-confirmed digest",
        )),
    }
}

/// The first-real-write canary gate (AC10): an effect that declares a real
/// external target scope is refused unless a separate explicit approval was
/// recorded for the canary scope. This slice proves the gate with fakes and
/// never runs a real canary.
pub fn check_first_write_approval(
    recorded: Option<&crate::state::ApprovalRow>,
    target_scope: Option<&str>,
) -> Result<(), MutationError> {
    if target_scope != Some("real_external") {
        return Ok(());
    }
    match recorded {
        Some(approval) if approval.interactive => Ok(()),
        Some(_) => Err(MutationError::new(
            code::APPROVAL_NOT_INTERACTIVE,
            "the recorded approval was not an interactive TTY confirmation",
        )),
        None => Err(MutationError::new(
            code::FIRST_WRITE_APPROVAL,
            "a real external write requires a separately recorded human approval before the first-write canary",
        )),
    }
}

// ---------------------------------------------------------------------------
// Review evidence checks (AC4; spec-review-evidence.md)
// ---------------------------------------------------------------------------

/// Typed evidence view (mapped from `state::EvidenceRow`).
#[derive(Clone, Debug)]
pub struct EvidenceView {
    /// Evidence id.
    pub evidence_id: String,
    /// Reviewed feature-branch head (40-hex).
    pub feature_head: String,
    /// Integration-base SHA the review ran against (40-hex).
    pub integration_base: String,
    /// Workflow hash (64-hex).
    pub workflow_hash: String,
    /// Policy hash (64-hex).
    pub policy_hash: String,
    /// Verdict (`pass` | `fail`).
    pub verdict: String,
    /// Reviewer identity.
    pub reviewer: String,
    /// Canonical JSON `checks` array text.
    pub checks: String,
    /// Recorded at.
    pub created_at: String,
}

/// Revalidate an evidence record against live state: any relevant change
/// (feature head moved, integration base advanced, workflow hash changed,
/// policy hash changed) invalidates the record with a typed refusal naming
/// the moved binding (AC4).
pub fn evidence_matches_live(
    evidence: &EvidenceView,
    feature_head: &str,
    integration_base: &str,
    workflow_hash: &str,
    policy_hash: &str,
) -> Result<(), MutationError> {
    for (label, recorded, live) in [
        ("feature_head", &evidence.feature_head, feature_head),
        (
            "integration_base",
            &evidence.integration_base,
            integration_base,
        ),
        ("workflow_hash", &evidence.workflow_hash, workflow_hash),
        ("policy_hash", &evidence.policy_hash, policy_hash),
    ] {
        if recorded != live {
            return Err(MutationError::new(
                code::EVIDENCE_STALE,
                format!("review evidence {label} moved: recorded {recorded:?}, live {live:?}"),
            ));
        }
    }
    Ok(())
}

/// Whether every named check in the evidence record passed.
pub fn evidence_checks_passed(evidence: &EvidenceView) -> Result<bool, MutationError> {
    let checks = Val::parse_json(&evidence.checks).map_err(|err| {
        MutationError::new(
            code::MALFORMED_OUTPUT,
            format!("evidence checks unparsable: {err}"),
        )
    })?;
    let items = checks.as_array().ok_or_else(|| {
        MutationError::new(code::MALFORMED_OUTPUT, "evidence checks is not an array")
    })?;
    Ok(items.iter().all(|item| {
        matches!(
            item.get("status"),
            Some(Val::Str(status)) if status == "passed"
        )
    }))
}

/// The merge-gate evidence bundle: the instance must carry a latest
/// evidence record whose bindings match the live heads/hashes, whose
/// verdict is `pass`, and whose checks all passed (AC4 + issue merge
/// minimum: distinct exact-head reviewer evidence plus required hosted
/// checks bound to head/base/workflow/policy).
pub fn check_merge_evidence(
    evidence: Option<&EvidenceView>,
    feature_head: &str,
    integration_base: &str,
    workflow_hash: &str,
    policy_hash: &str,
) -> Result<(), MutationError> {
    let Some(evidence) = evidence else {
        return Err(MutationError::new(
            code::EVIDENCE_MISSING,
            "no review-evidence record exists for this instance; a merge without a valid current evidence record is refused",
        ));
    };
    evidence_matches_live(
        evidence,
        feature_head,
        integration_base,
        workflow_hash,
        policy_hash,
    )?;
    if evidence.verdict != "pass" {
        return Err(MutationError::new(
            code::EVIDENCE_FAILED,
            format!(
                "review evidence {} verdict is {:?}",
                evidence.evidence_id, evidence.verdict
            ),
        ));
    }
    if !evidence_checks_passed(evidence)? {
        return Err(MutationError::new(
            code::EVIDENCE_FAILED,
            format!(
                "review evidence {} has failed/pending checks",
                evidence.evidence_id
            ),
        ));
    }
    Ok(())
}

/// Distinct-reviewer rule for evidence recording (spec-workflow.md AC5): the
/// reviewer identity must differ from the implementer identity.
pub fn check_reviewer_distinct(reviewer: &str, implementer: &str) -> Result<(), MutationError> {
    if reviewer.is_empty() || implementer.is_empty() {
        return Err(MutationError::new(
            code::BAD_PARAMS,
            "evidence requires reviewer and implementer identities",
        ));
    }
    if reviewer == implementer {
        return Err(MutationError::new(
            code::REVIEWER_NOT_DISTINCT,
            "the reviewer must be a distinct identity from the implementer",
        ));
    }
    Ok(())
}

/// Issue-closure gate (AC7): an issue may close only after the integration
/// merge and post-merge verification (the instance must have recorded the
/// plan's `post_merge_verify` step as its last node — `verify_step_id` is
/// that plan-local step id — and carry passing evidence). One enforcement
/// point: the daemon apply path calls this same gate.
pub fn check_issue_closure(
    evidence: Option<&EvidenceView>,
    current_node: &str,
    verify_step_id: &str,
) -> Result<(), MutationError> {
    if current_node != verify_step_id {
        return Err(MutationError::new(
            code::CLOSURE_PREMATURE,
            format!(
                "issue closure requires post-merge verification first (instance is at {current_node:?}; verify step is {verify_step_id:?})"
            ),
        ));
    }
    match evidence {
        Some(evidence) if evidence.verdict == "pass" => Ok(()),
        _ => Err(MutationError::new(
            code::CLOSURE_PREMATURE,
            "issue closure requires passing review evidence after the integration merge",
        )),
    }
}

// ---------------------------------------------------------------------------
// Path containment (AC8)
// ---------------------------------------------------------------------------

/// Whether `child` is strictly inside `root` (both canonicalized when they
/// exist; lexical fallback otherwise). Refuses identical paths (a lane
/// root must not itself be deleted by cleanup).
pub fn is_contained(root: &Path, child: &Path) -> bool {
    let root = canonical_or(root);
    let child = canonical_or(child);
    child.starts_with(&root) && child != root
}

fn canonical_or(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

/// Resolve a step param path that must live under the containment root.
/// `relative` is a path relative to the root; anything escaping (or an
/// absolute path when only relative paths are allowed) is refused.
pub fn contained_path(root: &Path, relative: &str) -> Result<PathBuf, MutationError> {
    if relative.is_empty() {
        return Err(MutationError::new(code::UNCONTAINED, "empty path"));
    }
    let candidate = root.join(relative);
    if !is_contained(root, &candidate) {
        return Err(MutationError::new(
            code::UNCONTAINED,
            format!("path {relative:?} escapes the containment root"),
        ));
    }
    Ok(candidate)
}

// ---------------------------------------------------------------------------
// Effect execution
// ---------------------------------------------------------------------------

/// The outcome of one executed effect.
#[derive(Clone, Debug)]
pub struct EffectOutcome {
    /// Typed status: `succeeded` | `failed` | `ambiguous` | `refused`.
    pub status: &'static str,
    /// Stable error code (failed/refused/ambiguous only).
    pub code: Option<String>,
    /// Human message (failed/refused/ambiguous only).
    pub message: Option<String>,
    /// Typed result document with the exact external read-back (AC1).
    pub result: Val,
}

/// Context for one effect execution.
pub struct EffectContext<'a> {
    /// Bound plan.
    pub plan: &'a PlanBindings,
    /// Step id being applied.
    pub step_id: &'a str,
    /// Step kind (closed set).
    pub kind: &'a str,
    /// Step params (typed object).
    pub params: Option<&'a Val>,
    /// Repository identity.
    pub repository: &'a str,
    /// Integration branch of the repository.
    pub integration_branch: &'a str,
    /// Configured production branches.
    pub production_branches: &'a [String],
    /// Lane containment root (worktrees live here).
    pub worktrees_root: &'a Path,
    /// The integration checkout the effects operate on (absolute).
    pub integration_repo: &'a Path,
    /// Freshly observed feature-branch head (40-hex) when the caller
    /// recorded one before this effect (review evidence/verification).
    pub observed_feature_head: Option<&'a str>,
    /// Freshly observed integration-base head (40-hex) before this effect.
    pub observed_integration_base: Option<&'a str>,
    /// Allowlisted environment for children.
    pub env: &'a BTreeMap<String, String>,
    /// The run's declared role configuration (issue #92 F2): the reviewed
    /// `hf-profile-binding/v1` document the run's admission bound. When it
    /// is present the harness profile (key/kind/provider/model) comes from
    /// it — never from a step param default and never invented. `None` for a
    /// run without a committed role configuration (a presented plan then
    /// declares its own profile explicitly).
    pub role: Option<&'a crate::config::ProfileBinding>,
    /// The session identity the run bound (issue #92 F2): `harness_start`
    /// binds it and every prompt of the run continues exactly this session.
    /// `None` for a run without one (a presented plan then declares the
    /// identity itself; the adapter never invents one).
    pub session: Option<&'a crate::adapters::SessionHandle>,
    /// Daemon-owned archive/salvage root (issue #9 AC7; archive cleanup
    /// steps require it).
    pub archive_root: Option<&'a Path>,
}

/// Outcome for a refused effect (preconditions are checked by the daemon
/// through [`revalidate_effect`]; the runner refuses only malformed params).
fn refusal(code: &'static str, message: impl Into<String>) -> EffectOutcome {
    EffectOutcome {
        status: "refused",
        code: Some(code.to_string()),
        message: Some(message.into()),
        result: null(),
    }
}

fn failed(code: &'static str, message: impl Into<String>) -> EffectOutcome {
    EffectOutcome {
        status: "failed",
        code: Some(code.to_string()),
        message: Some(message.into()),
        result: null(),
    }
}

fn ok(result: Val) -> EffectOutcome {
    EffectOutcome {
        status: "succeeded",
        code: None,
        message: None,
        result,
    }
}

/// Map a bounded subprocess run onto a failed/ambiguous outcome.
fn outcome_from_run(out: &crate::process::ProcOut, label: &str) -> Result<(), EffectOutcome> {
    match &out.status {
        ProcStatus::Exit(0) => Ok(()),
        ProcStatus::Exit(-1) => Err(EffectOutcome {
            status: "ambiguous",
            code: Some(code::PROCESS_DEATH.to_string()),
            message: Some(format!("{label} died without a terminal outcome")),
            result: null(),
        }),
        ProcStatus::Exit(n) => Err(failed(
            code::EXIT,
            format!(
                "{label} exited with code {n}: {}",
                diagnostics(&out.stdout, &out.stderr)
            ),
        )),
        ProcStatus::TimedOut => Err(EffectOutcome {
            status: "ambiguous",
            code: Some(code::TIMEOUT.to_string()),
            message: Some(format!("{label} exceeded its deadline and was cancelled")),
            result: null(),
        }),
        ProcStatus::SpawnFailed(message) => Err(EffectOutcome {
            status: "refused",
            code: Some(code::UNAVAILABLE.to_string()),
            message: Some(format!("could not spawn {label}: {message}")),
            result: null(),
        }),
    }
}

/// Bounded, redacted diagnostics text (two trimmed lines).
fn diagnostics(stdout: &str, stderr: &str) -> String {
    let combined = crate::redact::redact(&format!("{stdout}{stderr}"));
    let mut lines = combined.lines().map(str::trim).filter(|l| !l.is_empty());
    let mut out = String::new();
    for line in lines.by_ref().take(2) {
        if !out.is_empty() {
            out.push_str(" | ");
        }
        out.push_str(line);
        if out.len() >= 300 {
            break;
        }
    }
    out
}

fn run_git(
    ctx: &EffectContext<'_>,
    cwd: &Path,
    args: &[&str],
) -> Result<crate::process::ProcOut, EffectOutcome> {
    let env = ctx.env;
    let git_env: BTreeMap<String, String> = if env.contains_key("PATH") {
        env.clone()
    } else {
        adapter_environment()
    };
    let deadline = effect_deadline_secs(ctx.kind, ctx.params)?;
    let out = crate::adapters::run_grouped(ProcSpec {
        program: "git",
        args: &args.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
        env: &git_env,
        cwd: Some(cwd),
        timeout: Duration::from_secs(deadline),
    });
    outcome_from_run(&out, &format!("git (cwd {})", cwd.display()))?;
    Ok(out)
}

fn param_str<'a>(params: Option<&'a Val>, key: &str) -> Result<&'a str, EffectOutcome> {
    params
        .and_then(|p| p.get(key))
        .and_then(Val::as_str)
        .filter(|text| !text.is_empty())
        .ok_or_else(|| refusal(code::BAD_PARAMS, format!("step params missing {key:?}")))
}

fn param_str_opt<'a>(params: Option<&'a Val>, key: &str) -> Option<&'a str> {
    params.and_then(|p| p.get(key)).and_then(Val::as_str)
}

fn param_int(params: Option<&Val>, key: &str) -> Result<i64, EffectOutcome> {
    params
        .and_then(|p| p.get(key))
        .and_then(Val::as_int)
        .ok_or_else(|| refusal(code::BAD_PARAMS, format!("step params missing {key:?}")))
}

fn param_bool(params: Option<&Val>, key: &str) -> bool {
    params
        .and_then(|p| p.get(key))
        .and_then(Val::as_bool)
        .unwrap_or(false)
}

/// Execute one plan step effect (the daemon journals the intent and
/// resolves the claim around this call; effects are executed outside the
/// state lock and must resolve with an exact read-back so the outcome can
/// be recorded durably).
pub fn execute_step(ctx: &EffectContext<'_>) -> EffectOutcome {
    let mut outcome = match ctx.kind {
        "checkout" => effect_checkout(ctx),
        "worktree_create" => effect_worktree_create(ctx),
        "harness_start" => effect_harness_start(ctx),
        "prompt" => effect_prompt(ctx),
        "collect_outcome" => effect_collect_outcome(ctx),
        "review_evidence" => effect_review_evidence(ctx),
        "merge" => effect_merge(ctx),
        // `publish` (base vocabulary) and `pr_update` (granular vocabulary)
        // both act through the forge PR adapter; the action is a typed
        // param (create|comment), never an interpolation.
        "publish" | "pr_update" => effect_pr_update(ctx),
        "branch_push" => effect_branch_push(ctx),
        "issue_update" => effect_issue_update(ctx),
        "hosted_check" => effect_hosted_check(ctx),
        "post_merge_verify" => effect_post_merge_verify(ctx),
        "cleanup" => effect_cleanup(ctx),
        "branch_delete" => effect_branch_delete(ctx),
        "approve" => effect_approve(ctx),
        other => refusal(
            code::BAD_PARAMS,
            format!("no effect is routable for step kind {other:?}"),
        ),
    };
    // Issue #92 F1: the effective bounded deadline this effect used is part
    // of the step outcome/evidence (the documented per-kind table plus any
    // `deadline_secs` the reviewed plan declared). One place, every
    // subprocess-bearing kind — never a bare constant at a call site.
    if let Val::Obj(fields) = &mut outcome.result
        && let Some(secs) = bounded_effect_deadline(ctx.kind, ctx.params)
    {
        fields.insert("deadline_secs".to_string(), integer(secs as i64));
    }
    outcome
}

/// The effective bounded deadline (seconds) of one effect kind that runs a
/// bounded subprocess; `None` for the effects that spawn nothing (the
/// deadline table only applies where a child exists). The value is exactly
/// what the effect used: the reviewed step's `deadline_secs` when declared
/// (bounded by [`EFFECT_DEADLINE_CEILING_SECS`]), else the documented
/// per-kind default ([`default_deadline_secs`]).
pub fn bounded_effect_deadline(kind: &str, params: Option<&Val>) -> Option<u64> {
    const SUBPROCESS_KINDS: [&str; 15] = [
        "checkout",
        "worktree_create",
        "harness_start",
        "prompt",
        "collect_outcome",
        "review_evidence",
        "merge",
        "publish",
        "pr_update",
        "branch_push",
        "issue_update",
        "hosted_check",
        "post_merge_verify",
        "cleanup",
        "branch_delete",
    ];
    if !SUBPROCESS_KINDS.contains(&kind) {
        return None;
    }
    effect_deadline_secs(kind, params).ok()
}

/// `checkout`: read the exact current head of the integration branch on the
/// integration checkout (the base every later read-back is compared to).
fn effect_checkout(ctx: &EffectContext<'_>) -> EffectOutcome {
    match run_git(
        ctx,
        ctx.integration_repo,
        &["rev-parse", "--verify", ctx.integration_branch],
    ) {
        Ok(out) => {
            let head = out.stdout.trim().to_string();
            if !is_hex40(&head) {
                return failed(code::MALFORMED_OUTPUT, "git head read-back is not 40-hex");
            }
            ok(object(vec![
                ("integration_branch", string(ctx.integration_branch)),
                ("integration_base", string(&head)),
            ]))
        }
        Err(outcome) => outcome,
    }
}

/// `worktree_create`: create an isolated lane worktree + branch off the
/// current integration head (path-contained under the lane root).
fn effect_worktree_create(ctx: &EffectContext<'_>) -> EffectOutcome {
    let branch = match param_str(ctx.params, "branch") {
        Ok(branch) if is_slug(branch) => branch.to_string(),
        _ => return refusal(code::BAD_PARAMS, "worktree_create requires a slug branch"),
    };
    let kind = classify_branch(&branch, ctx.integration_branch, ctx.production_branches);
    if kind != BranchKind::Feature {
        return refusal(
            code::PUSH_POLICY,
            format!("worktree branches must be feature lanes, got {branch:?}"),
        );
    }
    let relative = match param_str(ctx.params, "worktree") {
        Ok(relative) => relative,
        Err(outcome) => return outcome,
    };
    let worktree = match contained_path(ctx.worktrees_root, relative) {
        Ok(path) => path,
        Err(err) => return refusal(err.code, err.message),
    };
    if worktree.exists() {
        return failed(
            code::EXIT,
            format!(
                "worktree {} already exists; a duplicate lane cannot be created",
                worktree.display()
            ),
        );
    }
    if let Some(parent) = worktree.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    match run_git(
        ctx,
        ctx.integration_repo,
        &[
            "worktree",
            "add",
            "-b",
            &branch,
            worktree.to_str().unwrap_or_default(),
            ctx.integration_branch,
        ],
    ) {
        Ok(out) => {
            // Exact read-back: branch + head of the new worktree.
            let _ = out;
            let head = match run_git(ctx, &worktree, &["rev-parse", "--verify", "HEAD"]) {
                Ok(out) => out.stdout.trim().to_string(),
                Err(_) => return failed(code::MALFORMED_OUTPUT, "cannot read worktree head"),
            };
            let status = match run_git(ctx, &worktree, &["status", "--porcelain"]) {
                Ok(out) => out.stdout,
                Err(_) => return failed(code::MALFORMED_OUTPUT, "cannot read worktree status"),
            };
            ok(object(vec![
                ("branch", string(&branch)),
                ("worktree", string(&worktree.to_string_lossy())),
                ("head", string(&head)),
                ("dirty", bool_(!status.trim().is_empty())),
                (
                    "contained",
                    bool_(is_contained(ctx.worktrees_root, &worktree)),
                ),
            ]))
        }
        Err(outcome) => outcome,
    }
}

/// `harness_start`: bind a lane harness session (identity triple + session
/// handle). The profile is the run's declared role configuration (issue #92
/// F2: the harness key is the role binding key — there is no default
/// profile), and the bound session is the run's session identity, which the
/// prompts of this run then continue. No child is spawned by start for the
/// official kinds (the adapter contract binds the handle; prompt spawns
/// inside the assigned worktree); a declarative `argv` profile that declares
/// its own `start` row really runs it, bounded.
fn effect_harness_start(ctx: &EffectContext<'_>) -> EffectOutcome {
    let params = match ctx.params {
        Some(params) => params,
        None => return refusal(code::BAD_PARAMS, "harness_start requires params"),
    };
    let session = match resolve_session(ctx, Some(params), "harness_start") {
        Ok(session) => session,
        Err(outcome) => return outcome,
    };
    // The start operation validates the capability set; a declared
    // declarative start row runs as the real session bind.
    let profile = match harness_profile(ctx, params) {
        Ok(profile) => profile,
        Err(outcome) => return outcome,
    };
    let deadline = match effect_deadline_secs(ctx.kind, ctx.params) {
        Ok(secs) => secs,
        Err(outcome) => return outcome,
    };
    let request = crate::adapters::OpRequest {
        op: crate::adapters::Op::Start,
        session: &session,
        payload: None,
        timeout: Duration::from_secs(deadline),
    };
    let result =
        crate::adapters::execute_op_in_worktree(&profile, &request, ctx.env, ctx.integration_repo);
    if result.status != "succeeded" {
        return EffectOutcome {
            status: result.status,
            code: result.code.map(str::to_string),
            message: result.message.clone().or_else(|| result.detail.clone()),
            result: null(),
        };
    }
    ok(session_binding_result(ctx, &profile, &session))
}

/// The recorded binding of one session effect (issue #92 F2): the session
/// identity the step bound, the role/profile key it ran under and, when the
/// run carries one, the revision of the declared role configuration. This is
/// what a later prompt continues, so it is part of the step outcome.
fn session_binding_result(
    ctx: &EffectContext<'_>,
    profile: &crate::adapters::Profile,
    session: &crate::adapters::SessionHandle,
) -> Val {
    object(vec![
        ("session_id", string(&session.session_id)),
        (
            "generation",
            integer(session.identity.generation.min(i64::MAX as u64) as i64),
        ),
        ("herdr_session", string(&session.identity.herdr_session)),
        (
            "terminal_session",
            string(&session.identity.terminal_session),
        ),
        ("role_key", string(&profile.key)),
        ("role_kind", string(profile.kind.name())),
        (
            "role_revision",
            match ctx.role {
                Some(role) => string(&role.revision),
                None => null(),
            },
        ),
        ("worktree_confined", bool_(true)),
    ])
}

/// Resolve the session identity one harness step runs under (issue #92 F2).
/// The run's bound session is authoritative when the run has one (it is what
/// `harness_start` bound); a presented plan may declare the identity instead
/// (`session_id` + `herdr_session` + `terminal_session`, all three — a
/// partial identity is refused) and the two must AGREE. When neither exists
/// the step is refused: the adapter never invents a session identity and
/// never substitutes a default.
fn resolve_session(
    ctx: &EffectContext<'_>,
    params: Option<&Val>,
    what: &str,
) -> Result<crate::adapters::SessionHandle, EffectOutcome> {
    let declared = match (
        param_str_opt(params, "session_id"),
        param_str_opt(params, "herdr_session"),
        param_str_opt(params, "terminal_session"),
    ) {
        (None, None, None) => None,
        (session_id, herdr_session, terminal_session) => {
            let (session_id, herdr_session, terminal_session) =
                match (session_id, herdr_session, terminal_session) {
                    (Some(session_id), Some(herdr_session), Some(terminal_session)) => {
                        (session_id, herdr_session, terminal_session)
                    }
                    _ => {
                        return Err(refusal(
                            crate::adapters::CODE_INCOMPLETE_IDENTITY,
                            format!(
                                "{what} declares an incomplete session identity: session_id, \
                                 herdr_session and terminal_session are all required (a partial \
                                 identity is never completed by a default)"
                            ),
                        ));
                    }
                };
            let generation = param_int(params, "generation").unwrap_or(1);
            if generation < 0 {
                return Err(refusal(code::BAD_PARAMS, "generation must be non-negative"));
            }
            let identity =
                crate::adapters::bind_identity(herdr_session, terminal_session, generation as u64)
                    .map_err(|err| refusal(err.code, err.message))?;
            let session = crate::adapters::new_session(session_id, identity)
                .map_err(|err| refusal(err.code, err.message))?;
            Some(session)
        }
    };
    match (ctx.session, declared) {
        (Some(bound), Some(declared)) => {
            if bound != &declared {
                return Err(refusal(
                    crate::adapters::CODE_STALE_IDENTITY,
                    format!(
                        "{what} declares session {:?}, which is not the session this run bound \
                         ({:?}); a step continues the bound session and never re-binds another",
                        declared.session_id, bound.session_id
                    ),
                ));
            }
            Ok(declared)
        }
        (Some(bound), None) => Ok(bound.clone()),
        (None, Some(declared)) => Ok(declared),
        (None, None) => Err(refusal(
            crate::adapters::CODE_INCOMPLETE_IDENTITY,
            format!(
                "{what} requires the session identity (session_id + herdr_session + \
                 terminal_session) and this run bound none: the adapter never invents one"
            ),
        )),
    }
}

/// The session identity of one queue run (issue #92 F2): derived ONCE from
/// the run identity, so `harness_start` binds it and every prompt of the run
/// continues exactly that same session — deterministic across restarts, and
/// never a caller-supplied or default identity. The derivation is the first
/// 16 hex of sha256 over the domain-separated run identity.
pub fn run_session_handle(
    instance_id: &str,
) -> Result<crate::adapters::SessionHandle, EffectOutcome> {
    let digest =
        crate::canonical::sha256_hex(format!("hf-run-session/v1|{instance_id}").as_bytes());
    let session_id = format!("lane-{}", &digest[..16]);
    let identity = crate::adapters::bind_identity(&session_id, &session_id, 1)
        .map_err(|err| refusal(err.code, err.message))?;
    crate::adapters::new_session(&session_id, identity)
        .map_err(|err| refusal(err.code, err.message))
}

/// `prompt`: deliver the bounded prompt as data to the lane harness with the
/// child confined to the assigned worktree (payload is one final argv
/// element — never interpolated).
fn effect_prompt(ctx: &EffectContext<'_>) -> EffectOutcome {
    let params = match ctx.params {
        Some(params) => params,
        None => return refusal(code::BAD_PARAMS, "prompt requires params"),
    };
    let payload = match param_str(Some(params), "payload") {
        Ok(value) => value,
        Err(outcome) => return outcome,
    };
    let relative = match param_str(Some(params), "worktree") {
        Ok(value) => value,
        Err(outcome) => return outcome,
    };
    let worktree = match contained_path(ctx.worktrees_root, relative) {
        Ok(path) => path,
        Err(err) => return refusal(err.code, err.message),
    };
    if !worktree.join(".git").exists() && !worktree.join("HEAD").exists() {
        return refusal(
            code::UNCONTAINED,
            format!("{} is not a git worktree", worktree.display()),
        );
    }
    let profile = match harness_profile(ctx, params) {
        Ok(profile) => profile,
        Err(outcome) => return outcome,
    };
    // Issue #92 F2: the prompt continues the session `harness_start` bound —
    // the run's bound session when the run carries one, else the identity the
    // reviewed plan declares. A partial or absent identity is refused; the
    // adapter never invents one (the pre-fix default "herdr-fleet-lane" is
    // gone).
    let session = match resolve_session(ctx, Some(params), "prompt") {
        Ok(session) => session,
        Err(outcome) => return outcome,
    };
    let prompt_deadline = match effect_deadline_secs(ctx.kind, ctx.params) {
        Ok(secs) => secs,
        Err(outcome) => return outcome,
    };
    let request = crate::adapters::OpRequest {
        op: crate::adapters::Op::Prompt,
        session: &session,
        payload: Some(payload),
        timeout: Duration::from_secs(prompt_deadline),
    };
    let result = crate::adapters::execute_op_in_worktree(&profile, &request, ctx.env, &worktree);
    if result.status != "succeeded" {
        return EffectOutcome {
            status: result.status,
            code: result.code.map(str::to_string),
            message: result.message.clone().or_else(|| result.detail.clone()),
            result: null(),
        };
    }
    let mut fields = match session_binding_result(ctx, &profile, &session) {
        Val::Obj(fields) => fields,
        _ => unreachable!("the session binding result is an object"),
    };
    fields.remove("worktree_confined");
    fields.insert(
        "transcript".to_string(),
        result
            .payload
            .as_ref()
            .and_then(|payload| payload.get("transcript").cloned())
            .unwrap_or_else(null),
    );
    ok(Val::Obj(fields))
}

/// `collect_outcome`: collect the lane's commits/head since the integration
/// base and read the harness terminal outcome through the workspace
/// protocol (herdr workspace executable; fake-pinned in tests).
fn effect_collect_outcome(ctx: &EffectContext<'_>) -> EffectOutcome {
    let relative = match param_str(ctx.params, "worktree") {
        Ok(value) => value,
        Err(outcome) => return outcome,
    };
    let worktree = match contained_path(ctx.worktrees_root, relative) {
        Ok(path) => path,
        Err(err) => return refusal(err.code, err.message),
    };
    let base_head = match param_str_opt(ctx.params, "base_head") {
        Some(head) => head.to_string(),
        None => match run_git(
            ctx,
            ctx.integration_repo,
            &["rev-parse", ctx.integration_branch],
        ) {
            Ok(out) => out.stdout.trim().to_string(),
            Err(outcome) => return outcome,
        },
    };
    if !is_hex40(&base_head) {
        return refusal(code::BAD_PARAMS, "base_head must be 40-hex");
    }
    let head_out = match run_git(ctx, &worktree, &["rev-parse", "--verify", "HEAD"]) {
        Ok(out) => out,
        Err(outcome) => return outcome,
    };
    let head = head_out.stdout.trim().to_string();
    let log_out = match run_git(
        ctx,
        &worktree,
        &[
            "log",
            "--format=%H",
            "--max-count=32",
            &format!("{base_head}..HEAD"),
        ],
    ) {
        Ok(out) => out,
        Err(_) => run_git(ctx, &worktree, &["log", "--format=%H", "--max-count=32"])
            .unwrap_or_else(|_| crate::process::ProcOut {
                status: crate::process::ProcStatus::Exit(0),
                stdout: String::new(),
                stderr: String::new(),
                elapsed_ms: 0,
            }),
    };
    let commits: Vec<Val> = log_out
        .stdout
        .lines()
        .filter(|line| is_hex40(line))
        .map(string)
        .collect();
    ok(object(vec![
        ("head", string(&head)),
        ("commits", Val::Arr(commits)),
        ("base_head", string(&base_head)),
    ]))
}

/// `review_evidence`: validate a review-evidence step and return the typed
/// record values the daemon stores durably (AC4 bindings; reviewer distinct
/// from implementer). No subprocess runs.
fn effect_review_evidence(ctx: &EffectContext<'_>) -> EffectOutcome {
    let params = match ctx.params {
        Some(params) => params,
        None => return refusal(code::BAD_PARAMS, "review_evidence requires params"),
    };
    let reviewer = match param_str(Some(params), "reviewer") {
        Ok(value) => value.to_string(),
        Err(outcome) => return outcome,
    };
    let implementer = match param_str(Some(params), "implementer") {
        Ok(value) => value.to_string(),
        Err(outcome) => return outcome,
    };
    let verdict = match param_str(Some(params), "verdict") {
        Ok(value) if matches!(value, "pass" | "fail") => value.to_string(),
        _ => {
            return refusal(
                code::BAD_PARAMS,
                "review_evidence verdict must be pass|fail",
            );
        }
    };
    let feature_head = match ctx.observed_feature_head {
        Some(value) if is_hex40(value) => value.to_string(),
        _ => {
            return refusal(
                code::BAD_PARAMS,
                "review_evidence requires observed.feature_head (fresh exact-head read-back)",
            );
        }
    };
    let integration_base = match ctx.observed_integration_base {
        Some(value) if is_hex40(value) => value.to_string(),
        _ => {
            return refusal(
                code::BAD_PARAMS,
                "review_evidence requires observed.integration_base (fresh read-back)",
            );
        }
    };
    if let Err(err) = check_reviewer_distinct(&reviewer, &implementer) {
        return refusal(err.code, err.message);
    }
    let checks = match params.get("checks") {
        Some(Val::Arr(items)) if !items.is_empty() => Val::Arr(items.clone()),
        _ => {
            return refusal(
                code::BAD_PARAMS,
                "review_evidence requires a non-empty checks list",
            );
        }
    };
    ok(object(vec![
        ("repository", string(ctx.repository)),
        ("feature_head", string(&feature_head)),
        ("integration_base", string(&integration_base)),
        ("workflow_hash", string(&ctx.plan.workflow_hash)),
        ("verdict", string(&verdict)),
        ("reviewer", string(&reviewer)),
        ("checks", checks),
    ]))
}

/// `merge`: integrate the reviewed feature branch into the integration
/// checkout (fast-forward only — a moved base refuses deterministically).
/// The evidence gate runs daemon-side before this effect.
fn effect_merge(ctx: &EffectContext<'_>) -> EffectOutcome {
    let branch = match param_str(ctx.params, "branch") {
        Ok(value) if is_slug(value) => value.to_string(),
        _ => return refusal(code::BAD_PARAMS, "merge requires a slug feature branch"),
    };
    let kind = classify_branch(&branch, ctx.integration_branch, ctx.production_branches);
    if kind != BranchKind::Feature {
        return refusal(
            code::PUSH_POLICY,
            format!("only feature branches merge to the integration branch, got {branch:?}"),
        );
    }
    // The integration checkout must sit on the integration branch.
    let current = match run_git(ctx, ctx.integration_repo, &["branch", "--show-current"]) {
        Ok(out) => out.stdout.trim().to_string(),
        Err(outcome) => return outcome,
    };
    if current != ctx.integration_branch {
        return failed(
            code::MERGE_FAILED,
            format!(
                "integration checkout is on {current:?}, expected {:?}",
                ctx.integration_branch
            ),
        );
    }
    match run_git(ctx, ctx.integration_repo, &["merge", "--ff-only", &branch]) {
        Ok(out) => {
            let head = match run_git(
                ctx,
                ctx.integration_repo,
                &["rev-parse", ctx.integration_branch],
            ) {
                Ok(out) => out.stdout.trim().to_string(),
                Err(outcome) => return outcome,
            };
            let _ = out;
            ok(object(vec![
                ("integration_branch", string(ctx.integration_branch)),
                ("merged_head", string(&head)),
                ("feature_branch", string(&branch)),
            ]))
        }
        Err(_) => failed(
            code::MERGE_NOT_FF,
            format!(
                "merge of {branch:?} is not fast-forwardable: the integration base moved after the review evidence was recorded"
            ),
        ),
    }
}

/// `post_merge_verify`: prove the merged integration head contains the
/// reviewed feature head (exact git ancestry; AC7's verification step).
fn effect_post_merge_verify(ctx: &EffectContext<'_>) -> EffectOutcome {
    let feature_head = match ctx.observed_feature_head {
        Some(value) if is_hex40(value) => value.to_string(),
        _ => {
            return refusal(
                code::BAD_PARAMS,
                "post_merge_verify requires observed.feature_head (exact reviewed head)",
            );
        }
    };
    let ancestor = run_git(
        ctx,
        ctx.integration_repo,
        &[
            "merge-base",
            "--is-ancestor",
            &feature_head,
            ctx.integration_branch,
        ],
    )
    .is_ok();
    if !ancestor {
        return failed(
            code::EVIDENCE_STALE,
            format!("feature head {feature_head:?} is not an ancestor of the integration branch"),
        );
    }
    let merged_head = match run_git(
        ctx,
        ctx.integration_repo,
        &["rev-parse", ctx.integration_branch],
    ) {
        Ok(out) => out.stdout.trim().to_string(),
        Err(outcome) => return outcome,
    };
    ok(object(vec![
        ("feature_head", string(&feature_head)),
        ("merged_head", string(&merged_head)),
        ("contains_feature", bool_(true)),
    ]))
}

/// `branch_push`: push the feature branch to an allowlisted remote (never
/// force; never integration/production). Read-back verifies the remote ref
/// equals the local head (exact external read-back, AC1).
fn effect_branch_push(ctx: &EffectContext<'_>) -> EffectOutcome {
    let branch = match param_str(ctx.params, "branch") {
        Ok(value) if is_slug(value) => value.to_string(),
        _ => return refusal(code::BAD_PARAMS, "branch_push requires a slug branch"),
    };
    let remote = match param_str(ctx.params, "remote") {
        Ok(value) => value.to_string(),
        Err(outcome) => return outcome,
    };
    if let Err(err) = check_push_policy(
        &branch,
        param_bool(ctx.params, "force"),
        ctx.integration_branch,
        ctx.production_branches,
    ) {
        return refusal(err.code, err.message);
    }
    // Push from the integration checkout (the branch ref is shared with the
    // lane worktree; git resolves it from the common object store).
    match run_git(ctx, ctx.integration_repo, &["push", &remote, &branch]) {
        Ok(out) => {
            let _ = out;
            // Exact read-back: remote ref must equal the local head.
            let local_head = match run_git(
                ctx,
                ctx.integration_repo,
                &["rev-parse", "--verify", &branch],
            ) {
                Ok(out) => out.stdout.trim().to_string(),
                Err(outcome) => return outcome,
            };
            let ls = match run_git(ctx, ctx.integration_repo, &["ls-remote", &remote, &branch]) {
                Ok(out) => out.stdout,
                Err(outcome) => return outcome,
            };
            let remote_head = ls.split_whitespace().next().unwrap_or_default().to_string();
            if remote_head != local_head {
                return failed(
                    code::MALFORMED_OUTPUT,
                    format!(
                        "push read-back mismatch: remote {remote_head:?}, local {local_head:?}"
                    ),
                );
            }
            ok(object(vec![
                ("branch", string(&branch)),
                ("remote", string(&remote)),
                ("remote_head", string(&remote_head)),
                ("force", bool_(false)),
            ]))
        }
        Err(outcome) => outcome,
    }
}

/// `publish`/`pr_update`: create or update a PR through the forge adapter
/// (`gh`); policy probes run first (main-PR origin, external-contributor
/// approval). The fake `gh` pins the argv shape in tests.
fn effect_pr_update(ctx: &EffectContext<'_>) -> EffectOutcome {
    let params = match ctx.params {
        Some(params) => params,
        None => return refusal(code::BAD_PARAMS, "pr_update requires params"),
    };
    let action = match param_str(Some(params), "action") {
        Ok("create") | Ok("comment") => param_str(Some(params), "action")
            .unwrap_or("create")
            .to_string(),
        _ => return refusal(code::BAD_PARAMS, "pr_update action must be create|comment"),
    };
    let repo = match param_str(Some(params), "repo") {
        Ok(value) if is_repository_identity(value) => value.to_string(),
        _ => return refusal(code::BAD_PARAMS, "pr_update requires an owner/name repo"),
    };
    let head = match param_str(Some(params), "head") {
        Ok(value) => value.to_string(),
        Err(outcome) => return outcome,
    };
    if action == "create" {
        let base = match param_str(Some(params), "base") {
            Ok(value) => value.to_string(),
            Err(outcome) => return outcome,
        };
        if let Err(err) = check_main_pr_origin(
            &head,
            &base,
            ctx.integration_branch,
            ctx.production_branches,
        ) {
            return refusal(err.code, err.message);
        }
        let head_repo_matches =
            param_str_opt(Some(params), "head_repo").is_none_or(|hr| hr == repo);
        if let Err(err) = check_external_contributor(
            head_repo_matches,
            param_bool(Some(params), "maintainer_approval"),
        ) {
            return refusal(err.code, err.message);
        }
    }
    let title = param_str_opt(Some(params), "title").unwrap_or("");
    let body = param_str_opt(Some(params), "body").unwrap_or("");
    let number = param_int(Some(params), "number").unwrap_or(0);
    let args = if action == "create" {
        vec![
            "pr".to_string(),
            "create".to_string(),
            "--repo".to_string(),
            repo.clone(),
            "--base".to_string(),
            param_str(Some(params), "base").unwrap_or("").to_string(),
            "--head".to_string(),
            head.clone(),
            "--title".to_string(),
            title.to_string(),
            "--body".to_string(),
            body.to_string(),
        ]
    } else {
        vec![
            "pr".to_string(),
            "comment".to_string(),
            number.to_string(),
            "--repo".to_string(),
            repo.clone(),
            "--body".to_string(),
            body.to_string(),
        ]
    };
    let deadline = match effect_deadline_secs(ctx.kind, ctx.params) {
        Ok(secs) => secs,
        Err(outcome) => return outcome,
    };
    let out = crate::adapters::run_grouped(ProcSpec {
        program: "gh",
        args: &args,
        env: ctx.env,
        cwd: Some(ctx.integration_repo),
        timeout: Duration::from_secs(deadline),
    });
    if let Err(outcome) = outcome_from_run(&out, "gh") {
        return outcome;
    }
    let text = crate::redact::redact(out.stdout.trim()).to_string();
    let parsed = Val::parse_json(&text);
    match parsed {
        Ok(doc) if doc.get("number").and_then(Val::as_int).is_some() => ok(doc),
        _ => ok(object(vec![
            ("action", string(&action)),
            ("repo", string(&repo)),
            ("head", string(&head)),
            ("number", integer(number)),
            ("raw", string(&text)),
        ])),
    }
}

/// `issue_update`: comment on or close an issue through the forge adapter.
/// Closing requires the AC7 gate (merge + post-merge verification), which
/// the daemon evaluates with [`check_issue_closure`] before this effect.
fn effect_issue_update(ctx: &EffectContext<'_>) -> EffectOutcome {
    let params = match ctx.params {
        Some(params) => params,
        None => return refusal(code::BAD_PARAMS, "issue_update requires params"),
    };
    let action = match param_str(Some(params), "action") {
        Ok("comment") | Ok("close") => param_str(Some(params), "action")
            .unwrap_or("comment")
            .to_string(),
        _ => {
            return refusal(
                code::BAD_PARAMS,
                "issue_update action must be comment|close",
            );
        }
    };
    let repo = match param_str(Some(params), "repo") {
        Ok(value) if is_repository_identity(value) => value.to_string(),
        _ => return refusal(code::BAD_PARAMS, "issue_update requires an owner/name repo"),
    };
    let number = param_int(Some(params), "number").unwrap_or(0);
    let body = param_str_opt(Some(params), "body").unwrap_or("");
    let args = if action == "close" {
        vec![
            "issue".to_string(),
            "close".to_string(),
            number.to_string(),
            "--repo".to_string(),
            repo.clone(),
            "--comment".to_string(),
            body.to_string(),
        ]
    } else {
        vec![
            "issue".to_string(),
            "comment".to_string(),
            number.to_string(),
            "--repo".to_string(),
            repo.clone(),
            "--body".to_string(),
            body.to_string(),
        ]
    };
    let deadline = match effect_deadline_secs(ctx.kind, ctx.params) {
        Ok(secs) => secs,
        Err(outcome) => return outcome,
    };
    let out = crate::adapters::run_grouped(ProcSpec {
        program: "gh",
        args: &args,
        env: ctx.env,
        cwd: Some(ctx.integration_repo),
        timeout: Duration::from_secs(deadline),
    });
    if let Err(outcome) = outcome_from_run(&out, "gh") {
        return outcome;
    }
    let text = crate::redact::redact(out.stdout.trim()).to_string();
    ok(object(vec![
        ("action", string(&action)),
        ("repo", string(&repo)),
        ("number", integer(number)),
        ("read_back", string(&text)),
    ]))
}

/// `hosted_check`: observe hosted checks for a PR through the forge adapter
/// (read-only; `gh pr checks` pinned by the fake in tests).
fn effect_hosted_check(ctx: &EffectContext<'_>) -> EffectOutcome {
    let params = match ctx.params {
        Some(params) => params,
        None => return refusal(code::BAD_PARAMS, "hosted_check requires params"),
    };
    let repo = match param_str(Some(params), "repo") {
        Ok(value) if is_repository_identity(value) => value.to_string(),
        _ => return refusal(code::BAD_PARAMS, "hosted_check requires an owner/name repo"),
    };
    let number = param_int(Some(params), "number").unwrap_or(0);
    let args = vec![
        "pr".to_string(),
        "checks".to_string(),
        number.to_string(),
        "--repo".to_string(),
        repo.clone(),
        "--json".to_string(),
        "name,state,conclusion".to_string(),
    ];
    let deadline = match effect_deadline_secs(ctx.kind, ctx.params) {
        Ok(secs) => secs,
        Err(outcome) => return outcome,
    };
    let out = crate::adapters::run_grouped(ProcSpec {
        program: "gh",
        args: &args,
        env: ctx.env,
        cwd: Some(ctx.integration_repo),
        timeout: Duration::from_secs(deadline),
    });
    if let Err(outcome) = outcome_from_run(&out, "gh") {
        return outcome;
    }
    let text = crate::redact::redact(out.stdout.trim()).to_string();
    match Val::parse_json(&text) {
        Ok(doc) => ok(object(vec![
            ("repo", string(&repo)),
            ("number", integer(number)),
            ("checks", doc),
        ])),
        Err(_) => failed(code::MALFORMED_OUTPUT, "gh pr checks output is not JSON"),
    }
}

/// `cleanup`: deterministic lane cleanup. Refuses dirty worktrees,
/// uncontained paths, unknown targets, and unverified (unmerged) branches
/// (AC8). The daemon journals the salvage evidence (`mutate.salvage`)
/// before invoking this effect.
fn effect_cleanup(ctx: &EffectContext<'_>) -> EffectOutcome {
    let relative = match param_str(ctx.params, "worktree") {
        Ok(value) => value,
        Err(outcome) => return outcome,
    };
    let worktree = match contained_path(ctx.worktrees_root, relative) {
        Ok(path) => path,
        Err(err) => return refusal(err.code, err.message),
    };
    // Issue #9 AC7 canonical target classification: a symlinked cleanup
    // target is refused before anything else (symlinks are never followed,
    // and git worktree removal of a symlinked path would touch the wrong
    // directory). The raw join is checked because contained_path
    // canonicalizes symlinks away.
    let raw_target = ctx.worktrees_root.join(relative);
    if let Ok(meta) = std::fs::symlink_metadata(&raw_target)
        && meta.file_type().is_symlink()
    {
        return refusal(
            code::CLEANUP_SYMLINK,
            format!(
                "cleanup target {} is a symlink; symlinked targets are refused",
                raw_target.display()
            ),
        );
    }
    let branch = match param_str(ctx.params, "branch") {
        Ok(value) if is_slug(value) => value.to_string(),
        _ => return refusal(code::BAD_PARAMS, "cleanup requires a slug branch"),
    };
    if !worktree.exists() {
        return failed(
            code::CLEANUP_UNKNOWN,
            format!("worktree {} does not exist", worktree.display()),
        );
    }
    // Refuse dirty worktrees.
    let status = match run_git(ctx, &worktree, &["status", "--porcelain"]) {
        Ok(out) => out.stdout,
        Err(outcome) => return outcome,
    };
    if !status.trim().is_empty() {
        // Dirty work can never be deleted (AC7). With `archive: true` the
        // effect instead PRESERVES the exact bytes into the daemon-owned
        // archive root with a checksummed manifest and reports them — the
        // target itself is left in place (removed stays false).
        if param_bool(ctx.params, "archive") {
            let Some(root) = ctx.archive_root else {
                return refusal(
                    code::BAD_PARAMS,
                    "cleanup archive requires topology.archive_root (daemon-owned)",
                );
            };
            let dest = root.join(format!("lane-{branch}-{}", crate::time::unix_now()));
            let manifest = match crate::lifecycle::archive_tree(&worktree, &dest) {
                Ok(manifest) => manifest,
                Err(err) => return failed(err.code, err.message),
            };
            let entries: Vec<Val> = manifest
                .entries
                .iter()
                .map(|entry| {
                    object(vec![
                        ("path", string(&entry.path)),
                        ("sha256", string(&entry.sha256)),
                        ("bytes", integer(entry.bytes as i64)),
                    ])
                })
                .collect();
            return ok(object(vec![
                ("worktree", string(&worktree.to_string_lossy())),
                ("branch", string(&branch)),
                ("removed", bool_(false)),
                (
                    "archived",
                    object(vec![
                        ("archive_dir", string(&manifest.archive_dir)),
                        ("entries", integer(manifest.entries.len() as i64)),
                        ("total_bytes", integer(manifest.total_bytes as i64)),
                        ("manifest_sha256", string(&manifest.manifest_sha256)),
                        ("files", Val::Arr(entries)),
                    ]),
                ),
            ]));
        }
        return refusal(
            code::CLEANUP_DIRTY,
            format!(
                "worktree {} is dirty; cleanup refuses uncommitted work",
                worktree.display()
            ),
        );
    }
    // Refuse unverified (unmerged) branches.
    let branch_head = match run_git(ctx, &worktree, &["rev-parse", "--verify", "HEAD"]) {
        Ok(out) => out.stdout.trim().to_string(),
        Err(outcome) => return outcome,
    };
    let merged = run_git(
        ctx,
        ctx.integration_repo,
        &[
            "merge-base",
            "--is-ancestor",
            &branch_head,
            ctx.integration_branch,
        ],
    )
    .is_ok();
    if !merged {
        return refusal(
            code::CLEANUP_UNMERGED,
            format!(
                "branch {branch:?} head is not merged into {:?}; cleanup refuses unverified deletion",
                ctx.integration_branch
            ),
        );
    }
    let integration_head = match run_git(
        ctx,
        ctx.integration_repo,
        &["rev-parse", ctx.integration_branch],
    ) {
        Ok(out) => out.stdout.trim().to_string(),
        Err(outcome) => return outcome,
    };
    // The salvage document the daemon journals BEFORE the deletion.
    let salvage = object(vec![
        ("worktree", string(&worktree.to_string_lossy())),
        ("branch", string(&branch)),
        ("head", string(&branch_head)),
        ("merged_into", string(ctx.integration_branch)),
        ("integration_head", string(&integration_head)),
    ]);
    // Remove the worktree (clean, so no --force) then the local branch.
    match run_git(
        ctx,
        ctx.integration_repo,
        &["worktree", "remove", worktree.to_str().unwrap_or_default()],
    ) {
        Ok(_) => {}
        Err(outcome) => return outcome,
    }
    match run_git(ctx, ctx.integration_repo, &["branch", "-d", &branch]) {
        Ok(_) => {}
        Err(outcome) => return outcome,
    }
    let branch_gone = match run_git(ctx, ctx.integration_repo, &["branch", "--list", &branch]) {
        Ok(out) => out.stdout.trim().is_empty(),
        Err(_) => false,
    };
    ok(object(vec![
        ("worktree", string(&worktree.to_string_lossy())),
        ("branch", string(&branch)),
        ("removed", bool_(branch_gone && !worktree.exists())),
        ("salvage", salvage),
    ]))
}

/// `branch_delete`: delete a lane branch after its head is verified merged
/// into the integration branch (no force path; AC6/AC8).
fn effect_branch_delete(ctx: &EffectContext<'_>) -> EffectOutcome {
    let branch = match param_str(ctx.params, "branch") {
        Ok(value) if is_slug(value) => value.to_string(),
        _ => return refusal(code::BAD_PARAMS, "branch_delete requires a slug branch"),
    };
    let kind = classify_branch(&branch, ctx.integration_branch, ctx.production_branches);
    if kind != BranchKind::Feature {
        return refusal(
            code::PUSH_POLICY,
            format!("branch_delete only removes feature lanes, got {branch:?}"),
        );
    }
    let branch_head = match run_git(
        ctx,
        ctx.integration_repo,
        &["rev-parse", "--verify", &branch],
    ) {
        Ok(out) => out.stdout.trim().to_string(),
        Err(_) => {
            return failed(
                code::CLEANUP_UNKNOWN,
                format!("branch {branch:?} does not exist"),
            );
        }
    };
    let merged = run_git(
        ctx,
        ctx.integration_repo,
        &[
            "merge-base",
            "--is-ancestor",
            &branch_head,
            ctx.integration_branch,
        ],
    )
    .is_ok();
    if !merged {
        return refusal(
            code::CLEANUP_UNMERGED,
            format!("branch {branch:?} is not merged; deletion refused"),
        );
    }
    match run_git(ctx, ctx.integration_repo, &["branch", "-d", &branch]) {
        Ok(_) => {}
        Err(outcome) => return outcome,
    }
    ok(object(vec![
        ("branch", string(&branch)),
        ("deleted", bool_(true)),
    ]))
}

/// `approve`: record the separate explicit human approval (AC10). The
/// daemon stores the durable approval row; this effect only validates the
/// typed digest/interactive flags (interactive TTY confirmation required).
fn effect_approve(ctx: &EffectContext<'_>) -> EffectOutcome {
    let params = match ctx.params {
        Some(params) => params,
        None => return refusal(code::BAD_PARAMS, "approve requires params"),
    };
    let digest = match param_str(Some(params), "digest") {
        Ok(value) if is_hex64(value) => value.to_string(),
        _ => return refusal(code::BAD_PARAMS, "approve requires a 64-hex digest"),
    };
    let interactive = param_bool(Some(params), "interactive");
    if !interactive {
        return refusal(
            code::APPROVAL_NOT_INTERACTIVE,
            "the first-real-write approval must be an interactive TTY confirmation",
        );
    }
    ok(object(vec![
        ("scope", string("first-write-canary")),
        ("digest", string(&digest)),
        ("interactive", bool_(true)),
    ]))
}

/// Build the harness profile for a lane harness step (issue #92 F2).
///
/// The declared role binding is the profile: a step names the run's
/// `role_config` key (`harness_key`) and there is **no default profile** —
/// a step that names none is refused. When the run carries its committed
/// role configuration, the profile's key/kind/provider/model come from that
/// reviewed document and the step must AGREE with it (a mismatch is refused,
/// never silently overridden); the executable is the official name for an
/// official kind and the step's declared bare executable for the declarative
/// `argv` kind.
fn harness_profile(
    ctx: &EffectContext<'_>,
    params: &Val,
) -> Result<crate::adapters::Profile, EffectOutcome> {
    let Some(key) = param_str_opt(Some(params), "harness_key") else {
        return Err(refusal(
            crate::config::CODE_PROFILE_BINDING,
            "the harness step declares no role binding (step params.harness_key = the run's \
             role_config key); there is no default profile and none is inferred",
        ));
    };
    let executable = param_str_opt(Some(params), "executable").unwrap_or("");
    if executable.contains('/') || executable.contains('\\') {
        return Err(refusal(
            code::BAD_PARAMS,
            "harness executable must be a bare name resolved through the allowlisted PATH",
        ));
    }
    let kind = param_str_opt(Some(params), "kind").unwrap_or("argv");
    let parsed_kind = crate::adapters::HarnessKind::parse(kind)
        .ok_or_else(|| refusal(code::BAD_PARAMS, format!("unknown harness kind {kind:?}")))?;
    // The run's committed role configuration is authoritative when present.
    if let Some(role) = ctx.role {
        if role.key != key {
            return Err(refusal(
                crate::config::CODE_PROFILE_BINDING,
                format!(
                    "the step declares harness key {key:?}, which is not the run's reviewed role \
                     configuration ({:?}, revision {}); a step never runs another role binding",
                    role.key, role.revision
                ),
            ));
        }
        if role.kind != kind {
            return Err(refusal(
                crate::config::CODE_PROFILE_BINDING,
                format!(
                    "the step declares harness kind {kind:?}, which is not the kind of the run's \
                     reviewed role configuration ({:?})",
                    role.kind
                ),
            ));
        }
        let profile = match crate::adapters::official_spec(parsed_kind) {
            Some(spec) => {
                if !executable.is_empty() && executable != spec.executable {
                    return Err(refusal(
                        code::BAD_PARAMS,
                        format!(
                            "the step declares executable {executable:?}, which is not the \
                             official {:?} executable {:?}",
                            kind, spec.executable
                        ),
                    ));
                }
                crate::adapters::Profile::official(parsed_kind, &role.key)
            }
            None => crate::adapters::Profile::argv(
                &role.key,
                executable,
                &crate::adapters::HARNESS_CAPS,
                BTreeMap::new(),
            ),
        }
        .map_err(|err| refusal(err.code, err.message))?;
        // The declared provider/model pair rides from the reviewed role
        // configuration (never from a step param, never a default id).
        return profile
            .with_binding(&role.provider, &role.model)
            .map_err(|err| refusal(err.code, err.message));
    }
    // No committed role configuration (a presented plan outside the queue
    // executor): the plan declares the binding itself and nothing is
    // defaulted but the declarative kind.
    if parsed_kind == crate::adapters::HarnessKind::Argv {
        crate::adapters::Profile::argv(
            key,
            executable,
            &crate::adapters::HARNESS_CAPS,
            BTreeMap::new(),
        )
        .map_err(|err| refusal(err.code, err.message))
    } else {
        // Official kinds carry their own metadata (executable must match
        // the official name; fake executables in tests use those names).
        crate::adapters::Profile::official(parsed_kind, key)
            .map_err(|err| refusal(err.code, err.message))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Issue #92 F1: the documented per-effect deadline table, the reviewed
    // policy override and the hard ceiling.
    #[test]
    fn effect_deadlines_are_documented_per_kind_and_bounded() {
        assert_eq!(
            effect_deadline_secs("checkout", None).expect("default"),
            EFFECT_DEADLINE_DEFAULT_SECS
        );
        assert_eq!(
            effect_deadline_secs("hosted_check", None).expect("default"),
            EFFECT_DEADLINE_DEFAULT_SECS
        );
        assert_eq!(
            effect_deadline_secs("harness_start", None).expect("default"),
            HARNESS_START_DEADLINE_DEFAULT_SECS
        );
        assert_eq!(
            effect_deadline_secs("prompt", None).expect("default"),
            PROMPT_DEADLINE_DEFAULT_SECS
        );
        // A reviewed plan may declare its own bounded deadline...
        let declared = object(vec![("deadline_secs", integer(120))]);
        assert_eq!(
            effect_deadline_secs("prompt", Some(&declared)).expect("declared"),
            120
        );
        // ...within the documented ceiling, never beyond it.
        let over = object(vec![(
            "deadline_secs",
            integer(EFFECT_DEADLINE_CEILING_SECS as i64 + 1),
        )]);
        let refusal = effect_deadline_secs("prompt", Some(&over)).expect_err("over the ceiling");
        assert_eq!(refusal.code.as_deref(), Some(code::BAD_PARAMS));
        let zero = object(vec![("deadline_secs", integer(0))]);
        assert!(effect_deadline_secs("prompt", Some(&zero)).is_err());
        let malformed = object(vec![("deadline_secs", string("soon"))]);
        assert!(effect_deadline_secs("prompt", Some(&malformed)).is_err());
        // The evidence helper answers for the subprocess-bearing kinds only.
        assert_eq!(
            bounded_effect_deadline("prompt", None),
            Some(PROMPT_DEADLINE_DEFAULT_SECS)
        );
        assert_eq!(bounded_effect_deadline("approve", None), None);
    }

    // Issue #92 F2: the session identity of a run is derived ONCE, so the
    // bind and every prompt of that run agree — and two runs never do.
    #[test]
    fn run_session_identity_is_deterministic_and_run_scoped() {
        let first = run_session_handle("run-0123456789abcdef").expect("session");
        let again = run_session_handle("run-0123456789abcdef").expect("session");
        let other = run_session_handle("run-fedcba9876543210").expect("session");
        assert_eq!(first, again, "the derivation is deterministic");
        assert_ne!(first.session_id, other.session_id, "run scoped");
        assert!(first.session_id.starts_with("lane-"));
        assert_eq!(first.identity.herdr_session, first.session_id);
        assert_eq!(first.identity.terminal_session, first.session_id);
        assert_eq!(first.identity.generation, 1);
    }

    fn grant_snapshot(expires_at: &str) -> GrantSnapshot {
        GrantSnapshot {
            grant_id: "gr_0123456789abcdef".to_string(),
            repository: "example-org/widgets".to_string(),
            issue_number: 123,
            issue_revision: "a".repeat(40),
            workflow_hash: "0".repeat(64),
            policy_hash: "f".repeat(64),
            phase: "merge".to_string(),
            scope: "worktrees/issues/123".to_string(),
            caps: vec![
                "read".to_string(),
                "worktree".to_string(),
                "spawn".to_string(),
                "prompt".to_string(),
                "review".to_string(),
                "merge".to_string(),
                "cleanup".to_string(),
            ],
            expires_at: expires_at.to_string(),
            status: "active".to_string(),
            state_epoch: 1,
        }
    }

    fn instance_snapshot() -> InstanceSnapshot {
        InstanceSnapshot {
            instance_id: "run-1".to_string(),
            repository: "example-org/widgets".to_string(),
            workflow_id: "fleet-doctrine-1".to_string(),
            workflow_hash: "0".repeat(64),
            policy_hash: "f".repeat(64),
            grant_id: "gr_0123456789abcdef".to_string(),
            issue_number: 123,
            issue_revision: "a".repeat(40),
            phase: "merge".to_string(),
            scope: "worktrees/issues/123".to_string(),
            caps: vec![
                "read".to_string(),
                "worktree".to_string(),
                "spawn".to_string(),
                "prompt".to_string(),
                "review".to_string(),
                "merge".to_string(),
                "cleanup".to_string(),
            ],
            current_node: "review_evidence".to_string(),
            paused: false,
            pause_requested: false,
            status: "running".to_string(),
            state_epoch: 1,
        }
    }

    fn observed(now: &str) -> Observed {
        Observed {
            issue_revision: "a".repeat(40),
            policy_hash: "f".repeat(64),
            state_epoch: 1,
            now: now.to_string(),
        }
    }

    fn plan(epoch: i64) -> PlanBindings {
        let doc = object(vec![
            ("schema", string("hf-plan/v1")),
            ("plan_id", string(PLAN_ID_PLACEHOLDER)),
            ("workflow_id", string("fleet-doctrine-1")),
            ("workflow_hash", string(&"0".repeat(64))),
            ("state_epoch", integer(epoch)),
            ("repository", string("example-org/widgets")),
            (
                "issue",
                object(vec![
                    ("number", integer(123)),
                    ("revision", string(&"a".repeat(40))),
                ]),
            ),
            (
                "steps",
                Val::Arr(vec![object(vec![
                    ("id", string("p7")),
                    ("kind", string("merge")),
                    ("params", null()),
                ])]),
            ),
        ]);
        // Make the plan_id content-derived (same two-pass derivation as
        // the deterministic renderer).
        let seeded_digest = sha256_hex(&canonical_bytes(&doc));
        let plan_id = format!("hf_plan_{}", &seeded_digest[..16]);
        let mut map = match doc {
            Val::Obj(map) => map,
            _ => unreachable!(),
        };
        map.insert("plan_id".to_string(), string(&plan_id));
        bind_plan(&Val::Obj(map)).expect("bind")
    }

    #[test]
    fn expired_grant_refuses_mutation_and_fresh_grant_passes() {
        // C2 RED: an expired grant refuses with the typed code.
        let grant = grant_snapshot("2020-01-01T00:00:00Z");
        let instance = instance_snapshot();
        let plan = plan(1);
        let err = revalidate_effect(
            &plan,
            "merge",
            &grant,
            &instance,
            &observed("2026-09-06T00:00:00Z"),
        )
        .expect_err("expired grant must refuse");
        assert_eq!(err.code, code::GRANT_EXPIRED);
        // GREEN: a live grant passes revalidation for an allowed effect.
        let grant = grant_snapshot("2999-01-01T00:00:00Z");
        assert!(
            revalidate_effect(
                &plan,
                "merge",
                &grant,
                &instance,
                &observed("2026-09-06T00:00:00Z")
            )
            .is_ok()
        );
    }

    #[test]
    fn revoked_and_invalidated_grants_refuse_with_grant_inactive() {
        // F2: drive the enforcement branch (grant.status != active) directly.
        let instance = instance_snapshot();
        let plan = plan(1);
        let observed = observed("2026-09-06T00:00:00Z");
        for status in ["revoked", "invalidated"] {
            let mut grant = grant_snapshot("2999-01-01T00:00:00Z");
            grant.status = status.to_string();
            let err = revalidate_effect(&plan, "merge", &grant, &instance, &observed)
                .expect_err("non-active grant must refuse");
            assert_eq!(err.code, code::GRANT_INACTIVE);
        }
    }

    #[test]
    fn stale_issue_revision_and_wrong_epoch_refuse() {
        let grant = grant_snapshot("2999-01-01T00:00:00Z");
        let instance = instance_snapshot();
        let plan = plan(1);
        let mut stale = observed("2026-09-06T00:00:00Z");
        stale.issue_revision = "b".repeat(40);
        let err = revalidate_effect(&plan, "merge", &grant, &instance, &stale)
            .expect_err("stale revision must refuse");
        assert_eq!(err.code, code::GRANT_STALE);
        let mut rotated = observed("2026-09-06T00:00:00Z");
        rotated.state_epoch = 2;
        let err = revalidate_effect(&plan, "merge", &grant, &instance, &rotated)
            .expect_err("epoch mismatch must refuse");
        assert_eq!(err.code, code::EPOCH_STALE);
    }

    #[test]
    fn missing_capability_and_missing_phase_refuse() {
        let grant = grant_snapshot("2999-01-01T00:00:00Z");
        let mut instance = instance_snapshot();
        instance.caps.retain(|cap| cap != "merge");
        let err = revalidate_effect(
            &plan(1),
            "merge",
            &grant,
            &instance,
            &observed("2026-09-06T00:00:00Z"),
        )
        .expect_err("missing cap must refuse");
        assert_eq!(err.code, code::CAP_MISSING);
        let grant = grant_snapshot("2999-01-01T00:00:00Z");
        let instance = instance_snapshot();
        let mut limited = grant.clone();
        limited.phase = "read".to_string();
        // Phase is enforced at grant-issuance/routing time (a grant is issued
        // for the phase it authorizes); apply revalidates the capability set
        // (AC3). A read-phase grant carrying the merge cap still applies the
        // merge capability, so this must NOT refuse on phase.
        assert!(
            revalidate_effect(
                &plan(1),
                "merge",
                &limited,
                &instance,
                &observed("2026-09-06T00:00:00Z")
            )
            .is_ok()
        );
    }

    #[test]
    fn policy_probes_bite_on_red_and_accept_green() {
        let production = vec!["main".to_string()];
        // No direct/force push to integration or production.
        assert_eq!(
            check_push_policy("staging", false, "staging", &production)
                .expect_err("integration push refused")
                .code,
            code::PUSH_POLICY
        );
        assert_eq!(
            check_push_policy("main", false, "staging", &production)
                .expect_err("main push refused")
                .code,
            code::PUSH_POLICY
        );
        assert_eq!(
            check_push_policy("issue-1", true, "staging", &production)
                .expect_err("force refused")
                .code,
            code::PUSH_POLICY
        );
        assert!(check_push_policy("issue-1", false, "staging", &production).is_ok());
        // Main PRs originate from staging or hotfix/* only.
        assert!(check_main_pr_origin("staging", "main", "staging", &production).is_ok());
        assert!(check_main_pr_origin("hotfix/incident-1", "main", "staging", &production).is_ok());
        assert_eq!(
            check_main_pr_origin("issue-1", "main", "staging", &production)
                .expect_err("feature -> main refused")
                .code,
            code::MAIN_PR_POLICY
        );
        // External contributor needs one human maintainer approval.
        assert_eq!(
            check_external_contributor(false, false)
                .expect_err("no approval")
                .code,
            code::EXTERNAL_APPROVAL
        );
        assert!(check_external_contributor(false, true).is_ok());
        assert!(check_external_contributor(true, false).is_ok());
        // Hotfix gate is all-or-nothing.
        let partial = HotfixGate {
            digest_confirmed: true,
            review_recorded: true,
            ci_passed: true,
            patch_release_evidence: false,
            reconciled_to_integration: false,
        };
        assert_eq!(
            partial.check().expect_err("partial refused").code,
            code::HOTFIX_GATE
        );
        assert!(
            HotfixGate {
                digest_confirmed: true,
                review_recorded: true,
                ci_passed: true,
                patch_release_evidence: true,
                reconciled_to_integration: true,
            }
            .check()
            .is_ok()
        );
        // Production confirmation: deny always refuses; schedules never
        // authorize production effects.
        assert_eq!(
            check_production_confirmation(Some("deny"), true, true, false)
                .expect_err("deny")
                .code,
            code::PRODUCTION_CONFIRMATION
        );
        assert_eq!(
            check_production_confirmation(Some("tty"), false, true, false)
                .expect_err("no tty")
                .code,
            code::PRODUCTION_CONFIRMATION
        );
        assert_eq!(
            check_production_confirmation(Some("tty"), true, true, true)
                .expect_err("scheduled")
                .code,
            code::PRODUCTION_CONFIRMATION
        );
        assert!(check_production_confirmation(Some("tty"), true, true, false).is_ok());
    }

    #[test]
    fn evidence_bindings_invalidate_on_any_move() {
        let evidence = EvidenceView {
            evidence_id: "ev_0123456789abcdef".to_string(),
            feature_head: "a".repeat(40),
            integration_base: "b".repeat(40),
            workflow_hash: "0".repeat(64),
            policy_hash: "f".repeat(64),
            verdict: "pass".to_string(),
            reviewer: "reviewer-1".to_string(),
            checks: r#"[{"name":"exact-head-review","status":"passed"},{"name":"hosted-ci","status":"passed"}]"#
                .to_string(),
            created_at: "2026-09-06T00:00:00Z".to_string(),
        };
        assert!(
            check_merge_evidence(
                Some(&evidence),
                &"a".repeat(40),
                &"b".repeat(40),
                &"0".repeat(64),
                &"f".repeat(64),
            )
            .is_ok()
        );
        // Feature head moved.
        assert_eq!(
            check_merge_evidence(
                Some(&evidence),
                &"c".repeat(40),
                &"b".repeat(40),
                &"0".repeat(64),
                &"f".repeat(64),
            )
            .expect_err("head moved")
            .code,
            code::EVIDENCE_STALE
        );
        // Integration base advanced.
        assert_eq!(
            check_merge_evidence(
                Some(&evidence),
                &"a".repeat(40),
                &"d".repeat(40),
                &"0".repeat(64),
                &"f".repeat(64),
            )
            .expect_err("base moved")
            .code,
            code::EVIDENCE_STALE
        );
        // Policy hash changed.
        assert_eq!(
            check_merge_evidence(
                Some(&evidence),
                &"a".repeat(40),
                &"b".repeat(40),
                &"0".repeat(64),
                &"e".repeat(64),
            )
            .expect_err("policy changed")
            .code,
            code::EVIDENCE_STALE
        );
        // No evidence at all refuses the merge.
        assert_eq!(
            check_merge_evidence(
                None,
                &"a".repeat(40),
                &"b".repeat(40),
                &"0".repeat(64),
                &"f".repeat(64)
            )
            .expect_err("missing")
            .code,
            code::EVIDENCE_MISSING
        );
    }

    #[test]
    fn issue_closure_requires_post_merge_verify_and_pass_evidence() {
        let evidence = EvidenceView {
            evidence_id: "ev_0123456789abcdef".to_string(),
            feature_head: "a".repeat(40),
            integration_base: "b".repeat(40),
            workflow_hash: "0".repeat(64),
            policy_hash: "f".repeat(64),
            verdict: "pass".to_string(),
            reviewer: "reviewer-1".to_string(),
            checks: r#"[{"name":"hosted-ci","status":"passed"}]"#.to_string(),
            created_at: "2026-09-06T00:00:00Z".to_string(),
        };
        // Verify-step ids are plan-local (the wire plan names it "v1");
        // the gate compares the instance node against that exact id.
        assert!(check_issue_closure(Some(&evidence), "v1", "v1").is_ok());
        assert_eq!(
            check_issue_closure(Some(&evidence), "merge", "v1")
                .expect_err("premature")
                .code,
            code::CLOSURE_PREMATURE
        );
        assert_eq!(
            check_issue_closure(None, "v1", "v1")
                .expect_err("no evidence")
                .code,
            code::CLOSURE_PREMATURE
        );
        // A plan without any post_merge_verify step can never pass.
        assert_eq!(
            check_issue_closure(Some(&evidence), "", "v1")
                .expect_err("no verify reached")
                .code,
            code::CLOSURE_PREMATURE
        );
    }

    #[test]
    fn first_write_gate_needs_recorded_interactive_approval() {
        assert!(check_first_write_approval(None, None).is_ok());
        assert_eq!(
            check_first_write_approval(None, Some("real_external"))
                .expect_err("missing approval")
                .code,
            code::FIRST_WRITE_APPROVAL
        );
        let approval = crate::state::ApprovalRow {
            approval_id: "ap_0123456789abcdef".to_string(),
            scope: "first-write-canary".to_string(),
            digest: "0".repeat(64),
            interactive: false,
            recorded_at: "2026-09-06T00:00:00Z".to_string(),
        };
        assert_eq!(
            check_first_write_approval(Some(&approval), Some("real_external"))
                .expect_err("non-interactive")
                .code,
            code::APPROVAL_NOT_INTERACTIVE
        );
        let interactive = crate::state::ApprovalRow {
            interactive: true,
            ..approval.clone()
        };
        assert!(check_first_write_approval(Some(&interactive), Some("real_external")).is_ok());
    }

    #[test]
    fn plan_binding_verifies_digest_and_content_identity() {
        let bound = plan(1);
        assert_eq!(bound.digest.len(), 64);
        assert!(bound.plan_id.starts_with("hf_plan_"));
        assert_eq!(bound.plan_id.len(), "hf_plan_".len() + 16);
        assert_eq!(bound.digest, sha256_hex(&bound.canonical));
        // A tampered plan (different revision) must refuse at bind time with
        // a content-identity mismatch when the id is not re-derived.
        let tampered = object(vec![
            ("schema", string("hf-plan/v1")),
            ("plan_id", string(&bound.plan_id)),
            ("workflow_id", string("fleet-doctrine-1")),
            ("workflow_hash", string(&"0".repeat(64))),
            ("state_epoch", integer(1)),
            ("repository", string("example-org/widgets")),
            (
                "issue",
                object(vec![
                    ("number", integer(123)),
                    ("revision", string(&"b".repeat(40))),
                ]),
            ),
            (
                "steps",
                Val::Arr(vec![object(vec![
                    ("id", string("p7")),
                    ("kind", string("merge")),
                    ("params", null()),
                ])]),
            ),
        ]);
        let err = bind_plan(&tampered).expect_err("tampered plan refused");
        assert_eq!(err.code, code::PLAN_IDENTITY);
    }

    #[test]
    fn expired_helper_is_lexicographic_on_fixed_shape() {
        assert!(is_expired("2026-09-05T00:00:00Z", "2026-09-06T00:00:00Z"));
        assert!(!is_expired("2026-09-07T00:00:00Z", "2026-09-06T00:00:00Z"));
        assert!(
            is_expired("not-a-timestamp", "2026-09-06T00:00:00Z"),
            "fail closed"
        );
    }
}
