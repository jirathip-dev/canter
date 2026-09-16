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
use std::path::{Component, Path, PathBuf};
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
    /// A delta-required collection found no committed content change.
    pub const COLLECT_EMPTY_DELTA: &str = "refusal.collect.empty_delta";
    /// The addressed worktree is not the worker output location the run bound.
    pub const OUTPUT_LOCATION: &str = "refusal.worker.output_location";
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
    expires_at <= now
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
/// `relative` is a path relative to the root; anything escaping (an absolute
/// path, a `..` walk, or a symlink that leaves the root) is refused. The
/// destination does not have to exist yet for the escape to be visible
/// (issue #130): the check resolves the path the effect would actually touch.
pub fn contained_path(root: &Path, relative: &str) -> Result<PathBuf, MutationError> {
    if relative.is_empty() {
        return Err(MutationError::new(code::UNCONTAINED, "empty path"));
    }
    let candidate = root.join(relative);
    if resolve_contained(root, relative).is_none() {
        return Err(MutationError::new(
            code::UNCONTAINED,
            format!("path {relative:?} escapes the containment root"),
        ));
    }
    Ok(candidate)
}

/// Resolve `relative` against `root` the way the OS resolves it at the moment
/// the effect touches it, WITHOUT requiring the destination to exist yet:
/// every component that exists is canonicalized (so a symlink can never hide
/// an escape), a `..` moves out of the already-resolved prefix, and a
/// component that does not exist yet is appended literally. `None` when the
/// walk leaves the root (or ends on the root itself).
///
/// Issue #130: the previous check compared the LITERAL `root.join(relative)`
/// with [`is_contained`], whose canonicalizing fallback cannot reveal the
/// escape while the target does not exist — `root/../escaped-lane` still
/// `starts_with` `root` lexically, so the pre-check admitted it and
/// `git worktree add` then created the lane outside the root.
fn resolve_contained(root: &Path, relative: &str) -> Option<PathBuf> {
    if Path::new(relative).is_absolute() {
        return None;
    }
    let root = canonical_or(root);
    let mut resolved = root.clone();
    for component in Path::new(relative).components() {
        match component {
            // `.` is a no-op; a `..` walks out of the resolved prefix, so an
            // escape is visible immediately instead of only once the target
            // exists.
            Component::CurDir => {}
            Component::ParentDir => {
                resolved = resolved.parent()?.to_path_buf();
            }
            Component::Normal(name) => {
                let candidate = resolved.join(name);
                resolved = match std::fs::symlink_metadata(&candidate) {
                    Ok(metadata) if metadata.file_type().is_symlink() => {
                        // A dangling symlink can make `git worktree add`
                        // create its branch before failing the filesystem
                        // operation. Refuse it before git sees the request.
                        std::fs::canonicalize(candidate).ok()?
                    }
                    Ok(_) => canonical_or(&candidate),
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => candidate,
                    Err(_) => return None,
                };
            }
            // An absolute presented path is never a lane-relative path.
            Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    (resolved.starts_with(&root) && resolved != root).then_some(resolved)
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

impl<'a> EffectContext<'a> {
    /// The param-contract view of this effect's caller-presented inputs (issue
    /// #92): the ONE place the pre-screen and the effects agree on what "the
    /// request's params" are.
    pub fn param_contract(&self) -> ParamContract<'a> {
        ParamContract {
            integration_branch: self.integration_branch,
            production_branches: self.production_branches,
            observed_feature_head: self.observed_feature_head,
            observed_integration_base: self.observed_integration_base,
            has_archive_root: self.archive_root.is_some(),
            worktrees_root: Some(self.worktrees_root),
        }
    }
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
        ProcStatus::TimedOut => {
            // Issue #92 round 2: the captured stderr carries the runner's
            // diagnostics (a group signal that could not be delivered, so a
            // descendant may have survived); the ambiguous outcome names it.
            let detail = diagnostics(&out.stdout, &out.stderr);
            Err(EffectOutcome {
                status: "ambiguous",
                code: Some(code::TIMEOUT.to_string()),
                message: Some(if detail.is_empty() {
                    format!("{label} exceeded its deadline and was cancelled")
                } else {
                    format!("{label} exceeded its deadline and was cancelled: {detail}")
                }),
                result: null(),
            })
        }
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

// ---------------------------------------------------------------------------
// Step param contracts (issue #92): every params-caused refusal an effect can
// raise is resolved HERE — before the bounded-retry fence can consume a
// single-use authorization. Each effect calls the SAME `*_inputs` function
// the pre-screen calls, so the two can never drift and no step kind inherits
// the burn.
// ---------------------------------------------------------------------------

/// The caller-presented inputs one step kind's param contract resolves
/// against besides the step params themselves: the topology fields the branch
/// classification and the archive gate read, and the request-level `observed`
/// read-backs `review_evidence` / `post_merge_verify` require. Pure values —
/// resolving a contract reads no state and runs no subprocess.
#[derive(Clone, Copy, Debug, Default)]
pub struct ParamContract<'a> {
    /// Integration branch of the repository (topology).
    pub integration_branch: &'a str,
    /// Configured production branches (topology).
    pub production_branches: &'a [String],
    /// The request's freshly observed feature head (`None` when absent).
    pub observed_feature_head: Option<&'a str>,
    /// The request's freshly observed integration base (`None` when absent).
    pub observed_integration_base: Option<&'a str>,
    /// Whether the request presented a daemon-owned archive root.
    pub has_archive_root: bool,
    /// The daemon-owned worktrees root the request presented (`None` only
    /// when the request presented none — the apply path always parses one).
    pub worktrees_root: Option<&'a Path>,
}

/// The containment screen the worktree-reading kinds run (issue #92): the
/// presented relative path must stay inside the request's worktrees root.
/// [`contained_path`] is the effect's own check, so the pre-screen and the
/// effect agree.
fn screened_containment<'a>(
    contract: &ParamContract<'a>,
    relative: &str,
) -> Result<(), EffectOutcome> {
    let Some(root) = contract.worktrees_root else {
        return Ok(());
    };
    contained_path(root, relative)
        .map(|_| ())
        .map_err(|err| refusal(err.code, err.message))
}

/// The declared harness role inputs of `harness_start` / `prompt`: the
/// role-binding key, the bare executable and the closed harness kind. The
/// run's committed role configuration is NOT part of this contract — it is
/// durable state, not a step param.
#[derive(Clone, Debug)]
pub struct HarnessInputs {
    /// The declared role-binding key (`params.harness_key`).
    pub key: String,
    /// The declared bare executable (`''` when absent).
    pub executable: String,
    /// The declared harness kind string (`argv` when absent).
    pub kind: String,
    /// The parsed closed-set kind.
    pub parsed_kind: crate::adapters::HarnessKind,
}

/// Resolve the declared harness role inputs from the step params alone. There
/// is no default profile: a step that names no role binding refuses.
pub fn harness_inputs(params: &Val) -> Result<HarnessInputs, EffectOutcome> {
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
    // An official kind carries its own executable: a declared one must match.
    if let Some(spec) = crate::adapters::official_spec(parsed_kind)
        && !executable.is_empty()
        && executable != spec.executable
    {
        return Err(refusal(
            code::BAD_PARAMS,
            format!(
                "the step declares executable {executable:?}, which is not the official {kind:?} \
                 executable {:?}",
                spec.executable
            ),
        ));
    }
    Ok(HarnessInputs {
        key: key.to_string(),
        executable: executable.to_string(),
        kind: kind.to_string(),
        parsed_kind,
    })
}

/// Resolve the declared session identity of one step (issue #92): `None` when
/// the step declares none, the bound handle otherwise. A partial identity or
/// a negative generation refuses — the adapter never completes an identity
/// with a default.
pub fn declared_session(
    params: Option<&Val>,
    what: &str,
) -> Result<Option<crate::adapters::SessionHandle>, EffectOutcome> {
    match (
        param_str_opt(params, "session_id"),
        param_str_opt(params, "herdr_session"),
        param_str_opt(params, "terminal_session"),
    ) {
        (None, None, None) => Ok(None),
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
            Ok(Some(session))
        }
    }
}

/// The params-caused inputs of `harness_start`.
#[derive(Clone, Debug)]
pub struct HarnessStartInputs {
    /// The declared harness role inputs.
    pub harness: HarnessInputs,
    /// The declared execution substrate (issue #139).
    pub execution: crate::adapters::ExecutionMode,
    /// The identity the step declares, when it declares one.
    pub declared: Option<crate::adapters::SessionHandle>,
}

/// Resolve the params-caused inputs of `harness_start` (params required; the
/// declared role key, executable and kind; the execution substrate; the
/// declared session identity).
pub fn harness_start_inputs(params: Option<&Val>) -> Result<HarnessStartInputs, EffectOutcome> {
    let Some(params) = params else {
        return Err(refusal(code::BAD_PARAMS, "harness_start requires params"));
    };
    let declared = declared_session(Some(params), "harness_start")?;
    Ok(HarnessStartInputs {
        harness: harness_inputs(params)?,
        execution: declared_execution(Some(params))?,
        declared,
    })
}

/// Resolve the declared execution substrate of one harness step (issue
/// #139). `params.execution` is a closed token (`herdr` | `headless`) and
/// defaults to the Herdr pane substrate — the product path (ADR-0003). The
/// bare-subprocess row is only ever run when the reviewed step declares
/// `"headless"`; an unknown token refuses typed and is never coerced to a
/// default, and nothing downgrades a substrate after a substrate failure.
pub fn declared_execution(
    params: Option<&Val>,
) -> Result<crate::adapters::ExecutionMode, EffectOutcome> {
    match params.and_then(|params| params.get("execution")) {
        None => Ok(crate::adapters::ExecutionMode::default()),
        Some(Val::Str(text)) => crate::adapters::ExecutionMode::parse(text).ok_or_else(|| {
            refusal(
                code::BAD_PARAMS,
                format!(
                    "step params.execution {text:?} is outside the closed substrate set ({}); a \
                         substrate is never defaulted",
                    crate::adapters::ExecutionMode::ALL
                        .iter()
                        .map(|mode| mode.name())
                        .collect::<Vec<_>>()
                        .join("|")
                ),
            )
        }),
        Some(other) => Err(refusal(
            code::BAD_PARAMS,
            format!(
                "step params.execution must be a string token ({}), got {}",
                crate::adapters::ExecutionMode::ALL
                    .iter()
                    .map(|mode| mode.name())
                    .collect::<Vec<_>>()
                    .join("|"),
                other.type_name()
            ),
        )),
    }
}

/// The lane worktrees the reviewed plan binds (issue #139), in first-bound
/// order and deduplicated. The plan document is where the lane path is
/// reviewed, so it is the only source the pane substrate reads for it.
fn plan_lane_worktrees(ctx: &EffectContext<'_>) -> Vec<String> {
    let steps = match ctx.plan.doc.get("steps") {
        Some(Val::Arr(steps)) => steps.clone(),
        _ => Vec::new(),
    };
    let mut worktrees: Vec<String> = Vec::new();
    for step in &steps {
        let Some(params) = step.get("params") else {
            continue;
        };
        let Some(worktree) = params.get("worktree").and_then(Val::as_str) else {
            continue;
        };
        if !worktrees.iter().any(|bound| bound == worktree) {
            worktrees.push(worktree.to_string());
        }
    }
    worktrees
}

/// The run's lane worktree for the pane substrate (issue #139): the pane is
/// created IN the run's lane worktree and never at a bare cwd, so the bind
/// step resolves that path from the reviewed plan and refuses typed when the
/// plan cannot name exactly one. A plan that binds several lane worktrees
/// (a multi-issue submission) is refused rather than given a pane in the
/// wrong lane — the operator keeps the explicit `params.execution =
/// "headless"` fallback for that shape.
fn run_lane_worktree(ctx: &EffectContext<'_>, what: &str) -> Result<PathBuf, EffectOutcome> {
    let worktrees = plan_lane_worktrees(ctx);
    match worktrees.len() {
        1 => {
            let worktree = contained_path(ctx.worktrees_root, &worktrees[0])
                .map_err(|err| refusal(err.code, err.message))?;
            if !worktree.is_dir() {
                return Err(refusal(
                    code::OUTPUT_LOCATION,
                    format!(
                        "{what} binds the lane worktree {:?}, which is not a directory; the Herdr \
                         pane substrate creates the worker's pane there and never at a bare cwd",
                        worktrees[0]
                    ),
                ));
            }
            Ok(worktree)
        }
        0 => Err(refusal(
            code::BAD_PARAMS,
            format!(
                "{what} runs on the Herdr pane substrate, which creates the worker's pane in the \
                 run's lane worktree, and no plan step binds a `worktree`; declare \
                 params.execution = \"headless\" to run the bare-subprocess fallback explicitly"
            ),
        )),
        _ => Err(refusal(
            code::OUTPUT_LOCATION,
            format!(
                "{what}: this plan binds {} lane worktrees ({worktrees:?}); the Herdr pane \
                 substrate binds ONE lane worktree per run and refuses rather than panning the \
                 wrong lane — declare params.execution = \"headless\" to run the bare-subprocess \
                 fallback explicitly",
                worktrees.len()
            ),
        )),
    }
}

/// The params-caused inputs of `prompt`.
#[derive(Clone, Debug)]
pub struct PromptInputs {
    /// The declared harness role inputs.
    pub harness: HarnessInputs,
    /// The declared execution substrate (issue #139).
    pub execution: crate::adapters::ExecutionMode,
    /// The identity the step declares, when it declares one.
    pub declared: Option<crate::adapters::SessionHandle>,
    /// The bounded prompt payload.
    pub payload: String,
    /// The relative lane worktree the prompt runs inside.
    pub worktree: String,
    /// The feature branch this run bound, when declared.
    pub branch: Option<String>,
    /// Whether the following collection requires a committed delta.
    pub requires_delta: bool,
}

/// Resolve the params-caused inputs of `prompt` (params required; payload and
/// worktree required; the declared role key, executable and kind; the
/// declared session identity).
pub fn prompt_inputs(
    params: Option<&Val>,
    contract: &ParamContract<'_>,
) -> Result<PromptInputs, EffectOutcome> {
    let Some(params) = params else {
        return Err(refusal(code::BAD_PARAMS, "prompt requires params"));
    };
    let payload = param_str(Some(params), "payload")?.to_string();
    let worktree = param_str(Some(params), "worktree")?.to_string();
    screened_containment(contract, &worktree)?;
    let branch = match param_str_opt(Some(params), "branch") {
        Some(branch) if is_slug(branch) => Some(branch.to_string()),
        Some(_) => return Err(refusal(code::BAD_PARAMS, "prompt branch must be a slug")),
        None => None,
    };
    let requires_delta = match params.get("requires_delta") {
        Some(Val::Bool(value)) => *value,
        Some(_) => {
            return Err(refusal(
                code::BAD_PARAMS,
                "prompt requires_delta must be true|false",
            ));
        }
        None => false,
    };
    let declared = declared_session(Some(params), "prompt")?;
    Ok(PromptInputs {
        harness: harness_inputs(params)?,
        execution: declared_execution(Some(params))?,
        declared,
        payload,
        worktree,
        branch,
        requires_delta,
    })
}

/// The params-caused inputs of `collect_outcome`.
#[derive(Clone, Debug)]
pub struct CollectOutcomeInputs {
    /// The relative lane worktree to collect from.
    pub worktree: String,
    /// The declared or freshly observed integration base.
    pub base_head: String,
    /// The feature branch the run bound, when declared.
    pub branch: Option<String>,
    /// Whether an empty committed delta is a typed refusal.
    pub requires_delta: bool,
}

/// Resolve the params-caused inputs of `collect_outcome` (worktree required;
/// a declared `base_head` must be 40-hex).
pub fn collect_outcome_inputs(
    params: Option<&Val>,
    contract: &ParamContract<'_>,
) -> Result<CollectOutcomeInputs, EffectOutcome> {
    let worktree = param_str(params, "worktree")?.to_string();
    screened_containment(contract, &worktree)?;
    let base_head = match param_str_opt(params, "base_head").or(contract.observed_integration_base)
    {
        Some(head) if is_hex40(head) => head.to_string(),
        Some(_) => return Err(refusal(code::BAD_PARAMS, "base_head must be 40-hex")),
        None => {
            return Err(refusal(
                code::BAD_PARAMS,
                "collect_outcome requires base_head from this run's recorded checkout or the apply's exact observed integration base; the current integration branch is never substituted",
            ));
        }
    };
    let branch = match param_str_opt(params, "branch") {
        Some(branch) if is_slug(branch) => Some(branch.to_string()),
        Some(_) => {
            return Err(refusal(
                code::BAD_PARAMS,
                "collect_outcome branch must be a slug",
            ));
        }
        None => None,
    };
    let requires_delta = match params.and_then(|value| value.get("requires_delta")) {
        Some(Val::Bool(value)) => *value,
        Some(_) => {
            return Err(refusal(
                code::BAD_PARAMS,
                "collect_outcome requires_delta must be true|false",
            ));
        }
        None => false,
    };
    Ok(CollectOutcomeInputs {
        worktree,
        base_head,
        branch,
        requires_delta,
    })
}

/// The params-caused inputs of `review_evidence`.
#[derive(Clone, Debug)]
pub struct ReviewEvidenceInputs {
    /// The reviewer identity.
    pub reviewer: String,
    /// The implementer identity.
    pub implementer: String,
    /// The verdict (`pass` | `fail`).
    pub verdict: String,
    /// The non-empty named-check list.
    pub checks: Val,
    /// The exact reviewed feature head (request-level read-back).
    pub feature_head: String,
    /// The observed integration base (request-level read-back).
    pub integration_base: String,
}

/// Resolve the params-caused inputs of `review_evidence` (params required;
/// reviewer/implementer/verdict/checks; the reviewer must differ from the
/// implementer; both observed read-backs are required and 40-hex).
pub fn review_evidence_inputs(
    params: Option<&Val>,
    contract: &ParamContract<'_>,
) -> Result<ReviewEvidenceInputs, EffectOutcome> {
    let Some(params) = params else {
        return Err(refusal(code::BAD_PARAMS, "review_evidence requires params"));
    };
    let reviewer = param_str(Some(params), "reviewer")?.to_string();
    let implementer = param_str(Some(params), "implementer")?.to_string();
    let verdict = match param_str(Some(params), "verdict") {
        Ok(value) if matches!(value, "pass" | "fail") => value.to_string(),
        _ => {
            return Err(refusal(
                code::BAD_PARAMS,
                "review_evidence verdict must be pass|fail",
            ));
        }
    };
    let feature_head = match contract.observed_feature_head {
        Some(value) if is_hex40(value) => value.to_string(),
        _ => {
            return Err(refusal(
                code::BAD_PARAMS,
                "review_evidence requires observed.feature_head (fresh exact-head read-back)",
            ));
        }
    };
    let integration_base = match contract.observed_integration_base {
        Some(value) if is_hex40(value) => value.to_string(),
        _ => {
            return Err(refusal(
                code::BAD_PARAMS,
                "review_evidence requires observed.integration_base (fresh read-back)",
            ));
        }
    };
    check_reviewer_distinct(&reviewer, &implementer)
        .map_err(|err| refusal(err.code, err.message))?;
    let checks = match params.get("checks") {
        Some(Val::Arr(items)) if !items.is_empty() => Val::Arr(items.clone()),
        _ => {
            return Err(refusal(
                code::BAD_PARAMS,
                "review_evidence requires a non-empty checks list",
            ));
        }
    };
    Ok(ReviewEvidenceInputs {
        reviewer,
        implementer,
        verdict,
        checks,
        feature_head,
        integration_base,
    })
}

/// The explicit integration policy of a read-only merge rehearsal.
#[derive(Clone, Debug)]
pub struct MergeInputs {
    /// The slug feature branch.
    pub branch: String,
    /// The closed policy (`squash` | `ff`).
    pub policy: String,
}

/// Resolve the params-caused inputs of `merge` (feature branch + policy).
pub fn merge_inputs(
    params: Option<&Val>,
    contract: &ParamContract<'_>,
) -> Result<MergeInputs, EffectOutcome> {
    let branch = match param_str(params, "branch") {
        Ok(value) if is_slug(value) => value.to_string(),
        _ => {
            return Err(refusal(
                code::BAD_PARAMS,
                "merge requires a slug feature branch",
            ));
        }
    };
    let kind = classify_branch(
        &branch,
        contract.integration_branch,
        contract.production_branches,
    );
    if kind != BranchKind::Feature {
        return Err(refusal(
            code::PUSH_POLICY,
            format!("only feature branches merge to the integration branch, got {branch:?}"),
        ));
    }
    let policy = match param_str(params, "merge_policy") {
        Ok(value @ ("squash" | "ff")) => value.to_string(),
        _ => {
            return Err(refusal(
                code::BAD_PARAMS,
                "merge requires merge_policy squash|ff",
            ));
        }
    };
    Ok(MergeInputs { branch, policy })
}

/// The params-caused inputs of `branch_push`.
#[derive(Clone, Debug)]
pub struct BranchPushInputs {
    /// The slug feature branch.
    pub branch: String,
    /// The allowlisted remote name.
    pub remote: String,
    /// The declared force flag (never allowed).
    pub force: bool,
}

/// Resolve the params-caused inputs of `branch_push` (branch slug, remote,
/// and the push policy).
pub fn branch_push_inputs(
    params: Option<&Val>,
    contract: &ParamContract<'_>,
) -> Result<BranchPushInputs, EffectOutcome> {
    let branch = match param_str(params, "branch") {
        Ok(value) if is_slug(value) => value.to_string(),
        _ => {
            return Err(refusal(
                code::BAD_PARAMS,
                "branch_push requires a slug branch",
            ));
        }
    };
    let remote = param_str(params, "remote")?.to_string();
    let force = param_bool(params, "force");
    check_push_policy(
        &branch,
        force,
        contract.integration_branch,
        contract.production_branches,
    )
    .map_err(|err| refusal(err.code, err.message))?;
    Ok(BranchPushInputs {
        branch,
        remote,
        force,
    })
}

/// The params-caused inputs of `publish` / `pr_update`.
#[derive(Clone, Debug)]
pub struct PrUpdateInputs {
    /// The action (`create` | `comment`).
    pub action: String,
    /// The owner/name repository identity.
    pub repo: String,
    /// The head branch.
    pub head: String,
    /// The base branch (`create` only).
    pub base: Option<String>,
    /// The PR title.
    pub title: String,
    /// The PR body / comment text.
    pub body: String,
    /// The PR number (`comment`; `0` when absent).
    pub number: i64,
}

/// Resolve the params-caused inputs of `publish` / `pr_update` (params
/// required; action, owner/name repo, head; `create` additionally requires a
/// base and passes the main-PR-origin and external-contributor policy).
pub fn pr_update_inputs(
    params: Option<&Val>,
    contract: &ParamContract<'_>,
) -> Result<PrUpdateInputs, EffectOutcome> {
    let Some(params) = params else {
        return Err(refusal(code::BAD_PARAMS, "pr_update requires params"));
    };
    let action = match param_str(Some(params), "action") {
        Ok(value @ ("create" | "comment")) => value.to_string(),
        _ => {
            return Err(refusal(
                code::BAD_PARAMS,
                "pr_update action must be create|comment",
            ));
        }
    };
    let repo = match param_str(Some(params), "repo") {
        Ok(value) if is_repository_identity(value) => value.to_string(),
        _ => {
            return Err(refusal(
                code::BAD_PARAMS,
                "pr_update requires an owner/name repo",
            ));
        }
    };
    let head = param_str(Some(params), "head")?.to_string();
    let base = if action == "create" {
        let base = param_str(Some(params), "base")?.to_string();
        check_main_pr_origin(
            &head,
            &base,
            contract.integration_branch,
            contract.production_branches,
        )
        .map_err(|err| refusal(err.code, err.message))?;
        let head_repo_matches =
            param_str_opt(Some(params), "head_repo").is_none_or(|hr| hr == repo);
        check_external_contributor(
            head_repo_matches,
            param_bool(Some(params), "maintainer_approval"),
        )
        .map_err(|err| refusal(err.code, err.message))?;
        Some(base)
    } else {
        None
    };
    Ok(PrUpdateInputs {
        action,
        repo,
        head,
        base,
        title: param_str_opt(Some(params), "title")
            .unwrap_or("")
            .to_string(),
        body: param_str_opt(Some(params), "body")
            .unwrap_or("")
            .to_string(),
        number: param_int(Some(params), "number").unwrap_or(0),
    })
}

/// The params-caused inputs of `issue_update`.
#[derive(Clone, Debug)]
pub struct IssueUpdateInputs {
    /// The action (`comment` | `close`).
    pub action: String,
    /// The owner/name repository identity.
    pub repo: String,
}

/// Resolve the params-caused inputs of `issue_update` (params required;
/// action and owner/name repo).
pub fn issue_update_inputs(params: Option<&Val>) -> Result<IssueUpdateInputs, EffectOutcome> {
    let Some(params) = params else {
        return Err(refusal(code::BAD_PARAMS, "issue_update requires params"));
    };
    let action = match param_str(Some(params), "action") {
        Ok("comment") | Ok("close") => param_str(Some(params), "action")
            .unwrap_or("comment")
            .to_string(),
        _ => {
            return Err(refusal(
                code::BAD_PARAMS,
                "issue_update action must be comment|close",
            ));
        }
    };
    let repo = match param_str(Some(params), "repo") {
        Ok(value) if is_repository_identity(value) => value.to_string(),
        _ => {
            return Err(refusal(
                code::BAD_PARAMS,
                "issue_update requires an owner/name repo",
            ));
        }
    };
    Ok(IssueUpdateInputs { action, repo })
}

/// Resolve the params-caused input of `hosted_check` (params required; an
/// owner/name repo).
pub fn hosted_check_inputs(params: Option<&Val>) -> Result<String, EffectOutcome> {
    let Some(params) = params else {
        return Err(refusal(code::BAD_PARAMS, "hosted_check requires params"));
    };
    match param_str(Some(params), "repo") {
        Ok(value) if is_repository_identity(value) => Ok(value.to_string()),
        _ => Err(refusal(
            code::BAD_PARAMS,
            "hosted_check requires an owner/name repo",
        )),
    }
}

/// Resolve the params-caused input of `post_merge_verify` (the exact reviewed
/// feature head from the request's observed block).
pub fn post_merge_verify_inputs(contract: &ParamContract<'_>) -> Result<String, EffectOutcome> {
    match contract.observed_feature_head {
        Some(value) if is_hex40(value) => Ok(value.to_string()),
        _ => Err(refusal(
            code::BAD_PARAMS,
            "post_merge_verify requires observed.feature_head (exact reviewed head)",
        )),
    }
}

/// The params-caused inputs of `cleanup`.
#[derive(Clone, Debug)]
pub struct CleanupInputs {
    /// The relative lane worktree to clean up.
    pub worktree: String,
    /// The slug branch the worktree carries.
    pub branch: String,
}

/// Resolve the params-caused inputs of `cleanup` (worktree and slug branch
/// required; a declared `archive` needs the daemon-owned archive root).
pub fn cleanup_inputs(
    params: Option<&Val>,
    contract: &ParamContract<'_>,
) -> Result<CleanupInputs, EffectOutcome> {
    let worktree = param_str(params, "worktree")?.to_string();
    screened_containment(contract, &worktree)?;
    let branch = match param_str(params, "branch") {
        Ok(value) if is_slug(value) => value.to_string(),
        _ => return Err(refusal(code::BAD_PARAMS, "cleanup requires a slug branch")),
    };
    if param_bool(params, "archive") && !contract.has_archive_root {
        return Err(refusal(
            code::BAD_PARAMS,
            "cleanup archive requires topology.archive_root (daemon-owned)",
        ));
    }
    Ok(CleanupInputs { worktree, branch })
}

/// Resolve the params-caused inputs of `branch_delete` (a slug FEATURE
/// branch).
pub fn branch_delete_inputs(
    params: Option<&Val>,
    contract: &ParamContract<'_>,
) -> Result<String, EffectOutcome> {
    let branch = match param_str(params, "branch") {
        Ok(value) if is_slug(value) => value.to_string(),
        _ => {
            return Err(refusal(
                code::BAD_PARAMS,
                "branch_delete requires a slug branch",
            ));
        }
    };
    let kind = classify_branch(
        &branch,
        contract.integration_branch,
        contract.production_branches,
    );
    if kind != BranchKind::Feature {
        return Err(refusal(
            code::PUSH_POLICY,
            format!("branch_delete only removes feature lanes, got {branch:?}"),
        ));
    }
    Ok(branch)
}

/// Resolve the params-caused inputs of `approve` (params required; a 64-hex
/// digest; the interactive confirmation).
pub fn approve_inputs(params: Option<&Val>) -> Result<String, EffectOutcome> {
    let Some(params) = params else {
        return Err(refusal(code::BAD_PARAMS, "approve requires params"));
    };
    let digest = match param_str(Some(params), "digest") {
        Ok(value) if is_hex64(value) => value.to_string(),
        _ => {
            return Err(refusal(
                code::BAD_PARAMS,
                "approve requires a 64-hex digest",
            ));
        }
    };
    if !param_bool(Some(params), "interactive") {
        return Err(refusal(
            code::APPROVAL_NOT_INTERACTIVE,
            "the first-real-write approval must be an interactive TTY confirmation",
        ));
    }
    Ok(digest)
}

/// The `worktree_create` lane inputs — the branch and the relative worktree
/// path — resolved from the step params. The ONE authoring of this step
/// kind's param contract: the effect and the pre-screen both read it.
pub fn worktree_create_inputs(
    params: Option<&Val>,
    contract: &ParamContract<'_>,
) -> Result<(String, String), EffectOutcome> {
    let branch = match param_str(params, "branch") {
        Ok(branch) if is_slug(branch) => branch.to_string(),
        _ => {
            return Err(refusal(
                code::BAD_PARAMS,
                "worktree_create requires a slug branch",
            ));
        }
    };
    let kind = classify_branch(
        &branch,
        contract.integration_branch,
        contract.production_branches,
    );
    if kind != BranchKind::Feature {
        return Err(refusal(
            code::PUSH_POLICY,
            format!("worktree branches must be feature lanes, got {branch:?}"),
        ));
    }
    let relative = param_str(params, "worktree")?.to_string();
    screened_containment(contract, &relative)?;
    Ok((branch, relative))
}

/// The daemon-side param contract of one step kind: `Ok(())` when the
/// presented params are well-formed enough for the effect to be ATTEMPTED, a
/// typed refusal otherwise. TOTAL and fail-closed over the closed step-kind
/// set: every params-caused refusal the effect body resolves (step params,
/// the request-level `observed` read-backs, the topology gates) is raised
/// here, BEFORE the bounded-retry fence can consume a single-use
/// authorization. A kind with no registered contract refuses too — no
/// unregistered kind ever inherits the burn. Pure: no state, no subprocess,
/// no side effect. The dispatch path evaluates it before anything is
/// journaled, so a malformed re-dispatch refuses typed and never burns the
/// operator's single-use authorization.
pub fn check_step_params(
    kind: &str,
    params: Option<&Val>,
    contract: &ParamContract<'_>,
) -> Result<(), (String, String)> {
    let typed = |outcome: EffectOutcome| -> (String, String) {
        (
            outcome.code.unwrap_or_else(|| code::BAD_PARAMS.to_string()),
            outcome
                .message
                .unwrap_or_else(|| "step params malformed".to_string()),
        )
    };
    match kind {
        // The effect reads no param and refuses none.
        "checkout" => {}
        "worktree_create" => {
            worktree_create_inputs(params, contract)
                .map(|_| ())
                .map_err(typed)?;
        }
        "harness_start" => {
            harness_start_inputs(params).map(|_| ()).map_err(typed)?;
        }
        "prompt" => {
            prompt_inputs(params, contract).map(|_| ()).map_err(typed)?;
        }
        "collect_outcome" => {
            collect_outcome_inputs(params, contract)
                .map(|_| ())
                .map_err(typed)?;
        }
        "review_evidence" => {
            review_evidence_inputs(params, contract)
                .map(|_| ())
                .map_err(typed)?;
        }
        "merge" => {
            merge_inputs(params, contract).map(|_| ()).map_err(typed)?;
        }
        "cleanup" => {
            cleanup_inputs(params, contract)
                .map(|_| ())
                .map_err(typed)?;
        }
        "publish" | "pr_update" => {
            pr_update_inputs(params, contract)
                .map(|_| ())
                .map_err(typed)?;
        }
        "branch_push" => {
            branch_push_inputs(params, contract)
                .map(|_| ())
                .map_err(typed)?;
        }
        "issue_update" => {
            issue_update_inputs(params).map(|_| ()).map_err(typed)?;
        }
        "hosted_check" => {
            hosted_check_inputs(params).map(|_| ()).map_err(typed)?;
        }
        "post_merge_verify" => {
            post_merge_verify_inputs(contract)
                .map(|_| ())
                .map_err(typed)?;
        }
        "branch_delete" => {
            branch_delete_inputs(params, contract)
                .map(|_| ())
                .map_err(typed)?;
        }
        "approve" => {
            approve_inputs(params).map(|_| ()).map_err(typed)?;
        }
        other => {
            return Err((
                code::UNKNOWN_KIND.to_string(),
                format!(
                    "step kind {other:?} has no registered param contract; a dispatch of an \
                     unsupported kind is refused before any bounded retry authorization is \
                     consumed"
                ),
            ));
        }
    }
    // A declared bounded deadline is part of the same contract.
    effect_deadline_secs(kind, params)
        .map(|_| ())
        .map_err(typed)
}

/// `worktree_create`: create an isolated lane worktree + branch off the
/// current integration head (path-contained under the lane root).
fn effect_worktree_create(ctx: &EffectContext<'_>) -> EffectOutcome {
    let (branch, relative) = match worktree_create_inputs(ctx.params, &ctx.param_contract()) {
        Ok(inputs) => inputs,
        Err(outcome) => return outcome,
    };
    let worktree = match contained_path(ctx.worktrees_root, &relative) {
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
    let inputs = match harness_start_inputs(ctx.params) {
        Ok(inputs) => inputs,
        Err(outcome) => return outcome,
    };
    let params = match ctx.params {
        Some(params) => params,
        None => return refusal(code::BAD_PARAMS, "harness_start requires params"),
    };
    let session = match resolve_session(ctx, inputs.declared, "harness_start") {
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
    // Issue #139: the substrate decides WHERE the role starts. The Herdr
    // pane substrate creates (or reuses) the worker's pane IN the run's lane
    // worktree — never at a bare cwd — so the bind effect resolves that path
    // from the reviewed plan and refuses typed when the plan cannot name
    // exactly one. The headless substrate keeps its pre-#139 working
    // directory byte for byte.
    let cwd = match profile.execution {
        crate::adapters::ExecutionMode::Headless => ctx.integration_repo.to_path_buf(),
        crate::adapters::ExecutionMode::HerdrPane => {
            match run_lane_worktree(ctx, "harness_start") {
                Ok(worktree) => worktree,
                Err(outcome) => return outcome,
            }
        }
    };
    let result = crate::adapters::execute_op_in_worktree(&profile, &request, ctx.env, &cwd);
    if result.status != "succeeded" {
        return EffectOutcome {
            status: result.status,
            code: result.code.map(str::to_string),
            message: result.message.clone().or_else(|| result.detail.clone()),
            result: null(),
        };
    }
    // The recorded binding names the substrate and, on the pane substrate,
    // the exact pane/agent identity the worker runs in (issue #139) — the
    // read-back the effect reports is the adapter's verified one.
    let mut fields = match session_binding_result(ctx, &profile, &session) {
        Val::Obj(fields) => fields,
        _ => unreachable!("the session binding result is an object"),
    };
    fields.insert("execution".to_string(), string(profile.execution.name()));
    for key in ["pane", "agent", "reused"] {
        fields.insert(
            key.to_string(),
            result
                .payload
                .as_ref()
                .and_then(|payload| payload.get(key).cloned())
                .unwrap_or_else(null),
        );
    }
    ok(Val::Obj(fields))
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

/// The session one harness step runs under (issue #92 F2): the run's BOUND
/// session is authoritative when the run has one (it is what `harness_start`
/// bound); the identity the step declares (resolved by [`declared_session`],
/// the params-only half both the pre-screen and this function read) must
/// AGREE with it. When neither exists the step is refused: the adapter never
/// invents a session identity and never substitutes a default.
fn resolve_session(
    ctx: &EffectContext<'_>,
    declared: Option<crate::adapters::SessionHandle>,
    what: &str,
) -> Result<crate::adapters::SessionHandle, EffectOutcome> {
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
    let inputs = match prompt_inputs(ctx.params, &ctx.param_contract()) {
        Ok(inputs) => inputs,
        Err(outcome) => return outcome,
    };
    let payload = inputs.payload.as_str();
    let worktree = match contained_path(ctx.worktrees_root, &inputs.worktree) {
        Ok(path) => path,
        Err(err) => return refusal(err.code, err.message),
    };
    if !worktree.join(".git").exists() && !worktree.join("HEAD").exists() {
        return refusal(
            code::UNCONTAINED,
            format!("{} is not a git worktree", worktree.display()),
        );
    }
    let branch = match observed_worktree_branch(ctx, &worktree, inputs.branch.as_deref()) {
        Ok(branch) => branch,
        Err(outcome) => return outcome,
    };
    let profile = match harness_profile(ctx, params) {
        Ok(profile) => profile,
        Err(outcome) => return outcome,
    };
    // Issue #92 F2: the prompt continues the session `harness_start` bound —
    // the run's bound session when the run carries one, else the identity the
    // reviewed plan declares. A partial or absent identity is refused; the
    // adapter never invents one (the pre-fix default "herdr-fleet-lane" is
    // gone).
    let session = match resolve_session(ctx, inputs.declared, "prompt") {
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
        // Issue #148 item 2: every failed prompt is DIAGNOSABLE on the run's
        // own records. The adapter's detail carries what actually happened —
        // the exact Herdr argv, the raw stdout, the raw stderr, the exit
        // status and the resolved pane/agent — and the apply path records ONE
        // message, so dropping the detail here is what left the #147 run with
        // a bare `adapter.exit` and the operator with nothing to act on.
        let message = match (result.message.clone(), result.detail.clone()) {
            (Some(message), Some(detail)) if !detail.is_empty() => {
                Some(format!("{message} | {detail}"))
            }
            (Some(message), _) => Some(message),
            (None, detail) => detail,
        };
        return EffectOutcome {
            status: result.status,
            code: result.code.map(str::to_string),
            message,
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
    fields.insert("worktree".to_string(), string(&inputs.worktree));
    fields.insert("branch".to_string(), string(&branch));
    fields.insert("requires_delta".to_string(), bool_(inputs.requires_delta));
    // Issue #139: the recorded outcome names the substrate and, on the pane
    // substrate, the settled Herdr agent state the delivery was observed in
    // — the terminal outcome is collected through Herdr, not inferred from a
    // process exit.
    fields.insert("execution".to_string(), string(profile.execution.name()));
    fields.insert(
        "harness_state".to_string(),
        result
            .payload
            .as_ref()
            .and_then(|payload| payload.get("state").cloned())
            .unwrap_or_else(null),
    );
    ok(Val::Obj(fields))
}

/// Read the branch of the exact worktree a prompt/collection binds. A
/// declared mismatch is an output-location refusal, never success against a
/// different worker checkout.
fn observed_worktree_branch(
    ctx: &EffectContext<'_>,
    worktree: &Path,
    expected: Option<&str>,
) -> Result<String, EffectOutcome> {
    let branch = run_git(ctx, worktree, &["branch", "--show-current"])?
        .stdout
        .trim()
        .to_string();
    if branch.is_empty() {
        return Err(refusal(
            code::OUTPUT_LOCATION,
            format!(
                "worker output location {} has no branch",
                worktree.display()
            ),
        ));
    }
    if let Some(expected) = expected
        && branch != expected
    {
        return Err(refusal(
            code::OUTPUT_LOCATION,
            format!(
                "worker output location {} is on branch {branch:?}, not the run's bound branch {expected:?}",
                worktree.display()
            ),
        ));
    }
    Ok(branch)
}

/// `collect_outcome`: collect the lane's commits/head since the integration
/// base and read the harness terminal outcome through the workspace
/// protocol (herdr workspace executable; fake-pinned in tests).
fn effect_collect_outcome(ctx: &EffectContext<'_>) -> EffectOutcome {
    let inputs = match collect_outcome_inputs(ctx.params, &ctx.param_contract()) {
        Ok(inputs) => inputs,
        Err(outcome) => return outcome,
    };
    let worktree = match contained_path(ctx.worktrees_root, &inputs.worktree) {
        Ok(path) => path,
        Err(err) => return refusal(err.code, err.message),
    };
    let base_head = inputs.base_head;
    let head_out = match run_git(ctx, &worktree, &["rev-parse", "--verify", "HEAD"]) {
        Ok(out) => out,
        Err(outcome) => return outcome,
    };
    let head = head_out.stdout.trim().to_string();
    let branch = match observed_worktree_branch(ctx, &worktree, inputs.branch.as_deref()) {
        Ok(branch) => branch,
        Err(outcome) => return outcome,
    };
    if run_git(
        ctx,
        &worktree,
        &["merge-base", "--is-ancestor", &base_head, &head],
    )
    .is_err()
    {
        return refusal(
            code::OUTPUT_LOCATION,
            format!(
                "worker output head {head} in {} is not descended from this run's recorded base {base_head}",
                worktree.display()
            ),
        );
    }
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
        Err(outcome) => return outcome,
    };
    let commits: Vec<Val> = log_out
        .stdout
        .lines()
        .filter(|line| is_hex40(line))
        .map(string)
        .collect();
    let delta = match run_git(
        ctx,
        &worktree,
        &["diff", "--name-only", &base_head, &head, "--"],
    ) {
        Ok(out) => out,
        Err(outcome) => return outcome,
    };
    let changed: Vec<Val> = delta
        .stdout
        .lines()
        .filter(|line| !line.is_empty())
        .map(string)
        .collect();
    if inputs.requires_delta && (head == base_head || commits.is_empty() || changed.is_empty()) {
        return refusal(
            code::COLLECT_EMPTY_DELTA,
            format!(
                "collect_outcome requires a committed delta in worktree {:?} on branch {branch:?}, but recorded base {base_head} and head {head} contain no changed files",
                inputs.worktree,
            ),
        );
    }
    ok(object(vec![
        ("head", string(&head)),
        ("commits", Val::Arr(commits)),
        ("base_head", string(&base_head)),
        ("worktree", string(&inputs.worktree)),
        ("branch", string(&branch)),
        ("requires_delta", bool_(inputs.requires_delta)),
        ("changed_files", Val::Arr(changed)),
    ]))
}

/// `review_evidence`: validate a review-evidence step and return the typed
/// record values the daemon stores durably (AC4 bindings; reviewer distinct
/// from implementer). No subprocess runs.
fn effect_review_evidence(ctx: &EffectContext<'_>) -> EffectOutcome {
    let inputs = match review_evidence_inputs(ctx.params, &ctx.param_contract()) {
        Ok(inputs) => inputs,
        Err(outcome) => return outcome,
    };
    ok(object(vec![
        ("repository", string(ctx.repository)),
        ("feature_head", string(&inputs.feature_head)),
        ("integration_base", string(&inputs.integration_base)),
        ("workflow_hash", string(&ctx.plan.workflow_hash)),
        ("verdict", string(&inputs.verdict)),
        ("reviewer", string(&inputs.reviewer)),
        ("checks", inputs.checks),
    ]))
}

/// The head of the integration branch **as published** on the integration
/// checkout's `origin` remote (`git ls-remote`) — never from the checkout's
/// own refs, which cannot see a bare-remote move (issue #132). An unreadable
/// or absent published ref refuses fail-closed: a rehearsal that cannot prove
/// the published base must not certify a merge.
fn published_integration_head(ctx: &EffectContext<'_>) -> Result<String, EffectOutcome> {
    let out = run_git(
        ctx,
        ctx.integration_repo,
        &[
            "ls-remote",
            "origin",
            &format!("refs/heads/{}", ctx.integration_branch),
        ],
    )?;
    let head = out.stdout.split_whitespace().next().unwrap_or_default();
    if !is_hex40(head) {
        return Err(failed(
            code::MERGE_FAILED,
            format!(
                "the published integration ref {:?} is not readable from origin: the integration checkout cannot prove the merge base",
                ctx.integration_branch
            ),
        ));
    }
    Ok(head.to_string())
}

/// `merge`: rehearse the explicit integration policy without changing the
/// integration checkout, any ref, or the remote. The evidence gate runs
/// daemon-side before this effect; the orchestrator owns the real forge merge.
fn effect_merge(ctx: &EffectContext<'_>) -> EffectOutcome {
    let inputs = match merge_inputs(ctx.params, &ctx.param_contract()) {
        Ok(inputs) => inputs,
        Err(outcome) => return outcome,
    };
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
    let integration_head = match run_git(
        ctx,
        ctx.integration_repo,
        &["rev-parse", "--verify", ctx.integration_branch],
    ) {
        Ok(out) => out.stdout.trim().to_string(),
        Err(outcome) => return outcome,
    };
    // Certify only the PUBLISHED integration ref (issue #132): a checkout that
    // disagrees with the remote's head — behind it (a bare-remote move without
    // a fetch) or ahead of it (an unpublished local move) — would record an
    // integration head the plan's next `checkout` step cannot trust.
    let published_head = match published_integration_head(ctx) {
        Ok(head) => head,
        Err(outcome) => return outcome,
    };
    if published_head != integration_head {
        return failed(
            code::MERGE_NOT_FF,
            format!(
                "{} policy rehearsal refused: the published integration ref {:?} is at {published_head}, but the integration checkout is at {integration_head}: fetch and re-review before merging",
                inputs.policy, ctx.integration_branch
            ),
        );
    }
    let reviewed_base = ctx.observed_integration_base.unwrap_or_default();
    let feature_tree = match run_git(
        ctx,
        ctx.integration_repo,
        &[
            "rev-parse",
            "--verify",
            &format!("{}^{{tree}}", inputs.branch),
        ],
    ) {
        Ok(out) => out.stdout.trim().to_string(),
        Err(outcome) => return outcome,
    };
    let integration_tree = match run_git(
        ctx,
        ctx.integration_repo,
        &[
            "rev-parse",
            "--verify",
            &format!("{}^{{tree}}", ctx.integration_branch),
        ],
    ) {
        Ok(out) => out.stdout.trim().to_string(),
        Err(outcome) => return outcome,
    };
    let feature_descends = run_git(
        ctx,
        ctx.integration_repo,
        &[
            "merge-base",
            "--is-ancestor",
            &integration_head,
            &inputs.branch,
        ],
    )
    .is_ok();
    if integration_head != reviewed_base && feature_tree != integration_tree {
        return failed(
            code::MERGE_NOT_FF,
            format!(
                "{} policy rehearsal refused: integration ref {:?} is at {integration_head}, not reviewed base {reviewed_base}",
                inputs.policy, ctx.integration_branch
            ),
        );
    }
    if inputs.policy == "ff" && !feature_descends {
        return failed(
            code::MERGE_NOT_FF,
            format!(
                "ff policy divergence: feature branch {:?} is not a descendant of integration ref {:?}; a squash result is not an ff merge",
                inputs.branch, ctx.integration_branch
            ),
        );
    }
    if inputs.policy == "squash" && !feature_descends && feature_tree != integration_tree {
        return failed(
            code::MERGE_FAILED,
            format!(
                "squash policy rehearsal cannot prove feature tree {feature_tree} against integration tree {integration_tree}"
            ),
        );
    }
    ok(object(vec![
        ("mode", string("rehearsal")),
        ("landed", bool_(false)),
        ("merge_policy", string(&inputs.policy)),
        ("integration_branch", string(ctx.integration_branch)),
        ("integration_head", string(&integration_head)),
        ("feature_branch", string(&inputs.branch)),
        ("result_tree", string(&feature_tree)),
    ]))
}

/// `post_merge_verify`: prove the merged integration head contains the
/// reviewed feature head (exact git ancestry; AC7's verification step).
fn effect_post_merge_verify(ctx: &EffectContext<'_>) -> EffectOutcome {
    let feature_head = match post_merge_verify_inputs(&ctx.param_contract()) {
        Ok(head) => head,
        Err(outcome) => return outcome,
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
    let inputs = match branch_push_inputs(ctx.params, &ctx.param_contract()) {
        Ok(inputs) => inputs,
        Err(outcome) => return outcome,
    };
    let branch = inputs.branch;
    let remote = inputs.remote;
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
    let inputs = match pr_update_inputs(ctx.params, &ctx.param_contract()) {
        Ok(inputs) => inputs,
        Err(outcome) => return outcome,
    };
    let action = inputs.action;
    let repo = inputs.repo;
    let head = inputs.head;
    let title = inputs.title;
    let body = inputs.body;
    let number = inputs.number;
    let base = inputs.base;
    let args = if action == "create" {
        vec![
            "pr".to_string(),
            "create".to_string(),
            "--repo".to_string(),
            repo.clone(),
            "--base".to_string(),
            base.clone().unwrap_or_default(),
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
    let inputs = match issue_update_inputs(ctx.params) {
        Ok(inputs) => inputs,
        Err(outcome) => return outcome,
    };
    let action = inputs.action;
    let repo = inputs.repo;
    let number = param_int(ctx.params, "number").unwrap_or(0);
    let body = param_str_opt(ctx.params, "body").unwrap_or("");
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
    let repo = match hosted_check_inputs(ctx.params) {
        Ok(repo) => repo,
        Err(outcome) => return outcome,
    };
    let number = param_int(ctx.params, "number").unwrap_or(0);
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
    let inputs = match cleanup_inputs(ctx.params, &ctx.param_contract()) {
        Ok(inputs) => inputs,
        Err(outcome) => return outcome,
    };
    let relative = inputs.worktree.as_str();
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
    let branch = inputs.branch;
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
    let branch = match branch_delete_inputs(ctx.params, &ctx.param_contract()) {
        Ok(branch) => branch,
        Err(outcome) => return outcome,
    };
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
    let digest = match approve_inputs(ctx.params) {
        Ok(digest) => digest,
        Err(outcome) => return outcome,
    };
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
    // The params-only half is the SAME authoring the pre-screen reads
    // ([`harness_inputs`]); this function adds the durable-state agreement.
    let HarnessInputs {
        key,
        executable,
        kind,
        parsed_kind,
    } = harness_inputs(params)?;
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
            // The declared executable was already screened against the
            // official spec by `harness_inputs` (the params-only half).
            Some(_spec) => crate::adapters::Profile::official(parsed_kind, &role.key),
            None => crate::adapters::Profile::argv(
                &role.key,
                &executable,
                &crate::adapters::HARNESS_CAPS,
                BTreeMap::new(),
            ),
        }
        .map_err(|err| refusal(err.code, err.message))?;
        // Issue #139: the substrate is the one the reviewed step declares
        // (default: the Herdr pane substrate). It is resolved BEFORE the
        // binding is applied — a malformed substrate token refuses, it is
        // never coerced to a default, and no failure ever downgrades it.
        let execution = declared_execution(Some(params))?;
        // The declared provider/model pair rides from the reviewed role
        // configuration (never from a step param, never a default id).
        return profile
            .with_binding(&role.provider, &role.model)
            .map(|profile| profile.with_execution(execution))
            .map_err(|err| refusal(err.code, err.message));
    }
    // No committed role configuration (a presented plan outside the queue
    // executor): the plan declares the binding itself and nothing is
    // defaulted but the declarative kind and the substrate (issue #139,
    // `params.execution`, default: the Herdr pane substrate).
    let execution = declared_execution(Some(params))?;
    if parsed_kind == crate::adapters::HarnessKind::Argv {
        crate::adapters::Profile::argv(
            &key,
            &executable,
            &crate::adapters::HARNESS_CAPS,
            BTreeMap::new(),
        )
        .map(|profile| profile.with_execution(execution))
        .map_err(|err| refusal(err.code, err.message))
    } else {
        // Official kinds carry their own metadata (executable must match
        // the official name; fake executables in tests use those names).
        crate::adapters::Profile::official(parsed_kind, &key)
            .map(|profile| profile.with_execution(execution))
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

    /// Issue #92 F7: the pre-screen is TOTAL over the closed step-kind set.
    /// Every kind that requires params refuses a param-less and an empty-object
    /// dispatch HERE (before the fence can consume a single-use
    /// authorization), a kind with no registered contract refuses instead of
    /// inheriting the burn, and a well-formed shape of each kind still passes
    /// — so the pre-screen is fail-closed without being blanket-refusing.
    #[test]
    fn the_param_pre_screen_is_total_over_every_step_kind() {
        let empty = ParamContract::default();
        let declared = Val::parse_json("{}").expect("an empty object parses");

        // A kind that requires params refuses with NO params and with `{}`.
        for kind in EFFECT_KINDS {
            if kind == "checkout" {
                // `checkout` reads no param (the integration branch is
                // topology), so it legitimately passes both shapes.
                assert!(check_step_params(kind, None, &empty).is_ok());
                assert!(check_step_params(kind, Some(&declared), &empty).is_ok());
                continue;
            }
            for params in [None, Some(&declared)] {
                let refused = check_step_params(kind, params, &empty).expect_err(&format!(
                    "{kind} must refuse a malformed dispatch before the fence"
                ));
                assert!(
                    !refused.0.is_empty() && !refused.1.is_empty(),
                    "{kind} refuses typed: {refused:?}"
                );
            }
        }

        // An unregistered kind never inherits the burn: it refuses too.
        let unregistered =
            check_step_params("no_such_kind", None, &empty).expect_err("unregistered kind");
        assert_eq!(unregistered.0, code::UNKNOWN_KIND);

        // Well-formed shapes of every kind pass (the table is not blanket).
        let feature = object(vec![
            ("branch", string("lane-7")),
            ("worktree", string("lane-7")),
        ]);
        let collect = object(vec![
            ("worktree", string("lane-7")),
            (
                "base_head",
                string("2222222222222222222222222222222222222222"),
            ),
        ]);
        let merge = object(vec![
            ("branch", string("lane-7")),
            ("merge_policy", string("squash")),
        ]);
        let harness = object(vec![("harness_key", string("lane"))]);
        let prompt = object(vec![
            ("harness_key", string("lane")),
            ("payload", string("continue the lane")),
            ("worktree", string("lane-7")),
        ]);
        let review = object(vec![
            ("reviewer", string("r1")),
            ("implementer", string("i1")),
            ("verdict", string("pass")),
            ("checks", Val::Arr(vec![string("c1")])),
        ]);
        let publish = object(vec![
            ("action", string("create")),
            ("repo", string("example-org/widgets")),
            ("head", string("lane-7")),
            ("base", string("staging")),
        ]);
        let push = object(vec![
            ("branch", string("lane-7")),
            ("remote", string("origin")),
        ]);
        let pr_comment = object(vec![
            ("action", string("comment")),
            ("repo", string("example-org/widgets")),
            ("head", string("lane-7")),
        ]);
        let issue = object(vec![
            ("action", string("comment")),
            ("repo", string("example-org/widgets")),
        ]);
        let hosted = object(vec![("repo", string("example-org/widgets"))]);
        let approve = object(vec![
            (
                "digest",
                string("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"),
            ),
            ("interactive", bool_(true)),
        ]);
        let observed = ParamContract {
            observed_feature_head: Some("1111111111111111111111111111111111111111"),
            observed_integration_base: Some("2222222222222222222222222222222222222222"),
            ..ParamContract::default()
        };
        let accepted: Vec<(&str, Option<&Val>, &ParamContract<'_>)> = vec![
            ("checkout", None, &empty),
            ("worktree_create", Some(&feature), &empty),
            ("harness_start", Some(&harness), &empty),
            ("prompt", Some(&prompt), &empty),
            ("collect_outcome", Some(&collect), &empty),
            ("review_evidence", Some(&review), &observed),
            ("merge", Some(&merge), &empty),
            ("cleanup", Some(&feature), &empty),
            ("publish", Some(&publish), &empty),
            ("branch_push", Some(&push), &empty),
            ("pr_update", Some(&pr_comment), &empty),
            ("issue_update", Some(&issue), &empty),
            ("hosted_check", Some(&hosted), &empty),
            ("post_merge_verify", None, &observed),
            ("branch_delete", Some(&feature), &empty),
            ("approve", Some(&approve), &empty),
        ];
        assert_eq!(
            accepted.len(),
            EFFECT_KINDS.len(),
            "every kind has one accepted witness"
        );
        for (kind, params, contract) in accepted {
            assert!(
                check_step_params(kind, params, contract).is_ok(),
                "a well-formed {kind} dispatch passes the pre-screen"
            );
        }
    }

    /// Issue #92 F7: the containment screen and the official-executable
    /// screen are part of the same pre-fence contract — an escaping worktree
    /// path and a foreign official executable are refused BEFORE the fence,
    /// never after it.
    #[test]
    fn the_param_pre_screen_screens_containment_and_official_executables() {
        let contained = ParamContract {
            worktrees_root: Some(Path::new("/tmp/canter-lanes")),
            ..ParamContract::default()
        };
        let escaping_lane = object(vec![
            ("branch", string("lane-7")),
            ("worktree", string("/tmp/escape")),
        ]);
        let escaping_prompt = object(vec![
            ("harness_key", string("lane")),
            ("payload", string("continue the lane")),
            ("worktree", string("/tmp/escape")),
        ]);
        let escaping_collect = object(vec![("worktree", string("/tmp/escape"))]);
        let cases: [(&str, &Val); 4] = [
            ("worktree_create", &escaping_lane),
            ("prompt", &escaping_prompt),
            ("collect_outcome", &escaping_collect),
            ("cleanup", &escaping_lane),
        ];
        for (kind, params) in cases {
            let (code, _) =
                check_step_params(kind, Some(params), &contained).expect_err("escaping path");
            assert_eq!(code, code::UNCONTAINED, "{kind} screens containment");
        }
        // The same shapes pass when they stay inside the presented root.
        let inside = object(vec![
            ("branch", string("lane-7")),
            ("worktree", string("lane-7")),
        ]);
        assert!(check_step_params("worktree_create", Some(&inside), &contained).is_ok());

        let foreign = object(vec![
            ("harness_key", string("lane")),
            ("kind", string("codex")),
            ("executable", string("not-codex")),
        ]);
        let (code, message) =
            check_step_params("harness_start", Some(&foreign), &ParamContract::default())
                .expect_err("foreign official executable");
        assert_eq!(code, code::BAD_PARAMS, "{message}");
    }

    /// Issue #130: the containment screen resolves the path the effect would
    /// actually touch, so an escape is refused even when the destination does
    /// not exist yet — and a symlink under the root cannot hide one either.
    /// The pre-fix check compared the LITERAL join, whose canonicalizing
    /// fallback leaves `root/../escaped-lane` `starts_with` the root, and
    /// `git worktree add` then created the lane outside it.
    #[test]
    fn containment_refuses_a_destination_that_does_not_exist_yet() {
        // A canonical fixture root: a symlinked temp ancestor must not be
        // able to mask (or manufacture) a containment failure.
        let dir = std::fs::canonicalize(std::env::temp_dir())
            .expect("temp dir")
            .join(format!("hf-mutation-130-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let root = dir.join("worktrees");
        std::fs::create_dir_all(&root).expect("worktrees root");

        // Escaping shapes refuse although no lane exists yet.
        for escaping in [
            "../escaped-lane",
            "issues/../../escaped-lane",
            "/tmp/escaped-lane",
        ] {
            let err = contained_path(&root, escaping).expect_err(escaping);
            assert_eq!(err.code, code::UNCONTAINED, "{escaping}");
        }

        // A symlink under the root that leaves it cannot hide the escape: the
        // presented path resolves through the link.
        let outside = dir.join("outside");
        std::fs::create_dir_all(&outside).expect("outside dir");
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            symlink(&outside, root.join("link-out")).expect("escaping symlink");
            let err = contained_path(&root, "link-out/lane").expect_err("symlinked escape");
            assert_eq!(err.code, code::UNCONTAINED);
            symlink(dir.join("missing"), root.join("dangle")).expect("dangling symlink");
            let err = contained_path(&root, "dangle/lane").expect_err("dangling symlink");
            assert_eq!(err.code, code::UNCONTAINED);
            // A symlink that stays INSIDE the root is still a lane path.
            std::fs::create_dir_all(root.join("real")).expect("real dir");
            symlink(root.join("real"), root.join("link-in")).expect("inner symlink");
            assert!(
                contained_path(&root, "link-in/lane").is_ok(),
                "an in-root symlink is not an escape"
            );
        }

        // The legitimate in-root shape resolves, and the screen creates
        // nothing on its own.
        let inside = contained_path(&root, "issues/130").expect("in-root lane");
        assert_eq!(inside, root.join("issues/130"));
        assert!(!root.join("issues").exists(), "the screen creates nothing");
        let err = contained_path(&root, ".").expect_err("root itself is not a lane");
        assert_eq!(err.code, code::UNCONTAINED);

        let _ = std::fs::remove_dir_all(&dir);
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
