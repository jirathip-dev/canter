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
use std::time::{Duration, Instant};

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

/// Documented default deadline (seconds) for one `cleanup` step's bounded
/// wait for the lane's own worker to settle (issue #224): the wait IS the
/// worker's round trip — a lane may outlive its own publish by minutes while
/// its turn finishes — so the cleanup kind carries the prompt tier's
/// documented bound instead of the generic 60 s I/O row, which would park a
/// run whose publish already SUCCEEDED. The wait only runs while the lane's
/// agent is genuinely alive and only then costs wall clock.
pub const CLEANUP_DEADLINE_DEFAULT_SECS: u64 = PROMPT_DEADLINE_DEFAULT_SECS;

/// The cleanup step's bounded lane-settle wait (issue #224) samples the lane,
/// and closes its workspace, under the COLLECTION's own discipline
/// ([`COLLECT_STOP_SAMPLES`] corroborated read-backs across
/// [`COLLECT_STOP_INTERVAL_SECS`]): the wait IS "the same discipline `p5`
/// already uses before certifying a delta", so a one-read settle is never a
/// settled turn here either. The one-read shape was exactly the measured flap
/// class the collection's confirmed stop exists for (#170 N7) — a status that
/// reports `idle`/`done` MID-TURN — and a close judged from it would retire
/// the workspace of a lane that is still alive.
const LANE_SETTLE_SAMPLE_INTERVAL_SECS: u64 = COLLECT_STOP_INTERVAL_SECS;

/// What a lane outliving its own recorded work MEANS for the step that waits
/// for it to settle (issue #224): the clause the bounded wait's park states.
/// One fact: p8's cleanup waits for the worker outliving its own PUBLISH (the
/// landing proof already holds), p6's verdict consume waits for the reviewer
/// outliving the VERDICT it wrote (the verdict is already consumed) — the same
/// timing condition, named for the step that hit it.
const LANE_OUTLIVED_PUBLISH: &str =
    "the delivery is already verified landed, so the lane outliving its own publish";
const LANE_OUTLIVED_REVIEW: &str =
    "the verdict this lane wrote is already consumed, so the lane outliving its own review";

/// Documented default deadline (seconds) for one review step's verdict wait
/// (`review_evidence`): the reviewer's own round trip — read the certified
/// head, review it, write the verdict — is the prompt tier's round trip, so
/// the review kind carries the prompt tier's documented bound instead of
/// falling into the generic I/O default (issue #217; the 60 s row it landed
/// in made every live review an `effect.review_timeout` by construction —
/// measured verdicts take tens of minutes on this host).
pub const REVIEW_DEADLINE_DEFAULT_SECS: u64 = PROMPT_DEADLINE_DEFAULT_SECS;

/// Issue #170 (N7): how many CONSECUTIVE non-working read-backs of a
/// collection's pane worker — each separated by the real
/// [`COLLECT_STOP_INTERVAL_SECS`] interval and corroborated by the lane's own
/// row — make the worker's turn a CONFIRMED stop.
///
/// Two read-backs are not a stop. The measured live `p5-101` collection judged
/// a still-working pane stopped from two reads ~100 ms apart of a status that
/// flaps to `idle`/`done` mid-turn, refused `refusal.collect.empty_delta` four
/// minutes into a 93-minute turn and consumed the run's retry; the retry then
/// parked the run on the old wall clock while the worker kept working. Three
/// read-backs span two real intervals in which a mid-turn flap has to hold,
/// and a lane whose own lifecycle counter moved across them never confirms.
pub const COLLECT_STOP_SAMPLES: usize = 3;

/// Issue #170 (N7 and N3): the real interval (seconds) between two of those
/// non-working read-backs — and therefore the collection wait's bounded poll
/// cadence. The pre-change loop polled every ~100 ms with two subprocess rows
/// per iteration (N3: ~600 read-backs/minute for a worker that runs for tens
/// of minutes); this is 12, and it stays well inside the driver's own 60 s
/// check interval, so a settled worker is noticed within one driver tick.
///
/// It is NOT a loop iteration: the wait sleeps this long between samples, so a
/// confirmed stop spans at least `(COLLECT_STOP_SAMPLES - 1) × this` seconds
/// of real time — the interval is measured off the wait's own clock.
pub const COLLECT_STOP_INTERVAL_SECS: u64 = 5;

/// Issue #170 (N8): the hard overall ceiling (seconds) of ONE collection wait.
///
/// The step's effective deadline is the wait's NO-PROGRESS window (seconds of
/// no recorded progress — see [`poll_pane_worker`]); this constant is the
/// absolute bound the window extensions may never leave. It is sized from the
/// measured lane: the live `p5-101` pane worker's real turn ran ≈93 minutes
/// (5580 s) and its delivery landed after the old 1800 s wall had already
/// parked the run, so the ceiling is ≈4× that turn — generous enough that a
/// real lane cannot be unconvergeable by construction, and still a hard bound:
/// even a lane that keeps producing progress parks as the typed
/// `effect.worker_timeout` once this is reached. The wait is never unbounded.
pub const COLLECT_CEILING_SECS: u64 = 6 * 60 * 60;

/// Upper bound (seconds) on any authorization window the engine mints or
/// renews for a run: 30 days. A grant is the bounded authorization of ONE
/// run's own committed work, so no derived window may exceed the documented
/// window class the operator surface already caps at (`grant issue
/// --expires-in`). One fact, two readers: the CLI's `--expires-in` bound and
/// the engine's own renewal (issue #184).
pub const GRANT_WINDOW_MAX_SECS: i64 = 30 * 24 * 60 * 60;

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
/// resolves to a bound; `prompt`, `collect_outcome`, `harness_start` and
/// `review_evidence` carry their own documented rows (see the constants
/// above).
pub fn default_deadline_secs(kind: &str) -> u64 {
    match kind {
        "prompt" | "collect_outcome" => PROMPT_DEADLINE_DEFAULT_SECS,
        "review_evidence" => REVIEW_DEADLINE_DEFAULT_SECS,
        "cleanup" => CLEANUP_DEADLINE_DEFAULT_SECS,
        "harness_start" => HARNESS_START_DEADLINE_DEFAULT_SECS,
        _ => EFFECT_DEADLINE_DEFAULT_SECS,
    }
}

/// The bound (seconds) of ONE `review_evidence` verdict wait (issue #217).
///
/// `effective` is the step's effective deadline ([`effect_deadline_secs`]):
/// the plan's own `deadline_secs` when it declared one, else the per-kind
/// default ([`REVIEW_DEADLINE_DEFAULT_SECS`]).
///
/// `resumed` says this attempt found THIS step's own PROVEN delivery for the
/// certified head and reviewer lane (issue #214): the reviewer leg is up and
/// already carries the brief, so the remaining work is the reviewer's and the
/// fresh window has already been spent once. Such an attempt RENEWS the wait
/// under the documented overall ceiling ([`EFFECT_DEADLINE_CEILING_SECS`])
/// instead of re-opening the fresh window a live review has already outrun —
/// the overall wait never leaves the documented effect ceiling.
///
/// A plan that declared its own `deadline_secs` keeps its reviewed policy
/// (bound by the plan digest): the renewal replaces only the engine's own
/// default window, never a declared one.
pub fn review_verdict_wait_secs(effective: u64, declared: bool, resumed: bool) -> u64 {
    if resumed && !declared {
        EFFECT_DEADLINE_CEILING_SECS
    } else {
        effective
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
    /// The review step declares no reviewer role binding (issue #193): the
    /// engine never invents a reviewer and never defaults a profile.
    pub const REVIEWER_UNBOUND: &str = "refusal.evidence.reviewer_unbound";
    /// The reviewer wrote no verdict artifact within the bounded wait
    /// (issue #193). The frontier is parked; nothing is synthesised.
    pub const VERDICT_MISSING: &str = "refusal.evidence.verdict_missing";
    /// The reviewer's written verdict artifact is ill-formed: the engine
    /// refuses it instead of filling anything in (issue #193).
    pub const VERDICT_MALFORMED: &str = "refusal.evidence.verdict_malformed";
    /// The reviewer's written verdict does not name the certified reviewed
    /// head (or its other bindings moved): never consumed as evidence.
    pub const VERDICT_STALE: &str = "refusal.evidence.verdict_stale";
    /// The reviewer's written verdict carries a `pending` check (issue #193):
    /// a pending check permanently strands the tail, so it is refused at the
    /// frontier instead of being recorded.
    pub const VERDICT_PENDING: &str = "refusal.evidence.verdict_pending";
    /// The bounded wait for the reviewer's own written verdict expired
    /// (issue #193): a typed outcome, never an unbounded poll.
    pub const REVIEW_TIMEOUT: &str = "effect.review_timeout";
    /// The engine's OWN record of a proven review-prompt delivery is
    /// unreadable, ill-formed, or not durably writable (issue #214). Fail
    /// closed: a re-dispatch never re-prompts a leg it may already have
    /// delivered to on a guess, and a proven delivery that cannot be
    /// recorded is refused rather than silently re-delivered.
    pub const REVIEW_DELIVERY: &str = "refusal.evidence.review_delivery";
    /// A recorded review FAIL could not be handed to the run's fix round
    /// (issue #238): the run carries no review root or no committed
    /// implementer leg, so no fix round can be dispatched and none is
    /// invented.
    pub const FIX_UNBOUND: &str = "refusal.fix.unbound";
    /// The fix round's lane could not be created (or its existing checkout
    /// could not be verified) at the certified reviewed head (issue #238).
    pub const FIX_LANE: &str = "refusal.fix.lane";
    /// The fix round's leg could not be started through the role-bound
    /// adapter (issue #238): its OWN code, carrying the substrate's refusal
    /// verbatim in the message, so a spawn refusal is never read as a prompt
    /// refusal and never as a review diagnosis.
    pub const FIX_SPAWN: &str = "refusal.fix.spawn";
    /// The fix round's instruction could not be PROVEN delivered to the fix
    /// leg (issue #238): its OWN code, carrying the substrate's refusal.
    pub const FIX_PROMPT: &str = "refusal.fix.prompt";
    /// The run's automatic fix-round bound is spent and the certified head
    /// still fails (issue #238): the escalation, whose message names the
    /// failures the reviewer recorded. Never a silent park.
    pub const FIX_BOUND_EXHAUSTED: &str = "refusal.fix.bound_exhausted";
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
    /// The published integration ref moved past the base the certified
    /// delivery was reviewed against AND the certified content cannot be
    /// refreshed onto it (issue #263): the replay does not apply cleanly, or
    /// it rewrites paths the review covered. It is a BASE MOVE, not a step
    /// defect — the refreshed content was never reviewed, so no step may
    /// consume it, and the run cannot resolve the condition by itself (a
    /// re-dispatch refuses identically). Its OWN typed condition, naming the
    /// certified base, the published head it moved to and the remedy, so
    /// supervision parks the frontier on it with the bounded retries UNSPENT
    /// instead of spending the whole budget on a condition the run can never
    /// resolve — never a terminal `effect.merge.failed` and never a silent
    /// consumption of unreviewed content.
    pub const MERGE_BASE_MOVED: &str = "effect.merge.base_moved";
    /// The merge step's post-merge bookkeeping hit a STATIC MECHANICAL
    /// condition (issue #224): the landed integration head is not readable
    /// from the integration checkout even after the fetch that brings it in
    /// (a missing object), or the delivery branch has no worktree in that
    /// checkout, so its certified content cannot be refreshed there (a missing
    /// checkout). Neither cause changes by re-running the SAME step — nothing
    /// fetches the object by itself and no checkout reappears — so it is this
    /// step's OWN typed condition and supervision parks the frontier on it
    /// with the bounded retries UNSPENT, exactly like the #263 base move: the
    /// measured #224 drive spent two attempts of p7 (and two of p6) on causes
    /// that were identical between attempts. The run escalates or is repaired
    /// instead of burning the budget on a static mechanical cause.
    pub const MERGE_STATIC: &str = "effect.merge.static";
    /// The remote REJECTED the publish (issue #219): the ref is protected by
    /// repository rules, so the update can never be accepted by a direct push
    /// however the local checkout is shaped. Its own code, so an operator
    /// never has to read `effect.merge.failed` and guess whether the push was
    /// refused by policy or simply never arrived.
    pub const MERGE_PUSH_REJECTED: &str = "effect.merge.push_rejected";
    /// The forge refused the declared pull-request publish (issue #219): the
    /// merge was not allowed (rules, an unmergeable head, or a check the
    /// repository requires). The published ref did not carry the delivery.
    pub const MERGE_PUBLISH_REJECTED: &str = "effect.merge.publish_rejected";
    /// A publish could not authenticate with the remote or the forge (issue
    /// #219): a missing/expired credential is its own class, never a policy
    /// refusal and never an opaque git-level failure.
    pub const CREDENTIAL_MISSING: &str = "refusal.credential.missing";
    /// The EXACT certified head carries a RED hosted check run (issue #225):
    /// the publish path COMPUTES the hosted CI conclusion for the head the
    /// verdict names (never a judgement, never the branch tip) and never
    /// publishes over a red check. The message names the workflow run, the
    /// job and the step that concluded red.
    pub const MERGE_CI_RED: &str = "effect.merge.ci_red";
    /// The hosted check runs of the EXACT certified head were still
    /// queued/in_progress when the step's bounded wait expired (issue #225):
    /// a still-running check is waited for, bounded, then refused typed —
    /// never silently treated as green.
    pub const MERGE_CI_PENDING: &str = "effect.merge.ci_pending";
    /// The declared pull-request publish route has nothing to publish (issue
    /// #219): no open pull request names the certified head for the
    /// integration branch. The reviewed delivery must be published as a pull
    /// request before the merge step can consume it.
    pub const PR_PUBLISH_MISSING: &str = "refusal.publish.pull_request_missing";
    /// The declared publish route cannot honour the step's declared merge
    /// policy (issue #219): a pull-request publish lands the forge's squash
    /// merge and can never perform an `ff` landing.
    pub const PUBLISH_POLICY: &str = "refusal.policy.publish";
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
    /// A collection step could not bind the delivery head it observed: the
    /// observation is not a certified delivery binding, so the step is a
    /// typed non-success rather than a `succeeded` outcome that bound nothing
    /// (issue #202 AC2).
    pub const COLLECT_UNBOUND: &str = "refusal.collect.unbound";
    /// A step was asked to consume a delivery head the run's own collection
    /// never certified (issue #202 AC2): no head is ever consumed that was
    /// not observed by the run's own collector.
    pub const DELIVERY_UNBOUND: &str = "refusal.delivery.unbound";
    /// The delivery branch moved past the head its recorded verdict names
    /// (issue #202 AC1): a commit landed on the reviewed delivery after the
    /// verdict, so no step may consume it — the delivery must re-enter review
    /// and a new verdict must name the moved head.
    pub const DELIVERY_MOVED: &str = "refusal.delivery.moved";
    /// The pane worker did not settle within the collection deadline.
    pub const WORKER_TIMEOUT: &str = "effect.worker_timeout";
    /// The lane's own worker did not settle within the cleanup step's bounded
    /// wait (issue #224). The delivery is already verified landed, so the
    /// lane outliving its own publish is a TIMING condition: the workspace is
    /// preserved, nothing is deleted, and the step is parked with the bounded
    /// retries UNSPENT instead of being refused into the retry budget.
    pub const LANE_TIMEOUT: &str = "effect.lane_timeout";
    /// An existing lane cannot safely be created at the recorded base.
    pub const WORKTREE_EXISTS: &str = "refusal.worktree.exists";
    /// A local lane branch already exists in the integration clone and is not
    /// a retired generation's reclaimable residue (issue #222): the duplicate
    /// lane cannot be created at the recorded base, and the branch name is
    /// carried so an operator can act without parsing `last_failure`.
    pub const WORKTREE_BRANCH_EXISTS: &str = "refusal.worktree.branch_exists";
    /// The addressed worktree is not the worker output location the run bound.
    pub const OUTPUT_LOCATION: &str = "refusal.worker.output_location";
    /// A step would bind a lane checkout that belongs to a different leg
    /// (issue #210): one lane checkout belongs to exactly one leg.
    pub const LANE_IDENTITY: &str = "refusal.lane.identity";
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

/// The step kind whose committed effect records the reviewed evidence a
/// verified delivery is read from (issue #152). One fact, two readers: the
/// completion timing (`state::delivery_completes_run`) and the supervised
/// committed-tail dispatch (`supervision::driver_dispatchable_kind`) both
/// anchor on this kind.
pub const DELIVERY_STEP_KIND: &str = "review_evidence";

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

/// The named checks of one evidence record that are NOT `passed`, rendered
/// `name=status` (issue #230): the exact fact the consumer refuses on and the
/// exact set a re-evaluation recomputes. Order is the recorded order.
///
/// The recorded STATUS decides, first and alone. The predicate is the base one
/// — a check passes only when its status is exactly `passed`, so every item
/// that is not `passed` (for any reason, including a missing status) makes the
/// record non-passing — and `name` is PRESENTATION, never a precondition: a
/// non-passing check whose name is absent, null or not a string is rendered
/// with the fallback [`UNNAMED_CHECK`] instead of being dropped. Dropping it
/// would let a nameless `failed` check PASS a gate the base refused (fix round
/// F1, finding B1).
pub fn non_passing_checks(evidence: &EvidenceView) -> Result<Vec<String>, MutationError> {
    let checks = Val::parse_json(&evidence.checks).map_err(|err| {
        MutationError::new(
            code::MALFORMED_OUTPUT,
            format!("evidence checks unparsable: {err}"),
        )
    })?;
    let items = checks.as_array().ok_or_else(|| {
        MutationError::new(code::MALFORMED_OUTPUT, "evidence checks is not an array")
    })?;
    Ok(items
        .iter()
        .filter_map(|item| {
            // The status decision comes FIRST and depends on nothing else.
            let status = match item.get("status") {
                Some(Val::Str(status)) if status == "passed" => return None,
                Some(Val::Str(status)) => status.as_str(),
                _ => "unknown",
            };
            let name = item
                .get("name")
                .and_then(Val::as_str)
                .filter(|name| !name.is_empty())
                .unwrap_or(UNNAMED_CHECK);
            Some(format!("{name}={status}"))
        })
        .collect())
}

/// The rendering fallback for a non-passing check that carries no usable name
/// (fix round F1, finding B1): presentation only — it never changes whether a
/// check is non-passing.
pub const UNNAMED_CHECK: &str = "unnamed";

/// Whether every named check in the evidence record passed. One derivation
/// with [`non_passing_checks`]: a record whose failing set is empty passed.
pub fn evidence_checks_passed(evidence: &EvidenceView) -> Result<bool, MutationError> {
    Ok(non_passing_checks(evidence)?.is_empty())
}

/// The engine's own refusal message for a record whose named checks are not all
/// `passed` — ONE derivation (issue #230), so a read-time report of that same
/// refusal (the supervision status of a frontier nothing ever dispatched) and
/// the refusal itself can never drift apart.
pub fn evidence_failed_message(evidence_id: &str, non_passing: &[String]) -> String {
    format!(
        "review evidence {evidence_id} has failed/pending checks: {}",
        non_passing.join(", ")
    )
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
            evidence_failed_message(&evidence.evidence_id, &non_passing_checks(evidence)?),
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
            publish_route: self.publish_route,
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
    /// The topology-declared integration publish route (issue #219): `push`
    /// (default) publishes the landing by fast-forwarding the integration
    /// checkout and pushing it; `pull_request` publishes the reviewed delivery
    /// through the open pull request whose head names the certified head. The
    /// closed set is [`INTEGRATION_PUBLISH_ROUTES`]; a declared route is never
    /// inferred from a failed push.
    pub publish_route: &'a str,
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
    /// Daemon-owned review root (issue #193): the directory the reviewer's
    /// OWN written verdict is consumed from. `None` for a presented plan
    /// (no daemon owns the review): a self-dispatching `review_evidence`
    /// step then refuses typed instead of inventing a verdict.
    pub review_root: Option<&'a Path>,
    /// Lane generations the run ledger RETIRED for this run's repository
    /// issue (issue #190), resolved by the caller from durable state and
    /// never from the substrate: the `harness_start` bind step retires their
    /// lane workspaces BEFORE it binds the new generation's, so a retired
    /// generation's residue (its pane/agent/workspace) can never keep the
    /// deterministic lane name and refuse the successor with
    /// `refusal.lane.name_collision`. A live lane is never in this set — a
    /// run that is not terminal still holds its issue's unique ownership —
    /// so the retire can never close a live current generation.
    pub retired_run_ids: &'a [String],
    /// This run's repository issue's OTHER generations that are NOT terminal
    /// in the ledger (issue #306), resolved by the caller from durable state
    /// and never from the substrate: the complement of
    /// [`EffectContext::retired_run_ids`], with the dispatching run itself
    /// excluded. `worktree_create` reclaims a retired generation's lane
    /// residue only when this set is EMPTY: any other non-terminal generation
    /// of the issue — including a run parked at `needs-attention` — still
    /// needs (or may still be holding) the issue's one lane, so nothing of
    /// that lane is deleted or adopted for it.
    pub live_sibling_run_ids: &'a [String],
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
    run_git_on(&residue_host(ctx)?, cwd, args)
}

/// The integration-clone access a lane-residue retire runs against: the
/// checkout the git reads target, the allowlisted child environment and the
/// bounded deadline. ONE authority: the plan-step effects (#190/#222) and the
/// operator `run.retire-lane` control (issue #236) run the same policy
/// through this host, so an operator retire and a bind-time reclaim can never
/// diverge.
pub struct ResidueHost<'a> {
    /// The integration checkout the retire operates on (absolute).
    pub integration_repo: &'a Path,
    /// Allowlisted environment for bounded children.
    pub env: &'a BTreeMap<String, String>,
    /// Bounded deadline of every context-relative git read the retire makes.
    pub deadline: Duration,
}

/// The host one plan-step effect presents: the effect's own integration
/// checkout, environment and per-kind deadline bound.
fn residue_host<'a>(ctx: &'a EffectContext<'a>) -> Result<ResidueHost<'a>, EffectOutcome> {
    Ok(ResidueHost {
        integration_repo: ctx.integration_repo,
        env: ctx.env,
        deadline: Duration::from_secs(effect_deadline_secs(ctx.kind, ctx.params)?),
    })
}

fn run_git_on(
    host: &ResidueHost<'_>,
    cwd: &Path,
    args: &[&str],
) -> Result<crate::process::ProcOut, EffectOutcome> {
    let env = host.env;
    let git_env: BTreeMap<String, String> = if env.contains_key("PATH") {
        env.clone()
    } else {
        adapter_environment()
    };
    let out = crate::adapters::run_grouped(ProcSpec {
        program: "git",
        args: &args.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
        env: &git_env,
        cwd: Some(cwd),
        timeout: host.deadline,
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
    match lane_integration_base(ctx) {
        Ok(head) => ok(object(vec![
            ("integration_branch", string(ctx.integration_branch)),
            ("integration_base", string(&head)),
        ])),
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

/// The closed set of integration PUBLISH routes a topology may declare (issue
/// #219): how the merge step publishes a landing to the integration ref.
///
/// `push` is the default and the historical behaviour: the landing is
/// fast-forwarded into the integration checkout and pushed to the same remote
/// the published ref was read from. `pull_request` is for a repository whose
/// own rules forbid a direct push to that ref (a pull-request-only ruleset on
/// the integration branch and/or a protected branch): there the reviewed
/// delivery is published through the repository's real integration path — the
/// open pull request whose head names the certified head, squash-merged by
/// the authenticated forge CLI — and the published ref is read back and
/// proven by content exactly as the push route proves it.
///
/// A route is DECLARED, never inferred: an engine that silently fell back from
/// a refused push to another route would violate the plan-policy discipline
/// (issue #196) and hide the refusal from the operator.
pub const INTEGRATION_PUBLISH_ROUTES: [&str; 2] = ["push", "pull_request"];
/// The documented default publish route (a topology that declares none).
pub const INTEGRATION_PUBLISH_DEFAULT: &str = "push";
/// The pull-request publish route.
pub const INTEGRATION_PUBLISH_PULL_REQUEST: &str = "pull_request";

/// Whether a topology-declared publish route value is one of
/// [`INTEGRATION_PUBLISH_ROUTES`].
pub fn is_publish_route(route: &str) -> bool {
    INTEGRATION_PUBLISH_ROUTES.contains(&route)
}

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
    /// The declared integration publish route (topology); `''` means the
    /// documented [`INTEGRATION_PUBLISH_DEFAULT`].
    pub publish_route: &'a str,
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

impl<'a> ParamContract<'a> {
    /// The effective publish route: the declared one, or the documented
    /// default when the contract declares none (a contract that predates the
    /// route, and every non-merge caller, keeps the historical `push`).
    pub fn publish_route(&self) -> &'a str {
        if is_publish_route(self.publish_route) {
            self.publish_route
        } else {
            INTEGRATION_PUBLISH_DEFAULT
        }
    }
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

/// The declared lane leg of one step (issues #154, #210): the closed role
/// (`implementer` by default, `reviewer`) and a positive round (default `1`).
/// ONE parse feeds both the names (`LaneNames`) and the lane checkout
/// (`lane_checkout`), so the two halves of a leg's identity can never drift.
fn step_lane_leg(params: Option<&Val>) -> Result<(&str, u64), EffectOutcome> {
    let role = match params.and_then(|params| params.get("lane_role")) {
        None => "implementer",
        Some(Val::Str(role)) if matches!(role.as_str(), "implementer" | "reviewer") => {
            role.as_str()
        }
        Some(_) => {
            return Err(refusal(
                code::BAD_PARAMS,
                "lane_role must be implementer|reviewer",
            ));
        }
    };
    let round = match params.and_then(|params| params.get("lane_round")) {
        None => 1,
        Some(Val::Int(round)) if *round > 0 => *round as u64,
        Some(_) => {
            return Err(refusal(
                code::BAD_PARAMS,
                "lane_round must be a positive integer",
            ));
        }
    };
    Ok((role, round))
}

/// The lane worktree a step's OWN leg resolves for the pane substrate (issues
/// #139, #210): the pane is created in the leg's lane checkout and never at a
/// bare cwd or in a sibling leg's lane. The checkout is derived from the
/// step's declared `(role, round)` and the plan's issue — never invented at
/// effect time — and the reviewed plan must bind it; a plan that does not is
/// refused here rather than given a pane in the wrong lane.
fn run_lane_worktree(ctx: &EffectContext<'_>, what: &str) -> Result<PathBuf, EffectOutcome> {
    let (role, round) = step_lane_leg(ctx.params)?;
    let relative = crate::lane::lane_checkout(ctx.plan.issue_number as u64, role, round);
    if !plan_lane_worktrees(ctx)
        .iter()
        .any(|bound| bound == &relative)
    {
        return Err(refusal(
            code::BAD_PARAMS,
            format!(
                "{what} runs on the Herdr pane substrate, which creates the worker's pane in the \
                 leg's own lane checkout {relative:?}, and no plan step binds that lane; declare \
                 params.execution = \"headless\" to run the bare-subprocess fallback explicitly"
            ),
        ));
    }
    let worktree = contained_path(ctx.worktrees_root, &relative)
        .map_err(|err| refusal(err.code, err.message))?;
    if !worktree.is_dir() {
        return Err(refusal(
            code::OUTPUT_LOCATION,
            format!(
                "{what} binds the lane checkout {relative:?}, which is not a directory; the Herdr \
                 pane substrate creates the worker's pane there and never at a bare cwd"
            ),
        ));
    }
    Ok(worktree)
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

/// The review facts ONE `review_evidence` step presents itself (the operator
/// dispatch shape: the reviewer's verdict is authored outside the engine and
/// presented as the step's params).
#[derive(Clone, Debug)]
pub struct PresentedReview {
    /// The reviewer identity.
    pub reviewer: String,
    /// The implementer identity.
    pub implementer: String,
    /// The verdict (`pass` | `fail`).
    pub verdict: String,
    /// The non-empty named-check list.
    pub checks: Val,
}

/// The reviewer role ONE self-dispatching `review_evidence` step declares
/// (issue #193): the role key the reviewed step names and the
/// `hf-profile-binding/v1` document the FLEET REGISTRY resolved for it
/// (harness kind + intended provider/model + fallback/limits + revision).
///
/// The engine never hardcodes a model, never defaults a profile and never
/// infers a reviewer: the binding is the reviewed registry resolution the
/// plan binds, and the step must agree with it.
#[derive(Clone, Debug)]
pub struct ReviewerLeg {
    /// The registry role-binding key (`params.harness_key`).
    pub key: String,
    /// The declared bare executable (`''` when absent; `argv` only).
    pub executable: String,
    /// The declared closed harness kind.
    pub kind: String,
    /// The parsed closed-set kind.
    pub parsed_kind: crate::adapters::HarnessKind,
    /// The declared execution substrate.
    pub execution: crate::adapters::ExecutionMode,
    /// The registry-resolved binding document.
    pub profile: crate::config::ProfileBinding,
    /// The run's lane worktree the reviewer starts in.
    pub worktree: String,
    /// The reviewer lane round (positive; default 1).
    pub round: u64,
}

/// Whether one step's params declare the self-dispatching reviewer LEG
/// (issue #193): the registry-resolved reviewer binding the engine dispatches
/// itself. Params-only and pure, so the daemon's fan-out admission gate and
/// the supervision predicate read the same ONE fact.
pub fn declares_reviewer_leg(params: Option<&Val>) -> bool {
    params
        .and_then(|params| params.get("reviewer_profile"))
        .is_some()
}

/// The two accepted shapes of one `review_evidence` step (issue #193).
#[derive(Clone, Debug)]
pub enum ReviewEvidenceShape {
    /// The step presents the review facts itself; the engine records them
    /// and never dispatches anything (the operator's own path).
    Presented(PresentedReview),
    /// The step declares the reviewer's role binding; the engine dispatches
    /// the run's own reviewer through the role-bound pane adapter and
    /// consumes the verdict that reviewer writes. Boxed: the leg carries the
    /// whole reviewed binding, and a step's shape must not inflate every
    /// other value of this enum.
    SelfDispatch(Box<ReviewerLeg>),
}

/// The params-caused inputs of `review_evidence`.
#[derive(Clone, Debug)]
pub struct ReviewEvidenceInputs {
    /// The exact reviewed feature head (request-level read-back).
    pub feature_head: String,
    /// The observed integration base (request-level read-back).
    pub integration_base: String,
    /// Which of the two shapes this step declares.
    pub shape: ReviewEvidenceShape,
}

/// Resolve the params-caused inputs of `review_evidence` (params required;
/// both observed read-backs required and 40-hex).
///
/// The step declares ONE of two shapes:
/// - `params.reviewer_profile` (with `params.harness_key`, `params.worktree`)
///   declares the reviewer LEG: the registry-resolved reviewer binding the
///   engine dispatches itself (issue #193). The presented review facts are
///   refused alongside it — a step is one shape or the other;
/// - otherwise the step presents the review facts itself
///   (reviewer/implementer/verdict/checks; the reviewer must differ from the
///   implementer).
pub fn review_evidence_inputs(
    params: Option<&Val>,
    contract: &ParamContract<'_>,
) -> Result<ReviewEvidenceInputs, EffectOutcome> {
    let Some(params) = params else {
        return Err(refusal(code::BAD_PARAMS, "review_evidence requires params"));
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
    let shape = match params.get("reviewer_profile") {
        Some(doc) => {
            for key in ["reviewer", "implementer", "verdict", "checks"] {
                if params.get(key).is_some() {
                    return Err(refusal(
                        code::BAD_PARAMS,
                        format!(
                            "review_evidence declares both the reviewer leg \
                             (params.reviewer_profile) and the presented review facts \
                             (params.{key}); a step declares one shape or the other"
                        ),
                    ));
                }
            }
            let profile = crate::config::ProfileBinding::from_doc(doc)
                .map_err(|err| refusal(err.code(), err.message().to_string()))?;
            let declared = harness_inputs(params)?;
            if declared.key != profile.key {
                return Err(refusal(
                    crate::config::CODE_PROFILE_BINDING,
                    format!(
                        "the review step declares harness key {:?} and presents a reviewer \
                         binding for {:?}; the reviewer's role key and its registry-resolved \
                         binding must agree",
                        declared.key, profile.key
                    ),
                ));
            }
            if declared.kind != profile.kind {
                return Err(refusal(
                    crate::config::CODE_PROFILE_BINDING,
                    format!(
                        "the review step declares harness kind {:?} and presents a reviewer \
                         binding of kind {:?}",
                        declared.kind, profile.kind
                    ),
                ));
            }
            let worktree = param_str(Some(params), "worktree")?.to_string();
            screened_containment(contract, &worktree)?;
            let round = match params.get("lane_round") {
                None => 1,
                Some(Val::Int(round)) if *round > 0 => *round as u64,
                Some(_) => {
                    return Err(refusal(
                        code::BAD_PARAMS,
                        "review_evidence lane_round must be a positive integer",
                    ));
                }
            };
            ReviewEvidenceShape::SelfDispatch(Box::new(ReviewerLeg {
                key: declared.key,
                executable: declared.executable,
                kind: declared.kind,
                parsed_kind: declared.parsed_kind,
                execution: declared_execution(Some(params))?,
                profile,
                worktree,
                round,
            }))
        }
        None => {
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
            ReviewEvidenceShape::Presented(PresentedReview {
                reviewer,
                implementer,
                verdict,
                checks,
            })
        }
    };
    Ok(ReviewEvidenceInputs {
        feature_head,
        integration_base,
        shape,
    })
}

/// The explicit integration policy of a merge landing.
#[derive(Clone, Debug)]
pub struct MergeInputs {
    /// The slug feature branch.
    pub branch: String,
    /// The closed policy (`squash` | `ff`).
    pub policy: String,
    /// The topology-declared publish route (issue #219), resolved to one of
    /// [`INTEGRATION_PUBLISH_ROUTES`] (the documented default when the
    /// topology declares none).
    pub route: String,
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
    // The ref a landing PUBLISHES to is never a production branch (issue
    // #176): the landing is the reviewed merge of one feature branch onto the
    // integration branch, and promotion to production stays a separate,
    // human-gated path — there is no direct push to integration/production
    // refs anywhere in this engine.
    if contract.integration_branch == "main"
        || contract
            .production_branches
            .iter()
            .any(|branch| branch == contract.integration_branch)
    {
        return Err(refusal(
            code::PUSH_POLICY,
            format!(
                "the integration branch {:?} is a production branch; a merge never publishes to production",
                contract.integration_branch
            ),
        ));
    }
    // Issue #219: the declared publish route must be able to honour the
    // step's declared landing policy. A `pull_request` publish lands the
    // forge's SQUASH merge (the repository's own integration path): an `ff`
    // landing has no pull-request equivalent, so the combination refuses
    // instead of silently landing something the plan did not declare.
    let route = contract.publish_route();
    if route == INTEGRATION_PUBLISH_PULL_REQUEST && policy != "squash" {
        return Err(refusal(
            code::PUBLISH_POLICY,
            format!(
                "the integration ref {:?} publishes through the declared pull_request route, which lands a squash merge and cannot honour merge_policy {policy:?}",
                contract.integration_branch
            ),
        ));
    }
    Ok(MergeInputs {
        branch,
        policy,
        route: route.to_string(),
    })
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

/// Freeze the observed base, or read the published ref for the first checkout.
/// Never substitute a local branch (including a stale remote-tracking ref).
fn lane_integration_base(ctx: &EffectContext<'_>) -> Result<String, EffectOutcome> {
    let base = match ctx.observed_integration_base {
        Some(base) if is_hex40(base) => base.to_string(),
        Some(_) => return Err(refusal(code::BAD_PARAMS, "integration base must be 40-hex")),
        None => published_integration_head(ctx)?,
    };
    let commit = format!("{base}^{{commit}}");
    if run_git(ctx, ctx.integration_repo, &["cat-file", "-e", &commit]).is_err() {
        run_git(
            ctx,
            ctx.integration_repo,
            &["fetch", "origin", ctx.integration_branch],
        )?;
        run_git(ctx, ctx.integration_repo, &["cat-file", "-e", &commit])?;
    }
    Ok(base)
}

/// Create a contained lane at the recorded/published integration base.
///
/// Issue #222: a ledger-TERMINAL generation's lane residue in the integration
/// clone — its registered lane checkout AND its local lane branch — is
/// reclaimed before the duplicate-lane refusals, so a new run for the same
/// issue reaches `harness_start` without an operator deleting artifacts by
/// hand (the measured `refusal.worktree.exists` and the raw
/// `git ... exited with code 255: a branch named 'issue-N' already exists`
/// reported as the generic `adapter.exit`). The reclaim is scoped by
/// construction: the daemon resolves the retired instance ids for exactly
/// this repository issue (a live run is never in that set, and a sibling
/// issue's run resolves to a different set), and only the branch and checkout
/// THIS step is about to create are touched.
///
/// Issue #282 adds the OTHER stale-host-state shape at the same scope: the
/// path this step is about to create is still REGISTERED by the integration
/// clone while its directory is gone, so the create would die on the stale
/// entry (git's `is a missing but already registered worktree`) and the death
/// would be charged to the run's bounded retry budget. The registration is
/// cleared for exactly that path first (see
/// [`clear_stale_lane_registration`]) and the repair rides the outcome.
///
/// Issue #306 adds the third shape at the same scope: the retired generation
/// left its local lane branch behind as a LOCAL-ONLY delivery (the published
/// branch on `origin` does not carry its tip) with no live lane and no
/// registered worktree, so the successor's create refused
/// `refusal.worktree.branch_exists` forever and the run was charged bounded
/// retries for a condition it did not create. Such a branch IS a retired
/// generation's reclaimable residue and is reclaimed (see
/// [`reclaim_lane_residue`]'s #306 half); a branch a registered worktree
/// holds, or one whose issue still has a live generation, keeps the refusal
/// verbatim.
fn effect_worktree_create(ctx: &EffectContext<'_>) -> EffectOutcome {
    let (branch, relative) = match worktree_create_inputs(ctx.params, &ctx.param_contract()) {
        Ok(inputs) => inputs,
        Err(outcome) => return outcome,
    };
    let worktree = match contained_path(ctx.worktrees_root, &relative) {
        Ok(path) => path,
        Err(err) => return refusal(err.code, err.message),
    };
    // The reclaim authority is the run ledger: only a terminal generation of
    // THIS issue authorizes a reclaim at all, and only while the issue has NO
    // other non-terminal generation (issue #306) — a live lane (a run parked
    // at `needs-attention` included) still needs the issue's one lane, whose
    // branch and checkout are derived from the issue number, so nothing of it
    // is ever reclaimed from under a live generation. With either fact absent
    // nothing is touched and the duplicate-lane refusals below stay the
    // answer.
    let reclaimed = if ctx.retired_run_ids.is_empty() || !ctx.live_sibling_run_ids.is_empty() {
        Vec::new()
    } else {
        reclaim_retired_lane_residue(ctx, &branch, &relative, &worktree)
    };
    // Whatever the reclaim did — reclaimed or refused — travels with the
    // refusal message: the retire happened, so it is audited either way.
    let note = reclaim_note(&reclaimed);
    if worktree.exists() {
        return refusal(
            code::WORKTREE_EXISTS,
            format!(
                "worktree {} already exists; a duplicate lane cannot be created{note}",
                worktree.display()
            ),
        );
    }
    // Issue #222 AC2: the stale-branch collision is its own typed code that
    // NAMES the branch — never a raw git 255 resolved as `adapter.exit`.
    // Issue #306 AC2: the refusal STANDS for every branch this reclaim may not
    // reclaim — one a registered worktree of the integration clone has checked
    // out (a live lane's own checkout, including a stale registration whose
    // directory is gone), and one whose issue has another live generation.
    if local_ref_tip(ctx, &format!("refs/heads/{branch}")).is_some() {
        let unresidue = if ctx.live_sibling_run_ids.is_empty() {
            "a local-only branch is reclaimed only when no registered worktree of the \
             integration clone holds it, and a held branch is never deleted or adopted"
                .to_string()
        } else {
            format!(
                "a live generation of this issue ({}) still needs the lane, so nothing is \
                 reclaimed and a held branch is never deleted or adopted",
                ctx.live_sibling_run_ids.join(", ")
            )
        };
        return refusal(
            code::WORKTREE_BRANCH_EXISTS,
            format!(
                "the integration clone already has the local lane branch {branch:?} and it is not \
                 a retired generation's reclaimable residue ({unresidue}); the duplicate lane \
                 cannot be created at the recorded base — resolve {branch:?} (its owner, or an \
                 operator) and re-dispatch{note}"
            ),
        );
    }
    let base = match lane_integration_base(ctx) {
        Ok(base) => base,
        Err(outcome) => return outcome,
    };
    if let Some(parent) = worktree.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    // Issue #282: a registration git still holds for exactly this lane path
    // while its directory is gone is stale host state with a mechanical remedy
    // — it is cleared for this path before the create, never charged to the
    // run's bounded retry budget as a step failure.
    let stale_registration = match clear_stale_lane_registration(ctx, &relative, &worktree) {
        Ok(record) => record,
        Err(outcome) => return outcome,
    };
    match run_git(
        ctx,
        ctx.integration_repo,
        &[
            "worktree",
            "add",
            "-b",
            &branch,
            worktree.to_str().unwrap_or_default(),
            &base,
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
            let mut fields = vec![
                ("branch", string(&branch)),
                ("worktree", string(&worktree.to_string_lossy())),
                ("head", string(&head)),
                ("base_head", string(&base)),
                ("dirty", bool_(!status.trim().is_empty())),
                (
                    "contained",
                    bool_(is_contained(ctx.worktrees_root, &worktree)),
                ),
            ];
            if !reclaimed.is_empty() {
                fields.push(("reclaimed", Val::Arr(reclaimed)));
            }
            if let Some(record) = stale_registration {
                fields.push(("stale_registration", record));
            }
            ok(object(fields))
        }
        Err(outcome) => outcome,
    }
}

/// The tip of one LOCAL ref in the integration clone (`None` when it does not
/// exist): a pure read-back, never a fetch.
fn local_ref_tip(ctx: &EffectContext<'_>, refname: &str) -> Option<String> {
    let host = residue_host(ctx).ok()?;
    local_ref_tip_on(&host, refname)
}

fn local_ref_tip_on(host: &ResidueHost<'_>, refname: &str) -> Option<String> {
    let out = run_git_on(
        host,
        host.integration_repo,
        &["rev-parse", "--verify", "--quiet", refname],
    )
    .ok()?;
    let tip = out.stdout.trim().to_string();
    is_hex40(&tip).then_some(tip)
}

fn published_branch_tip_on(host: &ResidueHost<'_>, branch: &str) -> Option<String> {
    let refname = format!("refs/heads/{branch}");
    let out = run_git_on(
        host,
        host.integration_repo,
        &["ls-remote", "origin", &refname],
    )
    .ok()?;
    let tip = out.stdout.split_whitespace().next()?.to_string();
    is_hex40(&tip).then_some(tip)
}

/// The checkout paths the integration clone registers as worktrees
/// (`git worktree list --porcelain`). A live generation's lane is registered
/// there, so its checkout is never confused with residue. Paths are
/// canonicalized before they are compared: git reports resolved paths (on
/// macOS `/private/var/...` for a `/var/...` root), and a byte comparison
/// would miss the very registration this read exists for.
fn registered_worktree_paths_on(host: &ResidueHost<'_>) -> Vec<PathBuf> {
    match run_git_on(
        host,
        host.integration_repo,
        &["worktree", "list", "--porcelain"],
    ) {
        Ok(out) => out
            .stdout
            .lines()
            .filter_map(|line| line.strip_prefix("worktree "))
            .map(PathBuf::from)
            .map(|path| std::fs::canonicalize(&path).unwrap_or(path))
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// The checkout the integration clone has the local branch `branch` checked
/// out at, from the clone's own registration (`git worktree list --porcelain`
/// pairs each registered path with the ref it has checked out) — `None` when
/// no registered worktree holds it, so the branch is unheld residue. A
/// registration whose directory is GONE still counts (git keeps its row),
/// exactly like issue #282's stale entry: a branch a registration holds is
/// never treated as unheld. The parse mirrors [`branch_worktree`]'s.
fn registered_branch_holder_on(host: &ResidueHost<'_>, branch: &str) -> Option<String> {
    let out = run_git_on(
        host,
        host.integration_repo,
        &["worktree", "list", "--porcelain"],
    )
    .ok()?;
    let wanted = format!("refs/heads/{branch}");
    let mut current: Option<String> = None;
    for line in out.stdout.lines() {
        if let Some(path) = line.strip_prefix("worktree ") {
            current = Some(path.trim().to_string());
        } else if let Some(refname) = line.strip_prefix("branch ")
            && refname.trim() == wanted
        {
            return current;
        }
    }
    None
}

/// The comparable form of a lane checkout path even when the checkout itself
/// is GONE (issue #282): the deepest EXISTING ancestor is canonicalized and
/// the missing tail re-appended. Git reports resolved paths (on macOS
/// `/private/var/...` for a `/var/...` root), so a byte comparison against a
/// raw path would miss the very registration this read exists for — while a
/// checkout whose directory was deleted can never be canonicalized whole.
fn resolved_lane_path(path: &Path) -> PathBuf {
    if let Ok(resolved) = std::fs::canonicalize(path) {
        return resolved;
    }
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    let mut cursor = path.to_path_buf();
    while let Some(name) = cursor.file_name() {
        tail.push(name.to_os_string());
        let parent = cursor.parent().map(Path::to_path_buf).unwrap_or_default();
        if let Ok(resolved) = std::fs::canonicalize(&parent) {
            let mut out = resolved;
            out.extend(tail.iter().rev());
            return out;
        }
        if parent.as_os_str().is_empty() {
            break;
        }
        cursor = parent;
    }
    path.to_path_buf()
}

/// Whether `path` is one of the integration clone's registered worktrees.
fn is_registered_worktree(path: &Path, registered: &[PathBuf]) -> bool {
    let resolved = resolved_lane_path(path);
    registered
        .iter()
        .any(|candidate| candidate == &resolved || candidate == path)
}

/// Issue #282: clear the integration clone's STALE registration of exactly the
/// lane checkout this step is about to materialize.
///
/// A checkout git still registers whose directory is GONE is the host state
/// `git worktree add` refuses with `fatal: '<path>' is a missing but already
/// registered worktree; use 'add -f' to override, or 'prune' or 'remove' to
/// clear`. It is not a step failure: the cause is stale host state and git's
/// own `worktree remove` is the mechanical remedy, scoped to the ONE path this
/// step is about to create — the path the run owns by its own recorded
/// topology. The registration is therefore cleared here, before the create, so
/// the dispatch never dies on it (a dispatch that died on it charged the run's
/// bounded retry budget and could neither re-dispatch nor terminate).
///
/// Scoped by construction: a checkout that is PRESENT is never addressed (the
/// duplicate-lane refusals stay the answer), a path this clone does not
/// register is left alone, another leg's lane is a different path, and no
/// branch is ever deleted. Returns the record for the step outcome, `None`
/// when there was nothing stale to clear.
fn clear_stale_lane_registration(
    ctx: &EffectContext<'_>,
    relative: &str,
    worktree: &Path,
) -> Result<Option<Val>, EffectOutcome> {
    if worktree.exists() {
        return Ok(None);
    }
    let host = residue_host(ctx)?;
    if !is_registered_worktree(worktree, &registered_worktree_paths_on(&host)) {
        return Ok(None);
    }
    let path = worktree.to_string_lossy().into_owned();
    run_git_on(&host, host.integration_repo, &["worktree", "remove", &path])?;
    Ok(Some(object(vec![
        ("worktree", string(relative)),
        ("path", string(&path)),
        (
            "message",
            string(
                "the integration clone still registered this lane checkout while its directory \
                 was gone; the registration was cleared for exactly this path, so the lane is \
                 created instead of the dispatch dying on the stale entry",
            ),
        ),
    ])))
}

/// What the branch half does with a LOCAL-ONLY lane branch — one whose tip the
/// published branch of `origin` does not carry. The two reclaim sites have
/// deliberately different policies (issue #306 states the worktree step's;
/// the operator control keeps its own), so the difference is a parameter, read
/// at exactly one place.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum LocalOnlyBranch {
    /// The operator control's #222 policy: an explicit, human-issued
    /// retirement never destroys the only copy of a delivery, so the branch
    /// stays where it is and the refusal is recorded.
    Preserve,
    /// The bind step's #306 policy: a retired generation's local-only branch
    /// that NO registered worktree holds is residue the successor's lane
    /// creation must not be refused forever by — it is reclaimed, and the
    /// recorded tip keeps the stale delivery traceable.
    ReclaimUnheld,
}

/// Issue #222: reclaim the lane residue a ledger-TERMINAL generation of this
/// repository issue left in the integration clone, and return one record of
/// the attempt (removed, or refused with its reason). The residue set is
/// three halves: the registered checkout, the local lane branch, and — issue
/// #231 — the lane's build residue (its DerivedData scratch roots) under the
/// run's own worktrees root.
///
/// Policy, stated because the issue asks which one is implemented: the retired
/// generation's REGISTERED lane checkout at this leg's own relative path is
/// removed (never forced — a dirty or unregistered path is left alone), and
/// its local lane branch is deleted either when the published branch on
/// `origin` carries the same tip (i.e. when the branch is re-creatable from the
/// remote — a refresh: the lane is then created clean at the recorded base) or
/// — issue #306 — when it is a LOCAL-ONLY delivery that no registered worktree
/// of the integration clone has checked out. The #306 half is what keeps a
/// successor off the bounded-retry ladder: the residual local-only branch
/// refused every fresh run's worktree step with
/// `refusal.worktree.branch_exists`, and the engine's policy left only a human
/// able to clear it. Both deletion halves are scoped by the ledger — this
/// function runs only for a ledger-TERMINAL generation of THIS issue, and the
/// caller has established that the issue has no OTHER non-terminal generation
/// — and a branch a registration holds is never deleted or adopted at all
/// (`git branch -D` refuses a branch checked out in a worktree; the holder is
/// read and recorded explicitly). Whatever still refuses surfaces as
/// `refusal.worktree.branch_exists` naming the branch instead of the raw git
/// failure the issue measured.
fn reclaim_retired_lane_residue(
    ctx: &EffectContext<'_>,
    branch: &str,
    relative: &str,
    worktree: &Path,
) -> Vec<Val> {
    match residue_host(ctx) {
        Ok(host) => reclaim_lane_residue(
            &host,
            ctx.retired_run_ids,
            branch,
            relative,
            worktree,
            ctx.worktrees_root,
            ctx.plan.issue_number as u64,
            LocalOnlyBranch::ReclaimUnheld,
        ),
        Err(_) => Vec::new(),
    }
}

/// The lane's BUILD residue (issue #231, the third residue half): the
/// per-lane build-scratch roots the host measured — `<agent>-derived` and
/// `<agent>-DD` — directly under the run's own `worktrees_root`.
///
/// The roots are DERIVED from the issue's own implementer leg
/// ([`crate::lane::lane_build_residue_roots`]), so the set is exactly this
/// lane's residue: a sibling lane of another issue is never a candidate, and
/// a path that is not one of the two derived names is never touched. The
/// caller has already proven the generation is ledger-TERMINAL, so a live
/// lane's scratch root is unreachable here — and a symlinked root is refused
/// and left in place (a symlink is never followed, exactly like a cleanup
/// target). One record per root is returned either way (removed or refused).
fn reclaim_build_residue(worktrees_root: &Path, issue: u64) -> Vec<Val> {
    let mut records = Vec::new();
    for name in crate::lane::lane_build_residue_roots(issue, "implementer", 1) {
        let path = worktrees_root.join(&name);
        let record = if !path.exists() {
            object(vec![
                ("root", string(&name)),
                ("removed", bool_(true)),
                ("message", string("no build residue")),
            ])
        } else if std::fs::symlink_metadata(&path)
            .map(|meta| meta.file_type().is_symlink())
            .unwrap_or(false)
        {
            object(vec![
                ("root", string(&name)),
                ("removed", bool_(false)),
                ("code", string(code::CLEANUP_SYMLINK)),
                (
                    "message",
                    string(
                        "the build-residue root is a symlink; a symlinked root is never followed \
                         and nothing is removed",
                    ),
                ),
            ])
        } else {
            match std::fs::remove_dir_all(&path) {
                Ok(()) => object(vec![
                    ("root", string(&name)),
                    ("removed", bool_(true)),
                    (
                        "message",
                        string("regenerable lane build residue (DerivedData) reclaimed"),
                    ),
                ]),
                Err(err) => object(vec![
                    ("root", string(&name)),
                    ("removed", bool_(false)),
                    ("code", string(code::CLEANUP_UNKNOWN)),
                    (
                        "message",
                        string(&format!(
                            "the build-residue root could not be removed: {err}"
                        )),
                    ),
                ]),
            }
        };
        records.push(record);
    }
    records
}

// The arity covers the three residue halves plus the policy; the repo's own
// convention for an internal dispatcher of this shape (see
// `resolve_apply_effect` in src/daemon.rs).
#[allow(clippy::too_many_arguments)]
fn reclaim_lane_residue(
    host: &ResidueHost<'_>,
    generations: &[String],
    branch: &str,
    relative: &str,
    worktree: &Path,
    worktrees_root: &Path,
    issue: u64,
    local_only: LocalOnlyBranch,
) -> Vec<Val> {
    let registered = registered_worktree_paths_on(host);
    let checkout = if !worktree.exists() {
        object(vec![
            ("checkout", string(relative)),
            ("removed", bool_(true)),
            ("message", string("no checkout residue")),
        ])
    } else if is_registered_worktree(worktree, &registered) {
        let text = worktree.to_string_lossy().into_owned();
        failure_doc(
            run_git_on(host, host.integration_repo, &["worktree", "remove", &text]),
            &[("checkout", string(relative))],
        )
    } else {
        // An existing path this clone does not register as a worktree is not
        // the retired generation's checkout: nothing is forced and the
        // duplicate-lane refusal below stays the answer.
        object(vec![
            ("checkout", string(relative)),
            ("removed", bool_(false)),
            ("code", string(code::WORKTREE_EXISTS)),
            (
                "message",
                string(
                    "the existing path is not a registered worktree of the integration clone; \
                     nothing is forced",
                ),
            ),
        ])
    };
    let branch_tip = local_ref_tip_on(host, &format!("refs/heads/{branch}"));
    let published = published_branch_tip_on(host, branch);
    let lane_branch = match (branch_tip.as_deref(), published.as_deref()) {
        (None, _) => object(vec![
            ("branch", string(branch)),
            ("removed", bool_(true)),
            ("message", string("no branch residue")),
        ]),
        (Some(tip), Some(published_tip)) if published_tip == tip => {
            let removal = run_git_on(host, host.integration_repo, &["branch", "-D", branch]);
            failure_doc(
                removal,
                &[
                    ("branch", string(branch)),
                    ("tip", string(tip)),
                    ("published_tip", string(published_tip)),
                ],
            )
        }
        (Some(tip), published_tip) if local_only == LocalOnlyBranch::ReclaimUnheld => {
            // Issue #306: a local-only delivery is a retired generation's
            // reclaimable residue — unless a registration holds it. The read
            // happens AFTER the checkout half above, so the very registration
            // this reclaim just removed no longer counts as a holder.
            match registered_branch_holder_on(host, branch) {
                Some(holder) => object(vec![
                    ("branch", string(branch)),
                    ("tip", string(tip)),
                    (
                        "published_tip",
                        published_tip.map(string).unwrap_or_else(null),
                    ),
                    ("holder", string(&holder)),
                    ("removed", bool_(false)),
                    (
                        "message",
                        string(
                            "the local-only lane branch is checked out by a registered worktree \
                             of the integration clone; a held branch is never deleted or adopted",
                        ),
                    ),
                ]),
                None => match run_git_on(host, host.integration_repo, &["branch", "-D", branch]) {
                    Ok(_) => object(vec![
                        ("branch", string(branch)),
                        ("tip", string(tip)),
                        (
                            "published_tip",
                            published_tip.map(string).unwrap_or_else(null),
                        ),
                        ("removed", bool_(true)),
                        (
                            "message",
                            string(
                                "the retired generation's local-only lane branch was \
                                     reclaimed as residue: no live lane and no registered \
                                     worktree held it, and the tip above keeps the stale \
                                     delivery traceable",
                            ),
                        ),
                    ]),
                    Err(outcome) => object(vec![
                        ("branch", string(branch)),
                        ("tip", string(tip)),
                        (
                            "published_tip",
                            published_tip.map(string).unwrap_or_else(null),
                        ),
                        ("removed", bool_(false)),
                        (
                            "code",
                            string(outcome.code.as_deref().unwrap_or(code::MALFORMED_OUTPUT)),
                        ),
                        (
                            "message",
                            string(outcome.message.as_deref().unwrap_or_default()),
                        ),
                    ]),
                },
            }
        }
        (Some(tip), published_tip) => object(vec![
            ("branch", string(branch)),
            ("tip", string(tip)),
            (
                "published_tip",
                published_tip.map(string).unwrap_or_else(null),
            ),
            ("removed", bool_(false)),
            (
                "message",
                string(
                    "the local branch is not recoverable from the published branch; an explicit \
                     operator retirement never deletes a local-only delivery (the automatic \
                     reclaim at the next bind step does, and only while no registered worktree \
                     holds it)",
                ),
            ),
        ]),
    };
    vec![object(vec![
        ("issue", Val::Int(issue as i64)),
        (
            "generations",
            Val::Arr(generations.iter().map(|id| string(id)).collect()),
        ),
        ("checkout_residue", checkout),
        ("branch_residue", lane_branch),
        (
            "build_residue",
            Val::Arr(reclaim_build_residue(worktrees_root, issue)),
        ),
    ])]
}

/// The default deadline (seconds) one operator lane retire presents: the
/// documented effect default, the same bound class the p8 cleanup uses.
pub fn lane_retirement_deadline_secs() -> u64 {
    default_deadline_secs("cleanup")
}

/// Issue #236: retire the lane of ONE run the ledger records as terminal —
/// the residue half of the bounded operator control `run.retire-lane`.
///
/// The run's lane is its own implementer leg: the branch and the checkout are
/// the SAME derivation the plan producer renders (`crate::lane::lane_branch` /
/// `lane_checkout`), never a caller-supplied path, and the checkout is
/// contained under the run's own `worktrees_root`. Both halves are recorded:
///
/// 1. the run's linked lane workspace, retired FIRST (its registration is
///    resolved FROM the checkout): the identity-verified #190 path closes
///    exactly the run's own single-pane registration at that checkout — a
///    different pane, another lane's binding, an unverifiable read-back or a
///    foreign worktree is refused and left untouched, never adopted;
/// 2. the registered lane checkout and the local lane branch in the
///    integration clone, under the #222 policy: only a checkout this clone
///    REGISTERS is removed, and a branch is deleted only when the published
///    branch carries the same tip — a local-only delivery is never destroyed
///    by THIS control (issue #306 keeps the policy deliberately different from
///    the automatic bind-step reclaim, which reclaims an unheld local-only
///    branch; see [`LocalOnlyBranch`]).
///
/// A refusal is recorded on the returned document (never forced, never
/// retried implicitly). The caller has already proven the run is terminal:
/// a LIVE lane still holds its issue's unique ownership and is never in the
/// retired set, so this function is unreachable for one.
pub fn retire_run_lane(
    integration_repo: &Path,
    worktrees_root: &Path,
    run: &str,
    issue_number: i64,
    env: &BTreeMap<String, String>,
) -> EffectOutcome {
    if issue_number <= 0 {
        return refusal(
            code::LANE_IDENTITY,
            format!(
                "run {run} records no repository issue, so its lane cannot be derived; a lane is \
                 addressed by its own issue, never by a guess"
            ),
        );
    }
    let issue = issue_number as u64;
    let branch = crate::lane::lane_branch(issue);
    let relative = crate::lane::lane_checkout(issue, "implementer", 1);
    let lane = match contained_path(worktrees_root, &relative) {
        Ok(path) => path,
        Err(err) => return refusal(err.code, err.message),
    };
    let host = ResidueHost {
        integration_repo,
        env,
        deadline: Duration::from_secs(lane_retirement_deadline_secs()),
    };
    // The lane's workspace is retired BEFORE its checkout: the registration
    // is resolved from the checkout path, and an absent checkout has no
    // registration left to retire (recorded, never forced).
    let workspace = if !lane.exists() {
        object(vec![
            ("retired", bool_(false)),
            ("message", string("no lane checkout residue")),
        ])
    } else {
        let retired = match run_session_handle(run) {
            Ok(session) => crate::adapters::retire_lane_workspace(
                &session,
                &lane,
                env,
                crate::adapters::ADAPTER_TIMEOUT,
            )
            .map_err(|err| (err.code.to_string(), err.message)),
            Err(outcome) => Err((
                outcome
                    .code
                    .unwrap_or_else(|| code::LANE_IDENTITY.to_string()),
                outcome.message.unwrap_or_else(|| {
                    "the run's own lane session handle is incomplete".to_string()
                }),
            )),
        };
        match retired {
            Ok(Some(doc)) => doc,
            Ok(None) => object(vec![
                ("retired", bool_(false)),
                (
                    "message",
                    string("no lane workspace registration to retire"),
                ),
            ]),
            Err((code_text, message)) => object(vec![
                ("retired", bool_(false)),
                ("code", string(&code_text)),
                ("message", string(&message)),
            ]),
        }
    };
    let generations = vec![run.to_string()];
    // Issue #224 (AC6): a Herdr-side retire that REFUSED typed is never a
    // success this control builds a deletion on. The lane's own workspace
    // could not be retired (the measured drive: `refusal.stale.generation`,
    // the pane substrate refusing a reused identity), so the registered
    // checkout and the local lane branch are left exactly where they are and
    // the refusal is surfaced as the residue half's OWN typed outcome. It
    // never coexists with a reported-successful removal of the refs a live
    // lane may depend on — the measured drive removed both while its workspace
    // retire refused, and the live run's next step had no branch to read.
    if let Some(code_text) = workspace.get("code").and_then(Val::as_str) {
        let detail = workspace
            .get("message")
            .and_then(Val::as_str)
            .unwrap_or("the lane workspace retire refused without a message");
        return EffectOutcome {
            status: "refused",
            code: Some(code_text.to_string()),
            message: Some(format!(
                "the lane workspace of run {run} was not retired ({code_text}: {detail}); the \
                 registered checkout {relative:?} and the local lane branch {branch:?} were NOT \
                 removed — a lane whose own workspace could not be retired is not residue this \
                 control may delete, and nothing is forced"
            )),
            result: null(),
        };
    }
    let residue = reclaim_lane_residue(
        &host,
        &generations,
        &branch,
        &relative,
        &lane,
        worktrees_root,
        issue,
        // Issue #306: the operator control keeps the #222 policy for a
        // local-only branch — an explicit, human-issued retirement never
        // destroys the only copy of a delivery. The automatic bind-step
        // reclaim is the half that reclaims an UNHELD local-only branch.
        LocalOnlyBranch::Preserve,
    );
    ok(object(vec![
        ("run", string(run)),
        ("branch", string(&branch)),
        ("worktree", string(&relative)),
        ("workspace", workspace),
        ("residue", Val::Arr(residue)),
    ]))
}

/// The compact record of a reclaim attempt, appended to a refusal message so
/// the retire is audited even when the step itself refuses: empty when there
/// was nothing to reclaim.
fn reclaim_note(reclaimed: &[Val]) -> String {
    if reclaimed.is_empty() {
        return String::new();
    }
    format!(
        "; reclaimed {}",
        crate::canonical::canonical_text(&Val::Arr(reclaimed.to_vec()))
    )
}

/// One reclaim sub-step's record: `removed: true` on success, otherwise the
/// typed code and message of the refused git call, merged with `fields`.
fn failure_doc(
    outcome: Result<crate::process::ProcOut, EffectOutcome>,
    fields: &[(&'static str, Val)],
) -> Val {
    let mut out: Vec<(&str, Val)> = fields.to_vec();
    match outcome {
        Ok(_) => out.push(("removed", bool_(true))),
        Err(outcome) => {
            out.push(("removed", bool_(false)));
            out.push((
                "code",
                string(outcome.code.as_deref().unwrap_or(code::MALFORMED_OUTPUT)),
            ));
            out.push((
                "message",
                string(outcome.message.as_deref().unwrap_or_default()),
            ));
        }
    }
    object(out)
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
    let mut profile = match harness_profile(ctx, params) {
        Ok(profile) => profile,
        Err(outcome) => return outcome,
    };
    if profile.execution == crate::adapters::ExecutionMode::HerdrPane {
        let (role, round) = match step_lane_leg(ctx.params) {
            Ok(leg) => leg,
            Err(outcome) => return outcome,
        };
        profile.lane_names =
            match crate::adapters::LaneNames::new(ctx.plan.issue_number as u64, role, round) {
                Ok(names) => Some(names),
                Err(err) => return refusal(err.code, err.message),
            };
    }
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
    // Issue #190: the lane workspace is part of a generation's residue. The
    // generations the run ledger RETIRED (resolved by the caller, never from
    // the substrate) are retired HERE, before the new generation binds: the
    // deterministic name/label belongs to ONE lane identity, so a retired
    // generation's still-open workspace would otherwise refuse this bind with
    // `refusal.lane.name_collision` and leave the issue with no product path
    // out (#173). Every retire outcome — retired or refused — is recorded in
    // this step's outcome below (and on a failed bind, in its message): the
    // retire happened, so it is audited either way.
    let mut retired_generations: Vec<Val> = Vec::new();
    if profile.execution == crate::adapters::ExecutionMode::HerdrPane {
        for run in ctx.retired_run_ids {
            let doc = match run_session_handle(run) {
                Ok(retired) => match crate::adapters::retire_lane_workspace(
                    &retired,
                    &cwd,
                    ctx.env,
                    crate::adapters::ADAPTER_TIMEOUT,
                ) {
                    Ok(Some(doc)) => doc,
                    Ok(None) => continue,
                    Err(err) => retire_refusal_doc(&retired.session_id, err.code, &err.message),
                },
                Err(err) => retire_refusal_doc(
                    run,
                    err.code
                        .as_deref()
                        .unwrap_or(crate::adapters::CODE_INCOMPLETE_IDENTITY),
                    err.message.as_deref().unwrap_or_default(),
                ),
            };
            retired_generations.push(doc);
        }
    }
    let result = crate::adapters::execute_op_in_worktree(&profile, &request, ctx.env, &cwd);
    if result.status != "succeeded" {
        let mut message = result.message.clone().or_else(|| result.detail.clone());
        if !retired_generations.is_empty() {
            let note = retire_note(&retired_generations);
            message = Some(match message {
                Some(message) => format!("{message}; {note}"),
                None => note,
            });
        }
        return EffectOutcome {
            status: result.status,
            code: result.code.map(str::to_string),
            message,
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
    for key in [
        "pane",
        "agent",
        "workspace",
        "workspace_label",
        "worktree_identity",
        "reused",
    ] {
        fields.insert(
            key.to_string(),
            result
                .payload
                .as_ref()
                .and_then(|payload| payload.get(key).cloned())
                .unwrap_or_else(null),
        );
    }
    if !retired_generations.is_empty() {
        fields.insert(
            "retired_generations".to_string(),
            Val::Arr(retired_generations),
        );
    }
    ok(Val::Obj(fields))
}

/// The recorded refusal of one pre-bind lane retire (issue #190): the
/// generation that could not be retired, the typed refusal and the fact that
/// nothing was closed by it.
fn retire_refusal_doc(lane: &str, code: &str, message: &str) -> Val {
    object(vec![
        ("lane", string(lane)),
        ("retired", bool_(false)),
        ("code", string(code)),
        ("message", string(message)),
    ])
}

/// One bounded line naming what the pre-bind lane retire did (issue #190),
/// recorded on a failed bind too: a retire that already happened must be
/// recorded even when the bind that followed it did not succeed.
fn retire_note(docs: &[Val]) -> String {
    let retired = docs
        .iter()
        .filter(|doc| doc.get("retired").and_then(Val::as_bool) == Some(true))
        .count();
    let refused: Vec<String> = docs
        .iter()
        .filter_map(|doc| doc.get("code").and_then(Val::as_str))
        .map(str::to_string)
        .collect();
    let mut note = format!(
        "lane-retire: {retired} of {} terminal generation(s) retired before this bind",
        docs.len()
    );
    if !refused.is_empty() {
        note.push_str(&format!(" (refused: {})", refused.join(", ")));
    }
    note
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
        // Issue #272: a DETACHED worker checkout binds the run's RECORDED
        // branch when — and only when — it holds exactly that branch's own
        // revision. The engine's own repair lane is a `git worktree add
        // --detach` checkout (the run's feature branch is already checked out
        // in the run's own lane), so the repair leg's work is committed there
        // detached and the re-collect that re-establishes the certificate
        // binding observes exactly that checkout. The branch is never
        // fabricated for a checkout that carries none: it is the collection's
        // own committed binding, and the agreement between the bound branch
        // and the observed head is verified here BEFORE either is named — the
        // certificate may only ever state a head its own delivery branch
        // holds.
        if let Some(expected) = expected {
            let head = run_git(ctx, worktree, &["rev-parse", "--verify", "HEAD"])?
                .stdout
                .trim()
                .to_string();
            match run_git(
                ctx,
                worktree,
                &["rev-parse", "--verify", &format!("refs/heads/{expected}")],
            ) {
                Ok(bound) if bound.stdout.trim() == head => return Ok(expected.to_string()),
                Ok(bound) => {
                    return Err(refusal(
                        code::OUTPUT_LOCATION,
                        format!(
                            "worker output location {} is detached at {head}, not at the tip {} \
                             of its own bound branch {expected:?}",
                            worktree.display(),
                            bound.stdout.trim()
                        ),
                    ));
                }
                Err(_) => {
                    return Err(refusal(
                        code::OUTPUT_LOCATION,
                        format!(
                            "worker output location {} is detached and its own bound branch \
                             {expected:?} does not exist here",
                            worktree.display()
                        ),
                    ));
                }
            }
        }
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

/// Collect a pane's delivery even while it is live. An empty result needs a
/// confirmed stop, not a single transient idle/done/blocked read-back.
fn await_pane_worker(
    ctx: &EffectContext<'_>,
    inputs: &CollectOutcomeInputs,
    worktree: &Path,
) -> Result<Option<EffectOutcome>, EffectOutcome> {
    let prompt = ctx
        .plan
        .doc
        .get("steps")
        .and_then(Val::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[])
        .iter()
        .take_while(|step| step.get("id").and_then(Val::as_str) != Some(ctx.step_id))
        .filter(|step| step.get("kind").and_then(Val::as_str) == Some("prompt"))
        .filter_map(|step| step.get("params"))
        .filter(|params| {
            params.get("worktree").and_then(Val::as_str) == Some(inputs.worktree.as_str())
        })
        .last();
    let Some(prompt) = prompt else {
        return Ok(None);
    };
    if declared_execution(Some(prompt))? == crate::adapters::ExecutionMode::Headless {
        return Ok(None);
    }
    let prompt = prompt_inputs(Some(prompt), &ctx.param_contract())?;
    let session = resolve_session(ctx, prompt.declared, "collect_outcome")?;
    let seconds = effect_deadline_secs(ctx.kind, ctx.params)?;
    let start = std::time::Instant::now();
    poll_pane_worker(
        Duration::from_secs(seconds),
        Duration::from_secs(COLLECT_STOP_INTERVAL_SECS),
        Duration::from_secs(COLLECT_CEILING_SECS),
        |remaining| crate::adapters::observe_pane_worker(&session, worktree, remaining, ctx.env),
        || collect_worktree_outcome(ctx, inputs, worktree),
        || start.elapsed(),
        std::thread::sleep,
    )
    .map(Some)
}

/// The production loop, with explicit bounds, cadence and clock/wait seams.
/// Tests advance a local clock; no environment override can shorten a real run.
///
/// Issue #200: a delta head is certified only at a GENUINELY SETTLED pane
/// turn — the stop state must be confirmed across consecutive read-backs,
/// exactly like the empty-delta path — because a head read while the worker is
/// still mid-turn can still move. The measured p4→p5 boundary certified
/// `38fb0929` while the same worker was still mid-turn and committed
/// `0d5e851b` 26 s later, wedging the spine on `refusal.evidence.verdict_stale`
/// forever. A delivery collected while the worker is still live, like an empty
/// delta while the worker is still live, therefore stays a WAIT/re-check until
/// the stop is confirmed or the wait parks as `effect.worker_timeout`. A
/// collection failure that is not emptiness (a refusal of the collection
/// itself, e.g. a diverged or mis-branched lane) certifies no head and stays
/// actionable without waiting for the stop.
///
/// Issue #170 (N7): a stop is CONFIRMED only by [`COLLECT_STOP_SAMPLES`]
/// consecutive read-backs — each separated by the real `interval` off the
/// wait's own clock, not a loop iteration — in which BOTH views of the lane
/// ([`crate::adapters::PaneSample`]: the lane's own row and its status row)
/// report a non-working state AND the lane's own lifecycle counter did not
/// move. `refusal.collect.empty_delta` is therefore only ever returned for a
/// confirmed stop; while the worker is working, the wait keeps reading.
///
/// Issue #170 (N8): the wait is bounded by RECORDED PROGRESS, not by a fixed
/// wall clock (the #232/#233 treatment for the frontier waits). `window` is
/// the no-progress window — the step's effective deadline, unchanged — and
/// progress is: the lane reports it is `working`, or its read-back MOVED
/// (state changed, own counter advanced), or the delivery it collected MOVED
/// (a new certified head / commit count). While progress is recorded the wait
/// extends past `window`; a lane that records NONE for `window` parks as
/// `effect.worker_timeout` naming the progress it last saw and when. `ceiling`
/// is the hard overall bound no extension may leave, so a lane that keeps
/// producing progress is still bounded and parks the same way.
fn poll_pane_worker(
    window: Duration,
    interval: Duration,
    ceiling: Duration,
    mut observe: impl FnMut(
        Duration,
    ) -> Result<crate::adapters::PaneSample, crate::adapters::ProcessFailure>,
    mut collect: impl FnMut() -> EffectOutcome,
    elapsed: impl Fn() -> Duration,
    mut sleep: impl FnMut(Duration),
) -> Result<EffectOutcome, EffectOutcome> {
    let window_secs = window.as_secs();
    let ceiling_secs = ceiling.as_secs();
    let stop_run_span = interval * COLLECT_STOP_SAMPLES.saturating_sub(1) as u32;
    let mut previous: Option<crate::adapters::PaneSample> = None;
    let mut previous_delivery: Option<String> = None;
    let mut stop_run: Option<(usize, Duration)> = None;
    let mut last_progress_at = Duration::ZERO;
    let mut last_progress = "no read-back yet".to_string();
    loop {
        let now = elapsed();
        // Issue #170 (N8): the ceiling is the hard bound on ONE collection
        // wait and is not a progress judgment, so it is decided before any
        // further read-back is attempted.
        if now >= ceiling {
            return Err(collection_park(
                format!(
                    "pane worker was still producing progress at the {ceiling_secs}s overall \
                     collection ceiling (waited {}s)",
                    now.as_secs()
                ),
                window_secs,
                ceiling_secs,
                now,
                now.saturating_sub(last_progress_at),
                &last_progress,
            ));
        }
        // Issue #170 (N8): the read-back is evidence for the no-progress
        // window, so it may never outlive it: the row's own budget is what the
        // window has left, floored at one second so a read is always given a
        // real chance, and capped by what the overall ceiling has left.
        let budget = window
            .saturating_sub(now.saturating_sub(last_progress_at))
            .max(Duration::from_secs(1))
            .min(ceiling.saturating_sub(now));
        let sample = match observe(budget) {
            Ok(sample) => Some(sample),
            Err(err) if err.code == crate::adapters::CODE_TIMEOUT => {
                // A read-back that timed out carries no evidence at all: the
                // stop run breaks, and the wait decides on its bounds below and
                // re-reads at its own cadence.
                stop_run = None;
                None
            }
            Err(err) => {
                return Err(EffectOutcome {
                    status: err.status(),
                    code: Some(err.code.to_string()),
                    message: Some(format!("{}: {}", err.message, err.detail)),
                    result: null(),
                });
            }
        };
        if let Some(sample) = &sample {
            let outcome = collect();
            // Issue #170 (N8): the recorded progress this sample carries, in
            // priority order — a lane that reports it is working is working, a
            // read-back that moved is a lane that moved, and a delivery head
            // that moved is committed work.
            let delivery = certified_delivery(&outcome);
            let mut progress: Option<String> = None;
            if sample.lane_state == PANE_WORKING_STATE {
                progress = Some(format!("the lane reports {:?}", sample.lane_state));
            }
            if let Some(previous) = &previous {
                if previous.lane_state != sample.lane_state {
                    progress = Some(format!(
                        "the lane read-back moved {:?} -> {:?}",
                        previous.lane_state, sample.lane_state
                    ));
                } else if previous.seq != sample.seq {
                    progress = Some(format!(
                        "the lane's own state counter advanced {:?} -> {:?}",
                        previous.seq, sample.seq
                    ));
                }
            }
            if let (Some(before), Some(after)) = (&previous_delivery, &delivery)
                && before != after
            {
                progress = Some(format!("the collected delivery moved {before} -> {after}"));
            }
            if let Some(evidence) = progress {
                last_progress_at = now;
                last_progress = evidence;
            }
            let counter_moved = previous
                .as_ref()
                .map(|previous| previous.seq != sample.seq)
                .unwrap_or(false);
            previous = Some(sample.clone());
            previous_delivery = delivery;
            // Issue #170 (N7): a stop sample needs the lane's own row AND its
            // independent second view (the status row) to report a non-working
            // state — a single status field is never enough — and a lane whose
            // own counter moved is not a settled one.
            let stop = pane_stop_state(&sample.lane_state)
                && status_corroborates_stop(&sample.status_state)
                && !counter_moved;
            if stop {
                let (samples, since) = match stop_run {
                    Some((samples, since)) => (samples + 1, since),
                    None => (1, now),
                };
                stop_run = Some((samples, since));
                // Issue #170 (N8): the confirmation outranks the window — a
                // pinned, correct-by-construction confirmation (N consecutive
                // corroborated samples across the real interval) may never be
                // cut by the no-progress park that the confirmation itself is
                // about to answer. The CEILING still bounds even this: a run
                // that cannot settle within it was never convergeable.
                if samples >= COLLECT_STOP_SAMPLES && now.saturating_sub(since) >= stop_run_span {
                    return Ok(outcome);
                }
            } else {
                stop_run = None;
            }
            if outcome.status != "succeeded"
                && outcome.code.as_deref() != Some(code::COLLECT_EMPTY_DELTA)
            {
                return Ok(outcome);
            }
        }
        // Issue #170 (N8): the bounds are decided on the progress RECORDED by
        // the samples — after this sample's own evidence — so a read-back that
        // carries progress at the window's boundary is never parked past, while
        // a silent lane (or a substrate that cannot even answer) still fails
        // typed: no recorded progress for the window, and never past the
        // overall ceiling. A confirmation IN PROGRESS (at least one corroborated
        // stop sample since the last recorded progress) defers the window park:
        // the pinned confirmation is exactly what answers the "has it stopped?"
        // question the window exists for, and it is bounded by its own shape
        // (N samples across (N-1) intervals) plus the ceiling.
        if now >= ceiling {
            return Err(collection_park(
                format!(
                    "pane worker was still producing progress at the {ceiling_secs}s overall \
                     collection ceiling (waited {}s)",
                    now.as_secs()
                ),
                window_secs,
                ceiling_secs,
                now,
                now.saturating_sub(last_progress_at),
                &last_progress,
            ));
        }
        if now.saturating_sub(last_progress_at) >= window && stop_run.is_none() {
            return Err(collection_park(
                format!(
                    "pane worker has no recorded progress for {}s of the {window_secs}s no-progress \
                     window (waited {}s of the {ceiling_secs}s overall ceiling)",
                    now.saturating_sub(last_progress_at).as_secs(),
                    now.as_secs()
                ),
                window_secs,
                ceiling_secs,
                now,
                now.saturating_sub(last_progress_at),
                &last_progress,
            ));
        }
        sleep(interval.min(ceiling.saturating_sub(elapsed())));
    }
}

/// The state one read-back reports for a lane whose turn is WORKING: the
/// lane's own state field, never inferred from the absence of a stop.
const PANE_WORKING_STATE: &str = "working";

/// Whether one read-back reports a lane whose turn is NOT working — the
/// documented stop states (`idle|done|blocked`), unchanged by issue #170.
fn pane_stop_state(state: &str) -> bool {
    matches!(state, "idle" | "done" | "blocked")
}

/// Whether the sample's SECOND view (the lane's status row) corroborates a
/// stop: it reports a non-working state — or it carries NO state field at all,
/// which is never read as the negative (the same convention
/// [`crate::adapters`] applies to a missing readiness signal: an older row
/// that omits a field neither corroborates nor blocks). The stop then rests on
/// the lane's own verified row plus the pinned sample count and the unmoved
/// counter — never weaker than the pre-change rule, which read that row alone.
fn status_corroborates_stop(state: &str) -> bool {
    state.is_empty() || pane_stop_state(state)
}

/// The delivery a `succeeded` collection read (issue #170 N8 progress
/// evidence): the certified head and the commit count it saw. An outcome that
/// certified no head reports none — a refusal is never read as a movement.
fn certified_delivery(outcome: &EffectOutcome) -> Option<String> {
    if outcome.status != "succeeded" {
        return None;
    }
    let head = outcome.result.get("head").and_then(Val::as_str)?;
    let commits = outcome
        .result
        .get("commits")
        .and_then(Val::as_array)
        .map(Vec::len)
        .unwrap_or(0);
    Some(format!("{head} ({commits} commit(s))"))
}

/// The typed park of one collection wait (issue #170 N8): `ambiguous` with
/// `effect.worker_timeout`, naming what fired (the no-progress window or the
/// overall ceiling), the progress last observed and the elapsed time — the
/// shape #232/#233 gave the frontier waits.
fn collection_park(
    reason: String,
    window_secs: u64,
    ceiling_secs: u64,
    waited: Duration,
    progress_age: Duration,
    progress: &str,
) -> EffectOutcome {
    EffectOutcome {
        status: "ambiguous",
        code: Some(code::WORKER_TIMEOUT.to_string()),
        message: Some(format!(
            "{reason}; last progress {}s ago ({progress}); worker may still be running; \
             collection parked without redispatch",
            progress_age.as_secs()
        )),
        result: object(vec![
            ("deadline_secs", integer(window_secs as i64)),
            ("progress_window_secs", integer(window_secs as i64)),
            ("ceiling_secs", integer(ceiling_secs as i64)),
            ("waited_secs", integer(waited.as_secs() as i64)),
            ("progress_secs", integer(progress_age.as_secs() as i64)),
            ("progress", string(progress)),
        ]),
    }
}

/// Wait, bounded, for the lane to produce a CONFIRMED settled turn and then
/// close its workspace (issue #224).
///
/// The confirmation is the collection's own (issue #170 N7) — this is "the
/// same discipline `p5` already uses before certifying a delta": a settled
/// turn is [`COLLECT_STOP_SAMPLES`] consecutive read-backs whose BOTH views
/// report a non-working state, with the lane's own lifecycle counter unmoved,
/// spanning at least the documented [`LANE_SETTLE_SAMPLE_INTERVAL_SECS`]
/// interval. ONE read-back is not a settle: the measured flap reports a stop
/// state MID-TURN, and closing on it would retire the workspace of a lane
/// that is still alive — the protection issue #224 fences off.
///
/// `close` is the whole-lane verification the step always ran (lane token,
/// generation, worktree, settled agent state); it stays the authority for
/// every outcome that is not the timing condition. A lane whose own read-back
/// cannot be taken at all carries no settle evidence and falls straight
/// through to it (nothing observable is not waited on); a superseded
/// generation's or another lane's workspace still refuses at once, never
/// waited on; and a busy close — the lane started working again between the
/// confirmation and the close — voids the confirmation and re-confirms from
/// the next read-back.
///
/// Returns `Ok(())` once the workspace is closed. `Err(outcome)` is terminal:
/// [`code::LANE_TIMEOUT`] when the caller's bound expires with the lane still
/// unsettled (the workspace, checkout and branch untouched, the bounded
/// retries unspent), or the close's own typed refusal.
///
/// `outlived` names what the timing condition MEANS for the waiting step — the
/// clause its park states. Two callers share this wait: p8's cleanup (the
/// worker outliving its own PUBLISH, the landing proof already holding) and
/// p6's verdict consume (the reviewer outliving the VERDICT it wrote, already
/// consumed) — see [`LANE_OUTLIVED_PUBLISH`] / [`LANE_OUTLIVED_REVIEW`].
fn await_settled_lane(
    bound: Duration,
    // What the lane outliving its own work MEANS for the caller's step: the
    // clause the park states (p8: its publish is already verified landed; p6:
    // the verdict it wrote is already consumed). One fact, two callers.
    outlived: &str,
    mut observe: impl FnMut(
        Duration,
    ) -> Result<crate::adapters::PaneSample, crate::adapters::ProcessFailure>,
    mut close: impl FnMut() -> Result<(), crate::adapters::AdapterError>,
    elapsed: impl Fn() -> Duration,
    mut sleep: impl FnMut(Duration),
) -> Result<(), EffectOutcome> {
    let bound_secs = bound.as_secs();
    let interval = Duration::from_secs(LANE_SETTLE_SAMPLE_INTERVAL_SECS);
    let span =
        Duration::from_secs(LANE_SETTLE_SAMPLE_INTERVAL_SECS * (COLLECT_STOP_SAMPLES as u64 - 1));
    let mut previous: Option<crate::adapters::PaneSample> = None;
    let mut stop_run: Option<(usize, Duration)> = None;
    let mut last_state: Option<String> = None;
    loop {
        let now = elapsed();
        if now >= bound {
            return Err(lane_settle_park(
                bound_secs,
                now,
                last_state.as_deref(),
                outlived,
            ));
        }
        // The read-back is evidence for the settle, so it may never outlive
        // the bound: its budget is what the bound has left, floored at one
        // second so a read is always given a real chance.
        let budget = bound.saturating_sub(now).max(Duration::from_secs(1));
        let settled = match observe(budget) {
            Ok(sample) => {
                let counter_moved = previous
                    .as_ref()
                    .map(|previous| previous.seq != sample.seq)
                    .unwrap_or(false);
                last_state = Some(sample.lane_state.clone());
                previous = Some(sample.clone());
                let stop = pane_stop_state(&sample.lane_state)
                    && status_corroborates_stop(&sample.status_state)
                    && !counter_moved;
                if stop {
                    let (samples, since) = match stop_run {
                        Some((samples, since)) => (samples + 1, since),
                        None => (1, now),
                    };
                    stop_run = Some((samples, since));
                    samples >= COLLECT_STOP_SAMPLES && now.saturating_sub(since) >= span
                } else {
                    stop_run = None;
                    false
                }
            }
            Err(_) => true,
        };
        if settled {
            match close() {
                Ok(()) => return Ok(()),
                Err(err) if err.code == crate::adapters::CODE_LANE_BUSY => stop_run = None,
                Err(err) => return Err(refusal(err.code, err.message)),
            }
        }
        let remaining = bound.saturating_sub(elapsed());
        if remaining.is_zero() {
            continue;
        }
        sleep(interval.min(remaining));
    }
}

/// The bounded lane-settle wait's park (issue #224): `effect.lane_timeout` as
/// `ambiguous`, its bound and the live state it last read named, the workspace
/// preserved and the bounded retries unspent.
fn lane_settle_park(
    bound_secs: u64,
    waited: Duration,
    last_state: Option<&str>,
    outlived: &str,
) -> EffectOutcome {
    let observed = match last_state {
        Some(state) => format!("lane is still {state}; preserve its workspace"),
        None => "the lane's own read-back could not be taken; preserve its workspace".to_string(),
    };
    EffectOutcome {
        status: "ambiguous",
        code: Some(code::LANE_TIMEOUT.to_string()),
        message: Some(format!(
            "{observed}; {outlived} is a timing condition: the bounded wait of {bound_secs}s \
             for a CONFIRMED settled turn expired (waited {}ms); the workspace is preserved \
             and the step parked without redispatch",
            waited.as_millis()
        )),
        result: object(vec![
            ("deadline_secs", integer(bound_secs as i64)),
            ("waited_ms", integer(waited.as_millis() as i64)),
        ]),
    }
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
    let base_head = &inputs.base_head;
    // A missing/unrelated base or wrong checkout cannot become a valid
    // collection by waiting for a worker. Refuse before observing that worker,
    // using only the recorded object, never the runner's refs or remotes.
    if run_git(
        ctx,
        &worktree,
        &["merge-base", "--is-ancestor", base_head, "HEAD"],
    )
    .is_err()
    {
        return refusal(
            code::OUTPUT_LOCATION,
            format!(
                "collection base {base_head} is unavailable or is not an ancestor of the worktree HEAD"
            ),
        );
    }
    if let Err(outcome) = observed_worktree_branch(ctx, &worktree, inputs.branch.as_deref()) {
        return outcome;
    }
    match await_pane_worker(ctx, &inputs, &worktree) {
        Ok(Some(outcome)) | Err(outcome) => outcome,
        Ok(None) => collect_worktree_outcome(ctx, &inputs, &worktree),
    }
}

fn collect_worktree_outcome(
    ctx: &EffectContext<'_>,
    inputs: &CollectOutcomeInputs,
    worktree: &Path,
) -> EffectOutcome {
    let base_head = &inputs.base_head;
    let head_out = match run_git(ctx, worktree, &["rev-parse", "--verify", "HEAD"]) {
        Ok(out) => out,
        Err(outcome) => return outcome,
    };
    let head = head_out.stdout.trim().to_string();
    let branch = match observed_worktree_branch(ctx, worktree, inputs.branch.as_deref()) {
        Ok(branch) => branch,
        Err(outcome) => return outcome,
    };
    if run_git(
        ctx,
        worktree,
        &["merge-base", "--is-ancestor", base_head, &head],
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
        worktree,
        &[
            "log",
            "--format=%H",
            "--max-count=32",
            &format!("{base_head}..{head}"),
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
        worktree,
        &["diff", "--name-only", base_head, &head, "--"],
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
    if inputs.requires_delta && (&head == base_head || commits.is_empty() || changed.is_empty()) {
        return refusal(
            code::COLLECT_EMPTY_DELTA,
            format!(
                "collect_outcome requires a committed delta in worktree {:?} on branch {branch:?}, but recorded base {base_head} and head {head} contain no changed files",
                inputs.worktree,
            ),
        );
    }
    // Issue #202 (AC2): the collection binds the certified delivery head it
    // OBSERVED, or it is a typed non-success. A `succeeded` collection that
    // bound no head is the defect the review frontier parked on forever: the
    // head below IS this run's certified delivery binding (branch + head +
    // base), and `certify_delivery_binding` refuses when it cannot be named.
    if let Err(outcome) = certify_delivery_binding(&head, &branch) {
        return outcome;
    }
    ok(object(vec![
        ("head", string(&head)),
        ("commits", Val::Arr(commits)),
        ("base_head", string(base_head)),
        ("worktree", string(&inputs.worktree)),
        ("branch", string(&branch)),
        ("requires_delta", bool_(inputs.requires_delta)),
        ("changed_files", Val::Arr(changed)),
    ]))
}

/// Whether one collection's observation IS a certified delivery binding
/// (issue #202 AC2): the observed head is a 40-hex commit sha and the branch
/// it was collected from is a slug. A collection that cannot name what it
/// observed is a typed non-success ([`code::COLLECT_UNBOUND`]), never a
/// `succeeded` outcome that bound nothing — the run's later steps may only
/// ever consume the head the run's own collector certified.
pub fn certify_delivery_binding(head: &str, branch: &str) -> Result<(), EffectOutcome> {
    if !is_hex40(head) {
        return Err(refusal(
            code::COLLECT_UNBOUND,
            format!(
                "collect_outcome observed no bindable delivery head ({head:?} is not a 40-hex sha); a collection that cannot bind the head it observed is a typed non-success, never a `succeeded` outcome that bound nothing"
            ),
        ));
    }
    if !is_slug(branch) {
        return Err(refusal(
            code::COLLECT_UNBOUND,
            format!(
                "collect_outcome observed no bindable delivery branch ({branch:?} is not a slug); a collection that cannot bind the delivery it observed is a typed non-success, never a `succeeded` outcome that bound nothing"
            ),
        ));
    }
    Ok(())
}

/// `review_evidence`: record review evidence for this run's certified head.
///
/// Two shapes (issue #193):
/// - the step presents the review facts itself (the operator's own dispatch
///   path): the typed record values are returned as-is, no subprocess runs;
/// - the step declares the reviewer LEG: the run's own reviewer is started
///   through the same role-bound pane adapter the rest of the spine uses, is
///   handed the bounded review brief, and the verdict THAT reviewer writes is
///   consumed as this step's evidence. The engine never synthesises a
///   verdict: a missing, ill-formed, wrong-head or `pending`-carrying verdict
///   leaves the frontier parked with a typed reason.
fn effect_review_evidence(ctx: &EffectContext<'_>) -> EffectOutcome {
    let inputs = match review_evidence_inputs(ctx.params, &ctx.param_contract()) {
        Ok(inputs) => inputs,
        Err(outcome) => return outcome,
    };
    match &inputs.shape {
        ReviewEvidenceShape::Presented(facts) => ok(object(vec![
            ("repository", string(ctx.repository)),
            ("feature_head", string(&inputs.feature_head)),
            ("integration_base", string(&inputs.integration_base)),
            ("workflow_hash", string(&ctx.plan.workflow_hash)),
            ("verdict", string(&facts.verdict)),
            ("reviewer", string(&facts.reviewer)),
            ("checks", facts.checks.clone()),
        ])),
        ReviewEvidenceShape::SelfDispatch(leg) => review_self_dispatch(ctx, &inputs, leg),
    }
}

/// The reviewer's session identity for one lane round (issue #193): derived
/// ONCE from the run's own bound implementer session and the round, so the
/// reviewer identity is never caller-supplied, is stable across restarts and
/// can never be the implementer's own session. The derivation is the first
/// 16 hex of sha256 over the domain-separated pair.
pub fn reviewer_session_handle(
    implementer: &crate::adapters::SessionHandle,
    round: u64,
) -> Result<crate::adapters::SessionHandle, EffectOutcome> {
    let digest = crate::canonical::sha256_hex(
        format!("hf-review-session/v1|{}|{round}", implementer.session_id).as_bytes(),
    );
    let session_id = format!("lane-{}", &digest[..16]);
    let identity = crate::adapters::bind_identity(&session_id, &session_id, 1)
        .map_err(|err| refusal(err.code, err.message))?;
    crate::adapters::new_session(&session_id, identity)
        .map_err(|err| refusal(err.code, err.message))
}

/// The absolute path of the verdict artifact ONE run's review step consumes
/// (issue #193): the daemon-owned review root, the run's own session identity
/// and the step id — deterministic, outside every lane worktree (a reviewer's
/// write never dirties the lane the cleanup step must be able to remove) and
/// per-run, so a stale verdict of another run can never be consumed.
pub fn review_verdict_path(
    review_root: &Path,
    implementer: &crate::adapters::SessionHandle,
    step_id: &str,
) -> PathBuf {
    review_root.join(format!("{}-{step_id}.json", implementer.session_id))
}

/// The absolute path of the engine's OWN review-delivery record for one
/// run's review step (issue #214): beside the verdict artifact, in the same
/// daemon-owned review root, keyed by the same run session and step — so a
/// re-dispatch of the SAME step is the only reader that can ever match it.
pub fn review_delivery_receipt_path(
    review_root: &Path,
    implementer: &crate::adapters::SessionHandle,
    step_id: &str,
) -> PathBuf {
    review_root.join(format!(
        "{}-{step_id}.delivery.json",
        implementer.session_id
    ))
}

/// The engine's OWN durable record that one review prompt was PROVEN
/// delivered to one reviewer leg for one certified head (issue #214).
///
/// The reviewer leg's identity, its lane checkout and the verdict path are
/// all DERIVED, so every dispatch of the step addresses the SAME leg: an
/// attempt that finds this record knows that leg already carries the review
/// brief. The record is written only after a delivery the adapter proved
/// (kick + the agent's own read-back, the #148 discipline), so trusting it
/// is trusting a proof, never a spawn: a lane that is up but was never
/// proven prompted has no record and is prompted (and proven) as before.
///
/// Re-delivering to a leg that already has the brief is what the measured
/// p6-132 wall was made of (`run-1d4806c802c1088c`): the second attempt's
/// prompt could not be taken inside the bounded delivery window while the
/// reviewer's first turn was still running, so the engine reported the
/// PROMPTED leg as `refusal.prompt.undelivered` and never consumed the
/// verdict that leg went on to write. A record that does not name THIS
/// attempt's certified head and reviewer lane (a fresh lane, a reclaimed
/// leg, a moved head) is never trusted: that attempt re-delivers and
/// re-proves, and a delivery that cannot be recorded is refused fail-closed
/// rather than re-delivered on a guess.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReviewDelivery {
    /// The certified reviewed head the delivered prompt asked to review.
    pub feature_head: String,
    /// The reviewer lane session the prompt was proven delivered to.
    pub reviewer_lane: String,
    /// The Herdr agent the delivery's read-back was verified against (empty
    /// on the bare-subprocess substrate, which has no pane agent).
    pub reviewer_agent: String,
    /// The pane the delivering submission was verified in (empty on the
    /// bare-subprocess substrate, which has no pane).
    pub pane: String,
    /// The submission attempts the PROVEN delivery took (the adapter's own
    /// count of rows that submitted for it).
    pub delivery_attempts: i64,
}

impl ReviewDelivery {
    fn to_doc(&self) -> Val {
        object(vec![
            ("schema", string("hf-review-delivery/v1")),
            ("feature_head", string(&self.feature_head)),
            ("reviewer_lane", string(&self.reviewer_lane)),
            ("reviewer_agent", string(&self.reviewer_agent)),
            ("pane", string(&self.pane)),
            ("delivery_attempts", integer(self.delivery_attempts)),
        ])
    }

    /// Whether this record is the delivery of THIS attempt's certified head
    /// to THIS attempt's reviewer lane. Anything else (a moved head, another
    /// lane round, a reclaimed leg) is not proof for this dispatch.
    fn matches(&self, feature_head: &str, reviewer_lane: &str) -> bool {
        self.feature_head == feature_head && self.reviewer_lane == reviewer_lane
    }

    /// Read the record at `path`. `Ok(None)` when no record exists; a record
    /// that EXISTS but does not carry its bindings is refused fail-closed —
    /// the engine never guesses whether a delivery belongs to this step, and
    /// it never re-prompts a leg it may already have delivered to.
    fn read(path: &Path) -> Result<Option<ReviewDelivery>, EffectOutcome> {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => {
                return Err(refusal(
                    code::REVIEW_DELIVERY,
                    format!(
                        "the review delivery record {:?} is unreadable: {err}; the engine never \
                         guesses whether this step's reviewer was already prompted",
                        path.display()
                    ),
                ));
            }
        };
        let doc = Val::parse_json(&text).map_err(|err| {
            refusal(
                code::REVIEW_DELIVERY,
                format!(
                    "the review delivery record {:?} is not JSON: {err}",
                    path.display()
                ),
            )
        })?;
        if doc.get("schema").and_then(Val::as_str) != Some("hf-review-delivery/v1") {
            return Err(refusal(
                code::REVIEW_DELIVERY,
                format!(
                    "the review delivery record {:?} schema must be \"hf-review-delivery/v1\"",
                    path.display()
                ),
            ));
        }
        let field = |key: &str| -> Result<String, EffectOutcome> {
            doc.get(key)
                .and_then(Val::as_str)
                .map(str::to_string)
                .ok_or_else(|| {
                    refusal(
                        code::REVIEW_DELIVERY,
                        format!(
                            "the review delivery record {:?} carries no string {key:?}",
                            path.display()
                        ),
                    )
                })
        };
        let attempts = doc
            .get("delivery_attempts")
            .and_then(Val::as_int)
            .filter(|attempts| *attempts >= 1)
            .ok_or_else(|| {
                refusal(
                    code::REVIEW_DELIVERY,
                    format!(
                        "the review delivery record {:?} must carry a positive \
                         delivery_attempts count",
                        path.display()
                    ),
                )
            })?;
        Ok(Some(ReviewDelivery {
            feature_head: field("feature_head")?,
            reviewer_lane: field("reviewer_lane")?,
            reviewer_agent: field("reviewer_agent")?,
            pane: field("pane")?,
            delivery_attempts: attempts,
        }))
    }

    /// Durably record the delivery (issue #214). Publish-then-read never
    /// observes a torn record: the document is written beside the path and
    /// renamed onto it in one step. A record that cannot land refuses: a
    /// proven delivery whose proof is lost would be re-delivered by the next
    /// dispatch, which is exactly the defect this record exists to remove.
    fn write(&self, path: &Path) -> Result<(), EffectOutcome> {
        let text = crate::canonical::canonical_text(&self.to_doc());
        let staged = path.with_extension("tmp");
        if let Err(err) = std::fs::write(&staged, &text) {
            return Err(refusal(
                code::REVIEW_DELIVERY,
                format!(
                    "the proven review delivery could not be staged at {:?}: {err}",
                    staged.display()
                ),
            ));
        }
        if let Err(err) = std::fs::rename(&staged, path) {
            let _ = std::fs::remove_file(&staged);
            return Err(refusal(
                code::REVIEW_DELIVERY,
                format!(
                    "the proven review delivery could not be recorded at {:?}: {err}",
                    path.display()
                ),
            ));
        }
        Ok(())
    }
}

/// Whether this start REUSED the leg's registered lane (its own generation's
/// already-registered agent and pane) instead of creating a fresh one. Only
/// a reused lane is the leg a recorded delivery can belong to: a fresh lane
/// has never been prompted (issue #214).
fn started_lane_reused(started: &crate::adapters::OpResult) -> bool {
    started
        .payload
        .as_ref()
        .and_then(|payload| payload.get("reused"))
        .and_then(Val::as_bool)
        == Some(true)
}

/// The delivery clause a review timeout's message carries (issue #214
/// observability): the reviewer lane, its pane, its serving model and the
/// submission attempts the PROVEN delivery took — so a stuck review is
/// diagnosable without reading panes, and so the message states exactly
/// whether the leg was delivered to (and that a re-dispatch re-checks that
/// same leg's verdict instead of re-prompting it).
fn review_delivery_clause(delivery: &ReviewDelivery, serving_model: &str) -> String {
    let mut facts = vec![format!("reviewer lane {:?}", delivery.reviewer_lane)];
    if !delivery.reviewer_agent.is_empty() {
        facts.push(format!("agent {:?}", delivery.reviewer_agent));
    }
    if !delivery.pane.is_empty() {
        facts.push(format!("pane {:?}", delivery.pane));
    }
    facts.push(format!("serving model {serving_model:?}"));
    facts.push(format!(
        "{} submission attempt(s)",
        delivery.delivery_attempts
    ));
    format!(
        "the review prompt was PROVEN delivered to {} and the delivered leg is left to finish; \
         a re-dispatch of this step re-checks this same leg's verdict without re-delivering the \
         prompt",
        facts.join(", ")
    )
}

/// The bounded review brief delivered to the run's own reviewer (issue #193):
/// the certified head it must review, the observed base, the read-only fence,
/// and the exact artifact path it must WRITE its verdict to. The engine states
/// the live bindings it will record; it never states a verdict.
fn review_brief(inputs: &ReviewEvidenceInputs, leg: &ReviewerLeg, verdict_path: &Path) -> String {
    format!(
        "Review the exact head {} of this run's reviewer lane checkout {:?} against the integration base \
         {}, read-only: do not commit, push, or edit the checkout. Your verdict IS the evidence \
         this run's review step consumes, so write it yourself as ONE JSON document to the exact \
         path {:?}: {{\"schema\":\"hf-evidence/v1\",\"feature_head\":\"{}\",\
         \"integration_base\":\"{}\",\"verdict\":\"pass|fail\",\"checks\":[{{\"name\":\"<check>\",\
         \"status\":\"passed|failed\"}}]}} — every check must carry an explicit passed|failed \
         status (a pending check can never be consumed), and a verdict that does not name \
         feature_head {} is refused. Your role is {:?} (registry revision {}); the engine records \
         your verdict verbatim and never fills one in.",
        inputs.feature_head,
        leg.worktree,
        inputs.integration_base,
        verdict_path.display(),
        inputs.feature_head,
        inputs.integration_base,
        inputs.feature_head,
        leg.key,
        leg.profile.revision,
    )
}

/// Verify an existing lane checkout is a resolvable linked worktree AT the
/// certified head and clean (issue #210): a moved or dirty checkout is
/// refused, never repaired — the deterministic #200 rule the moved-checkout
/// refusal already carries, so no re-dispatch can silently review another sha.
fn verify_reviewer_lane(
    ctx: &EffectContext<'_>,
    relative: &str,
    lane: &Path,
    feature_head: &str,
) -> Result<(), EffectOutcome> {
    let head = match run_git(ctx, lane, &["rev-parse", "--verify", "HEAD"]) {
        Ok(out) => out.stdout.trim().to_string(),
        Err(outcome) => {
            return Err(refusal(
                code::LANE_IDENTITY,
                format!(
                    "the reviewer lane checkout {relative:?} is not a resolvable linked worktree \
                     of this run's repository ({}); a reviewer lane is only ever a canter-created \
                     checkout, so this one is refused and left untouched",
                    outcome.message.as_deref().unwrap_or_default()
                ),
            ));
        }
    };
    if head != feature_head {
        return Err(refusal(
            code::VERDICT_STALE,
            format!(
                "the reviewer lane checkout {relative:?} is at {head}, not the certified reviewed \
                 head {feature_head}; a reviewer is never started on a moved checkout"
            ),
        ));
    }
    let status = run_git(ctx, lane, &["status", "--porcelain"])?.stdout;
    if !status.trim().is_empty() {
        return Err(refusal(
            code::LANE_IDENTITY,
            format!(
                "the reviewer lane checkout {relative:?} is not clean; a reviewer lane is a clean \
                 canter-owned checkout, so this one is refused and left untouched"
            ),
        ));
    }
    Ok(())
}

/// Fold the stale checkout removal of one reclaimed reviewer lane into its
/// retire document (issue #210): the registration was closed first, so the
/// clean checkout at that lane is the retired generation's residue too. A
/// refused removal (dirty, unregistered) is recorded verbatim, never forced.
fn retire_lane_checkout_doc(
    ctx: &EffectContext<'_>,
    mut doc: Val,
    relative: &str,
    lane: &Path,
) -> Val {
    let lane_text = lane.to_string_lossy().into_owned();
    let removal = match run_git(
        ctx,
        ctx.integration_repo,
        &["worktree", "remove", &lane_text],
    ) {
        Ok(_) => object(vec![("removed", bool_(true))]),
        Err(outcome) => object(vec![
            ("removed", bool_(false)),
            (
                "code",
                string(outcome.code.as_deref().unwrap_or(code::MALFORMED_OUTPUT)),
            ),
            (
                "message",
                string(outcome.message.as_deref().unwrap_or_default()),
            ),
        ]),
    };
    if let Val::Obj(fields) = &mut doc {
        fields.insert("checkout".to_string(), string(relative));
        fields.insert("checkout_removal".to_string(), removal);
    }
    doc
}

/// The reviewer lane checkout ONE re-dispatch of a reviewer-leg step binds for
/// the round it is dispatching (issue #248).
///
/// The reviewed plan binds the reviewer leg's own checkout for the round the
/// plan was rendered at (`issues-<N>-rev<R>`, `crate::lane`). A leg that
/// ADVANCES to a new round — the re-review a fix round hands the leg to, driven
/// by the run's own bounded re-evaluation control — therefore holds a binding
/// for a round the step is dispatched at no longer, and a dispatch presenting
/// that binding unchanged refuses (`refusal.lane.identity`: ONE lane checkout
/// belongs to exactly one leg). The control that advances the round is the ONE
/// place allowed to RE-BIND that checkout, so this derives the leg's own
/// checkout for the round being dispatched.
///
/// `None` whenever the step's binding is not this issue's reviewer checkout
/// for another round: a genuinely foreign checkout is never reinterpreted, it
/// is refused exactly as before (`None` leaves the bound params untouched).
/// Only the pane substrate derives a per-round reviewer checkout; the
/// bare-subprocess fallback runs in the run's own lane checkout and keeps the
/// binding it was rendered with, byte for byte.
pub fn rebound_reviewer_lane(issue: u64, params: Option<&Val>, round: u64) -> Option<String> {
    let params = params?;
    if !declares_reviewer_leg(Some(params)) {
        return None;
    }
    // The plan's own substrate rule (`queue_preview::step_is_pane_substrate`):
    // absent or `herdr` is the pane substrate; anything else keeps its binding.
    let pane = matches!(
        params.get("execution").and_then(Val::as_str),
        None | Some("herdr")
    );
    if !pane {
        return None;
    }
    let declared = params.get("worktree").and_then(Val::as_str)?;
    if reviewer_checkout_round(issue, declared)? == round {
        return None;
    }
    Some(crate::lane::lane_checkout(issue, "reviewer", round))
}

/// The round of ONE of this issue's reviewer lane checkouts — `Some` only when
/// the declared value really is one (`issues-<N>-rev<R>` for a positive `R`,
/// byte-equal to the derivation itself). Anything else is no round of this
/// leg's, so it is never re-bound.
fn reviewer_checkout_round(issue: u64, checkout: &str) -> Option<u64> {
    let round: u64 = checkout
        .strip_prefix(&format!("issues-{issue}-rev"))?
        .parse()
        .ok()?;
    if round == 0 || crate::lane::lane_checkout(issue, "reviewer", round) != checkout {
        return None;
    }
    Some(round)
}

/// Materialize the reviewer leg's OWN lane checkout at the certified head
/// (issue #210), reclaiming the retired generations' reviewer lanes of that
/// identity first (#190/#173 direction).
///
/// The pane substrate registers ONE workspace per checkout, so a reviewer leg
/// that bound the run's own lane checkout collides with the implementer lane
/// holding it (`refusal.lane.name_collision`, measured on run-a1eb1f68dc9f2976).
/// The reviewer leg therefore binds its own checkout — derived from
/// `(issue, reviewer, round)` and visible in the rendered plan — and this
/// effect materializes it: a ledger-terminal generation's reviewer lane is
/// reclaimed (registration closed, stale checkout cleared, both recorded on
/// the step outcome), then THIS generation's lane is created at the certified
/// head. A live or foreign holder is never adopted: its retire is refused and
/// the lane is left untouched (#157), and the substrate refusal stands.
///
/// Issue #282: a registration the integration clone still holds for THIS
/// leg's own lane path while its directory is gone is stale host state, not a
/// step failure — it is cleared for exactly that path before the create (see
/// [`clear_stale_lane_registration`]) and the repair rides the outcome, so a
/// re-dispatch materializes the lane instead of dying on the stale entry.
///
/// Returns the lane and, when one was cleared, the stale-registration record.
fn ensure_reviewer_lane(
    ctx: &EffectContext<'_>,
    leg: &ReviewerLeg,
    feature_head: &str,
    retired: &mut Vec<Val>,
) -> Result<(PathBuf, Option<Val>), EffectOutcome> {
    let issue = ctx.plan.issue_number as u64;
    let relative = crate::lane::lane_checkout(issue, "reviewer", leg.round);
    if relative != leg.worktree {
        return Err(refusal(
            code::LANE_IDENTITY,
            format!(
                "the reviewed plan binds lane checkout {:?} for this run's reviewer leg, but the \
                 reviewer leg's own lane checkout is {relative:?} (issue {issue}, reviewer, round \
                 {}); ONE lane checkout belongs to exactly one leg, so a plan that binds another \
                 leg's checkout is refused here and by the preview — re-render the plan",
                leg.worktree, leg.round
            ),
        ));
    }
    let lane = contained_path(ctx.worktrees_root, &relative)
        .map_err(|err| refusal(err.code, err.message))?;
    if lane.is_dir() {
        for run in ctx.retired_run_ids {
            let retired_reviewer = match run_session_handle(run)
                .and_then(|implementer| reviewer_session_handle(&implementer, leg.round))
            {
                Ok(session) => session,
                Err(outcome) => {
                    retired.push(retire_refusal_doc(
                        run,
                        outcome.code.as_deref().unwrap_or(code::LANE_IDENTITY),
                        outcome.message.as_deref().unwrap_or_default(),
                    ));
                    continue;
                }
            };
            match crate::adapters::retire_lane_workspace(
                &retired_reviewer,
                &lane,
                ctx.env,
                crate::adapters::ADAPTER_TIMEOUT,
            ) {
                Ok(Some(doc)) => {
                    retired.push(retire_lane_checkout_doc(ctx, doc, &relative, &lane));
                }
                Ok(None) => {}
                Err(err) => retired.push(retire_refusal_doc(
                    &retired_reviewer.session_id,
                    err.code,
                    &err.message,
                )),
            }
        }
    }
    if lane.is_dir() {
        verify_reviewer_lane(ctx, &relative, &lane, feature_head)?;
        return Ok((lane, None));
    }
    if let Some(parent) = lane.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    // Issue #282: the lane this leg is about to create is the run's own path
    // (derived from the issue and the leg's round), so a registration git still
    // holds for it while its directory is gone is stale host state with a
    // mechanical remedy: it is cleared for exactly this path before the create
    // below, and the repair is recorded on the step outcome.
    let stale_registration = clear_stale_lane_registration(ctx, &relative, &lane)?;
    let lane_text = lane.to_string_lossy().into_owned();
    match run_git(
        ctx,
        ctx.integration_repo,
        &["worktree", "add", "--detach", &lane_text, feature_head],
    ) {
        Ok(_) => {}
        Err(outcome) => return Err(outcome),
    }
    verify_reviewer_lane(ctx, &relative, &lane, feature_head)?;
    Ok((lane, stale_registration))
}

/// Remove the reviewer leg's own lane once its verdict is consumed (issue
/// #210): the lane exists FOR the review, so a consumed review leaves no
/// orphan workspace and no orphan checkout. Refusals — a checkout git will not
/// remove — are recorded on the step outcome and never forced; the residue
/// stays reclaimable (#190).
///
/// Issue #224: at the instant the verdict is consumed the reviewer is still
/// `working` — it has just written the verdict — so the single close that
/// retired nothing refused `refusal.lane.busy` on EVERY measured run (30 of 30
/// recorded p6 receipts, 2026-09-19..2026-09-25), and the registration, the
/// pane and the checkout then outlived the run forever: the next run of the
/// same issue collided with the deterministic lane name and needed an
/// operator to close the workspace by hand. The close is therefore WAITED for,
/// bounded by the step's own effective deadline, under the cleanup step's own
/// confirmed-settle discipline ([`await_settled_lane`], issue #170 N7): a lane
/// that is still working, that starts working again between the confirmation
/// and the close, or that only flaps a stop MID-TURN is never closed from
/// here, and a typed refusal that is not the busy timing condition returns at
/// once, never waited on.
///
/// The receipt keeps the close's OWN last read verbatim — a still-working lane
/// still records its `refusal.lane.busy` (issue #260 NB-2) — and records the
/// wait beside it (`waited_ms`, plus the wait's own terminal `wait` outcome
/// when it did not close: the `effect.lane_timeout` park names its bound and
/// the state it last read). Nothing here consumes a bounded retry: the step
/// still SUCCEEDS with its receipt, and a parked wait leaves the workspace,
/// the checkout and the branch reclaimable exactly as before.
fn remove_reviewer_lane(
    ctx: &EffectContext<'_>,
    reviewer: &crate::adapters::SessionHandle,
    lane: &Path,
    bound: Duration,
) -> Val {
    let mut close_lane = || {
        crate::adapters::close_lane_workspace(
            reviewer,
            lane,
            ctx.env,
            crate::adapters::ADAPTER_TIMEOUT,
        )
    };
    let started = std::time::Instant::now();
    let waited = await_settled_lane(
        bound,
        LANE_OUTLIVED_REVIEW,
        |remaining| crate::adapters::observe_pane_worker(reviewer, lane, remaining, ctx.env),
        &mut close_lane,
        || started.elapsed(),
        std::thread::sleep,
    );
    let waited_ms = started.elapsed().as_millis().min(i64::MAX as u128) as i64;
    let workspace = match waited {
        Ok(()) => object(vec![
            ("closed", bool_(true)),
            ("waited_ms", integer(waited_ms)),
        ]),
        Err(outcome) => {
            // The receipt carries the close's OWN last read verbatim — the
            // still-working lane keeps its `refusal.lane.busy` literal (issue
            // #260 NB-2) — and, beside it, the wait's own terminal outcome
            // (the `effect.lane_timeout` park when the bound expired), so the
            // timing is diagnosable without reading the wait's internals.
            match close_lane() {
                Ok(()) => object(vec![
                    ("closed", bool_(true)),
                    ("waited_ms", integer(waited_ms)),
                ]),
                Err(err) => object(vec![
                    ("closed", bool_(false)),
                    ("code", string(err.code)),
                    ("message", string(&err.message)),
                    ("waited_ms", integer(waited_ms)),
                    (
                        "wait",
                        object(vec![
                            ("bound_secs", integer(bound.as_secs() as i64)),
                            (
                                "code",
                                string(outcome.code.as_deref().unwrap_or(code::LANE_TIMEOUT)),
                            ),
                            (
                                "message",
                                string(outcome.message.as_deref().unwrap_or_default()),
                            ),
                        ]),
                    ),
                ]),
            }
        }
    };
    let checkout = if workspace.get("closed").and_then(Val::as_bool) == Some(true) {
        let lane_text = lane.to_string_lossy().into_owned();
        match run_git(
            ctx,
            ctx.integration_repo,
            &["worktree", "remove", &lane_text],
        ) {
            Ok(_) => object(vec![("removed", bool_(true))]),
            Err(outcome) => object(vec![
                ("removed", bool_(false)),
                (
                    "code",
                    string(outcome.code.as_deref().unwrap_or(code::MALFORMED_OUTPUT)),
                ),
                (
                    "message",
                    string(outcome.message.as_deref().unwrap_or_default()),
                ),
            ]),
        }
    } else {
        object(vec![
            ("removed", bool_(false)),
            (
                "skipped",
                string("the lane workspace is still held; the checkout is preserved"),
            ),
        ])
    };
    object(vec![("workspace", workspace), ("checkout", checkout)])
}

// ---------------------------------------------------------------------------
// The fix-round handoff of a recorded review FAIL (issue #238)
// ---------------------------------------------------------------------------

/// The number of automatic fix rounds one run may dispatch before a recorded
/// review FAIL escalates (issue #238).
///
/// ONE fact, deliberately shared with the doctrine's own budget
/// ([`crate::engine::NORMAL_REVIEW_ROUNDS`]): the reviewed workflow authorizes
/// at most that many normal review/fix rounds before exhaustion enters the
/// human queue, so this handoff can never dispatch more automatic repair
/// rounds than the workflow the run executes under.
pub const FIX_ROUNDS_MAX: u32 = crate::engine::NORMAL_REVIEW_ROUNDS;

/// The fix leg's session identity for one lane round (issue #238): derived
/// ONCE from the run's own bound implementer session and the round, exactly
/// as the reviewer identity is derived (#193) — never caller-supplied, stable
/// across restarts, and never the identity of the leg it repairs.
pub fn fix_session_handle(
    implementer: &crate::adapters::SessionHandle,
    round: u64,
) -> Result<crate::adapters::SessionHandle, EffectOutcome> {
    let digest =
        sha256_hex(format!("hf-fix-session/v1|{}|{round}", implementer.session_id).as_bytes());
    let session_id = format!("lane-{}", &digest[..16]);
    let identity = crate::adapters::bind_identity(&session_id, &session_id, 1)
        .map_err(|err| refusal(err.code, err.message))?;
    crate::adapters::new_session(&session_id, identity)
        .map_err(|err| refusal(err.code, err.message))
}

/// The absolute path of the engine's OWN fix-round record for one run's
/// review step (issue #238): beside the reviewer's verdict and delivery
/// artifacts, in the same daemon-owned review root, keyed by the run's own
/// session and the step — only a dispatch of that same step reads it.
pub fn fix_round_receipt_path(
    review_root: &Path,
    implementer: &crate::adapters::SessionHandle,
    step_id: &str,
) -> PathBuf {
    review_root.join(format!(
        "{}-{step_id}.fix-round.json",
        implementer.session_id
    ))
}

/// The engine's OWN durable record that ONE review FAIL was handed to the
/// run's fix round (issue #238).
///
/// The certified head is the idempotency key: a fix round dispatched for one
/// head is never re-dispatched for that head (a re-dispatch of the same
/// review attempt reuses the running round), and a MOVED head opens the next
/// round of the same automatic budget. The record is written only after a
/// delivery the substrate proved, so a round is never counted for a prompt
/// that never reached its leg — those refuse typed instead
/// (`refusal.fix.spawn` / `refusal.fix.prompt`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FixRoundReceipt {
    /// The fix round (1-based) this record names.
    pub round: u32,
    /// The automatic bound in force when the round was dispatched.
    pub bound: u32,
    /// The certified reviewed head the round was dispatched for.
    pub feature_head: String,
    /// The fix leg's lane session (the registered identity).
    pub lane: String,
    /// The agent the substrate verified the leg as ('' headless).
    pub agent: String,
    /// The workspace label the leg's lane was registered under ('' headless).
    pub workspace: String,
    /// The pane the leg was started in ('' headless).
    pub pane: String,
    /// The fix leg's OWN lane checkout, relative to the run's worktrees root
    /// (issue #256): the recorded place the leg's own state lives, so the
    /// handoff can be read against the head the leg DELIVERED.
    pub worktree: String,
    /// The submission attempts the proven delivery took.
    pub delivery_attempts: i64,
}

impl FixRoundReceipt {
    /// The receipt as the step outcome records it.
    fn to_doc(&self, failures: &[Val], reused: bool) -> Val {
        object(vec![
            ("schema", string("hf-fix-round/v1")),
            ("round", integer(self.round as i64)),
            ("bound", integer(self.bound as i64)),
            ("feature_head", string(&self.feature_head)),
            ("lane", string(&self.lane)),
            ("agent", string(&self.agent)),
            ("workspace", string(&self.workspace)),
            ("pane", string(&self.pane)),
            ("worktree", string(&self.worktree)),
            ("delivery_attempts", integer(self.delivery_attempts)),
            ("failures", Val::Arr(failures.to_vec())),
            ("reused", bool_(reused)),
        ])
    }

    /// Read the record at `path`. `Ok(None)` when none exists; a record that
    /// exists but does not carry its bindings is refused fail-closed — the
    /// engine never guesses whether a round was already dispatched, and it
    /// never burns another round on a guess.
    fn read(path: &Path) -> Result<Option<FixRoundReceipt>, EffectOutcome> {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => {
                return Err(refusal(
                    code::FIX_UNBOUND,
                    format!(
                        "the fix-round record {:?} is unreadable: {err}; the engine never \
                         guesses whether this FAIL already reached a fix round",
                        path.display()
                    ),
                ));
            }
        };
        let doc = Val::parse_json(&text).map_err(|err| {
            refusal(
                code::FIX_UNBOUND,
                format!(
                    "the fix-round record {:?} is not JSON: {err}",
                    path.display()
                ),
            )
        })?;
        if doc.get("schema").and_then(Val::as_str) != Some("hf-fix-round/v1") {
            return Err(refusal(
                code::FIX_UNBOUND,
                format!(
                    "the fix-round record {:?} must be an \"hf-fix-round/v1\" document",
                    path.display()
                ),
            ));
        }
        let text_field = |key: &str| -> Result<String, EffectOutcome> {
            doc.get(key)
                .and_then(Val::as_str)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
                .ok_or_else(|| {
                    refusal(
                        code::FIX_UNBOUND,
                        format!(
                            "the fix-round record {:?} carries no {key:?}",
                            path.display()
                        ),
                    )
                })
        };
        let int_field = |key: &str| -> Result<i64, EffectOutcome> {
            doc.get(key).and_then(Val::as_int).ok_or_else(|| {
                refusal(
                    code::FIX_UNBOUND,
                    format!(
                        "the fix-round record {:?} carries no {key:?}",
                        path.display()
                    ),
                )
            })
        };
        Ok(Some(FixRoundReceipt {
            round: u32::try_from(int_field("round")?).map_err(|_| {
                refusal(
                    code::FIX_UNBOUND,
                    format!(
                        "the fix-round record {:?} round is out of range",
                        path.display()
                    ),
                )
            })?,
            bound: u32::try_from(int_field("bound")?).map_err(|_| {
                refusal(
                    code::FIX_UNBOUND,
                    format!(
                        "the fix-round record {:?} bound is out of range",
                        path.display()
                    ),
                )
            })?,
            feature_head: text_field("feature_head")?,
            lane: text_field("lane")?,
            agent: doc
                .get("agent")
                .and_then(Val::as_str)
                .unwrap_or("")
                .to_string(),
            workspace: doc
                .get("workspace")
                .and_then(Val::as_str)
                .unwrap_or("")
                .to_string(),
            pane: doc
                .get("pane")
                .and_then(Val::as_str)
                .unwrap_or("")
                .to_string(),
            // Issue #256: the leg's own lane checkout. A record written before
            // this slice names none, and a handoff that names none is observed
            // against no checkout at all (never a guessed path).
            worktree: doc
                .get("worktree")
                .and_then(Val::as_str)
                .unwrap_or("")
                .to_string(),
            delivery_attempts: int_field("delivery_attempts")?,
        }))
    }

    /// Write the record — carrying the failures the instruction was derived
    /// from — so the round the bound counts is also the round's own evidence.
    /// A record that cannot be written is refused rather than leaving a
    /// dispatched round uncountable against the bound.
    fn write(&self, path: &Path, failures: &[Val]) -> Result<(), EffectOutcome> {
        let bytes = canonical_bytes(&self.to_doc(failures, false));
        std::fs::write(path, bytes).map_err(|err| {
            refusal(
                code::FIX_UNBOUND,
                format!(
                    "the fix-round record {:?} is not writable: {err}",
                    path.display()
                ),
            )
        })
    }
}

/// The named checks a recorded verdict FAILED (issue #238): the exact facts
/// the fix instruction is derived from. A verdict with no failed check still
/// fails as a whole — the failure clause says so rather than naming none.
fn failing_checks(checks: &Val) -> Vec<Val> {
    checks
        .as_array()
        .map(|checks| {
            checks
                .iter()
                .filter(|check| check.get("status").and_then(Val::as_str) == Some("failed"))
                .cloned()
                .collect()
        })
        .unwrap_or_default()
}

/// The failures as one bounded human clause (the ESCALATION text of issue
/// #238: the code names the class, this names the failures).
fn failures_clause(failures: &[Val]) -> String {
    if failures.is_empty() {
        return "the reviewer recorded no individually failed check; its verdict is the failure"
            .to_string();
    }
    failures
        .iter()
        .map(|check| {
            format!(
                "check {:?} is failed",
                check.get("name").and_then(Val::as_str).unwrap_or("")
            )
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// The run's own committed implementer leg (issue #238): the lane leg the run
/// itself was built by, resolved from the run's OWN committed plan — never
/// from a caller, a default or a literal.
///
/// The leg is the LOWEST-round `implementer` harness step of the committed
/// spine (the run's own lane); the fix round's legs are the later rounds of
/// that same lane (`crate::lane`: `impl-<N>-r<R>` / `issues-<N>-impl<R>`), so
/// the fix instruction runs under the run's reviewed role binding with the
/// run's own declared lane inputs.
struct ImplementerLeg {
    /// The run's role-resolved harness profile (kind/executable/binding).
    profile: crate::adapters::Profile,
    /// The run's own implementer round (the fix rounds follow it).
    round: u64,
    /// The run's own lane checkout, relative to the worktrees root.
    worktree: String,
    /// The run's own feature branch, when the committed plan declares one.
    branch: Option<String>,
}

fn run_implementer_leg(ctx: &EffectContext<'_>) -> Result<ImplementerLeg, EffectOutcome> {
    let steps = ctx
        .plan
        .doc
        .get("steps")
        .and_then(Val::as_array)
        .cloned()
        .unwrap_or_default();
    let issue = ctx.plan.issue_number as u64;
    let mut leg: Option<ImplementerLeg> = None;
    for step in &steps {
        let kind = step.get("kind").and_then(Val::as_str).unwrap_or("");
        if !matches!(kind, "harness_start" | "prompt") {
            continue;
        }
        let Some(params) = step.get("params") else {
            continue;
        };
        let (role, round) = step_lane_leg(Some(params))?;
        if role != "implementer" {
            continue;
        }
        if leg.as_ref().is_some_and(|leg| leg.round <= round) {
            continue;
        }
        // `harness_start` declares no worktree of its own (the lane is
        // created by the run's own worktree step): the leg's checkout is
        // derived from the same `(role, round)` triple the names come from.
        let worktree = params
            .get("worktree")
            .and_then(Val::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| crate::lane::lane_checkout(issue, "implementer", round));
        let profile = harness_profile(ctx, params)?;
        leg = Some(ImplementerLeg {
            profile,
            round,
            worktree,
            branch: None,
        });
    }
    let mut leg = leg.ok_or_else(|| {
        refusal(
            code::FIX_UNBOUND,
            "this run's committed plan declares no implementer harness step, so a review FAIL has \
             no leg to hand its fix round to; the fix leg is never invented",
        )
    })?;
    // The run's own feature branch: the branch its lane checkout was created
    // on, as the committed plan declares it. The fix instruction names it when
    // it is known; it is never guessed from a path or a label.
    for step in &steps {
        let kind = step.get("kind").and_then(Val::as_str).unwrap_or("");
        if kind != "worktree_create" {
            continue;
        }
        if let Some(branch) = step
            .get("params")
            .and_then(|params| params.get("branch"))
            .and_then(Val::as_str)
            && is_slug(branch)
        {
            leg.branch = Some(branch.to_string());
        }
        break;
    }
    Ok(leg)
}

/// Verify an existing fix-round lane checkout is a clean linked worktree AT
/// the certified reviewed head (issue #238). A moved or dirty checkout is
/// refused, never repaired: a fix round is only ever dispatched at the head
/// whose verdict failed.
fn verify_fix_lane(
    ctx: &EffectContext<'_>,
    relative: &str,
    lane: &Path,
    feature_head: &str,
) -> Result<PathBuf, EffectOutcome> {
    let head = match run_git(ctx, lane, &["rev-parse", "--verify", "HEAD"]) {
        Ok(out) => out.stdout.trim().to_string(),
        Err(outcome) => {
            return Err(EffectOutcome {
                status: outcome.status,
                code: Some(code::FIX_LANE.to_string()),
                message: Some(format!(
                    "the fix round's lane checkout {relative:?} is not a resolvable linked \
                     worktree of this run's repository ({}); it is refused and left untouched",
                    outcome.message.as_deref().unwrap_or_default()
                )),
                result: null(),
            });
        }
    };
    if head != feature_head {
        return Err(refusal(
            code::FIX_LANE,
            format!(
                "the fix round's lane checkout {relative:?} is at {head}, not the certified \
                 reviewed head {feature_head}; a fix round is only ever dispatched at the head \
                 whose review failed"
            ),
        ));
    }
    let status = run_git(ctx, lane, &["status", "--porcelain"])?.stdout;
    if !status.trim().is_empty() {
        return Err(refusal(
            code::FIX_LANE,
            format!(
                "the fix round's lane checkout {relative:?} is not clean; a fix leg is only ever \
                 started on a clean checkout, so this one is refused and left untouched"
            ),
        ));
    }
    Ok(lane.to_path_buf())
}

/// The fix leg's lane checkout at the certified head: created when absent
/// (the same way the reviewer leg's lane is), verified when present — so the
/// FAIL handoff both CREATES and REUSES a fix leg lane (issue #238).
fn ensure_fix_lane(
    ctx: &EffectContext<'_>,
    relative: &str,
    feature_head: &str,
) -> Result<PathBuf, EffectOutcome> {
    let lane = contained_path(ctx.worktrees_root, relative)
        .map_err(|err| refusal(code::FIX_LANE, err.message))?;
    if lane.is_dir() {
        return verify_fix_lane(ctx, relative, &lane, feature_head);
    }
    if let Some(parent) = lane.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    // Issue #282: the fix leg's lane is a lane path this run owns by its own
    // recorded topology, so a registration git still holds for it while its
    // directory is gone is cleared for exactly this path first (the fix round
    // is dispatched by the run's own machinery, with no operator involved).
    let _ = clear_stale_lane_registration(ctx, relative, &lane)?;
    let lane_text = lane.to_string_lossy().into_owned();
    match run_git(
        ctx,
        ctx.integration_repo,
        &["worktree", "add", "--detach", &lane_text, feature_head],
    ) {
        Ok(_) => {}
        Err(outcome) => {
            return Err(EffectOutcome {
                status: outcome.status,
                code: Some(code::FIX_LANE.to_string()),
                message: Some(format!(
                    "the fix round's lane {relative:?} could not be created at the certified head \
                     {feature_head}: {}",
                    outcome.message.as_deref().unwrap_or_default()
                )),
                result: null(),
            });
        }
    }
    verify_fix_lane(ctx, relative, &lane, feature_head)
}

/// Observe the repair leg's OWN lane checkout (issue #256): the head it holds,
/// and whether that head is a DESCENDANT of the certified head the recorded
/// handoff names.
///
/// The leg's own checkout is the ONLY state that names the delivered head —
/// the head a handoff was dispatched for is the head the FAIL was handed at
/// and can never move by itself. `None` when there is nothing to observe (no
/// recorded lane, an unreadable or uncleanable checkout): an unobserved leg is
/// never reported as moved. Read-only: no effect, no journal, no repair.
///
/// Issue #276: when the recorded lane checkout no longer EXISTS the leg is
/// observed as such — `lane: false`, no head — instead of being left
/// unobserved. The lane is the leg's own state and its absence is a fact
/// about it: a repair leg whose checkout is gone cannot deliver anything more,
/// and a run waiting on it has no end. A checkout that is present but cannot
/// be read stays `None`: an unreadable read is never a lost lane.
pub fn observe_fix_leg_checkout(
    root: &Path,
    worktree: &str,
    certified: &str,
) -> Option<crate::state::FixLegState> {
    if worktree.is_empty() || !is_hex40(certified) {
        return None;
    }
    let lane = contained_path(root, worktree).ok()?;
    if !lane.is_dir() {
        return Some(crate::state::FixLegState {
            head: String::new(),
            delivered: false,
            lane: false,
        });
    }
    let head = git_read_stdout(&lane, &["rev-parse", "--verify", "HEAD"])?;
    if !is_hex40(&head) {
        return None;
    }
    // A clean `merge-base --is-ancestor` exit IS the answer (its stdout is
    // empty), so only the exit code is read here.
    let delivered = head != certified
        && git_read_stdout(&lane, &["merge-base", "--is-ancestor", certified, &head]).is_some();
    Some(crate::state::FixLegState {
        head,
        delivered,
        lane: true,
    })
}

/// One read-only `git` invocation in `cwd` (issue #256), through the SAME
/// bounded runner and allowlisted environment every other adapter read uses.
/// `Some(stdout)` only for a clean exit; every other outcome (a failure, a
/// deadline, an unresolvable checkout) is `None` — a read that could not be
/// taken is never a fact.
fn git_read_stdout(cwd: &Path, args: &[&str]) -> Option<String> {
    let env = adapter_environment();
    let owned: Vec<String> = args.iter().map(|arg| arg.to_string()).collect();
    let out = crate::process::run(ProcSpec {
        program: "git",
        args: &owned,
        env: &env,
        cwd: Some(cwd),
        timeout: crate::observe::ADAPTER_TIMEOUT,
    });
    out.status
        .exit_code()
        .filter(|code| *code == 0)
        .map(|_| out.stdout.trim().to_string())
}

/// The fix instruction ONE recorded review FAIL produces (issue #238): built
/// from the verdict the reviewer wrote — the certified head it reviewed, the
/// integration base, and the failing checks it named — never from a human
/// summary. The instruction states what the leg must do and what the engine
/// does NOT do for it.
fn fix_brief(
    inputs: &ReviewEvidenceInputs,
    leg: &ImplementerLeg,
    round: u32,
    bound: u32,
    failures: &[Val],
) -> String {
    let branch = match &leg.branch {
        Some(branch) => format!("the run's feature branch {branch:?}"),
        None => "the run's own feature branch".to_string(),
    };
    format!(
        "Automatic fix round {} of {}: the review of the certified head {} against integration \
         base {} recorded verdict \"fail\". The failures the reviewer recorded are: {}. Fix \
         exactly those, in this fix leg's own lane checkout {:?} (a checkout of the reviewed \
         head — do not amend or rewrite it). Commit your change and push it to {} so the \
         reviewed head moves: the engine records nothing on your behalf and only a moved head \
         is re-reviewed. Your role is {:?}.",
        round,
        bound,
        inputs.feature_head,
        inputs.integration_base,
        failures_clause(failures),
        leg.worktree,
        branch,
        leg.profile.key,
    )
}

/// Whether the recorded fix round's own lane checkout still EXISTS (issue
/// #276): the leg's state is where a repair is committed, so a round whose
/// lane is gone can hold no delivered head at all.
///
/// A record that names NO checkout (a row written before issue #256) is
/// reported PRESENT: the recorded material does not say the leg is gone, and
/// a round is never superseded on a guess. A checkout the lane root cannot
/// address is treated the same way, for the same reason.
fn fix_round_lane_present(ctx: &EffectContext<'_>, worktree: &str) -> bool {
    if worktree.is_empty() {
        return true;
    }
    contained_path(ctx.worktrees_root, worktree)
        .map(|lane| lane.is_dir())
        .unwrap_or(true)
}

/// Dispatch the run's fix round for ONE recorded review FAIL (issue #238):
/// resolve the run's own committed implementer leg, keep or create the fix
/// leg's lane at the certified head, start the leg through the same
/// role-bound adapter the rest of the spine uses, deliver the fix
/// instruction derived from the recorded verdict, and prove that delivery
/// before recording it.
///
/// Every step failure keeps its OWN code (`refusal.fix.lane` / `spawn` /
/// `prompt`) with the substrate's refusal in the message, so the FAIL
/// handoff's disposition is readable from the recorded attempt alone.
/// The bound is enforced BEFORE any effect: a run whose automatic rounds are
/// spent escalates with `refusal.fix.bound_exhausted`, whose message names
/// the failures — it never parks silently and never dispatches an unbounded
/// number of repair rounds.
fn dispatch_fix_round(
    ctx: &EffectContext<'_>,
    inputs: &ReviewEvidenceInputs,
    facts: &VerdictFacts,
    implementer: &crate::adapters::SessionHandle,
) -> Result<Val, EffectOutcome> {
    let Some(review_root) = ctx.review_root else {
        return Err(refusal(
            code::FIX_UNBOUND,
            "review_evidence has no daemon-owned review root to record the fix round in; a \
             presented plan declares its own review facts and dispatches no fix leg",
        ));
    };
    let failures = failing_checks(&facts.checks);
    let leg = run_implementer_leg(ctx)?;
    let issue = ctx.plan.issue_number as u64;
    let receipt_path = fix_round_receipt_path(review_root, implementer, ctx.step_id);
    if let Err(err) = std::fs::create_dir_all(review_root) {
        return Err(refusal(
            code::FIX_UNBOUND,
            format!(
                "the review root {:?} is not creatable: {err}",
                review_root.display()
            ),
        ));
    }
    let recorded = FixRoundReceipt::read(&receipt_path)?;
    // One fix round per certified head: re-dispatching the review step this
    // round was handed to REUSES it — the leg already carries the
    // instruction, and re-prompting it would burn the bound the workflow gave.
    //
    // Issue #276: the round is the leg's OWN running work only while that
    // leg's recorded lane checkout still exists. A round whose lane is gone
    // (the measured dead-lane shape: the leg's checkout was deleted, so the
    // leg carries no state and can never deliver from it) is SUPERSEDED —
    // the FAIL is handed to the next round of the same bound, whose lane is
    // created at the certified head and whose instruction is delivered to a
    // leg that can still work. A record that names no checkout (a row written
    // before issue #256) is never superseded: the leg cannot be observed to
    // be gone, and a round is never re-dispatched on a guess.
    if let Some(recorded) = &recorded
        && recorded.feature_head == inputs.feature_head
        && fix_round_lane_present(ctx, &recorded.worktree)
    {
        return Ok(recorded.to_doc(&failures, true));
    }
    let round = recorded
        .as_ref()
        .map(|recorded| recorded.round)
        .unwrap_or(0)
        + 1;
    if round > FIX_ROUNDS_MAX {
        return Err(refusal(
            code::FIX_BOUND_EXHAUSTED,
            format!(
                "the run's automatic fix-round bound ({FIX_ROUNDS_MAX}) is spent and the reviewed \
                 head {} still fails: {}. The item escalates to the human queue instead of \
                 parking silently",
                inputs.feature_head,
                failures_clause(&failures)
            ),
        ));
    }
    let leg_round = leg.round + round as u64;
    let relative = crate::lane::lane_checkout(issue, "implementer", leg_round);
    let lane = ensure_fix_lane(ctx, &relative, &inputs.feature_head)?;
    let session = fix_session_handle(implementer, leg_round)?;
    let names = crate::adapters::LaneNames::new(issue, "implementer", leg_round)
        .map_err(|err| refusal(err.code, err.message))?;
    let mut profile = leg.profile.clone();
    profile.lane_names = Some(names.clone());
    let deadline = effect_deadline_secs(ctx.kind, ctx.params)?;
    // Start (create or reuse) the fix leg through the substrate the run's own
    // leg declared. Its refusal is the fix round's own spawn refusal.
    let start = crate::adapters::OpRequest {
        op: crate::adapters::Op::Start,
        session: &session,
        payload: None,
        timeout: Duration::from_secs(deadline),
    };
    let started = crate::adapters::execute_op_in_worktree(&profile, &start, ctx.env, &lane);
    if started.status != "succeeded" {
        return Err(EffectOutcome {
            status: started.status,
            code: Some(code::FIX_SPAWN.to_string()),
            message: Some(format!(
                "the fix round's leg could not be started ({}): {}",
                started.code.unwrap_or(""),
                started.message.unwrap_or_default()
            )),
            result: null(),
        });
    }
    // Deliver the instruction the recorded verdict produced. A prompt the
    // substrate did not take is the fix round's own prompt refusal — never a
    // silent park and never a counted round.
    let brief = fix_brief(inputs, &leg, round, FIX_ROUNDS_MAX, &failures);
    let prompt = crate::adapters::OpRequest {
        op: crate::adapters::Op::Prompt,
        session: &session,
        payload: Some(&brief),
        timeout: Duration::from_secs(deadline),
    };
    let delivered = crate::adapters::execute_op_in_worktree(&profile, &prompt, ctx.env, &lane);
    if delivered.status != "succeeded" {
        return Err(EffectOutcome {
            status: delivered.status,
            code: Some(code::FIX_PROMPT.to_string()),
            message: Some(format!(
                "the fix round's instruction was not delivered to lane {:?} ({}): {}",
                session.session_id,
                delivered.code.unwrap_or(""),
                delivered.message.unwrap_or_default()
            )),
            result: null(),
        });
    }
    let payload = delivered.payload.clone().unwrap_or_else(null);
    let receipt = FixRoundReceipt {
        round,
        bound: FIX_ROUNDS_MAX,
        feature_head: inputs.feature_head.clone(),
        lane: session.session_id.clone(),
        agent: payload
            .get("agent")
            .and_then(Val::as_str)
            .unwrap_or_default()
            .to_string(),
        workspace: names.workspace.clone(),
        pane: payload
            .get("pane")
            .and_then(Val::as_str)
            .unwrap_or_default()
            .to_string(),
        // Issue #256: the lane checkout the leg's OWN state lives in — the
        // same derived path the leg was created/verified at, recorded so a
        // later read can see the head the leg delivered.
        worktree: relative.clone(),
        delivery_attempts: payload.get("attempts").and_then(Val::as_int).unwrap_or(1),
    };
    receipt.write(&receipt_path, &failures)?;
    Ok(receipt.to_doc(&failures, false))
}

/// Start the run's own reviewer through the role-bound pane adapter and
/// consume the verdict it writes (issue #193).
fn review_self_dispatch(
    ctx: &EffectContext<'_>,
    inputs: &ReviewEvidenceInputs,
    leg: &ReviewerLeg,
) -> EffectOutcome {
    // The run's own bound implementer session is the identity the reviewer
    // must be distinct from, and the anchor the reviewer identity derives
    // from. A run that bound none has no implementer to review: refused.
    let Some(implementer) = ctx.session else {
        return refusal(
            code::SESSION_UNBOUND,
            "review_evidence dispatches the run's own reviewer, and this run bound no \
             implementer session (harness_start); the reviewer identity is never invented",
        );
    };
    // Issue #210: the reviewer's lane is its OWN checkout on the pane
    // substrate. The bare-subprocess fallback runs in the integration checkout
    // and keeps the plan's lane checkout as its evidence anchor, byte for
    // byte; the pane lane is materialized below, after the reviewer identity
    // is derived and validated.
    let headless_lane = match leg.execution {
        crate::adapters::ExecutionMode::Headless => {
            let worktree = match contained_path(ctx.worktrees_root, &leg.worktree) {
                Ok(path) => path,
                Err(err) => return refusal(err.code, err.message),
            };
            if !worktree.is_dir() {
                return refusal(
                    code::OUTPUT_LOCATION,
                    format!(
                        "review_evidence binds the lane worktree {:?}, which is not a directory",
                        leg.worktree
                    ),
                );
            }
            // The lane checkout must BE the certified head: a reviewer is never
            // started on a moved checkout, so the reviewed sha cannot drift.
            let head = match run_git(ctx, &worktree, &["rev-parse", "--verify", "HEAD"]) {
                Ok(out) => out.stdout.trim().to_string(),
                Err(outcome) => return outcome,
            };
            if head != inputs.feature_head {
                return refusal(
                    code::VERDICT_STALE,
                    format!(
                        "the run's lane checkout is at {head}, not the certified reviewed head {}; a \
                         reviewer is never started on a moved head",
                        inputs.feature_head
                    ),
                );
            }
            Some(worktree)
        }
        crate::adapters::ExecutionMode::HerdrPane => None,
    };
    let reviewer = match reviewer_session_handle(implementer, leg.round) {
        Ok(session) => session,
        Err(outcome) => return outcome,
    };
    if reviewer.session_id == implementer.session_id {
        return refusal(
            code::REVIEWER_NOT_DISTINCT,
            "the derived reviewer session is the implementer's own session; refusing to \
             dispatch a review to the identity under review",
        );
    }
    let names = match crate::adapters::LaneNames::new(
        ctx.plan.issue_number as u64,
        "reviewer",
        leg.round,
    ) {
        Ok(names) => names,
        Err(err) => return refusal(err.code, err.message),
    };
    if let Err(err) = check_reviewer_distinct(&names.agent, &implementer.session_id) {
        return refusal(err.code, err.message);
    }
    // The profile is the REGISTRY-resolved reviewer binding the reviewed plan
    // bound (never a code literal, never a default): the kind/executable come
    // from the step's declared role inputs, the intended provider/model from
    // the binding document the fleet registry resolved.
    let built = match crate::adapters::official_spec(leg.parsed_kind) {
        Some(_) => crate::adapters::Profile::official(leg.parsed_kind, &leg.key),
        None => crate::adapters::Profile::argv(
            &leg.key,
            &leg.executable,
            &crate::adapters::HARNESS_CAPS,
            BTreeMap::new(),
        ),
    };
    let mut profile = match built {
        Ok(profile) => profile,
        Err(err) => return refusal(err.code, err.message),
    };
    profile = match profile.with_binding(&leg.profile.provider, &leg.profile.model) {
        Ok(profile) => profile,
        Err(err) => return refusal(err.code, err.message),
    };
    profile = profile.with_execution(leg.execution);
    if leg.execution == crate::adapters::ExecutionMode::HerdrPane {
        profile.lane_names = Some(names.clone());
    }
    let mut retired_reviewer_lanes: Vec<Val> = Vec::new();
    let mut lane_registration: Option<Val> = None;
    let worktree = match headless_lane {
        Some(worktree) => worktree,
        None => {
            match ensure_reviewer_lane(ctx, leg, &inputs.feature_head, &mut retired_reviewer_lanes)
            {
                Ok((lane, registration)) => {
                    lane_registration = registration;
                    lane
                }
                Err(mut outcome) => {
                    // A reclaim that already happened is recorded on the failed
                    // outcome too, exactly as the pane bind records its own
                    // pre-bind retire (issue #190).
                    if !retired_reviewer_lanes.is_empty() {
                        let note = retire_note(&retired_reviewer_lanes);
                        outcome.message = Some(match outcome.message {
                            Some(message) => format!("{message}; {note}"),
                            None => note,
                        });
                    }
                    return outcome;
                }
            }
        }
    };
    let deadline = match effect_deadline_secs(ctx.kind, ctx.params) {
        Ok(secs) => secs,
        Err(outcome) => return outcome,
    };
    let cwd = match leg.execution {
        crate::adapters::ExecutionMode::Headless => ctx.integration_repo.to_path_buf(),
        crate::adapters::ExecutionMode::HerdrPane => worktree.clone(),
    };
    let request = crate::adapters::OpRequest {
        op: crate::adapters::Op::Start,
        session: &reviewer,
        payload: None,
        timeout: Duration::from_secs(deadline),
    };
    let started = crate::adapters::execute_op_in_worktree(&profile, &request, ctx.env, &cwd);
    if started.status != "succeeded" {
        return EffectOutcome {
            status: started.status,
            code: started.code.map(str::to_string),
            message: started.message,
            result: null(),
        };
    }
    // The verdict artifact is written by the REVIEWER, never by the engine:
    // any residue at the verdict path is cleared before a prompt, so a stale
    // verdict can never be consumed as this round's evidence. Beside it the
    // engine keeps its OWN delivery record (issue #214) — the one durable
    // fact that tells a re-dispatch this leg already carries the brief.
    let review_root = match ctx.review_root {
        Some(root) => root,
        None => {
            return refusal(
                code::REVIEWER_UNBOUND,
                "review_evidence has no daemon-owned review root to consume the reviewer's \
                 written verdict from; a presented plan declares its review facts itself",
            );
        }
    };
    let verdict_path = review_verdict_path(review_root, implementer, ctx.step_id);
    let receipt_path = review_delivery_receipt_path(review_root, implementer, ctx.step_id);
    if let Err(err) = std::fs::create_dir_all(review_root) {
        return refusal(
            code::REVIEWER_UNBOUND,
            format!(
                "the review root {:?} is not creatable: {err}",
                review_root.display()
            ),
        );
    }
    let recorded = match ReviewDelivery::read(&receipt_path) {
        Ok(recorded) => recorded,
        Err(outcome) => return outcome,
    };
    // A PROVEN delivery recorded for THIS certified head and THIS reviewer
    // lane, on a lane this dispatch REUSED, IS the leg that is already
    // running the review: the delivery discipline is satisfied by that
    // proof, and re-delivering would both throw away the turn the reviewer
    // is running and — whenever an in-flight turn cannot take a second
    // submission inside the bounded delivery window — report the PROMPTED
    // leg as `refusal.prompt.undelivered` (the measured p6-132 sequence:
    // `effect.review_timeout`, then two `refusal.prompt.undelivered`, while
    // the reviewer was working). The bare-subprocess substrate has no
    // asynchronous leg — its prompt IS the reviewer's run — so it always
    // re-delivers, unchanged.
    let (delivery, resumed) = match (leg.execution, recorded) {
        (crate::adapters::ExecutionMode::HerdrPane, Some(recorded))
            if started_lane_reused(&started)
                && recorded.matches(&inputs.feature_head, &reviewer.session_id) =>
        {
            (recorded, true)
        }
        _ => {
            match std::fs::remove_file(&verdict_path) {
                Ok(()) => {}
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => {
                    return refusal(
                        code::REVIEWER_UNBOUND,
                        format!(
                            "the verdict path {:?} carries residue that cannot be cleared: {err}",
                            verdict_path.display()
                        ),
                    );
                }
            }
            let payload = review_brief(inputs, leg, &verdict_path);
            let request = crate::adapters::OpRequest {
                op: crate::adapters::Op::Prompt,
                session: &reviewer,
                payload: Some(&payload),
                timeout: Duration::from_secs(deadline),
            };
            let delivered =
                crate::adapters::execute_op_in_worktree(&profile, &request, ctx.env, &cwd);
            if delivered.status != "succeeded" {
                return EffectOutcome {
                    status: delivered.status,
                    code: delivered.code.map(str::to_string),
                    message: delivered.message,
                    result: null(),
                };
            }
            // The delivered leg's own verified identity — the agent, the
            // pane and the submission attempts the adapter proved — is the
            // record a re-dispatch reads back. Only the pane substrate has a
            // leg to resume; the bare-subprocess substrate never reads it.
            let recorded = ReviewDelivery {
                feature_head: inputs.feature_head.clone(),
                reviewer_lane: reviewer.session_id.clone(),
                reviewer_agent: delivered
                    .payload
                    .as_ref()
                    .and_then(|payload| payload.get("agent"))
                    .and_then(Val::as_str)
                    .unwrap_or_default()
                    .to_string(),
                pane: delivered
                    .payload
                    .as_ref()
                    .and_then(|payload| payload.get("pane"))
                    .and_then(Val::as_str)
                    .unwrap_or_default()
                    .to_string(),
                delivery_attempts: delivered
                    .payload
                    .as_ref()
                    .and_then(|payload| payload.get("attempts"))
                    .and_then(Val::as_int)
                    .unwrap_or(1),
            };
            if leg.execution == crate::adapters::ExecutionMode::HerdrPane
                && let Err(outcome) = recorded.write(&receipt_path)
            {
                return outcome;
            }
            (recorded, false)
        }
    };
    // Issue #217: the wait this attempt opens for the verdict. A RESUMED
    // attempt (this step's own proven delivery, this head, this lane) renews
    // it under the documented overall ceiling — the reviewer is the one doing
    // the waiting-work by then — while a fresh attempt waits the step's
    // effective bound and a plan that declared its own `deadline_secs` keeps
    // its reviewed policy either way.
    let declared = ctx
        .params
        .is_some_and(|params| params.get("deadline_secs").is_some());
    let wait_secs = review_verdict_wait_secs(deadline, declared, resumed);
    let written = match await_written_verdict(
        &verdict_path,
        Duration::from_secs(wait_secs),
        &review_delivery_clause(&delivery, &leg.profile.model),
    ) {
        Ok(text) => text,
        Err(outcome) => return outcome,
    };
    // Issue #207 (b): the reviewed work is fenced for the WHOLE review window.
    // The lane checkout was AT the certified head when the reviewer started
    // (checked above); it must STILL be there now, before anything is
    // recorded. A commit that landed while the review was open moved the
    // content this run's verdict describes, so that verdict is never
    // consumed: the step refuses typed and the delivery must re-enter review
    // — a commit landing mid-review is never a silent consumption of a
    // delivery that moved under its own review, and the run's recorded
    // evidence can only ever name a head that was the branch for the whole
    // window.
    let settled = match run_git(ctx, &worktree, &["rev-parse", "--verify", "HEAD"]) {
        Ok(out) => out.stdout.trim().to_string(),
        Err(outcome) => return outcome,
    };
    if settled != inputs.feature_head {
        return refusal(
            code::VERDICT_STALE,
            format!(
                "the lane checkout moved from the reviewed head {} to {settled} while the \
                 review was open: the reviewed work is fenced for the whole review window, so \
                 a commit landing mid-review is never consumed; the delivery must re-enter \
                 review and a new review must name {settled}",
                inputs.feature_head
            ),
        );
    }
    let facts = match review_verdict_facts(&written, inputs) {
        Ok(facts) => facts,
        Err(outcome) => return outcome,
    };
    // The recorded reviewer identity is the adapter-verified lane identity
    // this dispatch started (never a caller-supplied string), and the
    // registry-resolved binding is recorded alongside it so the resolution is
    // auditable: key, kind, provider, model and the revision the plan bound.
    // On the pane substrate the reviewer's OWN lane (checkout, label, agent
    // and the reclaim/cleanup receipts) is recorded too (issue #210): the lane
    // exists FOR the review, so a consumed review removes it — a refused
    // removal is recorded verbatim and the residue stays reclaimable.
    //
    // Issue #214 observability: the outcome also names the reviewer's pane,
    // its SERVING model (the registry-resolved binding the reviewed plan
    // bound and the leg is launched with — the adapter read-backs carry no
    // model footer, so this is the recorded resolution, never an observation)
    // and the delivery attempt count of the PROVEN prompt delivery — so the
    // disposition of a stuck or resumed review leg is diagnosable from the
    // recorded step outcome without reading panes. A delivery recorded by an
    // EARLIER attempt of this step carries its own verified identity and
    // count forward (the resumed leg is never re-prompted).
    let reviewer_lane_cleanup = match leg.execution {
        crate::adapters::ExecutionMode::Headless => None,
        crate::adapters::ExecutionMode::HerdrPane => Some(remove_reviewer_lane(
            ctx,
            &reviewer,
            &worktree,
            Duration::from_secs(deadline),
        )),
    };
    // Issue #238: a recorded review FAIL is a normal, expected outcome of the
    // review step — never a terminal, silent one. The run's fix round is
    // dispatched HERE, in the effect that consumed the verdict, exactly the
    // way the reviewer leg was dispatched above: the fix leg's lane is created
    // (or reused) at the certified head, the fix instruction is derived from
    // the recorded verdict, and its delivery is proven before this outcome is
    // recorded. A refusal (no committed implementer leg, a spawn or prompt the
    // substrate did not take, an exhausted bound) returns the fix round's own
    // typed code, which the step attempt then carries to `run status` and
    // `supervision status`.
    let fix_round = match facts.verdict.as_str() {
        "fail" => match dispatch_fix_round(ctx, inputs, &facts, implementer) {
            Ok(doc) => doc,
            Err(outcome) => return outcome,
        },
        _ => null(),
    };
    ok(object(vec![
        ("repository", string(ctx.repository)),
        ("feature_head", string(&inputs.feature_head)),
        ("integration_base", string(&inputs.integration_base)),
        ("workflow_hash", string(&ctx.plan.workflow_hash)),
        ("verdict", string(&facts.verdict)),
        ("reviewer", string(&names.agent)),
        ("checks", facts.checks),
        ("reviewer_profile", leg.profile.to_doc()),
        ("reviewer_lane", string(&reviewer.session_id)),
        (
            "reviewer_pane",
            if delivery.pane.is_empty() {
                null()
            } else {
                string(&delivery.pane)
            },
        ),
        ("serving_model", string(&leg.profile.model)),
        ("delivery_attempts", integer(delivery.delivery_attempts)),
        ("reviewer_workspace", string(&names.workspace)),
        ("reviewer_worktree", string(&worktree.to_string_lossy())),
        ("verdict_path", string(&verdict_path.to_string_lossy())),
        ("retired_reviewer_lanes", Val::Arr(retired_reviewer_lanes)),
        ("stale_registration", lane_registration.unwrap_or_else(null)),
        (
            "reviewer_lane_cleanup",
            reviewer_lane_cleanup.unwrap_or_else(null),
        ),
        ("fix_round", fix_round),
    ]))
}

/// The facts ONE reviewer's written verdict carries, or a typed refusal
/// (issue #193). Nothing is defaulted, inferred or repaired here: the
/// document must be an `hf-evidence/v1` object that names THIS run's
/// certified head and every observed binding, with a closed verdict and a
/// non-empty check list whose statuses are explicit `passed`/`failed` — a
/// `pending` check is refused rather than recorded, because a pending check
/// permanently strands the tail (`refusal.run.step_done` blocks amendment and
/// `evidence_checks_passed()` requires every check `passed`).
struct VerdictFacts {
    verdict: String,
    checks: Val,
}

fn review_verdict_facts(
    text: &str,
    inputs: &ReviewEvidenceInputs,
) -> Result<VerdictFacts, EffectOutcome> {
    let doc = Val::parse_json(text).map_err(|err| {
        refusal(
            code::VERDICT_MALFORMED,
            format!("the reviewer's verdict is not JSON: {err}"),
        )
    })?;
    if !matches!(&doc, Val::Obj(_)) {
        return Err(refusal(
            code::VERDICT_MALFORMED,
            "the reviewer's verdict must be one JSON object",
        ));
    }
    const KEYS: [&str; 10] = [
        "schema",
        "evidence_id",
        "feature_head",
        "integration_base",
        "workflow_hash",
        "policy_hash",
        "verdict",
        "checks",
        "created_at",
        "reviewer",
    ];
    let fields = match &doc {
        Val::Obj(map) => map,
        _ => unreachable!("the verdict object was just matched as an object"),
    };
    if let Some(unknown) = fields.keys().find(|key| !KEYS.contains(&key.as_str())) {
        return Err(refusal(
            code::VERDICT_MALFORMED,
            format!("the reviewer's verdict carries unknown key {unknown:?} (closed surface)"),
        ));
    }
    match doc.get("schema").and_then(Val::as_str) {
        Some("hf-evidence/v1") => {}
        _ => {
            return Err(refusal(
                code::VERDICT_MALFORMED,
                "the reviewer's verdict schema must be \"hf-evidence/v1\"",
            ));
        }
    }
    // The reviewed head is the ONE binding the reviewer must name itself: a
    // verdict for any other sha is never this run's evidence. The other live
    // bindings (base/workflow/policy) are checked when the reviewer names
    // them, and the engine records its OWN live read-backs for them either
    // way — a reviewer can neither move them nor strand the tail with a
    // stale value.
    match doc.get("feature_head").and_then(Val::as_str) {
        Some(value) if value == inputs.feature_head => {}
        Some(value) => {
            return Err(refusal(
                code::VERDICT_STALE,
                format!(
                    "the reviewer's verdict names feature_head {value:?}, which is not this \
                     run's certified reviewed head {:?}",
                    inputs.feature_head
                ),
            ));
        }
        None => {
            return Err(refusal(
                code::VERDICT_MALFORMED,
                "the reviewer's verdict must name feature_head (the exact reviewed 40-hex sha)",
            ));
        }
    }
    if let Some(value) = doc.get("integration_base").and_then(Val::as_str)
        && value != inputs.integration_base
    {
        return Err(refusal(
            code::VERDICT_STALE,
            format!(
                "the reviewer's verdict names integration_base {value:?}, which is not this \
                 run's observed base {:?}",
                inputs.integration_base
            ),
        ));
    }
    for key in ["workflow_hash", "policy_hash"] {
        if let Some(value) = doc.get(key).and_then(Val::as_str)
            && !is_hex64(value)
        {
            return Err(refusal(
                code::VERDICT_MALFORMED,
                format!("the reviewer's verdict {key} must be 64-hex"),
            ));
        }
    }
    let verdict = match doc.get("verdict").and_then(Val::as_str) {
        Some(value @ ("pass" | "fail")) => value.to_string(),
        _ => {
            return Err(refusal(
                code::VERDICT_MALFORMED,
                "the reviewer's verdict must be pass|fail",
            ));
        }
    };
    let checks = match doc.get("checks") {
        Some(Val::Arr(items)) if !items.is_empty() => Val::Arr(items.clone()),
        _ => {
            return Err(refusal(
                code::VERDICT_MALFORMED,
                "the reviewer's verdict requires a non-empty checks list",
            ));
        }
    };
    let items = match &checks {
        Val::Arr(items) => items,
        _ => unreachable!("the checks value was just matched as a non-empty array"),
    };
    for item in items {
        match item.get("name").and_then(Val::as_str) {
            Some(name) if !name.is_empty() => {}
            _ => {
                return Err(refusal(
                    code::VERDICT_MALFORMED,
                    "every check of the reviewer's verdict needs a non-empty name",
                ));
            }
        }
        match item.get("status").and_then(Val::as_str) {
            Some("passed" | "failed") => {}
            Some("pending") => {
                return Err(refusal(
                    code::VERDICT_PENDING,
                    "the reviewer's verdict carries a `pending` check; a pending check can never \
                     be consumed as evidence (it strands the tail), so the frontier stays parked",
                ));
            }
            _ => {
                return Err(refusal(
                    code::VERDICT_MALFORMED,
                    "every check status of the reviewer's verdict must be passed|failed",
                ));
            }
        }
    }
    Ok(VerdictFacts { verdict, checks })
}

/// Wait, bounded, for the reviewer's OWN written verdict (issue #193). A
/// missing artifact at the deadline is the typed `effect.review_timeout`; an
/// artifact that is not yet PARSEABLE JSON is waited out rather than refused,
/// because a partially written file is indistinguishable from a malformed one
/// (the #186 lesson: publish-then-read must wait for parseable content).
///
/// The timeout outcome's message carries the delivery clause of the attempt
/// that reached this wait (issue #214): the reviewer lane, its pane, its
/// serving model and the submission attempts the PROVEN delivery took, plus
/// the fact that a re-dispatch re-checks this same leg instead of
/// re-delivering — a stuck review is diagnosable from the recorded outcome
/// alone (the durable `hf-outcome/v1` for an ambiguous effect drops the
/// `result`, so the message is where it must ride).
fn await_written_verdict(
    path: &Path,
    deadline: Duration,
    delivery: &str,
) -> Result<String, EffectOutcome> {
    let started = Instant::now();
    let interval = Duration::from_millis(50);
    loop {
        match std::fs::read_to_string(path) {
            Ok(text) => {
                if Val::parse_json(&text).is_ok() {
                    return Ok(text);
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(refusal(
                    code::VERDICT_MALFORMED,
                    format!(
                        "the reviewer's verdict artifact {:?} is unreadable: {err}",
                        path.display()
                    ),
                ));
            }
        }
        if started.elapsed() >= deadline {
            return Err(EffectOutcome {
                status: "ambiguous",
                code: Some(code::REVIEW_TIMEOUT.to_string()),
                message: Some(format!(
                    "the reviewer wrote no verdict at {:?} within {deadline:?}; {delivery}; \
                     nothing is synthesised",
                    path.display()
                )),
                result: null(),
            });
        }
        std::thread::sleep(interval.min(deadline.saturating_sub(started.elapsed())));
    }
}

/// The head of the integration branch **as published** on the integration
/// checkout's `origin` remote (`git ls-remote`) — never from the checkout's
/// own refs, which cannot see a bare-remote move (issue #132). An unreadable
/// or absent published ref refuses fail-closed: a merge that cannot prove the
/// published base must not land on it.
fn published_integration_head(ctx: &EffectContext<'_>) -> Result<String, EffectOutcome> {
    let out = match run_git(
        ctx,
        ctx.integration_repo,
        &[
            "ls-remote",
            "origin",
            &format!("refs/heads/{}", ctx.integration_branch),
        ],
    ) {
        Ok(out) => out,
        Err(outcome) => {
            // An `origin` the checkout cannot read at all (absent, unreachable,
            // unauthenticated) proves no base either, so it refuses this step's
            // own unprovable-base code — never a bare `adapter.exit` that reads
            // like an adapter fault (issue #132's review finding) — and keeps
            // the git read's diagnostics in the message. Ambiguous and
            // timed-out reads are NOT "not readable": they keep their own
            // outcomes untouched.
            if outcome.code.as_deref() != Some(code::EXIT) {
                return Err(outcome);
            }
            let detail = outcome
                .message
                .as_deref()
                .unwrap_or("the read failed without a message");
            return Err(failed(
                code::MERGE_FAILED,
                format!(
                    "the published integration ref {:?} is not readable from origin: {detail}",
                    ctx.integration_branch
                ),
            ));
        }
    };
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

/// Whether `ancestor` is an ancestor of (or equal to) `descendant` in the
/// integration repo. A git failure — an unresolvable object included — is
/// `false`: an unprovable ancestry is never a proof (fail closed).
fn is_commit_ancestor(ctx: &EffectContext<'_>, ancestor: &str, descendant: &str) -> bool {
    run_git(
        ctx,
        ctx.integration_repo,
        &["merge-base", "--is-ancestor", ancestor, descendant],
    )
    .is_ok()
}

/// The head of the published integration ref, FETCHED into the checkout's
/// remote-tracking ref and verified against the `ls-remote` read (issue
/// #178). A reconciliation may only merge against a view it has actually
/// fetched (issue #156): a fetch that cannot run, or a fetched head that
/// disagrees with the published read, refuses fail-closed.
fn fetched_published_head(
    ctx: &EffectContext<'_>,
    published_head: &str,
) -> Result<String, EffectOutcome> {
    let branch = ctx.integration_branch;
    let refspec = format!("+refs/heads/{branch}:refs/remotes/origin/{branch}");
    if let Err(outcome) = run_git(
        ctx,
        ctx.integration_repo,
        &["fetch", "--no-tags", "origin", &refspec],
    ) {
        if outcome.code.as_deref() != Some(code::EXIT) {
            return Err(outcome);
        }
        let detail = outcome
            .message
            .as_deref()
            .unwrap_or("the fetch failed without a message");
        return Err(failed(
            code::MERGE_FAILED,
            format!(
                "the published integration ref {branch:?} is not fetchable from origin: {detail}"
            ),
        ));
    }
    let fetched = run_git(
        ctx,
        ctx.integration_repo,
        &[
            "rev-parse",
            "--verify",
            &format!("refs/remotes/origin/{branch}"),
        ],
    )?
    .stdout
    .trim()
    .to_string();
    if fetched != published_head {
        return Err(failed(
            code::MERGE_FAILED,
            format!(
                "the published integration ref {branch:?} is not readable from origin: the fetched head {fetched} disagrees with the published head {published_head}"
            ),
        ));
    }
    Ok(fetched)
}

/// The landed integration head FETCHED into the integration checkout and
/// proven READABLE there before anything reads it (issue #224).
///
/// A forge landing happens on the REMOTE, so the commit object of the head the
/// read-back names is not in the integration checkout's object store until it
/// is fetched: the measured drive read it first and died on a bare
/// `adapter.exit`/128 (`fatal: bad object <landed-sha>`) — the merge action
/// and the verification of the merge action were not ordered against each
/// other, and the retry spent its budget on the same missing object. The fetch
/// is the same verified one the #178 reconciliation uses (the fetched head
/// must agree with the published read); the landed COMMIT is then proven
/// readable. A landed head the checkout still cannot read afterwards is this
/// step's own typed static condition — no re-dispatch fetches it any harder —
/// never the bare adapter exit the first read would produce.
fn fetched_landed_head(ctx: &EffectContext<'_>, landed: &str) -> Result<(), EffectOutcome> {
    // The fetch that brings the landed head in. It is the same verified fetch
    // the #178 reconciliation uses; a failure of ANY class that leaves the
    // landed head unreadable is re-stated as this step's own static condition
    // (naming the head) instead of a ref-shaped message an operator has to map
    // back to the landing.
    if let Err(outcome) = fetched_published_head(ctx, landed) {
        if outcome.code.as_deref() != Some(code::MERGE_FAILED) {
            return Err(outcome);
        }
        let detail = outcome
            .message
            .as_deref()
            .unwrap_or("the fetch failed without a message");
        return Err(failed(
            code::MERGE_STATIC,
            format!(
                "the landed integration head {landed} is not readable from the integration checkout {:?}: the fetch that brings it in from origin did not deliver it ({detail})",
                ctx.integration_repo.display()
            ),
        ));
    }
    let object = run_git(
        ctx,
        ctx.integration_repo,
        &["rev-parse", "--verify", &format!("{landed}^{{commit}}")],
    );
    match object {
        Ok(_) => Ok(()),
        Err(outcome) if outcome.code.as_deref() != Some(code::EXIT) => Err(outcome),
        Err(outcome) => {
            let detail = outcome
                .message
                .as_deref()
                .unwrap_or("the read failed without a message");
            Err(failed(
                code::MERGE_STATIC,
                format!(
                    "the landed integration head {landed} is not readable from the integration checkout {:?} after fetching it from origin: {detail}",
                    ctx.integration_repo.display()
                ),
            ))
        }
    }
}

/// The NUL-delimited paths that differ between two tree-ish in the
/// integration repo. The cleanup content proof's lossless-adapter rules
/// (issue #132) apply verbatim: a replacement character, a truncated NUL
/// stream or an empty path refuses instead of ever becoming a proof.
fn changed_paths_between(
    ctx: &EffectContext<'_>,
    from: &str,
    to: &str,
    refuse_code: &'static str,
) -> Result<Vec<String>, EffectOutcome> {
    let changed = run_git(
        ctx,
        ctx.integration_repo,
        &[
            "diff",
            "--name-only",
            "--no-renames",
            "--ignore-submodules=none",
            "-z",
            from,
            to,
            "--",
        ],
    )?;
    if changed.stdout.contains('\u{fffd}')
        || (!changed.stdout.is_empty() && !changed.stdout.ends_with('\0'))
    {
        return Err(refusal(
            refuse_code,
            "cannot compare changed paths losslessly; refusing an unverified proof",
        ));
    }
    let paths: Vec<String> = changed
        .stdout
        .split_terminator('\0')
        .map(str::to_string)
        .collect();
    if paths.iter().any(|path| path.is_empty()) {
        return Err(refusal(
            refuse_code,
            "the changed-path listing contains an empty path; refusing an unverified proof",
        ));
    }
    Ok(paths)
}

/// The subset of `paths` whose content differs between `a` and `b` in the
/// integration repo (`--literal-pathspecs`, so a path is never a pattern).
/// Empty means every named path is byte-identical there. An EMPTY path list
/// is independently confirmed against the whole diff, so a missing listing
/// can never become a vacuous proof.
fn differing_paths_between(
    ctx: &EffectContext<'_>,
    a: &str,
    b: &str,
    paths: &[String],
    refuse_code: &'static str,
) -> Result<Vec<String>, EffectOutcome> {
    if paths.is_empty() {
        run_git(
            ctx,
            ctx.integration_repo,
            &[
                "diff",
                "--quiet",
                "--no-ext-diff",
                "--no-textconv",
                "--ignore-submodules=none",
                a,
                b,
                "--",
            ],
        )?;
        return Ok(Vec::new());
    }
    let mut args: Vec<&str> = vec![
        "--literal-pathspecs",
        "diff",
        "--name-only",
        "--no-renames",
        "--ignore-submodules=none",
        "-z",
        a,
        b,
        "--",
    ];
    args.extend(paths.iter().map(String::as_str));
    let differing = run_git(ctx, ctx.integration_repo, &args)?;
    if differing.stdout.contains('\u{fffd}')
        || (!differing.stdout.is_empty() && !differing.stdout.ends_with('\0'))
    {
        return Err(refusal(
            refuse_code,
            "cannot compare changed paths losslessly; refusing an unverified proof",
        ));
    }
    Ok(differing
        .stdout
        .split_terminator('\0')
        .map(str::to_string)
        .collect())
}

/// The reviewed paths (`reviewed_base..certified`) and the subset of them whose
/// content is NOT identical between `certified` and `delivered` — the shared
/// fail-closed content fact of the squash landing (`delivered` = the merge
/// target), the reconciliation and the cleanup landed proof. An empty
/// `differing` means every path the review covered carries the certified
/// head's exact content in `delivered`.
fn certified_content_differences(
    ctx: &EffectContext<'_>,
    reviewed_base: &str,
    certified: &str,
    delivered: &str,
) -> Result<(Vec<String>, Vec<String>), EffectOutcome> {
    let paths = changed_paths_between(ctx, reviewed_base, certified, code::MERGE_FAILED)?;
    let differing = differing_paths_between(ctx, certified, delivered, &paths, code::MERGE_FAILED)?;
    Ok((paths, differing))
}

/// Prove the certified content survives in `delivered` (issue #178): every
/// path the review covered (`reviewed_base..certified`) must carry the
/// certified head's exact content. A dropped path, partial content or any
/// later divergence refuses — content is never merged that was not proven
/// against the ref it lands on.
fn prove_certified_content(
    ctx: &EffectContext<'_>,
    reviewed_base: &str,
    certified: &str,
    delivered: &str,
) -> Result<(), EffectOutcome> {
    let (paths, differing) =
        certified_content_differences(ctx, reviewed_base, certified, delivered)?;
    if !differing.is_empty() {
        return Err(failed(
            code::MERGE_FAILED,
            format!(
                "the delivered head {delivered} does not carry the certified content of {certified} on {} of the {} path(s) the review covered relative to {reviewed_base} (first {:?}); refusing to certify rewritten content",
                differing.len(),
                paths.len(),
                differing.first()
            ),
        ));
    }
    Ok(())
}

/// The worktree of the integration repo that has `branch` checked out — the
/// only place a reconciliation may run, and only when it is contained under
/// the lane root.
fn branch_worktree(ctx: &EffectContext<'_>, branch: &str) -> Result<PathBuf, EffectOutcome> {
    let listing = run_git(
        ctx,
        ctx.integration_repo,
        &["worktree", "list", "--porcelain"],
    )?;
    let wanted = format!("refs/heads/{branch}");
    let mut current: Option<String> = None;
    let mut found: Option<String> = None;
    for line in listing.stdout.lines() {
        if let Some(path) = line.strip_prefix("worktree ") {
            current = Some(path.trim().to_string());
        } else if let Some(head) = line.strip_prefix("branch ")
            && head.trim() == wanted
        {
            found = current.clone();
        }
    }
    let Some(path) = found else {
        return Err(failed(
            code::MERGE_STATIC,
            format!(
                "feature branch {branch:?} has no worktree in the integration checkout; a reconciliation refuses to rewrite a branch it cannot check out (a delivery whose reviewed content already landed on the published ref is certified without a worktree — this one is not there yet, so no re-dispatch can refresh it)"
            ),
        ));
    };
    let worktree = PathBuf::from(path);
    // The lane worktree must be strictly inside the presented lane root
    // (canonicalized, so a symlinked temp root cannot hide an escape).
    if !is_contained(ctx.worktrees_root, &worktree) {
        return Err(failed(
            code::MERGE_FAILED,
            format!(
                "the worktree of feature branch {branch:?} ({}) is outside the lane root; refusing to rewrite it",
                worktree.display()
            ),
        ));
    }
    Ok(worktree)
}

/// The typed BASE MOVE refusal (issue #263): the published integration ref
/// moved past the reviewed base and the certified content cannot be refreshed
/// onto it — the replay does not apply cleanly, or it rewrites content the
/// review covered. Refreshed content that was never reviewed is never left
/// behind as the delivery and never consumed, and a run cannot resolve a base
/// move by itself (a re-dispatch refuses identically), so it is this step's
/// OWN typed condition naming the reviewed base, the published head and the
/// remedy: supervision parks the frontier on it with the bounded retries
/// UNSPENT, never spending the budget on a condition the run cannot resolve.
fn base_moved_refusal(
    reviewed_base: &str,
    target: &str,
    branch: &str,
    head: &str,
    reason: &str,
) -> EffectOutcome {
    refusal(
        code::MERGE_BASE_MOVED,
        format!(
            "the published integration ref {target} moved past the reviewed base {reviewed_base} and the certified content of {branch:?} (head {head}) cannot be refreshed onto it: {reason}; the refreshed content was never reviewed, so the delivery was left at {head} and nothing was published — it must be refreshed under a fresh review, and a new verdict must name the refreshed head, before any step consumes it"
        ),
    )
}

/// Withdraw a reconciliation that could not be proven to carry the certified
/// content (issue #263): content that was never reviewed must never be left
/// where a later step (or a publish route) could consume it as the delivery,
/// and the delivery branch is left at the exact head its verdict names.
/// Best-effort, exactly like the conflicted-rebase abort: the refusal is not.
fn withdraw_reconcile(ctx: &EffectContext<'_>, branch: &str, head: &str) {
    if let Ok(worktree) = branch_worktree(ctx, branch) {
        let _ = run_git(ctx, &worktree, &["reset", "--hard", head]);
    }
}

/// Reconcile the certified delivery onto the fetched published head (issue
/// #178): replay exactly the delivered commits (`upstream..delivered`) onto
/// `target` in the branch's own worktree, then prove the certified content
/// survived byte-identically. Fails closed: a conflict, a dirty worktree or a
/// content divergence refuses and never leaves a partial rewrite behind. A
/// replay that cannot be carried out at all is the SAME base move as a replay
/// that rewrites reviewed content (`effect.merge.base_moved`, issue #263):
/// the delivery is left where the review left it and the run is parked on the
/// condition instead of spending its bounded retries on it.
fn reconcile_onto_published(
    ctx: &EffectContext<'_>,
    branch: &str,
    target: &str,
    upstream: &str,
    reviewed_base: &str,
    head: &str,
) -> Result<String, EffectOutcome> {
    let worktree = branch_worktree(ctx, branch)?;
    if let Err(outcome) = run_git(ctx, &worktree, &["rebase", "--onto", target, upstream]) {
        // Never leave a conflicted rebase behind: abort before refusing (the
        // abort is best-effort; the refusal is not).
        let _ = run_git(ctx, &worktree, &["rebase", "--abort"]);
        if outcome.code.as_deref() != Some(code::EXIT) {
            return Err(outcome);
        }
        let detail = outcome
            .message
            .as_deref()
            .unwrap_or("the rebase failed without a message");
        return Err(base_moved_refusal(
            reviewed_base,
            target,
            branch,
            head,
            &format!("the delivery's own commits do not replay cleanly onto it ({detail})"),
        ));
    }
    let reconciled = run_git(ctx, &worktree, &["rev-parse", "--verify", "HEAD"])?
        .stdout
        .trim()
        .to_string();
    if !is_hex40(&reconciled) || !is_commit_ancestor(ctx, target, &reconciled) {
        return Err(failed(
            code::MERGE_FAILED,
            format!(
                "the reconciled head {reconciled} does not descend from the published integration ref {target}; refusing an unverified reconciliation"
            ),
        ));
    }
    Ok(reconciled)
}

/// Certify a delivery against the FETCHED published ref once that ref moved
/// beyond the reviewed base while the run was in flight (issue #178).
///
/// `Ok(())` when the delivery is already certifiable against `target`: it
/// contains the published head, and — when the delivery is a reconciliation
/// rather than the exact certified head — its certified content is proven
/// present. A delivery still behind the published ref is reconciled in place
/// and reported as the bounded `refusal.run.retry_required` this step's own
/// next attempt re-certifies — never as a terminal failure. A published ref
/// that moves again between those attempts is reconciled again (the same
/// bounded loop), never merged unproven. A delivery the moved ref CANNOT
/// carry byte-identically (the replay conflicts, or it rewrites paths the
/// review covered) is the typed `effect.merge.base_moved` (issue #263): the
/// refresh is withdrawn, the delivery is left at the head its verdict names,
/// and the run is parked on the condition with its bounded retries UNSPENT
/// instead of spending them on a base move it can never resolve by itself.
fn reconcile_moved_published(
    ctx: &EffectContext<'_>,
    inputs: &MergeInputs,
    target: &str,
    reviewed_base: &str,
) -> Result<(), EffectOutcome> {
    let certified = ctx.observed_feature_head.unwrap_or_default();
    if !is_hex40(certified) {
        return Err(refusal(
            code::BAD_PARAMS,
            "merge requires observed.feature_head (the exact reviewed head) to reconcile a published ref that moved",
        ));
    }
    if !is_hex40(reviewed_base) {
        return Err(refusal(
            code::BAD_PARAMS,
            "merge requires observed.integration_base (the reviewed base) to reconcile a published ref that moved",
        ));
    }
    if !is_commit_ancestor(ctx, reviewed_base, certified) {
        return Err(failed(
            code::MERGE_FAILED,
            format!(
                "the certified head {certified} does not descend from the reviewed base {reviewed_base}; refusing to reconcile content that was never reviewed against it"
            ),
        ));
    }
    // Issue #224 (AC2/AC3): a delivery whose reviewed content ALREADY IS on
    // the published ref has landed. A squash landing rewrites the delivered
    // commits, so ancestry can never prove it, and the reconciliation below
    // would want to REWRITE a branch whose worktree a lane retirement may
    // legitimately have removed. The landing is therefore proven from the
    // published ref and the commit objects alone — every path the review
    // covered (`reviewed_base..certified`) carries the certified head's exact
    // content on `target` — which needs neither the delivery branch's ref nor
    // its worktree, and re-entry records success instead of attempting a
    // reconciliation. A delivery whose content is NOT (fully) on the target
    // still takes the reconciliation below, unchanged.
    if certified_content_differences(ctx, reviewed_base, certified, target)?
        .1
        .is_empty()
    {
        return Ok(());
    }
    let branch_head = run_git(
        ctx,
        ctx.integration_repo,
        &["rev-parse", "--verify", &inputs.branch],
    )?
    .stdout
    .trim()
    .to_string();
    if is_commit_ancestor(ctx, target, &branch_head) {
        // The delivery already contains the published ref. The exact certified
        // head certifies as-is; a reconciled (rewritten) delivery must prove
        // its certified content survived.
        if branch_head != certified {
            return prove_certified_content(ctx, reviewed_base, certified, &branch_head);
        }
        return Ok(());
    }
    // Still behind the (possibly moved-again) published ref: replay the
    // delivery's own commits onto the fetched published head.
    let fork = match run_git(
        ctx,
        ctx.integration_repo,
        &["merge-base", &branch_head, target],
    ) {
        Ok(out) => out.stdout.trim().to_string(),
        Err(_) => {
            return Err(failed(
                code::MERGE_FAILED,
                format!(
                    "feature branch {:?} head {branch_head} shares no fork point with the published ref {target}; refusing to reconcile unrelated histories",
                    inputs.branch
                ),
            ));
        }
    };
    if !is_hex40(&fork) {
        return Err(failed(
            code::MERGE_FAILED,
            format!(
                "feature branch {:?} head {branch_head} shares no provable fork point with the published ref {target}",
                inputs.branch
            ),
        ));
    }
    let reconciled = reconcile_onto_published(
        ctx,
        &inputs.branch,
        target,
        &fork,
        reviewed_base,
        &branch_head,
    )?;
    // Issue #263: content that was never reviewed is never consumed. A replay
    // that rewrites reviewed content cannot be certified against the stale
    // certified head, and the run cannot resolve that by itself, so the
    // refresh is WITHDRAWN (the delivery is left at the exact head its
    // verdict names) and the step reports the typed base-move park — never a
    // terminal `effect.merge.failed` that spends the bounded retries on a
    // condition no re-dispatch can repair.
    match certified_content_differences(ctx, reviewed_base, certified, &reconciled) {
        Ok((_, differing)) if differing.is_empty() => {}
        Ok((paths, differing)) => {
            withdraw_reconcile(ctx, &inputs.branch, &branch_head);
            return Err(base_moved_refusal(
                reviewed_base,
                target,
                &inputs.branch,
                &branch_head,
                &format!(
                    "replaying the delivery's own commits onto it rewrites {} of the {} path(s) the review covered relative to {reviewed_base} (first {:?})",
                    differing.len(),
                    paths.len(),
                    differing.first()
                ),
            ));
        }
        Err(outcome) => {
            // The refreshed content could not even be PROVEN: the rewrite is
            // withdrawn and the unprovable refresh fails closed.
            withdraw_reconcile(ctx, &inputs.branch, &branch_head);
            return Err(outcome);
        }
    }
    Err(refusal(
        code::RETRY_REQUIRED,
        format!(
            "the certified delivery {:?} is behind the published integration ref {target}: head {branch_head} was reconciled onto it (new head {reconciled}); the reconciled head is re-certified by this step's bounded retry against the fetched published ref",
            inputs.branch
        ),
    ))
}

/// Write the SQUASH landing commit of a certified delivery: ONE integration
/// commit whose tree is the delivered tree — the delivery contains the merge
/// target, so its tree is exactly the target's tree plus the delivered delta —
/// and whose parent is the merge target. The delivered commits are rewritten,
/// which is what the repository's squash policy states and why a squash
/// landing is never an ancestor of the delivery. The commit uses the daemon's
/// own deterministic identity: the landing is a control-plane mutation and
/// never depends on the host's git configuration.
fn squash_landing_commit(
    ctx: &EffectContext<'_>,
    inputs: &MergeInputs,
    tree: &str,
    target: &str,
    certified: &str,
) -> Result<String, EffectOutcome> {
    let mut message = format!(
        "squash the certified delivery {} onto {} (certified head {})",
        inputs.branch, ctx.integration_branch, certified
    );
    if ctx.plan.issue_number > 0 {
        message.push_str(&format!("\n\nRefs #{}", ctx.plan.issue_number));
    }
    let out = run_git(
        ctx,
        ctx.integration_repo,
        &[
            "-c",
            "user.name=canter",
            "-c",
            "user.email=canter@localhost",
            "commit-tree",
            tree,
            "-p",
            target,
            "-m",
            &message,
        ],
    )?;
    let head = out.stdout.trim().to_string();
    if !is_hex40(&head) {
        return Err(failed(
            code::MERGE_FAILED,
            format!("the squash landing commit could not be created (git reported {head:?})"),
        ));
    }
    Ok(head)
}

/// Roll the integration checkout back to the published merge target after a
/// landing the published ref does not carry. The local move must never be left
/// behind: on the next attempt it would read as an unpublished local move
/// (issue #156). The rollback is `reset --keep`, which aborts rather than
/// discard operator work; by construction no operator change overlaps the
/// landing delta (the fast-forward that preceded it succeeded).
fn roll_back_landing(ctx: &EffectContext<'_>, target: &str) -> Result<(), String> {
    match run_git(ctx, ctx.integration_repo, &["reset", "--keep", target]) {
        Ok(_) => Ok(()),
        Err(outcome) => Err(outcome.message.unwrap_or_else(|| {
            format!("the checkout rollback to the published head {target} failed")
        })),
    }
}

/// Classify a failed PUBLISH (a `git push` of a landing, or a forge call that
/// refuses a merge) into its own typed code (issue #219).
///
/// The raw diagnostics stay in the message either way; the code names the
/// CLASS so an operator can tell a rules refusal from a credential problem
/// from an unclassifiable local failure without reading stderr. `default` is
/// the caller's own code for the genuinely unclassifiable case.
fn classify_publish_failure(text: &str, default: &'static str) -> &'static str {
    let lowered = text.to_ascii_lowercase();
    // Credential first: an authentication failure is never reported as a
    // policy refusal, and a forge's auth error carries no rule marker.
    const CREDENTIAL_MARKERS: [&str; 8] = [
        "authentication failed",
        "could not read username",
        "could not read password",
        "permission denied (publickey",
        "terminal prompts disabled",
        "bad credentials",
        "no such identity",
        "gh_auth_token",
    ];
    if CREDENTIAL_MARKERS
        .iter()
        .any(|marker| lowered.contains(marker))
    {
        return code::CREDENTIAL_MISSING;
    }
    // The remote REFUSED the update: repository rules or a protected ref.
    // The markers are the ones a REFUSAL prints — a plain `[remote rejected]`
    // also covers a receiving-side failure that is not a policy refusal (a
    // read-only remote's `unpacker error`), and that case keeps the caller's
    // generic code rather than being reported as a rule refusal.
    const REJECTED_MARKERS: [&str; 6] = [
        "push declined",
        "repository rule violations",
        "gh013",
        "protected branch hook declined",
        "pre-receive hook declined",
        "refusing to allow",
    ];
    if REJECTED_MARKERS
        .iter()
        .any(|marker| lowered.contains(marker))
    {
        return code::MERGE_PUSH_REJECTED;
    }
    // The ref moved under us: the landing is not a fast-forward of the
    // published head any more.
    const NOT_FF_MARKERS: [&str; 2] = ["non-fast-forward", "fetch first"];
    if NOT_FF_MARKERS.iter().any(|marker| lowered.contains(marker)) {
        return code::MERGE_NOT_FF;
    }
    default
}

/// Run the forge CLI (`gh`) in the integration checkout. A non-zero exit is
/// classified by [`classify_publish_failure`] against `default` — never
/// collapsed into a bare adapter code — while spawn failures, deadlines and
/// process deaths keep their own outcomes untouched.
fn run_forge(
    ctx: &EffectContext<'_>,
    args: &[String],
    default: &'static str,
) -> Result<crate::process::ProcOut, EffectOutcome> {
    let deadline = effect_deadline_secs(ctx.kind, ctx.params)?;
    let out = crate::adapters::run_grouped(ProcSpec {
        program: "gh",
        args,
        env: ctx.env,
        cwd: Some(ctx.integration_repo),
        timeout: Duration::from_secs(deadline),
    });
    if let Err(outcome) = outcome_from_run(&out, "gh") {
        if outcome.code.as_deref() != Some(code::EXIT) {
            return Err(outcome);
        }
        let detail = outcome.message.unwrap_or_default();
        return Err(failed(classify_publish_failure(&detail, default), detail));
    }
    Ok(out)
}

/// The OPEN pull request that IS one delivery: the forge's own answer for
/// `gh pr list --head <delivery branch> --base <integration ref> --state
/// open`. `Ok(None)` when the forge reports none; a forge answer that is not
/// the documented JSON refuses `refusal.malformed.output` rather than being
/// guessed at.
fn open_pull_request(
    ctx: &EffectContext<'_>,
    inputs: &MergeInputs,
) -> Result<Option<(i64, String)>, EffectOutcome> {
    let args = vec![
        "pr".to_string(),
        "list".to_string(),
        "--repo".to_string(),
        ctx.repository.to_string(),
        "--head".to_string(),
        inputs.branch.clone(),
        "--base".to_string(),
        ctx.integration_branch.to_string(),
        "--state".to_string(),
        "open".to_string(),
        "--json".to_string(),
        "number,headRefOid".to_string(),
    ];
    let out = run_forge(ctx, &args, code::MERGE_PUBLISH_REJECTED)?;
    let text = crate::redact::redact(out.stdout.trim()).to_string();
    let unreadable = |detail: &str| {
        failed(
            code::MALFORMED_OUTPUT,
            format!(
                "the forge's pull-request read is not the documented JSON (`gh pr list --json number,headRefOid`): {detail}"
            ),
        )
    };
    let doc = match Val::parse_json(&text) {
        Ok(doc) => doc,
        Err(_) => return Err(unreadable(&text)),
    };
    let Some(items) = doc.as_array() else {
        return Err(unreadable(&text));
    };
    let Some(first) = items.first() else {
        return Ok(None);
    };
    let number = first.get("number").and_then(Val::as_int).unwrap_or(0);
    let head = first
        .get("headRefOid")
        .and_then(Val::as_str)
        .unwrap_or("")
        .to_string();
    if number <= 0 || !is_hex40(&head) {
        return Err(unreadable(&format!("{first:?}")));
    }
    Ok(Some((number, head)))
}

/// The tree of one tree-ish in the integration repo.
fn tree_of(ctx: &EffectContext<'_>, rev: &str) -> Result<String, EffectOutcome> {
    Ok(run_git(
        ctx,
        ctx.integration_repo,
        &["rev-parse", "--verify", &format!("{rev}^{{tree}}")],
    )?
    .stdout
    .trim()
    .to_string())
}

/// Fast-forward the integration checkout onto a PUBLISHED integration head
/// (issue #219). The run's later steps (`post_merge_verify`, `cleanup`) read
/// the LOCAL integration ref, so a checkout left behind a head the forge
/// published would present a stale view. Only a fast-forward is performed —
/// never a rewrite, never a forced update — and the fetched head is verified
/// against the published read first (the same #178 rule: a reconciliation may
/// only use a view it actually fetched).
fn advance_checkout_to_published(
    ctx: &EffectContext<'_>,
    published: &str,
) -> Result<(), EffectOutcome> {
    let checkout_head = run_git(
        ctx,
        ctx.integration_repo,
        &["rev-parse", "--verify", ctx.integration_branch],
    )?
    .stdout
    .trim()
    .to_string();
    if checkout_head == published {
        return Ok(());
    }
    let fetched = fetched_published_head(ctx, published)?;
    if !is_commit_ancestor(ctx, &checkout_head, &fetched) {
        return Err(failed(
            code::MERGE_NOT_FF,
            format!(
                "the integration checkout is at {checkout_head}, which does not descend from the published integration ref {:?} at {fetched}: an unpublished or diverged local view is never advanced onto it",
                ctx.integration_branch
            ),
        ));
    }
    if let Err(outcome) = run_git(ctx, ctx.integration_repo, &["merge", "--ff-only", &fetched]) {
        if outcome.code.as_deref() != Some(code::EXIT) {
            return Err(outcome);
        }
        let detail = outcome
            .message
            .as_deref()
            .unwrap_or("the fast-forward failed without a message");
        return Err(failed(
            code::MERGE_FAILED,
            format!(
                "the integration checkout {:?} cannot advance to the published head {fetched}: {detail}",
                ctx.integration_branch
            ),
        ));
    }
    Ok(())
}

/// Documented poll cadence (seconds) of the publish path's hosted-CI wait
/// (issue #225): one read per cadence while any check run of the exact
/// certified head is still queued/in_progress, bounded by the step's own
/// effective deadline ([`effect_deadline_secs`]).
pub const HOSTED_CI_POLL_INTERVAL_SECS: u64 = 5;

/// How many workflow runs ONE hosted-CI read asks the forge for (issue #225):
/// the read is the forge's own list of the runs carrying one exact commit.
pub const HOSTED_CI_RUNS_LIMIT: u64 = 100;

/// The conclusions of a COMPLETED hosted check run that are RED (issue #225).
/// `success`, `skipped` and `neutral` are not red; a run that has not
/// completed carries no conclusion yet.
const HOSTED_CI_RED_CONCLUSIONS: [&str; 5] = [
    "failure",
    "cancelled",
    "timed_out",
    "startup_failure",
    "action_required",
];

/// One hosted check run the forge reported for ONE exact commit (issue #225).
#[derive(Clone, Debug)]
struct HostedCiRun {
    /// Forge run identity (`databaseId`).
    id: i64,
    /// Workflow name (`workflowName`).
    workflow: String,
    /// Forge status (`queued` | `in_progress` | `completed` | ...).
    status: String,
    /// Forge conclusion (`success` | `failure` | ...; `''` until completed).
    conclusion: String,
}

/// The COMPUTED hosted-CI state of one exact commit (issue #225).
enum HostedCiState {
    /// Every check run the forge reported completed, and none is red.
    Green,
    /// At least one check run is still queued/in_progress (never green yet).
    Pending(Vec<String>),
    /// At least one completed check run concluded red.
    Red(Vec<HostedCiRun>),
}

/// Parse one `gh run list --json databaseId,workflowName,status,conclusion`
/// read (issue #225). Anything else is refused typed rather than guessed at.
fn parse_hosted_ci_runs(text: &str) -> Result<Vec<HostedCiRun>, EffectOutcome> {
    let unreadable = |detail: &str| {
        failed(
            code::MALFORMED_OUTPUT,
            format!(
                "the forge's hosted-check read is not the documented JSON (`gh run list --json databaseId,workflowName,status,conclusion`): {detail}"
            ),
        )
    };
    let doc = Val::parse_json(text).map_err(|_| unreadable(text))?;
    let Some(items) = doc.as_array() else {
        return Err(unreadable(text));
    };
    let mut runs = Vec::new();
    for item in items {
        let id = item.get("databaseId").and_then(Val::as_int).unwrap_or(0);
        let workflow = item
            .get("workflowName")
            .and_then(Val::as_str)
            .unwrap_or("")
            .to_string();
        let status = item
            .get("status")
            .and_then(Val::as_str)
            .unwrap_or("")
            .to_string();
        let conclusion = item
            .get("conclusion")
            .and_then(Val::as_str)
            .unwrap_or("")
            .to_string();
        if id <= 0 || workflow.is_empty() || status.is_empty() {
            return Err(unreadable(&format!("{item:?}")));
        }
        runs.push(HostedCiRun {
            id,
            workflow,
            status,
            conclusion,
        });
    }
    Ok(runs)
}

/// Classify one hosted-CI read (issue #225). Purely computed: a completed red
/// run decides the state on its own, a still-running run is never green, and
/// only a read whose every run completed and none red is green.
fn hosted_ci_state(runs: &[HostedCiRun]) -> HostedCiState {
    let red: Vec<HostedCiRun> = runs
        .iter()
        .filter(|run| {
            run.status == "completed"
                && HOSTED_CI_RED_CONCLUSIONS.contains(&run.conclusion.as_str())
        })
        .cloned()
        .collect();
    if !red.is_empty() {
        return HostedCiState::Red(red);
    }
    let pending: Vec<String> = runs
        .iter()
        .filter(|run| run.status != "completed")
        .map(|run| {
            format!(
                "workflow {:?} (run {}) is {}",
                run.workflow, run.id, run.status
            )
        })
        .collect();
    if !pending.is_empty() {
        return HostedCiState::Pending(pending);
    }
    HostedCiState::Green
}

/// ONE hosted-CI read of ONE exact commit (issue #225): the forge's own
/// workflow runs carrying that commit, read-only.
fn hosted_ci_runs(ctx: &EffectContext<'_>, head: &str) -> Result<Vec<HostedCiRun>, EffectOutcome> {
    let args = vec![
        "run".to_string(),
        "list".to_string(),
        "--repo".to_string(),
        ctx.repository.to_string(),
        "--commit".to_string(),
        head.to_string(),
        "--limit".to_string(),
        HOSTED_CI_RUNS_LIMIT.to_string(),
        "--json".to_string(),
        "databaseId,workflowName,status,conclusion".to_string(),
    ];
    let out = run_forge(ctx, &args, code::MERGE_FAILED)?;
    let text = crate::redact::redact(out.stdout.trim()).to_string();
    parse_hosted_ci_runs(&text)
}

/// The failing job(s) and step(s) of one red check run (issue #225): the
/// refusal NAMES what is red, so the durable record is readable without a
/// second lookup. This read only ENRICHES the refusal — a forge that answers
/// nothing here leaves the run-level naming, and never turns red into green.
fn hosted_ci_red_detail(ctx: &EffectContext<'_>, run: &HostedCiRun) -> String {
    let args = vec![
        "run".to_string(),
        "view".to_string(),
        run.id.to_string(),
        "--repo".to_string(),
        ctx.repository.to_string(),
        "--json".to_string(),
        "jobs".to_string(),
    ];
    let Ok(out) = run_forge(ctx, &args, code::MERGE_FAILED) else {
        return String::new();
    };
    let text = crate::redact::redact(out.stdout.trim()).to_string();
    let Ok(doc) = Val::parse_json(&text) else {
        return String::new();
    };
    let Some(jobs) = doc.get("jobs").and_then(Val::as_array) else {
        return String::new();
    };
    let mut named: Vec<String> = Vec::new();
    for job in jobs {
        let conclusion = job.get("conclusion").and_then(Val::as_str).unwrap_or("");
        if !HOSTED_CI_RED_CONCLUSIONS.contains(&conclusion) {
            continue;
        }
        let name = job.get("name").and_then(Val::as_str).unwrap_or("");
        let mut steps: Vec<String> = Vec::new();
        if let Some(items) = job.get("steps").and_then(Val::as_array) {
            for item in items {
                let step_conclusion = item.get("conclusion").and_then(Val::as_str).unwrap_or("");
                if !HOSTED_CI_RED_CONCLUSIONS.contains(&step_conclusion) {
                    continue;
                }
                if let Some(step_name) = item.get("name").and_then(Val::as_str) {
                    steps.push(format!("{step_name:?}"));
                }
            }
        }
        if steps.is_empty() {
            named.push(format!("job {name:?} concluded {conclusion:?}"));
        } else {
            named.push(format!(
                "job {name:?} concluded {conclusion:?} at step {}",
                steps.join(", ")
            ));
        }
    }
    named.join("; ")
}

/// COMPUTE the hosted CI conclusion at the exact certified head (issue #225).
///
/// The publish path never lands a delivery on a judgement: it asks the forge
/// itself which workflow runs carry the certified head (`gh run list --commit
/// <certified head>` — never the branch tip), waits while any of them is
/// still queued/in_progress (bounded by the step's own effective deadline and
/// [`HOSTED_CI_POLL_INTERVAL_SECS`]), and refuses typed when one concluded
/// red ([`code::MERGE_CI_RED`], naming the run, its job and its step) or when
/// the bounded wait expired with a check still running
/// ([`code::MERGE_CI_PENDING`]). An unreadable read is its own typed refusal,
/// so no check is ever silently treated as green; a commit the forge reports
/// no workflow runs for has no hosted check to conclude on.
fn hosted_ci_gate(ctx: &EffectContext<'_>, head: &str) -> Result<(), EffectOutcome> {
    if !is_hex40(head) {
        // No exact head to compute for: the daemon's own merge gate refuses a
        // merge that names no observed certified head before this effect runs
        // (`merge requires observed.feature_head`).
        return Ok(());
    }
    let secs = effect_deadline_secs(ctx.kind, ctx.params)?;
    let window = Duration::from_secs(secs);
    let cadence = Duration::from_secs(HOSTED_CI_POLL_INTERVAL_SECS);
    let started = Instant::now();
    loop {
        let runs = hosted_ci_runs(ctx, head)?;
        match hosted_ci_state(&runs) {
            HostedCiState::Green => return Ok(()),
            HostedCiState::Red(red) => {
                let named: Vec<String> = red
                    .iter()
                    .map(|run| {
                        let detail = hosted_ci_red_detail(ctx, run);
                        if detail.is_empty() {
                            format!(
                                "workflow {:?} (run {}) concluded {:?}",
                                run.workflow, run.id, run.conclusion
                            )
                        } else {
                            format!("workflow {:?} (run {}) {detail}", run.workflow, run.id)
                        }
                    })
                    .collect();
                return Err(refusal(
                    code::MERGE_CI_RED,
                    format!(
                        "the exact certified head {head} carries a RED hosted check run and the publish path never lands it: {}; a fixed head must re-run the check and a new verdict must name it before any step consumes it",
                        named.join("; ")
                    ),
                ));
            }
            HostedCiState::Pending(checks) => {
                let elapsed = started.elapsed();
                if elapsed >= window {
                    return Err(refusal(
                        code::MERGE_CI_PENDING,
                        format!(
                            "the hosted checks of the exact certified head {head} were still running when the bounded wait of {secs}s expired, and a check still running is never treated as green: {}; the plan may declare its own `deadline_secs`, and a re-dispatch re-reads the same exact head",
                            checks.join("; ")
                        ),
                    ));
                }
                std::thread::sleep(cadence.min(window - elapsed));
            }
        }
    }
}

/// PUBLISH a certified delivery through the repository's own integration path
/// (issue #219): the open pull request whose head names the certified head,
/// squash-merged by the authenticated forge CLI.
///
/// This is the route for a repository whose rules forbid a direct push to its
/// integration ref (a pull-request-only ruleset and/or a protected branch):
/// the repository's real integration path is the pull request, so the merge
/// step consumes the reviewed delivery there instead of trying to push a ref
/// the forge will always decline. It is DECLARED by the topology
/// (`integration_publish: "pull_request"`) and never inferred from a refused
/// push — a silent fallback would hide the refusal (issue #196's plan-policy
/// discipline).
///
/// Every discipline of the push route is kept: the delivery is frozen at the
/// certified head the recorded verdict names (the forge is asked to match that
/// exact head at merge time, so a head that moves mid-flight is refused by the
/// forge itself), the PUBLISHED ref is read back and must carry the landing,
/// and the landed content is proven by the same fail-closed content fact the
/// landing, `post_merge_verify` and the cleanup proof use. Nothing local moves
/// before the forge reports the landing, and the integration checkout follows
/// the published head only after the read-back proved it.
#[allow(clippy::too_many_arguments)]
fn publish_via_pull_request(
    ctx: &EffectContext<'_>,
    inputs: &MergeInputs,
    target: &str,
    published_head: &str,
    reviewed_base: &str,
    certified_head: &str,
    branch_head: &str,
    checkout_head: &str,
) -> EffectOutcome {
    // A delivery whose reviewed content is ALREADY on the merge target — a
    // retry after a partial publish, or a delivery with no content beyond the
    // base — publishes nothing; the step reports the already-present content
    // in the same `already-landed` shape the push route reports.
    let (_reviewed_paths, differing) =
        match certified_content_differences(ctx, reviewed_base, certified_head, target) {
            Ok(pair) => pair,
            Err(outcome) => return outcome,
        };
    if differing.is_empty() {
        if let Err(outcome) = advance_checkout_to_published(ctx, published_head) {
            return outcome;
        }
        let tree = match tree_of(ctx, published_head) {
            Ok(tree) => tree,
            Err(outcome) => return outcome,
        };
        return ok(merge_outcome_doc(
            ctx,
            inputs,
            "already-landed",
            checkout_head,
            target,
            published_head,
            published_head,
            target,
            certified_head,
            branch_head,
            &tree,
        ));
    }
    // The pull request that IS this delivery. Never invented, never opened
    // from here: the reviewed delivery is published as a pull request by the
    // run's own delivery step, and this step consumes exactly that.
    let pull = match open_pull_request(ctx, inputs) {
        Ok(pull) => pull,
        Err(outcome) => return outcome,
    };
    let Some((number, pull_head)) = pull else {
        return refusal(
            code::PR_PUBLISH_MISSING,
            format!(
                "the delivery branch {:?} has no OPEN pull request onto {:?} in {}: the declared pull_request publish route needs the reviewed delivery published as a pull request naming the certified head {certified_head}",
                inputs.branch, ctx.integration_branch, ctx.repository
            ),
        );
    };
    if pull_head != certified_head {
        return refusal(
            code::PR_PUBLISH_MISSING,
            format!(
                "the open pull request #{number} of the delivery branch {:?} names head {pull_head}, not the certified head {certified_head} the recorded verdict binds: a pull request a verdict does not name is never merged",
                inputs.branch
            ),
        );
    }
    // Merge THROUGH the repository's rules, matching the exact certified head
    // so a delivery that moves between this read and the merge is refused by
    // the forge rather than merged unproven.
    let args = vec![
        "pr".to_string(),
        "merge".to_string(),
        number.to_string(),
        "--repo".to_string(),
        ctx.repository.to_string(),
        "--squash".to_string(),
        "--match-head-commit".to_string(),
        certified_head.to_string(),
    ];
    if let Err(outcome) = run_forge(ctx, &args, code::MERGE_PUBLISH_REJECTED) {
        return outcome;
    }
    // The forge's landing is real only when the PUBLISHED ref carries it.
    let published_after = match published_integration_head(ctx) {
        Ok(head) => head,
        Err(outcome) => return outcome,
    };
    if published_after == published_head {
        return failed(
            code::MERGE_PUBLISH_REJECTED,
            format!(
                "the forge did not publish the merge of pull request #{number} (head {certified_head}) onto {:?}: the published ref still carries {published_head}; the pull request is left as it was and nothing local moved",
                ctx.integration_branch
            ),
        );
    }
    // The landed content, proven by content — the same fail-closed fact the
    // push landing, `post_merge_verify` and the cleanup proof use.
    //
    // Issue #224 (AC1): the landed head is FETCHED into the integration
    // checkout before any read of it. The forge landed it on the remote, so
    // the commit object is not in this checkout's object store yet; reading it
    // first is guaranteed to fail (`fatal: bad object`, a bare adapter exit)
    // and no re-dispatch repairs that by itself.
    if let Err(outcome) = fetched_landed_head(ctx, &published_after) {
        return outcome;
    }
    let (landed_paths, landed_differing) =
        match certified_content_differences(ctx, reviewed_base, certified_head, &published_after) {
            Ok(pair) => pair,
            Err(outcome) => return outcome,
        };
    if !landed_differing.is_empty() {
        return failed(
            code::MERGE_PUBLISH_REJECTED,
            format!(
                "the forge published {published_after} on {:?}, but {} of the {} path(s) the review covered relative to {reviewed_base} do not carry the certified content of {certified_head} there (first {:?}): the published ref does not carry the reviewed delivery",
                ctx.integration_branch,
                landed_differing.len(),
                landed_paths.len(),
                landed_differing.first()
            ),
        );
    }
    if let Err(outcome) = advance_checkout_to_published(ctx, &published_after) {
        return outcome;
    }
    let tree = match tree_of(ctx, &published_after) {
        Ok(tree) => tree,
        Err(outcome) => return outcome,
    };
    ok(merge_outcome_doc(
        ctx,
        inputs,
        "landed",
        checkout_head,
        target,
        published_head,
        &published_after,
        &published_after,
        certified_head,
        branch_head,
        &tree,
    ))
}

/// `merge`: LAND the certified delivery on the integration ref under the
/// plan's closed policy and PUBLISH it to the integration remote — a
/// control-plane mutation the daemon journals like every other effect. The
/// evidence gate runs daemon-side before this effect.
///
/// The merge target is always the PUBLISHED integration ref (issue #132): the
/// checkout's own refs cannot see a bare-remote move, so the published head is
/// read from the checkout's `origin` remote, and an unreadable or absent
/// published ref refuses fail-closed. An UNPUBLISHED local move (the checkout
/// ahead of, or diverged from, the published ref) is never reconciled: the
/// published ref is the only merge target (issue #156). A checkout strictly
/// BEHIND it is not a stale local view to refuse forever (issue #178): the
/// published ref is fetched and verified, and a certified delivery that does
/// not contain it is RECONCILED onto it — the reviewed delta is replayed in
/// the delivery's own worktree — before this same step's bounded retry
/// re-certifies the reconciled head.
///
/// The landing itself honours the declared policy: `squash` writes ONE new
/// integration commit whose tree is the delivered tree and whose parent is the
/// published head (the delivered commits are rewritten, exactly as the
/// repository's squash policy states), `ff` lands the delivered head itself.
/// The landing is fast-forwarded into the integration checkout — never a
/// rewrite, never a forced update — and pushed to the same `origin` remote the
/// published ref was read from; the published ref is then read back, and the
/// step succeeds only when it carries the landing. A landing that cannot be
/// published records a typed non-success and the checkout is rolled back to
/// the published head (never a local move the published ref does not carry). A
/// delivery whose content is already on the merge target — a prior landing of
/// this very delivery, or a delivery with no content beyond the base — reports
/// `already-landed` and publishes nothing.
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
    // Certify only the PUBLISHED integration ref (issue #132): the checkout's
    // own refs cannot see a bare-remote move, so the published head is always
    // read from the checkout's `origin` remote, and an unreadable or absent
    // published ref refuses fail-closed.
    let published_head = match published_integration_head(ctx) {
        Ok(head) => head,
        Err(outcome) => return outcome,
    };
    // The certifiable merge target: the published head when the checkout
    // disagrees with it, the checkout's own head when they agree.
    let target = if published_head == integration_head {
        integration_head.clone()
    } else {
        // Fetch the published ref and verify the fetched view before it can
        // become a merge target (issue #178). A checkout AHEAD of, or
        // diverged from, that view is an unpublished local move and is never
        // reconciled (issue #156).
        let fetched = match fetched_published_head(ctx, &published_head) {
            Ok(head) => head,
            Err(outcome) => return outcome,
        };
        if !is_commit_ancestor(ctx, &integration_head, &fetched) {
            return failed(
                code::MERGE_NOT_FF,
                format!(
                    "{} policy merge refused: the published integration ref {:?} is at {fetched}, but the integration checkout is at {integration_head}: an unpublished or diverged local view is never reconciled",
                    inputs.policy, ctx.integration_branch
                ),
            );
        }
        fetched
    };
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
        &["rev-parse", "--verify", &format!("{target}^{{tree}}")],
    ) {
        Ok(out) => out.stdout.trim().to_string(),
        Err(outcome) => return outcome,
    };
    let feature_descends = is_commit_ancestor(ctx, &target, &inputs.branch);
    // Issue #178: the published ref moved beyond the reviewed base while the
    // run was in flight. Reconcile the certified delivery onto it, explicitly
    // and within the existing bounded retry budget, instead of failing
    // terminally (the old `not reviewed base` fence refused here and left a
    // certified delivery stranded). A moved ref the certified content cannot
    // be refreshed onto is its OWN typed condition and parks the run with the
    // bounded retries UNSPENT (`effect.merge.base_moved`, issue #263).
    if target != reviewed_base
        && let Err(outcome) = reconcile_moved_published(ctx, &inputs, &target, reviewed_base)
    {
        return outcome;
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
    let certified_head = ctx.observed_feature_head.unwrap_or_default().to_string();
    let branch_head = match run_git(
        ctx,
        ctx.integration_repo,
        &["rev-parse", "--verify", &inputs.branch],
    ) {
        Ok(out) => out.stdout.trim().to_string(),
        Err(outcome) => return outcome,
    };
    // Issue #202 (AC1): a recorded verdict FREEZES the delivery at the exact
    // head it names. `ctx.observed_feature_head` IS that head here — the
    // daemon's own evidence gate has already proven the newest `pass` verdict
    // names it — so when the published integration ref has not moved, the
    // delivery branch may only be consumed AT that head. A commit that
    // landed on the delivery after the verdict is a move no verdict names:
    // the step refuses typed (never a silent consumption of the moved
    // content) and the delivery must re-enter review. The published-ref
    // reconciliation above stays the ONE documented engine refresh (issue
    // #178: it is a history rewrite onto the *published* ref whose certified
    // content is proven byte-for-byte), so it is not this rule's subject.
    if target == reviewed_base && branch_head != certified_head {
        return refusal(
            code::DELIVERY_MOVED,
            format!(
                "the delivery branch {:?} is at {branch_head}, not the head {certified_head} its recorded verdict names: a commit landed on the reviewed delivery after the verdict, so no step may consume it; the delivery must re-enter review and a new verdict must name {branch_head} before any step consumes it",
                inputs.branch
            ),
        );
    }
    // Issue #225: the publish path COMPUTES the hosted CI conclusion for the
    // EXACT head the verdict names — never a judgement recorded elsewhere and
    // never the branch tip. A red or still-running required check refuses
    // typed here, BEFORE any route publishes anything: the measured incident
    // was `p7` publishing a delivery whose hosted CI had already concluded
    // red because the gate adjudicated CI instead of computing it.
    if let Err(outcome) = hosted_ci_gate(ctx, &certified_head) {
        return outcome;
    }
    // Issue #219: the topology-declared publish route chooses HOW the
    // certified delivery is published. Every check above (the published ref,
    // the merge target, the #178 reconciliation, the #202 frozen head) is the
    // SAME for both routes: the only difference is the mechanism that lands
    // the delivery on the published ref.
    if inputs.route == INTEGRATION_PUBLISH_PULL_REQUEST {
        return publish_via_pull_request(
            ctx,
            &inputs,
            &target,
            &published_head,
            reviewed_base,
            &certified_head,
            &branch_head,
            &integration_head,
        );
    }
    // The landing commit, or `None` when the delivered content is ALREADY on
    // the merge target — a prior landing of this very delivery, or a delivery
    // with no content beyond the base. Nothing is published then (a landing
    // would only add an empty commit); the step reports the already-present
    // content instead of a landing it did not perform.
    let landing = if !feature_descends {
        // Only the squash policy reaches here (the ff policy refused above):
        // the delivery does not contain the merge target, so no landing can be
        // built from it — a commit based on the target could only rewrite the
        // target's own content. Its reviewed content must therefore already be
        // there, proven by the same fail-closed content fact the cleanup
        // landed proof and `post_merge_verify` use.
        let (reviewed_paths, differing) =
            match certified_content_differences(ctx, reviewed_base, &certified_head, &target) {
                Ok(pair) => pair,
                Err(outcome) => return outcome,
            };
        if !differing.is_empty() {
            return failed(
                code::MERGE_FAILED,
                format!(
                    "the certified delivery {:?} does not contain the published integration ref {target} and {} of the {} reviewed path(s) it changed are not content-identical there (first {:?}); nothing can be landed from it",
                    inputs.branch,
                    differing.len(),
                    reviewed_paths.len(),
                    differing.first()
                ),
            );
        }
        None
    } else if feature_tree == integration_tree {
        None
    } else if inputs.policy == "squash" {
        match squash_landing_commit(ctx, &inputs, &feature_tree, &target, &certified_head) {
            Ok(head) => Some(head),
            Err(outcome) => return outcome,
        }
    } else {
        Some(branch_head.clone())
    };
    let mut published_after = published_head.clone();
    if let Some(landed_head) = &landing {
        // Advance the integration checkout to the landing — a fast-forward
        // from the published head, never a rewrite, never a forced update. A
        // checkout that cannot advance (uncommitted operator work on the
        // landed paths) refuses BEFORE anything is published: no landing is
        // ever claimed from a checkout that did not take it.
        if let Err(outcome) = run_git(
            ctx,
            ctx.integration_repo,
            &["merge", "--ff-only", landed_head],
        ) {
            if outcome.code.as_deref() != Some(code::EXIT) {
                return outcome;
            }
            let detail = outcome
                .message
                .as_deref()
                .unwrap_or("the fast-forward failed without a message");
            return failed(
                code::MERGE_FAILED,
                format!(
                    "the integration checkout {:?} cannot advance to the landing {landed_head}: {detail}",
                    ctx.integration_branch
                ),
            );
        }
        // Publish to the same remote the merge target was read from, then read
        // the published ref back: the landing is real only when the published
        // ref carries it.
        let push = run_git(
            ctx,
            ctx.integration_repo,
            &[
                "push",
                "--porcelain",
                "origin",
                &format!("{landed_head}:refs/heads/{}", ctx.integration_branch),
            ],
        );
        published_after = match published_integration_head(ctx) {
            Ok(head) => head,
            Err(outcome) => {
                let _ = roll_back_landing(ctx, &target);
                return outcome;
            }
        };
        if published_after != *landed_head {
            let rollback = roll_back_landing(ctx, &target);
            let detail = match (&push, &rollback) {
                (Err(outcome), _) => outcome.message.clone().unwrap_or_default(),
                (Ok(_), Err(detail)) => format!("the checkout rollback also failed: {detail}"),
                (Ok(_), Ok(())) => "the published ref did not carry the landing".to_string(),
            };
            if published_after != published_head {
                return refusal(
                    code::RETRY_REQUIRED,
                    format!(
                        "the published integration ref {:?} moved to {published_after} while this step landed {landed_head}: the landing was rolled back and this step's bounded retry re-certifies the delivery against the fetched published ref",
                        ctx.integration_branch
                    ),
                );
            }
            // Issue #219: a publish that did not happen is never one opaque
            // code. The push's own diagnostics decide the class — a remote
            // that REJECTED the update (repository rules / a protected ref), a
            // remote that could not be authenticated, a ref that moved (a
            // non-fast-forward), or a genuinely local failure that keeps the
            // generic code.
            let publish_code = match &push {
                Err(_) => classify_publish_failure(&detail, code::MERGE_FAILED),
                Ok(_) => code::MERGE_FAILED,
            };
            return failed(
                publish_code,
                format!(
                    "the landing {landed_head} was not published to {:?}: {detail}",
                    ctx.integration_branch
                ),
            );
        }
    }
    let landed_head = landing.clone().unwrap_or_else(|| target.clone());
    ok(merge_outcome_doc(
        ctx,
        &inputs,
        if landing.is_some() {
            "landed"
        } else {
            "already-landed"
        },
        &integration_head,
        &target,
        &published_head,
        &published_after,
        &landed_head,
        &certified_head,
        &branch_head,
        &feature_tree,
    ))
}

/// The typed `merge` result document, ONE shape for both publish routes
/// (issue #219): the read-back identities every later step and the operator
/// read (`published_head` before, `published_after` after, the landed head,
/// the checkout's head, the certified head the verdict names) plus the
/// declared publish route.
#[allow(clippy::too_many_arguments)]
fn merge_outcome_doc(
    ctx: &EffectContext<'_>,
    inputs: &MergeInputs,
    mode: &str,
    checkout_head: &str,
    integration_head: &str,
    published_head: &str,
    published_after: &str,
    landed_head: &str,
    certified_head: &str,
    branch_head: &str,
    result_tree: &str,
) -> Val {
    object(vec![
        ("mode", string(mode)),
        ("landed", bool_(true)),
        ("publish_route", string(&inputs.route)),
        ("merge_policy", string(&inputs.policy)),
        ("integration_branch", string(ctx.integration_branch)),
        ("integration_head", string(integration_head)),
        ("published_head", string(published_head)),
        ("published_after", string(published_after)),
        ("landed_head", string(landed_head)),
        ("checkout_head", string(checkout_head)),
        ("certified_head", string(certified_head)),
        ("reconciled_head", string(branch_head)),
        (
            "reconciled",
            bool_(is_hex40(certified_head) && branch_head != certified_head),
        ),
        ("feature_branch", string(&inputs.branch)),
        ("result_tree", string(result_tree)),
    ])
}

/// `post_merge_verify`: prove the merged integration head contains the
/// reviewed feature head — by exact git ancestry (AC7's verification step),
/// or, for the repository's SQUASH policy, whose landing rewrites the
/// reviewed commits and can therefore never be an ancestor, by the same
/// fail-closed content fact the merge landing and the cleanup landed proof
/// use: every path the review covered must carry the reviewed head's exact
/// content in the integration ref (issue #178 — plan, merge and verifier
/// agree on the squash landing).
fn effect_post_merge_verify(ctx: &EffectContext<'_>) -> EffectOutcome {
    let feature_head = match post_merge_verify_inputs(&ctx.param_contract()) {
        Ok(head) => head,
        Err(outcome) => return outcome,
    };
    let merged_head = match run_git(
        ctx,
        ctx.integration_repo,
        &["rev-parse", ctx.integration_branch],
    ) {
        Ok(out) => out.stdout.trim().to_string(),
        Err(outcome) => return outcome,
    };
    if is_commit_ancestor(ctx, &feature_head, ctx.integration_branch) {
        return ok(object(vec![
            ("feature_head", string(&feature_head)),
            ("merged_head", string(&merged_head)),
            ("contains_feature", bool_(true)),
            ("proof", string("ancestry")),
        ]));
    }
    // The content route. Without the reviewed base there is nothing to
    // compare against: the ancestry failure stands as the typed refusal.
    let reviewed_base = ctx.observed_integration_base.unwrap_or_default();
    if !is_hex40(reviewed_base) {
        return failed(
            code::EVIDENCE_STALE,
            format!("feature head {feature_head:?} is not an ancestor of the integration branch"),
        );
    }
    let paths = match changed_paths_between(ctx, reviewed_base, &feature_head, code::EVIDENCE_STALE)
    {
        Ok(paths) => paths,
        Err(outcome) => return outcome,
    };
    let differing = match differing_paths_between(
        ctx,
        &feature_head,
        ctx.integration_branch,
        &paths,
        code::EVIDENCE_STALE,
    ) {
        Ok(differing) => differing,
        Err(outcome) => return outcome,
    };
    if !differing.is_empty() {
        return failed(
            code::EVIDENCE_STALE,
            format!(
                "feature head {feature_head:?} is not an ancestor of the integration branch and {} of the {} path(s) it changed relative to its reviewed base {reviewed_base} are not content-identical there (first {:?})",
                differing.len(),
                paths.len(),
                differing.first()
            ),
        );
    }
    ok(object(vec![
        ("feature_head", string(&feature_head)),
        ("merged_head", string(&merged_head)),
        ("contains_feature", bool_(true)),
        ("proof", string("content")),
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

/// How a lane branch's delivered work was proven to have landed in the
/// integration ref (issue #132).
///
/// The repository's policy here is SQUASH-merge the PR into the integration
/// branch: the delivered commits are rewritten into a single integration
/// commit, so a squash-landed branch head is never an ancestor of the
/// integration ref. An ancestry-only landed proof therefore refuses that
/// branch forever — which is what kept a run on a squash-policy repository
/// from ever completing its sanctioned cleanup.
enum LandedProof {
    /// The branch head is an ancestor of the integration ref (an ff landing).
    Ancestor,
    /// Every path the branch changed relative to its fork point already
    /// carries the branch's exact content in the integration ref — the same
    /// content fact the merge landing certifies for the `squash` policy.
    Content {
        /// The fork point the content proof compared from.
        merge_base: String,
    },
    /// The landing is visible only on the PUBLISHED integration ref (issue
    /// #132): the forge owns the repository's policy merge and a remote merge
    /// never updates the checkout's own ref, so the proof was made against the
    /// FETCHED, verified published head while the checkout's view was strictly
    /// behind it.
    Published {
        /// The fetched, verified published head the proof was made against.
        published_head: String,
        /// The fork point the content proof compared from; `None` when the
        /// branch head is an ancestor of `published_head` (an ff landing only
        /// the published ref had received).
        merge_base: Option<String>,
    },
}

/// Prove `branch_head`'s work landed in the integration ref, or refuse the
/// unverified deletion with `refusal.cleanup.unmerged`.
///
/// The content route keeps the fail-closed boundary intact: the deletion is
/// refused unless every path the branch changed is byte-identical in the
/// integration ref (a dropped path, a deletion that did not land, or any
/// later divergence refuses). Only the *shape* of the landed proof widens;
/// no deletion happens without a proof.
fn landed_in_integration(
    ctx: &EffectContext<'_>,
    branch: &str,
    branch_head: &str,
) -> Result<LandedProof, EffectOutcome> {
    if run_git(
        ctx,
        ctx.integration_repo,
        &[
            "merge-base",
            "--is-ancestor",
            branch_head,
            ctx.integration_branch,
        ],
    )
    .is_ok()
    {
        return Ok(LandedProof::Ancestor);
    }
    let merge_base = match run_git(
        ctx,
        ctx.integration_repo,
        &["merge-base", branch_head, ctx.integration_branch],
    ) {
        Ok(out) => out.stdout.trim().to_string(),
        Err(_) => {
            return Err(refusal(
                code::CLEANUP_UNMERGED,
                format!(
                    "branch {branch:?} head {branch_head} is not merged into {:?} and shares no fork point with it; cleanup refuses unverified deletion",
                    ctx.integration_branch
                ),
            ));
        }
    };
    let paths = changed_paths_between(ctx, &merge_base, branch_head, code::CLEANUP_UNMERGED)?;
    let differing = differing_paths_between(
        ctx,
        branch_head,
        ctx.integration_branch,
        &paths,
        code::CLEANUP_UNMERGED,
    )?;
    if !differing.is_empty() {
        // The refusal names the real cause (issue #132): the branch is not
        // ancestry-merged AND its changed content has not landed either.
        return Err(refusal(
            code::CLEANUP_UNMERGED,
            format!(
                "branch {branch:?} head {branch_head} is not merged into {:?} and {} of the {} path(s) it changed relative to {merge_base} are not content-identical there (first {:?}); cleanup refuses unverified deletion",
                ctx.integration_branch,
                differing.len(),
                paths.len(),
                differing.first(),
            ),
        ));
    }
    Ok(LandedProof::Content { merge_base })
}

/// Prove a branch landed in the PUBLISHED integration ref (issue #132).
///
/// The forge owns the repository's policy merge and a remote landing never
/// updates the checkout's own ref, so the run's own cleanup would refuse its
/// sanctioned deletion forever once the delivery landed on the forge. The
/// published head is read from the checkout's `origin` (`git ls-remote`),
/// FETCHED into the checkout's remote-tracking ref and verified against that
/// read (issues #156, #178). Only a checkout STRICTLY BEHIND the published ref
/// may certify from this view: a checkout ahead of, or diverged from, it is an
/// unpublished local move and this route refuses. The proof is the same
/// fail-closed fact as the local one — ancestry against the fetched head, or,
/// for the squash landing (which never is an ancestor), the branch's exact
/// content on every path it changed relative to the fork point. An unreadable
/// or unverifiable published view proves nothing and refuses.
fn landed_in_published(
    ctx: &EffectContext<'_>,
    branch_head: &str,
) -> Result<LandedProof, EffectOutcome> {
    let local_head = run_git(
        ctx,
        ctx.integration_repo,
        &["rev-parse", "--verify", ctx.integration_branch],
    )?
    .stdout
    .trim()
    .to_string();
    let published = published_integration_head(ctx)?;
    if published == local_head {
        // The checkout's own ref IS the published view; its own refusal (the
        // caller's) stands and nothing is re-proven against itself.
        return Err(refusal(
            code::CLEANUP_UNMERGED,
            format!(
                "branch head {branch_head} is not merged into {:?} and its changed content is not content-identical there; the checkout's own view is the published head {published}; cleanup refuses unverified deletion",
                ctx.integration_branch
            ),
        ));
    }
    let fetched = fetched_published_head(ctx, &published)?;
    if !is_commit_ancestor(ctx, &local_head, &fetched) {
        return Err(refusal(
            code::CLEANUP_UNMERGED,
            format!(
                "the checkout's integration ref {:?} is at {local_head}, which is not an ancestor of the published head {fetched}: an unpublished or diverged local view is never certified; cleanup refuses unverified deletion",
                ctx.integration_branch
            ),
        ));
    }
    if is_commit_ancestor(ctx, branch_head, &fetched) {
        return Ok(LandedProof::Published {
            published_head: fetched,
            merge_base: None,
        });
    }
    let merge_base = match run_git(
        ctx,
        ctx.integration_repo,
        &["merge-base", branch_head, &fetched],
    ) {
        Ok(out) => out.stdout.trim().to_string(),
        Err(_) => {
            return Err(refusal(
                code::CLEANUP_UNMERGED,
                format!(
                    "branch head {branch_head} is not merged into the published integration ref {fetched} and shares no fork point with it; cleanup refuses unverified deletion"
                ),
            ));
        }
    };
    let paths = changed_paths_between(ctx, &merge_base, branch_head, code::CLEANUP_UNMERGED)?;
    let differing =
        differing_paths_between(ctx, branch_head, &fetched, &paths, code::CLEANUP_UNMERGED)?;
    if !differing.is_empty() {
        return Err(refusal(
            code::CLEANUP_UNMERGED,
            format!(
                "branch head {branch_head} is not merged into the published integration ref {fetched} and {} of the {} path(s) it changed relative to {merge_base} are not content-identical there (first {:?}); cleanup refuses unverified deletion",
                differing.len(),
                paths.len(),
                differing.first(),
            ),
        ));
    }
    Ok(LandedProof::Published {
        published_head: fetched,
        merge_base: Some(merge_base),
    })
}

/// `cleanup`: deterministic lane cleanup. Refuses dirty worktrees,
/// uncontained paths, unknown targets, and unverified (unmerged) branches
/// (AC8). The daemon journals the salvage evidence (`mutate.salvage`)
/// before invoking this effect. The landed proof is ancestry or — for a
/// policy SQUASH landing, which is never an ancestor — content-equivalence
/// (issue #132); when the CHECKOUT's own view cannot see the landing, the
/// same fact is proven against the FETCHED, verified PUBLISHED ref, which
/// only a checkout strictly behind it may certify from (issue #132).
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
    // Refuse unverified (unmerged) branches: ancestry, or — under the
    // repository's squash policy — the delivered content proven identical in
    // the integration ref (issue #132).
    let branch_head = match run_git(ctx, &worktree, &["rev-parse", "--verify", "HEAD"]) {
        Ok(out) => out.stdout.trim().to_string(),
        Err(outcome) => return outcome,
    };
    let landed = match landed_in_integration(ctx, &branch, &branch_head) {
        Ok(landed) => landed,
        Err(outcome) if outcome.code.as_deref() == Some(code::CLEANUP_UNMERGED) => {
            // Issue #132: the sanctioned landing happens on the forge (the PR
            // is squash-merged) and a remote landing never updates the
            // checkout's own ref, so the checkout's view alone cannot certify
            // a delivered lane and the run would refuse its own cleanup
            // forever. Before refusing, prove the landing against the
            // PUBLISHED ref (fetched and verified, issues #156/#178); the
            // checkout's own refusal stands whenever that view cannot add a
            // proof.
            match landed_in_published(ctx, &branch_head) {
                Ok(landed) => landed,
                Err(_) => return outcome,
            }
        }
        Err(outcome) => return outcome,
    };
    let integration_head = match run_git(
        ctx,
        ctx.integration_repo,
        &["rev-parse", ctx.integration_branch],
    ) {
        Ok(out) => out.stdout.trim().to_string(),
        Err(outcome) => return outcome,
    };
    // The salvage document the daemon journals BEFORE the deletion.
    let mut salvage_pairs = vec![
        ("worktree", string(&worktree.to_string_lossy())),
        ("branch", string(&branch)),
        ("head", string(&branch_head)),
        ("merged_into", string(ctx.integration_branch)),
        ("integration_head", string(&integration_head)),
    ];
    match &landed {
        LandedProof::Ancestor => salvage_pairs.push(("landed_by", string("ancestor"))),
        LandedProof::Content { merge_base } => {
            salvage_pairs.push(("landed_by", string("content")));
            salvage_pairs.push(("merge_base", string(merge_base)));
        }
        LandedProof::Published {
            published_head,
            merge_base,
        } => {
            // The checkout's own ref (recorded above as integration_head)
            // could not see the landing: the proof is made against the
            // FETCHED published head, which the record names.
            salvage_pairs.push((
                "landed_by",
                string(match merge_base {
                    Some(_) => "content",
                    None => "ancestor",
                }),
            ));
            if let Some(merge_base) = merge_base {
                salvage_pairs.push(("merge_base", string(merge_base)));
            }
            salvage_pairs.push(("published_head", string(published_head)));
        }
    }
    let salvage = object(salvage_pairs);
    // p8 retires the owned workspace BEFORE deleting its checkout. Headless
    // plans have no pane; never probe or close unrelated fleet workspaces.
    // Issue #224: the landing proof above already holds, so a lane that is
    // still ALIVE is the worker outliving its own publish — a timing
    // condition. Wait, bounded by the step's effective deadline, for the
    // settled turn the worker produces on its own instead of refusing into
    // the bounded retry budget (a genuinely stale or foreign workspace still
    // refuses at once and is never waited on).
    let mut lane_wait = None;
    let pane_start = ctx
        .plan
        .doc
        .get("steps")
        .and_then(Val::as_array)
        .and_then(|steps| {
            steps
                .iter()
                .find(|step| step.get("kind").and_then(Val::as_str) == Some("harness_start"))
        });
    if let Some(start) = pane_start
        && declared_execution(start.get("params"))
            .is_ok_and(|mode| mode == crate::adapters::ExecutionMode::HerdrPane)
    {
        let session = match resolve_session(ctx, None, "cleanup") {
            Ok(session) => session,
            Err(outcome) => return outcome,
        };
        let bound = match effect_deadline_secs(ctx.kind, ctx.params) {
            Ok(secs) => secs,
            Err(outcome) => return outcome,
        };
        let started = std::time::Instant::now();
        let waited = await_settled_lane(
            Duration::from_secs(bound),
            LANE_OUTLIVED_PUBLISH,
            |remaining| {
                crate::adapters::observe_pane_worker(&session, &worktree, remaining, ctx.env)
            },
            || {
                crate::adapters::close_lane_workspace(
                    &session,
                    &worktree,
                    ctx.env,
                    crate::adapters::ADAPTER_TIMEOUT,
                )
            },
            || started.elapsed(),
            std::thread::sleep,
        );
        match waited {
            Ok(()) => {
                lane_wait = Some(object(vec![
                    ("bound_secs", integer(bound as i64)),
                    ("waited_ms", integer(started.elapsed().as_millis() as i64)),
                ]));
            }
            Err(outcome) => return outcome,
        }
    }
    // Remove the worktree (clean, so no --force) then the local branch.
    match run_git(
        ctx,
        ctx.integration_repo,
        &["worktree", "remove", worktree.to_str().unwrap_or_default()],
    ) {
        Ok(_) => {}
        Err(outcome) => return outcome,
    }
    // A squash landing is not an ancestor, so git's own merged check cannot
    // pass for it; there the effect already proved the landing above and
    // deletes with `-D`. A proof made against the PUBLISHED head (issue
    // #132) also cannot satisfy git's own merged check against the checkout's
    // ref, which is behind it. The ancestor route keeps git's own `-d` safety.
    let delete_arg = match landed {
        LandedProof::Ancestor => "-d",
        LandedProof::Content { .. } | LandedProof::Published { .. } => "-D",
    };
    match run_git(ctx, ctx.integration_repo, &["branch", delete_arg, &branch]) {
        Ok(_) => {}
        Err(outcome) => return outcome,
    }
    let branch_gone = match run_git(ctx, ctx.integration_repo, &["branch", "--list", &branch]) {
        Ok(out) => out.stdout.trim().is_empty(),
        Err(_) => false,
    };
    let mut result = vec![
        ("worktree", string(&worktree.to_string_lossy())),
        ("branch", string(&branch)),
        ("removed", bool_(branch_gone && !worktree.exists())),
        ("salvage", salvage),
    ];
    if let Some(wait) = lane_wait {
        // Issue #224: the bounded wait that let a lane outliving its own
        // publish settle before its workspace was closed is part of the
        // recorded outcome, its bound included.
        result.push(("lane_wait", wait));
    }
    ok(object(result))
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

    /// Issue #248: a leg that advanced to a new round holds a lane binding for
    /// the round the plan was rendered at; the ONE control allowed to advance
    /// the round (the bounded re-evaluation) re-binds the leg's OWN checkout
    /// for the round it dispatches, and nothing else is ever reinterpreted.
    #[test]
    fn a_reviewer_leg_re_binds_the_lane_checkout_of_the_round_it_dispatches() {
        let pane = |worktree: &str| {
            object(vec![
                ("execution", string("herdr")),
                ("harness_key", string("lane-role")),
                (
                    "reviewer_profile",
                    object(vec![("key", string("lane-role"))]),
                ),
                ("worktree", string(worktree)),
            ])
        };
        // The plan bound round 1; the dispatch is round 2 (the re-review a fix
        // round hands the leg to) — the binding is re-rendered for that round.
        assert_eq!(
            rebound_reviewer_lane(5, Some(&pane("issues-5-rev1")), 2),
            Some("issues-5-rev2".to_string())
        );
        // Already the dispatching round: nothing to re-render.
        assert_eq!(
            rebound_reviewer_lane(5, Some(&pane("issues-5-rev2")), 2),
            None
        );
        // A genuinely FOREIGN checkout is never reinterpreted — the effect's
        // own `refusal.lane.identity` stands.
        for foreign in [
            "issues-5",
            "issues-5-impl2",
            "issues-6-rev1",
            "issues-5-rev01",
            "worktrees/issues-5-rev1",
        ] {
            assert_eq!(
                rebound_reviewer_lane(5, Some(&pane(foreign)), 2),
                None,
                "{foreign} is not this leg's own checkout and is never re-bound"
            );
        }
        // The bare-subprocess fallback runs in the run's own lane checkout and
        // keeps the binding it was rendered with, byte for byte.
        let headless = object(vec![
            ("execution", string("headless")),
            ("harness_key", string("lane-role")),
            (
                "reviewer_profile",
                object(vec![("key", string("lane-role"))]),
            ),
            ("worktree", string("issues-5")),
        ]);
        assert_eq!(rebound_reviewer_lane(5, Some(&headless), 2), None);
        // A step that presents its own review facts declares no leg (it
        // computes nothing a re-evaluation could recompute): never re-bound.
        let presented = object(vec![
            ("execution", string("herdr")),
            ("worktree", string("issues-5-rev1")),
        ]);
        assert_eq!(rebound_reviewer_lane(5, Some(&presented), 2), None);
        assert_eq!(rebound_reviewer_lane(5, None, 2), None);
    }

    /// One synthetic pane sample (issue #170 N7): both views of the lane and
    /// the lane's own lifecycle counter, all under the test's control.
    fn pane_sample(lane: &str, status: &str, seq: Option<i64>) -> crate::adapters::PaneSample {
        crate::adapters::PaneSample {
            lane_state: lane.to_string(),
            status_state: status.to_string(),
            seq,
        }
    }

    /// A read-back whose two views agree, the measured shape of one Herdr row.
    fn pane(state: &str) -> crate::adapters::PaneSample {
        pane_sample(state, state, None)
    }

    // -------------------------------------------------------------------
    // Issue #224: the cleanup step's lane-settle wait. It closes the lane's
    // workspace only on a CONFIRMED settled turn — the collection's own
    // discipline (issue #170 N7) — driven here at a local clock.
    // -------------------------------------------------------------------

    /// A lane whose read-backs flap between working and a stop state is never
    /// a settled turn: no close is ever attempted, and the wait parks on its
    /// own bound with the live state it last read named.
    #[test]
    fn cleanup_lane_wait_never_closes_on_a_flapping_lane() {
        use std::cell::Cell;
        let elapsed = Cell::new(Duration::ZERO);
        let reads = Cell::new(0usize);
        let closes = Cell::new(0usize);
        let flap = ["working", "idle", "working", "done", "working"];
        let outcome = await_settled_lane(
            Duration::from_secs(30),
            LANE_OUTLIVED_PUBLISH,
            |_| {
                reads.set(reads.get() + 1);
                let state = match flap.get(reads.get() - 1) {
                    Some(state) => pane(state),
                    None => pane("working"),
                };
                Ok(state)
            },
            || {
                closes.set(closes.get() + 1);
                Ok(())
            },
            || elapsed.get(),
            |wait| elapsed.set(elapsed.get() + wait),
        )
        .expect_err("a transient stop report is not a settled turn");
        assert_eq!(outcome.status, "ambiguous");
        assert_eq!(outcome.code.as_deref(), Some(code::LANE_TIMEOUT));
        assert_eq!(
            closes.get(),
            0,
            "the workspace of a flapping lane is never closed"
        );
        assert_eq!(
            outcome.result.get("deadline_secs"),
            Some(&integer(30)),
            "the park states the step's own bound: {:?}",
            outcome.result
        );
        let message = outcome.message.unwrap_or_default();
        assert!(
            message.contains("still working") && message.contains("bounded wait of 30s"),
            "the park names the live state it last read and the bound: {message}"
        );
    }

    /// The settled turn is confirmed exactly like the collection's stop: three
    /// corroborated non-working read-backs spanning two real intervals. The
    /// close may not happen before that confirmation.
    #[test]
    fn cleanup_lane_wait_closes_only_on_the_confirmed_settle() {
        use std::cell::Cell;
        let elapsed = Cell::new(Duration::ZERO);
        let reads = Cell::new(0usize);
        let closes = Cell::new(0usize);
        let outcome = await_settled_lane(
            Duration::from_secs(60),
            LANE_OUTLIVED_PUBLISH,
            |_| {
                reads.set(reads.get() + 1);
                if reads.get() == 1 {
                    Ok(pane("working"))
                } else {
                    Ok(pane("idle"))
                }
            },
            || {
                closes.set(closes.get() + 1);
                Ok(())
            },
            || elapsed.get(),
            |wait| elapsed.set(elapsed.get() + wait),
        );
        assert!(outcome.is_ok(), "the confirmed settle closes: {outcome:?}");
        assert_eq!(closes.get(), 1, "the workspace is closed exactly once");
        assert_eq!(
            reads.get(),
            4,
            "one working read-back, then COLLECT_STOP_SAMPLES corroborated stop read-backs"
        );
        assert_eq!(
            elapsed.get(),
            Duration::from_secs(15),
            "the confirmation spans (N-1) real intervals"
        );
    }

    /// A lane whose own lifecycle counter moves between non-working read-backs
    /// is still moving through its lifecycle: it is never a settled turn.
    #[test]
    fn cleanup_lane_wait_never_settles_a_lane_whose_counter_moved() {
        use std::cell::Cell;
        let elapsed = Cell::new(Duration::ZERO);
        let reads = Cell::new(0i64);
        let closes = Cell::new(0usize);
        let outcome = await_settled_lane(
            Duration::from_secs(12),
            LANE_OUTLIVED_PUBLISH,
            |_| {
                reads.set(reads.get() + 1);
                Ok(pane_sample("idle", "idle", Some(reads.get())))
            },
            || {
                closes.set(closes.get() + 1);
                Ok(())
            },
            || elapsed.get(),
            |wait| elapsed.set(elapsed.get() + wait),
        )
        .expect_err("a moving lane is not a settled one");
        assert_eq!(outcome.code.as_deref(), Some(code::LANE_TIMEOUT));
        assert_eq!(closes.get(), 0);
    }

    /// The confirmed settle is void the moment the close finds the lane busy
    /// again (it took another turn): the wait re-confirms from the next
    /// read-back instead of closing under a live worker.
    #[test]
    fn cleanup_lane_wait_reconfirms_when_the_lane_started_working_again() {
        use std::cell::Cell;
        let elapsed = Cell::new(Duration::ZERO);
        let reads = Cell::new(0usize);
        let closes = Cell::new(0usize);
        let outcome = await_settled_lane(
            Duration::from_secs(120),
            LANE_OUTLIVED_PUBLISH,
            |_| {
                reads.set(reads.get() + 1);
                if reads.get() == 1 || reads.get() == 5 {
                    Ok(pane("working"))
                } else {
                    Ok(pane("idle"))
                }
            },
            || {
                closes.set(closes.get() + 1);
                if closes.get() == 1 {
                    Err(crate::adapters::AdapterError::refusal(
                        crate::adapters::CODE_LANE_BUSY,
                        "lane impl-5 is still working; preserve its workspace",
                    ))
                } else {
                    Ok(())
                }
            },
            || elapsed.get(),
            |wait| elapsed.set(elapsed.get() + wait),
        );
        assert!(
            outcome.is_ok(),
            "the re-confirmed settle closes the workspace: {outcome:?}"
        );
        assert_eq!(
            closes.get(),
            2,
            "the busy close voids the first confirmation and the wait re-confirms"
        );
    }

    /// Every outcome that is not the timing condition is never waited on: the
    /// close's own typed refusal returns at the confirmation, not after a wait.
    #[test]
    fn cleanup_lane_wait_never_waits_on_a_typed_refusal() {
        use std::cell::Cell;
        let elapsed = Cell::new(Duration::ZERO);
        let outcome = await_settled_lane(
            Duration::from_secs(600),
            LANE_OUTLIVED_PUBLISH,
            |_| Ok(pane("idle")),
            || {
                Err(crate::adapters::AdapterError::refusal(
                    crate::adapters::CODE_STALE_GENERATION,
                    "a superseded generation's workspace is never waited on",
                ))
            },
            || elapsed.get(),
            |wait| elapsed.set(elapsed.get() + wait),
        )
        .expect_err("a generation mismatch is never waited on");
        assert_eq!(
            outcome.code.as_deref(),
            Some(crate::adapters::CODE_STALE_GENERATION)
        );
        assert_eq!(
            elapsed.get(),
            Duration::from_secs(10),
            "the refusal returns at the confirmation, never after a wait"
        );
    }

    /// A lane whose own read-back cannot be taken at all carries no settle
    /// evidence: the close's own verification decides, at once — nothing
    /// observable is not waited on.
    #[test]
    fn cleanup_lane_wait_closes_when_the_lane_cannot_be_observed() {
        use std::cell::Cell;
        let elapsed = Cell::new(Duration::ZERO);
        let closes = Cell::new(0usize);
        let outcome = await_settled_lane(
            Duration::from_secs(30),
            LANE_OUTLIVED_PUBLISH,
            |_| {
                Err(crate::adapters::ProcessFailure {
                    code: crate::adapters::CODE_INCOMPLETE_IDENTITY,
                    message: "the lane's own read-back could not be taken".to_string(),
                    detail: String::new(),
                })
            },
            || {
                closes.set(closes.get() + 1);
                Ok(())
            },
            || elapsed.get(),
            |wait| elapsed.set(elapsed.get() + wait),
        );
        assert!(
            outcome.is_ok(),
            "the close decides when there is nothing to observe: {outcome:?}"
        );
        assert_eq!(closes.get(), 1, "the close runs once");
        assert_eq!(
            elapsed.get(),
            Duration::ZERO,
            "an unobservable lane is not waited on"
        );
    }

    /// Issue #170 N7/N8: the documented numbers are pinned contract values —
    /// the sample count a stop needs, the real interval between samples and
    /// the hard overall ceiling. What each rule DOES is witnessed by the tests
    /// above; this pins the numbers a future change may not move silently.
    #[test]
    fn collection_bounds_are_pinned_contract_values() {
        assert_eq!(COLLECT_STOP_SAMPLES, 3, "the confirmed-stop sample count");
        assert_eq!(COLLECT_STOP_INTERVAL_SECS, 5, "the real sample interval");
        assert_eq!(COLLECT_CEILING_SECS, 6 * 60 * 60, "the hard ceiling");
        const {
            assert!(
                COLLECT_STOP_SAMPLES > 2,
                "TWO read-backs is exactly the measured defect (a flap judged a stop)"
            );
            assert!(
                COLLECT_STOP_INTERVAL_SECS > 1,
                "an interval of loop iterations is exactly the measured defect"
            );
            assert!(
                COLLECT_CEILING_SECS > 2 * 1800,
                "the ceiling must be generous enough for a real lane (the measured \
                 turn was ≈93 minutes against the old 1800 s wall)"
            );
        }
    }

    #[test]
    fn collection_live_mid_turn_parks_worker_timeout_on_silence() {
        use std::cell::Cell;
        // A lane that flaps between working and a stop state (the measured
        // p5-101 shape) and then goes genuinely silent: no stop is ever
        // confirmed — the run of stop samples never reaches
        // COLLECT_STOP_SAMPLES — so the wait parks on the NO-PROGRESS window
        // with `effect.worker_timeout`, naming the progress it last recorded.
        let elapsed = Cell::new(Duration::ZERO);
        let reads = Cell::new(0usize);
        let flap = [
            "working", "idle", "working", "blocked", "working", "done", "working",
        ];
        let outcome = poll_pane_worker(
            Duration::from_secs(7),
            Duration::from_secs(1),
            Duration::from_secs(60),
            |_| {
                reads.set(reads.get() + 1);
                let state = match flap.get(reads.get() - 1) {
                    Some(state) => pane(state),
                    None => pane("unknown"),
                };
                Ok(state)
            },
            || refusal(code::COLLECT_EMPTY_DELTA, "no committed delta"),
            || elapsed.get(),
            |wait| elapsed.set(elapsed.get() + wait),
        )
        .expect_err("a transient stop report is not a stopped worker");
        assert_eq!(outcome.status, "ambiguous");
        assert_eq!(outcome.code.as_deref(), Some(code::WORKER_TIMEOUT));
        assert_eq!(
            elapsed.get(),
            Duration::from_secs(14),
            "the window is 7s of silence after the last progress at 6s"
        );
        assert_eq!(
            outcome.result.get("progress_secs"),
            Some(&integer(7)),
            "the park names how long ago progress was last recorded: {:?}",
            outcome.result
        );
        let message = outcome.message.unwrap_or_default();
        assert!(
            message.contains("no recorded progress for 7s of the 7s no-progress window")
                && message.contains("the lane read-back moved"),
            "the park names the bound that fired and the progress observed: {message}"
        );
    }

    #[test]
    fn collection_polling_uses_injected_time_and_live_state() {
        use std::cell::Cell;
        // A lane whose read-back carries no progress at all (`unknown`) is
        // sampled at the pinned interval, each read-back gets exactly what the
        // no-progress window has left, and the wait parks at the window.
        let elapsed = Cell::new(Duration::ZERO);
        let mut reads = Vec::new();
        let outcome = poll_pane_worker(
            Duration::from_secs(6),
            Duration::from_secs(1),
            Duration::from_secs(60),
            |remaining| {
                reads.push(remaining.as_secs());
                Ok(pane("unknown"))
            },
            || refusal(code::COLLECT_EMPTY_DELTA, "no committed delta"),
            || elapsed.get(),
            |wait| elapsed.set(elapsed.get() + wait),
        )
        .unwrap_err();
        assert_eq!(
            reads,
            [6, 5, 4, 3, 2, 1, 1],
            "consult live state until the worker stops; the read at the window's \
             edge is still given a real (1s) budget before the wait parks"
        );
        assert_eq!(elapsed.get(), Duration::from_secs(6));
        assert_eq!(outcome.status, "ambiguous");
        assert_eq!(outcome.code.as_deref(), Some(code::WORKER_TIMEOUT));

        // A lane that never stops is still BOUNDED: the hard ceiling ends the
        // wait, and each read-back budget is what the window has left, floored
        // at one second and never more than the ceiling has left.
        reads.clear();
        elapsed.set(Duration::ZERO);
        let outcome = poll_pane_worker(
            Duration::from_secs(5),
            Duration::from_secs(2),
            Duration::from_secs(3),
            |remaining| {
                assert!(reads.len() < 3, "the ceiling must bound polling");
                reads.push(remaining.as_secs());
                Ok(pane("working"))
            },
            || refusal(code::COLLECT_EMPTY_DELTA, "no committed delta"),
            || elapsed.get(),
            |wait| elapsed.set(elapsed.get() + wait),
        )
        .unwrap_err();
        assert_eq!(reads, [3, 1]);
        assert_eq!(elapsed.get(), Duration::from_secs(3), "last wait is capped");
        assert_eq!(outcome.status, "ambiguous");
        assert_eq!(outcome.code.as_deref(), Some(code::WORKER_TIMEOUT));
        assert_eq!(outcome.result.get("ceiling_secs"), Some(&integer(3)));
        assert!(
            outcome
                .message
                .unwrap_or_default()
                .contains("still producing progress at the 3s overall collection ceiling"),
            "the park names the ceiling and the progress it was still recording"
        );
    }

    /// Issue #202 (AC2): a collection's observation binds only when it names a
    /// 40-hex head AND the slug branch it was collected from — the certified
    /// delivery binding this run's later steps consume. Anything else is a
    /// typed non-success (`refusal.collect.unbound`), never a `succeeded`
    /// outcome that bound nothing.
    #[test]
    fn a_collection_that_cannot_bind_its_observed_head_is_a_typed_non_success() {
        let head = "1".repeat(40);
        let short = "1".repeat(39);
        assert!(
            certify_delivery_binding(&head, "issue-5").is_ok(),
            "a named head and its branch are the binding"
        );
        for (observed, branch) in [
            (String::new(), "issue-5".to_string()),
            ("not-a-sha".to_string(), "issue-5".to_string()),
            (short, "issue-5".to_string()),
            (head.clone(), String::new()),
            (head.clone(), "issue 5".to_string()),
        ] {
            let outcome = certify_delivery_binding(&observed, &branch)
                .expect_err("an un-bindable observation is never a success");
            assert_eq!(outcome.status, "refused", "{observed:?}/{branch:?}");
            assert_eq!(
                outcome.code.as_deref(),
                Some(code::COLLECT_UNBOUND),
                "{observed:?}/{branch:?}"
            );
        }
    }

    /// Issue #170 (N7) — the measured defect as a unit witness: the worker's
    /// status flaps to `done` for TWO consecutive read-backs while the worker
    /// is still working and nothing has been committed (the live `p5-101`
    /// collection read a flapping status twice, ~100 ms apart, judged the
    /// working pane stopped and refused `refusal.collect.empty_delta` four
    /// minutes into a 93-minute turn).
    ///
    /// The flap never confirms a stop: the wait keeps reading, the delivery
    /// that lands mid-turn is collected, and the emptiness refusal is never
    /// produced for a working worker.
    #[test]
    fn collection_status_flap_mid_turn_is_never_a_confirmed_stop() {
        use std::cell::Cell;
        let elapsed = Cell::new(Duration::ZERO);
        let reads = Cell::new(0usize);
        // (lane state, delivery present).
        let table = [
            ("working", false),
            ("done", false), // the flap ...
            ("done", false), // ... two stop read-backs, still mid-turn
            ("working", false),
            ("working", true), // the delivery lands MID-TURN
            ("done", true),
            ("done", true),
            ("done", true), // the settled turn
        ];
        let outcome = poll_pane_worker(
            Duration::from_millis(3),
            Duration::from_millis(1),
            Duration::from_millis(60),
            |_| {
                let (state, _) = table[reads.get().min(table.len() - 1)];
                reads.set(reads.get() + 1);
                Ok(pane(state))
            },
            || {
                let (_, delivered) = table[reads.get().saturating_sub(1).min(table.len() - 1)];
                if delivered {
                    ok(object(vec![
                        ("head", string(&"d".repeat(40))),
                        ("commits", Val::Arr(vec![string(&"d".repeat(40))])),
                    ]))
                } else {
                    refusal(code::COLLECT_EMPTY_DELTA, "no committed delta")
                }
            },
            || elapsed.get(),
            |wait| elapsed.set(elapsed.get() + wait),
        )
        .expect("the flap is not a stop and the delivery is collected at the settled turn");
        assert_eq!(outcome.status, "succeeded");
        assert_eq!(
            outcome.result.get("head"),
            Some(&string(&"d".repeat(40))),
            "the settled delivery is certified, never an empty refusal"
        );
        assert_eq!(
            reads.get(),
            8,
            "the two flap read-backs never satisfy the pinned sample count"
        );
    }

    /// Issue #170 (N7) witness (b): the number of non-working read-backs a stop
    /// needs is PINNED — [`COLLECT_STOP_SAMPLES`], each separated by the real
    /// interval off the wait's own clock, corroborated by the second view of
    /// the lane.
    #[test]
    fn collection_stop_needs_the_pinned_sample_count() {
        use std::cell::Cell;
        // One read-back fewer than the pinned count, then back to working and
        // then silent: the stop never confirms, so the emptiness refusal is
        // NEVER returned — the wait parks on the no-progress window instead.
        let elapsed = Cell::new(Duration::ZERO);
        let reads = Cell::new(0usize);
        let outcome = poll_pane_worker(
            Duration::from_millis(6),
            Duration::from_millis(1),
            Duration::from_millis(60),
            |_| {
                reads.set(reads.get() + 1);
                Ok(match reads.get() {
                    read if read < COLLECT_STOP_SAMPLES => pane("done"),
                    read if read == COLLECT_STOP_SAMPLES => pane("working"),
                    _ => pane("unknown"),
                })
            },
            || refusal(code::COLLECT_EMPTY_DELTA, "no committed delta"),
            || elapsed.get(),
            |wait| elapsed.set(elapsed.get() + wait),
        )
        .expect_err("fewer samples than the pinned count never confirm a stop");
        assert_eq!(
            outcome.code.as_deref(),
            Some(code::WORKER_TIMEOUT),
            "the emptiness refusal is only ever a CONFIRMED stop's outcome"
        );
        assert!(
            reads.get() >= COLLECT_STOP_SAMPLES,
            "the pinned count is what the wait reads for"
        );

        // The pinned count in a row — and the second view disagreeing on any
        // of them — never confirms either.
        let elapsed = Cell::new(Duration::ZERO);
        let reads = Cell::new(0usize);
        let outcome = poll_pane_worker(
            Duration::from_millis(6),
            Duration::from_millis(1),
            Duration::from_millis(60),
            |_| {
                reads.set(reads.get() + 1);
                // The lane's own row says `done`; its status row still says the
                // lane is working. One status field is never a stop.
                Ok(pane_sample("done", "working", None))
            },
            || refusal(code::COLLECT_EMPTY_DELTA, "no committed delta"),
            || elapsed.get(),
            |wait| elapsed.set(elapsed.get() + wait),
        )
        .expect_err("a disagreeing second view never confirms a stop");
        assert_eq!(outcome.code.as_deref(), Some(code::WORKER_TIMEOUT));
        assert!(
            reads.get() > COLLECT_STOP_SAMPLES,
            "both views must agree on every sample of the run"
        );

        // A lane whose own lifecycle counter is still moving is not settled
        // either, however many non-working read-backs it reports.
        let elapsed = Cell::new(Duration::ZERO);
        let reads = Cell::new(0usize);
        let outcome = poll_pane_worker(
            Duration::from_millis(6),
            Duration::from_millis(1),
            Duration::from_millis(60),
            |_| {
                let seq = reads.get() as i64;
                reads.set(reads.get() + 1);
                Ok(pane_sample("done", "done", Some(seq)))
            },
            || refusal(code::COLLECT_EMPTY_DELTA, "no committed delta"),
            || elapsed.get(),
            |wait| elapsed.set(elapsed.get() + wait),
        )
        .expect_err("a moving lane is not a settled one");
        assert_eq!(outcome.code.as_deref(), Some(code::WORKER_TIMEOUT));
        assert!(
            reads.get() > COLLECT_STOP_SAMPLES,
            "a counter that keeps moving restarts the stop run"
        );

        // An OLDER row shape that carries no state on the second view
        // corroborates nothing and blocks nothing (the same convention the
        // adapter applies to a missing readiness signal): the stop then rests
        // on the lane's own verified row, the pinned count and the unmoved
        // counter.
        let elapsed = Cell::new(Duration::ZERO);
        let reads = Cell::new(0);
        let outcome = poll_pane_worker(
            Duration::from_secs(6),
            Duration::from_secs(1),
            Duration::from_secs(60),
            |_| {
                reads.set(reads.get() + 1);
                Ok(pane_sample("done", "", None))
            },
            || refusal(code::COLLECT_EMPTY_DELTA, "no committed delta"),
            || elapsed.get(),
            |wait| elapsed.set(elapsed.get() + wait),
        )
        .expect("a stop still confirms without the second view's field");
        assert_eq!(outcome.code.as_deref(), Some(code::COLLECT_EMPTY_DELTA));
        assert_eq!(reads.get(), COLLECT_STOP_SAMPLES as i32);
    }

    /// Issue #170 (N8) witness (c): the wait is bounded by RECORDED PROGRESS,
    /// not a fixed wall clock — a still-working lane past the old 1800 s wall
    /// is NOT parked, and a genuinely silent lane still parks typed within the
    /// no-progress window, naming the progress observed and the elapsed time.
    #[test]
    fn collection_wait_extends_past_the_wall_on_progress_and_parks_a_silent_lane() {
        use std::cell::Cell;
        // The lane keeps working past the whole 1800 s no-progress window (the
        // measured real turn ran ≈93 minutes against exactly this wall) and is
        // still collected at its settled turn.
        let elapsed = Cell::new(Duration::ZERO);
        let reads = Cell::new(0usize);
        let outcome = poll_pane_worker(
            Duration::from_secs(1800),
            Duration::from_secs(10),
            Duration::from_secs(COLLECT_CEILING_SECS),
            |_| {
                reads.set(reads.get() + 1);
                // Working, flapping the way the measured pane did, until the
                // 190th read (t = 1890 s, past the old wall), then settled:
                // a settled lane's own counter stops moving.
                Ok(if reads.get() < 190 {
                    let state = if reads.get().is_multiple_of(2) {
                        "working"
                    } else {
                        "idle"
                    };
                    pane_sample(state, state, Some(reads.get() as i64))
                } else {
                    pane_sample("done", "done", Some(189))
                })
            },
            || {
                if reads.get() < 190 {
                    refusal(code::COLLECT_EMPTY_DELTA, "no committed delta")
                } else {
                    ok(object(vec![
                        ("head", string(&"f".repeat(40))),
                        ("commits", Val::Arr(vec![string(&"f".repeat(40))])),
                    ]))
                }
            },
            || elapsed.get(),
            |wait| elapsed.set(elapsed.get() + wait),
        )
        .expect("a still-working lane past the old wall is not parked");
        assert_eq!(outcome.status, "succeeded");
        assert_eq!(outcome.result.get("head"), Some(&string(&"f".repeat(40))));
        assert!(
            elapsed.get() > Duration::from_secs(1800),
            "the wait must have crossed the old wall: {:?}",
            elapsed.get()
        );

        // A lane that records no progress at all parks within the window.
        let elapsed = Cell::new(Duration::ZERO);
        let reads = Cell::new(0usize);
        let outcome = poll_pane_worker(
            Duration::from_secs(1800),
            Duration::from_secs(10),
            Duration::from_secs(COLLECT_CEILING_SECS),
            |_| {
                reads.set(reads.get() + 1);
                Ok(pane("unknown"))
            },
            || refusal(code::COLLECT_EMPTY_DELTA, "no committed delta"),
            || elapsed.get(),
            |wait| elapsed.set(elapsed.get() + wait),
        )
        .expect_err("a genuinely silent lane parks typed within the window");
        assert_eq!(outcome.status, "ambiguous");
        assert_eq!(outcome.code.as_deref(), Some(code::WORKER_TIMEOUT));
        assert_eq!(elapsed.get(), Duration::from_secs(1800));
        assert_eq!(outcome.result.get("progress_secs"), Some(&integer(1800)));
        assert_eq!(
            outcome.result.get("ceiling_secs"),
            Some(&integer(COLLECT_CEILING_SECS as i64))
        );
        let message = outcome.message.unwrap_or_default();
        assert!(
            message.contains("no recorded progress for 1800s of the 1800s no-progress window"),
            "the park names the window and the elapsed silence: {message}"
        );
    }

    /// Issue #200: a delivery read while the worker is still live is a
    /// WAIT/re-check, never a certification — the unchanged #147 rule for an
    /// empty delta now holds for a delivery too — and the delivery is still
    /// collected once the SAME stop state settles across the pinned read-backs.
    #[test]
    fn collection_delivery_while_live_waits_and_is_collected_once_settled() {
        use std::cell::Cell;
        let elapsed = Cell::new(Duration::ZERO);
        let reads = Cell::new(0);
        let collections = Cell::new(0);
        let outcome = poll_pane_worker(
            Duration::from_millis(6),
            Duration::from_millis(1),
            Duration::from_millis(60),
            |_| {
                reads.set(reads.get() + 1);
                Ok(pane(if reads.get() <= 3 { "working" } else { "idle" }))
            },
            || {
                collections.set(collections.get() + 1);
                if collections.get() < 3 {
                    refusal(code::COLLECT_EMPTY_DELTA, "no committed delta")
                } else {
                    ok(object(vec![(
                        "changed_files",
                        Val::Arr(vec![string("delivery.txt")]),
                    )]))
                }
            },
            || elapsed.get(),
            |wait| elapsed.set(elapsed.get() + wait),
        )
        .expect("a delivery is collected at the settled turn");
        assert_eq!(outcome.status, "succeeded");
        assert_eq!(
            outcome.result.get("changed_files"),
            Some(&Val::Arr(vec![string("delivery.txt")]))
        );
        assert_eq!(
            reads.get(),
            6,
            "the delivery read while working (read 3) never certifies"
        );
        assert_eq!(collections.get(), 6, "no bound is consumed by waiting");
        assert_eq!(elapsed.get(), Duration::from_millis(5));
    }

    /// Issue #200 (a): a worker that commits AFTER the outcome is read (the
    /// measured p4→p5 boundary: the head `38fb0929` was certified and the SAME
    /// worker committed `0d5e851b` 26 s later) must yield the FINAL settled
    /// head, never the head read first.
    #[test]
    fn collection_certifies_the_final_settled_head_never_an_earlier_read() {
        use std::cell::Cell;
        let elapsed = Cell::new(Duration::ZERO);
        let reads = Cell::new(0);
        let mut heads: Vec<String> = Vec::new();
        let outcome = poll_pane_worker(
            Duration::from_millis(8),
            Duration::from_millis(1),
            Duration::from_millis(60),
            |_| {
                reads.set(reads.get() + 1);
                Ok(pane(if reads.get() <= 3 { "working" } else { "done" }))
            },
            || {
                // Head A is read while the worker is still mid-turn; the
                // worker's later commit is head B at its settled turn.
                let head = if reads.get() <= 3 { "a" } else { "b" }.repeat(40);
                heads.push(head.clone());
                ok(object(vec![
                    ("head", string(&head)),
                    ("changed_files", Val::Arr(vec![string("delivery.txt")])),
                ]))
            },
            || elapsed.get(),
            |wait| elapsed.set(elapsed.get() + wait),
        )
        .expect("the settled turn certifies the delivery");
        assert_eq!(outcome.status, "succeeded");
        assert_eq!(
            outcome.result.get("head"),
            Some(&string(&"b".repeat(40))),
            "the certified head is the final settled head"
        );
        assert!(
            heads.contains(&"a".repeat(40)),
            "the earlier head was genuinely read while the worker was still live"
        );
        assert_eq!(reads.get(), 6, "a live read is never a certification");
        assert_eq!(elapsed.get(), Duration::from_millis(5));
    }

    #[test]
    fn collection_confirmed_stopped_empty_still_refuses() {
        use std::cell::Cell;
        for state in ["idle", "done", "blocked"] {
            let elapsed = Cell::new(Duration::ZERO);
            let reads = Cell::new(0);
            let outcome = poll_pane_worker(
                Duration::from_millis(6),
                Duration::from_millis(1),
                Duration::from_millis(60),
                |_| {
                    reads.set(reads.get() + 1);
                    Ok(pane(state))
                },
                || refusal(code::COLLECT_EMPTY_DELTA, "no committed delta"),
                || elapsed.get(),
                |wait| elapsed.set(elapsed.get() + wait),
            )
            .expect("a confirmed stopped worker settles before the window");
            assert_eq!(outcome.status, "refused");
            assert_eq!(outcome.code.as_deref(), Some(code::COLLECT_EMPTY_DELTA));
            assert_eq!(
                reads.get(),
                COLLECT_STOP_SAMPLES as i32,
                "the stop is confirmed across the PINNED number of read-backs"
            );
            assert_eq!(
                elapsed.get(),
                Duration::from_millis(COLLECT_STOP_SAMPLES as u64 - 1),
                "the samples are separated by the real interval, not by iterations"
            );
        }
    }

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
        assert_eq!(effect_deadline_secs("collect_outcome", None).unwrap(), 1800);
        // Issue #217: the review verdict wait carries its own documented row
        // at the prompt tier — never the generic 60 s I/O default.
        assert_eq!(
            effect_deadline_secs("review_evidence", None).expect("default"),
            REVIEW_DEADLINE_DEFAULT_SECS
        );
        assert_eq!(REVIEW_DEADLINE_DEFAULT_SECS, PROMPT_DEADLINE_DEFAULT_SECS);
        assert!(
            effect_deadline_secs("review_evidence", None).expect("default")
                > EFFECT_DEADLINE_DEFAULT_SECS,
            "the review bound is never the generic I/O default"
        );
        // Issue #224: the cleanup step's bounded wait for a lane that outlived
        // its own publish carries its own documented row at the prompt tier —
        // the generic 60 s I/O row would park a run whose publish already
        // SUCCEEDED.
        assert_eq!(
            effect_deadline_secs("cleanup", None).expect("default"),
            CLEANUP_DEADLINE_DEFAULT_SECS
        );
        assert_eq!(CLEANUP_DEADLINE_DEFAULT_SECS, PROMPT_DEADLINE_DEFAULT_SECS);
        assert!(
            effect_deadline_secs("cleanup", None).expect("default") > EFFECT_DEADLINE_DEFAULT_SECS,
            "the cleanup lane wait is never the generic I/O default"
        );
        assert_eq!(
            bounded_effect_deadline("review_evidence", None),
            Some(REVIEW_DEADLINE_DEFAULT_SECS)
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

    // Issue #217: the verdict wait ONE `review_evidence` attempt opens. A
    // fresh attempt waits the step's effective bound; an attempt that RESUMES
    // this step's own proven delivery (the reviewer leg is up and already
    // carries the brief, issue #214) renews the wait under the documented
    // overall ceiling; a declared `deadline_secs` is the plan's own policy and
    // is never overridden, resumed or not.
    #[test]
    fn a_resumed_review_wait_renews_under_the_overall_ceiling_and_never_overrides_policy() {
        assert_eq!(
            review_verdict_wait_secs(REVIEW_DEADLINE_DEFAULT_SECS, false, false),
            REVIEW_DEADLINE_DEFAULT_SECS,
            "a fresh attempt waits the documented review bound"
        );
        assert_eq!(
            review_verdict_wait_secs(REVIEW_DEADLINE_DEFAULT_SECS, false, true),
            EFFECT_DEADLINE_CEILING_SECS,
            "a resumed attempt renews the wait under the documented ceiling"
        );
        assert!(
            review_verdict_wait_secs(REVIEW_DEADLINE_DEFAULT_SECS, false, true)
                <= EFFECT_DEADLINE_CEILING_SECS,
            "the renewed wait never leaves the documented ceiling"
        );
        assert_eq!(
            review_verdict_wait_secs(1, true, true),
            1,
            "a declared deadline is the plan's reviewed policy: never renewed"
        );
        assert_eq!(review_verdict_wait_secs(1, true, false), 1);
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

    /// Issue #279: a plan admitted BEFORE #269 stores a `reviewer_profile` with
    /// no `skills` entry, and the review step's own param contract — the same
    /// pure pre-screen the daemon evaluates before anything is journaled —
    /// accepts it, so a run parked at its review step is never refused for a
    /// document the product itself wrote. Both fingerprints the engine reads
    /// (the preset material and the round-trip document) are derived here, from
    /// the material WITHOUT that entry, never by the code under test.
    #[test]
    fn a_stored_pre_269_reviewer_binding_passes_the_review_contract() {
        let material = object(vec![
            ("schema", string(crate::config::PROFILE_BINDING_SCHEMA)),
            ("key", string("lane-role")),
            ("kind", string("argv")),
            ("provider", string("provider-a")),
            ("model", string("model-a")),
            ("fallbacks", Val::Arr(Vec::new())),
            ("configured_limits", object(vec![])),
            ("introspection", bool_(false)),
            ("secrets", Val::Arr(Vec::new())),
        ]);
        let revision = crate::canonical::sha256_hex(&crate::canonical::canonical_bytes(&material));
        let mut reviewer = material;
        if let Val::Obj(map) = &mut reviewer {
            map.insert("revision".to_string(), string(&revision));
        }
        let contract = ParamContract {
            observed_feature_head: Some("1111111111111111111111111111111111111111"),
            observed_integration_base: Some("2222222222222222222222222222222222222222"),
            ..ParamContract::default()
        };
        let params = object(vec![
            ("harness_key", string("lane-role")),
            ("executable", string("hf-reviewer-example")),
            ("kind", string("argv")),
            ("execution", string("headless")),
            ("worktree", string("lane-7")),
            ("reviewer_profile", reviewer.clone()),
        ]);
        let inputs = review_evidence_inputs(Some(&params), &contract)
            .expect("a stored pre-#269 reviewer binding is accepted");
        match inputs.shape {
            ReviewEvidenceShape::SelfDispatch(leg) => {
                assert_eq!(leg.profile.key, "lane-role");
                assert_eq!(
                    leg.profile.revision, revision,
                    "the binding keeps the revision it was approved under"
                );
                assert!(
                    leg.profile.skills.is_empty(),
                    "an absent key resolves to the empty array"
                );
                // The engine re-renders the accepted document into its own
                // outcome: it round-trips unchanged.
                assert_eq!(leg.profile.to_doc(), reviewer);
            }
            ReviewEvidenceShape::Presented(_) => panic!("the step declares the reviewer leg"),
        }
        // The malformed directions are unchanged at this same contract: a
        // present-but-wrong `skills` value still refuses typed.
        let mut malformed = params.clone();
        if let Val::Obj(map) = &mut malformed
            && let Some(Val::Obj(profile)) = map.get_mut("reviewer_profile")
        {
            profile.insert("skills".to_string(), string("lane-implementer"));
        }
        let refused = check_step_params("review_evidence", Some(&malformed), &contract)
            .expect_err("a present string skills refuses");
        assert_eq!(refused.0, crate::config::CODE_PROFILE_BINDING);
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

    /// Issue #176: a landing PUBLISHES to the integration ref, so a topology
    /// whose integration branch is a production branch is refused before any
    /// work — production promotion stays human-gated.
    #[test]
    fn merge_inputs_never_publishes_to_a_production_integration_branch() {
        let main_only = vec!["main".to_string()];
        let params = object(vec![
            ("branch", string("issue-1")),
            ("merge_policy", string("squash")),
        ]);
        // `main` is production even when it is not declared.
        let contract = ParamContract {
            integration_branch: "main",
            production_branches: &main_only,
            ..ParamContract::default()
        };
        let refused =
            merge_inputs(Some(&params), &contract).expect_err("main is never a landing target");
        assert_eq!(refused.code.as_deref(), Some(code::PUSH_POLICY));
        assert!(
            refused
                .message
                .as_deref()
                .unwrap_or_default()
                .contains("production"),
            "{refused:?}"
        );
        // A DECLARED production integration branch is refused too.
        let declared = vec!["main".to_string(), "release".to_string()];
        let contract = ParamContract {
            integration_branch: "release",
            production_branches: &declared,
            ..ParamContract::default()
        };
        assert_eq!(
            merge_inputs(Some(&params), &contract)
                .expect_err("declared production refused")
                .code
                .as_deref(),
            Some(code::PUSH_POLICY)
        );
        // The ordinary integration branch still resolves.
        let contract = ParamContract {
            integration_branch: "staging",
            production_branches: &declared,
            ..ParamContract::default()
        };
        assert!(merge_inputs(Some(&params), &contract).is_ok());
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

    /// Issue #230: a recorded non-`passed` check refuses its consumer with the
    /// SAME typed code it always did (never weakened) and now NAMES itself; and
    /// the consumer reads the newest record — so a RE-EVALUATED record at the
    /// same head/base passes, while the frozen one never does. The recompute
    /// is a new record, never an edit of the old one.
    #[test]
    fn a_non_passing_check_refuses_the_consumer_and_names_itself() {
        let base = EvidenceView {
            evidence_id: "ev_0123456789abcdef".to_string(),
            feature_head: "a".repeat(40),
            integration_base: "b".repeat(40),
            workflow_hash: "0".repeat(64),
            policy_hash: "f".repeat(64),
            verdict: "pass".to_string(),
            reviewer: "reviewer-1".to_string(),
            checks: r#"[{"name":"hosted-ci","status":"passed"},{"name":"local_cargo_test_aggregate","status":"failed"}]"#
                .to_string(),
            created_at: "2026-09-06T00:00:00Z".to_string(),
        };
        let refused = check_merge_evidence(
            Some(&base),
            &"a".repeat(40),
            &"b".repeat(40),
            &"0".repeat(64),
            &"f".repeat(64),
        )
        .expect_err("a non-passing check refuses the merge");
        assert_eq!(
            refused.code,
            code::EVIDENCE_FAILED,
            "the same typed code the gate always returned"
        );
        assert!(
            refused
                .message
                .contains("local_cargo_test_aggregate=failed"),
            "the refusal names the check that is not passing: {}",
            refused.message
        );
        assert_eq!(
            non_passing_checks(&base).expect("failing set"),
            vec!["local_cargo_test_aggregate=failed".to_string()]
        );
        assert_eq!(
            non_passing_checks(&base).expect("failing set").len(),
            1,
            "only the non-passing check is named"
        );
        // The RE-EVALUATED record — same head, same base, the checks the
        // producer recomputed — is what the consumer reads next.
        let reevaluated = EvidenceView {
            evidence_id: "ev_fedcba9876543210".to_string(),
            checks: r#"[{"name":"hosted-ci","status":"passed"},{"name":"local_cargo_test_aggregate","status":"passed"}]"#
                .to_string(),
            created_at: "2026-09-06T01:00:00Z".to_string(),
            ..base.clone()
        };
        assert!(
            check_merge_evidence(
                Some(&reevaluated),
                &"a".repeat(40),
                &"b".repeat(40),
                &"0".repeat(64),
                &"f".repeat(64),
            )
            .is_ok(),
            "a recomputed record at the same certified head passes the gate"
        );
        assert!(
            non_passing_checks(&reevaluated)
                .expect("failing set")
                .is_empty()
        );
        // ...and a recomputation that comes back FAILING refuses exactly as
        // the first one did (nothing was upgraded or waived).
        let still_failing = EvidenceView {
            checks: r#"[{"name":"local_cargo_test_aggregate","status":"failed"},{"name":"hosted-ci","status":"passed"}]"#
                .to_string(),
            created_at: "2026-09-06T02:00:00Z".to_string(),
            ..base
        };
        assert_eq!(
            check_merge_evidence(
                Some(&still_failing),
                &"a".repeat(40),
                &"b".repeat(40),
                &"0".repeat(64),
                &"f".repeat(64),
            )
            .expect_err("still failing")
            .code,
            code::EVIDENCE_FAILED
        );
    }

    /// B1 (fix round F1): the evidence predicate must decide on the recorded
    /// STATUS alone. The base predicate was a total `all(status == "passed")`,
    /// so EVERY item that was not exactly `passed` made the record
    /// non-passing; a `?` on the presentation field `name` silently DROPS such
    /// an item and lets a nameless `failed` check PASS the publish gate the
    /// base refused. The matrix is the reviewer's probe verbatim, adjudicated
    /// in ONE aggregate assert so a regression names every leg it flipped.
    #[test]
    fn a_nameless_failed_check_never_passes_the_evidence_gate() {
        let view_of = |checks: &str| EvidenceView {
            evidence_id: "ev_0123456789abcdef".to_string(),
            feature_head: "a".repeat(40),
            integration_base: "b".repeat(40),
            workflow_hash: "0".repeat(64),
            policy_hash: "f".repeat(64),
            verdict: "pass".to_string(),
            reviewer: "reviewer-1".to_string(),
            checks: checks.to_string(),
            created_at: "2026-09-06T00:00:00Z".to_string(),
        };
        let matrix = [
            ("named_failed", r#"[{"name":"local","status":"failed"}]"#),
            ("NO_NAME_failed", r#"[{"status":"failed"}]"#),
            ("NONSTRING_NAME_failed", r#"[{"name":7,"status":"failed"}]"#),
            ("NULL_NAME_failed", r#"[{"name":null,"status":"failed"}]"#),
            (
                "mixed_passed_plus_nameless_failed",
                r#"[{"name":"hosted-ci","status":"passed"},{"status":"failed"}]"#,
            ),
            ("named_no_status", r#"[{"name":"local"}]"#),
        ];
        let mut flipped = Vec::new();
        for (label, checks) in matrix {
            let view = view_of(checks);
            let passed = evidence_checks_passed(&view).expect("predicate");
            let gate = check_merge_evidence(
                Some(&view),
                &"a".repeat(40),
                &"b".repeat(40),
                &"0".repeat(64),
                &"f".repeat(64),
            )
            .err()
            .map(|err| err.code);
            if passed || gate != Some(code::EVIDENCE_FAILED) {
                flipped.push(format!(
                    "{label}: evidence_checks_passed={passed:?} merge_gate={gate:?}"
                ));
            }
        }
        assert!(
            flipped.is_empty(),
            "a non-passing check whose name is absent, null or not a string must still \
             refuse — the base predicate refused it: {flipped:?}"
        );
        // The rendering half: a nameless non-passing check is still NAMED (a
        // fallback), so the refusal stays actionable for an operator.
        assert_eq!(
            non_passing_checks(&view_of(r#"[{"status":"failed"}]"#)).expect("failing set"),
            vec!["unnamed=failed".to_string()],
            "a nameless non-passing check is rendered with a fallback name"
        );
        // ...and the fallback is presentation only: a record whose checks are
        // ALL `passed` still passes, with or without names (no relaxation in
        // the other direction).
        assert!(
            check_merge_evidence(
                Some(&view_of(
                    r#"[{"name":"hosted-ci","status":"passed"},{"status":"passed"}]"#
                )),
                &"a".repeat(40),
                &"b".repeat(40),
                &"0".repeat(64),
                &"f".repeat(64),
            )
            .is_ok(),
            "an all-`passed` record still passes, nameless or not"
        );
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

    /// Issue #219: every distinguishable publish failure gets its OWN typed
    /// code — a refused direct push (repository rules), a credential that
    /// cannot be read, a ref that moved (non-fast-forward) — and only a
    /// genuinely unclassifiable failure keeps the caller's generic code.
    #[test]
    fn publish_failures_are_classified_into_their_own_typed_codes() {
        // The measured live shape: the forge's own rule refusal.
        let live = "the landing a5cb07a7 was not published to \"staging\": git (cwd /tmp/x) \
                    exited with code 1: To https://example.invalid/o/r.git | ! \
                    a5cb07a7:refs/heads/staging [remote rejected] (push declined due to \
                    repository rule violations)";
        assert_eq!(
            classify_publish_failure(live, code::MERGE_FAILED),
            code::MERGE_PUSH_REJECTED
        );
        // A protected branch hook declines the update the same way.
        assert_eq!(
            classify_publish_failure(
                "remote: error: protected branch hook declined",
                code::MERGE_FAILED
            ),
            code::MERGE_PUSH_REJECTED
        );
        // A credential that cannot be read is never a policy refusal.
        assert_eq!(
            classify_publish_failure(
                "fatal: could not read Username for 'https://example.invalid': terminal prompts disabled",
                code::MERGE_FAILED
            ),
            code::CREDENTIAL_MISSING
        );
        assert_eq!(
            classify_publish_failure(
                "Permission denied (publickey).\nfatal: Could not read from remote repository.",
                code::MERGE_FAILED
            ),
            code::CREDENTIAL_MISSING
        );
        // A ref that moved under the landing is the non-fast-forward class.
        assert_eq!(
            classify_publish_failure(
                "! [rejected]        head -> staging (non-fast-forward)",
                code::MERGE_FAILED
            ),
            code::MERGE_NOT_FF
        );
        assert_eq!(
            classify_publish_failure(
                "Updates were rejected because the remote contains work that you do not have locally (fetch first)",
                code::MERGE_FAILED
            ),
            code::MERGE_NOT_FF
        );
        // Receiving-side failures that are NOT a policy refusal keep the
        // generic code: a read-only remote's `unpacker error` out of an
        // otherwise ordinary `[remote rejected]` report, and a local failure
        // that never reached the remote.
        assert_eq!(
            classify_publish_failure(
                "To /tmp/origin.git | ! abc:refs/heads/staging [remote rejected] (unpacker error)",
                code::MERGE_FAILED
            ),
            code::MERGE_FAILED
        );
        assert_eq!(
            classify_publish_failure(
                "error: failed to push some refs to '/tmp/origin.git'",
                code::MERGE_FAILED
            ),
            code::MERGE_FAILED
        );
    }

    /// Issue #219: the declared publish route must be able to honour the
    /// step's declared policy — a pull-request publish lands the forge's
    /// squash merge and refuses to pretend it performed an `ff` landing.
    #[test]
    fn a_pull_request_route_refuses_a_merge_policy_it_cannot_honour() {
        let production = vec!["main".to_string()];
        let ff = object(vec![
            ("branch", string("issue-1")),
            ("merge_policy", string("ff")),
        ]);
        let squash = object(vec![
            ("branch", string("issue-1")),
            ("merge_policy", string("squash")),
        ]);
        let contract = ParamContract {
            integration_branch: "staging",
            production_branches: &production,
            publish_route: INTEGRATION_PUBLISH_PULL_REQUEST,
            ..ParamContract::default()
        };
        let refused =
            merge_inputs(Some(&ff), &contract).expect_err("an ff landing has no PR equivalent");
        assert_eq!(refused.code.as_deref(), Some(code::PUBLISH_POLICY));
        assert!(
            refused
                .message
                .as_deref()
                .unwrap_or_default()
                .contains("pull_request"),
            "{refused:?}"
        );
        let inputs = merge_inputs(Some(&squash), &contract).expect("squash is the PR landing");
        assert_eq!(inputs.route, INTEGRATION_PUBLISH_PULL_REQUEST);
        // A topology that declares no route (and every contract that predates
        // it) keeps the documented default.
        let defaulted = ParamContract {
            integration_branch: "staging",
            production_branches: &production,
            ..ParamContract::default()
        };
        assert_eq!(
            merge_inputs(Some(&ff), &defaulted)
                .expect("the push route keeps ff")
                .route,
            INTEGRATION_PUBLISH_DEFAULT
        );
    }
}
