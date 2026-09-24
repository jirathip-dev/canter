//! Supervised reconciliation driver (issue #95): durable, event-driven
//! evaluation and bounded dispatch of explicitly authorized runs, with a
//! timer fallback.
//!
//! Scope of this slice, stated positively and negatively:
//!
//! - Supervision is **disabled by default**: a run is supervised only when
//!   an explicit `hf-supervision-authorization/v1` block was presented as
//!   part of its queue submission (#85) and committed with it. The
//!   authorization binds the approved preview digest, so a run whose
//!   recorded binding no longer matches (unapproved/drifted plan) is
//!   classified `unknown`/held and is never eligible.
//! - The driver **evaluates and reports** and dispatches an armed run's first
//!   and next unattempted autonomous step through the daemon's existing apply
//!   engine. That preserves the committed grant, capability, admission,
//!   ownership, topology, journal and idempotency gates; a diagnosed step is
//!   re-dispatched only within the shared bounded retry budget (issue #179),
//!   and an authorization the run already holds is consumed by that
//!   re-dispatch, exactly once (issue #241).
//! - It also drives the risk-classed TAIL of a run whose own committed queue
//!   submission declares it (issue #152: the merge of its reviewed head, then
//!   the cleanup of its lane worktree), so the spine that produced a verified
//!   delivery reaches its own last committed step instead of being foreclosed
//!   by the delivery. That capability is NOT a blanket allow-list entry: it is
//!   the typed [`driver_dispatchable_kind`] decision — an admitted membership
//!   of a committed submission, the run's own approved caps carrying the
//!   kind's capability, and a step that follows that run's verified delivery.
//!   The dispatch still presents the step's OWN committed params, and the
//!   engine's unchanged contract/authority gates decide.
//! - A continuation the apply engine REFUSES before its claim (a fan-out
//!   admission refusal, a derived request the pre-screen rejects) leaves no
//!   attempt of its own, so the driver records it against the run (issue
//!   #141) and the classification reports the engine's own code as a named
//!   blocker instead of claiming the frontier is an eligible continuation.
//! - It also performs exactly ONE queue-continuation effect (issue #96): when
//!   the recorded evidence of an
//!   authorized run is a fresh VERIFIED delivery (reviewed `pass` with every
//!   named check `passed` at the recorded delivered head, bound to the run's
//!   own workflow/policy pins), the driver advances that run's
//!   already-authorized queue cursor — once per delivered issue — and admits
//!   the next eligible approved issue of the SAME committed submission under
//!   the existing admission and ownership checks. It never resumes a pause,
//!   never retries a diagnosed step past the shared bounded retry budget and
//!   never clears a hold.
//! - A duplicate delivery event, a replayed check or a crash/restart never
//!   duplicates a dispatch: the advance is keyed to the delivered issue
//!   (one consumption per submission item, ever) and the cursor is derived
//!   from the durable advance rows.
//! - Every classification is derived from **recorded evidence** re-read from
//!   the daemon state (run row, ownership, committed submission, bound step
//!   spine, recorded step attempts with their typed outcome codes, review
//!   evidence, bounded retries, in-flight claims). Evidence that is missing
//!   or stale stays `unknown`/held; an idle or `done` agent alone is neither
//!   completion nor permission to resume.
//! - Wakes are **coalesced per run**: semantic completion/review/CI events
//!   (folded from the durable event stream) and the bounded timer fallback
//!   both feed ONE pending trigger per run, so duplicate, out-of-order and
//!   concurrent timer/event wakes produce exactly one run-scoped
//!   reconciliation.
//! - The meaningful-progress marker moves only when recorded evidence
//!   actually changed: reads, heartbeats and rendered status never reset it,
//!   so the progress timeout identifies the **absence of evidence**, not
//!   useful reasoning, and long-running work or known waits never re-report
//!   a continuation. A run with NO recorded observation yet is **held**
//!   (`unknown` / `supervision.progress_unobserved`, never eligible): an
//!   unobserved run is not a timed-out one, so a fresh arm can never open a
//!   continuation window.
//! - Reads report **committed** state: `supervision.status` renders the
//!   recorded result of the last committed check as `class`/`reason`/
//!   `eligible`, carries the read-time re-classification separately as
//!   `observed`, and keeps the continuation block as durable window state.
//!   A read can therefore never re-classify to a friendlier class and hide a
//!   committed counter.
//! - All time arithmetic takes `now_unix` as an explicit argument (the same
//!   design as `crate::lifecycle`): wall-clock movement and sleep surface as
//!   jumps of that argument and re-anchor the next eligible check to the
//!   future, so a jump yields one fresh reconciliation instead of catch-up
//!   effects. No injectable clock type exists by design.
//!
//! The daemon owns the state transactions and the thread; this module owns
//! the policy, the pure classification and the driver loop that takes the
//! state guard only for short reads and writes (never across a wait).

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::canonical::{canonical_bytes, sha256_hex};
use crate::formats;
use crate::state::{
    State, StateError, SupervisionCheckPlan, SupervisionEvidence, SupervisionRow,
    SupervisionTriggerRow,
};
use crate::time;
use crate::value::{Val, bool_, integer, null, object, string};

/// The supervision status document schema id (module-local, exactly like
/// `hf-run-control/v1` (#86) and `hf-queue-submission/v1` (#85)).
pub const SUPERVISION_SCHEMA: &str = "hf-supervision/v1";

/// The authorization document schema id presented inside `queue.submit`
/// params (module-local).
pub const AUTHORIZATION_SCHEMA: &str = "hf-supervision-authorization/v1";

/// Closed desired-supervision vocabulary. `armed` evaluates and dispatches
/// supported unattempted steps; `disabled` is
/// an explicit recorded decision NOT to supervise (the default when no
/// authorization block is presented at all is no row).
pub const DESIRED: [&str; 2] = ["armed", "disabled"];

/// Closed classification vocabulary (issue #95 AC3).
pub const CLASSES: [&str; 11] = [
    "healthy",
    "waiting-workers",
    "worker-timeout",
    "waiting-CI",
    "waiting-approval",
    "blocked-capacity",
    "continuation-eligible",
    "paused",
    "completed",
    "needs-attention",
    "unknown",
];

/// Closed wake vocabulary: the semantic class of the event that opened (or
/// refreshed) one run's pending trigger.
pub const TRIGGERS: [&str; 7] = [
    "boot",
    "completion",
    "review",
    "ci",
    "control",
    "timer",
    "snapshot",
];

/// The statement every supervision document carries: what this surface does
/// and provably does NOT do.
pub const STATEMENT: &str = "an explicitly armed run is classified from recorded evidence and each unattempted autonomous next step — plus the risk-classed merge then cleanup tail of a run whose own committed queue submission declares it after that run's verified delivery — is dispatched through the existing apply engine with the committed grant, capability, admission, ownership, topology, journal and idempotency gates; a continuation the engine refuses before any effect is reported with the engine's own code and is never presented as an eligible next step; a fresh verified reviewed-and-CI-green delivery advances its authorized queue cursor exactly once under the same admission and ownership checks; when the run's own newest recorded review evidence carries a non-passing check the driver drives the run's OWN bounded, attributed and journaled check re-evaluation — the producer is re-run on a fresh lane round, never adjudicated, and the tail behind the unverified delivery stays undriven; supervision never resumes a pause, never retries a diagnosed step past the shared bounded retry budget (an authorization the run already holds is consumed by that re-dispatch, exactly once), invents missing inputs or clears a hold";

/// Default bounded timer fallback cadence (seconds).
pub const DEFAULT_CHECK_INTERVAL_SECS: i64 = 60;

/// Default meaningful-progress window (seconds).
pub const DEFAULT_PROGRESS_TIMEOUT_SECS: i64 = 900;

/// Lower bound of a presented check interval.
pub const MIN_CHECK_INTERVAL_SECS: i64 = 5;

/// Upper bound of a presented check interval.
pub const MAX_CHECK_INTERVAL_SECS: i64 = 3600;

/// Lower bound of a presented progress timeout.
pub const MIN_PROGRESS_TIMEOUT_SECS: i64 = 60;

/// Upper bound of a presented progress timeout.
pub const MAX_PROGRESS_TIMEOUT_SECS: i64 = 86_400;

/// Freshness margin added to the check interval: a status older than
/// `interval + margin` reports `stale` (the driver is not keeping up).
pub const FRESHNESS_MARGIN_SECS: i64 = 300;

/// Bound on the event rows one fold pass reads (retention is bounded too).
pub const WAKE_MAX_ROWS: usize = 512;

/// Upper bound on one driver wait between ticks, so an idle daemon still
/// re-anchors its clock and notices a stopped driver promptly.
pub const DEFAULT_MAX_WAIT_SECS: i64 = 60;

/// The step-kind classes the classification reads (closed effect kinds of
/// `crate::mutation`), grouped by the evidence source they wait on.
const WORKER_STEP_KINDS: [&str; 3] = ["harness_start", "prompt", "collect_outcome"];
const CI_STEP_KINDS: [&str; 2] = ["hosted_check", "post_merge_verify"];
const APPROVAL_STEP_KINDS: [&str; 2] = ["approve", "review_evidence"];
const AUTONOMOUS_STEP_KINDS: [&str; 6] = [
    "checkout",
    "worktree_create",
    "harness_start",
    "prompt",
    "collect_outcome",
    "hosted_check",
];

/// The risk-classed TAIL kinds a supervised run may drive on its OWN
/// committed spine (issue #152): the merge of its reviewed head (the closed
/// policy LANDING that publishes it — a control-plane mutation) and the
/// cleanup of its lane worktree (destructive: it removes a worktree whose
/// branch is provably merged).
///
/// They are deliberately NOT members of [`AUTONOMOUS_STEP_KINDS`]: an armed
/// run's ordinary work is dispatched unconditionally, while these two are
/// driven only under the typed conditions in [`driver_dispatchable_kind`] —
/// the run's own committed, digest-bound queue submission declares the step,
/// the run's own approved caps carry its capability, and the step is the tail
/// that follows that run's verified delivery. No blanket allow-list entry,
/// no widened cap and no bypass is involved.
const COMMITTED_TAIL_STEP_KINDS: [&str; 2] = ["merge", "cleanup"];

/// The run's own committed capability set (the instance row's caps array).
fn run_caps(evidence: &SupervisionEvidence) -> Vec<String> {
    crate::value::Val::parse_json(&evidence.run.caps)
        .ok()
        .and_then(|caps| caps.as_array().cloned())
        .map(|caps| {
            caps.iter()
                .filter_map(|cap| cap.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// The spine index of one run's reviewed-evidence step (`None` when the
/// committed spine carries none): the step whose committed record IS the
/// delivery (issue #152, and the frontier fact of issue #192).
pub fn delivery_step_index(steps: &[(String, String)]) -> Option<usize> {
    steps
        .iter()
        .rposition(|(_, kind)| kind == crate::mutation::DELIVERY_STEP_KIND)
}

/// Whether ONE committed spine step comes AFTER the run's reviewed-evidence
/// step: the delivery whose tail the step completes (issue #152).
fn after_delivery_step(evidence: &SupervisionEvidence, step: &str) -> bool {
    let Some(delivering) = delivery_step_index(&evidence.steps) else {
        return false;
    };
    match evidence.steps.iter().position(|(id, _)| id == step) {
        Some(index) => index > delivering,
        None => false,
    }
}

/// Whether ONE committed spine step declares the reviewer LEG (issue #193):
/// the step's own reviewed params name the registry-resolved reviewer binding
/// the engine dispatches itself. Read from the committed bound-input
/// document, so an unapproved or drifted spine can never authorize it.
fn declares_reviewer_leg(evidence: &SupervisionEvidence, step: &str) -> bool {
    evidence
        .reviewer_leg_steps
        .iter()
        .any(|declared| declared == step)
}

/// Whether one run's recorded frontier has REACHED its own reviewed-evidence
/// step (issue #192): the `review_evidence` step of the committed spine is
/// the run's next unachieved step, or is already achieved. Such a run
/// carries a verified spine (its recorded delivery included) that a
/// candidate rebuild must never discard, so it is carried forward to its own
/// committed merge/cleanup tail instead of being superseded.
///
/// Fail closed toward preservation: an exhausted spine has reached the step,
/// while a spine without a `review_evidence` step — or a frontier outside the
/// spine — never matches, and an unprovable frontier is only ever read as
/// "reached" when the spine itself proves it. Replacing a preserved run stays
/// possible through the explicit, audited `run.release` control.
pub fn frontier_reached_review(steps: &[(String, String)], frontier: Option<&str>) -> bool {
    let Some(delivering) = delivery_step_index(steps) else {
        return false;
    };
    match frontier {
        // The spine is exhausted: every committed step, the reviewed-evidence
        // step included, is achieved.
        None => true,
        Some(step) => steps
            .iter()
            .position(|(id, _)| id == step)
            .is_some_and(|index| index >= delivering),
    }
}

/// Whether the driver may dispatch ONE kind of ONE step for this run
/// (issue #152, extended by issue #193).
///
/// The unattended continuation set ([`AUTONOMOUS_STEP_KINDS`]) is
/// unconditional: those steps are the run's ordinary committed work. Two
/// further groups are authorized by the run's OWN committed submission
/// instead, and only when every one of these holds:
///
/// - the run is an ADMITTED member of a committed, digest-bound queue
///   submission (`evidence.item`): the spine is an approved plan, never an
///   ad-hoc run;
/// - the run's own committed caps carry the kind's required capability
///   (`review` / `merge` / `cleanup`) — the very capability
///   `revalidate_effect` demands at effect time, so the driver never attempts
///   what the run was not granted and no cap is widened here;
/// - the review step's OWN committed params declare the reviewer leg (issue
///   #193): the run dispatches its own reviewer instead of waiting for a lane
///   an operator hand-dispatches. A review step that declares no reviewer leg
///   is untouched by the driver — the operator's own path stays exactly as it
///   was, and nothing is inferred;
/// - the risk-classed TAIL kinds ([`COMMITTED_TAIL_STEP_KINDS`]) come AFTER
///   the run's reviewed-evidence step in the committed spine and that run
///   carries a fresh VERIFIED delivery ([`verified_delivery`]): the tail is
///   driven only behind the delivery it completes, so a destructive cleanup
///   can never be driven for a run that never delivered.
///
/// The step's parameters are never invented here: the dispatch presents the
/// committed step's OWN declared params verbatim (branch + `merge_policy` for
/// the merge, branch + worktree for the cleanup, the reviewer binding for the
/// review), which the engine's own `check_step_params`/`revalidate_effect`
/// then validates — the same production-branch, policy, cleanup-ancestry,
/// dirty-worktree and reviewer-identity gates as an operator dispatch. A step
/// already ATTEMPTED stays the operator's: the caller re-checks the attempt
/// ledger, so a diagnosed tail is never retried.
pub fn driver_dispatchable_kind(evidence: &SupervisionEvidence, step: &str, kind: &str) -> bool {
    if AUTONOMOUS_STEP_KINDS.contains(&kind) {
        return true;
    }
    if evidence.item.is_none() {
        return false;
    }
    if kind == crate::mutation::DELIVERY_STEP_KIND {
        let Some(capability) = crate::mutation::required_capability(kind) else {
            return false;
        };
        return run_caps(evidence).iter().any(|cap| cap == capability)
            && declares_reviewer_leg(evidence, step);
    }
    if !COMMITTED_TAIL_STEP_KINDS.contains(&kind) {
        return false;
    }
    let Some(capability) = crate::mutation::required_capability(kind) else {
        return false;
    };
    if !run_caps(evidence).iter().any(|cap| cap == capability) {
        return false;
    }
    verified_delivery(evidence).is_some() && after_delivery_step(evidence, step)
}

/// Stable supervision codes: `usage.supervision.*` for presented shape
/// errors, `supervision.*` for recorded-evidence classifications.
pub mod codes {
    /// The authorization block is not the closed shape.
    pub const AUTHORIZATION: &str = "usage.supervision.authorization";
    /// The presented desired state is outside the closed set.
    pub const DESIRED: &str = "usage.supervision.desired";
    /// The presented check interval is outside its bounds.
    pub const INTERVAL: &str = "usage.supervision.interval";
    /// The presented progress timeout is outside its bounds.
    pub const TIMEOUT: &str = "usage.supervision.timeout";
    /// The addressed identity is not a run.
    pub const TARGET: &str = "usage.supervision.target";
    /// The run's recorded authorization no longer matches its owning
    /// submission: an unapproved or drifted plan is never eligible.
    pub const UNAPPROVED_PLAN: &str = "supervision.unapproved_plan";
    /// No committed submission evidence backs this run.
    pub const UNBOUND: &str = "supervision.unbound";
    /// A terminal run (`done` / `invalidated`) is never armed (issue #261).
    pub const ARM_TERMINAL: &str = "refusal.supervision.terminal_run";
    /// The run already carries an ARMED supervision row: the recovery control
    /// addresses an admitted run that has no arming authorization (issue #261).
    pub const ARM_ARMED: &str = "refusal.supervision.already_armed";
    /// No committed submission admitted this run, so no authorization is bound
    /// to it and nothing can be armed (issue #261).
    pub const ARM_UNBOUND: &str = "refusal.supervision.unbound";
    /// The run's own submission committed no `armed` authorization: arming it
    /// would invent an authorization the operator never gave (issue #261).
    pub const ARM_UNARMED: &str = "refusal.supervision.unarmed";
    /// The read-time reason of an ADMITTED run that carries no supervision row
    /// at all: nothing will drive it (issue #261 AC4).
    pub const UNARMED_INERT: &str = "supervision.unarmed_inert";
    /// No committed step spine is recorded for the run.
    pub const SPINE_MISSING: &str = "supervision.spine_missing";
    /// The run carries a durable pause request or pause.
    pub const PAUSED: &str = "supervision.paused";
    /// The run is terminal-success WITH a passing review-evidence row.
    pub const COMPLETED: &str = "supervision.completed";
    /// The run reports `done` without passing evidence: not completion.
    pub const COMPLETION_UNVERIFIED: &str = "supervision.completion_unverified";
    /// The run was invalidated.
    pub const INVALIDATED: &str = "supervision.invalidated";
    /// The run holds a recorded terminal hold (blocked/human queue).
    pub const TERMINAL_HOLD: &str = "supervision.terminal_hold";
    /// The newest recorded review verdict is a failure.
    pub const REVIEW_FAILED: &str = "supervision.review_failed";
    /// The review step's FAIL handoff to the run's fix round could not be
    /// dispatched (issue #238): the fix round's OWN code (a lane that could
    /// not be created, a spawn or prompt the substrate did not take) is
    /// carried as `detail`, so the missing piece is named instead of the run
    /// parking on the FAIL.
    pub const FIX_REFUSED: &str = "supervision.fix_round_refused";
    /// The run's automatic fix-round bound is spent and the certified head
    /// still fails (issue #238): the escalation, whose detail names the
    /// engine's own `refusal.fix.bound_exhausted` — never a silent park.
    pub const FIX_EXHAUSTED: &str = "supervision.fix_rounds_exhausted";
    /// The recorded FAIL was handed to the run's fix round (issue #238) and
    /// the fix leg carries the instruction: the run waits on its own repair
    /// round, and `detail` names the fix leg's lane.
    pub const FIX_DISPATCHED: &str = "supervision.fix_round_dispatched";
    /// The newest recorded fix-round handoff names ANOTHER head than the run's
    /// newest recorded review evidence (issue #254): the repair leg advanced
    /// the branch past the head this FAIL was handed at, so the recorded round
    /// is not the handoff of THIS evidence. The fix round's own recorded lane
    /// is named as the remedy, with both head prefixes — the class is the
    /// fix-round disposition, never a bare `supervision.review_failed`.
    pub const FIX_HEAD_MOVED: &str = "supervision.fix_round_head_moved";
    /// The next step's latest attempt was refused for capacity.
    pub const CAPACITY_BLOCKED: &str = "supervision.capacity_blocked";
    /// A step dispatch is in flight: legitimate long-running work.
    pub const IN_FLIGHT: &str = "supervision.in_flight";
    /// The next unachieved step needs human approval.
    pub const WAITING_APPROVAL: &str = "supervision.waiting_approval";
    /// The next unachieved step is a hosted check.
    pub const WAITING_CI: &str = "supervision.waiting_CI";
    /// The next unachieved step drives worker lanes.
    pub const WAITING_WORKERS: &str = "supervision.waiting_workers";
    /// Recorded evidence has not moved within the policy window: this is
    /// the absence of evidence, and the run is reported eligible.
    pub const PROGRESS_TIMEOUT: &str = "supervision.progress_timeout";
    /// No meaningful-progress observation is recorded yet (or the recorded
    /// instant is unreadable): the run is HELD, never eligible — an
    /// unobserved run is not a timed-out one.
    pub const PROGRESS_UNOBSERVED: &str = "supervision.progress_unobserved";
    /// Recorded evidence moved within the policy window.
    pub const RECENT_PROGRESS: &str = "supervision.recent_progress";
    /// The committed check dispatched the run's next unachieved step through
    /// the apply engine (issue #92 F4).
    pub const DISPATCH: &str = "supervision.dispatch.next_step";
    /// The run was armed without the host-local topology/admission context
    /// required by the gated apply path.
    pub const DISPATCH_CONTEXT_MISSING: &str = "supervision.dispatch_context_missing";
    /// The apply engine REFUSED the recorded continuation dispatch of the
    /// next unachieved step BEFORE any effect ran (issue #141): the refusal
    /// is the durable record this classification reads, and `detail` carries
    /// the engine's own refusal code. The step is never reported eligible
    /// while the dispatch the driver names is refused.
    pub const DISPATCH_REFUSED: &str = "supervision.dispatch_refused";
    /// The run's own newest recorded review evidence carries a non-passing
    /// check, so its verified-delivery consumer is refused (issue #230) and
    /// the driver drives the run's OWN bounded, audited recovery control —
    /// the check producer re-evaluated on a fresh lane round (issue #243).
    /// Issue #254: the recorded FAIL the review step handed to the run's own
    /// fix round is the SAME precondition ([`recorded_fail_refusal`]), so the
    /// FAIL shape drives the same control instead of parking on it.
    /// The tail behind the unverified delivery is still never driven and the
    /// run is still never reported eligible.
    pub const REEVALUATION: &str = "supervision.reevaluation.next_round";
    /// The run's own fix round has delivered a MOVED head that its own
    /// collection never observed (issue #272), so the ONE continuation is a
    /// bounded RE-COLLECT of the repair leg's own lane checkout through the
    /// run's own collector step. Nothing else may be derived while the run's
    /// certified delivery does not name the head its own handoff delivered:
    /// a review re-entry would consume a head no collection observed (the
    /// engine refuses it typed), and the tail behind the delivery is never
    /// driven on an uncertified head. The re-collect is journaled (the
    /// ordinary `apply` record of the run's own collection step) and counted
    /// against the run's shared per-(run, step) bounded-dispatch budget
    /// ([`crate::state::RUN_RETRY_MAX`]).
    pub const RECOLLECT: &str = "supervision.recollect.fix_delivery";
    /// The next unachieved step is the run's own verified-delivery consumer
    /// (a committed `merge` / `cleanup` tail step) and the driver may not
    /// dispatch it because the run's newest recorded review evidence is a
    /// `pass` bound to the run's pins at one exact head whose named checks are
    /// NOT all `passed` (issue #230). Nothing is attempted in this shape, so
    /// no dispatch refusal is ever recorded — the engine's own evidence gate
    /// refuses before any dispatch, and reporting the frontier as an eligible
    /// continuation that never lands is exactly the deadlock. `detail` carries
    /// the engine's own refusal code and the read carries its reason, both
    /// DERIVED from the same recorded facts the gate reads; a recomputation
    /// that comes back failing keeps this refusal exactly as it was.
    pub const DELIVERY_UNVERIFIED: &str = "supervision.delivery_unverified";
    /// The next unachieved step HAS been attempted and its own recorded
    /// outcome is not `succeeded` (issue #148): the work ran and diagnosed a
    /// concrete failure/refusal, and the driver never re-dispatches a
    /// diagnosed step. Reporting such a frontier `waiting-workers`,
    /// `waiting-CI` or `waiting-approval` presents a stalled run as if
    /// something were still running; the recorded attempt's own code is the
    /// named blocker instead.
    pub const STEP_DIAGNOSED: &str = "supervision.step_diagnosed";
    /// Collection exhausted its bounded worker wait, without a retry.
    pub const WORKER_TIMEOUT: &str = "supervision.worker_timeout";
}

/// A typed supervision error/refusal (fail closed; stable codes).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SupervisionError {
    /// Stable dotted code.
    pub code: &'static str,
    /// Bounded human message.
    pub message: String,
}

impl SupervisionError {
    /// Build one typed error.
    pub fn new(code: &'static str, message: impl Into<String>) -> SupervisionError {
        SupervisionError {
            code,
            message: message.into(),
        }
    }
}

/// The validated supervision policy of one authorization: the explicit,
/// bounded deadlines the driver obeys.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Policy {
    /// Bounded timer fallback cadence (seconds).
    pub check_interval_secs: i64,
    /// Meaningful-progress window (seconds).
    pub progress_timeout_secs: i64,
}

impl Default for Policy {
    fn default() -> Policy {
        Policy {
            check_interval_secs: DEFAULT_CHECK_INTERVAL_SECS,
            progress_timeout_secs: DEFAULT_PROGRESS_TIMEOUT_SECS,
        }
    }
}

impl Policy {
    /// The freshness bound of a check: `interval + margin`.
    pub fn freshness_secs(&self) -> i64 {
        self.check_interval_secs + FRESHNESS_MARGIN_SECS
    }
}

/// One validated supervision authorization (presented as part of a queue
/// submission).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Authorization {
    /// Desired supervision (`armed` | `disabled`).
    pub desired: String,
    /// The validated bounded policy.
    pub policy: Policy,
}

/// Validate one presented `params.supervision` block. Fail closed: unknown
/// keys, a desired state outside the closed set, and out-of-bounds
/// deadlines refuse with typed usage codes before any state is read.
pub fn parse_authorization(value: &Val) -> Result<Authorization, SupervisionError> {
    let Val::Obj(map) = value else {
        return Err(SupervisionError::new(
            codes::AUTHORIZATION,
            "params.supervision must be an object",
        ));
    };
    for key in map.keys() {
        if !["schema", "desired", "policy"].contains(&key.as_str()) {
            return Err(SupervisionError::new(
                codes::AUTHORIZATION,
                format!("params.supervision does not accept {key:?} (closed surface)"),
            ));
        }
    }
    match map.get("schema").and_then(Val::as_str) {
        Some(schema) if schema == AUTHORIZATION_SCHEMA => {}
        _ => {
            return Err(SupervisionError::new(
                codes::AUTHORIZATION,
                format!("params.supervision.schema must be {AUTHORIZATION_SCHEMA:?}"),
            ));
        }
    }
    let desired = map
        .get("desired")
        .and_then(Val::as_str)
        .unwrap_or("")
        .to_string();
    if !DESIRED.contains(&desired.as_str()) {
        return Err(SupervisionError::new(
            codes::DESIRED,
            format!("params.supervision.desired must be one of {DESIRED:?}"),
        ));
    }
    let policy = match map.get("policy") {
        None | Some(Val::Null) => Policy::default(),
        Some(value) => parse_policy(value)?,
    };
    Ok(Authorization { desired, policy })
}

/// Validate one presented policy block (closed keys, bounded values).
pub fn parse_policy(value: &Val) -> Result<Policy, SupervisionError> {
    let Val::Obj(map) = value else {
        return Err(SupervisionError::new(
            codes::AUTHORIZATION,
            "params.supervision.policy must be an object",
        ));
    };
    for key in map.keys() {
        if !["check_interval_secs", "progress_timeout_secs"].contains(&key.as_str()) {
            return Err(SupervisionError::new(
                codes::AUTHORIZATION,
                format!("params.supervision.policy does not accept {key:?}"),
            ));
        }
    }
    let mut policy = Policy::default();
    if let Some(value) = map.get("check_interval_secs") {
        let interval = value.as_int().ok_or_else(|| {
            SupervisionError::new(
                codes::INTERVAL,
                "params.supervision.policy.check_interval_secs must be an integer",
            )
        })?;
        if !(MIN_CHECK_INTERVAL_SECS..=MAX_CHECK_INTERVAL_SECS).contains(&interval) {
            return Err(SupervisionError::new(
                codes::INTERVAL,
                format!(
                    "params.supervision.policy.check_interval_secs must be \
                     {MIN_CHECK_INTERVAL_SECS}..={MAX_CHECK_INTERVAL_SECS}"
                ),
            ));
        }
        policy.check_interval_secs = interval;
    }
    if let Some(value) = map.get("progress_timeout_secs") {
        let timeout = value.as_int().ok_or_else(|| {
            SupervisionError::new(
                codes::TIMEOUT,
                "params.supervision.policy.progress_timeout_secs must be an integer",
            )
        })?;
        if !(MIN_PROGRESS_TIMEOUT_SECS..=MAX_PROGRESS_TIMEOUT_SECS).contains(&timeout) {
            return Err(SupervisionError::new(
                codes::TIMEOUT,
                format!(
                    "params.supervision.policy.progress_timeout_secs must be \
                     {MIN_PROGRESS_TIMEOUT_SECS}..={MAX_PROGRESS_TIMEOUT_SECS}"
                ),
            ));
        }
        policy.progress_timeout_secs = timeout;
    }
    if policy.progress_timeout_secs < policy.check_interval_secs {
        return Err(SupervisionError::new(
            codes::TIMEOUT,
            "params.supervision.policy.progress_timeout_secs must not be smaller than \
             check_interval_secs",
        ));
    }
    Ok(policy)
}

/// The canonical `params.supervision` document of one authorization.
pub fn authorization_params(desired: &str, policy: Policy) -> Val {
    object(vec![
        ("schema", string(AUTHORIZATION_SCHEMA)),
        ("desired", string(desired)),
        (
            "policy",
            object(vec![
                ("check_interval_secs", integer(policy.check_interval_secs)),
                (
                    "progress_timeout_secs",
                    integer(policy.progress_timeout_secs),
                ),
            ]),
        ),
    ])
}

/// The `supervision.arm` document schema id (issue #261, module-local).
pub const ARM_SCHEMA: &str = "hf-supervision-arm/v1";

/// The statement every `supervision.arm` document carries: what the control
/// did and did NOT do.
pub const ARM_STATEMENT: &str = "arm only: exactly ONE already-admitted run's supervision is armed with the exact authorization its own committed submission presented (bound to that submission's approved digest, boundary and epoch); nothing is dispatched, resumed, retried, released or widened by this control, no policy is invented, and a run that is already armed, terminal, or not admitted by a submission refuses typed";

/// Validate one `supervision.arm` request: exactly one run identity plus the
/// caller's idempotency key (a fresh claim per invocation, exactly one effect
/// per key). Fail closed before any state is read.
pub fn parse_arm_params(params: &Val) -> Result<(String, String), SupervisionError> {
    let Val::Obj(map) = params else {
        return Err(SupervisionError::new(
            "refusal.malformed",
            "supervision.arm params must be an object",
        ));
    };
    for key in map.keys() {
        if !["idempotency_key", "instance_id"].contains(&key.as_str()) {
            return Err(SupervisionError::new(
                "refusal.malformed",
                format!("supervision.arm does not accept params.{key}"),
            ));
        }
    }
    let instance_id = map
        .get("instance_id")
        .and_then(Val::as_str)
        .unwrap_or("")
        .to_string();
    if !formats::is_run_id(&instance_id) {
        return Err(SupervisionError::new(
            codes::TARGET,
            format!(
                "supervision.arm addresses exactly ONE run (`run-` + 16 hex); \
                 {instance_id:?} is not a run identity"
            ),
        ));
    }
    let key = map
        .get("idempotency_key")
        .and_then(Val::as_str)
        .filter(|key| !key.is_empty())
        .ok_or_else(|| {
            SupervisionError::new(
                "refusal.malformed",
                "supervision.arm requires params.idempotency_key",
            )
        })?
        .to_string();
    Ok((instance_id, key))
}

/// The `hf-supervision-arm/v1` projection of ONE recorded arm: the run, the
/// armed supervision row and the submission whose committed authorization it
/// re-armed with.
pub fn arm_doc(armed: &crate::state::SupervisionArm, at: &str, key: &str) -> Val {
    let row = &armed.row;
    let run = &armed.run;
    object(vec![
        ("schema", string(ARM_SCHEMA)),
        ("statement", string(ARM_STATEMENT)),
        (
            "run",
            object(vec![
                ("instance_id", string(&run.instance_id)),
                ("repository", string(&run.repository)),
                ("issue_number", integer(run.issue_number)),
                ("status", string(&run.status)),
                ("phase", string(&run.phase)),
                ("node", string(&run.current_node)),
                ("state_epoch", integer(run.state_epoch)),
            ]),
        ),
        (
            "supervision",
            object(vec![
                ("id", string(&row.supervision_id)),
                ("desired", string(&row.desired)),
                ("state", string("active")),
                ("armed_at", string(&row.armed_at)),
                ("owner_generation", integer(row.owner_generation)),
                ("run_generation", integer(row.run_generation)),
                ("authorization_digest", string(&row.authorization_digest)),
                ("approved_boundary", string(&row.approved_boundary)),
                ("check_interval_secs", integer(row.check_interval_secs)),
                ("progress_timeout_secs", integer(row.progress_timeout_secs)),
            ]),
        ),
        (
            "submission",
            object(vec![("submission_id", string(&armed.submission_id))]),
        ),
        ("authorized_at", string(at)),
        ("idempotency_key", string(key)),
    ])
}

/// The read-only `hf-supervision/v1` projection of an ADMITTED run that
/// carries NO supervision row at all (issue #261 AC4): the run exists and
/// occupies the counted set, but nothing will drive it. The read tells that
/// state and the remedy apart from `armed, waiting` instead of leaving a cap
/// refusal as the only symptom — and it is a READ: no claim, no journal
/// write, no marker movement.
pub fn unarmed_doc(run: &crate::state::InstanceRow, submission_id: Option<&str>, at: &str) -> Val {
    object(vec![
        ("schema", string(SUPERVISION_SCHEMA)),
        (
            "run",
            object(vec![
                ("instance_id", string(&run.instance_id)),
                ("repository", string(&run.repository)),
                ("issue_number", integer(run.issue_number)),
                ("status", string(&run.status)),
                ("phase", string(&run.phase)),
                ("node", string(&run.current_node)),
                ("state_epoch", integer(run.state_epoch)),
                ("paused", bool_(run.paused)),
                ("pause_requested", bool_(run.pause_requested)),
                ("human_queue", bool_(run.human_queue)),
                ("terminal_blockers", integer(run.terminal_blockers as i64)),
            ]),
        ),
        (
            "supervision",
            object(vec![
                ("id", string("")),
                ("desired", string("disabled")),
                ("state", string("unarmed")),
                ("armed_at", string("")),
            ]),
        ),
        (
            "evaluation",
            object(vec![
                ("class", string("unknown")),
                ("reason", string(codes::UNARMED_INERT)),
                ("eligible", bool_(false)),
                (
                    "detail",
                    string(
                        "admitted with no arming authorization: no supervision row exists, so                          nothing will drive this run's next step and it holds its counted slot                          until it is armed or released",
                    ),
                ),
            ]),
        ),
        (
            "remedy",
            object(vec![
                (
                    "control",
                    string(&format!("supervision arm --run {}", run.instance_id)),
                ),
                (
                    "submission_id",
                    submission_id.map(string).unwrap_or_else(|| string("")),
                ),
            ]),
        ),
        ("observed_at", string(at)),
    ])
}

/// The canonical `supervision.arm` request document (issue #261).
pub fn arm_params(idempotency_key: &str, instance_id: &str) -> Val {
    object(vec![
        ("idempotency_key", string(idempotency_key)),
        ("instance_id", string(instance_id)),
    ])
}

/// Validate one `supervision.status` target (exactly one run identity).
pub fn parse_status_params(params: &Val) -> Result<String, SupervisionError> {
    let Val::Obj(map) = params else {
        return Err(SupervisionError::new(
            "refusal.malformed",
            "supervision.status params must be an object",
        ));
    };
    for key in map.keys() {
        if key != "instance_id" {
            return Err(SupervisionError::new(
                "refusal.malformed",
                format!("supervision.status does not accept params.{key}"),
            ));
        }
    }
    let instance_id = map
        .get("instance_id")
        .and_then(Val::as_str)
        .unwrap_or("")
        .to_string();
    if !formats::is_run_id(&instance_id) {
        return Err(SupervisionError::new(
            codes::TARGET,
            format!(
                "supervision.status addresses exactly ONE run (`run-` + 16 hex); \
                 {instance_id:?} is not a run identity"
            ),
        ));
    }
    Ok(instance_id)
}

/// The canonical `supervision.status` params document.
pub fn status_params(instance_id: &str) -> Val {
    object(vec![("instance_id", string(instance_id))])
}

/// One classification verdict: the closed class, the stable reason code and
/// whether the run is reported continuation-eligible (a REPORT — no effect).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verdict {
    /// One member of [`CLASSES`].
    pub class: &'static str,
    /// One stable `supervision.*` reason code.
    pub reason: &'static str,
    /// Whether this run is reported eligible for a later continuation.
    pub eligible: bool,
    /// Bounded detail (e.g. the next step id); empty when not applicable.
    pub detail: String,
}

impl Verdict {
    fn new(class: &'static str, reason: &'static str, eligible: bool, detail: &str) -> Verdict {
        Verdict {
            class,
            reason,
            eligible,
            detail: detail.to_string(),
        }
    }
}

/// The step kind recorded in the run's bound spine for one step id (`""`
/// when the step is unknown).
fn step_kind<'a>(evidence: &'a SupervisionEvidence, step: &str) -> &'a str {
    evidence
        .steps
        .iter()
        .find(|(id, _)| id == step)
        .map(|(_, kind)| kind.as_str())
        .unwrap_or("")
}

/// The next unachieved step from the recorded attempt ledger. Once any
/// attempt exists, the ledger is authoritative; `current_node` is only a
/// pre-ledger compatibility fallback. A diagnosed step therefore remains the
/// frontier until an explicit evidence resolution records it succeeded.
pub fn next_unachieved_step(evidence: &SupervisionEvidence) -> Option<(String, String)> {
    let spine: Vec<String> = evidence.steps.iter().map(|(id, _)| id.clone()).collect();
    let attempts: Vec<(String, String)> = evidence
        .attempts
        .iter()
        .map(|(step, status, _)| (step.clone(), status.clone()))
        .collect();
    let next = crate::run_control::frontier_of(&spine, &attempts, &evidence.run.current_node)?;
    let kind = step_kind(evidence, &next).to_string();
    Some((next, kind))
}

/// The newest recorded review verdict (`""` when no evidence row exists).
fn newest_verdict(evidence: &SupervisionEvidence) -> &str {
    evidence
        .verdicts
        .first()
        .map(|(_, verdict, _)| verdict.as_str())
        .unwrap_or("")
}

/// Whether the recorded authorization still matches the run's owning
/// submission: both the approved digest and the boundary must agree, and a
/// committed submission must exist. A drifted or unapproved plan is never
/// eligible.
pub fn authorization_bound(evidence: &SupervisionEvidence, authorization_digest: &str) -> bool {
    evidence.submission_digest.as_deref() == Some(authorization_digest)
}

/// ONE dispatch intent of a supervision check (issue #92 F4): the next
/// unachieved step of an explicitly armed run, to be dispatched through the
/// merged apply engine. The intent carries NO authority of its own — every
/// gate (capability, grant, admission, ownership, journal, idempotency) is
/// re-derived by the apply path, which refuses without them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DispatchIntent {
    /// The supervised run.
    pub instance_id: String,
    /// The bound-spine step to dispatch.
    pub step_id: String,
    /// That step's kind.
    pub kind: String,
    /// Why this dispatch is the run's continuation (stable reason code).
    pub reason: &'static str,
}

/// The dispatch hook the driver calls AFTER a check commits (issue #92 F4).
/// The daemon implements it with the merged apply engine; the driver itself
/// never runs an effect, and a refused or failed dispatch is logged and
/// never retried inside the same check.
pub trait SupervisedDispatch: Send + Sync {
    /// Dispatch ONE step through the apply engine. `Ok(word)` describes the
    /// recorded outcome; `Err(message)` is a refusal that only logs.
    fn dispatch(&self, intent: &DispatchIntent) -> Result<String, String>;
}

/// Derive the ONE continuation dispatch of a check (issue #92 F4).
///
/// `Some(intent)` only when every condition holds:
/// - the row is explicitly `armed` and its authorization still matches the
///   run's committed submission;
/// - the run is live: not paused, no pause request, no human queue, no
///   terminal blocker, not blocked/invalidated/done;
/// - no step dispatch is in flight (a run mid-effect is never advanced);
/// - the run still has a next unachieved step, never dispatched or eligible
///   for a bounded retry, and its kind is one the driver may dispatch for THIS run
///   ([`driver_dispatchable_kind`]): the ordinary autonomous kinds, or the
///   risk-classed merge/cleanup TAIL of a run whose own committed submission
///   declares it — so the delivering run's own merge and cleanup are driven
///   to the end of its committed spine (issue #152).
///
/// A diagnosed step may retry within the shared bounded budget. An
/// authorization the run ALREADY holds — the operator's `run.retry` row — is
/// consumed by this very dispatch (issue #241): the intent is derived for the
/// exact step it authorizes, the daemon's supervised apply path consumes it
/// with the dispatch's own idempotency key, and the engine's fence sees the
/// authorization spent by its own claim. It therefore never parks the
/// frontier, and a second attempt still needs its own authorization. The ONE
/// exception is the risk-classed committed TAIL (`merge` / `cleanup`), which
/// keeps issue #152's rule verbatim: an ATTEMPTED tail stays the operator's,
/// and a held authorization over it is spent by that operator's own
/// `run.dispatch` — the release refusal names exactly that remedy.
///
/// Non-armed/unknown supervision keeps its zero-effect guarantee: this
/// function returns `None` for every row that is not explicitly armed.
pub fn dispatch_intent(
    row: &SupervisionRow,
    evidence: &SupervisionEvidence,
) -> Option<DispatchIntent> {
    if !evidence.has_dispatch_context || row.desired != "armed" {
        return None;
    }
    if !authorization_bound(evidence, &row.authorization_digest) {
        return None;
    }
    let run = &evidence.run;
    if run.paused
        || run.pause_requested
        || run.human_queue
        || run.terminal_blockers > 0
        || matches!(run.status.as_str(), "blocked" | "invalidated" | "done")
    {
        return None;
    }
    if evidence.in_flight.is_some() {
        return None;
    }
    // Issue #272: the run's own fix round delivered a moved head its own
    // collection never observed. The ONE continuation is the bounded
    // re-collect of the repair leg's checkout — nothing else is derived while
    // that holds (the review would consume an uncollected head and refuse it
    // typed, and the tail is never driven behind an uncertified delivery).
    if let Some(intent) = fix_recollect_intent(evidence) {
        return Some(intent);
    }
    let (step_id, kind) = next_unachieved_step(evidence)?;
    if !driver_dispatchable_kind(evidence, &step_id, &kind) {
        // Issue #243: the driver may not drive THIS frontier, but when the
        // recorded condition is the engine's own typed recovery control's
        // precondition, the run's own check PRODUCER is re-evaluated through
        // that control — bounded, attributed and journaled — instead of the
        // run being parked for an operator. The frontier itself is untouched:
        // the tail behind an unverified delivery is still never driven, and
        // nothing else about the park changes.
        return reevaluation_intent(evidence, &step_id, &kind);
    }
    let step_retries: Vec<&crate::state::RunRetryRow> = evidence
        .retries
        .iter()
        .filter(|retry| retry.step_id == step_id)
        .collect();
    // Issue #241: the ONE authorization the run already holds is spent by the
    // re-dispatch it authorizes, so it is not a park. The park codes below
    // fence only the retries supervision MINTS for itself (a worker timeout,
    // a moved certificate and a moved/unbound delivery are never
    // re-dispatched on supervision's own initiative) — an explicit operator
    // authorization is exactly the act that asks for one bounded re-dispatch
    // of this diagnosed step.
    let authorized = step_retries
        .iter()
        .any(|retry| retry.consumed_at.is_empty());
    // The risk-classed committed TAIL keeps issue #152's own rule (see below).
    let tail = COMMITTED_TAIL_STEP_KINDS.contains(&kind.as_str());
    match latest_attempt_for(evidence, &step_id) {
        // Never dispatched: the plain continuation of an armed run.
        None => {}
        // Issue #184: a recorded refusal of the run's OWN lapsed window is
        // not a step diagnosis — the step never ran — so it is the same
        // plain continuation and never a bounded retry. A recorded review
        // failure still holds the frontier exactly as before.
        Some((_, status, code))
            if status != "succeeded" && !crate::state::step_attempt_diagnosed(status, code) =>
        {
            if newest_verdict(evidence) == "fail" {
                return None;
            }
        }
        Some((_, status, code))
            if crate::state::step_attempt_diagnosed(status, code)
                // Issue #200: a review step whose recorded diagnosis is
                // `refusal.evidence.verdict_stale` refuses because a head
                // binding MOVED (the lane checkout is no longer the certified
                // head). The certificate is a recorded fact and the checkout's
                // movement is external, so a re-dispatch is guaranteed to
                // refuse identically: the step is impossible, not retryable.
                // It parks the frontier typed (the recorded code) with the
                // bounded retries UNSPENT, instead of burning them on a step
                // that can never succeed.
                // Issue #202 (AC1): the same discipline for a delivery that
                // moved past the head its recorded verdict names. The verdict
                // is a recorded fact and the delivery branch's movement is
                // external, so re-dispatching the consumer refuses identically
                // until the delivery re-enters review and a new verdict names
                // the moved head: the frontier parks typed with the bounded
                // retries UNSPENT, and the run is never presented as a step
                // that could still be retried into consumption.
                //
                // Issue #272: that remedy is reachable now, so the fence ends
                // where the remedy lands — once the run's OWN collection has
                // certified the head its OWN handoff delivered, the head this
                // step consumes is a collected fact again and a re-dispatch is
                // the documented remedy, not a guarantee to refuse
                // identically. Everything else about the park is unchanged.
                && (newest_verdict(evidence) != "fail" || fix_delivery_recertified(evidence))
                // Issue #241: a held authorization is spent by the ONE
                // re-dispatch it authorizes, so it is dispatchable — for the
                // steps the driver already re-dispatches on its own within
                // the bounded budget. The risk-classed committed TAIL
                // (`merge` / `cleanup`) keeps issue #152's rule verbatim: an
                // ATTEMPTED tail stays the operator's, and a held
                // authorization over it is consumed by that operator's own
                // `run.dispatch` (the release refusal names that remedy).
                && ((authorized && !tail)
                    || (!authorized
                        && code != crate::mutation::code::WORKER_TIMEOUT
                        // Issue #224: the cleanup step's bounded wait for a
                        // lane that outlived its own publish is the same
                        // wait/park. The lane is ALIVE — a stale or foreign
                        // workspace is never waited on — so a re-dispatch buys
                        // nothing the first attempt's own bound did not
                        // already spend: the frontier parks typed with the
                        // bounded retries UNSPENT on the timing.
                        && code != crate::mutation::code::LANE_TIMEOUT
                        && code != crate::mutation::code::VERDICT_STALE
                        && code != crate::mutation::code::DELIVERY_MOVED
                        // Issue #272: an unbound-delivery diagnosis is only
                        // impossible while the head the step consumes is one
                        // no collection observed. Once the run's own
                        // collection certified the head its own handoff
                        // delivered, the diagnosis is resolved and the step is
                        // re-dispatched within its own bounded budget like
                        // every other diagnosed step.
                        && (code != crate::mutation::code::DELIVERY_UNBOUND
                            || fix_delivery_recertified(evidence))
                        // Issue #263: a published ref that moved past the
                        // base the delivery certified and cannot carry the
                        // certified content byte-identically is a recorded
                        // fact about the PUBLISHED ref, not a step defect: a
                        // re-dispatch refuses identically (the refresh is
                        // withdrawn), so the frontier parks typed with the
                        // bounded retries UNSPENT instead of spending the
                        // whole budget on a base move the run cannot resolve
                        // by itself.
                        && code != crate::mutation::code::MERGE_BASE_MOVED
                        && step_retries.len() < crate::state::RUN_RETRY_MAX as usize)) => {}
        Some(_) => return None,
    }
    Some(DispatchIntent {
        instance_id: run.instance_id.clone(),
        step_id,
        kind,
        reason: codes::DISPATCH,
    })
}

/// The audited reason the DRIVER records when it drives the run's own recovery
/// control (issue #243).
///
/// It names the recorded facts that made the act necessary and nothing else:
/// no check status, no verdict and no head are ever presented, exactly as an
/// operator's own reason is bounded and recorded. The presentation is bounded
/// to the control's own [`crate::run_control::REASON_MAX`] (a committed step id
/// may be a 64-character slug, and the driver never presents a reason the
/// control would refuse for its shape — that would put the recovery back
/// behind an operator for the longest step ids).
pub fn reevaluation_reason(step: &str) -> String {
    let reason = format!(
        "supervision derived this bounded re-evaluation of {step}: the newest recorded review \
         evidence carries a non-passing check, so its consumer is refused while the producer \
         cannot be re-run; recompute the checks by their own producer at the same certified \
         head (issue #243)"
    );
    reason
        .chars()
        .take(crate::run_control::REASON_MAX)
        .collect()
}

/// The driver's ONE recovery intent (issue #243): the run's own check PRODUCER
/// re-evaluated through the engine's own bounded, audited, recorded control.
///
/// `Some` only in the exact recorded shape the deadlock is made of — the
/// frontier is a committed tail step the run's own caps authorize, after the
/// run's reviewed-evidence step, and the run's newest recorded review evidence
/// carries a non-passing check at one exact head bound to the run's own pins:
/// the `pass` whose named checks are not all `passed` ([`unverified_delivery_refusal`],
/// the SAME derivation the classification reads), or the recorded FAIL that
/// evidence names and the review step handed to the run's own fix round
/// (issue #254, [`recorded_fail_refusal`]) — and only while the recorded bound
/// ([`crate::run_control::RUN_REEVALUATION_MAX`], counted from the durable
/// journal) has NOT been spent.
///
/// Everything else stays exactly as parked as it was: the intent is the run's
/// own control (the producer is re-run, never adjudicated), the tail behind
/// the unverified delivery is still never driven, the run is still never
/// reported eligible, and a spent bound is never re-minted as an intent that
/// is guaranteed to refuse.
fn reevaluation_intent(
    evidence: &SupervisionEvidence,
    frontier: &str,
    frontier_kind: &str,
) -> Option<DispatchIntent> {
    // The recorded precondition of the control (issue #230, extended by #254
    // to the recorded FAIL the run's own fix round was handed): the run's
    // newest recorded review evidence carries a non-passing check, so its
    // verified-delivery consumer is refused while the check producer cannot be
    // re-run by anything but this control.
    unverified_delivery_refusal(evidence, frontier, frontier_kind)
        .or_else(|| recorded_fail_refusal(evidence, frontier, frontier_kind))?;
    // The producer: the run's own check-producing step — the reviewed-evidence
    // step of the committed spine that declares its reviewer LEG (the only
    // shape that computes checks) and whose latest recorded attempt SUCCEEDED
    // (a diagnosed step belongs to the bounded-retry control, and a step that
    // never ran has no recorded check result to re-evaluate).
    let (producer, producer_kind) = evidence
        .steps
        .iter()
        .position(|(step, _)| step == frontier)
        .and_then(|frontier_index| {
            evidence.steps[..frontier_index]
                .iter()
                .rev()
                .find(|(step, kind)| {
                    kind == crate::run_control::REEVALUATION_KIND
                        && evidence.reviewer_leg_steps.contains(step)
                        && latest_attempt_for(evidence, step).map(|(_, status, _)| status.as_str())
                            == Some("succeeded")
                })
        })?;
    let recorded = evidence
        .reevaluations
        .iter()
        .find(|(step, _)| step == producer)
        .map(|(_, count)| *count)
        .unwrap_or(0);
    if recorded >= crate::run_control::RUN_REEVALUATION_MAX {
        return None;
    }
    Some(DispatchIntent {
        instance_id: evidence.run.instance_id.clone(),
        step_id: producer.clone(),
        kind: producer_kind.clone(),
        reason: codes::REEVALUATION,
    })
}

/// Whether the run's own recorded fix round has delivered a moved head its own
/// collection has NOT observed yet (issue #272).
///
/// The recorded handoff names the certified head the FAIL was handed at; the
/// repair leg advances the branch in its OWN lane checkout, so the head it
/// carries is a fact about that checkout — observed read-only by
/// [`observe_fix_leg`], never inferred, and only when the recorded handoff
/// names that checkout at all (a row written before issue #256 names none, and
/// a checkout is never guessed).
///
/// A delivery the run's own collection already certified is NOT this fact: the
/// derivation stops the moment the certificate names the delivered head, so it
/// converges by construction instead of looping.
fn fix_delivery_uncertified(evidence: &SupervisionEvidence) -> bool {
    // The run's durable evidence must still stand at the recorded FAIL: a
    // delivery that has already been re-reviewed (the newest recorded verdict
    // is a `pass`) must never be hijacked back into a collection — the run
    // owns its tail from there.
    if !matches!(evidence.verdicts.first(), Some((_, verdict, _)) if verdict == "fail") {
        return false;
    }
    let Some(leg) = evidence.fix_leg.as_ref().filter(|leg| leg.delivered) else {
        return false;
    };
    let Some(fix) = evidence.fix_round.as_ref() else {
        return false;
    };
    if fix.worktree.is_empty() {
        return false;
    }
    matches!(&evidence.delivery, Some(delivery) if delivery.head != leg.head)
}

/// Whether the run's own handoff has been RE-BOUND (issue #272): the head the
/// recorded fix-round leg delivered IS the head this run's own collection
/// certified, so the head the frontier would consume is a collected fact
/// again. One fact, two readers: the re-collect derivation above, and the
/// diagnosed-step fence below (an unbound-delivery park ends where it started
/// — a collection that observed the moved head).
fn fix_delivery_recertified(evidence: &SupervisionEvidence) -> bool {
    let delivered = evidence.fix_leg.as_ref().filter(|leg| leg.delivered);
    match (delivered, evidence.delivery.as_ref()) {
        (Some(leg), Some(delivery)) => leg.head == delivery.head,
        _ => false,
    }
}

/// The driver's ONE continuation while the run's own fix round has delivered a
/// moved head its own collection never observed (issue #272): a bounded
/// RE-COLLECT of the repair leg's own lane checkout through the run's OWN
/// collector step — the step the certified delivery was recorded by.
///
/// It re-establishes the certificate binding from recorded material only: the
/// step is the certificate's own step of this run's committed spine (its own
/// committed kind decides, never a name heuristic), the checkout is the one
/// the recorded handoff names, and the branch + base are the collection's own
/// recorded bindings, presented by the daemon's dispatch path. Nothing else is
/// derived while this holds: the review cannot consume an uncollected head and
/// the tail is never driven behind one.
///
/// Bounded twice over, both on recorded facts: the derivation stops as soon as
/// the certificate names the delivered head, and a re-collect that cannot be
/// taken is counted against the run's shared per-(run, step) bounded-dispatch
/// budget ([`crate::state::RUN_RETRY_MAX`]) — the same budget a diagnosed
/// step's bounded retry spends — so the collector is re-dispatched at most
/// that many times and the frontier then parks typed.
fn fix_recollect_intent(evidence: &SupervisionEvidence) -> Option<DispatchIntent> {
    if !fix_delivery_uncertified(evidence) {
        return None;
    }
    let collector = evidence.delivery.as_ref()?.step_id.clone();
    if step_kind(evidence, &collector) != "collect_outcome" {
        return None;
    }
    if !evidence.has_dispatch_context {
        return None;
    }
    let recorded = evidence
        .retries
        .iter()
        .filter(|retry| retry.step_id == collector)
        .count();
    if recorded >= crate::state::RUN_RETRY_MAX as usize {
        return None;
    }
    Some(DispatchIntent {
        instance_id: evidence.run.instance_id.clone(),
        step_id: collector,
        kind: "collect_outcome".to_string(),
        reason: codes::RECOLLECT,
    })
}

/// One run whose recorded evidence is a fresh VERIFIED delivery (issue #96):
/// the reviewed `pass` plus every named check `passed` at one recorded
/// delivered head, bound to the run's own membership item of an
/// already-authorized submission. This is the durable binding a queue-cursor
/// advance is keyed to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedDelivery {
    /// The committed submission the delivered run was admitted from.
    pub submission_id: String,
    /// Membership ordinal of the delivered issue (the idempotency key).
    pub item_ordinal: i64,
    /// Stable work-item id of the delivered issue.
    pub work_item: String,
    /// The delivered head (40-hex) the review and checks were recorded at.
    pub feature_head: String,
    /// The review-evidence row that carries the verdict (the delivery event).
    pub evidence_id: String,
}

/// Derive the fresh VERIFIED delivery of one run from its recorded evidence
/// (issue #96). `None` when the run carries a durable hold (paused, blocked,
/// human queue, invalidated, terminal blocker), has no committed submission
/// membership, or when its newest recorded review evidence is not a `pass`
/// with every named check `passed` at one exact head bound to the run's own
/// workflow and policy pins. Pure: no clock, no lock, no write.
///
/// The contract is the existing board/merge evidence contract (`verified`
/// requires recorded review evidence that is still current; the merge gate
/// requires verdict `pass` plus every named check `passed`), never a label:
/// a `done` status alone is not a verified delivery, and a newer failure
/// verdict (which is the newest row) hides any older pass.
pub fn verified_delivery(evidence: &SupervisionEvidence) -> Option<VerifiedDelivery> {
    let run = &evidence.run;
    if delivery_held(evidence) {
        return None;
    }
    let item = evidence.item.as_ref()?;
    let newest = evidence.newest_evidence.as_ref()?;
    if newest.verdict != "pass" {
        return None;
    }
    let view = crate::mutation::EvidenceView {
        evidence_id: newest.evidence_id.clone(),
        feature_head: newest.feature_head.clone(),
        integration_base: newest.integration_base.clone(),
        workflow_hash: newest.workflow_hash.clone(),
        policy_hash: newest.policy_hash.clone(),
        verdict: newest.verdict.clone(),
        reviewer: newest.reviewer.clone(),
        checks: newest.checks.clone(),
        created_at: newest.created_at.clone(),
    };
    if !crate::mutation::evidence_checks_passed(&view).ok()? {
        return None;
    }
    // The evidence must be bound to THIS run's pins and name one exact head.
    if newest.workflow_hash != run.workflow_hash || newest.policy_hash != run.policy_hash {
        return None;
    }
    if !crate::formats::is_hex40(&newest.feature_head) {
        return None;
    }
    Some(VerifiedDelivery {
        submission_id: item.submission_id.clone(),
        item_ordinal: item.ordinal,
        work_item: item.work_item.clone(),
        feature_head: newest.feature_head.clone(),
        evidence_id: newest.evidence_id.clone(),
    })
}

/// Whether the run is in a state in which NO delivery can be verified at all:
/// a durable hold (paused, blocked, invalidated, human queue, terminal
/// blockers) or a step still in flight (the run is mid-effect). ONE derivation,
/// shared by [`verified_delivery`] and [`unverified_delivery_refusal`], so the
/// two can never drift (fix round F1, finding NB-1).
fn delivery_held(evidence: &SupervisionEvidence) -> bool {
    let run = &evidence.run;
    run.paused
        || run.pause_requested
        || run.human_queue
        || run.status == "blocked"
        || run.status == "invalidated"
        || run.terminal_blockers > 0
        || evidence.in_flight.is_some()
}

/// The recorded subject the tail's own refusal and the run's own recovery
/// control are both derived from (issues #230, #243, #254): the run holds the
/// capability of this committed TAIL step, the step comes AFTER the run's
/// reviewed-evidence step, and the run's newest recorded review evidence is
/// bound to the run's own pins at one exact head. The verdict is NOT decided
/// here — each reader below says which one it accepts.
fn delivery_evidence_subject(
    evidence: &SupervisionEvidence,
    step: &str,
    kind: &str,
) -> Option<(String, crate::mutation::EvidenceView)> {
    // A run that is held, or that has a step in flight, is not a delivery at
    // all — the SAME fact [`verified_delivery`] applies, from the SAME
    // derivation, so the invariant is LOCAL here instead of positional in
    // `classify`'s arm order (fix round F1, finding NB-1).
    if delivery_held(evidence) {
        return None;
    }
    if !COMMITTED_TAIL_STEP_KINDS.contains(&kind) {
        return None;
    }
    evidence.item.as_ref()?;
    let capability = crate::mutation::required_capability(kind)?;
    if !run_caps(evidence).iter().any(|cap| cap == capability) {
        return None;
    }
    if !after_delivery_step(evidence, step) {
        return None;
    }
    let run = &evidence.run;
    let newest = evidence.newest_evidence.as_ref()?;
    if newest.workflow_hash != run.workflow_hash
        || newest.policy_hash != run.policy_hash
        || !crate::formats::is_hex40(&newest.feature_head)
    {
        return None;
    }
    Some((
        newest.evidence_id.clone(),
        crate::mutation::EvidenceView {
            evidence_id: newest.evidence_id.clone(),
            feature_head: newest.feature_head.clone(),
            integration_base: newest.integration_base.clone(),
            workflow_hash: newest.workflow_hash.clone(),
            policy_hash: newest.policy_hash.clone(),
            verdict: newest.verdict.clone(),
            reviewer: newest.reviewer.clone(),
            checks: newest.checks.clone(),
            created_at: newest.created_at.clone(),
        },
    ))
}

/// The engine's own refusal of an already-bound record whose named checks are
/// not all `passed` (issues #230, #254).
fn non_passing_refusal(
    step: &str,
    subject: &(String, crate::mutation::EvidenceView),
) -> Option<UnverifiedDelivery> {
    let non_passing = crate::mutation::non_passing_checks(&subject.1).ok()?;
    if non_passing.is_empty() {
        return None;
    }
    Some(UnverifiedDelivery {
        step: step.to_string(),
        code: crate::mutation::code::EVIDENCE_FAILED.to_string(),
        reason: crate::mutation::evidence_failed_message(&subject.0, &non_passing),
    })
}

/// The engine's own refusal of the run's verified-delivery consumer, derived
/// from the SAME recorded facts the dispatch gate reads (issue #230).
///
/// `Some` only in the ONE recorded shape the deadlock is made of: the frontier
/// is a committed TAIL step (`merge` / `cleanup`) the run's own caps
/// authorize, it comes AFTER the run's reviewed-evidence step in the committed
/// spine, and the run's newest recorded review evidence is a `pass` bound to
/// the run's own pins at one exact head whose named checks are NOT all
/// `passed`. Every OTHER reason a tail cannot be driven (no committed
/// membership, no capability, no recorded evidence, a moved pin, a verdict
/// that is not `pass`) is a different fact and is never named here.
///
/// Nothing is dispatched in this shape, so no dispatch refusal is ever
/// recorded against the run: the refusal an operator has to act on is DERIVED
/// here from the same facts, with the SAME code and the SAME message the
/// engine's own evidence gate refuses with
/// ([`crate::mutation::evidence_failed_message`]). It presents no check
/// status, waives nothing and adjudicates nothing — a recomputation that comes
/// back failing derives the identical refusal.
fn unverified_delivery_refusal(
    evidence: &SupervisionEvidence,
    step: &str,
    kind: &str,
) -> Option<UnverifiedDelivery> {
    let subject = delivery_evidence_subject(evidence, step, kind)?;
    if subject.1.verdict != "pass" {
        return None;
    }
    non_passing_refusal(step, &subject)
}

/// The SAME recorded subject in the OTHER verdict a FAIL handoff is made of
/// (issue #254): the review step recorded a `fail` whose named checks are not
/// all `passed`, so the run's newest recorded review evidence is exactly the
/// non-passing record the run's own bounded check re-evaluation exists for.
///
/// Deliberately SEPARATE from [`unverified_delivery_refusal`]: the read-time
/// refusal of the tail is the engine's own `pass`-keyed gate, and a recorded
/// FAIL keeps its own documented classification (the fix-round disposition, or
/// `supervision.review_failed` when no handoff was recorded). Only the
/// driver's own recovery-control derivation reads this one.
fn recorded_fail_refusal(
    evidence: &SupervisionEvidence,
    step: &str,
    kind: &str,
) -> Option<UnverifiedDelivery> {
    let subject = delivery_evidence_subject(evidence, step, kind)?;
    if subject.1.verdict != "fail" {
        return None;
    }
    non_passing_refusal(step, &subject)
}

/// ONE derived refusal of a frontier the driver may not dispatch (issue #230):
/// the engine's own code and message, exactly as the recorded facts imply
/// them. Read-time only — nothing about it is written down.
struct UnverifiedDelivery {
    /// The frontier step the refusal is about.
    step: String,
    /// The engine's own typed refusal code.
    code: String,
    /// The engine's own refusal message.
    reason: String,
}

/// The `evaluation.refusal` block of one status read (issue #230): the engine's
/// own refusal of this frontier's continuation, or `null` when the read-time
/// classification is not itself a refusal. Two sources share the ONE shape —
/// the durable record of a refused dispatch (issue #141), and the refusal
/// DERIVED from the recorded facts for the shape nothing ever dispatched.
/// Paired with the read-time class, so a superseded refusal is never presented
/// as current.
fn refusal_doc(
    evidence: &SupervisionEvidence,
    verdict: &Verdict,
    next_step: &str,
    next_kind: &str,
) -> Val {
    if verdict.reason == codes::DISPATCH_REFUSED {
        return match &evidence.dispatch_refusal {
            Some(refusal) => object(vec![
                ("step", string(&refusal.step)),
                ("code", string(&refusal.code)),
                ("reason", string(&refusal.reason)),
                ("at", string(&refusal.at)),
            ]),
            None => null(),
        };
    }
    if verdict.reason == codes::DELIVERY_UNVERIFIED {
        return match unverified_delivery_refusal(evidence, next_step, next_kind) {
            // No instant: this refusal is read-time, derived from the recorded
            // facts the gate reads, and nothing about it was written down.
            Some(refusal) => object(vec![
                ("step", string(&refusal.step)),
                ("code", string(&refusal.code)),
                ("reason", string(&refusal.reason)),
                ("at", null()),
            ]),
            None => null(),
        };
    }
    null()
}

/// The next step's latest recorded outcome, or `None` when the step has
/// never been attempted.
fn latest_attempt_for<'a>(
    evidence: &'a SupervisionEvidence,
    step: &str,
) -> Option<&'a (String, String, String)> {
    evidence.attempts.iter().rfind(|(id, _, _)| id == step)
}

/// Classify one run from its recorded evidence. Pure: no clock, no lock, no
/// write — the same function backs the driver and the status read.
pub fn classify(
    evidence: &SupervisionEvidence,
    authorization_digest: &str,
    policy: &Policy,
    now_unix: i64,
) -> Verdict {
    let run = &evidence.run;
    // 1. The approved-plan fence: an unapproved or drifted plan is held, so
    //    it can never be reported eligible.
    if evidence.submission_digest.is_none() {
        return Verdict::new("unknown", codes::UNBOUND, false, "");
    }
    if !authorization_bound(evidence, authorization_digest) {
        return Verdict::new("unknown", codes::UNAPPROVED_PLAN, false, "");
    }
    if evidence.steps.is_empty() {
        return Verdict::new("unknown", codes::SPINE_MISSING, false, "");
    }
    // 2. Durable holds: a paused run is never eligible and never completed.
    if run.paused || run.pause_requested {
        return Verdict::new("paused", codes::PAUSED, false, "");
    }
    // 3. Terminal states. Completion requires recorded passing evidence: a
    //    `done` label alone is not completion.
    if run.status == "done" {
        return if newest_verdict(evidence) == "pass" {
            Verdict::new("completed", codes::COMPLETED, false, "")
        } else {
            Verdict::new("unknown", codes::COMPLETION_UNVERIFIED, false, "")
        };
    }
    if run.status == "invalidated" {
        return Verdict::new("needs-attention", codes::INVALIDATED, false, "");
    }
    if run.human_queue || run.status == "blocked" || run.terminal_blockers > 0 {
        return Verdict::new("needs-attention", codes::TERMINAL_HOLD, false, "");
    }
    // Issue #238: the review step hands a recorded FAIL to the run's own fix
    // round, so a FAIL is reported with the handoff's recorded disposition —
    // never as a bare park nothing continues:
    // - the handoff was REFUSED (the fix leg's lane could not be created, the
    //   spawn or the prompt was not taken, or the automatic bound is spent):
    //   the fix round's OWN engine code is the detail, so the class is
    //   actionable (`fix round refused: <code>`, or the escalation);
    // - the handoff was DISPATCHED for the current verdict's head: the run
    //   waits on its own repair leg, and the detail names its lane.
    if let Some(failure) = &evidence.last_failure
        && failure.code.starts_with("refusal.fix.")
    {
        return Verdict::new(
            "needs-attention",
            if failure.code == crate::mutation::code::FIX_BOUND_EXHAUSTED {
                codes::FIX_EXHAUSTED
            } else {
                codes::FIX_REFUSED
            },
            false,
            &failure.code,
        );
    }
    if newest_verdict(evidence) == "fail" {
        if let Some(fix) = &evidence.fix_round {
            // Issue #256: the disposition is derived from the repair leg's OWN
            // recorded state, not from the head the FAIL was handed at. The
            // leg's own lane checkout holds the head it DELIVERED, so a leg
            // that has already advanced the branch is never reported as work
            // in flight: the movement is named, with the remedy (the recorded
            // lane) first and both head prefixes, and the run is not left
            // waiting on a worker that has already reported by moving its own
            // head.
            if let Some(delivered) = evidence
                .fix_leg
                .as_ref()
                .filter(|leg| leg.delivered)
                .map(|leg| leg.head.as_str())
            {
                return Verdict::new(
                    "needs-attention",
                    codes::FIX_HEAD_MOVED,
                    false,
                    &fix_round_delivered_detail(fix, delivered),
                );
            }
            let newest_head = evidence
                .newest_evidence
                .as_ref()
                .map(|newest| newest.feature_head.clone())
                .unwrap_or_default();
            if newest_head == fix.feature_head {
                return Verdict::new("waiting-workers", codes::FIX_DISPATCHED, false, &fix.lane);
            }
            // Issue #254: the newest recorded handoff names ANOTHER head than
            // the run's newest recorded review evidence — the repair leg
            // advanced the branch past the head this evidence names, so the
            // recorded round is not its handoff. The disposition is still the
            // fix round's own (never a bare `review_failed`): the recorded lane
            // IS the remedy, and both head prefixes are named so the movement
            // is readable from the same read.
            return Verdict::new(
                "needs-attention",
                codes::FIX_HEAD_MOVED,
                false,
                &fix_round_head_moved_detail(fix, &newest_head),
            );
        }
        // A FAIL whose review step recorded no fix round at all — a plan that
        // presents its own review facts, or a run recorded before this
        // handoff existed — still names the frontier it parks on instead of
        // reporting an unexplained `needs-attention`.
        let review_step = evidence
            .steps
            .iter()
            .rev()
            .find(|(_, kind)| kind == crate::mutation::DELIVERY_STEP_KIND)
            .map(|(step, _)| step.clone())
            .unwrap_or_default();
        return Verdict::new("needs-attention", codes::REVIEW_FAILED, false, &review_step);
    }
    let next = next_unachieved_step(evidence);
    let next_step = next
        .as_ref()
        .map(|(step, _)| step.clone())
        .unwrap_or_default();
    let next_kind = next
        .as_ref()
        .map(|(_, kind)| kind.clone())
        .unwrap_or_default();
    // 4. Capacity: the latest recorded dispatch of the next unachieved step
    //    was refused for capacity and nothing succeeded after it.
    if let Some((_, status, code)) = latest_attempt_for(evidence, &next_step)
        && status != "succeeded"
        && code.starts_with("refusal.admission.cap_")
    {
        return Verdict::new(
            "blocked-capacity",
            codes::CAPACITY_BLOCKED,
            false,
            &next_step,
        );
    }
    // 5. Live work: an in-flight step claim is legitimate long-running work.
    if evidence.in_flight.is_some() {
        if next_kind == "collect_outcome" && evidence.in_flight.as_deref() == Some(&next_step) {
            return Verdict::new("waiting-workers", codes::WAITING_WORKERS, true, &next_step);
        }
        return Verdict::new("healthy", codes::IN_FLIGHT, false, &next_step);
    }
    if driver_dispatchable_kind(evidence, &next_step, &next_kind)
        && latest_attempt_for(evidence, &next_step).is_none()
        && !evidence.has_dispatch_context
    {
        return Verdict::new(
            "needs-attention",
            codes::DISPATCH_CONTEXT_MISSING,
            false,
            &next_step,
        );
    }
    // A RECORDED refusal of this frontier's own continuation dispatch (issue
    // #141). The driver DID dispatch the step and the apply engine refused it
    // before any effect (`latest_attempt_for` is None: no claim, no attempt, no
    // pane), so the refusal is the only evidence there is: reporting the step
    // as eligible with `supervision.dispatch.next_step` while the dispatch it
    // names is refused is exactly the defect. The engine's own code is named
    // instead, and the run is never reported eligible while that refusal
    // stands. The refusal stays current until RECORDED progress supersedes it
    // (`progress_at` moves whenever the evidence marker changes), so a
    // repaired environment or a repaired frontier is classified from the new
    // evidence alone — the driver keeps attempting the same continuation it
    // would attempt for an untouched frontier.
    if let Some(refusal) = &evidence.dispatch_refusal
        && refusal.step == next_step
        && latest_attempt_for(evidence, &next_step).is_none()
        && refusal.at.as_str() >= evidence.progress_at.as_str()
    {
        return Verdict::new(
            "needs-attention",
            codes::DISPATCH_REFUSED,
            false,
            &refusal.code,
        );
    }
    // Issue #230: the frontier is the run's own verified-delivery consumer and
    // the driver may not dispatch it because the run's newest recorded review
    // evidence carries a non-passing check. NOTHING is attempted in this shape
    // — the evidence gate refuses the tail before any dispatch exists — so no
    // dispatch refusal is ever recorded, and the run would otherwise fall
    // through to the progress-timeout branch and be reported as an eligible
    // continuation that never lands: the measured deadlock, where supervision
    // said `continuation-eligible` while `daemon.log` held zero dispatch
    // events for the frontier. The engine's own refusal is named instead, with
    // the code and the reason DERIVED from the same recorded facts the gate
    // reads. This is a report, never a relaxation: `driver_dispatchable_kind`
    // is untouched, so the tail is still never driven behind an unverified
    // delivery, and a recomputation that comes back failing derives exactly
    // the same refusal.
    //
    // The `latest_attempt_for(...).is_none()` guard is the SAME one its #141
    // sibling above carries, and it is what keeps issue #148's invariant: a
    // tail that HAS been attempted and recorded a concrete diagnosis is
    // reported with the attempt's OWN code (`supervision.step_diagnosed`), not
    // with a refusal derived from evidence that the attempt never reached (fix
    // round F1, finding B2).
    if let Some(refusal) = unverified_delivery_refusal(evidence, &next_step, &next_kind)
        && latest_attempt_for(evidence, &next_step).is_none()
    {
        return Verdict::new(
            "needs-attention",
            codes::DELIVERY_UNVERIFIED,
            false,
            &refusal.code,
        );
    }
    // A never-attempted, fully authored executor step is eligible NOW. The
    // driver dispatches it through the apply engine on this same check. The
    // eligible set is the SAME predicate the dispatch producer uses, so a
    // reported-eligible frontier is exactly a dispatchable one (issue #152).
    if evidence.has_dispatch_context
        && driver_dispatchable_kind(evidence, &next_step, &next_kind)
        && latest_attempt_for(evidence, &next_step).is_none()
    {
        return Verdict::new("healthy", codes::DISPATCH, true, &next_step);
    }
    // 6. Known waits for external evidence: never a progress-timeout case.
    //
    // ...but a wait is only honest while nothing has DIAGNOSED the step
    // (issue #148). A frontier step whose own latest attempt is recorded and
    // is not `succeeded` has already run and produced a concrete
    // failure/refusal. Bounded retries do not turn that diagnosis into live
    // work, so reporting it `waiting-workers`/`waiting-CI`/`waiting-approval`
    // presents a stalled run as if work or CI were still in flight. The
    // recorded attempt's own code is the named blocker instead (the same
    // honesty #141/#144 apply to a refusal recorded before any attempt).
    if let Some((_, status, code)) = latest_attempt_for(evidence, &next_step)
        && status != "succeeded"
    {
        if next_kind == "collect_outcome" && code == crate::mutation::code::WORKER_TIMEOUT {
            return Verdict::new("worker-timeout", codes::WORKER_TIMEOUT, false, &next_step);
        }
        let detail = if code.is_empty() {
            status.as_str()
        } else {
            code.as_str()
        };
        return Verdict::new("needs-attention", codes::STEP_DIAGNOSED, false, detail);
    }
    if APPROVAL_STEP_KINDS.contains(&next_kind.as_str()) {
        return Verdict::new(
            "waiting-approval",
            codes::WAITING_APPROVAL,
            false,
            &next_step,
        );
    }
    if CI_STEP_KINDS.contains(&next_kind.as_str()) {
        return Verdict::new("waiting-CI", codes::WAITING_CI, false, &next_step);
    }
    if WORKER_STEP_KINDS.contains(&next_kind.as_str()) {
        return Verdict::new("waiting-workers", codes::WAITING_WORKERS, false, &next_step);
    }
    // 7. Absence of evidence. The recorded marker has not moved within the
    //    explicit policy window and nothing else explains the stall. A run
    //    with NO recorded observation yet is HELD, never eligible: an
    //    unobserved run is not a timed-out one, so a fresh arm can never open
    //    a continuation window.
    let progress_age = progress_age_secs(&evidence.progress_at, now_unix);
    match progress_age {
        Some(age) if age >= policy.progress_timeout_secs => Verdict::new(
            "continuation-eligible",
            codes::PROGRESS_TIMEOUT,
            true,
            &next_step,
        ),
        Some(_) => Verdict::new("healthy", codes::RECENT_PROGRESS, false, &next_step),
        None => Verdict::new("unknown", codes::PROGRESS_UNOBSERVED, false, &next_step),
    }
}

/// Observe the run's recorded fix-round leg against its OWN lane checkout
/// (issue #256).
///
/// The head a handoff was DISPATCHED for is the head the FAIL was handed at
/// and can never move by itself; the leg's own checkout is the only recorded
/// state that names the head it DELIVERED. The observation is a read (bounded
/// git, allowlisted environment — no effect, no journal, no write): every
/// failure to take it leaves `fix_leg` unset, and an unobserved leg is never
/// reported as moved.
pub fn observe_fix_leg(evidence: &mut SupervisionEvidence, worktrees_root: Option<&Path>) {
    if evidence.fix_leg.is_some() {
        return;
    }
    let (Some(root), Some(fix)) = (worktrees_root, evidence.fix_round.as_ref()) else {
        return;
    };
    evidence.fix_leg =
        crate::mutation::observe_fix_leg_checkout(root, &fix.worktree, &fix.feature_head);
}

/// The `worktrees_root` one run's own recorded topology declares (issue #256):
/// the containment root the handoff's recorded lane checkout is read under.
/// `None` when the run recorded no topology (or none that names a root) — the
/// observation is then simply not taken.
///
/// Issue #268: derived from the run's recorded rows, which every caller
/// already read for its own question (the driver's pass, the daemon's
/// review-head binding) instead of re-reading the run to answer this one.
pub(crate) fn recorded_worktrees_root_of(records: &crate::state::RunRecords) -> Option<PathBuf> {
    let context = records.dispatch_context().ok().flatten()?;
    context
        .topology
        .get("worktrees_root")
        .and_then(Val::as_str)
        .filter(|root| !root.is_empty())
        .map(PathBuf::from)
}

/// The bounded detail of a recorded handoff whose OWN leg DELIVERED a head
/// past the one the FAIL was handed at (issue #256): the remedy FIRST — the
/// fix leg's own lane — then both 12-character head prefixes: the head the
/// verdict certified (the head the handoff was dispatched for) and the head
/// the leg's own checkout delivered.
fn fix_round_delivered_detail(
    fix: &crate::state::SupervisionFixRound,
    delivered_head: &str,
) -> String {
    let prefix = |head: &str| head.chars().take(12).collect::<String>();
    format!(
        "{} (reviewed at {}, delivered at {})",
        fix.lane,
        prefix(&fix.feature_head),
        prefix(delivered_head)
    )
}

/// The bounded detail of a recorded handoff that names a head the run's newest
/// recorded review evidence does not name (issue #254): the remedy FIRST — the
/// fix leg's own lane — then both 12-character head prefixes, so the movement
/// the disposition reports is readable from the same status read.
fn fix_round_head_moved_detail(
    fix: &crate::state::SupervisionFixRound,
    newest_head: &str,
) -> String {
    let prefix = |head: &str| head.chars().take(12).collect::<String>();
    format!(
        "{} (handoff recorded at {}, newest evidence at {})",
        fix.lane,
        prefix(&fix.feature_head),
        prefix(newest_head)
    )
}

/// The age (seconds) of an RFC3339 instant against `now_unix`; `None` when
/// the instant is missing or unreadable. A future instant reports age 0
/// (clock movement is never read as progress).
fn progress_age_secs(at: &str, now_unix: i64) -> Option<i64> {
    let unix = time::unix_from_rfc3339(at)?;
    Some((now_unix - unix).max(0))
}

/// The meaningful-progress observation of one evidence snapshot: the marker
/// digest plus the closed family that most recently moved it. Derived from
/// RECORDED rows only — reads, heartbeats and rendered status are not
/// inputs, so they can never reset the marker.
pub fn progress_observation(
    evidence: &SupervisionEvidence,
    stored_at: &str,
) -> (String, &'static str) {
    let run = &evidence.run;
    let attempts: Vec<Val> = evidence
        .attempts
        .iter()
        .map(|(step, status, code)| {
            object(vec![
                ("step", string(step)),
                ("status", string(status)),
                ("code", string(code)),
            ])
        })
        .collect();
    let verdicts: Vec<Val> = evidence
        .verdicts
        .iter()
        .map(|(evidence_id, verdict, created_at)| {
            object(vec![
                ("evidence_id", string(evidence_id)),
                ("verdict", string(verdict)),
                ("created_at", string(created_at)),
            ])
        })
        .collect();
    let retries: Vec<Val> = evidence
        .retries
        .iter()
        .map(|retry| {
            object(vec![
                ("retry_id", string(&retry.retry_id)),
                ("step_id", string(&retry.step_id)),
                ("attempt", integer(retry.attempt)),
                ("consumed_at", string(&retry.consumed_at)),
            ])
        })
        .collect();
    let doc = object(vec![
        ("status", string(&run.status)),
        ("phase", string(&run.phase)),
        ("node", string(&run.current_node)),
        ("paused", bool_(run.paused)),
        ("pause_requested", bool_(run.pause_requested)),
        ("human_queue", bool_(run.human_queue)),
        ("terminal_blockers", integer(run.terminal_blockers as i64)),
        ("updated_at", string(&run.updated_at)),
        ("attempts", Val::Arr(attempts)),
        ("verdicts", Val::Arr(verdicts)),
        ("retries", Val::Arr(retries)),
        (
            "in_flight",
            string(evidence.in_flight.as_deref().unwrap_or("")),
        ),
        (
            "owner",
            string(evidence.ownership_instance.as_deref().unwrap_or("")),
        ),
    ]);
    let marker = sha256_hex(&canonical_bytes(&doc));
    let source = if let Some((_, _, created_at)) = evidence.verdicts.first() {
        if created_at.as_str() > stored_at {
            "review"
        } else {
            "state"
        }
    } else if let Some((step, _, _)) = evidence.attempts.last() {
        let kind = step_kind(evidence, step);
        if CI_STEP_KINDS.contains(&kind) {
            "ci"
        } else if step.is_empty() {
            "state"
        } else {
            "completion"
        }
    } else {
        "state"
    };
    (marker, source)
}

/// Render the `hf-supervision/v1` status projection of one supervised run:
/// the versioned status with freshness, last check, next eligible check and
/// reason (issue #95 AC7).
pub fn status_doc(
    row: &SupervisionRow,
    evidence: &SupervisionEvidence,
    trigger: Option<&SupervisionTriggerRow>,
    verdict: &Verdict,
    now_unix: i64,
) -> Val {
    let run = &evidence.run;
    let policy = Policy {
        check_interval_secs: row.check_interval_secs,
        progress_timeout_secs: row.progress_timeout_secs,
    };
    let freshness_secs = policy.freshness_secs();
    let last_age = progress_age_secs(&row.last_check_at, now_unix);
    let (freshness_state, freshness_age) = match last_age {
        None => ("missing", null()),
        Some(age) if age <= freshness_secs => ("fresh", integer(age)),
        Some(age) => ("stale", integer(age)),
    };
    let progress_age = progress_age_secs(&row.progress_at, now_unix);
    let next_unix = time::unix_from_rfc3339(&row.next_check_at);
    let next_in = next_unix.map(|unix| (unix - now_unix).max(0));
    let next_step = next_unachieved_step(evidence)
        .map(|(step, _)| step)
        .unwrap_or_default();
    let next_kind = if next_step.is_empty() {
        String::new()
    } else {
        step_kind(evidence, &next_step).to_string()
    };
    // Issue #241: the retry disposition of the frontier step, read from the
    // SAME durable rows the engine's own fence reads. It is what tells
    // `awaiting an operator authorization` (nothing is authorized and the
    // driver derives no dispatch) from `authorized, awaiting dispatch` (the
    // run holds an unconsumed `run.retry` authorization, spent by the ONE
    // re-dispatch it authorizes) from `driver dispatch` (no authorization is
    // held yet: supervision mints and consumes its own on this check) from an
    // exhausted bound — and a recorded dispatch refusal is already named by
    // the block below, never confused with a held authorization.
    let retry = {
        let step_retries: Vec<&crate::state::RunRetryRow> = evidence
            .retries
            .iter()
            .filter(|retry| retry.step_id == next_step)
            .collect();
        let consumed = step_retries
            .iter()
            .filter(|retry| !retry.consumed_at.is_empty())
            .count();
        let held = step_retries
            .iter()
            .any(|retry| retry.consumed_at.is_empty());
        let diagnosed =
            latest_attempt_for(evidence, &next_step).is_some_and(|(_, status, code)| {
                status != "succeeded" && crate::state::step_attempt_diagnosed(status, code)
            });
        let state = if !diagnosed {
            "none"
        } else if held {
            "authorized-awaiting-dispatch"
        } else if dispatch_intent(row, evidence).is_some_and(|intent| intent.step_id == next_step) {
            "driver-dispatch"
        } else if step_retries.len() >= crate::state::RUN_RETRY_MAX as usize {
            "exhausted"
        } else {
            "awaiting-authorization"
        };
        object(vec![
            ("step", string(&next_step)),
            ("state", string(state)),
            ("consumed", integer(consumed as i64)),
            ("bound", integer(crate::state::RUN_RETRY_MAX)),
        ])
    };
    let steps: Vec<Val> = evidence
        .steps
        .iter()
        .map(|(id, kind)| object(vec![("id", string(id)), ("kind", string(kind))]))
        .collect();
    let attempts: Vec<Val> = evidence
        .attempts
        .iter()
        .map(|(step, status, code)| {
            object(vec![
                ("step", string(step)),
                ("status", string(status)),
                ("code", string(code)),
            ])
        })
        .collect();
    let retries: Vec<Val> = evidence
        .retries
        .iter()
        .map(|retry| {
            object(vec![
                ("retry_id", string(&retry.retry_id)),
                ("step_id", string(&retry.step_id)),
                ("attempt", integer(retry.attempt)),
                ("authorized_at", string(&retry.authorized_at)),
                ("consumed_at", string(&retry.consumed_at)),
            ])
        })
        .collect();
    object(vec![
        ("schema", string(SUPERVISION_SCHEMA)),
        (
            "run",
            object(vec![
                ("instance_id", string(&run.instance_id)),
                ("repository", string(&run.repository)),
                ("issue_number", integer(run.issue_number)),
                ("status", string(&run.status)),
                ("phase", string(&run.phase)),
                ("node", string(&run.current_node)),
                ("state_epoch", integer(run.state_epoch)),
                ("paused", bool_(run.paused)),
                ("pause_requested", bool_(run.pause_requested)),
                ("human_queue", bool_(run.human_queue)),
                ("terminal_blockers", integer(run.terminal_blockers as i64)),
            ]),
        ),
        (
            "supervision",
            object(vec![
                ("id", string(&row.supervision_id)),
                ("desired", string(&row.desired)),
                (
                    "state",
                    string(if row.desired == "armed" {
                        "active"
                    } else {
                        "disabled"
                    }),
                ),
                ("armed_at", string(&row.armed_at)),
                ("owner_generation", integer(row.owner_generation)),
                ("run_generation", integer(row.run_generation)),
                (
                    "authorization",
                    object(vec![
                        ("digest", string(&row.authorization_digest)),
                        ("approved_boundary", string(&row.approved_boundary)),
                        (
                            "bound",
                            string(evidence.submission_digest.as_deref().unwrap_or("")),
                        ),
                    ]),
                ),
                (
                    "policy",
                    object(vec![
                        ("check_interval_secs", integer(row.check_interval_secs)),
                        ("progress_timeout_secs", integer(row.progress_timeout_secs)),
                        ("freshness_secs", integer(freshness_secs)),
                    ]),
                ),
            ]),
        ),
        (
            "evaluation",
            object(vec![
                // What a read reports is the RECORDED result of the last
                // committed check, never a read-time re-classification: a
                // committed counter can not be laundered by re-deriving the
                // class here. Before the first committed check nothing is
                // recorded yet, so the read-time observation is the only view
                // (and it is exactly the view the driver is about to commit).
                (
                    "class",
                    string(if row.checks > 0 {
                        row.last_check_class.as_str()
                    } else {
                        verdict.class
                    }),
                ),
                (
                    "reason",
                    string(if row.checks > 0 {
                        row.last_check_reason.as_str()
                    } else {
                        verdict.reason
                    }),
                ),
                (
                    "eligible",
                    bool_(if row.checks > 0 {
                        row.continuation_open
                    } else {
                        verdict.eligible
                    }),
                ),
                (
                    "observed",
                    object(vec![
                        ("class", string(verdict.class)),
                        ("reason", string(verdict.reason)),
                        ("eligible", bool_(verdict.eligible)),
                        ("detail", string(&verdict.detail)),
                    ]),
                ),
                ("detail", string(&verdict.detail)),
                ("checks", integer(row.checks)),
                (
                    "last_check",
                    object(vec![
                        ("at", string(&row.last_check_at)),
                        ("class", string(&row.last_check_class)),
                        ("reason", string(&row.last_check_reason)),
                        ("trigger", string(&row.last_check_trigger)),
                    ]),
                ),
                (
                    "next_check",
                    object(vec![
                        ("at", string(&row.next_check_at)),
                        ("reason", string(&row.next_check_reason)),
                        (
                            "due_in_secs",
                            match next_in {
                                Some(secs) => integer(secs),
                                None => null(),
                            },
                        ),
                    ]),
                ),
                (
                    "freshness",
                    object(vec![
                        ("state", string(freshness_state)),
                        ("age_secs", freshness_age.clone()),
                        ("max_age_secs", integer(freshness_secs)),
                    ]),
                ),
                (
                    "progress",
                    object(vec![
                        ("marker", string(&row.progress_marker)),
                        ("at", string(&row.progress_at)),
                        ("source", string(&row.progress_source)),
                        (
                            "age_secs",
                            match progress_age {
                                Some(age) => integer(age),
                                None => null(),
                            },
                        ),
                    ]),
                ),
                // Issue #230: the ENGINE's own refusal of this frontier's
                // continuation, named with BOTH its code and its reason. Two
                // sources, ONE shape: the durable record left by a refused
                // dispatch (issue #141), and — for the shape where the
                // evidence gate refuses the tail BEFORE any dispatch exists —
                // the refusal DERIVED from the same recorded facts. The
                // classification already refuses to report such a frontier
                // eligible; without this block the operator still saw only a
                // class, never the engine's own words for why nothing landed.
                // Read-time only and PAIRED with the read-time class: a
                // superseded refusal is never presented as current.
                (
                    "refusal",
                    refusal_doc(evidence, verdict, &next_step, &next_kind),
                ),
                // Issue #241: the retry disposition of this frontier (see
                // `retry` above). Read-time only, exactly like `refusal`.
                ("retry", retry),
                (
                    "continuation",
                    object(vec![
                        // Durable window state ONLY (never a read-time guess):
                        // `state`/`since`/`reports` are what the driver
                        // committed, so a read can not hide a report that
                        // already happened.
                        (
                            "state",
                            string(if row.continuation_open {
                                "open"
                            } else {
                                "closed"
                            }),
                        ),
                        ("since", string(&row.continuation_since)),
                        ("reports", integer(row.continuation_reports)),
                    ]),
                ),
                (
                    "pending",
                    object(vec![
                        (
                            "trigger",
                            match trigger {
                                Some(trigger) => string(&trigger.trigger),
                                None => null(),
                            },
                        ),
                        (
                            "seq",
                            match trigger {
                                Some(trigger) => integer(trigger.trigger_seq),
                                None => null(),
                            },
                        ),
                        (
                            "folded",
                            match trigger {
                                Some(trigger) => integer(trigger.folded),
                                None => null(),
                            },
                        ),
                    ]),
                ),
            ]),
        ),
        (
            "cursor",
            object(vec![
                ("next_step", string(&next_step)),
                ("next_step_kind", string(&next_kind)),
                ("steps", Val::Arr(steps)),
                ("attempts", Val::Arr(attempts)),
                (
                    "in_flight",
                    string(evidence.in_flight.as_deref().unwrap_or("")),
                ),
            ]),
        ),
        // Issue #219: the newest recorded NON-succeeded attempt WITH its raw
        // message. The measured defect was a failed effect whose reason existed
        // nowhere a read-back could show it (`detail` above carries the code
        // alone, and both daemon logs were 0 bytes), so the durable outcome's
        // own message is surfaced here verbatim for an operator to read.
        (
            "last_failure",
            match &evidence.last_failure {
                Some(failure) => object(vec![
                    ("step", string(&failure.step)),
                    ("status", string(&failure.status)),
                    ("code", string(&failure.code)),
                    ("message", string(&failure.message)),
                ]),
                None => null(),
            },
        ),
        (
            "retries",
            object(vec![
                ("bound", integer(crate::state::RUN_RETRY_MAX)),
                ("rows", Val::Arr(retries)),
            ]),
        ),
        (
            "scope",
            object(vec![
                ("level", string("run")),
                ("run", string(&run.instance_id)),
                ("fleet_effect", string("none")),
                ("harness_effect", string("none")),
            ]),
        ),
        ("statement", string(STATEMENT)),
    ])
}

// ---------------------------------------------------------------------------
// The driver: one coalesced reconciliation per run and wake window.
// ---------------------------------------------------------------------------

/// Optional knobs of the driver thread (`now` always comes from
/// `crate::time`, exactly like every other daemon loop).
#[derive(Clone)]
pub struct SupervisorOptions {
    /// Upper bound on one wait between ticks (seconds).
    pub max_wait_secs: i64,
    /// The dispatch hook of an armed run's continuation (issue #92 F4). The
    /// daemon implements it with the merged apply engine; `None` keeps the
    /// driver classification-only.
    pub dispatch: Option<Arc<dyn SupervisedDispatch>>,
}

impl Default for SupervisorOptions {
    fn default() -> SupervisorOptions {
        SupervisorOptions {
            max_wait_secs: DEFAULT_MAX_WAIT_SECS,
            dispatch: None,
        }
    }
}

/// The wait/stop half of the driver, shared with the daemon's request
/// handlers so a committed mutation can wake the driver without a handle
/// dance. Never holds the state guard.
pub struct SupervisorWake {
    stop: AtomicBool,
    gate: Mutex<bool>,
    condvar: Condvar,
    ticks: AtomicU64,
    #[cfg(test)]
    deadline_evaluations: AtomicU64,
    checks: AtomicU64,
    /// Dispatches handed to the daemon's apply engine (issue #92 F4).
    dispatches: AtomicU64,
    /// Whether the driver is blocked inside its wait RIGHT NOW (test
    /// observability: the wake is set strictly AFTER any guard the caller
    /// chose to hold, so an observer that sees `true` sees the driver's
    /// real waiting state).
    waiting: AtomicBool,
}

impl SupervisorWake {
    fn new() -> SupervisorWake {
        SupervisorWake {
            stop: AtomicBool::new(false),
            gate: Mutex::new(false),
            condvar: Condvar::new(),
            ticks: AtomicU64::new(0),
            #[cfg(test)]
            deadline_evaluations: AtomicU64::new(0),
            checks: AtomicU64::new(0),
            dispatches: AtomicU64::new(0),
            waiting: AtomicBool::new(false),
        }
    }

    /// Ask the driver to re-evaluate promptly (coalesced; never blocks).
    pub fn wake(&self) {
        let mut gate = match self.gate.lock() {
            Ok(gate) => gate,
            Err(_) => return,
        };
        *gate = true;
        drop(gate);
        self.condvar.notify_one();
    }

    /// Cancel the driver: the loop stops at its next check point.
    pub fn signal_stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
        self.wake();
    }

    /// Whether a stop was signalled.
    pub fn stopping(&self) -> bool {
        self.stop.load(Ordering::SeqCst)
    }

    /// Driver ticks performed (test observability).
    pub fn ticks(&self) -> u64 {
        self.ticks.load(Ordering::SeqCst)
    }

    /// Run-scoped reconciliations performed (test observability).
    pub fn checks(&self) -> u64 {
        self.checks.load(Ordering::SeqCst)
    }

    /// Dispatches handed to the apply engine so far (test observability).
    pub fn dispatches(&self) -> u64 {
        self.dispatches.load(Ordering::SeqCst)
    }

    /// Whether the driver is blocked in its wait right now (test
    /// observability; the flag is raised strictly after the caller has
    /// taken every guard it intends to hold).
    pub fn waiting(&self) -> bool {
        self.waiting.load(Ordering::SeqCst)
    }

    /// Block until a wake is signalled, `deadline` passes, or a stop is
    /// signalled. The state guard is NOT held here by design.
    fn wait_for_wake(&self, deadline: Option<Instant>) {
        let mut gate = match self.gate.lock() {
            Ok(gate) => gate,
            Err(_) => return,
        };
        if *gate || self.stop.load(Ordering::SeqCst) {
            *gate = false;
            return;
        }
        let timeout = match deadline {
            Some(deadline) => {
                let now = Instant::now();
                if deadline <= now {
                    // A due row can remain due when its reconciliation cannot
                    // commit. Back off instead of re-querying SQLite in a
                    // full-core loop; a new-work wake still interrupts this.
                    Duration::from_secs(1)
                } else {
                    deadline - now
                }
            }
            None => Duration::from_secs(DEFAULT_MAX_WAIT_SECS as u64),
        };
        self.waiting.store(true, Ordering::SeqCst);
        let (mut gate, _timeout_result) = match self.condvar.wait_timeout(gate, timeout) {
            Ok(result) => result,
            Err(_) => {
                self.waiting.store(false, Ordering::SeqCst);
                return;
            }
        };
        self.waiting.store(false, Ordering::SeqCst);
        *gate = false;
    }
}

/// A running driver: the shared wait handle plus its thread.
pub struct SupervisorHandle {
    wake: Arc<SupervisorWake>,
    thread: Option<JoinHandle<()>>,
}

impl SupervisorHandle {
    /// The shared wait/stop handle (cheap clone for request handlers).
    pub fn wake_handle(&self) -> Arc<SupervisorWake> {
        Arc::clone(&self.wake)
    }

    /// Join the driver thread (`true` when it exited cleanly).
    pub fn join(&mut self) -> bool {
        match self.thread.take() {
            Some(thread) => thread.join().is_ok(),
            None => true,
        }
    }
}

/// The driver body: one boot reconciliation, then one coalesced pass per
/// wake/deadline.
struct SupervisorCore {
    state: Arc<Mutex<State>>,
    wake: Arc<SupervisorWake>,
    options: SupervisorOptions,
}

impl SupervisorCore {
    /// ONE pass: fold the semantic events, then perform exactly one
    /// reconciliation per due run (the due set is folded per run, so a
    /// duplicate, out-of-order or concurrent timer/event wake can never
    /// produce two reconciliations).
    fn pass(&self, boot: bool) {
        let now_unix = time::unix_now();
        let at = time::rfc3339_now();
        // Phase 1 (short guard): fold the durable semantic events into the
        // per-run pending trigger slots and advance the retention cursor.
        {
            let state = match self.state.lock() {
                Ok(state) => state,
                Err(_) => return,
            };
            let runtime = match state.supervision_runtime() {
                Ok(runtime) => runtime,
                Err(_) => return,
            };
            let fold = match state.fold_supervision_events(runtime.event_cursor, &at) {
                Ok(fold) => fold,
                Err(_) => return,
            };
            if fold.cursor != runtime.event_cursor
                && state.set_supervision_runtime(fold.cursor, &at).is_err()
            {
                return;
            }
        }
        // Phase 2 (short guard): the coalesced due set — ONE entry per run
        // however many wake sources agree. The BOOT pass sweeps every armed
        // run instead: a restart (or any long gap) yields exactly ONE fresh
        // snapshot reconciliation per run, never a catch-up storm.
        let due = {
            let state = match self.state.lock() {
                Ok(state) => state,
                Err(_) => return,
            };
            let runs = if boot {
                state.supervision_armed_runs()
            } else {
                state.supervision_due_runs(now_unix)
            };
            match runs {
                Ok(due) => due,
                Err(_) => return,
            }
        };
        let mut checks = 0u64;
        for instance_id in due {
            if self.reconcile(&instance_id, boot, now_unix) {
                checks += 1;
            }
        }
        self.wake.ticks.fetch_add(1, Ordering::SeqCst);
        self.wake.checks.fetch_add(checks, Ordering::SeqCst);
    }

    /// ONE run-scoped reconciliation: short read, pure classification,
    /// short write. The state guard is released between the phases.
    fn reconcile(&self, instance_id: &str, boot: bool, now_unix: i64) -> bool {
        let (row, evidence, trigger, worktrees_root) = {
            let state = match self.state.lock() {
                Ok(state) => state,
                Err(_) => return false,
            };
            let row = match state.supervision_by_id(instance_id) {
                Ok(Some(row)) if row.desired == "armed" => row,
                _ => return false,
            };
            // Issue #268: the run's recorded rows are read ONCE here — the
            // evidence snapshot and the recorded worktrees root below are
            // derived from this one read instead of each re-scanning and
            // re-parsing the journal for itself.
            let records = match state.run_records(instance_id) {
                Ok(records) => records,
                Err(_) => return false,
            };
            let evidence = match state.supervision_evidence_from(&records) {
                Ok(Some(evidence)) => evidence,
                _ => return false,
            };
            let trigger = state.supervision_trigger(instance_id).ok().flatten();
            let worktrees_root = recorded_worktrees_root_of(&records);
            (row, evidence, trigger, worktrees_root)
        };
        // Issue #256: the repair leg's OWN checkout is read AFTER the state
        // guard is released — the classification reads a fact about the leg's
        // own state, and that read never holds the state.
        let mut evidence = evidence;
        observe_fix_leg(&mut evidence, worktrees_root.as_deref());
        let plan = check_plan(&row, &evidence, trigger.as_ref(), boot, now_unix);
        let committed = {
            let state = match self.state.lock() {
                Ok(state) => state,
                Err(_) => return false,
            };
            state.commit_supervision_check(&plan).is_ok()
        };
        if !committed {
            return false;
        }
        // Issue #92 F4: the committed check may carry ONE continuation
        // dispatch. It runs through the daemon's apply engine (every gate
        // re-derives there) AFTER the check is durable and OUTSIDE the state
        // guard; a refused or failed dispatch is the daemon's record — the
        // driver never retries it inside the same check.
        if let (Some(intent), Some(dispatcher)) = (&plan.dispatch, self.options.dispatch.as_ref()) {
            let _ = dispatcher.dispatch(intent);
            self.wake.dispatches.fetch_add(1, Ordering::SeqCst);
        }
        true
    }

    /// The nearest wake instant: the smallest scheduled check (bounded).
    fn next_deadline(&self) -> Option<Instant> {
        #[cfg(test)]
        self.wake
            .deadline_evaluations
            .fetch_add(1, Ordering::SeqCst);
        let wait = {
            let state = match self.state.lock() {
                Ok(state) => state,
                Err(_) => return Some(Instant::now()),
            };
            match state.supervision_next_due_in(time::unix_now()) {
                Ok(Some(secs)) => secs,
                Ok(None) => self.options.max_wait_secs,
                Err(_) => return Some(Instant::now()),
            }
        };
        let wait = wait.clamp(0, self.options.max_wait_secs);
        Some(Instant::now() + Duration::from_secs(wait as u64))
    }
}

/// Map one recorded trigger name onto the closed wake vocabulary.
fn trigger_name_static(name: &str) -> &'static str {
    TRIGGERS
        .iter()
        .find(|candidate| **candidate == name)
        .copied()
        .unwrap_or("completion")
}

/// The next eligible check after a reconciliation that ran at `now_unix`:
/// re-anchored to NOW, so any wall-clock jump (sleep, suspend, DST) skips the
/// missed windows instead of replaying them — the run is never due again
/// until a fresh interval has elapsed.
pub fn next_check_unix(now_unix: i64, policy: &Policy) -> i64 {
    now_unix + policy.check_interval_secs
}

/// Build the plan of ONE reconciliation from the recorded row and the
/// evidence snapshot the driver read: the pure half of the run-scoped check
/// (the state transaction consumes the wake slot and writes it). Every time
/// decision takes `now_unix` explicitly, so the whole driver path is
/// testable with a controllable clock.
pub fn check_plan(
    row: &SupervisionRow,
    evidence: &SupervisionEvidence,
    trigger: Option<&SupervisionTriggerRow>,
    boot: bool,
    now_unix: i64,
) -> SupervisionCheckPlan {
    let policy = Policy {
        check_interval_secs: row.check_interval_secs,
        progress_timeout_secs: row.progress_timeout_secs,
    };
    let verdict = classify(evidence, &row.authorization_digest, &policy, now_unix);
    let (marker, source) = progress_observation(evidence, &row.progress_at);
    // Issue #96: the fresh verified delivery of this run (if any) is the ONE
    // continuation effect of a check — the intent rides on the plan and the
    // commit transaction re-verifies it under the guard before it advances
    // the queue cursor. An unapproved plan is never a delivery.
    let advance = if authorization_bound(evidence, &row.authorization_digest) {
        verified_delivery(evidence)
    } else {
        None
    };
    let trigger_label: &'static str = if boot {
        "boot"
    } else {
        match trigger.map(|trigger| trigger.trigger.as_str()) {
            Some(name) => trigger_name_static(name),
            None => "timer",
        }
    };
    // Issue #92 F4: the ONE continuation dispatch of this check. The intent
    // is derived from the same snapshot the classification used, and the
    // caller (the daemon) runs it through the merged apply engine — the
    // driver itself runs no effect.
    let dispatch = dispatch_intent(row, evidence);
    SupervisionCheckPlan {
        instance_id: row.instance_id.clone(),
        now_unix,
        at: time::rfc3339_from_unix(now_unix),
        class: verdict.class,
        reason: verdict.reason,
        eligible: verdict.eligible,
        trigger: trigger_label,
        consumed_seq: if boot {
            0
        } else {
            trigger.map(|trigger| trigger.trigger_seq).unwrap_or(0)
        },
        consumed_all: boot,
        marker,
        marker_source: source,
        next_check_unix: next_check_unix(now_unix, &policy),
        next_check_reason: codes::RECENT_PROGRESS,
        advance,
        dispatch,
    }
}

/// Start the supervised reconciliation driver for one daemon state handle.
/// The boot reconciliation runs once (one fresh snapshot check per armed
/// run), then the loop waits for a wake or the bounded deadline.
pub fn start(state: Arc<Mutex<State>>, options: SupervisorOptions) -> SupervisorHandle {
    let wake = Arc::new(SupervisorWake::new());
    let core = SupervisorCore {
        state,
        wake: Arc::clone(&wake),
        options,
    };
    let handle = std::thread::Builder::new()
        .name("canter-supervision".to_string())
        .spawn(move || {
            let core = core;
            core.pass(true);
            loop {
                if core.wake.stopping() {
                    return;
                }
                let deadline = core.next_deadline();
                core.wake.wait_for_wake(deadline);
                if core.wake.stopping() {
                    return;
                }
                core.pass(false);
            }
        });
    SupervisorHandle {
        wake,
        thread: handle.ok(),
    }
}

/// The human rendering of one supervision document.
pub fn render_human(doc: &Val) -> String {
    let text = |value: &Val, key: &str| -> String {
        value
            .get(key)
            .and_then(Val::as_str)
            .unwrap_or("unknown")
            .to_string()
    };
    let number =
        |value: &Val, key: &str| -> i64 { value.get(key).and_then(Val::as_int).unwrap_or(0) };
    let run = doc.get("run").cloned().unwrap_or_else(null);
    let evaluation = doc.get("evaluation").cloned().unwrap_or_else(null);
    let supervision = doc.get("supervision").cloned().unwrap_or_else(null);
    let last_check = evaluation.get("last_check").cloned().unwrap_or_else(null);
    let next_check = evaluation.get("next_check").cloned().unwrap_or_else(null);
    let progress = evaluation.get("progress").cloned().unwrap_or_else(null);
    let mut lines = vec![
        format!(
            "supervision {} ({}), run {} ({})",
            text(&supervision, "id"),
            text(&supervision, "desired"),
            text(&run, "instance_id"),
            text(&run, "status")
        ),
        format!(
            "class {} ({}), eligible {}",
            text(&evaluation, "class"),
            text(&evaluation, "reason"),
            evaluation
                .get("eligible")
                .and_then(Val::as_bool)
                .unwrap_or(false)
        ),
    ];
    // Issue #219: a standing failure is rendered WITH its raw message — the
    // same reason the durable record carries, so a human read tells a rejected
    // push from a refused merge without opening a daemon log.
    let failure = doc.get("last_failure").cloned().unwrap_or_else(null);
    if failure.get("code").and_then(Val::as_str).is_some() {
        lines.push(format!(
            "last failure {} {} ({}): {}",
            text(&failure, "step"),
            text(&failure, "status"),
            text(&failure, "code"),
            text(&failure, "message")
        ));
    }
    // Issue #238: the FAIL handoff's recorded disposition, rendered with the
    // fix leg's lane or the fix round's OWN engine code — so a human read
    // tells "awaiting a fix round" from "fix round refused: <code>".
    let reason = text(&evaluation, "reason");
    let detail = text(&evaluation, "detail");
    if reason.starts_with("supervision.fix_round") && !detail.is_empty() {
        lines.push(match reason.as_str() {
            codes::FIX_DISPATCHED => format!("fix round dispatched to lane {detail}"),
            codes::FIX_HEAD_MOVED => {
                format!("fix round recorded for another head (lane {detail})")
            }
            codes::FIX_EXHAUSTED => {
                format!("fix round refused: {detail} (the automatic bound is spent)")
            }
            _ => format!("fix round refused: {detail}"),
        });
    }
    // Issue #230: a continuation the ENGINE refuses is rendered with the
    // engine's own code AND reason — an operator reading `supervision status`
    // sees why the named frontier never lands instead of a silent idle.
    let refusal = evaluation.get("refusal").cloned().unwrap_or_else(null);
    if refusal.get("code").and_then(Val::as_str).is_some() {
        lines.push(format!(
            "refused continuation {} ({}): {}",
            text(&refusal, "step"),
            text(&refusal, "code"),
            text(&refusal, "reason")
        ));
    }
    // Issue #241: the frontier's retry disposition in words — `awaiting an
    // operator authorization` and `authorized, awaiting dispatch` are never
    // the same read, and neither is a refused continuation.
    let retry = evaluation.get("retry").cloned().unwrap_or_else(null);
    let retry_label = match retry.get("state").and_then(Val::as_str).unwrap_or("") {
        "awaiting-authorization" => "awaiting an operator authorization",
        "authorized-awaiting-dispatch" => "authorized, awaiting dispatch",
        "driver-dispatch" => "the driver's own bounded retry",
        "exhausted" => "bound exhausted",
        _ => "",
    };
    if !retry_label.is_empty() {
        lines.push(format!(
            "retry {retry_label}: step {} ({}/{} consumed)",
            text(&retry, "step"),
            number(&retry, "consumed"),
            number(&retry, "bound")
        ));
    }
    lines.extend([
        format!(
            "last check {} ({}, {})",
            text(&last_check, "at"),
            text(&last_check, "class"),
            text(&last_check, "trigger")
        ),
        format!(
            "next check {} ({})",
            text(&next_check, "at"),
            text(&next_check, "reason")
        ),
        format!(
            "progress {} at {} ({})",
            text(&progress, "marker"),
            text(&progress, "at"),
            text(&progress, "source")
        ),
        format!(
            "checks {} | continuation reports {} | folded wakes {}",
            number(&evaluation, "checks"),
            number(
                &evaluation.get("continuation").cloned().unwrap_or_else(null),
                "reports"
            ),
            number(
                &evaluation.get("pending").cloned().unwrap_or_else(null),
                "folded"
            ),
        ),
        text(doc, "statement"),
    ]);
    lines.push(String::new());
    lines.join("\n").trim_end().to_string()
}

/// One typed state error mapped from a supervision refusal (the daemon
/// renders `code`/`message` unchanged).
impl From<SupervisionError> for StateError {
    fn from(err: SupervisionError) -> StateError {
        StateError {
            code: err.code,
            message: err.message,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{InstanceRow, Retention, State, dispatch_refusal_of};
    use std::path::PathBuf;

    /// Arm one run through the public state API (the same call the queue
    /// submission transaction makes). The helper exists so the tests exercise
    /// the production writer, never a private back door.
    trait ArmForTest {
        fn arm_supervision_for_test(
            &self,
            instance_id: &str,
            desired: &str,
            digest: &str,
            boundary: &str,
            policy: Policy,
            at: &str,
        ) -> Result<crate::state::SupervisionRow, crate::state::StateError>;
    }

    impl ArmForTest for State {
        fn arm_supervision_for_test(
            &self,
            instance_id: &str,
            desired: &str,
            digest: &str,
            boundary: &str,
            policy: Policy,
            at: &str,
        ) -> Result<crate::state::SupervisionRow, crate::state::StateError> {
            self.arm_supervision(
                instance_id,
                &crate::state::SupervisionAuthorizationPlan {
                    desired: desired.to_string(),
                    check_interval_secs: policy.check_interval_secs,
                    progress_timeout_secs: policy.progress_timeout_secs,
                },
                digest,
                boundary,
                1,
                at,
            )
        }
    }

    fn temp_state(name: &str) -> State {
        let base = std::env::temp_dir().join(format!("hf-supervision-{}", std::process::id()));
        std::fs::create_dir_all(&base).expect("temp dir");
        let path: PathBuf = base.join(format!("{name}.db"));
        let _ = std::fs::remove_file(&path);
        State::open(&path, Retention::default()).expect("state open")
    }

    fn run_row(instance_id: &str) -> InstanceRow {
        InstanceRow {
            instance_id: instance_id.to_string(),
            repository: "example-org/widgets".to_string(),
            workflow_id: "issue-cycle".to_string(),
            workflow_hash: "a".repeat(64),
            policy_hash: "b".repeat(64),
            grant_id: "gr_0123456789abcdef".to_string(),
            issue_number: 7,
            issue_revision: "c".repeat(40),
            phase: "read".to_string(),
            scope: "src/**".to_string(),
            caps: "[\"read\"]".to_string(),
            current_node: String::new(),
            normal_rounds: 0,
            recovery_rounds: 0,
            human_queue: false,
            terminal_blockers: 0,
            paused: false,
            resume_digest: String::new(),
            pause_requested: false,
            pause_reason: String::new(),
            pause_requested_at: String::new(),
            state_epoch: 1,
            status: "running".to_string(),
            created_at: "2026-09-13T00:00:00Z".to_string(),
            updated_at: "2026-09-13T00:00:10Z".to_string(),
        }
    }

    fn evidence_for(
        run: InstanceRow,
        submission_digest: Option<&str>,
        steps: &[(&str, &str)],
        attempts: &[(&str, &str, &str)],
        progress_at: &str,
    ) -> SupervisionEvidence {
        SupervisionEvidence {
            run,
            has_dispatch_context: true,
            ownership_instance: Some("run-0123456789abcdef".to_string()),
            submission_digest: submission_digest.map(str::to_string),
            submission_id: Some("qs_0123456789abcdef".to_string()),
            steps: steps
                .iter()
                .map(|(id, kind)| (id.to_string(), kind.to_string()))
                .collect(),
            reviewer_leg_steps: Vec::new(),
            attempts: attempts
                .iter()
                .map(|(step, status, code)| {
                    (step.to_string(), status.to_string(), code.to_string())
                })
                .collect(),
            last_failure: None,
            retries: Vec::new(),
            verdicts: Vec::new(),
            in_flight: None,
            progress_at: progress_at.to_string(),
            item: None,
            newest_evidence: None,
            dispatch_refusal: None,
            fix_round: None,
            fix_leg: None,
            reevaluations: Vec::new(),
            delivery: None,
        }
    }

    /// [`evidence_for`] with ONE recorded continuation-dispatch refusal
    /// (issue #141) — the durable record a refused frontier dispatch leaves
    /// behind instead of an attempt row. The recorded REASON (issue #230) is
    /// exercised by its own witness below.
    fn evidence_with_refusal(
        run: InstanceRow,
        submission_digest: Option<&str>,
        steps: &[(&str, &str)],
        attempts: &[(&str, &str, &str)],
        progress_at: &str,
        refusal: (&str, &str, &str),
    ) -> SupervisionEvidence {
        let mut evidence = evidence_for(run, submission_digest, steps, attempts, progress_at);
        evidence.dispatch_refusal = Some(crate::state::SupervisionDispatchRefusal {
            step: refusal.0.to_string(),
            code: refusal.1.to_string(),
            reason: String::new(),
            at: refusal.2.to_string(),
        });
        evidence
    }

    #[test]
    fn policy_parsing_is_bounded_and_validated() {
        let policy = parse_policy(&object(vec![
            ("check_interval_secs", integer(30)),
            ("progress_timeout_secs", integer(120)),
        ]))
        .expect("valid policy");
        assert_eq!(policy.check_interval_secs, 30);
        assert_eq!(policy.progress_timeout_secs, 120);
        for bad in [
            object(vec![("check_interval_secs", integer(1))]),
            object(vec![("check_interval_secs", integer(99_999))]),
            object(vec![("progress_timeout_secs", integer(1))]),
            object(vec![("progress_timeout_secs", integer(999_999))]),
            object(vec![
                ("check_interval_secs", integer(600)),
                ("progress_timeout_secs", integer(120)),
            ]),
            object(vec![("unknown", integer(1))]),
        ] {
            assert!(parse_policy(&bad).is_err(), "must refuse {bad:?}");
        }
        let authorization = parse_authorization(&authorization_params("armed", Policy::default()))
            .expect("round trip");
        assert_eq!(authorization.desired, "armed");
        assert!(
            parse_authorization(&object(vec![("schema", string(AUTHORIZATION_SCHEMA))])).is_err(),
            "a missing desired state refuses"
        );
        assert!(
            parse_authorization(&object(vec![
                ("schema", string(AUTHORIZATION_SCHEMA)),
                ("desired", string("on")),
            ]))
            .is_err(),
            "an unknown desired state refuses"
        );
    }

    #[test]
    fn classification_pins_the_closed_vocabulary() {
        let policy = Policy {
            check_interval_secs: 10,
            progress_timeout_secs: 60,
        };
        let digest = "d".repeat(64);
        let bound = Some(digest.as_str());
        let steps = [("merge", "merge"), ("check", "hosted_check")];
        let fresh = "2026-09-13T00:00:30Z";
        let fresh_unix = time::unix_from_rfc3339(fresh).expect("instant");
        let classify_at = |mut evidence: SupervisionEvidence, now_unix: i64| {
            evidence.progress_at = fresh.to_string();
            classify(&evidence, &digest, &policy, now_unix)
        };
        // The approved-plan fence wins over everything else.
        let verdict = classify_at(
            evidence_for(
                run_row("run-0123456789abcdef"),
                Some(&"e".repeat(64)),
                &steps,
                &[],
                fresh,
            ),
            fresh_unix,
        );
        assert_eq!(verdict.class, "unknown");
        assert_eq!(verdict.reason, codes::UNAPPROVED_PLAN);
        assert!(!verdict.eligible);
        // A missing submission is never eligible either.
        let verdict = classify_at(
            evidence_for(run_row("run-0123456789abcdef"), None, &steps, &[], fresh),
            fresh_unix,
        );
        assert_eq!(verdict.reason, codes::UNBOUND);
        // A paused run is never eligible and never completed.
        let mut paused = run_row("run-0123456789abcdef");
        paused.pause_requested = true;
        let verdict = classify_at(evidence_for(paused, bound, &steps, &[], fresh), fresh_unix);
        assert_eq!(verdict.class, "paused");
        assert!(!verdict.eligible);
        // A done run without passing evidence is NOT completion.
        let mut done = run_row("run-0123456789abcdef");
        done.status = "done".to_string();
        let verdict = classify_at(evidence_for(done, bound, &steps, &[], fresh), fresh_unix);
        assert_eq!(verdict.class, "unknown");
        assert_eq!(verdict.reason, codes::COMPLETION_UNVERIFIED);
        assert!(!verdict.eligible);
        // A done run WITH passing evidence is completion.
        let mut done = run_row("run-0123456789abcdef");
        done.status = "done".to_string();
        let mut completed = evidence_for(done, bound, &steps, &[], fresh);
        completed.verdicts.push((
            "ev_0123456789abcdef".to_string(),
            "pass".to_string(),
            fresh.to_string(),
        ));
        let verdict = classify_at(completed, fresh_unix);
        assert_eq!(verdict.class, "completed");
        assert!(!verdict.eligible);
        // An in-flight step is healthy even with an old marker.
        let mut in_flight = evidence_for(
            run_row("run-0123456789abcdef"),
            bound,
            &steps,
            &[],
            "2026-09-12T00:00:00Z",
        );
        in_flight.in_flight = Some("checkout".to_string());
        let verdict = classify(&in_flight, &digest, &policy, fresh_unix);
        assert_eq!(verdict.class, "healthy");
        assert_eq!(verdict.reason, codes::IN_FLIGHT);
        // Fully authored autonomous frontiers dispatch; explicit approval
        // remains a known external wait.
        for (kind, class, reason, eligible) in [
            ("hosted_check", "healthy", codes::DISPATCH, true),
            ("prompt", "healthy", codes::DISPATCH, true),
            (
                "approve",
                "waiting-approval",
                codes::WAITING_APPROVAL,
                false,
            ),
        ] {
            let evidence = evidence_for(
                run_row("run-0123456789abcdef"),
                bound,
                &[("step", kind)],
                &[],
                "2026-09-12T00:00:00Z",
            );
            let verdict = classify(&evidence, &digest, &policy, fresh_unix);
            assert_eq!(verdict.class, class, "kind {kind}");
            assert_eq!(verdict.reason, reason);
            assert_eq!(verdict.eligible, eligible);
        }
        // A capacity refusal on the next step blocks capacity.
        let evidence = evidence_for(
            run_row("run-0123456789abcdef"),
            bound,
            &[("checkout", "checkout")],
            &[("checkout", "refused", "refusal.admission.cap_harness")],
            fresh,
        );
        let verdict = classify_at(evidence, fresh_unix);
        assert_eq!(verdict.class, "blocked-capacity");
        assert!(!verdict.eligible);
        // Absence of evidence inside the window is healthy...
        let evidence = evidence_for(run_row("run-0123456789abcdef"), bound, &steps, &[], fresh);
        let verdict = classify_at(evidence, fresh_unix + 30);
        assert_eq!(verdict.class, "healthy");
        assert_eq!(verdict.reason, codes::RECENT_PROGRESS);
        // ...and beyond the window it is exactly one continuation report.
        let evidence = evidence_for(run_row("run-0123456789abcdef"), bound, &steps, &[], fresh);
        let verdict = classify_at(evidence, fresh_unix + 61);
        assert_eq!(verdict.class, "continuation-eligible");
        assert_eq!(verdict.reason, codes::PROGRESS_TIMEOUT);
        assert!(verdict.eligible);
        // A run with NO recorded observation at all is HELD, never eligible
        // (reviewer finding 95-R1): an unobserved run is not a timed-out one,
        // so a fresh arm can never open a continuation window.
        let evidence = evidence_for(run_row("run-0123456789abcdef"), bound, &steps, &[], "");
        let verdict = classify(&evidence, &digest, &policy, fresh_unix);
        assert_eq!(verdict.class, "unknown");
        assert_eq!(verdict.reason, codes::PROGRESS_UNOBSERVED);
        assert!(!verdict.eligible);
        // ...and an unreadable instant is held too: the timeout path requires
        // a recorded observation that is genuinely older than the policy.
        let evidence = evidence_for(
            run_row("run-0123456789abcdef"),
            bound,
            &steps,
            &[],
            "not-a-time",
        );
        let verdict = classify(&evidence, &digest, &policy, fresh_unix + 10_000);
        assert_eq!(verdict.class, "unknown");
        assert_eq!(verdict.reason, codes::PROGRESS_UNOBSERVED);
        assert!(!verdict.eligible);
        // A failure verdict needs attention.
        let mut failed = evidence_for(run_row("run-0123456789abcdef"), bound, &steps, &[], fresh);
        failed.verdicts.push((
            "ev_0123456789abcdef".to_string(),
            "fail".to_string(),
            fresh.to_string(),
        ));
        let verdict = classify_at(failed, fresh_unix);
        assert_eq!(verdict.class, "needs-attention");
        assert_eq!(verdict.reason, codes::REVIEW_FAILED);
    }

    /// Issue #141: the frontier of the MEASURED defect. `p2-137` was repaired
    /// by the operator (its latest attempt succeeded) and the cursor names
    /// `p3`, whose continuation dispatch the apply engine refuses before any
    /// effect — so no attempt row exists for `p3` and the refusal is the only
    /// evidence. Reporting `p3` eligible with `supervision.dispatch.next_step`
    /// while that dispatch is refused is the defect: the refusal is named with
    /// the engine's own code instead, and the step is never eligible.
    #[test]
    fn a_refused_continuation_dispatch_names_the_engines_code_and_is_never_eligible() {
        let policy = Policy {
            check_interval_secs: 10,
            progress_timeout_secs: 60,
        };
        let digest = "d".repeat(64);
        let bound = Some(digest.as_str());
        let steps = [
            ("p1", "checkout"),
            ("p2-137", "worktree_create"),
            ("p3", "harness_start"),
        ];
        let repaired = [
            ("p1", "succeeded", ""),
            ("p2-137", "failed", "adapter.exit"),
            ("p2-137", "succeeded", ""),
        ];
        let repaired_at = "2026-09-15T11:51:12Z";
        let refused_at = "2026-09-15T11:52:12Z";
        let now_unix = time::unix_from_rfc3339(refused_at).expect("instant");
        // Without a recorded refusal the frontier is the plain continuation...
        let evidence = evidence_for(
            run_row("run-604cf9439372a5e5"),
            bound,
            &steps,
            &repaired,
            repaired_at,
        );
        let verdict = classify(&evidence, &digest, &policy, now_unix);
        assert_eq!(verdict.reason, codes::DISPATCH);
        assert!(verdict.eligible, "the untouched frontier is eligible");
        // ...and with the engine's refusal on record it is named, never
        // eligible, and never re-reported as a dispatchable next step.
        let evidence = evidence_with_refusal(
            run_row("run-604cf9439372a5e5"),
            bound,
            &steps,
            &repaired,
            repaired_at,
            ("p3", "refusal.admission.proof_stale", refused_at),
        );
        let verdict = classify(&evidence, &digest, &policy, now_unix);
        assert_eq!(verdict.class, "needs-attention");
        assert_eq!(verdict.reason, codes::DISPATCH_REFUSED);
        assert!(!verdict.eligible);
        assert_eq!(
            verdict.detail, "refusal.admission.proof_stale",
            "the engine's own refusal code is the named blocker"
        );
        // A refusal for a DIFFERENT step never speaks for this frontier.
        let evidence = evidence_with_refusal(
            run_row("run-604cf9439372a5e5"),
            bound,
            &steps,
            &repaired,
            repaired_at,
            ("p1", "refusal.admission.proof_stale", refused_at),
        );
        assert_eq!(
            classify(&evidence, &digest, &policy, now_unix).reason,
            codes::DISPATCH
        );
        // Recorded progress SUPERSEDES the refusal (the operator's repair of
        // the environment or of the frontier): the classification returns to
        // the plain continuation of the new evidence alone.
        let evidence = evidence_with_refusal(
            run_row("run-604cf9439372a5e5"),
            bound,
            &steps,
            &repaired,
            "2026-09-15T12:01:26Z",
            ("p3", "refusal.admission.proof_stale", refused_at),
        );
        let later = time::unix_from_rfc3339("2026-09-15T12:02:26Z").expect("instant");
        let verdict = classify(&evidence, &digest, &policy, later);
        assert_eq!(verdict.reason, codes::DISPATCH);
        assert!(verdict.eligible);
    }

    /// Issue #241: a diagnosed frontier retries within the budget, and an
    /// operator authorization is the act that authorizes exactly that
    /// re-dispatch — the intent is derived for the authorized step, so the
    /// held row is consumed by the dispatch it pays for instead of parking the
    /// frontier. Every recorded non-success status, with or without a
    /// continuation refusal on record. A SPENT bound is the one park that
    /// stays: it escalates typed, never as a silent wait.
    #[test]
    fn a_diagnosed_frontier_retries_with_a_held_authorization() {
        let state = temp_state("diagnosed-fence-refusal");
        let digest = "d".repeat(64);
        let run = "run-0123456789abcdef";
        state
            .arm_supervision_for_test(
                run,
                "armed",
                &digest,
                "merge",
                Policy {
                    check_interval_secs: 10,
                    progress_timeout_secs: 60,
                },
                "2026-09-15T11:00:00Z",
            )
            .expect("arm");
        let row = state.supervision_by_id(run).expect("read").expect("row");
        let steps = [("p1", "checkout"), ("p2", "worktree_create")];
        let attempts = [("p1", "succeeded", ""), ("p2", "failed", "adapter.exit")];
        let at = "2026-09-15T11:51:12Z";
        let policy = Policy {
            check_interval_secs: 10,
            progress_timeout_secs: 60,
        };
        let now_unix = time::unix_from_rfc3339(at).expect("instant");
        for refusal in [None, Some(("p2", "refusal.admission.proof_stale", at))] {
            let mut evidence = match refusal {
                Some(refusal) => evidence_with_refusal(
                    run_row(run),
                    Some(&digest),
                    &steps,
                    &attempts,
                    at,
                    refusal,
                ),
                None => evidence_for(run_row(run), Some(&digest), &steps, &attempts, at),
            };
            for status in ["ambiguous", "refused", "failed"] {
                evidence.attempts.last_mut().unwrap().1 = status.to_string();
                assert!(
                    dispatch_intent(&row, &evidence).is_some(),
                    "{status} is retry eligible"
                );
            }
            evidence.retries.push(crate::state::RunRetryRow {
                retry_id: "rt_0123456789abcdef".into(),
                instance_id: run.into(),
                step_id: "p2".into(),
                attempt: 1,
                authorized_at: at.into(),
                consumed_at: String::new(),
                consumed_key: String::new(),
            });
            let intent = dispatch_intent(&row, &evidence)
                .expect("a held authorization is consumed by its own re-dispatch");
            assert_eq!(intent.step_id, "p2", "the intent is the authorized step");
            assert!(
                !classify(&evidence, &digest, &policy, now_unix).eligible,
                "a diagnosed frontier is never reported eligible"
            );
            // The budget is still the budget: a spent bound parks typed.
            let held = evidence.retries.last_mut().expect("the held row");
            held.consumed_at = at.to_string();
            held.consumed_key = "ik_spent-1".to_string();
            for attempt in 2..=crate::state::RUN_RETRY_MAX {
                evidence.retries.push(crate::state::RunRetryRow {
                    retry_id: format!("rt_0123456789abcde{attempt}"),
                    instance_id: run.into(),
                    step_id: "p2".into(),
                    attempt,
                    authorized_at: at.into(),
                    consumed_at: at.into(),
                    consumed_key: format!("ik_spent-{attempt}"),
                });
            }
            assert!(
                dispatch_intent(&row, &evidence).is_none(),
                "a spent bound is a park"
            );
            let verdict = classify(&evidence, &digest, &policy, now_unix);
            assert_eq!(verdict.class, "needs-attention");
            assert_eq!(verdict.reason, codes::STEP_DIAGNOSED);
            assert!(!verdict.eligible);
        }
    }

    /// Issue #200 (AC2): a review frontier whose recorded diagnosis is
    /// `refusal.evidence.verdict_stale` — the lane checkout moved past the
    /// certified head — is an IMPOSSIBLE step, not a retryable one. The
    /// certificate is a recorded fact and the checkout's movement is
    /// external, so a re-dispatch refuses identically every time: the
    /// frontier parks typed (needs-attention, the recorded code, the code as
    /// the detail) with the bounded retries UNSPENT, instead of burning the
    /// whole budget on it. The same frontier shape with a retryable diagnosis
    /// still takes its bounded retry (#179/#180 unchanged).
    #[test]
    fn a_moved_head_diagnosis_parks_the_frontier_without_burning_a_bounded_retry() {
        let state = temp_state("moved-head-park");
        let digest = "d".repeat(64);
        let run = "run-85a856d6b9e9e7d0";
        let policy = Policy {
            check_interval_secs: 10,
            progress_timeout_secs: 60,
        };
        let at = "2026-09-18T13:04:41Z";
        let now_unix = time::unix_from_rfc3339(at).expect("instant");
        state
            .arm_supervision_for_test(run, "armed", &digest, "merge", policy, at)
            .expect("arm");
        let row = state.supervision_by_id(run).expect("read").expect("row");
        let steps = [("p5", "collect_outcome"), ("p6", "review_evidence")];
        let scene = |code: &str| {
            let mut evidence = evidence_for(
                run_row(run),
                Some(&digest),
                &steps,
                &[("p5", "succeeded", ""), ("p6", "refused", code)],
                at,
            );
            // The frontier is the run's OWN committed review step: admitted
            // member, `review` cap, declared reviewer leg.
            evidence.run.caps = "[\"review\"]".to_string();
            evidence.reviewer_leg_steps = vec!["p6".to_string()];
            evidence.item = Some(crate::state::QueueItemRef {
                submission_id: "qs_0123456789abcdef".to_string(),
                ordinal: 0,
                work_item: "wi_4aabf3ad5bea87b0".to_string(),
                issue_number: 132,
                status: "admitted".to_string(),
            });
            evidence
        };
        let moved = scene(crate::mutation::code::VERDICT_STALE);
        assert!(
            driver_dispatchable_kind(&moved, "p6", "review_evidence"),
            "the fixture frontier is a genuinely dispatchable review step"
        );
        assert!(
            dispatch_intent(&row, &moved).is_none(),
            "an impossible step is never re-dispatched"
        );
        let verdict = classify(&moved, &digest, &policy, now_unix);
        assert_eq!(verdict.class, "needs-attention");
        assert_eq!(verdict.reason, codes::STEP_DIAGNOSED);
        assert_eq!(verdict.detail, crate::mutation::code::VERDICT_STALE);
        assert!(!verdict.eligible, "the parked frontier is never eligible");
        assert!(
            moved.retries.is_empty(),
            "the bounded retries stay unspent on an impossible step"
        );
        let retryable = scene("refusal.worktree.exists");
        assert_eq!(
            dispatch_intent(&row, &retryable).map(|intent| intent.step_id),
            Some("p6".to_string()),
            "a retryable diagnosis of the same frontier still retries"
        );
    }

    /// Issue #202 (AC1): a MERGE frontier whose recorded diagnosis is
    /// `refusal.delivery.moved` — a commit landed on the reviewed delivery
    /// branch after the verdict that names its head — is an IMPOSSIBLE step,
    /// not a retryable one. The verdict is a recorded fact and the delivery's
    /// movement is external, so every re-dispatch refuses identically until
    /// the delivery re-enters review and a new verdict names the moved head:
    /// the frontier parks TYPED (needs-attention, the recorded code as the
    /// detail) with the bounded retries UNSPENT — never a silent park, never
    /// `waiting-approval`, and never a retry into consuming a head no verdict
    /// names. The same frontier shape with a retryable diagnosis still takes
    /// its bounded retry. Issue #263 adds the SAME park for the merge
    /// frontier's own base move (`effect.merge.base_moved`: the published ref
    /// moved past the base the delivery certified and cannot carry the
    /// certified content byte-identically — a recorded fact about the
    /// published ref, not a step defect).
    #[test]
    fn a_moved_delivery_diagnosis_parks_the_merge_frontier_typed_and_unspent() {
        use crate::state::{EvidenceRow, QueueItemRef};
        let state = temp_state("moved-delivery-park");
        let digest = "e".repeat(64);
        let run = "run-f91ece4defffcced";
        let policy = Policy {
            check_interval_secs: 10,
            progress_timeout_secs: 60,
        };
        let at = "2026-09-18T15:40:24Z";
        let now_unix = time::unix_from_rfc3339(at).expect("instant");
        state
            .arm_supervision_for_test(run, "armed", &digest, "merge", policy, at)
            .expect("arm");
        let row = state.supervision_by_id(run).expect("read").expect("row");
        let steps = [
            ("p5", "collect_outcome"),
            ("p6", "review_evidence"),
            ("p7", "merge"),
            ("p8", "cleanup"),
        ];
        let scene = |code: &str| {
            let pins = run_row(run);
            let mut evidence = evidence_for(
                pins.clone(),
                Some(&digest),
                &steps,
                &[
                    ("p5", "succeeded", ""),
                    ("p6", "succeeded", ""),
                    ("p7", "refused", code),
                ],
                at,
            );
            // The frontier is the run's OWN committed tail step of a run whose
            // reviewed delivery is verified: the `merge` cap, an admitted
            // membership item and the newest recorded passing evidence.
            evidence.run.caps = "[\"merge\",\"cleanup\"]".to_string();
            evidence.item = Some(QueueItemRef {
                submission_id: "qs_0123456789abcdef".to_string(),
                ordinal: 0,
                work_item: "wi_4aabf3ad5bea87b0".to_string(),
                issue_number: 132,
                status: "admitted".to_string(),
            });
            evidence.newest_evidence = Some(EvidenceRow {
                evidence_id: "ev_f91ece4defffcced".to_string(),
                instance_id: run.to_string(),
                repository: "example-org/widgets".to_string(),
                feature_head: "1".repeat(40),
                integration_base: "2".repeat(40),
                workflow_hash: pins.workflow_hash.clone(),
                policy_hash: pins.policy_hash.clone(),
                verdict: "pass".to_string(),
                reviewer: "reviewer-1".to_string(),
                checks: "[{\"name\":\"hosted-ci\",\"status\":\"passed\"}]".to_string(),
                created_at: at.to_string(),
            });
            evidence
        };
        let moved = scene(crate::mutation::code::DELIVERY_MOVED);
        assert!(
            driver_dispatchable_kind(&moved, "p7", "merge"),
            "the fixture frontier is a genuinely dispatchable committed tail step"
        );
        assert!(
            dispatch_intent(&row, &moved).is_none(),
            "a delivery that moved past its verdict is never re-dispatched into consumption"
        );
        let verdict = classify(&moved, &digest, &policy, now_unix);
        assert_eq!(verdict.class, "needs-attention");
        assert_eq!(verdict.reason, codes::STEP_DIAGNOSED);
        assert_eq!(verdict.detail, crate::mutation::code::DELIVERY_MOVED);
        assert!(!verdict.eligible, "the parked frontier is never eligible");
        assert!(
            moved.retries.is_empty(),
            "the bounded retries stay unspent on an impossible step"
        );
        // Issue #263: the merge frontier's own base move is the same park —
        // the published ref cannot carry the certified content and the run
        // cannot resolve that by itself.
        let base_moved = scene(crate::mutation::code::MERGE_BASE_MOVED);
        assert!(
            driver_dispatchable_kind(&base_moved, "p7", "merge"),
            "the fixture frontier is a genuinely dispatchable committed tail step"
        );
        assert!(
            dispatch_intent(&row, &base_moved).is_none(),
            "a base move the run cannot resolve is never re-dispatched into the budget"
        );
        let verdict = classify(&base_moved, &digest, &policy, now_unix);
        assert_eq!(verdict.class, "needs-attention");
        assert_eq!(verdict.reason, codes::STEP_DIAGNOSED);
        assert_eq!(verdict.detail, crate::mutation::code::MERGE_BASE_MOVED);
        assert!(!verdict.eligible, "the parked frontier is never eligible");
        assert!(
            base_moved.retries.is_empty(),
            "the bounded retries stay unspent on a base move"
        );
        let retryable = scene("refusal.worktree.exists");
        assert_eq!(
            dispatch_intent(&row, &retryable).map(|intent| intent.step_id),
            Some("p7".to_string()),
            "a retryable diagnosis of the same merge frontier still retries"
        );
    }

    /// Issue #224: a CLEANUP frontier whose recorded attempt is the step's own
    /// bounded wait for a lane that outlived its publish timing out
    /// (`effect.lane_timeout`) is a wait/park, not a retryable failure. The
    /// lane was ALIVE when the whole bound was spent, so a re-dispatch buys
    /// nothing the first attempt did not already spend: the frontier parks
    /// typed (needs-attention, the recorded code as the detail) with the
    /// bounded retries UNSPENT, exactly like the collection's worker timeout
    /// (#200) — never a silent park and never a burn of the retry budget on
    /// the timing. The same frontier shape with a retryable diagnosis still
    /// takes its bounded retry.
    #[test]
    fn a_lane_wait_timeout_parks_the_cleanup_frontier_without_burning_a_bounded_retry() {
        use crate::state::{EvidenceRow, QueueItemRef};
        let state = temp_state("lane-timeout-park");
        let digest = "f".repeat(64);
        let run = "run-22404f5ac1de7b21";
        let policy = Policy {
            check_interval_secs: 10,
            progress_timeout_secs: 60,
        };
        let at = "2026-09-20T03:31:57Z";
        let now_unix = time::unix_from_rfc3339(at).expect("instant");
        state
            .arm_supervision_for_test(run, "armed", &digest, "merge", policy, at)
            .expect("arm");
        let row = state.supervision_by_id(run).expect("read").expect("row");
        let steps = [
            ("p5", "collect_outcome"),
            ("p6", "review_evidence"),
            ("p7", "merge"),
            ("p8", "cleanup"),
        ];
        let scene = |code: &str| {
            let pins = run_row(run);
            let mut evidence = evidence_for(
                pins.clone(),
                Some(&digest),
                &steps,
                &[
                    ("p5", "succeeded", ""),
                    ("p6", "succeeded", ""),
                    ("p7", "succeeded", ""),
                    ("p8", "ambiguous", code),
                ],
                at,
            );
            // The frontier is the run's OWN committed tail step of a run whose
            // reviewed delivery is verified: the `cleanup` cap, an admitted
            // membership item and the newest recorded passing evidence.
            evidence.run.caps = "[\"merge\",\"cleanup\"]".to_string();
            evidence.item = Some(QueueItemRef {
                submission_id: "qs_0123456789abcdef".to_string(),
                ordinal: 0,
                work_item: "wi_4aabf3ad5bea87b0".to_string(),
                issue_number: 224,
                status: "admitted".to_string(),
            });
            evidence.newest_evidence = Some(EvidenceRow {
                evidence_id: "ev_22404f5ac1de7b21".to_string(),
                instance_id: run.to_string(),
                repository: "example-org/widgets".to_string(),
                feature_head: "1".repeat(40),
                integration_base: "2".repeat(40),
                workflow_hash: pins.workflow_hash.clone(),
                policy_hash: pins.policy_hash.clone(),
                verdict: "pass".to_string(),
                reviewer: "reviewer-1".to_string(),
                checks: "[{\"name\":\"hosted-ci\",\"status\":\"passed\"}]".to_string(),
                created_at: at.to_string(),
            });
            evidence
        };
        let waited = scene(crate::mutation::code::LANE_TIMEOUT);
        assert!(
            driver_dispatchable_kind(&waited, "p8", "cleanup"),
            "the fixture frontier is a genuinely dispatchable committed tail step"
        );
        assert!(
            dispatch_intent(&row, &waited).is_none(),
            "the lane wait's own bound is never re-dispatched into a retry"
        );
        let verdict = classify(&waited, &digest, &policy, now_unix);
        assert_eq!(verdict.class, "needs-attention");
        assert_eq!(verdict.reason, codes::STEP_DIAGNOSED);
        assert_eq!(verdict.detail, crate::mutation::code::LANE_TIMEOUT);
        assert!(!verdict.eligible, "the parked frontier is never eligible");
        assert!(
            waited.retries.is_empty(),
            "the bounded retries stay unspent on the lane wait's own timeout"
        );
        // The collection's worker timeout is the same park at its own kind.
        let collecting = scene(crate::mutation::code::WORKER_TIMEOUT);
        assert!(
            dispatch_intent(&row, &collecting).is_none(),
            "a worker timeout is a wait/park at every kind"
        );
        let retryable = scene("refusal.worktree.exists");
        assert_eq!(
            dispatch_intent(&row, &retryable).map(|intent| intent.step_id),
            Some("p8".to_string()),
            "a retryable diagnosis of the same cleanup frontier still retries"
        );
    }

    /// Issue #148 item 4: the classification half of the MEASURED #147 defect.
    /// The supervisor dispatched p1..p4-147 itself and p3 created the real
    /// Herdr pane; p4-147 (the prompt) was then recorded as a non-succeeded
    /// attempt (`adapter.exit`, nothing delivered) — and the run was reported
    /// `waiting-workers`, exactly as if a busy worker would eventually deliver
    /// it. Nothing was running: the step's own failure code remains visible
    /// while the driver backs off or the bounded retry budget is exhausted.
    #[test]
    fn a_diagnosed_prompt_frontier_is_never_reported_as_waiting_for_workers() {
        let policy = Policy {
            check_interval_secs: 10,
            progress_timeout_secs: 60,
        };
        let digest = "d".repeat(64);
        let bound = Some(digest.as_str());
        let steps = [
            ("p1", "checkout"),
            ("p2-147", "worktree_create"),
            ("p3", "harness_start"),
            ("p4-147", "prompt"),
        ];
        let dispatched = [
            ("p1", "succeeded", ""),
            ("p2-147", "succeeded", ""),
            ("p3", "succeeded", ""),
        ];
        let diagnosed = [
            ("p1", "succeeded", ""),
            ("p2-147", "succeeded", ""),
            ("p3", "succeeded", ""),
            ("p4-147", "refused", "refusal.prompt.undelivered"),
        ];
        let at = "2026-09-15T18:10:38Z";
        let now_unix = time::unix_from_rfc3339(at).expect("instant");
        // The frontier step whose never-attempted continuation the driver owns
        // is still dispatched (the class vocabulary is unchanged)...
        let evidence = evidence_for(
            run_row("run-89284da1da70a294"),
            bound,
            &steps,
            &dispatched,
            at,
        );
        let verdict = classify(&evidence, &digest, &policy, now_unix);
        assert_eq!(verdict.reason, codes::DISPATCH);
        assert!(verdict.eligible, "the untouched frontier is eligible");
        // ...and the SAME frontier with its own recorded non-success is
        // diagnosed, never a wait for workers that are not running.
        let evidence = evidence_for(
            run_row("run-89284da1da70a294"),
            bound,
            &steps,
            &diagnosed,
            at,
        );
        let verdict = classify(&evidence, &digest, &policy, now_unix);
        assert_eq!(
            verdict.class, "needs-attention",
            "an undelivered prompt is not a wait: {verdict:?}"
        );
        assert_ne!(verdict.class, "waiting-workers");
        assert_eq!(verdict.reason, codes::STEP_DIAGNOSED);
        assert_eq!(
            verdict.detail, "refusal.prompt.undelivered",
            "the step's own recorded failure code is the named blocker"
        );
        assert!(!verdict.eligible, "a diagnosed step is never eligible");
        // The same rule holds for the bare `adapter.exit` the #147 run
        // actually recorded: the class names the diagnosis either way.
        let bare = [
            ("p1", "succeeded", ""),
            ("p2-147", "succeeded", ""),
            ("p3", "succeeded", ""),
            ("p4-147", "failed", "adapter.exit"),
        ];
        let evidence = evidence_for(run_row("run-89284da1da70a294"), bound, &steps, &bare, at);
        let verdict = classify(&evidence, &digest, &policy, now_unix);
        assert_eq!(verdict.class, "needs-attention");
        assert_eq!(verdict.reason, codes::STEP_DIAGNOSED);
        assert_eq!(verdict.detail, "adapter.exit");
    }

    /// Issue #141: the refusal record is durable and auditable, and only the
    /// target's own run may read it back. A foreign or malformed target is
    /// never read as this run's refusal (the read invents nothing).
    #[test]
    fn a_recorded_dispatch_refusal_is_journaled_and_read_back_by_its_own_run() {
        let state = temp_state("refusal-record");
        let run = "run-0123456789abcdef";
        state
            .record_supervision_dispatch_refusal(
                run,
                "p3",
                "refusal.admission.proof_stale",
                "the recorded admission proof is older than the live window",
            )
            .expect("record");
        let (_, lines) = state.journal_tail(0, 1_000).expect("journal");
        // The reader takes the target from the audit row itself (never a
        // reconstruction): the code AND the engine's reason ride it (issue #230).
        let target = lines
            .iter()
            .find(|line| line.contains(codes::DISPATCH_REFUSED) && line.contains(run))
            .and_then(|line| Val::parse_json(line).ok())
            .and_then(|doc| doc.get("target").and_then(Val::as_str).map(str::to_string))
            .expect("the recorded target");
        assert!(
            lines
                .iter()
                .any(|line| line.contains(codes::DISPATCH_REFUSED) && line.contains(&target)),
            "the refusal is a journal record of this run: {lines:?}"
        );
        let read = dispatch_refusal_of(run, &target, "2026-09-15T11:52:12Z").expect("read back");
        assert_eq!(read.step, "p3");
        assert_eq!(read.code, "refusal.admission.proof_stale");
        assert_eq!(
            read.reason, "the recorded admission proof is older than the live window",
            "the engine's own reason rides the durable record (issue #230)"
        );
        assert_eq!(read.at, "2026-09-15T11:52:12Z");
        for (instance, foreign) in [
            ("run-ffffffffffffffff", target.as_str()),
            (run, "run-0123456789abcdef"),
            (run, "run-0123456789abcdef:p3"),
            (run, "run-0123456789abcdef::refusal.admission.proof_stale"),
        ] {
            assert!(
                dispatch_refusal_of(instance, foreign, "2026-09-15T11:52:12Z").is_none(),
                "not this run's refusal: {foreign:?}"
            );
        }
    }

    /// NB-2 (fix round F1): the recorded refusal target carries the engine's
    /// own message LAST, after a `:reason:` marker, and is read back with
    /// `split_once(":reason:")`. A message that ITSELF contains the marker
    /// therefore round-trips EXACTLY — the FIRST marker is the delimiter and
    /// everything after it is the reason by construction — so the field can
    /// keep carrying raw engine text (git/gh stderr included). This pin fails
    /// if the reason is ever moved off the END of the target, or if the reader
    /// starts splitting on the LAST marker.
    #[test]
    fn a_recorded_refusal_reason_containing_the_marker_round_trips() {
        let state = temp_state("refusal-reason-roundtrip");
        let run = "run-0123456789abcdef";
        let reason = "gh run view failed: reason: the check:reason:run is gone; re-measure";
        state
            .record_supervision_dispatch_refusal(run, "p7", "refusal.evidence.failed", reason)
            .expect("record");
        let (_, lines) = state.journal_tail(0, 1_000).expect("journal");
        let target = lines
            .iter()
            .find(|line| line.contains(codes::DISPATCH_REFUSED) && line.contains(run))
            .and_then(|line| Val::parse_json(line).ok())
            .and_then(|doc| doc.get("target").and_then(Val::as_str).map(str::to_string))
            .expect("the recorded target");
        assert!(
            target.ends_with(reason),
            "the reason is recorded LAST: {target}"
        );
        let read = dispatch_refusal_of(run, &target, "2026-09-15T11:52:12Z").expect("read back");
        assert_eq!(read.step, "p7");
        assert_eq!(read.code, "refusal.evidence.failed");
        assert_eq!(
            read.reason, reason,
            "a reason that contains the marker round-trips exactly"
        );
    }

    /// Issue #230: a continuation the ENGINE refused is reported with the
    /// engine's own code AND its reason. The classification already refuses to
    /// report such a frontier eligible; this witness pins that the STATUS an
    /// operator reads also carries the engine's own words, which is what makes
    /// the refusal actionable.
    #[test]
    fn a_refused_continuation_reports_the_engine_code_and_reason() {
        let run = "run-0123456789abcdef";
        let digest = "d".repeat(64);
        let at = "2026-09-15T11:52:12Z";
        let policy = Policy {
            check_interval_secs: 10,
            progress_timeout_secs: 60,
        };
        let now_unix = time::unix_from_rfc3339("2026-09-15T11:53:12Z").expect("instant");
        let reason = "review evidence ev_f791aff0247293eb has failed/pending checks: \
                      local_cargo_test_aggregate=failed";
        let mut evidence = evidence_for(
            run_row(run),
            Some(&digest),
            &[("p1", "review_evidence"), ("p2", "merge")],
            &[],
            at,
        );
        evidence.dispatch_refusal = Some(crate::state::SupervisionDispatchRefusal {
            step: "p1".to_string(),
            code: "refusal.evidence.failed".to_string(),
            reason: reason.to_string(),
            at: at.to_string(),
        });
        let verdict = classify(&evidence, &digest, &policy, now_unix);
        assert_eq!(verdict.class, "needs-attention");
        assert_eq!(verdict.reason, codes::DISPATCH_REFUSED);
        assert!(
            !verdict.eligible,
            "a refused continuation is never eligible"
        );
        assert_eq!(verdict.detail, "refusal.evidence.failed");
        let row = supervision_row_for(run, at);
        let doc = status_doc(&row, &evidence, None, &verdict, now_unix);
        let refusal = doc
            .get("evaluation")
            .and_then(|evaluation| evaluation.get("refusal"))
            .cloned()
            .unwrap_or_else(null);
        assert_eq!(
            refusal.get("code").and_then(Val::as_str),
            Some("refusal.evidence.failed"),
            "the status names the engine's own code"
        );
        assert_eq!(
            refusal.get("reason").and_then(Val::as_str),
            Some(reason),
            "the status names the engine's own reason"
        );
        let human = render_human(&doc);
        assert!(
            human.contains(
                "refused continuation p1 (refusal.evidence.failed): review evidence \
                 ev_f791aff0247293eb has failed/pending checks"
            ),
            "the human read names the code and the reason: {human}"
        );
        // A superseded refusal (progress moved past it) is never presented as
        // current, and the status carries no refusal block for it.
        let mut superseded = evidence.clone();
        superseded.progress_at = "2026-09-15T11:59:00Z".to_string();
        let verdict = classify(&superseded, &digest, &policy, now_unix);
        assert_ne!(verdict.reason, codes::DISPATCH_REFUSED);
        let doc = status_doc(&row, &superseded, None, &verdict, now_unix);
        assert!(
            doc.get("evaluation")
                .and_then(|evaluation| evaluation.get("refusal"))
                .is_some_and(Val::is_null),
            "a superseded refusal is not presented as current"
        );
    }

    /// Issue #230, the deadlock half. The run's frontier is its OWN
    /// verified-delivery consumer (a committed `merge` tail step) and the
    /// driver may not dispatch it because the newest recorded review evidence
    /// carries a non-passing check. NOTHING is attempted in that shape — the
    /// evidence gate refuses the tail before any dispatch exists — so no
    /// dispatch refusal is ever recorded, and before this the run fell through
    /// to the progress-timeout branch and was reported `continuation-eligible`
    /// while nothing could ever land. The read names the engine's own refusal
    /// instead, with the code and the reason DERIVED from the same recorded
    /// facts the gate reads.
    #[test]
    fn an_unverified_delivery_tail_is_named_and_never_reported_eligible() {
        let policy = Policy {
            check_interval_secs: 10,
            progress_timeout_secs: 60,
        };
        let digest = "d".repeat(64);
        let at = "2026-09-15T11:52:12Z";
        let now_unix = time::unix_from_rfc3339("2026-09-15T11:53:12Z").expect("instant");
        let steps = [
            ("p1", "checkout"),
            ("p2", "prompt"),
            ("p6", "review_evidence"),
            ("p7", "merge"),
        ];
        let evidence_id = "ev_f791aff0247293eb";
        let passed = r#"[{"name":"hosted_ci_at_exact_head","status":"passed"}]"#;
        let one_failed = r#"[{"name":"hosted_ci_at_exact_head","status":"passed"},{"name":"local_full_suite_raw_101","status":"failed"}]"#;
        // The recorded shape of the measured deadlock: every step up to the
        // review SUCCEEDED (so the frontier IS the tail), and the newest
        // evidence is a `pass` bound to the run's own pins at one exact head.
        let deliver = |checks: &str, caps: &str| -> SupervisionEvidence {
            let mut run = run_row("run-0123456789abcdef");
            run.caps = caps.to_string();
            let mut evidence = evidence_for(
                run,
                Some(&digest),
                &steps,
                &[
                    ("p1", "succeeded", ""),
                    ("p2", "succeeded", ""),
                    ("p6", "succeeded", ""),
                ],
                at,
            );
            evidence.item = Some(crate::state::QueueItemRef {
                submission_id: "qs_0123456789abcdef".to_string(),
                ordinal: 1,
                work_item: "#7".to_string(),
                issue_number: 7,
                status: "admitted".to_string(),
            });
            evidence.newest_evidence = Some(crate::state::EvidenceRow {
                evidence_id: evidence_id.to_string(),
                instance_id: "run-0123456789abcdef".to_string(),
                repository: "example-org/widgets".to_string(),
                feature_head: "e".repeat(40),
                integration_base: "b".repeat(40),
                workflow_hash: "a".repeat(64),
                policy_hash: "b".repeat(64),
                verdict: "pass".to_string(),
                reviewer: "lane-reviewer".to_string(),
                checks: checks.to_string(),
                created_at: at.to_string(),
            });
            evidence
        };
        let row = supervision_row_for("run-0123456789abcdef", at);

        // (1) The non-passing check: the refusal is NAMED, never eligible.
        let unverified = deliver(one_failed, "[\"read\",\"merge\"]");
        let verdict = classify(&unverified, &digest, &policy, now_unix);
        assert_eq!(verdict.class, "needs-attention");
        assert_eq!(verdict.reason, codes::DELIVERY_UNVERIFIED);
        assert_eq!(verdict.detail, crate::mutation::code::EVIDENCE_FAILED);
        assert!(
            !verdict.eligible,
            "a tail whose delivery is unverified is never an eligible continuation"
        );
        let doc = status_doc(&row, &unverified, None, &verdict, now_unix);
        let refusal = doc
            .get("evaluation")
            .and_then(|evaluation| evaluation.get("refusal"))
            .cloned()
            .unwrap_or_else(null);
        assert_eq!(
            refusal.get("step").and_then(Val::as_str),
            Some("p7"),
            "the refusal names the frontier it is about"
        );
        assert_eq!(
            refusal.get("code").and_then(Val::as_str),
            Some(crate::mutation::code::EVIDENCE_FAILED),
            "the status names the engine's own code"
        );
        assert_eq!(
            refusal.get("reason").and_then(Val::as_str),
            Some(
                "review evidence ev_f791aff0247293eb has failed/pending checks: \
                 local_full_suite_raw_101=failed"
            ),
            "the status names the engine's own reason"
        );
        let human = render_human(&doc);
        assert!(
            human.contains(
                "refused continuation p7 (refusal.evidence.failed): review evidence \
                 ev_f791aff0247293eb has failed/pending checks: local_full_suite_raw_101=failed"
            ),
            "the human read names the code and the reason: {human}"
        );

        // (2) The positive control: the SAME recorded shape with every check
        //     `passed` IS a verified delivery, so the tail is dispatchable and
        //     the run is reported an eligible continuation. The derivation is
        //     keyed on the checks and on nothing else.
        let verified = deliver(passed, "[\"read\",\"merge\"]");
        let verdict = classify(&verified, &digest, &policy, now_unix);
        assert_eq!(verdict.class, "healthy");
        assert_eq!(verdict.reason, codes::DISPATCH);
        assert!(verdict.eligible, "a verified delivery IS dispatchable");
        let doc = status_doc(&row, &verified, None, &verdict, now_unix);
        assert!(
            doc.get("evaluation")
                .and_then(|evaluation| evaluation.get("refusal"))
                .is_some_and(Val::is_null),
            "an eligible frontier carries no refusal block"
        );

        // (2b) ...and the driver's OWN intent for the tail exists exactly then:
        //      the piece the deadlock was missing. With the recomputed passing
        //      record the driver dispatches the publish step; with the
        //      non-passing one it produces NO intent at all — which is why the
        //      status has to name the refusal, instead of calling the frontier
        //      an eligible continuation that never lands.
        let intent = dispatch_intent(&row, &verified).expect("the verified tail is dispatched");
        assert_eq!(intent.step_id, "p7");
        assert_eq!(intent.kind, "merge");
        assert!(
            dispatch_intent(&row, &unverified).is_none(),
            "an unverified delivery is never driven"
        );

        // (3) The derivation is the GATE's own: a run whose committed caps do
        //     not authorize the tail kind (or whose frontier is not the tail at
        //     all) is never given this refusal — the same non-passing check
        //     would refuse a `merge` the run was never granted.
        let uncapped = deliver(one_failed, "[\"read\"]");
        let verdict = classify(&uncapped, &digest, &policy, now_unix);
        assert_ne!(verdict.reason, codes::DELIVERY_UNVERIFIED);

        // (4) AC2 in read-time form: a recomputation that comes back FAILING
        //     derives the IDENTICAL refusal — nothing was upgraded or waived.
        let recomputed = deliver(
            r#"[{"name":"local_full_suite_raw_101","status":"failed"}]"#,
            "[\"read\",\"merge\"]",
        );
        let verdict = classify(&recomputed, &digest, &policy, now_unix);
        assert_eq!(verdict.reason, codes::DELIVERY_UNVERIFIED);
        assert_eq!(verdict.detail, crate::mutation::code::EVIDENCE_FAILED);
        assert!(!verdict.eligible);

        // (5) NB-1 (fix round F1): the derivation must not outrank a durable
        //     hold or an in-flight step — the SAME fact `verified_delivery`
        //     applies, from ONE shared derivation. The pin is DIRECT on the
        //     derivation because at the `classify` level the earlier arms make
        //     this shape unreachable, which is exactly the positional
        //     invariant the finding removes.
        let mut held = deliver(one_failed, "[\"read\",\"merge\"]");
        assert!(
            unverified_delivery_refusal(&held, "p7", "merge").is_some(),
            "the control: the shape DOES derive before a hold is applied"
        );
        held.run.paused = true;
        assert!(
            unverified_delivery_refusal(&held, "p7", "merge").is_none(),
            "a paused run is not a delivery"
        );
        held.run.paused = false;
        held.run.pause_requested = true;
        assert!(
            unverified_delivery_refusal(&held, "p7", "merge").is_none(),
            "a pause-requested run is not a delivery"
        );
        held.run.pause_requested = false;
        held.run.human_queue = true;
        assert!(
            unverified_delivery_refusal(&held, "p7", "merge").is_none(),
            "a human-queued run is not a delivery"
        );
        held.run.human_queue = false;
        held.run.terminal_blockers = 1;
        assert!(
            unverified_delivery_refusal(&held, "p7", "merge").is_none(),
            "a terminally blocked run is not a delivery"
        );
        held.run.terminal_blockers = 0;
        held.run.status = "blocked".to_string();
        assert!(
            unverified_delivery_refusal(&held, "p7", "merge").is_none(),
            "a blocked run is not a delivery"
        );
        held.run.status = "invalidated".to_string();
        assert!(
            unverified_delivery_refusal(&held, "p7", "merge").is_none(),
            "an invalidated run is not a delivery"
        );
        held.run.status = "running".to_string();
        held.in_flight = Some("p7".to_string());
        assert!(
            unverified_delivery_refusal(&held, "p7", "merge").is_none(),
            "a run mid-effect is not a delivery"
        );
        held.in_flight = None;
        assert!(
            unverified_delivery_refusal(&held, "p7", "merge").is_some(),
            "and the hold is the ONLY reason each leg above returned None"
        );
    }

    /// B2 (fix round F1): a tail frontier that HAS already been attempted, and
    /// whose own attempt recorded a concrete diagnosis, is reported with the
    /// attempt's OWN code (issue #148) — never with the derived evidence
    /// refusal, which exists only for the shape NOTHING ever dispatched. The
    /// new arm must carry the same `latest_attempt_for(...).is_none()` guard
    /// its #141 sibling carries; without it a diagnosed tail states the wrong
    /// why and outranks the recorded diagnosis.
    #[test]
    fn a_diagnosed_tail_keeps_its_own_recorded_code_over_the_derived_refusal() {
        let policy = Policy {
            check_interval_secs: 10,
            progress_timeout_secs: 60,
        };
        let digest = "d".repeat(64);
        let at = "2026-09-15T11:52:12Z";
        let now_unix = time::unix_from_rfc3339("2026-09-15T11:53:12Z").expect("instant");
        let steps = [
            ("p1", "checkout"),
            ("p2", "prompt"),
            ("p6", "review_evidence"),
            ("p7", "merge"),
        ];
        let mut run = run_row("run-0123456789abcdef");
        run.caps = "[\"read\",\"merge\"]".to_string();
        // Every step up to the review succeeded and the TAIL was attempted and
        // diagnosed with its own code — the exact shape issue #148 owns.
        let mut evidence = evidence_for(
            run,
            Some(&digest),
            &steps,
            &[
                ("p1", "succeeded", ""),
                ("p2", "succeeded", ""),
                ("p6", "succeeded", ""),
                ("p7", "failed", "adapter.exit"),
            ],
            at,
        );
        evidence.item = Some(crate::state::QueueItemRef {
            submission_id: "qs_0123456789abcdef".to_string(),
            ordinal: 1,
            work_item: "#7".to_string(),
            issue_number: 7,
            status: "admitted".to_string(),
        });
        evidence.newest_evidence = Some(crate::state::EvidenceRow {
            evidence_id: "ev_f791aff0247293eb".to_string(),
            instance_id: "run-0123456789abcdef".to_string(),
            repository: "example-org/widgets".to_string(),
            feature_head: "e".repeat(40),
            integration_base: "b".repeat(40),
            workflow_hash: "a".repeat(64),
            policy_hash: "b".repeat(64),
            verdict: "pass".to_string(),
            reviewer: "lane-reviewer".to_string(),
            checks: r#"[{"name":"local_full_suite_raw_101","status":"failed"}]"#.to_string(),
            created_at: at.to_string(),
        });
        // The derivation DOES hold for this shape (the newest record carries a
        // non-passing check): the guard is what must keep it from outranking
        // the recorded diagnosis, so this is not a vacuous leg.
        assert!(
            unverified_delivery_refusal(&evidence, "p7", "merge").is_some(),
            "the evidence refusal also applies here — only the guard separates them"
        );
        let verdict = classify(&evidence, &digest, &policy, now_unix);
        assert_eq!(
            verdict.reason,
            codes::STEP_DIAGNOSED,
            "a tail that already ran and diagnosed keeps its own class"
        );
        assert_eq!(
            verdict.detail, "adapter.exit",
            "the attempt's OWN code is the named blocker (issue #148)"
        );
        assert_eq!(verdict.class, "needs-attention");
        assert!(!verdict.eligible, "a diagnosed tail is never eligible");
    }

    /// The durable supervision row of one run, as the status read builds it.
    fn supervision_row_for(run: &str, at: &str) -> crate::state::SupervisionRow {
        crate::state::SupervisionRow {
            instance_id: run.to_string(),
            supervision_id: "sv_0123456789abcdef".to_string(),
            desired: "armed".to_string(),
            owner_generation: 1,
            run_generation: 1,
            authorization_digest: "d".repeat(64),
            approved_boundary: "review".to_string(),
            check_interval_secs: 10,
            progress_timeout_secs: 60,
            progress_marker: "m".repeat(64),
            progress_at: at.to_string(),
            progress_source: "attempt".to_string(),
            checks: 0,
            continuation_reports: 0,
            continuation_open: false,
            continuation_since: String::new(),
            last_check_at: at.to_string(),
            last_check_class: "healthy".to_string(),
            last_check_reason: codes::DISPATCH.to_string(),
            last_check_trigger: "timer".to_string(),
            next_check_at: at.to_string(),
            next_check_unix: 0,
            next_check_reason: codes::DISPATCH.to_string(),
            armed_at: at.to_string(),
            updated_at: at.to_string(),
        }
    }

    /// The recorded review FAIL of one run at `head` (issue #238): the newest
    /// verdict is a failure and its evidence row names the certified head.
    fn evidence_with_failed_review(
        run: InstanceRow,
        steps: &[(&str, &str)],
        head: &str,
    ) -> SupervisionEvidence {
        let digest = "d".repeat(64);
        let mut evidence = evidence_for(
            run,
            Some(&digest),
            steps,
            &[("p6", "succeeded", "")],
            "2026-09-13T00:00:30Z",
        );
        evidence.verdicts = vec![(
            "ev_0123456789abcdef".to_string(),
            "fail".to_string(),
            "2026-09-13T00:00:20Z".to_string(),
        )];
        evidence.newest_evidence = Some(crate::state::EvidenceRow {
            evidence_id: "ev_0123456789abcdef".to_string(),
            instance_id: "run-0123456789abcdef".to_string(),
            repository: "example-org/widgets".to_string(),
            feature_head: head.to_string(),
            integration_base: "b".repeat(40),
            workflow_hash: "a".repeat(64),
            policy_hash: "c".repeat(64),
            verdict: "fail".to_string(),
            reviewer: "lane-reviewer".to_string(),
            checks: r#"[{"name":"AC1-cursor","status":"failed"}]"#.to_string(),
            created_at: "2026-09-13T00:00:20Z".to_string(),
        });
        evidence
    }

    #[test]
    fn a_recorded_review_fail_reports_its_fix_round_handoff_never_a_silent_park() {
        let policy = Policy::default();
        let digest = "d".repeat(64);
        let steps = [
            ("p1", "checkout"),
            ("p2", "prompt"),
            ("p6", "review_evidence"),
        ];
        let head = "e".repeat(40);
        let now_unix = time::unix_from_rfc3339("2026-09-13T00:00:30Z").expect("instant");
        let classify_at =
            |evidence: SupervisionEvidence| classify(&evidence, &digest, &policy, now_unix);

        // (1) The FAIL was handed to the run's own fix round for THIS head:
        //     the run is waiting on that repair leg, and the detail names it.
        let mut dispatched =
            evidence_with_failed_review(run_row("run-0123456789abcdef"), &steps, &head);
        dispatched.fix_round = Some(crate::state::SupervisionFixRound {
            step: "p6".to_string(),
            feature_head: head.clone(),
            round: 1,
            bound: 3,
            lane: "lane-0123456789abcdef".to_string(),
            worktree: "issues-5-impl2".to_string(),
        });
        let verdict = classify_at(dispatched.clone());
        assert_eq!(verdict.class, "waiting-workers");
        assert_eq!(verdict.reason, codes::FIX_DISPATCHED);
        assert_eq!(verdict.detail, "lane-0123456789abcdef");
        assert_eq!(dispatched.fix_round.as_ref().expect("recorded").bound, 3);
        assert!(
            !verdict.eligible,
            "a dispatched fix round is work in flight, never completion"
        );

        // (2) The recorded round belongs to ANOTHER head (the repair leg
        //     advanced the branch past the head this FAIL was handed at): it is
        //     not this FAIL's handoff — and the disposition still is the fix
        //     round's own, naming the remedy (the recorded lane) and both head
        //     prefixes. Never a bare `supervision.review_failed` (issue #254).
        let mut stale = dispatched;
        stale.fix_round.as_mut().expect("recorded").feature_head = "f".repeat(40);
        let verdict = classify_at(stale);
        assert_eq!(verdict.class, "needs-attention");
        assert_eq!(verdict.reason, codes::FIX_HEAD_MOVED);
        assert_ne!(
            verdict.reason,
            codes::REVIEW_FAILED,
            "a visible fix round is never reported as a bare review failure"
        );
        assert_eq!(
            verdict.detail,
            format!(
                "lane-0123456789abcdef (handoff recorded at {}, newest evidence at {})",
                "f".repeat(12),
                head.chars().take(12).collect::<String>()
            ),
            "the remedy (the recorded lane) and the moved head are both named"
        );
        assert!(!verdict.eligible);
        let human = render_human(&object(vec![(
            "evaluation",
            object(vec![
                ("reason", string(codes::FIX_HEAD_MOVED)),
                ("detail", string(&verdict.detail)),
            ]),
        )]));
        assert!(
            human.contains(
                "fix round recorded for another head (lane lane-0123456789abcdef \
                 (handoff recorded at"
            ),
            "the human read names the lane and the movement: {human}"
        );

        // (2b) The repair leg's OWN checkout has DELIVERED a descendant head
        //      (issue #256): the disposition is derived from the LEG's own
        //      recorded state, never from the head the FAIL was handed at — so
        //      a leg that already advanced the branch is reported as moved (not
        //      as a worker still in flight), naming the recorded lane and both
        //      head prefixes.
        let mut delivered =
            evidence_with_failed_review(run_row("run-0123456789abcdef"), &steps, &head);
        delivered.fix_round = Some(crate::state::SupervisionFixRound {
            step: "p6".to_string(),
            feature_head: head.clone(),
            round: 1,
            bound: 3,
            lane: "lane-0123456789abcdef".to_string(),
            worktree: "issues-5-impl2".to_string(),
        });
        let delivered_head = "a".repeat(40);
        delivered.fix_leg = Some(crate::state::FixLegState {
            head: delivered_head.clone(),
            delivered: true,
        });
        let verdict = classify_at(delivered.clone());
        assert_eq!(verdict.class, "needs-attention");
        assert_eq!(
            verdict.reason,
            codes::FIX_HEAD_MOVED,
            "a delivered leg is never reported as work in flight"
        );
        assert_eq!(
            verdict.detail,
            format!(
                "lane-0123456789abcdef (reviewed at {}, delivered at {})",
                head.chars().take(12).collect::<String>(),
                delivered_head.chars().take(12).collect::<String>()
            ),
            "the remedy (the recorded lane) and both heads are named"
        );
        assert!(!verdict.eligible);

        // (2c) The leg's own checkout has NOT advanced: the wait keeps its
        //      current meaning (issue #256 AC3) — the in-flight disposition is
        //      only for a leg that has not delivered a head.
        let mut swimming = delivered;
        swimming.fix_leg = Some(crate::state::FixLegState {
            head: head.clone(),
            delivered: false,
        });
        let verdict = classify_at(swimming);
        assert_eq!(verdict.class, "waiting-workers");
        assert_eq!(verdict.reason, codes::FIX_DISPATCHED);
        assert_eq!(verdict.detail, "lane-0123456789abcdef");

        // (3) The handoff was REFUSED: the fix round's OWN engine code is the
        //     detail, so the missing piece is actionable — never a bare park.
        let mut refused =
            evidence_with_failed_review(run_row("run-0123456789abcdef"), &steps, &head);
        refused.last_failure = Some(crate::state::StepFailure {
            step: "p6".to_string(),
            status: "failed".to_string(),
            code: crate::mutation::code::FIX_PROMPT.to_string(),
            message: "the fix round's instruction was not delivered".to_string(),
        });
        let verdict = classify_at(refused.clone());
        assert_eq!(verdict.class, "needs-attention");
        assert_eq!(verdict.reason, codes::FIX_REFUSED);
        assert_eq!(verdict.detail, crate::mutation::code::FIX_PROMPT);
        assert!(!verdict.eligible);

        // (4) The automatic bound is spent: the escalation keeps its own code.
        refused
            .last_failure
            .as_mut()
            .expect("recorded failure")
            .code = crate::mutation::code::FIX_BOUND_EXHAUSTED.to_string();
        let verdict = classify_at(refused);
        assert_eq!(verdict.reason, codes::FIX_EXHAUSTED);
        assert_eq!(verdict.detail, crate::mutation::code::FIX_BOUND_EXHAUSTED);

        // (5) The human read says WHY the run is ineligible instead of
        //     reporting a bare `eligible false`: the fix round's own code,
        //     and the lane the dispatched handoff reached.
        let human = render_human(&object(vec![
            (
                "run",
                object(vec![
                    ("instance_id", string("run-0123456789abcdef")),
                    ("status", string("running")),
                ]),
            ),
            (
                "supervision",
                object(vec![
                    ("id", string("sv_0123456789abcdef")),
                    ("desired", string("armed")),
                ]),
            ),
            (
                "evaluation",
                object(vec![
                    ("class", string("needs-attention")),
                    ("reason", string(codes::FIX_REFUSED)),
                    ("eligible", bool_(false)),
                    ("detail", string(crate::mutation::code::FIX_PROMPT)),
                ]),
            ),
        ]));
        assert!(
            human.contains("fix round refused: refusal.fix.prompt"),
            "{human}"
        );
        let dispatched_human = render_human(&object(vec![
            (
                "run",
                object(vec![
                    ("instance_id", string("run-0123456789abcdef")),
                    ("status", string("running")),
                ]),
            ),
            (
                "supervision",
                object(vec![
                    ("id", string("sv_0123456789abcdef")),
                    ("desired", string("armed")),
                ]),
            ),
            (
                "evaluation",
                object(vec![
                    ("class", string("waiting-workers")),
                    ("reason", string(codes::FIX_DISPATCHED)),
                    ("eligible", bool_(false)),
                    ("detail", string("lane-0123456789abcdef")),
                ]),
            ),
        ]));
        assert!(
            dispatched_human.contains("fix round dispatched to lane lane-0123456789abcdef"),
            "{dispatched_human}"
        );
    }

    /// Issue #272: the run's own fix round delivered a MOVED head its own
    /// collection never observed. The driver's ONE continuation is a bounded
    /// re-collect of the repair leg's own lane checkout through the run's OWN
    /// collector step — and the consumption fences end exactly where the
    /// documented remedy lands.
    ///
    /// Three facts share one fixture: while the delivered head is unobserved
    /// the review is never re-dispatched (the #202 AC2 fence stands, exactly
    /// as `refusal.delivery.unbound` refuses it); the derivation converges the
    /// moment the certificate names the delivered head; and the SAME bound
    /// that fences a diagnosed step's retries fences the collector's
    /// re-dispatches.
    #[test]
    fn a_fix_delivery_the_runs_own_collection_never_observed_is_re_collected() {
        let state = temp_state("fix-recollect");
        let digest = "d".repeat(64);
        let run = "run-0123456789abcdef";
        let policy = Policy {
            check_interval_secs: 10,
            progress_timeout_secs: 60,
        };
        let at = "2026-09-24T02:28:59Z";
        let now_unix = time::unix_from_rfc3339(at).expect("instant");
        state
            .arm_supervision_for_test(run, "armed", &digest, "merge", policy, at)
            .expect("arm");
        let row = state.supervision_by_id(run).expect("read").expect("row");
        let steps = [
            ("p1", "checkout"),
            ("p5", "collect_outcome"),
            ("p6", "review_evidence"),
            ("p7", "merge"),
        ];
        let certified = "e".repeat(40);
        let delivered = "a".repeat(40);
        let certificate = |head: &str| crate::state::DeliveryCertificate {
            step_id: "p5".to_string(),
            key: "ik_run-0123456789abcdef-p5-1790208650".to_string(),
            branch: "issue-5".to_string(),
            head: head.to_string(),
            base_head: "b".repeat(40),
        };
        let retry_row = |step: &str, attempt: i64, consumed: bool| crate::state::RunRetryRow {
            retry_id: format!("rt_0123456789abcde{attempt}"),
            instance_id: run.to_string(),
            step_id: step.to_string(),
            attempt,
            authorized_at: at.to_string(),
            consumed_at: if consumed {
                at.to_string()
            } else {
                String::new()
            },
            consumed_key: if consumed {
                format!("ik_spent-{attempt}")
            } else {
                String::new()
            },
        };
        // The recorded shape of the measured park: the review step's attempt
        // was refused `refusal.delivery.unbound`, its FAIL stands, and the
        // handoff's own repair leg holds a head past the certified one.
        let scene = |code: &str| {
            let mut evidence = evidence_with_failed_review(run_row(run), &steps, &certified);
            evidence.attempts = vec![
                ("p1".to_string(), "succeeded".to_string(), String::new()),
                ("p5".to_string(), "succeeded".to_string(), String::new()),
                ("p6".to_string(), "refused".to_string(), code.to_string()),
            ];
            evidence.run.caps = "[\"review\",\"merge\"]".to_string();
            evidence.reviewer_leg_steps = vec!["p6".to_string()];
            evidence.item = Some(crate::state::QueueItemRef {
                submission_id: "qs_0123456789abcdef".to_string(),
                ordinal: 0,
                work_item: "wi_4aabf3ad5bea87b0".to_string(),
                issue_number: 272,
                status: "admitted".to_string(),
            });
            evidence.fix_round = Some(crate::state::SupervisionFixRound {
                step: "p6".to_string(),
                feature_head: certified.clone(),
                round: 1,
                bound: 3,
                lane: "lane-0123456789abcdef".to_string(),
                worktree: "issues-272-impl2".to_string(),
            });
            evidence.fix_leg = Some(crate::state::FixLegState {
                head: delivered.clone(),
                delivered: true,
            });
            evidence.delivery = Some(certificate(&certified));
            evidence
        };
        let unbound = scene(crate::mutation::code::DELIVERY_UNBOUND);

        // (1) The ONE derived continuation is the re-collect of the run's own
        //     collector step: the frontier review is NOT re-dispatched while
        //     the head it would consume is one no collection observed, and the
        //     tail is never driven on it either.
        let intent = dispatch_intent(&row, &unbound).expect("the re-collect is derived");
        assert_eq!(intent.step_id, "p5", "{intent:?}");
        assert_eq!(intent.kind, "collect_outcome");
        assert_eq!(intent.reason, codes::RECOLLECT);
        assert!(
            !classify(&unbound, &digest, &policy, now_unix).eligible,
            "the parked run is never reported eligible while it re-collects"
        );

        // (2) A held operator authorization does not buy the review's
        //     re-dispatch while the delivery is uncertified: the fence the
        //     measured runs parked on stands, and the authorization stays
        //     SPENT-BY-NOTHING (the re-collect names its own step).
        let mut held = unbound.clone();
        held.retries = vec![retry_row("p6", 2, false)];
        assert_eq!(
            dispatch_intent(&row, &held).map(|intent| intent.step_id),
            Some("p5".to_string()),
            "an uncertified delivery re-collects; the review is never re-dispatched"
        );

        // (3) Once the run's OWN collection certifies the head its own handoff
        //     delivered, the re-collect stops (it converges by construction)
        //     and the diagnosed review is dispatchable again — with the held
        //     authorization, and on the driver's own minted one when none is
        //     held. The head it consumes is a collected fact again.
        let mut recertified = held.clone();
        recertified.delivery = Some(certificate(&delivered));
        let intent = dispatch_intent(&row, &recertified).expect("the review re-enters");
        assert_eq!(intent.step_id, "p6", "{intent:?}");
        assert_eq!(intent.kind, "review_evidence");
        assert_eq!(intent.reason, codes::DISPATCH);
        let mut self_driving = recertified.clone();
        self_driving.retries = Vec::new();
        assert_eq!(
            dispatch_intent(&row, &self_driving).map(|intent| intent.step_id),
            Some("p6".to_string()),
            "the driver mints its own bounded retry for the rebind consumer"
        );
        // And the bound is still a bound: a spent budget parks typed.
        self_driving.retries = (1..=crate::state::RUN_RETRY_MAX)
            .map(|attempt| retry_row("p6", attempt, true))
            .collect();
        assert!(
            dispatch_intent(&row, &self_driving).is_none(),
            "a spent budget parks the consumer exactly as before"
        );
        // A re-collect that cannot be taken is bounded the same way.
        let mut spent_collector = recertified.clone();
        spent_collector.delivery = Some(certificate(&certified));
        spent_collector.retries = (1..=crate::state::RUN_RETRY_MAX)
            .map(|attempt| retry_row("p5", attempt, true))
            .collect();
        assert!(
            dispatch_intent(&row, &spent_collector).is_none(),
            "the collector is re-dispatched at most the shared bounded budget"
        );

        // (4) The head the run re-collects is only ever the landed fact of a
        //     recorded checkout: no observed leg, no recorded checkout, or a
        //     leg that has not moved derives no re-collect at all — the park
        //     stands exactly where it did before.
        let mut unobserved = unbound.clone();
        unobserved.fix_leg = None;
        assert!(
            dispatch_intent(&row, &unobserved).is_none(),
            "an unobserved leg is never collected from a guessed path"
        );
        let mut unnamed_checkout = unbound.clone();
        unnamed_checkout
            .fix_round
            .as_mut()
            .expect("recorded")
            .worktree = String::new();
        unnamed_checkout.fix_leg = None;
        assert!(
            dispatch_intent(&row, &unnamed_checkout).is_none(),
            "a handoff that names no checkout is never collected from a guessed path"
        );
        let mut swimming = unbound.clone();
        swimming.fix_leg = Some(crate::state::FixLegState {
            head: certified.clone(),
            delivered: false,
        });
        assert!(
            dispatch_intent(&row, &swimming).is_none(),
            "a leg that has not moved is the wait it always was"
        );

        // (5) A delivery that was ALREADY re-reviewed is never hijacked back
        //     into a collection: the newest recorded verdict owns the tail.
        let mut passed = unbound.clone();
        passed.verdicts[0].1 = "pass".to_string();
        assert!(
            dispatch_intent(&row, &passed).is_none_or(|intent| intent.reason != codes::RECOLLECT),
            "a passed delivery is never re-collected"
        );
    }

    #[test]
    fn progress_marker_is_content_bound_and_stable() {
        let evidence = evidence_for(
            run_row("run-0123456789abcdef"),
            Some(&"d".repeat(64)),
            &[("checkout", "checkout")],
            &[("checkout", "succeeded", "")],
            "2026-09-13T00:00:30Z",
        );
        let (marker, source) = progress_observation(&evidence, "2026-09-13T00:00:00Z");
        assert_eq!(marker.len(), 64, "sha256 hex");
        assert_eq!(source, "completion");
        let (again, _) = progress_observation(&evidence, "2026-09-13T00:00:00Z");
        assert_eq!(marker, again, "the marker is a pure function of evidence");
        // A new review verdict moves the marker and names the source.
        let mut reviewed = evidence.clone();
        reviewed.verdicts.push((
            "ev_0123456789abcdef".to_string(),
            "pass".to_string(),
            "2026-09-13T00:00:40Z".to_string(),
        ));
        let (moved, source) = progress_observation(&reviewed, "2026-09-13T00:00:30Z");
        assert_ne!(marker, moved);
        assert_eq!(source, "review");
        // A CI attempt names the CI source.
        let mut checked = evidence.clone();
        checked.steps = vec![("check".to_string(), "hosted_check".to_string())];
        checked.attempts = vec![("check".to_string(), "succeeded".to_string(), String::new())];
        let (_, source) = progress_observation(&checked, "2026-09-13T00:00:00Z");
        assert_eq!(source, "ci");
    }

    #[test]
    fn retry_timing_and_pause_survive_a_state_reopen() {
        let dir =
            std::env::temp_dir().join(format!("hf-supervision-reopen-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("state.db");
        let _ = std::fs::remove_file(&path);
        let digest = "d".repeat(64);
        let run = "run-0123456789abcdef";
        {
            let state = State::open(&path, Retention::default()).expect("open");
            state
                .arm_supervision_for_test(
                    run,
                    "armed",
                    &digest,
                    "review",
                    Policy {
                        check_interval_secs: 10,
                        progress_timeout_secs: 60,
                    },
                    "2026-09-13T00:00:00Z",
                )
                .expect("arm");
            state
                .record_supervision_trigger(run, "review", 4, "2026-09-13T00:00:05Z")
                .expect("trigger");
        }
        {
            let state = State::open(&path, Retention::default()).expect("reopen");
            let row = state
                .supervision_by_id(run)
                .expect("read")
                .expect("row survives a reopen");
            assert_eq!(row.desired, "armed");
            assert_eq!(row.authorization_digest, digest);
            assert_eq!(row.progress_timeout_secs, 60);
            let trigger = state
                .supervision_trigger(run)
                .expect("read")
                .expect("pending trigger survives a reopen");
            assert_eq!(trigger.trigger_seq, 4);
            assert_eq!(trigger.trigger, "review");
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn duplicate_and_out_of_order_events_fold_into_one_reconciliation() {
        let state = temp_state("fold");
        let digest = "d".repeat(64);
        let run = "run-0123456789abcdef";
        state
            .arm_supervision_for_test(
                run,
                "armed",
                &digest,
                "review",
                Policy {
                    check_interval_secs: 10,
                    progress_timeout_secs: 60,
                },
                "2026-09-13T00:00:00Z",
            )
            .expect("arm");
        for seq in [5, 5, 9, 7] {
            state
                .record_supervision_trigger(run, "completion", seq, "2026-09-13T00:00:01Z")
                .expect("trigger");
        }
        let trigger = state
            .supervision_trigger(run)
            .expect("read")
            .expect("pending");
        assert_eq!(trigger.trigger_seq, 9, "the fold keeps the highest seq");
        assert_eq!(trigger.folded, 3, "one duplicate is dropped, not folded");
        let due = state.supervision_due_runs(1_800_000_000).expect("due");
        assert_eq!(due, vec![run.to_string()], "one run, one pending slot");
    }

    #[test]
    fn due_set_folds_the_timer_and_event_sources_per_run() {
        let state = temp_state("due");
        let digest = "d".repeat(64);
        let run = "run-0123456789abcdef";
        state
            .arm_supervision_for_test(
                run,
                "armed",
                &digest,
                "review",
                Policy {
                    check_interval_secs: 10,
                    progress_timeout_secs: 60,
                },
                "2026-09-13T00:00:00Z",
            )
            .expect("arm");
        let armed_at = time::unix_from_rfc3339("2026-09-13T00:00:00Z").expect("instant");
        // A freshly armed run is due exactly once: it has no schedule yet, so
        // the driver performs its first (fresh snapshot) reconciliation.
        assert_eq!(
            state.supervision_due_runs(armed_at).expect("due"),
            vec![run.to_string()]
        );
        let check =
            |next_unix: i64, consumed_seq: i64, trigger: &'static str| SupervisionCheckPlan {
                instance_id: run.to_string(),
                now_unix: armed_at,
                at: "2026-09-13T00:00:00Z".to_string(),
                class: "healthy",
                reason: codes::RECENT_PROGRESS,
                eligible: false,
                trigger,
                consumed_seq,
                consumed_all: false,
                marker: "marker-a".to_string(),
                marker_source: "state",
                next_check_unix: next_unix,
                next_check_reason: codes::RECENT_PROGRESS,
                advance: None,
                dispatch: None,
            };
        state
            .commit_supervision_check(&check(armed_at + 10, 0, "boot"))
            .expect("first check");
        // Before the timer elapses and with no pending wake, nothing is due.
        assert!(
            state
                .supervision_due_runs(armed_at + 5)
                .expect("due")
                .is_empty()
        );
        // A pending semantic wake makes the run due immediately...
        state
            .record_supervision_trigger(run, "ci", 11, "2026-09-13T00:00:02Z")
            .expect("trigger");
        assert_eq!(
            state.supervision_due_runs(armed_at + 5).expect("due"),
            vec![run.to_string()],
            "an event wake is one entry"
        );
        // ...and the timer alone also makes it due, with ONE entry per run
        // even though a wake was pending at the same moment.
        state
            .commit_supervision_check(&check(armed_at + 20, 11, "ci"))
            .expect("second check");
        assert!(
            state
                .supervision_due_runs(armed_at + 15)
                .expect("due")
                .is_empty()
        );
        state
            .record_supervision_trigger(run, "completion", 12, "2026-09-13T00:00:03Z")
            .expect("trigger");
        assert_eq!(
            state.supervision_due_runs(armed_at + 25).expect("due"),
            vec![run.to_string()],
            "a pending wake AND an elapsed timer still coalesce into one entry"
        );
        // A disabled authorization is never due.
        state
            .arm_supervision_for_test(
                run,
                "disabled",
                &digest,
                "review",
                Policy::default(),
                "2026-09-13T00:00:00Z",
            )
            .expect("disable");
        assert!(
            state
                .supervision_due_runs(armed_at + 3600)
                .expect("due")
                .is_empty(),
            "a disabled supervision is never evaluated"
        );
    }

    #[test]
    fn commits_are_one_per_window_and_advance_the_marker_only_on_new_evidence() {
        let state = temp_state("commit");
        let digest = "d".repeat(64);
        let run = "run-0123456789abcdef";
        state
            .arm_supervision_for_test(
                run,
                "armed",
                &digest,
                "review",
                Policy {
                    check_interval_secs: 10,
                    progress_timeout_secs: 60,
                },
                "2026-09-13T00:00:00Z",
            )
            .expect("arm");
        let plan = |now_unix: i64, marker: &str, consumed: i64, class: &'static str| {
            SupervisionCheckPlan {
                instance_id: run.to_string(),
                now_unix,
                at: time::rfc3339_from_unix(now_unix),
                class,
                reason: codes::RECENT_PROGRESS,
                eligible: false,
                trigger: "boot",
                consumed_seq: consumed,
                consumed_all: false,
                marker: marker.to_string(),
                marker_source: "state",
                next_check_unix: now_unix + 10,
                next_check_reason: codes::RECENT_PROGRESS,
                advance: None,
                dispatch: None,
            }
        };
        let first = state
            .commit_supervision_check(&plan(1_800_000_000, "marker-a", 0, "healthy"))
            .expect("first check");
        assert_eq!(first.checks, 1);
        assert_eq!(first.progress_at, "2027-01-15T08:00:00Z");
        // A second check with identical evidence keeps the marker and its
        // observation time (a heartbeat is not progress).
        let second = state
            .commit_supervision_check(&plan(1_800_000_100, "marker-a", 0, "healthy"))
            .expect("second check");
        assert_eq!(second.checks, 2);
        assert_eq!(second.progress_marker, "marker-a");
        assert_eq!(
            second.progress_at, first.progress_at,
            "a heartbeat must not reset the marker"
        );
        // New evidence moves the marker.
        let third = state
            .commit_supervision_check(&plan(1_800_000_200, "marker-b", 0, "healthy"))
            .expect("third check");
        assert_eq!(third.progress_marker, "marker-b");
        assert_eq!(third.progress_at, "2027-01-15T08:03:20Z");
        // A pending trigger is consumed exactly once, fenced on its seq.
        state
            .record_supervision_trigger(run, "review", 21, "2026-09-13T00:00:09Z")
            .expect("trigger");
        let consumed = state
            .commit_supervision_check(&plan(1_800_000_300, "marker-b", 21, "healthy"))
            .expect("fourth check");
        assert_eq!(consumed.checks, 4);
        assert!(
            state.supervision_trigger(run).expect("read").is_none(),
            "the consumed trigger is gone"
        );
        // A stale consumer (an older seq) never clears a newer trigger.
        state
            .record_supervision_trigger(run, "ci", 30, "2026-09-13T00:00:10Z")
            .expect("trigger");
        let kept = state
            .commit_supervision_check(&plan(1_800_000_400, "marker-b", 21, "healthy"))
            .expect("stale consumer");
        assert_eq!(kept.checks, 5);
        assert!(
            state.supervision_trigger(run).expect("read").is_some(),
            "a newer trigger survives a stale consumer"
        );
    }

    #[test]
    fn semantic_journal_actions_fold_into_the_run_slot_with_their_wake_class() {
        let state = temp_state("fold-events");
        let digest = "d".repeat(64);
        let run = "run-0123456789abcdef";
        state
            .arm_supervision_for_test(
                run,
                "armed",
                &digest,
                "review",
                Policy {
                    check_interval_secs: 10,
                    progress_timeout_secs: 60,
                },
                "2026-09-13T00:00:00Z",
            )
            .expect("arm");
        // Journal the semantic events exactly as the daemon does: apply steps
        // target `repository:run-…:step`, run controls target `run:run-…`.
        let journal = |action: &str, target: &str, key: &str| {
            state
                .journal_intent(
                    action,
                    target,
                    key,
                    "0123456789abcdef",
                    "apply",
                    None,
                    None,
                    "{\"method\":\"apply\"}",
                )
                .expect("journal intent");
        };
        journal(
            "mutate.review_evidence",
            &format!("example-org/widgets:{run}:p1"),
            "ik_fold-review",
        );
        let fold = state
            .fold_supervision_events(0, "2026-09-13T00:00:01Z")
            .expect("fold");
        assert_eq!(fold.folded, 1);
        assert_eq!(fold.runs, vec![run.to_string()]);
        assert_eq!(fold.cursor, 1, "the cursor advances past the folded event");
        let trigger = state
            .supervision_trigger(run)
            .expect("read")
            .expect("pending");
        assert_eq!(
            trigger.trigger, "review",
            "the wake class comes from the action"
        );
        journal(
            "mutate.hosted_check",
            &format!("example-org/widgets:{run}:p1"),
            "ik_fold-ci",
        );
        journal("mutate.run.pause", &format!("run:{run}"), "ik_fold-control");
        journal(
            "mutate.prompt",
            &format!("example-org/widgets:{run}:p1"),
            "ik_fold-completion",
        );
        let fold = state
            .fold_supervision_events(fold.cursor, "2026-09-13T00:00:02Z")
            .expect("fold");
        assert_eq!(fold.folded, 3, "three distinct wakes, one slot");
        assert!(!fold.lost, "the retention window still covers the cursor");
        let trigger = state
            .supervision_trigger(run)
            .expect("read")
            .expect("pending");
        assert_eq!(trigger.trigger_seq, 4, "the highest folded seq wins");
        assert_eq!(trigger.folded, 4, "every distinct wake is counted once");
        // The coalesced due set still names the run exactly once.
        assert_eq!(
            state.supervision_due_runs(1_800_000_000).expect("due"),
            vec![run.to_string()]
        );
        // A second fold with the same cursor folds nothing (no double count).
        let fold = state
            .fold_supervision_events(fold.cursor, "2026-09-13T00:00:03Z")
            .expect("fold");
        assert_eq!(fold.folded, 0);
    }

    #[test]
    fn retention_loss_falls_back_to_a_fresh_snapshot_wake() {
        let state = temp_state("fold-lost");
        let digest = "d".repeat(64);
        let run = "run-0123456789abcdef";
        state
            .arm_supervision_for_test(
                run,
                "armed",
                &digest,
                "review",
                Policy {
                    check_interval_secs: 10,
                    progress_timeout_secs: 60,
                },
                "2026-09-13T00:00:00Z",
            )
            .expect("arm");
        // The persisted cursor is ahead of the retained window (retention
        // moved past it): the incremental fold cannot attribute the missed
        // events, so the run gets a fresh snapshot wake instead.
        let fold = state
            .fold_supervision_events(50, "2026-09-13T00:00:01Z")
            .expect("fold");
        assert!(fold.lost, "a cursor past retention is a loss");
        let trigger = state
            .supervision_trigger(run)
            .expect("read")
            .expect("pending");
        assert_eq!(trigger.trigger, "snapshot");
    }

    #[test]
    fn a_clock_jump_re_anchors_the_next_check_and_never_replays_missed_windows() {
        let state = temp_state("clock-jump");
        let digest = "d".repeat(64);
        let run = "run-0123456789abcdef";
        state
            .arm_supervision_for_test(
                run,
                "armed",
                &digest,
                "review",
                Policy {
                    check_interval_secs: 60,
                    progress_timeout_secs: 900,
                },
                "2026-09-13T00:00:00Z",
            )
            .expect("arm");
        let armed_at = time::unix_from_rfc3339("2026-09-13T00:00:00Z").expect("instant");
        let evidence = evidence_for(
            run_row(run),
            Some(&digest),
            &[("p1", "checkout")],
            &[],
            "2026-09-13T00:00:00Z",
        );
        // The first check runs at t0 and schedules the next one 60s later.
        let row = state.supervision_by_id(run).expect("read").expect("row");
        let first = check_plan(&row, &evidence, None, true, armed_at);
        assert_eq!(first.next_check_unix, armed_at + 60);
        let row = state.commit_supervision_check(&first).expect("commit");
        // The host then sleeps for ten hours: the next check at the NEW now
        // is what a tick computes, and it lands a fresh interval in the
        // FUTURE — no catch-up replay of the ~600 missed windows.
        let after_sleep = armed_at + 10 * 60 * 60;
        let plan = check_plan(&row, &evidence, None, false, after_sleep);
        assert!(
            plan.next_check_unix > after_sleep,
            "a jumped clock never schedules a check in the past"
        );
        assert_eq!(plan.next_check_unix - after_sleep, 60);
        let committed = state.commit_supervision_check(&plan).expect("commit");
        assert_eq!(
            committed.checks, 2,
            "exactly one fresh reconciliation for the whole jump"
        );
        assert!(
            state
                .supervision_due_runs(after_sleep + 1)
                .expect("due")
                .is_empty(),
            "the missed windows are skipped, never replayed"
        );
    }

    #[test]
    fn driver_reports_one_continuation_per_absence_window() {
        let state = temp_state("continuation");
        let digest = "d".repeat(64);
        let run = "run-0123456789abcdef";
        state
            .arm_supervision_for_test(
                run,
                "armed",
                &digest,
                "review",
                Policy {
                    check_interval_secs: 10,
                    progress_timeout_secs: 60,
                },
                "2026-09-13T00:00:00Z",
            )
            .expect("arm");
        let plan = |now_unix: i64, eligible: bool, class: &'static str| SupervisionCheckPlan {
            instance_id: run.to_string(),
            now_unix,
            at: time::rfc3339_from_unix(now_unix),
            class,
            reason: if eligible {
                codes::PROGRESS_TIMEOUT
            } else {
                codes::RECENT_PROGRESS
            },
            eligible,
            trigger: "timer",
            consumed_seq: 0,
            consumed_all: false,
            marker: "marker-a".to_string(),
            marker_source: "state",
            next_check_unix: now_unix + 10,
            next_check_reason: codes::RECENT_PROGRESS,
            advance: None,
            dispatch: None,
        };
        let first = state
            .commit_supervision_check(&plan(1_800_000_000, true, "continuation-eligible"))
            .expect("first");
        assert_eq!(first.continuation_reports, 1);
        assert!(first.continuation_open);
        let repeat = state
            .commit_supervision_check(&plan(1_800_000_010, true, "continuation-eligible"))
            .expect("repeat");
        assert_eq!(
            repeat.continuation_reports, 1,
            "one report per absence window, never one per check"
        );
        let recovered = state
            .commit_supervision_check(&plan(1_800_000_020, false, "healthy"))
            .expect("recovered");
        assert!(!recovered.continuation_open);
        let again = state
            .commit_supervision_check(&plan(1_800_000_030, true, "continuation-eligible"))
            .expect("again");
        assert_eq!(again.continuation_reports, 2, "a new window reports once");
    }

    /// Issue #219: the rendered status surfaces the newest recorded
    /// NON-succeeded attempt WITH its raw message, so an operator reads WHY a
    /// frontier is parked (a rejected push, a refused merge, a missing
    /// credential) from the same read that reports the class — never only
    /// from a daemon log. A run with no standing failure renders `null`.
    #[test]
    fn the_rendered_status_carries_the_recorded_failure_with_its_reason() {
        let state = temp_state("status-failure");
        let digest = "d".repeat(64);
        let run = "run-0123456789abcdef";
        let policy = Policy {
            check_interval_secs: 10,
            progress_timeout_secs: 60,
        };
        state
            .arm_supervision_for_test(
                run,
                "armed",
                &digest,
                "merge",
                policy,
                "2026-09-13T00:00:00Z",
            )
            .expect("arm");
        let steps = [("merge", "merge")];
        let now = 1_800_000_000;
        // No standing failure: the field is present and null.
        let clean = evidence_for(run_row(run), Some(&digest), &steps, &[], "");
        let (row, _) = commit_for(&state, &clean, true, now);
        let verdict = classify(&clean, &digest, &policy, now);
        let doc = status_doc(&row, &clean, None, &verdict, now);
        assert!(path(&doc, &["last_failure"]).is_null());
        // One recorded NON-succeeded attempt: the durable code AND message are
        // rendered verbatim.
        let mut failed = evidence_for(run_row(run), Some(&digest), &steps, &[], "");
        failed.last_failure = Some(crate::state::StepFailure {
            step: "p7-1".to_string(),
            status: "failed".to_string(),
            code: crate::mutation::code::MERGE_PUSH_REJECTED.to_string(),
            message: "the landing abcd was not published: [remote rejected] (push declined)"
                .to_string(),
        });
        let doc = status_doc(&row, &failed, None, &verdict, now);
        assert_eq!(path(&doc, &["last_failure", "step"]).as_str(), Some("p7-1"));
        assert_eq!(
            path(&doc, &["last_failure", "code"]).as_str(),
            Some(crate::mutation::code::MERGE_PUSH_REJECTED)
        );
        assert_eq!(
            path(&doc, &["last_failure", "message"]).as_str(),
            Some("the landing abcd was not published: [remote rejected] (push declined)")
        );
        let human = render_human(&doc);
        assert!(
            human.contains("last failure p7-1 failed (effect.merge.push_rejected)"),
            "{human}"
        );
        assert!(human.contains("[remote rejected]"), "{human}");
    }

    /// Walk one document path (`Val::get` per key), `null` when absent.
    fn path(doc: &Val, keys: &[&str]) -> Val {
        let mut cursor = doc.clone();
        for key in keys {
            cursor = cursor.get(key).cloned().unwrap_or_else(null);
        }
        cursor
    }

    /// Check (via `check_plan`, the driver's own plan builder) and commit one
    /// reconciliation of the armed run, returning the committed row.
    fn commit_for(
        state: &State,
        evidence: &SupervisionEvidence,
        boot: bool,
        now_unix: i64,
    ) -> (crate::state::SupervisionRow, SupervisionCheckPlan) {
        let row = state
            .supervision_by_id(&evidence.run.instance_id)
            .expect("read")
            .expect("row");
        let plan = check_plan(&row, evidence, None, boot, now_unix);
        let committed = state.commit_supervision_check(&plan).expect("commit");
        (committed, plan)
    }

    #[test]
    fn an_unobserved_run_is_held_and_a_genuine_deadline_opens_exactly_one_window() {
        // The production commit path (check_plan -> commit_supervision_check)
        // for the two cases the fix contract separates: NO observation (held,
        // no report ever) and an observation genuinely older than the explicit
        // policy (progress timeout, exactly one report per window).
        let state = temp_state("unobserved");
        let digest = "d".repeat(64);
        let run = "run-0123456789abcdef";
        let policy = Policy {
            check_interval_secs: 10,
            progress_timeout_secs: 60,
        };
        state
            .arm_supervision_for_test(
                run,
                "armed",
                &digest,
                "review",
                policy,
                "2026-09-13T00:00:00Z",
            )
            .expect("arm");
        let steps = [("merge", "merge")];
        let now = 1_800_000_000;
        // 1. No observation recorded yet: held, and the commit must not open
        //    a window (this is the reviewer's exact scenario).
        let unobserved = evidence_for(run_row(run), Some(&digest), &steps, &[], "");
        let (row, plan) = commit_for(&state, &unobserved, true, now);
        assert_eq!(plan.class, "unknown");
        assert_eq!(plan.reason, codes::PROGRESS_UNOBSERVED);
        assert!(!plan.eligible);
        assert_eq!(row.continuation_reports, 0);
        assert!(!row.continuation_open);
        // A second and third unobserved-looking check keep it at zero.
        for at in [now + 10, now + 20] {
            let unreadable = evidence_for(run_row(run), Some(&digest), &steps, &[], "not-a-time");
            let (row, plan) = commit_for(&state, &unreadable, false, at);
            assert_eq!(plan.reason, codes::PROGRESS_UNOBSERVED);
            assert_eq!(row.continuation_reports, 0);
            assert!(!row.continuation_open);
        }
        // 2. An observation that IS recorded and older than the deadline is
        //    the legitimate timeout path: eligible, exactly one report.
        let stale_at = time::rfc3339_from_unix(now - 61);
        let stale = evidence_for(run_row(run), Some(&digest), &steps, &[], &stale_at);
        let (row, plan) = commit_for(&state, &stale, false, now);
        assert!(plan.eligible, "a genuinely aged observation is eligible");
        assert_eq!(plan.class, "continuation-eligible");
        assert_eq!(plan.reason, codes::PROGRESS_TIMEOUT);
        assert_eq!(row.continuation_reports, 1);
        assert!(row.continuation_open);
        // 3. A repeat within the same window never reports again.
        let (row, _) = commit_for(&state, &stale, false, now + 10);
        assert_eq!(row.continuation_reports, 1, "one report per absence window");
        assert!(row.continuation_open);
        // 4. A fresh observation closes the window, and the SAME observation
        //    61s later is a NEW absence window (per window, not per run).
        let fresh_at = time::rfc3339_from_unix(now + 20);
        let fresh = evidence_for(run_row(run), Some(&digest), &steps, &[], &fresh_at);
        let (row, plan) = commit_for(&state, &fresh, false, now + 20);
        assert_eq!(plan.reason, codes::RECENT_PROGRESS);
        assert!(!row.continuation_open);
        assert_eq!(row.continuation_reports, 1);
        let (row, plan) = commit_for(&state, &fresh, false, now + 20 + 61);
        assert!(plan.eligible, "the aged observation is eligible again");
        assert_eq!(row.continuation_reports, 2, "a new window reports again");
    }

    #[test]
    fn the_read_reports_the_committed_state_and_never_launders_it() {
        // The status surface is durable-first: it reports the RECORDED result
        // of the last committed check and the durable window state, even when
        // a read-time re-classification of the same evidence would look
        // friendlier. Reads can therefore never hide a committed effect.
        let state = temp_state("read-honesty");
        let digest = "d".repeat(64);
        let run = "run-0123456789abcdef";
        let policy = Policy {
            check_interval_secs: 10,
            progress_timeout_secs: 60,
        };
        state
            .arm_supervision_for_test(
                run,
                "armed",
                &digest,
                "review",
                policy,
                "2026-09-13T00:00:00Z",
            )
            .expect("arm");
        let steps = [("merge", "merge")];
        let now = 1_800_000_000;
        // A committed HELD check is reported as held ...
        let unobserved = evidence_for(run_row(run), Some(&digest), &steps, &[], "");
        let (row, _) = commit_for(&state, &unobserved, true, now);
        let verdict = classify(&unobserved, &digest, &policy, now);
        let doc = status_doc(&row, &unobserved, None, &verdict, now);
        assert_eq!(
            path(&doc, &["evaluation", "class"]).as_str(),
            Some("unknown")
        );
        assert_eq!(
            path(&doc, &["evaluation", "reason"]).as_str(),
            Some(codes::PROGRESS_UNOBSERVED)
        );
        assert_eq!(
            path(&doc, &["evaluation", "eligible"]).as_bool(),
            Some(false)
        );
        assert_eq!(
            path(&doc, &["evaluation", "continuation", "reports"]).as_int(),
            Some(0)
        );
        // ...and the headline fields equal the committed record.
        assert_eq!(
            path(&doc, &["evaluation", "class"]),
            path(&doc, &["evaluation", "last_check", "class"]),
            "the reported class is the committed one"
        );
        // A committed ELIGIBLE check is an OPEN window with one report — and
        // the read says so even though re-classifying the SAME evidence with
        // the marker now on file would answer `healthy`.
        let stale = evidence_for(
            run_row(run),
            Some(&digest),
            &steps,
            &[],
            &time::rfc3339_from_unix(now - 61),
        );
        let (row, plan) = commit_for(&state, &stale, false, now);
        assert!(plan.eligible);
        assert_eq!(row.continuation_reports, 1);
        let fresh = evidence_for(
            run_row(run),
            Some(&digest),
            &steps,
            &[],
            &time::rfc3339_from_unix(now),
        );
        let observed_now = classify(&fresh, &digest, &policy, now);
        assert_eq!(
            observed_now.class, "healthy",
            "the read-time observation is the friendlier view"
        );
        let doc = status_doc(&row, &fresh, None, &observed_now, now);
        assert_eq!(
            path(&doc, &["evaluation", "class"]).as_str(),
            Some("continuation-eligible"),
            "the committed class is what a read reports"
        );
        assert_eq!(
            path(&doc, &["evaluation", "eligible"]).as_bool(),
            Some(true)
        );
        assert_eq!(
            path(&doc, &["evaluation", "continuation", "state"]).as_str(),
            Some("open")
        );
        assert_eq!(
            path(&doc, &["evaluation", "continuation", "reports"]).as_int(),
            Some(1)
        );
        assert_eq!(
            path(&doc, &["evaluation", "observed", "class"]).as_str(),
            Some("healthy"),
            "the observation is reported separately, never as the record"
        );
    }

    #[test]
    fn cycle2_idle_driver_bounds_deadline_evaluations_and_wakes() {
        // An immediately due deadline models an overdue check that cannot commit.
        // The read-only next_deadline calculation must not become a busy loop.
        let state = Arc::new(Mutex::new(temp_state("idle-deadline")));
        let mut driver = start(
            state,
            SupervisorOptions {
                max_wait_secs: 0,
                dispatch: None,
            },
        );
        let wake = driver.wake_handle();
        std::thread::sleep(Duration::from_millis(350));
        let evaluations = wake.deadline_evaluations.load(Ordering::SeqCst);
        let ticks = wake.ticks();
        wake.wake();
        let until = Instant::now() + Duration::from_secs(2);
        while wake.ticks() == ticks && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(5));
        }
        let woke = wake.ticks() > ticks;
        wake.signal_stop();
        assert!(driver.join());
        eprintln!("IDLE_WINDOW_MS=350 NEXT_DEADLINE_EVALUATIONS={evaluations} WAKE={woke}");
        assert!(
            evaluations <= 2,
            "idle driver spun: {evaluations} evaluations"
        );
        assert!(woke, "a new-work wake must interrupt the deadline wait");
    }

    #[test]
    fn driver_never_holds_the_state_guard_between_checks() {
        let state = temp_state("responsiveness");
        let digest = "d".repeat(64);
        let run = "run-0123456789abcdef";
        state
            .arm_supervision_for_test(
                run,
                "armed",
                &digest,
                "review",
                Policy {
                    check_interval_secs: 3600,
                    progress_timeout_secs: 7200,
                },
                &time::rfc3339_now(),
            )
            .expect("arm");
        let state = Arc::new(Mutex::new(state));
        let mut handle = start(
            Arc::clone(&state),
            SupervisorOptions {
                max_wait_secs: 3600,
                dispatch: None,
            },
        );
        // The driver must reach its wait WITHOUT the state guard: wait until
        // the driver is inside the wait (bounded, no fixed sleeps), then
        // acquire the guard with a bounded deadline — it must be free while
        // the driver idles, however long the wait lasts.
        let deadline = Instant::now() + Duration::from_secs(10);
        while !handle.wake_handle().waiting() {
            assert!(
                Instant::now() < deadline,
                "the driver never entered its wait"
            );
            std::thread::yield_now();
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut acquired = false;
        while Instant::now() < deadline {
            if let Ok(guard) = state.try_lock() {
                drop(guard);
                acquired = true;
                break;
            }
            std::thread::yield_now();
        }
        handle.wake_handle().signal_stop();
        let deadline = Instant::now() + Duration::from_secs(10);
        while !handle.thread.as_ref().expect("driver thread").is_finished() {
            assert!(
                Instant::now() < deadline,
                "the supervision driver did not exit after its stop signal"
            );
            std::thread::yield_now();
        }
        let joined = handle.join();
        assert!(
            acquired,
            "the driver held the state guard while waiting: timer work would monopolize RPC"
        );
        assert!(joined, "shutdown cancels and joins the driver");
    }
}
