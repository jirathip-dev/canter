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
//!   ownership, topology, journal and idempotency gates; diagnosed steps still
//!   require the operator's explicit corrected retry dispatch.
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
//!   authorizes a retry, retries a diagnosed step or clears a hold.
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
pub const STATEMENT: &str = "an explicitly armed run is classified from recorded evidence and each unattempted autonomous next step — plus the risk-classed merge then cleanup tail of a run whose own committed queue submission declares it after that run's verified delivery — is dispatched through the existing apply engine with the committed grant, capability, admission, ownership, topology, journal and idempotency gates; a continuation the engine refuses before any effect is reported with the engine's own code and is never presented as an eligible next step; a fresh verified reviewed-and-CI-green delivery advances its authorized queue cursor exactly once under the same admission and ownership checks; supervision never resumes a pause, authorizes or consumes a retry, retries a diagnosed step, invents missing inputs or clears a hold";

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
/// committed spine (issue #152): the merge of its reviewed head (a read-only
/// policy rehearsal) and the cleanup of its lane worktree (destructive: it
/// removes a worktree whose branch is provably merged).
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

/// Whether ONE committed spine step comes AFTER the run's reviewed-evidence
/// step: the delivery whose tail the step completes (issue #152).
fn after_delivery_step(evidence: &SupervisionEvidence, step: &str) -> bool {
    let Some(delivering) = evidence
        .steps
        .iter()
        .rposition(|(_, kind)| kind == crate::mutation::DELIVERY_STEP_KIND)
    else {
        return false;
    };
    match evidence.steps.iter().position(|(id, _)| id == step) {
        Some(index) => index > delivering,
        None => false,
    }
}

/// Whether the driver may dispatch ONE kind of ONE step for this run
/// (issue #152).
///
/// The unattended continuation set ([`AUTONOMOUS_STEP_KINDS`]) is
/// unconditional: those steps are the run's ordinary committed work. The
/// risk-classed TAIL kinds ([`COMMITTED_TAIL_STEP_KINDS`]) are authorized by
/// the run's OWN committed submission instead, and only when every one of
/// these holds:
///
/// - the run is an ADMITTED member of a committed, digest-bound queue
///   submission (`evidence.item`): the spine is an approved plan, never an
///   ad-hoc run;
/// - the run's own committed caps carry the kind's required capability
///   (`merge` / `cleanup`) — the very capability `revalidate_effect` demands
///   at effect time, so the driver never attempts what the run was not
///   granted and no cap is widened here;
/// - the step comes AFTER the run's reviewed-evidence step in the committed
///   spine and that run carries a fresh VERIFIED delivery
///   ([`verified_delivery`]): the tail is driven only behind the delivery it
///   completes, so a destructive cleanup can never be driven for a run that
///   never delivered.
///
/// The step's parameters are never invented here: the dispatch presents the
/// committed step's OWN declared params verbatim (branch + `merge_policy` for
/// the merge, branch + worktree for the cleanup), which the engine's own
/// `check_step_params`/`revalidate_effect` then validates — the same
/// production-branch, policy, cleanup-ancestry and dirty-worktree gates as an
/// operator dispatch. A step already ATTEMPTED stays the operator's: the
/// caller re-checks the attempt ledger, so a diagnosed tail is never retried.
pub fn driver_dispatchable_kind(evidence: &SupervisionEvidence, step: &str, kind: &str) -> bool {
    if AUTONOMOUS_STEP_KINDS.contains(&kind) {
        return true;
    }
    if !COMMITTED_TAIL_STEP_KINDS.contains(&kind) || evidence.item.is_none() {
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
/// A diagnosed step may retry within the shared bounded budget. A pending
/// operator authorization reserves the step for the operator's corrected
/// dispatch: supervision never consumes it. The daemon backs off attempts
/// and atomically records its own consumed authorization through the apply
/// path, without bypassing any effect gate.
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
    let (step_id, kind) = next_unachieved_step(evidence)?;
    if !driver_dispatchable_kind(evidence, &step_id, &kind) {
        return None;
    }
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
            if matches!(status.as_str(), "failed" | "refused" | "ambiguous")
                && code != crate::mutation::code::WORKER_TIMEOUT
                && newest_verdict(evidence) != "fail"
                && evidence
                    .retries
                    .iter()
                    .filter(|retry| retry.step_id == step_id)
                    .count()
                    < crate::state::RUN_RETRY_MAX as usize
                && !evidence
                    .retries
                    .iter()
                    .any(|retry| retry.step_id == step_id && retry.consumed_at.is_empty()) => {}
        Some(_) => return None,
    }
    Some(DispatchIntent {
        instance_id: run.instance_id.clone(),
        step_id,
        kind,
        reason: codes::DISPATCH,
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
    // Durable holds first: a held run is never a delivery event.
    if run.paused
        || run.pause_requested
        || run.human_queue
        || run.status == "blocked"
        || run.status == "invalidated"
        || run.terminal_blockers > 0
    {
        return None;
    }
    // A step claim still in flight means the run is mid-effect: it is not a
    // completed delivery yet.
    if evidence.in_flight.is_some() {
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
    if newest_verdict(evidence) == "fail" {
        return Verdict::new("needs-attention", codes::REVIEW_FAILED, false, "");
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
        let (row, evidence, trigger) = {
            let state = match self.state.lock() {
                Ok(state) => state,
                Err(_) => return false,
            };
            let row = match state.supervision_by_id(instance_id) {
                Ok(Some(row)) if row.desired == "armed" => row,
                _ => return false,
            };
            let evidence = match state.supervision_evidence(instance_id) {
                Ok(Some(evidence)) => evidence,
                _ => return false,
            };
            let trigger = state.supervision_trigger(instance_id).ok().flatten();
            (row, evidence, trigger)
        };
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
    ];
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
            attempts: attempts
                .iter()
                .map(|(step, status, code)| {
                    (step.to_string(), status.to_string(), code.to_string())
                })
                .collect(),
            retries: Vec::new(),
            verdicts: Vec::new(),
            in_flight: None,
            progress_at: progress_at.to_string(),
            item: None,
            newest_evidence: None,
            dispatch_refusal: None,
        }
    }

    /// [`evidence_for`] with ONE recorded continuation-dispatch refusal
    /// (issue #141) — the durable record a refused frontier dispatch leaves
    /// behind instead of an attempt row.
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

    /// A diagnosed frontier may retry within the budget, but an operator
    /// reservation fences it even when a continuation refusal is also recorded.
    #[test]
    fn a_diagnosed_frontier_retries_unless_reserved_by_the_operator() {
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
            assert!(
                dispatch_intent(&row, &evidence).is_none(),
                "operator reservation wins"
            );
            assert!(
                !classify(&evidence, &digest, &policy, now_unix).eligible,
                "a diagnosed frontier is never reported eligible"
            );
        }
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
            .record_supervision_dispatch_refusal(run, "p3", "refusal.admission.proof_stale")
            .expect("record");
        let (_, lines) = state.journal_tail(0, 1_000).expect("journal");
        let target = format!("{run}:p3:refusal.admission.proof_stale");
        assert!(
            lines
                .iter()
                .any(|line| line.contains(codes::DISPATCH_REFUSED) && line.contains(&target)),
            "the refusal is a journal record of this run: {lines:?}"
        );
        let read = dispatch_refusal_of(run, &target, "2026-09-15T11:52:12Z").expect("read back");
        assert_eq!(read.step, "p3");
        assert_eq!(read.code, "refusal.admission.proof_stale");
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
