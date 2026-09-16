//! Run-scoped controls (issue #86): safe-boundary pause, resume, bounded
//! retry and supported step dispatch for ONE queue run, plus (issue #146)
//! the explicit release of a run that can never progress.
//!
//! A *run* is one durable `instances` row (`run-` + 16 hex) — the identity
//! the merged queue executor (#85) commits for every admitted selected
//! issue. This module is the typed control surface over those rows:
//! parameter parsing, the closed refusal vocabulary, the deterministic
//! projections (`hf-run-control/v1` / `hf-run-retry/v1` /
//! `hf-run-release/v1`) and the pure diagnosis helpers. The daemon owns
//! journaling and the state transactions (`State::request_run_pause`,
//! `State::resume_run`, `State::record_run_retry`, `State::claim_run_retry`,
//! `State::release_run`).
//!
//! ## Scope matrix (run vs fleet vs lane)
//!
//! | level | identity | control surface | effect of a run control |
//! | --- | --- | --- | --- |
//! | run | one `run-` instance id | `run.pause` / `run.resume` / `run.retry` / `run.release` / `run.dispatch` / `run.status` | exactly this run: stop admitting new steps (pause), lift this run's pause (resume), authorize one bounded re-dispatch of one diagnosed step (retry, authorization only), release ONE run that can never progress — its issue ownership and the occupancy it held are freed and the run goes terminal (release), dispatch ONE committed-spine step with the operator's own step inputs (dispatch, derived from the run's committed submission), read the control state back (status) |
//! | fleet | the whole run population | NONE — no `fleet.*` method exists in the closed RPC set | a fleet-level hold is an operator policy expressed as the set of paused runs: every `run.resume` is fenced on the exact instance id, so it never lifts another run's pause and never re-enables anything fleet-wide |
//! | lane | one handoff lane generation (replacement/checkpoint records) | `lane.*` only | run controls never touch lane records; a run control naming a non-run identity refuses typed |
//!
//! Nothing on this surface kills a process, cleans up work, mutates Git,
//! clears a repository or fleet-level hold, or bypasses a gate: a pause
//! stops admitting NEW work and preserves in-flight dirty work, a retry
//! authorizes exactly ONE bounded step re-dispatch, and a release refuses
//! while work is in flight or a bounded authorization is unconsumed — it
//! frees durable BOOKKEEPING (ownership, occupancy) of a run that cannot
//! make progress, never a running effect.

use crate::canonical::sha256_hex;
use crate::formats;
use crate::state::{GrantRow, InstanceRow, RUN_RETRY_MAX, RunReleaseOutcome, RunRetryRow};
use crate::value::{Val, bool_, integer, null, object, string};

/// The run-control document schema id (module-local like the #84 preview
/// and the #85 submission: deliberately outside the closed `hf-*` family
/// set).
pub const RUN_CONTROL_SCHEMA: &str = "hf-run-control/v1";

/// The bounded-retry document schema id (module-local).
pub const RUN_RETRY_SCHEMA: &str = "hf-run-retry/v1";

/// The supported step-dispatch document schema id (module-local).
pub const RUN_DISPATCH_SCHEMA: &str = "hf-run-dispatch/v1";

/// Evidence-based diagnosed-step resolution (module-local).
pub const RUN_RESOLUTION_SCHEMA: &str = "hf-run-resolution/v1";

/// The explicit release of a run that can never progress (issue #146;
/// module-local).
pub const RUN_RELEASE_SCHEMA: &str = "hf-run-release/v1";

/// Bound on the operator pause reason (same bound as the lane hold).
pub const REASON_MAX: usize = 300;

/// The statement every control document carries: what it did and did NOT
/// do.
pub const CONTROL_STATEMENT: &str = "run-scoped control only: exactly one run is addressed; no other run's pause, no fleet-level hold and no lane handoff record is touched, nothing is killed or cleaned up, and no gate is bypassed";

/// The statement every retry document carries: minting the authorization is
/// the WHOLE effect — nothing is dispatched, spawned or consumed by it; the
/// operator's own (corrected) dispatch of that step consumes it exactly once.
pub const RETRY_STATEMENT: &str = "bounded retry only: exactly ONE diagnosed step of this run is authorized for ONE re-dispatch; minting the authorization dispatches nothing by itself, spawns nothing and consumes nothing — the operator's own corrected dispatch of that exact step consumes it exactly once (single use), and the retry never repeats the plan or widens the reviewed boundary";

/// The statement every dispatch document carries: what the supported
/// dispatch surface did and did NOT do.
pub const DISPATCH_STATEMENT: &str = "step dispatch only: exactly ONE step of this run is dispatched, derived from the run's committed submission spine and the run's own recorded dispatch context — the caller presents only that step's own inputs (merged over the committed params, never a stale reconstruction); a request that is not well-formed enough to be attempted refuses typed BEFORE any bounded retry authorization is consumed, and that pre-screen is TOTAL over the closed step-kind set (each kind's own param contract, including the request-level observed read-backs and the topology gates its effect reads — a kind with no registered contract refuses too), so no kind inherits the burn; an unconsumed authorization of a diagnosed step is consumed by exactly this dispatch (single use), and nothing else is dispatched, spawned, resumed, cleaned up or widened";

/// The statement on evidence-based resolution: the diagnosed effect is never
/// executed again and the record conveys no review or merge authority.
pub const RESOLUTION_STATEMENT: &str = "diagnosed-step resolution only: recorder-attributed artifact evidence marks exactly ONE prompt step delivered without re-executing its ambiguous/failed effect; no process is started or prompted, no Git/forge write occurs, no review verdict or merge authority is created, and supervision's diagnosed-step no-redispatch fence remains in force";

/// The statement every release document carries: what the release did and
/// did NOT do. A release is a BOOKKEEPING operation — it frees the durable
/// ownership and occupancy of ONE run that can never progress, and it
/// refuses while anything of that run is still live.
pub const RELEASE_STATEMENT: &str = "run release only: exactly ONE run is addressed — its durable ownership of its issue and the per-repository/per-harness occupancy it held are freed and the run becomes terminal (`invalidated`), so it is never resumed, retried, dispatched or reconciled again; a release refuses typed while a step of the run is in flight or while it still holds an unconsumed bounded retry authorization (that authorization is never burned by a release); nothing is killed, no in-flight work is cancelled or cleaned up, no other run's ownership or pause is touched, no worktree or Git state is mutated, no grant is rewritten and no gate is bypassed";

/// The closed control-state vocabulary rendered by the documents.
pub const CONTROL_STATES: [&str; 3] = ["active", "pause_requested", "paused"];

/// Stable run-control codes (the `refusal.run.*` namespace).
pub mod codes {
    /// The target is not a run identity (or not the requested one).
    pub const TARGET: &str = "refusal.run.target";
    /// The run is terminal (`done` / `invalidated`): no control applies.
    pub const TERMINAL: &str = "refusal.run.terminal";
    /// The run already carries a pause (or none to resume): a duplicate
    /// control never creates a second effect.
    pub const CONTROL: &str = "refusal.run.control";
    /// The run is paused or has a pause request: dispatch stays refused
    /// until it is explicitly resumed.
    pub const PAUSED: &str = "refusal.run.paused";
    /// The addressed run has no committed queue submission spine.
    pub const SCOPE: &str = "refusal.run.scope";
    /// The named step is not a step of the run's bound spine.
    pub const STEP_UNKNOWN: &str = "refusal.run.step_unknown";
    /// The named step is not the run's current unachieved frontier step.
    pub const STEP_ORDER: &str = "refusal.run.step_order";
    /// The named step already succeeded (or the run is past it): a
    /// terminal-success step is never retried.
    pub const STEP_DONE: &str = "refusal.run.step_done";
    /// The named step has no recorded terminal failed attempt: a retry is
    /// only for a DIAGNOSED failure, never for an attempt that never ran.
    pub const STEP_UNDIAGNOSED: &str = "refusal.run.step_undiagnosed";
    /// One unconsumed retry authorization already exists for this step; a
    /// release refuses on it rather than burning it.
    pub const RETRY_PENDING: &str = "refusal.run.retry_pending";
    /// All bounded retries for this step are used.
    pub const RETRY_BOUND: &str = "refusal.run.retry_bound";
    /// Evidence resolution is supported only for a diagnosed prompt effect.
    pub const RESOLUTION_KIND: &str = "refusal.run.resolution_kind";
    /// Artifact evidence or recorder identity is malformed/incomplete.
    pub const RESOLUTION_EVIDENCE: &str = "refusal.run.resolution_evidence";
    /// A claimed effect still exists; resolution cannot race it and a
    /// release never abandons it.
    pub const IN_FLIGHT: &str = "refusal.run.in_flight";
    /// The run was superseded: live ownership of its issue belongs to
    /// another run.
    pub const SUPERSEDED: &str = "refusal.run.superseded";
}

/// A typed run-control error/refusal (fail closed; stable codes).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControlError {
    /// Stable dotted code (`usage.run.*` or `refusal.*`).
    pub code: &'static str,
    /// Bounded human message.
    pub message: String,
}

impl ControlError {
    /// Build one typed error.
    pub fn new(code: &'static str, message: impl Into<String>) -> ControlError {
        ControlError {
            code,
            message: message.into(),
        }
    }
}

/// `run.pause` params, fully shape-validated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PauseParams {
    /// The presented idempotency key.
    pub idempotency_key: String,
    /// The exact run identity (`run-` + 16 hex).
    pub instance_id: String,
    /// The bounded operator reason.
    pub reason: String,
}

/// `run.resume` params, fully shape-validated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResumeParams {
    /// The presented idempotency key.
    pub idempotency_key: String,
    /// The exact run identity (`run-` + 16 hex).
    pub instance_id: String,
    /// The engine-minted resume digest (64-hex).
    pub digest: String,
}

/// `run.retry` params, fully shape-validated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetryParams {
    /// The presented idempotency key.
    pub idempotency_key: String,
    /// The exact run identity (`run-` + 16 hex).
    pub instance_id: String,
    /// The exact diagnosed step id (plan-local slug).
    pub step: String,
}

/// `run.resolve` params: one diagnosed prompt, attributed artifact evidence,
/// and no instruction capable of re-running the effect.
#[derive(Clone, Debug, PartialEq)]
pub struct ResolveParams {
    /// The presented idempotency key.
    pub idempotency_key: String,
    /// The exact run identity (`run-` + 16 hex).
    pub instance_id: String,
    /// The exact diagnosed prompt step.
    pub step: String,
    /// The bounded identity that attests/records the evidence.
    pub recorder: String,
    /// Closed artifact evidence: feature head, branch, PR and named checks.
    pub evidence: Val,
}

/// `run.dispatch` params, fully shape-validated (issue #92): the run, the
/// committed-spine step and ONLY the step-specific inputs the operator
/// actually knows — every other input (plan, issue pins, grant, topology,
/// admission) is derived from the run's committed submission and its own
/// recorded dispatch context.
#[derive(Clone, Debug, PartialEq)]
pub struct DispatchParams {
    /// The presented idempotency key.
    pub idempotency_key: String,
    /// The exact run identity (`run-` + 16 hex).
    pub instance_id: String,
    /// The committed-spine step to dispatch (plan-local slug).
    pub step: String,
    /// The operator's step inputs, merged over the step's committed params.
    /// `None` = the committed params as reviewed (no correction).
    pub step_params: Option<Val>,
    /// Initial lane paths; later dispatches reuse the recorded topology.
    pub topology: Option<Val>,
    /// Explicit current admission attestation; never a synthesized measurement.
    pub admission: Option<Val>,
}

/// `run.release` params (issue #146), fully shape-validated: ONE run, an
/// operator reason and nothing capable of dispatching work.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReleaseParams {
    /// The presented idempotency key.
    pub idempotency_key: String,
    /// The exact run identity (`run-` + 16 hex).
    pub instance_id: String,
    /// The bounded operator reason (recorded in the audit).
    pub reason: String,
}

/// Validate one required key and return its closed key set check.
fn only_keys(params: &Val, allowed: &[&str], method: &str) -> Result<(), ControlError> {
    let Val::Obj(map) = params else {
        return Err(ControlError::new(
            "refusal.malformed",
            format!("{method} params must be an object"),
        ));
    };
    for key in map.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(ControlError::new(
                "refusal.malformed",
                format!("{method} does not accept params.{key}"),
            ));
        }
    }
    Ok(())
}

/// The shared required-string read (never defaulted).
fn required(params: &Val, key: &str, method: &str) -> Result<String, ControlError> {
    params
        .get(key)
        .and_then(Val::as_str)
        .map(str::to_string)
        .ok_or_else(|| {
            ControlError::new(
                "refusal.malformed",
                format!("{method} requires params.{key}"),
            )
        })
}

/// Parse and shape-validate `run.pause` params. A missing, malformed or
/// foreign-target identity refuses before any state is read.
pub fn parse_pause_params(params: &Val) -> Result<PauseParams, ControlError> {
    only_keys(
        params,
        &["idempotency_key", "instance_id", "reason"],
        "run.pause",
    )?;
    let idempotency_key = required(params, "idempotency_key", "run.pause")?;
    if !formats::is_idempotency_key(&idempotency_key) {
        return Err(ControlError::new(
            "refusal.malformed",
            "run.pause params.idempotency_key must be `ik_` + 8-64 of [a-z0-9-]",
        ));
    }
    let instance_id = required(params, "instance_id", "run.pause")?;
    if !formats::is_run_id(&instance_id) {
        return Err(ControlError::new(
            codes::TARGET,
            format!(
                "run.pause addresses exactly ONE run (`run-` + 16 hex); {instance_id:?} is not a \
                 run identity (a lane id, a submission id or free text never addresses a run)"
            ),
        ));
    }
    let reason = required(params, "reason", "run.pause")?;
    if reason.is_empty() || reason.len() > REASON_MAX || reason.chars().any(char::is_control) {
        return Err(ControlError::new(
            "refusal.malformed",
            format!("run.pause params.reason must be 1-{REASON_MAX} printable characters"),
        ));
    }
    Ok(PauseParams {
        idempotency_key,
        instance_id,
        reason,
    })
}

/// Parse and shape-validate `run.resume` params.
pub fn parse_resume_params(params: &Val) -> Result<ResumeParams, ControlError> {
    only_keys(
        params,
        &["idempotency_key", "instance_id", "digest"],
        "run.resume",
    )?;
    let idempotency_key = required(params, "idempotency_key", "run.resume")?;
    if !formats::is_idempotency_key(&idempotency_key) {
        return Err(ControlError::new(
            "refusal.malformed",
            "run.resume params.idempotency_key must be `ik_` + 8-64 of [a-z0-9-]",
        ));
    }
    let instance_id = required(params, "instance_id", "run.resume")?;
    if !formats::is_run_id(&instance_id) {
        return Err(ControlError::new(
            codes::TARGET,
            format!(
                "run.resume addresses exactly ONE run (`run-` + 16 hex); {instance_id:?} is not a \
                 run identity"
            ),
        ));
    }
    let digest = required(params, "digest", "run.resume")?;
    if !formats::is_hex64(&digest) {
        return Err(ControlError::new(
            "refusal.malformed",
            "run.resume params.digest must be the 64-hex engine-minted resume digest",
        ));
    }
    Ok(ResumeParams {
        idempotency_key,
        instance_id,
        digest,
    })
}

/// Parse and shape-validate `run.retry` params.
pub fn parse_retry_params(params: &Val) -> Result<RetryParams, ControlError> {
    only_keys(
        params,
        &["idempotency_key", "instance_id", "step"],
        "run.retry",
    )?;
    let idempotency_key = required(params, "idempotency_key", "run.retry")?;
    if !formats::is_idempotency_key(&idempotency_key) {
        return Err(ControlError::new(
            "refusal.malformed",
            "run.retry params.idempotency_key must be `ik_` + 8-64 of [a-z0-9-]",
        ));
    }
    let instance_id = required(params, "instance_id", "run.retry")?;
    if !formats::is_run_id(&instance_id) {
        return Err(ControlError::new(
            codes::TARGET,
            format!(
                "run.retry addresses exactly ONE run (`run-` + 16 hex); {instance_id:?} is not a \
                 run identity"
            ),
        ));
    }
    let step = required(params, "step", "run.retry")?;
    if !formats::is_slug(&step) {
        return Err(ControlError::new(
            "refusal.malformed",
            "run.retry params.step must be a plan step id (slug)",
        ));
    }
    Ok(RetryParams {
        idempotency_key,
        instance_id,
        step,
    })
}

/// Parse and shape-validate `run.release` params (issue #146). A malformed,
/// missing or foreign-target identity refuses before any state is read, and
/// the closed key set keeps every dispatch-capable input out of this path.
pub fn parse_release_params(params: &Val) -> Result<ReleaseParams, ControlError> {
    only_keys(
        params,
        &["idempotency_key", "instance_id", "reason"],
        "run.release",
    )?;
    let idempotency_key = required(params, "idempotency_key", "run.release")?;
    if !formats::is_idempotency_key(&idempotency_key) {
        return Err(ControlError::new(
            "refusal.malformed",
            "run.release params.idempotency_key must be `ik_` + 8-64 of [a-z0-9-]",
        ));
    }
    let instance_id = required(params, "instance_id", "run.release")?;
    if !formats::is_run_id(&instance_id) {
        return Err(ControlError::new(
            codes::TARGET,
            format!(
                "run.release addresses exactly ONE run (`run-` + 16 hex); {instance_id:?} is not a \
                 run identity (a lane id, a submission id or free text never addresses a run)"
            ),
        ));
    }
    let reason = required(params, "reason", "run.release")?;
    if reason.is_empty() || reason.len() > REASON_MAX || reason.chars().any(char::is_control) {
        return Err(ControlError::new(
            "refusal.malformed",
            format!("run.release params.reason must be 1-{REASON_MAX} printable characters"),
        ));
    }
    Ok(ReleaseParams {
        idempotency_key,
        instance_id,
        reason,
    })
}

/// Parse a recorder-attributed artifact resolution. Its closed evidence is
/// deliberately data-only: no argv, prompt, topology, grant, or effect params
/// can ride this path and accidentally re-execute work.
pub fn parse_resolution_params(params: &Val) -> Result<ResolveParams, ControlError> {
    only_keys(
        params,
        &[
            "idempotency_key",
            "instance_id",
            "step",
            "recorder",
            "evidence",
        ],
        "run.resolve",
    )?;
    let idempotency_key = required(params, "idempotency_key", "run.resolve")?;
    if !formats::is_idempotency_key(&idempotency_key) {
        return Err(ControlError::new(
            "refusal.malformed",
            "run.resolve params.idempotency_key must be `ik_` + 8-64 of [a-z0-9-]",
        ));
    }
    let instance_id = required(params, "instance_id", "run.resolve")?;
    if !formats::is_run_id(&instance_id) {
        return Err(ControlError::new(
            codes::TARGET,
            "run.resolve addresses exactly ONE run (`run-` + 16 hex)",
        ));
    }
    let step = required(params, "step", "run.resolve")?;
    if !formats::is_slug(&step) {
        return Err(ControlError::new(
            "refusal.malformed",
            "run.resolve params.step must be a committed plan step id (slug)",
        ));
    }
    let recorder = required(params, "recorder", "run.resolve")?;
    if recorder.is_empty() || recorder.len() > 128 || recorder.chars().any(char::is_control) {
        return Err(ControlError::new(
            codes::RESOLUTION_EVIDENCE,
            "run.resolve recorder must be 1-128 printable characters",
        ));
    }
    let evidence = params.get("evidence").cloned().ok_or_else(|| {
        ControlError::new(
            codes::RESOLUTION_EVIDENCE,
            "run.resolve requires params.evidence",
        )
    })?;
    only_keys(
        &evidence,
        &["feature_head", "branch", "pull_request", "checks"],
        "run.resolve evidence",
    )
    .map_err(|err| ControlError::new(codes::RESOLUTION_EVIDENCE, err.message))?;
    let feature_head = required(&evidence, "feature_head", "run.resolve evidence")
        .map_err(|err| ControlError::new(codes::RESOLUTION_EVIDENCE, err.message))?;
    if !formats::is_hex40(&feature_head) {
        return Err(ControlError::new(
            codes::RESOLUTION_EVIDENCE,
            "run.resolve evidence.feature_head must be exact 40-hex",
        ));
    }
    let branch = required(&evidence, "branch", "run.resolve evidence")
        .map_err(|err| ControlError::new(codes::RESOLUTION_EVIDENCE, err.message))?;
    if !formats::is_slug(&branch) {
        return Err(ControlError::new(
            codes::RESOLUTION_EVIDENCE,
            "run.resolve evidence.branch must be a feature-branch slug",
        ));
    }
    let pull_request = evidence.get("pull_request").ok_or_else(|| {
        ControlError::new(
            codes::RESOLUTION_EVIDENCE,
            "run.resolve evidence requires pull_request {repository, number}",
        )
    })?;
    only_keys(pull_request, &["repository", "number"], "pull_request")
        .map_err(|err| ControlError::new(codes::RESOLUTION_EVIDENCE, err.message))?;
    let repository = required(pull_request, "repository", "pull_request")
        .map_err(|err| ControlError::new(codes::RESOLUTION_EVIDENCE, err.message))?;
    let number = pull_request.get("number").and_then(Val::as_int);
    if !formats::is_repository_identity(&repository) || !matches!(number, Some(value) if value > 0)
    {
        return Err(ControlError::new(
            codes::RESOLUTION_EVIDENCE,
            "run.resolve evidence.pull_request requires owner/name repository and positive number",
        ));
    }
    let checks = evidence
        .get("checks")
        .and_then(Val::as_array)
        .ok_or_else(|| {
            ControlError::new(
                codes::RESOLUTION_EVIDENCE,
                "run.resolve evidence.checks must be a non-empty named-check list",
            )
        })?;
    if checks.is_empty() {
        return Err(ControlError::new(
            codes::RESOLUTION_EVIDENCE,
            "run.resolve evidence.checks must be non-empty",
        ));
    }
    for check in checks {
        only_keys(check, &["name", "status"], "resolution check")
            .map_err(|err| ControlError::new(codes::RESOLUTION_EVIDENCE, err.message))?;
        let name = required(check, "name", "resolution check")
            .map_err(|err| ControlError::new(codes::RESOLUTION_EVIDENCE, err.message))?;
        let status = required(check, "status", "resolution check")
            .map_err(|err| ControlError::new(codes::RESOLUTION_EVIDENCE, err.message))?;
        if name.is_empty()
            || name.len() > 128
            || name.chars().any(char::is_control)
            || !matches!(status.as_str(), "passed" | "failed" | "pending")
        {
            return Err(ControlError::new(
                codes::RESOLUTION_EVIDENCE,
                "resolution checks require a bounded printable name and passed|failed|pending status",
            ));
        }
    }
    Ok(ResolveParams {
        idempotency_key,
        instance_id,
        step,
        recorder,
        evidence,
    })
}

/// Parse and shape-validate `run.dispatch` params (issue #92).
pub fn parse_dispatch_params(params: &Val) -> Result<DispatchParams, ControlError> {
    only_keys(
        params,
        &[
            "idempotency_key",
            "instance_id",
            "step",
            "params",
            "topology",
            "admission",
        ],
        "run.dispatch",
    )?;
    let idempotency_key = required(params, "idempotency_key", "run.dispatch")?;
    if !formats::is_idempotency_key(&idempotency_key) {
        return Err(ControlError::new(
            "refusal.malformed",
            "run.dispatch params.idempotency_key must be `ik_` + 8-64 of [a-z0-9-]",
        ));
    }
    let instance_id = required(params, "instance_id", "run.dispatch")?;
    if !formats::is_run_id(&instance_id) {
        return Err(ControlError::new(
            codes::TARGET,
            format!(
                "run.dispatch addresses exactly ONE run (`run-` + 16 hex); {instance_id:?} is not \
                 a run identity"
            ),
        ));
    }
    let step = required(params, "step", "run.dispatch")?;
    if !formats::is_slug(&step) {
        return Err(ControlError::new(
            "refusal.malformed",
            "run.dispatch params.step must be a committed plan step id (slug)",
        ));
    }
    let step_params = match params.get("params") {
        None | Some(Val::Null) => None,
        Some(inputs @ Val::Obj(map)) if map.keys().all(|key| formats::is_step_param_name(key)) => {
            Some(inputs.clone())
        }
        Some(other) => {
            return Err(ControlError::new(
                "refusal.malformed",
                format!(
                    "run.dispatch params.params must be an object of step inputs, got {}",
                    other.type_name()
                ),
            ));
        }
    };
    let context = |name: &str| match params.get(name) {
        None | Some(Val::Null) => Ok(None),
        Some(value @ Val::Obj(_)) => Ok(Some(value.clone())),
        _ => Err(ControlError::new(
            "refusal.malformed",
            format!("run.dispatch {name} must be an object"),
        )),
    };
    Ok(DispatchParams {
        idempotency_key,
        instance_id,
        step,
        step_params,
        topology: context("topology")?,
        admission: context("admission")?,
    })
}

/// The canonical `run.pause` params document.
pub fn pause_params(key: &str, instance_id: &str, reason: &str) -> Val {
    object(vec![
        ("idempotency_key", string(key)),
        ("instance_id", string(instance_id)),
        ("reason", string(reason)),
    ])
}

/// The canonical `run.resume` params document.
pub fn resume_params(key: &str, instance_id: &str, digest: &str) -> Val {
    object(vec![
        ("idempotency_key", string(key)),
        ("instance_id", string(instance_id)),
        ("digest", string(digest)),
    ])
}

/// The canonical `run.retry` params document.
pub fn retry_params(key: &str, instance_id: &str, step: &str) -> Val {
    object(vec![
        ("idempotency_key", string(key)),
        ("instance_id", string(instance_id)),
        ("step", string(step)),
    ])
}

/// The canonical `run.release` params document (issue #146).
pub fn release_params(key: &str, instance_id: &str, reason: &str) -> Val {
    object(vec![
        ("idempotency_key", string(key)),
        ("instance_id", string(instance_id)),
        ("reason", string(reason)),
    ])
}

/// The canonical `run.resolve` params document. Evidence is data, never an
/// effect request or a set of replacement step params.
pub fn resolution_params(
    key: &str,
    instance_id: &str,
    step: &str,
    recorder: &str,
    evidence: Val,
) -> Val {
    object(vec![
        ("idempotency_key", string(key)),
        ("instance_id", string(instance_id)),
        ("step", string(step)),
        ("recorder", string(recorder)),
        ("evidence", evidence),
    ])
}

/// The canonical `run.dispatch` params document: the run, the step and the
/// operator's step inputs (omitted when the committed params are dispatched
/// as reviewed).
pub fn dispatch_params(key: &str, instance_id: &str, step: &str, step_params: Option<Val>) -> Val {
    let mut fields = vec![
        ("idempotency_key", string(key)),
        ("instance_id", string(instance_id)),
        ("step", string(step)),
    ];
    if let Some(inputs) = step_params {
        fields.push(("params", inputs));
    }
    object(fields)
}

/// The canonical `run.status` params document.
pub fn status_params(instance_id: &str) -> Val {
    object(vec![("instance_id", string(instance_id))])
}

/// Validate one exact run-target read (`run.status`).
pub fn parse_status_target(params: &Val) -> Result<String, ControlError> {
    only_keys(params, &["instance_id"], "run.status")?;
    let instance_id = required(params, "instance_id", "run.status")?;
    if !formats::is_run_id(&instance_id) {
        return Err(ControlError::new(
            codes::TARGET,
            format!(
                "run.status addresses exactly ONE run (`run-` + 16 hex); {instance_id:?} is not a \
                 run identity"
            ),
        ));
    }
    Ok(instance_id)
}

/// The deterministic retry id: `rt_` + first 16 hex of the sha256 over the
/// domain-separated (run, step, attempt) triple — a retry addresses exactly
/// one bounded attempt of one (run, step), so a replay and a restart can
/// never invent a second id for one authorization.
pub fn retry_id(instance_id: &str, step: &str, attempt: i64) -> String {
    let preimage = format!("{RUN_RETRY_SCHEMA}|{instance_id}|{step}|{attempt}");
    format!("rt_{}", &sha256_hex(preimage.as_bytes())[..16])
}

/// The run's next unachieved step: the first spine step when no node has
/// been achieved yet, otherwise the step after the achieved node. `None`
/// when the frontier cannot be established (an achieved node outside the
/// bound spine, or an exhausted spine).
pub fn next_step_of(spine: &[String], current_node: &str) -> Option<String> {
    if current_node.is_empty() {
        return spine.first().cloned();
    }
    let index = spine.iter().position(|step| step == current_node)?;
    spine.get(index + 1).cloned()
}

/// The retry/continuation frontier of one run. Once an attempt ledger exists,
/// it is authoritative: the first bound-spine step whose LATEST recorded
/// attempt is not `succeeded` (including an unattempted gap) is the frontier.
/// A stale `current_node` can therefore neither hide a diagnosed step nor
/// skip an unattempted one. `current_node` is only the legacy fallback before
/// the run has any attempt record.
pub fn frontier_of(
    spine: &[String],
    attempts: &[(String, String)],
    current_node: &str,
) -> Option<String> {
    if attempts.is_empty() {
        return next_step_of(spine, current_node);
    }
    spine
        .iter()
        .find(|step| {
            attempts
                .iter()
                .rfind(|(id, _)| id == *step)
                .is_none_or(|(_, status)| status != "succeeded")
        })
        .cloned()
}

/// The position of one step in the bound spine (`None` when it is not a
/// spine step).
pub fn step_index_of(spine: &[String], step: &str) -> Option<usize> {
    spine.iter().position(|candidate| candidate == step)
}

/// The rendered control state of one run: `paused` once the safe boundary
/// has been reached, `pause_requested` while the request is durable but
/// in-flight work still runs, `active` otherwise.
pub fn control_state(run: &InstanceRow) -> &'static str {
    if run.paused {
        "paused"
    } else if run.pause_requested {
        "pause_requested"
    } else {
        "active"
    }
}

/// The scope block every run-control document carries: what the control
/// addresses and what it provably does NOT affect.
fn scope_block(instance_id: &str) -> Val {
    object(vec![
        ("level", string("run")),
        ("run", string(instance_id)),
        ("fleet_effect", string("none")),
        ("lane_effect", string("none")),
    ])
}

/// The run identity block of one control document.
fn run_block(run: &InstanceRow) -> Val {
    object(vec![
        ("instance_id", string(&run.instance_id)),
        ("repository", string(&run.repository)),
        ("issue_number", integer(run.issue_number)),
        ("status", string(&run.status)),
        ("state_epoch", integer(run.state_epoch)),
        ("grant_id", string(&run.grant_id)),
    ])
}

/// Render the `hf-run-control/v1` projection of one run. `in_flight_step`
/// is the step of the still-executing dispatch (probed live) and
/// `resume_digest` is the pause authorization (printed so the operator can
/// hold it across a restart; `null` when the run carries no pause).
pub fn control_doc(
    run: &InstanceRow,
    in_flight_step: Option<&str>,
    resume_digest: Option<&str>,
) -> Val {
    let state = control_state(run);
    let reached = run.paused || (run.pause_requested && in_flight_step.is_none());
    object(vec![
        ("schema", string(RUN_CONTROL_SCHEMA)),
        ("run", run_block(run)),
        (
            "control",
            object(vec![
                ("state", string(state)),
                ("pause_requested", bool_(run.pause_requested)),
                ("paused", bool_(run.paused)),
                ("reason", string(&run.pause_reason)),
                ("requested_at", string(&run.pause_requested_at)),
                (
                    "resume_digest",
                    match resume_digest {
                        Some(digest) => string(digest),
                        None => null(),
                    },
                ),
            ]),
        ),
        (
            "boundary",
            object(vec![
                ("reached", bool_(reached)),
                (
                    "in_flight_step",
                    match in_flight_step {
                        Some(step) => string(step),
                        None => null(),
                    },
                ),
            ]),
        ),
        ("scope", scope_block(&run.instance_id)),
        ("statement", string(CONTROL_STATEMENT)),
    ])
}

/// The deterministic release id: `rl_` + first 16 hex of the sha256 over
/// the domain-separated (run, claim key) pair — one release claim produces
/// exactly one release record, so a replay and a restart can never invent a
/// second id for one release.
pub fn release_id(instance_id: &str, key: &str) -> String {
    let preimage = format!("{RUN_RELEASE_SCHEMA}|{instance_id}|{key}");
    format!("rl_{}", &sha256_hex(preimage.as_bytes())[..16])
}

/// Render the `hf-run-release/v1` projection of one committed release
/// (issue #146): the released run (now terminal), the operator reason, what
/// the release freed, and the authorization window the run held when it was
/// released (`usable:false` when that window was missing, revoked or already
/// expired — the record states the window, it never presents or reuses it).
pub fn release_doc(outcome: &RunReleaseOutcome, reason: &str, released_at: &str, key: &str) -> Val {
    let run = &outcome.run;
    object(vec![
        ("schema", string(RUN_RELEASE_SCHEMA)),
        ("release_id", string(&release_id(&run.instance_id, key))),
        ("run", run_block(run)),
        (
            "release",
            object(vec![
                ("reason", string(reason)),
                ("released_at", string(released_at)),
                ("status", string(&run.status)),
                (
                    "ownership",
                    string(if outcome.ownership_freed {
                        "freed"
                    } else {
                        "absent"
                    }),
                ),
                (
                    "authorization",
                    match &outcome.grant {
                        Some(grant) => grant_window_block(grant, outcome.grant_usable),
                        None => object(vec![
                            ("grant_id", string(&run.grant_id)),
                            ("status", string("missing")),
                            ("expires_at", null()),
                            ("usable", bool_(false)),
                        ]),
                    },
                ),
            ]),
        ),
        ("scope", scope_block(&run.instance_id)),
        ("statement", string(RELEASE_STATEMENT)),
    ])
}

/// The authorization window block of one release document: the run's own
/// grant row at release time and whether that window was still usable.
fn grant_window_block(grant: &GrantRow, usable: bool) -> Val {
    object(vec![
        ("grant_id", string(&grant.grant_id)),
        ("status", string(&grant.status)),
        ("expires_at", string(&grant.expires_at)),
        ("usable", bool_(usable)),
    ])
}

/// Render the `hf-run-retry/v1` projection of one recorded bounded retry.
pub fn retry_doc(
    run: &InstanceRow,
    retry: &RunRetryRow,
    spine: &[String],
    step: &str,
    next_step: Option<&str>,
) -> Val {
    object(vec![
        ("schema", string(RUN_RETRY_SCHEMA)),
        ("run", run_block(run)),
        (
            "retry",
            object(vec![
                ("retry_id", string(&retry.retry_id)),
                ("step_id", string(&retry.step_id)),
                ("attempt", integer(retry.attempt)),
                ("bound", integer(RUN_RETRY_MAX)),
                ("status", string(&retry.status_word())),
                ("authorized_at", string(&retry.authorized_at)),
                ("consumed_at", string(&retry.consumed_at)),
                ("consumed_key", string(&retry.consumed_key)),
            ]),
        ),
        (
            "spine",
            object(vec![
                (
                    "steps",
                    Val::Arr(spine.iter().map(|step| string(step)).collect()),
                ),
                (
                    "step_index",
                    integer(step_index_of(spine, step).unwrap_or(0) as i64),
                ),
                (
                    "next_step",
                    match next_step {
                        Some(step) => string(step),
                        None => null(),
                    },
                ),
            ]),
        ),
        ("scope", scope_block(&run.instance_id)),
        ("statement", string(RETRY_STATEMENT)),
    ])
}

impl RunRetryRow {
    /// `authorized` while unconsumed, `consumed` after its single use.
    fn status_word(&self) -> String {
        if self.consumed_at.is_empty() {
            "authorized".to_string()
        } else {
            "consumed".to_string()
        }
    }
}

/// Render a successful evidence-based resolution of one diagnosed prompt.
/// The record advances the ledger without issuing the prompt effect again.
#[allow(clippy::too_many_arguments)]
pub fn resolution_doc(
    run: &InstanceRow,
    step: &str,
    kind: &str,
    prior_status: &str,
    recorder: &str,
    evidence: &Val,
    recorded_at: &str,
    key: &str,
) -> Val {
    let digest =
        sha256_hex(format!("{RUN_RESOLUTION_SCHEMA}|{}|{step}|{key}", run.instance_id).as_bytes());
    object(vec![
        ("schema", string(RUN_RESOLUTION_SCHEMA)),
        ("resolution_id", string(&format!("rs_{}", &digest[..16]))),
        ("run", run_block(run)),
        (
            "resolution",
            object(vec![
                ("step_id", string(step)),
                ("kind", string(kind)),
                ("prior_status", string(prior_status)),
                ("status", string("succeeded")),
                ("recorder", string(recorder)),
                ("recorded_at", string(recorded_at)),
                ("evidence", evidence.clone()),
                ("effect_reexecuted", bool_(false)),
            ]),
        ),
        ("scope", scope_block(&run.instance_id)),
        ("statement", string(RESOLUTION_STATEMENT)),
    ])
}

/// Render the `hf-run-dispatch/v1` projection of one supported step dispatch
/// (issue #92): the addressed run/step, the exact step params the dispatch
/// presented (the operator's inputs over the committed ones), the recorded
/// apply outcome and the bounded authorization this dispatch consumed.
pub fn dispatch_doc(
    run: &InstanceRow,
    spine: &[String],
    step: &str,
    kind: &str,
    params: Option<&Val>,
    outcome: &Val,
    retry: Option<&RunRetryRow>,
) -> Val {
    object(vec![
        ("schema", string(RUN_DISPATCH_SCHEMA)),
        ("run", run_block(run)),
        (
            "step",
            object(vec![
                ("step_id", string(step)),
                ("kind", string(kind)),
                (
                    "params",
                    match params {
                        Some(params) => params.clone(),
                        None => null(),
                    },
                ),
            ]),
        ),
        ("dispatch", outcome.clone()),
        (
            "retry",
            match retry {
                Some(retry) => object(vec![
                    ("retry_id", string(&retry.retry_id)),
                    ("attempt", integer(retry.attempt)),
                    ("bound", integer(RUN_RETRY_MAX)),
                    ("status", string(&retry.status_word())),
                    ("consumed_at", string(&retry.consumed_at)),
                    ("consumed_key", string(&retry.consumed_key)),
                ]),
                None => null(),
            },
        ),
        (
            "spine",
            object(vec![
                (
                    "steps",
                    Val::Arr(spine.iter().map(|step| string(step)).collect()),
                ),
                (
                    "step_index",
                    integer(step_index_of(spine, step).unwrap_or(0) as i64),
                ),
            ]),
        ),
        ("scope", scope_block(&run.instance_id)),
        ("statement", string(DISPATCH_STATEMENT)),
    ])
}

/// The human rendering of one control document (a rendering of the same
/// data, never a second contradicting contract).
pub fn render_human(document: &Val) -> String {
    let run = document.get("run").cloned().unwrap_or_else(null);
    let text = |value: &Val, key: &str| -> String {
        value
            .get(key)
            .and_then(Val::as_str)
            .unwrap_or("unknown")
            .to_string()
    };
    let number =
        |value: &Val, key: &str| -> i64 { value.get(key).and_then(Val::as_int).unwrap_or(0) };
    let flag = |value: &Val, key: &str| -> String {
        match value.get(key).and_then(Val::as_bool) {
            Some(value) => value.to_string(),
            None => "unknown".to_string(),
        }
    };
    let schema = text(document, "schema");
    if schema == RUN_DISPATCH_SCHEMA {
        let step = document.get("step").cloned().unwrap_or_else(null);
        let dispatch = document.get("dispatch").cloned().unwrap_or_else(null);
        let retry = document.get("retry").cloned().unwrap_or_else(null);
        let outcome = if text(&dispatch, "status") == "succeeded" {
            "succeeded".to_string()
        } else {
            format!(
                "{} ({})",
                text(&dispatch, "status"),
                text(&dispatch.get("error").cloned().unwrap_or_else(null), "code")
            )
        };
        let authorization = if retry.is_null() {
            "none consumed (no unconsumed authorization was required)".to_string()
        } else {
            format!(
                "{} {} consumed by {}",
                text(&retry, "status"),
                text(&retry, "retry_id"),
                text(&retry, "consumed_key")
            )
        };
        return format!(
            "run {} dispatch: step {} ({})\nstep params: {}\ndispatch: {}\nauthorization: {}\nscope: run {} only; no fleet-level or lane effect\n",
            text(&run, "instance_id"),
            text(&step, "step_id"),
            text(&step, "kind"),
            crate::canonical::canonical_text(&step.get("params").cloned().unwrap_or_else(null)),
            outcome,
            authorization,
            text(&run, "instance_id"),
        );
    }
    if schema == RUN_RELEASE_SCHEMA {
        let release = document.get("release").cloned().unwrap_or_else(null);
        let authorization = release.get("authorization").cloned().unwrap_or_else(null);
        let window = if authorization.is_null() {
            "none recorded".to_string()
        } else {
            format!(
                "{} ({}, expires {}, usable {})",
                text(&authorization, "grant_id"),
                text(&authorization, "status"),
                text(&authorization, "expires_at"),
                flag(&authorization, "usable")
            )
        };
        return format!(
            "run {} released: status {}, ownership {}, {} at {}\nreason: {}\nauthorization window at release: {}\nscope: run {} only; no fleet-level or lane effect\n",
            text(&run, "instance_id"),
            text(&release, "status"),
            text(&release, "ownership"),
            text(document, "release_id"),
            text(&release, "released_at"),
            text(&release, "reason"),
            window,
            text(&run, "instance_id"),
        );
    }
    if schema == RUN_RETRY_SCHEMA {
        let retry = document.get("retry").cloned().unwrap_or_else(null);
        let spine = document.get("spine").cloned().unwrap_or_else(null);
        return format!(
            "run {} retry: step {} attempt {}/{} ({})\nnext step: {}\nscope: run {} only; no fleet-level or lane effect\n",
            text(&run, "instance_id"),
            text(&retry, "step_id"),
            number(&retry, "attempt"),
            number(&retry, "bound"),
            text(&retry, "status"),
            text(&spine, "next_step"),
            text(&run, "instance_id"),
        );
    }
    let control = document.get("control").cloned().unwrap_or_else(null);
    let boundary = document.get("boundary").cloned().unwrap_or_else(null);
    format!(
        "run {} control: {} (status {}, issue {})\npause requested: {} at {}; reason: {}\nboundary reached: {}; in-flight step: {}\nscope: run {} only; no fleet-level or lane effect\n",
        text(&run, "instance_id"),
        text(&control, "state"),
        text(&run, "status"),
        number(&run, "issue_number"),
        text(&control, "pause_requested"),
        text(&control, "requested_at"),
        text(&control, "reason"),
        text(&boundary, "reached"),
        text(&boundary, "in_flight_step"),
        text(&run, "instance_id"),
    )
}
