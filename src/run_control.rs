//! Run-scoped controls (issue #86): safe-boundary pause, resume and
//! bounded retry for ONE queue run.
//!
//! A *run* is one durable `instances` row (`run-` + 16 hex) — the identity
//! the merged queue executor (#85) commits for every admitted selected
//! issue. This module is the typed control surface over those rows:
//! parameter parsing, the closed refusal vocabulary, the deterministic
//! projections (`hf-run-control/v1` / `hf-run-retry/v1`) and the pure
//! diagnosis helpers. The daemon owns journaling and the state
//! transactions (`State::request_run_pause`, `State::resume_run`,
//! `State::record_run_retry`, `State::claim_run_retry`).
//!
//! ## Scope matrix (run vs fleet vs lane)
//!
//! | level | identity | control surface | effect of a run control |
//! | --- | --- | --- | --- |
//! | run | one `run-` instance id | `run.pause` / `run.resume` / `run.retry` / `run.dispatch` / `run.status` | exactly this run: stop admitting new steps (pause), lift this run's pause (resume), authorize one bounded re-dispatch of one diagnosed step (retry, authorization only), dispatch ONE committed-spine step with the operator's own step inputs (dispatch, derived from the run's committed submission), read the control state back (status) |
//! | fleet | the whole run population | NONE — no `fleet.*` method exists in the closed RPC set | a fleet-level hold is an operator policy expressed as the set of paused runs: every `run.resume` is fenced on the exact instance id, so it never lifts another run's pause and never re-enables anything fleet-wide |
//! | lane | one handoff lane generation (replacement/checkpoint records) | `lane.*` only | run controls never touch lane records; a run control naming a non-run identity refuses typed |
//!
//! Nothing on this surface kills a process, cleans up work, mutates Git,
//! clears a repository or fleet-level hold, or bypasses a gate: a pause
//! stops admitting NEW work and preserves in-flight dirty work, and a
//! retry authorizes exactly ONE bounded step re-dispatch.

use crate::canonical::sha256_hex;
use crate::formats;
use crate::state::{InstanceRow, RUN_RETRY_MAX, RunRetryRow};
use crate::value::{Val, bool_, integer, null, object, string};

/// The run-control document schema id (module-local like the #84 preview
/// and the #85 submission: deliberately outside the closed `hf-*` family
/// set).
pub const RUN_CONTROL_SCHEMA: &str = "hf-run-control/v1";

/// The bounded-retry document schema id (module-local).
pub const RUN_RETRY_SCHEMA: &str = "hf-run-retry/v1";

/// The supported step-dispatch document schema id (module-local).
pub const RUN_DISPATCH_SCHEMA: &str = "hf-run-dispatch/v1";

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
pub const DISPATCH_STATEMENT: &str = "step dispatch only: exactly ONE step of this run is dispatched, derived from the run's committed submission spine and the run's own recorded dispatch context — the caller presents only that step's own inputs (merged over the committed params, never a stale reconstruction); a request that is not well-formed enough to be attempted refuses typed BEFORE any bounded retry authorization is consumed, an unconsumed authorization of a diagnosed step is consumed by exactly this dispatch (single use), and nothing else is dispatched, spawned, resumed, cleaned up or widened";

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
    /// One unconsumed retry authorization already exists for this step.
    pub const RETRY_PENDING: &str = "refusal.run.retry_pending";
    /// All bounded retries for this step are used.
    pub const RETRY_BOUND: &str = "refusal.run.retry_bound";
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

/// Parse and shape-validate `run.dispatch` params (issue #92).
pub fn parse_dispatch_params(params: &Val) -> Result<DispatchParams, ControlError> {
    only_keys(
        params,
        &["idempotency_key", "instance_id", "step", "params"],
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
        Some(inputs @ Val::Obj(_)) => Some(inputs.clone()),
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
    Ok(DispatchParams {
        idempotency_key,
        instance_id,
        step,
        step_params,
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

/// The retry frontier of one run, derived from the RECORDED attempt ledger
/// (issue #92 F3): the first bound-spine step whose latest recorded attempt
/// is not `succeeded` — an `ambiguous` (timed-out) or `failed` attempt IS
/// the frontier, which is exactly the step `run.retry` must be able to
/// address. The node-derived frontier ([`next_step_of`]) is kept as the
/// other input and the FURTHER of the two wins, so:
/// - a stale ledger can never rewind the frontier below the recorded node;
/// - a stale node can never hide a diagnosed step the ledger knows about.
///
/// `None` only when neither input establishes one (empty spine).
///
/// Fail-closed by construction: this only decides WHICH step is the
/// frontier; every eligibility check (diagnosis, bound, epoch, grant,
/// consumption) stays where it was.
pub fn frontier_of(
    spine: &[String],
    attempts: &[(String, String)],
    current_node: &str,
) -> Option<String> {
    let ledger = spine.iter().position(|step| {
        let latest = attempts
            .iter()
            .rfind(|(id, _)| id == step)
            .map(|(_, status)| status.as_str());
        latest != Some("succeeded")
    });
    let node = next_step_of(spine, current_node).and_then(|step| step_index_of(spine, &step));
    match (ledger, node) {
        (Some(ledger), Some(node)) => spine.get(ledger.max(node)).cloned(),
        (Some(ledger), None) => spine.get(ledger).cloned(),
        (None, Some(node)) => spine.get(node).cloned(),
        (None, None) => None,
    }
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
