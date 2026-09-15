//! Queue executor (issue #85): the daemon-owned durable submission path for
//! one approved queue preview.
//!
//! The #84 preview renders, for one explicitly selected issue set, a
//! deterministic effect-free document and a digest over exactly the bound
//! inputs. This module consumes that contract: [`parse_params`] validates
//! the presented submission material, [`presented_request`] rebuilds the
//! typed preview inputs from the bound document (so the digest can be
//! re-derived and re-confirmed), [`revalidate`] re-renders the preview
//! against live state and classifies every selected issue with its stable
//! per-item verdict (`admitted` / `waiting` / `refused`), and
//! [`submission_doc`] renders the durable readback from the committed rows.
//!
//! Ownership of the flow stays split: this module decides and renders; the
//! daemon journals the intent claim, and `State::submit_queue_run` commits
//! the submission, the membership items, the admitted runs and the unique
//! work-ownership rows in ONE transaction that re-verifies every
//! state-derived fact under the guard. Nothing here spawns a process, opens
//! a socket, or executes a workflow step: step execution stays with the
//! merged `apply` machinery, and an unsupported spine is refused and
//! labelled before anything is persisted.

use std::collections::{BTreeMap, BTreeSet};

use crate::canonical::sha256_hex;
use crate::config::{ProfileBinding, is_bare_token};
use crate::formats;
use crate::lifecycle::ConcurrencyCaps;
use crate::mutation::{code as mutation_code, is_expired, required_capability};
use crate::queue_preview::{
    Boundary, IssueId, PlannedStep, QueuePreview, QueueRequest, SelectedIssue, confirm, digest_of,
    holds as preview_holds, preview_queue,
};
use crate::state::{
    QueueAdvanceRow, QueueSubmissionItemRow, QueueSubmissionRow, State, SubmissionVerdict,
};
use crate::value::{Val, bool_, integer, null, object, string};

/// The submission document schema id (module-local, exactly like the #84
/// preview document: deliberately outside the closed `hf-*` family set).
pub const QUEUE_SUBMISSION_SCHEMA: &str = "hf-queue-submission/v1";

/// The closed per-item admission vocabulary (issue #85 AC3).
pub const ITEM_STATUSES: [&str; 3] = ["admitted", "waiting", "refused"];

/// Bound on presented per-issue grant bindings.
pub const GRANTS_MAX: usize = 64;

/// Bound on presented resume authorizations.
pub const RESUME_MAX: usize = 64;

/// Bound on one presented concurrency cap value.
pub const CAP_MAX: usize = 65_536;

/// The statement every submission document renders: what a committed
/// submission did and did NOT do. A submission admits runs; it never claims
/// a step executed.
pub const STATEMENT: &str = "the submission mutation only admits durable run records; when supervision is explicitly armed its separate driver may dispatch the run through the gated apply path, while a waiting item can be admitted later only by the ONE verified delivery that advances this queue cursor under the same admission and ownership checks; refused items are not running, and admission alone is not a completed implementation";

/// The queue-cursor advance vocabulary (issue #96): the durable continuation
/// from one verified delivery to the next eligible approved issue of the
/// SAME already-authorized submission. Holds reuse the admission vocabulary
/// (`refusal.admission.*`, `preview.*`, `submission.*`) verbatim, so one hold
/// language spans the preview, the submission and the advance.
pub mod advance {
    /// A required dependency is not part of the submission's selected set:
    /// this queue can never settle it, so the dependent stays held.
    pub const DEPENDENCY_UNRESOLVED: &str = "queue.dependency_unresolved";
    /// A required dependency is selected but its delivery is not verified
    /// yet: the dependent stays held — never dispatched and never marked
    /// done from an unmet dependency.
    pub const DEPENDENCY_UNSETTLED: &str = "queue.dependency_unsettled";
}

/// Submission-local stable codes (the `submission.*` namespace). Admission
/// holds reuse the #84 `preview.*` codes and the lifecycle
/// `refusal.admission.*` codes verbatim, so one hold vocabulary spans the
/// preview and the submission.
pub mod codes {
    /// The issue already has a live owner run; a duplicate submission never
    /// creates a second owner.
    pub const ALREADY_OWNED: &str = "submission.already_owned";
    /// The run is paused: paused fleets stay paused unless a separate
    /// explicit engine-minted resume authorization is presented.
    pub const PAUSED: &str = "submission.paused";
    /// The presented grant does not bind this issue/revision/scope.
    pub const GRANT: &str = "submission.grant";
    /// The presented step spine is empty: nothing executable can be admitted.
    pub const STEPS: &str = "submission.steps";
    /// A declared step requires a capability outside the reviewed boundary.
    pub const BOUNDARY: &str = "submission.boundary";
}

/// A typed submission error/refusal (fail closed; stable codes).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubmissionError {
    /// Stable dotted code (`usage.queue_submission.*`, `refusal.*`,
    /// `preview.*` or `submission.*`).
    pub code: &'static str,
    /// Bounded human message.
    pub message: String,
}

impl SubmissionError {
    fn new(code: &'static str, message: impl Into<String>) -> SubmissionError {
        SubmissionError {
            code,
            message: message.into(),
        }
    }
}

/// One presented per-issue grant binding: the issue reference text and the
/// grant id the operator bound it to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ItemGrant {
    /// Presented issue reference (`owner/name#123`, `#123` or `123`).
    pub id: String,
    /// Route grant id (`gr_` + 16 hex).
    pub grant_id: String,
}

/// One presented resume authorization for a paused run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResumeAuthorization {
    /// The paused run instance id.
    pub instance_id: String,
    /// The engine-minted resume digest (64-hex).
    pub digest: String,
}

/// The presented submission material, fully validated (shape only: every
/// durable fact is revalidated by [`revalidate`] and again inside the
/// submission transaction).
#[derive(Clone, Debug)]
pub struct SubmissionMaterial {
    /// The presented idempotency key (validated; the deterministic
    /// submission id derives from it and the digest).
    pub idempotency_key: String,
    /// The bound-input document (the #84 preview's `request` object).
    pub preview: Val,
    /// The reviewed `hf-profile-binding/v1` document.
    pub binding: Val,
    /// The approved preview digest (64-hex).
    pub digest: String,
    /// The approved state epoch.
    pub epoch: i64,
    /// The freshly observed profile-configuration revision (64-hex): the
    /// current one, compared against the bound revision at submit time.
    pub role_revision: String,
    /// Presented fan-out concurrency caps.
    pub caps: ConcurrencyCaps,
    /// Presented host availability; `None` = unknown.
    pub host_available: Option<bool>,
    /// Presented same-harness occupancy; `None` = unknown.
    pub harness_lanes: Option<i64>,
    /// Presented per-issue grant bindings.
    pub grants: Vec<ItemGrant>,
    /// Presented resume authorizations.
    pub resume: Vec<ResumeAuthorization>,
    /// The optional explicit supervision authorization (issue #95):
    /// `None` = supervision disabled for the admitted runs (the default).
    pub supervision: Option<crate::supervision::Authorization>,
}

/// Validate one presented `params.supervision` block and map its typed
/// refusal onto the submission vocabulary (the block is validated by the
/// supervision policy parser, never by a second copy of the rules).
fn parse_supervision(value: &Val) -> Result<crate::supervision::Authorization, SubmissionError> {
    crate::supervision::parse_authorization(value)
        .map_err(|err| SubmissionError::new(err.code, err.message))
}

/// The re-rendered preview plus the classified membership (issue #85 AC1).
#[derive(Clone, Debug)]
pub struct Revalidated {
    /// The rebuilt typed preview inputs.
    pub request: QueueRequest,
    /// The freshly re-rendered #84 preview (its digest must equal the
    /// presented one).
    pub preview: QueuePreview,
    /// The classified membership items, in the preview's order.
    pub items: Vec<PlannedItem>,
}

/// One classified membership item.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlannedItem {
    /// Canonical issue reference (`owner/name#123`).
    pub id: String,
    /// Stable work-item id (`wi_` + 16 hex).
    pub work_item: String,
    /// Issue number.
    pub issue_number: i64,
    /// Selected acceptance revision (40-hex).
    pub revision: String,
    /// The presented grant id bound to this issue, when one was presented.
    pub grant_id: Option<String>,
    /// The presented resume digest, when the item resumes a paused run.
    pub resume_digest: Option<String>,
    /// The classified verdict.
    pub verdict: SubmissionVerdict,
}

/// The deterministic submission id: `qs_` + first 16 hex of the sha256 over
/// the domain-separated (digest, idempotency key) pair. Deterministic so
/// restart reconciliation can look the committed row up from the claim's
/// request line without trusting anything else.
pub fn submission_id(digest: &str, idempotency_key: &str) -> String {
    let preimage = format!("{QUEUE_SUBMISSION_SCHEMA}|{digest}|{idempotency_key}");
    format!("qs_{}", &sha256_hex(preimage.as_bytes())[..16])
}

/// Parse and shape-validate the presented `queue.submit` params. Fail
/// closed: unknown keys, missing keys and malformed values are refused with
/// a typed code before any state is read.
pub fn parse_params(params: &Val) -> Result<SubmissionMaterial, SubmissionError> {
    let Val::Obj(map) = params else {
        return Err(SubmissionError::new(
            "usage.queue_submission.params",
            "the submission params must be an object",
        ));
    };
    const KEYS: [&str; 12] = [
        "idempotency_key",
        "digest",
        "epoch",
        "preview",
        "binding",
        "role_revision",
        "caps",
        "observations",
        "grants",
        "resume",
        "supervision",
        "dispatch",
    ];
    for key in map.keys() {
        if !KEYS.contains(&key.as_str()) {
            return Err(SubmissionError::new(
                "usage.queue_submission.params",
                format!("the submission params carry unknown key {key:?} (closed surface)"),
            ));
        }
    }
    let text = |key: &str| -> Result<String, SubmissionError> {
        match params.get(key).and_then(Val::as_str) {
            Some(value) if !value.is_empty() => Ok(value.to_string()),
            _ => Err(SubmissionError::new(
                "usage.queue_submission.params",
                format!("the submission params require {key} (non-empty string)"),
            )),
        }
    };
    let key = text("idempotency_key")?;
    if !formats::is_idempotency_key(&key) {
        return Err(SubmissionError::new(
            "usage.queue_submission.params",
            "idempotency_key must be an ik_ key (ik_ + 8-64 of [a-z0-9-])",
        ));
    }
    let digest = text("digest")?;
    if !formats::is_hex64(&digest) {
        return Err(SubmissionError::new(
            "usage.queue_submission.digest",
            "the approved digest must be the exact 64-hex preview digest",
        ));
    }
    let epoch = params
        .get("epoch")
        .and_then(Val::as_int)
        .filter(|epoch| *epoch >= 1)
        .ok_or_else(|| {
            SubmissionError::new(
                "usage.queue_submission.epoch",
                "the submission requires a positive integer epoch (the state epoch the approval \
                 was rendered against)",
            )
        })?;
    let role_revision = text("role_revision")?;
    if !formats::is_hex64(&role_revision) {
        return Err(SubmissionError::new(
            "usage.queue_submission.role_revision",
            "role_revision must be the 64-hex revision of the current profile configuration",
        ));
    }
    let preview = match params.get("preview") {
        Some(value @ Val::Obj(_)) => value.clone(),
        _ => {
            return Err(SubmissionError::new(
                "usage.queue_submission.preview",
                "the submission requires the bound-input preview document (object)",
            ));
        }
    };
    let binding = match params.get("binding") {
        Some(value @ Val::Obj(_)) => value.clone(),
        _ => {
            return Err(SubmissionError::new(
                "usage.queue_submission.binding",
                "the submission requires the reviewed profile-binding document (object)",
            ));
        }
    };
    let caps = parse_caps(params.get("caps"))?;
    let (host_available, harness_lanes) = parse_observations(params.get("observations"))?;
    let grants = parse_grants(params.get("grants"))?;
    let resume = parse_resume(params.get("resume"))?;
    // Issue #95: supervision is OPTIONAL and disabled by default. When a
    // block is presented it is validated here (closed shape, bounded
    // deadlines) and committed with the submission.
    let supervision = match params.get("supervision") {
        None | Some(Val::Null) => None,
        Some(value) => Some(parse_supervision(value)?),
    };
    if let Some(dispatch) = params.get("dispatch") {
        let valid = matches!(dispatch, Val::Obj(_))
            && matches!(dispatch.get("topology"), Some(Val::Obj(_)))
            && matches!(dispatch.get("admission"), Some(Val::Obj(_)));
        if !valid {
            return Err(SubmissionError::new(
                "usage.queue_submission.dispatch",
                "dispatch must carry topology and admission objects",
            ));
        }
    }
    Ok(SubmissionMaterial {
        idempotency_key: key,
        preview,
        binding,
        digest,
        epoch,
        role_revision,
        caps,
        host_available,
        harness_lanes,
        grants,
        resume,
        supervision,
    })
}

fn parse_caps(value: Option<&Val>) -> Result<ConcurrencyCaps, SubmissionError> {
    let Some(Val::Obj(_)) = value else {
        return Err(SubmissionError::new(
            "usage.queue_submission.caps",
            "the submission requires caps {global, repository, harness}",
        ));
    };
    let axis = |name: &str| -> Result<usize, SubmissionError> {
        match value
            .and_then(|caps| caps.get(name))
            .and_then(Val::as_int)
            .filter(|value| *value >= 0 && (*value as u128) <= CAP_MAX as u128)
        {
            Some(value) => Ok(value as usize),
            None => Err(SubmissionError::new(
                "usage.queue_submission.caps",
                format!("caps.{name} must be an integer in 0..={CAP_MAX}"),
            )),
        }
    };
    Ok(ConcurrencyCaps {
        global: axis("global")?,
        per_repository: axis("repository")?,
        per_harness: axis("harness")?,
    })
}

type Observations = (Option<bool>, Option<i64>);

fn parse_observations(value: Option<&Val>) -> Result<Observations, SubmissionError> {
    let Some(Val::Obj(_)) = value else {
        return Err(SubmissionError::new(
            "usage.queue_submission.observations",
            "the submission requires an observations object (host_available/harness_lanes may be \
             unknown, which is never readiness)",
        ));
    };
    let host_available = match value.and_then(|observations| observations.get("host_available")) {
        None | Some(Val::Null) => None,
        Some(Val::Bool(value)) => Some(*value),
        _ => {
            return Err(SubmissionError::new(
                "usage.queue_submission.observations",
                "observations.host_available must be a boolean or null (unknown)",
            ));
        }
    };
    let harness_lanes = match value.and_then(|observations| observations.get("harness_lanes")) {
        None | Some(Val::Null) => None,
        Some(Val::Int(value)) if *value >= 0 => Some(*value),
        _ => {
            return Err(SubmissionError::new(
                "usage.queue_submission.observations",
                "observations.harness_lanes must be a non-negative lane count or null \
                     (unknown)",
            ));
        }
    };
    Ok((host_available, harness_lanes))
}

fn parse_grants(value: Option<&Val>) -> Result<Vec<ItemGrant>, SubmissionError> {
    let items = match value {
        None | Some(Val::Null) => return Ok(Vec::new()),
        Some(Val::Arr(items)) => items,
        _ => {
            return Err(SubmissionError::new(
                "usage.queue_submission.grants",
                "grants must be an array of {id, grant_id} bindings",
            ));
        }
    };
    if items.len() > GRANTS_MAX {
        return Err(SubmissionError::new(
            "usage.queue_submission.grants",
            format!("the presented grant bindings exceed the bound of {GRANTS_MAX}"),
        ));
    }
    let mut grants: Vec<ItemGrant> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for item in items {
        let id = item
            .get("id")
            .and_then(Val::as_str)
            .filter(|text| !text.is_empty() && text.len() <= 256)
            .ok_or_else(|| {
                SubmissionError::new(
                    "usage.queue_submission.grants",
                    "every grant binding requires a bounded issue reference id",
                )
            })?;
        let grant_id = item
            .get("grant_id")
            .and_then(Val::as_str)
            .filter(|text| formats::is_grant_id(text))
            .ok_or_else(|| {
                SubmissionError::new(
                    "usage.queue_submission.grants",
                    format!("grant binding {id:?} requires a grant_id (gr_ + 16 hex)"),
                )
            })?;
        if !seen.insert(id.to_string()) {
            return Err(SubmissionError::new(
                "usage.queue_submission.grants",
                format!("the issue {id:?} is presented twice with grant bindings"),
            ));
        }
        grants.push(ItemGrant {
            id: id.to_string(),
            grant_id: grant_id.to_string(),
        });
    }
    Ok(grants)
}

fn parse_resume(value: Option<&Val>) -> Result<Vec<ResumeAuthorization>, SubmissionError> {
    let items = match value {
        None | Some(Val::Null) => return Ok(Vec::new()),
        Some(Val::Arr(items)) => items,
        _ => {
            return Err(SubmissionError::new(
                "usage.queue_submission.resume",
                "resume must be an array of {instance_id, digest} authorizations",
            ));
        }
    };
    if items.len() > RESUME_MAX {
        return Err(SubmissionError::new(
            "usage.queue_submission.resume",
            format!("the presented resume authorizations exceed the bound of {RESUME_MAX}"),
        ));
    }
    let mut resume: Vec<ResumeAuthorization> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for item in items {
        let instance_id = item
            .get("instance_id")
            .and_then(Val::as_str)
            .filter(|text| !text.is_empty() && text.len() <= 64)
            .ok_or_else(|| {
                SubmissionError::new(
                    "usage.queue_submission.resume",
                    "every resume authorization requires a bounded instance_id",
                )
            })?;
        let digest = item
            .get("digest")
            .and_then(Val::as_str)
            .filter(|text| formats::is_hex64(text))
            .ok_or_else(|| {
                SubmissionError::new(
                    "usage.queue_submission.resume",
                    format!(
                        "the resume authorization for {instance_id:?} requires the engine-minted \
                         64-hex digest"
                    ),
                )
            })?;
        if !seen.insert(instance_id.to_string()) {
            return Err(SubmissionError::new(
                "usage.queue_submission.resume",
                format!("the run {instance_id:?} is presented twice with resume authorizations"),
            ));
        }
        resume.push(ResumeAuthorization {
            instance_id: instance_id.to_string(),
            digest: digest.to_string(),
        });
    }
    Ok(resume)
}

/// The digest recomputed over one presented bound-input document. The
/// bound document IS the digest document, so its sha256 is the approved
/// preview digest (the daemon additionally re-renders the preview and
/// requires the re-derived digest to agree).
pub fn bound_digest(bound: &Val) -> Result<String, SubmissionError> {
    match bound {
        Val::Obj(_) => Ok(digest_of(bound)),
        _ => Err(SubmissionError::new(
            "usage.queue_submission.preview",
            "the bound-input preview document must be an object",
        )),
    }
}

/// Rebuild the typed #84 preview inputs from the presented bound-input
/// document plus the reviewed binding and presented observations. Strict by
/// construction: an unknown key, a missing field or a foreign schema is
/// refused, and the rebuild is what the digest is re-derived from.
pub fn presented_request(material: &SubmissionMaterial) -> Result<QueueRequest, SubmissionError> {
    let bound = &material.preview;
    const KEYS: [&str; 8] = [
        "schema",
        "repository",
        "host",
        "workflow",
        "role_config",
        "boundary",
        "steps",
        "selected",
    ];
    let Val::Obj(map) = bound else {
        return Err(SubmissionError::new(
            "usage.queue_submission.preview",
            "the bound-input preview document must be an object",
        ));
    };
    for key in map.keys() {
        if !KEYS.contains(&key.as_str()) {
            return Err(SubmissionError::new(
                "usage.queue_submission.preview",
                format!("the bound-input document carries unknown key {key:?} (closed surface)"),
            ));
        }
    }
    match bound.get("schema").and_then(Val::as_str) {
        Some(schema) if schema == crate::queue_preview::QUEUE_PREVIEW_SCHEMA => {}
        _ => {
            return Err(SubmissionError::new(
                "usage.queue_submission.preview",
                format!(
                    "the bound-input document schema must be {:?}",
                    crate::queue_preview::QUEUE_PREVIEW_SCHEMA
                ),
            ));
        }
    }
    let text = |value: Option<&Val>, what: &str| -> Result<String, SubmissionError> {
        value
            .and_then(Val::as_str)
            .filter(|text| !text.is_empty())
            .map(str::to_string)
            .ok_or_else(|| {
                SubmissionError::new(
                    "usage.queue_submission.preview",
                    format!("the bound-input document requires {what}"),
                )
            })
    };
    let repository = text(bound.get("repository"), "repository")?;
    let host = text(bound.get("host"), "host")?;
    let workflow_id = text(
        bound
            .get("workflow")
            .and_then(|workflow| workflow.get("id")),
        "workflow.id",
    )?;
    let workflow_hash = text(
        bound
            .get("workflow")
            .and_then(|workflow| workflow.get("hash")),
        "workflow.hash",
    )?;
    // The digest document binds the role key/revision only; the full
    // reviewed binding rides as a separate presented document and must
    // agree with both.
    let role_key = text(
        bound.get("role_config").and_then(|role| role.get("key")),
        "role_config.key",
    )?;
    let role_revision = text(
        bound
            .get("role_config")
            .and_then(|role| role.get("revision")),
        "role_config.revision",
    )?;
    let binding = ProfileBinding::from_doc(&material.binding)
        .map_err(|err| SubmissionError::new(err.code(), err.message().to_string()))?;
    if binding.key != role_key || binding.revision != role_revision {
        return Err(SubmissionError::new(
            "refusal.profile.revision",
            format!(
                "the presented binding ({}, revision {}) is not the reviewed role configuration \
                 ({role_key}, revision {role_revision}) the approval bound",
                binding.key, binding.revision
            ),
        ));
    }
    let boundary = parse_boundary(bound.get("boundary"))?;
    let steps = parse_steps(bound.get("steps"))?;
    let selected = parse_selected(bound.get("selected"))?;
    Ok(QueueRequest {
        repository,
        host,
        host_available: material.host_available,
        harness_key: role_key,
        harness_lanes: material.harness_lanes,
        caps: material.caps,
        workflow_id,
        workflow_hash,
        role_config: material.binding.clone(),
        boundary,
        steps,
        selected,
    })
}

fn parse_boundary(value: Option<&Val>) -> Result<Boundary, SubmissionError> {
    let malformed = |what: &str| {
        SubmissionError::new(
            "usage.queue_submission.preview",
            format!("the bound-input boundary requires {what}"),
        )
    };
    let phase = value
        .and_then(|boundary| boundary.get("phase"))
        .and_then(Val::as_str)
        .filter(|text| !text.is_empty())
        .ok_or_else(|| malformed("phase"))?
        .to_string();
    let integration_branch = value
        .and_then(|boundary| boundary.get("integration_branch"))
        .and_then(Val::as_str)
        .filter(|text| !text.is_empty())
        .ok_or_else(|| malformed("integration_branch"))?
        .to_string();
    let completion_branch = value
        .and_then(|boundary| boundary.get("completion_branch"))
        .and_then(Val::as_str)
        .filter(|text| !text.is_empty())
        .ok_or_else(|| malformed("completion_branch"))?
        .to_string();
    let caps = match value.and_then(|boundary| boundary.get("caps")) {
        Some(Val::Arr(caps)) => caps,
        _ => return Err(malformed("caps")),
    };
    let mut boundary_caps = Vec::new();
    for cap in caps {
        let cap = cap
            .as_str()
            .filter(|text| !text.is_empty())
            .ok_or_else(|| malformed("caps (bounded strings)"))?;
        if !boundary_caps.contains(&cap.to_string()) {
            boundary_caps.push(cap.to_string());
        }
    }
    Ok(Boundary {
        phase,
        integration_branch,
        completion_branch,
        caps: boundary_caps,
    })
}

fn parse_steps(value: Option<&Val>) -> Result<Vec<PlannedStep>, SubmissionError> {
    let steps = match value {
        Some(Val::Arr(steps)) => steps,
        _ => {
            return Err(SubmissionError::new(
                "usage.queue_submission.preview",
                "the bound-input document requires the steps array",
            ));
        }
    };
    let mut planned = Vec::new();
    for step in steps {
        let id = step
            .get("id")
            .and_then(Val::as_str)
            .filter(|text| !text.is_empty())
            .ok_or_else(|| {
                SubmissionError::new(
                    "usage.queue_submission.preview",
                    "every bound step requires an id",
                )
            })?
            .to_string();
        let kind = step
            .get("kind")
            .and_then(Val::as_str)
            .filter(|text| !text.is_empty())
            .ok_or_else(|| {
                SubmissionError::new(
                    "usage.queue_submission.preview",
                    format!("the bound step {id:?} requires a kind"),
                )
            })?
            .to_string();
        let params = match step.get("params") {
            None | Some(Val::Null) => None,
            Some(value @ Val::Obj(params))
                if params
                    .keys()
                    .all(|key| crate::formats::is_step_param_name(key)) =>
            {
                Some(value.clone())
            }
            _ => {
                return Err(SubmissionError::new(
                    "usage.queue_submission.preview",
                    format!(
                        "the bound step {id:?} params must be an object with names matching [a-z][a-z0-9_-]*, or null"
                    ),
                ));
            }
        };
        planned.push(PlannedStep { id, kind, params });
    }
    Ok(planned)
}

fn parse_selected(value: Option<&Val>) -> Result<Vec<SelectedIssue>, SubmissionError> {
    let selected = match value {
        Some(Val::Arr(selected)) => selected,
        _ => {
            return Err(SubmissionError::new(
                "usage.queue_submission.preview",
                "the bound-input document requires the selected array",
            ));
        }
    };
    let mut issues = Vec::new();
    for issue in selected {
        let id = issue
            .get("id")
            .and_then(Val::as_str)
            .filter(|text| !text.is_empty())
            .ok_or_else(|| {
                SubmissionError::new(
                    "usage.queue_submission.preview",
                    "every selected issue requires an id",
                )
            })?
            .to_string();
        let revision = issue
            .get("revision")
            .and_then(Val::as_str)
            .filter(|text| formats::is_hex40(text))
            .ok_or_else(|| {
                SubmissionError::new(
                    "usage.queue_submission.preview",
                    format!("the selected issue {id:?} requires its exact 40-hex revision"),
                )
            })?
            .to_string();
        let requires = match issue.get("requires") {
            Some(Val::Arr(requires)) => requires
                .iter()
                .map(|dependency| {
                    dependency
                        .as_str()
                        .filter(|text| !text.is_empty())
                        .map(str::to_string)
                        .ok_or_else(|| {
                            SubmissionError::new(
                                "usage.queue_submission.preview",
                                format!(
                                    "the selected issue {id:?} requires bounded dependency \
                                     references"
                                ),
                            )
                        })
                })
                .collect::<Result<Vec<_>, _>>()?,
            None => Vec::new(),
            _ => {
                return Err(SubmissionError::new(
                    "usage.queue_submission.preview",
                    format!("the selected issue {id:?} requires an array of dependencies"),
                ));
            }
        };
        issues.push(SelectedIssue {
            id,
            title: None,
            revision,
            requires,
        });
    }
    Ok(issues)
}

/// Revalidate one submission against live durable state and classify every
/// selected issue (issue #85 AC1/AC3/AC4/AC5):
///
/// - the preview is re-rendered from the rebuilt inputs and its digest must
///   equal the presented digest (`refusal.plan.stale` otherwise);
/// - the presented epoch, the bound role-configuration revision and the
///   presented fresh revision must all agree with live state
///   (`refusal.state.epoch` / `refusal.profile.revision` otherwise);
/// - the executable spine must be non-empty, wholly inside the closed
///   effect set, fully resolved, and covered by the reviewed boundary caps
///   (`preview.step_unsupported` / `preview.step_unresolved` /
///   `submission.steps` / `submission.boundary` otherwise): an unsupported
///   end-to-end flow is refused and labelled, never stubbed;
/// - policy holds (unsupported workflow, production/release boundary,
///   protected completion branch) refuse the whole submission;
/// - every other hold classifies per issue: dependency/ownership facts
///   refuse the item, while capacity, occupancy, availability and overlap
///   holds park it as `waiting`.
pub fn revalidate(
    state: &State,
    material: &SubmissionMaterial,
) -> Result<Revalidated, SubmissionError> {
    let request = presented_request(material)?;
    let preview = preview_queue(state, &request)
        .map_err(|err| SubmissionError::new(err.code, err.message))?;
    confirm(&preview, &material.digest)
        .map_err(|err| SubmissionError::new(err.code, err.message))?;
    let epoch = state
        .current_epoch()
        .map_err(|err| SubmissionError::new(err.code, err.message))?;
    if material.epoch != epoch {
        return Err(SubmissionError::new(
            mutation_code::EPOCH_STALE,
            format!(
                "the approval was rendered against epoch {} but the live epoch is {epoch}; an \
                 approval dies with its epoch (render a fresh preview)",
                material.epoch
            ),
        ));
    }
    let bound_revision = preview
        .doc
        .get("request")
        .and_then(|request| request.get("role_config"))
        .and_then(|role| role.get("revision"))
        .and_then(Val::as_str)
        .unwrap_or_default();
    if material.role_revision != bound_revision {
        return Err(SubmissionError::new(
            "refusal.profile.revision",
            format!(
                "the current profile-configuration revision {} is not the reviewed revision \
                 {bound_revision}; a configuration or credential change invalidates the reviewed \
                 run",
                material.role_revision
            ),
        ));
    }
    // The executable spine: non-empty, closed-set kinds, resolved params,
    // and every required capability inside the reviewed boundary.
    if request.steps.is_empty() {
        return Err(SubmissionError::new(
            codes::STEPS,
            "the declared step spine is empty: there is no executable flow to admit",
        ));
    }
    for step in &request.steps {
        let supported = required_capability(&step.kind);
        if supported.is_none() {
            return Err(SubmissionError::new(
                preview_holds::STEP_UNSUPPORTED,
                format!(
                    "step {:?} carries kind {:?}, which is outside the closed executable effect \
                     set; the end-to-end flow is refused and labelled, never stubbed",
                    step.id, step.kind
                ),
            ));
        }
        if step.params.is_none() {
            return Err(SubmissionError::new(
                preview_holds::STEP_UNRESOLVED,
                format!(
                    "step {:?} ({}) carries no resolved binding parameters; executing an \
                     unresolved step is not supported",
                    step.id, step.kind
                ),
            ));
        }
        let capability = supported.unwrap_or_default();
        if !request.boundary.caps.iter().any(|cap| cap == capability) {
            return Err(SubmissionError::new(
                codes::BOUNDARY,
                format!(
                    "step {:?} ({}) requires capability {capability:?}, which the reviewed \
                     completion boundary does not carry",
                    step.id, step.kind
                ),
            ));
        }
    }
    // Policy holds refuse the whole submission before anything is decided.
    let top_holds = holds_of(&preview.doc);
    for hold in &top_holds {
        let policy = hold.0 == preview_holds::WORKFLOW_UNSUPPORTED
            || hold.0 == preview_holds::PROTECTED_BRANCH
            || hold.0 == mutation_code::PRODUCTION_CONFIRMATION;
        if policy {
            return Err(SubmissionError::new(hold.0, hold.2.clone()));
        }
    }
    let environment = environment_hold(&top_holds);
    let overlap_subjects: BTreeSet<&str> = top_holds
        .iter()
        .filter(|hold| hold.0 == crate::lifecycle::code::MONOREPO_OVERLAP)
        .map(|hold| hold.1.as_str())
        .collect();
    let items = classify_items(state, material, &preview, &environment, &overlap_subjects)?;
    Ok(Revalidated {
        request,
        preview,
        items,
    })
}

/// One rendered hold: (code, subject, message).
type HoldText = (&'static str, String, String);

/// The rendered top-level holds of one preview document.
fn holds_of(doc: &Val) -> Vec<HoldText> {
    let mut holds = Vec::new();
    if let Some(Val::Arr(items)) = doc.get("holds") {
        for hold in items {
            let code = hold.get("code").and_then(Val::as_str).unwrap_or_default();
            let code = code_static(code);
            let subject = hold
                .get("subject")
                .and_then(Val::as_str)
                .unwrap_or_default()
                .to_string();
            let message = hold
                .get("message")
                .and_then(Val::as_str)
                .unwrap_or_default()
                .to_string();
            if let Some(code) = code {
                holds.push((code, subject, message));
            }
        }
    }
    holds
}

/// Map one rendered hold code back onto its `&'static str` constant. The
/// preview holds are a closed set; an unknown code is dropped (the preview
/// renderer is the only producer).
fn code_static(code: &str) -> Option<&'static str> {
    const CODES: [&str; 14] = [
        preview_holds::WORKFLOW_UNSUPPORTED,
        preview_holds::HOST_UNAVAILABLE,
        preview_holds::OCCUPANCY_UNKNOWN,
        preview_holds::AUTH_MISSING,
        preview_holds::STEP_UNSUPPORTED,
        preview_holds::STEP_UNRESOLVED,
        preview_holds::PROTECTED_BRANCH,
        preview_holds::REVISION_STALE,
        preview_holds::DEPENDENCY_UNRESOLVED,
        preview_holds::DEPENDENCY_UNSETTLED,
        preview_holds::DEPENDENCY_CYCLE,
        mutation_code::PRODUCTION_CONFIRMATION,
        crate::lifecycle::code::CAP_GLOBAL,
        crate::lifecycle::code::CAP_REPOSITORY,
    ];
    // The remaining admission codes are matched explicitly so the closed
    // list above stays readable.
    let extra: [&'static str; 3] = [
        crate::lifecycle::code::CAP_HARNESS,
        crate::lifecycle::code::MONOREPO_OVERLAP,
        crate::lifecycle::code::CAP_MISSING,
    ];
    CODES
        .iter()
        .chain(extra.iter())
        .copied()
        .find(|known| *known == code)
}

/// The environment hold pending for every not-yet-decided item, if any
/// (`host_unavailable` > `occupancy_unknown` > `auth_missing`).
fn environment_hold(holds: &[HoldText]) -> Option<(String, String)> {
    const ORDER: [&str; 3] = [
        preview_holds::HOST_UNAVAILABLE,
        preview_holds::OCCUPANCY_UNKNOWN,
        preview_holds::AUTH_MISSING,
    ];
    for code in ORDER {
        if let Some((_, _, message)) = holds.iter().find(|hold| hold.0 == code) {
            return Some((code.to_string(), message.clone()));
        }
    }
    None
}

/// Classify every selected issue of a freshly re-rendered preview. The
/// per-item order is: dependency facts (refuse), live ownership (refuse or
/// explicitly-resumed admit), the presented grant binding (refuse),
/// environment holds (wait), scope overlap (wait) — capacity itself is
/// decided inside the submission transaction.
fn classify_items(
    state: &State,
    material: &SubmissionMaterial,
    preview: &QueuePreview,
    environment: &Option<(String, String)>,
    overlap_subjects: &BTreeSet<&str>,
) -> Result<Vec<PlannedItem>, SubmissionError> {
    let repository = preview
        .doc
        .get("request")
        .and_then(|request| request.get("repository"))
        .and_then(Val::as_str)
        .unwrap_or_default()
        .to_string();
    let grants: BTreeMap<IssueId, String> = material
        .grants
        .iter()
        .map(|grant| {
            let id = IssueId::parse(&grant.id, &repository)
                .map_err(|err| SubmissionError::new(err.code, err.message))?;
            Ok((id, grant.grant_id.clone()))
        })
        .collect::<Result<_, SubmissionError>>()?;
    let mut items = Vec::new();
    let Some(Val::Arr(rendered)) = preview.doc.get("items") else {
        return Err(SubmissionError::new(
            "usage.queue_submission.preview",
            "the preview render carries no items",
        ));
    };
    for item in rendered {
        let id_text = item
            .get("id")
            .and_then(Val::as_str)
            .unwrap_or_default()
            .to_string();
        let id = IssueId::parse(&id_text, &repository)
            .map_err(|err| SubmissionError::new(err.code, err.message))?;
        let work_item = item
            .get("work_item")
            .and_then(Val::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| id.work_item());
        let revision = item
            .get("revision")
            .and_then(Val::as_str)
            .unwrap_or_default()
            .to_string();
        let status = item
            .get("status")
            .and_then(Val::as_str)
            .unwrap_or_default()
            .to_string();
        let item_holds = holds_of(item);
        let mut grant_id: Option<String> = None;
        let mut resume_digest: Option<String> = None;
        let verdict = if status == "blocked" {
            let (code, message) = item_holds
                .first()
                .map(|hold| (hold.0, hold.2.clone()))
                .unwrap_or((
                    preview_holds::DEPENDENCY_UNSETTLED,
                    "the item is blocked by a dependency fact this submission cannot settle"
                        .to_string(),
                ));
            SubmissionVerdict::Refused { code, message }
        } else if status == "already_owned" {
            let owned = item.get("owned");
            let instance_id = owned
                .and_then(|owned| owned.get("instance_id"))
                .and_then(Val::as_str)
                .unwrap_or_default()
                .to_string();
            let owned_status = owned
                .and_then(|owned| owned.get("status"))
                .and_then(Val::as_str)
                .unwrap_or_default();
            let owned_revision = owned
                .and_then(|owned| owned.get("issue_revision"))
                .and_then(Val::as_str)
                .unwrap_or_default();
            if owned_revision != revision {
                let Some(presented_grant) = grants.get(&id) else {
                    items.push(PlannedItem {
                        id: id.display(),
                        work_item,
                        issue_number: id.number,
                        revision,
                        grant_id: None,
                        resume_digest: None,
                        verdict: SubmissionVerdict::Refused {
                            code: codes::GRANT,
                            message: format!(
                                "revision rebind for {} requires a fresh presented grant window",
                                id.display()
                            ),
                        },
                    });
                    continue;
                };
                let row = state
                    .grant_by_id(presented_grant)
                    .map_err(|err| SubmissionError::new(err.code, err.message))?;
                match grant_binding_refusal(state, material, presented_grant, row, &id, &revision)?
                {
                    Some((code, message)) => SubmissionVerdict::Refused { code, message },
                    None => {
                        let stored = state
                            .instance_by_id(&instance_id)
                            .map_err(|err| SubmissionError::new(err.code, err.message))?
                            .ok_or_else(|| {
                                SubmissionError::new(
                                    "state.not_found",
                                    format!("owned run {instance_id} disappeared"),
                                )
                            })?;
                        if !state
                            .grant_issued_after(presented_grant, &stored.grant_id)
                            .map_err(|err| SubmissionError::new(err.code, err.message))?
                        {
                            SubmissionVerdict::Refused {
                                code: preview_holds::REVISION_STALE,
                                message: format!(
                                    "grant {presented_grant} is not a later authorization than the current owner's grant {}; the older selection remains stale",
                                    stored.grant_id
                                ),
                            }
                        } else {
                            grant_id = Some(presented_grant.clone());
                            if let Some((code, message)) = environment {
                                SubmissionVerdict::Waiting {
                                    code: code_static(code)
                                        .unwrap_or(preview_holds::OCCUPANCY_UNKNOWN),
                                    message: message.clone(),
                                }
                            } else if overlap_subjects.contains(id_text.as_str()) {
                                SubmissionVerdict::Waiting {
                                    code: crate::lifecycle::code::MONOREPO_OVERLAP,
                                    message: format!(
                                        "the planned scope worktrees/issues/{} overlaps a concurrent lane scope; the revision rebind waits",
                                        id.number
                                    ),
                                }
                            } else {
                                SubmissionVerdict::Approved
                            }
                        }
                    }
                }
            } else if owned_status == "paused" {
                let presented = material
                    .resume
                    .iter()
                    .find(|authorization| authorization.instance_id == instance_id);
                let stored = state
                    .instance_by_id(&instance_id)
                    .map_err(|err| SubmissionError::new(err.code, err.message))?;
                let authorized = match (presented, stored.as_ref()) {
                    (Some(authorization), Some(row)) if row.paused => {
                        crate::engine::authorize_resume(&row.resume_digest, &authorization.digest)
                            .is_ok()
                    }
                    _ => false,
                };
                if authorized {
                    resume_digest = presented.map(|authorization| authorization.digest.clone());
                    SubmissionVerdict::Approved
                } else {
                    SubmissionVerdict::Refused {
                        code: codes::PAUSED,
                        message: format!(
                            "run {instance_id} is paused and stays paused: a paused fleet is \
                             resumed only with a separate explicit engine-minted resume \
                             authorization"
                        ),
                    }
                }
            } else if let Some(presented_grant) = grants.get(&id) {
                let stored = state
                    .instance_by_id(&instance_id)
                    .map_err(|err| SubmissionError::new(err.code, err.message))?
                    .ok_or_else(|| {
                        SubmissionError::new(
                            "state.not_found",
                            format!("owned run {instance_id} disappeared"),
                        )
                    })?;
                let prior = state
                    .grant_by_id(&stored.grant_id)
                    .map_err(|err| SubmissionError::new(err.code, err.message))?;
                let prior_expired = prior.as_ref().is_some_and(|grant| {
                    grant.status == "active"
                        && is_expired(&grant.expires_at, &crate::time::rfc3339_now())
                });
                if !prior_expired {
                    SubmissionVerdict::Refused {
                        code: codes::ALREADY_OWNED,
                        message: format!(
                            "run {instance_id} already owns this issue under a live grant; a fresh window never rotates a live binding"
                        ),
                    }
                } else {
                    let candidate = state
                        .grant_by_id(presented_grant)
                        .map_err(|err| SubmissionError::new(err.code, err.message))?;
                    match grant_binding_refusal(
                        state,
                        material,
                        presented_grant,
                        candidate,
                        &id,
                        &revision,
                    )? {
                        Some((code, message)) => SubmissionVerdict::Refused { code, message },
                        None => {
                            if !state
                                .grant_issued_after(presented_grant, &stored.grant_id)
                                .map_err(|err| SubmissionError::new(err.code, err.message))?
                            {
                                SubmissionVerdict::Refused {
                                    code: preview_holds::REVISION_STALE,
                                    message: format!(
                                        "grant {presented_grant} is not a later authorization than expired grant {}; rotation is explicit and issuance-ordered",
                                        stored.grant_id
                                    ),
                                }
                            } else {
                                grant_id = Some(presented_grant.clone());
                                SubmissionVerdict::Approved
                            }
                        }
                    }
                }
            } else {
                SubmissionVerdict::Refused {
                    code: codes::ALREADY_OWNED,
                    message: format!(
                        "run {instance_id} already owns this issue; a duplicate submission never \
                         creates a second owner"
                    ),
                }
            }
        } else {
            // Eligible: grant binding, then environment, then overlap.
            match grants.get(&id) {
                None => SubmissionVerdict::Refused {
                    code: codes::GRANT,
                    message: format!(
                        "no grant is presented for {}; an eligible item is admitted only against \
                         an explicit active grant binding",
                        id.display()
                    ),
                },
                Some(grant_id_text) => {
                    let row = state
                        .grant_by_id(grant_id_text)
                        .map_err(|err| SubmissionError::new(err.code, err.message))?;
                    match grant_binding_refusal(
                        state,
                        material,
                        grant_id_text,
                        row,
                        &id,
                        &revision,
                    )? {
                        Some((code, message)) => SubmissionVerdict::Refused { code, message },
                        None => {
                            grant_id = Some(grant_id_text.clone());
                            if let Some((code, message)) = environment {
                                SubmissionVerdict::Waiting {
                                    code: code_static(code)
                                        .unwrap_or(preview_holds::OCCUPANCY_UNKNOWN),
                                    message: message.clone(),
                                }
                            } else if overlap_subjects.contains(id_text.as_str()) {
                                SubmissionVerdict::Waiting {
                                    code: crate::lifecycle::code::MONOREPO_OVERLAP,
                                    message: format!(
                                        "the planned scope worktrees/issues/{} overlaps a \
                                         concurrent lane scope; the item waits",
                                        id.number
                                    ),
                                }
                            } else {
                                SubmissionVerdict::Approved
                            }
                        }
                    }
                }
            }
        };
        items.push(PlannedItem {
            id: id.display(),
            work_item,
            issue_number: id.number,
            revision,
            grant_id,
            resume_digest,
            verdict,
        });
    }
    Ok(items)
}

/// The presented-grant binding check for one eligible item: `None` when the
/// grant is live and binds this issue, or the typed refusal otherwise. The
/// submission transaction re-verifies the volatile facts (status, epoch,
/// expiry) under its guard.
fn grant_binding_refusal(
    state: &State,
    material: &SubmissionMaterial,
    grant_id: &str,
    row: Option<crate::state::GrantRow>,
    id: &IssueId,
    revision: &str,
) -> Result<Option<(&'static str, String)>, SubmissionError> {
    let Some(grant) = row else {
        return Ok(Some((
            mutation_code::GRANT_INACTIVE,
            format!("no grant {grant_id:?} exists"),
        )));
    };
    if grant.status != "active" {
        return Ok(Some((
            mutation_code::GRANT_INACTIVE,
            format!(
                "grant {grant_id} is {}; a revoked or invalidated grant refuses this item before \
                 any effect",
                grant.status
            ),
        )));
    }
    let epoch = state
        .current_epoch()
        .map_err(|err| SubmissionError::new(err.code, err.message))?;
    if grant.state_epoch != epoch {
        return Ok(Some((
            mutation_code::EPOCH_STALE,
            format!(
                "grant {grant_id} was issued under epoch {}; grants die with their epoch",
                grant.state_epoch
            ),
        )));
    }
    let now = crate::time::rfc3339_now();
    if is_expired(&grant.expires_at, &now) {
        return Ok(Some((
            mutation_code::GRANT_EXPIRED,
            format!("grant {grant_id} expired at {}", grant.expires_at),
        )));
    }
    if grant.repository != id.repository
        || grant.issue_number != id.number
        || grant.issue_revision != revision
    {
        return Ok(Some((
            codes::GRANT,
            format!(
                "grant {grant_id} binds {}#{}@{}, not the selected {}@{revision}",
                grant.repository,
                grant.issue_number,
                grant.issue_revision,
                id.display()
            ),
        )));
    }
    let workflow_hash = material
        .preview
        .get("workflow")
        .and_then(|workflow| workflow.get("hash"))
        .and_then(Val::as_str)
        .unwrap_or_default();
    if grant.workflow_hash != workflow_hash {
        return Ok(Some((
            mutation_code::WORKFLOW_CHANGED,
            format!(
                "grant {grant_id} binds workflow {}; the submission binds {workflow_hash}",
                grant.workflow_hash
            ),
        )));
    }
    let scope = format!("worktrees/issues/{}", id.number);
    if grant.scope != scope {
        return Ok(Some((
            codes::GRANT,
            format!(
                "grant {grant_id} declares scope {:?}; the reviewed planned scope is {scope:?}",
                grant.scope
            ),
        )));
    }
    Ok(None)
}

/// The `advance` block of a submission document (issue #96): the durable
/// queue-cursor state — one row per consumed verified delivery, the cursor,
/// and the CURRENT hold (if any). A read reports committed rows only; it
/// never re-derives the cursor or hides a hold.
pub fn advance_doc(advances: &[QueueAdvanceRow]) -> Val {
    let mut dispatched = 0i64;
    let mut held: Option<&QueueAdvanceRow> = None;
    let mut rows: Vec<Val> = Vec::new();
    let mut cursor = 0i64;
    for row in advances {
        if row.next_instance_id.is_some() {
            dispatched += 1;
        }
        if row.reason.is_some() {
            held = Some(row);
        }
        cursor = cursor.max(row.delivered_ordinal);
        rows.push(object(vec![
            ("delivered_ordinal", integer(row.delivered_ordinal)),
            ("delivered_work_item", string(&row.delivered_work_item)),
            ("delivered_head", string(&row.delivered_head)),
            ("evidence_id", string(&row.evidence_id)),
            (
                "next_ordinal",
                row.next_ordinal.map(integer).unwrap_or_else(null),
            ),
            (
                "next_work_item",
                row.next_work_item
                    .as_deref()
                    .map(string)
                    .unwrap_or_else(null),
            ),
            (
                "next_instance_id",
                row.next_instance_id
                    .as_deref()
                    .map(string)
                    .unwrap_or_else(null),
            ),
            (
                "reason",
                row.reason.as_deref().map(string).unwrap_or_else(null),
            ),
            (
                "message",
                row.message.as_deref().map(string).unwrap_or_else(null),
            ),
            ("at", string(&row.at)),
        ]));
    }
    let held_doc = match held {
        Some(row) => object(vec![
            (
                "next_ordinal",
                row.next_ordinal.map(integer).unwrap_or_else(null),
            ),
            (
                "next_work_item",
                row.next_work_item
                    .as_deref()
                    .map(string)
                    .unwrap_or_else(null),
            ),
            (
                "reason",
                row.reason.as_deref().map(string).unwrap_or_else(null),
            ),
            (
                "message",
                row.message.as_deref().map(string).unwrap_or_else(null),
            ),
            ("at", string(&row.at)),
        ]),
        None => null(),
    };
    object(vec![
        ("cursor_ordinal", integer(cursor)),
        ("consumed", integer(advances.len() as i64)),
        ("dispatched", integer(dispatched)),
        (
            "last",
            match advances.last() {
                Some(row) => object(vec![
                    ("delivered_ordinal", integer(row.delivered_ordinal)),
                    ("delivered_work_item", string(&row.delivered_work_item)),
                    ("delivered_head", string(&row.delivered_head)),
                    ("at", string(&row.at)),
                ]),
                None => null(),
            },
        ),
        ("held", held_doc),
        ("rows", Val::Arr(rows)),
    ])
}

/// Render the committed submission document. The SAME function serves the
/// submit response, the `queue.status` readback and restart reconciliation,
/// so all three agree byte for byte (after canonicalization) — they are one
/// pure projection of the committed rows (items plus the issue #96 advance
/// rows).
pub fn submission_doc(
    row: &QueueSubmissionRow,
    items: &[QueueSubmissionItemRow],
    advances: &[QueueAdvanceRow],
) -> Val {
    let mut admitted = 0i64;
    let mut waiting = 0i64;
    let mut refused = 0i64;
    let mut items_doc: Vec<Val> = Vec::new();
    for item in items {
        match item.status.as_str() {
            "admitted" => admitted += 1,
            "waiting" => waiting += 1,
            _ => refused += 1,
        }
        items_doc.push(object(vec![
            (
                "id",
                string(&format!("{}#{}", row.repository, item.issue_number)),
            ),
            ("work_item", string(&item.work_item)),
            ("revision", string(&item.issue_revision)),
            ("status", string(&item.status)),
            (
                "reason",
                item.reason.as_deref().map(string).unwrap_or_else(null),
            ),
            (
                "message",
                item.message.as_deref().map(string).unwrap_or_else(null),
            ),
            (
                "instance_id",
                item.instance_id.as_deref().map(string).unwrap_or_else(null),
            ),
        ]));
    }
    let steps_doc: Vec<Val> = Val::parse_json(&row.request_line)
        .ok()
        .and_then(|request| request.get("steps").and_then(Val::as_array).cloned())
        .unwrap_or_default()
        .iter()
        .map(|step| {
            let id = step.get("id").and_then(Val::as_str).unwrap_or_default();
            let kind = step.get("kind").and_then(Val::as_str).unwrap_or_default();
            let supported = required_capability(kind).is_some();
            let resolved = !matches!(step.get("params"), None | Some(Val::Null));
            object(vec![
                ("id", string(id)),
                ("kind", string(kind)),
                ("supported", bool_(supported)),
                ("resolved", bool_(resolved)),
                (
                    "state",
                    string(if supported && resolved {
                        "executable"
                    } else {
                        "blocked"
                    }),
                ),
                (
                    "reason",
                    if supported && resolved {
                        null()
                    } else if !supported {
                        string(preview_holds::STEP_UNSUPPORTED)
                    } else {
                        string(preview_holds::STEP_UNRESOLVED)
                    },
                ),
            ])
        })
        .collect();
    let caps: Vec<Val> = Val::parse_json(&row.boundary_caps)
        .ok()
        .and_then(|caps| caps.as_array().cloned())
        .unwrap_or_default()
        .iter()
        .map(|cap| string(cap.as_str().unwrap_or_default()))
        .collect();
    object(vec![
        ("schema", string(QUEUE_SUBMISSION_SCHEMA)),
        ("submission_id", string(&row.submission_id)),
        (
            "state",
            object(vec![
                ("epoch", integer(row.state_epoch)),
                ("digest", string(&row.digest)),
                ("repository", string(&row.repository)),
                (
                    "workflow",
                    object(vec![
                        ("id", string(&row.workflow_id)),
                        ("hash", string(&row.workflow_hash)),
                    ]),
                ),
                (
                    "role_config",
                    object(vec![
                        ("key", string(&row.role_key)),
                        ("revision", string(&row.role_revision)),
                    ]),
                ),
                (
                    "boundary",
                    object(vec![
                        ("phase", string(&row.boundary_phase)),
                        ("caps", Val::Arr(caps)),
                        ("integration_branch", string(&row.integration_branch)),
                        ("completion_branch", string(&row.completion_branch)),
                    ]),
                ),
            ]),
        ),
        (
            "admission",
            object(vec![
                ("admitted", integer(admitted)),
                ("waiting", integer(waiting)),
                ("refused", integer(refused)),
            ]),
        ),
        ("items", Val::Arr(items_doc)),
        ("advance", advance_doc(advances)),
        ("steps", Val::Arr(steps_doc)),
        ("statement", string(STATEMENT)),
        ("created_at", string(&row.created_at)),
    ])
}

/// Build one `queue.submit` params document (the CLI's single construction
/// site; also the shape the daemon's `parse_params` accepts).
#[allow(clippy::too_many_arguments)]
pub fn submit_params(
    idempotency_key: &str,
    digest: &str,
    epoch: i64,
    preview: &Val,
    binding: &Val,
    role_revision: &str,
    caps: ConcurrencyCaps,
    host_available: Option<bool>,
    harness_lanes: Option<i64>,
    grants: &[ItemGrant],
    resume: &[ResumeAuthorization],
    supervision: Option<&crate::supervision::Authorization>,
) -> Val {
    let observations = object(vec![
        (
            "host_available",
            host_available.map(bool_).unwrap_or_else(null),
        ),
        (
            "harness_lanes",
            harness_lanes.map(integer).unwrap_or_else(null),
        ),
    ]);
    let grants_doc: Vec<Val> = grants
        .iter()
        .map(|grant| {
            object(vec![
                ("id", string(&grant.id)),
                ("grant_id", string(&grant.grant_id)),
            ])
        })
        .collect();
    let resume_doc: Vec<Val> = resume
        .iter()
        .map(|authorization| {
            object(vec![
                ("instance_id", string(&authorization.instance_id)),
                ("digest", string(&authorization.digest)),
            ])
        })
        .collect();
    let mut doc = object(vec![
        ("idempotency_key", string(idempotency_key)),
        ("digest", string(digest)),
        ("epoch", integer(epoch)),
        ("preview", preview.clone()),
        ("binding", binding.clone()),
        ("role_revision", string(role_revision)),
        (
            "caps",
            object(vec![
                ("global", integer(caps.global as i64)),
                ("repository", integer(caps.per_repository as i64)),
                ("harness", integer(caps.per_harness as i64)),
            ]),
        ),
        ("observations", observations),
        ("grants", Val::Arr(grants_doc)),
        ("resume", Val::Arr(resume_doc)),
    ]);
    // Issue #95: the supervision block is OPTIONAL — a submission that does
    // not present one leaves the keyboard of its runs un-supervised.
    if let (Some(authorization), Val::Obj(map)) = (supervision, &mut doc) {
        map.insert(
            "supervision".to_string(),
            crate::supervision::authorization_params(&authorization.desired, authorization.policy),
        );
    }
    doc
}

/// Validate one presented harness/profile key (`--profile KEY` shape).
pub fn is_profile_key(text: &str) -> bool {
    is_bare_token(text) && formats::is_slug(text)
}

/// The one-line human rendering of a submission document (the CLI's
/// non-JSON output; never a substitute for the JSON contract).
pub fn render_human(doc: &Val) -> String {
    let submission_id = doc
        .get("submission_id")
        .and_then(Val::as_str)
        .unwrap_or_default();
    let admission = doc.get("admission");
    let count = |name: &str| {
        admission
            .and_then(|admission| admission.get(name))
            .and_then(Val::as_int)
            .unwrap_or(0)
    };
    let mut lines = vec![
        format!("submission: {submission_id}"),
        format!(
            "admission: admitted {} · waiting {} · refused {}",
            count("admitted"),
            count("waiting"),
            count("refused")
        ),
    ];
    if let Some(Val::Arr(items)) = doc.get("items") {
        for item in items {
            let id = item.get("id").and_then(Val::as_str).unwrap_or_default();
            let status = item.get("status").and_then(Val::as_str).unwrap_or_default();
            let reason = item.get("reason").and_then(Val::as_str).unwrap_or("-");
            let instance = item.get("instance_id").and_then(Val::as_str).unwrap_or("-");
            lines.push(format!("  {id}: {status} ({reason}) run={instance}"));
        }
    }
    // Issue #96: the durable queue cursor and the current hold, if any.
    if let Some(advance) = doc.get("advance") {
        lines.push(format!(
            "advance: cursor {} · consumed {} · dispatched {}",
            advance
                .get("cursor_ordinal")
                .and_then(Val::as_int)
                .unwrap_or(0),
            advance.get("consumed").and_then(Val::as_int).unwrap_or(0),
            advance.get("dispatched").and_then(Val::as_int).unwrap_or(0),
        ));
        if let Some(held) = advance.get("held")
            && !matches!(held, Val::Null)
        {
            lines.push(format!(
                "  held: {} ({})",
                held.get("next_work_item")
                    .and_then(Val::as_str)
                    .unwrap_or("-"),
                held.get("reason").and_then(Val::as_str).unwrap_or("-"),
            ));
        }
    }
    lines.push(format!(
        "statement: {}",
        doc.get("statement")
            .and_then(Val::as_str)
            .unwrap_or_default()
    ));
    let mut out = lines.join("\n");
    out.push('\n');
    out
}
