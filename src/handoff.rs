//! Lane handoff CLI surface (issue #78): the read-only plan preview, the
//! explicit-authorization request binding, and the read-only status
//! projection for ONE explicit lane.
//!
//! This module is deterministic and side-effect free: it validates the
//! reviewable inputs, derives the `hf-lane-handoff/v1` plan document and its
//! plan digest (the exact bytes an authorization binds), applies the
//! confirmation rules (including the policy overlay's constraint), and
//! projects one `lane.replacement.status` result into the stable status
//! document with actionable guidance. The CLI (`crate::commands`) owns the
//! socket effects; nothing here spawns, kills, or writes.
//!
//! Vocabulary alignment (issue #78: no alternate control plane): the plan
//! binds exactly the `lane.replacement.request` inputs, the effect
//! boundaries name the existing daemon operations, and the status document
//! reuses the daemon's phase/outcome/`next_allowed` vocabulary.

use crate::canonical::{canonical_bytes, canonical_text, sha256_hex};
use crate::config::{Policy, ProfileBinding};
use crate::formats;
use crate::value::{Val, bool_, integer, null, object, string};

/// The plan document schema id emitted by `lane preview`/`lane request`.
pub const LANE_PLAN_SCHEMA: &str = "hf-lane-handoff/v1";

/// The closed replacement phase chain (mirrors [`crate::state::LANE_REPLACEMENT_PHASES`]).
pub const HANDOFF_PHASES: [&str; 7] = [
    "requested",
    "quiescing",
    "checkpointed",
    "retired",
    "starting",
    "adopting",
    "adopted",
];

/// The closed effect boundary of each phase: `(phase, operation, effect)`.
/// The effect text is bounded and authoritative for the plan preview — the
/// CLI never performs any of these operations; they belong to the daemon
/// surface (#73–#77) and to the automation the plan is handed to.
pub const EFFECT_BOUNDARIES: [(&str, &str, &str); 7] = [
    (
        "requested",
        "lane.replacement.request",
        "none: the request records durable intent only",
    ),
    (
        "quiescing",
        "lane.replacement.advance",
        "none: the handoff window opens",
    ),
    (
        "checkpointed",
        "lane.checkpoint.create",
        "none: read-only capture of the verified-quiescent lane",
    ),
    (
        "retired",
        "lane.retire",
        "ONE bounded graceful stop of the bound source session only",
    ),
    (
        "starting",
        "lane.start",
        "ONE bounded successor spawn on the same lane and worktree",
    ),
    (
        "adopting",
        "lane.adopt",
        "none: adapter verification read-back",
    ),
    (
        "adopted",
        "lane.successor.consume",
        "none: records consumption of the retained completion events",
    ),
];

/// Explicit-authorization modes for `lane request`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Confirmation {
    /// The exact plan digest was presented (interactively typed or via
    /// `--confirm-digest`): the authorization binds the reviewed plan.
    Digest(String),
    /// A blanket `--yes`: authorizes without binding the plan content and is
    /// therefore refused whenever the policy overlay constrains production
    /// confirmation.
    Blanket,
}

/// One validated lane handoff plan input (the exact
/// `lane.replacement.request` binding values, validated with the same closed
/// rules the daemon enforces).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanInput {
    /// Logical lane identity (slug).
    pub lane_id: String,
    /// Source lane generation being replaced (>= 1).
    pub generation: i64,
    /// Source session identity bound at request time.
    pub session: String,
    /// Source process identity bound at request time.
    pub process: String,
    /// Source role (one of the doctrine roles).
    pub role: String,
    /// Repository-relative worktree reference.
    pub worktree: String,
    /// Operator reason (1-300 printable characters).
    pub reason: String,
}

/// A typed handoff refusal with a stable code (mirrors the daemon's
/// never-downgrade style; `usage.*` codes are CLI-local argv errors).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandoffError {
    /// Stable lowercase-dotted code.
    pub code: &'static str,
    /// Bounded human message.
    pub message: String,
}

impl HandoffError {
    fn new(code: &'static str, message: impl Into<String>) -> HandoffError {
        HandoffError {
            code,
            message: message.into(),
        }
    }
}

/// Validate one field of a plan input; every rule mirrors the daemon's
/// `lane.replacement.request` validation so a CLI-validated plan can never
/// be refused as malformed by the daemon.
pub fn validate_plan_input(
    lane_id: &str,
    generation: i64,
    session: &str,
    process: &str,
    role: &str,
    worktree: &str,
    reason: &str,
) -> Result<PlanInput, HandoffError> {
    if !formats::is_slug(lane_id) {
        return Err(HandoffError::new(
            "usage.lane_id",
            "the lane id must be a lowercase slug (a-z, 0-9, '-')",
        ));
    }
    if generation < 1 {
        return Err(HandoffError::new(
            "usage.lane_generation",
            "generation must be a positive integer (>= 1)",
        ));
    }
    if !formats::is_actor(session) {
        return Err(HandoffError::new(
            "usage.lane_session",
            "the source session identity must be 1-64 characters of [A-Za-z0-9._-]",
        ));
    }
    if !formats::is_actor(process) {
        return Err(HandoffError::new(
            "usage.lane_process",
            "the source process identity must be 1-64 characters of [A-Za-z0-9._-]",
        ));
    }
    if !crate::state::LANE_REPLACEMENT_ROLES.contains(&role) {
        return Err(HandoffError::new(
            "usage.lane_role",
            "the role must be one of the doctrine roles: orchestrator, implementer, reviewer",
        ));
    }
    if !formats::is_worktree_ref(worktree) {
        return Err(HandoffError::new(
            "usage.lane_worktree",
            "the worktree must be a repository-relative path (no leading slash, no '.'/'..' \
             components)",
        ));
    }
    if reason.is_empty() || reason.len() > 300 || reason.chars().any(char::is_control) {
        return Err(HandoffError::new(
            "usage.lane_reason",
            "the reason must be 1-300 printable characters",
        ));
    }
    Ok(PlanInput {
        lane_id: lane_id.to_string(),
        generation,
        session: session.to_string(),
        process: process.to_string(),
        role: role.to_string(),
        worktree: worktree.to_string(),
        reason: reason.to_string(),
    })
}

/// One built lane handoff plan: the reviewable inputs, the optional target
/// profile binding and the digest an authorization binds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LanePlan {
    /// The validated request inputs.
    pub input: PlanInput,
    /// The optional target-profile binding (the `config show` preview).
    pub profile: Option<ProfileBinding>,
    /// sha256 (64-hex) over the canonical bytes of [`LanePlan::digest_document`].
    pub digest: String,
}

impl LanePlan {
    /// Build the plan and its digest from validated inputs and the optional
    /// target profile binding.
    pub fn build(input: PlanInput, profile: Option<ProfileBinding>) -> LanePlan {
        let mut plan = LanePlan {
            input,
            profile,
            digest: String::new(),
        };
        plan.digest = sha256_hex(&canonical_bytes(&plan.digest_document()));
        plan
    }

    /// The deterministic replacement id of the planned record.
    pub fn replacement_id(&self) -> String {
        crate::state::replacement_id_for(&self.input.lane_id, self.input.generation)
    }

    /// The exact document the digest binds: the plan inputs plus the target
    /// profile document (the plan a human reviews and authorizes). Render
    /// fields (effect boundaries, retained references, the durable record)
    /// are derivations and never change the digest.
    pub fn digest_document(&self) -> Val {
        object(vec![
            ("schema", string(LANE_PLAN_SCHEMA)),
            ("lane", string(&self.input.lane_id)),
            ("generation", integer(self.input.generation)),
            ("successor_generation", integer(self.input.generation + 1)),
            ("replacement_id", string(&self.replacement_id())),
            (
                "source",
                object(vec![
                    ("session", string(&self.input.session)),
                    ("process", string(&self.input.process)),
                    ("role", string(&self.input.role)),
                    ("worktree", string(&self.input.worktree)),
                ]),
            ),
            ("reason", string(&self.input.reason)),
            (
                "profile",
                self.profile
                    .as_ref()
                    .map(|profile| profile.to_doc())
                    .unwrap_or_else(null),
            ),
        ])
    }

    /// The full preview document: the digest document plus the effect
    /// boundaries, the policy-derived authorization state, the retained
    /// references (captured at the checkpointed boundary; empty until then)
    /// and the durable record when one exists (read-only enrichment).
    pub fn document(
        &self,
        policy: Option<&Policy>,
        retained: &RetainedView,
        record: Option<&Val>,
    ) -> Val {
        object(vec![
            ("schema", string(LANE_PLAN_SCHEMA)),
            ("plan", self.digest_document()),
            (
                "boundaries",
                object(vec![
                    ("mutates", bool_(false)),
                    (
                        "effects",
                        Val::Arr(
                            EFFECT_BOUNDARIES
                                .iter()
                                .map(|(phase, operation, effect)| {
                                    object(vec![
                                        ("phase", string(phase)),
                                        ("operation", string(operation)),
                                        ("effect", string(effect)),
                                    ])
                                })
                                .collect(),
                        ),
                    ),
                ]),
            ),
            (
                "authorization",
                object(vec![
                    ("policy", policy_rule_val(policy)),
                    ("requirement", string(requirement(policy))),
                ]),
            ),
            ("retained", retained.to_doc()),
            ("record", record.cloned().unwrap_or_else(null)),
            ("digest", string(&self.digest)),
        ])
    }
}

/// The retained worker/reviewer/gate references of one handoff: captured by
/// the checkpoint at the `checkpointed` boundary and preserved for the
/// successor; never addressed (stopped, killed, or altered) by the handoff.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct RetainedView {
    /// Whether a committed checkpoint captured the references.
    pub captured: bool,
    /// Retained worker (replacement) ids.
    pub workers: Vec<String>,
    /// Retained reviewer (replacement) ids.
    pub reviewers: Vec<String>,
    /// Retained pending completion-event tokens.
    pub pending_gates: Vec<String>,
}

impl RetainedView {
    /// Read the retained view from a committed checkpoint snapshot (the
    /// `observation.orchestration` block); empty when absent.
    pub fn from_checkpoint_snapshot(snapshot: &Val) -> RetainedView {
        let orchestration = snapshot.get("orchestration");
        let list = |key: &str| -> Vec<String> {
            orchestration
                .and_then(|value| value.get(key))
                .and_then(Val::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(Val::as_str)
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default()
        };
        RetainedView {
            captured: orchestration.is_some(),
            workers: list("workers"),
            reviewers: list("reviewers"),
            pending_gates: list("pending_events"),
        }
    }

    /// The RPC-facing document.
    pub fn to_doc(&self) -> Val {
        object(vec![
            ("captured", bool_(self.captured)),
            (
                "workers",
                Val::Arr(self.workers.iter().map(|id| string(id)).collect()),
            ),
            (
                "reviewers",
                Val::Arr(self.reviewers.iter().map(|id| string(id)).collect()),
            ),
            (
                "pending_gates",
                Val::Arr(self.pending_gates.iter().map(|id| string(id)).collect()),
            ),
        ])
    }
}

/// The policy overlay's `production_confirmation` rule, when declared.
fn policy_rule(policy: Option<&Policy>) -> Option<&str> {
    policy
        .and_then(|policy| policy.production_confirmation.as_deref())
        .filter(|rule| !rule.is_empty())
}

fn policy_rule_val(policy: Option<&Policy>) -> Val {
    policy_rule(policy).map(string).unwrap_or_else(null)
}

/// The authorization requirement derived from the policy overlay: a declared
/// `production_confirmation` rule always requires the exact plan digest (a
/// blanket `--yes` can never satisfy it); without one, either explicit mode
/// is accepted.
pub fn requirement(policy: Option<&Policy>) -> &'static str {
    match policy_rule(policy) {
        Some("deny") => "denied",
        Some(_) => "digest",
        None => "digest_or_blanket",
    }
}

/// Apply the confirmation rules to one presented authorization. The policy
/// overlay constrains, never relaxes: `deny` refuses every request, a
/// declared rule refuses the blanket `--yes`, and every explicit mode must
/// present the exact plan digest (a mismatch is a stale plan — the reviewed
/// inputs or the profile revision moved).
pub fn confirm(
    policy: Option<&Policy>,
    confirmation: &Confirmation,
    digest: &str,
) -> Result<(), HandoffError> {
    match policy_rule(policy) {
        Some("deny") => {
            return Err(HandoffError::new(
                "refusal.policy.production",
                "the policy overlay denies production confirmation for this installation \
                 (production_confirmation = \"deny\"): no lane handoff request may be authorized",
            ));
        }
        Some(rule) if *confirmation == Confirmation::Blanket => {
            return Err(HandoffError::new(
                "refusal.confirmation.policy",
                format!(
                    "the policy overlay requires an explicit digest-confirmed authorization \
                     (production_confirmation = {rule:?}): a blanket --yes cannot authorize this \
                     plan; review `canter lane preview` and re-run with --confirm-digest"
                ),
            ));
        }
        _ => {}
    }
    match confirmation {
        Confirmation::Digest(presented) if presented == digest => Ok(()),
        Confirmation::Digest(_) => Err(HandoffError::new(
            "refusal.plan.stale",
            "the presented plan digest does not match the current plan: the inputs or the \
             profile-configuration revision moved since the preview; re-run `canter lane preview` \
             and authorize the fresh digest",
        )),
        Confirmation::Blanket => Ok(()),
    }
}

/// The CLI authorization mode required by a plan with no presented
/// confirmation: in `hf-output/v1` JSON mode a prompt is never allowed, so
/// the caller must pass one explicitly.
pub const CONFIRMATION_REQUIRED: &str = "no authorization given: pass --confirm-digest HEX64 (explicit), --confirm (interactive \
     digest confirmation), or --yes (blanket; refused under a production_confirmation policy)";

// ---------------------------------------------------------------------------
// Status projection
// ---------------------------------------------------------------------------

/// The status document of one lane handoff: the record's phase, intended and
/// actual model bindings, blocker, last verified transition, next supported
/// action and the actionable guidance — identical data behind the human and
/// JSON renderings.
pub fn status_document(status_result: &Val, retained: &RetainedView) -> Val {
    let record = status_result
        .get("replacement")
        .cloned()
        .unwrap_or_else(null);
    let profile = status_result.get("profile").cloned().unwrap_or_else(null);
    let successor = status_result.get("successor").cloned().unwrap_or_else(null);
    let history = status_result
        .get("history")
        .and_then(Val::as_array)
        .cloned()
        .unwrap_or_default();
    let phase = record
        .get("phase")
        .and_then(Val::as_str)
        .unwrap_or("unknown")
        .to_string();
    let outcome = record
        .get("outcome")
        .and_then(Val::as_str)
        .unwrap_or("unknown")
        .to_string();
    let blocker = if outcome == "pending" {
        None
    } else {
        record
            .get("outcome_reason")
            .and_then(Val::as_str)
            .filter(|text| !text.is_empty())
            .map(str::to_string)
    };
    let next_phase = record.get("next_allowed").and_then(Val::as_str);
    let intended = profile
        .get("profile")
        .and_then(|doc| binding_pair(doc, "provider", "model"))
        .zip(profile.get("revision").and_then(Val::as_str))
        .map(|(pair, revision)| {
            object(vec![
                ("provider", string(pair.0)),
                ("model", string(pair.1)),
                ("revision", string(revision)),
            ])
        });
    let binding = successor
        .get("evidence")
        .and_then(|evidence| evidence.get("binding"))
        .filter(|value| value.get("status").is_some());
    let actual = binding.map(|binding| {
        object(vec![
            (
                "status",
                string(
                    binding
                        .get("status")
                        .and_then(Val::as_str)
                        .unwrap_or("unknown"),
                ),
            ),
            (
                "provider",
                binding
                    .get("actual")
                    .and_then(|actual| actual.get("provider"))
                    .cloned()
                    .unwrap_or_else(null),
            ),
            (
                "model",
                binding
                    .get("actual")
                    .and_then(|actual| actual.get("model"))
                    .cloned()
                    .unwrap_or_else(null),
            ),
            (
                "source",
                binding.get("source").cloned().unwrap_or_else(null),
            ),
        ])
    });
    let last_transition = history.last().map(|event| {
        object(vec![
            (
                "from",
                event.get("from_phase").cloned().unwrap_or_else(null),
            ),
            (
                "to",
                event
                    .get("to_phase")
                    .cloned()
                    .unwrap_or_else(|| string("unknown")),
            ),
            ("at", event.get("at").cloned().unwrap_or_else(null)),
            (
                "reason",
                event.get("reason").cloned().unwrap_or_else(|| string("")),
            ),
        ])
    });
    let next = object(vec![
        ("phase", next_phase.map(string).unwrap_or_else(null)),
        (
            "operation",
            next_phase
                .and_then(|phase| {
                    EFFECT_BOUNDARIES
                        .iter()
                        .find(|(name, _, _)| *name == phase)
                        .map(|(_, operation, _)| *operation)
                })
                .map(string)
                .unwrap_or_else(null),
        ),
        ("exposed_by_cli", bool_(false)),
    ]);
    let guidance = guidance(&record, &phase, &outcome, next_phase, actual.as_ref());
    object(vec![
        ("schema", string(LANE_PLAN_SCHEMA)),
        ("replacement", record),
        ("phase", string(&phase)),
        ("outcome", string(&outcome)),
        (
            "blocker",
            blocker.as_deref().map(string).unwrap_or_else(null),
        ),
        ("intended", intended.unwrap_or_else(null)),
        ("actual", actual.unwrap_or_else(null)),
        ("last_transition", last_transition.unwrap_or_else(null)),
        ("next", next),
        ("retained", retained.to_doc()),
        (
            "guidance",
            Val::Arr(guidance.iter().map(|line| string(line)).collect()),
        ),
    ])
}

/// One provider/model pair out of a document, when both are non-empty.
fn binding_pair<'a>(
    doc: &'a Val,
    provider_key: &str,
    model_key: &str,
) -> Option<(&'a str, &'a str)> {
    let provider = doc.get(provider_key).and_then(Val::as_str)?;
    let model = doc.get(model_key).and_then(Val::as_str)?;
    if provider.is_empty() || model.is_empty() {
        return None;
    }
    Some((provider, model))
}

/// The actionable guidance for one record status, using only existing
/// commands and daemon operations. Order is deterministic (state first, then
/// the next action, then the binding).
fn guidance(
    record: &Val,
    phase: &str,
    outcome: &str,
    next_phase: Option<&str>,
    actual: Option<&Val>,
) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    let replacement_id = record
        .get("replacement_id")
        .and_then(Val::as_str)
        .unwrap_or("<replacement>");
    match outcome {
        "ambiguous" => lines.push(format!(
            "the handoff is parked ambiguous (an interrupted transition left an unresolved \
             retirement/start/adoption); external reconciliation is required before it can \
             advance; inspect the durable record and its transition history with `canter lane \
             status --replacement {replacement_id}`"
        )),
        "held" => {
            let reason = record
                .get("outcome_reason")
                .and_then(Val::as_str)
                .filter(|text| !text.is_empty())
                .unwrap_or("no reason recorded");
            lines.push(format!(
                "the handoff is held ({reason}); advancement is refused while held — a held \
                 record before retirement can only be invalidated (daemon \
                 `lane.replacement.cancel`) or resolved by external reconciliation; re-check it \
                 with `canter lane status --replacement {replacement_id}`"
            ));
        }
        "cancelled" => lines.push(
            "the handoff was invalidated and the source lane was never touched; request a fresh \
             handoff with `canter lane request` once the lane is verified"
                .to_string(),
        ),
        _ => {}
    }
    match (outcome, next_phase) {
        ("pending", Some("quiescing")) => lines.push(
            "next: advance the record into the `quiescing` window (daemon \
             `lane.replacement.advance`); this CLI slice exposes `lane preview`, `lane request` \
             and `lane status` only"
                .to_string(),
        ),
        ("pending", Some("checkpointed")) => lines.push(
            "next: capture the safe-boundary checkpoint (daemon `lane.checkpoint.create`) from \
             TWO identical lane observations; a mismatched pair refuses (`refusal.checkpoint.\
             changed`) and is never truncated"
                .to_string(),
        ),
        ("pending", Some("retired")) => lines.push(
            "next: retire the bound source session (daemon `lane.retire`) with the committed \
             checkpoint binding and a fresh quiescence recheck; only the record's own bound \
             session is ever signalled"
                .to_string(),
        ),
        ("pending", Some("starting")) => lines.push(
            "next: start ONE successor (daemon `lane.start`) on the same lane and worktree; \
             admission is rechecked, and a capacity refusal (`refusal.admission.cap_global` / \
             `cap_repository` / `cap_harness`) is a typed hold that spawns nothing — free \
             capacity and retry the same start (the bounded attempt counter refuses \
             `refusal.successor.attempts`)"
                .to_string(),
        ),
        ("pending", Some("adopting")) => lines.push(
            "next: adopt the committed successor (daemon `lane.adopt`) with a fresh re-query \
             identical to the recorded checkpoint state; a differing re-query refuses \
             (`refusal.successor.differs`) with the changed fields named and the recorded \
             state is never replayed as success"
                .to_string(),
        ),
        ("pending", Some("adopted")) => lines.push(
            "next: consume the retained pending completion events (daemon \
             `lane.successor.consume`); retained child workers, reviewers and gates are never \
             addressed by this handoff"
                .to_string(),
        ),
        _ => {}
    }
    if let Some(actual) = actual {
        match actual.get("status").and_then(Val::as_str) {
            Some("unknown") => lines.push(
                "the successor's actual provider/model is UNKNOWN: the bound profile declares no \
                 binding introspection, and the recorded actual is never copied from the \
                 intended pair; re-inspect with `canter lane status`, or start a new generation \
                 under a profile that declares introspection"
                    .to_string(),
            ),
            Some("fallback") => {
                let pair = |key: &str| {
                    actual
                        .get(key)
                        .and_then(Val::as_str)
                        .filter(|text| !text.is_empty())
                        .unwrap_or("unknown")
                        .to_string()
                };
                lines.push(format!(
                    "the successor answered with an AUTHORIZED fallback binding ({}/{}); the \
                     intended pair stays recorded separately — re-inspect with `canter lane \
                     status`",
                    pair("provider"),
                    pair("model")
                ));
            }
            _ => {}
        }
    }
    if phase == "adopting" && outcome == "pending" {
        lines.push(
            "the adoption has not committed: a successor that is not verifiably usable holds \
             (`refusal.successor.held`) and a process-only observation parks the record \
             ambiguous — re-check with `canter lane status`"
                .to_string(),
        );
    }
    lines
}

/// The human rendering of one plan's effect boundary list.
pub fn boundary_lines() -> Vec<String> {
    EFFECT_BOUNDARIES
        .iter()
        .map(|(phase, operation, effect)| format!("  {phase:<12} {operation:<26} {effect}"))
        .collect()
}

/// A deterministic canonical text of one value (used by tests and callers).
pub fn canonical(value: &Val) -> String {
    canonical_text(value)
}

/// The digest of a document (canonical bytes → sha256 hex).
pub fn digest_of(value: &Val) -> String {
    sha256_hex(&canonical_bytes(value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, Harness, Repository, WorkflowPin};
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    fn policy(rule: Option<&str>) -> Policy {
        Policy {
            path: PathBuf::from("/tmp/policy.toml"),
            repositories: None,
            production_confirmation: rule.map(str::to_string),
        }
    }

    fn input() -> PlanInput {
        validate_plan_input(
            "lane-orch-3",
            1,
            "sess-0001",
            "proc-0001",
            "implementer",
            "worktrees/issues/78",
            "handoff window",
        )
        .expect("valid input")
    }

    fn config(provider: &str, model: &str) -> Config {
        Config {
            path: PathBuf::from("/tmp/config.toml"),
            daemon_enabled: Some(true),
            daemon_socket: None,
            policy: None,
            repositories: vec![Repository {
                key: "widgets".to_string(),
                owner: "example-org".to_string(),
                name: "widgets".to_string(),
                origin: "https://example.invalid/example-org/widgets".to_string(),
                branch: None,
                enabled: true,
            }],
            harnesses: vec![Harness {
                key: "lane-orch-1".to_string(),
                kind: "pi".to_string(),
                executable: "herdr".to_string(),
                env_allow: vec![],
                provider: Some(provider.to_string()),
                model: Some(model.to_string()),
                fallback: vec!["alt/backup".to_string()],
                secret_env: vec![],
                limits: vec![],
                binding_introspection: false,
                skills: Vec::new(),
            }],
            workflows: vec![WorkflowPin {
                key: "doctrine".to_string(),
                id: "fleet-doctrine-1".to_string(),
                hash: "a".repeat(64),
            }],
            skills: Vec::new(),
        }
    }

    #[test]
    fn plan_digest_is_deterministic_and_input_sensitive() {
        let plan = LanePlan::build(input(), None);
        let again = LanePlan::build(input(), None);
        assert_eq!(plan.digest, again.digest, "same inputs, same digest");
        assert!(formats::is_hex64(&plan.digest));
        assert_eq!(plan.replacement_id(), plan.replacement_id());

        let mut changed = input();
        changed.reason = "another window".to_string();
        let other = LanePlan::build(changed, None);
        assert_ne!(plan.digest, other.digest, "the reason is bound");
    }

    #[test]
    fn profile_revision_is_part_of_the_digest() {
        let mut config = config("acme", "turbo-9000");
        let env = BTreeMap::new();
        let plan = LanePlan::build(
            input(),
            ProfileBinding::from_config(&config, "lane-orch-1", &env)
                .expect("the role skills resolve"),
        );
        assert!(plan.profile.is_some());
        // A moved provider (a new revision) changes the digest: a previously
        // reviewed plan no longer binds.
        config.harnesses[0].provider = Some("other".to_string());
        let moved = LanePlan::build(
            input(),
            ProfileBinding::from_config(&config, "lane-orch-1", &env)
                .expect("the role skills resolve"),
        );
        assert_ne!(plan.digest, moved.digest, "profile revision is bound");
    }

    #[test]
    fn requirement_follows_the_policy_overlay() {
        assert_eq!(requirement(None), "digest_or_blanket");
        assert_eq!(requirement(Some(&policy(None))), "digest_or_blanket");
        assert_eq!(requirement(Some(&policy(Some("tty")))), "digest");
        assert_eq!(requirement(Some(&policy(Some("deny")))), "denied");
    }

    #[test]
    fn blanket_confirmation_is_refused_under_a_declared_policy() {
        let digest = "a".repeat(64);
        // Unconstrained: both modes are accepted.
        assert!(confirm(None, &Confirmation::Blanket, &digest).is_ok());
        assert!(confirm(None, &Confirmation::Digest(digest.clone()), &digest).is_ok());
        // tty: the blanket --yes is refused, the digest binds.
        let tty = policy(Some("tty"));
        let err = confirm(Some(&tty), &Confirmation::Blanket, &digest)
            .expect_err("blanket must not bypass the policy");
        assert_eq!(err.code, "refusal.confirmation.policy");
        assert!(confirm(Some(&tty), &Confirmation::Digest(digest.clone()), &digest).is_ok());
        // deny: every mode is refused.
        let deny = policy(Some("deny"));
        for mode in [Confirmation::Blanket, Confirmation::Digest(digest.clone())] {
            let err = confirm(Some(&deny), &mode, &digest).expect_err("deny refuses");
            assert_eq!(err.code, "refusal.policy.production");
        }
    }

    #[test]
    fn a_mismatching_digest_is_a_stale_plan() {
        let digest = "a".repeat(64);
        let err = confirm(None, &Confirmation::Digest("b".repeat(64)), &digest)
            .expect_err("stale digest");
        assert_eq!(err.code, "refusal.plan.stale");
    }

    #[test]
    fn invalid_inputs_refuse_typed() {
        let cases: [(PlanInput, &str); 5] = [
            (
                PlanInput {
                    lane_id: "Bad Lane".to_string(),
                    ..input()
                },
                "usage.lane_id",
            ),
            (
                PlanInput {
                    generation: 0,
                    ..input()
                },
                "usage.lane_generation",
            ),
            (
                PlanInput {
                    session: "no/slash".to_string(),
                    ..input()
                },
                "usage.lane_session",
            ),
            (
                PlanInput {
                    worktree: "/host/absolute".to_string(),
                    ..input()
                },
                "usage.lane_worktree",
            ),
            (
                PlanInput {
                    reason: String::new(),
                    ..input()
                },
                "usage.lane_reason",
            ),
        ];
        for (input, expected) in cases {
            let err = validate_plan_input(
                &input.lane_id,
                input.generation,
                &input.session,
                &input.process,
                &input.role,
                &input.worktree,
                &input.reason,
            )
            .expect_err("invalid");
            assert_eq!(err.code, expected);
        }
    }

    #[test]
    fn retained_view_reads_the_checkpoint_orchestration() {
        let snapshot = object(vec![
            ("role", string("orchestrator")),
            (
                "orchestration",
                object(vec![
                    ("workers", Val::Arr(vec![string("rp_1111111111111111")])),
                    ("reviewers", Val::Arr(vec![string("rp_2222222222222222")])),
                    (
                        "pending_events",
                        Val::Arr(vec![string("worker-finished:lane-8")]),
                    ),
                ]),
            ),
        ]);
        let retained = RetainedView::from_checkpoint_snapshot(&snapshot);
        assert!(retained.captured);
        assert_eq!(retained.workers, vec!["rp_1111111111111111"]);
        assert_eq!(retained.reviewers, vec!["rp_2222222222222222"]);
        assert_eq!(retained.pending_gates, vec!["worker-finished:lane-8"]);
        // A capture without the orchestrator block retains nothing.
        let plain =
            RetainedView::from_checkpoint_snapshot(&object(vec![("role", string("implementer"))]));
        assert!(!plain.captured);
        assert!(plain.workers.is_empty() && plain.pending_gates.is_empty());
    }

    fn status_fixture(phase: &str, outcome: &str, next: &str) -> Val {
        object(vec![
            (
                "replacement",
                object(vec![
                    ("replacement_id", string("rp_0123456789abcdef")),
                    ("lane_id", string("lane-orch-3")),
                    ("generation", integer(1)),
                    ("successor_generation", integer(2)),
                    ("phase", string(phase)),
                    ("outcome", string(outcome)),
                    (
                        "outcome_reason",
                        if outcome == "pending" {
                            string("")
                        } else {
                            string("interrupted transition; external reconciliation required")
                        },
                    ),
                    ("next_allowed", string(next)),
                    (
                        "source",
                        object(vec![
                            ("session", string("sess-0001")),
                            ("process", string("proc-0001")),
                            ("role", string("implementer")),
                            ("worktree", string("worktrees/issues/78")),
                        ]),
                    ),
                ]),
            ),
            (
                "profile",
                object(vec![
                    (
                        "profile",
                        object(vec![
                            ("provider", string("acme")),
                            ("model", string("turbo-9000")),
                        ]),
                    ),
                    ("revision", string(&"c".repeat(64))),
                ]),
            ),
            ("successor", null()),
            (
                "history",
                Val::Arr(vec![object(vec![
                    ("from_phase", string("checkpointed")),
                    ("to_phase", string(phase)),
                    ("reason", string("")),
                    ("at", string("2026-09-12T00:00:00Z")),
                ])]),
            ),
        ])
    }

    #[test]
    fn status_reports_intended_and_next_action() {
        let status = status_fixture("retired", "pending", "starting");
        let doc = status_document(&status, &RetainedView::default());
        assert_eq!(doc.get("phase").and_then(Val::as_str), Some("retired"));
        assert_eq!(doc.get("blocker").and_then(Val::as_str), None);
        let intended = doc.get("intended").expect("intended");
        assert_eq!(intended.get("provider").and_then(Val::as_str), Some("acme"));
        let next = doc.get("next").expect("next");
        assert_eq!(next.get("phase").and_then(Val::as_str), Some("starting"));
        assert_eq!(
            next.get("operation").and_then(Val::as_str),
            Some("lane.start")
        );
        assert_eq!(
            next.get("exposed_by_cli").and_then(Val::as_bool),
            Some(false)
        );
        let last = doc.get("last_transition").expect("transition");
        assert_eq!(last.get("to").and_then(Val::as_str), Some("retired"));
        let guidance = doc
            .get("guidance")
            .and_then(Val::as_array)
            .expect("guidance");
        assert!(
            guidance.iter().any(|line| line
                .as_str()
                .unwrap_or_default()
                .contains("refusal.admission.cap_global")),
            "a retired record must give the capacity-hold guidance: {guidance:?}"
        );
    }

    #[test]
    fn ambiguous_and_held_records_give_guided_actions() {
        let ambiguous = status_fixture("checkpointed", "ambiguous", "requested");
        let doc = status_document(&ambiguous, &RetainedView::default());
        assert_eq!(
            doc.get("blocker").and_then(Val::as_str),
            Some("interrupted transition; external reconciliation required")
        );
        let guidance = doc
            .get("guidance")
            .and_then(Val::as_array)
            .expect("guidance");
        assert!(
            guidance.iter().any(|line| line
                .as_str()
                .unwrap_or_default()
                .contains("external reconciliation")),
            "ambiguous guidance: {guidance:?}"
        );
        assert!(
            guidance
                .iter()
                .all(|line| !line.as_str().unwrap_or_default().contains("--resume")),
            "guidance names only existing commands"
        );

        let held = status_fixture("retired", "held", "starting");
        let doc = status_document(&held, &RetainedView::default());
        let guidance = doc
            .get("guidance")
            .and_then(Val::as_array)
            .expect("guidance");
        assert!(
            guidance.iter().any(|line| line
                .as_str()
                .unwrap_or_default()
                .contains("lane.replacement.cancel")),
            "held guidance: {guidance:?}"
        );
    }

    #[test]
    fn unknown_actual_binding_gives_guidance_and_never_copies_the_intended_pair() {
        let mut status = status_fixture("adopting", "pending", "adopted");
        let successor = object(vec![(
            "evidence",
            object(vec![(
                "binding",
                object(vec![
                    ("status", string("unknown")),
                    ("revision", string(&"c".repeat(64))),
                    ("introspection", bool_(false)),
                    (
                        "intended",
                        object(vec![
                            ("provider", string("acme")),
                            ("model", string("turbo-9000")),
                        ]),
                    ),
                    ("actual", null()),
                ]),
            )]),
        )]);
        if let Val::Obj(map) = &mut status {
            map.insert("successor".to_string(), successor);
        }
        let doc = status_document(&status, &RetainedView::default());
        let actual = doc.get("actual").expect("actual");
        assert_eq!(actual.get("status").and_then(Val::as_str), Some("unknown"));
        assert_eq!(actual.get("provider"), Some(&Val::Null), "never copied");
        assert_eq!(actual.get("model"), Some(&Val::Null), "never copied");
        let guidance = doc
            .get("guidance")
            .and_then(Val::as_array)
            .expect("guidance");
        assert!(
            guidance
                .iter()
                .any(|line| line.as_str().unwrap_or_default().contains("UNKNOWN")),
            "unknown-binding guidance: {guidance:?}"
        );
    }

    #[test]
    fn plan_document_carries_the_boundaries_and_the_digest() {
        let plan = LanePlan::build(input(), None);
        let doc = plan.document(None, &RetainedView::default(), None);
        assert_eq!(
            doc.get("schema").and_then(Val::as_str),
            Some(LANE_PLAN_SCHEMA)
        );
        assert_eq!(
            doc.get("digest").and_then(Val::as_str),
            Some(plan.digest.as_str())
        );
        let boundaries = doc.get("boundaries").expect("boundaries");
        assert_eq!(
            boundaries.get("mutates").and_then(Val::as_bool),
            Some(false)
        );
        let effects = boundaries
            .get("effects")
            .and_then(Val::as_array)
            .expect("effects");
        assert_eq!(effects.len(), HANDOFF_PHASES.len());
        for (index, phase) in HANDOFF_PHASES.iter().enumerate() {
            assert_eq!(
                effects[index].get("phase").and_then(Val::as_str),
                Some(*phase)
            );
        }
        let authorization = doc.get("authorization").expect("authorization");
        assert_eq!(
            authorization.get("requirement").and_then(Val::as_str),
            Some("digest_or_blanket")
        );
        assert_eq!(authorization.get("policy"), Some(&Val::Null));
    }
}
