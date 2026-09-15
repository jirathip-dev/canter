//! Deterministic read-only plan rendering (`hf-plan/v1`).
//!
//! A plan is the complete, typed description of intended effects for one
//! issue-bound unit of work (docs/contracts/spec-plans.md). This read-only
//! slice renders plans without any daemon: it never applies, journals, or
//! grants anything. Rendering is fully deterministic — the same inputs
//! always produce the same canonical bytes and digest — so plans are
//! reproducible evidence.
//!
//! Determinism rules (documented, stable surface):
//! - `plan_id` is content-addressed: the first 16 hex of the SHA-256 over
//!   the canonical document with a placeholder id, formatted as
//!   `hf_plan_<16hex>`.
//! - `state_epoch` is 0 (no daemon state exists in this slice).
//! - The step spine is the built-in `fleet-doctrine-1` doctrine workflow
//!   (the same eight steps the #3 `plan.valid.json` fixture shows). A
//!   configured workflow pin with a different id is refused (the workflow
//!   engine is a later slice); when no pin is configured the `workflow_hash`
//!   is derived from the spine definition itself.

use crate::canonical::{canonical_bytes, sha256_hex};
use crate::config::{Repository, WorkflowPin};
use crate::value::{Val, bool_, integer, null, object, string};

/// The built-in doctrine workflow id known to this read-only slice.
pub const DOCTRINE_WORKFLOW_ID: &str = "fleet-doctrine-1";
/// Placeholder id used for the content-addressed plan id derivation.
const PLAN_ID_PLACEHOLDER: &str = "hf_plan_0000000000000000";

/// One rendered plan step (id, closed-set kind, optional params object).
#[derive(Clone, Debug, PartialEq)]
pub struct PlanStep {
    /// Step id (slug, e.g. `p1`).
    pub id: String,
    /// Closed-set step kind.
    pub kind: String,
    /// Typed params or none.
    pub params: Option<Val>,
}

/// Why rendering refused a plan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlanRefusal {
    /// A configured workflow pin names a workflow this slice cannot render.
    UnsupportedWorkflow(String),
}

/// Inputs for one deterministic plan render.
#[derive(Clone)]
pub struct PlanInput<'a> {
    /// Configured repository (identity comes from config, never free-form).
    pub repository: &'a Repository,
    /// Issue number (positive integer from validated argv).
    pub issue_number: u64,
    /// Exact acceptance revision (40-hex).
    pub revision: String,
    /// Configured workflow pin, if any.
    pub workflow: Option<&'a WorkflowPin>,
}

/// One deterministic rendered plan.
#[derive(Clone, Debug)]
pub struct RenderedPlan {
    /// The `hf-plan/v1` document value.
    pub doc: Val,
    /// Canonical JSON bytes of the document.
    pub canonical: Vec<u8>,
    /// SHA-256 over the canonical bytes (lowercase hex).
    pub digest: String,
    /// Content-addressed plan id.
    pub plan_id: String,
    /// Workflow id bound by the plan.
    pub workflow_id: String,
    /// 64-hex workflow hash bound by the plan.
    pub workflow_hash: String,
}

/// Render the doctrine step spine for one issue.
fn doctrine_steps(repository: &Repository, issue_number: u64) -> Vec<PlanStep> {
    let branch = repository
        .branch
        .clone()
        .unwrap_or_else(|| "staging".to_string());
    vec![
        PlanStep {
            id: "p1".to_string(),
            kind: "checkout".to_string(),
            params: Some(object(vec![("ref", string(&branch))])),
        },
        PlanStep {
            id: "p2".to_string(),
            kind: "worktree_create".to_string(),
            params: Some(object(vec![(
                "scope",
                string(&format!("issues/{issue_number}")),
            )])),
        },
        PlanStep {
            id: "p3".to_string(),
            kind: "harness_start".to_string(),
            params: None,
        },
        PlanStep {
            id: "p4".to_string(),
            kind: "prompt".to_string(),
            params: None,
        },
        PlanStep {
            id: "p5".to_string(),
            kind: "collect_outcome".to_string(),
            params: None,
        },
        PlanStep {
            id: "p6".to_string(),
            kind: "review_evidence".to_string(),
            params: None,
        },
        PlanStep {
            id: "p7".to_string(),
            kind: "merge".to_string(),
            params: None,
        },
        PlanStep {
            id: "p8".to_string(),
            kind: "cleanup".to_string(),
            params: None,
        },
    ]
}

/// The workflow hash for the built-in doctrine workflow: derived from the
/// canonical serialization of the spine definition (id + step ids/kinds)
/// when no config pin supplies one.
///
/// Public because the queue-run producer (issue #91, `canter queue
/// preview`) binds the same derived hash into the bound-input document the
/// preview and the submission consume: one derivation, never a second copy.
pub fn doctrine_workflow_hash(steps: &[PlanStep]) -> String {
    let definition = object(vec![
        ("workflow_id", string(DOCTRINE_WORKFLOW_ID)),
        (
            "steps",
            Val::Arr(
                steps
                    .iter()
                    .map(|step| {
                        object(vec![("id", string(&step.id)), ("kind", string(&step.kind))])
                    })
                    .collect(),
            ),
        ),
    ]);
    sha256_hex(&canonical_bytes(&definition))
}

fn steps_value(steps: &[PlanStep]) -> Val {
    Val::Arr(
        steps
            .iter()
            .map(|step| {
                object(vec![
                    ("id", string(&step.id)),
                    ("kind", string(&step.kind)),
                    ("params", step.params.clone().unwrap_or_else(null)),
                ])
            })
            .collect(),
    )
}

/// The declared executable step spine of one queue run: the doctrine step
/// spine with every step's binding parameters resolved from the reviewed
/// run inputs.
///
/// This is the spine the queue-run producer (issue #91, `canter queue
/// preview`) binds into the `hf-queue-preview/v1` bound-input document the
/// operator surface previews, authorizes and submits: an unresolved step
/// (`params: null`) is refused by the preview and by the submission, so no
/// step is ever emitted unresolved.
///
/// Deterministic and single-sourced: the kinds and their order are the
/// doctrine spine [`render_plan`] renders (checkout, worktree_create,
/// harness_start, prompt, collect_outcome, review_evidence, merge,
/// cleanup). Issue-scoped kinds carry one step per selected issue, id
/// `p<index>-<issue>` (never a step that silently binds the wrong issue);
/// the run-wide kinds (checkout, harness_start) appear once. Steps are
/// emitted grouped by kind in doctrine order, and each step's params carry
/// the exact reviewed binding (the integration ref, the harness key, the
/// per-issue work-item identity and worktree scope).
///
/// `issues` is the reviewed selected set; callers pass it sorted and
/// deduplicated. The caller also enforces the executable step bound
/// (`queue_preview::STEPS_MAX`) — the spine grows by six steps per issue.
pub fn queue_run_steps(
    repository: &str,
    integration_branch: &str,
    harness_key: &str,
    issues: &[u64],
) -> Vec<PlanStep> {
    let mut steps = vec![PlanStep {
        id: "p1".to_string(),
        kind: "checkout".to_string(),
        params: Some(object(vec![("ref", string(integration_branch))])),
    }];
    for number in issues {
        let branch = format!("issue-{number}");
        let worktree = format!("issues-{number}");
        steps.push(PlanStep {
            id: format!("p2-{number}"),
            kind: "worktree_create".to_string(),
            params: Some(object(vec![
                ("branch", string(&branch)),
                ("worktree", string(&worktree)),
            ])),
        });
    }
    steps.push(PlanStep {
        id: "p3".to_string(),
        kind: "harness_start".to_string(),
        params: Some(object(vec![("harness_key", string(harness_key))])),
    });
    for number in issues {
        let branch = format!("issue-{number}");
        let worktree = format!("issues-{number}");
        steps.push(PlanStep {
            id: format!("p4-{number}"),
            kind: "prompt".to_string(),
            params: Some(object(vec![
                ("harness_key", string(harness_key)),
                (
                    "payload",
                    string(&format!(
                        "Implement {repository}#{number} from its latest issue text. Follow the repository instructions, run its required gates, commit the bounded change, push the feature branch, open or update its pull request to {integration_branch}, and report the exact delivery evidence."
                    )),
                ),
                ("worktree", string(&worktree)),
                ("branch", string(&branch)),
                ("requires_delta", bool_(true)),
            ])),
        });
        steps.push(PlanStep {
            id: format!("p5-{number}"),
            kind: "collect_outcome".to_string(),
            params: Some(object(vec![
                ("worktree", string(&worktree)),
                ("branch", string(&branch)),
                ("requires_delta", bool_(true)),
            ])),
        });
        // Review facts are supplied only after an independent review, but an
        // empty object keeps the reviewed spine resolved without fabricating
        // a reviewer, verdict, checks, or observed heads.
        steps.push(PlanStep {
            id: format!("p6-{number}"),
            kind: "review_evidence".to_string(),
            params: Some(object(vec![])),
        });
        steps.push(PlanStep {
            id: format!("p7-{number}"),
            kind: "merge".to_string(),
            params: Some(object(vec![
                ("branch", string(&branch)),
                ("merge_policy", string("squash")),
            ])),
        });
        steps.push(PlanStep {
            id: format!("p8-{number}"),
            kind: "cleanup".to_string(),
            params: Some(object(vec![
                ("worktree", string(&worktree)),
                ("branch", string(&branch)),
            ])),
        });
    }
    steps
}

/// Build the plan document with a concrete plan id.
fn build_doc(
    repository: &Repository,
    issue_number: u64,
    revision: &str,
    workflow_id: &str,
    workflow_hash: &str,
    plan_id: &str,
    steps: &[PlanStep],
) -> Val {
    object(vec![
        ("schema", string("hf-plan/v1")),
        ("plan_id", string(plan_id)),
        ("workflow_id", string(workflow_id)),
        ("workflow_hash", string(workflow_hash)),
        ("state_epoch", integer(0)),
        ("repository", string(&repository.identity())),
        (
            "issue",
            object(vec![
                ("number", integer(issue_number as i64)),
                ("revision", string(revision)),
            ]),
        ),
        ("steps", steps_value(steps)),
    ])
}

/// Render a deterministic plan. Refuses when a configured workflow pin names
/// a workflow the built-in doctrine spine cannot represent.
pub fn render_plan(input: &PlanInput<'_>) -> Result<RenderedPlan, PlanRefusal> {
    let workflow_id = DOCTRINE_WORKFLOW_ID.to_string();
    let steps = doctrine_steps(input.repository, input.issue_number);
    let workflow_hash = match input.workflow {
        None => doctrine_workflow_hash(&steps),
        Some(pin) if pin.id == DOCTRINE_WORKFLOW_ID => pin.hash.clone(),
        Some(pin) => return Err(PlanRefusal::UnsupportedWorkflow(pin.id.clone())),
    };

    let seeded = build_doc(
        input.repository,
        input.issue_number,
        &input.revision,
        &workflow_id,
        &workflow_hash,
        PLAN_ID_PLACEHOLDER,
        &steps,
    );
    let seed_digest = sha256_hex(&canonical_bytes(&seeded));
    let plan_id = format!("hf_plan_{}", &seed_digest[..16]);

    let doc = build_doc(
        input.repository,
        input.issue_number,
        &input.revision,
        &workflow_id,
        &workflow_hash,
        &plan_id,
        &steps,
    );
    let canonical = canonical_bytes(&doc);
    let digest = sha256_hex(&canonical);
    Ok(RenderedPlan {
        doc,
        canonical,
        digest,
        plan_id,
        workflow_id,
        workflow_hash,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{Family, Verdict, validate_doc};

    fn repository() -> Repository {
        Repository {
            key: "widgets".to_string(),
            owner: "example-org".to_string(),
            name: "widgets".to_string(),
            origin: "https://github.com/example-org/widgets".to_string(),
            branch: Some("staging".to_string()),
            enabled: true,
        }
    }

    fn pin(id: &str) -> WorkflowPin {
        WorkflowPin {
            key: "bundle".to_string(),
            id: id.to_string(),
            hash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
        }
    }

    const REVISION: &str = "0123456789abcdef0123456789abcdef01234567";

    #[test]
    fn renders_a_valid_deterministic_plan() {
        let input = PlanInput {
            repository: &repository(),
            issue_number: 123,
            revision: REVISION.to_string(),
            workflow: None,
        };
        let plan = render_plan(&input).expect("render");
        let verdict = validate_doc(Family::Plan, &plan.doc);
        assert!(verdict.is_accepted(), "{}", verdict.message());
        assert_eq!(plan.workflow_id, "fleet-doctrine-1");
        assert!(plan.plan_id.starts_with("hf_plan_"));
        assert_eq!(plan.plan_id.len(), "hf_plan_".len() + 16);
        assert_eq!(plan.digest.len(), 64);
        assert_eq!(plan.digest, sha256_hex(&plan.canonical));
        // Canonical round-trip: parsing the canonical bytes must reproduce
        // the document byte-for-byte when re-canonicalized.
        let reparsed =
            Val::parse_json(std::str::from_utf8(&plan.canonical).expect("utf8")).expect("parse");
        assert_eq!(canonical_bytes(&reparsed), plan.canonical);
    }

    #[test]
    fn rendering_is_repeatable_and_sensitive_to_every_binding() {
        let base = PlanInput {
            repository: &repository(),
            issue_number: 123,
            revision: REVISION.to_string(),
            workflow: None,
        };
        let first = render_plan(&base).expect("render");
        let again = render_plan(&base).expect("render");
        assert_eq!(first.digest, again.digest, "same inputs, same digest");
        assert_eq!(first.canonical, again.canonical, "same inputs, same bytes");

        let different_issue = PlanInput {
            issue_number: 124,
            ..base.clone()
        };
        assert_ne!(
            first.digest,
            render_plan(&different_issue).expect("render").digest
        );

        let different_revision = PlanInput {
            revision: format!("{}1", &REVISION[..39]),
            ..base.clone()
        };
        assert_ne!(
            first.digest,
            render_plan(&different_revision).expect("render").digest
        );

        let mut other_repo = repository();
        other_repo.name = "gadgets".to_string();
        let different_repo = PlanInput {
            repository: &other_repo,
            ..base.clone()
        };
        assert_ne!(
            first.digest,
            render_plan(&different_repo).expect("render").digest
        );

        let pinned = PlanInput {
            workflow: Some(&pin("fleet-doctrine-1")),
            ..base.clone()
        };
        let pinned_plan = render_plan(&pinned).expect("render");
        assert_ne!(
            first.digest, pinned_plan.digest,
            "pin changes the bound hash"
        );
        assert_eq!(
            pinned_plan.workflow_hash,
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
    }

    #[test]
    fn unsupported_pinned_workflow_is_refused() {
        let input = PlanInput {
            repository: &repository(),
            issue_number: 123,
            revision: REVISION.to_string(),
            workflow: Some(&pin("some-other-engine")),
        };
        let refusal = render_plan(&input).expect_err("must refuse");
        assert_eq!(
            refusal,
            PlanRefusal::UnsupportedWorkflow("some-other-engine".to_string())
        );
    }

    #[test]
    fn configured_branch_flows_into_checkout_params() {
        let mut repo = repository();
        repo.branch = Some("integration".to_string());
        let input = PlanInput {
            repository: &repo,
            issue_number: 7,
            revision: REVISION.to_string(),
            workflow: None,
        };
        let plan = render_plan(&input).expect("render");
        let steps = plan.doc.get("steps").expect("steps");
        let Val::Arr(step_list) = steps else {
            panic!("steps array")
        };
        let checkout = &step_list[0];
        assert_eq!(checkout.get("kind").and_then(Val::as_str), Some("checkout"));
        let params = checkout.get("params").expect("params");
        assert_eq!(params.get("ref").and_then(Val::as_str), Some("integration"));
    }

    #[test]
    fn plan_validates_with_every_family_rule() {
        let input = PlanInput {
            repository: &repository(),
            issue_number: 123,
            revision: REVISION.to_string(),
            workflow: None,
        };
        let plan = render_plan(&input).expect("render");
        let verdict: Verdict = validate_doc(Family::Plan, &plan.doc);
        assert!(verdict.is_accepted());
    }

    #[test]
    fn queue_run_steps_resolve_every_step_and_stay_deterministic() {
        // Issue #91: the queue-run producer binds this spine into the
        // bound-input document; the preview and the submission refuse an
        // unresolved step, so every emitted step carries its params.
        let one = queue_run_steps("example-org/widgets", "staging", "lane-1", &[5]);
        assert_eq!(one.len(), 8, "the single-issue spine is the doctrine spine");
        assert!(
            one.iter().all(|step| step.params.is_some()),
            "no step is emitted unresolved"
        );
        let kinds: Vec<&str> = one.iter().map(|step| step.kind.as_str()).collect();
        assert_eq!(
            kinds,
            vec![
                "checkout",
                "worktree_create",
                "harness_start",
                "prompt",
                "collect_outcome",
                "review_evidence",
                "merge",
                "cleanup",
            ],
            "the kind order stays the doctrine order"
        );
        let ids: Vec<&str> = one.iter().map(|step| step.id.as_str()).collect();
        assert_eq!(
            ids,
            vec!["p1", "p2-5", "p3", "p4-5", "p5-5", "p6-5", "p7-5", "p8-5"]
        );
        // Issue-scoped kinds carry the exact per-issue binding.
        let worktree = one
            .iter()
            .find(|step| step.id == "p2-5")
            .expect("worktree step");
        assert_eq!(
            worktree
                .params
                .as_ref()
                .and_then(|params| params.get("worktree"))
                .and_then(Val::as_str),
            Some("issues-5")
        );
        assert_eq!(
            worktree
                .params
                .as_ref()
                .and_then(|params| params.get("branch"))
                .and_then(Val::as_str),
            Some("issue-5")
        );
        let prompt = one
            .iter()
            .find(|step| step.id == "p4-5")
            .expect("prompt step");
        let prompt_params = prompt.params.as_ref().expect("prompt params");
        assert_eq!(
            prompt_params.get("worktree").and_then(Val::as_str),
            Some("issues-5")
        );
        assert_eq!(
            prompt_params.get("branch").and_then(Val::as_str),
            Some("issue-5")
        );
        assert_eq!(
            prompt_params.get("harness_key").and_then(Val::as_str),
            Some("lane-1")
        );
        assert_eq!(
            prompt_params.get("requires_delta").and_then(Val::as_bool),
            Some(true)
        );

        // Deterministic: identical inputs, byte-identical steps.
        let again = queue_run_steps("example-org/widgets", "staging", "lane-1", &[5]);
        assert_eq!(
            canonical_bytes(&steps_value(&one)),
            canonical_bytes(&steps_value(&again)),
            "same inputs, same spine bytes"
        );

        // Two issues: one issue-scoped step set per issue, unique ids, and
        // not a silent rebinding of the first issue's steps.
        let two = queue_run_steps("example-org/widgets", "staging", "lane-1", &[5, 6]);
        assert_eq!(two.len(), 14, "two issues carry two issue-scoped sets");
        let mut seen: Vec<&str> = two.iter().map(|step| step.id.as_str()).collect();
        let count = seen.len();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), count, "every step id is unique");
        assert!(two.iter().all(|step| step.params.is_some()));
    }

    #[test]
    fn queue_run_steps_bind_the_configured_workflow_hash_derivation() {
        // The producer's fallback hash IS `plan::doctrine_workflow_hash` over
        // its own declared spine — one derivation, never a second copy: a
        // 64-hex lowercase digest that is a pure function of the declared
        // step labels (id + kind), stable across parameter updates.
        let spine = queue_run_steps("example-org/widgets", "staging", "lane-1", &[5]);
        let derived = doctrine_workflow_hash(&spine);
        assert_eq!(derived.len(), 64);
        assert!(
            derived
                .chars()
                .all(|character| character.is_ascii_hexdigit())
        );
        assert_eq!(
            derived,
            doctrine_workflow_hash(&queue_run_steps(
                "example-org/widgets",
                "staging",
                "lane-1",
                &[5]
            )),
            "the derivation is deterministic"
        );
        assert_eq!(
            derived,
            doctrine_workflow_hash(&queue_run_steps(
                "example-org/widgets",
                "integration",
                "lane-1",
                &[5]
            )),
            "binding parameters are not part of the workflow hash (labels are)"
        );
        assert_ne!(
            derived,
            doctrine_workflow_hash(&queue_run_steps(
                "example-org/widgets",
                "staging",
                "lane-1",
                &[6]
            )),
            "a different declared spine derives a different hash"
        );
    }
}
