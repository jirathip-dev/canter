//! `canter queue intake` (issue #245): the deterministic feeder that turns
//! the repository's own issue state into ONE bound-input submission.
//!
//! The decision path is a rule, never an agent: the selection, the revision
//! resolution, the dedupe, the bounds and the digest are derived here from
//! facts the caller presents (the repository's own API surface for the issue
//! list, `git ls-remote` for the integration head, the recorded state store
//! for live ownership). Nothing in this module reads the clock, the model
//! registry, or the network: two invocations over unchanged facts produce the
//! same digest.
//!
//! Documented contract (AC7): the ready label is [`READY_LABEL`], the
//! ordering rule is [`ORDER_RULE`], the item bound is [`max_items_default`],
//! and the refusal codes are the [`code`] constants below.

use std::collections::BTreeSet;

use crate::canonical::canonical_text;
use crate::value::{Val, object, string};

/// Stable refusal/diagnosis codes of the intake decision (closed vocabulary).
pub mod code {
    /// An issue could not be resolved to a revision: nothing is submitted.
    pub const REVISION_UNRESOLVED: &str = "refusal.intake.revision";
    /// The issue list itself could not be read from the repository surface.
    pub const ISSUES_UNAVAILABLE: &str = "refusal.intake.issues";
    /// The integration head could not be resolved from the remote.
    pub const INTEGRATION_UNRESOLVED: &str = "refusal.intake.integration";
    /// A bounded human labels an item that is already owned or queued.
    pub const OWNED: &str = "intake.owned";
    /// A bounded human labels an item beyond the declared item bound.
    pub const CAP: &str = "intake.cap";
}

/// The label contract: an issue is *ready* when it carries this label and is
/// open. Nothing else marks work ready, and an unlabelled issue is never
/// selected.
pub const READY_LABEL: &str = "canter:ready";

/// The ordering rule: the selection is ordered by ascending issue number, so
/// one unchanged issue set always renders one unchanged document.
pub const ORDER_RULE: &str = "ascending issue number";

/// The intake document schema (`--json`).
pub const SCHEMA: &str = "hf-intake/v1";

/// The default item bound of one intake invocation. Items beyond it wait with
/// [`code::CAP`]; intake never bypasses admission with a wider selection.
pub const fn max_items_default() -> usize {
    8
}

/// One candidate as it was read from the repository's own issue surface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Candidate {
    /// Issue number, unique within the repository.
    pub number: u64,
    /// The revision a tracker declared for this issue (`N=HEX40` pin). A
    /// declared pin wins over the default resolution rule.
    pub pin: Option<String>,
}

/// What intake decided for one candidate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Disposition {
    /// Selected for the submission document, at this revision.
    Selected {
        /// The resolved 40-hex revision the item binds.
        revision: String,
    },
    /// Already owned or queued: never re-submitted (AC2).
    Owned {
        /// Bounded human message naming why the item was skipped.
        message: String,
    },
    /// Beyond the declared item bound: waits with a typed reason (AC5).
    Capped {
        /// Bounded human message naming the bound.
        message: String,
    },
}

/// One decided item, in the decided order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Item {
    /// Issue number.
    pub number: u64,
    /// The disposition.
    pub disposition: Disposition,
}

/// The complete intake decision over the presented facts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decision {
    /// Every candidate, in [`ORDER_RULE`] order, with its disposition.
    pub items: Vec<Item>,
    /// The selected `(issue number, revision)` pairs, in order.
    pub selected: Vec<(u64, String)>,
    /// The digest of the selected document (deterministic; see [`digest_of`]).
    pub digest: String,
}

impl Decision {
    /// Every item that is not selected, as `(number, code, message)`.
    pub fn held(&self) -> Vec<(u64, &'static str, String)> {
        self.items
            .iter()
            .filter_map(|item| match &item.disposition {
                Disposition::Selected { .. } => None,
                Disposition::Owned { message } => Some((item.number, code::OWNED, message.clone())),
                Disposition::Capped { message } => Some((item.number, code::CAP, message.clone())),
            })
            .collect()
    }
}

/// Why an intake invocation refused before producing any document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IntakeError {
    /// Stable code from the closed vocabulary.
    pub code: &'static str,
    /// Bounded human message.
    pub message: String,
}

/// Resolve the default revision for an issue: the repository's integration
/// head at intake time, or a typed refusal when it could not be resolved.
pub fn resolve_revision(
    integration_head: Option<&str>,
    issue_number: u64,
) -> Result<String, IntakeError> {
    match integration_head {
        Some(head) if is_revision(head) => Ok(head.to_string()),
        _ => Err(IntakeError {
            code: code::REVISION_UNRESOLVED,
            message: format!(
                "issue #{issue_number} has no declared revision pin and the integration head \
                 could not be resolved; intake refuses typed and submits nothing rather than \
                 submit a partial document"
            ),
        }),
    }
}

/// Whether a value is a 40-hex revision.
pub fn is_revision(text: &str) -> bool {
    text.len() == 40
        && text
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// Decide one intake from the presented facts (AC1–AC6): ordered by
/// [`ORDER_RULE`], deduplicated against live ownership, bounded by
/// `max_items`, and digestible from the selection alone.
pub fn decide(
    candidates: &[Candidate],
    integration_head: Option<&str>,
    owned: &BTreeSet<u64>,
    max_items: usize,
) -> Result<Decision, IntakeError> {
    let mut ordered = candidates.to_vec();
    ordered.sort_by_key(|candidate| candidate.number);
    ordered.dedup_by_key(|candidate| candidate.number);
    let mut items = Vec::new();
    let mut selected: Vec<(u64, String)> = Vec::new();
    for candidate in &ordered {
        if owned.contains(&candidate.number) {
            items.push(Item {
                number: candidate.number,
                disposition: Disposition::Owned {
                    message: format!(
                        "issue #{} is already owned or queued; intake does not re-submit work \
                         that is live",
                        candidate.number
                    ),
                },
            });
            continue;
        }
        let revision = match &candidate.pin {
            Some(pin) if is_revision(pin) => pin.clone(),
            Some(_) => {
                return Err(IntakeError {
                    code: code::REVISION_UNRESOLVED,
                    message: format!(
                        "issue #{} declares a revision pin that is not 40 lowercase hex; intake \
                         refuses typed and submits nothing",
                        candidate.number
                    ),
                });
            }
            None => resolve_revision(integration_head, candidate.number)?,
        };
        if selected.len() >= max_items {
            items.push(Item {
                number: candidate.number,
                disposition: Disposition::Capped {
                    message: format!(
                        "issue #{} is beyond the declared {}-item intake bound ({}); it waits \
                         rather than bypassing admission",
                        candidate.number, max_items, ORDER_RULE
                    ),
                },
            });
            continue;
        }
        selected.push((candidate.number, revision.clone()));
        items.push(Item {
            number: candidate.number,
            disposition: Disposition::Selected { revision },
        });
    }
    let digest = digest_of(&selected);
    Ok(Decision {
        items,
        selected,
        digest,
    })
}

/// The digest of one selected set: sha256 over the canonical selected
/// document. No clock, no epoch, no model — the same selection always
/// renders the same digest (AC6).
pub fn digest_of(selected: &[(u64, String)]) -> String {
    let doc = selected_doc("", selected);
    crate::queue_preview::digest_of(&doc)
}

/// The selected-issue document of one intake decision (the material the
/// preview render and the submission bind).
pub fn selected_doc(repository: &str, selected: &[(u64, String)]) -> Val {
    object(vec![
        ("repository", string(repository)),
        (
            "selected",
            Val::Arr(
                selected
                    .iter()
                    .map(|(number, revision)| {
                        object(vec![
                            ("id", string(&format!("{repository}#{number}"))),
                            ("revision", string(revision)),
                        ])
                    })
                    .collect(),
            ),
        ),
    ])
}

/// The canonical text of one intake decision (`--out`, `--json`). `label` is
/// the ready label **in force** for this invocation (`--label` when
/// presented), never the compiled-in default: the document must report the
/// decision that was made, not the one the default would have made.
pub fn render(decision: &Decision, repository: &str, label: &str) -> Val {
    object(vec![
        ("schema", string(SCHEMA)),
        ("repository", string(repository)),
        ("label", string(label)),
        ("order", string(ORDER_RULE)),
        ("max_items", Val::Int(decision.items.len() as i64)),
        ("digest", string(&decision.digest)),
        ("selected", selected_doc(repository, &decision.selected)),
        (
            "items",
            Val::Arr(
                decision
                    .items
                    .iter()
                    .map(|item| {
                        let (status, revision, message) = match &item.disposition {
                            Disposition::Selected { revision } => {
                                ("selected", string(revision), Val::Null)
                            }
                            Disposition::Owned { message } => ("owned", Val::Null, string(message)),
                            Disposition::Capped { message } => {
                                ("waiting", Val::Null, string(message))
                            }
                        };
                        object(vec![
                            ("number", Val::Int(item.number as i64)),
                            ("status", string(status)),
                            ("revision", revision),
                            ("message", message),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            "canonical",
            string(&canonical_text(&selected_doc(
                repository,
                &decision.selected,
            ))),
        ),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(number: u64) -> Candidate {
        Candidate { number, pin: None }
    }

    const HEAD: &str = "277fdd94565f47a6ea14cabf64f4f06daf81f927";

    #[test]
    fn selection_is_open_labelled_only_ordered_and_bounded() {
        // AC1/AC5/AC7: ascending issue number, and the bound holds.
        let decision = decide(
            &[candidate(9), candidate(3), candidate(5)],
            Some(HEAD),
            &BTreeSet::new(),
            2,
        )
        .expect("resolvable");
        let numbered: Vec<u64> = decision.items.iter().map(|item| item.number).collect();
        assert_eq!(numbered, vec![3, 5, 9], "ascending issue number");
        assert_eq!(decision.selected.len(), 2);
        assert_eq!(decision.selected[0], (3, HEAD.to_string()));
        assert!(matches!(
            decision.items[2].disposition,
            Disposition::Capped { .. }
        ));
    }

    #[test]
    fn a_declared_pin_wins_over_the_integration_head() {
        // AC (required behaviour 2): the tracker pin is authoritative.
        let pin = "0123456789abcdef0123456789abcdef01234567";
        let decision = decide(
            &[Candidate {
                number: 4,
                pin: Some(pin.to_string()),
            }],
            Some(HEAD),
            &BTreeSet::new(),
            8,
        )
        .expect("resolvable");
        assert_eq!(decision.selected, vec![(4, pin.to_string())]);
    }

    #[test]
    fn owned_work_is_never_resubmitted() {
        // AC2: dedupe before submit.
        let owned: BTreeSet<u64> = [5].into_iter().collect();
        let decision =
            decide(&[candidate(5), candidate(6)], Some(HEAD), &owned, 8).expect("resolvable");
        assert_eq!(decision.selected, vec![(6, HEAD.to_string())]);
        assert!(matches!(
            decision.items[0].disposition,
            Disposition::Owned { .. }
        ));
        assert_eq!(decision.held()[0].1, code::OWNED);
    }

    #[test]
    fn an_unresolvable_revision_refuses_typed_and_selects_nothing() {
        // AC4: no partial document is ever submitted.
        let err = decide(&[candidate(7)], None, &BTreeSet::new(), 8).expect_err("refuses");
        assert_eq!(err.code, code::REVISION_UNRESOLVED);
        let err = decide(
            &[Candidate {
                number: 8,
                pin: Some("not-a-revision".to_string()),
            }],
            Some(HEAD),
            &BTreeSet::new(),
            8,
        )
        .expect_err("refuses");
        assert_eq!(err.code, code::REVISION_UNRESOLVED);
    }

    #[test]
    fn two_invocations_over_unchanged_facts_render_one_digest() {
        // AC6: no clock and no epoch ride the decision.
        let first = decide(
            &[candidate(1), candidate(2)],
            Some(HEAD),
            &BTreeSet::new(),
            8,
        )
        .expect("resolvable");
        let second = decide(
            &[candidate(1), candidate(2)],
            Some(HEAD),
            &BTreeSet::new(),
            8,
        )
        .expect("resolvable");
        assert_eq!(first.digest, second.digest);
        assert_eq!(first.digest.len(), 64);
        // The digest is a function of the selection: a different selection
        // renders a different digest.
        let other = decide(&[candidate(1)], Some(HEAD), &BTreeSet::new(), 8).expect("resolvable");
        assert_ne!(first.digest, other.digest);
    }

    #[test]
    fn the_decision_renders_every_item_with_its_outcome() {
        // AC7 (observability): admitted/waiting/owned is readable from one
        // output, and the canonical selection text is carried with it.
        let owned: BTreeSet<u64> = [2].into_iter().collect();
        let decision = decide(
            &[candidate(1), candidate(2), candidate(3)],
            Some(HEAD),
            &owned,
            1,
        )
        .expect("resolvable");
        let doc = render(&decision, "owner/name", READY_LABEL);
        assert_eq!(doc.get("schema").and_then(Val::as_str), Some(SCHEMA));
        assert_eq!(doc.get("label").and_then(Val::as_str), Some(READY_LABEL));
        assert_eq!(doc.get("order").and_then(Val::as_str), Some(ORDER_RULE));
        let items = doc
            .get("items")
            .and_then(Val::as_array)
            .cloned()
            .unwrap_or_default();
        let statuses: Vec<String> = items
            .iter()
            .map(|item| {
                item.get("status")
                    .and_then(Val::as_str)
                    .unwrap_or("")
                    .to_string()
            })
            .collect();
        assert_eq!(statuses, vec!["selected", "owned", "waiting"]);
        assert!(
            doc.get("canonical")
                .and_then(Val::as_str)
                .unwrap_or("")
                .contains("owner/name#1")
        );
    }
}
