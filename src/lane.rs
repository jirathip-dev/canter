//! Per-leg lane identity (issue #210): the ONE derivation of a lane leg's
//! public identity strings.
//!
//! A lane leg is `(role, round)` of one reviewed issue, and its identity —
//! the registered Herdr agent name, the workspace label and the lane checkout
//! — is derived from that triple alone: never from a run, a generation, the
//! contract corpus or the execution substrate. Two consequences are load
//! bearing:
//!
//! - the derivation is STABLE: a retry/fix round and every generation that
//!   reclaims one issue derive the same identity, so a lane can be reused and
//!   a ledger-terminal generation's residue reclaimed deterministically;
//! - the derivation is INJECTIVE over the closed `(role, round)` set: distinct
//!   legs derive distinct names AND distinct checkouts, so a sibling leg (the
//!   measured `132-rev1` reviewer leg against the run's own `132-impl`
//!   implementer lane) can never resolve another leg's checkout — the
//!   collision is impossible by construction rather than refused late.
//!
//! The derivation is total; callers that accept operator input validate the
//! closed set first (`adapters::LaneNames::new`, the queue preview and the
//! effect boundary all refuse outside `implementer`/`reviewer` and round
//! `>= 1`).

/// The registered agent name and workspace label of one lane leg:
/// `impl-<N>` / `<N>-impl`, `impl-<N>-r<R>` / `<N>-impl<R>`,
/// `rev-<N>-r<R>` / `<N>-rev<R>`.
pub fn lane_names(issue: u64, role: &str, round: u64) -> (String, String) {
    let (agent, workspace, _) = lane_identity(issue, role, round);
    (agent, workspace)
}

/// The lane checkout of one lane leg, relative to the worktrees root:
/// `issues-<N>` for the implementer leg round 1 (the run's own lane),
/// `issues-<N>-impl<R>` for a later implementer round and
/// `issues-<N>-rev<R>` for every reviewer leg.
pub fn lane_checkout(issue: u64, role: &str, round: u64) -> String {
    lane_identity(issue, role, round).2
}

/// The lane BRANCH of one run's own implementer lane (round 1): `issue-<N>`.
/// The ONE derivation the plan producer renders into `worktree_create` and
/// every operator control that addresses the run's lane reads back (issue
/// #236): a lane addressed by the ledger, by a plan step or by a retire
/// control is the same lane, never a re-spelled name.
pub fn lane_branch(issue: u64) -> String {
    format!("issue-{issue}")
}

/// The three public identity strings of one leg, in one place.
fn lane_identity(issue: u64, role: &str, round: u64) -> (String, String, String) {
    match (role, round) {
        ("implementer", 1) => (
            format!("impl-{issue}"),
            format!("{issue}-impl"),
            format!("issues-{issue}"),
        ),
        ("implementer", _) => (
            format!("impl-{issue}-r{round}"),
            format!("{issue}-impl{round}"),
            format!("issues-{issue}-impl{round}"),
        ),
        _ => (
            format!("rev-{issue}-r{round}"),
            format!("{issue}-rev{round}"),
            format!("issues-{issue}-rev{round}"),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lane_identity_derives_only_from_issue_role_and_round() {
        for (issue, role, round, agent, workspace, checkout) in [
            (154, "implementer", 1, "impl-154", "154-impl", "issues-154"),
            (
                154,
                "implementer",
                2,
                "impl-154-r2",
                "154-impl2",
                "issues-154-impl2",
            ),
            (
                152,
                "reviewer",
                1,
                "rev-152-r1",
                "152-rev1",
                "issues-152-rev1",
            ),
            (
                152,
                "reviewer",
                2,
                "rev-152-r2",
                "152-rev2",
                "issues-152-rev2",
            ),
        ] {
            assert_eq!(
                lane_names(issue, role, round),
                (agent.to_string(), workspace.to_string())
            );
            assert_eq!(lane_checkout(issue, role, round), checkout);
        }
    }

    #[test]
    fn every_lane_addressed_by_the_ledger_or_a_control_is_the_same_lane() {
        // Issue #236: the branch a plan step binds and the branch a retire
        // control reclaims are ONE derivation — never two spellings that can
        // drift apart.
        for (issue, branch, checkout) in
            [(236, "issue-236", "issues-236"), (7, "issue-7", "issues-7")]
        {
            assert_eq!(lane_branch(issue), branch);
            assert_eq!(lane_checkout(issue, "implementer", 1), checkout);
        }
    }

    #[test]
    fn distinct_legs_derive_distinct_names_and_checkouts() {
        // Issue #210: the identity is injective over the closed set — the
        // property that makes a sibling-leg collision impossible by
        // construction (the measured `132-rev1` reviewer leg against the run's
        // own `132-impl` implementer lane).
        let mut seen: Vec<(String, String, String)> = Vec::new();
        for role in ["implementer", "reviewer"] {
            for round in 1..=4 {
                let (agent, workspace) = lane_names(132, role, round);
                let checkout = lane_checkout(132, role, round);
                let identity = (agent, workspace, checkout);
                assert!(
                    !seen.contains(&identity),
                    "two distinct legs derived one identity: {identity:?}"
                );
                seen.push(identity);
            }
        }
        assert_eq!(seen.len(), 8, "two roles times four rounds");
        assert!(seen.iter().any(|(agent, ..)| agent == "impl-132"));
        assert!(seen.iter().any(|(agent, ..)| agent == "rev-132-r1"));
        assert!(seen.iter().any(|(_, _, checkout)| checkout == "issues-132"));
        assert!(
            seen.iter()
                .any(|(_, _, checkout)| checkout == "issues-132-rev1")
        );
    }
}
