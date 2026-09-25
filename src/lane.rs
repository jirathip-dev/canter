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

/// The lane leg's BUILD-RESIDUE root names (issue #231): the per-lane
/// directories a native lane's build scratch (Xcode DerivedData) may live in,
/// derived from the same leg identity as every other lane name.
///
/// The host measured both spellings on disk — `<agent>-derived` and
/// `<agent>-DD` — and both are *regenerable lane residue*: a native lane is
/// told to use the first, and the reaper reclaims whichever exists for a
/// ledger-terminal generation of the issue. Deriving the names from the leg
/// (never from a run, a surface or the host home) is what makes that residue
/// attributable to exactly one lane and reclaimable under the same rules as
/// the checkout.
pub fn lane_build_residue_roots(issue: u64, role: &str, round: u64) -> [String; 2] {
    let (agent, _, _) = lane_identity(issue, role, round);
    [format!("{agent}-derived"), format!("{agent}-DD")]
}

/// The canonical build-scratch root name one lane leg is TOLD to use, as a
/// path relative to the lane checkout (`../<agent>-derived` from inside the
/// checkout — the sibling of `issues-<N>` under the run's worktrees root).
///
/// This is the ONE spelling the plan producer names in the worker payload:
/// build scratch belongs to the lane, never to the host home directory, and
/// the reaper reclaims exactly this derived root.
pub fn lane_build_root_relative(issue: u64, role: &str, round: u64) -> String {
    format!("../{}", lane_build_residue_roots(issue, role, round)[0])
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
    fn build_residue_roots_derive_from_the_leg_and_stay_outside_the_checkout() {
        // Issue #231: the residue a native lane's build leaves is attributable
        // to ONE leg — the two measured spellings derive from that leg alone,
        // and the scratch root a lane is told to use is the checkout's sibling
        // (never the host home directory).
        assert_eq!(
            lane_build_residue_roots(231, "implementer", 1),
            ["impl-231-derived".to_string(), "impl-231-DD".to_string()]
        );
        assert_eq!(
            lane_build_residue_roots(231, "implementer", 2),
            [
                "impl-231-r2-derived".to_string(),
                "impl-231-r2-DD".to_string()
            ]
        );
        assert_eq!(
            lane_build_residue_roots(158, "reviewer", 1),
            [
                "rev-158-r1-derived".to_string(),
                "rev-158-r1-DD".to_string()
            ]
        );
        assert_eq!(
            lane_build_root_relative(231, "implementer", 1),
            "../impl-231-derived"
        );
        // The relative scratch root never escapes the checkout's parent: it is
        // exactly one level up, beside the lane's own `issues-<N>` checkout.
        for (issue, role, round) in [(7, "implementer", 1), (210, "reviewer", 3)] {
            let relative = lane_build_root_relative(issue, role, round);
            assert_eq!(relative.matches('/').count(), 1, "{relative}");
            assert!(relative.starts_with("../"));
            assert_eq!(
                relative,
                format!("../{}", lane_build_residue_roots(issue, role, round)[0])
            );
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
