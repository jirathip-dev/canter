//! String-format validators for the #3 identity/scalar rules.
//!
//! The rules mirror the fixture probe (`scripts/check-contract-fixtures.py`)
//! exactly: repository identity `owner/name`, slugs, hex digests, RFC3339
//! seconds-`Z` shape, actor ids, error codes, and semantic versions.

/// `owner/name` repository identity, no protocol prefix.
pub fn is_repository_identity(text: &str) -> bool {
    let Some((owner, name)) = text.split_once('/') else {
        return false;
    };
    !owner.is_empty()
        && !name.is_empty()
        && !name.contains('/')
        && path_component_chars(owner)
        && path_component_chars(name)
}

/// One path component of an `owner/name` identity: `[A-Za-z0-9_.-]+`.
fn path_component_chars(text: &str) -> bool {
    !text.is_empty()
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// Step param names share the contract namespace, including underscores.
pub fn is_step_param_name(text: &str) -> bool {
    text.len() <= 64
        && text.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        && text
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_' || c == b'-')
}

/// Slug: `^[a-z0-9][a-z0-9-]{0,63}$` (repository keys, workflow ids, step ids).
pub fn is_slug(text: &str) -> bool {
    let mut chars = text.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_ascii_lowercase() || first.is_ascii_digit()) {
        return false;
    }
    let mut len = 1;
    for c in chars {
        len += 1;
        if !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') {
            return false;
        }
    }
    len <= 64
}

/// Lowercase hex of exactly `digits` characters.
pub fn is_lower_hex(text: &str, digits: usize) -> bool {
    text.len() == digits
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// 40-hex (SHA-1 sized) lowercase digest/commit.
pub fn is_hex40(text: &str) -> bool {
    is_lower_hex(text, 40)
}

/// 64-hex (SHA-256 sized) lowercase digest.
pub fn is_hex64(text: &str) -> bool {
    is_lower_hex(text, 64)
}

/// RFC3339 UTC seconds precision with `Z`: `^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$`
/// (shape rule only, mirroring the fixture probe).
pub fn is_rfc3339_seconds_z(text: &str) -> bool {
    let bytes = text.as_bytes();
    if bytes.len() != 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'Z'
    {
        return false;
    }
    text.bytes()
        .enumerate()
        .all(|(i, b)| matches!(i, 4 | 7 | 10 | 13 | 16 | 19) || b.is_ascii_digit())
}

/// Actor id: `^[A-Za-z0-9_.-]{1,64}$`.
pub fn is_actor(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 64
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// Error code: `^[a-z][a-z0-9_.-]*$`.
pub fn is_error_code(text: &str) -> bool {
    let mut chars = text.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_lowercase() {
        return false;
    }
    chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'))
}

/// Plan id: `hf_plan_` + 16 lowercase hex.
pub fn is_plan_id(text: &str) -> bool {
    const PREFIX: &str = "hf_plan_";
    text.len() == PREFIX.len() + 16
        && text.starts_with(PREFIX)
        && is_lower_hex(&text[PREFIX.len()..], 16)
}

/// Daemon request id: 8-64 lowercase hex (`^[a-f0-9]{8,64}$`).
pub fn is_request_id(text: &str) -> bool {
    (8..=64).contains(&text.len())
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Idempotency key: `ik_` + 8-64 `[a-z0-9-]`.
pub fn is_idempotency_key(text: &str) -> bool {
    const PREFIX: &str = "ik_";
    let body = text.strip_prefix(PREFIX).unwrap_or_default();
    (8..=64).contains(&body.len())
        && body
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Grant id: `gr_` + 16 lowercase hex.
pub fn is_grant_id(text: &str) -> bool {
    const PREFIX: &str = "gr_";
    text.len() == PREFIX.len() + 16
        && text.starts_with(PREFIX)
        && is_lower_hex(&text[PREFIX.len()..], 16)
}

/// Queue submission id: `qs_` + 16 lowercase hex (issue #85).
pub fn is_submission_id(text: &str) -> bool {
    const PREFIX: &str = "qs_";
    text.len() == PREFIX.len() + 16
        && text.starts_with(PREFIX)
        && is_lower_hex(&text[PREFIX.len()..], 16)
}

/// Run instance id: `run-` + 16 lowercase hex (issue #85/#86: the durable
/// run identity the queue executor commits for every admitted issue).
pub fn is_run_id(text: &str) -> bool {
    const PREFIX: &str = "run-";
    text.len() == PREFIX.len() + 16
        && text.starts_with(PREFIX)
        && is_lower_hex(&text[PREFIX.len()..], 16)
}

/// Schedule id: `sd_` + 16 lowercase hex (lifecycle slice, issue #9).
pub fn is_schedule_id(text: &str) -> bool {
    const PREFIX: &str = "sd_";
    text.len() == PREFIX.len() + 16
        && text.starts_with(PREFIX)
        && is_lower_hex(&text[PREFIX.len()..], 16)
}

/// Lane replacement id: `rp_` + 16 lowercase hex (issue #73).
pub fn is_replacement_id(text: &str) -> bool {
    const PREFIX: &str = "rp_";
    text.len() == PREFIX.len() + 16
        && text.starts_with(PREFIX)
        && is_lower_hex(&text[PREFIX.len()..], 16)
}

/// Lane checkpoint id: `ck_` + 16 lowercase hex (issue #74).
pub fn is_checkpoint_id(text: &str) -> bool {
    const PREFIX: &str = "ck_";
    text.len() == PREFIX.len() + 16
        && text.starts_with(PREFIX)
        && is_lower_hex(&text[PREFIX.len()..], 16)
}

/// Lane successor id: `su_` + 16 lowercase hex (issue #76).
pub fn is_successor_id(text: &str) -> bool {
    const PREFIX: &str = "su_";
    text.len() == PREFIX.len() + 16
        && text.starts_with(PREFIX)
        && is_lower_hex(&text[PREFIX.len()..], 16)
}

/// Evidence id: `ev_` + 16 lowercase hex (control-plane evidence rows;
/// issue #8 / #83 board evidence references).
pub fn is_evidence_id(text: &str) -> bool {
    const PREFIX: &str = "ev_";
    text.len() == PREFIX.len() + 16
        && text.starts_with(PREFIX)
        && is_lower_hex(&text[PREFIX.len()..], 16)
}

/// Work-item id: `wi_` + 16 lowercase hex (issue #83 read model). A stable
/// local identity for one source work item (repository identity + external
/// issue number), deterministic so repeated reads and restarts agree.
pub fn is_work_item_id(text: &str) -> bool {
    const PREFIX: &str = "wi_";
    text.len() == PREFIX.len() + 16
        && text.starts_with(PREFIX)
        && is_lower_hex(&text[PREFIX.len()..], 16)
}

/// Repository-relative worktree reference (issue #73 AC2):
/// `[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*` with no `.`/`..` components and
/// no leading slash — host-absolute paths and traversal never validate, so
/// a record can only bind a relative worktree identity.
pub fn is_worktree_ref(text: &str) -> bool {
    const MAX_LEN: usize = 200;
    if text.is_empty() || text.len() > MAX_LEN || text.starts_with('/') {
        return false;
    }
    text.split('/').all(|component| {
        !component.is_empty()
            && component != "."
            && component != ".."
            && component
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    })
}

/// Migration id: `mNNNN_<snake>` (`^m[0-9]{4}_[a-z0-9_]+$`).
pub fn is_migration_id(text: &str) -> bool {
    let body = text.strip_prefix('m').unwrap_or_default();
    let Some((digits, snake)) = body.split_once('_') else {
        return false;
    };
    digits.len() == 4
        && digits.bytes().all(|b| b.is_ascii_digit())
        && !snake.is_empty()
        && snake
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// Audit action code: `^[a-z][a-z0-9_.-]*$` (same grammar as error codes).
pub fn is_action_code(text: &str) -> bool {
    is_error_code(text)
}

/// Parse a semantic version `major.minor.patch` (numeric fields only).
pub fn parse_semver(text: &str) -> Option<(u64, u64, u64)> {
    let mut parts = text.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((major, minor, patch))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repository_identity_rules() {
        assert!(is_repository_identity("example-org/widgets"));
        assert!(is_repository_identity("a/b"));
        assert!(is_repository_identity("example_org/widgets.v2"));
        assert!(!is_repository_identity(
            "https://github.com/example-org/widgets"
        ));
        assert!(!is_repository_identity("example-org/"));
        assert!(!is_repository_identity("widgets"));
        assert!(!is_repository_identity(""));
    }

    #[test]
    fn slug_rules() {
        assert!(is_slug("widgets"));
        assert!(is_slug("fleet-doctrine-1"));
        assert!(is_slug("p1"));
        assert!(!is_slug("Widgets"));
        assert!(!is_slug("-widgets"));
        assert!(!is_slug("widgets/other"));
        assert!(!is_slug(""));
    }

    #[test]
    fn hex_rules() {
        assert!(is_hex40(&"0".repeat(40)));
        assert!(!is_hex40(&"0".repeat(39)));
        assert!(is_hex64(&"ab".repeat(32)));
        assert!(!is_hex64(&"AB".repeat(32)), "lowercase only");
    }

    #[test]
    fn rfc3339_shape() {
        assert!(is_rfc3339_seconds_z("2026-09-06T00:00:00Z"));
        assert!(!is_rfc3339_seconds_z("2026-09-06T00:00:00+00:00"));
        // Shape rule parity with the fixture probe: the regex validates
        // positions only; calendar semantics are the emitter's job.
        assert!(is_rfc3339_seconds_z("2026-13-45T99:00:00Z"));
        assert!(!is_rfc3339_seconds_z("2026-9-06T00:00:00Z"));
    }

    #[test]
    fn actor_and_error_code_rules() {
        assert!(is_actor("canter"));
        assert!(is_actor("gh"));
        assert!(!is_actor(""));
        assert!(is_error_code("config.invalid"));
        assert!(is_error_code("refusal.stale_state"));
        assert!(!is_error_code("Config.invalid"));
    }

    #[test]
    fn daemon_wire_format_rules() {
        assert!(is_request_id("0".repeat(8).as_str()));
        assert!(is_request_id("abcdef".repeat(8).as_str()));
        assert!(!is_request_id("0".repeat(7).as_str()), "min 8 hex");
        assert!(!is_request_id("0".repeat(65).as_str()), "max 64 hex");
        assert!(
            !is_request_id("ABCDEF0123456789".to_string().as_str()),
            "lowercase hex only"
        );
        assert!(!is_request_id("not-hex-0123456789"));

        assert!(is_idempotency_key("ik_apply-20260906-0001"));
        assert!(is_idempotency_key(&format!("ik_{}", "a".repeat(8))));
        assert!(!is_idempotency_key("ik_short"));
        assert!(
            !is_idempotency_key("apply-20260906-0001"),
            "ik_ prefix required"
        );
        assert!(
            !is_idempotency_key("ik_APPLY-20260906-0001"),
            "lowercase only"
        );

        assert!(is_grant_id("gr_0123456789abcdef"));
        assert!(!is_grant_id("gr_0123456789abcde"), "15 hex");
        assert!(!is_grant_id("gr_0123456789ABCDEF"), "lowercase only");
        assert!(!is_grant_id("0123456789abcdef"));

        assert!(is_migration_id("m0001_create_state_v1"));
        assert!(is_migration_id("m0042_a_b_c"));
        assert!(!is_migration_id("m001_create_state_v1"), "4 digits");
        assert!(!is_migration_id("m0001-odd"), "snake body only");
        assert!(!is_migration_id("x0001_create_state_v1"));

        assert!(is_action_code("mutate.merge"));
        assert!(is_action_code("read.status"));
        assert!(is_action_code("a1_b-c.d"));
        assert!(!is_action_code("Mutate.merge"));
        assert!(!is_action_code(""));
    }

    #[test]
    fn lane_replacement_format_rules() {
        // Issue #73: replacement ids and relative worktree references.
        assert!(is_replacement_id("rp_0123456789abcdef"));
        assert!(!is_replacement_id("rp_0123456789abcde"), "15 hex");
        assert!(!is_replacement_id("rp_0123456789ABCDEF"), "lowercase only");
        assert!(!is_replacement_id("0123456789abcdef"));

        // Issue #74: checkpoint ids share the 16-hex identity shape.
        assert!(is_checkpoint_id("ck_0123456789abcdef"));
        assert!(!is_checkpoint_id("ck_0123456789abcde"), "15 hex");
        assert!(
            !is_checkpoint_id("rp_0123456789abcdef"),
            "ck_ prefix required"
        );

        assert!(is_worktree_ref("worktrees/issues/73"));
        assert!(is_worktree_ref("lane-7"));
        assert!(is_worktree_ref("pods/team_a/issue-1"));
        assert!(!is_worktree_ref(""), "empty never binds");
        assert!(!is_worktree_ref("/var/tmp/host-path"), "absolute refused");
        assert!(!is_worktree_ref("../escape"), "traversal refused");
        assert!(!is_worktree_ref("a/./b"), "dot component refused");
        assert!(!is_worktree_ref("a//b"), "empty component refused");
        assert!(!is_worktree_ref("a/b/"), "trailing slash refused");
        assert!(!is_worktree_ref("a\\b"), "backslash refused");
        assert!(
            !is_worktree_ref(&"a".repeat(201)),
            "over-long worktree refused"
        );

        // Issue #83: board identity ids share the 16-hex shape.
        assert!(is_evidence_id("ev_0123456789abcdef"));
        assert!(!is_evidence_id("ev_0123456789abcde"), "15 hex");
        assert!(!is_evidence_id("ev_0123456789ABCDEF"), "lowercase only");
        assert!(!is_evidence_id("0123456789abcdef"));
        assert!(is_work_item_id("wi_0123456789abcdef"));
        assert!(!is_work_item_id("wi_0123456789abcde"), "15 hex");
        assert!(
            !is_work_item_id("ev_0123456789abcdef"),
            "wi_ prefix required"
        );
    }

    #[test]
    fn semver_parse_and_order() {
        assert_eq!(parse_semver("0.8.2"), Some((0, 8, 2)));
        assert_eq!(parse_semver("2.100.0"), Some((2, 100, 0)));
        assert_eq!(parse_semver("v0.8.2"), None);
        assert_eq!(parse_semver("0.8"), None);
        assert_eq!(parse_semver("0.8.2.1"), None);
    }
}
