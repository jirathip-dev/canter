//! Issue #106 rename sweep: no stale `herdr-fleet` product-surface
//! reference may survive in the tracked tree outside the documented
//! legacy/historical set.
//!
//! The normative set is docs/contracts/compatibility.md, "Product rename
//! (issue #106)". Every file that is *expected* to carry the pre-rename
//! name is listed below with its **exact pinned occurrence count** on
//! purpose: adding or removing such a mention is a compatibility-contract
//! change, not a chore, so the count must be re-reviewed and updated
//! together with that section (and the CHANGELOG note).
//!
//! Two whole groups are excluded by design and were not scanned before
//! either:
//! * `.report-*.md` — historical lane reports, kept as written;
//! * `docs/architecture/herdr-fleet.*` — frozen, SHA-256-pinned v0.1.0 /
//!   locked-target render artifacts (filenames and rendered titles
//!   included);
//! * this file itself (it defines the needles it scans for).
//!
//! The scan runs over `git ls-files`, i.e. exactly the tracked tree — a
//! build directory, scratch files, or untracked fixtures can never mask a
//! committed regression.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Pre-rename needles: hyphenated product name, crate path, env-var prefix.
const NEEDLES: [&str; 3] = ["herdr-fleet", "herdr_fleet", "HERDR_FLEET"];

/// Paths excluded from the sweep entirely (kept as historical records).
const EXCLUDED_PREFIXES: [&str; 3] = [
    ".report-",
    "docs/architecture/herdr-fleet.",
    "tests/rename_sweep.rs",
];

/// Binary assets that cannot be text-scanned (the frozen PNG previews are
/// already excluded by prefix above; this guards any future binary file).
const EXCLUDED_EXTENSIONS: [&str; 7] = ["png", "jpg", "jpeg", "gif", "ico", "webp", "pdf"];

/// Files that deliberately carry the pre-rename name, with the exact number
/// of pre-rename needles they contain and the reason (see the compatibility
/// contract table). Counts are pinned: any change must be reviewed.
const ALLOWED: &[(&str, usize, &str)] = &[
    (
        ".github/workflows/ci.yml",
        5,
        "required-files list names the frozen architecture artifacts; the CLI smoke asserts the alias binary",
    ),
    (
        "CHANGELOG.md",
        5,
        "the rename entry records the old name; earlier entries are history",
    ),
    ("Cargo.toml", 3, "the pre-rename alias binary target"),
    (
        "README.md",
        14,
        "rename note, frozen artifact links, and the historical roadmap section",
    ),
    (
        "docs/ARCHITECTURE.md",
        2,
        "live Herdr custom-integration source ids",
    ),
    (
        "docs/DEVELOPMENT.md",
        2,
        "alias binary note in the test layout",
    ),
    (
        "docs/OPERATIONS.md",
        5,
        "pre-rename upgrade note and live Herdr source ids",
    ),
    (
        "docs/architecture/README.md",
        17,
        "frozen artifact filenames and the frozen-set note",
    ),
    (
        "docs/contracts/compatibility.md",
        19,
        "the authoritative pre-rename compatibility table itself",
    ),
    (
        "docs/contracts/spec-capabilities.md",
        2,
        "live Herdr custom-integration source ids",
    ),
    (
        "docs/contracts/spec-config.md",
        1,
        "pre-rename config fallback pointer",
    ),
    (
        "scripts/build-archive.py",
        1,
        "the release archive ships the pre-rename alias binary member next to canter",
    ),
    (
        "scripts/test-build-archive.py",
        1,
        "the self-test pins the contract name of the shipped alias member",
    ),
    (
        "skills/canter/SKILL.md",
        1,
        "product-name/pre-rename compatibility pointer",
    ),
    (
        "src/adapters.rs",
        4,
        "live Herdr custom-integration source ids (retained; see compat table)",
    ),
    (
        "src/bin/herdr-fleet.rs",
        2,
        "the pre-rename alias binary source itself",
    ),
    ("src/commands.rs", 2, "alias-binary doc comment on cli_main"),
    (
        "src/config.rs",
        3,
        "pre-rename config dir constant + doc references",
    ),
    ("src/daemon.rs", 3, "pre-rename crash-point env alias"),
    ("src/dirs.rs", 1, "pre-rename state/runtime dir constant"),
    ("src/main.rs", 2, "doc comment naming the alias binary"),
    (
        "src/mutation.rs",
        1,
        "the issue #92 F2 comment naming the retired pre-fix default session identity",
    ),
    (
        "tests/harness_adapters.rs",
        10,
        "fake-executable rows that pin the live Herdr source ids",
    ),
    (
        "tests/rename_compat.rs",
        5,
        "pre-rename compat tests exercise the alias binary and paths",
    ),
];

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn tracked_files(root: &Path) -> Vec<String> {
    let out = Command::new("git")
        .args(["ls-files", "-z"])
        .current_dir(root)
        .output()
        .expect("run `git ls-files` (the sweep needs the tracked tree)");
    assert!(
        out.status.success(),
        "`git ls-files` failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    out.stdout
        .split(|byte| *byte == 0)
        .filter(|entry| !entry.is_empty())
        .map(|entry| String::from_utf8_lossy(entry).into_owned())
        .collect()
}

fn is_excluded(path: &str) -> bool {
    if EXCLUDED_PREFIXES
        .iter()
        .any(|prefix| path.starts_with(prefix))
    {
        return true;
    }
    let extension = Path::new(path)
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    EXCLUDED_EXTENSIONS.contains(&extension.as_str())
}

fn needle_count(text: &str) -> usize {
    NEEDLES
        .iter()
        .map(|needle| text.matches(needle).count())
        .sum()
}

#[test]
fn no_stale_pre_rename_reference_outside_the_documented_legacy_set() {
    let root = repo_root();
    let files = tracked_files(&root);
    assert!(
        files.len() > 100,
        "sweep must see the tracked tree (got {} files)",
        files.len()
    );

    let allowed: Vec<(&str, usize, &str)> = ALLOWED.to_vec();
    let mut violations: Vec<String> = Vec::new();
    let mut seen_allowed: Vec<String> = Vec::new();

    for path in &files {
        if is_excluded(path) {
            continue;
        }
        let full = root.join(path);
        let bytes = match std::fs::read(&full) {
            Ok(bytes) => bytes,
            Err(err) => {
                violations.push(format!("{path}: unreadable ({err})"));
                continue;
            }
        };
        let text = match std::str::from_utf8(&bytes) {
            Ok(text) => text.to_string(),
            Err(_) => {
                // A non-text file slipped outside the binary extension list:
                // count on the lossy decode so a stray mention is caught.
                let lossy = String::from_utf8_lossy(&bytes).into_owned();
                let count = needle_count(&lossy);
                if count > 0 {
                    violations.push(format!(
                        "{path}: {count} pre-rename needle(s) in a binary file"
                    ));
                }
                continue;
            }
        };
        let count = needle_count(&text);
        match allowed.iter().find(|(name, _, _)| name == path) {
            Some((_, expected, reason)) => {
                seen_allowed.push(path.clone());
                if count != *expected {
                    violations.push(format!(
                        "{path}: {count} pre-rename needle(s), pinned {expected} ({reason}); \
                         update the compatibility contract and this pin together"
                    ));
                }
            }
            None => {
                if count > 0 {
                    violations.push(format!(
                        "{path}: {count} stale pre-rename needle(s) outside the documented \
                         legacy/historical set (docs/contracts/compatibility.md)"
                    ));
                }
            }
        }
    }

    // A pin for a file that no longer exists (or no longer carries the name)
    // must be retired together with the mention.
    for (name, _, _) in &allowed {
        assert!(
            files.iter().any(|path| path == name),
            "allowlist entry {name} does not match a tracked file"
        );
        assert!(
            seen_allowed.iter().any(|path| path == name),
            "allowlist entry {name} was never scanned"
        );
    }

    assert!(
        violations.is_empty(),
        "rename sweep failed:\n{}",
        violations.join("\n")
    );
}
