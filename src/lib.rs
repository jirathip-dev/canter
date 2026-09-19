//! canter library surface.
//!
//! Read-only core (issue #4): configuration, doctor, read-only status/plan
//! rendering, and stable versioned JSON. No daemon, workflow execution,
//! mutation, migration, or release behavior exists in this slice.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod adapters;
pub mod backup;
pub mod board;
pub mod canonical;
pub mod client;
pub mod commands;
pub mod config;
pub mod daemon;
pub mod dirs;
pub mod engine;
pub mod formats;
pub mod handoff;
pub mod lane;
pub mod lifecycle;
pub mod lock;
pub mod mutation;
pub mod observe;
pub mod plan;
pub mod process;
pub mod queue_executor;
pub mod queue_preview;
pub mod redact;
pub mod remote;
pub mod run_control;
pub mod schema;
pub mod service;
pub mod state;
pub mod supervision;
pub mod time;
pub mod tui;
pub mod value;

/// The package name, taken from Cargo metadata at compile time.
pub const PACKAGE_NAME: &str = env!("CARGO_PKG_NAME");

/// The package version, taken from Cargo metadata at compile time.
pub const PACKAGE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// One-line human-readable description of the project, used by `--version`.
///
/// Truthful for the read-only core: this is a read-only companion CLI; no
/// daemon or live fleet mutation is implemented.
pub fn about() -> &'static str {
    "canter: typed, plan-first companion CLI for operating Herdr coding-agent fleets (read-only core; no daemon, no live fleet mutations)"
}

/// Release-facing version facts, printed by `--version` after the package
/// identity (issue #10). Lines are stable, machine-parseable
/// ``key: value`` records that the release archive builder
/// (`scripts/build-archive.py`) reads back from a built binary, so a
/// provenance record binds the binary's schema facts without parsing Rust
/// sources or trusting caller-supplied values.
pub fn release_facts() -> String {
    let mut facts = String::new();
    facts.push_str(&format!(
        "state schema version: {}\n",
        state::SCHEMA_VERSION
    ));
    facts.push_str("migration chain: ");
    for (index, id) in state::migration_chain_ids().iter().enumerate() {
        if index > 0 {
            facts.push_str(", ");
        }
        facts.push_str(id);
    }
    facts.push('\n');
    facts.push_str("document schema families: ");
    for (index, family) in schema::SUPPORTED_FAMILIES.iter().enumerate() {
        if index > 0 {
            facts.push_str(", ");
        }
        facts.push_str(family.schema_id());
    }
    facts.push('\n');
    facts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_identity_matches_cargo_metadata() {
        assert_eq!(PACKAGE_NAME, "canter");
        assert_eq!(PACKAGE_VERSION, env!("CARGO_PKG_VERSION"));
        assert!(!about().is_empty());
    }

    #[test]
    fn release_facts_cover_schema_version_chain_and_families() {
        // Issue #10: `--version` schema facts feed the release provenance
        // chain; every fact line must stay present and internally
        // consistent with the compile-time constants it reports.
        let facts = release_facts();
        assert!(
            facts.contains(&format!(
                "state schema version: {}\n",
                state::SCHEMA_VERSION
            )),
            "facts must name the state schema version"
        );
        let chain = state::migration_chain_ids();
        assert!(!chain.is_empty());
        assert!(chain[0].starts_with("m0001"), "chain starts at m0001");
        for id in chain {
            assert!(
                facts.contains(id),
                "facts must list every migration id ({id})"
            );
        }
        assert!(
            facts.contains("document schema families: hf-config/v1"),
            "facts must list the document schema families"
        );
        for family in schema::SUPPORTED_FAMILIES {
            assert!(
                facts.contains(family.schema_id()),
                "facts must list family {}",
                family.schema_id()
            );
        }
        assert!(facts.ends_with('\n'), "facts end with a newline");
    }
}
