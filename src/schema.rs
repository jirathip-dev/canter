//! #3 schema-family validators (closed v1 surfaces).
//!
//! This module is the Rust mirror of the machine-readable half of the
//! contract — `scripts/check-contract-fixtures.py` — for the families this
//! slice emits or consumes: the read-only CLI families (`hf-config/v1`,
//! `hf-policy/v1` (TOML), `hf-output/v1`, `hf-error/v1`,
//! `hf-observation/v1`, `hf-plan/v1`, `hf-capability/v1`) plus the daemon
//! wire/state families implemented by the daemon foundation slice
//! (`hf-rpc-request/v1`, `hf-rpc-response/v1`, `hf-event/v1` (JSONL),
//! `hf-audit/v1` (JSONL), `hf-migration/v1`, `hf-epoch/v1`, `hf-grant/v1`,
//! `hf-outcome/v1`).
//!
//! Verdict semantics mirror the probe: `refuse-parse`, `refuse-schema`
//! (missing/foreign identifier), `refuse-version` (known family, unsupported
//! version), `refuse-malformed` (closed-surface violations), and
//! `refuse-noncanonical` (valid but not canonical bytes, `hf-plan/v1` only).
//! The unit tests in this module run the committed fixture corpus from
//! `schemas/fixtures/` through these validators and assert every manifest
//! expectation holds, so the emitted JSON of every command is covered by the
//! same discriminating rules the #3 probe enforces on fixtures.

use crate::canonical::canonical_bytes;
use crate::formats::{
    is_action_code, is_actor, is_error_code, is_evidence_id, is_grant_id, is_hex40, is_hex64,
    is_idempotency_key, is_migration_id, is_plan_id, is_repository_identity, is_request_id,
    is_rfc3339_seconds_z, is_schedule_id, is_slug, is_work_item_id,
};
use crate::redact::redact;
use crate::value::Val;

/// A contract family handled by this slice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    /// `hf-config/v1` — canonical XDG TOML configuration.
    Config,
    /// `hf-policy/v1` — explicit optional policy overlay.
    Policy,
    /// `hf-output/v1` — CLI JSON output envelope.
    Output,
    /// `hf-error/v1` — typed error envelope.
    Error,
    /// `hf-observation/v1` — normalized observation.
    Observation,
    /// `hf-plan/v1` — deterministic plan (canonical bytes + digest).
    Plan,
    /// `hf-capability/v1` — capability negotiation envelope.
    Capability,
    /// `hf-rpc-request/v1` — daemon request document (per-user socket).
    RpcRequest,
    /// `hf-rpc-response/v1` — daemon response document.
    RpcResponse,
    /// `hf-event/v1` — local JSONL event record (one event per line).
    Event,
    /// `hf-audit/v1` — journal/audit record (JSONL; journal-before-mutation).
    Audit,
    /// `hf-migration/v1` — SQLite migration manifest.
    Migration,
    /// `hf-epoch/v1` — state epoch record (restore rotation).
    Epoch,
    /// `hf-grant/v1` — route grant (AC3 bindings).
    Grant,
    /// `hf-outcome/v1` — typed step outcome (idempotency-keyed).
    Outcome,
    /// `hf-workflow/v1` — closed typed workflow DAG (engine slice #6).
    Workflow,
    /// `hf-schedule/v1` — recurring non-destructive schedule document
    /// (lifecycle slice #9; bounded read-only cadence + exact bindings).
    Schedule,
    /// `hf-board/v1` — bounded paginated board read page (read-model slice
    /// #83: work-item identity, run state, verification, evidence refs).
    Board,
}

impl Family {
    /// The registry family name (`hf-config`, …).
    pub fn family_name(self) -> &'static str {
        match self {
            Family::Config => "hf-config",
            Family::Policy => "hf-policy",
            Family::Output => "hf-output",
            Family::Error => "hf-error",
            Family::Observation => "hf-observation",
            Family::Plan => "hf-plan",
            Family::Capability => "hf-capability",
            Family::RpcRequest => "hf-rpc-request",
            Family::RpcResponse => "hf-rpc-response",
            Family::Event => "hf-event",
            Family::Audit => "hf-audit",
            Family::Migration => "hf-migration",
            Family::Epoch => "hf-epoch",
            Family::Grant => "hf-grant",
            Family::Outcome => "hf-outcome",
            Family::Workflow => "hf-workflow",
            Family::Schedule => "hf-schedule",
            Family::Board => "hf-board",
        }
    }

    /// The versioned schema identifier (`hf-config/v1`, …).
    pub fn schema_id(self) -> &'static str {
        match self {
            Family::Config => "hf-config/v1",
            Family::Policy => "hf-policy/v1",
            Family::Output => "hf-output/v1",
            Family::Error => "hf-error/v1",
            Family::Observation => "hf-observation/v1",
            Family::Plan => "hf-plan/v1",
            Family::Capability => "hf-capability/v1",
            Family::RpcRequest => "hf-rpc-request/v1",
            Family::RpcResponse => "hf-rpc-response/v1",
            Family::Event => "hf-event/v1",
            Family::Audit => "hf-audit/v1",
            Family::Migration => "hf-migration/v1",
            Family::Epoch => "hf-epoch/v1",
            Family::Grant => "hf-grant/v1",
            Family::Outcome => "hf-outcome/v1",
            Family::Workflow => "hf-workflow/v1",
            Family::Schedule => "hf-schedule/v1",
            Family::Board => "hf-board/v1",
        }
    }

    /// Whether the family's document surface is newline-delimited JSONL.
    pub fn is_jsonl(self) -> bool {
        matches!(self, Family::Event | Family::Audit)
    }

    /// Parse document bytes into a [`Val`]: TOML for config/policy, strict
    /// JSON for every other single-document family. JSONL families are
    /// parsed line-by-line by [`validate_bytes`] instead.
    fn parse_bytes(self, bytes: &[u8]) -> Result<Val, String> {
        let text = std::str::from_utf8(bytes).map_err(|err| format!("not valid UTF-8 ({err})"))?;
        match self {
            Family::Config | Family::Policy => Val::parse_toml(text),
            _ => Val::parse_json(text),
        }
    }
}

/// Refusal classes, matching the probe's result vocabulary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// Bytes do not parse.
    Parse,
    /// Schema identifier is missing or names another family.
    Schema,
    /// Family is known but the version is not supported.
    Version,
    /// Structurally invalid for the family rules.
    Malformed,
    /// Bytes are not the canonical serialization.
    Noncanonical,
}

impl Refusal {
    /// The probe's refusal-code spelling (`refuse-parse`, …).
    pub fn as_str(self) -> &'static str {
        match self {
            Refusal::Parse => "refuse-parse",
            Refusal::Schema => "refuse-schema",
            Refusal::Version => "refuse-version",
            Refusal::Malformed => "refuse-malformed",
            Refusal::Noncanonical => "refuse-noncanonical",
        }
    }
}

/// One validation outcome: accepted, or refused with a class and message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verdict {
    refusal: Option<Refusal>,
    message: String,
}

impl Verdict {
    /// Accepted.
    pub fn accept() -> Verdict {
        Verdict {
            refusal: None,
            message: String::new(),
        }
    }

    /// Refused with a class and human message.
    pub fn refuse(class: Refusal, message: impl Into<String>) -> Verdict {
        Verdict {
            refusal: Some(class),
            message: message.into(),
        }
    }

    /// Whether the document was accepted.
    pub fn is_accepted(&self) -> bool {
        self.refusal.is_none()
    }

    /// The refusal class of a refused document.
    pub fn refusal(&self) -> Option<Refusal> {
        self.refusal
    }

    /// Human message (acceptance or refusal reason).
    pub fn message(&self) -> &str {
        &self.message
    }
}

/// Validate raw document bytes for a family (parse + version + shape +
/// canonical-bytes rules). This is the entry point used by the CLI's config
/// commands and by the fixture-corpus tests. JSONL families are validated
/// line by line: every non-empty line must parse and validate, mirroring the
/// probe's JSONL driver.
pub fn validate_bytes(family: Family, bytes: &[u8]) -> Verdict {
    if family.is_jsonl() {
        return validate_jsonl(family, bytes);
    }
    let doc = match family.parse_bytes(bytes) {
        Ok(doc) => doc,
        Err(message) => return Verdict::refuse(Refusal::Parse, message),
    };
    let verdict = validate_doc(family, &doc);
    if verdict.refusal.is_some() {
        return verdict;
    }
    if matches!(family, Family::Plan | Family::Workflow) {
        let canonical = canonical_bytes(&doc);
        let without_lf = &canonical[..canonical.len() - 1];
        if bytes != canonical.as_slice() && bytes != without_lf {
            return Verdict::refuse(
                Refusal::Noncanonical,
                "bytes are not the canonical serialization",
            );
        }
    }
    Verdict::accept()
}

/// Validate a newline-delimited JSONL document: one document per line, every
/// line must parse and validate for the family (a single bad line fails the
/// stream, mirroring the probe's JSONL driver).
fn validate_jsonl(family: Family, bytes: &[u8]) -> Verdict {
    let text = match std::str::from_utf8(bytes) {
        Ok(text) => text,
        Err(err) => return Verdict::refuse(Refusal::Parse, format!("not valid UTF-8 ({err})")),
    };
    let mut seen_line = false;
    for (lineno, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        seen_line = true;
        let doc = match Val::parse_json(line) {
            Ok(doc) => doc,
            Err(err) => {
                return Verdict::refuse(
                    Refusal::Parse,
                    format!("line {}: not valid JSON ({err})", lineno + 1),
                );
            }
        };
        let verdict = validate_doc(family, &doc);
        if verdict.refusal.is_some() {
            return Verdict::refuse(
                verdict.refusal().expect("refused"),
                format!("line {}: {}", lineno + 1, verdict.message()),
            );
        }
    }
    if !seen_line {
        return Verdict::refuse(Refusal::Parse, "empty JSONL document");
    }
    Verdict::accept()
}

/// Validate an already-parsed document value for a family.
pub fn validate_doc(family: Family, doc: &Val) -> Verdict {
    match family {
        Family::Config => validate_config(doc),
        Family::Policy => validate_policy(doc),
        Family::Output => validate_output(doc),
        Family::Error => validate_error(doc),
        Family::Observation => validate_observation(doc),
        Family::Plan => validate_plan(doc),
        Family::Capability => validate_capability(doc),
        Family::RpcRequest => validate_rpc_request(doc),
        Family::RpcResponse => validate_rpc_response(doc),
        Family::Event => validate_event(doc),
        Family::Audit => validate_audit(doc),
        Family::Migration => validate_migration(doc),
        Family::Epoch => validate_epoch(doc),
        Family::Grant => validate_grant(doc),
        Family::Outcome => validate_outcome(doc),
        Family::Workflow => validate_workflow(doc),
        Family::Schedule => validate_schedule(doc),
        Family::Board => validate_board(doc),
    }
}

// ---------------------------------------------------------------------------
// Shared shape helpers (each mirrors the probe's `_expect_*` helpers).
// ---------------------------------------------------------------------------

fn check_schema(obj: &Val, family: Family) -> Result<(), Verdict> {
    let Some(value) = obj.get("schema") else {
        return Err(Verdict::refuse(
            Refusal::Schema,
            "missing schema identifier",
        ));
    };
    let Some(text) = value.as_str() else {
        return Err(Verdict::refuse(
            Refusal::Schema,
            "schema identifier must be a string",
        ));
    };
    if text == family.schema_id() {
        return Ok(());
    }
    let prefix = format!("{}/v", family.family_name());
    if text.starts_with(&prefix) {
        Err(Verdict::refuse(
            Refusal::Version,
            format!("unsupported version {text:?} for {}", family.family_name()),
        ))
    } else {
        Err(Verdict::refuse(
            Refusal::Schema,
            format!("missing or foreign schema identifier {text:?}"),
        ))
    }
}

type Rule = Result<(), Verdict>;

fn require_keys(obj: &Val, required: &[&str], allowed: &[&str], where_: &str) -> Rule {
    for key in required {
        if obj.get(key).is_none() {
            return Err(Verdict::refuse(
                Refusal::Malformed,
                format!("{where_}: missing required key {key:?}"),
            ));
        }
    }
    if let Val::Obj(map) = obj {
        for key in map.keys() {
            if !allowed.contains(&key.as_str()) {
                return Err(Verdict::refuse(
                    Refusal::Malformed,
                    format!("{where_}: unknown key {key:?}"),
                ));
            }
        }
    }
    Ok(())
}

fn table(obj: &Val, where_: &str) -> Rule {
    match obj {
        Val::Obj(_) => Ok(()),
        other => Err(Verdict::refuse(
            Refusal::Malformed,
            format!("{where_} must be a table/object, got {}", other.type_name()),
        )),
    }
}

fn expect_str(obj: &Val, key: &str, where_: &str, check: Option<fn(&str) -> bool>) -> Rule {
    let Some(value) = obj.get(key) else {
        return Ok(());
    };
    match value {
        Val::Str(text) if !text.is_empty() => {
            if let Some(check) = check
                && !check(text)
            {
                return Err(Verdict::refuse(
                    Refusal::Malformed,
                    format!("{where_}: {key:?} fails its format rule"),
                ));
            }
            Ok(())
        }
        other => Err(Verdict::refuse(
            Refusal::Malformed,
            format!(
                "{where_}: {key:?} must be a non-empty string, got {}",
                other.type_name()
            ),
        )),
    }
}

fn expect_bool(obj: &Val, key: &str, where_: &str) -> Rule {
    match obj.get(key) {
        None | Some(Val::Bool(_)) => Ok(()),
        Some(other) => Err(Verdict::refuse(
            Refusal::Malformed,
            format!(
                "{where_}: {key:?} must be a boolean, got {}",
                other.type_name()
            ),
        )),
    }
}

fn expect_int(obj: &Val, key: &str, where_: &str, minimum: i64) -> Rule {
    match obj.get(key) {
        Some(Val::Int(int)) if *int >= minimum => Ok(()),
        Some(other) => Err(Verdict::refuse(
            Refusal::Malformed,
            format!(
                "{where_}: {key:?} must be an integer >= {minimum}, got {}",
                other.type_name()
            ),
        )),
        None => Err(Verdict::refuse(
            Refusal::Malformed,
            format!("{where_}: missing required integer {key:?}"),
        )),
    }
}

fn expect_timestamp(obj: &Val, key: &str, where_: &str) -> Rule {
    match obj.get(key) {
        Some(Val::Str(text)) if is_rfc3339_seconds_z(text) => Ok(()),
        Some(other) => Err(Verdict::refuse(
            Refusal::Malformed,
            format!(
                "{where_}: {key:?} must be RFC3339 UTC (seconds, Z), got {}",
                other.type_name()
            ),
        )),
        None => Err(Verdict::refuse(
            Refusal::Malformed,
            format!("{where_}: missing required timestamp {key:?}"),
        )),
    }
}

fn expect_in(obj: &Val, key: &str, where_: &str, closed: &[&str]) -> Rule {
    match obj.get(key) {
        Some(Val::Str(text)) if closed.contains(&text.as_str()) => Ok(()),
        Some(other) => Err(Verdict::refuse(
            Refusal::Malformed,
            format!(
                "{where_}: {key:?} must be one of the closed set {closed:?}, got {}",
                other.type_name()
            ),
        )),
        None => Err(Verdict::refuse(
            Refusal::Malformed,
            format!("{where_}: missing required key {key:?}"),
        )),
    }
}

/// Embedded error shape `{code, message}` used by output envelopes.
fn err_shaped(value: &Val) -> Rule {
    table(value, "embedded error")?;
    match value.get("code") {
        Some(Val::Str(text)) if is_error_code(text) => {}
        _ => {
            return Err(Verdict::refuse(
                Refusal::Malformed,
                "embedded error code invalid",
            ));
        }
    }
    match value.get("message") {
        Some(Val::Str(text)) if !text.is_empty() => {}
        _ => {
            return Err(Verdict::refuse(
                Refusal::Malformed,
                "embedded error message must be non-empty",
            ));
        }
    }
    Ok(())
}

/// Issue binding `{number: positive int, revision: 40-hex}`.
fn issue_shaped(value: &Val) -> Rule {
    table(value, "issue")?;
    match value.get("number") {
        Some(Val::Int(number)) if *number > 0 => {}
        _ => {
            return Err(Verdict::refuse(
                Refusal::Malformed,
                "issue.number must be a positive integer",
            ));
        }
    }
    expect_str(value, "revision", "issue", Some(is_hex40))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Per-family validators (normative; the docs under docs/contracts/ must not
// contradict these rules).
// ---------------------------------------------------------------------------

const CONFIG_TOP_KEYS: [&str; 7] = [
    "schema",
    "daemon",
    "policy",
    "repository",
    "harness",
    "workflow",
    "role",
];
const POLICY_TOP_KEYS: [&str; 4] = ["schema", "repositories", "production_confirmation", "role"];

fn validate_config(obj: &Val) -> Verdict {
    if let Err(verdict) = check_schema(obj, Family::Config) {
        return verdict;
    }
    if let Err(verdict) = require_keys(obj, &["schema"], &CONFIG_TOP_KEYS, "config") {
        return verdict;
    }
    for key in [
        "daemon",
        "policy",
        "repository",
        "harness",
        "workflow",
        "role",
    ] {
        if obj.get(key).is_some()
            && let Err(verdict) = table(obj.get(key).expect("present"), &format!("config.{key}"))
        {
            return verdict;
        }
    }
    // daemon: {enabled?: bool, socket?: string}
    if let Some(daemon) = obj.get("daemon") {
        if let Err(verdict) = require_keys(daemon, &[], &["enabled", "socket"], "config.daemon") {
            return verdict;
        }
        if let Err(verdict) = expect_bool(daemon, "enabled", "config.daemon") {
            return verdict;
        }
        if let Err(verdict) = expect_str(daemon, "socket", "config.daemon", None) {
            return verdict;
        }
    }
    // policy: exactly {overlay: non-empty string}
    if let Some(policy) = obj.get("policy") {
        if let Err(verdict) = require_keys(policy, &["overlay"], &["overlay"], "config.policy") {
            return verdict;
        }
        if let Err(verdict) = expect_str(policy, "overlay", "config.policy", None) {
            return verdict;
        }
    }
    // repository.<slug>: {origin: string required, branch?: string, enabled?: bool}
    if let Some(repositories) = obj.get("repository") {
        let Val::Obj(entries) = repositories else {
            return Verdict::refuse(Refusal::Malformed, "config.repository must be a table");
        };
        for (name, entry) in entries {
            if !is_slug(name) {
                return Verdict::refuse(
                    Refusal::Malformed,
                    format!("config.repository key {name:?} invalid (slug required)"),
                );
            }
            let where_ = format!("config.repository.{name}");
            if let Err(verdict) = table(entry, &where_) {
                return verdict;
            }
            if let Err(verdict) = require_keys(
                entry,
                &["origin"],
                &["origin", "branch", "enabled"],
                &where_,
            ) {
                return verdict;
            }
            if let Err(verdict) = expect_str(entry, "origin", &where_, None) {
                return verdict;
            }
            // Normative-table strictness: branch must be a string and enabled
            // a boolean when present (the fixture probe checks origin only;
            // these types come from docs/contracts/spec-config.md).
            if let Err(verdict) = expect_str(entry, "branch", &where_, None) {
                return verdict;
            }
            if let Err(verdict) = expect_bool(entry, "enabled", &where_) {
                return verdict;
            }
        }
    }
    // harness.<key>: {kind, executable, env_allow} plus the optional
    // provider/model binding pair (issue #80; bare-token validation lives
    // in the decoder, config.rs)
    if let Some(harnesses) = obj.get("harness") {
        let Val::Obj(entries) = harnesses else {
            return Verdict::refuse(Refusal::Malformed, "config.harness must be a table");
        };
        for (name, entry) in entries {
            let where_ = format!("config.harness.{name}");
            if let Err(verdict) = table(entry, &where_) {
                return verdict;
            }
            if let Err(verdict) = require_keys(
                entry,
                &["kind", "executable", "env_allow"],
                &[
                    "kind",
                    "executable",
                    "env_allow",
                    "provider",
                    "model",
                    "fallback",
                    "secret_env",
                    "limits",
                    "binding_introspection",
                ],
                &where_,
            ) {
                return verdict;
            }
            if let Err(verdict) = expect_str(entry, "kind", &where_, None) {
                return verdict;
            }
            if let Err(verdict) = expect_str(entry, "executable", &where_, None) {
                return verdict;
            }
            if let Err(verdict) = expect_str(entry, "provider", &where_, None) {
                return verdict;
            }
            if let Err(verdict) = expect_str(entry, "model", &where_, None) {
                return verdict;
            }
            // Issue #77 profile-planning keys: shape only (the decoder in
            // config.rs validates the bare-token/allowlist semantics).
            for key in ["fallback", "secret_env"] {
                match entry.get(key) {
                    None => {}
                    Some(Val::Arr(items)) => {
                        for item in items {
                            if !matches!(item, Val::Str(_)) {
                                return Verdict::refuse(
                                    Refusal::Malformed,
                                    format!("{where_}.{key} must be a [string]"),
                                );
                            }
                        }
                    }
                    Some(other) => {
                        return Verdict::refuse(
                            Refusal::Malformed,
                            format!(
                                "{where_}.{key} must be an array of strings, got {}",
                                other.type_name()
                            ),
                        );
                    }
                }
            }
            if let Some(limits) = entry.get("limits") {
                let Val::Obj(limits) = limits else {
                    return Verdict::refuse(
                        Refusal::Malformed,
                        format!("{where_}.limits must be a table of scalar values"),
                    );
                };
                for (name, value) in limits {
                    if !matches!(value, Val::Str(_) | Val::Int(_)) {
                        return Verdict::refuse(
                            Refusal::Malformed,
                            format!(
                                "{where_}.limits.{name} must be a string or integer, got {}",
                                value.type_name()
                            ),
                        );
                    }
                }
            }
            if let Err(verdict) = expect_bool(entry, "binding_introspection", &where_) {
                return verdict;
            }
            match entry.get("env_allow") {
                Some(Val::Arr(items)) => {
                    for item in items {
                        if !matches!(item, Val::Str(_)) {
                            return Verdict::refuse(
                                Refusal::Malformed,
                                format!("{where_}.env_allow must be a [string]"),
                            );
                        }
                    }
                }
                Some(other) => {
                    return Verdict::refuse(
                        Refusal::Malformed,
                        format!(
                            "{where_}.env_allow must be an array of strings, got {}",
                            other.type_name()
                        ),
                    );
                }
                None => unreachable!("require_keys enforced env_allow"),
            }
        }
    }
    // workflow.<key>: {id: non-empty string, hash: 64-hex}; role.<key>: {hash}
    for (table_key, allowed) in [("workflow", &["id", "hash"][..]), ("role", &["hash"][..])] {
        if let Some(entries) = obj.get(table_key) {
            let Val::Obj(map) = entries else {
                return Verdict::refuse(
                    Refusal::Malformed,
                    format!("config.{table_key} must be a table"),
                );
            };
            for (name, entry) in map {
                let where_ = format!("config.{table_key}.{name}");
                if let Err(verdict) = table(entry, &where_) {
                    return verdict;
                }
                if let Err(verdict) = require_keys(entry, allowed, allowed, &where_) {
                    return verdict;
                }
                if let Err(verdict) = expect_str(entry, "id", &where_, None) {
                    return verdict;
                }
                if let Err(verdict) = expect_str(entry, "hash", &where_, Some(is_hex64)) {
                    return verdict;
                }
            }
        }
    }
    Verdict::accept()
}

fn validate_policy(obj: &Val) -> Verdict {
    if let Err(verdict) = check_schema(obj, Family::Policy) {
        return verdict;
    }
    if let Err(verdict) = require_keys(obj, &["schema"], &POLICY_TOP_KEYS, "policy") {
        return verdict;
    }
    let constraining = ["repositories", "production_confirmation", "role"]
        .iter()
        .any(|key| obj.get(key).is_some());
    if !constraining {
        return Verdict::refuse(
            Refusal::Malformed,
            "policy: overlay must constrain at least one axis",
        );
    }
    if let Some(repositories) = obj.get("repositories") {
        match repositories {
            Val::Arr(items) if !items.is_empty() => {
                for item in items {
                    let ok = matches!(item, Val::Str(text) if is_repository_identity(text));
                    if !ok {
                        return Verdict::refuse(
                            Refusal::Malformed,
                            "policy.repositories must be a non-empty [owner/name]",
                        );
                    }
                }
            }
            _ => {
                return Verdict::refuse(
                    Refusal::Malformed,
                    "policy.repositories must be a non-empty [owner/name]",
                );
            }
        }
    }
    if let Some(confirmation) = obj.get("production_confirmation") {
        match confirmation {
            Val::Str(text) if text == "tty" || text == "deny" => {}
            other => {
                return Verdict::refuse(
                    Refusal::Malformed,
                    format!(
                        "policy.production_confirmation must be one of tty|deny (overlay may only tighten), got {}",
                        other.type_name()
                    ),
                );
            }
        }
    }
    if let Some(roles) = obj.get("role") {
        let Val::Obj(map) = roles else {
            return Verdict::refuse(Refusal::Malformed, "policy.role must be a table");
        };
        for (name, entry) in map {
            let where_ = format!("policy.role.{name}");
            if let Err(verdict) = table(entry, &where_) {
                return verdict;
            }
            if let Err(verdict) = require_keys(entry, &["hash"], &["hash"], &where_) {
                return verdict;
            }
            if let Err(verdict) = expect_str(entry, "hash", &where_, Some(is_hex64)) {
                return verdict;
            }
        }
    }
    Verdict::accept()
}

fn validate_output(obj: &Val) -> Verdict {
    if let Err(verdict) = check_schema(obj, Family::Output) {
        return verdict;
    }
    if let Err(verdict) = require_keys(
        obj,
        &["schema", "command", "kind", "exit_code"],
        &["schema", "command", "kind", "exit_code", "data", "error"],
        "output",
    ) {
        return verdict;
    }
    if let Err(verdict) = expect_str(obj, "command", "output", None) {
        return verdict;
    }
    if let Err(verdict) = expect_in(obj, "kind", "output", &["ok", "error", "partial"]) {
        return verdict;
    }

    match obj.get("exit_code") {
        Some(Val::Int(code)) if (0..=255).contains(code) => {}
        Some(other) => {
            return Verdict::refuse(
                Refusal::Malformed,
                format!(
                    "output.exit_code must be an int in 0..=255, got {}",
                    other.type_name()
                ),
            );
        }
        None => {
            return Verdict::refuse(Refusal::Malformed, "output: missing required exit_code");
        }
    }
    match obj.get("kind") {
        Some(Val::Str(kind)) if kind == "error" => {
            let Some(error) = obj.get("error") else {
                return Verdict::refuse(
                    Refusal::Malformed,
                    "output: error kind requires an error object",
                );
            };
            if let Err(verdict) = err_shaped(error) {
                return verdict;
            }
        }
        _ => {
            let Some(data) = obj.get("data") else {
                return Verdict::refuse(
                    Refusal::Malformed,
                    "output: ok|partial kind requires a data object",
                );
            };
            if let Err(verdict) = table(data, "output.data") {
                return verdict;
            }
        }
    }
    Verdict::accept()
}

fn validate_error(obj: &Val) -> Verdict {
    if let Err(verdict) = check_schema(obj, Family::Error) {
        return verdict;
    }
    let allowed = ["schema", "code", "message", "retryable", "details"];
    if let Err(verdict) = require_keys(obj, &allowed, &allowed, "error") {
        return verdict;
    }
    if let Err(verdict) = expect_str(obj, "code", "error", Some(is_error_code)) {
        return verdict;
    }
    if let Err(verdict) = expect_str(obj, "message", "error", None) {
        return verdict;
    }
    match obj.get("retryable") {
        Some(Val::Bool(_)) => {}
        Some(other) => {
            return Verdict::refuse(
                Refusal::Malformed,
                format!(
                    "error.retryable must be a boolean, got {}",
                    other.type_name()
                ),
            );
        }
        None => {
            return Verdict::refuse(Refusal::Malformed, "error: missing required retryable");
        }
    }
    match obj.get("details") {
        None | Some(Val::Null) | Some(Val::Obj(_)) => {}
        Some(other) => {
            return Verdict::refuse(
                Refusal::Malformed,
                format!(
                    "error.details must be an object or null, got {}",
                    other.type_name()
                ),
            );
        }
    }
    Verdict::accept()
}

fn validate_observation(obj: &Val) -> Verdict {
    if let Err(verdict) = check_schema(obj, Family::Observation) {
        return verdict;
    }
    if let Err(verdict) = require_keys(
        obj,
        &[
            "schema",
            "subject",
            "observed_at",
            "freshness",
            "completeness",
        ],
        &[
            "schema",
            "subject",
            "observed_at",
            "freshness",
            "completeness",
            "payload",
        ],
        "observation",
    ) {
        return verdict;
    }
    let Some(subject) = obj.get("subject") else {
        return Verdict::refuse(Refusal::Malformed, "observation: missing required subject");
    };
    if let Err(verdict) = table(subject, "observation.subject") {
        return verdict;
    }
    if let Err(verdict) = expect_in(
        subject,
        "type",
        "observation.subject",
        &["repository", "agent", "host"],
    ) {
        return verdict;
    }
    if let Err(verdict) = expect_str(subject, "id", "observation.subject", None) {
        return verdict;
    }
    if let Err(verdict) = expect_timestamp(obj, "observed_at", "observation") {
        return verdict;
    }
    if let Err(verdict) = expect_in(
        obj,
        "freshness",
        "observation",
        &["fresh", "stale", "unknown"],
    ) {
        return verdict;
    }
    if let Err(verdict) = expect_in(obj, "completeness", "observation", &["complete", "partial"]) {
        return verdict;
    }
    if let Some(payload) = obj.get("payload")
        && let Err(verdict) = table(payload, "observation.payload")
    {
        return verdict;
    }
    Verdict::accept()
}

fn validate_plan(obj: &Val) -> Verdict {
    if let Err(verdict) = check_schema(obj, Family::Plan) {
        return verdict;
    }
    let allowed = [
        "schema",
        "plan_id",
        "workflow_id",
        "workflow_hash",
        "state_epoch",
        "repository",
        "issue",
        "steps",
    ];
    if let Err(verdict) = require_keys(obj, &allowed, &allowed, "plan") {
        return verdict;
    }
    if let Err(verdict) = expect_str(obj, "plan_id", "plan", Some(is_plan_id)) {
        return verdict;
    }
    if let Err(verdict) = expect_str(obj, "workflow_id", "plan", Some(is_slug)) {
        return verdict;
    }
    if let Err(verdict) = expect_str(obj, "workflow_hash", "plan", Some(is_hex64)) {
        return verdict;
    }
    if let Err(verdict) = expect_int(obj, "state_epoch", "plan", 0) {
        return verdict;
    }
    if let Err(verdict) = expect_str(obj, "repository", "plan", Some(is_repository_identity)) {
        return verdict;
    }
    let Some(issue) = obj.get("issue") else {
        return Verdict::refuse(Refusal::Malformed, "plan: missing required issue");
    };
    if let Err(verdict) = issue_shaped(issue) {
        return verdict;
    }
    let Some(steps) = obj.get("steps") else {
        return Verdict::refuse(Refusal::Malformed, "plan: missing required steps");
    };
    // Closed plan step kinds. The base kinds ship from issue #3/#4; the
    // granular control-plane kinds (branch_push, pr_update, issue_update,
    // hosted_check, post_merge_verify, branch_delete, approve) are added by
    // issue #8 so a plan document can express the full daemon-mediated
    // mutation surface (docs/contracts/spec-plans.md §1 apply semantics).
    const STEP_KINDS: [&str; 16] = [
        "checkout",
        "worktree_create",
        "harness_start",
        "prompt",
        "collect_outcome",
        "review_evidence",
        "merge",
        "cleanup",
        "publish",
        "branch_push",
        "pr_update",
        "issue_update",
        "hosted_check",
        "post_merge_verify",
        "branch_delete",
        "approve",
    ];
    match steps {
        Val::Arr(items) if !items.is_empty() => {
            for step in items {
                if let Err(verdict) = table(step, "plan step") {
                    return verdict;
                }
                if let Err(verdict) = expect_str(step, "id", "plan step", Some(is_slug)) {
                    return verdict;
                }
                match step.get("kind") {
                    Some(Val::Str(kind)) if STEP_KINDS.contains(&kind.as_str()) => {}
                    _ => {
                        return Verdict::refuse(
                            Refusal::Malformed,
                            "plan step kind outside closed set",
                        );
                    }
                }
                match step.get("params") {
                    None | Some(Val::Null) => {}
                    Some(Val::Obj(params))
                        if params
                            .keys()
                            .all(|key| crate::formats::is_step_param_name(key)) => {}
                    Some(other) => {
                        return Verdict::refuse(
                            Refusal::Malformed,
                            format!(
                                "plan step params must be an object or null, got {}",
                                other.type_name()
                            ),
                        );
                    }
                }
            }
        }
        _ => return Verdict::refuse(Refusal::Malformed, "plan.steps must be a non-empty list"),
    }
    Verdict::accept()
}

fn validate_capability(obj: &Val) -> Verdict {
    if let Err(verdict) = check_schema(obj, Family::Capability) {
        return verdict;
    }
    if let Err(verdict) = require_keys(
        obj,
        &["schema", "axis", "actor", "capabilities"],
        &["schema", "axis", "actor", "capabilities"],
        "capability",
    ) {
        return verdict;
    }
    let axis = match obj.get("axis") {
        Some(Val::Str(text)) if text == "harness" || text == "forge" => text.as_str(),
        Some(other) => {
            return Verdict::refuse(
                Refusal::Malformed,
                format!(
                    "capability.axis outside closed set, got {}",
                    other.type_name()
                ),
            );
        }
        None => return Verdict::refuse(Refusal::Malformed, "capability: missing required axis"),
    };
    if let Err(verdict) = expect_str(obj, "actor", "capability", Some(is_actor)) {
        return verdict;
    }
    let closed: &[&str] = if axis == "harness" {
        &[
            "discover",
            "start",
            "prompt",
            "observe",
            "interrupt",
            "outcome",
            "identity",
        ]
    } else {
        &[
            "read_refs",
            "read_issues",
            "read_checks",
            "create_pr",
            "comment",
        ]
    };
    match obj.get("capabilities") {
        Some(Val::Arr(items)) if !items.is_empty() => {
            for item in items {
                let ok = matches!(item, Val::Str(text) if closed.contains(&text.as_str()));
                if !ok {
                    return Verdict::refuse(
                        Refusal::Malformed,
                        format!(
                            "capability.capabilities must be a non-empty subset of the closed {axis} set"
                        ),
                    );
                }
            }
        }
        _ => {
            return Verdict::refuse(
                Refusal::Malformed,
                format!(
                    "capability.capabilities must be a non-empty subset of the closed {axis} set"
                ),
            );
        }
    }
    Verdict::accept()
}

/// Registry of the families this module validates (used by drift tests).
pub const SUPPORTED_FAMILIES: [Family; 18] = [
    Family::Config,
    Family::Policy,
    Family::Output,
    Family::Error,
    Family::Observation,
    Family::Plan,
    Family::Capability,
    Family::RpcRequest,
    Family::RpcResponse,
    Family::Event,
    Family::Audit,
    Family::Migration,
    Family::Epoch,
    Family::Grant,
    Family::Outcome,
    Family::Workflow,
    Family::Schedule,
    Family::Board,
];

// ---------------------------------------------------------------------------
// Daemon wire/state family validators (mirror the probe's validators)
// ---------------------------------------------------------------------------

/// Closed RPC method set (spec-daemon.md; mirrored by the fixture probe).
/// The five `schedules.*` lifecycle methods beyond `schedules.list` are
/// added by issue #9 (recurring non-destructive schedules: create/pause/
/// resume/delete + one fresh coalesced evaluation per tick). The five
/// `lane.replacement.*` methods are added by issue #73 (request-only lane
/// replacement records: request/advance/hold/cancel + one status read).
/// `lane.checkpoint.*` methods are added by issue #74 (one atomic
/// checkpoint capture after verified quiescence + one status read). The
/// `lane.retire` method is added by issue #75 (one guarded retirement of a
/// checkpointed source session: bounded graceful stop + backend-evidence
/// confirmation). The `lane.start` / `lane.adopt` / `lane.successor.consume`
/// methods are added by issue #76 (one daemon-coordinated start/adopt
/// transition: one generation/nonce owns the fresh successor, adapter-
/// observed verification, a reconciliation-not-replay adoption re-query,
/// and exactly-once completion consumption after adoption). The
/// `grants.issue` method is added by issue #92 (the supported production
/// mint path for route grants: `params.grant` carries the exact
/// `hf-grant/v1` document, issuance stays daemon-issued — the closed set
/// grows by exactly the one method issuance needs); `run.release` is added
/// by issue #146 (the explicit release of a run that can never progress);
/// `run.reevaluate` is added by issue #230 (the bounded, audited re-evaluation
/// of a run's own recorded checks by their producer); `queue.redrive` is added
/// by issue #236 (the bounded, audited operator re-drive of ONE committed
/// submission's parked items).
pub const RPC_METHODS: [&str; 44] = [
    "capabilities",
    "doctor",
    "status",
    "plan",
    "apply",
    "grants.issue",
    "grants.list",
    "grants.revoke",
    "schedules.list",
    "schedules.create",
    "schedules.pause",
    "schedules.resume",
    "schedules.delete",
    "schedules.evaluate",
    "lane.replacement.request",
    "lane.replacement.advance",
    "lane.replacement.hold",
    "lane.replacement.cancel",
    "lane.replacement.status",
    "lane.checkpoint.create",
    "lane.checkpoint.status",
    "lane.retire",
    "lane.start",
    "lane.adopt",
    "lane.successor.consume",
    "state.epoch",
    "queue.submit",
    "queue.status",
    "queue.redrive",
    "run.pause",
    "run.resume",
    "run.retry",
    "run.reevaluate",
    "run.release",
    "run.retire-lane",
    "run.resolve",
    "run.dispatch",
    "run.status",
    "supervision.status",
    "supervision.arm",
    "backup.create",
    "restore.begin",
    "journal.tail",
    "events.subscribe",
];

/// Closed hf-event/v1 event-kind set (spec-daemon.md).
pub const EVENT_KINDS: [&str; 7] = [
    "state.snapshot",
    "agent.updated",
    "plan.updated",
    "grant.updated",
    "journal.appended",
    "epoch.rotated",
    "schedule.ran",
];

/// Closed hf-grant/v1 phase set (spec-plans.md §2).
pub const GRANT_PHASES: [&str; 9] = [
    "plan",
    "read",
    "worktree",
    "spawn",
    "review",
    "merge",
    "production",
    "cleanup",
    "recovery",
];

/// Closed hf-grant/v1 capability set (spec-plans.md §2).
pub const GRANT_CAPS: [&str; 9] = [
    "read",
    "worktree",
    "spawn",
    "prompt",
    "review",
    "merge",
    "production",
    "cleanup",
    "release",
];

/// Closed hf-schedule/v1 phase (issue #9): schedules may only carry the
/// read phase — production/destructive work can never be scheduled
/// (risk-model.md operational rule 4; refusal.policy.scheduled).
pub const SCHEDULE_PHASE: &str = "read";

/// Closed hf-schedule/v1 capability set (issue #9): bounded non-destructive
/// recurring grants carry exactly the read capability (every read-class
/// plan step — checkout, collect_outcome, hosted_check, post_merge_verify —
/// requires it). A schedule document naming any other capability is refused.
pub const SCHEDULE_CAPS: [&str; 1] = ["read"];

fn validate_rpc_request(obj: &Val) -> Verdict {
    if let Err(verdict) = check_schema(obj, Family::RpcRequest) {
        return verdict;
    }
    if let Err(verdict) = require_keys(
        obj,
        &["schema", "id", "method", "params"],
        &["schema", "id", "method", "params"],
        "rpc-request",
    ) {
        return verdict;
    }
    match obj.get("id") {
        Some(Val::Str(text)) if is_request_id(text) => {}
        _ => {
            return Verdict::refuse(
                Refusal::Malformed,
                "rpc-request.id must be 8-64 lowercase hex",
            );
        }
    }
    match obj.get("method") {
        Some(Val::Str(text)) if RPC_METHODS.contains(&text.as_str()) => {}
        _ => {
            return Verdict::refuse(
                Refusal::Malformed,
                "rpc-request.method outside the closed method set",
            );
        }
    }
    match obj.get("params") {
        None | Some(Val::Null) | Some(Val::Obj(_)) => {}
        _ => {
            return Verdict::refuse(
                Refusal::Malformed,
                "rpc-request.params must be object or null",
            );
        }
    }
    if matches!(obj.get("method"), Some(Val::Str(text)) if text == "apply") {
        let params = obj.get("params");
        let key_ok = match params {
            Some(Val::Obj(_)) => matches!(
                params.and_then(|p| p.get("idempotency_key")),
                Some(Val::Str(text)) if is_idempotency_key(text)
            ),
            _ => false,
        };
        if !key_ok {
            return Verdict::refuse(
                Refusal::Malformed,
                "rpc-request: apply requires params.idempotency_key (ik_ format)",
            );
        }
    }
    Verdict::accept()
}

fn validate_rpc_response(obj: &Val) -> Verdict {
    if let Err(verdict) = check_schema(obj, Family::RpcResponse) {
        return verdict;
    }
    if let Err(verdict) = require_keys(
        obj,
        &["schema", "id", "ok", "result", "error"],
        &["schema", "id", "ok", "result", "error"],
        "rpc-response",
    ) {
        return verdict;
    }
    match obj.get("id") {
        Some(Val::Str(text)) if is_request_id(text) => {}
        _ => {
            return Verdict::refuse(
                Refusal::Malformed,
                "rpc-response.id must be 8-64 lowercase hex",
            );
        }
    }
    let ok = match obj.get("ok") {
        Some(Val::Bool(value)) => *value,
        _ => {
            return Verdict::refuse(Refusal::Malformed, "rpc-response.ok must be a boolean");
        }
    };
    if ok {
        if !matches!(obj.get("error"), None | Some(Val::Null)) {
            return Verdict::refuse(
                Refusal::Malformed,
                "rpc-response: ok responses must have null error",
            );
        }
        if !matches!(obj.get("result"), Some(Val::Obj(_))) {
            return Verdict::refuse(
                Refusal::Malformed,
                "rpc-response: ok responses require a result object",
            );
        }
    } else {
        if !matches!(obj.get("result"), None | Some(Val::Null)) {
            return Verdict::refuse(
                Refusal::Malformed,
                "rpc-response: failed responses must have null result",
            );
        }
        match obj.get("error") {
            Some(value) => {
                if let Err(verdict) = err_shaped(value) {
                    return verdict;
                }
            }
            None => {
                return Verdict::refuse(
                    Refusal::Malformed,
                    "rpc-response: failed responses require an error object",
                );
            }
        }
    }
    Verdict::accept()
}

fn validate_event(obj: &Val) -> Verdict {
    if let Err(verdict) = check_schema(obj, Family::Event) {
        return verdict;
    }
    if let Err(verdict) = require_keys(
        obj,
        &["schema", "event", "seq", "ts", "data"],
        &["schema", "event", "seq", "ts", "data"],
        "event",
    ) {
        return verdict;
    }
    match obj.get("event") {
        Some(Val::Str(text)) if EVENT_KINDS.contains(&text.as_str()) => {}
        _ => {
            return Verdict::refuse(Refusal::Malformed, "event kind outside the closed set");
        }
    }
    if let Err(verdict) = expect_int(obj, "seq", "event", 0) {
        return verdict;
    }
    if let Err(verdict) = expect_timestamp(obj, "ts", "event") {
        return verdict;
    }
    if !matches!(obj.get("data"), Some(Val::Obj(_))) {
        return Verdict::refuse(Refusal::Malformed, "event.data must be an object");
    }
    Verdict::accept()
}

fn validate_audit(obj: &Val) -> Verdict {
    if let Err(verdict) = check_schema(obj, Family::Audit) {
        return verdict;
    }
    const KEYS: [&str; 10] = [
        "schema",
        "seq",
        "action",
        "target",
        "idempotency_key",
        "plan_hash",
        "grant_id",
        "epoch",
        "recorded_before_mutation",
        "at",
    ];
    if let Err(verdict) = require_keys(obj, &KEYS, &KEYS, "audit") {
        return verdict;
    }
    if let Err(verdict) = expect_int(obj, "seq", "audit", 0) {
        return verdict;
    }
    match obj.get("action") {
        Some(Val::Str(text)) if is_action_code(text) => {}
        _ => {
            return Verdict::refuse(Refusal::Malformed, "audit.action invalid");
        }
    }
    match obj.get("target") {
        Some(Val::Str(text)) if !text.is_empty() => {}
        _ => {
            return Verdict::refuse(Refusal::Malformed, "audit.target must be non-empty");
        }
    }
    match obj.get("idempotency_key") {
        Some(Val::Str(text)) if is_idempotency_key(text) => {}
        _ => {
            return Verdict::refuse(Refusal::Malformed, "audit.idempotency_key invalid");
        }
    }
    for (key, check) in [
        ("plan_hash", is_hex64 as fn(&str) -> bool),
        ("grant_id", is_grant_id),
    ] {
        match obj.get(key) {
            None | Some(Val::Null) => {}
            Some(Val::Str(text)) if check(text) => {}
            _ => {
                return Verdict::refuse(Refusal::Malformed, format!("audit.{key} invalid"));
            }
        }
    }
    if let Err(verdict) = expect_int(obj, "epoch", "audit", 0) {
        return verdict;
    }
    let recorded_before = match obj.get("recorded_before_mutation") {
        Some(Val::Bool(value)) => *value,
        _ => {
            return Verdict::refuse(
                Refusal::Malformed,
                "audit.recorded_before_mutation must be a boolean",
            );
        }
    };
    if let Some(Val::Str(action)) = obj.get("action")
        && action.starts_with("mutate.")
        && !recorded_before
    {
        return Verdict::refuse(
            Refusal::Malformed,
            "audit: mutation actions must be journaled before the mutation (fail closed)",
        );
    }
    if let Err(verdict) = expect_timestamp(obj, "at", "audit") {
        return verdict;
    }
    Verdict::accept()
}

fn validate_migration(obj: &Val) -> Verdict {
    if let Err(verdict) = check_schema(obj, Family::Migration) {
        return verdict;
    }
    if let Err(verdict) = require_keys(
        obj,
        &[
            "schema",
            "migration_id",
            "applies_from",
            "applies_to",
            "checksum",
            "description",
        ],
        &[
            "schema",
            "migration_id",
            "applies_from",
            "applies_to",
            "checksum",
            "description",
        ],
        "migration",
    ) {
        return verdict;
    }
    match obj.get("migration_id") {
        Some(Val::Str(text)) if is_migration_id(text) => {}
        _ => {
            return Verdict::refuse(Refusal::Malformed, "migration.migration_id invalid");
        }
    }
    if let Err(verdict) = expect_int(obj, "applies_from", "migration", 0) {
        return verdict;
    }
    if let Err(verdict) = expect_int(obj, "applies_to", "migration", 0) {
        return verdict;
    }
    let (from, to) = match (obj.get("applies_from"), obj.get("applies_to")) {
        (Some(Val::Int(from)), Some(Val::Int(to))) => (*from, *to),
        _ => unreachable!("expect_int enforced integers"),
    };
    if to != from + 1 {
        return Verdict::refuse(
            Refusal::Malformed,
            "migration: applies_to must be exactly applies_from + 1 (linear, ordered)",
        );
    }
    match obj.get("checksum") {
        Some(Val::Str(text)) if is_hex64(text) => {}
        _ => {
            return Verdict::refuse(Refusal::Malformed, "migration.checksum must be 64-hex");
        }
    }
    match obj.get("description") {
        Some(Val::Str(text)) if !text.is_empty() => {}
        _ => {
            return Verdict::refuse(
                Refusal::Malformed,
                "migration.description must be non-empty",
            );
        }
    }
    Verdict::accept()
}

fn validate_epoch(obj: &Val) -> Verdict {
    if let Err(verdict) = check_schema(obj, Family::Epoch) {
        return verdict;
    }
    if let Err(verdict) = require_keys(
        obj,
        &["schema", "epoch", "created_at", "reason", "prior_epoch"],
        &["schema", "epoch", "created_at", "reason", "prior_epoch"],
        "epoch",
    ) {
        return verdict;
    }
    if let Err(verdict) = expect_int(obj, "epoch", "epoch", 0) {
        return verdict;
    }
    if let Err(verdict) = expect_timestamp(obj, "created_at", "epoch") {
        return verdict;
    }
    match obj.get("reason") {
        Some(Val::Str(text))
            if matches!(text.as_str(), "initial" | "restore" | "security_rotation") => {}
        _ => {
            return Verdict::refuse(Refusal::Malformed, "epoch.reason outside closed set");
        }
    }
    let prior = obj.get("prior_epoch");
    match obj.get("reason") {
        Some(Val::Str(text)) if text == "initial" => {
            if !matches!(prior, None | Some(Val::Null)) {
                return Verdict::refuse(
                    Refusal::Malformed,
                    "epoch: initial epoch must have prior_epoch null",
                );
            }
        }
        _ => match prior {
            Some(Val::Int(number)) if *number >= 0 => {}
            _ => {
                return Verdict::refuse(
                    Refusal::Malformed,
                    "epoch: rotations must reference a prior_epoch integer",
                );
            }
        },
    }
    Verdict::accept()
}

fn validate_grant(obj: &Val) -> Verdict {
    if let Err(verdict) = check_schema(obj, Family::Grant) {
        return verdict;
    }
    const KEYS: [&str; 12] = [
        "schema",
        "grant_id",
        "repository",
        "issue",
        "workflow_hash",
        "policy_hash",
        "phase",
        "scope",
        "caps",
        "expires_at",
        "state_epoch",
        "created_at",
    ];
    if let Err(verdict) = require_keys(obj, &KEYS, &KEYS, "grant") {
        return verdict;
    }
    match obj.get("grant_id") {
        Some(Val::Str(text)) if is_grant_id(text) => {}
        _ => {
            return Verdict::refuse(Refusal::Malformed, "grant.grant_id invalid");
        }
    }
    match obj.get("repository") {
        Some(Val::Str(text)) if is_repository_identity(text) => {}
        _ => {
            return Verdict::refuse(Refusal::Malformed, "grant.repository must be owner/name");
        }
    }
    if let Some(issue) = obj.get("issue")
        && let Err(verdict) = issue_shaped(issue)
    {
        return verdict;
    }
    for key in ["workflow_hash", "policy_hash"] {
        match obj.get(key) {
            Some(Val::Str(text)) if is_hex64(text) => {}
            _ => {
                return Verdict::refuse(Refusal::Malformed, format!("grant.{key} must be 64-hex"));
            }
        }
    }
    match obj.get("phase") {
        Some(Val::Str(text)) if GRANT_PHASES.contains(&text.as_str()) => {}
        _ => {
            return Verdict::refuse(Refusal::Malformed, "grant.phase outside closed set");
        }
    }
    match obj.get("scope") {
        Some(Val::Str(text)) if !text.is_empty() && text.len() <= 256 => {}
        _ => {
            return Verdict::refuse(
                Refusal::Malformed,
                "grant.scope must be a non-empty string <= 256 chars",
            );
        }
    }
    let caps = obj.get("caps");
    let caps_ok = match caps {
        Some(Val::Arr(items)) if !items.is_empty() => items
            .iter()
            .all(|item| matches!(item, Val::Str(text) if GRANT_CAPS.contains(&text.as_str()))),
        _ => false,
    };
    if !caps_ok {
        return Verdict::refuse(
            Refusal::Malformed,
            "grant.caps must be a non-empty subset of the closed set",
        );
    }
    if let Err(verdict) = expect_timestamp(obj, "expires_at", "grant") {
        return verdict;
    }
    if let Err(verdict) = expect_int(obj, "state_epoch", "grant", 0) {
        return verdict;
    }
    if let Err(verdict) = expect_timestamp(obj, "created_at", "grant") {
        return verdict;
    }
    Verdict::accept()
}

/// Validate an `hf-schedule/v1` document (issue #9 lifecycle slice): the
/// recurring non-destructive cadence record. Every field mirrors the
/// recurring-grant bindings (repository/issue, workflow + policy hashes,
/// exact scope, read-only caps, expiry) plus the cadence (`anchor`,
/// `every_secs`). A schedule may only carry the read phase and read
/// capability — production/destructive work can never be scheduled and a
/// document naming any other capability/phase is refused (risk-model.md
/// operational rule 4; non-downgrade rule).
fn validate_schedule(obj: &Val) -> Verdict {
    if let Err(verdict) = check_schema(obj, Family::Schedule) {
        return verdict;
    }
    const KEYS: [&str; 12] = [
        "schema",
        "schedule_id",
        "repository",
        "issue",
        "workflow_hash",
        "policy_hash",
        "phase",
        "scope",
        "caps",
        "expires_at",
        "anchor",
        "every_secs",
    ];
    if let Err(verdict) = require_keys(obj, &KEYS, &KEYS, "schedule") {
        return verdict;
    }
    match obj.get("schedule_id") {
        Some(Val::Str(text)) if is_schedule_id(text) => {}
        _ => {
            return Verdict::refuse(Refusal::Malformed, "schedule.schedule_id invalid");
        }
    }
    match obj.get("repository") {
        Some(Val::Str(text)) if is_repository_identity(text) => {}
        _ => {
            return Verdict::refuse(Refusal::Malformed, "schedule.repository must be owner/name");
        }
    }
    if let Some(issue) = obj.get("issue")
        && let Err(verdict) = issue_shaped(issue)
    {
        return verdict;
    }
    for key in ["workflow_hash", "policy_hash"] {
        match obj.get(key) {
            Some(Val::Str(text)) if is_hex64(text) => {}
            _ => {
                return Verdict::refuse(
                    Refusal::Malformed,
                    format!("schedule.{key} must be 64-hex"),
                );
            }
        }
    }
    match obj.get("phase") {
        Some(Val::Str(text)) if text == SCHEDULE_PHASE => {}
        _ => {
            return Verdict::refuse(
                Refusal::Malformed,
                "schedule.phase must be exactly 'read' (production/destructive work is never schedulable)",
            );
        }
    }
    match obj.get("scope") {
        Some(Val::Str(text)) if !text.is_empty() && text.len() <= 256 => {}
        _ => {
            return Verdict::refuse(
                Refusal::Malformed,
                "schedule.scope must be a non-empty string <= 256 chars",
            );
        }
    }
    let caps = obj.get("caps");
    let caps_ok = match caps {
        Some(Val::Arr(items)) if !items.is_empty() => items
            .iter()
            .all(|item| matches!(item, Val::Str(text) if SCHEDULE_CAPS.contains(&text.as_str()))),
        _ => false,
    };
    if !caps_ok {
        return Verdict::refuse(
            Refusal::Malformed,
            "schedule.caps must be a non-empty subset of the closed read-only set ([\"read\"])",
        );
    }
    if let Err(verdict) = expect_timestamp(obj, "expires_at", "schedule") {
        return verdict;
    }
    if let Err(verdict) = expect_timestamp(obj, "anchor", "schedule") {
        return verdict;
    }
    match obj.get("every_secs") {
        Some(Val::Int(seconds)) if *seconds > 0 => {}
        _ => {
            return Verdict::refuse(
                Refusal::Malformed,
                "schedule.every_secs must be a positive integer",
            );
        }
    }
    Verdict::accept()
}

fn validate_outcome(obj: &Val) -> Verdict {
    if let Err(verdict) = check_schema(obj, Family::Outcome) {
        return verdict;
    }
    const KEYS: [&str; 8] = [
        "schema",
        "plan_id",
        "step_id",
        "status",
        "idempotency_key",
        "observed_at",
        "result",
        "error",
    ];
    if let Err(verdict) = require_keys(obj, &KEYS, &KEYS, "outcome") {
        return verdict;
    }
    match obj.get("plan_id") {
        Some(Val::Str(text)) if is_plan_id(text) => {}
        _ => {
            return Verdict::refuse(Refusal::Malformed, "outcome.plan_id invalid");
        }
    }
    match obj.get("step_id") {
        Some(Val::Str(text)) if is_slug(text) => {}
        _ => {
            return Verdict::refuse(Refusal::Malformed, "outcome.step_id invalid");
        }
    }
    match obj.get("status") {
        Some(Val::Str(text))
            if matches!(
                text.as_str(),
                "succeeded" | "failed" | "ambiguous" | "refused" | "superseded"
            ) => {}
        _ => {
            return Verdict::refuse(Refusal::Malformed, "outcome.status outside closed set");
        }
    }
    match obj.get("idempotency_key") {
        Some(Val::Str(text)) if is_idempotency_key(text) => {}
        _ => {
            return Verdict::refuse(Refusal::Malformed, "outcome.idempotency_key invalid");
        }
    }
    if let Err(verdict) = expect_timestamp(obj, "observed_at", "outcome") {
        return verdict;
    }
    for key in ["result", "error"] {
        match obj.get(key) {
            None | Some(Val::Null) | Some(Val::Obj(_)) => {}
            _ => {
                return Verdict::refuse(
                    Refusal::Malformed,
                    format!("outcome.{key} must be object or null"),
                );
            }
        }
    }
    if let Some(Val::Str(status)) = obj.get("status")
        && matches!(status.as_str(), "failed" | "refused")
    {
        match obj.get("error") {
            Some(value) if !matches!(value, Val::Null) => {
                if let Err(verdict) = err_shaped(value) {
                    return verdict;
                }
            }
            _ => {
                return Verdict::refuse(
                    Refusal::Malformed,
                    "outcome: failed|refused requires an error object",
                );
            }
        }
    }
    Verdict::accept()
}

/// Closed hf-workflow/v1 node kinds (spec-workflow.md; probe mirror).
pub const WORKFLOW_NODE_KINDS: [&str; 9] = [
    "start",
    "plan",
    "orchestrator",
    "implementer",
    "reviewer",
    "gate",
    "human_approval",
    "merge",
    "terminal",
];

fn validate_workflow(obj: &Val) -> Verdict {
    if let Err(verdict) = check_schema(obj, Family::Workflow) {
        return verdict;
    }
    const KEYS: [&str; 4] = ["schema", "workflow_id", "nodes", "edges"];
    if let Err(verdict) = require_keys(obj, &KEYS, &KEYS, "workflow") {
        return verdict;
    }
    match obj.get("workflow_id") {
        Some(Val::Str(text)) if is_slug(text) => {}
        _ => {
            return Verdict::refuse(Refusal::Malformed, "workflow.workflow_id invalid");
        }
    }
    let Some(nodes) = obj.get("nodes") else {
        return Verdict::refuse(Refusal::Malformed, "workflow: missing required nodes");
    };
    let Val::Arr(node_list) = nodes else {
        return Verdict::refuse(
            Refusal::Malformed,
            "workflow.nodes must be a non-empty list",
        );
    };
    if node_list.is_empty() {
        return Verdict::refuse(
            Refusal::Malformed,
            "workflow.nodes must be a non-empty list",
        );
    }
    let mut seen: Vec<&str> = Vec::with_capacity(node_list.len());
    for node in node_list {
        if let Err(verdict) = table(node, "workflow node") {
            return verdict;
        }
        if let Err(verdict) = expect_str(node, "id", "workflow node", Some(is_slug)) {
            return verdict;
        }
        let id = node.get("id").and_then(Val::as_str).unwrap_or_default();
        if seen.contains(&id) {
            return Verdict::refuse(
                Refusal::Malformed,
                format!("workflow: duplicate node id {id:?}"),
            );
        }
        seen.push(id);
        match node.get("kind") {
            Some(Val::Str(kind)) if WORKFLOW_NODE_KINDS.contains(&kind.as_str()) => {}
            _ => {
                return Verdict::refuse(
                    Refusal::Malformed,
                    "workflow node kind outside closed set",
                );
            }
        }
        if let Val::Obj(map) = node
            && let Some(extra) = map
                .keys()
                .find(|key| !matches!(key.as_str(), "id" | "kind" | "params"))
        {
            return Verdict::refuse(
                Refusal::Malformed,
                format!("workflow node {id:?}: unknown key {extra:?}"),
            );
        }
        match node.get("params") {
            None | Some(Val::Null) | Some(Val::Obj(_)) => {}
            Some(other) => {
                return Verdict::refuse(
                    Refusal::Malformed,
                    format!(
                        "workflow node params must be object or null, got {}",
                        other.type_name()
                    ),
                );
            }
        }
    }
    let Some(edges) = obj.get("edges") else {
        return Verdict::refuse(Refusal::Malformed, "workflow: missing required edges");
    };
    match edges {
        Val::Arr(edge_list) => {
            for edge in edge_list {
                if let Err(verdict) = table(edge, "workflow edge") {
                    return verdict;
                }
                let keys_ok = matches!(
                    edge,
                    Val::Obj(map)
                        if map.len() == 2 && map.contains_key("from") && map.contains_key("to")
                );
                if !keys_ok {
                    return Verdict::refuse(
                        Refusal::Malformed,
                        "workflow edge must have exactly from|to",
                    );
                }
                let from = edge.get("from").and_then(Val::as_str).unwrap_or_default();
                let to = edge.get("to").and_then(Val::as_str).unwrap_or_default();
                if !seen.contains(&from) || !seen.contains(&to) {
                    return Verdict::refuse(
                        Refusal::Malformed,
                        "workflow edge references an unknown node id",
                    );
                }
            }
        }
        _ => return Verdict::refuse(Refusal::Malformed, "workflow.edges must be a list"),
    }
    Verdict::accept()
}

// ---------------------------------------------------------------------------
// hf-board/v1 (issue #83 read model): closed sets + page validator
// ---------------------------------------------------------------------------

/// Closed `hf-board/v1` stage set (issue #83; approved #109 operator stages).
pub const BOARD_STAGES: [&str; 4] = ["planned", "in_progress", "needs_attention", "verified"];
/// Closed `hf-board/v1` verification set: `passed` exists only with recorded
/// review evidence; `none`/`failed` never present a run as verified.
pub const BOARD_VERIFICATIONS: [&str; 3] = ["none", "failed", "passed"];
/// Closed durable run-state set (`instances.status`).
pub const BOARD_RUN_STATES: [&str; 7] = [
    "new",
    "running",
    "paused",
    "human_queue",
    "blocked",
    "done",
    "invalidated",
];
/// Closed `next_action` set (null = not recorded is always allowed).
pub const BOARD_NEXT_ACTIONS: [&str; 2] = ["resume", "human_decision"];
/// Closed source-kind set for the intent side of a work item.
pub const BOARD_SOURCE_KINDS: [&str; 1] = ["github"];
/// Per-row cap on evidence references (overflow is explicit via
/// `evidence_total`).
pub const BOARD_EVIDENCE_REF_MAX: usize = 4;

/// One recorded-text board field: null, or redaction-stable text (the
/// secret-shaped boundary: recorded text may only enter a rendered page
/// after the conservative redaction pass, so a page carrying an unredacted
/// secret-shaped run is refused).
fn board_recorded_text(obj: &Val, key: &str, where_: &str) -> Rule {
    match obj.get(key) {
        Some(Val::Null) => Ok(()),
        Some(Val::Str(text)) => {
            if text.chars().count() > 128 || text.chars().any(char::is_control) {
                return Err(Verdict::refuse(
                    Refusal::Malformed,
                    format!("{where_}: {key:?} must be <= 128 characters without controls"),
                ));
            }
            if redact(text) != *text {
                return Err(Verdict::refuse(
                    Refusal::Malformed,
                    format!("{where_}: {key:?} carries an unredacted secret-shaped run"),
                ));
            }
            Ok(())
        }
        Some(other) => Err(Verdict::refuse(
            Refusal::Malformed,
            format!(
                "{where_}: {key:?} must be null or a string, got {}",
                other.type_name()
            ),
        )),
        None => Err(Verdict::refuse(
            Refusal::Malformed,
            format!("{where_}: missing required key {key:?}"),
        )),
    }
}

/// Optional timestamp field: null or RFC3339 UTC seconds-`Z`.
fn board_optional_timestamp(obj: &Val, key: &str, where_: &str) -> Rule {
    match obj.get(key) {
        Some(Val::Null) => Ok(()),
        Some(Val::Str(text)) if is_rfc3339_seconds_z(text) => Ok(()),
        Some(other) => Err(Verdict::refuse(
            Refusal::Malformed,
            format!(
                "{where_}: {key:?} must be null or RFC3339 UTC (seconds, Z), got {}",
                other.type_name()
            ),
        )),
        None => Err(Verdict::refuse(
            Refusal::Malformed,
            format!("{where_}: missing required key {key:?}"),
        )),
    }
}

/// Cursor shape: `repository|issue|run` where the repository part is empty
/// or `owner/name`, the issue part is a non-negative integer, and the run
/// part is a non-empty identifier.
fn board_cursor_shaped(text: &str) -> bool {
    let parts: Vec<&str> = text.split('|').collect();
    if parts.len() != 3 {
        return false;
    }
    let (repository, issue, run) = (parts[0], parts[1], parts[2]);
    if !repository.is_empty() && !is_repository_identity(repository) {
        return false;
    }
    if issue.is_empty() || !issue.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    !run.is_empty() && run.len() <= 64 && run.chars().all(crate::board::is_run_char)
}

/// `hf-board/v1` (issue #83): one bounded page of the authoritative board
/// read model. The closed consistency rules are the machine-checked half of
/// the coverage contract — a page either satisfies every rule or it is
/// refused, so a surface can never present an idle/working run as verified,
/// never join two runs of one work item into a row, never reorder a page,
/// never fabricate evidence, and never carry secret-shaped recorded text.
fn validate_board(obj: &Val) -> Verdict {
    if let Err(verdict) = check_schema(obj, Family::Board) {
        return verdict;
    }
    const KEYS: [&str; 6] = [
        "schema",
        "observed_at",
        "state",
        "rows",
        "next_cursor",
        "truncated",
    ];
    if let Err(verdict) = require_keys(obj, &KEYS, &KEYS, "board") {
        return verdict;
    }
    if let Err(verdict) = expect_timestamp(obj, "observed_at", "board") {
        return verdict;
    }
    let Some(state) = obj.get("state") else {
        return Verdict::refuse(Refusal::Malformed, "board.state: missing (required)");
    };
    const STATE_KEYS: [&str; 2] = ["epoch", "journal_seq"];
    if let Err(verdict) = require_keys(state, &STATE_KEYS, &STATE_KEYS, "board.state") {
        return verdict;
    }
    if let Err(verdict) = expect_int(state, "epoch", "board.state", 0) {
        return verdict;
    }
    if let Err(verdict) = expect_int(state, "journal_seq", "board.state", 0) {
        return verdict;
    }
    let truncated = match obj.get("truncated") {
        Some(Val::Bool(value)) => *value,
        _ => {
            return Verdict::refuse(Refusal::Malformed, "board.truncated must be a boolean");
        }
    };
    let has_cursor = match obj.get("next_cursor") {
        Some(Val::Null) => false,
        Some(Val::Str(text)) => {
            if !board_cursor_shaped(text) {
                return Verdict::refuse(
                    Refusal::Malformed,
                    "board.next_cursor must be a repository|issue|run ordering key",
                );
            }
            true
        }
        _ => {
            return Verdict::refuse(
                Refusal::Malformed,
                "board.next_cursor must be null or a string",
            );
        }
    };
    // The cursor exists exactly while more rows exist: a page either offers
    // a continuation or states that it is the last one.
    if has_cursor != truncated {
        return Verdict::refuse(
            Refusal::Malformed,
            "board.next_cursor and board.truncated must agree (cursor iff more rows)",
        );
    }
    let Some(Val::Arr(rows)) = obj.get("rows") else {
        return Verdict::refuse(Refusal::Malformed, "board.rows must be a list");
    };
    if rows.is_empty() && truncated {
        return Verdict::refuse(
            Refusal::Malformed,
            "board.truncated cannot be true for an empty page",
        );
    }
    let mut previous: Option<(String, i64, String)> = None;
    for row in rows {
        let key = match validate_board_row(row, previous.as_ref()) {
            Ok(key) => key,
            Err(verdict) => return verdict,
        };
        previous = Some(key);
    }
    Verdict::accept()
}

/// Validate one board row against the closed rules; returns its
/// `(repository, issue, run)` ordering key so the page loop can enforce
/// strictly increasing order.
fn validate_board_row(
    row: &Val,
    previous: Option<&(String, i64, String)>,
) -> Result<(String, i64, String), Verdict> {
    table(row, "board row")?;
    const KEYS: [&str; 17] = [
        "work_item",
        "source",
        "run",
        "run_state",
        "stage",
        "verification",
        "owner",
        "reason",
        "next_action",
        "human_gate",
        "milestone",
        "evidence",
        "evidence_total",
        "evidence_at",
        "reviewer",
        "progress_at",
        "observed_at",
    ];
    require_keys(row, &KEYS, &KEYS, "board row")?;
    let Some(source) = row.get("source") else {
        return Err(Verdict::refuse(
            Refusal::Malformed,
            "board row.source: missing (required)",
        ));
    };
    const SOURCE_KEYS: [&str; 7] = [
        "kind",
        "repository",
        "issue",
        "revision",
        "freshness",
        "completeness",
        "observed_at",
    ];
    require_keys(source, &SOURCE_KEYS, &SOURCE_KEYS, "board row.source")?;
    expect_in(source, "kind", "board row.source", &BOARD_SOURCE_KINDS)?;
    let repository = match source.get("repository") {
        Some(Val::Str(text)) => text.clone(),
        _ => {
            return Err(Verdict::refuse(
                Refusal::Malformed,
                "board row.source.repository must be a string",
            ));
        }
    };
    let issue = match source.get("issue") {
        Some(Val::Int(number)) if *number >= 0 => *number,
        _ => {
            return Err(Verdict::refuse(
                Refusal::Malformed,
                "board row.source.issue must be a non-negative integer",
            ));
        }
    };
    let revision = match source.get("revision") {
        Some(Val::Str(text)) => text.clone(),
        _ => {
            return Err(Verdict::refuse(
                Refusal::Malformed,
                "board row.source.revision must be a string",
            ));
        }
    };
    expect_in(source, "freshness", "board row.source", &["fresh", "stale"])?;
    let completeness = match source.get("completeness") {
        Some(Val::Str(text)) if matches!(text.as_str(), "complete" | "partial") => text.clone(),
        _ => {
            return Err(Verdict::refuse(
                Refusal::Malformed,
                "board row.source.completeness must be complete|partial",
            ));
        }
    };
    board_optional_timestamp(source, "observed_at", "board row.source")?;
    // A complete source row carries every binding; a partial row is a
    // legacy run whose bindings predate m0002 and is reported, never fixed.
    match (row.get("work_item"), completeness.as_str()) {
        (Some(Val::Null), "partial") => {}
        (Some(Val::Str(text)), "complete") if is_work_item_id(text) => {}
        _ => {
            return Err(Verdict::refuse(
                Refusal::Malformed,
                "board row.work_item must be a wi_ id for a complete source and null for a partial one",
            ));
        }
    }
    if completeness == "complete"
        && (!is_repository_identity(&repository) || issue < 1 || !is_hex40(&revision))
    {
        return Err(Verdict::refuse(
            Refusal::Malformed,
            "board row.source: a complete row requires owner/name, a positive issue, and a 40-hex revision",
        ));
    }
    let run = match row.get("run") {
        Some(Val::Str(text))
            if !text.is_empty()
                && text.len() <= 64
                && text.chars().all(crate::board::is_run_char) =>
        {
            text.clone()
        }
        _ => {
            return Err(Verdict::refuse(
                Refusal::Malformed,
                "board row.run must be a 1..=64 character identifier",
            ));
        }
    };
    let run_state = match row.get("run_state") {
        Some(Val::Str(text)) if BOARD_RUN_STATES.contains(&text.as_str()) => text.clone(),
        _ => {
            return Err(Verdict::refuse(
                Refusal::Malformed,
                "board row.run_state outside the closed set",
            ));
        }
    };
    expect_in(row, "stage", "board row", &BOARD_STAGES)?;
    let stage = row
        .get("stage")
        .and_then(Val::as_str)
        .unwrap_or_default()
        .to_string();
    let freshness = source
        .get("freshness")
        .and_then(Val::as_str)
        .unwrap_or_default();
    let verification = match row.get("verification") {
        Some(Val::Str(text)) if BOARD_VERIFICATIONS.contains(&text.as_str()) => text.clone(),
        _ => {
            return Err(Verdict::refuse(
                Refusal::Malformed,
                "board row.verification outside the closed set",
            ));
        }
    };
    // The delivery separation rule, enforced in both directions: a run is
    // `verified` exactly while recorded review evidence is passed and the
    // run's facts are current; `done`, busy, idle, paused, stale, or
    // invalidated runs can never be presented as verified without it.
    let verified = verification == "passed" && freshness == "fresh" && run_state != "invalidated";
    if (stage == "verified") != verified {
        return Err(Verdict::refuse(
            Refusal::Malformed,
            "board row.stage must be verified iff verification is passed, fresh, and not invalidated",
        ));
    }
    for key in ["owner", "reason", "reviewer"] {
        board_recorded_text(row, key, "board row")?;
    }
    let next_action = match row.get("next_action") {
        Some(Val::Null) => None,
        Some(Val::Str(text)) if BOARD_NEXT_ACTIONS.contains(&text.as_str()) => Some(text.clone()),
        _ => {
            return Err(Verdict::refuse(
                Refusal::Malformed,
                "board row.next_action outside the closed set (null when not recorded)",
            ));
        }
    };
    match next_action.as_deref() {
        None => {}
        Some("resume") if run_state == "paused" => {}
        Some("human_decision") if run_state == "human_queue" => {}
        Some(_) => {
            return Err(Verdict::refuse(
                Refusal::Malformed,
                "board row.next_action must match the recorded run state (resume -> paused, human_decision -> human_queue)",
            ));
        }
    }
    let human_gate = matches!(row.get("human_gate"), Some(Val::Bool(true)));
    if !matches!(row.get("human_gate"), Some(Val::Bool(_)))
        || human_gate != matches!(run_state.as_str(), "paused" | "human_queue")
    {
        return Err(Verdict::refuse(
            Refusal::Malformed,
            "board row.human_gate must be a boolean equal to (run_state is paused or human_queue)",
        ));
    }
    match row.get("milestone") {
        Some(Val::Null) => {}
        Some(Val::Str(text)) if is_slug(text) => {}
        _ => {
            return Err(Verdict::refuse(
                Refusal::Malformed,
                "board row.milestone must be null or an achieved node slug",
            ));
        }
    }
    let Some(Val::Arr(evidence)) = row.get("evidence") else {
        return Err(Verdict::refuse(
            Refusal::Malformed,
            "board row.evidence must be a list",
        ));
    };
    if evidence.len() > BOARD_EVIDENCE_REF_MAX {
        return Err(Verdict::refuse(
            Refusal::Malformed,
            "board row.evidence exceeds the bounded evidence-reference cap",
        ));
    }
    let mut seen: Vec<&str> = Vec::with_capacity(evidence.len());
    for item in evidence {
        match item {
            Val::Str(text) if is_evidence_id(text) => {
                if seen.contains(&text.as_str()) {
                    return Err(Verdict::refuse(
                        Refusal::Malformed,
                        "board row.evidence repeats an evidence reference",
                    ));
                }
                seen.push(text);
            }
            _ => {
                return Err(Verdict::refuse(
                    Refusal::Malformed,
                    "board row.evidence entries must be ev_ ids",
                ));
            }
        }
    }
    let evidence_total = match row.get("evidence_total") {
        Some(Val::Int(total)) if *total >= evidence.len() as i64 => *total,
        _ => {
            return Err(Verdict::refuse(
                Refusal::Malformed,
                "board row.evidence_total must be an integer >= the exposed evidence count",
            ));
        }
    };
    board_optional_timestamp(row, "evidence_at", "board row")?;
    board_optional_timestamp(row, "progress_at", "board row")?;
    expect_timestamp(row, "observed_at", "board row")?;
    // Evidence presence is an exact function of verification: no evidence
    // means `none` (and no timestamps/reviewer); any evidence means a
    // recorded verdict with its timestamp.
    let has_evidence_at = matches!(row.get("evidence_at"), Some(Val::Str(_)));
    match verification.as_str() {
        "none" => {
            if !evidence.is_empty() || evidence_total != 0 || has_evidence_at {
                return Err(Verdict::refuse(
                    Refusal::Malformed,
                    "board row.verification none requires no evidence references and no evidence_at",
                ));
            }
        }
        _ => {
            if evidence.is_empty() || evidence_total < 1 || !has_evidence_at {
                return Err(Verdict::refuse(
                    Refusal::Malformed,
                    "board row.verification failed|passed requires recorded evidence and its timestamp",
                ));
            }
        }
    }
    let key = (repository, issue, run);
    if let Some(previous) = previous
        && &key <= previous
    {
        return Err(Verdict::refuse(
            Refusal::Malformed,
            "board rows must be in strictly increasing (repository, issue, run) order",
        ));
    }
    Ok(key)
}

// ---------------------------------------------------------------------------
// Fixture-corpus discrimination tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::sha256_hex;
    use std::path::{Path, PathBuf};

    /// Location of the committed fixture corpus.
    fn repo_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }

    fn fixture_bytes(relative: &str) -> Vec<u8> {
        std::fs::read(repo_root().join("schemas/fixtures").join(relative))
            .unwrap_or_else(|err| panic!("read fixture {relative}: {err}"))
    }

    /// Every manifest row for a supported family holds under these
    /// validators: accepts accept, malformed/unknown-version/noncanonical
    /// refusals refuse with the right class, and pinned sha256 digests match.
    #[test]
    fn fixture_corpus_manifest_expectations_hold() {
        let manifest = fixture_bytes("manifest.jsonl");
        let text = std::str::from_utf8(&manifest).expect("manifest utf8");
        let mut rows = Vec::new();
        for (lineno, line) in text.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let row = Val::parse_json(line)
                .unwrap_or_else(|err| panic!("manifest line {}: {err}", lineno + 1));
            rows.push(row);
        }
        assert!(!rows.is_empty(), "manifest is empty");

        let family_of = |name: &str| -> Option<Family> {
            SUPPORTED_FAMILIES
                .iter()
                .copied()
                .find(|f| f.family_name() == name)
        };

        let mut checked = 0usize;
        let mut failures: Vec<String> = Vec::new();
        for row in rows {
            let Some(family_name) = row.get("family").and_then(Val::as_str) else {
                continue;
            };
            let Some(family) = family_of(family_name) else {
                continue;
            };
            let file = row.get("file").and_then(Val::as_str).expect("row file");
            let expect = row.get("expect").and_then(Val::as_str).expect("row expect");
            let kind = row.get("kind").and_then(Val::as_str);
            let bytes = fixture_bytes(file);
            let verdict = validate_bytes(family, &bytes);

            let expectation = match (expect, kind) {
                ("accept", _) => {
                    if !verdict.is_accepted() {
                        Some(format!(
                            "{file}: expected accept, got {} ({})",
                            verdict.refusal.map(Refusal::as_str).unwrap_or("accept"),
                            verdict.message()
                        ))
                    } else {
                        None
                    }
                }
                ("refuse", Some("unknown-version")) => {
                    if verdict.refusal() != Some(Refusal::Version) {
                        Some(format!(
                            "{file}: unknown-version fixture must refuse-version, got {:?}",
                            verdict.refusal().map(Refusal::as_str)
                        ))
                    } else {
                        None
                    }
                }
                ("refuse", Some("noncanonical")) => {
                    if verdict.refusal() != Some(Refusal::Noncanonical) {
                        Some(format!(
                            "{file}: noncanonical fixture must refuse-noncanonical, got {:?}",
                            verdict.refusal().map(Refusal::as_str)
                        ))
                    } else {
                        None
                    }
                }
                ("refuse", _) => {
                    if verdict.is_accepted() {
                        Some(format!("{file}: expected refusal, got accept"))
                    } else {
                        None
                    }
                }
                other => Some(format!("{file}: unexpected manifest row {other:?}")),
            };
            if let Some(failure) = expectation {
                failures.push(failure);
            }
            if let Some(pinned) = row.get("sha256").and_then(Val::as_str) {
                let actual = sha256_hex(&bytes);
                if actual != pinned {
                    failures.push(format!(
                        "{file}: digest mismatch (manifest {pinned} vs actual {actual})"
                    ));
                }
            }
            checked += 1;
        }
        assert!(checked > 0, "no supported-family rows were checked");
        assert!(
            failures.is_empty(),
            "fixture expectations failed ({} checked):\n{}",
            checked,
            failures.join("\n")
        );
    }

    /// Canonical-bytes rule: the stored plan.valid.json is byte-canonical,
    /// its digest is pinned, and re-canonicalizing the parsed document
    /// reproduces the stored bytes exactly.
    #[test]
    fn plan_valid_fixture_is_canonical_and_digest_pinned() {
        let bytes = fixture_bytes("plan/plan.valid.json");
        let parsed = Val::parse_json(std::str::from_utf8(&bytes).expect("utf8")).expect("parse");
        assert_eq!(
            canonical_bytes(&parsed),
            bytes,
            "fixture must be stored canonically"
        );
        assert_eq!(
            sha256_hex(&bytes),
            "8199a193f906491e3061847f1e02440360c75b2a7c8ee89b7d0edf532bb7fe33"
        );
        let verdict = validate_bytes(Family::Plan, &bytes);
        assert!(
            verdict.is_accepted(),
            "valid plan refused: {}",
            verdict.message()
        );
    }

    /// Discriminating acceptance: each family's valid fixture accepts and its
    /// malformed/unknown-version fixtures refuse with the expected class.
    /// (The manifest test above already covers every row generically; this
    /// table keeps the per-file expectations readable and explicit.)
    #[test]
    fn per_family_discrimination_bites() {
        let checks: &[(Family, &str, bool)] = &[
            (Family::Config, "config/config.valid.toml", true),
            (Family::Config, "config/config.malformed.toml", false),
            (Family::Config, "config/config.unknown-version.toml", false),
            (Family::Policy, "policy/policy.valid.toml", true),
            (Family::Policy, "policy/policy.malformed.toml", false),
            (Family::Policy, "policy/policy.unknown-version.toml", false),
            (Family::Output, "output/output.valid.json", true),
            (Family::Output, "output/output.partial.valid.json", true),
            (Family::Output, "output/output.error.valid.json", true),
            (Family::Output, "output/output.malformed.json", false),
            (Family::Output, "output/output.unknown-version.json", false),
            (Family::Error, "error/error.valid.json", true),
            (Family::Error, "error/error.malformed.json", false),
            (Family::Error, "error/error.unknown-version.json", false),
            (
                Family::Observation,
                "observation/observation.valid.json",
                true,
            ),
            (
                Family::Observation,
                "observation/observation.malformed.json",
                false,
            ),
            (
                Family::Observation,
                "observation/observation.unknown-version.json",
                false,
            ),
            (Family::Plan, "plan/plan.valid.json", true),
            (Family::Plan, "plan/plan.malformed.json", false),
            (Family::Plan, "plan/plan.noncanonical.json", false),
            (Family::Plan, "plan/plan.unknown-version.json", false),
            (
                Family::Capability,
                "capability/capability.harness.valid.json",
                true,
            ),
            (
                Family::Capability,
                "capability/capability.forge.valid.json",
                true,
            ),
            (
                Family::Capability,
                "capability/capability.malformed.json",
                false,
            ),
            (
                Family::Capability,
                "capability/capability.unknown-version.json",
                false,
            ),
            (Family::RpcRequest, "rpc/request.status.valid.json", true),
            (Family::RpcRequest, "rpc/request.apply.valid.json", true),
            (Family::RpcRequest, "rpc/request.malformed.json", false),
            (
                Family::RpcRequest,
                "rpc/request.unknown-version.json",
                false,
            ),
            (Family::RpcResponse, "rpc/response.ok.valid.json", true),
            (Family::RpcResponse, "rpc/response.error.valid.json", true),
            (Family::RpcResponse, "rpc/response.malformed.json", false),
            (
                Family::RpcResponse,
                "rpc/response.unknown-version.json",
                false,
            ),
            (Family::Event, "event/events.valid.jsonl", true),
            (Family::Event, "event/events.malformed.jsonl", false),
            (Family::Event, "event/events.badline.jsonl", false),
            (Family::Event, "event/events.unknown-version.jsonl", false),
            (Family::Audit, "audit/audit.valid.jsonl", true),
            (Family::Audit, "audit/audit.malformed.jsonl", false),
            (Family::Audit, "audit/audit.unknown-version.jsonl", false),
            (Family::Migration, "migration/migration.valid.json", true),
            (
                Family::Migration,
                "migration/migration.malformed.json",
                false,
            ),
            (
                Family::Migration,
                "migration/migration.unknown-version.json",
                false,
            ),
            (Family::Epoch, "epoch/epoch.initial.valid.json", true),
            (Family::Epoch, "epoch/epoch.restore.valid.json", true),
            (Family::Epoch, "epoch/epoch.malformed.json", false),
            (Family::Epoch, "epoch/epoch.unknown-version.json", false),
            (Family::Grant, "grant/grant.valid.json", true),
            (Family::Grant, "grant/grant.malformed.json", false),
            (Family::Grant, "grant/grant.unknown-version.json", false),
            (
                Family::Outcome,
                "outcome/outcome.succeeded.valid.json",
                true,
            ),
            (Family::Outcome, "outcome/outcome.failed.valid.json", true),
            (Family::Outcome, "outcome/outcome.malformed.json", false),
            (
                Family::Outcome,
                "outcome/outcome.unknown-version.json",
                false,
            ),
        ];
        for (family, file, expect_accept) in checks {
            let bytes = fixture_bytes(file);
            let verdict = validate_bytes(*family, &bytes);
            assert_eq!(
                verdict.is_accepted(),
                *expect_accept,
                "{file}: expected accept={expect_accept}, got {:?} ({})",
                verdict.refusal().map(Refusal::as_str),
                verdict.message()
            );
        }
    }

    /// The malformed config fixture refuses because of the unknown top-level
    /// table, and the unknown-version config refuses with REFUSE_VERSION —
    /// the two are distinguishable (discrimination).
    #[test]
    fn config_version_and_shape_refusals_are_distinct() {
        let malformed = fixture_bytes("config/config.malformed.toml");
        let verdict = validate_bytes(Family::Config, &malformed);
        assert_eq!(verdict.refusal(), Some(Refusal::Malformed));
        assert!(verdict.message().contains("unknown key"));

        let unknown = fixture_bytes("config/config.unknown-version.toml");
        let verdict = validate_bytes(Family::Config, &unknown);
        assert_eq!(verdict.refusal(), Some(Refusal::Version));
    }

    /// Parser equivalence: this crate's strict parser and the reference
    /// serde_json parser agree on every JSON fixture (catches escape/unicode
    /// handling regressions in the hand-written parser).
    #[test]
    fn json_parser_matches_serde_json_on_fixtures() {
        let dir = repo_root().join("schemas/fixtures");
        let mut files: Vec<PathBuf> = Vec::new();
        for entry in std::fs::read_dir(&dir).expect("fixtures dir") {
            collect_json_files(&entry.expect("entry").path(), &mut files);
        }
        assert!(files.len() >= 30, "expected a wide fixture corpus");
        for path in files {
            let text = std::fs::read_to_string(&path).expect("read fixture");
            let ours = Val::parse_json(&text);
            let theirs = serde_json::from_str::<serde_json::Value>(&text);
            match (&ours, &theirs) {
                (Ok(ours), Ok(theirs)) => {
                    let converted = from_json_value(theirs.clone());
                    assert_eq!(
                        &converted,
                        ours,
                        "parser disagreement on {}",
                        path.display()
                    );
                }
                (Err(_), Err(_)) => {}
                (Err(ours), Ok(_)) => panic!(
                    "our parser refused {} but serde_json accepts: {ours:?}",
                    path.display()
                ),
                (Ok(_), Err(theirs)) => panic!(
                    "serde_json refused {} but our parser accepts: {theirs}",
                    path.display()
                ),
            }
        }
    }

    fn collect_json_files(path: &Path, out: &mut Vec<PathBuf>) {
        if path.is_dir() {
            for entry in std::fs::read_dir(path).expect("read dir") {
                collect_json_files(&entry.expect("entry").path(), out);
            }
        } else if path
            .extension()
            .is_some_and(|ext| ext == "json" || ext == "jsonl")
        {
            out.push(path.to_path_buf());
        }
    }

    fn from_json_value(value: serde_json::Value) -> Val {
        match value {
            serde_json::Value::Null => Val::Null,
            serde_json::Value::Bool(b) => Val::Bool(b),
            serde_json::Value::Number(number) => {
                if let Some(int) = number.as_i64() {
                    Val::Int(int)
                } else {
                    Val::Float(number.as_f64().expect("number"))
                }
            }
            serde_json::Value::String(text) => Val::Str(text),
            serde_json::Value::Array(items) => Val::Arr(
                items
                    .iter()
                    .map(|item| from_json_value(item.clone()))
                    .collect(),
            ),
            serde_json::Value::Object(map) => Val::Obj(
                map.iter()
                    .map(|(k, v)| (k.clone(), from_json_value(v.clone())))
                    .collect(),
            ),
        }
    }
}
