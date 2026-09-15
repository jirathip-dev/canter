//! Harness adapters (issues #7, #33, #37): capability-negotiated adapters
//! for Hermes, Claude Code, Codex, Pi (earendil-works/pi), Jcode
//! (1jehuang/jcode), and the declarative generic argv adapter.
//!
//! # Adapter contract (docs/contracts/spec-capabilities.md, "Adapter
//! contract", issue #7)
//!
//! Every adapter profile declares an `hf-capability/v1` document (axis
//! `harness`, closed 7-capability set) and executes typed operations through
//! [`crate::process::run`]: argv arrays only, allowlisted environment only,
//! per-op deadline, capped + redacted output, typed exits. Prompts and
//! untrusted issue text are transported as data — a single final argv
//! element on the prompt operation — and can never alter adapter argv or
//! policy. Adapters never write files, never read the host environment
//! directly (the caller passes an allowlisted environment map), and never
//! store tokens or transcripts (trust model T5 / AC8).
//!
//! - Hermes / Claude Code / Codex / Pi / Jcode are the five official 1.0
//!   adapters (adapter examples per ADR-0003; metadata lives here, never
//!   in core planning). Their declared version ranges are recorded in
//!   docs/contracts/compatibility.md (Hermes/Claude Code/Codex measured
//!   2026-09-06; Pi 0.85.1 measured 2026-09-08 against the SHA-verified
//!   linux-x64 prebuilt, with darwin arm64/x64 prebuilts available at that
//!   version; Jcode 0.84.0 measured 2026-09-08 against the SHA-verified
//!   linux-x64 prebuilt of the upstream release, with darwin arm64/x64
//!   prebuilts available at that version); the exact real-world flag
//!   parity of the headless invocation rows is [awaiting-evidence] until
//!   the human-gated clean-host smokes run (AC6), so this slice verifies
//!   the contract with fake executables only (AC7).
//! - The `argv` kind is the declarative generic adapter: validated static
//!   argv prefixes per operation, explicit capability declarations, bare
//!   executable names resolved through the allowlisted PATH (the resolved
//!   absolute identity is what is spawned), bounded time/output, typed
//!   exits. No shell evaluation, no command templates, no capability
//!   inference from prose, no dynamic plugin SDK.
//! - Session identity (AC3) binds the Herdr workspace session id plus a
//!   stable terminal/native-session identity plus a generation counter.
//!   A mutable pane label is not part of the identity and can never
//!   substitute for any of the three parts; binding without all three is a
//!   typed refusal (`refusal.identity.incomplete`).
//! - One-shot official adapter lane lifecycle under Herdr (issues #33 A2,
//!   #37): when a pi or jcode profile operation runs inside a Herdr pane
//!   (`HERDR_ENV=1` + `HERDR_PANE_ID` in the allowlisted environment), the
//!   adapter reports the lane lifecycle through the workspace executable's
//!   `pane report-agent` row (custom-integration contract: pi reports
//!   `--source custom:herdr-fleet-pi --agent pi`; jcode reports
//!   `--source custom:herdr-fleet-jcode --agent jcode`). `start` reports
//!   `working`; a terminal `prompt` reports
//!   `idle` (Herdr has no done state), except `refusal.credentials` (a user
//!   decision — the provider key — is required) and
//!   `refusal.binding.missing` (the profile declares no provider/model
//!   binding, so a user decision — declare the binding — is required),
//!   which report `blocked` with static messages that never carry
//!   credential or binding detail. Reporting is
//!   best-effort and never changes the typed op result, and is a no-op
//!   outside Herdr. `herdr agent start --kind pi` remains the
//!   substrate/orchestrator path for interactive pi panes (requires a pane
//!   at an interactive shell prompt); headless adapter runs report through
//!   the pane rows instead.
//! - Unknown or unavailable harnesses fail with a typed refusal
//!   (`unknown.harness`, `refusal.unavailable.harness`) and never disturb
//!   independent read-only operations (observe.rs pattern, AC4).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::formats::{is_actor, parse_semver};
use crate::process::{ProcOut, ProcSpec, ProcStatus, run};
use crate::redact::redact;
use crate::schema::{Family, validate_doc};
use crate::value::{Val, bool_, integer, null, object, string};

/// Closed `harness` axis capability set (`hf-capability/v1`, mirror of
/// schema.rs and the fixture probe).
pub const HARNESS_CAPS: [&str; 7] = [
    "discover",
    "start",
    "prompt",
    "observe",
    "interrupt",
    "outcome",
    "identity",
];

/// The executable implementing workspace session operations (session
/// observation, interruption, outcome collection, identity read-back). The
/// invocation rows against it are a v1 candidate contract
/// ([awaiting-evidence] until clean-host verification, AC6); fake
/// executables in tests pin the exact argv shape.
pub const WORKSPACE_EXECUTABLE: &str = "herdr";

/// Default per-operation deadline (same bound as the read adapters).
pub const ADAPTER_TIMEOUT: Duration = Duration::from_secs(10);

/// Byte cap on captured harness/workspace output (bounded output; spec-cli
/// §6 redaction happens before this text is ever stored).
pub const OUTPUT_CAP: usize = 64 * 1024;

/// Cap on diagnostics text attached to typed failures.
const DIAGNOSTIC_CAP: usize = 300;

// ---------------------------------------------------------------------------
// Typed refusal / failure codes (documented in spec-capabilities.md,
// "Adapter contract — refusal and failure codes")
// ---------------------------------------------------------------------------

/// The configured kind is not one of the closed adapter kinds.
pub const CODE_UNKNOWN_HARNESS: &str = "unknown.harness";
/// A requested capability/operation is not in the closed harness set or is
/// not declared by the profile.
pub const CODE_UNKNOWN_CAPABILITY: &str = "unknown.capability";
/// The harness executable is missing from the allowlisted PATH or could not
/// be spawned.
pub const CODE_UNAVAILABLE: &str = "refusal.unavailable.harness";
/// The harness reported an authentication failure (closed-marker
/// classification of an already-failed invocation; never capability
/// inference from prose).
pub const CODE_CREDENTIALS: &str = "refusal.credentials";
/// The harness profile declares no explicit provider/model binding; the
/// terminal prompt is refused and nothing is substituted (issue #80). The
/// Herdr lifecycle mapping reports this refusal as `blocked` — declaring
/// the binding is a user decision.
pub const CODE_BINDING: &str = "refusal.binding.missing";
/// Structured output could not be parsed or validated.
pub const CODE_MALFORMED: &str = "refusal.malformed.output";
/// The identity read-back does not match the bound session identity.
pub const CODE_STALE_IDENTITY: &str = "refusal.stale.identity";
/// A session identity was bound without all three required parts.
pub const CODE_INCOMPLETE_IDENTITY: &str = "refusal.identity.incomplete";
/// The per-operation deadline was exceeded and the child was killed.
pub const CODE_TIMEOUT: &str = "adapter.timeout";
/// The child process died without producing a terminal outcome.
pub const CODE_PROCESS_DEATH: &str = "adapter.process_death";
/// The child exited with a non-zero code that is not a typed refusal.
pub const CODE_EXIT: &str = "adapter.exit";
/// The typed request itself is malformed (payload on a non-prompt
/// operation, prompt without a payload, path-like executable).
pub const CODE_BAD_REQUEST: &str = "refusal.request.malformed";
/// The Herdr workspace executable is missing from the allowlisted PATH or
/// could not be spawned (issue #139): the pane substrate is unavailable. A
/// typed refusal — the adapter NEVER falls back to a bare subprocess when
/// the substrate is unavailable.
pub const CODE_UNAVAILABLE_HERDR: &str = "refusal.unavailable.herdr";
/// The addressed Herdr pane/agent is not the bound lane generation's (issue
/// #139): the read-back belongs to a superseded generation, to another lane,
/// or to another worktree. The operation refuses instead of delivering work
/// to a reused identity (no cross-lane prompt delivery).
pub const CODE_STALE_GENERATION: &str = "refusal.stale.generation";
/// The kind has no documented pane row (issue #139): nothing is fabricated
/// for it and no fallback is substituted.
pub const CODE_EXECUTION_UNSUPPORTED: &str = "refusal.execution.unsupported";

/// A typed adapter error shaped like `hf-error/v1` (spec-cli.md §3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdapterError {
    /// Stable lowercase-dotted code (see constants above).
    pub code: &'static str,
    /// Human message.
    pub message: String,
    /// Whether retrying the same operation may succeed later.
    pub retryable: bool,
}

impl AdapterError {
    /// A typed refusal (not retryable).
    pub fn refusal(code: &'static str, message: impl Into<String>) -> AdapterError {
        AdapterError {
            code,
            message: message.into(),
            retryable: false,
        }
    }

    /// A runtime failure that may succeed on retry.
    pub fn failure(
        code: &'static str,
        message: impl Into<String>,
        retryable: bool,
    ) -> AdapterError {
        AdapterError {
            code,
            message: message.into(),
            retryable,
        }
    }

    /// Render as an `hf-error/v1` document (validated against the family in
    /// tests).
    pub fn to_error_doc(&self) -> Val {
        object(vec![
            ("schema", string("hf-error/v1")),
            ("code", string(self.code)),
            ("message", string(&self.message)),
            ("retryable", bool_(self.retryable)),
            ("details", null()),
        ])
    }
}

// ---------------------------------------------------------------------------
// Kinds and official adapter metadata
// ---------------------------------------------------------------------------

/// The six closed adapter kinds. Hermes, Claude Code, Codex, Pi, and Jcode
/// are the official 1.0 adapters; `argv` is the declarative generic
/// adapter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HarnessKind {
    /// Hermes Agent (`hermes` on PATH).
    Hermes,
    /// Claude Code (`claude` on PATH).
    ClaudeCode,
    /// OpenAI Codex CLI (`codex` on PATH).
    Codex,
    /// Pi (earendil-works/pi, `pi` on PATH).
    Pi,
    /// Jcode (1jehuang/jcode, `jcode` on PATH).
    Jcode,
    /// Declarative generic argv adapter (bare executable resolved via PATH).
    Argv,
}

impl HarnessKind {
    /// The official adapters (Argv is excluded).
    pub const OFFICIAL: [HarnessKind; 5] = [
        HarnessKind::Hermes,
        HarnessKind::ClaudeCode,
        HarnessKind::Codex,
        HarnessKind::Pi,
        HarnessKind::Jcode,
    ];

    /// Stable kind name used in config (`harness.<key>.kind`).
    pub fn name(self) -> &'static str {
        match self {
            HarnessKind::Hermes => "hermes",
            HarnessKind::ClaudeCode => "claude-code",
            HarnessKind::Codex => "codex",
            HarnessKind::Pi => "pi",
            HarnessKind::Jcode => "jcode",
            HarnessKind::Argv => "argv",
        }
    }

    /// Parse a config kind name; `None` for anything outside the closed set
    /// (the caller turns that into `unknown.harness`).
    pub fn parse(text: &str) -> Option<HarnessKind> {
        match text {
            "hermes" => Some(HarnessKind::Hermes),
            "claude-code" => Some(HarnessKind::ClaudeCode),
            "codex" => Some(HarnessKind::Codex),
            "pi" => Some(HarnessKind::Pi),
            "jcode" => Some(HarnessKind::Jcode),
            "argv" => Some(HarnessKind::Argv),
            _ => None,
        }
    }
}

/// A semantic version `major.minor.patch`.
pub type Semver = (u64, u64, u64);

/// Declared support range for an official adapter: the minimum version
/// below which canter refuses to operate, and the current version the
/// slice documents as the tested ceiling (compatibility.md policy shape).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VersionRange {
    /// Declared minimum (inclusive); below this the adapter is refused.
    pub minimum: Semver,
    /// Declared current — the version the release notes name as tested
    /// ceiling.
    pub current: Semver,
}

impl VersionRange {
    /// Whether a probed version satisfies the declared range.
    pub fn accepts(&self, version: Semver) -> bool {
        version >= self.minimum
    }
}

/// Official adapter metadata (adapter layer only — core never branches on
/// actor ids, ADR-0003). Version facts are measured from public release
/// metadata on 2026-09-06 (Hermes/Claude Code/Codex), 2026-09-08 (Pi;
/// docs/contracts/compatibility.md rows), and 2026-09-08 (Jcode v0.84.0
/// against the SHA-verified linux-x64 prebuilt of the upstream release,
/// with darwin arm64/x64 prebuilts available at that version); the
/// minimum == current rows are
/// provisional exact-version floors ([awaiting-evidence] until the
/// human-gated clean-host matrix, AC6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OfficialSpec {
    /// The kind.
    pub kind: HarnessKind,
    /// Bare executable name (resolved via the allowlisted PATH).
    pub executable: &'static str,
    /// Stable opaque actor id (`hf-capability/v1`).
    pub actor: &'static str,
    /// Declared version range.
    pub range: VersionRange,
    /// Declared capabilities (the full closed harness set for all four
    /// official adapters).
    pub capabilities: &'static [&'static str],
}

/// The five official adapter specs.
pub fn official_specs() -> [OfficialSpec; 5] {
    [
        OfficialSpec {
            kind: HarnessKind::Hermes,
            executable: "hermes",
            actor: "hermes",
            range: VersionRange {
                minimum: (0, 21, 0),
                current: (0, 21, 0),
            },
            capabilities: &HARNESS_CAPS,
        },
        OfficialSpec {
            kind: HarnessKind::ClaudeCode,
            executable: "claude",
            actor: "claude-code",
            range: VersionRange {
                minimum: (2, 1, 263),
                current: (2, 1, 263),
            },
            capabilities: &HARNESS_CAPS,
        },
        OfficialSpec {
            kind: HarnessKind::Codex,
            executable: "codex",
            actor: "codex",
            range: VersionRange {
                minimum: (0, 153, 4),
                current: (0, 153, 4),
            },
            capabilities: &HARNESS_CAPS,
        },
        OfficialSpec {
            kind: HarnessKind::Pi,
            executable: "pi",
            actor: "pi",
            range: VersionRange {
                minimum: (0, 85, 1),
                current: (0, 85, 1),
            },
            capabilities: &HARNESS_CAPS,
        },
        OfficialSpec {
            kind: HarnessKind::Jcode,
            executable: "jcode",
            actor: "jcode",
            range: VersionRange {
                minimum: (0, 84, 0),
                current: (0, 84, 0),
            },
            capabilities: &HARNESS_CAPS,
        },
    ]
}

/// Look up the official spec for a kind (`None` for `Argv`).
pub fn official_spec(kind: HarnessKind) -> Option<OfficialSpec> {
    official_specs().into_iter().find(|spec| spec.kind == kind)
}

// ---------------------------------------------------------------------------
// Execution substrates (issue #139)
// ---------------------------------------------------------------------------

/// The closed set of execution substrates one harness role operation runs on
/// (issue #139). Order is significant only in that [`ExecutionMode::default`]
/// is the product substrate.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ExecutionMode {
    /// Herdr-pane-backed execution — the default substrate (ADR-0003:
    /// Herdr owns workspaces, panes, terminals and agent-process hosting).
    /// The role starts as a Herdr agent inside a pane created in the run's
    /// lane worktree, the prompt is delivered through `herdr agent prompt`,
    /// and observation/interruption/terminal outcome are collected through
    /// the `herdr agent` rows.
    #[default]
    HerdrPane,
    /// Bare-subprocess execution: the pre-#139 row (the harness executable
    /// run as a direct child of the caller). Kept ONLY as a documented
    /// fallback that an operator selects explicitly on the reviewed step
    /// (`params.execution = "headless"`); it is never selected silently, and
    /// a Herdr failure never falls back to it.
    Headless,
}

impl ExecutionMode {
    /// Both substrates in closed-set order.
    pub const ALL: [ExecutionMode; 2] = [ExecutionMode::HerdrPane, ExecutionMode::Headless];

    /// Stable name used in the reviewed step params (`params.execution`).
    pub fn name(self) -> &'static str {
        match self {
            ExecutionMode::HerdrPane => "herdr",
            ExecutionMode::Headless => "headless",
        }
    }

    /// Parse a declared substrate name; `None` for anything outside the
    /// closed set (the caller turns that into a typed refusal — an unknown
    /// substrate is never coerced to a default).
    pub fn parse(text: &str) -> Option<ExecutionMode> {
        match text {
            "herdr" => Some(ExecutionMode::HerdrPane),
            "headless" => Some(ExecutionMode::Headless),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Profiles
// ---------------------------------------------------------------------------

/// The typed adapter operations (contract: capability discovery, start,
/// prompt delivery, observation, interruption/cancellation, terminal
/// outcome, identity/read-back).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Op {
    /// Instantiate/bind a harness session (validates the bound identity and
    /// the declared capability; the real workspace session creation is
    /// daemon/substrate wiring, not an adapter subprocess).
    Start,
    /// Deliver one prompt as data (single final argv element; transcript
    /// output is capped and redacted at the boundary).
    Prompt,
    /// Observe the session through the workspace read-back.
    Observe,
    /// Interrupt/cancel the session through the workspace read-back.
    Interrupt,
    /// Collect the terminal outcome through the workspace read-back.
    Outcome,
    /// Read back the stable agent identity and compare it to the bound one.
    Identity,
}

impl Op {
    /// All contract operations in closed-set order.
    pub const ALL: [Op; 6] = [
        Op::Start,
        Op::Prompt,
        Op::Observe,
        Op::Interrupt,
        Op::Outcome,
        Op::Identity,
    ];

    /// Stable operation name.
    pub fn name(self) -> &'static str {
        match self {
            Op::Start => "start",
            Op::Prompt => "prompt",
            Op::Observe => "observe",
            Op::Interrupt => "interrupt",
            Op::Outcome => "outcome",
            Op::Identity => "identity",
        }
    }

    /// The harness capability this operation requires.
    pub fn capability(self) -> &'static str {
        self.name()
    }

    /// Parse an operation name from the closed set.
    pub fn parse(text: &str) -> Option<Op> {
        Op::ALL.iter().copied().find(|op| op.name() == text)
    }
}

/// One typed operation request. The payload is data, never code: it is a
/// single final argv element on `Prompt` only, and it can never alter the
/// adapter argv or policy (AC5).
#[derive(Clone, Debug)]
pub struct OpRequest<'a> {
    /// The operation.
    pub op: Op,
    /// The bound session the operation targets.
    pub session: &'a SessionHandle,
    /// Untrusted text payload (prompt data); only valid for `Prompt`.
    pub payload: Option<&'a str>,
    /// Per-operation deadline.
    pub timeout: Duration,
}

/// One typed operation result. `status` uses the `hf-outcome/v1` closed set
/// (`succeeded` | `failed` | `ambiguous` | `refused`); interruption,
/// timeout, and process death yield `ambiguous`, typed refusals yield
/// `refused`, ordinary non-zero exits yield `failed`.
#[derive(Clone, Debug, PartialEq)]
pub struct OpResult {
    /// Profile key the operation ran against.
    pub profile_key: String,
    /// Session id the operation targeted.
    pub session_id: String,
    /// The operation that ran.
    pub op: Op,
    /// Outcome status (`hf-outcome/v1` closed set).
    pub status: &'static str,
    /// Stable failure code when the operation did not succeed.
    pub code: Option<&'static str>,
    /// Human message (redacted).
    pub message: Option<String>,
    /// Typed payload (redacted at the boundary).
    pub payload: Option<Val>,
    /// Bounded diagnostic detail (redacted).
    pub detail: Option<String>,
    /// Wall time of the operation in milliseconds.
    pub elapsed_ms: u64,
}

impl OpResult {
    /// Render as an `hf-outcome/v1` document bound to a plan step. The
    /// caller supplies the plan/step identity and the idempotency key; the
    /// status and error/result shape come from this result.
    pub fn to_outcome_doc(
        &self,
        plan_id: &str,
        step_id: &str,
        idempotency_key: &str,
        observed_at: &str,
    ) -> Val {
        let failed_like = matches!(self.status, "failed" | "refused");
        let error = if failed_like {
            object(vec![
                ("schema", string("hf-error/v1")),
                ("code", string(self.code.unwrap_or("adapter.exit"))),
                ("message", string(self.message.as_deref().unwrap_or(""))),
                ("retryable", bool_(false)),
                (
                    "details",
                    self.detail
                        .as_ref()
                        .map(|detail| object(vec![("diagnostics", string(detail))]))
                        .unwrap_or_else(null),
                ),
            ])
        } else {
            null()
        };
        let result = if failed_like {
            null()
        } else {
            self.payload
                .clone()
                .unwrap_or_else(|| object(vec![("ok", bool_(true))]))
        };
        object(vec![
            ("schema", string("hf-outcome/v1")),
            ("plan_id", string(plan_id)),
            ("step_id", string(step_id)),
            ("status", string(self.status)),
            ("idempotency_key", string(idempotency_key)),
            ("observed_at", string(observed_at)),
            ("result", result),
            ("error", error),
        ])
    }
}

/// A declarative adapter profile: kind, bare executable name, stable actor
/// id, explicit capability set, an explicit provider/model binding for the
/// prompt rows that carry the pair on argv (Pi, Jcode — issue #80), and
/// (for the `argv` kind) the explicit per-operation static argv prefixes.
/// Config v1 (`harness.<key>`) carries kind/executable/env_allow plus the
/// optional provider/model binding; the env allowlist is applied by the
/// caller when it builds the environment map ([`Profile::from_config`]
/// documents the argv-capability consequence).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Profile {
    /// Config/profile key (slug).
    pub key: String,
    /// Adapter kind.
    pub kind: HarnessKind,
    /// Bare executable name, resolved through the allowlisted PATH (never
    /// an absolute path in config).
    pub executable: String,
    /// Stable opaque actor id for `hf-capability/v1`.
    pub actor: String,
    /// Declared capabilities (explicit subset of the closed harness set).
    pub capabilities: Vec<String>,
    /// Declared version range (official adapters only).
    pub declared_range: Option<VersionRange>,
    /// Explicit provider/model binding for the official prompt rows that
    /// carry the pair on argv (Pi, Jcode; issue #80). `None` means unbound:
    /// the terminal prompt refuses with `refusal.binding.missing` — there
    /// is no default, no inference, and no substitution. Never persisted,
    /// never on a wire.
    pub provider: Option<String>,
    /// See [`Profile::provider`].
    pub model: Option<String>,
    /// Explicit per-operation static argv prefixes for the `argv` kind
    /// (op name -> prefix; the prompt payload is appended as one final
    /// element). Ignored for official kinds, which use their documented
    /// headless invocation rows.
    pub op_args: BTreeMap<String, Vec<String>>,
    /// The execution substrate this profile's role operations run on (issue
    /// #139). Defaults to [`ExecutionMode::HerdrPane`] — the product
    /// substrate — and is set explicitly by the caller that resolves the
    /// reviewed step (`params.execution`). Headless is only ever selected
    /// explicitly; nothing falls back to it.
    pub execution: ExecutionMode,
}

impl Profile {
    /// An official adapter profile (capabilities and range come from the
    /// official metadata table).
    pub fn official(kind: HarnessKind, key: impl Into<String>) -> Result<Profile, AdapterError> {
        let spec = official_spec(kind).ok_or_else(|| {
            AdapterError::refusal(CODE_UNKNOWN_HARNESS, "argv is not an official adapter kind")
        })?;
        Ok(Profile {
            key: key.into(),
            kind,
            executable: spec.executable.to_string(),
            actor: spec.actor.to_string(),
            capabilities: spec.capabilities.iter().map(|s| s.to_string()).collect(),
            declared_range: Some(spec.range),
            provider: None,
            model: None,
            op_args: BTreeMap::new(),
            execution: ExecutionMode::default(),
        })
    }

    /// A declarative generic argv profile. `capabilities` must be a
    /// non-empty subset of the closed harness set (anything else is refused
    /// with `unknown.capability`); `op_args` maps operations to explicit
    /// static argv prefixes whose names must be declared capabilities.
    /// `actor` defaults to the profile key.
    pub fn argv(
        key: impl Into<String>,
        executable: impl Into<String>,
        capabilities: &[&str],
        op_args: BTreeMap<String, Vec<String>>,
    ) -> Result<Profile, AdapterError> {
        let key = key.into();
        let executable = executable.into();
        Self::validate_bare_executable(&executable)?;
        if capabilities.is_empty() {
            return Err(AdapterError::refusal(
                CODE_UNKNOWN_CAPABILITY,
                "argv profiles must declare an explicit non-empty capability set",
            ));
        }
        for capability in capabilities {
            if !HARNESS_CAPS.contains(capability) {
                return Err(AdapterError::refusal(
                    CODE_UNKNOWN_CAPABILITY,
                    format!("capability {capability:?} is not in the closed harness set"),
                ));
            }
        }
        let actor = key.clone();
        if !is_actor(&actor) {
            return Err(AdapterError::refusal(
                CODE_BAD_REQUEST,
                format!("profile key {actor:?} is not a valid actor id"),
            ));
        }
        for (op_name, args) in &op_args {
            let Some(op) = Op::parse(op_name) else {
                return Err(AdapterError::refusal(
                    CODE_UNKNOWN_CAPABILITY,
                    format!("op {op_name:?} is not a harness operation"),
                ));
            };
            if !capabilities.contains(&op.capability()) {
                return Err(AdapterError::refusal(
                    CODE_UNKNOWN_CAPABILITY,
                    format!("op {op_name:?} requires a declared capability"),
                ));
            }
            for arg in args {
                if arg.contains('\0') {
                    return Err(AdapterError::refusal(
                        CODE_BAD_REQUEST,
                        "argv entries must not contain NUL bytes",
                    ));
                }
            }
        }
        Ok(Profile {
            key,
            kind: HarnessKind::Argv,
            executable,
            actor,
            capabilities: capabilities.iter().map(|s| s.to_string()).collect(),
            declared_range: None,
            provider: None,
            model: None,
            op_args,
            execution: ExecutionMode::default(),
        })
    }

    /// Build a profile from a validated `hf-config/v1` harness entry
    /// (`config::Harness`). Official kinds take their capability set and
    /// version range from the official metadata; the `argv` kind declares
    /// no capabilities through config v1 (its table carries no capability
    /// field), so config-declared argv profiles support discovery and
    /// probing only — any operation is refused with `unknown.capability`
    /// until an explicit capability declaration is wired from a profile
    /// source (documented in spec-config.md/spec-capabilities.md). The
    /// optional provider/model binding pair is carried when the config
    /// declares both tokens; the Pi/Jcode prompt rows refuse without it
    /// (issue #80).
    pub fn from_config(harness: &crate::config::Harness) -> Result<Profile, AdapterError> {
        let kind = HarnessKind::parse(&harness.kind).ok_or_else(|| {
            AdapterError::refusal(
                CODE_UNKNOWN_HARNESS,
                format!(
                    "unknown harness kind {:?}; supported kinds: {} (official) and {:?} (declarative)",
                    harness.kind,
                    HarnessKind::OFFICIAL
                        .iter()
                        .map(|kind| kind.name())
                        .collect::<Vec<_>>()
                        .join(", "),
                    "argv"
                ),
            )
        })?;
        let (actor, capabilities, declared_range) = match official_spec(kind) {
            Some(spec) => (
                spec.actor.to_string(),
                spec.capabilities.iter().map(|s| s.to_string()).collect(),
                Some(spec.range),
            ),
            None => (harness.key.clone(), Vec::new(), None),
        };
        let mut profile = Profile {
            key: harness.key.clone(),
            kind,
            executable: harness.executable.clone(),
            actor,
            capabilities,
            declared_range,
            provider: None,
            model: None,
            op_args: BTreeMap::new(),
            execution: ExecutionMode::default(),
        };
        // The explicit provider/model binding pair (issue #80): carried
        // only when both tokens are declared; a half pair is refused
        // rather than carried.
        match (&harness.provider, &harness.model) {
            (None, None) => {}
            (Some(provider), Some(model)) => {
                profile = profile.with_binding(provider, model)?;
            }
            _ => {
                return Err(AdapterError::refusal(
                    CODE_BAD_REQUEST,
                    "the harness provider/model binding must declare both tokens or neither",
                ));
            }
        }
        Ok(profile)
    }

    /// Whether the profile declares a capability.
    pub fn supports(&self, capability: &str) -> bool {
        self.capabilities.iter().any(|c| c == capability)
    }

    /// The `hf-capability/v1` declaration document for this profile
    /// (validated against the family before it is returned).
    pub fn declaration_doc(&self) -> Result<Val, AdapterError> {
        let doc = object(vec![
            ("schema", string("hf-capability/v1")),
            ("axis", string("harness")),
            ("actor", string(&self.actor)),
            (
                "capabilities",
                Val::Arr(self.capabilities.iter().map(|c| string(c)).collect()),
            ),
        ]);
        let verdict = validate_doc(Family::Capability, &doc);
        if !verdict.is_accepted() {
            return Err(AdapterError::refusal(
                CODE_BAD_REQUEST,
                format!("invalid capability declaration: {}", verdict.message()),
            ));
        }
        Ok(doc)
    }

    /// Attach the explicit provider/model binding the Pi/Jcode prompt rows
    /// build their `--provider`/`--model` argv from (issue #80). Both
    /// tokens are validated as bare tokens: non-empty, no whitespace, no
    /// path separators, no NUL (bare tokens are never paths and never
    /// shell text; the pair travels as argv data only).
    pub fn with_binding(mut self, provider: &str, model: &str) -> Result<Profile, AdapterError> {
        Self::validate_binding_token("provider", provider)?;
        Self::validate_binding_token("model", model)?;
        self.provider = Some(provider.to_string());
        self.model = Some(model.to_string());
        Ok(self)
    }

    /// Select the execution substrate this profile's role operations run on
    /// (issue #139). The caller resolves it from the reviewed step
    /// (`params.execution`, default [`ExecutionMode::HerdrPane`]) and states
    /// it explicitly: nothing infers a substrate, and a substrate is never
    /// downgraded after a substrate failure.
    pub fn with_execution(mut self, execution: ExecutionMode) -> Profile {
        self.execution = execution;
        self
    }

    /// The explicit provider/model binding this profile declares, or a
    /// typed refusal (`refusal.binding.missing`) when it declares none —
    /// no default is inferred and no fallback is substituted (issue #80).
    fn prompt_binding(&self) -> Result<(&str, &str), AdapterError> {
        match (self.provider.as_deref(), self.model.as_deref()) {
            (Some(provider), Some(model)) => Ok((provider, model)),
            _ => Err(AdapterError::refusal(
                CODE_BINDING,
                "the harness profile declares no provider/model binding; the prompt is refused (no default is inferred)",
            )),
        }
    }

    fn validate_binding_token(field: &str, value: &str) -> Result<(), AdapterError> {
        if crate::config::is_bare_token(value) {
            return Ok(());
        }
        Err(AdapterError::refusal(
            CODE_BAD_REQUEST,
            format!(
                "binding {field} must be a non-empty bare token (no whitespace or path separators)"
            ),
        ))
    }

    fn validate_bare_executable(executable: &str) -> Result<(), AdapterError> {
        if executable.is_empty()
            || executable.contains('/')
            || executable.contains('\\')
            || executable.contains('\0')
        {
            return Err(AdapterError::refusal(
                CODE_BAD_REQUEST,
                "executable must be a bare name resolved via PATH (never an absolute path)",
            ));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Executable resolution and version probing
// ---------------------------------------------------------------------------

/// Resolve a bare executable name to a verified absolute path through the
/// PATH of the allowlisted environment map. The child is spawned from the
/// resolved absolute identity, never from the parent process's PATH, which
/// keeps tests hermetic and matches the "absolute/verified executable
/// identity" requirement for subprocess adapters. Empty PATH entries are
/// not searched (no implicit current-directory lookup).
pub fn resolve_executable(
    program: &str,
    env: &BTreeMap<String, String>,
) -> Result<PathBuf, AdapterError> {
    if program.is_empty() || program.contains('/') || program.contains('\\') {
        return Err(AdapterError::refusal(
            CODE_BAD_REQUEST,
            "executable must be a bare name resolved via PATH",
        ));
    }
    let Some(path_value) = env.get("PATH") else {
        return Err(AdapterError::refusal(
            CODE_UNAVAILABLE,
            "PATH is not in the allowlisted environment; cannot resolve executables",
        ));
    };
    let sep = if cfg!(windows) { ';' } else { ':' };
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    for entry in path_value.split(sep) {
        if entry.is_empty() {
            continue;
        }
        let dir = PathBuf::from(entry);
        let dir = if dir.is_absolute() {
            dir
        } else {
            cwd.join(dir)
        };
        let candidate = dir.join(program);
        let Ok(metadata) = std::fs::metadata(&candidate) else {
            continue;
        };
        if !metadata.is_file() {
            continue;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o111 == 0 {
                continue;
            }
        }
        return Ok(candidate);
    }
    Err(AdapterError::refusal(
        CODE_UNAVAILABLE,
        format!("{program:?} not found on the allowlisted PATH"),
    ))
}

/// Outcome of a version/presence probe (`<executable> --version`, bounded).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProbeResult {
    /// Whether the executable was found and spawned.
    pub present: bool,
    /// Parsed version text when the probe succeeded.
    pub version: Option<String>,
    /// Version compatibility against the declared range when one exists
    /// (`Some(false)` below the declared minimum).
    pub compatible: Option<bool>,
    /// Stable failure code when the probe could not complete.
    pub code: Option<&'static str>,
    /// Redacted, bounded diagnostic detail.
    pub detail: Option<String>,
}

/// Probe a profile's executable presence and version against its declared
/// range (runtime capability probe; compatibility.md policy shape).
pub fn probe_profile(profile: &Profile, env: &BTreeMap<String, String>) -> ProbeResult {
    let (present, version, compatible, code, detail) =
        match resolve_executable(&profile.executable, env) {
            Err(err) => (false, None, None, Some(err.code), Some(err.message)),
            Ok(path) => {
                let args = vec!["--version".to_string()];
                let out = run(ProcSpec {
                    program: path.to_str().unwrap_or_default(),
                    args: &args,
                    env,
                    cwd: None,
                    timeout: ADAPTER_TIMEOUT,
                });
                match out.status {
                    ProcStatus::Exit(0) => {
                        let first_line = out.stdout.lines().next().unwrap_or("").trim();
                        match first_line
                            .split_whitespace()
                            // A leading `v`/`V` is not part of the semver
                            // grammar this crate validates (formats
                            // `parse_semver`), but real harnesses commonly
                            // prefix their version token with one — jcode
                            // v0.84.0 prints `jcode v0.84.0 (57d587899)` —
                            // so the probe strips one before parsing.
                            .find_map(|token| {
                                parse_semver(
                                    token
                                        .strip_prefix('v')
                                        .or_else(|| token.strip_prefix('V'))
                                        .unwrap_or(token),
                                )
                            }) {
                            Some(version) => {
                                let compatible = profile
                                    .declared_range
                                    .map(|range| range.accepts(version))
                                    .unwrap_or(true);
                                (
                                    true,
                                    Some(format!("{}.{}.{}", version.0, version.1, version.2)),
                                    Some(compatible),
                                    None,
                                    None,
                                )
                            }
                            None => (
                                true,
                                None,
                                Some(false),
                                Some(CODE_MALFORMED),
                                Some(format!(
                                    "unparsable version output: {}",
                                    diagnostics(first_line)
                                )),
                            ),
                        }
                    }
                    ProcStatus::Exit(_code) => (
                        true,
                        None,
                        Some(false),
                        Some(CODE_EXIT),
                        Some(format!(
                            "version probe failed: {}",
                            diagnostics(&out.stderr)
                        )),
                    ),
                    ProcStatus::TimedOut => (
                        true,
                        None,
                        Some(false),
                        Some(CODE_TIMEOUT),
                        Some("version probe timed out".to_string()),
                    ),
                    ProcStatus::SpawnFailed(message) => (
                        true,
                        None,
                        Some(false),
                        Some(CODE_UNAVAILABLE),
                        Some(diagnostics(&message)),
                    ),
                }
            }
        };
    ProbeResult {
        present,
        version,
        compatible,
        code,
        detail,
    }
}

// ---------------------------------------------------------------------------
// Session identity (AC3)
// ---------------------------------------------------------------------------

/// The stable agent identity triple (AC3): Herdr workspace session id +
/// stable terminal/native-session identity + generation. A mutable pane
/// label is deliberately not part of this type — labels can never satisfy
/// any of the three parts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentIdentity {
    /// Herdr workspace session id (stable across pane renames).
    pub herdr_session: String,
    /// Stable terminal/native-session identity (e.g. the session leader the
    /// harness process runs under).
    pub terminal_session: String,
    /// Generation counter: increments every time the workspace session is
    /// recreated/rerouted; read-backs from an older generation are stale.
    pub generation: u64,
}

/// Bind an agent identity from its three required parts. Binding without
/// all three parts (or with a part outside the closed identity grammar
/// `[A-Za-z0-9_.-]{1,64}`) is refused with `refusal.identity.incomplete`:
/// a caller that only knows a mutable pane label cannot construct this
/// identity at all (AC3).
pub fn bind_identity(
    herdr_session: &str,
    terminal_session: &str,
    generation: u64,
) -> Result<AgentIdentity, AdapterError> {
    let mut missing = Vec::new();
    if !is_actor(herdr_session) {
        missing.push("herdr_session");
    }
    if !is_actor(terminal_session) {
        missing.push("terminal_session");
    }
    if !missing.is_empty() {
        return Err(AdapterError::refusal(
            CODE_INCOMPLETE_IDENTITY,
            format!(
                "stable agent identity requires all three parts; missing/invalid: {}",
                missing.join(", ")
            ),
        ));
    }
    Ok(AgentIdentity {
        herdr_session: herdr_session.to_string(),
        terminal_session: terminal_session.to_string(),
        generation,
    })
}

/// A bound harness session: an id plus the full identity triple (AC3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionHandle {
    /// Session id (actor grammar; used for workspace read-back addressing).
    pub session_id: String,
    /// The bound stable identity.
    pub identity: AgentIdentity,
}

/// Create a bound session handle from a session id and a fully bound
/// identity.
pub fn new_session(
    session_id: &str,
    identity: AgentIdentity,
) -> Result<SessionHandle, AdapterError> {
    if !is_actor(session_id) {
        return Err(AdapterError::refusal(
            CODE_INCOMPLETE_IDENTITY,
            format!("session id {session_id:?} is outside the closed identity grammar"),
        ));
    }
    Ok(SessionHandle {
        session_id: session_id.to_string(),
        identity,
    })
}

// ---------------------------------------------------------------------------
// Invocation rows and operation execution
// ---------------------------------------------------------------------------

/// Headless prompt invocation rows for the official adapters (v1 contract
/// candidates; exact real-world flag parity is [awaiting-evidence] until
/// the human-gated clean-host smokes, AC6 — see the smoke commands in
/// .report-7.md). The prompt payload is appended as one final argv element
/// and is never interpolated. Workspace operations (observe/interrupt/
/// outcome/identity) run against the workspace executable with typed
/// session addressing.
///
/// Issue #92 F2: the row runs the **declared role binding** and continues
/// the session `harness_start` bound.
/// - The bound harness profile key is the run's declared role configuration
///   key. Hermes selects a named profile with the documented global flag
///   `-p <key>` (verified against the installed CLI: the flag is handled by
///   the launcher's pre-parse, `hermes_cli/main.py`), and the declared
///   provider/model pair is passed through on the documented global flags
///   `--provider <p>` / `-m <model>` when the profile declares one (never
///   invented, never defaulted). The other official kinds carry the pair on
///   their own documented rows (Pi, Jcode) and no role-key flag exists for
///   them — nothing is fabricated.
/// - Session continuity is the documented `chat --continue <session>
///   --create-if-missing` pair (`hermes chat --help`: continue a session by
///   name, creating it when it does not exist yet), so the first prompt of a
///   run creates the session `harness_start` bound and every later prompt
///   continues that exact same session by name.
fn prompt_args(profile: &Profile, session_id: &str) -> Result<Vec<String>, AdapterError> {
    match profile.kind {
        HarnessKind::Hermes => {
            let mut args = vec!["-p".to_string(), profile.key.clone()];
            if let (Some(provider), Some(model)) =
                (profile.provider.as_deref(), profile.model.as_deref())
            {
                args.push("--provider".to_string());
                args.push(provider.to_string());
                args.push("-m".to_string());
                args.push(model.to_string());
            }
            args.push("chat".to_string());
            args.push("--continue".to_string());
            args.push(session_id.to_string());
            args.push("--create-if-missing".to_string());
            args.push("-q".to_string());
            Ok(args)
        }
        HarnessKind::ClaudeCode => Ok(vec!["-p".to_string()]),
        HarnessKind::Codex => Ok(vec!["exec".to_string()]),
        // One-shot `--print` row (issue #33, measured against pi v0.85.1 on
        // 2026-09-08). The provider/model pair is the explicit profile
        // binding (issue #80) — a profile without it refuses here with
        // `refusal.binding.missing`; there is no default and nothing is
        // substituted. The pair is opaque adapter metadata carried as argv
        // flags (never persisted, never on a wire); credentials arrive
        // only through the allowlisted environment. The trailing `--` is
        // pi's documented end-of-options guard, so a data-last payload that
        // begins with `-` can never be parsed as an option.
        HarnessKind::Pi => {
            let (provider, model) = profile.prompt_binding()?;
            Ok(vec![
                "--provider".to_string(),
                provider.to_string(),
                "--model".to_string(),
                model.to_string(),
                "--print".to_string(),
                "--".to_string(),
            ])
        }
        // One-shot `jcode run` row (issue #37, measured against jcode
        // v0.84.0 on 2026-09-08: the documented row exits 1 with the
        // measured missing-key text when no provider key is present, and
        // the `--` end-of-options guard is accepted, keeping the data-last
        // payload safe). The provider/model pair is the explicit profile
        // binding (issue #80) — a profile without it refuses here with
        // `refusal.binding.missing`; there is no default and nothing is
        // substituted. `--json` makes the real binary emit a
        // machine-readable envelope on stdout (top-level object carrying
        // `text` plus the returned `provider`/`model`; verified
        // 2026-09-08); the adapter parses that envelope back into the
        // transcript and surfaces the returned identity, falling back to
        // raw stdout when the output is not an envelope (defensive against
        // non-envelope stdout). The pair is opaque adapter metadata in argv
        // — never persisted, never on a wire; credentials arrive only
        // through the allowlisted environment.
        HarnessKind::Jcode => {
            let (provider, model) = profile.prompt_binding()?;
            Ok(vec![
                "run".to_string(),
                "--provider".to_string(),
                provider.to_string(),
                "--model".to_string(),
                model.to_string(),
                "--json".to_string(),
                "--".to_string(),
            ])
        }
        HarnessKind::Argv => Ok(profile.op_args.get("prompt").cloned().unwrap_or_default()),
    }
}

/// Workspace session-operation argv rows (v1 candidate contract against
/// [`WORKSPACE_EXECUTABLE`]; fake executables in tests pin the shape).
fn workspace_args(op: Op, session_id: &str) -> Vec<String> {
    let subcommand = match op {
        Op::Start => "start",
        Op::Observe | Op::Identity => "show",
        Op::Interrupt => "interrupt",
        Op::Outcome => "outcome",
        _ => unreachable!("workspace_args called for a workspace op"),
    };
    vec![
        "session".to_string(),
        subcommand.to_string(),
        session_id.to_string(),
        "--json".to_string(),
    ]
}

// ---------------------------------------------------------------------------
// Official one-shot adapter lane lifecycle reporting under Herdr (issues
// #33 A2, #37)
//
// Herdr's custom-integration contract (verified at 0.8.2 and 0.9.0):
// an agent running in a Herdr pane inherits `HERDR_ENV`/`HERDR_PANE_ID`/
// `HERDR_BIN_PATH`/`HERDR_SOCKET_PATH`; integrations report semantic state
// through `pane report-agent <pane> --source <id> --agent <label>
// --state <working|idle|blocked>` and release the source's authority with
// `pane release-agent` when the agent exits. Reports must only fire when
// `HERDR_ENV=1` and the required variables are present, and `--source`
// must stay stable and unique to the integration.
// ---------------------------------------------------------------------------

/// Stable, unique lifecycle source id the pi adapter reports under (herdr
/// custom-integration contract). Never reported outside a Herdr pane.
///
/// Pre-rename identifier, retained deliberately: this is a live
/// custom-integration source name registered in operators' Herdr setups,
/// and renaming live registry identity is out of scope for the product
/// rename (docs/contracts/compatibility.md, "Product rename (issue #106)").
pub const HERDR_LIFECYCLE_SOURCE_PI: &str = "custom:herdr-fleet-pi";

/// Stable, unique lifecycle source id the jcode adapter reports under
/// (herdr custom-integration contract). Never reported outside a Herdr
/// pane. Pre-rename identifier, retained for the same reason as
/// [`HERDR_LIFECYCLE_SOURCE_PI`].
pub const HERDR_LIFECYCLE_SOURCE_JCODE: &str = "custom:herdr-fleet-jcode";

/// The agent label reported for pi lanes (herdr `agent list` shows the
/// lane as `agent=pi`).
pub const HERDR_LIFECYCLE_AGENT_PI: &str = "pi";

/// The agent label reported for jcode lanes (herdr `agent list` shows the
/// lane as `agent=jcode`).
pub const HERDR_LIFECYCLE_AGENT_JCODE: &str = "jcode";

/// The herdr lifecycle (source id, agent label) pair an official adapter
/// reports under (issues #33 A2 / #37); `None` for kinds with no lifecycle
/// reporting (hermes/claude-code/codex report through the workspace's own
/// agent kinds, and `argv` has no fixed agent identity).
fn herdr_lifecycle_identity(kind: HarnessKind) -> Option<(&'static str, &'static str)> {
    match kind {
        HarnessKind::Pi => Some((HERDR_LIFECYCLE_SOURCE_PI, HERDR_LIFECYCLE_AGENT_PI)),
        HarnessKind::Jcode => Some((HERDR_LIFECYCLE_SOURCE_JCODE, HERDR_LIFECYCLE_AGENT_JCODE)),
        _ => None,
    }
}

/// The herdr pane context of an operation: `Some(pane_id)` when the
/// allowlisted environment marks a Herdr pane (`HERDR_ENV=1` with a
/// non-empty `HERDR_PANE_ID`); `None` otherwise, which makes lifecycle
/// reporting a no-op outside Herdr.
pub fn herdr_pane_context(env: &BTreeMap<String, String>) -> Option<&str> {
    if env.get("HERDR_ENV").map(String::as_str) != Some("1") {
        return None;
    }
    env.get("HERDR_PANE_ID")
        .map(String::as_str)
        .filter(|pane| !pane.is_empty())
}

/// The herdr lifecycle report after a typed pi/jcode operation result
/// (issues #33 A2 / #37 / #80). `pane report-agent` has no `done` input
/// state, so a terminal one-shot `prompt` reports `idle`;
/// `refusal.credentials` (a user decision is required — the provider key)
/// and `refusal.binding.missing` (a user decision is required — declare
/// the provider/model binding) report `blocked` with static messages that
/// never carry credential or binding text. `start` reports `working` while
/// the lane is active. Returns `(state, message)` or `None` when no
/// report applies.
fn herdr_lifecycle_report(result: &OpResult) -> Option<(&'static str, Option<&'static str>)> {
    match result.op {
        Op::Start if result.status == "succeeded" => Some(("working", None)),
        Op::Prompt => match result.code {
            Some(CODE_CREDENTIALS) => Some(("blocked", Some("harness credentials required"))),
            Some(CODE_BINDING) => {
                Some(("blocked", Some("harness provider/model binding required")))
            }
            _ => Some(("idle", None)),
        },
        _ => None,
    }
}

/// Run the documented `pane report-agent` row for one lifecycle report.
/// Best-effort sideband: the typed op result is never changed by a report
/// failure (missing/unusable workspace executable, nonzero exit).
fn report_herdr_lifecycle(
    pane: &str,
    state: &str,
    message: Option<&str>,
    source: &str,
    agent: &str,
    env: &BTreeMap<String, String>,
) {
    let mut args = vec![
        "pane".to_string(),
        "report-agent".to_string(),
        pane.to_string(),
        "--source".to_string(),
        source.to_string(),
        "--agent".to_string(),
        agent.to_string(),
        "--state".to_string(),
        state.to_string(),
    ];
    if let Some(message) = message {
        args.push("--message".to_string());
        args.push(message.to_string());
    }
    match run_typed(WORKSPACE_EXECUTABLE, &args, ADAPTER_TIMEOUT, env, None) {
        ProcessOutcome::Ok(_) => {}
        ProcessOutcome::Failed(_) => {}
    }
}

// ---------------------------------------------------------------------------
// Herdr pane substrate (issue #139)
//
// ADR-0003 makes Herdr the execution/workspace substrate — it owns
// workspaces, panes, terminals and agent-process hosting — while Canter is
// the headless control plane. This section is the typed, closed row set the
// adapter uses to run a role INSIDE a Herdr pane instead of as a bare child
// of the daemon:
//
//   pane create/reuse   `herdr workspace create --cwd <lane worktree> --label <lane> --no-focus`
//                       (reuse is READ BACK, never assumed: `workspace list` + `pane list`)
//   role start          `herdr agent start <lane> --kind <kind> --pane <pane> [-- <role args>]`
//   lane binding        `herdr pane report-metadata <pane> --source custom:canter-lane
//                        --token canter_lane=<lane> --token canter_generation=<n>`
//   prompt delivery     `herdr agent prompt <lane> <payload> --wait --timeout <ms>`
//   observation         `herdr agent get <lane>` (state) + `herdr agent read <lane>` (transcript)
//   interruption        `herdr agent send-keys <lane> ctrl+c`
//
// Read-backs are the Herdr CLI's JSON envelope (`{"id":…,"result":{…},"type":…}`);
// the documented `pane`/`agent` result fields this code reads are `pane_id`,
// `cwd`, `name`, `agent_status` and `tokens`. The rows are a v1 candidate
// contract pinned by fake executables in tests ([awaiting-evidence] until the
// human-gated clean-host smoke — the same status the pre-existing workspace
// rows carry).
//
// Measured against herdr 0.9.0 (issue #144): `agent start` and
// `pane report-metadata` are EFFECT rows — the metadata row prints no
// document at all (exit 0, zero bytes of stdout) while its recording lands —
// so their contract is the exit status ([`herdr_call_effect`]); the
// `agent get` row nests its fields under `result.agent` and is read through
// [`herdr_agent_get_row`]. Every other row above is flat.
//
// Generation safety: the lane binding carries the lane session id AND the
// lane generation, and EVERY operation re-reads it before addressing the
// pane/agent. A superseded generation, another lane's identity or another
// worktree refuses typed (`refusal.stale.generation`) — a stale lane never
// addresses a reused pane/agent identity and never delivers a prompt to it.
//
// Availability: the substrate is reached through
// [`WORKSPACE_EXECUTABLE`], and a missing/unusable executable is the typed
// `refusal.unavailable.herdr`. There is NO fallback to a bare subprocess: the
// headless row is only run when the profile's substrate IS
// [`ExecutionMode::Headless`], which the reviewed step selects explicitly.
// ---------------------------------------------------------------------------

/// Stable custom-integration source id the pane substrate registers its lane
/// binding under (`herdr pane report-metadata --source`). Never reported
/// outside the pane substrate.
pub const HERDR_LANE_SOURCE: &str = "custom:canter-lane";

/// Token name carrying the bound lane session id in the pane's reported
/// metadata (closed key grammar `^[A-Za-z0-9_-]{1,32}$`).
pub const HERDR_TOKEN_LANE: &str = "canter_lane";

/// Token name carrying the bound lane generation.
pub const HERDR_TOKEN_GENERATION: &str = "canter_generation";

/// The logical key the interruption row sends (`herdr agent send-keys`).
pub const HERDR_INTERRUPT_KEY: &str = "ctrl+c";

/// Bounded transcript excerpt lines read back after a delivered prompt.
const HERDR_TRANSCRIPT_LINES: usize = 200;

/// Margin between the Herdr row's own wait bound and the outer op deadline:
/// the row reports its own timeout instead of being killed by the runner's
/// deadline.
const HERDR_WAIT_MARGIN_MS: u128 = 1_000;

/// The Herdr agent kind of one adapter kind: the closed `herdr agent start
/// --kind` set. `None` means the substrate has no documented row for this
/// adapter kind — the caller refuses typed (`refusal.execution.unsupported`)
/// and nothing is fabricated for it.
pub fn herdr_agent_kind(kind: HarnessKind) -> Option<&'static str> {
    match kind {
        HarnessKind::Hermes => Some("hermes"),
        HarnessKind::ClaudeCode => Some("claude"),
        HarnessKind::Codex => Some("codex"),
        HarnessKind::Pi => Some("pi"),
        HarnessKind::Jcode | HarnessKind::Argv => None,
    }
}

/// `herdr workspace list` — the workspace reuse probe (exit-zero JSON list).
fn herdr_workspace_list_args() -> Vec<String> {
    vec!["workspace".to_string(), "list".to_string()]
}

/// `herdr workspace create --cwd <lane worktree> --label <lane> --no-focus`:
/// the pane is created IN the run's lane worktree, never at a bare cwd, and
/// the caller's focus is left alone.
fn herdr_workspace_create_args(worktree: &str, lane: &str) -> Vec<String> {
    vec![
        "workspace".to_string(),
        "create".to_string(),
        "--cwd".to_string(),
        worktree.to_string(),
        "--label".to_string(),
        lane.to_string(),
        "--no-focus".to_string(),
    ]
}

/// `herdr pane list --workspace <id>` — the pane read-back of one workspace.
fn herdr_pane_list_args(workspace_id: &str) -> Vec<String> {
    vec![
        "pane".to_string(),
        "list".to_string(),
        "--workspace".to_string(),
        workspace_id.to_string(),
    ]
}

/// `herdr agent list` — the lane reuse probe (exit-zero JSON list).
fn herdr_agent_list_args() -> Vec<String> {
    vec!["agent".to_string(), "list".to_string()]
}

/// `herdr agent get <lane>` — the state/identity read-back row.
fn herdr_agent_get_args(lane: &str) -> Vec<String> {
    vec!["agent".to_string(), "get".to_string(), lane.to_string()]
}

/// `herdr agent read <lane> --source recent-unwrapped --lines <n>` — the
/// bounded transcript excerpt row (best-effort evidence; a failed read never
/// changes a typed op result).
fn herdr_agent_read_args(lane: &str) -> Vec<String> {
    vec![
        "agent".to_string(),
        "read".to_string(),
        lane.to_string(),
        "--source".to_string(),
        "recent-unwrapped".to_string(),
        "--lines".to_string(),
        HERDR_TRANSCRIPT_LINES.to_string(),
    ]
}

/// `herdr agent start <lane> --kind <kind> --pane <pane> [-- <role args>]`:
/// the role agent is started in the pane with the profile-authoritative
/// binding carried as agent arguments (nothing else rides on the row).
fn herdr_agent_start_args(lane: &str, kind: &str, pane: &str, role_args: &[String]) -> Vec<String> {
    let mut args = vec![
        "agent".to_string(),
        "start".to_string(),
        lane.to_string(),
        "--kind".to_string(),
        kind.to_string(),
        "--pane".to_string(),
        pane.to_string(),
    ];
    if !role_args.is_empty() {
        args.push("--".to_string());
        args.extend(role_args.iter().cloned());
    }
    args
}

/// `herdr agent prompt <lane> <payload> --wait --timeout <ms>`: the prompt is
/// delivered through the Herdr path as ONE data element (never interpolated
/// into a shell row) and the row waits for a settled agent state.
fn herdr_agent_prompt_args(lane: &str, payload: &str, wait_ms: u128) -> Vec<String> {
    vec![
        "agent".to_string(),
        "prompt".to_string(),
        lane.to_string(),
        payload.to_string(),
        "--wait".to_string(),
        "--timeout".to_string(),
        wait_ms.to_string(),
    ]
}

/// `herdr agent send-keys <lane> ctrl+c` — the interruption row.
fn herdr_agent_send_keys_args(lane: &str) -> Vec<String> {
    vec![
        "agent".to_string(),
        "send-keys".to_string(),
        lane.to_string(),
        HERDR_INTERRUPT_KEY.to_string(),
    ]
}

/// `herdr pane report-metadata <pane> --source <source> --agent <lane>
/// --token <lane token> --token <generation token>`: the lane↔pane/agent
/// binding (session identity + generation) is RECORDED in the substrate, so
/// every later operation can verify it instead of trusting a mutable label.
fn herdr_pane_report_metadata_args(pane: &str, lane: &str, generation: u64) -> Vec<String> {
    vec![
        "pane".to_string(),
        "report-metadata".to_string(),
        pane.to_string(),
        "--source".to_string(),
        HERDR_LANE_SOURCE.to_string(),
        "--agent".to_string(),
        lane.to_string(),
        "--token".to_string(),
        format!("{HERDR_TOKEN_LANE}={lane}"),
        "--token".to_string(),
        format!("{HERDR_TOKEN_GENERATION}={generation}"),
    ]
}

/// The role arguments the pane start row carries after `--`. The binding is
/// the profile's (never a param, never a default): Hermes passes the profile
/// key on the documented global flag `-p <key>` plus the declared
/// provider/model pair on `--provider`/`-m`, Pi passes its documented
/// `--provider`/`--model` pair. Kinds whose rows document no role/model flag
/// (Claude Code, Codex) carry none — nothing is fabricated for them, exactly
/// as on the headless rows. Kinds with no pane row at all are refused typed.
fn herdr_role_args(profile: &Profile) -> Result<Vec<String>, AdapterError> {
    match profile.kind {
        HarnessKind::Hermes => {
            let mut args = vec!["-p".to_string(), profile.key.clone()];
            if let (Some(provider), Some(model)) =
                (profile.provider.as_deref(), profile.model.as_deref())
            {
                args.push("--provider".to_string());
                args.push(provider.to_string());
                args.push("-m".to_string());
                args.push(model.to_string());
            }
            Ok(args)
        }
        HarnessKind::Pi => {
            let (provider, model) = profile.prompt_binding()?;
            Ok(vec![
                "--provider".to_string(),
                provider.to_string(),
                "--model".to_string(),
                model.to_string(),
            ])
        }
        HarnessKind::ClaudeCode | HarnessKind::Codex => Ok(Vec::new()),
        HarnessKind::Jcode | HarnessKind::Argv => Err(AdapterError::refusal(
            CODE_EXECUTION_UNSUPPORTED,
            format!(
                "adapter kind {:?} has no documented Herdr pane row; declare params.execution = \
                 \"headless\" to run the bare-subprocess fallback explicitly",
                profile.kind.name()
            ),
        )),
    }
}

/// Run one Herdr CLI row and return its raw stdout. A missing/unusable
/// workspace executable is remapped to the typed [`CODE_UNAVAILABLE_HERDR`] —
/// the substrate is never bypassed.
fn herdr_run(
    args: &[String],
    timeout: Duration,
    env: &BTreeMap<String, String>,
    cwd: Option<&Path>,
) -> Result<String, ProcessFailure> {
    match run_typed(WORKSPACE_EXECUTABLE, args, timeout, env, cwd) {
        ProcessOutcome::Ok(text) => Ok(text),
        ProcessOutcome::Failed(mut err) => {
            if err.code == CODE_UNAVAILABLE {
                err.code = CODE_UNAVAILABLE_HERDR;
                err.message = format!(
                    "the Herdr workspace executable is unavailable; the pane substrate is refused \
                     (no bare-subprocess fallback): {}",
                    err.message
                );
            }
            Err(err)
        }
    }
}

/// Run one Herdr CLI row and return its JSON result document. The CLI prints
/// `{"id": …, "result": {…}, "type": …}`; a bare object (the CLI's own error
/// envelope) is accepted as its own result.
///
/// A row whose stdout is not a JSON document refuses with the EXACT argv and
/// the raw stdout it printed (item 1 of issue #144): a bare "unparsable JSON"
/// named neither the row nor its payload, so a launch that had already
/// happened could not be told apart from a broken read-back.
fn herdr_call(
    args: &[String],
    timeout: Duration,
    env: &BTreeMap<String, String>,
    cwd: Option<&Path>,
) -> Result<Val, ProcessFailure> {
    let text = herdr_run(args, timeout, env, cwd)?;
    let doc = Val::parse_json(&text)
        .map_err(|parse_error| herdr_row_refusal(args, &text, &parse_error))?;
    Ok(match doc.get("result") {
        Some(result) => result.clone(),
        None => doc,
    })
}

/// Run one EFFECT-only Herdr row: the verb's contract is what it did, never a
/// document.
///
/// `herdr pane report-metadata` — the row that RECORDS the lane↔pane/agent
/// binding — prints nothing on success in herdr 0.9.0 (measured on the
/// acceptance host: exit 0, zero bytes of stdout, the binding landed and
/// `agent get` read its tokens back), so requiring a JSON document from it
/// refused a recording that had already succeeded (item 2 of issue #144). A
/// nonzero exit is classified exactly as [`herdr_call`] classifies it.
fn herdr_call_effect(
    args: &[String],
    timeout: Duration,
    env: &BTreeMap<String, String>,
    cwd: Option<&Path>,
) -> Result<(), ProcessFailure> {
    herdr_run(args, timeout, env, cwd).map(|_| ())
}

/// Bounded bytes of one row's argv / stdout a refusal carries (issue #144):
/// enough to name the row and show what it printed, small enough that a
/// refusal never becomes a data channel of its own (a role argv can carry a
/// whole prompt payload).
const HERDR_RAW_CAP: usize = 400;

/// The refusal of one Herdr row whose stdout is not a JSON document (item 1
/// of issue #144): it names the EXACT argv and carries the raw stdout
/// (bounded, single-line, redacted) instead of describing neither.
fn herdr_row_refusal(args: &[String], text: &str, parse_error: &str) -> ProcessFailure {
    let argv = bounded_raw(&args.join(" "));
    ProcessFailure {
        code: CODE_MALFORMED,
        message: format!(
            "the Herdr row `{WORKSPACE_EXECUTABLE} {argv}` returned output that is not a JSON \
             document ({parse_error})"
        ),
        detail: format!(
            "argv: {WORKSPACE_EXECUTABLE} {argv}\nstdout ({} bytes): {}",
            text.len(),
            bounded_raw(text)
        ),
    }
}

/// One bounded, single-line, redacted rendering of captured text (issue
/// #144): newlines are escaped so an argv and a stdout payload stay one
/// diagnosable line each, and truncation names the full size.
fn bounded_raw(text: &str) -> String {
    let escaped = redact(
        &text
            .replace('\\', "\\\\")
            .replace('\n', "\\n")
            .replace('\r', "\\r"),
    );
    if escaped.len() <= HERDR_RAW_CAP {
        return escaped;
    }
    let mut end = HERDR_RAW_CAP;
    while end > 0 && !escaped.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}... ({} bytes total)", &escaped[..end], text.len())
}

/// `herdr agent get <lane>`: the agent row of the CLI's `agent_info`
/// envelope.
///
/// The verb nests its row under `result.agent` (`{"agent": {…}, "type":
/// "agent_info"}`), while every other row of this substrate is flat, so the
/// documented fields (`name`, `pane_id`, `cwd`, `agent_status`, `tokens`) are
/// read from the row itself here (item 2 of issue #144). An agent the
/// substrate does not know is the CLI's own `error` document, which is passed
/// through unchanged so the lane-binding check names the identity mismatch.
fn herdr_agent_get_row(
    lane: &str,
    timeout: Duration,
    env: &BTreeMap<String, String>,
    cwd: Option<&Path>,
) -> Result<Val, ProcessFailure> {
    let doc = herdr_call(&herdr_agent_get_args(lane), timeout, env, cwd)?;
    Ok(match doc.get("agent") {
        Some(agent) => agent.clone(),
        None => doc,
    })
}

/// The raw stdout of one best-effort Herdr row (the transcript excerpt):
/// `None` on any failure, because the row is evidence and never a decision.
fn herdr_call_text(
    args: &[String],
    timeout: Duration,
    env: &BTreeMap<String, String>,
    cwd: Option<&Path>,
) -> Option<String> {
    match run_typed(WORKSPACE_EXECUTABLE, args, timeout, env, cwd) {
        ProcessOutcome::Ok(text) => Some(text),
        ProcessOutcome::Failed(_) => None,
    }
}

/// The typed op result of one failed Herdr row: the substrate's failure
/// classification rides through unchanged (a spawn failure was already
/// remapped to [`CODE_UNAVAILABLE_HERDR`] by [`herdr_call`]).
fn herdr_failure(
    profile: &Profile,
    request: &OpRequest<'_>,
    err: ProcessFailure,
    started: std::time::Instant,
) -> OpResult {
    op_result(
        profile,
        request,
        err.status(),
        Some(err.code),
        Some(err.message),
        None,
        Some(err.detail),
        started,
    )
}

/// A required string field of a Herdr read-back document (empty when absent).
fn herdr_str(doc: &Val, key: &str) -> String {
    doc.get(key).and_then(Val::as_str).unwrap_or("").to_string()
}

/// One reported metadata token of a Herdr document, when present.
fn herdr_token(doc: &Val, name: &str) -> Option<String> {
    doc.get("tokens")?
        .get(name)
        .and_then(Val::as_str)
        .map(str::to_string)
}

/// The first array element of a Herdr list document.
fn herdr_items<'a>(doc: &'a Val, key: &str) -> &'a [Val] {
    match doc.get(key) {
        Some(Val::Arr(items)) => items.as_slice(),
        _ => &[],
    }
}

/// The lane↔pane/agent binding as one Herdr read-back reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct LaneBinding {
    /// The registered agent name the row targeted.
    agent: String,
    /// The pane the agent runs in.
    pane: String,
    /// The pane/agent working directory the substrate reports.
    cwd: String,
    /// The reported lane session-id token, when the pane carries one.
    lane: Option<String>,
    /// The reported lane generation token, when the pane carries one.
    generation: Option<i64>,
    /// The settled agent state (`idle|working|blocked|done|unknown`).
    state: String,
}

impl LaneBinding {
    /// Read a lane binding out of one `agent get`/`agent list` entry.
    fn read(doc: &Val) -> LaneBinding {
        LaneBinding {
            agent: herdr_str(doc, "name"),
            pane: herdr_str(doc, "pane_id"),
            cwd: herdr_str(doc, "cwd"),
            lane: herdr_token(doc, HERDR_TOKEN_LANE),
            generation: herdr_token(doc, HERDR_TOKEN_GENERATION)
                .and_then(|token| token.parse::<i64>().ok()),
            state: herdr_str(doc, "agent_status"),
        }
    }
}

/// Whether two paths name the same directory: canonicalized when both
/// resolve (so `/tmp` and `/private/tmp` agree on macOS), literal otherwise.
fn same_worktree(reported: &str, expected: &Path) -> bool {
    if reported.is_empty() {
        return false;
    }
    let reported_path = Path::new(reported);
    if reported_path == expected {
        return true;
    }
    match (reported_path.canonicalize(), expected.canonicalize()) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

/// Verify one Herdr read-back against the bound lane identity. Every part is
/// REQUIRED: the row must have resolved the bound agent name, the pane must
/// carry THIS lane's session-id token and THIS generation, and — when the
/// caller knows the run's lane worktree — the reported working directory must
/// be that worktree. Anything else refuses typed
/// (`refusal.stale.generation`): a superseded generation, another lane's
/// identity or another worktree never receives work.
fn verify_lane_binding(
    doc: &Val,
    session: &SessionHandle,
    worktree: Option<&Path>,
) -> Result<LaneBinding, ProcessFailure> {
    let lane = session.session_id.as_str();
    let generation = session.identity.generation;
    let binding = LaneBinding::read(doc);
    let mut stale = Vec::new();
    if binding.agent != lane {
        stale.push(format!("agent {:?}", binding.agent));
    }
    match binding.lane.as_deref() {
        Some(reported) if reported == lane => {}
        Some(reported) => stale.push(format!("lane {reported:?}")),
        None => stale.push("lane token absent".to_string()),
    }
    match binding.generation {
        Some(reported) if reported == generation as i64 => {}
        Some(reported) => stale.push(format!("generation {reported}")),
        None => stale.push("generation token absent".to_string()),
    }
    if let Some(worktree) = worktree
        && !same_worktree(&binding.cwd, worktree)
    {
        stale.push(format!("worktree {:?}", binding.cwd));
    }
    if !stale.is_empty() {
        return Err(ProcessFailure {
            code: CODE_STALE_GENERATION,
            message: format!(
                "the addressed Herdr pane/agent is not lane {lane:?} generation {generation}: the \
                 pane substrate refuses rather than deliver work to a reused identity"
            ),
            detail: diagnostics(&format!("read-back differs on {}", stale.join(", "))),
        });
    }
    Ok(binding)
}

/// The wait bound (ms) a Herdr row gets inside an op deadline.
fn herdr_wait_ms(timeout: Duration) -> u128 {
    let budget = timeout.as_millis();
    budget.saturating_sub(HERDR_WAIT_MARGIN_MS).max(1)
}

/// The pane identity of one `pane list` row (item 3 of issue #144): the row's
/// own `pane_id`, which every measured `herdr pane list` row carries
/// (`{"pane_id":"w2VE:p1","cwd":…,"tokens":…}`).
///
/// A row that resolved as THIS lane's pane but carries no identity refuses
/// with the RAW ROW: it is a read-back this code cannot address, which the
/// operator has to see — never a "unparsable JSON" (the row parsed fine) and
/// never an empty detail.
fn herdr_pane_identity(row: &Val) -> Result<String, ProcessFailure> {
    let pane_id = herdr_str(row, "pane_id");
    if pane_id.is_empty() {
        return Err(ProcessFailure {
            code: CODE_MALFORMED,
            message: "a Herdr pane read-back carries no pane_id".to_string(),
            detail: diagnostics(&String::from_utf8_lossy(
                &crate::canonical::canonical_bytes(row),
            )),
        });
    }
    Ok(pane_id)
}

/// Resolve the pane the lane's workspace already owns, when there is one:
/// the workspace label is the lane session id and the pane's reported cwd is
/// the run's lane worktree. A workspace labelled for this lane WITHOUT a pane
/// in that worktree is a binding mismatch and refuses typed (never a silent
/// "reuse whatever pane is there").
fn herdr_lane_pane(
    lane: &str,
    worktree: &Path,
    timeout: Duration,
    env: &BTreeMap<String, String>,
    cwd: Option<&Path>,
) -> Result<Option<String>, ProcessFailure> {
    let list = herdr_call(&herdr_workspace_list_args(), timeout, env, cwd)?;
    let workspace = herdr_items(&list, "workspaces")
        .iter()
        .find(|workspace| herdr_str(workspace, "label") == lane);
    let Some(workspace) = workspace else {
        return Ok(None);
    };
    let workspace_id = herdr_str(workspace, "workspace_id");
    if workspace_id.is_empty() {
        return Err(ProcessFailure {
            code: CODE_MALFORMED,
            message: "a Herdr workspace read-back carries no workspace_id".to_string(),
            detail: String::new(),
        });
    }
    let panes = herdr_call(&herdr_pane_list_args(&workspace_id), timeout, env, cwd)?;
    let pane = herdr_items(&panes, "panes")
        .iter()
        .find(|pane| same_worktree(&herdr_str(pane, "cwd"), worktree));
    match pane {
        Some(pane) => Ok(Some(herdr_pane_identity(pane)?)),
        // The lane's label is already taken by a workspace whose panes are NOT
        // in this run's lane worktree: the identity was reused by another
        // generation, another lane or another worktree. Fail closed instead of
        // creating a second workspace under the same label or reusing a pane
        // that belongs elsewhere.
        None => Err(ProcessFailure {
            code: CODE_STALE_GENERATION,
            message: format!(
                "the Herdr workspace labelled {lane:?} carries no pane in the run's lane worktree \
                 {}: the lane↔pane identity was reused elsewhere, so the bind refuses rather than \
                 creating a duplicate workspace or reusing another lane's pane",
                worktree.display()
            ),
            detail: diagnostics(&format!("workspace {workspace_id}")),
        }),
    }
}

/// Start — or REUSE — the lane's role agent inside a Herdr pane created in
/// the run's lane worktree (issue #139). The lane binding is recorded in the
/// substrate and read back before the op reports success, so a run never
/// records a pane/agent it did not verify.
fn herdr_start(
    profile: &Profile,
    request: &OpRequest<'_>,
    worktree: Option<&Path>,
    env: &BTreeMap<String, String>,
    started: std::time::Instant,
) -> OpResult {
    let Some(agent_kind) = herdr_agent_kind(profile.kind) else {
        return op_result(
            profile,
            request,
            "refused",
            Some(CODE_EXECUTION_UNSUPPORTED),
            Some(format!(
                "adapter kind {:?} has no documented Herdr pane row; declare \
                 params.execution = \"headless\" to run the bare-subprocess fallback explicitly",
                profile.kind.name()
            )),
            None,
            None,
            started,
        );
    };
    let Some(worktree) = worktree else {
        return op_result(
            profile,
            request,
            "refused",
            Some(CODE_BAD_REQUEST),
            Some(
                "the Herdr pane substrate creates the pane in the run's lane worktree and this \
                 step bound none; declare params.execution = \"headless\" to run the \
                 bare-subprocess fallback explicitly"
                    .to_string(),
            ),
            None,
            None,
            started,
        );
    };
    let worktree_text = worktree.to_string_lossy().to_string();
    let lane = request.session.session_id.clone();
    let role_args = match herdr_role_args(profile) {
        Ok(args) => args,
        Err(err) => {
            return op_result(
                profile,
                request,
                "refused",
                Some(err.code),
                Some(err.message),
                None,
                None,
                started,
            );
        }
    };
    let timeout = request.timeout;
    // Reuse probe: an agent already registered under this lane name is
    // REUSED only when its binding verifies (lane + generation + worktree).
    match herdr_call(&herdr_agent_list_args(), timeout, env, Some(worktree)) {
        Ok(list) => {
            let existing = herdr_items(&list, "agents")
                .iter()
                .find(|agent| herdr_str(agent, "name") == lane);
            if let Some(existing) = existing {
                return match verify_lane_binding(existing, request.session, Some(worktree)) {
                    Ok(binding) => op_result(
                        profile,
                        request,
                        "succeeded",
                        None,
                        None,
                        Some(lane_start_payload(
                            profile,
                            request,
                            &binding,
                            &worktree_text,
                            true,
                        )),
                        None,
                        started,
                    ),
                    Err(err) => op_result(
                        profile,
                        request,
                        err.status(),
                        Some(err.code),
                        Some(err.message),
                        None,
                        Some(err.detail),
                        started,
                    ),
                };
            }
        }
        Err(err) => {
            return herdr_failure(profile, request, err, started);
        }
    }
    // Create (or reuse) the lane's workspace and pane IN the lane worktree.
    let pane = match herdr_lane_pane(&lane, worktree, timeout, env, Some(worktree)) {
        Ok(Some(pane)) => pane,
        Ok(None) => {
            let created = match herdr_call(
                &herdr_workspace_create_args(&worktree_text, &lane),
                timeout,
                env,
                Some(worktree),
            ) {
                Ok(doc) => doc,
                Err(err) => {
                    return herdr_failure(profile, request, err, started);
                }
            };
            let root = created.get("root_pane").cloned().unwrap_or_else(null);
            let pane = herdr_str(&root, "pane_id");
            if pane.is_empty() {
                return op_result(
                    profile,
                    request,
                    "refused",
                    Some(CODE_MALFORMED),
                    Some("a Herdr workspace create read-back carries no root pane".to_string()),
                    None,
                    Some(diagnostics(&String::from_utf8_lossy(
                        &crate::canonical::canonical_bytes(&created),
                    ))),
                    started,
                );
            }
            let reported = herdr_str(&root, "cwd");
            if !reported.is_empty() && !same_worktree(&reported, worktree) {
                return op_result(
                    profile,
                    request,
                    "refused",
                    Some(CODE_STALE_GENERATION),
                    Some(format!(
                        "the Herdr pane {} was created in {reported:?}, not in the run's lane \
                         worktree {worktree_text:?}",
                        pane
                    )),
                    None,
                    None,
                    started,
                );
            }
            pane
        }
        Err(err) => {
            return herdr_failure(profile, request, err, started);
        }
    };
    // Start the role agent in the pane, then RECORD the lane binding (session
    // identity + generation) so every later operation can verify it. Both are
    // EFFECT rows: `agent start` prints an `agent_started` document nobody
    // reads, and `pane report-metadata` prints none at all (issue #144), so
    // their contract is the exit status, never a parsed document.
    for row in [
        herdr_agent_start_args(&lane, agent_kind, &pane, &role_args),
        herdr_pane_report_metadata_args(&pane, &lane, request.session.identity.generation),
    ] {
        if let Err(err) = herdr_call_effect(&row, timeout, env, Some(worktree)) {
            return herdr_failure(profile, request, err, started);
        }
    }
    // The state/identity read-back is the `agent_info` envelope's own row.
    let read_back = match herdr_agent_get_row(&lane, timeout, env, Some(worktree)) {
        Ok(doc) => doc,
        Err(err) => {
            return herdr_failure(profile, request, err, started);
        }
    };
    match verify_lane_binding(&read_back, request.session, Some(worktree)) {
        Ok(binding) => op_result(
            profile,
            request,
            "succeeded",
            None,
            None,
            Some(lane_start_payload(
                profile,
                request,
                &binding,
                &worktree_text,
                false,
            )),
            None,
            started,
        ),
        Err(err) => op_result(
            profile,
            request,
            err.status(),
            Some(err.code),
            Some(err.message),
            None,
            Some(err.detail),
            started,
        ),
    }
}

/// The recorded result of one pane-substrate start: the lane, the substrate,
/// the pane and agent identity and the run's lane worktree. This is what the
/// step outcome carries, so a supervised run's recorded binding names the
/// Herdr pane its worker runs in.
fn lane_start_payload(
    profile: &Profile,
    request: &OpRequest<'_>,
    binding: &LaneBinding,
    worktree: &str,
    reused: bool,
) -> Val {
    object(vec![
        ("session_id", string(&request.session.session_id)),
        (
            "generation",
            integer(request.session.identity.generation as i64),
        ),
        ("profile_key", string(&profile.key)),
        ("execution", string(profile.execution.name())),
        ("pane", string(&binding.pane)),
        ("agent", string(&binding.agent)),
        ("worktree", string(worktree)),
        ("reused", bool_(reused)),
    ])
}

/// Deliver one prompt through the Herdr path: the lane binding is verified
/// FIRST (a stale or foreign pane/agent never receives the prompt), then
/// `herdr agent prompt … --wait` submits it and the settled state is read
/// back through `herdr agent get`, with a bounded `herdr agent read` excerpt
/// as the pane-visible delivery evidence.
fn herdr_prompt(
    profile: &Profile,
    request: &OpRequest<'_>,
    payload: &str,
    worktree: Option<&Path>,
    env: &BTreeMap<String, String>,
    started: std::time::Instant,
) -> OpResult {
    // A kind with no documented pane row cannot have been started in a pane:
    // reach the same typed refusal the bind reaches instead of addressing an
    // agent the substrate was never asked to host.
    if herdr_agent_kind(profile.kind).is_none() {
        return op_result(
            profile,
            request,
            "refused",
            Some(CODE_EXECUTION_UNSUPPORTED),
            Some(format!(
                "adapter kind {:?} has no documented Herdr pane row; declare \
                 params.execution = \"headless\" to run the bare-subprocess fallback explicitly",
                profile.kind.name()
            )),
            None,
            None,
            started,
        );
    }
    let lane = request.session.session_id.clone();
    let timeout = request.timeout;
    let read = match herdr_agent_get_row(&lane, timeout, env, worktree) {
        Ok(doc) => doc,
        Err(err) => {
            return herdr_failure(profile, request, err, started);
        }
    };
    let binding = match verify_lane_binding(&read, request.session, worktree) {
        Ok(binding) => binding,
        Err(err) => {
            return herdr_failure(profile, request, err, started);
        }
    };
    let args = herdr_agent_prompt_args(&lane, payload, herdr_wait_ms(timeout));
    let delivered = match herdr_call(&args, timeout, env, worktree) {
        Ok(doc) => doc,
        Err(err) => {
            return herdr_failure(profile, request, err, started);
        }
    };
    // The settled state comes from the Herdr agent surface, never from
    // process-exit inference: `agent prompt --wait` reports the settled state
    // it matched and `agent get` re-reads it.
    let settled = herdr_agent_get_row(&lane, timeout, env, worktree)
        .map(|doc| LaneBinding::read(&doc))
        .unwrap_or(binding.clone());
    let state = if settled.state.is_empty() {
        herdr_str(&delivered, "agent_status")
    } else {
        settled.state.clone()
    };
    let transcript =
        herdr_call_text(&herdr_agent_read_args(&lane), timeout, env, worktree).unwrap_or_default();
    op_result(
        profile,
        request,
        "succeeded",
        None,
        None,
        Some(object(vec![
            ("transcript", string(&transcript)),
            ("state", string(&state)),
            ("agent", string(&lane)),
            ("pane", string(&settled.pane)),
            ("delivered", bool_(true)),
            (
                "worktree",
                string(
                    &worktree
                        .map(|path| path.to_string_lossy().to_string())
                        .unwrap_or_default(),
                ),
            ),
            ("execution", string(profile.execution.name())),
        ])),
        None,
        started,
    )
}

/// Observe, interrupt or collect the terminal outcome of one lane through the
/// Herdr agent surface (issue #139). Every one of them re-verifies the lane
/// binding first, so interruption and the terminal outcome are collected
/// through Herdr for THIS lane generation only, and the recorded outcome
/// distinguishes an interruption from a settled terminal state.
fn herdr_agent_op(
    profile: &Profile,
    request: &OpRequest<'_>,
    worktree: Option<&Path>,
    env: &BTreeMap<String, String>,
    started: std::time::Instant,
) -> OpResult {
    // Same closed check as the bind and the prompt: a kind without a
    // documented pane row refuses typed here too.
    if herdr_agent_kind(profile.kind).is_none() {
        return op_result(
            profile,
            request,
            "refused",
            Some(CODE_EXECUTION_UNSUPPORTED),
            Some(format!(
                "adapter kind {:?} has no documented Herdr pane row; declare \
                 params.execution = \"headless\" to run the bare-subprocess fallback explicitly",
                profile.kind.name()
            )),
            None,
            None,
            started,
        );
    }
    let lane = request.session.session_id.clone();
    let timeout = request.timeout;
    let read = match herdr_agent_get_row(&lane, timeout, env, worktree) {
        Ok(doc) => doc,
        Err(err) => {
            return herdr_failure(profile, request, err, started);
        }
    };
    let binding = match verify_lane_binding(&read, request.session, worktree) {
        Ok(binding) => binding,
        Err(err) => {
            return herdr_failure(profile, request, err, started);
        }
    };
    match request.op {
        Op::Observe => op_result(
            profile,
            request,
            "succeeded",
            None,
            None,
            Some(object(vec![
                ("state", string(&binding.state)),
                ("agent", string(&binding.agent)),
                ("pane", string(&binding.pane)),
                ("worktree", string(&binding.cwd)),
                ("execution", string(profile.execution.name())),
            ])),
            None,
            started,
        ),
        Op::Identity => op_result(
            profile,
            request,
            "succeeded",
            None,
            None,
            Some(object(vec![
                (
                    "herdr_session",
                    string(&request.session.identity.herdr_session),
                ),
                (
                    "terminal_session",
                    string(&request.session.identity.terminal_session),
                ),
                (
                    "generation",
                    integer(request.session.identity.generation as i64),
                ),
                ("pane", string(&binding.pane)),
                ("agent", string(&binding.agent)),
            ])),
            None,
            started,
        ),
        Op::Interrupt => {
            if let Err(err) = herdr_call(&herdr_agent_send_keys_args(&lane), timeout, env, worktree)
            {
                return herdr_failure(profile, request, err, started);
            }
            let after = herdr_agent_get_row(&lane, timeout, env, worktree)
                .map(|doc| LaneBinding::read(&doc))
                .unwrap_or_else(|_| binding.clone());
            let outcome = if after.state == "done" {
                "done"
            } else {
                "interrupted"
            };
            op_result(
                profile,
                request,
                "succeeded",
                None,
                None,
                Some(object(vec![
                    ("interrupted", bool_(true)),
                    ("state", string(&after.state)),
                    ("outcome", string(outcome)),
                    ("agent", string(&lane)),
                    ("pane", string(&after.pane)),
                ])),
                None,
                started,
            )
        }
        // Op::Outcome: the terminal outcome is the settled Herdr agent state.
        // Only a settled state is a terminal outcome; a still-working or
        // unknown agent is ambiguous (never reported as a completed run).
        _ => {
            let outcome = match binding.state.as_str() {
                "done" => "done",
                "idle" => "idle",
                "blocked" => "blocked",
                _ => {
                    return op_result(
                        profile,
                        request,
                        "ambiguous",
                        Some(CODE_TIMEOUT),
                        Some(format!(
                            "the Herdr agent of lane {lane:?} is {:?}, not a settled terminal \
                             outcome; the state is read back through the Herdr agent surface",
                            binding.state
                        )),
                        None,
                        None,
                        started,
                    );
                }
            };
            op_result(
                profile,
                request,
                "succeeded",
                None,
                None,
                Some(object(vec![
                    ("state", string(&binding.state)),
                    ("outcome", string(outcome)),
                    ("agent", string(&binding.agent)),
                    ("pane", string(&binding.pane)),
                ])),
                None,
                started,
            )
        }
    }
}

/// Run one typed operation against a profile (see module docs for the
/// bounds). `Op::Start` binds no subprocess (the handle is already bound);
/// `Op::Prompt` runs the harness executable with the payload as a single
/// final data element; the remaining operations run the workspace
/// read-back/control rows against [`WORKSPACE_EXECUTABLE`].
pub fn execute_op(
    profile: &Profile,
    request: &OpRequest<'_>,
    env: &BTreeMap<String, String>,
) -> OpResult {
    execute_op_at(profile, request, env, None)
}

/// Execute an operation with the child process confined to `cwd` (issue #8:
/// harness work may edit, test, and commit only inside the assigned
/// worktree, so the daemon passes the lane worktree as the child working
/// directory). Everything else matches [`execute_op`].
pub fn execute_op_in_worktree(
    profile: &Profile,
    request: &OpRequest<'_>,
    env: &BTreeMap<String, String>,
    cwd: &Path,
) -> OpResult {
    execute_op_at(profile, request, env, Some(cwd))
}

/// Run one bounded invocation whose child leads its **own process group**
/// (issue #92 F1): the deadline terminates the whole group, so a harness or
/// effect child that forked helpers can never leave an orphan behind.
///
/// This is the runner for the effect-class children (the harness prompt rows
/// and the git/gh effect rows). The read adapters keep
/// [`crate::process::run`] (a direct-child deadline); the group semantics
/// need spawn-time group creation plus a group signal, so the effect runner
/// lives here rather than in the read-adapter module.
///
/// Group termination signals the child's process group through a `kill`
/// helper resolved from the ambient environment plus the standard system
/// directories — never from the child's allowlisted PATH, which a Linux
/// image can lack `kill` in (issue #92 round 2: that is how the group signal
/// silently failed and left a descendant behind). The helper's negative-pid
/// form is only a cheap best-effort first attempt, though: its parsing is not
/// portable (Linux `kill` rejects the form the BSD one accepts), so the
/// GUARANTEE comes from [`reap_group`] — after the deadline the group is
/// verified and emptied by POSITIVE pid inside a bounded window. One
/// diagnostic line describing all of it is appended to the captured stderr,
/// so the step outcome/evidence names what happened instead of discarding it.
/// The post-exit path is bounded by [`PIPE_READ_GRACE`], so a descendant that
/// survives the reaping and holds the inherited write ends can never extend
/// the op past `deadline + PIPE_READ_GRACE`; `ProcStatus::TimedOut` is
/// reported either way.
pub fn run_grouped(spec: ProcSpec<'_>) -> ProcOut {
    let started = std::time::Instant::now();
    let mut command = std::process::Command::new(spec.program);
    command
        .args(spec.args)
        .env_clear()
        .envs(spec.env)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    // The child becomes the leader of its own process group (its pid is the
    // group id), so every descendant inherits a group we can terminate.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    if let Some(cwd) = spec.cwd {
        command.current_dir(cwd);
    }

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(err) => {
            return ProcOut {
                status: ProcStatus::SpawnFailed(err.to_string()),
                stdout: String::new(),
                stderr: String::new(),
                elapsed_ms: started.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
            };
        }
    };
    let group = child.id();

    // The deadline signals the group ONCE (a helper that cannot deliver the
    // signal is reported, never silently retried); the direct child is always
    // also killed through the std API.
    let mut group_signal: Option<String> = None;
    let mut group_signalled = false;
    let status = loop {
        if started.elapsed() >= spec.timeout {
            if !group_signalled {
                group_signal = signal_group(group);
                group_signalled = true;
            }
            let _ = child.kill();
        }
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
            Err(err) => {
                // The signal is attempted ONCE: a failure recorded by the
                // deadline branch above is reported here too, never replaced by
                // "delivered" (issue #92 round 5 — `None` means delivered, so
                // the already-attempted failure must be handed on, not dropped).
                let failure = if group_signalled {
                    group_signal.clone()
                } else {
                    signal_group(group)
                };
                let _ = child.kill();
                return ProcOut {
                    status: ProcStatus::SpawnFailed(err.to_string()),
                    stdout: String::new(),
                    stderr: failure.map_or_else(String::new, |reason| {
                        group_signal_diagnostic(group, &reason)
                    }),
                    elapsed_ms: started.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
                };
            }
        }
    };

    // The child is gone; the post-exit path is bounded by the documented grace
    // measured from THIS moment (issue #92 rounds 2-3): deterministic group
    // reaping first, then the bounded read. The child's exit is itself inside
    // the deadline, so the AC's `deadline + grace` outer bound holds, and a
    // descendant that lingers on the inherited pipes can never stall the op
    // for the rest of the deadline window.
    let child_exit = Instant::now();
    let deadline_exceeded = child_exit.duration_since(started) >= spec.timeout;
    let group_reap = if deadline_exceeded {
        // Issue #92 round 3: the group signal alone is not a guarantee — the
        // helper's CLI form is not portable (Linux `kill` rejects the
        // negative-pid form the BSD one accepts) — so the group is verified
        // and emptied by positive pid inside a bounded window.
        Some(reap_group(
            group,
            child_exit + GROUP_REAP_WINDOW,
            group_signal.clone(),
        ))
    } else {
        None
    };
    let read_deadline = child_exit + PIPE_READ_GRACE;
    let stdout_pipe = BoundedPipe::read(child.stdout.take());
    let stderr_pipe = BoundedPipe::read(child.stderr.take());
    let stdout = stdout_pipe.take_within(read_deadline);
    let mut stderr = stderr_pipe.take_within(read_deadline);
    let diagnostic = match (&group_reap, &group_signal) {
        (Some(report), _) => Some(group_reap_diagnostic(group, report)),
        (None, Some(reason)) => Some(group_signal_diagnostic(group, reason)),
        (None, None) => None,
    };
    if let Some(diagnostic) = diagnostic {
        // Observable diagnostics (never discarded): the step outcome/evidence
        // names what the deadline kill did.
        if !stderr.is_empty() && !stderr.ends_with('\n') {
            stderr.push('\n');
        }
        stderr.push_str(&diagnostic);
    }
    let _ = child.wait();

    let timed_out = started.elapsed() >= spec.timeout;
    let final_status = if timed_out && !status.success() && status.code().is_none() {
        ProcStatus::TimedOut
    } else {
        ProcStatus::Exit(status.code().unwrap_or(-1))
    };

    ProcOut {
        status: final_status,
        stdout,
        stderr,
        elapsed_ms: started.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
    }
}

/// The bounded grace this runner allows a child's captured pipes to drain
/// after the child itself is gone (issue #92 round 2). A descendant the
/// deadline could not terminate can hold the inherited stdout/stderr write
/// ends for its whole lifetime, so the post-exit read is bounded by this
/// grace: the op's elapsed stays within `deadline + PIPE_READ_GRACE` (never
/// the descendant's lifetime), and whatever arrived inside the bound is kept.
pub const PIPE_READ_GRACE: Duration = Duration::from_millis(750);

/// One child pipe read under a bound (issue #92 round 2). The read runs on a
/// worker thread that appends whatever arrives into shared state;
/// [`BoundedPipe::take_within`] stops waiting at the deadline and returns the
/// capture so far, so a pipe held open by a survivor can never block the op.
/// The worker ends when the last writer closes the pipe — on a survivor it
/// simply stops being waited for (the thread is detached and holds nothing
/// the op needs, so the op's elapsed stays bounded either way).
struct BoundedPipe {
    text: Arc<Mutex<String>>,
    done: Arc<AtomicBool>,
}

impl BoundedPipe {
    fn read(pipe: Option<impl std::io::Read + Send + 'static>) -> BoundedPipe {
        let text = Arc::new(Mutex::new(String::new()));
        let done = Arc::new(AtomicBool::new(false));
        let Some(mut pipe) = pipe else {
            done.store(true, Ordering::SeqCst);
            return BoundedPipe { text, done };
        };
        let sink = Arc::clone(&text);
        let finished = Arc::clone(&done);
        std::thread::spawn(move || {
            let mut buffer = [0u8; 8192];
            loop {
                match std::io::Read::read(&mut pipe, &mut buffer) {
                    Ok(0) => break,
                    Ok(read) => {
                        if let Ok(mut text) = sink.lock() {
                            text.push_str(&String::from_utf8_lossy(&buffer[..read]));
                        }
                    }
                    Err(_) => break,
                }
            }
            finished.store(true, Ordering::SeqCst);
        });
        BoundedPipe { text, done }
    }

    /// Wait for the reader at most until `deadline`, then take the capture
    /// (the documented lossy-UTF-8 text) that arrived inside the bound.
    fn take_within(self, deadline: Instant) -> String {
        while !self.done.load(Ordering::SeqCst) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        self.text
            .lock()
            .map(|text| text.clone())
            .unwrap_or_default()
    }
}

/// The one-line runner diagnostic that names a process-group signal that
/// could not be delivered (issue #92 round 2): it rides on the captured
/// stderr of the run, so the step outcome/evidence can name it.
fn group_signal_diagnostic(group: u32, reason: &str) -> String {
    format!(
        "[canter] the process group (-{group}) could not be signalled by the kill helper: {reason}\n"
    )
}

/// The slice of the post-exit grace the deterministic group-reaping loop may
/// use (issue #92 round 3): reaping fits inside `deadline + PIPE_READ_GRACE`,
/// so the bounded capture always keeps part of the grace even when a member
/// cannot be reached.
pub const GROUP_REAP_WINDOW: Duration = Duration::from_millis(375);

/// The PATH the group helper runs under: the standard system directories
/// first, then the ambient PATH. The helpers are system utilities, not
/// children under test, so they never depend on the child's allowlisted
/// environment (issue #92 round 2).
fn group_helper_path() -> String {
    const SYSTEM_DIRS: &str = "/usr/bin:/bin:/usr/sbin:/sbin";
    match std::env::var("PATH") {
        Ok(ambient) if !ambient.is_empty() => format!("{SYSTEM_DIRS}:{ambient}"),
        _ => SYSTEM_DIRS.to_string(),
    }
}

/// The absolute candidates for a system helper, `/bin` first (present on both
/// platforms), then `/usr/bin`, with the bare name last (resolved through
/// [`group_helper_path`]).
const GROUP_HELPER_CANDIDATES: [&str; 3] = ["kill", "/bin/kill", "/usr/bin/kill"];
const PS_HELPER_CANDIDATES: [&str; 3] = ["ps", "/bin/ps", "/usr/bin/ps"];

/// Run one helper attempt under [`group_helper_path`], trying each candidate
/// until one launches and exits zero (issue #92 round 3). `None` means the
/// attempt was delivered; `Some(reason)` lists what every candidate did, so
/// the caller can report it instead of discarding it.
fn helper_attempt(candidates: &[&str], args: &[&str], label: &str) -> Option<String> {
    let path = group_helper_path();
    let mut failures: Vec<String> = Vec::new();
    for candidate in candidates {
        let launched = std::process::Command::new(candidate)
            .args(args)
            .env_clear()
            .env("PATH", &path)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        match launched {
            Ok(status) if status.success() => return None,
            Ok(status) => failures.push(format!(
                "{label} `{candidate} {}` exited {}",
                args.join(" "),
                status
                    .code()
                    .map_or_else(|| "without a code".to_string(), |code| code.to_string())
            )),
            Err(err) => failures.push(format!("{label} `{candidate}`: {err}")),
        }
    }
    Some(failures.join("; "))
}

/// Best-effort group signal: `kill -9 -<pgid>`. The form is not portable:
/// procps returned zero for a nonexistent group where BSD kill failed.
/// Exit status alone is not proof of delivery on either platform;
/// [`reap_group`] verifies and finishes the job by positive pid.
fn signal_group(group: u32) -> Option<String> {
    signal_group_with(&GROUP_HELPER_CANDIDATES, group)
}

fn signal_group_with(candidates: &[&str], group: u32) -> Option<String> {
    helper_attempt(candidates, &["-9", &format!("-{group}")], "group signal")
}

/// Terminate one process by POSITIVE pid (unambiguous on both platforms).
/// Same contract as [`signal_group`]: `None` means the kill was delivered,
/// `Some(reason)` means it was not ([`reap_group`] must never count that as a
/// reap — issue #92 round 5).
fn kill_pid(pid: u32) -> Option<String> {
    kill_pid_with(&GROUP_HELPER_CANDIDATES, pid)
}

fn kill_pid_with(candidates: &[&str], pid: u32) -> Option<String> {
    helper_attempt(candidates, &["-9", &pid.to_string()], "reap")
}

/// The live members of one process group, through the portable
/// `ps -A -o pid=,pgid=,stat=` form (issue #92 round 3). Zombies are excluded
/// (a dead-but-unreaped member is not a live process; reaping it belongs to
/// its parent), and our own pid is always excluded. `None` when `ps` could
/// not be run or its output could not be read, so the caller can report that
/// instead of guessing.
fn group_members(group: u32) -> Option<Vec<u32>> {
    let path = group_helper_path();
    let mut last = "ps not found".to_string();
    for candidate in PS_HELPER_CANDIDATES {
        let output = std::process::Command::new(candidate)
            .args(["-A", "-o", "pid=,pgid=,stat="])
            .env_clear()
            .env("PATH", &path)
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .output();
        let output = match output {
            Ok(output) if output.status.success() => output,
            Ok(output) => {
                last = format!("`{candidate}` exited {:?}", output.status.code());
                continue;
            }
            Err(err) => {
                last = format!("`{candidate}`: {err}");
                continue;
            }
        };
        let text = String::from_utf8_lossy(&output.stdout);
        let mut members = Vec::new();
        for line in text.lines() {
            let mut fields = line.split_whitespace();
            let (Some(pid), Some(pgid), Some(stat)) = (fields.next(), fields.next(), fields.next())
            else {
                continue;
            };
            let (Ok(pid), Ok(pgid)) = (pid.parse::<u32>(), pgid.parse::<u32>()) else {
                continue;
            };
            if pgid == group && pid != std::process::id() && !stat.starts_with('Z') {
                members.push(pid);
            }
        }
        return Some(members);
    }
    let _ = last;
    None
}

/// What one deadline's group termination did (issue #92 round 3): the outcome
/// of the best-effort group signal, how many members were reaped by positive
/// pid, which members no kill could reach (so they were still live at the last
/// enumeration), and any failure reason worth naming.
struct GroupReap {
    signal: Option<String>,
    reaped: usize,
    remaining: Vec<u32>,
    notes: Vec<String>,
}

/// Empty one child's process group inside a bounded window (issue #92 rounds
/// 1–3). The guarantee is the verification loop, not any single CLI form:
/// enumerate the group's live members with [`group_members`], kill them by
/// POSITIVE pid with [`kill_pid`], re-enumerate until the group is empty or
/// `deadline` expires. Never signals our own pid and never a pid outside the
/// target group; a descendant that left the group (its own session or process
/// group) is unreachable by construction and is reported instead of blocking.
///
/// Every number this loop reports is derived from the attempt results
/// (issue #92 round 5): `kill_pid` → `None` (delivered) is the only way a
/// member is counted as reaped, and only members no kill could reach are
/// carried into [`GroupReap::remaining`] as live survivors — a reported
/// failure is never evidence of delivery.
fn reap_group(group: u32, deadline: Instant, signal: Option<String>) -> GroupReap {
    let mut report = GroupReap {
        signal,
        reaped: 0,
        remaining: Vec::new(),
        notes: Vec::new(),
    };
    // Members whose positive-pid kill was delivered, once each: the
    // diagnostic counts members, never repeat attempts against a member that
    // is still dying.
    let mut killed: Vec<u32> = Vec::new();
    loop {
        match group_members(group) {
            None => {
                report
                    .notes
                    .push("ps could not enumerate the group".to_string());
                break;
            }
            Some(members) if members.is_empty() => {
                report.remaining.clear();
                break;
            }
            Some(members) => {
                let mut survivors = Vec::new();
                for pid in &members {
                    match kill_pid(*pid) {
                        None => {
                            if !killed.contains(pid) {
                                killed.push(*pid);
                            }
                        }
                        Some(reason) => {
                            survivors.push(*pid);
                            if report.notes.len() < 3 && !report.notes.contains(&reason) {
                                report.notes.push(reason);
                            }
                        }
                    }
                }
                report.reaped = killed.len();
                report.remaining = survivors;
            }
        }
        if Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    report
}

/// The one-line diagnostic of one deadline's group termination, so a failure
/// is self-diagnosing: what the best-effort signal did (a signal that was not
/// delivered is named with its reason — never rendered as delivered), how many
/// members were reaped by pid, which members no kill could reach, and any
/// failure reason (issue #92 round 5).
fn group_reap_diagnostic(group: u32, report: &GroupReap) -> String {
    let mut line = format!("[canter] deadline kill of process group -{group}: ");
    match &report.signal {
        None => line.push_str("the group-signal helper delivered"),
        Some(reason) => line.push_str(&format!(
            "the group-signal helper did not deliver ({reason})"
        )),
    }
    line.push_str(&format!(
        "; reaped {} member(s) by positive pid",
        report.reaped
    ));
    if !report.remaining.is_empty() {
        line.push_str(&format!(
            "; {} member(s) could not be killed by positive pid and were still live at the last \
             enumeration (pids {:?}; a descendant that left the process group is not reachable by \
             design)",
            report.remaining.len(),
            report.remaining
        ));
    }
    for note in &report.notes {
        line.push_str(&format!("; {note}"));
    }
    line.push('\n');
    line
}

fn execute_op_at(
    profile: &Profile,
    request: &OpRequest<'_>,
    env: &BTreeMap<String, String>,
    cwd: Option<&Path>,
) -> OpResult {
    let result = execute_op_inner(profile, request, env, cwd);
    // Issues #33 A2 / #37: a pi or jcode profile running inside a Herdr
    // pane reports the lane lifecycle through the workspace executable
    // (best-effort sideband that never changes the typed op result; no-op
    // outside Herdr).
    if let (Some((source, agent)), Some(pane)) = (
        herdr_lifecycle_identity(profile.kind),
        herdr_pane_context(env),
    ) && let Some((state, message)) = herdr_lifecycle_report(&result)
    {
        report_herdr_lifecycle(pane, state, message, source, agent, env);
    }
    result
}

fn execute_op_inner(
    profile: &Profile,
    request: &OpRequest<'_>,
    env: &BTreeMap<String, String>,
    cwd: Option<&Path>,
) -> OpResult {
    let started = std::time::Instant::now();
    let session_id = request.session.session_id.clone();
    let capability = request.op.capability();
    if !profile.supports(capability) {
        return op_result(
            profile,
            request,
            "refused",
            Some(CODE_UNKNOWN_CAPABILITY),
            Some(format!(
                "profile {:?} does not declare capability {:?}",
                profile.key, capability
            )),
            None,
            None,
            started,
        );
    }
    if request.payload.is_some() && request.op != Op::Prompt {
        return op_result(
            profile,
            request,
            "refused",
            Some(CODE_BAD_REQUEST),
            Some("a payload is only valid on the prompt operation".to_string()),
            None,
            None,
            started,
        );
    }
    match request.op {
        Op::Start => {
            // Issue #139: the product substrate starts (or REUSES) the role
            // inside a Herdr pane created in the run's lane worktree, through
            // the Herdr CLI. Unavailability is a typed refusal — the headless
            // row is never reached from here.
            if profile.execution == ExecutionMode::HerdrPane {
                return herdr_start(profile, request, cwd, env, started);
            }
            // Issue #92 F2: a declarative `argv` profile may declare its own
            // session-bind row. When it does, START really runs it (bounded,
            // worktree-confined) and the typed result is the real one; the
            // official kinds bind their documented session handle without a
            // subprocess, and nothing is invented for a profile that
            // declares no row.
            if let Some(row) = profile.op_args.get("start") {
                let out = run_typed_grouped(&profile.executable, row, request.timeout, env, cwd);
                if let ProcessOutcome::Failed(err) = out {
                    return op_result(
                        profile,
                        request,
                        err.status(),
                        Some(err.code),
                        Some(err.message),
                        None,
                        Some(err.detail),
                        started,
                    );
                }
            }
            op_result(
                profile,
                request,
                "succeeded",
                None,
                None,
                Some(object(vec![
                    ("session_id", string(&session_id)),
                    (
                        "generation",
                        integer(request.session.identity.generation as i64),
                    ),
                    ("profile_key", string(&profile.key)),
                ])),
                None,
                started,
            )
        }
        Op::Prompt => {
            let payload = match request.payload {
                Some(payload) => payload,
                None => {
                    return op_result(
                        profile,
                        request,
                        "refused",
                        Some(CODE_BAD_REQUEST),
                        Some("the prompt operation requires a payload".to_string()),
                        None,
                        None,
                        started,
                    );
                }
            };
            // Issue #139: the prompt is delivered THROUGH the Herdr path
            // (`herdr agent prompt … --wait`) for this lane generation, and
            // never by spawning the harness executable.
            if profile.execution == ExecutionMode::HerdrPane {
                return herdr_prompt(profile, request, payload, cwd, env, started);
            }
            let mut args = match prompt_args(profile, &session_id) {
                Ok(args) => args,
                Err(err) => {
                    return op_result(
                        profile,
                        request,
                        "refused",
                        Some(err.code),
                        Some(err.message),
                        None,
                        None,
                        started,
                    );
                }
            };
            // Data-last rule (AC5): the payload is appended as one literal
            // argv element; nothing else in the argv depends on it.
            args.push(payload.to_string());
            let out = run_typed_grouped(&profile.executable, &args, request.timeout, env, cwd);
            match out {
                ProcessOutcome::Ok(text) => {
                    let payload = prompt_result_payload(profile, text);
                    op_result(
                        profile,
                        request,
                        "succeeded",
                        None,
                        None,
                        Some(payload),
                        None,
                        started,
                    )
                }
                ProcessOutcome::Failed(err) => op_result(
                    profile,
                    request,
                    err.status(),
                    Some(err.code),
                    Some(err.message),
                    None,
                    Some(err.detail),
                    started,
                ),
            }
        }
        Op::Observe | Op::Identity | Op::Interrupt | Op::Outcome => {
            // Issue #139: on the pane substrate the observation, the
            // interruption and the terminal outcome are collected through the
            // `herdr agent` rows of THIS lane generation.
            if profile.execution == ExecutionMode::HerdrPane {
                return herdr_agent_op(profile, request, cwd, env, started);
            }
            let workspace_session = &request.session.identity.herdr_session;
            let args = workspace_args(request.op, workspace_session);
            let out = run_typed(WORKSPACE_EXECUTABLE, &args, request.timeout, env, cwd);
            let out = match out {
                ProcessOutcome::Ok(text) => text,
                ProcessOutcome::Failed(err) => {
                    return op_result(
                        profile,
                        request,
                        err.status(),
                        Some(err.code),
                        Some(err.message),
                        None,
                        Some(err.detail),
                        started,
                    );
                }
            };
            let doc = match Val::parse_json(&out) {
                Ok(doc) => doc,
                Err(message) => {
                    return op_result(
                        profile,
                        request,
                        "refused",
                        Some(CODE_MALFORMED),
                        Some("workspace read-back returned unparsable JSON".to_string()),
                        None,
                        Some(diagnostics(&format!("{message}: {out}"))),
                        started,
                    );
                }
            };
            match request.op {
                Op::Observe => op_result(
                    profile,
                    request,
                    "succeeded",
                    None,
                    None,
                    Some(session_state_payload(&doc)),
                    None,
                    started,
                ),
                Op::Outcome => {
                    let outcome = doc.get("outcome").and_then(Val::as_str).unwrap_or("");
                    if outcome.is_empty() {
                        op_result(
                            profile,
                            request,
                            "refused",
                            Some(CODE_MALFORMED),
                            Some(
                                "workspace read-back outcome is missing a terminal outcome"
                                    .to_string(),
                            ),
                            None,
                            Some(diagnostics(&out)),
                            started,
                        )
                    } else {
                        op_result(
                            profile,
                            request,
                            "succeeded",
                            None,
                            None,
                            Some(object(vec![
                                (
                                    "state",
                                    string(doc.get("state").and_then(Val::as_str).unwrap_or("")),
                                ),
                                ("outcome", string(outcome)),
                            ])),
                            None,
                            started,
                        )
                    }
                }
                Op::Interrupt => op_result(
                    profile,
                    request,
                    "succeeded",
                    None,
                    None,
                    Some(object(vec![("interrupted", bool_(true))])),
                    None,
                    started,
                ),
                // Op::Identity
                _ => {
                    let read_back = read_back_identity(&doc, request.session);
                    match read_back {
                        Ok(identity_doc) => op_result(
                            profile,
                            request,
                            "succeeded",
                            None,
                            None,
                            Some(identity_doc),
                            None,
                            started,
                        ),
                        Err(err) => op_result(
                            profile,
                            request,
                            "refused",
                            Some(err.code),
                            Some(err.message),
                            None,
                            Some(err.detail),
                            started,
                        ),
                    }
                }
            }
        }
    }
}

/// Execute an operation by name (the typed boundary for callers that carry
/// operation names as data). An operation outside the closed harness set is
/// refused with `unknown.capability`; the payload is only valid for the
/// `prompt` operation.
pub fn execute_named(
    profile: &Profile,
    op_name: &str,
    session: &SessionHandle,
    payload: Option<&str>,
    timeout: Duration,
    env: &BTreeMap<String, String>,
) -> OpResult {
    let Some(op) = Op::parse(op_name) else {
        let request = OpRequest {
            op: Op::Start,
            session,
            payload,
            timeout,
        };
        return op_result(
            profile,
            &request,
            "refused",
            Some(CODE_UNKNOWN_CAPABILITY),
            Some(format!(
                "capability {op_name:?} is not part of the closed harness set"
            )),
            None,
            None,
            std::time::Instant::now(),
        );
    };
    let request = OpRequest {
        op,
        session,
        payload,
        timeout,
    };
    execute_op(profile, &request, env)
}

// ---------------------------------------------------------------------------
// Session retirement (issue #75): the bounded graceful stop and the closed
// confirmation evidence grammar
// ---------------------------------------------------------------------------

/// One retirement target: the source session the workspace (Herdr) session
/// rows address and the backend process identity the confirmation compares
/// against. Both parts are bound from the durable replacement record — never
/// from request text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetirementTarget {
    /// The source session identity (the `<session>` argument of the
    /// workspace `session <verb> <session> --json` rows).
    pub session: String,
    /// The backend process identity of the source session.
    pub process: String,
}

/// The closed verdict of one retirement confirmation read-back. The
/// retirement is confirmed by BOTH backend evidence parts (the process is
/// absent AND the ownership/registration is released for the bound session
/// and generation); a read-back label (a `done`/`retired` state string, pane
/// text) is never read, so a label alone can never confirm a retirement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RetirementEvidence {
    /// The retirement is confirmed: the backend process is absent and the
    /// registration is released for the bound session and generation.
    Retired,
    /// The confirmation cannot prove absence (the session or process is
    /// still present, or the evidence is unknown/unreadable): hold — no
    /// further signal is attempted.
    Held {
        /// Bounded human detail (redacted).
        detail: String,
    },
    /// Backend evidence contradicts the retirement with a reused identity (a
    /// different process holds the bound session, or the registration
    /// belongs to another session/generation): fail closed.
    Reused {
        /// Bounded human detail (redacted).
        detail: String,
    },
}

/// Run the retirement stop row — the ONE graceful bounded stop request this
/// slice ever issues: `herdr session interrupt <session> --json` under
/// [`WORKSPACE_EXECUTABLE`] with the caller's deadline. `succeeded` means
/// the workspace accepted the stop request; a `refused` result means the
/// request was never delivered, `failed`/`ambiguous` mean the delivery is
/// unknown. Nothing here escalates: no SIGKILL, no process-group signal, no
/// broad pattern and no retry — a stop that does not confirm simply holds.
pub fn retirement_stop(
    profile: &Profile,
    target: &RetirementTarget,
    env: &BTreeMap<String, String>,
    timeout: Duration,
) -> OpResult {
    let started = std::time::Instant::now();
    if !profile.supports(Op::Interrupt.capability()) {
        return retirement_result(
            profile,
            target,
            Op::Interrupt,
            "refused",
            Some(CODE_UNKNOWN_CAPABILITY),
            Some(format!(
                "harness profile {:?} does not declare the {:?} capability required to stop a \
                 session; unsupported adapters are refused",
                profile.key,
                Op::Interrupt.capability()
            )),
            None,
            None,
            started,
        );
    }
    let args = workspace_args(Op::Interrupt, &target.session);
    match run_typed(WORKSPACE_EXECUTABLE, &args, timeout, env, None) {
        ProcessOutcome::Ok(text) => match Val::parse_json(&text) {
            Ok(_) => retirement_result(
                profile,
                target,
                Op::Interrupt,
                "succeeded",
                None,
                None,
                Some(object(vec![("interrupted", bool_(true))])),
                None,
                started,
            ),
            Err(message) => retirement_result(
                profile,
                target,
                Op::Interrupt,
                "refused",
                Some(CODE_MALFORMED),
                Some("workspace stop row returned unparsable JSON".to_string()),
                None,
                Some(diagnostics(&format!("{message}: {text}"))),
                started,
            ),
        },
        ProcessOutcome::Failed(err) => retirement_result(
            profile,
            target,
            Op::Interrupt,
            err.status(),
            Some(err.code),
            Some(err.message),
            None,
            Some(err.detail),
            started,
        ),
    }
}

/// Run the retirement confirmation read row and classify its closed evidence
/// grammar: the workspace `session show <session> --json` row, read back
/// AFTER the stop. A failure to read (unavailable/unparsable backend) is a
/// typed adapter error — the caller holds; the classification itself returns
/// the three closed verdicts (see [`RetirementEvidence`]).
pub fn retirement_evidence(
    profile: &Profile,
    target: &RetirementTarget,
    generation: i64,
    env: &BTreeMap<String, String>,
    timeout: Duration,
) -> Result<RetirementEvidence, AdapterError> {
    if !profile.supports(Op::Observe.capability()) {
        return Err(AdapterError::refusal(
            CODE_UNKNOWN_CAPABILITY,
            format!(
                "harness profile {:?} does not declare the {:?} capability required to confirm \
                 a retirement; unsupported adapters are refused",
                profile.key,
                Op::Observe.capability()
            ),
        ));
    }
    let args = workspace_args(Op::Observe, &target.session);
    let text = match run_typed(WORKSPACE_EXECUTABLE, &args, timeout, env, None) {
        ProcessOutcome::Ok(text) => text,
        ProcessOutcome::Failed(err) => {
            let retryable = err.status() == "ambiguous";
            return Err(AdapterError::failure(err.code, err.message, retryable));
        }
    };
    let doc = Val::parse_json(&text).map_err(|message| {
        AdapterError::refusal(
            CODE_MALFORMED,
            format!("retirement confirmation read-back returned unparsable JSON: {message}"),
        )
    })?;
    classify_retirement_evidence(&doc, target, generation)
}

/// Classify one retirement confirmation read-back document against the bound
/// target. The closed evidence grammar is:
///
/// ```json
/// {"session_id": "<bound session>",
///  "process": "<backend process identity>" | null,
///  "registration": {"state": "active" | "released",
///                   "session": "<bound session>", "generation": <generation>}}
/// ```
///
/// Only the two backend evidence parts are read — the read-back can carry any
/// other label, and no label confirms a retirement by itself. Missing or
/// unknown evidence holds; a positive contradiction (a different process for
/// the bound session, or a registration naming another session/generation) is
/// a reused identity and fails closed.
pub fn classify_retirement_evidence(
    doc: &Val,
    target: &RetirementTarget,
    generation: i64,
) -> Result<RetirementEvidence, AdapterError> {
    match doc.get("session_id").and_then(Val::as_str) {
        None => {
            return Ok(RetirementEvidence::Held {
                detail: "the confirmation read-back carries no session identity (an unknown \
                         session identity holds)"
                    .to_string(),
            });
        }
        Some(session) if session != target.session => {
            return Ok(RetirementEvidence::Reused {
                detail: format!(
                    "the confirmation read-back names session {session:?} for the bound session \
                     {:?} (reused pane/session identity)",
                    target.session
                ),
            });
        }
        Some(_) => {}
    }
    let process = match doc.get("process") {
        None => {
            return Ok(RetirementEvidence::Held {
                detail: "the confirmation read-back carries no process evidence (an unknown \
                         process identity holds)"
                    .to_string(),
            });
        }
        Some(Val::Null) => None,
        Some(Val::Str(process)) if is_actor(process) => Some(process.as_str()),
        Some(_) => {
            return Ok(RetirementEvidence::Held {
                detail: "the confirmation read-back process evidence is not a process identity \
                         or null (an unknown process identity holds)"
                    .to_string(),
            });
        }
    };
    let registration = match doc.get("registration") {
        Some(Val::Obj(map)) => map,
        _ => {
            return Ok(RetirementEvidence::Held {
                detail: "the confirmation read-back carries no ownership/registration evidence"
                    .to_string(),
            });
        }
    };
    let Some(registered_state) = registration.get("state").and_then(Val::as_str) else {
        return Ok(RetirementEvidence::Held {
            detail: "the registration evidence carries no state".to_string(),
        });
    };
    let Some(registered_session) = registration.get("session").and_then(Val::as_str) else {
        return Ok(RetirementEvidence::Held {
            detail: "the registration evidence carries no session identity".to_string(),
        });
    };
    let Some(registered_generation) = registration.get("generation").and_then(Val::as_int) else {
        return Ok(RetirementEvidence::Held {
            detail: "the registration evidence carries no generation".to_string(),
        });
    };
    if let Some(process) = process {
        return Ok(if process == target.process {
            RetirementEvidence::Held {
                detail: format!(
                    "the bound source process {process:?} is still present; the retirement \
                     cannot be confirmed and nothing further is signalled"
                ),
            }
        } else {
            RetirementEvidence::Reused {
                detail: format!(
                    "a different process {process:?} holds the bound session {:?} (reused \
                     process identity); the retirement cannot be confirmed",
                    target.session
                ),
            }
        });
    }
    if registered_session != target.session || registered_generation != generation {
        return Ok(RetirementEvidence::Reused {
            detail: format!(
                "stale registration: session {registered_session:?} generation \
                 {registered_generation} owns a registration, not the bound session {:?} \
                 generation {generation}",
                target.session
            ),
        });
    }
    Ok(match registered_state {
        "active" => RetirementEvidence::Held {
            detail: format!(
                "the registration is still active for session {:?} generation {generation}; \
                 the retirement cannot be confirmed",
                target.session
            ),
        },
        "released" => RetirementEvidence::Retired,
        other => RetirementEvidence::Held {
            detail: format!(
                "unknown registration state {other:?}; the retirement cannot be \
                             confirmed"
            ),
        },
    })
}

/// Build a retirement result with the wall time already measured.
#[allow(clippy::too_many_arguments)]
fn retirement_result(
    profile: &Profile,
    target: &RetirementTarget,
    op: Op,
    status: &'static str,
    code: Option<&'static str>,
    message: Option<String>,
    payload: Option<Val>,
    detail: Option<String>,
    started: std::time::Instant,
) -> OpResult {
    OpResult {
        profile_key: profile.key.clone(),
        session_id: target.session.clone(),
        op,
        status,
        code,
        message: message.map(|m| redact(&m)),
        payload,
        detail: detail.map(|d| redact(&d)),
        elapsed_ms: started.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
    }
}

// ---------------------------------------------------------------------------
// Session successors (issue #76): the bounded fresh start and the closed
// verification evidence grammar
// ---------------------------------------------------------------------------

/// One successor start target: the successor session the workspace (Herdr)
/// session rows address and the exact identity the verification read-back
/// must prove (fresh session identity, role, harness profile, the SAME
/// worktree, the kickoff receipt). All parts are bound from the durable
/// record and the request binding — never from read-back text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SuccessorTarget {
    /// The successor session identity (the `<session>` argument of the
    /// workspace `session <verb> <session> --json` rows).
    pub session: String,
    /// The doctrine role the successor must run.
    pub role: String,
    /// Harness profile key the start/read-back runs under.
    pub profile_key: String,
    /// Harness profile kind the start/read-back runs under.
    pub profile_kind: String,
    /// The SAME repository-relative worktree the read-back cwd must name.
    pub worktree: String,
    /// The kickoff receipt (64-hex sha256) the read-back must echo.
    pub kickoff_receipt: String,
    /// The retired source process identity (never a valid successor
    /// process: a reused identity fails closed).
    pub source_process: String,
    /// The planned target-profile binding (issue #77), when the replacement
    /// was requested under an explicit profile-configuration revision. The
    /// read-back is classified against it: the intended pair verifies, an
    /// authorized fallback is reported distinctly, an unexpected pair is
    /// fenced, and an unsupported/absent introspection leaves the actual
    /// binding unknown — never a copy of the intended pair.
    pub binding: Option<crate::config::ProfileBinding>,
}

/// The closed verdict of one successor confirmation read-back. The fresh
/// successor is confirmed by the adapter-observed identity parts; a spawned
/// process alone is never enough.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SuccessorEvidence {
    /// The successor is verified: fresh session identity, role/profile/cwd,
    /// the kickoff receipt, the adapter-observed readiness and (when a
    /// target-profile binding was planned) the binding verdict all match.
    Verified {
        /// The adapter-observed backend process identity.
        process: String,
        /// The adapter-observed readiness state (`ready`).
        readiness: String,
        /// What the read-back bound (planned pair, authorized fallback, or
        /// an honest unknown — never a copy of the planned pair).
        binding: BindingObservation,
    },
    /// The evidence cannot prove the boundary yet (missing/incomplete
    /// evidence or a not-ready state): hold — nothing further is attempted
    /// and a bounded same-nonce retry may re-verify.
    Held {
        /// Bounded human detail (redacted).
        detail: String,
    },
    /// The evidence contradicts the start with a reused or wrong identity:
    /// fail closed.
    Reused {
        /// Bounded human detail (redacted).
        detail: String,
    },
}

/// The closed verdict of one successor binding observation against the
/// planned target-profile binding (issue #77). The ACTUAL binding comes from
/// authoritative adapter evidence only; when the read-back reports nothing
/// the actual stays [`BindingObservation::Unknown`] (never a copy of the
/// requested configuration).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BindingObservation {
    /// The read-back reported the planned (intended) provider/model pair.
    Matched {
        /// The reported provider.
        provider: String,
        /// The reported model.
        model: String,
    },
    /// The read-back reported an AUTHORIZED fallback pair: accepted and
    /// reported distinctly.
    Fallback {
        /// The reported fallback provider.
        provider: String,
        /// The reported fallback model.
        model: String,
    },
    /// No planned binding was reviewed, or the profile declares no binding
    /// introspection and the read-back reported nothing: the actual binding
    /// stays unknown/unverified.
    Unknown,
}

impl BindingObservation {
    /// The closed observation status (`matched` | `fallback` | `unknown`).
    pub fn status(&self) -> &'static str {
        match self {
            BindingObservation::Matched { .. } => "matched",
            BindingObservation::Fallback { .. } => "fallback",
            BindingObservation::Unknown => "unknown",
        }
    }

    /// The observed pair, if the read-back reported one.
    pub fn observed(&self) -> Option<(&str, &str)> {
        match self {
            BindingObservation::Matched { provider, model }
            | BindingObservation::Fallback { provider, model } => {
                Some((provider.as_str(), model.as_str()))
            }
            BindingObservation::Unknown => None,
        }
    }

    /// The RPC/evidence document for one observation against the planned
    /// binding (issue #77). `intended` and `actual` are ALWAYS distinct:
    /// `actual` is null when the evidence reported nothing — it is never a
    /// copy of the requested configuration. Configured limits are reported
    /// as configured limits, never as proof of provider support.
    pub fn to_doc(&self, plan: Option<&crate::config::ProfileBinding>) -> crate::value::Val {
        let intended = plan.map(|plan| {
            object(vec![
                ("provider", string(&plan.provider)),
                ("model", string(&plan.model)),
            ])
        });
        let actual = self.observed().map(|(provider, model)| {
            object(vec![
                ("provider", string(provider)),
                ("model", string(model)),
            ])
        });
        let configured_limits = plan.map(|plan| {
            object(
                plan.configured_limits
                    .iter()
                    .map(|(name, value)| (name.as_str(), string(value)))
                    .collect(),
            )
        });
        object(vec![
            ("status", string(self.status())),
            (
                "revision",
                plan.map(|plan| string(&plan.revision)).unwrap_or_else(null),
            ),
            (
                "introspection",
                plan.map(|plan| bool_(plan.introspection))
                    .unwrap_or_else(null),
            ),
            ("intended", intended.unwrap_or_else(null)),
            ("actual", actual.unwrap_or_else(null)),
            (
                "source",
                if self.observed().is_some() {
                    string("adapter")
                } else {
                    null()
                },
            ),
            ("configured_limits", configured_limits.unwrap_or_else(null)),
        ])
    }
}

/// Run the successor start row — the ONE bounded fresh-session start
/// request this slice issues: `herdr session start <session> --json` under
/// [`WORKSPACE_EXECUTABLE`] with the caller's deadline. `succeeded` means
/// the workspace accepted the start request; a `refused` result means the
/// request was never delivered, `failed`/`ambiguous` mean the delivery is
/// unknown. Nothing here replays a transcript, resets a worktree, or
/// retries: a delivery that does not confirm is parked by the caller.
pub fn successor_start(
    profile: &Profile,
    target: &SuccessorTarget,
    env: &BTreeMap<String, String>,
    timeout: Duration,
) -> OpResult {
    let started = std::time::Instant::now();
    if !profile.supports(Op::Start.capability()) {
        return successor_result(
            profile,
            target,
            Op::Start,
            "refused",
            Some(CODE_UNKNOWN_CAPABILITY),
            Some(format!(
                "harness profile {:?} does not declare the {:?} capability required to start \
                 a successor session; unsupported adapters are refused",
                profile.key,
                Op::Start.capability()
            )),
            None,
            None,
            started,
        );
    }
    let args = workspace_args(Op::Start, &target.session);
    match run_typed(WORKSPACE_EXECUTABLE, &args, timeout, env, None) {
        ProcessOutcome::Ok(text) => match Val::parse_json(&text) {
            Ok(_) => successor_result(
                profile,
                target,
                Op::Start,
                "succeeded",
                None,
                None,
                Some(object(vec![("started", bool_(true))])),
                None,
                started,
            ),
            Err(message) => successor_result(
                profile,
                target,
                Op::Start,
                "refused",
                Some(CODE_MALFORMED),
                Some("workspace start row returned unparsable JSON".to_string()),
                None,
                Some(diagnostics(&format!("{message}: {text}"))),
                started,
            ),
        },
        ProcessOutcome::Failed(err) => successor_result(
            profile,
            target,
            Op::Start,
            err.status(),
            Some(err.code),
            Some(err.message),
            None,
            Some(err.detail),
            started,
        ),
    }
}

/// Run the successor confirmation read row and classify its closed evidence
/// grammar: the workspace `session show <session> --json` row, read back
/// after the start. A failure to read (unavailable/unparsable backend) is a
/// typed adapter error — the caller holds; the classification itself
/// returns the three closed verdicts (see [`SuccessorEvidence`]).
pub fn successor_evidence(
    profile: &Profile,
    target: &SuccessorTarget,
    env: &BTreeMap<String, String>,
    timeout: Duration,
) -> Result<SuccessorEvidence, AdapterError> {
    if !profile.supports(Op::Observe.capability()) {
        return Err(AdapterError::refusal(
            CODE_UNKNOWN_CAPABILITY,
            format!(
                "harness profile {:?} does not declare the {:?} capability required to \
                 verify a successor; unsupported adapters are refused",
                profile.key,
                Op::Observe.capability()
            ),
        ));
    }
    let args = workspace_args(Op::Observe, &target.session);
    let text = match run_typed(WORKSPACE_EXECUTABLE, &args, timeout, env, None) {
        ProcessOutcome::Ok(text) => text,
        ProcessOutcome::Failed(err) => {
            let retryable = err.status() == "ambiguous";
            return Err(AdapterError::failure(err.code, err.message, retryable));
        }
    };
    let doc = Val::parse_json(&text).map_err(|message| {
        AdapterError::refusal(
            CODE_MALFORMED,
            format!("successor confirmation read-back returned unparsable JSON: {message}"),
        )
    })?;
    classify_successor_evidence(&doc, target)
}

/// Classify one successor confirmation read-back document against the bound
/// target. The closed evidence grammar is:
///
/// ```json
/// {"session_id": "<bound successor>",
///  "process": "<backend process identity>",
///  "role": "<bound role>",
///  "profile": {"key": "<bound key>", "kind": "<bound kind>"},
///  "cwd": "<bound worktree>",
///  "kickoff_receipt": "<bound 64-hex receipt>",
///  "readiness": "ready"}
/// ```
///
/// Every part is required: the read-back cannot substitute a label for the
/// identity/role/profile/cwd/kickoff/readiness evidence. Missing or
/// incomplete evidence holds; a positive contradiction (another session,
/// the retired source process answering, a wrong role/profile/worktree, or
/// a mis-echoed receipt) is a reused identity and fails closed.
pub fn classify_successor_evidence(
    doc: &Val,
    target: &SuccessorTarget,
) -> Result<SuccessorEvidence, AdapterError> {
    match doc.get("session_id").and_then(Val::as_str) {
        None => {
            return Ok(SuccessorEvidence::Held {
                detail: "the confirmation read-back carries no session identity (an unknown \
                         session identity holds)"
                    .to_string(),
            });
        }
        Some(session) if session != target.session => {
            return Ok(SuccessorEvidence::Reused {
                detail: format!(
                    "the confirmation read-back names session {session:?} for the bound \
                     successor {:?} (reused pane/session identity)",
                    target.session
                ),
            });
        }
        Some(_) => {}
    };
    let process = match doc.get("process").and_then(Val::as_str) {
        None => {
            return Ok(SuccessorEvidence::Held {
                detail: "the confirmation read-back carries no process evidence (a spawned \
                         process alone is not an adopted successor)"
                    .to_string(),
            });
        }
        Some(process) if !crate::formats::is_actor(process) => {
            return Ok(SuccessorEvidence::Held {
                detail: "the confirmation read-back process evidence is not a process identity \
                         (an unknown process identity holds)"
                    .to_string(),
            });
        }
        Some(process) if process == target.source_process => {
            return Ok(SuccessorEvidence::Reused {
                detail: format!(
                    "the retired source process {process:?} answers for the successor session \
                     {:?} (reused process identity); the successor cannot be verified",
                    target.session
                ),
            });
        }
        Some(process) => process.to_string(),
    };
    match doc.get("role").and_then(Val::as_str) {
        None => {
            return Ok(SuccessorEvidence::Held {
                detail: "the confirmation read-back carries no role evidence (an unknown role \
                         holds)"
                    .to_string(),
            });
        }
        Some(role) if role != target.role => {
            return Ok(SuccessorEvidence::Reused {
                detail: format!(
                    "the confirmation read-back runs role {role:?}, not the bound role {:?}",
                    target.role
                ),
            });
        }
        Some(_) => {}
    }
    let profile = match doc.get("profile") {
        Some(Val::Obj(map)) => map,
        _ => {
            return Ok(SuccessorEvidence::Held {
                detail: "the confirmation read-back carries no profile evidence".to_string(),
            });
        }
    };
    match (
        profile.get("key").and_then(Val::as_str),
        profile.get("kind").and_then(Val::as_str),
    ) {
        (Some(key), Some(kind)) if key == target.profile_key && kind == target.profile_kind => {}
        (Some(key), Some(kind)) => {
            return Ok(SuccessorEvidence::Reused {
                detail: format!(
                    "the confirmation read-back runs profile {key:?}/{kind:?}, not the bound \
                     profile {:?}/{:?}",
                    target.profile_key, target.profile_kind
                ),
            });
        }
        _ => {
            return Ok(SuccessorEvidence::Held {
                detail: "the profile evidence is incomplete (an unknown profile holds)".to_string(),
            });
        }
    }
    match doc.get("cwd").and_then(Val::as_str) {
        None => {
            return Ok(SuccessorEvidence::Held {
                detail: "the confirmation read-back carries no cwd evidence (an unknown \
                         worktree holds)"
                    .to_string(),
            });
        }
        Some(cwd) if cwd != target.worktree => {
            return Ok(SuccessorEvidence::Reused {
                detail: format!(
                    "the confirmation read-back runs in worktree {cwd:?}, not the SAME \
                     worktree {:?} (a successor never forks to another worktree)",
                    target.worktree
                ),
            });
        }
        Some(_) => {}
    }
    match doc.get("kickoff_receipt").and_then(Val::as_str) {
        None => {
            return Ok(SuccessorEvidence::Held {
                detail: "the confirmation read-back carries no kickoff receipt (a missing \
                         kickoff acknowledgment holds)"
                    .to_string(),
            });
        }
        Some(receipt) if receipt != target.kickoff_receipt => {
            return Ok(SuccessorEvidence::Reused {
                detail: "the confirmation read-back echoed another kickoff receipt (a stale \
                         or replayed kickoff cannot confirm a successor)"
                    .to_string(),
            });
        }
        Some(_) => {}
    }
    let readiness = match doc.get("readiness").and_then(Val::as_str) {
        None => {
            return Ok(SuccessorEvidence::Held {
                detail: "the confirmation read-back carries no readiness evidence (a spawned \
                         process alone is not an adopted successor)"
                    .to_string(),
            });
        }
        Some(readiness) => readiness.to_string(),
    };
    if readiness != "ready" {
        return Ok(SuccessorEvidence::Held {
            detail: format!(
                "the successor is observed {readiness:?}, not adapter-observed `ready`; the \
                 boundary holds until the adapter observes readiness"
            ),
        });
    }
    // Target-profile binding verdict (issue #77). The ACTUAL binding is only
    // ever what the authoritative read-back reported: the planned pair
    // verifies, an AUTHORIZED fallback is accepted and reported distinctly,
    // an unexpected pair is fenced (fail closed), and a read-back that
    // reports nothing leaves the actual unknown — or holds honestly when the
    // bound profile declares binding introspection.
    let binding = match &target.binding {
        None => BindingObservation::Unknown,
        Some(plan) => match doc.get("binding") {
            None | Some(Val::Null) => {
                if plan.introspection {
                    return Ok(SuccessorEvidence::Held {
                        detail: format!(
                            "the confirmation read-back carries no provider/model binding \
                             although the bound profile {:?} declares binding introspection; \
                             the actual binding is unverifiable at this boundary (an honest \
                             capability hold — nothing is inferred and nothing is copied from \
                             the requested configuration)",
                            plan.key
                        ),
                    });
                }
                BindingObservation::Unknown
            }
            Some(Val::Obj(map)) => {
                match (
                    map.get("provider").and_then(Val::as_str),
                    map.get("model").and_then(Val::as_str),
                ) {
                    (Some(provider), Some(model)) => {
                        if provider == plan.provider && model == plan.model {
                            BindingObservation::Matched {
                                provider: provider.to_string(),
                                model: model.to_string(),
                            }
                        } else if plan.fallbacks.iter().any(|text| {
                            crate::config::fallback_pair(text) == Some((provider, model))
                        }) {
                            BindingObservation::Fallback {
                                provider: provider.to_string(),
                                model: model.to_string(),
                            }
                        } else {
                            return Ok(SuccessorEvidence::Reused {
                                detail: format!(
                                    "the confirmation read-back reports an unexpected \
                                     provider/model binding {provider:?}/{model:?} that is \
                                     neither the planned binding {:?}/{:?} nor one of the \
                                     authorized fallbacks; the successor stays fenced",
                                    plan.provider, plan.model
                                ),
                            });
                        }
                    }
                    _ => {
                        return Ok(SuccessorEvidence::Held {
                            detail: "the confirmation read-back carries an incomplete \
                                     provider/model binding (both parts are required); an \
                                     incomplete binding holds"
                                .to_string(),
                        });
                    }
                }
            }
            Some(_) => {
                return Ok(SuccessorEvidence::Held {
                    detail: "the confirmation read-back carries malformed provider/model \
                             binding evidence; an unreadable binding holds"
                        .to_string(),
                });
            }
        },
    };
    Ok(SuccessorEvidence::Verified {
        process,
        readiness,
        binding,
    })
}

/// Build a successor result with the wall time already measured.
#[allow(clippy::too_many_arguments)]
fn successor_result(
    profile: &Profile,
    target: &SuccessorTarget,
    op: Op,
    status: &'static str,
    code: Option<&'static str>,
    message: Option<String>,
    payload: Option<Val>,
    detail: Option<String>,
    started: std::time::Instant,
) -> OpResult {
    OpResult {
        profile_key: profile.key.clone(),
        session_id: target.session.clone(),
        op,
        status,
        code,
        message: message.map(|m| redact(&m)),
        payload,
        detail: detail.map(|d| redact(&d)),
        elapsed_ms: started.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
    }
}

/// The session-state payload fields the adapter contract reads back from
/// the workspace (whitelisted; everything else in the read-back document is
/// ignored).
fn session_state_payload(doc: &Val) -> Val {
    let mut fields = vec![
        (
            "session_id",
            doc.get("session_id")
                .and_then(Val::as_str)
                .map(string)
                .unwrap_or_else(null),
        ),
        (
            "generation",
            match doc.get("generation") {
                Some(Val::Int(n)) => integer(*n),
                _ => null(),
            },
        ),
        (
            "state",
            doc.get("state")
                .and_then(Val::as_str)
                .map(string)
                .unwrap_or_else(null),
        ),
    ];
    if let Some(outcome) = doc.get("outcome").and_then(Val::as_str) {
        fields.push(("outcome", string(outcome)));
    }
    object(fields)
}

/// Compare a workspace identity read-back document against the bound
/// identity. Any mismatch is a stale identity (`refusal.stale.identity`,
/// AC3): the session no longer runs under the bound triple.
fn read_back_identity(doc: &Val, bound: &SessionHandle) -> Result<Val, StaleIdentity> {
    let read_session = doc.get("session_id").and_then(Val::as_str).unwrap_or("");
    let read_terminal = doc
        .get("terminal_session")
        .and_then(Val::as_str)
        .unwrap_or("");
    let read_generation = match doc.get("generation") {
        Some(Val::Int(n)) => Some(*n),
        _ => None,
    };
    let mut stale = Vec::new();
    if read_session != bound.identity.herdr_session {
        stale.push("herdr_session");
    }
    if read_terminal != bound.identity.terminal_session {
        stale.push("terminal_session");
    }
    if read_generation != Some(bound.identity.generation as i64) {
        stale.push("generation");
    }
    if !stale.is_empty() {
        return Err(StaleIdentity {
            code: CODE_STALE_IDENTITY,
            message: format!("identity read-back mismatch on {}", stale.join(", ")),
            detail: format!(
                "bound={}/{} gen={}",
                bound.identity.herdr_session,
                bound.identity.terminal_session,
                bound.identity.generation
            ),
        });
    }
    Ok(object(vec![
        ("herdr_session", string(&bound.identity.herdr_session)),
        ("terminal_session", string(&bound.identity.terminal_session)),
        ("generation", integer(bound.identity.generation as i64)),
    ]))
}

/// A stale-identity failure carrying a redacted detail line.
#[derive(Debug)]
struct StaleIdentity {
    code: &'static str,
    message: String,
    detail: String,
}

/// Classified child outcome after a typed invocation.
enum ProcessOutcome {
    /// The child exited zero and its output was accepted.
    Ok(String),
    /// The child failed in a classified way.
    Failed(ProcessFailure),
}

/// A classified failure of one typed invocation.
struct ProcessFailure {
    code: &'static str,
    message: String,
    detail: String,
}

impl ProcessFailure {
    /// `hf-outcome/v1` status for the failure class: typed refusals are
    /// `refused`; interruption/timeout/process death are `ambiguous`
    /// (spec-plans.md §5: ambiguous = interrupted/restored work); ordinary
    /// exits are `failed`.
    fn status(&self) -> &'static str {
        if self.code.starts_with("refusal.") || self.code.starts_with("unknown.") {
            "refused"
        } else if matches!(self.code, CODE_TIMEOUT | CODE_PROCESS_DEATH) {
            "ambiguous"
        } else {
            "failed"
        }
    }
}

/// Run one bounded, allowlisted invocation and classify the outcome
/// (typed exits, auth markers, timeout, process death; output capped and
/// redacted at this boundary).
fn run_typed(
    program: &str,
    args: &[String],
    timeout: Duration,
    env: &BTreeMap<String, String>,
    cwd: Option<&Path>,
) -> ProcessOutcome {
    run_typed_with(program, args, timeout, env, cwd, false)
}

/// Issue #92 round 4 (blast radius): the group runner is for the effect-class
/// harness invocations only — the prompt row and a declared start row. Their
/// child leads its own process group and a deadline reaps the group. Every
/// other adapter operation (the workspace protocol rows) keeps the
/// pre-existing spawn path, byte for byte.
fn run_typed_grouped(
    program: &str,
    args: &[String],
    timeout: Duration,
    env: &BTreeMap<String, String>,
    cwd: Option<&Path>,
) -> ProcessOutcome {
    run_typed_with(program, args, timeout, env, cwd, true)
}

fn run_typed_with(
    program: &str,
    args: &[String],
    timeout: Duration,
    env: &BTreeMap<String, String>,
    cwd: Option<&Path>,
    grouped: bool,
) -> ProcessOutcome {
    let resolved = match resolve_executable(program, env) {
        Ok(path) => path,
        Err(err) => {
            return ProcessOutcome::Failed(ProcessFailure {
                code: err.code,
                message: err.message,
                detail: format!("while resolving {program:?}"),
            });
        }
    };
    let spec = ProcSpec {
        program: resolved.to_str().unwrap_or_default(),
        args,
        env,
        cwd,
        timeout,
    };
    let out = if grouped {
        run_grouped(spec)
    } else {
        run(spec)
    };
    match out.status {
        ProcStatus::Exit(0) => {
            let text = redact(&out.stdout);
            ProcessOutcome::Ok(cap_text(&text))
        }
        ProcStatus::Exit(code) => {
            if code == -1 {
                return ProcessOutcome::Failed(ProcessFailure {
                    code: CODE_PROCESS_DEATH,
                    message: "the harness process died without a terminal outcome".to_string(),
                    detail: diagnostics(&format!("{}{}", out.stderr, out.stdout)),
                });
            }
            let combined = format!("{}{}", out.stdout, out.stderr);
            let lower = combined.to_ascii_lowercase();
            if AUTH_MARKERS.iter().any(|marker| lower.contains(marker)) {
                ProcessOutcome::Failed(ProcessFailure {
                    code: CODE_CREDENTIALS,
                    message: "the harness reported an authentication failure; credentials live in the harness, never here".to_string(),
                    detail: diagnostics(&combined),
                })
            } else {
                ProcessOutcome::Failed(ProcessFailure {
                    code: CODE_EXIT,
                    message: format!("the harness exited with code {code}"),
                    detail: diagnostics(&combined),
                })
            }
        }
        ProcStatus::TimedOut => ProcessOutcome::Failed(ProcessFailure {
            code: CODE_TIMEOUT,
            message: "the operation exceeded its deadline and was cancelled".to_string(),
            detail: {
                // Issue #92 round 2: a group signal that could not be
                // delivered rides on the captured stderr, so the failure
                // detail names it instead of hiding it.
                let reason = diagnostics(&out.stderr);
                if reason.is_empty() {
                    format!("deadline {timeout:?}")
                } else {
                    format!("deadline {timeout:?} | {reason}")
                }
            },
        }),
        ProcStatus::SpawnFailed(message) => ProcessOutcome::Failed(ProcessFailure {
            code: CODE_UNAVAILABLE,
            message: format!("could not spawn {program:?}: {message}"),
            // The OS error rides in the detail too: the round-3 Linux log
            // named only the site, and the cause was unrecoverable from it.
            detail: format!("while spawning {program:?}: {message}"),
        }),
    }
}

/// Conservative closed markers that turn an already-failed invocation into
/// a `refusal.credentials` typed refusal. This is failure-shape
/// classification of nonzero exits only — never capability inference from
/// prose (ADR-0003), and the matched text never becomes a record.
/// `no api key found` is the measured missing-credentials stderr of pi
/// v0.85.1 (2026-09-08); `api_key not found in environment` is the
/// measured missing-credentials stderr of jcode v0.84.0 (2026-09-08:
/// `Error: DEEPSEEK_API_KEY not found in environment or
/// <home>/.config/jcode/deepseek.env`, exit 1).
const AUTH_MARKERS: [&str; 10] = [
    "authentication failed",
    "not authenticated",
    "not logged in",
    "unauthorized",
    "authentication required",
    "login required",
    "auth required",
    "api key required",
    "no api key found",
    "api_key not found in environment",
];

/// Build a result with the wall-time already measured.
#[allow(clippy::too_many_arguments)]
fn op_result(
    profile: &Profile,
    request: &OpRequest<'_>,
    status: &'static str,
    code: Option<&'static str>,
    message: Option<String>,
    payload: Option<Val>,
    detail: Option<String>,
    started: std::time::Instant,
) -> OpResult {
    OpResult {
        profile_key: profile.key.clone(),
        session_id: request.session.session_id.clone(),
        op: request.op,
        status,
        code,
        message: message.map(|m| redact(&m)),
        payload,
        detail: detail.map(|d| redact(&d)),
        elapsed_ms: started.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
    }
}

/// Cap captured output on a char boundary and redact (redaction happens
/// first so the byte cap never splits a redaction marker).
fn cap_text(text: &str) -> String {
    if text.len() <= OUTPUT_CAP {
        return text.to_string();
    }
    let mut end = OUTPUT_CAP;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_string()
}

/// Bounded, redacted diagnostics text for failure detail fields.
fn diagnostics(text: &str) -> String {
    let redacted = redact(text);
    let mut lines = redacted.lines().map(str::trim).filter(|l| !l.is_empty());
    let mut out = String::new();
    for line in lines.by_ref().take(2) {
        if !out.is_empty() {
            out.push_str(" | ");
        }
        out.push_str(line);
        if out.len() >= DIAGNOSTIC_CAP {
            break;
        }
    }
    if out.len() > DIAGNOSTIC_CAP {
        let mut end = DIAGNOSTIC_CAP;
        while end > 0 && !out.is_char_boundary(end) {
            end -= 1;
        }
        out.truncate(end);
    }
    out
}

/// The parsed jcode `--json` envelope (issues #37/#80): the transcript
/// text plus the identity the harness actually used. `provider`/`model`
/// are `None` when the envelope does not carry them — the returned
/// identity is never inferred from, or coerced to, the requested binding.
#[derive(Clone, Debug, PartialEq, Eq)]
struct JcodeEnvelope {
    /// The model's final answer (the `text` field).
    text: String,
    /// The provider the harness reports having used.
    provider: Option<String>,
    /// The model the harness reports having used.
    model: Option<String>,
}

/// Parse the jcode `--json` envelope (issue #37). jcode's `run --json` row
/// prints one JSON object on stdout whose `text` field carries the model's
/// final answer (shape verified against jcode v0.84.0 on 2026-09-08); the
/// same object carries the returned `provider`/`model` (issue #80). `None`
/// when stdout is not such an envelope — the raw stdout is kept as the
/// transcript instead, so a non-envelope output never loses content.
fn jcode_envelope(stdout: &str) -> Option<JcodeEnvelope> {
    let doc = Val::parse_json(stdout).ok()?;
    let text = doc.get("text").and_then(Val::as_str)?;
    Some(JcodeEnvelope {
        text: text.to_string(),
        provider: doc
            .get("provider")
            .and_then(Val::as_str)
            .map(str::to_string),
        model: doc.get("model").and_then(Val::as_str).map(str::to_string),
    })
}

/// The success payload of the prompt operation. For jcode (whose `--json`
/// row emits an envelope) the payload carries the transcript plus the
/// requested/returned identity pair (issue #80); for every other kind it
/// is the transcript alone.
fn prompt_result_payload(profile: &Profile, text: String) -> Val {
    // jcode's `--json` row makes the real binary emit a machine-readable
    // envelope on stdout; parse the transcript and the returned identity
    // out of it when the output has that shape (issues #37/#80; shape
    // verified against jcode v0.84.0 on 2026-09-08). Anything else is kept
    // as raw stdout so a non-envelope output never loses the transcript.
    let envelope = if profile.kind == HarnessKind::Jcode {
        jcode_envelope(&text)
    } else {
        None
    };
    let transcript = envelope
        .as_ref()
        .map(|envelope| envelope.text.clone())
        .unwrap_or(text);
    let mut fields = vec![("transcript", string(&transcript))];
    if profile.kind == HarnessKind::Jcode {
        // Requested-versus-returned identity is observable and never
        // silently coerced (issue #80): the requested pair is the profile
        // binding; the returned pair is exactly what the envelope reported
        // (`null` when it reported no identity).
        if let (Some(provider), Some(model)) =
            (profile.provider.as_deref(), profile.model.as_deref())
        {
            fields.push((
                "requested",
                object(vec![
                    ("provider", string(provider)),
                    ("model", string(model)),
                ]),
            ));
        }
        fields.push((
            "returned",
            envelope
                .as_ref()
                .map(|envelope| {
                    object(vec![
                        (
                            "provider",
                            envelope
                                .provider
                                .as_deref()
                                .map(string)
                                .unwrap_or_else(null),
                        ),
                        (
                            "model",
                            envelope.model.as_deref().map(string).unwrap_or_else(null),
                        ),
                    ])
                })
                .unwrap_or_else(null),
        ));
    }
    object(fields)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::validate_bytes;

    fn env_with_path(paths: &[&str]) -> BTreeMap<String, String> {
        let mut env = BTreeMap::new();
        env.insert("PATH".to_string(), paths.join(":"));
        env
    }

    fn sample_identity() -> AgentIdentity {
        bind_identity("ws-session-7", "tty-7-main", 3).expect("bound")
    }

    fn sample_session() -> SessionHandle {
        new_session("sess-20260906-0001", sample_identity()).expect("session")
    }

    #[test]
    fn closed_kind_set_and_official_metadata_are_consistent() {
        assert_eq!(HarnessKind::OFFICIAL.len(), 5);
        for kind in HarnessKind::OFFICIAL {
            assert_eq!(HarnessKind::parse(kind.name()), Some(kind));
            let spec = official_spec(kind).expect("official spec");
            assert_eq!(spec.kind, kind);
            assert!(is_actor(spec.actor));
            assert!(spec.range.accepts(spec.range.current));
            assert!(!spec.capabilities.is_empty());
            for cap in spec.capabilities {
                assert!(HARNESS_CAPS.contains(cap));
            }
        }
        assert_eq!(HarnessKind::parse("teleport"), None);
        assert_eq!(HarnessKind::parse("OpenCode"), None);
        assert_eq!(HarnessKind::parse("jcode"), Some(HarnessKind::Jcode));
        assert_eq!(HarnessKind::parse("argv"), Some(HarnessKind::Argv));
    }

    #[test]
    fn official_declarations_validate_and_declare_the_closed_sets() {
        for kind in HarnessKind::OFFICIAL {
            let profile = Profile::official(kind, kind.name()).expect("profile");
            let doc = profile.declaration_doc().expect("declaration");
            let verdict = validate_doc(Family::Capability, &doc);
            assert!(verdict.is_accepted(), "{}", verdict.message());
            let caps = doc
                .get("capabilities")
                .and_then(|c| c.as_array())
                .map(|items| items.len())
                .unwrap_or(0);
            assert_eq!(caps, HARNESS_CAPS.len());
        }
    }

    #[test]
    fn argv_profile_requires_explicit_closed_capabilities() {
        let empty = Profile::argv("cli", "hf-cli", &[], BTreeMap::new());
        assert_eq!(empty.err().map(|e| e.code), Some(CODE_UNKNOWN_CAPABILITY));
        let teleport = Profile::argv("cli", "hf-cli", &["teleport"], BTreeMap::new());
        assert_eq!(
            teleport.err().map(|e| e.code),
            Some(CODE_UNKNOWN_CAPABILITY)
        );
        let path_exe = Profile::argv("cli", "/abs/path", &["prompt"], BTreeMap::new());
        assert_eq!(path_exe.err().map(|e| e.code), Some(CODE_BAD_REQUEST));
        let mut ops = BTreeMap::new();
        ops.insert("prompt".to_string(), vec!["-p".to_string()]);
        let profile = Profile::argv("cli", "hf-cli", &["start", "prompt"], ops).expect("profile");
        assert!(profile.supports("start"));
        assert!(profile.supports("prompt"));
        assert!(!profile.supports("observe"));
        let doc = profile.declaration_doc().expect("declaration");
        assert!(validate_doc(Family::Capability, &doc).is_accepted());
    }

    #[test]
    fn config_profiles_parse_official_kinds_and_refuse_unknown_ones() {
        let harness = crate::config::Harness {
            key: "codex-a".to_string(),
            kind: "codex".to_string(),
            executable: "codex".to_string(),
            env_allow: vec!["PATH".to_string()],
            provider: None,
            model: None,
            fallback: vec![],
            secret_env: vec![],
            limits: vec![],
            binding_introspection: false,
        };
        let profile = Profile::from_config(&harness).expect("profile");
        assert_eq!(profile.kind, HarnessKind::Codex);
        assert!(profile.supports("prompt"));
        assert_eq!(profile.actor, "codex");

        let unknown = crate::config::Harness {
            key: "wat".to_string(),
            kind: "teleport".to_string(),
            executable: "wat".to_string(),
            env_allow: vec![],
            provider: None,
            model: None,
            fallback: vec![],
            secret_env: vec![],
            limits: vec![],
            binding_introspection: false,
        };
        let err = Profile::from_config(&unknown).expect_err("refused");
        assert_eq!(err.code, CODE_UNKNOWN_HARNESS);

        let argv = crate::config::Harness {
            key: "cli".to_string(),
            kind: "argv".to_string(),
            executable: "hf-cli".to_string(),
            env_allow: vec!["PATH".to_string()],
            provider: None,
            model: None,
            fallback: vec![],
            secret_env: vec![],
            limits: vec![],
            binding_introspection: false,
        };
        let profile = Profile::from_config(&argv).expect("profile");
        assert_eq!(profile.kind, HarnessKind::Argv);
        assert!(
            !profile.supports("prompt"),
            "config v1 declares no argv capabilities"
        );
    }

    #[test]
    fn bind_identity_requires_all_three_parts_and_labels_cannot_substitute() {
        let ok = bind_identity("ws-1", "tty-1", 0).expect("bound");
        assert_eq!(ok.generation, 0);
        for (session, terminal) in [
            ("", "tty-1"),
            ("ws-1", ""),
            ("bad id/with slash", "tty-1"),
            ("ws-1", "not a tty id either!"),
        ] {
            let err = bind_identity(session, terminal, 0).expect_err("refused");
            assert_eq!(err.code, CODE_INCOMPLETE_IDENTITY);
        }
        let missing_session = bind_identity("", "tty-1", 3);
        assert_eq!(
            missing_session.err().map(|e| e.code),
            Some(CODE_INCOMPLETE_IDENTITY)
        );
        let missing_terminal = bind_identity("ws-1", "", 3);
        assert_eq!(
            missing_terminal.err().map(|e| e.code),
            Some(CODE_INCOMPLETE_IDENTITY)
        );
        // A mutable pane label is not an accepted part anywhere: the type
        // has exactly three fields and no label constructor exists, so a
        // label-only identity cannot be expressed.
        let identity = ok;
        assert_eq!(identity.herdr_session, "ws-1");
        assert_eq!(identity.terminal_session, "tty-1");
        assert_eq!(identity.generation, 0);
    }

    #[test]
    fn version_ranges_accept_at_and_above_minimum() {
        let range = VersionRange {
            minimum: (2, 1, 263),
            current: (2, 1, 263),
        };
        assert!(range.accepts((2, 1, 263)));
        assert!(range.accepts((2, 1, 300)));
        assert!(!range.accepts((2, 1, 262)));
        assert!(!range.accepts((1, 0, 0)));
    }

    #[test]
    fn resolve_executable_uses_the_allowlisted_path_only() {
        let env = env_with_path(&["/definitely/not/a/real/dir"]);
        let err = resolve_executable("hermes", &env).expect_err("absent");
        assert_eq!(err.code, CODE_UNAVAILABLE);
        assert!(err.message.contains("not found"));
        let no_path = BTreeMap::new();
        let err = resolve_executable("hermes", &no_path).expect_err("no PATH");
        assert_eq!(err.code, CODE_UNAVAILABLE);
        let slashed = resolve_executable("/etc/hosts", &env);
        assert_eq!(slashed.err().map(|e| e.code), Some(CODE_BAD_REQUEST));
    }

    /// Issue #144 item 1: a row whose stdout is not a JSON document refuses
    /// NAMING the exact argv and CARRYING the raw stdout it printed —
    /// bounded, single-line, with the true size named when truncated.
    #[test]
    fn a_herdr_row_refusal_names_its_argv_and_carries_the_bounded_stdout() {
        let argv = ["pane", "list", "--workspace", "w1"]
            .iter()
            .map(|part| part.to_string())
            .collect::<Vec<String>>();
        let failure = herdr_row_refusal(&argv, "not json", "expected a value at byte 0");
        assert_eq!(failure.code, CODE_MALFORMED);
        assert!(
            failure.message.contains("herdr pane list --workspace w1"),
            "the refusal names the exact argv: {}",
            failure.message
        );
        assert!(
            failure
                .detail
                .contains("argv: herdr pane list --workspace w1"),
            "the detail carries the argv: {}",
            failure.detail
        );
        assert!(
            failure.detail.contains("stdout (8 bytes): not json"),
            "the detail carries the raw stdout and its size: {}",
            failure.detail
        );

        // A long multi-line payload is truncated with its full size named and
        // stays ONE diagnosable line (the argv line stays whole).
        let long = format!("first line\n{}", "x".repeat(HERDR_RAW_CAP * 2));
        let failure = herdr_row_refusal(&argv, &long, "trailing content at byte 0");
        assert_eq!(failure.detail.lines().count(), 2, "{}", failure.detail);
        let stdout_line = failure
            .detail
            .lines()
            .find(|line| line.starts_with("stdout ("))
            .expect("the stdout line");
        assert!(
            stdout_line.len() < HERDR_RAW_CAP + 64,
            "the carried stdout is bounded: {stdout_line}"
        );
        assert!(
            stdout_line.contains("bytes total"),
            "truncation names the full size: {stdout_line}"
        );
        assert!(
            stdout_line.contains("first line\\n"),
            "the newline is escaped, never a second line: {stdout_line}"
        );
        assert!(
            failure.detail.contains(&format!("({} bytes)", long.len())),
            "the true stdout size is carried: {}",
            failure.detail
        );
    }

    #[test]
    fn start_op_binds_and_reports_the_session_without_a_subprocess() {
        // Issue #139: this unit test pins the BARE-SUBPROCESS bind row (no
        // child is spawned for an official kind's headless start), so it
        // selects that substrate explicitly. The pane substrate's bind is
        // covered end-to-end in `tests/herdr_pane_execution.rs`.
        let profile = Profile::official(HarnessKind::Hermes, "h1")
            .expect("profile")
            .with_execution(ExecutionMode::Headless);
        let session = sample_session();
        let request = OpRequest {
            op: Op::Start,
            session: &session,
            payload: None,
            timeout: Duration::from_secs(1),
        };
        let result = execute_op(&profile, &request, &BTreeMap::new());
        assert_eq!(result.status, "succeeded");
        assert_eq!(result.elapsed_ms, 0);
        let doc = result.to_outcome_doc(
            "hf_plan_0123456789abcdef",
            "p3",
            "ik_apply-20260906-0001",
            "2026-09-06T00:00:00Z",
        );
        let bytes = crate::canonical::canonical_bytes(&doc);
        let verdict = validate_bytes(Family::Outcome, &bytes);
        assert!(verdict.is_accepted(), "{}", verdict.message());
    }

    #[test]
    fn declined_capabilities_refuse_without_running_anything() {
        // A config-declared argv profile declares no capabilities: every
        // operation is a typed refusal, not a subprocess attempt.
        let harness = crate::config::Harness {
            key: "cli".to_string(),
            kind: "argv".to_string(),
            executable: "hf-cli".to_string(),
            env_allow: vec![],
            provider: None,
            model: None,
            fallback: vec![],
            secret_env: vec![],
            limits: vec![],
            binding_introspection: false,
        };
        let profile = Profile::from_config(&harness).expect("profile");
        let session = sample_session();
        let request = OpRequest {
            op: Op::Prompt,
            session: &session,
            payload: Some("do the thing"),
            timeout: Duration::from_secs(1),
        };
        let result = execute_op(&profile, &request, &BTreeMap::new());
        assert_eq!(result.status, "refused");
        assert_eq!(result.code, Some(CODE_UNKNOWN_CAPABILITY));
    }

    #[test]
    fn payload_is_only_valid_on_prompt_and_prompt_requires_payload() {
        let profile = Profile::official(HarnessKind::Codex, "c1").expect("profile");
        let session = sample_session();
        let with_payload = OpRequest {
            op: Op::Observe,
            session: &session,
            payload: Some("nope"),
            timeout: Duration::from_secs(1),
        };
        let result = execute_op(&profile, &with_payload, &BTreeMap::new());
        assert_eq!(result.code, Some(CODE_BAD_REQUEST));
        let no_payload = OpRequest {
            op: Op::Prompt,
            session: &session,
            payload: None,
            timeout: Duration::from_secs(1),
        };
        let result = execute_op(&profile, &no_payload, &BTreeMap::new());
        assert_eq!(result.code, Some(CODE_BAD_REQUEST));
    }

    #[test]
    fn unknown_op_names_are_refused_at_the_named_boundary() {
        let profile = Profile::official(HarnessKind::Hermes, "h1").expect("profile");
        let session = sample_session();
        let result = execute_named(
            &profile,
            "teleport",
            &session,
            None,
            Duration::from_secs(1),
            &BTreeMap::new(),
        );
        assert_eq!(result.status, "refused");
        assert_eq!(result.code, Some(CODE_UNKNOWN_CAPABILITY));
        assert!(result.message.unwrap().contains("teleport"));
    }

    #[test]
    fn error_docs_validate_against_the_error_family() {
        for err in [
            AdapterError::refusal(CODE_UNKNOWN_HARNESS, "unknown kind"),
            AdapterError::refusal(CODE_STALE_IDENTITY, "stale"),
            AdapterError::failure(CODE_TIMEOUT, "timeout", true),
        ] {
            let doc = err.to_error_doc();
            let bytes = crate::canonical::canonical_bytes(&doc);
            let verdict = validate_bytes(Family::Error, &bytes);
            assert!(verdict.is_accepted(), "{}", verdict.message());
            assert!(matches!(doc.get("code"), Some(Val::Str(c)) if c == err.code));
        }
    }

    #[test]
    fn read_back_detects_each_stale_identity_part() {
        // identity read-back compares the workspace doc against the bound
        // triple; here the workspace is emulated by a doc (the subprocess
        // path is covered in tests/harness_adapters.rs).
        let identity = bind_identity("ws-7", "tty-7", 3).expect("bound");
        let session = new_session("sess-1", identity).expect("session");
        let doc = object(vec![
            ("session_id", string("ws-7")),
            ("terminal_session", string("tty-7")),
            ("generation", integer(3)),
            ("state", string("running")),
        ]);
        let read = read_back_identity(&doc, &session).expect("matches");
        assert_eq!(read.get("generation"), Some(&Val::Int(3)));

        for (field, doc) in [
            (
                "herdr_session",
                object(vec![
                    ("session_id", string("ws-OTHER")),
                    ("terminal_session", string("tty-7")),
                    ("generation", integer(3)),
                ]),
            ),
            (
                "terminal_session",
                object(vec![
                    ("session_id", string("ws-7")),
                    ("terminal_session", string("tty-OTHER")),
                    ("generation", integer(3)),
                ]),
            ),
            (
                "generation",
                object(vec![
                    ("session_id", string("ws-7")),
                    ("terminal_session", string("tty-7")),
                    ("generation", integer(4)),
                ]),
            ),
        ] {
            let err = read_back_identity(&doc, &session).expect_err("stale");
            assert_eq!(err.code, CODE_STALE_IDENTITY);
            assert!(err.message.contains(field), "{} names {field}", err.message);
        }
    }

    #[test]
    fn jcode_envelope_extracts_the_transcript_and_the_returned_identity() {
        // The measured jcode v0.84.0 `--json` envelope shape (2026-09-08):
        // one top-level object whose `text` field carries the final answer
        // and whose `provider`/`model` fields carry the identity the
        // harness actually used (issue #80).
        let envelope = r#"{
  "session_id": "session_kangaroo_1788883711941_a3cc1cf55178c963",
  "provider": "example-provider",
  "model": "example-model",
  "text": "implemented the ini parser; 12 tests pass",
  "usage": {"input_tokens": 123, "output_tokens": 45,
            "cache_read_input_tokens": null, "cache_creation_input_tokens": null}
}"#;
        let parsed = jcode_envelope(envelope).expect("envelope");
        assert_eq!(parsed.text, "implemented the ini parser; 12 tests pass");
        assert_eq!(parsed.provider.as_deref(), Some("example-provider"));
        assert_eq!(parsed.model.as_deref(), Some("example-model"));
        // An envelope without identity fields keeps them absent — the
        // returned identity is never inferred from the requested binding.
        let bare = jcode_envelope(r#"{"text":"no identity reported"}"#).expect("envelope");
        assert_eq!(bare.text, "no identity reported");
        assert_eq!(bare.provider, None);
        assert_eq!(bare.model, None);
        // Non-envelope stdout (plain text) and JSON without `text` fall
        // back to raw stdout (never lose the transcript).
        assert_eq!(jcode_envelope("plain model output"), None);
        assert_eq!(jcode_envelope(r#"{"session_id":"s1"}"#), None);
        assert_eq!(jcode_envelope(""), None);
    }

    #[test]
    fn prompt_rows_consume_the_declared_binding_and_refuse_without_one() {
        // AC1/AC3 (issue #80): the Pi/Jcode rows build the pair from the
        // profile binding; no binding is a typed refusal, never a literal.
        let pi = Profile::official(HarnessKind::Pi, "pi")
            .expect("profile")
            .with_binding("example-provider", "example-model")
            .expect("binding");
        assert_eq!(
            prompt_args(&pi, "sess-test").expect("args"),
            vec![
                "--provider".to_string(),
                "example-provider".to_string(),
                "--model".to_string(),
                "example-model".to_string(),
                "--print".to_string(),
                "--".to_string(),
            ]
        );
        let jcode = Profile::official(HarnessKind::Jcode, "jcode")
            .expect("profile")
            .with_binding("example-provider", "example-model")
            .expect("binding");
        assert_eq!(
            prompt_args(&jcode, "sess-test").expect("args"),
            vec![
                "run".to_string(),
                "--provider".to_string(),
                "example-provider".to_string(),
                "--model".to_string(),
                "example-model".to_string(),
                "--json".to_string(),
                "--".to_string(),
            ]
        );
        for kind in [HarnessKind::Pi, HarnessKind::Jcode] {
            let bare = Profile::official(kind, kind.name()).expect("profile");
            let err = prompt_args(&bare, "sess-test").expect_err("unbound prompt refused");
            assert_eq!(err.code, CODE_BINDING, "{}", kind.name());
            assert!(!err.retryable);
        }
        // Binding tokens are validated at construction: never paths, never
        // shell-shaped text, never blank.
        for (provider, model) in [
            ("provider/../x", "example-model"),
            ("example-provider", "  "),
            ("", "example-model"),
        ] {
            let err = Profile::official(HarnessKind::Pi, "pi")
                .expect("profile")
                .with_binding(provider, model)
                .expect_err("invalid binding refused");
            assert_eq!(err.code, CODE_BAD_REQUEST, "{provider:?}");
        }
    }

    #[test]
    fn config_binding_is_carried_and_a_half_pair_is_refused() {
        let harness = crate::config::Harness {
            key: "pi-a".to_string(),
            kind: "pi".to_string(),
            executable: "pi".to_string(),
            env_allow: vec!["PATH".to_string()],
            provider: Some("example-provider".to_string()),
            model: Some("example-model".to_string()),
            fallback: vec![],
            secret_env: vec![],
            limits: vec![],
            binding_introspection: false,
        };
        let profile = Profile::from_config(&harness).expect("profile");
        assert_eq!(profile.provider.as_deref(), Some("example-provider"));
        assert_eq!(profile.model.as_deref(), Some("example-model"));

        let half = crate::config::Harness {
            key: "pi-b".to_string(),
            kind: "pi".to_string(),
            executable: "pi".to_string(),
            env_allow: vec!["PATH".to_string()],
            provider: Some("example-provider".to_string()),
            model: None,
            fallback: vec![],
            secret_env: vec![],
            limits: vec![],
            binding_introspection: false,
        };
        let err = Profile::from_config(&half).expect_err("half pair refused");
        assert_eq!(err.code, CODE_BAD_REQUEST);
    }

    #[test]
    fn herdr_pane_context_requires_herdr_env_and_pane_id() {
        let mut env = BTreeMap::new();
        env.insert("PATH".to_string(), "/bin".to_string());
        assert_eq!(herdr_pane_context(&env), None, "no herdr markers");
        env.insert("HERDR_ENV".to_string(), "1".to_string());
        assert_eq!(herdr_pane_context(&env), None, "env without pane id");
        env.insert("HERDR_PANE_ID".to_string(), "w1:p2".to_string());
        assert_eq!(herdr_pane_context(&env), Some("w1:p2"));
        env.insert("HERDR_ENV".to_string(), "0".to_string());
        assert_eq!(herdr_pane_context(&env), None, "HERDR_ENV=0 is not a pane");
        env.insert("HERDR_ENV".to_string(), "1".to_string());
        env.insert("HERDR_PANE_ID".to_string(), "".to_string());
        assert_eq!(herdr_pane_context(&env), None, "empty pane id");
    }

    #[test]
    fn herdr_lifecycle_report_maps_typed_results_to_semantic_states() {
        let profile = Profile::official(HarnessKind::Pi, "pi").expect("profile");
        let session = sample_session();
        let started = std::time::Instant::now();
        let result_for = |op: Op, status: &'static str, code: Option<&'static str>| -> OpResult {
            op_result(
                &profile,
                &OpRequest {
                    op,
                    session: &session,
                    payload: if op == Op::Prompt { Some("x") } else { None },
                    timeout: Duration::from_secs(1),
                },
                status,
                code,
                None,
                None,
                None,
                started,
            )
        };
        // start succeeded -> working; terminal prompts -> idle except
        // credentials / missing provider-model binding -> blocked;
        // workspace ops -> no report.
        assert_eq!(
            herdr_lifecycle_report(&result_for(Op::Start, "succeeded", None)),
            Some(("working", None))
        );
        assert_eq!(
            herdr_lifecycle_report(&result_for(Op::Start, "refused", Some(CODE_BAD_REQUEST))),
            None
        );
        assert_eq!(
            herdr_lifecycle_report(&result_for(Op::Prompt, "succeeded", None)),
            Some(("idle", None))
        );
        assert_eq!(
            herdr_lifecycle_report(&result_for(Op::Prompt, "ambiguous", Some(CODE_TIMEOUT))),
            Some(("idle", None))
        );
        assert_eq!(
            herdr_lifecycle_report(&result_for(Op::Prompt, "refused", Some(CODE_CREDENTIALS))),
            Some(("blocked", Some("harness credentials required")))
        );
        assert_eq!(
            herdr_lifecycle_report(&result_for(Op::Prompt, "refused", Some(CODE_BINDING))),
            Some(("blocked", Some("harness provider/model binding required")))
        );
        assert_eq!(
            herdr_lifecycle_report(&result_for(Op::Prompt, "failed", Some(CODE_EXIT))),
            Some(("idle", None))
        );
        assert_eq!(
            herdr_lifecycle_report(&result_for(Op::Outcome, "succeeded", None)),
            None
        );
        assert_eq!(
            herdr_lifecycle_report(&result_for(Op::Identity, "succeeded", None)),
            None
        );
    }

    /// A temporary bin directory holding one fake `herdr` workspace
    /// executable; removed on drop. The body is trusted test code (never
    /// untrusted payload text).
    struct FakeWorkspace {
        dir: PathBuf,
    }

    impl FakeWorkspace {
        fn new(name: &str, body: &str) -> FakeWorkspace {
            let dir = std::env::temp_dir().join(format!("hf-ws-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("create fake bin dir");
            let path = dir.join(WORKSPACE_EXECUTABLE);
            // The allowlisted environment carries only the fake bin dir on
            // PATH, so the script sets its own utility PATH explicitly
            // (shell builtins alone cannot wait).
            std::fs::write(&path, format!("#!/bin/sh\nPATH=/usr/bin:/bin\n{body}\n"))
                .expect("write fake executable");
            let mut permissions = std::fs::metadata(&path).expect("metadata").permissions();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                permissions.set_mode(0o755);
            }
            std::fs::set_permissions(&path, permissions).expect("chmod");
            FakeWorkspace { dir }
        }

        fn env(&self) -> BTreeMap<String, String> {
            env_with_path(&[self.dir.to_str().expect("utf-8 path")])
        }
    }

    impl Drop for FakeWorkspace {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn retirement_target() -> RetirementTarget {
        RetirementTarget {
            session: "sess-0001".to_string(),
            process: "proc-0001".to_string(),
        }
    }

    fn evidence_doc(json: &str) -> Val {
        Val::parse_json(json).expect("evidence doc")
    }

    #[test]
    fn the_workspace_protocol_rows_keep_the_pre_existing_spawn_path() {
        // Issue #92 round 4: the group runner (own process group, group reap)
        // is for the effect-class harness invocations only. A workspace
        // protocol row must spawn exactly as it did before the group runner
        // existed — the child inherits the runner's process group. Hosted CI
        // caught the opposite on a loaded Linux runner at the test below, so
        // this pin lives beside it.
        let fake = FakeWorkspace::new(
            "group-shape",
            "pg=$(ps -o pgid= -p $$ | tr -d ' ')\n\
             if [ \"$pg\" = \"$$\" ]; then echo self > \"$(dirname \"$0\")/group-shape.txt\"; \
             else echo inherited > \"$(dirname \"$0\")/group-shape.txt\"; fi\n\
             echo '{\"interrupted\":true}'",
        );
        let target = retirement_target();
        let profile = Profile::official(HarnessKind::Pi, "pi").expect("profile");
        let result = retirement_stop(&profile, &target, &fake.env(), ADAPTER_TIMEOUT);

        assert_eq!(result.status, "succeeded", "{:?}", result.detail);
        let shape = std::fs::read_to_string(fake.dir.join("group-shape.txt")).unwrap_or_default();
        assert_eq!(
            shape.trim(),
            "inherited",
            "a workspace protocol row must keep the pre-existing spawn path"
        );
    }

    #[test]
    fn a_failed_group_reap_attempt_is_reported_not_discarded() {
        // A NUL in the executable name prevents launch on every platform;
        // no kill runs, and no platform-specific exit status is the oracle.
        let candidates = ["invalid\0kill-helper"];
        let signal = helper_attempt(&candidates, &["-9", "-7"], "group signal");
        assert!(
            signal
                .as_deref()
                .is_some_and(|reason| reason.contains("group signal")),
            "the unlaunchable helper must report its failure: {signal:?}"
        );
        assert_eq!(
            signal_group_with(&candidates, 7),
            signal,
            "the group-signal wrapper must preserve the failure unchanged"
        );

        let kill = helper_attempt(&candidates, &["-9", "7"], "reap");
        assert!(
            kill.as_deref()
                .is_some_and(|reason| reason.contains("reap")),
            "the unlaunchable helper must report its failure: {kill:?}"
        );
        assert_eq!(
            kill_pid_with(&candidates, 7),
            kill,
            "the positive-pid wrapper must preserve the failure unchanged"
        );
    }

    #[test]
    fn retirement_stop_requires_the_interrupt_capability_and_runs_the_stop_row() {
        let fake = FakeWorkspace::new("stop-ok", "echo '{\"interrupted\":true}'");
        let target = retirement_target();
        let profile = Profile::official(HarnessKind::Pi, "pi").expect("profile");
        let result = retirement_stop(&profile, &target, &fake.env(), ADAPTER_TIMEOUT);
        assert_eq!(result.status, "succeeded", "{:?}", result.detail);
        assert_eq!(result.op, Op::Interrupt);
        assert_eq!(result.session_id, "sess-0001");
        assert!(
            result
                .payload
                .as_ref()
                .and_then(|payload| payload.get("interrupted"))
                .and_then(Val::as_bool)
                .unwrap_or(false)
        );
        let unsupported = Profile::argv(
            "lane-a",
            "hf-lane",
            &[Op::Observe.capability()],
            BTreeMap::new(),
        )
        .expect("argv profile");
        let refused = retirement_stop(&unsupported, &target, &fake.env(), ADAPTER_TIMEOUT);
        assert_eq!(refused.status, "refused");
        assert_eq!(refused.code, Some(CODE_UNKNOWN_CAPABILITY));
    }

    #[test]
    fn retirement_stop_is_bounded_and_reports_unknown_delivery_on_failure() {
        let sleeper = FakeWorkspace::new("stop-sleep", "exec sleep 5");
        let target = retirement_target();
        let profile = Profile::official(HarnessKind::Pi, "pi").expect("profile");
        let bounded = retirement_stop(
            &profile,
            &target,
            &sleeper.env(),
            Duration::from_millis(150),
        );
        assert_eq!(bounded.status, "ambiguous", "{:?}", bounded.detail);
        assert_eq!(bounded.code, Some(CODE_TIMEOUT));
        let failing = FakeWorkspace::new("stop-fail", "echo 'no' >&2; exit 3");
        let failed = retirement_stop(&profile, &target, &failing.env(), ADAPTER_TIMEOUT);
        assert_eq!(failed.status, "failed");
        assert_eq!(failed.code, Some(CODE_EXIT));
    }

    #[test]
    fn retirement_evidence_classifies_the_closed_evidence_grammar() {
        let target = retirement_target();
        let retired = classify_retirement_evidence(
            &evidence_doc(
                "{\"session_id\":\"sess-0001\",\"state\":\"retired\",\"process\":null,\
                 \"registration\":{\"state\":\"released\",\"session\":\"sess-0001\",\
                 \"generation\":1}}",
            ),
            &target,
            1,
        )
        .expect("classification");
        assert_eq!(retired, RetirementEvidence::Retired);
        // A read-back label (`done`) is never sufficient: the bound process is
        // still present, so the retirement holds.
        let labelled = classify_retirement_evidence(
            &evidence_doc(
                "{\"session_id\":\"sess-0001\",\"state\":\"done\",\"process\":\"proc-0001\",\
                 \"registration\":{\"state\":\"released\",\"session\":\"sess-0001\",\
                 \"generation\":1}}",
            ),
            &target,
            1,
        )
        .expect("classification");
        assert!(matches!(labelled, RetirementEvidence::Held { .. }));
        // A different process under the bound session is a reused identity.
        let reused_process = classify_retirement_evidence(
            &evidence_doc(
                "{\"session_id\":\"sess-0001\",\"process\":\"proc-9\",\
                 \"registration\":{\"state\":\"released\",\"session\":\"sess-0001\",\
                 \"generation\":1}}",
            ),
            &target,
            1,
        )
        .expect("classification");
        assert!(matches!(reused_process, RetirementEvidence::Reused { .. }));
        // Unknown/missing evidence holds.
        for doc in [
            "{\"session_id\":\"sess-0001\",\"registration\":{\"state\":\"released\",\
              \"session\":\"sess-0001\",\"generation\":1}}",
            "{\"session_id\":\"sess-0001\",\"process\":7,\
              \"registration\":{\"state\":\"released\",\"session\":\"sess-0001\",\
              \"generation\":1}}",
            "{\"session_id\":\"sess-0001\",\"process\":null}",
            "{\"process\":null}",
            "{\"session_id\":\"sess-0001\",\"process\":null,\
              \"registration\":{\"state\":\"active\",\"session\":\"sess-0001\",\
              \"generation\":1}}",
            "{\"session_id\":\"sess-0001\",\"process\":null,\
              \"registration\":{\"state\":\"quarantined\",\"session\":\"sess-0001\",\
              \"generation\":1}}",
        ] {
            let verdict = classify_retirement_evidence(&evidence_doc(doc), &target, 1)
                .expect("classification");
            assert!(
                matches!(verdict, RetirementEvidence::Held { .. }),
                "{doc}: {verdict:?}"
            );
        }
        // A stale registration (another session or generation) and a
        // read-back naming another session fail closed as reused.
        for doc in [
            "{\"session_id\":\"sess-0001\",\"process\":null,\
              \"registration\":{\"state\":\"released\",\"session\":\"sess-0002\",\
              \"generation\":1}}",
            "{\"session_id\":\"sess-0001\",\"process\":null,\
              \"registration\":{\"state\":\"released\",\"session\":\"sess-0001\",\
              \"generation\":2}}",
            "{\"session_id\":\"sess-0002\",\"process\":null,\
              \"registration\":{\"state\":\"released\",\"session\":\"sess-0002\",\
              \"generation\":1}}",
        ] {
            let verdict = classify_retirement_evidence(&evidence_doc(doc), &target, 1)
                .expect("classification");
            assert!(
                matches!(verdict, RetirementEvidence::Reused { .. }),
                "{doc}: {verdict:?}"
            );
        }
    }

    #[test]
    fn retirement_evidence_reads_the_workspace_confirmation_row() {
        let fake = FakeWorkspace::new(
            "evidence-ok",
            "printf '%s' '{\"session_id\":\"sess-0001\",\"process\":null,\"registration\":{\"state\":\"released\",\"session\":\"sess-0001\",\"generation\":1}}'",
        );
        let target = retirement_target();
        let profile = Profile::official(HarnessKind::Pi, "pi").expect("profile");
        let evidence = retirement_evidence(&profile, &target, 1, &fake.env(), ADAPTER_TIMEOUT)
            .expect("evidence");
        assert_eq!(evidence, RetirementEvidence::Retired);
        let unsupported = Profile::argv(
            "lane-a",
            "hf-lane",
            &[Op::Interrupt.capability()],
            BTreeMap::new(),
        )
        .expect("argv profile");
        let err = retirement_evidence(&unsupported, &target, 1, &fake.env(), ADAPTER_TIMEOUT)
            .expect_err("unsupported profile refused");
        assert_eq!(err.code, CODE_UNKNOWN_CAPABILITY);
        let failing = FakeWorkspace::new("evidence-fail", "exit 4");
        let err = retirement_evidence(&profile, &target, 1, &failing.env(), ADAPTER_TIMEOUT)
            .expect_err("unavailable evidence holds");
        assert_eq!(err.code, CODE_EXIT);
    }
}
