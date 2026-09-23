//! CLI command parsing and execution.
//!
//! Every stable command emits one `hf-output/v1` envelope when `--json` is
//! requested (stdout = the JSON document only; diagnostics stay on stderr;
//! JSON mode never prompts). Human output is a rendering of the same data —
//! never a second, contradicting contract. Exit codes follow
//! docs/contracts/spec-cli.md: 0 ok, 1 operational error, 2 usage, 3
//! partial, 4 refusal, 5 config/policy error.
//!
//! Untrusted input handling: repository identities always come from the
//! validated config document (argv may only select a configured key or
//! identity), issue numbers must be digits, revisions must be 40-hex, and
//! captured adapter output is redacted at the boundary and never feeds back
//! into argv, framing, policy, or identity.

use std::path::PathBuf;

use crate::adapters::ExecutionMode;
use crate::canonical::canonical_bytes;
use crate::client::{self, RpcError};
use crate::config::{
    Config, LoadError, adapter_environment, default_config_hint, discover_config, init_template,
    load_config, resolve_repository,
};
use crate::daemon::{self, DaemonError};
use crate::dirs::DaemonPaths;
use crate::formats::is_hex40;
use crate::lock::describe_socket;
use crate::observe::{
    HERDR_MINIMUM, Observation, acceptance_revision, gh_issue_text, observe_all, observe_herdr,
    probe_gh_auth, probe_version,
};
use crate::plan::{
    DOCTRINE_WORKFLOW_ID, PlanInput, doctrine_workflow_hash, queue_run_steps, render_plan,
};
use crate::queue_preview::{Boundary, PlannedStep, QueueRequest, SelectedIssue};
use crate::service::{self, LAUNCHD_LABEL, SYSTEMD_UNIT_NAME};
use crate::state::{Retention, State};
use crate::tui::operator::{OperatorConsole, PresentedRun};
use crate::value::{Val, bool_, integer, null, object, string};

/// Top-level usage text (also the `--help` output body).
pub const USAGE: &str = "\
canter — typed, plan-first companion CLI for Herdr coding-agent fleets

READ-ONLY CORE: this binary observes configuration, prerequisites, and
repository state and renders deterministic plans. It never installs, starts,
stops, or upgrades Herdr; it never mutates repositories or fleet state; and
it never stores credentials (GitHub reads use the invoking environment's
authenticated `gh`).

USAGE:
    canter --help
    canter --version
    canter config init
    canter config validate [--config PATH] [--json]
    canter config show [--config PATH] [--json]
    canter doctor [--json]
    canter status [--config PATH] [--json]
    canter plan <repository> <issue> [--revision HEX40] [--config PATH] [--json]
    canter capabilities [--json]
    canter board [--plan FILE --caps G/R/H [--host-available yes|no|unknown] [--harness-lanes N|unknown] [--grant REF=GRANT_ID]... [--resume INSTANCE=DIGEST]...] [--config PATH]
    canter daemon run [--socket PATH] [--config PATH]
    canter daemon status [--config PATH] [--json]
    canter lane preview --lane ID --generation N --session S --process P --role R --worktree W --reason TEXT [--profile KEY] [--socket PATH] [--config PATH] [--json]
    canter lane request --lane ID --generation N --session S --process P --role R --worktree W --reason TEXT [--profile KEY] [--confirm-digest HEX64 | --confirm | --yes] [--idempotency-key IK] [--socket PATH] [--config PATH] [--json]
    canter lane status (--replacement RP_ID | --lane ID --generation N) [--socket PATH] [--config PATH] [--json]
    canter queue submit --request FILE --confirm-digest HEX64 [--epoch N] [--grant REF=GRANT_ID]... [--resume INSTANCE=DIGEST]... [--host-available yes|no|unknown] [--harness-lanes N|unknown] [--supervise arm|off] [--topology FILE] [--idempotency-key IK] [--socket PATH] [--config PATH] [--json]
    canter queue status --submission QS_ID [--socket PATH] [--config PATH] [--json]
    canter queue preview --repository KEY --harness KEY [--reviewer-harness KEY] --host HOST --issue N=HEX40... --caps G/R/H [--host-available yes|no|unknown] [--harness-lanes N|unknown] [--boundary-phase PHASE] [--integration-branch B] [--completion-branch B] [--execution herdr|headless] [--out FILE] [--socket PATH] [--config PATH] [--json]
    canter queue intake --repository KEY --harness KEY --host HOST --caps G/R/H [--label L] [--pin N=HEX40]... [--max-items N] [--dry-run] [--out FILE] [--integration-branch B] [--host-available yes|no|unknown] [--harness-lanes N|unknown] [--supervise arm|off] [--topology FILE] [--socket PATH] [--config PATH] [--json]
    canter run pause --run RUN_ID --reason TEXT [--idempotency-key IK] [--socket PATH] [--config PATH] [--json]
    canter run resume --run RUN_ID --digest HEX64 [--idempotency-key IK] [--socket PATH] [--config PATH] [--json]
    canter run retry --run RUN_ID --step STEP [--idempotency-key IK] [--socket PATH] [--config PATH] [--json]
    canter run reevaluate --run RUN_ID --step STEP --operator IDENTITY --reason TEXT [--idempotency-key IK] [--socket PATH] [--config PATH] [--json]
    canter run release --run RUN_ID --reason TEXT [--idempotency-key IK] [--socket PATH] [--config PATH] [--json]
    canter run resolve --run RUN_ID --step STEP --recorder IDENTITY --evidence FILE [--idempotency-key IK] [--socket PATH] [--config PATH] [--json]
    canter run dispatch --run RUN_ID --step STEP [--param KEY=VALUE]... [--topology FILE] [--admission FILE] [--idempotency-key IK] [--socket PATH] [--config PATH] [--json]
    canter run status --run RUN_ID [--socket PATH] [--config PATH] [--json]
    canter supervision status --run RUN_ID [--socket PATH] [--config PATH] [--json]
    canter grant issue --request FILE --issue N --expires-in SECS [--idempotency-key IK] [--socket PATH] [--config PATH] [--json]
    canter service doctor [--config PATH] [--json]
    canter service install-plan [--config PATH] [--json]
    canter service status-plan [--config PATH] [--json]
    canter service uninstall-plan [--config PATH] [--json]

GLOBAL OPTIONS:
    -h, --help       Print help (add --help to any command for its usage).
    -V, --version    Print the package name, version, description, and schema facts.

COMMANDS:
    config init      Print an annotated hf-config/v1 template to stdout.
    config validate  Validate the config file and its named policy overlay.
    config show      Inspect the effective configuration.
    doctor           Diagnose prerequisites; never installs/starts/stops.
    status           Observe configured repositories (read-only, bounded).
    plan             Render a deterministic read-only hf-plan/v1 plan.
    capabilities     Report the CLI's declared forge read capabilities.
    board            Render the read-only operator board in this terminal.
    daemon           Run or probe the single-writer state daemon.
    lane             Preview, request, or inspect ONE explicit lane handoff
                     (preview/status are read-only; request records intent).
    queue            Preview one reviewed run (the plan producer), submit one
                     approved selected-issue run, or read one committed
                     submission back (preview/status are read-only).
    run              Pause, resume, retry, resolve, dispatch, or inspect ONE
                     run (pause/resume/retry/resolve/dispatch are typed controls;
                     status is read-only; the surface is run-scoped only).
    supervision      Read the versioned supervision status of exactly ONE
                     supervised run back (read-only; an armed driver may
                     dispatch through apply, while this status/control
                     surface never dispatches work).
    grant            Mint ONE route grant (`hf-grant/v1`) through the daemon
                     from a reviewed bound-input document, so the operator
                     authority path has a supported way to obtain the grant
                     id it authorizes (issuance is not authorization).
    service          Render per-user launchd/systemd plans; doctor checks.

EXIT CODES (with or without --json):
    0 ok · 1 operational error · 2 usage · 3 partial · 4 refusal · 5 config error

JSON MODE: every command that accepts --json writes exactly one hf-output/v1
document to stdout; diagnostics go to stderr; JSON output never prompts.
";

/// Parsed top-level command line.
#[derive(Clone, Debug)]
pub struct Invocation {
    /// Canonical command name for the envelope `command` field.
    pub command: String,
    /// Whether `--json` was requested.
    pub json: bool,
    /// Explicit `--config` path.
    pub config_path: Option<PathBuf>,
    /// Per-command arguments (plan only).
    pub plan: Option<PlanArgs>,
    /// Presented reviewed run of the interactive `board` surface (issue
    /// #91): the bound-input document plus the operator's presented
    /// observations. `None` = the read-only board with no run to present
    /// (preview/authorization refuse typed).
    pub board: Option<BoardArgs>,
    /// Config subcommand kind (`init`/`validate`/`show`).
    pub config_action: Option<ConfigAction>,
    /// Daemon subcommand (`run`/`status`).
    pub daemon_action: Option<DaemonAction>,
    /// Service subcommand (doctor/plan actions).
    pub service_action: Option<ServiceAction>,
    /// Lane handoff subcommand (preview/request/status).
    pub lane_action: Option<LaneAction>,
    /// Queue executor subcommand (submit/status; issue #85).
    pub queue_action: Option<QueueAction>,
    /// Run-scoped control subcommand (pause/resume/retry/status; issue #86).
    pub run_action: Option<RunAction>,
    /// Supervision subcommand (status; issue #95): the versioned supervision
    /// status of ONE run. Read-only.
    pub supervision_action: Option<SupervisionAction>,
    /// Grant subcommand (issue #92): the supported production mint path for
    /// ONE route grant derived from a reviewed bound-input document.
    pub grant_action: Option<GrantAction>,
}

/// Run-scoped control subcommands (issue #86): pause, resume, retry or
/// inspect exactly ONE run. Pause/resume/retry are typed controls (each
/// journals its intent through the daemon claim machinery); status is
/// read-only.
#[derive(Clone, Debug, PartialEq)]
pub enum RunAction {
    /// Record ONE durable pause request: `run pause`.
    Pause(RunPauseArgs),
    /// Resume exactly one paused run with its engine-minted digest:
    /// `run resume`.
    Resume(RunResumeArgs),
    /// Authorize ONE bounded re-dispatch of ONE diagnosed step:
    /// `run retry`.
    Retry(RunRetryArgs),
    /// Re-evaluate ONE terminal-success check producer's own recorded checks
    /// at the same certified head, bounded and audited: `run reevaluate`
    /// (issue #230).
    Reevaluate(RunReevaluateArgs),
    /// Release ONE run that can never progress, freeing its issue ownership
    /// and the occupancy it held: `run release` (issue #146).
    Release(RunReleaseArgs),
    /// Resolve ONE diagnosed prompt from recorder-attributed artifact evidence
    /// without issuing its effect again: `run resolve`.
    Resolve(RunResolveArgs),
    /// Dispatch ONE committed-spine step with the operator's own step inputs:
    /// `run dispatch`.
    Dispatch(RunDispatchArgs),
    /// Read one run's control state back (read-only): `run status`.
    Status(RunStatusArgs),
}

/// `run pause`: the exact target plus the bounded operator reason.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunPauseArgs {
    /// Explicit run id (`run-` + 16 hex).
    pub run: String,
    /// Operator reason (1-300 printable characters).
    pub reason: String,
    /// `--idempotency-key`: replay-safe automation key.
    pub idempotency_key: Option<String>,
    /// Explicit daemon socket override.
    pub socket: Option<String>,
}

/// `run release`: the exact target plus the recorded operator reason
/// (issue #146).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunReleaseArgs {
    /// Explicit run id (`run-` + 16 hex).
    pub run: String,
    /// Operator reason (1-300 printable characters; audited with the run).
    pub reason: String,
    /// `--idempotency-key`: replay-safe automation key.
    pub idempotency_key: Option<String>,
    /// Explicit daemon socket override.
    pub socket: Option<String>,
}

/// `run resume`: the exact target plus the engine-minted resume digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunResumeArgs {
    /// Explicit run id (`run-` + 16 hex).
    pub run: String,
    /// The 64-hex digest the pause returned.
    pub digest: String,
    /// `--idempotency-key`: replay-safe automation key.
    pub idempotency_key: Option<String>,
    /// Explicit daemon socket override.
    pub socket: Option<String>,
}

/// `run retry`: the exact target plus the exact diagnosed step.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunRetryArgs {
    /// Explicit run id (`run-` + 16 hex).
    pub run: String,
    /// The exact plan step id being retried.
    pub step: String,
    /// `--idempotency-key`: replay-safe automation key.
    pub idempotency_key: Option<String>,
    /// Explicit daemon socket override.
    pub socket: Option<String>,
}

/// `run reevaluate`: the exact target, the check-producing step, the operator
/// identity and the audited reason (issue #230). Everything else — the head,
/// the checks and the fresh lane round — is derived daemon-side.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunReevaluateArgs {
    /// Explicit run id (`run-` + 16 hex).
    pub run: String,
    /// The exact plan step id whose own recorded checks are re-evaluated.
    pub step: String,
    /// The operator identity recorded as the authorizer (1-128 printable).
    pub operator: String,
    /// The audited reason (1-300 printable characters).
    pub reason: String,
    /// `--idempotency-key`: replay-safe automation key.
    pub idempotency_key: Option<String>,
    /// Explicit daemon socket override.
    pub socket: Option<String>,
}

/// `run resolve`: one diagnosed prompt plus a closed artifact-evidence file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunResolveArgs {
    /// Explicit run id (`run-` + 16 hex).
    pub run: String,
    /// The exact diagnosed prompt step.
    pub step: String,
    /// Identity of the operator/agent recording the evidence.
    pub recorder: String,
    /// Readable JSON evidence object (feature head, branch, PR and checks).
    pub evidence: PathBuf,
    /// `--idempotency-key`: replay-safe automation key.
    pub idempotency_key: Option<String>,
    /// Explicit daemon socket override.
    pub socket: Option<String>,
}

/// `run dispatch`: the exact target, the committed-spine step and the
/// operator's own step inputs (everything else is derived daemon-side).
#[derive(Clone, Debug, PartialEq)]
pub struct RunDispatchArgs {
    /// Explicit run id (`run-` + 16 hex).
    pub run: String,
    /// The committed-spine plan step to dispatch.
    pub step: String,
    /// The operator's step-specific inputs (`--param KEY=VALUE`, repeatable);
    /// merged over the step's committed params.
    pub params: Vec<(String, Val)>,
    /// Optional first-dispatch topology document.
    pub topology: Option<PathBuf>,
    /// Optional fresh admission attestation document.
    pub admission: Option<PathBuf>,
    /// Issue #250: the audited operator identity that authorizes the daemon's
    /// OWN host-resource measurement at dispatch time. Presented with a
    /// reason or not at all.
    pub operator: Option<String>,
    /// Issue #250: the bounded reason recorded with that measurement.
    pub reason: Option<String>,
    /// `--idempotency-key`: replay-safe automation key.
    pub idempotency_key: Option<String>,
    /// Explicit daemon socket override.
    pub socket: Option<String>,
}

/// `run status`: one exact run read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunStatusArgs {
    /// Explicit run id (`run-` + 16 hex).
    pub run: String,
    /// Explicit daemon socket override.
    pub socket: Option<String>,
}

/// Queue executor subcommands (issue #85): submit one approved selected-issue
/// run through the daemon, or read one committed submission back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QueueAction {
    /// Commit the approved run: `queue submit`.
    Submit(QueueSubmitArgs),
    /// Read one committed submission (read-only): `queue status`.
    Status(QueueStatusArgs),
    /// Re-evaluate ONE committed submission's parked items against the live
    /// capacity (the bounded, audited operator re-drive, #236):
    /// `queue redrive`.
    Redrive(QueueRedriveArgs),
    /// Render the effect-free preview of one reviewed run and produce the
    /// bound-input document (read-only; the plan producer of the operator
    /// path, issue #91): `queue preview`.
    Preview(QueuePreviewArgs),
    /// Turn the repository's own issue state into ONE bound-input submission,
    /// deterministically and idempotently (issue #245): `queue intake`.
    Intake(QueueIntakeArgs),
}

/// `queue intake` (issue #245): the deterministic feeder. Selection reads the
/// repository's own issue surface (open issues carrying the ready label),
/// revisions resolve by the documented rule, items already owned are never
/// re-submitted, and the rendered document goes through the SAME preview,
/// grant and submission surfaces the operator path uses — intake adds a rule,
/// never a shortcut around admission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueueIntakeArgs {
    /// Configured repository key or `owner/name` identity.
    pub repository: String,
    /// The ready label an open issue must carry to be selected
    /// ([`crate::intake::READY_LABEL`] by default).
    pub label: String,
    /// Configured harness key whose reviewed role binding is re-observed.
    pub harness: String,
    /// Explicit target host identity token.
    pub host: String,
    /// Presented host availability; `None` = unknown (a hold). Intake never
    /// assumes capacity.
    pub host_available: Option<bool>,
    /// Presented same-harness occupancy; `None` = unknown (a hold).
    pub harness_lanes: Option<i64>,
    /// The integration branch whose head is the default revision rule.
    pub integration_branch: Option<String>,
    /// Tracker declared revision pins (`--pin N=HEX40`): a declared pin wins
    /// over the default rule.
    pub pins: Vec<(u64, String)>,
    /// The declared item bound of one invocation.
    pub max_items: usize,
    /// `--dry-run`: print the exact submission and mutate nothing.
    pub dry_run: bool,
    /// Path the bound-input document is written to (required unless
    /// `--dry-run`).
    pub out: Option<PathBuf>,
    /// Presented fan-out concurrency caps (the admission axes).
    pub caps: crate::lifecycle::ConcurrencyCaps,
    /// `--supervise arm|off`: whether the submission arms supervision.
    /// `arm` requires `--topology`.
    pub supervise: String,
    /// Dispatch topology committed with an armed submission.
    pub topology: Option<PathBuf>,
    /// Explicit daemon socket override.
    pub socket: Option<String>,
}

/// Supervision subcommands (issue #95): the versioned status read of
/// exactly ONE supervised run. Read-only: nothing on this surface arms,
/// disarms or nudges supervision (arming is part of the run's queue
/// submission, and the driver is daemon-owned).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SupervisionAction {
    /// Read one run's supervision status back (read-only):
    /// `supervision status`.
    Status(SupervisionStatusArgs),
}

/// `supervision status`: one exact run read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SupervisionStatusArgs {
    /// The supervised run identity (`run-` + 16 hex).
    pub run: String,
    /// Explicit daemon socket override.
    pub socket: Option<String>,
}

/// Grant subcommands (issue #92): the supported production mint path for ONE
/// route grant. Issuance is not authorization — the grant only becomes
/// authority when the operator presents it at the board/`queue submit`
/// authorization point.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GrantAction {
    /// Mint ONE `hf-grant/v1` through the daemon: `grant issue`.
    Issue(GrantIssueArgs),
}

/// `grant issue`: the reviewed bound-input document plus the exact issue
/// and expiry the grant binds.
///
/// Every other grant field is DERIVED (repository identity, workflow hash,
/// role/policy revision, phase, caps, scope) so no binding can be typed by
/// hand: the minted grant binds exactly the reviewed material the operator
/// is about to authorize.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantIssueArgs {
    /// Path of the reviewed bound-input document (`canter queue preview
    /// --out`; the same material `queue submit --request` reads).
    pub request_path: PathBuf,
    /// The reviewed issue number the grant binds (one of the document's
    /// `selected[]` entries).
    pub issue: i64,
    /// Seconds from now until expiry (`--expires-in SECS`).
    pub expires_in: i64,
    /// `--idempotency-key`: replay-safe automation key.
    pub idempotency_key: Option<String>,
    /// Explicit daemon socket override.
    pub socket: Option<String>,
}

/// `queue submit`: the presented submission material plus the explicit
/// digest authorization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueueSubmitArgs {
    /// Path of the bound-input preview document (the reviewed material).
    pub request_path: PathBuf,
    /// `--confirm-digest HEX64`: the exact preview digest being approved.
    pub confirm_digest: String,
    /// The state epoch the approval was rendered against; `None` reads the
    /// live epoch from the daemon (a pinned value refuses when it moved).
    pub epoch: Option<i64>,
    /// Presented per-issue grant bindings (`REF=GRANT_ID`).
    pub grants: Vec<(String, String)>,
    /// Presented resume authorizations (`INSTANCE=DIGEST`).
    pub resume: Vec<(String, String)>,
    /// Presented host availability; `None` = unknown.
    pub host_available: Option<bool>,
    /// Presented same-harness occupancy; `None` = unknown.
    pub harness_lanes: Option<i64>,
    /// Presented fan-out concurrency caps (the admission axes).
    pub caps: crate::lifecycle::ConcurrencyCaps,
    /// `--supervise arm|off`: whether the admitted runs carry an explicit
    /// supervision authorization (issue #95). Default `off`: supervision is
    /// disabled unless it is explicitly authorized as part of this
    /// submission. `arm` requires the topology used by its gated apply path.
    pub supervise: String,
    /// Dispatch topology committed with an armed submission. It gives the
    /// supervisor the same immutable paths a first `run dispatch` accepts.
    pub topology: Option<PathBuf>,
    /// `--idempotency-key`: replay-safe automation key.
    pub idempotency_key: Option<String>,
    /// Explicit daemon socket override.
    pub socket: Option<String>,
}

/// `queue status`: one exact submission read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueueStatusArgs {
    /// Explicit submission id (`qs_` + 16 hex).
    pub submission: String,
    /// Explicit daemon socket override.
    pub socket: Option<String>,
}

/// `queue redrive`: the bounded, audited operator re-drive of ONE committed
/// submission (#236). It re-applies that submission's OWN approved admission
/// inputs to its parked (`waiting`) items — no new approval, no widened cap
/// and no lane is touched.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueueRedriveArgs {
    /// Explicit submission id (`qs_` + 16 hex).
    pub submission: String,
    /// Explicit daemon socket override.
    pub socket: Option<String>,
}

/// `queue preview`: the reviewed run inputs of one deterministic preview
/// render — the plan producer of the operator path (issue #91).
///
/// The preview is effect-free and reads only the recorded state; the bound-
/// input document it renders IS the material `queue submit --request` and
/// `board --plan` consume (its sha256 is the preview digest an approval
/// binds).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueuePreviewArgs {
    /// Configured repository key or `owner/name` identity.
    pub repository: String,
    /// Selected issues with their exact 40-hex spec revisions (`N=HEX40`).
    pub selected: Vec<(u64, String)>,
    /// Configured harness key whose reviewed role binding is re-observed.
    pub harness: String,
    /// `--reviewer-harness KEY`: the configured harness key of the run's OWN
    /// reviewer (issue #193). `None` declares no reviewer leg: the review
    /// step then stays the operator's own dispatch. The key is resolved
    /// against the configured harnesses, and the registry-resolved binding
    /// rides into the reviewed review step — no model name is ever a literal.
    pub reviewer_harness: Option<String>,
    /// Explicit target host identity token.
    pub host: String,
    /// Presented host availability; `None` = unknown (a hold).
    pub host_available: Option<bool>,
    /// Presented same-harness occupancy; `None` = unknown (a hold).
    pub harness_lanes: Option<i64>,
    /// Presented fan-out concurrency caps (the admission axes).
    pub caps: crate::lifecycle::ConcurrencyCaps,
    /// Allowed completion boundary phase (a closed grant phase); `None`
    /// renders the doctrine default (`merge`).
    pub boundary_phase: Option<String>,
    /// Integration branch of the allowed boundary; `None` renders the
    /// configured repository branch (or `staging`).
    pub integration_branch: Option<String>,
    /// Completion branch of the allowed boundary; `None` renders the
    /// integration branch.
    pub completion_branch: Option<String>,
    /// `--out PATH`: write the bound-input document (the exact
    /// `--request`/`--plan` material) to this path.
    pub out: Option<PathBuf>,
    /// `--execution herdr|headless`: the execution substrate every authored
    /// harness step declares (issue #139). `herdr` (the default) runs the
    /// role inside a Herdr pane in the run's lane worktree; `headless` is the
    /// documented bare-subprocess fallback and is only ever selected here,
    /// explicitly.
    pub execution: ExecutionMode,
    /// Explicit daemon socket override (path derivation only).
    pub socket: Option<String>,
}

/// `board`: the reviewed run presented to the interactive operator surface
/// (issue #91).
///
/// The plan is the bound-input document `queue submit --request` reads (the
/// same reviewed material `canter queue preview` produces); the remaining
/// fields are the operator's presented observations — attested, never
/// measured or inferred by the surface, and unknown stays a hold.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoardArgs {
    /// Path of the reviewed bound-input document.
    pub plan_path: PathBuf,
    /// Presented host availability; `None` = unknown (a hold).
    pub host_available: Option<bool>,
    /// Presented same-harness occupancy; `None` = unknown (a hold).
    pub harness_lanes: Option<i64>,
    /// Presented fan-out concurrency caps.
    pub caps: crate::lifecycle::ConcurrencyCaps,
    /// Presented per-issue grant bindings (`REF=GRANT_ID`).
    pub grants: Vec<(String, String)>,
    /// Presented resume authorizations (`INSTANCE=DIGEST`).
    pub resume: Vec<(String, String)>,
}

/// Daemon subcommands (issue #5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DaemonAction {
    /// Run the daemon in the foreground (`daemon run [--socket PATH]`).
    Run {
        /// Socket path override (`--socket PATH`).
        socket: Option<String>,
    },
    /// Probe the daemon socket and report state
    /// (`daemon status [--socket PATH]`).
    Status {
        /// Socket path override (`--socket PATH`).
        socket: Option<String>,
    },
}

/// Service-management subcommands: pure checks and rendered plans (never
/// activate the host service manager).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServiceAction {
    /// Diagnose the daemon/service environment (read-only).
    Doctor,
    /// Render the install plan (unit text + command steps).
    PlanInstall,
    /// Render the status-check plan.
    PlanStatus,
    /// Render the uninstall plan.
    PlanUninstall,
}

/// Config subcommands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigAction {
    /// Print the annotated template.
    Init,
    /// Validate the config (+ overlay).
    Validate,
    /// Show the effective config.
    Show,
}

/// Lane handoff subcommands (issue #78): preview, request, status for ONE
/// explicit lane. Preview and status are read-only; request records durable
/// intent only (no spawn, kill, or Git effect exists on this surface).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LaneAction {
    /// Render the reviewable `hf-lane-handoff/v1` plan (read-only).
    Preview(LaneArgs),
    /// Authorize and record ONE explicit replacement request.
    Request(LaneRequestArgs),
    /// Read one replacement record with its status and guidance (read-only).
    Status(LaneStatusArgs),
}

/// The shared plan inputs of `lane preview` / `lane request`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LaneArgs {
    /// Logical lane identity (slug).
    pub lane_id: String,
    /// Source lane generation being replaced (>= 1).
    pub generation: i64,
    /// Source session identity.
    pub session: String,
    /// Source process identity.
    pub process: String,
    /// Source role (doctrine role).
    pub role: String,
    /// Repository-relative worktree reference.
    pub worktree: String,
    /// Operator reason (1-300 printable characters).
    pub reason: String,
    /// Optional configured harness key whose reviewed profile plan binds.
    pub profile: Option<String>,
    /// Explicit daemon socket override.
    pub socket: Option<String>,
}

/// `lane request`: the plan inputs plus the explicit authorization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LaneRequestArgs {
    /// The plan inputs.
    pub plan: LaneArgs,
    /// `--confirm-digest HEX64`: the noninteractive explicit authorization.
    pub confirm_digest: Option<String>,
    /// `--confirm`: read the plan digest from stdin (interactive).
    pub confirm: bool,
    /// `--yes`: blanket authorization (refused under a declared policy).
    pub yes: bool,
    /// `--idempotency-key`: replay-safe automation key.
    pub idempotency_key: Option<String>,
}

/// `lane status`: one exact target (replacement id or lane + generation).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LaneStatusArgs {
    /// Explicit replacement id (`rp_` + 16 hex).
    pub replacement: Option<String>,
    /// Lane id (with `--generation`).
    pub lane_id: Option<String>,
    /// Source lane generation (with `--lane`).
    pub generation: Option<i64>,
    /// Explicit daemon socket override.
    pub socket: Option<String>,
}

/// Plan command arguments (validated during parsing).
#[derive(Clone, Debug)]
pub struct PlanArgs {
    /// Repository argument: a configured key or its owner/name identity.
    pub repository: String,
    /// Issue number (digits only, positive).
    pub issue_number: u64,
    /// Explicit acceptance revision (40-hex) when provided.
    pub revision: Option<String>,
}

/// Kind of an `hf-output/v1` envelope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// `ok` — complete result with data.
    Ok,
    /// `partial` — some targets observed, some not (never hidden).
    Partial,
    /// `error` — typed error.
    Error,
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Kind::Ok => "ok",
            Kind::Partial => "partial",
            Kind::Error => "error",
        }
    }
}

/// Typed error document (`hf-error/v1` shape, embedded in error envelopes).
#[derive(Clone, Debug)]
pub struct ErrorDoc {
    /// Stable lowercase-dotted code.
    pub code: String,
    /// Human message.
    pub message: String,
    /// Whether retrying may help.
    pub retryable: bool,
    /// Optional structured details.
    pub details: Option<Val>,
}

/// Result of executing one command.
#[derive(Clone, Debug)]
pub struct CmdResult {
    /// Process exit code (also carried inside the JSON envelope).
    pub exit_code: u8,
    /// Envelope kind.
    pub kind: Kind,
    /// `data` object for ok/partial results.
    pub data: Option<Val>,
    /// Error document for error results.
    pub error: Option<ErrorDoc>,
    /// Human rendering for stdout (empty for error results).
    pub human: String,
    /// Diagnostics for stderr (both modes).
    pub diagnostics: String,
}

fn ok_result(data: Val, human: String) -> CmdResult {
    CmdResult {
        exit_code: 0,
        kind: Kind::Ok,
        data: Some(data),
        error: None,
        human,
        diagnostics: String::new(),
    }
}

fn partial_result(data: Val, human: String, diagnostics: String) -> CmdResult {
    CmdResult {
        exit_code: 3,
        kind: Kind::Partial,
        data: Some(data),
        error: None,
        human,
        diagnostics,
    }
}

fn error_result(exit_code: u8, code: &str, message: String, retryable: bool) -> CmdResult {
    CmdResult {
        exit_code,
        kind: Kind::Error,
        data: None,
        error: Some(ErrorDoc {
            code: code.to_string(),
            message: message.clone(),
            retryable,
            details: None,
        }),
        human: String::new(),
        diagnostics: message,
    }
}

fn error_result_details(
    exit_code: u8,
    code: &str,
    message: String,
    retryable: bool,
    details: Val,
) -> CmdResult {
    let mut result = error_result(exit_code, code, message, retryable);
    if let Some(error) = &mut result.error {
        error.details = Some(details);
    }
    result
}

/// Outcome of parsing: an invocation, a help request (exit 0, stdout), or a
/// usage error (exit 2, stderr).
#[derive(Clone, Debug)]
pub enum ParseError {
    /// User asked for help: print text to stdout and exit 0.
    Help(String),
    /// Malformed argv: print message to stderr and exit 2.
    Usage(String),
}

/// Parse the full argv (after the program name).
pub fn parse_invocation(args: &[String]) -> Result<Invocation, ParseError> {
    let command = args
        .first()
        .ok_or_else(|| ParseError::Usage("missing command".to_string()))?;
    let rest: Vec<&String> = args[1..].iter().collect();
    match command.as_str() {
        "config" => parse_config(&rest),
        "doctor" => parse_flag_command("doctor", &rest),
        "status" => parse_flag_command("status", &rest),
        "capabilities" => parse_flag_command("capabilities", &rest),
        "board" => parse_board(&rest),
        "plan" => parse_plan(&rest),
        "daemon" => parse_daemon(&rest),
        "service" => parse_service(&rest),
        "lane" => parse_lane(&rest),
        "queue" => parse_queue(&rest),
        "run" => parse_run(&rest),
        "supervision" => parse_supervision(&rest),
        "grant" => parse_grant(&rest),
        other => Err(ParseError::Usage(format!("unknown command {other:?}"))),
    }
}

/// Shared flag loop for commands with no positionals (doctor/status/
/// capabilities).
fn parse_flag_command(name: &str, args: &[&String]) -> Result<Invocation, ParseError> {
    let mut json = false;
    let mut config_path: Option<PathBuf> = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--json" => json = true,
            "--config" => {
                index += 1;
                let value = args.get(index).ok_or_else(|| {
                    ParseError::Usage(format!("{name}: --config requires a path argument"))
                })?;
                config_path = Some(PathBuf::from(value));
            }
            "-h" | "--help" => return Err(ParseError::Help(help_request(name))),
            flag => {
                return Err(ParseError::Usage(format!(
                    "{name}: unknown flag {flag:?}; run `canter {name} --help`"
                )));
            }
        }
        index += 1;
    }
    Ok(Invocation {
        command: name.to_string(),
        json,
        config_path,
        board: None,
        plan: None,
        config_action: None,
        daemon_action: None,
        service_action: None,
        lane_action: None,
        queue_action: None,
        run_action: None,
        supervision_action: None,
        grant_action: None,
    })
}

/// `board`: the interactive operator surface (issue #91: the reachable
/// operator authority path).
///
/// `board` renders into the invoking terminal, so it deliberately accepts no
/// `--json`: the refusal is typed at parse time, and a malformed invocation
/// touches nothing (no config, no state store, no terminal). `--config` is
/// honoured because a configured `daemon.socket` is what lets the daemon
/// paths be derived on hosts without `XDG_RUNTIME_DIR` — the board reads the
/// same state store the daemon writes, and the operator submits through the
/// same derived socket.
///
/// `--plan PATH` presents one reviewed run (the bound-input document
/// `queue submit --request` reads, as produced by `canter queue preview`)
/// together with the operator's presented observations: the axis the CLI
/// presents with `--host-available`/`--harness-lanes`/`--caps`/`--grant`/
/// `--resume` on `queue submit`. Without `--plan` the board stays the
/// read-only surface: nothing can be previewed or authorized, and every
/// authority action refuses typed.
fn parse_board(args: &[&String]) -> Result<Invocation, ParseError> {
    let mut config_path: Option<PathBuf> = None;
    let mut plan_path: Option<PathBuf> = None;
    let mut host_available: Option<bool> = None;
    let mut harness_lanes: Option<i64> = None;
    let mut caps: Option<crate::lifecycle::ConcurrencyCaps> = None;
    let mut grants: Vec<(String, String)> = Vec::new();
    let mut resume: Vec<(String, String)> = Vec::new();
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--config" => {
                index += 1;
                let value = args.get(index).ok_or_else(|| {
                    ParseError::Usage("board: --config requires a path argument".to_string())
                })?;
                config_path = Some(PathBuf::from(value));
            }
            "--plan" => {
                index += 1;
                let value = args.get(index).ok_or_else(|| {
                    ParseError::Usage(
                        "board: --plan requires a path to the reviewed bound-input document"
                            .to_string(),
                    )
                })?;
                plan_path = Some(PathBuf::from(value));
            }
            "--grant" => {
                index += 1;
                let value = args.get(index).ok_or_else(|| {
                    ParseError::Usage("board: --grant requires a REF=GRANT_ID value".to_string())
                })?;
                grants.push(parse_grant_argument("board", value)?);
            }
            "--resume" => {
                index += 1;
                let value = args.get(index).ok_or_else(|| {
                    ParseError::Usage(
                        "board: --resume requires an INSTANCE=DIGEST value".to_string(),
                    )
                })?;
                resume.push(parse_resume_argument("board", value)?);
            }
            "--host-available" => {
                index += 1;
                let value = args.get(index).ok_or_else(|| {
                    ParseError::Usage("board: --host-available requires yes|no|unknown".to_string())
                })?;
                host_available = parse_host_available_argument("board", value)?;
            }
            "--harness-lanes" => {
                index += 1;
                let value = args.get(index).ok_or_else(|| {
                    ParseError::Usage(
                        "board: --harness-lanes requires a lane count or unknown".to_string(),
                    )
                })?;
                harness_lanes = parse_harness_lanes_argument("board", value)?;
            }
            "--caps" => {
                index += 1;
                let value = args.get(index).ok_or_else(|| {
                    ParseError::Usage(
                        "board: --caps requires a GLOBAL/REPOSITORY/HARNESS value".to_string(),
                    )
                })?;
                caps = Some(parse_caps_argument("board", value)?);
            }
            "-h" | "--help" => return Err(ParseError::Help(help_request("board"))),
            "--json" => {
                return Err(ParseError::Usage(
                    "board: this command is an interactive terminal surface and does not accept --json"
                        .to_string(),
                ));
            }
            other => {
                return Err(ParseError::Usage(format!(
                    "board: unexpected argument {other:?}; run `canter board --help`"
                )));
            }
        }
        index += 1;
    }
    let board = match plan_path {
        None => {
            // Presenting observations without a run is an invocation
            // mistake: there is nothing to observe, and silently dropping
            // attested facts would be exactly the kind of guess this surface
            // never makes.
            if caps.is_some()
                || host_available.is_some()
                || harness_lanes.is_some()
                || !grants.is_empty()
                || !resume.is_empty()
            {
                return Err(ParseError::Usage(
                    "board: --plan FILE is required with the presented observation flags \
                     (--caps/--host-available/--harness-lanes/--grant/--resume describe the one \
                     presented run)"
                        .to_string(),
                ));
            }
            None
        }
        Some(plan_path) => {
            // The admission axes are never assumed: an unspecified cap is
            // unknown capacity, and unknown capacity admits nothing, so the
            // presented run requires the same explicit --caps the CLI's
            // `queue submit` requires.
            let caps = caps.ok_or_else(|| {
                ParseError::Usage(
                    "board: --caps GLOBAL/REPOSITORY/HARNESS is required with --plan (the \
                     presented admission axes; unknown capacity is never assumed)"
                        .to_string(),
                )
            })?;
            Some(BoardArgs {
                plan_path,
                host_available,
                harness_lanes,
                caps,
                grants,
                resume,
            })
        }
    };
    Ok(Invocation {
        command: "board".to_string(),
        json: false,
        config_path,
        plan: None,
        board,
        config_action: None,
        daemon_action: None,
        service_action: None,
        lane_action: None,
        // The board surface is not a queue submission (issue #85): the field
        // exists on every initializer so the merged struct has one shape.
        queue_action: None,
        run_action: None,
        supervision_action: None,
        grant_action: None,
    })
}

/// Per-command help texts.
fn help_request(name: &str) -> String {
    match name {
        "doctor" => DOCTOR_USAGE.trim_end().to_string(),
        "status" => STATUS_USAGE.trim_end().to_string(),
        "capabilities" => CAPABILITIES_USAGE.trim_end().to_string(),
        "board" => BOARD_USAGE.trim_end().to_string(),
        "plan" => PLAN_USAGE.trim_end().to_string(),
        "config" => CONFIG_USAGE.trim_end().to_string(),
        "daemon" => DAEMON_USAGE.trim_end().to_string(),
        "lane" => LANE_USAGE.trim_end().to_string(),
        "queue" => QUEUE_USAGE.trim_end().to_string(),
        "run" => RUN_USAGE.trim_end().to_string(),
        "supervision" => SUPERVISION_USAGE.trim_end().to_string(),
        "grant" => GRANT_USAGE.trim_end().to_string(),
        "service" => SERVICE_USAGE.trim_end().to_string(),
        _ => USAGE.to_string(),
    }
}

const DOCTOR_USAGE: &str = "\
canter doctor — diagnose prerequisites (read-only; never installs,
starts, stops, or upgrades Herdr, gh, git, or any harness)

USAGE:
    canter doctor [--json]

Checks: git presence, herdr presence + version vs the declared minimum
0.8.2, gh presence + authentication + reported scopes, and the config file
(when present). Exits 0 when every check is ok, 3 when any prerequisite is
missing or degraded, and 5 when a found config/policy document is invalid.
";

const STATUS_USAGE: &str = "\
canter status — observe configured repositories (read-only)

USAGE:
    canter status [--config PATH] [--json]

Observes each enabled configured repository through the local git checkout
in the invoking directory and authenticated `gh` from the invoking
environment, plus a herdr presence/version probe. Observation is bounded
(at most 4 concurrent observers, 10s per process); freshness, completeness,
and every partial failure are explicit in the output. Exits 3 when any
observation is partial; 5 for config errors.
";

const CAPABILITIES_USAGE: &str = "\
canter capabilities — report the CLI's declared forge read capabilities

USAGE:
    canter capabilities [--json]

Emits the hf-capability/v1 declaration for this read-only CLI: axis
\"forge\", actor \"canter\", capabilities [\"read_refs\", \"read_issues\",
\"read_checks\"]. No negotiation or shell guessing is performed.
";

const BOARD_USAGE: &str = "\
canter board — render the read-only operator board in this terminal

USAGE:
    canter board [--plan FILE --caps G/R/H [--host-available yes|no|unknown] [--harness-lanes N|unknown] [--grant REF=GRANT_ID]... [--resume INSTANCE=DIGEST]...] [--config PATH]

Renders the live board from the recorded work items and runs of the daemon
state store (the bounded read model, no second database): wide four-group
board, narrow single-group view, explicit too-small state, and keyboard-only
controls (Tab focus, Up/Down select, Left/Right group, q quit). Terminal-
default colours with an ANSI/monochrome fallback; freshness and completeness
are shown as recorded, and a failed read is stated explicitly instead of
guessed. Synthetic mode is a separate, explicitly labelled mode.

The board never writes, never contacts the network, and does not require a
running daemon: it reads the state store the daemon writes. `--config` is
honoured for the daemon path derivation (a configured daemon.socket removes
the XDG_RUNTIME_DIR requirement). This command is an interactive terminal
surface and does not accept --json.

With `--plan FILE` the board runs the operator authority path over ONE
presented reviewed run: `p` opens the exact preview (the real preview
service re-derived against the live state), Enter continues to the
authorization screen, and Space then Enter is the ONLY keystroke that
authorizes anything. Back/cancel/quit never authorize, a resize clears the
approval box, and a moved preview digest, state epoch or role revision is
refused typed before anything is sent. FILE is the bound-input document
`canter queue preview --out` produces (the same material `queue submit
--request` reads). The presented observations (--host-available,
--harness-lanes, --caps, --grant, --resume) are attestations from the
operator: the surface never measures, infers or guesses them, and an
unattested value holds work instead of admitting it. The run itself is
daemon-owned: closing the terminal stops nothing, and a reopened board reads
the recorded state back.
";

const PLAN_USAGE: &str = "\
canter plan <repository> <issue> — render a deterministic read-only plan

USAGE:
    canter plan <repository> <issue> [--revision HEX40] [--config PATH] [--json]

<repository> names a configured repository (its config key or owner/name
identity — identities always come from the config, never from free text).
<issue> is a positive integer. The acceptance revision is either given with
--revision or derived from the issue's live acceptance text through gh; when
gh is unavailable and no --revision is given, the plan is refused explicitly
(exit 1, code forge.unavailable).

The rendered hf-plan/v1 document is deterministic: the same inputs always
produce the same canonical bytes and sha256 digest. state_epoch is 0 (no
daemon state in this slice). No plan is ever applied by this command.
";

const CONFIG_USAGE: &str = "\
canter config <init|validate|show> — configuration guidance/inspection

USAGE:
    canter config init
    canter config validate [--config PATH] [--json]
    canter config show [--config PATH] [--json]

init prints an annotated hf-config/v1 template to stdout (the CLI never
writes files). validate and show load the config at --config PATH or the XDG
default ($XDG_CONFIG_HOME/canter/config.toml or
~/.config/canter/config.toml) and its explicitly named policy overlay.
Unknown keys, foreign/missing schema identifiers, unsupported versions, and
invalid overlay content are refused with typed refusals (exit 5).
";

fn parse_config(args: &[&String]) -> Result<Invocation, ParseError> {
    let action = args
        .first()
        .ok_or_else(|| ParseError::Help(help_request("config")))?;
    let action = match action.as_str() {
        "init" => ConfigAction::Init,
        "validate" => ConfigAction::Validate,
        "show" => ConfigAction::Show,
        "-h" | "--help" => return Err(ParseError::Help(help_request("config"))),
        other => {
            return Err(ParseError::Usage(format!(
                "config: unknown subcommand {other:?}"
            )));
        }
    };
    let mut json = false;
    let mut config_path: Option<PathBuf> = None;
    let mut index = 1;
    while index < args.len() {
        match args[index].as_str() {
            "--json" => json = true,
            "--config" => {
                index += 1;
                let value = args.get(index).ok_or_else(|| {
                    ParseError::Usage("config: --config requires a path argument".to_string())
                })?;
                config_path = Some(PathBuf::from(value));
            }
            "-h" | "--help" => return Err(ParseError::Help(help_request("config"))),
            flag => {
                return Err(ParseError::Usage(format!(
                    "config: unknown flag {flag:?}; run `canter config --help`"
                )));
            }
        }
        index += 1;
    }
    Ok(Invocation {
        command: match action {
            ConfigAction::Init => "config init",
            ConfigAction::Validate => "config validate",
            ConfigAction::Show => "config show",
        }
        .to_string(),
        json,
        config_path,
        board: None,
        plan: None,
        config_action: Some(action),
        daemon_action: None,
        service_action: None,
        lane_action: None,
        queue_action: None,
        run_action: None,
        supervision_action: None,
        grant_action: None,
    })
}

/// Parse `daemon <run|status>`.
fn parse_daemon(args: &[&String]) -> Result<Invocation, ParseError> {
    let action = args
        .first()
        .ok_or_else(|| ParseError::Help(help_request("daemon")))?;
    let mut socket: Option<String> = None;
    let mut json = false;
    let mut config_path: Option<PathBuf> = None;
    let action = match action.as_str() {
        "run" => {
            let mut index = 1;
            while index < args.len() {
                match args[index].as_str() {
                    "--socket" => {
                        index += 1;
                        let value = args.get(index).ok_or_else(|| {
                            ParseError::Usage("daemon run: --socket requires a path".to_string())
                        })?;
                        socket = Some(value.to_string());
                    }
                    "--config" => {
                        index += 1;
                        let value = args.get(index).ok_or_else(|| {
                            ParseError::Usage("daemon run: --config requires a path".to_string())
                        })?;
                        config_path = Some(PathBuf::from(value));
                    }
                    "--json" => json = true,
                    "-h" | "--help" => return Err(ParseError::Help(help_request("daemon"))),
                    flag => {
                        return Err(ParseError::Usage(format!(
                            "daemon run: unknown flag {flag:?}; run `canter daemon --help`"
                        )));
                    }
                }
                index += 1;
            }
            DaemonAction::Run { socket }
        }
        "status" => {
            let mut index = 1;
            while index < args.len() {
                match args[index].as_str() {
                    "--socket" => {
                        index += 1;
                        let value = args.get(index).ok_or_else(|| {
                            ParseError::Usage("daemon status: --socket requires a path".to_string())
                        })?;
                        socket = Some(value.to_string());
                    }
                    "--config" => {
                        index += 1;
                        let value = args.get(index).ok_or_else(|| {
                            ParseError::Usage("daemon status: --config requires a path".to_string())
                        })?;
                        config_path = Some(PathBuf::from(value));
                    }
                    "--json" => json = true,
                    "-h" | "--help" => return Err(ParseError::Help(help_request("daemon"))),
                    flag => {
                        return Err(ParseError::Usage(format!(
                            "daemon status: unknown flag {flag:?}; run `canter daemon --help`"
                        )));
                    }
                }
                index += 1;
            }
            DaemonAction::Status { socket }
        }
        "-h" | "--help" => return Err(ParseError::Help(help_request("daemon"))),
        other => {
            return Err(ParseError::Usage(format!(
                "daemon: unknown subcommand {other:?}; run `canter daemon --help`"
            )));
        }
    };
    Ok(Invocation {
        command: match &action {
            DaemonAction::Run { .. } => "daemon run".to_string(),
            DaemonAction::Status { .. } => "daemon status".to_string(),
        },
        json,
        config_path,
        board: None,
        plan: None,
        config_action: None,
        daemon_action: Some(action),
        service_action: None,
        lane_action: None,
        queue_action: None,
        run_action: None,
        supervision_action: None,
        grant_action: None,
    })
}

/// Parse `service <doctor|install-plan|status-plan|uninstall-plan>`.
fn parse_service(args: &[&String]) -> Result<Invocation, ParseError> {
    let action = args
        .first()
        .ok_or_else(|| ParseError::Help(help_request("service")))?;
    let action = match action.as_str() {
        "doctor" => ServiceAction::Doctor,
        "install-plan" => ServiceAction::PlanInstall,
        "status-plan" => ServiceAction::PlanStatus,
        "uninstall-plan" => ServiceAction::PlanUninstall,
        "-h" | "--help" => return Err(ParseError::Help(help_request("service"))),
        other => {
            return Err(ParseError::Usage(format!(
                "service: unknown subcommand {other:?}; run `canter service --help`"
            )));
        }
    };
    let mut json = false;
    let mut config_path: Option<PathBuf> = None;
    let mut index = 1;
    while index < args.len() {
        match args[index].as_str() {
            "--json" => json = true,
            "--config" => {
                index += 1;
                let value = args.get(index).ok_or_else(|| {
                    ParseError::Usage("service: --config requires a path argument".to_string())
                })?;
                config_path = Some(PathBuf::from(value));
            }
            "-h" | "--help" => return Err(ParseError::Help(help_request("service"))),
            flag => {
                return Err(ParseError::Usage(format!(
                    "service: unknown flag {flag:?}; run `canter service --help`"
                )));
            }
        }
        index += 1;
    }
    let command = match action {
        ServiceAction::Doctor => "service doctor",
        ServiceAction::PlanInstall => "service install-plan",
        ServiceAction::PlanStatus => "service status-plan",
        ServiceAction::PlanUninstall => "service uninstall-plan",
    };
    Ok(Invocation {
        command: command.to_string(),
        json,
        config_path,
        board: None,
        plan: None,
        config_action: None,
        daemon_action: None,
        service_action: Some(action),
        lane_action: None,
        queue_action: None,
        run_action: None,
        supervision_action: None,
        grant_action: None,
    })
}

/// Parse `lane <preview|request|status>` (issue #78).
fn parse_lane(args: &[&String]) -> Result<Invocation, ParseError> {
    let action = args
        .first()
        .ok_or_else(|| ParseError::Help(help_request("lane")))?;
    if action.as_str() == "-h" || action.as_str() == "--help" {
        return Err(ParseError::Help(help_request("lane")));
    }
    let rest: Vec<&String> = args[1..].to_vec();

    let mut json = false;
    let mut config_path: Option<PathBuf> = None;
    let mut socket: Option<String> = None;
    let mut lane_id: Option<String> = None;
    let mut generation: Option<i64> = None;
    let mut session: Option<String> = None;
    let mut process: Option<String> = None;
    let mut role: Option<String> = None;
    let mut worktree: Option<String> = None;
    let mut reason: Option<String> = None;
    let mut profile: Option<String> = None;
    let mut confirm_digest: Option<String> = None;
    let mut confirm = false;
    let mut yes = false;
    let mut idempotency_key: Option<String> = None;
    let mut replacement: Option<String> = None;

    let mut index = 0;
    while index < rest.len() {
        match rest[index].as_str() {
            "--json" => json = true,
            "--config" => {
                config_path = Some(PathBuf::from(flag_value(
                    &rest, &mut index, "lane", "--config",
                )?))
            }
            "--socket" => socket = Some(flag_value(&rest, &mut index, "lane", "--socket")?),
            "--lane" => lane_id = Some(flag_value(&rest, &mut index, "lane", "--lane")?),
            "--generation" => {
                let raw = flag_value(&rest, &mut index, "lane", "--generation")?;
                let parsed = raw.parse::<i64>().map_err(|_| {
                    ParseError::Usage(format!(
                        "lane: --generation must be a positive integer, got {raw:?}"
                    ))
                })?;
                if parsed < 1 {
                    return Err(ParseError::Usage(format!(
                        "lane: --generation must be a positive integer, got {raw:?}"
                    )));
                }
                generation = Some(parsed);
            }
            "--session" => session = Some(flag_value(&rest, &mut index, "lane", "--session")?),
            "--process" => process = Some(flag_value(&rest, &mut index, "lane", "--process")?),
            "--role" => role = Some(flag_value(&rest, &mut index, "lane", "--role")?),
            "--worktree" => worktree = Some(flag_value(&rest, &mut index, "lane", "--worktree")?),
            "--reason" => reason = Some(flag_value(&rest, &mut index, "lane", "--reason")?),
            "--profile" => profile = Some(flag_value(&rest, &mut index, "lane", "--profile")?),
            "--confirm-digest" => {
                let raw = flag_value(&rest, &mut index, "lane", "--confirm-digest")?;
                if !crate::formats::is_hex64(&raw) {
                    return Err(ParseError::Usage(format!(
                        "lane request: --confirm-digest must be 64 lowercase hex (the plan digest), \
                         got {raw:?}"
                    )));
                }
                confirm_digest = Some(raw);
            }
            "--confirm" => confirm = true,
            "--yes" => yes = true,
            "--idempotency-key" => {
                let raw = flag_value(&rest, &mut index, "lane", "--idempotency-key")?;
                if !crate::formats::is_idempotency_key(&raw) {
                    return Err(ParseError::Usage(format!(
                        "lane request: --idempotency-key must match `ik_` + 8-64 of [a-z0-9-], got \
                         {raw:?}"
                    )));
                }
                idempotency_key = Some(raw);
            }
            "--replacement" => {
                let raw = flag_value(&rest, &mut index, "lane", "--replacement")?;
                if !crate::formats::is_replacement_id(&raw) {
                    return Err(ParseError::Usage(format!(
                        "lane status: --replacement must be `rp_` + 16 lowercase hex, got {raw:?}"
                    )));
                }
                replacement = Some(raw);
            }
            "-h" | "--help" => return Err(ParseError::Help(help_request("lane"))),
            flag => {
                return Err(ParseError::Usage(format!(
                    "lane: unknown flag {flag:?}; run `canter lane --help`"
                )));
            }
        }
        index += 1;
    }

    let command = match action.as_str() {
        "preview" => "lane preview",
        "request" => "lane request",
        "status" => "lane status",
        other => {
            return Err(ParseError::Usage(format!(
                "lane: unknown subcommand {other:?}; run `canter lane --help`"
            )));
        }
    };

    if command == "lane status" {
        if session.is_some()
            || process.is_some()
            || role.is_some()
            || worktree.is_some()
            || reason.is_some()
            || profile.is_some()
            || confirm_digest.is_some()
            || confirm
            || yes
        {
            return Err(ParseError::Usage(
                "lane status: plan inputs/authorization flags are not valid for a read-only \
                 status read"
                    .to_string(),
            ));
        }
        if replacement.is_some() && lane_id.is_some() {
            return Err(ParseError::Usage(
                "lane status: pass either --replacement RP_ID or --lane ID --generation N, not both"
                    .to_string(),
            ));
        }
        let status = match (replacement, lane_id, generation) {
            (Some(replacement), _, _) => LaneStatusArgs {
                replacement: Some(replacement),
                lane_id: None,
                generation: None,
                socket,
            },
            (None, Some(lane_id), Some(generation)) => {
                if !crate::formats::is_slug(&lane_id) {
                    return Err(ParseError::Usage(format!(
                        "lane status: --lane must be a lowercase slug (a-z, 0-9, '-'), got \
                         {lane_id:?}"
                    )));
                }
                LaneStatusArgs {
                    replacement: None,
                    lane_id: Some(lane_id),
                    generation: Some(generation),
                    socket,
                }
            }
            (None, Some(_), None) => {
                return Err(ParseError::Usage(
                    "lane status: --lane requires --generation".to_string(),
                ));
            }
            (None, None, Some(_)) => {
                return Err(ParseError::Usage(
                    "lane status: --generation requires --lane".to_string(),
                ));
            }
            (None, None, None) => {
                return Err(ParseError::Usage(
                    "lane status: pass --replacement RP_ID or --lane ID --generation N".to_string(),
                ));
            }
        };
        return Ok(Invocation {
            command: command.to_string(),
            json,
            config_path,
            board: None,
            plan: None,
            config_action: None,
            daemon_action: None,
            service_action: None,
            lane_action: Some(LaneAction::Status(status)),
            queue_action: None,
            run_action: None,
            supervision_action: None,
            grant_action: None,
        });
    }

    if replacement.is_some() {
        return Err(ParseError::Usage(format!(
            "{command}: --replacement is only valid for `canter lane status`"
        )));
    }
    let lane_id = required_flag(&lane_id, command, "--lane")?.to_string();
    let generation = generation.ok_or_else(|| {
        ParseError::Usage(format!(
            "{command}: --generation is required (positive integer)"
        ))
    })?;
    let session = required_flag(&session, command, "--session")?.to_string();
    let process = required_flag(&process, command, "--process")?.to_string();
    let role = required_flag(&role, command, "--role")?.to_string();
    let worktree = required_flag(&worktree, command, "--worktree")?.to_string();
    let reason = required_flag(&reason, command, "--reason")?.to_string();
    crate::handoff::validate_plan_input(
        &lane_id, generation, &session, &process, &role, &worktree, &reason,
    )
    .map_err(|err| ParseError::Usage(format!("{command}: {}", err.message)))?;
    if let Some(key) = &profile
        && !crate::formats::is_slug(key)
    {
        return Err(ParseError::Usage(format!(
            "{command}: --profile must name a configured harness key (lowercase slug), got \
             {key:?}"
        )));
    }
    let plan = LaneArgs {
        lane_id,
        generation,
        session,
        process,
        role,
        worktree,
        reason,
        profile,
        socket,
    };
    let lane_action = if command == "lane preview" {
        if confirm_digest.is_some() || confirm || yes || idempotency_key.is_some() {
            return Err(ParseError::Usage(
                "lane preview: authorization flags (--confirm-digest/--confirm/--yes/\
                 --idempotency-key) are request-only; preview is read-only"
                    .to_string(),
            ));
        }
        LaneAction::Preview(plan)
    } else {
        LaneAction::Request(LaneRequestArgs {
            plan,
            confirm_digest,
            confirm,
            yes,
            idempotency_key,
        })
    };
    Ok(Invocation {
        command: command.to_string(),
        json,
        config_path,
        board: None,
        plan: None,
        config_action: None,
        daemon_action: None,
        service_action: None,
        lane_action: Some(lane_action),
        queue_action: None,
        run_action: None,
        supervision_action: None,
        grant_action: None,
    })
}

/// Parse `run <pause|resume|retry|status>` (issue #86).
fn parse_run(args: &[&String]) -> Result<Invocation, ParseError> {
    let action = args
        .first()
        .ok_or_else(|| ParseError::Help(help_request("run")))?;
    let command = match action.as_str() {
        "pause" => "run pause",
        "resume" => "run resume",
        "retry" => "run retry",
        "reevaluate" => "run reevaluate",
        "release" => "run release",
        "resolve" => "run resolve",
        "dispatch" => "run dispatch",
        "status" => "run status",
        "-h" | "--help" => return Err(ParseError::Help(help_request("run"))),
        other => {
            return Err(ParseError::Usage(format!(
                "run: unknown subcommand {other:?}; run `canter run --help`"
            )));
        }
    };
    let mut json = false;
    let mut config_path: Option<PathBuf> = None;
    let mut socket: Option<String> = None;
    let mut run: Option<String> = None;
    let mut reason: Option<String> = None;
    let mut digest: Option<String> = None;
    let mut step: Option<String> = None;
    let mut idempotency_key: Option<String> = None;
    let mut step_params: Vec<(String, Val)> = Vec::new();
    let mut topology = None;
    let mut admission = None;
    let mut recorder: Option<String> = None;
    let mut operator: Option<String> = None;
    let mut evidence: Option<PathBuf> = None;
    let rest = &args[1..];
    let mut index = 0;
    while index < rest.len() {
        match rest[index].as_str() {
            "--json" => json = true,
            "--config" => {
                let value = flag_value(rest, &mut index, command, "--config")?;
                config_path = Some(PathBuf::from(value));
            }
            "--socket" => {
                socket = Some(flag_value(rest, &mut index, command, "--socket")?);
            }
            "--run" => {
                let value = flag_value(rest, &mut index, command, "--run")?;
                if !crate::formats::is_run_id(&value) {
                    return Err(ParseError::Usage(format!(
                        "{command}: --run must be `run-` + 16 lowercase hex, got {value:?}"
                    )));
                }
                run = Some(value);
            }
            "--reason" => {
                let value = flag_value(rest, &mut index, command, "--reason")?;
                if value.is_empty()
                    || value.len() > crate::run_control::REASON_MAX
                    || value.chars().any(char::is_control)
                {
                    return Err(ParseError::Usage(format!(
                        "{command}: --reason must be 1-{} printable characters, got {value:?}",
                        crate::run_control::REASON_MAX
                    )));
                }
                reason = Some(value);
            }
            "--digest" => {
                let value = flag_value(rest, &mut index, command, "--digest")?;
                if !crate::formats::is_hex64(&value) {
                    return Err(ParseError::Usage(format!(
                        "{command}: --digest must be the 64-hex engine-minted resume digest, got \
                         {value:?}"
                    )));
                }
                digest = Some(value);
            }
            "--step" => {
                let value = flag_value(rest, &mut index, command, "--step")?;
                if !crate::formats::is_slug(&value) {
                    return Err(ParseError::Usage(format!(
                        "{command}: --step must be a plan step id (slug), got {value:?}"
                    )));
                }
                step = Some(value);
            }
            "--topology" | "--admission" if action.as_str() == "dispatch" => {
                let flag = rest[index].as_str();
                let value = PathBuf::from(flag_value(rest, &mut index, command, flag)?);
                if flag == "--topology" {
                    topology = Some(value);
                } else {
                    admission = Some(value);
                }
            }
            "--recorder" if action.as_str() == "resolve" => {
                let value = flag_value(rest, &mut index, command, "--recorder")?;
                if value.is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
                    return Err(ParseError::Usage(
                        "run resolve: --recorder must be 1-128 printable characters".to_string(),
                    ));
                }
                recorder = Some(value);
            }
            "--operator" if action.as_str() == "reevaluate" || action.as_str() == "dispatch" => {
                let value = flag_value(rest, &mut index, command, "--operator")?;
                if value.is_empty()
                    || value.len() > 128
                    || value.contains(':')
                    || value.chars().any(char::is_control)
                {
                    return Err(ParseError::Usage(format!(
                        "run {}: --operator must be 1-128 printable characters without ':'",
                        action.as_str()
                    )));
                }
                operator = Some(value);
            }
            "--evidence" if action.as_str() == "resolve" => {
                evidence = Some(PathBuf::from(flag_value(
                    rest,
                    &mut index,
                    command,
                    "--evidence",
                )?));
            }
            "--param" => {
                let value = flag_value(rest, &mut index, command, "--param")?;
                let Some((name, raw)) = value.split_once('=') else {
                    return Err(ParseError::Usage(format!(
                        "{command}: --param must be KEY=VALUE, got {value:?}"
                    )));
                };
                if !crate::formats::is_step_param_name(name) {
                    return Err(ParseError::Usage(format!(
                        "{command}: --param key must be a step param name ([a-z][a-z0-9_-]*), got {name:?}"
                    )));
                }
                // One deterministic typing rule: a value that IS JSON
                // (number/bool/object/array) keeps its type, everything else
                // is the literal string.
                let typed = Val::parse_json(raw).unwrap_or_else(|_| string(raw));
                step_params.push((name.to_string(), typed));
            }
            "--idempotency-key" => {
                let value = flag_value(rest, &mut index, command, "--idempotency-key")?;
                if !crate::formats::is_idempotency_key(&value) {
                    return Err(ParseError::Usage(format!(
                        "{command}: --idempotency-key must match `ik_` + 8-64 of [a-z0-9-], got \
                         {value:?}"
                    )));
                }
                idempotency_key = Some(value);
            }
            "-h" | "--help" => return Err(ParseError::Help(help_request("run"))),
            flag => {
                return Err(ParseError::Usage(format!(
                    "run: unknown flag {flag:?}; run `canter run --help`"
                )));
            }
        }
        index += 1;
    }
    let Some(run) = run else {
        return Err(ParseError::Usage(format!(
            "{command}: --run RUN_ID is required"
        )));
    };
    let action = match action.as_str() {
        "pause" => {
            if digest.is_some() || step.is_some() || !step_params.is_empty() {
                return Err(ParseError::Usage(
                    "run pause takes --run and --reason only".to_string(),
                ));
            }
            let Some(reason) = reason else {
                return Err(ParseError::Usage(
                    "run pause: --reason TEXT is required (the journaled pause reason)".to_string(),
                ));
            };
            RunAction::Pause(RunPauseArgs {
                run,
                reason,
                idempotency_key,
                socket,
            })
        }
        "resume" => {
            if reason.is_some() || step.is_some() || !step_params.is_empty() {
                return Err(ParseError::Usage(
                    "run resume takes --run and --digest only".to_string(),
                ));
            }
            let Some(digest) = digest else {
                return Err(ParseError::Usage(
                    "run resume: --digest HEX64 is required (the digest the pause returned)"
                        .to_string(),
                ));
            };
            RunAction::Resume(RunResumeArgs {
                run,
                digest,
                idempotency_key,
                socket,
            })
        }
        "retry" => {
            if reason.is_some() || digest.is_some() || !step_params.is_empty() {
                return Err(ParseError::Usage(
                    "run retry takes --run and --step only".to_string(),
                ));
            }
            let Some(step) = step else {
                return Err(ParseError::Usage(
                    "run retry: --step STEP is required (the one diagnosed step)".to_string(),
                ));
            };
            RunAction::Retry(RunRetryArgs {
                run,
                step,
                idempotency_key,
                socket,
            })
        }
        "reevaluate" => {
            if digest.is_some() || !step_params.is_empty() {
                return Err(ParseError::Usage(
                    "run reevaluate takes --run, --step, --operator and --reason only".to_string(),
                ));
            }
            let Some(step) = step else {
                return Err(ParseError::Usage(
                    "run reevaluate: --step STEP is required (the check-producing step)"
                        .to_string(),
                ));
            };
            let Some(operator) = operator else {
                return Err(ParseError::Usage(
                    "run reevaluate: --operator IDENTITY is required (the recorded authorizer)"
                        .to_string(),
                ));
            };
            let Some(reason) = reason else {
                return Err(ParseError::Usage(
                    "run reevaluate: --reason TEXT is required (the audited reason)".to_string(),
                ));
            };
            RunAction::Reevaluate(RunReevaluateArgs {
                run,
                step,
                operator,
                reason,
                idempotency_key,
                socket,
            })
        }
        "release" => {
            if digest.is_some() || step.is_some() || !step_params.is_empty() {
                return Err(ParseError::Usage(
                    "run release takes --run and --reason only".to_string(),
                ));
            }
            let Some(reason) = reason else {
                return Err(ParseError::Usage(
                    "run release: --reason TEXT is required (the audited release reason)"
                        .to_string(),
                ));
            };
            RunAction::Release(RunReleaseArgs {
                run,
                reason,
                idempotency_key,
                socket,
            })
        }
        "resolve" => {
            if reason.is_some() || digest.is_some() || !step_params.is_empty() {
                return Err(ParseError::Usage(
                    "run resolve takes --run, --step, --recorder and --evidence only".to_string(),
                ));
            }
            let Some(step) = step else {
                return Err(ParseError::Usage(
                    "run resolve: --step STEP is required (the diagnosed prompt)".to_string(),
                ));
            };
            let Some(recorder) = recorder else {
                return Err(ParseError::Usage(
                    "run resolve: --recorder IDENTITY is required".to_string(),
                ));
            };
            let Some(evidence) = evidence else {
                return Err(ParseError::Usage(
                    "run resolve: --evidence FILE is required".to_string(),
                ));
            };
            RunAction::Resolve(RunResolveArgs {
                run,
                step,
                recorder,
                evidence,
                idempotency_key,
                socket,
            })
        }
        "dispatch" => {
            if digest.is_some() {
                return Err(ParseError::Usage(
                    "run dispatch takes --run, --step, --param and the audited --operator/--reason \
                     pair only"
                        .to_string(),
                ));
            }
            let Some(step) = step else {
                return Err(ParseError::Usage(
                    "run dispatch: --step STEP is required (the committed-spine step)".to_string(),
                ));
            };
            // Issue #250: the audited operator measurement is a PAIR.
            if operator.is_some() != reason.is_some() {
                return Err(ParseError::Usage(
                    "run dispatch: present BOTH --operator IDENTITY and --reason TEXT (the audited \
                     pair that authorizes the daemon's own host-resource measurement), or neither"
                        .to_string(),
                ));
            }
            RunAction::Dispatch(RunDispatchArgs {
                run,
                step,
                params: step_params,
                topology,
                admission,
                operator,
                reason,
                idempotency_key,
                socket,
            })
        }
        _ => {
            if reason.is_some() || digest.is_some() || step.is_some() || !step_params.is_empty() {
                return Err(ParseError::Usage("run status takes --run only".to_string()));
            }
            if idempotency_key.is_some() {
                return Err(ParseError::Usage(
                    "run status is read-only and takes no --idempotency-key".to_string(),
                ));
            }
            RunAction::Status(RunStatusArgs { run, socket })
        }
    };
    Ok(Invocation {
        command: command.to_string(),
        json,
        config_path,
        board: None,
        plan: None,
        config_action: None,
        daemon_action: None,
        service_action: None,
        lane_action: None,
        queue_action: None,
        run_action: Some(action),
        supervision_action: None,
        grant_action: None,
    })
}

/// Parse `supervision <status>` (issue #95). Read-only: it issues
/// `supervision.status` through the read-only allowlist, so a status read can
/// never arm, disable or nudge the supervised driver.
fn parse_supervision(args: &[&String]) -> Result<Invocation, ParseError> {
    let action = args
        .first()
        .ok_or_else(|| ParseError::Help(help_request("supervision")))?;
    let command = match action.as_str() {
        "status" => "supervision status",
        "-h" | "--help" => return Err(ParseError::Help(help_request("supervision"))),
        other => {
            return Err(ParseError::Usage(format!(
                "supervision: unknown subcommand {other:?}; run `canter supervision --help`"
            )));
        }
    };
    let mut json = false;
    let mut config_path: Option<PathBuf> = None;
    let mut socket: Option<String> = None;
    let mut run: Option<String> = None;
    let rest = &args[1..];
    let mut index = 0;
    while index < rest.len() {
        match rest[index].as_str() {
            "--json" => json = true,
            "--config" => {
                let value = flag_value(rest, &mut index, command, "--config")?;
                config_path = Some(PathBuf::from(value));
            }
            "--socket" => {
                socket = Some(flag_value(rest, &mut index, command, "--socket")?);
            }
            "--run" => {
                let value = flag_value(rest, &mut index, command, "--run")?;
                if !crate::formats::is_run_id(&value) {
                    return Err(ParseError::Usage(format!(
                        "{command}: --run must be `run-` + 16 lowercase hex, got {value:?}"
                    )));
                }
                run = Some(value);
            }
            "-h" | "--help" => return Err(ParseError::Help(help_request("supervision"))),
            flag => {
                return Err(ParseError::Usage(format!(
                    "{command}: unknown flag {flag:?}; run `canter supervision --help`"
                )));
            }
        }
        index += 1;
    }
    let Some(run) = run else {
        return Err(ParseError::Usage(format!(
            "{command}: --run RUN_ID is required"
        )));
    };
    Ok(Invocation {
        command: command.to_string(),
        json,
        config_path,
        board: None,
        plan: None,
        config_action: None,
        daemon_action: None,
        service_action: None,
        lane_action: None,
        queue_action: None,
        run_action: None,
        supervision_action: Some(SupervisionAction::Status(SupervisionStatusArgs {
            run,
            socket,
        })),
        grant_action: None,
    })
}

/// Parse `grant <issue>` (issue #92): the supported production mint path for
/// ONE route grant derived from the reviewed bound-input document.
///
/// Issuance is not authorization: the minted grant is only presented at the
/// board/`queue submit` authorization point, and the digest the operator
/// approves there is still the reviewed bound-input digest. The mint itself
/// binds exactly that reviewed material (repository, workflow hash, role
/// revision, boundary phase/caps, the selected issue and its acceptance
/// revision), plus the live state epoch and an explicit expiry.
fn parse_grant(args: &[&String]) -> Result<Invocation, ParseError> {
    let action = args
        .first()
        .ok_or_else(|| ParseError::Help(help_request("grant")))?;
    let command = match action.as_str() {
        "issue" => "grant issue",
        "-h" | "--help" => return Err(ParseError::Help(help_request("grant"))),
        other => {
            return Err(ParseError::Usage(format!(
                "grant: unknown subcommand {other:?}; run `canter grant --help`"
            )));
        }
    };
    let mut json = false;
    let mut config_path: Option<PathBuf> = None;
    let mut socket: Option<String> = None;
    let mut request_path: Option<PathBuf> = None;
    let mut issue: Option<i64> = None;
    let mut expires_in: Option<i64> = None;
    let mut idempotency_key: Option<String> = None;
    let rest = &args[1..];
    let mut index = 0;
    while index < rest.len() {
        match rest[index].as_str() {
            "--json" => json = true,
            "--config" => {
                let value = flag_value(rest, &mut index, command, "--config")?;
                config_path = Some(PathBuf::from(value));
            }
            "--socket" => {
                socket = Some(flag_value(rest, &mut index, command, "--socket")?);
            }
            "--request" => {
                let value = flag_value(rest, &mut index, command, "--request")?;
                request_path = Some(PathBuf::from(value));
            }
            "--issue" => {
                let value = flag_value(rest, &mut index, command, "--issue")?;
                let number: u64 = value.parse().map_err(|_| {
                    ParseError::Usage(format!(
                        "{command}: --issue takes a digits-only issue number, got {value:?}"
                    ))
                })?;
                if number == 0 || number > i64::MAX as u64 {
                    return Err(ParseError::Usage(format!(
                        "{command}: --issue must be a positive issue number, got {value:?}"
                    )));
                }
                issue = Some(number as i64);
            }
            "--expires-in" => {
                let value = flag_value(rest, &mut index, command, "--expires-in")?;
                let seconds: i64 = value.parse().map_err(|_| {
                    ParseError::Usage(format!(
                        "{command}: --expires-in takes whole seconds, got {value:?}"
                    ))
                })?;
                if !(1..=GRANT_EXPIRY_MAX_SECS).contains(&seconds) {
                    return Err(ParseError::Usage(format!(
                        "{command}: --expires-in must be 1..={GRANT_EXPIRY_MAX_SECS} seconds, got \
                         {value:?}"
                    )));
                }
                expires_in = Some(seconds);
            }
            "--idempotency-key" => {
                let value = flag_value(rest, &mut index, command, "--idempotency-key")?;
                if !crate::formats::is_idempotency_key(&value) {
                    return Err(ParseError::Usage(format!(
                        "{command}: --idempotency-key must be `ik_` + 8-64 of [a-z0-9-], got \
                         {value:?}"
                    )));
                }
                idempotency_key = Some(value);
            }
            "-h" | "--help" => return Err(ParseError::Help(help_request("grant"))),
            flag => {
                return Err(ParseError::Usage(format!(
                    "{command}: unknown flag {flag:?}; run `canter grant --help`"
                )));
            }
        }
        index += 1;
    }
    let Some(request_path) = request_path else {
        return Err(ParseError::Usage(format!(
            "{command}: --request FILE is required (the reviewed bound-input document)"
        )));
    };
    let Some(issue) = issue else {
        return Err(ParseError::Usage(format!(
            "{command}: --issue N is required (the reviewed issue the grant binds)"
        )));
    };
    let Some(expires_in) = expires_in else {
        return Err(ParseError::Usage(format!(
            "{command}: --expires-in SECS is required (the authorization window)"
        )));
    };
    Ok(Invocation {
        command: command.to_string(),
        json,
        config_path,
        board: None,
        plan: None,
        config_action: None,
        daemon_action: None,
        service_action: None,
        lane_action: None,
        queue_action: None,
        run_action: None,
        supervision_action: None,
        grant_action: Some(GrantAction::Issue(GrantIssueArgs {
            request_path,
            issue,
            expires_in,
            idempotency_key,
            socket,
        })),
    })
}

/// Upper bound on `grant issue --expires-in`: 30 days. A grant is the
/// authorization window of one reviewed run, not a standing capability.
/// The SAME documented bound caps an engine-side renewal (issue #184), so
/// the value lives once, in the mutation engine's window table.
const GRANT_EXPIRY_MAX_SECS: i64 = crate::mutation::GRANT_WINDOW_MAX_SECS;

/// Parse `queue intake` (issue #245).
///
/// The ready-label and ordering contract documented with the decision core
/// ([`crate::intake`]) is what this surface exposes: `--label` (ready label),
/// `--pin N=HEX40` (a tracker-declared revision that wins over the default
/// rule), `--max-items` (the declared item bound), `--dry-run` (mutate
/// nothing) and `--out` (where the rendered bound-input document goes).
fn parse_queue_intake(rest: &[&String]) -> Result<Invocation, ParseError> {
    let mut json = false;
    let mut config_path: Option<PathBuf> = None;
    let mut socket: Option<String> = None;
    let mut repository: Option<String> = None;
    let mut label = crate::intake::READY_LABEL.to_string();
    let mut harness: Option<String> = None;
    let mut host: Option<String> = None;
    let mut host_available: Option<bool> = None;
    let mut harness_lanes: Option<i64> = None;
    let mut integration_branch: Option<String> = None;
    let mut pins: Vec<(u64, String)> = Vec::new();
    let mut max_items = crate::intake::max_items_default();
    let mut dry_run = false;
    let mut out: Option<PathBuf> = None;
    // Intake adds a rule, never a shortcut: the submission it renders goes
    // through the same caps/supervision presentation the operator path uses.
    let mut caps: Option<crate::lifecycle::ConcurrencyCaps> = None;
    let mut supervise = "disabled".to_string();
    let mut topology: Option<PathBuf> = None;
    let mut index = 0;
    while index < rest.len() {
        match rest[index].as_str() {
            "--json" => json = true,
            "--config" => {
                config_path = Some(PathBuf::from(flag_value(
                    rest, &mut index, "queue", "--config",
                )?))
            }
            "--socket" => socket = Some(flag_value(rest, &mut index, "queue", "--socket")?),
            "--repository" => {
                let raw = flag_value(rest, &mut index, "queue", "--repository")?;
                if raw.trim().is_empty() {
                    return Err(ParseError::Usage(
                        "queue intake: --repository requires a non-empty configured repository \
                         key"
                        .to_string(),
                    ));
                }
                repository = Some(raw);
            }
            "--label" => {
                let raw = flag_value(rest, &mut index, "queue", "--label")?;
                if raw.trim().is_empty() {
                    return Err(ParseError::Usage(
                        "queue intake: --label requires the ready label an open issue must carry"
                            .to_string(),
                    ));
                }
                label = raw;
            }
            "--harness" => harness = Some(flag_value(rest, &mut index, "queue", "--harness")?),
            "--host" => host = Some(flag_value(rest, &mut index, "queue", "--host")?),
            "--host-available" => {
                let raw = flag_value(rest, &mut index, "queue", "--host-available")?;
                host_available = parse_host_available_argument("queue intake", &raw)?;
            }
            "--harness-lanes" => {
                let raw = flag_value(rest, &mut index, "queue", "--harness-lanes")?;
                harness_lanes = parse_harness_lanes_argument("queue intake", &raw)?;
            }
            "--integration-branch" => {
                integration_branch = Some(flag_value(
                    rest,
                    &mut index,
                    "queue",
                    "--integration-branch",
                )?);
            }
            "--pin" => {
                let raw = flag_value(rest, &mut index, "queue", "--pin")?;
                pins.push(parse_pin_argument(&raw)?);
            }
            "--max-items" => {
                let raw = flag_value(rest, &mut index, "queue", "--max-items")?;
                match raw.parse::<usize>() {
                    Ok(parsed) if parsed > 0 => max_items = parsed,
                    _ => {
                        return Err(ParseError::Usage(format!(
                            "queue intake: --max-items takes a positive integer (the declared \
                             item bound), got {raw:?}"
                        )));
                    }
                }
            }
            "--dry-run" => dry_run = true,
            "--out" => {
                out = Some(PathBuf::from(flag_value(
                    rest, &mut index, "queue", "--out",
                )?))
            }
            "--caps" => {
                let raw = flag_value(rest, &mut index, "queue", "--caps")?;
                caps = Some(parse_caps_argument("queue intake", &raw)?);
            }
            "--supervise" => {
                let raw = flag_value(rest, &mut index, "queue", "--supervise")?;
                match raw.as_str() {
                    "arm" => supervise = "armed".to_string(),
                    "off" => supervise = "disabled".to_string(),
                    other => {
                        return Err(ParseError::Usage(format!(
                            "queue intake: --supervise takes arm|off, got {other:?} (supervision \
                             is disabled unless it is explicitly authorized)"
                        )));
                    }
                }
            }
            "--topology" => {
                topology = Some(PathBuf::from(flag_value(
                    rest,
                    &mut index,
                    "queue",
                    "--topology",
                )?))
            }
            "-h" | "--help" => return Err(ParseError::Help(help_request("queue"))),
            flag => {
                return Err(ParseError::Usage(format!(
                    "queue intake: unknown flag {flag:?}; run `canter queue --help`"
                )));
            }
        }
        index += 1;
    }
    let repository = repository.ok_or_else(|| {
        ParseError::Usage(
            "queue intake: --repository KEY is required (the repository whose issue state is \
             read)"
                .to_string(),
        )
    })?;
    let harness = harness.ok_or_else(|| {
        ParseError::Usage(
            "queue intake: --harness KEY is required (the reviewed role binding the run \
             dispatches)"
                .to_string(),
        )
    })?;
    let host =
        host.ok_or_else(|| ParseError::Usage("queue intake: --host HOST is required".to_string()))?;
    let caps = caps.ok_or_else(|| {
        ParseError::Usage(
            "queue intake: --caps GLOBAL/REPOSITORY/HARNESS is required (the presented admission \
             axes; unknown capacity is never assumed)"
                .to_string(),
        )
    })?;
    if supervise == "armed" && topology.is_none() {
        return Err(ParseError::Usage(
            "queue intake: --supervise arm requires --topology FILE so the supervisor can \
             dispatch the first step without an operator nudge"
                .to_string(),
        ));
    }
    if !dry_run && out.is_none() {
        return Err(ParseError::Usage(
            "queue intake: --out FILE is required unless --dry-run is presented (the rendered \
             bound-input document is the material the submission binds)"
                .to_string(),
        ));
    }
    Ok(Invocation {
        command: "queue intake".to_string(),
        json,
        config_path,
        board: None,
        plan: None,
        config_action: None,
        daemon_action: None,
        service_action: None,
        lane_action: None,
        queue_action: Some(QueueAction::Intake(QueueIntakeArgs {
            repository,
            label,
            harness,
            host,
            host_available,
            harness_lanes,
            integration_branch,
            pins,
            max_items,
            dry_run,
            out,
            caps,
            supervise,
            topology,
            socket,
        })),
        run_action: None,
        supervision_action: None,
        grant_action: None,
    })
}

/// Parse one `--pin N=HEX40` tracker-declared revision.
fn parse_pin_argument(raw: &str) -> Result<(u64, String), ParseError> {
    let (number, revision) = raw.split_once('=').ok_or_else(|| {
        ParseError::Usage(format!(
            "queue intake: --pin takes N=HEX40 (the issue and the revision its tracker \
                 declares), got {raw:?}"
        ))
    })?;
    let number: u64 = number.parse().map_err(|_| {
        ParseError::Usage(format!(
            "queue intake: --pin takes N=HEX40, got {raw:?} (N must be a positive integer)"
        ))
    })?;
    if number == 0 {
        return Err(ParseError::Usage(format!(
            "queue intake: --pin takes N=HEX40, got {raw:?} (N must be a positive integer)"
        )));
    }
    if !crate::intake::is_revision(revision) {
        return Err(ParseError::Usage(format!(
            "queue intake: --pin takes N=HEX40, got {raw:?} (the revision must be 40 lowercase \
             hex)"
        )));
    }
    Ok((number, revision.to_string()))
}

/// Parse `queue <submit|status|preview>` (issue #85; `preview` is the
/// plan producer of the operator path, issue #91).
fn parse_queue(args: &[&String]) -> Result<Invocation, ParseError> {
    let action = args
        .first()
        .ok_or_else(|| ParseError::Help(help_request("queue")))?;
    if action.as_str() == "-h" || action.as_str() == "--help" {
        return Err(ParseError::Help(help_request("queue")));
    }
    let rest: Vec<&String> = args[1..].to_vec();
    let command = match action.as_str() {
        "submit" => "queue submit",
        "status" => "queue status",
        "redrive" => "queue redrive",
        "preview" => "queue preview",
        "intake" => return parse_queue_intake(&rest),
        other => {
            return Err(ParseError::Usage(format!(
                "queue: unknown subcommand {other:?}; run `canter queue --help`"
            )));
        }
    };
    let mut json = false;
    let mut config_path: Option<PathBuf> = None;
    let mut socket: Option<String> = None;
    let mut request_path: Option<PathBuf> = None;
    let mut confirm_digest: Option<String> = None;
    let mut epoch: Option<i64> = None;
    let mut grants: Vec<(String, String)> = Vec::new();
    let mut resume: Vec<(String, String)> = Vec::new();
    let mut host_available: Option<bool> = None;
    let mut host_available_set = false;
    let mut harness_lanes: Option<i64> = None;
    let mut harness_lanes_set = false;
    let mut caps: Option<crate::lifecycle::ConcurrencyCaps> = None;
    // Issue #95: supervision is disabled unless this submission explicitly
    // authorizes it (`--supervise arm`).
    let mut supervise = "disabled".to_string();
    let mut topology: Option<PathBuf> = None;
    let mut idempotency_key: Option<String> = None;
    let mut submission: Option<String> = None;
    // Plan-producer inputs (`queue preview`, issue #91).
    let mut repository: Option<String> = None;
    let mut selected: Vec<(u64, String)> = Vec::new();
    let mut harness: Option<String> = None;
    let mut reviewer_harness: Option<String> = None;
    let mut host: Option<String> = None;
    let mut boundary_phase: Option<String> = None;
    let mut integration_branch: Option<String> = None;
    let mut completion_branch: Option<String> = None;
    let mut out: Option<PathBuf> = None;
    // Issue #139: the reviewed execution substrate of the authored spine.
    // `herdr` is the default (the product substrate); `headless` must be
    // selected explicitly here.
    let mut execution: Option<ExecutionMode> = None;
    let mut index = 0;
    while index < rest.len() {
        match rest[index].as_str() {
            "--json" => json = true,
            "--config" => {
                config_path = Some(PathBuf::from(flag_value(
                    &rest, &mut index, "queue", "--config",
                )?))
            }
            "--socket" => socket = Some(flag_value(&rest, &mut index, "queue", "--socket")?),
            "--request" => {
                request_path = Some(PathBuf::from(flag_value(
                    &rest,
                    &mut index,
                    "queue",
                    "--request",
                )?))
            }
            "--confirm-digest" => {
                let raw = flag_value(&rest, &mut index, "queue", "--confirm-digest")?;
                if !crate::formats::is_hex64(&raw) {
                    return Err(ParseError::Usage(format!(
                        "queue submit: --confirm-digest must be 64 lowercase hex (the approved \
                         preview digest), got {raw:?}"
                    )));
                }
                confirm_digest = Some(raw);
            }
            "--epoch" => {
                let raw = flag_value(&rest, &mut index, "queue", "--epoch")?;
                let parsed = raw.parse::<i64>().map_err(|_| {
                    ParseError::Usage(format!(
                        "queue submit: --epoch must be a positive integer, got {raw:?}"
                    ))
                })?;
                if parsed < 1 {
                    return Err(ParseError::Usage(format!(
                        "queue submit: --epoch must be a positive integer, got {raw:?}"
                    )));
                }
                epoch = Some(parsed);
            }
            "--grant" => {
                let raw = flag_value(&rest, &mut index, "queue", "--grant")?;
                grants.push(parse_grant_argument("queue submit", &raw)?);
            }
            "--resume" => {
                let raw = flag_value(&rest, &mut index, "queue", "--resume")?;
                resume.push(parse_resume_argument("queue submit", &raw)?);
            }
            "--host-available" => {
                let raw = flag_value(&rest, &mut index, "queue", "--host-available")?;
                host_available_set = true;
                host_available = parse_host_available_argument("queue submit", &raw)?;
            }
            "--harness-lanes" => {
                let raw = flag_value(&rest, &mut index, "queue", "--harness-lanes")?;
                harness_lanes_set = true;
                harness_lanes = parse_harness_lanes_argument("queue submit", &raw)?;
            }
            "--caps" => {
                let raw = flag_value(&rest, &mut index, "queue", "--caps")?;
                caps = Some(parse_caps_argument(command, &raw)?);
            }
            "--supervise" => {
                let raw = flag_value(&rest, &mut index, "queue", "--supervise")?;
                supervise = match raw.as_str() {
                    "arm" => "armed".to_string(),
                    "off" => "disabled".to_string(),
                    other => {
                        return Err(ParseError::Usage(format!(
                            "queue submit: --supervise takes arm|off, got {other:?} (supervision is \
                             disabled unless explicitly authorized here, and arming only evaluates)"
                        )));
                    }
                };
            }
            "--topology" => {
                let raw = flag_value(&rest, &mut index, "queue submit", "--topology")?;
                topology = Some(PathBuf::from(raw));
            }
            "--idempotency-key" => {
                let raw = flag_value(&rest, &mut index, "queue", "--idempotency-key")?;
                if !crate::formats::is_idempotency_key(&raw) {
                    return Err(ParseError::Usage(format!(
                        "queue submit: --idempotency-key must match `ik_` + 8-64 of [a-z0-9-], got \
                         {raw:?}"
                    )));
                }
                idempotency_key = Some(raw);
            }
            "--submission" => {
                let raw = flag_value(&rest, &mut index, "queue", "--submission")?;
                if !crate::formats::is_submission_id(&raw) {
                    return Err(ParseError::Usage(format!(
                        "queue status: --submission must be `qs_` + 16 lowercase hex, got {raw:?}"
                    )));
                }
                submission = Some(raw);
            }
            // Plan-producer inputs (`queue preview`, issue #91). Every name
            // is a reviewed strategy input: the repository identity and the
            // role binding come from config, the selection and the
            // observations are attested, and nothing is inferred.
            "--repository" => {
                let raw = flag_value(&rest, &mut index, "queue", "--repository")?;
                if raw.trim().is_empty() {
                    return Err(ParseError::Usage(format!(
                        "queue preview: --repository requires a non-empty configured repository \
                         key or identity, got {raw:?}"
                    )));
                }
                repository = Some(raw.trim().to_string());
            }
            "--issue" => {
                let raw = flag_value(&rest, &mut index, "queue", "--issue")?;
                selected.push(parse_selected_issue_argument(&raw)?);
            }
            "--harness" => {
                let raw = flag_value(&rest, &mut index, "queue", "--harness")?;
                if !crate::formats::is_slug(&raw) {
                    return Err(ParseError::Usage(format!(
                        "queue preview: --harness must be a configured harness key (lowercase \
                         slug), got {raw:?}"
                    )));
                }
                harness = Some(raw);
            }
            "--reviewer-harness" => {
                let raw = flag_value(&rest, &mut index, "queue", "--reviewer-harness")?;
                if !crate::formats::is_slug(&raw) {
                    return Err(ParseError::Usage(format!(
                        "queue preview: --reviewer-harness must be a configured harness key \
                         (lowercase slug), got {raw:?}"
                    )));
                }
                reviewer_harness = Some(raw);
            }
            "--host" => {
                let raw = flag_value(&rest, &mut index, "queue", "--host")?;
                host = Some(raw);
            }
            "--boundary-phase" => {
                let raw = flag_value(&rest, &mut index, "queue", "--boundary-phase")?;
                boundary_phase = Some(raw);
            }
            "--integration-branch" => {
                let raw = flag_value(&rest, &mut index, "queue", "--integration-branch")?;
                integration_branch = Some(raw);
            }
            "--completion-branch" => {
                let raw = flag_value(&rest, &mut index, "queue", "--completion-branch")?;
                completion_branch = Some(raw);
            }
            "--out" => {
                let raw = flag_value(&rest, &mut index, "queue", "--out")?;
                if raw.trim().is_empty() {
                    return Err(ParseError::Usage(format!(
                        "queue preview: --out requires a file path, got {raw:?}"
                    )));
                }
                out = Some(PathBuf::from(raw));
            }
            "--execution" => {
                let raw = flag_value(&rest, &mut index, "queue", "--execution")?;
                let parsed = ExecutionMode::parse(&raw).ok_or_else(|| {
                    ParseError::Usage(format!(
                        "queue preview: --execution takes herdr|headless, got {raw:?} (the \
                         substrate is never defaulted; `herdr` is the product substrate and \
                         `headless` is the documented bare-subprocess fallback)"
                    ))
                })?;
                execution = Some(parsed);
            }
            "-h" | "--help" => return Err(ParseError::Help(help_request("queue"))),
            flag => {
                return Err(ParseError::Usage(format!(
                    "queue: unknown flag {flag:?}; run `canter queue --help`"
                )));
            }
        }
        index += 1;
    }
    // Cross-command flag refusals: one command's flags never silently apply
    // to another (a preview input is not a submission authorization).
    let preview_only = repository.is_some()
        || !selected.is_empty()
        || harness.is_some()
        || reviewer_harness.is_some()
        || host.is_some()
        || boundary_phase.is_some()
        || integration_branch.is_some()
        || completion_branch.is_some()
        || out.is_some()
        || execution.is_some();
    let queue_action = if command == "queue submit" {
        if submission.is_some() {
            return Err(ParseError::Usage(
                "queue submit: --submission is only valid for `canter queue status`".to_string(),
            ));
        }
        if preview_only {
            return Err(ParseError::Usage(
                "queue submit: preview flags are not valid for a submission (`canter queue preview` \
                 produces the --request document)"
                    .to_string(),
            ));
        }
        let request_path = request_path.ok_or_else(|| {
            ParseError::Usage(
                "queue submit: --request FILE is required (the bound-input preview document)"
                    .to_string(),
            )
        })?;
        let confirm_digest = confirm_digest.ok_or_else(|| {
            ParseError::Usage(
                "queue submit: --confirm-digest HEX64 is required (the approved preview digest)"
                    .to_string(),
            )
        })?;
        let caps = caps.ok_or_else(|| {
            ParseError::Usage(
                "queue submit: --caps GLOBAL/REPOSITORY/HARNESS is required (the presented \
                 admission axes; unknown capacity is never assumed)"
                    .to_string(),
            )
        })?;
        if supervise == "armed" && topology.is_none() {
            return Err(ParseError::Usage(
                "queue submit: --supervise arm requires --topology FILE so the supervisor can dispatch the first step without an operator nudge"
                    .to_string(),
            ));
        }
        QueueAction::Submit(QueueSubmitArgs {
            request_path,
            confirm_digest,
            epoch,
            grants,
            resume,
            host_available,
            harness_lanes,
            caps,
            supervise,
            topology,
            idempotency_key,
            socket,
        })
    } else if command == "queue preview" {
        if request_path.is_some()
            || confirm_digest.is_some()
            || epoch.is_some()
            || !grants.is_empty()
            || !resume.is_empty()
            || idempotency_key.is_some()
            || submission.is_some()
            || supervise != "disabled"
            || topology.is_some()
        {
            return Err(ParseError::Usage(
                "queue preview: submission flags are not valid for a read-only preview render \
                 (grants and resume authorizations are presented to `canter queue submit`)"
                    .to_string(),
            ));
        }
        let repository = repository.ok_or_else(|| {
            ParseError::Usage(
                "queue preview: --repository KEY is required (the configured repository whose \
                 identity and branches the plan binds)"
                    .to_string(),
            )
        })?;
        let harness = harness.ok_or_else(|| {
            ParseError::Usage(
                "queue preview: --harness KEY is required (the configured harness whose reviewed \
                 role configuration the plan re-observes)"
                    .to_string(),
            )
        })?;
        let host = host.ok_or_else(|| {
            ParseError::Usage(
                "queue preview: --host HOST is required (the explicit target host identity; it is \
                 never inferred)"
                    .to_string(),
            )
        })?;
        if selected.is_empty() {
            return Err(ParseError::Usage(
                "queue preview: at least one --issue N=HEX40 is required (the exact selected-issue \
                 set with its spec revisions)"
                    .to_string(),
            ));
        }
        let caps = caps.ok_or_else(|| {
            ParseError::Usage(
                "queue preview: --caps GLOBAL/REPOSITORY/HARNESS is required (the presented \
                 admission axes; unknown capacity is never assumed)"
                    .to_string(),
            )
        })?;
        QueueAction::Preview(QueuePreviewArgs {
            repository,
            selected,
            harness,
            reviewer_harness,
            host,
            host_available,
            harness_lanes,
            caps,
            boundary_phase,
            integration_branch,
            completion_branch,
            out,
            execution: execution.unwrap_or(ExecutionMode::HerdrPane),
            socket,
        })
    } else if command == "queue redrive" {
        if request_path.is_some()
            || confirm_digest.is_some()
            || epoch.is_some()
            || !grants.is_empty()
            || !resume.is_empty()
            || host_available_set
            || harness_lanes_set
            || caps.is_some()
            || idempotency_key.is_some()
            || topology.is_some()
            || preview_only
            || supervise != "disabled"
        {
            return Err(ParseError::Usage(
                "queue redrive: submission flags are not valid for a re-drive (it re-applies the \
                 submission's own approved admission inputs)"
                    .to_string(),
            ));
        }
        let submission = submission.ok_or_else(|| {
            ParseError::Usage(
                "queue redrive: --submission QS_ID is required (the committed submission whose \
                 parked items are re-evaluated)"
                    .to_string(),
            )
        })?;
        QueueAction::Redrive(QueueRedriveArgs { submission, socket })
    } else {
        if request_path.is_some()
            || confirm_digest.is_some()
            || epoch.is_some()
            || !grants.is_empty()
            || !resume.is_empty()
            || host_available_set
            || harness_lanes_set
            || caps.is_some()
            || idempotency_key.is_some()
            || topology.is_some()
            || preview_only
        {
            return Err(ParseError::Usage(
                "queue status: submission flags are not valid for a read-only status read"
                    .to_string(),
            ));
        }
        let submission = submission.ok_or_else(|| {
            ParseError::Usage("queue status: --submission QS_ID is required".to_string())
        })?;
        QueueAction::Status(QueueStatusArgs { submission, socket })
    };
    Ok(Invocation {
        command: command.to_string(),
        json,
        config_path,
        board: None,
        plan: None,
        config_action: None,
        daemon_action: None,
        service_action: None,
        lane_action: None,
        queue_action: Some(queue_action),
        run_action: None,
        supervision_action: None,
        grant_action: None,
    })
}

/// Read one `--flag value` pair out of an argv slice.
fn flag_value(
    args: &[&String],
    index: &mut usize,
    command: &str,
    flag: &str,
) -> Result<String, ParseError> {
    *index += 1;
    args.get(*index)
        .map(|value| value.to_string())
        .ok_or_else(|| ParseError::Usage(format!("{command}: {flag} requires a value")))
}

/// Parse one `--caps GLOBAL/REPOSITORY/HARNESS` value (the presented
/// admission axes; unknown capacity is never assumed).
///
/// Shared by the commands that present the same axis (`queue submit` and
/// the operator `board`) so the accepted grammar and its refusals cannot
/// drift apart.
fn parse_caps_argument(
    command: &str,
    raw: &str,
) -> Result<crate::lifecycle::ConcurrencyCaps, ParseError> {
    let parts: Vec<&str> = raw.split('/').collect();
    let parse = |text: &str| -> Option<usize> {
        text.parse::<usize>()
            .ok()
            .filter(|value| *value <= crate::queue_executor::CAP_MAX)
    };
    let refusal = || {
        ParseError::Usage(format!(
            "{command}: --caps takes GLOBAL/REPOSITORY/HARNESS (integers 0..={}), got {raw:?}",
            crate::queue_executor::CAP_MAX
        ))
    };
    if parts.len() != 3 {
        return Err(refusal());
    }
    let (Some(global), Some(per_repository), Some(per_harness)) =
        (parse(parts[0]), parse(parts[1]), parse(parts[2]))
    else {
        return Err(refusal());
    };
    Ok(crate::lifecycle::ConcurrencyCaps {
        global,
        per_repository,
        per_harness,
    })
}

/// Parse one `--grant REF=GRANT_ID` presented binding.
fn parse_grant_argument(command: &str, raw: &str) -> Result<(String, String), ParseError> {
    let Some((reference, grant_id)) = raw.split_once('=') else {
        return Err(ParseError::Usage(format!(
            "{command}: --grant takes REF=GRANT_ID, got {raw:?}"
        )));
    };
    let reference = reference.trim();
    if reference.is_empty() {
        return Err(ParseError::Usage(format!(
            "{command}: --grant requires a non-empty issue reference, got {raw:?}"
        )));
    }
    if !crate::formats::is_grant_id(grant_id) {
        return Err(ParseError::Usage(format!(
            "{command}: --grant grant ids are `gr_` + 16 lowercase hex, got {grant_id:?}"
        )));
    }
    Ok((reference.to_string(), grant_id.to_string()))
}

/// Parse one `--resume INSTANCE=DIGEST` presented authorization.
fn parse_resume_argument(command: &str, raw: &str) -> Result<(String, String), ParseError> {
    let Some((instance_id, digest)) = raw.split_once('=') else {
        return Err(ParseError::Usage(format!(
            "{command}: --resume takes INSTANCE=DIGEST, got {raw:?}"
        )));
    };
    if instance_id.is_empty() || instance_id.len() > 64 {
        return Err(ParseError::Usage(format!(
            "{command}: --resume requires a bounded instance id, got {raw:?}"
        )));
    }
    if !crate::formats::is_hex64(digest) {
        return Err(ParseError::Usage(format!(
            "{command}: --resume digests are the engine-minted 64-hex digests, got {digest:?}"
        )));
    }
    Ok((instance_id.to_string(), digest.to_string()))
}

/// Parse one `--host-available yes|no|unknown` attestation; `unknown` is
/// `None` (a hold, never a yes).
fn parse_host_available_argument(command: &str, raw: &str) -> Result<Option<bool>, ParseError> {
    match raw {
        "yes" => Ok(Some(true)),
        "no" => Ok(Some(false)),
        "unknown" => Ok(None),
        other => Err(ParseError::Usage(format!(
            "{command}: --host-available takes yes|no|unknown, got {other:?}"
        ))),
    }
}

/// Parse one `--harness-lanes N|unknown` attestation; `unknown` is `None`
/// (missing occupancy is never assumed to be spare capacity).
fn parse_harness_lanes_argument(command: &str, raw: &str) -> Result<Option<i64>, ParseError> {
    if raw == "unknown" {
        return Ok(None);
    }
    let refusal = || {
        ParseError::Usage(format!(
            "{command}: --harness-lanes takes a non-negative lane count or unknown, got {raw:?}"
        ))
    };
    let parsed = raw.parse::<i64>().map_err(|_| refusal())?;
    if parsed < 0 {
        return Err(refusal());
    }
    Ok(Some(parsed))
}

/// Parse one `--issue N=HEX40` reviewed selection: the issue number plus
/// its exact 40-hex spec revision (never a moving ref).
fn parse_selected_issue_argument(raw: &str) -> Result<(u64, String), ParseError> {
    let Some((number, revision)) = raw.split_once('=') else {
        return Err(ParseError::Usage(format!(
            "queue preview: --issue takes N=HEX40 (the issue and its exact spec revision), got \
             {raw:?}"
        )));
    };
    let parsed = number.trim().parse::<u64>().map_err(|_| {
        ParseError::Usage(format!(
            "queue preview: --issue takes N=HEX40, got {raw:?} (N must be a positive integer)"
        ))
    })?;
    if parsed == 0 {
        return Err(ParseError::Usage(format!(
            "queue preview: --issue takes N=HEX40, got {raw:?} (N must be a positive integer)"
        )));
    }
    if !crate::formats::is_hex40(revision) {
        return Err(ParseError::Usage(format!(
            "queue preview: --issue takes N=HEX40, got {raw:?} (the revision must be 40 lowercase \
             hex)"
        )));
    }
    Ok((parsed, revision.to_string()))
}

/// Require one already-parsed flag value.
fn required_flag<'a>(
    value: &'a Option<String>,
    command: &str,
    flag: &str,
) -> Result<&'a str, ParseError> {
    value
        .as_deref()
        .ok_or_else(|| ParseError::Usage(format!("{command}: {flag} is required")))
}

fn parse_plan(args: &[&String]) -> Result<Invocation, ParseError> {
    let mut json = false;
    let mut config_path: Option<PathBuf> = None;
    let mut revision: Option<String> = None;
    let mut positionals: Vec<String> = Vec::new();
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--json" => json = true,
            "--config" => {
                index += 1;
                let value = args.get(index).ok_or_else(|| {
                    ParseError::Usage("plan: --config requires a path argument".to_string())
                })?;
                config_path = Some(PathBuf::from(value));
            }
            "--revision" => {
                index += 1;
                let value = args.get(index).ok_or_else(|| {
                    ParseError::Usage("plan: --revision requires a 40-hex value".to_string())
                })?;
                if !is_hex40(value) {
                    return Err(ParseError::Usage(format!(
                        "plan: --revision must be 40 lowercase hex, got {value:?}"
                    )));
                }
                revision = Some(value.to_string());
            }
            "-h" | "--help" => return Err(ParseError::Help(help_request("plan"))),
            flag if flag.starts_with('-') => {
                return Err(ParseError::Usage(format!(
                    "plan: unknown flag {flag:?}; run `canter plan --help`"
                )));
            }
            positional => positionals.push(positional.to_string()),
        }
        index += 1;
    }
    if positionals.len() != 2 {
        return Err(ParseError::Usage(format!(
            "plan: expected <repository> <issue>, got {} positional argument(s)",
            positionals.len()
        )));
    }
    let issue_number = match positionals[1].parse::<u64>() {
        Ok(number) if number > 0 => number,
        _ => {
            return Err(ParseError::Usage(format!(
                "plan: issue must be a positive integer, got {:?}",
                positionals[1]
            )));
        }
    };
    Ok(Invocation {
        command: "plan".to_string(),
        json,
        config_path,
        daemon_action: None,
        service_action: None,
        board: None,
        plan: Some(PlanArgs {
            repository: positionals[0].clone(),
            issue_number,
            revision,
        }),
        config_action: None,
        lane_action: None,
        queue_action: None,
        run_action: None,
        supervision_action: None,
        grant_action: None,
    })
}

/// Load the config required by a command, mapping failures onto exit-5
/// error results with stable codes. The error is boxed so `required_config`
/// stays small (clippy result-large-err).
fn required_config(config_path: &Option<PathBuf>) -> Result<Config, Box<CmdResult>> {
    match discover_config(config_path.as_deref()) {
        Ok(Some(path)) => match load_config(&path) {
            Ok(config) => Ok(config),
            Err(load_error) => Err(Box::new(load_error_result(load_error))),
        },
        Ok(None) => Err(Box::new(error_result(
            5,
            "config.not_found",
            format!(
                "no config file found (looked for {}); run `canter config init` and save the template there",
                default_config_hint()
            ),
            false,
        ))),
        Err(load_error) => Err(Box::new(load_error_result(load_error))),
    }
}

fn load_error_result(error: LoadError) -> CmdResult {
    let mut pairs: Vec<(&str, Val)> = Vec::new();
    if let Some(refusal) = error.refusal {
        pairs.push(("refusal", string(refusal.as_str())));
    }
    if !error.path.is_empty() {
        pairs.push(("path", string(&error.path)));
    }
    let details = if pairs.is_empty() {
        null()
    } else {
        object(pairs)
    };
    error_result_details(5, error.code, error.message, false, details)
}

/// Render the JSON `hf-output/v1` envelope for a command result.
pub fn render_envelope(command: &str, result: &CmdResult) -> String {
    let mut fields = vec![
        ("schema", string("hf-output/v1")),
        ("command", string(command)),
        ("kind", string(result.kind.as_str())),
        ("exit_code", integer(result.exit_code as i64)),
    ];
    match (&result.kind, &result.data, &result.error) {
        (Kind::Error, _, Some(error)) => {
            fields.push((
                "error",
                object(vec![
                    ("code", string(&error.code)),
                    ("message", string(&error.message)),
                    ("retryable", bool_(error.retryable)),
                    ("details", error.details.clone().unwrap_or_else(null)),
                ]),
            ));
        }
        (Kind::Error, _, None) => {
            fields.push((
                "error",
                object(vec![
                    ("code", string("internal.error")),
                    ("message", string("error result without an error document")),
                    ("retryable", bool_(false)),
                    ("details", null()),
                ]),
            ));
        }
        (_, Some(data), _) => {
            fields.push(("data", data.clone()));
        }
        _ => {
            fields.push(("data", object(vec![])));
        }
    }
    let doc = object(fields);
    let mut out = String::from_utf8(canonical_bytes(&doc)).expect("canonical JSON is ASCII");
    out.push('\n');
    out
}

/// Execute one parsed invocation.
pub fn execute(invocation: &Invocation) -> CmdResult {
    if let Some(action) = invocation.run_action.clone() {
        return execute_run(action, invocation);
    }
    if let Some(action) = invocation.supervision_action.clone() {
        return execute_supervision(action, invocation);
    }
    if let Some(action) = invocation.grant_action.clone() {
        return execute_grant(action, invocation);
    }
    if let Some(action) = invocation.queue_action.clone() {
        return execute_queue(action, invocation);
    }
    if let Some(action) = invocation.lane_action.clone() {
        return execute_lane(action, invocation);
    }
    if let Some(action) = invocation.daemon_action.clone() {
        return execute_daemon(action, invocation);
    }
    if let Some(action) = invocation.service_action.clone() {
        return execute_service(action, invocation);
    }
    if let Some(action) = invocation.config_action {
        return execute_config(action, invocation);
    }
    if let Some(plan) = &invocation.plan {
        return execute_plan(plan, invocation);
    }
    match invocation.command.as_str() {
        "doctor" => execute_doctor(invocation),
        "status" => execute_status(invocation),
        "capabilities" => execute_capabilities(invocation),
        "board" => execute_board(invocation),
        other => error_result(
            2,
            "usage.error",
            format!("unknown command {other:?}"),
            false,
        ),
    }
}

// ---------------------------------------------------------------------------
// doctor
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct DoctorRow {
    name: &'static str,
    status: &'static str,
    detail: Option<String>,
}

impl DoctorRow {
    fn into_val(self) -> Val {
        let mut fields = vec![("name", string(self.name)), ("status", string(self.status))];
        if let Some(detail) = self.detail {
            fields.push(("detail", string(&detail)));
        }
        object(fields)
    }

    fn render(&self) -> String {
        match &self.detail {
            Some(detail) => format!("{:<12}  {:<9}{}\n", self.name, self.status, detail),
            None => format!("{:<12}  {:<9}\n", self.name, self.status),
        }
    }
}

fn execute_doctor(invocation: &Invocation) -> CmdResult {
    // Config row: an invalid found config is a hard config error (exit 5).
    let (config_status, config_path) = match discover_config(invocation.config_path.as_deref()) {
        Ok(Some(path)) => match load_config(&path) {
            Ok(_) => ("ok", Some(path)),
            Err(load_error) => return load_error_result(load_error),
        },
        Ok(None) => ("absent", None),
        Err(load_error) => return load_error_result(load_error),
    };

    let env = adapter_environment();
    let mut rows: Vec<DoctorRow> = Vec::new();

    // git presence.
    let (git_present, git_version, git_detail, _) = probe_version("git", &env);
    let git_detail = match (git_present, git_version) {
        (true, Some(version)) => format!("git version {version}"),
        (false, _) => "git not found on PATH — git is needed for local checkout reads".to_string(),
        (true, None) => git_detail.unwrap_or_else(|| "git version could not be parsed".to_string()),
    };
    rows.push(DoctorRow {
        name: "git",
        status: if git_present { "ok" } else { "missing" },
        detail: Some(git_detail),
    });

    // herdr presence + version + compatibility (never installed/started).
    let (herdr, _) = observe_herdr(&env);
    let herdr_present = matches!(herdr.payload.get("present"), Some(Val::Bool(true)));
    let herdr_version = herdr.payload.get("version").and_then(Val::as_str);
    let herdr_compatible = matches!(herdr.payload.get("compatible"), Some(Val::Bool(true)));
    let (herdr_status, herdr_detail) = match (herdr_present, herdr_version, herdr_compatible) {
        (false, _, _) => (
            "missing",
            "herdr not found on PATH — canter never installs or starts Herdr".to_string(),
        ),
        (true, Some(version), true) => (
            "ok",
            format!(
                "herdr {version} (declared minimum {}.{}.{})",
                HERDR_MINIMUM.0, HERDR_MINIMUM.1, HERDR_MINIMUM.2
            ),
        ),
        (true, Some(version), false) => (
            "degraded",
            format!(
                "herdr {version} is below the declared minimum {}.{}.{}",
                HERDR_MINIMUM.0, HERDR_MINIMUM.1, HERDR_MINIMUM.2
            ),
        ),
        (true, None, _) => {
            let cause = herdr
                .payload
                .get("detail")
                .and_then(Val::as_str)
                .unwrap_or("its version could not be determined");
            ("degraded", format!("herdr present but {cause}"))
        }
    };
    rows.push(DoctorRow {
        name: "herdr",
        status: herdr_status,
        detail: Some(herdr_detail),
    });

    // gh presence + authentication + reported scopes.
    let (gh_present, gh_version, _gh_version_detail, _) = probe_version("gh", &env);
    let gh_version_text = gh_version.as_deref().unwrap_or("unknown");
    let (gh_authed, gh_scopes, gh_auth_detail, _) = probe_gh_auth(&env);
    let (gh_status, gh_detail) = match (gh_present, gh_authed, &gh_scopes) {
        (false, _, _) => (
            "missing",
            "gh not found on PATH — GitHub reads need authenticated gh from the invoking environment"
                .to_string(),
        ),
        (true, false, _) => (
            "degraded",
            format!(
                "gh present but not authenticated{}",
                gh_auth_detail
                    .map(|detail| format!(" ({detail})"))
                    .unwrap_or_default()
            ),
        ),
        (true, true, Some(scopes)) if !scopes.is_empty() => (
            "ok",
            format!("gh {gh_version_text}; authenticated; scopes: {}", scopes.join(", ")),
        ),
        (true, true, _) => (
            "degraded",
            "gh authenticated but token scopes were not reported".to_string(),
        ),
    };
    rows.push(DoctorRow {
        name: "gh",
        status: gh_status,
        detail: Some(gh_detail),
    });

    let config_row = match &config_path {
        Some(path) => format!("config at {}", path.display()),
        None => "no config file (not required by doctor; status/plan need it)".to_string(),
    };

    let degraded = rows.iter().any(|row| row.status != "ok");
    let checks: Vec<Val> = rows.iter().cloned().map(DoctorRow::into_val).collect();

    let mut human = String::new();
    human.push_str("canter doctor\n");
    human.push_str(&format!(
        "{:<12}  {:<9}{}\n",
        "config", config_status, config_row
    ));
    for row in &rows {
        human.push_str(&row.render());
    }
    human.push_str("boundary: doctor never installs, upgrades, starts, or stops Herdr or gh\n");

    let data = object(vec![
        (
            "config",
            object(vec![
                ("status", string(config_status)),
                (
                    "path",
                    config_path
                        .as_ref()
                        .map(|path| string(&path.display().to_string()))
                        .unwrap_or_else(null),
                ),
            ]),
        ),
        ("checks", Val::Arr(checks)),
    ]);

    let diagnostics = if degraded {
        let count = rows.iter().filter(|row| row.status != "ok").count();
        format!(
            "doctor: {count} prerequisite check(s) not ok — canter never installs, upgrades, starts, or stops Herdr or gh"
        )
    } else {
        String::new()
    };

    if degraded {
        partial_result(data, human.trim_end().to_string(), diagnostics)
    } else {
        ok_result(data, human.trim_end().to_string())
    }
}

// ---------------------------------------------------------------------------
// status
// ---------------------------------------------------------------------------

fn execute_status(invocation: &Invocation) -> CmdResult {
    let config = match required_config(&invocation.config_path) {
        Ok(config) => config,
        Err(result) => return *result,
    };
    let repositories = config.effective_repositories();
    let env = adapter_environment();
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let observed_at = crate::time::rfc3339_now();

    let (observations, totals) = observe_all(&repositories, &env, &cwd);

    let expected = repositories.len();
    let repo_observations: Vec<&Observation> = observations
        .iter()
        .filter(|observation| observation.subject_type == "repository")
        .collect();
    let observed_repositories = repo_observations
        .iter()
        .filter(|observation| observation.completeness == "complete")
        .count();
    let repo_observations_all_fresh = repo_observations
        .iter()
        .all(|observation| observation.freshness == "fresh");
    // The overall freshness describes the repository read-backs; without any
    // repository observation (nothing configured) it is "unknown".
    let freshness = if expected == 0 {
        "unknown"
    } else if repo_observations_all_fresh {
        "fresh"
    } else {
        "unknown"
    };
    let all_observations_complete = observations
        .iter()
        .all(|observation| observation.completeness == "complete");

    let mut docs = Vec::new();
    for observation in &observations {
        docs.push(observation.to_doc(&observed_at));
    }
    let data = object(vec![
        ("expected_repositories", integer(expected as i64)),
        (
            "observed_repositories",
            integer(observed_repositories as i64),
        ),
        ("freshness", string(freshness)),
        ("observations", Val::Arr(docs)),
        ("timings_ms", totals.timings_obj()),
    ]);

    // Human rendering (same data, stable lines).
    let mut human = String::new();
    if expected == 0 {
        human.push_str("status: no repositories configured; nothing to observe\n");
    } else {
        human.push_str(&format!(
            "status: {observed_repositories} of {expected} repositories observed ({freshness})\n"
        ));
    }
    for observation in &observations {
        human.push_str(&render_observation_human(observation));
    }
    let timings = totals.timings_obj();
    let number = |key: &str| {
        timings
            .get(key)
            .and_then(|value| match value {
                Val::Int(int) => Some(int.to_string()),
                _ => None,
            })
            .unwrap_or_else(|| "?".to_string())
    };
    human.push_str(&format!(
        "timings_ms: p50={} p95={} min={} max={} requests={} processes={} partial_failures={}\n",
        number("p50_ms"),
        number("p95_ms"),
        number("min_ms"),
        number("max_ms"),
        number("requests"),
        number("processes"),
        number("partial_failures"),
    ));

    let partial = !all_observations_complete;
    if partial {
        partial_result(
            data,
            human.trim_end().to_string(),
            format!(
                "status: {observed_repositories} of {expected} repositories observed completely; \
                 unavailable surfaces are reported explicitly (partial_failures={})",
                totals.partial_failures
            ),
        )
    } else {
        ok_result(data, human.trim_end().to_string())
    }
}

/// One-line-per-subject human rendering of an observation.
fn render_observation_human(observation: &Observation) -> String {
    match observation.subject_type {
        "repository" => {
            let git = observation.payload.get("git");
            let github = observation.payload.get("github");
            let mut notes: Vec<String> = Vec::new();
            if let Some(git) = git {
                if matches!(git.get("available"), Some(Val::Bool(true))) {
                    notes.push("local checkout".to_string());
                    if let Some(branch) = git.get("branch").and_then(Val::as_str) {
                        notes.push(format!("branch {branch}"));
                    }
                } else {
                    notes.push("no local checkout".to_string());
                }
            }
            if let Some(github) = github {
                if matches!(github.get("available"), Some(Val::Bool(true))) {
                    let default_branch = github
                        .get("default_branch")
                        .and_then(Val::as_str)
                        .unwrap_or("?");
                    notes.push(format!("github default branch {default_branch}"));
                } else {
                    let reason = github
                        .get("reason")
                        .and_then(Val::as_str)
                        .unwrap_or("unavailable");
                    notes.push(format!("github {reason}"));
                }
            }
            format!(
                "  {} [{}/{}]: {}\n",
                observation.subject_id,
                observation.freshness,
                observation.completeness,
                notes.join("; ")
            )
        }
        _ => format!(
            "  {}: {}\n",
            observation.subject_id,
            render_payload_line(&observation.payload)
        ),
    }
}

fn render_payload_line(payload: &Val) -> String {
    match payload.get("present") {
        Some(Val::Bool(true)) => {
            let version = payload.get("version").and_then(Val::as_str).unwrap_or("?");
            let compatible = payload.get("compatible").and_then(Val::as_str);
            match compatible {
                Some("true") => format!("present {version} (compatible)"),
                Some("false") => format!("present {version} (below declared minimum)"),
                _ => format!("present {version}"),
            }
        }
        Some(Val::Bool(false)) => "absent".to_string(),
        _ => "?".to_string(),
    }
}

// ---------------------------------------------------------------------------
// plan
// ---------------------------------------------------------------------------

fn execute_plan(plan: &PlanArgs, invocation: &Invocation) -> CmdResult {
    let config = match required_config(&invocation.config_path) {
        Ok(config) => config,
        Err(result) => return *result,
    };
    let repository = match resolve_repository(&config, &plan.repository) {
        Ok(repository) => repository,
        Err(message) => {
            return error_result(
                2,
                "usage.error",
                format!("plan: {message}; run `canter plan --help`"),
                false,
            );
        }
    };

    // Acceptance revision: explicit --revision, or derived live from the
    // issue's acceptance text through gh. gh absence degrades explicitly.
    let (revision, revision_source) = match &plan.revision {
        Some(revision) => (revision.clone(), "argument"),
        None => {
            let env = adapter_environment();
            match gh_issue_text(&repository.owner, &repository.name, plan.issue_number, &env) {
                Ok((title, body)) => {
                    let revision = acceptance_revision(&title, &body);
                    (revision, "github")
                }
                Err(message) => {
                    return error_result(
                        1,
                        "forge.unavailable",
                        format!("{message}; pass --revision <40hex> to render the plan offline"),
                        true,
                    );
                }
            }
        }
    };

    // Workflow pin: prefer a fleet-doctrine-1 pin; a pin naming another
    // workflow is refused (the workflow engine is a later slice).
    let workflow = config
        .workflows
        .iter()
        .find(|pin| pin.id == DOCTRINE_WORKFLOW_ID)
        .or_else(|| config.workflows.first());
    let rendered = match render_plan(&PlanInput {
        repository,
        issue_number: plan.issue_number,
        revision: revision.clone(),
        workflow,
    }) {
        Ok(rendered) => rendered,
        Err(_refusal) => {
            return error_result(
                4,
                "refusal.workflow.unsupported",
                format!(
                    "the configured workflow pin is not supported by this read-only core (only \
                     {DOCTRINE_WORKFLOW_ID} is available; the workflow engine lands with a later slice)"
                ),
                false,
            );
        }
    };

    let data = object(vec![
        ("plan", rendered.doc.clone()),
        ("digest", string(&rendered.digest)),
        ("issue_source", string(revision_source)),
    ]);

    let mut human = String::new();
    human.push_str(&format!(
        "plan {} issue #{} (revision {})\n",
        repository.identity(),
        plan.issue_number,
        revision
    ));
    human.push_str(&format!(
        "workflow {} hash {}; state_epoch 0; digest sha256 {}\n",
        rendered.workflow_id, rendered.workflow_hash, rendered.digest
    ));
    human.push_str("steps:\n");
    if let Some(Val::Arr(items)) = rendered.doc.get("steps") {
        for step in items {
            let id = step.get("id").and_then(Val::as_str).unwrap_or("?");
            let kind = step.get("kind").and_then(Val::as_str).unwrap_or("?");
            human.push_str(&format!("  {id}  {kind}\n"));
        }
    }
    ok_result(data, human.trim_end().to_string())
}

// ---------------------------------------------------------------------------
// capabilities
// ---------------------------------------------------------------------------

fn execute_capabilities(_invocation: &Invocation) -> CmdResult {
    let capability = object(vec![
        ("schema", string("hf-capability/v1")),
        ("axis", string("forge")),
        ("actor", string("canter")),
        (
            "capabilities",
            Val::Arr(vec![
                string("read_refs"),
                string("read_issues"),
                string("read_checks"),
            ]),
        ),
    ]);
    let data = object(vec![("capability", capability)]);
    ok_result(
        data,
        "canter forge capabilities: read_refs read_issues read_checks\n".to_string(),
    )
}

/// `board`: render the live operator board over the daemon state store.
///
/// Read-only by construction: the board reads the bounded read model (a pure
/// projection over the state store, no second database, no per-row remote
/// request) and the surface only changes local selection/focus. A state
/// store that does not exist is reported typed — this command never creates
/// one — and a terminal failure is reported as the session error it is.
///
/// With `--plan` (issue #91) the same terminal runs the operator authority
/// path instead: the recorded board plus the exact preview, the explicit
/// authorization and the daemon-owned run. The console consumes the SAME
/// typed services the CLI uses ([`crate::queue_preview::preview_queue`],
/// [`crate::queue_executor::revalidate`], `queue.submit` over the derived
/// socket); the surface never synthesizes a shell command and never runs a
/// UI scheduler, and a plan whose digest/epoch/role revision moved is
/// refused typed before anything is sent.
fn execute_board(invocation: &Invocation) -> CmdResult {
    let config = match load_optional_config(invocation) {
        Ok(config) => config,
        Err(result) => return result,
    };
    // The socket override only affects the runtime root; passing the
    // configured one keeps the derivation identical to the daemon's on hosts
    // without an XDG runtime dir (the state store path is the same either
    // way — the board reads the store, it never touches the socket).
    let socket = effective_socket(None, config.as_ref());
    let paths = match derive_paths(socket) {
        Ok(paths) => paths,
        Err(result) => return result,
    };
    if !paths.db_path.exists() {
        return error_result(
            1,
            "board.no_state",
            format!(
                "no daemon state store at {}; run `canter daemon run` first (the board only reads recorded runs)",
                paths.db_path.display()
            ),
            false,
        );
    }
    let state = match State::open(&paths.db_path, Retention::default()) {
        Ok(state) => state,
        Err(err) => {
            return error_result(
                1,
                err.code,
                format!("board: state store unavailable: {}", err.message),
                false,
            );
        }
    };
    // The presented reviewed run: loaded from the bound-input document (the
    // same material `queue submit --request` reads) and paired with the
    // attested observations below. Absent `--plan`, no run is presented and
    // the operator surface refuses preview/authorize typed.
    let presented = match invocation.board.as_ref() {
        None => None,
        Some(args) => match presented_run(args) {
            Ok(run) => Some(run),
            Err(result) => return result,
        },
    };
    let mut console = OperatorConsole::new(&state, paths.socket_path.clone(), config, presented);
    match crate::tui::session::run_operator(&mut console) {
        Ok(()) => ok_result(object(vec![]), String::new()),
        Err(err) => error_result(
            1,
            "board.session",
            format!("board: terminal session failed: {err}"),
            false,
        ),
    }
}

/// Build the presented run of `board --plan`: the reviewed bound-input
/// document plus the operator's attested observations.
///
/// The document is loaded (never rebuilt — the same rule the tests of the
/// operator surface follow) and must be one JSON object; the operator
/// surface re-derives and refuses anything malformed or moved typed at
/// preview time. The label is the file NAME, never a host path: the surface
/// displays it, so it stays a label. (The error is a full `CmdResult`, the
/// CLI's one result shape, so the allowance mirrors the crate's convention.)
#[allow(clippy::result_large_err)]
fn presented_run(args: &BoardArgs) -> Result<PresentedRun, CmdResult> {
    let text = match std::fs::read_to_string(&args.plan_path) {
        Ok(text) => text,
        Err(err) => {
            return Err(error_result(
                2,
                "usage.board_plan",
                format!(
                    "board: cannot read {} ({err}); --plan names the reviewed bound-input document",
                    args.plan_path.display()
                ),
                false,
            ));
        }
    };
    let bound = match Val::parse_json(&text) {
        Ok(bound @ Val::Obj(_)) => bound,
        _ => {
            return Err(error_result(
                2,
                "usage.board_plan",
                format!(
                    "board: {} must carry one bound-input document (JSON object)",
                    args.plan_path.display()
                ),
                false,
            ));
        }
    };
    let label = args
        .plan_path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "reviewed-run-plan".to_string());
    let mut run = PresentedRun::new(label, bound, args.caps);
    run.host_available = args.host_available;
    run.harness_lanes = args.harness_lanes;
    run.grants = args
        .grants
        .iter()
        .map(|(id, grant_id)| crate::queue_executor::ItemGrant {
            id: id.clone(),
            grant_id: grant_id.clone(),
        })
        .collect();
    run.resume = args
        .resume
        .iter()
        .map(
            |(instance_id, digest)| crate::queue_executor::ResumeAuthorization {
                instance_id: instance_id.clone(),
                digest: digest.clone(),
            },
        )
        .collect();
    Ok(run)
}

// ---------------------------------------------------------------------------
// config init / validate / show
// ---------------------------------------------------------------------------

fn execute_config(action: ConfigAction, invocation: &Invocation) -> CmdResult {
    match action {
        ConfigAction::Init => {
            let template = init_template();
            let data = object(vec![("template", string(&template))]);
            ok_result(data, template)
        }
        ConfigAction::Validate => {
            let config = match discover_config(invocation.config_path.as_deref()) {
                Ok(Some(path)) => match load_config(&path) {
                    Ok(config) => config,
                    Err(load_error) => return load_error_result(load_error),
                },
                Ok(None) => {
                    return error_result(
                        5,
                        "config.not_found",
                        format!(
                            "no config file found (looked for {}); run `canter config init` and save the template there",
                            default_config_hint()
                        ),
                        false,
                    );
                }
                Err(load_error) => return load_error_result(load_error),
            };
            let overlay = config.policy.as_ref().map(|policy| {
                object(vec![
                    ("valid", bool_(true)),
                    ("path", string(&policy.path.display().to_string())),
                ])
            });
            let data = object(vec![
                ("valid", bool_(true)),
                ("config_path", string(&config.path.display().to_string())),
                ("policy_overlay", overlay.unwrap_or_else(null)),
            ]);
            let mut human = format!("config valid: {}\n", config.path.display());
            if let Some(policy) = &config.policy {
                human.push_str(&format!(
                    "policy overlay valid: {}\n",
                    policy.path.display()
                ));
            }
            ok_result(data, human.trim_end().to_string())
        }
        ConfigAction::Show => {
            let config = match required_config(&invocation.config_path) {
                Ok(config) => config,
                Err(result) => return *result,
            };
            let repositories: Vec<Val> = config
                .repositories
                .iter()
                .map(|repository| {
                    object(vec![
                        ("key", string(&repository.key)),
                        ("identity", string(&repository.identity())),
                        ("origin", string(&repository.origin)),
                        (
                            "branch",
                            repository
                                .branch
                                .as_ref()
                                .map(|branch| string(branch))
                                .unwrap_or_else(null),
                        ),
                        ("enabled", bool_(repository.enabled)),
                    ])
                })
                .collect();
            // Issue #77: the target-profile preview the human reviews before
            // requesting a replacement — the intended provider/model, the
            // authorized fallbacks, the configured limits (metadata
            // overrides, never provider proof), the declared introspection
            // support, the credential DIGESTS (never values) and the exact
            // profile-configuration revision the daemon will fence on.
            let harnesses: Vec<Val> = config
                .harnesses
                .iter()
                .map(|harness| {
                    let credential_env = crate::config::credential_environment(harness);
                    let binding = crate::config::ProfileBinding::from_config(
                        &config,
                        &harness.key,
                        &credential_env,
                    );
                    let (present, missing) =
                        crate::config::credential_presence(harness, &credential_env);
                    object(vec![
                        ("key", string(&harness.key)),
                        ("kind", string(&harness.kind)),
                        ("executable", string(&harness.executable)),
                        (
                            "env_allow",
                            Val::Arr(harness.env_allow.iter().map(|name| string(name)).collect()),
                        ),
                        (
                            "provider",
                            harness
                                .provider
                                .as_ref()
                                .map(|provider| string(provider))
                                .unwrap_or_else(null),
                        ),
                        (
                            "model",
                            harness
                                .model
                                .as_ref()
                                .map(|model| string(model))
                                .unwrap_or_else(null),
                        ),
                        (
                            "profile",
                            binding
                                .as_ref()
                                .map(|binding| binding.to_doc())
                                .unwrap_or_else(null),
                        ),
                        (
                            "credentials",
                            object(vec![
                                (
                                    "declared",
                                    Val::Arr(
                                        harness
                                            .secret_env
                                            .iter()
                                            .map(|name| string(name))
                                            .collect(),
                                    ),
                                ),
                                (
                                    "present",
                                    Val::Arr(present.iter().map(|name| string(name)).collect()),
                                ),
                                (
                                    "missing",
                                    Val::Arr(missing.iter().map(|name| string(name)).collect()),
                                ),
                            ]),
                        ),
                    ])
                })
                .collect();
            let workflows: Vec<Val> = config
                .workflows
                .iter()
                .map(|pin| {
                    object(vec![
                        ("key", string(&pin.key)),
                        ("id", string(&pin.id)),
                        ("hash", string(&pin.hash)),
                    ])
                })
                .collect();
            let policy_overlay = config.policy.as_ref().map(|policy| {
                object(vec![
                    ("path", string(&policy.path.display().to_string())),
                    (
                        "repositories",
                        policy
                            .repositories
                            .as_ref()
                            .map(|repos| Val::Arr(repos.iter().map(|repo| string(repo)).collect()))
                            .unwrap_or_else(null),
                    ),
                    (
                        "production_confirmation",
                        policy
                            .production_confirmation
                            .as_ref()
                            .map(|rule| string(rule))
                            .unwrap_or_else(null),
                    ),
                ])
            });
            let data = object(vec![
                ("schema", string("hf-config/v1")),
                ("config_path", string(&config.path.display().to_string())),
                (
                    "daemon_enabled",
                    config.daemon_enabled.map(bool_).unwrap_or_else(null),
                ),
                (
                    "daemon_socket",
                    config
                        .daemon_socket
                        .as_ref()
                        .map(|socket| string(socket))
                        .unwrap_or_else(null),
                ),
                ("repositories", Val::Arr(repositories)),
                ("harnesses", Val::Arr(harnesses)),
                ("workflows", Val::Arr(workflows)),
                ("policy_overlay", policy_overlay.unwrap_or_else(null)),
            ]);

            let mut human = format!("config: {}\n", config.path.display());
            if config.repositories.is_empty() {
                human.push_str("  repositories: none configured\n");
            }
            for repository in &config.repositories {
                human.push_str(&format!(
                    "  repository {} (key {}) origin {} enabled={}\n",
                    repository.identity(),
                    repository.key,
                    repository.origin,
                    repository.enabled
                ));
            }
            for harness in &config.harnesses {
                human.push_str(&format!(
                    "  harness {} kind {} executable {} env_allow=[{}]\n",
                    harness.key,
                    harness.kind,
                    harness.executable,
                    harness.env_allow.join(", ")
                ));
                let credential_env = crate::config::credential_environment(harness);
                if let Some(binding) = crate::config::ProfileBinding::from_config(
                    &config,
                    &harness.key,
                    &credential_env,
                ) {
                    human.push_str(&format!(
                        "    profile revision {} intended {}/{} (configured limits only; \
                         credential values never leave the environment)\n",
                        binding.revision, binding.provider, binding.model
                    ));
                }
            }
            for pin in &config.workflows {
                human.push_str(&format!(
                    "  workflow {} id {} hash {}\n",
                    pin.key, pin.id, pin.hash
                ));
            }
            match &config.policy {
                Some(policy) => {
                    human.push_str(&format!("  policy overlay: {}\n", policy.path.display()));
                }
                None => human.push_str("  policy overlay: none\n"),
            }
            ok_result(data, human.trim_end().to_string())
        }
    }
}

/// Map one typed code onto its stable exit code for the lane surface:
/// refusals 4, usage 2, config/policy 5, everything else (daemon/transport)
/// 1. `command | grep` is never used to decide this; the code is typed.
fn lane_exit_code(code: &str) -> u8 {
    if code.starts_with("refusal.") || code == "state.not_found" {
        4
    } else if code.starts_with("usage.") {
        2
    } else if code.starts_with("config.") || code.starts_with("policy.") {
        5
    } else {
        1
    }
}

fn lane_error(code: &str, message: String, retryable: bool) -> CmdResult {
    // Human mode carries the stable code in the diagnostic so the operator
    // and the JSON envelope agree on the same typed refusal.
    let mut result = error_result(lane_exit_code(code), code, message.clone(), retryable);
    result.diagnostics = format!("{code}: {message}");
    result
}

/// The closed read-only method allowlist of the lane/queue/run surface: lane
/// preview/status, queue status, run status and supervision status may issue ONLY these methods (plus the
/// live-epoch read `queue submit` needs to present the state epoch). Every
/// read-only call goes through [`read_only_call`], which fails closed
/// (typed) on anything else — the guard that keeps the read-only commands
/// free of mutations even if a call site is ever edited.
const READ_ONLY_METHODS: [&str; 6] = [
    "lane.replacement.status",
    "lane.checkpoint.status",
    "queue.status",
    "run.status",
    "supervision.status",
    "state.epoch",
];

/// One read-only lane RPC: refuses any method outside the read-only
/// allowlist BEFORE a socket is even opened.
fn read_only_call(
    socket_path: &std::path::Path,
    method: &str,
    params: Option<&Val>,
) -> Result<Val, RpcError> {
    if !READ_ONLY_METHODS.contains(&method) {
        return Err(RpcError {
            code: "client.read_only".to_string(),
            message: format!(
                "refusing {method:?} on the read-only lane surface (preview/status never mutate)"
            ),
        });
    }
    client::call(socket_path, method, params)
}

/// The read-only durable record read of one replacement (`None` when no
/// record exists yet — a preview may target a not-yet-requested lane).
fn read_only_lane_record(
    socket_path: &std::path::Path,
    replacement_id: &str,
) -> Result<Option<Val>, RpcError> {
    let params = object(vec![("replacement_id", string(replacement_id))]);
    match read_only_call(socket_path, "lane.replacement.status", Some(&params)) {
        Ok(result) => Ok(Some(result)),
        Err(RpcError { code, .. }) if code == "state.not_found" => Ok(None),
        Err(err) => Err(err),
    }
}

/// The read-only retained workers/reviewers/gates read: the committed
/// checkpoint snapshot's orchestration block, when one exists.
fn read_only_retained(
    socket_path: &std::path::Path,
    replacement_id: &str,
) -> crate::handoff::RetainedView {
    let params = object(vec![("replacement_id", string(replacement_id))]);
    match read_only_call(socket_path, "lane.checkpoint.status", Some(&params)) {
        Ok(result) => result
            .get("checkpoint")
            .and_then(|checkpoint| checkpoint.get("snapshot"))
            .map(crate::handoff::RetainedView::from_checkpoint_snapshot)
            .unwrap_or_default(),
        Err(_) => crate::handoff::RetainedView::default(),
    }
}

/// Require a live daemon for the lane mutation/read paths (mirrors the
/// `daemon status` presence rules; JSON/prompt behavior is unaffected).
fn require_live_daemon(paths: &DaemonPaths) -> Result<(), Box<CmdResult>> {
    match crate::lock::socket_presence(&paths.socket_path) {
        crate::lock::SocketPresence::Active => Ok(()),
        crate::lock::SocketPresence::Stale => Err(Box::new(lane_error(
            "daemon.stale",
            format!(
                "a stale daemon socket exists at {}; a fresh `daemon run` reclaims it",
                paths.socket_path.display()
            ),
            true,
        ))),
        crate::lock::SocketPresence::Absent => Err(Box::new(lane_error(
            "daemon.absent",
            format!(
                "no daemon is running on {}; the lane handoff surface needs the daemon (read-only commands like `canter status` stay available without it)",
                paths.socket_path.display()
            ),
            false,
        ))),
        crate::lock::SocketPresence::Unsafe(reason) => Err(Box::new(lane_error(
            "daemon.unsafe_socket",
            format!("{} ({})", reason, paths.socket_path.display()),
            false,
        ))),
    }
}

/// Build the plan (inputs already validated during parsing) plus the bound
/// target profile when `--profile KEY` names one.
fn build_lane_plan(
    args: &LaneArgs,
    config: Option<&Config>,
) -> Result<crate::handoff::LanePlan, Box<CmdResult>> {
    let input = crate::handoff::PlanInput {
        lane_id: args.lane_id.clone(),
        generation: args.generation,
        session: args.session.clone(),
        process: args.process.clone(),
        role: args.role.clone(),
        worktree: args.worktree.clone(),
        reason: args.reason.clone(),
    };
    let profile = match &args.profile {
        None => None,
        Some(key) => {
            let Some(config) = config else {
                return Err(Box::new(error_result(
                    5,
                    "config.not_found",
                    format!(
                        "--profile {key:?} needs a config to derive the reviewed plan; run \
                         `canter config init` and save the template, or omit --profile"
                    ),
                    false,
                )));
            };
            let Some(harness) = config.harnesses.iter().find(|harness| harness.key == *key) else {
                return Err(Box::new(error_result(
                    5,
                    "config.harness",
                    format!(
                        "no configured harness {key:?}; --profile names a harness key (see \
                         `canter config show --json`)"
                    ),
                    false,
                )));
            };
            let env = crate::config::credential_environment(harness);
            match crate::config::ProfileBinding::from_config(config, key, &env) {
                Some(binding) => Some(binding),
                None => {
                    return Err(Box::new(error_result(
                        5,
                        "config.harness",
                        format!(
                            "harness {key:?} declares no provider/model binding; there is no \
                             inferred profile plan (declare `provider`/`model` or omit --profile)"
                        ),
                        false,
                    )));
                }
            }
        }
    };
    Ok(crate::handoff::LanePlan::build(input, profile))
}

/// The requested authorization mode, or the typed usage refusal when none
/// (or more than one) was given. JSON mode NEVER prompts; the read-only
/// JSON contract is upheld by refusing instead of waiting on stdin.
fn resolve_confirmation(
    args: &LaneRequestArgs,
    digest: &str,
    json: bool,
) -> Result<crate::handoff::Confirmation, Box<CmdResult>> {
    let modes = usize::from(args.confirm_digest.is_some())
        + usize::from(args.confirm)
        + usize::from(args.yes);
    if modes > 1 {
        return Err(Box::new(error_result(
            2,
            "usage.confirmation",
            "pass exactly one authorization mode: --confirm-digest HEX64, --confirm, or --yes"
                .to_string(),
            false,
        )));
    }
    if let Some(presented) = &args.confirm_digest {
        return Ok(crate::handoff::Confirmation::Digest(presented.clone()));
    }
    if args.yes {
        return Ok(crate::handoff::Confirmation::Blanket);
    }
    if args.confirm && json {
        return Err(Box::new(error_result(
            2,
            "usage.confirmation_required",
            "`--confirm` reads the plan digest from the terminal and is never used with --json \
             (JSON never prompts): pass --confirm-digest HEX64"
                .to_string(),
            false,
        )));
    }
    let interactive =
        args.confirm || (!json && std::io::IsTerminal::is_terminal(&std::io::stdin()));
    if !interactive {
        return Err(Box::new(error_result(
            2,
            "usage.confirmation_required",
            crate::handoff::CONFIRMATION_REQUIRED.to_string(),
            false,
        )));
    }
    // Human confirmation: the prompt goes to stderr and the human types the
    // exact plan digest (binding the same digest the noninteractive mode
    // presents).
    eprintln!("authorize lane handoff plan {digest}");
    eprint!("type the plan digest to confirm (or 'abort'): ");
    let mut line = String::new();
    let read = std::io::stdin().read_line(&mut line);
    if let Err(err) = read {
        return Err(Box::new(lane_error(
            "refusal.confirmation.aborted",
            format!("cannot read the confirmation: {err}"),
            false,
        )));
    }
    let typed = line.trim();
    if typed.is_empty() || typed.eq_ignore_ascii_case("abort") {
        return Err(Box::new(lane_error(
            "refusal.confirmation.aborted",
            "the plan was not confirmed".to_string(),
            false,
        )));
    }
    Ok(crate::handoff::Confirmation::Digest(typed.to_string()))
}

/// The `lane.replacement.request` params for one authorized plan: exactly
/// the validated inputs the digest bound (never anything else), plus the
/// fresh or caller-supplied idempotency key.
fn lane_request_params(plan: &crate::handoff::LanePlan, key: Option<&str>) -> Val {
    let replacement_id = plan.replacement_id();
    let key = key.map(str::to_string).unwrap_or_else(|| {
        // The generated key is unique per invocation (replacement identity +
        // a per-process nonce): a re-run is a fresh claim, and the daemon's
        // record-level refusal is what keeps one successor owner. Automation
        // that needs replay semantics passes --idempotency-key explicitly.
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_secs())
            .unwrap_or(0);
        format!(
            "ik_lane-{}-{secs}-{}",
            &replacement_id[3..],
            client::fresh_id()
        )
    });
    let mut fields = vec![
        ("idempotency_key", string(&key)),
        ("lane_id", string(&plan.input.lane_id)),
        ("generation", integer(plan.input.generation)),
        ("source_session", string(&plan.input.session)),
        ("source_process", string(&plan.input.process)),
        ("role", string(&plan.input.role)),
        ("worktree", string(&plan.input.worktree)),
        ("reason", string(&plan.input.reason)),
    ];
    if let Some(profile) = &plan.profile {
        fields.push(("profile", profile.to_doc()));
    }
    object(fields)
}

/// `lane preview`: render the reviewable plan. Read-only: the only daemon
/// interaction is the read-only record/checkpoint read when a live daemon
/// exists; the preview never dispatches a mutation.
fn execute_lane_preview(args: &LaneArgs, invocation: &Invocation) -> CmdResult {
    let config = match load_optional_config(invocation) {
        Ok(config) => config,
        Err(result) => return result,
    };
    let plan = match build_lane_plan(args, config.as_ref()) {
        Ok(plan) => plan,
        Err(result) => return *result,
    };
    let socket = effective_socket(args.socket.as_deref(), config.as_ref());
    let mut diagnostics = String::new();
    let mut record: Option<Val> = None;
    let mut retained = crate::handoff::RetainedView::default();
    // The plan is local and read-only; the daemon enrichment (the durable
    // record and its retained block) is optional and degrades explicitly.
    match derive_paths(socket) {
        Ok(paths) => {
            if crate::lock::socket_presence(&paths.socket_path)
                == crate::lock::SocketPresence::Active
            {
                match read_only_lane_record(&paths.socket_path, &plan.replacement_id()) {
                    Ok(Some(status)) => {
                        retained = read_only_retained(&paths.socket_path, &plan.replacement_id());
                        record = Some(status);
                    }
                    Ok(None) => {}
                    Err(RpcError { code, message }) => {
                        diagnostics =
                            format!("read-only record read unavailable: {code}: {message}\n");
                    }
                }
            } else {
                diagnostics =
                    "no live daemon: the plan is rendered without the durable record (read-only)\n"
                        .to_string();
            }
        }
        Err(result) => {
            let detail = result
                .error
                .as_ref()
                .map(|error| format!("{}: {}", error.code, error.message))
                .unwrap_or_default();
            diagnostics = format!("read-only daemon enrichment unavailable ({detail})\n");
        }
    }
    let document = plan.document(
        config.as_ref().and_then(|config| config.policy.as_ref()),
        &retained,
        record.as_ref(),
    );
    let human = render_lane_preview_human(&document);
    let mut result = ok_result(document, human);
    result.diagnostics = diagnostics;
    result
}

/// `lane request`: authorize and record ONE explicit lane replacement
/// request through the daemon. This is the ONLY mutating dispatch site on
/// the lane surface.
fn execute_lane_request(args: &LaneRequestArgs, invocation: &Invocation) -> CmdResult {
    let config = match load_optional_config(invocation) {
        Ok(config) => config,
        Err(result) => return result,
    };
    let plan = match build_lane_plan(&args.plan, config.as_ref()) {
        Ok(plan) => plan,
        Err(result) => return *result,
    };
    let confirmation = match resolve_confirmation(args, &plan.digest, invocation.json) {
        Ok(confirmation) => confirmation,
        Err(result) => return *result,
    };
    if let Err(err) = crate::handoff::confirm(
        config.as_ref().and_then(|config| config.policy.as_ref()),
        &confirmation,
        &plan.digest,
    ) {
        return lane_error(err.code, err.message, false);
    }
    let socket = effective_socket(args.plan.socket.as_deref(), config.as_ref());
    let paths = match derive_paths(socket) {
        Ok(paths) => paths,
        Err(result) => return result,
    };
    if let Err(result) = require_live_daemon(&paths) {
        return *result;
    }
    let params = lane_request_params(&plan, args.idempotency_key.as_deref());
    match client::call(
        &paths.socket_path,
        "lane.replacement.request",
        Some(&params),
    ) {
        Ok(result) => {
            let replacement = result.get("replacement").cloned().unwrap_or_else(null);
            let replacement_id = replacement
                .get("replacement_id")
                .and_then(Val::as_str)
                .unwrap_or("")
                .to_string();
            let authorization = match confirmation {
                crate::handoff::Confirmation::Digest(_) => "digest",
                crate::handoff::Confirmation::Blanket => "blanket",
            };
            let data = object(vec![
                ("schema", string(crate::handoff::LANE_PLAN_SCHEMA)),
                ("plan_digest", string(&plan.digest)),
                ("authorization", string(authorization)),
                ("replacement", replacement),
                (
                    "profile",
                    result.get("profile").cloned().unwrap_or_else(null),
                ),
                (
                    "next",
                    object(vec![
                        ("operation", string("lane.replacement.status")),
                        (
                            "command",
                            string(&format!(
                                "canter lane status --replacement {replacement_id}"
                            )),
                        ),
                    ]),
                ),
            ]);
            let human = render_lane_request_human(&data);
            ok_result(data, human)
        }
        Err(RpcError { code, message }) => {
            lane_error(&code, format!("lane request: {message}"), false)
        }
    }
}

/// `lane status`: read one replacement record read-only and render the
/// status contract (phase, intended/actual binding, blocker, last verified
/// transition, next supported action, guidance). Never mutates; never
/// advances; never resumes anything.
fn execute_lane_status(args: &LaneStatusArgs, invocation: &Invocation) -> CmdResult {
    let config = match load_optional_config(invocation) {
        Ok(config) => config,
        Err(result) => return result,
    };
    let replacement_id = match &args.replacement {
        Some(replacement) => replacement.clone(),
        None => crate::state::replacement_id_for(
            args.lane_id.as_deref().unwrap_or_default(),
            args.generation.unwrap_or(0),
        ),
    };
    let socket = effective_socket(args.socket.as_deref(), config.as_ref());
    let paths = match derive_paths(socket) {
        Ok(paths) => paths,
        Err(result) => return result,
    };
    if let Err(result) = require_live_daemon(&paths) {
        return *result;
    }
    let status = match read_only_lane_record(&paths.socket_path, &replacement_id) {
        Ok(Some(status)) => status,
        Ok(None) => {
            return lane_error(
                "state.not_found",
                format!(
                    "no lane replacement {replacement_id:?} exists on this daemon; request one \
                     with `canter lane request`"
                ),
                false,
            );
        }
        Err(RpcError { code, message }) => {
            return lane_error(&code, format!("lane status: {message}"), false);
        }
    };
    let retained = read_only_retained(&paths.socket_path, &replacement_id);
    let document = crate::handoff::status_document(&status, &retained);
    let human = render_lane_status_human(&document);
    ok_result(document, human)
}

/// Execute one lane subcommand.
fn execute_lane(action: LaneAction, invocation: &Invocation) -> CmdResult {
    match action {
        LaneAction::Preview(args) => execute_lane_preview(&args, invocation),
        LaneAction::Request(args) => execute_lane_request(&args, invocation),
        LaneAction::Status(args) => execute_lane_status(&args, invocation),
    }
}

// ---------------------------------------------------------------------------
// queue (issue #85): the durable selected-run submission path
// ---------------------------------------------------------------------------

/// Execute one queue subcommand.
fn execute_queue(action: QueueAction, invocation: &Invocation) -> CmdResult {
    match action {
        QueueAction::Submit(args) => execute_queue_submit(&args, invocation),
        QueueAction::Status(args) => execute_queue_status(&args, invocation),
        QueueAction::Redrive(args) => execute_queue_redrive(&args, invocation),
        QueueAction::Preview(args) => execute_queue_preview(&args, invocation),
        QueueAction::Intake(args) => execute_queue_intake(&args, invocation),
    }
}

/// The reviewed role-configuration binding re-observed from the CURRENT
/// configuration (never a value from argv): the fresh `hf-profile-binding/v1`
/// document plus its revision. A missing config, unknown harness or
/// unbound harness refuses before any daemon call — the daemon compares the
/// re-observed revision against the approval binding.
fn fresh_role_binding(
    config: Option<&Config>,
    harness_key: &str,
) -> Result<(Val, String), Box<CmdResult>> {
    let Some(config) = config else {
        return Err(Box::new(error_result(
            5,
            "config.not_found",
            format!(
                "queue submit needs the profile configuration to re-observe the reviewed role \
                 revision for {harness_key:?}; run `canter config init` and save the template, or \
                 pass --config PATH"
            ),
            false,
        )));
    };
    let Some(harness) = config
        .harnesses
        .iter()
        .find(|harness| harness.key == *harness_key)
    else {
        return Err(Box::new(error_result(
            5,
            "config.harness",
            format!(
                "no configured harness {harness_key:?}; the reviewed role configuration names a \
                 configured harness key (see `canter config show --json`)"
            ),
            false,
        )));
    };
    let env = crate::config::credential_environment(harness);
    match crate::config::ProfileBinding::from_config(config, harness_key, &env) {
        Some(binding) => Ok((binding.to_doc(), binding.revision)),
        None => Err(Box::new(error_result(
            5,
            "config.harness",
            format!(
                "harness {harness_key:?} declares no provider/model binding; there is no \
                 re-observed role configuration to submit against"
            ),
            false,
        ))),
    }
}

/// Grant subcommand dispatch (issue #92).
fn execute_grant(action: GrantAction, invocation: &Invocation) -> CmdResult {
    match action {
        GrantAction::Issue(args) => execute_grant_issue(&args, invocation),
    }
}

/// `grant issue` (issue #92): mint ONE route grant through the daemon from
/// the reviewed bound-input document.
///
/// The whole binding is DERIVED — the document the operator reviewed plus the
/// configuration re-observed now plus the live epoch and an explicit expiry —
/// and the daemon is the authority that validates, journals and inserts it
/// (`grants.issue`). Issuance is not authorization: what the operator
/// authorizes is still the reviewed digest at the board/`queue submit` point,
/// with the minted grant id presented as the binding.
fn execute_grant_issue(args: &GrantIssueArgs, invocation: &Invocation) -> CmdResult {
    let config = match load_optional_config(invocation) {
        Ok(config) => config,
        Err(result) => return result,
    };
    let text = match std::fs::read_to_string(&args.request_path) {
        Ok(text) => text,
        Err(err) => {
            return lane_error(
                "usage.grant_request",
                format!(
                    "grant issue: cannot read {} ({err}); --request names the reviewed \
                     bound-input document",
                    args.request_path.display()
                ),
                false,
            );
        }
    };
    let bound = match Val::parse_json(&text) {
        Ok(bound @ Val::Obj(_)) => bound,
        _ => {
            return lane_error(
                "usage.grant_request",
                format!(
                    "grant issue: {} must carry one bound-input preview document (JSON object)",
                    args.request_path.display()
                ),
                false,
            );
        }
    };
    let plan_digest = match crate::queue_executor::bound_digest(&bound) {
        Ok(digest) => digest,
        Err(err) => return lane_error(err.code, err.message, false),
    };
    // The reviewed role configuration is re-observed from the CURRENT config
    // (the same rule `queue submit` applies): the grant's policy hash is that
    // revision, so a moved configuration refuses typed before anything is
    // sent and never mints a grant against a stale role.
    let harness_key = bound
        .get("role_config")
        .and_then(|role| role.get("key"))
        .and_then(Val::as_str)
        .unwrap_or_default()
        .to_string();
    if harness_key.is_empty() {
        return lane_error(
            "usage.grant_request",
            "grant issue: the bound-input document requires role_config.key (the reviewed role \
             configuration)"
                .to_string(),
            false,
        );
    }
    let (binding_doc, role_revision) = match fresh_role_binding(config.as_ref(), &harness_key) {
        Ok(pair) => pair,
        Err(result) => return *result,
    };
    // One strict reading of the document: the same typed rebuild the
    // submission and the operator surface use (closed key set, foreign
    // schema refused, the presented role revision must agree with the
    // re-observed one).
    let material = crate::queue_executor::SubmissionMaterial {
        idempotency_key: String::new(),
        preview: bound.clone(),
        binding: binding_doc,
        digest: plan_digest.clone(),
        epoch: 0,
        role_revision: role_revision.clone(),
        caps: crate::lifecycle::ConcurrencyCaps::default(),
        host_available: None,
        harness_lanes: None,
        grants: Vec::new(),
        resume: Vec::new(),
        supervision: None,
    };
    let request = match crate::queue_executor::presented_request(&material) {
        Ok(request) => request,
        Err(err) => return lane_error(err.code, err.message, false),
    };
    // The reviewed completion boundary and its capabilities: only the closed
    // grant sets reach the wire, and a production-class binding is refused
    // here and again in the daemon (production authority is human-only).
    let phase = request.boundary.phase.clone();
    if !crate::schema::GRANT_PHASES.contains(&phase.as_str()) {
        return lane_error(
            "usage.grant_boundary",
            format!(
                "grant issue: the reviewed boundary phase {phase:?} is outside the closed grant \
                 phase set"
            ),
            false,
        );
    }
    for cap in &request.boundary.caps {
        if !crate::schema::GRANT_CAPS.contains(&cap.as_str()) {
            return lane_error(
                "usage.grant_boundary",
                format!(
                    "grant issue: the reviewed boundary capability {cap:?} is outside the closed \
                     grant capability set"
                ),
                false,
            );
        }
    }
    if phase == "production"
        || request
            .boundary
            .caps
            .iter()
            .any(|cap| cap == "production" || cap == "release")
    {
        return lane_error(
            crate::mutation::code::PRODUCTION_CONFIRMATION,
            "grant issue: a production-class binding (phase/capability) is never minted over the \
             socket surface; production authority requires a fresh interactive TTY-confirmed \
             digest, which this surface does not carry"
                .to_string(),
            false,
        );
    }
    if !crate::formats::is_hex64(&request.workflow_hash) {
        return lane_error(
            "usage.grant_request",
            format!(
                "grant issue: the reviewed workflow hash {:?} is not the 64-hex digest the grant \
                 binds",
                request.workflow_hash
            ),
            false,
        );
    }
    // The reviewed selected issue the grant binds: its identity and its
    // exact acceptance revision come from the document, never from argv.
    let selected = request.selected.iter().find(|issue| {
        crate::queue_preview::IssueId::parse(&issue.id, &request.repository)
            .map(|id| id.number == args.issue)
            .unwrap_or(false)
    });
    let Some(selected) = selected else {
        let reviewed: Vec<String> = request
            .selected
            .iter()
            .map(|issue| issue.id.clone())
            .collect();
        return lane_error(
            "usage.grant_issue",
            format!(
                "grant issue: --issue {} is not one of the reviewed selected issues ({})",
                args.issue,
                reviewed.join(", ")
            ),
            false,
        );
    };
    if !crate::formats::is_hex40(&selected.revision) {
        return lane_error(
            "usage.grant_issue",
            format!(
                "grant issue: the reviewed acceptance revision {:?} for issue {} is not 40-hex",
                selected.revision, args.issue
            ),
            false,
        );
    }
    // The repository identity comes from the validated configuration, never
    // from argv or from the document alone.
    let configured_repository = config
        .as_ref()
        .map(|config| {
            config
                .repositories
                .iter()
                .any(|repository| repository.identity() == request.repository)
        })
        .unwrap_or(false);
    if !configured_repository {
        return lane_error(
            "            ",
            format!(
                "grant issue: the reviewed document binds {:?}, which is not a configured \
                 repository of this installation (see `canter config show --json`)",
                request.repository
            ),
            false,
        );
    }
    let socket = effective_socket(args.socket.as_deref(), config.as_ref());
    let paths = match derive_paths(socket) {
        Ok(paths) => paths,
        Err(result) => return result,
    };
    if let Err(result) = require_live_daemon(&paths) {
        return *result;
    }
    // The live epoch: the grant dies with its epoch, so the mint binds the
    // epoch the daemon holds right now (a moved epoch refuses typed).
    let epoch = {
        let params = object(vec![]);
        match read_only_call(&paths.socket_path, "state.epoch", Some(&params)) {
            Ok(result) => result
                .get("epoch")
                .and_then(|epoch| epoch.get("epoch"))
                .and_then(Val::as_int)
                .unwrap_or(0),
            Err(RpcError { code, message }) => {
                return lane_error(&code, format!("grant issue: {message}"), false);
            }
        }
    };
    let now = crate::time::unix_now();
    let created_at = crate::time::rfc3339_from_unix(now);
    let expires_at = crate::time::rfc3339_from_unix(now + args.expires_in);
    let scope = format!("worktrees/issues/{}", args.issue);
    let key = args
        .idempotency_key
        .clone()
        .unwrap_or_else(|| format!("ik_grant-{now}-{}", client::fresh_id()));
    let grant_id = grant_id_for(
        &request,
        args.issue,
        &selected.revision,
        &role_revision,
        &scope,
        epoch,
        &key,
    );
    let caps: Vec<Val> = request
        .boundary
        .caps
        .iter()
        .map(|cap| string(cap))
        .collect();
    let document = object(vec![
        ("schema", string("hf-grant/v1")),
        ("grant_id", string(&grant_id)),
        ("repository", string(&request.repository)),
        (
            "issue",
            object(vec![
                ("number", integer(args.issue)),
                ("revision", string(&selected.revision)),
            ]),
        ),
        ("workflow_hash", string(&request.workflow_hash)),
        ("policy_hash", string(&role_revision)),
        ("phase", string(&phase)),
        ("scope", string(&scope)),
        ("caps", Val::Arr(caps)),
        ("expires_at", string(&expires_at)),
        ("state_epoch", integer(epoch)),
        ("created_at", string(&created_at)),
    ]);
    let params = object(vec![
        ("grant", document.clone()),
        ("idempotency_key", string(&key)),
    ]);
    let minted = match client::call(&paths.socket_path, "grants.issue", Some(&params)) {
        Ok(minted @ Val::Obj(_)) => minted,
        Ok(_) => {
            return lane_error(
                "daemon.response",
                "grant issue: the daemon returned no grant document".to_string(),
                false,
            );
        }
        Err(RpcError { code, message }) => {
            return lane_error(&code, format!("grant issue: {message}"), false);
        }
    };
    if !grant_binding_matches(&minted, &document) {
        return lane_error(
            "daemon.grant_mismatch",
            "grant issue: the daemon returned a grant document that does not match the requested \
             binding (nothing is treated as authorized)"
                .to_string(),
            false,
        );
    }
    let next = format!("canter board --plan FILE --grant {}={grant_id}", args.issue);
    let data = object(vec![
        ("schema", string("hf-grant/v1")),
        ("grant_id", string(&grant_id)),
        ("plan_digest", string(&plan_digest)),
        ("grant", minted),
        (
            "next",
            object(vec![
                ("command", string(&next)),
                (
                    "note",
                    string(
                        "the board (or `queue submit`) remains the authorization point: minting is \
                         not authorization",
                    ),
                ),
            ]),
        ),
    ]);
    let human = render_grant_issue_human(&data);
    ok_result(data, human)
}

/// A grant binds one explicit issuance as well as the reviewed material.
/// A fresh invocation opens a fresh window without extending any old grant;
/// reusing its key is still refused by the daemon's exactly-once claim fence.
fn grant_id_for(
    request: &crate::queue_preview::QueueRequest,
    issue_number: i64,
    issue_revision: &str,
    policy_hash: &str,
    scope: &str,
    state_epoch: i64,
    issuance: &str,
) -> String {
    let caps: Vec<Val> = request
        .boundary
        .caps
        .iter()
        .map(|cap| string(cap))
        .collect();
    let preimage = object(vec![
        ("schema", string("hf-grant-id/v1")),
        ("issuance", string(issuance)),
        ("repository", string(&request.repository)),
        (
            "issue",
            object(vec![
                ("number", integer(issue_number)),
                ("revision", string(issue_revision)),
            ]),
        ),
        ("workflow_hash", string(&request.workflow_hash)),
        ("policy_hash", string(policy_hash)),
        ("phase", string(&request.boundary.phase)),
        ("scope", string(scope)),
        ("caps", Val::Arr(caps)),
        ("state_epoch", integer(state_epoch)),
    ]);
    format!(
        "gr_{}",
        &crate::canonical::sha256_hex(&canonical_bytes(&preimage))[..16]
    )
}

/// Cross-check the minted document against the exact binding this invocation
/// derived: every contract key must agree (an extra key the daemon may add in
/// a later slice is tolerated; a moved binding is not).
fn grant_binding_matches(minted: &Val, requested: &Val) -> bool {
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
    KEYS.iter()
        .all(|key| match (minted.get(key), requested.get(key)) {
            (Some(left), Some(right)) => canonical_bytes(left) == canonical_bytes(right),
            _ => false,
        })
}

/// The human rendering of one minted grant (the same data the JSON envelope
/// carries; never a second contract).
fn render_grant_issue_human(data: &Val) -> String {
    let text = |path: &[&str]| -> String {
        let mut current = data;
        for key in path {
            match current.get(key) {
                Some(value) => current = value,
                None => return String::new(),
            }
        }
        current.as_str().unwrap_or_default().to_string()
    };
    let grant_id = text(&["grant_id"]);
    let grant = data.get("grant").cloned().unwrap_or_else(null);
    let number = grant
        .get("issue")
        .and_then(|issue| issue.get("number"))
        .and_then(Val::as_int)
        .unwrap_or(0);
    let revision = grant
        .get("issue")
        .and_then(|issue| issue.get("revision"))
        .and_then(Val::as_str)
        .unwrap_or_default()
        .to_string();
    let caps = grant
        .get("caps")
        .and_then(Val::as_array)
        .map(|caps| {
            caps.iter()
                .filter_map(Val::as_str)
                .collect::<Vec<&str>>()
                .join(",")
        })
        .unwrap_or_default();
    let mut out = String::new();
    out.push_str(&format!("grant {grant_id} issued (active)\n"));
    out.push_str(&format!(
        "  binds {}#{number}@{revision}\n",
        text(&["grant", "repository"])
    ));
    out.push_str(&format!(
        "  phase {} · scope {} · caps {caps}\n",
        text(&["grant", "phase"]),
        text(&["grant", "scope"])
    ));
    out.push_str(&format!(
        "  workflow_hash {}\n  policy_hash   {}\n",
        text(&["grant", "workflow_hash"]),
        text(&["grant", "policy_hash"])
    ));
    out.push_str(&format!(
        "  state_epoch {} · created {} · expires {}\n",
        text(&["grant", "state_epoch"]),
        text(&["grant", "created_at"]),
        text(&["grant", "expires_at"])
    ));
    out.push_str(&format!(
        "  reviewed plan digest {}\n",
        text(&["plan_digest"])
    ));
    out.push_str(&format!("next: {}\n", text(&["next", "command"])));
    out
}

/// `queue submit`: authorize and commit ONE approved selected-issue run.
/// The local preflight is exactly the digest check plus the config
/// re-observation; every durable fact is the daemon's to revalidate.
/// `queue intake` (issue #245): the deterministic feeder.
///
/// One invocation turns the repository's OWN issue state into one bound-input
/// submission: the open issues carrying the ready label are selected in
/// ascending issue-number order, each revision resolves by the documented
/// rule (a tracker-declared `--pin` wins; otherwise the repository's
/// integration head at intake time), an issue that is already owned or queued
/// is never re-submitted, items beyond the declared bound wait instead of
/// bypassing admission, and an unresolvable revision refuses typed without
/// submitting anything. `--dry-run` renders the decision and mutates nothing.
///
/// The document, the grants and the submission are the SAME surfaces the
/// operator path uses (`queue preview` → `grant issue` per item →
/// `queue submit`); intake never invents a submission path of its own.
fn execute_queue_intake(args: &QueueIntakeArgs, invocation: &Invocation) -> CmdResult {
    let config = match required_config(&invocation.config_path) {
        Ok(config) => config,
        Err(result) => return *result,
    };
    let repository = match resolve_repository(&config, &args.repository) {
        Ok(repository) => repository,
        Err(message) => {
            return error_result(
                2,
                "usage.error",
                format!("queue intake: {message}; run `canter queue intake --help`"),
                false,
            );
        }
    };
    let identity = repository.identity();
    // The reviewed role configuration is re-observed from the CURRENT config
    // (never free-form argv): an unknown or unbound harness refuses before
    // anything is read or rendered.
    let Some(harness) = config
        .harnesses
        .iter()
        .find(|harness| harness.key == args.harness)
    else {
        return error_result(
            5,
            "config.harness",
            format!(
                "queue intake: no configured harness {:?}; --harness names a configured \
                 harness key (see `canter config show --json`)",
                args.harness
            ),
            false,
        );
    };
    if crate::config::ProfileBinding::from_config(
        &config,
        &args.harness,
        &crate::config::credential_environment(harness),
    )
    .is_none()
    {
        return error_result(
            5,
            "config.harness",
            format!(
                "queue intake: harness {:?} declares no provider/model binding; there is no \
                 re-observed role configuration to bind",
                args.harness
            ),
            false,
        );
    }
    // The ready issue set, read from the repository's own API surface (no
    // model, no agent, no third-party service).
    let env = crate::config::adapter_environment();
    let gh_args = vec![
        "api".to_string(),
        format!(
            "repos/{identity}/issues?state=open&labels={}&per_page=100",
            args.label
        ),
    ];
    let listed = crate::process::run(crate::process::ProcSpec {
        program: "gh",
        args: &gh_args,
        env: &env,
        cwd: None,
        timeout: std::time::Duration::from_secs(30),
    });
    if listed.status.exit_code() != Some(0) {
        let detail = crate::observe::diagnostics(&format!("{}\n{}", listed.stderr, listed.stdout));
        return lane_error(
            crate::intake::code::ISSUES_UNAVAILABLE,
            format!(
                "queue intake: the repository's own issue surface could not be read (gh api \
                 {identity} issues): {detail}"
            ),
            false,
        );
    }
    let listed_text = crate::redact::redact(&listed.stdout);
    let listed_doc = match Val::parse_json(&listed_text) {
        Ok(doc) => doc,
        Err(err) => {
            return lane_error(
                crate::intake::code::ISSUES_UNAVAILABLE,
                format!("queue intake: the issue surface returned unparsable JSON: {err}"),
                false,
            );
        }
    };
    let Some(entries) = listed_doc.as_array() else {
        return lane_error(
            crate::intake::code::ISSUES_UNAVAILABLE,
            "queue intake: the issue surface did not return one JSON array of issues".to_string(),
            false,
        );
    };
    // Selection is a rule: OPEN, carrying the ready label, and never a pull
    // request (the issues surface carries both).
    let mut candidates: Vec<crate::intake::Candidate> = Vec::new();
    for entry in entries {
        if entry.get("pull_request").is_some() {
            continue;
        }
        if entry.get("state").and_then(Val::as_str) != Some("open") {
            continue;
        }
        let labelled = entry
            .get("labels")
            .and_then(Val::as_array)
            .map(|labels| {
                labels.iter().any(|label| {
                    label.get("name").and_then(Val::as_str) == Some(args.label.as_str())
                })
            })
            .unwrap_or(false);
        if !labelled {
            continue;
        }
        if let Some(number) = entry.get("number").and_then(Val::as_int)
            && number > 0
        {
            candidates.push(crate::intake::Candidate {
                number: number as u64,
                pin: args
                    .pins
                    .iter()
                    .find(|(pinned, _)| *pinned == number as u64)
                    .map(|(_, revision)| revision.clone()),
            });
        }
    }
    // The default revision rule: the repository's integration head at intake
    // time, read from the remote (never from a stale local ref).
    let integration = args
        .integration_branch
        .clone()
        .or_else(|| repository.branch.clone())
        .unwrap_or_else(|| "staging".to_string());
    let integration_head = match crate::observe::ls_remote_head(&env, &integration) {
        Ok(head) => head,
        Err(detail) => {
            return lane_error(
                crate::intake::code::INTEGRATION_UNRESOLVED,
                format!(
                    "queue intake: the integration head of {integration:?} could not be resolved \
                     from the repository remote: {detail}"
                ),
                false,
            );
        }
    };
    // Dedupe before submit: live ownership is read from the recorded state
    // store (the same store the daemon writes), never inferred.
    let socket = effective_socket(args.socket.as_deref(), Some(&config));
    let paths = match derive_paths(socket) {
        Ok(paths) => paths,
        Err(result) => return result,
    };
    if !paths.db_path.exists() {
        return error_result(
            1,
            "queue.no_state",
            format!(
                "no daemon state store at {}; run `canter daemon run` first (intake only reads \
                 recorded ownership to decide what is already queued)",
                paths.db_path.display()
            ),
            false,
        );
    }
    let state = match State::open(&paths.db_path, Retention::default()) {
        Ok(state) => state,
        Err(err) => {
            return error_result(
                1,
                err.code,
                format!("queue intake: state store unavailable: {}", err.message),
                false,
            );
        }
    };
    let owned: std::collections::BTreeSet<u64> = match state.queue_ownership_rows() {
        Ok(rows) => rows
            .into_iter()
            .filter(|row| row.repository == identity)
            .map(|row| row.issue_number as u64)
            .collect(),
        Err(err) => {
            return error_result(
                1,
                err.code,
                format!("queue intake: ownership read failed: {}", err.message),
                false,
            );
        }
    };
    let decision = match crate::intake::decide(
        &candidates,
        integration_head.as_deref(),
        &owned,
        args.max_items,
    ) {
        Ok(decision) => decision,
        Err(err) => return lane_error(err.code, format!("queue intake: {}", err.message), false),
    };
    let mut data = crate::intake::render(&decision, &identity);
    let held = decision.held();
    let mut human = format!(
        "queue intake {identity} ({} selected of {} ready issue(s), label {:?}, order {})\n",
        decision.selected.len(),
        decision.items.len(),
        args.label,
        crate::intake::ORDER_RULE
    );
    human.push_str(&format!("plan digest sha256 {}\n", decision.digest));
    for (number, code, message) in &held {
        human.push_str(&format!("hold {number} {code}: {message}\n"));
    }
    if args.dry_run {
        // AC3: the dry run prints the exact decision and mutates nothing —
        // no submission, no grants, no run records, no journal entries and no
        // written document.
        human.push_str(
            "dry-run: nothing was submitted, no grant was issued, no document was written\n",
        );
        if let Val::Obj(map) = &mut data {
            map.insert("dry_run".to_string(), crate::value::bool_(true));
        }
        return ok_result(data, human);
    }
    let out_path = args
        .out
        .clone()
        .expect("--out is required unless --dry-run (parse_queue_intake)");
    if decision.selected.is_empty() {
        return lane_error(
            "refusal.intake.empty",
            format!(
                "queue intake: no issue is selectable in {identity} (every ready issue is \
                 already owned, capped or absent); nothing was submitted"
            ),
            false,
        );
    }
    // The bound-input document: the same render the operator path produces,
    // written to `--out` and bound by the digest the submission confirms.
    let rendered = execute_queue_preview(
        &QueuePreviewArgs {
            repository: args.repository.clone(),
            selected: decision.selected.clone(),
            harness: args.harness.clone(),
            reviewer_harness: None,
            host: args.host.clone(),
            host_available: args.host_available,
            harness_lanes: args.harness_lanes,
            caps: args.caps,
            boundary_phase: None,
            integration_branch: Some(integration.clone()),
            completion_branch: None,
            out: Some(out_path.clone()),
            execution: ExecutionMode::HerdrPane,
            socket: args.socket.clone(),
        },
        invocation,
    );
    if rendered.exit_code != 0 {
        return rendered;
    }
    let digest = rendered
        .data
        .as_ref()
        .and_then(|doc| doc.get("digest"))
        .and_then(Val::as_str)
        .unwrap_or("")
        .to_string();
    // One grant per selected item, under the declared expiry policy: the
    // same mint path the operator presents at the authorization point.
    let mut grants: Vec<(String, String)> = Vec::new();
    for (number, _) in &decision.selected {
        let minted = execute_grant_issue(
            &GrantIssueArgs {
                request_path: out_path.clone(),
                issue: *number as i64,
                expires_in: GRANT_EXPIRY_MAX_SECS,
                idempotency_key: None,
                socket: args.socket.clone(),
            },
            invocation,
        );
        if minted.exit_code != 0 {
            return minted;
        }
        let grant_id = minted
            .data
            .as_ref()
            .and_then(|doc| doc.get("grant_id"))
            .and_then(Val::as_str)
            .unwrap_or("")
            .to_string();
        grants.push((number.to_string(), grant_id));
    }
    let submitted = execute_queue_submit(
        &QueueSubmitArgs {
            request_path: out_path.clone(),
            confirm_digest: digest.clone(),
            epoch: None,
            grants,
            resume: Vec::new(),
            host_available: args.host_available,
            harness_lanes: args.harness_lanes,
            caps: args.caps,
            supervise: args.supervise.clone(),
            topology: args.topology.clone(),
            idempotency_key: None,
            socket: args.socket.clone(),
        },
        invocation,
    );
    if submitted.exit_code != 0 {
        return submitted;
    }
    let mut submitted_data = submitted.data.clone().unwrap_or_else(crate::value::null);
    if let Val::Obj(map) = &mut submitted_data {
        map.insert("intake".to_string(), data);
        map.insert("digest".to_string(), string(&digest));
        map.insert("out".to_string(), string(&out_path.display().to_string()));
    }
    human.push_str(&format!(
        "submitted: document {} bound by digest {digest}\n",
        out_path.display()
    ));
    human.push_str(&submitted.human);
    ok_result(submitted_data, human)
}

fn execute_queue_submit(args: &QueueSubmitArgs, invocation: &Invocation) -> CmdResult {
    let text = match std::fs::read_to_string(&args.request_path) {
        Ok(text) => text,
        Err(err) => {
            return error_result(
                2,
                "usage.queue_request",
                format!(
                    "queue submit: cannot read {} ({err}); --request names the bound-input preview \
                     document",
                    args.request_path.display()
                ),
                false,
            );
        }
    };
    let bound = match Val::parse_json(&text) {
        Ok(bound @ Val::Obj(_)) => bound,
        _ => {
            return error_result(
                2,
                "usage.queue_request",
                format!(
                    "queue submit: {} must carry one bound-input preview document (JSON object)",
                    args.request_path.display()
                ),
                false,
            );
        }
    };
    let computed = match crate::queue_executor::bound_digest(&bound) {
        Ok(digest) => digest,
        Err(err) => return lane_error(err.code, err.message, false),
    };
    if computed != args.confirm_digest {
        return lane_error(
            "refusal.plan.stale",
            format!(
                "the presented --confirm-digest {} is not the digest of {} ({computed}); the \
                 approval must bind the exact reviewed bound-input document",
                args.confirm_digest,
                args.request_path.display()
            ),
            false,
        );
    }
    let harness_key = bound
        .get("role_config")
        .and_then(|role| role.get("key"))
        .and_then(Val::as_str)
        .unwrap_or_default()
        .to_string();
    let config = match load_optional_config(invocation) {
        Ok(config) => config,
        Err(result) => return result,
    };
    let (binding, role_revision) = match fresh_role_binding(config.as_ref(), &harness_key) {
        Ok(pair) => pair,
        Err(result) => return *result,
    };
    let socket = effective_socket(args.socket.as_deref(), config.as_ref());
    let paths = match derive_paths(socket) {
        Ok(paths) => paths,
        Err(result) => return result,
    };
    if let Err(result) = require_live_daemon(&paths) {
        return *result;
    }
    let epoch = match args.epoch {
        Some(epoch) => epoch,
        None => {
            let params = object(vec![]);
            match read_only_call(&paths.socket_path, "state.epoch", Some(&params)) {
                Ok(result) => result
                    .get("epoch")
                    .and_then(|epoch| epoch.get("epoch"))
                    .and_then(Val::as_int)
                    .unwrap_or(0),
                Err(RpcError { code, message }) => {
                    return lane_error(&code, format!("queue submit: {message}"), false);
                }
            }
        }
    };
    let key = args.idempotency_key.clone().unwrap_or_else(|| {
        // A fresh per-invocation key: a re-run is a fresh claim, and the
        // daemon's record-level refusals keep one owner per issue.
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_secs())
            .unwrap_or(0);
        format!("ik_queue-{secs}-{}", client::fresh_id())
    });
    let grants: Vec<crate::queue_executor::ItemGrant> = args
        .grants
        .iter()
        .map(|(id, grant_id)| crate::queue_executor::ItemGrant {
            id: id.clone(),
            grant_id: grant_id.clone(),
        })
        .collect();
    let resume: Vec<crate::queue_executor::ResumeAuthorization> = args
        .resume
        .iter()
        .map(
            |(instance_id, digest)| crate::queue_executor::ResumeAuthorization {
                instance_id: instance_id.clone(),
                digest: digest.clone(),
            },
        )
        .collect();
    let mut params = crate::queue_executor::submit_params(
        &key,
        &args.confirm_digest,
        epoch,
        &bound,
        &binding,
        &role_revision,
        args.caps,
        args.host_available,
        args.harness_lanes,
        &grants,
        &resume,
        Some(&crate::supervision::Authorization {
            desired: args.supervise.clone(),
            policy: crate::supervision::Policy::default(),
        })
        .filter(|authorization| authorization.desired == "armed"),
    );
    if let Some(path) = &args.topology {
        let topology = match std::fs::read_to_string(path)
            .ok()
            .and_then(|text| Val::parse_json(&text).ok())
        {
            Some(topology @ Val::Obj(_)) => topology,
            _ => {
                return error_result(
                    2,
                    "usage.queue_topology",
                    format!(
                        "queue submit: --topology {} must be one JSON object",
                        path.display()
                    ),
                    false,
                );
            }
        };
        if let Val::Obj(map) = &mut params {
            map.insert(
                "dispatch".to_string(),
                object(vec![
                    ("topology", topology),
                    (
                        "admission",
                        object(vec![
                            (
                                "caps",
                                object(vec![
                                    ("global", integer(args.caps.global as i64)),
                                    ("repository", integer(args.caps.per_repository as i64)),
                                    ("harness", integer(args.caps.per_harness as i64)),
                                ]),
                            ),
                            (
                                "harness_lanes",
                                args.harness_lanes.map(integer).unwrap_or_else(null),
                            ),
                            (
                                "host_proof",
                                object(vec![("measured_at", string(&crate::time::rfc3339_now()))]),
                            ),
                        ]),
                    ),
                ]),
            );
        }
    }
    match client::call(&paths.socket_path, "queue.submit", Some(&params)) {
        Ok(result) => {
            let human = crate::queue_executor::render_human(&result);
            ok_result(result, human)
        }
        Err(RpcError { code, message }) => {
            lane_error(&code, format!("queue submit: {message}"), false)
        }
    }
}

/// `queue status`: read one committed submission document back read-only.
fn execute_queue_status(args: &QueueStatusArgs, invocation: &Invocation) -> CmdResult {
    let config = match load_optional_config(invocation) {
        Ok(config) => config,
        Err(result) => return result,
    };
    let socket = effective_socket(args.socket.as_deref(), config.as_ref());
    let paths = match derive_paths(socket) {
        Ok(paths) => paths,
        Err(result) => return result,
    };
    if let Err(result) = require_live_daemon(&paths) {
        return *result;
    }
    let params = object(vec![("submission_id", string(&args.submission))]);
    match read_only_call(&paths.socket_path, "queue.status", Some(&params)) {
        Ok(result) => {
            let human = crate::queue_executor::render_human(&result);
            ok_result(result, human)
        }
        Err(RpcError { code, message }) => {
            lane_error(&code, format!("queue status: {message}"), false)
        }
    }
}

/// `queue redrive` (#236): re-evaluate ONE committed submission's parked
/// (`waiting`) items against the live capacity, through the submission's OWN
/// approved admission inputs. This is the bounded, audited operator control
/// that recovers a submission stranded by a transient cap: the queue cursor
/// only moves on a verified delivery, so nothing else could re-drive it.
/// Nothing is spawned or killed here — an admitted item is admitted exactly
/// as a fresh submission would admit it, and a lane that is live is never
/// touched (a submission with nothing parked refuses typed).
fn execute_queue_redrive(args: &QueueRedriveArgs, invocation: &Invocation) -> CmdResult {
    let config = match load_optional_config(invocation) {
        Ok(config) => config,
        Err(result) => return result,
    };
    let socket = effective_socket(args.socket.as_deref(), config.as_ref());
    let paths = match derive_paths(socket) {
        Ok(paths) => paths,
        Err(result) => return result,
    };
    if let Err(result) = require_live_daemon(&paths) {
        return *result;
    }
    let params = object(vec![
        ("submission_id", string(&args.submission)),
        // A fresh per-invocation key (the same shape `queue submit` mints): a
        // re-run of the control is a fresh claim, and the daemon's claim
        // fence keeps exactly one effect per key.
        ("idempotency_key", string(&fresh_redrive_key())),
    ]);
    match client::call(&paths.socket_path, "queue.redrive", Some(&params)) {
        Ok(result) => {
            let human = crate::queue_executor::render_human(&result);
            ok_result(result, human)
        }
        Err(RpcError { code, message }) => {
            lane_error(&code, format!("queue redrive: {message}"), false)
        }
    }
}

/// `queue preview` (issue #91): render the effect-free preview of one
/// reviewed run and produce its bound-input document — the plan producer
/// the operator path consumes.
///
/// Read-only by construction: the render is the real #84 preview service
/// over the recorded state store (the same store the daemon writes), the
/// repository identity and the role binding are re-observed from
/// configuration (never free-form argv), and the declared spine is the
/// doctrine spine with resolved parameters. Nothing is spawned, no grant is
/// issued, and no external state is written; the emitted digest is the
/// exact authorization a `queue submit --confirm-digest` (or the operator
/// surface) binds.
fn execute_queue_preview(args: &QueuePreviewArgs, invocation: &Invocation) -> CmdResult {
    let config = match required_config(&invocation.config_path) {
        Ok(config) => config,
        Err(result) => return *result,
    };
    let repository = match resolve_repository(&config, &args.repository) {
        Ok(repository) => repository,
        Err(message) => {
            return error_result(
                2,
                "usage.error",
                format!("queue preview: {message}; run `canter queue preview --help`"),
                false,
            );
        }
    };
    // The reviewed role configuration: re-observed from the CURRENT config
    // exactly as `queue submit` re-observes it (a revision the operator
    // cannot edit). A missing/unknown/unbound harness refuses before any
    // state is touched.
    let Some(harness) = config
        .harnesses
        .iter()
        .find(|harness| harness.key == args.harness)
    else {
        return error_result(
            5,
            "config.harness",
            format!(
                "no configured harness {:?}; --harness names a configured harness key (see \
                 `canter config show --json`)",
                args.harness
            ),
            false,
        );
    };
    let env = crate::config::credential_environment(harness);
    let Some(binding) = crate::config::ProfileBinding::from_config(&config, &args.harness, &env)
    else {
        return error_result(
            5,
            "config.harness",
            format!(
                "harness {:?} declares no provider/model binding; there is no re-observed role \
                 configuration to preview",
                args.harness
            ),
            false,
        );
    };
    // The workflow binding: the same rule as `canter plan` (a configured pin
    // that names another workflow is refused; the workflow engine is a later
    // slice), otherwise the hash derived from the doctrine spine itself.
    let workflow = config
        .workflows
        .iter()
        .find(|pin| pin.id == DOCTRINE_WORKFLOW_ID)
        .or_else(|| config.workflows.first());
    if let Some(pin) = workflow.filter(|pin| pin.id != DOCTRINE_WORKFLOW_ID) {
        return error_result(
            4,
            "refusal.workflow.unsupported",
            format!(
                "the configured workflow pin {:?} is not supported by this read-only core (only \
                 {DOCTRINE_WORKFLOW_ID} is available; the workflow engine lands with a later \
                 slice)",
                pin.id
            ),
            false,
        );
    }
    // The reviewed selected set: stable issue identity plus its exact
    // 40-hex spec revision, sorted and deduplicated. The same issue with
    // two different revisions is a conflict, never a silent pick.
    let mut selected = args.selected.clone();
    selected.sort();
    let mut unique: Vec<(u64, String)> = Vec::new();
    for (number, revision) in selected {
        match unique.last() {
            Some((seen, other)) if *seen == number => {
                if other != &revision {
                    return error_result(
                        2,
                        "usage.queue_issue",
                        format!(
                            "queue preview: issue #{number} is presented twice with conflicting \
                             spec revisions ({other}, {revision})"
                        ),
                        false,
                    );
                }
            }
            _ => unique.push((number, revision)),
        }
    }
    let issues: Vec<u64> = unique.iter().map(|(number, _)| *number).collect();
    let integration = args
        .integration_branch
        .clone()
        .or_else(|| repository.branch.clone())
        .unwrap_or_else(|| "staging".to_string());
    let completion = args
        .completion_branch
        .clone()
        .unwrap_or_else(|| integration.clone());
    let phase = args
        .boundary_phase
        .clone()
        .unwrap_or_else(|| "merge".to_string());
    // The declared executable spine: the doctrine spine bound to the
    // reviewed run, with every step resolved.
    // Issue #193: the reviewed reviewer role. `--reviewer-harness KEY`
    // resolves that registry row into the reviewed binding the review step
    // declares, so the run dispatches its OWN reviewer at its certified head
    // instead of waiting for a lane an operator hand-dispatches. The row's
    // provider/model come from the configuration (never a literal here), and
    // an unknown or unbound row refuses before any state is touched.
    let reviewer_row = match args.reviewer_harness.as_deref() {
        None => None,
        Some(key) => {
            let Some(row) = config.harnesses.iter().find(|harness| harness.key == key) else {
                return error_result(
                    5,
                    "config.harness",
                    format!(
                        "no configured harness {key:?}; --reviewer-harness names a configured \
                         harness key (see `canter config show --json`)"
                    ),
                    false,
                );
            };
            let env = crate::config::credential_environment(row);
            let Some(binding) = crate::config::ProfileBinding::from_config(&config, key, &env)
            else {
                return error_result(
                    5,
                    "config.harness",
                    format!(
                        "harness {key:?} declares no provider/model binding; the reviewer role \
                         needs a reviewed binding the run's review step can declare"
                    ),
                    false,
                );
            };
            Some((
                row.key.clone(),
                row.kind.clone(),
                row.executable.clone(),
                binding.to_doc(),
            ))
        }
    };
    let reviewer =
        reviewer_row.as_ref().map(
            |(key, kind, executable, binding)| crate::plan::ReviewerRole {
                key: key.as_str(),
                kind: kind.as_str(),
                executable: executable.as_str(),
                binding,
            },
        );
    let steps = queue_run_steps(
        &repository.identity(),
        &integration,
        &args.harness,
        reviewer,
        &issues,
        args.execution,
    );
    if steps.len() > crate::queue_preview::STEPS_MAX {
        return error_result(
            2,
            "usage.queue_steps",
            format!(
                "queue preview: the derived executable spine for {} selected issues carries {} \
                 steps, above the {}-step bound the preview and the submission enforce; preview a \
                 narrower selected set",
                issues.len(),
                steps.len(),
                crate::queue_preview::STEPS_MAX
            ),
            false,
        );
    }
    // The allowed completion boundary: the phase/branches are reviewed
    // inputs, and the capability set is derived from the spine itself (every
    // step's required capability, in spine order) so the rendered boundary
    // can never contradict the declared steps.
    let mut boundary_caps: Vec<String> = Vec::new();
    for step in &steps {
        if let Some(capability) = crate::mutation::required_capability(&step.kind)
            && !boundary_caps.iter().any(|known| known == capability)
        {
            boundary_caps.push(capability.to_string());
        }
    }
    let workflow_hash = match workflow {
        Some(pin) => pin.hash.clone(),
        None => doctrine_workflow_hash(&steps),
    };
    let request = QueueRequest {
        repository: repository.identity(),
        host: args.host.clone(),
        host_available: args.host_available,
        harness_key: args.harness.clone(),
        harness_lanes: args.harness_lanes,
        caps: args.caps,
        workflow_id: DOCTRINE_WORKFLOW_ID.to_string(),
        workflow_hash,
        role_config: binding.to_doc(),
        boundary: Boundary {
            phase,
            integration_branch: integration,
            completion_branch: completion,
            caps: boundary_caps,
        },
        steps: steps
            .iter()
            .map(|step| PlannedStep {
                id: step.id.clone(),
                kind: step.kind.clone(),
                params: step.params.clone(),
            })
            .collect(),
        selected: unique
            .iter()
            .map(|(number, revision)| SelectedIssue {
                id: number.to_string(),
                title: None,
                revision: revision.clone(),
                requires: Vec::new(),
            })
            .collect(),
    };
    // The preview is a projection over the recorded state: it reads the
    // state store the daemon writes and never creates one (or contacts the
    // daemon): a missing store is reported typed.
    let socket = effective_socket(args.socket.as_deref(), Some(&config));
    let paths = match derive_paths(socket) {
        Ok(paths) => paths,
        Err(result) => return result,
    };
    if !paths.db_path.exists() {
        return error_result(
            1,
            "queue.no_state",
            format!(
                "no daemon state store at {}; run `canter daemon run` first (the preview only \
                 reads recorded state)",
                paths.db_path.display()
            ),
            false,
        );
    }
    let state = match State::open(&paths.db_path, Retention::default()) {
        Ok(state) => state,
        Err(err) => {
            return error_result(
                1,
                err.code,
                format!("queue preview: state store unavailable: {}", err.message),
                false,
            );
        }
    };
    let preview = match crate::queue_preview::preview_queue(&state, &request) {
        Ok(preview) => preview,
        Err(err) => return lane_error(err.code, err.message, false),
    };
    let Some(bound) = preview.doc.get("request").cloned() else {
        return error_result(
            1,
            "queue.preview",
            "queue preview: the preview render carries no bound-input document".to_string(),
            false,
        );
    };
    // `--out` writes the exact bound-input document (canonical bytes): the
    // material `queue submit --request` and `board --plan` read.
    let written = match &args.out {
        None => None,
        Some(out) => {
            let text = format!("{}\n", crate::canonical::canonical_text(&bound));
            match std::fs::write(out, text) {
                Ok(()) => Some(out.display().to_string()),
                Err(err) => {
                    return error_result(
                        1,
                        "queue.out",
                        format!("queue preview: cannot write {} ({err})", out.display()),
                        false,
                    );
                }
            }
        }
    };
    let mut data = vec![
        ("preview", preview.doc.clone()),
        ("request", bound.clone()),
        ("digest", string(&preview.digest)),
        ("ready", bool_(preview.ready)),
    ];
    if let Some(written) = &written {
        data.push(("out", string(written)));
    }
    let mut human = String::new();
    human.push_str(&format!(
        "queue preview {} ({} selected issue(s), revision-bound)\n",
        repository.identity(),
        unique.len()
    ));
    human.push_str(&format!(
        "plan digest sha256 {}\nready {}\n",
        preview.digest, preview.ready
    ));
    // #236: the named holds are rendered in the human text too — a cap hold
    // names the count, the cap and the lanes holding it, so the operator sees
    // who occupies the slot without parsing `--json`.
    let holds = preview
        .doc
        .get("holds")
        .and_then(Val::as_array)
        .cloned()
        .unwrap_or_default();
    if !holds.is_empty() {
        human.push_str(&format!("holds ({})\n", holds.len()));
        for hold in &holds {
            human.push_str(&format!(
                "  {}: {}\n",
                hold.get("code").and_then(Val::as_str).unwrap_or_default(),
                hold.get("message")
                    .and_then(Val::as_str)
                    .unwrap_or_default()
            ));
        }
    }
    human.push_str(&format!("steps ({})", steps.len()));
    for step in &steps {
        human.push_str(&format!(" {} {}", step.id, step.kind));
    }
    human.push('\n');
    if let Some(written) = &written {
        human.push_str(&format!("bound-input document: {written}\n"));
    }
    human.push_str(crate::queue_preview::NO_EFFECTS_STATEMENT);
    ok_result(object(data), human)
}

/// Execute one `run <pause|resume|retry|status>` invocation (issue #86).
fn execute_run(action: RunAction, invocation: &Invocation) -> CmdResult {
    match action {
        RunAction::Pause(args) => execute_run_pause(&args, invocation),
        RunAction::Resume(args) => execute_run_resume(&args, invocation),
        RunAction::Retry(args) => execute_run_retry(&args, invocation),
        RunAction::Reevaluate(args) => execute_run_reevaluate(&args, invocation),
        RunAction::Release(args) => execute_run_release(&args, invocation),
        RunAction::Resolve(args) => execute_run_resolve(&args, invocation),
        RunAction::Dispatch(args) => execute_run_dispatch(&args, invocation),
        RunAction::Status(args) => execute_run_status(&args, invocation),
    }
}

/// A fresh per-invocation idempotency key for one queue re-drive: a re-run is
/// a fresh claim, and the daemon's claim fence keeps one effect per key.
fn fresh_redrive_key() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0);
    format!("ik_queue-redrive-{secs}-{}", client::fresh_id())
}

/// A fresh per-invocation idempotency key for one run control: a re-run is a
/// fresh claim, and the daemon's record-level refusals keep one effect per
/// control (a duplicate pause is refused, a retry is single-use).
fn fresh_run_key() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0);
    format!("ik_run-{secs}-{}", client::fresh_id())
}

/// Resolve the daemon paths for one run control (config + socket + a live
/// daemon: every run control is a daemon-owned operation).
#[allow(clippy::result_large_err)]
fn run_control_paths(
    socket: Option<&str>,
    invocation: &Invocation,
) -> Result<DaemonPaths, CmdResult> {
    let config = load_optional_config(invocation)?;
    let socket = effective_socket(socket, config.as_ref());
    let paths = derive_paths(socket)?;
    if let Err(result) = require_live_daemon(&paths) {
        return Err(*result);
    }
    Ok(paths)
}

/// `run pause`: record ONE durable pause request through the daemon.
fn execute_run_pause(args: &RunPauseArgs, invocation: &Invocation) -> CmdResult {
    let paths = match run_control_paths(args.socket.as_deref(), invocation) {
        Ok(paths) => paths,
        Err(result) => return result,
    };
    let key = args.idempotency_key.clone().unwrap_or_else(fresh_run_key);
    let params = crate::run_control::pause_params(&key, &args.run, &args.reason);
    match client::call(&paths.socket_path, "run.pause", Some(&params)) {
        Ok(result) => {
            let human = crate::run_control::render_human(&result);
            ok_result(result, human)
        }
        Err(RpcError { code, message }) => {
            lane_error(&code, format!("run pause: {message}"), false)
        }
    }
}

/// `run resume`: lift exactly one run's pause with its stored digest.
fn execute_run_resume(args: &RunResumeArgs, invocation: &Invocation) -> CmdResult {
    let paths = match run_control_paths(args.socket.as_deref(), invocation) {
        Ok(paths) => paths,
        Err(result) => return result,
    };
    let key = args.idempotency_key.clone().unwrap_or_else(fresh_run_key);
    let params = crate::run_control::resume_params(&key, &args.run, &args.digest);
    match client::call(&paths.socket_path, "run.resume", Some(&params)) {
        Ok(result) => {
            let human = crate::run_control::render_human(&result);
            ok_result(result, human)
        }
        Err(RpcError { code, message }) => {
            lane_error(&code, format!("run resume: {message}"), false)
        }
    }
}

/// `run retry`: authorize ONE bounded re-dispatch of ONE diagnosed step.
fn execute_run_retry(args: &RunRetryArgs, invocation: &Invocation) -> CmdResult {
    let paths = match run_control_paths(args.socket.as_deref(), invocation) {
        Ok(paths) => paths,
        Err(result) => return result,
    };
    let key = args.idempotency_key.clone().unwrap_or_else(fresh_run_key);
    let params = crate::run_control::retry_params(&key, &args.run, &args.step);
    match client::call(&paths.socket_path, "run.retry", Some(&params)) {
        Ok(result) => {
            let human = crate::run_control::render_human(&result);
            ok_result(result, human)
        }
        Err(RpcError { code, message }) => {
            lane_error(&code, format!("run retry: {message}"), false)
        }
    }
}

/// `run reevaluate`: re-run ONE terminal-success check producer's checks at
/// the same certified head (issue #230), bounded, attributed and journaled.
fn execute_run_reevaluate(args: &RunReevaluateArgs, invocation: &Invocation) -> CmdResult {
    let paths = match run_control_paths(args.socket.as_deref(), invocation) {
        Ok(paths) => paths,
        Err(result) => return result,
    };
    let key = args.idempotency_key.clone().unwrap_or_else(fresh_run_key);
    let params = crate::run_control::reevaluation_params(
        &key,
        &args.run,
        &args.step,
        &args.operator,
        &args.reason,
    );
    match client::call(&paths.socket_path, "run.reevaluate", Some(&params)) {
        Ok(result) => {
            let human = crate::run_control::render_human(&result);
            ok_result(result, human)
        }
        Err(RpcError { code, message }) => {
            lane_error(&code, format!("run reevaluate: {message}"), false)
        }
    }
}

/// `run release`: release exactly ONE run that can never progress — its
/// durable issue ownership and the occupancy it held are freed and the run
/// goes terminal (issue #146). The daemon refuses typed while a step is in
/// flight or an unconsumed retry authorization exists.
fn execute_run_release(args: &RunReleaseArgs, invocation: &Invocation) -> CmdResult {
    let paths = match run_control_paths(args.socket.as_deref(), invocation) {
        Ok(paths) => paths,
        Err(result) => return result,
    };
    let key = args.idempotency_key.clone().unwrap_or_else(fresh_run_key);
    let params = crate::run_control::release_params(&key, &args.run, &args.reason);
    match client::call(&paths.socket_path, "run.release", Some(&params)) {
        Ok(result) => {
            let human = crate::run_control::render_human(&result);
            ok_result(result, human)
        }
        Err(RpcError { code, message }) => {
            lane_error(&code, format!("run release: {message}"), false)
        }
    }
}

/// `run resolve`: commit recorder-attributed evidence for one diagnosed
/// prompt. Reading the evidence file is the only local action; the daemon
/// validates and records the no-effect resolution.
fn execute_run_resolve(args: &RunResolveArgs, invocation: &Invocation) -> CmdResult {
    let paths = match run_control_paths(args.socket.as_deref(), invocation) {
        Ok(paths) => paths,
        Err(result) => return result,
    };
    let evidence = match std::fs::read_to_string(&args.evidence)
        .map_err(|err| err.to_string())
        .and_then(|text| Val::parse_json(&text))
    {
        Ok(value @ Val::Obj(_)) => value,
        _ => {
            return lane_error(
                "usage.run_resolve",
                "run resolve: --evidence requires a readable JSON object".to_string(),
                false,
            );
        }
    };
    let key = args.idempotency_key.clone().unwrap_or_else(fresh_run_key);
    let params = crate::run_control::resolution_params(
        &key,
        &args.run,
        &args.step,
        &args.recorder,
        evidence,
    );
    match client::call(&paths.socket_path, "run.resolve", Some(&params)) {
        Ok(result) => {
            let human = crate::run_control::render_human(&result);
            ok_result(result, human)
        }
        Err(RpcError { code, message }) => {
            lane_error(&code, format!("run resolve: {message}"), false)
        }
    }
}

/// `run dispatch`: dispatch ONE committed-spine step with the operator's own
/// step inputs (daemon `run.dispatch`). The plan document, the issue/grant
/// pins, the topology and the admission inputs are derived daemon-side from
/// the run's committed submission — the caller never hand-builds `hf-plan/v1`
/// params — and a request that is not well-formed enough to be attempted
/// refuses typed before any bounded retry authorization is consumed.
fn execute_run_dispatch(args: &RunDispatchArgs, invocation: &Invocation) -> CmdResult {
    let paths = match run_control_paths(args.socket.as_deref(), invocation) {
        Ok(paths) => paths,
        Err(result) => return result,
    };
    let key = args.idempotency_key.clone().unwrap_or_else(fresh_run_key);
    let supplied = if args.params.is_empty() {
        None
    } else {
        Some(object(
            args.params
                .iter()
                .map(|(name, value)| (name.as_str(), value.clone()))
                .collect(),
        ))
    };
    let mut params = crate::run_control::dispatch_params(
        &key,
        &args.run,
        &args.step,
        supplied,
        match (&args.operator, &args.reason) {
            (Some(operator), Some(reason)) => Some((operator.as_str(), reason.as_str())),
            _ => None,
        },
    );
    for (name, path) in [("topology", &args.topology), ("admission", &args.admission)] {
        if let Some(path) = path {
            let value = std::fs::read_to_string(path)
                .map_err(|err| err.to_string())
                .and_then(|text| Val::parse_json(&text));
            match value {
                Ok(value @ Val::Obj(_)) => {
                    if let Val::Obj(map) = &mut params {
                        map.insert(name.to_string(), value);
                    }
                }
                _ => {
                    return lane_error(
                        "usage.run_dispatch",
                        format!("run dispatch: --{name} requires a readable JSON object"),
                        false,
                    );
                }
            }
        }
    }
    match client::call(&paths.socket_path, "run.dispatch", Some(&params)) {
        Ok(result) => {
            let human = crate::run_control::render_human(&result);
            ok_result(result, human)
        }
        Err(RpcError { code, message }) => {
            lane_error(&code, format!("run dispatch: {message}"), false)
        }
    }
}

/// `run status`: read one run's control state back read-only.
fn execute_run_status(args: &RunStatusArgs, invocation: &Invocation) -> CmdResult {
    let paths = match run_control_paths(args.socket.as_deref(), invocation) {
        Ok(paths) => paths,
        Err(result) => return result,
    };
    let params = crate::run_control::status_params(&args.run);
    match read_only_call(&paths.socket_path, "run.status", Some(&params)) {
        Ok(result) => {
            let human = crate::run_control::render_human(&result);
            ok_result(result, human)
        }
        Err(RpcError { code, message }) => {
            lane_error(&code, format!("run status: {message}"), false)
        }
    }
}

/// `supervision status`: read one run's versioned supervision status back
/// read-only (issue #95) — class, reason, eligibility, freshness, last check
/// and next eligible check. This read NEVER moves the meaningful-progress
/// marker and never re-arms anything.
fn execute_supervision(action: SupervisionAction, invocation: &Invocation) -> CmdResult {
    match action {
        SupervisionAction::Status(args) => {
            let paths = match run_control_paths(args.socket.as_deref(), invocation) {
                Ok(paths) => paths,
                Err(result) => return result,
            };
            let params = crate::supervision::status_params(&args.run);
            match read_only_call(&paths.socket_path, "supervision.status", Some(&params)) {
                Ok(result) => {
                    let human = crate::supervision::render_human(&result);
                    ok_result(result, human)
                }
                Err(RpcError { code, message }) => {
                    lane_error(&code, format!("supervision status: {message}"), false)
                }
            }
        }
    }
}

/// The human rendering of one preview document (a rendering of the same
/// data, never a second contradicting contract).
fn render_lane_preview_human(document: &Val) -> String {
    let plan = document.get("plan").cloned().unwrap_or_else(null);
    let source = plan.get("source").cloned().unwrap_or_else(null);
    let text = |value: &Val, key: &str| -> String {
        value
            .get(key)
            .and_then(Val::as_str)
            .unwrap_or("unknown")
            .to_string()
    };
    let number =
        |value: &Val, key: &str| -> i64 { value.get(key).and_then(Val::as_int).unwrap_or(0) };
    let mut lines = vec![
        format!(
            "lane handoff plan: {} generation {} -> successor generation {}",
            text(&plan, "lane"),
            number(&plan, "generation"),
            number(&plan, "successor_generation")
        ),
        format!(
            "replacement: {} ({}), worktree {}",
            text(&plan, "replacement_id"),
            if document
                .get("record")
                .map(|record| !record.is_null())
                .unwrap_or(false)
            {
                "durable record present"
            } else {
                "not requested yet"
            },
            text(&source, "worktree")
        ),
        format!(
            "source: session {}, process {}, role {}",
            text(&source, "session"),
            text(&source, "process"),
            text(&source, "role")
        ),
    ];
    if let Some(profile) = plan.get("profile").filter(|profile| !profile.is_null()) {
        lines.push(format!(
            "profile: {} (revision {}, intended {}/{})",
            text(profile, "key"),
            text(profile, "revision"),
            text(profile, "provider"),
            text(profile, "model")
        ));
    } else {
        lines.push(
            "profile: none (unbound request; no target-profile revision is bound)".to_string(),
        );
    }
    lines.push("effect boundaries:".to_string());
    lines.extend(crate::handoff::boundary_lines());
    let retained = document.get("retained").cloned().unwrap_or_else(null);
    if retained.get("captured").and_then(Val::as_bool) == Some(true) {
        let list = |key: &str| -> String {
            retained
                .get(key)
                .and_then(Val::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(Val::as_str)
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default()
        };
        lines.push(format!(
            "retained: workers [{}] reviewers [{}] gates [{}] (captured; never addressed by the handoff)",
            list("workers"),
            list("reviewers"),
            list("pending_gates")
        ));
    } else {
        lines.push(
            "retained: not yet captured (the checkpoint captures the retained workers/reviewers/\
             gates at the `checkpointed` boundary)"
                .to_string(),
        );
    }
    let authorization = document.get("authorization").cloned().unwrap_or_else(null);
    let requirement = text(&authorization, "requirement");
    let policy = authorization
        .get("policy")
        .and_then(Val::as_str)
        .unwrap_or("none");
    lines.push(format!(
        "authorization: {requirement} (policy production_confirmation: {policy})"
    ));
    let digest = text(document, "digest");
    lines.push("preview: no mutation performed (read-only)".to_string());
    lines.push(format!("plan digest: {digest}"));
    lines.push(format!(
        "authorize with: canter lane request --confirm-digest {digest}"
    ));
    lines.join("\n") + "\n"
}

/// The human rendering of one request result.
fn render_lane_request_human(data: &Val) -> String {
    let replacement = data.get("replacement").cloned().unwrap_or_else(null);
    let text = |value: &Val, key: &str| -> String {
        value
            .get(key)
            .and_then(Val::as_str)
            .unwrap_or("unknown")
            .to_string()
    };
    let mut lines = vec![
        format!(
            "lane handoff requested: {} (lane {}, generation {} -> successor generation {})",
            text(&replacement, "replacement_id"),
            text(&replacement, "lane_id"),
            replacement
                .get("generation")
                .and_then(Val::as_int)
                .unwrap_or(0),
            replacement
                .get("successor_generation")
                .and_then(Val::as_int)
                .unwrap_or(0)
        ),
        format!("phase: {}", text(&replacement, "phase")),
        format!(
            "plan digest: {} (authorized by {})",
            text(data, "plan_digest"),
            text(data, "authorization")
        ),
    ];
    if let Some(next) = data.get("next") {
        lines.push(format!("next: {}", text(next, "command")));
    }
    lines.join("\n") + "\n"
}

/// The human text of one scalar document value: strings render verbatim;
/// any other value renders as its canonical JSON text, so a recorded value is
/// never silently replaced by a fallback word.
fn human_value(value: &Val) -> String {
    match value {
        Val::Str(text) => text.clone(),
        other => crate::canonical::canonical_text(other),
    }
}

/// The human rendering of one status document.
fn render_lane_status_human(document: &Val) -> String {
    let replacement = document.get("replacement").cloned().unwrap_or_else(null);
    let text = |value: &Val, key: &str| -> String {
        value
            .get(key)
            .and_then(Val::as_str)
            .unwrap_or("unknown")
            .to_string()
    };
    let mut lines = vec![
        format!(
            "lane handoff: {} (lane {}, generation {} -> successor generation {})",
            text(&replacement, "replacement_id"),
            text(&replacement, "lane_id"),
            replacement
                .get("generation")
                .and_then(Val::as_int)
                .unwrap_or(0),
            replacement
                .get("successor_generation")
                .and_then(Val::as_int)
                .unwrap_or(0)
        ),
        format!(
            "phase: {} · outcome: {}",
            text(document, "phase"),
            text(document, "outcome")
        ),
    ];
    // The recorded blocker is a plain string in the status document (the
    // exact `outcome_reason` JSON carries): render it verbatim, never
    // through a key lookup with a fallback word. The genuinely-absent case
    // stays an explicit, state-tied rendering.
    let blocker = match document.get("blocker") {
        Some(blocker) if !blocker.is_null() => human_value(blocker),
        _ if document.get("outcome").and_then(Val::as_str) == Some("pending") => {
            "none (outcome pending)".to_string()
        }
        _ => "none recorded".to_string(),
    };
    lines.push(format!("blocker: {blocker}"));
    lines.push(
        match document.get("intended").filter(|value| !value.is_null()) {
            Some(intended) => format!(
                "intended: {}/{} (revision {})",
                text(intended, "provider"),
                text(intended, "model"),
                text(intended, "revision")
            ),
            None => "intended: no bound profile plan".to_string(),
        },
    );
    lines.push(
        match document.get("actual").filter(|value| !value.is_null()) {
            Some(actual) => {
                // A null pair means the read-back reported nothing — render
                // it as unreported, never as a value.
                let pair = |key: &str| -> String {
                    actual
                        .get(key)
                        .and_then(Val::as_str)
                        .filter(|text| !text.is_empty())
                        .unwrap_or("not reported")
                        .to_string()
                };
                format!(
                    "actual: {} ({}/{})",
                    text(actual, "status"),
                    pair("provider"),
                    pair("model")
                )
            }
            None => "actual: no successor verification recorded".to_string(),
        },
    );
    lines.push(
        match document
            .get("last_transition")
            .filter(|value| !value.is_null())
        {
            Some(transition) => format!(
                "last transition: {} -> {} at {}",
                transition
                    .get("from")
                    .and_then(Val::as_str)
                    .unwrap_or("(start)"),
                text(transition, "to"),
                text(transition, "at")
            ),
            None => "last transition: none recorded".to_string(),
        },
    );
    if let Some(next) = document.get("next") {
        lines.push(match next.get("phase").and_then(Val::as_str) {
            Some(phase) => format!(
                "next: {} (daemon {}; not exposed by this CLI slice)",
                phase,
                text(next, "operation")
            ),
            None => "next: none (the record cannot advance)".to_string(),
        });
    }
    let retained = document.get("retained").cloned().unwrap_or_else(null);
    if retained.get("captured").and_then(Val::as_bool) == Some(true) {
        let list = |key: &str| -> String {
            retained
                .get(key)
                .and_then(Val::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(Val::as_str)
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default()
        };
        lines.push(format!(
            "retained: workers [{}] reviewers [{}] gates [{}]",
            list("workers"),
            list("reviewers"),
            list("pending_gates")
        ));
    }
    if let Some(guidance) = document.get("guidance").and_then(Val::as_array)
        && !guidance.is_empty()
    {
        lines.push("guidance:".to_string());
        for line in guidance {
            lines.push(format!("  - {}", line.as_str().unwrap_or_default()));
        }
    }
    lines.join("\n") + "\n"
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const DAEMON_USAGE: &str = "\
canter daemon <run|status> — run or probe the state daemon

USAGE:
    canter daemon run [--socket PATH] [--config PATH]
    canter daemon status [--config PATH] [--json]

run serves the single-writer daemon in the foreground: it acquires the
per-user flock, opens/migrates the SQLite state, reconciles interrupted
claims, and serves hf-rpc/v1 on the per-user Unix socket (default: the XDG
runtime dir; --socket or config daemon.socket override it). A second daemon
is refused (exit 1, code daemon.busy). status probes the socket and reports
the live state; when no daemon is running it exits 1 with code daemon.absent
— read-only commands stay available without the daemon.
";

const SERVICE_USAGE: &str = "\
canter service <doctor|install-plan|status-plan|uninstall-plan>

USAGE:
    canter service doctor [--config PATH] [--json]
    canter service install-plan [--config PATH] [--json]
    canter service status-plan [--config PATH] [--json]
    canter service uninstall-plan [--config PATH] [--json]

doctor checks the daemon environment read-only (platform, config, socket
state, per-user unit placement). The *-plan commands render the first-party
launchd/systemd unit text and the exact command steps for a clean host —
they never install, start, stop, or query the host service manager.
";

const LANE_USAGE: &str = "\
canter lane <preview|request|status> — ONE explicit lane handoff

USAGE:
    canter lane preview --lane ID --generation N --session S --process P \
--role R --worktree W --reason TEXT [--profile KEY] [--socket PATH] \
[--config PATH] [--json]
    canter lane request --lane ID --generation N --session S --process P \
--role R --worktree W --reason TEXT [--profile KEY] \
[--confirm-digest HEX64 | --confirm | --yes] [--idempotency-key IK] \
[--socket PATH] [--config PATH] [--json]
    canter lane status (--replacement RP_ID | --lane ID --generation N) \
[--socket PATH] [--config PATH] [--json]

preview renders the reviewable hf-lane-handoff/v1 plan for one lane
replacement: the source identity (session, process, role, generation), the
target profile plan (--profile KEY derives the reviewed
hf-profile-binding/v1 document from the config, the same plan
`canter config show` previews), the repository-relative worktree, the
effect boundaries of the phase chain, the retained workers/reviewers/gates
(captured at the checkpointed boundary; read-only when a checkpoint
exists), and the plan digest. preview NEVER mutates: it performs no
mutating RPC (only read-only record reads) and writes nothing.

request records ONE durable lane replacement request at phase `requested`
(daemon `lane.replacement.request`). The authorization binds the exact
plan digest: --confirm-digest HEX64 is the noninteractive explicit mode
and --confirm reads the digest you type on stdin (prompt on stderr).
--yes is a blanket authorization and is refused whenever the policy
overlay declares a production_confirmation rule (`tty` or `deny`) — it can
never bypass that policy. JSON mode never prompts: pass --confirm-digest.
A presented digest that does not match the current plan is refused as a
stale plan (refusal.plan.stale); the request has no spawn, kill, or Git
effect and never resumes a paused fleet.

status reads one replacement record read-only (daemon
`lane.replacement.status` plus the committed checkpoint): phase, outcome,
blocker, intended/actual model binding, the last verified transition, the
next supported action and actionable guidance. It never mutates, never
advances a record, and never resumes anything.

EXIT CODES: 0 ok · 1 daemon/transport error · 2 usage · 4 refusal
(refusal.plan.stale, refusal.confirmation.policy, refusal.policy.production,
daemon refusals, state.not_found) · 5 config/policy error.

EXAMPLES:
    canter lane preview --lane lane-0001 --generation 1 --session sess-1 \
--process proc-1 --role implementer --worktree worktrees/issues/78 \
--reason 'rotate the implementer lane' --profile lane-harness --json
    canter lane request --lane lane-0001 --generation 1 --session sess-1 \
--process proc-1 --role implementer --worktree worktrees/issues/78 \
--reason 'rotate the implementer lane' --confirm-digest <64-hex>
    canter lane status --lane lane-0001 --generation 1 --json
    canter lane status --replacement rp_0123456789abcdef --json
";

const QUEUE_USAGE: &str = "\
canter queue <preview|submit|status|redrive> — the durable selected-run path

USAGE:
    canter queue preview --repository KEY --harness KEY \
[--reviewer-harness KEY] --host HOST \
--issue N=HEX40... --caps G/R/H [--host-available yes|no|unknown] \
[--harness-lanes N|unknown] [--boundary-phase PHASE] \
[--integration-branch B] [--completion-branch B] \
[--execution herdr|headless] [--out FILE] \
[--socket PATH] [--config PATH] [--json]
    canter queue submit --request FILE --confirm-digest HEX64 [--epoch N] \
[--grant REF=GRANT_ID]... [--resume INSTANCE=DIGEST]... \
[--host-available yes|no|unknown] [--harness-lanes N|unknown] \
[--idempotency-key IK] [--socket PATH] [--config PATH] [--json]
    canter queue status --submission QS_ID [--socket PATH] [--config PATH] \
[--json]
    canter queue redrive --submission QS_ID [--socket PATH] [--config PATH] \
[--json]

redrive re-evaluates ONE committed submission's parked (`waiting`) items
against the live fan-out capacity, through the SAME approved admission inputs
the submission committed under: the bounded, audited operator control that
recovers a submission stranded by a transient cap (the queue cursor otherwise
moves only on a verified delivery). It admits nothing a fresh submission
would have refused, never touches a lane whose run is live, and a submission
with nothing parked refuses typed.

preview renders the effect-free preview of ONE reviewed run through the real
preview service and produces its bound-input document: the repository
identity, branch and the reviewed role configuration come from the config
(re-observed, never free text), each --issue carries its exact 40-hex spec
revision, and the declared step spine is the doctrine spine with every step
resolved. `--execution herdr|headless` (default `herdr`) is bound into every
authored harness step: `herdr` runs the role inside a Herdr pane created in
the run's lane worktree, while `headless` is the documented bare-subprocess
fallback and must be selected explicitly — a Herdr failure never falls back
to it. --out writes the exact bound-input document (the material
--request/--plan read); the printed digest is sha256 over that document's
canonical bytes, i.e. the exact authorization submit binds. It reads the
recorded state store the daemon writes and never creates one, spawns
nothing, issues no grant and writes no external state.

submit commits ONE approved selected-issue run (daemon `queue.submit`),
consuming the reviewed queue preview: --request names the exact bound-input
document a preview rendered (its sha256 IS the preview digest) and
--confirm-digest presents the approved digest — a mismatch is refused
locally as a stale plan before any daemon call. The reviewed role
configuration is re-observed from the config and must be unchanged: a
configuration or credential change is refused (refusal.profile.revision)
before any effect. --epoch pins the state epoch the approval was rendered
against (omit it to read the live epoch from the daemon; a pinned value that
moved is refused before any effect).

The submission persists the run membership: per selected issue the outcome
is explicit — admitted (a run record with unique work ownership), waiting
(capacity/attestation), or refused (dependency/ownership/grant) — and it is
NEVER a claim of completed implementation: no workflow step is executed by
this command. Unsupported or unresolved steps refuse the whole flow,
labelled, never stubbed. A paused run stays paused unless a separate
explicit engine-minted resume authorization is presented with --resume.
--grant binds each issue to its presented route grant (REF=GRANT_ID). The
scope stays exactly the approved selected set: no implicit backlog
expansion, and main/release work is a human-only boundary this surface
cannot authorize.

status reads one committed submission document back read-only (daemon
`queue.status`): the exact same projection the submit response carried. It
never mutates.

EXIT CODES: 0 ok · 1 daemon/transport error · 2 usage · 4 refusal
(refusal.plan.stale, refusal.profile.revision, refusal.state.epoch,
refusal.grant.*, preview.*, submission.*, daemon refusals,
state.not_found) · 5 config error.
";

const RUN_USAGE: &str = "\
canter run <pause|resume|retry|reevaluate|release|resolve|dispatch|status> — run-scoped controls for ONE run

USAGE:
    canter run pause --run RUN_ID --reason TEXT [--idempotency-key IK] \
[--socket PATH] [--config PATH] [--json]
    canter run resume --run RUN_ID --digest HEX64 [--idempotency-key IK] \
[--socket PATH] [--config PATH] [--json]
    canter run retry --run RUN_ID --step STEP [--idempotency-key IK] \
[--socket PATH] [--config PATH] [--json]
    canter run reevaluate --run RUN_ID --step STEP --operator IDENTITY --reason TEXT \
[--idempotency-key IK] [--socket PATH] [--config PATH] [--json]
    canter run release --run RUN_ID --reason TEXT [--idempotency-key IK] \
[--socket PATH] [--config PATH] [--json]
    canter run resolve --run RUN_ID --step STEP --recorder IDENTITY \
--evidence FILE [--idempotency-key IK] [--socket PATH] [--config PATH] [--json]
    canter run dispatch --run RUN_ID --step STEP [--param KEY=VALUE]... \
[--topology FILE] [--admission FILE] [--operator IDENTITY --reason TEXT] \
[--idempotency-key IK] [--socket PATH] [--config PATH] [--json]
    canter run status --run RUN_ID [--socket PATH] [--config PATH] [--json]

The scope is the RUN only: --run names exactly one durable run record
(`run-` + 16 hex) and every control is fenced on that exact identity.
There is deliberately no fleet-level control on this surface: a resume
lifts only the named run's pause, never another run's, and never any
fleet-wide hold; lane handoff records are untouched. Nothing here kills a
process, cleans up work, mutates repositories or bypasses a gate.

pause records ONE durable pause request (daemon `run.pause`): new step
dispatch for the run is refused from that moment on, while work already in
flight keeps running — nothing is signalled or killed — and the pause
commits its reached `paused` state at the run's next recorded step
boundary. The response carries the engine-minted resume digest; hold it
for `run resume`. A second pause of the same run is refused (no duplicate
intent), and a request that replays the same --idempotency-key returns the
recorded response.

resume lifts the pause of exactly that run (daemon `run.resume`). It
requires the stored digest (the operator authorization) and re-derives
fresh eligibility under the daemon guard: the run must still be live, at
the current state epoch, and still own its issue — a stale or foreign
digest refuses, and the digest is consumed on success (single use).

retry authorizes exactly ONE bounded re-dispatch of ONE diagnosed step
(daemon `run.retry`): the step must be a step of the run's committed
spine, its current unachieved frontier step, and must carry a recorded
terminal non-success attempt. Invalid (unknown/undiagnosed/out-of-order),
revoked (inactive grant), stale (moved epoch), already-succeeded and
exhausted (bounded attempts used) retries refuse. The request dispatches
nothing and spawns nothing by itself: the authorization is consumed by the
ONE re-dispatch of that exact step — the run's own armed supervision
performs it (issue #241), or the operator's own corrected dispatch of that
exact step consumes it when it arrives first (single use: a second attempt
needs its own authorization).

reevaluate recomputes the checks a terminal-success producer already recorded
(daemon `run.reevaluate`, issue #230): a check recorded `failed` inside the
evidence of a step that SUCCEEDED otherwise strands its consumer forever —
the producer can never be re-dispatched and the consumer refuses the frozen
result. The command names that exact step (it must be the run's own check
producer, with its own recorded success and a non-passing check in the run's
newest evidence) plus the operator identity and the audited reason, and the
daemon re-dispatches it at the SAME certified head on a FRESH reviewer lane
round, so the checks are really recomputed by their producer. It is bounded
per (run, step) from the durable journal, the record is written to the
hash-chained audit before anything is dispatched, and no check status is ever
presented or waived: a recomputation that comes back failing refuses the
consumer exactly as the first one did. The re-dispatched step is a fan-out,
so the control renews the run's OWN lapsed host-resource proof at dispatch
time exactly as the supervisor's continuation does (audited
`host.proof.renewal`, measured at the run's lane root); a host that cannot be
measured renews nothing and the admission refusal names the precondition and
the remedy.

resolve records an explicit, recorder-attributed artifact for ONE diagnosed
prompt (daemon `run.resolve`): a closed JSON object binds the delivered feature
head, output branch, PR identity and named checks. It advances the attempt
ledger without invoking the prompt effect again. It cannot resolve any other
step kind, an in-flight effect, an unattempted/refused/succeeded step, or an
artifact whose branch/repository differs from the run.

dispatch performs that corrected dispatch (daemon `run.dispatch`): it takes
the run, the committed-spine step and ONLY the step-specific inputs the
operator actually knows (`--param KEY=VALUE`, repeatable; a value that is
JSON keeps its type, everything else is the literal string). The plan
document and issue/grant/workflow pins are derived daemon-side from the run's
committed submission. `--topology FILE` supplies the documented topology for
the run's first dispatch; later dispatches reuse that immutable recorded
topology. `--admission FILE` may provide a fresh caller-attested admission
measurement. No `hf-plan/v1` is ever hand-built.
--operator IDENTITY --reason TEXT (a PAIR: both or neither) is the audited
operator's own measurement of the host-resource proof (issue #250): the
daemon measures the host at the run's lane root at dispatch time and binds
the measurement into the run's recorded admission (superseding a lapsed
proof), recording the identity, the reason, the superseded proof and the
measurement in the hash-chained journal BEFORE it presents them — so a
remedy that needs a proof is executable by the party it is addressed to.
The caps and occupancy stay the run's own recorded ones: the measurement
supplies a proof, never a cap. A host that cannot be measured (or a run that
recorded no admission to bind it into) produces nothing and the admission
gate still refuses the absent or lapsed proof, typed.
The operator's inputs are merged over the step's committed params and
validated against the step kind's existing param contract BEFORE anything
is journaled. That pre-screen is TOTAL over the step kinds: each kind's own
param contract, the request-level observed read-backs and the topology
gates its effect reads are all resolved up front, and a kind with no
registered contract refuses as well — so a request that is not well-formed
enough to be attempted refuses typed (e.g. `refusal.request.malformed`)
whatever its kind and leaves a pending bounded retry authorization
unconsumed for the correction. A re-dispatch of a diagnosed step consumes
exactly one unconsumed authorization.

release frees the durable bookkeeping of ONE run that can never progress
(daemon `run.release`, issue #146): the run's unique ownership of its issue
and the global/per-repository/per-harness occupancy it held are released,
and the run is terminal afterward (`done` stays `done`, otherwise `invalidated`)
so it is never resumed, retried or dispatched again — the operator's
--reason, the exact run identity and the authorization window it held are
recorded in the audit.
Eligibility is fenced daemon-side and refuses typed: a run with a step
dispatch in flight refuses `refusal.run.in_flight` (nothing in flight is
killed or abandoned), a run that still holds an unconsumed bounded retry
authorization refuses `refusal.run.retry_pending` (the authorization is
never burned), and an unknown run is `state.not_found`.
Terminal runs (`done` or `invalidated`) can release leftover ownership.
If ownership is already absent, a fresh --idempotency-key records an
audited no-op (`ownership: absent`); the SAME --idempotency-key replays
the recorded response. No other run's ownership is touched.
An expired, revoked or missing grant is NOT a fence: a run whose grant
expired is exactly the case a release exists for, and the release records
that window (`usable:false`) without ever
presenting or reusing it — continuing that work needs a freshly minted
grant window, never a silent reuse of the expired one. After the release
the issue can be submitted again on its own merits.

status reads the control state back read-only (daemon `run.status`):
active / pause_requested (request durable, in-flight work still running) /
paused (the safe boundary has been reached). Its `remedy` block is the
DECISION for a parked run (issue #250): the ONE control whose own gate will
accept the run's diagnosed frontier step (with its exact documented command
and the reason the others do not apply), or — when the bounded-retry budget
is spent, the step carries no re-evaluable check and no proof can be
produced — the terminal typed `escalation.run.owner_decision` naming the
owner decision, never an eligible-looking park; the read claims, measures,
journals and dispatches nothing.

EXIT CODES: 0 ok · 1 daemon/transport error · 2 usage · 4 refusal
(refusal.run.*, refusal.request.malformed, refusal.state.epoch,
refusal.grant.inactive, state.not_found, state.stale_resume, daemon
refusals) · 5 config error.
";

const SUPERVISION_USAGE: &str = "\
canter supervision status — the versioned supervision status of ONE run

USAGE:
    canter supervision status --run RUN_ID [--socket PATH] [--config PATH] \
[--json]

The scope is the RUN only: --run names exactly one durable supervised run
record (`run-` + 16 hex).

Supervision is a daemon-owned reconciliation driver (issue #95), NOT another
agent and NOT a scheduler surface:
  - it is DISABLED by default: a run is supervised only when an explicit
    hf-supervision-authorization/v1 block was committed as part of its
    queue submission, and the authorization binds the approved preview
    digest (a drifted or unapproved plan is held and is never eligible);
  - it evaluates and REPORTS: it classifies recorded evidence
    (healthy / waiting-workers / waiting-CI / waiting-approval /
    blocked-capacity / continuation-eligible / paused / completed /
    needs-attention, or unknown/held when evidence is missing) and never
    continues work, spawns, prompts, resumes a pause, authorizes a retry,
    mutates Git or clears a hold;
  - this status read is read-only and never resets the meaningful-progress
    marker, never re-arms anything and never nudges the driver.

status renders the hf-supervision/v1 document: the recorded authorization
and policy, the class/reason and eligibility, freshness of the last check,
the last check (time, class, reason, wake), the NEXT ELIGIBLE CHECK with its
reason, the observed progress marker (with its age and source), the
continuation report count and the folded pending wake.

EXIT CODES: 0 ok · 1 daemon/transport error · 2 usage · 4 refusal
(usage.supervision.*, state.not_found, daemon refusals) · 5 config error.
";

const GRANT_USAGE: &str = "\
canter grant issue — mint ONE route grant through the daemon

USAGE:
    canter grant issue --request FILE --issue N --expires-in SECS \
[--idempotency-key IK] [--socket PATH] [--config PATH] [--json]

A route grant is the only authorization to start durable work, so this is the
SUPPORTED mint path: the daemon inserts ONE hf-grant/v1 row through the closed
`grants.issue` method (journaled intent -> effect -> typed outcome), and the
resulting grant id is what `canter board --grant` / `canter queue submit
--grant` present. Issuance is NOT authorization: the board remains the
authorization point, and the digest the operator approves there is still the
reviewed bound-input digest.

FILE is the reviewed bound-input document `canter queue preview --out`
produces (the same material `queue submit --request` and `board --plan`
read). Every grant field is DERIVED from that document plus the configuration
and live state — never typed by hand:

  repository        the document's repository identity (must be configured)
  issue             the reviewed selected[] entry `--issue N` names, with
                    its exact 40-hex acceptance revision
  workflow_hash     the document's workflow.hash
  policy_hash       the document's role_config.revision, re-observed from the
                    CURRENT configuration (a moved revision refuses typed
                    before anything is sent)
  phase / caps      the document's boundary phase and capabilities
  scope             worktrees/issues/N (the reviewed planned scope)
  state_epoch       the live daemon epoch (a moved epoch refuses)
  expires_at        now + --expires-in SECS
  grant_id          content-addressed: gr_ + first 16 hex of sha256 over the
                    canonical binding

Refusals (exit 4): a malformed or foreign document (usage.grant_request), an
issue outside the reviewed selected set (usage.grant_issue), a moved role
revision (refusal.profile.revision), a production-class binding
(refusal.policy.production_confirmation: production authority stays
human-only), an already-expired window (refusal.grant.expired), a moved state
epoch (state.epoch_mismatch), an existing grant id (state.grant_exists), and
the daemon claim refusals (refusal.idempotency, state.claim_incomplete).

EXIT CODES: 0 ok · 1 operational/daemon error · 2 usage · 4 refusal ·
5 config error.
";

/// Resolve the daemon socket override: the CLI flag wins over
/// `config.daemon.socket`; otherwise the XDG runtime default applies.
fn effective_socket(flag: Option<&str>, config: Option<&Config>) -> Option<String> {
    flag.map(str::to_string).or_else(|| {
        config
            .and_then(|config| config.daemon_socket.clone())
            .filter(|socket| !socket.is_empty())
    })
}

/// Load the optional config; a found-but-invalid config is a hard error.
#[allow(clippy::result_large_err)]
fn load_optional_config(invocation: &Invocation) -> Result<Option<Config>, CmdResult> {
    match discover_config(invocation.config_path.as_deref()) {
        Ok(Some(path)) => match load_config(&path) {
            Ok(config) => Ok(Some(config)),
            Err(load_error) => Err(load_error_result(load_error)),
        },
        Ok(None) => Ok(None),
        Err(load_error) => Err(load_error_result(load_error)),
    }
}

/// Derive daemon paths, applying the config/flag socket override.
#[allow(clippy::result_large_err)]
fn derive_paths(socket: Option<String>) -> Result<DaemonPaths, CmdResult> {
    DaemonPaths::derive(socket.as_deref()).map_err(|err| {
        error_result(
            1,
            "daemon.paths",
            format!("{}: {}", err.code, err.message),
            false,
        )
    })
}

fn execute_daemon(action: DaemonAction, invocation: &Invocation) -> CmdResult {
    match action {
        DaemonAction::Run { socket: flag } => execute_daemon_run(flag.as_deref(), invocation),
        DaemonAction::Status { socket: flag } => execute_daemon_status(flag.as_deref(), invocation),
    }
}

fn execute_daemon_run(socket_flag: Option<&str>, invocation: &Invocation) -> CmdResult {
    let config = match load_optional_config(invocation) {
        Ok(config) => config,
        Err(result) => return result,
    };
    if let Some(false) = config.as_ref().and_then(|config| config.daemon_enabled) {
        return error_result(
            4,
            "refusal.daemon.disabled",
            "config daemon.enabled=false: the daemon is disabled for this user; remove the flag or set daemon.enabled=true".to_string(),
            false,
        );
    }
    let socket = effective_socket(socket_flag, config.as_ref());
    let paths = match derive_paths(socket) {
        Ok(paths) => paths,
        Err(result) => return result,
    };
    // The daemon logs readiness and every refusal to its own JSONL log; the
    // foreground process runs until stopped by the service manager or a
    // fatal error (there is no daemonize: launchd/systemd own the process).
    match daemon::serve(&paths) {
        Ok(()) => ok_result(object(vec![]), "daemon exited cleanly\n".to_string()),
        Err(DaemonError { code, message }) => error_result(1, code, message, false),
    }
}

fn execute_daemon_status(socket_flag: Option<&str>, invocation: &Invocation) -> CmdResult {
    let config = match load_optional_config(invocation) {
        Ok(config) => config,
        Err(result) => return result,
    };
    let socket = effective_socket(socket_flag, config.as_ref());
    let paths = match derive_paths(socket) {
        Ok(paths) => paths,
        Err(result) => return result,
    };
    match crate::lock::socket_presence(&paths.socket_path) {
        crate::lock::SocketPresence::Active => {
            let result = client::call(&paths.socket_path, "status", None);
            match result {
                Ok(doc) => {
                    let epoch = doc
                        .get("state")
                        .and_then(|state| state.get("epoch"))
                        .and_then(Val::as_int)
                        .unwrap_or(0);
                    let journal_seq = doc
                        .get("state")
                        .and_then(|state| state.get("journal_seq"))
                        .and_then(Val::as_int)
                        .unwrap_or(0);
                    let pid = doc
                        .get("daemon")
                        .and_then(|daemon| daemon.get("pid"))
                        .and_then(Val::as_int)
                        .unwrap_or(0);
                    let started_at = doc
                        .get("daemon")
                        .and_then(|daemon| daemon.get("started_at"))
                        .and_then(Val::as_str)
                        .unwrap_or("unknown");
                    let human = format!(
                        "daemon: running (pid {pid}, started {started_at})\nstate: epoch {epoch}, journal seq {journal_seq}\nsocket: {}\n",
                        paths.socket_path.display()
                    );
                    ok_result(doc, human)
                }
                Err(RpcError { code, message }) => {
                    error_result(1, &code, format!("daemon status: {message}"), false)
                }
            }
        }
        crate::lock::SocketPresence::Stale => error_result(
            1,
            "daemon.stale",
            format!(
                "a stale daemon socket exists at {}; a fresh `daemon run` reclaims it",
                paths.socket_path.display()
            ),
            true,
        ),
        crate::lock::SocketPresence::Absent => error_result(
            1,
            "daemon.absent",
            format!(
                "no daemon is running on {}; read-only commands (doctor/status/plan) stay available without it",
                paths.socket_path.display()
            ),
            false,
        ),
        crate::lock::SocketPresence::Unsafe(reason) => error_result(
            1,
            "daemon.unsafe_socket",
            format!("{} ({})", reason, paths.socket_path.display()),
            false,
        ),
    }
}

fn execute_service(action: ServiceAction, invocation: &Invocation) -> CmdResult {
    match action {
        ServiceAction::Doctor => execute_service_doctor(invocation),
        ServiceAction::PlanInstall => execute_service_plan(invocation, "install"),
        ServiceAction::PlanStatus => execute_service_plan(invocation, "status"),
        ServiceAction::PlanUninstall => execute_service_plan(invocation, "uninstall"),
    }
}

fn execute_service_doctor(invocation: &Invocation) -> CmdResult {
    let config = match load_optional_config(invocation) {
        Ok(config) => config,
        Err(result) => return result,
    };
    let platform = service::detect_platform();
    let socket = effective_socket(None, config.as_ref());
    let paths = match derive_paths(socket) {
        Ok(paths) => paths,
        Err(result) => return result,
    };
    let mut rows: Vec<DoctorRow> = Vec::new();
    let mut degraded = false;

    rows.push(DoctorRow {
        name: "platform",
        status: "ok",
        detail: Some(platform.to_string()),
    });
    let config_status = match &config {
        Some(config) => {
            let enabled = config.daemon_enabled.unwrap_or(true);
            let detail = format!(
                "daemon.enabled={enabled}{}",
                config
                    .daemon_socket
                    .as_ref()
                    .map(|socket| format!(", daemon.socket={socket}"))
                    .unwrap_or_default()
            );
            if !enabled {
                degraded = true;
            }
            ("found", detail)
        }
        None => ("absent", "no config file; defaults apply".to_string()),
    };
    rows.push(DoctorRow {
        name: "config",
        status: config_status.0,
        detail: Some(config_status.1),
    });

    let socket_presence = crate::lock::socket_presence(&paths.socket_path);
    let (socket_status, socket_detail) = match &socket_presence {
        crate::lock::SocketPresence::Active => ("running", describe_socket(&paths.socket_path)),
        crate::lock::SocketPresence::Absent => ("absent", "daemon not running".to_string()),
        crate::lock::SocketPresence::Stale => {
            degraded = true;
            ("stale", describe_socket(&paths.socket_path))
        }
        crate::lock::SocketPresence::Unsafe(reason) => {
            degraded = true;
            ("unsafe", reason.clone())
        }
    };
    rows.push(DoctorRow {
        name: "socket",
        status: socket_status,
        detail: Some(socket_detail),
    });

    // Per-user unit placement (read-only; never queried/activated).
    let home = std::env::var_os("HOME").map(std::path::PathBuf::from);
    let config_home = crate::dirs::config_home().ok();
    let (unit_name, unit_present) = match (platform, &home, &config_home) {
        ("launchd", Some(home), _) => {
            let path = service::launchd_plist_path(home);
            (path.display().to_string(), path.exists())
        }
        ("systemd", _, Some(config_home)) => {
            let path = service::systemd_unit_path(config_home);
            (path.display().to_string(), path.exists())
        }
        _ => ("no per-user unit for this platform".to_string(), false),
    };
    rows.push(DoctorRow {
        name: "service-unit",
        status: if unit_present { "installed" } else { "absent" },
        detail: Some(unit_name),
    });
    if unit_present && socket_status == "absent" {
        degraded = true;
    }

    let data = object(vec![
        (
            "checks",
            Val::Arr(
                rows.iter()
                    .map(DoctorRow::clone)
                    .map(DoctorRow::into_val)
                    .collect(),
            ),
        ),
        (
            "summary",
            object(vec![
                ("platform", string(platform)),
                ("daemon", string(socket_status)),
                (
                    "unit",
                    string(if unit_present { "installed" } else { "absent" }),
                ),
            ]),
        ),
    ]);
    let human = rows.iter().map(DoctorRow::render).collect::<String>();
    if degraded {
        partial_result(data, human, String::new())
    } else {
        ok_result(data, human)
    }
}

fn execute_service_plan(invocation: &Invocation, kind: &str) -> CmdResult {
    let config = match load_optional_config(invocation) {
        Ok(config) => config,
        Err(result) => return result,
    };
    let platform = service::detect_platform();
    let socket = effective_socket(None, config.as_ref());
    let paths = match derive_paths(socket) {
        Ok(paths) => paths,
        Err(result) => return result,
    };
    let bin = std::env::current_exe()
        .ok()
        .unwrap_or_else(|| std::path::PathBuf::from("canter"));
    let home = std::env::var_os("HOME").map(std::path::PathBuf::from);
    let config_home = crate::dirs::config_home().ok();

    let (unit, target) = match platform {
        "launchd" => {
            let target = home
                .as_ref()
                .map(|home| service::launchd_plist_path(home))
                .unwrap_or_else(|| std::path::PathBuf::from(format!("~/{LAUNCHD_LABEL}.plist")));
            (service::launchd_unit(&bin, &paths.socket_path), target)
        }
        "systemd" => {
            let target = config_home
                .as_ref()
                .map(|config_home| service::systemd_unit_path(config_home))
                .unwrap_or_else(|| {
                    std::path::PathBuf::from(format!("~/.config/systemd/user/{SYSTEMD_UNIT_NAME}"))
                });
            (service::systemd_unit(&bin, &paths.socket_path), target)
        }
        other => {
            return error_result(
                1,
                "service.unsupported",
                format!("no first-party unit exists for platform {other:?}"),
                false,
            );
        }
    };
    let steps = match kind {
        "install" => service::install_plan_steps(
            platform,
            &bin,
            &paths.socket_path,
            home.as_deref().unwrap_or(std::path::Path::new("~")),
            config_home.as_deref().unwrap_or(std::path::Path::new("~")),
        ),
        "status" => service::status_plan_steps(platform),
        "uninstall" => service::uninstall_plan_steps(
            platform,
            home.as_deref().unwrap_or(std::path::Path::new("~")),
            config_home.as_deref().unwrap_or(std::path::Path::new("~")),
        ),
        other => {
            return error_result(
                2,
                "usage.error",
                format!("unknown plan kind {other:?}"),
                false,
            );
        }
    };
    let step_vals: Vec<Val> = steps.iter().map(|step| string(step)).collect();
    let data = object(vec![
        ("platform", string(platform)),
        ("target", string(&target.display().to_string())),
        ("unit", string(&unit)),
        ("steps", Val::Arr(step_vals)),
    ]);
    let mut human = String::new();
    human.push_str(&format!(
        "canter service {kind}-plan (platform {platform}) — nothing was installed or started\n\n"
    ));
    human.push_str(&format!("unit file: {}\n\n", target.display()));
    human.push_str(&unit);
    human.push_str("\nsteps:\n");
    for (index, step) in steps.iter().enumerate() {
        human.push_str(&format!("  {}. {step}\n", index + 1));
    }
    ok_result(data, human)
}

/// Run the CLI from `std::env::args()` and return the process exit code.
///
/// Single shared entry point for the canonical `canter` binary and the
/// pre-rename `herdr-fleet` compatibility alias (`src/bin/herdr-fleet.rs`):
/// both must behave identically (docs/contracts/compatibility.md, "Product
/// rename (issue #106)").
pub fn cli_main() -> std::process::ExitCode {
    use std::process::ExitCode;

    let args: Vec<String> = std::env::args().skip(1).collect();

    // Top-level metadata flags (the only flag forms before a command).
    if args.len() == 1 {
        match args[0].as_str() {
            "--help" | "-h" => {
                print!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            "--version" | "-V" => {
                println!("{} {}", crate::PACKAGE_NAME, crate::PACKAGE_VERSION);
                println!("{}", crate::about());
                print!("{}", crate::release_facts());
                return ExitCode::SUCCESS;
            }
            _ => {}
        }
    }
    if args.is_empty() {
        eprintln!("{USAGE}");
        eprintln!("error: no arguments given; try `canter --help`");
        return ExitCode::from(2);
    }
    if matches!(
        args[0].split('=').next(),
        Some("--config" | "--socket" | "--json")
    ) {
        eprintln!(
            "error: --config/--socket/--json belong after the subcommand; for example: canter run status --run RUN_ID --config FILE --socket PATH"
        );
        return ExitCode::from(2);
    }
    if args[0].starts_with('-') {
        eprintln!("{USAGE}");
        eprintln!("error: unknown argument `{}`", args[0]);
        return ExitCode::from(2);
    }

    let invocation = match parse_invocation(&args) {
        Ok(invocation) => invocation,
        Err(ParseError::Help(text)) => {
            println!("{text}");
            return ExitCode::SUCCESS;
        }
        Err(ParseError::Usage(message)) => {
            eprintln!("error: {message}");
            eprintln!();
            eprintln!("{}", per_command_usage(&args[0]));
            return ExitCode::from(2);
        }
    };

    let result = execute(&invocation);

    if invocation.json {
        let json = render_envelope(&invocation.command, &result);
        print!("{json}");
    } else if !result.human.is_empty() {
        print!("{}", result.human);
        if !result.human.ends_with('\n') {
            println!();
        }
    }
    if !result.diagnostics.is_empty() {
        eprintln!("{}", result.diagnostics);
    }
    ExitCode::from(result.exit_code)
}

/// Usage hint line printed under a usage error for the offending command.
fn per_command_usage(command: &str) -> &'static str {
    match command {
        "config" => "usage: canter config <init|validate|show> [--config PATH] [--json]",
        "doctor" => "usage: canter doctor [--json]",
        "status" => "usage: canter status [--config PATH] [--json]",
        "plan" => {
            "usage: canter plan <repository> <issue> [--revision HEX40] [--config PATH] [--json]"
        }
        "capabilities" => "usage: canter capabilities [--json]",
        "board" => {
            "usage: canter board [--plan FILE --caps G/R/H [--host-available yes|no|unknown] [--harness-lanes N|unknown] [--grant REF=GRANT_ID]... [--resume INSTANCE=DIGEST]...] [--config PATH]"
        }
        "daemon" => {
            "usage: canter daemon run [--socket PATH] [--config PATH]\n       canter daemon status [--config PATH] [--json]"
        }
        "service" => {
            "usage: canter service <doctor|install-plan|status-plan|uninstall-plan> [--config PATH] [--json]"
        }
        "lane" => {
            "usage: canter lane preview|request --lane ID --generation N --session S --process P --role R --worktree W --reason TEXT [--profile KEY]\n       canter lane status --replacement RP_ID | --lane ID --generation N"
        }
        "queue" => {
            "usage: canter queue preview --repository KEY --harness KEY [--reviewer-harness KEY] --host HOST --issue N=HEX40... --caps G/R/H [--out FILE]\n       canter queue submit --request FILE --confirm-digest HEX64 --caps G/R/H [--epoch N]\n       canter queue status --submission QS_ID\n       canter queue redrive --submission QS_ID"
        }
        "grant" => {
            "usage: canter grant issue --request FILE --issue N --expires-in SECS [--idempotency-key IK] [--socket PATH] [--config PATH] [--json]"
        }
        _ => "usage: canter [--help] [--version] | canter <command> [options]",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{Family, validate_doc};

    fn invocation(args: &[&str]) -> Invocation {
        let owned: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        parse_invocation(&owned).expect("parse")
    }

    fn assert_envelope_valid(command: &str, result: &CmdResult) {
        let json = render_envelope(command, result);
        let doc = Val::parse_json(json.trim_end()).expect("envelope parses");
        let verdict = validate_doc(Family::Output, &doc);
        assert!(
            verdict.is_accepted(),
            "envelope for {command}: {}",
            verdict.message()
        );
        assert!(json.ends_with('\n'), "envelope output ends with a newline");
    }

    #[test]
    fn parse_forms_work() {
        assert!(parse_invocation(&[]).is_err());
        assert!(parse_invocation(&["frobnicate".to_string()]).is_err());
        let doctor =
            parse_invocation(&["doctor".to_string(), "--json".to_string()]).expect("doctor");
        assert!(doctor.json);
        assert_eq!(doctor.command, "doctor");
        let plan = parse_invocation(&[
            "plan".to_string(),
            "widgets".to_string(),
            "123".to_string(),
            "--revision".to_string(),
            "0".repeat(40),
        ])
        .expect("plan");
        let plan_args = plan.plan.expect("plan args");
        assert_eq!(plan_args.repository, "widgets");
        assert_eq!(plan_args.issue_number, 123);
        assert!(plan_args.revision.is_some());
        let config = parse_invocation(&[
            "config".to_string(),
            "show".to_string(),
            "--json".to_string(),
        ])
        .expect("config");
        assert_eq!(config.config_action, Some(ConfigAction::Show));
    }

    #[test]
    fn plan_argument_validation_bites() {
        for args in [
            vec!["plan", "widgets", "abc"],
            vec!["plan", "widgets", "0"],
            vec!["plan", "widgets", "1", "--revision", "xyz"],
            vec!["plan"],
            vec!["plan", "widgets", "1", "2"],
        ] {
            let owned: Vec<String> = args.iter().map(|s| s.to_string()).collect();
            assert!(
                parse_invocation(&owned).is_err(),
                "expected usage error for {args:?}"
            );
        }
    }

    #[test]
    fn capabilities_envelope_and_doc_validate() {
        let result = execute(&invocation(&["capabilities", "--json"]));
        assert_eq!(result.exit_code, 0);
        assert_eq!(result.kind, Kind::Ok);
        assert_envelope_valid("capabilities", &result);
        let doc = result.data.as_ref().expect("data");
        let capability = doc.get("capability").expect("capability doc");
        let verdict = validate_doc(Family::Capability, capability);
        assert!(verdict.is_accepted(), "{}", verdict.message());
    }

    #[test]
    fn config_init_envelope_validates() {
        let result = execute(&invocation(&["config", "init", "--json"]));
        assert_eq!(result.exit_code, 0);
        assert_envelope_valid("config init", &result);
    }

    #[test]
    fn missing_config_is_a_typed_config_error() {
        // Discovery is rooted at a home that holds no config, so the assertion
        // holds whatever the developer's ambient
        // $HOME/.config/canter/config.toml contains: plan/status/config
        // validate must refuse with exit 5 and the typed config.not_found.
        for (argv, command) in [
            (&["plan", "widgets", "1"][..], "plan"),
            (&["status"][..], "status"),
            (&["config", "validate"][..], "config validate"),
        ] {
            let result = crate::config::with_config_home(None, || execute(&invocation(argv)));
            assert_eq!(result.exit_code, 5, "{argv:?}");
            assert_eq!(result.kind, Kind::Error, "{argv:?}");
            assert_envelope_valid(command, &result);
            let error = result.error.as_ref().expect("error doc");
            assert_eq!(error.code, "config.not_found", "{argv:?}");
        }
    }

    #[test]
    fn unknown_flags_are_usage_errors() {
        assert!(parse_invocation(&["status".to_string(), "--spawn".to_string()]).is_err());
        assert!(parse_invocation(&["doctor".to_string(), "extra".to_string()]).is_err());
    }

    #[test]
    fn board_parses_config_plan_and_refuses_json_and_positionals() {
        // Issue #91: the interactive surface is now the reachable operator
        // authority path — it takes `--config PATH` (daemon path derivation)
        // and, for one presented reviewed run, `--plan FILE` plus the
        // attested observation axis. A malformed invocation stays a typed
        // usage error that never reaches the state store or the terminal.
        let board = invocation(&["board", "--config", "canter.toml"]);
        assert_eq!(board.command, "board");
        assert!(!board.json);
        assert_eq!(
            board.config_path.as_deref(),
            Some(std::path::Path::new("canter.toml"))
        );
        assert!(
            board.board.is_none(),
            "without --plan the read-only board presents no run"
        );

        let planned = invocation(&[
            "board",
            "--config",
            "canter.toml",
            "--plan",
            "reviewed-plan.json",
            "--caps",
            "4/2/2",
            "--host-available",
            "yes",
            "--harness-lanes",
            "0",
            "--grant",
            "5=gr_0123456789abcdef",
            "--resume",
            "run-seeded-0001=1111111111111111111111111111111111111111111111111111111111111111",
        ]);
        let presented = planned.board.expect("the presented run");
        assert_eq!(
            presented.plan_path,
            std::path::PathBuf::from("reviewed-plan.json")
        );
        assert_eq!(presented.host_available, Some(true));
        assert_eq!(presented.harness_lanes, Some(0));
        assert_eq!(presented.caps.global, 4);
        assert_eq!(presented.caps.per_repository, 2);
        assert_eq!(presented.caps.per_harness, 2);
        assert_eq!(
            presented.grants,
            vec![("5".to_string(), "gr_0123456789abcdef".to_string())]
        );
        assert_eq!(
            presented.resume,
            vec![("run-seeded-0001".to_string(), "1".repeat(64),)]
        );
        // The attestation axis defaults to unknown, never to a yes: an
        // unattested host/occupancy holds work instead of admitting it.
        let bare_plan = invocation(&["board", "--plan", "reviewed-plan.json", "--caps", "4/2/2"]);
        let presented = bare_plan.board.expect("the presented run");
        assert_eq!(presented.host_available, None);
        assert_eq!(presented.harness_lanes, None);
        assert!(presented.grants.is_empty());
        assert!(presented.resume.is_empty());

        // A presented run without the admission axes, and observation flags
        // without a run, are both typed refusals.
        for args in [
            vec!["board", "--plan", "reviewed-plan.json"],
            vec!["board", "--caps", "4/2/2"],
            vec!["board", "--host-available", "yes"],
            vec!["board", "--grant", "5=gr_0123456789abcdef"],
            vec![
                "board",
                "--resume",
                "run-x=1111111111111111111111111111111111111111111111111111111111111111",
            ],
        ] {
            let owned: Vec<String> = args.iter().map(|s| s.to_string()).collect();
            assert!(
                parse_invocation(&owned).is_err(),
                "expected a typed refusal for {args:?}"
            );
        }
        // Malformed flag values are typed usage errors too (never a call).
        for args in [
            vec!["board", "--plan", "p.json", "--caps", "4/2"],
            vec!["board", "--plan", "p.json", "--caps", "a/b/c"],
            vec![
                "board", "--plan", "p.json", "--caps", "4/2/2", "--grant", "5",
            ],
            vec![
                "board",
                "--plan",
                "p.json",
                "--caps",
                "4/2/2",
                "--grant",
                "5=not-a-grant",
            ],
            vec![
                "board", "--plan", "p.json", "--caps", "4/2/2", "--resume", "x=zz",
            ],
            vec![
                "board",
                "--plan",
                "p.json",
                "--caps",
                "4/2/2",
                "--host-available",
                "maybe",
            ],
            vec![
                "board",
                "--plan",
                "p.json",
                "--caps",
                "4/2/2",
                "--harness-lanes",
                "-1",
            ],
        ] {
            let owned: Vec<String> = args.iter().map(|s| s.to_string()).collect();
            assert!(
                parse_invocation(&owned).is_err(),
                "expected a typed refusal for {args:?}"
            );
        }
        for args in [
            vec!["board", "--json"],
            vec!["board", "extra"],
            vec!["board", "--config"],
            vec!["board", "--plan"],
            vec!["board", "--caps"],
        ] {
            let owned: Vec<String> = args.iter().map(|s| s.to_string()).collect();
            assert!(
                parse_invocation(&owned).is_err(),
                "expected a typed refusal for {args:?}"
            );
        }
    }

    #[test]
    fn queue_preview_invocation_parses_and_refuses_cross_command_flags() {
        // Issue #91: the plan producer is a first-class `queue` subcommand.
        let preview = invocation(&[
            "queue",
            "preview",
            "--repository",
            "widgets",
            "--harness",
            "lane-1",
            "--host",
            "host-1",
            "--issue",
            "5=1111111111111111111111111111111111111111",
            "--caps",
            "4/2/2",
            "--out",
            "plan.json",
            "--json",
        ]);
        assert_eq!(preview.command, "queue preview");
        assert!(preview.json);
        let Some(QueueAction::Preview(args)) = preview.queue_action else {
            panic!("expected the preview action");
        };
        assert_eq!(args.repository, "widgets");
        assert_eq!(args.harness, "lane-1");
        assert_eq!(args.host, "host-1");
        assert_eq!(
            args.selected,
            vec![(5, "1111111111111111111111111111111111111111".to_string())]
        );
        assert_eq!(args.caps.global, 4);
        assert_eq!(args.out.as_deref(), Some(std::path::Path::new("plan.json")));
        assert!(args.host_available.is_none(), "unknown is the default");
        assert!(args.harness_lanes.is_none(), "unknown is the default");
        assert!(args.boundary_phase.is_none());
        assert!(args.integration_branch.is_none());
        assert!(args.completion_branch.is_none());

        let base = [
            "queue",
            "preview",
            "--repository",
            "widgets",
            "--harness",
            "lane-1",
            "--host",
            "host-1",
            "--issue",
            "5=1111111111111111111111111111111111111111",
            "--caps",
            "4/2/2",
        ];
        let without = |drop: &str| -> Vec<String> {
            let mut args: Vec<String> = base.iter().map(|s| s.to_string()).collect();
            if let Some(position) = args.iter().position(|value| value == drop) {
                args.drain(position..=position + 1);
            }
            args
        };
        for flag in ["--repository", "--harness", "--host", "--issue", "--caps"] {
            assert!(
                parse_invocation(&without(flag)).is_err(),
                "{flag} is required for a preview"
            );
        }

        // The two surfaces never swap flags: a submission authorization is
        // not a preview input, and preview inputs are not a submission.
        let mut submit_with_preview = vec!["queue", "submit"];
        submit_with_preview.extend(base[2..].iter().copied());
        submit_with_preview.extend(["--request", "r.json", "--confirm-digest"]);
        let mut owned: Vec<String> = submit_with_preview.iter().map(|s| s.to_string()).collect();
        owned.push("0".repeat(64));
        assert!(parse_invocation(&owned).is_err());

        for args in [
            vec![
                "queue",
                "status",
                "--submission",
                "qs_0123456789abcdef",
                "--repository",
                "widgets",
            ],
            vec![
                "queue",
                "preview",
                "--repository",
                "widgets",
                "--harness",
                "lane-1",
                "--host",
                "h",
                "--issue",
                "5=1111111111111111111111111111111111111111",
                "--caps",
                "4/2/2",
                "--request",
                "r.json",
            ],
            vec![
                "queue",
                "preview",
                "--repository",
                "widgets",
                "--harness",
                "lane-1",
                "--host",
                "h",
                "--issue",
                "5=1111111111111111111111111111111111111111",
                "--caps",
                "4/2/2",
                "--supervise",
                "arm",
            ],
        ] {
            let owned: Vec<String> = args.iter().map(|s| s.to_string()).collect();
            assert!(
                parse_invocation(&owned).is_err(),
                "expected a cross-command refusal for {args:?}"
            );
        }
    }

    #[test]
    fn board_plan_preflight_is_typed_and_labels_without_a_host_path() {
        // `board --plan` loads the reviewed document as a pure file load (no
        // config, no state store, no terminal). The typed refusals are
        // stable codes; a loaded document is labelled with its file NAME so
        // the displayed source can never leak a host path.
        let dir = std::env::temp_dir().join(format!("hf-cmd-board-plan-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("fixture dir");
        let base = BoardArgs {
            plan_path: dir.join("missing.json"),
            host_available: None,
            harness_lanes: None,
            caps: crate::lifecycle::ConcurrencyCaps {
                global: 4,
                per_repository: 2,
                per_harness: 2,
            },
            grants: Vec::new(),
            resume: Vec::new(),
        };
        let refused = presented_run(&base).expect_err("an unreadable plan refuses");
        assert_eq!(refused.exit_code, 2);
        assert_eq!(
            refused.error.as_ref().expect("error doc").code,
            "usage.board_plan"
        );

        let malformed = dir.join("malformed.json");
        std::fs::write(&malformed, "[1, 2, 3]\n").expect("write malformed");
        let refused = presented_run(&BoardArgs {
            plan_path: malformed,
            ..base.clone()
        })
        .expect_err("a non-object document refuses");
        assert_eq!(refused.exit_code, 2);
        assert_eq!(
            refused.error.as_ref().expect("error doc").code,
            "usage.board_plan"
        );

        let valid = dir.join("reviewed-plan.json");
        std::fs::write(
            &valid,
            "{\"schema\":\"hf-queue-preview/v1\",\"repository\":\"example-org/widgets\"}\n",
        )
        .expect("write plan");
        let run = presented_run(&BoardArgs {
            plan_path: valid,
            host_available: Some(true),
            harness_lanes: Some(0),
            ..base.clone()
        })
        .expect("a document object loads");
        assert_eq!(
            run.source, "reviewed-plan.json",
            "the label is the file name"
        );
        assert!(!run.source.contains('/'), "the label is never a host path");
        assert_eq!(run.host_available, Some(true));
        assert_eq!(run.harness_lanes, Some(0));
        assert_eq!(run.caps.per_harness, 2);
        assert!(run.grants.is_empty() && run.resume.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn percentile_helper_is_reachable_through_execute_path() {
        // percentile_ms is a public observe helper; this guards the human
        // timings line math used by status.
        let samples = [3u64, 1, 2];
        assert_eq!(crate::observe::percentile_ms(&samples, 50.0), 2);
        assert_eq!(crate::observe::percentile_ms(&samples, 95.0), 3);
    }

    // -----------------------------------------------------------------
    // lane (issue #78)
    // -----------------------------------------------------------------

    fn lane_plan_flags(lane: &str) -> Vec<String> {
        [
            "--lane",
            lane,
            "--generation",
            "1",
            "--session",
            "sess-1",
            "--process",
            "proc-1",
            "--role",
            "implementer",
            "--worktree",
            "worktrees/issues/78",
            "--reason",
            "lane window",
        ]
        .iter()
        .map(|value| value.to_string())
        .collect()
    }

    fn lane_args(sub: &str, lane: &str, extra: &[&str]) -> Vec<String> {
        let mut args = vec!["lane".to_string(), sub.to_string()];
        args.extend(lane_plan_flags(lane));
        args.extend(extra.iter().map(|value| value.to_string()));
        args
    }

    fn invocation_of(args: Vec<String>) -> Invocation {
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        invocation(&refs)
    }

    fn parse_of(args: Vec<String>) -> Result<Invocation, ParseError> {
        parse_invocation(&args)
    }

    #[test]
    fn lane_invocations_parse_and_validate() {
        let preview = invocation_of(lane_args("preview", "lane-1", &["--json"]));
        assert_eq!(preview.command, "lane preview");
        assert!(matches!(preview.lane_action, Some(LaneAction::Preview(_))));

        let request = invocation_of(lane_args("request", "lane-1", &["--yes"]));
        assert_eq!(request.command, "lane request");
        match request.lane_action {
            Some(LaneAction::Request(args)) => {
                assert!(args.yes);
                assert!(args.confirm_digest.is_none());
            }
            other => panic!("expected a request action, got {other:?}"),
        }

        let status = invocation(&[
            "lane",
            "status",
            "--replacement",
            "rp_0123456789abcdef",
            "--json",
        ]);
        assert_eq!(status.command, "lane status");
        match status.lane_action {
            Some(LaneAction::Status(args)) => {
                assert_eq!(args.replacement.as_deref(), Some("rp_0123456789abcdef"));
            }
            other => panic!("expected a status action, got {other:?}"),
        }

        // Malformed or mixed invocations are usage errors (exit 2).
        for args in [
            lane_args("preview", "lane-1", &["--confirm-digest", &"a".repeat(64)]),
            lane_args("request", "lane-1", &["--confirm-digest", "not-hex"]),
            lane_args("request", "lane-1", &["--idempotency-key", "bad"]),
            lane_args("preview", "Bad Lane", &[]),
            lane_args("preview", "lane-1", &["--generation", "0"]),
            vec!["lane".to_string(), "status".to_string()],
            vec![
                "lane".to_string(),
                "status".to_string(),
                "--lane".to_string(),
                "lane-1".to_string(),
            ],
            vec![
                "lane".to_string(),
                "status".to_string(),
                "--replacement".to_string(),
                "rp_0123456789abcdef".to_string(),
                "--lane".to_string(),
                "lane-1".to_string(),
            ],
            vec!["lane".to_string(), "unknown".to_string()],
        ] {
            assert!(
                parse_of(args.clone()).is_err(),
                "expected a usage error for {args:?}"
            );
        }

        // Help requests print the lane usage.
        match parse_invocation(&["lane".to_string(), "--help".to_string()]) {
            Err(ParseError::Help(text)) => {
                assert!(text.contains("canter lane <preview|request|status>"))
            }
            other => panic!("expected lane help, got {other:?}"),
        }
    }

    #[test]
    fn lane_request_parameters_carry_exactly_the_plan_inputs() {
        let plan = crate::handoff::LanePlan::build(
            crate::handoff::validate_plan_input(
                "lane-1",
                2,
                "sess-1",
                "proc-1",
                "implementer",
                "worktrees/issues/78",
                "lane window",
            )
            .expect("valid plan input"),
            None,
        );
        let params = lane_request_params(&plan, None);
        assert_eq!(params.get("lane_id").and_then(Val::as_str), Some("lane-1"));
        assert_eq!(params.get("generation").and_then(Val::as_int), Some(2));
        assert_eq!(
            params.get("source_session").and_then(Val::as_str),
            Some("sess-1")
        );
        assert_eq!(
            params.get("reason").and_then(Val::as_str),
            Some("lane window")
        );
        assert!(params.get("profile").is_none(), "no bound profile");
        let key = params
            .get("idempotency_key")
            .and_then(Val::as_str)
            .expect("generated key");
        assert!(
            crate::formats::is_idempotency_key(key),
            "the generated key is well formed: {key:?}"
        );
        let explicit = lane_request_params(&plan, Some("ik_explicit-0001"));
        assert_eq!(
            explicit.get("idempotency_key").and_then(Val::as_str),
            Some("ik_explicit-0001")
        );
    }

    #[test]
    fn the_read_only_lane_guard_refuses_every_mutating_method() {
        // The guard is the closed allowlist: a mutating lane method is
        // refused typed BEFORE any socket is opened. Removing this check
        // makes this test fail (the mutation probe for issue #78).
        let path = std::env::temp_dir().join("canter-lane-read-only-guard.sock");
        for method in [
            "lane.replacement.request",
            "lane.replacement.advance",
            "lane.replacement.hold",
            "lane.replacement.cancel",
            "lane.checkpoint.create",
            "lane.retire",
            "lane.start",
            "lane.adopt",
            "lane.successor.consume",
            "apply",
            "run.pause",
            "run.resume",
            "run.retry",
        ] {
            let error = read_only_call(&path, method, None)
                .expect_err("a mutating method must never pass the read-only guard");
            assert_eq!(error.code, "client.read_only", "{method}: {error:?}");
        }
        // The allowlisted read-only methods pass the guard and fail only at
        // the (absent) socket.
        for method in READ_ONLY_METHODS {
            let error = read_only_call(&path, method, None)
                .expect_err("no socket exists at the probe path");
            assert_eq!(error.code, "client.connect", "{method}: {error:?}");
        }
    }
}
