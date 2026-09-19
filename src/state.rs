//! Daemon-owned SQLite state (issue #5, AC2/AC5/AC6).
//!
//! SQLite is the durable authority for leases, idempotency claims, audit
//! records (hash-chained), epochs, grants, workflow instances, schedules,
//! and recovery state. Every write goes through one `Connection` guarded by
//! a mutex: the daemon is the sole writer and the CLI never opens the
//! database (spec-state.md). Writes run with `synchronous=FULL` so a
//! committed transaction is fsynced; any SQLite write failure poisons the
//! state so later mutations fail closed until the process restarts.
//!
//! Journal semantics (spec-state.md AC6): a mutation's intent is journaled
//! in the same transaction that claims its idempotency key (durable before
//! any effect); the typed outcome is journaled when the effect resolves.
//! Audit records form a hash chain: `record_hash = sha256(line || prev)`.
//! Retention is bounded (defaults keep the chain genesis plus the last N
//! rows); the chain genesis row is never pruned so verification always has
//! an anchor.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use rusqlite::{Connection, OptionalExtension, params};

use crate::canonical::{canonical_bytes, canonical_text, sha256_hex};
use crate::time;
use crate::value::{Val, bool_, integer, null, object, string};

/// The schema version this binary understands (also `PRAGMA user_version`).
pub const SCHEMA_VERSION: i64 = 12;

/// Bounded-retention defaults (rows kept besides the chain genesis).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Retention {
    /// Audit rows retained beyond the genesis row.
    pub audit_rows: i64,
    /// Event rows retained.
    pub event_rows: i64,
}

impl Default for Retention {
    fn default() -> Retention {
        Retention {
            audit_rows: 5000,
            event_rows: 2000,
        }
    }
}

/// A state operation failure. Codes are stable and typed for RPC responses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateError {
    /// Stable error code (`state.open`, `state.corrupt`, `state.schema_future`,
    /// `state.write_full`, `state.write_io`, `state.busy`, `state.audit_tampered`,
    /// `state.poisoned`, `state.conflict`, `state.not_found`).
    pub code: &'static str,
    /// Human message (never contains credentials).
    pub message: String,
}

fn state_error(code: &'static str, message: impl Into<String>) -> StateError {
    StateError {
        code,
        message: message.into(),
    }
}

impl StateError {
    /// Map a rusqlite failure onto a typed state error.
    fn from_sqlite(context: &str, err: rusqlite::Error) -> StateError {
        match &err {
            rusqlite::Error::SqliteFailure(ffi, message) => {
                use rusqlite::ffi::ErrorCode;
                let detail = message.as_deref().unwrap_or("");
                match ffi.code {
                    ErrorCode::DiskFull => state_error(
                        "state.write_full",
                        format!("{context}: SQLite disk full (SQLITE_FULL) {detail}"),
                    ),
                    ErrorCode::SystemIoFailure | ErrorCode::CannotOpen => state_error(
                        "state.write_io",
                        format!("{context}: SQLite I/O failure (SQLITE_IOERR) {detail}"),
                    ),
                    ErrorCode::NotADatabase | ErrorCode::DatabaseCorrupt => state_error(
                        "state.corrupt",
                        format!("{context}: SQLite database corrupt ({detail})"),
                    ),
                    ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked => state_error(
                        "state.busy",
                        format!("{context}: SQLite busy/locked ({detail})"),
                    ),
                    ErrorCode::ReadOnly => state_error(
                        "state.readonly",
                        format!("{context}: SQLite database is read-only ({detail})"),
                    ),
                    ErrorCode::ConstraintViolation => state_error(
                        "state.conflict",
                        format!("{context}: SQLite constraint violated ({detail})"),
                    ),
                    _ => state_error(
                        "state.unavailable",
                        format!("{context}: SQLite error ({detail})"),
                    ),
                }
            }
            _ => state_error(
                "state.unavailable",
                format!("{context}: database error: {err}"),
            ),
        }
    }
}

/// One audit/journal record that was durably written.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditRow {
    /// Monotonic audit sequence.
    pub seq: i64,
    /// State epoch at append time.
    pub epoch: i64,
    /// Canonical hf-audit/v1 JSONL line (with trailing LF).
    pub line: String,
    /// sha256 over `line || prev_hash` ("" for the genesis row).
    pub record_hash: String,
    /// Event seq of the journal.appended event emitted with this record.
    pub event_seq: i64,
}

/// An idempotency claim row (recovery checkpoint when status = claimed).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClaimRow {
    /// The idempotency key.
    pub key: String,
    /// Request id that made the claim.
    pub request_id: String,
    /// RPC method.
    pub method: String,
    /// Claim status (`claimed` | `spent` | `ambiguous` | `voided`).
    pub status: String,
    /// Canonical hf-outcome/v1 document when resolved.
    pub outcome: Option<String>,
    /// Canonical hf-rpc-response/v1 document for idempotent replay.
    pub response: Option<String>,
    /// Canonical hf-rpc-request/v1 document that made the claim.
    pub request_line: String,
}

/// A grant row (route grants; issuance arrives with the workflow engine
/// slice, invalidation/revoke/list land here).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantRow {
    /// Grant id (`gr_` + 16 hex).
    pub grant_id: String,
    /// Repository identity (`owner/name`).
    pub repository: String,
    /// Issue number.
    pub issue_number: i64,
    /// Acceptance revision (40-hex).
    pub issue_revision: String,
    /// Workflow hash (64-hex).
    pub workflow_hash: String,
    /// Policy hash (64-hex).
    pub policy_hash: String,
    /// Phase (closed set).
    pub phase: String,
    /// Path-scoped lane scope.
    pub scope: String,
    /// Capabilities (closed set), JSON array text.
    pub caps: String,
    /// Expiry (RFC3339 UTC).
    pub expires_at: String,
    /// Epoch the grant was issued against.
    pub state_epoch: i64,
    /// Status (`active` | `revoked` | `invalidated`).
    pub status: String,
    /// Created at (RFC3339 UTC).
    pub created_at: String,
}

/// One durable run retry authorization (issue #86): exactly ONE bounded
/// re-dispatch of ONE diagnosed step of ONE run. Row count bounds attempts;
/// a row is never edited except to record its single consumption.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunRetryRow {
    /// Retry id (`rt_` + 16 hex, derived from the run and the step).
    pub retry_id: String,
    /// The owning run.
    pub instance_id: String,
    /// The diagnosed step id.
    pub step_id: String,
    /// 1-based bounded attempt number within (run, step).
    pub attempt: i64,
    /// When the authorization was recorded (RFC3339 UTC).
    pub authorized_at: String,
    /// When the authorization was consumed ('' while unconsumed).
    pub consumed_at: String,
    /// The idempotency key of the dispatch that consumed it ('' otherwise).
    pub consumed_key: String,
}

/// The outcome of checking one step dispatch against the bounded-retry
/// fence (issue #86): a first dispatch needs no authorization, a
/// re-dispatch of a diagnosed failed step consumes exactly one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RunRetryClaim {
    /// No diagnosed failure exists for this (run, step): no authorization
    /// is required (the fence only bounds RE-dispatches).
    NotRequired,
    /// One unconsumed authorization existed and was consumed by this
    /// dispatch (single use; the row records the claim key).
    Consumed(String),
    /// A diagnosed failed attempt exists but no unconsumed authorization
    /// does: the re-dispatch is refused (`refusal.run.retry_required`).
    Missing,
}

/// The number of bounded retries one (run, step) may ever authorize.
pub const RUN_RETRY_MAX: i64 = 3;

/// Whether one RECORDED step attempt is a step diagnosis: an outcome of an
/// attempt that actually ran (or whose work was refused for a reason of the
/// step's own), and therefore one the bounded-retry fence bounds.
///
/// Issue #184: a pre-effect refusal for the run's OWN lapsed authorization
/// window is NOT a step diagnosis. The step never ran, no effect was
/// attempted and nothing was consumed — the run's window lapsed, which is an
/// authorization event, not a step failure. Such a record neither demands
/// nor consumes a bounded retry authorization, so a lapse can never strand a
/// frontier behind `refusal.run.retry_required`. One fact, three readers:
/// the retry fence ([`State::claim_run_retry`]), the daemon's supervised
/// dispatch decision and the supervision driver's own eligibility.
pub fn step_attempt_diagnosed(status: &str, code: &str) -> bool {
    if !matches!(status, "failed" | "refused" | "ambiguous") {
        return false;
    }
    code != crate::mutation::code::GRANT_EXPIRED
}

/// The recorded outcome of ONE explicit run release (issue #146): the run
/// row as it stands AFTER the release commit, whether the release removed the
/// unique ownership row that named this run, and the authorization window the
/// run held when it was released.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunReleaseOutcome {
    /// The released row (`status: "invalidated"`, pause state cleared).
    pub run: InstanceRow,
    /// Whether this release removed the ownership row that named the run
    /// (`false` = the run owned no issue any more; nothing was removed).
    pub ownership_freed: bool,
    /// The run's own grant row at release time (`None` = the grant no longer
    /// exists).
    pub grant: Option<GrantRow>,
    /// Whether that window was still usable when the run was released: the
    /// row exists, is `active` and has not expired.
    pub grant_usable: bool,
}

/// The recorded outcome of ONE engine-owned renewal of a live run's own
/// lapsed authorization window (issue #184): the successor grant row the run
/// is bound to from here on, the lapsed grant row it supersedes, and the
/// window length (seconds) derived from the run's remaining committed spine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LapsedGrantRenewal {
    /// The successor grant (same bindings, new id, new recorded expiry).
    pub successor: GrantRow,
    /// The lapsed grant it supersedes (the run's own presented window).
    pub superseded: GrantRow,
    /// The window length recorded on the successor, in seconds.
    pub window_secs: i64,
}

/// The window (seconds) one renewal must cover for one run (issue #184):
/// the sum of the DOCUMENTED effect deadlines of the run's remaining
/// committed-spine steps — the worker and independent-review round trips the
/// run still owes — never a fixed default. `None` when the achieved ledger
/// says the run owes nothing (its frontier is exhausted) or a spine step
/// document is unreadable; the derived sum is clamped to the documented
/// window ceiling.
fn renewal_window_secs(
    spine: &[String],
    steps: &[Val],
    attempts: &[(String, String)],
    current_node: &str,
) -> Option<i64> {
    let frontier = crate::run_control::frontier_of(spine, attempts, current_node)?;
    let start = crate::run_control::step_index_of(spine, &frontier)?;
    let mut total: i64 = 0;
    for id in spine.iter().skip(start) {
        let step = steps
            .iter()
            .find(|step| step.get("id").and_then(Val::as_str) == Some(id.as_str()))?;
        let kind = crate::mutation::step_kind(step).ok()?;
        let params = match step.get("params") {
            Some(value @ Val::Obj(_)) => Some(value),
            _ => None,
        };
        // A declared `deadline_secs` that is outside the documented bounds
        // can never dispatch its own step, so it contributes the per-kind
        // default this table documents instead of refusing the renewal.
        let secs = crate::mutation::effect_deadline_secs(&kind, params)
            .unwrap_or_else(|_| crate::mutation::default_deadline_secs(&kind));
        total = total.saturating_add(secs as i64);
    }
    Some(total.clamp(1, crate::mutation::GRANT_WINDOW_MAX_SECS))
}

/// The content-derived successor grant id of one renewal (issue #184):
/// deterministic in the run, the superseded grant and the recorded expiry,
/// so a replayed renewal of the SAME lapsed window mints the same identity
/// and can never fork two live successors.
fn renewal_grant_id(instance_id: &str, superseded: &str, expires_at: &str) -> String {
    let derived = format!("canter/grant-renewal/v1|{instance_id}|{superseded}|{expires_at}");
    format!(
        "gr_{}",
        &crate::canonical::sha256_hex(derived.as_bytes())[..16]
    )
}

/// A workflow engine instance row (m0002: workflow pin, phase, node, review
/// rounds, pause state). Issuance/advance decisions belong to the engine;
/// this handle persists them durably.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstanceRow {
    /// Instance id (slug).
    pub instance_id: String,
    /// Repository identity.
    pub repository: String,
    /// Workflow id (slug).
    pub workflow_id: String,
    /// Workflow hash (64-hex; pinned at start — changed-in-flight refusal).
    pub workflow_hash: String,
    /// Policy hash (64-hex).
    pub policy_hash: String,
    /// Binding grant id.
    pub grant_id: String,
    /// Issue number.
    pub issue_number: i64,
    /// Acceptance revision (40-hex).
    pub issue_revision: String,
    /// Allowed phase (closed set).
    pub phase: String,
    /// Path-scoped lane scope.
    pub scope: String,
    /// Capabilities (closed set), JSON array text.
    pub caps: String,
    /// Current workflow node id ("" until started).
    pub current_node: String,
    /// Normal review/fix rounds used (AC4).
    pub normal_rounds: u32,
    /// Recovery rounds used (AC4).
    pub recovery_rounds: u32,
    /// Whether the item is in the human queue (AC4 exhaustion).
    pub human_queue: bool,
    /// Count of explicit terminal blockers (AC7).
    pub terminal_blockers: u32,
    /// Whether the instance is paused (AC8; durable across restart).
    pub paused: bool,
    /// Stored fresh authorized resume digest (AC8).
    pub resume_digest: String,
    /// Durable pause REQUEST recorded by the run-scoped control surface
    /// (issue #86): new step dispatch is refused from this moment on while
    /// in-flight work keeps running, and the pause reaches its safe
    /// boundary (commits `paused`) at the run's next recorded step
    /// boundary.
    pub pause_requested: bool,
    /// Bounded operator reason of the pause request ('' when none).
    pub pause_reason: String,
    /// When the pause request was recorded (RFC3339 UTC; '' when none).
    pub pause_requested_at: String,
    /// State epoch the instance runs under.
    pub state_epoch: i64,
    /// Status (`new` | `running` | `paused` | `human_queue` | `blocked` |
    /// `done` | `invalidated`).
    pub status: String,
    /// Created at (RFC3339 UTC).
    pub created_at: String,
    /// Last update (RFC3339 UTC).
    pub updated_at: String,
}

/// A durable review-evidence row (issue #8; spec-review-evidence.md):
/// exact feature head + integration base + workflow/policy hashes plus the
/// reviewer verdict and named checks. Invalidated only by revalidation
/// against live state before an integration merge (never edited in place).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidenceRow {
    /// Evidence id (`ev_` + 16 hex).
    pub evidence_id: String,
    /// Owning workflow instance id.
    pub instance_id: String,
    /// Repository identity.
    pub repository: String,
    /// Exact reviewed feature-branch head (40-hex).
    pub feature_head: String,
    /// Exact integration-base SHA the review was performed against (40-hex).
    pub integration_base: String,
    /// Workflow hash (64-hex).
    pub workflow_hash: String,
    /// Policy hash (64-hex).
    pub policy_hash: String,
    /// Verdict (`pass` | `fail`).
    pub verdict: String,
    /// Reviewer identity (distinct from the implementer).
    pub reviewer: String,
    /// Canonical JSON array of named checks (`[{"name","status"}]`).
    pub checks: String,
    /// Recorded at (RFC3339 UTC).
    pub created_at: String,
}

/// A bounded, deterministic board-read row (issue #83): one daemon-owned
/// run joined with a bounded slice of its durable review evidence. This is
/// a read projection over recorded facts only — the run identity is the
/// durable instance row and evidence is never inferred from activity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoardRunRow {
    /// The durable workflow-instance row (run identity and state).
    pub run: InstanceRow,
    /// Most recent evidence row for the run (merge-gate ordering), if any.
    pub evidence_newest: Option<EvidenceRow>,
    /// Bounded list of evidence ids, newest first (at most the requested
    /// per-row cap; [`BoardRunRow::evidence_total`] makes overflow explicit).
    pub evidence_ids: Vec<String>,
    /// Total recorded evidence rows for the run.
    pub evidence_total: i64,
}

/// A recorded first-real-write approval (issue #8 AC10 plumbing). The
/// approval is recorded by a human-gated flow BEFORE any real external
/// write canary; this slice only proves the gate with fakes and never runs
/// a real canary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalRow {
    /// Approval id (`ap_` + 16 hex).
    pub approval_id: String,
    /// Recorded scope (`first-write-canary` is the closed scope).
    pub scope: String,
    /// 64-hex human-confirmed digest bound to the approval.
    pub digest: String,
    /// Whether the digest was confirmed on an interactive TTY.
    pub interactive: bool,
    /// Recorded at (RFC3339 UTC).
    pub recorded_at: String,
}

/// One durable queue submission (issue #85): the committed approval binding
/// of one selected-issue run against the exact preview digest. The row, its
/// membership items and every admitted run/ownership row commit in ONE
/// transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueueSubmissionRow {
    /// Submission id (`qs_` + 16 hex, derived from the approved digest and
    /// the idempotency key).
    pub submission_id: String,
    /// Normalized repository identity (`owner/name`).
    pub repository: String,
    /// State epoch the submission committed under.
    pub state_epoch: i64,
    /// The approved preview digest (64-hex).
    pub digest: String,
    /// Bound role-configuration key (the harness key).
    pub role_key: String,
    /// Bound role-configuration revision (64-hex).
    pub role_revision: String,
    /// Bound workflow id.
    pub workflow_id: String,
    /// Bound workflow content hash (64-hex).
    pub workflow_hash: String,
    /// Allowed completion boundary phase (closed grant phase).
    pub boundary_phase: String,
    /// Integration branch of the boundary.
    pub integration_branch: String,
    /// Completion branch of the boundary.
    pub completion_branch: String,
    /// Boundary capability subset (closed set), JSON array text.
    pub boundary_caps: String,
    /// Canonical bound-input document (the exact digest document).
    pub request_line: String,
    /// Approved global concurrency cap (the admission input the advance
    /// re-applies against live counts).
    pub caps_global: i64,
    /// Approved per-repository concurrency cap.
    pub caps_per_repository: i64,
    /// Approved per-harness concurrency cap.
    pub caps_per_harness: i64,
    /// Attested same-harness occupancy the submission committed under;
    /// `None` = unknown (never admitted).
    pub harness_lanes: Option<i64>,
    /// Committed at (RFC3339 UTC).
    pub created_at: String,
}

/// One persisted membership item of a queue submission (issue #85): the
/// per-issue admission outcome (`admitted` | `waiting` | `refused`) with its
/// stable reason code and the bound run when one was started.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueueSubmissionItemRow {
    /// Owning submission id.
    pub submission_id: String,
    /// Deterministic membership order (the preview's classified order).
    pub ordinal: i64,
    /// Stable work-item id (`wi_` + 16 hex).
    pub work_item: String,
    /// Issue number within the submission's repository.
    pub issue_number: i64,
    /// Selected acceptance revision (40-hex).
    pub issue_revision: String,
    /// Admission status (`admitted` | `waiting` | `refused`).
    pub status: String,
    /// Stable reason code when not admitted.
    pub reason: Option<String>,
    /// Bounded human message for the reason.
    pub message: Option<String>,
    /// The bound run when the item was admitted (started or explicitly
    /// resumed); `None` for waiting/refused items.
    pub instance_id: Option<String>,
    /// The grant id the item was presented with (the exact approval the
    /// advance re-verifies under the guard); `''` when none was presented.
    pub grant_id: String,
}

/// One durable queue-advance row (issue #96): ONE consumed verified delivery
/// of one submission item. `(submission_id, delivered_ordinal)` is the
/// idempotency key — the delivery event can be consumed exactly once, so a
/// duplicate event, a replayed check or a crash/restart can never dispatch
/// twice. The row records the dispatch (`next_*`, `next_instance_id`) or the
/// recorded hold (`reason`/`message`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueueAdvanceRow {
    /// The already-authorized submission whose cursor moved.
    pub submission_id: String,
    /// Ordinal of the delivered membership item (the idempotency key).
    pub delivered_ordinal: i64,
    /// Stable work-item id of the delivered issue.
    pub delivered_work_item: String,
    /// The delivered head (40-hex) of the verified delivery.
    pub delivered_head: String,
    /// The review-evidence row that carried the verdict.
    pub evidence_id: String,
    /// Ordinal of the considered next item (`None` = nothing left).
    pub next_ordinal: Option<i64>,
    /// Stable work-item id of the considered next item.
    pub next_work_item: Option<String>,
    /// The dispatched run when the next item was admitted.
    pub next_instance_id: Option<String>,
    /// The stable hold code when the next item was held.
    pub reason: Option<String>,
    /// Bounded human message of the hold.
    pub message: Option<String>,
    /// Recorded at (RFC3339 UTC).
    pub at: String,
}

/// One unique work-ownership row (issue #85): the live owner of one
/// repository issue. `PRIMARY KEY (repository, issue_number)` is the
/// schema-level uniqueness guarantee.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueueOwnershipRow {
    /// Repository identity (`owner/name`).
    pub repository: String,
    /// Issue number.
    pub issue_number: i64,
    /// Stable work-item id (`wi_` + 16 hex).
    pub work_item: String,
    /// The submission that created the owning run.
    pub submission_id: String,
    /// The owning run.
    pub instance_id: String,
    /// Created at (RFC3339 UTC).
    pub created_at: String,
}

/// The presented verdict of one membership item (issue #85). The daemon
/// derives it from the freshly re-rendered preview; the transaction
/// re-verifies every state-derived fact before it commits, so the verdict is
/// a fail-closed hint, never the authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SubmissionVerdict {
    /// Eligible: the transaction decides admit-or-wait (live ownership,
    /// grant status, scope overlap and concurrency capacity are re-verified
    /// first).
    Approved,
    /// Waiting on an environment/attestation prerequisite; the transaction
    /// persists the label and consumes no capacity slot.
    Waiting {
        /// Stable reason code.
        code: &'static str,
        /// Bounded human message.
        message: String,
    },
    /// Refused before the transaction: a dependency, ownership or grant fact
    /// this submission cannot settle.
    Refused {
        /// Stable reason code.
        code: &'static str,
        /// Bounded human message.
        message: String,
    },
}

/// One membership item of a presented queue submission (issue #85).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueueSubmissionItemPlan {
    /// Deterministic membership order (the preview's classified order).
    pub ordinal: i64,
    /// Stable work-item id (`wi_` + 16 hex).
    pub work_item: String,
    /// Issue number within the submission's repository.
    pub issue_number: i64,
    /// Selected acceptance revision (40-hex).
    pub issue_revision: String,
    /// The presented active grant bound to this issue (required to admit).
    pub grant_id: Option<String>,
    /// The explicit resume authorization presented for this item's paused
    /// run, when one is (64-hex engine-minted digest).
    pub resume_digest: Option<String>,
    /// The presented verdict.
    pub verdict: SubmissionVerdict,
}

/// The presented plan of one durable queue submission (issue #85). Purely
/// typed: every field has been validated by the caller; the transaction
/// re-verifies the state-derived facts that can move (epoch, ownership,
/// grant status/expiry, overlap, capacity) before writing anything.
#[derive(Clone, Debug)]
pub struct QueueSubmissionPlan {
    /// Deterministic submission id (`qs_` + 16 hex).
    pub submission_id: String,
    /// Normalized repository identity.
    pub repository: String,
    /// The approved state epoch.
    pub state_epoch: i64,
    /// The approved preview digest.
    pub digest: String,
    /// Bound role-configuration key.
    pub role_key: String,
    /// Bound role-configuration revision.
    pub role_revision: String,
    /// Bound workflow id.
    pub workflow_id: String,
    /// Bound workflow content hash.
    pub workflow_hash: String,
    /// Allowed completion boundary phase.
    pub boundary_phase: String,
    /// Boundary integration branch.
    pub integration_branch: String,
    /// Boundary completion branch.
    pub completion_branch: String,
    /// Boundary capability subset (closed set).
    pub boundary_caps: Vec<String>,
    /// Canonical bound-input document (the exact digest document).
    pub request_line: String,
    /// Presented fan-out concurrency caps (the admission axes).
    pub admission_caps: crate::lifecycle::ConcurrencyCaps,
    /// Attested same-harness occupancy; `None` = unknown (never admitted).
    pub harness_lanes: Option<i64>,
    /// Presented membership items in classified order.
    pub items: Vec<QueueSubmissionItemPlan>,
    /// The explicit supervision authorization presented with this submission
    /// (issue #95). `None` = supervision disabled for the admitted runs: the
    /// default. The authorization is committed in the SAME transaction as
    /// the runs it names.
    pub supervision: Option<SupervisionAuthorizationPlan>,
    /// Committed at (RFC3339 UTC).
    pub at: String,
}

/// One live grant binding read inside the submission transaction (the
/// volatile facts — status, epoch, expiry — are re-verified there).
struct GrantBinding {
    repository: String,
    issue_number: i64,
    issue_revision: String,
    workflow_hash: String,
    phase: String,
    scope: String,
    caps: String,
    expires_at: String,
    state_epoch: i64,
    policy_hash: String,
    status: String,
}

/// Running fan-out slot accounting for one submission transaction: the
/// counted lanes (read under the guard) plus the runs admitted so far, in
/// the preview's axis order.
struct FanoutSlots<'a> {
    caps: &'a crate::lifecycle::ConcurrencyCaps,
    counted_global: i64,
    counted_repository: i64,
    harness_lanes: Option<i64>,
    admitted_global: i64,
    admitted_repository: i64,
    admitted_harness: i64,
}

impl FanoutSlots<'_> {
    /// The hold that parks the next eligible item, if one applies: capacity
    /// first (the preview's axis order), then the attestation gap.
    fn hold(&self) -> Option<(&'static str, String)> {
        if self.counted_global + self.admitted_global >= self.caps.global as i64 {
            return Some((
                crate::lifecycle::code::CAP_GLOBAL,
                format!(
                    "the global concurrency cap ({}) is reached ({} active lanes); the item \
                     waits",
                    self.caps.global, self.counted_global
                ),
            ));
        }
        if self.counted_repository + self.admitted_repository >= self.caps.per_repository as i64 {
            return Some((
                crate::lifecycle::code::CAP_REPOSITORY,
                format!(
                    "the per-repository concurrency cap ({}) is reached ({} active lanes); the \
                     item waits",
                    self.caps.per_repository, self.counted_repository
                ),
            ));
        }
        match self.harness_lanes {
            Some(lanes) if lanes + self.admitted_harness < self.caps.per_harness as i64 => None,
            Some(lanes) => Some((
                crate::lifecycle::code::CAP_HARNESS,
                format!(
                    "the per-harness concurrency cap ({}) is reached ({lanes} attested lanes); \
                     the item waits",
                    self.caps.per_harness
                ),
            )),
            None => Some((
                crate::queue_preview::holds::OCCUPANCY_UNKNOWN,
                "the same-harness occupancy is not attested; missing occupancy is never treated \
                 as spare capacity"
                    .to_string(),
            )),
        }
    }

    /// One admitted run consumes one slot on every axis.
    fn consume(&mut self) {
        self.admitted_global += 1;
        self.admitted_repository += 1;
        self.admitted_harness += 1;
    }
}

/// The guard-verified context of ONE membership admission: the live facts
/// the shared decision re-derives (ownership snapshots, counted
/// same-repository lanes) plus the inputs the approved submission bound.
struct QueueAdmission<'a> {
    state: &'a State,
    repository: &'a str,
    submission_id: &'a str,
    epoch: i64,
    at: &'a str,
    workflow_id: &'a str,
    workflow_hash: &'a str,
    ownership: &'a BTreeMap<i64, OwnedRunSnapshot>,
    repository_lanes: &'a [(i64, String)],
}

/// One membership item's admission inputs.
struct QueueAdmissionItem<'a> {
    issue_number: i64,
    issue_revision: &'a str,
    work_item: &'a str,
    grant_id: Option<&'a str>,
    resume_digest: Option<&'a str>,
}

/// Decide one membership item under the caller's transaction guard, and
/// commit its effect when it is admitted: live ownership, the presented
/// grant's status/epoch/expiry/binding, the fan-out capacity and the declared
/// scope overlap are re-derived from live rows HERE, before any write, and an
/// admitted item commits its run row plus its unique ownership row in the
/// same transaction. Shared by the #85 submission transaction and the #96
/// verified-delivery advance, so both admit through ONE code path.
fn admit_queue_item_in_tx(
    tx: &rusqlite::Transaction<'_>,
    ctx: &QueueAdmission<'_>,
    item: &QueueAdmissionItem<'_>,
    slots: &mut FanoutSlots<'_>,
) -> Result<AdmissionDecision, StateError> {
    let scope = format!("worktrees/issues/{}", item.issue_number);
    let mut rotation: Option<(String, String)> = None;
    if let Some(run) = ctx.ownership.get(&item.issue_number) {
        if run.issue_revision != item.issue_revision {
            let Some(candidate_grant) = item.grant_id else {
                return Ok(AdmissionDecision::Refused {
                    code: crate::queue_executor::codes::GRANT,
                    message: format!(
                        "revision rebind from {} to {} requires a fresh presented grant window",
                        run.issue_revision, item.issue_revision
                    ),
                });
            };
            let ordering: Option<(i64, i64)> = tx
                .query_row(
                    "SELECT candidate.rowid, prior.rowid
                       FROM grants candidate, grants prior
                      WHERE candidate.grant_id = ?1 AND prior.grant_id = ?2",
                    params![candidate_grant, run.grant_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(|err| {
                    StateError::from_sqlite("admit_queue_item: revision authorization", err)
                })?;
            if !matches!(ordering, Some((candidate, prior)) if candidate > prior) {
                return Ok(AdmissionDecision::Refused {
                    code: crate::queue_preview::holds::REVISION_STALE,
                    message: format!(
                        "run {} owns revision {} under grant {}; candidate grant {candidate_grant} is not a later authorization window for selected revision {}",
                        run.instance_id, run.issue_revision, run.grant_id, item.issue_revision
                    ),
                });
            }
            // Issue #192: a run whose recorded frontier has reached its own
            // review_evidence step is CARRIED FORWARD, never superseded by a
            // candidate rebuild. Its verified spine (the recorded delivery
            // included) is the thing of value and the committed merge/cleanup
            // tail is still owed, so the later window does not buy a p1
            // restart. The refusal is deliberate and recorded on this item;
            // replacing such a run is an explicit operator act — the audited
            // `run.release` frees its ownership, and a fresh submission then
            // admits a new run.
            if owner_reached_review_frontier_locked(ctx.state, tx, &run.instance_id)? {
                return Ok(AdmissionDecision::Refused {
                    code: crate::queue_executor::codes::FRONTIER_PRESERVED,
                    message: format!(
                        "run {} has reached its review_evidence frontier; {} is its recorded \
                         frontier — a fresh submission never supersedes a verified spine, the run \
                         keeps its ownership and continues its own committed merge/cleanup tail \
                         (release the run explicitly to replace it)",
                        run.instance_id,
                        owner_frontier_summary_locked(ctx.state, tx, &run.instance_id)?
                    ),
                });
            }
            // Issue #209: a run that is live and NOT terminal is never
            // invalidated by admission, wherever its frontier stands. A later
            // authorization window alone does not make the incumbent
            // disposable: its recorded frontier (step, kind, class) is named
            // and the item is refused typed, so an operator decides. The ONE
            // deliberate route stays the explicit, audited `run.release`,
            // after which a fresh submission admits a new run.
            return Ok(AdmissionDecision::Refused {
                code: crate::queue_executor::codes::LIVE_RUN,
                message: format!(
                    "run {} is live with frontier {}; a fresh submission never supersedes a live \
                     run — the incumbent keeps its ownership and its recorded frontier (release \
                     the run explicitly to replace it)",
                    run.instance_id,
                    owner_frontier_summary_locked(ctx.state, tx, &run.instance_id)?
                ),
            });
        } else {
            let expired_rotation = match item.grant_id {
                Some(candidate) if candidate != run.grant_id => {
                    let windows: Option<(i64, i64, String, String, i64)> = tx
                        .query_row(
                            "SELECT candidate.rowid, prior.rowid, prior.status,
                                    prior.expires_at, prior.state_epoch
                               FROM grants candidate, grants prior
                              WHERE candidate.grant_id = ?1 AND prior.grant_id = ?2",
                            params![candidate, run.grant_id],
                            |row| {
                                Ok((
                                    row.get(0)?,
                                    row.get(1)?,
                                    row.get(2)?,
                                    row.get(3)?,
                                    row.get(4)?,
                                ))
                            },
                        )
                        .optional()
                        .map_err(|err| {
                            StateError::from_sqlite("admit_queue_item: grant rotation", err)
                        })?;
                    matches!(
                        windows,
                        Some((candidate_row, prior_row, ref status, ref expires_at, epoch))
                            if candidate_row > prior_row
                                && status == "active"
                                && epoch == ctx.epoch
                                && crate::mutation::is_expired(expires_at, ctx.at)
                    )
                }
                _ => false,
            };
            if expired_rotation {
                rotation = Some((run.instance_id.clone(), run.grant_id.clone()));
            } else {
                // An owner that appeared after the preview moved the verdict: only
                // an explicit engine-authorized resume of a still-paused run admits
                // an owned item; every other same-revision item is refused.
                let authorized = match (item.resume_digest, run.paused) {
                    (Some(presented), true) => {
                        crate::engine::authorize_resume(&run.resume_digest, presented).is_ok()
                    }
                    _ => false,
                };
                if authorized {
                    let affected = tx
                        .execute(
                            "UPDATE instances SET paused = 0, resume_digest = '',
                                    status = 'running', updated_at = ?2
                              WHERE instance_id = ?1 AND paused = 1",
                            params![run.instance_id, ctx.at],
                        )
                        .map_err(|err| StateError::from_sqlite("admit_queue_item: resume", err))?;
                    if affected == 1 {
                        return Ok(AdmissionDecision::Admitted {
                            instance_id: run.instance_id.clone(),
                        });
                    }
                    return Ok(AdmissionDecision::Refused {
                        code: crate::queue_executor::codes::PAUSED,
                        message: "the run left its paused state while the submission committed; \
                             no implicit state change is applied"
                            .to_string(),
                    });
                }
                if run.paused {
                    return Ok(AdmissionDecision::Refused {
                        code: crate::queue_executor::codes::PAUSED,
                        message: format!(
                            "run {} is paused and stays paused: a paused fleet is resumed only \
                             with a separate explicit engine-minted resume authorization",
                            run.instance_id
                        ),
                    });
                }
                return Ok(AdmissionDecision::Refused {
                    code: crate::queue_executor::codes::ALREADY_OWNED,
                    message: format!(
                        "run {} already owns this issue with frontier {}; a duplicate submission \
                         never creates a second owner (release the run explicitly to replace it)",
                        run.instance_id,
                        owner_frontier_summary_locked(ctx.state, tx, &run.instance_id)?
                    ),
                });
            }
        }
    }
    // No live owner: re-verify the presented grant under the guard (status,
    // epoch and expiry).
    let grant_id = item.grant_id.unwrap_or_default();
    let grant: Option<GrantBinding> = tx
        .query_row(
            "SELECT repository, issue_number, issue_revision, workflow_hash, phase,
                    scope, caps, expires_at, state_epoch, policy_hash, status
               FROM grants WHERE grant_id = ?1",
            params![grant_id],
            |row| {
                Ok(GrantBinding {
                    repository: row.get(0)?,
                    issue_number: row.get(1)?,
                    issue_revision: row.get(2)?,
                    workflow_hash: row.get(3)?,
                    phase: row.get(4)?,
                    scope: row.get(5)?,
                    caps: row.get(6)?,
                    expires_at: row.get(7)?,
                    state_epoch: row.get(8)?,
                    policy_hash: row.get(9)?,
                    status: row.get(10)?,
                })
            },
        )
        .optional()
        .map_err(|err| StateError::from_sqlite("admit_queue_item: grant", err))?;
    let Some(grant) = grant else {
        return Ok(AdmissionDecision::Refused {
            code: crate::mutation::code::GRANT_INACTIVE,
            message: format!(
                "no grant {grant_id:?} exists; the presented grant is refused before \
                 any effect"
            ),
        });
    };
    if grant.status != "active" {
        return Ok(AdmissionDecision::Refused {
            code: crate::mutation::code::GRANT_INACTIVE,
            message: format!(
                "grant {grant_id} is {}; a revoked or invalidated grant refuses this \
                 item before any effect",
                grant.status
            ),
        });
    }
    if grant.state_epoch != ctx.epoch {
        return Ok(AdmissionDecision::Refused {
            code: crate::mutation::code::EPOCH_STALE,
            message: format!(
                "grant {grant_id} was issued under epoch {}; grants die with their \
                 epoch",
                grant.state_epoch
            ),
        });
    }
    if crate::mutation::is_expired(&grant.expires_at, ctx.at) {
        return Ok(AdmissionDecision::Refused {
            code: crate::mutation::code::GRANT_EXPIRED,
            message: format!("grant {grant_id} expired at {}", grant.expires_at),
        });
    }
    if grant.repository != ctx.repository
        || grant.issue_number != item.issue_number
        || grant.issue_revision != item.issue_revision
    {
        return Ok(AdmissionDecision::Refused {
            code: crate::queue_executor::codes::GRANT,
            message: format!(
                "grant {grant_id} binds {}#{}@{}, not the selected {scope}",
                grant.repository, grant.issue_number, grant.issue_revision
            ),
        });
    }
    if grant.workflow_hash != ctx.workflow_hash {
        return Ok(AdmissionDecision::Refused {
            code: crate::mutation::code::WORKFLOW_CHANGED,
            message: format!(
                "grant {grant_id} binds workflow {}; the submission binds {}",
                grant.workflow_hash, ctx.workflow_hash
            ),
        });
    }
    if grant.scope != scope {
        return Ok(AdmissionDecision::Refused {
            code: crate::queue_executor::codes::GRANT,
            message: format!(
                "grant {grant_id} declares scope {:?}; the reviewed planned scope is \
                 {scope:?}",
                grant.scope
            ),
        });
    }
    if let Some((instance_id, superseded_grant)) = rotation {
        let affected = tx
            .execute(
                "UPDATE instances SET grant_id = ?2, updated_at = ?3
                  WHERE instance_id = ?1 AND grant_id = ?4
                    AND status IN ('new', 'running', 'human_queue', 'blocked')",
                params![instance_id, grant_id, ctx.at, superseded_grant],
            )
            .map_err(|err| StateError::from_sqlite("admit_queue_item: rotate grant", err))?;
        if affected != 1 {
            return Err(state_error(
                "state.ownership_conflict",
                format!("run {instance_id} changed before its expired grant rotation committed"),
            ));
        }
        let mut key = format!("ik_rotate-{instance_id}-{grant_id}");
        key.truncate(64);
        ctx.state.append_audit_locked(
            tx,
            "grant.rotation",
            &format!(
                "run:{instance_id}:superseded:{superseded_grant}:replacement:{grant_id}:expires:{}",
                grant.expires_at
            ),
            &key,
            None,
            Some(grant_id),
        )?;
        return Ok(AdmissionDecision::Admitted { instance_id });
    }
    if let Some((code, message)) = slots.hold() {
        return Ok(AdmissionDecision::Waiting { code, message });
    }
    if ctx.repository_lanes.iter().any(|(lane_issue, lane_scope)| {
        *lane_issue != item.issue_number && crate::lifecycle::paths_overlap(&scope, lane_scope)
    }) {
        return Ok(AdmissionDecision::Waiting {
            code: crate::lifecycle::code::MONOREPO_OVERLAP,
            message: format!(
                "the planned scope {scope:?} overlaps a concurrent lane scope in {:?}; \
                 the item waits",
                ctx.repository
            ),
        });
    }
    // Admitted: one run row plus one unique ownership row, both inside this
    // transaction. A live incumbent is never invalidated by admission (issue
    // #209): this path is reached only when no live run owns the issue, and
    // replacing one is the explicit, audited `run.release`.
    let derived = format!("hf-queue-run/v1|{}|{}", ctx.submission_id, item.work_item);
    let run_id = format!(
        "run-{}",
        &crate::canonical::sha256_hex(derived.as_bytes())[..16]
    );
    tx.execute(
        "INSERT INTO instances (instance_id, repository, state_epoch, status,
                workflow_id, workflow_hash, policy_hash, grant_id, issue_number,
                issue_revision, phase, scope, caps, current_node, normal_rounds,
                recovery_rounds, human_queue, terminal_blockers, paused,
                resume_digest, created_at, updated_at)
         VALUES (?1, ?2, ?3, 'new', ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, '', 0, 0,
                 0, 0, 0, '', ?13, ?13)",
        params![
            run_id,
            ctx.repository,
            ctx.epoch,
            ctx.workflow_id,
            grant.workflow_hash,
            grant.policy_hash,
            grant_id,
            item.issue_number,
            item.issue_revision,
            grant.phase,
            grant.scope,
            grant.caps,
            ctx.at
        ],
    )
    .map_err(|err| StateError::from_sqlite("admit_queue_item: instance", err))?;
    // Issue #98, restart-matrix boundary (b): the dispatch is half-written —
    // the candidate's run row exists and its ownership row does not — inside
    // the caller's transaction, so an abort here rolls the whole dispatch
    // back and the resumed daemon re-dispatches it exactly once. This is the
    // SAME boundary for a submission that admits an item and for a queue
    // advance that dispatches the next one.
    crate::daemon::crash_point("queue.advance.during-dispatch");
    let prior: Option<String> = tx
        .query_row(
            "SELECT instance_id FROM queue_ownership
              WHERE repository = ?1 AND issue_number = ?2",
            params![ctx.repository, item.issue_number],
            |row| row.get(0),
        )
        .optional()
        .map_err(|err| StateError::from_sqlite("admit_queue_item: ownership read", err))?;
    match prior {
        None => {
            tx.execute(
                "INSERT INTO queue_ownership (repository, issue_number, work_item,
                        submission_id, instance_id, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    ctx.repository,
                    item.issue_number,
                    item.work_item,
                    ctx.submission_id,
                    run_id,
                    ctx.at
                ],
            )
            .map_err(|err| StateError::from_sqlite("admit_queue_item: ownership insert", err))?;
        }
        Some(prior_instance) => {
            // A prior owner that left the owned set is historical (the row is
            // replaced); a live one is a hard conflict that rolls the whole
            // transaction back.
            let still_owned: Option<i64> = tx
                .query_row(
                    "SELECT 1 FROM instances
                      WHERE instance_id = ?1
                        AND status IN ('new', 'running', 'paused', 'human_queue',
                                       'blocked')",
                    params![prior_instance],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|err| {
                    StateError::from_sqlite("admit_queue_item: ownership recheck", err)
                })?;
            if still_owned.is_some() {
                return Err(state_error(
                    "state.ownership_conflict",
                    format!(
                        "issue {} of {} already has a live owner ({prior_instance}); \
                         a duplicate owner is refused",
                        item.issue_number, ctx.repository
                    ),
                ));
            }
            tx.execute(
                "UPDATE queue_ownership SET work_item = ?3, submission_id = ?4,
                        instance_id = ?5, created_at = ?6
                  WHERE repository = ?1 AND issue_number = ?2",
                params![
                    ctx.repository,
                    item.issue_number,
                    item.work_item,
                    ctx.submission_id,
                    run_id,
                    ctx.at
                ],
            )
            .map_err(|err| StateError::from_sqlite("admit_queue_item: ownership update", err))?;
        }
    }
    slots.consume();
    Ok(AdmissionDecision::Admitted {
        instance_id: run_id,
    })
}

/// The recorded frontier of one live run (issue #209): its committed step
/// spine, its next unachieved step with that step's kind, and its recorded
/// supervision class.
///
/// Read from the SAME durable facts the driver's own frontier reads — the
/// committed bound-input line of the run's admitted submission, the recorded
/// apply attempts, and `current_node` only as the pre-ledger fallback — so
/// the submission path, the preview and the driver can never disagree about
/// where a run stands.
struct OwnedFrontier {
    /// The bound step spine as `(step id, step kind)` in spine order.
    steps: Vec<(String, String)>,
    /// The next unachieved step, when the recorded ledger establishes one.
    step: Option<String>,
    /// That step's kind.
    kind: String,
    /// The run's recorded supervision class: the class of its newest
    /// committed check (a member of the closed classification vocabulary), or
    /// empty while the run has recorded none.
    class: String,
}

impl OwnedFrontier {
    /// The frontier as one bounded summary: the step and its kind plus the
    /// recorded supervision class, or the honest statement of what the
    /// recorded ledger does establish instead.
    fn summary(&self) -> String {
        let class = if self.class.is_empty() {
            "unknown"
        } else {
            self.class.as_str()
        };
        match &self.step {
            Some(step) => format!("{step} ({}, supervision class {class})", self.kind),
            None if self.steps.is_empty() => {
                format!("no committed spine (supervision class {class})")
            }
            None => format!("an unresolved frontier (supervision class {class})"),
        }
    }
}

/// Read one run's recorded frontier under the caller's guard. `None` when the
/// durable run row itself is unreadable.
fn owner_frontier_locked(
    state: &State,
    conn: &Connection,
    instance_id: &str,
) -> Result<Option<OwnedFrontier>, StateError> {
    let line: Option<String> = conn
        .query_row(
            "SELECT s.request_line FROM queue_submissions s
               JOIN queue_submission_items i ON i.submission_id = s.submission_id
              WHERE i.instance_id = ?1 AND i.status = 'admitted'",
            params![instance_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|err| StateError::from_sqlite("frontier: spine", err))?;
    let steps = line.as_deref().map(bound_steps_of).unwrap_or_default();
    let current_node: Option<String> = conn
        .query_row(
            "SELECT current_node FROM instances WHERE instance_id = ?1",
            params![instance_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|err| StateError::from_sqlite("frontier: node", err))?;
    let Some(current_node) = current_node else {
        return Ok(None);
    };
    let attempts = state.run_step_attempts_with_codes(conn, instance_id)?;
    let spine: Vec<String> = steps.iter().map(|(id, _)| id.clone()).collect();
    let recorded: Vec<(String, String)> = attempts
        .into_iter()
        .map(|(step, status, _)| (step, status))
        .collect();
    let step = crate::run_control::frontier_of(&spine, &recorded, &current_node);
    let kind = step
        .as_deref()
        .and_then(|step| {
            steps
                .iter()
                .find(|(id, _)| id == step)
                .map(|(_, kind)| kind.clone())
        })
        .unwrap_or_default();
    let class = match state.supervision_row_locked(conn, instance_id)? {
        Some(row) if row.checks > 0 => row.last_check_class.clone(),
        _ => String::new(),
    };
    Ok(Some(OwnedFrontier {
        steps,
        step,
        kind,
        class,
    }))
}

/// The frontier of one run as one bounded human summary, naming the durable
/// row that could not be read when there is none to name.
fn owner_frontier_summary_locked(
    state: &State,
    conn: &Connection,
    instance_id: &str,
) -> Result<String, StateError> {
    Ok(match owner_frontier_locked(state, conn, instance_id)? {
        Some(owned) => owned.summary(),
        None => "an unreadable run row".to_string(),
    })
}

/// Whether the live owner of one issue has reached its own reviewed-evidence
/// frontier (issue #192): the `review_evidence` step of its committed queue
/// spine is its recorded frontier, or is already achieved.
///
/// A run without a committed spine, or without a `review_evidence` step,
/// never matches; an unreadable run row never matches.
fn owner_reached_review_frontier_locked(
    state: &State,
    conn: &Connection,
    instance_id: &str,
) -> Result<bool, StateError> {
    Ok(match owner_frontier_locked(state, conn, instance_id)? {
        Some(owned) => {
            crate::supervision::frontier_reached_review(&owned.steps, owned.step.as_deref())
        }
        None => false,
    })
}

/// The admission decision of one membership item, decided inside the
/// submission transaction.
enum AdmissionDecision {
    /// A run row was created (or an explicitly authorized paused run was
    /// resumed) inside the transaction.
    Admitted { instance_id: String },
    /// Persisted as waiting (capacity/attestation); no slot is consumed.
    Waiting { code: &'static str, message: String },
    /// Persisted as refused; no effect exists.
    Refused { code: &'static str, message: String },
}

/// One owned-status run snapshot read inside the submission transaction.
struct OwnedRunSnapshot {
    instance_id: String,
    issue_revision: String,
    grant_id: String,
    paused: bool,
    resume_digest: String,
}

/// One durable schedule row (lifecycle slice, issue #9): the recurring
/// non-destructive cadence record. `enabled` is the durable pause flag
/// (false = paused/disabled; only an explicit human resume lifts it),
/// `next_run_at` is the next aligned evaluation window, and `doc` is the
/// canonical `hf-schedule/v1` document binding the recurring grant's exact
/// repository/issue, workflow + policy hashes, read-only caps, scope,
/// expiry, and cadence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScheduleRow {
    /// Schedule id (`sd_` + 16 hex).
    pub schedule_id: String,
    /// State epoch the row belongs to (schedules die with their epoch).
    pub state_epoch: i64,
    /// Whether the schedule is enabled (false = paused/disabled; durable).
    pub enabled: bool,
    /// Next evaluation window (RFC3339 UTC, seconds precision), if any.
    pub next_run_at: Option<String>,
    /// Row creation time.
    pub created_at: String,
    /// Last row write time.
    pub updated_at: String,
    /// Canonical hf-schedule/v1 document text ('' on pre-m0004 rows).
    pub doc: String,
}

/// One durable lane replacement record (issue #73): a *request*, never an
/// effect. The record binds one logical lane generation to its source
/// owner identity and tracks the replacement phase through the linear
/// chain [`LANE_REPLACEMENT_PHASES`] via transactional compare-and-set.
/// Nothing in this slice spawns, kills, or touches Git — the record is the
/// durable handoff intent a future executor consumes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LaneReplacementRow {
    /// Replacement id (`rp_` + 16 hex; deterministic per lane generation).
    pub replacement_id: String,
    /// Logical lane identity (slug).
    pub lane_id: String,
    /// Source lane generation being replaced (>= 1).
    pub generation: i64,
    /// The successor generation slot (`generation + 1`).
    pub successor_generation: i64,
    /// Current phase (one of [`LANE_REPLACEMENT_PHASES`]).
    pub phase: String,
    /// Explicit outcome (one of [`LANE_REPLACEMENT_OUTCOMES`]).
    pub outcome: String,
    /// Bounded reason for a non-pending outcome ('' for `pending`).
    pub outcome_reason: String,
    /// Source session identity bound at request time.
    pub source_session: String,
    /// Source process identity bound at request time.
    pub source_process: String,
    /// Source role (one of [`LANE_REPLACEMENT_ROLES`]).
    pub role: String,
    /// Repository-relative worktree reference bound at request time.
    pub worktree: String,
    /// Operator reason for the replacement request.
    pub reason: String,
    /// Row creation time (RFC3339 UTC).
    pub created_at: String,
    /// Last row write time (RFC3339 UTC).
    pub updated_at: String,
}

/// One lane replacement transition-history row (issue #73 AC6): state
/// changes are appended inside the same transaction as the record write, so
/// a restart replays the exact history and next allowed transition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LaneReplacementEventRow {
    /// Monotonic event sequence.
    pub seq: i64,
    /// Replacement the event belongs to.
    pub replacement_id: String,
    /// Phase before the change (NULL for the creation event).
    pub from_phase: Option<String>,
    /// Phase after the change.
    pub to_phase: String,
    /// Outcome before the change (NULL for the creation event).
    pub from_outcome: Option<String>,
    /// Outcome after the change.
    pub to_outcome: String,
    /// Bounded reason ('' when the change carries none).
    pub reason: String,
    /// Recorded at (RFC3339 UTC).
    pub at: String,
}

/// One durable lane checkpoint record (issue #74): the atomic capture that
/// completes one replacement's `quiescing` → `checkpointed` transition.
/// The snapshot column is the durable authority (validated, bounded, and
/// digest-bound); the compact brief is a deterministic derivation of the
/// row — never trusted from a request, regenerated after a restart when the
/// derived artifact is missing. One checkpoint exists per replacement
/// (`UNIQUE (replacement_id)`); a second capture is refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LaneCheckpointRow {
    /// Checkpoint id (`ck_` + 16 hex; deterministic per replacement).
    pub checkpoint_id: String,
    /// The replacement record this checkpoint completes.
    pub replacement_id: String,
    /// Logical lane identity (slug).
    pub lane_id: String,
    /// Source lane generation the checkpoint captures.
    pub generation: i64,
    /// Source role (one of [`LANE_REPLACEMENT_ROLES`]).
    pub role: String,
    /// sha256 over the canonical bytes of the first observation.
    pub observation_digest: String,
    /// sha256 over the canonical bytes of the re-observation (equal by
    /// construction: the two-observation stability rule refuses a mismatch).
    pub reobservation_digest: String,
    /// Canonical snapshot JSON text (the durable capture authority).
    pub snapshot: String,
    /// sha256 over the canonical bytes of the snapshot.
    pub digest: String,
    /// sha256 over the generated brief bytes.
    pub brief_digest: String,
    /// Recorded at (RFC3339 UTC).
    pub created_at: String,
}

/// One validated lane retirement plan (issue #75): the durable binding a
/// retirement effect may act on. The plan is produced by validating the
/// presented binding (lane generation, source session/process identity,
/// committed checkpoint digest) and the immediate pre-stop quiescence
/// recheck against the durable record in one read — BEFORE any effect. The
/// effect executor must not act on anything the plan does not name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LaneRetirementPlan {
    /// The pending `checkpointed` replacement record being retired.
    pub record: LaneReplacementRow,
    /// The committed checkpoint the binding's digest was verified against.
    pub checkpoint: LaneCheckpointRow,
    /// The instant the immediate pre-stop quiescence recheck observed the
    /// lane (RFC3339 UTC, from the validated recheck).
    pub recheck_observed_at: String,
}

/// The validated retirement binding presented with one retirement request
/// (the grant-style document that binds the lane generation, the source
/// session/process identities and the committed checkpoint digest).
#[derive(Clone, Debug, PartialEq, Eq)]
struct RetirementBinding {
    generation: i64,
    session: String,
    process: String,
    checkpoint_digest: String,
}

/// The validated immediate pre-stop quiescence recheck: the observed source
/// identity, the observed child commands and the external-execution state.
#[derive(Clone, Debug, PartialEq, Eq)]
struct RetirementRecheck {
    observed_at: String,
    session: String,
    process: Option<String>,
    children: Vec<(String, String)>,
    active: bool,
}

/// One durable lane successor record (issue #76): the ONE successor owner a
/// replacement's startup nonce binds. The row is committed BEFORE any spawn
/// (the `retired` → `starting` boundary commits with it in one
/// transaction), so a simultaneous or replayed start can never create a
/// second successor, and a crash always leaves either no row (no spawn was
/// ever issued) or the exact bound identity the adapter observed. The
/// adapter-observed process, the verification evidence, the preserved
/// worker/reviewer orchestration and the consumed completion events are
/// durable on the row; restart reconciliation re-derives from it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LaneSuccessorRow {
    /// Successor id (`su_` + 16 hex; deterministic per replacement).
    pub successor_id: String,
    /// The replacement record this successor continues (`UNIQUE`).
    pub replacement_id: String,
    /// Logical lane identity (slug).
    pub lane_id: String,
    /// Successor generation slot (the record's `successor_generation`).
    pub generation: i64,
    /// Doctrine role the successor runs (the record's role).
    pub role: String,
    /// Repository-relative worktree reference (the record's worktree).
    pub worktree: String,
    /// The successor session identity bound by the start request.
    pub session: String,
    /// Adapter-observed backend process identity ('' until observed).
    pub process: String,
    /// The ONE startup nonce that owns this successor (bounded printable).
    pub nonce: String,
    /// Harness profile key the spawn/read-back ran under.
    pub profile_key: String,
    /// Harness profile kind the spawn/read-back ran under.
    pub profile_kind: String,
    /// sha256 of the kickoff receipt the read-back must echo.
    pub kickoff_receipt: String,
    /// Delivery marker (`none` before a confirmed spawn, `delivered` after).
    pub delivery: String,
    /// Bounded spawn attempts issued for this successor (1..=max).
    pub attempts: i64,
    /// Canonical start-verification evidence ('' until verified).
    pub evidence: String,
    /// sha256 over the evidence bytes ('' until verified).
    pub evidence_digest: String,
    /// Canonical preserved orchestration block ('' outside orchestrator
    /// replacements): workers/reviewers/pending completion events.
    pub orchestration: String,
    /// Canonical consumed completion events ('' until the successor is an
    /// adopted orchestrator; `[]` before the first consumption).
    pub consumed: String,
    /// Adoption time ('' until adopted).
    pub adopted_at: String,
    /// Canonical adoption evidence document ('' until adopted).
    pub adoption_evidence: String,
    /// sha256 over the adoption evidence bytes ('' until adopted).
    pub adoption_digest: String,
    /// Row creation time (RFC3339 UTC).
    pub created_at: String,
    /// Last row write time (RFC3339 UTC).
    pub updated_at: String,
}

/// One validated successor-start plan (issue #76): the durable binding a
/// start effect may act on. `begin_lane_successor` produces it read-only
/// BEFORE any effect and BEFORE the claim; the effect executor must not act
/// on anything the plan does not name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LaneSuccessorPlan {
    /// The pending `retired` replacement record being continued.
    pub record: LaneReplacementRow,
    /// The committed checkpoint whose integrity the binding re-verified.
    pub checkpoint: LaneCheckpointRow,
    /// The bound startup nonce (the ONE owner of this successor).
    pub nonce: String,
    /// The bound fresh successor session identity.
    pub session: String,
    /// The bound kickoff receipt the adapter read-back must echo.
    pub kickoff_receipt: String,
    /// The already-committed successor row when this is a bounded retry of
    /// the same nonce (None for a first start).
    pub existing: Option<LaneSuccessorRow>,
}

/// One validated adoption plan (issue #76): the successor boundary, the
/// committed checkpoint, and the fresh re-query compared against it. A
/// non-empty `differences` list is the RECONCILIATION verdict — the
/// adoption must not commit.
#[derive(Clone, Debug, PartialEq)]
pub struct LaneAdoptionPlan {
    /// The pending `adopting` replacement record being adopted.
    pub record: LaneReplacementRow,
    /// The committed checkpoint the adoption evidence is compared to.
    pub checkpoint: LaneCheckpointRow,
    /// The committed successor row being adopted.
    pub successor: LaneSuccessorRow,
    /// The canonical validated re-query comparison document.
    pub observation: Val,
    /// Compared fields whose values differ from the checkpoint snapshot
    /// (empty = the lane is the same logical task on the same worktree).
    pub differences: Vec<String>,
}

/// One durable target-profile binding plan attached to a lane replacement
/// record (issue #77): the canonical `hf-profile-binding/v1` document and
/// its explicit configuration revision. The row is written in the SAME
/// transaction as the replacement record, so a replacement is either bound
/// from birth or unbound — never retro-fitted after the fact. The successor
/// start must present the SAME reviewed plan; a changed revision (the
/// configuration or a declared credential moved since the preview) requires
/// a newly reviewed plan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LaneReplacementProfileRow {
    /// The replacement record this plan belongs to (`UNIQUE`).
    pub replacement_id: String,
    /// Canonical `hf-profile-binding/v1` document text.
    pub profile: String,
    /// The 64-hex profile-configuration revision the plan was reviewed under.
    pub revision: String,
    /// Row creation time (RFC3339 UTC).
    pub created_at: String,
}

/// Enforced byte bound of one bound profile-plan document (never truncated;
/// an oversize plan refuses at request time).
pub const PROFILE_BINDING_MAX_BYTES: usize = 4096;

/// The validated successor binding presented with one start request (the
/// grant-style document: lane generation, committed checkpoint digest, the
/// ONE startup nonce).
#[derive(Clone, Debug, PartialEq, Eq)]
struct SuccessorBinding {
    generation: i64,
    checkpoint_digest: String,
    nonce: String,
}

/// The validated adoption binding presented with one adoption request (the
/// committed successor identity the adoption acts on).
#[derive(Clone, Debug, PartialEq, Eq)]
struct AdoptionBinding {
    generation: i64,
    successor_id: String,
    session: String,
}

/// The daemon-owned state handle. All methods serialize on an internal
/// mutex (one writer); a failed write poisons the handle (fail closed).
pub struct State {
    conn: Mutex<Connection>,
    retention: Retention,
    poisoned: AtomicBool,
    /// The FIRST write that failed and poisoned this handle (item 4b of issue
    /// #144): the cause every later `state.poisoned` refusal names.
    poison_cause: Mutex<Option<String>>,
}

impl std::fmt::Debug for State {
    /// Deliberately does not expose the connection or its internals.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("State")
            .field("retention", &self.retention)
            .field("poisoned", &self.poisoned.load(Ordering::SeqCst))
            .finish()
    }
}

/// A minimal summary for the daemon `status` RPC and service doctor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateSummary {
    /// Current state epoch.
    pub epoch: i64,
    /// Highest audit seq (journal length minus pruned rows).
    pub audit_seq: i64,
    /// Highest event seq.
    pub event_seq: i64,
    /// SQLite schema version.
    pub schema_version: i64,
    /// Count of active grants.
    pub active_grants: i64,
    /// Count of un-resolved claims (recovery queue).
    pub pending_claims: i64,
    /// Whether the state is poisoned (fail closed after a write failure).
    pub poisoned: bool,
}

/// The outcome of an idempotent claim attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClaimAttempt {
    /// The key was free and is now claimed (the caller may journal intent).
    Claimed,
    /// The same request already resolved; replay the recorded response.
    Replay {
        /// Recorded canonical hf-rpc-response/v1 line.
        response: String,
    },
    /// The key was claimed/resolved by a *different* request (refuse).
    Reused {
        /// Recorded request id that owns the key.
        owner_request_id: String,
    },
}

impl State {
    /// Open (creating if needed) the state database at `path` and migrate it
    /// to the current schema. Fails closed on corrupt or newer-schema files.
    pub fn open(path: &Path, retention: Retention) -> Result<State, StateError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|err| {
                state_error("state.open", format!("create {}: {err}", parent.display()))
            })?;
        }
        let existed = path.exists() && fs::metadata(path).map(|m| m.len() > 0).unwrap_or(false);
        let mut conn = Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_CREATE,
        )
        .map_err(|err| StateError::from_sqlite("open state db", err))?;
        conn.execute_batch(
            "PRAGMA synchronous = FULL;
             PRAGMA foreign_keys = ON;
             PRAGMA busy_timeout = 5000;
             PRAGMA journal_mode = DELETE;",
        )
        .map_err(|err| StateError::from_sqlite("state pragmas", err))?;
        if existed {
            let ok: String = conn
                .query_row("PRAGMA quick_check", [], |row| row.get(0))
                .map_err(|err| StateError::from_sqlite("quick_check", err))?;
            if ok != "ok" {
                return Err(state_error(
                    "state.corrupt",
                    format!("state database failed PRAGMA quick_check: {ok}"),
                ));
            }
        }
        let mut user_version: i64 = conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .map_err(|err| StateError::from_sqlite("read user_version", err))?;
        // Apply pending migrations in order (linear chain; each migration
        // records itself in schema_migrations before bumping user_version).
        if user_version == 0 {
            run_initial_migration(&mut conn)?;
            user_version = M0001_APPLIES_TO;
        }
        if user_version == M0002_APPLIES_FROM {
            run_m0002(&mut conn)?;
            user_version = M0002_APPLIES_TO;
        }
        if user_version == M0003_APPLIES_FROM {
            run_m0003(&mut conn)?;
            user_version = M0003_APPLIES_TO;
        }
        if user_version == M0004_APPLIES_FROM {
            run_m0004(&mut conn)?;
            user_version = M0004_APPLIES_TO;
        }
        if user_version == M0005_APPLIES_FROM {
            run_m0005(&mut conn)?;
            user_version = M0005_APPLIES_TO;
        }
        if user_version == M0006_APPLIES_FROM {
            run_m0006(&mut conn)?;
            user_version = M0006_APPLIES_TO;
        }
        if user_version == M0007_APPLIES_FROM {
            run_m0007(&mut conn)?;
            user_version = M0007_APPLIES_TO;
        }
        if user_version == M0008_APPLIES_FROM {
            run_m0008(&mut conn)?;
            user_version = M0008_APPLIES_TO;
        }
        if user_version == M0009_APPLIES_FROM {
            run_m0009(&mut conn)?;
            user_version = M0009_APPLIES_TO;
        }
        if user_version == M0010_APPLIES_FROM {
            run_m0010(&mut conn)?;
            user_version = M0010_APPLIES_TO;
        }
        if user_version == M0011_APPLIES_FROM {
            run_m0011(&mut conn)?;
            user_version = M0011_APPLIES_TO;
        }
        if user_version == M0012_APPLIES_FROM {
            run_m0012(&mut conn)?;
            user_version = M0012_APPLIES_TO;
        }
        match user_version {
            v if v == SCHEMA_VERSION => {
                for (migration_id, _, _) in MIGRATIONS {
                    let recorded: Option<i64> = conn
                        .query_row(
                            "SELECT COUNT(*) FROM schema_migrations WHERE migration_id = ?1",
                            params![migration_id],
                            |row| row.get(0),
                        )
                        .optional()
                        .map_err(|err| StateError::from_sqlite("migration bookkeeping", err))?;
                    if recorded != Some(1) {
                        return Err(state_error(
                            "state.corrupt",
                            format!(
                                "user_version matches but migration bookkeeping is missing for {migration_id}"
                            ),
                        ));
                    }
                }
            }
            v => {
                return Err(state_error(
                    "state.schema_future",
                    format!(
                        "state schema version {v} is newer than this binary supports \
                         (maximum {SCHEMA_VERSION}); refusing to operate"
                    ),
                ));
            }
        }
        let state = State {
            conn: Mutex::new(conn),
            retention,
            poisoned: AtomicBool::new(false),
            poison_cause: Mutex::new(None),
        };
        state.verify_chain()?;
        Ok(state)
    }

    /// Whether the state is poisoned (fail closed after a write failure).
    pub fn is_poisoned(&self) -> bool {
        self.poisoned.load(Ordering::SeqCst)
    }

    /// Lock the connection, mapping lock/poison failures to typed errors.
    fn lock(
        &self,
        context: &'static str,
    ) -> Result<std::sync::MutexGuard<'_, Connection>, StateError> {
        self.conn.lock().map_err(|_| {
            state_error(
                "state.unavailable",
                format!("{context}: state mutex poisoned"),
            )
        })
    }

    // ---------------------------------------------------------------------
    // Epochs
    // ---------------------------------------------------------------------

    /// The current epoch (1 after initial migration).
    pub fn current_epoch(&self) -> Result<i64, StateError> {
        let conn = self.lock("current_epoch")?;
        conn.query_row("SELECT COALESCE(MAX(epoch), 0) FROM epoch", [], |row| {
            row.get(0)
        })
        .map_err(|err| StateError::from_sqlite("current_epoch", err))
    }

    /// Rotate to a new epoch (restore or security rotation). The new epoch
    /// is prior + 1 and the record mirrors hf-epoch/v1.
    pub fn rotate_epoch(&self, reason: &str) -> Result<i64, StateError> {
        if !matches!(reason, "restore" | "security_rotation") {
            return Err(state_error(
                "state.conflict",
                format!("epoch rotation reason {reason:?} outside {{restore, security_rotation}}"),
            ));
        }
        let conn = self.lock("rotate_epoch")?;
        let prior: i64 = conn
            .query_row("SELECT COALESCE(MAX(epoch), 0) FROM epoch", [], |row| {
                row.get(0)
            })
            .map_err(|err| StateError::from_sqlite("rotate_epoch: read", err))?;
        let next = prior + 1;
        conn.execute(
            "INSERT INTO epoch (epoch, reason, prior_epoch, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![next, reason, prior, time::rfc3339_now()],
        )
        .map_err(|err| StateError::from_sqlite("rotate_epoch: insert", err))?;
        Ok(next)
    }

    /// Invalidate every active grant issued against an epoch older than
    /// `current_epoch` (restore semantics: grants die with their epoch).
    /// Bound running instances are invalidated with their grants (C3:
    /// restore rotates the epoch; instances die with their epoch too).
    pub fn invalidate_grants_below_current(&self) -> Result<i64, StateError> {
        let conn = self.lock("invalidate_grants")?;
        let epoch: i64 = conn
            .query_row("SELECT COALESCE(MAX(epoch), 0) FROM epoch", [], |row| {
                row.get(0)
            })
            .map_err(|err| StateError::from_sqlite("invalidate_grants: read", err))?;
        conn.execute(
            "UPDATE grants SET status = 'invalidated' WHERE status = 'active' AND state_epoch < ?1",
            params![epoch],
        )
        .map_err(|err| StateError::from_sqlite("invalidate_grants: update", err))?;
        conn.execute(
            "UPDATE instances SET status = 'invalidated', updated_at = ?2
              WHERE state_epoch < ?1 AND status IN
                    ('new', 'running', 'paused', 'human_queue', 'blocked')",
            params![epoch, time::rfc3339_now()],
        )
        .map_err(|err| StateError::from_sqlite("invalidate_grants: instances", err))?;
        Ok(epoch)
    }

    /// A single hf-epoch/v1-shaped document for the current epoch.
    pub fn epoch_doc(&self) -> Result<Val, StateError> {
        let conn = self.lock("epoch_doc")?;
        let row: Option<(i64, String, Option<i64>, String)> = conn
            .query_row(
                "SELECT epoch, reason, prior_epoch, created_at FROM epoch ORDER BY epoch DESC LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(|err| StateError::from_sqlite("epoch_doc", err))?;
        match row {
            Some((epoch, reason, prior_epoch, created_at)) => Ok(object(vec![
                ("schema", string("hf-epoch/v1")),
                ("epoch", integer(epoch)),
                ("reason", string(&reason)),
                ("prior_epoch", prior_epoch.map(integer).unwrap_or_else(null)),
                ("created_at", string(&created_at)),
            ])),
            None => Err(state_error("state.not_found", "no epoch record exists")),
        }
    }

    // ---------------------------------------------------------------------
    // Idempotency claims (AC6) and journaled intents/outcomes (AC4/AC5)
    // ---------------------------------------------------------------------

    /// Look up an existing claim by key (idempotent replay check).
    pub fn claim(&self, key: &str) -> Result<Option<ClaimRow>, StateError> {
        let conn = self.lock("claim")?;
        conn.query_row(
            "SELECT key, request_id, method, status, outcome, response, request_line
               FROM idempotency WHERE key = ?1",
            params![key],
            |row| {
                Ok(ClaimRow {
                    key: row.get(0)?,
                    request_id: row.get(1)?,
                    method: row.get(2)?,
                    status: row.get(3)?,
                    outcome: row.get(4)?,
                    response: row.get(5)?,
                    request_line: row.get(6)?,
                })
            },
        )
        .optional()
        .map_err(|err| StateError::from_sqlite("claim: read", err))
    }

    /// Journal a mutation intent and claim its idempotency key in one
    /// transaction (durable before any effect; fail-closed AC5). Returns the
    /// claim decision plus the journaled audit/event seqs when claimed.
    #[allow(clippy::too_many_arguments)]
    pub fn journal_intent(
        &self,
        action: &str,
        target: &str,
        key: &str,
        request_id: &str,
        method: &str,
        plan_hash: Option<&str>,
        grant_id: Option<&str>,
        request_line: &str,
    ) -> Result<(ClaimAttempt, Option<AuditRow>), StateError> {
        let outcome = self.journal_intent_inner(
            action,
            target,
            key,
            request_id,
            method,
            plan_hash,
            grant_id,
            request_line,
        );
        if let Err(err) = &outcome {
            self.poison_on(err);
        }
        outcome
    }

    #[allow(clippy::too_many_arguments, clippy::type_complexity)]
    fn journal_intent_inner(
        &self,
        action: &str,
        target: &str,
        key: &str,
        request_id: &str,
        method: &str,
        plan_hash: Option<&str>,
        grant_id: Option<&str>,
        request_line: &str,
    ) -> Result<(ClaimAttempt, Option<AuditRow>), StateError> {
        self.ensure_writable()?;
        let mut conn = self.lock("journal_intent")?;
        let tx = conn
            .transaction()
            .map_err(|err| StateError::from_sqlite("journal_intent: begin", err))?;
        let existing: Option<(String, String, Option<String>, Option<String>, String)> = tx
            .query_row(
                "SELECT request_id, status, outcome, response, request_line FROM idempotency WHERE key = ?1",
                params![key],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .optional()
            .map_err(|err| StateError::from_sqlite("journal_intent: read", err))?;
        if let Some((owner_request_id, status, outcome, response, existing_line)) = existing {
            if owner_request_id == request_id {
                if status == "claimed" {
                    // A concurrent retry of the SAME request while the first
                    // attempt is still in flight: no response is recorded yet
                    // and re-claiming the key would violate its uniqueness —
                    // refuse typed (never a raw SQLite constraint error) and
                    // let the caller retry for the recorded replay.
                    return Err(state_error(
                        "state.claim_incomplete",
                        format!("claim {key:?} is still in flight (request {owner_request_id})"),
                    ));
                }
                if let Some(response) = response.filter(|response| !response.is_empty()) {
                    return Ok((ClaimAttempt::Replay { response }, None));
                }
                if status == "ambiguous" || status == "voided" {
                    // Interrupted claims resolve through reconcile; a
                    // matching retry without a recorded response is refused.
                    let message = if status == "ambiguous" {
                        "the claim was left ambiguous by an interrupted run; external reconciliation is required before retry with a new key"
                    } else {
                        "the claim was voided by recovery; retry with a new key"
                    };
                    let _ = (outcome, existing_line);
                    return Err(state_error("state.ambiguous_claim", message));
                }
                return Err(state_error(
                    "state.claim_incomplete",
                    format!("claim {key:?} is still in flight (request {owner_request_id})"),
                ));
            }
            return Err(state_error(
                "state.claim_reused",
                format!("idempotency key {key:?} already belongs to request {owner_request_id}"),
            ));
        }
        let audit = self.append_audit_locked(&tx, action, target, key, plan_hash, grant_id)?;
        tx.execute(
            "INSERT INTO idempotency (key, request_id, method, status, epoch, request_line, claimed_at)
             VALUES (?1, ?2, ?3, 'claimed', ?4, ?5, ?6)",
            params![
                key,
                request_id,
                method,
                audit.epoch,
                request_line,
                time::rfc3339_now()
            ],
        )
        .map_err(|err| StateError::from_sqlite("journal_intent: claim", err))?;
        tx.commit()
            .map_err(|err| StateError::from_sqlite("journal_intent: commit", err))?;
        Ok((ClaimAttempt::Claimed, Some(audit)))
    }

    /// Resolve a claim with its typed outcome (hf-outcome/v1 document) and
    /// the recorded response (hf-rpc-response/v1) in one transaction, and
    /// journal the outcome audit record. `status` is one of `spent`,
    /// `ambiguous`, `voided`; the audit action mirrors the operation.
    pub fn resolve_claim(
        &self,
        key: &str,
        method: &str,
        status: &str,
        outcome_line: &str,
        response_line: Option<&str>,
    ) -> Result<AuditRow, StateError> {
        let outcome = self.resolve_claim_inner(key, method, status, outcome_line, response_line);
        if let Err(err) = &outcome {
            self.poison_on(err);
        }
        outcome
    }

    fn resolve_claim_inner(
        &self,
        key: &str,
        method: &str,
        status: &str,
        outcome_line: &str,
        response_line: Option<&str>,
    ) -> Result<AuditRow, StateError> {
        self.ensure_writable()?;
        let mut conn = self.lock("resolve_claim")?;
        let tx = conn
            .transaction()
            .map_err(|err| StateError::from_sqlite("resolve_claim: begin", err))?;
        let action = format!("outcome.{method}");
        let audit = self.append_audit_locked(&tx, &action, key, key, None, None)?;
        let affected = tx
            .execute(
                "UPDATE idempotency SET status = ?1, outcome = ?2, response = ?3, resolved_at = ?4
                  WHERE key = ?5 AND status = 'claimed'",
                params![
                    status,
                    outcome_line,
                    response_line.unwrap_or(""),
                    time::rfc3339_now(),
                    key
                ],
            )
            .map_err(|err| StateError::from_sqlite("resolve_claim: update", err))?;
        if affected == 0 {
            return Err(state_error(
                "state.claim_conflict",
                format!("claim {key:?} is not in the claimed state"),
            ));
        }
        tx.commit()
            .map_err(|err| StateError::from_sqlite("resolve_claim: commit", err))?;
        Ok(audit)
    }

    /// Commit an evidence-based diagnosed-step resolution as one atomic
    /// journal transition. The resolution itself is the durable attempt-ledger
    /// row; any pending retry authorization is consumed by this no-effect
    /// record so it cannot later re-execute the diagnosed effect.
    #[allow(clippy::too_many_arguments)]
    pub fn resolve_run_step_claim(
        &self,
        key: &str,
        method: &str,
        outcome_line: &str,
        response_line: &str,
        instance_id: &str,
        step_id: &str,
        at: &str,
    ) -> Result<AuditRow, StateError> {
        self.ensure_writable()?;
        let mut conn = self.lock("resolve_run_step_claim")?;
        let tx = conn
            .transaction()
            .map_err(|err| StateError::from_sqlite("resolve_run_step_claim: begin", err))?;
        let exists: Option<i64> = tx
            .query_row(
                "SELECT 1 FROM instances WHERE instance_id = ?1",
                params![instance_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|err| StateError::from_sqlite("resolve_run_step_claim: run", err))?;
        if exists.is_none() {
            return Err(state_error(
                "state.not_found",
                format!("no instance {instance_id}"),
            ));
        }
        tx.execute(
            "UPDATE run_retries SET consumed_at = ?3, consumed_key = ?4
              WHERE instance_id = ?1 AND step_id = ?2 AND consumed_at = ''",
            params![instance_id, step_id, at, key],
        )
        .map_err(|err| StateError::from_sqlite("resolve_run_step_claim: retry", err))?;
        let action = format!("outcome.{method}");
        let audit = self.append_audit_locked(&tx, &action, key, key, None, None)?;
        let affected = tx
            .execute(
                "UPDATE idempotency SET status = 'spent', outcome = ?1, response = ?2,
                        resolved_at = ?3
                  WHERE key = ?4 AND method = ?5 AND status = 'claimed'",
                params![outcome_line, response_line, at, key, method],
            )
            .map_err(|err| StateError::from_sqlite("resolve_run_step_claim: claim", err))?;
        if affected != 1 {
            return Err(state_error(
                "state.claim_conflict",
                format!("claim {key:?} is not the unresolved {method} claim"),
            ));
        }
        tx.commit()
            .map_err(|err| StateError::from_sqlite("resolve_run_step_claim: commit", err))?;
        Ok(audit)
    }

    /// Every un-resolved claim (the recovery checkpoint queue). On restart
    /// the daemon reconciles each one before accepting retries (AC4).
    pub fn claims_in_flight(&self) -> Result<Vec<ClaimRow>, StateError> {
        let conn = self.lock("claims_in_flight")?;
        let mut statement = conn
            .prepare(
                "SELECT key, request_id, method, status, outcome, response, request_line
                   FROM idempotency WHERE status = 'claimed' ORDER BY claimed_at",
            )
            .map_err(|err| StateError::from_sqlite("claims_in_flight: prepare", err))?;
        let rows = statement
            .query_map([], |row| {
                Ok(ClaimRow {
                    key: row.get(0)?,
                    request_id: row.get(1)?,
                    method: row.get(2)?,
                    status: row.get(3)?,
                    outcome: row.get(4)?,
                    response: row.get(5)?,
                    request_line: row.get(6)?,
                })
            })
            .map_err(|err| StateError::from_sqlite("claims_in_flight: query", err))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(|err| StateError::from_sqlite("claims_in_flight: row", err))?);
        }
        Ok(out)
    }

    /// Void every claim that is still in flight (status `claimed`) by
    /// journaling a `reconcile.restore` audit record and marking the claim
    /// voided. Used after a restore rolls the database back to a snapshot
    /// that predates those claims' resolutions: resurrected in-flight
    /// claims must never become runnable or replayable in the restored
    /// world.
    pub fn void_in_flight_claims(&self, reason: &str) -> Result<usize, StateError> {
        let claims = self.claims_in_flight()?;
        let at = time::rfc3339_now();
        let count = claims.len();
        for claim in &claims {
            let outcome_line = canonical_text(&object(vec![
                ("schema", string("hf-outcome/v1")),
                ("status", string("voided")),
                ("reason", string(&format!("restore.voided.{reason}"))),
                ("at", string(&at)),
            ]));
            self.journal_reconcile(&claim.key, &claim.method, "voided", &outcome_line)?;
        }
        Ok(count)
    }

    /// Journal a reconcile decision (crash recovery marks claims ambiguous
    /// or voided with a typed outcome; action `reconcile.<method>`).
    pub fn journal_reconcile(
        &self,
        key: &str,
        method: &str,
        status: &str,
        outcome_line: &str,
    ) -> Result<AuditRow, StateError> {
        let outcome = self.journal_reconcile_inner(key, method, status, outcome_line);
        if let Err(err) = &outcome {
            self.poison_on(err);
        }
        outcome
    }

    fn journal_reconcile_inner(
        &self,
        key: &str,
        method: &str,
        status: &str,
        outcome_line: &str,
    ) -> Result<AuditRow, StateError> {
        self.ensure_writable()?;
        let mut conn = self.lock("journal_reconcile")?;
        let tx = conn
            .transaction()
            .map_err(|err| StateError::from_sqlite("journal_reconcile: begin", err))?;
        let action = format!("reconcile.{method}");
        let audit = self.append_audit_locked(&tx, &action, key, key, None, None)?;
        let affected = tx
            .execute(
                "UPDATE idempotency SET status = ?1, outcome = ?2, resolved_at = ?3
                  WHERE key = ?4 AND status = 'claimed'",
                params![status, outcome_line, time::rfc3339_now(), key],
            )
            .map_err(|err| StateError::from_sqlite("journal_reconcile: update", err))?;
        if affected == 0 {
            return Err(state_error(
                "state.claim_conflict",
                format!("claim {key:?} is not in the claimed state"),
            ));
        }
        tx.commit()
            .map_err(|err| StateError::from_sqlite("journal_reconcile: commit", err))?;
        Ok(audit)
    }

    // ---------------------------------------------------------------------
    // Grants (revoke/list here; issuance arrives with the engine slice)
    // ---------------------------------------------------------------------

    /// Revoke an active grant (state transition + journaled intent by the
    /// caller; this only flips the row).
    pub fn revoke_grant(&self, grant_id: &str, at: &str) -> Result<(), StateError> {
        let conn = self.lock("revoke_grant")?;
        let affected = conn
            .execute(
                "UPDATE grants SET status = 'revoked', revoked_at = ?2
                  WHERE grant_id = ?1 AND status = 'active'",
                params![grant_id, at],
            )
            .map_err(|err| StateError::from_sqlite("revoke_grant: update", err))?;
        if affected == 0 {
            return Err(state_error(
                "state.not_found",
                format!("no active grant {grant_id:?} to revoke"),
            ));
        }
        Ok(())
    }

    /// All grants that are not invalidated (daemon filters expired live).
    pub fn list_grants(&self) -> Result<Vec<GrantRow>, StateError> {
        let conn = self.lock("list_grants")?;
        let mut statement = conn
            .prepare(
                "SELECT grant_id, repository, issue_number, issue_revision, workflow_hash,
                        policy_hash, phase, scope, caps, expires_at, state_epoch, status, created_at
                   FROM grants WHERE status = 'active' ORDER BY created_at",
            )
            .map_err(|err| StateError::from_sqlite("list_grants: prepare", err))?;
        let rows = statement
            .query_map([], |row| {
                Ok(GrantRow {
                    grant_id: row.get(0)?,
                    repository: row.get(1)?,
                    issue_number: row.get(2)?,
                    issue_revision: row.get(3)?,
                    workflow_hash: row.get(4)?,
                    policy_hash: row.get(5)?,
                    phase: row.get(6)?,
                    scope: row.get(7)?,
                    caps: row.get(8)?,
                    expires_at: row.get(9)?,
                    state_epoch: row.get(10)?,
                    status: row.get(11)?,
                    created_at: row.get(12)?,
                })
            })
            .map_err(|err| StateError::from_sqlite("list_grants: query", err))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(|err| StateError::from_sqlite("list_grants: row", err))?);
        }
        Ok(out)
    }

    // ---------------------------------------------------------------------
    // Workflow engine: durable route grants + instances (issue #6)
    // ---------------------------------------------------------------------

    /// Issue a route grant from a validated `hf-grant/v1` document (AC3
    /// bindings: repository, issue set/revision, workflow/policy hashes,
    /// phase, scope, caps, expiry, state epoch). Refused when the document
    /// is invalid, when the grant id already exists, or when its epoch is
    /// not the current epoch (grants die with their epoch).
    pub fn issue_grant(&self, doc: &Val) -> Result<GrantRow, StateError> {
        let verdict = crate::schema::validate_doc(crate::schema::Family::Grant, doc);
        if !verdict.is_accepted() {
            return Err(state_error(
                "state.grant_invalid",
                format!("grant document refused: {}", verdict.message()),
            ));
        }
        let grant = grant_row_from_doc(doc)?;
        let conn = self.lock("issue_grant")?;
        let epoch = current_epoch_locked(&conn)?;
        if grant.state_epoch != epoch {
            return Err(state_error(
                "state.epoch_mismatch",
                format!(
                    "grant epoch {} != current epoch {}; grants die with their epoch",
                    grant.state_epoch, epoch
                ),
            ));
        }
        conn.execute(
            "INSERT INTO grants (grant_id, repository, issue_number, issue_revision,
                                 workflow_hash, policy_hash, phase, scope, caps,
                                 expires_at, state_epoch, status, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 'active', ?12)",
            params![
                grant.grant_id,
                grant.repository,
                grant.issue_number,
                grant.issue_revision,
                grant.workflow_hash,
                grant.policy_hash,
                grant.phase,
                grant.scope,
                grant.caps,
                grant.expires_at,
                grant.state_epoch,
                grant.created_at
            ],
        )
        .map_err(|err| {
            if err.to_string().contains("UNIQUE") {
                state_error(
                    "state.grant_exists",
                    format!("grant {} already exists", grant.grant_id),
                )
            } else {
                StateError::from_sqlite("issue_grant: insert", err)
            }
        })?;
        Ok(grant)
    }

    /// Fetch one grant row by id (any status; engine revalidation reads the
    /// live binding before every further mutation — AC2).
    pub fn grant_by_id(&self, grant_id: &str) -> Result<Option<GrantRow>, StateError> {
        let conn = self.lock("grant_by_id")?;
        let row = conn
            .query_row(
                "SELECT grant_id, repository, issue_number, issue_revision, workflow_hash,
                        policy_hash, phase, scope, caps, expires_at, state_epoch, status, created_at
                   FROM grants WHERE grant_id = ?1",
                params![grant_id],
                grant_row_from,
            )
            .optional()
            .map_err(|err| StateError::from_sqlite("grant_by_id: query", err))?;
        Ok(row)
    }

    /// Whether a candidate grant was issued after the grant of the current
    /// owner. SQLite insertion order is the authorization-window order; grant
    /// ids and revision hashes are never ordered lexically.
    pub fn grant_issued_after(
        &self,
        candidate_grant: &str,
        prior_grant: &str,
    ) -> Result<bool, StateError> {
        let conn = self.lock("grant_issued_after")?;
        let pair: Option<(i64, i64)> = conn
            .query_row(
                "SELECT candidate.rowid, prior.rowid
                   FROM grants candidate, grants prior
                  WHERE candidate.grant_id = ?1 AND prior.grant_id = ?2",
                params![candidate_grant, prior_grant],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|err| StateError::from_sqlite("grant_issued_after: query", err))?;
        Ok(matches!(pair, Some((candidate, prior)) if candidate > prior))
    }

    /// Whether durable state contains a later authorization window for this
    /// exact selected revision than the current owner's grant.
    pub fn revision_has_newer_grant(
        &self,
        repository: &str,
        issue_number: i64,
        issue_revision: &str,
        prior_grant: &str,
    ) -> Result<bool, StateError> {
        let conn = self.lock("revision_has_newer_grant")?;
        let newer: i64 = conn
            .query_row(
                "SELECT EXISTS(
                     SELECT 1 FROM grants candidate
                       JOIN grants prior ON prior.grant_id = ?4
                      WHERE candidate.repository = ?1
                        AND candidate.issue_number = ?2
                        AND candidate.issue_revision = ?3
                        AND candidate.rowid > prior.rowid
                 )",
                params![repository, issue_number, issue_revision, prior_grant],
                |row| row.get(0),
            )
            .map_err(|err| StateError::from_sqlite("revision_has_newer_grant: query", err))?;
        Ok(newer != 0)
    }

    /// Invalidate an active grant (material issue/acceptance edit — AC2).
    /// Bound instances are invalidated with it (C3: an instance bound to an
    /// invalidated grant can never advance again).
    pub fn invalidate_grant(&self, grant_id: &str, at: &str) -> Result<(), StateError> {
        let conn = self.lock("invalidate_grant")?;
        let affected = conn
            .execute(
                "UPDATE grants SET status = 'invalidated', revoked_at = ?2
                  WHERE grant_id = ?1 AND status = 'active'",
                params![grant_id, at],
            )
            .map_err(|err| StateError::from_sqlite("invalidate_grant: update", err))?;
        if affected == 0 {
            return Err(state_error(
                "state.not_found",
                format!("no active grant {grant_id:?} to invalidate"),
            ));
        }
        conn.execute(
            "UPDATE instances SET status = 'invalidated', updated_at = ?2
              WHERE grant_id = ?1 AND status IN
                    ('new', 'running', 'paused', 'human_queue', 'blocked')",
            params![grant_id, at],
        )
        .map_err(|err| StateError::from_sqlite("invalidate_grant: instances", err))?;
        Ok(())
    }

    /// Start a workflow instance bound to an active grant (durable pin of
    /// workflow/policy hashes and the issue binding). Refused when the
    /// grant is absent/inactive or its bindings disagree with the engine
    /// pin (`workflow_hash`/`policy_hash`).
    pub fn start_instance(
        &self,
        instance_id: &str,
        grant_id: &str,
        workflow_id: &str,
        at: &str,
    ) -> Result<InstanceRow, StateError> {
        let Some(grant) = self.grant_by_id(grant_id)? else {
            return Err(state_error(
                "state.not_found",
                format!("no grant {grant_id:?}"),
            ));
        };
        if grant.status != "active" {
            return Err(state_error(
                "state.grant_inactive",
                format!("grant {grant_id:?} is not active"),
            ));
        }
        {
            let conn = self.lock("start_instance")?;
            conn.execute(
                "INSERT INTO instances (instance_id, repository, state_epoch, status,
                                        workflow_id, workflow_hash, policy_hash, grant_id,
                                        issue_number, issue_revision, phase, scope, caps,
                                        current_node, normal_rounds, recovery_rounds,
                                        human_queue, terminal_blockers, paused, resume_digest,
                                        created_at, updated_at)
                 VALUES (?1, ?2, ?3, 'new', ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, '', 0, 0, 0, 0, 0, '', ?13, ?13)",
                params![
                    instance_id,
                    grant.repository,
                    grant.state_epoch,
                    workflow_id,
                    grant.workflow_hash,
                    grant.policy_hash,
                    grant_id,
                    grant.issue_number,
                    grant.issue_revision,
                    grant.phase,
                    grant.scope,
                    grant.caps,
                    at
                ],
            )
            .map_err(|err| StateError::from_sqlite("start_instance: insert", err))?;
        }
        let row = self.instance_by_id(instance_id)?.expect("just inserted");
        Ok(row)
    }

    /// One instance row by id.
    pub fn instance_by_id(&self, instance_id: &str) -> Result<Option<InstanceRow>, StateError> {
        let conn = self.lock("instance_by_id")?;
        let sql = format!("{} WHERE instance_id = ?1", instance_select_sql());
        let row = conn
            .query_row(sql.as_str(), params![instance_id], |row| {
                instance_row_from(row)
            })
            .optional()
            .map_err(|err| StateError::from_sqlite("instance_by_id: query", err))?;
        Ok(row)
    }

    /// Pause a workflow instance durably (AC8). The caller mints the fresh
    /// authorized resume digest via the engine; it is stored and required
    /// again on resume, surviving restarts.
    pub fn pause_instance(
        &self,
        instance_id: &str,
        resume_digest: &str,
        at: &str,
    ) -> Result<(), StateError> {
        let conn = self.lock("pause_instance")?;
        let affected = conn
            .execute(
                "UPDATE instances SET paused = 1, resume_digest = ?2, status = 'paused',
                        updated_at = ?3
                  WHERE instance_id = ?1 AND paused = 0",
                params![instance_id, resume_digest, at],
            )
            .map_err(|err| StateError::from_sqlite("pause_instance: update", err))?;
        if affected == 0 {
            return Err(state_error(
                "state.not_paused",
                format!("instance {instance_id:?} is not runnable (already paused or absent)"),
            ));
        }
        Ok(())
    }

    /// Resume a paused instance. `presented_digest` must equal the stored
    /// fresh authorized digest (engine [`crate::engine::authorize_resume`]);
    /// the digest is consumed on success so a stale digest can never resume
    /// twice (AC8).
    pub fn resume_instance(
        &self,
        instance_id: &str,
        presented_digest: &str,
        at: &str,
    ) -> Result<(), StateError> {
        let Some(row) = self.instance_by_id(instance_id)? else {
            return Err(state_error(
                "state.not_found",
                format!("no instance {instance_id:?}"),
            ));
        };
        if row.paused {
            crate::engine::authorize_resume(&row.resume_digest, presented_digest)
                .map_err(|err| state_error("state.stale_resume", err.message))?;
        }
        let conn = self.lock("resume_instance")?;
        let affected = conn
            .execute(
                "UPDATE instances SET paused = 0, resume_digest = '', status = 'running',
                        updated_at = ?2
                  WHERE instance_id = ?1 AND paused = 1",
                params![instance_id, at],
            )
            .map_err(|err| StateError::from_sqlite("resume_instance: update", err))?;
        if affected == 0 {
            return Err(state_error(
                "state.not_paused",
                format!("instance {instance_id:?} is not paused"),
            ));
        }
        Ok(())
    }

    // ---------------------------------------------------------------------
    // Run-scoped controls (issue #86): safe-boundary pause, resume and
    // bounded retry over the durable instance rows; plus the explicit
    // release of ONE run that can never progress (issue #146).
    // ---------------------------------------------------------------------

    /// Release ONE run that can never progress (issue #146) in ONE
    /// transaction: the run's unique ownership row is removed, the run goes
    /// terminal (`done` stays done, otherwise `invalidated`, pause cleared)
    /// so it stops counting against global/per-repository/per-harness
    /// occupancy. The audit records the reason, the exact run identity and
    /// the authorization window that run held.
    ///
    /// Fail closed on anything genuinely live: a step of the run still in
    /// flight (or an unattributable in-flight claim) refuses
    /// `refusal.run.in_flight`, and an unconsumed bounded retry
    /// authorization refuses `refusal.run.retry_pending` — a release never
    /// burns an authorization and never abandons work. Terminal runs can
    /// release leftover ownership; an already freed row is an audited no-op.
    /// A same-key retry replays the recorded response, and an unknown run is
    /// `state.not_found`. Everything else — including a
    /// run whose grant is missing, revoked or EXPIRED — is releasable: the
    /// release frees the durable bookkeeping, it never resurrects or reuses
    /// the window (a continuation needs a freshly minted grant window /
    /// explicit rotation, never a silent reuse of an expired one).
    pub fn release_run(
        &self,
        instance_id: &str,
        reason: &str,
        key: &str,
        at: &str,
    ) -> Result<RunReleaseOutcome, StateError> {
        self.ensure_writable()?;
        let mut conn = self.lock("release_run")?;
        let tx = conn
            .transaction()
            .map_err(|err| StateError::from_sqlite("release_run: begin", err))?;
        let row = tx
            .query_row(
                format!("{} WHERE instance_id = ?1", instance_select_sql()).as_str(),
                params![instance_id],
                instance_row_from,
            )
            .optional()
            .map_err(|err| StateError::from_sqlite("release_run: read", err))?;
        let Some(run) = row else {
            return Err(state_error(
                "state.not_found",
                format!("no instance {instance_id:?}"),
            ));
        };
        let in_flight = in_flight_steps_locked(&tx)?
            .iter()
            .any(|(named, _)| named == instance_id || named == "*");
        if in_flight {
            return Err(state_error(
                "refusal.run.in_flight",
                format!(
                    "run {instance_id} has a step dispatch in flight; a release never abandons \
                     live work (wait for its recorded boundary)"
                ),
            ));
        }
        if let Some((step_id, retry_id)) = unconsumed_retry_locked(&tx, instance_id)? {
            return Err(state_error(
                "refusal.run.retry_pending",
                format!(
                    "run {instance_id} still holds the unconsumed retry authorization {retry_id} \
                     for step {step_id:?}; a release never burns an authorization"
                ),
            ));
        }
        // The window this run held is recorded, never re-presented: a
        // missing, revoked or expired grant is exactly the case a release
        // exists for.
        let grant = tx
            .query_row(
                "SELECT grant_id, repository, issue_number, issue_revision, workflow_hash,
                        policy_hash, phase, scope, caps, expires_at, state_epoch, status,
                        created_at
                   FROM grants WHERE grant_id = ?1",
                params![run.grant_id],
                grant_row_from,
            )
            .optional()
            .map_err(|err| StateError::from_sqlite("release_run: grant", err))?;
        let grant_usable = grant.as_ref().is_some_and(|grant| {
            grant.status == "active" && !crate::mutation::is_expired(&grant.expires_at, at)
        });
        let affected = tx
            .execute(
                "UPDATE instances SET status = CASE WHEN status = 'done' THEN 'done' ELSE 'invalidated' END,
                        paused = 0, pause_requested = 0,
                        resume_digest = '', updated_at = ?2
                  WHERE instance_id = ?1
                    AND status IN ('new', 'running', 'paused', 'human_queue', 'blocked', 'done', 'invalidated')",
                params![instance_id, at],
            )
            .map_err(|err| StateError::from_sqlite("release_run: update", err))?;
        if affected != 1 {
            return Err(state_error(
                "state.ownership_conflict",
                format!("run {instance_id} moved before its release committed"),
            ));
        }
        let ownership_freed = tx
            .execute(
                "DELETE FROM queue_ownership
                  WHERE instance_id = ?1 AND repository = ?2 AND issue_number = ?3",
                params![instance_id, run.repository, run.issue_number],
            )
            .map_err(|err| StateError::from_sqlite("release_run: ownership", err))?
            == 1;
        // The release record: the reason, the exact run identity, what was
        // freed and the window the run held — in the same hash-chained audit
        // as every other mutation, committed in the SAME transaction.
        let target = format!(
            "run:{instance_id}:repository:{}#{}@{}:ownership:{}:grant:{}:grant_usable:{}:reason:{}",
            run.repository,
            run.issue_number,
            run.issue_revision,
            if ownership_freed { "freed" } else { "absent" },
            run.grant_id,
            grant_usable,
            reason
        );
        self.append_audit_locked(&tx, "run.release", &target, key, None, Some(&run.grant_id))?;
        let released = tx
            .query_row(
                format!("{} WHERE instance_id = ?1", instance_select_sql()).as_str(),
                params![instance_id],
                instance_row_from,
            )
            .map_err(|err| StateError::from_sqlite("release_run: reread", err))?;
        tx.commit()
            .map_err(|err| StateError::from_sqlite("release_run: commit", err))?;
        Ok(RunReleaseOutcome {
            run: released,
            ownership_freed,
            grant,
            grant_usable,
        })
    }

    /// The lane generations this system RETIRED for one repository issue
    /// (issue #190): the instance ids of the runs whose lane binding is
    /// terminal in the ledger — `invalidated` (a release, a revision rebind
    /// or an epoch rotation retired it) or `done` (its committed tail
    /// completed). A run's lane session id is derivable from its instance id
    /// ([`crate::mutation::run_session_handle`]), so a caller can retire the
    /// residue of exactly these generations and can never address a live one:
    /// a run that is not terminal still holds its issue's unique ownership.
    /// Ordered by instance id, so the caller's retire order is deterministic.
    pub fn retired_run_ids(
        &self,
        repository: &str,
        issue_number: i64,
    ) -> Result<Vec<String>, StateError> {
        let conn = self.lock("retired_run_ids")?;
        let mut stmt = conn
            .prepare(
                "SELECT instance_id FROM instances
                  WHERE repository = ?1 AND issue_number = ?2
                    AND status IN ('invalidated', 'done')
                  ORDER BY instance_id",
            )
            .map_err(|err| StateError::from_sqlite("retired_run_ids: prepare", err))?;
        let rows = stmt
            .query_map(params![repository, issue_number], |row| row.get(0))
            .map_err(|err| StateError::from_sqlite("retired_run_ids: read", err))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(|err| StateError::from_sqlite("retired_run_ids: row", err))?);
        }
        Ok(out)
    }

    /// The step id of a step-dispatch claim (`method:"apply"`) still in
    /// flight for one run, or `None` when nothing is in flight. An
    /// unreadable claimed line is treated as unknown in-flight work
    /// (conservative: the safe boundary is never claimed without proof).
    pub fn in_flight_run_step(&self, instance_id: &str) -> Result<Option<String>, StateError> {
        let held = self.in_flight_steps()?;
        Ok(held
            .into_iter()
            .find(|(run, _)| run == instance_id || run == "*")
            .map(|(_, step)| step))
    }

    /// Every in-flight step claim as `(instance_id, step)`; an unreadable
    /// claimed line is reported as `("*", "")` (attribution unknown).
    fn in_flight_steps(&self) -> Result<Vec<(String, String)>, StateError> {
        let conn = self.lock("in_flight_steps")?;
        in_flight_steps_locked(&conn)
    }

    /// Record ONE durable run pause (issue #86) in one transaction. The
    /// pause REQUEST takes effect immediately — new step dispatch for the
    /// run is refused from this moment on — while in-flight work keeps
    /// running: with a step still in flight the row carries
    /// `pause_requested` and the pause commits `paused` at the recorded
    /// step boundary ([`State::complete_run_pause_boundary`]); with no
    /// step in flight the safe boundary is already reached and the commit
    /// is immediate. The engine-minted resume digest is stored with the
    /// request (required and consumed by [`State::resume_run`]).
    pub fn request_run_pause(
        &self,
        instance_id: &str,
        reason: &str,
        resume_digest: &str,
        at: &str,
    ) -> Result<InstanceRow, StateError> {
        self.ensure_writable()?;
        let conn = self.lock("request_run_pause")?;
        let row = conn
            .query_row(
                format!("{} WHERE instance_id = ?1", instance_select_sql()).as_str(),
                params![instance_id],
                instance_row_from,
            )
            .optional()
            .map_err(|err| StateError::from_sqlite("request_run_pause: read", err))?;
        let Some(row) = row else {
            return Err(state_error(
                "state.not_found",
                format!("no instance {instance_id:?}"),
            ));
        };
        if row.status == "done" || row.status == "invalidated" {
            return Err(state_error(
                "refusal.run.terminal",
                format!(
                    "run {instance_id} is {}; a terminal run cannot be paused",
                    row.status
                ),
            ));
        }
        if row.paused || row.pause_requested {
            return Err(state_error(
                "refusal.run.control",
                format!(
                    "run {instance_id} already carries a pause (paused={}, pause_requested={}); \
                     a duplicate request never creates a second intent",
                    row.paused, row.pause_requested
                ),
            ));
        }
        let in_flight = in_flight_steps_locked(&conn)?
            .iter()
            .any(|(run, _)| run == instance_id || run == "*");
        // The reached boundary commits `paused`; the in-flight case records
        // the durable intent and leaves the running state untouched (no
        // signal, no kill, no cleanup — the in-flight work keeps its
        // worktree, its node and its dirty state).
        let (paused, requested, status): (i64, i64, &str) = if in_flight {
            (0, 1, row.status.as_str())
        } else {
            (1, 0, "paused")
        };
        let affected = conn
            .execute(
                "UPDATE instances SET paused = ?2, pause_requested = ?3, pause_reason = ?4,
                        pause_requested_at = ?5, resume_digest = ?6, status = ?7, updated_at = ?5
                  WHERE instance_id = ?1 AND paused = 0 AND pause_requested = 0",
                params![
                    instance_id,
                    paused,
                    requested,
                    reason,
                    at,
                    resume_digest,
                    status
                ],
            )
            .map_err(|err| StateError::from_sqlite("request_run_pause: update", err))?;
        if affected != 1 {
            return Err(state_error(
                "refusal.run.control",
                format!("run {instance_id} moved while the pause request committed"),
            ));
        }
        let row = conn
            .query_row(
                format!("{} WHERE instance_id = ?1", instance_select_sql()).as_str(),
                params![instance_id],
                instance_row_from,
            )
            .map_err(|err| StateError::from_sqlite("request_run_pause: reread", err))?;
        Ok(row)
    }

    /// Commit the reached safe boundary of one pause request (issue #86):
    /// `paused` becomes true and `pause_requested` false ONLY when no step
    /// claim of the run is in flight any more. Returns whether the
    /// boundary commit happened. Idempotent: a run without a pending
    /// request is left untouched.
    pub fn complete_run_pause_boundary(
        &self,
        instance_id: &str,
        at: &str,
    ) -> Result<bool, StateError> {
        self.ensure_writable()?;
        let conn = self.lock("complete_run_pause_boundary")?;
        let requested: Option<i64> = conn
            .query_row(
                "SELECT pause_requested FROM instances WHERE instance_id = ?1",
                params![instance_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|err| StateError::from_sqlite("complete_run_pause_boundary: read", err))?;
        if requested != Some(1) {
            return Ok(false);
        }
        let in_flight = in_flight_steps_locked(&conn)?
            .iter()
            .any(|(run, _)| run == instance_id || run == "*");
        if in_flight {
            return Ok(false);
        }
        let affected = conn
            .execute(
                "UPDATE instances SET paused = 1, pause_requested = 0, status = 'paused',
                        updated_at = ?2
                  WHERE instance_id = ?1 AND pause_requested = 1 AND paused = 0",
                params![instance_id, at],
            )
            .map_err(|err| StateError::from_sqlite("complete_run_pause_boundary: update", err))?;
        Ok(affected == 1)
    }

    /// Complete every pause request whose in-flight work is gone (boot
    /// reconciliation, issue #86): after a restart no step is executing,
    /// so a recorded request with no in-flight claim has reached its safe
    /// boundary. Returns the number of boundary commits.
    pub fn reconcile_run_pause_boundaries(&self, at: &str) -> Result<usize, StateError> {
        self.ensure_writable()?;
        let requested: Vec<String> = {
            let conn = self.lock("reconcile_run_pause_boundaries")?;
            let mut statement = conn
                .prepare("SELECT instance_id FROM instances WHERE pause_requested = 1")
                .map_err(|err| {
                    StateError::from_sqlite("reconcile_run_pause_boundaries: prepare", err)
                })?;
            let rows = statement
                .query_map([], |row| row.get::<_, String>(0))
                .map_err(|err| {
                    StateError::from_sqlite("reconcile_run_pause_boundaries: query", err)
                })?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row.map_err(|err| {
                    StateError::from_sqlite("reconcile_run_pause_boundaries: row", err)
                })?);
            }
            out
        };
        let mut committed = 0usize;
        for instance_id in requested {
            if self.complete_run_pause_boundary(&instance_id, at)? {
                committed += 1;
            }
        }
        Ok(committed)
    }

    /// Resume a paused run (issue #86). The caller must present the fresh
    /// engine-minted digest stored by [`State::request_run_pause`]; the
    /// digest binds the exact run and epoch and is consumed on success, so
    /// a stale or foreign digest can never resume anything. Fresh
    /// eligibility is re-derived under the guard: the run must still be
    /// live (not terminal), its epoch current, and its issue still owned
    /// by this run. The update is fenced on the EXACT instance id: an
    /// unrelated run's pause (or any fleet-level hold expressed as one) is
    /// never lifted.
    pub fn resume_run(
        &self,
        instance_id: &str,
        presented_digest: &str,
        at: &str,
    ) -> Result<InstanceRow, StateError> {
        self.ensure_writable()?;
        let conn = self.lock("resume_run")?;
        let row = conn
            .query_row(
                format!("{} WHERE instance_id = ?1", instance_select_sql()).as_str(),
                params![instance_id],
                instance_row_from,
            )
            .optional()
            .map_err(|err| StateError::from_sqlite("resume_run: read", err))?;
        let Some(row) = row else {
            return Err(state_error(
                "state.not_found",
                format!("no instance {instance_id:?}"),
            ));
        };
        if row.status == "done" || row.status == "invalidated" {
            return Err(state_error(
                "refusal.run.terminal",
                format!(
                    "run {instance_id} is {}; a terminal run cannot be resumed",
                    row.status
                ),
            ));
        }
        if !row.paused {
            return Err(state_error(
                "refusal.run.control",
                format!(
                    "run {instance_id} is not paused; there is nothing to resume (status {})",
                    row.status
                ),
            ));
        }
        crate::engine::authorize_resume(&row.resume_digest, presented_digest)
            .map_err(|err| state_error("state.stale_resume", err.message))?;
        // Fresh eligibility under the guard.
        let epoch = current_epoch_locked(&conn)?;
        if epoch != row.state_epoch {
            return Err(state_error(
                "refusal.state.epoch",
                format!(
                    "run {instance_id} was pinned to epoch {}; the live epoch is {epoch} (a \
                     resume authorization dies with its epoch)",
                    row.state_epoch
                ),
            ));
        }
        let owner: Option<String> = conn
            .query_row(
                "SELECT instance_id FROM queue_ownership
                  WHERE repository = ?1 AND issue_number = ?2",
                params![row.repository, row.issue_number],
                |owner| owner.get(0),
            )
            .optional()
            .map_err(|err| StateError::from_sqlite("resume_run: ownership", err))?;
        if let Some(owner) = owner
            && owner != instance_id
        {
            return Err(state_error(
                "refusal.run.superseded",
                format!(
                    "run {instance_id} no longer owns issue {} of {}; live ownership belongs to \
                     {owner}",
                    row.issue_number, row.repository
                ),
            ));
        }
        let affected = conn
            .execute(
                "UPDATE instances SET paused = 0, pause_requested = 0, pause_reason = '',
                        pause_requested_at = '', resume_digest = '', status = 'running',
                        updated_at = ?2
                  WHERE instance_id = ?1 AND paused = 1",
                params![instance_id, at],
            )
            .map_err(|err| StateError::from_sqlite("resume_run: update", err))?;
        if affected != 1 {
            return Err(state_error(
                "refusal.run.control",
                format!("run {instance_id} left its paused state while the resume committed"),
            ));
        }
        let row = conn
            .query_row(
                format!("{} WHERE instance_id = ?1", instance_select_sql()).as_str(),
                params![instance_id],
                instance_row_from,
            )
            .map_err(|err| StateError::from_sqlite("resume_run: reread", err))?;
        Ok(row)
    }

    /// The committed canonical bound-input line of one run (`None` for a run
    /// without a committed queue submission). Read from the durable
    /// submission — never from a caller.
    fn committed_bound_input(&self, instance_id: &str) -> Result<Option<String>, StateError> {
        let conn = self.lock("committed_bound_input")?;
        conn.query_row(
            "SELECT s.request_line FROM queue_submissions s
               JOIN queue_submission_items i ON i.submission_id = s.submission_id
              WHERE i.instance_id = ?1 AND i.status = 'admitted'",
            params![instance_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|err| StateError::from_sqlite("committed_bound_input: query", err))
    }

    /// The run's committed role identity (issue #92 F2): the reviewed
    /// `role_config` key and revision the submission bound, read from the
    /// durable bound-input line as `(key, revision)`. `None` when the run has
    /// no committed submission (or its `role_config` carries no key) — a
    /// harness step is then never bound to a profile, because there is no
    /// default profile to fall back to.
    pub fn run_role_identity(
        &self,
        instance_id: &str,
    ) -> Result<Option<(String, String)>, StateError> {
        let Some(line) = self.committed_bound_input(instance_id)? else {
            return Ok(None);
        };
        let doc = Val::parse_json(&line).map_err(|message| {
            state_error(
                "state.corrupt",
                format!("the committed bound-input line of {instance_id} is unreadable: {message}"),
            )
        })?;
        let role = doc.get("role_config").cloned().unwrap_or_else(null);
        let key = role.get("key").and_then(Val::as_str);
        let revision = role.get("revision").and_then(Val::as_str);
        match (key, revision) {
            (Some(key), Some(revision)) if !key.is_empty() && !revision.is_empty() => {
                Ok(Some((key.to_string(), revision.to_string())))
            }
            _ => Ok(None),
        }
    }

    /// Recover the full reviewed binding from the submission's durable claim.
    /// The bound preview pins its key/revision; the claim retains the document.
    pub fn run_role_binding(&self, instance_id: &str) -> Result<Option<Val>, StateError> {
        let Some(identity) = self.run_role_identity(instance_id)? else {
            return Ok(None);
        };
        let conn = self.lock("run_role_binding")?;
        let mut statement = conn
            .prepare(
                "SELECT d.key, d.request_line, s.submission_id FROM idempotency d
             JOIN queue_submissions s ON s.digest = json_extract(d.request_line, '$.params.digest')
             JOIN queue_submission_items i ON i.submission_id = s.submission_id
             WHERE d.method = 'queue.submit' AND i.instance_id = ?1 AND i.status = 'admitted'",
            )
            .map_err(|err| StateError::from_sqlite("run_role_binding: prepare", err))?;
        let rows = statement
            .query_map(params![instance_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .map_err(|err| StateError::from_sqlite("run_role_binding: query", err))?;
        for row in rows {
            let (key, line, submission) =
                row.map_err(|err| StateError::from_sqlite("run_role_binding: row", err))?;
            let doc =
                Val::parse_json(&line).map_err(|message| state_error("state.corrupt", message))?;
            let params = doc.get("params").unwrap_or(&Val::Null);
            let digest = params
                .get("digest")
                .and_then(Val::as_str)
                .unwrap_or_default();
            if crate::queue_executor::submission_id(digest, &key) != submission {
                continue;
            }
            if let Some(binding) = params.get("binding") {
                let parsed = crate::config::ProfileBinding::from_doc(binding)
                    .map_err(|err| state_error(err.code(), err.message()))?;
                if (parsed.key, parsed.revision) == identity {
                    return Ok(Some(binding.clone()));
                }
            }
        }
        Ok(None)
    }

    /// The committed executable spine of one run as raw step documents
    /// (`None` for a run without a committed queue submission). The spine is
    /// the reviewed bound-input `steps` array — never a caller's.
    pub fn run_step_documents(&self, instance_id: &str) -> Result<Option<Vec<Val>>, StateError> {
        let Some(line) = self.committed_bound_input(instance_id)? else {
            return Ok(None);
        };
        let doc = Val::parse_json(&line).map_err(|message| {
            state_error(
                "state.corrupt",
                format!("the committed bound-input line of {instance_id} is unreadable: {message}"),
            )
        })?;
        let mut steps = doc
            .get("steps")
            .and_then(Val::as_array)
            .cloned()
            .unwrap_or_default();
        // Apply claims already persist the effective params before an effect.
        // Replay only the addressed step's inputs, not a caller's entire plan.
        let conn = self.lock("run_step_documents")?;
        let mut statement = conn
            .prepare("SELECT request_line FROM idempotency WHERE method = 'apply' ORDER BY rowid")
            .map_err(|err| StateError::from_sqlite("run_step_documents: prepare", err))?;
        let rows = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|err| StateError::from_sqlite("run_step_documents: query", err))?;
        for row in rows {
            let line =
                row.map_err(|err| StateError::from_sqlite("run_step_documents: row", err))?;
            let request =
                Val::parse_json(&line).map_err(|message| state_error("state.corrupt", message))?;
            let Some(params) = request.get("params") else {
                continue;
            };
            if params.get("instance_id").and_then(Val::as_str) != Some(instance_id) {
                continue;
            }
            let id = params.get("step").and_then(Val::as_str);
            let Some(recorded) = params
                .get("plan")
                .and_then(|plan| plan.get("steps"))
                .and_then(Val::as_array)
                .and_then(|steps| {
                    steps
                        .iter()
                        .find(|step| step.get("id").and_then(Val::as_str) == id)
                })
            else {
                continue;
            };
            if let Some(Val::Obj(step)) = steps
                .iter_mut()
                .find(|step| step.get("id").and_then(Val::as_str) == id)
                && recorded.get("kind") == step.get("kind")
                && let Some(inputs @ Val::Obj(_)) = recorded.get("params")
            {
                step.insert("params".to_string(), inputs.clone());
            }
        }
        Ok(Some(steps))
    }

    /// The recorded dispatch context of one run: its first immutable topology,
    /// newest explicit admission attestation and successful worker heads.
    /// These are caller-observed durable facts; continuation never invents a
    /// topology, resource measurement, or repository head.
    ///
    /// Issue #202 (AC2): the run's `feature_head` is bound by the run's own
    /// COLLECTION alone (the [`DeliveryCertificate`] below, derived from the
    /// newest successful `collect_outcome` step response) or by a response
    /// that NAMES a reviewed head explicitly (the review-evidence and
    /// post-merge-verify records). A `head` echoed by any other effect — e.g.
    /// the base a `worktree_create`/`checkout` response carries — is never a
    /// certified feature head: a run whose collection never observed a
    /// delivery binds NOTHING here.
    pub fn run_dispatch_context(
        &self,
        instance_id: &str,
    ) -> Result<Option<RecordedDispatch>, StateError> {
        let conn = self.lock("run_dispatch_context")?;
        let delivery = self.delivery_certificate_locked(&conn, instance_id)?;
        let submissions: Vec<String> = {
            let mut statement = conn
                .prepare(
                    "SELECT submission_id FROM queue_submission_items
                      WHERE instance_id = ?1 AND status = 'admitted' ORDER BY rowid",
                )
                .map_err(|err| {
                    StateError::from_sqlite("run_dispatch_context: submissions prepare", err)
                })?;
            let rows = statement
                .query_map(params![instance_id], |row| row.get::<_, String>(0))
                .map_err(|err| {
                    StateError::from_sqlite("run_dispatch_context: submissions query", err)
                })?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row.map_err(|err| {
                    StateError::from_sqlite("run_dispatch_context: submission row", err)
                })?);
            }
            out
        };
        let mut statement = conn
            .prepare(
                "SELECT method, key, request_line, COALESCE(response, '') FROM idempotency
                  WHERE method IN ('queue.submit', 'apply') AND outcome IS NOT NULL
                  ORDER BY rowid",
            )
            .map_err(|err| StateError::from_sqlite("run_dispatch_context: prepare", err))?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })
            .map_err(|err| StateError::from_sqlite("run_dispatch_context: query", err))?;
        let mut topology: Option<Val> = None;
        let mut admission: Option<Val> = None;
        let mut integration_base: Option<String> = None;
        // Issue #202 (AC2): the collection's own certified head is the ONLY
        // head this context starts from; the loop below may only override it
        // with a response that NAMES a reviewed head explicitly.
        let mut feature_head: Option<String> = delivery
            .as_ref()
            .map(|certificate| certificate.head.clone());
        for row in rows {
            let (method, key, line, response_line) =
                row.map_err(|err| StateError::from_sqlite("run_dispatch_context: row", err))?;
            let Ok(request) = Val::parse_json(&line) else {
                continue;
            };
            let params = request.get("params").cloned().unwrap_or_else(null);
            if method == "queue.submit" {
                let digest = params
                    .get("digest")
                    .and_then(Val::as_str)
                    .unwrap_or_default();
                let submission = crate::queue_executor::submission_id(digest, &key);
                if !submissions.iter().any(|known| known == &submission) {
                    continue;
                }
                if let Some(dispatch @ Val::Obj(_)) = params.get("dispatch") {
                    if let Some(presented @ Val::Obj(_)) = dispatch.get("topology") {
                        match &topology {
                            Some(bound) if bound != presented => {
                                return Err(state_error(
                                    "state.corrupt",
                                    format!(
                                        "run {instance_id} recorded conflicting dispatch topologies"
                                    ),
                                ));
                            }
                            None => topology = Some(presented.clone()),
                            _ => {}
                        }
                    }
                    if let Some(presented @ Val::Obj(_)) = dispatch.get("admission") {
                        admission = Some(presented.clone());
                    }
                }
                continue;
            }
            if params.get("instance_id").and_then(Val::as_str) != Some(instance_id) {
                continue;
            }
            if let Some(presented @ Val::Obj(_)) = params.get("topology") {
                match &topology {
                    Some(bound) if bound != presented => {
                        return Err(state_error(
                            "state.corrupt",
                            format!("run {instance_id} recorded conflicting dispatch topologies"),
                        ));
                    }
                    None => topology = Some(presented.clone()),
                    _ => {}
                }
            }
            if let Some(presented @ Val::Obj(_)) =
                params.get("flags").and_then(|flags| flags.get("admission"))
            {
                admission = Some(presented.clone());
            }
            if let Ok(response) = Val::parse_json(&response_line)
                && response.get("ok").and_then(Val::as_bool) == Some(true)
                && let Some(result) = response.get("result")
            {
                if integration_base.is_none()
                    && let Some(base) = result
                        .get("integration_base")
                        .or_else(|| result.get("base_head"))
                        .and_then(Val::as_str)
                        .filter(|base| crate::formats::is_hex40(base))
                {
                    integration_base = Some(base.to_string());
                }
                if let Some(head) = result
                    .get("feature_head")
                    .and_then(Val::as_str)
                    .filter(|head| crate::formats::is_hex40(head))
                {
                    feature_head = Some(head.to_string());
                }
            }
        }
        Ok(topology.map(|topology| RecordedDispatch {
            topology,
            admission,
            integration_base,
            feature_head,
            delivery,
        }))
    }

    /// The certified delivery of one run (issue #202 AC2): the delivery
    /// binding ONE successful `collect_outcome` step of this run observed and
    /// recorded — the newest such binding in claim order. Derived from
    /// recorded rows only (never inferred, never a neighbouring effect's
    /// head): a run whose collection never certified a bindable head has
    /// `None` here, so no later step can consume a head the run never
    /// observed.
    fn delivery_certificate_locked(
        &self,
        conn: &Connection,
        instance_id: &str,
    ) -> Result<Option<DeliveryCertificate>, StateError> {
        let mut statement = conn
            .prepare(
                "SELECT key, request_line, COALESCE(response, '') FROM idempotency
                  WHERE method = 'apply' AND outcome IS NOT NULL
                  ORDER BY rowid",
            )
            .map_err(|err| StateError::from_sqlite("run_delivery_certificate: prepare", err))?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .map_err(|err| StateError::from_sqlite("run_delivery_certificate: query", err))?;
        let mut certificate: Option<DeliveryCertificate> = None;
        for row in rows {
            let (key, line, response_line) =
                row.map_err(|err| StateError::from_sqlite("run_delivery_certificate: row", err))?;
            let Ok(request) = Val::parse_json(&line) else {
                continue;
            };
            let params = request.get("params").cloned().unwrap_or_else(null);
            if params.get("instance_id").and_then(Val::as_str) != Some(instance_id) {
                continue;
            }
            let Some(step_id) = params.get("step").and_then(Val::as_str) else {
                continue;
            };
            // Only the run's own collection certifies a delivery head: the
            // step KIND is the committed plan step's own kind, never a name
            // heuristic on the step id.
            let kind = params
                .get("plan")
                .and_then(|plan| plan.get("steps"))
                .and_then(Val::as_array)
                .and_then(|steps| {
                    steps
                        .iter()
                        .find(|step| step.get("id").and_then(Val::as_str) == Some(step_id))
                })
                .and_then(|step| step.get("kind"))
                .and_then(Val::as_str)
                .unwrap_or("");
            if kind != "collect_outcome" {
                continue;
            }
            let Ok(response) = Val::parse_json(&response_line) else {
                continue;
            };
            if response.get("ok").and_then(Val::as_bool) != Some(true) {
                continue;
            }
            let Some(result) = response.get("result") else {
                continue;
            };
            let head = match result
                .get("head")
                .and_then(Val::as_str)
                .filter(|head| crate::formats::is_hex40(head))
            {
                Some(head) => head.to_string(),
                None => continue,
            };
            let branch = match result
                .get("branch")
                .and_then(Val::as_str)
                .filter(|branch| crate::formats::is_slug(branch))
            {
                Some(branch) => branch.to_string(),
                None => continue,
            };
            certificate = Some(DeliveryCertificate {
                step_id: step_id.to_string(),
                key: key.clone(),
                branch,
                head,
                base_head: result
                    .get("base_head")
                    .and_then(Val::as_str)
                    .unwrap_or_default()
                    .to_string(),
            });
        }
        Ok(certificate)
    }

    /// The certified delivery of one run (the locked helper above, read-only).
    pub fn run_delivery_certificate(
        &self,
        instance_id: &str,
    ) -> Result<Option<DeliveryCertificate>, StateError> {
        let conn = self.lock("run_delivery_certificate")?;
        self.delivery_certificate_locked(&conn, instance_id)
    }

    /// The `harness_start` step of one run whose dispatch is recorded as
    /// succeeded — the step that bound the run's session (issue #92 F2).
    /// `None` when the run has no committed submission, its spine names no
    /// `harness_start` step, or none of them is recorded succeeded: a prompt
    /// then continues nothing and is refused.
    pub fn run_bound_start_step(&self, instance_id: &str) -> Result<Option<String>, StateError> {
        let Some(line) = self.committed_bound_input(instance_id)? else {
            return Ok(None);
        };
        let doc = Val::parse_json(&line).map_err(|message| {
            state_error(
                "state.corrupt",
                format!("the committed bound-input line of {instance_id} is unreadable: {message}"),
            )
        })?;
        let steps = doc
            .get("steps")
            .and_then(Val::as_array)
            .cloned()
            .unwrap_or_default();
        let start_steps: Vec<String> = steps
            .iter()
            .filter(|step| step.get("kind").and_then(Val::as_str) == Some("harness_start"))
            .filter_map(|step| step.get("id").and_then(Val::as_str).map(str::to_string))
            .collect();
        if start_steps.is_empty() {
            return Ok(None);
        }
        let attempts = self.run_step_attempts(instance_id)?;
        Ok(start_steps.into_iter().find(|step| {
            attempts
                .iter()
                .any(|(id, status)| id == step && status == "succeeded")
        }))
    }

    /// The bound step spine of one run (`None` for a run without a
    /// committed queue submission). The spine is read from the committed
    /// submission's canonical bound-input line — never from a caller.
    pub fn run_step_spine(&self, instance_id: &str) -> Result<Option<Vec<String>>, StateError> {
        let conn = self.lock("run_step_spine")?;
        let line: Option<String> = conn
            .query_row(
                "SELECT s.request_line FROM queue_submissions s
                   JOIN queue_submission_items i ON i.submission_id = s.submission_id
                  WHERE i.instance_id = ?1 AND i.status = 'admitted'",
                params![instance_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|err| StateError::from_sqlite("run_step_spine: query", err))?;
        let Some(line) = line else {
            return Ok(None);
        };
        let doc = Val::parse_json(&line).map_err(|message| {
            state_error(
                "state.corrupt",
                format!("the committed bound-input line of {instance_id} is unreadable: {message}"),
            )
        })?;
        let steps = doc
            .get("steps")
            .and_then(Val::as_array)
            .cloned()
            .unwrap_or_default();
        Ok(Some(
            steps
                .iter()
                .filter_map(|step| step.get("id").and_then(Val::as_str))
                .map(str::to_string)
                .collect(),
        ))
    }

    /// The recorded step attempts of one run as `(step, status)` in claim
    /// order, from the durable apply claims (request line + resolved
    /// `hf-outcome/v1`). Diagnosis input for the bounded retry control:
    /// never inferred, always read back.
    pub fn run_step_attempts(
        &self,
        instance_id: &str,
    ) -> Result<Vec<(String, String)>, StateError> {
        let conn = self.lock("run_step_attempts")?;
        let mut statement = conn
            .prepare(
                "SELECT method, request_line, outcome FROM idempotency
                  WHERE method IN ('apply', 'run.resolve') AND outcome IS NOT NULL
                  ORDER BY rowid",
            )
            .map_err(|err| StateError::from_sqlite("run_step_attempts: prepare", err))?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                ))
            })
            .map_err(|err| StateError::from_sqlite("run_step_attempts: query", err))?;
        let mut out = Vec::new();
        for row in rows {
            let (method, line, outcome) =
                row.map_err(|err| StateError::from_sqlite("run_step_attempts: row", err))?;
            let Some(outcome) = outcome else {
                continue;
            };
            let Ok(request) = Val::parse_json(&line) else {
                continue;
            };
            let params = request.get("params").cloned().unwrap_or_else(null);
            if params.get("instance_id").and_then(Val::as_str) != Some(instance_id) {
                continue;
            }
            let step = params
                .get("step")
                .and_then(Val::as_str)
                .unwrap_or("")
                .to_string();
            let Ok(outcome) = Val::parse_json(&outcome) else {
                continue;
            };
            let status = outcome
                .get("status")
                .and_then(Val::as_str)
                .unwrap_or("unknown")
                .to_string();
            if method == "run.resolve" && status != "succeeded" {
                continue;
            }
            out.push((step, status));
        }
        Ok(out)
    }

    /// Whether one run's recorded frontier has reached its own
    /// reviewed-evidence step (issue #192). Read-only; the SAME durable facts
    /// the submission transaction's own check reads, so the preview and the
    /// admission agree about a run that a candidate rebuild may not supersede.
    pub fn run_reached_review_frontier(&self, instance_id: &str) -> Result<bool, StateError> {
        let conn = self.lock("run_reached_review_frontier")?;
        owner_reached_review_frontier_locked(self, &conn, instance_id)
    }

    /// One run's recorded frontier as one bounded summary — its frontier step
    /// and kind plus its recorded supervision class (issue #209). Read-only;
    /// the SAME facts the submission transaction's own refusal names, so the
    /// preview, the submission pre-screen and the admission agree about where
    /// a live run stands.
    pub fn run_frontier_summary(&self, instance_id: &str) -> Result<String, StateError> {
        let conn = self.lock("run_frontier_summary")?;
        owner_frontier_summary_locked(self, &conn, instance_id)
    }

    /// Every durable retry authorization of one run, oldest first.
    pub fn run_retries(&self, instance_id: &str) -> Result<Vec<RunRetryRow>, StateError> {
        let conn = self.lock("run_retries")?;
        let mut statement = conn
            .prepare(
                "SELECT retry_id, instance_id, step_id, attempt, authorized_at,
                        consumed_at, consumed_key
                   FROM run_retries WHERE instance_id = ?1
                  ORDER BY step_id, attempt",
            )
            .map_err(|err| StateError::from_sqlite("run_retries: prepare", err))?;
        let rows = statement
            .query_map(params![instance_id], |row| {
                Ok(RunRetryRow {
                    retry_id: row.get(0)?,
                    instance_id: row.get(1)?,
                    step_id: row.get(2)?,
                    attempt: row.get(3)?,
                    authorized_at: row.get(4)?,
                    consumed_at: row.get(5)?,
                    consumed_key: row.get(6)?,
                })
            })
            .map_err(|err| StateError::from_sqlite("run_retries: query", err))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(|err| StateError::from_sqlite("run_retries: row", err))?);
        }
        Ok(out)
    }

    /// Record ONE bounded retry authorization for one diagnosed step of
    /// one run (issue #86). The attempt number is the next unused slot,
    /// the deterministic retry id derives from (run, step, attempt), and
    /// the bound is enforced here (row count); a still-unconsumed
    /// authorization for the same step refuses a second one (no duplicate
    /// effect).
    pub fn record_run_retry(
        &self,
        instance_id: &str,
        step_id: &str,
        at: &str,
    ) -> Result<RunRetryRow, StateError> {
        self.record_run_retry_inner(instance_id, step_id, at, "")
    }

    /// Reserve and consume supervision's own retry in one write. A pending
    /// operator retry refuses here, never becoming the automatic claim.
    pub(crate) fn consume_supervised_retry(
        &self,
        instance_id: &str,
        step_id: &str,
        at: &str,
        claim_key: &str,
    ) -> Result<RunRetryRow, StateError> {
        self.record_run_retry_inner(instance_id, step_id, at, claim_key)
    }

    fn record_run_retry_inner(
        &self,
        instance_id: &str,
        step_id: &str,
        at: &str,
        claim_key: &str,
    ) -> Result<RunRetryRow, StateError> {
        self.ensure_writable()?;
        let conn = self.lock("record_run_retry")?;
        let existing: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM run_retries WHERE instance_id = ?1 AND step_id = ?2",
                params![instance_id, step_id],
                |row| row.get(0),
            )
            .map_err(|err| StateError::from_sqlite("record_run_retry: count", err))?;
        let pending: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM run_retries
                  WHERE instance_id = ?1 AND step_id = ?2 AND consumed_at = ''",
                params![instance_id, step_id],
                |row| row.get(0),
            )
            .map_err(|err| StateError::from_sqlite("record_run_retry: pending", err))?;
        if pending > 0 {
            return Err(state_error(
                "refusal.run.retry_pending",
                format!(
                    "run {instance_id} already holds an unconsumed retry authorization for step \
                     {step_id:?}; a duplicate request never creates a second one"
                ),
            ));
        }
        if existing >= RUN_RETRY_MAX {
            return Err(state_error(
                "refusal.run.retry_bound",
                format!(
                    "step {step_id:?} of run {instance_id} already used all {RUN_RETRY_MAX} \
                     bounded retries"
                ),
            ));
        }
        let attempt = existing + 1;
        let retry_id = crate::run_control::retry_id(instance_id, step_id, attempt);
        conn.execute(
            "INSERT INTO run_retries (retry_id, instance_id, step_id, attempt, authorized_at,
                    consumed_at, consumed_key)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                retry_id,
                instance_id,
                step_id,
                attempt,
                at,
                if claim_key.is_empty() { "" } else { at },
                claim_key
            ],
        )
        .map_err(|err| StateError::from_sqlite("record_run_retry: insert", err))?;
        Ok(RunRetryRow {
            retry_id,
            instance_id: instance_id.to_string(),
            step_id: step_id.to_string(),
            attempt,
            authorized_at: at.to_string(),
            consumed_at: if claim_key.is_empty() { "" } else { at }.to_string(),
            consumed_key: claim_key.to_string(),
        })
    }

    /// Check one step dispatch against the bounded-retry fence (issue #86)
    /// and consume the single-use authorization when one is needed:
    /// a first dispatch of a step is never fenced; a re-dispatch of a step
    /// whose recorded outcomes include a terminal non-success consumes one
    /// unconsumed authorization, and refuses (`RunRetryClaim::Missing`)
    /// when none exists. A recorded refusal of the run's OWN lapsed window
    /// is not a step diagnosis ([`step_attempt_diagnosed`], issue #184), so
    /// a lapse never demands a retry.
    pub fn claim_run_retry(
        &self,
        instance_id: &str,
        step_id: &str,
        claim_key: &str,
        at: &str,
    ) -> Result<RunRetryClaim, StateError> {
        self.ensure_writable()?;
        let conn = self.lock("claim_run_retry")?;
        let attempts = self.run_step_attempts_with_codes(&conn, instance_id)?;
        let diagnosed = attempts
            .iter()
            .any(|(step, status, code)| step == step_id && step_attempt_diagnosed(status, code));
        if !diagnosed {
            return Ok(RunRetryClaim::NotRequired);
        }
        // Supervision reserved and consumed its own slot with the intent.
        let consumed: Option<String> = conn
            .query_row(
                "SELECT retry_id FROM run_retries
              WHERE instance_id = ?1 AND step_id = ?2 AND consumed_key = ?3
                AND consumed_at != ''",
                params![instance_id, step_id, claim_key],
                |row| row.get(0),
            )
            .optional()
            .map_err(|err| StateError::from_sqlite("claim_run_retry: consumed", err))?;
        if let Some(retry_id) = consumed {
            return Ok(RunRetryClaim::Consumed(retry_id));
        }
        let pending: Option<(String, i64)> = conn
            .query_row(
                "SELECT retry_id, attempt FROM run_retries
                  WHERE instance_id = ?1 AND step_id = ?2 AND consumed_at = ''
                  ORDER BY attempt LIMIT 1",
                params![instance_id, step_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|err| StateError::from_sqlite("claim_run_retry: pending", err))?;
        let Some((retry_id, attempt)) = pending else {
            return Ok(RunRetryClaim::Missing);
        };
        let affected = conn
            .execute(
                "UPDATE run_retries SET consumed_at = ?3, consumed_key = ?4
                  WHERE retry_id = ?1 AND attempt = ?2 AND consumed_at = ''",
                params![retry_id, attempt, at, claim_key],
            )
            .map_err(|err| StateError::from_sqlite("claim_run_retry: consume", err))?;
        if affected != 1 {
            return Ok(RunRetryClaim::Missing);
        }
        Ok(RunRetryClaim::Consumed(retry_id))
    }

    /// Renew the OWN lapsed authorization window of one live run (issue
    /// #184) as an audited `grant.rotation`-class mutation.
    ///
    /// `Some(renewal)` exactly when the run's own presented grant row is
    /// `active`, bound to this run and to the live epoch, its window has
    /// actually lapsed, the run is live (unpaused, unheld, under the live
    /// epoch, still owning its issue) and its committed spine still owes
    /// steps. ONE transaction then inserts the successor grant derived from
    /// the lapsed one — same repository/issue/revision/workflow/policy/phase/
    /// scope/caps/epoch, NEW grant id and a new expiry SIZED FROM THE
    /// REMAINING SPINE — re-points the run to it, and appends one
    /// `grant.rotation` record naming the superseded grant, the replacement
    /// grant and the recorded expiry.
    ///
    /// `None` invents nothing and changes nothing: every continuation the
    /// engine does not own — a foreign, revoked, stale-epoch, released,
    /// paused, held or exhausted run, a run whose window is still live, or a
    /// run without a committed spine — keeps refusing exactly as before, so
    /// the renewal never becomes a blanket authorization.
    pub fn renew_lapsed_run_grant(
        &self,
        instance_id: &str,
        presented_grant_id: &str,
        at: &str,
    ) -> Result<Option<LapsedGrantRenewal>, StateError> {
        self.ensure_writable()?;
        let Some(run) = self.instance_by_id(instance_id)? else {
            return Ok(None);
        };
        // The committed spine is immutable once submitted: read it (with the
        // achieved ledger) OUTSIDE the transaction, so the derived window can
        // only ever come from durable rows.
        let (Some(spine), Some(steps)) = (
            self.run_step_spine(instance_id)?,
            self.run_step_documents(instance_id)?,
        ) else {
            return Ok(None);
        };
        let attempts = self.run_step_attempts(instance_id)?;
        let Some(window_secs) = renewal_window_secs(&spine, &steps, &attempts, &run.current_node)
        else {
            return Ok(None);
        };
        let Some(expires_unix) = time::unix_from_rfc3339(at) else {
            return Err(state_error(
                "state.corrupt",
                format!("the renewal instant {at:?} is not an RFC3339 UTC second"),
            ));
        };
        let expires_at = time::rfc3339_from_unix(expires_unix.saturating_add(window_secs));
        let successor_id = renewal_grant_id(instance_id, presented_grant_id, &expires_at);
        let mut conn = self.lock("renew_lapsed_run_grant")?;
        let tx = conn
            .transaction()
            .map_err(|err| StateError::from_sqlite("renew_lapsed_run_grant: begin", err))?;
        // Re-derive every guard under the transaction: the run as it is now,
        // the live epoch, its issue ownership and its own grant row.
        let sql = format!("{} WHERE instance_id = ?1", instance_select_sql());
        let run: Option<InstanceRow> = tx
            .query_row(sql.as_str(), params![instance_id], instance_row_from)
            .optional()
            .map_err(|err| StateError::from_sqlite("renew_lapsed_run_grant: run", err))?;
        let Some(run) = run else {
            return Ok(None);
        };
        let epoch = current_epoch_locked(&tx)?;
        let owner: Option<String> = tx
            .query_row(
                "SELECT instance_id FROM queue_ownership
                  WHERE repository = ?1 AND issue_number = ?2",
                params![run.repository, run.issue_number],
                |row| row.get(0),
            )
            .optional()
            .map_err(|err| StateError::from_sqlite("renew_lapsed_run_grant: ownership", err))?;
        if run.grant_id != presented_grant_id
            || run.state_epoch != epoch
            || !matches!(run.status.as_str(), "new" | "running")
            || run.paused
            || run.pause_requested
            || run.human_queue
            || run.terminal_blockers > 0
            || owner.as_deref() != Some(instance_id)
        {
            return Ok(None);
        }
        let grant: Option<GrantRow> = tx
            .query_row(
                "SELECT grant_id, repository, issue_number, issue_revision, workflow_hash,
                        policy_hash, phase, scope, caps, expires_at, state_epoch, status, created_at
                   FROM grants WHERE grant_id = ?1",
                params![presented_grant_id],
                grant_row_from,
            )
            .optional()
            .map_err(|err| StateError::from_sqlite("renew_lapsed_run_grant: grant", err))?;
        let Some(grant) = grant else {
            return Ok(None);
        };
        if grant.status != "active"
            || grant.state_epoch != epoch
            || grant.repository != run.repository
            || grant.issue_number != run.issue_number
            || grant.issue_revision != run.issue_revision
            || !crate::mutation::is_expired(&grant.expires_at, at)
        {
            return Ok(None);
        }
        tx.execute(
            "INSERT INTO grants (grant_id, repository, issue_number, issue_revision,
                                 workflow_hash, policy_hash, phase, scope, caps,
                                 expires_at, state_epoch, status, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 'active', ?12)",
            params![
                successor_id,
                grant.repository,
                grant.issue_number,
                grant.issue_revision,
                grant.workflow_hash,
                grant.policy_hash,
                grant.phase,
                grant.scope,
                grant.caps,
                expires_at,
                epoch,
                at
            ],
        )
        .map_err(|err| StateError::from_sqlite("renew_lapsed_run_grant: successor", err))?;
        let affected = tx
            .execute(
                "UPDATE instances SET grant_id = ?2, updated_at = ?3
                  WHERE instance_id = ?1 AND grant_id = ?4
                    AND status IN ('new', 'running') AND paused = 0 AND pause_requested = 0",
                params![instance_id, successor_id, at, presented_grant_id],
            )
            .map_err(|err| StateError::from_sqlite("renew_lapsed_run_grant: rebind", err))?;
        if affected != 1 {
            return Err(state_error(
                "state.ownership_conflict",
                format!("run {instance_id} changed before its lapsed window renewed"),
            ));
        }
        let mut key = format!("ik_renew-{instance_id}-{successor_id}");
        key.truncate(64);
        self.append_audit_locked(
            &tx,
            "grant.rotation",
            &format!(
                "run:{instance_id}:superseded:{presented_grant_id}:replacement:{successor_id}:expires:{expires_at}:window_secs:{window_secs}"
            ),
            &key,
            None,
            Some(&successor_id),
        )?;
        tx.commit()
            .map_err(|err| StateError::from_sqlite("renew_lapsed_run_grant: commit", err))?;
        Ok(Some(LapsedGrantRenewal {
            // The successor differs from the lapsed row in exactly three
            // fields: identity, recorded expiry and creation instant.
            successor: GrantRow {
                grant_id: successor_id,
                expires_at,
                state_epoch: epoch,
                status: "active".to_string(),
                created_at: at.to_string(),
                ..grant.clone()
            },
            superseded: grant,
            window_secs,
        }))
    }

    /// Record ONE host-proof renewal (issue #198) as an audited
    /// `host.proof.renewal` record.
    ///
    /// The supervisor measured the host at DISPATCH time and presents that
    /// measurement in place of the run's lapsed recorded attestation; this
    /// record makes the re-measurement inspectable (which proof was
    /// superseded, which measurement replaced it, when it was taken and what
    /// the host exposed), so the zero-operator witness stays auditable
    /// without reading any daemon-internal log. It changes no durable row:
    /// the renewal is an observation the run's own dispatch presents, not a
    /// mutation of control state.
    pub fn record_host_proof_renewal(
        &self,
        instance_id: &str,
        key: &str,
        superseded_at: &str,
        measured_at: &str,
        available_bytes: u64,
    ) -> Result<(), StateError> {
        self.ensure_writable()?;
        let mut conn = self.lock("record_host_proof_renewal")?;
        let tx = conn
            .transaction()
            .map_err(|err| StateError::from_sqlite("record_host_proof_renewal: begin", err))?;
        self.append_audit_locked(
            &tx,
            "host.proof.renewal",
            &format!(
                "run:{instance_id}:superseded:{superseded_at}:replacement:{measured_at}:available_bytes:{available_bytes}"
            ),
            key,
            None,
            None,
        )?;
        tx.commit()
            .map_err(|err| StateError::from_sqlite("record_host_proof_renewal: commit", err))?;
        Ok(())
    }

    /// Advance a running instance: record the current node and review-round
    /// counters (AC4) plus blocker accounting (AC7). The caller computes the
    /// new values with the engine; this only persists them.
    #[allow(clippy::too_many_arguments)]
    pub fn advance_instance(
        &self,
        instance_id: &str,
        current_node: &str,
        normal_rounds: u32,
        recovery_rounds: u32,
        human_queue: bool,
        terminal_blockers: u32,
        at: &str,
    ) -> Result<(), StateError> {
        let status = if human_queue {
            "human_queue"
        } else if terminal_blockers > 0 {
            "blocked"
        } else {
            "running"
        };
        let conn = self.lock("advance_instance")?;
        let affected = conn
            .execute(
                "UPDATE instances SET current_node = ?2, normal_rounds = ?3,
                        recovery_rounds = ?4, human_queue = ?5, terminal_blockers = ?6,
                        status = ?7, updated_at = ?8
                  WHERE instance_id = ?1",
                params![
                    instance_id,
                    current_node,
                    normal_rounds,
                    recovery_rounds,
                    human_queue as i64,
                    terminal_blockers,
                    status,
                    at
                ],
            )
            .map_err(|err| StateError::from_sqlite("advance_instance: update", err))?;
        let _ = affected;
        Ok(())
    }

    /// List workflow instances (any status), oldest first.
    pub fn list_instances(&self) -> Result<Vec<InstanceRow>, StateError> {
        let conn = self.lock("list_instances")?;
        let mut statement = conn
            .prepare(&instance_select_sql())
            .map_err(|err| StateError::from_sqlite("list_instances: prepare", err))?;
        let rows = statement
            .query_map([], instance_row_from)
            .map_err(|err| StateError::from_sqlite("list_instances: query", err))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(|err| StateError::from_sqlite("list_instances: row", err))?);
        }
        Ok(out)
    }

    // ---------------------------------------------------------------------
    // Queue executor (issue #85): durable submissions, membership and
    // unique work ownership
    // ---------------------------------------------------------------------

    /// One durable queue submission with its membership items (issue #85),
    /// or `None` when no submission with that id exists. Read-only.
    pub fn queue_submission_by_id(
        &self,
        submission_id: &str,
    ) -> Result<Option<(QueueSubmissionRow, Vec<QueueSubmissionItemRow>)>, StateError> {
        let conn = self.lock("queue_submission_by_id")?;
        let row = conn
            .query_row(
                format!("{} WHERE submission_id = ?1", queue_submission_select_sql()).as_str(),
                params![submission_id],
                queue_submission_row_from,
            )
            .optional()
            .map_err(|err| StateError::from_sqlite("queue_submission_by_id: query", err))?;
        let Some(submission) = row else {
            return Ok(None);
        };
        let mut statement = conn
            .prepare(
                "SELECT submission_id, ordinal, work_item, issue_number, issue_revision,
                        status, reason, message, instance_id, grant_id
                   FROM queue_submission_items WHERE submission_id = ?1 ORDER BY ordinal",
            )
            .map_err(|err| StateError::from_sqlite("queue_submission_by_id: prepare", err))?;
        let rows = statement
            .query_map(params![submission_id], |row| {
                Ok(QueueSubmissionItemRow {
                    submission_id: row.get(0)?,
                    ordinal: row.get(1)?,
                    work_item: row.get(2)?,
                    issue_number: row.get(3)?,
                    issue_revision: row.get(4)?,
                    status: row.get(5)?,
                    reason: row.get(6)?,
                    message: row.get(7)?,
                    instance_id: row.get(8)?,
                    grant_id: row.get(9)?,
                })
            })
            .map_err(|err| StateError::from_sqlite("queue_submission_by_id: query_map", err))?;
        let mut items = Vec::new();
        for row in rows {
            items.push(
                row.map_err(|err| StateError::from_sqlite("queue_submission_by_id: row", err))?,
            );
        }
        Ok(Some((submission, items)))
    }

    /// Every unique work-ownership row, oldest first (read-only; the
    /// ownership readback AC6 and the focused tests read this).
    pub fn queue_ownership_rows(&self) -> Result<Vec<QueueOwnershipRow>, StateError> {
        let conn = self.lock("queue_ownership_rows")?;
        let mut statement = conn
            .prepare(
                "SELECT repository, issue_number, work_item, submission_id, instance_id,
                        created_at
                   FROM queue_ownership ORDER BY created_at, repository, issue_number",
            )
            .map_err(|err| StateError::from_sqlite("queue_ownership_rows: prepare", err))?;
        let rows = statement
            .query_map([], |row| {
                Ok(QueueOwnershipRow {
                    repository: row.get(0)?,
                    issue_number: row.get(1)?,
                    work_item: row.get(2)?,
                    submission_id: row.get(3)?,
                    instance_id: row.get(4)?,
                    created_at: row.get(5)?,
                })
            })
            .map_err(|err| StateError::from_sqlite("queue_ownership_rows: query_map", err))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(|err| StateError::from_sqlite("queue_ownership_rows: row", err))?);
        }
        Ok(out)
    }

    /// Every durable queue-advance row of one submission, oldest delivery
    /// first (issue #96; read-only — the queue readback and the focused tests
    /// read this).
    pub fn queue_advance_rows(
        &self,
        submission_id: &str,
    ) -> Result<Vec<QueueAdvanceRow>, StateError> {
        let conn = self.lock("queue_advance_rows")?;
        queue_advance_rows_locked(&conn, submission_id)
    }

    /// Commit ONE durable queue submission in a single transaction (issue
    /// #85 AC2/AC3). Every state-derived decision — live ownership, grant
    /// status/expiry, scope overlap, concurrency capacity — is re-verified
    /// HERE, under the one state guard, before a row is written: the
    /// submission, its membership items, the admitted run rows and the
    /// unique work-ownership rows commit together or not at all, so a
    /// double click, a retry or a restart can never duplicate an owner or
    /// leave a partially admitted run.
    pub fn submit_queue_run(
        &self,
        plan: &QueueSubmissionPlan,
    ) -> Result<(QueueSubmissionRow, Vec<QueueSubmissionItemRow>), StateError> {
        let outcome = self.submit_queue_run_inner(plan);
        if let Err(err) = &outcome {
            self.poison_on(err);
        }
        outcome
    }

    fn submit_queue_run_inner(
        &self,
        plan: &QueueSubmissionPlan,
    ) -> Result<(QueueSubmissionRow, Vec<QueueSubmissionItemRow>), StateError> {
        self.ensure_writable()?;
        let mut conn = self.lock("submit_queue_run")?;
        let tx = conn
            .transaction()
            .map_err(|err| StateError::from_sqlite("submit_queue_run: begin", err))?;
        let epoch = current_epoch_locked(&tx)?;
        if epoch != plan.state_epoch {
            return Err(state_error(
                "state.epoch_mismatch",
                format!(
                    "submission epoch {} != current epoch {epoch}; an approval dies with its epoch \
                     (render a fresh preview)",
                    plan.state_epoch
                ),
            ));
        }
        let existing: Option<i64> = tx
            .query_row(
                "SELECT 1 FROM queue_submissions WHERE submission_id = ?1",
                params![plan.submission_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|err| StateError::from_sqlite("submit_queue_run: existing", err))?;
        if existing.is_some() {
            return Err(state_error(
                "state.submission_exists",
                format!(
                    "submission {} already exists; the same approval material was already \
                     committed",
                    plan.submission_id
                ),
            ));
        }
        // Live ownership: every owned-status run of this repository, keyed by
        // issue number. An issue already owned here can never gain a second
        // owner in this transaction.
        let owned: BTreeMap<i64, OwnedRunSnapshot> = {
            let mut statement = tx
                .prepare(
                    "SELECT issue_number, instance_id, issue_revision, grant_id, paused, resume_digest
                       FROM instances
                      WHERE repository = ?1
                        AND status IN ('new', 'running', 'paused', 'human_queue', 'blocked')",
                )
                .map_err(|err| StateError::from_sqlite("submit_queue_run: owned", err))?;
            let rows = statement
                .query_map(params![plan.repository], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        OwnedRunSnapshot {
                            instance_id: row.get(1)?,
                            issue_revision: row.get(2)?,
                            grant_id: row.get(3)?,
                            paused: row.get::<_, i64>(4)? != 0,
                            resume_digest: row.get(5)?,
                        },
                    ))
                })
                .map_err(|err| StateError::from_sqlite("submit_queue_run: owned query", err))?;
            let mut owned = BTreeMap::new();
            for row in rows {
                let (issue_number, run) =
                    row.map_err(|err| StateError::from_sqlite("submit_queue_run: owned row", err))?;
                owned.entry(issue_number).or_insert(run);
            }
            owned
        };
        // Counted lanes: the fan-out capacity axes plus the same-repository
        // declared scopes for the overlap re-check.
        let counted_global: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM instances
                  WHERE status IN ('new', 'running', 'human_queue', 'blocked')",
                [],
                |row| row.get(0),
            )
            .map_err(|err| StateError::from_sqlite("submit_queue_run: counted", err))?;
        let repository_lanes: Vec<(i64, String)> = {
            let mut statement = tx
                .prepare(
                    "SELECT issue_number, scope FROM instances
                      WHERE repository = ?1
                        AND status IN ('new', 'running', 'human_queue', 'blocked')",
                )
                .map_err(|err| StateError::from_sqlite("submit_queue_run: lanes", err))?;
            let rows = statement
                .query_map(params![plan.repository], |row| {
                    Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
                })
                .map_err(|err| StateError::from_sqlite("submit_queue_run: lanes query", err))?;
            let mut lanes = Vec::new();
            for row in rows {
                lanes.push(
                    row.map_err(|err| StateError::from_sqlite("submit_queue_run: lanes row", err))?,
                );
            }
            lanes
        };
        let counted_repository = repository_lanes.len() as i64;
        let mut slots = FanoutSlots {
            caps: &plan.admission_caps,
            counted_global,
            counted_repository,
            harness_lanes: plan.harness_lanes,
            admitted_global: 0,
            admitted_repository: 0,
            admitted_harness: 0,
        };
        let mut items: Vec<QueueSubmissionItemRow> = Vec::new();
        for item in &plan.items {
            // Decide the item under the guard. The presented verdict is a
            // fail-closed hint; ownership, grant status/expiry, overlap and
            // capacity are re-derived from live rows by the shared admission
            // helper (the SAME code path the #96 advance admits through).
            let decision: AdmissionDecision = match &item.verdict {
                SubmissionVerdict::Refused { code, message } => AdmissionDecision::Refused {
                    code,
                    message: message.clone(),
                },
                SubmissionVerdict::Waiting { code, message } => AdmissionDecision::Waiting {
                    code,
                    message: message.clone(),
                },
                SubmissionVerdict::Approved => {
                    let admission = QueueAdmission {
                        state: self,
                        repository: &plan.repository,
                        submission_id: &plan.submission_id,
                        epoch,
                        at: &plan.at,
                        workflow_id: &plan.workflow_id,
                        workflow_hash: &plan.workflow_hash,
                        ownership: &owned,
                        repository_lanes: &repository_lanes,
                    };
                    let candidate = QueueAdmissionItem {
                        issue_number: item.issue_number,
                        issue_revision: &item.issue_revision,
                        work_item: &item.work_item,
                        grant_id: item.grant_id.as_deref(),
                        resume_digest: item.resume_digest.as_deref(),
                    };
                    admit_queue_item_in_tx(&tx, &admission, &candidate, &mut slots)?
                }
            };
            let (status, reason, message, instance_id) = match decision {
                AdmissionDecision::Admitted { instance_id } => {
                    ("admitted".to_string(), None, None, Some(instance_id))
                }
                AdmissionDecision::Waiting { code, message } => (
                    "waiting".to_string(),
                    Some(code.to_string()),
                    Some(message),
                    None,
                ),
                AdmissionDecision::Refused { code, message } => (
                    "refused".to_string(),
                    Some(code.to_string()),
                    Some(message),
                    None,
                ),
            };
            items.push(QueueSubmissionItemRow {
                submission_id: plan.submission_id.clone(),
                ordinal: item.ordinal,
                work_item: item.work_item.clone(),
                issue_number: item.issue_number,
                issue_revision: item.issue_revision.clone(),
                status,
                reason,
                message,
                instance_id,
                // The presented grant binding persists with the item so the
                // #96 advance re-verifies the SAME approval under the guard.
                grant_id: item.grant_id.clone().unwrap_or_default(),
            });
        }
        tx.execute(
            "INSERT INTO queue_submissions (submission_id, repository, state_epoch, digest,
                    role_key, role_revision, workflow_id, workflow_hash, boundary_phase,
                    integration_branch, completion_branch, boundary_caps, request_line,
                    caps_global, caps_per_repository, caps_per_harness, harness_lanes, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17,
                     ?18)",
            params![
                plan.submission_id,
                plan.repository,
                plan.state_epoch,
                plan.digest,
                plan.role_key,
                plan.role_revision,
                plan.workflow_id,
                plan.workflow_hash,
                plan.boundary_phase,
                plan.integration_branch,
                plan.completion_branch,
                canonical_text(&Val::Arr(
                    plan.boundary_caps.iter().map(|cap| string(cap)).collect()
                )),
                plan.request_line,
                plan.admission_caps.global as i64,
                plan.admission_caps.per_repository as i64,
                plan.admission_caps.per_harness as i64,
                plan.harness_lanes,
                plan.at
            ],
        )
        .map_err(|err| StateError::from_sqlite("submit_queue_run: submission", err))?;
        for item in &items {
            tx.execute(
                "INSERT INTO queue_submission_items (submission_id, ordinal, work_item,
                        issue_number, issue_revision, status, reason, message, instance_id,
                        grant_id)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    item.submission_id,
                    item.ordinal,
                    item.work_item,
                    item.issue_number,
                    item.issue_revision,
                    item.status,
                    item.reason,
                    item.message,
                    item.instance_id,
                    item.grant_id
                ],
            )
            .map_err(|err| StateError::from_sqlite("submit_queue_run: item", err))?;
        }
        // Issue #95: the explicit supervision authorization commits in the
        // SAME transaction as the runs it names. Absent = supervision stays
        // disabled for every admitted run (the default), and an unapproved
        // plan can never be supervised later because the authorization binds
        // the approved digest committed right here.
        if let Some(supervision) = &plan.supervision {
            for item in &items {
                let Some(instance_id) = item.instance_id.as_deref() else {
                    continue;
                };
                arm_supervision_in_tx(
                    &tx,
                    instance_id,
                    supervision,
                    &plan.digest,
                    &plan.boundary_phase,
                    plan.state_epoch,
                    &plan.at,
                )
                .map_err(|err| {
                    state_error(
                        err.code,
                        format!("supervision authorization refused: {}", err.message),
                    )
                })?;
            }
        }
        tx.commit()
            .map_err(|err| StateError::from_sqlite("submit_queue_run: commit", err))?;
        let submission = QueueSubmissionRow {
            submission_id: plan.submission_id.clone(),
            repository: plan.repository.clone(),
            state_epoch: plan.state_epoch,
            digest: plan.digest.clone(),
            role_key: plan.role_key.clone(),
            role_revision: plan.role_revision.clone(),
            workflow_id: plan.workflow_id.clone(),
            workflow_hash: plan.workflow_hash.clone(),
            boundary_phase: plan.boundary_phase.clone(),
            integration_branch: plan.integration_branch.clone(),
            completion_branch: plan.completion_branch.clone(),
            boundary_caps: canonical_text(&Val::Arr(
                plan.boundary_caps.iter().map(|cap| string(cap)).collect(),
            )),
            request_line: plan.request_line.clone(),
            caps_global: plan.admission_caps.global as i64,
            caps_per_repository: plan.admission_caps.per_repository as i64,
            caps_per_harness: plan.admission_caps.per_harness as i64,
            harness_lanes: plan.harness_lanes,
            created_at: plan.at.clone(),
        };
        Ok((submission, items))
    }

    // ---------------------------------------------------------------------
    // Control-plane mutation state (issue #8): durable review evidence,
    // recorded first-write approvals, salvage journal records
    // ---------------------------------------------------------------------

    /// Durably record a review-evidence row bound to an exact feature head,
    /// integration base, workflow hash, and policy hash. Every binding is
    /// shape-checked here; semantic freshness is revalidated before the
    /// merge (evidence dies with its epoch: rows never carry their epoch,
    /// so an epoch rotation makes every row stale — see
    /// [`State::rotate_epoch`]).
    #[allow(clippy::too_many_arguments)]
    pub fn record_evidence(
        &self,
        instance_id: &str,
        repository: &str,
        feature_head: &str,
        integration_base: &str,
        workflow_hash: &str,
        policy_hash: &str,
        verdict: &str,
        reviewer: &str,
        checks: &Val,
    ) -> Result<EvidenceRow, StateError> {
        use crate::formats::{is_hex40, is_hex64, is_repository_identity, is_slug};
        if !matches!(verdict, "pass" | "fail") {
            return Err(state_error(
                "state.evidence_invalid",
                format!("evidence verdict {verdict:?} outside {{pass, fail}}"),
            ));
        }
        if !is_slug(instance_id) || !is_repository_identity(repository) {
            return Err(state_error(
                "state.evidence_invalid",
                "evidence instance/repository binding invalid",
            ));
        }
        if !is_hex40(feature_head) || !is_hex40(integration_base) {
            return Err(state_error(
                "state.evidence_invalid",
                "evidence head/base bindings must be exact 40-hex SHAs",
            ));
        }
        if !is_hex64(workflow_hash) || !is_hex64(policy_hash) {
            return Err(state_error(
                "state.evidence_invalid",
                "evidence workflow/policy hashes must be 64-hex",
            ));
        }
        if reviewer.is_empty() || reviewer.len() > 64 {
            return Err(state_error(
                "state.evidence_invalid",
                "evidence reviewer identity must be a non-empty identifier <= 64 chars",
            ));
        }
        let checks_ok = matches!(checks, Val::Arr(items) if !items.is_empty() && items.iter().all(|item| matches!(item, Val::Obj(_))
            && matches!(item.get("name"), Some(Val::Str(name)) if !name.is_empty())
            && matches!(item.get("status"), Some(Val::Str(status)) if matches!(status.as_str(), "passed" | "failed" | "pending"))));
        if !checks_ok {
            return Err(state_error(
                "state.evidence_invalid",
                "evidence checks must be a non-empty list of {{name, status(passed|failed|pending)}}",
            ));
        }
        let checks_line = canonical_text(checks);
        let created_at = time::rfc3339_now();
        let seed = canonical_text(&object(vec![
            ("instance_id", string(instance_id)),
            ("feature_head", string(feature_head)),
            ("integration_base", string(integration_base)),
            ("workflow_hash", string(workflow_hash)),
            ("policy_hash", string(policy_hash)),
            ("verdict", string(verdict)),
            ("reviewer", string(reviewer)),
            ("created_at", string(&created_at)),
        ]));
        let evidence_id = format!("ev_{}", &sha256_hex(seed.as_bytes())[..16]);
        let conn = self.lock("record_evidence")?;
        conn.execute(
            "INSERT INTO evidence (evidence_id, instance_id, repository, feature_head,
                                   integration_base, workflow_hash, policy_hash,
                                   verdict, reviewer, checks, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                evidence_id,
                instance_id,
                repository,
                feature_head,
                integration_base,
                workflow_hash,
                policy_hash,
                verdict,
                reviewer,
                checks_line,
                created_at
            ],
        )
        .map_err(|err| {
            if err.to_string().contains("UNIQUE") {
                state_error(
                    "state.evidence_exists",
                    format!("evidence {evidence_id} already exists"),
                )
            } else {
                StateError::from_sqlite("record_evidence: insert", err)
            }
        })?;
        Ok(EvidenceRow {
            evidence_id,
            instance_id: instance_id.to_string(),
            repository: repository.to_string(),
            feature_head: feature_head.to_string(),
            integration_base: integration_base.to_string(),
            workflow_hash: workflow_hash.to_string(),
            policy_hash: policy_hash.to_string(),
            verdict: verdict.to_string(),
            reviewer: reviewer.to_string(),
            checks: checks_line,
            created_at,
        })
    }

    /// One evidence row by id.
    pub fn evidence_by_id(&self, evidence_id: &str) -> Result<Option<EvidenceRow>, StateError> {
        let conn = self.lock("evidence_by_id")?;
        conn.query_row(
            "SELECT evidence_id, instance_id, repository, feature_head, integration_base,
                    workflow_hash, policy_hash, verdict, reviewer, checks, created_at
               FROM evidence WHERE evidence_id = ?1",
            params![evidence_id],
            evidence_row_from,
        )
        .optional()
        .map_err(|err| StateError::from_sqlite("evidence_by_id: query", err))
    }

    /// Latest-first evidence rows for one instance (the merge gate reads the
    /// most recent record and revalidates every binding live).
    pub fn evidence_for_instance(&self, instance_id: &str) -> Result<Vec<EvidenceRow>, StateError> {
        let conn = self.lock("evidence_for_instance")?;
        let mut statement = conn
            .prepare(
                "SELECT evidence_id, instance_id, repository, feature_head, integration_base,
                        workflow_hash, policy_hash, verdict, reviewer, checks, created_at
                   FROM evidence WHERE instance_id = ?1 ORDER BY created_at DESC, evidence_id DESC",
            )
            .map_err(|err| StateError::from_sqlite("evidence_for_instance: prepare", err))?;
        let rows = statement
            .query_map(params![instance_id], evidence_row_from)
            .map_err(|err| StateError::from_sqlite("evidence_for_instance: query", err))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(
                row.map_err(|err| StateError::from_sqlite("evidence_for_instance: row", err))?,
            );
        }
        Ok(out)
    }

    /// Bounded, deterministic board read (issue #83): run rows in
    /// `(repository, issue_number, instance_id)` order strictly after the
    /// exclusive `after` bound (`None` reads from the start), at most
    /// `limit` rows, each joined with its most recent evidence record and
    /// at most `per_row_cap` newest evidence ids.
    ///
    /// The read is a pure projection over recorded rows: it never writes,
    /// never scans an unbounded table, and the ordering key makes pages
    /// stable across restarts, inserts, and out-of-order attempts. The
    /// cursor is an ordering key, not a pointer: rows deleted between pages
    /// simply leave no gap. Legacy rows that predate the m0002 bindings are
    /// read with empty/null fields coalesced so a missing source is reported
    /// rather than failing the read.
    pub fn board_page_rows(
        &self,
        after: Option<(&str, i64, &str)>,
        limit: usize,
        per_row_cap: usize,
    ) -> Result<Vec<BoardRunRow>, StateError> {
        let conn = self.lock("board_page_rows")?;
        // The sentinel bound `("", -1, "")` is strictly below every real
        // row: repository is never negative-ordered below "" and any issue
        // number is >= 0 > -1 (one statement serves both the first page and
        // every cursor page).
        let (after_repository, after_issue, after_instance) = after.unwrap_or(("", -1, ""));
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let mut statement = conn
            .prepare(
                "SELECT instance_id, COALESCE(repository, ''), workflow_id, workflow_hash,
                        policy_hash, grant_id, issue_number, issue_revision, phase, scope,
                        caps, current_node, normal_rounds, recovery_rounds, human_queue,
                        terminal_blockers, paused, resume_digest, state_epoch, status,
                        created_at, COALESCE(updated_at, '')
                   FROM instances
                  WHERE (COALESCE(repository, ''), issue_number, instance_id) > (?1, ?2, ?3)
                  ORDER BY COALESCE(repository, ''), issue_number, instance_id
                  LIMIT ?4",
            )
            .map_err(|err| StateError::from_sqlite("board_page_rows: prepare", err))?;
        let rows = statement
            .query_map(
                params![after_repository, after_issue, after_instance, limit],
                instance_row_from,
            )
            .map_err(|err| StateError::from_sqlite("board_page_rows: query", err))?;
        let mut runs = Vec::new();
        for row in rows {
            runs.push(row.map_err(|err| StateError::from_sqlite("board_page_rows: row", err))?);
        }
        if runs.is_empty() {
            return Ok(Vec::new());
        }

        // One bounded evidence batch for the whole page (never one query per
        // row): newest-first row numbers plus a per-instance total, capped
        // per row.
        let placeholders = std::iter::repeat_n("?", runs.len())
            .collect::<Vec<_>>()
            .join(",");
        let batch_sql = format!(
            "SELECT evidence_id, instance_id, repository, feature_head, integration_base,
                    workflow_hash, policy_hash, verdict, reviewer, checks, created_at,
                    ROW_NUMBER() OVER (PARTITION BY instance_id
                                       ORDER BY created_at DESC, evidence_id DESC) AS rn,
                    COUNT(*) OVER (PARTITION BY instance_id) AS total
               FROM evidence WHERE instance_id IN ({placeholders})"
        );
        let mut statement = conn
            .prepare(&batch_sql)
            .map_err(|err| StateError::from_sqlite("board_page_rows: evidence prepare", err))?;
        let ids: Vec<&str> = runs.iter().map(|run| run.instance_id.as_str()).collect();
        let rows = statement
            .query_map(rusqlite::params_from_iter(ids), |row| {
                let evidence = evidence_row_from(row)?;
                Ok((evidence, row.get::<_, i64>(11)?, row.get::<_, i64>(12)?))
            })
            .map_err(|err| StateError::from_sqlite("board_page_rows: evidence query", err))?;
        let mut newest: std::collections::BTreeMap<String, EvidenceRow> =
            std::collections::BTreeMap::new();
        let mut ids_by_run: std::collections::BTreeMap<String, Vec<String>> =
            std::collections::BTreeMap::new();
        let mut totals: std::collections::BTreeMap<String, i64> = std::collections::BTreeMap::new();
        for row in rows {
            let (evidence, rank, total) =
                row.map_err(|err| StateError::from_sqlite("board_page_rows: evidence row", err))?;
            let instance_id = evidence.instance_id.clone();
            totals.insert(instance_id.clone(), total);
            if rank == 1 {
                newest.insert(instance_id.clone(), evidence.clone());
            }
            if rank <= i64::try_from(per_row_cap).unwrap_or(i64::MAX) {
                ids_by_run
                    .entry(instance_id)
                    .or_default()
                    .push(evidence.evidence_id);
            }
        }

        Ok(runs
            .into_iter()
            .map(|run| BoardRunRow {
                evidence_newest: newest.remove(&run.instance_id),
                evidence_ids: ids_by_run.remove(&run.instance_id).unwrap_or_default(),
                evidence_total: totals.remove(&run.instance_id).unwrap_or(0),
                run,
            })
            .collect())
    }

    /// Record the separate explicit human approval required before the
    /// first real external write canary (issue #8 AC10; the canary itself
    /// is never run by this slice). Refused when a newer recorded approval
    /// already exists for the scope (approvals are monotonic — an older
    /// digest must never overwrite a newer one).
    pub fn record_approval(
        &self,
        scope: &str,
        digest: &str,
        interactive: bool,
    ) -> Result<ApprovalRow, StateError> {
        use crate::formats::{is_hex64, is_slug};
        if !is_slug(scope) || scope != "first-write-canary" {
            return Err(state_error(
                "state.approval_invalid",
                format!(
                    "approval scope {scope:?} is outside the closed {{first-write-canary}} set"
                ),
            ));
        }
        if !is_hex64(digest) {
            return Err(state_error(
                "state.approval_invalid",
                "approval digest must be 64-hex",
            ));
        }
        let recorded_at = time::rfc3339_now();
        let seed = canonical_text(&object(vec![
            ("scope", string(scope)),
            ("digest", string(digest)),
            ("recorded_at", string(&recorded_at)),
        ]));
        let approval_id = format!("ap_{}", &sha256_hex(seed.as_bytes())[..16]);
        let conn = self.lock("record_approval")?;
        let newest: Option<String> = conn
            .query_row(
                "SELECT recorded_at FROM approvals WHERE scope = ?1 AND revoked_at IS NULL
                  ORDER BY recorded_at DESC LIMIT 1",
                params![scope],
                |row| row.get(0),
            )
            .optional()
            .map_err(|err| StateError::from_sqlite("record_approval: read", err))?;
        if let Some(prior) = newest
            && prior > recorded_at
        {
            return Err(state_error(
                "state.approval_stale",
                "a newer recorded approval exists for the scope; refusing the stale record",
            ));
        }
        conn.execute(
            "INSERT INTO approvals (approval_id, scope, digest, interactive, recorded_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![approval_id, scope, digest, interactive as i64, recorded_at],
        )
        .map_err(|err| StateError::from_sqlite("record_approval: insert", err))?;
        Ok(ApprovalRow {
            approval_id,
            scope: scope.to_string(),
            digest: digest.to_string(),
            interactive,
            recorded_at,
        })
    }

    /// The newest un-revoked recorded approval for a scope, if any.
    pub fn approval_for_scope(&self, scope: &str) -> Result<Option<ApprovalRow>, StateError> {
        let conn = self.lock("approval_for_scope")?;
        conn.query_row(
            "SELECT approval_id, scope, digest, interactive, recorded_at
               FROM approvals WHERE scope = ?1 AND revoked_at IS NULL
              ORDER BY recorded_at DESC LIMIT 1",
            params![scope],
            |row| {
                let interactive: i64 = row.get(3)?;
                Ok(ApprovalRow {
                    approval_id: row.get(0)?,
                    scope: row.get(1)?,
                    digest: row.get(2)?,
                    interactive: interactive != 0,
                    recorded_at: row.get(4)?,
                })
            },
        )
        .optional()
        .map_err(|err| StateError::from_sqlite("approval_for_scope: query", err))
    }

    /// Append a `salvage.cleanup` audit record capturing the required
    /// salvage evidence of a completed worktree/branch cleanup deletion
    /// (issue #8 AC8: cleanup preserves required salvage evidence; the
    /// deletion intent itself is journaled before the effect as
    /// `mutate.cleanup`, and this post-deletion evidence record completes
    /// the audit pair).
    pub fn journal_salvage(&self, target: &str, instance_id: &str) -> Result<AuditRow, StateError> {
        let outcome = self.journal_salvage_inner(target, instance_id);
        if let Err(err) = &outcome {
            self.poison_on(err);
        }
        outcome
    }

    fn journal_salvage_inner(
        &self,
        target: &str,
        instance_id: &str,
    ) -> Result<AuditRow, StateError> {
        self.ensure_writable()?;
        let mut conn = self.lock("journal_salvage")?;
        let tx = conn
            .transaction()
            .map_err(|err| StateError::from_sqlite("journal_salvage: begin", err))?;
        let mut key = format!("ik_salvage-{instance_id}");
        key.truncate(64);
        let audit = self.append_audit_locked(&tx, "salvage.cleanup", target, &key, None, None)?;
        tx.commit()
            .map_err(|err| StateError::from_sqlite("journal_salvage: commit", err))?;
        Ok(audit)
    }

    // ---------------------------------------------------------------------
    // Leases, schedules, instances
    // ---------------------------------------------------------------------

    /// Record the daemon's own lease row (informational; the flock is the
    /// authority). Overwrites any stale row from a crashed daemon.
    pub fn put_daemon_lease(&self, pid: u32, started_at: &str) -> Result<(), StateError> {
        let conn = self.lock("put_daemon_lease")?;
        conn.execute(
            "INSERT INTO leases (lease_id, holder, purpose, scope, state_epoch, created_at)
             VALUES ('daemon', ?1, 'single-writer daemon lease', 'local', ?2, ?3)
             ON CONFLICT(lease_id) DO UPDATE SET
               holder = excluded.holder,
               state_epoch = excluded.state_epoch,
               created_at = excluded.created_at,
               expires_at = NULL",
            params![
                format!("pid {pid}"),
                current_epoch_locked(&conn)?,
                started_at
            ],
        )
        .map_err(|err| StateError::from_sqlite("put_daemon_lease", err))?;
        Ok(())
    }

    /// Remove the daemon's lease row on graceful exit.
    pub fn drop_daemon_lease(&self) -> Result<(), StateError> {
        let conn = self.lock("drop_daemon_lease")?;
        conn.execute("DELETE FROM leases WHERE lease_id = 'daemon'", [])
            .map_err(|err| StateError::from_sqlite("drop_daemon_lease", err))?;
        Ok(())
    }

    /// Schedules (lifecycle rows; scheduling semantics land in the
    /// lifecycle slice). Returns every schedule row ordered by id.
    pub fn list_schedules(&self) -> Result<Vec<Val>, StateError> {
        let rows = self.list_schedule_rows()?;
        Ok(rows.iter().map(schedule_val).collect())
    }

    /// Every schedule row (ordered by id) for the lifecycle evaluator.
    pub fn list_schedule_rows(&self) -> Result<Vec<ScheduleRow>, StateError> {
        let conn = self.lock("list_schedule_rows")?;
        let mut statement = conn
            .prepare(
                "SELECT schedule_id, state_epoch, enabled, next_run_at, created_at, doc, updated_at
                   FROM schedules ORDER BY schedule_id",
            )
            .map_err(|err| StateError::from_sqlite("list_schedule_rows: prepare", err))?;
        let rows = statement
            .query_map([], schedule_row_from)
            .map_err(|err| StateError::from_sqlite("list_schedule_rows: query", err))?;
        let mut out = Vec::new();
        for row in rows {
            let row = row.map_err(|err| StateError::from_sqlite("list_schedule_rows: row", err))?;
            out.push(row);
        }
        Ok(out)
    }

    /// One schedule row by id.
    pub fn schedule_by_id(&self, schedule_id: &str) -> Result<Option<ScheduleRow>, StateError> {
        let conn = self.lock("schedule_by_id")?;
        conn.query_row(
            "SELECT schedule_id, state_epoch, enabled, next_run_at, created_at, doc, updated_at
               FROM schedules WHERE schedule_id = ?1",
            params![schedule_id],
            schedule_row_from,
        )
        .optional()
        .map_err(|err| StateError::from_sqlite("schedule_by_id: query", err))
    }

    /// Upsert a schedule row from a canonical `hf-schedule/v1` document
    /// (schema-validated by the caller through `crate::schema::validate_doc`).
    /// Create (or a re-arm update) resets the cadence state: enabled with a
    /// null `next_run_at` so the next evaluation is due immediately (one
    /// fresh evaluation, never a replay of missed windows).
    pub fn upsert_schedule(&self, doc: &Val) -> Result<ScheduleRow, StateError> {
        let schedule_id = doc
            .get("schedule_id")
            .and_then(Val::as_str)
            .ok_or_else(|| state_error("state.schedule_invalid", "schedule missing schedule_id"))?
            .to_string();
        let doc_text = canonical_text(doc);
        let now = time::rfc3339_now();
        {
            let conn = self.lock("upsert_schedule")?;
            let epoch = current_epoch_locked(&conn)?;
            conn.execute(
                "INSERT INTO schedules (schedule_id, state_epoch, enabled, next_run_at,
                                        created_at, doc, updated_at)
                 VALUES (?1, ?2, 1, NULL, ?3, ?4, ?3)
                 ON CONFLICT(schedule_id) DO UPDATE SET
                   doc = excluded.doc, updated_at = excluded.updated_at,
                   enabled = 1, next_run_at = NULL",
                params![schedule_id, epoch, now, doc_text],
            )
            .map_err(|err| StateError::from_sqlite("upsert_schedule", err))?;
        }
        let row = self
            .schedule_by_id(&schedule_id)?
            .expect("upserted schedule row");
        Ok(row)
    }

    /// Set the durable pause state of a schedule (`enabled` flag; false is
    /// paused/disabled). Only an explicit human `resume` lifts a pause; no
    /// evaluation path ever enables a schedule. Resuming resets the window
    /// (next_run_at = NULL) so the next evaluation is one fresh run.
    pub fn set_schedule_enabled(
        &self,
        schedule_id: &str,
        enabled: bool,
        at: &str,
    ) -> Result<ScheduleRow, StateError> {
        let (next_run_at, updated_at): (Option<String>, String) = {
            let conn = self.lock("set_schedule_enabled")?;
            if enabled {
                (None, at.to_string())
            } else {
                (
                    conn.query_row(
                        "SELECT next_run_at FROM schedules WHERE schedule_id = ?1",
                        params![schedule_id],
                        |row| row.get(0),
                    )
                    .optional()
                    .map_err(|err| StateError::from_sqlite("set_schedule_enabled: read", err))?
                    .flatten(),
                    at.to_string(),
                )
            }
        };
        let affected = {
            let conn = self.lock("set_schedule_enabled")?;
            conn.execute(
                "UPDATE schedules SET enabled = ?2, next_run_at = ?3, updated_at = ?4
                  WHERE schedule_id = ?1",
                params![schedule_id, enabled as i64, next_run_at, updated_at],
            )
            .map_err(|err| StateError::from_sqlite("set_schedule_enabled: update", err))?
        };
        if affected == 0 {
            return Err(state_error(
                "state.not_found",
                format!("no schedule {schedule_id:?}"),
            ));
        }
        let row = self
            .schedule_by_id(schedule_id)?
            .expect("updated schedule row");
        Ok(row)
    }

    /// Delete a schedule row (daemon-mediated; the deletion intent is
    /// journaled by the caller before this runs).
    pub fn delete_schedule(&self, schedule_id: &str) -> Result<(), StateError> {
        let conn = self.lock("delete_schedule")?;
        let affected = conn
            .execute(
                "DELETE FROM schedules WHERE schedule_id = ?1",
                params![schedule_id],
            )
            .map_err(|err| StateError::from_sqlite("delete_schedule", err))?;
        if affected == 0 {
            return Err(state_error(
                "state.not_found",
                format!("no schedule {schedule_id:?}"),
            ));
        }
        Ok(())
    }

    /// Atomically advance a schedule's evaluation window AND journal the
    /// run (audit row + `schedule.ran` event) in one transaction (issue #9).
    /// The persisted next window is the singleflight guard: a second
    /// evaluation in the same tick sees a future window and skips. A crash
    /// before commit leaves the pre-run state (the window re-fires at most
    /// once more — never a backlog replay).
    pub fn complete_schedule_run(
        &self,
        schedule_id: &str,
        next_run_at: Option<&str>,
        at: &str,
    ) -> Result<AuditRow, StateError> {
        let result = self.complete_schedule_run_inner(schedule_id, next_run_at, at);
        if let Err(err) = &result {
            self.poison_on(err);
        }
        result
    }

    fn complete_schedule_run_inner(
        &self,
        schedule_id: &str,
        next_run_at: Option<&str>,
        at: &str,
    ) -> Result<AuditRow, StateError> {
        self.ensure_writable()?;
        let mut conn = self.lock("complete_schedule_run")?;
        let tx = conn
            .transaction()
            .map_err(|err| StateError::from_sqlite("complete_schedule_run: begin", err))?;
        let affected = tx
            .execute(
                "UPDATE schedules SET next_run_at = ?2, updated_at = ?3 WHERE schedule_id = ?1",
                params![schedule_id, next_run_at, at],
            )
            .map_err(|err| StateError::from_sqlite("complete_schedule_run: update", err))?;
        if affected == 0 {
            return Err(state_error(
                "state.not_found",
                format!("no schedule {schedule_id:?}"),
            ));
        }
        let mut key = format!("ik_sched-{schedule_id}");
        key.truncate(64);
        let audit = self.append_audit_locked(
            &tx,
            "read.schedule.ran",
            &format!("{schedule_id}:ran"),
            &key,
            None,
            None,
        )?;
        let data = object(vec![
            ("schedule_id", string(schedule_id)),
            ("outcome", string("ran")),
            ("next_run_at", next_run_at.map(string).unwrap_or_else(null)),
        ]);
        append_event_locked(&tx, self.retention, "schedule.ran", &data)?;
        tx.commit()
            .map_err(|err| StateError::from_sqlite("complete_schedule_run: commit", err))?;
        Ok(audit)
    }

    /// Atomically pause (disable) a schedule with a journaled reason
    /// (issue #9): an evaluation that refuses — expired schedule, changed
    /// policy/issue binding, unparseable doc — parks the schedule in an
    /// explicit terminal state instead of retrying every tick (no retry
    /// storm). Only an explicit human resume/create re-arms it.
    pub fn pause_schedule_with_reason(
        &self,
        schedule_id: &str,
        reason: &str,
        at: &str,
    ) -> Result<AuditRow, StateError> {
        let result = self.pause_schedule_with_reason_inner(schedule_id, reason, at);
        if let Err(err) = &result {
            self.poison_on(err);
        }
        result
    }

    fn pause_schedule_with_reason_inner(
        &self,
        schedule_id: &str,
        reason: &str,
        at: &str,
    ) -> Result<AuditRow, StateError> {
        self.ensure_writable()?;
        let mut conn = self.lock("pause_schedule_with_reason")?;
        let tx = conn
            .transaction()
            .map_err(|err| StateError::from_sqlite("pause_schedule_with_reason: begin", err))?;
        let affected = tx
            .execute(
                "UPDATE schedules SET enabled = 0, updated_at = ?2 WHERE schedule_id = ?1",
                params![schedule_id, at],
            )
            .map_err(|err| StateError::from_sqlite("pause_schedule_with_reason: update", err))?;
        if affected == 0 {
            return Err(state_error(
                "state.not_found",
                format!("no schedule {schedule_id:?}"),
            ));
        }
        let mut key = format!("ik_sched-{schedule_id}");
        key.truncate(64);
        let audit = self.append_audit_locked(
            &tx,
            "read.schedule.ran",
            &format!("{schedule_id}:{reason}"),
            &key,
            None,
            None,
        )?;
        tx.commit()
            .map_err(|err| StateError::from_sqlite("pause_schedule_with_reason: commit", err))?;
        Ok(audit)
    }

    // ---------------------------------------------------------------------
    // Lane replacement records (issue #73: request-only handoff records)
    // ---------------------------------------------------------------------

    /// Create the one replacement record for a logical lane generation and
    /// append its creation history row in the same transaction. This is a
    /// *request*: it persists durable state only — no spawn, kill, or Git
    /// effect exists on this path. A second record for the same lane
    /// generation is refused with `refusal.replacement.exists`, so
    /// concurrent requests can never create two successor owners. Every
    /// identity binding (session, process, role, worktree, reason) is
    /// mandatory: missing/empty values refuse here too — never an inferred
    /// empty lane.
    #[allow(clippy::too_many_arguments)]
    pub fn request_lane_replacement(
        &self,
        lane_id: &str,
        generation: i64,
        source_session: &str,
        source_process: &str,
        role: &str,
        worktree: &str,
        reason: &str,
        profile: Option<(&str, &str)>,
        at: &str,
    ) -> Result<LaneReplacementRow, StateError> {
        let outcome = self.request_lane_replacement_inner(
            lane_id,
            generation,
            source_session,
            source_process,
            role,
            worktree,
            reason,
            profile,
            at,
        );
        if let Err(err) = &outcome {
            self.poison_on(err);
        }
        outcome
    }

    #[allow(clippy::too_many_arguments)]
    fn request_lane_replacement_inner(
        &self,
        lane_id: &str,
        generation: i64,
        source_session: &str,
        source_process: &str,
        role: &str,
        worktree: &str,
        reason: &str,
        profile: Option<(&str, &str)>,
        at: &str,
    ) -> Result<LaneReplacementRow, StateError> {
        for (field, value) in [
            ("lane_id", lane_id),
            ("source_session", source_session),
            ("source_process", source_process),
            ("role", role),
            ("worktree", worktree),
            ("reason", reason),
        ] {
            if value.is_empty() {
                return Err(state_error(
                    "state.replacement_invalid",
                    format!("replacement {field} must be non-empty (refuse, never infer)"),
                ));
            }
        }
        if generation < 1 {
            return Err(state_error(
                "state.replacement_invalid",
                "replacement generation must be >= 1",
            ));
        }
        if !LANE_REPLACEMENT_ROLES.contains(&role) {
            return Err(state_error(
                "state.replacement_invalid",
                format!("role {role:?} is outside the closed role set"),
            ));
        }
        // Issue #77: a bound plan carries the canonical target-profile
        // document and the explicit revision it was reviewed under; the
        // durable record is the authority the whole handoff is fenced on.
        if let Some((text, revision)) = profile
            && (text.is_empty()
                || !text.starts_with('{')
                || text.len() > PROFILE_BINDING_MAX_BYTES
                || !crate::formats::is_hex64(revision))
        {
            return Err(state_error(
                "state.replacement_invalid",
                "a bound replacement profile must be canonical hf-profile-binding/v1 \
                 text (bounded) and a 64-hex revision",
            ));
        }
        let replacement_id = replacement_id_for(lane_id, generation);
        self.ensure_writable()?;
        {
            let mut conn = self.lock("request_lane_replacement")?;
            let tx = conn
                .transaction()
                .map_err(|err| StateError::from_sqlite("request_lane_replacement: begin", err))?;
            let existing: Option<(String, String, String)> = tx
                .query_row(
                    "SELECT replacement_id, phase, outcome FROM lane_replacements
                      WHERE lane_id = ?1 AND generation = ?2",
                    params![lane_id, generation],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()
                .map_err(|err| StateError::from_sqlite("request_lane_replacement: lookup", err))?;
            if let Some((existing_id, phase, outcome)) = existing {
                return Err(state_error(
                    replacement_code::EXISTS,
                    format!(
                        "lane {lane_id:?} generation {generation} already has replacement \
                         {existing_id} ({phase}/{outcome}); a second successor owner cannot be created"
                    ),
                ));
            }
            // Quiescing fence (issue #74): while a pending replacement for
            // this lane sits inside the handoff window (the record has been
            // advanced to `quiescing` or `checkpointed`), new replacement
            // requests for the lane are fenced — a lane cannot fork into a
            // second successor slot mid-handoff. The fence lifts when the
            // handoff resolves (retired and beyond) or is cancelled/held.
            let fenced: Option<(String, String)> = tx
                .query_row(
                    "SELECT replacement_id, phase FROM lane_replacements
                      WHERE lane_id = ?1 AND outcome = 'pending'
                            AND phase IN ('quiescing', 'checkpointed')
                      LIMIT 1",
                    params![lane_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(|err| StateError::from_sqlite("request_lane_replacement: fence", err))?;
            if let Some((holder, phase)) = fenced {
                return Err(state_error(
                    replacement_code::FENCED,
                    format!(
                        "lane {lane_id:?} is inside the quiescing window: replacement {holder} \
                         is at {phase:?}; new replacement requests for this lane are fenced \
                         until the handoff resolves or is cancelled"
                    ),
                ));
            }
            tx.execute(
                "INSERT INTO lane_replacements (replacement_id, lane_id, generation,
                    successor_generation, phase, outcome, outcome_reason, source_session,
                    source_process, role, worktree, reason, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, 'requested', 'pending', '', ?5, ?6, ?7, ?8, ?9, ?10, ?10)",
                params![
                    replacement_id,
                    lane_id,
                    generation,
                    generation + 1,
                    source_session,
                    source_process,
                    role,
                    worktree,
                    reason,
                    at
                ],
            )
            .map_err(|err| StateError::from_sqlite("request_lane_replacement: insert", err))?;
            if let Some((text, revision)) = profile {
                tx.execute(
                    "INSERT INTO lane_replacement_profiles (replacement_id, profile, revision,
                        created_at)
                     VALUES (?1, ?2, ?3, ?4)",
                    params![replacement_id, text, revision, at],
                )
                .map_err(|err| {
                    StateError::from_sqlite("request_lane_replacement: profile insert", err)
                })?;
            }
            append_lane_replacement_event(
                &tx,
                &replacement_id,
                None,
                "requested",
                None,
                "pending",
                reason,
                at,
            )?;
            tx.commit()
                .map_err(|err| StateError::from_sqlite("request_lane_replacement: commit", err))?;
        }
        self.lane_replacement_by_id(&replacement_id)?
            .ok_or_else(|| state_error("state.not_found", "replacement vanished after insert"))
    }

    /// Advance a replacement to the phase that legally follows
    /// `expected_phase` (transactional compare-and-set: the update matches
    /// only when the record still carries exactly the presented phase,
    /// generation, and a `pending` outcome; a missed match is classified
    /// against the fresh row into a typed refusal). Stale generations,
    /// invalid order, held/ambiguous/cancelled records, and replayed
    /// expectations can never advance state.
    pub fn advance_lane_replacement(
        &self,
        replacement_id: &str,
        expected_phase: &str,
        generation: i64,
        at: &str,
    ) -> Result<LaneReplacementRow, StateError> {
        let outcome =
            self.advance_lane_replacement_inner(replacement_id, expected_phase, generation, at);
        if let Err(err) = &outcome {
            self.poison_on(err);
        }
        outcome
    }

    fn advance_lane_replacement_inner(
        &self,
        replacement_id: &str,
        expected_phase: &str,
        generation: i64,
        at: &str,
    ) -> Result<LaneReplacementRow, StateError> {
        self.ensure_writable()?;
        {
            let mut conn = self.lock("advance_lane_replacement")?;
            let tx = conn
                .transaction()
                .map_err(|err| StateError::from_sqlite("advance_lane_replacement: begin", err))?;
            let mut advanced = false;
            if let Some(next_phase) = next_allowed_phase(expected_phase) {
                let affected = tx
                    .execute(
                        "UPDATE lane_replacements
                            SET phase = ?1, updated_at = ?2
                          WHERE replacement_id = ?3 AND phase = ?4 AND generation = ?5
                                AND outcome = 'pending'",
                        params![next_phase, at, replacement_id, expected_phase, generation],
                    )
                    .map_err(|err| {
                        StateError::from_sqlite("advance_lane_replacement: update", err)
                    })?;
                if affected == 1 {
                    append_lane_replacement_event(
                        &tx,
                        replacement_id,
                        Some(expected_phase),
                        next_phase,
                        Some("pending"),
                        "pending",
                        "",
                        at,
                    )?;
                    advanced = true;
                }
            }
            if advanced {
                tx.commit().map_err(|err| {
                    StateError::from_sqlite("advance_lane_replacement: commit", err)
                })?;
            } else {
                let row: Option<LaneReplacementRow> = tx
                    .query_row(
                        "SELECT replacement_id, lane_id, generation, successor_generation,
                                phase, outcome, outcome_reason, source_session, source_process,
                                role, worktree, reason, created_at, updated_at
                           FROM lane_replacements WHERE replacement_id = ?1",
                        params![replacement_id],
                        lane_replacement_row_from,
                    )
                    .optional()
                    .map_err(|err| {
                        StateError::from_sqlite("advance_lane_replacement: classify", err)
                    })?;
                return Err(lane_replacement_transition_refusal(
                    row.as_ref(),
                    replacement_id,
                    expected_phase,
                    generation,
                ));
            }
        }
        self.lane_replacement_by_id(replacement_id)?
            .ok_or_else(|| state_error("state.not_found", "replacement vanished after advance"))
    }

    /// Park a pending replacement in the explicit `held` outcome (the pause
    /// refusal: a held replacement refuses advancement and the state is
    /// durable across restarts). The caller validates/normalizes `reason`.
    pub fn hold_lane_replacement(
        &self,
        replacement_id: &str,
        reason: &str,
        at: &str,
    ) -> Result<LaneReplacementRow, StateError> {
        let outcome = self.hold_lane_replacement_inner(replacement_id, reason, at);
        if let Err(err) = &outcome {
            self.poison_on(err);
        }
        outcome
    }

    fn hold_lane_replacement_inner(
        &self,
        replacement_id: &str,
        reason: &str,
        at: &str,
    ) -> Result<LaneReplacementRow, StateError> {
        self.ensure_writable()?;
        {
            let mut conn = self.lock("hold_lane_replacement")?;
            let tx = conn
                .transaction()
                .map_err(|err| StateError::from_sqlite("hold_lane_replacement: begin", err))?;
            let row: Option<LaneReplacementRow> = tx
                .query_row(
                    "SELECT replacement_id, lane_id, generation, successor_generation,
                            phase, outcome, outcome_reason, source_session, source_process,
                            role, worktree, reason, created_at, updated_at
                       FROM lane_replacements WHERE replacement_id = ?1",
                    params![replacement_id],
                    lane_replacement_row_from,
                )
                .optional()
                .map_err(|err| StateError::from_sqlite("hold_lane_replacement: lookup", err))?;
            let Some(row) = row else {
                return Err(state_error(
                    "state.not_found",
                    format!("no lane replacement {replacement_id:?}"),
                ));
            };
            let affected = if row.outcome == "pending" && row.phase != "adopted" {
                tx.execute(
                    "UPDATE lane_replacements
                        SET outcome = 'held', outcome_reason = ?1, updated_at = ?2
                      WHERE replacement_id = ?3 AND outcome = 'pending' AND phase != 'adopted'",
                    params![reason, at, replacement_id],
                )
                .map_err(|err| StateError::from_sqlite("hold_lane_replacement: update", err))?
            } else {
                0
            };
            if affected == 1 {
                append_lane_replacement_event(
                    &tx,
                    replacement_id,
                    Some(&row.phase),
                    &row.phase,
                    Some("pending"),
                    "held",
                    reason,
                    at,
                )?;
                tx.commit()
                    .map_err(|err| StateError::from_sqlite("hold_lane_replacement: commit", err))?;
            } else {
                return Err(lane_replacement_outcome_refusal(&row, "hold"));
            }
        }
        self.lane_replacement_by_id(replacement_id)?
            .ok_or_else(|| state_error("state.not_found", "replacement vanished after hold"))
    }

    /// Cancel (invalidate) a pending replacement while it is still before
    /// retirement: the original lane is preserved untouched and the pending
    /// replacement becomes permanently unable to advance. Cancellation from
    /// `retired` onward is refused (`refusal.replacement.retired`).
    pub fn cancel_lane_replacement(
        &self,
        replacement_id: &str,
        reason: &str,
        at: &str,
    ) -> Result<LaneReplacementRow, StateError> {
        let outcome = self.cancel_lane_replacement_inner(replacement_id, reason, at);
        if let Err(err) = &outcome {
            self.poison_on(err);
        }
        outcome
    }

    fn cancel_lane_replacement_inner(
        &self,
        replacement_id: &str,
        reason: &str,
        at: &str,
    ) -> Result<LaneReplacementRow, StateError> {
        self.ensure_writable()?;
        {
            let mut conn = self.lock("cancel_lane_replacement")?;
            let tx = conn
                .transaction()
                .map_err(|err| StateError::from_sqlite("cancel_lane_replacement: begin", err))?;
            let row: Option<LaneReplacementRow> = tx
                .query_row(
                    "SELECT replacement_id, lane_id, generation, successor_generation,
                            phase, outcome, outcome_reason, source_session, source_process,
                            role, worktree, reason, created_at, updated_at
                       FROM lane_replacements WHERE replacement_id = ?1",
                    params![replacement_id],
                    lane_replacement_row_from,
                )
                .optional()
                .map_err(|err| StateError::from_sqlite("cancel_lane_replacement: lookup", err))?;
            let Some(row) = row else {
                return Err(state_error(
                    "state.not_found",
                    format!("no lane replacement {replacement_id:?}"),
                ));
            };
            let cancellable = row.outcome != "cancelled" && phase_before_retirement(&row.phase);
            let affected = if cancellable {
                tx.execute(
                    "UPDATE lane_replacements
                        SET outcome = 'cancelled', outcome_reason = ?1, updated_at = ?2
                      WHERE replacement_id = ?3 AND outcome != 'cancelled'
                            AND phase IN ('requested', 'quiescing', 'checkpointed')",
                    params![reason, at, replacement_id],
                )
                .map_err(|err| StateError::from_sqlite("cancel_lane_replacement: update", err))?
            } else {
                0
            };
            if affected == 1 {
                append_lane_replacement_event(
                    &tx,
                    replacement_id,
                    Some(&row.phase),
                    &row.phase,
                    Some(&row.outcome),
                    "cancelled",
                    reason,
                    at,
                )?;
                tx.commit().map_err(|err| {
                    StateError::from_sqlite("cancel_lane_replacement: commit", err)
                })?;
            } else if row.outcome == "cancelled" {
                return Err(state_error(
                    replacement_code::INVALIDATED,
                    format!("replacement {replacement_id} was already cancelled"),
                ));
            } else {
                return Err(state_error(
                    replacement_code::RETIRED,
                    format!(
                        "cancellation after retirement is too late (replacement {replacement_id} \
                         is at {:?})",
                        row.phase
                    ),
                ));
            }
        }
        self.lane_replacement_by_id(replacement_id)?
            .ok_or_else(|| state_error("state.not_found", "replacement vanished after cancel"))
    }

    /// One lane replacement record by id.
    pub fn lane_replacement_by_id(
        &self,
        replacement_id: &str,
    ) -> Result<Option<LaneReplacementRow>, StateError> {
        let conn = self.lock("lane_replacement_by_id")?;
        conn.query_row(
            "SELECT replacement_id, lane_id, generation, successor_generation,
                    phase, outcome, outcome_reason, source_session, source_process,
                    role, worktree, reason, created_at, updated_at
               FROM lane_replacements WHERE replacement_id = ?1",
            params![replacement_id],
            lane_replacement_row_from,
        )
        .optional()
        .map_err(|err| StateError::from_sqlite("lane_replacement_by_id: query", err))
    }

    /// The target-profile binding plan attached to one replacement record
    /// (issue #77): `None` when the replacement was requested unbound.
    pub fn lane_replacement_profile(
        &self,
        replacement_id: &str,
    ) -> Result<Option<LaneReplacementProfileRow>, StateError> {
        let conn = self.lock("lane_replacement_profile")?;
        lane_replacement_profile_of(&conn, replacement_id)
    }

    /// The full transition history of one replacement, oldest first.
    pub fn lane_replacement_events(
        &self,
        replacement_id: &str,
    ) -> Result<Vec<LaneReplacementEventRow>, StateError> {
        let conn = self.lock("lane_replacement_events")?;
        let mut statement = conn
            .prepare(
                "SELECT seq, replacement_id, from_phase, to_phase, from_outcome, to_outcome,
                        reason, at
                   FROM lane_replacement_events WHERE replacement_id = ?1 ORDER BY seq",
            )
            .map_err(|err| StateError::from_sqlite("lane_replacement_events: prepare", err))?;
        let rows = statement
            .query_map(params![replacement_id], |row| {
                Ok(LaneReplacementEventRow {
                    seq: row.get(0)?,
                    replacement_id: row.get(1)?,
                    from_phase: row.get(2)?,
                    to_phase: row.get(3)?,
                    from_outcome: row.get(4)?,
                    to_outcome: row.get(5)?,
                    reason: row.get(6)?,
                    at: row.get(7)?,
                })
            })
            .map_err(|err| StateError::from_sqlite("lane_replacement_events: query", err))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(
                row.map_err(|err| StateError::from_sqlite("lane_replacement_events: row", err))?,
            );
        }
        Ok(out)
    }

    /// Capture one lane checkpoint (issue #74): validate the observed lane
    /// state against the record and the closed observation contract, enforce
    /// the two-observation stability rule, then commit the checkpoint record
    /// AND the record's `quiescing` → `checkpointed` transition in ONE
    /// transaction. Returns the committed checkpoint row, the updated
    /// replacement row, and the generated brief text. The brief is a pure
    /// derivation of the committed row (the durable authority) — the caller
    /// materializes it as an artifact, and restart reconciliation can always
    /// regenerate it byte-for-byte.
    ///
    /// `exclude_key` is the caller's own idempotency key: the in-flight
    /// claim of the capture itself is not an "outstanding operation".
    #[allow(clippy::too_many_arguments)]
    pub fn commit_lane_checkpoint(
        &self,
        replacement_id: &str,
        generation: i64,
        observation: &Val,
        reobservation: &Val,
        exclude_key: &str,
        at: &str,
    ) -> Result<(LaneCheckpointRow, LaneReplacementRow, String), StateError> {
        let outcome = self.commit_lane_checkpoint_inner(
            replacement_id,
            generation,
            observation,
            reobservation,
            exclude_key,
            at,
        );
        if let Err(err) = &outcome {
            self.poison_on(err);
        }
        outcome
    }

    #[allow(clippy::too_many_arguments)]
    fn commit_lane_checkpoint_inner(
        &self,
        replacement_id: &str,
        generation: i64,
        observation: &Val,
        reobservation: &Val,
        exclude_key: &str,
        at: &str,
    ) -> Result<(LaneCheckpointRow, LaneReplacementRow, String), StateError> {
        self.ensure_writable()?;
        // Two observations detect changes during capture: the capture only
        // commits when both views of the lane are canonically identical.
        // An inconsistent view refuses the checkpoint (neither is trusted).
        let observation_text = canonical_text(observation);
        let reobservation_text = canonical_text(reobservation);
        if observation_text != reobservation_text {
            return Err(state_error(
                checkpoint_code::CHANGED,
                "the two observations of the lane differ: the state changed during capture; \
                 the checkpoint refuses to commit either view (no state is changed)",
            ));
        }
        let observation_digest = sha256_hex(&canonical_bytes(observation));
        let reobservation_digest = sha256_hex(&canonical_bytes(reobservation));
        let checkpoint_id = checkpoint_id_for(replacement_id);
        {
            let mut conn = self.lock("commit_lane_checkpoint")?;
            let tx = conn
                .transaction()
                .map_err(|err| StateError::from_sqlite("commit_lane_checkpoint: begin", err))?;
            let record: Option<LaneReplacementRow> = tx
                .query_row(
                    "SELECT replacement_id, lane_id, generation, successor_generation,
                            phase, outcome, outcome_reason, source_session, source_process,
                            role, worktree, reason, created_at, updated_at
                       FROM lane_replacements WHERE replacement_id = ?1",
                    params![replacement_id],
                    lane_replacement_row_from,
                )
                .optional()
                .map_err(|err| StateError::from_sqlite("commit_lane_checkpoint: record", err))?;
            let Some(record) = record else {
                return Err(state_error(
                    "state.not_found",
                    format!("no lane replacement {replacement_id:?}"),
                ));
            };
            // One replacement carries at most ONE capture: an existing
            // checkpoint row refuses any second capture outright (the row
            // and the record transition commit together, so a row also
            // means the boundary was consumed).
            let existing: i64 = tx
                .query_row(
                    "SELECT COUNT(*) FROM lane_checkpoints WHERE replacement_id = ?1",
                    params![replacement_id],
                    |row| row.get(0),
                )
                .map_err(|err| StateError::from_sqlite("commit_lane_checkpoint: exists", err))?;
            if existing != 0 {
                return Err(state_error(
                    checkpoint_code::EXISTS,
                    format!(
                        "replacement {replacement_id} already has checkpoint {checkpoint_id}: \
                         one replacement carries at most one capture (a second one cannot exist)"
                    ),
                ));
            }
            // Capture is only admitted at the quiescing boundary: the
            // record must be pending, at `quiescing`, at the presented
            // generation (the same typed classifier as every transition).
            if record.outcome != "pending"
                || record.generation != generation
                || record.phase != "quiescing"
            {
                return Err(lane_replacement_transition_refusal(
                    Some(&record),
                    replacement_id,
                    "quiescing",
                    generation,
                ));
            }
            // Outstanding operations are daemon-observed: the unresolved
            // claims other than the capture itself (bounded, with the exact
            // total so nothing looks silently truncated).
            let outstanding_count: i64 = tx
                .query_row(
                    "SELECT COUNT(*) FROM idempotency WHERE status = 'claimed' AND key != ?1",
                    params![exclude_key],
                    |row| row.get(0),
                )
                .map_err(|err| {
                    StateError::from_sqlite("commit_lane_checkpoint: outstanding", err)
                })?;
            let mut outstanding: Vec<(String, String)> = Vec::new();
            {
                let mut statement = tx
                    .prepare(
                        "SELECT key, method FROM idempotency
                          WHERE status = 'claimed' AND key != ?1
                          ORDER BY key LIMIT 8",
                    )
                    .map_err(|err| {
                        StateError::from_sqlite("commit_lane_checkpoint: outstanding prepare", err)
                    })?;
                let rows = statement
                    .query_map(params![exclude_key], |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                    })
                    .map_err(|err| {
                        StateError::from_sqlite("commit_lane_checkpoint: outstanding query", err)
                    })?;
                for row in rows {
                    outstanding.push(row.map_err(|err| {
                        StateError::from_sqlite("commit_lane_checkpoint: outstanding row", err)
                    })?);
                }
            }
            let epoch = current_epoch_locked(&tx)?;
            let snapshot = checkpoint_snapshot_val(
                &record,
                observation,
                &observation_digest,
                &reobservation_digest,
                &outstanding,
                outstanding_count,
                epoch,
                at,
                &checkpoint_id,
                &tx,
            )?;
            let snapshot_text = canonical_text(&snapshot);
            let digest = sha256_hex(&canonical_bytes(&snapshot));
            let provisional = LaneCheckpointRow {
                checkpoint_id,
                replacement_id: record.replacement_id.clone(),
                lane_id: record.lane_id.clone(),
                generation,
                role: record.role.clone(),
                observation_digest,
                reobservation_digest,
                snapshot: snapshot_text,
                digest,
                brief_digest: String::new(),
                created_at: at.to_string(),
            };
            let brief = lane_checkpoint_brief(&provisional)?;
            if brief.len() > CHECKPOINT_BRIEF_MAX_BYTES {
                return Err(state_error(
                    checkpoint_code::OVERSIZE,
                    format!(
                        "the generated brief is {} bytes, over the enforced \n\
                         {CHECKPOINT_BRIEF_MAX_BYTES}-byte bound; required data is never truncated — \
                         reduce the recorded gates/children and retry",
                        brief.len()
                    ),
                ));
            }
            let brief_digest = sha256_hex(brief.as_bytes());
            tx.execute(
                "INSERT INTO lane_checkpoints (checkpoint_id, replacement_id, lane_id,
                    generation, role, observation_digest, reobservation_digest, snapshot,
                    digest, brief_digest, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    provisional.checkpoint_id,
                    provisional.replacement_id,
                    provisional.lane_id,
                    provisional.generation,
                    provisional.role,
                    provisional.observation_digest,
                    provisional.reobservation_digest,
                    provisional.snapshot,
                    provisional.digest,
                    brief_digest,
                    provisional.created_at
                ],
            )
            .map_err(|err| StateError::from_sqlite("commit_lane_checkpoint: insert", err))?;
            let affected = tx
                .execute(
                    "UPDATE lane_replacements
                        SET phase = 'checkpointed', updated_at = ?1
                      WHERE replacement_id = ?2 AND phase = 'quiescing'
                            AND generation = ?3 AND outcome = 'pending'",
                    params![at, replacement_id, generation],
                )
                .map_err(|err| StateError::from_sqlite("commit_lane_checkpoint: advance", err))?;
            if affected != 1 {
                return Err(state_error(
                    "state.conflict",
                    format!("checkpoint commit lost its compare-and-set fence on {replacement_id}"),
                ));
            }
            append_lane_replacement_event(
                &tx,
                replacement_id,
                Some("quiescing"),
                "checkpointed",
                Some("pending"),
                "pending",
                "",
                at,
            )?;
            let updated: LaneReplacementRow = tx
                .query_row(
                    "SELECT replacement_id, lane_id, generation, successor_generation,
                            phase, outcome, outcome_reason, source_session, source_process,
                            role, worktree, reason, created_at, updated_at
                       FROM lane_replacements WHERE replacement_id = ?1",
                    params![replacement_id],
                    lane_replacement_row_from,
                )
                .map_err(|err| StateError::from_sqlite("commit_lane_checkpoint: reread", err))?;
            tx.commit()
                .map_err(|err| StateError::from_sqlite("commit_lane_checkpoint: commit", err))?;
            let checkpoint = LaneCheckpointRow {
                brief_digest,
                ..provisional
            };
            Ok((checkpoint, updated, brief))
        }
    }

    /// One lane checkpoint by replacement id (read-only).
    pub fn lane_checkpoint_by_replacement(
        &self,
        replacement_id: &str,
    ) -> Result<Option<LaneCheckpointRow>, StateError> {
        let conn = self.lock("lane_checkpoint_by_replacement")?;
        conn.query_row(
            "SELECT checkpoint_id, replacement_id, lane_id, generation, role,
                    observation_digest, reobservation_digest, snapshot, digest,
                    brief_digest, created_at
               FROM lane_checkpoints WHERE replacement_id = ?1",
            params![replacement_id],
            lane_checkpoint_row_from,
        )
        .optional()
        .map_err(|err| StateError::from_sqlite("lane_checkpoint_by_replacement: query", err))
    }

    /// Validate one lane retirement request (issue #75) BEFORE any effect.
    ///
    /// The presented binding (lane generation, source session/process
    /// identity, committed checkpoint digest) must match the durable record
    /// and the checkpoint that completes it; the record must be a pending
    /// `checkpointed` handoff (a `held` record is the paused state and
    /// refuses, as do cancelled and ambiguous records); and the immediate
    /// pre-stop quiescence recheck must have observed every child exited, no
    /// active external execution, and the bound process identity. A changed
    /// identity or checkpoint refuses (`refusal.retirement.binding`); unknown
    /// child activity or an unknown process identity is a typed hold
    /// (`refusal.retirement.held`) — nothing is signalled, killed or cleaned
    /// up to obtain quiescence. Read-only: no state is written.
    pub fn begin_lane_retirement(&self, params: &Val) -> Result<LaneRetirementPlan, StateError> {
        let request = retirement_request(params)?;
        let conn = self.lock("begin_lane_retirement")?;
        let record: Option<LaneReplacementRow> = conn
            .query_row(
                "SELECT replacement_id, lane_id, generation, successor_generation,
                        phase, outcome, outcome_reason, source_session, source_process,
                        role, worktree, reason, created_at, updated_at
                   FROM lane_replacements WHERE replacement_id = ?1",
                params![request.replacement_id.as_str()],
                lane_replacement_row_from,
            )
            .optional()
            .map_err(|err| StateError::from_sqlite("begin_lane_retirement: lookup", err))?;
        let Some(record) = record else {
            return Err(state_error(
                "state.not_found",
                format!("no lane replacement {:?}", request.replacement_id),
            ));
        };
        match record.outcome.as_str() {
            "pending" => {}
            "held" => {
                let reason = if record.outcome_reason.is_empty() {
                    "no reason recorded"
                } else {
                    record.outcome_reason.as_str()
                };
                return Err(state_error(
                    replacement_code::HELD,
                    format!(
                        "replacement {} is held (paused): {reason}",
                        record.replacement_id
                    ),
                ));
            }
            "ambiguous" => {
                return Err(state_error(
                    replacement_code::AMBIGUOUS,
                    format!(
                        "replacement {} was left ambiguous by an interrupted transition; \
                         external reconciliation is required before it can be retired",
                        record.replacement_id
                    ),
                ));
            }
            _ => {
                return Err(state_error(
                    replacement_code::INVALIDATED,
                    format!(
                        "replacement {} was cancelled (invalidated); it can never be retired",
                        record.replacement_id
                    ),
                ));
            }
        }
        if record.phase != "checkpointed" {
            return Err(state_error(
                replacement_code::ORDER,
                format!(
                    "retirement requires the `checkpointed` handoff boundary (capture the \
                     checkpoint first); replacement {} is at {:?}",
                    record.replacement_id, record.phase
                ),
            ));
        }
        if request.binding.generation != record.generation {
            return Err(state_error(
                retirement_code::BINDING,
                format!(
                    "the retirement binding generation {} does not match replacement {} \
                     generation {}",
                    request.binding.generation, record.replacement_id, record.generation
                ),
            ));
        }
        if request.binding.session != record.source_session {
            return Err(state_error(
                retirement_code::BINDING,
                format!(
                    "the retirement binding session {:?} does not match the source session {:?} \
                     bound by replacement {} (a changed identity refuses before any effect)",
                    request.binding.session, record.source_session, record.replacement_id
                ),
            ));
        }
        if request.binding.process != record.source_process {
            return Err(state_error(
                retirement_code::BINDING,
                format!(
                    "the retirement binding process {:?} does not match the source process {:?} \
                     bound by replacement {} (a changed identity refuses before any effect)",
                    request.binding.process, record.source_process, record.replacement_id
                ),
            ));
        }
        let checkpoint: Option<LaneCheckpointRow> = conn
            .query_row(
                "SELECT checkpoint_id, replacement_id, lane_id, generation, role,
                        observation_digest, reobservation_digest, snapshot, digest,
                        brief_digest, created_at
                   FROM lane_checkpoints WHERE replacement_id = ?1",
                params![request.replacement_id.as_str()],
                lane_checkpoint_row_from,
            )
            .optional()
            .map_err(|err| StateError::from_sqlite("begin_lane_retirement: checkpoint", err))?;
        let Some(checkpoint) = checkpoint else {
            return Err(state_error(
                "state.replacement_invalid",
                format!(
                    "replacement {} is checkpointed but no committed checkpoint records it; \
                     external reconciliation is required",
                    record.replacement_id
                ),
            ));
        };
        if checkpoint.generation != record.generation
            || checkpoint.digest != request.binding.checkpoint_digest
        {
            return Err(state_error(
                retirement_code::BINDING,
                format!(
                    "the retirement binding checkpoint digest {} does not match the committed \
                     checkpoint {} for replacement {} (digest {}); changed evidence refuses \
                     before any effect",
                    request.binding.checkpoint_digest,
                    checkpoint.checkpoint_id,
                    record.replacement_id,
                    checkpoint.digest
                ),
            ));
        }
        // The immediate pre-stop quiescence recheck (AC2). Unknown child
        // activity or an unknown process identity HOLDS; a changed identity
        // refuses as a binding mismatch; nothing is signalled, killed, or
        // cleaned up to obtain quiescence and no broad process group is ever
        // addressed.
        if request.recheck.session != record.source_session {
            return Err(state_error(
                retirement_code::BINDING,
                format!(
                    "the pre-stop recheck observed session {:?}, not the source session {:?} \
                     bound by replacement {} (a changed identity refuses before any effect)",
                    request.recheck.session, record.source_session, record.replacement_id
                ),
            ));
        }
        let Some(observed_process) = request.recheck.process.as_deref() else {
            return Err(state_error(
                retirement_code::HELD,
                format!(
                    "the pre-stop recheck carries no process identity for session {:?} (an \
                     unknown process identity holds; nothing is signalled)",
                    record.source_session
                ),
            ));
        };
        if observed_process != record.source_process {
            return Err(state_error(
                retirement_code::BINDING,
                format!(
                    "the pre-stop recheck observed process {:?}, not the source process {:?} \
                     bound by replacement {} (a changed identity refuses before any effect)",
                    observed_process, record.source_process, record.replacement_id
                ),
            ));
        }
        if request.recheck.active {
            return Err(state_error(
                retirement_code::HELD,
                format!(
                    "the pre-stop recheck observed external harness execution still active for \
                     session {:?}; retirement holds (nothing is signalled, killed, or cleaned up)",
                    record.source_session
                ),
            ));
        }
        for (command, state) in &request.recheck.children {
            if state != "exited" {
                return Err(state_error(
                    retirement_code::HELD,
                    format!(
                        "the pre-stop recheck observed child command {command:?} in state \
                         {state:?}: unknown child activity holds retirement (nothing is \
                         signalled, killed, or cleaned up)"
                    ),
                ));
            }
        }
        Ok(LaneRetirementPlan {
            record,
            checkpoint,
            recheck_observed_at: request.recheck.observed_at,
        })
    }

    /// Commit one lane retirement (issue #75): the record's `checkpointed` →
    /// `retired` transition and its transition-history row commit in ONE
    /// transaction, fenced on the exact generation/phase/outcome and on the
    /// committed checkpoint digest (a missed fence is classified typed and
    /// changes nothing). `reason` is the bounded durable evidence summary —
    /// never silently truncated.
    pub fn commit_lane_retirement(
        &self,
        replacement_id: &str,
        generation: i64,
        checkpoint_digest: &str,
        reason: &str,
        at: &str,
    ) -> Result<LaneReplacementRow, StateError> {
        let outcome = self.commit_lane_retirement_inner(
            replacement_id,
            generation,
            checkpoint_digest,
            reason,
            at,
        );
        if let Err(err) = &outcome {
            self.poison_on(err);
        }
        outcome
    }

    fn commit_lane_retirement_inner(
        &self,
        replacement_id: &str,
        generation: i64,
        checkpoint_digest: &str,
        reason: &str,
        at: &str,
    ) -> Result<LaneReplacementRow, StateError> {
        if !printable_bounded(reason, RETIREMENT_REASON_MAX) {
            return Err(state_error(
                "state.replacement_invalid",
                format!(
                    "the retirement reason must be 1-{RETIREMENT_REASON_MAX} printable \
                     characters (the durable evidence summary is never truncated)"
                ),
            ));
        }
        self.ensure_writable()?;
        {
            let mut conn = self.lock("commit_lane_retirement")?;
            let tx = conn
                .transaction()
                .map_err(|err| StateError::from_sqlite("commit_lane_retirement: begin", err))?;
            let row: Option<LaneReplacementRow> = tx
                .query_row(
                    "SELECT replacement_id, lane_id, generation, successor_generation,
                            phase, outcome, outcome_reason, source_session, source_process,
                            role, worktree, reason, created_at, updated_at
                       FROM lane_replacements WHERE replacement_id = ?1",
                    params![replacement_id],
                    lane_replacement_row_from,
                )
                .optional()
                .map_err(|err| StateError::from_sqlite("commit_lane_retirement: lookup", err))?;
            let Some(row) = row else {
                return Err(state_error(
                    "state.not_found",
                    format!("no lane replacement {replacement_id:?}"),
                ));
            };
            if row.phase != "checkpointed"
                || row.outcome != "pending"
                || row.generation != generation
            {
                return Err(lane_replacement_transition_refusal(
                    Some(&row),
                    replacement_id,
                    "checkpointed",
                    generation,
                ));
            }
            let recorded: Option<String> = tx
                .query_row(
                    "SELECT digest FROM lane_checkpoints WHERE replacement_id = ?1",
                    params![replacement_id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|err| {
                    StateError::from_sqlite("commit_lane_retirement: checkpoint", err)
                })?;
            match recorded {
                Some(digest) if digest == checkpoint_digest => {}
                Some(digest) => {
                    return Err(state_error(
                        retirement_code::BINDING,
                        format!(
                            "the retirement commit checkpoint digest {checkpoint_digest} does \
                             not match the committed checkpoint digest {digest} for replacement \
                             {replacement_id}"
                        ),
                    ));
                }
                None => {
                    return Err(state_error(
                        "state.replacement_invalid",
                        format!(
                            "replacement {replacement_id} has no committed checkpoint; the \
                             retirement commit refuses (external reconciliation is required)"
                        ),
                    ));
                }
            }
            let affected = tx
                .execute(
                    "UPDATE lane_replacements
                        SET phase = 'retired', updated_at = ?1
                      WHERE replacement_id = ?2 AND phase = 'checkpointed'
                            AND generation = ?3 AND outcome = 'pending'",
                    params![at, replacement_id, generation],
                )
                .map_err(|err| StateError::from_sqlite("commit_lane_retirement: update", err))?;
            if affected != 1 {
                return Err(state_error(
                    "state.replacement_invalid",
                    format!(
                        "the retirement commit lost its compare-and-set fence on \
                         {replacement_id}; external reconciliation is required"
                    ),
                ));
            }
            append_lane_replacement_event(
                &tx,
                replacement_id,
                Some("checkpointed"),
                "retired",
                Some("pending"),
                "pending",
                reason,
                at,
            )?;
            tx.commit()
                .map_err(|err| StateError::from_sqlite("commit_lane_retirement: commit", err))?;
        }
        self.lane_replacement_by_id(replacement_id)?.ok_or_else(|| {
            state_error(
                "state.not_found",
                "replacement vanished after the retirement commit",
            )
        })
    }

    /// Restart-reconciliation hook (issue #73 AC5/AC6): an interrupted
    /// lane-replacement claim marks its record `ambiguous` — the explicit
    /// "unknown, external reconciliation required" outcome — unless the
    /// record is already terminal (cancelled/adopted). The record is
    /// located from the claim's params (`replacement_id`, or
    /// `lane_id` + `generation` for a request claim). Returns whether a
    /// record was flipped.
    pub fn mark_replacement_ambiguous(
        &self,
        params: &Val,
        reason: &str,
        at: &str,
    ) -> Result<bool, StateError> {
        let outcome = self.mark_replacement_ambiguous_inner(params, reason, at);
        if let Err(err) = &outcome {
            self.poison_on(err);
        }
        outcome
    }

    fn mark_replacement_ambiguous_inner(
        &self,
        params: &Val,
        reason: &str,
        at: &str,
    ) -> Result<bool, StateError> {
        self.ensure_writable()?;
        let mut conn = self.lock("mark_replacement_ambiguous")?;
        let tx = conn
            .transaction()
            .map_err(|err| StateError::from_sqlite("mark_replacement_ambiguous: begin", err))?;
        let replacement_id = match params.get("replacement_id").and_then(Val::as_str) {
            Some(id) => Some(id.to_string()),
            None => {
                let lane = params.get("lane_id").and_then(Val::as_str);
                let generation = params.get("generation").and_then(Val::as_int);
                match (lane, generation) {
                    (Some(lane), Some(generation)) => tx
                        .query_row(
                            "SELECT replacement_id FROM lane_replacements
                              WHERE lane_id = ?1 AND generation = ?2",
                            params![lane, generation],
                            |row| row.get::<_, String>(0),
                        )
                        .optional()
                        .map_err(|err| {
                            StateError::from_sqlite("mark_replacement_ambiguous: lookup", err)
                        })?,
                    _ => None,
                }
            }
        };
        let Some(replacement_id) = replacement_id else {
            return Ok(false);
        };
        let row: Option<LaneReplacementRow> = tx
            .query_row(
                "SELECT replacement_id, lane_id, generation, successor_generation,
                        phase, outcome, outcome_reason, source_session, source_process,
                        role, worktree, reason, created_at, updated_at
                   FROM lane_replacements WHERE replacement_id = ?1",
                params![replacement_id],
                lane_replacement_row_from,
            )
            .optional()
            .map_err(|err| StateError::from_sqlite("mark_replacement_ambiguous: read", err))?;
        let Some(row) = row else {
            return Ok(false);
        };
        if row.outcome == "cancelled" || row.outcome == "ambiguous" || row.phase == "adopted" {
            return Ok(false);
        }
        tx.execute(
            "UPDATE lane_replacements
                SET outcome = 'ambiguous', outcome_reason = ?1, updated_at = ?2
              WHERE replacement_id = ?3 AND outcome != 'cancelled'",
            params![reason, at, replacement_id],
        )
        .map_err(|err| StateError::from_sqlite("mark_replacement_ambiguous: update", err))?;
        append_lane_replacement_event(
            &tx,
            &replacement_id,
            Some(&row.phase),
            &row.phase,
            Some(&row.outcome),
            "ambiguous",
            reason,
            at,
        )?;
        tx.commit()
            .map_err(|err| StateError::from_sqlite("mark_replacement_ambiguous: commit", err))?;
        Ok(true)
    }

    // ---------------------------------------------------------------------
    // Lane successors (issue #76): the ONE daemon-coordinated start/adopt
    // transition — a fresh successor session on the SAME worktree/logical
    // task, bound by one generation + startup nonce, never a transcript
    // replay.
    // ---------------------------------------------------------------------

    /// Validate one successor start request read-only, BEFORE any effect and
    /// BEFORE the claim. The record must have committed its verified
    /// retirement (`retired`, pending) and its committed checkpoint digest
    /// must match the binding; the ONE startup nonce owns the successor
    /// slot. A same-nonce retry of a start whose boundary has not completed
    /// is returned as the existing row (bounded retry); every other path to
    /// a second successor refuses (`refusal.successor.exists` /
    /// `refusal.successor.nonce`). Read-only: no state is written.
    pub fn begin_lane_successor(&self, params: &Val) -> Result<LaneSuccessorPlan, StateError> {
        let replacement_id = match params.get("replacement_id").and_then(Val::as_str) {
            Some(text) if crate::formats::is_replacement_id(text) => text.to_string(),
            _ => {
                return Err(state_error(
                    successor_code::BINDING,
                    "a successor start requires params.replacement_id (rp_ + 16 hex)",
                ));
            }
        };
        let binding = successor_binding(params)?;
        let successor = match params.get("successor") {
            Some(Val::Obj(map)) => map,
            _ => {
                return Err(state_error(
                    successor_code::BINDING,
                    "a successor start requires params.successor (object: session, \
                     kickoff_receipt)",
                ));
            }
        };
        let session = match successor.get("session").and_then(Val::as_str) {
            Some(text) if crate::formats::is_actor(text) => text.to_string(),
            _ => {
                return Err(state_error(
                    successor_code::BINDING,
                    "a successor start requires params.successor.session (session identity)",
                ));
            }
        };
        let kickoff_receipt = match successor.get("kickoff_receipt").and_then(Val::as_str) {
            Some(text) if crate::formats::is_hex64(text) => text.to_string(),
            _ => {
                return Err(state_error(
                    successor_code::BINDING,
                    "a successor start requires params.successor.kickoff_receipt (64-hex \
                     sha256 receipt the adapter read-back must echo)",
                ));
            }
        };
        let conn = self.lock("begin_lane_successor")?;
        let record: Option<LaneReplacementRow> = conn
            .query_row(
                "SELECT replacement_id, lane_id, generation, successor_generation,
                        phase, outcome, outcome_reason, source_session, source_process,
                        role, worktree, reason, created_at, updated_at
                   FROM lane_replacements WHERE replacement_id = ?1",
                params![replacement_id.as_str()],
                lane_replacement_row_from,
            )
            .optional()
            .map_err(|err| StateError::from_sqlite("begin_lane_successor: lookup", err))?;
        let Some(record) = record else {
            return Err(state_error(
                "state.not_found",
                format!("no lane replacement {replacement_id:?}"),
            ));
        };
        // Target-profile binding (issue #77). A record requested under an
        // explicit profile-configuration revision only starts when the SAME
        // reviewed binding is presented: a changed revision (the relevant
        // configuration or a declared credential moved after the preview)
        // requires a newly reviewed plan; a missing, unexpected, or
        // materially different binding refuses BEFORE any effect.
        let stored_profile = lane_replacement_profile_of(&conn, &record.replacement_id)?;
        match (stored_profile, params.get("profile")) {
            (None, None) => {}
            (Some(stored), Some(presented)) => {
                let presented_revision = presented.get("revision").and_then(Val::as_str);
                if presented_revision != Some(stored.revision.as_str()) {
                    return Err(state_error(
                        crate::config::CODE_PROFILE_REVISION,
                        format!(
                            "replacement {} is bound to target profile revision {} but the \
                             start presents revision {}; the profile configuration changed \
                             after the preview and a newly reviewed plan is required",
                            record.replacement_id,
                            stored.revision,
                            presented_revision.unwrap_or("<missing>")
                        ),
                    ));
                }
                if canonical_text(presented) != stored.profile {
                    return Err(state_error(
                        crate::config::CODE_PROFILE_BINDING,
                        format!(
                            "the presented target-profile binding for replacement {} does not \
                             match the reviewed plan (the revision matches but the material \
                             does not)",
                            record.replacement_id
                        ),
                    ));
                }
            }
            (Some(_), None) => {
                return Err(state_error(
                    crate::config::CODE_PROFILE_BINDING,
                    format!(
                        "replacement {} was requested under an explicit profile-configuration \
                         revision; a start must present the same reviewed target-profile \
                         binding",
                        record.replacement_id
                    ),
                ));
            }
            (None, Some(_)) => {
                return Err(state_error(
                    crate::config::CODE_PROFILE_BINDING,
                    format!(
                        "replacement {} was not requested under a profile-configuration \
                         revision; a start cannot introduce one (request a new plan)",
                        record.replacement_id
                    ),
                ));
            }
        }
        match record.outcome.as_str() {
            "pending" => {}
            "held" => {
                let reason = if record.outcome_reason.is_empty() {
                    "no reason recorded"
                } else {
                    record.outcome_reason.as_str()
                };
                return Err(state_error(
                    replacement_code::HELD,
                    format!(
                        "replacement {} is held (paused): {reason}",
                        record.replacement_id
                    ),
                ));
            }
            "ambiguous" => {
                return Err(state_error(
                    replacement_code::AMBIGUOUS,
                    format!(
                        "replacement {} was left ambiguous by an interrupted transition; \
                         external reconciliation is required before it can start a successor",
                        record.replacement_id
                    ),
                ));
            }
            _ => {
                return Err(state_error(
                    replacement_code::INVALIDATED,
                    format!(
                        "replacement {} was cancelled (invalidated); it can never start a \
                         successor",
                        record.replacement_id
                    ),
                ));
            }
        }
        // The committed successor boundary is checked BEFORE the phase
        // fence: one generation/nonce owns startup, so any start after the
        // boundary committed refuses as a duplicate (or a foreign nonce),
        // never as a generic phase error.
        let existing: Option<LaneSuccessorRow> = conn
            .query_row(
                "SELECT successor_id, replacement_id, lane_id, generation, role, worktree,
                        session, process, nonce, profile_key, profile_kind, kickoff_receipt,
                        delivery, attempts, evidence, evidence_digest, orchestration,
                        consumed, adopted_at, adoption_evidence, adoption_digest, created_at,
                        updated_at
                   FROM lane_successors WHERE replacement_id = ?1",
                params![replacement_id.as_str()],
                lane_successor_row_from,
            )
            .optional()
            .map_err(|err| StateError::from_sqlite("begin_lane_successor: successor", err))?;
        if let Some(existing) = existing {
            if existing.nonce != binding.nonce {
                return Err(state_error(
                    successor_code::NONCE,
                    format!(
                        "successor {} is already owned by another startup nonce; one \
                         generation/nonce owns startup and a second nonce cannot take over \
                         a started successor",
                        existing.successor_id
                    ),
                ));
            }
            if existing.session != session {
                return Err(state_error(
                    successor_code::BINDING,
                    format!(
                        "successor {} is bound to session {:?}, not the presented {:?}",
                        existing.successor_id, existing.session, session
                    ),
                ));
            }
            if record.phase != "starting" {
                return Err(state_error(
                    successor_code::EXISTS,
                    format!(
                        "successor {} is already committed at replacement phase {:?}; the \
                         adoption path continues it (a second successor cannot be created)",
                        existing.successor_id, record.phase
                    ),
                ));
            }
            return Ok(LaneSuccessorPlan {
                record,
                checkpoint: match conn.query_row(
                    "SELECT checkpoint_id, replacement_id, lane_id, generation, role,
                            observation_digest, reobservation_digest, snapshot, digest,
                            brief_digest, created_at
                       FROM lane_checkpoints WHERE replacement_id = ?1",
                    params![replacement_id.as_str()],
                    lane_checkpoint_row_from,
                ) {
                    Ok(checkpoint) => checkpoint,
                    Err(err) => {
                        return Err(StateError::from_sqlite(
                            "begin_lane_successor: checkpoint",
                            err,
                        ));
                    }
                },
                nonce: binding.nonce,
                session,
                kickoff_receipt,
                existing: Some(existing),
            });
        }
        if record.phase != "retired" {
            return Err(state_error(
                replacement_code::ORDER,
                format!(
                    "starting a successor requires the verified `retired` boundary (retire \
                     the source session first); replacement {} is at {:?}",
                    record.replacement_id, record.phase
                ),
            ));
        }
        if binding.generation != record.generation {
            return Err(state_error(
                successor_code::BINDING,
                format!(
                    "the successor binding generation {} does not match replacement {} \
                     generation {}",
                    binding.generation, record.replacement_id, record.generation
                ),
            ));
        }
        let checkpoint: Option<LaneCheckpointRow> = conn
            .query_row(
                "SELECT checkpoint_id, replacement_id, lane_id, generation, role,
                        observation_digest, reobservation_digest, snapshot, digest,
                        brief_digest, created_at
                   FROM lane_checkpoints WHERE replacement_id = ?1",
                params![replacement_id.as_str()],
                lane_checkpoint_row_from,
            )
            .optional()
            .map_err(|err| StateError::from_sqlite("begin_lane_successor: checkpoint", err))?;
        let Some(checkpoint) = checkpoint else {
            return Err(state_error(
                successor_code::BINDING,
                format!(
                    "replacement {} has no committed checkpoint; checkpoint integrity cannot \
                     be verified (external reconciliation is required)",
                    record.replacement_id
                ),
            ));
        };
        if checkpoint.generation != record.generation
            || checkpoint.digest != binding.checkpoint_digest
        {
            return Err(state_error(
                successor_code::BINDING,
                format!(
                    "the successor binding checkpoint digest {} does not match the committed \
                     checkpoint {} for replacement {} (digest {}); changed evidence refuses \
                     before any effect",
                    binding.checkpoint_digest,
                    checkpoint.checkpoint_id,
                    record.replacement_id,
                    checkpoint.digest
                ),
            ));
        }
        Ok(LaneSuccessorPlan {
            record,
            checkpoint,
            nonce: binding.nonce,
            session,
            kickoff_receipt,
            existing: None,
        })
    }

    /// Commit the ONE successor owner boundary (issue #76) BEFORE any spawn:
    /// the successor row and the record's `retired` → `starting` transition
    /// commit in ONE transaction, fenced on the exact generation/phase/
    /// outcome and on the committed checkpoint. A simultaneous or replayed
    /// start loses the UNIQUE fence and refuses `refusal.successor.exists`
    /// with nothing spawned.
    #[allow(clippy::too_many_arguments)]
    pub fn commit_lane_successor_start(
        &self,
        replacement_id: &str,
        generation: i64,
        checkpoint_digest: &str,
        nonce: &str,
        session: &str,
        kickoff_receipt: &str,
        profile_key: &str,
        profile_kind: &str,
        at: &str,
    ) -> Result<(LaneSuccessorRow, LaneReplacementRow), StateError> {
        let outcome = self.commit_lane_successor_start_inner(
            replacement_id,
            generation,
            checkpoint_digest,
            nonce,
            session,
            kickoff_receipt,
            profile_key,
            profile_kind,
            at,
        );
        if let Err(err) = &outcome {
            self.poison_on(err);
        }
        outcome
    }

    #[allow(clippy::too_many_arguments)]
    fn commit_lane_successor_start_inner(
        &self,
        replacement_id: &str,
        generation: i64,
        checkpoint_digest: &str,
        nonce: &str,
        session: &str,
        kickoff_receipt: &str,
        profile_key: &str,
        profile_kind: &str,
        at: &str,
    ) -> Result<(LaneSuccessorRow, LaneReplacementRow), StateError> {
        if !printable_bounded(nonce, SUCCESSOR_NONCE_MAX) {
            return Err(state_error(
                successor_code::BINDING,
                format!("the startup nonce must be 1-{SUCCESSOR_NONCE_MAX} printable characters"),
            ));
        }
        self.ensure_writable()?;
        let successor_id = successor_id_for(replacement_id);
        {
            let mut conn = self.lock("commit_lane_successor_start")?;
            let tx = conn.transaction().map_err(|err| {
                StateError::from_sqlite("commit_lane_successor_start: begin", err)
            })?;
            let row: Option<LaneReplacementRow> = tx
                .query_row(
                    "SELECT replacement_id, lane_id, generation, successor_generation,
                            phase, outcome, outcome_reason, source_session, source_process,
                            role, worktree, reason, created_at, updated_at
                       FROM lane_replacements WHERE replacement_id = ?1",
                    params![replacement_id],
                    lane_replacement_row_from,
                )
                .optional()
                .map_err(|err| {
                    StateError::from_sqlite("commit_lane_successor_start: lookup", err)
                })?;
            let Some(row) = row else {
                return Err(state_error(
                    "state.not_found",
                    format!("no lane replacement {replacement_id:?}"),
                ));
            };
            if row.phase != "retired" || row.outcome != "pending" || row.generation != generation {
                return Err(lane_replacement_transition_refusal(
                    Some(&row),
                    replacement_id,
                    "retired",
                    generation,
                ));
            }
            let recorded: Option<String> = tx
                .query_row(
                    "SELECT digest FROM lane_checkpoints WHERE replacement_id = ?1",
                    params![replacement_id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|err| {
                    StateError::from_sqlite("commit_lane_successor_start: checkpoint", err)
                })?;
            match recorded {
                Some(digest) if digest == checkpoint_digest => {}
                Some(digest) => {
                    return Err(state_error(
                        successor_code::BINDING,
                        format!(
                            "the successor start checkpoint digest {checkpoint_digest} does \
                             not match the committed checkpoint digest {digest} for \
                             replacement {replacement_id}"
                        ),
                    ));
                }
                None => {
                    return Err(state_error(
                        successor_code::BINDING,
                        format!(
                            "replacement {replacement_id} has no committed checkpoint; the \
                             successor start refuses (external reconciliation is required)"
                        ),
                    ));
                }
            }
            let inserted = tx.execute(
                "INSERT INTO lane_successors (successor_id, replacement_id, lane_id, generation,
                    role, worktree, session, process, nonce, profile_key, profile_kind,
                    kickoff_receipt, delivery, attempts, evidence, evidence_digest,
                    orchestration, consumed, adopted_at, adoption_evidence, adoption_digest,
                    created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, '', ?8, ?9, ?10, ?11, 'none', 1, '', '',
                    '', '', '', '', '', ?12, ?12)",
                params![
                    successor_id,
                    replacement_id,
                    row.lane_id,
                    row.successor_generation,
                    row.role,
                    row.worktree,
                    session,
                    nonce,
                    profile_key,
                    profile_kind,
                    kickoff_receipt,
                    at
                ],
            );
            if let Err(err) = inserted {
                if err.sqlite_error_code() == Some(rusqlite::ErrorCode::ConstraintViolation) {
                    return Err(state_error(
                        successor_code::EXISTS,
                        format!(
                            "replacement {replacement_id} already has a successor \
                             ({successor_id}); one generation/nonce owns startup and a \
                             second successor cannot be created"
                        ),
                    ));
                }
                return Err(StateError::from_sqlite(
                    "commit_lane_successor_start: insert",
                    err,
                ));
            }
            let affected = tx
                .execute(
                    "UPDATE lane_replacements
                        SET phase = 'starting', updated_at = ?1
                      WHERE replacement_id = ?2 AND phase = 'retired'
                            AND generation = ?3 AND outcome = 'pending'",
                    params![at, replacement_id, generation],
                )
                .map_err(|err| {
                    StateError::from_sqlite("commit_lane_successor_start: update", err)
                })?;
            if affected != 1 {
                return Err(state_error(
                    "state.conflict",
                    format!(
                        "the successor start lost its compare-and-set fence on {replacement_id}"
                    ),
                ));
            }
            append_lane_replacement_event(
                &tx,
                replacement_id,
                Some("retired"),
                "starting",
                Some("pending"),
                "pending",
                nonce,
                at,
            )?;
            let successor: LaneSuccessorRow = tx
                .query_row(
                    "SELECT successor_id, replacement_id, lane_id, generation, role, worktree,
                            session, process, nonce, profile_key, profile_kind, kickoff_receipt,
                            delivery, attempts, evidence, evidence_digest, orchestration,
                            consumed, adopted_at, adoption_evidence, adoption_digest, created_at,
                            updated_at
                       FROM lane_successors WHERE replacement_id = ?1",
                    params![replacement_id],
                    lane_successor_row_from,
                )
                .map_err(|err| {
                    StateError::from_sqlite("commit_lane_successor_start: reread", err)
                })?;
            let updated: LaneReplacementRow = tx
                .query_row(
                    "SELECT replacement_id, lane_id, generation, successor_generation,
                            phase, outcome, outcome_reason, source_session, source_process,
                            role, worktree, reason, created_at, updated_at
                       FROM lane_replacements WHERE replacement_id = ?1",
                    params![replacement_id],
                    lane_replacement_row_from,
                )
                .map_err(|err| {
                    StateError::from_sqlite("commit_lane_successor_start: record", err)
                })?;
            tx.commit().map_err(|err| {
                StateError::from_sqlite("commit_lane_successor_start: commit", err)
            })?;
            Ok((successor, updated))
        }
    }

    /// Count one bounded re-spawn attempt of an undelivered successor start
    /// (bounded retry policy: at most [`SUCCESSOR_ATTEMPTS_MAX`] spawn
    /// attempts per successor). Only an undelivered boundary may retry a
    /// spawn; a delivered one can only re-verify.
    pub fn note_lane_successor_attempt(
        &self,
        replacement_id: &str,
        nonce: &str,
        at: &str,
    ) -> Result<LaneSuccessorRow, StateError> {
        let outcome = self.note_lane_successor_attempt_inner(replacement_id, nonce, at);
        if let Err(err) = &outcome {
            self.poison_on(err);
        }
        outcome
    }

    fn note_lane_successor_attempt_inner(
        &self,
        replacement_id: &str,
        nonce: &str,
        at: &str,
    ) -> Result<LaneSuccessorRow, StateError> {
        self.ensure_writable()?;
        {
            let mut conn = self.lock("note_lane_successor_attempt")?;
            let tx = conn.transaction().map_err(|err| {
                StateError::from_sqlite("note_lane_successor_attempt: begin", err)
            })?;
            let row: Option<LaneSuccessorRow> = tx
                .query_row(
                    "SELECT successor_id, replacement_id, lane_id, generation, role, worktree,
                            session, process, nonce, profile_key, profile_kind, kickoff_receipt,
                            delivery, attempts, evidence, evidence_digest, orchestration,
                            consumed, adopted_at, adoption_evidence, adoption_digest, created_at,
                            updated_at
                       FROM lane_successors WHERE replacement_id = ?1",
                    params![replacement_id],
                    lane_successor_row_from,
                )
                .optional()
                .map_err(|err| {
                    StateError::from_sqlite("note_lane_successor_attempt: lookup", err)
                })?;
            let Some(row) = row else {
                return Err(state_error(
                    successor_code::BINDING,
                    format!("replacement {replacement_id} has no successor boundary"),
                ));
            };
            if row.nonce != nonce {
                return Err(state_error(
                    successor_code::NONCE,
                    format!(
                        "successor {} is owned by another startup nonce; a second nonce \
                         cannot take over a started successor",
                        row.successor_id
                    ),
                ));
            }
            if row.delivery != "none" {
                return Err(state_error(
                    successor_code::HELD,
                    format!(
                        "successor {} already delivered a spawn; only an undelivered boundary \
                         may retry a spawn (a delivered successor re-verifies instead)",
                        row.successor_id
                    ),
                ));
            }
            if row.attempts >= SUCCESSOR_ATTEMPTS_MAX {
                return Err(state_error(
                    successor_code::ATTEMPTS,
                    format!(
                        "successor {} exhausted its bounded spawn-attempt budget \
                         ({SUCCESSOR_ATTEMPTS_MAX}); external reconciliation is required",
                        row.successor_id
                    ),
                ));
            }
            tx.execute(
                "UPDATE lane_successors SET attempts = attempts + 1, updated_at = ?1
                  WHERE successor_id = ?2 AND nonce = ?3 AND delivery = 'none'",
                params![at, row.successor_id, nonce],
            )
            .map_err(|err| StateError::from_sqlite("note_lane_successor_attempt: update", err))?;
            tx.commit().map_err(|err| {
                StateError::from_sqlite("note_lane_successor_attempt: commit", err)
            })?;
        }
        self.lane_successor_by_replacement(replacement_id)?
            .ok_or_else(|| state_error("state.not_found", "successor vanished after attempt"))
    }

    /// Mark the successor spawn delivered (the workspace accepted the start
    /// row). Idempotent: a replayed marker keeps `delivered`. Only a
    /// `delivered` successor may complete verification; an undelivered one
    /// can retry (bounded) or be parked by the caller.
    pub fn mark_lane_successor_delivered(
        &self,
        replacement_id: &str,
        nonce: &str,
        at: &str,
    ) -> Result<LaneSuccessorRow, StateError> {
        let outcome = self.mark_lane_successor_delivered_inner(replacement_id, nonce, at);
        if let Err(err) = &outcome {
            self.poison_on(err);
        }
        outcome
    }

    fn mark_lane_successor_delivered_inner(
        &self,
        replacement_id: &str,
        nonce: &str,
        at: &str,
    ) -> Result<LaneSuccessorRow, StateError> {
        self.ensure_writable()?;
        {
            let mut conn = self.lock("mark_lane_successor_delivered")?;
            let tx = conn.transaction().map_err(|err| {
                StateError::from_sqlite("mark_lane_successor_delivered: begin", err)
            })?;
            let row: Option<LaneSuccessorRow> = tx
                .query_row(
                    "SELECT successor_id, replacement_id, lane_id, generation, role, worktree,
                            session, process, nonce, profile_key, profile_kind, kickoff_receipt,
                            delivery, attempts, evidence, evidence_digest, orchestration,
                            consumed, adopted_at, adoption_evidence, adoption_digest, created_at,
                            updated_at
                       FROM lane_successors WHERE replacement_id = ?1",
                    params![replacement_id],
                    lane_successor_row_from,
                )
                .optional()
                .map_err(|err| {
                    StateError::from_sqlite("mark_lane_successor_delivered: lookup", err)
                })?;
            let Some(row) = row else {
                return Err(state_error(
                    successor_code::BINDING,
                    format!("replacement {replacement_id} has no successor boundary"),
                ));
            };
            if row.nonce != nonce {
                return Err(state_error(
                    successor_code::NONCE,
                    format!(
                        "successor {} is owned by another startup nonce",
                        row.successor_id
                    ),
                ));
            }
            if row.delivery == "none" {
                tx.execute(
                    "UPDATE lane_successors SET delivery = 'delivered', updated_at = ?1
                      WHERE successor_id = ?2 AND delivery = 'none'",
                    params![at, row.successor_id],
                )
                .map_err(|err| {
                    StateError::from_sqlite("mark_lane_successor_delivered: update", err)
                })?;
            }
            tx.commit().map_err(|err| {
                StateError::from_sqlite("mark_lane_successor_delivered: commit", err)
            })?;
        }
        self.lane_successor_by_replacement(replacement_id)?
            .ok_or_else(|| state_error("state.not_found", "successor vanished after delivery"))
    }

    /// Commit the verified successor boundary (issue #76): the successor
    /// row's adapter-observed process + verification evidence and the
    /// record's `starting` → `adopting` transition commit in ONE
    /// transaction, fenced on the exact generation/`starting`/pending state
    /// and on the owning nonce. A spawned process alone never reaches this
    /// commit: the caller only calls it with a closed adapter verdict.
    #[allow(clippy::too_many_arguments)]
    pub fn commit_lane_successor_verified(
        &self,
        replacement_id: &str,
        nonce: &str,
        process: &str,
        readiness: &str,
        binding: &Val,
        reason: &str,
        at: &str,
    ) -> Result<(LaneSuccessorRow, LaneReplacementRow), StateError> {
        let outcome = self.commit_lane_successor_verified_inner(
            replacement_id,
            nonce,
            process,
            readiness,
            binding,
            reason,
            at,
        );
        if let Err(err) = &outcome {
            self.poison_on(err);
        }
        outcome
    }

    #[allow(clippy::too_many_arguments)]
    fn commit_lane_successor_verified_inner(
        &self,
        replacement_id: &str,
        nonce: &str,
        process: &str,
        readiness: &str,
        binding: &Val,
        reason: &str,
        at: &str,
    ) -> Result<(LaneSuccessorRow, LaneReplacementRow), StateError> {
        if !crate::formats::is_actor(process) {
            return Err(state_error(
                successor_code::BINDING,
                "the verified successor process must be a process identity",
            ));
        }
        if !printable_bounded(readiness, 32) {
            return Err(state_error(
                successor_code::BINDING,
                "the verified successor readiness must be a bounded state",
            ));
        }
        if !printable_bounded(reason, RETIREMENT_REASON_MAX) {
            return Err(state_error(
                successor_code::BINDING,
                format!(
                    "the successor verification reason must be 1-{RETIREMENT_REASON_MAX} \
                     printable characters (the durable evidence summary is never truncated)"
                ),
            ));
        }
        self.ensure_writable()?;
        {
            let mut conn = self.lock("commit_lane_successor_verified")?;
            let tx = conn.transaction().map_err(|err| {
                StateError::from_sqlite("commit_lane_successor_verified: begin", err)
            })?;
            let record: Option<LaneReplacementRow> = tx
                .query_row(
                    "SELECT replacement_id, lane_id, generation, successor_generation,
                            phase, outcome, outcome_reason, source_session, source_process,
                            role, worktree, reason, created_at, updated_at
                       FROM lane_replacements WHERE replacement_id = ?1",
                    params![replacement_id],
                    lane_replacement_row_from,
                )
                .optional()
                .map_err(|err| {
                    StateError::from_sqlite("commit_lane_successor_verified: record", err)
                })?;
            let Some(record) = record else {
                return Err(state_error(
                    "state.not_found",
                    format!("no lane replacement {replacement_id:?}"),
                ));
            };
            if record.phase != "starting" || record.outcome != "pending" {
                return Err(lane_replacement_transition_refusal(
                    Some(&record),
                    replacement_id,
                    "starting",
                    record.generation,
                ));
            }
            let successor: Option<LaneSuccessorRow> = tx
                .query_row(
                    "SELECT successor_id, replacement_id, lane_id, generation, role, worktree,
                            session, process, nonce, profile_key, profile_kind, kickoff_receipt,
                            delivery, attempts, evidence, evidence_digest, orchestration,
                            consumed, adopted_at, adoption_evidence, adoption_digest, created_at,
                            updated_at
                       FROM lane_successors WHERE replacement_id = ?1",
                    params![replacement_id],
                    lane_successor_row_from,
                )
                .optional()
                .map_err(|err| {
                    StateError::from_sqlite("commit_lane_successor_verified: successor", err)
                })?;
            let Some(successor) = successor else {
                return Err(state_error(
                    successor_code::BINDING,
                    format!("replacement {replacement_id} has no committed successor boundary"),
                ));
            };
            if successor.nonce != nonce {
                return Err(state_error(
                    successor_code::NONCE,
                    format!(
                        "successor {} is owned by another startup nonce",
                        successor.successor_id
                    ),
                ));
            }
            let evidence = object(vec![
                ("schema", string("hf-lane-successor/v1")),
                ("successor_id", string(&successor.successor_id)),
                ("replacement_id", string(replacement_id)),
                ("lane_id", string(&successor.lane_id)),
                ("generation", integer(successor.generation)),
                ("role", string(&successor.role)),
                ("worktree", string(&successor.worktree)),
                ("session", string(&successor.session)),
                ("process", string(process)),
                (
                    "profile",
                    object(vec![
                        ("key", string(&successor.profile_key)),
                        ("kind", string(&successor.profile_kind)),
                    ]),
                ),
                ("kickoff_receipt", string(&successor.kickoff_receipt)),
                ("readiness", string(readiness)),
                ("binding", binding.clone()),
                ("observed_at", string(at)),
            ]);
            let evidence_text = canonical_text(&evidence);
            let evidence_digest = sha256_hex(&canonical_bytes(&evidence));
            let affected = tx
                .execute(
                    "UPDATE lane_successors
                        SET process = ?1, evidence = ?2, evidence_digest = ?3,
                            delivery = 'delivered', updated_at = ?4
                      WHERE successor_id = ?5 AND nonce = ?6",
                    params![
                        process,
                        evidence_text,
                        evidence_digest,
                        at,
                        successor.successor_id,
                        nonce
                    ],
                )
                .map_err(|err| {
                    StateError::from_sqlite("commit_lane_successor_verified: successor update", err)
                })?;
            if affected != 1 {
                return Err(state_error(
                    "state.conflict",
                    format!("the successor verification lost its nonce fence on {replacement_id}"),
                ));
            }
            let advanced = tx
                .execute(
                    "UPDATE lane_replacements
                        SET phase = 'adopting', updated_at = ?1
                      WHERE replacement_id = ?2 AND phase = 'starting'
                            AND generation = ?3 AND outcome = 'pending'",
                    params![at, replacement_id, record.generation],
                )
                .map_err(|err| {
                    StateError::from_sqlite("commit_lane_successor_verified: transition", err)
                })?;
            if advanced != 1 {
                return Err(state_error(
                    "state.conflict",
                    format!(
                        "the successor verification lost its compare-and-set fence on \
                         {replacement_id}"
                    ),
                ));
            }
            append_lane_replacement_event(
                &tx,
                replacement_id,
                Some("starting"),
                "adopting",
                Some("pending"),
                "pending",
                reason,
                at,
            )?;
            let successor: LaneSuccessorRow = tx
                .query_row(
                    "SELECT successor_id, replacement_id, lane_id, generation, role, worktree,
                            session, process, nonce, profile_key, profile_kind, kickoff_receipt,
                            delivery, attempts, evidence, evidence_digest, orchestration,
                            consumed, adopted_at, adoption_evidence, adoption_digest, created_at,
                            updated_at
                       FROM lane_successors WHERE replacement_id = ?1",
                    params![replacement_id],
                    lane_successor_row_from,
                )
                .map_err(|err| {
                    StateError::from_sqlite("commit_lane_successor_verified: reread", err)
                })?;
            let updated: LaneReplacementRow = tx
                .query_row(
                    "SELECT replacement_id, lane_id, generation, successor_generation,
                            phase, outcome, outcome_reason, source_session, source_process,
                            role, worktree, reason, created_at, updated_at
                       FROM lane_replacements WHERE replacement_id = ?1",
                    params![replacement_id],
                    lane_replacement_row_from,
                )
                .map_err(|err| {
                    StateError::from_sqlite("commit_lane_successor_verified: record reread", err)
                })?;
            tx.commit().map_err(|err| {
                StateError::from_sqlite("commit_lane_successor_verified: commit", err)
            })?;
            Ok((successor, updated))
        }
    }

    /// One lane successor by replacement id (read-only).
    pub fn lane_successor_by_replacement(
        &self,
        replacement_id: &str,
    ) -> Result<Option<LaneSuccessorRow>, StateError> {
        let conn = self.lock("lane_successor_by_replacement")?;
        conn.query_row(
            "SELECT successor_id, replacement_id, lane_id, generation, role, worktree,
                    session, process, nonce, profile_key, profile_kind, kickoff_receipt,
                    delivery, attempts, evidence, evidence_digest, orchestration,
                    consumed, adopted_at, adoption_evidence, adoption_digest, created_at,
                    updated_at
               FROM lane_successors WHERE replacement_id = ?1",
            params![replacement_id],
            lane_successor_row_from,
        )
        .optional()
        .map_err(|err| StateError::from_sqlite("lane_successor_by_replacement: query", err))
    }

    /// Validate one adoption re-query read-only, BEFORE any effect (issue
    /// #76 AC5). The record must be at the pending `adopting` boundary with
    /// its committed successor; the presented observation and reobservation
    /// must be canonically identical and satisfy the closed observation
    /// contract; the fresh re-query is compared against the committed
    /// checkpoint's recorded handoff state. A non-empty difference list is
    /// the RECONCILIATION verdict (the adoption must not commit). Read-only:
    /// no state is written.
    pub fn begin_lane_adoption(&self, params: &Val) -> Result<LaneAdoptionPlan, StateError> {
        let replacement_id = match params.get("replacement_id").and_then(Val::as_str) {
            Some(text) if crate::formats::is_replacement_id(text) => text.to_string(),
            _ => {
                return Err(state_error(
                    successor_code::BINDING,
                    "an adoption requires params.replacement_id (rp_ + 16 hex)",
                ));
            }
        };
        let binding = adoption_binding(params)?;
        let observation = match params.get("observation") {
            Some(value @ Val::Obj(_)) => value,
            _ => {
                return Err(state_error(
                    successor_code::BINDING,
                    "an adoption requires params.observation (the fresh re-query of the lane)",
                ));
            }
        };
        let reobservation = match params.get("reobservation") {
            Some(value @ Val::Obj(_)) => value,
            _ => {
                return Err(state_error(
                    successor_code::BINDING,
                    "an adoption requires params.reobservation (the second fresh re-query of \
                     the same window)",
                ));
            }
        };
        if canonical_text(observation) != canonical_text(reobservation) {
            return Err(state_error(
                successor_code::BINDING,
                "the two adoption re-queries differ: the lane changed during the re-query; \
                 the adoption refuses to commit either view (no state is changed)",
            ));
        }
        let conn = self.lock("begin_lane_adoption")?;
        let record: Option<LaneReplacementRow> = conn
            .query_row(
                "SELECT replacement_id, lane_id, generation, successor_generation,
                        phase, outcome, outcome_reason, source_session, source_process,
                        role, worktree, reason, created_at, updated_at
                   FROM lane_replacements WHERE replacement_id = ?1",
                params![replacement_id.as_str()],
                lane_replacement_row_from,
            )
            .optional()
            .map_err(|err| StateError::from_sqlite("begin_lane_adoption: lookup", err))?;
        let Some(record) = record else {
            return Err(state_error(
                "state.not_found",
                format!("no lane replacement {replacement_id:?}"),
            ));
        };
        match record.outcome.as_str() {
            "pending" => {}
            "held" => {
                let reason = if record.outcome_reason.is_empty() {
                    "no reason recorded"
                } else {
                    record.outcome_reason.as_str()
                };
                return Err(state_error(
                    replacement_code::HELD,
                    format!(
                        "replacement {} is held (paused): {reason}; a booted successor stays \
                         fenced and the adoption (activation) is prevented",
                        record.replacement_id
                    ),
                ));
            }
            "ambiguous" => {
                return Err(state_error(
                    replacement_code::AMBIGUOUS,
                    format!(
                        "replacement {} was left ambiguous by an interrupted transition; \
                         external reconciliation is required before it can be adopted",
                        record.replacement_id
                    ),
                ));
            }
            _ => {
                return Err(state_error(
                    replacement_code::INVALIDATED,
                    format!(
                        "replacement {} was cancelled (invalidated); it can never be adopted",
                        record.replacement_id
                    ),
                ));
            }
        }
        if record.phase != "adopting" {
            return Err(state_error(
                replacement_code::ORDER,
                format!(
                    "adoption requires the `adopting` boundary (start and verify the \
                     successor first); replacement {} is at {:?}",
                    record.replacement_id, record.phase
                ),
            ));
        }
        if binding.generation != record.generation {
            return Err(state_error(
                successor_code::BINDING,
                format!(
                    "the adoption binding generation {} does not match replacement {} \
                     generation {}",
                    binding.generation, record.replacement_id, record.generation
                ),
            ));
        }
        let successor: Option<LaneSuccessorRow> = conn
            .query_row(
                "SELECT successor_id, replacement_id, lane_id, generation, role, worktree,
                        session, process, nonce, profile_key, profile_kind, kickoff_receipt,
                        delivery, attempts, evidence, evidence_digest, orchestration,
                        consumed, adopted_at, adoption_evidence, adoption_digest, created_at,
                        updated_at
                   FROM lane_successors WHERE replacement_id = ?1",
                params![replacement_id.as_str()],
                lane_successor_row_from,
            )
            .optional()
            .map_err(|err| StateError::from_sqlite("begin_lane_adoption: successor", err))?;
        let Some(successor) = successor else {
            return Err(state_error(
                successor_code::BINDING,
                format!(
                    "replacement {} has no committed successor boundary; the adoption refuses \
                     (a successor that was never started cannot be adopted)",
                    record.replacement_id
                ),
            ));
        };
        if successor.successor_id != binding.successor_id || successor.session != binding.session {
            return Err(state_error(
                successor_code::BINDING,
                format!(
                    "the adoption binding (successor {}, session {:?}) does not match the \
                     committed successor {} session {:?}",
                    binding.successor_id,
                    binding.session,
                    successor.successor_id,
                    successor.session
                ),
            ));
        }
        let checkpoint: Option<LaneCheckpointRow> = conn
            .query_row(
                "SELECT checkpoint_id, replacement_id, lane_id, generation, role,
                        observation_digest, reobservation_digest, snapshot, digest,
                        brief_digest, created_at
                   FROM lane_checkpoints WHERE replacement_id = ?1",
                params![replacement_id.as_str()],
                lane_checkpoint_row_from,
            )
            .optional()
            .map_err(|err| StateError::from_sqlite("begin_lane_adoption: checkpoint", err))?;
        let Some(checkpoint) = checkpoint else {
            return Err(state_error(
                successor_code::BINDING,
                format!(
                    "replacement {} has no committed checkpoint to compare the adoption \
                     re-query against (external reconciliation is required)",
                    record.replacement_id
                ),
            ));
        };
        let observed = adoption_observation_val(&record, observation)?;
        let differences = adoption_differences(&checkpoint.snapshot, &observed);
        Ok(LaneAdoptionPlan {
            record,
            checkpoint,
            successor,
            observation: observed,
            differences,
        })
    }

    /// Commit one adoption (issue #76): the record's `adopting` → `adopted`
    /// transition, the successor row's adoption evidence and (for
    /// orchestrator replacements) the preserved worker/reviewer
    /// orchestration block commit in ONE transaction, fenced on the exact
    /// generation/phase/outcome and on the committed successor identity. A
    /// non-empty difference list refuses here too, so reconciliation can
    /// never be skipped by a racing caller.
    #[allow(clippy::too_many_arguments)]
    pub fn commit_lane_adoption(
        &self,
        replacement_id: &str,
        generation: i64,
        successor_id: &str,
        session: &str,
        observation: &Val,
        differences: &[String],
        binding: &Val,
        reason: &str,
        at: &str,
    ) -> Result<(LaneSuccessorRow, LaneReplacementRow), StateError> {
        let outcome = self.commit_lane_adoption_inner(
            replacement_id,
            generation,
            successor_id,
            session,
            observation,
            differences,
            binding,
            reason,
            at,
        );
        if let Err(err) = &outcome {
            self.poison_on(err);
        }
        outcome
    }

    #[allow(clippy::too_many_arguments)]
    fn commit_lane_adoption_inner(
        &self,
        replacement_id: &str,
        generation: i64,
        successor_id: &str,
        session: &str,
        observation: &Val,
        differences: &[String],
        binding: &Val,
        reason: &str,
        at: &str,
    ) -> Result<(LaneSuccessorRow, LaneReplacementRow), StateError> {
        if !printable_bounded(reason, RETIREMENT_REASON_MAX) {
            return Err(state_error(
                successor_code::BINDING,
                format!(
                    "the adoption reason must be 1-{RETIREMENT_REASON_MAX} printable \
                     characters (the durable evidence summary is never truncated)"
                ),
            ));
        }
        if !differences.is_empty() {
            return Err(state_error(
                successor_code::DIFFERS,
                format!(
                    "the adoption re-query differs from the recorded handoff state in {}; \
                     reconciliation is required (a blind replay or a stale PASS is never \
                     adopted)",
                    differences.join(", ")
                ),
            ));
        }
        self.ensure_writable()?;
        {
            let mut conn = self.lock("commit_lane_adoption")?;
            let tx = conn
                .transaction()
                .map_err(|err| StateError::from_sqlite("commit_lane_adoption: begin", err))?;
            let record: Option<LaneReplacementRow> = tx
                .query_row(
                    "SELECT replacement_id, lane_id, generation, successor_generation,
                            phase, outcome, outcome_reason, source_session, source_process,
                            role, worktree, reason, created_at, updated_at
                       FROM lane_replacements WHERE replacement_id = ?1",
                    params![replacement_id],
                    lane_replacement_row_from,
                )
                .optional()
                .map_err(|err| StateError::from_sqlite("commit_lane_adoption: record", err))?;
            let Some(record) = record else {
                return Err(state_error(
                    "state.not_found",
                    format!("no lane replacement {replacement_id:?}"),
                ));
            };
            if record.phase != "adopting"
                || record.outcome != "pending"
                || record.generation != generation
            {
                return Err(lane_replacement_transition_refusal(
                    Some(&record),
                    replacement_id,
                    "adopting",
                    generation,
                ));
            }
            let successor: Option<LaneSuccessorRow> = tx
                .query_row(
                    "SELECT successor_id, replacement_id, lane_id, generation, role, worktree,
                            session, process, nonce, profile_key, profile_kind, kickoff_receipt,
                            delivery, attempts, evidence, evidence_digest, orchestration,
                            consumed, adopted_at, adoption_evidence, adoption_digest, created_at,
                            updated_at
                       FROM lane_successors WHERE replacement_id = ?1",
                    params![replacement_id],
                    lane_successor_row_from,
                )
                .optional()
                .map_err(|err| StateError::from_sqlite("commit_lane_adoption: successor", err))?;
            let Some(successor) = successor else {
                return Err(state_error(
                    successor_code::BINDING,
                    format!("replacement {replacement_id} has no committed successor boundary"),
                ));
            };
            if successor.successor_id != successor_id || successor.session != session {
                return Err(state_error(
                    successor_code::BINDING,
                    format!(
                        "the adoption does not match the committed successor {} (session \
                         {:?})",
                        successor.successor_id, successor.session
                    ),
                ));
            }
            let checkpoint: Option<LaneCheckpointRow> = tx
                .query_row(
                    "SELECT checkpoint_id, replacement_id, lane_id, generation, role,
                            observation_digest, reobservation_digest, snapshot, digest,
                            brief_digest, created_at
                       FROM lane_checkpoints WHERE replacement_id = ?1",
                    params![replacement_id],
                    lane_checkpoint_row_from,
                )
                .optional()
                .map_err(|err| StateError::from_sqlite("commit_lane_adoption: checkpoint", err))?;
            let Some(checkpoint) = checkpoint else {
                return Err(state_error(
                    successor_code::BINDING,
                    format!(
                        "replacement {replacement_id} has no committed checkpoint to bind the \
                         adoption evidence to"
                    ),
                ));
            };
            // The re-query is compared against the DURABLE snapshot, not the
            // caller's claim: a difference committed by a racing caller
            // refuses here as well. The presented document is the reduced
            // comparison contract `begin_lane_adoption` produced from the
            // validated re-query.
            let fresh_differences = adoption_differences(&checkpoint.snapshot, observation);
            if !fresh_differences.is_empty() {
                return Err(state_error(
                    successor_code::DIFFERS,
                    format!(
                        "the adoption re-query differs from the recorded handoff state in {}; \
                         reconciliation is required",
                        fresh_differences.join(", ")
                    ),
                ));
            }
            let observation_digest = sha256_hex(&canonical_bytes(observation));
            let preserved = if successor.role == "orchestrator" {
                checkpoint_orchestration_of(&checkpoint.snapshot)
            } else {
                None
            };
            let adoption = object(vec![
                ("schema", string("hf-lane-adoption/v1")),
                ("successor_id", string(&successor.successor_id)),
                ("replacement_id", string(replacement_id)),
                ("lane_id", string(&successor.lane_id)),
                ("generation", integer(successor.generation)),
                ("role", string(&successor.role)),
                ("worktree", string(&successor.worktree)),
                ("session", string(&successor.session)),
                ("process", string(&successor.process)),
                ("checkpoint_id", string(&checkpoint.checkpoint_id)),
                ("checkpoint_digest", string(&checkpoint.digest)),
                ("observation_digest", string(&observation_digest)),
                ("differences", Val::Arr(Vec::new())),
                ("binding", binding.clone()),
                ("adopted_at", string(at)),
            ]);
            let adoption_text = canonical_text(&adoption);
            let adoption_digest = sha256_hex(&canonical_bytes(&adoption));
            let orchestration_text = preserved.as_ref().map(canonical_text).unwrap_or_default();
            let consumed_text = if preserved.is_some() {
                canonical_text(&Val::Arr(Vec::new()))
            } else {
                String::new()
            };
            let affected = tx.execute(
                "UPDATE lane_successors
                    SET adoption_evidence = ?1, adoption_digest = ?2, adopted_at = ?3,
                        orchestration = ?4, consumed = ?5, updated_at = ?3
                  WHERE successor_id = ?6",
                params![
                    adoption_text,
                    adoption_digest,
                    at,
                    orchestration_text,
                    consumed_text,
                    successor.successor_id
                ],
            );
            match affected {
                Ok(1) => {}
                Ok(_) => {
                    return Err(state_error(
                        "state.conflict",
                        format!("the adoption lost its successor fence on {replacement_id}"),
                    ));
                }
                Err(err) => {
                    return Err(StateError::from_sqlite(
                        "commit_lane_adoption: successor update",
                        err,
                    ));
                }
            }
            let advanced = tx.execute(
                "UPDATE lane_replacements
                    SET phase = 'adopted', updated_at = ?1
                  WHERE replacement_id = ?2 AND phase = 'adopting'
                        AND generation = ?3 AND outcome = 'pending'",
                params![at, replacement_id, generation],
            );
            match advanced {
                Ok(1) => {}
                Ok(_) => {
                    return Err(state_error(
                        "state.conflict",
                        format!("the adoption lost its compare-and-set fence on {replacement_id}"),
                    ));
                }
                Err(err) => {
                    return Err(StateError::from_sqlite(
                        "commit_lane_adoption: transition",
                        err,
                    ));
                }
            }
            append_lane_replacement_event(
                &tx,
                replacement_id,
                Some("adopting"),
                "adopted",
                Some("pending"),
                "pending",
                reason,
                at,
            )?;
            let successor: LaneSuccessorRow = tx
                .query_row(
                    "SELECT successor_id, replacement_id, lane_id, generation, role, worktree,
                            session, process, nonce, profile_key, profile_kind, kickoff_receipt,
                            delivery, attempts, evidence, evidence_digest, orchestration,
                            consumed, adopted_at, adoption_evidence, adoption_digest, created_at,
                            updated_at
                       FROM lane_successors WHERE replacement_id = ?1",
                    params![replacement_id],
                    lane_successor_row_from,
                )
                .map_err(|err| StateError::from_sqlite("commit_lane_adoption: reread", err))?;
            let updated: LaneReplacementRow = tx
                .query_row(
                    "SELECT replacement_id, lane_id, generation, successor_generation,
                            phase, outcome, outcome_reason, source_session, source_process,
                            role, worktree, reason, created_at, updated_at
                       FROM lane_replacements WHERE replacement_id = ?1",
                    params![replacement_id],
                    lane_replacement_row_from,
                )
                .map_err(|err| {
                    StateError::from_sqlite("commit_lane_adoption: record reread", err)
                })?;
            tx.commit()
                .map_err(|err| StateError::from_sqlite("commit_lane_adoption: commit", err))?;
            Ok((successor, updated))
        }
    }

    /// Consume recorded worker completions EXACTLY ONCE after adoption
    /// (issue #76 AC6). `completions` are (event, worker) pairs; every event
    /// must be a recorded pending completion of the replacement's
    /// orchestrator checkpoint and every worker a referenced worker lane;
    /// an event consumed twice refuses, so no duplicate reviewer dispatch
    /// can ever be produced from this surface. The consumed set is durable
    /// on the successor row (a restart re-derives it). This path records;
    /// it never dispatches, spawns, or signals anything.
    pub fn consume_lane_successor_completions(
        &self,
        replacement_id: &str,
        successor_id: &str,
        completions: &[(String, String)],
        at: &str,
    ) -> Result<(LaneSuccessorRow, Vec<String>), StateError> {
        let outcome = self.consume_lane_successor_completions_inner(
            replacement_id,
            successor_id,
            completions,
            at,
        );
        if let Err(err) = &outcome {
            self.poison_on(err);
        }
        outcome
    }

    fn consume_lane_successor_completions_inner(
        &self,
        replacement_id: &str,
        successor_id: &str,
        completions: &[(String, String)],
        at: &str,
    ) -> Result<(LaneSuccessorRow, Vec<String>), StateError> {
        if completions.is_empty() || completions.len() > SUCCESSOR_COMPLETIONS_MAX {
            return Err(state_error(
                successor_code::EVENT,
                format!(
                    "one consumption request carries 1-{SUCCESSOR_COMPLETIONS_MAX} completion \
                     events"
                ),
            ));
        }
        for (event, worker) in completions {
            if !printable_bounded(event, 120) {
                return Err(state_error(
                    successor_code::EVENT,
                    "each completion event must be a bounded printable token",
                ));
            }
            if !crate::formats::is_replacement_id(worker) {
                return Err(state_error(
                    successor_code::EVENT,
                    format!(
                        "completion worker {worker:?} is not a lane replacement id \
                         (rp_ + 16 hex)"
                    ),
                ));
            }
        }
        self.ensure_writable()?;
        let consumed_events: Vec<String>;
        {
            let mut conn = self.lock("consume_lane_successor_completions")?;
            let tx = conn.transaction().map_err(|err| {
                StateError::from_sqlite("consume_lane_successor_completions: begin", err)
            })?;
            let record: Option<LaneReplacementRow> = tx
                .query_row(
                    "SELECT replacement_id, lane_id, generation, successor_generation,
                            phase, outcome, outcome_reason, source_session, source_process,
                            role, worktree, reason, created_at, updated_at
                       FROM lane_replacements WHERE replacement_id = ?1",
                    params![replacement_id],
                    lane_replacement_row_from,
                )
                .optional()
                .map_err(|err| {
                    StateError::from_sqlite("consume_lane_successor_completions: record", err)
                })?;
            let Some(record) = record else {
                return Err(state_error(
                    "state.not_found",
                    format!("no lane replacement {replacement_id:?}"),
                ));
            };
            if record.phase != "adopted" || record.outcome != "pending" {
                return Err(state_error(
                    replacement_code::ORDER,
                    format!(
                        "completions are consumed AFTER adoption; replacement {} is at {:?}/{}",
                        record.replacement_id, record.phase, record.outcome
                    ),
                ));
            }
            let successor: Option<LaneSuccessorRow> = tx
                .query_row(
                    "SELECT successor_id, replacement_id, lane_id, generation, role, worktree,
                            session, process, nonce, profile_key, profile_kind, kickoff_receipt,
                            delivery, attempts, evidence, evidence_digest, orchestration,
                            consumed, adopted_at, adoption_evidence, adoption_digest, created_at,
                            updated_at
                       FROM lane_successors WHERE replacement_id = ?1",
                    params![replacement_id],
                    lane_successor_row_from,
                )
                .optional()
                .map_err(|err| {
                    StateError::from_sqlite("consume_lane_successor_completions: successor", err)
                })?;
            let Some(successor) = successor else {
                return Err(state_error(
                    successor_code::BINDING,
                    format!("replacement {replacement_id} has no committed successor boundary"),
                ));
            };
            if successor.successor_id != successor_id {
                return Err(state_error(
                    successor_code::BINDING,
                    format!(
                        "the consumption does not match the committed successor {}",
                        successor.successor_id
                    ),
                ));
            }
            let orchestration: Val = Val::parse_json(&successor.orchestration).map_err(|_| {
                state_error(
                    successor_code::EVENT,
                    format!(
                        "successor {} is not an orchestrator successor; worker completions are \
                         never consumed outside an orchestrator replacement",
                        successor.successor_id
                    ),
                )
            })?;
            let pending: Vec<String> = orchestration
                .get("pending_events")
                .and_then(Val::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(Val::as_str)
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default();
            let workers: Vec<String> = orchestration
                .get("workers")
                .and_then(Val::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(Val::as_str)
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default();
            let mut consumed: Vec<String> = if successor.consumed.is_empty() {
                Vec::new()
            } else {
                Val::parse_json(&successor.consumed)
                    .ok()
                    .and_then(|value| {
                        value.as_array().map(|items| {
                            items
                                .iter()
                                .filter_map(Val::as_str)
                                .map(str::to_string)
                                .collect()
                        })
                    })
                    .unwrap_or_default()
            };
            for (event, worker) in completions {
                if !pending.contains(event) {
                    return Err(state_error(
                        successor_code::EVENT,
                        format!(
                            "completion event {event:?} is not a recorded pending completion \
                             of replacement {replacement_id} (a completion that was never \
                             recorded is never consumed)"
                        ),
                    ));
                }
                if !workers.contains(worker) {
                    return Err(state_error(
                        successor_code::EVENT,
                        format!(
                            "completion worker {worker} is not a referenced worker lane of \
                             replacement {replacement_id}"
                        ),
                    ));
                }
                if consumed.contains(event) {
                    return Err(state_error(
                        successor_code::EVENT_CONSUMED,
                        format!(
                            "completion event {event:?} was already consumed; consumption is \
                             exactly once (a duplicate reviewer dispatch can never be produced)"
                        ),
                    ));
                }
                consumed.push(event.clone());
            }
            let consumed_text = canonical_text(&Val::Arr(
                consumed.iter().map(|event| string(event)).collect(),
            ));
            let affected = tx.execute(
                "UPDATE lane_successors SET consumed = ?1, updated_at = ?2
                  WHERE successor_id = ?3",
                params![consumed_text, at, successor.successor_id],
            );
            match affected {
                Ok(1) => {}
                Ok(_) => {
                    return Err(state_error(
                        "state.conflict",
                        format!("the consumption lost its successor fence on {replacement_id}"),
                    ));
                }
                Err(err) => {
                    return Err(StateError::from_sqlite(
                        "consume_lane_successor_completions: update",
                        err,
                    ));
                }
            }
            tx.commit().map_err(|err| {
                StateError::from_sqlite("consume_lane_successor_completions: commit", err)
            })?;
            consumed_events = consumed;
        }
        let row = self
            .lane_successor_by_replacement(replacement_id)?
            .ok_or_else(|| state_error("state.not_found", "successor vanished after consume"))?;
        Ok((row, consumed_events))
    }

    // ---------------------------------------------------------------------
    // Journal reads (hash-chain verified)
    // ---------------------------------------------------------------------

    /// Journal records with `seq > after_seq`, ordered, up to `limit`.
    /// Returns the retained window start so callers can detect stale cursors.
    pub fn journal_tail(
        &self,
        after_seq: i64,
        limit: i64,
    ) -> Result<(i64, Vec<String>), StateError> {
        let conn = self.lock("journal_tail")?;
        let first_retained: i64 = conn
            .query_row("SELECT MIN(seq) FROM audit", [], |row| row.get(0))
            .map_err(|err| StateError::from_sqlite("journal_tail: min", err))?;
        let mut statement = conn
            .prepare("SELECT line FROM audit WHERE seq > ?1 AND seq > ?2 ORDER BY seq LIMIT ?3")
            .map_err(|err| StateError::from_sqlite("journal_tail: prepare", err))?;
        let rows = statement
            .query_map(params![after_seq, first_retained - 1, limit], |row| {
                row.get(0)
            })
            .map_err(|err| StateError::from_sqlite("journal_tail: query", err))?;
        let mut lines = Vec::new();
        for row in rows {
            lines.push(row.map_err(|err| StateError::from_sqlite("journal_tail: row", err))?);
        }
        Ok((first_retained, lines))
    }

    /// Event rows with `seq > after_seq`, ordered, up to `limit` (the
    /// subscriber replay source; a gap is answered with a snapshot).
    pub fn events_after(&self, after_seq: i64, limit: i64) -> Result<Vec<Val>, StateError> {
        let conn = self.lock("events_after")?;
        let mut statement = conn
            .prepare("SELECT event, seq, ts, data FROM events WHERE seq > ?1 ORDER BY seq LIMIT ?2")
            .map_err(|err| StateError::from_sqlite("events_after: prepare", err))?;
        let rows = statement
            .query_map(params![after_seq, limit], |row| {
                Ok(object(vec![
                    ("schema", string("hf-event/v1")),
                    ("event", string(&row.get::<_, String>(0)?)),
                    ("seq", integer(row.get(1)?)),
                    ("ts", string(&row.get::<_, String>(2)?)),
                    ("data", parse_data(&row.get::<_, String>(3)?)),
                ]))
            })
            .map_err(|err| StateError::from_sqlite("events_after: query", err))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(|err| StateError::from_sqlite("events_after: row", err))?);
        }
        Ok(out)
    }

    /// Highest event seq and first retained event seq (subscribe cursor).
    /// `None` for both means the event stream is empty.
    pub fn event_bounds(&self) -> Result<(Option<i64>, Option<i64>), StateError> {
        let conn = self.lock("event_bounds")?;
        let max: Option<i64> = conn
            .query_row("SELECT MAX(seq) FROM events", [], |row| row.get(0))
            .optional()
            .map_err(|err| StateError::from_sqlite("event_bounds: max", err))?
            .flatten();
        let min: Option<i64> = conn
            .query_row("SELECT MIN(seq) FROM events", [], |row| row.get(0))
            .optional()
            .map_err(|err| StateError::from_sqlite("event_bounds: min", err))?
            .flatten();
        Ok((max, min))
    }

    /// A state.snapshot event document at the current event seq (0 when the
    /// stream is empty; real event seqs start at 1).
    pub fn snapshot_event(&self) -> Result<Val, StateError> {
        let (epoch, audit_seq, event_seq, _) = self.summary()?;
        Ok(object(vec![
            ("schema", string("hf-event/v1")),
            ("event", string("state.snapshot")),
            ("seq", integer(event_seq)),
            ("ts", string(&time::rfc3339_now())),
            (
                "data",
                object(vec![
                    ("epoch", integer(epoch)),
                    ("journal_seq", integer(audit_seq)),
                    ("event_seq", integer(event_seq)),
                ]),
            ),
        ]))
    }

    /// Current summary for status RPC / doctor.
    pub fn summary(&self) -> Result<(i64, i64, i64, i64), StateError> {
        let conn = self.lock("summary")?;
        let epoch = conn
            .query_row("SELECT COALESCE(MAX(epoch), 0) FROM epoch", [], |row| {
                row.get(0)
            })
            .map_err(|err| StateError::from_sqlite("summary: epoch", err))?;
        let audit_seq: i64 = conn
            .query_row("SELECT COALESCE(MAX(seq), 0) FROM audit", [], |row| {
                row.get(0)
            })
            .map_err(|err| StateError::from_sqlite("summary: audit", err))?;
        let event_seq: i64 = conn
            .query_row("SELECT COALESCE(MAX(seq), 0) FROM events", [], |row| {
                row.get(0)
            })
            .map_err(|err| StateError::from_sqlite("summary: events", err))?;
        Ok((epoch, audit_seq, event_seq, SCHEMA_VERSION))
    }

    /// Rich summary for the daemon `status` RPC.
    pub fn status_summary(&self) -> Result<StateSummary, StateError> {
        let (epoch, audit_seq, event_seq, schema_version) = self.summary()?;
        let conn = self.lock("status_summary")?;
        let active_grants: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM grants WHERE status = 'active'",
                [],
                |row| row.get(0),
            )
            .map_err(|err| StateError::from_sqlite("status_summary: grants", err))?;
        let pending_claims: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM idempotency WHERE status = 'claimed'",
                [],
                |row| row.get(0),
            )
            .map_err(|err| StateError::from_sqlite("status_summary: claims", err))?;
        Ok(StateSummary {
            epoch,
            audit_seq,
            event_seq,
            schema_version,
            active_grants,
            pending_claims,
            poisoned: self.is_poisoned(),
        })
    }

    // ---------------------------------------------------------------------
    // Audit mirror (JSONL journal file, bounded) and chain verification
    // ---------------------------------------------------------------------

    /// Verify the hash chain over the retained window (plus genesis).
    /// A broken chain means the audit table itself was tampered with and the
    /// daemon must fail closed.
    pub fn verify_chain(&self) -> Result<(), StateError> {
        let conn = self.lock("verify_chain")?;
        let mut statement = conn
            .prepare(
                "SELECT seq, action, target, idempotency_key, plan_hash, grant_id, epoch,
                        recorded_before_mutation, at, line, prev_hash, record_hash
                   FROM audit ORDER BY seq",
            )
            .map_err(|err| StateError::from_sqlite("verify_chain: prepare", err))?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, bool>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, String>(11)?,
                ))
            })
            .map_err(|err| StateError::from_sqlite("verify_chain: query", err))?;
        let mut previous_hash: Option<String> = None;
        for row in rows {
            let (
                seq,
                action,
                target,
                idempotency_key,
                plan_hash,
                grant_id,
                epoch,
                recorded_before_mutation,
                at,
                line,
                prev_hash,
                record_hash,
            ) = row.map_err(|err| StateError::from_sqlite("verify_chain: row", err))?;
            // The stored canonical line must match the row's own columns
            // (tampering with any journal column is a chain break).
            let expected_doc = canonical_text(&object(vec![
                ("schema", string("hf-audit/v1")),
                ("seq", integer(seq)),
                ("action", string(&action)),
                ("target", string(&target)),
                ("idempotency_key", string(&idempotency_key)),
                (
                    "plan_hash",
                    plan_hash.map(|h| string(&h)).unwrap_or_else(null),
                ),
                (
                    "grant_id",
                    grant_id.map(|g| string(&g)).unwrap_or_else(null),
                ),
                ("epoch", integer(epoch)),
                ("recorded_before_mutation", bool_(recorded_before_mutation)),
                ("at", string(&at)),
            ]));
            if line != expected_doc {
                return Err(state_error(
                    "state.audit_tampered",
                    format!("audit chain broken at seq {seq}: column/line mismatch"),
                ));
            }
            let expected_prev = previous_hash.as_deref().unwrap_or("");
            if prev_hash != expected_prev {
                return Err(state_error(
                    "state.audit_tampered",
                    format!("audit chain broken at seq {seq}: prev_hash mismatch"),
                ));
            }
            let computed = sha256_hex(&[line.as_bytes(), prev_hash.as_bytes()].concat());
            if computed != record_hash {
                return Err(state_error(
                    "state.audit_tampered",
                    format!("audit chain broken at seq {seq}: record hash mismatch"),
                ));
            }
            previous_hash = Some(record_hash);
        }
        Ok(())
    }

    /// Rewrite the bounded JSONL mirror file from the table (called at
    /// startup when the mirror is missing or drifted; the table is the
    /// authority). Returns whether the file was rebuilt.
    pub fn rebuild_audit_mirror(&self, mirror_path: &Path) -> Result<bool, StateError> {
        let conn = self.lock("rebuild_audit_mirror")?;
        let mut statement = conn
            .prepare("SELECT line FROM audit ORDER BY seq")
            .map_err(|err| StateError::from_sqlite("rebuild_audit_mirror: prepare", err))?;
        let rows = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|err| StateError::from_sqlite("rebuild_audit_mirror: query", err))?;
        let mut lines: Vec<String> = Vec::new();
        for row in rows {
            lines.push(
                row.map_err(|err| StateError::from_sqlite("rebuild_audit_mirror: row", err))?,
            );
        }
        let rebuilt = mirror_matches(mirror_path, &lines).is_err();
        if rebuilt {
            write_lines_atomic(mirror_path, &lines)?;
        }
        Ok(rebuilt)
    }

    /// Rewrite the bounded JSONL events mirror from the table (same
    /// authority/rebuild semantics as the audit mirror; the mirror is a
    /// convenience for read-only consumers, never the source of truth).
    pub fn rebuild_events_mirror(&self, mirror_path: &Path) -> Result<bool, StateError> {
        let conn = self.lock("rebuild_events_mirror")?;
        let mut statement = conn
            .prepare("SELECT event, seq, ts, data FROM events ORDER BY seq")
            .map_err(|err| StateError::from_sqlite("rebuild_events_mirror: prepare", err))?;
        let rows = statement
            .query_map([], |row| {
                Ok(canonical_text(&object(vec![
                    ("schema", string("hf-event/v1")),
                    ("event", string(&row.get::<_, String>(0)?)),
                    ("seq", integer(row.get(1)?)),
                    ("ts", string(&row.get::<_, String>(2)?)),
                    ("data", parse_data(&row.get::<_, String>(3)?)),
                ])))
            })
            .map_err(|err| StateError::from_sqlite("rebuild_events_mirror: query", err))?;
        let mut lines: Vec<String> = Vec::new();
        for row in rows {
            lines.push(
                row.map_err(|err| StateError::from_sqlite("rebuild_events_mirror: row", err))?,
            );
        }
        let rebuilt = mirror_matches(mirror_path, &lines).is_err();
        if rebuilt {
            write_lines_atomic(mirror_path, &lines)?;
        }
        Ok(rebuilt)
    }

    // ---------------------------------------------------------------------
    // Internals
    // ---------------------------------------------------------------------

    /// Refuse writes after a prior write failure (fail closed, AC5). The
    /// refusal NAMES the write that failed (item 4b of issue #144): the
    /// measured trigger was a data volume at 99% full, where the fail-closed
    /// behaviour was correct but "writes previously failed" left the operator
    /// nothing to act on.
    fn ensure_writable(&self) -> Result<(), StateError> {
        if self.poisoned.load(Ordering::SeqCst) {
            let cause = self
                .poison_cause
                .lock()
                .ok()
                .and_then(|cause| cause.clone())
                .unwrap_or_else(|| "cause not recorded".to_string());
            return Err(state_error(
                "state.poisoned",
                format!(
                    "state/audit writes previously failed: {cause}; mutations are refused until \
                     the daemon restarts"
                ),
            ));
        }
        Ok(())
    }

    /// Flip the fail-closed flag when a write-class failure escapes a
    /// mutation, remembering WHICH write failed first (item 4b of issue
    /// #144). Read-only queries keep working; every later mutation is refused
    /// until the process restarts.
    fn poison_on(&self, err: &StateError) {
        let write_class = matches!(
            err.code,
            "state.write_full"
                | "state.write_io"
                | "state.corrupt"
                | "state.readonly"
                | "state.busy"
        );
        if write_class {
            self.poisoned.store(true, Ordering::SeqCst);
            if let Ok(mut cause) = self.poison_cause.lock()
                && cause.is_none()
            {
                *cause = Some(format!("{}: {}", err.code, err.message));
            }
        }
    }

    /// Append an audit record inside an existing transaction. The caller
    /// decides the transaction boundary (intent + claim vs resolution).
    #[allow(clippy::too_many_arguments)]
    fn append_audit_locked(
        &self,
        conn: &rusqlite::Transaction<'_>,
        action: &str,
        target: &str,
        key: &str,
        plan_hash: Option<&str>,
        grant_id: Option<&str>,
    ) -> Result<AuditRow, StateError> {
        let epoch: i64 = conn
            .query_row("SELECT COALESCE(MAX(epoch), 1) FROM epoch", [], |row| {
                row.get(0)
            })
            .map_err(|err| StateError::from_sqlite("append_audit: epoch", err))?;
        let seq: i64 = conn
            .query_row("SELECT COALESCE(MAX(seq), -1) + 1 FROM audit", [], |row| {
                row.get(0)
            })
            .map_err(|err| StateError::from_sqlite("append_audit: seq", err))?;
        let prev_hash: String = conn
            .query_row(
                "SELECT record_hash FROM audit ORDER BY seq DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|err| StateError::from_sqlite("append_audit: prev", err))?
            .unwrap_or_default();
        // ONE clock read for the record: the stored `line` and the `at`
        // column must be the same instant, or the next open's chain
        // verification refuses the row (column/line mismatch) — two reads
        // could straddle a second boundary.
        let at = time::rfc3339_now();
        let doc = object(vec![
            ("schema", string("hf-audit/v1")),
            ("seq", integer(seq)),
            ("action", string(action)),
            ("target", string(target)),
            ("idempotency_key", string(key)),
            ("plan_hash", plan_hash.map(string).unwrap_or_else(null)),
            ("grant_id", grant_id.map(string).unwrap_or_else(null)),
            ("epoch", integer(epoch)),
            // A mutate.* record is journaled *before* its effect; every
            // other record class (outcome.*, reconcile.*, state.genesis)
            // journals after the fact and must say so (the schema refuses
            // mutate.* records that claim recorded_before_mutation:false).
            (
                "recorded_before_mutation",
                bool_(action.starts_with("mutate.")),
            ),
            ("at", string(&at)),
        ]);
        let line = canonical_text(&doc);
        let record_hash = sha256_hex(&[line.as_bytes(), prev_hash.as_bytes()].concat());
        conn.execute(
            "INSERT INTO audit (seq, action, target, idempotency_key, plan_hash, grant_id, epoch,
                                recorded_before_mutation, at, prev_hash, record_hash, line)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                seq,
                action,
                target,
                key,
                plan_hash,
                grant_id,
                epoch,
                action.starts_with("mutate."),
                at,
                prev_hash,
                record_hash,
                line
            ],
        )
        .map_err(|err| StateError::from_sqlite("append_audit: insert", err))?;
        prune_audit_locked(conn, self.retention)?;
        let event_data = object(vec![("action", string(action)), ("seq", integer(seq))]);
        let event_seq = append_event_locked(conn, self.retention, "journal.appended", &event_data)?;
        Ok(AuditRow {
            seq,
            epoch,
            line,
            record_hash,
            event_seq,
        })
    }
}

/// Parse one recorded dispatch-refusal target (`<run>:<step>:<code>`) into
/// its typed record. A target that does not belong to `instance_id` or does
/// not carry all three parts is not readable evidence and yields `None`
/// (never a guessed step or code).
pub(crate) fn dispatch_refusal_of(
    instance_id: &str,
    target: &str,
    at: &str,
) -> Option<SupervisionDispatchRefusal> {
    let rest = target.strip_prefix(instance_id)?.strip_prefix(':')?;
    let (step, code) = rest.split_once(':')?;
    if step.is_empty() || code.is_empty() {
        return None;
    }
    Some(SupervisionDispatchRefusal {
        step: step.to_string(),
        code: code.to_string(),
        at: at.to_string(),
    })
}

/// Read a grant row out of an `hf-grant/v1` document (validated by the
/// caller through [`crate::schema::validate_doc`]).
fn grant_row_from_doc(doc: &Val) -> Result<GrantRow, StateError> {
    let get = |key: &str| -> Result<String, StateError> {
        doc.get(key)
            .and_then(Val::as_str)
            .map(str::to_string)
            .ok_or_else(|| state_error("state.grant_invalid", format!("grant missing {key}")))
    };
    let issue = doc
        .get("issue")
        .ok_or_else(|| state_error("state.grant_invalid", "grant missing issue"))?;
    let issue_number = issue
        .get("number")
        .and_then(Val::as_int)
        .ok_or_else(|| state_error("state.grant_invalid", "issue.number missing"))?;
    let issue_revision = issue
        .get("revision")
        .and_then(Val::as_str)
        .ok_or_else(|| state_error("state.grant_invalid", "issue.revision missing"))?;
    let caps_text = match doc.get("caps") {
        Some(Val::Arr(items)) => {
            let parts: Vec<String> = items
                .iter()
                .filter_map(Val::as_str)
                .map(str::to_string)
                .collect();
            canonical_text(&Val::Arr(parts.iter().map(|p| string(p)).collect()))
        }
        _ => {
            return Err(state_error(
                "state.grant_invalid",
                "grant.caps must be an array",
            ));
        }
    };
    Ok(GrantRow {
        grant_id: get("grant_id")?,
        repository: get("repository")?,
        issue_number,
        issue_revision: issue_revision.to_string(),
        workflow_hash: get("workflow_hash")?,
        policy_hash: get("policy_hash")?,
        phase: get("phase")?,
        scope: get("scope")?,
        caps: caps_text,
        expires_at: get("expires_at")?,
        state_epoch: doc
            .get("state_epoch")
            .and_then(Val::as_int)
            .ok_or_else(|| state_error("state.grant_invalid", "state_epoch missing"))?,
        status: "active".to_string(),
        created_at: get("created_at")?,
    })
}

/// Every in-flight step claim (`method:"apply"`, status `claimed`) as
/// `(instance_id, step)` from its recorded request line. An unreadable
/// claimed line is reported as `("*", "")`: its attribution is unknown, so
/// no run may claim a safe boundary while it exists (fail closed).
fn in_flight_steps_locked(conn: &Connection) -> Result<Vec<(String, String)>, StateError> {
    let mut statement = conn
        .prepare("SELECT method, request_line FROM idempotency WHERE status = 'claimed'")
        .map_err(|err| StateError::from_sqlite("in_flight_steps: prepare", err))?;
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(|err| StateError::from_sqlite("in_flight_steps: query", err))?;
    let mut out = Vec::new();
    for row in rows {
        let (method, line) =
            row.map_err(|err| StateError::from_sqlite("in_flight_steps: row", err))?;
        if method != "apply" {
            continue;
        }
        match Val::parse_json(&line) {
            Ok(request) => {
                let params = request.get("params").cloned().unwrap_or_else(null);
                let instance = params
                    .get("instance_id")
                    .and_then(Val::as_str)
                    .unwrap_or("")
                    .to_string();
                let step = params
                    .get("step")
                    .and_then(Val::as_str)
                    .unwrap_or("")
                    .to_string();
                out.push((instance, step));
            }
            Err(_) => out.push(("*".to_string(), String::new())),
        }
    }
    Ok(out)
}

/// Map one grant row (the column order `grant_by_id` and the release
/// transaction both use).
fn grant_row_from(row: &rusqlite::Row<'_>) -> rusqlite::Result<GrantRow> {
    Ok(GrantRow {
        grant_id: row.get(0)?,
        repository: row.get(1)?,
        issue_number: row.get(2)?,
        issue_revision: row.get(3)?,
        workflow_hash: row.get(4)?,
        policy_hash: row.get(5)?,
        phase: row.get(6)?,
        scope: row.get(7)?,
        caps: row.get(8)?,
        expires_at: row.get(9)?,
        state_epoch: row.get(10)?,
        status: row.get(11)?,
        created_at: row.get(12)?,
    })
}

/// The next unconsumed bounded retry authorization of one run as
/// `(step_id, retry_id)`, oldest first (issue #146: a release refuses while
/// one exists, so an authorization is never burned by a bookkeeping
/// operation).
fn unconsumed_retry_locked(
    conn: &Connection,
    instance_id: &str,
) -> Result<Option<(String, String)>, StateError> {
    conn.query_row(
        "SELECT step_id, retry_id FROM run_retries
          WHERE instance_id = ?1 AND consumed_at = ''
          ORDER BY step_id, attempt LIMIT 1",
        params![instance_id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )
    .optional()
    .map_err(|err| StateError::from_sqlite("unconsumed_retry: query", err))
}

/// Shared SELECT for instance rows (m0002 columns).
fn instance_select_sql() -> String {
    // The issue #86 pause columns are APPENDED after the historical
    // 22-column shape: every projection that predates them (the board page
    // keeps its own SELECT list) still decodes through
    // [`instance_row_from`] — an absent trailing column means "no pause
    // recorded" (see the optional reads there).
    "SELECT instance_id, repository, workflow_id, workflow_hash, policy_hash, grant_id,
            issue_number, issue_revision, phase, scope, caps, current_node,
            normal_rounds, recovery_rounds, human_queue, terminal_blockers,
            paused, resume_digest, state_epoch, status, created_at, updated_at,
            pause_requested, pause_reason, pause_requested_at
       FROM instances"
        .to_string()
}

/// Map one SQLite row onto [`InstanceRow`] (column order of
/// [`instance_select_sql`]; the three trailing issue #86 pause columns are
/// optional so the historical 22-column projections keep decoding).
fn instance_row_from(row: &rusqlite::Row<'_>) -> rusqlite::Result<InstanceRow> {
    Ok(InstanceRow {
        instance_id: row.get(0)?,
        repository: row.get(1)?,
        workflow_id: row.get(2)?,
        workflow_hash: row.get(3)?,
        policy_hash: row.get(4)?,
        grant_id: row.get(5)?,
        issue_number: row.get(6)?,
        issue_revision: row.get(7)?,
        phase: row.get(8)?,
        scope: row.get(9)?,
        caps: row.get(10)?,
        current_node: row.get(11)?,
        normal_rounds: row.get(12)?,
        recovery_rounds: row.get(13)?,
        human_queue: row.get(14)?,
        terminal_blockers: row.get(15)?,
        paused: row.get(16)?,
        resume_digest: row.get(17)?,
        state_epoch: row.get(18)?,
        status: row.get(19)?,
        created_at: row.get(20)?,
        updated_at: row.get(21)?,
        pause_requested: optional_column::<i64>(row, 22).unwrap_or(0) == 1,
        pause_reason: optional_column::<String>(row, 23).unwrap_or_default(),
        pause_requested_at: optional_column::<String>(row, 24).unwrap_or_default(),
    })
}

/// Read one column of a row that may not carry it at all (a historical
/// projection whose SELECT list predates the column): `None` when the index
/// is out of range, the column is NULL, or it holds an unexpected type.
fn optional_column<T: rusqlite::types::FromSql>(
    row: &rusqlite::Row<'_>,
    index: usize,
) -> Option<T> {
    row.get::<_, Option<T>>(index).ok().flatten()
}

/// Map one SQLite row onto [`EvidenceRow`] (column order of the evidence
/// SELECTs in [`State::evidence_by_id`]/[`State::evidence_for_instance`]).
fn evidence_row_from(row: &rusqlite::Row<'_>) -> rusqlite::Result<EvidenceRow> {
    Ok(EvidenceRow {
        evidence_id: row.get(0)?,
        instance_id: row.get(1)?,
        repository: row.get(2)?,
        feature_head: row.get(3)?,
        integration_base: row.get(4)?,
        workflow_hash: row.get(5)?,
        policy_hash: row.get(6)?,
        verdict: row.get(7)?,
        reviewer: row.get(8)?,
        checks: row.get(9)?,
        created_at: row.get(10)?,
    })
}

/// Map one SQLite row onto [`ScheduleRow`] (column order of the schedules
/// SELECTs in [`State::list_schedules`]/[`State::schedule_by_id`]).
fn schedule_row_from(row: &rusqlite::Row<'_>) -> rusqlite::Result<ScheduleRow> {
    Ok(ScheduleRow {
        schedule_id: row.get(0)?,
        state_epoch: row.get(1)?,
        enabled: row.get(2)?,
        next_run_at: row.get(3)?,
        created_at: row.get(4)?,
        doc: row.get(5)?,
        updated_at: row.get(6)?,
    })
}

/// One schedule row as an `hf-rpc`-facing value (list_schedules RPC shape;
/// the `doc` field is the parsed canonical hf-schedule/v1 document or null).
pub fn schedule_val(row: &ScheduleRow) -> Val {
    object(vec![
        ("schedule_id", string(&row.schedule_id)),
        ("state_epoch", integer(row.state_epoch)),
        ("enabled", bool_(row.enabled)),
        (
            "next_run_at",
            row.next_run_at.as_deref().map(string).unwrap_or_else(null),
        ),
        ("created_at", string(&row.created_at)),
        ("updated_at", string(&row.updated_at)),
        ("doc", Val::parse_json(&row.doc).unwrap_or_else(|_| null())),
    ])
}

/// Map one SQLite row onto [`LaneReplacementRow`] (column order of the
/// lane_replacements SELECTs).
fn lane_replacement_row_from(row: &rusqlite::Row<'_>) -> rusqlite::Result<LaneReplacementRow> {
    Ok(LaneReplacementRow {
        replacement_id: row.get(0)?,
        lane_id: row.get(1)?,
        generation: row.get(2)?,
        successor_generation: row.get(3)?,
        phase: row.get(4)?,
        outcome: row.get(5)?,
        outcome_reason: row.get(6)?,
        source_session: row.get(7)?,
        source_process: row.get(8)?,
        role: row.get(9)?,
        worktree: row.get(10)?,
        reason: row.get(11)?,
        created_at: row.get(12)?,
        updated_at: row.get(13)?,
    })
}

/// Read the bound target-profile plan of one replacement record (issue #77)
/// on an open connection: `None` when the replacement was requested unbound.
fn lane_replacement_profile_of(
    conn: &rusqlite::Connection,
    replacement_id: &str,
) -> Result<Option<LaneReplacementProfileRow>, StateError> {
    conn.query_row(
        "SELECT replacement_id, profile, revision, created_at
           FROM lane_replacement_profiles WHERE replacement_id = ?1",
        params![replacement_id],
        |row| {
            Ok(LaneReplacementProfileRow {
                replacement_id: row.get(0)?,
                profile: row.get(1)?,
                revision: row.get(2)?,
                created_at: row.get(3)?,
            })
        },
    )
    .optional()
    .map_err(|err| StateError::from_sqlite("lane_replacement_profile: query", err))
}

/// One bound replacement profile plan as an RPC-facing value (issue #77):
/// the canonical document (parsed) plus the review revision and row time.
pub fn lane_replacement_profile_val(row: &LaneReplacementProfileRow) -> Val {
    let profile = Val::parse_json(&row.profile)
        .unwrap_or_else(|_| object(vec![("canonical", string(&row.profile))]));
    object(vec![
        ("profile", profile),
        ("revision", string(&row.revision)),
        ("created_at", string(&row.created_at)),
    ])
}

/// The parsed retirement request: the record identity, the grant-style
/// binding and the immediate pre-stop quiescence recheck.
struct RetirementRequest {
    replacement_id: String,
    binding: RetirementBinding,
    recheck: RetirementRecheck,
}

/// Parse one retirement request's params. Every bound value and every
/// recheck field is required and bounded. The binding contract is closed: a
/// missing, invalid or unknown binding field refuses
/// (`refusal.retirement.binding`). The recheck contract is closed too, but
/// its unknown/missing quiescence evidence is a typed HOLD
/// (`refusal.retirement.held`) — an unknown child or process state is never
/// inferred, and nothing is signalled to obtain quiescence.
fn retirement_request(params: &Val) -> Result<RetirementRequest, StateError> {
    let replacement_id = match params.get("replacement_id").and_then(Val::as_str) {
        Some(text) if crate::formats::is_replacement_id(text) => text.to_string(),
        _ => {
            return Err(state_error(
                retirement_code::BINDING,
                "a retirement requires params.replacement_id (rp_ + 16 hex)",
            ));
        }
    };
    let binding = match params.get("binding") {
        Some(Val::Obj(map)) => map,
        _ => {
            return Err(state_error(
                retirement_code::BINDING,
                "a retirement requires params.binding (object: generation, session, process, \
                 checkpoint_digest)",
            ));
        }
    };
    for key in binding.keys() {
        if !["generation", "session", "process", "checkpoint_digest"].contains(&key.as_str()) {
            return Err(state_error(
                retirement_code::BINDING,
                format!("binding carries unknown field {key:?}; the binding contract is closed"),
            ));
        }
    }
    let generation = match binding.get("generation").and_then(Val::as_int) {
        Some(generation) if generation >= 1 => generation,
        _ => {
            return Err(state_error(
                retirement_code::BINDING,
                "binding.generation must be a positive integer",
            ));
        }
    };
    let session = match binding.get("session").and_then(Val::as_str) {
        Some(text) if crate::formats::is_actor(text) => text.to_string(),
        _ => {
            return Err(state_error(
                retirement_code::BINDING,
                "binding.session must be the source session identity (actor)",
            ));
        }
    };
    let process = match binding.get("process").and_then(Val::as_str) {
        Some(text) if crate::formats::is_actor(text) => text.to_string(),
        _ => {
            return Err(state_error(
                retirement_code::BINDING,
                "binding.process must be the source process identity (actor)",
            ));
        }
    };
    let checkpoint_digest = match binding.get("checkpoint_digest").and_then(Val::as_str) {
        Some(text) if crate::formats::is_hex64(text) => text.to_string(),
        _ => {
            return Err(state_error(
                retirement_code::BINDING,
                "binding.checkpoint_digest must be the committed checkpoint digest (64-hex \
                 sha256)",
            ));
        }
    };
    let recheck = match params.get("recheck") {
        Some(Val::Obj(map)) => map,
        _ => {
            return Err(state_error(
                retirement_code::HELD,
                "a retirement requires params.recheck (the immediate pre-stop quiescence \
                 recheck)",
            ));
        }
    };
    for key in recheck.keys() {
        if !["observed_at", "session", "process", "children", "active"].contains(&key.as_str()) {
            return Err(state_error(
                retirement_code::HELD,
                format!(
                    "the recheck carries unknown field {key:?}; the recheck contract is \
                         closed"
                ),
            ));
        }
    }
    let observed_at = match recheck.get("observed_at").and_then(Val::as_str) {
        Some(text) if crate::formats::is_rfc3339_seconds_z(text) => text.to_string(),
        _ => {
            return Err(state_error(
                retirement_code::HELD,
                "recheck.observed_at must be an RFC3339 UTC (seconds, Z) timestamp (unknown \
                 evidence holds)",
            ));
        }
    };
    let recheck_session = match recheck.get("session").and_then(Val::as_str) {
        Some(text) if crate::formats::is_actor(text) => text.to_string(),
        _ => {
            return Err(state_error(
                retirement_code::HELD,
                "recheck.session must be the observed source session identity (unknown \
                 evidence holds)",
            ));
        }
    };
    let recheck_process = match recheck.get("process") {
        Some(Val::Null) => None,
        Some(Val::Str(text)) if crate::formats::is_actor(text) => Some(text.to_string()),
        _ => {
            return Err(state_error(
                retirement_code::HELD,
                "recheck.process must be the observed process identity or null (an unknown \
                 process identity holds; nothing is signalled)",
            ));
        }
    };
    let child_items = match recheck.get("children") {
        Some(Val::Arr(items)) => items,
        _ => {
            return Err(state_error(
                retirement_code::HELD,
                "recheck.children must be an array of observed child commands (unknown \
                 evidence holds)",
            ));
        }
    };
    if child_items.len() > RETIREMENT_RECHECK_CHILDREN_MAX {
        return Err(state_error(
            retirement_code::HELD,
            format!(
                "recheck.children carries {} entries; at most \
                 {RETIREMENT_RECHECK_CHILDREN_MAX} are considered (unknown evidence holds)",
                child_items.len()
            ),
        ));
    }
    let mut children = Vec::new();
    for item in child_items {
        let Val::Obj(entry) = item else {
            return Err(state_error(
                retirement_code::HELD,
                "every recheck child entry must be an object (command, state)",
            ));
        };
        for key in entry.keys() {
            if !["command", "state"].contains(&key.as_str()) {
                return Err(state_error(
                    retirement_code::HELD,
                    format!(
                        "a recheck child entry carries unknown field {key:?}; the child \
                             contract is closed"
                    ),
                ));
            }
        }
        let command = match entry.get("command").and_then(Val::as_str) {
            Some(text) if printable_bounded(text, RETIREMENT_CHILD_COMMAND_MAX) => text.to_string(),
            _ => {
                return Err(state_error(
                    retirement_code::HELD,
                    format!(
                        "a recheck child command must be a non-empty printable string of at \
                         most {RETIREMENT_CHILD_COMMAND_MAX} characters (unknown evidence holds)"
                    ),
                ));
            }
        };
        let state = match entry.get("state").and_then(Val::as_str) {
            Some(text) if CHECKPOINT_CHILD_STATES.contains(&text) => text.to_string(),
            _ => {
                return Err(state_error(
                    retirement_code::HELD,
                    format!(
                        "a recheck child state must be one of {CHECKPOINT_CHILD_STATES:?} \
                         (unknown child activity holds)"
                    ),
                ));
            }
        };
        children.push((command, state));
    }
    let active = match recheck.get("active") {
        Some(Val::Bool(active)) => *active,
        _ => {
            return Err(state_error(
                retirement_code::HELD,
                "recheck.active must be a boolean (unknown execution evidence holds)",
            ));
        }
    };
    Ok(RetirementRequest {
        replacement_id,
        binding: RetirementBinding {
            generation,
            session,
            process,
            checkpoint_digest,
        },
        recheck: RetirementRecheck {
            observed_at,
            session: recheck_session,
            process: recheck_process,
            children,
            active,
        },
    })
}

/// Classify a refused lane-replacement transition against the fresh record:
/// held/ambiguous/cancelled outcomes, stale generation, and invalid order
/// each get their own typed refusal code (never a generic error).
fn lane_replacement_transition_refusal(
    row: Option<&LaneReplacementRow>,
    replacement_id: &str,
    expected_phase: &str,
    presented_generation: i64,
) -> StateError {
    let Some(row) = row else {
        return state_error(
            "state.not_found",
            format!("no lane replacement {replacement_id:?}"),
        );
    };
    if row.outcome == "held" {
        let reason = if row.outcome_reason.is_empty() {
            "no reason recorded"
        } else {
            row.outcome_reason.as_str()
        };
        return state_error(
            replacement_code::HELD,
            format!("replacement {replacement_id} is held (paused): {reason}"),
        );
    }
    if row.outcome == "ambiguous" {
        return state_error(
            replacement_code::AMBIGUOUS,
            format!(
                "replacement {replacement_id} was left ambiguous by an interrupted transition; \
                 external reconciliation is required before it can advance"
            ),
        );
    }
    if row.outcome == "cancelled" {
        return state_error(
            replacement_code::INVALIDATED,
            format!(
                "replacement {replacement_id} was cancelled (invalidated); it can never advance"
            ),
        );
    }
    if row.generation != presented_generation {
        return state_error(
            replacement_code::STALE,
            format!(
                "presented generation {presented_generation} does not match replacement \
                 {replacement_id} generation {}",
                row.generation
            ),
        );
    }
    if row.phase != expected_phase {
        let next = next_allowed_phase(&row.phase).unwrap_or("none");
        return state_error(
            replacement_code::ORDER,
            format!(
                "presented phase {expected_phase:?} is not the current phase {:?} (next allowed: {next})",
                row.phase
            ),
        );
    }
    state_error(
        replacement_code::ORDER,
        format!(
            "replacement {replacement_id} is at {:?}; no phase follows it",
            row.phase
        ),
    )
}

/// Classify a refused hold against the fresh record (already-held,
/// cancelled, ambiguous, or nothing to hold).
fn lane_replacement_outcome_refusal(row: &LaneReplacementRow, verb: &str) -> StateError {
    if row.outcome == "held" {
        let reason = if row.outcome_reason.is_empty() {
            "no reason recorded"
        } else {
            row.outcome_reason.as_str()
        };
        return state_error(
            replacement_code::HELD,
            format!(
                "replacement {} is already held (paused): {reason}",
                row.replacement_id
            ),
        );
    }
    if row.outcome == "ambiguous" {
        return state_error(
            replacement_code::AMBIGUOUS,
            format!(
                "replacement {} is ambiguous (interrupted transition); external reconciliation \
                 is required",
                row.replacement_id
            ),
        );
    }
    if row.outcome == "cancelled" {
        return state_error(
            replacement_code::INVALIDATED,
            format!(
                "replacement {} was cancelled; it cannot be {verb}ed again",
                row.replacement_id
            ),
        );
    }
    state_error(
        replacement_code::ORDER,
        format!(
            "replacement {} is at {:?}; there is nothing to {verb}",
            row.replacement_id, row.phase
        ),
    )
}

/// Append one lane replacement transition-history row inside the caller's
/// transaction (record writes and their history commit atomically).
#[allow(clippy::too_many_arguments)]
fn append_lane_replacement_event(
    conn: &rusqlite::Transaction<'_>,
    replacement_id: &str,
    from_phase: Option<&str>,
    to_phase: &str,
    from_outcome: Option<&str>,
    to_outcome: &str,
    reason: &str,
    at: &str,
) -> Result<i64, StateError> {
    let seq: i64 = conn
        .query_row(
            "SELECT COALESCE(MAX(seq), 0) + 1 FROM lane_replacement_events",
            [],
            |row| row.get(0),
        )
        .map_err(|err| StateError::from_sqlite("replacement event: seq", err))?;
    conn.execute(
        "INSERT INTO lane_replacement_events (seq, replacement_id, from_phase, to_phase,
            from_outcome, to_outcome, reason, at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            seq,
            replacement_id,
            from_phase,
            to_phase,
            from_outcome,
            to_outcome,
            reason,
            at
        ],
    )
    .map_err(|err| StateError::from_sqlite("replacement event: insert", err))?;
    Ok(seq)
}

/// One lane replacement record as an RPC-facing value; `next_allowed` is
/// the precise next legal transition (null when the record cannot advance).
pub fn lane_replacement_val(row: &LaneReplacementRow) -> Val {
    let next_allowed = if row.outcome == "pending" {
        next_allowed_phase(&row.phase)
    } else {
        None
    };
    object(vec![
        ("replacement_id", string(&row.replacement_id)),
        ("lane_id", string(&row.lane_id)),
        ("generation", integer(row.generation)),
        ("successor_generation", integer(row.successor_generation)),
        ("phase", string(&row.phase)),
        ("outcome", string(&row.outcome)),
        ("outcome_reason", string(&row.outcome_reason)),
        (
            "next_allowed",
            next_allowed.map(string).unwrap_or_else(null),
        ),
        (
            "source",
            object(vec![
                ("session", string(&row.source_session)),
                ("process", string(&row.source_process)),
                ("role", string(&row.role)),
                ("worktree", string(&row.worktree)),
            ]),
        ),
        ("reason", string(&row.reason)),
        ("created_at", string(&row.created_at)),
        ("updated_at", string(&row.updated_at)),
    ])
}

/// One lane replacement history row as an RPC-facing value.
pub fn lane_replacement_event_val(row: &LaneReplacementEventRow) -> Val {
    object(vec![
        ("seq", integer(row.seq)),
        (
            "from_phase",
            row.from_phase.as_deref().map(string).unwrap_or_else(null),
        ),
        ("to_phase", string(&row.to_phase)),
        (
            "from_outcome",
            row.from_outcome.as_deref().map(string).unwrap_or_else(null),
        ),
        ("to_outcome", string(&row.to_outcome)),
        ("reason", string(&row.reason)),
        ("at", string(&row.at)),
    ])
}

/// Map one SQLite row onto [`LaneCheckpointRow`] (column order of the
/// lane_checkpoints SELECTs).
fn lane_checkpoint_row_from(row: &rusqlite::Row<'_>) -> rusqlite::Result<LaneCheckpointRow> {
    Ok(LaneCheckpointRow {
        checkpoint_id: row.get(0)?,
        replacement_id: row.get(1)?,
        lane_id: row.get(2)?,
        generation: row.get(3)?,
        role: row.get(4)?,
        observation_digest: row.get(5)?,
        reobservation_digest: row.get(6)?,
        snapshot: row.get(7)?,
        digest: row.get(8)?,
        brief_digest: row.get(9)?,
        created_at: row.get(10)?,
    })
}

/// One lane checkpoint row as an RPC-facing value (the snapshot field is the
/// parsed canonical snapshot object or null; the brief artifact is a
/// derivation, so its bytes are never echoed here).
pub fn lane_checkpoint_val(row: &LaneCheckpointRow) -> Val {
    object(vec![
        ("checkpoint_id", string(&row.checkpoint_id)),
        ("replacement_id", string(&row.replacement_id)),
        ("lane_id", string(&row.lane_id)),
        ("generation", integer(row.generation)),
        ("role", string(&row.role)),
        ("observation_digest", string(&row.observation_digest)),
        ("reobservation_digest", string(&row.reobservation_digest)),
        ("digest", string(&row.digest)),
        ("brief_digest", string(&row.brief_digest)),
        (
            "snapshot",
            Val::parse_json(&row.snapshot).unwrap_or_else(|_| null()),
        ),
        ("created_at", string(&row.created_at)),
    ])
}

/// A non-empty, bounded, printable string (no control characters).
fn printable_bounded(text: &str, max_len: usize) -> bool {
    !text.is_empty() && text.len() <= max_len && !text.chars().any(char::is_control)
}

/// One required bounded printable text field of a checkpoint observation
/// sub-object. Missing or invalid required evidence refuses typed — it is
/// never silently omitted.
fn cp_text(
    map: &BTreeMap<String, Val>,
    key: &str,
    what: &str,
    max_len: usize,
) -> Result<String, StateError> {
    match map.get(key).and_then(Val::as_str) {
        Some(text) if printable_bounded(text, max_len) => Ok(text.to_string()),
        _ => Err(state_error(
            checkpoint_code::INCOMPLETE,
            format!(
                "{what}.{key} must be a non-empty printable string of at most {max_len} \
                 characters (missing evidence is never silently omitted)"
            ),
        )),
    }
}

/// One required 64-hex sha256 integrity digest of a checkpoint observation
/// sub-object.
fn cp_hex64(map: &BTreeMap<String, Val>, key: &str, what: &str) -> Result<String, StateError> {
    match map.get(key).and_then(Val::as_str) {
        Some(text) if crate::formats::is_hex64(text) => Ok(text.to_string()),
        _ => Err(state_error(
            checkpoint_code::INCOMPLETE,
            format!("{what}.{key} must be a 64-hex sha256 digest (bounded integrity evidence)"),
        )),
    }
}

/// One required 40-hex (commit-sized) field of a checkpoint observation
/// sub-object.
fn cp_hex40(map: &BTreeMap<String, Val>, key: &str, what: &str) -> Result<String, StateError> {
    match map.get(key).and_then(Val::as_str) {
        Some(text) if crate::formats::is_hex40(text) => Ok(text.to_string()),
        _ => Err(state_error(
            checkpoint_code::INCOMPLETE,
            format!("{what}.{key} must be a 40-hex commit identity"),
        )),
    }
}

/// One required non-negative count field of a checkpoint observation
/// sub-object.
fn cp_count(map: &BTreeMap<String, Val>, key: &str, what: &str) -> Result<i64, StateError> {
    match map.get(key).and_then(Val::as_int) {
        Some(value) if (0..=1_000_000).contains(&value) => Ok(value),
        _ => Err(state_error(
            checkpoint_code::INCOMPLETE,
            format!("{what}.{key} must be a non-negative integer count"),
        )),
    }
}

/// One required object field of a checkpoint observation.
fn cp_object<'a>(
    map: &'a BTreeMap<String, Val>,
    key: &str,
    what: &str,
) -> Result<&'a BTreeMap<String, Val>, StateError> {
    match map.get(key) {
        Some(Val::Obj(inner)) => Ok(inner),
        _ => Err(state_error(
            checkpoint_code::INCOMPLETE,
            format!("{what}.{key} must be an object"),
        )),
    }
}

/// One required array field of a checkpoint observation.
fn cp_array<'a>(
    map: &'a BTreeMap<String, Val>,
    key: &str,
    what: &str,
) -> Result<&'a [Val], StateError> {
    match map.get(key) {
        Some(Val::Arr(items)) => Ok(items),
        _ => Err(state_error(
            checkpoint_code::INCOMPLETE,
            format!("{what}.{key} must be an array"),
        )),
    }
}

/// Enforce the closed key set of one checkpoint observation sub-object:
/// every required key present, no unknown key accepted.
fn cp_closed(
    map: &BTreeMap<String, Val>,
    required: &[&str],
    optional: &[&str],
    what: &str,
) -> Result<(), StateError> {
    for key in required {
        if !map.contains_key(*key) {
            return Err(state_error(
                checkpoint_code::INCOMPLETE,
                format!(
                    "{what} is missing required field {key:?} (missing evidence is never \
                     silently omitted)"
                ),
            ));
        }
    }
    for key in map.keys() {
        if !required.contains(&key.as_str()) && !optional.contains(&key.as_str()) {
            return Err(state_error(
                checkpoint_code::INCOMPLETE,
                format!("{what} carries unknown field {key:?}; the contract is closed"),
            ));
        }
    }
    Ok(())
}

/// Git-ref-shaped branch identity: 1-120 chars of `[A-Za-z0-9._/-]`, no
/// leading `-` or `/`, no `..`, no trailing `.`, `/` or `.lock`.
fn is_branch_ref(text: &str) -> bool {
    if text.is_empty() || text.len() > 120 {
        return false;
    }
    if text.starts_with('-') || text.starts_with('/') {
        return false;
    }
    if text.ends_with('.') || text.ends_with('/') || text.ends_with(".lock") {
        return false;
    }
    if text.contains("..") || text.contains("//") {
        return false;
    }
    text.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '/'))
}

/// Validate the `observation.execution` block: the declared external harness
/// execution state and its (optional for inactive execution) supported
/// quiescence acknowledgment. Active execution REQUIRES a supported
/// acknowledgment — daemon fencing alone is not claimed to stop arbitrary
/// shell actions, so the capture refuses without the session's own
/// acknowledgment.
// The return tuple is (execution active, optional (kind, session, at) ack).
#[allow(clippy::type_complexity)]
fn cp_execution(
    map: &BTreeMap<String, Val>,
) -> Result<(bool, Option<(String, String, String)>), StateError> {
    cp_closed(map, &["active", "ack"], &[], "observation.execution")?;
    let active = match map.get("active") {
        Some(Val::Bool(active)) => *active,
        _ => {
            return Err(state_error(
                checkpoint_code::INCOMPLETE,
                "observation.execution.active must be a boolean",
            ));
        }
    };
    let ack = match map.get("ack") {
        None | Some(Val::Null) => None,
        Some(Val::Obj(ack)) => {
            cp_closed(
                ack,
                &["kind", "session", "at"],
                &[],
                "observation.execution.ack",
            )?;
            let kind = cp_text(ack, "kind", "observation.execution.ack", 64)?;
            if !CHECKPOINT_ACK_KINDS.contains(&kind.as_str()) {
                return Err(state_error(
                    checkpoint_code::ACK,
                    format!(
                        "unsupported quiescence acknowledgment kind {kind:?} \
                         (supported: {:?})",
                        CHECKPOINT_ACK_KINDS
                    ),
                ));
            }
            let session = cp_text(ack, "session", "observation.execution.ack", 64)?;
            if !crate::formats::is_actor(&session) {
                return Err(state_error(
                    checkpoint_code::ACK,
                    "observation.execution.ack.session must be an actor identity",
                ));
            }
            let at = cp_text(ack, "at", "observation.execution.ack", 20)?;
            if !crate::formats::is_rfc3339_seconds_z(&at) {
                return Err(state_error(
                    checkpoint_code::ACK,
                    "observation.execution.ack.at must be an RFC3339 UTC (seconds, Z) timestamp",
                ));
            }
            Some((kind, session, at))
        }
        Some(_) => {
            return Err(state_error(
                checkpoint_code::INCOMPLETE,
                "observation.execution.ack must be an object or null",
            ));
        }
    };
    match (active, &ack) {
        (false, Some((kind, _, _))) => {
            return Err(state_error(
                checkpoint_code::ACK,
                format!(
                    "a quiescence acknowledgment ({kind:?}) was supplied while external harness \
                     execution is not active; refused, never silently ignored"
                ),
            ));
        }
        (true, None) => {
            return Err(state_error(
                checkpoint_code::ACK,
                "active external harness execution requires a supported quiescence \
                 acknowledgment AND a process/child observation; daemon fencing alone does \
                 not stop arbitrary shell actions",
            ));
        }
        _ => {}
    }
    Ok((active, ack))
}

/// Validate the `observation.orchestration` block (orchestrator records
/// only): worker/reviewer references must name EXISTING lane replacement
/// records of the matching role, and pending completion events are bounded
/// tokens. Referencing lanes never alters them.
// The return tuple is (workers, reviewers, pending events).
#[allow(clippy::type_complexity)]
fn cp_orchestration(
    tx: &rusqlite::Transaction<'_>,
    map: &BTreeMap<String, Val>,
) -> Result<(Vec<String>, Vec<String>, Vec<String>), StateError> {
    cp_closed(
        map,
        &["workers", "reviewers", "pending_events"],
        &[],
        "observation.orchestration",
    )?;
    let mut workers = Vec::new();
    for item in cp_array(map, "workers", "observation.orchestration")? {
        let Some(id) = item.as_str() else {
            return Err(state_error(
                checkpoint_code::REFERENCES,
                "observation.orchestration.workers entries must be replacement ids (rp_ + 16 hex)",
            ));
        };
        if !crate::formats::is_replacement_id(id) {
            return Err(state_error(
                checkpoint_code::REFERENCES,
                format!("reference {id:?} is not a lane replacement id (rp_ + 16 hex)"),
            ));
        }
        let role: Option<String> = tx
            .query_row(
                "SELECT role FROM lane_replacements WHERE replacement_id = ?1",
                params![id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|err| StateError::from_sqlite("checkpoint: worker reference", err))?;
        match role.as_deref() {
            Some("implementer") => workers.push(id.to_string()),
            Some(other) => {
                return Err(state_error(
                    checkpoint_code::REFERENCES,
                    format!(
                        "worker reference {id} names a {other} record; worker references must \
                         name existing implementer lanes"
                    ),
                ));
            }
            None => {
                return Err(state_error(
                    checkpoint_code::REFERENCES,
                    format!(
                        "worker reference {id} does not exist; orchestrator checkpoints \
                         reference existing worker identities only"
                    ),
                ));
            }
        }
        if workers.len() > CHECKPOINT_REFERENCES_MAX {
            return Err(state_error(
                checkpoint_code::INCOMPLETE,
                format!("at most {CHECKPOINT_REFERENCES_MAX} worker references per checkpoint"),
            ));
        }
    }
    let mut reviewers = Vec::new();
    for item in cp_array(map, "reviewers", "observation.orchestration")? {
        let Some(id) = item.as_str() else {
            return Err(state_error(
                checkpoint_code::REFERENCES,
                "observation.orchestration.reviewers entries must be replacement ids (rp_ + 16 hex)",
            ));
        };
        if !crate::formats::is_replacement_id(id) {
            return Err(state_error(
                checkpoint_code::REFERENCES,
                format!("reference {id:?} is not a lane replacement id (rp_ + 16 hex)"),
            ));
        }
        let role: Option<String> = tx
            .query_row(
                "SELECT role FROM lane_replacements WHERE replacement_id = ?1",
                params![id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|err| StateError::from_sqlite("checkpoint: reviewer reference", err))?;
        match role.as_deref() {
            Some("reviewer") => reviewers.push(id.to_string()),
            Some(other) => {
                return Err(state_error(
                    checkpoint_code::REFERENCES,
                    format!(
                        "reviewer reference {id} names a {other} record; reviewer references \
                         must name existing reviewer lanes"
                    ),
                ));
            }
            None => {
                return Err(state_error(
                    checkpoint_code::REFERENCES,
                    format!(
                        "reviewer reference {id} does not exist; orchestrator checkpoints \
                         reference existing reviewer identities only"
                    ),
                ));
            }
        }
        if reviewers.len() > CHECKPOINT_REFERENCES_MAX {
            return Err(state_error(
                checkpoint_code::INCOMPLETE,
                format!("at most {CHECKPOINT_REFERENCES_MAX} reviewer references per checkpoint"),
            ));
        }
    }
    let mut events = Vec::new();
    for item in cp_array(map, "pending_events", "observation.orchestration")? {
        let Some(text) = item.as_str() else {
            return Err(state_error(
                checkpoint_code::INCOMPLETE,
                "observation.orchestration.pending_events entries must be strings",
            ));
        };
        if !printable_bounded(text, 120) {
            return Err(state_error(
                checkpoint_code::INCOMPLETE,
                "observation.orchestration.pending_events entries must be 1-120 printable \
                 characters",
            ));
        }
        events.push(text.to_string());
        if events.len() > CHECKPOINT_REFERENCES_MAX {
            return Err(state_error(
                checkpoint_code::INCOMPLETE,
                format!(
                    "at most {CHECKPOINT_REFERENCES_MAX} pending completion events per checkpoint"
                ),
            ));
        }
    }
    Ok((workers, reviewers, events))
}

/// Validate one checkpoint observation against the replacement record and
/// the closed contract, and build the canonical snapshot value. Every
/// required field is present and bounded or the capture refuses; active or
/// ambiguous side-effecting child commands HOLD completion (nothing is
/// signalled, killed, or cleaned up to obtain a snapshot).
#[allow(clippy::too_many_arguments)]
fn checkpoint_snapshot_val(
    record: &LaneReplacementRow,
    observation: &Val,
    observation_digest: &str,
    reobservation_digest: &str,
    outstanding: &[(String, String)],
    outstanding_count: i64,
    epoch: i64,
    at: &str,
    checkpoint_id: &str,
    tx: &rusqlite::Transaction<'_>,
) -> Result<Val, StateError> {
    let Val::Obj(obs) = observation else {
        return Err(state_error(
            checkpoint_code::INCOMPLETE,
            "observation must be an object",
        ));
    };
    cp_closed(
        obs,
        &[
            "role",
            "task",
            "worktree",
            "branch",
            "head",
            "base",
            "dirty",
            "untracked",
            "report",
            "gates",
            "children",
            "execution",
        ],
        &["orchestration"],
        "observation",
    )?;
    let role = cp_text(obs, "role", "observation", 64)?;
    if role != record.role {
        return Err(state_error(
            checkpoint_code::INCOMPLETE,
            format!(
                "observation.role {role:?} does not match the replacement record role {:?} \
                 (a checkpoint binds the lane it captures)",
                record.role
            ),
        ));
    }
    let task = cp_text(obs, "task", "observation", 200)?;
    let worktree = cp_text(obs, "worktree", "observation", 200)?;
    if worktree != record.worktree || !crate::formats::is_worktree_ref(&worktree) {
        return Err(state_error(
            checkpoint_code::INCOMPLETE,
            format!(
                "observation.worktree {worktree:?} does not match the replacement record \
                 worktree {:?}",
                record.worktree
            ),
        ));
    }
    let branch = cp_text(obs, "branch", "observation", 120)?;
    if !is_branch_ref(&branch) {
        return Err(state_error(
            checkpoint_code::INCOMPLETE,
            format!("observation.branch {branch:?} is not a git-ref-shaped branch identity"),
        ));
    }
    let head = cp_hex40(obs, "head", "observation")?;
    let base = cp_hex40(obs, "base", "observation")?;
    let dirty = cp_object(obs, "dirty", "observation")?;
    cp_closed(dirty, &["count", "digest"], &[], "observation.dirty")?;
    let dirty_count = cp_count(dirty, "count", "observation.dirty")?;
    let dirty_digest = cp_hex64(dirty, "digest", "observation.dirty")?;
    let untracked = cp_object(obs, "untracked", "observation")?;
    cp_closed(
        untracked,
        &["count", "digest"],
        &[],
        "observation.untracked",
    )?;
    let untracked_count = cp_count(untracked, "count", "observation.untracked")?;
    let untracked_digest = cp_hex64(untracked, "digest", "observation.untracked")?;
    let report = cp_object(obs, "report", "observation")?;
    cp_closed(
        report,
        &["round", "reviewed_sha"],
        &[],
        "observation.report",
    )?;
    let report_round = match report.get("round").and_then(Val::as_int) {
        Some(value) if (1..=100_000).contains(&value) => value,
        _ => {
            return Err(state_error(
                checkpoint_code::INCOMPLETE,
                "observation.report.round must be a positive integer",
            ));
        }
    };
    let reviewed_sha = cp_hex40(report, "reviewed_sha", "observation.report")?;
    let gates = cp_array(obs, "gates", "observation")?;
    if gates.len() > CHECKPOINT_GATES_MAX {
        return Err(state_error(
            checkpoint_code::INCOMPLETE,
            format!("at most {CHECKPOINT_GATES_MAX} gate entries per checkpoint"),
        ));
    }
    let mut gate_vals: Vec<Val> = Vec::with_capacity(gates.len());
    for (index, gate) in gates.iter().enumerate() {
        let what = format!("observation.gates[{index}]");
        let Val::Obj(gate_map) = gate else {
            return Err(state_error(
                checkpoint_code::INCOMPLETE,
                format!("{what} must be an object"),
            ));
        };
        cp_closed(gate_map, &["name", "status"], &[], &what)?;
        let name = cp_text(gate_map, "name", &what, 80)?;
        let status = cp_text(gate_map, "status", &what, 16)?;
        if !CHECKPOINT_GATE_STATUSES.contains(&status.as_str()) {
            return Err(state_error(
                checkpoint_code::INCOMPLETE,
                format!("{what}.status {status:?} is outside {CHECKPOINT_GATE_STATUSES:?}"),
            ));
        }
        gate_vals.push(object(vec![
            ("name", string(&name)),
            ("status", string(&status)),
        ]));
    }
    let children = cp_array(obs, "children", "observation")?;
    if children.len() > CHECKPOINT_CHILDREN_MAX {
        return Err(state_error(
            checkpoint_code::INCOMPLETE,
            format!("at most {CHECKPOINT_CHILDREN_MAX} observed child commands per checkpoint"),
        ));
    }
    let mut child_vals: Vec<Val> = Vec::with_capacity(children.len());
    for (index, child) in children.iter().enumerate() {
        let what = format!("observation.children[{index}]");
        let Val::Obj(child_map) = child else {
            return Err(state_error(
                checkpoint_code::INCOMPLETE,
                format!("{what} must be an object"),
            ));
        };
        cp_closed(child_map, &["command", "state"], &[], &what)?;
        let command = cp_text(child_map, "command", &what, 160)?;
        let state = cp_text(child_map, "state", &what, 16)?;
        if !CHECKPOINT_CHILD_STATES.contains(&state.as_str()) {
            return Err(state_error(
                checkpoint_code::INCOMPLETE,
                format!("{what}.state {state:?} is outside {CHECKPOINT_CHILD_STATES:?}"),
            ));
        }
        if state != "exited" {
            return Err(state_error(
                checkpoint_code::HELD,
                format!(
                    "observed side-effecting child command {command:?} is {state:?}: checkpoint \
                     completion is held; nothing is signalled, killed, or cleaned up to obtain \
                     a snapshot — let the child finish and retry"
                ),
            ));
        }
        child_vals.push(object(vec![
            ("command", string(&command)),
            ("state", string(&state)),
        ]));
    }
    let execution = cp_object(obs, "execution", "observation")?;
    let (active, ack) = cp_execution(execution)?;
    let execution_val = object(vec![
        ("active", bool_(active)),
        (
            "ack",
            match &ack {
                Some((kind, session, ack_at)) => object(vec![
                    ("kind", string(kind)),
                    ("session", string(session)),
                    ("at", string(ack_at)),
                ]),
                None => null(),
            },
        ),
    ]);
    let orchestration = match (record.role.as_str(), obs.get("orchestration")) {
        ("orchestrator", Some(Val::Obj(map))) => {
            let (workers, reviewers, events) = cp_orchestration(tx, map)?;
            Some(object(vec![
                (
                    "workers",
                    Val::Arr(workers.iter().map(|id| string(id)).collect()),
                ),
                (
                    "reviewers",
                    Val::Arr(reviewers.iter().map(|id| string(id)).collect()),
                ),
                (
                    "pending_events",
                    Val::Arr(events.iter().map(|event| string(event)).collect()),
                ),
            ]))
        }
        ("orchestrator", _) => {
            return Err(state_error(
                checkpoint_code::REFERENCES,
                "an orchestrator checkpoint must reference its existing worker/reviewer lanes \
                 and pending completion events (observation.orchestration)",
            ));
        }
        (_, Some(_)) => {
            return Err(state_error(
                checkpoint_code::REFERENCES,
                "observation.orchestration is only valid for orchestrator lane checkpoints",
            ));
        }
        (_, None) => None,
    };
    let mut fields: Vec<(&str, Val)> = vec![
        ("checkpoint_id", string(checkpoint_id)),
        ("replacement_id", string(&record.replacement_id)),
        ("lane_id", string(&record.lane_id)),
        ("generation", integer(record.generation)),
        ("role", string(&role)),
        ("task", string(&task)),
        ("worktree", string(&worktree)),
        ("branch", string(&branch)),
        ("head", string(&head)),
        ("base", string(&base)),
        (
            "dirty",
            object(vec![
                ("count", integer(dirty_count)),
                ("digest", string(&dirty_digest)),
            ]),
        ),
        (
            "untracked",
            object(vec![
                ("count", integer(untracked_count)),
                ("digest", string(&untracked_digest)),
            ]),
        ),
        (
            "report",
            object(vec![
                ("round", integer(report_round)),
                ("reviewed_sha", string(&reviewed_sha)),
            ]),
        ),
        ("gates", Val::Arr(gate_vals)),
        ("children", Val::Arr(child_vals)),
        ("execution", execution_val),
        (
            "outstanding_operations",
            object(vec![
                ("count", integer(outstanding_count)),
                (
                    "operations",
                    Val::Arr(
                        outstanding
                            .iter()
                            .map(|(key, method)| {
                                object(vec![("key", string(key)), ("method", string(method))])
                            })
                            .collect(),
                    ),
                ),
            ]),
        ),
        ("state_epoch", integer(epoch)),
        ("captured_at", string(at)),
        ("observation_digest", string(observation_digest)),
        ("reobservation_digest", string(reobservation_digest)),
    ];
    if let Some(orchestration) = orchestration {
        fields.push(("orchestration", orchestration));
    }
    Ok(object(fields))
}

/// The compact human/agent brief for one committed checkpoint record.
/// Deterministic: the same row always renders the same bytes, so a restart
/// reconciliation can regenerate a missing artifact and verify it against
/// `brief_digest` byte-for-byte. The brief carries explicit pointers to the
/// retained evidence (ids + digests) only — never a raw transcript, never a
/// credential, and never a truncation of the recorded gates (oversize
/// required data refuses at commit instead).
pub fn lane_checkpoint_brief(row: &LaneCheckpointRow) -> Result<String, StateError> {
    let snapshot = Val::parse_json(&row.snapshot).map_err(|_| {
        state_error(
            "state.corrupt",
            format!(
                "checkpoint {} snapshot is not parseable canonical JSON",
                row.checkpoint_id
            ),
        )
    })?;
    let Val::Obj(obj) = &snapshot else {
        return Err(state_error(
            "state.corrupt",
            format!("checkpoint {} snapshot is not an object", row.checkpoint_id),
        ));
    };
    let text =
        |key: &str| -> String { obj.get(key).and_then(Val::as_str).unwrap_or("").to_string() };
    let int = |key: &str| -> i64 { obj.get(key).and_then(Val::as_int).unwrap_or(0) };
    let mut brief = String::new();
    brief.push_str(&format!(
        "lane checkpoint {} (replacement {})\n",
        row.checkpoint_id, row.replacement_id
    ));
    brief.push_str(&format!(
        "lane: {} generation {} role {}\n",
        text("lane_id"),
        int("generation"),
        text("role")
    ));
    brief.push_str(&format!("task: {}\n", text("task")));
    brief.push_str(&format!("worktree: {}\n", text("worktree")));
    brief.push_str(&format!("branch: {}\n", text("branch")));
    brief.push_str(&format!("head: {}\n", text("head")));
    brief.push_str(&format!("base: {}\n", text("base")));
    for key in ["dirty", "untracked"] {
        let count = obj
            .get(key)
            .and_then(|value| value.get("count"))
            .and_then(Val::as_int)
            .unwrap_or(0);
        let digest = obj
            .get(key)
            .and_then(|value| value.get("digest"))
            .and_then(Val::as_str)
            .unwrap_or("");
        brief.push_str(&format!("{key}: {count} file(s) sha256 {digest}\n"));
    }
    let report = obj.get("report");
    brief.push_str(&format!(
        "report: round {}, reviewed sha {}\n",
        report
            .and_then(|value| value.get("round"))
            .and_then(Val::as_int)
            .unwrap_or(0),
        report
            .and_then(|value| value.get("reviewed_sha"))
            .and_then(Val::as_str)
            .unwrap_or("")
    ));
    let gates = obj
        .get("gates")
        .and_then(Val::as_array)
        .cloned()
        .unwrap_or_default();
    brief.push_str(&format!("gates: {}\n", gates.len()));
    for gate in &gates {
        brief.push_str(&format!(
            "- {}: {}\n",
            gate.get("name").and_then(Val::as_str).unwrap_or(""),
            gate.get("status").and_then(Val::as_str).unwrap_or("")
        ));
    }
    let children = obj
        .get("children")
        .and_then(Val::as_array)
        .cloned()
        .unwrap_or_default();
    brief.push_str(&format!("children: {}\n", children.len()));
    for child in &children {
        brief.push_str(&format!(
            "- {}: {}\n",
            child.get("command").and_then(Val::as_str).unwrap_or(""),
            child.get("state").and_then(Val::as_str).unwrap_or("")
        ));
    }
    let execution = obj.get("execution");
    let execution_active = execution
        .and_then(|value| value.get("active"))
        .and_then(Val::as_bool)
        .unwrap_or(false);
    let ack = execution.and_then(|value| value.get("ack"));
    match ack {
        Some(Val::Obj(_)) if execution_active => {
            let ack = ack.expect("checked above");
            brief.push_str(&format!(
                "execution: active; ack {} session {} at {}\n",
                ack.get("kind").and_then(Val::as_str).unwrap_or(""),
                ack.get("session").and_then(Val::as_str).unwrap_or(""),
                ack.get("at").and_then(Val::as_str).unwrap_or("")
            ));
        }
        _ => {
            brief.push_str("execution: inactive\n");
        }
    }
    if let Some(orchestration) = obj.get("orchestration") {
        let count = |key: &str| -> usize {
            orchestration
                .get(key)
                .and_then(Val::as_array)
                .map(|items| items.len())
                .unwrap_or(0)
        };
        brief.push_str(&format!(
            "orchestration: workers {}, reviewers {}, pending events {}\n",
            count("workers"),
            count("reviewers"),
            count("pending_events")
        ));
    }
    brief.push_str(&format!(
        "outstanding operations: {}\n",
        obj.get("outstanding_operations")
            .and_then(|value| value.get("count"))
            .and_then(Val::as_int)
            .unwrap_or(0)
    ));
    brief.push_str(&format!(
        "evidence: snapshot sha256 {}; observations sha256 {} == {}\n",
        row.digest, row.observation_digest, row.reobservation_digest
    ));
    brief.push_str(&format!("record: lane_checkpoints/{}\n", row.checkpoint_id));
    Ok(brief)
}

/// Prune audit rows beyond the retention bound, always keeping the chain
/// genesis (seq 0) so verification keeps its anchor.
fn prune_audit_locked(
    conn: &rusqlite::Transaction<'_>,
    retention: Retention,
) -> Result<(), StateError> {
    let deleted = conn
        .execute(
            "DELETE FROM audit WHERE seq != 0 AND seq <= (
                SELECT seq FROM audit ORDER BY seq DESC LIMIT 1 OFFSET ?1
             )",
            params![retention.audit_rows],
        )
        .map_err(|err| StateError::from_sqlite("prune_audit", err))?;
    if deleted == 0 {
        return Ok(());
    }
    // Rechain the retained window: after rows are deleted, every surviving
    // non-genesis row is relinked to the previous surviving row (the
    // genesis row anchors the window) so verification stays exact over the
    // retained rows. Deleted rows are gone by design; the retained chain is
    // self-consistent.
    let mut statement = conn
        .prepare("SELECT seq, line FROM audit ORDER BY seq")
        .map_err(|err| StateError::from_sqlite("prune_audit: prepare rechain", err))?;
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(|err| StateError::from_sqlite("prune_audit: query rechain", err))?;
    let mut previous_hash: Option<String> = None;
    for row in rows {
        let (seq, line) = row.map_err(|err| StateError::from_sqlite("prune_audit: row", err))?;
        let prev_hash = previous_hash.clone().unwrap_or_default();
        let record_hash = sha256_hex(&[line.as_bytes(), prev_hash.as_bytes()].concat());
        conn.execute(
            "UPDATE audit SET prev_hash = ?1, record_hash = ?2 WHERE seq = ?3",
            params![prev_hash, record_hash, seq],
        )
        .map_err(|err| StateError::from_sqlite("prune_audit: relink", err))?;
        previous_hash = Some(record_hash);
    }
    Ok(())
}

/// Append one hf-event/v1 row inside the caller's transaction. Returns the
/// event seq. Retention pruning keeps the tail window. `data` becomes the
/// event's `data` object verbatim (closed event kinds: journal.appended,
/// schedule.ran, ...).
fn append_event_locked(
    conn: &rusqlite::Transaction<'_>,
    retention: Retention,
    kind: &str,
    data: &Val,
) -> Result<i64, StateError> {
    let seq: i64 = conn
        .query_row("SELECT COALESCE(MAX(seq), 0) + 1 FROM events", [], |row| {
            row.get(0)
        })
        .map_err(|err| StateError::from_sqlite("append_event: seq", err))?;
    let data_text = canonical_text(data);
    conn.execute(
        "INSERT INTO events (seq, event, ts, data) VALUES (?1, ?2, ?3, ?4)",
        params![seq, kind, time::rfc3339_now(), data_text],
    )
    .map_err(|err| StateError::from_sqlite("append_event: insert", err))?;
    conn.execute(
        "DELETE FROM events WHERE seq <= (
            SELECT seq FROM events ORDER BY seq DESC LIMIT 1 OFFSET ?1
         )",
        params![retention.event_rows],
    )
    .map_err(|err| StateError::from_sqlite("prune_events", err))?;
    Ok(seq)
}

/// Current epoch (helper for lease rows, which hold the epoch).
fn current_epoch_locked(conn: &Connection) -> Result<i64, StateError> {
    conn.query_row("SELECT COALESCE(MAX(epoch), 0) FROM epoch", [], |row| {
        row.get(0)
    })
    .map_err(|err| StateError::from_sqlite("current_epoch", err))
}

/// Parse a stored canonical data object back into a value (events table).
fn parse_data(text: &str) -> Val {
    Val::parse_json(text).unwrap_or_else(|_| null())
}

/// Compare a mirror file's lines to expected lines (tamper detection).
fn mirror_matches(path: &Path, expected: &[String]) -> Result<(), StateError> {
    let content = match fs::read_to_string(path) {
        Ok(content) => content,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Err(state_error("state.mirror_missing", "mirror file missing"));
        }
        Err(err) => {
            return Err(state_error(
                "state.mirror_unreadable",
                format!("read mirror {}: {err}", path.display()),
            ));
        }
    };
    let actual: Vec<&str> = content.lines().collect();
    let want: Vec<&str> = expected.iter().map(|line| line.trim_end()).collect();
    if actual != want {
        return Err(state_error(
            "state.mirror_drift",
            format!(
                "mirror file {} drifted from the journal table",
                path.display()
            ),
        ));
    }
    Ok(())
}

/// Atomically rewrite a mirror file (tmp + rename) and fsync.
fn write_lines_atomic(path: &Path, lines: &[String]) -> Result<(), StateError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            state_error(
                "state.mirror_write",
                format!("create {}: {err}", parent.display()),
            )
        })?;
    }
    let tmp = path.with_extension("jsonl.tmp");
    let mut file = fs::File::create(&tmp).map_err(|err| {
        state_error(
            "state.mirror_write",
            format!("create {}: {err}", tmp.display()),
        )
    })?;
    for line in lines {
        file.write_all(line.trim_end().as_bytes())
            .and_then(|()| file.write_all(b"\n"))
            .map_err(|err| state_error("state.mirror_write", format!("write mirror: {err}")))?;
    }
    file.sync_all()
        .map_err(|err| state_error("state.mirror_write", format!("fsync mirror: {err}")))?;
    fs::rename(&tmp, path)
        .map_err(|err| state_error("state.mirror_write", format!("rename mirror: {err}")))?;
    Ok(())
}

const M0001_ID: &str = "m0001_initial_state_v1";
const M0001_APPLIES_FROM: i64 = 0;
const M0001_APPLIES_TO: i64 = 1;

/// m0002 adds the workflow-engine runtime columns to `instances` (issue #6:
/// durable engine state for route-granted workflow instances).
const M0002_ID: &str = "m0002_workflow_engine_instances_v2";
const M0002_APPLIES_FROM: i64 = 1;
const M0002_APPLIES_TO: i64 = 2;

/// m0003 adds the control-plane mutation tables (issue #8): durable review
/// evidence rows bound to exact heads/workflow/policy hashes
/// (spec-review-evidence.md) and recorded first-real-write approval rows
/// (issue #8 AC10 plumbing — the canary itself is a separate human gate).
const M0003_ID: &str = "m0003_control_plane_evidence_v3";
const M0003_APPLIES_FROM: i64 = 2;
const M0003_APPLIES_TO: i64 = 3;

/// m0004 adds the lifecycle schedule payload columns (issue #9): the
/// `schedules` foundation rows (m0001) carry the canonical `hf-schedule/v1`
/// document (exact recurring-grant bindings: repository/issue, workflow +
/// policy hashes, read-only caps, expiry, cadence) plus the last-write
/// timestamp. Scheduling behavior (evaluation, coalescing, singleflight,
/// pause/resume/rearm) lands on these columns; the table itself was created
/// by m0001 and remains the durable schedule authority.
const M0004_ID: &str = "m0004_schedules_lifecycle_v4";
const M0004_APPLIES_FROM: i64 = 3;
const M0004_APPLIES_TO: i64 = 4;

/// m0005 adds the lane replacement record tables (issue #73): one durable
/// replacement request per logical lane generation (typed phases, explicit
/// held/ambiguous outcomes, CAS transitions) plus its transactional
/// transition history. Request-only — no spawn/kill/Git effect exists in
/// this slice; the tables are the durable handoff intent.
const M0005_ID: &str = "m0005_lane_replacements_v5";
const M0005_APPLIES_FROM: i64 = 4;
const M0005_APPLIES_TO: i64 = 5;

/// m0006 adds the lane checkpoint table (issue #74): the atomic,
/// restart-safe capture that completes the `quiescing` → `checkpointed`
/// transition for one replacement record. The snapshot column is the
/// durable authority; the compact brief is a deterministic derivation of
/// it (regenerated, never trusted from the request).
const M0006_ID: &str = "m0006_lane_checkpoints_v6";
const M0006_APPLIES_FROM: i64 = 5;
const M0006_APPLIES_TO: i64 = 6;

/// m0007 adds the lane successor table (issue #76): the ONE successor
/// owner a replacement's startup nonce binds. The row commits with the
/// `retired` → `starting` boundary BEFORE any spawn, so a simultaneous or
/// replayed start can never create a second successor; the adapter-observed
/// process, the verification evidence, the preserved orchestration block
/// and the consumed completion events are durable on the row.
const M0007_ID: &str = "m0007_lane_successors_v7";
const M0007_APPLIES_FROM: i64 = 6;
const M0007_APPLIES_TO: i64 = 7;

/// m0008 adds the lane replacement target-profile plans (issue #77): one
/// bound `hf-profile-binding/v1` plan per replacement record, written in the
/// same transaction as the record itself. Purely additive — unbound records
/// (and every stored #73/#74/#75/#76 row) are untouched and the table starts
/// empty.
const M0008_ID: &str = "m0008_lane_replacement_profiles_v8";
const M0008_APPLIES_FROM: i64 = 7;
const M0008_APPLIES_TO: i64 = 8;

/// Migration m0009 (issue #85: the queue executor). Purely additive: the
/// durable queue-submission tables (the committed approval binding, the
/// persisted run membership with per-issue admitted/waiting/refused
/// outcomes, and the unique work-ownership rows). No existing table or row
/// is touched, so stored grants, instances and lane records are never
/// reinterpreted by the upgrade.
const M0009_ID: &str = "m0009_queue_submissions_v9";
const M0009_APPLIES_FROM: i64 = 8;
const M0009_APPLIES_TO: i64 = 9;

/// Migration m0010 (issue #86: run-scoped controls). Purely additive: three
/// run-control columns on `instances` (`pause_requested`, `pause_reason`,
/// `pause_requested_at`; the pause REQUEST that stops admitting while
/// in-flight work finishes) and the bounded `run_retries` table (one row =
/// one authorized re-dispatch of one diagnosed step; the row count is the
/// attempt bound, `consumed_at`/`consumed_key` record the single
/// consumption). No existing table or row is touched, so stored grants,
/// instances, lane records and queue submissions are never reinterpreted.
const M0010_ID: &str = "m0010_run_controls_v10";
const M0010_APPLIES_FROM: i64 = 9;
const M0010_APPLIES_TO: i64 = 10;

/// Migration m0011 (issue #95: supervised reconciliation). Purely additive:
/// three tables — the durable supervision authorization of one run
/// (`supervisions`: desired state, owner/run generation, the approved-plan
/// binding, the observed meaningful-progress marker, last/next check with
/// their reasons, the bounded policy and the continuation report counters),
/// the ONE pending trigger slot per run (`supervision_triggers`: every
/// semantic wake folds into this row, which is what makes duplicate,
/// out-of-order and concurrent timer/event wakes coalesce into one
/// reconciliation) and the one-row driver cursor (`supervision_runtime`:
/// the event cursor plus the last tick time). No existing table or row is
/// touched, so stored grants, instances, lane records, queue submissions and
/// run controls are never reinterpreted.
const M0011_ID: &str = "m0011_supervision_v11";
const M0011_APPLIES_FROM: i64 = 10;
const M0011_APPLIES_TO: i64 = 11;

/// Migration m0012 (issue #96: bounded continuation to the next eligible
/// issue). Purely additive: the persisted per-item grant binding of a queue
/// membership item (the advance re-verifies the SAME presented grant under
/// the guard), the approved admission inputs the submission committed under
/// (caps + the attested same-harness occupancy: the advance re-applies the
/// approved inputs against live counts), and the `queue_advances` rows — one
/// consumed verified delivery per submission item, the durable cursor and
/// the recorded hold. No existing table or row is touched, so stored grants,
/// instances, lane records, submissions and supervisions are never
/// reinterpreted.
const M0012_ID: &str = "m0012_queue_advances_v12";
const M0012_APPLIES_FROM: i64 = 11;
const M0012_APPLIES_TO: i64 = 12;

/// Ordered migration chain (id, applies_from, applies_to). The runner in
/// [`State::open`] applies every pending migration before serving.
const MIGRATIONS: [(&str, i64, i64); 12] = [
    (M0001_ID, M0001_APPLIES_FROM, M0001_APPLIES_TO),
    (M0002_ID, M0002_APPLIES_FROM, M0002_APPLIES_TO),
    (M0003_ID, M0003_APPLIES_FROM, M0003_APPLIES_TO),
    (M0004_ID, M0004_APPLIES_FROM, M0004_APPLIES_TO),
    (M0005_ID, M0005_APPLIES_FROM, M0005_APPLIES_TO),
    (M0006_ID, M0006_APPLIES_FROM, M0006_APPLIES_TO),
    (M0007_ID, M0007_APPLIES_FROM, M0007_APPLIES_TO),
    (M0008_ID, M0008_APPLIES_FROM, M0008_APPLIES_TO),
    (M0009_ID, M0009_APPLIES_FROM, M0009_APPLIES_TO),
    (M0010_ID, M0010_APPLIES_FROM, M0010_APPLIES_TO),
    (M0011_ID, M0011_APPLIES_FROM, M0011_APPLIES_TO),
    (M0012_ID, M0012_APPLIES_FROM, M0012_APPLIES_TO),
];

/// Ordered migration-chain identifiers (`m0001`..`m0011`), exposed for the
/// release provenance chain (issue #10): `canter --version` prints
/// them so a release archive's provenance record can bind the exact
/// state-schema migration chain of the binary it ships.
pub fn migration_chain_ids() -> &'static [&'static str] {
    const IDS: [&str; MIGRATIONS.len()] = [
        M0001_ID, M0002_ID, M0003_ID, M0004_ID, M0005_ID, M0006_ID, M0007_ID, M0008_ID, M0009_ID,
        M0010_ID, M0011_ID, M0012_ID,
    ];
    &IDS
}

/// Engine-state columns added to `instances` by m0002 (SQLite ALTER ADD
/// COLUMN; each statement must carry a default for existing rows).
const M0002_SQL: &str = "\
ALTER TABLE instances ADD COLUMN workflow_id TEXT NOT NULL DEFAULT '';
ALTER TABLE instances ADD COLUMN workflow_hash TEXT NOT NULL DEFAULT '';
ALTER TABLE instances ADD COLUMN policy_hash TEXT NOT NULL DEFAULT '';
ALTER TABLE instances ADD COLUMN grant_id TEXT NOT NULL DEFAULT '';
ALTER TABLE instances ADD COLUMN issue_number INTEGER NOT NULL DEFAULT 0;
ALTER TABLE instances ADD COLUMN issue_revision TEXT NOT NULL DEFAULT '';
ALTER TABLE instances ADD COLUMN phase TEXT NOT NULL DEFAULT '';
ALTER TABLE instances ADD COLUMN scope TEXT NOT NULL DEFAULT '';
ALTER TABLE instances ADD COLUMN caps TEXT NOT NULL DEFAULT '';
ALTER TABLE instances ADD COLUMN current_node TEXT NOT NULL DEFAULT '';
ALTER TABLE instances ADD COLUMN normal_rounds INTEGER NOT NULL DEFAULT 0;
ALTER TABLE instances ADD COLUMN recovery_rounds INTEGER NOT NULL DEFAULT 0;
ALTER TABLE instances ADD COLUMN human_queue INTEGER NOT NULL DEFAULT 0;
ALTER TABLE instances ADD COLUMN terminal_blockers INTEGER NOT NULL DEFAULT 0;
ALTER TABLE instances ADD COLUMN paused INTEGER NOT NULL DEFAULT 0;
ALTER TABLE instances ADD COLUMN resume_digest TEXT NOT NULL DEFAULT '';
";

/// m0003 control-plane mutation tables (issue #8). `evidence` durably
/// records review evidence bound to exact heads/workflow/policy hashes;
/// `approvals` records the separate explicit human approval required
/// before the first real external write canary (AC10 — the canary itself
/// is never run by this slice).
const M0003_SQL: &str = "\
CREATE TABLE evidence (
    evidence_id TEXT PRIMARY KEY,
    instance_id TEXT NOT NULL,
    repository TEXT NOT NULL,
    feature_head TEXT NOT NULL,
    integration_base TEXT NOT NULL,
    workflow_hash TEXT NOT NULL,
    policy_hash TEXT NOT NULL,
    verdict TEXT NOT NULL CHECK (verdict IN ('pass', 'fail')),
    reviewer TEXT NOT NULL,
    checks TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX idx_evidence_instance ON evidence(instance_id, created_at);
CREATE TABLE approvals (
    approval_id TEXT PRIMARY KEY,
    scope TEXT NOT NULL,
    digest TEXT NOT NULL,
    interactive INTEGER NOT NULL,
    recorded_at TEXT NOT NULL,
    revoked_at TEXT
);
";

/// m0004 lifecycle payload columns on the foundation `schedules` table
/// (issue #9; SQLite ALTER ADD COLUMN — each statement carries a default so
/// existing rows migrate in place). `doc` is the canonical `hf-schedule/v1`
/// document ('' for pre-m0004 rows that no writer ever populated); the
/// existing `enabled`/`next_run_at` columns remain the live cadence state.
const M0004_SQL: &str = "\
ALTER TABLE schedules ADD COLUMN doc TEXT NOT NULL DEFAULT '';
ALTER TABLE schedules ADD COLUMN updated_at TEXT NOT NULL DEFAULT '';
";

/// m0006 lane checkpoint table (issue #74). One checkpoint per replacement
/// record (`UNIQUE (replacement_id)` — a second capture is refused, never
/// merged); the snapshot is the durable capture authority, `digest` binds
/// the canonical snapshot bytes, and `brief_digest` binds the generated
/// brief artifact (which lives beside the state database and is
/// regenerated — never trusted from a request or a torn write).
const M0006_SQL: &str = "\
CREATE TABLE lane_checkpoints (
    checkpoint_id TEXT PRIMARY KEY,
    replacement_id TEXT NOT NULL UNIQUE,
    lane_id TEXT NOT NULL,
    generation INTEGER NOT NULL,
    role TEXT NOT NULL,
    observation_digest TEXT NOT NULL,
    reobservation_digest TEXT NOT NULL,
    snapshot TEXT NOT NULL,
    digest TEXT NOT NULL,
    brief_digest TEXT NOT NULL,
    created_at TEXT NOT NULL
);
";

/// m0007 lane successor table (issue #76). One successor per replacement
/// record (`UNIQUE (replacement_id)` — the durable one-generation/one-nonce
/// owner fence: a second start can never create a duplicate successor). The
/// row commits with the `retired` → `starting` boundary BEFORE any spawn;
/// `delivery`/`attempts` carry the bounded retry state, `process`/`evidence`
/// the adapter-observed verification, `orchestration`/`consumed` the
/// preserved worker/reviewer identity and the exactly-once consumed
/// completions.
const M0007_SQL: &str = "\
CREATE TABLE lane_successors (
    successor_id TEXT PRIMARY KEY,
    replacement_id TEXT NOT NULL UNIQUE,
    lane_id TEXT NOT NULL,
    generation INTEGER NOT NULL,
    role TEXT NOT NULL,
    worktree TEXT NOT NULL,
    session TEXT NOT NULL,
    process TEXT NOT NULL DEFAULT '',
    nonce TEXT NOT NULL,
    profile_key TEXT NOT NULL,
    profile_kind TEXT NOT NULL,
    kickoff_receipt TEXT NOT NULL,
    delivery TEXT NOT NULL DEFAULT 'none',
    attempts INTEGER NOT NULL DEFAULT 1,
    evidence TEXT NOT NULL DEFAULT '',
    evidence_digest TEXT NOT NULL DEFAULT '',
    orchestration TEXT NOT NULL DEFAULT '',
    consumed TEXT NOT NULL DEFAULT '',
    adopted_at TEXT NOT NULL DEFAULT '',
    adoption_evidence TEXT NOT NULL DEFAULT '',
    adoption_digest TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
";

/// m0008 replacement-profile-plan table (issue #77). One bound plan per
/// replacement record: the canonical `hf-profile-binding/v1` document and
/// its explicit configuration revision. The row commits in the same
/// transaction as the replacement record; an unbound record has no row at
/// all (never an empty/placeholder plan).
const M0008_SQL: &str = "\
CREATE TABLE lane_replacement_profiles (
    replacement_id TEXT PRIMARY KEY,
    profile TEXT NOT NULL,
    revision TEXT NOT NULL,
    created_at TEXT NOT NULL
);
";

/// Queue-executor tables added by m0009 (issue #85): the committed
/// submission binding, the persisted run membership (one row per selected
/// issue with its admitted/waiting/refused outcome), and the unique
/// work-ownership rows (`PRIMARY KEY (repository, issue_number)`: the
/// schema-level guarantee that one live run owns one issue).
const M0009_SQL: &str = "\
CREATE TABLE queue_submissions (
    submission_id TEXT PRIMARY KEY,
    repository TEXT NOT NULL,
    state_epoch INTEGER NOT NULL,
    digest TEXT NOT NULL,
    role_key TEXT NOT NULL,
    role_revision TEXT NOT NULL,
    workflow_id TEXT NOT NULL,
    workflow_hash TEXT NOT NULL,
    boundary_phase TEXT NOT NULL,
    integration_branch TEXT NOT NULL,
    completion_branch TEXT NOT NULL,
    boundary_caps TEXT NOT NULL,
    request_line TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE queue_submission_items (
    submission_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL,
    work_item TEXT NOT NULL,
    issue_number INTEGER NOT NULL,
    issue_revision TEXT NOT NULL,
    status TEXT NOT NULL,
    reason TEXT,
    message TEXT,
    instance_id TEXT,
    PRIMARY KEY (submission_id, ordinal)
);
CREATE TABLE queue_ownership (
    repository TEXT NOT NULL,
    issue_number INTEGER NOT NULL,
    work_item TEXT NOT NULL,
    submission_id TEXT NOT NULL,
    instance_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (repository, issue_number)
);
";

/// m0010 run-scoped controls (issue #86). Three additive `instances`
/// columns carry the durable pause REQUEST (`pause_requested` stops new
/// step dispatch immediately; `pause_reason` is the bounded operator
/// reason; `pause_requested_at` the request time) — `paused` remains the
/// reached-safe-boundary flag, so a restart loses neither the intent nor
/// the boundary. `run_retries` holds one row per authorized bounded
/// re-dispatch of one diagnosed step: the row count bounds the attempts,
/// `UNIQUE (instance_id, step_id, attempt)` makes a duplicate authorization
/// impossible, and `consumed_at`/`consumed_key` record the single
/// consumption (a re-dispatch without an unconsumed authorization refuses).
const M0010_SQL: &str = "\
ALTER TABLE instances ADD COLUMN pause_requested INTEGER NOT NULL DEFAULT 0;
ALTER TABLE instances ADD COLUMN pause_reason TEXT NOT NULL DEFAULT '';
ALTER TABLE instances ADD COLUMN pause_requested_at TEXT NOT NULL DEFAULT '';
CREATE TABLE run_retries (
    retry_id TEXT PRIMARY KEY,
    instance_id TEXT NOT NULL,
    step_id TEXT NOT NULL,
    attempt INTEGER NOT NULL,
    authorized_at TEXT NOT NULL,
    consumed_at TEXT NOT NULL DEFAULT '',
    consumed_key TEXT NOT NULL DEFAULT '',
    UNIQUE (instance_id, step_id, attempt)
);
CREATE INDEX idx_run_retries_run ON run_retries(instance_id, step_id, attempt);
";

/// Ordered lane replacement phases (issue #73): one replacement moves
/// through exactly this chain; every transition is a transactional
/// compare-and-set on the current phase.
pub const LANE_REPLACEMENT_PHASES: [&str; 7] = [
    "requested",
    "quiescing",
    "checkpointed",
    "retired",
    "starting",
    "adopting",
    "adopted",
];

/// Explicit lane replacement outcomes (issue #73). `pending` is the normal
/// advanceable state; `held` is an explicit parked state (advancement
/// refused, durable across restarts — the lifecycle park verdict mirrored
/// for the pause refusal); `ambiguous` is written by restart reconciliation
/// when a replacement transition was interrupted (external reconciliation
/// is required before it can advance); `cancelled` invalidates a pending
/// replacement before retirement.
pub const LANE_REPLACEMENT_OUTCOMES: [&str; 4] = ["pending", "held", "ambiguous", "cancelled"];

/// Closed role set a replacement record may bind (doctrine roles). A role
/// outside this set is refused, never inferred.
pub const LANE_REPLACEMENT_ROLES: [&str; 3] = ["orchestrator", "implementer", "reviewer"];

/// Typed refusal codes for lane replacement records (issue #73). Same
/// dotted `refusal.*` vocabulary and never-downgrade style as the
/// control-plane engine codes (`crate::mutation::code`); produced by this
/// layer so RPC responses carry them unchanged.
pub mod replacement_code {
    /// A record already exists for this lane generation (no second
    /// successor owner can be created).
    pub const EXISTS: &str = "refusal.replacement.exists";
    /// The presented generation does not match the record's generation.
    pub const STALE: &str = "refusal.replacement.stale";
    /// The presented phase is not the record's current phase (invalid
    /// transition order, or nothing follows the current phase).
    pub const ORDER: &str = "refusal.replacement.order";
    /// The record is held (parked): advancement is refused until an
    /// explicit invalidation.
    pub const HELD: &str = "refusal.replacement.held";
    /// The record was left ambiguous by an interrupted transition;
    /// external reconciliation is required.
    pub const AMBIGUOUS: &str = "refusal.replacement.ambiguous";
    /// The record was cancelled (invalidated): it can never advance.
    pub const INVALIDATED: &str = "refusal.replacement.invalidated";
    /// Cancellation is only legal before retirement.
    pub const RETIRED: &str = "refusal.replacement.retired";
    /// The lane is inside the quiescing window of an existing handoff
    /// (issue #74): a new replacement slot for the lane is fenced until the
    /// handoff resolves or is cancelled.
    pub const FENCED: &str = "refusal.replacement.fenced";
}

/// Typed refusal codes for lane checkpoints (issue #74). Same dotted
/// `refusal.*` vocabulary as the replacement codes; produced by the state
/// layer so RPC responses carry them unchanged.
pub mod checkpoint_code {
    /// A checkpoint already exists for this replacement (no second capture
    /// can exist; the id is deterministic per replacement).
    pub const EXISTS: &str = "refusal.checkpoint.exists";
    /// The two observations of the lane disagree: the state changed during
    /// capture, so the checkpoint refuses to commit either view.
    pub const CHANGED: &str = "refusal.checkpoint.changed";
    /// An observed side-effecting child command is active or ambiguous:
    /// checkpoint completion is held (nothing is signalled, killed, or
    /// cleaned up to obtain a snapshot).
    pub const HELD: &str = "refusal.checkpoint.held";
    /// Required data (the generated brief) exceeds the enforced size bound:
    /// a typed hold — required gates are never silently truncated.
    pub const OVERSIZE: &str = "refusal.checkpoint.oversize";
    /// Active external harness execution without a supported quiescence
    /// acknowledgment (or an acknowledgment supplied while execution is not
    /// active, or an unsupported acknowledgment kind).
    pub const ACK: &str = "refusal.checkpoint.ack";
    /// Orchestrator references are invalid: a referenced worker/reviewer
    /// record does not exist, has the wrong role, or the orchestration
    /// block is missing/misplaced for the record's role.
    pub const REFERENCES: &str = "refusal.checkpoint.references";
    /// Required snapshot data is missing or malformed. Missing evidence is
    /// never silently omitted: the field must be present and valid or the
    /// checkpoint refuses.
    pub const INCOMPLETE: &str = "refusal.checkpoint.incomplete";
}

/// Typed refusal codes for lane retirement (issue #75). Same dotted
/// `refusal.*` vocabulary as the replacement and checkpoint codes; produced
/// by this layer so RPC responses carry them unchanged.
pub mod retirement_code {
    /// The retirement binding does not match the durable record or its
    /// committed checkpoint: the lane generation, the source session/process
    /// identity, or the checkpoint digest moved since the record was
    /// written. Refused BEFORE any effect — nothing is signalled.
    pub const BINDING: &str = "refusal.retirement.binding";
    /// A hold: the immediate pre-stop recheck cannot establish quiescence
    /// (unknown child activity or an unknown process identity), the bounded
    /// graceful stop did not confirm delivery, or the confirmation cannot
    /// prove absence. Nothing beyond the single bounded stop request is
    /// attempted and no authority is escalated.
    pub const HELD: &str = "refusal.retirement.held";
    /// Backend evidence contradicts the retirement with a reused identity (a
    /// different process holds the bound session, the read-back names
    /// another session, or a stale registration owns the session): fail
    /// closed — external reconciliation is required.
    pub const REUSED: &str = "refusal.retirement.reused";
}

/// Typed refusal codes for lane successors (issue #76). Same dotted
/// `refusal.*` vocabulary as the replacement/checkpoint/retirement codes;
/// produced by this layer so RPC responses carry them unchanged.
pub mod successor_code {
    /// A successor already exists for this replacement (one generation/nonce
    /// owns startup; no second successor can be created).
    pub const EXISTS: &str = "refusal.successor.exists";
    /// The presented binding does not match the durable record, its
    /// committed checkpoint, the committed successor row, or the closed
    /// observation contract: a changed generation, checkpoint digest,
    /// successor identity or missing evidence refuses BEFORE any effect.
    pub const BINDING: &str = "refusal.successor.binding";
    /// The presented startup nonce is not the nonce that owns this
    /// successor (a second nonce can never take over a started successor).
    pub const NONCE: &str = "refusal.successor.nonce";
    /// A hold: the spawn delivery, the adapter-observed readiness, or the
    /// successor evidence cannot prove the boundary. Nothing further is
    /// attempted; the successor stays fenced and a bounded same-nonce retry
    /// can re-verify (never re-spawn blindly).
    pub const HELD: &str = "refusal.successor.held";
    /// The adapter evidence contradicts the start/adoption with a reused or
    /// wrong identity (a different session/process/role/profile/worktree,
    /// or the retired source process answering): fail closed.
    pub const REUSED: &str = "refusal.successor.reused";
    /// The source session is still present (or its absence cannot be
    /// proven) while the successor boundary is being advanced: both live or
    /// ambiguous blocks advancement (nothing is signalled).
    pub const SOURCE_LIVE: &str = "refusal.successor.source_live";
    /// The adoption re-query differs from the recorded handoff state:
    /// RECONCILIATION is required (never a blind replay or a stale PASS
    /// reuse); the record is parked for external reconciliation.
    pub const DIFFERS: &str = "refusal.successor.differs";
    /// The bounded spawn-attempt budget for this successor is exhausted.
    pub const ATTEMPTS: &str = "refusal.successor.attempts";
    /// A completion event does not name a recorded pending completion of
    /// the replacement's orchestrator checkpoint (a completion that was
    /// never recorded is never consumed).
    pub const EVENT: &str = "refusal.successor.event";
    /// The completion event was already consumed (consumption is exactly
    /// once; a duplicate dispatch can never be produced).
    pub const EVENT_CONSUMED: &str = "refusal.successor.event_consumed";
}

/// Content bounds for one successor start/adoption. Every bound is enforced
/// up front; required evidence is never silently truncated.
/// Enforced character bound of one startup nonce.
pub const SUCCESSOR_NONCE_MAX: usize = 64;
/// Maximum spawn attempts issued for one successor (bounded retry policy).
pub const SUCCESSOR_ATTEMPTS_MAX: i64 = 3;
/// Maximum completion events consumed by one successor consumption request.
pub const SUCCESSOR_COMPLETIONS_MAX: usize = 8;

/// Content bounds for one retirement request. The binding is bounded like
/// every other lane contract; the transition reason is bounded so a durable
/// evidence summary is never silently truncated.
/// Maximum recheck child entries considered by one retirement request.
pub const RETIREMENT_RECHECK_CHILDREN_MAX: usize = 16;
/// Enforced byte bound of one retirement transition reason.
pub const RETIREMENT_REASON_MAX: usize = 300;
/// Enforced byte bound of one recheck child command text.
pub const RETIREMENT_CHILD_COMMAND_MAX: usize = 200;

/// Content bounds for one checkpoint observation. Every field is bounded
/// up front; the generated brief additionally enforces a total size bound
/// (oversize required data refuses typed, it is never truncated).
/// Maximum gate-list entries recorded.
pub const CHECKPOINT_GATES_MAX: usize = 24;
/// Maximum observed child commands recorded.
pub const CHECKPOINT_CHILDREN_MAX: usize = 16;
/// Maximum worker/reviewer references per orchestrator checkpoint.
pub const CHECKPOINT_REFERENCES_MAX: usize = 8;
/// Enforced byte bound of the generated brief artifact.
pub const CHECKPOINT_BRIEF_MAX_BYTES: usize = 3072;
/// Supported quiescence-acknowledgment kinds (closed set; anything else is
/// an unsupported acknowledgment and refuses).
pub const CHECKPOINT_ACK_KINDS: [&str; 1] = ["session-quiesced"];
/// Closed observed child-command states. `active` and `ambiguous` hold
/// checkpoint completion.
pub const CHECKPOINT_CHILD_STATES: [&str; 3] = ["exited", "active", "ambiguous"];
/// Closed gate statuses recorded in one snapshot.
pub const CHECKPOINT_GATE_STATUSES: [&str; 4] = ["pending", "running", "passed", "failed"];

/// The phase that legally follows `phase` (`None` for the terminal
/// `adopted`, or an unknown phase).
pub fn next_allowed_phase(phase: &str) -> Option<&'static str> {
    let index = LANE_REPLACEMENT_PHASES.iter().position(|p| *p == phase)?;
    LANE_REPLACEMENT_PHASES.get(index + 1).copied()
}

/// Whether `phase` precedes retirement (cancellation window).
fn phase_before_retirement(phase: &str) -> bool {
    LANE_REPLACEMENT_PHASES
        .iter()
        .position(|p| *p == phase)
        .map(|index| index < 3)
        .unwrap_or(false)
}

/// The deterministic replacement id for one logical lane generation:
/// `rp_` + 16 hex of sha256 over `hf-lane-replacement/v1|<lane>|<gen>`.
/// Same lane/generation → same id, so a replayed request and a restart
/// observe the identical record identity.
pub fn replacement_id_for(lane_id: &str, generation: i64) -> String {
    let digest = sha256_hex(format!("hf-lane-replacement/v1|{lane_id}|{generation}").as_bytes());
    format!("rp_{}", &digest[..16])
}

/// The deterministic checkpoint id for one replacement record: `ck_` + 16
/// hex of sha256 over `hf-lane-checkpoint/v1|<replacement_id>`. Same
/// replacement → same id, so a crash-then-retry and a restart observe the
/// identical artifact identity (at most one checkpoint per replacement).
pub fn checkpoint_id_for(replacement_id: &str) -> String {
    let digest = sha256_hex(format!("hf-lane-checkpoint/v1|{replacement_id}").as_bytes());
    format!("ck_{}", &digest[..16])
}

/// The deterministic successor id for one replacement record: `su_` + 16
/// hex of sha256 over `hf-lane-successor/v1|<replacement_id>`. Same
/// replacement → same successor identity, so a crash-then-retry, a restart
/// and a bounded same-nonce retry all address the identical successor.
pub fn successor_id_for(replacement_id: &str) -> String {
    let digest = sha256_hex(format!("hf-lane-successor/v1|{replacement_id}").as_bytes());
    format!("su_{}", &digest[..16])
}

/// Parse the successor binding of one start request (the grant-style
/// document: lane generation, committed checkpoint digest, the ONE startup
/// nonce). Missing or invalid fields refuse typed — never inferred.
fn successor_binding(params: &Val) -> Result<SuccessorBinding, StateError> {
    let binding = match params.get("binding") {
        Some(Val::Obj(map)) => map,
        _ => {
            return Err(state_error(
                successor_code::BINDING,
                "a successor start requires params.binding (object: generation, \
                 checkpoint_digest, nonce)",
            ));
        }
    };
    let generation = match binding.get("generation").and_then(Val::as_int) {
        Some(generation) if generation >= 1 => generation,
        _ => {
            return Err(state_error(
                successor_code::BINDING,
                "the successor binding generation must be a positive integer",
            ));
        }
    };
    let checkpoint_digest = match binding.get("checkpoint_digest").and_then(Val::as_str) {
        Some(text) if crate::formats::is_hex64(text) => text.to_string(),
        _ => {
            return Err(state_error(
                successor_code::BINDING,
                "the successor binding checkpoint_digest must be a 64-hex sha256 digest \
                 (checkpoint integrity evidence)",
            ));
        }
    };
    let nonce = match binding.get("nonce").and_then(Val::as_str) {
        Some(text) if printable_bounded(text, SUCCESSOR_NONCE_MAX) => text.to_string(),
        _ => {
            return Err(state_error(
                successor_code::BINDING,
                format!(
                    "the successor binding nonce must be 1-{SUCCESSOR_NONCE_MAX} printable \
                     characters (one generation/nonce owns startup)"
                ),
            ));
        }
    };
    Ok(SuccessorBinding {
        generation,
        checkpoint_digest,
        nonce,
    })
}

/// Parse the adoption binding of one adoption request (the committed
/// successor identity the adoption acts on). Missing or invalid fields
/// refuse typed — never inferred.
fn adoption_binding(params: &Val) -> Result<AdoptionBinding, StateError> {
    let binding = match params.get("binding") {
        Some(Val::Obj(map)) => map,
        _ => {
            return Err(state_error(
                successor_code::BINDING,
                "an adoption requires params.binding (object: generation, successor_id, \
                 session)",
            ));
        }
    };
    let generation = match binding.get("generation").and_then(Val::as_int) {
        Some(generation) if generation >= 1 => generation,
        _ => {
            return Err(state_error(
                successor_code::BINDING,
                "the adoption binding generation must be a positive integer",
            ));
        }
    };
    let successor_id = match binding.get("successor_id").and_then(Val::as_str) {
        Some(text) if crate::formats::is_successor_id(text) => text.to_string(),
        _ => {
            return Err(state_error(
                successor_code::BINDING,
                "the adoption binding successor_id must be a su_ successor id",
            ));
        }
    };
    let session = match binding.get("session").and_then(Val::as_str) {
        Some(text) if crate::formats::is_actor(text) => text.to_string(),
        _ => {
            return Err(state_error(
                successor_code::BINDING,
                "the adoption binding session must be a session identity",
            ));
        }
    };
    Ok(AdoptionBinding {
        generation,
        successor_id,
        session,
    })
}

/// Map one SQLite row onto [`LaneSuccessorRow`] (column order of the
/// lane_successors SELECTs).
fn lane_successor_row_from(row: &rusqlite::Row<'_>) -> rusqlite::Result<LaneSuccessorRow> {
    Ok(LaneSuccessorRow {
        successor_id: row.get(0)?,
        replacement_id: row.get(1)?,
        lane_id: row.get(2)?,
        generation: row.get(3)?,
        role: row.get(4)?,
        worktree: row.get(5)?,
        session: row.get(6)?,
        process: row.get(7)?,
        nonce: row.get(8)?,
        profile_key: row.get(9)?,
        profile_kind: row.get(10)?,
        kickoff_receipt: row.get(11)?,
        delivery: row.get(12)?,
        attempts: row.get(13)?,
        evidence: row.get(14)?,
        evidence_digest: row.get(15)?,
        orchestration: row.get(16)?,
        consumed: row.get(17)?,
        adopted_at: row.get(18)?,
        adoption_evidence: row.get(19)?,
        adoption_digest: row.get(20)?,
        created_at: row.get(21)?,
        updated_at: row.get(22)?,
    })
}

/// One lane successor row as an `hf-rpc`-facing value (the durable record a
/// start/adoption/consumption response carries; the evidence documents are
/// parsed when present, null otherwise).
pub fn lane_successor_val(row: &LaneSuccessorRow) -> Val {
    let optional_doc = |text: &str| -> Val {
        if text.is_empty() {
            null()
        } else {
            Val::parse_json(text).unwrap_or_else(|_| null())
        }
    };
    object(vec![
        ("successor_id", string(&row.successor_id)),
        ("replacement_id", string(&row.replacement_id)),
        ("lane_id", string(&row.lane_id)),
        ("generation", integer(row.generation)),
        ("role", string(&row.role)),
        ("worktree", string(&row.worktree)),
        ("session", string(&row.session)),
        ("process", string(&row.process)),
        ("nonce", string(&row.nonce)),
        (
            "profile",
            object(vec![
                ("key", string(&row.profile_key)),
                ("kind", string(&row.profile_kind)),
            ]),
        ),
        ("kickoff_receipt", string(&row.kickoff_receipt)),
        ("delivery", string(&row.delivery)),
        ("attempts", integer(row.attempts)),
        ("evidence", optional_doc(&row.evidence)),
        ("evidence_digest", string(&row.evidence_digest)),
        ("orchestration", optional_doc(&row.orchestration)),
        ("consumed", optional_doc(&row.consumed)),
        ("adopted_at", string(&row.adopted_at)),
        ("adoption_evidence", optional_doc(&row.adoption_evidence)),
        ("adoption_digest", string(&row.adoption_digest)),
        ("created_at", string(&row.created_at)),
        ("updated_at", string(&row.updated_at)),
    ])
}

/// Extract the preserved orchestration block from a committed checkpoint
/// snapshot (orchestrator checkpoints only; None otherwise).
fn checkpoint_orchestration_of(snapshot: &str) -> Option<Val> {
    let parsed = Val::parse_json(snapshot).ok()?;
    match parsed.get("orchestration") {
        Some(value @ Val::Obj(_)) => Some(value.clone()),
        _ => None,
    }
}

/// Validate one adoption re-query and reduce it to the closed comparison
/// document the adoption compares against the committed checkpoint. The
/// contract mirrors the checkpoint observation (closed key set; required
/// evidence is never silently omitted), minus the capture-only blocks.
fn adoption_observation_val(
    record: &LaneReplacementRow,
    observation: &Val,
) -> Result<Val, StateError> {
    adoption_observation_inner(record, observation)
        .map_err(|err| state_error(successor_code::BINDING, err.message))
}

fn adoption_observation_inner(
    record: &LaneReplacementRow,
    observation: &Val,
) -> Result<Val, StateError> {
    let Val::Obj(obs) = observation else {
        return Err(state_error(
            checkpoint_code::INCOMPLETE,
            "the adoption re-query must be an object",
        ));
    };
    cp_closed(
        obs,
        &[
            "role",
            "task",
            "worktree",
            "branch",
            "head",
            "base",
            "dirty",
            "untracked",
            "report",
            "gates",
            "children",
        ],
        &[],
        "observation",
    )?;
    let role = cp_text(obs, "role", "observation", 64)?;
    if role != record.role {
        return Err(state_error(
            checkpoint_code::INCOMPLETE,
            format!(
                "observation.role {role:?} does not match the replacement record role {:?}",
                record.role
            ),
        ));
    }
    let task = cp_text(obs, "task", "observation", 200)?;
    let worktree = cp_text(obs, "worktree", "observation", 200)?;
    if worktree != record.worktree || !crate::formats::is_worktree_ref(&worktree) {
        return Err(state_error(
            checkpoint_code::INCOMPLETE,
            format!(
                "observation.worktree {worktree:?} does not match the replacement record \
                 worktree {:?} (the successor continues the SAME worktree)",
                record.worktree
            ),
        ));
    }
    let branch = cp_text(obs, "branch", "observation", 120)?;
    if !is_branch_ref(&branch) {
        return Err(state_error(
            checkpoint_code::INCOMPLETE,
            format!("observation.branch {branch:?} is not a git-ref-shaped branch identity"),
        ));
    }
    let head = cp_hex40(obs, "head", "observation")?;
    let base = cp_hex40(obs, "base", "observation")?;
    let dirty = cp_object(obs, "dirty", "observation")?;
    cp_closed(dirty, &["count", "digest"], &[], "observation.dirty")?;
    let dirty_count = cp_count(dirty, "count", "observation.dirty")?;
    let dirty_digest = cp_hex64(dirty, "digest", "observation.dirty")?;
    let untracked = cp_object(obs, "untracked", "observation")?;
    cp_closed(
        untracked,
        &["count", "digest"],
        &[],
        "observation.untracked",
    )?;
    let untracked_count = cp_count(untracked, "count", "observation.untracked")?;
    let untracked_digest = cp_hex64(untracked, "digest", "observation.untracked")?;
    let report = cp_object(obs, "report", "observation")?;
    cp_closed(
        report,
        &["round", "reviewed_sha"],
        &[],
        "observation.report",
    )?;
    let report_round = match report.get("round").and_then(Val::as_int) {
        Some(value) if (1..=100_000).contains(&value) => value,
        _ => {
            return Err(state_error(
                checkpoint_code::INCOMPLETE,
                "observation.report.round must be a positive integer",
            ));
        }
    };
    let reviewed_sha = cp_hex40(report, "reviewed_sha", "observation.report")?;
    let gates = cp_array(obs, "gates", "observation")?;
    if gates.len() > CHECKPOINT_GATES_MAX {
        return Err(state_error(
            checkpoint_code::INCOMPLETE,
            format!("at most {CHECKPOINT_GATES_MAX} gate entries per adoption re-query"),
        ));
    }
    let mut gate_vals: Vec<Val> = Vec::with_capacity(gates.len());
    for (index, gate) in gates.iter().enumerate() {
        let what = format!("observation.gates[{index}]");
        let Val::Obj(gate_map) = gate else {
            return Err(state_error(
                checkpoint_code::INCOMPLETE,
                format!("{what} must be an object"),
            ));
        };
        cp_closed(gate_map, &["name", "status"], &[], &what)?;
        let name = cp_text(gate_map, "name", &what, 80)?;
        let status = cp_text(gate_map, "status", &what, 16)?;
        if !CHECKPOINT_GATE_STATUSES.contains(&status.as_str()) {
            return Err(state_error(
                checkpoint_code::INCOMPLETE,
                format!("{what}.status {status:?} is outside {CHECKPOINT_GATE_STATUSES:?}"),
            ));
        }
        gate_vals.push(object(vec![
            ("name", string(&name)),
            ("status", string(&status)),
        ]));
    }
    let children = cp_array(obs, "children", "observation")?;
    if children.len() > CHECKPOINT_CHILDREN_MAX {
        return Err(state_error(
            checkpoint_code::INCOMPLETE,
            format!("at most {CHECKPOINT_CHILDREN_MAX} observed child commands per re-query"),
        ));
    }
    let mut child_vals: Vec<Val> = Vec::with_capacity(children.len());
    for (index, child) in children.iter().enumerate() {
        let what = format!("observation.children[{index}]");
        let Val::Obj(child_map) = child else {
            return Err(state_error(
                checkpoint_code::INCOMPLETE,
                format!("{what} must be an object"),
            ));
        };
        cp_closed(child_map, &["command", "state"], &[], &what)?;
        let command = cp_text(child_map, "command", &what, 160)?;
        let state = cp_text(child_map, "state", &what, 16)?;
        if !CHECKPOINT_CHILD_STATES.contains(&state.as_str()) {
            return Err(state_error(
                checkpoint_code::INCOMPLETE,
                format!("{what}.state {state:?} is outside {CHECKPOINT_CHILD_STATES:?}"),
            ));
        }
        child_vals.push(object(vec![
            ("command", string(&command)),
            ("state", string(&state)),
        ]));
    }
    Ok(object(vec![
        ("task", string(&task)),
        ("worktree", string(&worktree)),
        ("branch", string(&branch)),
        ("head", string(&head)),
        ("base", string(&base)),
        (
            "dirty",
            object(vec![
                ("count", integer(dirty_count)),
                ("digest", string(&dirty_digest)),
            ]),
        ),
        (
            "untracked",
            object(vec![
                ("count", integer(untracked_count)),
                ("digest", string(&untracked_digest)),
            ]),
        ),
        (
            "report",
            object(vec![
                ("round", integer(report_round)),
                ("reviewed_sha", string(&reviewed_sha)),
            ]),
        ),
        ("gates", Val::Arr(gate_vals)),
        ("children", Val::Arr(child_vals)),
    ]))
}

/// Compare one fresh adoption re-query against the recorded checkpoint
/// snapshot's handoff state. Every worktree head/dirty-inventory/report/
/// gate/child difference is returned by name: a non-empty list is the
/// RECONCILIATION verdict (never a blind replay or a stale PASS reuse).
fn adoption_differences(snapshot: &str, observed: &Val) -> Vec<String> {
    let Ok(recorded) = Val::parse_json(snapshot) else {
        return vec!["checkpoint.snapshot".to_string()];
    };
    let mut differences = Vec::new();
    for key in ["task", "worktree", "branch", "head", "base"] {
        let before = recorded.get(key).and_then(Val::as_str).unwrap_or("");
        let after = observed.get(key).and_then(Val::as_str).unwrap_or("");
        if before != after {
            differences.push(key.to_string());
        }
    }
    for key in ["dirty", "untracked"] {
        let before = recorded.get(key).cloned().unwrap_or_else(null);
        let after = observed.get(key).cloned().unwrap_or_else(null);
        if canonical_text(&before) != canonical_text(&after) {
            differences.push(key.to_string());
        }
    }
    let before_report = recorded.get("report").cloned().unwrap_or_else(null);
    let after_report = observed.get("report").cloned().unwrap_or_else(null);
    if canonical_text(&before_report) != canonical_text(&after_report) {
        differences.push("report".to_string());
    }
    let pairs = |value: &Val, key: &str, left: &str, right: &str| -> Vec<(String, String)> {
        let mut pairs: Vec<(String, String)> = value
            .get(key)
            .and_then(Val::as_array)
            .map(|items| {
                items
                    .iter()
                    .map(|item| {
                        (
                            item.get(left)
                                .and_then(Val::as_str)
                                .unwrap_or("")
                                .to_string(),
                            item.get(right)
                                .and_then(Val::as_str)
                                .unwrap_or("")
                                .to_string(),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();
        pairs.sort();
        pairs
    };
    for (key, left, right) in [
        ("gates", "name", "status"),
        ("children", "command", "state"),
    ] {
        let before = pairs(&recorded, key, left, right);
        let after = pairs(observed, key, left, right);
        if before != after {
            differences.push(key.to_string());
        }
    }
    differences
}

/// m0005 lane replacement tables (issue #73). `lane_replacements` holds one
/// record per logical lane generation (UNIQUE — concurrent requests can
/// never create two successor owners); `lane_replacement_events` is the
/// transactional transition history appended inside the same transaction
/// as every record write.
const M0005_SQL: &str = "\
CREATE TABLE lane_replacements (
    replacement_id TEXT PRIMARY KEY,
    lane_id TEXT NOT NULL,
    generation INTEGER NOT NULL,
    successor_generation INTEGER NOT NULL,
    phase TEXT NOT NULL CHECK (phase IN
        ('requested', 'quiescing', 'checkpointed', 'retired', 'starting', 'adopting', 'adopted')),
    outcome TEXT NOT NULL CHECK (outcome IN ('pending', 'held', 'ambiguous', 'cancelled')),
    outcome_reason TEXT NOT NULL DEFAULT '',
    source_session TEXT NOT NULL,
    source_process TEXT NOT NULL,
    role TEXT NOT NULL,
    worktree TEXT NOT NULL,
    reason TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (lane_id, generation)
);
CREATE TABLE lane_replacement_events (
    seq INTEGER PRIMARY KEY,
    replacement_id TEXT NOT NULL,
    from_phase TEXT,
    to_phase TEXT NOT NULL,
    from_outcome TEXT,
    to_outcome TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    at TEXT NOT NULL
);
CREATE INDEX idx_lane_replacement_events_record
    ON lane_replacement_events(replacement_id, seq);
";

const M0001_SQL: &str = "\
CREATE TABLE schema_migrations (
    migration_id TEXT PRIMARY KEY,
    applies_from INTEGER NOT NULL,
    applies_to INTEGER NOT NULL,
    checksum TEXT NOT NULL,
    applied_at TEXT NOT NULL
);
CREATE TABLE epoch (
    epoch INTEGER PRIMARY KEY,
    reason TEXT NOT NULL CHECK (reason IN ('initial', 'restore', 'security_rotation')),
    prior_epoch INTEGER,
    created_at TEXT NOT NULL
);
CREATE TABLE grants (
    grant_id TEXT PRIMARY KEY,
    repository TEXT NOT NULL,
    issue_number INTEGER NOT NULL,
    issue_revision TEXT NOT NULL,
    workflow_hash TEXT NOT NULL,
    policy_hash TEXT NOT NULL,
    phase TEXT NOT NULL,
    scope TEXT NOT NULL,
    caps TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    state_epoch INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'revoked', 'invalidated')),
    created_at TEXT NOT NULL,
    revoked_at TEXT
);
CREATE TABLE idempotency (
    key TEXT PRIMARY KEY,
    request_id TEXT NOT NULL,
    method TEXT NOT NULL,
    status TEXT NOT NULL
        CHECK (status IN ('claimed', 'spent', 'ambiguous', 'voided')),
    epoch INTEGER NOT NULL,
    outcome TEXT,
    response TEXT,
    request_line TEXT NOT NULL,
    claimed_at TEXT NOT NULL,
    resolved_at TEXT
);
CREATE TABLE audit (
    seq INTEGER PRIMARY KEY,
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    plan_hash TEXT,
    grant_id TEXT,
    epoch INTEGER NOT NULL,
    recorded_before_mutation INTEGER NOT NULL,
    at TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    record_hash TEXT NOT NULL,
    line TEXT NOT NULL
);
CREATE TABLE events (
    seq INTEGER PRIMARY KEY,
    event TEXT NOT NULL,
    ts TEXT NOT NULL,
    data TEXT NOT NULL
);
CREATE TABLE leases (
    lease_id TEXT PRIMARY KEY,
    holder TEXT NOT NULL,
    purpose TEXT NOT NULL,
    scope TEXT,
    expires_at TEXT,
    state_epoch INTEGER NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE instances (
    instance_id TEXT PRIMARY KEY,
    repository TEXT,
    state_epoch INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'new',
    created_at TEXT NOT NULL,
    updated_at TEXT
);
CREATE TABLE schedules (
    schedule_id TEXT PRIMARY KEY,
    state_epoch INTEGER NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    next_run_at TEXT,
    created_at TEXT NOT NULL
);
";

/// Run migration m0001 in one transaction and record the initial epoch and
/// the audit-chain genesis row.
fn run_initial_migration(conn: &mut Connection) -> Result<(), StateError> {
    let tx = conn
        .transaction()
        .map_err(|err| StateError::from_sqlite("migrate: begin", err))?;
    let checksum = sha256_hex(M0001_SQL.as_bytes());
    tx.execute_batch(M0001_SQL)
        .map_err(|err| StateError::from_sqlite("migrate m0001", err))?;
    tx.execute(
        "INSERT INTO schema_migrations (migration_id, applies_from, applies_to, checksum, applied_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![M0001_ID, M0001_APPLIES_FROM, M0001_APPLIES_TO, checksum, time::rfc3339_now()],
    )
    .map_err(|err| StateError::from_sqlite("migrate: bookkeeping", err))?;
    let now = time::rfc3339_now();
    tx.execute(
        "INSERT INTO epoch (epoch, reason, prior_epoch, created_at) VALUES (1, 'initial', NULL, ?1)",
        params![now],
    )
    .map_err(|err| StateError::from_sqlite("migrate: initial epoch", err))?;
    // Chain genesis: seq 0 anchors every later record hash.
    tx.execute(
        "INSERT INTO audit (seq, action, target, idempotency_key, plan_hash, grant_id, epoch,
                            recorded_before_mutation, at, prev_hash, record_hash, line)
         VALUES (0, 'state.genesis', 'state', 'ik_genesis-00000000', NULL, NULL, 1, 0, ?1, '', ?2, ?3)",
        params![
            now,
            sha256_hex(
                canonical_text(&object(vec![
                    ("schema", string("hf-audit/v1")),
                    ("seq", integer(0)),
                    ("action", string("state.genesis")),
                    ("target", string("state")),
                    ("idempotency_key", string("ik_genesis-00000000")),
                    ("plan_hash", null()),
                    ("grant_id", null()),
                    ("epoch", integer(1)),
                    ("recorded_before_mutation", bool_(false)),
                    ("at", string(&now.clone())),
                ]))
                .as_bytes()
            ),
            canonical_text(&object(vec![
                ("schema", string("hf-audit/v1")),
                ("seq", integer(0)),
                ("action", string("state.genesis")),
                ("target", string("state")),
                ("idempotency_key", string("ik_genesis-00000000")),
                ("plan_hash", null()),
                ("grant_id", null()),
                ("epoch", integer(1)),
                ("recorded_before_mutation", bool_(false)),
                ("at", string(&now)),
            ]))
        ],
    )
    .map_err(|err| StateError::from_sqlite("migrate: genesis", err))?;
    tx.pragma_update(None, "user_version", M0001_APPLIES_TO)
        .map_err(|err| StateError::from_sqlite("migrate: user_version", err))?;
    tx.commit()
        .map_err(|err| StateError::from_sqlite("migrate: commit", err))?;
    Ok(())
}

/// Run migration m0002 in one transaction: engine runtime columns on the
/// `instances` table (workflow pin, phase/scope/caps, node, rounds, pause).
fn run_m0002(conn: &mut Connection) -> Result<(), StateError> {
    let tx = conn
        .transaction()
        .map_err(|err| StateError::from_sqlite("migrate m0002: begin", err))?;
    let checksum = sha256_hex(M0002_SQL.as_bytes());
    tx.execute_batch(M0002_SQL)
        .map_err(|err| StateError::from_sqlite("migrate m0002", err))?;
    tx.execute(
        "INSERT INTO schema_migrations (migration_id, applies_from, applies_to, checksum, applied_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            M0002_ID,
            M0002_APPLIES_FROM,
            M0002_APPLIES_TO,
            checksum,
            time::rfc3339_now()
        ],
    )
    .map_err(|err| StateError::from_sqlite("migrate m0002: bookkeeping", err))?;
    tx.pragma_update(None, "user_version", M0002_APPLIES_TO)
        .map_err(|err| StateError::from_sqlite("migrate m0002: user_version", err))?;
    tx.commit()
        .map_err(|err| StateError::from_sqlite("migrate m0002: commit", err))?;
    Ok(())
}

/// Run migration m0003 in one transaction: durable review-evidence rows and
/// recorded first-real-write approval rows (issue #8 control-plane
/// mutations; AC4 evidence + AC10 recorded-approval plumbing).
fn run_m0003(conn: &mut Connection) -> Result<(), StateError> {
    let tx = conn
        .transaction()
        .map_err(|err| StateError::from_sqlite("migrate m0003: begin", err))?;
    let checksum = sha256_hex(M0003_SQL.as_bytes());
    tx.execute_batch(M0003_SQL)
        .map_err(|err| StateError::from_sqlite("migrate m0003", err))?;
    tx.execute(
        "INSERT INTO schema_migrations (migration_id, applies_from, applies_to, checksum, applied_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            M0003_ID,
            M0003_APPLIES_FROM,
            M0003_APPLIES_TO,
            checksum,
            time::rfc3339_now()
        ],
    )
    .map_err(|err| StateError::from_sqlite("migrate m0003: bookkeeping", err))?;
    tx.pragma_update(None, "user_version", M0003_APPLIES_TO)
        .map_err(|err| StateError::from_sqlite("migrate m0003: user_version", err))?;
    tx.commit()
        .map_err(|err| StateError::from_sqlite("migrate m0003: commit", err))?;
    Ok(())
}

/// Run migration m0004 in one transaction: lifecycle payload columns on the
/// foundation `schedules` table (canonical hf-schedule/v1 doc + last-write
/// timestamp; issue #9 lifecycle slice).
fn run_m0004(conn: &mut Connection) -> Result<(), StateError> {
    let tx = conn
        .transaction()
        .map_err(|err| StateError::from_sqlite("migrate m0004: begin", err))?;
    let checksum = sha256_hex(M0004_SQL.as_bytes());
    tx.execute_batch(M0004_SQL)
        .map_err(|err| StateError::from_sqlite("migrate m0004", err))?;
    tx.execute(
        "INSERT INTO schema_migrations (migration_id, applies_from, applies_to, checksum, applied_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            M0004_ID,
            M0004_APPLIES_FROM,
            M0004_APPLIES_TO,
            checksum,
            time::rfc3339_now()
        ],
    )
    .map_err(|err| StateError::from_sqlite("migrate m0004: bookkeeping", err))?;
    tx.pragma_update(None, "user_version", M0004_APPLIES_TO)
        .map_err(|err| StateError::from_sqlite("migrate m0004: user_version", err))?;
    tx.commit()
        .map_err(|err| StateError::from_sqlite("migrate m0004: commit", err))?;
    Ok(())
}

/// Run migration m0005 in one transaction: the lane replacement record
/// tables (issue #73 request-only handoff records + transition history).
/// Purely additive — no existing table or row is touched, so stored grants
/// are never reinterpreted by the upgrade.
fn run_m0005(conn: &mut Connection) -> Result<(), StateError> {
    let tx = conn
        .transaction()
        .map_err(|err| StateError::from_sqlite("migrate m0005: begin", err))?;
    let checksum = sha256_hex(M0005_SQL.as_bytes());
    tx.execute_batch(M0005_SQL)
        .map_err(|err| StateError::from_sqlite("migrate m0005", err))?;
    tx.execute(
        "INSERT INTO schema_migrations (migration_id, applies_from, applies_to, checksum, applied_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            M0005_ID,
            M0005_APPLIES_FROM,
            M0005_APPLIES_TO,
            checksum,
            time::rfc3339_now()
        ],
    )
    .map_err(|err| StateError::from_sqlite("migrate m0005: bookkeeping", err))?;
    tx.pragma_update(None, "user_version", M0005_APPLIES_TO)
        .map_err(|err| StateError::from_sqlite("migrate m0005: user_version", err))?;
    tx.commit()
        .map_err(|err| StateError::from_sqlite("migrate m0005: commit", err))?;
    Ok(())
}

/// Run migration m0006 in one transaction: the lane checkpoint table
/// (issue #74 atomic capture record). Purely additive — no existing table
/// or row is touched, so stored grants and replacement records are never
/// reinterpreted by the upgrade.
fn run_m0006(conn: &mut Connection) -> Result<(), StateError> {
    let tx = conn
        .transaction()
        .map_err(|err| StateError::from_sqlite("migrate m0006: begin", err))?;
    let checksum = sha256_hex(M0006_SQL.as_bytes());
    tx.execute_batch(M0006_SQL)
        .map_err(|err| StateError::from_sqlite("migrate m0006", err))?;
    tx.execute(
        "INSERT INTO schema_migrations (migration_id, applies_from, applies_to, checksum, applied_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            M0006_ID,
            M0006_APPLIES_FROM,
            M0006_APPLIES_TO,
            checksum,
            time::rfc3339_now()
        ],
    )
    .map_err(|err| StateError::from_sqlite("migrate m0006: bookkeeping", err))?;
    tx.pragma_update(None, "user_version", M0006_APPLIES_TO)
        .map_err(|err| StateError::from_sqlite("migrate m0006: user_version", err))?;
    tx.commit()
        .map_err(|err| StateError::from_sqlite("migrate m0006: commit", err))?;
    Ok(())
}

/// Run migration m0007 in one transaction: the lane successor table
/// (issue #76). Purely additive — no existing table or row is touched, so
/// stored replacement/checkpoint rows are never reinterpreted by the
/// upgrade and the successor table starts empty.
fn run_m0007(conn: &mut Connection) -> Result<(), StateError> {
    let tx = conn
        .transaction()
        .map_err(|err| StateError::from_sqlite("migrate m0007: begin", err))?;
    let checksum = sha256_hex(M0007_SQL.as_bytes());
    tx.execute_batch(M0007_SQL)
        .map_err(|err| StateError::from_sqlite("migrate m0007", err))?;
    tx.execute(
        "INSERT INTO schema_migrations (migration_id, applies_from, applies_to, checksum, applied_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            M0007_ID,
            M0007_APPLIES_FROM,
            M0007_APPLIES_TO,
            checksum,
            time::rfc3339_now()
        ],
    )
    .map_err(|err| StateError::from_sqlite("migrate m0007: bookkeeping", err))?;
    tx.pragma_update(None, "user_version", M0007_APPLIES_TO)
        .map_err(|err| StateError::from_sqlite("migrate m0007: user_version", err))?;
    tx.commit()
        .map_err(|err| StateError::from_sqlite("migrate m0007: commit", err))?;
    Ok(())
}

/// Run migration m0008 in one transaction: the lane replacement
/// profile-plan table (issue #77). Purely additive — no existing table or
/// row is touched, so stored replacement/checkpoint/successor rows are never
/// reinterpreted by the upgrade and the profile table starts empty.
fn run_m0008(conn: &mut Connection) -> Result<(), StateError> {
    let tx = conn
        .transaction()
        .map_err(|err| StateError::from_sqlite("migrate m0008: begin", err))?;
    let checksum = sha256_hex(M0008_SQL.as_bytes());
    tx.execute_batch(M0008_SQL)
        .map_err(|err| StateError::from_sqlite("migrate m0008", err))?;
    tx.execute(
        "INSERT INTO schema_migrations (migration_id, applies_from, applies_to, checksum, applied_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            M0008_ID,
            M0008_APPLIES_FROM,
            M0008_APPLIES_TO,
            checksum,
            time::rfc3339_now()
        ],
    )
    .map_err(|err| StateError::from_sqlite("migrate m0008: bookkeeping", err))?;
    tx.pragma_update(None, "user_version", M0008_APPLIES_TO)
        .map_err(|err| StateError::from_sqlite("migrate m0008: user_version", err))?;
    tx.commit()
        .map_err(|err| StateError::from_sqlite("migrate m0008: commit", err))?;
    Ok(())
}

/// Run migration m0009 in one transaction: the queue-executor tables
/// (issue #85 — durable submissions, persisted run membership, unique work
/// ownership). Purely additive — no existing table or row is touched, so
/// stored grants, instances and lane records are never reinterpreted by the
/// upgrade.
fn run_m0009(conn: &mut Connection) -> Result<(), StateError> {
    let tx = conn
        .transaction()
        .map_err(|err| StateError::from_sqlite("migrate m0009: begin", err))?;
    let checksum = sha256_hex(M0009_SQL.as_bytes());
    tx.execute_batch(M0009_SQL)
        .map_err(|err| StateError::from_sqlite("migrate m0009", err))?;
    tx.execute(
        "INSERT INTO schema_migrations (migration_id, applies_from, applies_to, checksum, applied_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            M0009_ID,
            M0009_APPLIES_FROM,
            M0009_APPLIES_TO,
            checksum,
            time::rfc3339_now()
        ],
    )
    .map_err(|err| StateError::from_sqlite("migrate m0009: bookkeeping", err))?;
    tx.pragma_update(None, "user_version", M0009_APPLIES_TO)
        .map_err(|err| StateError::from_sqlite("migrate m0009: user_version", err))?;
    tx.commit()
        .map_err(|err| StateError::from_sqlite("migrate m0009: commit", err))?;
    Ok(())
}

/// Run migration m0010 in one transaction (issue #86: run-scoped controls).
fn run_m0010(conn: &mut Connection) -> Result<(), StateError> {
    let tx = conn
        .transaction()
        .map_err(|err| StateError::from_sqlite("migrate m0010: begin", err))?;
    let checksum = sha256_hex(M0010_SQL.as_bytes());
    tx.execute_batch(M0010_SQL)
        .map_err(|err| StateError::from_sqlite("migrate m0010", err))?;
    tx.execute(
        "INSERT INTO schema_migrations (migration_id, applies_from, applies_to, checksum, applied_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            M0010_ID,
            M0010_APPLIES_FROM,
            M0010_APPLIES_TO,
            checksum,
            time::rfc3339_now()
        ],
    )
    .map_err(|err| StateError::from_sqlite("migrate m0010: bookkeeping", err))?;
    tx.pragma_update(None, "user_version", M0010_APPLIES_TO)
        .map_err(|err| StateError::from_sqlite("migrate m0010: user_version", err))?;
    tx.commit()
        .map_err(|err| StateError::from_sqlite("migrate m0010: commit", err))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Supervision (issue #95): durable authorization, ONE coalesced wake slot per
// run, the recorded-evidence snapshot and the bounded event fold.
// ---------------------------------------------------------------------------

/// One durable supervision authorization of one run (issue #95). Written
/// ONLY by an explicit `hf-supervision-authorization/v1` block presented as
/// part of a queue submission, in the same transaction that commits the
/// submission: supervision is disabled by default, and a run without this
/// row is never evaluated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SupervisionRow {
    /// The supervised run identity.
    pub instance_id: String,
    /// Supervision id (`sv_` + 16 hex, derived from the run and its owner
    /// generation).
    pub supervision_id: String,
    /// Desired supervision (`armed` | `disabled`; closed set).
    pub desired: String,
    /// Ownership generation: 1 for the first authorization of the run, N+1
    /// for every explicit re-authorization (a generation the driver binds).
    pub owner_generation: i64,
    /// Run generation: the run's state epoch at authorization time.
    pub run_generation: i64,
    /// The approved preview digest the authorization bound.
    pub authorization_digest: String,
    /// The approved completion boundary phase.
    pub approved_boundary: String,
    /// Bounded timer fallback cadence (seconds).
    pub check_interval_secs: i64,
    /// Meaningful-progress window (seconds).
    pub progress_timeout_secs: i64,
    /// The observed meaningful-progress marker (sha256 hex; '' until the
    /// first reconciliation observed evidence).
    pub progress_marker: String,
    /// When the marker was observed (RFC3339 UTC; '' until then).
    pub progress_at: String,
    /// The recorded evidence family that moved the marker.
    pub progress_source: String,
    /// Reconciliations performed (the coalescing observable).
    pub checks: i64,
    /// Continuation reports opened (one per absence window, never one per
    /// check).
    pub continuation_reports: i64,
    /// Whether an absence window is currently open.
    pub continuation_open: bool,
    /// When the open absence window started ('' when none).
    pub continuation_since: String,
    /// Last check time (RFC3339 UTC; '' until the first check).
    pub last_check_at: String,
    /// Last check class (closed classification vocabulary).
    pub last_check_class: String,
    /// Last check reason (stable `supervision.*` code).
    pub last_check_reason: String,
    /// Last check wake class (closed wake vocabulary).
    pub last_check_trigger: String,
    /// Next eligible check (RFC3339 UTC).
    pub next_check_at: String,
    /// Next eligible check as Unix seconds (the driver's comparison key).
    pub next_check_unix: i64,
    /// Why the next check is eligible (stable reason code).
    pub next_check_reason: String,
    /// Authorized at (RFC3339 UTC).
    pub armed_at: String,
    /// Last row update (RFC3339 UTC).
    pub updated_at: String,
}

/// The ONE pending trigger slot of one supervised run. Every semantic wake
/// folds here; `trigger_seq` is the highest folded event seq and `folded`
/// counts distinct wakes in the current window, so duplicate and
/// out-of-order events can never open a second reconciliation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SupervisionTriggerRow {
    /// The supervised run identity.
    pub instance_id: String,
    /// The folded wake class (closed wake vocabulary).
    pub trigger: String,
    /// Highest folded event seq.
    pub trigger_seq: i64,
    /// Distinct wakes folded into this window.
    pub folded: i64,
    /// When the window opened (RFC3339 UTC).
    pub first_at: String,
    /// When the window was last refreshed (RFC3339 UTC).
    pub last_at: String,
}

/// The durable supervision driver cursor (one row).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SupervisionRuntime {
    /// Highest event seq folded by the driver.
    pub event_cursor: i64,
    /// Last tick time (RFC3339 UTC).
    pub last_tick_at: String,
}

/// One committed queue membership of a supervised run (issue #96): the item
/// of the already-authorized submission the run was admitted from. The
/// advance is keyed to its ordinal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueueItemRef {
    /// The committed submission the run belongs to.
    pub submission_id: String,
    /// Membership ordinal (the advance's idempotency key).
    pub ordinal: i64,
    /// Stable work-item id of the issue.
    pub work_item: String,
    /// Issue number within the submission's repository.
    pub issue_number: i64,
    /// Recorded item status (`admitted` | `waiting` | `refused`).
    pub status: String,
}

/// The recorded evidence snapshot of one supervised run: exactly the facts a
/// classification reads, re-read from durable rows under ONE guard. Nothing
/// here is inferred from activity or from the caller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SupervisionEvidence {
    /// The durable run row.
    pub run: InstanceRow,
    /// Whether a committed submission/apply claim contains the topology and
    /// admission material required to dispatch the next supported step.
    pub has_dispatch_context: bool,
    /// The live owner run recorded for the run's work item, when one is.
    pub ownership_instance: Option<String>,
    /// The committed submission that admitted the run, when one is.
    pub submission_id: Option<String>,
    /// That submission's approved preview digest.
    pub submission_digest: Option<String>,
    /// The bound step spine as `(step id, step kind)` in spine order.
    pub steps: Vec<(String, String)>,
    /// The committed step ids whose own params declare the reviewer LEG
    /// (issue #193): the review steps this run dispatches ITSELF instead of
    /// waiting for an externally hand-dispatched reviewer lane. Read from the
    /// committed bound-input document; an empty list means no step of this
    /// spine self-dispatches its reviewer.
    pub reviewer_leg_steps: Vec<String>,
    /// Recorded step attempts as `(step, status, error code)` in claim order.
    pub attempts: Vec<(String, String, String)>,
    /// Every durable retry authorization of the run (the retry cursor and
    /// its timing and the dispatch key that consumed each authorization).
    pub retries: Vec<RunRetryRow>,
    /// Recorded review evidence as `(evidence id, verdict, created_at)`,
    /// newest first.
    pub verdicts: Vec<(String, String, String)>,
    /// The step of the dispatch currently in flight, when one is.
    pub in_flight: Option<String>,
    /// The stored meaningful-progress observation time ('' when none).
    pub progress_at: String,
    /// The committed queue membership of this run, when the run was admitted
    /// from a submission (issue #96). `None` = no advance is ever possible.
    pub item: Option<QueueItemRef>,
    /// The NEWEST recorded review-evidence row, when one exists (the same
    /// row the board read model and the merge gate read).
    pub newest_evidence: Option<EvidenceRow>,
    /// The NEWEST recorded REFUSAL of this run's own continuation dispatch
    /// (issue #141), when one exists.
    pub dispatch_refusal: Option<SupervisionDispatchRefusal>,
}

/// One recorded refusal of a supervised continuation dispatch (issue #141).
///
/// A dispatch the apply engine refuses BEFORE its claim (fan-out admission,
/// a malformed derived request) leaves no attempt row and no intent of its
/// own, so this journal record is the only durable place a classification can
/// name the refusal from. It carries the engine's own typed code, never a
/// re-derivation: the refusal is recorded exactly where it happened.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SupervisionDispatchRefusal {
    /// The bound-spine step whose continuation dispatch was refused.
    pub step: String,
    /// The engine's own typed refusal code (e.g.
    /// `refusal.admission.proof_stale`).
    pub code: String,
    /// When the refusal was recorded (RFC3339 UTC).
    pub at: String,
}

/// The recorded dispatch context of one run: the first topology it bound,
/// the newest explicit admission attestation and successful worker heads.
#[derive(Clone, Debug, PartialEq)]
pub struct RecordedDispatch {
    /// The immutable `topology` object the run's first dispatch presented.
    pub topology: Val,
    /// The newest recorded `flags.admission` object, when one was presented.
    pub admission: Option<Val>,
    /// The integration base read by the run's successful checkout step.
    pub integration_base: Option<String>,
    /// The newest feature head read by a successful outcome collection.
    pub feature_head: Option<String>,
    /// The run's own certified delivery binding (issue #202 AC2), when its
    /// collection observed one: the branch + head + base the run's own
    /// `collect_outcome` step certified.
    pub delivery: Option<DeliveryCertificate>,
}

/// The certified delivery binding of ONE run (issue #202 AC2): the branch,
/// head and base its own newest successful `collect_outcome` step observed
/// and recorded, with the record that certifies it (step id + idempotency
/// key). A certified delivery is the ONLY source of a run's `feature_head`
/// binding; a head that no collection of this run observed is never consumed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeliveryCertificate {
    /// The step of the run's committed spine that certified the delivery.
    pub step_id: String,
    /// The idempotency key of that collection's recorded claim.
    pub key: String,
    /// The delivery branch the collection observed.
    pub branch: String,
    /// The certified delivery head (40-hex).
    pub head: String,
    /// The recorded collection base (40-hex; empty when unrecorded).
    pub base_head: String,
}

/// The plan of one committed supervision check (built by the driver from the
/// snapshot it read; the transaction re-reads the row and fences the wake
/// slot on `consumed_seq`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SupervisionCheckPlan {
    /// The supervised run identity.
    pub instance_id: String,
    /// The clock the driver used (Unix seconds).
    pub now_unix: i64,
    /// The clock the driver used (RFC3339 UTC).
    pub at: String,
    /// The classification class (closed vocabulary member).
    pub class: &'static str,
    /// The classification reason code.
    pub reason: &'static str,
    /// Whether the run is reported continuation-eligible.
    pub eligible: bool,
    /// The consumed wake class (closed wake vocabulary).
    pub trigger: &'static str,
    /// The exact trigger seq the driver read (`0` when none was pending).
    pub consumed_seq: i64,
    /// Consume the whole pending slot regardless of seq (a fresh snapshot
    /// check supersedes every pending wake).
    pub consumed_all: bool,
    /// The observed meaningful-progress marker.
    pub marker: String,
    /// The recorded evidence family that moved the marker.
    pub marker_source: &'static str,
    /// Next eligible check (Unix seconds).
    pub next_check_unix: i64,
    /// Why the next check is eligible.
    pub next_check_reason: &'static str,
    /// The fresh VERIFIED delivery of this run, when the recorded evidence
    /// carries one (issue #96): the ONE continuation effect of a committed
    /// check — the transaction re-verifies it under the guard and advances
    /// the queue cursor exactly once per delivered item. `None` = the check
    /// has no effect beyond its own durable record.
    pub advance: Option<crate::supervision::VerifiedDelivery>,
    /// The ONE continuation dispatch of this check (issue #92 F4): the run's
    /// next unachieved step, handed to the daemon's apply engine AFTER the
    /// check commits. `None` = this check dispatches nothing (non-armed
    /// supervision keeps its classification-only guarantee verbatim).
    pub dispatch: Option<crate::supervision::DispatchIntent>,
}

/// The outcome of one bounded event-fold pass.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SupervisionFold {
    /// The cursor after the pass.
    pub cursor: i64,
    /// Whether event retention moved past the cursor (or an audit row a
    /// folded event named was pruned): every armed run then gets a fresh
    /// snapshot reconciliation.
    pub lost: bool,
    /// Distinct wakes folded by this pass.
    pub folded: usize,
    /// The runs whose pending slot was refreshed.
    pub runs: Vec<String>,
}

/// The plan of one supervision authorization committed with a submission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SupervisionAuthorizationPlan {
    /// Desired supervision (`armed` | `disabled`).
    pub desired: String,
    /// Bounded timer fallback cadence (seconds).
    pub check_interval_secs: i64,
    /// Meaningful-progress window (seconds).
    pub progress_timeout_secs: i64,
}

/// One supervision-write outcome (the row plus whether it was a duplicate).
fn supervision_row_from(row: &rusqlite::Row<'_>) -> rusqlite::Result<SupervisionRow> {
    Ok(SupervisionRow {
        instance_id: row.get(0)?,
        supervision_id: row.get(1)?,
        desired: row.get(2)?,
        owner_generation: row.get(3)?,
        run_generation: row.get(4)?,
        authorization_digest: row.get(5)?,
        approved_boundary: row.get(6)?,
        check_interval_secs: row.get(7)?,
        progress_timeout_secs: row.get(8)?,
        progress_marker: row.get(9)?,
        progress_at: row.get(10)?,
        progress_source: row.get(11)?,
        checks: row.get(12)?,
        continuation_reports: row.get(13)?,
        continuation_open: row.get::<_, i64>(14)? != 0,
        continuation_since: row.get(15)?,
        last_check_at: row.get(16)?,
        last_check_class: row.get(17)?,
        last_check_reason: row.get(18)?,
        last_check_trigger: row.get(19)?,
        next_check_at: row.get(20)?,
        next_check_unix: row.get(21)?,
        next_check_reason: row.get(22)?,
        armed_at: row.get(23)?,
        updated_at: row.get(24)?,
    })
}

/// The shared supervision-row projection.
fn supervision_select_sql() -> &'static str {
    "SELECT instance_id, supervision_id, desired, owner_generation, run_generation,
            authorization_digest, approved_boundary, check_interval_secs,
            progress_timeout_secs, progress_marker, progress_at, progress_source, checks,
            continuation_reports, continuation_open, continuation_since, last_check_at,
            last_check_class, last_check_reason, last_check_trigger, next_check_at,
            next_check_unix, next_check_reason, armed_at, updated_at
       FROM supervisions"
}

/// The deterministic supervision id: `sv_` + first 16 hex of the sha256 over
/// the domain-separated `(run, owner generation)` pair, so a re-authorization
/// and a restart can never invent a second id for one generation.
pub fn supervision_id_for(instance_id: &str, owner_generation: i64) -> String {
    let preimage = format!("hf-supervision/v1|{instance_id}|{owner_generation}");
    format!("sv_{}", &sha256_hex(preimage.as_bytes())[..16])
}

/// The wake class of one journal action: review evidence, hosted checks,
/// run controls, or a generic semantic completion.
fn supervision_wake_class(action: &str) -> &'static str {
    let kind = action.strip_prefix("mutate.").unwrap_or("");
    match kind {
        "review_evidence" => "review",
        "hosted_check" | "post_merge_verify" => "ci",
        "run.pause" | "run.resume" | "run.retry" => "control",
        _ => "completion",
    }
}

/// The run identity named by one audit target, when one is named. Apply
/// targets read `repository:run-…:step`; run controls read `run:run-…`.
fn supervision_run_of_target(target: &str) -> Option<&str> {
    target
        .split(':')
        .find(|segment| crate::formats::is_run_id(segment))
}

/// One recorded retry row as the classification reads it.
fn retry_row_from(row: &rusqlite::Row<'_>) -> rusqlite::Result<RunRetryRow> {
    Ok(RunRetryRow {
        retry_id: row.get(0)?,
        instance_id: row.get(1)?,
        step_id: row.get(2)?,
        attempt: row.get(3)?,
        authorized_at: row.get(4)?,
        consumed_at: row.get(5)?,
        consumed_key: row.get(6)?,
    })
}

/// Arm (or re-arm) supervision inside the CALLER'S transaction: the queue
/// submission transaction commits the authorization together with the runs it
/// names, and a caller that already holds the state guard must use this form
/// (the std guard is not reentrant, so a lock-taking helper here would
/// self-deadlock the submission).
#[allow(clippy::too_many_arguments)]
fn arm_supervision_in_tx(
    tx: &rusqlite::Transaction<'_>,
    instance_id: &str,
    plan: &SupervisionAuthorizationPlan,
    authorization_digest: &str,
    approved_boundary: &str,
    run_generation: i64,
    at: &str,
) -> Result<SupervisionRow, StateError> {
    if !crate::formats::is_run_id(instance_id) {
        return Err(state_error(
            "state.supervision_invalid",
            format!("supervision addresses ONE run identity; {instance_id:?} is not one"),
        ));
    }
    if !crate::supervision::DESIRED.contains(&plan.desired.as_str()) {
        return Err(state_error(
            "state.supervision_invalid",
            format!(
                "desired supervision {:?} is outside the closed set",
                plan.desired
            ),
        ));
    }
    let existing: Option<i64> = tx
        .query_row(
            "SELECT owner_generation FROM supervisions WHERE instance_id = ?1",
            params![instance_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|err| StateError::from_sqlite("arm_supervision: existing", err))?;
    let owner_generation = existing.map(|value| value + 1).unwrap_or(1);
    let supervision_id = supervision_id_for(instance_id, owner_generation);
    tx.execute(
        "INSERT INTO supervisions (instance_id, supervision_id, desired, owner_generation,
                run_generation, authorization_digest, approved_boundary,
                check_interval_secs, progress_timeout_secs, progress_marker, progress_at,
                progress_source, checks, continuation_reports, continuation_open,
                continuation_since, last_check_at, last_check_class, last_check_reason,
                last_check_trigger, next_check_at, next_check_unix, next_check_reason,
                armed_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, '', '', '', 0, 0, 0, '', '', '', '',
                 '', '', 0, '', ?10, ?10)
         ON CONFLICT(instance_id) DO UPDATE SET
                supervision_id = excluded.supervision_id,
                desired = excluded.desired,
                owner_generation = excluded.owner_generation,
                run_generation = excluded.run_generation,
                authorization_digest = excluded.authorization_digest,
                approved_boundary = excluded.approved_boundary,
                check_interval_secs = excluded.check_interval_secs,
                progress_timeout_secs = excluded.progress_timeout_secs,
                next_check_at = '',
                next_check_unix = 0,
                next_check_reason = '',
                updated_at = excluded.updated_at",
        params![
            instance_id,
            supervision_id,
            plan.desired,
            owner_generation,
            run_generation,
            authorization_digest,
            approved_boundary,
            plan.check_interval_secs,
            plan.progress_timeout_secs,
            at
        ],
    )
    .map_err(|err| StateError::from_sqlite("arm_supervision: upsert", err))?;
    let row: Option<SupervisionRow> = tx
        .query_row(
            format!("{} WHERE instance_id = ?1", supervision_select_sql()).as_str(),
            params![instance_id],
            supervision_row_from,
        )
        .optional()
        .map_err(|err| StateError::from_sqlite("arm_supervision: reread", err))?;
    row.ok_or_else(|| state_error("state.supervision_invalid", "supervision row missing"))
}

// ---------------------------------------------------------------------------
// Queue cursor advance (issue #96): completion-to-next-work for one
// already-authorized queue, keyed to the verified delivery that triggers it.
// ---------------------------------------------------------------------------

/// One queue-submission row as the advance reads it (the shared projection).
fn queue_submission_row_from(row: &rusqlite::Row<'_>) -> rusqlite::Result<QueueSubmissionRow> {
    Ok(QueueSubmissionRow {
        submission_id: row.get(0)?,
        repository: row.get(1)?,
        state_epoch: row.get(2)?,
        digest: row.get(3)?,
        role_key: row.get(4)?,
        role_revision: row.get(5)?,
        workflow_id: row.get(6)?,
        workflow_hash: row.get(7)?,
        boundary_phase: row.get(8)?,
        integration_branch: row.get(9)?,
        completion_branch: row.get(10)?,
        boundary_caps: row.get(11)?,
        request_line: row.get(12)?,
        caps_global: row.get(13)?,
        caps_per_repository: row.get(14)?,
        caps_per_harness: row.get(15)?,
        harness_lanes: row.get(16)?,
        created_at: row.get(17)?,
    })
}

/// The submission-row projection (`queue_submission_row_from` order).
fn queue_submission_select_sql() -> &'static str {
    "SELECT submission_id, repository, state_epoch, digest, role_key,
            role_revision, workflow_id, workflow_hash, boundary_phase,
            integration_branch, completion_branch, boundary_caps,
            request_line, caps_global, caps_per_repository, caps_per_harness,
            harness_lanes, created_at
       FROM queue_submissions"
}

/// The durable queue-advance rows of one submission, oldest delivery first.
fn queue_advance_rows_locked(
    conn: &Connection,
    submission_id: &str,
) -> Result<Vec<QueueAdvanceRow>, StateError> {
    let mut statement = conn
        .prepare(
            "SELECT submission_id, delivered_ordinal, delivered_work_item, delivered_head,
                    evidence_id, next_ordinal, next_work_item, next_instance_id, reason,
                    message, at
               FROM queue_advances WHERE submission_id = ?1 ORDER BY delivered_ordinal",
        )
        .map_err(|err| StateError::from_sqlite("queue_advance_rows: prepare", err))?;
    let rows = statement
        .query_map(params![submission_id], advance_row_from)
        .map_err(|err| StateError::from_sqlite("queue_advance_rows: query", err))?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row.map_err(|err| StateError::from_sqlite("queue_advance_rows: row", err))?);
    }
    Ok(out)
}

/// One queue-advance row as the read API returns it.
fn advance_row_from(row: &rusqlite::Row<'_>) -> rusqlite::Result<QueueAdvanceRow> {
    Ok(QueueAdvanceRow {
        submission_id: row.get(0)?,
        delivered_ordinal: row.get(1)?,
        delivered_work_item: row.get(2)?,
        delivered_head: row.get(3)?,
        evidence_id: row.get(4)?,
        next_ordinal: row.get(5)?,
        next_work_item: row.get(6)?,
        next_instance_id: row.get(7)?,
        reason: row.get(8)?,
        message: row.get(9)?,
        at: row.get(10)?,
    })
}

/// The NEWEST recorded review-evidence row of one run, read on the caller's
/// guard (the same ordering the board read model and the merge gate use).
fn newest_evidence_locked(
    conn: &Connection,
    instance_id: &str,
) -> Result<Option<EvidenceRow>, StateError> {
    conn.query_row(
        "SELECT evidence_id, instance_id, repository, feature_head, integration_base,
                workflow_hash, policy_hash, verdict, reviewer, checks, created_at
           FROM evidence WHERE instance_id = ?1
          ORDER BY created_at DESC, evidence_id DESC LIMIT 1",
        params![instance_id],
        evidence_row_from,
    )
    .optional()
    .map_err(|err| StateError::from_sqlite("newest_evidence", err))
}

/// Whether one run's RECORDED evidence is a fresh VERIFIED delivery, re-read
/// under the caller's guard. The same predicate `supervision::verified_delivery`
/// applies to the driver's snapshot, minus the plan's exact-evidence binding:
/// the run must not be held (paused, blocked, human queue, invalidated,
/// terminal blocker), its epoch must be live, and its newest review evidence
/// must be a `pass` with every named check `passed` at one exact head bound
/// to the run's own workflow and policy pins.
fn delivery_verified_locked(
    conn: &Connection,
    run: &InstanceRow,
) -> Result<Option<EvidenceRow>, StateError> {
    if run.paused
        || run.pause_requested
        || run.human_queue
        || run.status == "blocked"
        || run.status == "invalidated"
        || run.terminal_blockers > 0
    {
        return Ok(None);
    }
    if run.state_epoch != current_epoch_locked(conn)? {
        return Ok(None);
    }
    // A step claim still in flight means the run is mid-effect.
    if in_flight_steps_locked(conn)?
        .iter()
        .any(|(named, _)| named == &run.instance_id || named == "*")
    {
        return Ok(None);
    }
    let Some(newest) = newest_evidence_locked(conn, &run.instance_id)? else {
        return Ok(None);
    };
    if newest.verdict != "pass" {
        return Ok(None);
    }
    let view = crate::mutation::EvidenceView {
        evidence_id: newest.evidence_id.clone(),
        feature_head: newest.feature_head.clone(),
        integration_base: newest.integration_base.clone(),
        workflow_hash: newest.workflow_hash.clone(),
        policy_hash: newest.policy_hash.clone(),
        verdict: newest.verdict.clone(),
        reviewer: newest.reviewer.clone(),
        checks: newest.checks.clone(),
        created_at: newest.created_at.clone(),
    };
    if !crate::mutation::evidence_checks_passed(&view)
        .map_err(|err| state_error("state.evidence_invalid", err.message))?
    {
        return Ok(None);
    }
    if newest.workflow_hash != run.workflow_hash || newest.policy_hash != run.policy_hash {
        return Ok(None);
    }
    if !crate::formats::is_hex40(&newest.feature_head) {
        return Ok(None);
    }
    Ok(Some(newest))
}

/// The declared dependencies of one selection item of a committed submission:
/// `(issue number, required issue numbers)` per selected issue, parsed from
/// the canonical bound-input document. A requirement outside the submission's
/// repository can never be settled by this queue.
fn bound_selected_dependencies(request_line: &str, repository: &str) -> Vec<(i64, Vec<i64>)> {
    let Ok(request) = Val::parse_json(request_line) else {
        return Vec::new();
    };
    let Some(Val::Arr(selected)) = request.get("selected") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for issue in selected {
        let Some(id) = issue.get("id").and_then(Val::as_str) else {
            continue;
        };
        let Ok(identity) = crate::queue_preview::IssueId::parse(id, repository) else {
            continue;
        };
        let requires = issue
            .get("requires")
            .and_then(Val::as_array)
            .map(|requires| {
                requires
                    .iter()
                    .filter_map(Val::as_str)
                    .filter_map(|text| {
                        crate::queue_preview::IssueId::parse(text, repository)
                            .ok()
                            .filter(|dependency| dependency.repository == identity.repository)
                            .map(|dependency| dependency.number)
                    })
                    .collect()
            })
            .unwrap_or_default();
        out.push((identity.number, requires));
    }
    out
}

/// Whether one dependency issue of a submission is DELIVERED AND VERIFIED:
/// its membership item must be admitted, its run must carry a fresh verified
/// delivery, and nothing about it may be inferred from a label. Any doubt is
/// an unmet dependency (a held dependent), never a settled one.
fn dependency_met_locked(
    conn: &Connection,
    items: &[QueueSubmissionItemRow],
    dependency: i64,
) -> Result<bool, StateError> {
    let Some(item) = items.iter().find(|item| item.issue_number == dependency) else {
        // Not part of the selected set: only a committed membership can
        // prove delivery, so an unselected requirement is never met.
        return Ok(false);
    };
    let Some(instance_id) = item.instance_id.as_deref() else {
        return Ok(false);
    };
    let run: Option<InstanceRow> = conn
        .query_row(
            format!("{} WHERE instance_id = ?1", instance_select_sql()).as_str(),
            params![instance_id],
            instance_row_from,
        )
        .optional()
        .map_err(|err| StateError::from_sqlite("dependency_met: run", err))?;
    let Some(run) = run else {
        return Ok(false);
    };
    Ok(delivery_verified_locked(conn, &run)?.is_some())
}

/// One submission's queue cursor state as the transaction reads it.
struct QueueAdvanceAttempt {
    /// The first not-yet-dispatched approved item, in membership order.
    candidate: Option<QueueSubmissionItemRow>,
    /// Its unmet dependency, when one is declared and unmet.
    unmet_dependency: Option<i64>,
    /// Whether an advance row for this delivery already exists.
    recorded: Option<QueueAdvanceRow>,
}

/// Re-read the durable facts ONE advance decision needs: the existing
/// consumption of this delivery (the idempotency fence), the candidate item
/// and its dependency state. Pure reads only.
fn queue_advance_attempt_locked(
    tx: &rusqlite::Transaction<'_>,
    delivery: &crate::supervision::VerifiedDelivery,
    repository: &str,
    request_line: &str,
    items: &[QueueSubmissionItemRow],
) -> Result<QueueAdvanceAttempt, StateError> {
    let recorded: Option<QueueAdvanceRow> = tx
        .query_row(
            "SELECT submission_id, delivered_ordinal, delivered_work_item, delivered_head,
                    evidence_id, next_ordinal, next_work_item, next_instance_id, reason,
                    message, at
               FROM queue_advances WHERE submission_id = ?1 AND delivered_ordinal = ?2",
            params![delivery.submission_id, delivery.item_ordinal],
            advance_row_from,
        )
        .optional()
        .map_err(|err| StateError::from_sqlite("queue_advance: recorded", err))?;
    let candidate = items.iter().find(|item| item.status == "waiting").cloned();
    let dependencies = bound_selected_dependencies(request_line, repository);
    let requires = candidate
        .as_ref()
        .and_then(|candidate| {
            dependencies
                .iter()
                .find(|(number, _)| *number == candidate.issue_number)
                .map(|(_, requires)| requires.clone())
        })
        .unwrap_or_default();
    let mut unmet: Option<i64> = None;
    for dependency in &requires {
        if !dependency_met_locked(tx, items, *dependency)? {
            unmet = Some(*dependency);
            break;
        }
    }
    Ok(QueueAdvanceAttempt {
        candidate,
        unmet_dependency: unmet,
        recorded,
    })
}

/// Whether ONE delivering run owes NOTHING after its own verified delivery
/// (issue #152): the delivery may complete the run only when it is the run's
/// LAST committed spine step, or when every committed step after it has been
/// recorded as achieved. The delivering step is the last committed step of
/// `crate::mutation::DELIVERY_STEP_KIND` — the same fact the supervised
/// committed-tail dispatch anchors on.
///
/// The spine is re-read from the SAME committed bound-input line the run's
/// membership was admitted from and the achievements from the SAME attempt
/// ledger `frontier_of` reads, so the completion timing and the frontier
/// agree by construction: a recorded refusal or failure is never an
/// achievement, and a run with a step still owed stays live instead of being
/// foreclosed by its own delivery. A spine with no reviewed-evidence step
/// binds no successor to a delivery, so the completion keeps its #96
/// behaviour there.
fn delivery_completes_run(
    state: &State,
    conn: &Connection,
    request_line: &str,
    instance_id: &str,
) -> Result<bool, StateError> {
    let steps = bound_steps_of(request_line);
    let Some(delivering) = steps
        .iter()
        .rposition(|(_, kind)| kind == crate::mutation::DELIVERY_STEP_KIND)
    else {
        return Ok(true);
    };
    let owed: Vec<&str> = steps[delivering + 1..]
        .iter()
        .map(|(id, _)| id.as_str())
        .collect();
    if owed.is_empty() {
        return Ok(true);
    }
    let attempts = state.run_step_attempts_with_codes(conn, instance_id)?;
    Ok(owed.iter().all(|step| {
        attempts
            .iter()
            .rfind(|(id, _, _)| id == step)
            .is_some_and(|(_, status, _)| status == "succeeded")
    }))
}

/// Commit the queue-cursor advance of ONE fresh verified delivery (issue
/// #96) inside the caller's transaction, atomically with the reconciliation
/// that recognized it.
///
/// The plan was built from an earlier snapshot, so everything is re-read and
/// re-verified here before any write: the run still exists and its DELIVERY is
/// still the fresh verified delivery the plan claims (`delivered_head` +
/// `evidence_id` included), the run is still the admitted membership item of
/// the named submission, and the delivery has not been consumed yet. ONE
/// consumption per delivered issue, ever: a duplicate delivery event, a
/// replayed check or a crash and restart can only ever observe the recorded
/// row. The candidate is the first `waiting` item in membership order; its
/// declared dependencies must each be delivered and verified, otherwise the
/// item is HELD with the reason recorded (never dispatched, never marked
/// done). An admitted candidate is created through the SAME admission helper
/// the submission used, with the same approved caps and occupancy
/// attestation, and is armed with the delivering run's supervision
/// authorization so the queue keeps continuing.
fn advance_queue_in_tx(
    state: &State,
    tx: &rusqlite::Transaction<'_>,
    delivery: &crate::supervision::VerifiedDelivery,
    delivering_instance: &str,
    at: &str,
) -> Result<(), StateError> {
    // 1. Re-verify the delivery itself, under this guard.
    let run: Option<InstanceRow> = tx
        .query_row(
            format!("{} WHERE instance_id = ?1", instance_select_sql()).as_str(),
            params![delivering_instance],
            instance_row_from,
        )
        .optional()
        .map_err(|err| StateError::from_sqlite("queue_advance: run", err))?;
    let Some(run) = run else {
        return Ok(());
    };
    let Some(newest) = delivery_verified_locked(tx, &run)? else {
        return Ok(());
    };
    if newest.evidence_id != delivery.evidence_id || newest.feature_head != delivery.feature_head {
        // A newer (or different) evidence row moved the delivery: the plan is
        // stale and the next reconciliation re-derives it. Nothing advances.
        return Ok(());
    }
    // 2. The run must still be the ADMITTED membership item named by the plan.
    let item: Option<(String, i64, String)> = tx
        .query_row(
            "SELECT submission_id, ordinal, work_item FROM queue_submission_items
              WHERE submission_id = ?1 AND ordinal = ?2 AND instance_id = ?3
                AND status = 'admitted'",
            params![
                delivery.submission_id,
                delivery.item_ordinal,
                delivering_instance
            ],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|err| StateError::from_sqlite("queue_advance: item", err))?;
    let Some((submission_id, _, work_item)) = item else {
        return Ok(());
    };
    if work_item != delivery.work_item {
        return Ok(());
    }
    // 3. The submission must still exist and be readable (its approved
    //    admission inputs are re-applied below).
    let submission: Option<QueueSubmissionRow> = tx
        .query_row(
            format!("{} WHERE submission_id = ?1", queue_submission_select_sql()).as_str(),
            params![submission_id],
            queue_submission_row_from,
        )
        .optional()
        .map_err(|err| StateError::from_sqlite("queue_advance: submission", err))?;
    let Some(submission) = submission else {
        return Ok(());
    };
    let mut statement = tx
        .prepare(
            "SELECT submission_id, ordinal, work_item, issue_number, issue_revision,
                    status, reason, message, instance_id, grant_id
               FROM queue_submission_items WHERE submission_id = ?1 ORDER BY ordinal",
        )
        .map_err(|err| StateError::from_sqlite("queue_advance: items", err))?;
    let rows = statement
        .query_map(params![submission_id], |row| {
            Ok(QueueSubmissionItemRow {
                submission_id: row.get(0)?,
                ordinal: row.get(1)?,
                work_item: row.get(2)?,
                issue_number: row.get(3)?,
                issue_revision: row.get(4)?,
                status: row.get(5)?,
                reason: row.get(6)?,
                message: row.get(7)?,
                instance_id: row.get(8)?,
                grant_id: row.get(9)?,
            })
        })
        .map_err(|err| StateError::from_sqlite("queue_advance: items query", err))?;
    let mut items: Vec<QueueSubmissionItemRow> = Vec::new();
    for row in rows {
        items.push(row.map_err(|err| StateError::from_sqlite("queue_advance: items row", err))?);
    }
    drop(statement);
    // Issue #152: the verified delivery COMPLETES the delivering run — but
    // only when the delivery is the run's LAST committed spine step. A run
    // whose committed spine still owes steps after the delivery (the merge
    // and the cleanup of the queue spine) stays LIVE, so the plan it was
    // authorized for can still be driven to its end instead of being
    // foreclosed by the very delivery it verified; the completion then lands
    // on a later reconciliation of the same run, once those steps are
    // recorded as achieved. Completion is what frees the counted slot for
    // the next approved issue, so it is written HERE, ahead of the cursor
    // fence, and it is idempotent by construction (a done run stays done)
    // and atomic with the cursor move.
    if delivery_completes_run(state, tx, &submission.request_line, delivering_instance)? {
        tx.execute(
            "UPDATE instances SET status = 'done', updated_at = ?2
              WHERE instance_id = ?1 AND status NOT IN ('done', 'invalidated')",
            params![delivering_instance, at],
        )
        .map_err(|err| StateError::from_sqlite("queue_advance: complete", err))?;
        // Free only this run's ownership, atomically with completion. A
        // replay must never delete a fresh successor's ownership.
        tx.execute(
            "DELETE FROM queue_ownership WHERE instance_id = ?1",
            params![delivering_instance],
        )
        .map_err(|err| StateError::from_sqlite("queue_advance: ownership", err))?;
    }
    // 4. The idempotency fence + the candidate: a consumed delivery with a
    //    dispatch (or an exhausted queue) is final; a recorded HOLD is
    //    re-evaluated, because its reason is observed state that can settle.
    let attempt = queue_advance_attempt_locked(
        tx,
        delivery,
        &submission.repository,
        &submission.request_line,
        &items,
    )?;
    if let Some(recorded) = &attempt.recorded {
        if recorded.next_instance_id.is_some() {
            return Ok(());
        }
        if recorded.reason.is_none() {
            // Exhausted: nothing was left to dispatch then, and a later
            // delivery owns any further cursor move.
            return Ok(());
        }
    }
    let (next_ordinal, next_work_item, next_instance_id, reason, message) = match &attempt.candidate
    {
        None => (None, None, None, None, None),
        Some(candidate) => {
            if let Some(dependency) = attempt.unmet_dependency {
                let in_set = items.iter().any(|item| item.issue_number == dependency);
                let (code, message) = if in_set {
                    (
                        crate::queue_executor::advance::DEPENDENCY_UNSETTLED,
                        format!(
                            "issue {} declares the dependency #{dependency}, whose delivery is \
                             not verified yet; the item stays held and is never dispatched or \
                             marked done from an unmet dependency",
                            candidate.issue_number
                        ),
                    )
                } else {
                    (
                        crate::queue_executor::advance::DEPENDENCY_UNRESOLVED,
                        format!(
                            "issue {} declares the dependency #{dependency}, which is not part \
                             of this submission's selected set; this queue can never settle it, \
                             so the item stays held",
                            candidate.issue_number
                        ),
                    )
                };
                (
                    Some(candidate.ordinal),
                    Some(candidate.work_item.clone()),
                    None,
                    Some(code.to_string()),
                    Some(message),
                )
            } else {
                // Re-apply the approved admission inputs against live counts:
                // the SAME caps and occupancy attestation the submission
                // committed under, and the SAME guard-verifying helper.
                let epoch = current_epoch_locked(tx)?;
                let counted_global: i64 = tx
                    .query_row(
                        "SELECT COUNT(*) FROM instances
                          WHERE status IN ('new', 'running', 'human_queue', 'blocked')",
                        [],
                        |row| row.get(0),
                    )
                    .map_err(|err| StateError::from_sqlite("queue_advance: counted", err))?;
                let mut statement = tx
                    .prepare(
                        "SELECT issue_number, scope FROM instances
                          WHERE repository = ?1
                            AND status IN ('new', 'running', 'human_queue', 'blocked')",
                    )
                    .map_err(|err| StateError::from_sqlite("queue_advance: lanes", err))?;
                let rows = statement
                    .query_map(params![submission.repository], |row| {
                        Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
                    })
                    .map_err(|err| StateError::from_sqlite("queue_advance: lanes query", err))?;
                let mut repository_lanes: Vec<(i64, String)> = Vec::new();
                for row in rows {
                    repository_lanes.push(
                        row.map_err(|err| {
                            StateError::from_sqlite("queue_advance: lanes row", err)
                        })?,
                    );
                }
                drop(statement);
                let mut owned: BTreeMap<i64, OwnedRunSnapshot> = BTreeMap::new();
                let mut statement = tx
                    .prepare(
                        "SELECT issue_number, instance_id, issue_revision, grant_id, paused, resume_digest
                           FROM instances
                          WHERE repository = ?1
                            AND status IN ('new', 'running', 'paused', 'human_queue', 'blocked')",
                    )
                    .map_err(|err| StateError::from_sqlite("queue_advance: owned", err))?;
                let rows = statement
                    .query_map(params![submission.repository], |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            OwnedRunSnapshot {
                                instance_id: row.get(1)?,
                                issue_revision: row.get(2)?,
                                grant_id: row.get(3)?,
                                paused: row.get::<_, i64>(4)? != 0,
                                resume_digest: row.get(5)?,
                            },
                        ))
                    })
                    .map_err(|err| StateError::from_sqlite("queue_advance: owned query", err))?;
                for row in rows {
                    let (issue_number, snapshot) = row
                        .map_err(|err| StateError::from_sqlite("queue_advance: owned row", err))?;
                    owned.entry(issue_number).or_insert(snapshot);
                }
                drop(statement);
                let caps = crate::lifecycle::ConcurrencyCaps {
                    global: usize::try_from(submission.caps_global).unwrap_or(0),
                    per_repository: usize::try_from(submission.caps_per_repository).unwrap_or(0),
                    per_harness: usize::try_from(submission.caps_per_harness).unwrap_or(0),
                };
                let mut slots = FanoutSlots {
                    caps: &caps,
                    counted_global,
                    counted_repository: repository_lanes.len() as i64,
                    harness_lanes: submission.harness_lanes,
                    admitted_global: 0,
                    admitted_repository: 0,
                    admitted_harness: 0,
                };
                let admission = QueueAdmission {
                    state,
                    repository: &submission.repository,
                    submission_id: &submission.submission_id,
                    epoch,
                    at,
                    workflow_id: &submission.workflow_id,
                    workflow_hash: &submission.workflow_hash,
                    ownership: &owned,
                    repository_lanes: &repository_lanes,
                };
                let candidate_item = QueueAdmissionItem {
                    issue_number: candidate.issue_number,
                    issue_revision: &candidate.issue_revision,
                    work_item: &candidate.work_item,
                    grant_id: Some(candidate.grant_id.as_str()).filter(|grant| !grant.is_empty()),
                    resume_digest: None,
                };
                match admit_queue_item_in_tx(tx, &admission, &candidate_item, &mut slots)? {
                    AdmissionDecision::Admitted { instance_id } => {
                        tx.execute(
                            "UPDATE queue_submission_items
                                SET status = 'admitted', reason = NULL, message = NULL,
                                    instance_id = ?3
                              WHERE submission_id = ?1 AND ordinal = ?2",
                            params![submission.submission_id, candidate.ordinal, instance_id],
                        )
                        .map_err(|err| StateError::from_sqlite("queue_advance: item admit", err))?;
                        // A recorded hold that named THIS item is settled by
                        // the dispatch that superseded it: the older delivery
                        // row keeps its consumption key and now records the
                        // dispatch, so a read can never report a stale hold.
                        tx.execute(
                            "UPDATE queue_advances
                                SET next_instance_id = ?3, reason = NULL, message = NULL,
                                    at = ?4
                              WHERE submission_id = ?1 AND next_ordinal = ?2
                                AND next_instance_id IS NULL",
                            params![submission.submission_id, candidate.ordinal, instance_id, at],
                        )
                        .map_err(|err| {
                            StateError::from_sqlite("queue_advance: hold settled", err)
                        })?;
                        // Arm the dispatched run with the SAME supervision
                        // authorization that is driving this queue, so the
                        // continuation keeps going without a conductor.
                        let source: Option<SupervisionRow> = tx
                            .query_row(
                                format!("{} WHERE instance_id = ?1", supervision_select_sql())
                                    .as_str(),
                                params![delivering_instance],
                                supervision_row_from,
                            )
                            .optional()
                            .map_err(|err| {
                                StateError::from_sqlite("queue_advance: supervision", err)
                            })?;
                        if let Some(source) = source {
                            arm_supervision_in_tx(
                                tx,
                                &instance_id,
                                &SupervisionAuthorizationPlan {
                                    desired: source.desired.clone(),
                                    check_interval_secs: source.check_interval_secs,
                                    progress_timeout_secs: source.progress_timeout_secs,
                                },
                                &source.authorization_digest,
                                &source.approved_boundary,
                                submission.state_epoch,
                                at,
                            )?;
                        }
                        (
                            Some(candidate.ordinal),
                            Some(candidate.work_item.clone()),
                            Some(instance_id),
                            None,
                            None,
                        )
                    }
                    AdmissionDecision::Waiting { code, message } => (
                        Some(candidate.ordinal),
                        Some(candidate.work_item.clone()),
                        None,
                        Some(code.to_string()),
                        Some(message),
                    ),
                    AdmissionDecision::Refused { code, message } => (
                        Some(candidate.ordinal),
                        Some(candidate.work_item.clone()),
                        None,
                        Some(code.to_string()),
                        Some(message),
                    ),
                }
            }
        }
    };
    // Issue #98, restart-matrix boundary (c1): the dispatch phase finished
    // (run row, ownership row, membership flip and the dispatched run's own
    // supervision arm all written) and the cursor row is not yet recorded.
    // The code writes the dispatch first and the cursor last; both live in
    // this ONE transaction, so an abort here rolls the dispatch back too.
    crate::daemon::crash_point("queue.advance.after-dispatch");
    // 5. Record the consumption of this delivery: the durable idempotency
    //    key, the cursor and the outcome. A held row is updated in place when
    //    its reason settles (the row is keyed to the delivery, so the update
    //    can never become a second dispatch) and a dispatched row is final.
    tx.execute(
        "INSERT INTO queue_advances (submission_id, delivered_ordinal, delivered_work_item,
                delivered_head, evidence_id, next_ordinal, next_work_item, next_instance_id,
                reason, message, at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
         ON CONFLICT(submission_id, delivered_ordinal) DO UPDATE SET
                next_ordinal = excluded.next_ordinal,
                next_work_item = excluded.next_work_item,
                next_instance_id = COALESCE(queue_advances.next_instance_id,
                                           excluded.next_instance_id),
                reason = excluded.reason,
                message = excluded.message,
                at = excluded.at",
        params![
            submission.submission_id,
            delivery.item_ordinal,
            delivery.work_item,
            delivery.feature_head,
            delivery.evidence_id,
            next_ordinal,
            next_work_item,
            next_instance_id,
            reason,
            message,
            at
        ],
    )
    .map_err(|err| StateError::from_sqlite("queue_advance: record", err))?;
    // Issue #98, restart-matrix boundary (c2): the cursor row is written and
    // nothing is committed yet: an abort here leaves no consumed delivery and
    // no dispatched run, and the resumed daemon re-applies both once.
    crate::daemon::crash_point("queue.advance.after-cursor");
    Ok(())
}

impl State {
    /// Arm (or explicitly disable) supervision for ONE run. Called by the
    /// queue submission transaction with the authorization the submission
    /// presented; a re-authorization increments the ownership generation and
    /// keeps the observed progress observation (a re-arm is not progress).
    #[allow(clippy::too_many_arguments)]
    pub fn arm_supervision(
        &self,
        instance_id: &str,
        plan: &SupervisionAuthorizationPlan,
        authorization_digest: &str,
        approved_boundary: &str,
        run_generation: i64,
        at: &str,
    ) -> Result<SupervisionRow, StateError> {
        let outcome = self.arm_supervision_inner(
            instance_id,
            plan,
            authorization_digest,
            approved_boundary,
            run_generation,
            at,
        );
        if let Err(err) = &outcome {
            self.poison_on(err);
        }
        outcome
    }

    fn arm_supervision_inner(
        &self,
        instance_id: &str,
        plan: &SupervisionAuthorizationPlan,
        authorization_digest: &str,
        approved_boundary: &str,
        run_generation: i64,
        at: &str,
    ) -> Result<SupervisionRow, StateError> {
        self.ensure_writable()?;
        if !crate::formats::is_run_id(instance_id) {
            return Err(state_error(
                "state.supervision_invalid",
                format!("supervision addresses ONE run identity; {instance_id:?} is not one"),
            ));
        }
        if !crate::supervision::DESIRED.contains(&plan.desired.as_str()) {
            return Err(state_error(
                "state.supervision_invalid",
                format!(
                    "desired supervision {:?} is outside the closed set",
                    plan.desired
                ),
            ));
        }
        let mut conn = self.lock("arm_supervision")?;
        let tx = conn
            .transaction()
            .map_err(|err| StateError::from_sqlite("arm_supervision: begin", err))?;
        arm_supervision_in_tx(
            &tx,
            instance_id,
            plan,
            authorization_digest,
            approved_boundary,
            run_generation,
            at,
        )?;
        tx.commit()
            .map_err(|err| StateError::from_sqlite("arm_supervision: commit", err))?;
        self.supervision_row_locked(&conn, instance_id)?
            .ok_or_else(|| state_error("state.supervision_invalid", "supervision row missing"))
    }

    /// One supervision row by run identity.
    pub fn supervision_by_id(
        &self,
        instance_id: &str,
    ) -> Result<Option<SupervisionRow>, StateError> {
        let conn = self.lock("supervision_by_id")?;
        self.supervision_row_locked(&conn, instance_id)
    }

    fn supervision_row_locked(
        &self,
        conn: &Connection,
        instance_id: &str,
    ) -> Result<Option<SupervisionRow>, StateError> {
        conn.query_row(
            format!("{} WHERE instance_id = ?1", supervision_select_sql()).as_str(),
            params![instance_id],
            supervision_row_from,
        )
        .optional()
        .map_err(|err| StateError::from_sqlite("supervision_by_id: read", err))
    }

    /// Every supervision row, ordered by run identity.
    pub fn supervision_rows(&self) -> Result<Vec<SupervisionRow>, StateError> {
        let conn = self.lock("supervision_rows")?;
        let mut statement = conn
            .prepare(format!("{} ORDER BY instance_id", supervision_select_sql()).as_str())
            .map_err(|err| StateError::from_sqlite("supervision_rows: prepare", err))?;
        let rows = statement
            .query_map([], supervision_row_from)
            .map_err(|err| StateError::from_sqlite("supervision_rows: query", err))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(|err| StateError::from_sqlite("supervision_rows: row", err))?);
        }
        Ok(out)
    }

    /// Fold ONE semantic wake into the run's single pending slot. A wake
    /// whose seq already IS the slot's seq is a duplicate and changes
    /// nothing; an older (out-of-order) wake folds without lowering the
    /// slot's seq. Returns whether the slot changed.
    pub fn record_supervision_trigger(
        &self,
        instance_id: &str,
        trigger: &str,
        seq: i64,
        at: &str,
    ) -> Result<bool, StateError> {
        let outcome = self.record_supervision_trigger_inner(instance_id, trigger, seq, at);
        if let Err(err) = &outcome {
            self.poison_on(err);
        }
        outcome
    }

    fn record_supervision_trigger_inner(
        &self,
        instance_id: &str,
        trigger: &str,
        seq: i64,
        at: &str,
    ) -> Result<bool, StateError> {
        self.ensure_writable()?;
        let conn = self.lock("record_supervision_trigger")?;
        Self::fold_trigger_locked(&conn, instance_id, trigger, seq, at)
    }

    /// Fold one wake inside an existing guard/transaction.
    fn fold_trigger_locked(
        conn: &Connection,
        instance_id: &str,
        trigger: &str,
        seq: i64,
        at: &str,
    ) -> Result<bool, StateError> {
        let existing: Option<(String, i64, i64)> = conn
            .query_row(
                "SELECT trigger, trigger_seq, folded FROM supervision_triggers
                  WHERE instance_id = ?1",
                params![instance_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(|err| StateError::from_sqlite("record_supervision_trigger: read", err))?;
        match existing {
            Some((_, current_seq, _)) if current_seq == seq => Ok(false),
            Some((current_trigger, current_seq, folded)) => {
                let (label, next_seq) = if seq > current_seq {
                    (trigger.to_string(), seq)
                } else {
                    (current_trigger, current_seq)
                };
                conn.execute(
                    "UPDATE supervision_triggers
                        SET trigger = ?2, trigger_seq = ?3, folded = ?4, last_at = ?5
                      WHERE instance_id = ?1",
                    params![instance_id, label, next_seq, folded + 1, at],
                )
                .map_err(|err| {
                    StateError::from_sqlite("record_supervision_trigger: update", err)
                })?;
                Ok(true)
            }
            None => {
                conn.execute(
                    "INSERT INTO supervision_triggers (instance_id, trigger, trigger_seq,
                            folded, first_at, last_at)
                     VALUES (?1, ?2, ?3, 1, ?4, ?4)",
                    params![instance_id, trigger, seq, at],
                )
                .map_err(|err| {
                    StateError::from_sqlite("record_supervision_trigger: insert", err)
                })?;
                Ok(true)
            }
        }
    }

    /// The pending wake slot of one run.
    pub fn supervision_trigger(
        &self,
        instance_id: &str,
    ) -> Result<Option<SupervisionTriggerRow>, StateError> {
        let conn = self.lock("supervision_trigger")?;
        conn.query_row(
            "SELECT instance_id, trigger, trigger_seq, folded, first_at, last_at
               FROM supervision_triggers WHERE instance_id = ?1",
            params![instance_id],
            |row| {
                Ok(SupervisionTriggerRow {
                    instance_id: row.get(0)?,
                    trigger: row.get(1)?,
                    trigger_seq: row.get(2)?,
                    folded: row.get(3)?,
                    first_at: row.get(4)?,
                    last_at: row.get(5)?,
                })
            },
        )
        .optional()
        .map_err(|err| StateError::from_sqlite("supervision_trigger: read", err))
    }

    /// The coalesced due set: every ARMED run that has a pending wake OR an
    /// elapsed (or never scheduled) next eligible check — ONE entry per run,
    /// however many wake sources agree. A disabled or absent supervision is
    /// never evaluated.
    pub fn supervision_due_runs(&self, now_unix: i64) -> Result<Vec<String>, StateError> {
        let conn = self.lock("supervision_due_runs")?;
        let mut statement = conn
            .prepare(
                "SELECT s.instance_id
                   FROM supervisions s
                   LEFT JOIN supervision_triggers t ON t.instance_id = s.instance_id
                  WHERE s.desired = 'armed'
                    AND (t.instance_id IS NOT NULL
                         OR s.next_check_unix = 0
                         OR s.next_check_unix <= ?1)
                  ORDER BY s.instance_id",
            )
            .map_err(|err| StateError::from_sqlite("supervision_due_runs: prepare", err))?;
        let rows = statement
            .query_map(params![now_unix], |row| row.get::<_, String>(0))
            .map_err(|err| StateError::from_sqlite("supervision_due_runs: query", err))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(|err| StateError::from_sqlite("supervision_due_runs: row", err))?);
        }
        Ok(out)
    }

    /// Every ARMED run, ordered by run identity: the boot sweep reconciles
    /// each exactly once (a fresh snapshot), so a restart after any number of
    /// missed windows still yields one check per run, never a catch-up storm.
    pub fn supervision_armed_runs(&self) -> Result<Vec<String>, StateError> {
        let conn = self.lock("supervision_armed_runs")?;
        let mut statement = conn
            .prepare(
                "SELECT instance_id FROM supervisions WHERE desired = 'armed' ORDER BY instance_id",
            )
            .map_err(|err| StateError::from_sqlite("supervision_armed_runs: prepare", err))?;
        let rows = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|err| StateError::from_sqlite("supervision_armed_runs: query", err))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(
                row.map_err(|err| StateError::from_sqlite("supervision_armed_runs: row", err))?,
            );
        }
        Ok(out)
    }

    /// Seconds until the nearest scheduled check among armed runs (`None`
    /// when nothing is scheduled).
    pub fn supervision_next_due_in(&self, now_unix: i64) -> Result<Option<i64>, StateError> {
        let conn = self.lock("supervision_next_due_in")?;
        let next: Option<i64> = conn
            .query_row(
                "SELECT MIN(next_check_unix) FROM supervisions
                  WHERE desired = 'armed' AND next_check_unix > 0",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|err| StateError::from_sqlite("supervision_next_due_in: read", err))?
            .flatten();
        Ok(next.map(|unix| (unix - now_unix).max(0)))
    }

    /// Whether this run has committed host-local material for autonomous
    /// dispatch. Queue submission context belongs only to its exact durable
    /// submission; apply context belongs only to its exact run.
    fn has_dispatch_context_locked(
        &self,
        conn: &Connection,
        instance_id: &str,
        submission: Option<&str>,
    ) -> Result<bool, StateError> {
        let mut statement = conn
            .prepare(
                "SELECT method, key, request_line FROM idempotency
                  WHERE method IN ('apply', 'queue.submit') AND outcome IS NOT NULL
                  ORDER BY rowid DESC",
            )
            .map_err(|err| StateError::from_sqlite("supervision dispatch context: prepare", err))?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .map_err(|err| StateError::from_sqlite("supervision dispatch context: query", err))?;
        for row in rows {
            let (method, key, line) = row
                .map_err(|err| StateError::from_sqlite("supervision dispatch context: row", err))?;
            let Ok(request) = Val::parse_json(&line) else {
                continue;
            };
            let Some(params) = request.get("params") else {
                continue;
            };
            if method == "apply"
                && params.get("instance_id").and_then(Val::as_str) == Some(instance_id)
                && matches!(params.get("topology"), Some(Val::Obj(_)))
            {
                return Ok(true);
            }
            if method != "queue.submit" || !matches!(params.get("dispatch"), Some(Val::Obj(_))) {
                continue;
            }
            let Some(digest) = params.get("digest").and_then(Val::as_str) else {
                continue;
            };
            if submission == Some(crate::queue_executor::submission_id(digest, &key).as_str()) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// The recorded-evidence snapshot of one supervised run, read under ONE
    /// guard. `None` when no supervision row exists (a run that was never
    /// authorized is never evaluated).
    pub fn supervision_evidence(
        &self,
        instance_id: &str,
    ) -> Result<Option<SupervisionEvidence>, StateError> {
        let conn = self.lock("supervision_evidence")?;
        let row = match self.supervision_row_locked(&conn, instance_id)? {
            Some(row) => row,
            None => return Ok(None),
        };
        let run: Option<InstanceRow> = conn
            .query_row(
                format!("{} WHERE instance_id = ?1", instance_select_sql()).as_str(),
                params![instance_id],
                instance_row_from,
            )
            .optional()
            .map_err(|err| StateError::from_sqlite("supervision_evidence: run", err))?;
        let Some(run) = run else {
            return Ok(None);
        };
        let mut statement = conn
            .prepare(
                "SELECT i.submission_id, s.digest, s.request_line, i.ordinal, i.work_item,
                        i.issue_number, i.status
                   FROM queue_submission_items i
                   JOIN queue_submissions s ON s.submission_id = i.submission_id
                  WHERE i.instance_id = ?1 AND i.status = 'admitted'
                  ORDER BY i.rowid DESC LIMIT 1",
            )
            .map_err(|err| StateError::from_sqlite("supervision_evidence: submission", err))?;
        let submission: Option<(String, String, String, i64, String, i64, String)> = statement
            .query_row(params![instance_id], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            })
            .optional()
            .map_err(|err| StateError::from_sqlite("supervision_evidence: submission row", err))?;
        drop(statement);
        let (submission_id, submission_digest, steps, reviewer_leg_steps, item) = match submission {
            Some((
                submission_id,
                digest,
                request_line,
                ordinal,
                work_item,
                issue_number,
                status,
            )) => (
                Some(submission_id.clone()),
                Some(digest),
                bound_steps_of(&request_line),
                bound_reviewer_leg_steps_of(&request_line),
                Some(QueueItemRef {
                    submission_id,
                    ordinal,
                    work_item,
                    issue_number,
                    status,
                }),
            ),
            None => (None, None, Vec::new(), Vec::new(), None),
        };
        let has_dispatch_context =
            self.has_dispatch_context_locked(&conn, instance_id, submission_id.as_deref())?;
        let ownership_instance: Option<String> = conn
            .query_row(
                "SELECT instance_id FROM queue_ownership WHERE instance_id = ?1",
                params![instance_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|err| StateError::from_sqlite("supervision_evidence: ownership", err))?;
        let mut statement = conn
            .prepare(
                "SELECT retry_id, instance_id, step_id, attempt, authorized_at, consumed_at,
                        consumed_key
                   FROM run_retries WHERE instance_id = ?1 ORDER BY step_id, attempt",
            )
            .map_err(|err| StateError::from_sqlite("supervision_evidence: retries", err))?;
        let rows = statement
            .query_map(params![instance_id], retry_row_from)
            .map_err(|err| StateError::from_sqlite("supervision_evidence: retries query", err))?;
        let mut retries = Vec::new();
        for row in rows {
            retries.push(
                row.map_err(|err| StateError::from_sqlite("supervision_evidence: retry", err))?,
            );
        }
        drop(statement);
        let attempts = self.run_step_attempts_with_codes(&conn, instance_id)?;
        let mut statement = conn
            .prepare(
                "SELECT evidence_id, verdict, created_at FROM evidence
                  WHERE instance_id = ?1 ORDER BY created_at DESC, evidence_id DESC",
            )
            .map_err(|err| StateError::from_sqlite("supervision_evidence: verdicts", err))?;
        let rows = statement
            .query_map(params![instance_id], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .map_err(|err| StateError::from_sqlite("supervision_evidence: verdicts query", err))?;
        let mut verdicts = Vec::new();
        for row in rows {
            verdicts.push(
                row.map_err(|err| StateError::from_sqlite("supervision_evidence: verdict", err))?,
            );
        }
        drop(statement);
        let in_flight = in_flight_steps_locked(&conn)?
            .into_iter()
            .find(|(run, _)| run == instance_id || run == "*")
            .map(|(_, step)| step);
        // Issue #96: the NEWEST recorded review-evidence row (the same row
        // the board read model and the merge gate read).
        let newest_evidence: Option<EvidenceRow> = conn
            .query_row(
                "SELECT evidence_id, instance_id, repository, feature_head, integration_base,
                        workflow_hash, policy_hash, verdict, reviewer, checks, created_at
                   FROM evidence WHERE instance_id = ?1
                  ORDER BY created_at DESC, evidence_id DESC LIMIT 1",
                params![instance_id],
                evidence_row_from,
            )
            .optional()
            .map_err(|err| StateError::from_sqlite("supervision_evidence: newest", err))?;
        // Issue #141: the newest RECORDED refusal of this run's own
        // continuation dispatch. The driver's dispatch runs through the apply
        // engine, which refuses a fan-out step BEFORE any claim when the
        // run's recorded admission inputs no longer admit it — leaving no
        // attempt row to classify. The journal record is read here so the
        // classification names the engine's own code instead of reporting the
        // step as eligible while nothing happens.
        let dispatch_refusal = conn
            .query_row(
                "SELECT target, at FROM audit
                  WHERE action = ?2 AND target LIKE ?1
                  ORDER BY seq DESC LIMIT 1",
                params![
                    format!("{instance_id}:%"),
                    crate::supervision::codes::DISPATCH_REFUSED
                ],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(|err| StateError::from_sqlite("supervision_evidence: dispatch refusal", err))?
            .and_then(|(target, at)| dispatch_refusal_of(instance_id, &target, &at));
        Ok(Some(SupervisionEvidence {
            run,
            has_dispatch_context,
            ownership_instance,
            submission_id,
            submission_digest,
            steps,
            reviewer_leg_steps,
            attempts,
            retries,
            verdicts,
            in_flight,
            progress_at: row.progress_at,
            item,
            newest_evidence,
            dispatch_refusal,
        }))
    }

    /// Recorded step attempts of one run as `(step, status, error code)` in
    /// claim order, read on the caller's guard. Never inferred: an unreadable
    /// outcome is skipped, and an attempt without a recorded outcome is not
    /// an attempt yet (the claim is still in flight).
    fn run_step_attempts_with_codes(
        &self,
        conn: &Connection,
        instance_id: &str,
    ) -> Result<Vec<(String, String, String)>, StateError> {
        let mut statement = conn
            .prepare(
                "SELECT method, request_line, outcome FROM idempotency
                  WHERE method IN ('apply', 'run.resolve') AND outcome IS NOT NULL
                  ORDER BY rowid",
            )
            .map_err(|err| StateError::from_sqlite("supervision attempts: prepare", err))?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                ))
            })
            .map_err(|err| StateError::from_sqlite("supervision attempts: query", err))?;
        let mut out = Vec::new();
        for row in rows {
            let (method, line, outcome) =
                row.map_err(|err| StateError::from_sqlite("supervision attempts: row", err))?;
            let Some(outcome) = outcome else {
                continue;
            };
            let Ok(request) = Val::parse_json(&line) else {
                continue;
            };
            let params = request.get("params").cloned().unwrap_or_else(null);
            if params.get("instance_id").and_then(Val::as_str) != Some(instance_id) {
                continue;
            }
            let step = params
                .get("step")
                .and_then(Val::as_str)
                .unwrap_or("")
                .to_string();
            let Ok(outcome) = Val::parse_json(&outcome) else {
                continue;
            };
            let status = outcome
                .get("status")
                .and_then(Val::as_str)
                .unwrap_or("unknown")
                .to_string();
            if method == "run.resolve" && status != "succeeded" {
                continue;
            }
            let code = outcome
                .get("error")
                .and_then(|error| error.get("code"))
                .and_then(Val::as_str)
                .unwrap_or("")
                .to_string();
            out.push((step, status, code));
        }
        Ok(out)
    }

    /// Record ONE refused continuation dispatch of a supervised run (issue
    /// #141).
    ///
    /// The apply engine refuses a fan-out dispatch BEFORE its claim when the
    /// run's recorded admission inputs no longer admit it, so the refusal
    /// leaves no attempt row, no pane and no intent to read: it exists only
    /// in the daemon log. Journaling it here (after the fact — never a
    /// mutation intent) makes the refusal durable AND auditable, and the
    /// classification reads it back so a parked run names the engine's own
    /// code instead of reporting its next step eligible while nothing runs.
    ///
    /// The record is journaling only: it claims nothing, authorizes nothing
    /// and never becomes an attempt (no effect ran).
    pub fn record_supervision_dispatch_refusal(
        &self,
        instance_id: &str,
        step: &str,
        code: &str,
    ) -> Result<AuditRow, StateError> {
        let outcome = self.record_supervision_dispatch_refusal_inner(instance_id, step, code);
        if let Err(err) = &outcome {
            self.poison_on(err);
        }
        outcome
    }

    fn record_supervision_dispatch_refusal_inner(
        &self,
        instance_id: &str,
        step: &str,
        code: &str,
    ) -> Result<AuditRow, StateError> {
        self.ensure_writable()?;
        let mut conn = self.lock("record_supervision_dispatch_refusal")?;
        let tx = conn
            .transaction()
            .map_err(|err| StateError::from_sqlite("supervision.dispatch_refused: begin", err))?;
        let mut key = format!("ik_sv-refused-{instance_id}");
        key.truncate(64);
        let audit = self.append_audit_locked(
            &tx,
            crate::supervision::codes::DISPATCH_REFUSED,
            &format!("{instance_id}:{step}:{code}"),
            &key,
            None,
            None,
        )?;
        tx.commit()
            .map_err(|err| StateError::from_sqlite("supervision.dispatch_refused: commit", err))?;
        Ok(audit)
    }

    /// Commit ONE run-scoped reconciliation in one transaction: consume the
    /// pending wake slot (fenced on the exact seq the driver read), advance
    /// the meaningful-progress observation ONLY when the evidence marker
    /// changed, open/close the continuation window, and record the check with
    /// its reason and next eligible check.
    pub fn commit_supervision_check(
        &self,
        plan: &SupervisionCheckPlan,
    ) -> Result<SupervisionRow, StateError> {
        let outcome = self.commit_supervision_check_inner(plan);
        if let Err(err) = &outcome {
            self.poison_on(err);
        }
        outcome
    }

    fn commit_supervision_check_inner(
        &self,
        plan: &SupervisionCheckPlan,
    ) -> Result<SupervisionRow, StateError> {
        self.ensure_writable()?;
        // Issue #98, restart-matrix boundary (a): this reconciliation verified
        // a fresh delivery of the run and the cursor-advance transaction has
        // not started. The durable state at this instant is the recorded
        // delivery evidence alone, so a resumed daemon re-derives the whole
        // advance from it (exactly once).
        if plan.advance.is_some() {
            crate::daemon::crash_point("queue.advance.after-delivery");
        }
        let mut conn = self.lock("commit_supervision_check")?;
        let tx = conn
            .transaction()
            .map_err(|err| StateError::from_sqlite("commit_supervision_check: begin", err))?;
        let row: Option<SupervisionRow> = tx
            .query_row(
                format!("{} WHERE instance_id = ?1", supervision_select_sql()).as_str(),
                params![plan.instance_id],
                supervision_row_from,
            )
            .optional()
            .map_err(|err| StateError::from_sqlite("commit_supervision_check: read", err))?;
        let Some(row) = row else {
            return Err(state_error(
                "state.not_found",
                format!("no supervision exists for run {:?}", plan.instance_id),
            ));
        };
        if row.desired != "armed" {
            return Err(state_error(
                "state.supervision_disabled",
                format!(
                    "supervision {} of run {} is {}, not armed",
                    row.supervision_id, plan.instance_id, row.desired
                ),
            ));
        }
        // Consume the wake slot the driver read: a NEWER wake that arrived
        // while the driver was classifying stays pending for the next pass
        // (never lost, never double-counted).
        if plan.consumed_all {
            tx.execute(
                "DELETE FROM supervision_triggers WHERE instance_id = ?1",
                params![plan.instance_id],
            )
            .map_err(|err| StateError::from_sqlite("commit_supervision_check: consume all", err))?;
        } else if plan.consumed_seq > 0 {
            tx.execute(
                "DELETE FROM supervision_triggers WHERE instance_id = ?1 AND trigger_seq = ?2",
                params![plan.instance_id, plan.consumed_seq],
            )
            .map_err(|err| StateError::from_sqlite("commit_supervision_check: consume", err))?;
        }
        // The meaningful-progress marker moves ONLY when the observed
        // evidence differs: a heartbeat, a read or a rendered status is not
        // progress, so the absence-of-evidence timeout can actually fire.
        let (marker, progress_at, source) = if plan.marker != row.progress_marker {
            (
                plan.marker.clone(),
                plan.at.clone(),
                plan.marker_source.to_string(),
            )
        } else {
            (
                row.progress_marker.clone(),
                row.progress_at.clone(),
                row.progress_source.clone(),
            )
        };
        // One continuation report per absence window.
        let (reports, open, since) = if plan.eligible && !row.continuation_open {
            (row.continuation_reports + 1, true, plan.at.clone())
        } else if plan.eligible {
            (
                row.continuation_reports,
                true,
                row.continuation_since.clone(),
            )
        } else {
            (row.continuation_reports, false, String::new())
        };
        tx.execute(
            "UPDATE supervisions
                SET checks = checks + 1, last_check_at = ?2, last_check_class = ?3,
                    last_check_reason = ?4, last_check_trigger = ?5, next_check_at = ?6,
                    next_check_unix = ?7, next_check_reason = ?8, progress_marker = ?9,
                    progress_at = ?10, progress_source = ?11, continuation_reports = ?12,
                    continuation_open = ?13, continuation_since = ?14, updated_at = ?2
              WHERE instance_id = ?1",
            params![
                plan.instance_id,
                plan.at,
                plan.class,
                plan.reason,
                plan.trigger,
                time::rfc3339_from_unix(plan.next_check_unix),
                plan.next_check_unix,
                plan.next_check_reason,
                marker,
                progress_at,
                source,
                reports,
                if open { 1 } else { 0 },
                since
            ],
        )
        .map_err(|err| StateError::from_sqlite("commit_supervision_check: update", err))?;
        let updated: Option<SupervisionRow> = tx
            .query_row(
                format!("{} WHERE instance_id = ?1", supervision_select_sql()).as_str(),
                params![plan.instance_id],
                supervision_row_from,
            )
            .optional()
            .map_err(|err| StateError::from_sqlite("commit_supervision_check: reread", err))?;
        let Some(updated) = updated else {
            return Err(state_error(
                "state.corrupt",
                "the supervision row vanished inside its own transaction",
            ));
        };
        // Issue #96: the ONE bounded continuation effect — a fresh verified
        // delivery of this run advances the already-authorized queue cursor
        // and admits the next eligible approved issue ATOMICALLY with the
        // reconciliation that recognized it. The whole advance re-reads the
        // delivery, the membership and the idempotency fence under this same
        // guard (see `advance_queue_in_tx`); a refusal inside it rolls the
        // check back rather than committing a half an advance.
        if let Some(delivery) = &plan.advance {
            advance_queue_in_tx(self, &tx, delivery, &plan.instance_id, &plan.at)?;
        }
        tx.commit()
            .map_err(|err| StateError::from_sqlite("commit_supervision_check: commit", err))?;
        // Issue #98, restart-matrix boundary (d): the whole advance is durable.
        // A crash here leaves the consumed delivery, the dispatched run and
        // the cursor row committed together; the resumed daemon re-derives the
        // same delivery and the recorded consumption keeps the restart from
        // repeating any of it.
        if plan.advance.is_some() {
            crate::daemon::crash_point("queue.advance.after-commit");
        }
        Ok(updated)
    }

    /// The durable driver cursor (event cursor + last tick time).
    pub fn supervision_runtime(&self) -> Result<SupervisionRuntime, StateError> {
        let conn = self.lock("supervision_runtime")?;
        conn.query_row(
            "SELECT event_cursor, last_tick_at FROM supervision_runtime WHERE id = 1",
            [],
            |row| {
                Ok(SupervisionRuntime {
                    event_cursor: row.get(0)?,
                    last_tick_at: row.get(1)?,
                })
            },
        )
        .map_err(|err| StateError::from_sqlite("supervision_runtime: read", err))
    }

    /// Persist the driver cursor.
    pub fn set_supervision_runtime(&self, event_cursor: i64, at: &str) -> Result<(), StateError> {
        let outcome = self.set_supervision_runtime_inner(event_cursor, at);
        if let Err(err) = &outcome {
            self.poison_on(err);
        }
        outcome
    }

    fn set_supervision_runtime_inner(&self, event_cursor: i64, at: &str) -> Result<(), StateError> {
        self.ensure_writable()?;
        let conn = self.lock("set_supervision_runtime")?;
        conn.execute(
            "UPDATE supervision_runtime
                SET event_cursor = CASE WHEN event_cursor > ?1 THEN event_cursor ELSE ?1 END,
                    last_tick_at = ?2
              WHERE id = 1",
            params![event_cursor, at],
        )
        .map_err(|err| StateError::from_sqlite("set_supervision_runtime: update", err))?;
        Ok(())
    }

    /// Fold the durable semantic events after `cursor` into the per-run wake
    /// slots. Bounded (at most `WAKE_MAX_ROWS` rows per pass); a cursor that
    /// retention moved past — or a folded event whose audit row was pruned —
    /// reports `lost`, and every armed run then gets a fresh snapshot wake
    /// instead of an incremental one.
    pub fn fold_supervision_events(
        &self,
        cursor: i64,
        at: &str,
    ) -> Result<SupervisionFold, StateError> {
        let outcome = self.fold_supervision_events_inner(cursor, at);
        if let Err(err) = &outcome {
            self.poison_on(err);
        }
        outcome
    }

    fn fold_supervision_events_inner(
        &self,
        cursor: i64,
        at: &str,
    ) -> Result<SupervisionFold, StateError> {
        let mut conn = self.lock("fold_supervision_events")?;
        let armed: Vec<String> = {
            let mut statement = conn
                .prepare("SELECT instance_id FROM supervisions WHERE desired = 'armed' ORDER BY instance_id")
                .map_err(|err| StateError::from_sqlite("fold: armed prepare", err))?;
            let rows = statement
                .query_map([], |row| row.get::<_, String>(0))
                .map_err(|err| StateError::from_sqlite("fold: armed query", err))?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row.map_err(|err| StateError::from_sqlite("fold: armed row", err))?);
            }
            out
        };
        if armed.is_empty() {
            return Ok(SupervisionFold {
                cursor,
                lost: false,
                folded: 0,
                runs: Vec::new(),
            });
        }
        let bounds: (Option<i64>, Option<i64>) = conn
            .query_row("SELECT MAX(seq), MIN(seq) FROM events", [], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .map_err(|err| StateError::from_sqlite("fold: bounds", err))?;
        let (max_seq, min_seq) = bounds;
        let max_seq = max_seq.unwrap_or(0);
        // Retention moved past the cursor: the events between were pruned and
        // can never be folded incrementally.
        let mut lost = match min_seq {
            Some(min) => min > cursor + 1,
            None => cursor > 0,
        };
        let rows: Vec<(i64, String, String)> = {
            let mut statement = conn
                .prepare("SELECT seq, event, data FROM events WHERE seq > ?1 ORDER BY seq LIMIT ?2")
                .map_err(|err| StateError::from_sqlite("fold: events prepare", err))?;
            let rows = statement
                .query_map(
                    params![cursor, crate::supervision::WAKE_MAX_ROWS as i64],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .map_err(|err| StateError::from_sqlite("fold: events query", err))?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row.map_err(|err| StateError::from_sqlite("fold: events row", err))?);
            }
            out
        };
        let mut new_cursor = cursor;
        let mut folded = 0usize;
        let mut runs: Vec<String> = Vec::new();
        let tx = conn
            .transaction()
            .map_err(|err| StateError::from_sqlite("fold: begin", err))?;
        for (seq, event, data) in &rows {
            if *seq > new_cursor {
                new_cursor = *seq;
            }
            if event != "journal.appended" {
                continue;
            }
            let audit_seq = Val::parse_json(data)
                .ok()
                .and_then(|data| data.get("seq").and_then(Val::as_int));
            let Some(audit_seq) = audit_seq else {
                lost = true;
                continue;
            };
            let audit: Option<(String, String)> = tx
                .query_row(
                    "SELECT action, target FROM audit WHERE seq = ?1",
                    params![audit_seq],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(|err| StateError::from_sqlite("fold: audit read", err))?;
            let Some((action, target)) = audit else {
                // The audit row this event named was pruned: the incremental
                // fold cannot attribute it, so fall back to a fresh snapshot.
                lost = true;
                continue;
            };
            let Some(run) = supervision_run_of_target(&target) else {
                continue;
            };
            if !armed.iter().any(|armed_run| armed_run == run) {
                continue;
            }
            let class = supervision_wake_class(&action);
            let run = run.to_string();
            if Self::fold_trigger_locked(&tx, &run, class, *seq, at)? {
                folded += 1;
                if !runs.contains(&run) {
                    runs.push(run);
                }
            }
        }
        if lost {
            let snapshot_seq = max_seq + 1;
            for run in &armed {
                if Self::fold_trigger_locked(&tx, run, "snapshot", snapshot_seq, at)? {
                    folded += 1;
                    if !runs.contains(run) {
                        runs.push(run.clone());
                    }
                }
            }
        }
        tx.commit()
            .map_err(|err| StateError::from_sqlite("fold: commit", err))?;
        Ok(SupervisionFold {
            cursor: new_cursor,
            lost,
            folded,
            runs,
        })
    }
}

/// The `(step id, step kind)` pairs of one committed bound-input line; an
/// unreadable line yields no steps (the classification then holds the run).
fn bound_steps_of(request_line: &str) -> Vec<(String, String)> {
    let Ok(doc) = Val::parse_json(request_line) else {
        return Vec::new();
    };
    doc.get("steps")
        .and_then(Val::as_array)
        .map(|steps| {
            steps
                .iter()
                .filter_map(|step| {
                    let id = step.get("id").and_then(Val::as_str)?;
                    let kind = step.get("kind").and_then(Val::as_str).unwrap_or("");
                    Some((id.to_string(), kind.to_string()))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// The step ids of one committed bound-input line whose OWN params declare
/// the reviewer leg (issue #193): the review steps the run dispatches itself.
/// An unreadable line yields no ids, so a corrupted spine can never authorize
/// a self-dispatch.
fn bound_reviewer_leg_steps_of(request_line: &str) -> Vec<String> {
    let Ok(doc) = Val::parse_json(request_line) else {
        return Vec::new();
    };
    doc.get("steps")
        .and_then(Val::as_array)
        .map(|steps| {
            steps
                .iter()
                .filter(|step| crate::mutation::declares_reviewer_leg(step.get("params")))
                .filter_map(|step| step.get("id").and_then(Val::as_str))
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// Run migration m0011 in one transaction (issue #95: supervised
/// reconciliation: the durable authorization, the ONE pending wake slot per
/// run and the driver cursor).
fn run_m0011(conn: &mut Connection) -> Result<(), StateError> {
    let tx = conn
        .transaction()
        .map_err(|err| StateError::from_sqlite("migrate m0011: begin", err))?;
    let checksum = sha256_hex(M0011_SQL.as_bytes());
    tx.execute_batch(M0011_SQL)
        .map_err(|err| StateError::from_sqlite("migrate m0011", err))?;
    tx.execute(
        "INSERT INTO schema_migrations (migration_id, applies_from, applies_to, checksum, applied_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            M0011_ID,
            M0011_APPLIES_FROM,
            M0011_APPLIES_TO,
            checksum,
            time::rfc3339_now()
        ],
    )
    .map_err(|err| StateError::from_sqlite("migrate m0011: bookkeeping", err))?;
    tx.pragma_update(None, "user_version", M0011_APPLIES_TO)
        .map_err(|err| StateError::from_sqlite("migrate m0011: user_version", err))?;
    tx.commit()
        .map_err(|err| StateError::from_sqlite("migrate m0011: commit", err))?;
    Ok(())
}

/// Supervision tables added by m0011 (issue #95), purely additive: the
/// durable authorization of one run, the ONE pending wake slot per run and
/// the one-row driver cursor.
const M0011_SQL: &str = "\
CREATE TABLE supervisions (
    instance_id TEXT PRIMARY KEY,
    supervision_id TEXT NOT NULL,
    desired TEXT NOT NULL CHECK (desired IN ('armed', 'disabled')),
    owner_generation INTEGER NOT NULL,
    run_generation INTEGER NOT NULL,
    authorization_digest TEXT NOT NULL,
    approved_boundary TEXT NOT NULL,
    check_interval_secs INTEGER NOT NULL,
    progress_timeout_secs INTEGER NOT NULL,
    progress_marker TEXT NOT NULL DEFAULT '',
    progress_at TEXT NOT NULL DEFAULT '',
    progress_source TEXT NOT NULL DEFAULT '',
    checks INTEGER NOT NULL DEFAULT 0,
    continuation_reports INTEGER NOT NULL DEFAULT 0,
    continuation_open INTEGER NOT NULL DEFAULT 0,
    continuation_since TEXT NOT NULL DEFAULT '',
    last_check_at TEXT NOT NULL DEFAULT '',
    last_check_class TEXT NOT NULL DEFAULT '',
    last_check_reason TEXT NOT NULL DEFAULT '',
    last_check_trigger TEXT NOT NULL DEFAULT '',
    next_check_at TEXT NOT NULL DEFAULT '',
    next_check_unix INTEGER NOT NULL DEFAULT 0,
    next_check_reason TEXT NOT NULL DEFAULT '',
    armed_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE supervision_triggers (
    instance_id TEXT PRIMARY KEY,
    trigger TEXT NOT NULL,
    trigger_seq INTEGER NOT NULL,
    folded INTEGER NOT NULL DEFAULT 1,
    first_at TEXT NOT NULL,
    last_at TEXT NOT NULL
);
CREATE TABLE supervision_runtime (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    event_cursor INTEGER NOT NULL DEFAULT 0,
    last_tick_at TEXT NOT NULL DEFAULT ''
);
INSERT INTO supervision_runtime (id, event_cursor, last_tick_at) VALUES (1, 0, '');
";

/// Run the m0012 migration (issue #96): the queue-advance tables and the
/// persisted admission inputs / per-item grant bindings they re-verify.
fn run_m0012(conn: &mut Connection) -> Result<(), StateError> {
    let tx = conn
        .transaction()
        .map_err(|err| StateError::from_sqlite("migrate m0012: begin", err))?;
    let checksum = sha256_hex(M0012_SQL.as_bytes());
    tx.execute_batch(M0012_SQL)
        .map_err(|err| StateError::from_sqlite("migrate m0012", err))?;
    tx.execute(
        "INSERT INTO schema_migrations (migration_id, applies_from, applies_to, checksum, applied_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            M0012_ID,
            M0012_APPLIES_FROM,
            M0012_APPLIES_TO,
            checksum,
            time::rfc3339_now()
        ],
    )
    .map_err(|err| StateError::from_sqlite("migrate m0012: bookkeeping", err))?;
    tx.pragma_update(None, "user_version", M0012_APPLIES_TO)
        .map_err(|err| StateError::from_sqlite("migrate m0012: user_version", err))?;
    tx.commit()
        .map_err(|err| StateError::from_sqlite("migrate m0012: commit", err))?;
    Ok(())
}

/// Queue-advance tables added by m0012 (issue #96), purely additive.
///
/// `queue_submission_items.grant_id` persists the grant the item was
/// admitted against, so the advance re-verifies the SAME presented approval
/// under the guard instead of inventing a grant. `queue_submissions`
/// persists the approved admission inputs (caps + the attested same-harness
/// occupancy), so the advance re-applies exactly the approved fan-out
/// bounds against live counts. `queue_advances` records ONE consumed
/// verified delivery per submission item: `delivered_ordinal` is the
/// idempotency key (a duplicate delivery event, a replayed check or a crash
/// and restart can never consume it twice), `next_instance_id` names the
/// dispatched run of the outcome, and `reason`/`message` record a hold.
const M0012_SQL: &str = "\
ALTER TABLE queue_submission_items ADD COLUMN grant_id TEXT NOT NULL DEFAULT '';
ALTER TABLE queue_submissions ADD COLUMN caps_global INTEGER NOT NULL DEFAULT 0;
ALTER TABLE queue_submissions ADD COLUMN caps_per_repository INTEGER NOT NULL DEFAULT 0;
ALTER TABLE queue_submissions ADD COLUMN caps_per_harness INTEGER NOT NULL DEFAULT 0;
ALTER TABLE queue_submissions ADD COLUMN harness_lanes INTEGER;
CREATE TABLE queue_advances (
    submission_id TEXT NOT NULL,
    delivered_ordinal INTEGER NOT NULL,
    delivered_work_item TEXT NOT NULL,
    delivered_head TEXT NOT NULL,
    evidence_id TEXT NOT NULL,
    next_ordinal INTEGER,
    next_work_item TEXT,
    next_instance_id TEXT,
    reason TEXT,
    message TEXT,
    at TEXT NOT NULL,
    PRIMARY KEY (submission_id, delivered_ordinal)
);
";

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn temp_db(name: &str) -> PathBuf {
        let base = std::env::temp_dir().join(format!("hf-state-{}", std::process::id()));
        std::fs::create_dir_all(&base).expect("temp dir");
        let path = base.join(name);
        let _ = std::fs::remove_file(&path);
        path
    }

    fn retention_tiny() -> Retention {
        Retention {
            audit_rows: 4,
            event_rows: 4,
        }
    }

    fn sample_request_line(key: &str) -> String {
        canonical_text(&object(vec![
            ("schema", string("hf-rpc-request/v1")),
            ("id", string(&"a".repeat(16))),
            ("method", string("backup.create")),
            ("params", object(vec![("idempotency_key", string(key))])),
        ]))
    }

    /// A synthetic hf-grant/v1 document (all AC3 bindings).
    fn sample_grant_doc() -> Val {
        let workflow_hash = "0".repeat(64);
        let policy_hash = "f".repeat(64);
        object(vec![
            ("schema", string("hf-grant/v1")),
            ("grant_id", string("gr_0123456789abcdef")),
            ("repository", string("example-org/widgets")),
            (
                "issue",
                object(vec![
                    ("number", integer(123)),
                    ("revision", string(&"a".repeat(40))),
                ]),
            ),
            ("workflow_hash", string(&workflow_hash)),
            ("policy_hash", string(&policy_hash)),
            ("phase", string("merge")),
            ("scope", string("worktrees/issues/123")),
            ("caps", Val::Arr(vec![string("read"), string("merge")])),
            ("expires_at", string("2999-01-01T00:00:00Z")),
            ("state_epoch", integer(1)),
            ("created_at", string("2026-09-06T00:00:00Z")),
        ])
    }

    /// A synthetic hf-schedule/v1 document (all recurring-grant bindings;
    /// cadence 300s anchored at 2026-09-06T00:00:00Z).
    fn sample_schedule_doc(schedule_id: &str) -> Val {
        object(vec![
            ("schema", string("hf-schedule/v1")),
            ("schedule_id", string(schedule_id)),
            ("repository", string("example-org/widgets")),
            (
                "issue",
                object(vec![
                    ("number", integer(123)),
                    ("revision", string(&"a".repeat(40))),
                ]),
            ),
            ("workflow_hash", string(&"0".repeat(64))),
            ("policy_hash", string(&"f".repeat(64))),
            ("phase", string("read")),
            ("scope", string("worktrees/issues/123")),
            ("caps", Val::Arr(vec![string("read")])),
            ("expires_at", string("2999-01-01T00:00:00Z")),
            ("anchor", string("2026-09-06T00:00:00Z")),
            ("every_secs", integer(300)),
        ])
    }

    #[test]
    fn m0002_migrates_instances_for_the_engine() {
        let path = temp_db("m0002.db");
        let state = State::open(&path, Retention::default()).expect("open");
        let (_, _, _, version) = state.summary().expect("summary");
        assert_eq!(version, SCHEMA_VERSION);
        // A legacy v1 database is migrated in place (m0002 adds engine
        // columns); reopening never loses recorded migrations.
        let reopened = State::open(&path, Retention::default()).expect("reopen");
        assert_eq!(reopened.list_instances().expect("list").len(), 0);
    }

    #[test]
    fn m0004_schedule_rows_carry_docs_and_survive_reopen() {
        let path = temp_db("m0004.db");
        let state = State::open(&path, Retention::default()).expect("open");
        let (_, _, _, version) = state.summary().expect("summary");
        assert_eq!(
            version, SCHEMA_VERSION,
            "the full migration chain is applied on a fresh database"
        );
        // A v3-era database (m0003 applied, m0004 pending) migrates forward:
        // the migration runner applies m0004 in place and the bookkeeping
        // row exists for the whole chain.
        // Upsert + durable doc/pause/window round trip.
        let doc = sample_schedule_doc("sd_0123456789abcdef");
        let row = state.upsert_schedule(&doc).expect("upsert");
        assert!(row.enabled);
        assert_eq!(row.doc, canonical_text(&doc));
        assert_eq!(row.next_run_at, None, "fresh create is due immediately");
        state
            .complete_schedule_run("sd_0123456789abcdef", Some("2026-09-06T01:00:00Z"), "t")
            .expect("complete run");
        state
            .pause_schedule_with_reason("sd_0123456789abcdef", "expired", "t")
            .expect("pause");
        let reopened = State::open(&path, Retention::default()).expect("reopen");
        let row = reopened
            .schedule_by_id("sd_0123456789abcdef")
            .expect("row")
            .expect("present");
        assert!(!row.enabled, "pause survives reopen");
        assert_eq!(
            row.next_run_at.as_deref(),
            Some("2026-09-06T01:00:00Z"),
            "persisted window survives reopen"
        );
        reopened
            .set_schedule_enabled("sd_0123456789abcdef", true, "t")
            .expect("resume");
        let resumed = reopened
            .schedule_by_id("sd_0123456789abcdef")
            .expect("row")
            .expect("present");
        assert!(resumed.enabled);
        assert_eq!(resumed.next_run_at, None, "resume resets to due now");
        // Journal side effects: audit rows + schedule.ran events exist.
        let (_, lines) = reopened.journal_tail(0, 10).expect("journal tail");
        let ran_lines: Vec<&String> = lines
            .iter()
            .filter(|line| line.contains("read.schedule.ran"))
            .collect();
        assert_eq!(ran_lines.len(), 2, "run + pause reason journaled");
        let events = reopened.events_after(0, 10).expect("events");
        assert!(
            events
                .iter()
                .any(|event| event.get("event").and_then(Val::as_str) == Some("schedule.ran")),
            "schedule.ran event appended"
        );
    }

    #[test]
    fn grant_issuance_binds_and_duplicates_are_refused() {
        let path = temp_db("engine-grants.db");
        let state = State::open(&path, Retention::default()).expect("open");
        let grant = state.issue_grant(&sample_grant_doc()).expect("issue");
        assert_eq!(grant.status, "active");
        assert_eq!(state.list_grants().expect("list").len(), 1);

        let duplicate = state
            .issue_grant(&sample_grant_doc())
            .expect_err("duplicate refused");
        assert_eq!(duplicate.code, "state.grant_exists");

        // Wrong epoch is refused (grants die with their epoch).
        let mut doc = sample_grant_doc();
        let map = match &mut doc {
            Val::Obj(map) => map,
            _ => unreachable!(),
        };
        map.insert("state_epoch".to_string(), integer(99));
        let wrong_epoch = state.issue_grant(&doc).expect_err("epoch refused");
        assert_eq!(wrong_epoch.code, "state.epoch_mismatch");
    }

    #[test]
    fn engine_instance_pause_is_durable_across_restart_and_resume_needs_fresh_digest() {
        let path = temp_db("engine-pause.db");
        let at = "2026-09-06T00:00:00Z";
        {
            let state = State::open(&path, Retention::default()).expect("open");
            state.issue_grant(&sample_grant_doc()).expect("issue");
            state
                .start_instance("run-1", "gr_0123456789abcdef", "fleet-doctrine-1", at)
                .expect("start");
            let digest = crate::engine::mint_resume_digest("run-1", 1, "pause-1");
            state.pause_instance("run-1", &digest, at).expect("pause");
            let row = state.instance_by_id("run-1").expect("read").expect("row");
            assert!(row.paused);
            assert_eq!(row.resume_digest, digest);
            // A stale digest is refused before any state change.
            let stale = state
                .resume_instance("run-1", &"0".repeat(64), at)
                .expect_err("stale digest refused");
            assert_eq!(stale.code, "state.stale_resume");
        }
        // Restart: reopen the same state file; pause must survive.
        {
            let state = State::open(&path, Retention::default()).expect("reopen");
            let row = state.instance_by_id("run-1").expect("read").expect("row");
            assert!(row.paused, "pause durable across restart");
            assert!(!row.resume_digest.is_empty());
            let fresh = crate::engine::mint_resume_digest("run-1", 1, "pause-1");
            state.resume_instance("run-1", &fresh, at).expect("resume");
            let row = state.instance_by_id("run-1").expect("read").expect("row");
            assert!(!row.paused);
            assert_eq!(row.status, "running");
            // Digest is consumed: the same digest cannot resume again.
            let replay = state
                .resume_instance("run-1", &fresh, at)
                .expect_err("digest consumed");
            assert_eq!(replay.code, "state.not_paused");
        }
    }

    #[test]
    fn issue_edit_invalidates_grant_and_engine_stops_further_mutation() {
        let path = temp_db("engine-issue-edit.db");
        let at = "2026-09-06T00:00:00Z";
        let state = State::open(&path, Retention::default()).expect("open");
        state.issue_grant(&sample_grant_doc()).expect("issue");
        let grant = state
            .grant_by_id("gr_0123456789abcdef")
            .expect("read")
            .expect("grant");

        // Material issue/acceptance edit: observed revision differs.
        let mut edited = "a".repeat(40);
        edited.replace_range(0..1, "b");
        let refused = crate::engine::grant_binding_valid(&grant.issue_revision, &edited)
            .expect_err("stale grant");
        assert_eq!(refused.code, "engine.grant_stale");
        state
            .invalidate_grant("gr_0123456789abcdef", at)
            .expect("invalidate");
        let after = state
            .grant_by_id("gr_0123456789abcdef")
            .expect("read")
            .expect("grant");
        assert_eq!(after.status, "invalidated");
        // Active-grant listing no longer offers it; a bound instance cannot
        // start on an invalidated grant.
        assert_eq!(state.list_grants().expect("list").len(), 0);
        let denied = state
            .start_instance("run-2", "gr_0123456789abcdef", "fleet-doctrine-1", at)
            .expect_err("start refused");
        assert_eq!(denied.code, "state.grant_inactive");
    }

    #[test]
    fn engine_advance_persists_review_rounds_and_blockers() {
        let path = temp_db("engine-advance.db");
        let at = "2026-09-06T00:00:00Z";
        let state = State::open(&path, Retention::default()).expect("open");
        state.issue_grant(&sample_grant_doc()).expect("issue");
        state
            .start_instance("run-3", "gr_0123456789abcdef", "fleet-doctrine-1", at)
            .expect("start");
        state
            .advance_instance("run-3", "exact-head-review", 1, 0, false, 0, at)
            .expect("advance");
        let row = state.instance_by_id("run-3").expect("read").expect("row");
        assert_eq!(row.current_node, "exact-head-review");
        assert_eq!(row.normal_rounds, 1);
        assert_eq!(row.status, "running");
        // Review exhaustion -> human queue; a terminal blocker is counted.
        state
            .advance_instance("run-3", "exact-head-review", 3, 1, true, 1, at)
            .expect("advance");
        let row = state.instance_by_id("run-3").expect("read").expect("row");
        assert!(row.human_queue);
        assert_eq!(row.terminal_blockers, 1);
        assert_eq!(row.status, "human_queue");
    }

    #[test]
    fn open_migrates_and_seeds_epoch_and_genesis() {
        let path = temp_db("migrate.db");
        let state = State::open(&path, Retention::default()).expect("open");
        assert_eq!(state.current_epoch().expect("epoch"), 1);
        let (epoch, audit_seq, event_seq, version) = state.summary().expect("summary");
        assert_eq!(
            (epoch, audit_seq, event_seq, version),
            (1, 0, 0, SCHEMA_VERSION)
        );
        assert_eq!(state.verify_chain(), Ok(()));
        let doc = state.epoch_doc().expect("epoch doc");
        assert_eq!(doc.get("reason").and_then(Val::as_str), Some("initial"));
    }

    #[test]
    fn schema_too_new_fails_closed() {
        let path = temp_db("future.db");
        {
            let conn = Connection::open(&path).expect("open");
            conn.pragma_update(None, "user_version", SCHEMA_VERSION + 1)
                .expect("set future version");
        }
        let err = State::open(&path, Retention::default()).expect_err("must refuse");
        assert_eq!(err.code, "state.schema_future");
    }

    #[test]
    fn corrupt_database_fails_closed() {
        let path = temp_db("corrupt.db");
        std::fs::write(&path, b"this is not a sqlite database at all........").expect("write");
        let err = State::open(&path, Retention::default()).expect_err("must refuse");
        assert_eq!(err.code, "state.corrupt");
    }

    #[test]
    fn intent_then_resolution_journals_chain_and_claims() {
        let path = temp_db("intent.db");
        let state = State::open(&path, Retention::default()).expect("open");
        let key = "ik_apply-20260906-0001";
        let request = sample_request_line(key);
        let (attempt, audit) = state
            .journal_intent(
                "mutate.backup.create",
                "example-org/widgets",
                key,
                &"a".repeat(16),
                "backup.create",
                None,
                None,
                &request,
            )
            .expect("journal intent");
        assert_eq!(attempt, ClaimAttempt::Claimed);
        let audit = audit.expect("audit row");
        assert_eq!(audit.seq, 1);
        assert!(audit.line.contains("\"recorded_before_mutation\":true"));
        assert_eq!(state.verify_chain(), Ok(()));

        let outcome_line = canonical_text(&object(vec![
            ("schema", string("hf-outcome/v1")),
            ("plan_id", string("hf_plan_0123456789abcdef")),
            ("step_id", string("p1")),
            ("status", string("succeeded")),
            ("idempotency_key", string(key)),
            ("observed_at", string(&time::rfc3339_now())),
            ("result", object(vec![("exit_code", integer(0))])),
            ("error", null()),
        ]));
        let response_line = canonical_text(&object(vec![
            ("schema", string("hf-rpc-response/v1")),
            ("id", string(&"a".repeat(16))),
            ("ok", bool_(true)),
            ("result", object(vec![("backup", string("manifest-1"))])),
            ("error", null()),
        ]));
        state
            .resolve_claim(
                key,
                "backup.create",
                "spent",
                &outcome_line,
                Some(&response_line),
            )
            .expect("resolve");

        // Replay: same request + key returns the recorded response.
        let (attempt, _) = state
            .journal_intent(
                "mutate.backup.create",
                "example-org/widgets",
                key,
                &"a".repeat(16),
                "backup.create",
                None,
                None,
                &request,
            )
            .expect("replay");
        match attempt {
            ClaimAttempt::Replay { response } => {
                assert_eq!(response, response_line);
            }
            other => panic!("expected replay, got {other:?}"),
        }
        // A different request reusing the key is refused.
        let other_request = canonical_text(&object(vec![
            ("schema", string("hf-rpc-request/v1")),
            ("id", string(&"b".repeat(16))),
            ("method", string("backup.create")),
            ("params", object(vec![("idempotency_key", string(key))])),
        ]));
        let err = state
            .journal_intent(
                "mutate.backup.create",
                "example-org/widgets",
                key,
                &"b".repeat(16),
                "backup.create",
                None,
                None,
                &other_request,
            )
            .expect_err("reused key must refuse");
        assert_eq!(err.code, "state.claim_reused");
        assert_eq!(state.verify_chain(), Ok(()));
    }

    #[test]
    fn pending_claim_is_a_recovery_checkpoint() {
        let path = temp_db("pending.db");
        let state = State::open(&path, Retention::default()).expect("open");
        let key = "ik_backup-20260906-0042";
        state
            .journal_intent(
                "mutate.backup.create",
                "example-org/widgets",
                key,
                &"c".repeat(16),
                "backup.create",
                None,
                None,
                &sample_request_line(key),
            )
            .expect("journal intent");
        let pending = state.claims_in_flight().expect("pending");
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].key, key);
        assert_eq!(pending[0].status, "claimed");
        assert!(pending[0].response.is_none());
    }

    #[test]
    fn retention_prunes_but_keeps_genesis_and_chain_intact() {
        let path = temp_db("retention.db");
        let state = State::open(&path, retention_tiny()).expect("open");
        for i in 0..10 {
            let key = format!("ik_retention-{:08}", i);
            state
                .journal_intent(
                    "mutate.backup.create",
                    "example-org/widgets",
                    &key,
                    &"d".repeat(16),
                    "backup.create",
                    None,
                    None,
                    &sample_request_line(&key),
                )
                .expect("journal intent");
            let outcome = canonical_text(&object(vec![
                ("schema", string("hf-outcome/v1")),
                ("plan_id", string("hf_plan_0123456789abcdef")),
                ("step_id", string("p1")),
                ("status", string("refused")),
                ("idempotency_key", string(&key)),
                ("observed_at", string(&time::rfc3339_now())),
                ("result", null()),
                (
                    "error",
                    object(vec![
                        ("code", string("refusal.effect.unregistered")),
                        ("message", string("no effect handler")),
                    ]),
                ),
            ]));
            state
                .resolve_claim(&key, "backup.create", "spent", &outcome, None)
                .expect("resolve");
        }
        assert_eq!(state.verify_chain(), Ok(()), "chain survives pruning");
        let (first_retained, lines) = state.journal_tail(-1, 100).expect("tail");
        assert_eq!(lines.len(), 5, "genesis + retention window of 4");
        assert_eq!(first_retained, 0);
        let (event_max, event_min) = state.event_bounds().expect("bounds");
        assert!(event_max.is_some(), "events were journaled");
        assert_eq!(
            event_max.expect("max") - event_min.expect("min") + 1,
            4,
            "events pruned to the tail window"
        );
        assert!(
            state
                .claim("ik_retention-00000009")
                .expect("claim")
                .is_some()
        );
    }

    #[test]
    fn audit_tamper_breaks_the_chain_detection() {
        let path = temp_db("tamper.db");
        let state = State::open(&path, Retention::default()).expect("open");
        // De-shaped at runtime: the static tree must never carry a
        // secret-shaped literal (public-tree scanners gate on the tracked
        // tree, so the fixture key is assembled here instead).
        let key = format!("ik_tamper-{}-0001", "20260906");
        state
            .journal_intent(
                "mutate.backup.create",
                "example-org/widgets",
                &key,
                &"e".repeat(16),
                "backup.create",
                None,
                None,
                &sample_request_line(&key),
            )
            .expect("journal intent");
        assert_eq!(state.verify_chain(), Ok(()));
        drop(state);
        // Tamper with the stored line (simulates a modified journal row).
        {
            let conn = Connection::open(&path).expect("reopen");
            conn.execute(
                "UPDATE audit SET target = 'tampered-target' WHERE seq = 1",
                [],
            )
            .expect("tamper");
        }
        let reopened =
            State::open(&path, Retention::default()).expect_err("tamper must fail closed");
        assert_eq!(reopened.code, "state.audit_tampered");
    }

    #[test]
    fn mirror_rebuilds_from_table_after_drift() {
        let path = temp_db("mirror.db");
        let mirror = path.with_extension("mirror.jsonl");
        let state = State::open(&path, Retention::default()).expect("open");
        let key = "ik_mirror-20260906-0001";
        state
            .journal_intent(
                "mutate.backup.create",
                "example-org/widgets",
                key,
                &"f".repeat(16),
                "backup.create",
                None,
                None,
                &sample_request_line(key),
            )
            .expect("journal intent");
        // A missing mirror is rebuilt from the table.
        assert!(state.rebuild_audit_mirror(&mirror).expect("rebuild"));
        // A matching mirror is not rebuilt.
        assert!(!state.rebuild_audit_mirror(&mirror).expect("rebuild"));
        // A drifted mirror is detected and rebuilt.
        let content = fs::read_to_string(&mirror).expect("read mirror");
        let mut lines: Vec<String> = content.lines().map(str::to_string).collect();
        lines.push("{\"tampered\":true}".to_string());
        fs::write(&mirror, lines.join("\n") + "\n").expect("tamper mirror");
        assert!(
            state
                .rebuild_audit_mirror(&mirror)
                .expect("rebuild detects drift")
        );
        assert_eq!(fs::read_to_string(&mirror).expect("read rebuilt"), content);
    }

    #[test]
    fn grants_revoke_list_and_epoch_invalidation() {
        let path = temp_db("grants.db");
        let state = State::open(&path, Retention::default()).expect("open");
        // Fixture setup via the raw connection (grants issuance is a later
        // slice; these rows stand in for operator-issued grants).
        {
            let conn = Connection::open(&path).expect("open");
            conn.execute(
                "INSERT INTO grants (grant_id, repository, issue_number, issue_revision,
                                     workflow_hash, policy_hash, phase, scope, caps,
                                     expires_at, state_epoch, status, created_at)
                 VALUES ('gr_0000000000000001', 'example-org/widgets', 123,
                         '0123456789abcdef0123456789abcdef01234567',
                         '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
                         'feedface01234567feedface01234567feedface01234567feedface01234567',
                         'merge', 'worktrees/issues/123',
                         '[\"read\",\"merge\"]', '2999-01-01T00:00:00Z', 1, 'active', ?1)",
                params![time::rfc3339_now()],
            )
            .expect("seed grant");
        }
        let grants = state.list_grants().expect("list");
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0].grant_id, "gr_0000000000000001");

        state
            .revoke_grant("gr_0000000000000001", "2026-09-06T00:00:00Z")
            .expect("revoke");
        assert_eq!(state.list_grants().expect("list after revoke").len(), 0);

        // Re-seed for the epoch invalidation path (restore semantics).
        {
            let conn = Connection::open(&path).expect("open");
            conn.execute(
                "INSERT INTO grants (grant_id, repository, issue_number, issue_revision,
                                     workflow_hash, policy_hash, phase, scope, caps,
                                     expires_at, state_epoch, status, created_at)
                 VALUES ('gr_0000000000000002', 'example-org/widgets', 123,
                         '0123456789abcdef0123456789abcdef01234567',
                         '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
                         'feedface01234567feedface01234567feedface01234567feedface01234567',
                         'merge', 'worktrees/issues/123',
                         '[\"read\"]', '2999-01-01T00:00:00Z', 1, 'active', ?1)",
                params![time::rfc3339_now()],
            )
            .expect("re-seed grant");
        }
        state.rotate_epoch("restore").expect("rotate");
        state.invalidate_grants_below_current().expect("invalidate");
        let remaining = state.list_grants().expect("list after invalidation");
        assert!(remaining.is_empty(), "grants die with their epoch");
        assert_eq!(state.current_epoch().expect("epoch"), 2);
    }

    /// Issue #190: the RETIRED generations of one repository issue — the
    /// terminal runs whose lane residue a successor may retire — are exactly
    /// the ledger's `invalidated`/`done` rows for that repository+issue,
    /// ordered by run identity. A live run is never in the set (it still holds
    /// its issue's ownership), and another issue/repository is never in it.
    #[test]
    fn retired_run_ids_lists_only_terminal_generations_of_the_issue() {
        let path = temp_db("retired-runs.db");
        let state = State::open(&path, Retention::default()).expect("open");
        for (grant_id, issue) in [("gr_0000000000000011", 190), ("gr_0000000000000012", 191)] {
            let doc = Val::parse_json(&format!(
                r#"{{"schema":"hf-grant/v1","grant_id":"{grant_id}","repository":"example-org/widgets",
                    "issue":{{"number":{issue},"revision":"{}"}},
                    "workflow_hash":"{}","policy_hash":"{}","phase":"merge",
                    "scope":"worktrees/issues/{issue}","caps":["read","worktree","spawn","prompt"],
                    "expires_at":"2999-01-01T00:00:00Z","state_epoch":1,
                    "created_at":"2026-09-18T00:00:00Z"}}"#,
                "a".repeat(40),
                "b".repeat(64),
                "c".repeat(64),
            ))
            .expect("grant doc");
            state.issue_grant(&doc).expect("issue grant");
        }
        let at = "2026-09-18T00:00:00Z";
        for (run, grant) in [
            ("run-00000000000000a1", "gr_0000000000000011"),
            ("run-00000000000000a2", "gr_0000000000000011"),
            ("run-00000000000000b1", "gr_0000000000000012"),
        ] {
            state
                .start_instance(run, grant, "fleet-doctrine-1", at)
                .expect("start");
        }
        // One retired generation of issue 190; the other run stays live and
        // the third belongs to another issue.
        state
            .release_run(
                "run-00000000000000a1",
                "superseded generation",
                "ik_retired-0001",
                at,
            )
            .expect("release");
        assert_eq!(
            state
                .retired_run_ids("example-org/widgets", 190)
                .expect("retired"),
            vec!["run-00000000000000a1".to_string()]
        );
        assert!(
            state
                .retired_run_ids("example-org/widgets", 191)
                .expect("retired")
                .is_empty(),
            "another issue's runs are never in the set"
        );
        assert!(
            state
                .retired_run_ids("example-org/other", 190)
                .expect("retired")
                .is_empty(),
            "another repository's runs are never in the set"
        );
        // Every retired generation of the issue joins the set, ordered.
        state
            .release_run(
                "run-00000000000000a2",
                "superseded generation",
                "ik_retired-0002",
                at,
            )
            .expect("release");
        state
            .release_run(
                "run-00000000000000b1",
                "superseded generation",
                "ik_retired-0003",
                at,
            )
            .expect("release");
        assert_eq!(
            state
                .retired_run_ids("example-org/widgets", 190)
                .expect("retired"),
            vec![
                "run-00000000000000a1".to_string(),
                "run-00000000000000a2".to_string()
            ]
        );
    }

    #[test]
    fn daemon_lease_upsert_and_drop() {
        let path = temp_db("lease.db");
        let state = State::open(&path, Retention::default()).expect("open");
        state
            .put_daemon_lease(4242, "2026-09-06T00:00:00Z")
            .expect("put");
        state
            .put_daemon_lease(4243, "2026-09-06T00:00:01Z")
            .expect("put overwrite (stale recovery)");
        state.drop_daemon_lease().expect("drop");
        assert_eq!(state.list_schedules().expect("schedules").len(), 0);
    }

    // ---------------------------------------------------------------------
    // Issue #8: durable review evidence, recorded approvals (m0003), and C3
    // instance invalidation wiring
    // ---------------------------------------------------------------------

    fn sample_checks() -> Val {
        Val::Arr(vec![
            object(vec![
                ("name", string("exact-head-review")),
                ("status", string("passed")),
            ]),
            object(vec![
                ("name", string("hosted-ci")),
                ("status", string("passed")),
            ]),
        ])
    }

    #[test]
    fn m0003_evidence_round_trips_and_refuses_bad_bindings() {
        let path = temp_db("m0003-evidence.db");
        let state = State::open(&path, Retention::default()).expect("open");
        let (_, _, _, version) = state.summary().expect("summary");
        assert_eq!(
            version, SCHEMA_VERSION,
            "schema version {} after the full migration chain (m0001..m0005)",
            SCHEMA_VERSION
        );
        state.issue_grant(&sample_grant_doc()).expect("issue");
        state
            .start_instance(
                "run-1",
                "gr_0123456789abcdef",
                "fleet-doctrine-1",
                "2026-09-06T00:00:00Z",
            )
            .expect("start");
        let row = state
            .record_evidence(
                "run-1",
                "example-org/widgets",
                &"a".repeat(40),
                &"b".repeat(40),
                &"0".repeat(64),
                &"f".repeat(64),
                "pass",
                "reviewer-1",
                &sample_checks(),
            )
            .expect("record evidence");
        assert!(row.evidence_id.starts_with("ev_"));
        let by_id = state.evidence_by_id(&row.evidence_id).expect("by id");
        assert_eq!(by_id.expect("row").feature_head, "a".repeat(40));
        let rows = state.evidence_for_instance("run-1").expect("for instance");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].verdict, "pass");
        // Bad bindings refuse at the record boundary.
        let bad = state.record_evidence(
            "run-1",
            "example-org/widgets",
            "not-a-sha",
            &"b".repeat(40),
            &"0".repeat(64),
            &"f".repeat(64),
            "pass",
            "reviewer-1",
            &sample_checks(),
        );
        assert_eq!(
            bad.expect_err("bad head refused").code,
            "state.evidence_invalid"
        );
        let bad_verdict = state.record_evidence(
            "run-1",
            "example-org/widgets",
            &"a".repeat(40),
            &"b".repeat(40),
            &"0".repeat(64),
            &"f".repeat(64),
            "maybe",
            "reviewer-1",
            &sample_checks(),
        );
        assert_eq!(
            bad_verdict.expect_err("bad verdict refused").code,
            "state.evidence_invalid"
        );
    }

    #[test]
    fn first_write_approval_records_are_monotonic_and_scoped() {
        let path = temp_db("m0003-approvals.db");
        let state = State::open(&path, Retention::default()).expect("open");
        let approval = state
            .record_approval("first-write-canary", &"a".repeat(64), true)
            .expect("record approval");
        assert!(approval.approval_id.starts_with("ap_"));
        assert!(approval.interactive);
        let found = state
            .approval_for_scope("first-write-canary")
            .expect("lookup")
            .expect("row");
        assert_eq!(found.digest, "a".repeat(64));
        // Closed scope only; bad digests refuse.
        assert_eq!(
            state
                .record_approval("some-other-scope", &"a".repeat(64), true)
                .expect_err("scope refused")
                .code,
            "state.approval_invalid"
        );
        assert_eq!(
            state
                .record_approval("first-write-canary", "short", true)
                .expect_err("digest refused")
                .code,
            "state.approval_invalid"
        );
    }

    #[test]
    fn c3_instance_invalidation_follows_grant_invalidation_and_epoch_rotation() {
        // C3 RED/GREEN: invalidating a grant invalidates its bound running
        // instances; rotating the epoch (restore) invalidates instances
        // below the new epoch.
        let path = temp_db("c3-invalidation.db");
        let state = State::open(&path, Retention::default()).expect("open");
        let at = "2026-09-06T00:00:00Z";
        state.issue_grant(&sample_grant_doc()).expect("issue");
        state
            .start_instance("run-1", "gr_0123456789abcdef", "fleet-doctrine-1", at)
            .expect("start");
        let row = state.instance_by_id("run-1").expect("read").expect("row");
        assert_eq!(row.status, "new");

        state
            .invalidate_grant("gr_0123456789abcdef", at)
            .expect("invalidate");
        let row = state.instance_by_id("run-1").expect("read").expect("row");
        assert_eq!(
            row.status, "invalidated",
            "C3: an instance bound to an invalidated grant must be invalidated"
        );
        // A done/absent instance is untouched by the wiring.
        assert_eq!(state.instance_by_id("run-9").expect("read"), None);

        // Restore rotation: a fresh grant+instance under epoch 1 die when
        // the epoch rotates to 2.
        let path2 = temp_db("c3-restore.db");
        let state2 = State::open(&path2, Retention::default()).expect("open");
        state2.issue_grant(&sample_grant_doc()).expect("issue");
        state2
            .start_instance("run-1", "gr_0123456789abcdef", "fleet-doctrine-1", at)
            .expect("start");
        state2.rotate_epoch("restore").expect("rotate");
        state2
            .invalidate_grants_below_current()
            .expect("invalidate below");
        let row = state2.instance_by_id("run-1").expect("read").expect("row");
        assert_eq!(
            row.status, "invalidated",
            "C3: restore rotation invalidates instances that died with their epoch"
        );
        assert!(state2.list_grants().expect("list").is_empty());
    }

    #[test]
    fn salvage_journal_record_completes_the_cleanup_audit_pair() {
        let path = temp_db("salvage.db");
        let state = State::open(&path, Retention::default()).expect("open");
        let audit = state
            .journal_salvage("example-org/widgets:worktrees/issues/123", "run-1")
            .expect("salvage journal");
        assert_eq!(audit.seq, 1, "salvage follows the genesis row");
        let lines = state.journal_tail(0, 10).expect("tail").1;
        let line = lines
            .iter()
            .find(|line| line.contains("salvage.cleanup"))
            .expect("salvage line in the journal");
        let doc = Val::parse_json(line).expect("parse");
        assert_eq!(
            doc.get("action").and_then(Val::as_str),
            Some("salvage.cleanup")
        );
        assert_eq!(
            doc.get("recorded_before_mutation").and_then(Val::as_bool),
            Some(false),
            "salvage is post-deletion evidence (the mutate.cleanup intent is the before record)"
        );
    }

    #[test]
    fn lane_replacement_migration_preserves_stored_grants() {
        // Issue #73 AC6: the m0005 upgrade is purely additive. A database
        // written at schema v4 (m0001..m0004) with a stored grant upgrades
        // in place; the grant row (and the epoch) are exactly what they
        // were — existing stored grants are never reinterpreted.
        let path = temp_db("replacement-upgrade.db");
        {
            let mut conn = Connection::open(&path).expect("open raw");
            run_initial_migration(&mut conn).expect("m0001");
            run_m0002(&mut conn).expect("m0002");
            run_m0003(&mut conn).expect("m0003");
            run_m0004(&mut conn).expect("m0004");
            let version: i64 = conn
                .query_row("PRAGMA user_version", [], |row| row.get(0))
                .expect("user_version");
            assert_eq!(version, 4, "raw fixture lands at schema v4");
            conn.execute(
                "INSERT INTO grants (grant_id, repository, issue_number, issue_revision,
                    workflow_hash, policy_hash, phase, scope, caps, expires_at, state_epoch,
                    status, created_at, revoked_at)
                 VALUES ('gr_0123456789abcdef', 'example-org/widgets', 123, ?1, ?2, ?3, 'merge',
                    'worktrees/issues/123', 'read,merge', '2999-01-01T00:00:00Z', 1, 'active',
                    '2026-09-06T00:00:00Z', NULL)",
                params!["a".repeat(40), "0".repeat(64), "f".repeat(64)],
            )
            .expect("stored grant insert");
        }
        // The current binary upgrades the v4 database; m0005 is additive.
        let state = State::open(&path, Retention::default()).expect("upgrade open");
        let grants = state.list_grants().expect("grants");
        assert_eq!(grants.len(), 1);
        let grant = &grants[0];
        assert_eq!(grant.grant_id, "gr_0123456789abcdef");
        assert_eq!(grant.repository, "example-org/widgets");
        assert_eq!(grant.issue_number, 123);
        assert_eq!(grant.issue_revision, "a".repeat(40));
        assert_eq!(grant.workflow_hash, "0".repeat(64));
        assert_eq!(grant.policy_hash, "f".repeat(64));
        assert_eq!(grant.status, "active");
        assert_eq!(grant.state_epoch, 1);
        assert_eq!(state.current_epoch().expect("epoch"), 1);
        assert_eq!(SCHEMA_VERSION, 12);
        {
            let conn = state.lock("test: m0005..m0012 bookkeeping").expect("lock");
            for migration_id in [
                M0005_ID, M0006_ID, M0007_ID, M0008_ID, M0009_ID, M0010_ID, M0011_ID, M0012_ID,
            ] {
                let recorded: i64 = conn
                    .query_row(
                        "SELECT COUNT(*) FROM schema_migrations WHERE migration_id = ?1",
                        params![migration_id],
                        |row| row.get(0),
                    )
                    .expect("bookkeeping");
                assert_eq!(recorded, 1, "{migration_id} recorded in schema_migrations");
            }
            let version: i64 = conn
                .query_row("PRAGMA user_version", [], |row| row.get(0))
                .expect("user_version");
            assert_eq!(version, SCHEMA_VERSION);
        }
    }

    #[test]
    fn queue_advance_dependencies_parse_and_unselected_requirements_are_never_met() {
        let path = temp_db("queue-advance-dependencies.db");
        let state = State::open(&path, Retention::default()).expect("open");
        // The declared edges come from the committed bound-input document: a
        // bare reference resolves against the submission's repository and a
        // foreign-repository requirement is reported as outside this queue.
        let request = object(vec![
            ("schema", string("hf-queue-preview/v1")),
            ("repository", string("example-org/widgets")),
            (
                "selected",
                Val::Arr(vec![
                    object(vec![
                        ("id", string("example-org/widgets#5")),
                        ("revision", string(&"a".repeat(40))),
                        ("requires", Val::Arr(vec![])),
                    ]),
                    object(vec![
                        ("id", string("example-org/widgets#6")),
                        ("revision", string(&"a".repeat(40))),
                        (
                            "requires",
                            Val::Arr(vec![
                                string("#5"),
                                string("other-org/elsewhere#9"),
                                string("example-org/widgets#5"),
                            ]),
                        ),
                    ]),
                ]),
            ),
        ]);
        let parsed = bound_selected_dependencies(&canonical_text(&request), "example-org/widgets");
        assert_eq!(
            parsed,
            vec![(5, vec![]), (6, vec![5, 5])],
            "cross-repository requirements cannot be settled by this queue and are dropped"
        );
        assert_eq!(
            bound_selected_dependencies("not json", "example-org/widgets"),
            Vec::new(),
            "an unreadable bound document never invents an edge"
        );
        let item = |number: i64, status: &str, instance_id: Option<&str>| QueueSubmissionItemRow {
            submission_id: "qs_0123456789abcdef".to_string(),
            ordinal: number - 5,
            work_item: format!("wi_{number:016}"),
            issue_number: number,
            issue_revision: "a".repeat(40),
            status: status.to_string(),
            reason: None,
            message: None,
            instance_id: instance_id.map(str::to_string),
            grant_id: String::new(),
        };
        let conn = state
            .lock("test: queue-advance dependencies")
            .expect("lock");
        // A requirement outside the selected set is never met...
        assert!(
            !dependency_met_locked(&conn, &[item(5, "waiting", None)], 9).expect("read"),
            "an unselected requirement can never be settled by this submission"
        );
        // ...and neither is a selected requirement with no run, or a run
        // without a verified delivery.
        assert!(
            !dependency_met_locked(&conn, &[item(5, "waiting", None)], 5).expect("read"),
            "a waiting item is not a delivered one"
        );
        assert!(
            !dependency_met_locked(
                &conn,
                &[item(5, "admitted", Some("run-0000000000000000"))],
                5
            )
            .expect("read"),
            "a missing run is not a delivery"
        );
    }

    #[test]
    fn lane_replacement_record_lifecycle_is_cas_fenced_and_durable() {
        let path = temp_db("replacement-lifecycle.db");
        let at = "2026-09-06T00:00:00Z";
        let state = State::open(&path, Retention::default()).expect("open");
        let row = state
            .request_lane_replacement(
                "lane-7",
                1,
                "sess-0001",
                "proc-0001",
                "implementer",
                "worktrees/issues/73",
                "host rotation window",
                None,
                at,
            )
            .expect("request");
        assert_eq!(row.phase, "requested");
        assert_eq!(row.outcome, "pending");
        assert_eq!(row.successor_generation, 2);
        assert_eq!(row.replacement_id, replacement_id_for("lane-7", 1));

        // A second record for the same lane generation is refused (no two
        // successor owners).
        let duplicate = state
            .request_lane_replacement(
                "lane-7",
                1,
                "sess-0002",
                "proc-0002",
                "implementer",
                "worktrees/issues/73",
                "second request",
                None,
                at,
            )
            .expect_err("duplicate refused");
        assert_eq!(duplicate.code, replacement_code::EXISTS);

        // CAS fences: stale generation and invalid order cannot advance.
        let stale = state
            .advance_lane_replacement(&row.replacement_id, "requested", 9, at)
            .expect_err("stale generation refused");
        assert_eq!(stale.code, replacement_code::STALE);
        let wrong_order = state
            .advance_lane_replacement(&row.replacement_id, "checkpointed", 1, at)
            .expect_err("invalid order refused");
        assert_eq!(wrong_order.code, replacement_code::ORDER);
        let moved = state
            .advance_lane_replacement(&row.replacement_id, "requested", 1, at)
            .expect("advance to quiescing");
        assert_eq!(moved.phase, "quiescing");
        // A replayed expectation (same phase again) cannot advance state.
        let replayed = state
            .advance_lane_replacement(&row.replacement_id, "requested", 1, at)
            .expect_err("replayed expectation refused");
        assert_eq!(replayed.code, replacement_code::ORDER);
        assert_eq!(
            state
                .lane_replacement_by_id(&row.replacement_id)
                .expect("read")
                .expect("row")
                .phase,
            "quiescing"
        );

        // PAUSED (held) refuses advancement; the state survives reopen.
        let held = state
            .hold_lane_replacement(&row.replacement_id, "operator hold", at)
            .expect("hold");
        assert_eq!(held.outcome, "held");
        let held_advance = state
            .advance_lane_replacement(&row.replacement_id, "quiescing", 1, at)
            .expect_err("held refuses advancement");
        assert_eq!(held_advance.code, replacement_code::HELD);
        assert!(
            held_advance.message.contains("operator hold"),
            "{}",
            held_advance.message
        );

        // Cancellation escapes the hold, preserves the original lane, and
        // invalidates the pending replacement permanently.
        let cancelled = state
            .cancel_lane_replacement(&row.replacement_id, "cancelled by operator", at)
            .expect("cancel");
        assert_eq!(cancelled.outcome, "cancelled");
        assert_eq!(cancelled.phase, "quiescing", "cancel leaves the phase");
        assert_eq!(
            cancelled.lane_id, "lane-7",
            "the original lane is preserved"
        );
        assert_eq!(cancelled.source_session, "sess-0001");
        let invalidated = state
            .advance_lane_replacement(&row.replacement_id, "quiescing", 1, at)
            .expect_err("cancelled record cannot advance");
        assert_eq!(invalidated.code, replacement_code::INVALIDATED);
        let re_cancel = state
            .cancel_lane_replacement(&row.replacement_id, "", at)
            .expect_err("already cancelled");
        assert_eq!(re_cancel.code, replacement_code::INVALIDATED);

        // Retirement passed: cancellation is too late (second lane).
        let second = state
            .request_lane_replacement(
                "lane-8",
                1,
                "sess-0001",
                "proc-0001",
                "orchestrator",
                "worktrees/issues/74",
                "second lane replacement",
                None,
                at,
            )
            .expect("request lane-8");
        for expected in ["requested", "quiescing", "checkpointed"] {
            state
                .advance_lane_replacement(&second.replacement_id, expected, 1, at)
                .expect("phase chain");
        }
        let too_late = state
            .cancel_lane_replacement(&second.replacement_id, "", at)
            .expect_err("cancellation after retirement refused");
        assert_eq!(too_late.code, replacement_code::RETIRED);
        let row2 = state
            .lane_replacement_by_id(&second.replacement_id)
            .expect("read")
            .expect("row");
        assert_eq!(row2.phase, "retired");
        assert_eq!(
            row2.outcome, "pending",
            "refused cancellation changed nothing"
        );

        // History: one row per accepted change, in order.
        let events = state
            .lane_replacement_events(&row.replacement_id)
            .expect("history");
        let to_phases: Vec<&str> = events.iter().map(|event| event.to_phase.as_str()).collect();
        assert_eq!(
            to_phases,
            vec!["requested", "quiescing", "quiescing", "quiescing"]
        );
        let to_outcomes: Vec<&str> = events
            .iter()
            .map(|event| event.to_outcome.as_str())
            .collect();
        assert_eq!(to_outcomes, vec!["pending", "pending", "held", "cancelled"]);
        drop(state);

        // Restart: record, outcome, history and next-allowed persist exactly.
        let state = State::open(&path, Retention::default()).expect("reopen");
        let row = state
            .lane_replacement_by_id(&row.replacement_id)
            .expect("read")
            .expect("row");
        assert_eq!(row.outcome, "cancelled", "outcome durable across restart");
        assert_eq!(row.phase, "quiescing");
        assert!(
            matches!(
                lane_replacement_val(&row).get("next_allowed"),
                Some(Val::Null)
            ),
            "a cancelled record has no allowed transition"
        );
        assert_eq!(
            state
                .lane_replacement_events(&row.replacement_id)
                .expect("history")
                .len(),
            4,
            "history durable across restart"
        );
    }
    /// A valid synthetic checkpoint observation for a lane-7 implementer
    /// record on `worktrees/issues/74`. Every required field is explicitly
    /// present — the contract refuses missing evidence instead of omitting
    /// it (issue #74).
    fn sample_checkpoint_observation() -> Val {
        object(vec![
            ("role", string("implementer")),
            ("task", string("issue-74 checkpoint capture")),
            ("worktree", string("worktrees/issues/74")),
            ("branch", string("issue-74-checkpoint")),
            ("head", string(&"a".repeat(40))),
            ("base", string(&"b".repeat(40))),
            (
                "dirty",
                object(vec![
                    ("count", integer(3)),
                    ("digest", string(&"c".repeat(64))),
                ]),
            ),
            (
                "untracked",
                object(vec![
                    ("count", integer(2)),
                    ("digest", string(&"d".repeat(64))),
                ]),
            ),
            (
                "report",
                object(vec![
                    ("round", integer(2)),
                    ("reviewed_sha", string(&"e".repeat(40))),
                ]),
            ),
            (
                "gates",
                Val::Arr(vec![
                    object(vec![
                        ("name", string("focused")),
                        ("status", string("pending")),
                    ]),
                    object(vec![("name", string("full")), ("status", string("passed"))]),
                ]),
            ),
            (
                "children",
                Val::Arr(vec![object(vec![
                    ("command", string("cargo test --locked")),
                    ("state", string("exited")),
                ])]),
            ),
            (
                "execution",
                object(vec![("active", bool_(false)), ("ack", null())]),
            ),
        ])
    }

    /// Request + advance one replacement to the quiescing boundary.
    fn quiescing_replacement(state: &State, lane: &str, at: &str) -> LaneReplacementRow {
        let row = state
            .request_lane_replacement(
                lane,
                1,
                "sess-0001",
                "proc-0001",
                "implementer",
                "worktrees/issues/74",
                "checkpoint capture",
                None,
                at,
            )
            .expect("request");
        state
            .advance_lane_replacement(&row.replacement_id, "requested", 1, at)
            .expect("advance to quiescing")
    }

    fn edit_checkpoint_observation(mut observation: Val, key: &str, value: Option<Val>) -> Val {
        if let Val::Obj(map) = &mut observation {
            match value {
                Some(value) => {
                    map.insert(key.to_string(), value);
                }
                None => {
                    map.remove(key);
                }
            }
        }
        observation
    }

    fn edit_checkpoint_observation_nested(
        observation: Val,
        outer: &str,
        key: &str,
        value: Option<Val>,
    ) -> Val {
        let mut observation = observation;
        if let Val::Obj(map) = &mut observation
            && let Some(Val::Obj(inner)) = map.get_mut(outer)
        {
            match value {
                Some(value) => {
                    inner.insert(key.to_string(), value);
                }
                None => {
                    inner.remove(key);
                }
            }
        }
        observation
    }

    #[test]
    fn lane_checkpoint_migration_preserves_replacement_rows() {
        // Issue #74: the m0006 upgrade is purely additive. A database
        // written at schema v5 (m0001..m0005) with a stored replacement
        // record and its history upgrades in place; the record, its event
        // history and the next allowed transition are exactly what they
        // were, and the new checkpoint table starts empty.
        let path = temp_db("checkpoint-upgrade.db");
        {
            let mut conn = Connection::open(&path).expect("open raw");
            run_initial_migration(&mut conn).expect("m0001");
            run_m0002(&mut conn).expect("m0002");
            run_m0003(&mut conn).expect("m0003");
            run_m0004(&mut conn).expect("m0004");
            run_m0005(&mut conn).expect("m0005");
            let version: i64 = conn
                .query_row("PRAGMA user_version", [], |row| row.get(0))
                .expect("user_version");
            assert_eq!(version, 5, "raw fixture lands at schema v5");
            let replacement_id = replacement_id_for("lane-7", 1);
            conn.execute(
                "INSERT INTO lane_replacements (replacement_id, lane_id, generation,
                    successor_generation, phase, outcome, outcome_reason, source_session,
                    source_process, role, worktree, reason, created_at, updated_at)
                 VALUES (?1, 'lane-7', 1, 2, 'quiescing', 'pending', '', 'sess-0001',
                    'proc-0001', 'implementer', 'worktrees/issues/74', 'host rotation window',
                    '2026-09-12T00:00:00Z', '2026-09-12T00:00:00Z')",
                params![replacement_id],
            )
            .expect("stored replacement insert");
            conn.execute(
                "INSERT INTO lane_replacement_events (seq, replacement_id, from_phase, to_phase,
                    from_outcome, to_outcome, reason, at)
                 VALUES (1, ?1, NULL, 'requested', NULL, 'pending', 'host rotation window',
                    '2026-09-12T00:00:00Z')",
                params![replacement_id],
            )
            .expect("stored event insert");
            conn.execute(
                "INSERT INTO lane_replacement_events (seq, replacement_id, from_phase, to_phase,
                    from_outcome, to_outcome, reason, at)
                 VALUES (2, ?1, 'requested', 'quiescing', 'pending', 'pending', '',
                    '2026-09-12T00:00:00Z')",
                params![replacement_id],
            )
            .expect("stored event insert");
        }
        let state = State::open(&path, Retention::default()).expect("upgrade open");
        let row = state
            .lane_replacement_by_id(&replacement_id_for("lane-7", 1))
            .expect("read")
            .expect("the stored replacement survives the upgrade");
        assert_eq!(row.phase, "quiescing");
        assert_eq!(row.outcome, "pending");
        assert_eq!(row.successor_generation, 2);
        let events = state
            .lane_replacement_events(&row.replacement_id)
            .expect("history");
        assert_eq!(events.len(), 2, "the stored history is preserved");
        assert_eq!(
            state
                .lane_checkpoint_by_replacement(&row.replacement_id)
                .expect("checkpoint read"),
            None,
            "the new checkpoint table starts empty"
        );
        // The preserved next transition still works after the upgrade.
        let advanced = state
            .advance_lane_replacement(&row.replacement_id, "quiescing", 1, "2026-09-12T01:00:00Z")
            .expect("advance after upgrade");
        assert_eq!(advanced.phase, "checkpointed");
        assert_eq!(
            state
                .lane_successor_by_replacement(&row.replacement_id)
                .expect("successor read"),
            None,
            "the new successor table starts empty"
        );
        {
            let conn = state
                .lock("test: m0006/m0007/m0008/m0009 bookkeeping")
                .expect("lock");
            for migration_id in [M0006_ID, M0007_ID, M0008_ID, M0009_ID] {
                let recorded: i64 = conn
                    .query_row(
                        "SELECT COUNT(*) FROM schema_migrations WHERE migration_id = ?1",
                        params![migration_id],
                        |row| row.get(0),
                    )
                    .expect("bookkeeping");
                assert_eq!(recorded, 1, "{migration_id} recorded in schema_migrations");
            }
            let version: i64 = conn
                .query_row("PRAGMA user_version", [], |row| row.get(0))
                .expect("user_version");
            assert_eq!(version, SCHEMA_VERSION);
        }
    }

    #[test]
    fn lane_successor_migration_preserves_checkpoint_rows() {
        // Issue #76: the m0007 upgrade is purely additive. A database
        // written at schema v6 (m0001..m0006) with a stored replacement
        // record, its history and a committed checkpoint upgrades in place;
        // every stored row and the next allowed transition are exactly what
        // they were, and the new successor table starts empty.
        let path = temp_db("successor-upgrade.db");
        let replacement_id = replacement_id_for("lane-7", 1);
        {
            let mut conn = Connection::open(&path).expect("open raw");
            run_initial_migration(&mut conn).expect("m0001");
            run_m0002(&mut conn).expect("m0002");
            run_m0003(&mut conn).expect("m0003");
            run_m0004(&mut conn).expect("m0004");
            run_m0005(&mut conn).expect("m0005");
            run_m0006(&mut conn).expect("m0006");
            let version: i64 = conn
                .query_row("PRAGMA user_version", [], |row| row.get(0))
                .expect("user_version");
            assert_eq!(version, 6, "raw fixture lands at schema v6");
            conn.execute(
                "INSERT INTO lane_replacements (replacement_id, lane_id, generation,
                    successor_generation, phase, outcome, outcome_reason, source_session,
                    source_process, role, worktree, reason, created_at, updated_at)
                 VALUES (?1, 'lane-7', 1, 2, 'retired', 'pending', '', 'sess-0001',
                    'proc-0001', 'implementer', 'worktrees/issues/76', 'host rotation window',
                    '2026-09-12T00:00:00Z', '2026-09-12T00:00:00Z')",
                params![replacement_id],
            )
            .expect("stored replacement insert");
            conn.execute(
                "INSERT INTO lane_replacements (replacement_id, lane_id, generation,
                    successor_generation, phase, outcome, outcome_reason, source_session,
                    source_process, role, worktree, reason, created_at, updated_at)
                 VALUES (?1, 'lane-8', 1, 2, 'checkpointed', 'pending', '', 'sess-0002',
                    'proc-0002', 'implementer', 'worktrees/issues/76', 'stored worker lane',
                    '2026-09-12T00:00:00Z', '2026-09-12T00:00:00Z')",
                params![replacement_id_for("lane-8", 1)],
            )
            .expect("stored worker insert");
            conn.execute(
                "INSERT INTO lane_replacement_events (seq, replacement_id, from_phase, to_phase,
                    from_outcome, to_outcome, reason, at)
                 VALUES (1, ?1, NULL, 'requested', NULL, 'pending', 'host rotation window',
                    '2026-09-12T00:00:00Z')",
                params![replacement_id],
            )
            .expect("stored event insert");
            conn.execute(
                "INSERT INTO lane_replacement_events (seq, replacement_id, from_phase, to_phase,
                    from_outcome, to_outcome, reason, at)
                 VALUES (2, ?1, 'requested', 'retired', 'pending', 'pending', 'stored',
                    '2026-09-12T00:00:00Z')",
                params![replacement_id],
            )
            .expect("stored event insert");
            conn.execute(
                "INSERT INTO lane_checkpoints (checkpoint_id, replacement_id, lane_id, generation,
                    role, observation_digest, reobservation_digest, snapshot, digest,
                    brief_digest, created_at)
                 VALUES ('ck_0123456789abcdef', ?1, 'lane-7', 1, 'implementer',
                    '0', '0', '{}', ?2, '0', '2026-09-12T00:00:00Z')",
                params![replacement_id, "d".repeat(64)],
            )
            .expect("stored checkpoint insert");
        }
        let state = State::open(&path, Retention::default()).expect("upgrade open");
        let row = state
            .lane_replacement_by_id(&replacement_id)
            .expect("read")
            .expect("the stored replacement survives the upgrade");
        assert_eq!(row.phase, "retired");
        assert_eq!(row.outcome, "pending");
        let checkpoint = state
            .lane_checkpoint_by_replacement(&replacement_id)
            .expect("checkpoint read")
            .expect("the stored checkpoint survives the upgrade");
        assert_eq!(checkpoint.checkpoint_id, "ck_0123456789abcdef");
        assert_eq!(
            state
                .lane_replacement_events(&replacement_id)
                .expect("history")
                .len(),
            2,
            "the stored history is preserved"
        );
        assert_eq!(
            state
                .lane_successor_by_replacement(&replacement_id)
                .expect("successor read"),
            None,
            "the new successor table starts empty"
        );
        assert_eq!(
            state
                .lane_replacement_profile(&replacement_id)
                .expect("profile read"),
            None,
            "the new replacement-profile table starts empty"
        );
        // The preserved next transition still works after the upgrade: the
        // stored `retired` boundary admits the successor start.
        let plan = state
            .begin_lane_successor(&object(vec![
                ("replacement_id", string(&replacement_id)),
                (
                    "binding",
                    object(vec![
                        ("generation", integer(1)),
                        ("checkpoint_digest", string(&"d".repeat(64))),
                        ("nonce", string("nonce-upgrade-0001")),
                    ]),
                ),
                (
                    "successor",
                    object(vec![
                        ("session", string("sess-0002")),
                        ("kickoff_receipt", string(&"a".repeat(64))),
                    ]),
                ),
            ]))
            .expect("the stored retirement boundary admits a start after the upgrade");
        assert_eq!(plan.record.phase, "retired");
        {
            let conn = state
                .lock("test: m0007/m0008/m0009 bookkeeping")
                .expect("lock");
            for migration_id in [M0007_ID, M0008_ID, M0009_ID] {
                let recorded: i64 = conn
                    .query_row(
                        "SELECT COUNT(*) FROM schema_migrations WHERE migration_id = ?1",
                        params![migration_id],
                        |row| row.get(0),
                    )
                    .expect("bookkeeping");
                assert_eq!(recorded, 1, "{migration_id} recorded in schema_migrations");
            }
            let version: i64 = conn
                .query_row("PRAGMA user_version", [], |row| row.get(0))
                .expect("user_version");
            assert_eq!(version, SCHEMA_VERSION);
        }
    }

    #[test]
    fn lane_checkpoint_commit_is_atomic_and_binds_outstanding_operations() {
        // Issue #74 AC3/AC5/AC7 at the state layer: one transaction commits
        // the checkpoint row, the record's quiescing -> checkpointed
        // transition and its history; the snapshot binds the lane facts and
        // the daemon-observed outstanding operations (the capture's own
        // claim excluded); the brief is a byte-deterministic derivation of
        // the committed row.
        let path = temp_db("checkpoint-commit.db");
        let at = "2026-09-12T00:00:00Z";
        let state = State::open(&path, Retention::default()).expect("open");
        let record = quiescing_replacement(&state, "lane-7", at);

        // An unrelated in-flight claim is an outstanding operation.
        state
            .journal_intent(
                "mutate.backup.create",
                "backups:demo",
                "ik_outstanding-000001",
                &"b".repeat(16),
                "backup.create",
                None,
                None,
                &sample_request_line("ik_outstanding-000001"),
            )
            .expect("outstanding claim");

        let observation = sample_checkpoint_observation();
        let (checkpoint, updated, brief) = state
            .commit_lane_checkpoint(
                &record.replacement_id,
                1,
                &observation,
                &observation,
                "ik_capture-0000000001",
                at,
            )
            .expect("commit");
        assert_eq!(updated.phase, "checkpointed");
        assert_eq!(updated.outcome, "pending");
        assert_eq!(
            checkpoint.checkpoint_id,
            checkpoint_id_for(&record.replacement_id)
        );
        assert_eq!(
            checkpoint.observation_digest,
            checkpoint.reobservation_digest
        );
        assert_eq!(
            checkpoint.digest,
            sha256_hex(&canonical_bytes(
                &Val::parse_json(&checkpoint.snapshot).expect("snapshot parses")
            )),
            "the digest binds the canonical snapshot bytes"
        );
        assert_eq!(
            checkpoint.brief_digest,
            sha256_hex(brief.as_bytes()),
            "the brief digest binds the generated bytes"
        );
        assert_eq!(
            lane_checkpoint_brief(&checkpoint).expect("regenerate"),
            brief,
            "brief regeneration is byte-for-byte deterministic"
        );
        assert!(brief.len() <= CHECKPOINT_BRIEF_MAX_BYTES);
        assert!(brief.contains(&format!(
            "record: lane_checkpoints/{}",
            checkpoint.checkpoint_id
        )));
        assert!(
            brief.contains("outstanding operations: 1"),
            "the brief counts outstanding operations: {brief}"
        );
        assert!(
            brief.contains("- focused: pending") && brief.contains("- full: passed"),
            "every recorded gate is listed (never silently truncated): {brief}"
        );

        let snapshot = Val::parse_json(&checkpoint.snapshot).expect("snapshot");
        assert_eq!(
            snapshot.get("role").and_then(Val::as_str),
            Some("implementer")
        );
        assert_eq!(
            snapshot.get("task").and_then(Val::as_str),
            Some("issue-74 checkpoint capture")
        );
        let expected_head = "a".repeat(40);
        let expected_base = "b".repeat(40);
        assert_eq!(
            snapshot.get("head").and_then(Val::as_str),
            Some(expected_head.as_str())
        );
        assert_eq!(
            snapshot.get("base").and_then(Val::as_str),
            Some(expected_base.as_str())
        );
        assert_eq!(
            snapshot.get("state_epoch").and_then(Val::as_int),
            Some(1),
            "the snapshot binds the state epoch"
        );
        assert_eq!(snapshot.get("captured_at").and_then(Val::as_str), Some(at));
        assert_eq!(
            snapshot
                .get("gates")
                .and_then(Val::as_array)
                .map(|items| items.len()),
            Some(2)
        );
        assert_eq!(
            snapshot
                .get("children")
                .and_then(Val::as_array)
                .map(|items| items.len()),
            Some(1)
        );
        let outstanding = snapshot
            .get("outstanding_operations")
            .expect("outstanding operations");
        assert_eq!(outstanding.get("count").and_then(Val::as_int), Some(1));
        let operations = outstanding
            .get("operations")
            .and_then(Val::as_array)
            .expect("operations");
        assert_eq!(operations.len(), 1);
        assert_eq!(
            operations[0].get("key").and_then(Val::as_str),
            Some("ik_outstanding-000001"),
            "the outstanding claim is recorded (the capture's own key excluded)"
        );

        // One replacement carries at most one checkpoint: a second capture
        // refuses while touching nothing.
        let second = state
            .commit_lane_checkpoint(
                &record.replacement_id,
                1,
                &observation,
                &observation,
                "ik_capture-0000000002",
                at,
            )
            .expect_err("second capture refused");
        assert_eq!(second.code, checkpoint_code::EXISTS);

        // Read-back is the durable authority, and the record's history
        // carries the quiescing -> checkpointed transition.
        assert_eq!(
            state
                .lane_checkpoint_by_replacement(&record.replacement_id)
                .expect("read")
                .expect("row"),
            checkpoint
        );
        let events = state
            .lane_replacement_events(&record.replacement_id)
            .expect("events");
        let last = events.last().expect("last event");
        assert_eq!(last.from_phase.as_deref(), Some("quiescing"));
        assert_eq!(last.to_phase, "checkpointed");
    }

    #[test]
    fn lane_checkpoint_observation_contract_refuses_incomplete_and_changed_views() {
        // Issue #74 AC5: two observations must agree; every required field
        // must be present and valid. Missing evidence is never silently
        // omitted and an inconsistent view refuses the checkpoint.
        let path = temp_db("checkpoint-contract.db");
        let at = "2026-09-12T00:00:00Z";
        let state = State::open(&path, Retention::default()).expect("open");
        let record = quiescing_replacement(&state, "lane-7", at);
        let observation = sample_checkpoint_observation();

        let cases: Vec<(&str, &str, Val, Val)> = vec![
            (
                "changed view",
                checkpoint_code::CHANGED,
                observation.clone(),
                edit_checkpoint_observation(
                    observation.clone(),
                    "head",
                    Some(string(&"f".repeat(40))),
                ),
            ),
            (
                "missing dirty digest",
                checkpoint_code::INCOMPLETE,
                edit_checkpoint_observation_nested(observation.clone(), "dirty", "digest", None),
                edit_checkpoint_observation_nested(observation.clone(), "dirty", "digest", None),
            ),
            (
                "missing report block",
                checkpoint_code::INCOMPLETE,
                edit_checkpoint_observation(observation.clone(), "report", None),
                edit_checkpoint_observation(observation.clone(), "report", None),
            ),
            (
                "missing gate status",
                checkpoint_code::INCOMPLETE,
                edit_checkpoint_observation(
                    observation.clone(),
                    "gates",
                    Some(Val::Arr(vec![object(vec![("name", string("focused"))])])),
                ),
                edit_checkpoint_observation(
                    observation.clone(),
                    "gates",
                    Some(Val::Arr(vec![object(vec![("name", string("focused"))])])),
                ),
            ),
            (
                "unknown field",
                checkpoint_code::INCOMPLETE,
                edit_checkpoint_observation(
                    observation.clone(),
                    "transcript",
                    Some(string("raw transcript is never accepted")),
                ),
                edit_checkpoint_observation(
                    observation.clone(),
                    "transcript",
                    Some(string("raw transcript is never accepted")),
                ),
            ),
            (
                "role does not bind the record",
                checkpoint_code::INCOMPLETE,
                edit_checkpoint_observation(observation.clone(), "role", Some(string("reviewer"))),
                edit_checkpoint_observation(observation.clone(), "role", Some(string("reviewer"))),
            ),
            (
                "worktree does not bind the record",
                checkpoint_code::INCOMPLETE,
                edit_checkpoint_observation(
                    observation.clone(),
                    "worktree",
                    Some(string("worktrees/issues/999")),
                ),
                edit_checkpoint_observation(
                    observation.clone(),
                    "worktree",
                    Some(string("worktrees/issues/999")),
                ),
            ),
            (
                "invalid head identity",
                checkpoint_code::INCOMPLETE,
                edit_checkpoint_observation(
                    observation.clone(),
                    "head",
                    Some(string("not-a-commit")),
                ),
                edit_checkpoint_observation(
                    observation.clone(),
                    "head",
                    Some(string("not-a-commit")),
                ),
            ),
        ];
        for (index, (label, expected, obs, reobs)) in cases.into_iter().enumerate() {
            let err = state
                .commit_lane_checkpoint(
                    &record.replacement_id,
                    1,
                    &obs,
                    &reobs,
                    &format!("ik_contract-{index:08}"),
                    at,
                )
                .expect_err(label);
            assert_eq!(err.code, expected, "{label}: {}", err.message);
        }
        // No refusal left partial state: no checkpoint, record untouched.
        assert_eq!(
            state
                .lane_checkpoint_by_replacement(&record.replacement_id)
                .expect("read"),
            None
        );
        let untouched = state
            .lane_replacement_by_id(&record.replacement_id)
            .expect("read")
            .expect("row");
        assert_eq!(untouched.phase, "quiescing");
        assert_eq!(untouched.outcome, "pending");

        // The valid observation still commits afterwards.
        state
            .commit_lane_checkpoint(
                &record.replacement_id,
                1,
                &observation,
                &observation,
                "ik_contract-valid-0001",
                at,
            )
            .expect("valid capture");
    }

    #[test]
    fn lane_checkpoint_acknowledgment_and_child_observation_gate_active_execution() {
        // Issue #74 AC1/AC2: active external harness execution requires a
        // supported quiescence acknowledgment AND a process/child
        // observation; active or ambiguous side-effecting children HOLD
        // completion (nothing is signalled or killed to obtain a snapshot).
        let path = temp_db("checkpoint-ack.db");
        let at = "2026-09-12T00:00:00Z";
        let state = State::open(&path, Retention::default()).expect("open");
        let record = quiescing_replacement(&state, "lane-7", at);
        let base = sample_checkpoint_observation();

        let active_no_ack = edit_checkpoint_observation(
            base.clone(),
            "execution",
            Some(object(vec![("active", bool_(true)), ("ack", null())])),
        );
        let unsupported_ack = edit_checkpoint_observation(
            base.clone(),
            "execution",
            Some(object(vec![
                ("active", bool_(true)),
                (
                    "ack",
                    object(vec![
                        ("kind", string("pane-text")),
                        ("session", string("sess-0001")),
                        ("at", string(at)),
                    ]),
                ),
            ])),
        );
        let ack_while_inactive = edit_checkpoint_observation(
            base.clone(),
            "execution",
            Some(object(vec![
                ("active", bool_(false)),
                (
                    "ack",
                    object(vec![
                        ("kind", string("session-quiesced")),
                        ("session", string("sess-0001")),
                        ("at", string(at)),
                    ]),
                ),
            ])),
        );
        let active_child = edit_checkpoint_observation(
            base.clone(),
            "children",
            Some(Val::Arr(vec![object(vec![
                ("command", string("git push origin issue-74-checkpoint")),
                ("state", string("active")),
            ])])),
        );
        let ambiguous_child = edit_checkpoint_observation(
            base.clone(),
            "children",
            Some(Val::Arr(vec![object(vec![
                ("command", string("cargo build --release")),
                ("state", string("ambiguous")),
            ])])),
        );

        for (index, (label, expected, obs)) in [
            (
                "active execution without acknowledgment",
                checkpoint_code::ACK,
                active_no_ack,
            ),
            (
                "unsupported acknowledgment kind",
                checkpoint_code::ACK,
                unsupported_ack,
            ),
            (
                "acknowledgment while execution is inactive",
                checkpoint_code::ACK,
                ack_while_inactive,
            ),
            (
                "active side-effecting child",
                checkpoint_code::HELD,
                active_child,
            ),
            (
                "ambiguous side-effecting child",
                checkpoint_code::HELD,
                ambiguous_child,
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let err = state
                .commit_lane_checkpoint(
                    &record.replacement_id,
                    1,
                    &obs,
                    &obs,
                    &format!("ik_gate-{index:08}"),
                    at,
                )
                .expect_err(label);
            assert_eq!(err.code, expected, "{label}: {}", err.message);
        }
        assert_eq!(
            state
                .lane_checkpoint_by_replacement(&record.replacement_id)
                .expect("read"),
            None,
            "held/refused captures commit nothing"
        );

        // A supported acknowledgment with an observed (exited) child commits.
        let supported = edit_checkpoint_observation(
            base,
            "execution",
            Some(object(vec![
                ("active", bool_(true)),
                (
                    "ack",
                    object(vec![
                        ("kind", string("session-quiesced")),
                        ("session", string("sess-0001")),
                        ("at", string(at)),
                    ]),
                ),
            ])),
        );
        let (checkpoint, _, _) = state
            .commit_lane_checkpoint(
                &record.replacement_id,
                1,
                &supported,
                &supported,
                "ik_gate-valid-0000001",
                at,
            )
            .expect("supported acknowledgment commits");
        let snapshot = Val::parse_json(&checkpoint.snapshot).expect("snapshot");
        assert_eq!(
            snapshot
                .get("execution")
                .and_then(|value| value.get("active"))
                .and_then(Val::as_bool),
            Some(true)
        );
    }

    #[test]
    fn lane_checkpoint_oversize_required_data_holds_typed() {
        // Issue #74 AC6: the generated brief enforces a byte bound; oversize
        // REQUIRED data (here: the maximal recorded child list plus maximal
        // task text) yields a typed hold — required data is never truncated.
        let path = temp_db("checkpoint-oversize.db");
        let at = "2026-09-12T00:00:00Z";
        let state = State::open(&path, Retention::default()).expect("open");
        let record = quiescing_replacement(&state, "lane-7", at);
        let base = sample_checkpoint_observation();

        // Fit within every per-field bound but exceed the brief byte bound.
        let long_children: Vec<Val> = (0..CHECKPOINT_CHILDREN_MAX)
            .map(|_| {
                object(vec![
                    ("command", string(&"x".repeat(160))),
                    ("state", string("exited")),
                ])
            })
            .collect();
        let oversize = edit_checkpoint_observation(
            edit_checkpoint_observation(base.clone(), "task", Some(string(&"t".repeat(200)))),
            "children",
            Some(Val::Arr(long_children)),
        );
        let err = state
            .commit_lane_checkpoint(
                &record.replacement_id,
                1,
                &oversize,
                &oversize,
                "ik_oversize-00000001",
                at,
            )
            .expect_err("oversize holds");
        assert_eq!(err.code, checkpoint_code::OVERSIZE, "{}", err.message);
        assert_eq!(
            state
                .lane_checkpoint_by_replacement(&record.replacement_id)
                .expect("read"),
            None
        );

        // A compliant observation still commits (the hold is not durable).
        state
            .commit_lane_checkpoint(
                &record.replacement_id,
                1,
                &base,
                &base,
                "ik_oversize-00000002",
                at,
            )
            .expect("reduced capture commits");
    }

    #[test]
    fn lane_replacement_requests_are_fenced_inside_the_quiescing_window() {
        // Issue #74 AC1: quiescing fences new daemon-mediated actions for
        // the source generation — no second replacement slot for a lane
        // whose handoff is inside the quiescing window. The fence lifts
        // when the handoff resolves or is cancelled.
        let path = temp_db("checkpoint-fence.db");
        let at = "2026-09-12T00:00:00Z";
        let state = State::open(&path, Retention::default()).expect("open");
        let record = quiescing_replacement(&state, "lane-7", at);

        let fenced = state
            .request_lane_replacement(
                "lane-7",
                2,
                "sess-0002",
                "proc-0002",
                "implementer",
                "worktrees/issues/74",
                "second generation while mid-handoff",
                None,
                at,
            )
            .expect_err("new generation fenced");
        assert_eq!(fenced.code, replacement_code::FENCED, "{}", fenced.message);
        assert!(
            fenced.message.contains(&record.replacement_id),
            "the fence names the holding record: {}",
            fenced.message
        );
        // The same lane generation keeps its own (more specific) refusal.
        let duplicate = state
            .request_lane_replacement(
                "lane-7",
                1,
                "sess-0002",
                "proc-0002",
                "implementer",
                "worktrees/issues/74",
                "duplicate",
                None,
                at,
            )
            .expect_err("duplicate refused");
        assert_eq!(duplicate.code, replacement_code::EXISTS);
        // A different lane is not fenced.
        state
            .request_lane_replacement(
                "lane-8",
                1,
                "sess-0002",
                "proc-0002",
                "implementer",
                "worktrees/issues/74",
                "different lane",
                None,
                at,
            )
            .expect("other lanes are unaffected");

        // The window stays up while the record is checkpointed (still
        // inside the handoff)...
        let observation = sample_checkpoint_observation();
        state
            .commit_lane_checkpoint(
                &record.replacement_id,
                1,
                &observation,
                &observation,
                "ik_fence-0000000001",
                at,
            )
            .expect("capture");
        let still_fenced = state
            .request_lane_replacement(
                "lane-7",
                2,
                "sess-0002",
                "proc-0002",
                "implementer",
                "worktrees/issues/74",
                "still mid-handoff",
                None,
                at,
            )
            .expect_err("checkpointed is still inside the window");
        assert_eq!(still_fenced.code, replacement_code::FENCED);

        // ...and lifts when the handoff is cancelled.
        state
            .cancel_lane_replacement(&record.replacement_id, "operator abort", at)
            .expect("cancel");
        state
            .request_lane_replacement(
                "lane-7",
                2,
                "sess-0002",
                "proc-0002",
                "implementer",
                "worktrees/issues/74",
                "successor request after cancellation",
                None,
                at,
            )
            .expect("the fence lifted");
    }

    #[test]
    fn lane_checkpoint_references_bind_existing_orchestrator_lanes() {
        // Issue #74 AC4: an orchestrator checkpoint references EXISTING
        // worker/reviewer identities and pending completion events without
        // altering those lanes; bogus or role-mismatched references refuse.
        let path = temp_db("checkpoint-orchestrator.db");
        let at = "2026-09-12T00:00:00Z";
        let state = State::open(&path, Retention::default()).expect("open");
        let orchestrator = state
            .request_lane_replacement(
                "lane-orch",
                1,
                "sess-0001",
                "proc-0001",
                "orchestrator",
                "worktrees/issues/74",
                "orchestrator handoff",
                None,
                at,
            )
            .expect("orchestrator request");
        state
            .advance_lane_replacement(&orchestrator.replacement_id, "requested", 1, at)
            .expect("advance");
        let worker = quiescing_replacement(&state, "lane-8", at);
        let reviewer = state
            .request_lane_replacement(
                "lane-9",
                1,
                "sess-0001",
                "proc-0001",
                "reviewer",
                "worktrees/issues/74",
                "reviewer lane",
                None,
                at,
            )
            .expect("reviewer request");

        let worker_before = state
            .lane_replacement_by_id(&worker.replacement_id)
            .expect("read")
            .expect("row");
        let worker_events_before = state
            .lane_replacement_events(&worker.replacement_id)
            .expect("history");
        let reviewer_before = state
            .lane_replacement_by_id(&reviewer.replacement_id)
            .expect("read")
            .expect("row");

        let mut observation = sample_checkpoint_observation();
        if let Val::Obj(map) = &mut observation {
            map.insert("role".to_string(), string("orchestrator"));
            map.insert(
                "orchestration".to_string(),
                object(vec![
                    ("workers", Val::Arr(vec![string(&worker.replacement_id)])),
                    (
                        "reviewers",
                        Val::Arr(vec![string(&reviewer.replacement_id)]),
                    ),
                    (
                        "pending_events",
                        Val::Arr(vec![string("worker-finished:lane-8")]),
                    ),
                ]),
            );
        }

        let (checkpoint, _, _) = state
            .commit_lane_checkpoint(
                &orchestrator.replacement_id,
                1,
                &observation,
                &observation,
                "ik_orch-0000000001",
                at,
            )
            .expect("orchestrator capture");
        let snapshot = Val::parse_json(&checkpoint.snapshot).expect("snapshot");
        let orchestration = snapshot.get("orchestration").expect("orchestration");
        assert_eq!(
            orchestration
                .get("workers")
                .and_then(Val::as_array)
                .map(|items| items.len()),
            Some(1)
        );
        assert_eq!(
            orchestration
                .get("reviewers")
                .and_then(Val::as_array)
                .map(|items| items.len()),
            Some(1)
        );
        assert_eq!(
            orchestration
                .get("pending_events")
                .and_then(Val::as_array)
                .map(|items| items.len()),
            Some(1)
        );

        // Referencing lanes never alters them: rows and history identical.
        assert_eq!(
            state
                .lane_replacement_by_id(&worker.replacement_id)
                .expect("read")
                .expect("row"),
            worker_before
        );
        assert_eq!(
            state
                .lane_replacement_events(&worker.replacement_id)
                .expect("history"),
            worker_events_before
        );
        assert_eq!(
            state
                .lane_replacement_by_id(&reviewer.replacement_id)
                .expect("read")
                .expect("row"),
            reviewer_before
        );

        // A second orchestrator lane for the refusal cases.
        let second = state
            .request_lane_replacement(
                "lane-orch-2",
                1,
                "sess-0001",
                "proc-0001",
                "orchestrator",
                "worktrees/issues/74",
                "second orchestrator",
                None,
                at,
            )
            .expect("second orchestrator");
        state
            .advance_lane_replacement(&second.replacement_id, "requested", 1, at)
            .expect("advance");

        let with_orchestration = |orchestration: Val| -> Val {
            let mut observation = sample_checkpoint_observation();
            if let Val::Obj(map) = &mut observation {
                map.insert("role".to_string(), string("orchestrator"));
                map.insert("orchestration".to_string(), orchestration);
            }
            observation
        };
        let cases: Vec<(&str, Val)> = vec![
            (
                "worker reference does not exist",
                with_orchestration(object(vec![
                    (
                        "workers",
                        Val::Arr(vec![string(&replacement_id_for("lane-404", 1))]),
                    ),
                    ("reviewers", Val::Arr(vec![])),
                    ("pending_events", Val::Arr(vec![])),
                ])),
            ),
            (
                "reviewer reference names an implementer record",
                with_orchestration(object(vec![
                    ("workers", Val::Arr(vec![])),
                    ("reviewers", Val::Arr(vec![string(&worker.replacement_id)])),
                    ("pending_events", Val::Arr(vec![])),
                ])),
            ),
            (
                "orchestrator checkpoint without references",
                edit_checkpoint_observation(
                    edit_checkpoint_observation(
                        sample_checkpoint_observation(),
                        "role",
                        Some(string("orchestrator")),
                    ),
                    "orchestration",
                    None,
                ),
            ),
        ];
        for (index, (label, observation)) in cases.into_iter().enumerate() {
            let err = state
                .commit_lane_checkpoint(
                    &second.replacement_id,
                    1,
                    &observation,
                    &observation,
                    &format!("ik_orch-refs-{index:04}"),
                    at,
                )
                .expect_err(label);
            assert_eq!(
                err.code,
                checkpoint_code::REFERENCES,
                "{label}: {}",
                err.message
            );
        }
        assert_eq!(
            state
                .lane_checkpoint_by_replacement(&second.replacement_id)
                .expect("read"),
            None
        );

        // A non-orchestrator (implementer) checkpoint carrying orchestration
        // references refuses: references belong to orchestrator lanes only.
        let plain = quiescing_replacement(&state, "lane-10", at);
        let with_references = edit_checkpoint_observation(
            sample_checkpoint_observation(),
            "orchestration",
            Some(object(vec![
                ("workers", Val::Arr(vec![])),
                ("reviewers", Val::Arr(vec![])),
                ("pending_events", Val::Arr(vec![])),
            ])),
        );
        let err = state
            .commit_lane_checkpoint(
                &plain.replacement_id,
                1,
                &with_references,
                &with_references,
                "ik_orch-refs-9001",
                at,
            )
            .expect_err("non-orchestrator references refuse");
        assert_eq!(err.code, checkpoint_code::REFERENCES, "{}", err.message);
        assert_eq!(
            state
                .lane_checkpoint_by_replacement(&plain.replacement_id)
                .expect("read"),
            None
        );
    }

    /// Request + advance + capture one replacement to the `checkpointed`
    /// boundary: the precondition of every retirement test.
    fn checkpointed_replacement(
        state: &State,
        lane: &str,
        at: &str,
        key: &str,
    ) -> (LaneReplacementRow, LaneCheckpointRow) {
        let record = quiescing_replacement(state, lane, at);
        let observation = sample_checkpoint_observation();
        let (checkpoint, updated, _) = state
            .commit_lane_checkpoint(
                &record.replacement_id,
                1,
                &observation,
                &observation,
                key,
                at,
            )
            .expect("checkpoint");
        assert_eq!(updated.phase, "checkpointed");
        (updated, checkpoint)
    }

    fn retirement_binding(
        generation: i64,
        session: &str,
        process: &str,
        checkpoint_digest: &str,
    ) -> Val {
        object(vec![
            ("generation", integer(generation)),
            ("session", string(session)),
            ("process", string(process)),
            ("checkpoint_digest", string(checkpoint_digest)),
        ])
    }

    fn retirement_recheck(
        session: &str,
        process: Option<&str>,
        children: Vec<(&str, &str)>,
        active: bool,
    ) -> Val {
        object(vec![
            ("observed_at", string("2026-09-12T00:00:00Z")),
            ("session", string(session)),
            ("process", process.map(string).unwrap_or_else(null)),
            (
                "children",
                Val::Arr(
                    children
                        .into_iter()
                        .map(|(command, state)| {
                            object(vec![("command", string(command)), ("state", string(state))])
                        })
                        .collect(),
                ),
            ),
            ("active", bool_(active)),
        ])
    }

    fn retirement_params(replacement_id: &str, binding: Val, recheck: Val) -> Val {
        object(vec![
            ("replacement_id", string(replacement_id)),
            ("binding", binding),
            ("recheck", recheck),
            (
                "harness",
                object(vec![("key", string("lane-a")), ("kind", string("pi"))]),
            ),
        ])
    }

    /// One synthetic reviewed target-profile plan (issue #77): the same
    /// canonical document the daemon validates at its boundary.
    fn sample_profile_binding() -> crate::config::ProfileBinding {
        let mut binding = crate::config::ProfileBinding {
            key: "lane-orch-1".to_string(),
            kind: "pi".to_string(),
            provider: "example-provider".to_string(),
            model: "example-model".to_string(),
            fallbacks: vec!["example-fallback-provider/example-fallback-model".to_string()],
            configured_limits: vec![("context_tokens".to_string(), "131072".to_string())],
            introspection: true,
            secrets: vec![(
                "EXAMPLE_PROVIDER_KEY".to_string(),
                crate::config::PROFILE_SECRET_UNSET.to_string(),
            )],
            revision: String::new(),
        };
        binding.revision = binding.revision_of();
        binding
    }

    #[test]
    fn lane_replacement_profile_plan_is_fenced_at_the_start() {
        // Issue #77 at the state layer: the reviewed plan is durable on the
        // replacement record and the start is fenced on it — a changed
        // revision requires a newly reviewed plan, a missing/unexpected/
        // different binding refuses before any effect.
        let path = temp_db("profile-fence.db");
        let at = "2026-09-12T00:00:00Z";
        let state = State::open(&path, Retention::default()).expect("open");
        let plan = sample_profile_binding();

        // An unbound record refuses a start that tries to introduce a plan.
        let (unbound, _) = checkpointed_replacement(&state, "lane-8", at, "ik_cap-7701");
        state
            .commit_lane_retirement(
                &unbound.replacement_id,
                1,
                &state
                    .lane_checkpoint_by_replacement(&unbound.replacement_id)
                    .expect("checkpoint")
                    .expect("row")
                    .digest,
                "retired for the profile fence test",
                at,
            )
            .expect("retire");
        let err = state
            .begin_lane_successor(&object(vec![
                ("replacement_id", string(&unbound.replacement_id)),
                ("profile", plan.to_doc()),
                (
                    "binding",
                    object(vec![
                        ("generation", integer(1)),
                        ("checkpoint_digest", string(&"d".repeat(64))),
                        ("nonce", string("nonce-0001")),
                    ]),
                ),
                (
                    "successor",
                    object(vec![
                        ("session", string("sess-0002")),
                        ("kickoff_receipt", string(&"a".repeat(64))),
                    ]),
                ),
            ]))
            .expect_err("an unbound record cannot introduce a plan");
        assert_eq!(err.code, crate::config::CODE_PROFILE_BINDING);

        // A bound record: request under the reviewed revision.
        let text = plan.to_canonical_text();
        let record = state
            .request_lane_replacement(
                "lane-9",
                1,
                "sess-0001",
                "proc-0001",
                "implementer",
                "worktrees/issues/74",
                "profile-bound rotation",
                Some((text.as_str(), plan.revision.as_str())),
                at,
            )
            .expect("request");
        let stored = state
            .lane_replacement_profile(&record.replacement_id)
            .expect("read")
            .expect("the plan is durable on the record");
        assert_eq!(stored.revision, plan.revision);
        assert_eq!(stored.profile, text);
        state
            .advance_lane_replacement(&record.replacement_id, "requested", 1, at)
            .expect("advance");
        let observation = sample_checkpoint_observation();
        let (checkpoint, updated, _) = state
            .commit_lane_checkpoint(
                &record.replacement_id,
                1,
                &observation,
                &observation,
                "ik_cap-7702",
                at,
            )
            .expect("checkpoint");
        assert_eq!(updated.phase, "checkpointed");
        state
            .commit_lane_retirement(
                &record.replacement_id,
                1,
                &checkpoint.digest,
                "retired for the profile fence test",
                at,
            )
            .expect("retire");

        let start = |profile: Option<Val>| -> Result<crate::state::LaneSuccessorPlan, StateError> {
            let mut params = vec![
                ("replacement_id", string(&record.replacement_id)),
                (
                    "binding",
                    object(vec![
                        ("generation", integer(1)),
                        ("checkpoint_digest", string(&checkpoint.digest)),
                        ("nonce", string("nonce-0001")),
                    ]),
                ),
                (
                    "successor",
                    object(vec![
                        ("session", string("sess-0002")),
                        ("kickoff_receipt", string(&"a".repeat(64))),
                    ]),
                ),
            ];
            if let Some(profile) = profile {
                params.push(("profile", profile));
            }
            state.begin_lane_successor(&object(params))
        };

        // The identical plan passes.
        start(Some(plan.to_doc())).expect("the reviewed plan admits the start");

        // A changed configuration revision (the reviewed plan was edited)
        // requires a newly reviewed plan.
        let mut edited = plan.clone();
        edited.provider = "example-provider-2".to_string();
        edited.revision = edited.revision_of();
        let err = start(Some(edited.to_doc())).expect_err("changed revision");
        assert_eq!(
            err.code,
            crate::config::CODE_PROFILE_REVISION,
            "{}",
            err.message
        );

        // The same revision with different material is a binding mismatch.
        let mut mixed = plan.to_doc();
        if let Val::Obj(map) = &mut mixed {
            map.insert("revision".to_string(), string(&plan.revision));
            map.insert("provider".to_string(), string("example-provider-2"));
        }
        let err = start(Some(mixed)).expect_err("material mismatch");
        assert_eq!(
            err.code,
            crate::config::CODE_PROFILE_BINDING,
            "{}",
            err.message
        );

        // A missing plan on a bound record refuses too.
        let err = start(None).expect_err("missing plan");
        assert_eq!(
            err.code,
            crate::config::CODE_PROFILE_BINDING,
            "{}",
            err.message
        );

        // Nothing above changed the record: it is still retired/pending.
        let row = state
            .lane_replacement_by_id(&record.replacement_id)
            .expect("read")
            .expect("row");
        assert_eq!(row.phase, "retired");
        assert_eq!(row.outcome, "pending");
    }

    #[test]
    fn lane_retirement_binds_generation_identity_and_checkpoint_digest() {
        // Issue #75 AC1/AC2 at the state layer: the binding (lane generation,
        // source session/process identity, committed checkpoint digest) and
        // the immediate pre-stop quiescence recheck are validated BEFORE any
        // effect; a changed identity or checkpoint refuses, unknown child or
        // process evidence holds, and nothing about the record changes.
        let path = temp_db("retirement-bind.db");
        let at = "2026-09-12T00:00:00Z";
        let state = State::open(&path, Retention::default()).expect("open");
        let (record, checkpoint) = checkpointed_replacement(&state, "lane-8", at, "ik_cap-8001");
        let digest = checkpoint.digest.clone();

        // The exact binding passes and names only the plan's own record.
        let plan = state
            .begin_lane_retirement(&retirement_params(
                &record.replacement_id,
                retirement_binding(1, "sess-0001", "proc-0001", &digest),
                retirement_recheck("sess-0001", Some("proc-0001"), vec![], false),
            ))
            .expect("bound plan");
        assert_eq!(plan.record.replacement_id, record.replacement_id);
        assert_eq!(plan.checkpoint.checkpoint_id, checkpoint.checkpoint_id);
        assert_eq!(plan.recheck_observed_at, at);

        let cases: Vec<(&str, Val, Val, &str)> = vec![
            (
                "changed checkpoint digest",
                retirement_binding(1, "sess-0001", "proc-0001", &"f".repeat(64)),
                retirement_recheck("sess-0001", Some("proc-0001"), vec![], false),
                retirement_code::BINDING,
            ),
            (
                "changed binding session",
                retirement_binding(1, "sess-0009", "proc-0001", &digest),
                retirement_recheck("sess-0009", Some("proc-0001"), vec![], false),
                retirement_code::BINDING,
            ),
            (
                "changed binding process",
                retirement_binding(1, "sess-0001", "proc-0009", &digest),
                retirement_recheck("sess-0001", Some("proc-0009"), vec![], false),
                retirement_code::BINDING,
            ),
            (
                "stale binding generation",
                retirement_binding(2, "sess-0001", "proc-0001", &digest),
                retirement_recheck("sess-0001", Some("proc-0001"), vec![], false),
                retirement_code::BINDING,
            ),
            (
                "recheck observed another session",
                retirement_binding(1, "sess-0001", "proc-0001", &digest),
                retirement_recheck("sess-0002", Some("proc-0001"), vec![], false),
                retirement_code::BINDING,
            ),
            (
                "recheck observed another process",
                retirement_binding(1, "sess-0001", "proc-0001", &digest),
                retirement_recheck("sess-0001", Some("proc-0002"), vec![], false),
                retirement_code::BINDING,
            ),
            (
                "unknown process identity",
                retirement_binding(1, "sess-0001", "proc-0001", &digest),
                retirement_recheck("sess-0001", None, vec![], false),
                retirement_code::HELD,
            ),
            (
                "unknown child activity",
                retirement_binding(1, "sess-0001", "proc-0001", &digest),
                retirement_recheck(
                    "sess-0001",
                    Some("proc-0001"),
                    vec![("cargo test", "active")],
                    false,
                ),
                retirement_code::HELD,
            ),
            (
                "ambiguous child activity",
                retirement_binding(1, "sess-0001", "proc-0001", &digest),
                retirement_recheck(
                    "sess-0001",
                    Some("proc-0001"),
                    vec![("cargo test", "ambiguous")],
                    false,
                ),
                retirement_code::HELD,
            ),
            (
                "execution still active",
                retirement_binding(1, "sess-0001", "proc-0001", &digest),
                retirement_recheck("sess-0001", Some("proc-0001"), vec![], true),
                retirement_code::HELD,
            ),
        ];
        for (what, binding, recheck, code) in cases {
            let err = state
                .begin_lane_retirement(&retirement_params(&record.replacement_id, binding, recheck))
                .expect_err(what);
            assert_eq!(err.code, code, "{what}: {}", err.message);
            let unchanged = state
                .lane_replacement_by_id(&record.replacement_id)
                .expect("read")
                .expect("row");
            assert_eq!(unchanged, record, "{what}: the record is untouched");
        }

        // Closed contracts: an unknown binding/recheck field refuses and an
        // unknown child state holds (never inferred).
        let mut binding = retirement_binding(1, "sess-0001", "proc-0001", &digest);
        if let Val::Obj(map) = &mut binding {
            map.insert("lane_id".to_string(), string("lane-8"));
        }
        let err = state
            .begin_lane_retirement(&retirement_params(
                &record.replacement_id,
                binding,
                retirement_recheck("sess-0001", Some("proc-0001"), vec![], false),
            ))
            .expect_err("unknown binding field");
        assert_eq!(err.code, retirement_code::BINDING, "{}", err.message);
        let err = state
            .begin_lane_retirement(&retirement_params(
                &record.replacement_id,
                retirement_binding(1, "sess-0001", "proc-0001", &digest),
                retirement_recheck(
                    "sess-0001",
                    Some("proc-0001"),
                    vec![("cargo test", "running")],
                    false,
                ),
            ))
            .expect_err("unknown child state");
        assert_eq!(err.code, retirement_code::HELD, "{}", err.message);

        // The paused state refuses before any effect: a held record.
        let (held, _) = checkpointed_replacement(&state, "lane-9", at, "ik_cap-9001");
        state
            .hold_lane_replacement(&held.replacement_id, "operator pause", at)
            .expect("hold");
        let err = state
            .begin_lane_retirement(&retirement_params(
                &held.replacement_id,
                retirement_binding(1, "sess-0001", "proc-0001", &"a".repeat(64)),
                retirement_recheck("sess-0001", Some("proc-0001"), vec![], false),
            ))
            .expect_err("held record refuses");
        assert_eq!(err.code, replacement_code::HELD, "{}", err.message);

        // A record that has not reached the checkpointed boundary refuses.
        let quiescing = quiescing_replacement(&state, "lane-11", at);
        let err = state
            .begin_lane_retirement(&retirement_params(
                &quiescing.replacement_id,
                retirement_binding(1, "sess-0001", "proc-0001", &"a".repeat(64)),
                retirement_recheck("sess-0001", Some("proc-0001"), vec![], false),
            ))
            .expect_err("quiescing record refuses");
        assert_eq!(err.code, replacement_code::ORDER, "{}", err.message);
    }

    #[test]
    fn lane_retirement_commit_is_atomic_and_fenced() {
        // Issue #75 AC1/AC6 at the state layer: the retirement commit is one
        // transaction (record phase + history), fenced on the committed
        // checkpoint digest and the exact phase/generation/outcome; a missed
        // fence changes nothing and is classified typed.
        let path = temp_db("retirement-commit.db");
        let at = "2026-09-12T00:00:00Z";
        let state = State::open(&path, Retention::default()).expect("open");
        let (record, checkpoint) = checkpointed_replacement(&state, "lane-12", at, "ik_cap-1201");
        let reason = "retired after one bounded graceful stop: backend process absent";

        // A wrong checkpoint digest refuses and leaves the record untouched.
        let err = state
            .commit_lane_retirement(&record.replacement_id, 1, &"f".repeat(64), reason, at)
            .expect_err("digest fence");
        assert_eq!(err.code, retirement_code::BINDING, "{}", err.message);
        let unchanged = state
            .lane_replacement_by_id(&record.replacement_id)
            .expect("read")
            .expect("row");
        assert_eq!(unchanged, record);

        // An unbounded evidence summary refuses (never silently truncated).
        let err = state
            .commit_lane_retirement(
                &record.replacement_id,
                1,
                &checkpoint.digest,
                &"x".repeat(RETIREMENT_REASON_MAX + 1),
                at,
            )
            .expect_err("oversize reason");
        assert_eq!(err.code, "state.replacement_invalid", "{}", err.message);

        // The exact fence commits: phase retired + the transition history,
        // atomically.
        let retired = state
            .commit_lane_retirement(&record.replacement_id, 1, &checkpoint.digest, reason, at)
            .expect("commit");
        assert_eq!(retired.phase, "retired");
        assert_eq!(retired.outcome, "pending");
        assert_eq!(retired.generation, 1);
        let events = state
            .lane_replacement_events(&record.replacement_id)
            .expect("events");
        let last = events.last().expect("last event");
        assert_eq!(last.from_phase.as_deref(), Some("checkpointed"));
        assert_eq!(last.to_phase, "retired");
        assert_eq!(last.reason, reason);
        assert_eq!(
            events.len(),
            4,
            "requested (creation) -> quiescing -> checkpointed -> retired is the full history"
        );

        // A second commit cannot re-apply: the phase fence refuses typed.
        let err = state
            .commit_lane_retirement(&record.replacement_id, 1, &checkpoint.digest, reason, at)
            .expect_err("second commit");
        assert_eq!(err.code, replacement_code::ORDER, "{}", err.message);

        // Cancellation after retirement is already refused by the record's
        // own contract (the retirement is terminal for the cancellation
        // window).
        let err = state
            .cancel_lane_replacement(&record.replacement_id, "too late", at)
            .expect_err("cancel after retirement");
        assert_eq!(err.code, replacement_code::RETIRED, "{}", err.message);
    }
}
