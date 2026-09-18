//! Portable lifecycle behavior (issue #9): recurring non-destructive
//! schedule evaluation (single-flight, coalesced, no catch-up replay) and
//! admission for concurrent lane fan-out (global/per-repository/per-harness
//! caps, fresh host-resource proof, monorepo scope overlap).
//!
//! The daemon owns every durable write and all clock reads; this module is
//! pure policy plus the reconcile driver over `state::State`. Wall-clock
//! movement, sleep, and DST transitions all surface as jumps of the `now`
//! argument, so every scenario is unit-testable with explicit Unix seconds
//! (no injectable clock exists by design — see `crate::time`).
//!
//! Schedule semantics (normative, docs/contracts/spec-lifecycle.md):
//!
//! - A schedule doc pins an `anchor` (RFC3339 UTC) and `every_secs`; the
//!   evaluation windows are `anchor + k * every_secs` forever (no drift,
//!   no wall-clock phase chasing).
//! - One evaluation per window, at most. When a tick finds the window in
//!   the past (sleep, reboot, DST/wall-clock jumps), the schedule fires
//!   exactly ONCE and re-anchors its persisted `next_run_at` to the next
//!   boundary strictly after now — missed windows are skipped, never
//!   replayed (no catch-up storm).
//! - The persisted `next_run_at` is the single-flight guard: a second
//!   evaluation in the same tick skips. Paused (`enabled = 0`) schedules
//!   never run; nothing in this module ever enables a schedule.
//! - A refusal (expired, changed policy/issue binding, unparseable doc)
//!   parks the schedule in an explicit terminal paused state with a
//!   journaled reason — no retry storm. Resume is an explicit human RPC.

use std::path::{Path, PathBuf};

use crate::canonical::{canonical_bytes, sha256_hex};
use crate::state::{ScheduleRow, State, StateError};
use crate::time;
use crate::value::{Val, integer, object, string};

/// Freshness bound for host-resource proof (seconds). Older measurements
/// are stale and refuse new fan-out (AC1: stale measurements refuse work).
pub const HOST_PROOF_FRESHNESS_SECS: i64 = 120;

/// Default concurrency caps (bootstrap design commitment; configurable via
/// policy overlay in a later slice — ponytail: defaults keep the AC
/// machine-provable without widening the config contract).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConcurrencyCaps {
    /// Maximum concurrently running lanes across all repositories.
    pub global: usize,
    /// Maximum concurrently running lanes per repository.
    pub per_repository: usize,
    /// Maximum concurrently running lanes per harness key.
    pub per_harness: usize,
}

impl Default for ConcurrencyCaps {
    fn default() -> ConcurrencyCaps {
        ConcurrencyCaps {
            global: 8,
            per_repository: 2,
            per_harness: 2,
        }
    }
}

/// A typed lifecycle refusal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LifecycleError {
    /// Stable dotted refusal code (refusal.admission.*).
    pub code: &'static str,
    /// Human message.
    pub message: String,
}

impl LifecycleError {
    fn new(code: &'static str, message: impl Into<String>) -> LifecycleError {
        LifecycleError {
            code,
            message: message.into(),
        }
    }
}

/// Lifecycle refusal codes (stable, typed; never downgraded by callers).
pub mod code {
    /// A concurrency cap is exceeded (global axis).
    pub const CAP_GLOBAL: &str = "refusal.admission.cap_global";
    /// A concurrency cap is exceeded (per-repository axis).
    pub const CAP_REPOSITORY: &str = "refusal.admission.cap_repository";
    /// A concurrency cap is exceeded (per-harness axis).
    pub const CAP_HARNESS: &str = "refusal.admission.cap_harness";
    /// The declared monorepo scope overlaps a concurrent lane's scope.
    pub const MONOREPO_OVERLAP: &str = "refusal.admission.monorepo_overlap";
    /// Fan-out requires fresh host-resource proof; none was supplied.
    pub const PROOF_MISSING: &str = "refusal.admission.proof_missing";
    /// The supplied host-resource proof is stale (older than the bound).
    pub const PROOF_STALE: &str = "refusal.admission.proof_stale";
    /// The requested fan-out omits an applicable cap axis.
    pub const CAP_MISSING: &str = "refusal.admission.cap_missing";
}

// ---------------------------------------------------------------------------
// Schedule window arithmetic (pure; all times are Unix seconds)
// ---------------------------------------------------------------------------

/// The next evaluation window strictly after `now_unix` for a cadence
/// anchored at `anchor_unix` with `every_secs` spacing, or `None` when the
/// schedule has not started yet (`anchor` itself when it is still ahead).
///
/// Missed windows (sleep/reboot/DST jumps) fall out of the arithmetic: the
/// result is the boundary after `now`, so a late tick fires once and never
/// replays the skipped windows.
pub fn next_window_unix(anchor_unix: i64, every_secs: i64, now_unix: i64) -> Option<i64> {
    if every_secs <= 0 {
        return None;
    }
    if now_unix < anchor_unix {
        return Some(anchor_unix);
    }
    let steps = (now_unix - anchor_unix).div_euclid(every_secs) + 1;
    Some(anchor_unix + steps * every_secs)
}

/// Whether a schedule is due at `now_unix` given its persisted window.
/// A `None` window (fresh create/resume) is always due (one fresh run).
pub fn window_due(next_run_at: Option<i64>, now_unix: i64) -> bool {
    match next_run_at {
        None => true,
        Some(window) => now_unix >= window,
    }
}

// ---------------------------------------------------------------------------
// Schedule evaluation decisions (pure over one row)
// ---------------------------------------------------------------------------

/// What one schedule evaluation decided.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EvalVerdict {
    /// The window fired: one fresh coalesced run; `next` is the persisted
    /// next window (always strictly after the tick that just ran).
    Ran {
        /// Next evaluation window (RFC3339 UTC) to persist.
        next: String,
    },
    /// Not due / paused / future window: nothing happens.
    Idle,
    /// The schedule refused and must park (explicit terminal state).
    Paused {
        /// Stable reason (`expired` | `policy_changed` | `issue_changed` |
        /// `doc_invalid`).
        reason: &'static str,
    },
}

/// Fresh observations an evaluating side may attest (client-attested like
/// apply `observed` params — same trust boundary as #8's observations).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScheduleAttest<'a> {
    /// Attested policy hash (64-hex) at evaluation time.
    pub policy_hash: &'a str,
    /// Attested issue acceptance revision (40-hex) at evaluation time.
    pub issue_revision: &'a str,
}

/// Decide one schedule evaluation from a row and the current Unix time.
/// Pure: no state writes happen here; the caller commits the verdict.
pub fn decide_schedule(
    row: &ScheduleRow,
    now_unix: i64,
    attest: Option<&ScheduleAttest<'_>>,
) -> EvalVerdict {
    if !row.enabled {
        return EvalVerdict::Idle;
    }
    let doc = match parse_doc_val(&row.doc) {
        Some(doc) => doc,
        None => {
            return EvalVerdict::Paused {
                reason: "doc_invalid",
            };
        }
    };
    let get = |key: &str| -> Option<&str> { doc.get(key).and_then(crate::value::Val::as_str) };
    // Expiry: an expired schedule parks itself (explicit terminal state).
    if let Some(expires_at) = get("expires_at")
        && let Some(expires_unix) = time::unix_from_rfc3339(expires_at)
        && now_unix >= expires_unix
    {
        return EvalVerdict::Paused { reason: "expired" };
    }
    // Binding attestation: a changed policy hash or issue revision parks
    // the schedule — it must never keep firing under an unverified policy.
    if let Some(attest) = attest {
        if let Some(policy_hash) = get("policy_hash")
            && attest.policy_hash != policy_hash
        {
            return EvalVerdict::Paused {
                reason: "policy_changed",
            };
        }
        let issue_revision = doc
            .get("issue")
            .and_then(|issue| issue.get("revision"))
            .and_then(crate::value::Val::as_str);
        if let Some(bound) = issue_revision
            && attest.issue_revision != bound
        {
            return EvalVerdict::Paused {
                reason: "issue_changed",
            };
        }
    }
    let window = row.next_run_at.as_deref().and_then(time::unix_from_rfc3339);
    if !window_due(window, now_unix) {
        return EvalVerdict::Idle;
    }
    let anchor = get("anchor").and_then(time::unix_from_rfc3339);
    let every_secs = doc.get("every_secs").and_then(crate::value::Val::as_int);
    let (Some(anchor_unix), Some(every)) = (anchor, every_secs) else {
        return EvalVerdict::Paused {
            reason: "doc_invalid",
        };
    };
    match next_window_unix(anchor_unix, every, now_unix) {
        Some(next) => EvalVerdict::Ran {
            next: time::rfc3339_from_unix(next),
        },
        None => EvalVerdict::Paused {
            reason: "doc_invalid",
        },
    }
}

/// Parse a stored schedule doc into a value (unparseable rows pause).
fn parse_doc_val(text: &str) -> Option<crate::value::Val> {
    crate::value::Val::parse_json(text).ok()
}

// ---------------------------------------------------------------------------
// Reconcile driver (daemon startup + schedules.evaluate)
// ---------------------------------------------------------------------------

/// The outcome of one reconcile pass over every schedule row.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ScheduleSummary {
    /// Schedule ids that ran once in this pass.
    pub ran: Vec<String>,
    /// (schedule_id, reason) pairs parked by this pass.
    pub paused: Vec<(String, String)>,
    /// Schedule ids that were idle (paused or not yet due).
    pub idle: Vec<String>,
    /// Schedules that errored at the state layer (should never happen).
    pub failed: Vec<(String, String)>,
}

impl ScheduleSummary {
    /// Total evaluated rows (ran + paused + idle + failed).
    pub fn total(&self) -> usize {
        self.ran.len() + self.paused.len() + self.idle.len() + self.failed.len()
    }
}

/// Evaluate every enabled schedule exactly once at `now_unix` (the daemon
/// calls this at cold boot and via `schedules.evaluate`). Semantics:
///
/// - Each due schedule fires exactly ONCE and persists its next window
///   atomically with its `schedule.ran` journal record/event — a second
///   pass in the same tick is a no-op (single-flight via the persisted
///   window).
/// - Refused schedules park themselves (enabled = 0) with a journaled
///   reason. Idle schedules are untouched (no journal spam).
pub fn reconcile_schedules(
    state: &State,
    now_unix: i64,
    attest: Option<&ScheduleAttest<'_>>,
) -> Result<ScheduleSummary, StateError> {
    let rows = state.list_schedule_rows()?;
    let mut summary = ScheduleSummary::default();
    for row in rows {
        match decide_schedule(&row, now_unix, attest) {
            EvalVerdict::Ran { next } => {
                match state.complete_schedule_run(
                    &row.schedule_id,
                    Some(&next),
                    &time::rfc3339_now(),
                ) {
                    Ok(_) => summary.ran.push(row.schedule_id),
                    Err(err) => summary
                        .failed
                        .push((row.schedule_id, format!("{}: {}", err.code, err.message))),
                }
            }
            EvalVerdict::Paused { reason } => {
                match state.pause_schedule_with_reason(
                    &row.schedule_id,
                    reason,
                    &time::rfc3339_now(),
                ) {
                    Ok(_) => summary.paused.push((row.schedule_id, reason.to_string())),
                    Err(err) => summary
                        .failed
                        .push((row.schedule_id, format!("{}: {}", err.code, err.message))),
                }
            }
            EvalVerdict::Idle => summary.idle.push(row.schedule_id),
        }
    }
    Ok(summary)
}

/// Evaluate ONE schedule at `now_unix` (the `schedules.evaluate` RPC with a
/// schedule_id filter). Mirrors [`reconcile_schedules`] for a single row.
pub fn reconcile_schedule(
    state: &State,
    schedule_id: &str,
    now_unix: i64,
    attest: Option<&ScheduleAttest<'_>>,
) -> Result<Option<ScheduleSummary>, StateError> {
    let Some(row) = state.schedule_by_id(schedule_id)? else {
        return Ok(None);
    };
    let mut summary = ScheduleSummary::default();
    match decide_schedule(&row, now_unix, attest) {
        EvalVerdict::Ran { next } => {
            state.complete_schedule_run(&row.schedule_id, Some(&next), &time::rfc3339_now())?;
            summary.ran.push(row.schedule_id);
        }
        EvalVerdict::Paused { reason } => {
            state.pause_schedule_with_reason(&row.schedule_id, reason, &time::rfc3339_now())?;
            summary.paused.push((row.schedule_id, reason.to_string()));
        }
        EvalVerdict::Idle => summary.idle.push(row.schedule_id),
    }
    Ok(Some(summary))
}

// ---------------------------------------------------------------------------
// Admission: concurrency caps + fresh host proof + monorepo overlap
// ---------------------------------------------------------------------------

/// A lane footprint: everything admission counts and compares. Scope paths
/// are compared as path components (a lane may never overlap another
/// lane's declared monorepo path inside the same repository).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LaneFootprint {
    /// Repository identity (`owner/name`).
    pub repository: String,
    /// Harness key the lane runs on (the per-harness cap axis).
    pub harness_key: String,
    /// Declared scope/lane path (e.g. `worktrees/issues/123`).
    pub scope: String,
}

/// Whether two declared lane paths overlap as path components (equal, or
/// one is a component-wise prefix of the other). `a/b` overlaps `a/b/c` but
/// not `a/bc` (component boundary respected).
pub fn paths_overlap(a: &str, b: &str) -> bool {
    let a_parts: Vec<&str> = a.split('/').filter(|part| !part.is_empty()).collect();
    let b_parts: Vec<&str> = b.split('/').filter(|part| !part.is_empty()).collect();
    if a_parts.is_empty() || b_parts.is_empty() {
        return false;
    }
    let common = a_parts.len().min(b_parts.len());
    a_parts[..common] == b_parts[..common]
}

/// Host-resource proof: the daemon may refuse fan-out when the caller
/// cannot present a FRESH measurement (unknown or stale measurements refuse
/// new work — AC1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostProof {
    /// Unix seconds when the resource measurement was taken.
    pub measured_at_unix: i64,
}

impl HostProof {
    /// Whether the proof is fresh at `now_unix`.
    pub fn fresh_at(self, now_unix: i64) -> bool {
        now_unix - self.measured_at_unix <= HOST_PROOF_FRESHNESS_SECS
            && self.measured_at_unix <= now_unix
    }
}

/// One host-resource observation (issue #198): the daemon's own measurement
/// at dispatch time, or the typed reason it could not be taken.
///
/// The proof a fan-out presents is a CALLER attestation; the supervisor is a
/// caller too, so when it continues a run it must measure the host itself at
/// DISPATCH time instead of echoing the submit-time attestation back. A host
/// that cannot be observed is `Unmeasurable`: no measurement is ever
/// fabricated for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostMeasurement {
    /// The host was observed at this instant: the free bytes it exposed at
    /// the lane root a fan-out writes into.
    Measured {
        /// Unix seconds of the observation itself.
        measured_at_unix: i64,
        /// Free bytes the host exposed at the lane root.
        available_bytes: u64,
    },
    /// The host could not be observed; an unmeasurable host never renews a
    /// proof (the admission gate keeps refusing the lapsed one).
    Unmeasurable {
        /// Human reason, recorded on the daemon log.
        reason: String,
    },
}

/// The recorded renewal of one run's lapsed host-resource proof (issue
/// #198): the presented (lapsed) proof, the dispatch-time measurement that
/// replaces it, and the observation behind it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostProofRenewal {
    /// The presented proof this renewal supersedes.
    pub superseded: HostProof,
    /// The measurement the run presents from this dispatch on.
    pub replacement: HostProof,
    /// Free bytes the host exposed at the lane root.
    pub available_bytes: u64,
}

/// Whether a run's OWN lapsed host-resource proof renews from a measurement
/// taken at dispatch time (issue #198).
///
/// `Some(renewal)` only when ALL of these hold, so the renewal can never
/// become a blanket authorization:
/// - the run PRESENTED a proof (a missing one is never invented — the
///   gate's own `proof_missing` stands);
/// - that proof has actually lapsed (a fresh one is presented as recorded);
/// - the run is live (`renewable` — the renewal is the run's own act, like
///   its lapsed grant window, issue #184);
/// - the host was MEASURED (`Unmeasurable` never renews: the gate then
///   refuses `refusal.admission.proof_stale` exactly as before).
///
/// The freshness bound itself is untouched: the replacement is a measurement
/// of THIS dispatch, and it goes stale on the same bound as any other proof.
pub fn renew_lapsed_host_proof(
    presented: Option<HostProof>,
    measurement: &HostMeasurement,
    renewable: bool,
    now_unix: i64,
) -> Option<HostProofRenewal> {
    let presented = presented?;
    if presented.fresh_at(now_unix) {
        return None;
    }
    if !renewable {
        return None;
    }
    match measurement {
        HostMeasurement::Measured {
            measured_at_unix,
            available_bytes,
        } => Some(HostProofRenewal {
            superseded: presented,
            replacement: HostProof {
                measured_at_unix: *measured_at_unix,
            },
            available_bytes: *available_bytes,
        }),
        HostMeasurement::Unmeasurable { .. } => None,
    }
}

/// Admission gate for one fan-out request (harness_start/prompt and other
/// spawn-cap steps) before any effect runs.
///
/// Refuses when:
/// - no host-resource proof is supplied (`proof_missing`) or it is stale
///   (`proof_stale`) — unknown/stale measurements never admit fan-out;
/// - an applicable cap axis is omitted by the caller (`cap_missing`);
/// - any applicable concurrency cap is already exhausted (cap_*);
/// - the proposed scope overlaps a concurrent lane's declared scope in the
///   same repository (`monorepo_overlap`).
#[allow(clippy::too_many_arguments)]
pub fn check_fanout_admission(
    proposed: &LaneFootprint,
    running: &[LaneFootprint],
    caps: &ConcurrencyCaps,
    host_proof: Option<HostProof>,
    now_unix: i64,
) -> Result<(), LifecycleError> {
    let proof = match host_proof {
        Some(proof) if proof.fresh_at(now_unix) => proof,
        Some(_) => {
            return Err(LifecycleError::new(
                code::PROOF_STALE,
                "the host-resource proof is stale; re-measure before fan-out",
            ));
        }
        None => {
            return Err(LifecycleError::new(
                code::PROOF_MISSING,
                "fan-out requires a fresh host-resource proof (unknown measurements refuse new work)",
            ));
        }
    };
    let _ = proof;
    if proposed.harness_key.is_empty() {
        return Err(LifecycleError::new(
            code::CAP_MISSING,
            "fan-out requires a harness key (the per-harness cap axis)",
        ));
    }
    if running.len() >= caps.global {
        return Err(LifecycleError::new(
            code::CAP_GLOBAL,
            format!(
                "the global concurrency cap ({}) is reached; refuse fan-out",
                caps.global
            ),
        ));
    }
    let same_repository = running
        .iter()
        .filter(|lane| lane.repository == proposed.repository)
        .count();
    if same_repository >= caps.per_repository {
        return Err(LifecycleError::new(
            code::CAP_REPOSITORY,
            format!(
                "the per-repository concurrency cap ({}) is reached for {}; refuse fan-out",
                caps.per_repository, proposed.repository
            ),
        ));
    }
    let same_harness = running
        .iter()
        .filter(|lane| lane.harness_key == proposed.harness_key)
        .count();
    if same_harness >= caps.per_harness {
        return Err(LifecycleError::new(
            code::CAP_HARNESS,
            format!(
                "the per-harness concurrency cap ({}) is reached for {:?}; refuse fan-out",
                caps.per_harness, proposed.harness_key
            ),
        ));
    }
    // Monorepo overlap: concurrent lanes in one repository may never
    // overlap declared scope paths. The proposed lane is not counted
    // against itself (the caller excludes its own footprint).
    for lane in running {
        if lane.repository == proposed.repository && paths_overlap(&proposed.scope, &lane.scope) {
            return Err(LifecycleError::new(
                code::MONOREPO_OVERLAP,
                format!(
                    "scope {:?} overlaps the concurrent lane scope {:?}; concurrent lanes cannot overlap declared monorepo paths",
                    proposed.scope, lane.scope
                ),
            ));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Filesystem safety: canonical target classification + archive/salvage
// ---------------------------------------------------------------------------

/// One archived file entry (relative path + sha256 + byte size).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArchiveEntry {
    /// Path relative to the archived root (forward-slash joined).
    pub path: String,
    /// sha256 hex of the file bytes.
    pub sha256: String,
    /// File size in bytes.
    pub bytes: u64,
}

/// The result of archiving one tree (issue #9 AC7): every archived file is
/// checksummed, the manifest itself is canonical JSON, and
/// `manifest_sha256` pins the manifest bytes so archived content can be
/// verified byte-for-byte later.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArchiveManifest {
    /// Absolute destination directory holding the archived tree + manifest.
    pub archive_dir: String,
    /// Files archived (sorted by relative path).
    pub entries: Vec<ArchiveEntry>,
    /// Total bytes archived.
    pub total_bytes: u64,
    /// sha256 over the canonical manifest document.
    pub manifest_sha256: String,
}

/// A filesystem-safety refusal/error (issue #9 AC7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArchiveError {
    /// Stable code (`refusal.cleanup.symlink`, `effect.archive.failed`).
    pub code: &'static str,
    /// Human message.
    pub message: String,
}

/// Archive error codes (stable, typed).
pub mod archive_code {
    /// A symlink was found where real content is required; symlinks are
    /// never followed or removed (canonical target classification).
    pub const SYMLINK: &str = "refusal.cleanup.symlink";
    /// The archive operation failed (I/O, path escape).
    pub const FAILED: &str = "effect.archive.failed";
}

/// Copy `src` into a NEW directory `dest` (created here), excluding the
/// git internals (`.git`), refusing every symlink, and checksumming every
/// file. `dest` must not exist yet. Returns the manifest; on any symlink or
/// I/O failure the partially written destination is removed and an error
/// returned (no half-archives survive).
pub fn archive_tree(src: &Path, dest: &Path) -> Result<ArchiveManifest, ArchiveError> {
    if dest.exists() {
        return Err(ArchiveError {
            code: archive_code::FAILED,
            message: format!("archive destination {} already exists", dest.display()),
        });
    }
    std::fs::create_dir_all(dest).map_err(|err| ArchiveError {
        code: archive_code::FAILED,
        message: format!("create {}: {err}", dest.display()),
    })?;
    let mut entries = Vec::new();
    let mut total_bytes: u64 = 0;
    let walk_result = archive_walk(src, dest, &mut entries, &mut total_bytes);
    if let Err(err) = walk_result {
        let _ = std::fs::remove_dir_all(dest);
        return Err(err);
    }
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    let entries_val: Vec<Val> = entries
        .iter()
        .map(|entry| {
            object(vec![
                ("path", string(&entry.path)),
                ("sha256", string(&entry.sha256)),
                ("bytes", integer(entry.bytes as i64)),
            ])
        })
        .collect();
    let manifest_doc = object(vec![
        ("schema", string("hf-archive/v1")),
        ("source_entries", integer(entries.len() as i64)),
        ("total_bytes", integer(total_bytes as i64)),
        ("entries", Val::Arr(entries_val)),
    ]);
    let manifest_bytes = canonical_bytes(&manifest_doc);
    let manifest_sha256 = sha256_hex(&manifest_bytes);
    let manifest_path = dest.join("manifest.json");
    std::fs::write(&manifest_path, &manifest_bytes).map_err(|err| ArchiveError {
        code: archive_code::FAILED,
        message: format!("write manifest: {err}"),
    })?;
    Ok(ArchiveManifest {
        archive_dir: dest.to_string_lossy().into_owned(),
        entries,
        total_bytes,
        manifest_sha256,
    })
}

/// Recursive walk copying files (git internals excluded, symlinks refused).
fn archive_walk(
    src: &Path,
    dest: &Path,
    entries: &mut Vec<ArchiveEntry>,
    total_bytes: &mut u64,
) -> Result<(), ArchiveError> {
    let mut stack: Vec<(PathBuf, String)> = vec![(src.to_path_buf(), String::new())];
    while let Some((dir, rel)) = stack.pop() {
        let read = std::fs::read_dir(&dir).map_err(|err| ArchiveError {
            code: archive_code::FAILED,
            message: format!("read {}: {err}", dir.display()),
        })?;
        let mut children: Vec<(PathBuf, String)> = Vec::new();
        for entry in read {
            let entry = entry.map_err(|err| ArchiveError {
                code: archive_code::FAILED,
                message: format!("read dir entry: {err}"),
            })?;
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            if name == ".git" {
                continue;
            }
            let meta = std::fs::symlink_metadata(&path).map_err(|err| ArchiveError {
                code: archive_code::FAILED,
                message: format!("metadata {}: {err}", path.display()),
            })?;
            if meta.file_type().is_symlink() {
                return Err(ArchiveError {
                    code: archive_code::SYMLINK,
                    message: format!(
                        "archive refuses symlink {} (canonical target classification)",
                        path.display()
                    ),
                });
            }
            let child_rel = if rel.is_empty() {
                name.clone()
            } else {
                format!("{rel}/{name}")
            };
            if meta.is_dir() {
                children.push((path, child_rel));
            } else {
                let dest_file = dest.join(&child_rel);
                if let Some(parent) = dest_file.parent() {
                    std::fs::create_dir_all(parent).map_err(|err| ArchiveError {
                        code: archive_code::FAILED,
                        message: format!("create {}: {err}", parent.display()),
                    })?;
                }
                let bytes = std::fs::read(&path).map_err(|err| ArchiveError {
                    code: archive_code::FAILED,
                    message: format!("read {}: {err}", path.display()),
                })?;
                std::fs::write(&dest_file, &bytes).map_err(|err| ArchiveError {
                    code: archive_code::FAILED,
                    message: format!("write {}: {err}", dest_file.display()),
                })?;
                entries.push(ArchiveEntry {
                    sha256: sha256_hex(&bytes),
                    path: child_rel.clone(),
                    bytes: bytes.len() as u64,
                });
                *total_bytes += bytes.len() as u64;
            }
        }
        // Re-push directories in deterministic (reversed-name) order so the
        // walk order is stable; entries are sorted afterwards anyway.
        children.sort_by(|a, b| b.0.cmp(&a.0));
        stack.extend(children);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{Retention, State};
    use crate::value::{integer, object, string};

    fn anchor_secs() -> i64 {
        time::unix_from_rfc3339("2026-09-06T00:00:00Z").expect("anchor")
    }

    /// Build a schedule row in a temp state with a doc and persisted window.
    fn seeded_row(
        db: &std::path::Path,
        schedule_id: &str,
        enabled: bool,
        next_run_at: Option<&str>,
        doc: crate::value::Val,
    ) -> ScheduleRow {
        let state = State::open(db, Retention::default()).expect("open");
        let _ = state.delete_schedule(schedule_id);
        state.upsert_schedule(&doc).expect("upsert");
        state
            .set_schedule_enabled(schedule_id, enabled, "2026-09-06T00:00:00Z")
            .expect("set enabled");
        if let Some(window) = next_run_at {
            state
                .complete_schedule_run(schedule_id, Some(window), "2026-09-06T00:00:00Z")
                .expect("set window");
        }
        state
            .schedule_by_id(schedule_id)
            .expect("row")
            .expect("present")
    }

    fn schedule_doc(schedule_id: &str, expires_at: &str) -> crate::value::Val {
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
            ("caps", crate::value::Val::Arr(vec![string("read")])),
            ("expires_at", string(expires_at)),
            ("anchor", string("2026-09-06T00:00:00Z")),
            ("every_secs", integer(300)),
        ])
    }

    // -----------------------------------------------------------------
    // Window arithmetic
    // -----------------------------------------------------------------

    #[test]
    fn windows_align_to_anchor_and_never_replay_missed_ticks() {
        let anchor = anchor_secs();
        // Exactly on the first window: fires, next = anchor + 300.
        assert_eq!(next_window_unix(anchor, 300, anchor), Some(anchor + 300));
        // Mid-window: next boundary is the one after now.
        assert_eq!(
            next_window_unix(anchor, 300, anchor + 10),
            Some(anchor + 300)
        );
        // Sleep: many windows passed (06:00), next = boundary after now.
        let late = anchor + 6 * 3600 + 42;
        assert_eq!(
            next_window_unix(anchor, 300, late),
            Some(anchor + ((late - anchor).div_euclid(300) + 1) * 300)
        );
        // Before the anchor (schedule starts later): anchor itself.
        assert_eq!(next_window_unix(anchor, 300, anchor - 60), Some(anchor));
        // Degenerate cadence refuses.
        assert_eq!(next_window_unix(anchor, 0, anchor + 1), None);
    }

    #[test]
    fn window_due_treats_null_as_immediately_due() {
        assert!(window_due(None, 0));
        assert!(!window_due(Some(1_000), 999));
        assert!(window_due(Some(1_000), 1_000));
    }

    #[test]
    fn clock_jump_backwards_never_double_fires() {
        let anchor = anchor_secs();
        // A run at t0 persisted next = anchor + 300.
        let next = next_window_unix(anchor, 300, anchor).expect("next");
        // Wall clock jumps BACK (DST fall-back / NTP): now < persisted next.
        assert!(!window_due(Some(next), next - 1800));
        // ...and once it catches back up it fires exactly once more.
        assert!(window_due(Some(next), next));
    }

    // -----------------------------------------------------------------
    // Evaluation decisions
    // -----------------------------------------------------------------

    fn eval_at(row: &ScheduleRow, now_unix: i64) -> EvalVerdict {
        decide_schedule(row, now_unix, None)
    }

    #[test]
    fn due_schedule_verdict_advances_one_window() {
        let db = std::env::temp_dir().join(format!(
            "hf-lc-eval-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let anchor = anchor_secs();
        let row = seeded_row(
            &db,
            "sd_0123456789abcdef",
            true,
            Some("2026-09-06T00:00:00Z"),
            schedule_doc("sd_0123456789abcdef", "2999-01-01T00:00:00Z"),
        );
        // 10 minutes into the cadence: exactly one fresh run to anchor+300.
        assert_eq!(
            eval_at(&row, anchor + 600),
            EvalVerdict::Ran {
                next: time::rfc3339_from_unix(anchor + 900)
            }
        );
        let _ = std::fs::remove_file(&db);
    }

    #[test]
    fn overlap_and_missed_ticks_coalesce_into_one_fresh_evaluation() {
        let db = std::env::temp_dir().join(format!(
            "hf-lc-coalesce-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let anchor = anchor_secs();
        let id = "sd_0123456789abcdef";
        let row = seeded_row(
            &db,
            id,
            true,
            Some("2026-09-06T00:00:00Z"),
            schedule_doc(id, "2999-01-01T00:00:00Z"),
        );
        // Simulate a host that slept 2 hours: many missed windows.
        let slept = anchor + 2 * 3600 + 7;
        // First evaluation fires once (coalesced)...
        let first = eval_at(&row, slept);
        let EvalVerdict::Ran { next } = &first else {
            panic!("expected ran, got {first:?}");
        };
        // ...and the persisted next window makes a second evaluation in the
        // SAME tick (overlapping evaluation requests) a no-op.
        let mut after = row.clone();
        after.next_run_at = Some(next.clone());
        assert_eq!(eval_at(&after, slept), EvalVerdict::Idle);
        // Reboot at a later instant: one more fresh evaluation, never a
        // replay of the skipped backlog.
        let later = slept + 3600 + 13;
        let EvalVerdict::Ran { next: later_next } = eval_at(&after, later) else {
            panic!("expected later run");
        };
        assert!(later_next.as_str() > next.as_str());
        let _ = std::fs::remove_file(&db);
    }

    #[test]
    fn expired_schedule_parks_with_terminal_reason() {
        let db = std::env::temp_dir().join(format!(
            "hf-lc-expired-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let id = "sd_0123456789abcdef";
        let row = seeded_row(
            &db,
            id,
            true,
            None,
            schedule_doc(id, "2026-09-06T00:05:00Z"),
        );
        assert_eq!(
            eval_at(&row, anchor_secs() + 3600),
            EvalVerdict::Paused { reason: "expired" }
        );
        let _ = std::fs::remove_file(&db);
    }

    #[test]
    fn policy_and_issue_changes_park_the_schedule() {
        let db = std::env::temp_dir().join(format!(
            "hf-lc-policy-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let id = "sd_0123456789abcdef";
        let row = seeded_row(
            &db,
            id,
            true,
            None,
            schedule_doc(id, "2999-01-01T00:00:00Z"),
        );
        let other_hash = "e".repeat(64);
        assert_eq!(
            decide_schedule(
                &row,
                anchor_secs(),
                Some(&ScheduleAttest {
                    policy_hash: &other_hash,
                    issue_revision: &"a".repeat(40),
                })
            ),
            EvalVerdict::Paused {
                reason: "policy_changed"
            }
        );
        assert_eq!(
            decide_schedule(
                &row,
                anchor_secs(),
                Some(&ScheduleAttest {
                    policy_hash: &"f".repeat(64),
                    issue_revision: &"b".repeat(40),
                })
            ),
            EvalVerdict::Paused {
                reason: "issue_changed"
            }
        );
        // Matching attestation proceeds.
        assert!(matches!(
            decide_schedule(
                &row,
                anchor_secs(),
                Some(&ScheduleAttest {
                    policy_hash: &"f".repeat(64),
                    issue_revision: &"a".repeat(40),
                })
            ),
            EvalVerdict::Ran { .. }
        ));
        let _ = std::fs::remove_file(&db);
    }

    #[test]
    fn paused_schedule_is_idle_and_reconcile_never_enables() {
        let db = std::env::temp_dir().join(format!(
            "hf-lc-paused-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let id = "sd_0123456789abcdef";
        let row = seeded_row(
            &db,
            id,
            false, // paused
            None,
            schedule_doc(id, "2999-01-01T00:00:00Z"),
        );
        assert_eq!(eval_at(&row, anchor_secs() + 3600), EvalVerdict::Idle);
        // Reconcile over the state keeps it paused and journals nothing.
        let state = State::open(&db, Retention::default()).expect("open");
        let summary = reconcile_schedules(&state, anchor_secs() + 3600, None).expect("reconcile");
        assert_eq!(summary.ran.len(), 0);
        assert_eq!(summary.paused.len(), 0);
        let after = state.schedule_by_id(id).expect("row").expect("present");
        assert!(
            !after.enabled,
            "reconcile must never enable a paused schedule"
        );
        let _ = std::fs::remove_file(&db);
    }

    #[test]
    fn reconcile_fires_due_schedule_once_and_parks_expired() {
        let db = std::env::temp_dir().join(format!(
            "hf-lc-reconcile-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let state = State::open(&db, Retention::default()).expect("open");
        let live_id = "sd_0123456789abcde1";
        let dead_id = "sd_0123456789abcde2";
        state
            .upsert_schedule(&schedule_doc(live_id, "2999-01-01T00:00:00Z"))
            .expect("upsert live");
        state
            .upsert_schedule(&schedule_doc(dead_id, "2026-09-06T00:05:00Z"))
            .expect("upsert dead");
        // A first reconcile fires the live schedule once.
        let first = reconcile_schedules(&state, anchor_secs() + 3600, None).expect("reconcile");
        assert_eq!(first.ran, vec![live_id.to_string()]);
        assert!(
            first
                .paused
                .iter()
                .any(|(id, reason)| id == dead_id && reason == "expired")
        );
        // A second reconcile in the same tick is a no-op (single-flight).
        let second = reconcile_schedules(&state, anchor_secs() + 3600, None).expect("reconcile");
        assert!(second.ran.is_empty());
        assert!(second.idle.contains(&live_id.to_string()));
        let live = state.schedule_by_id(live_id).expect("row").expect("live");
        assert!(live.enabled);
        assert!(live.next_run_at.as_deref().unwrap_or("") > "2026-09-06T01:00:00Z");
        // The dead schedule is parked (terminal state).
        let dead = state.schedule_by_id(dead_id).expect("row").expect("dead");
        assert!(!dead.enabled);
        let _ = std::fs::remove_file(&db);
    }

    // -----------------------------------------------------------------
    // Admission
    // -----------------------------------------------------------------

    fn lane(repository: &str, harness_key: &str, scope: &str) -> LaneFootprint {
        LaneFootprint {
            repository: repository.to_string(),
            harness_key: harness_key.to_string(),
            scope: scope.to_string(),
        }
    }

    #[test]
    fn scope_overlap_is_component_wise() {
        assert!(paths_overlap(
            "worktrees/issues/123",
            "worktrees/issues/123"
        ));
        assert!(paths_overlap(
            "worktrees/issues/123",
            "worktrees/issues/123/extra"
        ));
        assert!(!paths_overlap("worktrees/issues/1", "worktrees/issues/123"));
        assert!(!paths_overlap(
            "worktrees/issues/123",
            "worktrees/issues/456"
        ));
    }

    #[test]
    fn fanout_refuses_without_fresh_proof_and_when_caps_exhausted() {
        let now = anchor_secs();
        let proposed = lane("example-org/widgets", "lane", "worktrees/issues/456");
        // Missing proof refuses.
        assert_eq!(
            check_fanout_admission(&proposed, &[], &ConcurrencyCaps::default(), None, now)
                .unwrap_err()
                .code,
            code::PROOF_MISSING
        );
        // Stale proof refuses.
        assert_eq!(
            check_fanout_admission(
                &proposed,
                &[],
                &ConcurrencyCaps::default(),
                Some(HostProof {
                    measured_at_unix: now - HOST_PROOF_FRESHNESS_SECS - 1,
                }),
                now
            )
            .unwrap_err()
            .code,
            code::PROOF_STALE
        );
        // Global cap reached refuses.
        let caps = ConcurrencyCaps {
            global: 1,
            ..ConcurrencyCaps::default()
        };
        assert_eq!(
            check_fanout_admission(
                &proposed,
                &[lane("example-org/other", "lane", "worktrees/issues/1")],
                &caps,
                Some(HostProof {
                    measured_at_unix: now
                }),
                now
            )
            .unwrap_err()
            .code,
            code::CAP_GLOBAL
        );
        // Per-repository cap reached refuses.
        let caps = ConcurrencyCaps {
            per_repository: 1,
            ..ConcurrencyCaps::default()
        };
        assert_eq!(
            check_fanout_admission(
                &proposed,
                &[lane(
                    "example-org/widgets",
                    "other-harness",
                    "worktrees/issues/1"
                )],
                &caps,
                Some(HostProof {
                    measured_at_unix: now
                }),
                now
            )
            .unwrap_err()
            .code,
            code::CAP_REPOSITORY
        );
        // Per-harness cap reached refuses.
        let caps = ConcurrencyCaps {
            per_harness: 1,
            ..ConcurrencyCaps::default()
        };
        assert_eq!(
            check_fanout_admission(
                &proposed,
                &[lane("example-org/widgets", "lane", "worktrees/issues/1")],
                &caps,
                Some(HostProof {
                    measured_at_unix: now
                }),
                now
            )
            .unwrap_err()
            .code,
            code::CAP_HARNESS
        );
    }

    #[test]
    fn a_lapsed_proof_renews_only_from_a_dispatch_time_measurement_of_a_live_run() {
        let now = anchor_secs();
        let lapsed = HostProof {
            measured_at_unix: now - HOST_PROOF_FRESHNESS_SECS - 1,
        };
        let measured = HostMeasurement::Measured {
            measured_at_unix: now,
            available_bytes: 4096,
        };
        // The lapsed proof of a live run renews from the measurement: the
        // replacement is the MEASUREMENT's own instant, never `now` echoed.
        let renewal = renew_lapsed_host_proof(Some(lapsed), &measured, true, now)
            .expect("a lapsed proof of a live run renews");
        assert_eq!(renewal.superseded, lapsed);
        assert_eq!(
            renewal.replacement,
            HostProof {
                measured_at_unix: now
            }
        );
        assert_eq!(renewal.available_bytes, 4096);
        // The replacement is fresh under the SAME unchanged bound.
        assert!(renewal.replacement.fresh_at(now));
        assert!(
            !renewal
                .replacement
                .fresh_at(now + HOST_PROOF_FRESHNESS_SECS + 1)
        );
        // A FRESH presented proof is never re-measured.
        assert_eq!(
            renew_lapsed_host_proof(
                Some(HostProof {
                    measured_at_unix: now
                }),
                &measured,
                true,
                now
            ),
            None
        );
        // A missing proof is never invented (the gate's own proof_missing stands).
        assert_eq!(renew_lapsed_host_proof(None, &measured, true, now), None);
        // A run that is not live never renews: the renewal is its OWN act.
        assert_eq!(
            renew_lapsed_host_proof(Some(lapsed), &measured, false, now),
            None
        );
        // An UNMEASURABLE host never renews: nothing is fabricated, and the
        // lapsed proof stays the one the gate refuses.
        let unmeasurable = HostMeasurement::Unmeasurable {
            reason: "the host does not expose the lane root".to_string(),
        };
        assert_eq!(
            renew_lapsed_host_proof(Some(lapsed), &unmeasurable, true, now),
            None
        );
        // A measurement from the FUTURE is never a renewal either: the
        // gate's own clock bound still decides.
        let future = HostMeasurement::Measured {
            measured_at_unix: now + HOST_PROOF_FRESHNESS_SECS + 60,
            available_bytes: 4096,
        };
        let renewal = renew_lapsed_host_proof(Some(lapsed), &future, true, now)
            .expect("the presenter passes the measurement through");
        assert!(
            !renewal.replacement.fresh_at(now),
            "a future measurement is presented as measured and refused by the gate"
        );
    }

    #[test]
    fn overlapping_monorepo_scopes_refuse_and_disjoint_scope_passes() {
        let now = anchor_secs();
        let proof = Some(HostProof {
            measured_at_unix: now,
        });
        // Another lane of the same repository already claims issues/123 and
        // its subpaths; a fan-out into that subtree refuses.
        let overlapping = lane("example-org/widgets", "lane", "worktrees/issues/123");
        let err = check_fanout_admission(
            &lane(
                "example-org/widgets",
                "lane",
                "worktrees/issues/123/sub-worktree",
            ),
            std::slice::from_ref(&overlapping),
            &ConcurrencyCaps::default(),
            proof,
            now,
        )
        .unwrap_err();
        assert_eq!(err.code, code::MONOREPO_OVERLAP);
        // A disjoint lane in the same repository passes the overlap check.
        check_fanout_admission(
            &lane("example-org/widgets", "lane", "worktrees/issues/456"),
            &[overlapping],
            &ConcurrencyCaps::default(),
            proof,
            now,
        )
        .expect("disjoint scope admitted");
        // Different repositories never overlap each other's scopes.
        check_fanout_admission(
            &lane("example-org/other", "lane", "worktrees/issues/123"),
            &[lane("example-org/widgets", "lane", "worktrees/issues/123")],
            &ConcurrencyCaps::default(),
            proof,
            now,
        )
        .expect("cross-repository scopes admitted");
    }

    // -----------------------------------------------------------------
    // Archive / salvage (filesystem safety, AC7)
    // -----------------------------------------------------------------

    fn sandbox_dir(name: &str) -> PathBuf {
        let base = std::env::temp_dir().join(format!("hf-lc-archive-{}", std::process::id()));
        let dir = base.join(name);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("sandbox");
        dir
    }

    #[test]
    fn archived_bytes_and_manifest_match_the_source() {
        let dir = sandbox_dir("bytes");
        let src = dir.join("lane");
        std::fs::create_dir_all(src.join("sub")).expect("dirs");
        std::fs::write(src.join("a.txt"), "alpha content\n").expect("a");
        std::fs::write(src.join("sub/b.bin"), [0u8, 1, 2, 250, 251, 252]).expect("b");
        std::fs::create_dir_all(src.join(".git")).expect("git dir");
        std::fs::write(src.join(".git/config"), "git internals never archived").expect("git file");
        let dest = dir.join("archive-out");

        let manifest = archive_tree(&src, &dest).expect("archive");
        // Byte-for-byte: every archived file matches the source and the
        // manifest's own sha256, and the git internals were excluded.
        assert_eq!(manifest.entries.len(), 2);
        assert_eq!(manifest.total_bytes, 14 + 6);
        for entry in &manifest.entries {
            let source_bytes = std::fs::read(src.join(&entry.path)).expect("read source");
            let dest_bytes = std::fs::read(dest.join(&entry.path)).expect("read dest");
            assert_eq!(source_bytes, dest_bytes, "{} bytes match", entry.path);
            assert_eq!(crate::canonical::sha256_hex(&source_bytes), entry.sha256);
        }
        assert!(!dest.join(".git").exists(), "git internals excluded");
        // The manifest file exists and its digest pins the manifest bytes.
        let manifest_bytes = std::fs::read(dest.join("manifest.json")).expect("manifest file");
        assert_eq!(
            crate::canonical::sha256_hex(&manifest_bytes),
            manifest.manifest_sha256
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn archive_refuses_symlinks_and_fails_closed() {
        let dir = sandbox_dir("symlink");
        let src = dir.join("lane");
        std::fs::create_dir_all(&src).expect("src");
        std::fs::write(src.join("real.txt"), "real").expect("real");
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(dir.join("outside.txt"), src.join("link.txt"))
                .expect("symlink");
        }
        let dest = dir.join("archive-out");
        let err = archive_tree(&src, &dest).expect_err("symlink must refuse");
        assert_eq!(err.code, archive_code::SYMLINK);
        // Fail closed: no half-archive survives.
        assert!(!dest.exists(), "partial archive removed on failure");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn archive_tree_refuses_an_existing_destination_without_touching_it() {
        // Deterministic boundary for the destination-exists refusal (issue
        // #99): the daemon names archive destinations with second-granular
        // wall-clock time, so a repeat archive can collide with an existing
        // destination. Pre-creating `dest` exercises the refusal here
        // without any clock dependence.
        let dir = sandbox_dir("dest-exists");
        let src = dir.join("lane");
        std::fs::create_dir_all(&src).expect("src");
        std::fs::write(src.join("real.txt"), "real").expect("real");
        let dest = dir.join("archive-out");
        std::fs::create_dir_all(dest.join("nested")).expect("dest");
        std::fs::write(dest.join("nested/pre-existing.txt"), "untouched").expect("pre-existing");

        let err = archive_tree(&src, &dest).expect_err("existing destination must refuse");
        assert_eq!(err.code, archive_code::FAILED);
        // The pre-existing destination content is untouched: nothing is
        // copied in and no manifest is written over it.
        assert_eq!(
            std::fs::read_to_string(dest.join("nested/pre-existing.txt")).expect("read"),
            "untouched"
        );
        assert!(!dest.join("real.txt").exists());
        assert!(!dest.join("manifest.json").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
