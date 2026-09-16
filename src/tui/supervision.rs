//! Compact supervision status and guarded continuation controls (issue #97).
//!
//! This module surfaces the merged #95/#96 supervision state for exactly ONE
//! selected run — the recorded run classification, the stable reason code,
//! evidence freshness, the last committed check, the next eligible check, the
//! blocked reason and the continuation window — and offers the two guarded
//! continuation controls the brief names: a hold (pause automatic
//! continuation) and an authorized continue (resume).
//!
//! Everything displayed is read from the daemon's OWN typed services: the
//! status projection of `supervision.status`
//! ([`crate::supervision::status_doc`], consumed as data) and the run-control
//! projection of `run.status` ([`crate::run_control::control_doc`]). The
//! controls send the SAME params documents the CLI builds
//! ([`crate::run_control::pause_params`] over `run.pause`,
//! [`crate::run_control::resume_params`] over `run.resume`); there is no UI
//! scheduler, no second state store and no synthesized shell command.
//!
//! Honesty rules (pinned by tests):
//!
//! - a missing, stale or unreadable observation is `unknown`/held and never
//!   reads as `healthy`: [`SupervisionView::class_slot`] only reports a
//!   recorded class when the evidence is fresh, committed and the run is
//!   actually armed;
//! - reads report RECORDED state. The committed class/reason/eligibility of
//!   the last check are displayed as recorded and the read-time observation
//!   is carried separately ([`Observed`]); neither replaces the other;
//! - requested and observed effects are distinct blocks; an unconfirmed
//!   request is `UNKNOWN` and is never replayed (the read-only refresh `r` is
//!   the only follow-up);
//! - a paused/gated run renders as paused/gated and is never advanced here:
//!   the resume binds the digest the pause recorded and is a separate
//!   explicit confirmation.
//!
//! Hard rule taken from the merged code (`operator.rs`: the operator submit
//! path presents no supervision block): this surface NEVER arms, disables or
//! nudges the supervised reconciliation driver. Enabling supervision is the
//! CLI's explicit `--supervise arm` authorization committed with the run's
//! submission; nothing in this module can reach it, and no key sequence
//! enables it by accident.
//!
//! Keyboard safety: every effect needs a distinct request key (`h`/`u`), then
//! `Space` setting the confirmation box, then `Enter` committing it. A bare
//! `Enter`, an escape/back key, a resize or any autorepeat/release event
//! effects nothing; every key handler ignores non-`Press` events, so a held
//! key cannot commit a control the operator did not confirm frame by frame.

use std::path::Path;

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyEventKind};

use crate::client::{self, RpcError};
use crate::run_control;
use crate::supervision;
use crate::value::Val;

use super::operator::{AttemptOutcome, Notice, ScreenLine, Tone};
use super::{Action, age_label, clip};

/// Surface-local notice: no run is selected (the status addresses one run).
pub const CODE_NO_RUN: &str = "supervision.no_run";
/// Surface-local notice: the typed read failed (daemon unavailable/refused).
pub const CODE_READ: &str = "supervision.read";
/// Surface-local notice: the confirmation box is not set.
pub const CODE_CONFIRM: &str = "supervision.confirm";
/// Surface-local notice: the requested control is not available (with reason).
pub const CODE_DISABLED: &str = "supervision.control_unavailable";
/// Surface-local notice: the confirmed digest moved before the commit.
pub const CODE_STALE: &str = "supervision.stale";
/// Surface-local notice: the daemon answered for a different run identity.
pub const CODE_IDENTITY: &str = "supervision.effect";

/// The recorded pause reason the surface submits: bounded, explicit and
/// distinguishable from a CLI invocation in the journal.
pub const PAUSE_REASON: &str = "operator hold from the supervision surface (pause automatic continuation; no arming, no scope change)";

/// The scope statement every compact status carries.
pub const SCOPE_STATEMENT: &str = "scope: run only; no fleet-level and no harness-level effect";

/// The statement of the resume confirmation: what it does and does not do.
pub const RESUME_STATEMENT: &str = "resume lifts exactly ONE recorded pause of this run with the digest the pause \
recorded; it does not arm supervision, does not disable it, does not widen the run's scope, does not clear any other \
run's pause and does not clear a fleet-level hold";

/// The closed run-classification vocabulary of the merged classifier
/// ([`crate::supervision::CLASSES`]); an unrecognized recorded class maps to
/// [`RunClass::Unknown`], which never reads as progress.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunClass {
    /// Live work or recent recorded progress.
    Healthy,
    /// A known wait for workers.
    WaitingWorkers,
    /// The worker exhausted its collection deadline.
    WorkerTimeout,
    /// A known wait for CI evidence.
    WaitingCi,
    /// A known wait for a human approval.
    WaitingApproval,
    /// The latest recorded dispatch of the next step was refused for capacity.
    BlockedCapacity,
    /// The recorded progress window is genuinely exhausted.
    ContinuationEligible,
    /// A durable pause (requested or reached) holds the run.
    Paused,
    /// Completed with recorded passing evidence.
    Completed,
    /// A recorded terminal hold, invalidated facts or a failed review.
    NeedsAttention,
    /// Unknown, unobserved or unreadable state — never progress.
    Unknown,
}

impl RunClass {
    /// The merged classifier's class code for this arm.
    pub fn code(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::WaitingWorkers => "waiting-workers",
            Self::WorkerTimeout => "worker-timeout",
            Self::WaitingCi => "waiting-CI",
            Self::WaitingApproval => "waiting-approval",
            Self::BlockedCapacity => "blocked-capacity",
            Self::ContinuationEligible => "continuation-eligible",
            Self::Paused => "paused",
            Self::Completed => "completed",
            Self::NeedsAttention => "needs-attention",
            Self::Unknown => "unknown",
        }
    }

    /// Map a recorded class code; an unrecognized code is `None` (rendered as
    /// unknown, never as the closest known class).
    pub fn from_code(code: &str) -> Option<Self> {
        [
            Self::Healthy,
            Self::WaitingWorkers,
            Self::WorkerTimeout,
            Self::WaitingCi,
            Self::WaitingApproval,
            Self::BlockedCapacity,
            Self::ContinuationEligible,
            Self::Paused,
            Self::Completed,
            Self::NeedsAttention,
            Self::Unknown,
        ]
        .into_iter()
        .find(|arm| arm.code() == code)
    }

    /// The display tone of this class (colour-free: the renderer maps it).
    pub fn tone(self) -> Tone {
        match self {
            Self::Healthy | Self::Completed => Tone::Normal,
            Self::Paused | Self::Unknown => Tone::Muted,
            Self::ContinuationEligible | Self::WaitingApproval => Tone::Warn,
            Self::WaitingWorkers | Self::WaitingCi => Tone::Muted,
            Self::BlockedCapacity | Self::NeedsAttention | Self::WorkerTimeout => Tone::Alert,
        }
    }
}

/// Freshness of the recorded last check against the recorded freshness bound.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Evidence {
    /// The last check is within the recorded bound.
    Fresh {
        /// Age of the last committed check in seconds.
        age_secs: u64,
    },
    /// The last check is older than the recorded bound.
    Stale {
        /// Age of the last committed check in seconds.
        age_secs: u64,
    },
    /// No committed check was recorded yet.
    Missing,
    /// The source reported nothing readable (or an unrecognized state).
    Unreadable,
}

impl Evidence {
    /// Map the recorded freshness block (`state`, `age_secs`).
    pub fn from_recorded(state: Option<&str>, age_secs: Option<u64>) -> Self {
        match (state, age_secs) {
            (Some("fresh"), Some(age_secs)) => Self::Fresh { age_secs },
            (Some("stale"), Some(age_secs)) => Self::Stale { age_secs },
            (Some("missing"), _) => Self::Missing,
            _ => Self::Unreadable,
        }
    }

    /// Whether this evidence may be read as its recorded class.
    pub fn trusted(self) -> bool {
        matches!(self, Self::Fresh { .. })
    }

    /// `fresh 12s` / `stale 15m` / `missing` / `unreadable`.
    pub fn label(self) -> String {
        match self {
            Self::Fresh { age_secs } => format!("fresh {}", age_label(age_secs)),
            Self::Stale { age_secs } => format!("stale {}", age_label(age_secs)),
            Self::Missing => "missing".to_string(),
            Self::Unreadable => "unreadable".to_string(),
        }
    }
}

/// The recorded last committed check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LastCheck {
    /// Recorded instant.
    pub at: String,
    /// Recorded class code of that check.
    pub class: String,
    /// Recorded reason code of that check.
    pub reason: String,
    /// Recorded trigger (`boot`, `timer`, ...).
    pub trigger: String,
}

/// The recorded next eligible check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NextCheck {
    /// Recorded instant.
    pub at: String,
    /// Seconds until due, when the recorded instant is readable.
    pub due_in_secs: Option<u64>,
    /// Recorded reason code.
    pub reason: String,
}

/// The durable continuation window.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Continuation {
    /// Whether the recorded window is open.
    pub open: bool,
    /// Recorded instant the window opened at.
    pub since: String,
    /// Recorded number of continuation reports.
    pub reports: i64,
}

/// The read-time observation of the merged classifier (never a replacement
/// for the recorded class: both are displayed).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Observed {
    /// Observed class code.
    pub class: String,
    /// Observed reason code.
    pub reason: String,
    /// Observed eligibility (a report — no effect).
    pub eligible: bool,
    /// Observed detail (for example the next step the class addresses).
    pub detail: String,
}

impl Observed {
    /// The observation's display form.
    pub fn label(&self) -> String {
        format!(
            "observed now: {} ({}) eligible {}",
            self.class,
            self.reason,
            if self.eligible { "yes" } else { "no" }
        )
    }
}

/// The compact supervision status of ONE run: the recorded state plus the
/// read-time observation, with the honesty rules of this module applied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SupervisionView {
    /// The addressed run identity.
    pub run: String,
    /// Whether the status read reached the daemon's typed service.
    pub read: bool,
    /// The recorded `desired` value (`armed`/`disabled`) when a row exists.
    pub desired: String,
    /// The recorded class (unrecognized codes map to [`RunClass::Unknown`]).
    pub class: RunClass,
    /// The recorded class code verbatim (displayed as recorded).
    pub class_code: String,
    /// The recorded reason code.
    pub reason: String,
    /// The recorded eligibility/window flag of the last committed check.
    pub eligible: bool,
    /// The read-time observation, when the daemon reported one.
    pub observed: Option<Observed>,
    /// The recorded detail of the observation.
    pub detail: String,
    /// Freshness of the recorded last check.
    pub evidence: Evidence,
    /// The recorded freshness bound in seconds.
    pub max_age_secs: Option<u64>,
    /// The recorded number of committed checks.
    pub checks: i64,
    /// The recorded last check, when one exists.
    pub last_check: Option<LastCheck>,
    /// The recorded next eligible check, when one exists.
    pub next_check: Option<NextCheck>,
    /// The durable continuation window.
    pub continuation: Continuation,
    /// Recorded progress source (`state`, `review`, `ci`, `completion`).
    pub progress_source: String,
    /// Age of the recorded progress marker in seconds.
    pub progress_age_secs: Option<u64>,
    /// The recorded pending wake trigger, when one is folded.
    pub pending_trigger: Option<String>,
    /// The recorded supervision id (a role identity, never a host path).
    pub supervision_id: String,
    /// The recorded approved boundary.
    pub approved_boundary: String,
    /// The recorded policy interval.
    pub interval_secs: Option<i64>,
    /// The recorded progress timeout.
    pub progress_timeout_secs: Option<i64>,
    /// The daemon's own note (a refusal message or a read failure).
    pub note: Option<String>,
    /// The stable code of the read failure, when the read failed.
    pub read_code: String,
    /// The document's own statement (one technical disclosure).
    pub statement: String,
}

impl SupervisionView {
    /// The view of a failed read: unknown, held, with the stable code.
    pub fn unavailable(run: &str, code: &str, message: &str) -> Self {
        SupervisionView {
            run: run.to_string(),
            read: false,
            desired: String::new(),
            class: RunClass::Unknown,
            class_code: String::new(),
            reason: String::new(),
            eligible: false,
            observed: None,
            detail: String::new(),
            evidence: Evidence::Unreadable,
            max_age_secs: None,
            checks: 0,
            last_check: None,
            next_check: None,
            continuation: Continuation {
                open: false,
                since: String::new(),
                reports: 0,
            },
            progress_source: String::new(),
            progress_age_secs: None,
            pending_trigger: None,
            supervision_id: String::new(),
            approved_boundary: String::new(),
            interval_secs: None,
            progress_timeout_secs: None,
            note: Some(format!("{code}: {message}")),
            read_code: code.to_string(),
            statement: String::new(),
        }
    }

    /// The view of a run with NO recorded supervision row: supervision is
    /// disabled by default (the daemon's own refusal message is kept).
    pub fn unarmed(run: &str, message: &str) -> Self {
        let mut view = Self::unavailable(run, "state.not_found", message);
        view.read = true;
        view.desired = "disabled".to_string();
        view.read_code = String::new();
        view
    }

    /// Map the recorded `hf-supervision/v1` status document as data.
    pub fn from_status_doc(run: &str, doc: &Val) -> Self {
        let class_code = text_at(doc, &["evaluation", "class"]).unwrap_or_default();
        let class = RunClass::from_code(&class_code).unwrap_or(RunClass::Unknown);
        let freshness_state = text_at(doc, &["evaluation", "freshness", "state"]);
        let freshness_age = uint_at(doc, &["evaluation", "freshness", "age_secs"]);
        let observed = text_at(doc, &["evaluation", "observed", "class"]).map(|class| Observed {
            class,
            reason: text_at(doc, &["evaluation", "observed", "reason"]).unwrap_or_default(),
            eligible: bool_at(doc, &["evaluation", "observed", "eligible"]).unwrap_or(false),
            detail: text_at(doc, &["evaluation", "observed", "detail"]).unwrap_or_default(),
        });
        let last_check = text_at(doc, &["evaluation", "last_check", "at"]).map(|at| LastCheck {
            at,
            class: text_at(doc, &["evaluation", "last_check", "class"]).unwrap_or_default(),
            reason: text_at(doc, &["evaluation", "last_check", "reason"]).unwrap_or_default(),
            trigger: text_at(doc, &["evaluation", "last_check", "trigger"]).unwrap_or_default(),
        });
        let next_check = text_at(doc, &["evaluation", "next_check", "at"]).map(|at| NextCheck {
            at,
            due_in_secs: uint_at(doc, &["evaluation", "next_check", "due_in_secs"]),
            reason: text_at(doc, &["evaluation", "next_check", "reason"]).unwrap_or_default(),
        });
        SupervisionView {
            run: text_at(doc, &["run", "instance_id"]).unwrap_or_else(|| run.to_string()),
            read: true,
            desired: text_at(doc, &["supervision", "desired"]).unwrap_or_default(),
            class,
            class_code,
            reason: text_at(doc, &["evaluation", "reason"]).unwrap_or_default(),
            eligible: bool_at(doc, &["evaluation", "eligible"]).unwrap_or(false),
            observed,
            detail: text_at(doc, &["evaluation", "detail"]).unwrap_or_default(),
            evidence: Evidence::from_recorded(freshness_state.as_deref(), freshness_age),
            max_age_secs: uint_at(doc, &["evaluation", "freshness", "max_age_secs"]),
            checks: int_at(doc, &["evaluation", "checks"]).unwrap_or(0),
            last_check,
            next_check,
            continuation: Continuation {
                open: text_at(doc, &["evaluation", "continuation", "state"]).as_deref()
                    == Some("open"),
                since: text_at(doc, &["evaluation", "continuation", "since"]).unwrap_or_default(),
                reports: int_at(doc, &["evaluation", "continuation", "reports"]).unwrap_or(0),
            },
            progress_source: text_at(doc, &["evaluation", "progress", "source"])
                .unwrap_or_default(),
            progress_age_secs: uint_at(doc, &["evaluation", "progress", "age_secs"]),
            pending_trigger: text_at(doc, &["evaluation", "pending", "trigger"]),
            supervision_id: text_at(doc, &["supervision", "id"]).unwrap_or_default(),
            approved_boundary: text_at(doc, &["supervision", "authorization", "approved_boundary"])
                .unwrap_or_default(),
            interval_secs: int_at(doc, &["supervision", "policy", "check_interval_secs"]),
            progress_timeout_secs: int_at(doc, &["supervision", "policy", "progress_timeout_secs"]),
            note: None,
            read_code: String::new(),
            statement: text_at(doc, &["statement"]).unwrap_or_default(),
        }
    }

    /// Whether the recorded class may be read as a live, committed fact: the
    /// read reached the daemon, the run is actually armed and the recorded
    /// check is fresh. Anything else is held/unknown.
    pub fn trusted(&self) -> bool {
        self.read && self.desired == "armed" && self.evidence.trusted()
    }

    /// Whether this status must render as held/unknown instead of its class.
    pub fn held(&self) -> bool {
        !self.trusted()
    }

    /// The compact class slot: never `healthy` without fresh committed
    /// evidence; stale/missing/unreadable evidence reads unknown/held.
    pub fn class_slot(&self) -> String {
        if !self.read {
            return "unknown — the daemon was not read".to_string();
        }
        if self.desired != "armed" {
            return "disabled — not armed".to_string();
        }
        match self.evidence {
            Evidence::Fresh { .. } => self.class.code().to_string(),
            Evidence::Stale { age_secs } => format!(
                "stale {} — last recorded {} (held)",
                age_label(age_secs),
                self.class.code()
            ),
            Evidence::Missing => "unknown — no committed check yet (held)".to_string(),
            Evidence::Unreadable => "unknown — evidence unreadable (held)".to_string(),
        }
    }

    /// The blocked reason of a hold class, as recorded; `None` for classes
    /// that are not holds.
    pub fn blocked_reason(&self) -> Option<String> {
        match self.class {
            RunClass::BlockedCapacity | RunClass::NeedsAttention => Some(self.reason.clone()),
            _ => None,
        }
    }

    /// The one-line compact status (the board strip and the screen heading).
    pub fn compact_line(&self) -> String {
        if !self.read {
            return format!(
                "unavailable ({}) — unknown, held; the daemon was not read",
                self.read_code
            );
        }
        if self.desired != "armed" {
            return "disabled — not armed (enabling supervision is the CLI's `--supervise arm` \
                    authorization; this surface never arms)"
                .to_string();
        }
        let mut line = format!(
            "{} | reason {} | evidence {} | checks {}",
            self.class_slot(),
            dash(&self.reason),
            self.evidence.label(),
            self.checks
        );
        if self.continuation.open {
            line.push_str(&format!(
                " | window open since {} ({} reports)",
                dash(&self.continuation.since),
                self.continuation.reports
            ));
        } else {
            line.push_str(" | window closed");
        }
        match &self.next_check {
            Some(next) => {
                let due = match next.due_in_secs {
                    Some(secs) => format!("in {secs}s"),
                    None => "due —".to_string(),
                };
                line.push_str(&format!(" | next check {due} ({})", dash(&next.reason)));
            }
            None => line.push_str(" | next check none recorded"),
        }
        line
    }

    /// The read-only detail block of the status screen, bounded to `width`.
    pub fn detail_lines(&self, width: usize) -> Vec<ScreenLine> {
        let mut lines = vec![
            ScreenLine::new(
                Tone::Normal,
                clip(
                    &format!("status: {} | checks {}", self.class_slot(), self.checks),
                    width,
                ),
            ),
            ScreenLine::new(
                Tone::Normal,
                clip(
                    &format!(
                        "reason: {} | detail: {} | blocked reason: {}",
                        dash(&self.reason),
                        dash(&self.detail),
                        self.blocked_reason().unwrap_or_else(|| "none".to_string())
                    ),
                    width,
                ),
            ),
            ScreenLine::new(
                Tone::Normal,
                clip(
                    &format!(
                        "evidence: {} | freshness bound: {}",
                        self.evidence.label(),
                        match self.max_age_secs {
                            Some(secs) => format!("{secs}s"),
                            None => "unknown".to_string(),
                        }
                    ),
                    width,
                ),
            ),
        ];
        match &self.last_check {
            Some(last) => lines.push(ScreenLine::new(
                Tone::Normal,
                clip(
                    &format!(
                        "last check: {} ({}) reported {} ({})",
                        dash(&last.at),
                        dash(&last.trigger),
                        dash(&last.class),
                        dash(&last.reason)
                    ),
                    width,
                ),
            )),
            None => lines.push(ScreenLine::new(
                Tone::Warn,
                clip("last check: none recorded yet", width),
            )),
        }
        match &self.next_check {
            Some(next) => lines.push(ScreenLine::new(
                Tone::Normal,
                clip(
                    &format!(
                        "next eligible check: {} ({} — {})",
                        dash(&next.at),
                        match next.due_in_secs {
                            Some(secs) => format!("in {secs}s"),
                            None => "due now/unknown".to_string(),
                        },
                        dash(&next.reason)
                    ),
                    width,
                ),
            )),
            None => lines.push(ScreenLine::new(
                Tone::Muted,
                clip("next eligible check: none recorded", width),
            )),
        }
        let window = if self.continuation.open {
            format!(
                "continuation window: OPEN since {} ({} reports)",
                dash(&self.continuation.since),
                self.continuation.reports
            )
        } else {
            "continuation window: closed".to_string()
        };
        lines.push(ScreenLine::new(
            if self.continuation.open && self.trusted() {
                Tone::Warn
            } else {
                Tone::Normal
            },
            clip(&window, width),
        ));
        lines.push(ScreenLine::new(
            Tone::Muted,
            clip(
                &format!(
                    "progress: {} {} ago | pending wake: {} | policy: every {}s, timeout {}s",
                    dash(&self.progress_source),
                    match self.progress_age_secs {
                        Some(secs) => age_label(secs),
                        None => "unknown".to_string(),
                    },
                    dash(self.pending_trigger.as_deref().unwrap_or("none")),
                    match self.interval_secs {
                        Some(secs) => secs.to_string(),
                        None => "?".to_string(),
                    },
                    match self.progress_timeout_secs {
                        Some(secs) => secs.to_string(),
                        None => "?".to_string(),
                    }
                ),
                width,
            ),
        ));
        lines.push(ScreenLine::new(
            Tone::Muted,
            clip(
                &format!(
                    "authorization: {} | id {} | approved boundary {} | {SCOPE_STATEMENT}",
                    if self.desired.is_empty() {
                        "not recorded".to_string()
                    } else {
                        self.desired.clone()
                    },
                    dash(&self.supervision_id),
                    dash(&self.approved_boundary)
                ),
                width,
            ),
        ));
        if let Some(observed) = &self.observed {
            lines.push(ScreenLine::new(
                Tone::Muted,
                clip(
                    &format!(
                        "{} (read-time re-observation, never a re-classification)",
                        observed.label()
                    ),
                    width,
                ),
            ));
        }
        if let Some(note) = &self.note {
            lines.push(ScreenLine::new(
                Tone::Warn,
                clip(&format!("daemon: {note}"), width),
            ));
        }
        lines.push(ScreenLine::new(
            Tone::Muted,
            clip(
                "arming, disarming and arming-by-keyboard are not offered here: supervision stays \
                 exactly as the CLI authorization committed it (this surface never arms)",
                width,
            ),
        ));
        if !self.statement.is_empty() {
            lines.push(ScreenLine::new(
                Tone::Muted,
                clip(&format!("statement: {}", self.statement), width),
            ));
        }
        lines
    }
}

/// The recorded run-control projection (`run.status`) as the surface tracks
/// it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControlSnapshot {
    /// `active` / `pause_requested` / `paused` as recorded.
    pub state: String,
    /// The run status the control doc reports.
    pub run_status: String,
    /// A pause request is recorded (durable).
    pub pause_requested: bool,
    /// The pause boundary has been reached.
    pub paused: bool,
    /// The recorded pause reason.
    pub reason: String,
    /// The recorded request instant.
    pub requested_at: String,
    /// The engine-minted digest a resume must present (recorded only while a
    /// pause is recorded).
    pub resume_digest: Option<String>,
    /// Whether the pause boundary has been reached.
    pub boundary_reached: bool,
    /// The step still executing at the safe boundary, when one is.
    pub in_flight_step: Option<String>,
}

impl ControlSnapshot {
    /// Map the recorded `hf-run-control/v1` document as data.
    pub fn from_doc(doc: &Val) -> Self {
        ControlSnapshot {
            state: text_at(doc, &["control", "state"]).unwrap_or_default(),
            run_status: text_at(doc, &["run", "status"]).unwrap_or_default(),
            pause_requested: bool_at(doc, &["control", "pause_requested"]).unwrap_or(false),
            paused: bool_at(doc, &["control", "paused"]).unwrap_or(false),
            reason: text_at(doc, &["control", "reason"]).unwrap_or_default(),
            requested_at: text_at(doc, &["control", "requested_at"]).unwrap_or_default(),
            resume_digest: text_at(doc, &["control", "resume_digest"])
                .filter(|digest| !digest.is_empty()),
            boundary_reached: bool_at(doc, &["boundary", "reached"]).unwrap_or(false),
            in_flight_step: text_at(doc, &["boundary", "in_flight_step"]),
        }
    }

    /// Whether a pause (requested or reached) is recorded.
    pub fn recorded_pause(&self) -> bool {
        self.paused || self.pause_requested
    }

    /// The run is terminal: a terminal run is never paused or resumed.
    pub fn terminal(&self) -> bool {
        self.run_status == "done" || self.run_status == "invalidated"
    }
}

/// Whether one continuation control may be requested right now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Availability {
    /// The control may be requested (the daemon re-validates on the wire).
    Enabled,
    /// The control is disabled with a stable, displayed reason.
    Disabled {
        /// The displayed reason.
        reason: String,
    },
}

impl Availability {
    /// Whether the control is available.
    pub fn enabled(&self) -> bool {
        matches!(self, Self::Enabled)
    }

    /// The display text of the availability.
    pub fn label(&self) -> String {
        match self {
            Self::Enabled => "ready".to_string(),
            Self::Disabled { reason } => format!("disabled: {reason}"),
        }
    }
}

/// The two continuation controls this surface offers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlEffect {
    /// A hold: pause automatic continuation (never stops current work).
    Pause,
    /// An authorized continue: lift exactly one recorded pause.
    Resume,
}

impl ControlEffect {
    /// The wire method of this control (the CLI's own method).
    pub fn method(self) -> &'static str {
        match self {
            Self::Pause => "run.pause",
            Self::Resume => "run.resume",
        }
    }

    /// `hold` / `continue`.
    pub fn label(self) -> &'static str {
        match self {
            Self::Pause => "hold",
            Self::Resume => "continue",
        }
    }
}

/// What the operator asked the daemon to do (the REQUESTED side).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestedControl {
    /// The control.
    pub effect: ControlEffect,
    /// The addressed run.
    pub run: String,
    /// The submitted pause reason (pause only).
    pub reason: Option<String>,
    /// The bound resume digest (resume only).
    pub digest: Option<String>,
}

/// One continuation-control attempt: the request and the daemon's outcome.
#[derive(Clone, Debug, PartialEq)]
pub struct ControlAttempt {
    /// What the operator authorized.
    pub requested: RequestedControl,
    /// What the daemon did (or did not) confirm.
    pub outcome: AttemptOutcome,
}

/// Which confirmation is open, if any.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Confirm {
    None,
    Pause,
    Resume {
        /// The digest shown when the confirmation was opened.
        digest: String,
    },
}

/// The supervision screen/panel state: the last read status, the run-control
/// read, the confirmation state machine and the requested-vs-observed attempt.
pub struct SupervisionPanel {
    run: Option<String>,
    view: Option<SupervisionView>,
    control: Option<ControlSnapshot>,
    confirm: Confirm,
    checked: bool,
    attempt: Option<ControlAttempt>,
    notice: Option<Notice>,
    scroll: u16,
}

impl Default for SupervisionPanel {
    fn default() -> Self {
        Self::new()
    }
}

impl SupervisionPanel {
    /// An empty panel (nothing read yet).
    pub fn new() -> Self {
        SupervisionPanel {
            run: None,
            view: None,
            control: None,
            confirm: Confirm::None,
            checked: false,
            attempt: None,
            notice: None,
            scroll: 0,
        }
    }

    /// The run the panel shows, if any.
    pub fn run(&self) -> Option<&str> {
        self.run.as_deref()
    }

    /// The last read compact status.
    pub fn view(&self) -> Option<&SupervisionView> {
        self.view.as_ref()
    }

    /// The last read run-control snapshot.
    pub fn control(&self) -> Option<&ControlSnapshot> {
        self.control.as_ref()
    }

    /// The last control attempt, if any.
    pub fn attempt(&self) -> Option<&ControlAttempt> {
        self.attempt.as_ref()
    }

    /// Whether the confirmation box is set.
    pub fn checked(&self) -> bool {
        self.checked
    }

    /// Whether a confirmation is open (a control key alone can never effect).
    pub fn confirming(&self) -> bool {
        self.confirm != Confirm::None
    }

    /// The panel's own typed notice, if any.
    pub fn notice(&self) -> Option<&Notice> {
        self.notice.as_ref()
    }

    /// The scroll offset of the screen.
    pub fn scroll(&self) -> u16 {
        self.scroll
    }

    /// Whether `hold` may be requested right now.
    pub fn pause_availability(&self) -> Availability {
        let Some(control) = &self.control else {
            return Availability::Disabled {
                reason: "the run could not be read from the daemon".to_string(),
            };
        };
        if control.terminal() {
            return Availability::Disabled {
                reason: format!(
                    "the run is terminal ({}); a terminal run is never paused",
                    control.run_status
                ),
            };
        }
        if control.recorded_pause() {
            return Availability::Disabled {
                reason: format!("a pause is already recorded ({})", control.state),
            };
        }
        Availability::Enabled
    }

    /// Whether `continue` may be requested right now (a recorded pause AND
    /// the recorded digest are both required).
    pub fn resume_availability(&self) -> Availability {
        let Some(control) = &self.control else {
            return Availability::Disabled {
                reason: "the run could not be read from the daemon".to_string(),
            };
        };
        if !control.recorded_pause() {
            return Availability::Disabled {
                reason: "no pause is recorded for this run".to_string(),
            };
        }
        match control.resume_digest.as_deref() {
            Some(_) => Availability::Enabled,
            None => Availability::Disabled {
                reason:
                    "no recorded resume digest (a resume presents the digest the pause recorded)"
                        .to_string(),
            },
        }
    }

    /// Read (or re-read) the panel for `run` through the typed read services.
    ///
    /// Both reads are read-only and address exactly one run identity: a
    /// refused `run.status` renders the run as unknown; a refused
    /// `supervision.status` with `state.not_found` means no supervision row is
    /// recorded (disabled by default), never a healthy state.
    pub fn read(&mut self, socket: &Path, run: &str) {
        self.run = Some(run.to_string());
        self.confirm = Confirm::None;
        self.checked = false;
        self.notice = None;
        match client::call(socket, "run.status", Some(&run_control::status_params(run))) {
            Ok(doc) => {
                self.control = Some(ControlSnapshot::from_doc(&doc));
                match client::call(
                    socket,
                    "supervision.status",
                    Some(&supervision::status_params(run)),
                ) {
                    Ok(doc) => self.view = Some(SupervisionView::from_status_doc(run, &doc)),
                    Err(err) if err.code == "state.not_found" => {
                        self.view = Some(SupervisionView::unarmed(run, &err.message));
                    }
                    Err(err) => {
                        self.notice = Some(Notice::new(
                            CODE_READ,
                            format!("supervision.status refused: {}: {}", err.code, err.message),
                        ));
                        self.view =
                            Some(SupervisionView::unavailable(run, &err.code, &err.message));
                    }
                }
            }
            Err(err) => {
                self.control = None;
                self.view = Some(SupervisionView::unavailable(run, &err.code, &err.message));
                self.notice = Some(Notice::new(
                    CODE_READ,
                    format!("run.status refused: {}: {}", err.code, err.message),
                ));
            }
        }
    }

    /// Handle one key on the supervision screen.
    ///
    /// Only `Press` events are handled: autorepeat and release events effect
    /// nothing. Without an open confirmation this reads (`r`), opens the two
    /// guarded confirmations (`h`/`u`) or scrolls; inside a confirmation
    /// `Space` sets the box and the boxed `Enter` is the only commit, while
    /// `Esc`/`b` cancel and clear it.
    pub fn handle_key(&mut self, socket: &Path, key: KeyEvent) -> Option<Action> {
        if key.kind != KeyEventKind::Press {
            return None;
        }
        match self.confirm.clone() {
            Confirm::None => match key.code {
                KeyCode::Char('r') => {
                    if let Some(run) = self.run.clone() {
                        self.read(socket, &run);
                    }
                    Some(Action::Redraw)
                }
                KeyCode::Char('h') => {
                    self.begin(ControlEffect::Pause);
                    Some(Action::Redraw)
                }
                KeyCode::Char('u') => {
                    self.begin(ControlEffect::Resume);
                    Some(Action::Redraw)
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    self.scroll = self.scroll.saturating_add(1);
                    Some(Action::Redraw)
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    self.scroll = self.scroll.saturating_sub(1);
                    Some(Action::Redraw)
                }
                _ => None,
            },
            Confirm::Pause | Confirm::Resume { .. } => match key.code {
                KeyCode::Esc | KeyCode::Char('b') => {
                    self.cancel();
                    Some(Action::Redraw)
                }
                KeyCode::Char(' ') => {
                    self.checked = !self.checked;
                    self.notice = None;
                    Some(Action::Redraw)
                }
                KeyCode::Enter => {
                    self.commit(socket);
                    Some(Action::Redraw)
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    self.scroll = self.scroll.saturating_add(1);
                    Some(Action::Redraw)
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    self.scroll = self.scroll.saturating_sub(1);
                    Some(Action::Redraw)
                }
                _ => None,
            },
        }
    }

    /// Open one confirmation: a distinct request step, never an effect.
    fn begin(&mut self, effect: ControlEffect) {
        let availability = match effect {
            ControlEffect::Pause => self.pause_availability(),
            ControlEffect::Resume => self.resume_availability(),
        };
        if let Availability::Disabled { reason } = availability {
            self.notice = Some(Notice::new(
                CODE_DISABLED,
                format!("{} is not available: {reason}", effect.label()),
            ));
            return;
        }
        match effect {
            ControlEffect::Pause => {
                self.confirm = Confirm::Pause;
            }
            ControlEffect::Resume => {
                let digest = self
                    .control
                    .as_ref()
                    .and_then(|control| control.resume_digest.clone())
                    .unwrap_or_default();
                self.confirm = Confirm::Resume { digest };
            }
        }
        self.checked = false;
        self.notice = None;
        self.scroll = 0;
    }

    /// Cancel an open confirmation and clear the box.
    fn cancel(&mut self) {
        self.confirm = Confirm::None;
        self.checked = false;
        self.notice = None;
    }

    /// Commit one confirmed control through the CLI's own params documents.
    ///
    /// Nothing is sent without the box; the availability and (for a resume)
    /// the digest are re-checked against the latest read before the single
    /// call, and an unconfirmed outcome is never replayed.
    fn commit(&mut self, socket: &Path) {
        if !self.checked {
            self.notice = Some(Notice::new(
                CODE_CONFIRM,
                "the confirmation box is not set; Space sets it explicitly and Enter then requests the \
                 control — no other key can",
            ));
            return;
        }
        let Some(run) = self.run.clone() else {
            self.cancel();
            self.notice = Some(Notice::new(
                CODE_NO_RUN,
                "no run is addressed; select a run on the board first",
            ));
            return;
        };
        let (effect, reason, digest) = match self.confirm.clone() {
            Confirm::Pause => {
                if let Availability::Disabled { reason } = self.pause_availability() {
                    self.cancel();
                    self.notice = Some(Notice::new(
                        CODE_DISABLED,
                        format!("hold is not available: {reason}"),
                    ));
                    return;
                }
                (ControlEffect::Pause, Some(PAUSE_REASON.to_string()), None)
            }
            Confirm::Resume { digest } => {
                if let Availability::Disabled { reason } = self.resume_availability() {
                    self.cancel();
                    self.notice = Some(Notice::new(
                        CODE_DISABLED,
                        format!("continue is not available: {reason}"),
                    ));
                    return;
                }
                let recorded = self
                    .control
                    .as_ref()
                    .and_then(|control| control.resume_digest.clone())
                    .unwrap_or_default();
                if recorded != digest {
                    self.cancel();
                    self.notice = Some(Notice::new(
                        CODE_STALE,
                        "the recorded resume digest moved since the confirmation was opened; a resume \
                         binds the digest it displayed — open a fresh confirmation",
                    ));
                    return;
                }
                (ControlEffect::Resume, None, Some(digest))
            }
            Confirm::None => return,
        };
        let key = fresh_control_key();
        let params = match effect {
            ControlEffect::Pause => {
                run_control::pause_params(&key, &run, reason.as_deref().unwrap_or(PAUSE_REASON))
            }
            ControlEffect::Resume => {
                run_control::resume_params(&key, &run, digest.as_deref().unwrap_or_default())
            }
        };
        let outcome = match client::call(socket, effect.method(), Some(&params)) {
            Ok(doc) => match text_at(&doc, &["run", "instance_id"]) {
                Some(answered) if answered == run => AttemptOutcome::Observed { doc },
                other => AttemptOutcome::Uncertain {
                    code: CODE_IDENTITY.to_string(),
                    message: format!(
                        "the daemon answered for run {:?}, not the addressed {run}; the effect \
                         cannot be confirmed by this surface",
                        other.as_deref().unwrap_or("none")
                    ),
                },
            },
            Err(RpcError { code, message }) => super::operator::failure_outcome(&code, &message),
        };
        self.checked = false;
        self.confirm = Confirm::None;
        let unconfirmed = matches!(outcome, AttemptOutcome::Uncertain { .. });
        self.attempt = Some(ControlAttempt {
            requested: RequestedControl {
                effect,
                run: run.clone(),
                reason,
                digest,
            },
            outcome,
        });
        // The requested effect is read back immediately ONLY when the daemon
        // confirmed or refused it; an unconfirmed attempt is never followed by
        // an automatic second call — the operator's explicit `r` reads the
        // daemon back (read-only, never a replay).
        if !unconfirmed {
            self.read(socket, &run);
        }
    }

    /// The lines of the supervision screen, bounded to `width`.
    pub fn lines(&self, width: usize) -> Vec<ScreenLine> {
        let mut lines = vec![ScreenLine::new(
            Tone::Heading,
            clip(
                &format!(
                    "SUPERVISION — {} (read-only status; controls are run-scoped)",
                    dash(self.run.as_deref().unwrap_or("no run selected"))
                ),
                width,
            ),
        )];
        if let Some(notice) = &self.notice {
            lines.push(ScreenLine::new(
                Tone::Warn,
                clip(&format!("{}: {}", notice.code, notice.message), width),
            ));
        }
        match &self.confirm {
            Confirm::None => {
                if let Some(run) = &self.run {
                    lines.push(ScreenLine::new(
                        Tone::Muted,
                        clip(&format!("run: {run} | {SCOPE_STATEMENT}"), width),
                    ));
                }
                match &self.view {
                    Some(view) => lines.extend(view.detail_lines(width)),
                    None => lines.push(ScreenLine::new(
                        Tone::Warn,
                        clip("no status was read yet; press r to read the daemon", width),
                    )),
                }
                lines.extend(self.control_lines(width));
                lines.push(ScreenLine::new(
                    Tone::Heading,
                    clip(
                        "CONTROLS — run-scoped only; no arming, no retry, no queue effect",
                        width,
                    ),
                ));
                lines.push(ScreenLine::new(
                    Tone::Normal,
                    clip(
                        &format!(
                            "hold (pause automatic continuation):  h  [{}]",
                            self.pause_availability().label()
                        ),
                        width,
                    ),
                ));
                lines.push(ScreenLine::new(
                    Tone::Normal,
                    clip(
                        &format!(
                            "continue (authorized resume):         u  [{}]",
                            self.resume_availability().label()
                        ),
                        width,
                    ),
                ));
                if let Some(attempt) = &self.attempt {
                    lines.extend(attempt_lines(attempt, width));
                }
                lines.push(ScreenLine::new(
                    Tone::Muted,
                    clip(
                        "r re-reads the daemon (read-only); b back to the board; q quits",
                        width,
                    ),
                ));
            }
            Confirm::Pause => {
                lines.push(ScreenLine::new(
                    Tone::Heading,
                    clip(
                        &format!(
                            "HOLD REQUEST — confirm the run-scoped pause of {}",
                            dash(self.run.as_deref().unwrap_or(""))
                        ),
                        width,
                    ),
                ));
                lines.push(ScreenLine::new(
                    Tone::Muted,
                    clip(run_control::CONTROL_STATEMENT, width),
                ));
                lines.push(ScreenLine::new(
                    Tone::Normal,
                    clip(
                        "a hold pauses automatic continuation only: work already in flight keeps \
                         running, the pause commits at the run's next step boundary, nothing is \
                         killed and nothing is armed",
                        width,
                    ),
                ));
                lines.push(ScreenLine::new(
                    Tone::Input,
                    clip(
                        &format!(
                            "[{}] hold {} (pause automatic continuation)",
                            if self.checked { "x" } else { " " },
                            dash(self.run.as_deref().unwrap_or(""))
                        ),
                        width,
                    ),
                ));
                lines.push(ScreenLine::new(
                    Tone::Muted,
                    clip(
                        "Space sets the confirmation; Enter then requests the hold; b/Esc cancels and \
                         clears it; q quits",
                        width,
                    ),
                ));
            }
            Confirm::Resume { digest } => {
                lines.push(ScreenLine::new(
                    Tone::Heading,
                    clip(
                        &format!(
                            "CONTINUE REQUEST — confirm the authorized resume of {}",
                            dash(self.run.as_deref().unwrap_or(""))
                        ),
                        width,
                    ),
                ));
                lines.push(ScreenLine::new(Tone::Muted, clip(RESUME_STATEMENT, width)));
                lines.push(ScreenLine::new(
                    Tone::Normal,
                    clip(&format!("digest {}", dash(digest)), width),
                ));
                lines.push(ScreenLine::new(
                    Tone::Input,
                    clip(
                        &format!(
                            "[{}] continue {} (lift exactly this recorded pause)",
                            if self.checked { "x" } else { " " },
                            dash(self.run.as_deref().unwrap_or(""))
                        ),
                        width,
                    ),
                ));
                lines.push(ScreenLine::new(
                    Tone::Muted,
                    clip(
                        "Space sets the confirmation; Enter then requests the resume; b/Esc cancels \
                         and clears it; q quits",
                        width,
                    ),
                ));
            }
        }
        lines
    }

    fn control_lines(&self, width: usize) -> Vec<ScreenLine> {
        match &self.control {
            Some(control) => vec![
                ScreenLine::new(
                    Tone::Normal,
                    clip(
                        &format!(
                            "run control: {} | pause_requested {} | paused {} | boundary reached {} | in-flight {}",
                            dash(&control.state),
                            control.pause_requested,
                            control.paused,
                            control.boundary_reached,
                            dash(control.in_flight_step.as_deref().unwrap_or("none"))
                        ),
                        width,
                    ),
                ),
                ScreenLine::new(
                    Tone::Muted,
                    clip(
                        &format!(
                            "recorded pause: {} | reason {} | at {} | digest {}",
                            if control.recorded_pause() {
                                "yes"
                            } else {
                                "no"
                            },
                            dash(&control.reason),
                            dash(&control.requested_at),
                            dash(control.resume_digest.as_deref().unwrap_or("none"))
                        ),
                        width,
                    ),
                ),
            ],
            None => vec![ScreenLine::new(
                Tone::Warn,
                clip(
                    "run control: not read (the daemon was not reachable)",
                    width,
                ),
            )],
        }
    }

    /// The one-line compact strip for the board screen.
    ///
    /// It reports the read status for the SELECTED run only; a different
    /// selection reads `not read` instead of displaying another run's state.
    pub fn strip(&self, selection: Option<&str>, width: usize) -> ScreenLine {
        let Some(showing) = self.run.as_deref() else {
            return ScreenLine::new(
                Tone::Muted,
                clip("supervision: not read — select a run and press s", width),
            );
        };
        match selection {
            Some(run) if run == showing => match &self.view {
                Some(view) => ScreenLine::new(
                    view.class.tone(),
                    clip(&format!("supervision: {}", view.compact_line()), width),
                ),
                None => {
                    ScreenLine::new(Tone::Muted, clip("supervision: not read — press s", width))
                }
            },
            _ => ScreenLine::new(
                Tone::Muted,
                clip("supervision: not read for this run — press s", width),
            ),
        }
    }
}

/// The REQUESTED vs OBSERVED block of one control attempt.
fn attempt_lines(attempt: &ControlAttempt, width: usize) -> Vec<ScreenLine> {
    let mut lines = vec![
        ScreenLine::new(
            Tone::Heading,
            clip("CONTROL OUTCOME — requested vs observed", width),
        ),
        ScreenLine::new(
            Tone::Normal,
            clip(
                &format!(
                    "REQUESTED {} of run {} | reason {} | digest {}",
                    attempt.requested.effect.label(),
                    attempt.requested.run,
                    dash(attempt.requested.reason.as_deref().unwrap_or("none")),
                    dash(attempt.requested.digest.as_deref().unwrap_or("none"))
                ),
                width,
            ),
        ),
    ];
    match &attempt.outcome {
        AttemptOutcome::Observed { doc } => {
            let control = ControlSnapshot::from_doc(doc);
            lines.push(ScreenLine::new(
                Tone::Normal,
                clip(
                    &format!(
                        "OBSERVED the daemon committed: state {} | pause_requested {} | paused {} | \
                         boundary reached {} | in-flight {}",
                        dash(&control.state),
                        control.pause_requested,
                        control.paused,
                        control.boundary_reached,
                        dash(control.in_flight_step.as_deref().unwrap_or("none"))
                    ),
                    width,
                ),
            ));
            lines.push(ScreenLine::new(
                Tone::Muted,
                clip(
                    "the committed effect lives in the daemon; closing this terminal stops nothing",
                    width,
                ),
            ));
        }
        AttemptOutcome::Refused { code, message } => {
            lines.push(ScreenLine::new(
                Tone::Alert,
                clip(&format!("NOT APPLIED [{code}] {message}"), width),
            ));
            lines.push(ScreenLine::new(
                Tone::Muted,
                clip(
                    "the daemon refused before any effect; nothing was committed by this attempt",
                    width,
                ),
            ));
        }
        AttemptOutcome::Uncertain { code, message } => {
            lines.push(ScreenLine::new(
                Tone::Alert,
                clip(&format!("UNKNOWN [{code}] {message}"), width),
            ));
            lines.push(ScreenLine::new(
                Tone::Warn,
                clip(
                    "the request was sent and the daemon did not confirm it; this surface will not \
                     replay it — press r to read the run back",
                    width,
                ),
            ));
        }
    }
    lines
}

/// A fresh per-attempt idempotency key (a re-request is a fresh claim).
fn fresh_control_key() -> String {
    format!(
        "ik_supervision-{}-{}",
        crate::time::unix_now(),
        client::fresh_id()
    )
}

fn dash(text: &str) -> String {
    if text.is_empty() {
        "-".to_string()
    } else {
        text.to_string()
    }
}

fn text_at(doc: &Val, keys: &[&str]) -> Option<String> {
    let mut current = doc;
    for key in keys {
        current = current.get(key)?;
    }
    current.as_str().map(str::to_string)
}

fn int_at(doc: &Val, keys: &[&str]) -> Option<i64> {
    let mut current = doc;
    for key in keys {
        current = current.get(key)?;
    }
    current.as_int()
}

fn uint_at(doc: &Val, keys: &[&str]) -> Option<u64> {
    int_at(doc, keys).and_then(|value| u64::try_from(value).ok())
}

fn bool_at(doc: &Val, keys: &[&str]) -> Option<bool> {
    let mut current = doc;
    for key in keys {
        current = current.get(key)?;
    }
    current.as_bool()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::value::object;
    use crate::value::string;

    // -----------------------------------------------------------------------
    // Fixture documents (synthetic; shape-identical to the merged projections)
    // -----------------------------------------------------------------------

    /// A recorded `hf-supervision/v1` status document with explicit fields.
    fn status_doc(
        class: &str,
        reason: &str,
        freshness: (&str, Option<i64>),
        eligible: bool,
        window_open: bool,
    ) -> Val {
        object(vec![
            ("schema", string("hf-supervision/v1")),
            (
                "run",
                object(vec![
                    ("instance_id", string("run-0123456789abcdef")),
                    ("status", string("running")),
                ]),
            ),
            (
                "supervision",
                object(vec![
                    ("id", string("su_0123456789abcdef")),
                    ("desired", string("armed")),
                    (
                        "authorization",
                        object(vec![
                            ("approved_boundary", string("staging")),
                            ("bound", string("bound-digest")),
                        ]),
                    ),
                    (
                        "policy",
                        object(vec![
                            ("check_interval_secs", crate::value::integer(60)),
                            ("progress_timeout_secs", crate::value::integer(900)),
                            ("freshness_secs", crate::value::integer(360)),
                        ]),
                    ),
                ]),
            ),
            (
                "evaluation",
                object(vec![
                    ("class", string(class)),
                    ("reason", string(reason)),
                    ("eligible", Val::Bool(eligible)),
                    ("detail", string("p2")),
                    (
                        "observed",
                        object(vec![
                            ("class", string(class)),
                            ("reason", string(reason)),
                            ("eligible", Val::Bool(eligible)),
                            ("detail", string("p2")),
                        ]),
                    ),
                    ("checks", crate::value::integer(3)),
                    (
                        "last_check",
                        object(vec![
                            ("at", string("2026-09-13T00:00:00Z")),
                            ("class", string(class)),
                            ("reason", string(reason)),
                            ("trigger", string("timer")),
                        ]),
                    ),
                    (
                        "next_check",
                        object(vec![
                            ("at", string("2026-09-13T00:01:00Z")),
                            ("reason", string("supervision.recent_progress")),
                            ("due_in_secs", crate::value::integer(42)),
                        ]),
                    ),
                    (
                        "freshness",
                        object(vec![
                            ("state", string(freshness.0)),
                            (
                                "age_secs",
                                match freshness.1 {
                                    Some(secs) => crate::value::integer(secs),
                                    None => crate::value::null(),
                                },
                            ),
                            ("max_age_secs", crate::value::integer(360)),
                        ]),
                    ),
                    (
                        "progress",
                        object(vec![
                            ("marker", string("marker-digest")),
                            ("at", string("2026-09-13T00:00:00Z")),
                            ("source", string("state")),
                            ("age_secs", crate::value::integer(12)),
                        ]),
                    ),
                    (
                        "continuation",
                        object(vec![
                            ("state", string(if window_open { "open" } else { "closed" })),
                            ("since", string("2026-09-13T00:00:00Z")),
                            ("reports", crate::value::integer(1)),
                        ]),
                    ),
                    (
                        "pending",
                        object(vec![
                            ("trigger", string("timer")),
                            ("seq", crate::value::integer(7)),
                            ("folded", crate::value::integer(1)),
                        ]),
                    ),
                ]),
            ),
            ("statement", string("supervision only: fixture statement")),
        ])
    }

    fn control_doc(state: &str, digest: Option<&str>) -> Val {
        object(vec![
            ("schema", string("hf-run-control/v1")),
            (
                "run",
                object(vec![
                    ("instance_id", string("run-0123456789abcdef")),
                    ("status", string("running")),
                ]),
            ),
            (
                "control",
                object(vec![
                    ("state", string(state)),
                    ("pause_requested", Val::Bool(state != "active")),
                    ("paused", Val::Bool(state == "paused")),
                    ("reason", string("operator hold")),
                    ("requested_at", string("2026-09-13T00:00:00Z")),
                    (
                        "resume_digest",
                        match digest {
                            Some(digest) => string(digest),
                            None => crate::value::null(),
                        },
                    ),
                ]),
            ),
            (
                "boundary",
                object(vec![
                    ("reached", Val::Bool(state == "paused")),
                    (
                        "in_flight_step",
                        match state {
                            "pause_requested" => string("p2"),
                            _ => crate::value::null(),
                        },
                    ),
                ]),
            ),
            ("statement", string("run-scoped control only")),
        ])
    }

    fn unavailable_socket() -> std::path::PathBuf {
        std::env::temp_dir().join(format!("hf-97-no-daemon-{}.sock", std::process::id()))
    }

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::from(code)
    }

    // -----------------------------------------------------------------------
    // Status honesty: missing/stale/unknown never read healthy
    // -----------------------------------------------------------------------

    #[test]
    fn an_unread_status_is_unknown_held_and_never_healthy() {
        let view =
            SupervisionView::unavailable("run-0123456789abcdef", "client.connect", "no socket");
        assert!(!view.read);
        assert!(!view.trusted());
        assert!(view.held());
        assert!(
            view.class_slot().starts_with("unknown"),
            "{}",
            view.class_slot()
        );
        assert!(view.compact_line().contains("unavailable"));
        assert!(!view.compact_line().contains("healthy"));
    }

    #[test]
    fn a_fresh_recorded_class_reads_its_recorded_class() {
        let doc = status_doc(
            "healthy",
            "supervision.recent_progress",
            ("fresh", Some(12)),
            false,
            false,
        );
        let view = SupervisionView::from_status_doc("run-0123456789abcdef", &doc);
        assert!(view.trusted());
        assert_eq!(view.class_slot(), "healthy");
        assert_eq!(view.evidence, Evidence::Fresh { age_secs: 12 });
        assert!(view.compact_line().contains("healthy"));
        assert!(view.compact_line().contains("window closed"));
        assert!(view.compact_line().contains("next check in 42s"));
    }

    #[test]
    fn stale_evidence_is_held_and_never_reads_healthy_alone() {
        let doc = status_doc(
            "healthy",
            "supervision.recent_progress",
            ("stale", Some(900)),
            false,
            false,
        );
        let view = SupervisionView::from_status_doc("run-0123456789abcdef", &doc);
        assert!(!view.trusted(), "stale evidence is never a trusted class");
        assert!(view.held());
        let slot = view.class_slot();
        assert!(slot.starts_with("stale 15m"), "{slot}");
        assert!(slot.contains("held"), "{slot}");
        assert!(
            !slot.starts_with("healthy"),
            "a stale check never leads with the recorded class: {slot}"
        );
        assert!(!view.compact_line().starts_with("healthy"));
    }

    #[test]
    fn missing_evidence_reads_unknown_not_healthy() {
        let doc = status_doc(
            "healthy",
            "supervision.recent_progress",
            ("missing", None),
            false,
            false,
        );
        let view = SupervisionView::from_status_doc("run-0123456789abcdef", &doc);
        assert!(!view.trusted());
        assert!(
            view.class_slot().starts_with("unknown"),
            "{}",
            view.class_slot()
        );
        assert!(view.class_slot().contains("held"));
        assert!(view.compact_line().contains("unknown"));
    }

    #[test]
    fn an_unrecognized_class_and_freshness_never_read_healthy() {
        let doc = status_doc(
            "sparkling-progress",
            "supervision.sparkle",
            ("shimmering", None),
            false,
            false,
        );
        let view = SupervisionView::from_status_doc("run-0123456789abcdef", &doc);
        assert_eq!(view.class, RunClass::Unknown);
        assert_eq!(view.class_code, "sparkling-progress");
        assert_eq!(view.evidence, Evidence::Unreadable);
        assert!(!view.trusted());
        assert!(view.class_slot().starts_with("unknown"));
        // The recorded code is still displayed as recorded, never as a known
        // class.
        let text = view
            .detail_lines(200)
            .into_iter()
            .map(|line| line.text)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(text.contains("sparkling-progress"), "{text}");
    }

    #[test]
    fn a_not_armed_run_renders_disabled_and_never_healthy() {
        let view = SupervisionView::unarmed("run-0123456789abcdef", "no supervision exists");
        assert!(view.read);
        assert_eq!(view.desired, "disabled");
        assert!(!view.trusted());
        assert_eq!(view.class_slot(), "disabled — not armed");
        assert!(view.compact_line().contains("disabled"));
        assert!(view.compact_line().contains("never arms"));
    }

    #[test]
    fn the_continuation_window_is_reported_from_the_record_only() {
        let doc = status_doc(
            "continuation-eligible",
            "supervision.progress_timeout",
            ("fresh", Some(5)),
            true,
            true,
        );
        let view = SupervisionView::from_status_doc("run-0123456789abcdef", &doc);
        assert!(view.continuation.open);
        assert_eq!(view.continuation.reports, 1);
        assert!(view.trusted());
        assert!(view.compact_line().contains("window open since"));
        assert!(view.compact_line().contains("1 reports"));
        assert_eq!(view.blocked_reason(), None);
    }

    #[test]
    fn blocked_classes_report_their_recorded_reason() {
        let doc = status_doc(
            "blocked-capacity",
            "supervision.capacity_blocked",
            ("fresh", Some(1)),
            false,
            false,
        );
        let view = SupervisionView::from_status_doc("run-0123456789abcdef", &doc);
        assert_eq!(
            view.blocked_reason().as_deref(),
            Some("supervision.capacity_blocked")
        );
        assert_eq!(view.class, RunClass::BlockedCapacity);
        assert_eq!(view.class.tone(), Tone::Alert);
        let doc = status_doc(
            "needs-attention",
            "supervision.review_failed",
            ("fresh", Some(1)),
            false,
            false,
        );
        let view = SupervisionView::from_status_doc("run-0123456789abcdef", &doc);
        assert_eq!(
            view.blocked_reason().as_deref(),
            Some("supervision.review_failed")
        );
    }

    #[test]
    fn every_recorded_class_maps_onto_the_closed_vocabulary() {
        for code in supervision::CLASSES {
            assert!(
                RunClass::from_code(code).is_some(),
                "recorded class {code} must have a closed arm"
            );
        }
        assert_eq!(RunClass::from_code("not-a-class"), None);
    }

    // -----------------------------------------------------------------------
    // Guarded controls: confirmations, autorepeat, escape, no arming
    // -----------------------------------------------------------------------

    /// A panel positioned exactly like a read one, with the given control doc.
    fn panel_with(control: Option<Val>, view: Option<Val>) -> SupervisionPanel {
        let mut panel = SupervisionPanel::new();
        panel.run = Some("run-0123456789abcdef".to_string());
        panel.control = control.map(|doc| ControlSnapshot::from_doc(&doc));
        panel.view = view.map(|doc| SupervisionView::from_status_doc("run-0123456789abcdef", &doc));
        panel
    }

    fn active_control() -> Val {
        control_doc("active", None)
    }

    #[test]
    fn a_hold_requires_the_request_key_the_box_and_enter() {
        let mut panel = panel_with(Some(active_control()), None);
        // A bare Enter on the read view effects nothing.
        assert_eq!(
            panel.handle_key(&unavailable_socket(), key(KeyCode::Enter)),
            None
        );
        assert!(panel.attempt().is_none());
        assert!(!panel.confirming());
        // `h` opens the confirmation only; it does not effect.
        assert_eq!(
            panel.handle_key(&unavailable_socket(), key(KeyCode::Char('h'))),
            Some(Action::Redraw)
        );
        assert!(panel.confirming());
        assert!(!panel.checked());
        assert!(panel.attempt().is_none());
        // Enter without the box refuses locally and sends nothing.
        panel.handle_key(&unavailable_socket(), key(KeyCode::Enter));
        assert!(panel.attempt().is_none(), "an unboxed Enter never effects");
        assert_eq!(panel.notice().expect("notice").code, CODE_CONFIRM);
        assert!(panel.confirming(), "the confirmation stays open");
    }

    #[test]
    fn autorepeat_and_release_never_commit_or_open_anything() {
        let mut panel = panel_with(Some(active_control()), None);
        let mut repeat = key(KeyCode::Char('h'));
        repeat.kind = KeyEventKind::Repeat;
        assert_eq!(panel.handle_key(&unavailable_socket(), repeat), None);
        assert!(!panel.confirming(), "a held key never opens a confirmation");
        // A held Enter with the box set is not a commit either: the box can
        // only be set by a Press and the commit only by a Press.
        panel.handle_key(&unavailable_socket(), key(KeyCode::Char('h')));
        panel.handle_key(&unavailable_socket(), key(KeyCode::Char(' ')));
        assert!(panel.checked());
        let mut held_enter = key(KeyCode::Enter);
        held_enter.kind = KeyEventKind::Repeat;
        assert_eq!(panel.handle_key(&unavailable_socket(), held_enter), None);
        assert!(panel.attempt().is_none(), "no attempt from a held key");
        let mut released = key(KeyCode::Enter);
        released.kind = KeyEventKind::Release;
        assert_eq!(panel.handle_key(&unavailable_socket(), released), None);
        assert!(panel.attempt().is_none(), "no attempt from a release");
        // The box survives; a real Press Enter is the one commit key and it
        // reaches the typed call (here: a definite no-daemon refusal).
        panel.handle_key(&unavailable_socket(), key(KeyCode::Enter));
        let attempt = panel.attempt().expect("the press commit reached the call");
        assert!(matches!(attempt.outcome, AttemptOutcome::Refused { .. }));
        assert_eq!(attempt.requested.effect, ControlEffect::Pause);
    }

    #[test]
    fn escape_cancels_the_confirmation_and_clears_the_box() {
        let mut panel = panel_with(Some(active_control()), None);
        panel.handle_key(&unavailable_socket(), key(KeyCode::Char('h')));
        panel.handle_key(&unavailable_socket(), key(KeyCode::Char(' ')));
        assert!(panel.checked());
        panel.handle_key(&unavailable_socket(), key(KeyCode::Esc));
        assert!(!panel.confirming());
        assert!(!panel.checked());
        panel.handle_key(&unavailable_socket(), key(KeyCode::Enter));
        assert!(
            panel.attempt().is_none(),
            "an escape kills the pending commit"
        );
    }

    #[test]
    fn a_recorded_pause_disables_a_second_hold_and_enables_continue() {
        let digest = "ab".repeat(32);
        let mut panel = panel_with(Some(control_doc("paused", Some(&digest))), None);
        assert!(!panel.pause_availability().enabled());
        assert!(
            panel
                .pause_availability()
                .label()
                .contains("already recorded")
        );
        assert!(panel.resume_availability().enabled());
        panel.handle_key(&unavailable_socket(), key(KeyCode::Char('h')));
        assert!(
            !panel.confirming(),
            "a disabled control never opens a confirmation"
        );
        assert_eq!(panel.notice().expect("notice").code, CODE_DISABLED);
        panel.handle_key(&unavailable_socket(), key(KeyCode::Char('u')));
        assert!(panel.confirming(), "continue opens its own confirmation");
    }

    #[test]
    fn continue_requires_the_recorded_digest() {
        let mut panel = panel_with(Some(control_doc("paused", None)), None);
        assert!(!panel.resume_availability().enabled());
        assert!(
            panel
                .resume_availability()
                .label()
                .contains("no recorded resume digest")
        );
        panel.handle_key(&unavailable_socket(), key(KeyCode::Char('u')));
        assert!(!panel.confirming());
        assert_eq!(panel.notice().expect("notice").code, CODE_DISABLED);
    }

    #[test]
    fn a_terminal_run_is_never_holdable_or_continuable() {
        // A done run: the control doc reports the terminal status.
        let mut done = control_doc("active", None);
        if let Val::Obj(map) = &mut done {
            map.insert(
                "run".to_string(),
                object(vec![
                    ("instance_id", string("run-0123456789abcdef")),
                    ("status", string("done")),
                ]),
            );
        }
        let panel = panel_with(Some(done), None);
        assert!(!panel.pause_availability().enabled());
        assert!(panel.pause_availability().label().contains("terminal"));
        assert!(!panel.resume_availability().enabled());
        assert!(
            panel
                .resume_availability()
                .label()
                .contains("no pause is recorded")
        );
    }

    #[test]
    fn a_moved_resume_digest_refuses_before_any_call() {
        let first = "ab".repeat(32);
        let second = "cd".repeat(32);
        let mut panel = panel_with(Some(control_doc("paused", Some(&first))), None);
        panel.handle_key(&unavailable_socket(), key(KeyCode::Char('u')));
        assert!(panel.confirming());
        // The recorded digest moves between the confirmation and the commit.
        panel.control = Some(ControlSnapshot::from_doc(&control_doc(
            "paused",
            Some(&second),
        )));
        panel.handle_key(&unavailable_socket(), key(KeyCode::Char(' ')));
        panel.handle_key(&unavailable_socket(), key(KeyCode::Enter));
        assert!(panel.attempt().is_none(), "a moved digest sends nothing");
        assert_eq!(panel.notice().expect("notice").code, CODE_STALE);
    }

    #[test]
    fn the_status_screen_renders_the_controls_and_the_scope_but_never_an_arm_control() {
        let doc = status_doc(
            "waiting-CI",
            "supervision.waiting_CI",
            ("fresh", Some(30)),
            false,
            false,
        );
        let panel = panel_with(Some(active_control()), Some(doc));
        let text = panel
            .lines(200)
            .into_iter()
            .map(|line| line.text)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(text.contains("SUPERVISION"), "{text}");
        assert!(text.contains("waiting-CI"), "{text}");
        assert!(text.contains("CONTROLS"), "{text}");
        assert!(
            text.contains("hold (pause automatic continuation):  h  [ready]"),
            "{text}"
        );
        assert!(
            text.contains(
                "continue (authorized resume):         u  [disabled: no pause is recorded"
            ),
            "{text}"
        );
        assert!(
            text.contains("no fleet-level and no harness-level effect"),
            "{text}"
        );
        assert!(text.contains("never arms"), "{text}");
        assert!(!text.contains("arm supervision"), "{text}");
    }

    #[test]
    fn the_strip_reports_only_the_selected_run() {
        let doc = status_doc(
            "healthy",
            "supervision.recent_progress",
            ("fresh", Some(3)),
            false,
            false,
        );
        let panel = panel_with(Some(active_control()), Some(doc));
        let mine = panel.strip(Some("run-0123456789abcdef"), 200);
        assert!(mine.text.contains("supervision: healthy"), "{}", mine.text);
        let other = panel.strip(Some("run-ffffffffffffffff"), 200);
        assert!(
            other.text.contains("not read for this run"),
            "{}",
            other.text
        );
        let fresh = SupervisionPanel::new().strip(None, 200);
        assert!(fresh.text.contains("not read"), "{}", fresh.text);
    }
}
