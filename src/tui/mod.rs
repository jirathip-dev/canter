//! Ratatui + Crossterm operator surface (slice #90; consumes the read-model
//! contract of #83 through an explicit interface).
//!
//! This is an independent rendering module. It owns the approved board-first
//! information hierarchy (wide board, narrow single-group view, keyboard-only
//! controls, explicit too-small state) and renders it from an explicitly
//! typed view model: [`BoardView`] arrives through the narrow [`ReadModel`]
//! boundary. The module never opens the daemon database or state files, never
//! shells out, and never infers workflow status from terminal text — status,
//! freshness and completeness are data, and they are rendered as data.
//!
//! Terminal policy: terminal-default foreground/background colours with a
//! small ANSI accent palette ([`ColorMode::Ansi`]) and a monochrome fallback
//! ([`ColorMode::Mono`]) that keeps every textual label and drops every
//! colour. There is no forced green, no fixed RGB background, no embedded
//! chat, no card drag mutation and no fabricated metric: the renderer can
//! only display what the view model carries.
//!
//! Fixture discipline: examples and tests use synthetic identities only
//! (`acme/widgets`, `lane-alpha`, `run-0001`, ...). Provider/model names
//! never appear here; they stay dynamic in profile configuration elsewhere.

pub mod board;
pub mod live;
pub mod operator;
pub mod session;
pub mod supervision;

use ratatui::crossterm::event::{KeyCode, KeyEvent};

/// Terminal colour capability the surface is rendering into.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColorMode {
    /// ANSI semantic accents on terminal-default foreground/background.
    Ansi,
    /// Monochrome fallback: identical text, no colour attributes at all.
    Mono,
}

impl ColorMode {
    /// Select a mode from terminal capability signals.
    ///
    /// Pure so it is testable without a terminal: a set `NO_COLOR`, a
    /// `TERM=dumb` terminal, or a terminal reporting at most one colour all
    /// select [`ColorMode::Mono`]; anything else selects [`ColorMode::Ansi`].
    pub fn from_signals(no_color: bool, term: Option<&str>, color_count: u16) -> Self {
        if no_color || matches!(term, Some("dumb")) || color_count <= 1 {
            Self::Mono
        } else {
            Self::Ansi
        }
    }

    /// Detect the mode for the current process environment.
    ///
    /// Reads `NO_COLOR`/`TERM` and asks Crossterm how many colours the
    /// terminal advertises. Only the interactive session entry point uses
    /// this; rendering itself always takes the mode as a parameter.
    pub fn detect() -> Self {
        let no_color = std::env::var_os("NO_COLOR").is_some();
        let term = std::env::var("TERM").ok();
        let color_count = ratatui::crossterm::style::available_color_count();
        Self::from_signals(no_color, term.as_deref(), color_count)
    }
}

/// Board column (ratified board-first hierarchy): the four stage groups.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StageGroup {
    /// Work that is scoped or waiting on a dependency; nothing is running.
    Planned,
    /// Work with a live owner or an in-flight external check.
    InProgress,
    /// Work that needs an operator decision or a diagnosed repair.
    NeedsAttention,
    /// Work whose delivery was verified by external readback.
    Verified,
}

impl StageGroup {
    /// The four groups in board order.
    pub const ALL: [StageGroup; 4] = [
        StageGroup::Planned,
        StageGroup::InProgress,
        StageGroup::NeedsAttention,
        StageGroup::Verified,
    ];

    /// Short human-readable label (also the visible board column header).
    pub fn label(self) -> &'static str {
        match self {
            Self::Planned => "Planned",
            Self::InProgress => "In progress",
            Self::NeedsAttention => "Needs attention",
            Self::Verified => "Verified",
        }
    }
}

/// Workflow stage of one work attempt, as reported by the read model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    /// Scoped and eligible, no owner yet.
    Ready,
    /// Blocked on another work item's verification.
    DependencyHold,
    /// A lane is actively implementing.
    Implementing,
    /// Independent review of an exact head is pending.
    Review,
    /// A review round requested fixes.
    FixesRequested,
    /// Required continuous-integration checks are queued or running.
    CiWaiting,
    /// A required check failed; one diagnosed repair may be applicable.
    CiFailure,
    /// The run is stopped on a recorded terminal blocker.
    Blocked,
    /// The worker reported completion; external delivery is not verified.
    WorkerReportedDone,
    /// Waiting on a human-only approval (for example a production gate).
    HumanOnlyGate,
    /// The run's recorded facts were invalidated (for example by an epoch
    /// rotation); this is not progress and never delivery.
    Invalidated,
    /// External readback verified the delivery (for example a merge commit).
    VerifiedMerge,
    /// The required capability is not available; this is not progress.
    UnsupportedStep,
}

impl Stage {
    /// The board column this stage belongs to.
    pub fn group(self) -> StageGroup {
        match self {
            Self::Ready | Self::DependencyHold | Self::UnsupportedStep => StageGroup::Planned,
            Self::Implementing | Self::Review | Self::CiWaiting => StageGroup::InProgress,
            Self::FixesRequested
            | Self::CiFailure
            | Self::Blocked
            | Self::WorkerReportedDone
            | Self::HumanOnlyGate
            | Self::Invalidated => StageGroup::NeedsAttention,
            Self::VerifiedMerge => StageGroup::Verified,
        }
    }

    /// Human-readable stage label.
    ///
    /// Deliberately distinct labels keep ambiguous states distinct:
    /// "Worker-reported done" is a report, "Verified merge" is verified
    /// delivery, and neither means "the whole workflow is finished".
    pub fn label(self) -> &'static str {
        match self {
            Self::Ready => "Ready",
            Self::DependencyHold => "Dependency hold",
            Self::Implementing => "Implementing",
            Self::Review => "Review",
            Self::FixesRequested => "Fixes requested",
            Self::CiWaiting => "CI waiting",
            Self::CiFailure => "CI failure",
            Self::Blocked => "Blocked",
            Self::WorkerReportedDone => "Worker-reported done",
            Self::HumanOnlyGate => "Human-only gate",
            Self::Invalidated => "Invalidated",
            Self::VerifiedMerge => "Verified merge",
            Self::UnsupportedStep => "Unsupported step",
        }
    }
}

/// Delivery outcome as far as the read model can tell.
///
/// "Idle" or "working" never implies delivery: only [`Outcome::VerifiedDelivery`]
/// is delivered, and [`Outcome::ReportedDone`] is explicitly unverified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Work is still in progress; no completion claim exists.
    InProgress,
    /// Someone reported completion; no external readback verified it.
    ReportedDone,
    /// External readback verified the delivery.
    VerifiedDelivery,
}

impl Outcome {
    /// Human-readable outcome label; reported done is explicitly unverified.
    pub fn label(self) -> &'static str {
        match self {
            Self::InProgress => "in progress",
            Self::ReportedDone => "reported done (unverified)",
            Self::VerifiedDelivery => "verified delivery",
        }
    }

    /// Compact board marker for this outcome, if any.
    pub fn marker(self) -> Option<&'static str> {
        match self {
            Self::InProgress => None,
            Self::ReportedDone => Some("[R]"),
            Self::VerifiedDelivery => Some("[V]"),
        }
    }
}

/// Kind of evidence reference attached to a work attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceKind {
    /// A review verdict at an exact head.
    Review,
    /// A continuous-integration check result.
    Ci,
    /// A human gate or approval record.
    Gate,
    /// A recorded evidence reference the source does not classify (its
    /// durable identifier, displayed as recorded).
    Reference,
    /// The row's recorded verification verdict (derived by the read model
    /// from the newest recorded review evidence).
    Verification,
}

impl EvidenceKind {
    /// Short human-readable label used in the evidence summary.
    pub fn label(self) -> &'static str {
        match self {
            Self::Review => "review",
            Self::Ci => "ci",
            Self::Gate => "gate",
            Self::Reference => "ref",
            Self::Verification => "verification",
        }
    }
}

/// One bounded evidence reference: a kind plus a short display label.
///
/// Labels are short identifiers ("review round 2", "checks queued"), never
/// raw logs or terminal dumps; the renderer additionally bounds and
/// control-character-filters everything it displays.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceRef {
    /// What kind of evidence this is.
    pub kind: EvidenceKind,
    /// Bounded display label for the reference.
    pub label: String,
}

/// Source freshness and completeness for a row or the whole board.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Freshness {
    /// Age of the observation in seconds.
    pub age_secs: u64,
    /// Whether the source itself flagged this observation as stale.
    pub stale: bool,
    /// Whether the source reports the observation as complete.
    pub complete: bool,
}

impl Freshness {
    /// `fresh 12s` / `stale 15m` style label.
    pub fn label(self) -> String {
        let prefix = if self.stale { "stale" } else { "fresh" };
        format!("{prefix} {}", age_label(self.age_secs))
    }

    /// `complete` / `partial` label.
    pub fn completeness_label(self) -> &'static str {
        if self.complete { "complete" } else { "partial" }
    }
}

pub(crate) fn age_label(secs: u64) -> String {
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m", secs / 60)
    } else {
        format!("{}h", secs / 3600)
    }
}

/// Stable identity of a work item on the specification side (for example a
/// repository issue). Two rows may share it when one issue has multiple
/// attempts; identity never collapses them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssueKey {
    /// Repository (owner/name) the work item belongs to.
    pub repository: String,
    /// Work item number inside that repository.
    pub issue: u64,
}

impl IssueKey {
    /// `owner/name#123` display label.
    pub fn label(&self) -> String {
        format!("{}#{}", self.repository, self.issue)
    }
}

/// Stable identity of one execution attempt under an issue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunKey {
    /// Run identifier.
    pub run: String,
    /// Attempt number within that run, when the source numbers attempts.
    /// `None` when it does not: the read model numbers no attempts (several
    /// attempts under one issue are several runs), so one is never invented.
    pub attempt: Option<u32>,
}

impl RunKey {
    /// `run-0001 attempt 2`, or the bare run identifier when the source
    /// recorded no attempt number.
    pub fn label(&self) -> String {
        match self.attempt {
            Some(attempt) => format!("{} attempt {}", self.run, attempt),
            None => self.run.clone(),
        }
    }
}

/// One row of the board: a work attempt with everything the surface displays.
///
/// All fields arrive from the read model as data. `owner`, `reason`,
/// `next_action` and `human_gate` are display strings; the renderer bounds
/// and sanitizes them at draw time (see `board::draw`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkRow {
    /// Specification-side identity (issue).
    pub issue: IssueKey,
    /// Execution-side identity; `None` when no attempt exists yet.
    pub run: Option<RunKey>,
    /// Work-item summary line, when the source carries one.
    pub title: Option<String>,
    /// Workflow stage of this attempt.
    pub stage: Stage,
    /// Who currently owns the attempt.
    pub owner: Option<String>,
    /// Why the attempt is where it is (blocker or last transition reason).
    pub reason: Option<String>,
    /// The single next action for the operator.
    pub next_action: Option<String>,
    /// Human gate that must be satisfied, when the stage requires one.
    pub human_gate: Option<String>,
    /// Bounded evidence references (review/CI/gate).
    pub evidence: Vec<EvidenceRef>,
    /// Delivery outcome for this attempt.
    pub outcome: Outcome,
    /// Freshness/completeness of this row's observation.
    pub freshness: Freshness,
}

impl WorkRow {
    /// This row's [`Selection`] identity (issue plus attempt, if any).
    pub fn selection(&self) -> Selection {
        Selection {
            issue: self.issue.clone(),
            run: self.run.clone(),
        }
    }
}

/// A keyboard selection: the exact issue AND attempt selected.
///
/// Selection is identity-based, never index-based, so a refresh that
/// reorders or reparses rows cannot silently move the selection to a
/// sibling attempt or a different issue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selection {
    /// Selected issue.
    pub issue: IssueKey,
    /// Selected attempt (`None` for rows without an attempt).
    pub run: Option<RunKey>,
}

impl Selection {
    /// Whether `row` is the selected attempt.
    pub fn matches_row(&self, row: &WorkRow) -> bool {
        row.issue == self.issue && row.run == self.run
    }
}

/// Which region currently holds keyboard focus.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Focus {
    /// The row list/board.
    #[default]
    Rows,
    /// The selected-item detail.
    Detail,
}

/// What the caller should do after a key event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// State changed; redraw.
    Redraw,
    /// The operator asked to quit.
    Quit,
}

/// Keyboard surface state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UiState {
    /// Selected issue/attempt, by identity.
    pub selected: Option<Selection>,
    /// Focused region.
    pub focus: Focus,
}

impl UiState {
    /// Index of the selected row resolved by stable identity.
    ///
    /// Resolution happens fresh on every draw; if the selected identity is
    /// not in the current view the result is `None` and the renderer states
    /// that the selection is retained but no longer in view, instead of
    /// silently selecting some other row.
    pub fn selected_index(&self, view: &BoardView) -> Option<usize> {
        let selected = self.selected.as_ref()?;
        view.rows.iter().position(|row| selected.matches_row(row))
    }
}

/// Board-level source state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoardState {
    /// A first read is in flight; no rows are known yet.
    Loading,
    /// The source read succeeded and holds no work items.
    Empty,
    /// The source read succeeded and is fresh.
    Ready,
    /// The source read succeeded earlier but is now stale; last known data.
    Stale,
    /// The source is unreachable; last known data only, no fresh reads.
    Offline,
    /// The source refused access; no rows are shown.
    NoAccess,
}

/// Bounded pagination of the board read.
///
/// `count` and `total_rows` are `None` while the source reports that more
/// rows exist beyond the bounded read: the totals are unknown then and are
/// never guessed. The renderer says so explicitly, and states the page's
/// window in the read's order from [`Page::rows_before`] plus the rows it
/// actually holds — the position is a fact of the reads performed, not an
/// estimate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Page {
    /// 1-based page number.
    pub current: u64,
    /// Total number of pages, when the source can report it.
    pub count: Option<u64>,
    /// Total number of rows across all pages, when the source can report it.
    pub total_rows: Option<u64>,
    /// Rows read on the pages before this one (0 on the first page).
    ///
    /// A page is only left behind when the read reported another page, i.e.
    /// when it held exactly a full page, so this is the number of recorded
    /// rows the surface has paged past — never an assumed or invented count.
    pub rows_before: u64,
}

/// Explicit typed view model: everything the surface renders.
///
/// This is the interface the renderer codes against. It is produced by the
/// read model (#83) through [`ReadModel::snapshot`]; nothing else reaches
/// the surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoardView {
    /// Display label of the source feed (for example `fixture-feed`).
    pub source: String,
    /// Explicit synthetic-mode flag: when true the surface labels itself.
    pub synthetic: bool,
    /// Board-level source state.
    pub state: BoardState,
    /// Optional human note for non-ready states (for example the no-access
    /// reason). Displayed bounded and sanitized.
    pub state_note: Option<String>,
    /// Rows of this page, in source order.
    pub rows: Vec<WorkRow>,
    /// Bounded pagination.
    pub page: Page,
    /// Board-level freshness/completeness.
    pub freshness: Freshness,
}

/// The read-model boundary.
///
/// The TUI consumes an explicit snapshot through this one-method trait and
/// nothing else: no database handle, no state internals, no subprocesses,
/// no terminal-text inference. Implementations map their own errors onto
/// [`BoardState`] values (offline, no access, ...) instead of panicking.
pub trait ReadModel {
    /// Produce the current board snapshot.
    fn snapshot(&self) -> BoardView;
}

/// Explicitly truncate adapter text for display.
///
/// Control characters (including escape sequences, newlines and `DEL`) are
/// neutralized to spaces so no raw terminal escape can reach the screen, and
/// the result is bounded to `max_columns` display columns with a trailing
/// `…` marker when it was clipped. `max_columns == 0` yields an empty string.
pub(crate) fn clip(text: &str, max_columns: usize) -> String {
    if max_columns == 0 {
        return String::new();
    }
    let cleaned: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if cleaned.chars().count() <= max_columns {
        return cleaned;
    }
    let keep = max_columns.saturating_sub(1);
    let mut out: String = cleaned.chars().take(keep).collect();
    out.push('…');
    out
}

/// Handle one key event against the current view.
///
/// Controls are keyboard-only: `Tab` toggles focus between the rows and the
/// detail, `Up`/`Down` (or `k`/`j`) move the selection, `Left`/`Right` jump
/// to the previous/next stage group, and `q`/`Esc` request quit. Unhandled
/// keys change nothing and return `None`.
pub fn handle_key(state: &mut UiState, view: &BoardView, key: KeyEvent) -> Option<Action> {
    match key.code {
        KeyCode::Esc | KeyCode::Char('q') => Some(Action::Quit),
        KeyCode::Tab | KeyCode::BackTab => {
            state.focus = match state.focus {
                Focus::Rows => Focus::Detail,
                Focus::Detail => Focus::Rows,
            };
            Some(Action::Redraw)
        }
        KeyCode::Down | KeyCode::Char('j') => {
            move_selection(state, view, 1);
            Some(Action::Redraw)
        }
        KeyCode::Up | KeyCode::Char('k') => {
            move_selection(state, view, -1);
            Some(Action::Redraw)
        }
        KeyCode::Right => {
            jump_group(state, view, 1);
            Some(Action::Redraw)
        }
        KeyCode::Left => {
            jump_group(state, view, -1);
            Some(Action::Redraw)
        }
        _ => None,
    }
}

fn move_selection(state: &mut UiState, view: &BoardView, delta: i64) {
    if view.rows.is_empty() {
        return;
    }
    let last = view.rows.len() as i64 - 1;
    let index = match state.selected_index(view) {
        Some(current) => (current as i64 + delta).clamp(0, last) as usize,
        None => {
            if delta > 0 {
                0
            } else {
                last as usize
            }
        }
    };
    state.selected = Some(view.rows[index].selection());
}

fn jump_group(state: &mut UiState, view: &BoardView, direction: i64) {
    let present: Vec<StageGroup> = StageGroup::ALL
        .into_iter()
        .filter(|group| view.rows.iter().any(|row| row.stage.group() == *group))
        .collect();
    if present.is_empty() {
        return;
    }
    let target = match state.selected_index(view) {
        Some(index) => {
            let current = view.rows[index].stage.group();
            let position = present
                .iter()
                .position(|group| *group == current)
                .unwrap_or(0) as i64;
            present[(position + direction).clamp(0, present.len() as i64 - 1) as usize]
        }
        None => present[0],
    };
    if let Some(index) = view.rows.iter().position(|row| row.stage.group() == target) {
        state.selected = Some(view.rows[index].selection());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_color_capability_selects_monochrome() {
        assert_eq!(
            ColorMode::from_signals(true, Some("xterm-256color"), 256),
            ColorMode::Mono
        );
        assert_eq!(
            ColorMode::from_signals(false, Some("dumb"), 256),
            ColorMode::Mono
        );
        assert_eq!(
            ColorMode::from_signals(false, Some("xterm"), 1),
            ColorMode::Mono
        );
        assert_eq!(
            ColorMode::from_signals(false, Some("xterm-256color"), 256),
            ColorMode::Ansi
        );
        assert_eq!(ColorMode::from_signals(false, None, 8), ColorMode::Ansi);
    }

    #[test]
    fn clip_neutralizes_controls_and_bounds_with_marker() {
        assert_eq!(clip("plain", 10), "plain");
        assert_eq!(
            clip("escape \u{1b}[31mred\u{1b}[0m here", 64),
            "escape  [31mred [0m here"
        );
        assert_eq!(clip("line\nbreak\ttab", 64), "line break tab");
        assert_eq!(clip("abcdef", 4), "abc…");
        assert_eq!(clip("abcdef", 6), "abcdef");
        assert_eq!(clip("abcdef", 0), "");
        assert_eq!(clip("abcdef", 1), "…");
    }

    #[test]
    fn outcome_markers_keep_reported_and_verified_distinct() {
        assert_eq!(Outcome::ReportedDone.marker(), Some("[R]"));
        assert_eq!(Outcome::VerifiedDelivery.marker(), Some("[V]"));
        assert_eq!(Outcome::InProgress.marker(), None);
    }

    #[test]
    fn stage_groups_cover_every_stage() {
        let stages = [
            Stage::Ready,
            Stage::DependencyHold,
            Stage::Implementing,
            Stage::Review,
            Stage::FixesRequested,
            Stage::CiWaiting,
            Stage::CiFailure,
            Stage::Blocked,
            Stage::WorkerReportedDone,
            Stage::HumanOnlyGate,
            Stage::Invalidated,
            Stage::VerifiedMerge,
            Stage::UnsupportedStep,
        ];
        for stage in stages {
            assert!(StageGroup::ALL.contains(&stage.group()));
        }
        assert_eq!(
            Stage::WorkerReportedDone.group(),
            StageGroup::NeedsAttention
        );
        assert_eq!(Stage::VerifiedMerge.group(), StageGroup::Verified);
        assert_eq!(Stage::Blocked.group(), StageGroup::NeedsAttention);
        assert_eq!(Stage::Invalidated.group(), StageGroup::NeedsAttention);
    }

    #[test]
    fn run_labels_omit_an_unrecorded_attempt_number() {
        let numbered = RunKey {
            run: "run-0001".to_string(),
            attempt: Some(2),
        };
        assert_eq!(numbered.label(), "run-0001 attempt 2");
        let unnumbered = RunKey {
            run: "run-0001".to_string(),
            attempt: None,
        };
        assert_eq!(
            unnumbered.label(),
            "run-0001",
            "an unrecorded attempt number is never invented"
        );
    }

    #[test]
    fn freshness_labels_are_stable() {
        let fresh = Freshness {
            age_secs: 12,
            stale: false,
            complete: true,
        };
        assert_eq!(fresh.label(), "fresh 12s");
        assert_eq!(fresh.completeness_label(), "complete");
        let stale = Freshness {
            age_secs: 900,
            stale: true,
            complete: false,
        };
        assert_eq!(stale.label(), "stale 15m");
        assert_eq!(stale.completeness_label(), "partial");
        let hours = Freshness {
            age_secs: 7200,
            stale: false,
            complete: true,
        };
        assert_eq!(hours.label(), "fresh 2h");
    }
}
