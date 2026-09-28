//! Focused regression tests for the Ratatui operator surface (slice #90).
//!
//! Everything here renders through the real Ratatui test backend at fixed
//! sizes and asserts the actual cell/row content and cell styles — the same
//! `board::draw` path the interactive surface uses. All identities are
//! synthetic.

use canter::tui::board::{self, MIN_HEIGHT, MIN_WIDTH, WIDE_MIN_WIDTH};
use canter::tui::{
    Action, BoardState, BoardView, ColorMode, EvidenceKind, EvidenceRef, Focus, Freshness,
    IssueKey, Outcome, Page, RunKey, Stage, UiState, WorkRow, handle_key,
};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::Terminal;
use ratatui::backend::TestBackend;
use ratatui::buffer::Buffer;
use ratatui::style::Color;

const WIDE: (u16, u16) = (120, 32);
const NARROW: (u16, u16) = (72, 28);

// ---------------------------------------------------------------------------
// Fixtures (synthetic identities only)
// ---------------------------------------------------------------------------

fn issue(repository: &str, number: u64) -> IssueKey {
    IssueKey {
        repository: repository.to_string(),
        issue: number,
    }
}

fn run(id: &str, attempt: Option<u32>) -> RunKey {
    RunKey {
        run: id.to_string(),
        attempt,
    }
}

fn fresh(age_secs: u64) -> Freshness {
    Freshness {
        age_secs,
        stale: false,
        complete: true,
    }
}

#[allow(clippy::too_many_arguments)]
fn row(
    repository: &str,
    number: u64,
    attempt: Option<u32>,
    title: Option<&str>,
    stage: Stage,
    owner: Option<&str>,
    reason: Option<&str>,
    next_action: Option<&str>,
    human_gate: Option<&str>,
    evidence: Vec<EvidenceRef>,
    outcome: Outcome,
) -> WorkRow {
    WorkRow {
        issue: issue(repository, number),
        run: attempt.map(|attempt| run("run-fixture", Some(attempt))),
        title: title.map(str::to_string),
        stage,
        owner: owner.map(str::to_string),
        reason: reason.map(str::to_string),
        next_action: next_action.map(str::to_string),
        human_gate: human_gate.map(str::to_string),
        evidence,
        outcome,
        freshness: fresh(12),
    }
}

fn evidence(kind: EvidenceKind, label: &str) -> EvidenceRef {
    EvidenceRef {
        kind,
        label: label.to_string(),
    }
}

/// One work item in each interesting stage, across the four board groups.
fn rich_rows() -> Vec<WorkRow> {
    vec![
        row(
            "acme/widgets",
            41,
            None,
            Some("Preserve query filters on return"),
            Stage::Ready,
            None,
            Some("Scoped and eligible for bounded checkout."),
            Some("Preview selected work"),
            None,
            vec![evidence(EvidenceKind::Review, "spec revision validated")],
            Outcome::InProgress,
        ),
        row(
            "northwind/api",
            42,
            None,
            Some("Keep selection after source refresh"),
            Stage::DependencyHold,
            None,
            Some("Depends on #41; dependency not yet verified."),
            Some("Wait for #41; do not add other work"),
            None,
            vec![evidence(EvidenceKind::Review, "dependency snapshot")],
            Outcome::InProgress,
        ),
        row(
            "acme/widgets",
            43,
            Some(2),
            Some("Expose the last verified checkpoint"),
            Stage::Implementing,
            Some("lane-alpha"),
            Some("Already owned by run-fixture attempt 2."),
            Some("Inspect current attempt"),
            None,
            Vec::new(),
            Outcome::InProgress,
        ),
        row(
            "globex/edge",
            44,
            Some(1),
            Some("Label partial source evidence"),
            Stage::Review,
            Some("lane-beta"),
            Some("Independent review of exact head pending."),
            Some("Wait for reviewer verdict"),
            None,
            vec![evidence(
                EvidenceKind::Review,
                "review request at head demo4",
            )],
            Outcome::InProgress,
        ),
        row(
            "acme/widgets",
            45,
            Some(1),
            Some("Explain a blocked admission"),
            Stage::FixesRequested,
            Some("lane-alpha"),
            Some("Reviewer found an unknown-as-ready label."),
            Some("Correct label; request a fresh review"),
            None,
            vec![evidence(EvidenceKind::Review, "round 2 FAIL at demo5")],
            Outcome::InProgress,
        ),
        row(
            "northwind/api",
            46,
            Some(1),
            Some("Retain evidence through reconnect"),
            Stage::CiWaiting,
            Some("ci-runner"),
            Some("Required checks queued at reviewed head."),
            Some("Wait for exact-head checks"),
            None,
            vec![evidence(
                EvidenceKind::Ci,
                "checks queued; not a passing result",
            )],
            Outcome::InProgress,
        ),
        row(
            "globex/edge",
            47,
            Some(1),
            Some("Bound source refresh attempts"),
            Stage::CiFailure,
            Some("lane-gamma"),
            Some("Fixture runner unavailable; no ambiguous effect."),
            Some("Review one diagnosed retry"),
            None,
            vec![evidence(
                EvidenceKind::Ci,
                "job demo7 infrastructure timeout",
            )],
            Outcome::InProgress,
        ),
        row(
            "acme/widgets",
            48,
            Some(3),
            Some("Clarify completion evidence"),
            Stage::WorkerReportedDone,
            Some("reconciler"),
            Some("Worker report received; merge readback absent."),
            Some("Reconcile external evidence"),
            None,
            vec![evidence(
                EvidenceKind::Review,
                "report only; delivery unverified",
            )],
            Outcome::ReportedDone,
        ),
        row(
            "northwind/api",
            49,
            Some(1),
            Some("Keep issue and attempt identities separate"),
            Stage::VerifiedMerge,
            Some("reconciler"),
            Some("Exact merge commit read back on staging."),
            Some("No action needed for staging delivery"),
            None,
            vec![evidence(
                EvidenceKind::Gate,
                "external merge demo9 verified",
            )],
            Outcome::VerifiedDelivery,
        ),
        row(
            "globex/edge",
            50,
            None,
            Some("Promote the reviewed release candidate"),
            Stage::HumanOnlyGate,
            Some("authorized-human"),
            Some("Production promotion requires fresh local approval."),
            Some("Use the supported local approval path"),
            Some("fresh local approval"),
            vec![evidence(EvidenceKind::Gate, "remote approval unavailable")],
            Outcome::InProgress,
        ),
        row(
            "acme/widgets",
            51,
            None,
            Some("Complete the release workflow"),
            Stage::UnsupportedStep,
            Some("operator"),
            Some("Release binding unresolved; outline is not executable."),
            Some("Wait for separately routed capability"),
            None,
            vec![evidence(
                EvidenceKind::Review,
                "outline only; no execution plan",
            )],
            Outcome::InProgress,
        ),
    ]
}

fn view_with(rows: Vec<WorkRow>, state: BoardState) -> BoardView {
    let total_rows = rows.len() as u64;
    BoardView {
        source: "fixture-feed".to_string(),
        synthetic: true,
        state,
        state_note: None,
        rows,
        page: Page {
            current: 1,
            count: Some(1),
            total_rows: Some(total_rows),
            rows_before: 0,
        },
        freshness: fresh(12),
    }
}

fn rich_view() -> BoardView {
    view_with(rich_rows(), BoardState::Ready)
}

fn state_selected_on(repository: &str, number: u64, attempt: Option<u32>) -> UiState {
    UiState {
        selected: Some(canter::tui::Selection {
            issue: issue(repository, number),
            run: attempt.map(|attempt| run("run-fixture", Some(attempt))),
        }),
        focus: Focus::Rows,
    }
}

// ---------------------------------------------------------------------------
// Render helpers
// ---------------------------------------------------------------------------

fn draw_view(
    view: &BoardView,
    state: &UiState,
    mode: ColorMode,
    size: (u16, u16),
) -> Terminal<TestBackend> {
    let mut terminal = Terminal::new(TestBackend::new(size.0, size.1)).expect("test terminal");
    terminal
        .draw(|frame| board::draw(view, state, mode, frame))
        .expect("draw");
    terminal
}

fn buffer_of(terminal: &Terminal<TestBackend>) -> &Buffer {
    terminal.backend().buffer()
}

fn screen_lines(buffer: &Buffer) -> Vec<String> {
    let area = *buffer.area();
    (0..area.height)
        .map(|y| {
            let line: String = (0..area.width)
                .map(|x| buffer[(x, y)].symbol().to_string())
                .collect();
            line.trim_end().to_string()
        })
        .collect()
}

fn text_of(buffer: &Buffer) -> String {
    screen_lines(buffer).join("\n")
}

// ---------------------------------------------------------------------------
// States: loading, empty, stale, offline, no access
// ---------------------------------------------------------------------------

#[test]
fn loading_state_renders_the_exact_notice() {
    let mut view = rich_view();
    view.state = BoardState::Loading;
    view.rows.clear();
    view.freshness = fresh(0);
    let terminal = draw_view(&view, &UiState::default(), ColorMode::Ansi, WIDE);
    let lines = screen_lines(buffer_of(&terminal));
    assert_eq!(
        lines[3], "Loading board data from fixture-feed (no rows yet)",
        "loading notice must be exact"
    );
    assert!(lines[0].contains("Canter operator board"));
    assert!(lines[1].contains("source: fixture-feed"));
    // No ghost rows while loading.
    assert!(!text_of(buffer_of(&terminal)).contains("#41"));
}

#[test]
fn empty_state_renders_the_exact_notice() {
    let mut view = rich_view();
    view.state = BoardState::Empty;
    view.rows.clear();
    let terminal = draw_view(&view, &UiState::default(), ColorMode::Ansi, WIDE);
    let lines = screen_lines(buffer_of(&terminal));
    assert_eq!(lines[3], "no work items in view");
}

#[test]
fn stale_state_shows_last_known_rows_plus_explicit_warning() {
    let mut view = rich_view();
    view.state = BoardState::Stale;
    view.freshness = Freshness {
        age_secs: 900,
        stale: true,
        complete: false,
    };
    let terminal = draw_view(&view, &UiState::default(), ColorMode::Ansi, WIDE);
    let text = text_of(buffer_of(&terminal));
    assert!(
        text.contains("warning: source is stale; showing last known data"),
        "stale banner must be explicit"
    );
    assert!(text.contains("stale 15m"), "freshness must show the age");
    assert!(text.contains("partial"), "completeness must be explicit");
    assert!(
        text.contains("Verified merge"),
        "last known rows stay visible"
    );
    assert!(text.contains("#49 northwind/api"));
}

#[test]
fn offline_state_is_explicit_and_keeps_last_known_rows() {
    let mut view = rich_view();
    view.state = BoardState::Offline;
    let terminal = draw_view(&view, &UiState::default(), ColorMode::Ansi, WIDE);
    let text = text_of(buffer_of(&terminal));
    assert!(text.contains("warning: source is offline; showing last known data (no fresh reads)"));
    assert!(text.contains("Verified merge"));
}

#[test]
fn no_access_state_withholds_rows_and_names_the_reason() {
    let mut view = rich_view();
    view.state = BoardState::NoAccess;
    view.state_note = Some("credentials missing".to_string());
    let terminal = draw_view(&view, &UiState::default(), ColorMode::Ansi, WIDE);
    let text = text_of(buffer_of(&terminal));
    assert!(text.contains("no access to source: credentials missing; cached rows are withheld"));
    assert!(!text.contains("#43"), "cached rows must not be shown");
    assert!(!text.contains("#49"), "cached rows must not be shown");
}

// ---------------------------------------------------------------------------
// Wide board: ratified hierarchy, focus, rows
// ---------------------------------------------------------------------------

#[test]
fn wide_board_renders_four_group_columns_and_headers() {
    let view = rich_view();
    let terminal = draw_view(&view, &UiState::default(), ColorMode::Ansi, WIDE);
    let lines = screen_lines(buffer_of(&terminal));
    let text = lines.join("\n");
    assert!(lines[0].contains("Canter operator board"));
    assert!(
        lines[0].contains("[SYNTHETIC MODE]"),
        "synthetic mode is labelled"
    );
    assert!(lines[0].contains("focus: rows"));
    assert_eq!(
        lines[1], "source: fixture-feed | fresh 12s | complete | page 1/1 | 11 rows",
        "source line must be exact"
    );
    assert!(lines[2].contains("[R] reported done"));
    for header in [
        "Planned (3)",
        "In progress (3)",
        "Needs attention (4)",
        "Verified (1)",
    ] {
        assert!(text.contains(header), "group header `{header}` must render");
    }
    assert!(text.contains("#41 acme/widgets"));
    assert!(text.contains("Verified merge"));
    assert_eq!(
        lines[lines.len() - 1],
        "keys: Tab focus | Up/Down select | Left/Right group | q quit",
        "keyboard-only controls must be listed"
    );
}

#[test]
fn tab_moves_visible_keyboard_focus_between_rows_and_detail() {
    let view = rich_view();
    let mut state = state_selected_on("acme/widgets", 43, Some(2));
    let terminal = draw_view(&view, &state, ColorMode::Ansi, WIDE);
    let before = text_of(buffer_of(&terminal));
    assert!(before.contains("focus: rows"));
    assert!(before.contains("> #43 acme/widgets"), "selection is marked");

    assert_eq!(
        handle_key(
            &mut state,
            &view,
            KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE)
        ),
        Some(Action::Redraw)
    );
    assert_eq!(state.focus, Focus::Detail);
    let terminal = draw_view(&view, &state, ColorMode::Ansi, WIDE);
    let after = text_of(buffer_of(&terminal));
    assert!(after.contains("focus: detail"));
    assert!(
        after.contains("> #43 acme/widgets"),
        "selection survives focus change"
    );
    assert!(after.contains("selected: acme/widgets#43"));
}

#[test]
fn blockers_and_human_gates_render_markers() {
    let view = rich_view();
    let state = state_selected_on("globex/edge", 50, None);
    let terminal = draw_view(&view, &state, ColorMode::Ansi, WIDE);
    let text = text_of(buffer_of(&terminal));
    assert!(text.contains("[!]"), "blocked marker must render");
    assert!(text.contains("[G]"), "human gate marker must render");
    assert!(text.contains("gate: fresh local approval"));
}

// ---------------------------------------------------------------------------
// Narrow single-group view
// ---------------------------------------------------------------------------

#[test]
fn narrow_view_shows_one_group_with_exact_row_line() {
    let view = rich_view();
    let state = state_selected_on("acme/widgets", 43, Some(2));
    let terminal = draw_view(&view, &state, ColorMode::Ansi, NARROW);
    let lines = screen_lines(buffer_of(&terminal));
    let text = lines.join("\n");
    assert!(lines[0].contains("Canter operator board"));
    assert!(lines[0].contains("[SYNTHETIC MODE]"));
    assert!(text.contains("group: In progress (2/4)"));
    assert!(text.contains("focus: rows"));
    assert_eq!(
        lines[4], "> #43 acme/widgets | Implementing | attempt 2 | lane-alpha [!]",
        "the selected row line must be exact"
    );
    // Single group only: no rows from other groups.
    assert!(!text.contains("#41"), "planned rows must not render");
    assert!(!text.contains("#49"), "verified rows must not render");
    // Detail for the selected attempt is visible.
    assert!(text.contains("selected: acme/widgets#43"));
    assert!(text.contains("| attempt: 2"));
    assert!(text.contains("owner: lane-alpha"));
}

#[test]
fn narrow_left_right_switch_groups_and_up_down_move_within_rows() {
    let view = rich_view();
    let mut state = state_selected_on("acme/widgets", 43, Some(2));

    handle_key(
        &mut state,
        &view,
        KeyEvent::new(KeyCode::Down, KeyModifiers::NONE),
    );
    let terminal = draw_view(&view, &state, ColorMode::Ansi, NARROW);
    assert!(text_of(buffer_of(&terminal)).contains("> #44 globex/edge"));

    handle_key(
        &mut state,
        &view,
        KeyEvent::new(KeyCode::Right, KeyModifiers::NONE),
    );
    let terminal = draw_view(&view, &state, ColorMode::Ansi, NARROW);
    let text = text_of(buffer_of(&terminal));
    assert!(text.contains("group: Needs attention (3/4)"));
    assert!(
        text.contains("> #45 acme/widgets"),
        "Right jumps to the next group"
    );

    handle_key(
        &mut state,
        &view,
        KeyEvent::new(KeyCode::Left, KeyModifiers::NONE),
    );
    let terminal = draw_view(&view, &state, ColorMode::Ansi, NARROW);
    assert!(text_of(buffer_of(&terminal)).contains("group: In progress (2/4)"));
}

#[test]
fn too_small_terminal_renders_the_explicit_state() {
    let view = rich_view();
    let terminal = draw_view(&view, &UiState::default(), ColorMode::Ansi, (30, 8));
    let lines = screen_lines(buffer_of(&terminal));
    assert_eq!(lines[0], "terminal too small");
    assert_eq!(lines[1], "need >=34x9, have 30x8");
    assert!(
        lines[2..].iter().all(|line| line.trim().is_empty()),
        "nothing else renders below the minimum size"
    );
    // The minimum size itself renders normally.
    let terminal = draw_view(
        &view,
        &UiState::default(),
        ColorMode::Ansi,
        (MIN_WIDTH, MIN_HEIGHT),
    );
    assert!(screen_lines(buffer_of(&terminal))[0].contains("Canter operator board"));
}

// ---------------------------------------------------------------------------
// Selection identity: attempts, refresh, resize
// ---------------------------------------------------------------------------

#[test]
fn multiple_attempts_under_one_issue_stay_separate() {
    let rows = vec![
        row(
            "acme/widgets",
            77,
            Some(1),
            Some("First attempt"),
            Stage::FixesRequested,
            Some("lane-alpha"),
            Some("Reviewer found an unknown-as-ready label."),
            Some("Correct label; request a fresh review"),
            None,
            Vec::new(),
            Outcome::InProgress,
        ),
        row(
            "acme/widgets",
            77,
            Some(2),
            Some("Second attempt"),
            Stage::Implementing,
            Some("lane-beta"),
            Some("Fresh attempt after the fix."),
            Some("Inspect current attempt"),
            None,
            Vec::new(),
            Outcome::InProgress,
        ),
    ];
    let view = view_with(rows, BoardState::Ready);
    let state = state_selected_on("acme/widgets", 77, Some(2));
    assert_eq!(
        state.selected_index(&view),
        Some(1),
        "attempt 2 is the selected row"
    );
    let terminal = draw_view(&view, &state, ColorMode::Ansi, WIDE);
    let text = text_of(buffer_of(&terminal));
    assert_eq!(
        text.matches("#77 acme/widgets").count(),
        2,
        "both attempts must render as separate rows"
    );
    assert!(text.contains("> #77 acme/widgets"));
    assert!(text.contains("| attempt: 2"), "selection is attempt 2");
    assert!(text.contains("owner: lane-beta"));
}

#[test]
fn refresh_keeps_the_selected_issue_when_rows_reorder() {
    let rows = rich_rows();
    let first = view_with(rows.clone(), BoardState::Ready);
    let state = state_selected_on("acme/widgets", 43, Some(2));
    assert_eq!(state.selected_index(&first), Some(2));

    // Simulated refresh: same identities, different order.
    let mut reordered = rows;
    reordered.swap(1, 2);
    let refreshed = view_with(reordered, BoardState::Ready);
    assert_ne!(
        refreshed.rows[0].issue,
        issue("acme/widgets", 43),
        "row order really changed"
    );
    assert_eq!(
        state.selected_index(&refreshed),
        Some(1),
        "selection follows the identity, not the index"
    );

    let terminal = draw_view(&refreshed, &state, ColorMode::Ansi, WIDE);
    let text = text_of(buffer_of(&terminal));
    assert!(
        text.contains("> #43 acme/widgets"),
        "selected marker follows the issue"
    );
    assert!(
        !text.contains("> #41 acme/widgets"),
        "the first row must not grab selection"
    );
    assert!(text.contains("selected: acme/widgets#43"));
    assert!(text.contains("| attempt: 2"));
}

#[test]
fn selection_survives_resize_between_wide_and_narrow() {
    let view = rich_view();
    let state = state_selected_on("northwind/api", 49, Some(1));
    let wide = draw_view(&view, &state, ColorMode::Ansi, WIDE);
    let narrow = draw_view(&view, &state, ColorMode::Ansi, NARROW);
    assert!(text_of(buffer_of(&wide)).contains("> #49 northwind/api"));
    let narrow_text = text_of(buffer_of(&narrow));
    assert!(
        narrow_text.contains("group: Verified (4/4)"),
        "freeze: selected group shown"
    );
    assert!(narrow_text.contains("> #49 northwind/api"));
}

#[test]
fn selection_that_left_the_view_is_stated_not_silently_moved() {
    let view = rich_view();
    let state = state_selected_on("example-org/absent", 999, None);
    assert_eq!(state.selected_index(&view), None);
    let terminal = draw_view(&view, &state, ColorMode::Ansi, WIDE);
    let text = text_of(buffer_of(&terminal));
    assert!(
        text.contains("selected example-org/absent#999 is retained but no longer in this view")
    );
    assert!(
        !text.contains("> #41"),
        "no other row may take the selection"
    );
    assert!(
        !text.contains("no selection"),
        "the retention notice replaces the empty-selection notice"
    );
}

// ---------------------------------------------------------------------------
// Accessibility: colour policy, monochrome fallback, synthetic label
// ---------------------------------------------------------------------------

#[test]
fn monochrome_fallback_has_no_colour_and_identical_text() {
    let view = rich_view();
    let state = state_selected_on("acme/widgets", 48, Some(3));
    let ansi = draw_view(&view, &state, ColorMode::Ansi, WIDE);
    let mono = draw_view(&view, &state, ColorMode::Mono, WIDE);

    assert_eq!(
        screen_lines(buffer_of(&ansi)),
        screen_lines(buffer_of(&mono)),
        "monochrome must keep identical text"
    );

    let mut ansi_coloured = 0_usize;
    for cell in buffer_of(&ansi).content() {
        if cell.fg != Color::Reset {
            ansi_coloured += 1;
        }
    }
    assert!(
        ansi_coloured > 0,
        "the ANSI palette must actually colour something"
    );

    for cell in buffer_of(&mono).content() {
        assert_eq!(
            cell.fg,
            Color::Reset,
            "monochrome must not set a foreground colour"
        );
        assert_eq!(
            cell.bg,
            Color::Reset,
            "monochrome must not set a background colour"
        );
    }
}

#[test]
fn ansi_palette_avoids_forced_green_and_background_colours() {
    let view = rich_view();
    let terminal = draw_view(
        &view,
        &state_selected_on("acme/widgets", 48, Some(3)),
        ColorMode::Ansi,
        WIDE,
    );
    for cell in buffer_of(&terminal).content() {
        assert_ne!(cell.fg, Color::Green, "forced green is banned");
        assert_ne!(cell.bg, Color::Green, "forced green is banned");
        assert_eq!(cell.bg, Color::Reset, "no fixed background colours");
        assert!(
            matches!(
                cell.fg,
                Color::Reset | Color::Cyan | Color::Yellow | Color::Red
            ),
            "unexpected foreground colour: {:?}",
            cell.fg
        );
    }
}

#[test]
fn synthetic_mode_is_labelled_and_absent_when_not_synthetic() {
    let mut view = rich_view();
    view.synthetic = true;
    let terminal = draw_view(&view, &UiState::default(), ColorMode::Ansi, NARROW);
    assert!(text_of(buffer_of(&terminal)).contains("[SYNTHETIC MODE]"));

    view.synthetic = false;
    let terminal = draw_view(&view, &UiState::default(), ColorMode::Ansi, NARROW);
    assert!(
        !text_of(buffer_of(&terminal)).contains("SYNTHETIC"),
        "the label must be absent when not in synthetic mode"
    );

    view.synthetic = true;
    let terminal = draw_view(&view, &UiState::default(), ColorMode::Mono, NARROW);
    assert!(
        text_of(buffer_of(&terminal)).contains("[SYNTHETIC MODE]"),
        "the monochrome fallback must keep the label"
    );
}

// ---------------------------------------------------------------------------
// Bounded content and no fabricated metrics
// ---------------------------------------------------------------------------

#[test]
fn long_content_is_truncated_explicitly_and_controls_are_neutralized() {
    let mut hostile_title = "Very long work-item summary ".repeat(40);
    hostile_title.push_str("\u{1b}[31mRAW\u{1b}[0m\nsecond line\tend");
    let rows = vec![row(
        "acme/widgets",
        88,
        Some(1),
        Some(&hostile_title),
        Stage::Implementing,
        Some("lane-alpha"),
        Some(&"a very long blocker explanation ".repeat(60)),
        Some("the single next action"),
        None,
        Vec::new(),
        Outcome::InProgress,
    )];
    let view = view_with(rows, BoardState::Ready);
    let state = state_selected_on("acme/widgets", 88, Some(1));
    let terminal = draw_view(&view, &state, ColorMode::Ansi, WIDE);
    let buffer = buffer_of(&terminal);
    let text = text_of(buffer);

    assert!(
        text.contains('…'),
        "truncation must use the explicit marker"
    );
    for cell in buffer.content() {
        let symbol = cell.symbol();
        assert!(
            !symbol.chars().any(char::is_control),
            "no control character may reach a terminal cell"
        );
    }
    assert!(
        text.contains("reason: a very long blocker"),
        "reason still shows its start"
    );
}

#[test]
fn render_contains_no_fabricated_metrics() {
    let view = rich_view();
    let terminal = draw_view(
        &view,
        &state_selected_on("acme/widgets", 48, Some(3)),
        ColorMode::Ansi,
        WIDE,
    );
    let text = text_of(buffer_of(&terminal));
    assert!(!text.contains('%'), "no fabricated percentage may render");
    for glyph in ['█', '▓', '▒', '░'] {
        assert!(
            !text.contains(glyph),
            "no fabricated progress bar may render"
        );
    }
}

#[test]
fn evidence_references_are_bounded_with_a_more_marker() {
    let rows = vec![row(
        "acme/widgets",
        91,
        Some(1),
        None,
        Stage::Review,
        Some("lane-alpha"),
        Some("awaiting review"),
        Some("wait"),
        None,
        vec![
            evidence(EvidenceKind::Review, "ev-1"),
            evidence(EvidenceKind::Ci, "ev-2"),
            evidence(EvidenceKind::Gate, "ev-3"),
            evidence(EvidenceKind::Review, "ev-4"),
            evidence(EvidenceKind::Ci, "ev-5"),
        ],
        Outcome::InProgress,
    )];
    let view = view_with(rows, BoardState::Ready);
    let state = state_selected_on("acme/widgets", 91, Some(1));
    let terminal = draw_view(&view, &state, ColorMode::Ansi, WIDE);
    let text = text_of(buffer_of(&terminal));
    assert!(
        text.contains("evidence: review ev-1, ci ev-2, gate ev-3 (+2 more)"),
        "evidence must be bounded with an explicit remainder"
    );
}

// ---------------------------------------------------------------------------
// Verified delivery vs reported done
// ---------------------------------------------------------------------------

#[test]
fn verified_delivery_and_reported_done_are_different_states() {
    let view = rich_view();

    let reported = draw_view(
        &view,
        &state_selected_on("acme/widgets", 48, Some(3)),
        ColorMode::Ansi,
        WIDE,
    );
    let text = text_of(buffer_of(&reported));
    assert!(text.contains("outcome: reported done (unverified)"));
    assert!(text.contains("[R]"));

    let verified = draw_view(
        &view,
        &state_selected_on("northwind/api", 49, Some(1)),
        ColorMode::Ansi,
        WIDE,
    );
    let text = text_of(buffer_of(&verified));
    assert!(text.contains("outcome: verified delivery"));
    assert!(text.contains("[V]"));
    assert!(!text.contains("reported done (unverified)"));
}

// ---------------------------------------------------------------------------
// Keyboard-only controls
// ---------------------------------------------------------------------------

#[test]
fn keyboard_controls_are_keyboard_only() {
    let view = rich_view();
    let mut state = UiState::default();

    assert_eq!(
        handle_key(
            &mut state,
            &view,
            KeyEvent::new(KeyCode::Down, KeyModifiers::NONE)
        ),
        Some(Action::Redraw)
    );
    assert_eq!(state.selected_index(&view), Some(0));
    assert_eq!(state.focus, Focus::Rows);

    handle_key(
        &mut state,
        &view,
        KeyEvent::new(KeyCode::Char('j'), KeyModifiers::NONE),
    );
    assert_eq!(state.selected_index(&view), Some(1));
    handle_key(
        &mut state,
        &view,
        KeyEvent::new(KeyCode::Char('k'), KeyModifiers::NONE),
    );
    assert_eq!(state.selected_index(&view), Some(0));

    handle_key(
        &mut state,
        &view,
        KeyEvent::new(KeyCode::Up, KeyModifiers::NONE),
    );
    assert_eq!(
        state.selected_index(&view),
        Some(0),
        "Up clamps at the first row"
    );

    handle_key(
        &mut state,
        &view,
        KeyEvent::new(KeyCode::BackTab, KeyModifiers::NONE),
    );
    assert_eq!(state.focus, Focus::Detail, "BackTab also cycles focus");

    let untouched = state.clone();
    assert_eq!(
        handle_key(
            &mut state,
            &view,
            KeyEvent::new(KeyCode::Char('x'), KeyModifiers::NONE)
        ),
        None,
        "unknown keys are ignored"
    );
    assert_eq!(state, untouched);

    assert_eq!(
        handle_key(
            &mut state,
            &view,
            KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE)
        ),
        Some(Action::Quit)
    );
    assert_eq!(
        handle_key(
            &mut state,
            &view,
            KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)
        ),
        Some(Action::Quit)
    );
}

// ---------------------------------------------------------------------------
// Captured render evidence (run with --nocapture for the raw output)
// ---------------------------------------------------------------------------

#[test]
fn render_evidence_dump() {
    let view = rich_view();
    let state = state_selected_on("acme/widgets", 48, Some(3));

    for (label, mode, size) in [
        ("wide-ansi", ColorMode::Ansi, WIDE),
        ("wide-mono", ColorMode::Mono, WIDE),
        ("narrow-ansi", ColorMode::Ansi, NARROW),
    ] {
        let terminal = draw_view(&view, &state, mode, size);
        let buffer = buffer_of(&terminal);
        println!("=== {label} ({}x{}) ===", size.0, size.1);
        for line in screen_lines(buffer) {
            println!("|{line}|");
        }
        let mut colors: Vec<String> = Vec::new();
        for cell in buffer.content() {
            let name = format!("{:?}", cell.fg);
            if cell.fg != Color::Reset && !colors.contains(&name) {
                colors.push(name);
            }
        }
        println!("coloured cells: fg colours used = {colors:?}");
        println!();
    }
    assert!(WIDE.0 >= WIDE_MIN_WIDTH);
}
