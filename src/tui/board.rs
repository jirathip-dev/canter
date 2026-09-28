//! Board rendering: wide four-group board, narrow single-group view, and the
//! explicit too-small state.
//!
//! Everything displayed comes from [`crate::tui::BoardView`] through the
//! selection in [`crate::tui::UiState`]. Text that originates in the read
//! model is bounded and control-character-filtered (see the tui module's
//! `clip` helper) before it reaches a cell, so no raw terminal content
//! (escape sequences, unbounded logs) can be displayed by default.

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::Paragraph;

use super::{BoardState, BoardView, ColorMode, Focus, StageGroup, UiState, WorkRow, clip};

/// Minimum usable surface; below this the explicit too-small state renders.
pub const MIN_WIDTH: u16 = 34;
/// Minimum usable surface height.
pub const MIN_HEIGHT: u16 = 9;
/// At and above this width the four-group board renders; below it the
/// narrow single-group view renders.
pub const WIDE_MIN_WIDTH: u16 = 80;

/// How many evidence references the detail shows before summarizing the rest.
const EVIDENCE_SHOWN: usize = 3;

#[derive(Clone, Copy)]
struct Palette {
    title: Style,
    group: Style,
    accent: Style,
    warn: Style,
    alert: Style,
    muted: Style,
    selected: Style,
}

impl Palette {
    fn for_mode(mode: ColorMode) -> Self {
        let base = Self {
            title: Style::default().add_modifier(Modifier::BOLD),
            group: Style::default().add_modifier(Modifier::BOLD),
            accent: Style::default(),
            warn: Style::default().add_modifier(Modifier::BOLD),
            alert: Style::default().add_modifier(Modifier::BOLD),
            muted: Style::default().add_modifier(Modifier::DIM),
            selected: Style::default().add_modifier(Modifier::REVERSED),
        };
        match mode {
            ColorMode::Mono => base,
            ColorMode::Ansi => Self {
                group: Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
                accent: Style::default().fg(Color::Cyan),
                warn: Style::default().fg(Color::Yellow),
                alert: Style::default().fg(Color::Red),
                ..base
            },
        }
    }
}

/// Render the surface into the frame's full area.
pub fn draw(view: &BoardView, state: &UiState, mode: ColorMode, frame: &mut ratatui::Frame) {
    draw_in(frame.area(), view, state, mode, frame);
}

/// Render the surface into `area` instead of the whole frame.
///
/// Every rect the board lays out is confined to `area`, so a caller that
/// draws lines of its own (the operator console's supervision strip, issue
/// #340) reserves the rows it needs and passes the remainder here: one row
/// then carries exactly one logical line, and no widget can overprint
/// another's row.
pub fn draw_in(
    area: Rect,
    view: &BoardView,
    state: &UiState,
    mode: ColorMode,
    frame: &mut ratatui::Frame,
) {
    if area.width < MIN_WIDTH || area.height < MIN_HEIGHT {
        draw_too_small(area, frame);
        return;
    }
    let palette = Palette::for_mode(mode);
    if area.width >= WIDE_MIN_WIDTH {
        draw_wide(view, state, &palette, area, frame);
    } else {
        draw_narrow(view, state, &palette, area, frame);
    }
}

fn draw_too_small(area: Rect, frame: &mut ratatui::Frame) {
    let text = Text::from(vec![
        Line::from("terminal too small"),
        Line::from(format!(
            "need >={}x{}, have {}x{}",
            MIN_WIDTH, MIN_HEIGHT, area.width, area.height
        )),
    ]);
    frame.render_widget(Paragraph::new(text), area);
}

fn draw_wide(
    view: &BoardView,
    state: &UiState,
    palette: &Palette,
    area: Rect,
    frame: &mut ratatui::Frame,
) {
    let notices = notice_lines(view, palette);
    let [head, notice_area, board, detail_area, footer] = Layout::vertical([
        Constraint::Length(3),
        Constraint::Length(notices.len() as u16),
        Constraint::Min(4),
        Constraint::Length(4),
        Constraint::Length(1),
    ])
    .areas(area);

    let head_text = Text::from(vec![
        header_line(view, state, palette, true),
        source_line(view, palette),
        legend_line(palette),
    ]);
    frame.render_widget(Paragraph::new(head_text), head);
    frame.render_widget(Paragraph::new(Text::from(notices)), notice_area);

    let side = Layout::horizontal([Constraint::Ratio(1, 4); 4]).areas::<4>(board);
    for (index, group) in StageGroup::ALL.into_iter().enumerate() {
        render_group_column(view, state, palette, group, side[index], frame);
    }

    let detail = detail_lines(view, state, palette, area.width as usize);
    frame.render_widget(Paragraph::new(Text::from(detail)), detail_area);
    frame.render_widget(Paragraph::new(footer_line(palette)), footer);
}

fn draw_narrow(
    view: &BoardView,
    state: &UiState,
    palette: &Palette,
    area: Rect,
    frame: &mut ratatui::Frame,
) {
    let notices = notice_lines(view, palette);
    let [head, notice_area, body, footer] = Layout::vertical([
        Constraint::Length(4),
        Constraint::Length(notices.len() as u16),
        Constraint::Min(3),
        Constraint::Length(1),
    ])
    .areas(area);

    let head_text = Text::from(vec![
        header_line(view, state, palette, false),
        source_line(view, palette),
        legend_line(palette),
        group_line(view, state, palette),
    ]);
    frame.render_widget(Paragraph::new(head_text), head);
    frame.render_widget(Paragraph::new(Text::from(notices)), notice_area);

    let mut lines: Vec<Line<'static>> = Vec::new();
    if rows_visible(view) {
        if let Some(group) = current_group(view, state) {
            for row in view.rows.iter().filter(|row| row.stage.group() == group) {
                lines.push(narrow_row_line(row, state, palette, area.width as usize));
            }
        }
        if !lines.is_empty() {
            lines.push(Line::from(String::new()));
        }
        lines.extend(detail_lines(view, state, palette, area.width as usize));
    }
    frame.render_widget(Paragraph::new(Text::from(lines)), body);
    frame.render_widget(Paragraph::new(footer_line(palette)), footer);
}

fn header_line(
    view: &BoardView,
    state: &UiState,
    palette: &Palette,
    with_focus: bool,
) -> Line<'static> {
    let mut spans = vec![Span::styled("Canter operator board", palette.title)];
    if view.synthetic {
        spans.push(Span::raw(" "));
        spans.push(Span::styled("[SYNTHETIC MODE]", palette.warn));
    }
    if with_focus {
        spans.push(Span::raw(" "));
        spans.push(Span::styled(
            format!("| focus: {}", focus_label(state.focus)),
            palette.muted,
        ));
    }
    Line::from(spans)
}

fn source_line(view: &BoardView, palette: &Palette) -> Line<'static> {
    let freshness = view.freshness.label();
    let freshness_style = if view.freshness.stale {
        palette.warn
    } else {
        palette.accent
    };
    // Unknown totals (a bounded read that reported more rows) are stated as
    // unknown, never filled in with a guess.
    let page = match view.page.count {
        Some(count) => format!("page {}/{}", view.page.current, count),
        None => format!("page {}/?", view.page.current),
    };
    let rows = match view.page.total_rows {
        Some(total) => format!("{total} rows"),
        None => format!("{}+ rows", view.rows.len()),
    };
    Line::from(vec![
        Span::styled("source: ", palette.muted),
        Span::raw(clip(&view.source, 64)),
        Span::raw(" | "),
        Span::styled(freshness, freshness_style),
        Span::raw(" | "),
        Span::raw(view.freshness.completeness_label()),
        Span::raw(" | "),
        Span::raw(page),
        Span::raw(" | "),
        Span::raw(rows),
    ])
}

fn legend_line(palette: &Palette) -> Line<'static> {
    Line::styled(
        "markers: [R] reported done | [V] verified delivery | [!] blocked | [G] human gate",
        palette.muted,
    )
}

fn footer_line(palette: &Palette) -> Line<'static> {
    Line::styled(
        "keys: Tab focus | Up/Down select | Left/Right group | q quit",
        palette.muted,
    )
}

fn group_line(view: &BoardView, state: &UiState, palette: &Palette) -> Line<'static> {
    let group = current_group(view, state).unwrap_or(StageGroup::Planned);
    let index = StageGroup::ALL
        .iter()
        .position(|candidate| *candidate == group)
        .unwrap_or(0)
        + 1;
    Line::from(vec![
        Span::styled("group: ", palette.muted),
        Span::styled(group.label(), palette.group),
        Span::raw(format!(" ({index}/4)")),
        Span::styled(
            format!(" | focus: {}", focus_label(state.focus)),
            palette.muted,
        ),
    ])
}

fn focus_label(focus: Focus) -> &'static str {
    match focus {
        Focus::Rows => "rows",
        Focus::Detail => "detail",
    }
}

fn rows_visible(view: &BoardView) -> bool {
    !matches!(
        view.state,
        BoardState::Loading | BoardState::Empty | BoardState::NoAccess
    )
}

fn notice_lines(view: &BoardView, palette: &Palette) -> Vec<Line<'static>> {
    match view.state {
        BoardState::Ready => Vec::new(),
        BoardState::Loading => vec![Line::raw(format!(
            "Loading board data from {} (no rows yet)",
            clip(&view.source, 64)
        ))],
        BoardState::Empty => vec![Line::raw("no work items in view")],
        BoardState::Stale => vec![Line::styled(
            "warning: source is stale; showing last known data",
            palette.warn,
        )],
        BoardState::Offline => vec![Line::styled(
            match view.state_note.as_deref() {
                Some(note) => format!(
                    "warning: source is offline; showing last known data (no fresh reads): {}",
                    clip(note, 64)
                ),
                None => "warning: source is offline; showing last known data (no fresh reads)"
                    .to_string(),
            },
            palette.alert,
        )],
        BoardState::NoAccess => vec![Line::styled(
            format!(
                "no access to source: {}; cached rows are withheld",
                clip(view.state_note.as_deref().unwrap_or("not authorized"), 64)
            ),
            palette.alert,
        )],
    }
}

fn current_group(view: &BoardView, state: &UiState) -> Option<StageGroup> {
    if let Some(index) = state.selected_index(view) {
        return Some(view.rows[index].stage.group());
    }
    StageGroup::ALL
        .into_iter()
        .find(|group| view.rows.iter().any(|row| row.stage.group() == *group))
}

fn render_group_column(
    view: &BoardView,
    state: &UiState,
    palette: &Palette,
    group: StageGroup,
    area: Rect,
    frame: &mut ratatui::Frame,
) {
    let width = area.width as usize;
    let rows: Vec<&WorkRow> = view
        .rows
        .iter()
        .filter(|row| row.stage.group() == group)
        .collect();
    let mut lines = vec![Line::styled(
        clip(&format!("{} ({})", group.label(), rows.len()), width),
        palette.group,
    )];
    if rows_visible(view) {
        for row in rows {
            let selected = state
                .selected
                .as_ref()
                .is_some_and(|selection| selection.matches_row(row));
            let marker = if selected { "> " } else { "  " };
            let identity = format!("{marker}#{} {}", row.issue.issue, row.issue.repository);
            let mut identity_line = Line::styled(clip(&identity, width), Style::default());
            let mut stage_line = wide_stage_line(row, palette, width);
            if selected {
                identity_line = identity_line.style(palette.selected);
                stage_line = stage_line.style(palette.selected);
            }
            lines.push(identity_line);
            lines.push(stage_line);
        }
    }
    frame.render_widget(Paragraph::new(Text::from(lines)), area);
}

fn wide_stage_line(row: &WorkRow, palette: &Palette, width: usize) -> Line<'static> {
    let mut text = format!("  {}", row.stage.label());
    if let Some(marker) = row.outcome.marker() {
        text.push_str(&format!(" {marker}"));
    }
    if row.reason.is_some() {
        text.push_str(" [!]");
    }
    if row.human_gate.is_some() {
        text.push_str(" [G]");
    }
    Line::styled(clip(&text, width), palette.muted)
}

fn narrow_row_line(
    row: &WorkRow,
    state: &UiState,
    palette: &Palette,
    width: usize,
) -> Line<'static> {
    let selected = state
        .selected
        .as_ref()
        .is_some_and(|selection| selection.matches_row(row));
    let marker = if selected { "> " } else { "  " };
    let mut text = format!("{marker}#{} {}", row.issue.issue, row.issue.repository);
    text.push_str(&format!(" | {}", row.stage.label()));
    if let Some(attempt) = row.run.as_ref().and_then(|run| run.attempt) {
        text.push_str(&format!(" | attempt {attempt}"));
    }
    if let Some(owner) = &row.owner {
        text.push_str(&format!(" | {}", clip(owner, 24)));
    }
    if let Some(marker) = row.outcome.marker() {
        text.push_str(&format!(" {marker}"));
    }
    if row.reason.is_some() {
        text.push_str(" [!]");
    }
    if row.human_gate.is_some() {
        text.push_str(" [G]");
    }
    let style = if selected {
        palette.selected
    } else {
        Style::default()
    };
    Line::styled(clip(&text, width), style)
}

fn detail_lines(
    view: &BoardView,
    state: &UiState,
    palette: &Palette,
    width: usize,
) -> Vec<Line<'static>> {
    if !rows_visible(view) {
        return Vec::new();
    }
    let Some(selected) = state.selected.as_ref() else {
        return vec![Line::styled(
            clip("no selection: press Up/Down to select work", width),
            palette.muted,
        )];
    };
    let Some(index) = state.selected_index(view) else {
        return vec![Line::styled(
            clip(
                &format!(
                    "selected {} is retained but no longer in this view",
                    selection_label(selected)
                ),
                width,
            ),
            palette.warn,
        )];
    };
    let row = &view.rows[index];
    let attempt = row
        .run
        .as_ref()
        .and_then(|run| run.attempt)
        .map(|attempt| attempt.to_string())
        .unwrap_or_else(|| "-".to_string());

    let head = format!(
        "selected: {} | stage: {} | attempt: {attempt}",
        selection_label(selected),
        row.stage.label()
    );

    let owner_text = clip(row.owner.as_deref().unwrap_or("unassigned"), 32);
    let mut meta = format!("owner: {owner_text} | outcome: {}", row.outcome.label());
    if let Some(title) = &row.title {
        let used = 7 + owner_text.chars().count() + 12 + row.outcome.label().chars().count() + 9;
        let title_budget = width.saturating_sub(used);
        if title_budget >= 8 {
            meta.push_str(&format!(" | title: {}", clip(title, title_budget)));
        }
    }

    let field_budget = (width.saturating_sub(31) / 3).max(12);
    let middle = format!(
        "reason: {} | next: {} | gate: {}",
        clip(row.reason.as_deref().unwrap_or("-"), field_budget),
        clip(row.next_action.as_deref().unwrap_or("-"), field_budget),
        clip(row.human_gate.as_deref().unwrap_or("none"), field_budget)
    );

    let freshness = row.freshness.label();
    let evidence_budget = width
        .saturating_sub(34 + freshness.chars().count() + 2)
        .max(16);
    let tail = format!(
        "evidence: {} | freshness: {freshness} | {}",
        clip(&evidence_summary(row), evidence_budget),
        row.freshness.completeness_label()
    );

    vec![
        Line::styled(clip(&head, width), Style::default()),
        Line::styled(clip(&meta, width), Style::default()),
        Line::styled(clip(&middle, width), Style::default()),
        Line::styled(clip(&tail, width), palette.muted),
    ]
}

fn selection_label(selection: &super::Selection) -> String {
    let mut label = selection.issue.label();
    if let Some(attempt) = selection.run.as_ref().and_then(|run| run.attempt) {
        label.push_str(&format!(" (attempt {attempt})"));
    }
    label
}

fn evidence_summary(row: &WorkRow) -> String {
    if row.evidence.is_empty() {
        return "none".to_string();
    }
    let shown: Vec<String> = row
        .evidence
        .iter()
        .take(EVIDENCE_SHOWN)
        .map(|reference| format!("{} {}", reference.kind.label(), clip(&reference.label, 32)))
        .collect();
    let mut summary = shown.join(", ");
    let hidden = row.evidence.len().saturating_sub(EVIDENCE_SHOWN);
    if hidden > 0 {
        summary.push_str(&format!(" (+{hidden} more)"));
    }
    summary
}
