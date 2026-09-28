//! Issue #90 live wiring acceptance: the real board read model (#83) rendered
//! through the operator surface, and the real Crossterm session driven
//! through a REAL pseudo-terminal.
//!
//! Every test opens a real `canter::state::State` in a per-test temp dir and
//! reads it through `canter::board::read_board` (the authoritative bounded
//! join `State::board_page_rows`) — synthetic identities only, nothing
//! touches a live fleet, a network, or a real session. The two PTY tests
//! re-execute this test binary under a fresh pseudo-terminal (`forkpty`, the
//! crate's existing `libc` dependency; no new dependency and no host tool),
//! so the session's terminal setup, its raw-key input, and the bytes a real
//! terminal receives are exercised for real.
//!
//! Captured output is evidence, never a claim: the tests assert on the bytes
//! the terminal actually emitted.

use std::path::PathBuf;

use canter::board::{BoardQuery, read_board};
use canter::state::{Retention, State};
use canter::tui::board;
use canter::tui::live::{LiveBoard, view_of_page};
use canter::tui::{
    BoardState, BoardView, ColorMode, EvidenceKind, Focus, IssueKey, Outcome, Page, ReadModel,
    RunKey, Selection, Stage, UiState,
};
use canter::value::Val;
use ratatui::Terminal;
use ratatui::backend::TestBackend;
use ratatui::buffer::Buffer;
use ratatui::style::Color;

const REPO_A: &str = "example-org/widgets";
const REPO_B: &str = "example-org/gadgets";
const REVISION: &str = "0123456789abcdef0123456789abcdef01234567";
const WORKFLOW_HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const POLICY_HASH: &str = "feedface01234567feedface01234567feedface01234567feedface01234567";

const WIDE: (u16, u16) = (120, 32);
const NARROW: (u16, u16) = (72, 28);

// ---------------------------------------------------------------------------
// Fixtures: a real state store seeded through the public state API
// ---------------------------------------------------------------------------

/// A per-test fixture directory with its own state database.
struct Fixture {
    dir: PathBuf,
}

impl Fixture {
    fn new(name: &str) -> Fixture {
        let dir =
            std::env::temp_dir().join(format!("canter-tui-live-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("fixture dir");
        Fixture { dir }
    }

    fn db(&self) -> PathBuf {
        self.dir.join("state.db")
    }

    fn open(&self) -> State {
        State::open(&self.db(), Retention::default()).expect("open state")
    }

    /// Direct SQLite access for the seeds the public API cannot produce: a
    /// `done`/`invalidated` status (declared in the state vocabulary, written
    /// only by a later slice) and a legacy row that predates the m0002
    /// bindings. This is the same seeding form the #83 read-model suite uses.
    fn raw(&self) -> rusqlite::Connection {
        rusqlite::Connection::open(self.db()).expect("raw connection")
    }
}

/// One synthetic hf-grant/v1 document for `state_epoch`.
fn grant_doc(grant_id: &str, repository: &str, issue: i64, state_epoch: i64) -> Val {
    Val::parse_json(&format!(
        r#"{{"schema":"hf-grant/v1","grant_id":"{grant_id}","repository":"{repository}",
            "issue":{{"number":{issue},"revision":"{REVISION}"}},
            "workflow_hash":"{WORKFLOW_HASH}","policy_hash":"{POLICY_HASH}",
            "phase":"review","scope":"worktrees/issues/{issue}",
            "caps":["read","worktree","spawn","review","merge"],
            "expires_at":"2999-01-01T00:00:00Z","state_epoch":{state_epoch},
            "created_at":"2026-09-06T00:00:00Z"}}"#
    ))
    .expect("grant document parses")
}

/// Monotone per-process counter: grant ids must be unique within one epoch.
fn seed_counter() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    COUNTER.fetch_add(1, Ordering::SeqCst)
}

/// Seed one grant and one run bound to it.
fn seed_run(state: &State, repository: &str, issue: i64, run: &str) {
    let epoch = state.summary().expect("summary").0;
    let grant_id = format!("gr_{:016x}", seed_counter());
    state
        .issue_grant(&grant_doc(&grant_id, repository, issue, epoch))
        .expect("issue grant");
    state
        .start_instance(run, &grant_id, "fleet-doctrine-1", "2026-09-06T00:00:00Z")
        .expect("start instance");
}

/// Record one passing review-evidence row (all checks passed).
fn record_pass(state: &State, repository: &str, run: &str, feature_head: &str) {
    let checks =
        Val::parse_json(r#"[{"name":"exact-head-review","status":"passed"}]"#).expect("checks");
    state
        .record_evidence(
            run,
            repository,
            feature_head,
            "89abcdef0123456789abcdef0123456789abcdef",
            WORKFLOW_HASH,
            POLICY_HASH,
            "pass",
            "reviewer-example",
            &checks,
        )
        .expect("record pass evidence");
}

/// Record one failing review-evidence row.
fn record_fail(state: &State, repository: &str, run: &str) {
    let checks =
        Val::parse_json(r#"[{"name":"exact-head-review","status":"failed"}]"#).expect("checks");
    state
        .record_evidence(
            run,
            repository,
            "1111111111111111111111111111111111111111",
            "89abcdef0123456789abcdef0123456789abcdef",
            WORKFLOW_HASH,
            POLICY_HASH,
            "fail",
            "reviewer-example",
            &checks,
        )
        .expect("record fail evidence");
}

/// The live fixture board: one run per recorded run state of the read model's
/// closed set, with both verification outcomes and both human-gate actions
/// recorded. Ordered by `(repository, issue, run)` the rows are:
///
/// 0. `example-org/gadgets#5`  `run-gadgets-0005`  new         (Ready)
/// 1. `example-org/gadgets#7`  `run-gadgets-0007`  paused      (Human-only gate, resume)
/// 2. `example-org/gadgets#9`  `run-gadgets-0009`  blocked     (Blocked)
/// 3. `example-org/gadgets#11` `run-gadgets-0011`  human_queue (Human-only gate, human_decision)
/// 4. `example-org/widgets#12` `run-widgets-0001`  running + passing review (Verified merge)
/// 5. `example-org/widgets#12` `run-widgets-0002`  running + failing review (Implementing)
/// 6. `example-org/widgets#12` `run-widgets-0003`  done        (Worker-reported done)
/// 7. `example-org/widgets#12` `run-widgets-0004`  invalidated (Invalidated)
fn seed_live_board(state: &State, fixture: &Fixture) {
    seed_run(state, REPO_B, 5, "run-gadgets-0005");

    seed_run(state, REPO_B, 7, "run-gadgets-0007");
    state
        .pause_instance("run-gadgets-0007", &"a".repeat(64), "2026-09-06T00:00:01Z")
        .expect("pause");

    seed_run(state, REPO_B, 9, "run-gadgets-0009");
    state
        .advance_instance(
            "run-gadgets-0009",
            "implementer",
            0,
            0,
            false,
            2,
            "2026-09-06T00:00:02Z",
        )
        .expect("advance blocked");

    seed_run(state, REPO_B, 11, "run-gadgets-0011");
    state
        .advance_instance(
            "run-gadgets-0011",
            "reviewer",
            3,
            1,
            true,
            0,
            "2026-09-06T00:00:03Z",
        )
        .expect("advance human queue");

    seed_run(state, REPO_A, 12, "run-widgets-0001");
    state
        .advance_instance(
            "run-widgets-0001",
            "reviewer",
            0,
            0,
            false,
            0,
            "2026-09-06T00:00:04Z",
        )
        .expect("advance verified");
    record_pass(
        state,
        REPO_A,
        "run-widgets-0001",
        "2222222222222222222222222222222222222222",
    );

    seed_run(state, REPO_A, 12, "run-widgets-0002");
    state
        .advance_instance(
            "run-widgets-0002",
            "implementer",
            0,
            0,
            false,
            0,
            "2026-09-06T00:00:05Z",
        )
        .expect("advance failing review");
    record_fail(state, REPO_A, "run-widgets-0002");

    // Two statuses the public API cannot write yet (declared in the state
    // vocabulary, written by a later slice): seeded directly, as the #83
    // read-model suite does.
    seed_run(state, REPO_A, 12, "run-widgets-0003");
    seed_run(state, REPO_A, 12, "run-widgets-0004");
    let conn = fixture.raw();
    conn.execute(
        "UPDATE instances SET status = 'done', current_node = 'merge', updated_at = ?2
          WHERE instance_id = ?1",
        rusqlite::params!["run-widgets-0003", "2026-09-06T00:00:06Z"],
    )
    .expect("seed reported done");
    conn.execute(
        "UPDATE instances SET status = 'invalidated', updated_at = ?2
          WHERE instance_id = ?1",
        rusqlite::params!["run-widgets-0004", "2026-09-06T00:00:07Z"],
    )
    .expect("seed invalidated");
    drop(conn);
}

/// One recorded page, read through the real read model.
fn real_page(state: &State) -> canter::board::BoardPage {
    let query = BoardQuery::new(Some(20), None).expect("query");
    read_board(state, &query).expect("read board")
}

/// The surface row for one recorded run identity.
fn row_for<'a>(view: &'a BoardView, run: &str) -> &'a canter::tui::WorkRow {
    view.rows
        .iter()
        .find(|row| row.run.as_ref().is_some_and(|key| key.run == run))
        .unwrap_or_else(|| panic!("no rendered row for {run}"))
}

fn selection_for(run: &str) -> Selection {
    Selection {
        issue: IssueKey {
            repository: REPO_A.to_string(),
            issue: 12,
        },
        run: Some(RunKey {
            run: run.to_string(),
            attempt: None,
        }),
    }
}

// ---------------------------------------------------------------------------
// Render helpers (real Ratatui backend; the same board::draw the PTY uses)
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

fn text_of(terminal: &Terminal<TestBackend>) -> String {
    screen_lines(terminal.backend().buffer()).join("\n")
}

// ---------------------------------------------------------------------------
// Real read-model consumption: recorded rows reach the surface
// ---------------------------------------------------------------------------

#[test]
fn live_board_renders_the_real_read_model_rows() {
    let fixture = Fixture::new("live-rows");
    let state = fixture.open();
    seed_live_board(&state, &fixture);

    let live = LiveBoard::new(&state);
    let view = live.snapshot();
    let page = real_page(&state);

    // The view is the real page: same rows, same deterministic order, no
    // synthetic mode, no invented identity.
    assert!(!view.synthetic, "the live path is never synthetic-labelled");
    assert_eq!(view.source, "state-store");
    assert_eq!(view.state, BoardState::Ready);
    assert_eq!(
        view.page,
        Page {
            current: 1,
            count: Some(1),
            total_rows: Some(8),
            rows_before: 0,
        }
    );
    assert!(!view.freshness.stale, "a fresh read is not stale");
    assert!(
        view.freshness.complete,
        "every recorded binding is complete"
    );
    assert_eq!(view.rows.len(), page.rows.len());
    for (surface, recorded) in view.rows.iter().zip(&page.rows) {
        assert_eq!(surface.issue.repository, recorded.repository);
        assert_eq!(surface.issue.issue, u64::try_from(recorded.issue).unwrap());
        assert_eq!(
            surface.run,
            Some(RunKey {
                run: recorded.run.clone(),
                attempt: None,
            }),
            "the recorded run identity is rendered; no attempt is invented"
        );
        // The read model reports owner/reason as unknown (null): they must
        // stay unknown through the adapter.
        assert_eq!(surface.owner, None);
        assert_eq!(surface.reason, None);
    }
    // The pure page mapping agrees with the live read on every mapped field.
    let mapped = view_of_page(&page);
    for (live_row, page_row) in view.rows.iter().zip(&mapped.rows) {
        assert_eq!(live_row.issue, page_row.issue);
        assert_eq!(live_row.run, page_row.run);
        assert_eq!(live_row.stage, page_row.stage);
        assert_eq!(live_row.outcome, page_row.outcome);
        assert_eq!(live_row.evidence, page_row.evidence);
        assert_eq!(live_row.human_gate, page_row.human_gate);
        assert_eq!(live_row.next_action, page_row.next_action);
        assert_eq!(live_row.freshness.stale, page_row.freshness.stale);
        assert_eq!(live_row.freshness.complete, page_row.freshness.complete);
    }

    // One arm per recorded state of the read model's closed vocabulary.
    let by_run = |run: &str| row_for(&view, run);
    let ready = by_run("run-gadgets-0005");
    assert_eq!(ready.stage, Stage::Ready);
    assert_eq!(ready.outcome, Outcome::InProgress);
    assert_eq!(ready.next_action, None);
    assert_eq!(ready.human_gate, None);

    let paused = by_run("run-gadgets-0007");
    assert_eq!(paused.stage, Stage::HumanOnlyGate);
    assert_eq!(paused.next_action.as_deref(), Some("resume"));
    assert_eq!(paused.human_gate.as_deref(), Some("resume"));

    let blocked = by_run("run-gadgets-0009");
    assert_eq!(blocked.stage, Stage::Blocked);

    let human_queue = by_run("run-gadgets-0011");
    assert_eq!(human_queue.stage, Stage::HumanOnlyGate);
    assert_eq!(human_queue.next_action.as_deref(), Some("human_decision"));
    assert_eq!(human_queue.human_gate.as_deref(), Some("human_decision"));

    let verified = by_run("run-widgets-0001");
    assert_eq!(verified.stage, Stage::VerifiedMerge);
    assert_eq!(verified.outcome, Outcome::VerifiedDelivery);
    assert!(
        verified
            .evidence
            .iter()
            .any(|reference| reference.kind == EvidenceKind::Verification
                && reference.label == "passed"),
        "the recorded verification verdict is displayed"
    );
    assert!(
        verified
            .evidence
            .iter()
            .any(|reference| reference.kind == EvidenceKind::Reference),
        "the recorded evidence reference is displayed"
    );

    let failing = by_run("run-widgets-0002");
    assert_eq!(
        failing.stage,
        Stage::Implementing,
        "a failing review does not hide the run's recorded state"
    );
    assert_eq!(failing.outcome, Outcome::InProgress);
    assert!(failing.evidence.iter().any(
        |reference| reference.kind == EvidenceKind::Verification && reference.label == "failed"
    ));

    let reported = by_run("run-widgets-0003");
    assert_eq!(reported.stage, Stage::WorkerReportedDone);
    assert_eq!(reported.outcome, Outcome::ReportedDone);
    assert_ne!(
        reported.outcome,
        Outcome::VerifiedDelivery,
        "a recorded done status is never verified delivery"
    );

    let invalidated = by_run("run-widgets-0004");
    assert_eq!(invalidated.stage, Stage::Invalidated);
    assert_eq!(invalidated.outcome, Outcome::InProgress);

    // The wide frame carries the recorded identities, stages and the source,
    // and the detail states that no attempt number was recorded.
    let ui = UiState {
        selected: Some(selection_for("run-widgets-0001")),
        focus: Focus::Rows,
    };
    let wide = draw_view(&view, &ui, ColorMode::Ansi, WIDE);
    let text = text_of(&wide);
    assert!(text.contains("#12 example-org/widgets"));
    assert!(text.contains("#5 example-org/gadgets"));
    assert!(text.contains("Verified merge"));
    assert!(text.contains("Worker-reported done"));
    assert!(text.contains("Human-only gate"));
    assert!(text.contains("Blocked"));
    assert!(text.contains("source: state-store"));
    assert!(text.contains("stage: Verified merge | attempt: -"));
    assert!(!text.contains("SYNTHETIC"));

    // The narrow layout renders the same live row.
    let narrow = draw_view(&view, &ui, ColorMode::Ansi, NARROW);
    let narrow_text = text_of(&narrow);
    assert!(
        narrow_text.contains("> #12 example-org/widgets | Verified merge"),
        "narrow row line: {narrow_text}"
    );
}

#[test]
fn live_rows_never_fabricate_owner_reason_or_title() {
    let fixture = Fixture::new("live-fabrication");
    let state = fixture.open();
    seed_live_board(&state, &fixture);

    let view = LiveBoard::new(&state).snapshot();
    assert!(!view.rows.is_empty());
    for row in &view.rows {
        assert_eq!(row.owner, None, "no durable record names an owner");
        assert_eq!(row.reason, None, "no durable per-run reason text exists");
        assert_eq!(row.title, None, "the intent side is not re-observed");
    }

    let ui = UiState {
        selected: Some(selection_for("run-widgets-0001")),
        focus: Focus::Detail,
    };
    let text = text_of(&draw_view(&view, &ui, ColorMode::Ansi, WIDE));
    assert!(
        text.contains("owner: unassigned"),
        "an unknown owner renders as its explicit unknown form"
    );
    assert!(
        !text.contains("title:"),
        "no title segment without a recorded title"
    );
}

#[test]
fn live_refresh_keeps_the_selected_identity_when_rows_reorder() {
    let fixture = Fixture::new("live-refresh");
    let state = fixture.open();
    seed_live_board(&state, &fixture);

    let live = LiveBoard::new(&state);
    let before = live.snapshot();
    let ui = UiState {
        selected: Some(selection_for("run-widgets-0001")),
        focus: Focus::Rows,
    };
    assert_eq!(ui.selected_index(&before), Some(4));
    let text = text_of(&draw_view(&before, &ui, ColorMode::Ansi, WIDE));
    assert!(text.contains("> #12 example-org/widgets"));
    assert!(text.contains("selected: example-org/widgets#12"));

    // A refresh whose recorded facts reorder the rows: a new run sorts
    // before the selected one.
    seed_run(&state, REPO_B, 5, "run-gadgets-0004");
    let after = live.snapshot();
    assert_eq!(
        ui.selected_index(&before),
        Some(4),
        "the earlier view is unchanged"
    );
    assert_eq!(
        ui.selected_index(&after),
        Some(5),
        "the selected row moved position"
    );
    assert_eq!(
        after.rows[5].run,
        Some(RunKey {
            run: "run-widgets-0001".to_string(),
            attempt: None
        }),
        "the selection still names the same recorded run"
    );
    let text = text_of(&draw_view(&after, &ui, ColorMode::Ansi, WIDE));
    assert!(text.contains("> #12 example-org/widgets"));

    // Sibling attempts under one issue are separate identities: selecting
    // the other run of the same issue resolves to the other row.
    let ui = UiState {
        selected: Some(selection_for("run-widgets-0002")),
        focus: Focus::Rows,
    };
    assert_eq!(
        ui.selected_index(&after),
        Some(6),
        "the second run under issue 12 is its own row"
    );
    let text = text_of(&draw_view(&after, &ui, ColorMode::Ansi, WIDE));
    assert!(text.contains("> #12 example-org/widgets"));
    assert!(!text.contains("is retained but no longer in this view"));
}

#[test]
fn live_synthetic_mode_is_never_claimed() {
    let fixture = Fixture::new("live-synthetic");
    let state = fixture.open();
    seed_live_board(&state, &fixture);

    let view = LiveBoard::new(&state).snapshot();
    assert!(
        !view.synthetic,
        "the real read path must never claim synthetic mode"
    );
    let text = text_of(&draw_view(
        &view,
        &UiState::default(),
        ColorMode::Ansi,
        WIDE,
    ));
    assert!(!text.contains("SYNTHETIC"));
}

#[test]
fn live_monochrome_rendering_sets_no_colour() {
    let fixture = Fixture::new("live-colour");
    let state = fixture.open();
    seed_live_board(&state, &fixture);
    let view = LiveBoard::new(&state).snapshot();
    let ui = UiState {
        selected: Some(selection_for("run-widgets-0001")),
        focus: Focus::Rows,
    };

    let mono = draw_view(&view, &ui, ColorMode::Mono, WIDE);
    for cell in mono.backend().buffer().content() {
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

    let ansi = draw_view(&view, &ui, ColorMode::Ansi, WIDE);
    let coloured = ansi
        .backend()
        .buffer()
        .content()
        .iter()
        .filter(|cell| cell.fg != Color::Reset)
        .count();
    assert!(
        coloured > 0,
        "the ANSI palette must colour something, so the monochrome check discriminates"
    );
    for cell in ansi.backend().buffer().content() {
        assert_ne!(cell.fg, Color::Green, "forced green is banned");
        assert_eq!(cell.bg, Color::Reset, "no fixed background colour");
    }
}

#[test]
fn live_failed_read_states_offline_with_the_code_and_keeps_the_last_page() {
    let fixture = Fixture::new("live-offline");
    let state = fixture.open();
    seed_live_board(&state, &fixture);

    let live = LiveBoard::new(&state);
    let before = live.snapshot();
    assert_eq!(before.rows.len(), 8);

    // A recorded run state outside the read model's closed set: the read is
    // refused (never guessed), so no fresh read happened.
    let conn = fixture.raw();
    conn.execute(
        "UPDATE instances SET status = 'mystery' WHERE instance_id = 'run-gadgets-0005'",
        [],
    )
    .expect("seed an unrecorded run state");
    drop(conn);

    let after = live.snapshot();
    assert_eq!(after.state, BoardState::Offline);
    assert_eq!(
        after.state_note.as_deref(),
        Some("read failed: board.run_state"),
        "the stable refusal code is stated"
    );
    assert_eq!(
        after.rows.len(),
        8,
        "the last known page stays visible when no fresh read happened"
    );
    assert!(after.freshness.stale);
    assert!(!after.freshness.complete);

    let text = text_of(&draw_view(
        &after,
        &UiState::default(),
        ColorMode::Ansi,
        WIDE,
    ));
    assert!(
        text.contains(
            "warning: source is offline; showing last known data (no fresh reads): \
             read failed: board.run_state"
        ),
        "the offline notice names the failure: {text}"
    );
    assert!(text.contains("#5 example-org/gadgets"));
}

#[test]
fn live_legacy_rows_stay_partial_and_are_never_given_an_identity() {
    let fixture = Fixture::new("live-legacy");
    let state = fixture.open();
    seed_run(&state, REPO_A, 12, "run-widgets-0001");
    let epoch = state.summary().expect("summary").0;
    let conn = fixture.raw();
    conn.execute(
        "INSERT INTO instances (instance_id, state_epoch, status, created_at)
         VALUES ('legacy-run-0001', ?1, 'new', '2026-09-06T00:00:00Z')",
        rusqlite::params![epoch],
    )
    .expect("seed legacy row");
    drop(conn);

    let view = LiveBoard::new(&state).snapshot();
    let legacy = row_for(&view, "legacy-run-0001");
    assert_eq!(legacy.issue.repository, "", "no fabricated repository");
    assert_eq!(legacy.issue.issue, 0, "no fabricated issue number");
    assert!(!legacy.freshness.complete, "a partial row stays partial");
    assert_eq!(legacy.stage, Stage::Ready);
    assert!(
        !view.freshness.complete,
        "a partial row makes the observation incomplete, never complete-by-default"
    );
    let bound = row_for(&view, "run-widgets-0001");
    assert!(bound.freshness.complete);
}

// ---------------------------------------------------------------------------
// Real terminal: the session driven through a pseudo-terminal
// ---------------------------------------------------------------------------

/// Marker + database path the PTY child reads; set only for the re-executed
/// child, so the normal test run is untouched.
const CHILD_MARKER: &str = "CANTER_TUI_PTY_CHILD";
const CHILD_DB: &str = "CANTER_TUI_PTY_DB";

/// Child entry: re-executed under a real pseudo-terminal by the PTY tests.
///
/// A no-op in a normal run (the marker is absent). The PTY tests select this
/// test by name with `--exact`, so the child runs exactly one thing: the
/// real session against the real read model.
#[test]
fn pty_child_session_entry() {
    if std::env::var_os(CHILD_MARKER).is_none() {
        return;
    }
    let db = std::env::var_os(CHILD_DB).expect("child state path");
    let state = State::open(&PathBuf::from(db), Retention::default())
        .expect("child opens the seeded state store");
    let live = LiveBoard::new(&state);
    // The real session: Crossterm raw mode, alternate screen, key loop.
    canter::tui::session::run(&live).expect("the session runs against the real terminal");
}

#[test]
fn live_pty_session_renders_the_real_frame_and_accepts_real_keys() {
    let fixture = Fixture::new("live-pty-ansi");
    let state = fixture.open();
    seed_live_board(&state, &fixture);
    drop(state);

    let db = fixture.db();
    let db = db.to_str().expect("utf-8 temp path").to_string();
    let run = pty::run(
        &[
            (CHILD_MARKER, "1"),
            (CHILD_DB, db.as_str()),
            ("TERM", "xterm-256color"),
        ],
        &[
            "--nocapture",
            "--test-threads",
            "1",
            "--exact",
            "pty_child_session_entry",
        ],
        b"jq",
    )
    .expect("pty run");

    let text = strip_ansi(&run.output);
    print_evidence("ansi", &run.output, &text);

    assert_eq!(
        run.exit_code,
        0,
        "the session must quit cleanly on q; captured frame: {}",
        bounded(&text)
    );
    // The real terminal received the real rendered frame.
    assert!(
        contains_content(&text, "Canter operator board"),
        "captured frame: {}",
        bounded(&text)
    );
    assert!(contains_content(&text, "#5 example-org/gadgets"));
    assert!(contains_content(&text, "#12 example-org/widgets"));
    assert!(contains_content(&text, "Verified merge"));
    assert!(!text.contains("SYNTHETIC"));
    // Real key input moved the selection before quitting (j then q).
    assert!(
        contains_content(&text, "> #5 example-org/gadgets"),
        "the j key must move the selection; captured frame: {}",
        bounded(&text)
    );
    assert!(contains_content(&text, "selected: example-org/gadgets#5"));
    // A real terminal was driven and restored.
    let raw = String::from_utf8_lossy(&run.output);
    assert!(
        raw.contains("\u{1b}[?1049h"),
        "the alternate screen must be entered"
    );
    assert!(
        raw.contains("\u{1b}[?1049l"),
        "the terminal must be restored on quit"
    );
    assert!(
        sets_colour(&run.output),
        "the ANSI palette must set a terminal colour"
    );
}

#[test]
fn live_pty_session_is_monochrome_when_the_terminal_reports_no_colour() {
    // Two no-colour signals, both must reach a colour-free terminal:
    //
    // - `TERM=dumb` — a terminal that reports no colour support. Crossterm's
    //   own NO_COLOR gate is OPEN here, so this run discriminates the
    //   surface's capability selection itself.
    // - `NO_COLOR=1` — the surface and Crossterm both refuse colour; the
    //   terminal receives no colour codes at all.
    for (label, term, no_color) in [
        ("dumb", "dumb", None),
        ("no-color", "xterm-256color", Some("1")),
    ] {
        let fixture = Fixture::new(&format!("live-pty-mono-{label}"));
        let state = fixture.open();
        seed_live_board(&state, &fixture);
        drop(state);

        let db = fixture.db();
        let db = db.to_str().expect("utf-8 temp path").to_string();
        let mut env = vec![(CHILD_MARKER, "1"), (CHILD_DB, db.as_str()), ("TERM", term)];
        if let Some(value) = no_color {
            env.push(("NO_COLOR", value));
        }
        let run = pty::run(
            &env,
            &[
                "--nocapture",
                "--test-threads",
                "1",
                "--exact",
                "pty_child_session_entry",
            ],
            b"jq",
        )
        .expect("pty run");

        let text = strip_ansi(&run.output);
        print_evidence(&format!("mono-{label}"), &run.output, &text);

        assert_eq!(
            run.exit_code,
            0,
            "the session must quit cleanly on q ({label}); captured frame: {}",
            bounded(&text)
        );
        assert!(contains_content(&text, "Canter operator board"));
        assert!(
            contains_content(&text, "> #5 example-org/gadgets"),
            "the same keyboard path must work without colour ({label}); captured frame: {}",
            bounded(&text)
        );
        assert!(contains_content(&text, "Verified merge"));
        assert!(
            !sets_colour(&run.output),
            "no colour may be forced when the terminal reports none ({label})"
        );
    }
}

// ---------------------------------------------------------------------------
// Bounded capture helpers (evidence, never claims)
// ---------------------------------------------------------------------------

/// A bounded, escape-free excerpt of captured terminal output for the log.
fn bounded(text: &str) -> String {
    let mut excerpt: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if excerpt.chars().count() > 1500 {
        excerpt = excerpt.chars().take(1500).collect();
    }
    excerpt
}

/// Whether a captured frame carries `needle`, ignoring whitespace.
///
/// A real terminal legitimately receives fewer bytes than the cell grid:
/// Ratatui's diff skips a blank cell that is already blank on screen, so the
/// spaces inside default-styled runs are not re-emitted. The exact cell text
/// (spacing included) is pinned by the `board::draw` tests in
/// `tests/tui_board.rs` and by the fixed-size frames in this file; the PTY
/// assertions compare content.
fn contains_content(text: &str, needle: &str) -> bool {
    let squash = |value: &str| -> String { value.chars().filter(|c| !c.is_whitespace()).collect() };
    squash(text).contains(&squash(needle))
}

/// Print a bounded evidence excerpt plus the SGR census of the raw capture.
fn print_evidence(label: &str, raw: &[u8], text: &str) {
    println!("=== {label}: captured frame (escape-free, bounded) ===");
    for line in text.lines().take(20) {
        println!("|{line}|");
    }
    println!("=== {label}: raw bytes (control-escaped, bounded) ===");
    let escaped: String = raw
        .iter()
        .take(1200)
        .flat_map(|byte| std::ascii::escape_default(*byte))
        .map(char::from)
        .collect();
    println!("{escaped}");
    println!("=== {label}: SGR parameter groups seen ===");
    let mut seen: Vec<String> = Vec::new();
    for params in sgr_params(raw) {
        if !seen.contains(&params) {
            seen.push(params);
        }
    }
    println!("{seen:?}");
    println!("coloured: {}", sets_colour(raw));
}

/// Strip ANSI escape sequences from a captured terminal stream.
fn strip_ansi(bytes: &[u8]) -> String {
    let mut text: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != 0x1b {
            text.push(bytes[index]);
            index += 1;
            continue;
        }
        index += 1;
        match bytes.get(index) {
            Some(b'[') => {
                index += 1;
                while index < bytes.len() && !(0x40..=0x7e).contains(&bytes[index]) {
                    index += 1;
                }
                index += 1;
            }
            Some(b']') => {
                index += 1;
                while index < bytes.len() && bytes[index] != 0x07 {
                    index += 1;
                }
                index += 1;
            }
            Some(b'(') | Some(b')') => index += 2,
            _ => index += 1,
        }
    }
    String::from_utf8_lossy(&text).into_owned()
}

/// Every SGR (`ESC [ ... m`) parameter group in a captured stream.
fn sgr_params(bytes: &[u8]) -> Vec<String> {
    let mut found = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        let Some(position) = bytes[index..].iter().position(|byte| *byte == 0x1b) else {
            break;
        };
        index += position + 1;
        if bytes.get(index) != Some(&b'[') {
            index += 1;
            continue;
        }
        let start = index + 1;
        let mut end = start;
        while end < bytes.len() && (bytes[end].is_ascii_digit() || bytes[end] == b';') {
            end += 1;
        }
        if bytes.get(end) == Some(&b'm') {
            found.push(String::from_utf8_lossy(&bytes[start..end]).into_owned());
        }
        index = end + 1;
    }
    found
}

/// Whether a captured stream sets a colour attribute. Default-colour
/// parameters (39/49) are not colours.
fn sets_colour(bytes: &[u8]) -> bool {
    sgr_params(bytes).iter().any(|params| {
        params.split(';').any(|param| {
            matches!(
                param.parse::<u16>(),
                Ok(code) if matches!(code, 30..=38 | 40..=48 | 90..=97 | 100..=107)
            )
        })
    })
}

// ---------------------------------------------------------------------------
// Minimal real pseudo-terminal harness
// ---------------------------------------------------------------------------

mod pty {
    //! Run the test binary under a genuine pseudo-terminal.
    //!
    //! `forkpty` is the POSIX PTY fork: the child gets a real controlling
    //! terminal (which is what Crossterm's `/dev/tty` raw-mode path needs),
    //! the parent captures every byte the terminal emits and writes key
    //! bytes back. The crate's existing `libc` dependency is enough; no new
    //! dependency and no host tool are added.

    use std::ffi::CString;
    use std::io;
    use std::os::unix::ffi::OsStrExt;
    use std::time::{Duration, Instant};

    /// Wall-clock budget for one child (bounded; a live child is killed).
    const DEADLINE: Duration = Duration::from_secs(45);
    /// Budget for the first frame before the child is treated as wedged.
    const FIRST_FRAME: Duration = Duration::from_secs(20);
    const WIN_ROWS: u16 = 40;
    const WIN_COLS: u16 = 120;
    const TITLE: &[u8] = b"Canter operator board";

    pub struct Run {
        pub output: Vec<u8>,
        pub exit_code: i32,
    }

    fn invalid(what: &str) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidInput, what.to_string())
    }

    /// Run this test binary (with `argv_tail` appended) in a fresh PTY with
    /// exactly `env`, writing `keys` once the first frame has been drawn.
    pub fn run(env: &[(&str, &str)], argv_tail: &[&str], keys: &[u8]) -> io::Result<Run> {
        let exe = std::env::current_exe()?;
        let mut argv_strings =
            vec![CString::new(exe.as_os_str().as_bytes()).map_err(|_| invalid("executable path"))?];
        for arg in argv_tail {
            argv_strings.push(CString::new(*arg).map_err(|_| invalid("argument"))?);
        }
        let mut env_strings = Vec::with_capacity(env.len());
        for (key, value) in env {
            env_strings
                .push(CString::new(format!("{key}={value}")).map_err(|_| invalid("environment"))?);
        }
        let argv: Vec<*const libc::c_char> = argv_strings
            .iter()
            .map(|arg| arg.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect();
        let envp: Vec<*const libc::c_char> = env_strings
            .iter()
            .map(|value| value.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect();

        let mut winsize = libc::winsize {
            ws_row: WIN_ROWS,
            ws_col: WIN_COLS,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // The window size is read by `forkpty`; the libc signature takes
        // `*mut winsize` on the BSD/macOS builds and `*const winsize` on
        // Linux, so the size is passed as an explicit raw pointer. That is
        // what both signatures accept, and it keeps the call free of a
        // mutable borrow one of the two platforms does not need
        // (`clippy::unnecessary_mut_passed` on Linux).
        let winsize_ptr: *mut libc::winsize = &raw mut winsize;
        let mut master: libc::c_int = -1;
        // SAFETY: `forkpty` is the POSIX pseudo-terminal fork. The child
        // performs only `execve`/`_exit` before replacing its image, so no
        // lock or allocator state is touched after the fork.
        let pid = unsafe {
            libc::forkpty(
                &mut master,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                winsize_ptr,
            )
        };
        if pid < 0 {
            return Err(io::Error::last_os_error());
        }
        if pid == 0 {
            // SAFETY: exec with the argv/envp built above; on failure the
            // child must not run the test harness, so it exits immediately.
            unsafe {
                libc::execve(argv[0], argv.as_ptr(), envp.as_ptr());
                libc::_exit(127);
            }
        }

        let started = Instant::now();
        let mut output: Vec<u8> = Vec::new();
        let mut keys_sent = false;
        let mut quiet = 0_u32;
        let mut status: Option<libc::c_int> = None;
        while started.elapsed() < DEADLINE {
            let mut pollfd = libc::pollfd {
                fd: master,
                events: libc::POLLIN,
                revents: 0,
            };
            let ready = unsafe { libc::poll(&mut pollfd, 1, 100) };
            let mut read_bytes = 0_usize;
            if ready > 0 && pollfd.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
                let mut buffer = [0_u8; 8192];
                let count = unsafe { libc::read(master, buffer.as_mut_ptr().cast(), buffer.len()) };
                if count > 0 {
                    read_bytes = count as usize;
                    output.extend_from_slice(&buffer[..read_bytes]);
                }
            }
            if !keys_sent && output.windows(TITLE.len()).any(|window| window == TITLE) {
                // The first frame is drawn, so the session is already in raw
                // mode: the keys arrive as keystrokes, without Enter.
                let written = unsafe { libc::write(master, keys.as_ptr().cast(), keys.len()) };
                if written < 0 {
                    return Err(io::Error::last_os_error());
                }
                keys_sent = true;
            }
            if !keys_sent && started.elapsed() > FIRST_FRAME {
                break;
            }
            quiet = if read_bytes > 0 { 0 } else { quiet + 1 };
            if status.is_none() {
                let mut raw: libc::c_int = 0;
                if unsafe { libc::waitpid(pid, &mut raw, libc::WNOHANG) } == pid {
                    status = Some(raw);
                }
            }
            if status.is_some() && quiet >= 2 {
                break;
            }
        }
        if status.is_none() {
            // Bounded: never leave a live child behind.
            unsafe {
                libc::kill(pid, libc::SIGKILL);
            }
            let mut raw: libc::c_int = 0;
            unsafe {
                libc::waitpid(pid, &mut raw, 0);
            }
            status = Some(raw);
        }
        unsafe {
            libc::close(master);
        }
        let raw = status.unwrap_or(-1);
        let exit_code = if libc::WIFEXITED(raw) {
            libc::WEXITSTATUS(raw)
        } else {
            -1
        };
        Ok(Run { output, exit_code })
    }
}
