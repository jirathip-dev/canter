//! Live wiring (issue #90): the real read model of #83 adapted to the
//! surface view model.
//!
//! This module is the only path from the daemon state store to the surface.
//! [`LiveBoard`] implements [`ReadModel`] by reading one bounded page
//! through the real read model — [`crate::board::read_board`], which issues
//! the authoritative bounded join [`crate::state::State::board_page_rows`] —
//! and mapping the returned [`BoardRow`]s onto [`WorkRow`]s with closed,
//! documented rules. Nothing else reaches the surface: no second database,
//! no subprocess, no terminal-text inference, and no write path.
//!
//! Faithfulness rules (this module never invents a fact):
//!
//! - every displayed value is a recorded field of the row or the page;
//!   fields the read model reports as `null` (owner, reason, the intent-side
//!   title) stay `None` and render as their explicit unknown forms;
//! - `stage` maps one arm per recorded state of the read model's closed
//!   `stage`/`run_state` vocabulary, and `outcome` follows the delivery
//!   separation: only the read model's `verified` stage (recorded, current
//!   review evidence) is verified delivery, a recorded `done` status is
//!   reported-done (unverified), and nothing else claims delivery;
//! - `attempt` stays unknown: the read model numbers no attempts (several
//!   attempts under one issue are several runs, and therefore several rows),
//!   so the surface never numbers them either;
//! - freshness is the recorded `source.freshness`/`source.completeness`, and
//!   its age is measured from recorded timestamps only (the run's recorded
//!   `progress_at`, or the page's `observed_at` when the run recorded none);
//! - a failed read is stated as offline with the stable error code, and the
//!   last successfully read page stays visible as the last known data.
//!
//! The live path is never labelled synthetic; the explicit synthetic mode
//! stays a separate, explicitly labelled mode (see `tests/tui_board.rs`).

use std::cell::RefCell;

use crate::board::{BOARD_PAGE_DEFAULT, BoardPage, BoardQuery, BoardRow, read_board};
use crate::state::State;
use crate::time::{unix_from_rfc3339, unix_now};

use super::{
    BoardState, BoardView, EvidenceKind, EvidenceRef, Freshness, IssueKey, Outcome, Page,
    ReadModel, RunKey, Stage, WorkRow,
};

/// Stable display label of the live source feed.
///
/// A role, never a location: the surface identifies the source as the local
/// state store and never displays a host path.
pub const LIVE_SOURCE: &str = "state-store";

/// Rows requested per live read (the read model's bounded default page).
pub const LIVE_PAGE_LIMIT: i64 = BOARD_PAGE_DEFAULT as i64;

/// Live board adapter: one bounded page of the real read model per snapshot.
///
/// The read model is re-read on every snapshot (a bounded, deterministic
/// read with no cache), at the cursor the operator has paged to, so a
/// refresh always shows recorded facts; the last successfully read page is
/// retained only so a failed read can state that no fresh read happened
/// while the last known page stays visible.
pub struct LiveBoard<'a> {
    state: &'a State,
    limit: i64,
    last: RefCell<Option<CachedPage>>,
    paging: RefCell<Paging>,
}

/// Where the surface is in the read model's order (issue #341).
///
/// Paging is cursor-based, exactly like the read model it drives: `current`
/// is the cursor of the page being shown (`None` for the first page), `trail`
/// holds the cursors of the pages before it so `previous_page` can step back,
/// and `next` is the cursor the last successful read reported for the page
/// after this one (`None` when that read reached the end of the order).
#[derive(Default)]
struct Paging {
    current: Option<String>,
    trail: Vec<Option<String>>,
    next: Option<String>,
}

#[derive(Clone)]
struct CachedPage {
    view: BoardView,
    observed_at: String,
}

impl<'a> LiveBoard<'a> {
    /// A live board over `state` with the read model's default page size.
    pub fn new(state: &'a State) -> Self {
        Self::with_limit(state, LIVE_PAGE_LIMIT)
    }

    /// [`LiveBoard::new`] with an explicit page limit.
    ///
    /// The limit is validated by the read model: a limit outside the closed
    /// range is reported as a failed read (offline), never silently clamped.
    pub fn with_limit(state: &'a State, limit: i64) -> Self {
        LiveBoard {
            state,
            limit,
            last: RefCell::new(None),
            paging: RefCell::new(Paging::default()),
        }
    }

    /// Advance to the page after the one being shown (issue #341).
    ///
    /// Returns whether the board moved. A page is only left behind when the
    /// last read reported a next-page cursor — i.e. when that page held a
    /// full page of rows and more rows exist beyond it — so the rows the
    /// surface has paged past are always known exactly. At the end of the
    /// order this is a no-op: the surface never invents a page.
    pub fn next_page(&mut self) -> bool {
        let paging = self.paging.get_mut();
        let Some(next) = paging.next.take() else {
            return false;
        };
        paging.trail.push(paging.current.take());
        paging.current = Some(next);
        true
    }

    /// Go back to the page before the one being shown (issue #341).
    ///
    /// Returns whether the board moved; on the first page this is a no-op.
    pub fn previous_page(&mut self) -> bool {
        let paging = self.paging.get_mut();
        let Some(previous) = paging.trail.pop() else {
            return false;
        };
        paging.current = previous;
        paging.next = None;
        true
    }

    /// The view of one freshly read page, positioned in the paging session.
    ///
    /// The page number and the rows before it come from the pages this
    /// surface actually read; `count`/`total_rows` stay `None` while the
    /// read reports more rows beyond the page (an unknown total is never
    /// guessed — the renderer states the page's window instead).
    fn view_of(&self, page: &BoardPage) -> BoardView {
        let mut view = view_of_page(page);
        let pages_before = self.paging.borrow().trail.len() as u64;
        let rows_before = pages_before * self.limit.max(0) as u64;
        view.page = Page {
            current: pages_before + 1,
            count: if page.truncated {
                None
            } else {
                Some(pages_before + 1)
            },
            total_rows: if page.truncated {
                None
            } else {
                Some(rows_before + page.rows.len() as u64)
            },
            rows_before,
        };
        view
    }

    /// The offline view: the stable failure code, plus the last known page
    /// when one was read before.
    fn offline(&self, note: String) -> BoardView {
        match self.last.borrow().as_ref() {
            Some(cached) => {
                let mut view = cached.view.clone();
                view.state = BoardState::Offline;
                view.state_note = Some(note);
                view.freshness = Freshness {
                    age_secs: age_secs(&cached.observed_at).unwrap_or(0),
                    stale: true,
                    complete: false,
                };
                view
            }
            None => BoardView {
                source: LIVE_SOURCE.to_string(),
                synthetic: false,
                state: BoardState::Offline,
                state_note: Some(note),
                rows: Vec::new(),
                page: Page {
                    current: 1,
                    count: None,
                    total_rows: None,
                    rows_before: 0,
                },
                freshness: Freshness {
                    age_secs: 0,
                    stale: true,
                    complete: false,
                },
            },
        }
    }
}

impl ReadModel for LiveBoard<'_> {
    fn snapshot(&self) -> BoardView {
        let after = self.paging.borrow().current.clone();
        let query = match BoardQuery::new(Some(self.limit), after.as_deref()) {
            Ok(query) => query,
            Err(err) => return self.offline(format!("board query refused: {}", err.code)),
        };
        match read_board(self.state, &query) {
            Ok(page) => {
                let view = self.view_of(&page);
                self.paging.borrow_mut().next = page.next_cursor.clone();
                *self.last.borrow_mut() = Some(CachedPage {
                    view: view.clone(),
                    observed_at: page.observed_at.clone(),
                });
                view
            }
            Err(err) => self.offline(format!("read failed: {}", err.code)),
        }
    }
}

/// Adapt one real read-model page to the surface view model.
///
/// Pure: the same page always renders the same view. The rows keep the read
/// model's deterministic order and the page is the one bounded page that was
/// loaded, positioned first (`current: 1`, no rows before it);
/// [`LiveBoard::snapshot`] repositions it when the operator has paged.
/// `count`/`total_rows` stay `None` when the read model reported more rows
/// beyond that bounded read — an unknown total is never guessed, and the
/// surface states the page's window and how to reach the rest instead.
pub fn view_of_page(page: &BoardPage) -> BoardView {
    let complete = !page.truncated
        && page
            .rows
            .iter()
            .all(|row| row.source_completeness == "complete");
    BoardView {
        source: LIVE_SOURCE.to_string(),
        synthetic: false,
        state: if page.rows.is_empty() {
            BoardState::Empty
        } else {
            BoardState::Ready
        },
        state_note: None,
        rows: page
            .rows
            .iter()
            .map(|row| work_row_of(row, &page.observed_at))
            .collect(),
        page: Page {
            current: 1,
            count: if page.truncated { None } else { Some(1) },
            total_rows: if page.truncated {
                None
            } else {
                Some(page.rows.len() as u64)
            },
            rows_before: 0,
        },
        freshness: Freshness {
            age_secs: age_secs(&page.observed_at).unwrap_or(0),
            stale: false,
            complete,
        },
    }
}

/// Map one recorded row onto the surface row.
fn work_row_of(row: &BoardRow, observed_at: &str) -> WorkRow {
    let stage = stage_of(row);
    WorkRow {
        // The recorded source identity exactly as the read model reports it;
        // a row whose recorded bindings are missing keeps its recorded
        // (empty/legacy) values and is marked partial, never given an
        // invented identity.
        issue: IssueKey {
            repository: row.repository.clone(),
            issue: u64::try_from(row.issue).unwrap_or(0),
        },
        // The run identity is recorded; an attempt number is not a concept
        // of the read model, so it stays unknown.
        run: Some(RunKey {
            run: row.run.clone(),
            attempt: None,
        }),
        // The intent side is not re-observed by a board read: no title is
        // displayed rather than a fabricated one.
        title: None,
        stage,
        // Recorded text or unknown: never inferred from activity or prose.
        owner: row.owner.clone(),
        reason: row.reason.clone(),
        // The recorded closed next-action pointer, verbatim.
        next_action: row.next_action.map(str::to_string),
        // `human_gate` is exactly `paused`/`human_queue` in the read model;
        // the recorded next action names the decision that is waiting.
        human_gate: if row.human_gate {
            Some(row.next_action.unwrap_or("required").to_string())
        } else {
            None
        },
        evidence: evidence_of(row),
        outcome: outcome_of(row, stage),
        freshness: Freshness {
            age_secs: row_age_secs(row, observed_at),
            stale: row.source_freshness == "stale",
            complete: row.source_completeness == "complete",
        },
    }
}

/// Closed stage mapping: one arm per recorded run state, plus the read
/// model's derived `verified` stage.
///
/// The read model refuses a run state outside its closed set before the
/// adapter ever sees it, so the final arm is unreachable for real pages; it
/// exists so that a future state can never render as progress.
fn stage_of(row: &BoardRow) -> Stage {
    if row.stage == "verified" {
        return Stage::VerifiedMerge;
    }
    match row.run_state {
        "new" => Stage::Ready,
        "running" => Stage::Implementing,
        "paused" | "human_queue" => Stage::HumanOnlyGate,
        "blocked" => Stage::Blocked,
        "done" => Stage::WorkerReportedDone,
        "invalidated" => Stage::Invalidated,
        _ => Stage::UnsupportedStep,
    }
}

/// Delivery outcome: only the read model's verified stage is verified
/// delivery; a recorded `done` status is a report and stays unverified.
fn outcome_of(row: &BoardRow, stage: Stage) -> Outcome {
    if stage == Stage::VerifiedMerge {
        Outcome::VerifiedDelivery
    } else if row.run_state == "done" {
        Outcome::ReportedDone
    } else {
        Outcome::InProgress
    }
}

/// The bounded evidence references of one row: the recorded verification
/// verdict (the read model derives it from the newest recorded review
/// evidence), the recorded evidence references themselves, and — when the
/// read model reported overflow beyond its per-row bound — an explicit
/// remainder. Recorded references the source does not classify keep their
/// recorded identifiers; no kind is invented for them.
fn evidence_of(row: &BoardRow) -> Vec<EvidenceRef> {
    let mut references = Vec::new();
    if row.verification != "none" {
        references.push(EvidenceRef {
            kind: EvidenceKind::Verification,
            label: row.verification.to_string(),
        });
    }
    references.extend(row.evidence.iter().map(|id| EvidenceRef {
        kind: EvidenceKind::Reference,
        label: id.clone(),
    }));
    let hidden = row.evidence_total - row.evidence.len() as i64;
    if hidden > 0 {
        references.push(EvidenceRef {
            kind: EvidenceKind::Reference,
            label: format!("{hidden} more recorded"),
        });
    }
    references
}

/// Age of one row's recorded facts, measured from recorded timestamps only:
/// the run's last recorded progress, or the page's observation time when the
/// run recorded none.
fn row_age_secs(row: &BoardRow, observed_at: &str) -> u64 {
    age_secs(row.progress_at.as_deref().unwrap_or(observed_at)).unwrap_or(0)
}

/// Seconds between a recorded RFC3339 timestamp and now; `None` when the
/// timestamp is missing or unparsable (never guessed).
fn age_secs(stamp: &str) -> Option<u64> {
    let recorded = unix_from_rfc3339(stamp)?;
    u64::try_from((unix_now() - recorded).max(0)).ok()
}
