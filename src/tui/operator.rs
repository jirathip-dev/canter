//! Operator authority path (issue #91): exact selection, exact preview,
//! explicit authorization, daemon-owned run.
//!
//! The surface renders the recorded board ([`LiveBoard`]) and, for one
//! explicitly selected work item, the *exact* run that would start: the
//! reviewed bound-input document is re-rendered through the real preview
//! service ([`crate::queue_preview::preview_queue`]) and re-classified
//! through the same revalidation the daemon runs
//! ([`crate::queue_executor::revalidate`]) — the same typed services the CLI
//! uses, never a UI scheduler and never a synthesized shell command.
//!
//! Authorization is a separate, explicit action: the operator opens the
//! preview (`p`), continues to the authorization screen (`Enter`, only when
//! at least one selected item is eligible) and must set the authorization
//! box (`Space`) before `Enter` commits anything. Back, cancel, quit,
//! resize or any other key can never authorize a start, and no key other
//! than that `Enter` reaches the submit path.
//!
//! The start itself is daemon-owned: the surface sends the same
//! `queue.submit` params document the CLI builds
//! ([`crate::queue_executor::submit_params`]) over the daemon socket, so
//! closing the terminal stops nothing — the run lives in the daemon's state
//! store and a reopened surface reads it back through the recorded rows and
//! `queue.status`. An attempt the daemon does not confirm is reported as
//! unknown and is NEVER replayed; the only follow-up is the explicit
//! readback (`r`), which is read-only.
//!
//! The surface writes no state of its own, adds no privilege path (the
//! daemon's review/admission rules decide everything), and displays
//! requested facts and observed facts as distinct blocks with the observed
//! ones read from the daemon.

use std::collections::BTreeMap;
use std::path::PathBuf;

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyEventKind};
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::Paragraph;

use crate::client::{self, RpcError};
use crate::config::{Config, ProfileBinding, credential_environment};
use crate::lifecycle::ConcurrencyCaps;
use crate::queue_executor::{
    self as executor, ItemGrant, PlannedItem, ResumeAuthorization, SubmissionMaterial,
};
use crate::queue_preview::QueueRequest;
use crate::state::{State, SubmissionVerdict};
use crate::time::unix_now;
use crate::value::{Val, object, string};

use super::live::LiveBoard;
use super::supervision::SupervisionPanel;
use super::{Action, BoardView, ColorMode, ReadModel, UiState, clip, handle_key as board_key};

/// The statement the authorization screen shows: what the action does and
/// what it does not do.
pub const AUTHORIZE_STATEMENT: &str = "authorization commits a daemon-owned run that survives this terminal; \
the submission mutation itself claims no implementation, review or merge, while explicitly armed supervision \
may separately dispatch the run through the gated apply path";

/// Surface-local notice: no reviewed run plan was presented to this surface.
pub const CODE_PLAN: &str = "operator.plan";
/// Surface-local notice: nothing is selected on the board.
pub const CODE_SELECTION: &str = "operator.selection";
/// Surface-local notice: the selected work item is not part of the presented
/// plan (the plan is never silently re-scoped to the selection).
pub const CODE_NOT_BOUND: &str = "operator.not_bound";
/// Surface-local notice: the authorization box is not set.
pub const CODE_AUTHORIZATION: &str = "operator.authorization";
/// Surface-local notice: the preview cannot proceed to authorization
/// (no selected item is eligible).
pub const CODE_HELD: &str = "operator.held";
/// Surface-local notice: the submitted document did not carry the
/// deterministic submission id the surface derived.
pub const CODE_IDENTITY: &str = "operator.submission_id";

/// One presented run: the reviewed plan material plus the observations the
/// CLI presents on `queue submit` argv. The surface never invents any of it.
#[derive(Clone, Debug, PartialEq)]
pub struct PresentedRun {
    /// Display label of where the reviewed plan came from (a role or file
    /// name, never a host path).
    pub source: String,
    /// The reviewed bound-input document (`hf-queue-preview/v1`'s `request`
    /// object shape — the same document `queue submit --request` reads).
    pub bound: Val,
    /// Presented fan-out concurrency caps (the admission axes).
    pub caps: ConcurrencyCaps,
    /// Presented host availability; `None` = unknown (a hold, never a yes).
    pub host_available: Option<bool>,
    /// Presented same-harness occupancy; `None` = unknown (a hold).
    pub harness_lanes: Option<i64>,
    /// Presented per-issue grant bindings.
    pub grants: Vec<ItemGrant>,
    /// Presented resume authorizations.
    pub resume: Vec<ResumeAuthorization>,
}

impl PresentedRun {
    /// A presented run with unknown observations and no grant/resume
    /// bindings: the fail-closed default the operator (or the CLI) refines.
    pub fn new(source: impl Into<String>, bound: Val, caps: ConcurrencyCaps) -> Self {
        PresentedRun {
            source: source.into(),
            bound,
            caps,
            host_available: None,
            harness_lanes: None,
            grants: Vec::new(),
            resume: Vec::new(),
        }
    }
}

/// Display tone of one screen line; the renderer maps it to a style in both
/// colour modes (colour never carries a fact alone).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tone {
    /// Ordinary text.
    Normal,
    /// Section heading.
    Heading,
    /// Secondary/context text.
    Muted,
    /// A hold or a prerequisite that is not satisfied.
    Warn,
    /// A refusal or a blocker.
    Alert,
    /// The operator's own input/state (for example the authorization box).
    Input,
}

/// One display line of the operator surface: bounded, control-filtered text
/// plus its tone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScreenLine {
    /// The text (already clipped to the requested width).
    pub text: String,
    /// The tone the renderer styles it with.
    pub tone: Tone,
}

impl ScreenLine {
    pub(crate) fn new(tone: Tone, text: impl Into<String>) -> Self {
        ScreenLine {
            text: text.into(),
            tone,
        }
    }
}

/// Which screen the operator surface is showing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Screen {
    /// The recorded board (selection and navigation only).
    #[default]
    Board,
    /// The exact preview of the presented run.
    Preview,
    /// The explicit authorization of that exact preview.
    Authorize,
    /// The outcome: what was requested and what the daemon observed.
    Outcome,
    /// The compact supervision status of the selected run plus the two
    /// guarded continuation controls (issue #97): read-only status, the
    /// run-scoped hold (`h`) and the authorized continue (`u`).
    Supervision,
}

/// One typed notice: a stable code plus a bounded human message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Notice {
    /// Stable code (`operator.*`, a reused `refusal.*`/`usage.*` code, or a
    /// `client.*` transport code).
    pub code: String,
    /// Bounded human message.
    pub message: String,
}

impl Notice {
    pub(crate) fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Notice {
            code: code.into(),
            message: message.into(),
        }
    }

    /// `code: message` display form.
    pub fn label(&self) -> String {
        format!("{}: {}", self.code, self.message)
    }
}

/// What the daemon did with one attempt. The distinction between the
/// variants is what keeps the surface honest: only [`AttemptOutcome::Observed`]
/// is a committed effect, [`AttemptOutcome::Refused`] is a definite no-effect,
/// and [`AttemptOutcome::Uncertain`] is unknown and never replayed.
#[derive(Clone, Debug, PartialEq)]
pub enum AttemptOutcome {
    /// The daemon confirmed the committed submission (its own document).
    Observed {
        /// The committed `hf-queue-submission/v1` document.
        doc: Val,
    },
    /// Nothing was applied: a typed daemon refusal, or a connect failure
    /// where no request was sent (`client.connect`).
    Refused {
        /// Stable refusal code.
        code: String,
        /// Bounded human message.
        message: String,
    },
    /// The request may have reached the daemon and was not confirmed; the
    /// outcome is unknown until a readback says otherwise.
    Uncertain {
        /// Stable code (`client.*`, `state.claim_reused`, ...).
        code: String,
        /// Bounded human message.
        message: String,
    },
}

impl AttemptOutcome {
    /// The committed document, when the daemon confirmed one.
    pub fn observed_doc(&self) -> Option<&Val> {
        match self {
            Self::Observed { doc } => Some(doc),
            _ => None,
        }
    }
}

/// One authorization attempt: the deterministic submission id the surface
/// derived BEFORE the call (so a readback is possible even when no response
/// arrived), the authorized digest, and the daemon's outcome.
#[derive(Clone, Debug, PartialEq)]
pub struct Attempt {
    /// Deterministic submission id (`qs_` + 16 hex) derived from the digest
    /// and the attempt's idempotency key.
    pub submission_id: String,
    /// The exact preview digest that was authorized.
    pub digest: String,
    /// What the daemon did (or did not) confirm.
    pub outcome: AttemptOutcome,
}

/// The re-derived, freshly revalidated facts of one presented run: what the
/// preview screen shows and what the authorization binds.
#[derive(Clone, Debug)]
pub struct PreviewFacts {
    /// The exact preview digest (sha256 over the bound-input document).
    pub digest: String,
    /// The state epoch the approval was rendered against.
    pub epoch: i64,
    /// The freshly re-observed role-configuration revision.
    pub role_revision: String,
    /// The rendered `hf-queue-preview/v1` document.
    pub doc: Val,
    /// The rebuilt typed request.
    pub request: QueueRequest,
    /// The classified membership (one item per selected issue).
    pub items: Vec<PlannedItem>,
}

impl PreviewFacts {
    /// Whether the preview may proceed to authorization: at least one
    /// selected item is eligible (every item level hold — dependency,
    /// ownership, environment, capacity — is displayed, and a held item
    /// never offers a start).
    pub fn authorizable(&self) -> bool {
        self.items
            .iter()
            .any(|item| matches!(item.verdict, SubmissionVerdict::Approved))
    }

    /// The selected issue identities of this preview, in preview order.
    pub fn selected_ids(&self) -> Vec<String> {
        self.items.iter().map(|item| item.id.clone()).collect()
    }

    /// The item bound to `issue_number`, when the plan carries it.
    pub fn item(&self, issue_number: i64) -> Option<&PlannedItem> {
        self.items
            .iter()
            .find(|item| item.issue_number == issue_number)
    }
}

/// The operator console: the board, the presented run, and the authority
/// path over it.
pub struct OperatorConsole<'a> {
    state: &'a State,
    socket: PathBuf,
    config: Option<Config>,
    run: Option<PresentedRun>,
    board: LiveBoard<'a>,
    ui: UiState,
    screen: Screen,
    scroll: u16,
    checked: bool,
    notice: Option<Notice>,
    preview: Option<PreviewFacts>,
    attempt: Option<Attempt>,
    supervision: SupervisionPanel,
}

impl<'a> OperatorConsole<'a> {
    /// A console over `state`, submitting through the daemon at `socket`
    /// and re-observing the role configuration from `config`.
    pub fn new(
        state: &'a State,
        socket: PathBuf,
        config: Option<Config>,
        run: Option<PresentedRun>,
    ) -> Self {
        OperatorConsole {
            state,
            socket,
            config,
            run,
            board: LiveBoard::new(state),
            ui: UiState::default(),
            screen: Screen::Board,
            scroll: 0,
            checked: false,
            notice: None,
            preview: None,
            attempt: None,
            supervision: SupervisionPanel::new(),
        }
    }

    /// The supervision panel (issue #97): the compact status of the selected
    /// run plus the guarded continuation controls.
    pub fn supervision(&self) -> &SupervisionPanel {
        &self.supervision
    }

    /// The screen currently shown.
    pub fn screen(&self) -> Screen {
        self.screen
    }

    /// The board selection/focus state (the renderer needs it).
    pub fn ui_state(&self) -> &UiState {
        &self.ui
    }

    /// The typed notice currently displayed, if any.
    pub fn notice(&self) -> Option<&Notice> {
        self.notice.as_ref()
    }

    /// The presented run, if any.
    pub fn presented_run(&self) -> Option<&PresentedRun> {
        self.run.as_ref()
    }

    /// The current preview facts, if a preview was rendered.
    pub fn preview(&self) -> Option<&PreviewFacts> {
        self.preview.as_ref()
    }

    /// The last authorization attempt, if one exists.
    pub fn attempt(&self) -> Option<&Attempt> {
        self.attempt.as_ref()
    }

    /// Whether the authorization box is currently set.
    pub fn authorized(&self) -> bool {
        self.checked
    }

    /// Handle one key event. Returns the action the session should take.
    ///
    /// `p` opens the exact preview of the presented run for the selected
    /// work item; `Enter` continues the preview to the authorization screen
    /// when at least one selected item is eligible; `Space` sets the
    /// authorization box; the authorization screen's `Enter` is the ONLY key
    /// that starts work. `s` opens the compact supervision status and the
    /// guarded continuation controls of the selected run (issue #97). `b`/`Esc`
    /// navigate back (never forward) and always clear the authorization box;
    /// `q` quits.
    ///
    /// Only `Press` events are handled: an autorepeat or release event never
    /// effects anything on any screen (a held key cannot commit a control the
    /// operator did not confirm).
    pub fn handle_key(&mut self, key: KeyEvent) -> Option<Action> {
        if key.kind != KeyEventKind::Press {
            return None;
        }
        match self.screen {
            Screen::Board => self.board_key(key),
            Screen::Preview => match key.code {
                KeyCode::Esc | KeyCode::Char('b') => {
                    self.back();
                    Some(Action::Redraw)
                }
                KeyCode::Char('q') => Some(Action::Quit),
                KeyCode::Enter => {
                    self.begin_authorization();
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
            Screen::Authorize => match key.code {
                KeyCode::Esc | KeyCode::Char('b') => {
                    self.back();
                    Some(Action::Redraw)
                }
                KeyCode::Char('q') => Some(Action::Quit),
                KeyCode::Char(' ') => {
                    self.checked = !self.checked;
                    self.notice = None;
                    Some(Action::Redraw)
                }
                KeyCode::Enter => {
                    self.authorize();
                    Some(Action::Redraw)
                }
                _ => None,
            },
            Screen::Outcome => match key.code {
                KeyCode::Esc | KeyCode::Char('b') => {
                    self.back();
                    Some(Action::Redraw)
                }
                KeyCode::Char('q') => Some(Action::Quit),
                KeyCode::Char('r') => {
                    self.readback();
                    Some(Action::Redraw)
                }
                _ => None,
            },
            Screen::Supervision => self.supervision_key(key),
        }
    }

    /// The supervision screen (issue #97): back/quit are the console's; every
    /// other key belongs to the panel, whose confirmation state machine owns
    /// both effects. A confirmation is cancelled (`b`/`Esc`) before it can
    /// leave the screen, so no navigation can ever carry an approval away.
    fn supervision_key(&mut self, key: KeyEvent) -> Option<Action> {
        match key.code {
            KeyCode::Esc | KeyCode::Char('b') if !self.supervision.confirming() => {
                self.back();
                Some(Action::Redraw)
            }
            KeyCode::Char('q') => Some(Action::Quit),
            _ => self.supervision.handle_key(&self.socket, key),
        }
    }

    /// The board screen: board navigation plus `p` (open the exact preview)
    /// and `s` (open the compact supervision status/controls).
    fn board_key(&mut self, key: KeyEvent) -> Option<Action> {
        if key.code == KeyCode::Char('p') {
            self.request_preview();
            return Some(Action::Redraw);
        }
        if key.code == KeyCode::Char('s') {
            self.open_supervision();
            return Some(Action::Redraw);
        }
        let view = self.board.snapshot();
        board_key(&mut self.ui, &view, key)
    }

    /// Open the compact supervision status for the SELECTED run (issue #97).
    ///
    /// The status addresses exactly one run identity, so a selection that
    /// carries no recorded attempt refuses typed instead of inventing a
    /// target; the reads themselves are the daemon's typed services.
    pub fn open_supervision(&mut self) {
        match self.selected_run() {
            Some(run) => self.open_supervision_run(&run),
            None => {
                self.notice = Some(Notice::new(
                    crate::tui::supervision::CODE_NO_RUN,
                    "select a recorded run on the board first (Up/Down), then press s: the status \
                     addresses exactly one run identity",
                ));
                self.screen = Screen::Board;
            }
        }
    }

    /// Open the supervision screen for ONE explicit run identity.
    ///
    /// The `s` key resolves the board selection into this call; an embedder
    /// that already addressed a run may call it directly. It reads the
    /// daemon's typed status services (read-only) and changes only this
    /// surface's screen — it never effects anything on the run.
    pub fn open_supervision_run(&mut self, run: &str) {
        self.supervision.read(&self.socket, run);
        self.scroll = 0;
        self.notice = None;
        self.screen = Screen::Supervision;
    }

    /// The run identity of the current board selection, when it has one.
    pub fn selected_run(&self) -> Option<String> {
        self.ui
            .selected
            .as_ref()
            .and_then(|selection| selection.run.as_ref())
            .map(|run| run.run.clone())
    }

    /// Back/cancel: the screen-appropriate step backwards. Never forward,
    /// never an authorization; cancelling the preview discards it, so only a
    /// freshly derived preview can ever be authorized.
    fn back(&mut self) {
        match self.screen {
            Screen::Board => {}
            Screen::Preview => {
                self.screen = Screen::Board;
                self.preview = None;
                self.scroll = 0;
            }
            Screen::Authorize => {
                self.screen = Screen::Preview;
                self.scroll = 0;
            }
            Screen::Outcome => {
                self.screen = Screen::Board;
                self.scroll = 0;
                self.preview = None;
                self.attempt = None;
            }
            Screen::Supervision => {
                // The board strip keeps the last compact status of the run it
                // was read for; the confirmation state is cleared by the
                // panel's own key handling before this point.
                self.screen = Screen::Board;
                self.scroll = 0;
            }
        }
        self.checked = false;
        self.notice = None;
    }

    /// Render the exact preview of the presented run for the selected work
    /// item: a fresh, read-only re-derivation through the real services.
    ///
    /// A fresh preview starts a new review cycle: any earlier attempt record
    /// is superseded (an earlier attempt is never replayed, only reported).
    pub fn request_preview(&mut self) {
        self.preview = None;
        self.attempt = None;
        self.checked = false;
        let Some(run) = self.run.clone() else {
            self.notice = Some(Notice::new(
                CODE_PLAN,
                "no reviewed run plan is presented to this surface; the run plan must be presented as \
                 the reviewed bound-input document before anything can be previewed or authorized",
            ));
            return;
        };
        let Some(selection) = self.ui.selected.clone() else {
            self.notice = Some(Notice::new(
                CODE_SELECTION,
                "select a work item on the board first (↑/↓ or k/j), then press p to preview its run",
            ));
            return;
        };
        let facts = match self.preview_facts(&run) {
            Ok(facts) => facts,
            Err(notice) => {
                self.notice = Some(notice);
                return;
            }
        };
        let number = i64::try_from(selection.issue.issue).unwrap_or(-1);
        match facts.item(number) {
            Some(item)
                if item
                    .id
                    .eq_ignore_ascii_case(&format!("{}#{number}", selection.issue.repository)) =>
            {
                self.notice = None;
                self.preview = Some(facts);
                self.scroll = 0;
                self.screen = Screen::Preview;
            }
            _ => {
                self.notice = Some(Notice::new(
                    CODE_NOT_BOUND,
                    format!(
                        "the selected work item {} is not part of the presented run plan ({}); the plan \
                         is never re-scoped to the selection",
                        selection.issue.label(),
                        run.source
                    ),
                ));
            }
        }
    }

    /// A terminal resize (the approved interaction contract): the selection
    /// survives, the authorization box is cleared, and the operator is told
    /// on the authorization screen — an approval is never carried across a
    /// frame change the operator did not see.
    pub fn on_resize(&mut self) {
        self.checked = false;
        if self.screen == Screen::Authorize {
            self.notice = Some(Notice::new(
                CODE_AUTHORIZATION,
                "the terminal was resized; the authorization box is cleared — Space sets it again",
            ));
        }
    }

    /// Continue the preview to the authorization screen. Held work never
    /// reaches it.
    pub fn begin_authorization(&mut self) {
        let Some(facts) = self.preview.as_ref() else {
            self.notice = Some(Notice::new(
                CODE_PLAN,
                "render the preview (p) before authorizing anything",
            ));
            return;
        };
        if !facts.authorizable() {
            self.notice = Some(Notice::new(
                CODE_HELD,
                "no selected item is eligible in this preview; a held item never offers a start — \
                 resolve the displayed holds and render a fresh preview",
            ));
            return;
        }
        self.notice = None;
        self.checked = false;
        self.scroll = 0;
        self.screen = Screen::Authorize;
    }

    /// The ONE mutating path: authorize the exact preview and submit it to
    /// the daemon. Everything is re-derived first; a moved digest, epoch or
    /// role revision refuses typed and submits nothing.
    pub fn authorize(&mut self) {
        if !self.checked {
            self.notice = Some(Notice::new(
                CODE_AUTHORIZATION,
                "the authorization box is not set; Space sets it explicitly and Enter then authorizes \
                 the exact plan — no other key can",
            ));
            return;
        }
        let Some(run) = self.run.clone() else {
            self.checked = false;
            self.notice = Some(Notice::new(
                CODE_PLAN,
                "no reviewed run plan is presented to this surface; there is nothing to authorize",
            ));
            return;
        };
        let Some(shown) = self.preview.clone() else {
            self.checked = false;
            self.notice = Some(Notice::new(
                CODE_PLAN,
                "render the preview (p) before authorizing anything",
            ));
            return;
        };
        // ONE material build and ONE fresh revalidation: the digest, epoch
        // and role revision the authorization binds are re-derived exactly
        // once, from the live state and the current configuration.
        let (material, _) = match self.derive(&run) {
            Ok(pair) => pair,
            Err(notice) => {
                self.checked = false;
                self.notice = Some(notice);
                return;
            }
        };
        if material.digest != shown.digest {
            self.refuse(
                "refusal.plan.stale",
                "the freshly derived digest is not the digest that was rendered and authorized; render \
                 a fresh preview and authorize its digest",
            );
            return;
        }
        if material.epoch != shown.epoch {
            self.refuse(
                "refusal.state.epoch",
                &format!(
                    "the approval was rendered against epoch {} but the live epoch is {}; an approval \
                     dies with its epoch — render a fresh preview",
                    shown.epoch, material.epoch
                ),
            );
            return;
        }
        if material.role_revision != shown.role_revision {
            self.refuse(
                "refusal.profile.revision",
                "the re-observed role-configuration revision is not the reviewed one; a configuration \
                 or credential change invalidates the approval — render a fresh preview",
            );
            return;
        }
        let submission_id = executor::submission_id(&material.digest, &material.idempotency_key);
        let params = executor::submit_params(
            &material.idempotency_key,
            &material.digest,
            material.epoch,
            &material.preview,
            &material.binding,
            &material.role_revision,
            material.caps,
            material.host_available,
            material.harness_lanes,
            &material.grants,
            &material.resume,
            // Issue #95: supervision is OPTIONAL and disabled by default. The
            // operator surface does not arm the supervised reconciliation
            // driver on the operator's behalf (the CLI's `--supervise arm` is
            // the explicit arming decision); the admitted runs stay
            // un-supervised unless that authorization is presented.
            None,
        );
        let outcome = match client::call(&self.socket, "queue.submit", Some(&params)) {
            Ok(doc) => match doc.get("submission_id").and_then(Val::as_str) {
                Some(committed) if committed == submission_id => AttemptOutcome::Observed { doc },
                other => AttemptOutcome::Uncertain {
                    code: CODE_IDENTITY.to_string(),
                    message: format!(
                        "the daemon answered with submission id {:?}, not the derived {submission_id}; \
                         the committed submission cannot be confirmed by this surface",
                        other.unwrap_or("none")
                    ),
                },
            },
            Err(RpcError { code, message }) => failure_outcome(&code, &message),
        };
        self.checked = false;
        self.notice = None;
        self.attempt = Some(Attempt {
            submission_id,
            digest: material.digest.clone(),
            outcome,
        });
        self.scroll = 0;
        self.screen = Screen::Outcome;
    }

    /// Read the last attempt back from the daemon (read-only): the honest
    /// follow-up to an unconfirmed attempt. Nothing is ever re-sent.
    pub fn readback(&mut self) {
        let Some(attempt) = self.attempt.as_mut() else {
            self.notice = Some(Notice::new(
                CODE_PLAN,
                "there is no attempt to read back; nothing was sent",
            ));
            return;
        };
        let submission_id = attempt.submission_id.clone();
        let params = object(vec![("submission_id", string(&submission_id))]);
        match client::call(&self.socket, "queue.status", Some(&params)) {
            Ok(doc) => {
                attempt.outcome = AttemptOutcome::Observed { doc };
                self.notice = None;
            }
            Err(RpcError { code, message }) => {
                if code == "state.not_found" {
                    self.notice = Some(Notice::new(
                        "state.not_found",
                        format!(
                            "the daemon holds no committed submission {submission_id}; this \
                             authorization did not commit"
                        ),
                    ));
                } else {
                    self.notice = Some(Notice::new(
                        code,
                        format!("the daemon could not be read back: {message}"),
                    ));
                }
            }
        }
    }

    /// A local typed refusal before anything is sent: the authorization
    /// stays on its screen with the box cleared.
    fn refuse(&mut self, code: &str, message: &str) {
        self.checked = false;
        self.notice = Some(Notice::new(code, message));
    }

    /// Re-derive the preview material from the live state and configuration
    /// (read-only): the same revalidation the daemon runs at submit time.
    fn derive(
        &self,
        run: &PresentedRun,
    ) -> Result<(SubmissionMaterial, executor::Revalidated), Notice> {
        let material = self.material(run)?;
        let revalidated = executor::revalidate(self.state, &material)
            .map_err(|err| Notice::new(err.code, err.message))?;
        Ok((material, revalidated))
    }

    /// The preview facts of one presented run (one material build, one
    /// revalidation).
    fn preview_facts(&self, run: &PresentedRun) -> Result<PreviewFacts, Notice> {
        let (material, revalidated) = self.derive(run)?;
        Ok(PreviewFacts {
            digest: material.digest.clone(),
            epoch: material.epoch,
            role_revision: material.role_revision.clone(),
            doc: revalidated.preview.doc.clone(),
            request: revalidated.request.clone(),
            items: revalidated.items.clone(),
        })
    }

    /// Build the presented submission material: the bound document's digest,
    /// the live epoch, and the role binding re-observed from the CURRENT
    /// configuration (never a value the operator can edit), exactly as the
    /// CLI's `queue submit` preflight does.
    fn material(&self, run: &PresentedRun) -> Result<SubmissionMaterial, Notice> {
        let digest =
            executor::bound_digest(&run.bound).map_err(|err| Notice::new(err.code, err.message))?;
        let harness_key = run
            .bound
            .get("role_config")
            .and_then(|role| role.get("key"))
            .and_then(Val::as_str)
            .filter(|key| !key.is_empty())
            .map(str::to_string)
            .ok_or_else(|| {
                Notice::new(
                    "usage.queue_submission.preview",
                    "the bound-input document requires role_config.key",
                )
            })?;
        let binding = self.reobserved_binding(&harness_key)?;
        let epoch = self
            .state
            .current_epoch()
            .map_err(|err| Notice::new(err.code, err.message))?;
        Ok(SubmissionMaterial {
            idempotency_key: fresh_key(),
            preview: run.bound.clone(),
            binding: binding.to_doc(),
            digest,
            epoch,
            role_revision: binding.revision.clone(),
            caps: run.caps,
            host_available: run.host_available,
            harness_lanes: run.harness_lanes,
            grants: run.grants.clone(),
            resume: run.resume.clone(),
            // Issue #95: no supervision authorization is presented by this
            // surface, so the admitted runs stay un-supervised (the daemon
            // equivalent of the CLI's `--supervise off` default).
            supervision: None,
        })
    }

    /// Re-observe the reviewed role configuration from the current config
    /// (the CLI's `fresh_role_binding` rule): a missing config, an unknown
    /// harness or an unbound harness refuses before any daemon call.
    fn reobserved_binding(&self, harness_key: &str) -> Result<ProfileBinding, Notice> {
        let Some(config) = self.config.as_ref() else {
            return Err(Notice::new(
                "config.not_found",
                format!(
                    "the surface needs the profile configuration to re-observe the reviewed role \
                     revision for {harness_key:?}; pass the config the daemon runs with"
                ),
            ));
        };
        let Some(harness) = config
            .harnesses
            .iter()
            .find(|harness| harness.key == harness_key)
        else {
            return Err(Notice::new(
                "config.harness",
                format!(
                    "no configured harness {harness_key:?}; the reviewed role configuration names a \
                     configured harness key"
                ),
            ));
        };
        let env: BTreeMap<String, String> = credential_environment(harness);
        ProfileBinding::from_config(config, harness_key, &env).ok_or_else(|| {
            Notice::new(
                "config.harness",
                format!(
                    "harness {harness_key:?} declares no provider/model binding; there is no \
                     re-observed role configuration to submit against"
                ),
            )
        })
    }

    /// Display lines of the current screen, bounded to `width` columns.
    ///
    /// The board screen renders through the board renderer, so it has no
    /// lines of its own here.
    pub fn lines(&self, width: usize) -> Vec<ScreenLine> {
        let mut lines = match self.screen {
            Screen::Board => Vec::new(),
            Screen::Preview => self.preview_lines(width),
            Screen::Authorize => self.authorize_lines(width),
            Screen::Outcome => self.outcome_lines(width),
            Screen::Supervision => self.supervision.lines(width),
        };
        // A typed notice (a hold, a refusal, a readback failure) is never
        // invisible: on every screen it renders as the line after the
        // heading, and on the board it replaces the footer row.
        if self.screen != Screen::Board
            && let Some(notice) = self.notice_line(width)
        {
            let position = if lines.is_empty() { 0 } else { 1 };
            lines.insert(position, notice);
        }
        lines
    }

    /// The notice line (also shown as a one-line strip over the board).
    pub fn notice_line(&self, width: usize) -> Option<ScreenLine> {
        self.notice
            .as_ref()
            .map(|notice| ScreenLine::new(Tone::Warn, clip(&notice.label(), width)))
    }

    fn preview_lines(&self, width: usize) -> Vec<ScreenLine> {
        let mut lines = Vec::new();
        lines.push(ScreenLine::new(
            Tone::Heading,
            clip("PREVIEW — nothing has run (read-only, effect-free)", width),
        ));
        let Some(facts) = self.preview.as_ref() else {
            lines.push(ScreenLine::new(
                Tone::Warn,
                clip("no preview was rendered", width),
            ));
            return lines;
        };
        let Some(run) = self.run.as_ref() else {
            lines.push(ScreenLine::new(
                Tone::Warn,
                clip("no reviewed run plan is presented", width),
            ));
            return lines;
        };
        lines.push(ScreenLine::new(
            Tone::Muted,
            clip(&format!("plan source: {}", run.source), width),
        ));
        lines.push(ScreenLine::new(
            Tone::Normal,
            clip(
                &format!(
                    "digest {}  epoch {}  state {}",
                    facts.digest,
                    facts.epoch,
                    if facts.authorizable() {
                        "at least one eligible item"
                    } else {
                        "held"
                    }
                ),
                width,
            ),
        ));
        let request = &facts.request;
        lines.push(ScreenLine::new(
            Tone::Normal,
            clip(
                &format!(
                    "repository {}  host {} ({})  harness {}",
                    request.repository,
                    request.host,
                    availability(request.host_available),
                    request.harness_key
                ),
                width,
            ),
        ));
        lines.push(ScreenLine::new(
            Tone::Normal,
            clip(
                &format!("workflow {} {}", request.workflow_id, request.workflow_hash),
                width,
            ),
        ));
        lines.push(ScreenLine::new(
            Tone::Normal,
            clip(
                &format!(
                    "role revision {} (re-observed from the current configuration)",
                    facts.role_revision
                ),
                width,
            ),
        ));
        lines.push(ScreenLine::new(
            Tone::Heading,
            clip("AUTHORIZATION SCOPE (what the run may reach)", width),
        ));
        lines.push(ScreenLine::new(
            Tone::Normal,
            clip(
                &format!(
                    "boundary {}: {} -> {}  caps {}",
                    request.boundary.phase,
                    request.boundary.integration_branch,
                    request.boundary.completion_branch,
                    request.boundary.caps.join(", ")
                ),
                width,
            ),
        ));
        lines.push(ScreenLine::new(
            Tone::Muted,
            clip(
                &format!(
                    "presented observations: host {}  occupancy {}  caps {}/{}/{}  grants {}  resume {}",
                    availability(run.host_available),
                    occupancy(run.harness_lanes),
                    run.caps.global,
                    run.caps.per_repository,
                    run.caps.per_harness,
                    run.grants.len(),
                    run.resume.len()
                ),
                width,
            ),
        ));
        lines.push(ScreenLine::new(Tone::Heading, clip("STEPS", width)));
        for step in &request.steps {
            lines.push(ScreenLine::new(
                Tone::Normal,
                clip(
                    &format!(
                        "  {} {}  resolved {}",
                        step.id,
                        step.kind,
                        if step.params.is_some() { "yes" } else { "NO" }
                    ),
                    width,
                ),
            ));
        }
        lines.push(ScreenLine::new(Tone::Heading, clip("SELECTED", width)));
        for item in &facts.items {
            lines.push(ScreenLine::new(
                Tone::Normal,
                clip(&format!("  {} revision {}", item.id, item.revision), width),
            ));
            let (tone, text) = verdict_lines(&item.verdict);
            lines.push(ScreenLine::new(tone, clip(&format!("    {text}"), width)));
            if let Some(grant_id) = &item.grant_id {
                lines.push(ScreenLine::new(
                    Tone::Muted,
                    clip(&format!("    bound grant {grant_id}"), width),
                ));
            }
        }
        let holds = doc_holds(&facts.doc);
        lines.push(ScreenLine::new(
            Tone::Heading,
            clip(&format!("HOLDS ({})", holds.len()), width),
        ));
        if holds.is_empty() {
            lines.push(ScreenLine::new(Tone::Muted, clip("  none", width)));
        }
        for hold in holds {
            lines.push(ScreenLine::new(
                Tone::Warn,
                clip(&format!("  {hold}"), width),
            ));
        }
        lines.push(ScreenLine::new(
            Tone::Muted,
            clip(
                "preview only: nothing is spawned, no grant is issued, nothing is written",
                width,
            ),
        ));
        lines.push(ScreenLine::new(
            Tone::Muted,
            clip(
                "Enter continues to the authorization screen; j/k scroll; b cancels; q quits",
                width,
            ),
        ));
        lines
    }

    fn authorize_lines(&self, width: usize) -> Vec<ScreenLine> {
        let mut lines = Vec::new();
        lines.push(ScreenLine::new(
            Tone::Heading,
            clip("AUTHORIZATION — this starts a daemon-owned run", width),
        ));
        lines.push(ScreenLine::new(
            Tone::Muted,
            clip(AUTHORIZE_STATEMENT, width),
        ));
        let Some(facts) = self.preview.as_ref() else {
            lines.push(ScreenLine::new(
                Tone::Warn,
                clip("no preview was rendered", width),
            ));
            return lines;
        };
        lines.push(ScreenLine::new(
            Tone::Normal,
            clip(&format!("exact digest {}", facts.digest), width),
        ));
        lines.push(ScreenLine::new(
            Tone::Normal,
            clip(
                &format!(
                    "epoch {}  role revision {}",
                    facts.epoch, facts.role_revision
                ),
                width,
            ),
        ));
        lines.push(ScreenLine::new(
            Tone::Normal,
            clip(
                &format!("selected {}", facts.selected_ids().join(", ")),
                width,
            ),
        ));
        lines.push(ScreenLine::new(
            Tone::Normal,
            clip(
                &format!(
                    "boundary {} -> {}  caps {}",
                    facts.request.boundary.integration_branch,
                    facts.request.boundary.completion_branch,
                    facts.request.boundary.caps.join(", ")
                ),
                width,
            ),
        ));
        lines.push(ScreenLine::new(
            Tone::Input,
            clip(
                &format!(
                    "[{}] authorize this exact plan and the daemon-owned run it starts",
                    if self.checked { "x" } else { " " }
                ),
                width,
            ),
        ));
        lines.push(ScreenLine::new(
            Tone::Muted,
            clip(
                "Space sets the authorization; Enter then authorizes THIS digest; b/Esc cancels and \
                 clears it; q quits",
                width,
            ),
        ));
        lines
    }

    fn outcome_lines(&self, width: usize) -> Vec<ScreenLine> {
        let mut lines = Vec::new();
        lines.push(ScreenLine::new(
            Tone::Heading,
            clip("OUTCOME — requested vs observed", width),
        ));
        let Some(attempt) = self.attempt.as_ref() else {
            lines.push(ScreenLine::new(
                Tone::Warn,
                clip("no authorization was attempted", width),
            ));
            return lines;
        };
        lines.push(ScreenLine::new(
            Tone::Heading,
            clip("REQUESTED (what the operator authorized)", width),
        ));
        lines.push(ScreenLine::new(
            Tone::Normal,
            clip(
                &format!(
                    "  digest {}  submission {}",
                    attempt.digest, attempt.submission_id
                ),
                width,
            ),
        ));
        if let Some(facts) = self.preview.as_ref() {
            lines.push(ScreenLine::new(
                Tone::Normal,
                clip(
                    &format!(
                        "  selected {}  boundary {} -> {}",
                        facts.selected_ids().join(", "),
                        facts.request.boundary.integration_branch,
                        facts.request.boundary.completion_branch
                    ),
                    width,
                ),
            ));
        }
        if let Some(run) = self.run.as_ref() {
            lines.push(ScreenLine::new(
                Tone::Normal,
                clip(
                    &format!(
                        "  presented observations: host {}  occupancy {}  caps {}/{}/{}",
                        availability(run.host_available),
                        occupancy(run.harness_lanes),
                        run.caps.global,
                        run.caps.per_repository,
                        run.caps.per_harness
                    ),
                    width,
                ),
            ));
        }
        lines.push(ScreenLine::new(
            Tone::Heading,
            clip("OBSERVED (what the daemon reports)", width),
        ));
        match &attempt.outcome {
            AttemptOutcome::Observed { doc } => {
                let admission = doc.get("admission");
                lines.push(ScreenLine::new(
                    Tone::Normal,
                    clip(
                        &format!(
                            "  committed under epoch {}; admission {} admitted / {} waiting / {} refused",
                            doc.get("state")
                                .and_then(|state| state.get("epoch"))
                                .and_then(Val::as_int)
                                .unwrap_or_default(),
                            admission
                                .and_then(|counts| counts.get("admitted"))
                                .and_then(Val::as_int)
                                .unwrap_or_default(),
                            admission
                                .and_then(|counts| counts.get("waiting"))
                                .and_then(Val::as_int)
                                .unwrap_or_default(),
                            admission
                                .and_then(|counts| counts.get("refused"))
                                .and_then(Val::as_int)
                                .unwrap_or_default(),
                        ),
                        width,
                    ),
                ));
                for line in submission_item_lines(doc) {
                    lines.push(ScreenLine::new(
                        Tone::Normal,
                        clip(&format!("  {line}"), width),
                    ));
                }
                if let Some(statement) = doc.get("statement").and_then(Val::as_str) {
                    lines.push(ScreenLine::new(
                        Tone::Muted,
                        clip(&format!("  {statement}"), width),
                    ));
                }
            }
            AttemptOutcome::Refused { code, message } => {
                lines.push(ScreenLine::new(
                    Tone::Alert,
                    clip(&format!("  NOT APPLIED [{code}] {message}"), width),
                ));
                lines.push(ScreenLine::new(
                    Tone::Muted,
                    clip(
                        "  the daemon refused before any effect; nothing was committed by this attempt",
                        width,
                    ),
                ));
            }
            AttemptOutcome::Uncertain { code, message } => {
                lines.push(ScreenLine::new(
                    Tone::Alert,
                    clip(&format!("  UNKNOWN [{code}] {message}"), width),
                ));
                lines.push(ScreenLine::new(
                    Tone::Warn,
                    clip(
                        "  the request was sent and the daemon did not confirm it; this surface will \
                         not replay it — press r to read the daemon back",
                        width,
                    ),
                ));
            }
        }
        lines.push(ScreenLine::new(
            Tone::Muted,
            clip(
                "r reads this submission back from the daemon; b returns to the board; q quits",
                width,
            ),
        ));
        lines
    }
}

impl ReadModel for OperatorConsole<'_> {
    fn snapshot(&self) -> BoardView {
        self.board.snapshot()
    }
}

/// Render the operator surface into the frame.
///
/// On the board screen the board renderer draws and the bottom row carries the
/// supervision strip of the selected run (issue #97) — or the typed notice,
/// which always wins because it reports why an action refused. Every other
/// screen renders its own bounded lines; the supervision screen scrolls with
/// the panel's own offset.
pub fn draw(console: &OperatorConsole<'_>, mode: ColorMode, frame: &mut ratatui::Frame) {
    let area = frame.area();
    match console.screen() {
        Screen::Board => {
            let view = console.snapshot();
            super::board::draw(&view, console.ui_state(), mode, frame);
            if area.height > 0 {
                let strip = Rect {
                    x: area.x,
                    y: area.y + area.height - 1,
                    width: area.width,
                    height: 1,
                };
                let line = match console.notice_line(area.width as usize) {
                    Some(notice) => notice,
                    None => console
                        .supervision
                        .strip(console.selected_run().as_deref(), area.width as usize),
                };
                frame.render_widget(
                    Paragraph::new(Line::from(Span::styled(
                        line.text,
                        style_of(line.tone, mode),
                    ))),
                    strip,
                );
            }
        }
        _ => {
            let lines = console.lines(area.width as usize);
            let text = Text::from(
                lines
                    .iter()
                    .map(|line| {
                        Line::from(Span::styled(line.text.clone(), style_of(line.tone, mode)))
                    })
                    .collect::<Vec<Line<'static>>>(),
            );
            let scroll = match console.screen() {
                Screen::Supervision => console.supervision.scroll(),
                _ => console.scroll,
            };
            frame.render_widget(Paragraph::new(text).scroll((scroll, 0)), area);
        }
    }
}

/// Style for one tone: colour in [`ColorMode::Ansi`], modifiers only in
/// [`ColorMode::Mono`] (state never depends on colour alone).
fn style_of(tone: Tone, mode: ColorMode) -> Style {
    let mono = mode == ColorMode::Mono;
    match tone {
        Tone::Normal => Style::default(),
        Tone::Heading => Style::default().add_modifier(Modifier::BOLD),
        Tone::Muted => Style::default().add_modifier(Modifier::DIM),
        Tone::Warn => {
            if mono {
                Style::default().add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Yellow)
            }
        }
        Tone::Alert => {
            if mono {
                Style::default().add_modifier(Modifier::BOLD | Modifier::REVERSED)
            } else {
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
            }
        }
        Tone::Input => {
            if mono {
                Style::default().add_modifier(Modifier::REVERSED)
            } else {
                Style::default().fg(Color::Cyan)
            }
        }
    }
}

/// Classify one transport/daemon failure. A `client.*` code (other than a
/// connect failure, where no request was sent) and the claim-in-flight codes
/// leave the outcome unknown; everything else is a definite no-effect.
pub(crate) fn failure_outcome(code: &str, message: &str) -> AttemptOutcome {
    let uncertain = (code.starts_with("client.") && code != "client.connect")
        || code == "state.claim_reused"
        || code == "state.claim_incomplete";
    if uncertain {
        AttemptOutcome::Uncertain {
            code: code.to_string(),
            message: message.to_string(),
        }
    } else {
        AttemptOutcome::Refused {
            code: code.to_string(),
            message: message.to_string(),
        }
    }
}

/// The tone/text of one classified item verdict.
fn verdict_lines(verdict: &SubmissionVerdict) -> (Tone, String) {
    match verdict {
        SubmissionVerdict::Approved => (
            Tone::Normal,
            "eligible — the submission transaction decides admit-or-wait".to_string(),
        ),
        SubmissionVerdict::Waiting { code, message } => {
            (Tone::Warn, format!("waiting [{code}] {message}"))
        }
        SubmissionVerdict::Refused { code, message } => {
            (Tone::Alert, format!("refused [{code}] {message}"))
        }
    }
}

/// `yes`/`no`/`unknown` for a presented availability observation.
fn availability(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "available",
        Some(false) => "unavailable",
        None => "unknown",
    }
}

/// `N lanes`/`unknown` for a presented occupancy observation.
fn occupancy(value: Option<i64>) -> String {
    match value {
        Some(lanes) => format!("{lanes} lanes"),
        None => "unknown".to_string(),
    }
}

/// The rendered top-level holds of a preview document.
fn doc_holds(doc: &Val) -> Vec<String> {
    doc.get("holds")
        .and_then(Val::as_array)
        .map(|holds| {
            holds
                .iter()
                .map(|hold| {
                    format!(
                        "[{}] {} — {}",
                        hold.get("code").and_then(Val::as_str).unwrap_or("hold"),
                        hold.get("subject").and_then(Val::as_str).unwrap_or(""),
                        hold.get("message").and_then(Val::as_str).unwrap_or("")
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

/// The committed membership lines of a submission document.
fn submission_item_lines(doc: &Val) -> Vec<String> {
    doc.get("items")
        .and_then(Val::as_array)
        .map(|items| {
            items
                .iter()
                .map(|item| {
                    let id = item.get("id").and_then(Val::as_str).unwrap_or("item");
                    let status = item
                        .get("status")
                        .and_then(Val::as_str)
                        .unwrap_or("unknown");
                    let reason = item.get("reason").and_then(Val::as_str);
                    let instance = item.get("instance_id").and_then(Val::as_str);
                    match (reason, instance) {
                        (Some(reason), _) => format!("{id} {status} [{reason}]"),
                        (None, Some(instance)) => format!("{id} {status} -> run {instance}"),
                        (None, None) => format!("{id} {status}"),
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}

/// A fresh per-attempt idempotency key: a re-authorization is a fresh claim,
/// and the daemon's record-level refusals keep one owner per issue.
fn fresh_key() -> String {
    format!("ik_operator-{}-{}", unix_now(), client::fresh_id())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Harness;
    use crate::plan::DOCTRINE_WORKFLOW_ID;
    use crate::queue_preview as preview_service;
    use crate::queue_preview::{Boundary, PlannedStep, SelectedIssue};
    use crate::state::Retention;
    use crate::tui::{IssueKey, Selection};
    use crate::value::{null, string};

    const REPO: &str = "example-org/widgets";
    const REVISION: &str = "1111111111111111111111111111111111111111";
    const WORKFLOW_HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const POLICY_HASH: &str = "feedface01234567feedface01234567feedface01234567feedface01234567";

    struct Fixture {
        dir: PathBuf,
        state: State,
    }

    impl Fixture {
        fn new(name: &str) -> Fixture {
            let dir =
                std::env::temp_dir().join(format!("hf-operator-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("fixture dir");
            let state =
                State::open(&dir.join("state.db"), Retention::default()).expect("open state");
            Fixture { dir, state }
        }

        fn socket(&self) -> PathBuf {
            self.dir.join("daemon.sock")
        }
    }

    /// A credential-free harness: no declared credential is missing, so the
    /// binding re-observes cleanly without touching the process environment.
    fn harness() -> Harness {
        Harness {
            key: "lane-1".to_string(),
            kind: "argv".to_string(),
            executable: "fixture-harness".to_string(),
            env_allow: Vec::new(),
            provider: Some("provider-a".to_string()),
            model: Some("model-a".to_string()),
            fallback: Vec::new(),
            secret_env: Vec::new(),
            limits: Vec::new(),
            binding_introspection: false,
        }
    }

    fn config() -> Config {
        Config {
            path: PathBuf::from("canter.toml"),
            daemon_enabled: None,
            daemon_socket: None,
            policy: None,
            repositories: Vec::new(),
            harnesses: vec![harness()],
            workflows: Vec::new(),
        }
    }

    fn request() -> QueueRequest {
        QueueRequest {
            repository: REPO.to_string(),
            host: "host-1".to_string(),
            host_available: Some(true),
            harness_key: "lane-1".to_string(),
            harness_lanes: Some(0),
            caps: ConcurrencyCaps {
                global: 4,
                per_repository: 2,
                per_harness: 2,
            },
            workflow_id: DOCTRINE_WORKFLOW_ID.to_string(),
            workflow_hash: WORKFLOW_HASH.to_string(),
            role_config: ProfileBinding::from_config(&config(), "lane-1", &BTreeMap::new())
                .expect("binding")
                .to_doc(),
            boundary: Boundary {
                phase: "merge".to_string(),
                integration_branch: "staging".to_string(),
                completion_branch: "staging".to_string(),
                caps: vec!["read".to_string(), "merge".to_string()],
            },
            steps: vec![PlannedStep {
                id: "p1".to_string(),
                kind: "checkout".to_string(),
                params: Some(object(vec![("ref", string("staging"))])),
            }],
            selected: vec![SelectedIssue {
                id: "5".to_string(),
                title: None,
                revision: REVISION.to_string(),
                requires: Vec::new(),
            }],
        }
    }

    /// The reviewed bound-input document exactly as the preview service
    /// renders it (never hand-assembled).
    fn bound(state: &State) -> Val {
        preview_service::preview_queue(state, &request())
            .expect("preview")
            .doc
            .get("request")
            .cloned()
            .expect("bound document")
    }

    fn presented(state: &State) -> PresentedRun {
        let grant_id = seed_grant(state);
        let mut run = PresentedRun::new("fixture-plan", bound(state), request().caps);
        run.host_available = Some(true);
        run.harness_lanes = Some(0);
        run.grants = vec![ItemGrant {
            id: "5".to_string(),
            grant_id,
        }];
        run
    }

    /// Seed one active `hf-grant/v1` for issue 5 (no instance: the issue
    /// stays unowned) and return its id.
    fn seed_grant(state: &State) -> String {
        let epoch = state.current_epoch().expect("epoch");
        let grant_id = format!(
            "gr_{}",
            &crate::canonical::sha256_hex(b"operator-fixture")[..16]
        );
        let doc = Val::parse_json(&format!(
            r#"{{"schema":"hf-grant/v1","grant_id":"{grant_id}","repository":"{REPO}",
                "issue":{{"number":5,"revision":"{REVISION}"}},
                "workflow_hash":"{WORKFLOW_HASH}","policy_hash":"{POLICY_HASH}",
                "phase":"merge","scope":"worktrees/issues/5",
                "caps":["read","worktree","spawn","review","merge"],
                "expires_at":"2999-01-01T00:00:00Z","state_epoch":{epoch},
                "created_at":"2026-09-06T00:00:00Z"}}"#
        ))
        .expect("grant document");
        state.issue_grant(&doc).expect("issue grant");
        grant_id
    }

    /// The identity the board hands the console for work item `number`.
    fn selection(number: u64) -> Selection {
        Selection {
            issue: IssueKey {
                repository: REPO.to_string(),
                issue: number,
            },
            run: None,
        }
    }

    fn console<'a>(fixture: &'a Fixture) -> OperatorConsole<'a> {
        let mut console = OperatorConsole::new(
            &fixture.state,
            fixture.socket(),
            Some(config()),
            Some(presented(&fixture.state)),
        );
        console.ui.selected = Some(selection(5));
        console
    }

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::from(code)
    }

    fn preview(console: &mut OperatorConsole<'_>) {
        console.handle_key(key(KeyCode::Char('p')));
        assert_eq!(console.screen(), Screen::Preview, "preview screen");
        assert!(
            console.notice().is_none(),
            "no notice: {:?}",
            console.notice()
        );
    }

    fn authorize_screen(console: &mut OperatorConsole<'_>) {
        preview(console);
        console.handle_key(key(KeyCode::Enter));
        assert_eq!(console.screen(), Screen::Authorize);
    }

    #[test]
    fn no_presentation_means_no_preview_and_no_authorization() {
        let fixture = Fixture::new("no-plan");
        let mut console =
            OperatorConsole::new(&fixture.state, fixture.socket(), Some(config()), None);
        console.handle_key(key(KeyCode::Down));
        console.handle_key(key(KeyCode::Char('p')));
        assert_eq!(console.screen(), Screen::Board);
        assert_eq!(console.notice().expect("notice").code, CODE_PLAN);
        console.handle_key(key(KeyCode::Enter));
        assert_eq!(console.screen(), Screen::Board);
    }

    #[test]
    fn a_selection_outside_the_presented_plan_is_never_re_scoped() {
        let fixture = Fixture::new("not-bound");
        // The plan selects issue 5 of example-org/widgets. The board
        // selection is first a different issue, then the same number in a
        // different repository — neither is ever re-scoped into the plan.
        let mut console = console(&fixture);
        for (repository, issue) in [(REPO, 9u64), ("example-org/gadgets", 5)] {
            console.ui.selected = Some(Selection {
                issue: IssueKey {
                    repository: repository.to_string(),
                    issue,
                },
                run: None,
            });
            console.handle_key(key(KeyCode::Char('p')));
            assert_eq!(console.screen(), Screen::Board);
            assert_eq!(
                console.notice().expect("notice").code,
                CODE_NOT_BOUND,
                "{repository}#{issue}"
            );
            assert!(console.preview().is_none());
        }
    }

    #[test]
    fn the_preview_binds_the_exact_plan_and_the_authorization_scope() {
        let fixture = Fixture::new("preview");
        let mut console = console(&fixture);
        preview(&mut console);
        let facts = console.preview().expect("preview facts");
        assert!(
            facts.authorizable(),
            "one eligible item, holds: {:?}, items: {:?}",
            doc_holds(&facts.doc),
            facts.items
        );
        assert_eq!(facts.selected_ids(), vec![format!("{REPO}#5")]);
        assert_eq!(facts.epoch, fixture.state.current_epoch().expect("epoch"));
        // The digest is the bound-input document's digest, recomputed.
        assert_eq!(
            facts.digest,
            executor::bound_digest(&console.presented_run().expect("run").bound).expect("digest")
        );
        let text = console
            .lines(200)
            .into_iter()
            .map(|line| line.text)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(text.contains("AUTHORIZATION SCOPE"), "{text}");
        assert!(
            text.contains("boundary merge: staging -> staging"),
            "{text}"
        );
        assert!(text.contains(&format!("{REPO}#5")), "{text}");
        assert!(text.contains("preview only"), "{text}");
    }

    #[test]
    fn back_and_cancel_never_authorize_and_never_reach_the_submit_path() {
        let fixture = Fixture::new("back");
        let mut console = console(&fixture);
        preview(&mut console);
        // Every cancel key on the preview screen: back, never forward.
        for code in [KeyCode::Esc, KeyCode::Char('b')] {
            console.handle_key(key(code));
            assert_eq!(console.screen(), Screen::Board);
            assert!(console.attempt().is_none());
            assert!(console.preview().is_none());
            assert!(!console.authorized());
            preview(&mut console);
        }
        authorize_screen(&mut console);
        // Space alone never authorizes; Enter without the box never submits.
        console.handle_key(key(KeyCode::Char(' ')));
        assert!(console.authorized());
        console.handle_key(key(KeyCode::Esc));
        assert_eq!(console.screen(), Screen::Preview);
        assert!(!console.authorized(), "cancel clears the authorization");
        console.handle_key(key(KeyCode::Enter));
        console.handle_key(key(KeyCode::Enter));
        assert_eq!(console.screen(), Screen::Authorize);
        assert!(console.attempt().is_none(), "the box is not set");
        assert_eq!(console.notice().expect("notice").code, CODE_AUTHORIZATION);
        // The submit path is reachable only with the box set and Enter.
        console.handle_key(key(KeyCode::Char(' ')));
        console.handle_key(key(KeyCode::Enter));
        assert_eq!(console.screen(), Screen::Outcome);
        let attempt = console.attempt().expect("attempt");
        assert!(matches!(attempt.outcome, AttemptOutcome::Refused { .. }));
    }

    #[test]
    fn a_submit_that_cannot_connect_is_a_definite_no_effect() {
        let fixture = Fixture::new("no-daemon");
        let mut console = console(&fixture);
        authorize_screen(&mut console);
        console.handle_key(key(KeyCode::Char(' ')));
        console.handle_key(key(KeyCode::Enter));
        let attempt = console.attempt().expect("attempt");
        match &attempt.outcome {
            AttemptOutcome::Refused { code, .. } => assert_eq!(code, "client.connect"),
            other => panic!("expected a connect refusal, got {other:?}"),
        }
        assert!(!fixture.socket().exists(), "the surface created no socket");
        assert!(!console.authorized(), "the authorization is consumed");
    }

    #[test]
    fn an_epoch_rotation_between_preview_and_authorization_refuses_and_sends_nothing() {
        let fixture = Fixture::new("epoch");
        let mut console = console(&fixture);
        authorize_screen(&mut console);
        let shown = console.preview().expect("preview").epoch;
        fixture
            .state
            .rotate_epoch("security_rotation")
            .expect("rotate");
        console.handle_key(key(KeyCode::Char(' ')));
        console.handle_key(key(KeyCode::Enter));
        assert_eq!(console.screen(), Screen::Authorize, "no submission");
        assert!(console.attempt().is_none(), "nothing was sent");
        assert!(!console.authorized(), "the authorization is cleared");
        let notice = console.notice().expect("notice");
        assert_eq!(notice.code, "refusal.state.epoch");
        assert!(
            notice.message.contains(&format!("epoch {shown}")),
            "{notice:?}"
        );
        let text = console
            .lines(200)
            .into_iter()
            .map(|line| line.text)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            text.contains("refusal.state.epoch"),
            "the staleness refusal must be visible on the authorization screen: {text}"
        );
    }

    #[test]
    fn a_resize_clears_the_authorization_but_keeps_the_selection() {
        let fixture = Fixture::new("resize");
        let mut console = console(&fixture);
        authorize_screen(&mut console);
        console.handle_key(key(KeyCode::Char(' ')));
        assert!(console.authorized());
        console.on_resize();
        assert!(!console.authorized(), "a resize clears the authorization");
        assert_eq!(console.screen(), Screen::Authorize, "the screen survives");
        assert_eq!(
            console.notice().expect("notice").code,
            CODE_AUTHORIZATION,
            "the operator is told why"
        );
        assert!(
            console.ui_state().selected.is_some(),
            "the selection survives"
        );
        // Space sets it again, and Enter then authorizes the same preview.
        console.handle_key(key(KeyCode::Char(' ')));
        assert!(console.authorized());
    }

    #[test]
    fn a_held_item_never_reaches_the_authorization_screen() {
        let fixture = Fixture::new("held");
        let mut run = presented(&fixture.state);
        run.host_available = None;
        run.harness_lanes = None;
        let mut console =
            OperatorConsole::new(&fixture.state, fixture.socket(), Some(config()), Some(run));
        console.ui.selected = Some(selection(5));
        preview(&mut console);
        assert!(!console.preview().expect("preview").authorizable());
        console.handle_key(key(KeyCode::Enter));
        assert_eq!(
            console.screen(),
            Screen::Preview,
            "held work never proceeds"
        );
        assert_eq!(console.notice().expect("notice").code, CODE_HELD);
        let text = console
            .lines(200)
            .into_iter()
            .map(|line| line.text)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(text.contains("preview.occupancy_unknown"), "{text}");
        assert!(
            text.contains(CODE_HELD),
            "the refusal must be visible on the preview screen: {text}"
        );
    }

    #[test]
    fn an_unconfirmed_attempt_is_reported_as_unknown_and_never_replayed() {
        let fixture = Fixture::new("unknown");
        // A peer that accepts the request and drops the connection without a
        // response: the request may have reached the daemon and is not
        // confirmed — the uncertain class, with no timeout to wait for.
        let listener = std::os::unix::net::UnixListener::bind(fixture.socket())
            .expect("bind fixture listener");
        let peer = std::thread::spawn(move || {
            let _ = listener.accept();
        });
        let mut console = console(&fixture);
        authorize_screen(&mut console);
        console.handle_key(key(KeyCode::Char(' ')));
        console.handle_key(key(KeyCode::Enter));
        peer.join().expect("peer thread");
        let attempt = console.attempt().expect("attempt");
        match &attempt.outcome {
            // Either a dropped write or a dropped connection: both are the
            // unconfirmed class (the closed-set rule is pinned separately).
            AttemptOutcome::Uncertain { code, .. } => {
                assert!(code.starts_with("client."), "transport class: {code}")
            }
            other => panic!("expected an unconfirmed outcome, got {other:?}"),
        }
        // Readback stays honest: the attempt is unchanged and nothing is
        // re-sent (the listener is gone, so the read cannot connect).
        let submission_id = attempt.submission_id.clone();
        let digest = attempt.digest.clone();
        console.handle_key(key(KeyCode::Char('r')));
        let attempt = console.attempt().expect("attempt");
        assert_eq!(attempt.submission_id, submission_id);
        assert_eq!(attempt.digest, digest);
        assert!(
            console.notice().is_some(),
            "the readback failure is displayed"
        );
        let text = console
            .lines(200)
            .into_iter()
            .map(|line| line.text)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(text.contains("UNKNOWN"), "{text}");
        assert!(text.contains("will not replay"), "{text}");
        // And the only way to authorize again is a fresh preview + box.
        console.handle_key(key(KeyCode::Char('b')));
        assert_eq!(console.screen(), Screen::Board);
        assert!(console.attempt().is_none());
    }

    #[test]
    fn transport_failure_classes_are_closed() {
        assert!(matches!(
            failure_outcome("client.connect", "no socket"),
            AttemptOutcome::Refused { .. }
        ));
        assert!(matches!(
            failure_outcome("client.read", "EAGAIN"),
            AttemptOutcome::Uncertain { .. }
        ));
        assert!(matches!(
            failure_outcome("state.claim_reused", "key spent"),
            AttemptOutcome::Uncertain { .. }
        ));
        assert!(matches!(
            failure_outcome("state.claim_incomplete", "in flight"),
            AttemptOutcome::Uncertain { .. }
        ));
        assert!(matches!(
            failure_outcome("refusal.plan.stale", "moved"),
            AttemptOutcome::Refused { .. }
        ));
        assert!(matches!(
            failure_outcome("refusal.state.epoch", "rotated"),
            AttemptOutcome::Refused { .. }
        ));
    }

    #[test]
    fn the_outcome_screen_separates_requested_from_observed() {
        let fixture = Fixture::new("outcome");
        let mut console = console(&fixture);
        authorize_screen(&mut console);
        console.handle_key(key(KeyCode::Char(' ')));
        console.handle_key(key(KeyCode::Enter));
        let text = console
            .lines(200)
            .into_iter()
            .map(|line| line.text)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(text.contains("REQUESTED"), "{text}");
        assert!(text.contains("OBSERVED"), "{text}");
        assert!(text.contains("NOT APPLIED"), "{text}");
        assert!(text.contains(&format!("{REPO}#5")), "{text}");
    }

    #[test]
    fn the_board_screen_has_no_lines_and_renders_the_notice_strip() {
        let fixture = Fixture::new("board-lines");
        let mut console =
            OperatorConsole::new(&fixture.state, fixture.socket(), Some(config()), None);
        console.handle_key(key(KeyCode::Char('p')));
        assert_eq!(console.screen(), Screen::Board);
        assert!(console.lines(80).is_empty());
        let strip = console.notice_line(80).expect("notice strip");
        assert!(strip.text.contains(CODE_PLAN), "{strip:?}");
    }

    #[test]
    fn selection_identity_binding_is_case_insensitive_and_exact() {
        let fixture = Fixture::new("identity");
        let mut console = console(&fixture);
        console.ui.selected = Some(Selection {
            issue: IssueKey {
                repository: REPO.to_ascii_uppercase(),
                issue: 5,
            },
            run: None,
        });
        preview(&mut console);
        assert_eq!(console.screen(), Screen::Preview);
        assert!(console.notice().is_none());
    }

    #[test]
    fn a_null_bound_document_is_refused_typed_before_any_call() {
        let fixture = Fixture::new("null-bound");
        let mut run = PresentedRun::new("fixture-plan", object(vec![]), request().caps);
        run.bound = null();
        let mut console =
            OperatorConsole::new(&fixture.state, fixture.socket(), Some(config()), Some(run));
        console.ui.selected = Some(selection(5));
        console.handle_key(key(KeyCode::Char('p')));
        assert_eq!(console.screen(), Screen::Board);
        assert_eq!(
            console.notice().expect("notice").code,
            "usage.queue_submission.preview"
        );
        assert!(console.attempt().is_none());
    }
}
