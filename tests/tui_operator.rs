//! Issue #91 acceptance tests: the operator authority path — exact
//! selection, exact preview, explicit authorization and a daemon-owned run.
//!
//! Every test drives the real `canter::tui::operator` surface over the real
//! `canter` binary's daemon (the `tests/queue_submit.rs` fixture pattern):
//! a per-test temp state directory, a spawned `canter daemon run` child on
//! an explicit socket, a real seeded `hf-grant/v1` and a real recorded run.
//! Nothing here is a fixture view model: the preview is the #84 service's
//! own document, the submission goes through `queue.submit` over the
//! daemon socket (the same params document the CLI builds), and the observed
//! facts are read back from the daemon. Synthetic identities only.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use canter::client::Connection;
use canter::config::{Config, Harness, ProfileBinding};
use canter::lifecycle::ConcurrencyCaps;
use canter::plan::DOCTRINE_WORKFLOW_ID;
use canter::queue_executor::ItemGrant;
use canter::queue_preview as qp;
use canter::state::{Retention, State};
use canter::tui::operator::{AttemptOutcome, OperatorConsole, PresentedRun, Screen};
use canter::tui::{Action, ColorMode, ReadModel};
use canter::value::{Val, object, string};
use ratatui::Terminal;
use ratatui::backend::TestBackend;
use ratatui::crossterm::event::{KeyCode, KeyEvent};

// ---------------------------------------------------------------------------
// Constants and builders (synthetic identities only)
// ---------------------------------------------------------------------------

const REPO: &str = "example-org/widgets";
const REVISION: &str = "1111111111111111111111111111111111111111";
const WORKFLOW_HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const POLICY_HASH: &str = "feedface01234567feedface01234567feedface01234567feedface01234567";
const SEEDED_RUN: &str = "run-seeded-0001";

/// The configured role the plan and the surface both re-observe. It declares
/// no credential environment, so the surface needs no process environment to
/// re-observe the reviewed revision.
fn config() -> Config {
    Config {
        path: PathBuf::from("canter.toml"),
        daemon_enabled: None,
        daemon_socket: None,
        policy: None,
        repositories: Vec::new(),
        harnesses: vec![Harness {
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
            skills: Vec::new(),
        }],
        workflows: Vec::new(),
        skills: Vec::new(),
    }
}

fn binding_doc() -> Val {
    ProfileBinding::from_config(&config(), "lane-1", &std::collections::BTreeMap::new())
        .expect("the role skills resolve")
        .expect("binding")
        .to_doc()
}

fn caps() -> ConcurrencyCaps {
    ConcurrencyCaps {
        global: 4,
        per_repository: 2,
        per_harness: 2,
    }
}

fn request() -> qp::QueueRequest {
    qp::QueueRequest {
        repository: REPO.to_string(),
        host: "host-1".to_string(),
        host_available: Some(true),
        harness_key: "lane-1".to_string(),
        harness_lanes: Some(0),
        caps: caps(),
        workflow_id: DOCTRINE_WORKFLOW_ID.to_string(),
        workflow_hash: WORKFLOW_HASH.to_string(),
        role_config: binding_doc(),
        boundary: qp::Boundary {
            phase: "merge".to_string(),
            integration_branch: "staging".to_string(),
            completion_branch: "staging".to_string(),
            caps: vec!["read".to_string(), "merge".to_string()],
        },
        steps: vec![qp::PlannedStep {
            id: "p1".to_string(),
            kind: "checkout".to_string(),
            params: Some(object(vec![("ref", string("staging"))])),
        }],
        selected: vec![qp::SelectedIssue {
            id: "5".to_string(),
            title: None,
            revision: REVISION.to_string(),
            requires: Vec::new(),
        }],
    }
}

/// The exact bound-input document the preview service renders (never
/// hand-assembled): the material a reviewed run is presented as.
fn bound(state: &State) -> Val {
    qp::preview_queue(state, &request())
        .expect("preview renders")
        .doc
        .get("request")
        .cloned()
        .expect("bound-input document")
}

fn grant_id() -> String {
    format!(
        "gr_{}",
        &canter::canonical::sha256_hex(b"operator-91-grant")[..16]
    )
}

fn grant_doc(epoch: i64) -> Val {
    Val::parse_json(&format!(
        r#"{{"schema":"hf-grant/v1","grant_id":"{id}","repository":"{REPO}",
            "issue":{{"number":5,"revision":"{REVISION}"}},
            "workflow_hash":"{WORKFLOW_HASH}","policy_hash":"{POLICY_HASH}",
            "phase":"merge","scope":"worktrees/issues/5",
            "caps":["read","worktree","spawn","review","merge"],
            "expires_at":"2999-01-01T00:00:00Z","state_epoch":{epoch},
            "created_at":"2026-09-06T00:00:00Z"}}"#,
        id = grant_id()
    ))
    .expect("grant document")
}

/// One presented run: the reviewed plan plus the observations the operator
/// presents (the CLI's `queue submit` argv), with the real grant binding.
fn presented(state: &State) -> PresentedRun {
    let mut run = PresentedRun::new("reviewed-run-plan", bound(state), caps());
    run.host_available = Some(true);
    run.harness_lanes = Some(0);
    run.grants = vec![ItemGrant {
        id: "5".to_string(),
        grant_id: grant_id(),
    }];
    run
}

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::from(code)
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("hf-operator-91-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("fixture dir");
    dir
}

struct Fixture {
    dir: PathBuf,
    state_dir: PathBuf,
    socket: PathBuf,
}

impl Fixture {
    /// A fixture seeded exactly like the daemon finds it: one active grant
    /// and one recorded run for issue 5 that already left the owned set
    /// (`done`), so the issue is free for a fresh attempt.
    fn seeded(name: &str) -> Fixture {
        let dir = temp_dir(name);
        let fixture = Fixture {
            state_dir: dir.join("state"),
            socket: dir.join("daemon.sock"),
            dir,
        };
        std::fs::create_dir_all(fixture.state_dir.join("canter")).expect("state dir");
        {
            let state = fixture.open();
            let epoch = state.current_epoch().expect("epoch");
            state.issue_grant(&grant_doc(epoch)).expect("issue grant");
            state
                .start_instance(
                    SEEDED_RUN,
                    &grant_id(),
                    DOCTRINE_WORKFLOW_ID,
                    "2026-09-06T00:00:00Z",
                )
                .expect("start instance");
            // The reported-done record: no public API writes `done` yet (the
            // same seed `tests/board_read_model.rs` uses).
            let raw = rusqlite::Connection::open(fixture.db()).expect("raw open");
            raw.execute(
                "UPDATE instances SET status = 'done', current_node = 'merge', updated_at = ?2
                  WHERE instance_id = ?1",
                rusqlite::params![SEEDED_RUN, "2026-09-06T00:00:05Z"],
            )
            .expect("seed reported done");
        }
        fixture
    }

    fn db(&self) -> PathBuf {
        self.state_dir.join("canter").join("state.db")
    }

    fn open(&self) -> State {
        State::open(&self.db(), Retention::default()).expect("open state")
    }

    fn spawn(&self) -> Child {
        std::fs::create_dir_all(&self.state_dir).expect("state home");
        Command::new(bin())
            .args(["daemon", "run", "--socket"])
            .arg(&self.socket)
            .env("XDG_STATE_HOME", &self.state_dir)
            .env("HOME", &self.dir)
            .stdout(Stdio::null())
            .stderr(Stdio::from(
                std::fs::File::create(self.dir.join("daemon.stderr.log")).expect("stderr log"),
            ))
            .spawn()
            .expect("spawn daemon")
    }
}

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_canter")
}

fn wait_ready(fixture: &Fixture) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if canter::lock::socket_presence(&fixture.socket) == canter::lock::SocketPresence::Active {
            let ok = Connection::open(&fixture.socket)
                .and_then(|mut connection| {
                    connection.send_request("aaaaaaaaaaaaaaaa", "status", None)?;
                    connection.read_response()
                })
                .map(|response| response.ok)
                .unwrap_or(false);
            if ok {
                return;
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let stderr = std::fs::read_to_string(fixture.dir.join("daemon.stderr.log")).unwrap_or_default();
    panic!(
        "daemon did not become ready on {}; stderr:\n{stderr}",
        fixture.socket.display()
    );
}

fn shutdown(mut daemon: Child) {
    let _ = daemon.kill();
    let deadline = Instant::now() + Duration::from_secs(10);
    while daemon.try_wait().expect("try_wait").is_none() {
        assert!(Instant::now() < deadline, "daemon did not exit");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// A fresh connection RPC (the test's own client, never the console's).
fn rpc(socket: &Path, id: &str, method: &str, params: Option<Val>) -> Val {
    let mut connection = Connection::open(socket).expect("connect");
    connection
        .send_request(id, method, params.as_ref())
        .expect("send");
    let response = connection.read_response().expect("read response");
    if response.ok {
        object(vec![("ok", Val::Bool(true)), ("result", response.result)])
    } else {
        let error = response.error.unwrap_or_else(|| canter::client::RpcError {
            code: "missing.error".to_string(),
            message: "no error doc".to_string(),
        });
        object(vec![
            ("ok", Val::Bool(false)),
            (
                "error",
                object(vec![
                    ("code", string(&error.code)),
                    ("message", string(&error.message)),
                ]),
            ),
        ])
    }
}

fn rpc_ok(socket: &Path, id: &str, method: &str, params: Option<Val>) -> Val {
    let doc = rpc(socket, id, method, params);
    assert_eq!(
        doc.get("ok").and_then(Val::as_bool),
        Some(true),
        "expected ok for {method}: {}",
        canter::canonical::canonical_text(&doc)
    );
    doc.get("result").expect("result").clone()
}

fn select_first_row(console: &mut OperatorConsole<'_>) {
    assert!(
        console.handle_key(key(KeyCode::Down)).is_some(),
        "the board accepts navigation"
    );
    assert!(
        console.ui_state().selected.is_some(),
        "a recorded run is selectable on the board"
    );
}

fn item_of(doc: &Val, number: i64) -> &Val {
    let target = format!("{REPO}#{number}");
    doc.get("items")
        .and_then(Val::as_array)
        .expect("items")
        .iter()
        .find(|item| item.get("id").and_then(Val::as_str) == Some(target.as_str()))
        .unwrap_or_else(|| {
            panic!(
                "item {target} present: {}",
                canter::canonical::canonical_text(doc)
            )
        })
}

fn text_of(doc: &Val, key: &str) -> String {
    doc.get(key)
        .and_then(Val::as_str)
        .unwrap_or_default()
        .to_string()
}

// ---------------------------------------------------------------------------
// The full operator path
// ---------------------------------------------------------------------------

#[test]
fn the_operator_path_previews_authorizes_and_reads_a_daemon_owned_run_back() {
    let fixture = Fixture::seeded("full-path");
    let daemon = fixture.spawn();
    wait_ready(&fixture);
    let state = fixture.open();
    let console_config = config();

    // -- exact selection on the board -------------------------------------
    let mut console = OperatorConsole::new(
        &state,
        fixture.socket.clone(),
        Some(console_config.clone()),
        Some(presented(&state)),
    );
    assert_eq!(console.screen(), Screen::Board);
    assert_eq!(console.snapshot().rows.len(), 1, "one recorded run");
    select_first_row(&mut console);
    let selected = console.ui_state().selected.clone().expect("selection");
    assert_eq!(selected.issue.repository, REPO);
    assert_eq!(selected.issue.issue, 5);

    // -- exact preview ----------------------------------------------------
    console.handle_key(key(KeyCode::Char('p')));
    assert_eq!(console.screen(), Screen::Preview, "{:?}", console.notice());
    let facts = console.preview().expect("preview facts").clone();
    assert!(facts.authorizable(), "{:?}", facts.items);
    assert_eq!(
        facts.digest,
        canter::queue_preview::digest_of(&console.presented_run().expect("run").bound),
        "the preview digest binds the presented document"
    );
    let preview_text = console_lines(&console, 200);
    assert!(
        preview_text.contains("AUTHORIZATION SCOPE"),
        "{preview_text}"
    );
    assert!(
        preview_text.contains(&format!("{REPO}#5")),
        "{preview_text}"
    );

    // -- explicit authorization -------------------------------------------
    console.handle_key(key(KeyCode::Enter));
    assert_eq!(
        console.screen(),
        Screen::Authorize,
        "{:?}",
        console.notice()
    );
    console.handle_key(key(KeyCode::Char(' ')));
    assert!(console.authorized());
    console.handle_key(key(KeyCode::Enter));
    assert_eq!(console.screen(), Screen::Outcome, "{:?}", console.notice());

    let attempt = console.attempt().expect("attempt").clone();
    assert!(
        attempt.submission_id.starts_with("qs_"),
        "{:?}",
        attempt.submission_id
    );
    assert_eq!(attempt.digest, facts.digest);
    let doc = attempt
        .outcome
        .observed_doc()
        .expect("the daemon confirmed the submission")
        .clone();
    assert!(
        !text_of(&doc, "statement").is_empty(),
        "the committed document carries its statement"
    );
    let item = item_of(&doc, 5);
    assert_eq!(
        item.get("status").and_then(Val::as_str),
        Some("admitted"),
        "{}",
        canter::canonical::canonical_text(&doc)
    );
    let admitted_run = item
        .get("instance_id")
        .and_then(Val::as_str)
        .expect("admitted item names its run")
        .to_string();
    assert_ne!(admitted_run, SEEDED_RUN, "a fresh run was admitted");

    // The daemon owned the effect: an independent client reads the same
    // committed submission back over its own connection.
    let readback = rpc_ok(
        &fixture.socket,
        "bbbbbbbbbbbbbbbb",
        "queue.status",
        Some(object(vec![(
            "submission_id",
            string(&attempt.submission_id),
        )])),
    );
    assert_eq!(
        canter::canonical::canonical_text(&readback),
        canter::canonical::canonical_text(&doc)
    );

    // The recorded rows are real: two runs (the seeded one and the admitted
    // one) and exactly one ownership row for the issue.
    let rows = state.list_instances().expect("instances");
    assert_eq!(rows.len(), 2, "the admitted run is a real instance row");
    assert!(
        rows.iter().any(|row| row.instance_id == admitted_run),
        "the admitted run is durable"
    );
    assert_eq!(
        state.queue_ownership_rows().expect("ownership").len(),
        1,
        "one owner per issue"
    );

    // -- the surface's own readback stays honest --------------------------
    console.handle_key(key(KeyCode::Char('r')));
    assert!(matches!(
        console.attempt().expect("attempt").outcome,
        AttemptOutcome::Observed { .. }
    ));

    // -- terminal closes: the daemon keeps the run -------------------------
    console.handle_key(key(KeyCode::Char('b')));
    assert_eq!(console.screen(), Screen::Board);
    drop(console);

    // A reopened surface reads REAL state: a fresh console sees both
    // recorded runs and performs no submission of its own.
    let mut reopened = OperatorConsole::new(
        &state,
        fixture.socket.clone(),
        Some(console_config),
        Some(presented(&state)),
    );
    assert_eq!(
        reopened.snapshot().rows.len(),
        2,
        "recorded runs are visible"
    );
    assert!(reopened.attempt().is_none(), "a reopen replays nothing");
    select_first_row(&mut reopened);
    reopened.handle_key(key(KeyCode::Char('p')));
    // Whichever row is selected, a fresh preview of issue 5 is held: the
    // issue has a live owner, so the surface offers no second start.
    if reopened.screen() == Screen::Preview {
        assert!(
            !reopened.preview().expect("preview").authorizable(),
            "a live owner keeps the item out of the authorizable set"
        );
        reopened.handle_key(key(KeyCode::Enter));
        assert_eq!(
            reopened.screen(),
            Screen::Preview,
            "held work never proceeds"
        );
    }
    assert!(reopened.attempt().is_none(), "no replay on reopen");

    shutdown(daemon);
}

fn console_lines(console: &OperatorConsole<'_>, width: usize) -> String {
    console
        .lines(width)
        .into_iter()
        .map(|line| line.text)
        .collect::<Vec<_>>()
        .join("\n")
}

// ---------------------------------------------------------------------------
// Rendered frames (the screens are what the operator sees)
// ---------------------------------------------------------------------------

fn render_text(console: &OperatorConsole<'_>, size: (u16, u16)) -> String {
    let mut terminal = Terminal::new(TestBackend::new(size.0, size.1)).expect("test terminal");
    terminal
        .draw(|frame| canter::tui::operator::draw(console, ColorMode::Mono, frame))
        .expect("draw");
    let buffer = terminal.backend().buffer();
    let area = *buffer.area();
    (0..area.height)
        .map(|y| {
            let line: String = (0..area.width)
                .map(|x| buffer[(x, y)].symbol().to_string())
                .collect();
            line.trim_end().to_string()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn the_screens_render_the_exact_plan_the_scope_and_the_observed_facts() {
    let fixture = Fixture::seeded("render");
    let state = fixture.open();
    let mut console = OperatorConsole::new(
        &state,
        fixture.socket.clone(),
        Some(config()),
        Some(presented(&state)),
    );
    select_first_row(&mut console);

    // The board screen renders the recorded run (plus the notice strip when
    // a notice exists).
    let board = render_text(&console, (120, 40));
    assert!(
        board.contains(&format!("{REPO}#5")) || board.contains(SEEDED_RUN),
        "{board}"
    );

    // The preview frame shows the exact plan, the authorization scope and
    // the preview-only statement.
    console.handle_key(key(KeyCode::Char('p')));
    let preview = render_text(&console, (120, 40));
    assert!(preview.contains("PREVIEW"), "{preview}");
    assert!(preview.contains("AUTHORIZATION SCOPE"), "{preview}");
    assert!(preview.contains(&format!("{REPO}#5")), "{preview}");
    assert!(preview.contains("preview only"), "{preview}");

    // The authorization frame shows the unchecked box, then the checked one.
    console.handle_key(key(KeyCode::Enter));
    let authorize = render_text(&console, (120, 40));
    assert!(authorize.contains("AUTHORIZATION"), "{authorize}");
    assert!(authorize.contains("[ ] authorize"), "{authorize}");
    console.handle_key(key(KeyCode::Char(' ')));
    let authorize = render_text(&console, (120, 40));
    assert!(authorize.contains("[x] authorize"), "{authorize}");

    // With no daemon the outcome frame separates requested from observed and
    // states the definite no-effect refusal.
    console.handle_key(key(KeyCode::Enter));
    let outcome = render_text(&console, (120, 40));
    assert!(outcome.contains("REQUESTED"), "{outcome}");
    assert!(outcome.contains("OBSERVED"), "{outcome}");
    assert!(outcome.contains("NOT APPLIED"), "{outcome}");
    assert!(outcome.contains("client.connect"), "{outcome}");
}

// ---------------------------------------------------------------------------
// Authorization is the ONE key that writes
// ---------------------------------------------------------------------------

#[test]
fn no_other_key_authorizes_and_cancellation_writes_nothing() {
    let fixture = Fixture::seeded("cancel");
    let daemon = fixture.spawn();
    wait_ready(&fixture);
    let state = fixture.open();

    let mut console = OperatorConsole::new(
        &state,
        fixture.socket.clone(),
        Some(config()),
        Some(presented(&state)),
    );
    select_first_row(&mut console);

    // Every key that is not the explicit authorization: navigation, the
    // preview, cancel/back on every screen, the readback and quit.
    for code in [
        KeyCode::Down,
        KeyCode::Up,
        KeyCode::Tab,
        KeyCode::BackTab,
        KeyCode::Left,
        KeyCode::Right,
        KeyCode::Char('j'),
        KeyCode::Char('k'),
        KeyCode::Enter, // board: no-op; preview: continue
    ] {
        console.handle_key(key(code));
    }
    console.handle_key(key(KeyCode::Char('p')));
    assert_eq!(console.screen(), Screen::Preview, "{:?}", console.notice());
    console.handle_key(key(KeyCode::Enter));
    assert_eq!(
        console.screen(),
        Screen::Authorize,
        "{:?}",
        console.notice()
    );
    // Space sets the box, but only Enter authorizes; every exit clears it.
    for code in [
        KeyCode::Esc,
        KeyCode::Char('b'),
        KeyCode::Char(' '),
        KeyCode::Char('r'),
        KeyCode::Char('x'),
    ] {
        console.handle_key(key(code));
    }
    assert!(!console.authorized(), "cancel clears the authorization");
    assert!(console.attempt().is_none(), "no attempt exists");
    // Quit from every screen is a quit, never an authorization.
    assert!(matches!(
        console.handle_key(key(KeyCode::Char('q'))),
        Some(Action::Quit)
    ));
    assert!(console.attempt().is_none());

    shutdown(daemon);

    // Nothing was written: one seeded run, no ownership row, no submission.
    let state = fixture.open();
    let rows = state.list_instances().expect("instances");
    assert_eq!(rows.len(), 1, "no run was admitted");
    assert_eq!(rows[0].instance_id, SEEDED_RUN);
    assert_eq!(
        state.queue_ownership_rows().expect("ownership").len(),
        0,
        "cancellation performs no write"
    );
}

// ---------------------------------------------------------------------------
// Real terminal: the operator path through a pseudo-terminal
// ---------------------------------------------------------------------------

/// Markers + paths the PTY child reads; set only for the re-executed child,
/// so a normal test run is untouched.
const CHILD_MARKER: &str = "CANTER_OPERATOR_PTY_CHILD";
const CHILD_DB: &str = "CANTER_OPERATOR_PTY_DB";
const CHILD_SOCKET: &str = "CANTER_OPERATOR_PTY_SOCKET";
const CHILD_PLAN: &str = "CANTER_OPERATOR_PTY_PLAN";

/// Child entry: re-executed under a real pseudo-terminal by the PTY test.
///
/// A no-op in a normal run (the marker is absent). The PTY test selects this
/// test by name with `--exact`, so the child runs exactly one thing: the real
/// operator session over the real daemon socket and the reviewed plan file.
#[test]
fn pty_child_operator_entry() {
    if std::env::var_os(CHILD_MARKER).is_none() {
        return;
    }
    let db = std::env::var(CHILD_DB).expect("child state path");
    let socket = std::env::var(CHILD_SOCKET).expect("child socket path");
    let plan = std::env::var(CHILD_PLAN).expect("child plan path");
    let state = State::open(Path::new(&db), Retention::default()).expect("child state store");
    let bound = Val::parse_json(&std::fs::read_to_string(&plan).expect("child plan"))
        .expect("reviewed plan document");
    let mut run = PresentedRun::new("reviewed-run-plan", bound, caps());
    run.host_available = Some(true);
    run.harness_lanes = Some(0);
    run.grants = vec![ItemGrant {
        id: "5".to_string(),
        grant_id: grant_id(),
    }];
    let mut console =
        OperatorConsole::new(&state, PathBuf::from(socket), Some(config()), Some(run));
    canter::tui::session::run_operator(&mut console).expect("the operator session runs");
}

#[test]
fn a_real_terminal_selects_previews_authorizes_and_starts_a_daemon_owned_run() {
    let fixture = Fixture::seeded("pty-run");
    let daemon = fixture.spawn();
    wait_ready(&fixture);
    let state = fixture.open();
    // The reviewed plan material is presented as a document (the shape
    // `queue submit --request` reads): the child loads it, never rebuilds it.
    let plan_path = fixture.dir.join("reviewed-plan.json");
    std::fs::write(
        &plan_path,
        canter::canonical::canonical_text(&bound(&state)),
    )
    .expect("plan file");
    let db = fixture.db().to_str().expect("utf-8 path").to_string();
    let socket = fixture.socket.to_str().expect("utf-8 path").to_string();
    let plan = plan_path.to_str().expect("utf-8 path").to_string();

    let run = pty::run(
        &[
            (CHILD_MARKER, "1"),
            (CHILD_DB, db.as_str()),
            (CHILD_SOCKET, socket.as_str()),
            (CHILD_PLAN, plan.as_str()),
            ("TERM", "xterm-256color"),
        ],
        &[
            "--nocapture",
            "--test-threads",
            "1",
            "--exact",
            "pty_child_operator_entry",
        ],
        // j (select the recorded run), p (exact preview), Enter (continue),
        // Space (explicit authorization), Enter (authorize), q (quit).
        b"jp\x0d \x0dq",
    )
    .expect("pty run");

    let text = strip_ansi(&run.output);
    for line in text.lines().take(24) {
        println!("|{line}|");
    }
    assert_eq!(run.exit_code, 0, "captured frame:\n{text}");
    assert!(
        contains_content(&text, "Canter operator board"),
        "the board frame: {text}"
    );
    assert!(
        contains_content(&text, "PREVIEW"),
        "the preview frame: {text}"
    );
    assert!(
        contains_content(&text, "AUTHORIZATION SCOPE"),
        "the authorization scope: {text}"
    );
    // The unchecked authorization box is in the emitted frame. The checked
    // state ([x]) is a one-cell diff, so a real terminal receives only the
    // changed cell — it is pinned by the fixed-size frame test above
    // (`the_screens_render_the_exact_plan_the_scope_and_the_observed_facts`).
    assert!(contains_content(&text, "[ ] authorize"), "{text}");

    // The run the terminal authorized is daemon-owned and REAL: the daemon
    // holds the submission, the admitted run and the single ownership row,
    // and the id the terminal displayed is the id the durable row names.
    let ownership = state.queue_ownership_rows().expect("ownership");
    assert_eq!(ownership.len(), 1, "exactly one admitted owner");
    let submission_id = ownership[0].submission_id.clone();
    let displayed: Vec<String> = text
        .split("qs_")
        .skip(1)
        .map(|tail| tail.chars().take(16).collect::<String>())
        .collect();
    assert!(
        contains_content(&text, "admitted"),
        "the observed admission: {text}"
    );
    let expected_id = submission_id.trim_start_matches("qs_").to_string();
    assert!(
        displayed.contains(&expected_id),
        "the outcome frame must carry the committed submission id {submission_id}: {text}"
    );
    let doc = rpc_ok(
        &fixture.socket,
        "cccccccccccccccc",
        "queue.status",
        Some(object(vec![("submission_id", string(&submission_id))])),
    );
    let item = item_of(&doc, 5);
    assert_eq!(item.get("status").and_then(Val::as_str), Some("admitted"));
    assert_ne!(
        item.get("instance_id").and_then(Val::as_str),
        Some(SEEDED_RUN)
    );
    assert_eq!(state.list_instances().expect("instances").len(), 2);

    shutdown(daemon);
}

/// Minimal real pseudo-terminal harness (the `tests/tui_live_wiring.rs`
/// shape): `forkpty` gives the child a genuine controlling terminal, which is
/// what Crossterm's raw-mode path needs; the parent captures every byte the
/// terminal emits and writes the key bytes back once the first frame is
/// drawn.
mod pty {
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
        // The libc signature takes `*mut winsize` on BSD/macOS and
        // `*const winsize` on Linux; an explicit raw pointer satisfies both.
        let winsize_ptr: *mut libc::winsize = &raw mut winsize;
        let mut master: libc::c_int = -1;
        // SAFETY: `forkpty` is the POSIX pseudo-terminal fork; the child only
        // execve/_exit before replacing its image.
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

/// Whether a captured frame carries `needle`, ignoring whitespace: a real
/// terminal legitimately receives fewer bytes than the cell grid (Ratatui's
/// diff skips blank default cells), so PTY assertions compare content.
fn contains_content(text: &str, needle: &str) -> bool {
    let squash = |value: &str| -> String { value.chars().filter(|c| !c.is_whitespace()).collect() };
    squash(text).contains(&squash(needle))
}
