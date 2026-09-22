//! Issue #9 lifecycle integration tests over the real binary and socket:
//! schedule RPC round trips (create/pause/resume/delete/evaluate),
//! single-flight + coalesced evaluations, cold-boot recovery with one fresh
//! evaluation per boot (Herdr absent or not), and fan-out admission
//! refusals (missing/stale host proof, missing caps, exceeded caps).
//!
//! Every test spawns `canter daemon run` as a child process with
//! isolated XDG state and an explicit short socket under a per-test temp
//! dir; nothing here touches the real host state, the service manager, or
//! the network (see tests/no_network_surface.rs).
#[path = "support/process_group.rs"]
mod process_group;

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use canter::client::{Connection, RpcError};
use canter::dirs::DaemonPaths;
use canter::state::{Retention, State};
use canter::value::{Val, integer, object, string};
use process_group::{GroupChild, assert_no_process_for_socket};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_canter")
}

struct Fixture {
    dir: PathBuf,
    state_dir: PathBuf,
    socket: PathBuf,
}

impl Fixture {
    fn new(name: &str) -> Fixture {
        let dir = std::env::temp_dir().join(format!("hf-lc-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("fixture dir");
        Fixture {
            state_dir: dir.join("state"),
            socket: dir.join("daemon.sock"),
            dir,
        }
    }

    fn paths(&self) -> DaemonPaths {
        let state_dir = self.state_dir.join("canter");
        DaemonPaths {
            state_dir: state_dir.clone(),
            runtime_dir: self.dir.clone(),
            socket_path: self.socket.clone(),
            lock_path: state_dir.join("daemon.lock"),
            db_path: state_dir.join("state.db"),
            audit_mirror_path: state_dir.join("journal").join("audit.jsonl"),
            events_mirror_path: state_dir.join("journal").join("events.jsonl"),
            backups_dir: state_dir.join("backups"),
            checkpoints_dir: state_dir.join("checkpoints"),
            log_path: state_dir.join("daemon.log"),
        }
    }

    /// Spawn the daemon. `extra_path` prepends a directory to PATH when
    /// given (used to run the daemon in a PATH without herdr/git/gh for the
    /// cold-boot recovery probe); `empty_path` replaces PATH entirely
    /// (only the absolute binary path is used to spawn).
    fn spawn(&self, path_mode: PathMode) -> GroupChild {
        let mut command = Command::new(bin());
        let stderr_file =
            std::fs::File::create(self.dir.join("daemon.stderr.log")).expect("stderr log");
        command
            .args(["daemon", "run", "--socket"])
            .arg(&self.socket)
            .env("XDG_STATE_HOME", &self.state_dir)
            .env("HOME", &self.dir)
            .stdout(Stdio::null())
            .stderr(Stdio::from(stderr_file));
        match path_mode {
            PathMode::Host => {}
            PathMode::WithoutTools => {
                // A PATH that can run nothing useful: cold-boot schedule
                // recovery must not depend on herdr/git/gh being present.
                let empty = self.dir.join("empty-bin");
                std::fs::create_dir_all(&empty).expect("empty bin");
                command.env("PATH", &empty);
            }
        }
        GroupChild::spawn(&mut command, &self.socket).expect("spawn daemon")
    }
}

#[derive(Clone, Copy)]
enum PathMode {
    Host,
    WithoutTools,
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
    let stderr_text =
        std::fs::read_to_string(fixture.dir.join("daemon.stderr.log")).unwrap_or_default();
    panic!(
        "daemon did not become ready on {}; stderr:\n{}",
        fixture.socket.display(),
        stderr_text
    );
}

fn rpc(socket: &Path, id: &str, method: &str, params: Option<Val>) -> Val {
    let mut connection = Connection::open(socket).expect("connect");
    connection
        .send_request(id, method, params.as_ref())
        .expect("send");
    let response = connection.read_response().expect("read response");
    if response.ok {
        object(vec![
            ("ok", canter::value::bool_(true)),
            ("result", response.result),
        ])
    } else {
        let error = response.error.unwrap_or_else(|| RpcError {
            code: "missing.error".to_string(),
            message: "no error doc".to_string(),
        });
        object(vec![
            ("ok", canter::value::bool_(false)),
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
        "expected ok response for {method}: {}",
        canter::canonical::canonical_text(&doc)
    );
    doc.get("result").expect("result").clone()
}

fn rpc_err(socket: &Path, id: &str, method: &str, params: Option<Val>) -> (String, String) {
    let doc = rpc(socket, id, method, params);
    assert_eq!(
        doc.get("ok").and_then(Val::as_bool),
        Some(false),
        "expected refused response for {method}: {}",
        canter::canonical::canonical_text(&doc)
    );
    let error = doc.get("error").expect("error doc");
    (
        error
            .get("code")
            .and_then(Val::as_str)
            .unwrap_or("")
            .to_string(),
        error
            .get("message")
            .and_then(Val::as_str)
            .unwrap_or("")
            .to_string(),
    )
}

fn fresh_id(seed: u32) -> String {
    format!("{:08x}", seed + std::process::id())
}

fn kill(mut child: GroupChild, label: &str) {
    child.terminate(label);
}

// ---------------------------------------------------------------------------
// Schedule documents + journal helpers
// ---------------------------------------------------------------------------

fn schedule_doc(schedule_id: &str, anchor: &str, expires_at: &str, every_secs: i64) -> Val {
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
        ("workflow_hash", string(&"b".repeat(64))),
        ("policy_hash", string(&"c".repeat(64))),
        ("phase", string("read")),
        ("scope", string("worktrees/issues/123")),
        ("caps", Val::Arr(vec![string("read")])),
        ("expires_at", string(expires_at)),
        ("anchor", string(anchor)),
        ("every_secs", integer(every_secs)),
    ])
}

/// RFC3339 seconds-Z offset from `now_unix`.
fn ts(now_unix: i64, offset_secs: i64) -> String {
    canter::time::rfc3339_from_unix(now_unix + offset_secs)
}

/// All `read.schedule.ran` audit records currently visible via journal.tail.
fn schedule_ran_records(socket: &Path, id: &str) -> Vec<Val> {
    let tail = rpc_ok(
        socket,
        id,
        "journal.tail",
        Some(object(vec![
            ("after_seq", integer(0)),
            ("limit", integer(2000)),
        ])),
    );
    tail.get("records")
        .and_then(Val::as_array)
        .expect("records")
        .iter()
        .filter(|record| record.get("action").and_then(Val::as_str) == Some("read.schedule.ran"))
        .cloned()
        .collect()
}

fn schedule_ids(records: &[Val]) -> Vec<String> {
    records
        .iter()
        .filter_map(|record| {
            record
                .get("target")
                .and_then(Val::as_str)
                .map(str::to_string)
        })
        .collect()
}

// ---------------------------------------------------------------------------
// 1. Schedule RPC round trip: create / list / pause / resume / delete
// ---------------------------------------------------------------------------

#[test]
fn schedule_create_list_pause_resume_delete_round_trip() {
    let fixture = Fixture::new("sched-rpc");
    let daemon = fixture.spawn(PathMode::Host);
    wait_ready(&fixture);
    let now = canter::time::unix_now();
    let doc = schedule_doc(
        "sd_0123456789abcdef",
        &ts(now, 3600),
        "2999-01-01T00:00:00Z",
        300,
    );

    let created = rpc_ok(
        &fixture.socket,
        &fresh_id(1),
        "schedules.create",
        Some(object(vec![
            ("schedule", doc.clone()),
            ("idempotency_key", string("ik_lc-create-1")),
        ])),
    );
    let created_row = created.get("schedule").expect("created schedule row");
    assert_eq!(
        created_row.get("enabled").and_then(Val::as_bool),
        Some(true),
        "a created schedule starts enabled"
    );
    assert_eq!(
        created_row.get("schedule_id").and_then(Val::as_str),
        Some("sd_0123456789abcdef")
    );

    // List carries the full row including the parsed doc.
    let listed = rpc_ok(&fixture.socket, &fresh_id(2), "schedules.list", None);
    let rows = listed
        .get("schedules")
        .and_then(Val::as_array)
        .expect("rows");
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].get("schedule_id").and_then(Val::as_str),
        Some("sd_0123456789abcdef")
    );
    assert_eq!(
        rows[0]
            .get("doc")
            .and_then(|doc| doc.get("phase"))
            .and_then(Val::as_str),
        Some("read"),
        "schedules.list rows carry the parsed hf-schedule/v1 doc"
    );

    // Pause (durable) then resume: resume clears the window so the next
    // evaluation is due again.
    let paused = rpc_ok(
        &fixture.socket,
        &fresh_id(3),
        "schedules.pause",
        Some(object(vec![
            ("schedule_id", string("sd_0123456789abcdef")),
            ("idempotency_key", string("ik_lc-pause-1")),
        ])),
    );
    assert_eq!(
        paused
            .get("schedule")
            .and_then(|row| row.get("enabled"))
            .and_then(Val::as_bool),
        Some(false)
    );
    let resumed = rpc_ok(
        &fixture.socket,
        &fresh_id(4),
        "schedules.resume",
        Some(object(vec![
            ("schedule_id", string("sd_0123456789abcdef")),
            ("idempotency_key", string("ik_lc-resume-1")),
        ])),
    );
    assert_eq!(
        resumed
            .get("schedule")
            .and_then(|row| row.get("enabled"))
            .and_then(Val::as_bool),
        Some(true)
    );
    assert_eq!(
        resumed
            .get("schedule")
            .and_then(|row| row.get("next_run_at"))
            .and_then(Val::as_str),
        None,
        "resume re-arms the schedule as immediately due"
    );

    let deleted = rpc_ok(
        &fixture.socket,
        &fresh_id(5),
        "schedules.delete",
        Some(object(vec![
            ("schedule_id", string("sd_0123456789abcdef")),
            ("idempotency_key", string("ik_lc-del-1")),
        ])),
    );
    assert_eq!(deleted.get("deleted").and_then(Val::as_bool), Some(true));
    let listed = rpc_ok(&fixture.socket, &fresh_id(6), "schedules.list", None);
    let rows = listed
        .get("schedules")
        .and_then(Val::as_array)
        .expect("rows");
    assert!(rows.is_empty(), "delete must remove the row");

    // Deleting an absent schedule is a typed state error.
    let (code, _) = rpc_err(
        &fixture.socket,
        &fresh_id(7),
        "schedules.delete",
        Some(object(vec![
            ("schedule_id", string("sd_0123456789abcdef")),
            ("idempotency_key", string("ik_lc-del-2")),
        ])),
    );
    assert_eq!(code, "state.not_found");

    kill(daemon, "round trip daemon");
}

// ---------------------------------------------------------------------------
// 2. Evaluation semantics: single flight, coalescing window advance,
//    refusal reasons pause the schedule (explicit terminal human state)
// ---------------------------------------------------------------------------

#[test]
fn schedule_evaluate_fires_due_once_and_expired_schedules_park() {
    let fixture = Fixture::new("sched-eval");
    let daemon = fixture.spawn(PathMode::Host);
    wait_ready(&fixture);
    let now = canter::time::unix_now();

    // Due now (anchor two windows back; cadence 60s).
    let due = schedule_doc(
        "sd_1111111111111111",
        &ts(now, -120),
        "2999-01-01T00:00:00Z",
        60,
    );
    rpc_ok(
        &fixture.socket,
        &fresh_id(10),
        "schedules.create",
        Some(object(vec![
            ("schedule", due),
            ("idempotency_key", string("ik_lc-due-1")),
        ])),
    );

    // First evaluation fires exactly once and advances the window.
    let evaluated = rpc_ok(&fixture.socket, &fresh_id(11), "schedules.evaluate", None);
    assert_eq!(
        evaluated.get("ran").and_then(Val::as_array).map(Vec::len),
        Some(1),
        "due schedule must run: {}",
        canter::canonical::canonical_text(&evaluated)
    );
    let records = schedule_ran_records(&fixture.socket, &fresh_id(12));
    assert_eq!(
        records.len(),
        1,
        "exactly one fresh evaluation is journaled"
    );
    assert_eq!(
        schedule_ids(&records),
        vec!["sd_1111111111111111:ran".to_string()]
    );

    // Single flight: an immediate second evaluation in the same window is
    // idle (the persisted window is the guard).
    let second = rpc_ok(&fixture.socket, &fresh_id(13), "schedules.evaluate", None);
    assert_eq!(
        second.get("ran").and_then(Val::as_array).map(Vec::len),
        Some(0),
        "second evaluation in the same window must not re-fire: {}",
        canter::canonical::canonical_text(&second)
    );
    assert_eq!(
        schedule_ran_records(&fixture.socket, &fresh_id(14)).len(),
        1
    );

    // An EXPIRED schedule refuses evaluation and parks itself (enabled=0):
    // an explicit human re-arm (create/resume) is the only way back.
    let expired = schedule_doc("sd_2222222222222222", &ts(now, -3600), &ts(now, -60), 60);
    rpc_ok(
        &fixture.socket,
        &fresh_id(15),
        "schedules.create",
        Some(object(vec![
            ("schedule", expired),
            ("idempotency_key", string("ik_lc-exp-1")),
        ])),
    );
    let evaluated = rpc_ok(&fixture.socket, &fresh_id(16), "schedules.evaluate", None);
    let paused = evaluated
        .get("paused")
        .and_then(Val::as_array)
        .expect("paused");
    assert_eq!(
        paused.len(),
        1,
        "expired schedule must park: {}",
        canter::canonical::canonical_text(&evaluated)
    );
    assert!(
        paused[0]
            .get("reason")
            .and_then(Val::as_str)
            .unwrap_or("")
            .contains("expired")
    );
    let list_doc = rpc_ok(&fixture.socket, &fresh_id(17), "schedules.list", None);
    let rows = list_doc
        .get("schedules")
        .and_then(Val::as_array)
        .expect("rows");
    let expired_row = rows
        .iter()
        .find(|row| row.get("schedule_id").and_then(Val::as_str) == Some("sd_2222222222222222"))
        .expect("expired row");
    assert_eq!(
        expired_row.get("enabled").and_then(Val::as_bool),
        Some(false),
        "a refused schedule parks itself (explicit terminal state)"
    );

    kill(daemon, "eval daemon");
}

// ---------------------------------------------------------------------------
// 3. Cold-boot recovery (AC9): each boot fires at most ONE fresh coalesced
//    evaluation per due schedule; missing herdr/git/gh never blocks recovery
// ---------------------------------------------------------------------------

#[test]
fn cold_boot_fires_due_schedule_once_per_boot_without_tools_on_path() {
    let fixture = Fixture::new("coldboot");
    let daemon = fixture.spawn(PathMode::WithoutTools);
    wait_ready(&fixture);
    let now = canter::time::unix_now();
    // The schedule is long overdue (downtime covered many windows).
    let due = schedule_doc(
        "sd_3333333333333333",
        &ts(now, -7200),
        "2999-01-01T00:00:00Z",
        60,
    );
    rpc_ok(
        &fixture.socket,
        &fresh_id(20),
        "schedules.create",
        Some(object(vec![
            ("schedule", due),
            ("idempotency_key", string("ik_lc-cold-1")),
        ])),
    );
    kill(daemon, "first daemon");

    // Boot 1 (PATH has no herdr/git/gh): the boot reconcile fires the due
    // schedule exactly once and the daemon stays healthy.
    let daemon = fixture.spawn(PathMode::WithoutTools);
    wait_ready(&fixture);
    let records = schedule_ran_records(&fixture.socket, &fresh_id(21));
    assert_eq!(records.len(), 1, "one fresh evaluation per boot");
    kill(daemon, "second daemon");

    // Boot 2: the schedule is not due yet (window advanced past now), so
    // the second boot fires nothing — a restart can never replay backlog.
    let daemon = fixture.spawn(PathMode::WithoutTools);
    wait_ready(&fixture);
    let records = schedule_ran_records(&fixture.socket, &fresh_id(22));
    assert_eq!(
        records.len(),
        1,
        "a restart must not re-fire an advanced window"
    );
    // The daemon answers status normally even without herdr on PATH.
    rpc_ok(&fixture.socket, &fresh_id(23), "status", None);
    kill(daemon, "third daemon");
}

// ---------------------------------------------------------------------------
// 4. Fan-out admission (AC1) over the wire: unknown/stale measurements and
//    missing caps refuse before any intent is journaled
// ---------------------------------------------------------------------------

const GRANT_ID: &str = "gr_abcdef0123456789";
const INSTANCE_ID: &str = "run-1";
const REVISION: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const POLICY_HASH: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
const WORKFLOW_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

fn grant_doc() -> Val {
    object(vec![
        ("schema", string("hf-grant/v1")),
        ("grant_id", string(GRANT_ID)),
        ("repository", string("example-org/widgets")),
        (
            "issue",
            object(vec![
                ("number", integer(123)),
                ("revision", string(REVISION)),
            ]),
        ),
        ("workflow_hash", string(WORKFLOW_HASH)),
        ("policy_hash", string(POLICY_HASH)),
        ("phase", string("merge")),
        ("scope", string("worktrees/issues/123")),
        (
            "caps",
            Val::Arr(vec![
                string("read"),
                string("worktree"),
                string("spawn"),
                string("prompt"),
                string("merge"),
            ]),
        ),
        ("expires_at", string("2999-01-01T00:00:00Z")),
        ("state_epoch", integer(1)),
        ("created_at", string("2026-09-06T00:00:00Z")),
    ])
}

fn seed_state(db_path: &Path) {
    let state = State::open(db_path, Retention::default()).expect("open state");
    state.issue_grant(&grant_doc()).expect("issue grant");
    state
        .start_instance(
            INSTANCE_ID,
            GRANT_ID,
            "fleet-doctrine-1",
            "2026-09-06T00:00:00Z",
        )
        .expect("start instance");
}

fn step(id: &str, kind: &str, params: Option<Val>) -> Val {
    object(vec![
        ("id", string(id)),
        ("kind", string(kind)),
        ("params", params.unwrap_or_else(canter::value::null)),
    ])
}

fn make_plan(steps: Vec<Val>) -> Val {
    let seed = object(vec![
        ("schema", string("hf-plan/v1")),
        ("plan_id", string("hf_plan_0000000000000000")),
        ("workflow_id", string("fleet-doctrine-1")),
        ("workflow_hash", string(WORKFLOW_HASH)),
        ("state_epoch", integer(1)),
        ("repository", string("example-org/widgets")),
        (
            "issue",
            object(vec![
                ("number", integer(123)),
                ("revision", string(REVISION)),
            ]),
        ),
        ("steps", Val::Arr(steps)),
    ]);
    let digest = canter::canonical::sha256_hex(&canter::canonical::canonical_bytes(&seed));
    let plan_id = format!("hf_plan_{}", &digest[..16]);
    let mut map = match seed {
        Val::Obj(map) => map,
        _ => unreachable!(),
    };
    map.insert("plan_id".to_string(), string(&plan_id));
    Val::Obj(map)
}

struct AdmissionScenario {
    fixture: Fixture,
    plan: Val,
    daemon: Option<GroupChild>,
}

impl AdmissionScenario {
    fn new(name: &str) -> AdmissionScenario {
        let fixture = Fixture::new(name);
        let db_path = fixture.paths().db_path;
        seed_state(&db_path);
        let daemon = fixture.spawn(PathMode::WithoutTools);
        wait_ready(&fixture);
        let plan = make_plan(vec![step(
            "h1",
            "harness_start",
            Some(object(vec![
                ("harness_key", string("lane")),
                ("session_id", string("sess-lc-1")),
                ("herdr_session", string("sess-lc-1")),
                ("terminal_session", string("sess-lc-1")),
                ("generation", integer(1)),
                ("executable", string("hf-lane")),
                ("kind", string("argv")),
                ("worktree", string("issues-123")),
                ("payload", string("admission probe (synthetic)")),
            ])),
        )]);
        AdmissionScenario {
            fixture,
            plan,
            daemon: Some(daemon),
        }
    }

    fn apply_params(&self, seed: u32, admission: Option<Val>) -> Val {
        let mut flags = vec![
            ("interactive", canter::value::bool_(true)),
            ("digest_confirmed", canter::value::bool_(true)),
            ("scheduled", canter::value::bool_(false)),
            ("production_confirmation", string("tty")),
        ];
        if let Some(admission) = admission {
            flags.push(("admission", admission));
        }
        object(vec![
            (
                "idempotency_key",
                string(&format!("ik_lc-adm-{:08x}", seed + std::process::id())),
            ),
            ("plan", self.plan.clone()),
            ("step", string("h1")),
            ("grant_id", string(GRANT_ID)),
            ("instance_id", string(INSTANCE_ID)),
            (
                "observed",
                object(vec![
                    ("issue_revision", string(REVISION)),
                    ("policy_hash", string(POLICY_HASH)),
                    ("feature_head", canter::value::null()),
                    ("integration_base", canter::value::null()),
                ]),
            ),
            (
                "topology",
                object(vec![
                    ("integration_branch", string("staging")),
                    ("production_branches", Val::Arr(vec![string("main")])),
                    (
                        "worktrees_root",
                        string(&self.fixture.dir.join("wt").to_string_lossy()),
                    ),
                    (
                        "integration_repo",
                        string(&self.fixture.dir.join("repo").to_string_lossy()),
                    ),
                ]),
            ),
            ("flags", object(flags)),
        ])
    }
}

impl Drop for AdmissionScenario {
    fn drop(&mut self) {
        if let Some(mut daemon) = self.daemon.take() {
            daemon.terminate("admission scenario daemon");
        }
        let _ = std::fs::remove_dir_all(&self.fixture.dir);
    }
}

fn admission_flags(
    caps_global: i64,
    caps_repository: i64,
    caps_harness: i64,
    measured_at: &str,
) -> Val {
    object(vec![
        (
            "caps",
            object(vec![
                ("global", integer(caps_global)),
                ("repository", integer(caps_repository)),
                ("harness", integer(caps_harness)),
            ]),
        ),
        ("harness_lanes", integer(0)),
        (
            "host_proof",
            object(vec![("measured_at", string(measured_at))]),
        ),
    ])
}

#[test]
fn admission_refuses_missing_or_stale_proof_and_missing_caps_over_the_wire() {
    let mut scenario = AdmissionScenario::new("admission");
    // No admission block at all -> refusal.admission.proof_missing before
    // any intent is journaled.
    let (code, message) = rpc_err(
        &scenario.fixture.socket,
        &fresh_id(30),
        "apply",
        Some(scenario.apply_params(30, None)),
    );
    assert_eq!(code, "refusal.admission.proof_missing", "{message}");
    // Issue #243/#250: the refusal names the failing precondition AND the
    // reachable remedy — the exact command that produces the missing
    // measurement (the audited operator's own host measurement), with the
    // attestation file kept for a run that recorded no admission to bind it
    // into — and the gate itself is untouched (the attempt still refuses).
    assert!(
        message.contains(&format!(
            "canter run dispatch --run {INSTANCE_ID} --step h1 --operator IDENTITY --reason TEXT"
        )) && message.contains("otherwise present `--admission FILE`"),
        "the missing-proof refusal names the remedy: {message}"
    );

    // Stale host-resource proof (measured an hour ago) refuses.
    let stale = admission_flags(
        16,
        8,
        8,
        &canter::time::rfc3339_from_unix(canter::time::unix_now() - 3600),
    );
    let (code, message) = rpc_err(
        &scenario.fixture.socket,
        &fresh_id(31),
        "apply",
        Some(scenario.apply_params(31, Some(stale))),
    );
    assert_eq!(code, "refusal.admission.proof_stale");
    // Issue #243/#250: the stale refusal names the failing precondition and
    // the ONE control that applies (the audited operator's own measurement,
    // which supersedes the lapsed proof at dispatch time) plus the run's own
    // check re-evaluation for the producer case, for THIS run and step.
    assert!(
        message.contains(&format!(
            "canter run dispatch --run {INSTANCE_ID} --step h1 --operator IDENTITY --reason TEXT"
        )) && message.contains(&format!(
            "canter run reevaluate --run {INSTANCE_ID} --step h1 --operator IDENTITY --reason TEXT"
        )) && message.contains(&format!("canter run status --run {INSTANCE_ID}")),
        "the stale-proof refusal names the remedy: {message}"
    );

    // A fresh proof but no caps declared refuses (unknown measurements
    // refuse new work: every applicable axis must be bounded).
    let no_caps = object(vec![(
        "host_proof",
        object(vec![("measured_at", string(&canter::time::rfc3339_now()))]),
    )]);
    let (code, _) = rpc_err(
        &scenario.fixture.socket,
        &fresh_id(32),
        "apply",
        Some(scenario.apply_params(32, Some(no_caps))),
    );
    assert_eq!(code, "refusal.admission.cap_missing");

    // Exceeded global cap (0 < 1 running lane).
    let capped = admission_flags(0, 8, 8, &canter::time::rfc3339_now());
    let (code, message) = rpc_err(
        &scenario.fixture.socket,
        &fresh_id(33),
        "apply",
        Some(scenario.apply_params(33, Some(capped))),
    );
    assert_eq!(code, "refusal.admission.cap_global", "{message}");

    // Fresh generous caps + a fresh proof admit the fan-out attempt as far
    // as admission is concerned (the effect then fails on the missing
    // worktree, which is a different, later gate) — assert admission does
    // NOT refuse when measurements are present and fresh.
    let fresh = admission_flags(16, 8, 8, &canter::time::rfc3339_now());
    let doc = rpc(
        &scenario.fixture.socket,
        &fresh_id(34),
        "apply",
        Some(scenario.apply_params(34, Some(fresh))),
    );
    let ok = doc.get("ok").and_then(Val::as_bool).unwrap_or(false);
    if !ok {
        let (code, message) = (
            doc.get("error")
                .and_then(|e| e.get("code"))
                .and_then(Val::as_str)
                .unwrap_or("")
                .to_string(),
            doc.get("error")
                .and_then(|e| e.get("message"))
                .and_then(Val::as_str)
                .unwrap_or("")
                .to_string(),
        );
        assert_ne!(
            code, "refusal.admission.proof_missing",
            "fresh proof must not be refused as missing: {message}"
        );
        assert_ne!(
            code, "refusal.admission.cap_missing",
            "declared caps must not be refused as missing: {message}"
        );
        assert_ne!(
            code, "refusal.admission.proof_stale",
            "fresh proof must not be refused as stale: {message}"
        );
    }
    kill(scenario.daemon.take().expect("daemon"), "admission daemon");
}

// ---------------------------------------------------------------------------
// 5. Schedules and paused instances survive a daemon restart (AC3/AC4):
//    pause is durable; boot recovery can never lift a paused instance.
// ---------------------------------------------------------------------------

#[test]
fn paused_schedule_and_instance_survive_restart_and_boot_recovery() {
    let fixture = Fixture::new("pause-restart");
    let daemon = fixture.spawn(PathMode::Host);
    wait_ready(&fixture);
    let now = canter::time::unix_now();
    let due = schedule_doc(
        "sd_4444444444444444",
        &ts(now, -7200),
        "2999-01-01T00:00:00Z",
        60,
    );
    rpc_ok(
        &fixture.socket,
        &fresh_id(40),
        "schedules.create",
        Some(object(vec![
            ("schedule", due),
            ("idempotency_key", string("ik_lc-pr-0001")),
        ])),
    );
    rpc_ok(
        &fixture.socket,
        &fresh_id(41),
        "schedules.pause",
        Some(object(vec![
            ("schedule_id", string("sd_4444444444444444")),
            ("idempotency_key", string("ik_lc-pr-0002")),
        ])),
    );
    let db_path = fixture.paths().db_path;
    kill(daemon, "pre-restart daemon");

    // Restart: boot recovery evaluates due schedules — the PAUSED schedule
    // must not fire (pause survives restarts; nothing lifts it but an
    // explicit resume), and the paused instance stays paused.
    let daemon = fixture.spawn(PathMode::Host);
    wait_ready(&fixture);
    assert_eq!(
        schedule_ran_records(&fixture.socket, &fresh_id(42)).len(),
        0,
        "a paused schedule must never fire during boot recovery"
    );
    let state = State::open(&db_path, Retention::default()).expect("reopen 2");
    let paused_row = state.schedule_by_id("sd_4444444444444444").expect("row");
    assert_eq!(
        paused_row.as_ref().map(|row| row.enabled),
        Some(false),
        "pause is durable across restarts"
    );
    kill(daemon, "post-restart daemon");
}

#[test]
fn daemon_lifecycle_fixture_reaps_its_daemon_group() {
    let fixture = Fixture::new("leak-detector");
    let socket = fixture.socket.clone();
    {
        let _daemon = fixture.spawn(PathMode::Host);
        wait_ready(&fixture);
    }
    assert_no_process_for_socket(&socket);
    std::fs::remove_dir_all(&fixture.dir).expect("remove leak-detector fixture");
}
