//! The shared fixture of the pane-collection witnesses (issue #170) and the
//! pane-substrate witnesses in `tests/supervision.rs`: the daemon fixture,
//! the document readers, the fake Herdr CLI (with the collection modes of
//! issue #170), the fake Hermes and `gh` fakes, the git helpers, and the
//! harness spine builders.
//!
//! Extracted verbatim from `tests/supervision.rs` when the six collection
//! witnesses moved to their own suite (`tests/supervision_collection.rs`) so
//! both suites fit the hosted per-suite budget; no assertion changed.
#![allow(dead_code)]

#[path = "process_group.rs"]
pub mod process_group;

#[allow(unused_imports)]
pub use process_group::{GroupChild, assert_no_process_for_socket};

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use canter::client::Connection;
use canter::config::ProfileBinding;
use canter::lifecycle::ConcurrencyCaps;
use canter::plan::DOCTRINE_WORKFLOW_ID;
use canter::queue_executor as qx;
use canter::queue_preview as qp;
use canter::state::{Retention, State};
use canter::supervision;
use canter::value::{Val, integer, null, object, string};

pub const REPO: &str = "example-org/widgets";

pub const HOST: &str = "host-1";

pub const HARNESS: &str = "lane-1";

pub const REV_A: &str = "1111111111111111111111111111111111111111";

pub const WORKFLOW_HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

pub const POLICY_HASH: &str = "feedface01234567feedface01234567feedface01234567feedface01234567";

pub const SECRET_DIGEST: &str = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

pub struct DaemonFixture {
    pub dir: PathBuf,
    pub state_dir: PathBuf,
    pub socket: PathBuf,
}

impl DaemonFixture {
    pub fn new(name: &str) -> DaemonFixture {
        let dir = temp_dir(name);
        DaemonFixture {
            state_dir: dir.join("state"),
            socket: dir.join("daemon.sock"),
            dir,
        }
    }

    pub fn db(&self) -> PathBuf {
        self.state_dir.join("canter").join("state.db")
    }

    pub fn daemon_log(&self) -> PathBuf {
        self.state_dir.join("canter").join("daemon.log")
    }

    pub fn seed(&self) -> State {
        std::fs::create_dir_all(self.state_dir.join("canter")).expect("state dir");
        State::open(&self.db(), Retention::default()).expect("open state")
    }

    /// Spawn the daemon with an explicit `PATH` (the fake harness/forge
    /// executables the dispatched effects must resolve).
    pub fn spawn_with_path(&self, path: &str) -> GroupChild {
        std::fs::create_dir_all(&self.state_dir).expect("state home");
        let mut command = Command::new(env!("CARGO_BIN_EXE_canter"));
        command
            .args(["daemon", "run", "--socket"])
            .arg(&self.socket)
            .env("XDG_STATE_HOME", &self.state_dir)
            .env("HOME", &self.dir)
            .env("PATH", path)
            .stdout(Stdio::null())
            .stderr(Stdio::from(
                std::fs::File::create(self.dir.join("daemon.stderr.log")).expect("stderr log"),
            ));
        GroupChild::spawn(&mut command, &self.socket).expect("spawn daemon")
    }

    pub fn spawn(&self) -> GroupChild {
        std::fs::create_dir_all(&self.state_dir).expect("state home");
        let mut command = Command::new(env!("CARGO_BIN_EXE_canter"));
        command
            .args(["daemon", "run", "--socket"])
            .arg(&self.socket)
            .env("XDG_STATE_HOME", &self.state_dir)
            .env("HOME", &self.dir)
            .stdout(Stdio::null())
            .stderr(Stdio::from(
                std::fs::File::create(self.dir.join("daemon.stderr.log")).expect("stderr log"),
            ));
        GroupChild::spawn(&mut command, &self.socket).expect("spawn daemon")
    }
}

/// The no-progress ceiling of a recorded-state wait, in seconds (issue #232).
///
/// Progress-driven, never a fixed wall-clock bound: the driver wakes
/// semantically on each committed step and otherwise re-checks on its bounded
/// timer fallback (`canter::supervision::DEFAULT_CHECK_INTERVAL_SECS`, 60 s),
/// so one starved wake legitimately leaves the recorded frontier, the attempt
/// ledger or the committed check count unchanged for a little over a minute
/// on a loaded host. Every wait below that observes one of those records
/// therefore fails only after this much time with NO durable change — any new
/// recorded attempt, committed check or frontier move resets the ceiling.
/// Two driver ticks, so a single starved wake can never fail a witness, and
/// it leaves room inside the CI test driver's per-suite budget
/// (`.github/workflows/ci.yml` runs each suite with `--per-suite-seconds
/// 150`) for the suite's own serialized baseline, so a genuinely stuck witness
/// still reports itself instead of being killed by the driver.
pub const NO_PROGRESS_SECS: u64 = 120;

pub fn binding_doc() -> Val {
    let mut binding = ProfileBinding {
        key: HARNESS.to_string(),
        kind: "pi".to_string(),
        provider: "provider-a".to_string(),
        model: "model-a".to_string(),
        fallbacks: Vec::new(),
        configured_limits: Vec::new(),
        introspection: false,
        secrets: vec![("PROVIDER_TOKEN".to_string(), SECRET_DIGEST.to_string())],
        skills: Vec::new(),
        revision: String::new(),
    };
    binding.revision = binding.revision_of();
    binding.to_doc()
}

pub fn resolved() -> Val {
    object(vec![("ref", string("staging"))])
}

pub fn request_with(issues: Vec<qp::SelectedIssue>) -> qp::QueueRequest {
    qp::QueueRequest {
        repository: REPO.to_string(),
        host: HOST.to_string(),
        host_available: Some(true),
        harness_key: HARNESS.to_string(),
        harness_lanes: Some(0),
        caps: ConcurrencyCaps {
            global: 4,
            per_repository: 2,
            per_harness: 2,
        },
        workflow_id: DOCTRINE_WORKFLOW_ID.to_string(),
        workflow_hash: WORKFLOW_HASH.to_string(),
        role_config: binding_doc(),
        boundary: qp::Boundary {
            phase: "merge".to_string(),
            integration_branch: "staging".to_string(),
            completion_branch: "staging".to_string(),
            caps: vec![
                "read".to_string(),
                "worktree".to_string(),
                "spawn".to_string(),
                "prompt".to_string(),
                "merge".to_string(),
            ],
        },
        steps: vec![qp::PlannedStep {
            id: "p1".to_string(),
            kind: "checkout".to_string(),
            params: Some(resolved()),
        }],
        selected: issues,
    }
}

pub fn selected(id: &str, revision: &str) -> qp::SelectedIssue {
    qp::SelectedIssue {
        id: id.to_string(),
        title: None,
        revision: revision.to_string(),
        requires: Vec::new(),
    }
}

pub fn render_bound(state: &State, request: &qp::QueueRequest) -> (Val, String) {
    let preview = qp::preview_queue(state, request).expect("preview renders");
    let bound = preview
        .doc
        .get("request")
        .cloned()
        .expect("preview carries the bound-input document");
    (bound, preview.digest)
}

pub fn grant_doc_at(grant_id: &str, number: i64, revision: &str, epoch: i64) -> Val {
    Val::parse_json(&format!(
        r#"{{"schema":"hf-grant/v1","grant_id":"{grant_id}","repository":"{REPO}",
            "issue":{{"number":{number},"revision":"{revision}"}},
            "workflow_hash":"{WORKFLOW_HASH}","policy_hash":"{POLICY_HASH}",
            "phase":"merge","scope":"worktrees/issues/{number}",
            "caps":["read","worktree","spawn","prompt","merge"],
            "expires_at":"2999-01-01T00:00:00Z","state_epoch":{epoch},
            "created_at":"2026-09-06T00:00:00Z"}}"#
    ))
    .expect("grant document")
}

pub fn seed_grant(state: &State, grant_id: &str, number: i64) {
    let epoch = state.current_epoch().expect("epoch");
    state
        .issue_grant(&grant_doc_at(grant_id, number, REV_A, epoch))
        .expect("issue grant");
}

pub fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("hf-supervision-95-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
}

/// Runtime-assembled idempotency key (the tracked file never carries a
/// `key = "<literal>"` shape the secret scanners read as an API key).
pub fn idem_key(stem: &str) -> String {
    format!("ik_95-{stem}-{}", std::process::id())
}

pub fn fresh_id(seed: u64) -> String {
    format!("{seed:016x}")
}

pub fn wait_ready(fixture: &DaemonFixture) {
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

pub fn rpc(socket: &Path, id: &str, method: &str, params: Option<Val>) -> Val {
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

pub fn rpc_ok(socket: &Path, id: &str, method: &str, params: Option<Val>) -> Val {
    let doc = rpc(socket, id, method, params);
    assert_eq!(
        doc.get("ok").and_then(Val::as_bool),
        Some(true),
        "expected ok for {method}: {}",
        canter::canonical::canonical_text(&doc)
    );
    doc.get("result").expect("result").clone()
}

pub fn shutdown(mut daemon: GroupChild) {
    daemon.terminate("supervision fixture daemon");
}

pub fn item_of(result: &Val, number: i64) -> Val {
    let wanted = format!("{REPO}#{number}");
    result
        .get("items")
        .and_then(Val::as_array)
        .and_then(|items| {
            items
                .iter()
                .find(|item| item.get("id").and_then(Val::as_str) == Some(wanted.as_str()))
                .cloned()
        })
        .unwrap_or_else(|| {
            panic!(
                "no item for issue {number}: {}",
                canter::canonical::canonical_text(result)
            )
        })
}

pub fn instance_of(result: &Val, number: i64) -> String {
    item_of(result, number)
        .get("instance_id")
        .and_then(Val::as_str)
        .expect("admitted item carries the run")
        .to_string()
}

pub fn status_doc(socket: &Path, id: &str, run: &str) -> Val {
    rpc_ok(
        socket,
        id,
        "supervision.status",
        Some(supervision::status_params(run)),
    )
}

pub fn evaluation(doc: &Val) -> Val {
    doc.get("evaluation").cloned().unwrap_or_else(|| {
        panic!(
            "no evaluation block: {}",
            canter::canonical::canonical_text(doc)
        )
    })
}

pub fn checks_of(doc: &Val) -> i64 {
    evaluation(doc)
        .get("checks")
        .and_then(Val::as_int)
        .unwrap_or(-1)
}

pub fn class_of(doc: &Val) -> String {
    evaluation(doc)
        .get("class")
        .and_then(Val::as_str)
        .unwrap_or_default()
        .to_string()
}

/// Poll `supervision.status` until the recorded check count reaches `want`,
/// failing only after `NO_PROGRESS_SECS` with no NEW committed check (issue
/// #232) and naming the progress observed and the elapsed time.
pub fn wait_for_checks(fixture: &DaemonFixture, run: &str, want: i64) -> Val {
    let started = Instant::now();
    let mut last_progress = started;
    let mut progress = -1i64;
    let mut id = 100u64;
    loop {
        id += 1;
        let doc = status_doc(&fixture.socket, &fresh_id(id), run);
        let checks = checks_of(&doc);
        if checks >= want {
            return doc;
        }
        if checks != progress {
            progress = checks;
            last_progress = Instant::now();
        }
        let last = canter::canonical::canonical_text(&doc);
        let stalled = last_progress.elapsed().as_secs();
        assert!(
            stalled < NO_PROGRESS_SECS,
            "run {run} never reached {want} recorded check(s): no progress for {stalled}s of {}s \
             waited (recorded {checks}); last: {last}",
            started.elapsed().as_secs()
        );
        std::thread::sleep(Duration::from_millis(25));
    }
}

/// The `hf-plan/v1` document for one committed spine (the derivation
/// docs/contracts/spec-plans.md documents; the daemon's `bind_plan`
/// re-verifies it, so a divergent derivation refuses rather than runs).
pub fn plan_doc_for_bound(bound: &Val, number: i64) -> Val {
    plan_doc_with_steps(bound.get("steps").cloned().unwrap_or_else(null), number)
}

/// [`plan_doc_for_bound`] over an explicit step spine (tamper cases).
pub fn plan_doc_with_steps(steps: Val, number: i64) -> Val {
    let placeholder = object(vec![
        ("schema", string("hf-plan/v1")),
        ("plan_id", string("hf_plan_0000000000000000")),
        ("workflow_id", string(DOCTRINE_WORKFLOW_ID)),
        ("workflow_hash", string(WORKFLOW_HASH)),
        ("state_epoch", integer(1)),
        ("repository", string(REPO)),
        (
            "issue",
            object(vec![
                ("number", integer(number)),
                ("revision", string(REV_A)),
            ]),
        ),
        ("steps", steps),
    ]);
    let digest = canter::canonical::sha256_hex(&canter::canonical::canonical_bytes(&placeholder));
    match placeholder {
        Val::Obj(mut map) => {
            map.insert(
                "plan_id".to_string(),
                string(&format!("hf_plan_{}", &digest[..16])),
            );
            Val::Obj(map)
        }
        _ => unreachable!("the plan seed is an object"),
    }
}

/// One caller-driven `apply` of a committed run step: the plan of the run's
/// own spine, the run's grant, the caller's topology and its admission
/// proof — exactly the dispatch the operator drives.
pub fn caller_apply_params(
    fixture: &DaemonFixture,
    integration: &Path,
    bound: &Val,
    run: &str,
    grant_id: &str,
    target: (&str, i64),
    key: &str,
) -> Val {
    let (step, number) = target;
    object(vec![
        ("idempotency_key", string(key)),
        ("plan", plan_doc_for_bound(bound, number)),
        ("step", string(step)),
        ("grant_id", string(grant_id)),
        ("instance_id", string(run)),
        (
            "observed",
            object(vec![
                ("issue_revision", string(REV_A)),
                ("policy_hash", string(POLICY_HASH)),
                ("feature_head", Val::Null),
                ("integration_base", Val::Null),
            ]),
        ),
        (
            "topology",
            object(vec![
                ("integration_branch", string("staging")),
                ("production_branches", Val::Arr(Vec::new())),
                (
                    "worktrees_root",
                    string(&fixture.dir.join("worktrees").to_string_lossy()),
                ),
                (
                    "archive_root",
                    string(&fixture.dir.join("archive").to_string_lossy()),
                ),
                ("integration_repo", string(&integration.to_string_lossy())),
            ]),
        ),
        (
            "flags",
            object(vec![
                ("interactive", canter::value::bool_(true)),
                ("digest_confirmed", canter::value::bool_(true)),
                ("scheduled", canter::value::bool_(false)),
                ("production_confirmation", string("tty")),
                (
                    "admission",
                    object(vec![
                        (
                            "caps",
                            object(vec![
                                ("global", integer(16)),
                                ("repository", integer(8)),
                                ("harness", integer(8)),
                            ]),
                        ),
                        ("harness_lanes", integer(0)),
                        (
                            "host_proof",
                            object(vec![("measured_at", string(&canter::time::rfc3339_now()))]),
                        ),
                    ]),
                ),
            ]),
        ),
    ])
}

/// A minimal REAL git repository: the integration checkout the dispatches
/// run their read effects against.
pub fn init_repo(path: &Path) {
    std::fs::create_dir_all(path).expect("repo dir");
    for args in [
        vec!["init", "-q", "-b", "staging"],
        vec!["remote", "add", "origin", "."],
        vec!["config", "user.email", "lane@example.invalid"],
        vec!["config", "user.name", "lane"],
        vec!["commit", "--allow-empty", "-q", "-m", "base"],
    ] {
        let status = Command::new("git")
            .args(&args)
            .current_dir(path)
            // #226: copy nothing from the host's shared git templates.
            .env("GIT_TEMPLATE_DIR", "")
            .status()
            .expect("git runs");
        assert!(status.success(), "git {args:?}");
    }
}

/// A fake `gh` answering the hosted-check row with a green check set (the
/// continuation effect of the fixture spine).
pub fn write_fake_gh(dir: &Path) -> PathBuf {
    let bin = dir.join("fakebin");
    std::fs::create_dir_all(&bin).expect("bin dir");
    let path = bin.join("gh");
    std::fs::write(
        &path,
        "#!/bin/sh\n\
         if [ \"$1\" = \"pr\" ] && [ \"$2\" = \"checks\" ]; then\n\
           printf '[{\"name\":\"hosted-ci\",\"state\":\"SUCCESS\",\"conclusion\":\"SUCCESS\"}]'\n\
           exit 0\n\
         fi\n\
         echo \"unexpected argv: $*\" >&2\n\
         exit 9\n",
    )
    .expect("write fake gh");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = std::fs::metadata(&path).expect("metadata").permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&path, permissions).expect("chmod");
    }
    bin
}

/// One raw `git` invocation in a fixture repository.
pub fn git_output(repo: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .args(args)
        .current_dir(repo)
        // #226: copy nothing from the host's shared git templates.
        .env("GIT_TEMPLATE_DIR", "")
        .output()
        .expect("git runs");
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// A fake `herdr` that answers with the documented JSON envelope and keeps the
/// state of the pane it created (plus the lane binding reported into it) next
/// to its own working directory — the lane worktree the daemon passes as the
/// row's cwd. Every row it receives is appended to `herdr-argv.txt` in the
/// same directory, which is what the assertions read back.
pub fn write_fake_herdr(dir: &Path) -> PathBuf {
    let bin = dir.join("fakebin-herdr");
    std::fs::create_dir_all(&bin).expect("bin dir");
    let path = bin.join("herdr");
    std::fs::write(&path, FAKE_HERDR_BODY).expect("write fake herdr");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = std::fs::metadata(&path).expect("metadata").permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&path, permissions).expect("chmod");
    }
    bin
}

/// A fake `hermes` that refuses any row other than the documented role-bound
/// prompt row: the run's declared role key (`-p <key>`), the declared
/// provider/model binding, and the session the run's `harness_start` bound
/// (`chat --continue <session> --create-if-missing`), payload last. Its real
/// stdout carries the session it ran under, so the transcript proves which
/// session the child was given.
pub fn write_fake_hermes(dir: &Path) -> PathBuf {
    let bin = dir.join("fakebin-hermes");
    std::fs::create_dir_all(&bin).expect("bin dir");
    let path = bin.join("hermes");
    std::fs::write(
        &path,
        "#!/bin/sh\n\
         printf '%s\\n' \"$@\" > argv.txt\n\
         [ \"$1\" = \"-p\" ] && [ \"$2\" = \"lane-1\" ] || { echo \"bad role: $*\" >&2; exit 7; }\n\
         [ \"$3\" = \"--provider\" ] && [ \"$4\" = \"provider-a\" ] || { echo \"bad provider: $*\" >&2; exit 8; }\n\
         [ \"$5\" = \"-m\" ] && [ \"$6\" = \"model-a\" ] || { echo \"bad model: $*\" >&2; exit 9; }\n\
         [ \"$7\" = \"chat\" ] && [ \"$8\" = \"--continue\" ] || { echo \"bad row: $*\" >&2; exit 10; }\n\
         [ \"${10}\" = \"--create-if-missing\" ] && [ \"${11}\" = \"-q\" ] || { echo \"bad continue: $*\" >&2; exit 11; }\n\
         printf 'session:%s output:%s' \"$9\" \"${12}\"\n",
    )
    .expect("write fake hermes");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = std::fs::metadata(&path).expect("metadata").permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&path, permissions).expect("chmod");
    }
    bin
}

/// The fake Herdr CLI body (POSIX shell; it sets its own utility PATH, because
/// the adapter runs it with the allowlisted environment only).
pub const FAKE_HERDR_BODY: &str = r#"#!/bin/sh
PATH=/usr/bin:/bin
export PATH
LOG="$HOME/herdr-argv.txt"
STATE="$HOME/herdr-state"
[ -d "$STATE" ] || mkdir -p "$STATE"
log() { printf '%s\n' "$*" >> "$LOG"; }
# Hot polling reads use shell builtins, not a new sed process per field.
read_state() {
  if [ -f "$STATE/$1" ]; then
    IFS= read -r value < "$STATE/$1" || :
    printf '%s' "$value"
  else
    printf '%s' "$2"
  fi
}
agent_doc() {
  printf '{"name":"%s","pane_id":"%s","cwd":"%s","agent_status":"%s","tokens":{"canter_lane":"%s","canter_generation":"%s"}}' \
    "$(read_state name '')" "$(read_state pane 'w1:p1')" "$(read_state cwd '')" "$(read_state state 'idle')" \
    "$(read_state lane '')" "$(read_state generation '')"
}
workspace_doc() {
  printf '{"workspace_id":"w1","label":"%s","worktree":{"repo_root":"%s","checkout_path":"%s","is_linked_worktree":true,"repo_name":"widgets"}}' \
    "$(read_state label '')" "$(read_state root '')" "$(read_state cwd '')"
}
case "$1 $2" in
  "workspace close")
    log "$*"
    rm -f "$STATE/pane" "$STATE/name"
    printf '{"result":{}}\n'
    ;;
  "workspace list")
    log "$*"
    if [ -f "$STATE/pane" ]; then
      printf '{"result":{"workspaces":[%s]}}\n' "$(workspace_doc)"
    else
      printf '{"id":"cli:workspace:list","result":{"workspaces":[],"type":"workspace_list"}}\n'
    fi
    ;;
  "worktree open")
    log "$*"
    cwd=""; label=""
    shift 2
    while [ $# -gt 0 ]; do
      case "$1" in
        --cwd) root="$2"; shift 2 ;;
        --path) cwd="$2"; shift 2 ;;
        --label) label="$2"; shift 2 ;;
        *) shift ;;
      esac
    done
    printf '%s' "$root" > "$STATE/root"
    printf '%s' "$cwd" > "$STATE/cwd"
    printf '%s' "$label" > "$STATE/label"
    printf 'w1' > "$STATE/workspace"
    printf 'w1:p1' > "$STATE/pane"
    printf '{"result":{"workspace":%s,"already_open":false}}\n' "$(workspace_doc)"
    ;;
  "pane list")
    log "$*"
    printf '{"result":{"panes":[{"pane_id":"w1:p1","cwd":"%s","tokens":{"canter_lane":"%s","canter_generation":"%s"}}]}}\n' "$(read_state cwd '')" "$(read_state lane '')" "$(read_state generation '')"
    ;;
  "pane report-metadata")
    log "$*"
    shift 2
    while [ $# -gt 0 ]; do
      case "$1" in
        --token)
          case "$2" in
            canter_lane=*) printf '%s' "${2#canter_lane=}" > "$STATE/lane" ;;
            canter_generation=*) printf '%s' "${2#canter_generation=}" > "$STATE/generation" ;;
          esac
          shift 2
          ;;
        *) shift ;;
      esac
    done
    printf '{"id":"cli:pane:report-metadata","result":{"pane_id":"w1:p1"},"type":"pane_metadata"}\n'
    ;;
  "agent list")
    log "$*"
    if [ -f "$STATE/name" ]; then
      printf '{"id":"cli:agent:list","result":{"agents":[%s],"type":"agent_list"}}\n' "$(agent_doc)"
    else
      printf '{"id":"cli:agent:list","result":{"agents":[],"type":"agent_list"}}\n'
    fi
    ;;
  "agent start")
    log "$*"
    printf '%s' "$3" > "$STATE/name"
    printf '{"id":"cli:agent:start","result":{"name":"%s","pane_id":"w1:p1"},"type":"agent_start"}\n' "$3"
    ;;
  "agent get")
    log "$*"
    if [ -f "$HOME/collect-mode" ] && [ -f "$STATE/pane_content" ]; then
      mode=$(cat "$HOME/collect-mode")
      # Issue #170 N7: the measured flap. While the harness holds `flap-now`
      # armed, the lane's own status reports `done` for exactly TWO read-backs
      # and then moves back to working — the live p5-101 collection read
      # exactly this shape (two stop read-backs ~100 ms apart) as a stop while
      # the worker was still mid-turn. Nothing is committed during the flap.
      if [ "$mode" = flap ] && [ -f "$HOME/flap-now" ]; then
        seen=$(read_state flap_reads 0)
        seen=$((seen + 1))
        printf '%s' "$seen" > "$STATE/flap_reads"
        if [ "$seen" -le 2 ]; then
          printf 'done' > "$STATE/state"
        else
          printf 'working' > "$STATE/state"
          rm -f "$HOME/flap-now"
        fi
      fi
      # Issue #170 N8: the `extend` mode withholds the delivery for longer than
      # the step's declared no-progress window (11 s) while the lane keeps
      # reporting it is working. The wait must EXTEND on recorded progress and
      # certify the delivery afterwards, never park on the wall clock.
      if [ "$mode" = extend ]; then
        started=$(read_state extend_started '')
        if [ -z "$started" ]; then
          started=$(date +%s)
          printf '%s' "$started" > "$STATE/extend_started"
        fi
        elapsed=$(( $(date +%s) - started ))
        if [ "$elapsed" -ge 14 ]; then
          checkout=$(read_state cwd '')
          if [ ! -f "$checkout/delivery.txt" ]; then
            printf 'worker delivery\n' > "$checkout/delivery.txt"
            git -C "$checkout" add delivery.txt || exit 8
            git -C "$checkout" -c commit.gpgsign=false commit -qm delivery || exit 8
            printf '%s' "$elapsed" > "$STATE/delivered_after_secs"
            log "worker-delivery-committed"
          else
            printf done > "$STATE/state"
          fi
        fi
      fi
      # Issue #170 N8: the `timeout` mode's read-backs carry NO progress at all
      # (a lane whose own state cannot be read): the wait must park on its
      # no-progress window with a typed timeout instead of running forever — a
      # lane that keeps REPORTING it is working is never parked on the window
      # (that is the `extend` mode, end to end).
      if [ "$mode" = timeout ]; then
        printf unknown > "$STATE/state"
      fi
      log "worker-poll $(read_state state idle)"
      if [ -f "$HOME/allow-stop" ] && [ "$(read_state state idle)" = working ]; then
        case "$mode" in
          delta|flap)
            checkout=$(read_state cwd '')
            if [ ! -f "$checkout/delivery.txt" ]; then
              printf 'worker delivery\n' > "$checkout/delivery.txt"
              git -C "$checkout" add delivery.txt || exit 8
              git -C "$checkout" -c commit.gpgsign=false commit -qm delivery || exit 8
              log "worker-delivery-committed"
              # Issue #200: the delivery lands MID-TURN — the worker stays
              # working after the commit, so the head it read can still move.
            else
              # ...and only NOW does the turn settle. A collection may read the
              # delta only at this settled turn — and only after the pinned
              # number of non-working read-backs (issue #170 N7).
              printf done > "$STATE/state"
            fi
            ;;
          extend)
            # Driven by its own elapsed timer above, never by `allow-stop`:
            # the lane keeps reporting `working` past the declared window.
            ;;
          *)
            printf done > "$STATE/state"
            ;;
        esac
      fi
    fi
    printf '{"id":"cli:agent:get","result":%s,"type":"agent_info"}\n' "$(agent_doc)"
    ;;
  "agent prompt")
    log "$*"
    printf '%s' "$4" > "$STATE/pane_content"
    if [ -f "$HOME/collect-mode" ]; then
      printf working > "$STATE/state"
    else
      printf done > "$STATE/state"
    fi
    printf '{"id":"cli:agent:prompt","result":{"agent_status":"%s","submitted":true},"type":"agent_prompt"}\n' "$(read_state state idle)"
    ;;
  "agent read")
    log "$*"
    cat "$STATE/pane_content" 2>/dev/null
    ;;
  "agent send-keys")
    log "$*"
    printf '{"id":"cli:agent:send-keys","result":{"sent":true},"type":"agent_send_keys"}\n'
    ;;
  *)
    log "UNEXPECTED $*"
    printf 'unexpected herdr row: %s\n' "$*" >&2
    exit 9
    ;;
esac
"#;

/// The committed spine of the pane-substrate fixture: the lane worktree, the
/// run's session bind and the prompt that continues it, with NO declared
/// substrate — the default (Herdr pane) is what the daemon must select.
pub fn harness_pane_steps(harness_key: &str) -> Vec<qp::PlannedStep> {
    vec![
        qp::PlannedStep {
            id: "p1".to_string(),
            kind: "worktree_create".to_string(),
            params: Some(object(vec![
                ("branch", string("issue-5")),
                ("worktree", string("issues-5")),
            ])),
        },
        qp::PlannedStep {
            id: "p2".to_string(),
            kind: "harness_start".to_string(),
            params: Some(object(vec![
                ("harness_key", string(harness_key)),
                ("kind", string("hermes")),
            ])),
        },
        qp::PlannedStep {
            id: "p3".to_string(),
            kind: "prompt".to_string(),
            params: Some(object(vec![
                ("harness_key", string(harness_key)),
                ("kind", string("hermes")),
                ("worktree", string("issues-5")),
                ("payload", string("do the bounded work")),
            ])),
        },
        qp::PlannedStep {
            id: "p8-5".to_string(),
            kind: "cleanup".to_string(),
            params: Some(object(vec![
                ("worktree", string("issues-5")),
                ("branch", string("issue-5")),
            ])),
        },
    ]
}

// The worker is held by a fixture latch, not a timing guess. Only the fake
// Herdr's own read-back commits the delivery and reports the terminal state.

/// The reviewed role configuration of the harness-lifecycle fixture: a
/// `hermes` profile (the kind whose documented prompt row carries the role
/// key, the declared provider/model pair and the session continuation).
pub fn harness_binding_doc() -> Val {
    let mut binding = ProfileBinding {
        key: HARNESS.to_string(),
        kind: "hermes".to_string(),
        provider: "provider-a".to_string(),
        model: "model-a".to_string(),
        fallbacks: Vec::new(),
        configured_limits: Vec::new(),
        introspection: false,
        secrets: Vec::new(),
        skills: Vec::new(),
        revision: String::new(),
    };
    binding.revision = binding.revision_of();
    binding.to_doc()
}

pub fn harness_role_revision() -> String {
    harness_binding_doc()
        .get("revision")
        .and_then(Val::as_str)
        .expect("binding revision")
        .to_string()
}

/// `queue.submit` params under the fixture's own reviewed role configuration.
pub fn harness_submit_params(key: &str, bound: &Val, digest: &str, grant_id: &str) -> Val {
    let grants = vec![qx::ItemGrant {
        id: "#5".to_string(),
        grant_id: grant_id.to_string(),
    }];
    qx::submit_params(
        key,
        digest,
        1,
        bound,
        &harness_binding_doc(),
        &harness_role_revision(),
        ConcurrencyCaps {
            global: 4,
            per_repository: 2,
            per_harness: 2,
        },
        Some(true),
        Some(0),
        &grants,
        &[],
        None,
    )
}
