//! Herdr-pane execution substrate (issue #139): the role agent runs INSIDE a
//! Herdr pane created in the run's lane worktree, the prompt is delivered
//! through the Herdr CLI, and observation/interruption/terminal outcome are
//! collected through the `herdr agent` rows.
//!
//! Every case here is a fake-executable contract test (no harness
//! credentials, no live Herdr server): the fake `herdr` records the exact
//! rows it receives and answers with the documented JSON envelope, and a fake
//! `hermes` writes an incriminating marker if the bare-subprocess row is ever
//! reached from the pane substrate.
//!
//! Witnessed here:
//! 1. the pane is created IN the run's lane worktree and the role starts in
//!    it (`worktree open --cwd … --path …`, `agent start … --pane`, read-back);
//! 2. the prompt is delivered through `herdr agent prompt` and the pane
//!    content shows it (the bare harness is never spawned);
//! 3. Herdr unavailable is the typed `refusal.unavailable.herdr` — and never a
//!    silent bare-subprocess fallback;
//! 4. a superseded lane generation is refused typed and NO prompt is
//!    delivered to the reused pane/agent identity;
//! 5. interruption and the terminal outcome are collected through Herdr and
//!    the recorded outcome distinguishes them;
//! 6. the headless row is only reached when the reviewed step selects it
//!    explicitly, and an unknown substrate token refuses.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use canter::adapters::{
    CODE_BAD_REQUEST, CODE_EXECUTION_UNSUPPORTED, CODE_NAME_COLLISION, CODE_PROMPT_UNDELIVERED,
    CODE_STALE_GENERATION, CODE_UNAVAILABLE_HERDR, ExecutionMode, HarnessKind, LaneNames, Op,
    OpRequest, Profile, bind_identity, execute_op_in_worktree, new_session,
};
use canter::canonical::canonical_bytes;
use canter::canonical::sha256_hex;
use canter::mutation::{EffectContext, bind_plan, declared_execution, execute_step};
use canter::value::{Val, integer, object, string};

static DIR_COUNTER: AtomicUsize = AtomicUsize::new(0);

/// One temporary directory per test (removed on drop).
struct Dir {
    root: PathBuf,
}

impl Dir {
    fn new(name: &str) -> Dir {
        let n = DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
        let root =
            std::env::temp_dir().join(format!("hf-herdr-pane-{name}-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("create temp dir");
        Dir {
            root: root.canonicalize().expect("canonical fixture root"),
        }
    }

    fn path(&self, relative: &str) -> PathBuf {
        self.root.join(relative)
    }

    fn write_executable(&self, relative: &str, body: &str) -> PathBuf {
        let path = self.path(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create bin dir");
        }
        fs::write(&path, format!("#!/bin/sh\n{body}\n")).expect("write fake executable");
        let file = fs::File::open(&path).expect("open fake executable");
        file.sync_all().expect("fsync fake executable");
        let mut permissions = fs::metadata(&path).expect("metadata").permissions();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            permissions.set_mode(0o755);
            fs::set_permissions(&path, permissions).expect("chmod");
        }
        path
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

/// The environment one adapter call receives: the fake bin directory FIRST on
/// PATH (so `herdr`/`hermes` resolve to the fakes) plus the fixture
/// variables the fakes read.
fn fixture_env(bin: &Path, extra: &[(&str, String)]) -> BTreeMap<String, String> {
    let host_path = std::env::var("PATH").unwrap_or_default();
    let mut env = BTreeMap::new();
    env.insert(
        "PATH".to_string(),
        format!("{}:{host_path}", bin.to_string_lossy()),
    );
    for (name, value) in extra {
        env.insert((*name).to_string(), value.clone());
    }
    env
}

/// A fake `hermes` that records an incriminating marker whenever it is
/// spawned. Nothing on the pane substrate may reach it.
const FAKE_HERMES: &str = "\
printf 'spawned:%s\\n' \"$*\" >> \"$HF_FAKE_HERMES_MARKER\"\n\
printf 'bare-subprocess-ran'";

/// The fake Herdr CLI. It keeps a small state directory and answers with the
/// documented JSON envelope (`{"id":…,"result":{…},"type":…}`), so the
/// adapter's read-backs are exercised against the real shape. Every row is
/// appended to the invocation log, which is what the assertions read.
const FAKE_HERDR: &str = r#"
PATH=/usr/bin:/bin
export PATH
LOG="$HF_FAKE_HERDR_LOG"
STATE="$HF_FAKE_HERDR_STATE"
mkdir -p "$STATE"
log() { printf '%s\n' "$*" >> "$LOG"; }
read_state() { [ -f "$STATE/$1" ] && sed -n 1p "$STATE/$1" || printf '%s' "$2"; }
report_lane() { printf '%s' "${HF_FAKE_HERDR_REPORT_LANE:-$(read_state lane '')}"; }
report_generation() { printf '%s' "${HF_FAKE_HERDR_REPORT_GENERATION:-$(read_state generation '')}"; }
agent_doc() {
  printf '{"name":"%s","pane_id":"%s","cwd":"%s","agent_status":"%s","state_change_seq":%s,"tokens":{"canter_lane":"%s","canter_generation":"%s"}%s}' \
    "$(read_state name '')" "$(read_state pane 'w1:p1')" "$(read_state cwd '')" "$(read_state state 'idle')" \
    "$(read_state seq '0')" \
    "$(report_lane)" "$(report_generation)" "${1:-}"
}
workspace_doc() {
  root=$(read_state root ''); checkout=$(read_state cwd ''); linked=true; repo=widgets
  case "${HF_FAKE_HERDR_BAD_IDENTITY:-}" in
    missing)
      printf '{"workspace_id":"w1","label":"%s","cwd":"%s"}' "$(read_state label '')" "$checkout"
      return ;;
    root) root="$root/other-repo" ;;
    checkout) checkout="$checkout/other-lane" ;;
    unlinked) linked=false ;;
    unnamed) repo="" ;;
  esac
  printf '{"workspace_id":"w1","label":"%s","cwd":"%s","worktree":{"repo_root":"%s","checkout_path":"%s","is_linked_worktree":%s,"repo_name":"%s"}}' \
    "$(read_state label '')" "$(read_state cwd '')" "$root" "$checkout" "$linked" "$repo"
}
case "$1 $2" in
  "workspace close")
    log "$*"
    rm -f "$STATE/pane" "$STATE/name" "$STATE/workspace"
    printf '{"result":{}}\n'
    ;;
  "workspace list")
    log "$*"
    if [ -f "$STATE/pane" ]; then
      printf '{"id":"cli:workspace:list","result":{"workspaces":[%s],"type":"workspace_list"}}\n' "$(workspace_doc)"
    else
      printf '{"id":"cli:workspace:list","result":{"workspaces":[],"type":"workspace_list"}}\n'
    fi
    ;;
  "worktree open")
    log "$*"
    cwd=""; label=""; root=""
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
    printf '{"id":"cli:worktree:open","result":{"workspace":%s,"root_pane":{"pane_id":"w1:p1","cwd":"%s"},"already_open":false,"type":"worktree_opened"}}\n' "$(workspace_doc)" "$cwd"
    ;;
  "pane list")
    log "$*"
    if [ -f "$STATE/pane" ]; then
      if [ -n "${HF_FAKE_HERDR_PANE_NO_ID:-}" ]; then
        # Measured-shape control (issue #144 item 3): a pane row that resolves
        # as this lane's pane but carries no pane_id.
        printf '{"id":"cli:pane:list","result":{"panes":[{"cwd":"%s","tokens":{"canter_lane":"%s","canter_generation":"%s"}}],"type":"pane_list"}}\n' \
          "$(read_state cwd '')" "$(report_lane)" "$(report_generation)"
      else
        printf '{"id":"cli:pane:list","result":{"panes":[{"pane_id":"%s","cwd":"%s","tokens":{"canter_lane":"%s","canter_generation":"%s"}}],"type":"pane_list"}}\n' \
          "$(read_state pane 'w1:p1')" "$(read_state cwd '')" "$(report_lane)" "$(report_generation)"
      fi
    else
      printf '{"id":"cli:pane:list","result":{"panes":[],"type":"pane_list"}}\n'
    fi
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
    # Measured herdr 0.9.0 (issue #144): this row prints NO document on
    # success (exit 0, zero bytes of stdout) while its recording lands.
    ;;
  "agent list")
    log "$*"
    if [ -f "$STATE/name" ] && [ ! -f "$STATE/no_agent" ]; then
      printf '{"id":"cli:agent:list","result":{"agents":[%s],"type":"agent_list"}}\n' "$(agent_doc)"
    else
      printf '{"id":"cli:agent:list","result":{"agents":[],"type":"agent_list"}}\n'
    fi
    ;;
  "agent start")
    log "$*"
    if [ -n "${HF_FAKE_HERDR_START_FAIL:-}" ]; then
      printf '{"error":{"code":"agent_name_taken","message":"fixture name collision"}}\n' >&2
      exit 1
    fi
    printf '%s' "$3" > "$STATE/name"
    # Measured herdr 0.9.0: the started agent rides under `result.agent`.
    printf '{"id":"cli:agent:start","result":{"agent":%s,"argv":["hermes"],"type":"agent_started"}}\n' "$(agent_doc)"
    ;;
  "agent get")
    log "$*"
    reads=0
    [ -f "$STATE/get_reads" ] && reads=$(sed -n 1p "$STATE/get_reads")
    reads=$((reads + 1))
    printf '%s' "$reads" > "$STATE/get_reads"
    # Issue #148 readiness control: the first N read-backs report the agent
    # NOT promptable (its terminal is still starting), so a prompt must wait
    # for the substrate's own signal instead of submitting into it.
    extra=""
    if [ -n "${HF_FAKE_HERDR_NOT_READY_READS:-}" ]; then
      if [ "$reads" -le "$HF_FAKE_HERDR_NOT_READY_READS" ]; then
        extra=',"interactive_ready":false'
      else
        extra=',"interactive_ready":true'
      fi
    fi
    if [ -n "${HF_FAKE_HERDR_GET_RAW:-}" ]; then
      # Measured-shape control (issue #144 item 1): a row whose stdout is not
      # a JSON document at all (exit 0).
      printf '%s' "$HF_FAKE_HERDR_GET_RAW"
    elif [ -f "$STATE/pane" ]; then
      # Measured herdr 0.9.0: the agent row rides under `result.agent`.
      printf '{"id":"cli:agent:get","result":{"agent":%s,"type":"agent_info"}}\n' "$(agent_doc "$extra")"
    else
      printf '{"id":"cli:agent:get","result":null,"type":"agent_info"}\n'
      exit 3
    fi
    ;;
  "agent prompt")
    log "$*"
    attempts=0
    [ -f "$STATE/prompt_attempts" ] && attempts=$(sed -n 1p "$STATE/prompt_attempts")
    attempts=$((attempts + 1))
    printf '%s' "$attempts" > "$STATE/prompt_attempts"
    case "${HF_FAKE_HERDR_PROMPT_FAIL:-}" in
      "")
        ;;
      deliver-after-*)
        # Issue #148 readiness race: the first N submissions are the CLI's own
        # transient wait (`agent_prompt_stalled`, exit 1, stderr document);
        # the submission then lands.
        limit=${HF_FAKE_HERDR_PROMPT_FAIL#deliver-after-}
        if [ "$attempts" -le "$limit" ]; then
          printf '%s\n' '{"error":{"code":"agent_prompt_stalled","message":"no working or blocked state observed within 5000ms"},"id":"cli:agent:prompt"}' >&2
          exit 1
        fi
        ;;
      no-delivery)
        # Issue #148: the row reports a submission (exit 0) but NOTHING
        # reaches the pane — the agent's read-back never shows the task text
        # AND the agent's lifecycle never moved.
        printf '{"id":"cli:agent:prompt","result":{"agent_status":"idle","submitted":true},"type":"agent_prompt"}\n'
        exit 0
        ;;
      accepted-no-text)
        # Issue #148 round 1: the agent TOOK the submission (its lifecycle
        # moved) but the task text never reached it — so the transcript half of
        # the proof is load-bearing too.
        printf 'working' > "$STATE/state"
        advanced=$(( $(read_state seq 0) + 1 ))
        printf '%s' "$advanced" > "$STATE/seq"
        printf '{"id":"cli:agent:prompt","result":{"agent_status":"working","submitted":true},"type":"agent_prompt"}\n'
        exit 0
        ;;
      *)
        printf '%s\n' "{\"error\":{\"code\":\"$HF_FAKE_HERDR_PROMPT_FAIL\",\"message\":\"fixture refusal\"},\"id\":\"cli:agent:prompt\"}" >&2
        exit 1
        ;;
    esac
    # A real delivery: the pane shows the submitted text AND the agent's own
    # lifecycle moves (state + the substrate's state-change counter).
    printf '%s' "$4" > "$STATE/pane_content"
    printf 'done' > "$STATE/state"
    advanced=$(( $(read_state seq 0) + 1 ))
    printf '%s' "$advanced" > "$STATE/seq"
    printf '{"id":"cli:agent:prompt","result":{"agent_status":"done","submitted":true},"type":"agent_prompt"}\n'
    ;;
  "agent read")
    log "$*"
    # A REALISTIC pane transcript (issue #148 round 1): a real pane's
    # `agent read` returns the whole scrollback — the launch command line, the
    # agent's banner and its TUI placeholder — and the launch line can carry
    # the task text (measured live on the #148 pane). A text match alone is
    # therefore not a delivery, and this double must be able to express that.
    printf 'hermes -p lane-role --provider example-provider -m example-model\n'
    if [ -f "$STATE/launch_echo" ]; then
      cat "$STATE/launch_echo"
      printf '\n'
    fi
    printf '\nWelcome to the harness.\n'
    printf 'fleet-impl > Turn these notes into a to-do list\n'
    if [ -f "$STATE/pane_content" ]; then
      cat "$STATE/pane_content"
      printf '\n'
    fi
    ;;
  "agent send-keys")
    log "$*"
    printf '%s\n' "$*" >> "$STATE/signals"
    printf '{"id":"cli:agent:send-keys","result":{"sent":true},"type":"agent_send_keys"}\n'
    ;;
  *)
    log "UNEXPECTED $*"
    printf 'unexpected herdr row: %s\n' "$*" >&2
    exit 9
    ;;
esac
"#;

/// A fixture holding one lane worktree, a fake bin directory and the fixture
/// environment for one adapter call.
struct Fixture {
    dir: Dir,
    log: PathBuf,
    state: PathBuf,
    marker: PathBuf,
    bin: PathBuf,
    worktree: PathBuf,
}

impl Fixture {
    fn new(name: &str) -> Fixture {
        let dir = Dir::new(name);
        let bin = dir.path("fakebin");
        fs::create_dir_all(&bin).expect("bin dir");
        let worktree = dir.path("worktrees/issues-5");
        let integration = dir.path("integration");
        for args in [
            vec!["init", "-b", "staging", integration.to_str().unwrap()],
            vec![
                "-C",
                integration.to_str().unwrap(),
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "--allow-empty",
                "-m",
                "seed",
            ],
            vec![
                "-C",
                integration.to_str().unwrap(),
                "worktree",
                "add",
                "-b",
                "issue-5",
                worktree.to_str().unwrap(),
                "staging",
            ],
        ] {
            let out = std::process::Command::new("git")
                .args(args)
                .output()
                .expect("git fixture");
            assert!(
                out.status.success(),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
        let worktree = worktree.canonicalize().expect("canonical lane");
        let log = dir.path("herdr.log");
        let state = dir.path("herdr-state");
        let marker = dir.path("hermes-marker");
        Fixture {
            dir,
            log,
            state,
            marker,
            bin,
            worktree,
        }
    }

    /// Install the fake `herdr` (and a fake `hermes` that records any spawn).
    fn install(&self, herdr_body: &str) {
        self.dir.write_executable("fakebin/herdr", herdr_body);
        self.dir.write_executable("fakebin/hermes", FAKE_HERMES);
    }

    fn env(&self, extra: &[(&str, String)]) -> BTreeMap<String, String> {
        let mut rows: Vec<(&str, String)> = vec![
            ("HF_FAKE_HERDR_LOG", self.log.to_string_lossy().into_owned()),
            (
                "HF_FAKE_HERDR_STATE",
                self.state.to_string_lossy().into_owned(),
            ),
            (
                "HF_FAKE_HERMES_MARKER",
                self.marker.to_string_lossy().into_owned(),
            ),
        ];
        for (name, value) in extra {
            rows.push((name, value.clone()));
        }
        fixture_env(&self.bin, &rows)
    }

    /// The fixture environment with the fake bin directory as the ONLY PATH
    /// entry: the host's real `herdr`/harness executables are unreachable, so
    /// an "unavailable" case is genuine (and portable to CI hosts).
    fn isolated_env(&self) -> BTreeMap<String, String> {
        let mut env = self.env(&[]);
        env.insert("PATH".to_string(), self.bin.to_string_lossy().into_owned());
        env
    }

    /// Every Herdr row the fake received.
    fn rows(&self) -> Vec<String> {
        fs::read_to_string(&self.log)
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect()
    }

    /// Whether the bare harness executable was ever spawned.
    fn bare_spawned(&self) -> bool {
        self.marker.exists()
    }

    /// The pane content the fake recorded for the delivered prompt.
    fn pane_content(&self) -> String {
        fs::read_to_string(self.state.join("pane_content")).unwrap_or_default()
    }

    /// Seed the state the fake answers its read-backs from.
    fn seed(&self, name: &str, value: &str) {
        fs::create_dir_all(&self.state).expect("state dir");
        fs::write(self.state.join(name), value).expect("seed state");
    }

    /// Plant the launch command line the pane's scrollback shows BEFORE any
    /// prompt (issue #148 round 1): the measured #148 pane's launch line
    /// embedded the task text, so this double must be able to carry it — a
    /// text match alone must never be read as a delivery.
    fn seed_launch_echo(&self, task: &str) {
        self.seed(
            "launch_echo",
            &format!("hermes -p lane-role --provider example-provider -m example-model \"{task}\""),
        );
    }
}

/// The profile of one lane role on the given substrate.
fn lane_profile(execution: ExecutionMode) -> Profile {
    let mut profile = Profile::official(HarnessKind::Hermes, "lane-role")
        .expect("profile")
        .with_binding("example-provider", "example-model")
        .expect("binding")
        .with_execution(execution);
    profile.lane_names = Some(LaneNames::new(5, "implementer", 1).unwrap());
    profile
}

/// The bound session of one lane run (generation is the lane generation).
fn lane_session(generation: u64) -> canter::adapters::SessionHandle {
    let identity = bind_identity("lane-abc123", "lane-abc123", generation).expect("identity");
    new_session("lane-abc123", identity).expect("session")
}

fn start_request<'a>(session: &'a canter::adapters::SessionHandle) -> OpRequest<'a> {
    OpRequest {
        op: Op::Start,
        session,
        payload: None,
        timeout: Duration::from_secs(30),
    }
}

fn prompt_request<'a>(
    session: &'a canter::adapters::SessionHandle,
    payload: &'a str,
) -> OpRequest<'a> {
    OpRequest {
        op: Op::Prompt,
        session,
        payload: Some(payload),
        timeout: Duration::from_secs(30),
    }
}

/// Witness 1: the worker is started/reused INSIDE a Herdr pane created in the
/// run's lane worktree, and the role starts there with the bound
/// role/profile/model.
#[test]
fn the_role_starts_in_a_herdr_pane_created_in_the_lane_worktree() {
    let fixture = Fixture::new("start-pane");
    fixture.install(FAKE_HERDR);
    let env = fixture.env(&[]);
    let session = lane_session(1);
    let profile = lane_profile(ExecutionMode::HerdrPane);

    let result =
        execute_op_in_worktree(&profile, &start_request(&session), &env, &fixture.worktree);

    assert_eq!(result.status, "succeeded", "{:?}", result.message);
    let payload = result.payload.clone().expect("payload");
    // The recorded binding names the pane/agent identity and the worktree.
    assert_eq!(payload.get("pane").and_then(Val::as_str), Some("w1:p1"));
    assert_eq!(payload.get("agent").and_then(Val::as_str), Some("impl-5"));
    assert_eq!(
        payload.get("worktree").and_then(Val::as_str),
        Some(fixture.worktree.to_string_lossy().as_ref())
    );
    assert_eq!(
        payload.get("execution").and_then(Val::as_str),
        Some("herdr")
    );

    // The pane was created IN the lane worktree, and the role was started in
    // that pane with the profile-authoritative binding on the start row.
    let rows = fixture.rows();
    assert!(
        rows.iter().any(|row| {
            row == &format!(
                "worktree open --cwd {} --path {} --label 5-impl --no-focus",
                fixture
                    .dir
                    .path("integration")
                    .canonicalize()
                    .unwrap()
                    .display(),
                fixture.worktree.display()
            )
        }),
        "the pane is created in the lane worktree: {rows:?}"
    );
    assert!(
        rows.iter().any(|row| row
            == "agent start impl-5 --kind hermes --pane w1:p1 -- -p lane-role \
                --provider example-provider -m example-model"),
        "the role starts in that pane with the bound binding: {rows:?}"
    );
    assert!(
        rows.iter().any(|row| row
            == "pane report-metadata w1:p1 --source custom:canter-lane --agent canter \
                --token canter_lane=lane-abc123 --token canter_generation=1"),
        "the lane↔pane/agent binding is recorded: {rows:?}"
    );
    // The pane's reported cwd is the lane worktree (the read-back the binding
    // verification compares), and the bare harness was never spawned.
    assert_eq!(
        fs::read_to_string(fixture.state.join("cwd")).unwrap_or_default(),
        fixture.worktree.to_string_lossy()
    );
    assert!(
        !fixture.bare_spawned(),
        "the pane substrate never spawns the bare harness executable"
    );
}

/// A second start of the same lane REUSES the recorded pane/agent instead of
/// creating another one, and it never re-runs the bare row.
#[test]
fn a_second_start_reuses_the_bound_pane_and_agent() {
    let fixture = Fixture::new("start-reuse");
    fixture.install(FAKE_HERDR);
    let env = fixture.env(&[]);
    let session = lane_session(1);
    let profile = lane_profile(ExecutionMode::HerdrPane);

    let first = execute_op_in_worktree(&profile, &start_request(&session), &env, &fixture.worktree);
    assert_eq!(first.status, "succeeded", "{:?}", first.message);
    let creates_after_first = fixture
        .rows()
        .iter()
        .filter(|row| row.starts_with("worktree open"))
        .count();
    assert_eq!(creates_after_first, 1);

    let second =
        execute_op_in_worktree(&profile, &start_request(&session), &env, &fixture.worktree);
    assert_eq!(second.status, "succeeded", "{:?}", second.message);
    let payload = second.payload.clone().expect("payload");
    assert_eq!(payload.get("reused").and_then(Val::as_bool), Some(true));
    assert_eq!(
        fixture
            .rows()
            .iter()
            .filter(|row| row.starts_with("worktree open"))
            .count(),
        1,
        "the reuse path creates no second pane: {:?}",
        fixture.rows()
    );
    assert_eq!(
        fixture
            .rows()
            .iter()
            .filter(|row| row.starts_with("agent start"))
            .count(),
        1,
        "the reuse path starts no second agent: {:?}",
        fixture.rows()
    );
}

#[test]
fn lane_names_derive_only_from_issue_role_and_round() {
    for (issue, role, round, agent, workspace) in [
        (154, "implementer", 1, "impl-154", "154-impl"),
        (152, "reviewer", 1, "rev-152-r1", "152-rev1"),
        (152, "reviewer", 2, "rev-152-r2", "152-rev2"),
        (154, "implementer", 2, "impl-154-r2", "154-impl2"),
    ] {
        let names = LaneNames::new(issue, role, round).unwrap();
        assert_eq!(names.agent, agent);
        assert_eq!(names.workspace, workspace);
    }
    for (issue, role, round) in [(0, "implementer", 1), (1, "other", 1), (1, "reviewer", 0)] {
        assert!(LaneNames::new(issue, role, round).is_err());
    }
}

#[test]
fn worktree_identity_is_required_and_returned_with_the_workspace() {
    let fixture = Fixture::new("identity");
    fixture.install(FAKE_HERDR);
    let session = lane_session(1);
    let mut profile = lane_profile(ExecutionMode::HerdrPane);
    profile.lane_names = None;
    let unnamed = execute_op_in_worktree(
        &profile,
        &start_request(&session),
        &fixture.env(&[]),
        &fixture.worktree,
    );
    assert_eq!(unnamed.code, Some(CODE_BAD_REQUEST));
    assert!(fixture.rows().is_empty());
    profile.lane_names = Some(LaneNames::new(5, "implementer", 1).unwrap());
    let result = execute_op_in_worktree(
        &profile,
        &start_request(&session),
        &fixture.env(&[]),
        &fixture.worktree,
    );
    assert_eq!(result.status, "succeeded", "{:?}", result.message);
    let payload = result.payload.unwrap();
    assert_eq!(payload.get("workspace").and_then(Val::as_str), Some("w1"));
    assert_eq!(
        payload.get("workspace_label").and_then(Val::as_str),
        Some("5-impl")
    );
    let identity = payload.get("worktree_identity").unwrap();
    assert_eq!(
        identity.get("repo_root").and_then(Val::as_str),
        fixture
            .dir
            .path("integration")
            .canonicalize()
            .unwrap()
            .to_str()
    );
    assert_eq!(
        identity.get("checkout_path").and_then(Val::as_str),
        fixture.worktree.to_str()
    );
    assert_eq!(
        identity.get("is_linked_worktree").and_then(Val::as_bool),
        Some(true)
    );
    assert!(
        !fixture
            .rows()
            .iter()
            .any(|row| row.starts_with("workspace create"))
    );
}

#[test]
fn malformed_workspace_identity_is_refused_and_rolled_back() {
    for mode in ["missing", "root", "checkout", "unlinked", "unnamed"] {
        let fixture = Fixture::new(mode);
        fixture.install(FAKE_HERDR);
        let session = lane_session(1);
        let profile = lane_profile(ExecutionMode::HerdrPane);
        let result = execute_op_in_worktree(
            &profile,
            &start_request(&session),
            &fixture.env(&[("HF_FAKE_HERDR_BAD_IDENTITY", mode.to_string())]),
            &fixture.worktree,
        );
        assert_eq!(result.status, "refused", "{mode}: {result:?}");
        assert_eq!(
            result.code,
            Some(canter::adapters::CODE_INCOMPLETE_IDENTITY),
            "{mode}: {result:?}"
        );
        let rows = fixture.rows();
        assert_eq!(
            rows.iter()
                .filter(|row| row.starts_with("worktree open"))
                .count(),
            1,
            "{mode}: {rows:?}"
        );
        assert_eq!(
            rows.iter()
                .filter(|row| *row == "workspace close w1")
                .count(),
            1,
            "{mode}: {rows:?}"
        );
        assert_eq!(rows.last().map(String::as_str), Some("workspace list"));
        assert!(
            !rows.iter().any(|row| row.starts_with("agent start")),
            "{mode}: {rows:?}"
        );
        assert!(!fixture.state.join("pane").exists(), "{mode}");
        assert!(!fixture.state.join("workspace").exists(), "{mode}");
        assert!(!fixture.bare_spawned(), "{mode}");
    }
}

#[test]
fn a_duplicate_agent_name_is_refused_without_adoption_or_new_workspace() {
    let fixture = Fixture::new("duplicate-name");
    fixture.install(FAKE_HERDR);
    let env = fixture.env(&[]);
    let session = lane_session(1);
    let profile = lane_profile(ExecutionMode::HerdrPane);
    let first = execute_op_in_worktree(&profile, &start_request(&session), &env, &fixture.worktree);
    assert_eq!(first.status, "succeeded");
    let foreign = new_session(
        "lane-other",
        bind_identity("lane-other", "lane-other", 1).unwrap(),
    )
    .unwrap();
    let refused =
        execute_op_in_worktree(&profile, &start_request(&foreign), &env, &fixture.worktree);
    assert_eq!(refused.status, "refused");
    assert_eq!(refused.code, Some(CODE_NAME_COLLISION));
    assert!(refused.message.unwrap().contains("impl-5"));
    assert_eq!(
        fixture
            .rows()
            .iter()
            .filter(|row| row.starts_with("worktree open"))
            .count(),
        1
    );
    assert_eq!(
        fixture
            .rows()
            .iter()
            .filter(|row| row.starts_with("agent start"))
            .count(),
        1
    );
    assert!(
        !fixture
            .rows()
            .iter()
            .any(|row| row.starts_with("workspace close"))
    );
    assert_eq!(
        fs::read_to_string(fixture.state.join("lane")).unwrap(),
        session.session_id
    );
}

#[test]
fn same_lane_fix_round_reuses_original_names_and_workspace() {
    let fixture = Fixture::new("fix-round");
    fixture.install(FAKE_HERDR);
    let session = lane_session(1);
    let mut profile = lane_profile(ExecutionMode::HerdrPane);
    let first = execute_op_in_worktree(
        &profile,
        &start_request(&session),
        &fixture.env(&[]),
        &fixture.worktree,
    );
    assert_eq!(first.status, "succeeded");
    profile.lane_names = Some(LaneNames::new(5, "implementer", 2).unwrap());
    let retry = execute_op_in_worktree(
        &profile,
        &start_request(&session),
        &fixture.env(&[]),
        &fixture.worktree,
    );
    assert_eq!(retry.status, "succeeded", "{:?}", retry.message);
    let payload = retry.payload.unwrap();
    assert_eq!(
        payload.get("agent"),
        first.payload.as_ref().unwrap().get("agent")
    );
    assert_eq!(
        payload.get("workspace"),
        first.payload.as_ref().unwrap().get("workspace")
    );
    assert_eq!(payload.get("reused").and_then(Val::as_bool), Some(true));
    assert_eq!(
        fixture
            .rows()
            .iter()
            .filter(|row| row.starts_with("worktree open"))
            .count(),
        1
    );
}

#[test]
fn failed_start_rolls_back_only_its_new_workspace_and_retry_starts_cleanly() {
    let fixture = Fixture::new("failed-start");
    fixture.install(FAKE_HERDR);
    let session = lane_session(1);
    let profile = lane_profile(ExecutionMode::HerdrPane);
    let failed = execute_op_in_worktree(
        &profile,
        &start_request(&session),
        &fixture.env(&[("HF_FAKE_HERDR_START_FAIL", "1".to_string())]),
        &fixture.worktree,
    );
    assert_eq!(failed.code, Some(CODE_NAME_COLLISION), "{:?}", failed);
    assert!(
        !fixture.state.join("pane").exists(),
        "failed attempt leaves no orphan"
    );
    assert!(fixture.rows().iter().any(|row| row == "workspace close w1"));
    let retry = execute_op_in_worktree(
        &profile,
        &start_request(&session),
        &fixture.env(&[]),
        &fixture.worktree,
    );
    assert_eq!(retry.status, "succeeded", "{:?}", retry.message);
}

#[test]
fn p8_preserves_dirty_live_and_stale_lanes_then_closes_the_owned_workspace() {
    let fixture = Fixture::new("cleanup");
    fixture.install(FAKE_HERDR);
    let env = fixture.env(&[]);
    let session = lane_session(1);
    let profile = lane_profile(ExecutionMode::HerdrPane);
    assert_eq!(
        execute_op_in_worktree(&profile, &start_request(&session), &env, &fixture.worktree).status,
        "succeeded"
    );
    let params = object(vec![
        ("worktree", string("issues-5")),
        ("branch", string("issue-5")),
    ]);
    let start_params = object(vec![
        ("harness_key", string("lane-role")),
        ("kind", string("hermes")),
    ]);
    let plan = bound_plan(vec![
        plan_step("p3", "harness_start", start_params),
        plan_step("p8-5", "cleanup", params.clone()),
    ]);
    let root = fixture.dir.path("worktrees");
    let integration = fixture.dir.path("integration");
    let ctx = EffectContext {
        plan: &plan,
        step_id: "p8-5",
        kind: "cleanup",
        params: Some(&params),
        repository: "example-org/widgets",
        integration_branch: "staging",
        production_branches: &[],
        worktrees_root: &root,
        integration_repo: &integration,
        observed_feature_head: None,
        observed_integration_base: None,
        env: &env,
        role: None,
        session: Some(&session),
        archive_root: None,
    };
    let dirty = fixture.worktree.join("keep.txt");
    fs::write(&dirty, "unfinished work").unwrap();
    let refused = execute_step(&ctx);
    assert_eq!(refused.code.as_deref(), Some("refusal.cleanup.dirty"));
    assert!(dirty.exists());
    assert!(
        !fixture
            .rows()
            .iter()
            .any(|row| row.starts_with("workspace close"))
    );
    fs::remove_file(dirty).unwrap();
    fixture.seed("state", "working");
    assert_eq!(
        execute_step(&ctx).code.as_deref(),
        Some(CODE_STALE_GENERATION)
    );
    fixture.seed("state", "idle");
    fixture.seed("generation", "2");
    assert_eq!(
        execute_step(&ctx).code.as_deref(),
        Some(CODE_STALE_GENERATION)
    );
    assert!(fixture.worktree.exists());
    assert!(
        !fixture
            .rows()
            .iter()
            .any(|row| row.starts_with("workspace close"))
    );
    fixture.seed("generation", "1");
    let cleaned = execute_step(&ctx);
    assert_eq!(cleaned.status, "succeeded", "{:?}", cleaned.message);
    assert!(!fixture.worktree.exists());
    assert!(!fixture.state.join("pane").exists());
    assert_eq!(
        fixture
            .rows()
            .iter()
            .filter(|row| row.starts_with("workspace close"))
            .count(),
        1
    );
}

/// Witness 2: the prompt is delivered through the Herdr path (`agent prompt
/// … --wait`) and the pane content shows the delivered prompt; the bound
/// profile/model pair rides on the pane's start row, and the bare harness
/// executable is never spawned.
#[test]
fn the_prompt_is_delivered_through_herdr_and_the_pane_shows_it() {
    let fixture = Fixture::new("prompt-delivery");
    fixture.install(FAKE_HERDR);
    let env = fixture.env(&[]);
    let session = lane_session(1);
    let profile = lane_profile(ExecutionMode::HerdrPane);

    let started =
        execute_op_in_worktree(&profile, &start_request(&session), &env, &fixture.worktree);
    assert_eq!(started.status, "succeeded", "{:?}", started.message);

    let payload = "Implement jirathip-dev/canter#139 from its latest issue text.";
    let result = execute_op_in_worktree(
        &profile,
        &prompt_request(&session, payload),
        &env,
        &fixture.worktree,
    );

    assert_eq!(result.status, "succeeded", "{:?}", result.message);
    let result_payload = result.payload.clone().expect("payload");
    assert_eq!(
        result_payload.get("delivered").and_then(Val::as_bool),
        Some(true)
    );
    // The settled state is read back through the Herdr agent surface.
    assert_eq!(
        result_payload.get("state").and_then(Val::as_str),
        Some("done")
    );
    let transcript = result_payload
        .get("transcript")
        .and_then(Val::as_str)
        .unwrap_or_default();
    // A real pane's read-back is the whole scrollback (launch line, banner,
    // placeholder); the delivered task is what must appear in it.
    assert!(
        transcript.contains(payload),
        "the pane content read back through `herdr agent read` shows the delivered prompt: \
         {transcript}"
    );
    assert_eq!(fixture.pane_content(), payload);
    assert!(
        fixture.rows().iter().any(|row| row.starts_with(&format!(
            "agent prompt impl-5 {payload} --wait --timeout "
        ))),
        "the prompt is delivered through the Herdr row: {:?}",
        fixture.rows()
    );
    assert!(
        !fixture.bare_spawned(),
        "the pane substrate never spawns the bare harness executable for a prompt"
    );
}

/// Issue #148 witnesses 1 and 3: a prompt to a FRESHLY created agent waits —
/// bounded — through the substrate's own readiness signal and through the
/// CLI's transient wait codes, and it reports success ONLY because the
/// agent's own read-back shows the task text arrived. The row's exit status
/// is never the verdict.
#[test]
fn a_fresh_agents_prompt_waits_bounded_and_delivers_a_verified_read_back() {
    let fixture = Fixture::new("prompt-readiness");
    fixture.install(FAKE_HERDR);
    // The substrate reports the agent not promptable for the first two
    // read-backs (its terminal is still starting), and the CLI's own first
    // submission is its transient "no working state observed" wait.
    let env = fixture.env(&[
        ("HF_FAKE_HERDR_NOT_READY_READS", "2".to_string()),
        ("HF_FAKE_HERDR_PROMPT_FAIL", "deliver-after-1".to_string()),
    ]);
    let session = lane_session(1);
    let profile = lane_profile(ExecutionMode::HerdrPane);
    let payload = "Implement jirathip-dev/canter#148 from its latest issue text.";
    // The pane's scrollback ALREADY shows the task text (the measured #148
    // launch echo), so this witness can only pass through the agent's own
    // lifecycle — never through the text.
    fixture.seed_launch_echo(payload);
    let started =
        execute_op_in_worktree(&profile, &start_request(&session), &env, &fixture.worktree);
    assert_eq!(started.status, "succeeded", "{:?}", started.message);

    let result = execute_op_in_worktree(
        &profile,
        &prompt_request(&session, payload),
        &env,
        &fixture.worktree,
    );

    assert_eq!(result.status, "succeeded", "{:?}", result.message);
    let result_payload = result.payload.clone().expect("payload");
    assert_eq!(
        result_payload.get("delivered").and_then(Val::as_bool),
        Some(true)
    );
    assert_eq!(
        result_payload.get("verified").and_then(Val::as_str),
        Some("agent-lifecycle-and-transcript"),
        "the delivery is verified against the agent's own lifecycle AND its read-back"
    );
    assert!(
        result_payload
            .get("transcript")
            .and_then(Val::as_str)
            .unwrap_or_default()
            .contains(payload)
    );
    assert_eq!(
        result_payload.get("state_before").and_then(Val::as_str),
        Some("idle"),
        "the pre-submission lifecycle is recorded"
    );
    assert_eq!(
        result_payload
            .get("state_change_seq_before")
            .and_then(Val::as_int),
        Some(0)
    );
    assert!(
        result_payload
            .get("state_change_seq_after")
            .and_then(Val::as_int)
            .unwrap_or(0)
            > 0,
        "the substrate's state-change counter advanced: {result_payload:?}"
    );
    assert_eq!(
        result_payload.get("state").and_then(Val::as_str),
        Some("done")
    );
    let attempts = result_payload
        .get("attempts")
        .and_then(Val::as_int)
        .unwrap_or(0);
    assert!(
        attempts >= 2,
        "the transient wait inside the bounded window was retried: {attempts}"
    );
    let readiness = result_payload
        .get("readiness_ms")
        .and_then(Val::as_int)
        .unwrap_or(-1);
    assert!(
        readiness > 0,
        "the prompt waited for the substrate's readiness signal: {readiness}"
    );
    // The readiness gate ran BEFORE any submission: the first two read-backs
    // report not-ready, the third is promptable, and only then is the task
    // submitted — the #147 race (start and prompt in the same second) cannot
    // submit into a terminal that is not accepting input yet.
    let rows = fixture.rows();
    let first_prompt = rows
        .iter()
        .position(|row| row.starts_with("agent prompt"))
        .expect("a submission row");
    let reads_before = rows[..first_prompt]
        .iter()
        .filter(|row| row.starts_with("agent get"))
        .count();
    assert_eq!(
        reads_before, 3,
        "two not-ready read-backs, then the ready one: {rows:?}"
    );
    assert_eq!(fixture.pane_content(), payload);
    assert!(
        !fixture.bare_spawned(),
        "the pane substrate never spawns the bare harness executable for a prompt"
    );
}

/// Issue #148 witnesses 2 and 4: a prompt that never arrives refuses TYPED
/// with everything the operator needs — the CLI's own error code, the exact
/// argv, the raw stdout and the raw stderr, the exit status and the resolved
/// pane/agent — and it never leaves the run claiming a worker is running: the
/// concrete outcome is `refusal.prompt.undelivered`, reported by the
/// classification as a diagnosed step (never `waiting-workers`).
#[test]
fn an_undelivered_prompt_refuses_typed_with_argv_raw_output_exit_and_identity() {
    let fixture = Fixture::new("prompt-undelivered");
    fixture.install(FAKE_HERDR);
    let env = fixture.env(&[(
        "HF_FAKE_HERDR_PROMPT_FAIL",
        "agent_prompt_stalled".to_string(),
    )]);
    let payload = "Implement jirathip-dev/canter#148 from its latest issue text.";
    // The pane's scrollback holds the task text (the measured #148 launch
    // echo) while the agent receives nothing: the payload is in the read-back
    // the whole time, so only the agent's own lifecycle can refuse this.
    fixture.seed_launch_echo(payload);
    let session = lane_session(1);
    let profile = lane_profile(ExecutionMode::HerdrPane);
    let started =
        execute_op_in_worktree(&profile, &start_request(&session), &env, &fixture.worktree);
    assert_eq!(started.status, "succeeded", "{:?}", started.message);

    // The operation's own deadline caps the delivery window, so the witness
    // is bounded: the prompt waits, retries the transient wait, and refuses.
    let request = OpRequest {
        op: Op::Prompt,
        session: &session,
        payload: Some(payload),
        timeout: Duration::from_secs(14),
    };
    let result = execute_op_in_worktree(&profile, &request, &env, &fixture.worktree);

    assert_eq!(result.status, "refused", "{:?}", result.message);
    assert_eq!(result.code, Some(CODE_PROMPT_UNDELIVERED));
    let message = result.message.clone().unwrap_or_default();
    assert!(
        message.contains("agent_prompt_stalled"),
        "the CLI's own error code is named: {message}"
    );
    assert!(
        message.contains("impl-5") && message.contains("w1:p1"),
        "the refusal names the resolved agent and pane: {message}"
    );
    let detail = result.detail.clone().unwrap_or_default();
    assert_eq!(
        detail.lines().count(),
        1,
        "the recorded evidence stays ONE diagnosable line: {detail}"
    );
    assert!(
        detail.contains("argv: herdr agent prompt impl-5"),
        "the exact argv is recorded: {detail}"
    );
    assert!(
        detail.contains("exit: 1"),
        "the exit status is recorded: {detail}"
    );
    assert!(
        detail.contains("stdout (0 bytes)"),
        "the raw stdout (and its size) is recorded: {detail}"
    );
    assert!(
        detail.contains("stderr (") && detail.contains("agent_prompt_stalled"),
        "the raw stderr is recorded: {detail}"
    );
    assert!(
        detail.contains("agent: impl-5") && detail.contains("pane: w1:p1"),
        "the resolved identity is recorded: {detail}"
    );
    assert!(
        detail.contains("read-back ("),
        "the read-back the verdict was judged against is recorded: {detail}"
    );
    assert_eq!(
        detail.matches("state idle seq 0").count(),
        2,
        "both snapshots show the agent's lifecycle NEVER moved (the task text was already in \
         the scrollback — the launch echo — and that alone is not a delivery): {detail}"
    );
    // The bounded window retried the transient wait and then refused: never a
    // single un-retried exit, and never an unbounded loop.
    let submissions = fixture
        .rows()
        .iter()
        .filter(|row| row.starts_with("agent prompt"))
        .count();
    assert!(
        submissions >= 2,
        "the transient wait was retried inside the window: {submissions}"
    );
    assert!(
        submissions <= 32,
        "the retry stays inside the bounded window: {submissions}"
    );
    assert!(
        fixture.pane_content().is_empty(),
        "nothing was delivered to the pane"
    );
    assert!(
        !fixture.bare_spawned(),
        "no silent fallback: the bare harness executable must never run for an undelivered prompt"
    );
}

/// Issue #148 witness 1 (and the mutation probe's target): a prompt row that
/// exits ZERO while nothing reaches the agent is STILL undelivered. Success is
/// tied to the agent's own read-back, so the run never records a delivery (and
/// never parks as a worker-wait) because a subprocess happened to exit 0.
/// Removing the read-back verification turns this test GREEN — the probe that
/// proves the verification bites.
#[test]
fn a_prompt_row_that_exited_zero_without_delivering_is_still_undelivered() {
    let fixture = Fixture::new("prompt-zero-no-delivery");
    fixture.install(FAKE_HERDR);
    let env = fixture.env(&[("HF_FAKE_HERDR_PROMPT_FAIL", "no-delivery".to_string())]);
    let payload = "Implement jirathip-dev/canter#148 from its latest issue text.";
    // Same fork as the witness above: the task text sits in the scrollback
    // (launch echo) while the zero-exit row delivers nothing.
    fixture.seed_launch_echo(payload);
    let session = lane_session(1);
    let profile = lane_profile(ExecutionMode::HerdrPane);
    let started =
        execute_op_in_worktree(&profile, &start_request(&session), &env, &fixture.worktree);
    assert_eq!(started.status, "succeeded", "{:?}", started.message);

    let result = execute_op_in_worktree(
        &profile,
        &prompt_request(&session, payload),
        &env,
        &fixture.worktree,
    );

    assert_eq!(
        result.status, "refused",
        "a zero exit is not a delivery: {:?}",
        result.message
    );
    assert_eq!(result.code, Some(CODE_PROMPT_UNDELIVERED));
    let detail = result.detail.clone().unwrap_or_default();
    assert!(
        detail.contains("exit: 0"),
        "the row's own exit status is recorded: {detail}"
    );
    assert!(
        detail.contains("submitted"),
        "the raw stdout document is recorded: {detail}"
    );
    assert!(
        detail.contains("agent: impl-5") && detail.contains("pane: w1:p1"),
        "the resolved identity is recorded: {detail}"
    );
    assert!(
        fixture.pane_content().is_empty(),
        "the agent's own read-back never showed the task text"
    );
    assert!(!fixture.bare_spawned());
}

/// Issue #148 round 1, the reviewer's fork: a real pane's scrollback can hold
/// the task text WITHOUT the agent ever receiving it — measured live on the
/// #148 pane, whose launch command line embedded the task text while the agent
/// sat idle at its TUI placeholder. Here the pane's read-back carries the task
/// text from BEFORE the submission (the launch echo), the row reports an
/// accepted-looking submission, and the agent's own lifecycle never moves: the
/// prompt must be judged NOT delivered. The mutation probe that removes the
/// lifecycle half of the proof turns this witness RED.
#[test]
fn a_launch_echo_of_the_task_text_is_not_a_delivery() {
    let fixture = Fixture::new("prompt-launch-echo");
    fixture.install(FAKE_HERDR);
    // The row reports a submission (exit 0) and the read-back carries the task
    // text — but only because the pane's scrollback already shows it.
    let env = fixture.env(&[("HF_FAKE_HERDR_PROMPT_FAIL", "no-delivery".to_string())]);
    let payload = "Implement jirathip-dev/canter#148 from its latest issue text.";
    fixture.seed_launch_echo(payload);
    let session = lane_session(1);
    let profile = lane_profile(ExecutionMode::HerdrPane);
    let started =
        execute_op_in_worktree(&profile, &start_request(&session), &env, &fixture.worktree);
    assert_eq!(started.status, "succeeded", "{:?}", started.message);

    let result = execute_op_in_worktree(
        &profile,
        &prompt_request(&session, payload),
        &env,
        &fixture.worktree,
    );

    assert_eq!(
        result.status, "refused",
        "the task text in the scrollback is not a delivery: {:?}",
        result.message
    );
    assert_eq!(result.code, Some(CODE_PROMPT_UNDELIVERED));
    // The pane's own read-back DID carry the task text (the launch echo the
    // measured #148 pane shows) — the verdict came from the agent's lifecycle.
    let echo = fs::read_to_string(fixture.state.join("launch_echo")).unwrap_or_default();
    assert!(
        echo.contains(payload),
        "the double's pane really carries the task text before any delivery: {echo}"
    );
    assert_eq!(
        fixture.pane_content(),
        "",
        "and nothing was delivered to the agent"
    );
    let detail = result.detail.clone().unwrap_or_default();
    assert_eq!(
        detail.matches("state idle seq 0").count(),
        2,
        "the agent's lifecycle never moved in either snapshot: {detail}"
    );
    let message = result.message.clone().unwrap_or_default();
    assert!(
        message.contains("lifecycle") && message.contains("impl-5"),
        "the refusal names what it judged and the agent: {message}"
    );
    assert!(!fixture.bare_spawned());
}

/// Issue #148 round 1, the other half: an agent that TOOK the submission
/// (its lifecycle moved) while the task text never arrived must not be read as
/// delivered either — the transcript half is load-bearing, so a state move for
/// any other reason can never manufacture a delivery.
#[test]
fn a_prompt_the_agent_took_without_the_text_is_not_a_delivery() {
    let fixture = Fixture::new("prompt-accepted-no-text");
    fixture.install(FAKE_HERDR);
    let env = fixture.env(&[("HF_FAKE_HERDR_PROMPT_FAIL", "accepted-no-text".to_string())]);
    let payload = "Implement jirathip-dev/canter#148 from its latest issue text.";
    let session = lane_session(1);
    let profile = lane_profile(ExecutionMode::HerdrPane);
    let started =
        execute_op_in_worktree(&profile, &start_request(&session), &env, &fixture.worktree);
    assert_eq!(started.status, "succeeded", "{:?}", started.message);

    let result = execute_op_in_worktree(
        &profile,
        &prompt_request(&session, payload),
        &env,
        &fixture.worktree,
    );

    assert_eq!(
        result.status, "refused",
        "a lifecycle move without the text is not a delivery: {:?}",
        result.message
    );
    assert_eq!(result.code, Some(CODE_PROMPT_UNDELIVERED));
    let detail = result.detail.clone().unwrap_or_default();
    assert!(
        detail.contains("state idle seq 0")
            && detail.contains("state working seq 1")
            && detail.contains(" -> "),
        "the recorded snapshots show the lifecycle moved but the text never arrived: {detail}"
    );
    assert_eq!(
        fixture.pane_content(),
        "",
        "the agent never received the task text"
    );
    assert!(!fixture.bare_spawned());
}

/// Witness 3: Herdr unavailable is the typed refusal `refusal.unavailable.herdr`
/// — and there is NO silent bare-subprocess fallback (the incriminating marker
/// stays absent). This is the test the mutation probe (reintroduce the bare
/// spawn) turns RED.
#[test]
fn an_unavailable_herdr_is_a_typed_refusal_and_never_a_bare_subprocess() {
    let fixture = Fixture::new("herdr-unavailable");
    // Only the harness executable exists: the substrate is unavailable, and
    // the isolated PATH keeps a host Herdr out of reach.
    fixture.dir.write_executable("fakebin/hermes", FAKE_HERMES);
    let env = fixture.isolated_env();
    let session = lane_session(1);
    let profile = lane_profile(ExecutionMode::HerdrPane);

    let start = execute_op_in_worktree(&profile, &start_request(&session), &env, &fixture.worktree);
    assert_eq!(start.status, "refused", "{:?}", start.message);
    assert_eq!(start.code, Some(CODE_UNAVAILABLE_HERDR));
    assert!(
        start
            .message
            .as_deref()
            .unwrap_or_default()
            .contains("Herdr"),
        "the refusal names the unavailable substrate: {:?}",
        start.message
    );

    let prompt = execute_op_in_worktree(
        &profile,
        &prompt_request(&session, "do the bounded work"),
        &env,
        &fixture.worktree,
    );
    assert_eq!(prompt.status, "refused", "{:?}", prompt.message);
    assert_eq!(prompt.code, Some(CODE_UNAVAILABLE_HERDR));
    assert!(
        !fixture.bare_spawned(),
        "no silent fallback: the bare harness executable must never run when Herdr is unavailable"
    );
}

/// Witness 4: a superseded lane generation never addresses a reused
/// pane/agent identity — the operation refuses typed and NOTHING is delivered
/// to the pane. The mutation probe that removes the generation check turns
/// this test RED.
#[test]
fn a_superseded_lane_generation_is_refused_before_any_prompt_is_delivered() {
    let fixture = Fixture::new("stale-generation");
    fixture.install(FAKE_HERDR);
    // The pane is bound to ANOTHER lane generation (the lane's session id
    // was reused by a later generation, or the pane belongs to another lane).
    let env = fixture.env(&[
        ("HF_FAKE_HERDR_REPORT_LANE", "lane-abc123".to_string()),
        ("HF_FAKE_HERDR_REPORT_GENERATION", "7".to_string()),
    ]);
    // The pane read-back belongs to generation 7 while this run bound 2.
    fixture.seed("lane", "lane-abc123");
    fixture.seed("generation", "7");
    fixture.seed("name", "impl-5");
    fixture.seed("cwd", &fixture.worktree.to_string_lossy());
    fixture.seed("pane", "w1:p1");
    let session = lane_session(2);
    let profile = lane_profile(ExecutionMode::HerdrPane);

    let result = execute_op_in_worktree(
        &profile,
        &prompt_request(&session, "do the bounded work"),
        &env,
        &fixture.worktree,
    );

    assert_eq!(result.status, "refused", "{:?}", result.message);
    assert_eq!(result.code, Some(CODE_STALE_GENERATION));
    assert!(
        result
            .message
            .as_deref()
            .unwrap_or_default()
            .contains("generation 2"),
        "the refusal names the bound generation: {:?}",
        result.message
    );
    assert!(
        !fixture
            .rows()
            .iter()
            .any(|row| row.starts_with("agent prompt")),
        "no prompt is delivered to a reused/stale pane identity: {:?}",
        fixture.rows()
    );
    assert!(
        fixture.pane_content().is_empty(),
        "the stale pane received no content"
    );

    // The same check holds for the observation, interruption and terminal
    // outcome rows: a stale generation is refused there too.
    for op in [Op::Observe, Op::Interrupt, Op::Outcome] {
        let request = OpRequest {
            op,
            session: &session,
            payload: None,
            timeout: Duration::from_secs(30),
        };
        let result = execute_op_in_worktree(&profile, &request, &env, &fixture.worktree);
        assert_eq!(result.code, Some(CODE_STALE_GENERATION), "{op:?}");
    }
    assert!(
        !fixture
            .rows()
            .iter()
            .any(|row| row.starts_with("agent send-keys")),
        "an interruption is never sent to a stale lane's pane: {:?}",
        fixture.rows()
    );
}

/// A workspace whose lane label is already taken by a pane IN ANOTHER
/// worktree is not reused and not duplicated: the bind refuses typed (the
/// lane↔pane identity was reused elsewhere).
#[test]
fn a_labelled_workspace_bound_to_another_worktree_is_refused_not_duplicated() {
    let fixture = Fixture::new("reused-workspace");
    fixture.install(FAKE_HERDR);
    let elsewhere = fixture.dir.path("worktrees/issues-9");
    fs::create_dir_all(&elsewhere).expect("other worktree");
    let env = fixture.env(&[]);
    let session = lane_session(1);
    let profile = lane_profile(ExecutionMode::HerdrPane);
    // The lane's label already exists, hosted at another path, and no agent
    // of this lane is registered.
    fixture.seed("label", "5-impl");
    fixture.seed("workspace", "w9");
    fixture.seed("pane", "w9:p1");
    fixture.seed("cwd", &elsewhere.to_string_lossy());
    fixture.seed("no_agent", "1");

    let result =
        execute_op_in_worktree(&profile, &start_request(&session), &env, &fixture.worktree);

    assert_eq!(result.status, "refused", "{:?}", result.message);
    assert_eq!(result.code, Some(CODE_NAME_COLLISION));
    assert!(
        !fixture
            .rows()
            .iter()
            .any(|row| row.starts_with("worktree open")),
        "no duplicate workspace/pane is created: {:?}",
        fixture.rows()
    );
    assert!(
        !fixture
            .rows()
            .iter()
            .any(|row| row.starts_with("agent start")),
        "no role is started in another lane's pane: {:?}",
        fixture.rows()
    );
}

/// Witness 5: interruption and the terminal outcome are collected through
/// Herdr, and the recorded outcome DISTINGUISHES them (an interrupted lane
/// records `interrupted`; a settled terminal state records the Herdr state).
#[test]
fn interruption_and_the_terminal_outcome_are_collected_through_herdr() {
    let fixture = Fixture::new("interrupt-outcome");
    fixture.install(FAKE_HERDR);
    let env = fixture.env(&[]);
    let session = lane_session(1);
    let profile = lane_profile(ExecutionMode::HerdrPane);

    let started =
        execute_op_in_worktree(&profile, &start_request(&session), &env, &fixture.worktree);
    assert_eq!(started.status, "succeeded", "{:?}", started.message);

    // The run is still working: there is no terminal outcome yet (ambiguous,
    // never reported as a completed run).
    fixture.seed("state", "working");
    let outcome = execute_op_in_worktree(
        &profile,
        &OpRequest {
            op: Op::Outcome,
            session: &session,
            payload: None,
            timeout: Duration::from_secs(30),
        },
        &env,
        &fixture.worktree,
    );
    assert_eq!(outcome.status, "ambiguous", "{:?}", outcome.message);
    assert_eq!(outcome.code, Some("adapter.timeout"));

    // Interruption goes through the Herdr key row and records `interrupted`
    // (distinct from a settled terminal outcome).
    let interrupted = execute_op_in_worktree(
        &profile,
        &OpRequest {
            op: Op::Interrupt,
            session: &session,
            payload: None,
            timeout: Duration::from_secs(30),
        },
        &env,
        &fixture.worktree,
    );
    assert_eq!(interrupted.status, "succeeded", "{:?}", interrupted.message);
    let payload = interrupted.payload.clone().expect("payload");
    assert_eq!(
        payload.get("interrupted").and_then(Val::as_bool),
        Some(true)
    );
    assert_eq!(
        payload.get("outcome").and_then(Val::as_str),
        Some("interrupted")
    );
    assert!(
        fixture
            .rows()
            .iter()
            .any(|row| row == "agent send-keys impl-5 ctrl+c"),
        "the interruption is delivered through the Herdr key row: {:?}",
        fixture.rows()
    );

    // A settled terminal state is collected through the Herdr agent state.
    fixture.seed("state", "done");
    let settled = execute_op_in_worktree(
        &profile,
        &OpRequest {
            op: Op::Outcome,
            session: &session,
            payload: None,
            timeout: Duration::from_secs(30),
        },
        &env,
        &fixture.worktree,
    );
    assert_eq!(settled.status, "succeeded", "{:?}", settled.message);
    let payload = settled.payload.clone().expect("payload");
    assert_eq!(payload.get("state").and_then(Val::as_str), Some("done"));
    assert_eq!(payload.get("outcome").and_then(Val::as_str), Some("done"));

    // Observation reads the Herdr agent state, not a process exit.
    let observed = execute_op_in_worktree(
        &profile,
        &OpRequest {
            op: Op::Observe,
            session: &session,
            payload: None,
            timeout: Duration::from_secs(30),
        },
        &env,
        &fixture.worktree,
    );
    assert_eq!(observed.status, "succeeded", "{:?}", observed.message);
    assert_eq!(
        observed
            .payload
            .as_ref()
            .and_then(|payload| payload.get("state"))
            .and_then(Val::as_str),
        Some("done")
    );
}

/// The bare-subprocess row is the EXPLICIT fallback: it runs only when the
/// profile/steps select it, and a kind with no documented pane row refuses
/// typed instead of being given a fabricated row.
#[test]
fn the_headless_fallback_runs_only_when_it_is_selected_and_unsupported_kinds_refuse() {
    let fixture = Fixture::new("headless-fallback");
    fixture.install(FAKE_HERDR);
    let env = fixture.env(&[]);
    let session = lane_session(1);

    let headless = lane_profile(ExecutionMode::Headless);
    let result = execute_op_in_worktree(
        &headless,
        &prompt_request(&session, "do the bounded work"),
        &env,
        &fixture.worktree,
    );
    assert_eq!(result.status, "succeeded", "{:?}", result.message);
    assert!(
        fixture.bare_spawned(),
        "the headless substrate runs the bare harness row (the documented fallback)"
    );
    assert!(
        !fixture
            .rows()
            .iter()
            .any(|row| row.starts_with("agent prompt")),
        "the headless substrate never reaches the Herdr rows: {:?}",
        fixture.rows()
    );

    // A kind with no documented Herdr pane row refuses typed on the pane
    // substrate (nothing is fabricated, no fallback is taken).
    let jcode = Profile::official(HarnessKind::Jcode, "lane-role")
        .expect("profile")
        .with_binding("example-provider", "example-model")
        .expect("binding");
    let refused = execute_op_in_worktree(&jcode, &start_request(&session), &env, &fixture.worktree);
    assert_eq!(refused.status, "refused", "{:?}", refused.message);
    assert_eq!(refused.code, Some(CODE_EXECUTION_UNSUPPORTED));
}

/// The substrate token is a closed set: an unknown value refuses typed at the
/// mutation layer (it is never coerced to a default), and the default is the
/// Herdr pane.
#[test]
fn the_declared_substrate_is_closed_and_defaults_to_the_pane() {
    assert_eq!(
        declared_execution(None).expect("default"),
        ExecutionMode::HerdrPane
    );
    let defaults = object(vec![("harness_key", string("lane-role"))]);
    assert_eq!(
        declared_execution(Some(&defaults)).expect("default"),
        ExecutionMode::HerdrPane
    );
    let explicit = object(vec![("execution", string("headless"))]);
    assert_eq!(
        declared_execution(Some(&explicit)).expect("explicit"),
        ExecutionMode::Headless
    );
    let unknown = object(vec![("execution", string("ssh"))]);
    let err = declared_execution(Some(&unknown)).expect_err("unknown substrate refuses");
    assert_eq!(err.status, "refused");
    assert_eq!(err.code.as_deref(), Some(CODE_BAD_REQUEST));
    assert!(
        err.message
            .as_deref()
            .unwrap_or_default()
            .contains("never defaulted"),
        "{:?}",
        err.message
    );
}

// ---------------------------------------------------------------------------
// The mutation-layer wiring: the reviewed plan is what names the run's lane
// worktree, and the recorded bind outcome names the pane the worker runs in.
// ---------------------------------------------------------------------------

fn plan_step(id: &str, kind: &str, params: Val) -> Val {
    object(vec![
        ("id", string(id)),
        ("kind", string(kind)),
        ("params", params),
    ])
}

/// A validated plan document whose harness bind step runs on the substrate
/// the step declares (default: the Herdr pane).
fn bound_plan(steps: Vec<Val>) -> canter::mutation::PlanBindings {
    let seed = object(vec![
        ("schema", string("hf-plan/v1")),
        ("plan_id", string("hf_plan_0000000000000000")),
        ("workflow_id", string("fleet-doctrine-1")),
        ("workflow_hash", string(&"0".repeat(64))),
        ("state_epoch", integer(1)),
        ("repository", string("example-org/widgets")),
        (
            "issue",
            object(vec![
                ("number", integer(5)),
                ("revision", string(&"a".repeat(40))),
            ]),
        ),
        ("steps", Val::Arr(steps)),
    ]);
    let digest = sha256_hex(&canonical_bytes(&seed));
    let plan_id = format!("hf_plan_{}", &digest[..16]);
    let mut map = match seed {
        Val::Obj(map) => map,
        _ => unreachable!("object"),
    };
    map.insert("plan_id".to_string(), string(&plan_id));
    let doc = Val::Obj(map);
    bind_plan(&doc).expect("a validated plan")
}

/// Witness 1 at the mutation layer: the supervised run's bind step starts its
/// worker in a Herdr pane whose cwd is the run's lane worktree, and the
/// recorded step outcome names the pane/agent and the substrate.
#[test]
fn the_harness_start_step_starts_the_worker_in_the_lane_worktrees_pane() {
    let fixture = Fixture::new("effect-start");
    fixture.install(FAKE_HERDR);
    let env = fixture.env(&[]);
    let worktrees_root = fixture.dir.path("worktrees");
    let integration = fixture.dir.path("integration");
    fs::create_dir_all(&integration).expect("integration repo");
    let session = lane_session(1);
    let params = object(vec![
        ("harness_key", string("lane-role")),
        ("kind", string("hermes")),
    ]);
    let plan = bound_plan(vec![
        plan_step(
            "p1",
            "worktree_create",
            object(vec![
                ("branch", string("issue-5")),
                ("worktree", string("issues-5")),
            ]),
        ),
        plan_step("p2", "harness_start", params.clone()),
    ]);
    let ctx = EffectContext {
        plan: &plan,
        step_id: "p2",
        kind: "harness_start",
        params: Some(&params),
        repository: "example-org/widgets",
        integration_branch: "staging",
        production_branches: &[],
        worktrees_root: &worktrees_root,
        integration_repo: &integration,
        observed_feature_head: None,
        observed_integration_base: None,
        env: &env,
        role: None,
        session: Some(&session),
        archive_root: None,
    };

    let outcome = execute_step(&ctx);

    assert_eq!(outcome.status, "succeeded", "{:?}", outcome.message);
    let fields = match &outcome.result {
        Val::Obj(fields) => fields,
        other => panic!("an object result, got {other:?}"),
    };
    assert_eq!(
        fields.get("pane").and_then(Val::as_str),
        Some("w1:p1"),
        "the recorded bind names the pane the worker runs in"
    );
    assert_eq!(fields.get("agent").and_then(Val::as_str), Some("impl-5"));
    assert_eq!(fields.get("execution").and_then(Val::as_str), Some("herdr"));
    assert!(
        fixture.rows().iter().any(|row| row
            == &format!(
                "worktree open --cwd {} --path {} --label 5-impl --no-focus",
                fixture
                    .dir
                    .path("integration")
                    .canonicalize()
                    .unwrap()
                    .display(),
                fixture.worktree.display()
            )),
        "the pane is created in the run's lane worktree: {:?}",
        fixture.rows()
    );
    assert!(!fixture.bare_spawned());
}

/// The pane substrate refuses typed when the reviewed plan cannot name exactly
/// one lane worktree — a pane is never created at a bare cwd and never in the
/// wrong lane.
#[test]
fn a_plan_without_one_lane_worktree_refuses_typed_on_the_pane_substrate() {
    let fixture = Fixture::new("effect-worktree");
    fixture.install(FAKE_HERDR);
    let env = fixture.env(&[]);
    let worktrees_root = fixture.dir.path("worktrees");
    let integration = fixture.dir.path("integration");
    fs::create_dir_all(&integration).expect("integration repo");
    let session = lane_session(1);
    let params = object(vec![
        ("harness_key", string("lane-role")),
        ("kind", string("hermes")),
    ]);

    // No step binds a worktree at all.
    let bare_plan = bound_plan(vec![plan_step("p2", "harness_start", params.clone())]);
    let ctx = EffectContext {
        plan: &bare_plan,
        step_id: "p2",
        kind: "harness_start",
        params: Some(&params),
        repository: "example-org/widgets",
        integration_branch: "staging",
        production_branches: &[],
        worktrees_root: &worktrees_root,
        integration_repo: &integration,
        observed_feature_head: None,
        observed_integration_base: None,
        env: &env,
        role: None,
        session: Some(&session),
        archive_root: None,
    };
    let outcome = execute_step(&ctx);
    assert_eq!(outcome.status, "refused", "{:?}", outcome.message);
    assert_eq!(outcome.code.as_deref(), Some(CODE_BAD_REQUEST));
    assert!(
        outcome
            .message
            .as_deref()
            .unwrap_or_default()
            .contains("lane worktree"),
        "{:?}",
        outcome.message
    );
    assert!(
        !fixture
            .rows()
            .iter()
            .any(|row| row.starts_with("worktree open")),
        "no pane is created at a bare cwd: {:?}",
        fixture.rows()
    );

    // Two lane worktrees cannot be represented by one pane: refuse, never
    // panning the wrong lane.
    let two = bound_plan(vec![
        plan_step(
            "p1",
            "worktree_create",
            object(vec![
                ("branch", string("issue-5")),
                ("worktree", string("issues-5")),
            ]),
        ),
        plan_step(
            "p2",
            "worktree_create",
            object(vec![
                ("branch", string("issue-6")),
                ("worktree", string("issues-6")),
            ]),
        ),
        plan_step("p3", "harness_start", params.clone()),
    ]);
    let ctx = EffectContext {
        plan: &two,
        step_id: "p3",
        kind: "harness_start",
        params: Some(&params),
        repository: "example-org/widgets",
        integration_branch: "staging",
        production_branches: &[],
        worktrees_root: &worktrees_root,
        integration_repo: &integration,
        observed_feature_head: None,
        observed_integration_base: None,
        env: &env,
        role: None,
        session: Some(&session),
        archive_root: None,
    };
    let outcome = execute_step(&ctx);
    assert_eq!(outcome.status, "refused", "{:?}", outcome.message);
    assert!(
        outcome
            .message
            .as_deref()
            .unwrap_or_default()
            .contains("headless"),
        "the refusal names the explicit fallback: {:?}",
        outcome.message
    );
    assert!(fixture.rows().is_empty(), "{:?}", fixture.rows());
}

// ---------------------------------------------------------------------------
// Issue #144: the start path's own result/read-back contract
// ---------------------------------------------------------------------------

/// Item 1 of issue #144: a Herdr row whose stdout is not a JSON document
/// refuses NAMING the exact argv and CARRYING the raw stdout it printed.
///
/// The measured defect was the opposite: `harness_start` created the pane and
/// started the agent and then refused `refusal.malformed.output` with the
/// message "the Herdr row returned unparsable JSON", which named neither the
/// row nor what it printed — the launch that happened was indistinguishable
/// from a broken read-back.
#[test]
fn a_non_json_row_refuses_with_its_exact_argv_and_raw_stdout() {
    let fixture = Fixture::new("raw-row");
    fixture.install(FAKE_HERDR);
    let raw = "herdr: not a json document (upgrade in progress)";
    let env = fixture.env(&[("HF_FAKE_HERDR_GET_RAW", raw.to_string())]);
    let session = lane_session(1);
    let profile = lane_profile(ExecutionMode::HerdrPane);

    let result =
        execute_op_in_worktree(&profile, &start_request(&session), &env, &fixture.worktree);

    assert_eq!(result.status, "refused", "{:?}", result.message);
    assert_eq!(result.code, Some("refusal.malformed.output"));
    let message = result.message.clone().unwrap_or_default();
    assert!(
        message.contains("herdr agent get impl-5"),
        "the refusal names the exact row: {message}"
    );
    assert!(
        !message.contains("the Herdr row returned unparsable JSON"),
        "the old unnamed message is gone: {message}"
    );
    let detail = result.detail.clone().unwrap_or_default();
    assert!(
        detail.contains("argv: herdr agent get impl-5"),
        "the exact argv is carried: {detail}"
    );
    assert!(detail.contains(raw), "the raw stdout is carried: {detail}");
    assert!(
        !fixture.bare_spawned(),
        "the pane substrate never falls back to the bare harness"
    );
}

/// Item 3 of issue #144: a `pane list` row that resolves as THIS lane's pane
/// but carries no `pane_id` refuses with the RAW ROW — never with the
/// "unparsable JSON" message (the row parsed fine) and never with an empty
/// detail, and without creating a second pane or starting an agent at no
/// identity.
#[test]
fn a_pane_row_without_an_identity_refuses_with_the_raw_row() {
    let fixture = Fixture::new("pane-no-id");
    fixture.install(FAKE_HERDR);
    fixture.seed("lane", "lane-abc123");
    fixture.seed("generation", "1");
    fixture.seed("cwd", &fixture.worktree.to_string_lossy());
    fixture.seed("pane", "w9:p1");
    fixture.seed("label", "5-impl");
    fixture.seed("workspace", "w9");
    fixture.seed("no_agent", "1");
    let env = fixture.env(&[("HF_FAKE_HERDR_PANE_NO_ID", "1".to_string())]);
    let session = lane_session(1);
    let profile = lane_profile(ExecutionMode::HerdrPane);

    let result =
        execute_op_in_worktree(&profile, &start_request(&session), &env, &fixture.worktree);

    assert_eq!(result.status, "refused", "{:?}", result.message);
    assert_eq!(result.code, Some("refusal.malformed.output"));
    let message = result.message.clone().unwrap_or_default();
    assert_eq!(message, "a Herdr pane read-back carries no pane_id");
    assert!(
        !message.contains("unparsable JSON"),
        "a row without an identity is not conflated with unparsable JSON: {message}"
    );
    let detail = result.detail.clone().unwrap_or_default();
    assert!(
        !detail.is_empty(),
        "the refusal carries the raw row it could not address"
    );
    assert!(
        detail.contains(&fixture.worktree.to_string_lossy().to_string()),
        "the raw row is carried: {detail}"
    );
    let rows = fixture.rows();
    assert!(
        !rows.iter().any(|row| row.starts_with("worktree open")),
        "a read-back without an identity creates no second pane: {rows:?}"
    );
    assert!(
        !rows.iter().any(|row| row.starts_with("agent start")),
        "a read-back without an identity starts no agent: {rows:?}"
    );
}
