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
//!    it (`workspace create --cwd …`, `agent start … --pane`, pane read-back);
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
    CODE_BAD_REQUEST, CODE_EXECUTION_UNSUPPORTED, CODE_STALE_GENERATION, CODE_UNAVAILABLE_HERDR,
    ExecutionMode, HarnessKind, Op, OpRequest, Profile, bind_identity, execute_op_in_worktree,
    new_session,
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
        Dir { root }
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
  printf '{"name":"%s","pane_id":"%s","cwd":"%s","agent_status":"%s","tokens":{"canter_lane":"%s","canter_generation":"%s"}}' \
    "$(read_state lane '')" "$(read_state pane 'w1:p1')" "$(read_state cwd '')" "$(read_state state 'idle')" \
    "$(report_lane)" "$(report_generation)"
}
case "$1 $2" in
  "workspace list")
    log "$*"
    if [ -f "$STATE/pane" ]; then
      printf '{"id":"cli:workspace:list","result":{"workspaces":[{"workspace_id":"%s","label":"%s","cwd":"%s"}],"type":"workspace_list"}}\n' \
        "$(read_state workspace 'w1')" "$(read_state label '')" "$(read_state cwd '')"
    else
      printf '{"id":"cli:workspace:list","result":{"workspaces":[],"type":"workspace_list"}}\n'
    fi
    ;;
  "workspace create")
    log "$*"
    cwd=""; label=""
    shift 2
    while [ $# -gt 0 ]; do
      case "$1" in
        --cwd) cwd="$2"; shift 2 ;;
        --label) label="$2"; shift 2 ;;
        *) shift ;;
      esac
    done
    printf '%s' "$cwd" > "$STATE/cwd"
    printf '%s' "$label" > "$STATE/label"
    printf 'w1' > "$STATE/workspace"
    printf 'w1:p1' > "$STATE/pane"
    printf '{"id":"cli:workspace:create","result":{"workspace":{"workspace_id":"w1"},"root_pane":{"pane_id":"w1:p1","cwd":"%s"},"type":"workspace_create"}}\n' "$cwd"
    ;;
  "pane list")
    log "$*"
    if [ -f "$STATE/pane" ]; then
      printf '{"id":"cli:pane:list","result":{"panes":[{"pane_id":"%s","cwd":"%s","tokens":{"canter_lane":"%s","canter_generation":"%s"}}],"type":"pane_list"}}\n' \
        "$(read_state pane 'w1:p1')" "$(read_state cwd '')" "$(report_lane)" "$(report_generation)"
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
    printf '{"id":"cli:pane:report-metadata","result":{"pane_id":"w1:p1"},"type":"pane_metadata"}\n'
    ;;
  "agent list")
    log "$*"
    if [ -f "$STATE/pane" ] && [ ! -f "$STATE/no_agent" ]; then
      printf '{"id":"cli:agent:list","result":{"agents":[%s],"type":"agent_list"}}\n' "$(agent_doc)"
    else
      printf '{"id":"cli:agent:list","result":{"agents":[],"type":"agent_list"}}\n'
    fi
    ;;
  "agent start")
    log "$*"
    lane="$3"
    printf '%s' "$lane" > "$STATE/lane"
    printf '{"id":"cli:agent:start","result":{"name":"%s","pane_id":"%s"},"type":"agent_start"}\n' "$lane" "$(read_state pane 'w1:p1')"
    ;;
  "agent get")
    log "$*"
    if [ -f "$STATE/pane" ]; then
      printf '{"id":"cli:agent:get","result":%s,"type":"agent_info"}\n' "$(agent_doc)"
    else
      printf '{"id":"cli:agent:get","result":null,"type":"agent_info"}\n'
      exit 3
    fi
    ;;
  "agent prompt")
    log "$*"
    printf '%s' "$4" > "$STATE/pane_content"
    printf 'done' > "$STATE/state"
    printf '{"id":"cli:agent:prompt","result":{"agent_status":"done","submitted":true},"type":"agent_prompt"}\n'
    ;;
  "agent read")
    log "$*"
    cat "$STATE/pane_content" 2>/dev/null
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
        fs::create_dir_all(&worktree).expect("lane worktree");
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
}

/// The profile of one lane role on the given substrate.
fn lane_profile(execution: ExecutionMode) -> Profile {
    Profile::official(HarnessKind::Hermes, "lane-role")
        .expect("profile")
        .with_binding("example-provider", "example-model")
        .expect("binding")
        .with_execution(execution)
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
    assert_eq!(
        payload.get("agent").and_then(Val::as_str),
        Some("lane-abc123")
    );
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
                "workspace create --cwd {} --label lane-abc123 --no-focus",
                fixture.worktree.display()
            )
        }),
        "the pane is created in the lane worktree: {rows:?}"
    );
    assert!(
        rows.iter().any(|row| row
            == "agent start lane-abc123 --kind hermes --pane w1:p1 -- -p lane-role \
                --provider example-provider -m example-model"),
        "the role starts in that pane with the bound binding: {rows:?}"
    );
    assert!(
        rows.iter().any(|row| row
            == "pane report-metadata w1:p1 --source custom:canter-lane --agent lane-abc123 \
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
        .filter(|row| row.starts_with("workspace create"))
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
            .filter(|row| row.starts_with("workspace create"))
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
    assert_eq!(
        transcript, payload,
        "the pane content read back through `herdr agent read` shows the delivered prompt"
    );
    assert_eq!(fixture.pane_content(), payload);
    assert!(
        fixture.rows().iter().any(|row| row.starts_with(&format!(
            "agent prompt lane-abc123 {payload} --wait --timeout "
        ))),
        "the prompt is delivered through the Herdr row: {:?}",
        fixture.rows()
    );
    assert!(
        !fixture.bare_spawned(),
        "the pane substrate never spawns the bare harness executable for a prompt"
    );
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
    fixture.seed("label", "lane-abc123");
    fixture.seed("workspace", "w9");
    fixture.seed("pane", "w9:p1");
    fixture.seed("cwd", &elsewhere.to_string_lossy());
    fixture.seed("no_agent", "1");

    let result =
        execute_op_in_worktree(&profile, &start_request(&session), &env, &fixture.worktree);

    assert_eq!(result.status, "refused", "{:?}", result.message);
    assert_eq!(result.code, Some(CODE_STALE_GENERATION));
    assert!(
        !fixture
            .rows()
            .iter()
            .any(|row| row.starts_with("workspace create")),
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
            .any(|row| row == "agent send-keys lane-abc123 ctrl+c"),
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
    assert_eq!(
        fields.get("agent").and_then(Val::as_str),
        Some("lane-abc123")
    );
    assert_eq!(fields.get("execution").and_then(Val::as_str), Some("herdr"));
    assert!(
        fixture.rows().iter().any(|row| row
            == &format!(
                "workspace create --cwd {} --label lane-abc123 --no-focus",
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
            .any(|row| row.starts_with("workspace create")),
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
