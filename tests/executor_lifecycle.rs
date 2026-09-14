//! Focused acceptance tests for the executor-lifecycle fixes (issue #92).
//!
//! F1 — bounded, explicit, cancellable per-effect deadlines: the deadline
//! terminates the child AND its process group (no orphan), a deadline within
//! the bound completes, and the effective deadline is visible on the step
//! outcome.
//!
//! F2 — a harness step runs the declared role binding (the harness key
//! resolved from the run's committed role configuration, never a default
//! profile), the prompt continues the session `harness_start` bound, and the
//! real child stdout is captured as the step result.
//!
//! The fake executables here are deliberately hostile: they exit non-zero
//! when the argv they receive is not the documented row, so the process-level
//! assertions bite.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use canter::adapters::{
    Op, OpRequest, Profile, bind_identity, execute_op, new_session, run_grouped,
};
use canter::process::{ProcOut, ProcSpec, ProcStatus};

static DIR_COUNTER: AtomicUsize = AtomicUsize::new(0);

/// A temporary directory for one test (removed on drop).
struct Dir {
    root: PathBuf,
}

impl Dir {
    fn new(name: &str) -> Dir {
        let n = DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
        let base = std::env::var_os("CARGO_TARGET_TMPDIR")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let root = base.join(format!(
            "hf-executor-lifecycle-{name}-{}-{n}",
            std::process::id()
        ));
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
        // Fixture processes are recorded-pid only: the runner under test owns
        // their lifetime (this drop removes FILES).
        let _ = fs::remove_dir_all(&self.root);
    }
}

/// The environment one runner invocation receives: PATH (host PATH + the
/// fake bin dir) plus the fixture variables the fake scripts read.
fn runner_env(bin: &Path, extra: &[(&str, &str)]) -> BTreeMap<String, String> {
    let host_path = std::env::var("PATH").unwrap_or_default();
    let mut env = BTreeMap::new();
    env.insert(
        "PATH".to_string(),
        format!("{}:{host_path}", bin.to_string_lossy()),
    );
    for (name, value) in extra {
        env.insert(name.to_string(), value.to_string());
    }
    env
}

/// Whether a pid still exists (`kill -0`); reaps nothing, only observes.
fn pid_alive(pid: u32) -> bool {
    Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

/// The runner's own words about one op (issue #92 round 3): every assertion
/// about the deadline kill prints the status and the captured stderr, so a CI
/// failure self-diagnoses instead of only naming the symptom.
fn describe(out: &ProcOut) -> String {
    format!("status: {:?}; stderr: {:?}", out.status, out.stderr)
}

/// Poll `pid_alive` until it reports gone, bounded by `timeout`.
fn wait_pid_gone(pid: u32, timeout: Duration) -> bool {
    let started = Instant::now();
    while started.elapsed() < timeout {
        if !pid_alive(pid) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    !pid_alive(pid)
}

/// Read the recorded pid file, bounded (the fake writes it right after it
/// forks its own child).
fn read_pid(path: &Path, timeout: Duration) -> u32 {
    let started = Instant::now();
    while started.elapsed() < timeout {
        if let Ok(text) = fs::read_to_string(path)
            && let Ok(pid) = text.trim().parse::<u32>()
        {
            return pid;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    panic!(
        "the fixture never recorded a pid in {} (content: {:?})",
        path.display(),
        fs::read_to_string(path)
    );
}

// ---------------------------------------------------------------------------
// F1 — deadline exceeded: the child AND its process group are gone
// ---------------------------------------------------------------------------

#[test]
fn deadline_kills_the_child_and_its_process_group() {
    let dir = Dir::new("group-kill");
    let bin = dir.path("fakebin");
    let pid_file = dir.path("grandchild.pid");
    // The lane script forks a long-lived helper of its own and waits: this is
    // the real shape that produced an orphan (a harness spawning a helper).
    let lane = dir.write_executable(
        "fakebin/slow-lane",
        "sleep 300 & echo $! > \"$LANE_HELPER_PID\"\nwait",
    );
    let env = runner_env(&bin, &[("LANE_HELPER_PID", &pid_file.to_string_lossy())]);

    let started = Instant::now();
    let out = run_grouped(ProcSpec {
        program: lane.to_str().expect("utf8 path"),
        args: &[],
        env: &env,
        cwd: None,
        // Generous on purpose: the fixture must record its helper pid before
        // the deadline fires, and a loaded host must never lose that race
        // (the assertion under test is the no-orphan kill, not the precision).
        timeout: Duration::from_secs(5),
    });
    let elapsed = started.elapsed();

    assert_eq!(
        out.status,
        ProcStatus::TimedOut,
        "deadline enforced: {}",
        describe(&out)
    );
    assert!(
        elapsed < Duration::from_secs(10),
        "the deadline kill is bounded, took {elapsed:?}: {}",
        describe(&out)
    );
    // The deadline's own diagnosis must be part of the outcome (issue #92
    // round 3): a CI failure can then say what the kill path did.
    assert!(
        out.stderr.contains("deadline kill of process group"),
        "the runner must record what the deadline kill did: {}",
        describe(&out)
    );
    let helper = read_pid(&pid_file, Duration::from_secs(15));
    assert!(
        wait_pid_gone(helper, Duration::from_secs(5)),
        "the forked helper (pid {helper}) survived the deadline: the process group was not \
         terminated: {}",
        describe(&out)
    );
}

#[test]
fn the_group_signal_never_depends_on_the_childs_allowlisted_path() {
    // The exact Linux shape hosted CI caught (run 34807920125): the child's
    // allowlisted PATH cannot resolve `kill`, the pre-fix helper inherited
    // that PATH, and the group signal silently failed while the descendant
    // survived. The helper is now resolved from the ambient environment plus
    // the standard system directories, so the group dies even when the
    // child's PATH carries neither `kill` nor `sleep` (the fixture's helper
    // is spawned by absolute path, so only the group signal depends on the
    // resolution under test).
    let dir = Dir::new("starved-path");
    let bin = dir.path("fakebin");
    let pid_file = dir.path("helper.pid");
    let lane = dir.write_executable(
        "fakebin/starved-lane",
        "/bin/sleep 300 & echo $! > \"$LANE_HELPER_PID\"\nwait",
    );
    let mut env = runner_env(&bin, &[("LANE_HELPER_PID", &pid_file.to_string_lossy())]);
    // Only the fixture's own directory: no system directory is on it.
    env.insert("PATH".to_string(), bin.to_string_lossy().to_string());

    let started = Instant::now();
    let out = run_grouped(ProcSpec {
        program: lane.to_str().expect("utf8 path"),
        args: &[],
        env: &env,
        cwd: None,
        // Generous on purpose: the fixture must record its helper pid before
        // the deadline fires, and a loaded host must never lose that race
        // (the assertion under test is the no-orphan kill, not the precision).
        timeout: Duration::from_secs(5),
    });
    let elapsed = started.elapsed();

    assert_eq!(
        out.status,
        ProcStatus::TimedOut,
        "deadline enforced: {}",
        describe(&out)
    );
    assert!(
        elapsed < Duration::from_secs(10),
        "the deadline kill is bounded, took {elapsed:?}: {}",
        describe(&out)
    );
    let helper = read_pid(&pid_file, Duration::from_secs(15));
    assert!(
        wait_pid_gone(helper, Duration::from_secs(5)),
        "the forked helper (pid {helper}) survived a deadline whose child PATH cannot resolve \
         `kill`: the group signal depended on the child's allowlisted PATH: {}",
        describe(&out)
    );
}

#[test]
fn a_descendant_that_holds_the_pipe_never_blocks_the_deadline() {
    let dir = Dir::new("pipe-survivor");
    let bin = dir.path("fakebin");
    let pid_file = dir.path("survivor.pid");
    // The lane script writes a partial line, then forks a helper into its OWN
    // process group (`set -m`, job control) so the deadline's group signal
    // cannot reach it, and waits: the survivor holds the inherited stdout and
    // stderr write ends for its whole lifetime. This is the shape hosted CI
    // caught on Linux (a descendant outliving the child keeps a read-to-EOF
    // blocked), made deterministic on every platform. The helper's life is
    // deliberately short (20 s): long past the deadline + grace, far short of
    // stalling a failing run.
    let lane = dir.write_executable(
        "fakebin/pipe-holder",
        "printf 'partial'\nset -m\nsleep 20 &\necho $! > \"$LANE_SURVIVOR_PID\"\nwait",
    );
    let env = runner_env(&bin, &[("LANE_SURVIVOR_PID", &pid_file.to_string_lossy())]);

    // Generous on purpose (as in the group-kill cases): the fixture must
    // record its survivor pid before the deadline fires.
    let timeout = Duration::from_secs(5);
    let started = Instant::now();
    let out = run_grouped(ProcSpec {
        program: lane.to_str().expect("utf8 path"),
        args: &[],
        env: &env,
        cwd: None,
        timeout,
    });
    let elapsed = started.elapsed();
    // The survivor escapes this runner's group by construction, so the test
    // owns its lifetime: reap it by its recorded pid before asserting.
    let survivor = read_pid(&pid_file, Duration::from_secs(15));
    let _ = Command::new("kill")
        .args(["-9", &survivor.to_string()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    assert_eq!(
        out.status,
        ProcStatus::TimedOut,
        "deadline enforced: {}",
        describe(&out)
    );
    assert!(
        elapsed < timeout + canter::adapters::PIPE_READ_GRACE + Duration::from_secs(2),
        "a descendant holding the pipes must never extend the op past the deadline plus the \
         documented grace ({:?}), took {elapsed:?}: {}",
        canter::adapters::PIPE_READ_GRACE,
        describe(&out)
    );
    assert!(
        out.stdout.is_empty() || out.stdout == "partial",
        "the capture stays whatever arrived inside the bound: {:?} ({})",
        out.stdout,
        describe(&out)
    );
}

#[test]
fn a_deadline_within_the_bound_completes_and_keeps_its_group() {
    let dir = Dir::new("within-bound");
    let bin = dir.path("fakebin");
    let pid_file = dir.path("helper.pid");
    // The helper outlives nothing here: the child finishes inside the
    // deadline, so the runner must report a completed process and must NOT
    // signal the group.
    let lane = dir.write_executable(
        "fakebin/fast-lane",
        "printf 'done' ; sleep 0.2 & echo $! > \"$LANE_HELPER_PID\"\nwait",
    );
    let env = runner_env(&bin, &[("LANE_HELPER_PID", &pid_file.to_string_lossy())]);

    let out = run_grouped(ProcSpec {
        program: lane.to_str().expect("utf8 path"),
        args: &[],
        env: &env,
        cwd: None,
        timeout: Duration::from_secs(30),
    });

    assert_eq!(out.status, ProcStatus::Exit(0), "{:?}", out.stderr);
    assert_eq!(out.stdout, "done", "the real child stdout is captured");
}

// ---------------------------------------------------------------------------
// F2 — the declared role binding is the only binding the prompt row uses
// ---------------------------------------------------------------------------

/// A fake Hermes executable that refuses any row other than the documented
/// role-bound prompt row: the profile key on the documented global flag
/// (`-p <key>`), the declared provider/model pair, and the session the run's
/// `harness_start` bound (`chat --continue <session> --create-if-missing`),
/// with the payload last. Its stdout is the real output the step result must
/// carry.
fn role_bound_fake(dir: &Dir, key: &str, provider: &str, model: &str, session: &str) -> PathBuf {
    dir.write_executable(
        "fakebin/hermes",
        &format!(
            "if [ \"$1\" != \"-p\" ] || [ \"$2\" != \"{key}\" ]; then exit 7; fi\n\
             if [ \"$3\" != \"--provider\" ] || [ \"$4\" != \"{provider}\" ]; then exit 8; fi\n\
             if [ \"$5\" != \"-m\" ] || [ \"$6\" != \"{model}\" ]; then exit 9; fi\n\
             if [ \"$7\" != \"chat\" ] || [ \"$8\" != \"--continue\" ]; then exit 10; fi\n\
             if [ \"$9\" != \"{session}\" ]; then exit 11; fi\n\
             if [ \"${{10}}\" != \"--create-if-missing\" ] || [ \"${{11}}\" != \"-q\" ]; then exit 12; fi\n\
             printf 'real-output:%s|session:%s' \"${{12}}\" \"$9\""
        ),
    )
}

fn prompt_request<'a>(
    session: &'a canter::adapters::SessionHandle,
    payload: &'a str,
    timeout: Duration,
) -> OpRequest<'a> {
    OpRequest {
        op: Op::Prompt,
        session,
        payload: Some(payload),
        timeout,
    }
}

#[test]
fn prompt_runs_the_declared_role_binding_and_returns_real_output() {
    let dir = Dir::new("role-bound");
    let bin = dir.path("fakebin");
    let env = runner_env(&bin, &[]);
    role_bound_fake(&dir, "lane-7", "provider-a", "model-a", "sess-92");
    let profile = Profile::official(canter::adapters::HarnessKind::Hermes, "lane-7")
        .expect("profile")
        .with_binding("provider-a", "model-a")
        .expect("binding");
    let identity = bind_identity("lane-7", "tty-7", 1).expect("identity");
    let session = new_session("sess-92", identity).expect("session");

    let result = execute_op(
        &profile,
        &prompt_request(&session, "do the bounded work", Duration::from_secs(10)),
        &env,
    );

    assert_eq!(result.status, "succeeded", "{:?}", result.message);
    let payload = result.payload.expect("payload");
    assert_eq!(
        payload.get("transcript").and_then(|value| value.as_str()),
        Some("real-output:do the bounded work|session:sess-92"),
        "the real child stdout is the step result"
    );
}
