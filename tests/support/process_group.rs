//! Test-child containment: every daemon owns one process group and is reaped.

use std::io;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus};
use std::time::{Duration, Instant};

const REAP_WAIT: Duration = Duration::from_secs(5);

pub struct GroupChild {
    child: Child,
    pid: i32,
    socket: PathBuf,
    status: Option<ExitStatus>,
}

impl GroupChild {
    pub fn spawn(command: &mut Command, socket: &Path) -> io::Result<Self> {
        command.process_group(0);
        let child = command.spawn()?;
        let pid = child.id() as i32;
        Ok(Self {
            child,
            pid,
            socket: socket.to_path_buf(),
            status: None,
        })
    }

    pub fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        if self.status.is_none() {
            self.status = self.child.try_wait()?;
        }
        Ok(self.status)
    }

    pub fn terminate(&mut self, label: &str) -> ExitStatus {
        let _ = self.try_wait();
        if alive(-self.pid) {
            signal(-self.pid, libc::SIGTERM).expect("SIGTERM fixture process group");
        }
        if !self.wait_group(REAP_WAIT) {
            signal(-self.pid, libc::SIGKILL).expect("SIGKILL fixture process group");
            assert!(
                self.wait_group(REAP_WAIT),
                "{label} process group {} survived SIGKILL",
                self.pid
            );
        }
        let status = self
            .status
            .or_else(|| self.child.try_wait().ok().flatten())
            .unwrap_or_else(|| panic!("{label} leader {} was not reaped", self.pid));
        self.status = Some(status);
        assert_gone(self.pid, label);
        status
    }

    fn wait_group(&mut self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            let _ = self.try_wait();
            if self.status.is_some() && !alive(-self.pid) {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn reap_on_drop(&mut self) {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = self.terminate("fixture daemon Drop");
        }));
        if result.is_err() {
            let _ = signal(-self.pid, libc::SIGKILL);
            let reaped = self.wait_group(REAP_WAIT);
            eprintln!(
                "fixture daemon Drop fallback: group={} reaped={} socket={}",
                self.pid,
                reaped,
                self.socket.display()
            );
        }
    }
}

impl Drop for GroupChild {
    fn drop(&mut self) {
        self.reap_on_drop();
    }
}

pub fn assert_no_process_for_socket(socket: &Path) {
    let matches = socket_processes(socket).expect("inspect process table");
    assert!(
        matches.is_empty(),
        "fixture socket {} still has process(es): {matches:?}",
        socket.display()
    );
}

fn assert_gone(pid: i32, label: &str) {
    assert!(!alive(pid), "{label} leader {pid} is still alive");
    assert!(!alive(-pid), "{label} process group {pid} is still alive");
}

fn signal(target: i32, signal: i32) -> io::Result<()> {
    if unsafe { libc::kill(target, signal) } == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        Ok(())
    } else {
        Err(error)
    }
}

fn alive(target: i32) -> bool {
    if unsafe { libc::kill(target, 0) } == 0 {
        return true;
    }
    io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
}

fn socket_processes(socket: &Path) -> io::Result<Vec<String>> {
    let output = Command::new("ps")
        .args(["-Aww", "-o", "pid=,ppid=,command="])
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other("ps process-table inspection failed"));
    }
    let needle = socket.as_os_str().to_string_lossy();
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| line.contains(needle.as_ref()))
        .map(str::to_string)
        .collect())
}
