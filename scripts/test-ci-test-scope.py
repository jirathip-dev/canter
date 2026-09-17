#!/usr/bin/env python3
"""Linux regression/witness: setsid + exec + anonymous argv cannot escape CI."""
import importlib.util
import ctypes
import fcntl
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

from ci_test_processes import MARKER, has_marker, signal_members

ROOT = Path(__file__).resolve().parents[1]
WRAPPER = ROOT / "scripts/ci-test-scope.py"
SPEC = importlib.util.spec_from_file_location("ci_test_driver", ROOT / "scripts/ci-test-driver.py")
driver = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = driver
SPEC.loader.exec_module(driver)

# exec preserves ignored TERM and the inherited marker; argv/cwd carry no
# target-directory spelling. The handshake waits for exec, not a blind sleep.
ESCAPE = '''import json, os, signal, sys, time
from pathlib import Path
pid = os.fork()
if pid == 0:
    os.setsid()
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    env = dict(os.environ) if sys.argv[2] != "clear" else {}
    os.chdir("/")
    os.execve("/bin/sleep", ["innocent-worker", "120"], env)
deadline = time.monotonic() + 3
while b"innocent-worker" not in Path(f"/proc/{pid}/cmdline").read_bytes():
    if time.monotonic() >= deadline: raise RuntimeError("exec handshake timed out")
    time.sleep(0.01)
record = Path(sys.argv[1])
temporary = record.with_name(record.name + ".tmp")
temporary.write_text(json.dumps({"pid": pid, "tag": os.environ["CANTER_FIXTURE_TAG"], "start": Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19]}))
os.replace(temporary, record)
print("test escaped_descendant_witness ... ", end="", flush=True)
if sys.argv[2] == "kill-driver":
    os.kill(os.getppid(), signal.SIGKILL)
if sys.argv[2] == "hang":
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    time.sleep(120)
'''


class WitnessOutputError(RuntimeError):
    """A witness contract file was absent, empty, or not JSON."""


def contract_record(path, command, exit_status):
    """Parse a fixture's JSON contract file. Absent, empty, and non-JSON
    content all fail typed, naming the command that produced nothing and its
    raw exit status; a bare JSONDecodeError from an empty parse is never an
    acceptable witness failure."""
    try:
        raw = path.read_text()
    except (OSError, UnicodeDecodeError) as error:
        detail = f"unreadable: {type(error).__name__}: {error}"
    else:
        try:
            return json.loads(raw)
        except json.JSONDecodeError as error:
            detail = f"{type(error).__name__}: {error} ({len(raw)} bytes)"
    raise WitnessOutputError(
        f"witness contract {path.name} produced no JSON: {detail}; "
        f"command={' '.join(command)}; raw_exit={exit_status!r}"
    ) from None


def wait_for_contract(path, command, child, deadline):
    """Existence is not readiness: a record is usable only once it parses, so
    a publication observed mid-write is waited for instead of misread."""
    while True:
        try:
            return contract_record(path, command, child.poll())
        except WitnessOutputError:
            if child.poll() is not None or time.monotonic() >= deadline:
                raise
            time.sleep(0.01)


@unittest.skipUnless(sys.platform == "linux", "requires Linux /proc + setsid")
class LinuxScopeTests(unittest.TestCase):
    def test_marker_matches_exact_environment_entry(self):
        with patch.object(Path, "stat") as stat, patch.object(Path, "read_bytes") as read:
            stat.return_value.st_uid = os.getuid()
            for body, expected in [(b"CANTER_FIXTURE_TAG=abc\0", True), (b"CANTER_FIXTURE_TAG=abcd\0", False), (b"OTHER_CANTER_FIXTURE_TAG=abc\0", False)]:
                read.return_value = body
                self.assertEqual(has_marker(123, "abc"), expected)
            read.side_effect = PermissionError("same-user environ denied")
            with self.assertRaises(PermissionError):
                has_marker(123, "abc")

    def test_marker_finds_reexec_in_an_unrelated_session(self):
        env = dict(os.environ, CANTER_FIXTURE_TAG="scope-marker-unit")
        child = subprocess.Popen(["/bin/sleep", "120"], env=env, start_new_session=True)
        try:
            with patch.object(driver, "_fixture_tag", env[MARKER]):
                found = driver.matching_processes(Path("/unused-target"), set(), time.monotonic() + 5)
            self.assertIn(child.pid, [row[0] for row in found])
        finally:
            child.kill()
            child.wait(timeout=3)

    def test_marker_skips_processes_older_than_its_creator(self):
        with patch("ci_test_processes.proc_stat", return_value=["0"] * 19 + ["10"]), patch.object(Path, "read_bytes", side_effect=PermissionError("pre-existing service")) as read:
            self.assertFalse(has_marker(123, "abc", since=20))
            read.assert_not_called()

    def test_signal_rechecks_pid_identity_and_keeps_denial_visible(self):
        with patch("ci_test_processes.proc_stat", return_value=["0"] * 19 + ["new"]), patch("ci_test_processes.os.kill") as kill:
            signal_members({123: "old"}, signal.SIGKILL, time.monotonic() + 1)
            kill.assert_not_called()
        with patch("ci_test_processes.proc_stat", return_value=["0"] * 19 + ["old"]), patch("ci_test_processes.os.kill", side_effect=PermissionError):
            with self.assertRaises(PermissionError):
                signal_members({123: "old"}, signal.SIGKILL, time.monotonic() + 1)

    def witness(self, mode, real_driver=False):
        with tempfile.TemporaryDirectory(prefix="canter-scope-witness-") as temp:
            root = Path(temp)
            pid_file = root / "escape.json"
            fixture = root / "escape.py"
            fixture.write_text(ESCAPE)
            env = dict(os.environ, CARGO_TARGET_DIR=str(root / "target"))
            command = [sys.executable, "-u", str(fixture), str(pid_file), mode]
            if real_driver:
                cargo = root / "cargo"
                cargo.write_text(f"#!/bin/sh\nexec {sys.executable} {fixture} {pid_file} {mode}\n")
                cargo.chmod(0o755)
                env["PATH"] = str(root) + os.pathsep + env["PATH"]
                command = [sys.executable, "-u", str(ROOT / "scripts/ci-test-driver.py"), "--suite=--lib", "--aggregate-seconds", "20", "--per-suite-seconds", "10"]
            argv = [sys.executable, "-u", str(WRAPPER), "--seconds", "1" if mode == "hang" else "25", "--log-dir", str(root / "logs"), "--", *command]
            start = time.monotonic()
            # communicate's timeout also proves calling-shell EOF, not merely
            # leader exit. The escapee intentionally retains inherited fds.
            child = subprocess.Popen(argv, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            record = None
            try:
                record = wait_for_contract(pid_file, argv, child, start + 5)
                output, _ = child.communicate(timeout=30)
                elapsed = time.monotonic() - start
                print(f"WITNESS mode={mode} real_driver={real_driver} raw_exit={child.returncode} duration_s={elapsed:.2f}")
                print(output)
                for filename in ("ps-before.txt", "ps-after.txt", "scope-status.txt"):
                    print(f"--- {filename} ---\n{(root / 'logs' / filename).read_text()}")
                expected = {"hang": 124, "kill-driver": 137}.get(mode, 1)
                self.assertEqual(child.returncode, expected, output)
                self.assertIn("remaining=[] ps_exit=1", output)
                self.assertIn("escaped_descendant_witness", output)
                self.assertFalse(Path(f"/proc/{record['pid']}").exists(), "escapee must be reaped, not merely zombified")
                self.assertLess(elapsed, 18)
                self.assertEqual(len((root / "logs/ps-after.txt").read_text().splitlines()), 1)
                if real_driver:
                    summary = (root / "logs/canter-test-summary.txt").read_text()
                    if mode == "kill-driver":
                        self.assertIn("current_suite=--lib", summary)
                        self.assertIn("innocent-worker", (root / "logs/ps-before.txt").read_text())
                    else:
                        self.assertIn("status\tfailed", summary)
                        self.assertIn("escaped_descendant_witness", summary)
                        self.assertIn("leaked 1 process(es); sweep reaped all", output)
                else:
                    self.assertIn("innocent-worker", (root / "logs/ps-before.txt").read_text())
                print("ZERO_SURVIVORS=1 PROMPT_SHELL_EOF=1")
            finally:
                if child.poll() is None:
                    child.terminate()
                    try:
                        child.wait(timeout=20)
                    except subprocess.TimeoutExpired:
                        child.kill()
                        child.wait(timeout=3)
                if record:
                    signal_members({record["pid"]: record["start"]}, signal.SIGKILL, time.monotonic() + 3)

    def test_escapee_scope_leak_is_red_and_shell_returns(self):
        self.witness("escape")

    def test_term_ignoring_driver_and_escapee_are_killed(self):
        self.witness("hang")

    def test_env_clear_escapee_is_adopted_and_killed(self):
        self.witness("clear")

    def test_real_driver_marker_sweep_finds_escapee_and_stays_red(self):
        self.witness("escape", real_driver=True)

    def test_sigkill_driver_keeps_logs_and_reaps_escapee(self):
        self.witness("kill-driver", real_driver=True)

    def test_success_and_failure_exit_codes_survive_scope(self):
        for code in (0, 42):
            with self.subTest(code=code), tempfile.TemporaryDirectory() as root:
                result = subprocess.run([sys.executable, str(WRAPPER), "--seconds", "3", "--log-dir", root, "--", sys.executable, "-c", f"raise SystemExit({code})"], capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, code, result.stdout + result.stderr)
                self.assertIn("remaining=[] ps_exit=1", result.stdout)

    def flood_witness(self, hostile):
        # The caller deliberately NEVER drains stdout until the wrapper exits.
        # A small kernel pipe makes backpressure deterministic, not load-based.
        libc = ctypes.CDLL(None, use_errno=True)
        old = ctypes.c_int()
        self.assertEqual(libc.prctl(37, ctypes.byref(old), 0, 0, 0), 0)
        self.assertEqual(libc.prctl(36, 1, 0, 0, 0), 0)
        read_fd, write_fd = os.pipe()
        fcntl.fcntl(write_fd, fcntl.F_SETPIPE_SZ, 4096)
        child = None
        records = {}
        try:
            with tempfile.TemporaryDirectory(prefix="canter-emit-witness-") as temp:
                root = Path(temp)
                fixture = root / "flood.py"
                fixture.write_text('''import json, os, signal, subprocess, sys, time
from pathlib import Path
if sys.argv[2] == "hostile": signal.signal(signal.SIGTERM, signal.SIG_IGN)
worker = subprocess.Popen(["/bin/sleep", "120"], start_new_session=True)
rows = {str(pid): Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19] for pid in (os.getpid(), worker.pid)}
record = Path(sys.argv[1])
temporary = record.with_name(record.name + ".tmp")
temporary.write_text(json.dumps(rows))
os.replace(temporary, record)
sys.stdout.buffer.write(b"F" * (4 * 1024 * 1024) + b"FLOOD_COMPLETE\\n")
sys.stdout.buffer.flush()
time.sleep(120)
''')
                argv = [sys.executable, "-u", str(WRAPPER), "--seconds", "1", "--log-dir", str(root / "logs"), "--", sys.executable, "-u", str(fixture), str(root / "pids.json"), "hostile" if hostile else "normal"]
                started = time.monotonic()
                child = subprocess.Popen(argv, stdout=write_fd, stderr=subprocess.STDOUT)
                records = {int(pid): ticks for pid, ticks in wait_for_contract(root / "pids.json", argv, child, started + 3).items()}
                before = subprocess.run(["ps", "-ww", "-p", ",".join(map(str, records)), "-o", "pid,ppid,pgid,sid,stat,args"], capture_output=True, text=True, timeout=3)
                self.assertEqual(before.returncode, 0, before.stderr)
                try:
                    code = child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    print(f"BLOCKED_WRAPPER_PID={child.pid} WCHAN={Path(f'/proc/{child.pid}/wchan').read_text()}")
                    self.fail("scope blocked on a full caller pipe past its deadline")
                elapsed = time.monotonic() - started
                self.assertTrue(os.get_blocking(write_fd), "stdout blocking mode must be restored")
                os.close(write_fd)
                write_fd = None
                # A retained pipe writer would block EOF; select bounds that too.
                import select
                while True:
                    self.assertTrue(select.select([read_fd], [], [], 1)[0], "caller pipe has no EOF")
                    if not os.read(read_fd, 8192):
                        break
                after = subprocess.run(["ps", "-ww", "-p", ",".join(map(str, records)), "-o", "pid,ppid,pgid,sid,stat,args"], capture_output=True, text=True, timeout=3)
                print(f"FLOOD hostile={hostile} raw_exit={code} duration_s={elapsed:.3f} cleanup_s={elapsed - 1:.3f}")
                print(f"PS_BEFORE_EXIT={before.returncode}\n{before.stdout}PS_AFTER_EXIT={after.returncode}\n{after.stdout}")
                print((root / "logs/scope-status.txt").read_text())
                self.assertEqual(code, 124)
                self.assertLess(elapsed, 4.5 if hostile else 3)
                self.assertEqual(after.returncode, 1, after.stdout + after.stderr)
                for pid in records:
                    self.assertFalse(Path(f"/proc/{pid}").exists(), "survivor or zombie remains")
                self.assertEqual((root / "logs/driver.log").read_bytes(), b"F" * (4 * 1024 * 1024) + b"FLOOD_COMPLETE\n")
                self.assertIn("status=finished\nexit=124", (root / "logs/scope-status.txt").read_text())
                self.assertIn("remaining=[] ps_exit=1", (root / "logs/scope.log").read_text())
                print("AUTHORITATIVE_FLOOD_INTACT=1 ZERO_SURVIVORS=1 PROMPT_SHELL_EOF=1")
        finally:
            # Own subreaper/PID identities keep even the pre-fix RED bounded.
            if child is not None and child.poll() is None:
                child.kill()
                child.wait(timeout=3)
            signal_members(records, signal.SIGKILL, time.monotonic() + 3)
            for pid in records:
                try:
                    deadline = time.monotonic() + 3
                    while os.waitpid(pid, os.WNOHANG)[0] == 0:
                        if time.monotonic() >= deadline:
                            raise TimeoutError(f"owned witness PID {pid} did not reap")
                        time.sleep(0.01)
                except ChildProcessError:
                    pass
            if write_fd is not None:
                os.close(write_fd)
            os.close(read_fd)
            libc.prctl(36, old.value, 0, 0, 0)

    def test_full_caller_pipe_cannot_block_scope_deadline(self):
        self.flood_witness(False)

    def test_full_caller_pipe_cannot_block_hostile_child_cleanup(self):
        self.flood_witness(True)

    def test_live_emit_budget_does_not_reduce_authoritative_files(self):
        from ci_test_processes import LiveOutput
        with tempfile.TemporaryDirectory(prefix="canter-emit-budget-") as temp:
            root = Path(temp)
            code = "from pathlib import Path; import time; root=Path(%r); [(root/f'flood-{i}.log').write_bytes(b'X'*(1024*1024)) for i in range(20)]; time.sleep(3)" % temp
            result = subprocess.run([sys.executable, "-u", str(WRAPPER), "--seconds", "6", "--log-dir", temp, "--", sys.executable, "-u", "-c", code], capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertGreater(len(result.stdout), 1024 * 1024)
            self.assertLessEqual(len(result.stdout), 2 * 1024 * 1024 + len(LiveOutput.NOTICE))
            self.assertEqual(result.stdout.count(LiveOutput.NOTICE), 1)
            for i in range(20):
                self.assertEqual((root / f"flood-{i}.log").read_bytes(), b"X" * (1024 * 1024))
            self.assertIn(LiveOutput.NOTICE, (root / "scope.log").read_bytes())
            print(f"LIVE_BYTES={len(result.stdout)} LIMIT={LiveOutput.LIMIT} NOTICE_COUNT={result.stdout.count(LiveOutput.NOTICE)} AUTHORITATIVE_FILES_INTACT=20")

    def test_live_pending_stays_small_and_closed_reader_is_harmless(self):
        from ci_test_processes import LiveOutput
        read_fd, write_fd = os.pipe()
        try:
            fcntl.fcntl(write_fd, fcntl.F_SETPIPE_SZ, 4096)
            with LiveOutput(write_fd) as live:
                self.assertFalse(os.get_blocking(write_fd))
                for _ in range(300):
                    live.write(b"X" * 8192)
                    self.assertLessEqual(len(live.pending), 64 * 1024)
                self.assertEqual(live.consumed, 2 * 1024 * 1024)
                self.assertTrue(live.limited)
                self.assertTrue(live.pending, "exercise partial writes and EAGAIN")
                os.close(read_fd)
                read_fd = None
                live.flush()
                self.assertTrue(live.closed)
                self.assertFalse(live.pending)
            self.assertTrue(os.get_blocking(write_fd))
        finally:
            if read_fd is not None:
                os.close(read_fd)
            os.close(write_fd)


class WitnessContractTests(unittest.TestCase):
    """Platform-independent pin on the record handshake: a contract file is
    readable only once it parses, and an absent, empty, or non-JSON record
    fails typed with the command and its raw exit status."""

    COMMAND = [
        "python3", "-u", "scripts/ci-test-scope.py", "--seconds", "25", "--log-dir", "logs", "--",
        "python3", "-u", "scripts/ci-test-driver.py", "--suite=--lib",
    ]

    def test_absent_empty_and_non_json_records_fail_typed(self):
        with tempfile.TemporaryDirectory(prefix="canter-record-") as temp:
            path = Path(temp) / "escape.json"
            for label, content in (("absent", None), ("empty", ""), ("not-json", "<html>no record</html>")):
                with self.subTest(label=label):
                    if content is None:
                        path.unlink(missing_ok=True)
                    else:
                        path.write_text(content)
                    with self.assertRaises(WitnessOutputError) as raised:
                        contract_record(path, self.COMMAND, 1)
                    message = str(raised.exception)
                    self.assertIn("witness contract escape.json produced no JSON", message)
                    self.assertIn(" ".join(self.COMMAND), message)
                    self.assertIn("raw_exit=1", message)

    def test_a_late_publication_is_waited_for_not_misread(self):
        with tempfile.TemporaryDirectory(prefix="canter-record-late-") as temp:
            path = Path(temp) / "escape.json"
            child = Mock()
            child.poll.return_value = None
            payload = {"pid": 4321, "start": "7"}

            def publish():
                time.sleep(0.05)
                path.write_text(json.dumps(payload))

            writer = threading.Thread(target=publish)
            writer.start()
            try:
                self.assertEqual(wait_for_contract(path, self.COMMAND, child, time.monotonic() + 5), payload)
            finally:
                writer.join(timeout=5)

    def test_a_record_without_a_live_command_fails_typed_with_its_exit(self):
        with tempfile.TemporaryDirectory(prefix="canter-record-settled-") as temp:
            child = Mock()
            child.poll.return_value = 137
            with self.assertRaises(WitnessOutputError) as raised:
                wait_for_contract(Path(temp) / "escape.json", self.COMMAND, child, time.monotonic() + 5)
            self.assertIn("raw_exit=137", str(raised.exception))

    def test_a_record_that_never_arrives_fails_at_the_deadline(self):
        with tempfile.TemporaryDirectory(prefix="canter-record-deadline-") as temp:
            child = Mock()
            child.poll.return_value = None
            started = time.monotonic()
            with self.assertRaises(WitnessOutputError) as raised:
                wait_for_contract(Path(temp) / "escape.json", self.COMMAND, child, started + 0.05)
            self.assertGreaterEqual(time.monotonic() - started, 0.05, "the wait is bounded by its deadline")
            self.assertIn("raw_exit=None", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
