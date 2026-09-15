#!/usr/bin/env python3
"""Linux regression/witness: setsid + exec + anonymous argv cannot escape CI."""
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

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
Path(sys.argv[1]).write_text(json.dumps({"pid": pid, "tag": os.environ["CANTER_FIXTURE_TAG"], "start": Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19]}))
print("test escaped_descendant_witness ... ", end="", flush=True)
if sys.argv[2] == "kill-driver":
    os.kill(os.getppid(), signal.SIGKILL)
if sys.argv[2] == "hang":
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    time.sleep(120)
'''


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
                deadline = start + 5
                while not pid_file.exists() and child.poll() is None:
                    if time.monotonic() >= deadline:
                        self.fail("witness never started")
                    time.sleep(0.01)
                record = json.loads(pid_file.read_text())
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


if __name__ == "__main__":
    unittest.main()
