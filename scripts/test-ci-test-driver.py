#!/usr/bin/env python3
"""Deterministic cleanup complexity/deadline and driver failure regressions."""
import contextlib
import importlib.util
import inspect
import io
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

SPEC = importlib.util.spec_from_file_location(
    "ci_test_driver", Path(__file__).with_name("ci-test-driver.py")
)
driver = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = driver
SPEC.loader.exec_module(driver)


class SweepTests(unittest.TestCase):
    def setUp(self):
        self.now = 0.0
        self.calls = 0
        self.alive = set(range(100001, 100129))
        self.rows = {pid: (1, pid, "/synthetic-target/debug/fixture") for pid in self.alive}
        self.enterContext(contextlib.redirect_stdout(io.StringIO()))
        self.enterContext(patch.object(driver.time, "monotonic", side_effect=lambda: self.now))
        self.enterContext(patch.object(driver.time, "sleep", side_effect=self.advance))
        self.enterContext(patch.object(driver.os, "kill", side_effect=self.kill))

    def advance(self, seconds):
        self.now += seconds

    def kill(self, pid, signum):
        if pid not in self.alive:
            raise ProcessLookupError(pid)
        if signum == signal.SIGKILL:
            self.alive.remove(pid)

    def table(self, *args):
        self.calls += 1
        return dict(self.rows)

    def sweep(self, deadline):
        # Allows the pre-fix implementation to reach the behavioral assertion.
        kwargs = {"deadline": deadline} if "deadline" in inspect.signature(driver.sweep_survivors).parameters else {}
        with patch.object(driver, "process_table", side_effect=self.table):
            return driver.sweep_survivors(Path("/synthetic-target"), **kwargs)

    def test_storm_takes_one_snapshot_and_escalates(self):
        found, remaining = self.sweep(12)
        self.assertEqual(self.calls, 1, "one process-table snapshot per sweep")
        self.assertEqual(len(found), 128)
        self.assertEqual(remaining, [])
        self.assertFalse(self.alive)

    def test_entire_sweep_obeys_remaining_deadline(self):
        found, remaining = self.sweep(0.2)
        self.assertLessEqual(self.now, 0.2, "cleanup cannot reset its deadline per phase")
        self.assertEqual(len(found), 128)
        self.assertEqual(set(remaining), self.alive)
        self.assertTrue(remaining, "unreaped processes must remain visible")

    def test_permission_denied_is_not_absence(self):
        with patch.object(driver.os, "kill", side_effect=PermissionError("denied")):
            found, remaining = self.sweep(0.2)
        self.assertEqual(len(found), 128)
        self.assertEqual(len(remaining), 128)

    def test_signal_loop_stops_at_deadline_and_reports_unchecked_pids(self):
        def slow_kill(pid, signum):
            self.advance(0.01)
            return self.kill(pid, signum)
        with patch.object(driver.os, "kill", side_effect=slow_kill):
            _, remaining = self.sweep(0.2)
        self.assertLess(self.now, 0.23)
        self.assertEqual(len(remaining), 128)

    def test_snapshot_timeout_uses_remaining_budget(self):
        with patch.object(driver.subprocess, "run", return_value=Mock(stdout="")) as run:
            kwargs = {"deadline": 0.2} if "deadline" in inspect.signature(driver.process_table).parameters else {}
            driver.process_table(**kwargs)
        self.assertLessEqual(run.call_args.kwargs["timeout"], 0.2)

    def test_snapshot_deadline_failure_still_writes_summary(self):
        with tempfile.TemporaryDirectory() as root:
            summary = Path(root) / "summary.txt"
            with patch.object(sys, "argv", ["driver", "--suite=--lib", "--log-dir", root, "--summary-file", str(summary)]), patch.object(driver, "run_suites", return_value=0), patch.object(driver, "process_table", side_effect=subprocess.TimeoutExpired("ps", 0.2)), patch.object(driver.signal, "signal"):
                self.assertNotEqual(driver.main(), 0)
            self.assertIn("status\tfailed", summary.read_text())
            self.assertIn("sweep", summary.read_text())

    def test_group_waits_share_the_deadline(self):
        child = Mock(pid=100001)
        child.poll.return_value = None
        def wait(timeout):
            self.advance(timeout)
            raise subprocess.TimeoutExpired("child", timeout)
        child.wait.side_effect = wait
        kwargs = {"deadline": 0.2} if "deadline" in inspect.signature(driver.reap_group).parameters else {}
        with patch.object(driver.os, "killpg"):
            driver.reap_group(child, **kwargs)
        self.assertLessEqual(self.now, 0.2)


class InvocationTests(unittest.TestCase):
    def test_ci_budgets(self):
        workflow = Path(__file__).resolve().parents[1] / ".github/workflows/ci.yml"
        text = workflow.read_text()
        self.assertIn("timeout -k 15 900 python3 -u scripts/ci-test-driver.py --aggregate-seconds 600 --per-suite-seconds 150", text)
        self.assertIn("timeout-minutes: 35", text)
        self.assertIn("cargo test --locked --no-run", text)

    def test_real_driver_keeps_failure_last_test_and_serial_flags(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            cargo = root / "cargo"
            cargo.write_text("#!/bin/sh\ncase \"$*\" in *'--test-threads=1 --nocapture'*) ;; *) exit 99;; esac\nprintf 'test deliberately_failing ... FAILED\\n'\nexit 42\n")
            cargo.chmod(0o755)
            env = dict(os.environ, PATH=str(root) + os.pathsep + os.environ["PATH"], CARGO_TARGET_DIR=str(root / "target"), RUNNER_TEMP=str(root / "runner"))
            result = subprocess.run([sys.executable, "-u", driver.__file__, "--suite=--lib", "--aggregate-seconds", "10", "--per-suite-seconds", "2"], env=env, capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 42, result.stdout + result.stderr)
            summary = (root / "runner/canter-test-summary.txt").read_text()
            self.assertIn("status\tfailed", summary)
            self.assertIn("deliberately_failing", summary)
            self.assertIn("TESTS_SUITE_TABLE_END", summary)

    def test_real_driver_timeout_reaps_and_publishes_last_test(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            cargo = root / "cargo"
            cargo.write_text("#!/bin/sh\nprintf 'test hanging_witness ... '\nexec sleep 30\n")
            cargo.chmod(0o755)
            env = dict(os.environ, PATH=str(root) + os.pathsep + os.environ["PATH"], CARGO_TARGET_DIR=str(root / "target"), RUNNER_TEMP=str(root / "runner"))
            result = subprocess.run([sys.executable, "-u", driver.__file__, "--suite=--lib", "--aggregate-seconds", "8", "--per-suite-seconds", "2"], env=env, capture_output=True, text=True, timeout=12)
            self.assertEqual(result.returncode, 124, result.stdout + result.stderr)
            self.assertIn("remaining=0", result.stdout)
            summary = (root / "runner/canter-test-summary.txt").read_text()
            self.assertIn("hanging_witness", summary)
            self.assertIn("TESTS_SUITE_TABLE_END", summary)


if __name__ == "__main__":
    unittest.main()
