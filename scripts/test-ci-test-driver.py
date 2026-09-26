#!/usr/bin/env python3
"""Deterministic cleanup complexity/deadline and driver failure regressions."""
import contextlib
import importlib.util
import inspect
import io
import json
import os
import re
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
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
        self.rows = {pid: (1, pid, "S", "/synthetic-target/debug/fixture") for pid in self.alive}
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

    def test_snapshot_carries_the_state_column_into_the_row(self):
        # The state column is what tells a running process from one that has
        # already exited; the snapshot must keep it (issue #301).
        with patch.object(driver.subprocess, "run", return_value=Mock(stdout="100 3 3 Z [sh] <defunct>\n")) as run:
            rows = driver.process_table(deadline=5)
        self.assertEqual(rows, {100: (3, 3, "Z", "[sh] <defunct>")})
        self.assertEqual(run.call_args.args[0][-1], "pid=,ppid=,sess=,state=,command=")

    def rows_with_a_defunct_shell(self):
        # The ubuntu runner's own snapshot row: a shell that has exited and
        # still awaits its reap, inside the suite's session.
        rows = dict(self.rows)
        rows[100200] = (1, 100200, "Z", "[sh] <defunct>")
        return rows

    def test_a_defunct_process_is_not_a_survivor_while_live_rows_still_are(self):
        # Issue #301: the ubuntu runner counted a transient `[sh] <defunct>`
        # in the suite's own session as a leak. An exited process holds no
        # resources and only its parent can reap it, so it is never a
        # survivor this sweep could reclaim — while the live rows of the very
        # same snapshot stay leaks.
        live = set(self.rows)
        with patch.object(driver, "process_table", return_value=self.rows_with_a_defunct_shell()):
            found, remaining = driver.sweep_survivors(Path("/synthetic-target"), {100200}, deadline=12)
        self.assertEqual(remaining, [], "nothing defunct may remain to report")
        self.assertEqual({row[0] for row in found}, live)

    def test_defunct_exclusion_is_load_bearing(self):
        # The classifier — not the snapshot — is what excludes the defunct
        # row: disabling it reproduces the pre-fix reading of the runner's
        # process table, so a regression cannot pass by narrowing the snapshot.
        with patch.object(driver, "is_defunct", return_value=False), patch.object(driver, "process_table", return_value=self.rows_with_a_defunct_shell()):
            found, _ = driver.sweep_survivors(Path("/synthetic-target"), {100200}, deadline=12)
        self.assertIn(100200, {row[0] for row in found})


@unittest.skipUnless(sys.platform == "linux", "the runner-row witness needs /proc session identity")
class RealProcessSweepTests(unittest.TestCase):
    """The sweep against the kernel's process table, not a fabricated snapshot.

    This is the exact shape the ubuntu runner produced (issue #301): a helper
    shell in the suite's own session that has exited while its exit status
    still waits to be reaped. It must not read as a leak, while a live helper
    in the same session still must.
    """

    def spawn(self, body):
        return subprocess.Popen(["/bin/sh", "-c", body], start_new_session=True)

    def test_an_exited_helper_is_no_leak_and_a_live_helper_still_is(self):
        exited = self.spawn("exit 0")
        live = self.spawn("sleep 60")
        sessions = {exited.pid, live.pid}
        try:
            wait_until = time.monotonic() + 5
            while time.monotonic() < wait_until and driver.proc_stat(exited.pid)[0] != "Z":
                time.sleep(0.01)
            self.assertEqual(driver.proc_stat(exited.pid)[0], "Z", "precondition: the helper exited and awaits its reap")
            pids = {row[0] for row in driver.matching_processes(Path("/unused-target"), sessions, time.monotonic() + 5)}
            self.assertIn(live.pid, pids, "a live helper of the same session is still a survivor")
            self.assertNotIn(exited.pid, pids, "an exited helper is not a survivor")
            # Discriminating control: the pre-fix sweep counted the exited
            # helper, so the exclusion above really is the fix at work.
            with patch.object(driver, "is_defunct", return_value=False):
                prefix = {row[0] for row in driver.matching_processes(Path("/unused-target"), sessions, time.monotonic() + 5)}
            self.assertIn(exited.pid, prefix, "the pre-fix reading counted the exited helper")
        finally:
            live.kill()
            live.wait(timeout=3)
            exited.wait(timeout=3)


class InvocationTests(unittest.TestCase):
    def job(self, name):
        text = (Path(__file__).resolve().parents[1] / ".github/workflows/ci.yml").read_text()
        match = re.search(rf"(?ms)^  {re.escape(name)}:\n(.*?)(?=^  [\w-]+:|\Z)", text)
        self.assertIsNotNone(match, f"missing independent job {name}")
        return match[1]

    def test_matrix_enumerates_every_suite_once(self):
        job = self.job("rust-ubuntu-suite")
        # JSON is a YAML subset; a closed single-axis strategy cannot exclude
        # suites or silently expand them into duplicate matrix combinations.
        strategy = job.split("    strategy:\n", 1)[1].split("    steps:\n", 1)[0]
        prefix = "      fail-fast: false\n      max-parallel: 8\n      matrix:\n        suite: "
        self.assertTrue(strategy.startswith(prefix), "independent, non-fail-fast suite matrix")
        actual = json.loads(strategy[len(prefix):])
        root = Path(__file__).resolve().parents[1]
        expected = ["--lib", "--bins"] + ["--test " + p.stem for p in sorted((root / "tests").glob("*.rs"))] + ["--doc"]
        self.assertCountEqual(actual, expected, "matrix must match every tests/*.rs plus lib/bins/doc")
        for suite in actual:
            self.assertEqual(driver.select_suites(suite), [suite.split()], suite)

    def test_ci_budgets(self):
        job = self.job("rust-ubuntu-suite")
        header = job.split("    steps:\n", 1)[0]
        self.assertIn("    name: rust-ubuntu (${{ matrix.suite }})\n", header)
        self.assertIn("    timeout-minutes: 5\n", header)
        self.assertIn("    needs: rust-ubuntu-build\n", header)
        self.assertNotIn("    if:", header)
        self.assertNotIn("continue-on-error", job)
        self.assertNotRegex(job, r"\|\|\s*true")
        step = job.split("      - name: Tests group\n", 1)[1].split("      - name:", 1)[0]
        self.assertIn("timeout-minutes: 4", step)
        self.assertNotIn("if:", step)
        self.assertIn("SUITE: ${{ matrix.suite }}", step)
        self.assertIn('run: python3 -u scripts/ci-test-scope.py --seconds 200 --log-dir "$LOG_DIR" -- python3 -u scripts/ci-test-driver.py --suite="$SUITE" --aggregate-seconds 180 --per-suite-seconds 150\n', step)
        self.assertEqual(job.count("scripts/ci-test-driver.py --suite="), 1)
        upload = job.split("      - name: Upload group diagnostics\n", 1)[1]
        self.assertIn("if: ${{ always() }}", upload)
        self.assertIn("timeout-minutes: 2", upload)
        self.assertIn("if-no-files-found: error", upload)
        self.assertIn("name: rust-ubuntu-tests-${{ matrix.suite }}-${{ github.run_id }}-${{ github.run_attempt }}", upload)
        self.assertEqual(job.count("${{ runner.temp }}/canter-test-group"), 2)
        build = self.job("rust-ubuntu-build")
        self.assertIn("run: cargo test --locked --no-run", build)
        self.assertIn("python3 scripts/test-ci-test-driver.py", build)
        self.assertIn("python3 scripts/test-ci-test-scope.py", build)
        self.assertIn("name: rust-ubuntu-test-build", build)
        self.assertIn("name: rust-ubuntu-test-build", job)

    def test_matrix_aggregate_rejects_failure_cancelled_and_skipped(self):
        gate = self.job("rust-ubuntu")
        self.assertIn("needs: [rust-ubuntu-build, rust-ubuntu-suite]", gate)
        self.assertIn("if: ${{ always() }}", gate)
        self.assertIn("BUILD_RESULT: ${{ needs.rust-ubuntu-build.result }}", gate)
        self.assertIn("SUITE_RESULT: ${{ needs.rust-ubuntu-suite.result }}", gate)
        script = gate.split("        run: |\n", 1)[1]
        for build in ("success", "failure", "cancelled", "skipped"):
            for suites in ("success", "failure", "cancelled", "skipped"):
                result = subprocess.run(["bash", "-euo", "pipefail", "-c", script], env=dict(os.environ, BUILD_RESULT=build, SUITE_RESULT=suites), capture_output=True, text=True, timeout=3)
                self.assertEqual(result.returncode == 0, build == suites == "success", (build, suites, result.stdout))

    def test_matrix_witness_is_explicit_manual_only(self):
        text = (Path(__file__).resolve().parents[1] / ".github/workflows/ci.yml").read_text()
        self.assertIn("matrix_witness:\n        description: 'Deliberately hang --lib and fail --bins; other suites run normally'\n        type: boolean\n        default: false", text)
        step = self.job("rust-ubuntu-suite").split("      - name: Install deliberate matrix witness\n", 1)[1].split("      - name:", 1)[0]
        self.assertIn("if: ${{ github.event_name == 'workflow_dispatch' && inputs.matrix_witness }}", step)
        self.assertIn("run: python3 scripts/ci-matrix-witness.py", step)

    def test_matrix_witness_really_hangs_fails_and_delegates(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            real_cargo = root / "cargo"
            real_cargo.write_text("#!/bin/sh\nprintf 'test real_cargo_delegate ... FAILED\\n'\nexit 23\n")
            real_cargo.chmod(0o755)
            github_path = root / "github-path"
            env = dict(os.environ, PATH=str(root) + os.pathsep + os.environ["PATH"], RUNNER_TEMP=str(root), GITHUB_PATH=str(github_path), CARGO_TARGET_DIR=str(root / "target"))
            subprocess.run([sys.executable, str(Path(__file__).with_name("ci-matrix-witness.py"))], env=env, check=True, timeout=5)
            env["PATH"] = github_path.read_text().strip() + os.pathsep + env["PATH"]
            for suite, expected in [("--lib", 124), ("--bins", 42), ("--test cli_smoke", 23)]:
                result = subprocess.run([sys.executable, "-u", driver.__file__, "--suite=" + suite, "--aggregate-seconds", "8", "--per-suite-seconds", "2"], env=env, capture_output=True, text=True, timeout=12)
                self.assertEqual(result.returncode, expected, (suite, result.stdout, result.stderr))
                self.assertIn("remaining=0", result.stdout)

    def test_groups_enumerate_every_suite_once_including_new_tests(self):
        expected = [("--lib",), ("--bins",), ("--doc",)]
        expected += [("--test", path.stem) for path in Path("tests").glob("*.rs")]
        actual = [tuple(suite) for group in range(1, 5) for suite in driver.select_suites(None, group)]
        self.assertCountEqual(actual, expected)
        with patch.object(driver, "suites", return_value=[["--test", "newly_added"], *driver.suites()]):
            extended = [tuple(suite) for group in range(1, 5) for suite in driver.select_suites(None, group)]
        self.assertCountEqual(extended, [("--test", "newly_added"), *expected])

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
