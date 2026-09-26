#!/usr/bin/env python3
"""Bounded serial Rust test driver with leak-safe logging and cleanup."""

from __future__ import annotations

import argparse
from collections import deque
from dataclasses import dataclass
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import time

from ci_test_processes import MARKER, fixture_environment, has_marker, proc_stat

# CI pre-builds every test executable in its own bounded step, so this
# deadline measures serial suite execution rather than a cold compilation.
AGGREGATE_SECONDS = 18 * 60
PER_SUITE_SECONDS = 300
CLEANUP_SECONDS = 10
TAIL_LINES = 120
TEST_LINE = re.compile(r"^test (.+?)(?: \.\.\.| has been running)")
_active_child: subprocess.Popen[bytes] | None = None
_active_target: Path | None = None
_suite_sessions: set[int] = set()
_fixture_tag: str | None = None


@dataclass
class Result:
    suite: str
    exit_code: int
    duration: float
    last_test: str
    survivors: int
    timed_out: bool
    stdout_path: Path
    stderr_path: Path


def suites() -> list[list[str]]:
    result = [["--lib"], ["--bins"]]
    result += [["--test", path.stem] for path in sorted(Path("tests").glob("*.rs"))]
    result += [["--doc"]]
    return result


def select_suites(name: str | None, group: int | None = None) -> list[list[str]]:
    available = suites()
    if group is not None:
        return available[group - 1::4]
    if name is None:
        return available
    aliases = {" ".join(suite): suite for suite in available}
    aliases.update(
        {suite[1]: suite for suite in available if len(suite) == 2 and suite[0] == "--test"}
    )
    try:
        return [aliases[name]]
    except KeyError:
        choices = ", ".join(sorted(aliases))
        raise SystemExit(f"unknown suite {name!r}; choose one of: {choices}") from None


def process_table(deadline: float) -> dict[int, tuple[int, int, str, str]]:
    budget = deadline - time.monotonic()
    if budget <= 0:
        raise TimeoutError("survivor sweep deadline exhausted before snapshot")
    output = subprocess.run(
        ["ps", "-Aww", "-o", "pid=,ppid=,sess=,state=,command="],
        check=True,
        capture_output=True,
        text=True,
        timeout=min(5, budget),
    ).stdout
    rows: dict[int, tuple[int, int, str, str]] = {}
    for line in output.splitlines():
        if time.monotonic() >= deadline:
            raise TimeoutError("survivor sweep deadline exhausted parsing snapshot")
        fields = line.strip().split(None, 4)
        if len(fields) != 5:
            continue
        try:
            rows[int(fields[0])] = (int(fields[1]), int(fields[2]), fields[3], fields[4])
        except ValueError:
            continue
    return rows


def ancestor_pids(rows: dict[int, tuple[int, int, str, str]]) -> set[int]:
    ancestors = {os.getpid()}
    pid = os.getppid()
    while pid > 0 and pid not in ancestors:
        ancestors.add(pid)
        parent = rows.get(pid)
        if parent is None:
            break
        pid = parent[0]
    return ancestors


def is_defunct(state: str) -> bool:
    """Whether a snapshot state is an exited process awaiting its parent's reap.

    A defunct (zombie) process holds none of the resources a leak is about —
    no address space, no open descriptors — and no signal this sweep sends can
    reap it, so counting it false-reds a healthy run: the ubuntu runner's
    process table carried a transient `[sh] <defunct>` in the suite's own
    session and the sweep read it as `leaked 1 process(es)` (issue #301).
    """
    return state.startswith("Z")


def matching_processes(
    target_dir: Path, session_ids: set[int] | None, deadline: float
) -> list[tuple[int, int, str]]:
    rows = process_table(deadline)
    excluded = ancestor_pids(rows)
    since = int(proc_stat(os.getpid())[19]) if sys.platform == "linux" else 0
    # macOS spells /tmp processes as /tmp even though Path.resolve() yields
    # /private/tmp. Match both byte spellings; Linux normally has one.
    markers = {
        str(target_dir.absolute()) + os.sep,
        str(target_dir.resolve()) + os.sep,
    }
    found = []
    for pid, (ppid, sid, state, command) in rows.items():
        if time.monotonic() >= deadline:
            raise TimeoutError("survivor sweep deadline exhausted selecting snapshot")
        if is_defunct(state):
            continue
        if pid not in excluded and (
            any(marker in command for marker in markers)
            or (session_ids is not None and sid in session_ids)
            or (sys.platform == "linux" and has_marker(pid, _fixture_tag, since))
        ):
            found.append((pid, ppid, command))
    return found


def pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        pass  # Permission denied is not proof of absence.
    return True


def signal_rows(
    rows: list[tuple[int, int, str]], signum: int, deadline: float
) -> None:
    for index, (pid, ppid, command) in enumerate(rows):
        if time.monotonic() >= deadline:
            break
        try:
            if pid_alive(pid):
                if index < 20:
                    print(f"Tests survivor signal={signum}: pid={pid} ppid={ppid} command={command[:500]}")
                os.kill(pid, signum)
        except (ProcessLookupError, PermissionError):
            pass  # The liveness check below keeps denied/live PIDs visible.


def wait_for_survivors(
    rows: list[tuple[int, int, str]], deadline: float
) -> list[tuple[int, int, str]]:
    while rows:
        remaining = []
        for index, row in enumerate(rows):
            if time.monotonic() >= deadline:
                return remaining + rows[index:]  # Unchecked is not gone.
            if pid_alive(row[0]):
                remaining.append(row)
        rows = remaining
        if rows:
            time.sleep(min(0.05, max(0, deadline - time.monotonic())))
    return rows


def sweep_survivors(
    target_dir: Path, session_ids: set[int] | None = None, *, deadline: float
) -> tuple[list[tuple[int, int, str]], list[int]]:
    deadline = min(deadline, time.monotonic() + CLEANUP_SECONDS)
    found = matching_processes(target_dir, session_ids, deadline)
    signal_rows(found, signal.SIGTERM, deadline)
    remaining = wait_for_survivors(found, min(deadline, time.monotonic() + 5))
    if remaining:
        signal_rows(remaining, signal.SIGKILL, deadline)
        remaining = wait_for_survivors(remaining, deadline)
    return found, [row[0] for row in remaining]


def reap_group(child: subprocess.Popen[bytes], deadline: float) -> None:
    for signum in (signal.SIGTERM, signal.SIGKILL):
        if child.poll() is not None:
            return
        if time.monotonic() >= deadline:
            break
        try:
            os.killpg(child.pid, signum)
        except ProcessLookupError:
            return
        except PermissionError:
            break
        try:
            child.wait(timeout=max(0, min(5, deadline - time.monotonic())))
            return
        except subprocess.TimeoutExpired:
            pass
    print(f"::error::test process group {child.pid} not reaped within cleanup deadline")


def handle_signal(signum: int, _frame: object) -> None:
    # Unwind through the same deadline-bounded cleanup as an ordinary failure.
    print(f"Tests interrupted by signal {signum}")
    raise SystemExit(128 + signum)


def bounded_tail_lines(path: Path) -> list[str]:
    try:
        with path.open(encoding="utf-8", errors="replace") as stream:
            lines = deque(stream, maxlen=TAIL_LINES)
    except OSError as error:
        return [f"<unreadable: {error}>"]
    if not lines:
        return ["<empty>"]
    rendered = []
    for line in lines:
        text = line.rstrip("\n")
        suffix = "…" if len(text) > 2_000 else ""
        rendered.append(text[:2_000] + suffix)
    return rendered


def print_tail(path: Path) -> None:
    print(f"--- bounded tail: {path} ---")
    for line in bounded_tail_lines(path):
        print(line)


def last_test_name(*paths: Path) -> str:
    last = "<none seen>"
    for path in paths:
        try:
            stream = path.open(encoding="utf-8", errors="replace")
        except OSError:
            continue
        with stream:
            for line in stream:
                match = TEST_LINE.match(line)
                if match:
                    last = match.group(1).strip()
    return last.replace("\t", " ")


def table_lines(results: list[Result]) -> list[str]:
    lines = [
        "TESTS_SUITE_TABLE_BEGIN",
        "suite\texit\tduration_s\tlast_test\tsurvivors\ttimeout",
    ]
    for result in results:
        lines.append(
            f"{result.suite}\t{result.exit_code}\t{result.duration:.1f}\t"
            f"{result.last_test}\t{result.survivors}\t{str(result.timed_out).lower()}"
        )
    lines.append("TESTS_SUITE_TABLE_END")
    return lines


def print_table(results: list[Result]) -> None:
    for line in table_lines(results):
        print(line)


def write_summary(
    path: Path,
    status: str,
    results: list[Result],
    failure: Result | None = None,
    note: str | None = None,
) -> None:
    lines = [f"status\t{status}"]
    if note:
        lines.append(f"note\t{note}")
    lines.extend(table_lines(results))
    if failure is not None:
        lines.extend(
            [
                "FAILURE_DETAIL_BEGIN",
                f"suite\t{failure.suite}",
                f"exit\t{failure.exit_code}",
                f"last_test\t{failure.last_test}",
                f"stdout\t{failure.stdout_path}",
                *bounded_tail_lines(failure.stdout_path),
                f"stderr\t{failure.stderr_path}",
                *bounded_tail_lines(failure.stderr_path),
                "FAILURE_DETAIL_END",
            ]
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text("\n".join(lines) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument("--suite", help="run one suite label or integration-test stem")
    selection.add_argument("--group", type=int, choices=range(1, 5), help="run one of four complete-suite partitions")
    parser.add_argument("--aggregate-seconds", type=float, default=AGGREGATE_SECONDS)
    parser.add_argument("--per-suite-seconds", type=float, default=PER_SUITE_SECONDS)
    parser.add_argument("--log-dir", type=Path)
    parser.add_argument("--summary-file", type=Path)
    return parser.parse_args()


def run_suites(
    chosen: list[list[str]],
    log_dir: Path,
    summary_path: Path,
    target_dir: Path,
    started: float,
    deadline: float,
    per_suite_seconds: float,
    results: list[Result],
) -> int:
    global _active_child

    # Keep teardown inside the aggregate, including when its last suite stalls.
    execution_deadline = deadline - min(CLEANUP_SECONDS, (deadline - started) / 2)
    for index, suite in enumerate(chosen, start=1):
        label = " ".join(suite)
        budget = min(per_suite_seconds, execution_deadline - time.monotonic())
        if budget <= 0:
            note = f"Tests aggregate deadline exceeded before {label}"
            print(f"::error::{note}")
            print_table(results)
            write_summary(summary_path, "deadline", results, note=note)
            return 124

        safe_label = "-".join(part.lstrip("-") for part in suite)
        stdout_path = log_dir / f"{index:02d}-{safe_label}.stdout.log"
        stderr_path = log_dir / f"{index:02d}-{safe_label}.stderr.log"
        suite_started = time.monotonic()
        timed_out = False
        print(f"::group::Tests {label} at +{suite_started - started:.1f}s")
        write_summary(summary_path, "running", results, note=f"current_suite={label}")
        child: subprocess.Popen[bytes] | None = None
        code = 1
        with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
            try:
                child = subprocess.Popen(
                    [
                        "cargo",
                        "test",
                        "--locked",
                        *suite,
                        "--",
                        "--test-threads=1",
                        "--nocapture",
                    ],
                    env=fixture_environment(),
                    start_new_session=True,
                    stdin=subprocess.DEVNULL,
                    stdout=stdout,
                    stderr=stderr,
                )
                _active_child = child
                _suite_sessions.add(child.pid)
                try:
                    code = child.wait(timeout=budget)
                except subprocess.TimeoutExpired:
                    timed_out = True
                    code = 124
                    print(f"::error::Tests {label} exceeded {budget:.1f}s")
            finally:
                cleanup_deadline = min(deadline, time.monotonic() + CLEANUP_SECONDS)
                if child is not None:
                    reap_group(child, cleanup_deadline)
                _active_child = None

        found, remaining = [], []
        cleanup_note = None
        try:
            found, remaining = sweep_survivors(
                target_dir, {child.pid} if child is not None else None,
                deadline=cleanup_deadline,
            )
        except (OSError, subprocess.SubprocessError) as error:
            cleanup_note = f"Tests {label} survivor sweep incomplete: {error}"
            print(f"::error::{cleanup_note}")
            code = code or 1
        if child is not None and not remaining and cleanup_note is None:
            _suite_sessions.discard(child.pid)
        if remaining:
            print(f"::error::Tests {label} survivor sweep could not reap pids {remaining}")
            code = code if code != 0 else 1
        elif found:
            print(f"::error::Tests {label} leaked {len(found)} process(es); sweep reaped all")
            code = code if code != 0 else 1
        if time.monotonic() >= deadline:
            timed_out = True
            code = code or 124
        duration = time.monotonic() - suite_started
        last_test = last_test_name(stdout_path, stderr_path)
        print_tail(stdout_path)
        print_tail(stderr_path)
        print(
            f"Tests {label}: exit {code}; duration={duration:.1f}s; "
            f"last_test={last_test}; survivors={len(found)}; timeout={str(timed_out).lower()}"
        )
        print("::endgroup::")
        result = Result(
            label,
            code,
            duration,
            last_test,
            len(found),
            timed_out,
            stdout_path,
            stderr_path,
        )
        results.append(result)
        if code != 0:
            print_table(results)
            write_summary(summary_path, "failed", results, failure=result, note=cleanup_note)
            return code if code > 0 else 1
        write_summary(summary_path, "running", results)

    print_table(results)
    print(f"Tests aggregate: exit 0; duration={time.monotonic() - started:.1f}s; suites={len(results)}")
    return 0


def main() -> int:
    global _active_target, _fixture_tag

    args = parse_args()
    chosen = select_suites(args.suite, args.group)
    _fixture_tag = fixture_environment()[MARKER]
    os.environ[MARKER] = _fixture_tag
    runner_temp = Path(os.environ.get("RUNNER_TEMP", tempfile.gettempdir()))
    log_dir = args.log_dir or runner_temp / "canter-test-logs"
    summary_path = args.summary_file or runner_temp / "canter-test-summary.txt"
    log_dir.mkdir(parents=True, exist_ok=True)
    target_dir = Path(os.environ.get("CARGO_TARGET_DIR", "target")).absolute()
    _active_target = target_dir
    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)
    started = time.monotonic()
    deadline = started + args.aggregate_seconds
    results: list[Result] = []
    write_summary(summary_path, "starting", results)

    code = 1
    interrupted: BaseException | None = None
    try:
        code = run_suites(
            chosen,
            log_dir,
            summary_path,
            target_dir,
            started,
            deadline,
            args.per_suite_seconds,
            results,
        )
    except BaseException as error:
        interrupted = error
    finally:
        found, remaining = [], []
        note = None
        try:
            found, remaining = sweep_survivors(target_dir, _suite_sessions, deadline=deadline)
            print(
                f"Tests final survivor sweep: found={len(found)} "
                f"remaining={len(remaining)} pids={remaining}"
            )
        except (OSError, subprocess.SubprocessError) as error:
            note = f"final survivor sweep incomplete: {error}; unchecked sessions={sorted(_suite_sessions)}"
            print(f"::error::{note}")
            code = code or 1
        if found and code == 0:
            code = 1
        if remaining:
            code = 1
            note = f"final survivor sweep could not reap pids {remaining}"
        if time.monotonic() >= deadline:
            code = code or 124
        failure = results[-1] if results and results[-1].exit_code != 0 else None
        if interrupted is not None:
            note = f"driver aborted: {type(interrupted).__name__}: {interrupted}; {note or ''}"
        elif found and note is None:
            note = f"final survivor sweep found {len(found)} process(es)"
        write_summary(
            summary_path,
            "passed" if code == 0 else "failed",
            results,
            failure=failure,
            note=note,
        )
    if interrupted is not None:
        raise interrupted
    return code


if __name__ == "__main__":
    raise SystemExit(main())
