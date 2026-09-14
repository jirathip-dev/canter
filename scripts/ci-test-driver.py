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
import tempfile
import time

AGGREGATE_SECONDS = 18 * 60
PER_SUITE_SECONDS = 300
TAIL_LINES = 120
TEST_LINE = re.compile(r"^test (.+?)(?: \.\.\.| has been running)")
_active_child: subprocess.Popen[bytes] | None = None
_active_target: Path | None = None


@dataclass
class Result:
    suite: str
    exit_code: int
    duration: float
    last_test: str
    survivors: int


def suites() -> list[list[str]]:
    result = [["--lib"], ["--bins"]]
    result += [["--test", path.stem] for path in sorted(Path("tests").glob("*.rs"))]
    result += [["--doc"]]
    return result


def select_suites(name: str | None) -> list[list[str]]:
    available = suites()
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


def process_table() -> dict[int, tuple[int, str]]:
    output = subprocess.run(
        ["ps", "-Aww", "-o", "pid=,ppid=,command="],
        check=True,
        capture_output=True,
        text=True,
        timeout=5,
    ).stdout
    rows: dict[int, tuple[int, str]] = {}
    for line in output.splitlines():
        fields = line.strip().split(None, 2)
        if len(fields) != 3:
            continue
        try:
            rows[int(fields[0])] = (int(fields[1]), fields[2])
        except ValueError:
            continue
    return rows


def ancestor_pids(rows: dict[int, tuple[int, str]]) -> set[int]:
    ancestors = {os.getpid()}
    pid = os.getppid()
    while pid > 0 and pid not in ancestors:
        ancestors.add(pid)
        parent = rows.get(pid)
        if parent is None:
            break
        pid = parent[0]
    return ancestors


def matching_processes(target_dir: Path) -> list[tuple[int, int, str]]:
    rows = process_table()
    excluded = ancestor_pids(rows)
    # macOS spells /tmp processes as /tmp even though Path.resolve() yields
    # /private/tmp. Match both byte spellings; Linux normally has one.
    markers = {
        str(target_dir.absolute()) + os.sep,
        str(target_dir.resolve()) + os.sep,
    }
    return [
        (pid, ppid, command)
        for pid, (ppid, command) in rows.items()
        if pid not in excluded and any(marker in command for marker in markers)
    ]


def sweep_survivors(target_dir: Path) -> tuple[list[tuple[int, int, str]], list[int]]:
    found = matching_processes(target_dir)
    for pid, ppid, command in found:
        # Re-read immediately before signalling so PID reuse cannot target an
        # unrelated process. Ancestors are excluded by matching_processes.
        current = {row[0]: row for row in matching_processes(target_dir)}.get(pid)
        if current is None:
            continue
        print(f"Tests survivor: pid={pid} ppid={ppid} command={command[:500]}")
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    deadline = time.monotonic() + 5
    remaining = [row[0] for row in matching_processes(target_dir)]
    while remaining and time.monotonic() < deadline:
        time.sleep(0.05)
        remaining = [row[0] for row in matching_processes(target_dir)]
    return found, remaining


def kill_group(child: subprocess.Popen[bytes]) -> None:
    if child.poll() is not None:
        return
    try:
        os.killpg(child.pid, signal.SIGKILL)
    except ProcessLookupError:
        return
    try:
        child.wait(timeout=5)
    except subprocess.TimeoutExpired:
        print(f"::error::test process group {child.pid} survived SIGKILL")


def handle_signal(signum: int, _frame: object) -> None:
    if _active_child is not None:
        kill_group(_active_child)
    if _active_target is not None:
        found, remaining = sweep_survivors(_active_target)
        print(
            f"Tests interrupted by signal {signum}; "
            f"survivors={len(found)} remaining={len(remaining)}"
        )
    raise SystemExit(128 + signum)


def tail(path: Path) -> None:
    print(f"--- bounded tail: {path} ---")
    try:
        with path.open(encoding="utf-8", errors="replace") as stream:
            lines = deque(stream, maxlen=TAIL_LINES)
    except OSError as error:
        print(f"<unreadable: {error}>")
        return
    if not lines:
        print("<empty>")
    else:
        for line in lines:
            text = line.rstrip("\n")
            suffix = "…" if len(text) > 2_000 else ""
            print(text[:2_000] + suffix)


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


def print_table(results: list[Result]) -> None:
    print("TESTS_SUITE_TABLE_BEGIN")
    print("suite\texit\tduration_s\tlast_test\tsurvivors")
    for result in results:
        print(
            f"{result.suite}\t{result.exit_code}\t{result.duration:.1f}\t"
            f"{result.last_test}\t{result.survivors}"
        )
    print("TESTS_SUITE_TABLE_END")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--suite", help="run one suite label or integration-test stem")
    parser.add_argument("--aggregate-seconds", type=float, default=AGGREGATE_SECONDS)
    parser.add_argument("--per-suite-seconds", type=float, default=PER_SUITE_SECONDS)
    parser.add_argument("--log-dir", type=Path)
    return parser.parse_args()


def main() -> int:
    global _active_child, _active_target

    args = parse_args()
    chosen = select_suites(args.suite)
    log_dir = args.log_dir or Path(os.environ.get("RUNNER_TEMP", tempfile.gettempdir())) / "canter-test-logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    target_dir = Path(os.environ.get("CARGO_TARGET_DIR", "target")).absolute()
    _active_target = target_dir
    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)
    started = time.monotonic()
    deadline = started + args.aggregate_seconds
    results: list[Result] = []

    for index, suite in enumerate(chosen, start=1):
        label = " ".join(suite)
        budget = min(args.per_suite_seconds, deadline - time.monotonic())
        if budget <= 0:
            print(f"::error::Tests aggregate deadline exceeded before {label}")
            print_table(results)
            return 124

        safe_label = "-".join(part.lstrip("-") for part in suite)
        stdout_path = log_dir / f"{index:02d}-{safe_label}.stdout.log"
        stderr_path = log_dir / f"{index:02d}-{safe_label}.stderr.log"
        suite_started = time.monotonic()
        timed_out = False
        print(f"::group::Tests {label} at +{suite_started - started:.1f}s")
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
                    start_new_session=True,
                    stdout=stdout,
                    stderr=stderr,
                )
                _active_child = child
                try:
                    code = child.wait(timeout=budget)
                except subprocess.TimeoutExpired:
                    timed_out = True
                    code = 124
                    print(f"::error::Tests {label} exceeded {budget:.1f}s")
                    kill_group(child)
            finally:
                if child is not None:
                    kill_group(child)
                _active_child = None

        found, remaining = sweep_survivors(target_dir)
        if remaining:
            print(f"::error::Tests {label} survivor sweep could not reap pids {remaining}")
            code = code if code != 0 else 1
        elif found:
            print(f"::error::Tests {label} leaked {len(found)} target process(es); sweep reaped all")
            code = code if code != 0 else 1
        duration = time.monotonic() - suite_started
        last_test = last_test_name(stdout_path, stderr_path)
        tail(stdout_path)
        tail(stderr_path)
        print(
            f"Tests {label}: exit {code}; duration={duration:.1f}s; "
            f"last_test={last_test}; survivors={len(found)}; timeout={str(timed_out).lower()}"
        )
        print("::endgroup::")
        results.append(Result(label, code, duration, last_test, len(found)))
        if code != 0:
            print_table(results)
            return code if code > 0 else 1

    print_table(results)
    print(f"Tests aggregate: exit 0; duration={time.monotonic() - started:.1f}s; suites={len(results)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
