#!/usr/bin/env python3
"""Linux outer supervisor: file-backed streams, setsid, marker + orphan reap."""
import argparse
import ctypes
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import uuid

from ci_test_processes import MARKER, LiveOutput, cleanup_scope, reap_adopted


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--seconds", type=float, default=270)
    parser.add_argument("--log-dir", type=Path, required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if sys.platform != "linux" or not command or args.seconds <= 0:
        parser.error("requires Linux, a positive deadline, and a command after --")
    with LiveOutput() as live:
        return run_scope(args, command, live)


def run_scope(args, command, live):
    args.log_dir.mkdir(parents=True, exist_ok=True)
    status = args.log_dir / "scope-status.txt"
    scope_log = args.log_dir / "scope.log"
    status.write_text("status=starting\n")

    def report(text, flush=False):
        # Cleanup/control messages also must never block on the runner pipe.
        with scope_log.open("a") as stream:
            stream.write(text + "\n")
        live.write((text + "\n").encode())
    # PR_SET_CHILD_SUBREAPER: orphaned double-forks (even env_clear + setsid)
    # become ours, not init's. This changes only this supervisor process.
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "cannot enable child subreaper")
    tag = uuid.uuid4().hex
    env = dict(os.environ, CANTER_FIXTURE_TAG=tag, RUNNER_TEMP=str(args.log_dir))
    stopped = 0

    def stop(signum, _frame):
        nonlocal stopped
        stopped = signum

    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, stop)
    offsets = {}

    def emit_logs():
        live.flush()
        if live.consumed >= live.LIMIT:
            return
        # Files remain complete; neither a blocked pipe nor a huge log can
        # prevent the next deadline check. Live output is strictly best-effort.
        for path in sorted(args.log_dir.rglob("*.log")):
            if live.consumed >= live.LIMIT:
                break
            if path == scope_log:
                continue
            with path.open("rb") as stream:
                stream.seek(offsets.get(path, 0))
                data = stream.read(8192)
                offsets[path] = stream.tell()
            if data:
                live.write(f"\n--- {path.relative_to(args.log_dir)} ---\n".encode() + data)

    code = 1
    child = None
    started = time.monotonic()
    try:
        with (args.log_dir / "driver.log").open("wb") as out:
            child = subprocess.Popen(
                ["setsid", "--wait", *command], env=env,
                stdin=subprocess.DEVNULL, stdout=out, stderr=subprocess.STDOUT,
            )
            status.write_text(f"status=running\npgid={child.pid}\n{MARKER}={tag}\n")
            while child.poll() is None and not stopped and time.monotonic() - started < args.seconds:
                reap_adopted(child.pid)
                emit_logs()
                time.sleep(0.1)
            code = child.returncode if child.returncode is not None else 124
            if stopped:
                code = 128 + stopped
    finally:
        if child is not None:
            cleanup_deadline = time.monotonic() + 15
            try:
                found = cleanup_scope(child, tag, args.log_dir, cleanup_deadline, report=report)
                if found:
                    code = code or 1  # Reaping a leak never turns a suite green.
            except (OSError, RuntimeError, subprocess.SubprocessError) as error:
                report(f"::error::scope cleanup incomplete: {error}")
                code = code or 1
                # A denied marker read must not prevent containment cleanup.
                # Retry ancestry-only within the SAME bound; still fail RED.
                try:
                    cleanup_scope(child, None, args.log_dir, cleanup_deadline, report=report)
                except (OSError, RuntimeError, subprocess.SubprocessError) as fallback:
                    report(f"::error::scope fallback incomplete: {fallback}")
        emit_logs()
        code = code if code >= 0 else 128 - code
        status.write_text(f"status=finished\nexit={code}\nduration_s={time.monotonic() - started:.2f}\n{MARKER}={tag}\n")
        report(f"Scope exit={code} duration_s={time.monotonic() - started:.2f}")
        if live.limited:
            with scope_log.open("ab") as stream:
                stream.write(live.NOTICE)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
