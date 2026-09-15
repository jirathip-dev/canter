"""Linux fixture identity and bounded process-scope cleanup (stdlib only)."""
import os
from pathlib import Path
import signal
import subprocess
import time
import uuid

MARKER = "CANTER_FIXTURE_TAG"


class LiveOutput:
    """Best-effort runner output; never wait for a pipe reader."""

    LIMIT = 2 * 1024 * 1024
    PENDING = 64 * 1024
    NOTICE = b"\n::notice::Live output limited; full logs remain in the group artifact files.\n"

    def __init__(self, fd=1):
        self.fd = fd
        self.pending = bytearray()
        self.consumed = 0
        self.limited = False
        self.noticed = False
        self.closed = False

    def __enter__(self):
        self.blocking = os.get_blocking(self.fd)
        os.set_blocking(self.fd, False)
        return self

    def __exit__(self, *_exc):
        try:
            self.flush()
        finally:
            os.set_blocking(self.fd, self.blocking)

    def write(self, data):
        self.flush()
        allowed = min(len(data), self.LIMIT - self.consumed)
        self.consumed += allowed
        queued = min(allowed, self.PENDING - len(self.pending))
        self.pending.extend(data[:queued])
        self.limited |= queued < len(data)
        self.flush()

    def flush(self):
        # At most a data write and a notice write; partial writes/EAGAIN wait
        # for a later tick, never for the consumer. No buffered Python stdout.
        for _ in range(2):
            if self.closed:
                return
            if not self.pending:
                if not self.limited or self.noticed:
                    return
                self.pending.extend(self.NOTICE)
                self.noticed = True
            try:
                written = os.write(self.fd, self.pending)
            except BlockingIOError:
                return
            except BrokenPipeError:
                self.closed = True
                self.pending.clear()
                return
            del self.pending[:written]
            if self.pending:
                return


def fixture_environment():
    env = dict(os.environ)
    env.setdefault(MARKER, uuid.uuid4().hex)
    return env


def has_marker(pid, tag, since=0):
    if not tag:
        return False
    path = Path(f"/proc/{pid}")
    try:
        # A fresh per-scope marker cannot have been inherited by a process
        # older than its creator. This excludes pre-existing nondumpable user
        # services without silently ignoring denial on a possible fixture.
        if since and int(proc_stat(pid)[19]) < since:
            return False
        if (path / "environ").stat().st_uid != os.getuid():
            return False
        return f"{MARKER}={tag}".encode() in (path / "environ").read_bytes().split(b"\0")
    except (FileNotFoundError, ProcessLookupError):
        return False


def proc_stat(pid):
    # comm can contain spaces and parentheses; fields after its final ')' are
    # state, ppid, pgrp, session, ... starttime (the PID-reuse identity).
    text = Path(f"/proc/{pid}/stat").read_text()
    return text.rsplit(")", 1)[1].split()


def scope_snapshot(tag, deadline):
    rows = {}
    since = int(proc_stat(os.getpid())[19])
    for path in Path("/proc").iterdir():
        if time.monotonic() >= deadline:
            raise TimeoutError("scope snapshot deadline exhausted")
        if not path.name.isdecimal():
            continue
        pid = int(path.name)
        try:
            if path.stat().st_uid != os.getuid():
                continue
            stat = proc_stat(pid)
            if int(stat[19]) < since:
                continue
            rows[pid] = (int(stat[1]), stat[19], has_marker(pid, tag, since))
        except (FileNotFoundError, ProcessLookupError):
            continue
    # Subreaper ancestry also covers fixtures intentionally using env_clear.
    # One adjacency traversal, not one full-table search for every child.
    children = {}
    for pid, (ppid, _, _) in rows.items():
        children.setdefault(ppid, []).append(pid)
    owned = set()
    pending = list(children.get(os.getpid(), []))
    while pending:
        pid = pending.pop()
        if pid not in owned:
            owned.add(pid)
            pending.extend(children.get(pid, []))
    owned.update(pid for pid, (_, _, marked) in rows.items() if marked)
    owned.discard(os.getpid())
    return {pid: rows[pid][1] for pid in owned}


def signal_members(rows, signum, deadline):
    for pid, started in rows.items():
        if time.monotonic() >= deadline:
            raise TimeoutError("scope signalling deadline exhausted")
        try:
            if proc_stat(pid)[19] == started:
                os.kill(pid, signum)
        except (FileNotFoundError, ProcessLookupError):
            pass


def reap_adopted(leader):
    # Do not steal Popen's exit status. Reap only this supervisor's adopted
    # children, including zombies that init on a container might leave behind.
    path = Path(f"/proc/{os.getpid()}/task/{os.getpid()}/children")
    for text in path.read_text().split():
        pid = int(text)
        if pid != leader:
            try:
                os.waitpid(pid, os.WNOHANG)
            except ChildProcessError:
                pass


def ps_check(pids, path, deadline):
    if not pids:
        path.write_text("PID PPID PGID SID STAT COMMAND\n")
        return 1
    with path.open("wb") as out:
        out.write(b"PID PPID PGID SID STAT COMMAND\n")
        out.flush()
        return subprocess.run(
            ["ps", "-ww", "-p", ",".join(map(str, sorted(pids))),
             "-o", "pid=,ppid=,pgid=,sid=,stat=,args="],
            stdout=out, stderr=subprocess.STDOUT,
            timeout=max(0.01, min(3, deadline - time.monotonic())),
        ).returncode


def cleanup_scope(child, tag, log_dir, deadline, report=print):
    child.poll()
    found = scope_snapshot(tag, deadline)
    seen = set(found) | {child.pid}
    ps_check(seen, log_dir / "ps-before.txt", deadline)
    report(f"Scope cleanup: found={sorted(found)}", flush=True)
    for signum in (signal.SIGTERM, signal.SIGKILL):
        # The leader's exit is NOT evidence its group died. Signal the whole
        # session-created group even when Popen already observed leader exit.
        try:
            os.killpg(child.pid, signum)
        except ProcessLookupError:
            pass
        rows = scope_snapshot(tag, deadline)
        seen.update(rows)
        signal_members(rows, signum, deadline)
        until = min(deadline, time.monotonic() + 2)
        while time.monotonic() < until:
            child.poll()
            reap_adopted(child.pid)
            if not any(Path(f"/proc/{pid}").exists() for pid in rows):
                break
            time.sleep(0.05)
    child.poll()
    reap_adopted(child.pid)
    remaining = scope_snapshot(tag, deadline)
    ps_code = ps_check(seen | set(remaining), log_dir / "ps-after.txt", deadline)
    report(f"Scope final: remaining={sorted(remaining)} ps_exit={ps_code}", flush=True)
    if remaining or ps_code != 1:
        raise RuntimeError(f"scope not empty: pids={sorted(remaining)} ps_exit={ps_code}")
    return len(found)
