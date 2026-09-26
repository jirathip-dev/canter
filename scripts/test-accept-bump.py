#!/usr/bin/env python3
"""test-accept-bump.py — self-test for scripts/accept-bump.py (issue #277).

Every scenario runs the REAL driver in a disposable root under /tmp with the
supervisor boundary injected (a fake `launchctl`), so the suite proves the bump
contract without touching this host's service manager, its socket, or its
installed CLI:

* install — both paths carry the same bytes and both verify their signature;
* restart — the restart goes through the supervisor, which launches the
  installed service path (the path the bump writes);
* verify — exactly ONE pid holds the socket, that pid's executable sha256 IS
  the installed build's sha256, and the log records pid, started_at, sha256;
* refusals — a daemon that never comes up, a socket held by a superseded
  build, two holders (each named with its executable), a supervisor that
  launches another path, an unloaded job, a refused restart, an unresolved
  holder executable, a lease naming another pid, diverging installed paths, a
  non-fast-forward move and a failed build each exit non-zero with their
  typed `bump.refusal.<code>`, and never print DONE;
* idempotence — a second bump at the same candidate leaves one socket holder;
* census (issue #316) — the bump takes the PPID-1 `canter daemon` census
  before the restart and after the verify, records both counts, and refuses
  (`bump.refusal.orphans`) naming every NEW daemon when the count grew; a
  pre-existing orphan never blocks a bump;
* daemon ownership (issue #316) — every scenario daemon the harness starts is
  reaped on every exit path (a failing pass included, witnessed by a nested
  failing pass), a killed harness is still reaped by its guardian, and the
  suite FAILS if any scenario daemon outlives it.

Usage:
  python3 scripts/test-accept-bump.py [--bin PATH] [--lsof PATH]

`--bin` defaults to target/release/canter (build it with
`cargo build --release --locked`). Exit codes: 0 all scenarios passed,
1 a scenario failed, 2 usage error.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import signal
import socket as socket_module
import subprocess
import sys
import tempfile
import time
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
DRIVER = os.path.join(HERE, "accept-bump.py")

# Bounded waits for the driver's single-holder deadline: a scenario that must
# observe a freshly started daemon gets room for a loaded host, while a scenario
# that starts nothing classifies at the short deadline.
START_WAIT_SECS = 15.0
NO_START_WAIT_SECS = 2.0

# Fake supervisor: only the two verb forms the driver uses (`print`,
# `kickstart -k`) exist, and it launches exactly the program the spec names —
# so a bump that installs the wrong path cannot fake agreement with it.
LAUNCHCTL_SHIM = r'''#!/usr/bin/env python3
"""Fake `launchctl` for scripts/test-accept-bump.py. Spec via HF_BUMP_SPEC."""
import json
import os
import signal
import socket
import subprocess
import sys
import time

spec = json.load(open(os.environ["HF_BUMP_SPEC"], encoding="utf-8"))
argv = sys.argv[1:]


def log(message):
    with open(spec["log"], "a", encoding="utf-8") as handle:
        handle.write(message + "\n")


def read_state():
    try:
        with open(spec["state"], encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return {}


def write_state(data):
    with open(spec["state"], "w", encoding="utf-8") as handle:
        json.dump(data, handle)


def alive(pid):
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def stop_previous():
    pid = read_state().get("pid")
    if pid and alive(pid):
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            pass
        deadline = time.time() + 10
        while alive(pid) and time.time() < deadline:
            time.sleep(0.05)
        if alive(pid):
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
        log("stopped pid %s" % pid)
    write_state({})


def wait_for_socket(path):
    deadline = time.time() + 10
    while time.time() < deadline:
        probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            probe.settimeout(0.5)
            probe.connect(path)
            return True
        except OSError:
            time.sleep(0.1)
        finally:
            probe.close()
    return False


def lease_pid(path):
    try:
        with open(path, encoding="utf-8") as handle:
            for line in handle:
                if line.startswith("pid "):
                    return line.split(" ", 1)[1].strip()
    except OSError:
        pass
    return "0"


if argv[:1] == ["print"]:
    if spec.get("mode") == "not_loaded":
        print("Could not find service in domain for user", file=sys.stderr)
        sys.exit(113)
    print("%s = {" % spec["job"])
    print("\tprogram = %s" % (spec.get("print_program") or spec["program"]))
    print("}")
    sys.exit(0)

if argv[:1] == ["kickstart"]:
    if spec.get("mode") == "fail":
        print("kickstart: failed", file=sys.stderr)
        sys.exit(1)
    stop_previous()
    if spec.get("mode") == "start":
        env = dict(os.environ)
        env.update(spec.get("env", {}))
        with open(spec["log"], "ab") as out:
            try:
                proc = subprocess.Popen(
                    [spec["program"]] + spec.get("args", []), env=env,
                    stdout=out, stderr=out, start_new_session=True)
            except OSError as exc:
                log("start failed: %s" % exc)
                print("kickstart: %s" % exc, file=sys.stderr)
                sys.exit(3)
        write_state({"pid": proc.pid})
        log("started %s pid=%s" % (spec["program"], proc.pid))
    if spec.get("lease_pid") is not None or spec.get("lease_started_at"):
        # Only after the daemon itself recorded its lease: these scenarios are
        # a lease that names another pid, and a lease whose recorded start
        # predates the build the bump installed.
        wait_for_socket(spec["socket"])
        pid = spec.get("lease_pid")
        if pid == "holder":
            pid = lease_pid(spec["lease"])
        with open(spec["lease"], "w", encoding="utf-8") as handle:
            handle.write("pid %s\nstarted_at %s\n" % (
                pid, spec.get("lease_started_at") or "2000-01-01T00:00:00Z"))
    sys.exit(0)

print("unsupported launchctl invocation: %s" % argv, file=sys.stderr)
sys.exit(2)
'''

# Fake `lsof` variants: a fixed holder set (two holders / no executable row).
LSOF_HOLDERS_SHIM = r'''#!/usr/bin/env python3
"""Fake `lsof` for scripts/test-accept-bump.py: a TWO-holder socket.

One holder resolves an executable and the other does not, so the refusal's
per-holder naming (pid + exe, `unresolved` when it cannot be read) is
observable rather than assumed.
"""
import os
import sys

socket = os.environ["HF_BUMP_SOCKET"]
argv = sys.argv[1:]
if argv[:1] == ["-U"]:
    print("COMMAND   PID     USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME")
    for pid in (11111, 22222):
        print("canter  %d jirathip    4u  unix 0x0000000000000000      0t0 %s" % (pid, socket))
    sys.exit(0)
if "-Fn" in argv:
    if "-p" in argv and argv[argv.index("-p") + 1] == "11111":
        print("n/tmp/orphan-one/canter")
    sys.exit(0)
sys.exit(2)
'''

LSOF_NO_EXE_SHIM = r'''#!/usr/bin/env python3
"""Fake `lsof` for scripts/test-accept-bump.py: one holder, no executable row."""
import os
import sys

socket = os.environ["HF_BUMP_SOCKET"]
argv = sys.argv[1:]
if argv[:1] == ["-U"]:
    print("COMMAND   PID     USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME")
    print("canter  33333 jirathip    4u  unix 0x0000000000000000      0t0 %s" % socket)
    sys.exit(0)
if "-Fn" in argv:
    sys.exit(0)
sys.exit(2)
'''

# Fake `codesign`. BOTH: every signed copy gets the same trailing byte (the two
# installed paths stay identical to each other and diverge from the stale
# daemon that still holds the socket). ACCEPT: only the acceptance target is
# rewritten, so the two installed paths diverge.
CODESIGN_SHIM = r'''#!/usr/bin/env python3
"""Fake `codesign` for scripts/test-accept-bump.py (deterministic rewrite)."""
import sys

MODE = "%(mode)s"
argv = sys.argv[1:]
if argv[:2] == ["--force", "--sign"]:
    path = argv[-1]
    if MODE == "both" or "accept/target" in path:
        with open(path, "ab") as handle:
            handle.write(b"\x00")
    sys.exit(0)
if argv[:1] == ["-v"]:
    sys.exit(0)
sys.exit(2)
'''

# Fake `codesign` that cannot verify: the sign step "succeeds" and the check
# fails, so a bump must refuse rather than leave an unverifiable install.
CODESIGN_UNVERIFIABLE_SHIM = r'''#!/usr/bin/env python3
"""Fake `codesign` for scripts/test-accept-bump.py: signatures never verify."""
import sys

argv = sys.argv[1:]
if argv[:2] == ["--force", "--sign"]:
    sys.exit(0)
if argv[:1] == ["-v"]:
    sys.exit(1)
sys.exit(2)
'''

# Fake `cargo` driven by HF_TEST_CARGO_MODE: HF_TEST_CARGO_BIN is the prebuilt
# real binary the fake build "produces", so the installed candidate runs.
CARGO_SHIM = r'''#!/usr/bin/env python3
"""Fake `cargo` for scripts/test-accept-bump.py."""
import os
import shutil
import sys

mode = os.environ.get("HF_TEST_CARGO_MODE", "ok")
if mode == "fail":
    print("cargo: deliberate build failure", file=sys.stderr)
    sys.exit(101)
built = os.path.join(os.getcwd(), "target", "release", "canter")
os.makedirs(os.path.dirname(built), exist_ok=True)
shutil.copyfile(os.environ["HF_TEST_CARGO_BIN"], built)
os.chmod(built, 0o755)
print("fake cargo: wrote %s" % built)
sys.exit(0)
'''


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_sha256(path: str) -> str | None:
    """sha256 of a file, or None when it is missing/unreadable."""
    try:
        return sha256_file(path)
    except OSError:
        return None


def write_shim(directory: str, name: str, text: str) -> str:
    path = os.path.join(directory, name)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)
    os.chmod(path, 0o755)
    return path


def git(args: list[str], cwd: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(["git"] + args, cwd=cwd, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, text=True, check=False)


# --- scenario-daemon ownership (issue #316) --------------------------------
#
# Every scenario daemon the harness starts runs with
# `--socket <workspace>/<scenario>/state/canter/canter.sock` and is reparented
# to PPID 1 the moment the fake supervisor's launcher exits. That argv is the
# daemon's ONLY durable owner record, and it is what the two sweeps below use:
# the harness reaps its own workspace on every exit path, and the guardian
# (a separate process) reaps it again if the harness is killed outright.

SOCKET_SUFFIX = "/state/canter/canter.sock"


def alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def process_rows() -> list[tuple[int, int, str]]:
    """(pid, ppid, command) for every host process (`ps -axww`)."""
    proc = subprocess.run(["ps", "-axww", "-o", "pid=,ppid=,command="],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          text=True, check=False)
    rows: list[tuple[int, int, str]] = []
    for line in (proc.stdout or "").splitlines():
        fields = line.split(None, 2)
        if len(fields) < 3:
            continue
        try:
            rows.append((int(fields[0]), int(fields[1]), fields[2].strip()))
        except ValueError:
            continue
    return rows


def wait_reaped(pid: int, timeout: float = 10.0) -> bool:
    """True when `pid` is truly gone (a zombie of OUR child is reaped first)."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if not alive(pid):
            return True
        try:
            reaped, _status = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            reaped = pid  # not our child: whoever owns it reaps it
        except OSError:
            reaped = pid
        if reaped == pid:
            return not alive(pid)
        time.sleep(0.05)
    return not alive(pid)


def daemons_under(root: str, skip: set[int], suffix: str = SOCKET_SUFFIX) -> dict[int, str]:
    """Scenario daemons whose command names a socket under `root`.

    Scoped by construction: the marker is the scored socket suffix plus the
    root's own socket needle (`<root><suffix>`), so a foreign daemon (another
    lane's, or the real one) can never match. Callers that own a whole
    workspace pass `suffix=""` — every fixture socket is still required to
    carry the scored suffix.
    """
    forms = {root, os.path.realpath(root)}
    needles = {form.rstrip("/") + suffix for form in forms}
    found: dict[int, str] = {}
    for pid, _ppid, command in process_rows():
        if pid in skip or SOCKET_SUFFIX not in command:
            continue
        if any(needle in command for needle in needles):
            found[pid] = command
    return found


def reap_daemons(root: str, skip: set[int], grace: float = 5.0,
                 suffix: str = SOCKET_SUFFIX) -> dict[int, str]:
    """SIGTERM every scenario daemon under `root`, SIGKILL the bounded survivors.

    Returns whatever is still alive afterwards (empty == fully reaped), so a
    caller can turn a leak into a failure instead of a silent residue.
    """
    found = daemons_under(root, skip, suffix)
    if not found:
        return {}
    print("reap {}, SIGTERM {}".format(root, sorted(found)), flush=True)
    for pid in found:
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            pass
    deadline = time.time() + grace
    while time.time() < deadline and daemons_under(root, skip, suffix):
        time.sleep(0.05)
    for pid in daemons_under(root, skip, suffix):
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass
    deadline = time.time() + grace
    while time.time() < deadline and daemons_under(root, skip, suffix):
        time.sleep(0.05)
    survivors = daemons_under(root, skip, suffix)
    print("reap {}: remaining={}".format(root, sorted(survivors)), flush=True)
    return survivors


def host_census() -> list[tuple[int, str]]:
    """The issue's reproducible measurement: PPID-1 `canter daemon run` rows."""
    census: list[tuple[int, str]] = []
    for pid, ppid, command in process_rows():
        tokens = command.split()
        if ppid != 1 or not tokens:
            continue
        if os.path.basename(tokens[0]) != "canter":
            continue
        if "daemon" not in tokens or "run" not in tokens:
            continue
        census.append((pid, command))
    return census


def start_stand_in_daemon(root: str) -> int:
    """A REAL process whose argv names a socket under `root` (a stand-in)."""
    socket_path = os.path.join(root, "state", "canter", "canter.sock")
    os.makedirs(os.path.dirname(socket_path), exist_ok=True)
    with open(os.path.join(root, "stand-in.log"), "ab") as out:
        proc = subprocess.Popen(
            [sys.executable, "-c", "import time\nwhile True: time.sleep(1)",
             "--settled-stand-in", socket_path],
            stdout=out, stderr=out, start_new_session=True)
    deadline = time.time() + 10
    while time.time() < deadline:
        if proc.pid in daemons_under(root, skip=set()):
            return proc.pid
        time.sleep(0.05)
    raise AssertionError("the stand-in daemon never showed up under {}".format(root))


GUARDIAN_SRC = r'''#!/usr/bin/env python3
"""scripts/test-accept-bump.py guardian: reap a killed harness's scenario daemons.

Usage: guardian <harness-pid> <workspace-root>

The harness reaps its own workspace on every exit path it can run Python on.
A SIGKILLed harness runs none, so this process — outside it, started per
suite — waits for the harness pid to disappear and then sweeps the SAME
workspace: every `... daemon run --socket <workspace>/...canter.sock` process
is SIGTERM'd, then SIGKILL'd, bounded, and the survivor set is recorded to
`<workspace>/guardian.log`. It is path-scoped to the workspace it was given,
so it can never touch a foreign daemon (another lane's, or the real one).
"""
import os
import signal
import subprocess
import sys
import time

SOCKET_SUFFIX = "/state/canter/canter.sock"


def alive(pid):
    # `os.kill(pid, 0)` answers true for a ZOMBIE too, and a killed harness
    # whose parent has not reaped it yet is exactly that: ask `ps` for the
    # state and treat `Z` as gone.
    proc = subprocess.run(["ps", "-p", str(pid), "-o", "stat="],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          text=True, check=False)
    stat = (proc.stdout or "").strip()
    return bool(stat) and "Z" not in stat


def record(workspace, message):
    # The durable record is a FILE inside the workspace the harness handed
    # over: the guardian may be sweeping because the harness (and any pipe to
    # it) is already gone, so the reap must never depend on stdout.
    try:
        with open(os.path.join(workspace, "guardian.log"), "a",
                  encoding="utf-8") as handle:
            handle.write(message + "\n")
    except OSError:
        pass
    try:
        print(message, flush=True)
    except OSError:
        pass


def daemons_under(root, skip):
    forms = {root, os.path.realpath(root)}
    proc = subprocess.run(["ps", "-axww", "-o", "pid=,command="],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          text=True, check=False)
    found = {}
    for line in (proc.stdout or "").splitlines():
        fields = line.split(None, 1)
        if len(fields) < 2:
            continue
        try:
            pid = int(fields[0])
        except ValueError:
            continue
        command = fields[1]
        if pid in skip or SOCKET_SUFFIX not in command:
            continue
        if any(form in command for form in forms):
            found[pid] = command
    return found


def main(argv):
    harness, workspace = int(argv[0]), argv[1]
    skip = {harness, os.getpid()}
    while alive(harness):
        time.sleep(0.5)
    found = daemons_under(workspace, skip)
    if not found:
        return 0
    record(workspace, "guardian: SIGTERM {}".format(sorted(found)))
    for pid in found:
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            pass
    deadline = time.time() + 5
    while time.time() < deadline and daemons_under(workspace, skip):
        time.sleep(0.05)
    for pid in daemons_under(workspace, skip):
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass
    deadline = time.time() + 5
    while time.time() < deadline and daemons_under(workspace, skip):
        time.sleep(0.05)
    remaining = daemons_under(workspace, skip)
    record(workspace, "guardian: remaining={}".format(sorted(remaining)))
    return 1 if remaining else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
'''

# Fake `ps`: the driver's PPID-1 daemon census is a scripted table, so the
# self-test proves the count/refusal logic without depending on this host's
# live process population. Call 1 serves `before` (the census the bump takes
# just before the restart), later calls serve `after`.
PS_SHIM = r'''#!/usr/bin/env python3
"""Fake `ps` for scripts/test-accept-bump.py: a scripted PPID-1 census."""
import json
import os

SPEC = "@SPEC@"


def main():
    spec = json.load(open(SPEC, encoding="utf-8"))
    try:
        calls = int(open(spec["counter"], encoding="utf-8").read().strip() or "0")
    except OSError:
        calls = 0
    calls += 1
    with open(spec["counter"], "w", encoding="utf-8") as handle:
        handle.write(str(calls))
    rows = spec["before"] if calls == 1 else spec["after"]
    print("  PID  PPID COMMAND")
    for pid, ppid, command in rows:
        print("%6d  %4d %s" % (pid, ppid, command))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''


def write_ps_shim(directory: str, name: str, before, after) -> str:
    """A fake `ps` serving `before` on its first call and `after` afterwards."""
    spec = os.path.join(directory, name + ".json")
    with open(spec, "w", encoding="utf-8") as handle:
        json.dump({"before": before, "after": after,
                   "counter": os.path.join(directory, name + "-calls")}, handle)
    return write_shim(directory, name, PS_SHIM.replace("@SPEC@", spec))


class Fixture:
    """One disposable bump root: home, bin dir, state, integration, supervisor."""

    def __init__(self, name: str, workspace: str, binary: str):
        self.name = name
        self.root = os.path.join(workspace, name)
        self.home = os.path.join(self.root, "home")
        self.bin_dir = os.path.join(self.root, "bin")
        self.service_path = os.path.join(self.bin_dir, "canter")
        self.state = os.path.join(self.root, "state", "canter")
        self.socket = os.path.join(self.state, "canter.sock")
        self.lease = os.path.join(self.state, "daemon.lock")
        self.accept_target = os.path.join(self.state, "accept", "target", "release", "canter")
        self.integration = os.path.join(self.root, "work", "integration", "canter")
        self.log = os.path.join(self.state, "accept", "bump.log")
        self.candidate = os.path.join(self.root, "candidate", "canter")
        self.spec_path = os.path.join(self.root, "supervisor", "spec.json")
        self.supervisor_log = os.path.join(self.root, "supervisor", "launchctl.log")
        self.supervisor_state = os.path.join(self.root, "supervisor", "state.json")
        self.binary = binary
        for directory in (self.home, self.bin_dir, self.state,
                          os.path.dirname(self.candidate),
                          os.path.dirname(self.spec_path),
                          os.path.join(self.root, "config"),
                          os.path.join(self.root, "run")):
            os.makedirs(directory, exist_ok=True)
        shutil.copyfile(binary, self.candidate)
        os.chmod(self.candidate, 0o755)

    # -- supervisor spec ---------------------------------------------------

    def daemon_env(self) -> dict:
        return {
            "HOME": self.home,
            "XDG_STATE_HOME": os.path.join(self.root, "state"),
            "XDG_CONFIG_HOME": os.path.join(self.root, "config"),
            "XDG_RUNTIME_DIR": os.path.join(self.root, "run"),
        }

    def write_spec(self, mode: str = "start", program: str | None = None,
                   print_program: str | None = None, lease_pid=None,
                   lease_started_at: str | None = None) -> None:
        spec = {
            "mode": mode,
            "job": "gui/501/com.canter.daemon",
            "program": program or self.service_path,
            "print_program": print_program,
            "args": ["daemon", "run", "--socket", self.socket],
            "env": self.daemon_env(),
            "state": self.supervisor_state,
            "log": self.supervisor_log,
            "lease": self.lease,
            "lease_pid": lease_pid,
            "lease_started_at": lease_started_at,
            "socket": self.socket,
        }
        with open(self.spec_path, "w", encoding="utf-8") as handle:
            json.dump(spec, handle)

    # -- inspection --------------------------------------------------------

    def holder_pids(self) -> list[int]:
        proc = subprocess.run(["lsof", "-U"], stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, text=True, check=False)
        pids = []
        for line in proc.stdout.splitlines()[1:]:
            fields = line.split()
            if len(fields) >= 3 and fields[-1] == self.socket:
                try:
                    pids.append(int(fields[1]))
                except ValueError:
                    pass
        return pids

    def log_text(self) -> str:
        try:
            with open(self.log, encoding="utf-8") as handle:
                return handle.read()
        except OSError:
            return ""

    def done_events(self) -> list[dict]:
        events = []
        for line in self.log_text().splitlines():
            _, _, payload = line.partition(" ")
            if payload.strip().startswith('{"event": "bump.done"'):
                events.append(json.loads(payload.strip()))
        return events

    # -- lifecycle ---------------------------------------------------------

    def start_stale_daemon(self) -> int:
        """A superseded build already serving the socket (the #277 race)."""
        stale = os.path.join(self.root, "stale", "canter")
        os.makedirs(os.path.dirname(stale), exist_ok=True)
        if not os.path.exists(stale):
            shutil.copyfile(self.binary, stale)
            os.chmod(stale, 0o755)
        with open(self.supervisor_log, "ab") as out:
            proc = subprocess.Popen(
                [stale, "daemon", "run", "--socket", self.socket],
                env=dict(os.environ, **self.daemon_env()), stdout=out,
                stderr=out, start_new_session=True)
        deadline = time.time() + 15
        while time.time() < deadline:
            if self.holder_pids():
                return proc.pid
            if proc.poll() is not None:
                raise AssertionError("stale daemon exited with %s" % proc.returncode)
            time.sleep(0.1)
        raise AssertionError("stale daemon never took the socket")

    def cleanup(self) -> None:
        """Reap every scenario daemon of THIS fixture by its own socket argv.

        The argv is the daemon's durable owner record (the fake supervisor's
        launcher is gone, and lsof sees only live descriptors), so this also
        reaps a daemon a scenario failed to track — and it is what the suite's
        final audit re-checks (issue #316).
        """
        reap_daemons(self.root, skip={os.getpid()})

    # -- driver invocation -------------------------------------------------

    def run_driver(self, shims: "Shims", lsof: str, codesign: str,
                   wait: float = START_WAIT_SECS,
                   sha: str | None = None, branch: str = "staging",
                   accept_target: str | None = None, cargo: str | None = None,
                   integration: str | None = None,
                   ps: str | None = None,
                   verify_only: bool = False) -> subprocess.CompletedProcess:
        argv = [
            sys.executable, DRIVER,
            "--home", self.home,
            "--bin-dir", self.bin_dir,
            "--state", self.state,
            "--socket", self.socket,
            "--lease", self.lease,
            "--log", self.log,
            "--integration", integration or self.integration,
            "--integration-branch", branch,
            "--accept-target", accept_target or self.accept_target,
            "--wait-seconds", str(wait),
            "--launchctl", shims.launchctl,
            "--lsof", lsof,
            "--codesign", codesign,
            "--cargo", cargo or shims.cargo,
            "--ps", ps or shims.ps_stable,
        ]
        if verify_only:
            argv += ["--verify-only"]
        elif sha is not None:
            argv += ["--sha", sha]
        else:
            argv += ["--candidate", self.candidate]
        env = dict(os.environ)
        env["HF_BUMP_SPEC"] = self.spec_path
        env["HF_BUMP_SOCKET"] = self.socket
        return subprocess.run(argv, env=env, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, text=True, check=False)


# The scripted census rows (the fake `ps` tables, issue #316): a foreign
# daemon that predates the bump never blocks one; a NEW PPID-1 daemon after
# the restart is exactly the leak `bump.refusal.orphans` must name.
FOREIGN_DAEMON = ("/var/tmp/foreign-lane/bin/canter daemon run --socket "
                  "/var/tmp/foreign-lane/state/canter/canter.sock")
FOREIGN_TWO = ("/var/tmp/foreign-two/bin/canter daemon run --socket "
               "/var/tmp/foreign-two/state/canter/canter.sock")
LEFTOVER_DAEMON = ("/var/tmp/leftover-harness/bin/canter daemon run --socket "
                   "/var/tmp/leftover-harness/state/canter/canter.sock")


class Shims:
    """The injected host boundaries: supervisor, lsof variants, codesign, cargo."""

    def __init__(self, directory: str, binary: str):
        os.makedirs(directory, exist_ok=True)
        self.launchctl = write_shim(directory, "launchctl", LAUNCHCTL_SHIM)
        self.lsof_holders = write_shim(directory, "lsof-holders", LSOF_HOLDERS_SHIM)
        self.lsof_no_exe = write_shim(directory, "lsof-no-exe", LSOF_NO_EXE_SHIM)
        self.codesign_both = write_shim(
            directory, "codesign-both", CODESIGN_SHIM % {"mode": "both"})
        self.codesign_accept = write_shim(
            directory, "codesign-accept", CODESIGN_SHIM % {"mode": "accept"})
        self.codesign_unverifiable = write_shim(
            directory, "codesign-unverifiable", CODESIGN_UNVERIFIABLE_SHIM)
        self.cargo = write_shim(directory, "cargo", CARGO_SHIM)
        env_bin = os.path.join(directory, "cargo-bin")
        shutil.copyfile(binary, env_bin)
        os.chmod(env_bin, 0o755)
        os.environ["HF_TEST_CARGO_BIN"] = env_bin
        # The daemons a scenario starts are REAL processes; the supervisor,
        # the daemon census and the guardian are the scripted boundaries.
        self.ps_stable = write_ps_shim(
            directory, "ps-stable",
            [[70001, 1, FOREIGN_DAEMON]], [[70001, 1, FOREIGN_DAEMON]])
        self.ps_preexisting = write_ps_shim(
            directory, "ps-preexisting",
            [[70001, 1, FOREIGN_DAEMON], [70002, 1, FOREIGN_TWO]],
            [[70001, 1, FOREIGN_DAEMON], [70002, 1, FOREIGN_TWO]])
        self.ps_growth = write_ps_shim(
            directory, "ps-growth", [[70001, 1, FOREIGN_DAEMON]],
            [[70001, 1, FOREIGN_DAEMON], [424242, 1, LEFTOVER_DAEMON]])
        self.guardian = write_shim(directory, "guardian", GUARDIAN_SRC)


class Suite:
    def __init__(self, binary: str, workspace: str, lsof: str, codesign: str, shims: Shims):
        self.binary = binary
        self.workspace = workspace
        self.lsof = lsof
        self.codesign = codesign
        self.shims = shims
        self.fixtures: list[Fixture] = []
        self.checks: list[str] = []
        self.failures: list[str] = []

    def check(self, label: str, condition: bool, detail: str = "") -> None:
        self.checks.append(label)
        if condition:
            print("PASS: {}".format(label), flush=True)
        else:
            self.failures.append("{}: {}".format(label, detail))
            print("FAIL: {}: {}".format(label, detail), flush=True)

    def fixture(self, name: str) -> Fixture:
        fixture = Fixture(name, self.workspace, self.binary)
        self.fixtures.append(fixture)
        return fixture

    def expectation(self, label: str, proc: subprocess.CompletedProcess,
                    exit_code: int, code: str, fixture: Fixture) -> None:
        """A refusal: typed code, exit status, and NEVER a DONE."""
        self.check("{} exits {}".format(label, exit_code),
                   proc.returncode == exit_code,
                   "got {} stderr={}".format(proc.returncode, proc.stderr.strip()[-400:]))
        self.check("{} names {}".format(label, code),
                   code in proc.stderr,
                   "stderr={}".format(proc.stderr.strip()[-400:]))
        self.check("{} never prints DONE".format(label),
                   "DONE" not in proc.stdout and "DONE" not in fixture.log_text(),
                   "stdout tail={}".format(proc.stdout.strip()[-400:]))

    # -- scenarios ---------------------------------------------------------

    def scenario_usage(self) -> None:
        for label, argv in (
            ("no source", []),
            ("short sha", ["--sha", "abc123"]),
            ("zero wait", ["--candidate", "/bin/sh", "--wait-seconds", "0"]),
        ):
            proc = subprocess.run([sys.executable, DRIVER] + argv,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  text=True, check=False)
            self.check("usage: {} exits 2".format(label), proc.returncode == 2,
                       "got {} stderr={}".format(proc.returncode, proc.stderr.strip()[-200:]))

    def scenario_happy_path(self, name: str = "happy") -> Fixture:
        fixture = self.fixture(name)
        fixture.write_spec(mode="start")
        proc = fixture.run_driver(self.shims, self.lsof, self.codesign)
        self.check("bump exits 0", proc.returncode == 0,
                   "got {} stderr={} log={}".format(
                       proc.returncode, proc.stderr.strip()[-300:],
                       fixture.log_text().strip()[-500:]))
        self.check("bump prints DONE", "DONE" in proc.stdout,
                   "stdout={}".format(proc.stdout.strip()[-300:]))
        self.check("both paths installed",
                   os.path.exists(fixture.accept_target)
                   and os.path.exists(fixture.service_path))
        accept_sha = safe_sha256(fixture.accept_target)
        service_sha = safe_sha256(fixture.service_path)
        self.check("installed paths are byte-identical",
                   bool(accept_sha) and accept_sha == service_sha,
                   "accept={} service={}".format(accept_sha, service_sha))
        if self.codesign == "codesign":
            for label, path in (("accept target", fixture.accept_target),
                                ("service path", fixture.service_path)):
                verify = subprocess.run(["codesign", "-v", path], stdout=subprocess.PIPE,
                                        stderr=subprocess.STDOUT, text=True, check=False)
                self.check("{} carries a valid signature".format(label),
                           verify.returncode == 0,
                           "codesign -v exit {} output={}".format(
                               verify.returncode, verify.stdout.strip()[-200:]))
        events = fixture.done_events()
        self.check("the bump log records a bump.done event", len(events) == 1,
                   "events={}".format(events))
        if events:
            event = events[0]
            self.check("logged sha256 is the installed build's",
                       event.get("sha256") == service_sha,
                       "logged={} installed={}".format(event.get("sha256"), service_sha))
            self.check("logged pid is a live socket holder",
                       event.get("pid") in fixture.holder_pids(),
                       "pid={} holders={}".format(event.get("pid"), fixture.holder_pids()))
            self.check("logged started_at is recorded", bool(event.get("started_at")),
                       "event={}".format(event))
            self.check("logged exe is the supervisor's program path",
                       event.get("exe") == fixture.service_path
                       or os.path.realpath(event.get("exe") or "")
                       == os.path.realpath(fixture.service_path),
                       "exe={}".format(event.get("exe")))
            self.check("the done event carries both census counts (issue #316)",
                       event.get("orphans_before") == 1
                       and event.get("orphans_after") == 1,
                       "event={}".format(event))
        self.check("the bump logs the census before the restart and after the verify",
                   "orphans_before count=1 pids=[70001]" in fixture.log_text()
                   and "orphans_after count=1 pids=[70001]" in fixture.log_text(),
                   "log={}".format(fixture.log_text().strip()[-600:]))
        self.check("exactly one socket holder", len(fixture.holder_pids()) == 1,
                   "holders={}".format(fixture.holder_pids()))
        return fixture

    def scenario_idempotence(self) -> None:
        fixture = self.scenario_happy_path("idempotence")
        first = fixture.done_events()
        proc = fixture.run_driver(self.shims, self.lsof, self.codesign)
        self.check("second bump at the same candidate exits 0", proc.returncode == 0,
                   "got {} log={}".format(proc.returncode, fixture.log_text().strip()[-400:]))
        self.check("second bump leaves one socket holder",
                   len(fixture.holder_pids()) == 1,
                   "holders={}".format(fixture.holder_pids()))
        events = fixture.done_events()
        self.check("the second bump logged a new holder pid",
                   len(events) == 2 and bool(first)
                   and events[1].get("pid") != first[0].get("pid"),
                   "events={}".format(events))
        self.check("the running build is unchanged",
                   len(events) == 2 and events[1].get("sha256") == events[0].get("sha256"),
                   "events={}".format(events))

    def scenario_stale_daemon(self) -> None:
        """A superseded build wins the socket: refuse, never DONE (AC2)."""
        fixture = self.fixture("stale_daemon")
        fixture.write_spec(mode="noop")
        fixture.start_stale_daemon()
        try:
            proc = fixture.run_driver(self.shims, self.lsof, self.shims.codesign_both,
                                      wait=NO_START_WAIT_SECS)
            self.expectation("stale daemon", proc, 15,
                             "bump.refusal.stale_daemon", fixture)
        finally:
            fixture.cleanup()

    def scenario_superseded_program(self) -> None:
        """The supervisor starts a superseded copy: refuse via the sha proof (AC2).

        The printed `program` is the service path (so the program guard passes)
        and the started daemon is an older copy: its lease is fresh, so only the
        holder-executable sha256 proof can catch it.
        """
        fixture = self.fixture("superseded")
        stale = os.path.join(fixture.root, "old", "canter")
        os.makedirs(os.path.dirname(stale), exist_ok=True)
        shutil.copyfile(self.binary, stale)
        os.chmod(stale, 0o755)
        fixture.write_spec(mode="start", program=stale,
                           print_program=fixture.service_path)
        try:
            proc = fixture.run_driver(self.shims, self.lsof, self.codesign)
            self.expectation("supervisor starts a superseded copy", proc, 15,
                             "bump.refusal.stale_daemon", fixture)
        finally:
            fixture.cleanup()

    def scenario_verify_only(self) -> None:
        """Read-only certification of the running daemon: same pid, no restart."""
        fixture = self.scenario_happy_path("verify_only")
        events = fixture.done_events()
        pid = events[0].get("pid") if events else None
        proc = fixture.run_driver(self.shims, self.lsof, self.codesign, verify_only=True)
        self.check("verify-only exits 0", proc.returncode == 0,
                   "got {} stderr={} log={}".format(
                       proc.returncode, proc.stderr.strip()[-300:],
                       fixture.log_text().strip()[-400:]))
        self.check("verify-only prints DONE", "DONE" in proc.stdout,
                   "stdout={}".format(proc.stdout.strip()[-300:]))
        self.check("verify-only restarts nothing (the same pid still holds the socket)",
                   fixture.holder_pids() == [pid],
                   "holders={} pid={}".format(fixture.holder_pids(), pid))
        events = fixture.done_events()
        self.check("verify-only logs the same build, pid, started_at and mode",
                   len(events) == 2 and events[1].get("mode") == "verify-only"
                   and events[1].get("pid") == pid
                   and events[1].get("sha256") == events[0].get("sha256")
                   and bool(events[1].get("started_at")),
                   "events={}".format(events))

    def scenario_daemon_not_up(self) -> None:
        fixture = self.fixture("not_up")
        fixture.write_spec(mode="noop")
        proc = fixture.run_driver(self.shims, self.lsof, self.codesign,
                                  wait=NO_START_WAIT_SECS)
        self.expectation("daemon never up", proc, 13, "bump.refusal.daemon_not_up", fixture)

    def scenario_socket_holders(self) -> None:
        fixture = self.fixture("two_holders")
        fixture.write_spec(mode="start")
        proc = fixture.run_driver(self.shims, self.shims.lsof_holders, self.codesign,
                                  wait=NO_START_WAIT_SECS)
        self.expectation("two socket holders", proc, 14,
                         "bump.refusal.socket_holders", fixture)
        self.check("the refusal names each holder with its executable (issue #316 AC1)",
                   "pid=11111 exe=/tmp/orphan-one/canter" in proc.stderr
                   and "pid=22222 exe=unresolved" in proc.stderr,
                   "stderr={}".format(proc.stderr.strip()[-500:]))
        fixture.cleanup()

    def scenario_pid_exe_unresolved(self) -> None:
        fixture = self.fixture("no_exe")
        fixture.write_spec(mode="start")
        proc = fixture.run_driver(self.shims, self.shims.lsof_no_exe, self.codesign,
                                  wait=NO_START_WAIT_SECS)
        self.expectation("holder executable unresolvable", proc, 16,
                         "bump.refusal.pid_exe_unresolved", fixture)
        fixture.cleanup()

    def scenario_supervisor_program(self) -> None:
        fixture = self.fixture("supervisor_program")
        other = os.path.join(fixture.root, "old", "canter")
        os.makedirs(os.path.dirname(other), exist_ok=True)
        shutil.copyfile(self.binary, other)
        fixture.write_spec(mode="start", print_program=other)
        proc = fixture.run_driver(self.shims, self.lsof, self.codesign)
        self.expectation("supervisor launches another path", proc, 10,
                         "bump.refusal.supervisor_program", fixture)

    def scenario_supervisor_not_loaded(self) -> None:
        fixture = self.fixture("not_loaded")
        fixture.write_spec(mode="not_loaded")
        proc = fixture.run_driver(self.shims, self.lsof, self.codesign)
        self.expectation("supervisor job not loaded", proc, 11,
                         "bump.refusal.supervisor_not_loaded", fixture)

    def scenario_restart_failure(self) -> None:
        fixture = self.fixture("restart_fail")
        fixture.write_spec(mode="fail")
        proc = fixture.run_driver(self.shims, self.lsof, self.codesign)
        self.expectation("restart refused", proc, 12, "bump.refusal.restart", fixture)

    def scenario_lease_mismatch(self) -> None:
        fixture = self.fixture("lease")
        fixture.write_spec(mode="start", lease_pid=999999)
        proc = fixture.run_driver(self.shims, self.lsof, self.codesign)
        self.expectation("lease names another pid", proc, 17, "bump.refusal.lease", fixture)
        fixture.cleanup()

    def scenario_stale_lease(self) -> None:
        """A holder whose recorded start predates the install: refuse (never DONE)."""
        fixture = self.fixture("stale_lease")
        fixture.write_spec(mode="start", lease_pid="holder",
                           lease_started_at="2000-01-01T00:00:00Z")
        proc = fixture.run_driver(self.shims, self.lsof, self.codesign)
        self.expectation("lease start predates the install", proc, 15,
                         "bump.refusal.stale_daemon", fixture)
        fixture.cleanup()

    def scenario_sign_verification(self) -> None:
        """An install whose signature cannot be verified: refuse (never DONE)."""
        fixture = self.fixture("unverifiable")
        fixture.write_spec(mode="noop")
        proc = fixture.run_driver(self.shims, self.lsof, self.shims.codesign_unverifiable)
        self.expectation("unverifiable signature", proc, 8, "bump.refusal.sign", fixture)

    def scenario_install_divergence(self) -> None:
        fixture = self.fixture("divergence")
        fixture.write_spec(mode="noop")
        proc = fixture.run_driver(self.shims, self.lsof, self.shims.codesign_accept)
        self.expectation("installed paths diverge", proc, 9,
                         "bump.refusal.install_divergence", fixture)
        proc = fixture.run_driver(self.shims, self.lsof, self.shims.codesign_accept,
                                  verify_only=True)
        self.expectation("verify-only on diverging paths", proc, 9,
                         "bump.refusal.install_divergence", fixture)

    def scenario_install_failure(self) -> None:
        fixture = self.fixture("install_fail")
        fixture.write_spec(mode="noop")
        blocker = os.path.join(fixture.root, "blocker")
        with open(blocker, "w", encoding="utf-8") as handle:
            handle.write("not a directory\n")
        proc = fixture.run_driver(self.shims, self.lsof, self.codesign,
                                  accept_target=os.path.join(blocker, "canter"))
        self.expectation("accept target not installable", proc, 7,
                         "bump.refusal.install", fixture)

    def scenario_orphans(self) -> None:
        """The bump refuses when its own census grew (issue #316 AC2).

        The fake `ps` serves a NEW PPID-1 daemon on the census taken after the
        restart; the bump must refuse 18, name that pid and its command, and
        never print DONE. The control leg is a census that ALREADY carried
        foreign orphans (before == after): a pre-existing leak must never
        block a bump.
        """
        fixture = self.fixture("orphans")
        fixture.write_spec(mode="start")
        proc = fixture.run_driver(self.shims, self.lsof, self.codesign,
                                  ps=self.shims.ps_growth)
        self.expectation("census grew across the bump", proc, 18,
                         "bump.refusal.orphans", fixture)
        self.check("the refusal names the new orphan and its command (issue #316 AC2)",
                   "pid=424242" in proc.stderr and "leftover-harness" in proc.stderr,
                   "stderr={}".format(proc.stderr.strip()[-500:]))
        self.check("the log records both census counts and both pid sets",
                   "orphans_before count=1 pids=[70001]" in fixture.log_text()
                   and "orphans_after count=2 pids=[70001, 424242]"
                   in fixture.log_text(),
                   "log={}".format(fixture.log_text().strip()[-700:]))
        fixture.cleanup()

        control = self.fixture("orphans_preexisting")
        control.write_spec(mode="start")
        proc = control.run_driver(self.shims, self.lsof, self.codesign,
                                  ps=self.shims.ps_preexisting)
        self.check("pre-existing orphans do not fail the bump", proc.returncode == 0,
                   "got {} log={}".format(proc.returncode,
                                          control.log_text().strip()[-400:]))
        self.check("pre-existing orphans are counted, not cleared",
                   "orphans_before count=2 pids=[70001, 70002]" in control.log_text()
                   and "orphans_after count=2 pids=[70001, 70002]"
                   in control.log_text(),
                   "log={}".format(control.log_text().strip()[-700:]))
        control.cleanup()

    def scenario_daemon_ownership(self) -> None:
        """The sweep reaps a REAL scenario daemon (issue #316 AC3/AC4).

        The stand-in is a real process whose argv carries a socket under the
        scored root: the same shape every scenario daemon has. The sweep must
        find it, kill it, and report nothing left — the primitive the suite's
        exit audit and the guardian both use.
        """
        scratch = os.path.join(self.workspace, "reap-witness")
        pid = start_stand_in_daemon(scratch)
        self.check("a scenario daemon is found by its own socket argv",
                   daemons_under(scratch, skip=set()).get(pid),
                   "found={}".format(daemons_under(scratch, skip=set())))
        survivors = reap_daemons(scratch, skip=set())
        self.check("the sweep leaves no scenario daemon behind", not survivors,
                   "survivors={}".format(survivors))
        self.check("the reaped daemon is gone", wait_reaped(pid), "pid={}".format(pid))
        self.check("a foreign daemon can never match the sweep",
                   not daemons_under("/var/tmp/foreign-lane", skip=set()),
                   "found={}".format(daemons_under("/var/tmp/foreign-lane", skip=set())))

    def scenario_guardian(self) -> None:
        """A KILLED harness is still reaped: the guardian owns the workspace.

        The measured defect (issue #316) was exactly this: a harness killed
        mid-pass ran no `finally`, and its scenario daemons survived it. The
        guardian is a separate process watching the harness pid; the stand-in
        harness below is SIGKILLed and the stand-in daemon must still die.
        """
        scratch = os.path.join(self.workspace, "guardian-witness")
        daemon_pid = start_stand_in_daemon(scratch)
        harness = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(600)"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True)
        guardian = subprocess.Popen(
            [sys.executable, self.shims.guardian, str(harness.pid), scratch],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        try:
            os.kill(harness.pid, signal.SIGKILL)
            harness.wait(timeout=10)
            deadline = time.time() + 30
            while time.time() < deadline and daemons_under(scratch, skip=set()):
                time.sleep(0.25)
            remaining = daemons_under(scratch, skip=set())
            self.check("the guardian reaps a killed harness's daemon",
                       not remaining and wait_reaped(daemon_pid),
                       "remaining={} daemon_pid={}".format(remaining, daemon_pid))
            self.check("the guardian exits 0 with an empty workspace",
                       guardian.wait(timeout=15) == 0,
                       "guardian exit={} output={}".format(
                           guardian.returncode, (guardian.stdout.read() or "")[-300:]))
        finally:
            if guardian.poll() is None:
                guardian.kill()

    def scenario_failure_path(self) -> None:
        """A FAILING pass still reaps its scenarios (issue #316 AC3).

        The nested pass runs the same suite with a fake `lsof` that never
        resolves a holder executable, so its scenarios fail (exit 1); the
        point is that its own reap still empties the workspace before it
        exits. Its kept workspace is swept and removed here.
        """
        proc = subprocess.run(
            [sys.executable, os.path.abspath(__file__), "--bin", self.binary,
             "--lsof", self.shims.lsof_no_exe, "--keep", "--skip-nested"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            check=False)
        kept = ""
        for line in (proc.stdout or "").splitlines():
            if line.startswith("kept: "):
                kept = line[len("kept: "):].strip()
        self.check("the nested failing pass exits non-zero", proc.returncode != 0,
                   "nested exit={} tail={}".format(
                       proc.returncode, (proc.stdout or "")[-400:]))
        self.check("the nested pass kept its workspace for inspection", bool(kept),
                   "stdout tail={}".format((proc.stdout or "")[-400:]))
        if kept:
            try:
                surviving = daemons_under(kept, skip=set(), suffix="")
                self.check("a FAILING pass still left no scenario daemon",
                           not surviving, "survivors={}".format(surviving))
            finally:
                shutil.rmtree(kept, ignore_errors=True)

    def scenario_full_mode(self) -> None:
        fixture = self.fixture("full_mode")
        head, _side = self.make_source_fixture(fixture)
        proc = fixture.run_driver(self.shims, self.lsof, self.codesign, sha=head)
        self.check("full bump (reconcile+build) exits 0", proc.returncode == 0,
                   "got {} stderr={} log={}".format(
                       proc.returncode, proc.stderr.strip()[-300:],
                       fixture.log_text().strip()[-500:]))
        self.check("reconcile lands on the requested sha",
                   "reconcile=ok HEAD={} branch=staging".format(head) in fixture.log_text(),
                   "log={}".format(fixture.log_text().strip()[-600:]))
        built = os.path.join(fixture.integration, "target", "release", "canter")
        events = fixture.done_events()
        self.check("the built tree is what got installed (pre-sign candidate sha256)",
                   os.path.exists(built) and bool(events)
                   and events[0].get("candidate_sha256") == safe_sha256(built),
                   "candidate={} built={}".format(
                       events[0].get("candidate_sha256") if events else None,
                       safe_sha256(built)))
        self.check("the served build is the installed one (post-sign identity)",
                   bool(events) and bool(safe_sha256(fixture.service_path))
                   and events[0].get("sha256") == safe_sha256(fixture.service_path),
                   "events={}".format(events))
        fixture.cleanup()

        non_ff = self.fixture("non_ff")
        _non_ff_head, non_ff_side = self.make_source_fixture(non_ff)
        proc = non_ff.run_driver(self.shims, self.lsof, self.codesign, sha=non_ff_side)
        self.expectation("non-fast-forward target", proc, 5, "bump.refusal.non_ff", non_ff)

        failing = self.fixture("build_fail")
        failing_head, _failing_side = self.make_source_fixture(failing)
        os.environ["HF_TEST_CARGO_MODE"] = "fail"
        try:
            proc = failing.run_driver(self.shims, self.lsof, self.codesign, sha=failing_head)
        finally:
            os.environ.pop("HF_TEST_CARGO_MODE", None)
        self.expectation("failed build", proc, 4, "bump.refusal.build", failing)

    def make_source_fixture(self, fixture: Fixture) -> tuple[str, str]:
        """A real git repo with an `origin` remote and a `staging` branch."""
        origin = os.path.join(fixture.root, "work", "origin.git")
        os.makedirs(os.path.dirname(origin), exist_ok=True)
        subprocess.run(["git", "init", "--bare", "--initial-branch", "staging", origin],
                       stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, check=True)
        seed = os.path.join(fixture.root, "work", "seed")
        subprocess.run(["git", "init", "--initial-branch", "staging", seed],
                       stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, check=True)
        git(["config", "user.email", "selftest@example.invalid"], cwd=seed)
        git(["config", "user.name", "selftest"], cwd=seed)
        with open(os.path.join(seed, "README.md"), "w", encoding="utf-8") as handle:
            handle.write("fixture\n")
        git(["add", "README.md"], cwd=seed)
        git(["commit", "-m", "fixture"], cwd=seed)
        git(["remote", "add", "origin", origin], cwd=seed)
        git(["push", "origin", "staging"], cwd=seed)
        os.makedirs(os.path.dirname(fixture.integration), exist_ok=True)
        subprocess.run(["git", "clone", origin, fixture.integration],
                       stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, check=True)
        git(["config", "user.email", "selftest@example.invalid"], cwd=fixture.integration)
        git(["config", "user.name", "selftest"], cwd=fixture.integration)
        head = git(["rev-parse", "HEAD"], cwd=fixture.integration).stdout.strip()
        # A commit that is NOT a descendant of HEAD (the non-fast-forward case).
        git(["checkout", "-B", "side"], cwd=seed)
        with open(os.path.join(seed, "SIDE.md"), "w", encoding="utf-8") as handle:
            handle.write("side\n")
        git(["add", "SIDE.md"], cwd=seed)
        git(["commit", "-m", "side"], cwd=seed)
        git(["push", "origin", "side"], cwd=seed)
        side = git(["rev-parse", "HEAD"], cwd=seed).stdout.strip()
        fixture.write_spec(mode="start")
        return head, side


class Interrupted(Exception):
    """The harness caught a termination signal and is reaping on the way out."""


SIGNALS = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)


def install_reap_handlers(received: list[int]) -> None:
    """Termination signals still reap: every handler exits through the finally.

    A second signal restores the default disposition, so a harness that cannot
    get through its reap never traps the operator in it.
    """
    def handler(signum, _frame):
        received.append(signum)
        signal.signal(signum, signal.SIG_DFL)
        raise Interrupted("signal {}".format(signum))
    for signum in SIGNALS:
        signal.signal(signum, handler)


def start_guardian(workspace: str, shims: "Shims") -> subprocess.Popen:
    """The kill-proof half: reap the workspace if THIS harness is killed.

    A `kill -9` runs no Python, so the guardian is a separate process watching
    this pid; it sweeps the same workspace the suite owns (and only that one)
    the moment the harness is gone. Its durable record is the file it writes
    inside the workspace (`guardian.log`); THIS process hands it DEVNULL, never
    a pipe that dies with the harness.
    """
    return subprocess.Popen(
        [sys.executable, shims.guardian, str(os.getpid()), workspace],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="test-accept-bump.py")
    parser.add_argument("--bin", default=os.path.join(REPO, "target", "release", "canter"))
    parser.add_argument("--lsof", default="lsof")
    parser.add_argument("--keep", action="store_true",
                        help="keep the disposable roots for inspection")
    parser.add_argument("--skip-nested", action="store_true",
                        help="skip the nested failing-pass witness (a nested pass sets this)")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    binary = os.path.abspath(args.bin)
    if not (os.path.isfile(binary) and os.access(binary, os.X_OK)):
        print("error: --bin {} is not an executable file "
              "(cargo build --release --locked)".format(binary), file=sys.stderr)
        return 2
    lsof = args.lsof
    if shutil.which(lsof) is None:
        print("note: no lsof on this host; the socket proofs use the injected "
              "lsof fixtures only", file=sys.stderr)
    codesign = "codesign" if shutil.which("codesign") else os.path.join(HERE, "missing-codesign")
    workspace = tempfile.mkdtemp(prefix="hf-bump-", dir="/tmp")
    shims = Shims(os.path.join(workspace, "shims"), binary)
    suite = Suite(binary, workspace, lsof, codesign, shims)
    host_before = host_census()
    print("== accept-bump self-test: bin={} lsof={} codesign={}".format(
        binary, lsof, codesign), flush=True)
    print("harness pass census (PPID-1 `canter daemon run`) before: count={} "
          "pids={}".format(len(host_before),
                           [pid for pid, _command in host_before]), flush=True)
    guardian = start_guardian(workspace, shims)
    received: list[int] = []
    install_reap_handlers(received)
    try:
        suite.scenario_usage()
        suite.scenario_happy_path()
        suite.scenario_verify_only()
        suite.scenario_idempotence()
        suite.scenario_stale_daemon()
        suite.scenario_superseded_program()
        suite.scenario_daemon_not_up()
        suite.scenario_socket_holders()
        suite.scenario_pid_exe_unresolved()
        suite.scenario_supervisor_program()
        suite.scenario_supervisor_not_loaded()
        suite.scenario_restart_failure()
        suite.scenario_lease_mismatch()
        suite.scenario_stale_lease()
        suite.scenario_sign_verification()
        suite.scenario_install_divergence()
        suite.scenario_install_failure()
        suite.scenario_orphans()
        suite.scenario_daemon_ownership()
        suite.scenario_guardian()
        if not args.skip_nested:
            suite.scenario_failure_path()
        suite.scenario_full_mode()
    except Interrupted as exc:
        print("interrupted: {}".format(exc), flush=True)
    except Exception:
        report = "a scenario raised:\n{}".format(traceback.format_exc())
        suite.failures.append(report)
        print("FAIL: {}".format(report), flush=True)
    finally:
        # Issue #316 AC3: every scenario daemon is reaped on EVERY exit path,
        # and whatever survived is a failure, not a residue.
        for fixture in suite.fixtures:
            fixture.cleanup()
        surviving = reap_daemons(workspace, skip={os.getpid(), guardian.pid},
                                 suffix="")
        if surviving:
            leak = "scenario daemons outlived the harness: {}".format(
                ", ".join("pid={} {}".format(pid, command)
                          for pid, command in sorted(surviving.items())))
            suite.failures.append(leak)
            print("FAIL: {}".format(leak), flush=True)
        host_after = host_census()
        print("harness pass census (PPID-1 `canter daemon run`) after: count={} "
              "pids={}".format(len(host_after),
                               [pid for pid, _command in host_after]), flush=True)
        if args.keep:
            print("kept: {}".format(workspace), flush=True)
        else:
            shutil.rmtree(workspace, ignore_errors=True)
    if suite.failures:
        print("\naccept-bump self-test: {} check(s) FAILED".format(len(suite.failures)))
        for failure in suite.failures:
            print("  - {}".format(failure))
        return 1
    if received:
        print("\naccept-bump self-test: interrupted (signal {}) after reaping; "
              "{} check(s) passed".format(received[0], len(suite.checks)))
        return 130
    print("\naccept-bump self-test: all {} checks passed".format(len(suite.checks)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
