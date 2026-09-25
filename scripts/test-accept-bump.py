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
  build, two holders, a supervisor that launches another path, an unloaded
  job, a refused restart, an unresolved holder executable, a lease naming
  another pid, diverging installed paths, a non-fast-forward move and a failed
  build each exit non-zero with their typed `bump.refusal.<code>`, and never
  print DONE;
* idempotence — a second bump at the same candidate leaves one socket holder.

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
"""Fake `lsof` for scripts/test-accept-bump.py: a TWO-holder socket."""
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

    def supervisor_pid(self) -> int | None:
        try:
            with open(self.supervisor_state, encoding="utf-8") as handle:
                return json.load(handle).get("pid")
        except (OSError, ValueError):
            return None

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

    def kill(self, pid: int | None) -> None:
        if not pid:
            return
        for sig in (signal.SIGTERM, signal.SIGKILL):
            try:
                os.kill(pid, sig)
            except OSError:
                return
            for _ in range(100):
                try:
                    os.kill(pid, 0)
                except OSError:
                    return
                time.sleep(0.05)

    def cleanup(self) -> None:
        for pid in self.holder_pids() + [self.supervisor_pid()]:
            self.kill(pid)

    # -- driver invocation -------------------------------------------------

    def run_driver(self, shims: "Shims", lsof: str, codesign: str,
                   wait: float = START_WAIT_SECS,
                   sha: str | None = None, branch: str = "staging",
                   accept_target: str | None = None, cargo: str | None = None,
                   integration: str | None = None,
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


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="test-accept-bump.py")
    parser.add_argument("--bin", default=os.path.join(REPO, "target", "release", "canter"))
    parser.add_argument("--lsof", default="lsof")
    parser.add_argument("--keep", action="store_true",
                        help="keep the disposable roots for inspection")
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
    print("== accept-bump self-test: bin={} lsof={} codesign={}".format(
        binary, lsof, codesign), flush=True)
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
        suite.scenario_full_mode()
    finally:
        for fixture in suite.fixtures:
            fixture.cleanup()
        if args.keep:
            print("kept: {}".format(workspace))
        else:
            shutil.rmtree(workspace, ignore_errors=True)
    if suite.failures:
        print("\naccept-bump self-test: {} check(s) FAILED".format(len(suite.failures)))
        for failure in suite.failures:
            print("  - {}".format(failure))
        return 1
    print("\naccept-bump self-test: all {} checks passed".format(len(suite.checks)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
