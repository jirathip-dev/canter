#!/usr/bin/env python3
"""accept-bump.py — bump an installed candidate and PROVE the supervised
daemon is running the build that was just installed (issue #277).

The defect this closes
----------------------

An acceptance bump used to install the freshly built candidate to exactly ONE
path (the acceptance target) and then start *that* copy detached, while the
per-user service unit (`com.canter.daemon`, `KeepAlive SuccessfulExit => false`)
kept launching a **separate** copy: the installed CLI at `<bin-dir>/canter`.
The moment the bump killed the old daemon the supervisor raced to restart the
superseded binary; when it won the socket the host ran the previous build while
the bump still reported DONE — silently invalidating every measurement taken
from that daemon.

What this driver does instead
-----------------------------

1. ``reconcile`` — fetch the integration ref, fast-forward-check the target
   sha, move the integration checkout (branch included) onto it, and rebuild
   the candidate from that exact tree.
2. ``install`` — install the SAME bytes to BOTH paths (the acceptance target
   and the path the service unit launches) and ad-hoc re-sign BOTH, so the two
   paths cannot diverge in bytes *or* signature.
3. ``supervisor`` — refuse unless the supervised job really launches the
   service path (the durable fix: the supervisor's program is the path we
   install to).
4. ``restart`` — restart through the supervisor (``launchctl kickstart -k``).
   The supervisor owns the daemon; no detached second copy is started.
5. ``verify`` — prove that exactly ONE pid holds the socket, resolve that
   pid's executable, and require its sha256 to equal the installed build's
   sha256; require the daemon lease to name that same pid and to record a
   start that postdates the install (a superseded daemon that still holds the
   socket cannot pass); record the daemon pid, ``started_at`` and sha256.
6. Every failure exits non-zero with a typed ``bump.refusal.<code>`` and the
   run NEVER prints DONE for a daemon that is not the installed build.

Operator tooling: run by hand, never from CI. Public-data rule: no host paths
are committed — every runtime path comes from arguments or environment-derived
XDG defaults. Stdlib only. macOS launchd is the default supervisor; the
``--launchctl``/``--lsof``/``--codesign``/``--cargo`` boundaries are injectable
so the self-test can drive fake executables (scripts/test-accept-bump.py).

Usage:
  accept-bump.py --sha <40-hex-sha> [options]
  accept-bump.py --candidate <path> [options]     # skip reconcile+build
  accept-bump.py --verify-only [options]          # certify, mutate nothing

Exit codes (typed refusal table; 0 is the only success):
  0  DONE — exactly one socket holder, running the installed build
  2  bump.refusal.usage                  invalid invocation
  4  bump.refusal.build                  candidate build failed
  5  bump.refusal.non_ff                 integration checkout is not an ancestor
  6  bump.refusal.reconcile              checkout did not land on the target
  7  bump.refusal.install                install to a destination failed
  8  bump.refusal.sign                   re-sign or signature check failed
  9  bump.refusal.install_divergence     the two installed paths differ
 10  bump.refusal.supervisor_program     job does not launch the service path
 11  bump.refusal.supervisor_not_loaded  job is not loaded
 12  bump.refusal.restart                supervisor refused the restart
 13  bump.refusal.daemon_not_up          no pid held the socket before deadline
 14  bump.refusal.socket_holders         more than one pid holds the socket
 15  bump.refusal.stale_daemon           holder's executable is not the build
 16  bump.refusal.pid_exe_unresolved     holder's executable unresolvable
 17  bump.refusal.lease                  lease does not name the socket holder
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time

SHA_RE = re.compile(r"^[0-9a-f]{40}$")

# A daemon that recorded its start more than this many seconds before the
# installed binary's mtime cannot be running those bytes (the lease timestamp is
# second-granular; a fresh restart lands well inside this tolerance).
RECENCY_TOLERANCE_SECS = 2.0

# Typed refusal table: code -> (exit status, meaning). Single authoritative
# copy: docs/OPERATIONS.md section 10.1 renders the same table.
REFUSALS = (
    ("bump.refusal.usage", 2, "invalid invocation"),
    ("bump.refusal.build", 4, "the candidate failed to build from the requested tree"),
    ("bump.refusal.non_ff", 5, "the integration checkout is not an ancestor of the target sha"),
    ("bump.refusal.reconcile", 6, "the integration checkout did not land on the target sha/branch"),
    ("bump.refusal.install", 7, "installing the candidate to a destination path failed"),
    ("bump.refusal.sign", 8, "ad-hoc re-signing or the ad-hoc signature check failed"),
    ("bump.refusal.install_divergence", 9, "the two installed paths are not byte-identical"),
    ("bump.refusal.supervisor_program", 10, "the supervised job does not launch the service path"),
    ("bump.refusal.supervisor_not_loaded", 11, "the supervised job is not loaded"),
    ("bump.refusal.restart", 12, "the supervisor refused to restart the unit"),
    ("bump.refusal.daemon_not_up", 13, "no pid held the socket before the deadline"),
    ("bump.refusal.socket_holders", 14, "more than one pid holds the socket"),
    ("bump.refusal.stale_daemon", 15, "the socket is held by a pid running something other than the installed build"),
    ("bump.refusal.pid_exe_unresolved", 16, "the socket holder's executable could not be resolved"),
    ("bump.refusal.lease", 17, "the daemon lease does not name the socket holder"),
)
EXIT_BY_CODE = {code: status for code, status, _meaning in REFUSALS}


class Refusal(Exception):
    """A typed bump refusal: ``bump.refusal.<code>`` plus its exit status."""

    def __init__(self, code: str, message: str):
        self.code = code
        self.exit_code = EXIT_BY_CODE[code]
        self.message = message
        super().__init__("{}: {}".format(code, message))


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def same_path(left: str, right: str) -> bool:
    """Compare paths tolerantly (macOS /tmp is a symlink to /private/tmp)."""
    return os.path.realpath(left) == os.path.realpath(right)


def parse_rfc3339(timestamp: str | None) -> float | None:
    """Epoch seconds for the daemon's recorded ``started_at``, or None."""
    if not timestamp:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ",
                "%Y-%m-%dT%H:%M:%S%z"):
        try:
            parsed = datetime.datetime.strptime(timestamp, fmt)
        except ValueError:
            continue
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=datetime.timezone.utc)
        return parsed.timestamp()
    return None


class Bump:
    def __init__(self, args: argparse.Namespace):
        self.sha = args.sha
        self.candidate = args.candidate
        self.verify_only = args.verify_only
        self.home = args.home
        self.bin_dir = args.bin_dir
        self.state = args.state
        self.integration = args.integration
        self.accept_target = args.accept_target
        self.socket = args.socket
        self.lease = args.lease
        self.log_path = args.log
        self.label = args.label
        self.branch = args.integration_branch
        self.wait_seconds = args.wait_seconds
        self.tool_launchctl = args.launchctl
        self.tool_lsof = args.lsof
        self.tool_codesign = args.codesign
        self.tool_cargo = args.cargo
        self.uid = os.getuid()
        self.service_path = os.path.join(self.bin_dir, "canter")
        self.installed_sha = ""
        self.reconciled = "skipped (prebuilt candidate)"
        self._log_handle = None

    # -- logging -----------------------------------------------------------

    def open_log(self) -> None:
        directory = os.path.dirname(self.log_path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        self._log_handle = open(self.log_path, "a", encoding="utf-8")

    def log(self, message: str) -> None:
        line = "{} {}".format(time.strftime("%H:%M:%S"), message)
        print(line, flush=True)
        if self._log_handle is not None:
            self._log_handle.write(line + "\n")
            self._log_handle.flush()

    def log_tool(self, argv: list[str], proc: subprocess.CompletedProcess) -> None:
        self.log("tool exit={} argv={}".format(proc.returncode, " ".join(argv)))
        for stream, text in (("stdout", proc.stdout), ("stderr", proc.stderr)):
            text = (text or "").strip()
            if text:
                self.log("tool {}= {}".format(stream, text[-4000:]))

    def run_tool(self, argv: list[str], **kwargs) -> subprocess.CompletedProcess:
        proc = subprocess.run(
            argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, check=False, **kwargs)
        self.log_tool(argv, proc)
        return proc

    # -- stages ------------------------------------------------------------

    def reconcile(self) -> None:
        """Move the integration checkout (branch included) onto the target sha."""
        if self.candidate is not None:
            self.log("reconcile=skipped (--candidate {})".format(self.candidate))
            return
        fetch = self.run_tool(["git", "-C", self.integration, "fetch", "--no-tags",
                               "origin", self.branch])
        if fetch.returncode != 0:
            raise Refusal("bump.refusal.reconcile",
                          "git fetch origin {} failed in {}".format(self.branch, self.integration))
        published = self.run_tool(["git", "-C", self.integration, "rev-parse",
                                   "origin/" + self.branch]).stdout.strip()
        if published != self.sha:
            self.log("WARNING origin/{}={} but target sha={}".format(self.branch, published, self.sha))
        old = self.run_tool(["git", "-C", self.integration, "rev-parse", "HEAD"]).stdout.strip()
        ancestor = subprocess.run(
            ["git", "-C", self.integration, "merge-base", "--is-ancestor", old, self.sha],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        if ancestor.returncode != 0:
            raise Refusal("bump.refusal.non_ff",
                          "{} is not an ancestor of {} - refusing to move the integration checkout".format(old, self.sha))
        self.run_tool(["git", "-C", self.integration, "checkout", "-B", self.branch, self.sha])
        head = self.run_tool(["git", "-C", self.integration, "rev-parse", "HEAD"]).stdout.strip()
        current = self.run_tool(["git", "-C", self.integration, "rev-parse",
                                 "--abbrev-ref", "HEAD"]).stdout.strip()
        tree = self.run_tool(["git", "-C", self.integration, "rev-parse",
                              "HEAD^{tree}"]).stdout.strip()
        if head != self.sha:
            raise Refusal("bump.refusal.reconcile",
                          "checkout landed on {} (expected {})".format(head, self.sha))
        if current != self.branch:
            raise Refusal("bump.refusal.reconcile",
                          "checkout landed on branch '{}' (expected '{}')".format(current, self.branch))
        self.reconciled = "HEAD={} branch={} tree={}".format(head, current, tree)
        self.log("reconcile=ok {}".format(self.reconciled))

    def build(self) -> None:
        if self.candidate is not None:
            if not os.access(self.candidate, os.X_OK):
                raise Refusal("bump.refusal.usage",
                              "--candidate {} is not an executable file".format(self.candidate))
            self.log("build=skipped (prebuilt candidate)")
            return
        proc = subprocess.run([self.tool_cargo, "build", "--release", "--locked"],
                              cwd=self.integration, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, text=True, check=False)
        self.log("cargo_build_release_exit={}".format(proc.returncode))
        if proc.returncode != 0:
            self.log("tool stdout= {}".format((proc.stdout or "").strip()[-4000:]))
            raise Refusal("bump.refusal.build",
                          "cargo build --release --locked failed in {}".format(self.integration))
        self.candidate = os.path.join(self.integration, "target", "release", "canter")
        if not os.access(self.candidate, os.X_OK):
            raise Refusal("bump.refusal.build",
                          "the build produced no executable at {}".format(self.candidate))

    def install(self) -> None:
        """Install the candidate to BOTH paths and ad-hoc re-sign both."""
        destinations = (
            ("accept_target", self.accept_target),
            ("service_path", self.service_path),
        )
        try:
            self.candidate_sha = sha256_file(self.candidate)
        except OSError as exc:
            raise Refusal("bump.refusal.build",
                          "cannot read the candidate {}: {}".format(self.candidate, exc))
        self.log("candidate={} pre_sign_sha256={}".format(self.candidate, self.candidate_sha))
        for name, destination in destinations:
            try:
                self.install_atomic(self.candidate, destination)
                installed_pre_sign = sha256_file(destination)
            except OSError as exc:
                raise Refusal("bump.refusal.install",
                              "installing {} to {} failed: {}".format(name, destination, exc))
            self.log("installed {}={} pre_sign_sha256={} (the ad-hoc re-sign below "
                     "rewrites these bytes)".format(name, destination, installed_pre_sign))
        if os.path.exists(self.tool_codesign) or shutil.which(self.tool_codesign):
            for name, destination in destinations:
                sign = self.run_tool([self.tool_codesign, "--force", "--sign", "-", destination])
                if sign.returncode != 0:
                    raise Refusal("bump.refusal.sign",
                                  "ad-hoc re-signing {} ({}) failed".format(name, destination))
                verify = self.run_tool([self.tool_codesign, "-v", destination])
                if verify.returncode != 0:
                    raise Refusal("bump.refusal.sign",
                                  "{} ({}) does not carry a valid signature".format(name, destination))
        else:
            self.log("sign=skipped (no codesign on this host)")
        try:
            accept_sha = sha256_file(self.accept_target)
            service_sha = sha256_file(self.service_path)
        except OSError as exc:
            raise Refusal("bump.refusal.install",
                          "an installed path is not readable: {}".format(exc))
        if accept_sha != service_sha:
            raise Refusal("bump.refusal.install_divergence",
                          "{} ({}) and {} ({}) are not byte-identical".format(
                              self.accept_target, accept_sha, self.service_path, service_sha))
        self.installed_sha = service_sha
        self.installed_mtime = os.stat(self.service_path).st_mtime
        self.log("installed binary_sha256={} mtime={} (both paths, post-sign: the "
                 "identity of the executed bytes)".format(
                     self.installed_sha, self.installed_mtime))

    @staticmethod
    def install_atomic(source: str, destination: str) -> None:
        directory = os.path.dirname(destination)
        if directory:
            os.makedirs(directory, exist_ok=True)
        staging = "{}.new-{}".format(destination, os.getpid())
        try:
            shutil.copyfile(source, staging)
            os.chmod(staging, 0o755)
            os.replace(staging, destination)
        except OSError:
            if os.path.exists(staging):
                os.unlink(staging)
            raise

    def supervisor_program(self) -> str:
        """The program path the supervised job launches (launchd `print`)."""
        target = "gui/{}/{}".format(self.uid, self.label)
        proc = self.run_tool([self.tool_launchctl, "print", target])
        if proc.returncode != 0:
            raise Refusal("bump.refusal.supervisor_not_loaded",
                          "{} is not loaded ({}: exit {}); install the unit per "
                          "docs/OPERATIONS.md section 5.1".format(
                              target, self.tool_launchctl, proc.returncode))
        for line in (proc.stdout or "").splitlines():
            stripped = line.strip()
            if stripped.startswith("program = "):
                return stripped[len("program = "):].strip()
        raise Refusal("bump.refusal.supervisor_not_loaded",
                      "{} printed no 'program = ' row".format(target))

    def check_supervisor(self) -> None:
        program = self.supervisor_program()
        if not same_path(program, self.service_path):
            raise Refusal("bump.refusal.supervisor_program",
                          "the job launches {} but the bump installs {}".format(
                              program, self.service_path))
        self.log("supervisor_program={} (matches the installed service path)".format(program))

    def restart(self) -> None:
        target = "gui/{}/{}".format(self.uid, self.label)
        proc = self.run_tool([self.tool_launchctl, "kickstart", "-k", target])
        if proc.returncode != 0:
            raise Refusal("bump.refusal.restart",
                          "{} kickstart -k {} failed (exit {})".format(
                              self.tool_launchctl, target, proc.returncode))
        self.log("restart=ok ({})".format(target))

    def socket_holders(self) -> list[int]:
        proc = subprocess.run([self.tool_lsof, "-U"], stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, text=True, check=False)
        holders: list[int] = []
        for line in (proc.stdout or "").splitlines()[1:]:
            fields = line.split()
            if len(fields) < 3:
                continue
            if not same_path(fields[-1], self.socket):
                continue
            try:
                pid = int(fields[1])
            except ValueError:
                continue
            if pid not in holders:
                holders.append(pid)
        return holders

    def pid_executable(self, pid: int) -> str | None:
        proc = subprocess.run([self.tool_lsof, "-p", str(pid), "-a", "-d", "txt", "-Fn"],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              text=True, check=False)
        for line in (proc.stdout or "").splitlines():
            if line.startswith("n") and len(line) > 1:
                return line[1:]
        return None

    def lease_facts(self) -> tuple[int | None, str | None]:
        try:
            with open(self.lease, encoding="utf-8") as handle:
                text = handle.read()
        except OSError:
            return None, None
        pid = None
        started_at = None
        for line in text.splitlines():
            if line.startswith("pid "):
                try:
                    pid = int(line.split(" ", 1)[1].strip())
                except ValueError:
                    pid = None
            elif line.startswith("started_at "):
                started_at = line.split(" ", 1)[1].strip()
        return pid, started_at

    def lease_disagreement(self, holder: int) -> tuple[str, str] | None:
        """Why the daemon lease does not certify `holder`, or None if it does."""
        lease_pid, started_at = self.lease_facts()
        if lease_pid != holder:
            return ("bump.refusal.lease",
                    "{} records pid {} but the socket is held by {}".format(
                        self.lease, lease_pid, holder))
        started = parse_rfc3339(started_at)
        if started is None:
            return ("bump.refusal.lease",
                    "{} records no parseable started_at ({!r}) for pid {}".format(
                        self.lease, started_at, holder))
        if started + RECENCY_TOLERANCE_SECS < self.installed_mtime:
            return ("bump.refusal.stale_daemon",
                    "socket {} is held by pid {} whose recorded start ({}) predates the "
                    "installed build (mtime {}): the running daemon is not the build "
                    "just installed".format(
                        self.socket, holder, started_at, self.installed_mtime))
        return None

    def verify(self) -> tuple[int, str, str, str | None]:
        """Prove exactly one holder whose executable IS the installed build."""
        deadline = time.monotonic() + self.wait_seconds
        last_holders: list[int] = []
        last_reason: tuple[str, str] | None = None
        while True:
            holders = self.socket_holders()
            if holders:
                last_holders = holders
                if len(holders) == 1:
                    exe = self.pid_executable(holders[0])
                    if exe is None:
                        last_reason = (
                            "bump.refusal.pid_exe_unresolved",
                            "cannot resolve the executable of pid {}".format(holders[0]))
                    else:
                        try:
                            observed_sha = sha256_file(exe)
                        except OSError as exc:
                            observed_sha = None
                            last_reason = (
                                "bump.refusal.pid_exe_unresolved",
                                "cannot read the executable of pid {} ({}): {}".format(
                                    holders[0], exe, exc))
                        if observed_sha is not None:
                            if observed_sha != self.installed_sha:
                                last_reason = (
                                    "bump.refusal.stale_daemon",
                                    "socket {} is held by pid {} ({} sha256={}) which is not "
                                    "the installed build (sha256={})".format(
                                        self.socket, holders[0], exe, observed_sha,
                                        self.installed_sha))
                            else:
                                last_reason = self.lease_disagreement(holders[0])
                                if last_reason is None:
                                    _lease_pid, started_at = self.lease_facts()
                                    self.log("socket_holders=1 pid={} exe={} sha256={} "
                                             "started_at={}".format(
                                                 holders[0], exe, self.installed_sha,
                                                 started_at))
                                    return holders[0], exe, self.installed_sha, started_at
            if time.monotonic() >= deadline:
                break
            time.sleep(0.25)
        if not last_holders:
            raise Refusal("bump.refusal.daemon_not_up",
                          "no pid held {} within {}s".format(self.socket, self.wait_seconds))
        if len(last_holders) > 1:
            raise Refusal("bump.refusal.socket_holders",
                          "{} pids hold {}: {}".format(
                              len(last_holders), self.socket, last_holders))
        if last_reason is not None:
            raise Refusal(*last_reason)
        raise Refusal("bump.refusal.pid_exe_unresolved",
                      "the holder of {} could not be verified".format(self.socket))

    # -- run ---------------------------------------------------------------

    def certify_installed(self) -> None:
        """Certify the running daemon against what is already installed."""
        try:
            service_sha = sha256_file(self.service_path)
            accept_sha = sha256_file(self.accept_target)
        except OSError as exc:
            raise Refusal("bump.refusal.install",
                          "the installed paths are not readable: {}".format(exc))
        if service_sha != accept_sha:
            raise Refusal("bump.refusal.install_divergence",
                          "{} ({}) and {} ({}) are not byte-identical".format(
                              self.accept_target, accept_sha, self.service_path, service_sha))
        self.installed_sha = service_sha
        self.installed_mtime = os.stat(self.service_path).st_mtime
        self.log("verify_only installed binary_sha256={} mtime={}".format(
            self.installed_sha, self.installed_mtime))
        self.check_supervisor()

    def run(self) -> int:
        self.open_log()
        self.log("bump.start mode={} sha={} candidate={} socket={} service_path={} "
                 "accept_target={} label={} uid={}".format(
                     "verify-only" if self.verify_only else "bump", self.sha,
                     self.candidate, self.socket, self.service_path,
                     self.accept_target, self.label, self.uid))
        try:
            if self.verify_only:
                self.certify_installed()
            else:
                self.reconcile()
                self.build()
                self.install()
                self.check_supervisor()
                self.restart()
            pid, exe, sha, started_at = self.verify()
        except Refusal as refusal:
            self.log("{}: {}".format(refusal.code, refusal.message))
            self.log(json.dumps({
                "event": "bump.refused", "code": refusal.code,
                "exit_code": refusal.exit_code, "socket": self.socket,
                "installed_sha256": self.installed_sha or None}))
            print("{}: {}".format(refusal.code, refusal.message), file=sys.stderr)
            return refusal.exit_code
        self.log(json.dumps({
            "event": "bump.done", "socket": self.socket, "pid": pid,
            "started_at": started_at, "exe": exe, "sha256": sha,
            "candidate_sha256": getattr(self, "candidate_sha", None),
            "mode": "verify-only" if self.verify_only else "bump",
            "socket_holders": 1, "accept_target": self.accept_target,
            "service_path": self.service_path, "reconciled": self.reconciled}))
        self.log("DONE (pid={} started_at={} sha256={})".format(pid, started_at, sha))
        return 0


def default_state(home: str) -> str:
    xdg = os.environ.get("XDG_STATE_HOME")
    if xdg:
        return os.path.join(xdg, "canter")
    return os.path.join(home, ".local", "state", "canter")


def parse_args(argv: list[str]) -> argparse.Namespace:
    home = os.path.expanduser("~")
    parser = argparse.ArgumentParser(
        prog="accept-bump.py", add_help=True,
        description="Install a candidate to BOTH the acceptance target and the "
                    "path the supervised service launches, restart through the "
                    "supervisor, and prove the running daemon is that build.")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--sha", help="40-hex sha to reconcile+build the candidate from")
    source.add_argument("--candidate", help="prebuilt candidate binary (skips reconcile+build)")
    source.add_argument("--verify-only", action="store_true",
                        help="certify the RUNNING daemon against the installed paths and "
                             "record the facts; install, restart and build nothing")
    parser.add_argument("--home", default=home)
    parser.add_argument("--bin-dir", default=None,
                        help="directory holding the service-launched binary (default: <home>/.local/bin)")
    parser.add_argument("--state", default=None,
                        help="canter state dir (default: XDG_STATE_HOME/canter or <home>/.local/state/canter)")
    parser.add_argument("--integration", default=None,
                        help="integration checkout to reconcile (default: <state>/accept/integration/canter)")
    parser.add_argument("--accept-target", default=None,
                        help="acceptance target binary (default: <state>/accept/target/release/canter)")
    parser.add_argument("--socket", default=None, help="daemon socket (default: <state>/canter.sock)")
    parser.add_argument("--lease", default=None, help="daemon lease file (default: <state>/daemon.lock)")
    parser.add_argument("--log", default=None, help="bump log (default: <state>/accept/bump.log)")
    parser.add_argument("--label", default="com.canter.daemon", help="supervised job label")
    parser.add_argument("--integration-branch", default="staging",
                        help="integration branch the checkout must land on")
    parser.add_argument("--wait-seconds", type=float, default=30.0,
                        help="bounded wait for the single-holder invariant (default: 30)")
    parser.add_argument("--launchctl", default="launchctl", help="supervisor CLI")
    parser.add_argument("--lsof", default="lsof", help="lsof binary")
    parser.add_argument("--codesign", default="codesign", help="codesign binary")
    parser.add_argument("--cargo", default="cargo", help="cargo binary")
    args = parser.parse_args(argv)
    if args.sha is not None and not SHA_RE.match(args.sha):
        parser.error("--sha must be 40 lowercase hex characters")
    if args.wait_seconds <= 0:
        parser.error("--wait-seconds must be positive")
    args.home = os.path.abspath(args.home)
    args.bin_dir = os.path.abspath(args.bin_dir or os.path.join(args.home, ".local", "bin"))
    args.state = os.path.abspath(args.state or default_state(args.home))
    args.integration = os.path.abspath(
        args.integration or os.path.join(args.state, "accept", "integration", "canter"))
    args.accept_target = os.path.abspath(
        args.accept_target or os.path.join(args.state, "accept", "target", "release", "canter"))
    args.socket = os.path.abspath(args.socket or os.path.join(args.state, "canter.sock"))
    args.lease = os.path.abspath(args.lease or os.path.join(args.state, "daemon.lock"))
    args.log = os.path.abspath(args.log or os.path.join(args.state, "accept", "bump.log"))
    return args


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    bump = Bump(args)
    try:
        return bump.run()
    finally:
        if bump._log_handle is not None:
            bump._log_handle.close()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
