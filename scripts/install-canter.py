#!/usr/bin/env python3
"""install-canter.py — install a built canter to a stable PATH prefix, record
the installed sha, read `--version` back, and keep a one-step rollback
(issue #221).

The cutover this closes
-----------------------

The fleet cutover cannot run from a build artifact: `which canter` resolves to
nothing, and every operator action runs a build path by absolute value. Taking
over a real queue needs a stable, versioned binary on PATH — installed from a
known head, with the installed sha recorded — and a one-command way back out.

What this driver does
---------------------

1. ``candidate`` — build ``cargo build --release --locked`` in the checkout
   (a dirty tree refuses: the installed bytes must match a recorded head), or
   take a prebuilt ``--candidate`` path.
2. ``install`` — stage the bytes beside the destination, RUN the staged copy
   (``--version``) before anything is replaced, retain the bytes currently
   installed as ``canter.previous``, then replace the destination atomically.
   The destination is re-hashed afterwards and must equal the staged bytes, so
   the recorded sha256 is the identity of the bytes that were read back.
3. ``record`` — ``canter.installed.json`` beside the binary carries the
   schema, the action, the installed sha256, the ``--version`` read-back, the
   source revision (with whether the checkout was dirty) and the retained
   previous binary, so the cutover's provenance is one read.
4. ``rollback`` — ``--rollback`` restores the retained previous binary
   (re-running the read-back first) and retains the replaced one, so the pair
   swaps: one step back, executable again.
5. ``--dry-run`` — print the exact commands and touch nothing (the recorded
   dry run the issue asks for).

Never touched: the service manager and the daemon. This driver installs
BYTES; a human renders ``canter service install-plan`` from the INSTALLED
binary and executes the printed steps (docs/OPERATIONS.md section 5.1) —
install execution stays human-gated.

Operator tooling: run by hand, never from CI. The public-data rule holds — no
host path is baked in; every path comes from arguments or the derived
``$HOME``/``$XDG`` defaults. Stdlib only.

Usage:
  install-canter.py [--checkout DIR] [--prefix DIR] [--dry-run] [--allow-dirty]
  install-canter.py --candidate PATH [--prefix DIR] [--dry-run]
  install-canter.py --rollback [--prefix DIR] [--dry-run]

Exit codes (typed refusal table; 0 is the only success):
  0  DONE — installed (or rolled back) and read back
  2  install.refusal.usage        invalid invocation
  4  install.refusal.build        the candidate failed to build
  5  install.refusal.candidate    the candidate is missing or not executable
  6  install.refusal.prefix       the install prefix is unusable
  7  install.refusal.install      staging or replacing the binary failed
  8  install.refusal.readback     the bytes to install did not answer --version
  9  install.refusal.rollback     no retained previous binary to restore
 10  install.refusal.tree_dirty   the checkout has uncommitted changes
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import shutil
import subprocess
import sys

SCHEMA = "canter-install/v1"
BINARY_NAME = "canter"
PREVIOUS_NAME = "canter.previous"
RECORD_NAME = "canter.installed.json"
EXEC_MODE = 0o755

# Typed refusal table: code -> (exit status, meaning). Single authoritative
# copy: docs/OPERATIONS.md section 10.2 renders the same table.
REFUSALS = (
    ("install.refusal.usage", 2, "invalid invocation"),
    ("install.refusal.build", 4, "the candidate failed to build from the checkout"),
    ("install.refusal.candidate", 5, "the candidate is missing or not an executable file"),
    ("install.refusal.prefix", 6, "the install prefix is unusable"),
    ("install.refusal.install", 7, "staging or replacing the installed binary failed"),
    ("install.refusal.readback", 8, "the bytes to install did not answer `--version`"),
    ("install.refusal.rollback", 9, "no retained previous binary to restore"),
    ("install.refusal.tree_dirty", 10, "the checkout has uncommitted changes"),
)
EXIT_BY_CODE = {code: status for code, status, _meaning in REFUSALS}


class Refusal(Exception):
    """A typed install refusal: ``install.refusal.<code>`` plus its status."""

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


def now_rfc3339() -> str:
    stamp = datetime.datetime.now(datetime.timezone.utc)
    return stamp.strftime("%Y-%m-%dT%H:%M:%SZ")


def home_dir() -> str:
    return os.path.expanduser("~")


class Installer:
    def __init__(self, args: argparse.Namespace):
        self.checkout = os.path.abspath(args.checkout) if args.checkout else None
        self.candidate = os.path.abspath(args.candidate) if args.candidate else None
        self.prefix = os.path.abspath(args.prefix or os.path.join(home_dir(), ".local", "bin"))
        self.rollback = args.rollback
        self.dry_run = args.dry_run
        self.allow_dirty = args.allow_dirty
        self.tool_cargo = args.cargo
        self.tool_git = args.git
        self.binary = os.path.join(self.prefix, BINARY_NAME)
        self.previous = os.path.join(self.prefix, PREVIOUS_NAME)
        self.record = os.path.join(self.prefix, RECORD_NAME)
        self.staged = "{}.new-{}".format(self.binary, os.getpid())
        self.staged_previous = "{}.new-{}".format(self.previous, os.getpid())
        self.staged_rollback = "{}.rollback-{}".format(self.binary, os.getpid())
        self.source_revision: str | None = None
        self.source_dirty = False

    # -- reporting ---------------------------------------------------------

    def out(self, message: str) -> None:
        print(message, flush=True)

    def step(self, command: str, action) -> None:
        """Run one filesystem mutation, or print it under --dry-run."""
        if self.dry_run:
            self.out("would run: {}".format(command))
            return
        try:
            action()
        except OSError as exc:
            raise Refusal("install.refusal.install",
                          "{} failed: {}".format(command, exc))

    def tool(self, argv: list[str], cwd: str | None = None,
             dry_run_line: str | None = None) -> subprocess.CompletedProcess:
        """Run one child process (or print it under --dry-run)."""
        if self.dry_run:
            self.out("would run: {}".format(dry_run_line or " ".join(argv)))
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")
        return subprocess.run(argv, cwd=cwd, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, text=True, check=False)

    # -- candidate resolution ---------------------------------------------

    def executable_file(self, path: str) -> bool:
        return os.path.isfile(path) and os.access(path, os.X_OK)

    def resolve_candidate(self) -> str:
        if self.candidate is not None:
            self.out("candidate={} (prebuilt)".format(self.candidate))
            if not self.executable_file(self.candidate):
                raise Refusal(
                    "install.refusal.candidate",
                    "--candidate {} is not an executable file".format(self.candidate))
            return self.candidate
        if self.checkout is None:
            raise Refusal("install.refusal.usage",
                          "one of --checkout DIR or --candidate PATH is required")
        if not os.path.isdir(self.checkout):
            raise Refusal("install.refusal.usage",
                          "--checkout {} is not a directory".format(self.checkout))
        self.read_source(self.checkout)
        build = self.tool([self.tool_cargo, "build", "--release", "--locked"],
                          cwd=self.checkout)
        self.out("cargo build --release --locked exit={}".format(build.returncode))
        if build.returncode != 0:
            self.out("tool stdout= {}".format((build.stdout or "").strip()[-2000:]))
            raise Refusal("install.refusal.build",
                          "cargo build --release --locked failed in {}".format(self.checkout))
        if self.dry_run:
            return os.path.join(self.checkout, "target", "release", BINARY_NAME)
        metadata = self.tool([self.tool_cargo, "metadata", "--format-version", "1",
                              "--no-deps"], cwd=self.checkout)
        if metadata.returncode != 0:
            raise Refusal("install.refusal.build",
                          "cargo metadata --format-version 1 --no-deps failed in {}".format(
                              self.checkout))
        target = self.target_directory(metadata.stdout or "")
        candidate = os.path.join(target, "release", BINARY_NAME)
        if not self.executable_file(candidate):
            raise Refusal("install.refusal.build",
                          "the build produced no executable at {}".format(candidate))
        return candidate

    def target_directory(self, metadata: str) -> str:
        try:
            document = json.loads(metadata)
        except ValueError as exc:
            raise Refusal("install.refusal.build",
                          "cargo metadata printed no readable JSON: {}".format(exc))
        target = document.get("target_directory")
        if not isinstance(target, str) or not target:
            raise Refusal("install.refusal.build",
                          "cargo metadata printed no target_directory")
        return target

    def read_source(self, checkout: str) -> None:
        """Record the head the candidate is built from; refuse a dirty tree."""
        revision = self.tool([self.tool_git, "-C", checkout, "rev-parse", "HEAD"],
                             dry_run_line="{} -C {} rev-parse HEAD".format(
                                 self.tool_git, checkout))
        if self.dry_run:
            self.out("would run: {} -C {} status --porcelain".format(
                self.tool_git, checkout))
            return
        if revision.returncode != 0:
            raise Refusal(
                "install.refusal.usage",
                "{} is not a git checkout ({} -C {} rev-parse HEAD exit {}); install a "
                "prebuilt binary with --candidate instead".format(
                    checkout, self.tool_git, checkout, revision.returncode))
        self.source_revision = (revision.stdout or "").strip().splitlines()[0].strip()
        status = self.tool([self.tool_git, "-C", checkout, "status", "--porcelain"])
        self.source_dirty = bool((status.stdout or "").strip())
        if self.source_dirty and not self.allow_dirty:
            raise Refusal(
                "install.refusal.tree_dirty",
                "{} has uncommitted changes; the installed bytes would match no recorded "
                "head (commit them, install a clean checkout, or pass --allow-dirty to "
                "record the dirty source)".format(checkout))
        self.out("source revision={} dirty={}".format(
            self.source_revision, "yes" if self.source_dirty else "no"))

    # -- the read-back -----------------------------------------------------

    def readback(self, path: str) -> list[str]:
        """Execute ``path --version``; the lines are the recorded proof."""
        proc = self.tool([path, "--version"], dry_run_line="{} --version".format(path))
        if self.dry_run:
            return []
        lines = [line.strip() for line in (proc.stdout or "").splitlines() if line.strip()]
        if proc.returncode != 0 or not lines:
            raise Refusal(
                "install.refusal.readback",
                "{} --version exited {} with no version line (stdout: {!r})".format(
                    path, proc.returncode, (proc.stdout or "").strip()[:400]))
        return lines

    # -- install -----------------------------------------------------------

    def prefix_ready(self) -> None:
        if os.path.exists(self.prefix) and not os.path.isdir(self.prefix):
            raise Refusal("install.refusal.prefix",
                          "--prefix {} exists and is not a directory".format(self.prefix))
        self.step("mkdir -p {} && chmod 0755 {}".format(self.prefix, self.prefix),
                  lambda: self.make_prefix())

    def make_prefix(self) -> None:
        os.makedirs(self.prefix, mode=EXEC_MODE, exist_ok=True)
        os.chmod(self.prefix, EXEC_MODE)

    def stage(self, source: str, destination: str) -> None:
        shutil.copyfile(source, destination)
        os.chmod(destination, EXEC_MODE)

    @staticmethod
    def discard(path: str) -> None:
        """Remove one staged file; a refusal never leaves one behind."""
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
        except OSError:
            pass

    def do_install(self) -> int:
        if os.path.isdir(self.binary):
            raise Refusal("install.refusal.install",
                          "{} is a directory; remove it before installing".format(
                              self.binary))
        candidate = self.resolve_candidate()
        candidate_sha = "" if self.dry_run else sha256_file(candidate)
        self.out("candidate_sha256={}".format(candidate_sha or "(dry-run)"))
        self.step("cp {candidate} {staged} && chmod 0755 {staged}".format(
            candidate=candidate, staged=self.staged),
            lambda: self.stage(candidate, self.staged))
        try:
            readback = self.readback(self.staged)
        except Refusal:
            self.discard(self.staged)
            raise
        staged_sha = candidate_sha
        if not self.dry_run:
            staged_sha = sha256_file(self.staged)
            self.out("staged_sha256={}".format(staged_sha))
        retained: dict[str, str] | None = None
        if self.dry_run:
            if os.path.exists(self.binary):
                self.out("would run: cp {} {} && chmod 0755 {}".format(
                    self.binary, self.previous, self.previous))
        elif os.path.exists(self.binary):
            retained_sha = sha256_file(self.binary)
            self.step("cp {binary} {previous} && chmod 0755 {previous}".format(
                binary=self.binary, previous=self.previous),
                lambda: self.stage(self.binary, self.previous))
            if sha256_file(self.previous) != retained_sha:
                raise Refusal("install.refusal.install",
                              "the retained copy {} does not match {}".format(
                                  self.previous, self.binary))
            retained = {"binary": self.previous, "sha256": retained_sha}
            self.out("retained previous sha256={}".format(retained_sha))
        try:
            self.step("mv {staged} {binary}".format(staged=self.staged, binary=self.binary),
                      lambda: os.replace(self.staged, self.binary))
        except Refusal:
            self.discard(self.staged)
            raise
        if self.dry_run:
            self.out("would run: {} --version   (record the read-back)".format(self.binary))
        else:
            installed_sha = sha256_file(self.binary)
            if installed_sha != staged_sha:
                raise Refusal("install.refusal.install",
                              "{} ({}) is not the staged bytes ({})".format(
                                  self.binary, installed_sha, staged_sha))
            self.write_record({
                "schema": SCHEMA,
                "action": "install",
                "acted_at": now_rfc3339(),
                "binary": self.binary,
                "binary_sha256": installed_sha,
                "version": readback[0],
                "readback": readback,
                "source_revision": self.source_revision,
                "source_dirty": self.source_dirty,
                "candidate": candidate,
                "candidate_sha256": candidate_sha,
                "retained": retained,
            })
            self.out("readback version={!r} lines={}".format(readback[0], len(readback)))
        return 0

    def write_record(self, document: dict) -> None:
        payload = json.dumps(document, indent=2, sort_keys=True) + "\n"
        self.step("write {record}".format(record=self.record),
                  lambda: self.atomic_write(self.record, payload))
        self.out("record={} action={} binary_sha256={}".format(
            self.record, document["action"], document["binary_sha256"]))

    @staticmethod
    def atomic_write(path: str, payload: str) -> None:
        staging = "{}.new-{}".format(path, os.getpid())
        try:
            with open(staging, "w", encoding="utf-8") as handle:
                handle.write(payload)
            os.replace(staging, path)
        except OSError:
            Installer.discard(staging)
            raise

    # -- rollback ----------------------------------------------------------

    def load_record(self) -> dict:
        if not os.path.isfile(self.record) or not os.path.isfile(self.previous):
            raise Refusal(
                "install.refusal.rollback",
                "no retained previous binary at {} (record: {})".format(
                    self.previous, self.record))
        try:
            with open(self.record, "r", encoding="utf-8") as handle:
                document = json.load(handle)
        except (OSError, ValueError) as exc:
            raise Refusal("install.refusal.rollback",
                          "the install record {} is not readable JSON: {}".format(
                              self.record, exc))
        retained = document.get("retained")
        if not isinstance(retained, dict) or not retained.get("sha256"):
            raise Refusal("install.refusal.rollback",
                          "the install record {} names no retained previous binary".format(
                              self.record))
        return document

    def do_rollback(self) -> int:
        document = self.load_record()
        retained_sha = document["retained"]["sha256"]
        current_sha = sha256_file(self.previous)
        if current_sha != retained_sha:
            raise Refusal(
                "install.refusal.rollback",
                "{} ({}) is not the retained bytes recorded ({})".format(
                    self.previous, current_sha, retained_sha))
        self.out("rollback target={} retained_sha256={}".format(self.previous, retained_sha))
        self.step("cp {previous} {staged} && chmod 0755 {staged}".format(
            previous=self.previous, staged=self.staged_rollback),
            lambda: self.stage(self.previous, self.staged_rollback))
        try:
            readback = self.readback(self.staged_rollback)
        except Refusal:
            self.discard(self.staged_rollback)
            raise
        replaced_sha = sha256_file(self.binary)
        self.step("cp {binary} {staged_previous} && chmod 0755 {staged_previous}".format(
            binary=self.binary, staged_previous=self.staged_previous),
            lambda: self.stage(self.binary, self.staged_previous))
        try:
            self.step("mv {staged} {binary}".format(
                staged=self.staged_rollback, binary=self.binary),
                lambda: os.replace(self.staged_rollback, self.binary))
        except Refusal:
            self.discard(self.staged_rollback)
            self.discard(self.staged_previous)
            raise
        try:
            self.step("mv {staged_previous} {previous}".format(
                staged_previous=self.staged_previous, previous=self.previous),
                lambda: os.replace(self.staged_previous, self.previous))
        except Refusal:
            self.discard(self.staged_previous)
            raise
        if self.dry_run:
            self.out("would run: {} --version   (record the read-back)".format(self.binary))
            return 0
        installed_sha = sha256_file(self.binary)
        if installed_sha != retained_sha:
            raise Refusal("install.refusal.rollback",
                          "{} ({}) is not the retained bytes ({})".format(
                              self.binary, installed_sha, retained_sha))
        self.write_record({
            "schema": SCHEMA,
            "action": "rollback",
            "acted_at": now_rfc3339(),
            "binary": self.binary,
            "binary_sha256": installed_sha,
            "version": readback[0],
            "readback": readback,
            "source_revision": document.get("source_revision"),
            "source_dirty": document.get("source_dirty", False),
            "candidate": document.get("candidate"),
            "candidate_sha256": document.get("candidate_sha256"),
            "retained": {"binary": self.previous, "sha256": replaced_sha},
        })
        self.out("readback version={!r} replaced_sha256={}".format(
            readback[0], replaced_sha))
        return 0

    # -- entry -------------------------------------------------------------

    def run(self) -> int:
        mode = "rollback" if self.rollback else "install"
        self.out("install.start mode={} prefix={} binary={} dry_run={}".format(
            mode, self.prefix, self.binary, "yes" if self.dry_run else "no"))
        try:
            if self.rollback:
                if not self.dry_run:
                    self.prefix_ready()
                code = self.do_rollback()
            else:
                self.prefix_ready()
                code = self.do_install()
        except Refusal as refusal:
            self.out("{}: {}".format(refusal.code, refusal.message))
            print("{}: {}".format(refusal.code, refusal.message), file=sys.stderr)
            return refusal.exit_code
        except OSError as exc:
            for staged in (self.staged, self.staged_previous, self.staged_rollback):
                self.discard(staged)
            message = "install.refusal.install: {}".format(exc)
            self.out(message)
            print(message, file=sys.stderr)
            return EXIT_BY_CODE["install.refusal.install"]
        if self.dry_run:
            self.out("DRY-RUN: plan complete; nothing was written")
            self.out("DONE action={} dry_run=yes prefix={}".format(mode, self.prefix))
            return 0
        retention = "none"
        try:
            with open(self.record, "r", encoding="utf-8") as handle:
                document = json.load(handle)
            if document.get("retained"):
                retention = document["retained"]["sha256"]
        except (OSError, ValueError):
            retention = "unreadable"
        self.out("next: {binary} --version   (the same read-back from a fresh shell)"
                 .format(binary=self.binary))
        self.out("next: {binary} config init > $XDG_CONFIG_HOME/canter/config.toml   "
                 "(edit one repository in, then `config validate` and `doctor`)"
                 .format(binary=self.binary))
        self.out("next: {binary} service install-plan --json   (a HUMAN executes the "
                 "printed steps; install execution is human-gated)".format(binary=self.binary))
        self.out("DONE action={} binary={} sha256={} version={!r} previous={} source={}".format(
            mode, self.binary, sha256_file(self.binary), self.installed_version(), retention,
            self.source_revision or "none"))
        return code

    def installed_version(self) -> str:
        try:
            with open(self.record, "r", encoding="utf-8") as handle:
                return json.load(handle).get("version", "")
        except (OSError, ValueError):
            return ""


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="install-canter.py", add_help=True,
        description="Install a built canter to a stable PATH prefix, record the "
                    "installed sha, read `--version` back, and keep a one-step "
                    "rollback.")
    parser.add_argument("--checkout", default=None,
                        help="checkout to build `cargo build --release --locked` in "
                             "(default: the current directory)")
    parser.add_argument("--candidate", default=None,
                        help="prebuilt candidate binary (skips the build)")
    parser.add_argument("--prefix", default=None,
                        help="install prefix (default: $HOME/.local/bin)")
    parser.add_argument("--rollback", action="store_true",
                        help="restore the retained previous binary instead of installing")
    parser.add_argument("--dry-run", action="store_true",
                        help="print the exact commands and touch nothing")
    parser.add_argument("--allow-dirty", action="store_true",
                        help="install although the checkout has uncommitted changes "
                             "(recorded as source_dirty)")
    parser.add_argument("--cargo", default="cargo", help="cargo binary")
    parser.add_argument("--git", default="git", help="git binary")
    args = parser.parse_args(argv)
    if args.rollback and args.candidate is not None:
        parser.error("--rollback installs nothing and takes no --candidate")
    if args.checkout is None and args.candidate is None and not args.rollback:
        args.checkout = os.getcwd()
    return args


def main(argv: list[str]) -> int:
    return Installer(parse_args(argv)).run()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
