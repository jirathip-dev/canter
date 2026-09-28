#!/usr/bin/env python3
"""test-install-canter.py — self-test for scripts/install-canter.py (#221).

Every scenario runs the REAL driver against a DISPOSABLE prefix: the host's
`~/.local/bin` is never touched, no service manager is ever called, and no
daemon is started. The candidates are tiny fake executables, so the suite
needs no release build; `--bin PATH` adds one scenario that installs a real
built canter and checks the recorded read-back against its own output.

What is proven:

* install — the candidate's bytes land at `<prefix>/canter` (mode 0755) and
  the record's sha256 is the sha256 of those bytes;
* read-back — the record carries the `--version` line the INSTALLED bytes
  answered (the staged copy is executed before anything is replaced);
* retention — a second install retains the first bytes as `canter.previous`
  and records their sha256;
* rollback — `--rollback` restores the retained bytes, retains the replaced
  ones (the pair swaps), and rewrites the record for the restored bytes;
* refusal — a rollback with nothing retained, a missing candidate, a prefix
  that is a file, a candidate whose `--version` fails, a dirty checkout, a
  checkout that is not a git repository, a failing build and a directory at
  the destination each exit with their typed `install.refusal.<code>` and
  change nothing;
* dry-run — the exact commands are printed and no file is created, changed
  or removed (install and rollback).

Usage:
  python3 scripts/test-install-canter.py [--keep] [--bin PATH]
Exit codes: 0 all checks passed, 1 a check failed, 2 usage error.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
DRIVER = os.path.join(HERE, "install-canter.py")

CANDIDATE_TEMPLATE = """#!/usr/bin/env python3
import sys

if sys.argv[1:] == ["--version"]:
    print("canter {version}")
    print("state schema version: 15")
    sys.exit({exit_code})
sys.exit(3)
"""

CARGO_SHIM = """#!/usr/bin/env python3
import json
import os
import sys

argv = sys.argv[1:]
cwd = os.getcwd()
if argv[:1] == ["build"]:
    source = os.environ["HF_INSTALL_TEST_CANDIDATE"]
    destination = os.path.join(cwd, "target", "release", "canter")
    os.makedirs(os.path.dirname(destination), exist_ok=True)
    with open(source, "rb") as handle:
        payload = handle.read()
    with open(destination, "wb") as handle:
        handle.write(payload)
    os.chmod(destination, 0o755)
    sys.exit(0)
if argv[:1] == ["metadata"]:
    print(json.dumps({"target_directory": os.path.join(cwd, "target")}))
    sys.exit(0)
sys.exit(2)
"""


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


class Suite:
    def __init__(self) -> None:
        self.checks = 0

    def check(self, condition: bool, message: str) -> None:
        self.checks += 1
        if not condition:
            raise AssertionError(message)


def make_executable(path: str, text: str) -> str:
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)
    os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


def write_candidate(directory: str, name: str, version: str, exit_code: int = 0) -> str:
    return make_executable(
        os.path.join(directory, name),
        CANDIDATE_TEMPLATE.format(version=version, exit_code=exit_code))


def run_driver(args: list[str], cwd: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, DRIVER] + args, cwd=cwd,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          text=True, check=False)


def load_record(prefix: str) -> dict:
    with open(os.path.join(prefix, "canter.installed.json"), "r",
              encoding="utf-8") as handle:
        return json.load(handle)


def git(directory: str, *argv: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-c", "user.name=canter-selftest", "-c", "user.email=selftest@example.invalid"]
        + list(argv), cwd=directory, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, check=False)


def install(suite: Suite, workspace: str, args: list[str], expect: int,
            what: str) -> subprocess.CompletedProcess:
    proc = run_driver(args, cwd=workspace)
    suite.check(
        proc.returncode == expect,
        "{}: expected exit {}, got {}\nstdout:\n{}\nstderr:\n{}".format(
            what, expect, proc.returncode, proc.stdout, proc.stderr))
    return proc


def fresh_install(suite: Suite, workspace: str, prefix: str, candidate: str,
                  what: str) -> subprocess.CompletedProcess:
    return install(suite, workspace,
                   ["--candidate", candidate, "--prefix", prefix], 0, what)


def checks(binary: str | None, keep: bool) -> int:
    suite = Suite()
    workspace = tempfile.mkdtemp(prefix="hf-install-221-")
    try:
        candidate_a = write_candidate(workspace, "candidate-a", "9.9.9-alpha")
        candidate_b = write_candidate(workspace, "candidate-b", "9.9.9-beta")
        sha_a, sha_b = sha256_file(candidate_a), sha256_file(candidate_b)
        prefix_one = os.path.join(workspace, "prefix-one")
        prefix_two = os.path.join(workspace, "prefix-two")

        # 1. A fresh install lands the candidate's bytes and records them.
        proc = fresh_install(suite, workspace, prefix_one, candidate_a, "fresh install")
        suite.check("DONE action=install" in proc.stdout,
                    "fresh install prints no DONE action=install line: " + proc.stdout)
        installed = os.path.join(prefix_one, "canter")
        suite.check(os.path.isfile(installed), "no installed binary at " + installed)
        suite.check(sha256_file(installed) == sha_a,
                    "the installed bytes are not the candidate's")
        mode = stat.S_IMODE(os.stat(installed).st_mode)
        suite.check(mode == 0o755, "installed mode is {:o}, expected 755".format(mode))
        record = load_record(prefix_one)
        suite.check(record["schema"] == "canter-install/v1", "record schema changed")
        suite.check(record["action"] == "install", "record action is not install")
        suite.check(record["binary_sha256"] == sha_a,
                    "the record's sha256 is not the installed bytes'")
        suite.check(record["candidate_sha256"] == sha_a, "record candidate sha mismatch")
        suite.check(record["version"] == "canter 9.9.9-alpha",
                    "the record does not carry the read-back version: "
                    + repr(record.get("version")))
        suite.check(any(line.startswith("state schema version")
                        for line in record["readback"]),
                    "the record does not carry the full read-back")
        suite.check(record["retained"] is None, "a fresh install retained something")
        suite.check(record["source_revision"] is None,
                    "a prebuilt candidate must record no source revision")
        suite.check(not os.path.exists(os.path.join(prefix_one, "canter.previous")),
                    "a fresh install created a previous binary")
        print("PASS: a fresh install lands the candidate's bytes and records the "
              "read-back sha256={}".format(sha_a[:12]))

        # 2. A second install retains the first bytes.
        fresh_install(suite, workspace, prefix_one, candidate_b, "second install")
        suite.check(sha256_file(installed) == sha_b, "the second install did not land")
        previous = os.path.join(prefix_one, "canter.previous")
        suite.check(sha256_file(previous) == sha_a,
                    "the retained previous bytes are not the first install's")
        record = load_record(prefix_one)
        suite.check(record["retained"]["sha256"] == sha_a,
                    "the record does not name the retained sha256")
        suite.check(record["binary_sha256"] == sha_b, "the record kept a stale sha256")
        print("PASS: a second install retains the previous bytes (previous={})"
              .format(sha_a[:12]))

        # 3. Rollback restores the retained bytes and swaps the pair.
        proc = install(suite, workspace, ["--rollback", "--prefix", prefix_one], 0,
                       "rollback")
        suite.check("DONE action=rollback" in proc.stdout,
                    "rollback prints no DONE action=rollback line: " + proc.stdout)
        suite.check(sha256_file(installed) == sha_a,
                    "rollback did not restore the retained bytes")
        suite.check(sha256_file(previous) == sha_b,
                    "rollback did not retain the replaced bytes")
        record = load_record(prefix_one)
        suite.check(record["action"] == "rollback", "record action is not rollback")
        suite.check(record["binary_sha256"] == sha_a,
                    "the record does not certify the restored bytes")
        suite.check(record["retained"]["sha256"] == sha_b,
                    "the record does not name the replaced bytes")
        suite.check(record["version"] == "canter 9.9.9-alpha",
                    "the record kept the replaced read-back")
        install(suite, workspace, ["--rollback", "--prefix", prefix_one], 0,
                "second rollback")
        suite.check(sha256_file(installed) == sha_b,
                    "the pair does not swap: a second rollback must go back forward")
        print("PASS: rollback restores the retained bytes and the pair swaps")

        # 4. A rollback with nothing retained refuses and changes nothing.
        fresh_install(suite, workspace, prefix_two, candidate_a, "install into prefix-two")
        installed_two = os.path.join(prefix_two, "canter")
        before = sha256_file(installed_two)
        proc = install(suite, workspace, ["--rollback", "--prefix", prefix_two], 9,
                       "rollback with nothing retained")
        suite.check("install.refusal.rollback" in proc.stderr,
                    "the refusal code is not on stderr: " + proc.stderr)
        suite.check(sha256_file(installed_two) == before,
                    "a refused rollback changed the installed binary")
        record = load_record(prefix_two)
        suite.check(record["action"] == "install",
                    "a refused rollback rewrote the record")
        print("PASS: a rollback with nothing retained refuses typed and changes nothing")

        # 5. A refused read-back never replaces the installed bytes.
        bad = write_candidate(workspace, "candidate-bad", "9.9.9-bad", exit_code=7)
        proc = install(suite, workspace,
                       ["--candidate", bad, "--prefix", prefix_two], 8,
                       "read-back refusing candidate")
        suite.check("install.refusal.readback" in proc.stderr,
                    "the refusal code is not on stderr: " + proc.stderr)
        suite.check(sha256_file(installed_two) == before,
                    "a candidate that failed the read-back replaced the installed bytes")
        suite.check(not os.path.exists(os.path.join(prefix_two, "canter.previous")),
                    "a refused install retained a previous binary")
        suite.check(load_record(prefix_two)["binary_sha256"] == before,
                    "a refused install rewrote the record")
        empty = make_executable(os.path.join(workspace, "candidate-empty"),
                                "#!/usr/bin/env python3\nimport sys\nsys.exit(0)\n")
        install(suite, workspace, ["--candidate", empty, "--prefix", prefix_two], 8,
                "silent candidate")
        suite.check(sha256_file(installed_two) == before,
                    "a silent candidate replaced the installed bytes")
        leftovers = [name for name in os.listdir(prefix_two) if ".new-" in name
                     or ".rollback-" in name]
        suite.check(not leftovers,
                    "staged files were left behind: {}".format(leftovers))
        print("PASS: a candidate that fails (or answers nothing on) --version never "
              "replaces the installed bytes")

        # 6. A dry run prints the exact commands and writes nothing.
        prefix_three = os.path.join(workspace, "prefix-three")
        proc = install(suite, workspace,
                       ["--candidate", candidate_a, "--prefix", prefix_three, "--dry-run"],
                       0, "dry-run install")
        for expected in ("would run: cp {} ".format(candidate_a),
                         "canter.new-", " --version", "DRY-RUN",
                         "DONE action=install dry_run=yes"):
            suite.check(expected in proc.stdout,
                        "the dry-run plan does not print {!r}:\n{}".format(
                            expected, proc.stdout))
        suite.check(not os.path.exists(prefix_three),
                    "a dry-run install created the prefix")
        proc = install(suite, workspace,
                       ["--candidate", candidate_b, "--prefix", prefix_two, "--dry-run"],
                       0, "dry-run install over an existing install")
        suite.check("would run: cp {} {}".format(installed_two, os.path.join(
            prefix_two, "canter.previous")) in proc.stdout,
            "the dry-run plan does not name the retention copy:\n" + proc.stdout)
        suite.check(sha256_file(installed_two) == before,
                    "a dry-run install changed the installed bytes")
        suite.check(load_record(prefix_two)["action"] == "install",
                    "a dry-run install rewrote the record")
        print("PASS: a dry-run install prints the exact commands and writes nothing")

        # 7. A dry-run rollback changes nothing either.
        install(suite, workspace, ["--rollback", "--prefix", prefix_two, "--dry-run"],
                9, "dry-run rollback with nothing retained")
        fresh_install(suite, workspace, prefix_two, candidate_b, "install beta")
        proc = install(suite, workspace, ["--rollback", "--prefix", prefix_two, "--dry-run"],
                       0, "dry-run rollback")
        suite.check("would run: cp {} {}".format(
            os.path.join(prefix_two, "canter.previous"), installed_two) in proc.stdout,
            "the dry-run rollback plan does not name the restore:\n" + proc.stdout)
        suite.check(sha256_file(installed_two) == sha_b,
                    "a dry-run rollback changed the installed bytes")
        suite.check(sha256_file(os.path.join(prefix_two, "canter.previous")) == before,
                    "a dry-run rollback changed the retained bytes")
        suite.check(load_record(prefix_two)["action"] == "install",
                    "a dry-run rollback rewrote the record")
        print("PASS: a dry-run rollback prints the exact commands and changes nothing")

        # 8. Build mode records the head it built from and refuses a dirty tree.
        checkout = os.path.join(workspace, "checkout")
        os.makedirs(checkout)
        git(checkout, "init", "-q")
        with open(os.path.join(checkout, "README.md"), "w", encoding="utf-8") as handle:
            handle.write("fixture\n")
        git(checkout, "add", "README.md")
        git(checkout, "commit", "-q", "-m", "fixture")
        head = git(checkout, "rev-parse", "HEAD").stdout.strip()
        suite.check(len(head) == 40, "the fixture checkout has no HEAD: " + head)
        cargo = make_executable(os.path.join(workspace, "fake-cargo"), CARGO_SHIM)
        env_previous = os.environ.get("HF_INSTALL_TEST_CANDIDATE")
        os.environ["HF_INSTALL_TEST_CANDIDATE"] = candidate_a
        try:
            prefix_four = os.path.join(workspace, "prefix-four")
            install(suite, workspace,
                    ["--checkout", checkout, "--prefix", prefix_four, "--cargo", cargo],
                    0, "build-mode install")
            record = load_record(prefix_four)
            suite.check(record["source_revision"] == head,
                        "the record does not name the built head")
            suite.check(record["source_dirty"] is False,
                        "a clean checkout was recorded dirty")
            suite.check(sha256_file(os.path.join(prefix_four, "canter")) == sha_a,
                        "the build-mode install did not land the built bytes")
            suite.check(os.path.realpath(record["candidate"]) == os.path.realpath(
                os.path.join(checkout, "target", "release", "canter")),
                "the record does not name the built candidate: "
                + repr(record["candidate"]))

            # The dirty-tree refusal, and its explicit override.
            with open(os.path.join(checkout, "WIP.md"), "w", encoding="utf-8") as handle:
                handle.write("uncommitted\n")
            proc = install(suite, workspace,
                           ["--checkout", checkout, "--prefix", prefix_four, "--cargo", cargo],
                           10, "dirty checkout")
            suite.check("install.refusal.tree_dirty" in proc.stderr,
                        "the refusal code is not on stderr: " + proc.stderr)
            install(suite, workspace,
                    ["--checkout", checkout, "--prefix", prefix_four, "--cargo", cargo,
                     "--allow-dirty"], 0, "--allow-dirty install")
            suite.check(load_record(prefix_four)["source_dirty"] is True,
                        "--allow-dirty did not record the dirty source")
            print("PASS: build mode records the built head {} and refuses a dirty tree"
                  .format(head[:12]))
        finally:
            if env_previous is None:
                os.environ.pop("HF_INSTALL_TEST_CANDIDATE", None)
            else:
                os.environ["HF_INSTALL_TEST_CANDIDATE"] = env_previous

        # 9. Usage refusals: a missing candidate, a prefix that is a file.
        proc = install(suite, workspace,
                       ["--candidate", os.path.join(workspace, "absent"),
                        "--prefix", prefix_three], 5, "missing candidate")
        suite.check("install.refusal.candidate" in proc.stderr,
                    "the refusal code is not on stderr: " + proc.stderr)
        prefix_file = os.path.join(workspace, "prefix-file")
        with open(prefix_file, "w", encoding="utf-8") as handle:
            handle.write("not a directory\n")
        proc = install(suite, workspace,
                       ["--candidate", candidate_a, "--prefix", prefix_file], 6,
                       "prefix that is a file")
        suite.check("install.refusal.prefix" in proc.stderr,
                    "the refusal code is not on stderr: " + proc.stderr)
        proc = install(suite, workspace,
                       ["--checkout", workspace, "--prefix", prefix_three], 2,
                       "checkout that is not a git checkout")
        suite.check("install.refusal.usage" in proc.stderr,
                    "the refusal code is not on stderr: " + proc.stderr)
        print("PASS: a missing candidate and an unusable prefix refuse typed")

        # 8b. The remaining refusal branches: a failed build, and a
        # destination that exists as a directory.
        failing_cargo = make_executable(
            os.path.join(workspace, "fake-cargo-fails"),
            "#!/usr/bin/env python3\nimport sys\nsys.exit(9)\n")
        proc = install(suite, workspace,
                       ["--checkout", checkout, "--prefix", prefix_three,
                        "--cargo", failing_cargo, "--allow-dirty"], 4,
                       "failing build")
        suite.check("install.refusal.build" in proc.stderr,
                    "the refusal code is not on stderr: " + proc.stderr)
        prefix_six = os.path.join(workspace, "prefix-six")
        os.makedirs(os.path.join(prefix_six, "canter"))
        proc = install(suite, workspace,
                       ["--candidate", candidate_a, "--prefix", prefix_six], 7,
                       "destination that is a directory")
        suite.check("install.refusal.install" in proc.stderr,
                    "the refusal code is not on stderr: " + proc.stderr)
        suite.check(os.path.isdir(os.path.join(prefix_six, "canter")),
                    "the refusal touched the directory at the destination")
        leftovers = [name for name in os.listdir(prefix_six) if ".new-" in name]
        suite.check(not leftovers, "staged files were left behind: {}".format(leftovers))
        print("PASS: a failing build and a directory at the destination refuse typed")

        # 10. Optional: the REAL binary installs and reads its own version back.
        if binary is not None:
            prefix_five = os.path.join(workspace, "prefix-five")
            install(suite, workspace,
                    ["--candidate", binary, "--prefix", prefix_five], 0,
                    "real-binary install")
            readback = subprocess.run([os.path.join(prefix_five, "canter"), "--version"],
                                      stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                      text=True, check=False)
            first = readback.stdout.strip().splitlines()[0]
            suite.check(load_record(prefix_five)["version"] == first,
                        "the record's version is not the real binary's first line")
            print("PASS: the real binary installs and the record carries {!r}".format(first))

    finally:
        if not keep:
            shutil.rmtree(workspace, ignore_errors=True)
        else:
            print("kept: {}".format(workspace))

    print("\ninstall-canter self-test: all {} checks passed".format(suite.checks))
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog="test-install-canter.py",
                                     add_help=True)
    parser.add_argument("--keep", action="store_true",
                        help="keep the disposable workspace for inspection")
    parser.add_argument("--bin", default=None,
                        help="a real built canter binary for the extra scenario")
    arguments = parser.parse_args()
    try:
        sys.exit(checks(os.path.abspath(arguments.bin) if arguments.bin else None,
                        arguments.keep))
    except AssertionError as exc:
        print("FAIL: {}".format(exc))
        sys.exit(1)
