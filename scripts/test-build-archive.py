#!/usr/bin/env python3
"""test-build-archive.py — self-tests for scripts/build-archive.py.

Proves the issue #10 release-archive chain end-to-end on the current host:
builder failure modes BITE (wrong source ref, dirty tree, version mismatch,
unknown platform) and a real archive maps back to source + binary-reported
schema facts + checksums + SBOM digest, deterministically (two builds with
the same inputs produce byte-identical metadata and archive). Issue #106
review-fix round: the archive must also ship the pre-rename alias member
with its own executable framing, SHA256SUMS entry and provenance record
(docs/contracts/compatibility.md).

Stdlib only. Run from the repository root:
    python3 scripts/test-build-archive.py
Requirements: git, the release binaries (canter plus the pre-rename alias,
built with `cargo build --release --locked` when absent), and a clean
tracked worktree at a fixed HEAD. Never touches the network.
"""

from __future__ import annotations

import gzip
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUILDER = os.path.join(REPO, "scripts", "build-archive.py")

# The pre-rename alias binary member every release archive must ship next to
# `canter` (docs/contracts/compatibility.md, "Product rename (issue #106)").
# This single occurrence is a deliberate legacy mention pinned by
# tests/rename_sweep.rs.
LEGACY_ALIAS = "herdr-fleet"


def _load_builder():
    """Import the builder under test — single source for its member list."""
    spec = importlib.util.spec_from_file_location("hf_build_archive", BUILDER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


builder = _load_builder()


def run(argv, cwd=None, check=True):
    proc = subprocess.run(argv, cwd=cwd, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, check=False)
    if check and proc.returncode != 0:
        raise AssertionError(
            f"command failed (exit {proc.returncode}): {' '.join(argv)}\n"
            + proc.stdout.decode("utf-8", "replace") + "\n"
            + proc.stderr.decode("utf-8", "replace"))
    return proc


def ensure_release_binary():
    binary = os.path.join(REPO, "target", "release", "canter")
    alias = os.path.join(REPO, "target", "release", LEGACY_ALIAS)
    if not os.path.isfile(binary) or not os.path.isfile(alias):
        proc = run(["cargo", "build", "--release", "--locked"], cwd=REPO)
        if proc.returncode != 0:
            raise AssertionError("could not build the release binaries")
    return binary


def clean_worktree_check():
    proc = run(["git", "status", "--porcelain"], cwd=REPO)
    dirty = [line for line in proc.stdout.decode().splitlines()
             if not line.startswith("??")]
    if dirty:
        raise AssertionError(
            "test-build-archive.py requires a clean tracked worktree "
            f"(the builder enforces this); dirty lines:\n{chr(10).join(dirty)}")


def head_of(repo):
    return run(["git", "rev-parse", "HEAD"], cwd=repo).stdout.decode().strip()


def checks():
    binary = ensure_release_binary()
    clean_worktree_check()
    source_ref = head_of(REPO)

    with tempfile.TemporaryDirectory(prefix="hf-test-archive-") as tmp:
        out_dir = os.path.join(tmp, "out")
        os.makedirs(out_dir)

        # --- failure modes bite -------------------------------------------------
        wrong_ref = "0" * 40
        proc = run([sys.executable, BUILDER, "build", "--repo", REPO,
                    "--source-ref", wrong_ref, "--version", "0.1.0",
                    "--binary", binary, "--platform", "linux-x86_64",
                    "--out-dir", out_dir], check=False)
        assert proc.returncode != 0, "wrong source ref must fail"
        assert b"HEAD" in proc.stderr, "wrong-ref failure must name the mismatch"

        proc = run([sys.executable, BUILDER, "build", "--repo", REPO,
                    "--source-ref", source_ref, "--version", "9.9.9",
                    "--binary", binary, "--platform", "linux-x86_64",
                    "--out-dir", out_dir], check=False)
        assert proc.returncode != 0, "version mismatch with the binary must fail"
        assert b"binary reports version" in proc.stderr

        proc = run([sys.executable, BUILDER, "build", "--repo", REPO,
                    "--source-ref", source_ref, "--version", "0.1.0",
                    "--binary", binary, "--platform", "windows-x86_64",
                    "--out-dir", out_dir], check=False)
        assert proc.returncode != 0, "unknown platform must fail"
        print(f"PASS: builder failure modes bite ({len(os.listdir(out_dir))} "
              "artifacts produced before failure)")

        # --- verify refuses a crafted traversal member (safety hardening) -------
        # A malicious archive whose member basenames match the documented
        # layout but whose paths escape the extraction directory must be
        # refused by verify (tarfile extractall runs with filter='data').
        malicious = os.path.join(tmp, "canter-0.1.0-linux-x86_64.tar.gz")
        # The fixture must pass the layout check so the refusal provably comes
        # from the traversal path, not from a missing member: take every
        # documented member except `canter` (which the traversal member
        # reports as its basename) off the builder's own member list.
        benign_names = [name for name in builder.ARCHIVE_MEMBERS
                        if name != "canter"]
        with open(malicious, "wb") as raw:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw,
                               mtime=0) as gz:
                with tarfile.open(fileobj=gz, mode="w",
                                  format=tarfile.GNU_FORMAT) as tar:
                    for name in benign_names:
                        info = tarfile.TarInfo("canter-0.1.0/" + name)
                        info.size = 0
                        info.mtime = 0
                        info.uid = 0
                        info.gid = 0
                        tar.addfile(info)
                    # Traversal member: same basename as the documented
                    # executable, path escapes the extraction directory.
                    evil = tarfile.TarInfo(
                        "canter-0.1.0/../../../canter")
                    evil.size = 0
                    evil.mtime = 0
                    evil.uid = 0
                    evil.gid = 0
                    tar.addfile(evil)
        refused = run([sys.executable, BUILDER, "verify",
                       "--archive", malicious], check=False)
        assert refused.returncode != 0, (
            "verify must refuse an archive with a traversal member")
        assert b"FAIL" in refused.stderr, refused.stderr.decode()
        print("PASS: verify refuses a crafted traversal member "
              "(extractall filter='data')")

        # --- real end-to-end build + verify -------------------------------------
        build_args = [sys.executable, BUILDER, "build", "--repo", REPO,
                      "--source-ref", source_ref, "--version", "0.1.0",
                      "--binary", binary, "--platform", "linux-x86_64",
                      "--out-dir", out_dir]
        first = run(build_args)
        assert first.returncode == 0, first.stderr.decode()
        archive = os.path.join(out_dir, "canter-0.1.0-linux-x86_64.tar.gz")
        assert os.path.isfile(archive)
        assert os.path.isfile(archive + ".sha256")

        verify = run([sys.executable, BUILDER, "verify", "--archive", archive])
        assert verify.returncode == 0, verify.stderr.decode()
        out_text = verify.stdout.decode()
        assert out_text.count("OK:") == 6, out_text
        assert "6 checks passed" in out_text, out_text
        print("PASS: archive verifies against its provenance record "
              "(6 checks)")

        # --- the pre-rename alias ships as a wired, executable member ----------
        # The compatibility contract promises the alias binary is shipped next
        # to `canter`; these witnesses fail if the member is missing, loses
        # its executable framing, or drops out of SHA256SUMS/provenance.files.
        with tarfile.open(archive, "r:gz") as tar:
            members = {os.path.basename(member.name): member
                       for member in tar.getmembers() if member.isfile()}
            expected = sorted(builder.ARCHIVE_MEMBERS)
            assert sorted(members) == expected, sorted(members)
            assert LEGACY_ALIAS in members, sorted(members)
            alias_member = members[LEGACY_ALIAS]
            assert alias_member.mode == 0o755, oct(alias_member.mode)
            alias_digest = hashlib.sha256(
                tar.extractfile(alias_member).read()).hexdigest()
            sums_text = tar.extractfile(members["SHA256SUMS"]).read().decode()
            provenance_text = tar.extractfile(
                members["provenance.json"]).read().decode()
        sums = {}
        for line in sums_text.splitlines():
            digest, _, name = line.partition("  ")
            sums[name] = digest
        provenance_files = json.loads(provenance_text)["files"]
        assert sums.get(LEGACY_ALIAS) == alias_digest, sums
        assert provenance_files.get(LEGACY_ALIAS) == alias_digest, (
            provenance_files)
        print(f"PASS: archive ships the {LEGACY_ALIAS} alias member (755) "
              "wired into SHA256SUMS and provenance.files")

        # --- provenance maps to source + schema facts ---------------------------
        with tarfile.open(archive, "r:gz") as tar:
            provenance_data = None
            for member in tar.getmembers():
                if member.name.endswith("provenance.json"):
                    provenance_data = json.loads(tar.extractfile(member).read())
            assert provenance_data is not None, "provenance.json missing"
        assert provenance_data["record"] == "release-provenance/v1"
        assert provenance_data["source"]["ref"] == source_ref
        assert provenance_data["version"] == "0.1.0"
        assert provenance_data["platform"] == "linux-x86_64"
        schema_facts = provenance_data["schema_facts"]
        assert schema_facts["state_schema_version"] == 13
        assert schema_facts["migration_chain"][0] == "m0001_initial_state_v1"
        assert schema_facts["migration_chain"][-1] == "m0013_supervision_retirement_v13"
        assert "hf-config/v1" in schema_facts["document_schema_families"]
        assert "hf-schedule/v1" in schema_facts["document_schema_families"]
        assert "hf-board/v1" in schema_facts["document_schema_families"]
        assert len(schema_facts["document_schema_families"]) == 18
        print("PASS: provenance binds source ref, state schema v13, migration "
              "chain m0001..m0013, and all 18 document schema families")

        # --- SBOM mirrors Cargo.lock (offline) ----------------------------------
        with tarfile.open(archive, "r:gz") as tar:
            sbom_data = None
            for member in tar.getmembers():
                if member.name.endswith("SBOM.spdx.json"):
                    sbom_data = json.loads(tar.extractfile(member).read())
        assert sbom_data is not None, "SBOM missing"
        assert sbom_data["spdxVersion"] == "SPDX-2.3"
        # Reuse the builder's own Cargo.lock parser (single source of truth).
        lock_text = open(os.path.join(REPO, "Cargo.lock"),
                         encoding="utf-8").read()
        packages = {p["name"]: p.get("version", "")
                    for p in builder.parse_lockfile_packages(lock_text)}
        sbom_names = {p["name"]: p.get("versionInfo")
                      for p in sbom_data["packages"]}
        assert "canter" in sbom_names and sbom_names["canter"] == "0.1.0"
        # Every dependency in Cargo.lock appears once with its version; the
        # SBOM's root package entry corresponds to Cargo.lock's own
        # canter entry (same name/version), so counts are equal.
        for name, version in packages.items():
            assert sbom_names.get(name) == version, (
                f"SBOM must mirror Cargo.lock for {name}@{version}")
        assert len(sbom_names) == len(packages), (
            "SBOM package count must equal Cargo.lock packages "
            "(root entry covers Cargo.lock's own canter row)")
        print(f"PASS: SBOM mirrors Cargo.lock offline ({len(packages)} "
              "packages incl. root)")

        # --- deterministic metadata + archive framing ---------------------------
        second_out = os.path.join(tmp, "out2")
        os.makedirs(second_out)
        second = run(build_args + ["--out-dir", second_out])
        assert second.returncode == 0, second.stderr.decode()
        archive2 = os.path.join(second_out, "canter-0.1.0-linux-x86_64.tar.gz")

        def file_sha(path):
            digest = hashlib.sha256()
            with open(path, "rb") as handle:
                for chunk in iter(lambda: handle.read(1 << 20), b""):
                    digest.update(chunk)
            return digest.hexdigest()

        assert file_sha(archive) == file_sha(archive2), (
            "two builds from identical inputs must produce byte-identical "
            "archives (fixed mtimes + gzip framing)")
        print("PASS: two builds with identical inputs produce byte-identical "
              "archives")

        # --- verification instructions are executable ---------------------------
        verify2 = run([sys.executable, BUILDER, "verify",
                       "--archive", archive2])
        assert verify2.returncode == 0
        print("PASS: verification of the second build also passes")

    print("test-build-archive.py: all checks passed")


if __name__ == "__main__":
    try:
        checks()
    except AssertionError as exc:
        sys.stderr.write(f"FAIL: {exc}\n")
        sys.exit(1)
