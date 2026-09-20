#!/usr/bin/env python3
"""test-check-public-tree.py — positive/negative self-tests for the scanner.

Every test builds a TEMPORARY real git repository (git init in a tempfile
dir), commits the fixture files, runs scripts/check-public-tree.py against
it, and asserts the raw exit code and reported rule id. Fixture contents are
assembled at runtime so this file's own source never trips the rules.

Run: python3 scripts/test-check-public-tree.py   (also runs in CI policy job)
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCANNER = os.path.join(HERE, "check-public-tree.py")
# Scratch repositories are never initialised from the host's shared git
# template directory (issue #226): that copy belongs to the machine and fails
# intermittently under CI. An empty template directory copies nothing.
GIT_TEMPLATE_ENV = dict(os.environ, GIT_TEMPLATE_DIR="")


def _build_abs_unix_path() -> str:
    """A machine-local absolute path, assembled to avoid self-matching."""
    slash = chr(47)  # "/"
    return slash + "Users" + slash + "jirathip" + slash + "secret.txt"


def _build_abs_home_path() -> str:
    slash = chr(47)
    return slash + "home" + slash + "alice" + slash + "notes.txt"


def _build_abs_windows_path() -> str:
    bs = chr(92)  # "\"
    return "C:" + bs + "Users" + bs + "alice" + bs + "secret.txt"


def _build_pem() -> str:
    begin = "-----BEGIN "
    end = "-----END "
    algo = "RSA "
    key_marker = "PRIVATE KEY-----"
    return (
        begin + algo + key_marker + "\n"
        "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ"
        "\n"
        + end + algo + key_marker + "\n"
    )


def _build_github_token() -> str:
    return "ghp_" + "A" * 36


def _build_aws_key() -> str:
    return "AKIA" + "B" * 16


def _build_slack_token() -> str:
    return "xoxb-" + "C" * 24


def _build_openai_key() -> str:
    return "sk-" + "D" * 24


def _run_scanner(repo_dir: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, SCANNER, "."],
        cwd=repo_dir,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


class ScannerFixtureTest(unittest.TestCase):
    """Base: a temporary git repository with committed fixture files."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="hf-public-tree-test-")
        self.repo = self._tmp.name
        subprocess.run(["git", "init", "-q", self.repo], check=True, env=GIT_TEMPLATE_ENV)
        subprocess.run(
            ["git", "-C", self.repo, "config", "user.email", "test@example.invalid"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", self.repo, "config", "user.name", "Scanner Self Test"],
            check=True,
        )

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def commit_files(self, files: dict[str, str]) -> None:
        for relpath, content in files.items():
            path = os.path.join(self.repo, relpath)
            os.makedirs(os.path.dirname(path) or self.repo, exist_ok=True)
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(content)
        subprocess.run(["git", "-C", self.repo, "add", "-A"], check=True)
        subprocess.run(
            ["git", "-C", self.repo, "commit", "-q", "-m", "fixture"],
            check=True,
        )

    def assert_clean(self) -> None:
        proc = _run_scanner(self.repo)
        self.assertEqual(
            proc.returncode,
            0,
            "expected a clean scan, exit 0; got {}: stdout={!r} stderr={!r}".format(
                proc.returncode, proc.stdout, proc.stderr
            ),
        )

    def assert_violation(self, rule_id: str, path_hint: str) -> None:
        proc = _run_scanner(self.repo)
        self.assertEqual(proc.returncode, 1, "expected exit 1; stderr={!r}".format(proc.stderr))
        stdout = proc.stdout.decode("utf-8", "replace")
        self.assertIn(rule_id, stdout, "expected rule {} in {!r}".format(rule_id, stdout))
        self.assertIn(path_hint, stdout, "expected path {} in {!r}".format(path_hint, stdout))


class FilenameRuleTests(ScannerFixtureTest):
    def test_tracked_dotenv_file_is_rejected(self) -> None:
        self.commit_files({".env": "FOO=bar\n"})
        self.assert_violation("RULE-CRED-FILENAME-ENV", ".env")

    def test_tracked_dotenv_variant_is_rejected(self) -> None:
        self.commit_files({"config/.env.local": "FOO=bar\n"})
        self.assert_violation("RULE-CRED-FILENAME-ENV", "config/.env.local")

    def test_tracked_pem_file_is_rejected(self) -> None:
        self.commit_files({"keys/prod.pem": "synthetic\n"})
        self.assert_violation("RULE-CRED-FILENAME-KEY", "keys/prod.pem")

    def test_tracked_p8_and_key_extensions_are_rejected(self) -> None:
        self.commit_files({"a.p8": "x\n", "b.key": "x\n", "c.mobileprovision": "x\n"})
        proc = _run_scanner(self.repo)
        self.assertEqual(proc.returncode, 1)
        stdout = proc.stdout.decode("utf-8", "replace")
        self.assertEqual(stdout.count("RULE-CRED-FILENAME-KEY"), 3)

    def test_tracked_id_rsa_basename_is_rejected(self) -> None:
        self.commit_files({"secrets/id_rsa": "synthetic\n"})
        self.assert_violation("RULE-CRED-FILENAME-KEY", "secrets/id_rsa")

    def test_empty_dotenv_example_is_permitted(self) -> None:
        self.commit_files({".env.example": ""})
        self.assert_clean()

    def test_synthetic_dotenv_example_is_permitted(self) -> None:
        self.commit_files({".env.example": "DATABASE_URL=postgres://user:pass@db.example/app\n"})
        self.assert_clean()

    def test_pem_example_suffix_is_permitted(self) -> None:
        self.commit_files({"certs/example.pem.example": "synthetic\n"})
        self.assert_clean()


class ContentRuleTests(ScannerFixtureTest):
    def test_unix_absolute_path_is_rejected(self) -> None:
        self.commit_files({"notes.md": "todo: see " + _build_abs_unix_path() + "\n"})
        self.assert_violation("RULE-ABS-PATH-UNIX", "notes.md")

    def test_home_absolute_path_is_rejected(self) -> None:
        self.commit_files({"notes.md": "todo: see " + _build_abs_home_path() + "\n"})
        self.assert_violation("RULE-ABS-PATH-UNIX", "notes.md")

    def test_windows_absolute_path_is_rejected(self) -> None:
        self.commit_files({"notes.md": "todo: see " + _build_abs_windows_path() + "\n"})
        self.assert_violation("RULE-ABS-PATH-WINDOWS", "notes.md")

    def test_pem_private_key_content_is_rejected(self) -> None:
        self.commit_files({"notes.md": _build_pem()})
        self.assert_violation("RULE-PEM-PRIVATE-KEY", "notes.md")

    def test_github_token_content_is_rejected(self) -> None:
        self.commit_files({"notes.md": "token=" + _build_github_token() + "\n"})
        self.assert_violation("RULE-GITHUB-TOKEN", "notes.md")

    def test_aws_access_key_content_is_rejected(self) -> None:
        self.commit_files({"notes.md": "key=" + _build_aws_key() + "\n"})
        self.assert_violation("RULE-AWS-ACCESS-KEY", "notes.md")

    def test_slack_token_content_is_rejected(self) -> None:
        self.commit_files({"notes.md": "token=" + _build_slack_token() + "\n"})
        self.assert_violation("RULE-SLACK-TOKEN", "notes.md")

    def test_openai_key_content_is_rejected(self) -> None:
        self.commit_files({"notes.md": "key=" + _build_openai_key() + "\n"})
        self.assert_violation("RULE-OPENAI-API-KEY", "notes.md")


class CleanFixtureTests(ScannerFixtureTest):
    def test_clean_tree_with_public_urls_passes(self) -> None:
        self.commit_files(
            {
                "README.md": "# demo\nSee https://github.com/jirathip-dev/canter for info.\n",
                "src/lib.rs": "pub fn hello() -> &'static str { \"world\" }\n",
            }
        )
        self.assert_clean()

    def test_binary_content_is_not_text_scanned(self) -> None:
        # Token-shaped bytes inside a binary extension must not trip content
        # rules; filename rules still apply to tracked names.
        png_head = b"\x89PNG\r\n\x1a\n"
        self.commit_files(
            {
                "assets/logo.png": (png_head + b"ghp_" + b"A" * 36).decode("latin-1"),
            }
        )
        self.assert_clean()

    def test_working_tree_modification_does_not_change_the_scan(self) -> None:
        # Scanner reads the INDEX, so an uncommitted local secret must not be
        # scanned (and an uncommitted removal must not hide a committed one).
        self.commit_files({"ok.md": "clean\n"})
        secret = _build_github_token()
        with open(os.path.join(self.repo, "ok.md"), "w", encoding="utf-8") as handle:
            handle.write("local only " + secret + "\n")
        self.assert_clean()


class OperationalTests(unittest.TestCase):
    def test_non_repository_directory_fails_loudly(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hf-public-tree-nonrepo-") as tmp:
            proc = _run_scanner(tmp)
        self.assertEqual(proc.returncode, 3, "expected exit 3, got {}".format(proc.returncode))
        self.assertIn(b"ERROR", proc.stderr)

    def test_empty_tracked_tree_is_never_clean(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hf-public-tree-empty-") as tmp:
            subprocess.run(["git", "init", "-q", tmp], check=True, env=GIT_TEMPLATE_ENV)
            proc = _run_scanner(tmp)
        self.assertEqual(proc.returncode, 3, "expected exit 3, got {}".format(proc.returncode))


if __name__ == "__main__":
    unittest.main(verbosity=2)
