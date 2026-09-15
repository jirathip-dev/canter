#!/usr/bin/env python3
"""check-contract-fixtures.py — fail-closed validator for contract fixtures.

Validates the synthetic fixture corpus under schemas/fixtures against the
schema rules defined in this module, using the expectation manifest
(schemas/fixtures/manifest.jsonl). Deterministic and stdlib-only.

The rules here ARE the machine-readable half of the contract; the
human-readable half lives in docs/contracts/schema-registry.md and the
per-surface spec documents. scripts/test-check-contract-fixtures.py proves
the validators actually bite (tamper discrimination), and its registry
cross-check keeps this module, the manifest, and schema-registry.md from
drifting apart.

Result codes returned by validators (first element of each tuple):
  accept              — document is valid for its family
  refuse-parse        — bytes do not parse (JSON/TOML/JSONL)
  refuse-schema       — schema identifier is missing or names another family
  refuse-version      — family is known but the version is not supported
  refuse-malformed    — structurally invalid for the family rules
  refuse-noncanonical — bytes are not the canonical serialization

Exit codes:
  0 — every manifest expectation held
  1 — one or more expectations failed
  2 — usage error
  3 — operational error (missing manifest/fixture, internal rule error)
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - python < 3.11
    print("check-contract-fixtures: ERROR: tomllib requires python 3.11+", file=sys.stderr)
    sys.exit(3)

ACCEPT = "accept"
REFUSE_PARSE = "refuse-parse"
REFUSE_SCHEMA = "refuse-schema"
REFUSE_VERSION = "refuse-version"
REFUSE_MALFORMED = "refuse-malformed"
REFUSE_NONCANONICAL = "refuse-noncanonical"
REFUSE_CODES = frozenset(
    {REFUSE_PARSE, REFUSE_SCHEMA, REFUSE_VERSION, REFUSE_MALFORMED, REFUSE_NONCANONICAL}
)

# ---------------------------------------------------------------------------
# Shared format rules (mirrored in docs/contracts/spec-cli.md "identities")
# ---------------------------------------------------------------------------

RX_RFC3339_Z = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
RX_HEX64 = re.compile(r"^[0-9a-f]{64}$")
RX_HEX40 = re.compile(r"^[0-9a-f]{40}$")
RX_HEX_ID = re.compile(r"^[a-f0-9]{8,64}$")          # daemon request id
RX_REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")  # owner/name
RX_PLAN_ID = re.compile(r"^hf_plan_[0-9a-f]{16}$")
RX_GRANT_ID = re.compile(r"^gr_[0-9a-f]{16}$")
RX_SCHEDULE_ID = re.compile(r"^sd_[0-9a-f]{16}$")
RX_EVIDENCE_ID = re.compile(r"^ev_[0-9a-f]{16}$")
RX_WORK_ITEM_ID = re.compile(r"^wi_[0-9a-f]{16}$")
RX_IDEMPOTENCY_KEY = re.compile(r"^ik_[a-z0-9-]{8,64}$")
RX_SLUG_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
RX_ACTION = re.compile(r"^[a-z][a-z0-9_.-]*$")
RX_ACTOR = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
RX_MIGRATION_ID = re.compile(r"^m[0-9]{4}_[a-z0-9_]+$")
RX_ERROR_CODE = re.compile(r"^[a-z][a-z0-9_.-]*$")

PLAN_STEP_KINDS = frozenset(
    {"checkout", "worktree_create", "harness_start", "prompt",
     "collect_outcome", "review_evidence", "merge", "cleanup", "publish"}
)
GRANT_PHASES = frozenset(
    {"plan", "read", "worktree", "spawn", "review", "merge",
     "production", "cleanup", "recovery"}
)
GRANT_CAPS = frozenset(
    {"read", "worktree", "spawn", "prompt", "review", "merge",
     "production", "cleanup", "release"}
)
WORKFLOW_NODE_KINDS = frozenset(
    {"start", "plan", "orchestrator", "implementer", "reviewer",
     "gate", "human_approval", "merge", "terminal"}
)
RPC_METHODS = frozenset(
    {"capabilities", "doctor", "status", "plan", "apply",
     "grants.issue", "grants.list",
     "grants.revoke", "schedules.list", "schedules.create", "schedules.pause",
     "schedules.resume", "schedules.delete", "schedules.evaluate",
     "lane.replacement.request", "lane.replacement.advance",
     "lane.replacement.hold", "lane.replacement.cancel",
     "lane.replacement.status",
     "lane.checkpoint.create", "lane.checkpoint.status",
     "lane.retire",
     "lane.start", "lane.adopt", "lane.successor.consume",
     "state.epoch", "queue.submit", "queue.status",
     "run.pause", "run.resume", "run.retry", "run.release", "run.resolve", "run.dispatch", "run.status",
     "supervision.status",
     "backup.create", "restore.begin", "journal.tail",
     "events.subscribe"}
)
EVENT_KINDS = frozenset(
    {"state.snapshot", "agent.updated", "plan.updated", "grant.updated",
     "journal.appended", "epoch.rotated", "schedule.ran"}
)
HARNESS_CAPS = frozenset({"discover", "start", "prompt", "observe",
                          "interrupt", "outcome", "identity"})
FORGE_CAPS = frozenset({"read_refs", "read_issues", "read_checks",
                        "create_pr", "comment"})
# hf-board/v1 (issue #83 read model): closed sets mirrored in src/schema.rs.
BOARD_STAGES = frozenset({"planned", "in_progress", "needs_attention", "verified"})
BOARD_VERIFICATIONS = frozenset({"none", "failed", "passed"})
BOARD_RUN_STATES = frozenset({"new", "running", "paused", "human_queue",
                              "blocked", "done", "invalidated"})
BOARD_NEXT_ACTIONS = frozenset({"resume", "human_decision"})
BOARD_SOURCE_KINDS = frozenset({"github"})
BOARD_EVIDENCE_REF_MAX = 4


def canon_json_bytes(obj) -> bytes:
    """Canonical JSON bytes: sorted keys, compact separators, ASCII escapes,
    single trailing LF. Mirrors docs/contracts/spec-plans.md and
    docs/contracts/spec-workflow.md (canonical serialization rule)."""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8") + b"\n"


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _ref(code: str, msg: str) -> tuple[str, str]:
    return (code, msg)


def _type_check(value, expected: type, what: str, allow_none: bool = False):
    if value is None and allow_none:
        return None
    if not isinstance(value, expected):
        raise ValueError("{} must be {}".format(what, expected.__name__))


def check_schema(obj: dict, family: str, version: str = "1") -> tuple[str, str]:
    """Verify the top-level `schema` identifier. The id encodes the family
    AND the version (e.g. "hf-plan/v1"), so an unsupported version is
    distinguishable from an unknown family."""
    schema_id = "{}/v{}".format(family, version)
    value = obj.get("schema")
    if value == schema_id:
        return _ref(ACCEPT, "schema ok")
    if isinstance(value, str) and value.startswith(family + "/v"):
        return _ref(REFUSE_VERSION, "unsupported version {!r} for {}".format(value, family))
    return _ref(REFUSE_SCHEMA, "missing or foreign schema identifier {!r}".format(value))


def _require_keys(obj: dict, required, allowed, where: str) -> tuple[str, str] | None:
    for key in required:
        if key not in obj:
            return _ref(REFUSE_MALFORMED, "{}: missing required key {!r}".format(where, key))
    for key in obj:
        if key not in allowed:
            return _ref(REFUSE_MALFORMED, "{}: unknown key {!r}".format(where, key))
    return None


def _expect_str(obj: dict, key: str, where: str, rx=None) -> tuple[str, str] | None:
    value = obj.get(key)
    if not isinstance(value, str) or not value:
        return _ref(REFUSE_MALFORMED, "{}: {!r} must be a non-empty string".format(where, key))
    if rx is not None and not rx.match(value):
        return _ref(REFUSE_MALFORMED, "{}: {!r} fails its format rule".format(where, key))
    return None


def _expect_int(obj: dict, key: str, where: str, minimum: int = 0) -> tuple[str, str] | None:
    value = obj.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        return _ref(REFUSE_MALFORMED,
                    "{}: {!r} must be an integer >= {}".format(where, key, minimum))
    return None


def _expect_timestamp(obj: dict, key: str, where: str) -> tuple[str, str] | None:
    value = obj.get(key)
    if not isinstance(value, str) or not RX_RFC3339_Z.match(value):
        return _ref(REFUSE_MALFORMED, "{}: {!r} must be RFC3339 UTC (seconds, Z)".format(where, key))
    return None


def _expect_object(obj: dict, key: str, where: str, allow_none: bool = False) -> tuple[str, str] | None:
    value = obj.get(key)
    if value is None and allow_none:
        return None
    if not isinstance(value, dict):
        return _ref(REFUSE_MALFORMED, "{}: {!r} must be an object".format(where, key))
    return None


def _expect_in(obj: dict, key: str, where: str, closed_set) -> tuple[str, str] | None:
    value = obj.get(key)
    if value not in closed_set:
        return _ref(REFUSE_MALFORMED,
                    "{}: {!r} must be one of the closed set {}".format(where, key,
                                                                      sorted(closed_set)))
    return None


def _json_obj(obj: dict, family: str, required, allowed) -> tuple[str, str] | None:
    err = check_schema(obj, family)
    if err[0] != ACCEPT:
        return err
    return _require_keys(obj, required, allowed, family)


def _err_shaped(value) -> tuple[str, str] | None:
    """Minimal embedded error shape {code, message} used by output/response/outcome."""
    if not isinstance(value, dict):
        return _ref(REFUSE_MALFORMED, "embedded error must be an object")
    if not isinstance(value.get("code"), str) or not RX_ERROR_CODE.match(value.get("code", "")):
        return _ref(REFUSE_MALFORMED, "embedded error code invalid")
    if not isinstance(value.get("message"), str) or not value.get("message"):
        return _ref(REFUSE_MALFORMED, "embedded error message must be non-empty")
    return _ref(ACCEPT, "embedded error ok")


def _issue_shaped(value) -> tuple[str, str] | None:
    """Issue binding: exact issue number + acceptance revision (hex40)."""
    if not isinstance(value, dict):
        return _ref(REFUSE_MALFORMED, "issue must be an object")
    number = value.get("number")
    if isinstance(number, bool) or not isinstance(number, int) or number <= 0:
        return _ref(REFUSE_MALFORMED, "issue.number must be a positive integer")
    if not isinstance(value.get("revision"), str) or not RX_HEX40.match(value.get("revision", "")):
        return _ref(REFUSE_MALFORMED, "issue.revision must be a 40-hex acceptance revision")
    return None


# ---------------------------------------------------------------------------
# Per-family validators. Every validator returns (code, message). The rule
# sets below are normative: docs/contracts/*.md must not contradict them.
# ---------------------------------------------------------------------------

def validate_config(obj: dict) -> tuple[str, str]:
    err = _json_obj(obj, "hf-config", {"schema"}, {"schema", "daemon", "policy",
                                                   "repository", "harness", "workflow", "role"})
    if err:
        return err
    for key in ("daemon", "policy"):
        if key in obj:
            if not isinstance(obj[key], dict):
                return _ref(REFUSE_MALFORMED, "config: {} must be a table".format(key))
    if "daemon" in obj:
        if _require_keys(obj["daemon"], set(), {"enabled", "socket"}, "config.daemon"):
            return _ref(REFUSE_MALFORMED, "config.daemon: unknown key")
        if "enabled" in obj["daemon"] and not isinstance(obj["daemon"]["enabled"], bool):
            return _ref(REFUSE_MALFORMED, "config.daemon.enabled must be a boolean")
        if "socket" in obj["daemon"] and not isinstance(obj["daemon"]["socket"], str):
            return _ref(REFUSE_MALFORMED, "config.daemon.socket must be a string")
    if "policy" in obj:
        if not isinstance(obj["policy"].get("overlay"), str) or not obj["policy"]["overlay"]:
            return _ref(REFUSE_MALFORMED, "config.policy.overlay must be a non-empty string")
        if set(obj["policy"]) != {"overlay"}:
            return _ref(REFUSE_MALFORMED, "config.policy: unknown key")
    if "repository" in obj:
        if not isinstance(obj["repository"], dict):
            return _ref(REFUSE_MALFORMED, "config.repository must be a table")
        for name, entry in obj["repository"].items():
            if not RX_SLUG_ID.match(name):
                return _ref(REFUSE_MALFORMED, "config.repository key {!r} invalid".format(name))
            if not isinstance(entry, dict):
                return _ref(REFUSE_MALFORMED, "config.repository.{} must be a table".format(name))
            if _require_keys(entry, {"origin"}, {"origin", "branch", "enabled"}, "repository." + name):
                return _ref(REFUSE_MALFORMED, "config.repository.{}: bad keys".format(name))
            if not isinstance(entry.get("origin"), str):
                return _ref(REFUSE_MALFORMED, "config.repository.{}.origin must be a string".format(name))
    if "harness" in obj:
        if not isinstance(obj["harness"], dict):
            return _ref(REFUSE_MALFORMED, "config.harness must be a table")
        for name, entry in obj["harness"].items():
            shape = {"kind", "executable", "env_allow", "provider", "model",
                     "fallback", "secret_env", "limits", "binding_introspection"}
            required = {"kind", "executable", "env_allow"}
            if (
                not isinstance(entry, dict)
                or not required.issubset(entry)
                or not set(entry) <= shape
            ):
                return _ref(REFUSE_MALFORMED, "config.harness.{}: bad shape".format(name))
            if not isinstance(entry["kind"], str) or not isinstance(entry["executable"], str):
                return _ref(REFUSE_MALFORMED, "config.harness.{}: kind/executable strings".format(name))
            # Optional provider/model binding pair (issue #80): the document
            # carries strings; bare-token and both-or-neither validation is
            # the decoder's (config.rs) rule.
            for key in ("provider", "model"):
                if key in entry and not isinstance(entry[key], str):
                    return _ref(REFUSE_MALFORMED,
                                "config.harness.{}.{} must be a string".format(name, key))
            # Optional issue #77 profile-planning keys: shape only here
            # (bare-token pairs, allowlisted credential names and bounded
            # limits are the decoder's rules).
            for key in ("fallback", "secret_env"):
                if key in entry and (
                    not isinstance(entry[key], list)
                    or not all(isinstance(item, str) for item in entry[key])
                ):
                    return _ref(REFUSE_MALFORMED,
                                "config.harness.{}.{} must be [string]".format(name, key))
            if "limits" in entry and (
                not isinstance(entry["limits"], dict)
                or not all(isinstance(item, (str, int)) for item in entry["limits"].values())
            ):
                return _ref(REFUSE_MALFORMED,
                            "config.harness.{}.limits must be scalar values".format(name))
            if "binding_introspection" in entry and not isinstance(entry["binding_introspection"], bool):
                return _ref(REFUSE_MALFORMED,
                            "config.harness.{}.binding_introspection must be a boolean".format(name))
            env_allow = entry["env_allow"]
            if not isinstance(env_allow, list) or not all(
                isinstance(item, str) for item in env_allow
            ):
                return _ref(REFUSE_MALFORMED, "config.harness.{}.env_allow must be [string]".format(name))
    for table, allowed in (("workflow", {"id", "hash"}), ("role", {"hash"})):
        if table in obj:
            if not isinstance(obj[table], dict):
                return _ref(REFUSE_MALFORMED, "config.{} must be a table".format(table))
            for name, entry in obj[table].items():
                if not isinstance(entry, dict) or set(entry) != allowed:
                    return _ref(REFUSE_MALFORMED, "config.{}.{}: bad shape".format(table, name))
                for key in allowed:
                    if key == "hash":
                        if not isinstance(entry[key], str) or not RX_HEX64.match(entry[key]):
                            return _ref(REFUSE_MALFORMED,
                                        "config.{}.{}.hash must be 64-hex".format(table, name))
                    elif not isinstance(entry[key], str) or not entry[key]:
                        return _ref(REFUSE_MALFORMED,
                                    "config.{}.{}.id must be non-empty".format(table, name))
    return _ref(ACCEPT, "config ok")


def validate_policy(obj: dict) -> tuple[str, str]:
    err = _json_obj(obj, "hf-policy", {"schema"},
                    {"schema", "repositories", "production_confirmation", "role"})
    if err:
        return err
    present = [key for key in ("repositories", "production_confirmation", "role") if key in obj]
    if not present:
        return _ref(REFUSE_MALFORMED, "policy: overlay must constrain at least one axis")
    if "repositories" in obj:
        repos = obj["repositories"]
        if not isinstance(repos, list) or not repos or not all(
            isinstance(item, str) and RX_REPOSITORY.match(item) for item in repos
        ):
            return _ref(REFUSE_MALFORMED, "policy.repositories must be a non-empty [owner/name]")
    if "production_confirmation" in obj and obj["production_confirmation"] not in {"tty", "deny"}:
        return _ref(REFUSE_MALFORMED,
                    "policy.production_confirmation must be one of tty|deny (overlay may only tighten)")
    if "role" in obj:
        if not isinstance(obj["role"], dict):
            return _ref(REFUSE_MALFORMED, "policy.role must be a table")
        for name, entry in obj["role"].items():
            if not isinstance(entry, dict) or set(entry) != {"hash"}:
                return _ref(REFUSE_MALFORMED, "policy.role.{}: bad shape".format(name))
            if not isinstance(entry["hash"], str) or not RX_HEX64.match(entry["hash"]):
                return _ref(REFUSE_MALFORMED, "policy.role.{}.hash must be 64-hex".format(name))
    return _ref(ACCEPT, "policy ok")


def validate_output(obj: dict) -> tuple[str, str]:
    err = _json_obj(obj, "hf-output", {"schema", "command", "kind", "exit_code"},
                    {"schema", "command", "kind", "exit_code", "data", "error"})
    if err:
        return err
    if not isinstance(obj["command"], str) or not obj["command"]:
        return _ref(REFUSE_MALFORMED, "output.command must be non-empty")
    kind = obj["kind"]
    if kind not in {"ok", "error", "partial"}:
        return _ref(REFUSE_MALFORMED, "output.kind must be one of ok|error|partial")
    code = obj["exit_code"]
    if isinstance(code, bool) or not isinstance(code, int) or not 0 <= code <= 255:
        return _ref(REFUSE_MALFORMED, "output.exit_code must be an int in 0..=255")
    if kind == "error":
        if "error" not in obj:
            return _ref(REFUSE_MALFORMED, "output: error kind requires an error object")
        return _err_shaped(obj["error"])
    if "data" not in obj or not isinstance(obj["data"], dict):
        return _ref(REFUSE_MALFORMED, "output: ok|partial kind requires a data object")
    return _ref(ACCEPT, "output ok")


def validate_error(obj: dict) -> tuple[str, str]:
    err = _json_obj(obj, "hf-error", {"schema", "code", "message", "retryable", "details"},
                    {"schema", "code", "message", "retryable", "details"})
    if err:
        return err
    if not isinstance(obj["code"], str) or not RX_ERROR_CODE.match(obj["code"]):
        return _ref(REFUSE_MALFORMED, "error.code invalid")
    if not isinstance(obj["message"], str) or not obj["message"]:
        return _ref(REFUSE_MALFORMED, "error.message must be non-empty")
    if not isinstance(obj["retryable"], bool):
        return _ref(REFUSE_MALFORMED, "error.retryable must be a boolean")
    if obj["details"] is not None and not isinstance(obj["details"], dict):
        return _ref(REFUSE_MALFORMED, "error.details must be an object or null")
    return _ref(ACCEPT, "error ok")


def validate_observation(obj: dict) -> tuple[str, str]:
    err = _json_obj(obj, "hf-observation",
                    {"schema", "subject", "observed_at", "freshness", "completeness"},
                    {"schema", "subject", "observed_at", "freshness", "completeness", "payload"})
    if err:
        return err
    subject = obj["subject"]
    if not isinstance(subject, dict):
        return _ref(REFUSE_MALFORMED, "observation.subject must be an object")
    if subject.get("type") not in {"repository", "agent", "host"}:
        return _ref(REFUSE_MALFORMED, "observation.subject.type outside closed set")
    if not isinstance(subject.get("id"), str) or not subject["id"]:
        return _ref(REFUSE_MALFORMED, "observation.subject.id must be non-empty")
    if _expect_timestamp(obj, "observed_at", "observation"):
        return _ref(REFUSE_MALFORMED, "observation.observed_at invalid")
    if obj["freshness"] not in {"fresh", "stale", "unknown"}:
        return _ref(REFUSE_MALFORMED, "observation.freshness outside closed set")
    if obj["completeness"] not in {"complete", "partial"}:
        return _ref(REFUSE_MALFORMED, "observation.completeness outside closed set")
    return _ref(ACCEPT, "observation ok")


def validate_plan(obj: dict) -> tuple[str, str]:
    err = _json_obj(obj, "hf-plan",
                    {"schema", "plan_id", "workflow_id", "workflow_hash", "state_epoch",
                     "repository", "issue", "steps"},
                    {"schema", "plan_id", "workflow_id", "workflow_hash", "state_epoch",
                     "repository", "issue", "steps"})
    if err:
        return err
    for key, rx in (("plan_id", RX_PLAN_ID), ("workflow_id", RX_SLUG_ID)):
        if _expect_str(obj, key, "plan", rx):
            return _ref(REFUSE_MALFORMED, "plan.{} invalid".format(key))
    if not isinstance(obj["workflow_hash"], str) or not RX_HEX64.match(obj["workflow_hash"]):
        return _ref(REFUSE_MALFORMED, "plan.workflow_hash must be 64-hex")
    if _expect_int(obj, "state_epoch", "plan"):
        return _ref(REFUSE_MALFORMED, "plan.state_epoch invalid")
    if not isinstance(obj["repository"], str) or not RX_REPOSITORY.match(obj["repository"]):
        return _ref(REFUSE_MALFORMED, "plan.repository must be owner/name")
    issue_err = _issue_shaped(obj["issue"])
    if issue_err:
        return issue_err
    steps = obj["steps"]
    if not isinstance(steps, list) or not steps:
        return _ref(REFUSE_MALFORMED, "plan.steps must be a non-empty list")
    for step in steps:
        if not isinstance(step, dict):
            return _ref(REFUSE_MALFORMED, "plan step must be an object")
        if not isinstance(step.get("id"), str) or not RX_SLUG_ID.match(step.get("id", "")):
            return _ref(REFUSE_MALFORMED, "plan step id invalid")
        if step.get("kind") not in PLAN_STEP_KINDS:
            return _ref(REFUSE_MALFORMED, "plan step kind outside closed set")
        params = step.get("params")
        if params is not None and not isinstance(params, dict):
            return _ref(REFUSE_MALFORMED, "plan step params must be an object or null")
        if isinstance(params, dict) and any(not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", key) for key in params):
            return _ref(REFUSE_MALFORMED, "invalid plan step param name")
    return _ref(ACCEPT, "plan ok")


def validate_grant(obj: dict) -> tuple[str, str]:
    err = _json_obj(obj, "hf-grant",
                    {"schema", "grant_id", "repository", "issue", "workflow_hash",
                     "policy_hash", "phase", "scope", "caps", "expires_at",
                     "state_epoch", "created_at"},
                    {"schema", "grant_id", "repository", "issue", "workflow_hash",
                     "policy_hash", "phase", "scope", "caps", "expires_at",
                     "state_epoch", "created_at"})
    if err:
        return err
    if not isinstance(obj["grant_id"], str) or not RX_GRANT_ID.match(obj["grant_id"]):
        return _ref(REFUSE_MALFORMED, "grant.grant_id invalid")
    if not isinstance(obj["repository"], str) or not RX_REPOSITORY.match(obj["repository"]):
        return _ref(REFUSE_MALFORMED, "grant.repository must be owner/name")
    if _issue_shaped(obj["issue"]):
        return _ref(REFUSE_MALFORMED, "grant.issue binding invalid")
    for key in ("workflow_hash", "policy_hash"):
        if not isinstance(obj[key], str) or not RX_HEX64.match(obj[key]):
            return _ref(REFUSE_MALFORMED, "grant.{} must be 64-hex".format(key))
    if obj["phase"] not in GRANT_PHASES:
        return _ref(REFUSE_MALFORMED, "grant.phase outside closed set")
    if not isinstance(obj["scope"], str) or not obj["scope"] or len(obj["scope"]) > 256:
        return _ref(REFUSE_MALFORMED, "grant.scope must be a non-empty string <= 256 chars")
    caps = obj["caps"]
    if not isinstance(caps, list) or not caps or not all(item in GRANT_CAPS for item in caps):
        return _ref(REFUSE_MALFORMED, "grant.caps must be a non-empty subset of the closed set")
    if _expect_timestamp(obj, "expires_at", "grant"):
        return _ref(REFUSE_MALFORMED, "grant.expires_at invalid")
    if _expect_int(obj, "state_epoch", "grant"):
        return _ref(REFUSE_MALFORMED, "grant.state_epoch invalid")
    if _expect_timestamp(obj, "created_at", "grant"):
        return _ref(REFUSE_MALFORMED, "grant.created_at invalid")
    return _ref(ACCEPT, "grant ok")


def validate_schedule(obj: dict) -> tuple[str, str]:
    """hf-schedule/v1 (issue #9 lifecycle): recurring NON-DESTRUCTIVE
    cadence record. Every field mirrors the recurring-grant bindings
    (repository/issue, workflow+policy hash, phase, scope, caps, expiry)
    plus the cadence (anchor + every_secs). Schedules are closed to the
    read phase and to the single 'read' capability: a schedule document
    can never carry production/destructive effects."""
    err = _json_obj(obj, "hf-schedule",
                    {"schema", "schedule_id", "repository", "issue",
                     "workflow_hash", "policy_hash", "phase", "scope",
                     "caps", "expires_at", "anchor", "every_secs"},
                    {"schema", "schedule_id", "repository", "issue",
                     "workflow_hash", "policy_hash", "phase", "scope",
                     "caps", "expires_at", "anchor", "every_secs"})
    if err:
        return err
    if not isinstance(obj["schedule_id"], str) or not RX_SCHEDULE_ID.match(obj["schedule_id"]):
        return _ref(REFUSE_MALFORMED, "schedule.schedule_id invalid")
    if not isinstance(obj["repository"], str) or not RX_REPOSITORY.match(obj["repository"]):
        return _ref(REFUSE_MALFORMED, "schedule.repository must be owner/name")
    if _issue_shaped(obj["issue"]):
        return _ref(REFUSE_MALFORMED, "schedule.issue binding invalid")
    for key in ("workflow_hash", "policy_hash"):
        if not isinstance(obj[key], str) or not RX_HEX64.match(obj[key]):
            return _ref(REFUSE_MALFORMED, "schedule.{} must be 64-hex".format(key))
    if obj["phase"] != "read":
        return _ref(REFUSE_MALFORMED,
                    "schedule.phase must be exactly 'read' (schedules are "
                    "non-destructive and never schedulable with more)")
    if not isinstance(obj["scope"], str) or not obj["scope"] or len(obj["scope"]) > 256:
        return _ref(REFUSE_MALFORMED, "schedule.scope must be a non-empty string <= 256 chars")
    caps = obj["caps"]
    if not isinstance(caps, list) or not caps or not all(item == "read" for item in caps):
        return _ref(REFUSE_MALFORMED,
                    "schedule.caps must be exactly ['read'] (recurring grants "
                    "carry no other capability)")
    for key in ("expires_at", "anchor"):
        if _expect_timestamp(obj, key, "schedule"):
            return _ref(REFUSE_MALFORMED, "schedule.{} invalid".format(key))
    if not isinstance(obj["every_secs"], int) or obj["every_secs"] <= 0:
        return _ref(REFUSE_MALFORMED, "schedule.every_secs must be a positive integer")
    return _ref(ACCEPT, "schedule ok")


def validate_epoch(obj: dict) -> tuple[str, str]:
    err = _json_obj(obj, "hf-epoch", {"schema", "epoch", "created_at", "reason", "prior_epoch"},
                    {"schema", "epoch", "created_at", "reason", "prior_epoch"})
    if err:
        return err
    if _expect_int(obj, "epoch", "epoch"):
        return _ref(REFUSE_MALFORMED, "epoch.epoch invalid")
    if _expect_timestamp(obj, "created_at", "epoch"):
        return _ref(REFUSE_MALFORMED, "epoch.created_at invalid")
    if obj["reason"] not in {"initial", "restore", "security_rotation"}:
        return _ref(REFUSE_MALFORMED, "epoch.reason outside closed set")
    prior = obj["prior_epoch"]
    if obj["reason"] == "initial":
        if prior is not None:
            return _ref(REFUSE_MALFORMED,
                        "epoch: initial epoch must have prior_epoch null")
    elif isinstance(prior, bool) or not isinstance(prior, int) or prior < 0:
        return _ref(REFUSE_MALFORMED,
                    "epoch: rotations must reference a prior_epoch integer")
    return _ref(ACCEPT, "epoch ok")


def validate_outcome(obj: dict) -> tuple[str, str]:
    err = _json_obj(obj, "hf-outcome",
                    {"schema", "plan_id", "step_id", "status", "idempotency_key",
                     "observed_at", "result", "error"},
                    {"schema", "plan_id", "step_id", "status", "idempotency_key",
                     "observed_at", "result", "error"})
    if err:
        return err
    if not isinstance(obj["plan_id"], str) or not RX_PLAN_ID.match(obj["plan_id"]):
        return _ref(REFUSE_MALFORMED, "outcome.plan_id invalid")
    if not isinstance(obj["step_id"], str) or not RX_SLUG_ID.match(obj["step_id"]):
        return _ref(REFUSE_MALFORMED, "outcome.step_id invalid")
    if obj["status"] not in {"succeeded", "failed", "ambiguous", "refused", "superseded"}:
        return _ref(REFUSE_MALFORMED, "outcome.status outside closed set")
    if not isinstance(obj["idempotency_key"], str) or not RX_IDEMPOTENCY_KEY.match(
        obj["idempotency_key"]
    ):
        return _ref(REFUSE_MALFORMED, "outcome.idempotency_key invalid")
    if _expect_timestamp(obj, "observed_at", "outcome"):
        return _ref(REFUSE_MALFORMED, "outcome.observed_at invalid")
    for key in ("result", "error"):
        value = obj[key]
        if value is not None and not isinstance(value, dict):
            return _ref(REFUSE_MALFORMED, "outcome.{} must be object or null".format(key))
    if obj["status"] in {"failed", "refused"}:
        if obj["error"] is None:
            return _ref(REFUSE_MALFORMED, "outcome: failed|refused requires an error object")
        err_shape = _err_shaped(obj["error"])
        if err_shape:
            return err_shape
    return _ref(ACCEPT, "outcome ok")


def validate_workflow(obj: dict) -> tuple[str, str]:
    err = _json_obj(obj, "hf-workflow", {"schema", "workflow_id", "nodes", "edges"},
                    {"schema", "workflow_id", "nodes", "edges"})
    if err:
        return err
    if not isinstance(obj["workflow_id"], str) or not RX_SLUG_ID.match(obj["workflow_id"]):
        return _ref(REFUSE_MALFORMED, "workflow.workflow_id invalid")
    nodes = obj["nodes"]
    if not isinstance(nodes, list) or not nodes:
        return _ref(REFUSE_MALFORMED, "workflow.nodes must be a non-empty list")
    seen: set[str] = set()
    for node in nodes:
        if not isinstance(node, dict):
            return _ref(REFUSE_MALFORMED, "workflow node must be an object")
        node_id = node.get("id")
        if not isinstance(node_id, str) or not RX_SLUG_ID.match(node_id):
            return _ref(REFUSE_MALFORMED, "workflow node id invalid")
        if node_id in seen:
            return _ref(REFUSE_MALFORMED, "workflow: duplicate node id {!r}".format(node_id))
        seen.add(node_id)
        if node.get("kind") not in WORKFLOW_NODE_KINDS:
            return _ref(REFUSE_MALFORMED, "workflow node kind outside closed set")
        extra = set(node) - {"id", "kind", "params"}
        if extra:
            return _ref(REFUSE_MALFORMED, "workflow node {}: unknown keys {}".format(node_id, extra))
        params = node.get("params")
        if params is not None and not isinstance(params, dict):
            return _ref(REFUSE_MALFORMED, "workflow node params must be object or null")
    edges = obj["edges"]
    if not isinstance(edges, list):
        return _ref(REFUSE_MALFORMED, "workflow.edges must be a list")
    for edge in edges:
        if not isinstance(edge, dict) or set(edge) != {"from", "to"}:
            return _ref(REFUSE_MALFORMED, "workflow edge must have exactly from|to")
        if edge["from"] not in seen or edge["to"] not in seen:
            return _ref(REFUSE_MALFORMED, "workflow edge references an unknown node id")
    return _ref(ACCEPT, "workflow ok")


def validate_rpc_request(obj: dict) -> tuple[str, str]:
    err = _json_obj(obj, "hf-rpc-request", {"schema", "id", "method", "params"},
                    {"schema", "id", "method", "params"})
    if err:
        return err
    if not isinstance(obj["id"], str) or not RX_HEX_ID.match(obj["id"]):
        return _ref(REFUSE_MALFORMED, "rpc-request.id must be 8-64 lowercase hex")
    if obj["method"] not in RPC_METHODS:
        return _ref(REFUSE_MALFORMED, "rpc-request.method outside the closed method set")
    params = obj["params"]
    if params is not None and not isinstance(params, dict):
        return _ref(REFUSE_MALFORMED, "rpc-request.params must be object or null")
    if obj["method"] == "apply":
        if not isinstance(params, dict) or not isinstance(
            params.get("idempotency_key"), str
        ) or not RX_IDEMPOTENCY_KEY.match(params.get("idempotency_key", "")):
            return _ref(REFUSE_MALFORMED,
                        "rpc-request: apply requires params.idempotency_key (ik_ format)")
    return _ref(ACCEPT, "rpc-request ok")


def validate_rpc_response(obj: dict) -> tuple[str, str]:
    err = _json_obj(obj, "hf-rpc-response", {"schema", "id", "ok", "result", "error"},
                    {"schema", "id", "ok", "result", "error"})
    if err:
        return err
    if not isinstance(obj["id"], str) or not RX_HEX_ID.match(obj["id"]):
        return _ref(REFUSE_MALFORMED, "rpc-response.id must be 8-64 lowercase hex")
    if not isinstance(obj["ok"], bool):
        return _ref(REFUSE_MALFORMED, "rpc-response.ok must be a boolean")
    if obj["ok"]:
        if obj["error"] is not None:
            return _ref(REFUSE_MALFORMED, "rpc-response: ok responses must have null error")
        if obj["result"] is None:
            return _ref(REFUSE_MALFORMED, "rpc-response: ok responses require a result object")
    else:
        if obj["result"] is not None:
            return _ref(REFUSE_MALFORMED, "rpc-response: failed responses must have null result")
        err_shape = _err_shaped(obj["error"])
        if err_shape:
            return err_shape
    return _ref(ACCEPT, "rpc-response ok")


def validate_event(obj: dict) -> tuple[str, str]:
    err = _json_obj(obj, "hf-event", {"schema", "event", "seq", "ts", "data"},
                    {"schema", "event", "seq", "ts", "data"})
    if err:
        return err
    if obj["event"] not in EVENT_KINDS:
        return _ref(REFUSE_MALFORMED, "event kind outside the closed set")
    if _expect_int(obj, "seq", "event"):
        return _ref(REFUSE_MALFORMED, "event.seq invalid")
    if _expect_timestamp(obj, "ts", "event"):
        return _ref(REFUSE_MALFORMED, "event.ts invalid")
    if not isinstance(obj["data"], dict):
        return _ref(REFUSE_MALFORMED, "event.data must be an object")
    return _ref(ACCEPT, "event ok")


def validate_audit(obj: dict) -> tuple[str, str]:
    err = _json_obj(obj, "hf-audit",
                    {"schema", "seq", "action", "target", "idempotency_key", "plan_hash",
                     "grant_id", "epoch", "recorded_before_mutation", "at"},
                    {"schema", "seq", "action", "target", "idempotency_key", "plan_hash",
                     "grant_id", "epoch", "recorded_before_mutation", "at"})
    if err:
        return err
    if _expect_int(obj, "seq", "audit"):
        return _ref(REFUSE_MALFORMED, "audit.seq invalid")
    if not isinstance(obj["action"], str) or not RX_ACTION.match(obj["action"]):
        return _ref(REFUSE_MALFORMED, "audit.action invalid")
    if not isinstance(obj["target"], str) or not obj["target"]:
        return _ref(REFUSE_MALFORMED, "audit.target must be non-empty")
    if not isinstance(obj["idempotency_key"], str) or not RX_IDEMPOTENCY_KEY.match(
        obj["idempotency_key"]
    ):
        return _ref(REFUSE_MALFORMED, "audit.idempotency_key invalid")
    for key in ("plan_hash", "grant_id"):
        value = obj[key]
        if value is None:
            continue
        rx = RX_HEX64 if key == "plan_hash" else RX_GRANT_ID
        if not isinstance(value, str) or not rx.match(value):
            return _ref(REFUSE_MALFORMED, "audit.{} invalid".format(key))
    if _expect_int(obj, "epoch", "audit"):
        return _ref(REFUSE_MALFORMED, "audit.epoch invalid")
    if not isinstance(obj["recorded_before_mutation"], bool):
        return _ref(REFUSE_MALFORMED, "audit.recorded_before_mutation must be a boolean")
    if obj["action"].startswith("mutate.") and not obj["recorded_before_mutation"]:
        return _ref(REFUSE_MALFORMED,
                    "audit: mutation actions must be journaled before the mutation (fail closed)")
    if _expect_timestamp(obj, "at", "audit"):
        return _ref(REFUSE_MALFORMED, "audit.at invalid")
    return _ref(ACCEPT, "audit ok")


def validate_migration(obj: dict) -> tuple[str, str]:
    err = _json_obj(obj, "hf-migration",
                    {"schema", "migration_id", "applies_from", "applies_to",
                     "checksum", "description"},
                    {"schema", "migration_id", "applies_from", "applies_to",
                     "checksum", "description"})
    if err:
        return err
    if not isinstance(obj["migration_id"], str) or not RX_MIGRATION_ID.match(
        obj["migration_id"]
    ):
        return _ref(REFUSE_MALFORMED, "migration.migration_id invalid")
    if _expect_int(obj, "applies_from", "migration"):
        return _ref(REFUSE_MALFORMED, "migration.applies_from invalid")
    if _expect_int(obj, "applies_to", "migration"):
        return _ref(REFUSE_MALFORMED, "migration.applies_to invalid")
    if obj["applies_to"] != obj["applies_from"] + 1:
        return _ref(REFUSE_MALFORMED,
                    "migration: applies_to must be exactly applies_from + 1 (linear, ordered)")
    if not isinstance(obj["checksum"], str) or not RX_HEX64.match(obj["checksum"]):
        return _ref(REFUSE_MALFORMED, "migration.checksum must be 64-hex")
    if not isinstance(obj["description"], str) or not obj["description"]:
        return _ref(REFUSE_MALFORMED, "migration.description must be non-empty")
    return _ref(ACCEPT, "migration ok")


def validate_capability(obj: dict) -> tuple[str, str]:
    err = _json_obj(obj, "hf-capability", {"schema", "axis", "actor", "capabilities"},
                    {"schema", "axis", "actor", "capabilities"})
    if err:
        return err
    axis = obj["axis"]
    if axis not in {"harness", "forge"}:
        return _ref(REFUSE_MALFORMED, "capability.axis outside closed set")
    if not isinstance(obj["actor"], str) or not RX_ACTOR.match(obj["actor"]):
        return _ref(REFUSE_MALFORMED, "capability.actor invalid")
    caps = obj["capabilities"]
    closed = HARNESS_CAPS if axis == "harness" else FORGE_CAPS
    if not isinstance(caps, list) or not caps or not all(item in closed for item in caps):
        return _ref(REFUSE_MALFORMED,
                    "capability.capabilities must be a non-empty subset of the closed {} set".format(axis))
    return _ref(ACCEPT, "capability ok")


def validate_evidence(obj: dict) -> tuple[str, str]:
    err = _json_obj(obj, "hf-evidence",
                    {"schema", "evidence_id", "feature_head", "integration_base",
                     "workflow_hash", "policy_hash", "verdict", "checks", "created_at"},
                    {"schema", "evidence_id", "feature_head", "integration_base",
                     "workflow_hash", "policy_hash", "verdict", "checks", "created_at"})
    if err:
        return err
    if not isinstance(obj["evidence_id"], str) or not RX_EVIDENCE_ID.match(obj["evidence_id"]):
        return _ref(REFUSE_MALFORMED, "evidence.evidence_id invalid")
    for key in ("feature_head", "integration_base"):
        if not isinstance(obj[key], str) or not RX_HEX40.match(obj[key]):
            return _ref(REFUSE_MALFORMED, "evidence.{} must be a 40-hex SHA".format(key))
    for key in ("workflow_hash", "policy_hash"):
        if not isinstance(obj[key], str) or not RX_HEX64.match(obj[key]):
            return _ref(REFUSE_MALFORMED, "evidence.{} must be 64-hex".format(key))
    if obj["verdict"] not in {"pass", "fail"}:
        return _ref(REFUSE_MALFORMED, "evidence.verdict outside closed set")
    checks = obj["checks"]
    if not isinstance(checks, list) or not checks:
        return _ref(REFUSE_MALFORMED, "evidence.checks must be a non-empty list")
    for check in checks:
        if not isinstance(check, dict) or set(check) != {"name", "status"}:
            return _ref(REFUSE_MALFORMED, "evidence check must have exactly name|status")
        if not isinstance(check["name"], str) or not check["name"]:
            return _ref(REFUSE_MALFORMED, "evidence check name must be non-empty")
        if check["status"] not in {"passed", "failed", "pending"}:
            return _ref(REFUSE_MALFORMED, "evidence check status outside closed set")
    if _expect_timestamp(obj, "created_at", "evidence"):
        return _ref(REFUSE_MALFORMED, "evidence.created_at invalid")
    return _ref(ACCEPT, "evidence ok")


# ---------------------------------------------------------------------------
# Family registry: kind -> (file suffix group, parser, validator)
# ---------------------------------------------------------------------------

def _parse_jsonl(raw: bytes, family: str) -> list[dict]:
    text = raw.decode("utf-8")
    docs = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            doc = json.loads(line)
        except ValueError as exc:
            raise ValueError("line {}: {}".format(lineno, exc)) from exc
        if not isinstance(doc, dict):
            raise ValueError("line {}: not an object".format(lineno))
        docs.append(doc)
    if not docs:
        raise ValueError("empty JSONL document")
    return docs


def _validate_json_doc(raw: bytes, family: str) -> tuple[str, str]:
    try:
        obj = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        return _ref(REFUSE_PARSE, "{}: not valid JSON ({})".format(family, exc))
    if not isinstance(obj, dict):
        return _ref(REFUSE_PARSE, "{}: root must be an object".format(family))
    return VALIDATORS[family](obj)


def _validate_jsonl_doc(raw: bytes, family: str) -> tuple[str, str]:
    try:
        docs = _parse_jsonl(raw, family)
    except ValueError as exc:
        return _ref(REFUSE_PARSE, "{}: {}".format(family, exc))
    for doc in docs:
        code, msg = VALIDATORS[family](doc)
        if code != ACCEPT:
            return _ref(code, msg)
    return _ref(ACCEPT, "{} ok".format(family))


def _validate_toml_doc(raw: bytes, family: str) -> tuple[str, str]:
    try:
        obj = tomllib.loads(raw.decode("utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        return _ref(REFUSE_PARSE, "{}: not valid TOML ({})".format(family, exc))
    return VALIDATORS[family](obj)


# ---------------------------------------------------------------------------
# hf-board/v1 (issue #83 read model): bounded page of run rows
# ---------------------------------------------------------------------------

# Token shapes mirrored conservatively from src/redact.rs (prefix, minimum
# token-run length after the prefix). A recorded-text field must be
# redaction-stable: the conservative pass would not change it.
_SECRET_TOKEN_PREFIXES = (
    ("github_pat_", 20), ("ghp_", 8), ("gho_", 8), ("ghu_", 8), ("ghs_", 8),
    ("ghr_", 8), ("glpat-", 8), ("xoxb-", 8), ("xoxp-", 8), ("sk-", 20),
    ("xoxa-", 8), ("xoxr-", 8), ("AKIA", 16),
)


def _token_char(ch: str) -> bool:
    return ch.isascii() and (ch.isalnum() or ch in "_-./=+$")


def _token_run_len(text: str) -> int:
    run = 0
    for ch in text:
        if not _token_char(ch):
            break
        run += 1
    return run


def _secret_shaped(text: str) -> bool:
    """True when the conservative redaction pass (src/redact.rs) would
    change this text: a token-prefixed secret at a boundary, a PEM block
    begin marker, or a URL userinfo segment."""
    for start, ch in enumerate(text):
        boundary = start == 0 or not _token_char(text[start - 1])
        rest = text[start:]
        if boundary:
            for prefix, floor in _SECRET_TOKEN_PREFIXES:
                if rest.startswith(prefix) and _token_run_len(rest[len(prefix):]) >= floor:
                    return True
            if rest.startswith("-----BEGIN"):
                return True
        if rest.startswith("://"):
            after = rest[3:]
            at = after.find("@")
            if at >= 0:
                before_at = after[:at]
                if "/" not in before_at and len(before_at) >= 3:
                    return True
    return False


def _board_recorded_text(obj: dict, key: str, where: str) -> tuple[str, str] | None:
    if key not in obj:
        return _ref(REFUSE_MALFORMED, "{}: missing required key {!r}".format(where, key))
    value = obj[key]
    if value is None:
        return None
    if not isinstance(value, str):
        return _ref(REFUSE_MALFORMED,
                    "{}: {!r} must be null or a string".format(where, key))
    if len(value) > 128 or any(ord(c) < 0x20 or ord(c) == 0x7F for c in value):
        return _ref(REFUSE_MALFORMED,
                    "{}: {!r} must be <= 128 characters without controls".format(where, key))
    if _secret_shaped(value):
        return _ref(REFUSE_MALFORMED,
                    "{}: {!r} carries an unredacted secret-shaped run".format(where, key))
    return None


def _board_optional_timestamp(obj: dict, key: str, where: str) -> tuple[str, str] | None:
    if key not in obj:
        return _ref(REFUSE_MALFORMED, "{}: missing required key {!r}".format(where, key))
    value = obj[key]
    if value is None:
        return None
    if not isinstance(value, str) or not RX_RFC3339_Z.match(value):
        return _ref(REFUSE_MALFORMED,
                    "{}: {!r} must be null or RFC3339 UTC (seconds, Z)".format(where, key))
    return None


def _board_cursor_shaped(text: str) -> bool:
    parts = text.split("|")
    if len(parts) != 3:
        return False
    repository, issue, run = parts
    if repository and not RX_REPOSITORY.match(repository):
        return False
    if not issue or not issue.isascii() or not issue.isdigit():
        return False
    return bool(run) and len(run) <= 64 and all(
        c.isascii() and (c.isalnum() or c in "._-") for c in run)


def validate_board(obj: dict) -> tuple[str, str]:
    """hf-board/v1 (issue #83 read model): one bounded page of run rows.
    The closed consistency rules are the machine-checked half of the
    coverage contract: a page never presents an idle/working run as
    verified without current recorded review evidence, never joins two
    runs of one work item into a row, never reorders a page, never
    fabricates evidence, and never carries secret-shaped recorded text."""
    keys = {"schema", "observed_at", "state", "rows", "next_cursor", "truncated"}
    err = _json_obj(obj, "hf-board", keys, keys)
    if err:
        return err
    err = _expect_timestamp(obj, "observed_at", "board")
    if err:
        return err
    err = _expect_object(obj, "state", "board")
    if err:
        return err
    state_keys = {"epoch", "journal_seq"}
    err = _require_keys(obj["state"], state_keys, state_keys, "board.state")
    if err:
        return err
    for key in ("epoch", "journal_seq"):
        err = _expect_int(obj["state"], key, "board.state")
        if err:
            return err
    truncated = obj["truncated"]
    if not isinstance(truncated, bool):
        return _ref(REFUSE_MALFORMED, "board.truncated must be a boolean")
    cursor = obj["next_cursor"]
    has_cursor = cursor is not None
    if has_cursor and (not isinstance(cursor, str) or not _board_cursor_shaped(cursor)):
        return _ref(REFUSE_MALFORMED,
                    "board.next_cursor must be a repository|issue|run ordering key")
    if has_cursor != truncated:
        return _ref(REFUSE_MALFORMED,
                    "board.next_cursor and board.truncated must agree (cursor iff more rows)")
    rows = obj["rows"]
    if not isinstance(rows, list):
        return _ref(REFUSE_MALFORMED, "board.rows must be a list")
    if not rows and truncated:
        return _ref(REFUSE_MALFORMED, "board.truncated cannot be true for an empty page")
    previous = None
    for row in rows:
        code, msg, key = _validate_board_row(row, previous)
        if code != ACCEPT:
            return _ref(code, msg)
        previous = key
    return _ref(ACCEPT, "board ok")


def _validate_board_row(row, previous):
    """Validate one board row; returns (code, message, ordering key)."""
    where = "board row"
    if not isinstance(row, dict):
        return (REFUSE_MALFORMED, "{} must be an object".format(where), None)
    keys = {"work_item", "source", "run", "run_state", "stage", "verification",
            "owner", "reason", "next_action", "human_gate", "milestone",
            "evidence", "evidence_total", "evidence_at", "reviewer",
            "progress_at", "observed_at"}
    err = _require_keys(row, keys, keys, where)
    if err:
        return (err[0], err[1], None)
    source = row["source"]
    if not isinstance(source, dict):
        return (REFUSE_MALFORMED, "{} source must be an object".format(where), None)
    source_keys = {"kind", "repository", "issue", "revision", "freshness",
                   "completeness", "observed_at"}
    err = _require_keys(source, source_keys, source_keys, "{} source".format(where))
    if err:
        return (err[0], err[1], None)
    err = _expect_in(source, "kind", "{} source".format(where), BOARD_SOURCE_KINDS)
    if err:
        return (err[0], err[1], None)
    repository = source["repository"]
    if not isinstance(repository, str):
        return (REFUSE_MALFORMED, "{} source.repository must be a string".format(where), None)
    issue = source["issue"]
    if isinstance(issue, bool) or not isinstance(issue, int) or issue < 0:
        return (REFUSE_MALFORMED, "{} source.issue must be a non-negative integer".format(where), None)
    revision = source["revision"]
    if not isinstance(revision, str):
        return (REFUSE_MALFORMED, "{} source.revision must be a string".format(where), None)
    err = _expect_in(source, "freshness", "{} source".format(where), {"fresh", "stale"})
    if err:
        return (err[0], err[1], None)
    completeness = source["completeness"]
    if completeness not in ("complete", "partial"):
        return (REFUSE_MALFORMED, "{} source.completeness must be complete|partial".format(where), None)
    err = _board_optional_timestamp(source, "observed_at", "{} source".format(where))
    if err:
        return (err[0], err[1], None)
    work_item = row["work_item"]
    if completeness == "partial":
        if work_item is not None:
            return (REFUSE_MALFORMED,
                    "{} work_item must be null for a partial source".format(where), None)
    elif not isinstance(work_item, str) or not RX_WORK_ITEM_ID.match(work_item):
        return (REFUSE_MALFORMED,
                "{} work_item must be a wi_ id for a complete source".format(where), None)
    if completeness == "complete" and (
            not RX_REPOSITORY.match(repository) or issue < 1 or not RX_HEX40.match(revision)):
        return (REFUSE_MALFORMED,
                "{} source: a complete row requires owner/name, a positive issue, "
                "and a 40-hex revision".format(where), None)
    run = row["run"]
    if not isinstance(run, str) or not run or len(run) > 64 or not all(
            c.isascii() and (c.isalnum() or c in "._-") for c in run):
        return (REFUSE_MALFORMED, "{} run must be a 1..=64 character identifier".format(where), None)
    run_state = row["run_state"]
    if run_state not in BOARD_RUN_STATES:
        return (REFUSE_MALFORMED, "{} run_state outside the closed set".format(where), None)
    stage = row["stage"]
    if stage not in BOARD_STAGES:
        return (REFUSE_MALFORMED, "{} stage outside the closed set".format(where), None)
    freshness = source["freshness"]
    verification = row["verification"]
    if verification not in BOARD_VERIFICATIONS:
        return (REFUSE_MALFORMED, "{} verification outside the closed set".format(where), None)
    verified = verification == "passed" and freshness == "fresh" and run_state != "invalidated"
    if (stage == "verified") != verified:
        return (REFUSE_MALFORMED,
                "{} stage must be verified iff verification is passed, fresh, "
                "and not invalidated".format(where), None)
    for key in ("owner", "reason", "reviewer"):
        err = _board_recorded_text(row, key, where)
        if err:
            return (err[0], err[1], None)
    next_action = row["next_action"]
    if next_action is not None and next_action not in BOARD_NEXT_ACTIONS:
        return (REFUSE_MALFORMED, "{} next_action outside the closed set".format(where), None)
    if next_action == "resume" and run_state != "paused":
        return (REFUSE_MALFORMED, "{} next_action resume requires a paused run".format(where), None)
    if next_action == "human_decision" and run_state != "human_queue":
        return (REFUSE_MALFORMED, "{} next_action human_decision requires a human_queue run".format(where), None)
    human_gate = row["human_gate"]
    if not isinstance(human_gate, bool) or human_gate != (run_state in ("paused", "human_queue")):
        return (REFUSE_MALFORMED,
                "{} human_gate must be a boolean equal to (run_state is paused "
                "or human_queue)".format(where), None)
    milestone = row["milestone"]
    if milestone is not None and (not isinstance(milestone, str) or not RX_SLUG_ID.match(milestone)):
        return (REFUSE_MALFORMED, "{} milestone must be null or a node slug".format(where), None)
    evidence = row["evidence"]
    if not isinstance(evidence, list):
        return (REFUSE_MALFORMED, "{} evidence must be a list".format(where), None)
    if len(evidence) > BOARD_EVIDENCE_REF_MAX:
        return (REFUSE_MALFORMED, "{} evidence exceeds the bounded cap".format(where), None)
    seen = set()
    for item in evidence:
        if not isinstance(item, str) or not RX_EVIDENCE_ID.match(item):
            return (REFUSE_MALFORMED, "{} evidence entries must be ev_ ids".format(where), None)
        if item in seen:
            return (REFUSE_MALFORMED, "{} evidence repeats a reference".format(where), None)
        seen.add(item)
    evidence_total = row["evidence_total"]
    if isinstance(evidence_total, bool) or not isinstance(evidence_total, int) \
            or evidence_total < len(evidence):
        return (REFUSE_MALFORMED,
                "{} evidence_total must be an integer >= the exposed count".format(where), None)
    err = _board_optional_timestamp(row, "evidence_at", where)
    if err:
        return (err[0], err[1], None)
    err = _board_optional_timestamp(row, "progress_at", where)
    if err:
        return (err[0], err[1], None)
    err = _expect_timestamp(row, "observed_at", where)
    if err:
        return (err[0], err[1], None)
    has_evidence_at = isinstance(row["evidence_at"], str)
    if verification == "none":
        if evidence or evidence_total != 0 or has_evidence_at:
            return (REFUSE_MALFORMED,
                    "{} verification none requires no evidence references and "
                    "no evidence_at".format(where), None)
    elif not evidence or evidence_total < 1 or not has_evidence_at:
        return (REFUSE_MALFORMED,
                "{} verification failed|passed requires recorded evidence and "
                "its timestamp".format(where), None)
    key = (repository, issue, run)
    if previous is not None and key <= previous:
        return (REFUSE_MALFORMED,
                "{} rows must be in strictly increasing (repository, issue, run) "
                "order".format(where), None)
    return (ACCEPT, "board row ok", key)


VALIDATORS = {
    "hf-config": validate_config,
    "hf-policy": validate_policy,
    "hf-output": validate_output,
    "hf-error": validate_error,
    "hf-observation": validate_observation,
    "hf-plan": validate_plan,
    "hf-grant": validate_grant,
    "hf-epoch": validate_epoch,
    "hf-outcome": validate_outcome,
    "hf-workflow": validate_workflow,
    "hf-schedule": validate_schedule,
    "hf-board": validate_board,
    "hf-rpc-request": validate_rpc_request,
    "hf-rpc-response": validate_rpc_response,
    "hf-event": validate_event,
    "hf-audit": validate_audit,
    "hf-migration": validate_migration,
    "hf-capability": validate_capability,
    "hf-evidence": validate_evidence,
}

PARSERS = {
    "hf-config": ("toml", _validate_toml_doc),
    "hf-policy": ("toml", _validate_toml_doc),
    "hf-event": ("jsonl", _validate_jsonl_doc),
    "hf-audit": ("jsonl", _validate_jsonl_doc),
}
for _family in VALIDATORS:
    if _family not in PARSERS:
        PARSERS[_family] = ("json", _validate_json_doc)

# Families whose on-disk bytes must equal the canonical serialization.
CANONICAL_FAMILIES = frozenset({"hf-plan", "hf-workflow"})


def validate_bytes(raw: bytes, family: str) -> tuple[str, str]:
    """Validate raw bytes against a family. Also enforces the canonical-bytes
    rule for canonical families (refuse-noncanonical)."""
    if family not in VALIDATORS:
        raise ValueError("unknown family {!r}".format(family))
    code, msg = PARSERS[family][1](raw, family)
    if code != ACCEPT:
        return _ref(code, msg)
    if family in CANONICAL_FAMILIES:
        obj = json.loads(raw.decode("utf-8"))
        if raw not in (canon_json_bytes(obj), canon_json_bytes(obj).rstrip(b"\n")):
            return _ref(REFUSE_NONCANONICAL,
                        "{}: bytes are not the canonical serialization".format(family))
    return _ref(ACCEPT, "{} ok".format(family))


def validate_file(path: Path, family: str) -> tuple[str, str]:
    return validate_bytes(path.read_bytes(), family)


def _load_manifest(root: Path) -> list[dict]:
    manifest_path = root / "schemas" / "fixtures" / "manifest.jsonl"
    rows = []
    for lineno, line in enumerate(
        manifest_path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except ValueError as exc:
            raise RuntimeError("manifest line {}: {}".format(lineno, exc)) from exc
        if not isinstance(row, dict) or not set(row) <= {
            "family", "file", "expect", "kind", "note", "sha256",
        }:
            raise RuntimeError("manifest line {}: unexpected fields".format(lineno))
        rows.append(row)
    if not rows:
        raise RuntimeError("manifest is empty")
    return rows


def main(argv: list[str]) -> int:
    if len(argv) > 2:
        print("usage: check-contract-fixtures.py [repo-root]  (default: .)", file=sys.stderr)
        return 2
    root = Path(argv[1] if len(argv) == 2 else ".")
    try:
        rows = _load_manifest(root)
    except (RuntimeError, OSError) as exc:
        print("check-contract-fixtures: ERROR: {}".format(exc), file=sys.stderr)
        return 3

    failures = []
    for row in rows:
        family = row.get("family")
        rel = row.get("file")
        expect = row.get("expect")
        kind = row.get("kind")
        path = root / "schemas" / "fixtures" / rel
        try:
            code, msg = validate_file(path, family)
        except (OSError, ValueError) as exc:
            failures.append("{}: operational error: {}".format(rel, exc))
            continue
        if expect == "accept":
            if code != ACCEPT:
                failures.append("{}: expected accept, got {} ({})".format(rel, code, msg))
        elif expect == "refuse":
            if code == ACCEPT:
                failures.append("{}: expected refusal, got accept".format(rel))
            elif kind == "unknown-version" and code != REFUSE_VERSION:
                failures.append("{}: unknown-version fixture must refuse-version, got {}".format(
                    rel, code))
            elif kind == "noncanonical" and code != REFUSE_NONCANONICAL:
                failures.append("{}: noncanonical fixture must refuse-noncanonical, got {}".format(
                    rel, code))
        else:
            failures.append("{}: manifest row has invalid expect {!r}".format(rel, expect))
        if "sha256" in row:
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            if digest != row["sha256"]:
                failures.append(
                    "{}: digest mismatch (manifest {} vs actual {})".format(rel, row["sha256"], digest)
                )

    for failure in failures:
        print("check-contract-fixtures: {}".format(failure))
    if failures:
        print("check-contract-fixtures: {} expectation(s) failed".format(len(failures)), file=sys.stderr)
        return 1
    print("check-contract-fixtures: {} manifest expectation(s) held ({} rows)".format(
        len(rows), len(rows)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
