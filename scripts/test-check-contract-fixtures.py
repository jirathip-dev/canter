#!/usr/bin/env python3
"""test-check-contract-fixtures.py — self-tests for check-contract-fixtures.py.

Proves the fixture validators actually bite (tamper discrimination), in the
same style as test-check-public-tree.py: every scenario copies a committed
fixture into a temp dir, mutates it, and asserts the exact refusal code.
Also enforces registry coherence between this module's family registry, the
fixture manifest, and the human schema registry in
docs/contracts/schema-registry.md, plus AC2 coverage (every family needs at
least one accept, one malformed-refusal, and one unknown-version-refusal
fixture).

Deterministic and stdlib-only. Exit codes: 0 pass, 1 failure, 3 operational.
"""

from __future__ import annotations

import importlib.util
import json
import re
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "schemas" / "fixtures"
FAILURES: list[str] = []
CHECKS = 0


def _check(cond: bool, msg: str) -> None:
    global CHECKS
    CHECKS += 1
    if not cond:
        FAILURES.append(msg)


def _load_probe():
    spec = importlib.util.spec_from_file_location(
        "check_contract_fixtures", ROOT / "scripts" / "check-contract-fixtures.py"
    )
    probe = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(probe)
    return probe


def _tamper_copy(rel: str, transform) -> Path:
    """Copy a committed fixture into a temp dir and apply `transform` to the
    bytes; returns the tampered path."""
    tmp = Path(tempfile.mkdtemp(prefix="hf-fixtures-test-"))
    target = tmp / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(transform((FIXTURES / rel).read_bytes()))
    return target


def run_discrimination(probe) -> None:
    # 1. Config: unsupported version must refuse-version; unknown table must
    #    refuse-malformed.
    p = _tamper_copy("config/config.valid.toml",
                     lambda b: b.replace(b'hf-config/v1', b'hf-config/v2'))
    code, _msg = probe.validate_file(p, "hf-config")
    _check(code == probe.REFUSE_VERSION, "config v2 tamper must refuse-version, got " + code)

    p = _tamper_copy("config/config.valid.toml",
                     lambda b: b + b'\n[watcher]\ninterval = 5\n')
    code, _msg = probe.validate_file(p, "hf-config")
    _check(code == probe.REFUSE_MALFORMED,
           "config unknown table must refuse-malformed, got " + code)

    # 1b. Config harness binding (issue #80): the optional provider/model
    #     pair is a string pair in the document rules; a non-string token is
    #     refused. (Bare-token / both-or-neither rules live in the decoder.)
    p = _tamper_copy("config/config.valid.toml",
                     lambda b: b.replace(b'env_allow = ["PATH", "HOME"]',
                                         b'env_allow = ["PATH", "HOME"]\nprovider = 5'))
    code, _msg = probe.validate_file(p, "hf-config")
    _check(code == probe.REFUSE_MALFORMED,
           "config harness non-string provider must refuse-malformed, got " + code)

    p = _tamper_copy("config/config.valid.toml",
                     lambda b: b.replace(b'env_allow = ["PATH", "HOME"]',
                                         b'env_allow = ["PATH", "HOME"]\n'
                                         b'provider = "example-provider"\n'
                                         b'model = "example-model"'))
    code, _msg = probe.validate_file(p, "hf-config")
    _check(code == probe.ACCEPT,
           "config harness provider/model pair must be accepted, got " + code)

    # 1c. Config profile-planning keys (issue #77): shape rules bite in the
    #     document validator; a non-boolean introspection flag, a non-scalar
    #     limit value and a non-array fallback list are refused.
    for label, extra in (
        ("non-boolean introspection", b'binding_introspection = 5'),
        ("non-scalar limit", b'limits = { context = [1] }'),
        ("non-array fallback", b'fallback = "example-provider/example-model"'),
    ):
        p = _tamper_copy("config/config.valid.toml",
                         lambda b, extra=extra: b.replace(b'env_allow = ["PATH", "HOME"]',
                                                          b'env_allow = ["PATH", "HOME"]\n' + extra))
        code, _msg = probe.validate_file(p, "hf-config")
        _check(code == probe.REFUSE_MALFORMED,
               "config harness {} must refuse-malformed, got {}".format(label, code))

    # 2. Policy: overlay may only tighten.
    p = _tamper_copy("policy/policy.valid.toml",
                     lambda b: b.replace(b'production_confirmation = "tty"',
                                         b'production_confirmation = "never-tty"'))
    code, _msg = probe.validate_file(p, "hf-policy")
    _check(code == probe.REFUSE_MALFORMED,
           "policy relaxing confirmation must refuse-malformed, got " + code)

    # 3. Plan: non-canonical bytes must refuse-noncanonical; unknown step kind
    #    must refuse-malformed.
    raw = (FIXTURES / "plan/plan.valid.json").read_bytes()
    obj = json.loads(raw.decode("utf-8"))
    p = _tamper_copy("plan/plan.valid.json",
                     lambda _b: (json.dumps(obj, indent=2, sort_keys=True) + "\n").encode())
    code, _msg = probe.validate_file(p, "hf-plan")
    _check(code == probe.REFUSE_NONCANONICAL,
           "plan pretty-print must refuse-noncanonical, got " + code)

    p = _tamper_copy("plan/plan.valid.json",
                     lambda b: b.replace(b'"kind":"merge"', b'"kind":"shell_exec"', 1))
    code, _msg = probe.validate_file(p, "hf-plan")
    _check(code == probe.REFUSE_MALFORMED,
           "plan shell step kind must refuse-malformed, got " + code)

    # 4. Workflow DAG: unknown node kind must refuse-malformed (closed types).
    p = _tamper_copy("workflow/workflow.valid.json",
                     lambda b: b.replace(b'"kind":"gate"', b'"kind":"shell"', 1))
    code, _msg = probe.validate_file(p, "hf-workflow")
    _check(code == probe.REFUSE_MALFORMED,
           "workflow unknown node kind must refuse-malformed, got " + code)

    # 5. Grant: AC3 binding fields are required.
    p = _tamper_copy("grant/grant.valid.json",
                     lambda b: re.sub(rb'"state_epoch":3,', b'', b, count=1))
    code, _msg = probe.validate_file(p, "hf-grant")
    _check(code == probe.REFUSE_MALFORMED,
           "grant without state_epoch must refuse-malformed, got " + code)

    # 6. Epoch restore (AC7): rotation must reference a prior epoch.
    p = _tamper_copy("epoch/epoch.restore.valid.json",
                     lambda b: b.replace(b'"prior_epoch":1', b'"prior_epoch":null'))
    code, _msg = probe.validate_file(p, "hf-epoch")
    _check(code == probe.REFUSE_MALFORMED,
           "restore epoch without prior must refuse-malformed, got " + code)

    # 7. Audit (AC6): a mutation journaled as NOT-before-mutation fails closed.
    p = _tamper_copy("audit/audit.valid.jsonl",
                     lambda b: b.replace(b'"recorded_before_mutation":true',
                                         b'"recorded_before_mutation":false', 1))
    code, _msg = probe.validate_file(p, "hf-audit")
    _check(code == probe.REFUSE_MALFORMED,
           "mutation not journaled before effect must refuse-malformed, got " + code)

    # 8. Daemon apply request: idempotency key is mandatory on apply.
    p = _tamper_copy("rpc/request.apply.valid.json",
                     lambda b: re.sub(rb'"idempotency_key":"ik_[a-z0-9-]+",', b'', b, count=1))
    code, _msg = probe.validate_file(p, "hf-rpc-request")
    _check(code == probe.REFUSE_MALFORMED,
           "apply request without idempotency key must refuse-malformed, got " + code)

    # 9. Capability negotiation: unknown capability is a typed refusal.
    p = _tamper_copy("capability/capability.harness.valid.json",
                     lambda b: b.replace(b'"identity"', b'"teleport"', 1))
    code, _msg = probe.validate_file(p, "hf-capability")
    _check(code == probe.REFUSE_MALFORMED,
           "unknown harness capability must refuse-malformed, got " + code)

    # 10. Evidence (AC4): a running check status is not a closed value.
    p = _tamper_copy("evidence/evidence.valid.json",
                     lambda b: b.replace(b'"status":"passed"', b'"status":"running"', 1))
    code, _msg = probe.validate_file(p, "hf-evidence")
    _check(code == probe.REFUSE_MALFORMED,
           "evidence running status must refuse-malformed, got " + code)

    # 10b. Board (issue #83): a reported-done run relabelled as verified
    #      without recorded evidence must refuse — verified delivery and
    #      reported status are separate axes.
    raw = (FIXTURES / "board/board.valid.json").read_bytes()
    obj = json.loads(raw.decode("utf-8"))
    obj["rows"].reverse()
    p = _tamper_copy("board/board.valid.json",
                     lambda _b: (json.dumps(obj, sort_keys=True,
                                            separators=(",", ":")).encode() + b"\n"))
    code, _msg = probe.validate_file(p, "hf-board")
    _check(code == probe.REFUSE_MALFORMED,
           "board rows out of order must refuse-malformed, got " + code)

    obj = json.loads(raw.decode("utf-8"))
    for row in obj["rows"]:
        if row["run"] == "run-widgets-0003":
            row["stage"] = "verified"
    p = _tamper_copy("board/board.valid.json",
                     lambda _b: (json.dumps(obj, sort_keys=True,
                                            separators=(",", ":")).encode() + b"\n"))
    code, _msg = probe.validate_file(p, "hf-board")
    _check(code == probe.REFUSE_MALFORMED,
           "reported-done relabelled verified must refuse-malformed, got " + code)

    # An unredacted secret-shaped recorded-text field must refuse.
    obj = json.loads(raw.decode("utf-8"))
    for row in obj["rows"]:
        if row["run"] == "run-widgets-0003":
            row["reason"] = "handoff ghp_" + "0123456789abcdef0123456789abcdef012345"
    p = _tamper_copy("board/board.valid.json",
                     lambda _b: (json.dumps(obj, sort_keys=True,
                                            separators=(",", ":")).encode() + b"\n"))
    code, _msg = probe.validate_file(p, "hf-board")
    _check(code == probe.REFUSE_MALFORMED,
           "board unredacted recorded text must refuse-malformed, got " + code)

    # 10c. Escalation surface (issue #208): the closed code set and the
    #      read-only/answer rules bite.

    def escalation_page(page):
        return (json.dumps(page, sort_keys=True, separators=(",", ":")).encode() + b"\n")

    def mutated_page(mutate, rel="escalation/escalation.valid.json"):
        page = json.loads((FIXTURES / rel).read_bytes().decode("utf-8"))
        mutate(page)
        return escalation_page(page)

    def first_record(page):
        return page["escalations"][0]

    # An escalation code outside the closed set must refuse, even when it
    # looks like a real engine code family.
    p = _tamper_copy("escalation/escalation.valid.json",
                     lambda _b: mutated_page(
                         lambda page: first_record(page).update(code="refusal.delivery.reviewed")))
    code, _msg = probe.validate_file(p, "hf-escalation")
    _check(code == probe.REFUSE_MALFORMED,
           "escalation unlisted code must refuse-malformed, got " + code)

    # A park never presents as waiting-approval (issue #202's park rule).
    p = _tamper_copy("escalation/escalation.valid.json",
                     lambda _b: mutated_page(
                         lambda page: first_record(page).update(state="waiting-approval")))
    code, _msg = probe.validate_file(p, "hf-escalation")
    _check(code == probe.REFUSE_MALFORMED,
           "escalation waiting-approval state must refuse-malformed, got " + code)

    # An escalation nobody can answer is not an escalation: the answer list
    # must be non-empty and every name a typed operation.
    for label, mutate in (
        ("empty", lambda record: record.update(answerable_by=[])),
        ("untyped", lambda record: record.update(answerable_by=["poke_the_pane"])),
        ("duplicated", lambda record: record.update(answerable_by=["run.retry", "run.retry"])),
    ):
        p = _tamper_copy("escalation/escalation.valid.json",
                         lambda _b, mutate=mutate: mutated_page(
                             lambda page: mutate(first_record(page))))
        code, _msg = probe.validate_file(p, "hf-escalation")
        _check(code == probe.REFUSE_MALFORMED,
               "escalation {} answerable_by must refuse-malformed, got {}".format(label, code))

    # A bound head that is not a 40-hex commit must refuse.
    p = _tamper_copy("escalation/escalation.valid.json",
                     lambda _b: mutated_page(
                         lambda page: first_record(page)["bound_heads"].update(
                             certified="not-a-commit")))
    code, _msg = probe.validate_file(p, "hf-escalation")
    _check(code == probe.REFUSE_MALFORMED,
           "escalation non-hex certified head must refuse-malformed, got " + code)

    # An unredacted secret-shaped message must refuse (redaction is the write
    # boundary, not a display concern).
    p = _tamper_copy("escalation/escalation.valid.json",
                     lambda _b: mutated_page(
                         lambda page: first_record(page).update(
                             message="handoff ghp_" + "0123456789abcdef0123456789abcdef012345")))
    code, _msg = probe.validate_file(p, "hf-escalation")
    _check(code == probe.REFUSE_MALFORMED,
           "escalation unredacted message must refuse-malformed, got " + code)

    # Rows out of (raised_at, id) order must refuse.
    def _reverse_records(page):
        page["escalations"].reverse()
    p = _tamper_copy("escalation/escalation.valid.json",
                     lambda _b: mutated_page(_reverse_records))
    code, _msg = probe.validate_file(p, "hf-escalation")
    _check(code == probe.REFUSE_MALFORMED,
           "escalation rows out of order must refuse-malformed, got " + code)

    # A cursor that is not the ordering key of the last row must refuse.
    def _wrong_cursor(page):
        page["cursor"] = "2026-09-06T00:00:05Z|esc_ffffffffffffffff"
    p = _tamper_copy("escalation/escalation.page.valid.json",
                     lambda _b: mutated_page(_wrong_cursor,
                                             "escalation/escalation.page.valid.json"))
    code, _msg = probe.validate_file(p, "hf-escalation")
    _check(code == probe.REFUSE_MALFORMED,
           "escalation cursor that names no row must refuse-malformed, got " + code)

    # Unknown keys stay closed (the surface is additive-only, never silent).
    p = _tamper_copy("escalation/escalation.valid.json",
                     lambda _b: mutated_page(
                         lambda page: first_record(page).update(priority="high")))
    code, _msg = probe.validate_file(p, "hf-escalation")
    _check(code == probe.REFUSE_MALFORMED,
           "escalation unknown key must refuse-malformed, got " + code)

    # 11. JSONL event stream: a bad line must refuse-parse.
    p = _tamper_copy("event/events.valid.jsonl",
                     lambda b: b + b'{"schema": "hf-event/v1", broken\n')
    code, _msg = probe.validate_file(p, "hf-event")
    _check(code == probe.REFUSE_PARSE,
           "event stream with bad line must refuse-parse, got " + code)

    # 12. Canonical digest: known-answer check on the committed valid plan.
    digest_row = None
    for line in (FIXTURES / "manifest.jsonl").read_text().splitlines():
        row = json.loads(line)
        if row.get("family") == "hf-plan" and row.get("expect") == "accept":
            digest_row = row
    _check(digest_row is not None, "manifest must carry a sha256 row for hf-plan")
    if digest_row and "sha256" in digest_row:
        import hashlib
        actual = hashlib.sha256((FIXTURES / digest_row["file"]).read_bytes()).hexdigest()
        _check(actual == digest_row["sha256"],
               "plan known-answer digest mismatch (fixture drifted from manifest)")


def run_registry_coherence(probe) -> None:
    manifest_rows = []
    for line in (FIXTURES / "manifest.jsonl").read_text(encoding="utf-8").splitlines():
        if line.strip():
            manifest_rows.append(json.loads(line))

    manifest_families = {row["family"] for row in manifest_rows}
    probe_families = set(probe.VALIDATORS)
    _check(manifest_families == probe_families,
           "manifest families {} != probe families {}".format(
               sorted(manifest_families), sorted(probe_families)))

    registry_doc = (ROOT / "docs" / "contracts" / "schema-registry.md").read_text(
        encoding="utf-8")
    doc_ids = set(re.findall(r"\bhf-[a-z0-9-]+/v[0-9]+\b", registry_doc))
    doc_families = {doc_id.rsplit("/", 1)[0] for doc_id in doc_ids}
    expected_ids = {family + "/v1" for family in probe_families}
    _check(doc_ids == expected_ids,
           "schema-registry.md ids {} != probe ids {}".format(
               sorted(doc_ids), sorted(expected_ids)))

    # AC2 coverage: every family needs accept, malformed, and unknown-version
    # rows in the manifest (refusal discrimination per stable surface).
    for family in sorted(probe_families):
        rows = [row for row in manifest_rows if row["family"] == family]
        kinds = {row["kind"] for row in rows if row["expect"] == "refuse"}
        has_accept = any(row["expect"] == "accept" for row in rows)
        _check(has_accept, "family {} lacks an accept fixture".format(family))
        _check("malformed" in kinds, "family {} lacks a malformed-refusal fixture".format(family))
        _check("unknown-version" in kinds,
               "family {} lacks an unknown-version-refusal fixture".format(family))

    # Every manifest row must resolve to a real tracked fixture file.
    for row in manifest_rows:
        _check((FIXTURES / row["file"]).is_file(),
               "manifest row points at missing fixture {}".format(row["file"]))


def main() -> int:
    try:
        probe = _load_probe()
        run_discrimination(probe)
        run_registry_coherence(probe)
    except Exception as exc:  # operational failure — never exit 0
        print("test-check-contract-fixtures: ERROR: {}".format(exc))
        return 3

    for failure in FAILURES:
        print("test-check-contract-fixtures: FAIL: {}".format(failure))
    if FAILURES:
        print("test-check-contract-fixtures: {} failure(s) of {} checks".format(
            len(FAILURES), CHECKS))
        return 1
    print("test-check-contract-fixtures: {} discrimination/coherence checks passed".format(CHECKS))
    return 0


if __name__ == "__main__":
    sys.exit(main())
