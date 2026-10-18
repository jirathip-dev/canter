# Schema registry — every stable serialized surface (AC2)

Refs #3 (deliverable "versioned specifications and synthetic fixtures") and
umbrella #1 (locked spec). This registry is the AC2 checklist: every stable
serialized surface has a schema identifier, a compatibility rule, a
canonical bytes/hash rule where relevant, and malformed/unknown-version
refusal fixtures.

The machine-readable half of these rules lives in
[`scripts/check-contract-fixtures.py`](../../scripts/check-contract-fixtures.py)
(family validators) and the fixture manifest at
[`schemas/fixtures/manifest.jsonl`](../../schemas/fixtures/manifest.jsonl).
The self-test
[`scripts/test-check-contract-fixtures.py`](../../scripts/test-check-contract-fixtures.py)
asserts that this table, the validator registry, and the manifest name the
same families — the three cannot drift apart.

## Versioning and compatibility rule (all families)

- A schema identifier encodes family and version: `hf-<family>/v<version>`.
- A document whose identifier names a known family with an unsupported
  version is refused with `REFUSE_VERSION` (unknown-version refusal).
- A document whose identifier is missing or names an unknown family is
  refused with `REFUSE_SCHEMA`.
- v1 envelopes are **closed surfaces**: unknown keys and values outside the
  documented closed sets are refused (`REFUSE_MALFORMED`). Compatibility
  changes therefore require a new schema version (fail closed), not silent
  tolerance.
- Canonical JSON bytes: UTF-8 of the JSON value with keys sorted
  lexicographically, compact separators (`,` and `:`), ASCII escaping, and a
  single trailing LF. Where the rule says "canonical", documents that are
  semantically valid but not byte-canonical are refused with
  `REFUSE_NONCANONICAL`.
- Digests: `sha256` over the canonical bytes, lowercase hex.

## Registry

| Schema id | Stable surface | Spec | Canonical bytes/hash | Fixtures (valid / malformed / unknown-version) |
| --- | --- | --- | --- | --- |
| `hf-config/v1` | Canonical XDG TOML configuration | [spec-config.md](spec-config.md) | No canonical-bytes rule (TOML) | `config/config.valid.toml`, `config/config.malformed.toml`, `config/config.unknown-version.toml` |
| `hf-policy/v1` | Explicit optional policy overlay (constrain-only) | [spec-config.md](spec-config.md) | No canonical-bytes rule (TOML) | `policy/policy.valid.toml`, `policy/policy.malformed.toml`, `policy/policy.unknown-version.toml` |
| `hf-output/v1` | CLI `--json` output envelope (human-vs-JSON, exit codes, partial results) | [spec-cli.md](spec-cli.md) | No canonical-bytes rule | `output/output.valid.json`, `output/output.partial.valid.json`, `output/output.error.valid.json`, `output/output.malformed.json`, `output/output.unknown-version.json` |
| `hf-error/v1` | Typed error envelope | [spec-cli.md](spec-cli.md) | No canonical-bytes rule | `error/error.valid.json`, `error/error.malformed.json`, `error/error.unknown-version.json` |
| `hf-observation/v1` | Normalized observation with freshness/partial states | [spec-cli.md](spec-cli.md) | No canonical-bytes rule | `observation/observation.valid.json`, `observation/observation.malformed.json`, `observation/observation.unknown-version.json` |
| `hf-plan/v1` | Deterministic plan | [spec-plans.md](spec-plans.md) | **Canonical + digest** (sha256 pinned in manifest) | `plan/plan.valid.json`, `plan/plan.noncanonical.json`, `plan/plan.malformed.json`, `plan/plan.unknown-version.json` |
| `hf-grant/v1` | Route grant (AC3 bindings) | [spec-plans.md](spec-plans.md) | No canonical-bytes rule (fields are hash-bound, not the grant bytes) | `grant/grant.valid.json`, `grant/grant.malformed.json`, `grant/grant.unknown-version.json` |
| `hf-epoch/v1` | State epoch record (restore rotation, AC7) | [spec-plans.md](spec-plans.md) | No canonical-bytes rule | `epoch/epoch.initial.valid.json`, `epoch/epoch.restore.valid.json`, `epoch/epoch.malformed.json`, `epoch/epoch.unknown-version.json` |
| `hf-outcome/v1` | Typed step outcome (idempotency-keyed) | [spec-plans.md](spec-plans.md) | No canonical-bytes rule | `outcome/outcome.succeeded.valid.json`, `outcome/outcome.failed.valid.json`, `outcome/outcome.malformed.json`, `outcome/outcome.unknown-version.json` |
| `hf-workflow/v1` | Closed typed workflow DAG | [spec-workflow.md](spec-workflow.md) | **Canonical + digest** (sha256 pinned in manifest) | `workflow/workflow.valid.json`, `workflow/workflow.noncanonical.json`, `workflow/workflow.malformed.json`, `workflow/workflow.unknown-version.json` |
| `hf-schedule/v1` | Recurring non-destructive grant cadence (issue #9) | [spec-lifecycle.md](spec-lifecycle.md) | canonical JSON (stored in the `schedules.doc` column) | `schedule/schedule.valid.json`, `schedule/schedule.malformed.json`, `schedule/schedule.unknown-version.json` |
| `hf-rpc-request/v1` | Daemon request (per-user Unix socket) | [spec-daemon.md](spec-daemon.md) | No canonical-bytes rule | `rpc/request.status.valid.json`, `rpc/request.apply.valid.json`, `rpc/request.malformed.json`, `rpc/request.unknown-version.json` |
| `hf-rpc-response/v1` | Daemon response | [spec-daemon.md](spec-daemon.md) | No canonical-bytes rule | `rpc/response.ok.valid.json`, `rpc/response.error.valid.json`, `rpc/response.malformed.json`, `rpc/response.unknown-version.json` |
| `hf-event/v1` | Local JSONL event protocol (one event per line) | [spec-daemon.md](spec-daemon.md) | Sequence numbers are canonical ordering keys | `event/events.valid.jsonl`, `event/events.malformed.jsonl`, `event/events.badline.jsonl`, `event/events.unknown-version.jsonl` |
| `hf-audit/v1` | Journal/audit record (JSONL; journal-before-mutation) | [spec-state.md](spec-state.md) | Monotonic `seq` per journal | `audit/audit.valid.jsonl`, `audit/audit.malformed.jsonl`, `audit/audit.unknown-version.jsonl` |
| `hf-migration/v1` | SQLite migration manifest | [spec-state.md](spec-state.md) | No canonical-bytes rule (migration checksum covers the migration artifact) | `migration/migration.valid.json`, `migration/migration.malformed.json`, `migration/migration.unknown-version.json` |
| `hf-capability/v1` | Harness/forge capability negotiation envelope | [spec-capabilities.md](spec-capabilities.md) | No canonical-bytes rule | `capability/capability.harness.valid.json`, `capability/capability.forge.valid.json`, `capability/capability.malformed.json`, `capability/capability.unknown-version.json` |
| `hf-evidence/v1` | Review evidence record (AC4 bindings) | [spec-review-evidence.md](spec-review-evidence.md) | No canonical-bytes rule | `evidence/evidence.valid.json`, `evidence/evidence.malformed.json`, `evidence/evidence.unknown-version.json` |
| `hf-board/v1` | Bounded paginated board read page (issue #83 read model) | [spec-board.md](spec-board.md) | No canonical-bytes rule | `board/board.valid.json`, `board/board.page.valid.json`, `board/board.malformed.json`, `board/board.unknown-version.json` |
| `hf-escalation/v1` | Read-only escalation listing page (issue #208, the ORCH + CANTER contract) | [spec-escalations.md](spec-escalations.md) | No canonical-bytes rule; `cursor` is the (raised_at, id) ordering key of the last row | `escalation/escalation.valid.json`, `escalation/escalation.page.valid.json`, `escalation/escalation.malformed.json`, `escalation/escalation.unknown-version.json` |

## Embedded scalar formats (no standalone document)

These formats are stable serialized values that appear **inside** the
envelopes above; their malformed/unknown-value refusal is exercised through
the containing family fixtures:

| Format | Rule | Refusal exercised by |
| --- | --- | --- |
| Plan id | `hf_plan_` + 16 lowercase hex | `plan/plan.valid.json` vs grant referencing a malformed plan id (`grant/grant.malformed.json` covers missing bindings) |
| Grant id | `gr_` + 16 lowercase hex | audit/grant fixtures |
| Evidence id | `ev_` + 16 lowercase hex | `evidence/*` fixtures |
| Run id (daemon) | `run-` + 16 lowercase hex | `escalation/*` fixtures (`hf-escalation/v1` names exactly one durable run record) |
| Escalation id | `esc_` + 16 lowercase hex (content-derived and stable across reads) | `escalation/*` fixtures |
| Plan step id | the plan's own step id (`p1`, `p6-12`) | `escalation/*`, `outcome/*` fixtures |
| Request id (daemon) | 8-64 lowercase hex | `rpc/*` fixtures |
| Idempotency key | `ik_` + 8-64 `[a-z0-9-]` | `rpc/request.malformed.json` (apply without key refused), `outcome/*`, `audit/*` |
| Repository identity | `owner/name`, no protocol prefix | plan/grant/observation fixtures |
| Issue binding | exact issue number + 40-hex acceptance revision | plan/grant fixtures |
| SHA-256 digest / SHA-1 commit | 64 / 40 lowercase hex | plan/workflow/evidence fixtures |
| Timestamps | RFC3339 UTC, seconds precision, `Z` suffix | all time-bearing fixtures |
| State epoch | non-negative integer | plan/grant/epoch/audit fixtures |

## Coverage rules (enforced by the self-test)

- Every family has at least one accept fixture, one malformed-refusal
  fixture, and one unknown-version-refusal fixture.
- Canonical families (`hf-plan/v1`, `hf-workflow/v1`) carry a non-canonical
  refusal fixture and a known-answer `sha256` in the manifest.
- Fixture content is synthetic: no downstream repository identifiers, no
  absolute host paths, no credentials. The public-tree gate
  ([`scripts/check-public-tree.py`](../../scripts/check-public-tree.py))
  scans every fixture on every PR.
