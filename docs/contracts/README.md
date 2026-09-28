# canter 1.0 contract artifacts

Refs #3 (Contracts), umbrella #1 (locked spec). This directory turns the
locked 1.0 product decisions into public, reviewable, machine-checked
contract artifacts. It authorizes **no implementation**: commands, the
daemon, adapters, workflows, and migrations are non-goals of #3
([issue body](https://github.com/jirathip-dev/canter/issues/3)).

## Evidence legend

Every document distinguishes **design commitment** (locked by issue #1's
locked-spec/architecture-decision comments; normative for later slices) from
**[awaiting-evidence]** claims (measured compatibility/performance facts that
do not exist yet because no implementation or benchmark run exists). AC10 of
#3 requires this distinction; prose that lacks a marker is a design
commitment.

## Deliverable map

| Issue #3 deliverable | Acceptance criteria | Artifact |
| --- | --- | --- |
| Capability map (RETAIN / MERGE / SEPARATE / RETIRE, rationale, dependency order) | AC1 owner + dependency position | [capability-map.md](capability-map.md) |
| Versioned specs + fixtures: XDG config + policy overlay | AC2 | [schema-registry.md](schema-registry.md) · [spec-config.md](spec-config.md) · fixtures under [`schemas/fixtures/config/`](../../schemas/fixtures/config/config.valid.toml), [`schemas/fixtures/policy/`](../../schemas/fixtures/policy/policy.valid.toml) |
| Versioned specs + fixtures: identities/observations/errors/exit codes/partial-freshness/human-vs-JSON | AC2 | [spec-cli.md](spec-cli.md) · `hf-error/v1`, `hf-output/v1`, `hf-observation/v1` fixtures |
| Versioned specs + fixtures: plans/digests/grants/epochs/idempotency keys/typed outcomes | AC2 · AC3 | [spec-plans.md](spec-plans.md) · `hf-plan/v1`, `hf-grant/v1`, `hf-epoch/v1`, `hf-outcome/v1` fixtures |
| Versioned specs + fixtures: closed typed workflow DAGs + canonical hashing/serialization | AC2 | [spec-workflow.md](spec-workflow.md) · `hf-workflow/v1` fixtures |
| Versioned specs + fixtures: lifecycle (recurring non-destructive schedules, fan-out admission, cleanup archive/salvage, remote transport contract, cold-boot recovery) | AC1 · AC2 · AC5 · AC6 · AC7 · AC8 · AC9 · AC10 | [spec-lifecycle.md](spec-lifecycle.md) · `hf-schedule/v1` fixtures |
| Versioned specs + fixtures: daemon request/response + JSONL events | AC2 | [spec-daemon.md](spec-daemon.md) · `hf-rpc-request/v1`, `hf-rpc-response/v1`, `hf-event/v1` fixtures |
| Versioned specs + fixtures: SQLite migration/journal/audit, backup/restore, retention | AC2 · AC6 · AC7 | [spec-state.md](spec-state.md) · `hf-migration/v1`, `hf-audit/v1` fixtures |
| Versioned specs + fixtures: harness + forge capability negotiation | AC2 | [spec-capabilities.md](spec-capabilities.md) · `hf-capability/v1` fixtures |
| Review evidence contract | AC4 | [spec-review-evidence.md](spec-review-evidence.md) · `hf-evidence/v1` fixtures |
| Trust model | — | [trust-model.md](trust-model.md) |
| Daemon-owned fail-closed target/risk model | AC5 | [risk-model.md](risk-model.md) |
| Corral archaeology matrix (REUSE/ADAPT/LEARN/REJECT + provenance) | AC8 · AC9 | [corral-archaeology.md](corral-archaeology.md) |
| Tested Herdr + `gh` compatibility policy; doctor boundary | — | [compatibility.md](compatibility.md) |
| Benchmark corpus + method | AC10 | [benchmarks.md](benchmarks.md) |
| Fixtures pass privacy/public-tree gate | AC8 | fixture corpus + `scripts/check-public-tree.py`; no downstream identifiers or machine paths |
| Malformed/unknown-version refusal probes | AC2 | [Fixture checks](#fixture-checks) |

## Fixture checks

The fixture corpus is machine-checked by a stdlib probe in the repository's
fail-closed scanner style (deterministic exit codes, no network):

```text
python3 scripts/check-contract-fixtures.py      # manifest expectations
python3 scripts/test-check-contract-fixtures.py # tamper discrimination + coherence
```

`check-contract-fixtures.py` asserts every manifest row
([`schemas/fixtures/manifest.jsonl`](../../schemas/fixtures/manifest.jsonl)):
accept fixtures validate, malformed fixtures are refused, unknown-version
fixtures are refused with the version refusal, non-canonical bytes are
refused for canonical families, and known-answer `sha256` digests hold.
`test-check-contract-fixtures.py` mutates committed fixtures in temp copies
to prove each refusal rule bites, and enforces that this table,
`schema-registry.md`, the probe registry, and the manifest name the same 20
families with the same coverage.

Gate wiring: the probe is deliberately **not** referenced from `justfile` or
workflow files in this slice (those paths are owned elsewhere this round;
see the lane fence). Wiring them into `just ci`/CI is a one-line follow-up
for the owning lane once #3 merges.

## Reading order

1. [capability-map.md](capability-map.md) — what 1.0 is, owner by owner
2. [schema-registry.md](schema-registry.md) — every serialized surface at a glance
3. Per-surface specs (config, CLI, plans/grants, workflow, daemon, state,
   capabilities, review evidence)
4. [trust-model.md](trust-model.md) · [risk-model.md](risk-model.md)
5. [corral-archaeology.md](corral-archaeology.md) — public provenance for every
   candidate seam
6. [compatibility.md](compatibility.md) · [benchmarks.md](benchmarks.md) —
   measured-fact policy and how facts will be produced

Privacy: every committed artifact in this set is synthetic and passes the
public-tree gate (AC8). Do not add real repository names, host paths,
credentials, or downstream policy here.
