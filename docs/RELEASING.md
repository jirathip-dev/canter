# Releasing

**Active for the in-repo release-readiness machinery (issue #10); release
EXECUTION remains human-gated.** This repository ships the machine-provable
parts of the release contract — a deterministic archive builder with
checksums/SBOM/provenance, verification instructions, clean-host
verification scripts, and a committed baseline — but it performs **no**
release by itself. Every release remains a separate human decision
(promotion, tag, upload, attestation, soak), exactly as the roadmap
umbrella (https://github.com/jirathip-dev/canter/issues/1) requires.
Nothing in this file authorizes an agent or CI run to tag, publish,
promote, or upload.

Status summary:

| Part | Status |
| --- | --- |
| Archive builder + checksums + SBOM + provenance (`scripts/build-archive.py`) | Active in-repo; self-tested (`scripts/test-build-archive.py`) |
| Clean-host verification scripts (`scripts/clean-host-verify.sh`, `scripts/clean-host-probe.py`) | Active in-repo; self-tested fixture-level; **real clean-host runs are a human gate** |
| Version/schema policy below | Active (this document + [schema-registry.md](contracts/schema-registry.md)) |
| Compatibility/baseline evidence rows | [compatibility.md](contracts/compatibility.md), [benchmarks.md](contracts/benchmarks.md) + committed baseline CSV |
| Promotion, tagging, GitHub Releases upload, Sigstore attestation, 30-day soak, 1.0 RC | **Human-gated** — not runnable from this repository |
| Shell completions/manpages generation | Not implemented in the bootstrap (no completion framework in the hand-rolled parser); tracked as a follow-up before 1.0 (`Refs #10`) |
| Package-manager channels (crates.io/Homebrew/plugins) | **Absent by contract** until a later slice proves real consumer demand (see [ADR-0003](decisions/0003-companion-boundary-and-harness-neutrality.md)); GitHub Releases is the sole canonical 1.0 channel |

## Sources and channels

- **`main` is the only release source**, after human promotion from
  `staging` ([WORKFLOW.md](WORKFLOW.md)) and a human-approved on-demand
  release issue (below). Feature work never targets `main`.
- GitHub Releases is the sole canonical distribution channel through 1.0.
  No crates.io/Homebrew/plugin manifest publication exists in this
  repository (see [ADR-0003](decisions/0003-companion-boundary-and-harness-neutrality.md)).
- Release-blocking archives are built on **standard public GitHub-hosted
  runners** for macOS arm64/x86_64 and Linux arm64/x86_64 — no larger/paid
  or permanent self-hosted release runner.
- Shipped binaries never self-update and have no auto-update/telemetry
  surface (enforced statically by `tests/no_network_surface.rs`); an
  explicit read-only update check remains a possible future opt-in, never a
  silent background behavior.

## Version and schema policy

Product versioning is SemVer (MAJOR.MINOR.PATCH). Schema versioning is
explicit and separate (see [schema-registry.md](contracts/schema-registry.md)):

- Every stable serialized surface carries a versioned identifier
  (`hf-<family>/v<version>`; 18 families today) plus the SQLite state schema
  version (`SCHEMA_VERSION`, currently 13, applied by the migration chain
  `m0001`..`m0013` — queryable from any binary via `canter --version`).
- **Breaking a stable schema requires a migration and a MAJOR release.** A
  migration that changes serialized state or document semantics is
  additive and versioned (`m000N`); unknown-version documents are refused
  fail-closed (never tolerated silently).
- **The latest minor release receives fixes** while its compatible 1.x
  interfaces remain supported; support commitments are documented in
  [compatibility.md](contracts/compatibility.md) and
  [SECURITY.md](../SECURITY.md).
- Through the 1.0 RC, schemas are explicitly experimental: 0.x milestones
  may change schemas with migrations and a minor/major bump per the rules
  above, and nothing promises cross-0.x stability beyond the fail-closed
  versioning machinery.
- Runtime/schema/workflow/migration changes reset the 1.0 soak clock;
  docs-only changes do not when the release bytes are unchanged (the
  migration records make the determination auditable — see
  [spec-state.md](contracts/spec-state.md)).

## Release-blocking archives

Every release ships four archives, one per platform token
(`linux-x86_64`, `linux-aarch64`, `darwin-x86_64`, `darwin-aarch64`):

```text
canter-<version>-<platform>.tar.gz
canter-<version>-<platform>.tar.gz.sha256   (adjacent archive checksum)
```

Archive layout (deterministic; documented by
[`scripts/build-archive.py`](../scripts/build-archive.py)):

```text
canter-<version>/
  canter            platform-correct executable (755)
  LICENSE-APACHE
  LICENSE-MIT
  SBOM.spdx.json         SPDX 2.3, derived OFFLINE from Cargo.lock
  SHA256SUMS             per-file sha256 manifest (payload files)
  provenance.json        release-provenance/v1 record (below)
```

The metadata layer is byte-deterministic for a fixed source ref + version +
input binary (fixed member mtimes, fixed gzip framing). Binary
reproducibility across toolchains is not claimed; instead the artifact is
**mapped back** to its provenance record at verification time (checksums +
the binary's self-reported version/schema facts).

`provenance.json` (`record: release-provenance/v1`) binds:

- the product version + platform token,
- the **exact recorded source ref** (40-hex commit; the builder refuses to
  run unless the checkout HEAD equals it and the tracked tree is clean),
- **schema facts reported by the binary itself** (`--version`: state schema
  version, migration chain, all document schema families),
- per-file SHA-256 digests (matching `SHA256SUMS`), and
- the SBOM digest.

## Documented command rows (human executes at release time)

Build (on each platform runner, from the exact release commit checkout):

```console
$ cargo build --release --locked
$ python3 scripts/build-archive.py build \
    --repo . \
    --source-ref "$(git rev-parse HEAD)" \
    --version <version> \
    --binary target/release/canter \
    --platform linux-x86_64 \
    --out-dir target/release-archives
```

Verify (any host, against the downloaded archive + adjacent `.sha256`):

```console
$ python3 scripts/build-archive.py verify --archive canter-<version>-<platform>.tar.gz
```

The verify step re-runs the archived binary's `--version` and checks it
against the provenance record, recomputes every file digest, and checks the
adjacent checksum file — the full AC1 machine chain. Self-test of the
builder (any checkout):

```console
$ python3 scripts/test-build-archive.py
```

Clean-host verification (AC2; see also
[compatibility.md](contracts/compatibility.md) for the real authenticated
harness smokes that stay separate, issue #7 AC6). On **fresh macOS and
Linux maintainer hosts**, from a checkout of the exact release commit with
the downloaded archive binary:

```console
$ scripts/clean-host-verify.sh --bin /path/to/extracted/canter --repo /path/to/release-tree
```

It runs, with no private repositories and no service-manager activation:
help/version (schema facts present), config init + validate (synthetic),
`service install/status/uninstall-plan` rendering, and a disposable-temp-dir
daemon round trip (`scripts/clean-host-probe.py`): boot + status/epoch,
`backup.create` → `restore.begin` (epoch rotation) → post-restore
mutation, a synthetic `hf-schedule/v1` lifecycle (create/list/pause/
resume/delete on the committed fixture), a fail-closed `apply` refusal
without an idempotency key, and one `hf-event/v1` snapshot line.
Fixture-level self-test (runs the same checks against a locally built
binary):

```console
$ python3 scripts/test-clean-host-probe.py
```

Baselines (AC5; see [benchmarks.md](contracts/benchmarks.md)):

```console
$ python3 scripts/measure-baseline.py measure --binary target/release/canter \
    --out baseline-<platform>.csv
$ python3 scripts/measure-baseline.py check --binary target/release/canter \
    --baseline baseline-<platform>.csv
```

The committed reference baseline for the current release is
[`docs/contracts/baseline-linux-x86_64.csv`](contracts/baseline-linux-x86_64.csv).
Baseline checks are **not** CI gates (wall-clock budgets on shared runners
would flake); they are opt-in on the reference host class.

## Release issue/PR contract (on-demand)

A release starts with a human-authored on-demand release issue carrying, at
minimum:

- the exact version (SemVer) and the schema-version delta (state schema,
  migration chain, any document-family bumps),
- a curated changelog plus structured PR history since the last release,
- the compatibility matrix rows ([compatibility.md](contracts/compatibility.md)),
- the exact source commit (main tag after promotion),
- CI/review evidence for the exact head,
- clean-host evidence (AC2 runs above) and, where applicable, the redacted
  exact-version authenticated harness smoke results (AC3, issue #7 AC6 —
  never full logs, only redacted version rows),
- rollback notes (restore/epoch machinery in
  [spec-state.md](contracts/spec-state.md); `hotfix/*` path in
  [WORKFLOW.md](WORKFLOW.md)).

## 1.0 process

The 1.0 flow stays human-gated end to end:

1. Validate the qualification artifacts from **frozen staging** (release
   issue evidence above).
2. Human-promote the exact tree to `main` (dedicated promotion PR).
3. Human tag `v1.0.0-rc.N` on `main`; build + attest on public runners.
4. Run the live 30-day soak; any executable/config-schema/workflow/
   migration change produces a new RC and resets the clock (docs-only
   changes do not when release bytes are unchanged).
5. Human tag `v1.0.0` on the fully soaked main commit after the private
   zero-reference/archive gates verify.

## Checksums, SBOM, provenance, attestation

- Every archive ships with an adjacent `.sha256`; publishing verifies
  checksums before upload and never uploads unverified artifacts.
- SBOM is generated offline from the committed `Cargo.lock` (SPDX 2.3).
- GitHub release provenance attestations and Sigstore signatures are
  created by the human release run on the GitHub side (per the release
  issue evidence), and the verification instructions above are the
  machine-checkable complement.

## Rollback notes

State rollback uses the daemon's snapshot/restore + epoch rotation
machinery ([spec-state.md](contracts/spec-state.md),
[spec-lifecycle.md](contracts/spec-lifecycle.md)); code rollback of a bad
release is the documented `hotfix/*` + reconciliation path in
[WORKFLOW.md](WORKFLOW.md). A release that is found bad after upload is
yanked at the GitHub side (human action) and superseded by a patch release
per the SemVer rules above.
