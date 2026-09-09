# AGENTS.md — repository contract for coding agents


canter is a **public** repository. The surfaces shipped on `staging`
are implemented and proven by tests that use synthetic fixtures and fake
executables only: a read-only CLI core, a single-writer local daemon
(SQLite state + per-user Unix socket RPC), a deterministic workflow engine
with the bundled Doctrine default workflow, harness adapters, a grant-gated
daemon-mediated mutation path, lifecycle safety, and release-readiness
tooling. **Live workflow execution, release execution, and real harness
sessions are not proved end-to-end and never run from public CI or fork
PRs** — they remain human-gated (see "Shipped vs unverified" below). The
repository itself never mutates real repositories, fleets, or external
state. The umbrella issue #1 tracks the delivery graph; the shipped slices
are listed in [README.md](README.md) (Roadmap).

## Ownership map

Every path below exists at the reviewed head; keep the map accurate when a
slice lands.

| Area | Canonical files |
| --- | --- |
| Library surface | `src/lib.rs` |
| CLI entry, parsing, execution | `src/main.rs`, `src/commands.rs` |
| Read-only observation + plan rendering | `src/observe.rs`, `src/plan.rs`, `src/process.rs` |
| Config/policy model (`hf-config/v1`, `hf-policy/v1`) | `src/config.rs` |
| Schema validators, value model, canonical bytes, redaction | `src/schema.rs`, `src/value.rs`, `src/canonical.rs`, `src/redact.rs`, `src/formats.rs`, `src/time.rs` |
| Daemon, state, lock, RPC client, paths, backup | `src/daemon.rs`, `src/state.rs`, `src/lock.rs`, `src/client.rs`, `src/dirs.rs`, `src/backup.rs` |
| Workflow engine + bundled Doctrine default | `src/engine.rs` |
| Harness adapters (Hermes, Claude Code, Codex, Pi, Jcode, generic argv) | `src/adapters.rs` |
| Control-plane mutations (daemon `apply` path) | `src/mutation.rs` |
| Lifecycle: schedules, admission, cleanup, remote | `src/lifecycle.rs`, `src/remote.rs` |
| Service unit plans (launchd/systemd) | `src/service.rs` |
| Behavior + integration tests | `tests/` (`cli_smoke`, `cli_readonly`, `daemon_rpc`, `daemon_lifecycle`, `mutation_engine`, `harness_adapters`, `herdr_compatibility`, `service_plans`, `no_network_surface`) |
| Privacy scanner + self-tests | `scripts/check-public-tree.py`, `scripts/test-check-public-tree.py` |
| Contract fixture oracle | `scripts/check-contract-fixtures.py`, `scripts/test-check-contract-fixtures.py` |
| Release-readiness scripts + self-tests | `scripts/build-archive.py`, `scripts/clean-host-verify.sh`, `scripts/clean-host-probe.py`, `scripts/measure-baseline.py` (+ `test-*.py`) |
| Developer gates | `justfile` — canonical docs: `docs/DEVELOPMENT.md` |
| CI + security workflows | `.github/workflows/ci.yml`, `.github/workflows/security.yml` |
| Architecture docs + ADRs | `docs/ARCHITECTURE.md`, `docs/decisions/`, `docs/architecture/` |

| Contract corpus + fixtures | `docs/contracts/`, `schemas/fixtures/` |
| Process + operations docs | `docs/WORKFLOW.md`, `docs/OPERATIONS.md`, `docs/RELEASING.md` |
| Public skill | `skills/canter/SKILL.md` |

## Shipped vs unverified

- **Implemented and test-proven (synthetic fixtures / fake executables,
  no credentials, no network):** the read-only CLI (`config`, `doctor`,
  `status`, `plan`, `capabilities`, `service *-plan`); the single-writer
  daemon (`daemon run|status`, SQLite migrations, audit/event journals,
  Unix-socket RPC); the workflow engine and bundled Doctrine default;
  harness adapters for Hermes, Claude Code, Codex, Pi, Jcode, and the
  declarative generic argv adapter; the grant-gated daemon `apply` mutation
  path (one digest-bound, journaled step per request); lifecycle
  schedules/admission/cleanup/recovery; and release-readiness tooling
  (archives, SBOM, provenance, clean-host scripts).
- **Not proved end-to-end (do not present as done):** live workflow
  execution, release execution, and real harness sessions. Real harness
  parity is a human-gated clean-host smoke (issue #7); release execution is
  human-gated per `docs/RELEASING.md`; no live fleet cutover or real
  external-write canary is authorized by this repository. Public CI and
  fork PRs run with fake executables and synthetic fixtures only.

## Mandatory gates

Run the exact local aggregate before any PR: `just ci` (fmt-check → check →
lint → test → doc → build-release → security) and record raw exit codes;
never pipe a gate through grep as a pass/fail test. `just security` requires
gitleaks — a missing tool is a failure, not a skip. The canonical gate
list, prerequisites, and CI-parity table live in `docs/DEVELOPMENT.md`.
Hosted CI mirrors the gates plus policy checks (promotion policy, forbidden
workflow triggers, full-SHA action pins, scanner self-test, required files,
documentation links, staging guard) and secret scans.

## Public-data boundary (hard rule)

Never commit host paths, private repository names, credentials/secret-shaped
content, provider/model policy, or live scheduler identity. The tracked
tree is machine-scanned on every PR (git-index parser + gitleaks); rules are
proven by self-tests. Synthetic `.example` files are permitted; real
credential-class files are rejected. When in doubt, keep it out.

## Branch discipline

- Feature/dependency PRs target `staging` (never `main`). No direct pushes
  to `staging` or `main`; only PR squash merges, linear history.
- Promotion to `main` is a dedicated human-only PR (`staging` → `main`); a
  narrow `hotfix/*` exception exists for incidents (fresh human approval +
  mandatory reconciliation). Details: `docs/WORKFLOW.md`.
- Release-readiness machinery is active in-repo; release execution
  (promotion, tag, upload, attestation, soak) is human-gated and never runs
  from CI or agent lanes. GitHub Releases is the sole canonical channel; no
  crates.io/Homebrew/plugin-manifest publication exists — see
  `docs/RELEASING.md`.

## Smallest-change discipline

- Prefer the smallest correct diff that satisfies the issue; stdlib first.
  Add a dependency only where a shipped slice proves the need (current set:
  `serde`/`toml`/`sha2` in the read-only core; `rusqlite`/`fs2`/`libc` in
  the daemon). No clap/async/HTTP/tracing.
- No speculative structure: each surface landed with its owning slice and
  its own review; do not add modules, directories, or abstractions before
  their first real owner exists.
- Keep one fact authoritative and link to it: `docs/DEVELOPMENT.md` (gates),
  `docs/ARCHITECTURE.md` (modules and boundaries), `docs/WORKFLOW.md`
  (process), `docs/contracts/` (normative contracts).
- This file describes the repository as it is; it authorizes no work. Work
  starts from an issue routed per `docs/WORKFLOW.md`, and nothing here
  authorizes live execution, release execution, or live fleet mutation.
- Commit wording: `Refs #N` (never `Fixes`/`Closes`/`Resolves`).

## License

Apache-2.0 OR MIT (see LICENSE-APACHE, LICENSE-MIT). DCO not adopted.
