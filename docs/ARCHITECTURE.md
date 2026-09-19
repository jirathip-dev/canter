# Architecture

Current bootstrap vs approved target, boundaries, and dependency direction.
The locked target is documented in the committed architecture artifacts in
[`architecture/`](architecture/README.md) and in
[ADR-0001](decisions/0001-public-core-private-overlays.md),
[ADR-0002](decisions/0002-staging-integration-main-release.md), and
[ADR-0003](decisions/0003-companion-boundary-and-harness-neutrality.md).

## Current scaffold (as shipped)

One Cargo package (library + `canter` binary). The read-only CLI core
keeps a deliberately small dependency set (serde/toml/sha2); the daemon adds
bundled SQLite + flock (rusqlite/fs2/libc) for its single-writer state
store:

- Read-only CLI surface: `config init|validate|show`, `doctor`, `status`,
  `plan`, `capabilities`, and `service *-plan` — observing and rendering
  only, never mutating.
- Single-writer per-user state daemon: flock + migrated SQLite state,
  audit/event journals, one Unix socket; the only mutation path is the
  grant-gated daemon `apply` RPC (issue #8 semantics).
- Domain behavior as `src/` modules (plan/engine/lifecycle/mutation/
  observe/process/adapters/remote/backup/service) bound by the typed
  contract specs under [`contracts/`](contracts/README.md).
- Typed harness adapters at the edge: five official agent kinds — `hermes`,
  `claude-code`, `codex`, `pi`, `jcode` — plus Herdr/Git/GitHub surfaces.
- `tests/` — CLI, daemon RPC/lifecycle, mutation-engine, adapter-contract,
  service-plan, and no-network-surface suites (fake executables + synthetic
  fixtures only); `scripts/` — public-tree privacy scanner + self-tests;
  `.github/workflows/` — policy, rust (ubuntu + macOS), supply-chain, and
  secret-scan gates; `docs/architecture/` — committed diagram artifacts.

The [README](../README.md) as-shipped architecture diagram and
[OPERATIONS.md](OPERATIONS.md) are the authoritative current-state
walkthrough; the sections below record the approved target and the ecosystem
boundaries.

## Module split (approved target — as implemented)

The locked target keeps a harness-neutral core with adapters at the edge;
that is the module structure the shipped slices implement:

- **Plan/domain core** — typed workflow + plan engine, grants/digests,
  leases, idempotency, recovery. No product-name branching in domain types.
- **Adapters (edge, typed, small)** — Herdr (workspace/terminal/process
  execution), Git/GitHub (branches/PRs/checks/read-back), and **agent-harness
  adapters**. Hermes, Claude Code, Codex, and OpenCode may appear **only as
  adapter examples** in this repository; they are never core assumptions and
  none is promised to ship in any particular slice. Unsupported capabilities
  return typed refusals.
- **Separate axes**: harness, model/provider, role, skills, workflow, policy,
  repository, and execution substrate compose via configuration; none is
  inferred from another, and no model/provider names are compiled into core.

Dependency direction is strictly inward: adapters depend on the core; the
core depends on nothing external. Side-effect boundaries are explicit:
mutations are plan-first, digest-bound, journaled, and read back exactly;
production/destructive actions require fresh interactive TTY confirmation and
can never be scheduled; remote data is never shell-evaluated.

## Locked target core flow (for context)

```text
Operator + Route Grant -> CLI -> local daemon (sole state/transition
authority) -> typed workflow + plan engine -> typed effects + adapters
    -> Herdr · Git/GitHub · agent harnesses
```

- **XDG config**: one canonical TOML config plus one explicit optional
  private downstream policy overlay; no implicit profile/repository merge
  stack. The overlay is private/deployment-owned and never required by the
  public core.
- **SQLite state + audit**: leases, idempotency claims, schedules, journals,
  and recovery state; issues own intent, live read-back owns observed
  reality.
- **Trust boundary**: same-user TTY approval is an *accidental-safety*
  boundary, not cryptographic isolation; hardened isolation requires a
  separate OS principal/container plus external branch controls.
- **One daemon per host** on a per-user Unix socket; read-only CLI operations
  remain usable without the daemon.

## Control-layer model (current vs target)

The control chain — what drives a lane's next step — is recorded here in
**current vs target** terms. This is a documentation record; it authorizes no
structural change.

**Current:** `owner -> conductor model -> orchestrator model -> lanes`, with **two control planes registered** — the legacy fleet tooling and the canter daemon — so two controllers drive the same chain at once. Model-driven hops sit in the middle of the chain, and every model hop is a conversation turn: **a stalled hop stops the queue**. If any model-driven hop in the middle stalls — an exhausted capacity window, a wedged turn, a human waiting on a ruling — the whole chain stops even though the daemon and the lanes are healthy.

**Target:** `owner -> typed operator surface -> canter daemon (the only driver) -> execution substrate -> implementer/reviewer lanes`. The daemon is the only driver, and models are used only for lane work and exception escalation — **never as a required hop** in the control chain. A model stall then degrades to a waiting lane instead of a stopped queue: the daemon's typed refusals and honest states keep every control-plane outcome observable without a model in the loop.

## Scheduler-cutover truth

canter does **not** replace Hermes Agent, the Hermes scheduler as a
platform, Corral's daemon, Herdr's server, or unrelated research/office/host-
maintenance automation. Its planned scope is **portable fleet scheduling**
(pause/resume/rearm/supervision/recovery/cleanup for software-repository
fleets). A private host's cron/service/caller census and any legacy-scheduler
disposition are out of scope for this public project and remain private
concerns tracked elsewhere. **Issue #2 changes no live state**: no cron,
launchd, service, caller, daemon, live config, or runtime state is touched by
this repository's content.

## Layer responsibilities (Herdr hosts / canter tracks / Corral displays)

Each product owns one layer of a fleet lane's life:

- **Herdr hosts.** Herdr is the terminal/workspace layer: it owns the
  panes, worktrees, terminals, and the per-user server socket lanes run in.
  It detects its recognized agent kinds in panes, rolls their states up
  into the sidebar (`working`, `blocked`, `done`, `idle`, `unknown`), and
  exposes the `herdr agent` / `herdr pane` CLI and socket API.
- **canter tracks.** canter owns fleet state and discipline:
  plans, route grants, lanes/instances, review evidence, journals, epochs,
  and schedules live in its own single-writer daemon state store — never in
  Herdr, which canter observes but never controls (the
  [README](../README.md) as-shipped diagram; [OPERATIONS.md](OPERATIONS.md)).
  Where Herdr supports a custom reporting source, the shipped `pi`
  (issue #33) and `jcode` (issue #37) adapter profiles also report a lane
  into Herdr's sidebar through `herdr pane report-agent` custom rows
  (`--source custom:herdr-fleet-pi` / `--source custom:herdr-fleet-jcode`)
  with Herdr's semantic states — adapter-side reporting, contracted in
  [spec-capabilities.md](contracts/spec-capabilities.md).
- **Corral displays.** Corral is the optional, independent **read-only**
  display layer: `corrald` consumes Herdr's per-user socket and renders
  read-model boards. Corral has no runtime dependency on canter and
  canter none on Corral; an optional future Corral adapter that reads
  canter status for lanes Herdr cannot classify is an open idea —
  [Corral#443](https://github.com/jirathip-dev/corral/issues/443).

**Recognized vs unrecognized harnesses.** Herdr 0.9.0 spawns from a closed
list of recognized agent kinds — 23 kinds in the 0.9.0 measured for this
revision (`herdr agent start --help`, 2026-09-09; the list grows as Herdr
adds agents). jcode is a first-class canter adapter (issue #37) but
**not** a Herdr agent kind — by design, Herdr's owner declined an upstream
feature request. An unrecognized harness runs fine in a pane (it is an
ordinary terminal process) but gets no Herdr agent-kind lifecycle tracking,
so the agents-sidebar gap for such lanes is **not a defect**. canter's
daemon state above, plus the custom `pane report-agent` rows, are the
intended tracker: `pi` is also a recognized Herdr kind (`herdr agent start
--kind pi` starts interactive Pi panes), while headless adapter lanes report
through the custom rows; jcode registers through the custom rows only.
OPERATIONS.md section 3.1 describes monitoring an unrecognized-harness lane
from canter state instead of `herdr agent list`.

## Corral's actual current path (separate product)

```text
Herdr per-user Unix socket -> corrald -> FleetNotifier (iOS)
```

Corral is an independent, optional, **read-only** observability product. It
has no runtime dependency on canter, and canter has none on Corral.
If a concrete need ever justifies it, a future Corral adapter may consume the
versioned canter local read/event contract — shown **dashed** and
labeled **optional future adapter** in the committed diagram. Nothing in this
repository implies a required canter → Corral edge.

## YAGNI rule

No speculative structure is added before its first real owner exists. Each
shipped surface above landed with its owning slice's demonstrated need and
its own review; nothing speculative remains at the top level — no `domain/`,
`commands/`, `examples/`, plugin, or TUI directories, no async runtime, no
HTTP client crate, no tracing stack, and no dependency on clap. A future
slice may introduce each only with a demonstrated need and its own review.

## Corral reuse/provenance process

Corral's public evidence and discipline (see its issue trail) inform this
repository's gates — fmt-first CI, real RED/GREEN scanner proofs, no
`pull_request_target`, no `producer | grep -q` pass/fail, platform coverage
on both host families, blocking license/advisory checks. This repository
reuses that *discipline*, not Corral product code, app machinery, launchd
installers, or UI/demo tooling. Any future code reuse follows normal open-
source provenance (license-compatible, attributed), reviewed in the slice
that needs it.

## Contract artifacts (issue #3)

The locked 1.0 decisions are decomposed into machine-checked contract
artifacts under [`contracts/`](contracts/README.md): capability map,
schema registry, per-surface specifications (config, CLI output,
plans/grants/epochs/outcomes, workflow DAGs, daemon protocol, state and
journal, capability negotiation, review evidence), trust and risk models,
the Corral archaeology/provenance matrix, compatibility and benchmark
policy. Synthetic fixtures live under `schemas/fixtures/` and are verified
by `scripts/check-contract-fixtures.py` + its self-test. The registry and
specs bind the approved target and — since the roadmap slices shipped — the
implemented surface: the `src/` modules, daemon, adapters, and migrations
described under "Current scaffold" above.

## Links

- Committed target artifacts: [`architecture/`](architecture/README.md)
- ADR-0001 (public core / private overlays), ADR-0002 (branch model),
  ADR-0003 (companion boundary + harness neutrality)
- 1.0 contracts (issue #3): [`contracts/`](contracts/README.md)
- [README](../README.md) · [DEVELOPMENT](DEVELOPMENT.md) ·
  [WORKFLOW](WORKFLOW.md) · [RELEASING](RELEASING.md)
