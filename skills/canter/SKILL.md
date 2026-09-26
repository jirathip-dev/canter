---
name: canter
description: "Use when working with or on the canter repository or CLI. Read-only CLI core (config/doctor/status/plan/capabilities), single-writer daemon (run/status), service unit plans, and grant-gated mutations via the daemon apply RPC; no live harness runs."
version: 1.11.0
author: canter contributors
license: Apache-2.0 OR MIT
platforms: [macos, linux]
metadata:
  hermes:
    tags: [canter, cli, fleet, repository, read-only-core, operations]
---

# canter

canter is a public companion CLI for operating Herdr coding-agent
fleets. Roadmap slices #3-#10 are merged on `staging` (PRs #13-#21): a
read-only CLI core (#4), a daemon foundation with SQLite state and a local
socket RPC (#5), the deterministic workflow engine with the bundled
Doctrine default workflow (#6), the capability-negotiated harness adapters
(#7: Hermes, Claude Code, Codex + a declarative generic argv adapter;
#33 adds Pi, earendil-works/pi, with a measured 0.85.1 floor; #37 adds
Jcode, 1jehuang/jcode, with a measured 0.84.0 floor — all
verified with fake-executable contract tests that need no credentials), the
control-plane mutation layer (#8: the daemon mediates plan `apply` — one
typed, digest-bound, capability-gated plan step per request — with durable
review-evidence rows, recorded first-real-write approvals, and
worktree-confined harness execution), the lifecycle layer (#9: durable
recurring non-destructive schedules with single-flight/coalesced evaluation
and cold-boot recovery, fan-out admission, cleanup archive/salvage with
byte-verified manifests, a verified system-SSH remote transport contract,
and retention-bounded backup pruning), and the release-readiness layer
(#10: deterministic platform archives with checksums, offline SPDX SBOM,
release provenance; clean-host verification; measured baselines; in-repo
release policy). The daemon never starts/stops Herdr, the CLI never mutates
repositories or fleet state directly, and no live workflow execution,
release execution, or real harness session runs from public CI (those are
human-gated). Issue #35 verifies Herdr 0.9.0's current behavior with isolated
live probes and portable contract tests: same-version protocol 22 is green,
while both 0.8.2/protocol-20 mixed directions fail closed. The doctor minimum
therefore remains 0.8.2 and is not a mixed-server compatibility claim.

## When to use

- You are contributing to the canter repository (Rust, docs,
  contracts, CI).
- You need to know what the CLI does today — or operate it read-only —
  without guessing.

## Product name and pre-rename compatibility (issue #106)

The product/repository is `canter` (renamed from `herdr-fleet`; old GitHub
URLs redirect). The pre-rename binary name, state/runtime tree, config path,
and debug crash-point env var keep working, and live Herdr integration ids
keep their pre-rename spelling — the normative list is
`docs/contracts/compatibility.md` ("Product rename (issue #106)"). Use
`canter` in new work; do not rename live registry/session identity.

## Safe discovery (read-only, no side effects)

1. Index and status: `README.md` (current surface, boundaries, quickstart).
2. Operations runbook: `docs/OPERATIONS.md` (task-ordered; every claim
   exercised against the real binary).
3. Contracts: `docs/contracts/README.md` (schema registry, specs for
   CLI/config/plans/daemon/state/capabilities, capability-map,
   compatibility — the #3 corpus this surface implements).
4. Canonical gates: `docs/DEVELOPMENT.md` (`just ci` is the full local
   aggregate).
5. Process: `docs/WORKFLOW.md`; architecture: `docs/ARCHITECTURE.md` and
   the ADRs under `docs/decisions/`.
6. Repository contract for agents: `AGENTS.md` (public-data boundary,
   branch discipline, smallest-change rule).
7. To inspect the compiled binary (after `cargo build --locked`):
   `canter --help`, then per command.

## Command surface (100% of `--help`; classification per command)

| Command | Classification | Behavior |
| --- | --- | --- |
| `config init` | read-only | Prints an annotated `hf-config/v1` TOML template to stdout (writes nothing). |
| `config validate [--config PATH] [--json]` | read-only | Validates the config document and its named policy overlay (exit 5 refusals on unknown keys/versions/overlays). |
| `config show [--config PATH] [--json]` | read-only | Renders the effective configuration (repositories, identities, harnesses, daemon, policy). |
| `doctor [--json]` | read-only | Checks git/herdr(>=0.8.2)/gh + config; never installs/starts anything. Exit 0 ok, 3 missing/degraded, 5 invalid config. |
| `status [--config PATH] [--json]` | read-only | Bounded observation of configured repositories from inside the local checkout (git + authenticated `gh` + herdr probe); degradation explicit. |
| `plan <repository> <issue> [--revision HEX40] [--config PATH] [--json]` | read-only (renders; NEVER applies) | Deterministic `hf-plan/v1` with canonical sha256 digest + redacted acceptance-revision binding. |
| `capabilities [--json]` | read-only | Declared forge read capabilities (`read_refs`, `read_issues`, `read_checks`). |
| `daemon run [--socket PATH] [--config PATH]` | local state server (no fleet/external mutation) | Foreground single-writer daemon: flock, SQLite state open/migrated, interrupted-claim reconciliation, `hf-rpc/v1` on the per-user Unix socket. Second daemon refused. |
| `daemon status [--config PATH] [--json]` | read-only probe | Live daemon + state facts; exit 1 `daemon.absent`/`daemon.stale` when not running. |
| `service doctor [--config PATH] [--json]` | read-only | Daemon-environment checks (platform, config, socket, unit placement). |
| `service install-plan [--config PATH] [--json]` | read-only (renders; never activates) | Renders the per-user launchd/systemd unit text + install steps. |
| `service status-plan [--config PATH] [--json]` | read-only (renders) | Renders verification steps for the unit. |
| `service uninstall-plan [--config PATH] [--json]` | read-only (renders) | Renders removal steps for the unit. |
| `grant issue --request FILE --issue N --expires-in SECS [--idempotency-key IK] [--socket PATH] [--config PATH] [--json]` | **daemon-journaled mint (no repository/session/external effect)** | Mints ONE route grant (`hf-grant/v1`) through the closed `grants.issue` method from a reviewed bound-input document; every binding is derived (repository, workflow hash, role/policy revision, phase, caps, scope, live epoch, explicit expiry), the intent is journaled before the row, a production-class binding and an already-expired window refuse typed, and the minted `gr_` id is presented at the board / `queue submit` authorization point. |
| daemon `apply` RPC (NOT a CLI subcommand) | **grant-gated mutation** | One digest-bound plan step per request over the socket, idempotency-keyed, journaled before effect; typed `hf-outcome/v1`. |

Mutating surfaces are the daemon's closed, journaled methods: the CLI
exposes `grant issue`, `lane request`, `queue submit` and the run controls
(pause/resume/retry) as thin clients over them, and each records durable
intent before any effect. `apply` (step execution, spawn/prompt/Git effects)
remains a daemon RPC that no CLI subcommand exposes, and production-class
work stays human-only. Never work around a refusal: fix the reviewed inputs
and re-run the surface that refused.

## JSON envelope contract

- `--json` commands write exactly one `hf-output/v1` document to stdout:
  `schema`, `command`, `kind` (`ok` | `error` | `partial`), `data` or
  `error` (with stable `code`, `retryable`), `exit_code`.
- Exit codes (with or without `--json`): 0 ok · 1 operational error ·
  2 usage · 3 partial · 4 refusal · 5 config error.
- Diagnostics go to stderr; JSON output never prompts. Adapter reads run
  through a bounded env-isolated runner with one redaction pass at the
  boundary (never trust/shell-evaluate adapter or remote text).

## Observe → plan (read-only) flow — do this unaided first

1. Build: `cargo build --locked` (release: add `--release`).
2. `canter config init > ~/.config/canter/config.toml`, edit it
   to the repository you operate, then
   `canter config validate --json` → expect `kind:"ok"`, exit 0
   (`config.invalid` exit 5 = fix the document).
3. `canter doctor --json` → expect all checks `status:"ok"`, exit 0
   (exit 3 = a prerequisite is missing/degraded — install/auth the named
   tool, never have the CLI do it).
4. From inside the repository's local checkout:
   `canter status --json` → expect `freshness:"fresh"` and
   `observed_repositories >= 1`, exit 0; `git.available:false` /
   `github.available:false` are explicit degradations, not errors.
5. `canter plan <owner/name> <issue> --revision <40-hex> --json` →
   expect `kind:"ok"`, exit 0, with a `hf-plan/v1` document, `plan_id`,
   `digest` (sha256 over canonical bytes), and `state_epoch`. Without
   `--revision`, authenticated `gh` is required (else exit 1
   `forge.unavailable`; the message suggests offline mode). Rerun the same
   command and diff: output is byte-deterministic.

Never present `plan` output as applied work — plans are read-only
renderings until an authorized grant + daemon `apply` executes them.

## Lane handoff (thin client, read-only preview/status + one authorized record)

- `canter lane preview ...` renders the reviewable `hf-lane-handoff/v1`
  plan for ONE lane (source identity, target profile plan via `--profile
  KEY`, repository-relative worktree, effect boundaries, retained
  workers/reviewers/gates, plan digest). Read-only; works without a daemon.
- `canter lane request ...` records ONE durable replacement request. The
  authorization binds the exact plan digest: `--confirm-digest <64-hex>`
  (noninteractive) or `--confirm` (type the digest; prompt on stderr). A
  digest that no longer matches the plan refuses `refusal.plan.stale`
  before any daemon call. A blanket `--yes` is refused under a declared
  policy overlay (`production_confirmation = "tty" | "deny"`).
- `canter lane status --replacement rp_... | --lane ID --generation N`
  reads phase/outcome/blocker, intended vs actual binding, the last
  verified transition, the next supported action and guidance. Read-only.
  Never prompts; `--json` is exactly one `hf-output/v1` document.

## Plan digest + grant flow (mutations, #8 semantics)

- The digest binds the plan: same inputs → same canonical bytes → same
  `digest`; tampered bytes are refused at apply (`refusal.plan.identity`).
- A route grant (`hf-grant/v1`) is the only authorization to start durable
  work: it binds repository, plan digest, capabilities, role/policy
  hashes, `state_epoch`, expiry, and instance; grants expire and die with
  their epoch (material edits or restore rotate the epoch and invalidate
  prior grants).
- The SUPPORTED mint path is `canter grant issue` over the closed
  `grants.issue` method: it mints ONE grant from the reviewed bound-input
  document (`canter queue preview --out`) with every binding derived, the
  intent journaled before the row, and typed refusals for a moved role
  revision / epoch, an expired window and a production-class binding.
  Minting is NOT authorization — the minted id is presented at the board /
  `queue submit` point. `grants.list` reads live grants; `grants.revoke`
  cancels one.
- `apply` runs ONE plan step per request, requires `params.idempotency_key`
  (`ik_` + 8-64 `[a-z0-9-]`), revalidates live under the state lock
  (epoch/grant/expiry/revision/hashes/capability) and journals
  (`mutate.*`) before the effect. Replaying a consumed key returns the
  recorded response (at-most-once dispatch, exactly-once read-back).
- Outcomes are typed `hf-outcome/v1`: `succeeded` | `failed` | `refused` |
  `ambiguous` | `superseded`. `ambiguous` (crash/timeout/restore) always
  requires external reconciliation before a new key.
- Kind gates: merge needs current review evidence bound to the exact head
  (`refusal.evidence.stale` on moved bindings); issue closure requires the
  instance at `post_merge_verify` with passing evidence; production-branch
  effects need a fresh interactive TTY-confirmed digest; real-external
  scopes need the recorded first-write approval.
- Normative sources (link, never duplicate): `docs/contracts/spec-plans.md`
  (apply semantics, grants, epochs, idempotency), `docs/contracts/
  spec-daemon.md` (RPC request/response, methods, replay),
  `docs/contracts/spec-review-evidence.md` (evidence rows).
- Tests that prove these flows: `tests/mutation_engine.rs` (socket-level
  flows over disposable local repositories), `tests/daemon_rpc.rs`,
  `tests/daemon_lifecycle.rs` — no credentials, no external state.

## Bundled Doctrine default workflow (#6, link not duplicate)

- Canonical source (versioned + hash-pinned):
  `schemas/fixtures/workflow/workflow.doctrine.json` (`workflow_id`
  `fleet-doctrine-1`, `hf-workflow/v1`).
- Normative spec and engine rules: `docs/contracts/spec-workflow.md`
  ("Engine semantics" and "Bundled Doctrine default").
- Rust embedding + pinned digest: `src/engine.rs`
  (`engine::doctrine_default`, `engine::DOCTRINE_DIGEST`).
- The public skill uses this workflow's model-agnostic default roles
  (orchestrator/implementer/reviewer); workflow content can never carry
  policy, capabilities, target, or approval authority.

## Harness adapters (#7/#33/#37, link not duplicate)

- Normative contract: `docs/contracts/spec-capabilities.md` ("Adapter
  contract") — closed operation set, typed refusal codes, identity-triple
  rule, fake-adapter doctrine.
- Declared version ranges and measured version facts:
  `docs/contracts/compatibility.md` — Hermes 0.21.0, Claude Code 2.1.263,
  Codex 0.153.4 (measured 2026-09-06), Pi 0.85.1 (earendil-works/pi,
  measured 2026-09-08; darwin prebuilts available at that version, parity
  human-gated) and Jcode 0.84.0 (1jehuang/jcode, measured 2026-09-08
  against the SHA-verified linux-x64 prebuilt; darwin prebuilts available
  at that version, parity human-gated; issue #37 darwin canary peak RSS
  ~19.9 MB).
- Rust implementation: `src/adapters.rs` (`canter::adapters`);
  contract tests with fake executables: `tests/harness_adapters.rs` — the
  shared fixture loop drives every official adapter (hermes, claude-code,
  codex, pi, jcode) plus the argv fake; public CI and fork PRs need no
  harness credentials. Real harness parity is a human-gated clean-host
  smoke, never run from this repository's CI (the issue #33 lane ran one
  local pi live smoke outside CI as sandbox evidence; the issue #37 lane
  ran the real jcode binary's probe/argv rows outside CI — see
  `.report-37.md`).

## Control-plane mutations (#8, link not duplicate)

- Normative contract: `docs/contracts/spec-plans.md` ("Apply semantics")
  and `docs/contracts/spec-review-evidence.md` (durable evidence rows).
- Rust implementation: `src/mutation.rs` (`canter::mutation` engine +
  effect registry), `src/daemon.rs` (`plan`/`apply` RPC handlers), durable
  rows + invalidation semantics in `src/state.rs`.
- Acceptance tests: `tests/mutation_engine.rs` (socket-level flows over
  disposable local repositories) — public CI needs no credentials.

## Lifecycle, cleanup, and recovery (#9 — pointers)

- Schedules/admission/cleanup-archive/recovery/remote semantics:
  `docs/contracts/spec-lifecycle.md` (recurring non-destructive
  `hf-schedule/v1`; cold boot runs one fresh evaluation per due schedule
  before the socket serves; fan-out admission refuses without host-resource
  proofs or on monorepo overlap; cleanup archives with byte-verified
  salvage manifests; system-SSH remote transport is a verified contract).
- Daemon recovery: after a crash/kill, `daemon status --json` reports
  `daemon.stale` (exit 1, retryable); a fresh `daemon run` reclaims the
  socket, migrates state, reconciles interrupted claims, and serves —
  read-only commands never need the daemon.
- State/journal/backup: `docs/contracts/spec-state.md` (migrations
  m0001-m0013, audit/event journals, backup/restore with retention);
  restore rotates the epoch and invalidates prior grants.
- Operations runbook: `docs/OPERATIONS.md` sections 5, 7, 8 (daemon
  lifecycle, cleanup/archives, recovery after crash/cold boot).
- Release archives/provenance/upgrade: `docs/RELEASING.md` (execution
  human-gated).

## Release readiness (#10, link not duplicate)

- Normative contract + version/schema policy + documented command rows:
  `docs/RELEASING.md` (in-repo machinery active; release EXECUTION
  human-gated).
- Deterministic archive builder + verifier (`scripts/build-archive.py`,
  `scripts/test-build-archive.py`): platform archives with SHA-256
  checksums, offline SPDX SBOM from `Cargo.lock`, and
  `release-provenance/v1` records.
- Clean-host verification (`scripts/clean-host-verify.sh`,
  `scripts/clean-host-probe.py`, `scripts/test-clean-host-probe.py`).
- Baseline machinery + committed table (`scripts/measure-baseline.py`,
  `docs/contracts/baseline-linux-x86_64.csv`,
  `docs/contracts/benchmarks.md`): never a CI gate.
- Compatibility probe mapping: `docs/contracts/compatibility.md`.

## Herdr 0.9 compatibility (#35 — pointers)

- Canonical matrix and evidence classes:
  `docs/contracts/compatibility.md` (same-version 0.9.0 green; both
  0.8.2/0.9.0 mixed protocol directions red and fail closed).
- Portable discriminating tests: `tests/herdr_compatibility.rs` (subscribe
  before snapshot, no retained replay, explicit group close, prompt activity
  gate, unscrolled recent reads, and the #9 no-dependency guard).
- `HERDR_MINIMUM` remains 0.8.2 because the mixed matrix is red. Treat it as
  the supported CLI floor, never as permission to operate mismatched
  protocol-20/protocol-22 endpoints; update Herdr endpoints together through
  Herdr's own workflow, never from canter.

## Safety direction (plan/apply gates)

Mutations are typed, digest-bound, journaled before effect, exactly read
back, and revalidated against live grant/instance/epoch state immediately
before the effect; production/destructive actions require fresh interactive
TTY confirmation (and recorded first-write approval for real-external
scopes) and can never be scheduled. Any proposal to add mutation behavior
outside this machinery is out-of-scope and routes through the roadmap.

## Adapter-example note

Hermes (or any agent harness) may appear in this repository only as a
clearly labeled *adapter example* of the harness-neutral design — never as
a required invocation path, profile layout, or core dependency. This skill
is usable with any harness or with none.

## Making this skill available to Pi lanes (issue #33 A1) and Jcode lanes (issue #37)

Hermes lanes read this skill from the profile skill directory. Pi lanes
(the pi harness adapter, issue #33) load the same operating knowledge
through pi's native skills discovery (pi `docs/skills.md`; this directory
is a standard skill: `SKILL.md` + freeform files):

- Global: symlink (keeps the relative `docs/...` links working) or copy
  this directory to `~/.pi/agent/skills/canter/`.
- Project: `cp -r skills/canter <worktree>/.pi/skills/` (project
  skills load once the project is trusted).
- One-shot/CLI: `pi --skill <repo>/skills/canter ...` (repeatable,
  additive even with `--no-skills`).

Verified 2026-09-08 (issue #33 A1): a real pi session loaded this skill
and answered a canter usage question from the skill content alone —
redacted Q/A evidence in `.report-33.md`.

Jcode lanes (the jcode harness adapter, issue #37) have no skill
discovery surface in v0.84.0: the real binary's command list exposes no
skill subcommand and `run` accepts no `--skill` flag (verified 2026-09-08
against the v0.84.0 linux-x64 prebuilt). For one-shot jcode lanes the
skill content travels as prompt data — the adapter delivers the brief
text (which may reference this skill's sections) as the payload of the
documented `run` row, and the lane reads the referenced repository files
itself. This repository keeps exactly one canonical copy of the skill
(here); nothing is duplicated for jcode.

## Role procedures: what a lane is given (issue #267)

A worker lane is judged by its artifacts, not by what it was told: the plan
declares, **per leg**, the role skills the lane is given
(`role_config.skills` / `legs` in the bound-input document,
`steps[].params.reviewer_profile.skills` for the reviewer leg), and the
role→skill binding is configuration (`harness.<key>.skills` resolved against
the `skill.<key>` inventory). A declared skill the installation does not
resolve refuses the plan typed (`refusal.skill.unresolved`) before any lane
exists.

The three doctrine role contracts ship here as installable procedure
sources — the same "one canonical copy, linked not duplicated" rule as this
skill:

- [`skills/lane-implementer`](../lane-implementer/SKILL.md) — work only in
  the given worktree, commit in the repository's own wording, push the
  branch and never merge, run the repository's gates and record raw exit
  codes, never touch the control plane.
- [`skills/lane-reviewer`](../lane-reviewer/SKILL.md) — review the exact
  certified head, refuse a stale head (the rule the engine enforces with
  `refusal.evidence.verdict_stale`), write the verdict in the form the
  engine consumes, no self-approval.
- [`skills/lane-orchestrator`](../lane-orchestrator/SKILL.md) — drive the
  control plane through typed operations only (`queue` / `run` /
  `supervision` / `grant` / the bounded re-drive); never nudge a pane, never
  merge ad hoc.

Nothing requires a worker lane to carry a skill named after this repository:
a repository unrelated to canter binds its own skill names, and no worker
lane is given — or needs — the control-plane socket.

## Repository rules that bind work here

- Public-data rule: never commit host paths, private repository names,
  credentials, provider/model policy, or live scheduler identity (CI scans
  every PR).
- Branches: PRs target `staging`; `main` changes only via human promotion
  (or the documented hotfix exception).
- License: Apache-2.0 OR MIT; DCO not adopted.
