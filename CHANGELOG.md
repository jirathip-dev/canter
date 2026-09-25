# Changelog

All notable changes to this project are documented here. This project
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) until a
release process activates (docs/RELEASING.md), then semver applies.

## [Unreleased]

### Fixed (issue #224 — a completed run leaves no reviewer lane behind)

- The verdict-consume path (p6) WAITS, bounded by the step's own effective
  deadline, for the reviewer lane to settle before it closes the workspace and
  removes the checkout (`remove_reviewer_lane`), on the cleanup step's own
  confirmed-settle discipline (`await_settled_lane`, issue #170 N7): the
  measured defect was that the verdict is consumed while the reviewer's own
  turn is still `working`, so the single close refused
  `refusal.lane.busy` — recorded on 30 of 30 p6 receipts (2026-09-19..
  2026-09-25) — and the registration, the pane and the checkout outlived the
  run forever. A lane that is still working, that starts working again
  between the confirmation and the close, or that only flaps a stop mid-turn
  is never closed; the receipt keeps the close's own refusal verbatim and
  records the wait beside it (`waited_ms`, plus the `effect.lane_timeout`
  park when the bound expires), and the step still succeeds — no bounded
  retry is ever spent on the timing.
- The next run's reviewer-leg bind RECLAIMS that residue without an operator:
  the daemon resolves the run's issue's ledger-terminal generations for the
  reviewer-leg bind (`lane_binding_step_kind`: `harness_start`,
  `worktree_create`, `review_evidence`) exactly as it already did for the
  implementer lane's bind, so `ensure_reviewer_lane` retires the terminal
  generation's own registration (ownership-verified: this leg's own checkout,
  exactly that generation's lane token) instead of refusing
  `refusal.lane.name_collision`. A live or foreign holder is still refused
  verbatim, never adopted or renamed.
- Witnesses: `tests/review_dispatch.rs` drives the REAL effect path for the
  settle-then-close (RED at the base commit: `closed=false`,
  `refusal.lane.busy`), for the bounded park that preserves the lane, and for
  the successor's reclaim of an unsettled terminal generation; `src/daemon.rs`
  pins the resolved kind set against a real ledger.

### Fixed (issue #231 — native lanes' build scratch belongs to the lane, and disk pressure is typed)

- A lane's build scratch is derived from its own leg
  (`crate::lane::lane_build_residue_roots`: `<agent>-derived` and
  `<agent>-DD`) and named in the worker payload the plan produces
  (`-derivedDataPath ../<agent>-derived`, with the home directory explicitly
  forbidden): the measured defect was native lanes dropping a full Xcode
  DerivedData tree per lane into the host home directory, filling the data
  volume. `tests/lane_build_residue.rs` witnesses the payload's path, a
  native build that follows it leaving the home directory untouched (with the
  leaked shape as the discriminating control), and the reaper below.
- The lane-residue reclaim gained a THIRD half (`build_residue`): for a
  ledger-terminal generation the reaper reclaims both derived roots (any
  `DerivedData` tree inside them included) under the run's own
  `worktrees_root`, and touches nothing else — a sibling lane's root
  survives, and a symlinked root is refused (`refusal.cleanup.symlink`) and
  left exactly where it is.
- The fan-out admission gate enforces a documented free-space floor
  (`HOST_FREE_FLOOR_BYTES`): a lane start whose host proof carries a free-byte
  observation below the floor is refused typed
  (`refusal.admission.resource_floor`, naming the floor and the observation)
  before any effect runs. The proof carries the observation the presenter
  measured (`host_proof.available_bytes`): `queue submit --topology` records
  one from the host it runs on, and the dispatch-time renewal supersedes it
  with the daemon's own measurement.
- Disk exhaustion is its own typed state condition: a write-class SQLite
  failure observed while the state root holds fewer free bytes than the same
  documented floor is reported as `state.disk_exhausted` (naming the
  observation, the floor and the raw SQLite detail) instead of the
  indistinguishable `state.write_io`; a database fault keeps its own code
  however little space the host has, and an unobservable host is never
  guessed.

### Fixed (issue #277 — a bump installs BOTH paths and proves the daemon runs the installed build)

- `scripts/accept-bump.py` is the versioned bump driver (operator tooling, run
  by hand, never from CI): it reconciles the integration checkout to the
  requested sha (fetch, fast-forward check, `checkout -B <branch> <sha>`),
  rebuilds with `cargo build --release --locked`, installs the SAME bytes to
  BOTH the acceptance target and the path the service unit launches, ad-hoc
  re-signs both (`codesign --force --sign -`, then `codesign -v`), refuses
  unless the supervised job's `program` really is that service path, restarts
  through the supervisor (`launchctl kickstart -k`) — no detached second copy —
  and then proves the invariant: exactly ONE pid holds the socket, that pid's
  executable sha256 IS the installed binary's sha256, and the daemon lease
  names that pid with a recorded start that postdates the install. The measured
  defect was a bump that installed one path while the KeepAlive unit kept
  launching a separate copy: the supervisor resurrected the superseded build,
  it won the socket, and the bump still reported success — silently
  invalidating every measurement taken from that daemon.
- `DONE` is printed only under that proof; every other outcome is a typed
  `bump.refusal.<code>` with a non-zero exit status (build 4, non-fast-forward
  5, reconcile 6, install 7, sign 8, install-divergence 9, supervisor-program
  10, supervisor-not-loaded 11, restart 12, daemon-not-up 13, socket-holders 14,
  stale-daemon 15, pid-exe-unresolved 16, lease 17). The bump log
  (`<state>/accept/bump.log`) records the daemon pid, `started_at` and the
  installed sha256 (post-sign, the identity of the executed bytes) with the
  pre-sign candidate sha256 recorded alongside it.
- `scripts/test-accept-bump.py` self-tests the driver in disposable roots with
  an injected `launchctl` and no host activation: both-path identity and
  signature, the single-holder/sha/lease proof, the read-only `--verify-only`
  certification (same pid, no restart), idempotence, and every refusal
  including the induced "a superseded build wins the socket" run, a lease whose
  start predates the install, a supervisor that launches another path, a
  refused restart and two socket holders. Runbook:
  [docs/OPERATIONS.md](docs/OPERATIONS.md) section 10.1;
  [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) carries the self-test row.

### Fixed (issue #224 — the publish route's post-merge bookkeeping, and a lane retire that removed a live run's lane)

- The `pull_request` publish route FETCHES the landed head into the integration
  checkout — verified against the published read — BEFORE anything reads it:
  the forge's landing exists on the remote alone, and reading the commit it
  had just landed first is the measured bare `adapter.exit`/128 (`fatal: bad
  object <landed-sha>`). A landed head the checkout still cannot read after
  that fetch is the step's OWN typed static condition `effect.merge.static`,
  which parks its frontier with the bounded retries UNSPENT — the measured
  drive spent two attempts of `p7`, and two of `p6`, on causes identical
  between attempts.
- A delivery whose reviewed content ALREADY IS on the published ref is
  certified as landed from the published ref and the commit objects alone
  (`mode:"already-landed"` on re-entry), WITHOUT requiring the delivery
  branch's worktree — a lane retirement may legitimately have removed it, and
  the old reconciliation refused `effect.merge.failed` for a delivery that had
  already landed.
- `run retire-lane` refuses typed BEFORE any claim when another NON-TERMINAL
  run of the same repository issue exists: one issue has ONE lane, so a live
  sibling still needs exactly the refs the retire would remove (the measured
  drive removed a DONE run's checkout and branch while a live same-issue run
  was mid-flight). A Herdr-side lane-retire refusal
  (`refusal.stale.generation`) is recorded as the residue half's OWN typed
  outcome and the registered checkout and the local lane branch are left in
  place — a reported removal never coexists with a failed workspace retire.

### Fixed (issue #224 — the cleanup lane wait closes only on a CONFIRMED settled turn)

- The `p8` lane wait's settled turn is the COLLECTION's confirmed stop (issue
  #170 N7), not one read-back: the cleanup step closes the live lane's
  workspace only after `COLLECT_STOP_SAMPLES` consecutive corroborated
  read-backs — BOTH views non-working, the lane's own lifecycle counter
  unmoved — sampled across the documented `COLLECT_STOP_INTERVAL_SECS`
  interval, and keeps calling the same whole-lane close (lane token,
  generation, worktree, settled agent state) afterwards. A status that FLAPS
  to `idle`/`done` MID-TURN — the measured shape the collection's confirmed
  stop exists for — is therefore never read as a settle, so a live lane's
  workspace cannot be retired on a flap; a lane that starts working again
  between the confirmation and the close voids it and the wait re-confirms.
  The bound, the `effect.lane_timeout` park (workspace preserved, bounded
  retries unspent) and every refusal that is not the timing condition are
  unchanged, as is the one-read policy for a lane whose own read-back cannot
  be taken at all (the close's own verification decides it, at once).

### Fixed (issue #285 — a retry-exhausted run no longer pins a concurrency slot)

- A run that is TERMINAL BY OUTCOME stops being counted as an active lane. When
  the run's newest recorded attempt is a step DIAGNOSIS (the same predicate the
  bounded-retry fence reads) and that step's whole bounded-retry budget is spent
  with no unconsumed authorization left, every further dispatch of it refuses
  `refusal.run.retry_bound` and no exposed control can move it — so the global,
  per-repository and per-harness slots it held are free again for work that can
  still progress. One derivation (`State::retry_exhausted_run_ids`) feeds the
  queue admission's counted-lane set, the preview's capacity holds and the
  daemon's dispatch-time fan-out gate, so a preview or a fresh submission
  admits the issue that was waiting on the cap WITHOUT an operator
  `run release`, and exactly one slot is freed. Nothing is released, retried,
  moved or deleted: the run keeps its status, its issue ownership, its attempt
  rows, its retry authorizations and its evidence rows, all still readable. A
  park that is the run's own lapsed window (the admission proof codes, a lapsed
  grant), a park whose budget is NOT spent, and a run holding an unconsumed
  authorization are never excluded.

### Fixed (issue #279 — a stored pre-#269 admission binding dispatches again)

- A `hf-profile-binding/v1` document with NO `skills` key is accepted again:
  the axis was added to the material by #269, so a binding approved BEFORE it
  carries no such key at all and its revision fingerprints the material as it
  stood then (the same document without that entry). An absent key resolves to
  the empty array the shape already allows and is verified against that
  pre-#269 material, so a run admitted before #269 — whose every dispatch
  presents the STORED document — is dispatchable again instead of refusing
  `refusal.profile.binding` forever, with its unconsumed bounded retry
  unspendable and its per-repository slot pinned. Only the absent key is
  tolerated: a PRESENT `skills` value is validated exactly as before (an array
  of well-formed `{key, hash}` pins, no duplicates), and a malformed,
  mis-keyed or duplicated one still refuses typed. Nothing is migrated,
  re-bound or written back: the stored rows and the runs that hold them are
  untouched.

### Fixed (issue #276 — a fix-round wait ends when the leg's own lane is gone, and the run re-dispatches itself)

- A fix-round wait is no longer exempt from the policy's progress timeout: the
  repair leg's OWN lane checkout is observed (`FixLegState.lane`), and a leg
  whose checkout is GONE — the measured dead-lane shape, where the leg's
  worktree no longer exists on the host — is reported class `needs-attention`,
  reason `supervision.fix_round_lane_lost` (detail: the recorded lane and the
  window that was read), `eligible:true`, instead of `waiting-workers` /
  `supervision.fix_round_dispatched` forever. A LIVE leg (its checkout present,
  at the certified head) keeps the unchanged wait, and an UNOBSERVED leg is
  never a lost one, so nothing is inferred from a read that could not be taken.
- The SAME derivation is the driver's ONE continuation: the recorded handoff's
  own step is re-dispatched through the apply engine, so the bounded-retry
  authorization the run already holds is spent by the run's own supervision —
  `consumed_at` recorded under the dispatch's own journaled key, exactly once —
  rather than parked. Nothing is loosened: the run consumes no head its own
  collection did not observe, and the tail behind an uncertified delivery stays
  undriven.
- The engine's own fix-round record follows the same fact: a recorded round is
  reused only while its leg's lane checkout still exists, so a DEAD round is
  superseded by the next round of the same bound — whose lane the engine creates
  at the certified head and whose instruction is delivered to a leg that can
  still work — instead of the FAIL being re-handed to a leg that carries no
  state. A record naming no checkout keeps the unchanged reuse rule.

### Added (issue #267 — role skills are declared per leg, bound by the plan digest, and resolved against the installation's own inventory)

- A plan now names, **per leg**, the role skills the lane is given: the
  bound-input document's `role_config.skills` carries the implementer leg's
  resolved procedure pins and each self-dispatching review step's
  `params.reviewer_profile.skills` carries the reviewer leg's, while the new
  top-level `legs` array lists every declared leg (`role` + `skills`) so the
  per-leg declaration is readable in the raw plan JSON. The role binding is
  what decides a lane's procedure, so the resolution rides the plan digest:
  changing the role→skill binding changes the digest (the binding revision
  fingerprints the resolved pins).
- Configuration is where the binding lives (`hf-config/v1`):
  `harness.<key>.skills` declares the role skills one role binding gives its
  lane, and a new `skill.<key>` table declares the installation's own
  resolvable inventory (each entry pins the installed procedure's 64-hex
  content identity). A binding that declares a skill the inventory does not
  resolve refuses typed `refusal.skill.unresolved` **before** any lane
  exists — no run, no worktree, no pane — instead of starting a lane short of
  its declared procedure. `canter config show` reports each harness row's
  declared skills and the identity (or the missing resolution) alongside the
  profile revision.
- The three role contracts are committed as portable procedure sources
  (`skills/lane-implementer`, `skills/lane-reviewer`,
  `skills/lane-orchestrator`): the implementer works only in its given
  worktree, commits in the repository's own wording, pushes the branch and
  never merges; the reviewer judges the exact certified head, refuses a stale
  head (the rule the engine already enforces with
  `refusal.evidence.verdict_stale`) and never self-approves; the orchestrator
  drives the control plane through typed operations only and never nudges a
  pane or merges ad hoc. Worker lanes stay canter-agnostic: no worker lane
  receives — or is required to use — the control-plane socket, and a
  repository unrelated to canter is never required to carry a canter-named
  skill.
- `canter run status` shows the run's committed plan legs (role + skills per
  leg) with the rest of the control document.

### Added (issue #236 — `run retire-lane`, the bounded operator retirement of ONE terminal run's stale lane records)

- `canter run retire-lane --run RUN_ID --reason TEXT [--topology FILE]`
  retires the stale lane records of ONE run the ledger already records as
  terminal, so a released run's residue is recoverable by one bounded,
  audited operator control instead of hand-editing state or waiting for a
  successor run's bind step: the leftover `queue_ownership` row that still
  names the run the owner of its issue is removed in ONE transaction with a
  `run.retire-lane` audit record, and its lane residue is retired under the
  SAME #190/#222 policy a bind step applies — the run's OWN linked lane
  workspace (a different pane, another lane's binding or an unverifiable
  read-back is refused and left untouched), its REGISTERED lane checkout in
  the integration clone, and its local lane branch only when the published
  branch carries the same tip (a local-only delivery is never destroyed).
  The lane is derived from the run's own issue (`issue-<N>` at
  `issues-<N>`) and the integration clone from the run's own recorded
  topology, never from a caller-named path. A run that is NOT terminal
  refuses typed `refusal.lane.live_run` before any claim — a live lane still
  holds its issue's unique ownership and is never in the retired set. The
  same idempotency key replays the recorded response.

### Added (issue #245 — `queue intake`, the deterministic feeder)

- `canter queue intake` turns the repository's own issue state into ONE
  bound-input submission by rule: the open issues carrying the ready label
  (default `canter:ready`) are selected in ascending issue-number order, each
  revision resolves by the documented rule (a tracker-declared `--pin N=HEX40`
  wins; otherwise the repository's integration head at intake time, read from
  the remote), an issue already owned or queued is never re-submitted
  (`intake.owned`), items beyond the declared `--max-items` bound wait
  (`intake.cap`) instead of bypassing admission, and an unresolvable revision
  refuses typed (`refusal.intake.revision`) without submitting anything.
  `--dry-run` prints the exact decision and mutates nothing; `--json` names the
  selected issues, revisions, caps, digest and each item's status. The rendered
  document, the per-item grants and the submission are the SAME surfaces the
  operator path uses (`queue preview` → `grant issue` → `queue submit`).
  Contract: `docs/contracts/spec-intake.md`.

### Added (bootstrap)

- Public repository foundation for canter (issue #2):
  - Single-package Rust scaffold: `canter` library + binary with
    truthful `--help`/`--version` only; edition 2024, pinned toolchain
    1.97.1, committed `Cargo.lock`, zero external dependencies.
  - Real-binary CLI smoke tests (`tests/cli_smoke.rs`).
  - Canonical `just` developer gates (`just ci` aggregate) and strict
    `deny.toml` for cargo-deny.
  - Hosted CI (policy, rust-ubuntu, rust-macos, supply-chain, secret-scan)
    with stable job names, minimal permissions, full-SHA action pins, and
    no caching.
  - Public-tree privacy scanner (`scripts/check-public-tree.py`) with
    discriminating self-tests (`scripts/test-check-public-tree.py`).
  - Contributor tooling: issue/PR templates, CODEOWNERS (comment-only),
    Dependabot grouped weekly updates targeting `staging`.
  - Public docs: README, ARCHITECTURE, DEVELOPMENT, WORKFLOW, RELEASING,
    three ADRs, SECURITY, CONTRIBUTING, AGENTS, CODE_OF_CONDUCT, and the
    public `skills/canter` skill.
  - Amendment-3 architecture artifact set committed under
    `docs/architecture/` (sanitized locked-target JSON/HTML + static
    light/dark previews + SHA-256 provenance README).

### Added (issue #3 — Contracts, PR #14)

- Versioned contract corpus under `docs/contracts/` with machine-checked
  fixtures under `schemas/fixtures/`: capability map and owner dependency
  order; schema registry; specs for config/policy, CLI/JSON (envelopes,
  exit codes 0-5, partial-freshness), plans/digests/grants/epochs/
  idempotency keys/typed outcomes, closed typed workflow DAGs with
  canonical hashing, daemon request/response + JSONL events, SQLite
  migration/journal/audit and backup/restore/retention, harness/forge
  capability negotiation, review evidence, trust model, daemon-owned
  fail-closed risk model, Corral archaeology matrix, tested Herdr + `gh`
  compatibility policy, and the benchmark corpus.
- Fixture oracle: `scripts/check-contract-fixtures.py` +
  `scripts/test-check-contract-fixtures.py` (accept/refuse/tamper
  discrimination, known-answer digests, manifest coherence).

### Added (issue #4 — Read-only core, PR #15)

- Typed `hf-config/v1` configuration: `config init` (stdout template),
  `config validate`, `config show` (refusals for unknown keys, foreign
  schema identifiers, unsupported versions, invalid overlays — exit 5).
- `doctor`: read-only prerequisite checks (git, herdr >= 0.8.2, gh auth +
  scopes) plus config status; exits 3 on missing/degraded prerequisites.
- `status`: bounded read-only observation of configured repositories
  (local git checkout + authenticated `gh`, herdr presence/version), with
  explicit freshness/completeness and per-surface degradation.
- `plan`: deterministic read-only `hf-plan/v1` rendering (canonical bytes,
  sha256 digest, redacted acceptance-revision binding; `--revision` offline
  mode; `forge.unavailable` refusal when gh is unavailable without one).
- `capabilities`: declared forge read capabilities
  (`read_refs`, `read_issues`, `read_checks`).
- Stable JSON contract: every `--json` invocation writes exactly one
  `hf-output/v1` envelope; closed exit-code set 0-5; adapter reads are
  env-isolated and redacted at the boundary.

### Added (issue #5 — Daemon foundation, PR #16)

- `daemon run`: single-writer state daemon in the foreground (per-user
  flock, SQLite state open/migrated, interrupted-claim reconciliation,
  per-user Unix socket `hf-rpc/v1`); a second daemon is refused
  (`daemon.busy`).
- `daemon status`: socket probe reporting live daemon + state facts; exit 1
  with `daemon.absent` when no daemon is running (read-only commands stay
  available without it).
- `service doctor` + `service install-plan|status-plan|uninstall-plan`:
  per-user launchd/systemd environment checks and unit-plan rendering —
  plans only, never installing/starting/stopping/querying the host service
  manager.
- State layer: SQLite migrations m0001-m0008, audit/event JSONL journals
  with mirror rebuild, backup/restore hooks, per-user path resolution.
- Socket RPC: `hf-rpc-request/v1`/`hf-rpc-response/v1` closed method set,
  typed refusal codes, `events.subscribe` stream.

### Added (issue #6 — Workflow engine, PR #17)

- Typed workflow engine: closed step-kind set, canonical serialization and
  hashing, instance state (`hf-workflow/v1`, m0002).
- Bundled Doctrine default workflow (`fleet-doctrine-1`, model-agnostic
  orchestrator/implementer/reviewer roles; fake/no-effect step kinds only).
- Route grants (`hf-grant/v1`), state epochs (`hf-epoch/v1`), role
  composition with hash-pinned roles.

### Added (issue #7 — Harness adapters, PR #18)

- Harness adapters for Hermes, Claude Code, and Codex plus a declarative
  generic argv adapter: closed operation set, typed refusal codes,
  identity-triple rule, capability negotiation against `hf-capability/v1`.
- Fake-executable contract tests (`tests/harness_adapters.rs`) — public CI
  and fork PRs need no credentials; real harness parity stays a
  human-gated clean-host smoke (AC6/AC7).
- Versioned compatibility matrix (`docs/contracts/compatibility.md`).

### Added (issue #8 — Control-plane mutations, PR #19)

- Daemon-mediated plan `apply` RPC: one typed, digest-bound,
  capability-gated plan step per request; digest/identity recomputation
  before journaling; live revalidation under the state lock (epoch vs
  plan/grant/instance, grant expiry, issue revision, workflow/policy
  hashes, step capabilities).
- Durable review evidence rows and recorded first-write approvals for
  real-external scopes (m0003/schema v3).
- Granular step kinds (checkout, worktree_create, harness_start, prompt,
  collect_outcome, review_evidence, merge, cleanup, hosted_check,
  post_merge_verify, branch_delete, approve), worktree-confined harness
  execution, typed `hf-outcome/v1` results (succeeded/failed/refused/
  ambiguous/superseded), idempotency-keyed dispatch with exactly-once
  read-back of recorded results.
- Grant/instance invalidation on material edits and epoch rotation;
  production-branch effects require fresh interactive TTY confirmation.

### Added (issue #9 — Lifecycle safety, PR #20)

- Durable recurring non-destructive schedules (`hf-schedule/v1`, m0004)
  with single-flight/coalesced evaluation and pause/resume that survives
  daemon/service/host restarts; explicit human re-arm after refusal.
- Cold-boot recovery: one fresh evaluation per due schedule before the
  socket serves; recovery independent of herdr/git/gh presence.
- Fan-out admission: host-resource proofs, capability bounds, and
  monorepo-overlap refusal.
- Cleanup archive/salvage with byte-verified manifests and retention-
  bounded backup pruning.
- Verified system-SSH remote transport contract.

### Added (issue #10 — Release readiness, PR #21)

- Deterministic platform archives with SHA-256 checksums, offline SPDX
  SBOM derived from `Cargo.lock`, and `release-provenance/v1` records
  (`scripts/build-archive.py` + self-tests).
- Clean-host verification scripts (`scripts/clean-host-verify.sh`,
  `clean-host-probe.py` + self-tests) for fresh macOS/Linux hosts.
- Measured baseline + regression-budget machinery
  (`scripts/measure-baseline.py`, committed Linux x86_64 table) and
  compatibility probe mapping — never a CI gate.
- Active in-repo release/version policy with release execution
  human-gated (`docs/RELEASING.md`).

### Added (issue #35 — Herdr 0.9 compatibility)

- Portable contract coverage for Herdr 0.9.0 event bootstrap ordering and
  live-only subscriptions, explicit workspace-group close, prompt wait
  activity, unscrolled recent pane reads, and issue #9's lack of an upstream
  retained-event dependency.
- Measured compatibility matrix: same-version 0.9.0/protocol 22 passed in an
  isolated scratch server; both 0.8.2/protocol-20 mixed directions refused
  normal API calls with `protocol_mismatch`, consistent with upstream's
  endpoint-generation boundary.
- The doctor minimum remains 0.8.2 because the required mixed-version matrix
  is red; documentation distinguishes that CLI floor from server protocol
  compatibility rather than claiming or working around interoperability.

### Added (issue #73 — Lane replacement records)

- Request-only lane replacement records: one durable record per logical
  lane generation (`lane.replacement.request|advance|hold|cancel|status`
  RPCs, m0005/schema v5) with explicit phases (requested → quiescing →
  checkpointed → retired → starting → adopting → adopted) and explicit
  `held` (parked: advancement refused) / `ambiguous` (interrupted
  transition: external reconciliation required) / `cancelled` (invalidated
  before retirement) outcomes.
- Records bind source session/process identity, role, worktree and reason;
  missing/invalid identities refuse instead of inferring an empty lane.
  Transitions are transactional compare-and-set (stale generation, invalid
  order and replayed expectations cannot advance) and the transition
  history is committed atomically with each record write and preserved
  across daemon restarts.
- The surface has no spawn/kill/Git effect and no authority uplift (no
  grants are required, issued, or consumed); an agent may request its own
  retirement but can never authorize its own replacement effects.
  Retirement execution, automatic triggers and successor execution remain
  out of scope.

### Added (issue #74 — Safe-boundary checkpoints)

- One safe-boundary checkpoint operation for a lane replacement at the
  `quiescing` boundary (`lane.checkpoint.create` / `lane.checkpoint.status`
  RPCs, `lane_checkpoints` table via m0006/schema v6): the capture validates
  TWO observations of the lane (canonically identical, or the checkpoint
  refuses with `refusal.checkpoint.changed`), requires a supported
  quiescence acknowledgment AND a process/child observation for active
  external harness execution (`refusal.checkpoint.ack` — daemon fencing
  alone is not claimed to stop arbitrary shell actions), holds completion
  on active/ambiguous side-effecting child commands (`refusal.checkpoint.held`
  — nothing is ever signalled, killed, or cleaned up to obtain a snapshot),
  refuses missing evidence (`refusal.checkpoint.incomplete`), and yields a
  typed hold when required data exceeds the enforced brief bound
  (`refusal.checkpoint.oversize` — required gates are never silently
  truncated).
- Quiescing fences new replacement slots for the lane
  (`refusal.replacement.fenced`) until the handoff resolves or is cancelled;
  capture is only admitted at the quiescing boundary; one replacement
  carries at most one checkpoint (`refusal.checkpoint.exists`).
- The checkpoint row and the record's `quiescing` → `checkpointed`
  transition commit in ONE transaction; the compact brief (≤ 3 KiB) is
  generated deterministically from the durable record, carries explicit
  evidence pointers only, and is regenerated (digest-verified) by restart
  reconciliation when a crash lands between the commit and the artifact
  write. An artifact without a committed record fails closed. Orchestrator
  checkpoints reference existing worker/reviewer records and pending
  completion events without altering them. No spawn/kill/Git effect, no
  grant, no scheduler, and no automatic trigger exists on the surface.

### Added (issue #75 — Guarded single-session retirement)

- One guarded retirement of a single checkpointed source session
  (`lane.retire` RPC, no schema change): the request binds the record's lane
  generation, source session/process identity and the committed checkpoint
  digest, and a changed identity, checkpoint or paused (`held`) state
  refuses BEFORE any effect (`refusal.retirement.binding` — nothing is
  signalled). The immediate pre-stop quiescence recheck must observe every
  child `exited` and no active external execution; unknown child activity or
  an unknown process identity holds (`refusal.retirement.held`), and a hold
  writes nothing, kills nothing and never addresses a process group.
- The graceful stop is ONE bounded request over the existing workspace
  (Herdr) session adapter row (`session interrupt <session> --json`), with
  no retry, no SIGKILL, no broad pattern, no process-group signal and no
  authority escalation in the slice; a stop that never ran refuses
  (`refusal.unavailable.harness`) and an unconfirmed delivery holds and
  parks the record `ambiguous`. Adapter profiles that do not declare the
  required `interrupt` + `observe` capabilities are unsupported and refuse
  with `unknown.capability` before the claim.
- The retirement is confirmed by backend evidence only — the process is
  absent AND the ownership/registration is released for the bound session
  and generation; a pane text or a `done` label is never read, a reused
  process/pane or a stale registration fails closed
  (`refusal.retirement.reused`), and child lanes, worker/reviewer records
  and worktree bytes are never touched. The `checkpointed` → `retired`
  transition commits atomically with its history row (the phase transition
  is the commit marker), and restart reconciliation of an interrupted claim
  reconciles exact absence without ever repeating a signal — never against a
  reused identity. Excluded, as the issue requires: successor start,
  process-tree cleanup, whole-fleet restart and real deployment activation.

### Added (issue #76 — Bounded start, verification and adoption of one successor)

- ONE bounded start of one successor for a retired replacement and its
  single adoption (`lane.start` / `lane.adopt` RPCs, `lane_successors`
  table via m0007/schema v7): the start commits exactly one successor owner
  boundary (a deterministic `su_` successor id bound to the lane
  generation, the startup nonce, the target session and the committed
  checkpoint digest) BEFORE any spawn, and reuses the existing admission
  gate and the workspace (Herdr) session adapter row
  (`session start <session> --json`) — the same logical lane and worktree,
  never a new infrastructure model.
- A booted process alone is never a successor: adoption refuses whenever
  the successor is not verifiably interactive/usable
  (`refusal.successor.held`), a process observation without a usable
  session parks `ambiguous`, and the adoption RE-QUERIES the lane and
  compares the fresh observation against the durable checkpoint snapshot
  (`refusal.successor.differs`) instead of replaying the recorded state as
  success.
- Adoption reconciles the orchestrator identity: the successor keeps the
  retired session's role, the record's worker/reviewer references and its
  pending completion events; the events are consumed at most once by a
  logged consumer (`lane.successor.consume`) and a started successor is
  fenced while the record is held (`refusal.replacement.held`) — a paused
  lane cannot activate a booted successor.
- Capacity remains the existing bounded admission path: a missing host
  proof, a missing admission claim or an exhausted global/per-repository/
  per-harness cap holds typed (`refusal.capacity.*`) with NO child, no
  state change and a bounded fresh retry only.
- A crash between the boundary commit and the spawn is reconciled on
  restart (successor read-back before any retry; non-verifiable evidence
  parks `ambiguous` and refuses the retry until reconciliation resolves
  it), so a restart never silently writes off the boundary and never
  spawns twice. Excluded, as the issue requires: scheduler-driven successor
  work, automatic retries, process-tree cleanup and real deployment
  activation.

### Added (issue #77 — Target profile identity/fingerprint bound to the successor)

- One replacement may be requested under an EXPLICIT profile-configuration
  revision (`params.profile`, the canonical `hf-profile-binding/v1`
  document a human reviewed; optional — an unbound request keeps the
  pre-#77 behavior). The document carries the target profile key/kind, the
  intended `provider`/`model` pair sourced from the supported profile
  configuration, the authorized fallback pairs, the configured limits
  (metadata overrides — reported as configured limits, never as proof of
  provider support), the declared binding-introspection support and the
  credential DIGESTS (never values; a declared-but-absent credential is
  recorded as `unset`). Its `revision` is the sha256 over that canonical
  material: the daemon recomputes it and refuses a presented revision that
  does not fingerprint its own material (`refusal.profile.revision`), so a
  revision is never a claim. Any relevant configuration or credential
  change produces a different revision, and a start that presents the
  changed revision refuses
  (`refusal.profile.revision`: a newly reviewed plan is required) with
  nothing spawned; a missing or unexpected binding refuses
  (`refusal.profile.binding`).
- The reviewed plan is durable (`lane_replacement_profiles`, m0008/schema
  v8, committed in the SAME transaction as the replacement record — a
  replacement is bound from birth or unbound, never retro-fitted) and is
  re-validated on read. The start must present the identical plan, run the
  profile the plan names, and the successor read-back is classified against
  it: the planned pair verifies (`matched`), an AUTHORIZED fallback is
  accepted and reported distinctly (`fallback`), an unexpected
  provider/model stays fenced (fail closed, parked for reconciliation), and
  a read-back that reports nothing leaves the actual binding `unknown` — a
  profile that declares binding introspection instead holds with an honest
  capability hold, and the actual binding is NEVER copied from the
  requested configuration. The binding verdict (intended vs actual from
  authoritative adapter evidence, the reviewed revision, the configured
  limits) is recorded in the successor verification/adoption evidence and
  returns on `lane.start`/`lane.adopt`; `lane.replacement.status` exposes
  the bound plan and `config show --json` previews the exact plan (and the
  credential names present/missing) the human reviews.
- Excluded, as the issue requires: live in-place provider switching,
  editing user profiles, provider benchmark/availability services and
  automatic fallback-policy expansion. The source session is untouched
  until normal quiescence/retirement; no new store, scheduler or automatic
  rotation trigger exists.

### Added (issue #83 — Minimal authoritative board read model)

- One bounded, deterministic, paginated read for a board
  (`src/board.rs` + `State::board_page_rows`): the recorded source
  identity of a work item (repository identity, external issue number,
  and the acceptance revision bound when the run started) joined to the
  daemon-owned workflow runs and their durable review evidence. Read-only
  and state-store-only: no second database, no remote request per row, no
  terminal-text status inference, and no write path.
- Identity: a stable local work-item id (`wi_` + 16 hex of sha256 over
  `hf-work-item/v1|<repository>|<issue>`) cannot collide across
  repositories or issue numbers, and every run is its own row — multiple
  attempts under one issue stay separate. Legacy runs whose bindings
  predate m0002 are reported `partial` (null work item) instead of being
  dropped or fabricated.
- Delivery separation: `stage` (`planned`/`in_progress`/`needs_attention`/
  `verified`) and `verification` (`none`/`failed`/`passed`) are separate
  axes. Only recorded review evidence can raise verification to `passed`,
  and a run is `verified` only while that evidence is current (live epoch,
  run not invalidated): an idle, working, paused, blocked, stale or merely
  reported-`done` run is never presented as verified delivery. Recorded
  text is redacted at the read boundary, and not-recorded facts stay
  `null`.
- Pagination: ordering is the `(repository, issue, run)` key (stable
  across restarts, inserts and out-of-order attempts), the hard page cap
  is refused rather than clamped, the cursor is an ordering key (not a
  pointer), and evidence references are bounded with explicit overflow
  (`evidence_total`).
- Contract: new closed `hf-board/v1` family (validator in `src/schema.rs`
  mirroring the fixture probe), fixtures under `schemas/fixtures/board/`
  with manifest expectations, and a registry/spec entry
  (`docs/contracts/spec-board.md`). Focused acceptance tests
  (`tests/board_read_model.rs`) pin identity, the delivery separation, the
  pagination/restart behavior, the empty/stale/missing-source cases, the
  redaction boundary, read-only behavior, and the absence of any
  process/remote surface per rendered row.
### Added (issue #85 — Daemon-owned durable selected-run submission path)

- The queue executor consumes the reviewed preview: `queue.submit`
  commits ONE approved selected-issue run. The local/operator material is
  the exact bound-input document the preview rendered (its sha256 IS the
  approved digest), the reviewed role-configuration revision re-observed
  from configuration, the presented state epoch, the per-issue grant
  bindings and the presented observations; the daemon re-renders the
  preview and refuses a stale digest (`refusal.plan.stale`), a moved
  epoch (`refusal.state.epoch`), a changed configuration
  (`refusal.profile.revision`) or a revoked grant
  (`refusal.grant.inactive` / `refusal.grant.expired`) before any effect.
- Persistence is ONE transaction (`m0009_queue_submissions_v9`): the
  submission binding, the per-issue membership with explicit
  admitted/waiting/refused outcomes, the admitted run rows and the unique
  work-ownership rows (`PRIMARY KEY (repository, issue_number)`) commit
  together or not at all. Live ownership, grant status/expiry, declared
  scope overlap and concurrency capacity are re-verified under the
  transaction guard, so a double click, a retry or a restart can never
  duplicate an owner or leave a partially admitted run.
- Only supported workflow steps exist on this surface: an empty spine, a
  kind outside the closed executable effect set, unresolved step
  parameters or a step outside the reviewed boundary caps refuse the
  whole flow, labelled — an unsupported end-to-end flow is never
  represented by stub success, and no step is executed by the submission
  itself (step execution stays with the merged grant/apply machinery).
- Paused runs stay paused: a paused run in scope refuses the item
  (`submission.paused`) unless a separate explicit engine-minted resume
  authorization is presented, which resumes exactly that run once and
  admits it against the same run (never a new owner). The scope stays
  exactly the approved selected set (no implicit backlog expansion) and
  a production/protected boundary is refused (main/release stays
  human-only).
- `queue.submit` / `queue.status` are the first two methods added after
  #76 (closed RPC set 29 -> 31); restart reconciliation treats the
  committed submission row as the commit marker (an interrupted
  pre-commit claim leaves nothing behind), and `queue.status` is the same
  pure projection of the committed rows the submit response carried.
- CLI parity: `canter queue submit` (exact-digest authorization, local
  stale-digest refusal, re-observed role revision, optional pinned
  epoch) and `canter queue status` render the daemon document
  byte-identically (`tests/queue_cli.rs`); `tests/queue_submit.rs` pins
  the wire contract, the double-click/concurrent retry behavior, both
  crash windows and the per-issue outcomes over a real daemon.

### Added (issue #86 — Run-scoped safe-boundary pause, resume and bounded retry)

- `run.pause` / `run.resume` / `run.retry` / `run.status` complete the
  closed RPC set (31 -> 35) with a typed control surface over exactly ONE
  run (the `run-` instance row the queue executor commits). Scope is the
  run only: no `fleet.*` control exists, a resume never lifts another
  run's pause, and lane handoff records are untouched.
- Safe-boundary pause: a pause request is durable BEFORE the run reaches
  its boundary (`pause_requested`, `pause_reason`, `pause_requested_at`
  columns, m0010) and stops admitting new step dispatch from that moment
  (`refusal.run.paused` before any effect) while in-flight work keeps
  running untouched — nothing is signalled, killed or cleaned up. The
  pause commits its reached `paused` state at the run's next recorded
  step boundary (the apply path), and a restart commits any request whose
  in-flight work is gone; `run.status` renders `active` |
  `pause_requested` | `paused` plus the live boundary.
- Resume requires the engine-minted digest minted at pause time (bound to
  the exact run, epoch and claim), re-derives fresh eligibility under the
  guard (live, non-terminal, current epoch, still owning its issue) and is
  fenced on the exact instance id; the digest is single-use.
- Bounded retry names exactly ONE diagnosed step: it must be a step of the
  run's committed spine, the current unachieved frontier step, and carry a
  recorded terminal non-success attempt. Invalid, revoked (inactive
  grant), stale (moved epoch), already-succeeded and exhausted retries
  refuse; each `run.retry` records one single-use authorization
  (`run_retries`, bounded attempts) that the next dispatch of that exact
  step consumes — a re-dispatch of a diagnosed failed step without one
  refuses (`refusal.run.retry_required`).
- Duplicate and concurrent controls serialize: the same idempotency key
  replays the recorded response, a second pause/retry intent is refused
  typed, and every control journals through the shared claim machinery
  (restart reconciliation reads the durable rows back — `reconcile.run-control`).
- CLI parity: `canter run pause|resume|retry|status` (`tests/run_control.rs`,
  `tests/run_control_cli.rs`), `run.status` on the read-only allowlist.

### Added (issue #95 — Supervised reconciliation driver with a bounded timer fallback)

- `supervision.status` extends the closed RPC set (35 -> 36) with the
  versioned `hf-supervision/v1` status of exactly ONE authorized run: the
  recorded authorization and policy, the closed classification with its
  stable reason and eligibility, the freshness of the last check, the last
  check, the NEXT ELIGIBLE CHECK with its reason, the observed
  meaningful-progress marker and the folded pending wake. Read-only: a read
  never moves the marker. Arming is NOT a method — it is an explicit
  `hf-supervision-authorization/v1` block presented as an optional
  `params.supervision` of `queue.submit` (disabled by default) and
  committed in the same transaction as the runs it names, bound to the
  approved preview digest.
- The daemon-owned driver evaluates each armed run from RECORDED evidence
  (run row, ownership, committed submission and bound spine, recorded step
  attempts with their typed outcome codes, review evidence, bounded
  retries, in-flight claims) into `healthy` / `waiting-workers` /
  `waiting-CI` / `waiting-approval` / `blocked-capacity` /
  `continuation-eligible` / `paused` / `completed` / `needs-attention`, or
  `unknown` when the evidence is missing or stale. An idle or `done` agent
  alone is neither completion (a `done` run without passing review evidence
  stays unknown) nor permission to resume (a paused run is never eligible),
  and an unapproved or drifted plan is never eligible either.
- Wakes coalesce: semantic completion/review/CI/control events folded from
  the durable journal stream and the bounded timer fallback share ONE
  pending trigger slot per run (`supervision_triggers`, m0011), so
  duplicate, out-of-order and concurrent timer/event wakes produce exactly
  one run-scoped reconciliation; the meaningful-progress marker moves only
  when recorded evidence changed, so reads, heartbeats and rendered status
  never reset it and the progress timeout identifies the ABSENCE of
  evidence (long-running work and known waits never re-report a
  continuation; one continuation report per absence window).
- Restart and clock movement: durable pause/terminal holds, the policy, the
  check counters and the retry timing survive a restart; the boot pass
  reconciles every armed run exactly once with a fresh snapshot, and the
  next eligible check is re-anchored to `now + interval` (missed windows
  are skipped, never replayed). A persisted event cursor that retention
  moved past falls back to a fresh snapshot wake. Shutdown cancels and
  joins the driver, and the timer path never holds the state guard across a
  wait.
- NO continuation effect ships in this slice: nothing spawns, prompts,
  resumes, retries, mutates Git or clears a hold.
- CLI parity: `canter supervision status --run RUN_ID` (read-only, on the
  read-only method allowlist; `tests/supervision.rs` pins the acceptance
  over a real daemon: armed-without-another-request, reads-are-inert,
  disabled-by-default, restart-holds, and the recorded-evidence fold).

### Fixed (issue #95-R1 — an unobserved run is held, and reads report committed state)

- **No continuation report for a freshly armed run.** A run with no recorded
  progress observation yet (`progress_at` empty — the m0011 default — or an
  unreadable instant) is held: class `unknown`, reason
  `supervision.progress_unobserved`, `eligible:false`. The first
  reconciliation of a fresh arm therefore opens no continuation window and
  never advances `continuation_reports`; only a recorded observation that is
  genuinely older than the explicit `progress_timeout_secs` policy is
  `continuation-eligible` (`supervision.progress_timeout`) and reports once
  per absence window.
- **Reads report committed state.** `supervision.status` (and the human
  rendering of the same document) now reports the RECORDED result of the last
  committed check as `class`/`reason`/`eligible` (before the first check: the
  read's own observation, which is exactly what the driver is about to
  commit), carries the read-time re-classification separately as `observed`,
  and keeps the `continuation` block as durable window state
  (`state`/`since`/`reports`). A read can no longer re-classify to a
  friendlier class and hide a committed counter.

### Added (issue #96 — Bounded continuation to the next eligible issue)

- A fresh VERIFIED delivery of an authorized run now advances its
  already-authorized queue cursor and admits the next eligible approved
  issue, atomically with the reconciliation that recognized it: the SAME
  #95 event/timer driver and the SAME #85 admission helper (no parallel
  scheduler, no LLM, no conductor prompt). A delivery is the recorded
  evidence contract, never a label: reviewed `pass` with every named check
  `passed` at one exact head bound to the run's own workflow/policy pins,
  with no durable hold (paused, blocked, human queue, invalidated, terminal
  blocker) and no in-flight step claim; the verified delivery also completes
  the delivering run (`done`), which is what frees the slot the next issue
  is admitted into.
- Duplicate delivery events, replayed reconciliations and crash/restarts can
  never dispatch twice: `queue_advances` (m0012) records ONE consumed
  delivery per membership item (`(submission_id, delivered_ordinal)` is the
  durable idempotency key, keyed to the delivered issue and its recorded
  head), the dispatched item's run is created through the same
  guard-verifying admission path under the same approved caps and occupancy
  attestation, and the consumed record is immutable — a replay can only
  observe it. `queue.status` (and the queued document) renders the committed
  cursor: consumed/dispatched counts, the rows, and the current hold.
- Dependency holds never fabricate completion: an issue whose declared
  dependencies are not delivered and verified is HELD with its stable reason
  recorded (`queue.dependency_unsettled` / `queue.dependency_unresolved`),
  never dispatched and never marked done; a hold is re-evaluated as later
  deliveries settle it, and the dispatch that supersedes it is recorded on
  the older delivery row so a read never reports a stale hold.
- Existing safeguards stay authoritative: a paused or invalidated run never
  auto-advances (no cursor row is written), a failure verdict is a terminal
  hold, terminal holds stick, and a run with no supervision authorization is
  never evaluated at all. Only items of the SAME committed submission are
  eligible — no scope expansion, no new issue creation and no speculative
  prerequisite chain.

### Added (issue #92 — Supported production grant issuance path)

- `grants.issue` extends the closed RPC set (36 -> 37) with the MINT half of
  the route-grant contract: `State::issue_grant` existed with test-only
  callers, so no supported surface could produce the `gr_` id that
  `apply` / `queue submit --grant` / `board --grant` authorize against. The
  method takes `params.grant` (one `hf-grant/v1` document) plus
  `params.idempotency_key`, validates the document BEFORE any journaling,
  journals `mutate.grant.issue` before the single row insert, and returns
  the minted document itself. Exactly-once per idempotency key, replay of
  the same request id + key returns the recorded response, and an interrupt
  between intent and outcome leaves no partial grant: restart
  reconciliation re-reads the row as its commit marker and reports
  `committed before the interrupt` / `never committed`.
- `canter grant issue --request FILE --issue N --expires-in SECS` is the
  supported CLI mint path over that method. Every binding is DERIVED from
  the reviewed bound-input document (`canter queue preview --out`), the
  configuration re-observed now, the live daemon epoch and the explicit
  window: repository identity, issue number + acceptance revision,
  `workflow_hash`, `policy_hash` (the reviewed role-configuration
  revision), phase, caps, scope (`worktrees/issues/N`), `state_epoch`,
  `expires_at`. The grant id is content-addressed (`gr_` + sha256 of the
  canonical reviewed binding plus its issuance idempotency key). A fresh key
  opens a separate authorization window without extending or replacing any
  prior live/expired row; replay of one key remains exactly-once. Minting is
  NOT authorization: the returned grant id is presented
  at the board / `queue submit` point, and the reviewed digest approval
  there is unchanged.
- Fail-closed refusals on the mint surface: a foreign/malformed document
  (`usage.grant_request`), an issue outside the reviewed selected set
  (`usage.grant_issue`), a moved role revision
  (`refusal.profile.revision`), a moved epoch (`state.epoch_mismatch`,
  with epoch rotation invalidating the grant), an already-expired window
  (`refusal.grant.expired`) and any production-class binding (phase
  `production` or a `production`/`release` capability →
  `refusal.policy.production_confirmation`: production authority stays
  human-only and this surface carries no confirmation channel) — refused
  before any claim or row, in the CLI and again in the daemon.
- `tests/grant_issue.rs` proves the surface over the real binary, the real
  socket and real daemon children (14 tests): the minted binding read back
  by `grants.list` and by the dispatched run, consumption through the real
  `queue submit` path, expiry/epoch/role/production refusals, exactly-once
  + recorded replay, both crash points, and the untouched single-writer
  daemon lock.

### Added (issue #78 — CLI preview / request / inspect for one explicit lane handoff)

- The thin CLI lane surface over the completed daemon handoff path
  (#73–#77): `canter lane preview`, `canter lane request` and
  `canter lane status` for ONE exact lane. Preview and status are
  read-only — they may issue only `lane.replacement.status` /
  `lane.checkpoint.status` (a closed allowlist guard refuses anything
  else before a socket is opened), dispatch no mutation, and never
  advance a record.
- `lane preview` renders the reviewable `hf-lane-handoff/v1` plan: the
  source identity (session/process/role/generation), the target profile
  plan (`--profile KEY` derives the same reviewed
  `hf-profile-binding/v1` document `config show` previews), the
  repository-relative worktree, the closed effect-boundary chain of the
  phase surface, the retained workers/reviewers/pending gates (captured
  at the `checkpointed` boundary; read from the committed checkpoint when
  one exists) and the plan digest.
- `lane request` records ONE durable replacement request through the
  existing `lane.replacement.request` endpoint (no spawn, kill, Git or
  grant effect). The authorization binds the exact plan digest:
  `--confirm-digest HEX64` (noninteractive explicit) and `--confirm`
  (the human types the digest; the prompt goes to stderr) check the SAME
  digest, and a digest that no longer matches the current plan refuses
  as a stale plan (`refusal.plan.stale`) before any daemon call. A
  blanket `--yes` is refused whenever the policy overlay declares
  `production_confirmation` (`refusal.confirmation.policy`) and `deny`
  refuses every mode (`refusal.policy.production`) — the flag can never
  bypass the policy.
- `lane status` reads one record read-only: phase, outcome, blocker,
  intended (bound profile revision + provider/model) vs actual
  (successor verification evidence — `unknown` is never copied from the
  intended pair), the last verified transition, the next supported
  action and actionable guidance for an ambiguous retirement, a capacity
  hold, a failed adoption and an unknown model binding, naming only
  existing commands.
- JSON mode is pure: exactly one `hf-output/v1` document on stdout,
  never a prompt (a missing authorization is a typed usage refusal, not
  a read from stdin), and the human rendering carries the same plan
  digest, phase, bindings, transition, next action and stable error
  codes (the human diagnostic carries the code too).
- `tests/lane_cli.rs` proves the surface over the real binary and
  socket: read-only preview/status on the wire (a recording fake daemon),
  digest parity between the two authorization paths, policy refusal of
  `--yes`, stale-plan rejection after a moved profile revision, JSON
  purity, the paused-fleet boundary, the four guidance scenarios,
  human/JSON success and refusal parity, and a bounded read against a
  hung daemon.
- Excluded, as the issue requires: no TUI, no context auto-trigger, no
  whole-fleet recycle, no service activation, no new scheduler, no
  authorization bypass and no hidden auto-resume (a paused fleet stays
  paused through every CLI path).

### Changed (issue #106 — product rename `herdr-fleet` → `canter`)

- The product is renamed: package + library crate `canter`, canonical binary
  `canter`, and `--help`/`--version`, docs, skills, install/archive scripts,
  CI references, and the changelog all use the new name. Schema families
  (`hf-*`), envelopes, exit codes, and the daemon wire contract are
  unchanged, and the schema/version facts (`--version`) stay accurate.
- Compatibility is normative in
  [docs/contracts/compatibility.md](docs/contracts/compatibility.md#product-rename-issue-106):
  the pre-rename `herdr-fleet` binary ships as an alias running the identical
  CLI (deprecation warning on stderr); a pre-rename state/runtime tree is
  adopted **in place** (never copied, moved, migrated, or deleted) and a
  pre-rename config is still discovered; `HERDR_FLEET_CRASH_POINT` remains
  honored; live Herdr integration ids (`custom:herdr-fleet-pi|-jcode`,
  `herdr-fleet-lane`) are retained; frozen v0.1.0 architecture renders and
  historical `.report-*.md` records keep the old name by design.
- Machine-checked by `tests/rename_sweep.rs` (no stale reference outside the
  documented legacy set) and `tests/rename_compat.rs` (alias binary, legacy
  tree adoption, legacy config discovery, legacy env var).

### Fixed (issue #92 — executor lifecycle: deadlines, role-bound sessions, ledger retry frontier, executable supervision)

- Bounded, explicit, cancellable per-effect deadlines: no call site reads a
  bare timeout constant any more. A documented per-kind table (prompt
  1800 s, harness_start 300 s, other subprocess kinds 60 s, hard ceiling
  3600 s) plus an optional reviewed `deadline_secs` plan policy; the
  effective deadline rides on the step result, and a deadline terminates
  the child AND its process group.
- Group termination is confined to the effect-class harness invocations (the
  prompt row and a declared start row): every other adapter operation — the
  workspace protocol rows — spawns byte-for-byte as it did before the group
  runner existed, so the blast radius of the deadline fix stays on the
  audited effect path (issue #92 round 4).
- The harness prompt row runs the run's declared role binding (`-p <role>`,
  the declared provider/model pair, `chat --continue <session>
  --create-if-missing`) instead of a bare one-shot invocation; the session
  is derived once per run, bound by `harness_start` and continued by every
  prompt, and the retired pre-fix default session identity is never
  substituted (a step whose run bound no session, and that declares none
  either, is refused instead): a step never invents a binding or a session
  (`refusal.profile.binding`, `refusal.stale.identity`,
  `refusal.session.unbound`).
- The retry frontier derives from the recorded attempt ledger, so an
  `ambiguous` (timed-out) attempt is addressable by `run.retry` even when
  the run's recorded node fell behind; the single-use authorization, the
  fail-closed refusals and the no-duplicate-effect replay guarantees are
  unchanged.
- Armed supervision can advance its run: the driver hands the next
  unachieved step to the merged `apply` engine under every existing gate
  (journaled before effect, consumed retry authorizations respected, holds
  never cleared); non-armed supervision keeps its classification-only
  zero-effect contract verbatim.
- Round-5 diagnostic-truthfulness fix (found by the independent round-3
  review, finding V1): the group-signal and positive-pid-kill wrappers hand
  the helper attempt's result on unchanged — `None` means the attempt was
  delivered, `Some(reason)` means every candidate failed — so the one
  diagnostic line names a group signal that could NOT be delivered (with its
  reason) instead of rendering it as delivered, and the reap count and the
  survivor list are derived from delivered attempts only (a member no kill
  could reach is never counted as reaped). Pinned by
  `adapters::tests::a_failed_group_reap_attempt_is_reported_not_discarded`
  (raw exit 101 at the pre-fix head, 0 with the fix).
- Round-3 platform fix (found by hosted CI on Linux: the round-2 helper form
  does not deliver the group signal there, so both no-orphan tests failed with
  the helpers alive and the assertions did not print the runner's own
  diagnosis): the deadline now VERIFIES the group instead of trusting one CLI
  form — a best-effort `kill -9 -<pgid>` attempt, then the group's live
  members enumerated with the portable `ps -A -o pid=,pgid=,stat=` and killed
  by POSITIVE pid, re-enumerated until the group is empty or the bounded
  `GROUP_REAP_WINDOW` (375 ms) expires; the captured stderr carries one
  diagnostic line (helper attempt result, members reaped by pid, members that
  survived), and every group assertion in the suite prints the status and that
  stderr, so a CI failure is self-diagnosing.
- Round-2 platform fix (found by hosted CI on Linux, not visible on macOS):
  the group signal no longer depends on the child's allowlisted PATH — the
  `kill` helper is resolved from the ambient environment plus the standard
  system directories (absolute candidates included), and a signal that could
  not be delivered is named on the captured stderr (observable in the step
  outcome/evidence) instead of being discarded. The post-exit read of the
  captured pipes is bounded by the documented grace (`PIPE_READ_GRACE`,
  750 ms), so a descendant that survives the signal and holds the inherited
  write ends can never extend an effect past `deadline + grace` (the Linux
  failure: a timed-out `hermes` step with a surviving helper blocked the read
  for the descendant's lifetime and blew a 300 s bound).

### Added (issue #139 — `harness_start` runs the role inside a Herdr pane)

- The harness role now runs on a closed **execution substrate** selected by
  the reviewed step (`params.execution`):
  - `herdr` (the **default**, ADR-0003: Herdr owns workspaces, panes,
    terminals and agent-process hosting): the bind step creates (or, read
    back and REUSES) a Herdr pane in the run's lane worktree
    (`herdr workspace create --cwd <lane worktree> --label <session>
    --no-focus`), starts the role in it
    (`herdr agent start <session> --kind <kind> --pane <pane> [--
    <role args>]`, the profile-authoritative role/provider/model binding on
    the kind's documented flags), and records the lane↔pane/agent binding in
    the substrate (`herdr pane report-metadata … --token canter_lane=<session>
    --token canter_generation=<n>`). The prompt is delivered THROUGH the
    Herdr path (`herdr agent prompt <session> <payload> --wait`), the state
    and the delivery evidence are read back through `herdr agent get` /
    `herdr agent read`, and the interruption is the documented
    `herdr agent send-keys <session> ctrl+c` row. The recorded step outcome
    names the substrate, the pane, the agent and the settled Herdr state
    (`result.pane` / `result.agent` / `result.harness_state`), so the
    terminal outcome is collected through Herdr instead of being inferred
    from a process exit, and an interruption records `outcome: "interrupted"`
    distinctly from a settled terminal state;
  - `headless`: the pre-#139 bare-subprocess row, kept ONLY as a documented
    fallback an operator selects explicitly on the reviewed step. It is never
    chosen silently.
- **Availability and identity are fail-closed**: a missing/unspawnable Herdr
  executable refuses typed `refusal.unavailable.herdr` with NO fallback to a
  bare subprocess, a superseded lane generation (or another lane's, or another
  worktree's) pane/agent refuses typed `refusal.stale.generation` before any
  prompt is delivered, a kind with no documented Herdr kind refuses
  `refusal.execution.unsupported`, and a plan that cannot name exactly one
  lane worktree refuses typed on the pane substrate instead of creating a pane
  at a bare cwd or in the wrong lane.
- The admission/grant/ownership/journal/idempotency gates and the single
  `method_apply` effect path are unchanged; the substrate is a plan-bound step
  param, so it can never move at effect time.

### Added (issue #146 — A run that can never progress is releasable)

- `canter run release --run RUN_ID --reason TEXT` (daemon `run.release`,
  closed RPC set 39 -> 40; module-local `hf-run-release/v1`) frees the
  durable BOOKKEEPING of exactly ONE run that can never progress: the run's
  own `queue_ownership` row is removed without touching any successor's
  ownership, and the run is terminal afterward (`done` stays `done`, otherwise
  `invalidated`, pause state cleared, resume digest consumed) so it holds
  no global/per-repository/per-harness capacity. A
  hash-chained `run.release` audit record carries the operator reason, the
  exact run identity, what was freed and the authorization window the run
  held. After the release the freed issue is admitted by a fresh submission
  on its own merits, and the freed slot admits the issue that was waiting
  for capacity.
- The release is fenced fail-closed on anything genuinely live: a step
  dispatch still in flight refuses `refusal.run.in_flight` (nothing is
  killed, cancelled or cleaned up), an unconsumed bounded retry
  authorization refuses `refusal.run.retry_pending` (the authorization is
  never burned) and an unknown run is `state.not_found`.
  Terminal runs (`done` or `invalidated`) can release leftover ownership.
  The same idempotency key replays the recorded response; a fresh key records
  an audited ownership-absent no-op if ownership is already freed.
  A missing, revoked or EXPIRED grant is deliberately NOT
  a fence — an expired-grant run is exactly the case the release exists for:
  the record states that window (`usable:false`) without presenting or
  reusing it, so continuing that work needs a freshly minted window. A
  released run stays non-dispatchable (`refusal.instance.state` on the engine
  path; `refusal.run.terminal` on pause/resume/retry/dispatch; no supervision
  dispatch intent).
- The completing advance frees only the delivering run's ownership in the
  same transaction that marks it `done`; it cannot delete a successor's row.
  A fresh submission for the freed issue is admitted on its own merits.
- No schema, column, migration or dependency change: the release is a state
  transition over the existing `instances`/`queue_ownership` rows, proven by
  the `tests/run_control.rs` release battery (freed ownership and occupancy,
  a paused predecessor, the expired-grant window, the unconsumed
  authorization, the in-flight refusal and the idempotent replay) plus the
  public-entry-point parity test in `tests/run_control_cli.rs`.

### Added (issue #132 — the merge rehearsal certifies the published integration ref)

- The read-only `merge` rehearsal now proves the integration checkout is not
  diverged from the PUBLISHED integration ref before it certifies a
  policy-compatible merge: the ref is read from the checkout's `origin` remote
  (`git ls-remote`, so a bare-remote move is visible without a fetch) and a
  checkout behind it (someone landed without a fetch) or ahead of it (an
  unpublished local move) refuses `effect.merge.not_fast_forward`, naming the
  published head and the local head. An unreadable or absent published ref
  refuses `effect.merge.failed`: an unprovable base is never certified. No new
  step params, no schema change, and still no ref/checkout/remote mutation.

### Fixed (issue #132 — the unprovable-base refusal is the merge step's own code)

- The merge rehearsal's published-ref read now refuses `effect.merge.failed`
  on BOTH unprovable-base routes: an absent published ref, and an `origin` the
  checkout cannot read at all (absent, unreachable, unauthenticated). The
  latter used to surface the read's ordinary non-zero exit as a bare
  `adapter.exit`, which is not the published-ref contract the plan spec
  states (found by the exact-head review of PR #156). The refusal keeps the
  read's git diagnostics in its message; ambiguous and timed-out reads keep
  their own outcomes untouched. Regression witnesses cover both routes in
  `tests/mutation_engine.rs`.

### Fixed (issues #132, #172 — fail-closed squash-landed cleanup)

- The spine's `cleanup` accepts ancestry or content-equivalence against the
  local integration ref, allowing complete squash landings. The content
  proof uses NUL-delimited paths, disables rename detection to retain both
  endpoints, and compares literal pathspecs. Non-ASCII names no longer turn
  into unmatched quoted paths; glob/pathspec syntax is never interpreted.
- Partial landings (any changed path absent, modified, or still present
  after the lane deleted it, including a rename source) refuse
  `refusal.cleanup.unmerged`. Malformed path records and replacement
  characters also refuse: the text adapter cannot safely compare non-UTF-8
  paths, even when landed. An empty path list requires an independent empty
  delta check; Git failures/timeouts do not authorize deletion.
- Salvage records identify `landed_by: ancestor | content`, with `merge_base`
  for content. Only proven content uses branch deletion `-D`; ancestry uses
  `-d`. This is not a published-remote/forge-merge proof, and standalone
  `branch_delete` still requires ancestry. Real-daemon regressions in
  `tests/mutation_engine.rs` check refusal plus surviving branches, complete
  landings with unrelated integration work, and the ancestor proof label.

### Fixed (issue #176 — the merge step honours the plan's policy and publishes)

- The built-in `merge` step (`p7`) declared `merge_policy:"squash"` while the
  effect was a read-only rehearsal that never moved the integration ref: the
  step recorded `succeeded` with `landed:false`, the published integration
  branch never advanced, and the run's own `cleanup` (`p8`) could only refuse
  `refusal.cleanup.unmerged` — the acceptance spine's last-mile blocker. The
  effect now LANDS the certified delivery under the declared policy and
  PUBLISHES it: `squash` writes one integration commit whose tree is the
  delivered tree and whose parent is the published head, `ff` lands the
  delivered head itself; the landing is fast-forwarded into the integration
  checkout (never a rewrite, never a forced update; uncommitted operator work
  the landing does not touch survives) and pushed to the same `origin` remote
  the published ref is read from. The published ref is read back, so the step
  succeeds only when it carries the landing; a landing that cannot be
  published records a typed non-success (`effect.merge.failed`, or the bounded
  `refusal.run.retry_required` when the published ref moved) and the checkout
  is rolled back to the published head. A delivery whose content is already on
  the merge target reports `mode:"already-landed"` and publishes nothing. The
  outcome now records `published_head`, `published_after`, `landed_head` and
  the pre-landing `checkout_head`. The #156 published-ref target, the #182
  bounded reconciliation loop, the evidence gate and the closed
  `squash | ff` policy are unchanged; `post_merge_verify` and `cleanup`
  certify the landed head by ancestry or by the same fail-closed content fact
  (`tests/mutation_engine.rs`).

### Fixed (issue #132 — cleanup certifies a squash landing visible only on the published ref)

- The spine's `cleanup` no longer refuses its own sanctioned deletion when
  the landing exists only on the forge: the checkout's own integration ref
  cannot see a remote (squash) landing, so once the reviewed PR was merged
  the run could never complete on this repository's (squash) policy. When
  the local proof refuses `refusal.cleanup.unmerged`, cleanup now proves the
  landing against the PUBLISHED integration ref — read from `origin`
  (`git ls-remote`), FETCHED and verified against that read — with the same
  fail-closed ancestry-or-content fact, and only when the checkout's own ref
  is strictly BEHIND it; a checkout ahead of, or diverged from, the
  published view still refuses and is never certified. The checkout's own
  ref is never moved, an unreadable or unverifiable published ref proves
  nothing, and the refusal the local view produced stands whenever the
  published view cannot add a proof. A published-proof salvage record names
  the `published_head` it was made against and deletes with `-D`. The local
  and published proofs share the same changed-path/content comparison
  helpers, so the two routes cannot drift. Real-daemon witnesses in
  `tests/mutation_engine.rs`.

### Fixed (issue #101 — one clock read per audit record)

- `append_audit_locked` binds ONE instant per record: the value is handed to
  the append at the call boundary (`append_audit_at_locked`) and the SAME
  value builds the hash-chained canonical `line` and the persisted `at`
  column. Two reads could straddle a wall-clock second boundary and leave a
  row whose own columns disagreed with its hashed line, so the next open's
  chain verification refused it (`state.audit_tampered` / "column/line
  mismatch") on a loaded host. The regression test drives the call-boundary
  seam with an instant far from any wall-clock read — a re-introduced second
  read disagrees with it and is RED — and the production entry point is
  asserted against the same column/line invariant plus the reopen check
  (`src/state.rs`).

### Changed

- An authorized bounded retry is consumed by the run's own supervision
  (issue #241). `run retry` records the single-use authorization; the very
  re-dispatch it authorizes now spends it — the armed driver derives the
  continuation of that exact diagnosed step (including the ambiguous effects
  and worker/review timeouts the class vocabulary names) and the daemon's
  supervised apply path consumes the HELD row with the dispatch's own
  journaled idempotency key, instead of refusing it `refusal.run.retry_pending`
  and parking the frontier until an operator dispatched by hand. The
  consumption is exactly once (a second attempt still needs its own
  authorization), the bounded budget is unchanged (a spent bound parks typed),
  a re-dispatch without an authorization still refuses
  `refusal.run.retry_required` before any effect, and `run release` still
  never burns an authorization — its refusal now names the remedy precisely.
  `supervision status` reads the frontier's retry disposition back
  (`evaluation.retry`: `awaiting-authorization` / `authorized-awaiting-dispatch`
  / `driver-dispatch` / `exhausted`), so "awaiting an operator authorization",
  "authorized, awaiting dispatch" and a refused continuation are three
  distinct reads. The ONE exception is the risk-classed committed TAIL
  (`merge` / `cleanup`): an ATTEMPTED tail keeps issue #152's rule (it stays
  the operator's) and a held authorization over it is consumed by the
  operator's own `run dispatch`. The operator's own corrected `run dispatch`
  still consumes
  the authorization when it arrives first (and is the only consumer for a run
  whose supervision is not armed).
- The bounded check re-evaluation is reachable in the exact case it exists
  for (issue #243). `run reevaluate` re-dispatches the run's own check
  producer, so its inner dispatch is a fan-out like any other: the control
  now PRODUCES the host-resource proof the gate requires, by running the SAME
  dispatch-time renewal the supervisor already takes (audited
  `host.proof.renewal`, measured at the run's lane root) on the
  re-evaluation's own dispatch — a lapsed proof renews, an unmeasurable host
  still refuses the recorded proof, and a proof that was never recorded is
  never invented. The fan-out admission refusal names the failing
  PRECONDITION and the reachable REMEDY (the exact commands that renew the
  proof), never a bare code. The run's own armed supervision drives that same
  bounded, attributed, journaled control when the recorded condition is the
  engine's own — bounded by the control's own recorded bound — so a stranded
  green delivery reaches its publish step with no operator action, while a
  parked run is still never reported eligible, the tail behind an unverified
  delivery is still never driven, and a normal dispatch with no proof still
  refuses.
- A transient check failure recorded inside the evidence of a step that
  succeeded no longer deadlocks the run (issue #230). The new
  `run.reevaluate` control re-runs the run's OWN `review_evidence` step
  (reviewer leg only) at the SAME certified head on a fresh derived lane
  round, so the checks are RECOMPUTED by their producer instead of being
  trusted forever: bounded per `(run, step)` from the durable journal,
  attributed (operator identity + reason) in the hash-chained audit before
  anything is dispatched, and never adjudicated — a recomputation that comes
  back failing refuses the consumer with the same `refusal.evidence.failed`
  (the merge gate reads the newest recorded evidence, so it consumes the
  recomputed fact, never a frozen one). `refusal.evidence.failed` now names
  the non-passing checks, and a continuation the engine refuses is reported
  by supervision with the engine's own code AND reason
  (`evaluation.refusal`). A tail frontier the engine refuses *before any
  dispatch exists* — the run's own verified-delivery consumer behind a record
  whose checks are not all `passed` — is named too (`supervision.delivery_unverified`
  with `refusal.evidence.failed` and the engine's own message derived from the
  same recorded facts), instead of being reported `continuation-eligible`
  while nothing can land.
- Documentation polish (issue #12, PR #13): security recipe doc line fix
  and dark-preview renderer note; `docs/` claims kept in step with the
  shipped surface.

### Fixed

- A fix round no longer strands the re-review it hands the leg to (issue
  #248). A recorded review FAIL advances the run's reviewer leg to a new lane
  round, so the plan's binding — the checkout of the round the plan was
  rendered at — names a lane the step is dispatched at no longer, and every
  re-dispatch refused `refusal.lane.identity` and parked. The bounded
  re-evaluation control now RE-RENDERS the binding it dispatches: `run
  reevaluate` merges the leg's OWN lane checkout for the round it is
  dispatching (`issues-<N>-rev<R>`) over the committed params, exactly as it
  already merged the derived round. ONE lane checkout still belongs to exactly
  one leg — a genuinely foreign checkout (the run's own lane, a sibling leg's,
  another issue's) is never reinterpreted and is refused typed exactly as
  before, and the bare-subprocess fallback keeps its byte-for-byte binding.
- The recorded fix-round handoff is read where the daemon persists it, and the
  run drives its own bounded check re-evaluation for a recorded FAIL (issue
  #255 / #254) — and the disposition it reports is derived from the repair
  leg's OWN recorded state, never from the head the FAIL was handed at (issue
  #256). The head a handoff is DISPATCHED for is a recorded fact and can never
  move by itself; the leg advances the branch in its OWN lane checkout, so the
  engine's `hf-fix-round/v1` record now names that checkout (`worktree`: the
  lane the leg was created or verified at) and the daemon reads THAT checkout's
  head when it classifies the run — a bounded, allowlisted, READ-ONLY `git`
  read taken outside the state guard. A head that DESCENDS the certified head
  means the leg delivered, and the disposition says so instead of reporting a
  dispatched leg as work in flight. A leg whose own checkout has not advanced
  keeps `waiting-workers` / `supervision.fix_round_dispatched` unchanged, and
  every read that cannot be taken leaves the recorded disposition exactly as it
  was. The same read binds the next review round: a review dispatch of a run
  whose handoff leg delivered a descendant head presents THAT head as the
  observed head, so the reviewer leg's derived checkout materializes the
  delivered commit instead of re-reviewing a head whose check can never flip.
  The run's own delivery-certification gate (issue #202) is untouched: a head
  the run's own collection has not certified is still never consumed.
- The recorded FAIL handoff is read from where the daemon ACTUALLY persists it
  (issue #254), so a review FAIL reports its fix-round disposition instead of
  parking with no remedy. The review step's own apply row keeps the effect's
  returned document in its RESPONSE column (`hf-rpc-response/v1`,
  `result.fix_round`) while `outcome.result` is `null` — the supervision
  evidence loader read only the outcome column, so `evidence.fix_round` was
  `None` in production and the classifier fell through to a bare
  `supervision.review_failed`. The loader now reads the response document
  (the same way the other recorded read models read a dispatch's own result)
  with its validation unchanged (`hf-fix-round/v1` plus the four named fields;
  the outcome shape stays readable beside it). A handoff recorded at another
  head than the run's newest recorded review evidence is no longer silent
  either: it is reported as the fix-round disposition
  `supervision.fix_round_head_moved` (class `needs-attention`), whose detail
  names the remedy — the fix leg's recorded lane — and both head prefixes.
  The driver drives the run's own bounded check re-evaluation for the recorded
  FAIL as well (the same control, the same per-`(run, step)` bound), so a
  FAIL-then-fix sequence is not parked on the fail.

### Security

- Private vulnerability reporting via GitHub's private advisory flow
  (SECURITY.md); no secrets in public issues.

### Fixed (issue #170 — the pane-collection wait: a confirmed stop, and bounds driven by recorded progress)

- **A stop is CONFIRMED, never inferred from a flapping status.** A pane
  `collect_outcome` now reads TWO views of the run's own lane per sample (the
  lane's `agent get` row and its `agent list` status row) plus the lane's own
  `state_change_seq` counter, and only `COLLECT_STOP_SAMPLES` (3) consecutive
  samples — each separated by the real `COLLECT_STOP_INTERVAL_SECS` (5 s)
  interval, BOTH views non-working, the lane's own counter not moving — make
  the worker's turn a stop. `refusal.collect.empty_delta` is therefore only
  ever the outcome of a confirmed stop, and a live worker is never judged
  empty: the measured live `p5-101` collection judged a working pane stopped
  from two read-backs ~100 ms apart, refused the emptiness four minutes into a
  93-minute turn and consumed the run's retry (issue #170 N7).
- **The wait is bounded by recorded progress, not by a wall clock.** The
  step's effective `deadline_secs` is now the wait's NO-PROGRESS WINDOW: while
  the lane reports `working`, its read-back moves, or its collected delivery
  head moves, the wait extends — up to the hard `COLLECT_CEILING_SECS` (6 h,
  ≈4× the measured 93-minute real turn, against which the old 1800 s wall made
  the step unconvergeable by construction). A lane that records no progress for
  the window parks as the typed `effect.worker_timeout` naming the progress it
  last saw and the elapsed silence; so does a lane still producing progress at
  the ceiling. The window is decided on what each SAMPLE recorded, so a
  read-back that carries progress at the window's boundary is never parked
  past, while every read gets a real budget (what the window has left, floored
  at one second). The wait is never unbounded (issue #170 N8).
- The wait polls at a bounded documented cadence (`COLLECT_STOP_INTERVAL_SECS`,
  5 s — two subprocess rows per sample, 12 samples/minute instead of the
  pre-change ~100 ms loop; issue #170 N3); the in-memory collection reservation
  is keyed by `(run, step)`, so a spine with two collection steps in one run
  never has the second silently answered `awaiting <other step>` (issue #170
  N5); and the daemon's shutdown invariant is restated EXACTLY — the
  supervision driver is cancelled and joined before the lease is dropped, while
  a bounded collection runs on its own thread and is deliberately never joined
  (an interrupted collection is the already-modelled ambiguous claim, never a
  second claim; issue #170 N4).
- Contract surfaces updated and the remaining doc items recorded as accepted
  limitations: `spec-daemon.md` (the confirmed stop, the progress bound, the
  fail-closed `refusal.incomplete.identity` widening of the collection's
  refusal surface — issue #170 N6 — and what the continuation-window counter
  counts, since an in-flight collection wait is eligible and refreshes it —
  issue #170 N1) and `spec-plans.md` (the collection's window semantics, and
  the shared published-ref read's `effect.merge.failed` code on
  `checkout`/`worktree_create` — issue #170 N2).
