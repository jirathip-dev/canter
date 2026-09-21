# Spec: lifecycle semantics — schedules, admission, cleanup archive, remote transport, cold-boot recovery

Refs #9, #35 (lifecycle slice plus Herdr 0.9 compatibility audit). Family:
`hf-schedule/v1` (fixtures under
[`schedule/schedule.valid.json`](../../schemas/fixtures/schedule/schedule.valid.json)).
Rust: `src/lifecycle.rs`,
`src/remote.rs`, state migration `m0004_schedules_lifecycle_v4`.
Wire probes: `tests/daemon_lifecycle.rs`, cleanup probes in
`tests/mutation_engine.rs`; pure probes in `src/lifecycle.rs` and
`src/remote.rs` test modules.

## 1. `hf-schedule/v1` — recurring non-destructive cadence records

A schedule is the durable recurring-grant record: it pins the exact grant
bindings (repository/issue, `workflow_hash`, `policy_hash`, `phase`,
`scope`, `caps`, `expires_at`) plus the cadence (`anchor`,
`every_secs`). It validates like a grant but is **closed to the `read`
phase and the single `read` capability** — a schedule document can never
carry production/destructive effects (schema-level refusal; fixtures
`schedule.malformed.json`). `schedule_id` is `sd_` + 16 lowercase hex.

```json
{"schema":"hf-schedule/v1","schedule_id":"sd_0123456789abcdef",
 "repository":"example-org/widgets","issue":{"number":123,"revision":"<40hex>"},
 "workflow_hash":"<64hex>","policy_hash":"<64hex>","phase":"read",
 "scope":"worktrees/issues/123","caps":["read"],
 "expires_at":"2999-01-01T00:00:00Z","anchor":"2026-09-06T00:00:00Z",
 "every_secs":300}
```

Rows live in the SQLite `schedules` table (m0004 adds the canonical `doc`
+ `updated_at`). `enabled` is a hard pause flag (durable across
daemon/service/host restarts); `next_run_at` is the single-flight window
guard (NULL = immediately due — create and resume both re-arm this way).

## 2. Evaluation semantics

One evaluation tick evaluates every enabled schedule once. Semantics are
anchored, coalesced, single-flight, and never replay a backlog:

- The next window is anchor-aligned: `next = anchor + k*every_secs` for
  the smallest `k` with `next > now` (unit: UTC seconds; cadence keeps its
  original phase across sleep/reboot/DST-style wall-clock jumps).
- A schedule fires when `now >= next_run_at` (or `next_run_at` is NULL).
  Firing journals `read.schedule.ran` (audit) + `schedule.ran` (event)
  and atomically advances `next_run_at` to the next window — a second
  tick in the same window is idle (persisted-window single flight).
- Missed windows are never replayed: after a long sleep/reboot exactly
  ONE fresh evaluation fires and the window jumps ahead of `now`. This is
  internal schedule-window state, not retained events from Herdr; the #9
  runtime never subscribes to Herdr's event stream.
- Clock movement backward makes ticks idle until the window catches up
  (never a double fire).
- Refused evaluations **park the schedule** (`enabled:false`) with a
  journaled reason (`expired`, `policy_changed`, `issue_changed`,
  `doc_invalid`): parking is an explicit terminal state that only an
  explicit human `schedules.resume`/`schedules.create` can lift — no
  evaluation path can ever enable a schedule. Optional `observed`
  params attest the live policy hash/issue revision (same
  client-attestation boundary as `apply`); a mismatch parks with
  `policy_changed`/`issue_changed`.
- `schedules.evaluate` RPC and cold boot both run ticks; evaluations are
  not idempotency-claimed (a crash between window advance and journal
  leaves at most one extra fresh evaluation — never a backlog).

## 3. Cold-boot recovery (AC9)

`daemon serve` runs, after claim reconciliation and before serving the
socket, exactly one evaluation tick per due schedule — the same
reconcile path that runs when Herdr is absent or unhealthy, because the
tick never spawns or probes anything (daemon-owned state only; PATH
without herdr/git/gh is covered by `cold_boot_fires_due_schedule_once_per_boot_without_tools_on_path`).
A restart can never re-fire an advanced window, so there is no retry
storm: each boot fires each due schedule at most once.

## 4. Fan-out admission (AC1)

`harness_start`/`prompt` applies refuse **before any intent is journaled**
when any applicable admission input is missing, stale, or exceeded:

- `flags.admission` (whole bundle) missing → `refusal.admission.proof_missing`;
  its `host_proof.measured_at` older than the freshness window →
  `refusal.admission.proof_stale`; caps block absent →
  `refusal.admission.cap_missing` (unknown measurements refuse new work).
- Global and per-repository caps are enforced against the daemon's own
  durable state (active lanes per repository; the proposed lane itself is
  excluded). The per-harness axis uses the caller-attested
  `harness_lanes` count (harness occupancy is client-side state; same
  attestation boundary as apply observed params). Refusals:
  `refusal.admission.cap_global` / `cap_repository` / `cap_harness`.
- Declared monorepo paths never overlap: concurrent lanes whose scopes
  share a path-component prefix in the same repository refuse
  (`refusal.admission.monorepo_overlap`; component-aware — `issues/1`
  never overlaps `issues/12`). Pure predicate probes in
  `src/lifecycle.rs`.
- Caps are per-request declared bounds (like plan/observed attests); the
  durable, state-owned half is the running-lane count. Default caps and
  freshness windows are design commitments (`src/lifecycle.rs` consts).

### 4.1 The supervisor's own measurement (issue #198)

The supervisor is a caller of this gate, so when it dispatches a fan-out
step it presents a proof **measured at dispatch time** — never the
submit-time attestation echoed back, and never a fabricated instant:

- The measurement is a real host-resource observation of THIS dispatch: the
  free bytes the host exposes at the run's lane root
  (`topology.worktrees_root`, where the lane's own worktree lives). The
  measurement instant is the instant of that observation.
- The renewal is the RUN's own act (like its lapsed grant window, issue
  #184) and is bounded: only a fan-out step (`harness_start`, `prompt`, or
  the reviewer leg of a `review_evidence` step — issue #193) of a LIVE run
  whose own recorded proof has actually lapsed renews. A missing proof is
  never invented (`proof_missing` stands), a fresh proof is presented as
  recorded, and a paused/held/blocked/queued/finished run never renews.
- Every renewal is audited BEFORE the renewed proof is presented: one
  `host.proof.renewal` journal record naming the superseded instant, the
  replacement (the measurement) and the observed free bytes, plus one
  `run.host_proof.renewed` daemon-log line. A renewal that cannot be
  recorded is not presented (fail closed).
- An UNMEASURABLE host renews nothing: the recorded proof is presented
  unchanged and the gate still refuses `refusal.admission.proof_stale`
  (`run.host_proof.unmeasurable` names why on the daemon log). Nothing here
  weakens a gate — caps, occupancy, pacing, overlap and the freshness bound
  itself stay the gate's own decisions; the presenter only ever supplies a
  measurement.

The operator's own `run dispatch` presents its explicit admission
attestation (`run_control::DispatchParams::admission`), exactly as before.

### 4.2 The recovery control produces the same measurement (issue #243)

A control that recomputes a recorded check (`run.reevaluate`) re-dispatches
the run's own check producer, so its inner dispatch is a fan-out like any
other and the proof requirement genuinely applies to its effect. The control
therefore **produces** the proof instead of being exempted from it: the
dispatch-time renewal of §4.1 runs on the re-evaluation's own dispatch too
(same bound, same audit record, same fail-closed rule). An unmeasurable host
renews nothing and the recorded proof is refused exactly as before, and a
proof that was never recorded is never invented.

The policy choice is deliberate: the alternative the issue offered —
not applying the proof requirement to a read-and-recompute operation — was
rejected, because the recompute starts the run's own reviewer lane, so the
host resource the gate measures is exactly the resource the recompute
consumes. Nothing else is relaxed: caps, occupancy, pacing, overlap and the
freshness bound stay the gate's own decisions for this dispatch as for any
other.

The refusal names the failing precondition AND the remedy. `proof_stale`
names the stale proof and the exact commands that renew it (`run reevaluate`
for the run's own terminal-success check producer, `run dispatch --admission
FILE` for a frontier step or for a proof that was never recorded);
`proof_missing` names the attestation path. Every other admission refusal
keeps the gate's own message verbatim.

## 5. Cleanup archive/salvage and canonical target classification (AC7)

- Cleanup targets are canonicalized and must stay inside the worktrees
  root (`refusal.path.uncontained`); a **symlinked** cleanup target is
  refused outright (`refusal.cleanup.symlink`) — cleanup never follows or
  removes symlinks.
- Dirty work can never be deleted (`refusal.cleanup.dirty`). With
  `params.archive: true` (and an optional `topology.archive_root`, which
  must be daemon-owned), the effect instead **preserves the exact bytes**
  into `archive-<branch>-<unix>` under the archive root, excluding `.git`,
  refusing nested symlinks, and writing a checksummed `manifest.json`
  (`hf-archive/v1` entries: relative path + sha256 + bytes, totals, and
  the manifest digest). `removed` stays false; the lane is left in place
  and a repeat archive within the same second refuses to overwrite
  (`effect.archive.failed`). Byte-for-byte probes live in
  `tests/mutation_engine.rs`.
- Cleanup first accepts ancestry into the **local** integration ref. If
  ancestry fails (as it normally does after a squash), the content route
  compares every path changed since the merge base against that ref. Git
  supplies NUL-delimited names with rename detection disabled, so both the
  deleted source and added destination of a rename must match. Comparisons
  use literal pathspecs: Unicode, whitespace, glob characters and leading
  pathspec magic are names, not quoting or patterns. Git compares content,
  existence and modes; submodule changes are not ignored. Integration-only
  changes outside the lane's changed paths do not block cleanup.
- When the local proof refuses `refusal.cleanup.unmerged`, cleanup proves the
  landing against the **published** integration ref (issue #132): the
  sanctioned landing happens on the forge, and a remote landing never updates
  the checkout's own ref. The published head is read from the checkout's
  `origin` (`git ls-remote`), FETCHED into the checkout's remote-tracking ref
  and verified against that read; only a checkout **strictly behind** it may
  certify from this view — a checkout ahead of, or diverged from, the
  published ref is an unpublished local move and refuses. The same
  ancestry-or-content fact is then proven against the fetched head, never a
  weaker one. An unreadable or unverifiable published ref proves nothing and
  leaves the checkout's own refusal standing; the checkout's ref is never
  moved.
- A **partial landing** means at least one changed path differs from the
  lane's final state: an addition is absent/modified, a deletion survives,
  or only one half of a rename landed. It refuses `refusal.cleanup.unmerged`,
  as does later divergence on those paths. The text-only subprocess adapter
  cannot guarantee lossless non-UTF-8 names: any replacement character
  (including a literal U+FFFD), malformed NUL framing or empty name refuses
  the same code, even if the content landed. An empty path list is accepted
  only after a separate unrestricted quiet diff confirms an empty lane
  delta. Git errors/timeouts propagate without deletion.
- The salvage record names `landed_by: ancestor | content` (the latter also
  records `merge_base`). Cleanup removes the clean worktree then deletes
  the branch using `-d` for ancestry or `-D` for proven content; a proof made
  against the published head deletes with `-D` and also records the
  `published_head` it was made against. The proof does not itself perform or
  claim a forge merge (the forge owns the policy merge); standalone
  `branch_delete` remains ancestry-only. Refs #132, #172.

## 6. Remote transport contract (AC5/AC6, capability C16)

`src/remote.rs` is the ONLY remote path: the system `ssh` executable,
argv-built (never shell-evaluated), allowlisted environment, bounded
deadline. It adds no daemon federation and no network control API — no
daemon RPC carries a remote invocation; real remote canaries are
separately human-gated (issue stop condition), while this slice proves
the contract with fake-ssh argv tests.

- Remote plans bind a VERIFIED host identity (`RemoteTarget` +
  `verified_identity`, 64-hex or `SHA256:` form) and the remote state
  (`expected_epoch`); a reply that does not echo the binding is refused
  (`refusal.remote.state_mismatch`); unparseable replies are refused
  (`refusal.remote.malformed`), never guessed.
- UNKNOWN target/action/remote identity classifies as production +
  destructive (risk-model lattice) and requires a fresh interactive TTY
  confirmation (`refusal.remote.identity` otherwise); scheduled
  automation can never authorize remote work.
- Transport failure (spawn failure, deadline, process death) yields an
  explicit **ambiguous** outcome: the caller never replays locally;
  ambiguous remote effects require external reconciliation exactly like
  interrupted local effects.

## 7. Retention and audit deletion (AC8)

- Audit/event rows are bounded append-side by `Retention`
  (defaults: audit 5000 rows beyond genesis, events 2000); the chain
  genesis is never pruned.
- Daemon-owned backups are bounded by count/age/bytes
  (`backup::BackupPolicy` defaults: keep 8, 90 days, 1 GiB);
  `backup.create` journals a `mutate.backup.prune` intent, prunes only
  verified pairs, and reports the removed snapshots.
- Deleting audit records is itself an explicit destructive operation:
  the only `DELETE FROM audit` sits inside the append-side retention
  prune, and no purge/truncate surface exists (static probe in
  tests/no_network_surface.rs).

## 8. Surface closure (AC10)

Schedules, admission, recovery, and the remote transport add no network
listener, no messaging/notification, no MCP/plugin/webhook surface, and
no telemetry (banned-token scan in tests/no_network_surface.rs extends
to the new modules; the daemon's only listener stays the Unix socket).
