# Spec: SQLite migration/journal/audit semantics, backup/restore boundaries, retention

Refs #3. Families: `hf-migration/v1`, `hf-audit/v1` (JSONL records of the
journal/audit tables). Fixtures under
[`migration/`](../../schemas/fixtures/migration/migration.valid.json),
[`audit/`](../../schemas/fixtures/audit/audit.valid.jsonl). Design commitment (locked spec:
"SQLite owns leases, idempotency claims, schedules, journals, and recovery
state"; AC6 journal-before-mutation; AC7 restore semantics).

## SQLite role and invariants

- One SQLite state database per user/daemon owns: leases, idempotency
  claims, schedules, journals, audit records, migration bookkeeping, and
  recovery state. SQLite is the durable authority for these; live
  Git/Herdr/GitHub read-back owns observed reality; issues own intent.
- Writes are versioned, locked, atomic, and recoverable. The database is
  daemon-owned; the CLI never writes it behind the daemon's back.

## Migration semantics: `hf-migration/v1`

Migrations are linear, ordered, and journaled:

```json
{"schema":"hf-migration/v1","migration_id":"m0001_create_state_v1","applies_from":0,
 "applies_to":1,"checksum":"<64hex>","description":"create leases, idempotency claims, journal, and audit tables"}
```

- `migration_id` format `mNNNN_<snake>`; `applies_to` must be exactly
  `applies_from + 1` (linear chain; `migration.malformed.json` jumps
  0 → 3 and is refused).
- `checksum` is sha256 over the migration artifact's canonical bytes; the
  checksum is recorded before the migration executes.
- Migration procedure (future implementation contract): run inside a
  transaction against the recorded `PRAGMA user_version`; apply each
  pending manifest in order; record success; on any failure the
  transaction rolls back and the daemon fails closed (never half-migrated).
- Runtime/schema/workflow/migration changes reset the 1.0 soak clock
  (locked spec release rule) — migration records make that determination
  auditable.

## Journal/audit semantics: `hf-audit/v1` (AC6)

Audit intent is durably recorded **before** any mutation effect; inability
to journal fails closed — the mutation does not start.

```json
{"schema":"hf-audit/v1","seq":41,"action":"mutate.merge",
 "target":"example-org/widgets:staging<-issues/123",
 "idempotency_key":"ik_apply-20260906-0001","plan_hash":"<64hex>",
 "grant_id":"gr_0123456789abcdef","epoch":3,
 "recorded_before_mutation":true,"at":"2026-09-06T00:00:00Z"}
```

- Every record: monotonic `seq`, closed action code (`mutate.*` for
  mutations, `read.*` for reads), target, idempotency key, optional plan
  hash/grant id, epoch, and the `recorded_before_mutation` flag.
- A `mutate.*` record with `recorded_before_mutation:false` is **refused**
  (`audit/audit.malformed.jsonl`) — the fail-closed rule is in the schema
  itself, so no implementation can journal after the fact and still produce
  valid records.
- The journal is append-only; consumers read it as JSONL
  (`journal.tail` RPC). Redaction applies before any record is written.

## Write-failure classification: disk exhaustion is its own condition (issue #231)

A write-class SQLite failure still fails closed exactly as before: the
handle is poisoned and every later mutation refuses `state.poisoned` naming
the FIRST failure. What changed with #231 is that the failure is CLASSIFIED
before it is remembered and returned:

- An I/O-class failure (`SQLITE_IOERR`, `SQLITE_FULL`) observed while the
  state database's own filesystem holds fewer free bytes than the
  documented floor (`HOST_FREE_FLOOR_BYTES`, the same commitment the
  fan-out admission enforces) is reported as **`state.disk_exhausted`** —
  naming the observation, the floor and the raw SQLite detail — so an
  operator can tell "the host's disk is full" from "the database is
  broken". The measured trigger: a 100% full data volume surfaced as
  `state.poisoned: state.write_io: … SQLITE_IOERR unable to open database
  file`, indistinguishable from corruption.
- A corrupt, future-schema, read-only or busy database keeps its own typed
  code however little space the host has; an unobservable state root (a
  host that does not expose its free bytes) proves nothing and the failure
  is reported unchanged. No measurement is ever fabricated.
- The classification is decided by one pure predicate over (error class,
  observed free bytes) with the probe at its call boundary, so the decision
  is witnessable without a genuinely full volume.

## Backup/restore boundaries and retention

| Boundary | Content | Owner | Retention (default; configurable via policy overlay) |
| --- | --- | --- | --- |
| Daemon-owned backup | SQLite snapshot + migration chain + journal tail, created via `backup.create` | daemon-owned state dir | keep last N point-in-time backups; prune only with a `cleanup` grant; never touches external repos |
| External repositories/worktrees | NOT backed up by canter | Git remotes + operator | Git history is the operator's own retention domain; canter never copies external state into its backup |
| Logs/events | JSONL event stream | daemon | bounded by retention policy; rotated without data loss of journal records |

- Backup covers daemon-owned state only; the boundary is explicit so that
  "restore" can never be mistaken for a repository restore.
- **Restore (AC7)** = restore.begin on a daemon-owned backup → rotate epoch
  (`hf-epoch/v1`, `reason:"restore"`) → invalidate prior grants/digests →
  mark interrupted work ambiguous → require external reconciliation before
  new grants. See [spec-plans.md](spec-plans.md) §3.
- Retention defaults are design commitments; actual sizes/budgets are
  [awaiting-evidence] (benchmarks, [benchmarks.md](benchmarks.md)).

## Lifecycle additions (issue #9)

- **Migration `m0004_schedules_lifecycle_v4`** (0 → 4 chain) adds two
  columns to the `schedules` table: `doc` (the canonical `hf-schedule/v1`
  document text) and `updated_at`. `SCHEMA_VERSION` is 4.
- **Schedule rows** are the durable recurring-grant cadence records
  (spec-lifecycle.md): `enabled` is a hard pause flag — the evaluation
  path never toggles it; `next_run_at` is the single-flight window guard
  (NULL means immediately due, e.g. after create/resume). Evaluation
  commits window advance + `read.schedule.ran` audit + `schedule.ran`
  event atomically; a refused evaluation (expired, policy/issue changed)
  parks the row with a journaled reason.
- **Retention of daemon-owned backups** is bounded by age, count, and
  total bytes (`backup::BackupPolicy` defaults: keep 8, 90 days, 1 GiB);
  `backup.create` prunes verified pairs outside the policy and journals
  the prune intent (`mutate.backup.prune`) before removing anything.
- **Deletion of audit records is itself an explicit destructive
  operation**: the single `DELETE FROM audit` lives inside the append-side
  retention prune (`prune_audit_locked`, always keeping the chain
  genesis); there is no purge/truncate surface anywhere
  (static probe in tests/no_network_surface.rs).

## Handoff additions (issue #73)

- **Migration `m0005_lane_replacements_v5`** (0 → 5 chain) adds the lane
  replacement record tables: `lane_replacements` (one record per logical
  lane generation, `UNIQUE (lane_id, generation)`, with the typed phases
  `requested` → `quiescing` → `checkpointed` → `retired` → `starting` →
  `adopting` → `adopted`, explicit `pending`/`held`/`ambiguous`/`cancelled`
  outcomes, and the bound source session/process/role/worktree/reason
  identity) and `lane_replacement_events` (the transactional transition
  history committed with each record write). `SCHEMA_VERSION` is 5. The
  migration is purely additive — no existing table or row is touched, so
  stored grants are never reinterpreted by the upgrade.
- **Request-only semantics**: the `lane.replacement.*` RPCs (see
  spec-daemon.md) write durable records and journal their intents through
  the same claim machinery as every daemon mutation; nothing on the surface
  spawns, kills, or touches Git, and no grant is required, issued, or
  consumed. Transitions are transactional compare-and-set (stale
  generation, invalid order and replayed expectations cannot advance); a
  `held` record refuses advancement durably across restarts; restart
  reconciliation marks an interrupted transition `ambiguous` (external
  reconciliation required); and cancellation before retirement invalidates
  a pending replacement while leaving the original lane generation
  untouched. An agent may request its own retirement but can never
  authorize its own replacement effects.

## Checkpoint additions (issue #74)

- **Migration `m0006_lane_checkpoints_v6`** (0 → 6 chain) adds the lane
  checkpoint table `lane_checkpoints`: one checkpoint per replacement
  record (`UNIQUE (replacement_id)`), holding the canonical snapshot of
  the captured lane (role/task, worktree/branch/head/base, dirty and
  untracked inventory with their bounded integrity digests, report round +
  reviewed sha, pending gates, observed child commands, execution/ack
  state, orchestrator references, daemon-observed outstanding operations),
  the two observation digests, the snapshot digest, and the generated
  brief digest. `SCHEMA_VERSION` is 6. The migration is purely additive —
  no existing table or row is touched, so stored grants and replacement
  records are never reinterpreted by the upgrade.
- **The checkpoint commit is atomic**: `commit_lane_checkpoint` writes the
  checkpoint row, the record's `quiescing` → `checkpointed` transition and
  the transition-history row in ONE transaction (the record's compare-and-
  set fence re-asserts pending/quiescing/generation). The compact brief is
  a deterministic derivation of the committed row: it is materialized
  after the commit, and restart reconciliation regenerates it (verifying
  `brief_digest`) when a crash lands between the commit and the artifact
  write. An artifact without a committed record can only come from a
  non-atomic implementation and fails closed (the record is parked
  `ambiguous`, never adopted or silently deleted) — so a restart yields
  either the previous complete checkpoint or the new complete one.
- **Quiescing fence**: while a pending replacement sits inside the
  quiescing window (`quiescing` or `checkpointed`, outcome `pending`), new
  replacement requests for the lane are refused (`refusal.replacement.fenced`)
  — a lane cannot fork into a second successor slot mid-handoff — and the
  capture itself is only admitted at the exact `quiescing` boundary.
- **Two observations + closed contract**: the capture requires two
  observations of the lane that are canonically identical (a disagreement
  refuses with `refusal.checkpoint.changed`); every required field must be
  present, bounded and valid (`refusal.checkpoint.incomplete` — missing
  evidence is never silently omitted); active external harness execution
  requires a supported quiescence acknowledgment AND a process/child
  observation (`refusal.checkpoint.ack`); active or ambiguous
  side-effecting child commands hold completion (`refusal.checkpoint.held`
  — nothing is signalled, killed, or cleaned up to obtain a snapshot); and
  required data whose generated brief exceeds the enforced 3 KiB bound is
  a typed hold (`refusal.checkpoint.oversize`), never a truncation.
- **Orchestrator checkpoints** reference existing worker/reviewer
  replacement records (existence and role are validated;
  `refusal.checkpoint.references` otherwise) plus bounded pending
  completion-event tokens, and never alter the referenced lanes.
- **Restart reconciliation**: an interrupted `lane.checkpoint.create`
  claim reconciles against its commit marker (the checkpoint row) instead
  of blindly parking the record — the record's transition commits
  atomically with the row, so the record is never in doubt.

## Retirement additions (issue #75)

- **The binding (the plan/grant unit of this slice)**: a retirement
  request carries `binding` = {lane generation, source session identity,
  source process identity, committed checkpoint digest}. `begin_lane_retirement`
  validates it against the durable record and the checkpoint that completes
  it in one read BEFORE any effect: a changed generation, session, process
  or checkpoint digest refuses with `refusal.retirement.binding` (and
  nothing is signalled), a `held` record refuses as the paused state
  (`refusal.replacement.held`), a cancelled/ambiguous record refuses
  (`refusal.replacement.invalidated` / `refusal.replacement.ambiguous`),
  and a record that has not reached the `checkpointed` boundary refuses
  with `refusal.replacement.order`. The request is journaled as a claim
  like every other daemon mutation, so the exact binding (including the
  checkpoint digest) is durable in the claim's request line and the audit
  journal.
- **Immediate pre-stop quiescence recheck**: the same request carries
  `recheck` = {observed_at, session, process, children[] (command + state
  from the closed `exited`/`active`/`ambiguous` set), active}. Every child
  must be observed `exited` and external execution must not be active
  (`refusal.retirement.held` otherwise), a process identity that is missing
  or not a process identity is an unknown identity and holds, and an
  observed identity that differs from the record refuses as a binding
  mismatch. A hold writes nothing: nothing is signalled, killed, or cleaned
  up to obtain quiescence and no process group is ever addressed.
- **Atomic retirement commit**: `commit_lane_retirement` writes the
  record's `checkpointed` → `retired` transition and its transition-history
  row in ONE transaction, fenced on the exact generation/phase/outcome and
  on the committed checkpoint digest (a missed fence is classified typed
  and changes nothing). The bounded evidence summary is recorded as the
  transition reason (never truncated). No new table is added: the phase
  transition is the commit marker.
- **Held, not escalated**: a graceful stop whose delivery cannot be
  confirmed, a confirmation that cannot prove absence, or a retirement
  that cannot commit after the stop parks the record `ambiguous` (external
  reconciliation required) with the no-repeat decision recorded; there is
  no SIGKILL, no broad pattern, no process-group signal and no authority
  escalation anywhere on the path.
- **Restart reconciliation**: an interrupted `lane.retire` claim is
  reconciled against the backend confirmation read-back — exact absence
  (process absent AND registration released for the bound session and
  generation) completes the retirement, and every other outcome parks the
  record `ambiguous`. The stop is issued at most once: reconciliation never
  repeats a signal, and never against a reused identity.

## Successor additions (issue #76)

## Replacement profile plans (issue #77)

- **The bound plan**: `lane_replacement_profiles` (m0008/schema v8, `PRIMARY
  KEY (replacement_id)`) stores one canonical `hf-profile-binding/v1`
  document plus its 64-hex configuration revision, written in the SAME
  transaction as the replacement record — a replacement is either bound
  from birth or unbound, and an unbound record has no row at all (never a
  placeholder plan). The stored document is re-validated on read and its
  revision re-derived.
- **The start fence**: `begin_lane_successor` compares the presented
  `profile` against the stored plan BEFORE any effect — a changed revision
  refuses `refusal.profile.revision` (the relevant configuration or a
  declared credential moved after the preview; a newly reviewed plan is
  required) and a missing, unexpected, or materially different binding
  refuses `refusal.profile.binding`. The daemon additionally refuses a
  start that would run another profile than the plan names.
- **Recorded binding evidence**: the successor verification and adoption
  evidence carry `binding` = {status (`matched` | `fallback` | `unknown`),
  revision, introspection, intended, actual, source, configured_limits} —
  the ACTUAL pair comes from authoritative adapter evidence only and is
  `null` when unproven (never a copy of the intended pair), the configured
  limits are reported as configured limits (never provider proof), and an
  unexpected pair is fenced before any verification commits.

- **The successor boundary**: `begin_lane_successor` validates one start
  request (`replacement_id`, `binding` = {generation, checkpoint_digest,
  nonce}, `successor` = {session, kickoff_receipt}, `harness`, `admission`)
  and commits exactly ONE durable succession row (`lane_successors`,
  m0007/schema v7, `UNIQUE (replacement_id)`) BEFORE any spawn. The
  successor id is deterministic (`su_` + the first 16 hex of sha256 over
  `hf-lane-successor/v1|<replacement_id>`), so a crash-then-retry, a restart
  and a bounded same-nonce retry all address the identical successor. A
  record that has not retired refuses `refusal.replacement.order`; a record
  left ambiguous or cancelled refuses `refusal.replacement.ambiguous` /
  `refusal.replacement.invalidated`; a held record refuses
  `refusal.replacement.held`. A committed boundary owned by another nonce
  refuses `refusal.successor.nonce` (one generation/nonce owns startup and a
  second nonce can never take over a started successor), a mismatched
  bound session refuses `refusal.successor.binding`, and any start after the
  boundary committed refuses `refusal.successor.exists` (the adoption path
  continues it). A missing committed checkpoint or a changed checkpoint
  digest refuses `refusal.successor.binding` and nothing is invoked.
- **Bounded startup, fresh by construction**: the start rechecks the source
  absence first (a live or unreadable source refuses
  `refusal.successor.source_live`; an unresolvable workspace executable
  refuses `refusal.unavailable.harness`), then starts the successor session
  over the workspace (Herdr) adapter row (`session start <session> --json`)
  on the SAME logical lane and the record's worktree, and verifies the
  successor from a fresh read-back — a booted process alone is never a
  usable successor (`refusal.successor.held`), and a session or process
  identity that is already owned refuses `refusal.successor.reused`. A
  refused spawn leaves the committed boundary `delivery` = `none` for a
  bounded same-nonce retry (the attempt counter refuses
  `refusal.successor.attempts` when exhausted; a delivered successor
  re-verifies instead of spawning again). Admission failures are the
  lifecycle codes (`refusal.admission.proof_missing` / `proof_stale` /
  `resource_floor` / `cap_missing` / `cap_global` / `cap_repository` /
  `cap_harness` / `monorepo_overlap`) and hold with no child and no state
  change.
- **Adoption**: `commit_lane_adoption` requires the fresh `observation` and
  `reobservation` of the lane to be canonically identical
  (`refusal.successor.binding` otherwise), compares the fresh observation
  against the DURABLE checkpoint snapshot (head/base/dirty/untracked/report
  scalars plus the sorted gates and children pairs) and refuses with
  `refusal.successor.differs` naming the differing fields — the recorded
  state is never replayed as success and reconciliation is required. The
  record's `starting` → `adopting` … `adopted` transitions commit
  atomically with their history row (the phase transition is the commit
  marker) and the adoption evidence is digest-bound. A successor that is
  not verifiably usable refuses `refusal.successor.held`; a verify failure
  contradicted by a process-only observation parks the record `ambiguous`.
- **Identity and completions**: the successor continues the retired
  session's role and the record's role/worktree, and the orchestrator's
  worker/reviewer references and pending completion events stay the
  record's. `lane.successor.consume` records the consumption at most once
  (`consumed_at`, `consumer`, `consumed_events`) and refuses a second
  consumption (`refusal.successor.event_consumed`), an event that is not a
  recorded pending completion of the replacement or a worker that is not a
  referenced lane (`refusal.successor.event`), and a successor that has not
  adopted (`refusal.replacement.order`).
- **Restart reconciliation**: an interrupted `lane.start` claim is
  reconciled by reading the successor back (the committed boundary is the
  commit marker) — a verifiable successor completes the boundary, every
  other read-back parks the record `ambiguous` and refuses the retry until
  reconciliation resolves it, so a restart never spawns twice and never
  silently writes off the boundary.

## Queue submission additions (issue #85)

- **Tables (m0009/schema v9, purely additive)**: `queue_submissions`
  (the committed approval binding: digest, epoch, role key/revision,
  workflow pin, boundary, canonical bound-input line), 
  `queue_submission_items` (the persisted run membership: one row per
  selected issue with its closed `admitted` | `waiting` | `refused`
  status, stable reason code and bound run), and `queue_ownership`
  (`PRIMARY KEY (repository, issue_number)` — the schema-level guarantee
  that one live run owns one issue; a prior row whose run left the owned
  status set is replaced inside the same transaction).
- **One transaction**: the submission row, every membership item, the
  admitted `instances` rows and the ownership rows commit together or not
  at all. A crash before the commit leaves nothing (no partial
  admission); a crash after the commit leaves exactly the committed rows.
  State-derived facts (live ownership, grant status/epoch/expiry,
  declared scope overlap, concurrency capacity) are re-verified under the
  transaction guard, so concurrent submissions cannot duplicate an owner.
- **Restart reconciliation**: an interrupted `queue.submit` claim is
  reconciled against its commit marker — the submission row is
  recomputed from the claim's `(digest, idempotency key)` pair, the
  derived document is read back and its digest binding re-verified; the
  claim itself resolves `ambiguous` (a retry needs a fresh key) and no
  effect is ever repeated.
- **Readback**: `queue.status` renders the same `hf-queue-submission/v1`
  document from the committed rows, and the original submit response is
  the same projection, so CLI/JSON and daemon readback agree.

## Run control additions (issue #86)

- **Columns and table (m0010/schema v10, purely additive)**: three
  `instances` columns — `pause_requested` (the durable pause REQUEST that
  stops new step dispatch while in-flight work finishes),
  `pause_reason` (the bounded operator reason) and `pause_requested_at`
  — plus `run_retries` (one row per authorized bounded re-dispatch of one
  diagnosed step: `UNIQUE (instance_id, step_id, attempt)` bounds the
  attempts, `consumed_at`/`consumed_key` record the single consumption).
  No existing table or row is touched, so stored grants, instances, lane
  records and queue submissions are never reinterpreted by the upgrade.
- **Two-phase pause**: `request_run_pause` commits ONE transaction. With a
  step-dispatch claim (`method:"apply"`, status `claimed`) still in flight
  for the run the row carries `pause_requested` — the request is durable
  and new dispatch is already refused, while the in-flight work keeps its
  worktree, node and dirty state (nothing is signalled, killed or cleaned
  up) — and `complete_run_pause_boundary` commits `paused` (clearing
  `pause_requested`) only when no step of the run is in flight any more.
  With no step in flight the boundary is already reached: `paused` commits
  in the same transaction as the request. Boot reconciliation completes
  every request whose in-flight work is gone (after a restart nothing is
  executing), so a restart loses neither the intent nor the boundary. An
  unreadable claimed line is unknown in-flight work: no run claims a safe
  boundary while it exists.
- **Exact-target resume**: `resume_run` requires the fresh engine-minted
  digest stored at pause time (`mint_resume_digest` over the instance, the
  pause-time epoch and the claim key; `authorize_resume` compares), refuses
  a terminal run, a run that is not paused, a moved epoch
  (`refusal.state.epoch`) and a superseded owner
  (`refusal.run.superseded`), consumes the digest on success
  (`resume_digest = ''`) and updates `WHERE instance_id = ?1 AND paused = 1`
  — an unrelated run's pause (or any fleet-level hold expressed as paused
  runs) is never cleared by a resume.
- **Bounded retry state**: `run_retries` rows are the single-use
  authorizations. `record_run_retry` refuses a second authorization while
  one is unconsumed (`refusal.run.retry_pending`) and refuses beyond the
  bound (`refusal.run.retry_bound`, three per (run, step)); the deterministic
  retry id derives from `(run, step, attempt)`. `claim_run_retry` is the
  dispatch-side fence: a first dispatch of a step is never fenced, a
  re-dispatch of a step with a recorded terminal non-success attempt
  consumes one unconsumed authorization, and `Missing` refuses the dispatch
  (`refusal.run.retry_required`) before any effect. A SUPERVISED dispatch
  resolves the same fence earlier and in one write
  (`consume_supervised_retry`): an authorization the run already HOLDS is the
  one consumed (recorded with the dispatching claim's own idempotency key, so
  it is spent exactly once and a second attempt still needs its own
  authorization — issue #241), and with none held supervision mints its own
  bounded row in the same write (the automatic retry of issue #179). The
  diagnosis input
  (`run_step_attempts`) and the bound spine (`run_step_spine`) are read
  back from the durable apply claims and the committed submission's
  bound-input line — never from a caller.
- **Release state (issue #146)**: `release_run` commits ONE transaction:
  the run's own `queue_ownership` row is removed without touching a successor's
  ownership, and the run is terminal afterward (`done` stays `done`, otherwise
  `invalidated`) with the pause state cleared and the resume digest consumed
  (so the run holds no global/per-repository/per-harness occupancy). A
  hash-chained `run.release` audit record carries the operator reason, the
  exact run identity, what was freed and the authorization window the run held.
  Terminal runs (`done` or `invalidated`) can release leftover ownership.
  The daemon replays the recorded response for the same idempotency key;
  a fresh key records an audited ownership-absent no-op if already freed.
  No table, column or schema version changes: the release is a state
  TRANSITION over the existing rows. It refuses `refusal.run.in_flight` (a
  claimed `apply` of the run is still in flight, or an unreadable claim's
  attribution is unknown), `refusal.run.retry_pending` (an unconsumed
  `run_retries` authorization exists — a release never burns one) and
  `state.not_found`; a missing, revoked or expired grant is deliberately NOT
  a fence, and the release records that window without presenting or reusing
  it. Terminal runs remain non-dispatchable: the engine refuses
  `refusal.instance.state`, pause/resume/retry/dispatch refuse
  `refusal.run.terminal`, and supervision's dispatch intent returns nothing.
  Separately, the completing `advance_queue_in_tx` frees only the delivering
  run's ownership in the same transaction that marks it `done`, so a fresh
  submission for that issue can be admitted on its own merits.
- **Restart reconciliation**: an interrupted `run.*` claim is read back
  against its commit marker (the run's control rows) and logged
  (`reconcile.run-control`); no control is ever repeated and nothing is
  ever signalled.

## Supervision additions (issue #95)

- **Tables (m0011/schema v11, purely additive)**: `supervisions` (one row
  per explicitly authorized run: desired state, the owner/run generation,
  the approved-plan binding, the bounded policy, the observed
  meaningful-progress marker with its observation time and source, the
  check counters/continuation report counters, and the last/next check with
  their reasons), `supervision_triggers` (`instance_id` PRIMARY KEY — the ONE
  pending wake slot per run that every semantic wake folds into, which is
  what makes duplicate, out-of-order and concurrent timer/event wakes
  coalesce into one reconciliation) and `supervision_runtime` (the single
  driver-cursor row: the folded event cursor and the last tick time). No
  existing table or row is touched.
- **Disabled by default**: a run is supervised only when an explicit
  `hf-supervision-authorization/v1` block was presented inside
  `queue.submit` params AND the submission transaction committed it — the
  authorization, the admitted `instances` rows and the ownership rows commit
  in ONE transaction, and the authorization binds the approved preview
  digest, so an unapproved/drifted plan is held (`supervision.unapproved_plan`)
  and is never eligible. A re-authorization increments the owner generation
  and re-derives the supervision id.
- **Evaluation-only**: the driver classifies recorded evidence (run row,
  ownership, committed submission and bound spine, recorded step attempts
  with their typed outcome codes, review evidence, bounded retries,
  in-flight claims) into the closed class set, and writes ONLY its own
  `supervisions` check fields plus the consumed wake slot. It never spawns,
  prompts, resumes, retries, mutates Git or clears a hold; the
  meaningful-progress marker moves only when the observed evidence changed,
  so reads, heartbeats and rendered status can never reset it.
- **Restart and clock movement**: the boot pass reconciles every ARMED run
  exactly once (a fresh snapshot), the next eligible check is re-anchored to
  `now + interval` (missed windows are skipped, never replayed), and a
  persisted event cursor that retention moved past (or a folded event whose
  audit row was pruned) reports a loss and falls back to a fresh snapshot
  wake for every armed run.

## Supervision retirement additions (issue #311)

- **Columns (m0013/schema v13, purely additive)**: `supervisions.retired_state`
  records the TERMINAL run state that retired the supervision (`done` |
  `invalidated`; `''` when it was never retired) and `supervisions.retired_at`
  the instant it was retired (`''` until then). No existing table or row is
  touched.
- **Retirement rides the transition the engine already records**: the
  transaction that records a run's terminal transition — `run release`, the
  delivery that completes the run's own committed spine (issue #152), and the
  grant/epoch invalidation that invalidates bound runs — flips that run's
  supervision to `disabled` and records the terminal state and instant in the
  SAME transaction. No operator action and no later pass is involved, and a
  row a pre-fix fleet still carries (a terminal run whose supervision is
  `armed`) is retired by the ONE check that observes it — the boot pass
  reconciles every armed run exactly once — after which it is never scheduled
  again. `supervisions.desired` therefore stays the closed set
  `armed` | `disabled`; retiring is a recorded decision NOT to supervise.
- **What a reader tells apart**: a retired-and-finished run carries a row
  whose `retired_state`/`retired_at` name the cause and the instant
  (`supervision.status` renders both inside its `supervision` block, and the
  human rendering names the retirement); an operator-disabled row carries `''`
  in both; a run that was never supervised carries no row at all (the #261
  unarmed read).
- **Live states are untouched**: a `running` run (including a parked
  `needs-attention` one), a `blocked` or `human_queue` run keeps being
  classified exactly as before, and a `paused` run keeps its row and remains
  ineligible — the retirement only ever removes rows whose run the engine's
  own record has made terminal.

## Queue-advance additions (issue #96)

- **Tables (m0012/schema v12, purely additive)**: `queue_advances` (one row
  per consumed verified delivery of one membership item: the delivered
  ordinal/work-item/head and the evidence id, the considered next item, the
  dispatched run when one was admitted, or the recorded hold reason and
  message; `PRIMARY KEY (submission_id, delivered_ordinal)` is the durable
  idempotency key) plus the persisted admission inputs the advance
  re-applies (`queue_submission_items.grant_id` — the exact presented grant
  binding — and `queue_submissions.caps_global`/`caps_per_repository`/
  `caps_per_harness`/`harness_lanes`). No existing table or row is touched.
- **Completion-to-next-work**: a fresh verified delivery (reviewed `pass`
  with every named check `passed` at one exact head bound to the run's own
  workflow/policy pins, no durable hold, no in-flight step, live epoch)
  advances that submission's cursor exactly once; the candidate is the first
  `waiting` item in membership order and is
  admitted through the SAME guard-verifying helper, caps and occupancy
  attestation the submission used, armed with the delivering run's
  supervision authorization so the queue keeps continuing. That same
  transaction completes the DELIVERING run (`done`) only once the delivery is
  its LAST committed spine step (issue #152): a run whose committed spine
  still carries steps after the delivery stays live and keeps its counted
  slot until those steps are recorded as achieved, so its own authorized
  merge and cleanup stay dispatchable — and the supervision driver drives
  that committed tail itself, under its own typed conditions — and a `done`
  is never recorded over an unexecuted plan; a spine that ends at its
  reviewed-evidence step completes exactly as before.
- **Dependency holds**: every declared requirement of the candidate must be
  delivered and verified — a requirement that is selected but not delivered
  is `queue.dependency_unsettled`, one outside the selected set is
  `queue.dependency_unresolved`; either way the dependent stays `waiting`
  with the reason recorded and is never dispatched or marked done. A
  recorded hold is re-evaluated on later reconciliations and settled in
  place once a dispatch supersedes it.
- **Refusals do not advance**: a paused/invalidated/blocked/human-queued run
  is never a delivery (no cursor row is written), a failed verdict hides any
  older pass, a non-current evidence row refuses the planned advance, and an
  unapproved plan is never a delivery.
## Fixture map

Accept: `migration.valid.json` (0→1, checksummed), `audit.valid.jsonl`
(mutate journaled before + read record). Refuse: non-linear migration,
mutation journaled after the fact, unknown-version variants of both.
