# Spec: daemon request/response and local JSONL event protocols

Refs #3. Families: `hf-rpc-request/v1`, `hf-rpc-response/v1`, `hf-event/v1`.
Fixtures under [`rpc/`](../../schemas/fixtures/rpc/request.status.valid.json),
[`event/`](../../schemas/fixtures/event/events.valid.jsonl). Design commitment (locked spec:
one daemon per host on a per-user Unix socket; read-only CLI operations
remain usable without it; SQLite owns state; no network control API).

## Transport

- Per-user Unix socket only (no TCP listener, no network control API in
  1.0). Default path derives from the XDG runtime dir; explicit override
  via `daemon.socket`.
- Newline-delimited JSON-RPC-style exchanges: one `hf-rpc-request/v1`
  document per request line, one `hf-rpc-response/v1` document per response
  line. Request `id` is echoed in the response (8-64 lowercase hex,
  client-generated) and is the replay handle.

## Requests: `hf-rpc-request/v1`

```json
{"schema":"hf-rpc-request/v1","id":"0123456789abcdef0123","method":"status","params":null}
```

- `method` is a closed set: `capabilities`, `doctor`, `status`, `plan`,
  `apply`, `grants.issue`, `grants.list`, `grants.revoke`, `schedules.list`,
  `schedules.create`, `schedules.pause`, `schedules.resume`,
  `schedules.delete`, `schedules.evaluate`, `lane.replacement.request`,
  `lane.replacement.advance`, `lane.replacement.hold`,
  `lane.replacement.cancel`, `lane.replacement.status`,
  `lane.checkpoint.create`, `lane.checkpoint.status`, `lane.retire`,
  `lane.start`, `lane.adopt`, `lane.successor.consume`,
  `state.epoch`, `queue.submit`, `queue.status`, `run.pause`,
  `run.resume`, `run.retry`, `run.status`, `supervision.status`,
  `backup.create`, `restore.begin`, `journal.tail`,
  `events.subscribe` (issue #77 adds no method: the target-profile plan
  travels as an optional `params.profile` on `lane.replacement.request` and
  `lane.start`, and returns on `lane.replacement.status` /
  `lane.start` / `lane.adopt`)
  (issues #5/#9/#73/#74/#75 add the event stream, the lifecycle methods, the
  request-only lane replacement surface, the safe-boundary checkpoint
  surface, and the guarded single-session retirement over the socket;
  issues #85/#86 add the queue submission surface and the run-scoped
  controls, and issue #95 adds the supervision status read; issue #92 adds
  `grants.issue`, the mint half of the route-grant contract the closed set
  was missing; the closed set
  above is mirrored by the Rust schema validator and the fixture oracle).
- `grants.issue` **requires** `params.grant` (one `hf-grant/v1` object) and
  `params.idempotency_key`: it is the SUPPORTED production mint path for a
  route grant (a caller could otherwise never obtain the `gr_` id that
  `apply` / `queue.submit` / the board present). The document is validated
  before anything is journaled, an already-expired window refuses
  `refusal.grant.expired` and a production-class binding (phase
  `production`, or a `production`/`release` capability) refuses
  `refusal.policy.production_confirmation` — production authority stays
  human-only and this surface carries no confirmation channel. The intent
  (`mutate.grant.issue`) is journaled before the row is inserted, so the
  mint is exactly-once per idempotency key, a replay of the same request id
  + key returns the recorded response, and an interrupt between intent and
  outcome leaves no partial grant (restart reconciliation re-reads the row
  and reports `committed before the interrupt` / `never committed`). The
  response document is the minted `hf-grant/v1` document itself (the
  contract shape, `caps` as an array). Minting is not authorization: the
  grant only becomes authority at the board / `queue submit` point.
- `apply` **requires** `params.idempotency_key` (`ik_` format): an apply
  without a key is refused at parse time (`rpc/request.malformed.json`).
  Replaying the same request id + idempotency key returns the recorded
  response instead of re-dispatching (daemon replay table).
- Unknown methods are refused with a typed refusal (never guessed).

## Lifecycle methods (issue #9)

- `schedules.create` accepts one canonical `hf-schedule/v1` document in
  `params.schedule` (see [spec-lifecycle.md](spec-lifecycle.md)) and
  persists it as a schedule row (`m0004` columns: the canonical doc +
  `updated_at`). Like every mutation it requires `params.idempotency_key`
  and journals its intent (`mutate.schedule.create`) before the row write.
- `schedules.pause` / `schedules.resume` durably flip the row's `enabled`
  flag (`mutate.schedule.pause` / `mutate.schedule.resume`). Paused
  schedules survive daemon/service/host restarts; the evaluation path can
  never enable one, and resume additionally clears the evaluation window so
  the next boot/evaluate tick is due again (explicit human re-arm).
- `schedules.delete` removes the row after journaling its intent
  (`mutate.schedule.delete`); deleting an absent schedule is a typed
  `state.not_found`.
- `schedules.evaluate` runs one fresh evaluation tick (see
  spec-lifecycle.md semantics): each due schedule fires at most once and
  atomically persists its next window with its `read.schedule.ran` audit +
  `schedule.ran` event; refused schedules park themselves (`enabled:false`)
  with a journaled reason and need an explicit human re-arm. Evaluations
  are not idempotency-claimed (a crash leaves at most one extra fresh
  evaluation, never a backlog replay).
- Cold boot runs the same evaluation once per due schedule before the
  socket serves (recovery with Herdr absent is covered in
  spec-lifecycle.md).

## Lane replacement methods (issue #73)

Request-only lane replacement records (spec-state.md "Handoff additions"):
one durable record per logical lane generation, persisted through the same
claim/journal machinery as every daemon mutation (each method requires
`params.idempotency_key`). No method on this surface spawns, kills, or
touches Git, and none requires, issues, or consumes a grant — an agent may
*request* its own retirement but can never authorize its own replacement
effects.

- `lane.replacement.request` creates the record at phase `requested` from
  `params` `lane_id`, `generation`, `source_session`, `source_process`,
  `role` (doctrine roles), `worktree` (repository-relative) and `reason`.
  Missing or invalid identities are refused typed (`refusal.malformed`) and
  nothing is inferred; a second record for the same lane generation is
  refused (`refusal.replacement.exists`) — concurrent requests can never
  create two successor owners, and the same request (same id + idempotency
  key) replays its recorded response.
- `lane.replacement.advance` performs the transactional compare-and-set to
  the phase that follows `params.expected_phase` (with `replacement_id` and
  `generation`). A stale generation (`refusal.replacement.stale`), an
  invalid order or replayed expectation (`refusal.replacement.order`), and
  a held/ambiguous/cancelled record (`refusal.replacement.held` /
  `.ambiguous` / `.invalidated`) cannot advance state.
- `lane.replacement.hold` parks a pending record in the explicit `held`
  outcome (required `reason`); advancement is refused while held, and the
  held state is durable across daemon restarts.
- `lane.replacement.cancel` invalidates a pending replacement before
  retirement; the original lane generation is preserved untouched and the
  invalidated record can never advance. From `retired` onward cancellation
  is refused (`refusal.replacement.retired`).
- `lane.replacement.status` reads one record with its exact transition
  history and the precise `next_allowed` transition (null when the record
  cannot advance). Read-only — no claim and no journal write.
- Restart reconciliation marks a record whose transition was interrupted
  `ambiguous` (the claim machinery and the record agree); external
  reconciliation is required before it can advance.

## Lane checkpoint methods (issue #74)

The safe-boundary checkpoint operation (spec-state.md "Checkpoint
additions"): ONE atomic capture of a lane's verified-quiescent state,
committed at the replacement's `quiescing` boundary. Both methods journal
through the same claim machinery as every daemon mutation
(`lane.checkpoint.create` requires `params.idempotency_key`); no method on
this surface spawns, kills, signals, or touches Git, and none requires,
issues, or consumes a grant.

- `lane.checkpoint.create` captures one checkpoint for
  `params.replacement_id` at `params.generation` and commits the
  checkpoint record together with the record's `quiescing` →
  `checkpointed` transition in one transaction. It requires TWO
  observations of the lane (`params.observation` and
  `params.reobservation`): the two must be canonically identical, or the
  checkpoint refuses (`refusal.checkpoint.changed`). The observation is a
  closed document — role, task, worktree (bound to the record), branch,
  head, base, dirty/untracked inventory with their 64-hex integrity
  digests, report round + reviewed sha, bounded pending gates, bounded
  observed child commands, and the execution/acknowledgment block. Missing
  or invalid required evidence refuses (`refusal.checkpoint.incomplete` —
  never silently omitted); active external harness execution requires a
  supported quiescence acknowledgment AND a process/child observation
  (`refusal.checkpoint.ack` — daemon fencing alone is not claimed to stop
  arbitrary shell actions); observed side-effecting children that are
  active or ambiguous HOLD completion (`refusal.checkpoint.held` — nothing
  is signalled, killed, or cleaned up to obtain a snapshot); orchestrator
  records require `params.observation.orchestration` referencing EXISTING
  worker/reviewer replacement records and bounded pending completion
  events (`refusal.checkpoint.references`), which the capture never
  alters; and required data whose generated brief would exceed the
  enforced 3 KiB bound is a typed hold (`refusal.checkpoint.oversize`).
  The response carries the committed checkpoint (snapshot + digests), the
  generated brief text, its artifact path, and the updated replacement
  record. Replays (same id + key) return the recorded response; a second
  capture for the same replacement refuses (`refusal.checkpoint.exists`).
- `lane.checkpoint.status` reads the durable checkpoint for
  `params.replacement_id` (snapshot, digests, and the derived brief
  artifact pointer). Read-only — no claim and no journal write; a
  replacement without a committed checkpoint is a typed `state.not_found`.
- Restart reconciliation treats the committed checkpoint row as the commit
  marker: the derived brief artifact is (re)generated from the durable row
  and verified against `brief_digest` (so a restart yields the previous
  complete checkpoint or the new complete one), and an artifact without a
  committed record fails closed (the replacement is parked `ambiguous` —
  never adopted or silently deleted).

## Lane retirement method (issue #75)

The guarded retirement of ONE checkpointed source session (spec-state.md
"Retirement additions"): the effect consumes the durable handoff the
checkpoint surface left behind and retires exactly the session the record
binds. `lane.retire` journals through the same claim machinery as every
daemon mutation (it requires `params.idempotency_key`); no method on this
surface spawns a successor, cleans up a process tree, restarts a fleet,
touches Git, or requires/issues/consumes a grant.

- `lane.retire` requires `params.replacement_id`, `params.binding`
  ({generation, session, process, checkpoint_digest}), `params.recheck`
  (the immediate pre-stop quiescence recheck:
  {observed_at, session, process, children[{command, state}], active}) and
  `params.harness` (the adapter profile binding: `key` + `kind`, plus
  `executable` and `capabilities` for the declarative `argv` kind). The
  binding and the recheck are validated against the durable record and its
  committed checkpoint BEFORE any effect: a changed generation, session,
  process or checkpoint digest refuses (`refusal.retirement.binding`), the
  paused (`held`) state refuses (`refusal.replacement.held`), and
  unknown/active child activity or an unknown process identity holds
  (`refusal.retirement.held`). A refusal before the effect signals nothing
  and changes nothing.
- The retirement's only wired adapter path is the workspace (Herdr) session
  rows. A profile that does not declare both the `interrupt` and `observe`
  capabilities is an unsupported adapter and refuses with
  `unknown.capability` BEFORE the claim; an unknown kind refuses with
  `unknown.harness`.
- The graceful stop is ONE bounded request (`session interrupt <session>
  --json`, the adapter deadline). It is never retried and never escalated:
  there is no SIGKILL, no broad pattern, no process-group signal and no
  authority uplift on this path. A stop whose delivery cannot be confirmed
  answers `refusal.retirement.held` and parks the record `ambiguous`; a
  stop that never ran (the workspace executable is unavailable) refuses
  with `refusal.unavailable.harness` and leaves the record untouched.
- The retirement is confirmed by backend evidence ONLY: the confirmation
  read-back (`session show <session> --json`) must show the backend process
  absent AND the ownership/registration released for the bound session and
  generation. A pane text or a `done`/`retired` label is never read, so a
  label alone can never confirm a retirement; a different process under the
  bound session, a read-back naming another session, or a stale
  registration fails closed (`refusal.retirement.reused`) and parks the
  record `ambiguous`; missing, unknown or unparsable evidence holds
  (`refusal.retirement.held`). Child lanes are never addressed: only the
  record's own bound session identity is.
- On success the response carries `retirement` = the updated replacement
  record (phase `retired`), the committed checkpoint id + digest, the bound
  session/process, the bounded stop evidence (status, elapsed) and the
  confirmation evidence (process absent, registration released,
  generation). Replays (same id + key) return the recorded response and
  never repeat the stop.
- Restart reconciliation for an interrupted `lane.retire` claim reconciles
  EXACT ABSENCE through the confirmation read-back: verified absence
  completes the `checkpointed` → `retired` transition with a reconciled
  evidence summary, and every other outcome (still present, reused
  identity, unreadable backend) parks the record `ambiguous`. The stop is
  issued at most once — reconciliation never repeats a signal, and never
  against a reused identity.

## Queue submission methods (issue #85)

`queue.submit` commits ONE approved selected-issue run; `queue.status`
reads one committed submission back read-only. Both require
`params.idempotency_key` (`ik_` format) on the mutating path only;
`queue.submit` journals a claim before any effect and records the typed
outcome after the effect transaction commits.

- `queue.submit` requires `params`: `idempotency_key`, `digest` (the
  approved 64-hex preview digest), `epoch` (the presented state epoch the
  approval was rendered against), `preview` (the exact bound-input
  document the #84 preview rendered), `binding` (the reviewed
  `hf-profile-binding/v1` document), `role_revision` (the 64-hex revision
  of the CURRENT profile configuration, re-observed by the caller),
  `caps` `{global, repository, harness}` and `observations`
  `{host_available, harness_lanes}` (both may be null = unknown, which is
  never readiness); optional `grants` (`[{id, grant_id}]`, the per-issue
  route-grant bindings) and `resume` (`[{instance_id, digest}]`, the
  explicit engine-minted authorizations for paused runs).
- Refusals happen BEFORE the claim (nothing is journaled, no effect
  exists): malformed params, a digest that does not match the freshly
  re-rendered preview (`refusal.plan.stale`), a stale epoch
  (`refusal.state.epoch`), a configuration/credential change
  (`refusal.profile.revision`), an unsupported/unresolved/empty step
  spine or a step outside the reviewed boundary (`preview.step_*`,
  `submission.steps`, `submission.boundary`), and a production/protected
  completion boundary (`refusal.policy.production_confirmation`,
  `preview.protected_branch`).
- The committed document (`hf-queue-submission/v1`, module-local like the
  preview) carries the submission id (`qs_` + 16 hex of sha256 over
  `hf-queue-submission/v1|<digest>|<idempotency_key>`), the bound
  state/role/workflow/boundary block, per-issue items with their closed
  status (`admitted` | `waiting` | `refused`), stable reason code,
  bounded message and the bound run id, the executable spine, and an
  explicit statement that no workflow step has been executed.
- One transaction decides and writes: live ownership (a duplicate owner
  is refused `submission.already_owned`), grant status/epoch/expiry
  (`refusal.grant.*`, `refusal.state.epoch`), scope overlap
  (`refusal.admission.monorepo_overlap`) and capacity
  (`refusal.admission.cap_*`); waiting items consume no capacity slot. A
  paused run refuses `submission.paused` unless the presented engine
  digest authorizes exactly that run's resume (applied once, in the same
  transaction, against the same run).
- `queue.status` requires `params.submission_id` (`qs_` + 16 hex) and
  returns the same document the submit response carried (a pure
  projection of the committed rows; `state.not_found` for an unknown id).
- Restart reconciliation reads the committed submission row (the commit
  marker) back: a present row means exactly the committed effects exist
  and its digest binding is re-verified; a missing row means the
  all-or-nothing transaction never committed. The interrupted claim is
  resolved `ambiguous` like every other interrupted mutation, so a retry
  needs a fresh key and no effect is ever repeated.

## Run-scoped control methods (issue #86)

Safe-boundary pause, resume and bounded retry over exactly ONE run — the
`run-` instance row the queue executor commits for every admitted issue
(spec-state.md "Run control additions"). All four methods address one
exact run identity, journal through the same claim machinery as every
daemon mutation (`params.idempotency_key` required on the mutating paths;
a same-key retry replays the recorded response) and render a module-local
document (`hf-run-control/v1` / `hf-run-retry/v1`, deliberately outside
the closed `hf-*` family set like the #84 preview and the #85 submission).

**Scope matrix (run vs fleet vs lane), normative:**

| level | identity | methods | effect of a control |
| --- | --- | --- | --- |
| run | one `run-` + 16 hex instance id | `run.pause` / `run.resume` / `run.retry` / `run.status` | exactly this run: stop admitting new steps, lift THIS run's pause, authorize one bounded re-dispatch of one diagnosed step |
| fleet | the whole run population | NONE — there is no `fleet.*` method in the closed set | a fleet-level hold is an operator policy expressed as the set of paused runs; every resume is fenced on the exact instance id, so no run control ever lifts another run's pause or anything fleet-wide |
| lane | one handoff lane generation (`rp_` records) | `lane.*` only | run controls never touch lane records; a non-run identity refuses `refusal.run.target` |

No method on this surface kills a process, cleans up work, mutates Git,
clears a repository/fleet-level hold or bypasses a gate.

- `run.pause` requires `params.instance_id` (`run-` + 16 hex),
  `params.reason` (1-300 printable characters) and `params.idempotency_key`.
  It records ONE durable pause REQUEST: new step dispatch for the run is
  refused from that moment on (`refusal.run.paused` before any effect)
  while in-flight work keeps running untouched. When a step dispatch of the
  run is still in flight the row carries `pause_requested` (the rendered
  control state is `pause_requested`) and the pause commits `paused` at the
  run's next recorded step boundary (the apply path completes the boundary;
  a restart completes any request whose in-flight work is gone); when no
  step is in flight the safe boundary is already reached and `paused`
  commits immediately. The response carries the run control document with
  the engine-minted resume digest (`mint_resume_digest` over the exact run,
  the pause-time epoch and the claim key) and the live boundary
  (`boundary.reached`, `boundary.in_flight_step`). A second pause for the
  same run is refused `refusal.run.control` (a duplicate never creates a
  second intent); a terminal run refuses `refusal.run.terminal`; an unknown
  run is `state.not_found`.
- `run.resume` requires `params.instance_id` and `params.digest` (the
  64-hex digest `run.pause` returned). It refuses before any effect when
  the run is unknown (`state.not_found`), terminal
  (`refusal.run.terminal`), not paused (`refusal.run.control`), when the
  digest does not equal the stored one (`state.stale_resume` — the digest
  binds the exact run/epoch, so a stale or foreign digest can never resume
  anything), when the run's epoch moved (`refusal.state.epoch`) or when the
  run no longer owns its issue (`refusal.run.superseded`). The update is
  fenced on the exact instance id (`WHERE instance_id = ? AND paused = 1`)
  and consumes the digest on success: an unrelated run's pause — or any
  fleet-level hold expressed as paused runs — is NEVER cleared.
- `run.retry` requires `params.instance_id` and `params.step` (a plan step
  id). It refuses: a terminal run (`refusal.run.terminal`), a paused or
  pause-requested run (`refusal.run.paused` — resume first), a run without
  a committed submission spine (`refusal.run.scope`), a step outside the
  bound spine (`refusal.run.step_unknown`), a step that is not the run's
  current unachieved frontier step (`refusal.run.step_order`), a step that
  already succeeded or whose last recorded attempt succeeded
  (`refusal.run.step_done`), a step with no recorded terminal failed
  attempt (`refusal.run.step_undiagnosed` — a retry is for a DIAGNOSED
  failure), a moved epoch (`refusal.state.epoch`), an inactive or absent
  grant (`refusal.grant.inactive`), an unconsumed authorization that
  already exists (`refusal.run.retry_pending`) and an exhausted attempt
  bound (`refusal.run.retry_bound`, three bounded retries per step). On
  success it records ONE single-use authorization (`run_retries`); the next
  dispatch of that exact step consumes it (a re-dispatch of a diagnosed
  failed step without an unconsumed authorization refuses
  `refusal.run.retry_required` before any effect). Nothing is spawned by
  the retry itself.
- `run.status` requires `params.instance_id` and renders the control state
  read-only: `active` / `pause_requested` / `paused`, the durable request
  fields, the live boundary and the scope block. No claim and no journal
  write.
- Restart reconciliation reads each interrupted `run.*` claim's commit
  marker (the run's control rows) and logs whether the control committed
  (`reconcile.run-control`); no control is ever repeated.

## Supervision method (issue #95) + queue continuation (issue #96)

- Supervision is a daemon-owned reconciliation driver, NOT another agent
  and NOT a scheduler: routine checks make no inference requests, and
  nothing on this surface spawns, prompts, resumes, retries, mutates Git or
  clears a hold. `supervision.status` is the only method it adds, and issue
  #96 adds no method at all: the continuation rides on the SAME driver.
- Arming is part of the run's submission, never a separate call:
  `queue.submit` accepts an OPTIONAL `params.supervision`
  (`hf-supervision-authorization/v1`: `desired` in the closed set
  `armed` | `disabled`, plus an optional bounded `policy` with
  `check_interval_secs` 5..=3600 and `progress_timeout_secs` 60..=86400,
  which must not be smaller than the interval). Absent = supervision stays
  disabled for every admitted run (the default). A present block commits in
  the SAME transaction as the runs it names, binds the approved preview
  digest, and is validated before any state is read
  (`usage.supervision.*`).
- The driver is woken by SEMANTIC events (the durable journal stream:
  completion/review/CI/control wakes folded per run) plus a bounded timer
  fallback; duplicate, out-of-order and concurrent timer/event wakes
  coalesce into ONE run-scoped reconciliation, and a restart yields exactly
  one fresh snapshot reconciliation per armed run (missed windows are
  skipped, never replayed). A persisted event cursor that retention moved
  past falls back to a fresh snapshot wake.
- `supervision.status` requires `params.instance_id` (`run-` + 16 hex) and
  renders `hf-supervision/v1` read-only: the recorded authorization and
  policy, the closed classification (`healthy`, `waiting-workers`,
  `waiting-CI`, `waiting-approval`, `blocked-capacity`,
  `continuation-eligible`, `paused`, `completed`, `needs-attention`, or
  `unknown` when evidence is missing/stale) with its stable reason and the
  eligibility REPORT, the freshness of the last check, the last check
  (time, class, reason, wake), the NEXT ELIGIBLE CHECK with its reason, the
  observed meaningful-progress marker (time, age, source), the continuation
  report count and the folded pending wake. No claim, no journal write and
  no marker movement: a read, a heartbeat or a rendered status is never
  progress. `state.not_found` when the run carries no authorization. The
  reported `class`/`reason`/`eligible` are the RECORDED result of the last
  committed check (and, before the first check, the read's own observation);
  the read-time re-classification of the same evidence is carried separately
  as `observed`, and the `continuation` block is durable window state only
  (`state`/`since`/`reports`) — a read can therefore never launder a
  committed effect, and the surface never presents an observation as if it
  were the record.
- A run with NO recorded progress observation yet (a fresh arm: `progress_at`
  empty, or an unreadable instant) is **held** — class `unknown`, reason
  `supervision.progress_unobserved`, `eligible:false` — never eligible: an
  unobserved run is not a timed-out one, so a fresh arm cannot open a
  continuation window. Only a recorded observation that is genuinely older
  than the explicit `progress_timeout_secs` policy is `continuation-eligible`
  with reason `supervision.progress_timeout`.
- `continuation-eligible` is a REPORT: supervision never continues work on
  a stalled run, and an idle/done agent alone is neither completion (a
  `done` run without passing review evidence stays unknown) nor permission
  to resume (a paused run is never eligible).
- **Completion-to-next-work (issue #96)**: a fresh VERIFIED delivery of an
  armed run — reviewed `pass` with every named check `passed` at one exact
  head, bound to the run's own workflow/policy pins, no durable hold and no
  in-flight step claim — completes that run (`done`) and advances its
  already-authorized queue cursor EXACTLY ONCE, admitting the next eligible
  approved item of the SAME committed submission through the same
  guard-verifying admission path (the same approved caps and occupancy
  attestation), armed with the delivering run's supervision authorization.
  The consumption is keyed to the delivered membership item
  (`queue_advances`, m0012) and is durable across restarts: a duplicate
  delivery event, a replayed reconciliation or a crash can only observe the
  recorded row and never dispatch twice. A declared dependency that is not
  delivered and verified holds the dependent with its reason recorded
  (`queue.dependency_unsettled` / `queue.dependency_unresolved`), never
  dispatches it and never marks it done; a hold is re-evaluated as later
  deliveries settle it and the superseding dispatch is recorded on the older
  delivery row. Nothing else is eligible: only items of that submission, no
  new issue creation, no speculative chain, and no LLM in the loop.

## Responses: `hf-rpc-response/v1`

```json
{"schema":"hf-rpc-response/v1","id":"0123456789abcdef0123","ok":true,
 "result":{"repository":"example-org/widgets","freshness":"fresh"},"error":null}
```

- `ok:true` ⇒ `result` object, `error:null`; `ok:false` ⇒ `result:null` and
  `error` shaped like `hf-error/v1`. Mixed responses are refused
  (`rpc/response.malformed.json`).
- Errors carry stable codes; refusal codes (`refusal.*`) are typed and
  never downgraded by clients.

## Local JSONL event protocol: `hf-event/v1` (one event per line)

The daemon appends events to a local JSONL stream for read-only consumers
(the future optional Corral-style adapter boundary, ADR-0003 — dashed and
optional; nothing requires it):

```json
{"schema":"hf-event/v1","event":"state.snapshot","seq":0,"ts":"2026-09-06T00:00:00Z",
 "data":{"repository":"example-org/widgets","epoch":3}}
```

- `event` closed set: `state.snapshot` | `agent.updated` | `plan.updated` |
  `grant.updated` | `journal.appended` | `epoch.rotated` | `schedule.ran`.
- `seq` is a monotonic per-daemon sequence (replay cursor); consumers
  resume from `Last-Seq`, and a stale cursor is answered with a fresh
  snapshot (reconnect semantics are the consumer's concern; the daemon only
  guarantees append-only, seq-ordered, redacted lines).
- `ts` RFC3339 UTC; `data` is an object; every line is self-describing with
  its schema id. Unknown event kinds are refused
  (`event/events.malformed.jsonl`); a non-JSON line fails the stream
  (`event/events.badline.jsonl` refuses at parse).
- Event content is redacted by construction (shared adapter-boundary
  redaction, [spec-cli.md](spec-cli.md)); no credentials ever ride events.

## `events.subscribe` (issue #5; AC7)

A subscriber connection sends one `events.subscribe` request (params
`{"cursor": <int>}` optional — absent means "fresh snapshot first"). The
daemon answers with the ok response, then pushes `hf-event/v1` lines:

- No cursor ⇒ one `state.snapshot` line first (current state at the latest
  journal seq), then live events.
- `cursor` inside the retained window ⇒ contiguous replay of `seq > cursor`
  (no snapshot), then live events.
- `cursor` at/behind the retained window edge or in the future ⇒ a fresh
  `state.snapshot` line (gap/resnapshot semantics).
- Lines are seq-ordered and strictly increasing; per-subscriber queues are
  bounded, and a subscriber that does not drain is disconnected (bounded
  backpressure; mutations keep succeeding).
- A subscribe connection is push-only after the response: the client never
  sends again on it.

This is the **canter daemon's** event contract, not Herdr's workspace
socket contract. Herdr 0.9.0 changed its own new subscriptions to live-only;
that does not remove this cursor-based replay/resnapshot surface. Issue #9's
schedule lifecycle writes this daemon-owned journal and never consumes
upstream Herdr `events.subscribe`, so it has no retained-history dependency
(guarded by `tests/herdr_compatibility.rs`).

## `lane.start` / `lane.adopt` / `lane.successor.consume` (issue #76)

The start/adopt surface binds one successor of a retired replacement and
journals through the same claim machinery as every other mutation
(`params.idempotency_key` required; a retry with the same key replays the
recorded outcome and never repeats the spawn).

- `lane.start` optionally requires `params.profile` when the record was
  requested under an explicit profile-configuration revision (issue #77):
  the SAME canonical `hf-profile-binding/v1` plan, validated and
  revision-checked. A changed revision refuses `refusal.profile.revision`
  (the configuration or a declared credential moved after the preview — a
  newly reviewed plan is required), a missing or unexpected binding refuses
  `refusal.profile.binding`, and the start must run the profile the plan
  names. The successor read-back is verified against the plan: the intended
  pair verifies, an AUTHORIZED fallback is accepted and reported
  distinctly, an unexpected provider/model is fenced
  (`refusal.successor.reused`, parked for reconciliation), a profile that
  declares binding introspection but returns none holds
  (`refusal.successor.held`, an honest capability hold), and a profile
  without introspection evidence records the actual binding as `unknown` —
  never a copy of the requested configuration. The verification result
  carries `binding` = {status, revision, introspection, intended, actual,
  source, configured_limits}.
- `lane.start` requires `params.replacement_id`, `params.binding`
  (object: `generation`, `checkpoint_digest`, `nonce`), `params.successor`
  (object: `session`, `kickoff_receipt`), `params.harness` and
  `params.admission`. It commits exactly ONE successor boundary before any
  spawn and then starts the successor session over the workspace (Herdr)
  adapter row (`session start <session> --json`) on the SAME logical lane
  and worktree. A record that has not retired refuses as the phase order
  (`refusal.replacement.order`); a missing/changed checkpoint digest, a
  mismatched committed session or a malformed request refuses as the
  binding (`refusal.successor.binding`); a committed boundary refuses a
  second start (`refusal.successor.exists`); a different or empty startup
  nonce refuses (`refusal.successor.nonce`); a held record refuses
  (`refusal.replacement.held`) and a cancelled/ambiguous record refuses
  (`refusal.replacement.invalidated` / `refusal.replacement.ambiguous`);
  the bounded attempt counter refuses with `refusal.successor.attempts`.
  The start rechecks the source absence first (a live or unreadable source
  refuses `refusal.successor.source_live`; an unresolvable workspace
  executable refuses `refusal.unavailable.harness`) and verifies the
  successor from a fresh observation — a booted process alone is never a
  usable successor. Admission failures are the lifecycle codes
  (`refusal.admission.proof_missing` / `proof_stale` / `cap_missing` /
  `cap_global` / `cap_repository` / `cap_harness` / `monorepo_overlap`);
  every refusal before the spawn holds with no child and no state change.
  `params.successor.kickoff_receipt` is the closed kickoff binding: a
  64-hex digest of the kickoff receipt that the adapter read-back must
  echo, or the start refuses.
- `lane.adopt` re-verifies the committed successor against the SAME durable
  plan the start was fenced on (the profile binding is part of the adoption
  evidence, issue #77).
- `lane.adopt` requires `params.replacement_id`, `params.binding`
  (object: `generation`, `successor_id`, `session`), `params.observation`
  and `params.reobservation` (the fresh re-query, canonically identical or
  `refusal.successor.binding`) plus `params.harness`. The fresh observation
  is compared against the DURABLE checkpoint snapshot — a difference
  refuses (`refusal.successor.differs`, naming the fields) and the
  recorded state is never replayed as success. A successor that is not
  verifiably usable refuses (`refusal.successor.held`); a process-only
  observation parks the record `ambiguous`; a record that is not at the
  committed boundary refuses (`refusal.successor.binding`) and a held
  record refuses (`refusal.replacement.held`).
- `lane.successor.consume` requires `params.replacement_id`,
  `params.successor_id` and `params.events` (the pending completion-event
  tokens). It records the consumption at most once (`consumed_at`,
  `consumer`, `consumed_events`) and refuses a second consumption
  (`refusal.successor.event_consumed`), an unknown/not-pending event
  (`refusal.successor.event`) or a successor that has not adopted
  (`refusal.replacement.order`).
- `lane.replacement.request` accepts the optional `params.profile`
  (`hf-profile-binding/v1`); a present document is validated with its
  revision recomputed (`refusal.profile.binding` /
  `refusal.profile.revision`) and committed with the record in ONE
  transaction; `lane.replacement.status` returns the bound `profile` (the
  canonical plan) or null.
- Restart reconciliation: an interrupted `lane.start`/`lane.adopt` claim is
  reconciled against the successor read-back BEFORE any retry — a
  verifiable successor completes the boundary, every other read-back parks
  the record `ambiguous` and refuses the retry until reconciliation
  resolves it. The spawn is issued at most once per committed boundary.

## Read-only independence

`doctor`, `status`, and `plan` never require the daemon to be running
(locked spec). When the daemon is absent, read-only commands operate on
config + direct adapter read-back and report daemon absence as part of the
observation (not as a crash).

## Fixture map

Accept: `request.status.valid.json`, `request.apply.valid.json` (with
idempotency key), `response.ok.valid.json`, `response.error.valid.json`,
`events.valid.jsonl`. Refuse: apply without key, mixed ok/error response,
unknown event kind, non-JSON event line, unknown-version variants of
request/response/event.
