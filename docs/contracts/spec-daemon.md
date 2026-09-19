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
  `run.resume`, `run.retry`, `run.reevaluate`, `run.resolve`, `run.dispatch`,
  `run.status`,
  `supervision.status`,
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
  contract shape, `caps` as an array). The `gr_` id is content-addressed
  over the REVIEWED BINDING (repository, issue number + acceptance revision,
  workflow hash, policy hash, phase, scope, caps, live state epoch) AND the
  issuance idempotency key. A fresh key therefore opens a fresh authorization
  window without extending or replacing an earlier live/expired row; replaying
  one key remains exactly-once and returns its recorded response.
  Minting is not authorization: the
  grant only becomes authority at the board / `queue submit` point.
- `apply` **requires** `params.idempotency_key` (`ik_` format): an apply
  without a key is refused at parse time (`rpc/request.malformed.json`).
  Replaying the same request id + idempotency key returns the recorded
  response instead of re-dispatching (daemon replay table).
- A harness step (`harness_start` / `prompt`) of a run with a committed
  submission runs the run's DECLARED role configuration and only that one
  (issue #92 F2): the full reviewed `hf-profile-binding/v1` document rides
  as the presented `params.profile`, verified against the durable
  `role_key`/`role_revision` the approval bound — a foreign or tampered
  binding refuses `refusal.profile.revision`, an absent one refuses
  `refusal.profile.binding` (there is no default profile), and a step that
  names another `harness_key` than the run's role refuses
  `refusal.profile.binding`. The run's session identity is derived from the
  run itself; a `prompt` whose run recorded no succeeded `harness_start`
  refuses `refusal.session.unbound`.
- A LIVE run whose OWN authorization window lapsed mid-spine renews it
  before any effect gate reads the window (issue #184): ONE audited
  `grant.rotation`-class transaction inserts a successor grant derived from
  the lapsed one (same repository/issue/revision/workflow/policy/phase/
  scope/caps/epoch, new `gr_` id), records an expiry SIZED FROM THE
  REMAINING COMMITTED SPINE (the sum of the remaining steps' own documented
  effect deadlines), re-points the run to it and names the superseded
  grant, the replacement and the recorded expiry. No operator key and no
  bounded retry (`run.retry`) is involved, and the renewal is never a
  blanket authorization: a foreign, revoked, stale-epoch, released, paused,
  held or exhausted run — or a run whose window is still live — refuses
  exactly as before. A recorded refusal of the run's own lapsed window is
  likewise not a STEP diagnosis: it neither demands nor consumes a bounded
  retry. The same shape holds for the fan-out host-resource proof (issue
  #198): the supervisor's own continuation dispatch measures the host when
  the run's recorded proof has lapsed (one audited `host.proof.renewal`
  record; see [spec-lifecycle.md](spec-lifecycle.md) §4.1), and an
  unmeasurable host keeps the typed `refusal.admission.proof_stale`.
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
  explicit engine-minted authorizations for paused runs). An armed
  submission also carries `dispatch:{topology, admission}`, sourced from
  `--topology FILE` and the presented capacity/host observation.
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
  explicit statement that submission itself only admits; its armed driver
  may separately dispatch through the gated apply path.
- One transaction decides and writes: live ownership (a duplicate owner
  is refused `submission.already_owned`), grant status/epoch/expiry
  (`refusal.grant.*`, `refusal.state.epoch`), scope overlap
  (`refusal.admission.monorepo_overlap`) and capacity
  (`refusal.admission.cap_*`); waiting items consume no capacity slot. A
  paused run refuses `submission.paused` unless the presented engine
  digest authorizes exactly that run's resume (applied once, in the same
  transaction, against the same run).
- Acceptance revision hashes are opaque and never sorted lexically. A selected
  revision different from the active owner's revision is `preview.revision_stale`
  unless a route grant for that exact selection was issued AFTER the owner's
  grant. A later, still-valid grant makes that exact selection REBINDABLE, and
  only rebindable: presenting an older grant remains stale, and a live run is
  never invalidated by admission (issue #209, next bullet). A same-revision
  live window remains `submission.already_owned`, and a fresh window never
  rotates a live binding; a later issuance may rotate an EXPIRED window on
  that same run, with `grant.rotation` naming both rows and the new expiry. The
  grant insertion order is the normative authorization-window order.
- **Live incumbent (issue #209):** a `queue submit` for an issue whose run is
  live and not terminal is refused typed — `submission.live_run`, naming the
  live run and its recorded frontier — and the incumbent keeps its unique
  ownership, its authorization window and its frontier. Admission never
  invalidates an incumbent as a side effect: the submit path contains no
  invalidation of a live run at all. The named frontier is the same durable
  fact the driver's own frontier reads (the committed bound-input spine plus
  the recorded apply-attempt ledger, with `current_node` only as the
  pre-ledger fallback): the frontier step with its kind, plus the run's
  recorded supervision class — the class of its newest committed check, and
  `unknown` before the first check. Every refusal that declines an item
  because of a live incumbent names that incumbent the same way
  (`submission.already_owned` on a same-revision duplicate,
  `submission.frontier_preserved` at the reviewed-evidence frontier), and the
  preview reports `preview.live_run` with the same summary instead of
  presenting the rebind as authorized.
- **Reviewed-evidence frontier (issue #192):** the rebind above never
  supersedes a run whose recorded frontier has REACHED its own
  `review_evidence` step — that step is the run's next unachieved step, or is
  already achieved (read from the same committed bound-input spine plus the
  same recorded apply-attempt ledger the driver's own frontier reads, with
  `current_node` only as the pre-ledger fallback). Such a run's verified spine
  (its recorded delivery included) is carried forward: the presented item is
  refused `submission.frontier_preserved`, the run keeps its unique ownership
  and its own authorization window, and it continues its own committed
  merge/cleanup tail. The preview reports the same fact as
  `preview.frontier_preserved` instead of presenting the rebind as
  authorized. Replacing such a run is an explicit, audited act: the
  `run.release` control frees its ownership and the run goes terminal, after
  which a fresh submission admits a new run. A run that has not reached that
  frontier is refused `submission.live_run` under the rule above — never
  superseded.
- `queue.status` requires `params.submission_id` (`qs_` + 16 hex) and
  returns the same document the submit response carried (a pure
  projection of the committed rows; `state.not_found` for an unknown id).
- Restart reconciliation reads the committed submission row (the commit
  marker) back: a present row means exactly the committed effects exist
  and its digest binding is re-verified; a missing row means the
  all-or-nothing transaction never committed. The interrupted claim is
  resolved `ambiguous` like every other interrupted mutation, so a retry
  needs a fresh key and no effect is ever repeated.

## Run-scoped control methods (issue #86 + issue #146)

Safe-boundary pause, resume, bounded retry, bounded check re-evaluation, evidence resolution, one supported step dispatch
and the explicit release of a run that can never progress over exactly ONE run — the
`run-` instance row the queue executor commits for every admitted issue
(spec-state.md "Run control additions"). All eight methods address one
exact run identity, journal through the same claim machinery as every
daemon mutation (`params.idempotency_key` required on the mutating paths;
a same-key retry replays the recorded response) and render a module-local
document (`hf-run-control/v1` / `hf-run-retry/v1` /
`hf-run-reevaluation/v1` /
`hf-run-resolution/v1` / `hf-run-dispatch/v1` / `hf-run-release/v1`,
deliberately outside the closed `hf-*` family set like the #84 preview and
the #85 submission).

**Scope matrix (run vs fleet vs lane), normative:**

| level | identity | methods | effect of a control |
| --- | --- | --- | --- |
| run | one `run-` + 16 hex instance id | `run.pause` / `run.resume` / `run.retry` / `run.reevaluate` / `run.release` / `run.resolve` / `run.dispatch` / `run.status` | exactly this run: stop admitting new steps, lift THIS run's pause, authorize one bounded re-dispatch of one diagnosed step (authorization only), re-evaluate the run's own recorded checks by re-running its check producer at the same certified head (bounded, attributed, journaled; recomputation only), release a run that can never progress — its issue ownership and the occupancy it held are freed and it goes terminal (bookkeeping only), resolve one diagnosed prompt from recorder-attributed evidence without an effect, or dispatch ONE committed-spine step with the caller's own step inputs |
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
- After the first recorded attempt, the RECORDED attempt ledger is the run's
  authoritative frontier (issue #92 F10): it is the first bound-spine step
  whose latest recorded attempt is not `succeeded`. Before any attempt, the
  node-derived frontier preserves the pre-ledger run behavior. A diagnosed
  `ambiguous` or failed attempt therefore cannot be hidden by a stale or
  optimistically advanced node.
- The rendered control document (`run.pause` / `run.resume` / `run.status`)
  carries `last_failure`: the newest recorded NON-succeeded step attempt as
  `{step, status, code, message}` — the durable outcome's own typed code and
  its raw message (redacted like every other recorded text) — or `null` when
  the run has no standing failure (its newest recorded attempt succeeded, or
  the run has no recorded attempt). Issue #219: a failed effect's reason is
  readable read-only, from the same document that reports the frontier, and
  never only from a daemon log — an operator can tell a rejected publish from
  a conflict from a bad credential without one.
- `run.retry` requires `params.instance_id` and `params.step` (a plan step
  id). It refuses: a terminal run (`refusal.run.terminal`), a paused or
  pause-requested run (`refusal.run.paused` — resume first), a run without
  a committed submission spine (`refusal.run.scope`), a step outside the
  bound spine (`refusal.run.step_unknown`), a step that is not the run's
  frontier step (`refusal.run.step_order`), a step that
  already succeeded or whose last recorded attempt succeeded
  (`refusal.run.step_done`), a step with no recorded terminal failed
  attempt (`refusal.run.step_undiagnosed` — a retry is for a DIAGNOSED
  failure), a moved epoch (`refusal.state.epoch`), an inactive or absent
  grant (`refusal.grant.inactive`), an unconsumed authorization that
  already exists (`refusal.run.retry_pending`) and an exhausted attempt
  bound (`refusal.run.retry_bound`, three bounded retries per step). On
  success it records ONE single-use authorization (`run_retries`) and
  NOTHING else: the request dispatches no step and spawns nothing. The
  authorization is consumed by the ONE re-dispatch of that exact step — the
  run's own armed supervision performs it (issue #241: the held authorization
  is spent by the very re-dispatch it authorizes, recorded under that
  dispatch's journaled idempotency key, and a consumed authorization is never
  spent twice), or the operator's own `run.dispatch` consumes it when it
  arrives first, which is also how corrected step inputs are presented (see
  `run.dispatch`). A
  re-dispatch of a diagnosed failed step without an unconsumed
  authorization refuses `refusal.run.retry_required` before any effect.
- `run.reevaluate` (issue #230) requires `params.instance_id`,
  `params.step` (a plan step id), `params.operator` (1-128 printable
  characters, no `:`) and `params.reason` (1-300 printable characters). It
  exists for exactly ONE recorded deadlock: a check recorded non-`passed`
  inside the evidence of a step that already SUCCEEDED, whose consumer
  therefore refuses (`refusal.evidence.failed`) while the producer can never
  be re-run (`refusal.run.step_done`). It refuses: a terminal run
  (`refusal.run.terminal`), a paused or pause-requested run
  (`refusal.run.paused`), a run without a committed submission spine
  (`refusal.run.scope`), a step outside the bound spine
  (`refusal.run.step_unknown`), a step that is not the run's own
  `review_evidence` step or that presents STATIC review facts instead of a
  reviewer leg (`refusal.run.reevaluation_step` — a step with no check
  producer computes nothing, and no check status is ever presented,
  adjudicated or waived), a step whose latest recorded attempt is not a
  terminal success (`refusal.run.reevaluation_step`; a DIAGNOSED step is the
  bounded-retry control's subject), a run whose newest recorded evidence
  carries no non-passing check (`refusal.run.reevaluation_shape` — there is
  nothing to recompute), an exhausted bound
  (`refusal.run.reevaluation_bound`, three re-evaluations per `(run, step)`,
  counted from the durable journal), a moved epoch (`refusal.state.epoch`)
  and an inactive or absent grant (`refusal.grant.inactive`). On success it
  writes ONE hash-chained audit record BEFORE dispatching anything
  (`run.reevaluate`, target
  `run:<id>:step:<step>:evidence:<ev>:operator:<operator>:reason:<reason>`,
  the reason bounded and recorded LAST) and then re-dispatches that step
  through the SAME `run.dispatch` path every other step uses, with the
  DERIVED next reviewer lane round merged over the committed params
  (`lane_round = recorded successful evaluations + 1`, so the re-run binds a
  fresh reviewer identity and a fresh verdict path and can never re-read the
  verdict of the round it supersedes), plus — for a reviewer leg whose plan
  binds a lane checkout of ANOTHER step-visible round (issue #248) — that
  round's OWN lane checkout (`issues-<N>-rev<R>`, merged over the committed
  `worktree`): a leg the fix round advanced holds a binding for the round the
  plan was rendered at, and ONE lane checkout belongs to exactly one leg, so
  the control RE-BINDS the binding it is dispatching instead of presenting a
  binding that can only refuse. Nothing else is ever reinterpreted: a
  genuinely foreign checkout is still refused by the effect
  (`refusal.lane.identity`), and the bare-subprocess fallback keeps its
  binding byte for byte. The control presents no check status,
  no verdict and no head: the producer recomputes, its fresh verdict is
  recorded exactly like the first one, and a recomputation that comes back
  FAILING refuses the consumer with the same `refusal.evidence.failed`. A
  refused re-dispatch still leaves the attributed record (the operator's act
  is durable) and carries the inner typed refusal VERBATIM.
  The re-dispatched step is a fan-out (it starts the run's own reviewer
  lane), so the control PRODUCES the host-resource proof that gate requires
  (issue #243): the dispatch-time renewal of the supervisor's own
  continuation (spec-lifecycle.md §4.1 — measured at the run's lane root,
  audited `host.proof.renewal`, bounded, fail closed) runs on the
  re-evaluation's dispatch, so a lapsed proof no longer refuses the ONE
  control that exists to recompute a stranded check. Nothing is exempted or
  weakened: an unmeasurable host still refuses the recorded proof, a proof
  that was never recorded is never invented, and the admission refusal now
  names the failing precondition AND the exact commands that renew the proof.
- `run.release` (issue #146) requires `params.instance_id`,
  `params.reason` (1-300 printable characters) and
  `params.idempotency_key`. It releases exactly ONE run that can never
  progress, in ONE transaction: only that run's ownership row is removed
  (never a successor's), and the run is terminal afterward (`done` stays `done`,
  otherwise `invalidated`, pause state cleared and the resume digest consumed)
  so it holds no global, per-repository or per-harness occupancy. A
  `run.release` audit record carries the operator reason, the exact run identity
  (repository/issue/revision), what was freed and the authorization window
  the run held. It refuses BEFORE any effect while anything of that run is
  genuinely live: a step-dispatch claim still in flight
  (`refusal.run.in_flight` — nothing is killed, cancelled or cleaned up),
  an unconsumed bounded retry authorization (`refusal.run.retry_pending` —
  the authorization is never burned by a release, and the refusal names the
  remedy precisely: the authorization is spent by the ONE re-dispatch of that
  exact step, which the run's own armed supervision performs at its next
  check, or `run dispatch` of that step consumes it) and an unknown run
  (`state.not_found`).
  Terminal runs (`done` or `invalidated`) can release leftover ownership.
  The same idempotency key replays the recorded response; a fresh key records
  an audited ownership-absent no-op if ownership is already freed.
  A missing, revoked or EXPIRED grant is deliberately
  NOT a fence: such a run is exactly what a release exists for, and the
  release records that window (`release.authorization.status` /
  `expires_at` / `usable:false`) without presenting or reusing it — a
  continuation of that work needs a freshly minted grant window (a
  same-binding rotation), never a silent reuse of the expired one. A
  released run is never resumed, retried, dispatched or continued: the
  engine refuses a terminal instance (`refusal.instance.state`) and
  supervision's dispatch intent is a no-op for it, while the freed issue
  is admitted by a fresh submission on its own merits.
- `run.resolve` requires one diagnosed `prompt` step plus a recorder identity
  and closed artifact evidence (`feature_head`, the prompt's bound `branch`,
  `pull_request {repository, number}`, and non-empty named `checks`). It
  validates the run, ownership, live epoch/grant, exact diagnosed frontier,
  output branch and repository, then atomically records a successful attempt
  attributed to the recorder. It carries no prompt, argv, topology, grant or
  effect params and never executes the prompt again. The next frontier is the
  next genuinely unachieved step; a prompt without a resolution remains
  diagnosed and fenced from supervision re-dispatch.
- `run.dispatch` requires `params.instance_id`, `params.step` (a
  committed-spine plan step id) and an optional `params.params` object: the
  step's OWN inputs, which are merged over the step's committed params (the
  caller supplies only what the operator actually knows — a correction — and
  never a hand-built `hf-plan/v1`). Everything else is DERIVED from durable
  state: the plan document (run row pins + the committed step spine with the
  merged params), the run's grant/epoch/issue revision and the topology +
  admission inputs of the run's own recorded dispatch context. A run without
  a committed spine or without a recorded dispatch context refuses
  `refusal.run.scope` (the first dispatch of a run belongs to the caller that
  holds the topology), a step outside the spine refuses
  `refusal.run.step_unknown`, a step other than the ledger-authoritative
  frontier refuses `refusal.run.step_order`, and the merged params are checked against the
  step kind's existing param contract BEFORE anything is journaled. That
  pre-screen is TOTAL over the closed step-kind set: each kind's own param
  contract, the durable worker-head read-backs (`review_evidence`,
  `post_merge_verify`) and the topology gates its effect reads (the archive
  root) are resolved up front, and a kind with no registered contract refuses
  as well — so a request that is not well-formed enough to be attempted
  refuses typed (e.g. `refusal.request.malformed`, `refusal.push_policy`)
  whatever its kind, records no attempt, and leaves any pending bounded retry
  authorization UNCONSUMED. The resulting dispatch runs through
  the same `apply` engine, so every gate re-derives there and exactly one
  unconsumed authorization is consumed by a re-dispatch of a diagnosed step.
  It renders `hf-run-dispatch/v1` (the addressed run/step, the params the
  dispatch presented, the recorded apply outcome and the authorization this
  dispatch consumed).
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
  policy, the closed classification (`healthy`, `waiting-workers`, `worker-timeout`,
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
  were the record. The status document carries top-level `last_failure`: the
  newest recorded NON-succeeded step attempt with its raw message (`step`,
  `status`, `code`, `message`; `null` when the run has no standing failure) —
  issue #219: the frontier's diagnosis is readable WITH its reason, not as a
  bare code. The `evaluation` block also carries `retry`: the frontier step's
  own bounded-retry disposition, read from the same durable rows the engine's
  fence reads — `state` is `none` (no recorded non-success diagnosis),
  `awaiting-authorization` (diagnosed, nothing authorized, and the driver
  derives no dispatch: an operator authorization is the act that authorizes
  one), `authorized-awaiting-dispatch` (the run HOLDS an unconsumed `run.retry`
  authorization for that exact step: it is spent by the ONE re-dispatch it
  authorizes — issue #241), `driver-dispatch` (no authorization is held yet:
  supervision mints and consumes its own on the check), or `exhausted` (the
  shared bounded budget is spent, the typed escalation of issue #241 AC2) —
  with `step`, `consumed` and `bound`. A continuation the engine REFUSED is
  still named separately (`evaluation.refusal`), so `awaiting an operator
  authorization`, `authorized, awaiting dispatch` and `dispatch refused:
  <code>` are three distinct reads.
- A run with NO recorded progress observation yet (a fresh arm: `progress_at`
  empty, or an unreadable instant) is **held** — class `unknown`, reason
  `supervision.progress_unobserved`, `eligible:false` — never eligible: an
  unobserved run is not a timed-out one, so a fresh arm cannot open a
  continuation window. Only a recorded observation that is genuinely older
  than the explicit `progress_timeout_secs` policy is `continuation-eligible`
  with reason `supervision.progress_timeout`.
- **What the continuation window counts (issue #170 N1, accepted limitation)**:
  the durable window keys on the check's own eligibility, so an IN-FLIGHT
  collection wait — classified `waiting-workers` / `supervision.waiting_workers`
  with `eligible:true` (see "Pane collection" below: it is the one wait that is
  legitimate long-running work with a live claim) — also refreshes
  `continuation_reports`, and the operator surface renders the window OPEN with
  its report count for such a run. The counter therefore means "the run's own
  committed checks reported it eligible/healthy", not exclusively the absence
  window it was introduced for; the recorded check reason still names WHICH one
  (`supervision.progress_timeout` vs `supervision.waiting_workers`). No safety
  consequence: the second-dispatch gate is `evidence.in_flight`, never this
  counter.
- **Armed continuation dispatch (issue #92 F4)**: an explicitly `armed`
  run whose authorization still matches its committed submission is
  advanced by the driver itself from its FIRST step onward — the check hands
  the run's NEXT UNACHIEVED
  step to the merged `apply` engine, which re-derives every gate
  (capability, grant, admission, ownership, journal, idempotency) and
  journals the intent before any effect. The dispatch exists only when the
  run is live (not paused/pause-requested/human-queued/blocked/invalidated/
  done, no terminal blocker), has no step claim in flight, has a committed
  spine and dispatch context, and the frontier step has NEVER been attempted.
  The initial context (topology plus the admission observation) is committed
  by `queue submit --supervise arm --topology FILE`; later derived heads and
  session identities come only from the run's recorded apply outcomes. None
  is invented. A
  DIAGNOSED step (a recorded non-success) is re-dispatched by the driver only
  within the shared bounded retry budget (issue #179), and that re-dispatch
  presents the committed step's OWN params; the retry it spends is minted and
  consumed atomically through the apply path. The diagnoses a re-dispatch can
  never repair — `effect.worker_timeout`, `refusal.evidence.verdict_stale`,
  `refusal.delivery.moved` / `refusal.delivery.unbound` — stay parked with
  their bounded retries UNSPENT. An authorization the run already HOLDS (a
  `run.retry` row, issue #241) is consumed by that very re-dispatch, exactly
  once, recorded under the dispatch's own journaled idempotency key: the
  driver dispatches it, so a held authorization never parks the frontier and
  never makes a run unreleasable. The ONE exception is the risk-classed
  committed TAIL (`merge` / `cleanup`), which keeps issue #152's rule
  verbatim: an ATTEMPTED tail stays the operator's, and a held authorization
  over it is spent by that operator's own `run.dispatch` — which is also how
  corrected step inputs are presented, and which consumes the authorization
  when it arrives before the driver's next check (it is the only consumer for
  a run that is not armed). A fan-out step
  still needs the submission-presented
  admission inputs: supervision re-presents the run's committed caps and
  occupancy and, when the run's own recorded proof has LAPSED, presents a
  host-resource proof measured at DISPATCH time (issue #198) — the free
  bytes the host exposes at the run's lane root, audited as one
  `host.proof.renewal` record before the renewed proof is presented. An
  unmeasurable host renews nothing and the admission gate still refuses
  `refusal.admission.proof_stale`; a run that presented no proof is never
  given one (`refusal.admission.proof_missing` stands). `review_evidence`
  remains a concrete `supervision.waiting_approval` frontier until
  independent evidence is presented. Non-armed/unknown supervision keeps its
  classification-only, zero-effect guarantee verbatim: without a row the run
  is never even read.
- **Committed-tail dispatch (issue #152)**: the frontier is also dispatched
  when it is the risk-classed TAIL of that run's OWN committed queue spine —
  `merge` (the closed-policy LANDING of the reviewed head: it lands it on the
  integration ref and publishes it, a journaled control-plane mutation) and
  `cleanup` (destructive: the removal of a lane worktree whose branch is
  provably merged) — so the run that produced a verified delivery reaches its
  own last committed step instead of being foreclosed by it. This is NOT a
  blanket addition to the autonomous set and it widens NO gate: the step is
  dispatched only when the run is an ADMITTED member of a committed,
  digest-bound submission, the run's own committed caps carry the kind's
  required capability (`merge`/`cleanup` — the same capability
  `revalidate_effect` demands), and the step follows that run's
  reviewed-delivery step while the
  run carries a fresh verified delivery. The dispatch presents the committed
  step's OWN params (branch + `merge_policy`; branch + worktree) and the
  unchanged engine gates decide: production branches, the scheduled
  production/destructive refusal, the evidence-bound merge gate, the cleanup
  ancestry and dirty-worktree refusals and the capability check are all still
  in force; a DIAGNOSED tail is still never re-dispatched (the operator's
  corrected `run dispatch` owns it); and every refusal is reported with the
  engine's own code exactly like any other continuation refusal. The
  classification reads the SAME predicate, so a frontier reported eligible
  with `supervision.dispatch.next_step` is exactly a dispatchable one.
- **Pane collection (issue #147)**: a collection following a pane prompt
  polls that run's own Herdr agent, verifying lane token, generation and
  worktree on every read — and since issue #170 reading TWO views of that lane
  per sample (its own `agent get` row AND its `agent list` status row) plus the
  lane's own `state_change_seq` counter, so no stop is ever decided on one
  status field. While it waits, its single claim remains in flight:
  `waiting-workers` / `supervision.waiting_workers`, eligible for continued
  checks, not a second dispatch. Collection runs off the reconciliation thread
  (its own `canter-collect` thread) so other runs and timer checks continue;
  the wait's sample cadence is bounded (`mutation::COLLECT_STOP_INTERVAL_SECS`,
  5 s — two subprocess rows per sample instead of the pre-change ~100 ms loop,
  issue #170 N3).
- **A CONFIRMED stop (issue #170 N7)**: only `mutation::COLLECT_STOP_SAMPLES`
  (3) consecutive samples — each separated by that real interval, in which
  BOTH views report a non-working state (`idle`/`done`/`blocked`) and the
  lane's own counter did NOT move — make the worker's turn a stop, and only a
  confirmed stop permits certifying the delta. A status field that flaps to
  `done`/`idle` mid-turn is not a stop (measured live: two read-backs ~100 ms
  apart judged a working pane stopped four minutes into a 93-minute turn), and
  `refusal.collect.empty_delta` is ONLY ever the outcome of a confirmed stop:
  while the worker is working the collection keeps waiting. A delivery read
  while the worker is still live, like an empty delta while the worker is still
  live, stays a wait/re-check (issue #200 — a head read mid-turn can still
  move), and a confirmed stopped worker with no delta still refuses
  `refusal.collect.empty_delta`. A collection failure that is not emptiness (a
  refusal of the collection itself, e.g. a diverged or mis-branched lane)
  certifies no head and stays actionable without waiting for the stop. A row
  that carries NO state on the second view corroborates nothing and blocks
  nothing (the same convention a missing readiness signal gets), so an older
  row shape is never weaker than the pre-change rule.
- **The wait is bounded by RECORDED PROGRESS (issue #170 N8)**: the step's
  effective deadline is the wait's NO-PROGRESS WINDOW, and the wait EXTENDS
  past it while progress is recorded — the lane reports `working`, its
  read-back moved (state changed, own counter advanced), or the delivery it
  collected moved (a new certified head) — up to the hard overall ceiling
  `mutation::COLLECT_CEILING_SECS` (6 h ≈ 4× the measured real turn, which ran
  ≈93 minutes against the old 1800 s wall: the step was unconvergeable by
  construction). The window is decided on the progress each SAMPLE recorded —
  a read-back that carries progress at the window's boundary is never parked
  past, while the read itself is always given a real budget (what the window
  has left, floored at one second). A lane that records NO progress for the
  whole window parks as `effect.worker_timeout`, ambiguous, `worker-timeout` /
  `supervision.worker_timeout`, ineligible, and so does a lane still producing
  progress at the ceiling; the message names the progress last observed and
  the elapsed silence. The wait is never unbounded. Neither a waiting claim nor
  a timed-out attempt is re-dispatched by the supervisor.
- **Collection refusals widened, recorded (issue #170 N6)**: a
  `collect_outcome` whose run never recorded a succeeded `harness_start`
  refuses `refusal.incomplete.identity` BEFORE evaluating any delta. The
  fail-closed direction is deliberate and this is the canonical record of it.
- **Frozen certified delivery and the bound collection head (issue #202)**: a
  step consumes only the head the run's OWN collection certified. The run's
  `feature_head` is bound by its newest successful `collect_outcome` (branch +
  head + base, recorded and attributed); a `head` echoed by any other effect's
  response never becomes a certified feature head, and a `review_evidence` or
  `merge` step arriving when no collection certified a delivery refuses typed
  (`refusal.delivery.unbound`) before any effect runs. A collection that cannot
  name the 40-hex head and slug branch it observed is a typed non-success
  (`refusal.collect.unbound`), never a `succeeded` outcome that bound nothing.
  Once a verdict is recorded against a head, the delivery is FROZEN at exactly
  that head: with the published integration ref unchanged, the merge consumes
  the delivery branch only when it is AT that head — a commit that landed on
  the reviewed delivery afterwards refuses typed
  (`refusal.delivery.moved`, naming both heads) without publishing or moving
  anything, and the delivery must re-enter review so a new verdict names the
  moved head. Like the moved-certificate case below, that diagnosis is
  deterministic (the verdict is a recorded fact and the delivery's movement is
  external), so the frontier parks typed with its bounded retries UNSPENT. The
  published-ref reconciliation (issue #178) is the ONE documented engine
  refresh and is unchanged: a history rewrite onto the *published* ref whose
  reviewed content is proven byte-for-byte.
- **Moved certified head (issue #200, extended by issue #207)**: a review step
  whose recorded diagnosis is `refusal.evidence.verdict_stale` — the lane
  checkout is no longer the run's certified head — is an IMPOSSIBLE step, not
  a retryable one: the certificate is a recorded fact and the checkout's
  movement is external, so a re-dispatch is guaranteed to refuse identically.
  The frontier parks typed (class `needs-attention`, reason
  `supervision.step_diagnosed`, the recorded code as the detail, ineligible)
  with the run's bounded retries UNSPENT, instead of burning the budget on a
  step that can never succeed. Refusing to review a moved head is unchanged:
  a reviewer is never started on a head that does not match the certificate.
  The reviewed work is fenced for the WHOLE review window (issue #207): the
  self-dispatching review step reads the lane checkout once when the reviewer
  starts (that check) and AGAIN after the reviewer's verdict is awaited,
  before anything is recorded. A checkout that moved while the review was
  open refuses the same deterministic `refusal.evidence.verdict_stale`
  (naming both heads and the re-entry requirement) — a commit that lands
  mid-review forces re-entry into review, and no verdict is ever recorded for
  a delivery that moved under its own review.
- **Lane base (issue #164)**: checkout and lane creation use the exact
  observed integration base, or resolve the published origin ref when no
  observation exists yet; never the local branch. Missing objects are fetched
  without moving that frozen base. Existing lane directories refuse typed
  (`refusal.worktree.exists`); they are not reset or silently reused.
- **Lane wait on p8 (issue #224)**: the cleanup step's landing proof runs
  BEFORE its workspace retirement, so a lane that is still ALIVE when the
  proof already holds is the worker outliving its own publish — a timing
  condition, not an ownership problem. The step then WAITS, bounded by its own
  effective deadline (the cleanup row of the per-kind table, or the plan's
  declared `deadline_secs`), for the settled turn the worker produces on its
  own (`refusal.lane.busy` names the live lane on every read-back), and closes
  the workspace once the lane settles; the recorded outcome carries the wait
  (`lane_wait`: `bound_secs`, `waited_ms`) alongside the step's own
  `deadline_secs`. A wait that exhausts the bound records `effect.lane_timeout`
  as `ambiguous` with the live lane's own message and the bound named, and the
  frontier parks typed with the bounded retries UNSPENT — never a retry burned
  on the timing, and never a workspace closed. A lane that is NOT published is
  refused typed (`refusal.cleanup.unmerged`, see the lifecycle contract), and a
  workspace that is a superseded generation's or another lane's is still
  refused at once (`refusal.stale.generation`/`refusal.lane.name_collision`) —
  neither is ever waited on, so the live-lane protection is unchanged.
- **Diagnosed frontier (issue #148)**: the classification half of the same
  honesty. The frontier step's own LATEST recorded attempt is read from the
  run's claim/outcome material, and when it is not `succeeded` the run is
  reported class `needs-attention`, reason `supervision.step_diagnosed`, the
  recorded attempt's own error code as the detail, `eligible:false`. A step
  that has already run and diagnosed a concrete failure or refusal — the
  measured #147 prompt, whose outcome says nothing was delivered — is never
  reported as `waiting-workers`/`waiting-CI`/`waiting-approval`: nothing is
  in flight, and a wait for
  workers that are not running is exactly the lie that parked that run. The
  driver fence is unchanged in what it refuses: a diagnosed step whose
  recorded code is one a re-dispatch can never repair, or whose bounded budget
  is spent, is never re-dispatched — while an authorization the run already
  holds is consumed by the re-dispatch it authorizes (issue #241), so a
  diagnosed frontier is reported with its own code as the detail and is never
  presented as eligible. A step with NO
  recorded attempt keeps its own rules: the driver still dispatches a
  never-attempted autonomous step, and the refusal-before-any-effect case
  keeps `supervision.dispatch_refused` above. The frontier's own retry
  disposition is read back separately in `evaluation.retry` (below).
- **Fix-round handoff (issue #238)**: a recorded review FAIL is handed to the
  run's own fix round by the review step itself, and the classification reports
  the handoff's recorded disposition instead of parking on the FAIL. The
  handoff's record is the review step's own apply row (the round, the automatic
  bound and the fix leg's lane), read back with the same material the
  classification already reads — from the RESPONSE document the daemon
  persists (`hf-rpc-response/v1`, `result.fix_round`), with the `outcome`
  column read beside it (issue #254) and its `hf-fix-round/v1` validation
  unchanged:
  - the handoff was DISPATCHED for the newest verdict's head — class
    `waiting-workers`, reason `supervision.fix_round_dispatched`, the fix leg's
    lane as the detail, `eligible:false` (the repair leg is work in flight, not
    completion). The wait keeps this meaning only while the repair leg's OWN
    lane checkout has not advanced: the leg's own state is what tells a leg
    that is still working from one that has DELIVERED (issue #256);
  - the handoff was REFUSED, or its budget is spent — class
    `needs-attention`, reason `supervision.fix_round_refused` /
    `supervision.fix_rounds_exhausted`, the fix round's OWN engine code
    (`refusal.fix.spawn` / `refusal.fix.prompt` / `refusal.fix.lane` /
    `refusal.fix.bound_exhausted`) as the detail, `eligible:false`. The refusal
    is the review step's recorded outcome, so `run status` names the same code;
  - the newest recorded handoff names ANOTHER head than the newest recorded
    review evidence (issue #254: the repair leg advanced the branch past the
    head the FAIL was handed at) — class `needs-attention`, reason
    `supervision.fix_round_head_moved`, the fix leg's recorded lane as the
    detail followed by both head prefixes, `eligible:false`. The recorded round
    is not this evidence's handoff, so the movement is named instead of
    discarded: still the fix-round disposition, never a bare
    `supervision.review_failed`;
  - the handoff's OWN repair leg has DELIVERED a head past the one the FAIL was
    handed at (issue #256) — the SAME class and reason
    (`needs-attention` / `supervision.fix_round_head_moved`), the fix leg's
    recorded lane as the detail followed by both head prefixes (the head the
    verdict certified and the head the leg's own checkout holds),
    `eligible:false`. The disposition is derived from the repair leg's OWN
    recorded state, never from the head the FAIL was handed at: the engine's
    `hf-fix-round/v1` record names the leg's own lane checkout (`worktree`,
    recorded where the leg was created or verified) and the classification
    reads THAT checkout's head — bounded `git`, allowlisted environment,
    read-only, outside the state guard — where a head DESCENDING the certified
    head is the delivery itself. Nothing is inferred: a leg whose own checkout
    has not advanced, a handoff that names no lane, and every read that cannot
    be taken are all "no movement", and the recorded disposition stands
    unchanged;
  - the same read binds the next review round (issue #256): a dispatch of the
    run's review step presents the DELIVERED head as the observed head when the
    recorded handoff's leg delivered a descendant one, so the reviewer leg's
    derived checkout materializes the delivered commit (the reviewer lane's own
    creation/verification, unchanged) instead of re-reviewing the head whose
    check can never flip. The run's own delivery-certification gate (issue
    #202, `refusal.delivery.unbound`) is untouched: a head the run's own
    collection has never certified is still never consumed, so the delivered
    head still has to be certified by that collection before a step consumes it
    (the gate's own message names exactly that precondition);
  - a FAIL whose review step recorded no fix round at all — a plan that
    presents its own review facts, or a run recorded before this handoff
    existed — keeps `supervision.review_failed`, now with the review step as
    its detail instead of an empty one.
  A fix-round record naming ANOTHER head is never this FAIL's handoff (the
  certified head moved past it), so the rule is keyed to the head the verdict
  names, never to the newest row — and the driver's own recovery-control
  derivation reads the recorded FAIL too (issue #254): when the run's newest
  recorded review evidence carries a non-passing check and its check producer
  already succeeded, the run's own bounded re-evaluation is driven at the
  recorded head instead of the run parking on the FAIL.
- **Refused continuation dispatch (issue #141)**: when the engine refuses the
  driver's continuation of the frontier step BEFORE its claim (a fan-out
  admission refusal such as `refusal.admission.proof_stale`, a derived
  request the pre-screen rejects), the refusal leaves no attempt row, no pane
  and no intent of its own. It is therefore journaled against the run as
  `supervision.dispatch_refused` with the engine's own code and the engine's
  own message (the target is `<run>:<step>:<code>`, with the message recorded
  LAST as `:reason:<message>`, bounded at the recording site — issue #230; a
  refusal recorded with an empty message keeps the bare
  `<run>:<step>:<code>` target), and the classification reports it — class
  `needs-attention`, reason `supervision.dispatch_refused`, the engine's code
  as the detail, `eligible:false` — for as long as that refusal is the newest
  recorded evidence of the run. A frontier whose dispatch is refused is never
  reported eligible with `supervision.dispatch.next_step`, and the refusal is
  never an attempt: a *currently* DIAGNOSED frontier keeps its own
  no-redispatch fence unchanged. The driver keeps attempting the same
  continuation it would attempt for an untouched frontier, so a repaired
  environment (a refreshed admission attestation) is admitted as soon as the
  apply gate accepts it, and any recorded progress supersedes the reported
  refusal.
- **Refused continuation dispatch, never attempted (issue #230)**: the same
  report is produced when the engine's own gate refuses the frontier *before
  any dispatch exists* — the run's next unachieved step is its
  verified-delivery consumer (a committed `merge` / `cleanup` tail step its
  own caps authorize, after the reviewed-evidence step) and the run's newest
  recorded review evidence is a `pass` bound to the run's pins at one exact
  head whose named checks are NOT all `passed`. Nothing is attempted in that
  shape, so no `supervision.dispatch_refused` record can exist; the
  classification DERIVES the engine's refusal from the same recorded facts the
  gate reads and reports class `needs-attention`, reason
  `supervision.delivery_unverified`, the engine's own code
  (`refusal.evidence.failed`) as the detail and the engine's own message as
  the read's reason, `eligible:false`. The gate itself is untouched: the tail
  is still never driven behind an unverified delivery, and a recomputation
  that comes back failing derives the identical refusal.
- **The driver drives the run's own recovery control (issue #243)**: in
  exactly that recorded shape — the frontier is the run's committed
  verified-delivery consumer and the run's newest recorded review evidence is
  a `pass` at one exact head whose named checks are NOT all `passed` — the
  driver's ONE intent is the run's OWN check producer, re-evaluated through
  the engine's own bounded, attributed, journaled control (`run.reevaluate`):
  a fresh derived lane round, the producer's own recomputation, the driver's
  recorded identity (`supervision`) and a derived reason in the hash-chained
  journal BEFORE anything is dispatched. The bound is the control's own
  (three per `(run, step)`, counted from the durable journal), so a spent
  bound mints no intent at all, and a refused recovery carries the engine's
  own code and message (the control's own outcome row, plus a
  `supervision.dispatch_refused` record when the refusal left no claim of its
  own). Nothing else changes: the
  run is still reported class `needs-attention`, reason
  `supervision.delivery_unverified`, `eligible:false`; the tail behind the
  unverified delivery is still never driven; a recomputation that comes back
  failing derives the identical refusal; and the general rule that a parked
  run stays parked is untouched — only the engine's own typed recovery
  control is driven, exactly as an operator would drive it.
- `continuation-eligible` remains a REPORT (the classification half), and
  an idle/done agent alone is neither completion (a `done` run without
  passing review evidence stays unknown) nor permission to resume (a paused
  run is never eligible and is never dispatched).
- **Completion-to-next-work (issue #96)**: a fresh VERIFIED delivery of an
  armed run — reviewed `pass` with every named check `passed` at one exact
  head, bound to the run's own workflow/policy pins, no durable hold and no
  in-flight step claim — advances its
  already-authorized queue cursor EXACTLY ONCE, admitting the next eligible
  approved item of the SAME committed submission through the same
  guard-verifying admission path (the same approved caps and occupancy
  attestation), armed with the delivering run's supervision authorization.
  The DELIVERING run is completed (`done`) by that same transaction only once
  the delivery is its LAST committed spine step (issue #152): a run whose
  committed spine still carries steps after the delivery (the merge, then the
  cleanup) stays live and keeps its counted slot until those steps are
  recorded as achieved — and the driver DRIVES that tail itself (the
  committed-tail dispatch above), so the run's own authorized merge and
  cleanup run without an operator request and the completion is never a bare
  `done` over an unexecuted plan. A spine that ends at its reviewed-evidence
  step completes exactly as before.
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
