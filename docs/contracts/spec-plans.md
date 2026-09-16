# Spec: deterministic plans, plan digests, route grants, state epochs, idempotency keys, typed outcomes

Refs #3. Families: `hf-plan/v1`, `hf-grant/v1`, `hf-epoch/v1`,
`hf-outcome/v1`. Fixtures under
[`plan/`](../../schemas/fixtures/plan/plan.valid.json), [`grant/`](../../schemas/fixtures/grant/grant.valid.json),
[`epoch/`](../../schemas/fixtures/epoch/epoch.initial.valid.json), [`outcome/`](../../schemas/fixtures/outcome/outcome.succeeded.valid.json).
Design commitment (locked spec: plan-first, digest-bound, freshly
revalidated, journaled before effect, idempotency-keyed, exactly read back).

## 1. Deterministic plans: `hf-plan/v1`

A plan is the complete, typed description of intended effects for one
issue-bound unit of work: repository identity, pinned workflow id + hash,
the state epoch it was computed against, the exact issue/acceptance
revision, and an ordered list of typed steps.

```json
{"schema":"hf-plan/v1","plan_id":"hf_plan_0123456789abcdef","workflow_id":"fleet-doctrine-1",
 "workflow_hash":"<64hex>","state_epoch":3,"repository":"example-org/widgets",
 "issue":{"number":123,"revision":"<40hex>"},
 "steps":[{"id":"p1","kind":"checkout","params":{"ref":"staging"}}, ...]}
```

Normative rules:

- `issue.revision` is the **exact acceptance revision** the plan is bound
  to (issue body/acceptance text hash or issue-level commit pin recorded by
  the grant issuer). Changing acceptance text invalidates plans bound to
  the old revision.
- Step `kind` is a closed set (`checkout`, `worktree_create`,
  `harness_start`, `prompt`, `collect_outcome`, `review_evidence`, `merge`,
  `cleanup`, `publish`, `branch_push`, `pr_update`, `issue_update`,
  `hosted_check`, `post_merge_verify`, `branch_delete`, `approve`). The
  granular kinds after `publish` are added by issue #8 so a plan document
  can express the full daemon-mediated control-plane mutation surface
  (worktree/branch ops, forge issue/PR updates, hosted-check observation,
  post-merge verification, branch deletion, first-write approval). There is
  no shell/embedded-code step; a document carrying an unknown kind is
  refused (`plan.malformed.json`).
- Plans do not classify risk; risk comes from the target/effect table in
  the daemon ([risk-model.md](risk-model.md)) — nodes cannot downgrade it.
- The built-in selected-issue spine binds `worktree_create`, `prompt`, and
  `collect_outcome` to one feature branch/worktree. Its prompt and collection
  declare `requires_delta:true`; collection refuses
  `refusal.collect.empty_delta` unless the worker head contains a committed
  file delta from this run's own successfully recorded `checkout` base.
  `base_head` defaults only from that durable response, never from whatever
  the integration clone points at later. A plan may explicitly declare
  `requires_delta:false` for a legitimate no-op prompt; collection then
  succeeds with equal base/head while still enforcing the bound output branch.
- The built-in `merge` step declares `merge_policy:"squash"`. `merge_policy`
  is a closed `squash | ff` input and the effect is a read-only rehearsal: it
  verifies the reviewed integration ref and policy-compatible result tree but
  never moves the integration checkout or a ref. The orchestrator/forge owns
  the actual policy merge; `post_merge_verify` proves its landed head.

### Canonical serialization and digest

- Canonical bytes: JSON with keys sorted lexicographically, compact
  separators, ASCII escaping, single trailing LF (shared rule,
  [schema-registry.md](schema-registry.md)).
- Plan digest = lowercase hex sha256 over the canonical bytes. `plan.valid.json`
  is stored in canonical form and the manifest pins its known-answer digest;
  `plan.noncanonical.json` (same content, pretty-printed) is refused with
  `REFUSE_NONCANONICAL`.
- The digest is what grants/audit records bind to, and what apply
  revalidation re-computes immediately before effects.

## 2. Route grants: `hf-grant/v1` (AC3)

A route grant is the only authorization to start durable work:

```json
{"schema":"hf-grant/v1","grant_id":"gr_0123456789abcdef","repository":"example-org/widgets",
 "issue":{"number":123,"revision":"<40hex>"},"workflow_hash":"<64hex>","policy_hash":"<64hex>",
 "phase":"merge","scope":"worktrees/issues/123","caps":["read","worktree","spawn","prompt","review","merge"],
 "expires_at":"2026-09-13T00:00:00Z","state_epoch":3,"created_at":"2026-09-06T00:00:00Z"}
```

AC3 bindings, all required fields of the document:

- repository identity (`repository`),
- exact issue and acceptance revision (`issue.number`, `issue.revision`),
- workflow hash (`workflow_hash` — canonical digest of the pinned workflow
  document, [spec-workflow.md](spec-workflow.md)),
- policy hash (`policy_hash` — digest of the effective config+overlay),
- allowed phase (`phase`, closed set), scope (`scope` — path-scoped lanes
  and overlap checks), caps (`caps`, closed subset),
- expiry (`expires_at`),
- state epoch (`state_epoch`).

Semantics: labels/comments alone never authorize (trust model T6). Grants
are consumed/checked by the daemon, expire, and die with their epoch. A
grant missing any binding is refused (`grant.malformed.json` removes
`state_epoch`).
For the same live binding, a later issuance may replace an expired window on
the same durable run; the daemon records `grant.rotation` naming both grant
rows and the new expiry. A live window remains the owner and refuses rotation.
No expired row is replaced or silently reused.

## 3. State epochs: `hf-epoch/v1` (AC7)

Epochs give every durable claim a generation anchor:

```json
{"schema":"hf-epoch/v1","epoch":1,"created_at":"2026-09-06T00:00:00Z",
 "reason":"initial","prior_epoch":null}
```

- The initial epoch has `prior_epoch: null`; every later epoch (reason
  `restore` or `security_rotation`) **must** reference its `prior_epoch`
  (`epoch.malformed.json` drops it).
- **Restore semantics (AC7)**: a restore creates a new state epoch;
  prior grants and digests are invalidated; interrupted work is marked
  ambiguous; external state must be reconciled by a human/operator before
  new grants issue. The `hf-epoch/v1` record with `reason:"restore"` is the
  durable marker of that rotation.

## 4. Idempotency keys

Format: `ik_` + 8-64 `[a-z0-9-]` (registry scalar table). Rules:

- Every mutating apply carries one (`hf-rpc-request/v1` `apply` requires
  `params.idempotency_key`; see [spec-daemon.md](spec-daemon.md)).
- The daemon records the key in the audit journal before the effect (AC6)
  and in the typed outcome; replaying an effect with a consumed key returns
  the recorded outcome instead of re-executing.
- Exactly-once across external systems is never claimed; the key gives
  at-most-once dispatch plus exactly-once read-back of the recorded result.

### Apply semantics (issue #8; daemon `apply`, one plan step per request)

The daemon `apply` method executes ONE plan step per request (the plan is
bound by digest; the step is addressed by id) and is the only path that
runs control-plane effects:

- The request carries the canonical plan document; the daemon recomputes
  the digest and the content-derived `plan_id` before anything is journaled
  (`refusal.plan.identity` on tamper). The plan hash and grant id ride the
  journaled intent.
- Immediately before the effect the daemon revalidates, under the state
  lock: live epoch vs plan/grant/instance, grant status and expiry (an
  expired grant refuses with `refusal.grant.expired`), the observed issue
  revision vs the grant binding, workflow/policy hashes vs the grant and
  the pinned instance, and the step's required capability (`caps`, AC3).
- Kind-specific gates run before the effect: an integration merge requires
  current review evidence (distinct exact-head reviewer + passed checks
  bound to head/base/workflow/policy — any moved binding refuses with
  `refusal.evidence.stale`); issue closure requires the instance to sit at
  the plan's `post_merge_verify` step with passing evidence; cleanup keeps
  its salvage audit pair (`mutate.cleanup` before, `salvage.cleanup`
  after); production-branch effects require a fresh interactive
  TTY-confirmed digest; a real-external target scope requires the recorded
  first-write approval (AC10; the canary itself is a separate human gate).
- The effect runs outside the state lock through allowlisted subprocesses
  (`git` against disposable local repositories in tests; `gh`/workspace
  fakes) and resolves with a typed `hf-outcome/v1` (succeeded/failed/
  refused/ambiguous) plus the exact external read-back; ambiguous effects
  (timeout, process death, post-effect record failure) resolve the claim as
  `ambiguous` — external reconciliation is required before a new key.
- **Per-effect deadlines (issue #92 F1)**: every effect that spawns has an
  explicit, documented, bounded deadline, resolved from a per-kind table —
  never a bare constant at the effect site:
  - `prompt` 1800 s, `harness_start` 300 s, every other
    kind 60 s (`EFFECT_DEADLINE_DEFAULT_SECS`), and the hard ceiling is
    3600 s (`EFFECT_DEADLINE_CEILING_SECS`);
  - a reviewed plan step may declare its own `deadline_secs` (policy, bound
    by the plan digest); a value outside `1..=ceiling` — or a non-integer —
    refuses `refusal.request.malformed` (`effect_deadline_secs` validates
    the override; `refusal.plan.malformed` is bind-time only) before the
    effect runs;
  - the EFFECTIVE value rides on the step's `result` as `deadline_secs`, so
    the step outcome/evidence always names the deadline the effect used;
  - the child of an effect leads its own process group and a deadline
    EMPTIES that group (no orphan), reporting `adapter.timeout` as the typed
    `ambiguous` outcome. Group semantics are confined to the effect-class
    harness invocations — the prompt row and a declared start row — because
    that is the audited defect path; every other adapter operation (the
    workspace protocol rows: observe/identity/interrupt/outcome/retirement)
    keeps the pre-existing spawn path unchanged, so a workspace row that
    existed before the group runner spawns byte-for-byte as it did
    (issue #92 round 4). The guarantee is verification, not one CLI form: a
    `kill -9 -<pgid>` helper attempt is made first (best-effort — the
    negative-pid form is not portable), then the group's live members are
    enumerated with a portable `ps -A -o pid=,pgid=,stat=` and terminated by
    POSITIVE pid, re-enumerated until the group is empty or the bounded
    window expires (`GROUP_REAP_WINDOW`, 375 ms). Our own pid and any pid
    outside the group are never signalled; a descendant that left the group
    (its own session or process group) is unreachable by design and is
    reported rather than waited for. The helpers are resolved from the
    ambient environment plus the standard system directories — never from the
    child's allowlisted PATH — and the whole termination is named in one
    diagnostic line on the captured stderr (what the helper attempt did, how
    many members were reaped by positive pid, which members no kill could
    reach): a failed attempt is named with its reason and is never counted as
    a reap nor rendered as delivered, so the step outcome/evidence explains a
    failure instead of hiding it;
  - the post-exit path of the captured pipes is bounded by a documented grace
    (`PIPE_READ_GRACE`, 750 ms, which contains the reap window): a descendant
    that survives the reaping and holds the inherited write ends can never
    extend an effect past `deadline + grace`, and whatever arrived inside the
    bound is kept (the capture may be empty or partial in that case).

- **Execution substrate per step (issue #139)**: a harness step
  (`harness_start`, `prompt`) may declare `params.execution`, a closed token
  (`herdr` | `headless`):
  - absent ⇒ `herdr`, the product substrate: the role runs inside a Herdr
    pane registered for the run's linked worktree (`worktree open --cwd … --path …`), the
    prompt is delivered through `herdr agent prompt`, and observation/
    interruption/terminal outcome are collected through the `herdr agent`
    rows (see [spec-capabilities.md](spec-capabilities.md), "Execution
    substrates"). The bind step resolves the lane worktree from the reviewed
    plan: a plan that binds no `worktree` (or more than one, e.g. a
    multi-issue submission) refuses typed on this substrate and names the
    explicit fallback instead of creating a pane at a bare cwd or in the
    wrong lane;
  - `headless` ⇒ the pre-#139 bare-subprocess row, selected explicitly by the
    reviewed plan. It is never chosen silently, and a Herdr failure never
    falls back to it: the substrate is a step param, so it is bound by the
    plan digest and can never move at effect time;
  - a token outside the closed set refuses `refusal.request.malformed`; it is
    never defaulted.
  `harness_start` also accepts `lane_role` (`implementer` or `reviewer`,
  default `implementer`) and a positive integer `lane_round` (default `1`).
  With the plan's issue number these produce human-readable names; they do
  not replace the opaque session/generation ownership tokens. The verified
  workspace id, label and worktree identity accompany the pane and agent in
  the response AND the durable start outcome (issue #154).
  The recorded step outcome names the substrate (`result.execution`), the
  pane and agent of a pane-substrate bind (`result.pane` / `result.agent`),
  and the settled Herdr state of a pane-substrate prompt
  (`result.harness_state`). A pane-substrate prompt is recorded as succeeded
  only when the agent's own read-back proves BOTH that the task text arrived
  and that the agent took the submission (issue #148 round 1: the pane's
  scrollback can show the task text without the agent receiving it, so the
  transcript alone is not a delivery; the prompt's bounded window is the retry
  bound and a prompt that never arrives refuses `refusal.prompt.undelivered` —
  see [spec-capabilities.md](spec-capabilities.md), "Execution substrates").

## 5. Typed outcomes: `hf-outcome/v1`

Every plan step ends in one typed outcome:

```json
{"schema":"hf-outcome/v1","plan_id":"hf_plan_0123456789abcdef","step_id":"p5",
 "status":"succeeded","idempotency_key":"ik_apply-20260906-0001",
 "observed_at":"2026-09-06T00:00:00Z","result":{"exit_code":0},"error":null}
```

- `status` closed set: `succeeded` | `failed` | `ambiguous` | `refused` |
  `superseded`.
- `failed`/`refused` outcomes must carry an `error` shaped like
  `hf-error/v1` (`outcome.malformed.json` is a failed outcome without one).
- `ambiguous` is reserved for interrupted/restored work (AC7: restore marks
  interrupted work ambiguous) and always requires external reconciliation.

## Fixture map

| Fixture | Expectation |
| --- | --- |
| `plan/plan.valid.json` | accept + pinned known-answer digest |
| `plan/plan.noncanonical.json` | refuse (non-canonical bytes) |
| `plan/plan.malformed.json` | refuse (shell step kind — closed set) |
| `plan/plan.unknown-version.json` | refuse (unknown version) |
| `grant/grant.valid.json` | accept (all AC3 bindings) |
| `grant/grant.malformed.json` | refuse (missing state epoch) |
| `grant/grant.unknown-version.json` | refuse |
| `epoch/epoch.initial.valid.json`, `epoch/epoch.restore.valid.json` | accept |
| `epoch/epoch.malformed.json` | refuse (restore without prior epoch) |
| `epoch/epoch.unknown-version.json` | refuse |
| `outcome/outcome.succeeded.valid.json`, `outcome/outcome.failed.valid.json` | accept |
| `outcome/outcome.malformed.json` | refuse (failed without error) |
| `outcome/outcome.unknown-version.json` | refuse |
