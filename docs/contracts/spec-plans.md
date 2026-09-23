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
  A collection whose run never recorded a succeeded `harness_start` refuses
  `refusal.incomplete.identity` before it evaluates any delta (issue #170 N6 —
  fail-closed, recorded in [spec-daemon.md](spec-daemon.md) as an accepted
  limitation). A collection that cannot bind the head it observed still refuses
  `refusal.collect.unbound` (issue #202).
- The `checkout` and `worktree_create` steps resolve their base through the
  SAME published-integration-ref read the merge step uses, so an `origin` the
  integration checkout cannot read (absent, unreachable, unauthenticated)
  refuses with that read's own code, `effect.merge.failed` — a merge-typed code
  on a lane-creating step. It is fail-closed and names the read's diagnostics;
  recorded here as an accepted limitation of the shared read (issue #170 N2),
  never as the merge step's outcome.
- The built-in `merge` step declares `merge_policy:"squash"`. `merge_policy`
  is a closed `squash | ff` input and the effect LANDS the certified delivery
  on the integration ref and PUBLISHES it to the integration remote — a
  control-plane mutation the daemon journals like every other effect. It
  certifies only the PUBLISHED integration ref: that head is read from the
  checkout's `origin` remote (`git ls-remote` — a bare-remote move is visible
  without a fetch, never from the checkout's own refs). An unreadable or absent
  published ref refuses the typed `effect.merge.failed` on both routes — an
  absent ref, or an `origin` the checkout cannot read at all (absent,
  unreachable, unauthenticated), which keeps the read's git diagnostics in the
  message — rather than certifying an unprovable base. A checkout AHEAD of, or
  diverged from, the published ref is an unpublished local move and refuses
  `effect.merge.not_fast_forward`, naming the published head and the local
  head. A checkout strictly BEHIND the published ref (any concurrent landing
  moves it while a run is in flight) is reconciled instead of refused forever
  (issue #178): the published ref is FETCHED into the checkout's
  remote-tracking ref and verified against the published read, a certified
  delivery that does not contain it has exactly its reviewed delta
  (`reviewed_base..certified_head`) replayed onto the fetched published head in
  the delivery's own contained lane worktree, and the step then reports the
  bounded `refusal.run.retry_required` naming the reconciled head; the retry
  re-certifies the reconciled head against the fetched published ref, proving
  every path the review covered carries the reviewed head's exact content
  (the same fail-closed content fact as the cleanup landed proof — NUL-delimited
  names, literal pathspecs, both rename endpoints). A replay that CANNOT be
  carried out, or one that rewrites the paths the review covered, is never a
  step failure and never content to consume: the refresh is withdrawn (the
  delivery is left at the exact head its verdict names) and the step refuses
  its OWN typed condition `effect.merge.base_moved`, naming the reviewed base,
  the published head it moved to and the remedy (issue #263) — a base move is
  a recorded fact about the PUBLISHED ref, so the run parks on it with the
  bounded retries UNSPENT instead of spending the whole budget on a condition
  it can never resolve by itself, and the delivery must be refreshed under a
  fresh review whose new verdict names the refreshed head. A missing or
  uncontained lane worktree still refuses with diagnostics and never leaves a
  partial rewrite.
  The LANDING honours the declared policy: `squash` writes ONE new integration
  commit whose tree is the delivered tree and whose parent is the published
  head (the delivered commits are rewritten, so a squash landing is never an
  ancestor of the delivery), `ff` lands the delivered head itself. The landing
  is fast-forwarded into the integration checkout — never a rewrite, never a
  forced update; a checkout that cannot advance (uncommitted operator work on
  the landed paths) refuses `effect.merge.failed` BEFORE anything is published
  — and pushed to the same `origin` remote the published ref was read from.
  The published ref is then read back: the step succeeds only when it carries
  the landing (`mode:"landed"`), and a landing that cannot be published records
  a typed non-success (never `succeeded`) with the integration checkout rolled
  back to the published head, so no local move the published ref does not carry
  is ever left behind. A delivery whose content is already on the merge target
  — a prior landing of this very delivery, or a delivery with no content beyond
  the base — reports `mode:"already-landed"` and publishes nothing. The outcome
  records `published_head`, `published_after`, `landed_head`, `checkout_head`,
  `certified_head`, `reconciled_head` and `reconciled`. `post_merge_verify`
  proves the landed head — by exact ancestry, or, for a squash landing, which
  rewrites the reviewed commits and can never be an ancestor, by the same
  content fact (issue #176, #178).
  Separately, the spine's
  `cleanup` step proves ancestry or content-equivalence against the
  integration ref: the checkout's own ref first, and — when the sanctioned
  landing happened on the forge instead, which no checkout's own ref ever
  sees — the FETCHED, verified PUBLISHED head, which only a checkout
  strictly behind it may certify against (a checkout ahead of, or diverged
  from, the published ref is an unpublished local move and refuses; issues
  #132/#156). The content fallback covers every changed path, including both
  rename endpoints, with NUL-delimited names and literal pathspecs. Partial
  landings and paths that the text adapter cannot compare losslessly refuse
  without removing the lane or branch. The precise fail-closed cases and
  deletion flags are in [the lifecycle contract](spec-lifecycle.md#5-cleanup-archivesalvage-and-canonical-target-classification-ac7).
  This permits complete squash landings without weakening the ancestry-only
  standalone `branch_delete` effect (Refs #132, #172, #176, #178).
- The step PUBLISHES through the route the topology DECLARES (issue #219):
  `topology.integration_publish`, closed `push | pull_request`, default
  `push` when the topology declares none. `push` is the landing above —
  fast-forwarded into the integration checkout, pushed to the same `origin`
  the published ref was read from. `pull_request` is the route for a
  repository whose own rules forbid a direct push to its integration ref
  (a pull-request-only ruleset and/or a protected branch): there the reviewed
  delivery is published through the repository's REAL integration path — the
  OPEN pull request whose head branch is the delivery branch, whose base is
  the integration ref, and whose head names the certified head — squash-merged
  by the authenticated forge CLI with the certified head matched at merge time
  (`gh pr merge --squash --match-head-commit <certified head>`). The published
  ref is then read back and the landed content is proven by the SAME
  fail-closed content fact the landing and `post_merge_verify` use; the
  integration checkout is fast-forwarded onto the published head (fetch, verify
  the fetched head against the published read, `merge --ff-only`), so no later
  step of the run reads a stale local view. Nothing local moves before the
  forge reports the landing, and a delivery the forge has not published as a
  pull request refuses `refusal.publish.pull_request_missing` without
  publishing anything. A route is DECLARED, never inferred from a refused
  push: a silent fallback would hide the refusal and violate the plan-policy
  discipline (issue #196). `pull_request` lands the forge's SQUASH merge and
  therefore refuses a plan that declares `merge_policy:"ff"`
  (`refusal.policy.publish`). The outcome records `publish_route` alongside the
  heads above — identical in shape for both routes.
- The publish path COMPUTES the hosted CI conclusion for the EXACT certified
  head before either route publishes anything (issue #225). The step reads the
  forge's own workflow runs carrying that exact commit (`gh run list --commit
  <certified head> --json databaseId,workflowName,status,conclusion` — the head
  the recorded verdict names, never the branch tip) and holds while any run is
  still `queued`/`in_progress`, on a documented poll cadence
  (`HOSTED_CI_POLL_INTERVAL_SECS`) bounded by the step's own effective deadline
  (`deadline_secs`, else the per-kind default). A run that concluded red
  (`failure`, `cancelled`, `timed_out`, `startup_failure`, `action_required`)
  refuses typed with its own code (`effect.merge.ci_red`) naming the workflow
  run, the JOB and the STEP that failed, so the durable outcome is readable
  without a second lookup; a bounded wait that expires with a run still
  running refuses typed (`effect.merge.ci_pending`) — a still-running check is
  never treated as green. Nothing is published on either refusal. CI status is
  COMPUTED, not adjudicated: a recorded review-evidence check (including one
  that explains a failing CI job) may explain a state, but it never overrides
  this computation, and the conclusion is read for the certified sha, so a
  moved head can never inherit another commit's green. An unreadable forge
  read is its own typed refusal rather than an absent check, and a commit the
  forge reports no workflow runs for has no hosted check to conclude on. The
  gate is route-independent: both `push` and `pull_request` publish through it.
- A publish that did not happen is never one opaque code (issue #219). The
  remote REJECTING the update (repository rules, a protected ref) records
  `effect.merge.push_rejected`; a credential that cannot be read records
  `refusal.credential.missing`; a ref that moved under the landing records
  `effect.merge.not_fast_forward`; a forge that refused the merge, or a
  published ref that does not carry the reviewed content, records
  `effect.merge.publish_rejected`; a delivery with no open pull request
  records `refusal.publish.pull_request_missing`; a production-branch landing
  refusal keeps `refusal.policy.push`. Only a genuinely unclassifiable local
  failure keeps `effect.merge.failed`. Every one of them keeps the underlying
  diagnostics in its message, and the daemon records that code + message in the
  durable outcome, where the run's own read-backs surface it (see
  [the daemon contract](spec-daemon.md)).

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
  expired grant refuses with `refusal.grant.expired` — after the run's OWN
  lapsed window has had its chance to renew itself, see
  [spec-daemon.md](spec-daemon.md) and issue #184), the observed issue
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
  - `prompt`, `collect_outcome` and `review_evidence` 1800 s (the review
    step's own documented row, `REVIEW_DEADLINE_DEFAULT_SECS`: a reviewer's
    verdict round trip is a worker-turn-class wait and never the generic I/O
    default — issue #217), `cleanup` 1800 s (`CLEANUP_DEADLINE_DEFAULT_SECS`:
    the step's bounded wait for a lane that outlived its own publish IS the
    worker's round trip, so the generic 60 s row would park a run whose
    publish already succeeded — issue #224), `harness_start` 300 s, every
    other kind 60 s (`EFFECT_DEADLINE_DEFAULT_SECS`), and the hard ceiling is
    3600 s (`EFFECT_DEADLINE_CEILING_SECS`);
  - for a pane `collect_outcome` the effective deadline is the wait's
    NO-PROGRESS WINDOW, not a wall: the wait extends past it while the lane
    records progress and is bounded above by its own kind ceiling
    (`mutation::COLLECT_CEILING_SECS`, 6 h) — normative detail in
    [spec-daemon.md](spec-daemon.md) ("The wait is bounded by RECORDED
    PROGRESS");
  - a reviewed plan step may declare its own `deadline_secs` (policy, bound
    by the plan digest); a value outside `1..=ceiling` — or a non-integer —
    refuses `refusal.request.malformed` (`effect_deadline_secs` validates
    the override; `refusal.plan.malformed` is bind-time only) before the
    effect runs;
  - one review step's verdict wait is the ONE wait a re-dispatch may RENEW
    (issue #217): an attempt that resumes this step's own proven delivery
    (issue #214 — the reviewer leg is up and already carries the brief) waits
    under the overall ceiling (`EFFECT_DEADLINE_CEILING_SECS`) instead of
    re-opening the fresh window a live review has already outrun, while a
    reviewed plan that declared its own `deadline_secs` keeps its policy
    either way (`review_verdict_wait_secs`; the resumed wait never leaves the
    documented ceiling, and no retry budget is widened by it);
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
    pane registered for the leg's OWN lane checkout (`worktree open --cwd … --path …`), the
    prompt is delivered through `herdr agent prompt`, and observation/
    interruption/terminal outcome are collected through the `herdr agent`
    rows (see [spec-capabilities.md](spec-capabilities.md), "Execution
    substrates"). The bind step resolves that path from the reviewed plan —
    the leg's lane checkout, derived from `(issue, role, round)` (issue #210;
    the reviewer leg binds `issues-<N>-rev<R>`, never the implementer lane's
    checkout) — and a plan that does not bind the leg's own lane refuses typed
    on this substrate and names the explicit fallback instead of creating a
    pane at a bare cwd or in a sibling leg's lane;
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
