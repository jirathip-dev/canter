# Spec: review evidence contract (AC4)

Refs #3 (AC4: review evidence binds feature head SHA, current
integration-base SHA, workflow hash, and policy hash; any relevant change
invalidates it). Family: `hf-evidence/v1`. Fixtures:
[`evidence/`](../../schemas/fixtures/evidence/evidence.valid.json). Design commitment (locked
spec: "Integration merge requires a distinct exact-head reviewer and hosted
checks bound to feature SHA, current integration-base SHA, workflow hash,
and policy hash").

## Record: `hf-evidence/v1`

```json
{"schema":"hf-evidence/v1","evidence_id":"ev_0123456789abcdef",
 "feature_head":"<40hex>","integration_base":"<40hex>",
 "workflow_hash":"<64hex>","policy_hash":"<64hex>","verdict":"pass",
 "checks":[{"name":"hosted-ci","status":"passed"},
           {"name":"exact-head-review","status":"passed"}],
 "created_at":"2026-09-06T00:00:00Z"}
```

Normative rules:

- All four bindings are required 40/64-hex fields: `feature_head` (the
  reviewed feature branch head), `integration_base` (the exact
  integration-base SHA the review was performed against — re-basing the
  feature or advancing the base changes this field), `workflow_hash`, and
  `policy_hash`.
- `verdict` closed set: `pass` | `fail`.
- `checks` is a non-empty list of named checks with closed statuses
  `passed` | `failed` | `pending`. A check with an unknown status is
  refused (`evidence.malformed.json` uses `running`).
- A `pass` verdict is only meaningful while every binding still matches the
  live state: **any relevant change invalidates the evidence**. Relevant =
  feature head moved, integration base advanced/changed, workflow document
  hash changed, or policy hash changed (config/overlay changed). The daemon
  re-checks all four before an integration merge; stale evidence is refused
  like any other stale state (exit class 4, [spec-cli.md](spec-cli.md)).
- `feature_head` and `integration_base` must be exact 40-hex SHAs — no
  branch names, no abbreviated refs, no "current tip" indirection.

## Review procedure contract (locked spec, for child #8)

- The reviewer is a **distinct exact-head reviewer**: a different reviewer
  role/identity than the implementer, evaluating the exact committed head
  recorded in the evidence.
- Hosted CI checks must run against the recorded feature head (never a
  moved head); CI status is one of the named checks.
- Evidence records are durable (journaled) so the merge decision is
  auditable after the fact; a merge without a valid, current evidence
  record is refused.
- Storage (issue #8): the daemon keeps durable evidence rows and recorded
  first-real-write approval rows in its SQLite state (migration m0003,
  schema v3). A `review_evidence` apply writes the row under the state
  lock before the idempotency claim resolves; the merge gate then
  revalidates every binding (feature head, integration base, workflow
  hash, policy hash, verdict, named checks) against the live refs — any
  moved binding refuses with `refusal.evidence.stale`. The row is
  invalidated when the plan's workflow/policy hash set changes; latest
  per instance, append-only history is retained.
- Reviewer procedure source (issue #267): the reviewer role contract is
  committed as a portable, installable procedure,
  [`skills/lane-reviewer/SKILL.md`](../../skills/lane-reviewer/SKILL.md). It
  states the rule the engine already enforces — a verdict is written for the
  exact **certified head** the lane was dispatched at, a head that moved under
  the review (or a verdict naming another head) is refused with
  `refusal.evidence.verdict_stale` rather than consumed, and the reviewer is
  never the implementer that produced the head. The plan declares, per leg,
  which role skill a lane is given (`docs/contracts/spec-plans.md`, "The
  queue-run plan names, per leg, the role skills"), so the procedure is
  configuration the plan digest binds — never an accident of profile
  contents.

## Fixture map

Accept: `evidence.valid.json` (all four bindings + two passed checks).
Refuse: unknown check status, unknown version.

## Self-dispatching review step (issue #193)

A `review_evidence` step (p6) has two shapes, and its OWN committed params
declare which one:

- **presented facts** (`reviewer`, `implementer`, `verdict`, `checks`): the
  operator's own dispatch path, unchanged — the engine records exactly what
  the step presents and runs nothing;
- **the reviewer leg** (`harness_key` + `reviewer_profile` + `worktree`, with
  the optional `lane_round` and `deadline_secs`): the run dispatches its OWN
  reviewer. `params.reviewer_profile` is the `hf-profile-binding/v1` document
  the **fleet registry** resolved for that role key (`canter queue preview
  --reviewer-harness KEY` resolves the configured `harness.<key>` row), so the
  reviewer's kind, provider and model are configuration — never a literal in
  the engine, and never a step-param default. A step that declares both shapes
  refuses (`refusal.request.malformed`), and a step that declares neither is
  refused exactly as before: the engine never invents a reviewer.

The leg runs, in order:

1. the run's own bound implementer session is resolved from durable state
   (a run that bound none refuses `refusal.session.unbound`); the reviewer's
   session identity is DERIVED from it (domain-separated, one per
   `lane_round`), so it is never caller-supplied and can never be the
   implementer's own session (`refusal.evidence.reviewer_not_distinct`);
2. the lane worktree the reviewed plan binds must be AT the run's certified
   `observed.feature_head`: a moved checkout refuses
   (`refusal.evidence.verdict_stale`) rather than reviewing a head nobody
   certified. That refusal is deterministic — the certificate is a recorded
   fact and the checkout's movement is external — so a re-dispatch can never
   repair it: the frontier parks typed with the run's bounded retries unspent
   (issue #200) instead of retrying an impossible step;
3. **the reviewer leg binds its OWN lane checkout (issue #210)**: on the pane
   substrate the plan binds the reviewer leg's lane — derived from
   `(issue, reviewer, lane_round)` as `issues-<N>-rev<R>` — never the
   implementer lane's checkout the run's own worker holds (that shape refused
   `refusal.lane.name_collision` at p6-132 on the live spine). The effect
   materializes that checkout at the certified head (a canter-created,
   detached, clean linked worktree), verifies an existing one (a moved or
   dirty reviewer lane refuses and is left untouched, never repaired), and
   reclaims the LEDGER-TERMINAL generations' reviewer lanes of that same
   identity first — their registrations closed, their stale checkouts cleared,
   both recorded on the step outcome (`retired_reviewer_lanes`) — while a live
   or foreign holder is never adopted (its refusal stands). This bind step
   resolves that terminal set from the run ledger exactly like the run's own
   lane bind (issue #224): the reviewer lane exists FOR the review and is left
   behind when its run completes, so an unresolvable set would leave the next
   run of the same issue refused `refusal.lane.name_collision` until an
   operator closed the old workspace by hand. Once the verdict is consumed the
   lane is removed (`reviewer_lane_cleanup`): the close is WAITED for, bounded
   by the step's own effective deadline, under the cleanup step's confirmed
   settle discipline (issue #224 — at the instant the verdict lands the
   reviewer is still `working`, so a single close retires nothing), and a
   refused removal is recorded verbatim and the residue stays reclaimable.
   The bare-subprocess fallback has no lane registration and keeps the run's
   lane checkout as its anchor, unchanged;
4. the reviewer is started through the SAME role-bound adapter the rest of the
   spine uses (`Start`, then the bounded review brief as `Prompt`), in its own
   lane checkout, under the registry-resolved binding, with the reviewer lane
   identity (`rev-<issue>-r<round>`) the adapter verifies back;
5. the reviewed work is FENCED for the whole review window (issue #207): the
   lane checkout was at the certified head when the reviewer started (item 2),
   and it is read AGAIN after the reviewer's verdict arrives and before
   anything is recorded. A checkout that moved while the review was open
   refuses `refusal.evidence.verdict_stale` (naming both heads and the
   re-entry requirement) exactly like the start-side check: a commit that
   lands mid-review forces re-entry into review, instead of the verdict being
   recorded for a delivery that moved under it;
6. the engine then consumes the verdict the REVIEWER writes — as one
   `hf-evidence/v1` object at the daemon-owned verdict path named in the brief
   (`<state>/reviews/<lane session>-<step id>.json`), outside every lane
   worktree. Nothing is synthesised: a missing artifact at the deadline is
   `effect.review_timeout` (ambiguous, parked), and the engine only ever READS
   that path. The deadline is the step's own effective bound: the plan's
   declared `deadline_secs` when it declared one, else the documented review
   row `REVIEW_DEADLINE_DEFAULT_SECS` (1800 s, the prompt tier — a verdict
   round trip is a worker-turn-class wait, issue #217; before that row the
   kind fell into the generic 60 s I/O default and every live review —
   measured verdicts take tens of minutes — was an `effect.review_timeout` by
   construction).

**Proven delivery, recorded — a re-dispatch resumes, never re-delivers
(issue #214).** The pane-substrate prompt reports success only through the
#148 discipline (the agent's own read-back shows the task arrived AND its
lifecycle moved), and a delivery PROVEN that way is recorded by the engine
beside the verdict artifact as one `hf-review-delivery/v1` document
(`<state>/reviews/<lane session>-<step id>.delivery.json`): the certified
head, the reviewer lane, the adapter-verified agent and pane, and the
submission attempt count. Every dispatch of the step addresses the SAME
derived leg (the lane identity, its checkout and the verdict path are all
derived, issue #210), so when a re-dispatch REUSES that leg's registered lane
and finds the record bound to THIS certified head and THIS reviewer lane, the
delivery is never repeated: the attempt resumes the bounded verdict wait, and
— on a plan that declared no `deadline_secs` of its own — that resumed wait is
RENEWED under the overall ceiling (`EFFECT_DEADLINE_CEILING_SECS`, 3600 s;
issue #217: the reviewer is the one doing the waiting-work by then, so the
attempt waits the maximum this effect family is ever allowed to wait instead
of re-opening the fresh 1800 s window a live review has already outrun; a
declared `deadline_secs` is the plan's own reviewed policy and is never
overridden). The
duplicate delivery is exactly what the measured chain was made of
(`run-1d4806c802c1088c`, p6-132): while the reviewer's turn was running the
substrate could not take a second submission inside the prompt's bounded
delivery window, so the re-attempts reported the PROMPTED leg as
`refusal.prompt.undelivered` while the reviewer went on to write its PASS
verdict — and the late verdict was cleared before the next prompt instead of
being consumed. In the shipped shape:

- a leg that is up but UNPROMPTED has no record and is prompted (and proven)
  as before — a start alone is never a delivery;
- a record that does not name this attempt's certified head and reviewer lane
  (a fresh lane, a reclaimed leg, a moved head) is never trusted: that attempt
  re-delivers and re-proves;
- the residue clear runs only before a delivery, so a verdict already at the
  path is consumed by the resumed wait (and validated exactly as any written
  verdict — `verdict_stale`/`verdict_malformed`/`verdict_pending` refuse it);
- a delivery record that EXISTS but cannot be read refuses
  `refusal.evidence.review_delivery` fail-closed, and a proven delivery that
  cannot be recorded refuses the same way instead of being delivered again on
  a guess;
- the bare-subprocess substrate has no asynchronous leg (its prompt IS the
  reviewer's run), so it always re-delivers and never reads a record.

The recorded step outcome names the reviewer lane, its pane, its SERVING
model (the registry-resolved binding the reviewed plan bound and the leg is
launched with — the adapter read-backs carry no model footer, so this is the
recorded resolution, never an observation) and the delivery attempt count; the
ambiguous `effect.review_timeout` outcome carries the same facts in its
message, because the durable `hf-outcome/v1` of a non-succeeded effect carries
no `result` ([spec-plans.md](spec-plans.md), "Typed outcomes"). So a stuck or
resumed review leg is diagnosable — and honourably re-driven by the run's own
bounded retries — from the recorded outcomes alone.

The written verdict must name the exact reviewed sha (`feature_head`), the
observed `integration_base` when it names one, a closed `verdict`
(`pass`|`fail`) and a non-empty `checks` list whose statuses are explicit
`passed`/`failed`. A `pending` check refuses
(`refusal.evidence.verdict_pending`): a recorded pending check permanently
strands the tail (`refusal.run.step_done` blocks amendment and
`evidence_checks_passed()` requires every check `passed`), so it is refused at
the frontier instead of being recorded. An ill-formed document refuses
(`refusal.evidence.verdict_malformed`); a document naming another sha refuses
(`refusal.evidence.verdict_stale`). The other live bindings
(`workflow_hash`/`policy_hash`) are recorded by the engine from its own live
state, so a reviewer can neither move them nor strand the tail with a stale
value.

A check recorded non-`passed` inside the evidence of a step that SUCCEEDED is
the ONE recorded state in which the tail can strand itself (issue #230): the
consumer refuses `refusal.evidence.failed` and the producer can never be
re-run (`refusal.run.step_done`), while supervision keeps reporting the
frontier from its recorded class alone. The shipped shape is RECOMPUTATION,
never adjudication:

- the `run.reevaluate` control (spec-daemon.md) re-runs the run's OWN
  `review_evidence` step — the reviewer LEG only, never a step that presents
  static review facts — at the SAME certified head, on a FRESH derived lane
  round, bounded per `(run, step)` from the durable journal and attributed
  (operator identity + reason) in the hash-chained audit BEFORE anything is
  dispatched. The control presents no check status, no verdict and no head:
  it cannot make a check pass;
- the re-run's verdict is recorded through the ordinary review path, so a
  recomputation that comes back FAILING is a new record that refuses the
  consumer with the same `refusal.evidence.failed`, and
- the consumer reads the NEWEST recorded evidence only (the merge gate and
  the crash-point read both take `ORDER BY created_at DESC LIMIT 1`), so what
  it consumes is the recomputed fact, never a result frozen at review time.
  The superseded row stays as history; nothing rewrites or deletes it.

A continuation the engine refuses is also named: the recorded refusal now
carries the engine's own message beside its code, and the supervision status
renders both (`evaluation.refusal` / the human read), so a parked run states
WHY its frontier never lands instead of reporting an idle fleet. The same
report covers the shape where NOTHING is ever dispatched — the run's own
verified-delivery consumer behind a record whose checks are not all `passed`:
the classification derives the engine's own refusal from these same recorded
facts (`supervision.delivery_unverified` + `refusal.evidence.failed`, spec-daemon.md)
rather than reporting the frontier an eligible continuation, and the dispatch
gate itself is unchanged, so the tail is still never driven behind an
unverified delivery.

The certified delivery (issue #202): a step may only ever consume the head the
run's OWN `collect_outcome` step certified. That binding is recorded and
attributed (`run_delivery_certificate`: the newest successful collection's step
id, idempotency key, branch, head and base) and is the ONLY source of the run's
`feature_head` — a `head` echoed by another effect's response (the base a
`worktree_create`/`checkout` response carries) is never a certified feature
head. A run whose collection never observed a delivery therefore binds
nothing, and a `review_evidence`/`merge` step of such a run refuses typed
(`refusal.delivery.unbound`) BEFORE a reviewer is started or a landing is
built: a head no collection of the run observed is never reviewed and never
landed. A collection that cannot name the 40-hex head (and the slug branch) it
observed is itself a typed non-success (`refusal.collect.unbound`), never a
`succeeded` outcome that bound nothing. Once a verdict IS recorded, the
delivery is frozen at the head that verdict names: see the freeze rule in
[spec-daemon.md](spec-daemon.md).

Supervision (issue #152's rule, extended): the driver dispatches a
`review_evidence` step only when the run is an admitted member of a committed,
digest-bound submission, the run's own approved caps carry `review`, and the
step's OWN committed params declare the reviewer leg. A review step that
declares no leg is untouched — it stays the operator's own dispatch and is
classified `waiting-approval` exactly as before, and no cap is widened for
either shape. The step still requires the `review` capability and phase at
effect time, the reviewer's identity is still checked distinct, and the
reviewer's dispatch passes the same fan-out admission gate (`harness_start` /
`prompt` carry it) — the same caps, host-resource proof and overlap fence.

## The FAIL handoff: the run's own fix round (issue #238)

A recorded review FAIL is a normal, expected outcome of the review step — never
a terminal, silent one. The SAME effect that consumed the failing verdict hands
it to the run's own fix round before its outcome is recorded, so a FAIL reaches
a repair leg with no operator action between the two. The handoff is stated
positively and negatively:

- the fix leg is the run's OWN implementer lane, next round (`crate::lane`:
  `impl-<N>-r<R>` / `issues-<N>-impl<R>`), resolved from the run's committed
  spine — its `harness_start`/`prompt` step supplies the reviewed role binding
  (and, for a run without a committed role configuration, the plan-declared
  key/kind), and its `worktree_create` step names the branch the instruction
  must push to. No leg is invented, no profile is defaulted, and no caller
  supplies an identity;
- the fix leg's lane CHECKOUT is created (or reused) at the certified head by
  the engine, exactly like the reviewer leg's own lane (issue #210). A checkout
  that exists but is not a clean linked worktree at the reviewed head refuses
  `refusal.fix.lane` and is left untouched — never repaired, because a fix
  round is only ever dispatched at the head whose review failed;
- the instruction is DERIVED from the recorded verdict: the certified head, the
  observed integration base and the checks the reviewer marked `failed` (a
  passing check is never quoted), plus the run's own feature branch. The engine
  records nothing on the leg's behalf, so the leg itself has to commit and push
  for the reviewed head to move;
- the delivery is PROVEN through the same role-bound adapter the rest of the
  spine uses. A spawn the substrate refused is `refusal.fix.spawn` and a prompt
  it did not take is `refusal.fix.prompt`, each carrying the substrate's own
  refusal code in the message — an undispatchable handoff is a typed refusal,
  never a silent park, and a round whose delivery was never proven is never
  counted against the bound;
- the round is BOUNDED by `mutation::FIX_ROUNDS_MAX`, the doctrine's own
  `engine::NORMAL_REVIEW_ROUNDS` (one fact, two readers). The bound is enforced
  BEFORE any effect: the next round on a head the budget cannot cover refuses
  `refusal.fix.bound_exhausted`, whose message names the failures the reviewer
  recorded and the bound it spent. An exhausted budget escalates; it never
  parks silently and never dispatches an unbounded number of repair rounds;
- the engine's OWN record (`<session>-<step>.fix-round.json`, `hf-fix-round/v1`,
  in the daemon-owned review root, beside the verdict and delivery artifacts) is
  keyed by the certified head. A re-dispatch of the SAME review attempt
  therefore REUSES the round that head was already handed to (the leg is never
  re-prompted and the bound is never burnt twice), while a MOVED head opens the
  next round of the same budget. The record also names the leg's OWN lane
  checkout (`worktree`, the lane the leg was created or verified at, issue
  #256): the head a handoff was dispatched for can never move by itself, so the
  leg's own checkout is the recorded state a classification reads to tell a
  repair leg that is still working from one that has DELIVERED — and a handoff
  that names no checkout (a record written before this slice) observes nothing
  and keeps its recorded disposition.

`supervision status` reports the handoff's recorded disposition instead of a
bare FAIL: `supervision.fix_round_dispatched` (class `waiting-workers`, detail:
the fix leg's lane) while the repair leg works — the leg's OWN checkout is read
for this, so a leg that has already delivered a descendant head is never
reported as work in flight (issue #256, `supervision.fix_round_head_moved`
below) — `supervision.fix_round_lane_lost` (class `needs-attention`, detail: the
fix leg's lane and the window that was read) when the leg has NOT delivered and
its own recorded lane checkout is GONE (issue #276), which is also `eligible:true`
because the same fact is the driver's ONE continuation — the handoff's own step
is re-dispatched by the run's own supervision (the re-dispatch a held
`run.retry` authorization pays for), and the engine's own record then hands the
FAIL to the next round of the same bound, whose lane it creates at the certified
head — `supervision.fix_round_refused`
with the fix round's OWN engine code as detail when the handoff was refused,
and `supervision.fix_rounds_exhausted` when the budget is spent. The handoff is
read from the review step's own apply row — the response document the daemon
persists (`result.fix_round`), with the `outcome` column read beside it (issue
#254) — and its `hf-fix-round/v1` validation is unchanged. `run status`
carries the same code, because the refusal IS the review step's recorded
outcome (`last_failure`). A handoff recorded at a head the run's newest
recorded review evidence does NOT name is its own fix-round disposition —
`supervision.fix_round_head_moved` (class `needs-attention`), whose detail
names the fix leg's recorded lane and both head prefixes — never a bare
`supervision.review_failed`; and the run's own bounded check re-evaluation is
driven for the recorded FAIL as well (the same control, the same per-`(run,
step)` bound, at the recorded head), so a FAIL-then-fix sequence continues
instead of parking on the FAIL. A handoff whose leg DELIVERED a descendant head
in its own lane checkout (issue #256) reports the same class and reason, with
the certified and the delivered head prefixes; the same read binds the next
review round to the delivered head, and the head a handoff was DISPATCHED for is
never mistaken for the head the leg delivered. A FAIL recorded before this
handoff existed —
or by a plan that presents its own review facts and dispatches no leg — keeps
`supervision.review_failed` with the review step named as its detail.
