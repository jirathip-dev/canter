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
   or foreign holder is never adopted (its refusal stands). Once the verdict
   is consumed the lane is removed (`reviewer_lane_cleanup`; a refused removal
   is recorded verbatim and the residue stays reclaimable). The bare-subprocess
   fallback has no lane registration and keeps the run's lane checkout as its
   anchor, unchanged;
4. the reviewer is started through the SAME role-bound adapter the rest of the
   spine uses (`Start`, then the bounded review brief as `Prompt`), in its own
   lane checkout, under the registry-resolved binding, with the reviewer lane
   identity (`rev-<issue>-r<round>`) the adapter verifies back;
5. the engine then consumes the verdict the REVIEWER writes — as one
   `hf-evidence/v1` object at the daemon-owned verdict path named in the brief
   (`<state>/reviews/<lane session>-<step id>.json`), outside every lane
   worktree. Nothing is synthesised: a missing artifact at the deadline is
   `effect.review_timeout` (ambiguous, parked), and the engine only ever READS
   that path.

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
delivery is never repeated: the attempt resumes the bounded verdict wait. The
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
