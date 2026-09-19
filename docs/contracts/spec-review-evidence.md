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
3. the reviewer is started through the SAME role-bound adapter the rest of the
   spine uses (`Start`, then the bounded review brief as `Prompt`), in the
   run's lane, under the registry-resolved binding, with the reviewer lane
   identity (`rev-<issue>-r<round>`) the adapter verifies back;
4. the reviewed work is FENCED for the whole review window (issue #207): the
   lane checkout was at the certified head when the reviewer started (item 2),
   and it is read AGAIN after the reviewer's verdict arrives and before
   anything is recorded. A checkout that moved while the review was open
   refuses `refusal.evidence.verdict_stale` (naming both heads and the
   re-entry requirement) exactly like the start-side check: a commit that
   lands mid-review forces re-entry into review, instead of the verdict being
   recorded for a delivery that moved under it;
5. the engine then consumes the verdict the REVIEWER writes — as one
   `hf-evidence/v1` object at the daemon-owned verdict path named in the brief
   (`<state>/reviews/<lane session>-<step id>.json`), outside every lane
   worktree. Nothing is synthesised: a missing artifact at the deadline is
   `effect.review_timeout` (ambiguous, parked), and the engine only ever READS
   that path.

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
