# Spec: the ORCH + CANTER contract and the read-only escalation surface (issue #208)

Refs #208 (owner architecture decision: the target is **ORCH + CANTER**, not
canter-alone) and umbrella #1 (locked spec). Family: `hf-escalation/v1`,
fixtures under
[`escalation/`](../../schemas/fixtures/escalation/escalation.valid.json),
validated by
[`scripts/check-contract-fixtures.py`](../../scripts/check-contract-fixtures.py)
and its self-test ([Fixture map](#fixture-map)). **Design commitment.**

> **Status at this revision: the surface is NOT implemented.** This document
> fixes the contract and its machine-checked schema; §8 names exactly what
> remains. Nothing below may be presented as shipped until its own witness
> exists, and no part of this document authorizes bypassing the typed surface
> it describes.

The contract is stated against the surfaces that **ship at this revision**.
Where the contract needs something the shipped surface lacks, it is named as
a **surface gap with its proposed typed operation** (§7) — never as a licence
to bypass the surface.

## 1. The contract (the owner's five requirements)

### 1.1 Canter owns execution and state (single writer)

Canter owns dispatch, step order, admission, grants, ownership, evidence,
bounded retry, renewal, publish and cleanup, and it is **the only writer of
run state**. This is the shipped architecture: the per-user daemon is the
single-writer state store (flock + migrated SQLite, audit/event journals,
one Unix socket) and the only mutation path is the grant-gated daemon `apply`
RPC ([ARCHITECTURE.md](../ARCHITECTURE.md) "Current scaffold";
[spec-daemon.md](spec-daemon.md); [spec-state.md](spec-state.md)).

No other component — orchestrator, model, or operator shell — writes run
state directly, and no component is handed a way around the daemon's gates
(admission, grant, epoch, ownership, topology, journal, idempotency). A
control the daemon refuses is a **refusal**, never advice to be worked
around.

### 1.2 The orch owns decisions and acts ONLY through the typed operations

The orchestrator owns **scope, routing a new issue, defect triage, escalation
judgement, and cross-repo calls**. It acts **only** through canter's typed
operations, enumerated in §2. Explicitly **forbidden and out of contract**:

- free-form pane poking (reading or writing pane text to steer a run);
- ad-hoc `herdr-spawn` of lane work outside the run's committed spine;
- `gh` merges for canter queues (or any other untyped path that moves the
  work the typed surface drives).

Lane work still happens — that is what the typed surface drives — but the
orchestrator's **control** of it is typed, not textual. Reads are typed too:
the read-only operations in §2 never mutate, and a read that returned
something the orch must act on is answered by a typed control (§3.3).

### 1.3 No polling: canter emits escalations

Canter exposes a first-class, **read-only** surface listing the decisions
that need a human or the orch (§3). The orch is **woken by a signal** — the
escalation surface itself, or a runner that watches it — instead of polling
panes, CI and `supervision status`. The accounting of what that removes is
§6.

### 1.4 Robustness: an absent or idle orch never blocks deterministic work

A run whose escalation is unanswered **parks in a named, honest state
carrying the refusal code** and **resumes when the escalation is answered**
by a typed operation (§4, §5). Nothing deterministic waits on a model: if no
decision is required, the spine keeps moving; if one is, the run stops in a
state that says exactly what is missing — never in a state that implies work
is still in flight, and never spinning. The shipped parking rules this
contract inherits unchanged are in §5.

### 1.5 The flexibility test

The orch must still be able to **change scope, file issues, request extra
verification, and route defects** — through the typed surface, without
bypassing it:

| The orch's action | Through the typed surface |
| --- | --- |
| Change scope | `queue preview` renders the new scope; `queue submit` commits it as a new digest-bound submission; a superseded run that can never progress is freed with `run release` first (a released issue can be submitted again on its own merits — issue #146) |
| File issues / cross-repo calls | The orch's own decisions, taken with `gh` and recorded in its own process; when they must affect a canter queue they enter through `queue submit` (never a merge or a poke) |
| Request extra verification | The run's `review_evidence` step is dispatched with `run dispatch` (its committed params declare which shape of the step it is: presented facts, or the run's own reviewer leg — [spec-review-evidence.md](spec-review-evidence.md)); additional verification beyond one run is a new submission whose caps and params carry the reviewer leg |
| Route defects | Repair a diagnosed step with `run retry` (authorize) + `run dispatch` (corrected dispatch); record an operator-attributed artifact with `run resolve`; route new work with `queue submit`; abandon with `run release` |

If a needed action has **no** typed operation, that is a **gap in the
surface** (§7 — fix the surface), not a licence to bypass it.

## 2. The typed operation surface (existing — reuse, do not invent)

Every canter-affecting orchestrator action is one of these operations. They
ship at this revision with their own contracts; this document does not
re-specify them, it binds the orch to them.

| Family | Operations | Kind | Scope |
| --- | --- | --- | --- |
| `queue` | `preview`, `submit`, `status` | preview/status read-only; `submit` records one digest-bound submission | one reviewed submission |
| `run` | `pause`, `resume`, `retry`, `release`, `resolve`, `dispatch`, `status` | `status` read-only; the rest are typed controls | exactly ONE run (`run-` + 16 hex) |
| `grant` | `issue` | mint ONE route grant from a reviewed bound-input document (issuance is not authorization) | one repository/phase/scope |
| `lane` | `preview`, `request`, `status` | `preview`/`status` read-only; `request` records ONE durable request (no spawn/kill/Git/grant/resume) | exactly ONE lane |
| `supervision` | `status` | read-only | exactly ONE run |

Rules that hold for the whole list:

- Controls are **run-scoped or lane-scoped only**; there is deliberately no
  fleet-level control, and nothing kills a process, cleans up work, mutates
  a repository or bypasses a gate.
- A control that records a decision is **journaled** (audit record before
  effect) and **idempotency-keyed** where it mutates, so a replay returns the
  recorded response instead of acting twice.
- Refusals are **typed** (`refusal.*`, `state.*`, `usage.*`), never silent.
- `--json` writes exactly one `hf-output/v1` document
  ([spec-cli.md](spec-cli.md)).

## 3. The escalation surface

### 3.1 The surface and the envelope

```
canter escalations [--cursor CURSOR] [--json]
```

A **read-only** command: it lists the open escalations and nothing else. In
`--json` mode it writes exactly one `hf-output/v1` document whose `data` is
one `hf-escalation/v1` page (§3.2). Human output renders the same data; it
is never a second, contradicting contract. Exit codes follow
[spec-cli.md](spec-cli.md): 0 ok, 1 daemon/transport, 2 usage, 4 refusal,
5 config.

### 3.2 The page document and the stable schema

One read returns one **bounded page** (`hf-escalation/v1`):

```json
{"schema":"hf-escalation/v1",
 "escalations":[
   {"id":"esc_0f0e1d2c3b4a5968","raised_at":"2026-09-06T00:00:05Z",
    "run":"run-0123456789abcdef","issue":12,"step":"p6-12",
    "state":"needs-attention","code":"refusal.delivery.moved",
    "message":"<the engine's own message, verbatim>",
    "bound_heads":{"certified":"<40hex>","published":"<40hex|null>","reviewed":"<40hex|null>"},
    "needs":"orch",
    "context":{"attempts":3,"run_retries_consumed":0,"last_progress_at":"2026-09-06T00:00:05Z"},
    "answerable_by":["run.retry","run.release","escalation.ack"]}],
 "cursor":null}
```

Field rules (closed sets refuse unknown values; every field is required):

| Field | Rule |
| --- | --- |
| `id` | `esc_` + 16 lowercase hex. Content-derived and stable across reads and restarts (the implementation slice pins the exact derivation; the schema pins the shape) |
| `raised_at` | RFC3339 UTC seconds + `Z`: when the parked condition was recorded |
| `run` | `run-` + 16 hex — the durable run identity (never a branch, issue or lane name) |
| `issue` | non-negative integer |
| `step` | the plan's own frontier step id (`p5-12`, `p6-12`) |
| `state` | closed set: `needs-attention`, `worker-timeout` — the run's recorded state at the park (`waiting-approval` is never a park state; issue #202) |
| `code` | closed set (§4): the engine's own recorded code, carried **verbatim** |
| `message` | recorded text: the engine's own message, redacted at the write boundary; the validator refuses an unredacted secret-shaped run |
| `bound_heads` | object with exactly `certified`, `published`, `reviewed`: each null or a 40-hex commit. `certified` is the run's certified delivery head, `published` the integration ref the park is about, `reviewed` the head a recorded verdict names |
| `needs` | closed set: `orch`, `human` — who the decision belongs to |
| `context.attempts` | non-negative integer: recorded attempts for the step |
| `context.run_retries_consumed` | non-negative integer: bounded retries the run has consumed (an honest park never consumes one) |
| `context.last_progress_at` | RFC3339 UTC or null |
| `answerable_by` | non-empty, duplicate-free list of typed operation names from the closed vocabulary `run.pause`, `run.resume`, `run.retry`, `run.resolve`, `run.release`, `run.dispatch`, `queue.submit`, `grant.issue`, `escalation.ack` |
| `cursor` | null, or the ordering key `<raised_at>|<esc id>` of the page's last row. Rows are in strictly increasing `(raised_at, id)` order; a cursor exists exactly while more rows remain |

Nothing in a record is inferred or invented: the run, step, state, code and
message are **recorded facts**, the heads are the heads the park is actually
about, and `needs`/`answerable_by` are the contract's mapping of the code
(§4), not a heuristic.

### 3.3 Response rules (normative)

1. **Listing is read-only.** Reading never mutates anything: not run state,
   not the journals, not the audit, not the escalations themselves. Any
   number of reads return the same projection; a read is never an event.
2. **Answering is a typed operation** listed in `answerable_by` (one of §2's
   controls, or `escalation.ack`, §7). There is no free-form answer channel:
   no pane text, no ad-hoc spawn, no `gh` merge.
3. **Answers are recorded and auditable**: who answered, with which
   operation, when, and against which escalation identity. The record is
   journaled like every other control, and the answering invocation names the
   escalation it answers; an answer that cannot be recorded does not happen.
4. **Reading never mutates** — restated because it is the property acceptance
   witnesses must prove: state counts (epoch, journal sequence, table
   contents) are unchanged across any number of reads.
5. **An unanswered escalation never blocks deterministic work**: the run
   stays parked in the named state bearing the code until the answer lands,
   and nothing else waits on it.

### 3.4 Stable-schema rule

Field names, the closed `code` set, and the `answerable_by` operation names
are part of the contract: **additive changes only, never repurposed**. A new
park code is a new row; renaming or re-meaning an existing code is a breaking
change and requires a new schema version. Unknown keys and values outside the
closed sets are refused (the fixture corpus pins this:
`escalation.malformed.json` is a page carrying a code outside the set).

## 4. The closed code set and the answering map (v1)

Each code is an existing engine code (`src/mutation.rs` `code` module) whose
documented semantics park a run or leave it needing a decision. `needs`
separates a decision the orch can record through the typed controls from one
that requires authority outside the run's committed boundary.

| `code` | The parked condition (shipped semantics) | `state` | `needs` | `answerable_by` (v1) |
| --- | --- | --- | --- | --- |
| `refusal.delivery.moved` | The delivery branch moved past the head its recorded verdict names; no step may consume it — the delivery must re-enter review and a new verdict must name the moved head (#202) | `needs-attention` | `orch` | `run.retry`, `run.release`, `escalation.ack` |
| `refusal.delivery.unbound` | A consuming step was asked to consume a head the run's own collection never certified (#202) | `needs-attention` | `orch` | `run.retry`, `run.dispatch`, `run.release`, `escalation.ack` |
| `refusal.evidence.verdict_stale` | The reviewer leg's lane worktree is not at the run's certified head, or the written verdict names another sha — a deterministic, impossible step (#193, #200) | `needs-attention` | `orch` | `run.retry`, `run.release`, `escalation.ack` |
| `refusal.evidence.verdict_pending` | The written verdict carries a `pending` check, which would permanently strand the tail (#193) | `needs-attention` | `orch` | `run.retry`, `run.release`, `escalation.ack` |
| `refusal.evidence.verdict_missing` | The reviewer wrote no verdict artifact within the bounded wait (#193) | `needs-attention` | `orch` | `run.retry`, `run.dispatch`, `run.release`, `escalation.ack` |
| `effect.review_timeout` | The bounded wait for the reviewer's own written verdict expired (#193); ambiguous, parked — the two reviewer-wait shapes are recorded distinctly and neither is retried silently | `needs-attention` | `orch` | `run.retry`, `run.dispatch`, `run.release`, `escalation.ack` |
| `refusal.collect.empty_delta` | A delta-required collection found no committed content change (#200, #202); repeated across re-dispatches it is the stalled-frontier case | `needs-attention` | `orch` | `run.retry`, `run.dispatch`, `run.release`, `escalation.ack` |
| `refusal.collect.unbound` | A collection could not bind the delivery head it observed (#202) | `needs-attention` | `orch` | `run.retry`, `run.dispatch`, `run.release`, `escalation.ack` |
| `effect.worker_timeout` | The pane worker did not settle within the collection deadline (#200): the step parks typed and needs an operator retry | `worker-timeout` | `orch` | `run.retry`, `run.pause`, `run.release`, `escalation.ack` |
| `refusal.run.retry_required` | A re-dispatch of a diagnosed failed step needs (and consumes) one recorded bounded retry authorization (#86) | `needs-attention` | `orch` | `run.retry`, `run.dispatch`, `escalation.ack` |
| `refusal.lane.name_collision` | The issue's lane identity is still held by another generation (#190 residue class); a live or foreign holder still refuses | `needs-attention` | `orch` | `run.pause`, `run.release`, `escalation.ack` |
| `refusal.grant.expired` | The run's grant window expired before the step could be dispatched (#146); continuing needs a freshly minted window | `needs-attention` | `human` | `grant.issue`, `run.release`, `escalation.ack` |

Rules for the table:

- Every listed operation answers **that** condition; a surface must not
  advertise an operation it cannot answer with (see `escalation.ack`, §7).
- Reviewing a v1 park must never consume a bounded retry by being read: an
  honest park records its unspent retries in
  `context.run_retries_consumed` (0).
- `run.resolve` is in the answer vocabulary for prompt-shaped parks (it
  records an operator-attributed artifact for ONE diagnosed prompt); no v1
  row uses it because a routine prompt diagnosis sits outside the v1
  boundary below.
- **Boundary (disclosed):** a *routine* diagnosed step failure whose only need
  is the run's own declared bounded-retry path (for example an ordinary
  non-zero exit on a prompt step) is reported by `supervision status` today
  and is **not** a v1 escalation row. Closing that boundary is part of §8:
  the implementation slice must either prove that boundary with a witness, or
  extend this set additively (which is exactly what additive-only permits).

## 5. Robustness already shipped (non-weakening)

The contract adds a surface; it weakens nothing. These shipped rules are
inputs the escalation surface must **read**, never recompute or soften:

- **Single writer, journaled controls, idempotency keys** — §1.1, and the
  daemon's audit-before-effect rule ([spec-state.md](spec-state.md)).
- **Bounded retry is an authorization, not an action** (#86): `run retry`
  authorizes one bounded re-dispatch of one diagnosed step; the corrected
  `run dispatch` consumes it exactly once. Nothing dispatches itself.
- **Settled-turn certification and the impossible-step park** (#200): a
  delivery is certified only at a confirmed settled pane turn; a recorded
  deterministic refusal at a review frontier (e.g.
  `refusal.evidence.verdict_stale`) parks typed with the bounded retries
  **unspent** rather than retrying an impossible step.
- **Certified-head binding and the delivery freeze** (#202): a step consumes
  only the head the run's own collection certified, and `merge` freezes the
  delivery at the head its recorded verdict names. These parks refuse as
  `refusal.delivery.unbound` / `refusal.delivery.moved` and **never present
  as `waiting-approval`**.
- **Host-proof renewal and admission** stay in the path (#198): a dispatch
  carries a live host proof; the escalation surface cannot mint one.
- **No model decides what the daemon can verify** (#95, the supervision
  statement): the driver dispatches only recorded, gate-cleared steps; a
  refusal is reported with the engine's own code and is never presented as an
  eligible next step.

Acceptance criterion 5 of #208 ("non-weakening") is therefore a property of
the surfaces above, and the implementation slice must re-run their witnesses
unchanged (not re-derive them).

## 6. Token accounting (the note the owner asked for)

**What the polling loop costs per tick (before).** For each live run the
orchestrator must find out whether anything needs it, so a tick costs, per
run: one `supervision status` invocation — a daemon round-trip plus a full
`hf-supervision/v1` document (policy, evaluation, attempts, retries, steps,
continuation report) — and, in the fleet's own loop, pane reads and CI reads
on top. Every one of those documents is read by a model that most ticks
decides **nothing**, because nothing is wrong.

**What replaces it (after).** One signal-driven read of a bounded listing:
`canter escalations --json` returns **O(open escalations)** rows — normally
zero — and each open row carries the run, the step, the recorded code, the
heads, who must answer, and the typed operations that can answer. The orch
answers each item with one typed control (commonly `run retry` then
`run dispatch`) and goes back to waiting for the next signal.

**The structural account (design commitment).**

- Per tick: `O(live runs)` document reads collapse to **one bounded page
  read**; the steady state (nothing parked) is one read that returns an empty
  page — zero pane sweeps, zero CI scrapes, zero `supervision status`
  round-trips.
- Per decision: one listing row + one typed answer, instead of a poll cycle
  that discovers the condition late and re-reads everything around it.
- Reads are projections: reading never mutates, so a watcher may read as
  often as it likes without perturbing state or writing audit rows.
- [awaiting-evidence]: the fleet's measured before/after numbers (documents
  per tick, tokens per tick, decision latency) do not exist at this revision;
  the slice that implements the surface (§8) produces them. This document
  asserts the structure, not the numbers.
- [awaiting-evidence]: the saving is complete only once the escalation set
  covers every condition the fleet polls for today (see the §4 boundary).

## 7. Surface gaps (with proposed typed operations)

- **`escalation.ack`** — the one answer operation with no shipped
  implementation. It records that an escalation was seen and is being handled
  (who, when), as a journaled, idempotency-keyed no-op on run state: it
  **never** clears a park, never mutates run state, and never removes a
  condition from the listing while the park remains. Proposed spelling:
  `canter escalations ack --escalation esc_<16hex> --reason TEXT
  [--idempotency-key IK] [--json]`. Until it ships, a listing must not
  advertise it (§4 rule; the fixture corpus names it because it is part of
  the contract's answer vocabulary).
- **The answer binding** — the recorded/auditable rule (§3.3) requires the
  answering invocation to carry the escalation identity it answers. Proposed:
  an optional `--escalation esc_<16hex>` on the answering controls; the exact
  flag spelling is the implementation slice's to pin, the binding is not.
- No other gap was found: each of §1.5's four orchestrator actions maps to
  existing typed operations (§1.5, §4), so the surface needs no new control
  besides `escalation.ack`.

## 8. What remains (the implementation slice — not done here)

The surface above is a contract; a half-built surface that mutated on read
would be worse than none, so this lane stops at the contract and its
machine-checked schema. The bounded work list:

1. **Emission.** A bounded read that projects parked runs from durable state
   onto the schema: per non-terminal run, the recorded frontier class +
   code (the pieces exist — `src/supervision.rs` classifies recorded
   evidence into the closed class vocabulary, and the attempt/refusal rows
   carry the engine's own codes). No new writes are needed to read them.
2. **Stable identity.** `esc_` + the first 16 hex of a domain-separated hash
   over the identifying facts (run, step, code), deterministic across reads
   and restarts — the `wi_` construction ([spec-board.md](spec-board.md)).
3. **The command.** `canter escalations` as a read-only command with the
   `--json` envelope, cursor pagination, and the exit codes of
   [spec-cli.md](spec-cli.md); added to that spec's command list.
4. **The answer binding and `escalation.ack`** (§7), including the typed
   refusals for an unknown/already-answered escalation and the journaled
   answer record.
5. **The read-only witness + RED mutation.** A witness showing state
   counts (epoch, journal sequence, table contents) unchanged across a read,
   with a mutation of the read path that makes the witness fail — the exact
   evidence the brief's optional clause reserved, and the first thing a
   reviewer should demand.
6. **Classification boundary.** Resolve the §4 boundary with a witness:
   which diagnosed non-successes are routine repairs and which are escalation
   rows; extend the closed set additively if needed.
7. **The measured before/after numbers** of §6 in the fleet's own terms.
8. **Tests + gate wiring.** The witness suite enumerated in the
   `rust-ubuntu-suite` matrix, and the fixture family already wired into the
   contract probe (the corpus ships with this document).

## 9. Non-goals

No new orchestration engine; no model in the control path; no change to the
p1..p8 spine's semantics; no agent-framework rewrite; no fleet-level control;
no new write path; the surface never dispatches, resumes, retries, releases
or resolves anything by itself — it lists, and a typed operation answers.

## Fixture map

Accept: `escalation.valid.json` (a complete page: a moved-head refusal, a
worker timeout, an expired-grant window — closed codes, closed `needs`, typed
answers), `escalation.page.valid.json` (a bounded first page whose cursor is
the ordering key of its last row).
Refuse: `escalation.malformed.json` (a code outside the closed set — unknown
keys, `waiting-approval`, empty or untyped `answerable_by`, malformed heads,
unredacted text, wrong order, and a cursor that names no row are refused by
the family validator and proven to bite by
[`scripts/test-check-contract-fixtures.py`](../../scripts/test-check-contract-fixtures.py)),
`escalation.unknown-version.json` (unsupported version).
