# Intake contract (issue #245)

`canter queue intake` turns the repository's own issue state into ONE
bound-input submission. The decision is a rule, never judgement: no model, no
agent, no third-party service — only the repository's own API surface, the
remote's own integration head, and the recorded state store.

## Label contract (which work is ready)

- An issue is **ready** when it is **open** and carries the configured ready
  label. The default ready label is `canter:ready` (`--label` overrides it for
  one invocation).
- **Decision (issue #258): the compiled-in default stays `canter:ready`, and a
  repository whose own tracker convention differs points `--label` at it.**
  The default is a product-level name that no repository has to adopt; baking
  one repository's convention in would make every other repository's default
  wrong, and the override is one flag on the invocation that already carries
  the repository. The first live use measured the exception the other way
  round: a repository labelling its ready issues `ready-to-work` selected
  nothing until `--label ready-to-work` was presented — the flag is the
  contract, and the label in force is always reported (`label` in `--json`).
- A **closed** issue is never selected. An **unlabelled** issue is never
  selected. A **pull request** is never selected (the issues surface carries
  both and intake excludes anything carrying `pull_request`).
- Intake never invents work: it selects exactly the open, ready-labelled set
  it read.

## Ordering rule

- The selection is ordered by **ascending issue number** (duplicates collapse
  to one entry). One unchanged issue set therefore always renders one
  unchanged document, and the ordering is reviewable rather than implicit.

## Revision resolution rule

- Default: the repository's **integration head at intake time**, read from the
  remote with `git ls-remote origin refs/heads/<integration>` — never from a
  stale local remote-tracking ref.
- A tracker that declares a revision for an issue **wins** over the default
  (`--pin N=HEX40`).
- A revision that cannot be resolved (`git` unavailable, a pin that is not
  40 lowercase hex) **refuses typed** (`refusal.intake.revision`) and submits
  **nothing**: a partial document is never submitted silently.

## Bounds (the declared caps)

- One invocation carries at most `--max-items` (default 8) selected items.
  Items beyond the declared bound **wait** with the typed reason
  `intake.cap`; intake never widens the selection to bypass admission.
- Admission itself is untouched: an admitted item is still admitted by the
  existing admission path under the presented `--caps GLOBAL/REPOSITORY/HARNESS`.

## Dedupe before submit

- An issue that is already **owned or queued** (a live row in the recorded
  ownership set for this repository) is **not re-submitted**; it is reported
  with the typed reason `intake.owned`.
- The engine's `refusal.admission.*` codes remain a backstop, never the
  mechanism.

## Digest discipline and determinism

- The decision digest is sha256 over the canonical selected document
  (repository identity + ordered `(issue, revision)` pairs). No clock, no
  epoch and no model ride the decision, so **two invocations over unchanged
  state produce the same digest**.
- The rendered bound-input document, the per-item grants and the submission
  itself are the SAME surfaces the operator path uses (`queue preview` →
  `grant issue` per item → `queue submit`) with the same digest confirmation.
  Intake adds a rule, never a shortcut around the authorization point.

## Dry run

- `--dry-run` prints the exact decision (selected issues, revisions, the
  ready label, the ordering rule, the item bound, the digest and each item's
  selected/owned/waiting status) and **mutates nothing**: no submission, no
  grants, no run records, no journal entries and no written document.
- Without `--dry-run`, `--out FILE` is required and names where the rendered
  bound-input document goes.

## Observability

- `--json` carries the same facts as one document (`hf-intake/v1`): the
  repository, the ready label, the ordering rule, the item bound, the digest,
  the selected set and each item's status — so the whole decision is auditable
  from one output.
- A refused read names its **cause**, not the payload (issue #258): the
  refusal carries the recorded status, the program and the exact argv, and the
  first non-empty stderr line (`gh api … exited with code 4; first stderr line:
  gh: …`). A refusal that quotes captured stdout cannot be told from a success.
- Every external read is drained while the child runs (issue #258): a payload
  larger than one pipe buffer is read in full rather than deadlocking the child
  until the deadline kills a complete result. The first live use measured this
  at 246 KB of issue JSON against a 64 KB pipe — a bounded read is a read that
  completes, not a read that waits for the writer to stop.

## Closed refusal vocabulary

| Code | Meaning |
| --- | --- |
| `refusal.intake.issues` | the issue surface could not be read (gh unavailable/failed/unparsable) |
| `refusal.intake.integration` | the integration head could not be resolved from the remote |
| `refusal.intake.revision` | an issue's revision could not be resolved — nothing is submitted |
| `refusal.intake.empty` | nothing is selectable (every ready issue is owned, capped or absent) |
| `intake.owned` | an item is already owned or queued (waiting, not selected) |
| `intake.cap` | an item is beyond the declared item bound (waiting, not selected) |
