# Workflow

Contributor and maintainer workflow for canter. This is the process
contract; mechanical enforcement lives in CI (`policy` job) and in
repository rulesets applied by maintainers.

## Issue-first

Durable work starts from an issue. The umbrella
[#1](https://github.com/jirathip-dev/canter/issues/1) tracks the
approved architecture and delivery graph; its children are routed one slice
at a time. In this bootstrap, `ready-to-work` is **bootstrap-process state**
recording that an issue is authorized and queued under today's external
process — it is **not** the future product's route-grant mechanism (route
grants are a locked-target concept, not yet implemented).

## Contributor flow

1. **Issue first** — comment or open an issue describing intent; never open
   a PR without one.
2. **Branch from `staging`** — feature/dependency branches cut from the
   current `staging` head: `git fetch origin && git checkout -b my-change
   origin/staging`.
3. **Commit** — small, focused commits; `Refs #N` wording (never
   `Fixes`/`Closes`/`Resolves`; issues stay open until a maintainer closes
   them).
4. **Gates** — run `just ci` locally until green, then push and open a PR
   with **base `staging`**.
5. **Review** — trusted fleet PRs are reviewed by an **independent
   exact-head agent**; its verdict is recorded as evidence. Zero formal
   GitHub approvals are required for those PRs (repository rulesets allow
   squash merges without approvals).
6. **External contributors** — a PR whose head repository differs from this
   repository is marked `EXTERNAL_CONTRIBUTOR — human maintainer approval
   required` by CI (an annotation, not a failure) and **additionally
   requires one human maintainer approval** before merge.
7. **CI** — every intended check must pass at the exact reviewed head
   (`policy`, `rust-ubuntu`, `rust-macos`, `supply-chain`, `secret-scan`).
8. **Merge** — reviewed + green PRs squash-merge into `staging`. Squash
   commits keep history linear; branch deletion follows automatically.

## Maintainer flow

### Promotion (staging → main)

`main` is the stable, default, release branch; `staging` is the permanent
integration branch.

- Promotion is a **dedicated PR from `staging` to `main`** — the only
  ordinary PR to `main` that exists. It is **human-only** and requires the
  full CI suite on `main`-targeting PRs.
- The always-present promotion-policy check fails any PR to `main` whose
  head is not `staging` (or a `hotfix/*` branch).
- Direct pushes, force/non-fast-forward updates, and branch deletion are
  forbidden on both long-lived branches by repository rulesets; only PR
  squash merges are allowed, with linear history.

> **WARNING — promotion PRs carry the integration branch as their HEAD.**
> A promotion PR's head branch *is* `staging`. GitHub's automatic
> head-branch deletion on merge (`delete_branch_on_merge`, "automatically
> delete head branches") therefore deletes the integration branch when the
> promotion PR merges. This happened after promotion PR
> [#28](https://github.com/jirathip-dev/canter/pull/28): `staging` was
> silently deleted, later landing was blocked until a maintainer recreated
> it by hand, and the repository setting is now off. The setting must stay
> **off** while promotion PRs exist.
>
> After **any** promotion merge, verify the integration branch still
> exists before continuing:
>
> ```console
> $ git ls-remote origin refs/heads/staging
> ```
>
> Empty output means `staging` is missing — restore it immediately
> ([OPERATIONS.md](OPERATIONS.md) section 8.1) and re-check the
> auto-delete setting. The CI `policy` job enforces this on every run via
> its "Integration branch exists (staging guard)" step.

### Hotfix exception (narrow, fail-closed)

An incident/security fix may target `main` directly from a `hotfix/*`
branch **based on current `main`**, and only with:

1. fresh human approval (CI never grants it — the policy job annotates
   exactly this),
2. focused review,
3. required CI green,
4. patch-release evidence, and
5. **mandatory `main` → `staging` reconciliation** immediately after.

The policy check allows `hotfix/*` heads with a warning annotation
recording that the path requires that human approval and reconciliation;
it does not itself authorize anything.

### Releases

Releases happen from `main` only, on demand, per
[RELEASING.md](RELEASING.md). The release-*readiness* machinery
(deterministic archives + checksums/SBOM/provenance, verification and
clean-host scripts, version/schema policy) is active in-repo; every actual
release execution (promotion, tag, upload, attestation, soak) is a
separate human decision and never runs from CI or agent lanes.

### Required checks and metadata

Required status checks and branch rulesets are maintainer-owned metadata
applied **after** CI check names are observed from real runs — never
guessed. This bootstrap ships source + workflows only.

### Recovery when CI is unavailable

If hosted CI is down or unusable:

1. State it on the PR — do not merge on self-reported green alone.
2. Run `just ci` locally on the exact head and paste the raw exit codes
   into the PR (evidence, not replacement).
3. Wait for hosted CI to confirm before merge; if a required check cannot
   run (infrastructure), escalate to a maintainer rather than bypassing.

### Branch deletion

After a squash merge to `staging`, delete the feature branch. `staging` and
`main` are never deleted. Worktrees/checkouts pointing at deleted branches
are pruned by their owner.

## Operator workflow: grant windows and revision rebinds

The route-grant semantics an operator drives through `canter grant issue`
and `canter queue submit` were reworked by the executor authoring batch
(issue #92, PR #136). The mechanics live in [OPERATIONS.md](OPERATIONS.md)
sections 4 and 6; this section records the windowing and rebinding rules an
operator meets in the field.

### A fresh invocation opens a fresh authorization window

- The `gr_` id is content-addressed over the reviewed binding (repository,
  `issue.number` + acceptance revision, `workflow_hash`, `policy_hash`,
  `phase`, `scope`, `caps`, live `state_epoch`) **and the issuance element of
  the minting invocation** — its idempotency key (`--idempotency-key`,
  defaulting to a fresh per-invocation key). One reviewed binding therefore no
  longer names exactly one grant: every `grant issue` invocation mints a
  fresh window with a distinct id (an invocation that reuses an
  already-spent `--idempotency-key` replays its recorded response instead),
  and a fresh window never extends, replaces or revives an earlier row.
- **When a window lapses.** A LIVE run whose own window expired mid-spine
  renews it by itself, as one audited `grant.rotation` sized from its
  remaining committed spine — nothing to do. For any other run, re-mint and
  present the new window: a later issuance may rotate an EXPIRED window on
  the same durable run — the daemon records `grant.rotation` naming both rows
  and the new expiry — while a live window remains the owner and refuses
  rotation. An already-dead window is never minted
  (`refusal.grant.expired`).
- **`state.grant_exists`: what it meant, what it means now.** Re-minting the
  same binding used to recompute the same id, so the standing row (whose
  window may already have expired) held the binding and a same-binding
  re-mint refused `state.grant_exists` — a lapsed window could not be
  replaced. That is no longer the rule: a fresh invocation always mints a
  fresh window, and `state.grant_exists` now means exactly one thing — a
  grant with this exact id is already recorded (the same issuance window
  presented again). Replaying an already-spent `--idempotency-key` returns
  the recorded response (exactly-once); it never opens a second window.

### Windows are ordered by issuance, never by id or revision hash

- Authorization windows are ordered by grant INSERTION order; the contract
  states it plainly: "The grant insertion order is the normative
  authorization-window order"
  ([spec-daemon.md](contracts/spec-daemon.md)). Grant ids and 40-hex
  acceptance revisions are opaque and are never sorted lexically.
- **Which grant wins when the operator mints twice:** the LATER issuance is
  the later authorization. An earlier window presented afterwards is not a
  second, independent window: for a moved revision it stays stale
  (`preview.revision_stale`), and for a live same-revision owner the item
  stays `submission.already_owned` — a fresh window never rotates a live
  binding. Only an EXPIRED window on the same durable run is rotated by a
  later issuance.

### Revision rebind is explicit

- When the integration branch advances, the selected acceptance revision
  differs from the active owner's revision, and the selection is rebindable
  ONLY under a presented route grant that binds that exact revision and is a
  LATER issuance than the incumbent's window. Nothing else authorizes it:
  presenting no window for the moved revision refuses `submission.grant`
  ("revision rebind ... requires a fresh presented grant window"), and a
  window that is not a later authorization than the owner's refuses
  `preview.revision_stale` — the older authorization remains the only one.
- A later window alone never supersedes a LIVE run (issue #209): the
  submission is refused typed with the incumbent named — `submission.live_run`
  over its recorded frontier, or `submission.frontier_preserved` when the
  run's frontier has reached its own `review_evidence` step — and the
  incumbent keeps its ownership, its window and its frontier. Admission
  invalidates nothing as a side effect; the deliberate replacement is the
  explicit, audited `run release` control, after which a fresh submission
  under the later window admits a new run bound to the newer revision and the
  issue's ownership row is rebound to it.

### Where the durable step inputs live

- A run's step inputs are committed ONCE with its submission: the reviewed
  bound-input document (`canter queue preview --out request.json`) rides into
  the submission's canonical bound-input line, and the run's step spine plus
  every step's committed params are read back from there — never from a
  caller.
- `canter run dispatch` presents only the addressed step's OWN inputs
  (`--param KEY=VALUE`), merged over the step's committed params; everything
  else (the plan document, the run's grant/epoch/issue revision, and the
  topology + admission inputs of the run's recorded dispatch context) is
  derived from durable state. The effective params are persisted with the
  apply claim BEFORE the effect, so a restart and a supervision re-dispatch
  of that step reuse the recorded inputs: the operator does NOT re-supply
  them.
- What is re-supplied: a CORRECTION — presented as `--param` on the
  re-dispatch, merged over the committed params — and, on the FIRST dispatch
  of a run, the topology/admission inputs its caller holds. A run without a
  recorded dispatch context refuses `refusal.run.scope`; later dispatches
  read the run's own recorded context.

### Worked example: expire → re-mint → rebind → continue

Synthetic names; the acceptance revision is the 40-hex the run binds.
Situation: `run-0123456789abcdef` owns `example-org/widgets#7` at the old
acceptance revision, its window has lapsed, and the integration branch has
advanced to a new revision.

```console
# 1. Re-render the reviewed bound inputs at the CURRENT acceptance revision.
$ NEW=fedcba9876543210fedcba9876543210fedcba98
$ ./target/release/canter queue preview --repository example-org/widgets \
    --harness worker --host build-host --issue 7=$NEW --caps 4/2/2 \
    --out request.json                                            # exit 0
{"command":"queue preview","data":{"digest":"<64hex>",
 "preview":{"items":[{"id":"example-org/widgets#7","revision":"<new 40hex>", ...

# 2. Expire -> re-mint: a fresh invocation opens a fresh window (new gr_ id).
$ ./target/release/canter grant issue --request request.json --issue 7 \
    --expires-in 3600 --json                                      # exit 0
{"command":"grant issue","data":{"grant_id":"gr_bbbbbbbbbbbbbbbb",
 "next":{"command":"canter board --plan FILE --grant 7=gr_bbbbbbbbbbbbbbbb", ...

# 3. Present it at the authorization point. A live incumbent on a MOVED
#    revision refuses typed — nothing is invalidated.
$ ./target/release/canter queue submit --request request.json \
    --confirm-digest <64hex> --caps 4/2/2 --grant 7=gr_bbbbbbbbbbbbbbbb \
    --topology topology.json --host-available yes --harness-lanes 0 \
    --supervise arm --config config.toml --json                   # exit 0
... "items":[{"id":"example-org/widgets#7","status":"refused",
     "reason":"submission.live_run",
     "message":"run run-0123456789abcdef is live with frontier ...

# 4. Rebind explicitly: release the incumbent and retire its lane residue
#    (the released run is terminal, so its lane is retired explicitly).
$ ./target/release/canter run release --run run-0123456789abcdef \
    --reason "revision rebind: staging advanced to fedcba98" --json   # exit 0
$ ./target/release/canter run retire-lane --run run-0123456789abcdef \
    --reason "released: lane residue retired for the rebind" --json   # exit 0

# 5. Present the SAME submission again (a fresh per-invocation key is minted
#    when --idempotency-key is omitted): the item is admitted, bound to $NEW,
#    and the issue's ownership row is rebound to the new run.
$ ./target/release/canter queue submit --request request.json \
    --confirm-digest <64hex> --caps 4/2/2 --grant 7=gr_bbbbbbbbbbbbbbbb \
    --topology topology.json --host-available yes --harness-lanes 0 \
    --supervise arm --config config.toml --json                   # exit 0
... "items":[{"id":"example-org/widgets#7","status":"admitted",
     "instance_id":"run-<16hex>", ...

# 6. Continue: the admitted run's inputs are the committed ones.
$ ./target/release/canter run status --run run-<16hex> --json      # exit 0
$ ./target/release/canter supervision status --run run-<16hex> --json  # exit 0
```

## Public-data rule

Everything in this repository is public. Never commit host paths, private
repository names, credentials, provider/model policy, or live scheduler
identity. The `policy` CI job and the secret-scan job enforce this
mechanically (`scripts/check-public-tree.py`, gitleaks); if you think you
need to commit something private, you need a different (private) repository.

## Links

- [CONTRIBUTING.md](../CONTRIBUTING.md) — contribution rules and DCO note
- [DEVELOPMENT.md](DEVELOPMENT.md) — canonical gates
- [RELEASING.md](RELEASING.md) — release readiness; execution human-gated
- ADR-0002: [staging integration, main release](decisions/0002-staging-integration-main-release.md)
