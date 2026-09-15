# Issue 92 executor authoring, batch 1 report

Candidate code head: `3f09c71da8cc518cc456adbdea3d22b16d6d75d4`

Base: `a4ef50f03d17b43b8ac897d883019e357d4c00b8`

Scope: F3 through F11. F12 is excluded.

## Commit series

1. `efcaece161dc21dae9b313f4ddaccf01e62ca5c5` — Author run dispatch inputs and topology
2. `5f8c015199a6495ef1c2a38268d4a82db7fe8933` — Renew grants and rebind authorized revisions
3. `31c2bc99dac8f730c9786ea0e465de68d5e6d106` — Bind collected outcomes to recorded worker deltas
4. `5476ed5eb015142b4a6394ffbb0bf28217420790` — Resolve diagnosed prompts without duplicate effects
5. `3f09c71da8cc518cc456adbdea3d22b16d6d75d4` — Complete executor usage and misplaced flag errors

Every commit carries `Refs #92`.

## Delivered contracts

- F3: a run persists the addressed step inputs, and a later process invocation reuses those inputs instead of reconstructing them from empty arguments.
- F4: revisions remain opaque identifiers. A changed revision can replace an owner only when a later grant window explicitly authorizes that exact revision; an older authorization stays stale.
- F5: a fresh issuance idempotency key opens a separate immutable grant window for the same reviewed binding, including while another window is live and after expiry. Replaying one key still replays only its recorded result.
- F6: the first dispatch can supply the run topology; continuation reuses the recorded topology.
- F7: step parameter keys use the shared identifier contract and accept underscore-containing names.
- F8: dispatch reads the run's reviewed role profile and derives the run-scoped session identity without operator assembly.
- F9: prompt and collection share a bound worker worktree and branch. `requires_delta` is explicit; false permits a legitimate no-op, while true requires a verifiable delta. The default collection base is the run's recorded checkout base, never the current integration checkout position. Direct applies may use their exact observed integration base.
- F10: `run.resolve` records recorder-attributed worker delivery evidence without invoking the prompt again. The attempt ledger is authoritative for the frontier. Diagnosed steps remain fenced from supervision re-dispatch. Malformed requests are rejected before an attempt or retry authorization is consumed. Completed steps return `refusal.run.step_done` and are never repeated.
- F11: root and nested help expose the executor commands, including `run dispatch` and `run resolve`. Misplaced `--config`, `--socket`, and `--json` receive a targeted usage error instead of the full usage dump.

## RED evidence

The delivered test bytes were copied onto the pinned base. Every feature filter was nonzero:

| Feature | Base exit |
| --- | ---: |
| F3 | 101 |
| F4 | 101 |
| F5 | 101 |
| F6 | 101 |
| F7 | 101 |
| F8 | 101 |
| F9 | 101 |
| F10 | 101 |
| F11 | 101 |

F3, F6, F7, and F8 intentionally share the supported-entry-point fixture, so the pinned base stops at the earliest missing topology prerequisite. The per-mechanism mutation evidence below isolates each contract. F4's independent base leg fails because the newer authorized revision remains refused as stale.

The later groups also failed against their exact current predecessors with the delivered tests:

| Group | Predecessor | Command filter | Exit |
| --- | --- | --- | ---: |
| F9 | `5f8c015199a6495ef1c2a38268d4a82db7fe8933` | `executor_authoring f9_` | 101 |
| F10 | `31c2bc99dac8f730c9786ea0e465de68d5e6d106` | `executor_authoring f10_` | 101 |
| F11 | `5476ed5eb015142b4a6394ffbb0bf28217420790` | `cli_smoke f11_` | 101 |

## Focused GREEN evidence

All focused commands used an external Cargo target directory and four build jobs.

| Command | Exit |
| --- | ---: |
| `cargo test --locked --test executor_authoring -- --nocapture` | 0 |
| `cargo test --locked --lib f10_supervision_preflight -- --nocapture` | 0 |
| `cargo test --locked --test supervision f10_ -- --nocapture` | 0 |
| `cargo test --locked --test cli_smoke -- --nocapture` | 0 |
| `cargo test --locked --test supervision -- --nocapture` | 0 |

The executor-authoring target passed 11 tests. Its sequential tests cover restart persistence, authorization rebinding, no-op and required-delta collection, output-branch binding, unresolved duplicate-effect fencing, and evidence-only resolution.

## Mutation RED / restoration / GREEN evidence

The final runner head was `3f09c71da8cc518cc456adbdea3d22b16d6d75d4`. Every mutation matched once, the focused test reported `FAILED`, the source was restored byte-for-byte, Cargo recompiled `canter`, and the post-restore focused test passed.

| Probe | Mutation | RED | GREEN | Restored SHA-256 |
| --- | --- | ---: | ---: | --- |
| F3 | disable persisted step-input overlay | 101 | 0 | `b26a2f34fd5dce3568bca004f72c7972daa11fbb087536cf88169edd671c64c2` |
| F4 | reject every newer authorization window | 101 | 0 | `b26a2f34fd5dce3568bca004f72c7972daa11fbb087536cf88169edd671c64c2` |
| F5 | remove issuance identity from grant id | 101 | 0 | `0b0c64ea8c1445cf5169a6ecac3ef9f9858f85885acbb2b7b54e003ce1e8ce9c` |
| F6 | ignore first-dispatch topology input | 101 | 0 | `8b77e4e0fc43014ef76236dbfc68596607cda2760872fd353467d778fde96b90` |
| F7 | restore slug-only parameter parsing | 101 | 0 | `0b0c64ea8c1445cf5169a6ecac3ef9f9858f85885acbb2b7b54e003ce1e8ce9c` |
| F8 | drop the recorded role profile | 101 | 0 | `8b77e4e0fc43014ef76236dbfc68596607cda2760872fd353467d778fde96b90` |
| F9 | ignore explicit delta requirements | 101 | 0 | `68e9bb301f7f1bd5bd0f9a27fb0b42f4d7190626bfed729933208dbb4975dc4d` |
| F10 resolution | hide evidence resolutions from the attempt ledger | 101 | 0 | `b26a2f34fd5dce3568bca004f72c7972daa11fbb087536cf88169edd671c64c2` |
| F10 guard | allow supervision to re-dispatch a diagnosed step | 101 | 0 | `fde75c7532ed869a8d0963f48cc66177fca123d7f30c76f2e292ad8cf55ef21b` |
| F10 preflight | let malformed applies enter the attempt path | 101 | 0 | `8b77e4e0fc43014ef76236dbfc68596607cda2760872fd353467d778fde96b90` |
| F11 | restore the generic usage dump for misplaced flags | 101 | 0 | `0b0c64ea8c1445cf5169a6ecac3ef9f9858f85885acbb2b7b54e003ce1e8ce9c` |

The runner's final tracked-tree check was true.

## Canonical gates

The final code head was committed before these gates ran. Cargo artifacts lived outside the repository.

| Command | Raw exit |
| --- | ---: |
| `just fmt-check` | 0 |
| `just check` | 0 |
| `just lint` | 0 |
| `just test` | 0 |
| `just doc` | 0 |
| `just build-release` | 0 |
| `just security` | 0 |
| `just ci` | 0 |
| `python3 scripts/check-contract-fixtures.py` | 0 |
| `python3 scripts/test-check-contract-fixtures.py` | 0 |
| `python3 scripts/test-check-public-tree.py` | 0 |
| `python3 scripts/check-public-tree.py .` | 0 |
| `CARGO_TARGET_DIR=target-batch1 python3 scripts/test-build-archive.py` | 0 |

`just ci` completed its full chain: formatting, check, clippy with warnings denied, tests, documentation, release build, scanner self-test, public-tree scan, cargo-deny, cargo-audit, and gitleaks. Gitleaks reported no leaks.

Earlier diagnostic gates were intentionally not treated as green evidence: the first lint run exited 101 on a needless manual match; full-test runs exited 101 while stale predecessor expectations for fresh grants, recorded collection bases, complete session identity, and malformed-attempt accounting were corrected. The final commands above supersede those diagnostics.

## Scope and safety verification

- `git diff --check` against the pinned base exits 0.
- The code diff contains no hunk matching `review_evidence` or `check_review_evidence` in `src/daemon.rs`; issue 133's evidence gate remains untouched.
- `dispatch_intent` still returns no intent for a diagnosed step, and its reviewer-style mutation is RED.
- No live provider, Herdr workspace, remote GitHub mutation, acceptance daemon, or integration checkout was used. All behavior evidence came from disposable fixtures.
- The orchestrator briefs and feature-list notes remain untracked. They are neither committed nor added to product ignore rules.

## Delivery reconciliation onto staging `3a9e52f`

### Exact heads and ancestry

- Old batch head: `ff4e64e6cfcc668d5c65d293285827efe02abebf`.
- Incoming `origin/staging`: `3a9e52f820f3e748605d8696b3b1bce2db27b054`, the merged PR 135 / issue 133 result.
- Normal merge commit: `c5ec98b7fae0b8f86bb5cff6f924fc6684481eaf`.
- Merge parent 1: `ff4e64e6cfcc668d5c65d293285827efe02abebf`.
- Merge parent 2: `3a9e52f820f3e748605d8696b3b1bce2db27b054`.
- Reconciliation-prep head tested by all commands below: `f07081160da36a2dc3fcc9a7f3c42468bdb70fc3`.
- `git merge-base HEAD origin/staging` returned the exact staging head.

The normal merge command was `git merge --no-ff origin/staging -m "Merge staging 3a9e52f into batch1 executor authoring" -m "Refs #92"`. Git exited 1 after reporting the three expected content conflicts; after the bounded resolutions below, `git commit --no-edit` exited 0 and produced the merge commit above. No rebase, reset, force update, or staging/main mutation was used.

### Conflict decisions

Three paths conflicted:

1. `src/daemon.rs`: unioned both contracts. The F3–F11 pure step preflight (`check_apply_step_contract` and `preflight_apply_request`) remains immediately before issue 133's executor-owned `ApplyClaim` and its `Drop` cleanup. The presented-profile error arm uses the shared `resolve_apply_refusal` path once; both sides had the same durable-refusal semantics with only formatting differences.
2. `src/mutation.rs`: retained staging's issue 130 `resolve_contained` implementation. It is the stronger current-staging implementation: it resolves each existing component, rejects absolute and parent escapes, follows symlinks for containment, and permits an in-root destination that does not exist yet. This replaces the batch's narrower local canonical-root workaround without removing F3–F11 collection or parameter behavior.
3. `tests/supervision.rs`: unioned the comment around the already-identical explicit `run retry` call, naming both issue 133's durable refusal and F10's no-redispatch boundary.

`tests/mutation_engine.rs` auto-merged. The three issue 133 socket regressions and all batch collection-base updates are present. `f13-report.md` was retained unchanged from staging.

The first merged supervision run exposed one deterministic fixture dependency: issue 130's containment test still manufactured its diagnosis by omitting `branch`, while F3 now commits complete `p2` parameters. That run exited 101 with 17 passed / 1 failed because the complete step legitimately executed. The only follow-up commit, `f07081160da36a2dc3fcc9a7f3c42468bdb70fc3`, makes the fixture create and then remove a private branch/target obstruction so it records a real adapter failure before testing the escaping destination. The focused test then exited 0, and the final supervision suite passed 18/18. No product code changed after the merge commit.

Conflict-marker checks covered all four diff3 tokens in both the working tree and staged blobs before the merge commit, then the committed tree after the fix. Each check found zero markers. `git diff --check` also exited 0.

### Both contracts preserved

Structural inventory at the tested prep head found exactly one each of:

- `struct ApplyClaim` and `impl Drop for ApplyClaim`;
- `preflight_apply_request` and `check_apply_step_contract`;
- `method_run_resolve`;
- the `apply.reap_failed` diagnostic.

The merged daemon has all issue 133 guard releases and executor cleanup relative to the old batch parent. Relative to staging it adds the F3–F11 preflight/dispatch/resolution contract without deleting `ApplyClaim`. The merged test outlines contain issue 133's `apply_refusal_keeps_daemon_responsive_and_records_attempt`, `apply_profile_refusal_resolves_its_claim_without_restart`, and `disconnected_apply_is_resolved_after_its_effect_deadline_without_restart`, plus all F3–F11 executor and supervision regressions.

All focused Cargo commands used a private target named `canter-reconcile-3a9e52f-target` and `CARGO_BUILD_JOBS=4`.

| Exact command | Log | Raw exit | Count |
| --- | --- | ---: | ---: |
| `cargo test --locked --test mutation_engine apply_refusal_keeps_daemon_responsive_and_records_attempt -- --nocapture` | `canter-reconcile-focused-final-133-refusal.log` | 0 | 1 passed |
| `cargo test --locked --lib abandoned_apply_claim_is_reaped_on_executor_unwind -- --nocapture` | `canter-reconcile-focused-final-133-reaper.log` | 0 | 1 passed |
| `cargo test --locked --test executor_authoring -- --nocapture` | `canter-reconcile-focused-final-executor.log` | 0 | 11 passed |
| `cargo test --locked --test supervision -- --nocapture` | `canter-reconcile-focused-final-supervision.log` | 0 | 18 passed |
| `cargo test --locked --test grant_issue -- --nocapture` | `canter-reconcile-focused-final-grant.log` | 0 | 14 passed |
| `cargo test --locked --test cli_smoke -- --nocapture` | `canter-reconcile-focused-final-cli.log` | 0 | 8 passed |

### Full merged-head gates

The recorded head before and after each full gate was byte-identical at `f07081160da36a2dc3fcc9a7f3c42468bdb70fc3`.

| Exact command | Log | Raw exit | Count/result |
| --- | --- | ---: | --- |
| `just --list` | `canter-reconcile-just-list.log` | 0 | canonical recipes listed once |
| `cargo check --locked --all-targets` | `canter-reconcile-precommit-check.log` | 0 | merge union compiled |
| `just test` | `canter-reconcile-just-test.log` | 0 | 663 passed, 0 failed |
| `just ci` | `canter-reconcile-just-ci.log` | 0 | 663 passed, 0 failed; format/check/lint/doc/release/security all completed |
| `git diff a4ef50f03d17b43b8ac897d883019e357d4c00b8..HEAD --check` | `canter-reconcile-diff-check.log` | 0 | no whitespace errors |
| `python3 scripts/check-contract-fixtures.py` | `canter-reconcile-contract-fixtures.log` | 0 | contract oracle passed |
| `python3 scripts/test-check-contract-fixtures.py` | `canter-reconcile-contract-selftest.log` | 0 | contract-oracle self-test passed |
| `python3 scripts/test-check-public-tree.py` | `canter-reconcile-public-selftest.log` | 0 | 21 tests passed |
| `python3 scripts/check-public-tree.py .` | `canter-reconcile-public-tree.log` | 0 | public-tree scan passed |
| `gitleaks dir --no-banner --redact --exit-code 1 .` | `canter-reconcile-gitleaks.log` | 0 | no leaks found |
| `cargo build --release --locked` | `canter-reconcile-standard-release.log` | 0 | standard release binary rebuilt at the tested head |
| `CARGO_TARGET_DIR=target-batch1 python3 scripts/test-build-archive.py` | `canter-reconcile-archive-selftest.log` | 0 | archive self-test passed |

`just ci` itself recorded the scanner self-test's 21 passing tests, cargo-deny's four `ok` categories, a cargo-audit scan of 119 dependencies, and `no leaks found` from gitleaks.

### Fetch, scope, and delivery boundary

- `gh auth status`, the full-comment reads of issues 92 and 133, and the PR 135 merged-state/evidence read each exited 0.
- The initial broad `git fetch origin` exited 1 only because the local `v0.1.0` tag would be clobbered. Per the repository's documented recovery, `git fetch --no-tags origin staging` exited 0 and resolved `origin/staging` to the required exact SHA.
- From the old batch head to the tested prep head, the reconciliation changes only the five incoming paths: `f13-report.md`, `src/daemon.rs`, `src/mutation.rs`, `tests/mutation_engine.rs`, and `tests/supervision.rs` (1,141 insertions / 19 deletions). The 15-line fixture resolution is inside the already-overlapping supervision test.
- From staging to the tested prep head, all 22 F3–F11 paths remain present. No deletion is reported.
- The post-gate tracked-worktree check exited 0. The seven orchestrator-owned brief/F-list files remain untracked and unchanged.
- Before reconciliation, the remote feature branch read back as the old batch head `ff4e64e6cfcc668d5c65d293285827efe02abebf`. The report commit is intentionally not self-referential; the normal push and exact post-push remote readback are recorded in the final lane handoff.
