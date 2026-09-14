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
