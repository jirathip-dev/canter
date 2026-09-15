# Cycle 2 fused executor report

Base: `79d6800508a9463ad2ada1d5120c0da9f7f53321` (`staging` after #136).
Implementation head: the commit containing this report.
Scope: one fused change for #132, #134, #92 grant recovery, supervision idle waiting, and the review addendum.

## Verdicts

| Item | Verdict | Result |
|---|---|---|
| A — policy-aware merge | fixed | `merge_policy` is closed to `squash | ff`; the effect is a read-only rehearsal and reports the policy-specific cause. |
| B — failed worktree escape leaves a ref | fixed | dangling symlinks are refused before git; all four escape spellings preserve refs, worktree inventory, paths, attempts, and retry authorization. |
| C — expired grant wedges ownership | fixed | a later issuance rotates the same binding/run in one transaction and records both grant rows plus the new expiry; live grants do not rotate. |
| NB-1 — collect pre-screen asymmetry | fixed | pre-screen and effect use `collect_outcome_inputs`; malformed input stays before the claim/retry fence. |
| NB-3 — 3/16 coverage uncertainty | closed | all 16 kinds have accepted/malformed unit coverage and no-attempt integration coverage; the inventory is below. |
| Idle supervision CPU | fixed | an immediately due/error deadline waits on the condvar for one second and remains wakeable; five isolated-daemon samples were 0.0% CPU. |
| Armed self-dispatch | fixed with an evidence boundary | the supported submission records dispatch context and the supervisor drives p1 through p5 to the p6 approval boundary through `method_apply`; a nested real worker/remote PR was not run because this lane may not spawn a competing agent session or mutate GitHub. |

Freeze residual disposition:

| Residual | Disposition | Evidence |
|---|---|---|
| #132 squash policy | DONE+verified | Three policy regressions pass; the mutation probe fails. |
| #134 stray branch ref | DONE+verified | All four escaping destinations preserve the exact ref/worktree inventory; the mutation probe fails. |
| Expired-grant re-bind | DONE+verified | The CLI rotation test rebinds the same run after expiry and records both rows. |
| #127 dead ownership | DONE+verified | The expired owner is recoverable on the same run; terminal owners were already excluded and paused owners retain explicit resume. |
| Supervision busy-wait | DONE+verified | The discriminating test passes and five isolated idle samples report 0.0% CPU. |
| Real worker/PR acceptance | FOLLOW-UP | Zero-operator dispatch is verified through p5 and stops at p6 (`supervision.waiting_approval`) because independent review evidence is absent; this lane did not spawn a competing real agent or mutate GitHub. |

## Structural inspection

The required structural search was run before reading implementation ranges:

    ast-grep run --lang rust --kind function_item --json src/mutation.rs src/state.rs src/supervision.rs src/daemon.rs
    AST_FUNCTION_COUNT=566
    AST_GREP_RAW_EXIT=0

The result is `/tmp/canter-cycle2-evidence/ast-functions-final.json`.

## A — squash/ff policy and read-only rehearsal

Defect: `effect_merge` ran `git merge --ff-only` in the integration checkout. That both contradicted this repository's squash policy and could leave a local integration ref ahead of the published ref.

Change:

- `src/mutation.rs:1850-1884` resolves a feature branch and requires explicit `merge_policy: squash | ff`.
- `src/mutation.rs:2716-2814` verifies the exact reviewed integration ref, branch/tree identity, and policy relation without checkout/ref/remote mutation. The result says `mode:"rehearsal"`, `landed:false`, policy, and `result_tree`.
- `src/plan.rs:262-263` authors `merge_policy:"squash"` in the built-in queue spine.
- `docs/contracts/spec-plans.md` records that the orchestrator/forge owns the actual squash and `post_merge_verify` proves the landed result.

Legacy adjudication: `lane_flow_rehearses_then_verifies_landed_head_and_cleans_with_salvage` was the one old local-landing expectation. It encoded the retired `git merge --ff-only` effect, not a published delivery contract. The regression now asserts the effect leaves the local base unchanged, then the fixture emulates the external policy landing before running the unchanged `post_merge_verify` and cleanup gates. This is an explicit semantic update; no verification gate was deleted or weakened.

Evidence:

- Base: `cargo test --locked --test mutation_engine cycle2_ -- --nocapture` — raw exit 101, 0 passed / 3 failed (`base-a.log`).
- Candidate: same command — raw exit 0, 3 passed (`focused-a-final.log`).
- Mutation: forcing squash through the ff ancestry branch — raw exit 101, 0 passed / 1 failed (`probe-a-red.log`).
- Restore: `src/mutation.rs` pre/post SHA-256 `8c31c61edbd6d00ae42aaf5dd666f0ea0e65037c919384d0cefc3b033aff38a7`.

Residual: this lane intentionally does not perform the remote squash. The one staging squash belongs to the orchestrator under the loop contract.

## B — dangling worktree target and branch-ref containment

Defect: canonical fallback treated a dangling symlink lexically as in-root. `git worktree add -b` then created the branch before the filesystem failure, leaving a stray ref.

Change: `src/mutation.rs:1148-1162` uses `symlink_metadata` for each existing path component. A symlink must canonicalize; a dangling symlink refuses before any git subprocess. The chosen remedy is pre-fence refusal, not post-failure branch deletion.

The integration regression `tests/supervision.rs:2715` presents:

- `../escaped-lane`
- an absolute destination
- an existing symlink to an external directory
- a dangling symlink

For each it asserts typed `refusal.path.uncontained`, identical branch refs, one unchanged worktree, no external path, no new attempt, and an unconsumed retry. It then proves a normal in-root target still succeeds. The cheap root-clause witness was included: `contained_path(&root, ".")` refuses in the lib test at `src/mutation.rs:3606`.

Evidence:

- Base: `cargo test --locked --test supervision an_uncontained_worktree_dispatch -- --nocapture` — raw exit 101, 0 passed / 1 failed (`base-b.log`).
- Candidate: same command — raw exit 0, 1 passed (`focused-b-final.log`).
- Mutation: disable the symlink-specific canonicalization guard — raw exit 101, 0 passed / 1 failed (`probe-b-red.log`).
- Restore: `src/mutation.rs` pre/post SHA-256 `8c31c61edbd6d00ae42aaf5dd666f0ea0e65037c919384d0cefc3b033aff38a7`.
- Root clause: `cargo test --locked --lib containment_refuses_a_destination_that_does_not_exist_yet -- --nocapture` — raw exit 0, 1 passed (`focused-root-final.log`).

Residual: none for the four required escaping spellings.

## C — explicit expired-grant rotation and ownership recovery

The merged base already minted a distinct grant row per fresh idempotency issuance. The remaining wedge was admission: same-revision ownership always returned `submission.already_owned`, and apply still required the run's old expired grant id.

Change:

- `src/queue_executor.rs:1200-1260` accepts only a later issuance when the current same-binding window is active but expired; a live window still returns `submission.already_owned`.
- `src/state.rs:725-760` rechecks issuance row order, status, epoch and expiry under the submission transaction.
- `src/state.rs:909-945` updates the existing run's grant id and appends one `grant.rotation` audit row naming run, superseded grant, replacement grant, and replacement expiry.
- `src/daemon.rs:3620-3622` also prevents an expired run grant from authorizing a retry.
- Expiry is effective at its timestamp (`expires_at <= now`); no expired row is replaced, revoked, or reused.

Supported-CLI artifact (`focused-c-final2.log`): a 4-second grant was admitted, p1 succeeded, p2 refused `refusal.grant.expired`, a new grant was issued, `queue submit` returned the same run as `admitted`, restart preserved the new binding, `run retry` plus `run dispatch` continued p2, and replay did not add another rotation. The audit line was:

    action=grant.rotation
    target=run:run-e6ee80afba047761:superseded:gr_e5d0cfbefafd028e:replacement:gr_0671a03b92490e5e:expires:2026-09-15T08:39:42Z

(The identifiers are isolated synthetic fixture data.)

Evidence:

- Base: `cargo test --locked --test executor_authoring cycle2_ -- --nocapture` — raw exit 101, 1 passed / 1 failed (`base-c.log`).
- Candidate: same command — raw exit 0, 3 passed (`focused-c-final2.log`).
- Mutation: disable the state rebind branch — raw exit 101, 0 passed / 1 failed (`probe-c-red.log`).
- Restore: `src/state.rs` pre/post SHA-256 `ef8c57e8ca6be35b61122319eaf02c1425b50a700f56011c7e1e452cf1dcbe5b`.
- Live-window guard: `cycle2_live_grant_is_not_rotated_by_another_issuance` is one of the three passing candidate tests.

NB-2 remains deliberate: a fresh issuance creates a fresh row, same-key reuse remains fenced, and no one-grant-forever rule was reintroduced.

Residual: terminal ownership was already excluded from the live ownership snapshot and paused runs already had explicit resume authorization. This change closes the uncovered expired-run path on the same run, so a dead window no longer permanently owns the issue.

## NB-1 — one collect resolver on both sides of the fence

Change: `src/mutation.rs:1718-1750` resolves `worktree`, exact base (`params.base_head` or the apply's observed base), and `requires_delta` once. `check_step_params` and `effect_collect_outcome` both consume that resolver.

Evidence:

- Base: `cargo test --locked --test supervision cycle2_collect_missing_base -- --nocapture` — raw exit 101, 0 passed / 1 failed (`base-nb1.log`).
- Candidate: same command — raw exit 0, 1 passed (`focused-nb1-final.log`).
- Mutation: restore the old partial collect pre-screen — raw exit 101, 0 passed / 1 failed (`probe-nb1-red.log`).
- Restore: `src/mutation.rs` pre/post SHA-256 `8c31c61edbd6d00ae42aaf5dd666f0ea0e65037c919384d0cefc3b033aff38a7`.

The witness checks typed pre-fence refusal, unchanged attempt count, and an unconsumed retry before the corrected request consumes it.

## NB-3 — all 16 kinds

Two closed-set tests cover every row below:

- `the_param_pre_screen_is_total_over_every_step_kind`: each kind refuses absent/empty malformed input and accepts a contract-complete input.
- `f10_every_kind_refuses_a_malformed_dispatch_without_recording_an_attempt`: each reachable kind refuses pre-fence without an attempt.

`cargo test --locked --lib the_param_pre_screen_is_total_over_every_step_kind -- --nocapture` — raw exit 0, 1 passed (`focused-nb3-final.log`). The additional behavior witness is listed per kind:

| Kind | Additional behavior witness |
|---|---|
| checkout | autonomous p1 in `cycle2_supervision_dispatches_the_authored_spine_through_collection` |
| worktree_create | four-escape ref-invariance regression |
| harness_start | autonomous p3, role/session binding tests |
| prompt | autonomous p4, role-bound continued-session tests |
| collect_outcome | NB-1 pre-fence test and autonomous p5 |
| review_evidence | policy merge scenarios record exact review evidence before merge |
| merge | Item A ff/squash read-only tests |
| cleanup | lane-flow cleanup/salvage and dirty/unmerged refusal tests |
| publish | shared forge-PR handler tests |
| branch_push | production scheduling/first-write gate tests |
| pr_update | trusted/fork PR update regression |
| issue_update | premature issue-close regression |
| hosted_check | lane-flow hosted-check execution and supervision continuation test |
| post_merge_verify | legacy-adjudicated lane-flow verification |
| branch_delete | cleanup/branch-retirement tests plus closed resolver table |
| approve | scheduled first-write approval regression |

Residual: none of the 16 registered kinds is uncovered.

## Idle supervision wait

Defect: when `next_deadline` returned an immediately due instant (including the error path), `wait_for_wake` returned immediately and the loop re-ran the SQLite deadline query continuously.

Change: `src/supervision.rs:1303-1329` waits one second on the existing condvar for an already-due deadline; a semantic wake or stop still interrupts it. `next_deadline` calculation itself is unchanged.

Evidence:

- Conductor baseline: acceptance daemon process was measured 72.7% then 99.9% CPU, with 2098/2098 samples in `canter-supervision -> next_deadline -> supervision_next_due_in`.
- Base: `cargo test --locked --lib cycle2_idle_driver -- --nocapture` — raw exit 101, 0 passed / 1 failed (`base-cpu.log`).
- Candidate: same command — raw exit 0, 1 passed (`focused-cpu-final.log`); over 350 ms the driver evaluated the deadline at most twice and a wake remained prompt.
- Mutation: replace the one-second wait with zero — raw exit 101, 0 passed / 1 failed (`probe-cpu-red2.log`).
- Restore: `src/supervision.rs` pre/post SHA-256 `63e2e23d710a3adbc1fcb966faf331a37f511ce804af521c44a74d846fb59186`.
- Isolated candidate daemon, five process samples two seconds apart: `0.0, 0.0, 0.0, 0.0, 0.0%`; cumulative CPU time stayed `0:00.15` (`idle-cpu-after.log`, raw exit 0). The daemon and owned temp state were then removed and the PID was verified absent.

Residual: the one-second error/due backoff intentionally trades a maximum one-second timer retry delay for bounded idle cost; event/new-work wakes remain immediate.

## Armed self-dispatch and cursor progression

Defect: the supervisor refused to create an intent before any attempt, while queue submission did not retain topology/admission material. The product-authored p1-p8 spine therefore remained at p1 indefinitely.

Change:

- `src/commands.rs:2257-2261,4740-4775` requires `--topology FILE` for `queue submit --supervise arm` and commits topology plus the submission's fresh host/cap observation as dispatch context.
- `src/state.rs:2889-3020` recovers only the context belonging to the run's exact submission/apply claims and derives later base/head/session data from recorded outcomes.
- `src/supervision.rs:158-165,557-596,764-782` marks supported unattempted frontiers eligible, names missing context as `supervision.dispatch_context_missing`, dispatches first and next steps, and leaves diagnosed/retry/approval frontiers untouched.
- `src/daemon.rs:1356-1425` routes each intent back through `method_apply`; there is no alternate effect path.
- `src/plan.rs:230-240` now authors the p4 implementation/PR payload, eliminating its missing-payload stall.

Evidence:

- Base archive at exact base plus the new regression: `cargo test --locked --test executor_authoring cycle2_supervision_dispatches -- --nocapture` — raw exit 101, 0 passed / 1 failed; base CLI refused the required submission topology flag (`base-dispatch-real2.log`).
- Candidate: same command — raw exit 0, 1 passed (`focused-dispatch-final.log`).
- Mutation: remove checkout from the autonomous kind set — raw exit 101, 0 passed / 1 failed (`probe-dispatch-red.log`).
- Restore: `src/supervision.rs` pre/post SHA-256 `63e2e23d710a3adbc1fcb966faf331a37f511ce804af521c44a74d846fb59186`.
- Missing-context classification: `cargo test --locked --test supervision an_armed_run_is_dispatched_only -- --nocapture` — raw exit 0, 1 passed (`focused-honesty-final.log`).

The isolated supported-CLI witness used no `run dispatch` call. It reached p6 with these exact adjacent audit sequence pairs:

    p1 checkout             mutate/outcome seq 5/6
    p2-5 worktree_create    mutate/outcome seq 7/8
    p3 harness_start        mutate/outcome seq 9/10
    p4-5 prompt             mutate/outcome seq 11/12
    p5-5 collect_outcome    mutate/outcome seq 13/14

Cursor attempts were exactly p1, p2-5, p3, p4-5, p5-5, each `succeeded`; the cursor then reported p6-5 with `supervision.waiting_approval` and `eligible:false`. The worker adapter fixture committed `autonomous.txt` on branch `issue-5`; one prompt invocation was observed.

Evidence boundary, stated plainly: I drove the full daemon/apply/journal/cursor path through p5 and to the p6 independent-review boundary. I did not run a nested real `fleet-impl` session or create/push a real PR: this implementation lane is forbidden to hand-spawn a competing agent session and forbidden to mutate GitHub. Therefore the real-session/profile and remote-PR portions remain for the orchestrator's single acceptance/review run. The product reports this remaining p6 dependency as the concrete approval reason rather than claiming eligibility.

## Gates and delivery boundary

Pre-report executions:

- `just --list` — raw exit 0 (`just-list.log`).
- `just fmt-check` — raw exit 0 (`fmt-check-1.log`).
- `just lint` — raw exit 0 (`lint-1.log`).
- `cargo test --locked --lib -- --nocapture` — raw exit 0, 296 passed (`lib-all-2.log`).
- `cargo test --locked --test mutation_engine -- --nocapture` — raw exit 0, 18 passed (`suite-mutation-3.log`).
- `cargo test --locked --test executor_authoring -- --nocapture` — raw exit 0, 15 passed (`suite-executor-3.log`; rerun after final edits is listed below).

Final canonical gate results after this report was added to the tree:

- `just fmt-check` — raw exit 0 (`final-fmt-check.log`).
- `just lint` — raw exit 0 (`final-lint.log`).
- `cargo test --locked --test mutation_engine cycle2_ -- --nocapture` — raw exit 0, 3 passed (`final-focused-a.log`).
- `cargo test --locked --test supervision an_uncontained_worktree_dispatch -- --nocapture` — raw exit 0, 1 passed (`final-focused-b.log`).
- `cargo test --locked --test executor_authoring cycle2_ -- --nocapture` — raw exit 0, 3 passed (`final-focused-c.log`).
- `cargo test --locked --test supervision cycle2_collect_missing_base -- --nocapture` — raw exit 0, 1 passed (`final-focused-nb1.log`).
- `cargo test --locked --lib the_param_pre_screen_is_total_over_every_step_kind -- --nocapture` — raw exit 0, 1 passed (`final-focused-nb3.log`).
- `cargo test --locked --lib cycle2_idle_driver -- --nocapture` — raw exit 0, 1 passed (`final-focused-cpu.log`).
- `cargo test --locked --test supervision an_armed_run_is_dispatched_only -- --nocapture` — raw exit 0, 1 passed (`final-focused-honesty.log`).
- `cargo test --locked --test supervision -- --nocapture` — raw exit 0, 20 passed (`final-suite-supervision.log`).
- `just test` — raw exit 0, 677 passed across 40 test/doc-test binaries (`final-just-test-2.log`). The prior run was raw exit 101 because one TUI regression still expected the superseded generic `unknown` classification; that expectation was updated to require `supervision.dispatch_context_missing`, and its focused rerun passed (`tui-stale-final.log`).
- `just ci` — raw exit 0 (`final-just-ci-1.log`, 407.50 seconds): fmt, check, clippy, all tests, docs, release build, scanner self-tests, public-tree scan, cargo-deny, cargo-audit, and gitleaks all completed; gitleaks reported no leaks.

The TUI reason adjustment had focused TUI, fmt, lint, full-test, and full-CI coverage. After that full gate, freeze finalization changed only contract/help/report prose.

No main/release ref, other fleet, live acceptance state, acceptance run, or staging ref was mutated. The authorized delivery consists only of pushing `cycle2-92-executor` and opening this PR for the orchestrator's one review, one CI run, and one squash merge to `staging`.

Refs #92
