# F13 — refusal deadlock and abandoned apply claims

Refs #133; acceptance context: #92.

Base: `600c46b876af9022092c07b0dba75492a10bb642` (the supplied merged staging head).
Implementation/probe head: `a15bc34f5e0c348f2d40d188fd196a1f166b0fda`.
Final code/test candidate: `9827a29bd6f5e4421160457e2a53c3aae52d7ddb`.
The delivery commit adds this report only. No dependency, migration, schema,
refusal-code, adapter-deadline, or gate changes.

## 1. Eliminate live-guard recursion

Defect: the review-evidence recorder refuses string-valued checks while its
state guard is live, then `finish_apply_refused` locks the same non-recursive
mutex. The apply caller, later status callers, and supervisor all stall.
The earlier pause-boundary guard at base line 1742 actually ends at 1757;
it is not live at 2145. The proven recursion is the recorder's own guard
crossing its refusal arm.

Change: release state before calling a lock-taking terminal helper. All changed
sites below are in `src/daemon.rs` (candidate line numbers):

| Site | Release line | Helper called after release |
| --- | ---: | --- |
| Apply retry-spine read error | 2132 | `resolve_apply_refusal` |
| Apply review-evidence recorder refusal | 2289 | `finish_apply_refused` |
| Apply cleanup salvage recorder refusal | 2330 | `finish_apply_refused` |
| Apply approval recorder refusal | 2376 | `finish_apply_refused` |
| Lane start stored-profile error | 5173 | `finish_mutation` |
| Lane adopt stored-profile error | 5785 | `finish_mutation` |
| Backup current-epoch error | 6802 | `finish_mutation` |

Regression: `tests/mutation_engine.rs:816`,
`apply_refusal_keeps_daemon_responsive_and_records_attempt`, sends the exact
`["policy=pass","rust-macos=pass"]` payload to a real per-test daemon.
The socket helper at line 791 uses 3-second read/write deadlines. It obtains
both the apply and a separate status observation, then reads the fixture's
claim before asserting, so a deadlock prints all three witnesses. The existing
`Scenario` destructor kills/waits its own daemon on assertion failure.

Exact command for base, both deadlock probes, and restored GREEN:

```sh
cargo test --locked --test mutation_engine apply_refusal_keeps_daemon_responsive_and_records_attempt -- --nocapture
```

Base RED (`base-red.log`, raw terminal `BASE_RED_EXIT=101`):

```text
apply=Err("Resource temporarily unavailable (os error 35)")
status=Err("Resource temporarily unavailable (os error 35)")
claim_status=claimed outcome=None
post-effect refusal must return, not deadlock: "Resource temporarily unavailable (os error 35)"
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 13 filtered out; finished in 7.23s
```

Probe: remove only `drop(state)` in the evidence recorder's `Err(err)` arm.
This reinstates the live-guard recursion, not a fabricated error or compile
failure. `probe-deadlock-red-1.log` and `probe-deadlock-red-2.log` both have
`RAW_EXIT=101`, the same three blocked/NULL witnesses above, and the intended
assertion failure. Test durations were 7.11s and 6.75s. The repeated run stayed
RED. Restoration refreshed the source mtime; cargo recompiled the restored
source. `probe-deadlock-restored.log`:

```text
test apply_refusal_keeps_daemon_responsive_and_records_attempt ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 13 filtered out; finished in 1.10s
RAW_EXIT=0
```

Residual: the malformed-evidence path is dynamically discriminated. The other
six release sites were audited structurally and exercised by the existing
sibling/full suites; their individual storage-failure arms were not each
fault-injected.

## 2. Preserve the typed refusal and durable attempt

Change: the same evidence release lets the existing `finish_apply_refused`
(`src/daemon.rs:2525`) actually record its terminal outcome, cached response,
audit/event rows, and publish after releasing state. It still returns the
recorder's `state.evidence_invalid` and exact reason. Because the effect already
succeeded, the existing terminal status remains `ambiguous`, never success.
No evidence row is accepted for invalid checks.

RED: the base and both probes above leave `claim_status=claimed outcome=None`.
GREEN: the restored log contains this raw response:

```text
apply=Ok(Obj({"error": Obj({"code": Str("state.evidence_invalid"), "message": Str("evidence checks must be a non-empty list of {{name, status(passed|failed|pending)}}"), "retryable": Bool(false)}), "id": Str("00009970"), "ok": Bool(false), "result": Null, "schema": Str("hf-rpc-response/v1")}))
```

The same log records status `ok=true`, `pending_claims=0`, and a non-NULL
`ambiguous` outcome with that error. The test compares the complete persisted
error to the response error, compares the cached response to the wire response,
asserts no in-flight run step and no accepted evidence, and replays the same
request/key to obtain the identical typed refusal. The probe and raw GREEN
exit are those in item 1; neither a timeout nor a generic refusal passes.

Residual: a post-effect refusal is deliberately still ambiguous and is not
permission to repeat an effect. Storage unavailability is not converted into
success.

## 3. Resolve claims when their executor leaves

Defects: malformed presented-profile and unavailable run-binding errors used
to return a bare response after claiming, leaving the attempt NULL. A handler
unwind also lacked executor-owned terminal cleanup.

Changes:
- `src/daemon.rs:2189,2199`: route the two known pre-effect refusals through
  `resolve_apply_refusal`, preserving their error code/message while spending
  and recording their claims.
- `src/daemon.rs:1670-1737,1885`: an executor-owned `ApplyClaim` destructor is
  installed only after a NEW claim commits, before any later state guards.
  On early return/unwind it resolves only its own still-claimed request as
  `ambiguous` with `state.interrupted`, records the replay response, completes
  any pending pause boundary, and publishes after releasing the guard.
  Already-completed claims are unchanged. Replay callers do not own a reaper.
- Live executors are NOT expired by age: disconnecting a client does not
  cancel the server handler. Reuse the existing bounded effect runner; once
  its deadline settles the effect, the claim is recorded without a restart.

Pre-effect regression (`tests/mutation_engine.rs:899`):

```sh
cargo test --locked --test mutation_engine apply_profile_refusal_resolves_its_claim_without_restart -- --nocapture
```

`base-profile-red.log`, `BASE_PROFILE_EXIT=101`:

```text
assertion `left == right` failed: pre-effect profile refusal must not orphan the claim
  left: "claimed"
 right: "spent"
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 13 filtered out; finished in 0.73s
```

GREEN: this test passes in `final-mutation.log` (14 passed, `RAW_EXIT=0`),
asserting a spent/non-NULL claim, exact persisted response error, and no
in-flight run step.

Unwind regression (`src/daemon.rs:8405`), exact probe/restore command:

```sh
cargo test --locked --lib abandoned_apply_claim_is_reaped_on_executor_unwind -- --nocapture
```

Probe: change the reaper's skip condition from `claim.status != "claimed"`
to `claim.status == "claimed"`. `probe-reaper-red-1.log`:

```text
assertion `left == right` failed: abandoned executor must not leave an in-flight claim
  left: "claimed"
 right: "ambiguous"
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 292 filtered out; finished in 0.02s
RAW_EXIT=101
```

After byte-restoration/recompilation, `probe-reaper-restored.log`:

```text
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 292 filtered out; finished in 0.07s
RAW_EXIT=0
```

This test also checks the claim remains owned while the executor is live, the
persisted `state.interrupted` error, an empty in-flight set after unwind, and
byte-unchanged outcome on a later scope exit. Its synthetic panic occurs outside
the state guard and is caught intentionally.

Disconnect regression (`tests/mutation_engine.rs:926`):

```sh
cargo test --locked --test mutation_engine disconnected_apply_is_resolved_after_its_effect_deadline_without_restart -- --nocapture
```

A private fake git executable starts a 30-second sleep, with a 1-second effect
deadline. The test observes the started/claimed state before dropping the
connection, checks another status connection, and bounds settlement by 10
seconds. `base-disconnect.log` already passed (`BASE_DISCONNECT_EXIT=0`);
this is a characterization of existing disconnect/deadline behavior, not a
claim that the reaper introduced it. Candidate `final-mutation.log` repeats:

```text
disconnected caller: claim=ambiguous code=adapter.timeout; no in-flight step; replay recorded
```

Residual: no age-based eviction or automatic replay of uncertain effects.
Whole-daemon SIGKILL/process abort cannot run destructors; existing boot
reconciliation remains responsible then. A poisoned state mutex or failed
SQLite resolution can prevent cleanup and emits `apply.reap_failed`; these
storage-failure cases were not fault-injected. No acceptance daemon or live
state was read or written. Executor unwind is a unit-level fault injection;
client disappearance/effect timeout is proved at the real daemon socket.

## 4. Keep refusal/retry semantics honest

The first full `just test` run at `a15bc34` was RED (`just-test.log`,
`RAW_EXIT=101`): the supervision role-binding fixture expected a corrected
prompt to succeed after its earlier refused prompt. Once that earlier refusal
was recorded, the EXISTING retry fence correctly returned
`refusal.run.retry_required`. Supervision's result was 16 passed / 1 failed.
This was a real fixture dependency exposed by the fix, not blamed on load.

`tests/supervision.rs:2944-2949` now authorizes the retry through the public
`run retry --run ... --step p3` CLI before the corrected dispatch. All original
refusal, bound-role, continued-session, real-stdout and journal assertions stay.
The production retry fence was not loosened. Operationally, a formerly lost
pre-effect refusal is now a visible failed attempt, so correcting its inputs
requires the same explicit bounded retry authorization as other recorded
failures.

```sh
cargo test --locked --test supervision the_prompt_runs_the_runs_declared_role_binding_and_continues_its_session -- --nocapture
```

`supervision-retry-green.log`, `SUPERVISION_RETRY_EXIT=0`:

```text
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 16 filtered out; finished in 2.46s
```

The complete supervision suite then passed (`v2-supervision.log`, 17 passed,
`RAW_EXIT=0`). Residual: refusal semantics remain fail-closed; this is not a
new automatic retry path.

## Structural audit inventory

Commands actually run, from the repository root:

```sh
ast-grep run -l rust -p '$S.lock_state()' src/daemon.rs
ast-grep run -l rust -k function_item --json=compact src/daemon.rs
ast-grep run -l rust -p 'finish_apply_refused($$$ARGS)' src/daemon.rs
```

The base lock query returned 68 call sites; the function inventory returned
117 function items. The whole apply body and all sibling handler guard/error
scopes were inspected, including helper calls and publication. `err_response`,
`ok_response`, `replay`, and logging do not lock state. Other mutations use
lexical scopes or `resolve_mutation_on(&guard)`. `park_retirement` and
`park_successor` release their match-scope guards before `finish_mutation`.
Restore retains its single guard through commit and drops it before publishing;
`compute_replay` preserves hub-to-state ordering. Lock-acquisition failure arms
own no guard. The new reaper drops its closure's guard before publication.

Full named inventory (base line numbers; brackets list lock-call lines):

```text
serve:251 locks=[410]
method_capabilities:650 locks=[]
method_doctor:670 locks=[]
summary_val:688 locks=[689]
method_status:696 locks=[]
method_state_epoch:727 locks=[728]
method_plan:747 locks=[]
resolve_run_binding:1141 locks=[1153]
admission_gate:1244 locks=[1294]
build_dispatch_request:1550 locks=[1557]
method_apply:1665 locks=[1742, 1780, 1829, 2042, 2059, 2145, 2224, 2260, 2313]
resolve_apply_refusal:2385 locks=[2392]
finish_apply_refused:2440 locks=[2450]
method_schedules:2600 locks=[2601]
method_schedule_create:2617 locks=[2654]
method_schedule_pause:2690 locks=[]
method_schedule_resume:2694 locks=[]
method_schedule_set_enabled:2698 locks=[2723]
method_schedule_delete:2771 locks=[2791]
method_schedule_evaluate:2834 locks=[2868]
method_grants_list:2921 locks=[2922]
method_queue_submit:2952 locks=[2968, 3034]
method_queue_status:3079 locks=[3093]
method_run_pause:3128 locks=[3148]
method_run_resume:3194 locks=[3214]
method_run_retry:3251 locks=[3271]
method_run_dispatch:3478 locks=[3491, 3626]
method_run_status:3651 locks=[3663]
method_supervision_status:3697 locks=[3709]
method_lane_replacement_request:3866 locks=[3958]
method_lane_replacement_advance:4021 locks=[4061]
method_lane_replacement_hold:4109 locks=[4139]
method_lane_replacement_cancel:4182 locks=[4211]
method_lane_replacement_status:4255 locks=[4266]
method_lane_checkpoint_create:4332 locks=[4383]
method_lane_checkpoint_status:4474 locks=[4485]
method_lane_retire:4526 locks=[4599, 4694]
park_retirement:4835 locks=[4844]
method_lane_start:4969 locks=[5051, 5079, 5258, 5289, 5400, 5458]
method_lane_adopt:5594 locks=[5661, 5690, 5897]
method_lane_successor_consume:5977 locks=[6041, 6059]
park_successor:6113 locks=[6122]
method_journal_tail:6278 locks=[6289]
journal_mutation:6338 locks=[6339]
method_grants_issue:6432 locks=[6514]
method_grants_revoke:6584 locks=[6601]
prune_backups_with_journal:6645 locks=[6652, 6685]
method_backup_create:6702 locks=[6706]
summary_tuple:6815 locks=[6816]
method_restore_begin:6824 locks=[6861]
finish_mutation:7021 locks=[7030]
publish_events:7158 locks=[7163, 7186]
compute_replay:7250 locks=[7254]
```

## Gate evidence and provenance

All tests ran locally on macOS from this lane, with `CARGO_BUILD_JOBS=2` and a
lane-private, out-of-tree `CARGO_TARGET_DIR`. They used isolated per-test
sockets/databases and fake adapters, never acceptance state/targets. Each gate
has a named raw log; the bounded runner records its command, HEAD, participating
file hashes, and raw exit. Its aggregate deadline is 1200 seconds per command;
mutation commands were bounded at 180 seconds. Initial shell exit markers are
preserved separately in `initial-raw-exits.log`.

| Exact command | Raw exit | Result | Named log |
| --- | ---: | --- | --- |
| `just --list` | 0 | Canonical recipes listed once | `just-list.log`, `initial-raw-exits.log` |
| `just fmt-check` | 0 | Formatting clean | `v2-fmt-check.log` |
| `just lint` | 0 | Clippy passed with warnings denied | `v2-lint.log` |
| `cargo test --locked --lib daemon::tests -- --nocapture` | 0 | 8 Rust tests passed | `final-daemon-unit.log` |
| `cargo test --locked --test mutation_engine -- --nocapture` | 0 | 14 Rust tests passed | `final-mutation.log` |
| `cargo test --locked --test daemon_rpc --test start_adopt --test profile_binding --test run_control` | 0 | 45 Rust tests passed | `siblings.log` |
| `cargo test --locked --test supervision` | 0 | 17 Rust tests passed | `v2-supervision.log` |
| `just test` | 0 | 649 Rust tests passed | `v2-just-test.log` |
| `just ci` | 0 | 649 Rust tests passed; docs/release/security passed | `v2-just-ci.log` |

The final aggregate reached every canonical stage. Raw security output included:

```text
Ran 21 tests in 1.325s
OK
advisories ok, bans ok, licenses ok, sources ok
    Scanning Cargo.lock for vulnerabilities (119 crate dependencies)
RAW_EXIT=0
```

`gitleaks` reported `no leaks found`. Rustdoc emitted one non-blocking
`private_intra_doc_links` warning for the unchanged `src/adapters.rs:1310`
link to `reap_group`; this is not a warning-free documentation claim.

The focused suites and mutation probes ran at `a15bc34`; the final static,
supervision and full gates ran at `9827a29`. Between those candidates, only the
six-line supervision fixture correction changed. The probe participants
`src/daemon.rs` and `tests/mutation_engine.rs` remained byte-identical:

```text
src/daemon.rs (base)        8e4574cac583dcccaf7f90bd281f072ea57c163e8ff4b63f38581ec649eaae77
src/daemon.rs (restored)    4a47a081b94ec7ac337f82a2a2709e3a0e0fd996d9ab1e3fb7ab89ce0397dd39
tests/mutation_engine.rs    c8113f97bcc711560954a539565e90722767daa930110a1d14518b0b7013e13c
tests/supervision.rs        d48300df12f8b89a1a51801d1c4691e861828c13717848f622eb78d722e45b93
src/daemon.rs deadlock probe 4e9d183ff1f5c8a631bbb42307fb3c17e98c311d7fa499db7d0c67c0de26bdc6
src/daemon.rs reaper probe  542ff0909d9059201e21372927b6ae0d9a228b54fb32077a9e1a913e2ee1b816
```

The base witness compiled the base daemon against the final regression-test
bytes. Mutation logs contain the mutated source hash; restoration was verified
by hash and `git diff --exit-code -- src/daemon.rs`. The final candidate also
has no diff from the probe candidate for either participant.

Other disclosed diagnostic failures: the first reaper unit run exited 101
because the generic daemon outcome builder discarded an ambiguous outcome's
error (`None` instead of `Some("state.interrupted")`). It was corrected to
reuse `apply_outcome`, and the focused suite then passed 8/8. The external
probe runner first exited 1 on its import before mutating anything; its import
was corrected before the recorded probes. The failed legacy supervision
fixture left a child daemon; only the recorded PID, verified against this
lane's private executable and fixture socket, was stopped and checked absent.

No hosted/Linux CI or live acceptance run is claimed. No merge, release,
main-branch update, issue/PR mutation, force push, gate bypass, or sibling-lane
worktree change was performed. This report is committed separately after the
candidate gates; delivered-head public-tree/scanner checks are recorded in the
local closeout logs before the single branch push.
