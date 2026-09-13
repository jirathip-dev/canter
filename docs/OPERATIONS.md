# Operations runbook

Task-ordered, human-oriented guide to operating `canter` day to day:
install → configure → observe → plan → daemon/service lifecycle →
grant-gated mutations (dry-run → apply → verify) → cleanup → recovery →
remote transport → upgrade. Every command below was exercised against the
real release binary (`cargo build --release --locked`) in a private,
disposable sandbox with **synthetic fixtures only** — a fake `gh`/`herdr` on
a controlled PATH, a synthetic local git checkout of `example-org/widgets`,
and isolated XDG config/state/runtime dirs. No repository, fleet, host
service manager, or external system was mutated; quoted outputs are trimmed
and host paths are redacted (`.../`), per the repository's public-data rule.

Normative contracts (authoritative; this runbook links, never duplicates):
[contracts/README.md](contracts/README.md) (corpus index),
[contracts/spec-cli.md](contracts/spec-cli.md) (envelopes/exit codes),
[contracts/spec-daemon.md](contracts/spec-daemon.md) (RPC),
[contracts/spec-plans.md](contracts/spec-plans.md) (plan/apply/grant/outcome
semantics),
[contracts/spec-lifecycle.md](contracts/spec-lifecycle.md)
(schedules/admission/cleanup/recovery/remote),
[RELEASING.md](RELEASING.md) (archives/upgrade policy).

Exit-code contract (with or without `--json`): 0 ok · 1 operational error ·
2 usage · 3 partial · 4 refusal · 5 config error. In `--json` mode stdout
carries exactly one `hf-output/v1` document; diagnostics go to stderr; JSON
output never prompts.

---

## 1. Install

Prerequisites: Rust 1.97.1 (pinned by `rust-toolchain.toml`), `git` on
PATH. `doctor` (section 3) additionally checks `herdr` >= 0.8.2 and
authenticated `gh`; nothing here installs them.

```console
$ git clone https://github.com/jirathip-dev/canter.git
$ cd canter
$ cargo build --release --locked
$ ./target/release/canter --version        # exit 0
canter 0.1.0
...
state schema version: 12
migration chain: m0001_initial_state_v1, m0002_workflow_engine_instances_v2, m0003_control_plane_evidence_v3, m0004_schedules_lifecycle_v4, m0005_lane_replacements_v5, m0006_lane_checkpoints_v6, m0007_lane_successors_v7, m0008_lane_replacement_profiles_v8, m0009_queue_submissions_v9, m0010_run_controls_v10, m0011_supervision_v11, m0012_queue_advances_v12
document schema families: hf-config/v1, hf-policy/v1, hf-output/v1, hf-error/v1, ...
```

`--version` reports the schema facts the binary was built against — the
same facts release archives bind to their provenance records
([RELEASING.md](RELEASING.md)).

Failure → remedy:

| Symptom | Remedy |
| --- | --- |
| `cargo build` fails to fetch | Offline host: pre-fetch with the committed `Cargo.lock` (`cargo fetch --locked`), then `--offline`. |
| `--version` exits != 0 | Wrong toolchain: install the pinned 1.97.1 (see [DEVELOPMENT.md](DEVELOPMENT.md)) and rebuild `--locked`. |

## 2. Configure

Prerequisites: a target repository identity of the form `owner/name`.

The CLI never writes files: `config init` prints an annotated
`hf-config/v1` template to stdout; you redirect it to the canonical XDG
location yourself.

```console
$ ./target/release/canter config init > ~/.config/canter/config.toml   # exit 0
$ $EDITOR ~/.config/canter/config.toml
```

Minimal document (schema + one repository; optional tables only — daemon,
policy, repository, harness, workflow, role):

```toml
schema = "hf-config/v1"

[daemon]
enabled = true

[policy]
overlay = "policy.toml"

[repository.widgets]
origin = "https://github.com/example-org/widgets"
branch = "staging"
enabled = true
```

Validate and inspect:

```console
$ ./target/release/canter config validate            # exit 0
config valid: .../.config/canter/config.toml
$ ./target/release/canter config validate --json     # exit 0
{"command":"config validate","data":{"config_path":".../.config/canter/config.toml",
 "policy_overlay":{"path":".../.config/canter/policy.toml","valid":true},
 "valid":true},"exit_code":0,"kind":"ok","schema":"hf-output/v1"}
$ ./target/release/canter config show --json         # exit 0
{"command":"config show","data":{"config_path":".../.config/canter/config.toml",
 "daemon_enabled":true,"daemon_socket":null,
 "repositories":[{"branch":"staging","enabled":true,"identity":"example-org/widgets",
 "key":"widgets","origin":"https://github.com/example-org/widgets"}], ...},
 "exit_code":0,"kind":"ok","schema":"hf-output/v1"}
```

Failure → remedy:

| Symptom (exit) | Envelope | Remedy |
| --- | --- | --- |
| Named overlay missing (5) | `policy.not_found` | Create the `[policy] overlay` file you named (it is never implicitly discovered). |
| Unsupported version (5) | `config.invalid`, `refusal: refuse-version` | `schema` must be `hf-config/v1` (and the overlay `hf-policy/v1`); see the template. |
| `--config PATH` unreadable (5) | `config.invalid` | Point `--config` at an existing file or fix permissions. |

## 3. Observe (read-only)

Prerequisites: nothing beyond what you are observing. `doctor` checks git,
`herdr`, and `gh` presence/versions/auth and the config document; it never
installs, starts, or stops anything.

```console
$ ./target/release/canter doctor --json              # exit 0
{"command":"doctor","data":{"checks":[
 {"detail":"git version 2.52.0","name":"git","status":"ok"},
 {"detail":"herdr 0.8.2 (declared minimum 0.8.2)","name":"herdr","status":"ok"},
 {"detail":"gh 9.9.9; authenticated; scopes: repo, read:org","name":"gh","status":"ok"}],
 "config":{"path":".../.config/canter/config.toml","status":"ok"}},
 "exit_code":0,"kind":"ok","schema":"hf-output/v1"}
```

The Herdr row is a CLI-version gate only. Issue #35 measured that 0.8.2
(protocol 20) and 0.9.0 (protocol 22) clients/servers reject both mixed
pairings with `protocol_mismatch`; see
[compatibility.md](contracts/compatibility.md). During a Herdr update, use
Herdr's own status/handoff workflow and update both endpoints rather than
reading the 0.8.2 doctor floor as mixed-version support. canter never
restarts either endpoint.

Declared read capabilities (static; no negotiation, no shell guessing):

```console
$ ./target/release/canter capabilities --json        # exit 0
{"command":"capabilities","data":{"capability":{
 "actor":"canter","axis":"forge",
 "capabilities":["read_refs","read_issues","read_checks"],
 "schema":"hf-capability/v1"}},"exit_code":0,"kind":"ok","schema":"hf-output/v1"}
```

`status` observes each enabled configured repository **from inside its
local checkout** (the invoking directory) through local git + authenticated
`gh`, plus a herdr probe. Bounded: at most 4 concurrent observers, 10s per
process; partial failures are explicit, never hidden.

```console
$ cd .../widgets-checkout
$ /path/to/canter status --json                      # exit 0
{"command":"status","data":{"expected_repositories":1,"freshness":"fresh",
 "observed_repositories":1,
 "observations":[
  {"completeness":"complete","freshness":"fresh","payload":{
   "compatible":true,"declared_minimum":"0.8.2","present":true,
   "source":"herdr --version","surface":"herdr","version":"0.8.2"},
   "schema":"hf-observation/v1","subject":{"id":"herdr","type":"host"}},
  {"completeness":"complete","freshness":"fresh","observed_at":"<ts>","payload":{
   "git":{"available":true,"branch":"staging","head":"ef1c...b4c8",
    "origin_matches":true,"source":"local git checkout","surface":"git"},
   "github":{"archived":false,"available":true,"default_branch":"staging",
    "identity_matches":true,"remote_identity":"example-org/widgets",
    "source":"gh api repos/owner/name","surface":"github"}},
   "schema":"hf-observation/v1","subject":{"id":"example-org/widgets","type":"repository"}}],
 "timings_ms":{"partial_failures":0,"requests":3,...}},
 "exit_code":0,"kind":"ok","schema":"hf-output/v1"}
```

Failure → remedy:

| Symptom (exit) | Envelope/detail | Remedy |
| --- | --- | --- |
| Missing prerequisites (3) | checks `status: "missing"`, e.g. `gh not found on PATH — GitHub reads need authenticated gh` | Install/auth the named tool; re-run `doctor`. |
| Config invalid (5) | `config.invalid` | Fix the config per section 2. |
| `github.available:false` (still 0) | `reason: "gh.unavailable"` | Degradation is explicit and reported, not hidden: authenticate `gh` or accept the local-only observation. |
| `git.available:false` (still 0) | `reason: "no_local_checkout"` | Run `status` from the repository's local checkout (or configure the repo you are standing in). |

### 3.1 Monitoring a lane on an unrecognized harness (jcode example)

herdr 0.9.0 recognizes a closed list of agent kinds at spawn ([ARCHITECTURE.md](ARCHITECTURE.md)
"Layer responsibilities"). A harness outside that list — jcode today, a
canter first-class adapter (issue #37) but not a herdr agent kind —
runs fine in a pane but never appears as a herdr agent-kind row, so
`herdr agent list` is the wrong surface for its lifecycle; the
agents-sidebar gap is expected, not a defect. Monitor the lane from
canter state and the pane rows instead:

1. **State and phase.** The daemon state store is the tracker: the lane's
   plan, route grant, instance, and recorded review evidence live there,
   and every applied step returns a typed `hf-outcome/v1` — `succeeded` |
   `failed` | `refused` | `ambiguous` | `superseded` (section 6;
   [spec-plans.md](contracts/spec-plans.md)). Refusals carry
   `hf-error/v1` codes (`refusal.credentials`, `refusal.grant.expired`,
   ...). The typed exit taxonomy applies to the client surface: 0 ok · 1
   operational · 2 usage · 3 partial · 4 refusal · 5 config error
   ([spec-cli.md](contracts/spec-cli.md)).
2. **Transcript.** The adapter's typed prompt result carries the step's
   transcript (jcode: parsed from the `--json` envelope's `text` field, or
   raw stdout when the output has no envelope shape). Raw prompts and
   transcripts are never persisted (AC8; trust model T5) — the journal
   records the step and its outcome, not the conversation. The live pane
   terminal stays available as the working transcript: `herdr pane read
   <pane>` reads it back at any time (no agent kind required). Herdr 0.9.0
   also returns recent output that is still in the unscrolled viewport; the
   issue #35 live and portable probes pin that behavior.
3. **Semantic lifecycle (adapter-side sideband).** When the pi/jcode
   profile operation runs inside a herdr pane (`HERDR_ENV=1` +
   `HERDR_PANE_ID` in the allowlisted environment), the adapter reports the
   lane through `herdr pane report-agent <pane> --source
   custom:herdr-fleet-pi|custom:herdr-fleet-jcode --agent pi|jcode
   --state ...`: start → `working`; a terminal prompt result → `idle`;
   `refusal.credentials` → `blocked` with the static message `harness
   credentials required`. `pane report-agent` has no `done` input, although
   Herdr may derive `done` for unseen settled agents; consumers accept both
   `idle` and `done`. Releasing the reporting source's authority (`herdr pane
   release-agent`, with the same `--source`/`--agent`) is the lane owner's
   pane-closeout row.

Truthful limits today: the pane rows come from the harness adapter inside
the pane — no canter daemon caller drives or consumes them yet in this
bootstrap, and the daemon state store is not wired to them; consuming the
rows in daemon-driven lifecycle reporting is future work on the shipped
issue #8 state. The full row contract is in
[spec-capabilities.md](contracts/spec-capabilities.md).

## 4. Plan (read-only)

Prerequisites: a configured repository (section 2) and either authenticated
`gh` (to derive the acceptance revision from the issue's live text) or an
explicit `--revision <40-hex>`.

`plan` renders a deterministic `hf-plan/v1` — the same inputs always
produce the same canonical bytes and sha256 `digest`, and `state_epoch` is
bound to the state it was computed against. **`plan` never applies
anything.**

Offline (explicit revision):

```console
$ ./target/release/canter plan example-org/widgets 7 \
    --revision 0123456789abcdef0123456789abcdef01234567 --json   # exit 0
{"command":"plan","data":{
 "digest":"816469e345ff69d255ccb4ed211326f0704dd16c3f2e6eabce2bd87fccd3e87b",
 "issue_source":"argument",
 "plan":{"issue":{"number":7,"revision":"0123...4567"},
  "plan_id":"hf_plan_facc0e46cf38511f","repository":"example-org/widgets",
  "schema":"hf-plan/v1","state_epoch":0,
  "steps":[{"id":"p1","kind":"checkout","params":{"ref":"staging"}},
   {"id":"p2","kind":"worktree_create","params":{"scope":"issues/7"}},
   {"id":"p3","kind":"harness_start","params":null},
   {"id":"p4","kind":"prompt","params":null},
   {"id":"p5","kind":"collect_outcome","params":null},
   {"id":"p6","kind":"review_evidence","params":null},
   {"id":"p7","kind":"merge","params":null},
   {"id":"p8","kind":"cleanup","params":null}],
  "workflow_hash":"a906f1289dee1b1d3f1a5fbe3641c0cfcf166dc645e7a3827d419f010767c01f",
  "workflow_id":"fleet-doctrine-1"}},
 "exit_code":0,"kind":"ok","schema":"hf-output/v1"}
```

Live (revision derived from the issue's redacted acceptance text through
`gh`):

```console
$ ./target/release/canter plan example-org/widgets 7 --json   # exit 0
{"command":"plan","data":{"digest":"5566...93d",
 "issue_source":"github",
 "plan":{"issue":{"number":7,"revision":"463becfc6674875eee85a7371b3c6037980424ab"}, ...}}
```

Failure → remedy:

| Symptom (exit) | Envelope | Remedy |
| --- | --- | --- |
| `gh` unavailable, no `--revision` (1) | `forge.unavailable` — "pass `--revision <40hex>` to render the plan offline" | Render offline with `--revision` or make `gh` available. |
| Unconfigured repository (2) | stderr: ``plan: no configured repository matches "not-configured"; configure it first (see `canter config init`); run `canter plan --help``` `` | Add the repository to the config (section 2). |
| Non-numeric issue / malformed `--revision` (2) | usage error on stderr | `<issue>` is a positive integer; `--revision` is exactly 40 hex. |

Determinism check: run the same offline command twice and diff — byte
identical stdout (the digest is over the canonical plan bytes).

## 5. Daemon + service lifecycle

Prerequisites: config with `[daemon] enabled = true` (section 2). The
daemon is a single-writer per-user state server: flock + SQLite state +
audit/event journals + one Unix socket. State location follows XDG
(`.../.local/state/canter/...` by default; isolate with
`XDG_STATE_HOME`); the socket defaults to the XDG runtime dir
(`.../canter/daemon.sock`) unless `--socket` or `config daemon.socket`
overrides it. A second daemon is refused.

Start (foreground — run it in a terminal or under a service unit, section
5.1):

```console
$ ./target/release/canter daemon run
# daemon.log: {"event":"daemon.start",...} {"event":"daemon.ready",
#  "message":"state open; reconciled 0 interrupted claim(s); serving .../canter/daemon.sock",...}
```

Probe from another terminal:

```console
$ ./target/release/canter daemon status --json       # exit 0 (live)
{"command":"daemon status","data":{"daemon":{"pid":<pid>,
 "started_at":"<ts>","version":"0.1.0"},
 "freshness":"fresh","state":{"active_grants":0,"epoch":1,"event_seq":0,
 "journal_seq":0,"pending_claims":0,"poisoned":false,"schema_version":10}},
 "exit_code":0,"kind":"ok","schema":"hf-output/v1"}
```

Stop the daemon with Ctrl-C / SIGTERM in the daemon terminal. The binary
installs no signal handler, so the socket file is **not** unlinked on exit:
immediately after a stop — or a crash — `daemon status` reports the stale
socket:

```console
$ ./target/release/canter daemon status --json   # after stop/crash: exit 1
{"command":"daemon status","error":{"code":"daemon.stale","details":null,
 "message":"a stale daemon socket exists at .../canter/daemon.sock; a fresh `daemon run` reclaims it","retryable":true},
 "exit_code":1,"kind":"error","schema":"hf-output/v1"}
```

Remedy: start a fresh `daemon run` — it reclaims the stale socket,
reopens/migrates the state, and reconciles interrupted claims on start;
verify with `daemon status --json` again (exit 0). Full recovery flow:
section 8.

The `daemon.absent` envelope below appears only when the runtime directory
never served a daemon (fresh boot or a fresh XDG runtime dir) or after the
stale socket has been reclaimed/removed:

```console
$ ./target/release/canter daemon status --json       # exit 1
{"command":"daemon status","error":{"code":"daemon.absent","details":null,
 "message":"no daemon is running on .../canter/daemon.sock; read-only commands (doctor/status/plan) stay available without it","retryable":false},
 "exit_code":1,"kind":"error","schema":"hf-output/v1"}
```

Read-only commands stay available without the daemon.

Failure → remedy:

| Symptom (exit) | Detail | Remedy |
| --- | --- | --- |
| Second daemon refused (1) | stderr: `another daemon is already running: another daemon holds the lock (pid <pid> ...)` | One daemon per user by design; probe with `daemon status`, do not stack daemons. |
| No daemon (1) | `daemon.absent` | Start `daemon run` (or the service unit). |
| Stale socket (1, retryable) | `daemon.stale` — "a stale daemon socket exists ...; a fresh `daemon run` reclaims it" | Start a fresh `daemon run`; it reclaims the socket (section 8). |
| Wrong socket probed | `daemon.absent` naming a path you did not serve | Match `--socket` (or config `daemon.socket`) between `run` and `status`, or use the default path on both. |

### 5.1 Service units (plans only — never activated by the CLI)

`service doctor` checks the daemon environment read-only; the `*-plan`
commands render the first-party per-user launchd/systemd unit text and the
exact host steps. **They never install, start, stop, or query the host
service manager** — a human executes the rendered steps on the target host.

```console
$ ./target/release/canter service doctor --json      # exit 0
{"command":"service doctor","data":{"checks":[
 {"detail":"systemd","name":"platform","status":"ok"},
 {"detail":"daemon.enabled=true","name":"config","status":"found"},
 {"detail":"daemon not running","name":"socket","status":"absent"},
 {"detail":".../.config/systemd/user/canter.service","name":"service-unit","status":"absent"}],
 "summary":{"daemon":"absent","platform":"systemd","unit":"absent"}},
 "exit_code":0,"kind":"ok","schema":"hf-output/v1"}
```

```console
$ ./target/release/canter service install-plan --json   # exit 0
{"command":"service install-plan","data":{"platform":"systemd",
 "steps":[
  "write the rendered unit to .../.config/systemd/user/canter.service (content printed by the install command)",
  "run: systemctl --user daemon-reload",
  "run: systemctl --user enable --now canter.service",
  "verify: systemctl --user --no-pager status canter.service"],
 "target":".../.config/systemd/user/canter.service",
 "unit":"# canter per-user daemon unit (issue #5; rendered, not activated)
[Unit]
Description=canter state daemon (single writer per user)
...
[Service]
Type=simple
ExecStart=<canter-binary> daemon run --socket .../canter/daemon.sock
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
...
"}, "exit_code":0,"kind":"ok","schema":"hf-output/v1"}
```

`service status-plan` renders the verification steps and `service
uninstall-plan` the removal steps for the same unit; both exit 0 and both
contain the unit text for inspection.

Failure → remedy:

| Symptom (exit) | Detail | Remedy |
| --- | --- | --- |
| `service doctor` rows not ok | e.g. `daemon.enabled=false` in config, socket absent | Enable the daemon in config / start the daemon first; re-run `service doctor`. |
| Wrong platform unit | `platform` row says `launchd`/`systemd` | The renderer targets the host it runs on; run `*-plan` on the target host (macOS → launchd, Linux → systemd). |

## 6. Grant-gated mutations (daemon `apply` — RPC only)

Boundary: the CLI surface never mutates repositories, sessions, or external
state. The mutation paths are the daemon `apply` RPC over the local socket
(issue #8 semantics, [spec-plans.md](contracts/spec-plans.md),
[spec-daemon.md](contracts/spec-daemon.md)), the explicitly authorized
`canter lane request` record (section 11) — the latter records a durable
request and has no spawn, kill, signal, Git, grant, or resume effect — and
the supported mint path below, which only inserts a durable grant row in the
daemon's own state (no repository, session, signal, Git, or external effect).
The material below is the operator
workflow in terms of the documented contract and is **synthetic guidance**:
this repository never mutates real repositories, fleets, or external state,
and its tests use disposable local repositories and fakes only.

Workflow: **render → grant → apply one step at a time → verify**, always
with a fresh interactive TTY for production-branch effects.

1. **Dry-run (render + validate).** Render the plan (section 4), keep the
   envelope: `plan_id`, `digest`, `state_epoch`, and the exact step ids are
   what grants and applies bind to. A plan's digest is over its canonical
   bytes; any tamper changes the digest and apply refuses it
   (`refusal.plan.identity`).
2. **Grant.** A route grant (`hf-grant/v1`) is the only authorization to
   start durable work. It binds repository, plan digest, capabilities,
   role/policy hashes, `state_epoch`, expiry, and instance. Grants are
   issued/consumed by the daemon, expire, and die with their epoch.
   The SUPPORTED mint path is `canter grant issue`, a thin CLI over the
   daemon's closed `grants.issue` method — the same method any other client
   may call, journaled before the row and exactly-once per idempotency key.
   Review the run first (`canter queue preview ... --out request.json`), then
   mint the grant for ONE reviewed issue:

       canter grant issue --request request.json --issue 92 --expires-in 3600

   Every binding is derived from that reviewed document plus the
   configuration re-observed now plus the live epoch — never typed by hand:
   repository identity, `issue.number` + acceptance revision,
   `workflow_hash`, `policy_hash` (the reviewed role-configuration
   revision), `phase`, `caps`, `scope` (`worktrees/issues/N`), `state_epoch`
   and the explicit expiry. A moved role revision
   (`refusal.profile.revision`), a moved epoch (`state.epoch_mismatch`), an
   already-expired window (`refusal.grant.expired`), a production-class
   binding (`refusal.policy.production_confirmation`) and a foreign or
   malformed document (`usage.grant_request`) all refuse typed before any
   row exists. Minting is NOT authorization: the returned `gr_` id is
   presented at the board / `queue submit` point, which stays the
   authorization. `grants.list` shows live grants; `grants.revoke` cancels
   one.
3. **Apply.** `apply` executes **one plan step per request** and requires
   `params.idempotency_key` (`ik_` + 8-64 `[a-z0-9-]`). The daemon
   recomputes the digest before anything is journaled, then revalidates
   under the state lock: live epoch vs plan/grant/instance, grant status
   and expiry (expired → `refusal.grant.expired`), the observed issue
   revision vs the grant binding, workflow/policy hashes, and the step's
   required capability. The intent is journaled (`mutate.*`) before the
   effect; the effect runs outside the lock through allowlisted
   subprocesses; the response is a typed `hf-outcome/v1`.
4. **Verify.** Read the exact result back: the recorded outcome for a
   consumed idempotency key is returned instead of re-dispatching
   (exactly-once read-back; at-most-once dispatch). Replaying a request id
   + key returns the recorded response. Kind-specific verification gates
   run before sensitive steps: an integration merge requires current
   review evidence bound to head/base/workflow/policy (moved bindings →
   `refusal.evidence.stale`); issue closure requires the instance to sit at
   `post_merge_verify` with passing evidence; production-branch effects
   require a fresh interactive TTY-confirmed digest; real-external target
   scopes require the recorded first-write approval.

Outcome statuses: `succeeded` | `failed` | `refused` | `ambiguous` |
`superseded`. `failed`/`refused` outcomes carry an `hf-error/v1`-shaped
error. `ambiguous` (timeout, process death, post-effect record failure)
**always requires external reconciliation before a new key**.

Failure → remedy:

| Symptom | Detail | Remedy |
| --- | --- | --- |
| Apply refused | `refusal.plan.identity` | The carried plan bytes were tampered; re-render and re-grant. |
| Apply refused | `refusal.grant.expired` / epoch mismatch | Re-issue a grant against the live epoch; material edits or restore rotated the epoch and invalidated prior grants. |
| Merge refused | `refusal.evidence.stale` | Re-review at the moved head; evidence must bind the current head/base/workflow/policy. |
| Outcome `ambiguous` | interrupted/restored work | External reconciliation required before a new idempotency key — never blindly retry. |
| Mutation request rejected | missing/`ik_`-malformed idempotency key | Every mutating apply requires a well-formed `params.idempotency_key`. |

## 7. Cleanup and archives

- **Worktree cleanup / salvage** (issue #9): the daemon's cleanup path
  archives rather than destroys — cleanup keeps its salvage audit pair
  (`mutate.cleanup` before, `salvage.cleanup` after) with byte-verified
  manifests. Operator-facing semantics, retention, and audit deletion:
  [spec-lifecycle.md](contracts/spec-lifecycle.md) sections 5 and 7.
- **Backups**: `backup.create` snapshots state through the daemon;
  retention-bounded pruning keeps the backup set bounded. Restore is an
  epoch event: `restore.begin` creates a new state epoch, marks interrupted
  work `ambiguous`, invalidates prior grants/digests, and only then do new
  grants issue — see [spec-plans.md](contracts/spec-plans.md) (epoch restore) and
  [spec-lifecycle.md](contracts/spec-lifecycle.md).
- **Release archives** (issue #10) are a separate, human-gated surface:
  deterministic platform archives with checksums + offline SBOM +
  provenance are built by `scripts/build-archive.py` per
  [RELEASING.md](RELEASING.md); release execution is human-only.

## 8. Recovery after crash / cold boot

The daemon is designed to be restarted freely; state is SQLite + journals,
and the socket is reclaimable.

```console
$ ./target/release/canter daemon status --json   # after a crash/kill: exit 1
{"command":"daemon status","error":{"code":"daemon.stale",...,
 "message":"a stale daemon socket exists at .../canter/daemon.sock; a fresh `daemon run` reclaims it",...},
 "exit_code":1,"kind":"error","schema":"hf-output/v1"}
```

Remedy — start a fresh daemon; it reclaims the stale socket, opens/migrates
the state, and reconciles interrupted claims:

```console
$ ./target/release/canter daemon run     # foreground; on ready, daemon.log shows
#  "state open; reconciled 0 interrupted claim(s); serving .../canter/daemon.sock"
$ ./target/release/canter daemon status --json    # exit 0 — live again
{"command":"daemon status","data":{"daemon":{"pid":<pid>,...},
 "state":{"active_grants":0,"epoch":1,...}},"exit_code":0,"kind":"ok","schema":"hf-output/v1"}
```

- **Cold boot**: the daemon runs the same recovery plus one fresh
  evaluation per due schedule before the socket serves; recovery never
  depends on herdr/git/gh being present (spec-lifecycle.md section 3).
- **Journal inspection**: `journal.tail` reads the audit/event streams;
  interrupted claims are reconciled at startup (the journal is the
  authority for what was journaled before an effect).
- **Restore after corruption/restore events**: epoch rotates (section 7);
  interrupted work becomes `ambiguous` and needs external reconciliation.
- Read-only commands never need the daemon — observing and planning stay
  available while the daemon is down.

### 8.1 Integration branch deleted (staging)

`staging` is the permanent integration branch and the HEAD of every
promotion PR (`staging` → `main`; see [WORKFLOW.md](WORKFLOW.md),
"Promotion (staging → main)"). If the repository's automatic head-branch
deletion setting (`delete_branch_on_merge`, "automatically delete head
branches") is enabled, merging a promotion PR deletes `staging` itself —
this happened after promotion PR #28 and blocked all later merges until a
maintainer recreated the branch by hand. The CI `policy` job fails every
run while `staging` is missing ("Integration branch exists (staging
guard)" step); restore the branch before merging anything else:

1. Confirm the branch is missing — empty output means gone:

   ```console
   $ git ls-remote origin refs/heads/staging
   ```

2. Find the last known head SHA of `staging`. Candidates, in order:

   - the deleted promotion PR's head SHA — GitHub keeps it after deletion
     (`gh pr view <pr> --json headRefOid`),
   - a local remote-tracking ref fetched before the deletion
     (`git rev-parse refs/remotes/origin/staging`), or
   - the promotion squash-merge commit on `main` (it was created from
     `staging`'s head).

3. Restore the branch from that SHA:

   ```console
   $ git push origin <last-known-sha>:refs/heads/staging
   ```

   If the ruleset rejects the direct push to the long-lived branch, create
   the ref through the GitHub refs API instead (run inside a checkout of
   this repository so `gh` fills in `{owner}/{repo}`):

   ```console
   $ gh api --method POST repos/{owner}/{repo}/git/refs \
     -f ref=refs/heads/staging -f sha=<last-known-sha>
   ```

4. Verify the restore, then re-check the setting:

   ```console
   $ git ls-remote origin refs/heads/staging    # must print the restored SHA
   ```

   Confirm the repository's automatic head-branch deletion
   (`delete_branch_on_merge`) is **off** — a promotion PR whose head is
   `staging` must never auto-delete it again. Restoring the ref directly
   is the recovery action; it is not a PR and does not change promotion
   policy.

## 9. Remote transport boundary

The system-SSH remote transport is a **verified contract**, not a live
background feature of the CLI: the surface an operator reaches is local
(git/gh/herdr on the invoking host; the daemon on the per-user socket).
Remote semantics — what may cross an SSH boundary, and the verified
transport contract — are specified in
[spec-lifecycle.md](contracts/spec-lifecycle.md) section 6. Nothing in this
repository connects outward from CI or lanes, and no harness session runs
from public CI or fork PRs.

## 10. Upgrade

1. Pull the new release, rebuild pinned: `cargo build --release --locked`.
2. Check the schema facts: `canter --version` (migration chain must
   include the new `mNNNN_*` entry).
3. Stop the daemon/service (Ctrl-C, or the service steps from section
   5.1), start the new binary — the daemon opens/migrates SQLite state on
   start (`daemon.ready` in `daemon.log`), then verify with
   `daemon status --json` (state row shows `schema_version`).
4. Re-issue grants after any restore/epoch rotation (section 7); schedules
   survive restarts by design and stay paused until explicitly resumed.
5. Release/version policy, archive verification, and rollback notes:
   [RELEASING.md](RELEASING.md).

**Pre-rename compatibility (issue #106).** A state/runtime tree or config
created under the old `herdr-fleet` name is adopted in place — no migration
step, no copy, and nothing deleted — and the pre-rename `herdr-fleet` binary
name, `HERDR_FLEET_CRASH_POINT`, and live Herdr source ids keep working. The
single normative list is the
[compatibility contract](contracts/compatibility.md#product-rename-issue-106)
(also: the archive/executable name is now `canter-<version>-<platform>`).

---

## 11. Lane handoff for ONE explicit lane: preview / request / status

Boundary: this surface is **thin and read-only except for one explicitly
authorized request record**. `canter lane preview` and `canter lane status`
perform no mutation at all — they may issue only the read-only
`lane.replacement.status` / `lane.checkpoint.status` reads (a closed
allowlist guard refuses any other method before a socket is opened), they
never prompt, and they never advance a record. `canter lane request`
records **one durable replacement request** at phase `requested`; it never
spawns, kills, signals, touches Git, issues a grant, resumes a paused
fleet, or performs any of the handoff's later effects (checkpoint,
retirement, start, adoption — those remain the daemon RPCs documented in
[spec-daemon.md](contracts/spec-daemon.md)).

Workflow: **preview → authorize → request → inspect**, always for ONE
exact lane (a `--lane` slug + `--generation`, or a `--replacement` id).

1. **Preview** (read-only). Render the reviewable plan:

       canter lane preview --lane lane-0001 --generation 1 \
         --session sess-1 --process proc-1 --role implementer \
         --worktree worktrees/issues/78 --reason 'rotate the implementer lane' \
         --profile lane-harness --json

   The `hf-lane-handoff/v1` plan shows: the source identity
   (session/process/role/generation), the target profile plan
   (`--profile KEY` derives the reviewed `hf-profile-binding/v1` document
   from the configuration — the same plan `canter config show` previews,
   revision included; a changed configuration or credential produces a new
   revision), the repository-relative worktree, the closed effect-boundary
   chain, the retained workers/reviewers/pending gates (captured at the
   `checkpointed` boundary; the committed checkpoint's references are shown
   when one exists), the authorization requirement derived from the policy
   overlay, and the **plan digest** (sha256 over the plan inputs and the
   bound profile document).

2. **Authorize.** The authorization binds the exact plan digest. Either
   path binds the SAME digest:
   - noninteractive explicit: pass the digest from the preview,
     `--confirm-digest <64-hex>`;
   - human confirmation: `--confirm` prints the digest to stderr and the
     human types it (an empty line or `abort` refuses; a different digest
     refuses as a stale plan).

   A blanket `--yes` authorizes without binding the content and is
   **refused** whenever the policy overlay declares a
   `production_confirmation` rule: `tty` requires the digest
   (`refusal.confirmation.policy`), `deny` refuses every mode
   (`refusal.policy.production`). The overlay can only tighten.

3. **Request.**

       canter lane request --lane lane-0001 --generation 1 \
         --session sess-1 --process proc-1 --role implementer \
         --worktree worktrees/issues/78 --reason 'rotate the implementer lane' \
         --confirm-digest <64-hex> --profile lane-harness

   Records the record at phase `requested` (daemon
   `lane.replacement.request`). Automation that needs replay semantics
   passes `--idempotency-key ik_...`; otherwise a fresh key is generated
   per invocation. A second request for the same lane generation is the
   daemon's typed `refusal.replacement.exists` — a record is never
   silently overwritten.

4. **Inspect** (read-only). `canter lane status` reads the record, its
   exact transition history and the committed checkpoint:

       canter lane status --replacement rp_0123456789abcdef --json
       canter lane status --lane lane-0001 --generation 1

   The output carries `phase`, `outcome`, `blocker` (the recorded
   non-pending reason), `intended` (the bound profile revision and
   provider/model), `actual` (the successor verification evidence; an
   unsupported introspection stays `unknown` with a null pair — never a
   copy of the intended), `last_transition`, `next` (the next allowed
   transition and the daemon operation that performs it; this CLI slice
   exposes preview/request/status only) and `guidance`.

**Guidance for the four parked scenarios** (all read-only; nothing is
signalled, killed, or resumed by the CLI):

| Scenario | What status reports | Guidance names |
| --- | --- | --- |
| Ambiguous retirement | `outcome: ambiguous` + the recorded reconcile reason | external reconciliation is required before it can advance; re-inspect with `canter lane status` |
| Capacity hold (record at `retired`) | `phase: retired`, `next.phase: starting` | the admission refusals (`refusal.admission.cap_global` / `cap_repository` / `cap_harness`) hold without a state change: free capacity and retry the same start; the bounded attempt counter refuses `refusal.successor.attempts` |
| Failed adoption | `phase: adopting`, or `ambiguous` after a parked failure | a differing re-query refuses (`refusal.successor.differs`) and is never replayed as success; re-inspect with `canter lane status` |
| Unknown model binding | `actual.status: unknown` with null provider/model | the bound profile declares no binding introspection; the actual is never copied from the intended — re-inspect, or start a new generation under a profile that declares introspection |

**While the fleet is PAUSED** (its automation schedule durably disabled):
`canter lane status` stays useful and `canter lane request` still records
the request, but no CLI path enables a schedule, advances a record, starts
a successor, or otherwise resumes anything — there is no hidden
auto-resume.

**JSON contract.** `--json` writes exactly one `hf-output/v1` document to
stdout (diagnostics go to stderr) and never prompts: a missing
authorization is the typed usage refusal `usage.confirmation_required`
(exit 2); `--confirm` is refused with `--json`. Exit codes: 0 ok; 1
daemon/transport error (`daemon.absent` / `daemon.stale` / `client.read`
on the bounded 15s read deadline); 2 usage; 4 refusal (`refusal.plan.stale`,
`refusal.confirmation.policy`, `refusal.policy.production`, the daemon's
typed refusals, `state.not_found`); 5 config/policy error (e.g. `--profile`
naming an unknown or unbound harness). The human rendering carries the
same digest, phase, bindings, transition, next action and error code.

## Appendix: command/exit summary

| Command | Read-only? | Typical exit |
| --- | --- | --- |
| `config init` / `config validate` / `config show` | yes | 0; 5 on config/policy errors |
| `doctor` | yes | 0 ok; 3 missing/degraded; 5 invalid config |
| `status` | yes | 0 (degradations explicit); 5 config errors |
| `plan` | yes (never applies) | 0; 1 `forge.unavailable`; 2 usage; 5 config errors |
| `capabilities` | yes | 0 |
| `daemon run` | local state server (no fleet/external mutation) | foreground; 1 when another daemon holds the lock |
| `daemon status` | yes | 0 live; 1 `daemon.absent`/`daemon.stale` |
| `lane preview` / `lane status` | yes (read-only reads only; no mutation, no prompt) | 0; 1 daemon/transport (incl. bounded read timeout); 4 `state.not_found`/daemon refusals; 5 config errors |
| `lane request` | records ONE authorized request (no spawn/kill/Git/grant; never resumes a paused fleet) | 0; 1 daemon/transport; 2 usage; 4 refusals (`refusal.plan.stale`, `refusal.confirmation.policy`, `refusal.policy.production`, daemon refusals); 5 config errors |
| `service doctor` / `install-plan` / `status-plan` / `uninstall-plan` | yes (plans only) | 0 |
| daemon `apply` RPC | **grant-gated mutation** (one digest-bound plan step per request, idempotency-keyed) | typed `hf-outcome/v1`; refusals are typed and never downgraded |
