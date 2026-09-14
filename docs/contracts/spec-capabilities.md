# Spec: harness and forge capability negotiation

Refs #3, #7, #80. Family: `hf-capability/v1`. Fixtures:
[`capability/`](../../schemas/fixtures/capability/capability.harness.valid.json). Design commitment
(ADR-0003: adapters at a small typed capability boundary; unsupported
capabilities return a typed refusal and never silently fall back to shell
guessing).

## Negotiation envelope: `hf-capability/v1`

One side of a negotiation declares what its actor can do:

```json
{"schema":"hf-capability/v1","axis":"harness","actor":"hermes",
 "capabilities":["discover","start","prompt","observe","interrupt","outcome","identity"]}
```

- `axis` closed set: `harness` | `forge`.
- `actor`: stable opaque id for the tool (harness product name, `gh`,
  adapter profile id). Actor ids are adapter metadata, never core
  branching inputs (ADR-0003).
- `capabilities`: non-empty subset of the **closed per-axis sets** below.
  An unknown capability is refused (`capability.malformed.json` adds
  `teleport`), because a client that advertises things the contract does
  not define cannot be negotiated with safely.

### Closed capability sets

| Axis | Capabilities |
| --- | --- |
| `harness` | `discover` · `start` · `prompt` · `observe` · `interrupt` · `outcome` · `identity` |
| `forge` | `read_refs` · `read_issues` · `read_checks` · `create_pr` · `comment` |

Notes: `interrupt` = interruption/cancellation; `outcome` = terminal
outcome collection; `identity` = identity/read-back of the harness actor
(ADR-0003 adapter contract list). Forge read caps (`read_refs`,
`read_issues`, `read_checks`) are what read-only status/plan use; write
caps are gated by grants and phases ([spec-plans.md](spec-plans.md)).

## Negotiation semantics

1. The daemon/CLI asks an adapter for its capability declaration before
   using it (`capabilities` RPC method).
2. A missing or refused capability means the operation is **refused with a
   typed refusal** — never emulated by shell guessing, never downgraded to
   a weaker mechanism.
3. Adapters may declare additional detail in typed params, but the
   `hf-capability/v1` document itself stays closed; anything unknown is
   refused at the boundary.
4. Core planning never branches on actor ids; it plans against declared
   capabilities, and fake adapters in tests declare the same closed sets
   (ADR-0003: fake-adapter contract tests prove core planning without any
   installed harness).

## Adapter contract (issue #7)

Refs #7. Implemented in `src/adapters.rs`; verified by fake-executable
contract tests (`tests/harness_adapters.rs`) that public CI and fork PRs
can run with **no harness credentials** (AC7).

- **Official adapters**: Hermes (`hermes`), Claude Code (`claude`), Codex
  (`codex`), Pi (`pi`, earendil-works/pi — issue #33), and Jcode (`jcode`,
  1jehuang/jcode — issue #37) — adapter
  examples per ADR-0003, with declared version ranges in
  [compatibility.md](compatibility.md) (Hermes/Claude Code/Codex measured
  2026-09-06; Pi measured 2026-09-08; Jcode measured 2026-09-08) and the
  full closed harness
  capability set above.
- **Generic adapter**: the declarative `argv` kind — validated argv arrays,
  explicit capability declarations, bare executable names resolved through
  the allowlisted PATH (the verified absolute identity is what is spawned),
  bounded time/output, cancellation, redaction, typed exits. No shell
  evaluation, no command templates, no capability inference from prose, no
  dynamic plugin SDK (AC9).
- **Operations** (closed set): `start` binds a session handle; `prompt`
  delivers untrusted text as data — a single final argv element that can
  never alter adapter argv or policy (AC5); `observe`, `interrupt`,
  `outcome`, and `identity` run the workspace session protocol (session
  observation, interruption/cancellation, terminal outcome collection,
  identity read-back) through the workspace executable. The workspace
  invocation rows are a v1 candidate contract: their real-world parity is
  [awaiting-evidence] until the human-gated clean-host smokes (AC6), and
  fakes pin the exact argv shape in tests.
- **Role-bound session lifecycle (issue #92 F2)**: a harness step runs the
  **declared role binding** — the harness profile key is the run's
  `role_config` key (there is no default profile and none is inferred), the
  declared provider/model pair is passed through on the kind's documented
  flags, and the session identity the run bound is carried from
  `harness_start` into every `prompt` of that run:
  - Hermes: `hermes -p <role-key> [--provider <p> -m <model>] chat
    --continue <session> --create-if-missing -q <payload>` (the global
    flags are handled by the launcher's pre-parse; the continuation pair is
    the documented create-if-missing row). Pi/Jcode carry the provider/model
    pair on their own documented rows; no role-key flag is fabricated for a
    kind that has none;
  - the session identity of a queue run is derived ONCE from the run
    identity (`lane-` + 16 hex of the sha256 over `hf-run-session/v1|<run>`),
    so `start` binds it and every prompt continues exactly that session; a
    prompt that declares another session refuses `refusal.stale.identity`,
    a partial identity refuses `refusal.identity.incomplete`, and a prompt
    whose run never bound one refuses `refusal.session.unbound`;
  - the real child stdout is the step result (`result.transcript`); no
    transcript is synthesized and no binding is invented at the adapter.
- **Stable agent identity (AC3)**: an agent identity binds the Herdr
  workspace session id + a stable terminal/native-session identity + a
  generation counter. A mutable pane label is not part of the identity and
  cannot substitute for any part; binding without all three parts is refused
  (`refusal.identity.incomplete`), and an identity read-back that disagrees
  with the bound triple is refused (`refusal.stale.identity`).
- **Refusal and failure codes** (typed, `hf-error/v1` shape): `unknown.harness`
  (kind outside the closed set), `unknown.capability` (capability/operation
  not in the closed harness set or not declared), `refusal.unavailable.harness`
  (executable missing/unspawnable), `refusal.credentials` (auth failure —
  credentials stay in the harness, never in canter, AC8),
  `refusal.binding.missing` (the harness profile declares no explicit
  provider/model binding; the terminal prompt refuses — no default is
  inferred and no fallback model is substituted, issue #80),
  `refusal.malformed.output` (unparsable structured output),
  `refusal.stale.identity`, `refusal.identity.incomplete`,
  `refusal.request.malformed`, `refusal.session.unbound` (a harness step
  addressed the run's bound session but the run bound none; issue #92 F2),
  `adapter.timeout` (deadline exceeded, and the child's process group is
  verified empty by the bounded reaping loop — a best-effort
  `kill -9 -<pgid>` helper attempt first, then the group's live members
  terminated by positive pid until none remain; helpers are resolved from the
  ambient environment plus the standard system directories, never the child's
  allowlisted PATH, and one diagnostic line names what the whole termination
  did; the post-exit pipe read is bounded by the documented grace, so a
  surviving descendant can never extend the op — outcome class `ambiguous`),
  `adapter.process_death`
  (`ambiguous`), and `adapter.exit` (ordinary non-zero exit).
- **Boundaries**: adapters pass only the explicit environment allowlist
  (`env_allow`, spec-config.md), never read the host environment
  themselves, never store tokens, and never persist raw prompts or
  transcripts (AC8; trust model T5). Unknown or unavailable harnesses fail
  per-surface and never break independent read-only operations (AC4,
  observe.rs pattern).
- **Fake-adapter doctrine (AC1/AC7)**: the same core workflow/plan
  fixtures drive fake implementations of every adapter contract (fake
  executables declaring the same closed sets); every official adapter has
  exact-version contract tests for success, missing executable/auth,
  unsupported capability, timeout, cancellation, malformed output, stale
  identity, and process death (AC2).
- **Herdr lane-lifecycle reporting (issue #33 A2 pi adapter; issue #37
  jcode adapter)**: when a pi or jcode profile operation runs inside a
  Herdr pane (`HERDR_ENV=1` +
  `HERDR_PANE_ID` in the allowlisted environment), the adapter reports the
  lane through the workspace executable's `pane report-agent` row
  (pi: `--source custom:herdr-fleet-pi --agent pi`; jcode:
  `--source custom:herdr-fleet-jcode --agent jcode`), per Herdr's
  custom-integration contract (verified unchanged at Herdr 0.9.0). Typed-result
  mapping:

  | Typed result | Herdr report |
  | --- | --- |
  | `start` succeeded | `working` (lane active) |
  | terminal `prompt` — succeeded / failed / refused / ambiguous (timeout, process death, plain exit) | `idle` |
  | terminal `prompt` with `refusal.credentials` | `blocked` + static message `harness credentials required` (a provider key decision is needed; the message never carries credential text) |
  | terminal `prompt` with `refusal.binding.missing` | `blocked` + static message `harness provider/model binding required` (a declaration decision is needed — the profile has no `provider`/`model` binding pair; the message never carries binding values) |

  The `pane report-agent` input accepts `idle`/`working`/`blocked`/`unknown`,
  not the derived `done` status, so terminal one-shots report `idle`. A live
  0.9.0 scratch row read back as `idle`; consumers must accept both `idle` and
  `done` as settled because visibility/seen state may derive `done`. The older
  0.8.2 scratch evidence rendered an unseen custom-reported idle row as
  `done` while `agent explain` reported semantic `idle` (`.report-33.md`).
  Reporting is a best-effort sideband that never changes the typed op result
  and is a no-op outside Herdr (no `HERDR_ENV=1`). `herdr agent start --kind pi` is
  the substrate/orchestrator path for *interactive* pi panes (it requires
  a pane at an interactive shell prompt and is not drivable by a headless
  library adapter); headless adapter runs report through the pane rows
  above. Herdr has no `jcode` agent kind (owner decision, issue #37 — no
  upstream feature request), so jcode lanes register through the custom
  pane rows only. Releasing the reporting source's authority (`herdr pane
  release-agent`, same `--source`/`--agent`) is the lane owner's
  pane-closeout step for future daemon wiring. The rows are pinned by
  fake-`herdr` contract tests in `tests/harness_adapters.rs`.

## Harness neutrality consequences

- Hermes/Claude Code/Codex/Pi/Jcode are 1.0 **adapter examples**
  (issues #7/#33/#37/#80)
  with their own compatibility matrices
  ([compatibility.md](compatibility.md)); the domain core contains no
  product-name branches and no model/provider names. Pi's one-shot prompt
  row and Jcode's one-shot `jcode run` row source their
  `--provider`/`--model` argv pair from the harness profile's **explicit
  binding** (`harness.<key>.provider`/`model`, issue #80);
  the pair is declared input — never a code literal, never persisted,
  never on a wire — and a profile without the binding refuses the prompt
  (`refusal.binding.missing`: no default, no substitution); provider keys
  arrive only through the environment allowlist. Jcode's `--json` row
  emits a machine-readable envelope on stdout (top-level object with a
  `text` field plus the returned `provider`/`model`, shape measured
  against v0.84.0 on 2026-09-08); the adapter parses the transcript out
  of that envelope and surfaces the returned identity alongside the
  requested pair on the typed result (a requested/returned mismatch is
  observable and never silently coerced), and otherwise keeps raw stdout.
- An unknown or unavailable harness fails clearly without degrading
  unrelated read-only operations (issue #7 AC4; observe.rs pattern).
- Herdr and `gh` themselves are negotiated the same way; see
  [compatibility.md](compatibility.md).

## Fixture map

Accept: `capability.harness.valid.json` (full harness set), `capability.forge.valid.json`
(read subset). Refuse: unknown capability, unknown version.
