# Spec: XDG TOML configuration and policy overlay

Refs #3, #80, #77. Family: `hf-config/v1` (config), `hf-policy/v1` (overlay). Fixtures:
[`config/`](../../schemas/fixtures/config/config.valid.toml), [`policy/`](../../schemas/fixtures/policy/policy.valid.toml),
manifest rows in [`schemas/fixtures/manifest.jsonl`](../../schemas/fixtures/manifest.jsonl).
Design commitment (locked spec: "One canonical XDG TOML config plus one
explicit optional policy overlay; no implicit profile/repository merge
stack").

## Config: `hf-config/v1` (TOML)

- Location: explicit `--config` path wins; otherwise XDG default
  (`$XDG_CONFIG_HOME/canter/config.toml`; a pre-rename
  `herdr-fleet/config.toml` is still discovered when the new path holds
  none — see [compatibility.md](compatibility.md#product-rename-issue-106)).
  Values below are portable; no machine-specific default is compiled in.
- The config is **one canonical file**. There is no implicit merge stack of
  profiles/repositories/hosts. Additional input arrives only through the
  single explicit overlay (below).
- Unknown keys anywhere in the document are refused (closed v1 surface).
- Axes compose but never infer: harness, model/provider, role, skills,
  workflow, policy, repository, and execution substrate are separate
  tables/entries; none is derived from another, and no model/provider name is
  a core assumption.

### Normative fields

| Key | Type | Required | Meaning |
| --- | --- | --- | --- |
| `schema` | string | yes | `"hf-config/v1"` |
| `daemon.enabled` | bool | no | run the local daemon (defaults apply when absent) |
| `daemon.socket` | string | no | explicit socket path override; default derives from the XDG runtime dir — portable default only |
| `policy.overlay` | string | no | explicit relative/absolute path of the optional policy overlay; no implicit discovery |
| `repository.<key>` | table | no | one configured repository per key (slug); `origin` (string URL) required; `branch`, `enabled` optional |
| `harness.<key>` | table | no | adapter profile per configured harness: `kind` (string; e.g. `argv`), `executable` (name resolved via PATH, never an absolute path), `env_allow` (array of environment variable names — the explicit allowlist), and the optional `provider`/`model` binding pair: bare tokens, declared together, used by the official prompt rows that carry the pair on argv (`pi`, `jcode`). Without the binding the terminal prompt refuses (`refusal.binding.missing`) — there is no default and no substitution. Issue #77 adds the optional profile-planning keys `fallback` (array of authorized `"provider/model"` bare-token pairs), `secret_env` (credential environment NAMES, each already declared in `env_allow`), `limits` (a table of string/integer metadata overrides — reported as configured limits, never as proof of provider support) and `binding_introspection` (boolean: the profile can report the bound provider/model back). Issue #267 adds `skills` (array of skill keys): the **role skills this role binding gives its lane**, each resolved against the `skill.<key>` inventory |
| `workflow.<key>` | table | no | pinned workflow selection: `id` + `hash` (64-hex sha256 over the canonical workflow document) |
| `role.<key>` | table | no | custom roles only, explicit and hash-pinned: `hash` (64-hex) |
| `skill.<key>` | table | no | the declared **resolvable skill inventory** (issue #267): `hash` (64-hex content identity of the installed procedure, the install readback). A role binding that declares a skill the inventory does not name refuses typed (`refusal.skill.unresolved`) wherever a plan binds the role — never a lane started without its role procedure |

Synthetic valid example: `config/config.valid.toml` (one repository
`example-org/widgets`, one harness, one workflow pin — all values fictional).

## Policy overlay: `hf-policy/v1` (TOML)

- The overlay is **explicit, optional, and constrain-only**: it can add
  restrictions on top of the canonical config and can never relax or remove
  a core key. "No implicit profile/repository merge stack" means exactly
  one overlay, named by `policy.overlay`, applied in addition to the one
  canonical file.
- Overlay content is downstream-owned policy (ADR-0001: models/providers,
  organizational role policy, allowlists live downstream); the public repo
  only specifies the shape.

### Normative fields

| Key | Type | Meaning |
| --- | --- | --- |
| `schema` | string | `"hf-policy/v1"` |
| `repositories` | [string] | repository allowlist (`owner/name`); narrows which configured repositories may be acted on |
| `production_confirmation` | string | `tty` (fresh interactive TTY confirmation required, the base rule) or `deny` (block production/destructive entirely); any other value refused — the overlay may only tighten |
| `role.<key>.hash` | string | pins/hash-locks a role that the overlay may add; 64-hex |

An overlay that constrains nothing is refused (an empty overlay is a config
error, not a no-op).

## Profile-configuration revision and preview (issue #77)

`canter config show --json` previews, per bound harness, the exact
`hf-profile-binding/v1` plan a human reviews before requesting a lane
replacement: the target profile key/kind, the intended `provider`/`model`
(sourced from the supported profile configuration — never a code literal),
the authorized `fallback` pairs, the `configured_limits` (metadata
overrides; they are declared configuration, not provider support), the
declared `introspection` support, the credential DIGESTS and the
`revision`. The same row reports the declared credential NAMES as
`present`/`missing` — a credential VALUE is never read into a report or a
log. The revision is the sha256 over the canonical material
(domain-separated; a missing credential is bound as `unset`), so any
relevant configuration OR credential change produces a different revision
and invalidates a previously reviewed plan: a daemon start under a changed
revision refuses (`refusal.profile.revision`) and a newly reviewed plan is
required, while a revision that does not fingerprint its own material is
refused at the boundary. A plan under an unchanged revision keeps binding.

## Role skills: declared per leg, resolved against the installation's inventory (issue #267)

- A lane is an untrusted worker judged by its artifacts; what procedure it is
  given is **configuration**, never an accident of the profile it happens to
  run under. `harness.<key>.skills` declares the role skills one role binding
  gives its lane, and the `hf-profile-binding/v1` material carries them
  resolved: one `{"key", "hash"}` pin per declared skill, where `hash` is the
  `skill.<key>` inventory's content identity for that procedure. The binding
  revision fingerprints the pins, so a moved procedure (or a moved binding)
  moves the revision and every plan that bound it.
- Resolution is **total and fail-closed**: one declared key the `skill.<key>`
  inventory does not resolve refuses the whole binding with the typed
  `refusal.skill.unresolved` (exit 4) at the plan boundary — `queue preview`,
  `queue submit`, `queue intake`, `grant issue` and the operator surface all
  derive their binding from the same configuration — and the refusal happens
  BEFORE any run, worktree or pane exists.
- **Backward compatibility (issue #279):** the `skills` entry was added to the
  material by #269, so a binding approved BEFORE it carries no `skills` key at
  all, and such a document's revision fingerprints the material as it stood
  then (the same document without that entry). An ABSENT key resolves to the
  empty array the shape already allows and is verified against that pre-#269
  material, so a stored pre-#269 binding stays dispatchable instead of
  refusing `refusal.profile.binding` forever; such a binding's `revision_of()`
  still reproduces the revision it was approved under and it re-serializes to
  the same document, so a surface that re-renders it (the review outcome, a
  stored lane plan) never writes a document the next read refuses. Only the
  absent key is tolerated: a PRESENT `skills` value is validated exactly as
  before (an array of well-formed `{key, hash}` pins, no duplicates), and a
  malformed, mis-keyed or duplicated pin still refuses typed.
- The canonical procedure sources for the three doctrine role contracts ship
  in this repository as installable skills (`skills/lane-implementer`,
  `skills/lane-reviewer`, `skills/lane-orchestrator`). They are sources, not
  requirements: a repository unrelated to canter binds its own skill names,
  and nothing in the engine requires a canter-named skill of any lane. The
  per-hand-install adapters that place these sources in a harness's native
  location remain issue #203's scope.
- `canter config show` reports, per harness row, the declared skills with the
  identity each resolves to (`hash: null` marks an unresolved declaration) so
  the operator can fix the configuration before a plan refuses.

## Compatibility and refusal

- A declared `harness.<key>.fallback` entry must be a `"provider/model"`
  pair of bare tokens; each `harness.<key>.secret_env` name must be a bare
  name already declared in `env_allow` (credentials arrive only through the
  explicit allowlist, trust model T5); `limits` values are bounded
  strings/integers. Violations refuse at load (`config.invalid`, naming the
  `config.harness.<key>.<field>` path).
- A declared `harness.<key>.provider`/`model` binding must be a bare-token
  pair: non-empty, no whitespace, no path separators. Malformed, blank, or
  half-declared values are refused at load (`config.invalid`, naming the
  `config.harness.<key>.<field>` path — issue #80). An absent binding is
  not a config error; the terminal prompt refuses instead
  (`refusal.binding.missing`, [spec-capabilities.md](spec-capabilities.md)) —
  no default and no fallback model are inferred.
- Exact version match required: `hf-config/v2` or any other version is
  refused (`REFUSE_VERSION`), as is a missing/foreign `schema`
  (`REFUSE_SCHEMA`).
- Malformed examples exercised by fixtures: unknown top-level table
  (`config.malformed.toml`), overlay value outside `tty|deny`
  (`policy.malformed.toml`).
- TOML documents carry no canonical-bytes rule; ordering is not semantic.

## Relationship to other surfaces

- Repository identity inside config entries is validated against the shared
  `owner/name` format (registry scalar table; also used by plans/grants).
- The env allowlist here is the only environment channel to subprocesses
  (trust model T5).
