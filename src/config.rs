//! `hf-config/v1` / `hf-policy/v1` loading, validation, and typed model.
//!
//! Discovery contract (docs/contracts/spec-config.md): an explicit `--config`
//! path wins; otherwise the XDG default
//! (`$XDG_CONFIG_HOME/canter/config.toml`, falling back to
//! `$HOME/.config/canter/config.toml`) is used when present. There is
//! exactly one canonical config file and at most one explicit policy overlay
//! named by `config.policy.overlay` — no implicit profile/repository merge
//! stack exists. Overlay paths are resolved relative to the config file's
//! directory.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::formats::{is_repository_identity, is_slug};
use crate::schema::{Family, Refusal, Verdict, validate_bytes};
use crate::value::{Val, bool_, object, string};

/// An error that prevents a config/policy document from being loaded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadError {
    /// Stable CLI error code (`config.invalid`, `config.not_found`,
    /// `policy.invalid`, `policy.not_found`).
    pub code: &'static str,
    /// Human message.
    pub message: String,
    /// Refusal class when the document itself was refused.
    pub refusal: Option<Refusal>,
    /// Path that was being loaded (display-only).
    pub path: String,
}

impl LoadError {
    fn invalid(path: &Path, verdict: &Verdict) -> LoadError {
        LoadError {
            code: "config.invalid",
            message: verdict.message().to_string(),
            refusal: verdict.refusal(),
            path: path.display().to_string(),
        }
    }
}

/// One configured repository entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Repository {
    /// Config table key (slug).
    pub key: String,
    /// Derived `owner` component of the repository identity.
    pub owner: String,
    /// Derived `name` component of the repository identity.
    pub name: String,
    /// The configured origin URL.
    pub origin: String,
    /// Optional pinned branch.
    pub branch: Option<String>,
    /// Whether the entry is enabled (default: true).
    pub enabled: bool,
}

impl Repository {
    /// The `owner/name` repository identity.
    pub fn identity(&self) -> String {
        format!("{}/{}", self.owner, self.name)
    }
}

/// One configured workflow pin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkflowPin {
    /// Config table key (slug).
    pub key: String,
    /// Workflow id.
    pub id: String,
    /// 64-hex hash of the canonical workflow document.
    pub hash: String,
}

/// One configured harness entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Harness {
    /// Harness table key.
    pub key: String,
    /// Adapter kind (e.g. `argv`).
    pub kind: String,
    /// Executable resolved via PATH (never an absolute path).
    pub executable: String,
    /// Explicit environment allowlist.
    pub env_allow: Vec<String>,
    /// Explicit provider binding token for the official prompt rows that
    /// carry the provider/model pair on argv (Pi, Jcode; issue #80). `None`
    /// when the config declares no binding — there is no default and no
    /// inference; the prompt refuses instead (`refusal.binding.missing`).
    pub provider: Option<String>,
    /// See [`Harness::provider`].
    pub model: Option<String>,
    /// Authorized fallback pairs (`"provider/model"`, issue #77): the only
    /// alternative bindings a successor may answer with. Anything else is
    /// fenced. Empty when the profile authorizes no fallback.
    pub fallback: Vec<String>,
    /// Credential environment variable names (issue #77): allowlisted
    /// variables whose *values* participate in the profile-configuration
    /// revision as digests only. Never stored, never reported.
    pub secret_env: Vec<String>,
    /// Configured limits (issue #77 metadata overrides), key → value. These
    /// are declared configuration, never proof of provider support.
    pub limits: Vec<(String, String)>,
    /// Whether the configured profile supports binding introspection (the
    /// session read-back reports the bound provider/model, issue #77). An
    /// unsupported profile yields an honest capability hold instead of an
    /// inferred binding.
    pub binding_introspection: bool,
}

/// A bare binding token: non-empty, no whitespace, no path separators, no
/// NUL. The harness provider/model binding (issue #80) is carried as argv
/// data only — bare tokens are never paths and never shell text.
pub(crate) fn is_bare_token(text: &str) -> bool {
    !text.is_empty()
        && !text.contains('/')
        && !text.contains('\\')
        && !text.contains('\0')
        && !text.chars().any(char::is_whitespace)
}

/// The parsed policy overlay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    /// Absolute path the overlay was loaded from.
    pub path: PathBuf,
    /// Repository allowlist (`owner/name`), if present.
    pub repositories: Option<Vec<String>>,
    /// `production_confirmation` rule (`tty` | `deny`), if present.
    pub production_confirmation: Option<String>,
}

/// A fully loaded and validated configuration document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    /// Absolute path the config was loaded from.
    pub path: PathBuf,
    /// `daemon.enabled` when present (informational in this read-only slice).
    pub daemon_enabled: Option<bool>,
    /// `daemon.socket` when present.
    pub daemon_socket: Option<String>,
    /// Loaded policy overlay, when the config names one.
    pub policy: Option<Policy>,
    /// Configured repositories in key order.
    pub repositories: Vec<Repository>,
    /// Configured harnesses in key order.
    pub harnesses: Vec<Harness>,
    /// Configured workflow pins in key order.
    pub workflows: Vec<WorkflowPin>,
}

impl Config {
    /// Configured repositories that may be acted on: enabled repositories,
    /// narrowed by the policy overlay's repository allowlist when one is
    /// present (the overlay is constrain-only).
    pub fn effective_repositories(&self) -> Vec<&Repository> {
        let allowlist = self
            .policy
            .as_ref()
            .and_then(|policy| policy.repositories.as_ref());
        self.repositories
            .iter()
            .filter(|repository| {
                repository.enabled
                    && allowlist.is_none_or(|allowed| allowed.contains(&repository.identity()))
            })
            .collect()
    }
}

/// Locate the config file: explicit path wins; otherwise the XDG default
/// when present, then the pre-rename default (see [`legacy_config_path`]).
/// Returns `Ok(None)` when no default config exists.
pub fn discover_config(explicit: Option<&Path>) -> Result<Option<PathBuf>, LoadError> {
    if let Some(path) = explicit {
        if path.is_file() {
            return Ok(Some(path.to_path_buf()));
        }
        return Err(LoadError {
            code: "config.not_found",
            message: format!("config file not found: {}", path.display()),
            refusal: None,
            path: path.display().to_string(),
        });
    }
    Ok(default_config_path()
        .filter(|path| path.is_file())
        .or_else(|| legacy_config_path().filter(|path| path.is_file())))
}

/// The config directory name under the XDG config home (product rename,
/// issue #106).
pub const CONFIG_DIR_NAME: &str = "canter";

/// Pre-rename config directory name. A config at the pre-rename path is
/// still discovered when no new-path config exists; it is read in place
/// (never copied, moved, or rewritten). Normative rule:
/// docs/contracts/compatibility.md, "Product rename (issue #106)".
pub const LEGACY_CONFIG_DIR_NAME: &str = "herdr-fleet";

/// The XDG default config path (`$XDG_CONFIG_HOME` or `$HOME/.config`,
/// then `canter/config.toml`) regardless of whether it exists.
pub fn default_config_path() -> Option<PathBuf> {
    config_path_in(CONFIG_DIR_NAME)
}

/// The pre-rename XDG config path (`.../herdr-fleet/config.toml`),
/// regardless of whether it exists. Only used as a fallback when the
/// new path holds no config.
pub fn legacy_config_path() -> Option<PathBuf> {
    config_path_in(LEGACY_CONFIG_DIR_NAME)
}

fn config_path_in(dir_name: &str) -> Option<PathBuf> {
    #[cfg(test)]
    if let Some(home) = overridden_config_home() {
        return home.map(|home| home.join(dir_name).join("config.toml"));
    }
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let xdg = std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from);
    let base = xdg.or_else(|| home.map(|home| home.join(".config")));
    base.map(|base| base.join(dir_name).join("config.toml"))
}

// Test-only override of the config home used by `config_path_in`.
//
// The override is thread-local and compiled only into the crate's test target
// (`cfg(test)`), so the shipped binary's discovery — explicit `--config`, then
// the XDG default — is untouched. A suite that reads the ambient
// `$HOME/.config/canter/config.toml` is not hermetic: a developer (or a lane
// acceptance run) that saved a config there silently changes what the
// no-config tests exercise. `home: None` means "no config home at all", i.e.
// no config can be discovered.
#[cfg(test)]
thread_local! {
    static CONFIG_HOME_OVERRIDE: std::cell::RefCell<Option<Option<PathBuf>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn overridden_config_home() -> Option<Option<PathBuf>> {
    CONFIG_HOME_OVERRIDE.with(|cell| cell.borrow().clone())
}

/// Run `f` with config discovery rooted at `home` (test-only; see the
/// `CONFIG_HOME_OVERRIDE` seam above). Nested scopes restore the previous root.
#[cfg(test)]
pub fn with_config_home<R>(home: Option<PathBuf>, f: impl FnOnce() -> R) -> R {
    struct Restore(Option<Option<PathBuf>>);
    impl Drop for Restore {
        fn drop(&mut self) {
            CONFIG_HOME_OVERRIDE.with(|cell| *cell.borrow_mut() = self.0.take());
        }
    }
    let previous = CONFIG_HOME_OVERRIDE.with(|cell| cell.replace(Some(home)));
    let restore = Restore(previous);
    let out = f();
    drop(restore);
    out
}

/// A human hint naming where the default config would live.
pub fn default_config_hint() -> String {
    default_config_path()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| format!("<XDG config home>/{CONFIG_DIR_NAME}/config.toml"))
}

/// Load, validate, and type a config document from a path.
pub fn load_config(path: &Path) -> Result<Config, LoadError> {
    let bytes = std::fs::read(path).map_err(|err| LoadError {
        code: "config.invalid",
        message: format!("cannot read config file: {err}"),
        refusal: None,
        path: path.display().to_string(),
    })?;
    let verdict = validate_bytes(Family::Config, &bytes);
    if !verdict.is_accepted() {
        return Err(LoadError::invalid(path, &verdict));
    }
    let doc = Val::parse_toml(std::str::from_utf8(&bytes).expect("validated UTF-8"))
        .expect("validated TOML");
    extract_config(path, &doc)
}

/// Load and validate the policy overlay named by a config document.
fn load_policy(config_dir: &Path, overlay: &str) -> Result<Policy, LoadError> {
    let raw = Path::new(overlay);
    let resolved = if raw.is_absolute() {
        raw.to_path_buf()
    } else {
        config_dir.join(raw)
    };
    let bytes = std::fs::read(&resolved).map_err(|err| LoadError {
        code: "policy.not_found",
        message: format!("cannot read policy overlay {}: {err}", resolved.display()),
        refusal: None,
        path: resolved.display().to_string(),
    })?;
    let verdict = validate_bytes(Family::Policy, &bytes);
    if !verdict.is_accepted() {
        return Err(LoadError {
            code: "policy.invalid",
            message: verdict.message().to_string(),
            refusal: verdict.refusal(),
            path: resolved.display().to_string(),
        });
    }
    let doc = Val::parse_toml(std::str::from_utf8(&bytes).expect("validated UTF-8"))
        .expect("validated TOML");
    Ok(Policy {
        path: resolved,
        repositories: doc.get("repositories").and_then(|value| match value {
            Val::Arr(items) => Some(
                items
                    .iter()
                    .filter_map(Val::as_str)
                    .map(str::to_string)
                    .collect(),
            ),
            _ => None,
        }),
        production_confirmation: doc
            .get("production_confirmation")
            .and_then(Val::as_str)
            .map(str::to_string),
    })
}

/// Walk a validated config document into the typed model. All shape and
/// format checks already passed [`validate_bytes`]; this step adds the
/// documented closed-surface type rules for `branch`/`enabled` and derives
/// the `owner/name` identity from each repository origin.
fn extract_config(path: &Path, doc: &Val) -> Result<Config, LoadError> {
    let fail = |message: String| LoadError {
        code: "config.invalid",
        message,
        refusal: Some(Refusal::Malformed),
        path: path.display().to_string(),
    };

    let mut repositories = Vec::new();
    if let Some(entries) = doc.get("repository") {
        let Val::Obj(map) = entries else {
            return Err(fail("config.repository must be a table".to_string()));
        };
        for (key, entry) in map {
            let Some(origin) = entry.get("origin").and_then(Val::as_str) else {
                return Err(fail(format!(
                    "config.repository.{key}.origin must be a string"
                )));
            };
            let Some((owner, name)) = identity_from_origin(origin) else {
                return Err(fail(format!(
                    "config.repository.{key}.origin {origin:?} does not end in an owner/name identity"
                )));
            };
            let branch = entry
                .get("branch")
                .and_then(Val::as_str)
                .map(str::to_string);
            let enabled = match entry.get("enabled") {
                None => true,
                Some(Val::Bool(value)) => *value,
                Some(_) => {
                    return Err(fail(format!(
                        "config.repository.{key}.enabled must be a boolean"
                    )));
                }
            };
            repositories.push(Repository {
                key: key.clone(),
                owner: owner.to_string(),
                name: name.to_string(),
                origin: origin.to_string(),
                branch,
                enabled,
            });
        }
    }

    let mut harnesses = Vec::new();
    if let Some(entries) = doc.get("harness") {
        let Val::Obj(map) = entries else {
            return Err(fail("config.harness must be a table".to_string()));
        };
        for (key, entry) in map {
            let executable = entry
                .get("executable")
                .and_then(Val::as_str)
                .expect("validated")
                .to_string();
            // C1 (issue #8): a bare-name parse guard. Config harness
            // executables are always bare names resolved through the
            // allowlisted PATH (the verified absolute identity is spawned);
            // an absolute path in config is refused so no config can bypass
            // the resolution witness or name an unverifiable executable.
            if executable.is_empty() || executable.contains('/') || executable.contains('\\') {
                return Err(fail(format!(
                    "config.harness.{key}.executable must be a bare executable name (no path separators); it is resolved through the allowlisted PATH"
                )));
            }
            // The optional provider/model binding pair (issue #80). Each
            // declared token must be a bare token and the pair must be
            // declared together: there is no default, no inferred half, and
            // an unbound profile refuses the prompt at the adapter boundary.
            let provider = entry
                .get("provider")
                .and_then(Val::as_str)
                .map(str::to_string);
            let model = entry.get("model").and_then(Val::as_str).map(str::to_string);
            for (field, value) in [("provider", &provider), ("model", &model)] {
                if let Some(value) = value
                    && !is_bare_token(value)
                {
                    return Err(fail(format!(
                        "config.harness.{key}.{field} must be a non-empty bare token (no whitespace or path separators)"
                    )));
                }
            }
            if provider.is_some() != model.is_some() {
                return Err(fail(format!(
                    "config.harness.{key}.provider and .model must be declared together"
                )));
            }
            // Issue #77 profile-planning keys. Everything is validated in
            // the decoder (the schema validator checks shape only): fallback
            // pairs and secret names are bare-token bounded, credentials must
            // flow through the declared environment allowlist, and limits are
            // bounded scalar metadata overrides.
            let fallback = match entry.get("fallback") {
                None => Vec::new(),
                Some(Val::Arr(items)) => {
                    let mut pairs = Vec::new();
                    for item in items {
                        let Some(text) = item.as_str() else {
                            return Err(fail(format!(
                                "config.harness.{key}.fallback must be an array of \"provider/model\" strings"
                            )));
                        };
                        if fallback_pair(text).is_none() {
                            return Err(fail(format!(
                                "config.harness.{key}.fallback entry {text:?} must be a bare-token provider/model pair"
                            )));
                        }
                        pairs.push(text.to_string());
                    }
                    pairs
                }
                Some(_) => {
                    return Err(fail(format!(
                        "config.harness.{key}.fallback must be an array of \"provider/model\" strings"
                    )));
                }
            };
            let secret_env = match entry.get("secret_env") {
                None => Vec::new(),
                Some(Val::Arr(items)) => {
                    let mut names = Vec::new();
                    for item in items {
                        let Some(name) = item.as_str() else {
                            return Err(fail(format!(
                                "config.harness.{key}.secret_env must be an array of environment variable names"
                            )));
                        };
                        names.push(name.to_string());
                    }
                    names
                }
                Some(_) => {
                    return Err(fail(format!(
                        "config.harness.{key}.secret_env must be an array of environment variable names"
                    )));
                }
            };
            let env_allow: Vec<String> = match entry.get("env_allow") {
                Some(Val::Arr(items)) => items
                    .iter()
                    .filter_map(Val::as_str)
                    .map(str::to_string)
                    .collect(),
                _ => Vec::new(),
            };
            // Credentials arrive only through the explicit environment
            // allowlist (trust model T5): a secret name outside it would be a
            // value channel with no declared boundary, so it refuses.
            for name in &secret_env {
                if !is_bare_token(name) || !env_allow.contains(name) {
                    return Err(fail(format!(
                        "config.harness.{key}.secret_env entry {name:?} must be a declared env_allow variable name"
                    )));
                }
            }
            let binding_introspection = match entry.get("binding_introspection") {
                None => false,
                Some(Val::Bool(value)) => *value,
                Some(_) => {
                    return Err(fail(format!(
                        "config.harness.{key}.binding_introspection must be a boolean"
                    )));
                }
            };
            let limits = match entry.get("limits") {
                None => Vec::new(),
                Some(Val::Obj(map)) => {
                    let mut bounds = Vec::new();
                    for (name, value) in map {
                        if !bounded_printable(name, CONFIG_LIMIT_KEY_MAX) {
                            return Err(fail(format!(
                                "config.harness.{key}.limits key {name:?} must be 1-{CONFIG_LIMIT_KEY_MAX} printable characters"
                            )));
                        }
                        let text = match value {
                            Val::Str(text) => text.clone(),
                            Val::Int(number) => number.to_string(),
                            _ => {
                                return Err(fail(format!(
                                    "config.harness.{key}.limits.{name} must be a string or integer"
                                )));
                            }
                        };
                        if !bounded_printable(&text, CONFIG_LIMIT_VALUE_MAX) {
                            return Err(fail(format!(
                                "config.harness.{key}.limits.{name} must be 1-{CONFIG_LIMIT_VALUE_MAX} printable characters"
                            )));
                        }
                        bounds.push((name.clone(), text));
                    }
                    bounds
                }
                Some(_) => {
                    return Err(fail(format!(
                        "config.harness.{key}.limits must be a table of scalar values"
                    )));
                }
            };
            harnesses.push(Harness {
                key: key.clone(),
                kind: entry
                    .get("kind")
                    .and_then(Val::as_str)
                    .expect("validated")
                    .to_string(),
                executable,
                env_allow,
                provider,
                model,
                fallback,
                secret_env,
                limits,
                binding_introspection,
            });
        }
    }

    let mut workflows = Vec::new();
    if let Some(entries) = doc.get("workflow") {
        let Val::Obj(map) = entries else {
            return Err(fail("config.workflow must be a table".to_string()));
        };
        for (key, entry) in map {
            workflows.push(WorkflowPin {
                key: key.clone(),
                id: entry
                    .get("id")
                    .and_then(Val::as_str)
                    .expect("validated")
                    .to_string(),
                hash: entry
                    .get("hash")
                    .and_then(Val::as_str)
                    .expect("validated")
                    .to_string(),
            });
        }
    }

    let daemon = doc.get("daemon");
    let daemon_enabled = daemon
        .and_then(|d| d.get("enabled"))
        .and_then(|value| match value {
            Val::Bool(b) => Some(*b),
            _ => None,
        });
    let daemon_socket = daemon
        .and_then(|d| d.get("socket"))
        .and_then(Val::as_str)
        .map(str::to_string);

    let policy = match doc
        .get("policy")
        .and_then(|p| p.get("overlay"))
        .and_then(Val::as_str)
    {
        Some(overlay) => {
            let config_dir = path.parent().unwrap_or_else(|| Path::new("."));
            Some(load_policy(config_dir, overlay)?)
        }
        None => None,
    };

    Ok(Config {
        path: path.to_path_buf(),
        daemon_enabled,
        daemon_socket,
        policy,
        repositories,
        harnesses,
        workflows,
    })
}

/// Derive the `owner/name` identity from a repository origin. Rules:
/// - a trailing `.git` is ignored;
/// - with a scheme (`://`), the URL path must be exactly two segments that
///   form a valid identity (no nested subgroup paths — use the canonical
///   repository URL);
/// - without a scheme, the whole origin must be exactly `owner/name`.
fn identity_from_origin(origin: &str) -> Option<(&str, &str)> {
    let trimmed = origin.strip_suffix(".git").unwrap_or(origin);
    let segments: Vec<&str> = trimmed.split('/').collect();
    let (owner, name) = if trimmed.contains("://") {
        // segments: [scheme, "", authority, owner, name]
        if segments.len() != 5 {
            return None;
        }
        (segments[3], segments[4])
    } else {
        // bare owner/name only
        if segments.len() != 2 {
            return None;
        }
        (segments[0], segments[1])
    };
    if owner.is_empty() || name.is_empty() || !is_repository_identity(&format!("{owner}/{name}")) {
        return None;
    }
    Some((owner, name))
}

/// An annotated synthetic `hf-config/v1` template for `config init` (stdout
/// guidance; the CLI never writes files itself).
pub fn init_template() -> String {
    r#"# canter canonical configuration (hf-config/v1).
# One canonical XDG file, no implicit profile/repository merge stack.
# Save this as $XDG_CONFIG_HOME/canter/config.toml (or
# ~/.config/canter/config.toml) and edit the synthetic values below.
# A pre-rename config at $XDG_CONFIG_HOME/herdr-fleet/config.toml is still
# read when no new-path config exists (docs/contracts/compatibility.md).

schema = "hf-config/v1"

[daemon]
enabled = false

# Optional explicit policy overlay; no implicit discovery.
# [policy]
# overlay = "policy.toml"

# One configured repository per key. The origin URL must end in
# /owner/name; the owner/name pair is the repository identity.
[repository.widgets]
origin = "https://github.com/example-org/widgets"
branch = "staging"
enabled = true

# Optional harness adapter profiles (kind, PATH-resolved executable, and
# the explicit environment allowlist for subprocesses). A harness whose
# prompt row carries a provider/model pair on argv (pi, jcode) also needs
# this explicit binding pair; without it the prompt refuses (no default is
# inferred).
# [harness.cli]
# kind = "argv"
# executable = "hf-cli-example"
# env_allow = ["PATH", "HOME"]
# provider = "example-provider"
# model = "example-model"

# Optional workflow pin: id + 64-hex hash of the canonical workflow
# document. Without a pin, `plan` uses the built-in doctrine workflow.
# [workflow.bundle]
# id = "fleet-doctrine-1"
# hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
"#
    .to_string()
}

/// Validate a repository key lookup argument: it may name a configured key
/// (slug) or the repository's `owner/name` identity directly.
pub fn resolve_repository<'a>(
    config: &'a Config,
    argument: &str,
) -> Result<&'a Repository, String> {
    if is_slug(argument)
        && let Some(repository) = config.repositories.iter().find(|r| r.key == argument)
    {
        return Ok(repository);
    }
    config
        .repositories
        .iter()
        .find(|r| r.identity() == argument)
        .ok_or_else(|| {
            format!(
                "no configured repository matches {argument:?}; configure it first (see `canter config init`)"
            )
        })
}

/// Deterministic order helper: sort repository keys for display.
pub fn sorted_repositories(config: &Config) -> Vec<&Repository> {
    let mut repos: Vec<&Repository> = config.repositories.iter().collect();
    repos.sort_by(|a, b| a.key.cmp(&b.key));
    repos
}

/// Allowed subprocess environment for the built-in adapters. The trust model
/// (docs/contracts/trust-model.md T5) makes this allowlist the only
/// environment channel to child processes: no host variable beyond these
/// names is ever inherited.
pub const ADAPTER_ENV_ALLOW: [&str; 6] = [
    "PATH",
    "HOME",
    "LANG",
    "LC_ALL",
    "XDG_CONFIG_HOME",
    "TMPDIR",
];

/// Build a `BTreeMap` of the adapter environment from the invoking process.
pub fn adapter_environment() -> BTreeMap<String, String> {
    let mut env = BTreeMap::new();
    for name in ADAPTER_ENV_ALLOW {
        if let Some(value) = std::env::var_os(name)
            && let Ok(value) = value.into_string()
        {
            env.insert(name.to_string(), value);
        }
    }
    env
}

// ---------------------------------------------------------------------------
// Target profile binding plans (issue #77)
//
// One validated profile-configuration revision binds a replacement plan to
// the exact target profile a human reviewed: the intended provider/model,
// the authorized fallback pairs, the configured limits (metadata overrides
// — declared configuration, never provider proof), the declared binding
// introspection support and the credential digests (never values). The
// revision is the sha256 over the canonical material, so any relevant
// configuration or credential change produces a different revision and the
// durable binding is invalidated (a newly reviewed plan is required).
// ---------------------------------------------------------------------------

/// Canonical schema id of one target-profile binding plan document.
pub const PROFILE_BINDING_SCHEMA: &str = "hf-profile-binding/v1";

/// Typed refusal code: the profile binding is malformed or does not match
/// the durable plan (missing, unexpected, or materially different).
pub const CODE_PROFILE_BINDING: &str = "refusal.profile.binding";

/// Typed refusal code: the presented configuration revision does not match
/// the reviewed plan revision — the relevant configuration (or a declared
/// credential) changed after the preview.
pub const CODE_PROFILE_REVISION: &str = "refusal.profile.revision";

/// Recorded digest marker for a declared credential environment variable
/// that is absent from the environment: the revision still covers the
/// declared name and the fact that no value was present.
pub const PROFILE_SECRET_UNSET: &str = "unset";

/// Enforced bound of one configured-limit key (issue #77).
pub const CONFIG_LIMIT_KEY_MAX: usize = 64;
/// Enforced bound of one configured-limit value.
pub const CONFIG_LIMIT_VALUE_MAX: usize = 96;
/// Maximum authorized fallback pairs bound into one plan.
pub const PROFILE_FALLBACK_MAX: usize = 8;
/// Maximum declared credential names bound into one plan.
pub const PROFILE_SECRET_MAX: usize = 8;
/// Maximum configured-limit entries bound into one plan.
pub const PROFILE_LIMITS_MAX: usize = 16;

/// A bounded printable string (never control characters, never empty).
fn bounded_printable(text: &str, max: usize) -> bool {
    !text.is_empty() && text.chars().count() <= max && !text.chars().any(char::is_control)
}

/// Split one `"provider/model"` fallback text into its bare-token pair.
pub fn fallback_pair(text: &str) -> Option<(&str, &str)> {
    let (provider, model) = text.split_once('/')?;
    if is_bare_token(provider) && is_bare_token(model) {
        Some((provider, model))
    } else {
        None
    }
}

/// The digest of one declared credential environment variable: a sha256 over
/// a fixed domain-separated preimage, or [`PROFILE_SECRET_UNSET`] when the
/// variable is absent. The value itself never enters the binding, a report,
/// or a log — only this digest does.
pub fn secret_digest(env: &BTreeMap<String, String>, name: &str) -> String {
    match env.get(name) {
        Some(value) => crate::canonical::sha256_hex(
            format!("{PROFILE_BINDING_SCHEMA}|secret|{name}|{value}").as_bytes(),
        ),
        None => PROFILE_SECRET_UNSET.to_string(),
    }
}

/// Read the declared credential environment of one harness from the invoking
/// process (issue #77): the NAMES come from the configuration; each value is
/// read only to be digested and never leaves this map (it is never stored in
/// a plan, a report, or a log).
pub fn credential_environment(harness: &Harness) -> BTreeMap<String, String> {
    let mut env = BTreeMap::new();
    for name in &harness.secret_env {
        if let Ok(value) = std::env::var(name) {
            env.insert(name.clone(), value);
        }
    }
    env
}

/// The declared credential presence of one configured harness (issue #77):
/// `(present, missing)` variable names. Names only — credential values are
/// never read into a report and never disclosed.
pub fn credential_presence(
    harness: &Harness,
    env: &BTreeMap<String, String>,
) -> (Vec<String>, Vec<String>) {
    let mut present = Vec::new();
    let mut missing = Vec::new();
    for name in &harness.secret_env {
        if env.contains_key(name) {
            present.push(name.clone());
        } else {
            missing.push(name.clone());
        }
    }
    (present, missing)
}

/// One validated target-profile binding plan (issue #77): the explicit
/// profile-configuration revision a human reviewed together with the exact
/// material the revision fingerprints.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProfileBinding {
    /// Target harness profile key.
    pub key: String,
    /// Target adapter kind.
    pub kind: String,
    /// INTENDED provider (sourced from the supported profile configuration).
    pub provider: String,
    /// INTENDED model (sourced from the supported profile configuration).
    pub model: String,
    /// Authorized fallback pairs (`"provider/model"`); anything else is
    /// fenced at verification time.
    pub fallbacks: Vec<String>,
    /// Configured limits (metadata overrides), key → value. Reported as
    /// configured limits, never as proof of provider support.
    pub configured_limits: Vec<(String, String)>,
    /// Whether the configured profile supports binding introspection.
    pub introspection: bool,
    /// Declared credential names with their digest (or `unset`).
    pub secrets: Vec<(String, String)>,
    /// 64-hex sha256 over the canonical material.
    pub revision: String,
}

/// Why a presented profile binding was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProfileBindingError {
    /// Malformed or inconsistent binding material.
    Binding(String),
    /// The presented revision does not match the recomputed fingerprint of
    /// the presented material.
    Revision(String),
}

impl ProfileBindingError {
    /// The typed refusal code for this error.
    pub fn code(&self) -> &'static str {
        match self {
            ProfileBindingError::Binding(_) => CODE_PROFILE_BINDING,
            ProfileBindingError::Revision(_) => CODE_PROFILE_REVISION,
        }
    }

    /// The human message for this error.
    pub fn message(&self) -> &str {
        match self {
            ProfileBindingError::Binding(message) | ProfileBindingError::Revision(message) => {
                message
            }
        }
    }
}

fn binding_error(message: impl Into<String>) -> ProfileBindingError {
    ProfileBindingError::Binding(message.into())
}

impl ProfileBinding {
    /// The canonical material document the revision fingerprints: exactly
    /// the fields a plan binds. Credential entries carry digests only.
    pub fn material(&self) -> Val {
        object(vec![
            ("schema", string(PROFILE_BINDING_SCHEMA)),
            ("key", string(&self.key)),
            ("kind", string(&self.kind)),
            ("provider", string(&self.provider)),
            ("model", string(&self.model)),
            (
                "fallbacks",
                Val::Arr(self.fallbacks.iter().map(|text| string(text)).collect()),
            ),
            (
                "configured_limits",
                object(
                    self.configured_limits
                        .iter()
                        .map(|(name, value)| (name.as_str(), string(value)))
                        .collect(),
                ),
            ),
            ("introspection", bool_(self.introspection)),
            (
                "secrets",
                Val::Arr(
                    self.secrets
                        .iter()
                        .map(|(name, digest)| {
                            object(vec![("name", string(name)), ("digest", string(digest))])
                        })
                        .collect(),
                ),
            ),
        ])
    }

    /// The sha256 over the canonical material — the configuration revision.
    pub fn revision_of(&self) -> String {
        crate::canonical::sha256_hex(&crate::canonical::canonical_bytes(&self.material()))
    }

    /// The full `hf-profile-binding/v1` document (material + revision).
    pub fn to_doc(&self) -> Val {
        match self.material() {
            Val::Obj(mut map) => {
                map.insert("revision".to_string(), string(&self.revision));
                Val::Obj(map)
            }
            _ => unreachable!("material is an object"),
        }
    }

    /// Canonical JSON text of the full document (the durable plan bytes).
    pub fn to_canonical_text(&self) -> String {
        crate::canonical::canonical_text(&self.to_doc())
    }

    /// Build one binding from supported profile configuration (issue #77):
    /// the harness row keyed `key`, with the intended pair taken from the
    /// declared `provider`/`model` binding and the credential digests taken
    /// from the supplied environment (digests only). `None` when the profile
    /// is unknown or declares no binding pair (the prompt would refuse
    /// `refusal.binding.missing`; there is no inferred plan).
    pub fn from_config(
        config: &Config,
        key: &str,
        env: &BTreeMap<String, String>,
    ) -> Option<ProfileBinding> {
        let harness = config.harnesses.iter().find(|harness| harness.key == key)?;
        let provider = harness.provider.clone()?;
        let model = harness.model.clone()?;
        let secrets = harness
            .secret_env
            .iter()
            .map(|name| (name.clone(), secret_digest(env, name)))
            .collect();
        let mut binding = ProfileBinding {
            key: harness.key.clone(),
            kind: harness.kind.clone(),
            provider,
            model,
            fallbacks: harness.fallback.clone(),
            configured_limits: harness.limits.clone(),
            introspection: harness.binding_introspection,
            secrets,
            revision: String::new(),
        };
        binding.revision = binding.revision_of();
        Some(binding)
    }

    /// Validate one PRESENTED `hf-profile-binding/v1` document (the daemon
    /// boundary: the document is untrusted) and recompute its revision: the
    /// presented revision must equal the fingerprint of the presented
    /// material, so a revision can never be claimed without the material it
    /// binds. Unknown keys refuse (closed surface).
    pub fn from_doc(doc: &Val) -> Result<ProfileBinding, ProfileBindingError> {
        let Val::Obj(map) = doc else {
            return Err(binding_error("the profile binding must be an object"));
        };
        const KEYS: [&str; 10] = [
            "schema",
            "key",
            "kind",
            "provider",
            "model",
            "fallbacks",
            "configured_limits",
            "introspection",
            "secrets",
            "revision",
        ];
        for key in map.keys() {
            if !KEYS.contains(&key.as_str()) {
                return Err(binding_error(format!(
                    "the profile binding carries unknown key {key:?} (closed surface)"
                )));
            }
        }
        let text = |key: &str| -> Result<String, ProfileBindingError> {
            match doc.get(key).and_then(Val::as_str) {
                Some(value) if !value.is_empty() => Ok(value.to_string()),
                _ => Err(binding_error(format!(
                    "the profile binding requires {key} (non-empty string)"
                ))),
            }
        };
        match doc.get("schema").and_then(Val::as_str) {
            Some(schema) if schema == PROFILE_BINDING_SCHEMA => {}
            _ => {
                return Err(binding_error(format!(
                    "the profile binding schema must be {PROFILE_BINDING_SCHEMA:?}"
                )));
            }
        }
        let key = text("key")?;
        if !crate::formats::is_actor(&key) {
            return Err(binding_error(
                "the profile binding key must be an actor identity",
            ));
        }
        let kind = text("kind")?;
        if !is_bare_token(&kind) || kind.chars().count() > 32 {
            return Err(binding_error(
                "the profile binding kind must be a bounded bare token",
            ));
        }
        let provider = text("provider")?;
        let model = text("model")?;
        for (field, value) in [("provider", &provider), ("model", &model)] {
            if !is_bare_token(value) {
                return Err(binding_error(format!(
                    "the profile binding {field} must be a bare token (no whitespace or path separators)"
                )));
            }
        }
        let fallbacks = match doc.get("fallbacks") {
            Some(Val::Arr(items)) => {
                if items.len() > PROFILE_FALLBACK_MAX {
                    return Err(binding_error(format!(
                        "the profile binding carries more than {PROFILE_FALLBACK_MAX} fallback pairs"
                    )));
                }
                let mut pairs = Vec::new();
                for item in items {
                    let Some(entry) = item.as_str() else {
                        return Err(binding_error(
                            "every profile binding fallback must be a \"provider/model\" string",
                        ));
                    };
                    if fallback_pair(entry).is_none() {
                        return Err(binding_error(format!(
                            "profile binding fallback {entry:?} must be a bare-token provider/model pair"
                        )));
                    }
                    pairs.push(entry.to_string());
                }
                pairs
            }
            _ => {
                return Err(binding_error(
                    "the profile binding requires fallbacks (array of \"provider/model\" strings)",
                ));
            }
        };
        let configured_limits = match doc.get("configured_limits") {
            Some(Val::Obj(entries)) => {
                if entries.len() > PROFILE_LIMITS_MAX {
                    return Err(binding_error(format!(
                        "the profile binding carries more than {PROFILE_LIMITS_MAX} configured limits"
                    )));
                }
                let mut limits = Vec::new();
                for (name, value) in entries {
                    let Some(value) = value.as_str() else {
                        return Err(binding_error(format!(
                            "profile binding configured_limits.{name} must be a string"
                        )));
                    };
                    if !bounded_printable(name, CONFIG_LIMIT_KEY_MAX)
                        || !bounded_printable(value, CONFIG_LIMIT_VALUE_MAX)
                    {
                        return Err(binding_error(format!(
                            "profile binding configured_limits.{name} must be bounded printable text"
                        )));
                    }
                    limits.push((name.clone(), value.to_string()));
                }
                limits
            }
            _ => {
                return Err(binding_error(
                    "the profile binding requires configured_limits (an object; may be empty)",
                ));
            }
        };
        let introspection = match doc.get("introspection") {
            Some(Val::Bool(value)) => *value,
            _ => {
                return Err(binding_error(
                    "the profile binding requires introspection (a boolean)",
                ));
            }
        };
        let secrets = match doc.get("secrets") {
            Some(Val::Arr(items)) => {
                if items.len() > PROFILE_SECRET_MAX {
                    return Err(binding_error(format!(
                        "the profile binding carries more than {PROFILE_SECRET_MAX} declared credentials"
                    )));
                }
                let mut entries = Vec::new();
                for item in items {
                    let name = match item.get("name").and_then(Val::as_str) {
                        Some(name) if is_bare_token(name) => name.to_string(),
                        _ => {
                            return Err(binding_error(
                                "every profile binding credential requires a bare-token name",
                            ));
                        }
                    };
                    let digest = match item.get("digest").and_then(Val::as_str) {
                        Some(digest)
                            if digest == PROFILE_SECRET_UNSET
                                || crate::formats::is_hex64(digest) =>
                        {
                            digest.to_string()
                        }
                        _ => {
                            return Err(binding_error(format!(
                                "profile binding credential {name:?} requires a 64-hex digest or {PROFILE_SECRET_UNSET:?}"
                            )));
                        }
                    };
                    entries.push((name, digest));
                }
                entries
            }
            _ => {
                return Err(binding_error(
                    "the profile binding requires secrets (an array; may be empty)",
                ));
            }
        };
        let revision = text("revision")?;
        if !crate::formats::is_hex64(&revision) {
            return Err(binding_error(
                "the profile binding revision must be a 64-hex sha256",
            ));
        }
        let binding = ProfileBinding {
            key,
            kind,
            provider,
            model,
            fallbacks,
            configured_limits,
            introspection,
            secrets,
            revision,
        };
        let expected = binding.revision_of();
        if expected != binding.revision {
            return Err(ProfileBindingError::Revision(format!(
                "the presented profile revision {} does not match the fingerprint of the presented \
                 material ({}); the profile configuration changed since the plan and a newly \
                 reviewed plan is required",
                binding.revision, expected
            )));
        }
        Ok(binding)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_temp(name: &str, content: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("hf-config-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join(name);
        std::fs::write(&path, content).expect("write");
        path
    }

    const VALID: &str = r#"schema = "hf-config/v1"
[daemon]
enabled = true
[policy]
overlay = "policy.overlay.toml"
[repository.widgets]
origin = "https://github.com/example-org/widgets"
branch = "staging"
enabled = true
[harness.cli]
kind = "argv"
executable = "hf-cli-example"
env_allow = ["PATH", "HOME"]
[workflow.bundle]
id = "fleet-doctrine-1"
hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
"#;

    const POLICY_VALID: &str = r#"schema = "hf-policy/v1"
repositories = ["example-org/widgets"]
production_confirmation = "tty"
"#;

    #[test]
    fn loads_and_types_valid_config_with_overlay() {
        let dir = std::env::temp_dir().join(format!("hf-config-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        std::fs::write(dir.join("policy.overlay.toml"), POLICY_VALID).expect("write overlay");
        let path = write_temp("config.toml", VALID);
        let config = load_config(&path).expect("load");
        assert_eq!(config.daemon_enabled, Some(true));
        assert_eq!(config.repositories.len(), 1);
        let repo = &config.repositories[0];
        assert_eq!(repo.key, "widgets");
        assert_eq!(repo.identity(), "example-org/widgets");
        assert_eq!(repo.origin, "https://github.com/example-org/widgets");
        assert_eq!(repo.branch.as_deref(), Some("staging"));
        assert!(repo.enabled);
        let policy = config.policy.as_ref().expect("overlay loaded");
        assert_eq!(
            policy.repositories.as_ref().map(|r| r.len()),
            Some(1),
            "allowlist present"
        );
        assert_eq!(policy.production_confirmation.as_deref(), Some("tty"));
        let effective = config.effective_repositories();
        assert_eq!(effective.len(), 1);
    }

    #[test]
    fn harness_provider_model_binding_is_decoded_and_validated() {
        let bound = load_config(&write_temp(
            "harness-binding.toml",
            r#"schema = "hf-config/v1"
[harness.pi]
kind = "pi"
executable = "pi"
env_allow = ["PATH"]
provider = "example-provider"
model = "example-model"
"#,
        ))
        .expect("binding decodes");
        let harness = &bound.harnesses[0];
        assert_eq!(harness.provider.as_deref(), Some("example-provider"));
        assert_eq!(harness.model.as_deref(), Some("example-model"));

        // A declared binding must be a bare token pair: no path separators,
        // no blank/whitespace values, and never a half pair.
        for (name, provider_line, model_line) in [
            (
                "path",
                "provider = \"example/provider\"",
                "model = \"example-model\"",
            ),
            ("blank", "provider = \"example-provider\"", "model = \"  \""),
            ("half", "provider = \"example-provider\"", ""),
        ] {
            let content = format!(
                "schema = \"hf-config/v1\"\n[harness.pi]\nkind = \"pi\"\nexecutable = \"pi\"\nenv_allow = [\"PATH\"]\n{provider_line}\n{model_line}\n"
            );
            let err = load_config(&write_temp(
                &format!("harness-binding-{name}.toml"),
                &content,
            ))
            .expect_err("invalid binding refused");
            assert_eq!(err.code, "config.invalid", "{name}");
            assert!(
                err.message.contains("provider") || err.message.contains("model"),
                "{name}: {}",
                err.message
            );
        }
    }

    /// One synthetic profile row exercising every issue #77 key.
    const PROFILE_VALID: &str = r#"schema = "hf-config/v1"
[harness.lane-orch-1]
kind = "pi"
executable = "pi-example"
env_allow = ["PATH", "HOME", "EXAMPLE_PROVIDER_KEY"]
provider = "example-provider"
model = "example-model"
fallback = ["example-provider/example-fallback-model", "example-fallback-provider/example-fallback-model"]
secret_env = ["EXAMPLE_PROVIDER_KEY"]
binding_introspection = true
[harness.lane-orch-1.limits]
context_tokens = 131072
request_timeout = "90s"
"#;

    fn profile_config(name: &str) -> Config {
        load_config(&write_temp(
            &format!("profile-binding-{name}.toml"),
            PROFILE_VALID,
        ))
        .expect("profile config loads")
    }

    fn profile_env(secret: Option<&str>) -> BTreeMap<String, String> {
        let mut env = BTreeMap::new();
        env.insert("PATH".to_string(), "/usr/bin:/bin".to_string());
        if let Some(secret) = secret {
            env.insert("EXAMPLE_PROVIDER_KEY".to_string(), secret.to_string());
        }
        env
    }

    #[test]
    fn profile_binding_preview_binds_the_reviewed_configuration() {
        let config = profile_config("preview");
        let binding = ProfileBinding::from_config(
            &config,
            "lane-orch-1",
            &profile_env(Some("example-secret-material")),
        )
        .expect("bound profile preview");
        assert_eq!(binding.key, "lane-orch-1");
        assert_eq!(binding.kind, "pi");
        assert_eq!(binding.provider, "example-provider");
        assert_eq!(binding.model, "example-model");
        assert_eq!(binding.fallbacks.len(), 2);
        assert_eq!(
            binding.configured_limits,
            vec![
                ("context_tokens".to_string(), "131072".to_string()),
                ("request_timeout".to_string(), "90s".to_string()),
            ]
        );
        assert!(binding.introspection);
        assert_eq!(binding.secrets.len(), 1);
        assert_eq!(binding.secrets[0].0, "EXAMPLE_PROVIDER_KEY");
        assert!(
            crate::formats::is_hex64(&binding.secrets[0].1),
            "a present credential is bound as a digest"
        );
        assert!(crate::formats::is_hex64(&binding.revision));

        // The canonical plan round-trips through the validated decoder and
        // the fingerprint covers exactly the presented material.
        let doc = binding.to_doc();
        let reparsed = ProfileBinding::from_doc(&doc).expect("validated plan");
        assert_eq!(reparsed, binding);
        assert_eq!(reparsed.revision_of(), binding.revision);

        // An unbound profile has no plan (nothing is inferred).
        let unbound = load_config(&write_temp(
            "profile-unbound.toml",
            "schema = \"hf-config/v1\"\n[harness.cli]\nkind = \"argv\"\nexecutable = \"hf-cli-example\"\nenv_allow = [\"PATH\"]\n",
        ))
        .expect("load");
        assert!(
            ProfileBinding::from_config(&unbound, "cli", &profile_env(None)).is_none(),
            "no declared binding means no plan"
        );
        assert!(ProfileBinding::from_config(&unbound, "absent", &profile_env(None)).is_none());
    }

    #[test]
    fn profile_revision_invalidates_on_config_and_credential_change_without_disclosure() {
        const SECRET_VALUE: &str = "example-secret-2417-not-a-real-credential";
        let config = profile_config("revision");
        let first =
            ProfileBinding::from_config(&config, "lane-orch-1", &profile_env(Some(SECRET_VALUE)))
                .expect("preview");

        // The credential VALUE never enters the plan, its canonical bytes,
        // or the revision — only the digest does.
        let text = first.to_canonical_text();
        assert!(
            !text.contains(SECRET_VALUE),
            "no credential value in the plan"
        );
        assert!(
            !text.contains("2417"),
            "no credential value fragment in the plan"
        );
        assert!(!first.revision.contains(SECRET_VALUE));

        // The same reviewed configuration is stable.
        let again =
            ProfileBinding::from_config(&config, "lane-orch-1", &profile_env(Some(SECRET_VALUE)))
                .expect("preview");
        assert_eq!(
            first.revision, again.revision,
            "unchanged profile, same revision"
        );

        // A rotated credential changes the revision (safe revision
        // semantics): the previous plan no longer matches.
        let rotated = ProfileBinding::from_config(
            &config,
            "lane-orch-1",
            &profile_env(Some("example-secret-rotated")),
        )
        .expect("preview");
        assert_ne!(
            first.revision, rotated.revision,
            "credential change invalidates"
        );

        // A missing credential is bound as `unset` (the fact of the
        // declaration is covered) and disclosed as a NAME only.
        let missing = ProfileBinding::from_config(&config, "lane-orch-1", &profile_env(None))
            .expect("preview");
        assert_eq!(missing.secrets[0].1, PROFILE_SECRET_UNSET);
        assert_ne!(first.revision, missing.revision);
        let (present, absent) = credential_presence(&config.harnesses[0], &profile_env(None));
        assert!(present.is_empty());
        assert_eq!(absent, vec!["EXAMPLE_PROVIDER_KEY".to_string()]);
        assert!(
            !missing
                .to_canonical_text()
                .contains("EXAMPLE_PROVIDER_KEY="),
            "presence is a name, never a value"
        );

        // Every relevant configuration axis is revision-bound.
        let mut variants: Vec<Config> = Vec::new();
        for (name, needle, replacement) in [
            (
                "provider",
                "provider = \"example-provider\"",
                "provider = \"example-provider-2\"",
            ),
            (
                "model",
                "model = \"example-model\"",
                "model = \"example-model-2\"",
            ),
            (
                "fallback",
                "fallback = [\"example-provider/example-fallback-model\", \"example-fallback-provider/example-fallback-model\"]",
                "fallback = [\"example-provider/example-fallback-model\"]",
            ),
            (
                "limits",
                "context_tokens = 131072",
                "context_tokens = 65536",
            ),
            (
                "introspection",
                "binding_introspection = true",
                "binding_introspection = false",
            ),
        ] {
            let text = PROFILE_VALID.replace(needle, replacement);
            assert_ne!(text, PROFILE_VALID, "{name} variant rewritten");
            variants.push(
                load_config(&write_temp(&format!("profile-{name}.toml"), &text))
                    .expect("variant loads"),
            );
        }
        for (index, variant) in variants.iter().enumerate() {
            let changed = ProfileBinding::from_config(
                variant,
                "lane-orch-1",
                &profile_env(Some(SECRET_VALUE)),
            )
            .expect("preview");
            assert_ne!(
                first.revision, changed.revision,
                "variant {index} must change the revision"
            );
        }
    }

    #[test]
    fn profile_binding_documents_are_validated_and_revision_checked() {
        let config = profile_config("documents");
        let binding = ProfileBinding::from_config(&config, "lane-orch-1", &profile_env(None))
            .expect("preview");
        let doc = binding.to_doc();

        // A presented revision that does not fingerprint the presented
        // material refuses as a revision mismatch.
        let mut tampered = doc.clone();
        if let Val::Obj(map) = &mut tampered {
            map.insert(
                "revision".to_string(),
                string("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
            );
        }
        let err = ProfileBinding::from_doc(&tampered).expect_err("revision mismatch");
        assert_eq!(err.code(), CODE_PROFILE_REVISION);

        // A changed intended pair with the old revision is a revision
        // mismatch too: the material moved, the plan did not.
        let mut re_bound = binding.clone();
        re_bound.provider = "example-provider-2".to_string();
        let mut mixed = re_bound.to_doc();
        if let Val::Obj(map) = &mut mixed {
            map.insert("revision".to_string(), string(&binding.revision));
        }
        assert_eq!(
            ProfileBinding::from_doc(&mixed)
                .expect_err("stale revision")
                .code(),
            CODE_PROFILE_REVISION
        );

        // Shape violations refuse as binding errors.
        for (label, mutate) in [
            (
                "unknown key",
                Box::new(|map: &mut BTreeMap<String, Val>| {
                    map.insert("extra".to_string(), string("value"));
                }) as Box<dyn Fn(&mut BTreeMap<String, Val>)>,
            ),
            (
                "bad fallback",
                Box::new(|map: &mut BTreeMap<String, Val>| {
                    map.insert(
                        "fallbacks".to_string(),
                        Val::Arr(vec![string("not-a-pair")]),
                    );
                }),
            ),
            (
                "credential digest",
                Box::new(|map: &mut BTreeMap<String, Val>| {
                    map.insert(
                        "secrets".to_string(),
                        Val::Arr(vec![object(vec![
                            ("name", string("EXAMPLE_PROVIDER_KEY")),
                            ("digest", string("example-secret-material")),
                        ])]),
                    );
                }),
            ),
        ] {
            let mut mutated = doc.clone();
            if let Val::Obj(map) = &mut mutated {
                map.insert("revision".to_string(), string(&"0".repeat(63)));
                mutate(map);
            }
            let err = ProfileBinding::from_doc(&mutated).expect_err(label);
            assert_eq!(err.code(), CODE_PROFILE_BINDING, "{label}");
        }
    }

    #[test]
    fn secret_env_must_flow_through_the_declared_allowlist() {
        let err = load_config(&write_temp(
            "profile-secret-undeclared.toml",
            "schema = \"hf-config/v1\"\n[harness.pi]\nkind = \"pi\"\nexecutable = \"pi\"\nenv_allow = [\"PATH\"]\nprovider = \"example-provider\"\nmodel = \"example-model\"\nsecret_env = [\"EXAMPLE_PROVIDER_KEY\"]\n",
        ))
        .expect_err("undeclared secret channel refuses");
        assert_eq!(err.code, "config.invalid");
        assert!(err.message.contains("secret_env"), "{}", err.message);
    }

    #[test]
    fn overlay_narrows_effective_repositories() {
        let dir = std::env::temp_dir().join(format!("hf-config-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let config_text = r#"schema = "hf-config/v1"
[policy]
overlay = "policy.narrow.toml"
[repository.alpha]
origin = "https://github.com/example-org/alpha"
[repository.beta]
origin = "https://github.com/example-org/beta"
"#;
        std::fs::write(
            dir.join("policy.narrow.toml"),
            r#"schema = "hf-policy/v1"
repositories = ["example-org/alpha"]
"#,
        )
        .expect("write");
        let path = dir.join("narrow-config.toml");
        std::fs::write(&path, config_text).expect("write");
        let config = load_config(&path).expect("load");
        assert_eq!(config.repositories.len(), 2);
        let effective: Vec<&str> = config
            .effective_repositories()
            .iter()
            .map(|r| r.key.as_str())
            .collect();
        assert_eq!(effective, vec!["alpha"]);
    }

    #[test]
    fn origin_identity_derivation_rules() {
        assert_eq!(
            identity_from_origin("https://github.com/example-org/widgets"),
            Some(("example-org", "widgets"))
        );
        assert_eq!(
            identity_from_origin("https://github.com/example-org/widgets.git"),
            Some(("example-org", "widgets"))
        );
        assert_eq!(
            identity_from_origin("example-org/widgets"),
            Some(("example-org", "widgets"))
        );
        assert_eq!(identity_from_origin("https://github.com/widgets"), None);
        assert_eq!(
            identity_from_origin("git@github.com:example-org/widgets"),
            None
        );
        assert_eq!(identity_from_origin("not a url"), None);
    }

    #[test]
    fn explicit_missing_config_is_not_found() {
        let missing = std::env::temp_dir().join(format!(
            "hf-config-test-{}-definitely-missing.toml",
            std::process::id()
        ));
        let err = discover_config(Some(&missing)).expect_err("must fail");
        assert_eq!(err.code, "config.not_found");
    }

    #[test]
    fn resolve_repository_by_key_and_identity() {
        let dir = std::env::temp_dir().join(format!("hf-config-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        // Self-contained: no policy overlay reference, so this test never
        // depends on an overlay another test wrote into the shared
        // per-process temp dir (order-dependent coupling).
        let path = write_temp(
            "resolve.toml",
            r#"schema = "hf-config/v1"
[repository.widgets]
origin = "https://github.com/example-org/widgets"
branch = "staging"
enabled = true
"#,
        );
        let config = load_config(&path).expect("load");
        assert_eq!(
            resolve_repository(&config, "widgets")
                .expect("key")
                .identity(),
            "example-org/widgets"
        );
        assert_eq!(
            resolve_repository(&config, "example-org/widgets")
                .expect("identity")
                .key,
            "widgets"
        );
        assert!(resolve_repository(&config, "example-org/other").is_err());
        assert!(resolve_repository(&config, "other").is_err());
    }

    #[test]
    fn template_is_a_valid_config_document() {
        let template = init_template();
        let verdict = validate_bytes(Family::Config, template.as_bytes());
        assert!(
            verdict.is_accepted(),
            "init template must validate: {}",
            verdict.message()
        );
    }

    #[test]
    fn scp_like_origins_are_refused_at_extraction() {
        let dir = std::env::temp_dir().join(format!("hf-config-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = write_temp(
            "scp.toml",
            r#"schema = "hf-config/v1"
[repository.widgets]
origin = "git@github.com:example-org/widgets"
"#,
        );
        let err = load_config(&path).expect_err("scp origin must not yield an identity");
        assert_eq!(err.code, "config.invalid");
        assert!(err.message.contains("origin"));
    }
}
