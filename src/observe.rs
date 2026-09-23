//! Read adapters and bounded concurrent observation.
//!
//! This slice's read-only surfaces:
//! - **git** — local checkout reads (`git rev-parse`/`config`) executed in
//!   the invoking working directory; never any network git operation,
//! - **github** — authenticated `gh api` reads from the invoking
//!   environment's `gh` (no token storage, no credential handling),
//! - **herdr** — a presence/version probe (`herdr --version`); workspace
//!   session protocol reads (session observation, interruption, outcome
//!   collection, identity read-back) landed as typed session operations in
//!   the adapter slice (child #7, [`crate::adapters`]) with a v1 candidate
//!   invocation contract whose real-world parity is verified on clean hosts
//!   (issue #7 AC6), never in public CI.
//!
//! Every adapter runs through [`crate::process::run`] with a per-process
//! deadline, an allowlisted environment, and no shell evaluation. Captured
//! output is redacted at this boundary before it can become a canonical
//! record (spec-cli.md §6). Observations carry explicit freshness,
//! completeness, and exact source identity; nothing is hidden when a surface
//! is unavailable.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use crate::canonical::sha256_hex;
use crate::config::Repository;
use crate::formats::{is_hex40, is_hex64, parse_semver};
use crate::process::{ProcSpec, ProcStatus, run};
use crate::redact::redact;
use crate::value::{Val, bool_, integer, null, object, string};

/// Per-process deadline for every adapter read.
pub const ADAPTER_TIMEOUT: Duration = Duration::from_secs(10);
/// Maximum concurrent repository observers (worker threads).
pub const MAX_CONCURRENT_OBSERVERS: usize = 4;
/// Declared minimum Herdr CLI version (docs/contracts/compatibility.md).
/// Issue #35 retained this floor because protocol 20/22 mixed pairs are red;
/// the value is not a mixed-server compatibility claim.
pub const HERDR_MINIMUM: (u64, u64, u64) = (0, 8, 2);
/// Declared minimum `gh` major.minor floor.
pub const GH_MINIMUM: (u64, u64, u64) = (2, 0, 0);
/// Cap on diagnostics text captured from adapters.
const DIAGNOSTIC_CAP: usize = 200;

/// One normalized observation about a subject.
#[derive(Clone, Debug)]
pub struct Observation {
    /// Subject type from the closed set (`repository` | `agent` | `host`).
    pub subject_type: &'static str,
    /// Subject id (repository identity or a fixed adapter subject id).
    pub subject_id: String,
    /// `fresh` (read back within this invocation) or `unknown`.
    pub freshness: &'static str,
    /// `complete` (every requested target read) or `partial`.
    pub completeness: &'static str,
    /// Free-form typed payload (redacted at the adapter boundary).
    pub payload: Val,
    /// Wall time of the observation in milliseconds.
    pub duration_ms: u64,
}

impl Observation {
    /// Render the observation as an `hf-observation/v1` document.
    pub fn to_doc(&self, observed_at: &str) -> Val {
        object(vec![
            ("schema", string("hf-observation/v1")),
            (
                "subject",
                object(vec![
                    ("type", string(self.subject_type)),
                    ("id", string(&self.subject_id)),
                ]),
            ),
            ("observed_at", string(observed_at)),
            ("freshness", string(self.freshness)),
            ("completeness", string(self.completeness)),
            ("payload", self.payload.clone()),
        ])
    }
}

/// Aggregate observation counters and durations (AC6 evidence).
#[derive(Clone, Debug, Default)]
pub struct RunTotals {
    /// Adapter read requests attempted.
    pub requests: usize,
    /// Child processes spawned.
    pub processes: usize,
    /// Observations that ended partial.
    pub partial_failures: usize,
    /// Per-observation wall times in milliseconds.
    pub durations_ms: Vec<u64>,
}

impl RunTotals {
    /// Summary object for the `timings_ms` field of status data.
    pub fn timings_obj(&self) -> Val {
        object(vec![
            (
                "p50_ms",
                integer(percentile_ms(&self.durations_ms, 50.0) as i64),
            ),
            (
                "p95_ms",
                integer(percentile_ms(&self.durations_ms, 95.0) as i64),
            ),
            (
                "min_ms",
                integer(self.durations_ms.iter().copied().min().unwrap_or(0) as i64),
            ),
            (
                "max_ms",
                integer(self.durations_ms.iter().copied().max().unwrap_or(0) as i64),
            ),
            ("requests", integer(self.requests as i64)),
            ("processes", integer(self.processes as i64)),
            ("partial_failures", integer(self.partial_failures as i64)),
        ])
    }
}

/// Nearest-rank percentile over an ascending-sorted sample; empty samples
/// yield 0. The rank of the p-th percentile of n samples is
/// `ceil(p/100 * n)`, 1-based (documented so reported p50/p95 values are
/// reproducible from the raw durations).
pub fn percentile_ms(samples: &[u64], percentile: f64) -> u64 {
    if samples.is_empty() {
        return 0;
    }
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let rank = ((percentile / 100.0) * sorted.len() as f64).ceil() as usize;
    sorted[rank.saturating_sub(1).min(sorted.len() - 1)]
}

/// Cap and redact captured adapter text for diagnostics.
///
/// Adapter output is hostile and may be lossy UTF-8, so the final byte cap
/// must land on a char boundary: truncating mid-char panics (review r1-1)
/// and would destroy the hf-output/v1 framing. All call sites go through
/// this one primitive.
/// The head of one remote branch, read with `git ls-remote` from the
/// allowlisted environment. Never a stale local remote-tracking ref: the
/// read is the remote's own answer, and `Ok(None)` means the branch does not
/// exist there.
pub fn ls_remote_head(
    env: &BTreeMap<String, String>,
    branch: &str,
) -> Result<Option<String>, String> {
    let refname = format!("refs/heads/{branch}");
    let args = vec![
        "ls-remote".to_string(),
        "origin".to_string(),
        refname.clone(),
    ];
    let (result, _) = adapter_run("git", &args, env, None);
    let out = result.map_err(|message| {
        if message == "timeout" {
            "git ls-remote timed out".to_string()
        } else {
            format!("git unavailable: {message}")
        }
    })?;
    if out.status.exit_code() != Some(0) {
        return Err(diagnostics(&format!("{}\n{}", out.stderr, out.stdout)));
    }
    for line in out.stdout.lines() {
        let mut parts = line.split_whitespace();
        if let (Some(sha), Some(name)) = (parts.next(), parts.next())
            && name == refname
            && is_hex40(sha)
        {
            return Ok(Some(sha.to_string()));
        }
    }
    Ok(None)
}

/// Bounded one-line human stderr/stdout diagnostics, redacted at the boundary.
pub fn diagnostics(text: &str) -> String {
    let redacted = redact(text);
    let mut lines = redacted.lines().map(str::trim).filter(|l| !l.is_empty());
    let mut out = String::new();
    for line in lines.by_ref().take(2) {
        if !out.is_empty() {
            out.push_str(" | ");
        }
        out.push_str(line);
        if out.len() >= DIAGNOSTIC_CAP {
            break;
        }
    }
    out.truncate(floor_char_boundary(&out, DIAGNOSTIC_CAP));
    out
}

/// Largest char boundary at or below `limit` bytes (see [`diagnostics`]).
fn floor_char_boundary(text: &str, limit: usize) -> usize {
    if text.len() <= limit {
        return text.len();
    }
    let mut end = limit;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    end
}

/// Run one adapter command, returning a typed result plus the process count.
fn adapter_run(
    program: &str,
    args: &[String],
    env: &BTreeMap<String, String>,
    cwd: Option<&Path>,
) -> (Result<crate::process::ProcOut, String>, usize) {
    let out = run(ProcSpec {
        program,
        args,
        env,
        cwd,
        timeout: ADAPTER_TIMEOUT,
    });
    let processes = usize::from(!matches!(out.status, ProcStatus::SpawnFailed(_)));
    match out.status {
        ProcStatus::Exit(_) => (Ok(out), processes),
        ProcStatus::TimedOut => (Err("timeout".to_string()), processes),
        ProcStatus::SpawnFailed(message) => (Err(message), processes),
    }
}

/// Probe an executable's version (`<program> --version`).
/// Returns (present, version, detail).
pub fn probe_version(
    program: &str,
    env: &BTreeMap<String, String>,
) -> (bool, Option<String>, Option<String>, usize) {
    let args = vec!["--version".to_string()];
    let (result, processes) = adapter_run(program, &args, env, None);
    match result {
        Err(_) => (
            false,
            None,
            Some(format!("{program} not found on PATH")),
            processes,
        ),
        Ok(out) if out.status.exit_code() == Some(0) => {
            let first_line = out.stdout.lines().next().unwrap_or("").trim().to_string();
            let version = first_line
                .split_whitespace()
                .find_map(parse_semver)
                .map(|(maj, min, pat)| format!("{maj}.{min}.{pat}"));
            match version {
                Some(version) => (true, Some(version), None, processes),
                None => (
                    true,
                    None,
                    Some(format!(
                        "unparsable version output: {}",
                        diagnostics(&first_line)
                    )),
                    processes,
                ),
            }
        }
        Ok(out) => (
            true,
            None,
            Some(format!(
                "version probe failed: {}",
                diagnostics(&out.stderr)
            )),
            processes,
        ),
    }
}

/// Probe `gh` authentication state (`gh auth status`, no token output).
/// Returns (authenticated, scopes, detail).
pub fn probe_gh_auth(
    env: &BTreeMap<String, String>,
) -> (bool, Option<Vec<String>>, Option<String>, usize) {
    let args = vec!["auth".to_string(), "status".to_string()];
    let (result, processes) = adapter_run("gh", &args, env, None);
    match result {
        Err(_) => (
            false,
            None,
            Some("gh not found on PATH".to_string()),
            processes,
        ),
        Ok(out) => {
            let combined = format!("{}\n{}", out.stdout, out.stderr);
            if out.status.exit_code() == Some(0) {
                let scopes = combined.lines().find_map(|line| {
                    let line = line.trim();
                    let marker = "Token scopes:";
                    line.find(marker).map(|idx| {
                        line[idx + marker.len()..]
                            .split(',')
                            .map(|part| {
                                part.trim()
                                    .trim_matches(|c| c == '\'' || c == '"' || c == '[' || c == ']')
                                    .to_string()
                            })
                            .filter(|s| !s.is_empty())
                            .collect::<Vec<String>>()
                    })
                });
                (true, scopes, None, processes)
            } else {
                (false, None, Some(diagnostics(&combined)), processes)
            }
        }
    }
}

/// Herdr presence/version observation (host subject, fixed id `herdr`).
pub fn observe_herdr(env: &BTreeMap<String, String>) -> (Observation, RunTotals) {
    let mut totals = RunTotals::default();
    totals.requests += 1;
    let args = vec!["--version".to_string()];
    let (result, processes) = adapter_run("herdr", &args, env, None);
    totals.processes += processes;
    let (present, version, detail) = match result {
        Err(_) => (false, None, Some("herdr not found on PATH".to_string())),
        Ok(out) if out.status.exit_code() == Some(0) => {
            let first_line = out.stdout.lines().next().unwrap_or("").trim().to_string();
            match first_line.split_whitespace().find_map(parse_semver) {
                Some((maj, min, pat)) => (true, Some(format!("{maj}.{min}.{pat}")), None),
                None => (
                    true,
                    None,
                    Some(format!(
                        "unparsable version output: {}",
                        diagnostics(&first_line)
                    )),
                ),
            }
        }
        Ok(out) => (
            true,
            None,
            Some(format!(
                "version probe failed: {}",
                diagnostics(&out.stderr)
            )),
        ),
    };
    let (freshness, completeness, payload) = match (present, &version) {
        (true, Some(version)) => {
            let compatible = parse_semver(version).is_some_and(|v| v >= HERDR_MINIMUM);
            let payload = object(vec![
                ("surface", string("herdr")),
                ("source", string("herdr --version")),
                ("present", bool_(true)),
                ("version", string(version)),
                ("compatible", bool_(compatible)),
                ("declared_minimum", string("0.8.2")),
            ]);
            ("fresh", "complete", payload)
        }
        (true, None) => {
            let mut fields = vec![
                ("surface", string("herdr")),
                ("source", string("herdr --version")),
                ("present", bool_(true)),
            ];
            if let Some(detail) = detail {
                fields.push(("detail", string(&detail)));
            }
            ("unknown", "partial", object(fields))
        }
        (false, _) => {
            let mut fields = vec![
                ("surface", string("herdr")),
                ("source", string("herdr --version")),
                ("present", bool_(false)),
            ];
            if let Some(detail) = detail {
                fields.push(("detail", string(&detail)));
            }
            ("unknown", "complete", object(fields))
        }
    };
    let observation = Observation {
        subject_type: "host",
        subject_id: "herdr".to_string(),
        freshness,
        completeness,
        payload,
        duration_ms: 0,
    };
    (observation, totals)
}

/// Normalize an origin URL for comparison: strip a trailing `.git` and `/`.
fn normalized_origin(origin: &str) -> &str {
    origin
        .trim_end_matches('/')
        .strip_suffix(".git")
        .unwrap_or(origin.trim_end_matches('/'))
}

/// Observe one repository (git local + github remote) with bounded adapter
/// calls; returns the observation and the request/process totals it used.
pub fn observe_repository(
    repository: &Repository,
    env: &BTreeMap<String, String>,
    cwd: &Path,
) -> (Observation, RunTotals) {
    let started = std::time::Instant::now();
    let mut totals = RunTotals::default();
    let git_payload;

    // --- git local surface (only local commands; never network git) ---
    totals.requests += 1;
    let top = vec!["rev-parse".to_string(), "--show-toplevel".to_string()];
    let (result, processes) = adapter_run("git", &top, env, Some(cwd));
    totals.processes += processes;
    let checkout = matches!(&result, Ok(out) if out.status.exit_code() == Some(0));
    if checkout {
        let mut origin_matches: Option<bool> = None;
        let mut branch: Option<String> = None;
        let mut head: Option<String> = None;
        let mut head_format: Option<&'static str> = None;
        for (args, label) in [
            (
                vec![
                    "config".to_string(),
                    "--get".to_string(),
                    "remote.origin.url".to_string(),
                ],
                "origin",
            ),
            (
                vec![
                    "rev-parse".to_string(),
                    "--abbrev-ref".to_string(),
                    "HEAD".to_string(),
                ],
                "branch",
            ),
            (vec!["rev-parse".to_string(), "HEAD".to_string()], "head"),
        ] {
            let (result, processes) = adapter_run("git", &args, env, Some(cwd));
            totals.processes += processes;
            let Ok(out) = result else { continue };
            if out.status.exit_code() != Some(0) {
                continue;
            }
            let text = out.stdout.trim().to_string();
            match label {
                "origin" => {
                    origin_matches =
                        Some(normalized_origin(&text) == normalized_origin(&repository.origin));
                }
                "branch" if text != "HEAD" && !text.is_empty() => branch = Some(text),
                "head" if is_hex40(&text) => {
                    head_format = Some("sha1");
                    head = Some(text);
                }
                "head" if is_hex64(&text) => {
                    head_format = Some("sha256");
                    head = Some(text);
                }
                _ => {}
            }
        }
        git_payload = Some(object(vec![
            ("surface", string("git")),
            ("source", string("local git checkout")),
            ("available", bool_(true)),
            (
                "origin_matches",
                match origin_matches {
                    Some(value) => bool_(value),
                    None => null(),
                },
            ),
            (
                "branch",
                match branch {
                    Some(value) => string(&value),
                    None => null(),
                },
            ),
            (
                "head",
                match head {
                    Some(value) => string(&value),
                    None => null(),
                },
            ),
            (
                "head_format",
                match head_format {
                    Some(value) => string(value),
                    None => null(),
                },
            ),
        ]));
    } else {
        git_payload = Some(object(vec![
            ("surface", string("git")),
            ("source", string("local git checkout")),
            ("available", bool_(false)),
            ("reason", string("no_local_checkout")),
        ]));
    }

    // --- github remote surface (authenticated gh from the invoking env) ---
    totals.requests += 1;
    let api_args = vec![
        "api".to_string(),
        format!("repos/{}/{}", repository.owner, repository.name),
    ];
    let (result, processes) = adapter_run("gh", &api_args, env, Some(cwd));
    totals.processes += processes;
    let github_payload = match result {
        Err(message) => object(vec![
            ("surface", string("github")),
            ("source", string("gh api repos/owner/name")),
            ("available", bool_(false)),
            ("reason", string("gh.unavailable")),
            ("detail", string(&diagnostics(&message))),
        ]),
        Ok(out) if out.status.exit_code() == Some(0) => {
            let text = redact(&out.stdout);
            match Val::parse_json(&text) {
                Ok(doc) => {
                    let remote_identity = doc
                        .get("full_name")
                        .and_then(Val::as_str)
                        .unwrap_or("")
                        .to_string();
                    let identity_matches = remote_identity == repository.identity();
                    let default_branch = doc
                        .get("default_branch")
                        .and_then(Val::as_str)
                        .unwrap_or("")
                        .to_string();
                    let archived = matches!(doc.get("archived"), Some(Val::Bool(true)));
                    object(vec![
                        ("surface", string("github")),
                        ("source", string("gh api repos/owner/name")),
                        ("available", bool_(true)),
                        ("remote_identity", string(&remote_identity)),
                        ("identity_matches", bool_(identity_matches)),
                        ("default_branch", string(&default_branch)),
                        ("archived", bool_(archived)),
                    ])
                }
                Err(_) => object(vec![
                    ("surface", string("github")),
                    ("source", string("gh api repos/owner/name")),
                    ("available", bool_(false)),
                    ("reason", string("gh.api_error")),
                    ("detail", string(&diagnostics(&text))),
                ]),
            }
        }
        Ok(out) => object(vec![
            ("surface", string("github")),
            ("source", string("gh api repos/owner/name")),
            ("available", bool_(false)),
            ("reason", string("gh.api_error")),
            (
                "detail",
                string(&diagnostics(&format!("{}\n{}", out.stderr, out.stdout))),
            ),
        ]),
    };

    // --- combine ---
    let git_available = git_payload
        .as_ref()
        .is_some_and(|p| matches!(p.get("available"), Some(Val::Bool(true))));
    let git_matches = git_payload
        .as_ref()
        .is_some_and(|p| matches!(p.get("origin_matches"), Some(Val::Bool(true))));
    let github_available = matches!(github_payload.get("available"), Some(Val::Bool(true)));
    let complete = github_available || (git_available && git_matches);
    let payload = object(vec![
        ("git", git_payload.unwrap_or_else(null)),
        ("github", github_payload),
    ]);

    let observation = Observation {
        subject_type: "repository",
        subject_id: repository.identity(),
        freshness: if complete { "fresh" } else { "unknown" },
        completeness: if complete { "complete" } else { "partial" },
        payload,
        duration_ms: started.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
    };
    (observation, totals)
}

/// Observe every effective repository with bounded concurrency
/// ([`MAX_CONCURRENT_OBSERVERS`] workers), plus the herdr probe, and return
/// observations sorted by repository identity (deterministic output order)
/// with the aggregated request/process/duration totals.
pub fn observe_all(
    repositories: &[&Repository],
    env: &BTreeMap<String, String>,
    cwd: &Path,
) -> (Vec<Observation>, RunTotals) {
    let mut totals = RunTotals::default();
    let mut observations: Vec<Observation> = Vec::new();

    let (herdr, herdr_totals) = observe_herdr(env);
    totals.requests += herdr_totals.requests;
    totals.processes += herdr_totals.processes;
    observations.push(herdr);

    let next = AtomicUsize::new(0);
    let results: Mutex<Vec<(String, Observation, RunTotals)>> = Mutex::new(Vec::new());
    let worker_count = repositories.len().min(MAX_CONCURRENT_OBSERVERS);
    if worker_count > 0 {
        std::thread::scope(|scope| {
            for _ in 0..worker_count {
                scope.spawn(|| {
                    loop {
                        let index = next.fetch_add(1, Ordering::Relaxed);
                        let Some(repository) = repositories.get(index) else {
                            break;
                        };
                        let (observation, per_repo) = observe_repository(repository, env, cwd);
                        results.lock().expect("results lock").push((
                            observation.subject_id.clone(),
                            observation,
                            per_repo,
                        ));
                    }
                });
            }
        });
    }

    let mut collected: Vec<(String, Observation, RunTotals)> =
        results.into_inner().expect("results");
    collected.sort_by(|a, b| a.0.cmp(&b.0));
    for (_, observation, per_repo) in collected {
        totals.requests += per_repo.requests;
        totals.processes += per_repo.processes;
        totals.durations_ms.push(observation.duration_ms);
        if observation.completeness == "partial" {
            totals.partial_failures += 1;
        }
        observations.push(observation);
    }
    (observations, totals)
}

/// Fetch an issue's acceptance text (title + body) through `gh api`.
/// Returns `(title, body)` with both values redacted at the boundary.
pub fn gh_issue_text(
    owner: &str,
    name: &str,
    number: u64,
    env: &BTreeMap<String, String>,
) -> Result<(String, String), String> {
    let args = vec![
        "api".to_string(),
        format!("repos/{owner}/{name}/issues/{number}"),
    ];
    let (result, _) = adapter_run("gh", &args, env, None);
    let out = result.map_err(|message| {
        if message == "timeout" {
            "gh api timed out".to_string()
        } else {
            format!("gh unavailable: {message}")
        }
    })?;
    if out.status.exit_code() != Some(0) {
        return Err(format!(
            "gh api failed: {}",
            diagnostics(&format!("{}\n{}", out.stderr, out.stdout))
        ));
    }
    let text = redact(&out.stdout);
    let doc =
        Val::parse_json(&text).map_err(|err| format!("gh api returned unparsable JSON: {err}"))?;
    let title = doc
        .get("title")
        .and_then(Val::as_str)
        .unwrap_or("")
        .to_string();
    let body = doc
        .get("body")
        .and_then(Val::as_str)
        .unwrap_or("")
        .to_string();
    Ok((title, body))
}

/// Compute the acceptance revision (40-hex) for issue text: the first 40 hex
/// characters of the SHA-256 over the canonical serialization of the
/// redacted `{title, body}` pair. Redaction happens before hashing, so the
/// revision never binds secret-shaped text (spec-cli.md §6).
pub fn acceptance_revision(title: &str, body: &str) -> String {
    let doc = object(vec![
        ("title", string(&redact(title))),
        ("body", string(&redact(body))),
    ]);
    let digest = sha256_hex(&crate::canonical::canonical_bytes(&doc));
    digest[..40].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::adapter_environment;
    use crate::schema::{Family, validate_doc};

    fn sample_repository() -> Repository {
        Repository {
            key: "widgets".to_string(),
            owner: "example-org".to_string(),
            name: "widgets".to_string(),
            origin: "https://github.com/example-org/widgets".to_string(),
            branch: Some("staging".to_string()),
            enabled: true,
        }
    }

    #[test]
    fn percentile_nearest_rank_is_deterministic() {
        let samples = [10u64, 20, 30, 40];
        assert_eq!(percentile_ms(&samples, 50.0), 20);
        assert_eq!(percentile_ms(&samples, 95.0), 40);
        let single = [7u64];
        assert_eq!(percentile_ms(&single, 50.0), 7);
        assert_eq!(percentile_ms(&[], 50.0), 0);
    }

    #[test]
    fn observation_docs_validate_against_the_family() {
        let observation = Observation {
            subject_type: "repository",
            subject_id: "example-org/widgets".to_string(),
            freshness: "fresh",
            completeness: "complete",
            payload: object(vec![
                ("surface", string("github")),
                ("available", bool_(true)),
            ]),
            duration_ms: 3,
        };
        let doc = observation.to_doc("2026-09-06T00:00:00Z");
        let verdict = validate_doc(Family::Observation, &doc);
        assert!(verdict.is_accepted(), "{}", verdict.message());
    }

    #[test]
    fn herdr_observation_doc_validates_when_present_and_absent() {
        let env = adapter_environment();
        let (observation, _) = observe_herdr(&env);
        let doc = observation.to_doc("2026-09-06T00:00:00Z");
        let verdict = validate_doc(Family::Observation, &doc);
        assert!(verdict.is_accepted(), "{}", verdict.message());
        assert!(matches!(observation.freshness, "fresh" | "unknown"));
    }

    #[test]
    fn repository_observation_is_deterministic_shape() {
        let env = adapter_environment();
        // A synthetic cwd that is not a git checkout: git surface degrades;
        // gh may or may not be available, but the document must validate.
        let cwd = std::env::temp_dir();
        let (observation, totals) = observe_repository(&sample_repository(), &env, &cwd);
        let doc = observation.to_doc("2026-09-06T00:00:00Z");
        let verdict = validate_doc(Family::Observation, &doc);
        assert!(verdict.is_accepted(), "{}", verdict.message());
        assert!(totals.requests >= 2);
        assert!(matches!(observation.completeness, "complete" | "partial"));
    }

    #[test]
    fn acceptance_revision_is_stable_and_sensitive() {
        let first = acceptance_revision("Fix the thing", "Acceptance: build passes");
        assert_eq!(
            first,
            acceptance_revision("Fix the thing", "Acceptance: build passes")
        );
        assert_ne!(
            first,
            acceptance_revision("Fix the thing", "Acceptance: tests pass")
        );
        assert_ne!(
            first,
            acceptance_revision("Fix the other thing", "Acceptance: build passes")
        );
        assert_eq!(first.len(), 40);
        assert!(is_hex40(&first));
    }

    #[test]
    fn acceptance_revision_redacts_secrets_before_hashing() {
        let secret = format!("Deploy key: ghp_{}", "a".repeat(36));
        let normal = format!("Deploy key: {}", "[REDACTED]");
        assert_eq!(
            acceptance_revision(&secret, ""),
            acceptance_revision(&normal, ""),
            "secret-shaped text must be redacted before the revision is bound"
        );
    }

    #[test]
    fn gh_issue_text_rejects_hostile_payloads_safely() {
        // The gh binary may be absent here; the function must return a typed
        // Err rather than panic, and never evaluate the response.
        let env = adapter_environment();
        if let Ok((title, body)) = gh_issue_text("example-org", "widgets", 1, &env) {
            assert!(title.len() < 10_000 && body.len() < 10_000);
        }
    }
}
