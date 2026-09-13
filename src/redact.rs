//! Conservative secret-shaped text redaction.
//!
//! The #3 CLI spec (spec-cli.md §6) requires one shared redaction pass at
//! the adapter boundary: anything captured from adapters/remotes that becomes
//! a canonical record is redacted first. Redaction is conservative —
//! false positives cost nothing, false negatives leak — and deterministic
//! (the same input always produces the same output, so acceptance-revision
//! digests over redacted text stay stable).
//!
//! The pass is a single left-to-right scan: `anchored_match` runs once per
//! input position, no helper materialises the remaining input, and every
//! helper search only walks characters that the span it yields then consumes.
//! Work is therefore linear in the input length. The pre-fix implementation
//! re-scanned the tail from each position and allocated a `String` of it at
//! every candidate — a quadratic tail per position, cubic overall — which
//! stalled the operator plan path on real issue texts (#92 acceptance
//! blocker).
//! Detections and spans are kept byte-for-byte identical to that
//! implementation, including its byte-offset span arithmetic for PEM blocks
//! and URL userinfo (pinned by `tests/redact_scale.rs` against a verbatim
//! transcription of the pre-fix algorithm).

const REPLACEMENT: &str = "[REDACTED]";

/// Token characters that may appear inside a secret-shaped run.
fn is_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '/' | '=' | '+' | '$')
}

/// A match is `(start, end)` char indices into the input.
type Match = (usize, usize);

/// Test-only complexity instrumentation for the #92 acceptance blocker:
/// candidate visits and helper-search scan steps.
///
/// Compiled out of every non-test build. The scale tests below assert
/// deterministic per-position budgets over these counters (never wall-clock
/// timing), and `tests/redact_scale.rs` adds an allocation-volume witness
/// that is independent of this instrumentation.
#[cfg(test)]
mod scale_probe {
    use std::sync::atomic::{AtomicU64, Ordering};

    static CANDIDATE_VISITS: AtomicU64 = AtomicU64::new(0);
    static SCAN_STEPS: AtomicU64 = AtomicU64::new(0);

    /// Count one per-position rule test.
    pub(super) fn note_candidate() {
        CANDIDATE_VISITS.fetch_add(1, Ordering::Relaxed);
    }

    /// Count one character examined by a search helper.
    pub(super) fn note_scan_step() {
        SCAN_STEPS.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn reset() {
        CANDIDATE_VISITS.store(0, Ordering::Relaxed);
        SCAN_STEPS.store(0, Ordering::Relaxed);
    }

    pub(super) fn counters() -> (u64, u64) {
        (
            CANDIDATE_VISITS.load(Ordering::Relaxed),
            SCAN_STEPS.load(Ordering::Relaxed),
        )
    }
}

/// Redact secret-shaped text, returning an owned copy with each match
/// replaced by `[REDACTED]`.
pub fn redact(input: &str) -> String {
    let chars: Vec<char> = input.chars().collect();
    let mut out = String::with_capacity(input.len());
    let mut url = UrlScan::new();
    let mut i = 0;
    while i < chars.len() {
        match anchored_match(&chars, i, &mut url) {
            Some((start, end)) => {
                out.extend(chars[i..start].iter());
                out.push_str(REPLACEMENT);
                i = end;
            }
            None => {
                out.push(chars[i]);
                i += 1;
            }
        }
    }
    out
}

/// Detect a secret anchored exactly at `start`; returns the absolute span to
/// redact (rules below).
///
/// Runs once per position in the pass; every search it performs is either
/// constant-bounded or charged to the span it returns.
fn anchored_match(chars: &[char], start: usize, url: &mut UrlScan) -> Option<Match> {
    #[cfg(test)]
    scale_probe::note_candidate();
    // Token-prefixed secrets (ghp_, github_pat_, glpat-, xox*, sk-, AKIA)
    // must begin at a token boundary so prose words never trigger.
    let at_boundary = start == 0 || !is_token_char(chars[start - 1]);
    if at_boundary {
        const TOKEN_PREFIXES: [(&str, usize); 10] = [
            ("github_pat_", 20),
            ("ghp_", 8),
            ("gho_", 8),
            ("ghu_", 8),
            ("ghs_", 8),
            ("ghr_", 8),
            ("glpat-", 8),
            ("xoxb-", 8),
            ("xoxp-", 8),
            ("sk-", 20),
        ];
        for (prefix, floor) in TOKEN_PREFIXES {
            if starts_with_str(chars, start, prefix) {
                // `token_run_len` returns at once for failed floors (< 20
                // characters examined) and is consumed by the span on a hit.
                let run = token_run_len(&chars[start + prefix.len()..]);
                if run >= floor {
                    return Some((start, start + prefix.len() + run));
                }
            }
        }
        for (prefix, floor) in [("xoxa-", 8), ("xoxr-", 8), ("AKIA", 16)] {
            if starts_with_str(chars, start, prefix) {
                let run = token_run_len(&chars[start + prefix.len()..]);
                if run >= floor {
                    return Some((start, start + prefix.len() + run));
                }
            }
        }
        // PEM private-key blocks: redact through the END marker line. The
        // line's trailing newline (when present) is left in place so line
        // structure survives.
        if starts_with_str(chars, start, "-----BEGIN") {
            return pem_span(chars, start);
        }
    }

    // URL userinfo: scheme://user[:pass]@host — redact the part between the
    // "://" and the "@", keeping the scheme/host text outside the span. This
    // shape is recognized regardless of the preceding character.
    if starts_with_str(chars, start, "://") {
        let segment_start = start + 3;
        // The first `/` or `@` after the scheme decides the rule: a `/` first
        // means there is no userinfo before the host path (no match).
        if let Some(at) = url.first_special(chars, segment_start)
            && chars[at] == '@'
        {
            let userinfo_bytes = byte_len(&chars[segment_start..at]);
            if userinfo_bytes >= 3 {
                return Some((segment_start, segment_start + userinfo_bytes + 1));
            }
        }
    }
    None
}

/// Span for a `-----BEGIN…` candidate: through the END marker line, or to
/// the end of the input when the block is unterminated.
///
/// The END-marker offsets are accumulated in UTF-8 bytes, exactly like the
/// pre-fix implementation's `str::find` results (which are byte offsets used
/// as character offsets); outputs stay byte-for-byte identical, and both
/// scans run over characters the span then consumes.
fn pem_span(chars: &[char], start: usize) -> Option<Match> {
    let Some(marker) = find_str(chars, start, "-----END") else {
        return Some((start, chars.len())); // unterminated: redact to end
    };
    let mut line_end = byte_len(&chars[start..marker]);
    for c in &chars[marker..] {
        if *c == '\n' {
            return Some((start, start + line_end));
        }
        #[cfg(test)]
        scale_probe::note_scan_step();
        line_end += c.len_utf8();
    }
    Some((start, start + line_end))
}

/// Amortised "first `/` or `@` at or after a position" search for the URL
/// userinfo rule.
///
/// The rule asks the question once per `://` candidate, in increasing
/// position order, so one cursor answers them all: a character is examined at
/// most once per `redact` call, which keeps inputs made of many `://`
/// near-candidates linear.
struct UrlScan {
    /// Every position below this one was examined and is neither `/` nor `@`.
    examined_to: usize,
    /// First `/` or `@` at or after `examined_to`, once it has been found.
    found: Option<usize>,
}

impl UrlScan {
    fn new() -> Self {
        Self {
            examined_to: 0,
            found: None,
        }
    }

    /// First index `>= start` holding `/` or `@`.
    ///
    /// `start` must not decrease between calls on one instance.
    fn first_special(&mut self, chars: &[char], start: usize) -> Option<usize> {
        if let Some(found) = self.found {
            if found >= start {
                return Some(found);
            }
            // The recorded hit sits before `start`; resume just after it.
            self.examined_to = found + 1;
            self.found = None;
        }
        let mut i = self.examined_to.max(start);
        while i < chars.len() {
            #[cfg(test)]
            scale_probe::note_scan_step();
            let c = chars[i];
            if c == '/' || c == '@' {
                self.examined_to = i;
                self.found = Some(i);
                return Some(i);
            }
            i += 1;
        }
        self.examined_to = chars.len();
        None
    }
}

/// First character index at or after `from` where the ASCII `needle` occurs.
///
/// The scan is charged to the span the caller consumes: a `-----BEGIN…`
/// candidate either finds its END marker inside the span it redacts or
/// redacts to the end of the input.
fn find_str(chars: &[char], from: usize, needle: &str) -> Option<usize> {
    let width = needle.chars().count();
    if width == 0 {
        return None;
    }
    let mut i = from;
    while i + width <= chars.len() {
        #[cfg(test)]
        scale_probe::note_scan_step();
        if needle.chars().eq(chars[i..i + width].iter().copied()) {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Prefix test against the character slice (no `String` materialisation).
fn starts_with_str(chars: &[char], start: usize, prefix: &str) -> bool {
    prefix
        .chars()
        .enumerate()
        .all(|(offset, expected)| chars.get(start + offset) == Some(&expected))
}

/// UTF-8 byte width of a character slice.
fn byte_len(chars: &[char]) -> usize {
    let mut total = 0;
    for c in chars {
        #[cfg(test)]
        scale_probe::note_scan_step();
        total += c.len_utf8();
    }
    total
}

/// Length of the maximal token-character run.
fn token_run_len(chars: &[char]) -> usize {
    chars.iter().take_while(|c| is_token_char(**c)).count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_common_token_shapes() {
        let token = format!("ghp_{}", "0123456789abcdef0123456789abcdef012345");
        assert_eq!(
            redact(&format!("token {token} here")),
            "token [REDACTED] here"
        );
        assert_eq!(
            redact("github_pat_0123456789abcdef0123456789abcdef"),
            "[REDACTED]"
        );
        assert_eq!(
            redact("sk-ant-0123456789abcdef0123456789abcdef0123456789abcdef"),
            "[REDACTED]"
        );
        assert_eq!(redact(concat!("AKIA", "0123456789ABCDEF")), "[REDACTED]");
    }

    #[test]
    fn redacts_pem_blocks_including_end_line() {
        let pem = format!(
            "-----BEGIN {} KEY-----\nMIIB\n-----END {} KEY-----\n",
            "PRIVATE", "PRIVATE"
        );
        assert_eq!(redact(&pem), "[REDACTED]\n");
        let no_trailing_newline = format!(
            "-----BEGIN {} KEY-----\nMIIB\n-----END {} KEY-----",
            "PRIVATE", "PRIVATE"
        );
        assert_eq!(redact(&no_trailing_newline), "[REDACTED]");
    }

    #[test]
    fn redacts_url_userinfo() {
        assert_eq!(
            redact("https://user:supersecret@example.com/path"),
            "https://[REDACTED]example.com/path"
        );
        assert_eq!(
            redact("clone from https://user@example.com/repo now"),
            "clone from https://[REDACTED]example.com/repo now"
        );
    }

    #[test]
    fn idempotent_and_conservative() {
        let text = "plain prose with ghp_short token (too short) and normal words";
        let once = redact(text);
        assert_eq!(redact(&once), once, "redaction is idempotent");
        assert!(once.contains("plain prose"));
        assert!(once.contains("ghp_short"), "short runs stay prose");
    }

    #[test]
    fn short_prefixes_stay_untouched_in_words() {
        // A ghp_-like prefix inside a longer word must not trigger.
        assert_eq!(redact("myghp_thing"), "myghp_thing");
        assert_eq!(redact("prefix-ghp_short-suffix"), "prefix-ghp_short-suffix");
    }

    #[test]
    fn adjacent_text_survives() {
        assert_eq!(
            redact(&format!(
                "before ghp_{} after",
                "0123456789abcdef0123456789abcdef012345"
            )),
            "before [REDACTED] after"
        );
    }
}

/// Deterministic complexity witnesses for the #92 acceptance blocker.
///
/// The witnesses are structural, not wall-clock: per-position rule tests
/// ("candidate visits") and characters examined by the helper searches
/// ("scan steps") must stay proportional to the input length. The pre-fix
/// implementation re-entered `anchored_match` for every position of every
/// remaining tail and allocated a copy of that tail per candidate, so its
/// work grows with the cube of the input (a quadratic tail per position) and
/// these bounds fail on it by orders of magnitude.
///
/// Fixture sizes are chosen so the same tests stay runnable against the
/// pre-fix tree (its cost there is n³/6 character copies); the large-input
/// scale cases live in `tests/redact_scale.rs`.
#[cfg(test)]
mod scale_tests {
    use super::*;
    use std::sync::Mutex;

    /// Serialises measurements: the counters are process-global and other
    /// unit tests in this binary also call `redact`. Bounds carry generous
    /// slack, so a concurrent small call cannot move a verdict.
    static MEASURE: Mutex<()> = Mutex::new(());

    /// Deterministic prose-shaped text: no secret prefix and no `://` inside.
    fn prose(len: usize) -> String {
        const ALPHABET: &[u8] = b"the quick brown foxes jump over lazy dogs 0123456789 ";
        (0..len)
            .map(|i| ALPHABET[i % ALPHABET.len()] as char)
            .collect()
    }

    /// Run `redact` once and report (output chars, candidate visits, scan steps).
    fn measure(input: &str) -> (usize, u64, u64) {
        let guard = MEASURE
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        scale_probe::reset();
        let output = redact(input);
        let (visits, steps) = scale_probe::counters();
        drop(guard);
        (output.chars().count(), visits, steps)
    }

    #[test]
    fn candidate_visits_and_scan_steps_stay_linear() {
        let shapes: Vec<(&str, String)> = vec![
            ("prose_2k", prose(2_000)),
            ("many_url_candidates", "://".repeat(500)),
            (
                "many_url_candidates_long_tail",
                format!("{}{}", "://".repeat(500), "x".repeat(1_000)),
            ),
            ("many_near_prefix_candidates", "ghp_ab ".repeat(250)),
            (
                "one_huge_single_token",
                format!("ghp_{}", "a".repeat(2_000)),
            ),
            (
                "unterminated_pem_block",
                format!("-----BEGIN KEY-----\n{}", "MIIB\n".repeat(400)),
            ),
            ("unicode_run", "é🎉 ".repeat(400)),
        ];
        for (name, input) in shapes {
            let n = input.chars().count() as u64;
            let (out_chars, visits, steps) = measure(&input);
            eprintln!(
                "scale witness {name}: input_chars={n} output_chars={out_chars} \
                 candidate_visits={visits} scan_steps={steps}"
            );
            assert!(
                visits <= 2 * n + 64,
                "{name}: {visits} candidate visits for {n} input characters is not linear"
            );
            assert!(
                steps <= 8 * n + 1024,
                "{name}: {steps} scan steps for {n} input characters is not linear"
            );
        }
    }

    #[test]
    fn repeated_redaction_stays_within_the_same_budget() {
        // Idempotent output re-entry: a redacted document is redacted again at
        // the board/observe boundaries, so the budget must hold on it too.
        let once = redact(&prose(1_000));
        let (_, visits, steps) = measure(&once);
        let n = once.chars().count() as u64;
        assert!(visits <= 2 * n + 64, "re-entry visits: {visits} for {n}");
        assert!(steps <= 8 * n + 1024, "re-entry steps: {steps} for {n}");
    }
}
