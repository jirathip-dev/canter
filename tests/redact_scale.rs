//! Scale, discrimination, and semantic-equivalence tests for the
//! adapter-boundary redaction pass (#92 acceptance blocker).
//!
//! The pre-fix `redact` stalled the operator plan path on a real issue text:
//! it scanned every position, re-scanned the tail from each one, and
//! allocated a `String` of the remaining input at every candidate — a
//! quadratic tail per position, cubic overall. The witnesses here are
//! deterministic and structural, never wall-clock:
//!
//! 1. `allocation_*` — allocation volume and allocation count for one
//!    `redact` call must stay proportional to the input length, measured with
//!    a counting global allocator (independent of any library
//!    instrumentation);
//! 2. `corpus_*` — every corpus case (ASCII, non-ASCII, adversarial, prose)
//!    must equal `reference_redact`, a verbatim transcription of the pre-fix
//!    algorithm, which pins detection and span semantics byte-for-byte on
//!    every input class, not just ASCII.
//!
//! Corpus cases are deliberately small so the equality tests also run against
//! the pre-fix tree: there, `reference_redact` matches by construction while
//! every `allocation_*` bound fails by orders of magnitude.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Instant;

use canter::redact::redact;

// --- allocation instrumentation -------------------------------------------

static TRACKING: AtomicBool = AtomicBool::new(false);
static ALLOC_CALLS: AtomicUsize = AtomicUsize::new(0);
static ALLOC_BYTES: AtomicUsize = AtomicUsize::new(0);

struct CountingAllocator;

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if TRACKING.load(Ordering::Relaxed) {
            ALLOC_CALLS.fetch_add(1, Ordering::Relaxed);
            ALLOC_BYTES.fetch_add(layout.size(), Ordering::Relaxed);
        }
        // SAFETY: the caller's layout is forwarded to the system allocator
        // unchanged, so ownership and alignment requirements are preserved.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: `ptr`/`layout` come from this allocator's `alloc`
        // (or realloc, which routes through it) and are forwarded unchanged.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

/// Serialises measurement: the allocation counters are process-global, so
/// every test in this binary takes this guard for its whole body — that is
/// what makes a window contain exactly one thread's allocations.
static WINDOW: Mutex<()> = Mutex::new(());

/// Guard held by every test in this file (see [`WINDOW`]).
fn serial() -> std::sync::MutexGuard<'static, ()> {
    WINDOW
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Allocation calls and bytes made while `f` runs.
///
/// Callers must hold the [`serial`] guard so no other test in this binary can
/// allocate inside the window.
fn measured<T>(f: impl FnOnce() -> T) -> (T, usize, usize) {
    ALLOC_CALLS.store(0, Ordering::SeqCst);
    ALLOC_BYTES.store(0, Ordering::SeqCst);
    TRACKING.store(true, Ordering::SeqCst);
    let value = f();
    TRACKING.store(false, Ordering::SeqCst);
    let calls = ALLOC_CALLS.load(Ordering::SeqCst);
    let bytes = ALLOC_BYTES.load(Ordering::SeqCst);
    (value, calls, bytes)
}

/// Linear allocation budget for one `redact` call on `n` input characters:
/// the input copy (`Vec<char>`, 4 bytes per char) plus the output buffer plus
/// a generous allowance for runtime noise. The pre-fix implementation
/// allocated a fresh copy of the remaining input at every candidate position,
/// which is ~n²/2 bytes for a no-match input — an order of magnitude over
/// budget on the 2 000-character adversarial shapes below and astronomically
/// over it on the issue-scale shapes.
const BYTES_PER_CHAR: usize = 64;
const BYTES_SLACK: usize = 64 * 1024;
const ALLOC_CALL_LIMIT: usize = 1024;

// --- deterministic fixture builders ---------------------------------------

/// Token-shaped run over characters that are legal inside a run.
fn run(len: usize) -> String {
    const RUN_CHARS: &[u8] =
        b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-.=/+$";
    (0..len)
        .map(|i| RUN_CHARS[i % RUN_CHARS.len()] as char)
        .collect()
}

/// Prefix plus a token-shaped run of `len` characters.
fn token(prefix: &str, len: usize) -> String {
    format!("{prefix}{}", run(len))
}

/// Deterministic prose-shaped text: no secret prefix and no `://` inside.
fn prose(len: usize) -> String {
    const ALPHABET: &[u8] = b"the quick brown foxes jump over lazy dogs 0123456789 ";
    (0..len)
        .map(|i| ALPHABET[i % ALPHABET.len()] as char)
        .collect()
}

/// A PEM marker line, assembled at runtime: the public-tree scanner rejects
/// literal PEM markers in the tracked tree (`RULE-PEM-PRIVATE-KEY`,
/// scripts/check-public-tree.py).
fn pem_marker(kind: &str, label: &str) -> String {
    let fence = "-".repeat(5);
    format!("{fence}{kind} {label} KEY{fence}")
}

/// `-----BEGIN <label> KEY-----` block with an END line and a trailing LF.
fn pem_block(label: &str) -> String {
    format!(
        "{}\nMIIB\n{}\n",
        pem_marker("BEGIN", label),
        pem_marker("END", label)
    )
}

/// `PRIVATE KEY` label assembled at runtime (see [`pem_marker`]).
fn private_key_label() -> String {
    ["PRIVATE", "KEY"].join(" ")
}

/// Markdown-shaped issue text of roughly 200 KiB: the size class that
/// reproduces the pre-fix stall on a real issue.
fn issue_scale_text() -> String {
    let mut text = String::with_capacity(256 * 1024);
    let mut section = 0;
    while text.len() < 200 * 1024 {
        section += 1;
        text.push_str(&format!("## Acceptance notes, section {section}\n"));
        text.push_str("Context lives at https://example.com/issues/92 and in the logs below.\n");
        text.push_str("```sh\ncargo test --locked --lib redact\n```\n");
        text.push_str("Repeated prose keeps the tail long enough to matter: ");
        text.push_str(&prose(400));
        text.push_str("\n\n");
        text.push_str(&format!(
            "A pasted log line carried token {} once.\n",
            token("ghp_", 40)
        ));
        text.push_str("- [ ] follow-up\n- [x] recorded\n\n");
    }
    text
}

/// Corpus cases: (name, input, must contain `[REDACTED]`). Every case is
/// small so the quadratic reference below stays cheap.
fn corpus() -> Vec<(&'static str, String, bool)> {
    let label = private_key_label();
    let cases: Vec<(&'static str, String, bool)> = vec![
        ("empty_input", String::new(), false),
        ("single_char", "a".to_string(), false),
        (
            "prose_plain",
            "the quick brown fox jumps over the lazy dog".to_string(),
            false,
        ),
        ("ghp_floor_exact", token("ghp_", 8), true),
        ("ghp_below_floor", token("ghp_", 7), false),
        (
            "ghp_long_in_prose",
            format!("token {} here", token("ghp_", 40)),
            true,
        ),
        ("ghp_in_word", "myghp_thing".to_string(), false),
        (
            // A `-` is a token character, so this is NOT a token boundary:
            // the pre-fix algorithm leaves the run alone.
            "ghp_after_dash_not_at_boundary",
            format!("prefix-ghp_{}-suffix", run(40)),
            false,
        ),
        ("ghp_after_space", format!(" {}", token("ghp_", 40)), true),
        (
            "ghp_after_newline",
            format!("\n{}", token("ghp_", 40)),
            true,
        ),
        ("ghp_after_dot", format!(".{}", token("ghp_", 40)), false),
        (
            "ghp_not_at_boundary",
            format!("x{}", token("ghp_", 40)),
            false,
        ),
        ("github_pat_floor_exact", token("github_pat_", 20), true),
        ("github_pat_below_floor", token("github_pat_", 19), false),
        (
            "github_pat_in_prose",
            format!("see {} for details", token("github_pat_", 50)),
            true,
        ),
        ("gho_floor_exact", token("gho_", 8), true),
        ("ghs_below_floor", token("ghs_", 7), false),
        ("glpat_floor_exact", token("glpat-", 8), true),
        ("glpat_symbols_in_run", token("glpat-", 15), true),
        ("xoxb_floor_exact", token("xoxb-", 8), true),
        ("xoxp_long", token("xoxp-", 30), true),
        ("xoxa_floor_exact", token("xoxa-", 8), true),
        ("xoxr_long", token("xoxr-", 20), true),
        ("sk_floor_exact", token("sk-", 20), true),
        ("sk_below_floor", token("sk-", 19), false),
        ("akia_floor_exact", format!("AKIA{}", run(16)), true),
        ("akia_below_floor", format!("AKIA{}", run(15)), false),
        ("pem_terminated", pem_block(&label), true),
        (
            "pem_no_trailing_newline",
            format!(
                "{}\nMIIB\n{}",
                pem_marker("BEGIN", &label),
                pem_marker("END", &label)
            ),
            true,
        ),
        (
            "pem_crlf",
            "-----BEGIN KEY-----\r\nMIIB\r\n-----END KEY-----\r\n".to_string(),
            true,
        ),
        (
            "pem_two_blocks",
            format!("{}\n{}", pem_block("A"), pem_block("B")),
            true,
        ),
        (
            "pem_unterminated",
            format!("{}\nMIIB\n", pem_marker("BEGIN", &label)),
            true,
        ),
        (
            "pem_unterminated_in_prose",
            "log follows\n-----BEGIN KEY-----\npartial body".to_string(),
            true,
        ),
        (
            // `-----BEGIN` with no END marker anywhere: the pre-fix
            // algorithm redacts to the end of the input.
            "pem_marker_unterminated_string",
            "-----BEGIN-ish but not a block".to_string(),
            true,
        ),
        (
            "pem_not_at_boundary",
            "x-----BEGIN KEY-----\nbody\n-----END KEY-----\n".to_string(),
            false,
        ),
        (
            "url_userinfo_password",
            "https://user:supersecret@example.com/path".to_string(),
            true,
        ),
        (
            "url_userinfo_user_only",
            "clone from https://user@example.com/repo now".to_string(),
            true,
        ),
        (
            "url_exact_three_bytes",
            "https://abc@example.com".to_string(),
            true,
        ),
        ("url_two_bytes", "https://ab@example.com".to_string(), false),
        (
            "url_slash_before_at",
            "https://us/er@example.com".to_string(),
            false,
        ),
        (
            "url_no_userinfo",
            "https://example.com/path".to_string(),
            false,
        ),
        ("url_bare_scheme", "://".to_string(), false),
        ("url_bare_scheme_then_at", "://@".to_string(), false),
        (
            "url_nonascii_userinfo",
            "https://éé@example.com/path".to_string(),
            true,
        ),
        (
            "url_nonascii_one_char",
            "https://é@example.com".to_string(),
            false,
        ),
        ("url_short_scheme_prefix", "a://b@c".to_string(), false),
        (
            "at_without_scheme",
            "mail user@example.com please".to_string(),
            false,
        ),
        (
            "unicode_prose",
            "héllo wörld — emoji 🎉 and ümlauts".to_string(),
            false,
        ),
        (
            "unicode_pem_body",
            "-----BEGIN KEY-----\né\n-----END KEY-----\nrest".to_string(),
            true,
        ),
        (
            "unicode_pem_after",
            "-----BEGIN KEY-----\nbody\n-----END KEY-----\ntail é 🎉".to_string(),
            true,
        ),
        (
            "mixed_shapes",
            format!(
                "{} and https://u:p@h.example {} {}",
                token("ghp_", 40),
                token("sk-", 30),
                token("AKIA", 16)
            ),
            true,
        ),
        (
            "many_url_candidates_no_userinfo",
            ":/://:/:".repeat(20),
            false,
        ),
        ("newline_heavy_prose", "line\n".repeat(30), false),
        (
            "adjacent_tokens",
            format!(
                "{} {} {}",
                token("ghp_", 40),
                token("glpat-", 20),
                token("AKIA", 16)
            ),
            true,
        ),
    ];
    cases
}

// --- pre-fix reference algorithm ------------------------------------------

const REFERENCE_REPLACEMENT: &str = "[REDACTED]";

fn reference_is_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '/' | '=' | '+' | '$')
}

/// The pre-fix redaction algorithm, transcribed from the #92 base
/// implementation (`src/redact.rs` at `786419f`). Scanning is quadratic and
/// allocates the whole remaining input per candidate — that is exactly the
/// defect being fixed — so this reference is only used on the small corpus.
fn reference_redact(input: &str) -> String {
    let chars: Vec<char> = input.chars().collect();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    while i < chars.len() {
        match reference_find_match(&chars, i) {
            Some((start, end)) => {
                out.extend(chars[i..start].iter());
                out.push_str(REFERENCE_REPLACEMENT);
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

fn reference_find_match(chars: &[char], from: usize) -> Option<(usize, usize)> {
    let mut start = from;
    while start < chars.len() {
        if let Some(matched) = reference_anchored_match(chars, start) {
            return Some(matched);
        }
        start += 1;
    }
    None
}

fn reference_anchored_match(chars: &[char], start: usize) -> Option<(usize, usize)> {
    let rest: String = chars[start..].iter().collect();

    let at_boundary = start == 0 || !reference_is_token_char(chars[start - 1]);
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
            if rest.starts_with(prefix) {
                let run = reference_token_run_len(&chars[start + prefix.len()..]);
                if run >= floor {
                    return Some((start, start + prefix.len() + run));
                }
            }
        }
        for (prefix, floor) in [("xoxa-", 8), ("xoxr-", 8), ("AKIA", 16)] {
            if rest.starts_with(prefix) {
                let run = reference_token_run_len(&chars[start + prefix.len()..]);
                if run >= floor {
                    return Some((start, start + prefix.len() + run));
                }
            }
        }
        if rest.starts_with("-----BEGIN") {
            let full: String = chars[start..].iter().collect();
            return match full.find("-----END") {
                Some(end_marker) => {
                    let line_end = full[end_marker..]
                        .find('\n')
                        .map(|offset| end_marker + offset)
                        .unwrap_or(full.len());
                    Some((start, start + line_end))
                }
                None => Some((start, chars.len())), // unterminated: redact to end
            };
        }
    }

    if let Some(after) = rest.strip_prefix("://")
        && let Some(at) = after.find('@')
    {
        let before_at = &after[..at];
        let has_slash_before = before_at.contains('/');
        if !has_slash_before && before_at.len() >= 3 {
            let segment_start = start + 3;
            return Some((segment_start, segment_start + at + 1));
        }
    }
    None
}

fn reference_token_run_len(chars: &[char]) -> usize {
    chars
        .iter()
        .take_while(|c| reference_is_token_char(**c))
        .count()
}

// --- tests ----------------------------------------------------------------

/// Every corpus case must match the pre-fix algorithm byte-for-byte, stay
/// idempotent, and only redact where a secret shape actually occurs.
#[test]
fn corpus_matches_the_pre_fix_algorithm_byte_for_byte() {
    let _serial = serial();
    let cases = corpus();
    assert!(cases.len() >= 50, "corpus shrank: {}", cases.len());
    for (name, input, expects_marker) in cases {
        let actual = redact(&input);
        let reference = reference_redact(&input);
        assert!(
            actual == reference,
            "case {name}: fixed pass differs from the pre-fix algorithm \
             (fixed_chars={}, reference_chars={})",
            actual.chars().count(),
            reference.chars().count()
        );
        assert!(
            redact(&actual) == actual,
            "case {name}: redaction is not idempotent (chars={})",
            actual.chars().count()
        );
        assert!(
            actual.contains(REFERENCE_REPLACEMENT) == expects_marker,
            "case {name}: unexpected marker presence \
             (expected={expects_marker}, output_chars={})",
            actual.chars().count()
        );
    }
}

/// Prose that carries no secret shape must pass through untouched.
#[test]
fn plain_prose_is_never_touched() {
    let _serial = serial();
    let inputs = [
        "the quick brown fox jumps over the lazy dog",
        "path/to/file.rs:12: error: unexpected token",
        "see https://example.com/issues/92 and user@example.com",
        "x----BEGIN y",
        "----BEGIN-ish but not a block",
        "a-b_c.d/e=f+g$h",
    ];
    for input in inputs {
        assert!(redact(input) == input, "over-redaction on: {input}");
    }
}

/// Exhaustive short-string equivalence: every string up to length 6 over an
/// alphabet carrying the trigger characters (token-prefix letters, `_`, `://`,
/// `@`, `-`, a near-boundary letter) must match the pre-fix algorithm. This is
/// the interaction net under the hand-written corpus: boundaries, near-prefix
/// candidates and userinfo shapes are all combinations the corpus only samples.
#[test]
fn exhaustive_short_strings_match_the_pre_fix_algorithm() {
    let _serial = serial();
    const ALPHABET: [char; 10] = ['g', 'h', 'p', '_', ':', '/', '@', '-', 'A', 'K'];
    const MAX_LEN: usize = 6;

    fn walk(
        alphabet: &[char],
        max_len: usize,
        buf: &mut String,
        checked: &mut u64,
        mismatch: &mut Option<Vec<u32>>,
    ) {
        *checked += 1;
        if mismatch.is_none() && redact(buf) != reference_redact(buf) {
            *mismatch = Some(buf.chars().map(|c| c as u32).collect());
        }
        if buf.chars().count() >= max_len {
            return;
        }
        for c in alphabet {
            buf.push(*c);
            walk(alphabet, max_len, buf, checked, mismatch);
            buf.pop();
        }
    }

    let mut buf = String::new();
    let mut checked = 0u64;
    let mut mismatch: Option<Vec<u32>> = None;
    walk(&ALPHABET, MAX_LEN, &mut buf, &mut checked, &mut mismatch);
    eprintln!(
        "exhaustive equivalence: checked={checked} strings over 10 symbols, max_len={MAX_LEN}"
    );
    assert!(checked > 1_000_000, "coverage shrank: {checked} strings");
    assert!(
        mismatch.is_none(),
        "mismatch at code points {:?}",
        mismatch.expect("checked")
    );
}

fn assert_allocation_budget(name: &str, input: &str) {
    let n = input.chars().count();
    let limit = BYTES_PER_CHAR * n + BYTES_SLACK;
    let (output, calls, bytes) = measured(|| redact(input));
    eprintln!(
        "allocation witness {name}: input_chars={n} output_chars={} alloc_calls={calls} \
         alloc_bytes={bytes} limit_bytes={limit}",
        output.chars().count()
    );
    assert!(
        bytes <= limit,
        "{name}: {bytes} bytes allocated for {n} input characters exceeds the linear budget \
         ({limit} bytes); the pre-fix implementation allocated a copy of the remaining input \
         at every candidate position"
    );
    assert!(
        calls <= ALLOC_CALL_LIMIT,
        "{name}: {calls} allocations for one redact call exceeds the linear budget \
         ({ALLOC_CALL_LIMIT})"
    );
}

/// Adversarial shapes that make the pre-fix pass cubic (a quadratic tail scan
/// per input position): long runs beside a prefix, many near-prefix
/// candidates, many `://` near-candidates, one huge single token, an
/// unterminated PEM block, multi-byte runs.
///
/// Sized so the runnable-against-the-pre-fix cases fail the budget in seconds
/// (`n³/6` character copies); the genuinely large cases live in
/// `allocation_volume_for_issue_scale_text_stays_linear`.
#[test]
fn allocation_volume_for_adversarial_shapes_stays_linear() {
    let _serial = serial();
    let shapes: Vec<(&str, String)> = vec![
        ("prose_no_prefixes_2k", prose(2_000)),
        ("many_url_candidates_no_at", "://".repeat(600)),
        ("many_near_prefix_candidates", "ghp_ab ".repeat(300)),
        (
            "long_run_adjacent_to_prefix",
            format!("x{}", token("ghp_", 1_800)),
        ),
        ("one_huge_single_token", token("ghp_", 2_000)),
        (
            "unterminated_pem_block",
            format!("-----BEGIN KEY-----\n{}", "MIIB\n".repeat(400)),
        ),
        ("many_pem_begins", "-----BEGIN".repeat(200)),
        ("unicode_heavy", "é🎉 ".repeat(400)),
        (
            "url_userinfo_huge_segment",
            format!("https://{}@example.com", run(1_800)),
        ),
    ];
    for (name, input) in shapes {
        assert_allocation_budget(name, &input);
    }
}

/// Issue-scale input (the size class that reproduces the pre-fix stall) and
/// large adversarial shapes must stay inside the same linear budget. Elapsed
/// time is recorded as evidence only; the asserted witness is the allocation
/// budget. This case is skipped when running the suite against the pre-fix
/// tree, whose cost here is astronomically past any runnable deadline.
#[test]
fn allocation_volume_for_issue_scale_text_stays_linear() {
    let _serial = serial();
    let large: Vec<(&str, String)> = vec![
        (
            "long_run_adjacent_to_prefix_100k",
            format!("x{}", token("ghp_", 100_000)),
        ),
        ("many_url_candidates_no_at_60k", "://".repeat(30_000)),
        (
            "unterminated_pem_block_60k",
            format!("-----BEGIN KEY-----\n{}", "MIIB\n".repeat(20_000)),
        ),
        ("unicode_heavy_40k", "é🎉 ".repeat(13_000)),
    ];
    for (name, input) in large {
        assert_allocation_budget(name, &input);
    }
    let text = issue_scale_text();
    assert!(text.len() >= 200 * 1024, "fixture shrank: {}", text.len());
    assert_allocation_budget("issue_scale_text", &text);
    let start = Instant::now();
    let output = redact(&text);
    let elapsed = start.elapsed();
    eprintln!(
        "issue-scale redact: input_chars={} output_chars={} elapsed_ms={}",
        text.chars().count(),
        output.chars().count(),
        elapsed.as_millis()
    );
    assert!(output.contains(REFERENCE_REPLACEMENT));
}
