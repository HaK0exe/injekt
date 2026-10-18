use super::normalize_response_for_diff;

pub(super) const MAX_LEVENSHTEIN_LEN: usize = 1024;

/// Similarities below this threshold all take the same detection branch
/// (`combined_sim < 0.5` in [`crate::detection::response_diff::diff_against_baseline`]), so the DP result
/// is interchangeable with `0.0` there — the early-exit below exploits this.
const EARLY_EXIT_SIM: f64 = 0.5;

/// Normalized Levenshtein similarity 0..1. Truncates inputs to 1024 chars
/// and skips the O(n·m) DP when the length difference alone guarantees a
/// similarity below `EARLY_EXIT_SIM`.
/// Bench noise (`request_id`/`generated_at`) is normalized first so direct
/// callers get the same anti-noise behaviour as [`adaptive_similarity`].
#[must_use]
// Inputs are truncated to MAX_LEVENSHTEIN_LEN (1024); casts are always lossless.
#[allow(clippy::cast_precision_loss)]
pub fn levenshtein_similarity(a: &str, b: &str) -> f64 {
    let norm_a = normalize_response_for_diff(a);
    let norm_b = normalize_response_for_diff(b);
    let a_trunc = truncate(&norm_a);
    let b_trunc = truncate(&norm_b);
    // Early-exit: edit distance >= |n-m|, so similarity <= 1 - |n-m|/max.
    // Char counts are O(n); the DP they skip is O(n*m).
    let n_chars = a_trunc.chars().count();
    let m_chars = b_trunc.chars().count();
    let max_len = n_chars.max(m_chars).max(1);
    let len_diff = n_chars.abs_diff(m_chars);
    if 1.0 - (len_diff as f64 / max_len as f64) < EARLY_EXIT_SIM {
        return 0.0;
    }
    let dist = levenshtein_distance(a_trunc, b_trunc);
    // `dist` counts chars (see `levenshtein_distance`); the denominator must
    // too — `.len()` is bytes and overstates similarity on CJK/emoji.
    let max_len = a_trunc.chars().count().max(b_trunc.chars().count()).max(1) as f64;
    1.0 - (dist as f64 / max_len)
}

fn levenshtein_distance(a: &str, b: &str) -> usize {
    let a_chars: Vec<char> = a.chars().collect();
    let b_chars: Vec<char> = b.chars().collect();
    let n = a_chars.len();
    let m = b_chars.len();
    if n == 0 {
        return m;
    }
    if m == 0 {
        return n;
    }
    let mut prev: Vec<usize> = (0..=m).collect();
    let mut cur = vec![0; m + 1];
    for i in 1..=n {
        cur[0] = i;
        for j in 1..=m {
            let cost = usize::from(a_chars[i - 1] != b_chars[j - 1]);
            cur[j] = (prev[j] + 1).min(cur[j - 1] + 1).min(prev[j - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    prev[m]
}

#[inline]
pub(super) fn truncate(s: &str) -> &str {
    // Char-based (not byte-based): 1024 CJK chars are ~3 KiB but cost the
    // same DP as 1024 ASCII chars. Byte slicing would also under-truncate
    // CJK to ~341 chars and overstate similarity denominators.
    match s.char_indices().nth(MAX_LEVENSHTEIN_LEN) {
        Some((idx, _)) => &s[..idx],
        None => s,
    }
}

/// Choose similarity strategy based on body size: Levenshtein for small, Jaccard for large.
/// Both inputs are normalized for bench noise (`request_id`/`generated_at`)
/// before comparison so per-response randomness never reads as a differential.
///
/// The switch is char-based: byte length would route ~350 CJK/emoji chars
/// (>1024 bytes) to Jaccard while Levenshtein measures chars — degraded
/// precision on non-ASCII targets.
#[must_use]
pub fn adaptive_similarity(a: &str, b: &str) -> f64 {
    let norm_a = normalize_response_for_diff(a);
    let norm_b = normalize_response_for_diff(b);
    if norm_a.chars().count() > MAX_LEVENSHTEIN_LEN || norm_b.chars().count() > MAX_LEVENSHTEIN_LEN
    {
        jaccard(&norm_a, &norm_b)
    } else {
        levenshtein_similarity(&norm_a, &norm_b)
    }
}

/// Jaccard index over whitespace tokens.
/// Normalizes bench noise first (see [`crate::detection::response_diff::normalize_response_for_diff`]): direct
/// callers such as the boolean detector get the same anti-noise behaviour as
/// [`adaptive_similarity`] without pre-processing.
#[must_use]
// Token-set sizes never approach f64's 2^52 mantissa limit for HTTP response bodies.
#[allow(clippy::cast_precision_loss)]
pub fn jaccard(a: &str, b: &str) -> f64 {
    let norm_a = normalize_response_for_diff(a);
    let norm_b = normalize_response_for_diff(b);
    let sa: std::collections::HashSet<&str> = norm_a.split_whitespace().collect();
    let sb: std::collections::HashSet<&str> = norm_b.split_whitespace().collect();
    if sa.is_empty() && sb.is_empty() {
        return 1.0;
    }
    let inter = sa.intersection(&sb).count() as f64;
    let union = sa.union(&sb).count() as f64;
    inter / union.max(1.0)
}
