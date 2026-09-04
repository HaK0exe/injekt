#![deny(unsafe_code)]

/// Result of diffing a response against baseline.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct DiffResult {
    pub similarity: f64, // 0..1 (1 = identical)
    pub time_delta_ms: f64,
    pub length_delta: i64,
    pub confidence: f64,
    pub technique: Option<String>,
}

impl DiffResult {
    #[must_use]
    pub fn is_significant(&self) -> bool {
        self.confidence > 0.6
    }
}

const MAX_LEVENSHTEIN_LEN: usize = 4096;

/// Normalized Levenshtein similarity 0..1. Truncates inputs to 4096 chars.
#[must_use]
// Inputs are truncated to MAX_LEVENSHTEIN_LEN (4096); casts are always lossless.
#[allow(clippy::cast_precision_loss)]
pub fn levenshtein_similarity(a: &str, b: &str) -> f64 {
    let a_trunc = truncate(a);
    let b_trunc = truncate(b);
    let dist = levenshtein_distance(a_trunc, b_trunc);
    let max_len = a_trunc.len().max(b_trunc.len()).max(1) as f64;
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
fn truncate(s: &str) -> &str {
    if s.len() <= MAX_LEVENSHTEIN_LEN {
        s
    } else {
        // Byte slicing can split a multi-byte char (emoji/CJK/accents) and
        // panic. Walk back to the previous char boundary instead.
        let mut end = MAX_LEVENSHTEIN_LEN;
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        &s[..end]
    }
}

/// Choose similarity strategy based on body size: Levenshtein for small, Jaccard for large.
#[must_use]
pub fn adaptive_similarity(a: &str, b: &str) -> f64 {
    if a.len() > MAX_LEVENSHTEIN_LEN || b.len() > MAX_LEVENSHTEIN_LEN {
        jaccard(a, b)
    } else {
        levenshtein_similarity(a, b)
    }
}

/// Jaccard index over whitespace tokens.
#[must_use]
// Token-set sizes never approach f64's 2^52 mantissa limit for HTTP response bodies.
#[allow(clippy::cast_precision_loss)]
pub fn jaccard(a: &str, b: &str) -> f64 {
    let sa: std::collections::HashSet<&str> = a.split_whitespace().collect();
    let sb: std::collections::HashSet<&str> = b.split_whitespace().collect();
    if sa.is_empty() && sb.is_empty() {
        return 1.0;
    }
    let inter = sa.intersection(&sb).count() as f64;
    let union = sa.union(&sb).count() as f64;
    inter / union.max(1.0)
}

/// Build `DiffResult` from baseline and candidate response.
#[must_use]
// HTTP response bodies never approach i64::MAX/usize precision-loss thresholds.
#[allow(clippy::cast_possible_wrap)]
pub fn diff_against_baseline(
    baseline_body: &str,
    candidate_body: &str,
    baseline_ms: f64,
    candidate_ms: f64,
    sigma: f64,
) -> DiffResult {
    let time_delta = candidate_ms - baseline_ms;
    let length_delta = candidate_body.len() as i64 - baseline_body.len() as i64;
    // An empty candidate must never score as a finding: a transport/body
    // error surfacing as `""` yields similarity ~0 and would otherwise map
    // to confidence 0.75 (false positive). Callers must skip scoring on
    // `Err`/status 0; this guard is the last line of defence.
    if candidate_body.is_empty() {
        return DiffResult {
            similarity: 0.0,
            time_delta_ms: time_delta,
            length_delta,
            confidence: 0.0,
            technique: None,
        };
    }
    let similarity = adaptive_similarity(baseline_body, candidate_body);
    let j = jaccard(baseline_body, candidate_body);
    let combined_sim = (similarity * 0.7 + j * 0.3).clamp(0.0, 1.0);
    let time_significant = time_delta > sigma * 2.0;
    let confidence = if time_significant && combined_sim < 0.9 {
        0.85
    } else if combined_sim < 0.5 {
        0.75
    } else if time_significant {
        0.65
    } else {
        1.0 - combined_sim
    };
    DiffResult {
        similarity: combined_sim,
        time_delta_ms: time_delta,
        length_delta,
        confidence: confidence.clamp(0.0, 1.0),
        technique: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn lev_identical() {
        assert!((levenshtein_similarity("hello", "hello") - 1.0).abs() < 1e-6);
    }
    #[test]
    // jaccard("", "") takes the early-return literal-1.0 path; exact comparison is safe.
    #[allow(clippy::float_cmp)]
    fn jaccard_empty() {
        assert_eq!(jaccard("", ""), 1.0);
    }
    #[test]
    fn empty_candidate_never_significant() {
        // A transport/body error surfacing as `""` must not map to the
        // `combined_sim < 0.5 => 0.75` false positive.
        let diff = diff_against_baseline("hello world baseline body", "", 100.0, 110.0, 100.0);
        assert!(!diff.is_significant());
        assert!(diff.confidence < 0.4);
    }
    #[test]
    fn truncate_never_splits_char_boundary() {
        // `🌍` is 4 bytes: pad so the 4096-byte cut lands mid-char.
        let s = format!("{}{}", "a".repeat(4095), "🌍".repeat(8));
        assert!(s.len() > MAX_LEVENSHTEIN_LEN);
        let t = truncate(&s);
        assert!(t.len() <= MAX_LEVENSHTEIN_LEN);
        assert!(s.starts_with(t));
        // Must not panic and must stay valid UTF-8 (len check is enough:
        // `&s[..end]` would have panicked above on a split boundary).
        assert!(t.is_char_boundary(t.len()));
        // Similarity over such bodies must not panic either.
        let _ = levenshtein_similarity(&s, &s);
    }
}
