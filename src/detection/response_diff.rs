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

const MAX_LEVENSHTEIN_LEN: usize = 1024;
/// Bench anti-noise: `bench/app.py::noisy()` injects a random `request_id`
/// (8 hex chars) + `generated_at` (epoch float) into every JSON envelope so
/// naive string-compare diffing breaks. Normalize both fields to fixed
/// placeholders before any similarity so two identical pages with different
/// noise compare ~1.0. Handles pretty-printed (`"request_id": "abc",`) and
/// compact (`"request_id":"abc"`) shapes; unknown fields are untouched.
/// Bodies without either marker are returned unchanged (cheap path).
#[must_use]
pub fn normalize_response_for_diff(body: &str) -> String {
    if !body.contains("request_id") && !body.contains("generated_at") {
        return body.to_owned();
    }
    let normalized_id = normalize_json_field(body, "request_id", "\"\"");
    normalize_json_field(&normalized_id, "generated_at", "0")
}

/// Replace the value of one `"field": <value>` JSON member with `placeholder`,
/// preserving keys, separators and structure. String values (`"..."`) and
/// bare numbers/literals (`123.4`, `null`) are both handled; anything else
/// leaves the body intact so detection never scores a mangled page.
fn normalize_json_field(body: &str, field: &str, placeholder: &str) -> String {
    let needle = format!("\"{field}\"");
    let mut out = String::with_capacity(body.len());
    let mut rest = body;
    while let Some(start) = rest.find(needle.as_str()) {
        let after_key = &rest[start + needle.len()..];
        let Some(colon_off) = after_key.find(':') else {
            out.push_str(rest);
            return out;
        };
        // Byte offset of the value start inside `after_key`.
        let mut value_off = colon_off + 1;
        let bytes = after_key.as_bytes();
        while value_off < bytes.len() && bytes[value_off].is_ascii_whitespace() {
            value_off += 1;
        }
        if value_off >= bytes.len() {
            out.push_str(rest);
            return out;
        }
        // End offset (exclusive) of the value inside `after_key`.
        let mut value_end = None;
        if bytes[value_off] == b'"' {
            let mut i = value_off + 1;
            while i < bytes.len() {
                if bytes[i] == b'\\' {
                    i = i.saturating_add(2);
                } else if bytes[i] == b'"' {
                    value_end = Some(i + 1);
                    break;
                } else {
                    i += 1;
                }
            }
        } else {
            let mut i = value_off;
            while i < bytes.len()
                && (bytes[i].is_ascii_alphanumeric() || matches!(bytes[i], b'.' | b'+' | b'-'))
            {
                i += 1;
            }
            if i > value_off {
                value_end = Some(i);
            }
        }
        let Some(value_end) = value_end else {
            out.push_str(rest);
            return out;
        };
        out.push_str(&rest[..start]);
        out.push_str(needle.as_str());
        out.push_str(": ");
        out.push_str(placeholder);
        rest = &after_key[value_end..];
    }
    out.push_str(rest);
    out
}

/// Similarities below this threshold all take the same detection branch
/// (`combined_sim < 0.5` in [`diff_against_baseline`]), so the DP result
/// is interchangeable with `0.0` there — the early-exit below exploits this.
const EARLY_EXIT_SIM: f64 = 0.5;

/// Normalized Levenshtein similarity 0..1. Truncates inputs to 1024 chars
/// and skips the O(n·m) DP when the length difference alone guarantees a
/// similarity below [`EARLY_EXIT_SIM`].
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
/// Both inputs are normalized for bench noise (`request_id`/`generated_at`)
/// before comparison so per-response randomness never reads as a differential.
#[must_use]
pub fn adaptive_similarity(a: &str, b: &str) -> f64 {
    let norm_a = normalize_response_for_diff(a);
    let norm_b = normalize_response_for_diff(b);
    if norm_a.len() > MAX_LEVENSHTEIN_LEN || norm_b.len() > MAX_LEVENSHTEIN_LEN {
        jaccard(&norm_a, &norm_b)
    } else {
        levenshtein_similarity(&norm_a, &norm_b)
    }
}

/// Jaccard index over whitespace tokens.
/// Normalizes bench noise first (see [`normalize_response_for_diff`]): direct
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
    #[test]
    fn bench_noise_normalized_before_similarity() {
        // `bench/app.py::noisy()` shape: same page, different per-response
        // `request_id` + `generated_at` must compare ~identical.
        let a = "{\n  \"data\": [{\"id\": 1}],\n  \"request_id\": \"a1b2c3d4\",\n  \"generated_at\": 1757328000.123\n}";
        let b = "{\n  \"data\": [{\"id\": 1}],\n  \"request_id\": \"e5f6a7b8\",\n  \"generated_at\": 1757328001.456\n}";
        assert!(adaptive_similarity(a, b) > 0.95);
        let diff = diff_against_baseline(a, b, 100.0, 105.0, 100.0);
        assert!(!diff.is_significant());
        // Compact shape normalizes too.
        let c = "{\"data\":1,\"request_id\":\"aaaa\",\"generated_at\":1.5}";
        let d = "{\"data\":1,\"request_id\":\"bbbb\",\"generated_at\":2.5}";
        assert!(adaptive_similarity(c, d) > 0.95);
    }
    #[test]
    fn normalize_leaves_clean_bodies_untouched() {
        let body = "{\"data\": [1, 2, 3]}";
        assert_eq!(normalize_response_for_diff(body), body);
        assert_eq!(normalize_response_for_diff(""), "");
    }
}
