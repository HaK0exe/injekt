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

/// Normalized Levenshtein similarity 0..1.
#[must_use]
pub fn levenshtein_similarity(a: &str, b: &str) -> f64 {
    let dist = levenshtein_distance(a, b);
    let max_len = a.len().max(b.len()).max(1) as f64;
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

/// Jaccard index over whitespace tokens.
#[must_use]
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
pub fn diff_against_baseline(
    baseline_body: &str,
    candidate_body: &str,
    baseline_ms: f64,
    candidate_ms: f64,
    sigma: f64,
) -> DiffResult {
    let similarity = levenshtein_similarity(baseline_body, candidate_body);
    let j = jaccard(baseline_body, candidate_body);
    let combined_sim = (similarity * 0.7 + j * 0.3).clamp(0.0, 1.0);
    let time_delta = candidate_ms - baseline_ms;
    let length_delta = candidate_body.len() as i64 - baseline_body.len() as i64;
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
    fn jaccard_empty() {
        assert_eq!(jaccard("", ""), 1.0);
    }
}
