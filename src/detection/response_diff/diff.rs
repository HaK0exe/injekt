use super::{adaptive_similarity, jaccard};

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
