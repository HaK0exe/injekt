#![deny(unsafe_code)]

use crate::detection::response_diff::{diff_against_baseline, jaccard};

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct UnionResult {
    pub is_vulnerable: bool,
    pub confidence: f64,
    pub columns: Option<usize>,
}

#[derive(Debug, Default)]
pub struct UnionDetector;

impl UnionDetector {
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Heuristic: UNION should change response but keep structure; check Jaccard drop and marker presence.
    #[must_use]
    pub fn evaluate(
        &self,
        baseline_body: &str,
        candidate_body: &str,
        baseline_ms: f64,
        candidate_ms: f64,
    ) -> UnionResult {
        let diff = diff_against_baseline(
            baseline_body,
            candidate_body,
            baseline_ms,
            candidate_ms,
            100.0,
        );
        let j = jaccard(baseline_body, candidate_body);
        // UNION often introduces numbers 1,2,3 in body if successful
        let has_union_marker = candidate_body.contains("1") && candidate_body.contains("2");
        let is_vuln = (diff.confidence > 0.6 && j < 0.85)
            || (has_union_marker && j < 0.95 && diff.confidence > 0.4);
        let confidence = if is_vuln {
            let c = (diff.confidence * 0.6 + (1.0 - j) * 0.4).clamp(0.0, 1.0);
            c.max(0.65)
        } else {
            0.2
        };
        UnionResult {
            is_vulnerable: is_vuln,
            confidence,
            columns: if is_vuln { Some(3) } else { None },
        }
    }

    /// ORDER BY probe: error indicates column count exceeded.
    #[must_use]
    pub fn evaluate_order_by(&self, body: &str) -> bool {
        let lower = body.to_ascii_lowercase();
        lower.contains("order by")
            && (lower.contains("unknown column")
                || lower.contains("invalid")
                || body.contains("SQL"))
            || lower.contains("ora-00904")
            || lower.contains("the order by position")
    }
}
