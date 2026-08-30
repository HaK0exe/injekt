#![deny(unsafe_code)]

use crate::detection::response_diff::{diff_against_baseline, jaccard};

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct BooleanResult {
    pub is_vulnerable: bool,
    pub confidence: f64,
    pub true_similarity: f64,
    pub false_similarity: f64,
}

#[derive(Debug, Default)]
pub struct BooleanDetector;

impl BooleanDetector {
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Compare TRUE vs FALSE payload responses against baseline.
    #[must_use]
    pub fn evaluate(
        &self,
        baseline_body: &str,
        true_body: &str,
        false_body: &str,
        baseline_ms: f64,
        true_ms: f64,
        false_ms: f64,
    ) -> BooleanResult {
        let diff_true =
            diff_against_baseline(baseline_body, true_body, baseline_ms, true_ms, 100.0);
        let diff_false =
            diff_against_baseline(baseline_body, false_body, baseline_ms, false_ms, 100.0);
        // TRUE should be similar to baseline, FALSE should differ, or vice versa depending on injection.
        let j_true = jaccard(baseline_body, true_body);
        let j_false = jaccard(baseline_body, false_body);
        // Heuristic: true branch keeps similarity high, false branch drops.
        let is_vuln = (j_true - j_false).abs() > 0.15
            || (diff_true.confidence < 0.4 && diff_false.confidence > 0.6);
        let confidence = if is_vuln {
            (0.5 + (j_true - j_false).abs() * 0.5).clamp(0.0, 1.0)
        } else {
            0.2
        };
        BooleanResult {
            is_vulnerable: is_vuln,
            confidence,
            true_similarity: j_true,
            false_similarity: j_false,
        }
    }
}
