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

/// Minimum absolute TRUE-vs-FALSE Jaccard gap to treat the pair as differential.
const JACCARD_DIFF_THRESHOLD: f64 = 0.15;
/// `diff_against_baseline` confidence at or below this counts as "similar to baseline".
const SIMILAR_CONFIDENCE_MAX: f64 = 0.4;
/// `diff_against_baseline` confidence above this counts as "different from baseline".
const DIFFERENT_CONFIDENCE_MIN: f64 = 0.6;
/// Timing sigma (ms) for the baseline diff — small enough to ignore clock jitter.
const DIFF_SIGMA_MS: f64 = 100.0;

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
        let diff_true = diff_against_baseline(
            baseline_body,
            true_body,
            baseline_ms,
            true_ms,
            DIFF_SIGMA_MS,
        );
        let diff_false = diff_against_baseline(
            baseline_body,
            false_body,
            baseline_ms,
            false_ms,
            DIFF_SIGMA_MS,
        );
        // TRUE should be similar to baseline, FALSE should differ, or vice versa depending on injection.
        let j_true = jaccard(baseline_body, true_body);
        let j_false = jaccard(baseline_body, false_body);
        // Heuristic: true branch keeps similarity high, false branch drops.
        let is_vuln = (j_true - j_false).abs() > JACCARD_DIFF_THRESHOLD
            || (diff_true.confidence < SIMILAR_CONFIDENCE_MAX
                && diff_false.confidence > DIFFERENT_CONFIDENCE_MIN);
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
