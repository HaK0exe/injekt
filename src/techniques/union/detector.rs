#![deny(unsafe_code)]

use crate::detection::response_diff::{diff_against_baseline, jaccard};
use uuid::Uuid;

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

    /// Generate a random 8-char hex marker for UNION probes.
    #[must_use]
    pub fn generate_marker() -> String {
        Uuid::new_v4().simple().to_string()[..8].to_string()
    }

    /// Heuristic: UNION should change response but keep structure; check Jaccard drop and ordered marker presence.
    #[must_use]
    pub fn evaluate(
        &self,
        baseline_body: &str,
        candidate_body: &str,
        baseline_ms: f64,
        candidate_ms: f64,
        tested_columns: usize,
        marker: &str,
    ) -> UnionResult {
        // Reject if marker already present in baseline (echo/false positive)
        if baseline_body.contains(marker) {
            return UnionResult {
                is_vulnerable: false,
                confidence: 0.1,
                columns: None,
            };
        }
        let diff = diff_against_baseline(
            baseline_body,
            candidate_body,
            baseline_ms,
            candidate_ms,
            100.0,
        );
        let j = jaccard(baseline_body, candidate_body);
        let has_marker = candidate_body.contains(marker);
        let is_vuln = has_marker && diff.confidence > 0.6 && j < 0.85;
        let confidence = if is_vuln {
            let c = (diff.confidence * 0.6 + (1.0 - j) * 0.4).clamp(0.0, 1.0);
            c.max(0.65)
        } else {
            0.2
        };
        UnionResult {
            is_vulnerable: is_vuln,
            confidence,
            columns: if is_vuln { Some(tested_columns) } else { None },
        }
    }

    /// ORDER BY probe: error indicates column count exceeded.
    #[must_use]
    pub fn evaluate_order_by(&self, body: &str) -> bool {
        let lower = body.to_ascii_lowercase();
        (lower.contains("order by")
            && (lower.contains("unknown column")
                || lower.contains("invalid")
                || lower.contains("sql")))
            || lower.contains("ora-00904")
            || lower.contains("the order by position")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn order_by_detects_unknown_column() {
        let d = UnionDetector::new();
        assert!(d.evaluate_order_by("Unknown column '4' in 'order clause' ORDER BY 4"));
        assert!(d.evaluate_order_by("the order by position 5 is out of range"));
        // ORA variant also covers Oracle path
        assert!(d.evaluate_order_by("ORA-00904: invalid identifier"));
    }

    #[test]
    fn order_by_detects_ora_00904() {
        let d = UnionDetector::new();
        assert!(d.evaluate_order_by("ORA-00904: invalid identifier ORDER BY"));
        assert!(d.evaluate_order_by("the order by position 10 is out of range"));
    }

    #[test]
    fn order_by_no_false_positive_on_normal_page() {
        let d = UnionDetector::new();
        assert!(!d.evaluate_order_by("welcome normal page id=1 user data"));
        assert!(!d.evaluate_order_by("SQL injection UNION SELECT 1,2,3 without error"));
        assert!(!d.evaluate_order_by("order by date desc — no error"));
        // "unknown column" without "order by" must not trigger (prevents FP on generic SQL errors)
        assert!(!d.evaluate_order_by("Unknown column 'foo' in field list"));
    }

    #[test]
    fn order_by_requires_order_by_keyword_for_some_patterns() {
        let d = UnionDetector::new();
        // "unknown column" without "order by" should not trigger — prevents FP
        assert!(!d.evaluate_order_by("Unknown column 'foo' in field list"));
        // ORA-00904 alone should still trigger (oracle-specific, no need for order by keyword)
        assert!(d.evaluate_order_by("ORA-00904: \"FOO\": invalid identifier"));
    }

    #[test]
    fn union_evaluate_requires_marker_and_diff() {
        let d = UnionDetector::new();
        let marker = "abc12345";
        let baseline = "welcome page normal content id=1";
        let with_marker = format!(
            "welcome page {marker} injected content extra data different enough to drop jaccard"
        );
        let r = d.evaluate(baseline, &with_marker, 100.0, 110.0, 3, marker);
        // Should be vulnerable because marker present and diff significant
        assert!(r.is_vulnerable);
        assert_eq!(r.columns, Some(3));

        let without_marker = "welcome page normal content id=1";
        let r2 = d.evaluate(baseline, without_marker, 100.0, 105.0, 3, marker);
        assert!(!r2.is_vulnerable);
    }

    #[test]
    fn union_evaluate_rejects_high_similarity() {
        let d = UnionDetector::new();
        let marker = "abc12345";
        let baseline = format!("identical content with marker {marker} but actually baseline");
        let candidate = format!("identical content with marker {marker} but actually baseline");
        let r = d.evaluate(&baseline, &candidate, 100.0, 102.0, 3, marker);
        assert!(
            !r.is_vulnerable,
            "identical bodies should not be vuln even with marker"
        );
    }

    #[test]
    fn union_evaluate_rejects_marker_in_baseline() {
        let d = UnionDetector::new();
        let marker = "abc12345";
        let baseline = format!("welcome page {marker} normal content");
        let candidate = format!("welcome page {marker} injected content");
        let r = d.evaluate(&baseline, &candidate, 100.0, 110.0, 3, marker);
        assert!(!r.is_vulnerable, "marker in baseline should reject");
    }

    #[test]
    fn generate_marker_is_random_hex() {
        let m1 = UnionDetector::generate_marker();
        let m2 = UnionDetector::generate_marker();
        assert_eq!(m1.len(), 8);
        assert!(m1.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(m1, m2, "markers should be unique");
    }
}
