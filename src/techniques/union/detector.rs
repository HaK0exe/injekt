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

    /// Heuristic: UNION should change response but keep structure; check Jaccard drop and ordered marker presence.
    #[must_use]
    pub fn evaluate(
        &self,
        baseline_body: &str,
        candidate_body: &str,
        baseline_ms: f64,
        candidate_ms: f64,
        tested_columns: usize,
    ) -> UnionResult {
        let diff = diff_against_baseline(
            baseline_body,
            candidate_body,
            baseline_ms,
            candidate_ms,
            100.0,
        );
        let j = jaccard(baseline_body, candidate_body);
        // UNION payloads inject sequences like "1,2,3". Require ordered occurrence
        // to avoid FP on any HTML containing "1" and "2" separately.
        let has_union_marker = Self::has_ordered_union_marker(candidate_body, tested_columns);
        // Require both diff + jaccard jointly; marker tightens threshold rather
        // than loosening it. Previous `j<0.95 && diff>0.4` was far too permissive.
        // With marker we allow 0.6/0.85, without marker require stronger change.
        let is_vuln = if has_union_marker {
            diff.confidence > 0.6 && j < 0.85
        } else {
            diff.confidence > 0.65 && j < 0.80
        };
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

    fn has_ordered_union_marker(body: &str, columns: usize) -> bool {
        if columns < 2 {
            return body.contains('1');
        }
        let seq = (1..=columns)
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let spaced = (1..=columns)
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        if body.contains(&seq) || body.contains(&spaced) {
            return true;
        }
        // Fallback: check numbers 1..columns appear in order without requiring commas
        let mut last = 0usize;
        for i in 1..=columns {
            let token = i.to_string();
            match body[last..].find(&token) {
                Some(pos) => last += pos + token.len(),
                None => return false,
            }
        }
        true
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
        let baseline = "welcome page normal content id=1";
        let with_marker =
            "welcome page 1,2,3 injected content extra data different enough to drop jaccard";
        let r = d.evaluate(baseline, with_marker, 100.0, 110.0, 3);
        // Should be vulnerable because marker present and diff significant
        assert!(r.is_vulnerable);
        assert_eq!(r.columns, Some(3));

        let without_marker = "welcome page normal content id=1";
        let r2 = d.evaluate(baseline, without_marker, 100.0, 105.0, 3);
        assert!(!r2.is_vulnerable);
    }

    #[test]
    fn union_evaluate_rejects_high_similarity() {
        let d = UnionDetector::new();
        let baseline = "identical content with numbers 1,2,3 but actually baseline";
        let candidate = "identical content with numbers 1,2,3 but actually baseline";
        let r = d.evaluate(baseline, candidate, 100.0, 102.0, 3);
        assert!(
            !r.is_vulnerable,
            "identical bodies should not be vuln even with marker"
        );
    }
}
