#![deny(unsafe_code)]

use crate::detection::response_diff::{diff_against_baseline, jaccard};
use crate::techniques::stacked::payloads::StackedPayload;

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct StackedResult {
    pub is_vulnerable: bool,
    pub confidence: f64,
    pub dbms: Option<String>,
}

#[derive(Debug, Default)]
pub struct StackedDetector;

impl StackedDetector {
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Stacked queries: second statement should execute and produce visible side-effect.
    /// We probe with a tautology that changes response (e.g., `; SELECT 1 --`).
    /// Detection: response differs from baseline AND contains marker from second query.
    #[must_use]
    pub fn evaluate(
        &self,
        baseline_body: &str,
        candidate_body: &str,
        baseline_ms: f64,
        candidate_ms: f64,
        payload: &StackedPayload,
    ) -> StackedResult {
        let diff = diff_against_baseline(
            baseline_body,
            candidate_body,
            baseline_ms,
            candidate_ms,
            100.0,
        );
        let j = jaccard(baseline_body, candidate_body);
        let has_marker = candidate_body.contains(&payload.marker);
        // Stacked queries often produce subtle changes; lower thresholds than UNION.
        // Require marker + some diff + reasonable jaccard drop.
        let is_vuln = has_marker && diff.confidence > 0.4 && j < 0.95;
        let confidence = if is_vuln {
            (diff.confidence * 0.5 + (1.0 - j) * 0.3 + 0.2)
                .clamp(0.0, 1.0)
                .max(0.55)
        } else {
            0.15
        };
        StackedResult {
            is_vulnerable: is_vuln,
            confidence,
            dbms: if is_vuln {
                Some(payload.dbms.clone())
            } else {
                None
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_mysql_stacked_select() {
        let d = StackedDetector::new();
        let baseline = "welcome page id=1";
        let injected = "welcome page id=1 stacked_marker_12345";
        let payload = StackedPayload::new(
            "; SELECT 'stacked_marker_12345' -- -",
            "mysql",
            "stacked_marker_12345",
        );
        let r = d.evaluate(baseline, injected, 100.0, 110.0, &payload);
        assert!(r.is_vulnerable);
        assert_eq!(r.dbms, Some("mysql".to_owned()));
    }

    #[test]
    fn no_false_positive_on_same_page() {
        let d = StackedDetector::new();
        let baseline = "welcome page id=1";
        let payload = StackedPayload::new("; SELECT 'marker' -- -", "mysql", "marker");
        let r = d.evaluate(baseline, baseline, 100.0, 102.0, &payload);
        assert!(!r.is_vulnerable);
    }

    #[test]
    fn requires_marker_and_diff() {
        let d = StackedDetector::new();
        let baseline = "welcome page id=1 normal content here";
        // Much more different content + marker
        let with_marker = "welcome page id=1 normal content here marker_here EXTRA DATA THAT MAKES IT DIFFERENT ENOUGH";
        let payload = StackedPayload::new("; SELECT 'marker_here' -- -", "mysql", "marker_here");
        let r = d.evaluate(baseline, with_marker, 100.0, 110.0, &payload);
        assert!(
            r.is_vulnerable,
            "should detect with marker and diff, confidence={}",
            r.confidence
        );
        assert_eq!(r.dbms, Some("mysql".to_owned()));

        let different_no_marker = "completely different page content without any marker";
        let r2 = d.evaluate(baseline, different_no_marker, 100.0, 105.0, &payload);
        assert!(
            !r2.is_vulnerable,
            "diff alone without marker should not trigger"
        );
    }
}
