#![deny(unsafe_code)]

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct TimeResult {
    pub is_vulnerable: bool,
    pub confidence: f64,
    pub measured_ms: f64,
    pub expected_ms: f64,
}

#[derive(Debug, Default)]
pub struct TimeDetector {
    pub baseline_mean_ms: f64,
    pub baseline_stddev_ms: f64,
}

/// Sigmas above the baseline mean before a delay counts as anomalous.
const SIGMA_MULTIPLIER: f64 = 2.0;
/// Floor for the baseline stddev (ms) — ignores sub-100ms network jitter.
const STDDEV_FLOOR_MS: f64 = 100.0;
/// Required fraction of the expected sleep actually observed (anti-flake).
const MIN_SLEEP_FRACTION: f64 = 0.5;

impl TimeDetector {
    #[must_use]
    pub fn new(mean: f64, stddev: f64) -> Self {
        Self {
            baseline_mean_ms: mean,
            baseline_stddev_ms: stddev,
        }
    }

    /// Build from an existing [`crate::detection::baseline::Baseline`].
    /// Reuses the baseline's mean/stddev so the time threshold stays
    /// consistent with [`crate::detection::baseline::Baseline::threshold_ms`]
    /// at `sigma = 2.0` (same floor of 100ms, same multiplier).
    #[must_use]
    pub fn from_baseline(baseline: &crate::detection::baseline::Baseline) -> Self {
        Self::new(baseline.mean_ms, baseline.stddev_ms)
    }

    #[must_use]
    pub fn threshold(&self) -> f64 {
        self.baseline_mean_ms + SIGMA_MULTIPLIER * self.baseline_stddev_ms.max(STDDEV_FLOOR_MS)
    }

    #[must_use]
    pub fn evaluate(&self, measured_ms: f64, expected_sleep_secs: f64) -> TimeResult {
        let expected = expected_sleep_secs * 1000.0 + self.baseline_mean_ms;
        let threshold = self.threshold();
        let is_vuln = measured_ms > threshold
            && (measured_ms - self.baseline_mean_ms)
                > expected_sleep_secs * 1000.0 * MIN_SLEEP_FRACTION;
        let confidence = if is_vuln {
            let ratio = ((measured_ms - self.baseline_mean_ms) / (expected_sleep_secs * 1000.0))
                .clamp(0.0, 1.5);
            (0.6 + ratio * 0.3).clamp(0.0, 1.0)
        } else {
            0.1
        };
        TimeResult {
            is_vulnerable: is_vuln,
            confidence,
            measured_ms,
            expected_ms: expected,
        }
    }

    /// Two-shot confirmation against network jitter: both shots must
    /// independently exceed [`Self::threshold`] (via [`Self::evaluate`]).
    /// A single slow response (hiccup, GC pause, WAF throttle) never
    /// confirms. Reported `measured_ms` is the mean of both shots and
    /// confidence is re-derived from that mean, so callers keep a single
    /// calibrated score.
    #[must_use]
    pub fn evaluate_confirmed(
        &self,
        first_ms: f64,
        second_ms: f64,
        expected_sleep_secs: f64,
    ) -> TimeResult {
        let first = self.evaluate(first_ms, expected_sleep_secs);
        let second = self.evaluate(second_ms, expected_sleep_secs);
        if first.is_vulnerable && second.is_vulnerable {
            self.evaluate((first_ms + second_ms) / 2.0, expected_sleep_secs)
        } else {
            // Negative: report the weaker shot so evidence shows the miss.
            let weaker = first_ms.min(second_ms);
            let mut r = self.evaluate(weaker, expected_sleep_secs);
            r.is_vulnerable = false;
            r.confidence = 0.1;
            r.measured_ms = weaker;
            r
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detection::baseline::{Baseline, Sample};
    use std::time::Duration;

    fn baseline(mean_ms: u64) -> Baseline {
        let samples = vec![
            Sample {
                status: 200,
                body: b"ok".to_vec(),
                duration: Duration::from_millis(mean_ms),
            },
            Sample {
                status: 200,
                body: b"ok".to_vec(),
                duration: Duration::from_millis(mean_ms),
            },
            Sample {
                status: 200,
                body: b"ok".to_vec(),
                duration: Duration::from_millis(mean_ms),
            },
        ];
        Baseline::new(&samples)
    }

    #[test]
    fn from_baseline_matches_threshold_ms() {
        let bl = baseline(100);
        let det = TimeDetector::from_baseline(&bl);
        assert_eq!(det.baseline_mean_ms, bl.mean_ms);
        assert_eq!(det.baseline_stddev_ms, bl.stddev_ms);
        // Same formula: mean + 2 * max(stddev, 100).
        assert!((det.threshold() - bl.threshold_ms(2.0)).abs() < f64::EPSILON);
    }

    #[test]
    fn single_shot_detects_sleep() {
        let det = TimeDetector::new(100.0, 10.0);
        let r = det.evaluate(3200.0, 3.0);
        assert!(r.is_vulnerable);
        assert!(r.confidence >= 0.6);
    }

    #[test]
    fn single_shot_rejects_baseline_jitter() {
        let det = TimeDetector::new(100.0, 10.0);
        let r = det.evaluate(150.0, 3.0);
        assert!(!r.is_vulnerable);
    }

    #[test]
    fn confirmed_requires_both_shots() {
        let det = TimeDetector::new(100.0, 10.0);
        let ok = det.evaluate_confirmed(3200.0, 3300.0, 3.0);
        assert!(ok.is_vulnerable);
        let flaky = det.evaluate_confirmed(3200.0, 120.0, 3.0);
        assert!(!flaky.is_vulnerable);
        assert_eq!(flaky.confidence, 0.1);
    }

    #[test]
    fn confirmed_reports_mean() {
        let det = TimeDetector::new(100.0, 10.0);
        let r = det.evaluate_confirmed(3000.0, 3400.0, 3.0);
        assert!(r.is_vulnerable);
        assert!((r.measured_ms - 3200.0).abs() < f64::EPSILON);
    }
}
