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
/// Mean above which the sleep-fraction requirement relaxes (slow targets:
/// a full 50% extra delay is harsh when the baseline itself is seconds).
const SLOW_MEAN_THRESHOLD_MS: f64 = 3000.0;
/// Relaxed sleep fraction on slow targets (`mean > 3s`).
const MIN_SLEEP_FRACTION_SLOW: f64 = 0.3;

/// Adaptive stddev floor (Phase 3): `max(100ms, mean * 0.1)`.
///
/// Fast targets (`mean <= 1s`) keep the historical 100ms floor
/// byte-identical; slow targets tolerate proportional jitter (e.g. mean 5s
/// => floor 500ms => threshold `mean + 2*500`) instead of flagging every
/// ±200ms wobble as anomalous.
#[must_use]
pub fn adaptive_stddev_floor_ms(mean_ms: f64) -> f64 {
    if !mean_ms.is_finite() || mean_ms <= 0.0 {
        return STDDEV_FLOOR_MS;
    }
    STDDEV_FLOOR_MS.max(mean_ms * 0.1)
}

/// Adaptive sleep fraction (Phase 3): `0.5` by default, `0.3` when
/// `mean > 3s`.
///
/// On slow targets the absolute sleep delay is already large relative to
/// jitter, so requiring only 30% of the expected sleep keeps a 5s sleep on
/// a 5s-mean baseline detectable without waiting for a 7.5s response.
#[must_use]
pub fn adaptive_min_sleep_fraction(mean_ms: f64) -> f64 {
    if mean_ms.is_finite() && mean_ms > SLOW_MEAN_THRESHOLD_MS {
        MIN_SLEEP_FRACTION_SLOW
    } else {
        MIN_SLEEP_FRACTION
    }
}

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
    /// at `sigma = 2.0` on fast targets (same floor of 100ms, same
    /// multiplier). On slow targets (`mean > 1s`) the adaptive floor
    /// `max(100ms, mean*0.1)` widens the threshold proportionally.
    #[must_use]
    pub fn from_baseline(baseline: &crate::detection::baseline::Baseline) -> Self {
        Self::new(baseline.mean_ms, baseline.stddev_ms)
    }

    #[must_use]
    pub fn threshold(&self) -> f64 {
        self.baseline_mean_ms
            + SIGMA_MULTIPLIER
                * self
                    .baseline_stddev_ms
                    .max(adaptive_stddev_floor_ms(self.baseline_mean_ms))
    }

    #[must_use]
    pub fn evaluate(&self, measured_ms: f64, expected_sleep_secs: f64) -> TimeResult {
        let expected = expected_sleep_secs * 1000.0 + self.baseline_mean_ms;
        let threshold = self.threshold();
        let min_fraction = adaptive_min_sleep_fraction(self.baseline_mean_ms);
        let is_vuln = measured_ms > threshold
            && (measured_ms - self.baseline_mean_ms) > expected_sleep_secs * 1000.0 * min_fraction;
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
            self.evaluate(first_ms.midpoint(second_ms), expected_sleep_secs)
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
                headers: Vec::new(),
            },
            Sample {
                status: 200,
                body: b"ok".to_vec(),
                duration: Duration::from_millis(mean_ms),
                headers: Vec::new(),
            },
            Sample {
                status: 200,
                body: b"ok".to_vec(),
                duration: Duration::from_millis(mean_ms),
                headers: Vec::new(),
            },
        ];
        Baseline::new(&samples)
    }

    #[test]
    fn from_baseline_matches_threshold_ms() {
        let bl = baseline(100);
        let det = TimeDetector::from_baseline(&bl);
        assert!((det.baseline_mean_ms - bl.mean_ms).abs() < f64::EPSILON);
        assert!((det.baseline_stddev_ms - bl.stddev_ms).abs() < f64::EPSILON);
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
        assert!((flaky.confidence - 0.1).abs() < f64::EPSILON);
    }

    #[test]
    fn confirmed_reports_mean() {
        let det = TimeDetector::new(100.0, 10.0);
        let r = det.evaluate_confirmed(3000.0, 3400.0, 3.0);
        assert!(r.is_vulnerable);
        assert!((r.measured_ms - 3200.0).abs() < f64::EPSILON);
    }

    #[test]
    fn adaptive_floor_stays_static_on_fast_targets() {
        // L1 byte-identical: mean <= 1s => floor 100ms.
        assert!((adaptive_stddev_floor_ms(100.0) - 100.0).abs() < f64::EPSILON);
        assert!((adaptive_stddev_floor_ms(1000.0) - 100.0).abs() < f64::EPSILON);
        assert!((adaptive_min_sleep_fraction(100.0) - 0.5).abs() < f64::EPSILON);
        let det = TimeDetector::new(100.0, 10.0);
        assert!((det.threshold() - 300.0).abs() < f64::EPSILON);
    }

    #[test]
    fn adaptive_floor_scales_on_slow_targets() {
        // mean 5s => floor max(100, 500) = 500, threshold 5000 + 2*500 = 6000.
        assert!((adaptive_stddev_floor_ms(5000.0) - 500.0).abs() < f64::EPSILON);
        assert!((adaptive_min_sleep_fraction(5000.0) - 0.3).abs() < f64::EPSILON);
        let det = TimeDetector::new(5000.0, 10.0);
        assert!((det.threshold() - 6000.0).abs() < f64::EPSILON);
    }

    #[test]
    fn slow_baseline_sleep_stays_detectable() {
        // Phase 3: mean 5s, sleep 5s => measured ~10s must confirm.
        let det = TimeDetector::new(5000.0, 50.0);
        let r = det.evaluate(10_000.0, 5.0);
        assert!(r.is_vulnerable, "5s sleep on 5s mean must detect");
        assert!(r.confidence >= 0.6);
        // Jitter just under threshold must not flag.
        let jitter = det.evaluate(5500.0, 5.0);
        assert!(!jitter.is_vulnerable);
        // Two-shot confirmation holds on slow targets too.
        let ok = det.evaluate_confirmed(10_000.0, 10_200.0, 5.0);
        assert!(ok.is_vulnerable);
    }
}
