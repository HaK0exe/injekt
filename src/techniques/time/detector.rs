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
}
