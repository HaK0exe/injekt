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
        self.baseline_mean_ms + 2.0 * self.baseline_stddev_ms.max(100.0)
    }

    #[must_use]
    pub fn evaluate(&self, measured_ms: f64, expected_sleep_secs: f64) -> TimeResult {
        let expected = expected_sleep_secs * 1000.0 + self.baseline_mean_ms;
        let threshold = self.threshold();
        let is_vuln = measured_ms > threshold
            && (measured_ms - self.baseline_mean_ms) > expected_sleep_secs * 500.0;
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
