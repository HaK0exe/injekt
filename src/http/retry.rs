#![deny(unsafe_code)]

use std::time::Duration;

/// Exponential backoff with jitter.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct RetryPolicy {
    pub max_retries: usize,
    pub base_delay: Duration,
    pub max_delay: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 3,
            base_delay: Duration::from_millis(500),
            max_delay: Duration::from_secs(5),
        }
    }
}

impl RetryPolicy {
    #[must_use]
    pub fn delay_for(&self, attempt: usize) -> Duration {
        if attempt == 0 {
            return Duration::from_millis(0);
        }
        let exp = self.base_delay.as_millis() as f64 * 2_f64.powi(attempt as i32 - 1);
        let capped = exp.min(self.max_delay.as_millis() as f64);
        // add ±20% jitter
        let jitter: f64 = rand::random_range(-0.2..0.2);
        let ms = (capped * (1.0 + jitter)).round().max(0.0) as u64;
        Duration::from_millis(ms)
    }

    #[must_use]
    pub fn should_retry(&self, attempt: usize, status: Option<u16>) -> bool {
        if attempt >= self.max_retries {
            return false;
        }
        match status {
            Some(429 | 500 | 502 | 503 | 504) => true,
            None => true, // network error
            _ => false,
        }
    }
}
