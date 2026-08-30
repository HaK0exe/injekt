#![deny(unsafe_code)]
#![allow(clippy::expect_used)]

use rand_distr::{Distribution, Normal};

/// Human-like jitter between requests: normal distribution, never negative.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct Jitter {
    mean_ms: f64,
    stddev_ms: f64,
    min_ms: u64,
}

impl Jitter {
    #[must_use]
    pub fn new(mean_ms: f64, stddev_ms: f64) -> Self {
        Self {
            mean_ms,
            stddev_ms,
            min_ms: 0,
        }
    }

    #[must_use]
    pub fn with_min(mut self, min_ms: u64) -> Self {
        self.min_ms = min_ms;
        self
    }

    #[must_use]
    pub fn next_delay(&self) -> std::time::Duration {
        let mut rng = rand::rng();
        let normal = Normal::new(self.mean_ms, self.stddev_ms.max(1.0))
            .unwrap_or_else(|_| Normal::new(self.mean_ms, 50.0).expect("normal"));
        let sample = normal
            .sample(&mut rng)
            .max(f64::from(u32::try_from(self.min_ms).unwrap_or(0)));
        let ms = sample.max(0.0).round() as u64;
        std::time::Duration::from_millis(ms)
    }

    pub async fn sleep(&self) {
        tokio::time::sleep(self.next_delay()).await;
    }
}

impl Default for Jitter {
    fn default() -> Self {
        Self::new(750.0, 250.0).with_min(200)
    }
}
