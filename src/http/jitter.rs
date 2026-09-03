#![deny(unsafe_code)]

use rand_distr::{Distribution, Normal};

/// Human-like jitter between requests: normal distribution, never negative.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
// All fields carry a `_ms` unit suffix by design — that's the point, not a naming collision.
#[allow(clippy::struct_field_names)]
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
    // Delay values are small millisecond magnitudes, always non-negative; casts are safe here.
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    pub fn next_delay(&self) -> std::time::Duration {
        let mut rng = rand::rng();
        let normal = match Normal::new(self.mean_ms, self.stddev_ms.max(1.0)) {
            Ok(n) => n,
            Err(_) => {
                if let Ok(n) = Normal::new(self.mean_ms, 50.0) {
                    n
                } else {
                    // Both attempts failed (stddev invalid) — fallback to uniform jitter around mean
                    let fallback: f64 = rand::random_range(500.0..1000.0);
                    return std::time::Duration::from_millis(
                        fallback.max(self.min_ms as f64).round() as u64,
                    );
                }
            }
        };
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
