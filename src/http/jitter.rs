#![deny(unsafe_code)]

use rand_distr::{Distribution, Normal};
use tokio_util::sync::CancellationToken;

/// OPSEC floor for inter-request jitter (C10): no scan path may pace probes
/// closer than this, whatever `--jitter` says. Enforced by the client
/// builders (`client_builder`, recon `build_client`) via
/// [`Jitter::with_min`]; [`Jitter::default`] carries it directly.
pub const JITTER_FLOOR_MS: u64 = 200;

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

    /// OS-random delay; the scan path must use [`Self::next_delay_with_rng`]
    /// with the shared run RNG instead (C10: jitter seedé partout).
    #[must_use]
    // Delay values are small millisecond magnitudes, always non-negative; casts are safe here.
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    pub fn next_delay(&self) -> std::time::Duration {
        // OS-random path routed through the single seeded entry point
        // (`make_rng(None)`); seeded scans use `next_delay_with_rng`.
        let mut rng = crate::seeded_rng::make_rng(None);
        self.next_delay_with_rng(&mut rng)
    }

    /// Seeded variant of [`Self::next_delay`]: randomness is drawn from `rng`.
    /// Pass `&mut crate::seeded_rng::make_rng(seed)` for deterministic runs.
    #[must_use]
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    pub fn next_delay_with_rng(&self, rng: &mut impl rand::Rng) -> std::time::Duration {
        let normal = match Normal::new(self.mean_ms, self.stddev_ms.max(1.0)) {
            Ok(n) => n,
            Err(_) => {
                if let Ok(n) = Normal::new(self.mean_ms, 50.0) {
                    n
                } else {
                    // Both attempts failed (stddev invalid) — fallback to uniform jitter around mean
                    let fallback: f64 = rng.random_range(500.0..1000.0);
                    return std::time::Duration::from_millis(
                        fallback.max(self.min_ms as f64).round() as u64,
                    );
                }
            }
        };
        let sample = normal
            .sample(&mut *rng)
            .max(f64::from(u32::try_from(self.min_ms).unwrap_or(0)));
        let ms = sample.max(0.0).round() as u64;
        std::time::Duration::from_millis(ms)
    }

    /// Seeded jitter sleep: delay drawn from `rng`.
    pub async fn sleep_with_rng(&self, rng: &mut impl rand::Rng) {
        let delay = self.next_delay_with_rng(rng);
        tokio::time::sleep(delay).await;
    }

    /// OS-random sleep; off the scan path (C10). Scan code draws the delay
    /// from the shared run RNG and sleeps cancellably itself.
    pub async fn sleep(&self) {
        tokio::time::sleep(self.next_delay()).await;
    }

    /// Cancellable jitter sleep: returns `false` when `cancel` fires first,
    /// `true` once the delay fully elapsed.
    ///
    /// OS-random delay; off the scan path (C10) — see
    /// [`Self::sleep_cancellable_with_rng`].
    pub async fn sleep_cancellable(&self, cancel: &CancellationToken) -> bool {
        tokio::select! {
            () = cancel.cancelled() => false,
            () = tokio::time::sleep(self.next_delay()) => true,
        }
    }

    /// Seeded variant of [`Self::sleep_cancellable`]: delay drawn from `rng`
    /// before sleeping, so `--seed` runs are deterministic.
    pub async fn sleep_cancellable_with_rng(
        &self,
        rng: &mut impl rand::Rng,
        cancel: &CancellationToken,
    ) -> bool {
        let delay = self.next_delay_with_rng(rng);
        tokio::select! {
            () = cancel.cancelled() => false,
            () = tokio::time::sleep(delay) => true,
        }
    }
}

impl Default for Jitter {
    fn default() -> Self {
        Self::new(750.0, 250.0).with_min(JITTER_FLOOR_MS)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::seeded_rng::make_rng;

    #[test]
    fn same_seed_same_delay_sequence() {
        let jitter = Jitter::new(750.0, 250.0).with_min(200);
        let mut a = make_rng(Some(11));
        let mut b = make_rng(Some(11));
        for _ in 0..10 {
            assert_eq!(
                jitter.next_delay_with_rng(&mut a),
                jitter.next_delay_with_rng(&mut b)
            );
        }
    }

    #[test]
    fn different_seeds_likely_differ() {
        let jitter = Jitter::new(750.0, 250.0).with_min(200);
        let mut a = make_rng(Some(1));
        let mut b = make_rng(Some(2));
        let xs: Vec<std::time::Duration> = (0..10)
            .map(|_| jitter.next_delay_with_rng(&mut a))
            .collect();
        let ys: Vec<std::time::Duration> = (0..10)
            .map(|_| jitter.next_delay_with_rng(&mut b))
            .collect();
        assert_ne!(xs, ys);
    }

    #[test]
    fn none_path_produces_nonnegative_delay() {
        let jitter = Jitter::new(750.0, 250.0).with_min(200);
        let mut rng = make_rng(None);
        let delay = jitter.next_delay_with_rng(&mut rng);
        assert!(delay.as_millis() >= 200);
        // OS-random wrapper stays usable.
        assert!(jitter.next_delay().as_millis() >= 200);
    }
}
