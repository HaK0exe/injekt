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

/// Upper bound for honoring a server `Retry-After` (C10): the ask is taken
/// at face value up to this cap (A3-style `1s` values fully honored), so a
/// malicious `Retry-After: 3600` parks one retry at most 60s instead of an
/// hour. Must stay consistent with
/// [`crate::http::rate_limit::MAX_RETRY_AFTER_PENALTY_SECS`].
pub const RETRY_AFTER_HONOR_CAP_SECS: u64 = 60;

/// Check if a reqwest error is retryable (timeout, connect, body).
/// `is_decode` is deliberately excluded: decode failures are deterministic
/// (bad body framing) and retrying them just burns requests.
#[must_use]
pub fn is_retryable_error(e: &reqwest::Error) -> bool {
    e.is_timeout() || e.is_connect() || e.is_body()
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
    /// OS-random backoff; seeded runs must use [`Self::delay_for_with_rng`].
    /// Routed through `make_rng(None)` so the seeded entry point stays unique.
    #[must_use]
    // Retry delays are bounded, sub-minute millisecond magnitudes; casts are safe here.
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_possible_wrap
    )]
    pub fn delay_for(&self, attempt: usize) -> Duration {
        let mut rng = crate::seeded_rng::make_rng(None);
        self.delay_for_with_rng(attempt, &mut rng)
    }

    /// Seeded variant of [`Self::delay_for`]: the ±20% jitter is drawn from
    /// `rng` so the same `--seed` yields the same backoff sequence.
    #[must_use]
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_possible_wrap
    )]
    pub fn delay_for_with_rng(&self, attempt: usize, rng: &mut impl rand::Rng) -> Duration {
        if attempt == 0 {
            return Duration::from_millis(0);
        }
        let exp = self.base_delay.as_millis() as f64 * 2_f64.powi(attempt as i32 - 1);
        let capped = exp.min(self.max_delay.as_millis() as f64);
        // add ±20% jitter
        let jitter: f64 = rng.random_range(-0.2..0.2);
        let ms = (capped * (1.0 + jitter)).round().max(0.0) as u64;
        Duration::from_millis(ms)
    }

    #[must_use]
    pub fn should_retry(&self, attempt: usize, status: Option<u16>) -> bool {
        if attempt >= self.max_retries {
            return false;
        }
        #[allow(clippy::match_same_arms)]
        match status {
            Some(408 | 425 | 429 | 500 | 502 | 503 | 504) => true,
            None => true, // network error
            _ => false,
        }
    }

    /// Delay for `attempt`, honoring an optional `Retry-After` header value
    /// (delta-seconds). The header value is honored up to
    /// [`RETRY_AFTER_HONOR_CAP_SECS`] (C10): previously it was truncated to
    /// `max_delay` (5s), so any `Retry-After` above 5s was silently shortened
    /// and the scanner re-hit the limiter early (A3 `5/s` shape). A malicious
    /// server can still park one retry at most 60s, and the per-run retry
    /// budget (`max_retries`) bounds the total stall.
    ///
    /// OS-random wrapper around [`Self::delay_for_retry_after_with_rng`];
    /// scan-path callers must use the seeded variant.
    /// Routed through `make_rng(None)` so the seeded entry point stays unique.
    #[must_use]
    pub fn delay_for_retry_after(&self, attempt: usize, retry_after: Option<&str>) -> Duration {
        let mut rng = crate::seeded_rng::make_rng(None);
        self.delay_for_retry_after_with_rng(attempt, retry_after, &mut rng)
    }

    /// Seeded variant of [`Self::delay_for_retry_after`].
    #[must_use]
    pub fn delay_for_retry_after_with_rng(
        &self,
        attempt: usize,
        retry_after: Option<&str>,
        rng: &mut impl rand::Rng,
    ) -> Duration {
        let base = self.delay_for_with_rng(attempt, rng);
        let Some(raw) = retry_after else {
            return base;
        };
        if let Some(secs) = parse_retry_after_secs(raw) {
            let honored = secs.min(Duration::from_secs(RETRY_AFTER_HONOR_CAP_SECS));
            return base.max(honored);
        }
        base
    }
}

/// Parse `Retry-After` delta-seconds into a capped `Duration`.
/// HTTP-date form is ignored (`None`) — delta-seconds covers the common
/// `429`/`503` case without a new date-parsing dependency.
/// Returns `None` when unparseable.
#[must_use]
pub fn parse_retry_after_secs(raw: &str) -> Option<Duration> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Ok(secs) = trimmed.parse::<u64>() {
        return Some(Duration::from_secs(secs.min(60)));
    }
    None
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::seeded_rng::make_rng;

    fn policy() -> RetryPolicy {
        RetryPolicy {
            max_retries: 3,
            base_delay: Duration::from_millis(500),
            max_delay: Duration::from_secs(5),
        }
    }

    #[test]
    fn same_seed_same_backoff_sequence() {
        let retry = policy();
        let mut a = make_rng(Some(21));
        let mut b = make_rng(Some(21));
        for attempt in 1..=5 {
            assert_eq!(
                retry.delay_for_with_rng(attempt, &mut a),
                retry.delay_for_with_rng(attempt, &mut b)
            );
        }
    }

    #[test]
    fn different_seeds_likely_differ() {
        let retry = policy();
        let mut a = make_rng(Some(1));
        let mut b = make_rng(Some(2));
        let xs: Vec<Duration> = (1..=8)
            .map(|i| retry.delay_for_with_rng(i, &mut a))
            .collect();
        let ys: Vec<Duration> = (1..=8)
            .map(|i| retry.delay_for_with_rng(i, &mut b))
            .collect();
        assert_ne!(xs, ys);
    }

    #[test]
    fn none_path_and_attempt_zero() {
        let retry = policy();
        assert_eq!(
            retry.delay_for_with_rng(0, &mut make_rng(None)),
            Duration::from_millis(0)
        );
        // OS-random wrapper stays usable and bounded.
        let delay = retry.delay_for(1);
        assert!(delay.as_millis() >= 400 && delay.as_millis() <= 600);
    }

    #[test]
    fn retry_after_above_max_delay_is_honored_not_truncated() {
        // C10: `Retry-After: 30` used to be truncated to `max_delay` (5s),
        // re-hitting an A3-style limiter early. Now honored up to the 60s cap.
        let retry = policy();
        let delay = retry.delay_for_retry_after_with_rng(1, Some("30"), &mut make_rng(Some(3)));
        assert!(
            delay >= Duration::from_secs(30),
            "Retry-After: 30 must be honored, got {delay:?}"
        );
        assert!(delay <= Duration::from_secs(RETRY_AFTER_HONOR_CAP_SECS));
    }

    #[test]
    fn retry_after_malicious_value_is_capped() {
        let retry = policy();
        let delay = retry.delay_for_retry_after_with_rng(1, Some("3600"), &mut make_rng(Some(3)));
        assert_eq!(delay, Duration::from_secs(RETRY_AFTER_HONOR_CAP_SECS));
    }

    #[test]
    fn retry_after_small_value_beats_base_backoff() {
        let retry = policy();
        let delay = retry.delay_for_retry_after_with_rng(1, Some("1"), &mut make_rng(Some(3)));
        assert!(
            delay >= Duration::from_secs(1),
            "Retry-After: 1 must floor the backoff, got {delay:?}"
        );
    }
}
