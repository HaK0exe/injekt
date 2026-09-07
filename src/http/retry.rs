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
    #[must_use]
    // Retry delays are bounded, sub-minute millisecond magnitudes; casts are safe here.
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_possible_wrap
    )]
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
        #[allow(clippy::match_same_arms)]
        match status {
            Some(408 | 425 | 429 | 500 | 502 | 503 | 504) => true,
            None => true, // network error
            _ => false,
        }
    }

    /// Delay for `attempt`, honoring an optional `Retry-After` header value
    /// (delta-seconds). The header value is capped at `max_delay` so a
    /// malicious server cannot park the scanner.
    #[must_use]
    pub fn delay_for_retry_after(&self, attempt: usize, retry_after: Option<&str>) -> Duration {
        let base = self.delay_for(attempt);
        let Some(raw) = retry_after else {
            return base;
        };
        if let Some(secs) = parse_retry_after_secs(raw) {
            return base.max(secs).min(self.max_delay);
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
