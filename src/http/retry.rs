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
///
/// Stale-pool TLS race included: Cloudflare-style edges close idle
/// keep-alive connections without TLS `close_notify`; rustls/hyper then
/// surfaces the reuse as `UnexpectedEof` (`Kind::Request` with an
/// `UnexpectedEof`/`close_notify` in the source chain). That race is
/// transient — the immediate retry gets a fresh connection — so it is
/// retryable. Plain `is_request` errors without that signature stay
/// non-retryable to avoid burning budget on deterministic request errors.
///
/// Idempotence gate: this legacy overload assumes an idempotent method
/// (equivalent to `GET`; Cloudflare keep-alive fix preserved). Callers that
/// know the request method MUST use
/// [`is_retryable_error_for_method`] instead: replaying a non-idempotent
/// `POST`/`PATCH` on a stale-pool `EOF` would double-submit (the server may
/// already have executed the first copy). See [`is_idempotent_method`].
#[must_use]
pub fn is_retryable_error(e: &reqwest::Error) -> bool {
    e.is_timeout() || e.is_connect() || e.is_body() || is_stale_pool_eof(e)
}

/// Method-aware retry gate (preferred over [`is_retryable_error`]).
///
/// `timeout`/`connect`/`body` stay retryable for every method (historical
/// behaviour, unchanged): they fire before/without a usable response and the
/// scanner's detection payloads are read-only probes. The stale-pool TLS
/// `EOF` race replays the *whole* request, so it is only retryable for
/// idempotent methods (see [`is_idempotent_method`]): a `POST` that hit the
/// race is surfaced as-is instead of being replayed.
#[must_use]
pub fn is_retryable_error_for_method(e: &reqwest::Error, method: &http::Method) -> bool {
    e.is_timeout() || e.is_connect() || e.is_body() || is_stale_pool_eof_for_method(e, method)
}

/// RFC 9110 §9.2.2 idempotent methods: replaying the request has the same
/// effect as a single copy. `GET`/`HEAD` (the scanner's query-param path)
/// plus `OPTIONS`/`TRACE`/`PUT`/`DELETE` are safe to replay on a stale-pool
/// `EOF`; `POST`/`PATCH`/`CONNECT` are not (double-submit risk) and must
/// never auto-retry that race.
#[must_use]
pub fn is_idempotent_method(method: &http::Method) -> bool {
    matches!(
        *method,
        http::Method::GET
            | http::Method::HEAD
            | http::Method::OPTIONS
            | http::Method::TRACE
            | http::Method::PUT
            | http::Method::DELETE
    )
}

/// Detect the stale-pooled-connection TLS race: `Kind::Request` whose source
/// chain carries `io::ErrorKind::UnexpectedEof` or mentions `close_notify` /
/// `UnexpectedEof` (rustls `UnexpectedEof` docs: peer closed without
/// `close_notify`; safe to retry when no message is in flight, which is
/// exactly the idle-pool checkout case).
fn is_stale_pool_eof(e: &reqwest::Error) -> bool {
    use std::error::Error as _;
    if !e.is_request() {
        return false;
    }
    source_chain_has_eof(e.source())
}

/// Idempotent-gated variant of [`is_stale_pool_eof`]: returns `false` for
/// non-idempotent methods without even inspecting the chain, so a `POST`
/// checkout race is never replayed (double-submit). Pure gate extracted as
/// [`should_retry_stale_eof_for_method`] for unit tests.
fn is_stale_pool_eof_for_method(e: &reqwest::Error, method: &http::Method) -> bool {
    use std::error::Error as _;
    if !should_retry_stale_eof_for_method(method, true) {
        return false;
    }
    if !e.is_request() {
        return false;
    }
    source_chain_has_eof(e.source())
}

/// Pure idempotence gate for the stale-pool `EOF` race, unit-testable without
/// a real `reqwest::Error`: `chain_has_eof` is the [`source_chain_has_eof`]
/// verdict. `POST`/`PATCH` (non-idempotent) never retry the race, even when
/// the chain matches — the request is surfaced as-is.
#[must_use]
pub fn should_retry_stale_eof_for_method(method: &http::Method, chain_has_eof: bool) -> bool {
    chain_has_eof && is_idempotent_method(method)
}

/// Walk an error source chain looking for the stale-pool TLS signature.
/// Split out (pure over `&dyn Error`) so it is unit-testable without
/// constructing a real `reqwest::Error`.
///
/// Fragility note (PR20): the `Display.contains("close_notify" |
/// "UnexpectedEof")` arm is best-effort string matching across
/// rustls/hyper versions — message wording is not a stable API and a
/// reword could silently disable the Cloudflare keep-alive retry (false
/// negative, never a false retry: unknown errors stay non-retryable). The
/// authoritative signal is the `io::ErrorKind::UnexpectedEof` downcast
/// checked first; the string arm only covers rustls builds that surface the
/// race as `io::Error::other` with the token in the message. Keep both arms,
/// keep the gate fail-closed (no match = no retry).
fn source_chain_has_eof(mut source: Option<&(dyn std::error::Error + 'static)>) -> bool {
    while let Some(err) = source {
        if let Some(io) = err.downcast_ref::<std::io::Error>()
            && io.kind() == std::io::ErrorKind::UnexpectedEof
        {
            return true;
        }
        let msg = err.to_string();
        if msg.contains("close_notify") || msg.contains("UnexpectedEof") {
            return true;
        }
        source = err.source();
    }
    false
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

    #[test]
    fn stale_pool_eof_chain_is_detected() {
        use std::io::{Error as IoError, ErrorKind};
        // Direct `UnexpectedEof` kind.
        let eof = IoError::new(ErrorKind::UnexpectedEof, "early eof");
        assert!(super::source_chain_has_eof(Some(&eof)));
        // rustls-style message without the kind.
        let notify = IoError::other("peer closed connection without sending TLS close_notify");
        assert!(super::source_chain_has_eof(Some(&notify)));
        // Ordinary errors are not the pool race.
        let timed_out = IoError::new(ErrorKind::TimedOut, "timed out");
        assert!(!super::source_chain_has_eof(Some(&timed_out)));
        assert!(!super::source_chain_has_eof(None));
    }

    #[test]
    fn idempotent_methods_allow_stale_eof_retry() {
        assert!(super::is_idempotent_method(&http::Method::GET));
        assert!(super::is_idempotent_method(&http::Method::HEAD));
        assert!(super::is_idempotent_method(&http::Method::OPTIONS));
        assert!(super::is_idempotent_method(&http::Method::PUT));
        assert!(super::is_idempotent_method(&http::Method::DELETE));
    }

    #[test]
    fn post_is_never_replayed_on_stale_pool_eof() {
        // PR20 double-submit guard: even with a matching EOF chain, a
        // non-idempotent method must not retry the stale-pool race.
        // `GET` keeps the Cloudflare keep-alive fix.
        assert!(super::should_retry_stale_eof_for_method(
            &http::Method::GET,
            true
        ));
        assert!(super::should_retry_stale_eof_for_method(
            &http::Method::HEAD,
            true
        ));
        assert!(!super::should_retry_stale_eof_for_method(
            &http::Method::POST,
            true
        ));
        assert!(!super::should_retry_stale_eof_for_method(
            &http::Method::PATCH,
            true
        ));
        // No chain match = no retry whatever the method (fail-closed).
        assert!(!super::should_retry_stale_eof_for_method(
            &http::Method::GET,
            false
        ));
        assert!(!super::should_retry_stale_eof_for_method(
            &http::Method::POST,
            false
        ));
        assert!(!super::is_idempotent_method(&http::Method::POST));
        assert!(!super::is_idempotent_method(&http::Method::PATCH));
    }
}
