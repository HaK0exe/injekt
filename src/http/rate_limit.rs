#![deny(unsafe_code)]

use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

/// Token-bucket rate limiter.
///
/// Note on pacing: [`HttpClient::send_with_retry`] awaits
/// `acquire_cancellable()` (chemin scan, annulable via `CancellationToken`)
/// and then the jitter sleep back-to-back, so per-request pacing is additive
/// (`rate-limit wait` + `jitter wait`), not `max()` of the two. Lower both
/// knobs together to speed up scans; raising only one leaves the other.
///
/// `acquire()` (non-annulable) est conservé pour les chemins hors scan
/// (tests/outils); tout le chemin scan utilise `acquire_cancellable()`
/// (vérifié Phase 0: `client.rs` 4 appels, 0 `acquire()` restant dans `src/`).
///
/// Cap `Retry-After` 60s: voir [`MAX_RETRY_AFTER_PENALTY_SECS`] (pénalité
/// pacing) + `RETRY_AFTER_HONOR_CAP_SECS` (`retry.rs`, délai retry) +
/// `parse_retry_after_secs` (parse, cap 60s) — les trois bornes restent à
/// 60s pour qu'un `Retry-After: 3600` malicieux ne parque ni le pacing ni un
/// retry plus de 60s.
#[derive(Debug)]
#[non_exhaustive]
pub struct RateLimiter {
    max_per_sec: f64,
    bucket: Mutex<Bucket>,
}

/// Single default request rate (req/s) shared by [`RateLimiter::default`]
/// and the [`HttpClient`] fallback when no limiter is injected.
pub const DEFAULT_RPS: f64 = 10.0;

/// Upper bound for a `Retry-After`-driven pacing penalty (C10): the server's
/// ask is honored up to this cap so a malicious `Retry-After: 3600` cannot
/// park the scanner, while legitimate A3-style `1s` values are fully honored
/// (well above the `429` sizes a `5/s` limiter emits).
pub const MAX_RETRY_AFTER_PENALTY_SECS: u64 = 60;

#[derive(Debug)]
struct Bucket {
    tokens: f64,
    last: Instant,
    /// Earliest instant the next acquire may proceed: set by
    /// [`RateLimiter::notify_rate_limited`] from the `Retry-After` value so
    /// the burst does not resume the moment a per-request backoff sleep ends
    /// (A3 `5/s` limiter). `None` = no penalty outstanding.
    not_before: Option<Instant>,
}

impl RateLimiter {
    #[must_use]
    pub fn new(requests_per_sec: f64) -> Self {
        Self {
            max_per_sec: requests_per_sec.max(0.1),
            bucket: Mutex::new(Bucket {
                tokens: requests_per_sec,
                last: Instant::now(),
                not_before: None,
            }),
        }
    }

    /// Record a `429` (or `503`) throttling signal (C10): drain the burst
    /// tokens and, when the server sent `Retry-After`, pace all subsequent
    /// acquires until it elapses (capped at
    /// [`MAX_RETRY_AFTER_PENALTY_SECS`]). Without a header value the bucket
    /// is still drained so the next acquire pays one full refill interval
    /// instead of bursting straight back into the limiter.
    ///
    /// Down-only by design: this never raises the rate (`stealth` is never
    /// auto-escalated, OPSEC), it only yields to the server's ask.
    pub async fn notify_rate_limited(&self, retry_after: Option<Duration>) {
        if !self.max_per_sec.is_finite() {
            return;
        }
        let mut b = self.bucket.lock().await;
        let now = Instant::now();
        b.tokens = 0.0;
        b.last = now;
        if let Some(d) = retry_after {
            let capped = d.min(Duration::from_secs(MAX_RETRY_AFTER_PENALTY_SECS));
            let until = now + capped;
            b.not_before = Some(match b.not_before {
                Some(prev) if prev > until => prev,
                _ => until,
            });
        }
    }

    /// Remaining pacing penalty, if any (expired penalties read as zero).
    /// Test-only observability for the C10 penalty-horizon unit tests.
    #[cfg(test)]
    async fn penalty_remaining(&self) -> Duration {
        let b = self.bucket.lock().await;
        match b.not_before {
            Some(until) => until.saturating_duration_since(Instant::now()),
            None => Duration::ZERO,
        }
    }

    pub async fn acquire(&self) {
        // Hors scan uniquement (tests/outils) : le chemin scan doit utiliser
        // `acquire_cancellable()` pour que Ctrl+C interrompe l'attente.
        // Fast-path: `disabled()` uses infinite tokens — no locking/sleep.
        if !self.max_per_sec.is_finite() {
            return;
        }
        loop {
            let mut b = self.bucket.lock().await;
            let now = Instant::now();
            let elapsed = now.duration_since(b.last).as_secs_f64();
            b.tokens = (b.tokens + elapsed * self.max_per_sec).min(self.max_per_sec);
            b.last = now;
            // A `429`-driven pacing penalty (`not_before`) gates even a full
            // bucket: the server asked for quiet, burst tokens do not override it.
            let penalty = b
                .not_before
                .map_or(Duration::ZERO, |until| until.saturating_duration_since(now));
            if penalty.is_zero() {
                b.not_before = None;
            }
            if b.tokens >= 1.0 && penalty.is_zero() {
                b.tokens -= 1.0;
                return;
            }
            let needed = (1.0 - b.tokens).max(0.0) / self.max_per_sec;
            let wait = needed.max(penalty.as_secs_f64());
            drop(b);
            tokio::time::sleep(Duration::from_secs_f64(wait.max(0.001))).await;
        }
    }

    /// Cancellable variant: returns `false` when `cancel` fires before a
    /// token is acquired, `true` once the caller may proceed.
    ///
    /// The internal sleep is wrapped in `tokio::select!` so Ctrl+C aborts
    /// promptly instead of stalling for the full refill delay.
    pub async fn acquire_cancellable(&self, cancel: &CancellationToken) -> bool {
        if !self.max_per_sec.is_finite() {
            return !cancel.is_cancelled();
        }
        loop {
            if cancel.is_cancelled() {
                return false;
            }
            let wait = {
                let mut b = self.bucket.lock().await;
                let now = Instant::now();
                let elapsed = now.duration_since(b.last).as_secs_f64();
                b.tokens = (b.tokens + elapsed * self.max_per_sec).min(self.max_per_sec);
                b.last = now;
                let penalty = b
                    .not_before
                    .map_or(Duration::ZERO, |until| until.saturating_duration_since(now));
                if penalty.is_zero() {
                    b.not_before = None;
                }
                if b.tokens >= 1.0 && penalty.is_zero() {
                    b.tokens -= 1.0;
                    return true;
                }
                let needed = (1.0 - b.tokens).max(0.0) / self.max_per_sec;
                needed.max(penalty.as_secs_f64()).max(0.001)
            };
            tokio::select! {
                () = cancel.cancelled() => return false,
                () = tokio::time::sleep(Duration::from_secs_f64(wait)) => {},
            }
        }
    }

    #[must_use]
    pub fn disabled() -> Self {
        Self {
            max_per_sec: f64::INFINITY,
            bucket: Mutex::new(Bucket {
                tokens: f64::INFINITY,
                last: Instant::now(),
                not_before: None,
            }),
        }
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new(DEFAULT_RPS)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn retry_after_penalty_paces_next_acquire() {
        let rl = RateLimiter::new(20.0);
        rl.notify_rate_limited(Some(Duration::from_millis(300)))
            .await;
        let cancel = CancellationToken::new();
        let start = Instant::now();
        assert!(rl.acquire_cancellable(&cancel).await);
        assert!(
            start.elapsed() >= Duration::from_millis(250),
            "penalty must pace the next acquire, elapsed={:?}",
            start.elapsed()
        );
    }

    #[tokio::test]
    async fn penalty_is_capped_and_down_only() {
        let rl = RateLimiter::new(20.0);
        // Absurd server ask: capped at 60s, never infinite — assert the stored
        // penalty horizon stays within the cap without sleeping it out.
        rl.notify_rate_limited(Some(Duration::from_secs(3600)))
            .await;
        let remaining = rl.penalty_remaining().await;
        assert!(
            remaining <= Duration::from_secs(MAX_RETRY_AFTER_PENALTY_SECS),
            "penalty must be capped, remaining={remaining:?}"
        );
        assert!(!remaining.is_zero());
        // A later, smaller ask never extends an earlier larger horizon.
        rl.notify_rate_limited(Some(Duration::from_millis(10)))
            .await;
        let still = rl.penalty_remaining().await;
        assert!(
            still >= remaining.saturating_sub(Duration::from_millis(50)),
            "smaller ask must not shrink the horizon"
        );
    }

    #[tokio::test]
    async fn headerless_429_still_drains_burst() {
        let rl = RateLimiter::new(1.0);
        // Fresh bucket holds 1 token: first acquire is instant.
        let cancel = CancellationToken::new();
        assert!(rl.acquire_cancellable(&cancel).await);
        // Headerless notify drains without a time penalty: next acquire pays
        // one refill interval (~1s) instead of bursting.
        rl.notify_rate_limited(None).await;
        let start = Instant::now();
        assert!(rl.acquire_cancellable(&cancel).await);
        assert!(
            start.elapsed() >= Duration::from_millis(800),
            "drained bucket must refill, elapsed={:?}",
            start.elapsed()
        );
    }
}
