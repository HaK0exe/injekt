#![deny(unsafe_code)]

use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

/// Token-bucket rate limiter.
///
/// Note on pacing: [`HttpClient::send_with_retry`] awaits `acquire()` and
/// then the jitter sleep back-to-back, so per-request pacing is additive
/// (`rate-limit wait` + `jitter wait`), not `max()` of the two. Lower both
/// knobs together to speed up scans; raising only one leaves the other.
#[derive(Debug)]
#[non_exhaustive]
pub struct RateLimiter {
    max_per_sec: f64,
    bucket: Mutex<Bucket>,
}

/// Single default request rate (req/s) shared by [`RateLimiter::default`]
/// and the [`HttpClient`] fallback when no limiter is injected.
pub const DEFAULT_RPS: f64 = 10.0;

#[derive(Debug)]
struct Bucket {
    tokens: f64,
    last: Instant,
}

impl RateLimiter {
    #[must_use]
    pub fn new(requests_per_sec: f64) -> Self {
        Self {
            max_per_sec: requests_per_sec.max(0.1),
            bucket: Mutex::new(Bucket {
                tokens: requests_per_sec,
                last: Instant::now(),
            }),
        }
    }

    pub async fn acquire(&self) {
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
            if b.tokens >= 1.0 {
                b.tokens -= 1.0;
                return;
            }
            let needed = (1.0 - b.tokens) / self.max_per_sec;
            drop(b);
            tokio::time::sleep(Duration::from_secs_f64(needed)).await;
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
                if b.tokens >= 1.0 {
                    b.tokens -= 1.0;
                    return true;
                }
                (1.0 - b.tokens) / self.max_per_sec
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
            }),
        }
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new(DEFAULT_RPS)
    }
}
