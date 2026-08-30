#![deny(unsafe_code)]

use std::time::{Duration, Instant};
use tokio::sync::Mutex;

/// Token-bucket rate limiter.
#[derive(Debug)]
#[non_exhaustive]
pub struct RateLimiter {
    max_per_sec: f64,
    bucket: Mutex<Bucket>,
}

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
        Self::new(10.0)
    }
}
