#![deny(unsafe_code)]

use sha2::{Digest, Sha256};
use std::time::Duration;

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Baseline {
    pub status_codes: Vec<u16>,
    pub body_hashes: Vec<String>,
    pub body_lengths: Vec<usize>,
    pub durations: Vec<Duration>,
    pub mean_ms: f64,
    pub stddev_ms: f64,
}

impl Baseline {
    #[must_use]
    pub fn new(samples: Vec<Sample>) -> Self {
        let status_codes = samples.iter().map(|s| s.status).collect();
        let body_hashes = samples.iter().map(|s| Self::hash(&s.body)).collect();
        let body_lengths = samples.iter().map(|s| s.body.len()).collect();
        let durations = samples.iter().map(|s| s.duration).collect();
        let ms: Vec<f64> = samples
            .iter()
            .map(|s| s.duration.as_secs_f64() * 1000.0)
            .collect();
        let mean = if ms.is_empty() {
            0.0
        } else {
            ms.iter().sum::<f64>() / ms.len() as f64
        };
        let var = if ms.len() < 2 {
            0.0
        } else {
            ms.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / ms.len() as f64
        };
        let stddev = var.sqrt();
        Self {
            status_codes,
            body_hashes,
            body_lengths,
            durations,
            mean_ms: mean,
            stddev_ms: stddev,
        }
    }

    fn hash(body: &[u8]) -> String {
        let mut h = Sha256::new();
        h.update(body);
        hex::encode(h.finalize())
    }

    #[must_use]
    pub fn threshold_ms(&self, sigma: f64) -> f64 {
        self.mean_ms + sigma * self.stddev_ms.max(50.0)
    }

    #[must_use]
    pub fn is_waf_blocked(&self) -> bool {
        let blocked = self
            .status_codes
            .iter()
            .filter(|c| **c == 403 || **c == 406)
            .count();
        blocked >= 2
    }
}

#[derive(Debug, Clone)]
pub struct Sample {
    pub status: u16,
    pub body: Vec<u8>,
    pub duration: Duration,
}

/// Collect 3-5 baseline samples via client.
pub async fn collect_baseline<F, Fut>(mut fetcher: F, count: usize) -> Baseline
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Sample>,
{
    let mut samples = Vec::new();
    let n = count.clamp(3, 5);
    for _ in 0..n {
        samples.push(fetcher().await);
    }
    Baseline::new(samples)
}
