#![deny(unsafe_code)]

use sha2::{Digest, Sha256};
use std::time::Duration;

/// Statuses counted as WAF blocks for [`Baseline::is_waf_blocked`].
const WAF_BLOCK_STATUSES: [u16; 2] = [403, 406];
/// Minimum block count across baseline samples before calling it a WAF.
const MIN_WAF_BLOCKS: usize = 2;

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Baseline {
    pub status_codes: Vec<u16>,
    pub body_hashes: Vec<String>,
    pub body_lengths: Vec<usize>,
    pub durations: Vec<Duration>,
    pub mean_ms: f64,
    pub stddev_ms: f64,
    pub representative_body: Vec<u8>,
    /// WAF/CDN vendor observed across samples (`"cloudflare"`, …), if any.
    pub waf_vendor: Option<String>,
    /// Signal names that fired (header/body markers, never values).
    pub waf_hits: Vec<String>,
    /// `true` when a *blocking* signal (challenge/deny/rate-limit) was seen
    /// in any sample. Mere CDN presence (`cf-ray` alone) records
    /// `waf_vendor`/`waf_hits` but leaves this `false`.
    pub waf_blocking: bool,
}

impl Baseline {
    #[must_use]
    // Sample counts are small (single-digit baseline probes); usize->f64 precision loss is not reachable.
    #[allow(clippy::cast_precision_loss)]
    pub fn new(samples: &[Sample]) -> Self {
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
            // Bessel's correction for sample variance (n-1) more accurate for n=3..5
            ms.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / (ms.len() - 1) as f64
        };
        let stddev = var.sqrt();
        let representative_body = if samples.is_empty() {
            Vec::new()
        } else {
            // Median by length (robust against outliers), fallback to most common hash
            let mut sorted = samples.to_vec();
            sorted.sort_by_key(|s| s.body.len());
            sorted[sorted.len() / 2].body.clone()
        };
        // Aggregate WAF signals across samples (headers + body per sample).
        // `Cloudflare` wins over `Generic` when both appear; hits are
        // deduplicated in first-seen order; blocking sticks if any sample
        // blocked.
        let mut waf_vendor: Option<String> = None;
        let mut waf_hits: Vec<String> = Vec::new();
        let mut waf_blocking = false;
        for sample in samples {
            let signals =
                super::waf::detect_cloudflare_flat(sample.status, &sample.headers, &sample.body);
            if let Some(vendor) = signals.vendor {
                let label = vendor.to_string();
                match &waf_vendor {
                    None => waf_vendor = Some(label),
                    Some(current) if current == "generic" && label != "generic" => {
                        waf_vendor = Some(label);
                    }
                    _ => {}
                }
                for hit in &signals.hits {
                    if !waf_hits.contains(hit) {
                        waf_hits.push(hit.clone());
                    }
                }
            }
            waf_blocking = waf_blocking || signals.blocking;
        }
        Self {
            status_codes,
            body_hashes,
            body_lengths,
            durations,
            mean_ms: mean,
            stddev_ms: stddev,
            representative_body,
            waf_vendor,
            waf_hits,
            waf_blocking,
        }
    }

    fn hash(body: &[u8]) -> String {
        let mut h = Sha256::new();
        h.update(body);
        hex::encode(h.finalize())
    }

    #[must_use]
    pub fn threshold_ms(&self, sigma: f64) -> f64 {
        // Unified floor 100ms per 2026 audit (time detector uses 100)
        self.mean_ms + sigma * self.stddev_ms.max(100.0)
    }

    #[must_use]
    pub fn representative_body_str(&self) -> String {
        String::from_utf8_lossy(&self.representative_body).into_owned()
    }

    #[must_use]
    pub fn is_waf_blocked(&self) -> bool {
        let blocked = self
            .status_codes
            .iter()
            .filter(|c| WAF_BLOCK_STATUSES.contains(c))
            .count();
        blocked >= MIN_WAF_BLOCKS
    }

    /// Any WAF/CDN presence (headers or challenge markers observed).
    /// Drives the informational warn + light auto-tamper.
    #[must_use]
    pub const fn is_waf_suspected(&self) -> bool {
        self.waf_vendor.is_some()
    }

    /// A *blocking* signal (challenge/deny/rate-limit) was observed.
    /// Drives finding confidence downgrade (see `waf::downgrade_for_waf`).
    #[must_use]
    pub const fn is_waf_blocking(&self) -> bool {
        self.waf_blocking
    }

    /// Short evidence fragment (`" waf=cloudflare:… blocking=…"`) or `""`
    /// when nothing was detected. Appended to finding evidence strings.
    #[must_use]
    pub fn waf_evidence_suffix(&self) -> String {
        let Some(vendor) = self.waf_vendor.as_deref() else {
            return String::new();
        };
        format!(
            " waf={}:{} blocking={}",
            vendor,
            self.waf_hits.join(","),
            self.waf_blocking
        )
    }
}

#[derive(Debug, Clone)]
pub struct Sample {
    pub status: u16,
    pub body: Vec<u8>,
    pub duration: Duration,
    /// Response headers as `(lowercased-name, value-prefix ≤128 chars)`.
    /// Values are truncated at collection time (OPSEC: bounds retention of
    /// `Set-Cookie` tokens in RAM); detection only needs `contains` on
    /// markers such as `__cf_bm`.
    pub headers: Vec<(String, String)>,
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
    Baseline::new(&samples)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(status: u16, body: &[u8], headers: &[(&str, &str)]) -> Sample {
        Sample {
            status,
            body: body.to_vec(),
            duration: Duration::from_millis(50),
            headers: headers
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
        }
    }

    #[test]
    fn baseline_without_signals_is_clean() {
        let samples = vec![
            sample(200, b"<html>hello</html>", &[]),
            sample(200, b"<html>hello</html>", &[]),
            sample(200, b"<html>hello</html>", &[]),
        ];
        let bl = Baseline::new(&samples);
        assert!(!bl.is_waf_blocked());
        assert!(!bl.is_waf_suspected());
        assert!(!bl.is_waf_blocking());
        assert_eq!(bl.waf_evidence_suffix(), "");
    }

    #[test]
    fn baseline_propagates_cf_presence_without_blocking() {
        let headers = [("cf-ray", "abc-IAD"), ("server", "cloudflare")];
        let samples = vec![
            sample(200, b"<html>hello</html>", &headers),
            sample(200, b"<html>hello</html>", &headers),
            sample(200, b"<html>hello</html>", &headers),
        ];
        let bl = Baseline::new(&samples);
        assert!(!bl.is_waf_blocked());
        assert!(bl.is_waf_suspected());
        assert!(
            !bl.is_waf_blocking(),
            "mere CDN presence must not downgrade"
        );
        assert_eq!(bl.waf_vendor.as_deref(), Some("cloudflare"));
        assert!(bl.waf_evidence_suffix().contains("waf=cloudflare:"));
    }

    #[test]
    fn baseline_blocking_challenge_propagates() {
        let headers = [("cf-ray", "abc-IAD")];
        let body = b"<html><title>Just a moment...</title>managed challenge</html>";
        let samples = vec![
            sample(200, body, &headers),
            sample(200, body, &headers),
            sample(200, body, &headers),
        ];
        let bl = Baseline::new(&samples);
        assert!(bl.is_waf_suspected());
        assert!(bl.is_waf_blocking());
        assert!(bl.waf_evidence_suffix().contains("blocking=true"));
    }
}
