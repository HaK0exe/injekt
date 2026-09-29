#![deny(unsafe_code)]

use sha2::{Digest, Sha256};
use std::time::Duration;

/// Statuses counted as WAF blocks for [`Baseline::is_waf_blocked`].
/// `403`/`406` are classic deny/challenge codes; `429` is throttling (the
/// `is_waf_blocking` signal path corroborates it via headers/body markers).
/// `5xx` deliberately excluded: origin errors on a down target must not
/// trigger bypass tampers.
const WAF_BLOCK_STATUSES: [u16; 3] = [403, 406, 429];
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
        // A specific vendor wins over `Generic` when both appear; hits are
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
        // Unified floor 100ms per 2026 audit (time detector uses 100).
        // PR20 divergence note: this static floor is intentional for generic
        // (fast-differential) use. `TimeDetector::threshold` reuses the same
        // mean/stddev via `from_baseline` but swaps the floor for
        // `adaptive_stddev_floor_ms` (`max(100ms, mean*0.1)`): byte-identical
        // below/at 1s mean, proportionally wider above (e.g. mean 5s →
        // threshold 6000 vs 5200 here). Rationale: on slow targets a static
        // 100ms floor flags every ±200ms wobble as anomalous for sleep
        // probes, while boolean/error differentials still want the tight
        // static bar — so the time channel alone adapts, this helper stays
        // put.
        self.mean_ms + sigma * self.stddev_ms.max(100.0)
    }

    #[must_use]
    pub fn representative_body_str(&self) -> String {
        String::from_utf8_lossy(&self.representative_body).into_owned()
    }

    /// Returns whether the samples are stable enough to be used as an oracle.
    ///
    /// A differential detector cannot distinguish injection from application
    /// noise when the baseline itself changes between requests.  Status
    /// consistency is required, then the median pairwise body agreement is
    /// checked. The baseline stores hashes rather than raw samples, so this
    /// gate intentionally fails closed for changing bodies; dynamic-field
    /// normalization belongs to the later response-diff stage.
    /// This is deliberately conservative: callers should report an
    /// inconclusive scan rather than manufacture a finding from an unstable
    /// page.
    #[must_use]
    pub fn is_stable(&self) -> bool {
        if self.status_codes.len() < 3 || self.body_hashes.len() < 3 {
            return false;
        }
        if self.status_codes.windows(2).any(|pair| pair[0] != pair[1]) {
            return false;
        }
        let bodies: Vec<String> = self
            .body_hashes
            .iter()
            .zip(self.body_lengths.iter())
            .map(|(hash, length)| format!("{hash}:{length}"))
            .collect();
        // Exact hashes are a cheap fast path. A changing body cannot be
        // safely normalized here because raw baseline samples are not kept.
        if bodies.iter().all(|body| body == &bodies[0]) {
            return true;
        }
        let mut similarities = Vec::new();
        for (idx, left) in self.body_hashes.iter().enumerate() {
            for (right_idx, right) in self.body_hashes.iter().enumerate().skip(idx + 1) {
                if left == right && self.body_lengths[idx] == self.body_lengths[right_idx] {
                    similarities.push(1.0);
                } else {
                    // Hashes intentionally do not retain bodies.  A body that
                    // differs cannot be safely normalized here, so it is
                    // treated as unstable; this keeps the gate fail-closed.
                    similarities.push(0.0);
                }
            }
        }
        similarities.sort_by(f64::total_cmp);
        similarities[similarities.len() / 2] >= 0.8
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

    /// Merge a request/response Content-Type mismatch signal (P0-4) into the
    /// aggregate: the caller sent an API payload (`expected_ct`, e.g.
    /// `application/json` from `--raw-file`) but a sample answered with a
    /// different document kind (typically `text/html` — a challenge/deny
    /// page intercepted the call).
    ///
    /// A mismatch alone is presence-level (`Generic`, `blocking=false` —
    /// informational, never auto-tamper/downgrade by itself); it turns
    /// `blocking` only together with a corroborating status on a mismatching
    /// sample, mirroring the marker+status contract in
    /// [`super::waf::detect_cloudflare_flat`]. No-op when `expected_ct` is
    /// not an API kind or every sample agrees (see
    /// [`super::waf::ct_mismatch_hit`]).
    pub fn apply_ct_mismatch(&mut self, samples: &[Sample], expected_ct: &str) {
        let mut blocking = false;
        for sample in samples {
            let Some(hit) = super::waf::ct_mismatch_hit(expected_ct, &sample.headers) else {
                continue;
            };
            if !self.waf_hits.contains(&hit) {
                self.waf_hits.push(hit);
            }
            if super::waf::is_coroborating_status(sample.status) {
                blocking = true;
            }
        }
        if self.waf_hits.iter().any(|h| h.starts_with("ct-mismatch:")) {
            if self.waf_vendor.is_none() {
                self.waf_vendor = Some("generic".to_owned());
            }
            self.waf_blocking = self.waf_blocking || blocking;
        }
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
    fn stable_requires_same_status_and_body() {
        let samples = vec![
            sample(200, b"same", &[]),
            sample(200, b"same", &[]),
            sample(200, b"same", &[]),
        ];
        assert!(Baseline::new(&samples).is_stable());

        let mut different_status = samples.clone();
        different_status[2].status = 302;
        assert!(!Baseline::new(&different_status).is_stable());

        let mut different_body = samples;
        different_body[2].body = b"different".to_vec();
        assert!(!Baseline::new(&different_body).is_stable());
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

    #[test]
    fn ct_mismatch_json_api_served_html_is_presence() {
        let headers = [("content-type", "text/html; charset=utf-8")];
        let samples = vec![
            sample(200, b"<html>ok</html>", &headers),
            sample(200, b"<html>ok</html>", &headers),
        ];
        let mut bl = Baseline::new(&samples);
        assert!(!bl.is_waf_suspected());
        bl.apply_ct_mismatch(&samples, "application/json");
        assert!(bl.is_waf_suspected());
        assert!(
            !bl.is_waf_blocking(),
            "mismatch alone must not block: {}",
            bl.waf_evidence_suffix()
        );
        assert_eq!(bl.waf_vendor.as_deref(), Some("generic"));
        assert!(
            bl.waf_hits
                .iter()
                .any(|h| h == "ct-mismatch:expected-json-got-html"),
            "{}",
            bl.waf_evidence_suffix()
        );
    }

    #[test]
    fn ct_mismatch_with_coroborating_status_blocks() {
        let headers = [("content-type", "text/html")];
        let samples = vec![sample(403, b"<html>denied</html>", &headers)];
        let mut bl = Baseline::new(&samples);
        bl.apply_ct_mismatch(&samples, "application/json");
        assert!(bl.is_waf_blocking(), "{}", bl.waf_evidence_suffix());
    }

    #[test]
    fn ct_mismatch_noop_when_kinds_agree() {
        let headers = [("content-type", "application/json")];
        let samples = vec![sample(200, b"{\"a\":1}", &headers)];
        let mut bl = Baseline::new(&samples);
        bl.apply_ct_mismatch(&samples, "application/json");
        assert!(!bl.is_waf_suspected());
        assert_eq!(bl.waf_evidence_suffix(), "");
        // Non-API expectations never flag.
        let html = [("content-type", "text/html")];
        let html_samples = vec![sample(200, b"<html>ok</html>", &html)];
        let mut bl2 = Baseline::new(&html_samples);
        bl2.apply_ct_mismatch(&html_samples, "text/html");
        assert!(!bl2.is_waf_suspected());
    }
}
