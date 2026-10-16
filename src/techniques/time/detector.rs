#![deny(unsafe_code)]

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct TimeResult {
    pub is_vulnerable: bool,
    pub confidence: f64,
    pub measured_ms: f64,
    pub expected_ms: f64,
}

#[derive(Debug, Default)]
pub struct TimeDetector {
    pub baseline_mean_ms: f64,
    pub baseline_stddev_ms: f64,
}

/// Sigmas above the baseline mean before a delay counts as anomalous.
const SIGMA_MULTIPLIER: f64 = 2.0;
/// Floor for the baseline stddev (ms) — ignores sub-100ms network jitter.
const STDDEV_FLOOR_MS: f64 = 100.0;
/// Required fraction of the expected sleep actually observed (anti-flake).
const MIN_SLEEP_FRACTION: f64 = 0.5;
/// Mean above which the sleep-fraction requirement relaxes (slow targets:
/// a full 50% extra delay is harsh when the baseline itself is seconds).
const SLOW_MEAN_THRESHOLD_MS: f64 = 3000.0;
/// Relaxed sleep fraction on slow targets (`mean > 3s`).
const MIN_SLEEP_FRACTION_SLOW: f64 = 0.3;
/// Robust-cutoff multiplier for baseline spike removal (P2.1).
///
/// Ported from sqlmap master (`lib/core/settings.py::TIME_OUTLIER_MAD_COEFF`,
/// value `10`): "crazy bias towards central values" — a sample must sit more
/// than ~15 raw MADs above the median to be trimmed.
const TIME_OUTLIER_MAD_COEFF: f64 = 10.0;
/// MAD → σ consistency constant for a normal distribution.
///
/// Applied exactly once, to the *raw* median absolute deviation, in
/// [`strip_time_outliers_ms`] — never pre-scaled, never applied twice.
const MAD_SIGMA_CONSISTENCY: f64 = 1.4826;

/// Adaptive stddev floor (Phase 3): `max(100ms, mean * 0.1)`.
///
/// Fast targets (`mean <= 1s`) keep the historical 100ms floor
/// byte-identical; slow targets tolerate proportional jitter (e.g. mean 5s
/// => floor 500ms => threshold `mean + 2*500`) instead of flagging every
/// ±200ms wobble as anomalous.
#[must_use]
pub fn adaptive_stddev_floor_ms(mean_ms: f64) -> f64 {
    if !mean_ms.is_finite() || mean_ms <= 0.0 {
        return STDDEV_FLOOR_MS;
    }
    STDDEV_FLOOR_MS.max(mean_ms * 0.1)
}

/// Adaptive sleep fraction (Phase 3): `0.5` by default, `0.3` when
/// `mean > 3s`.
///
/// On slow targets the absolute sleep delay is already large relative to
/// jitter, so requiring only 30% of the expected sleep keeps a 5s sleep on
/// a 5s-mean baseline detectable without waiting for a 7.5s response.
#[must_use]
pub fn adaptive_min_sleep_fraction(mean_ms: f64) -> f64 {
    if mean_ms.is_finite() && mean_ms > SLOW_MEAN_THRESHOLD_MS {
        MIN_SLEEP_FRACTION_SLOW
    } else {
        MIN_SLEEP_FRACTION
    }
}

/// Robust spike removal for time samples (P2.1), faithful port of sqlmap
/// master's `stripTimeOutliers` (`lib/core/common.py`, 2026).
///
/// A single network spike (GC pause, TCP retransmit, cold cache) landing in
/// the baseline model inflates both `mean` and `stddev`, which explodes the
/// anomaly bar (`mean + 2σ` here, `avg + 7σ` in sqlmap) and hides every
/// genuine delay behind it. The median/MAD pair is robust to a minority of
/// outliers, so the cutoff is computed from the clean bulk:
///
/// * `values.len() < 2` → returned unchanged (nothing to compare against);
/// * `median = sorted[len / 2]` (upper median on even counts, identical to
///   sqlmap's index-based `getMedian`-free form);
/// * `mad = median(|x − median|)` — the **raw** deviation, *not* pre-scaled;
/// * `mad <= 0` → unchanged (degenerate near-constant model: nothing robust
///   to trim on);
/// * `cutoff = median + mad_coeff * 1.4826 * mad` — the 1.4826 consistency
///   constant is applied exactly once, to the raw MAD (`sqlmap`:
///   `median + TIME_OUTLIER_MAD_COEFF * 1.4826 * mad`);
/// * values `> cutoff` are dropped, but never more than half the sample
///   (sqlmap's "never trim away the bulk" guard, kept verbatim — defensive
///   by construction since at least half the values sit within one raw MAD
///   of the median; it also protects any caller pairing a non-zero
///   `mad_coeff` with a wide/bimodal model).
///
/// On a clean model no value exceeds `median + 10 * 1.4826 * MAD`, so the
/// input is returned untouched (sqlmap docstring parity): the historical
/// mean/stddev/threshold stay byte-identical.
#[must_use]
pub fn strip_time_outliers_ms(values: &[f64], mad_coeff: f64) -> Vec<f64> {
    if values.len() < 2 {
        return values.to_vec();
    }
    let mut ordered = values.to_vec();
    ordered.sort_by(f64::total_cmp);
    let median = ordered[ordered.len() / 2];
    let mut deviations: Vec<f64> = values.iter().map(|v| (v - median).abs()).collect();
    deviations.sort_by(f64::total_cmp);
    let mad = deviations[deviations.len() / 2];
    if mad <= 0.0 {
        return values.to_vec();
    }
    let cutoff = median + mad_coeff * MAD_SIGMA_CONSISTENCY * mad;
    let kept: Vec<f64> = values.iter().copied().filter(|v| *v <= cutoff).collect();
    if kept.len() < values.len() / 2 {
        values.to_vec()
    } else {
        kept
    }
}

/// Byte-varied twin of a time probe payload for the *second* (confirmation)
/// shot: the SQL comment `/*xxxxxxxx*/` (8 random hex chars drawn from the
/// run RNG) is prefixed to `payload`.
///
/// Why: a reverse proxy / CDN keyed on the full URL or request bytes can
/// answer the byte-identical second probe from its cache, replaying the first
/// response *and its timing* — the double-shot then "confirms" a cache hit
/// instead of a second network round-trip (Invicti 2024: caching skews
/// time-based tests). Varying the bytes forces a fresh origin fetch while
/// keeping the first shot and the benign control untouched (no extra
/// requests, no coverage loss).
///
/// Why a comment: `/*…*/` is valid C-style SQL whitespace on every targeted
/// DBMS (MySQL, PostgreSQL, MSSQL, Oracle, SQLite). Prefixed to an expression
/// it is semantically a no-op, so the payload core after the comment is
/// byte-identical — including payloads starting with `'`, where the comment
/// lands inside the surrounding string literal (harmless) and the quote still
/// closes it exactly as before. Coverage is never reduced.
///
/// The token comes from the seeded RNG (`crate::seeded_rng::make_rng`), so
/// `--seed` runs stay deterministic.
#[must_use]
pub fn cache_variant(payload: &str, rng: &mut impl rand::Rng) -> String {
    let token: u32 = rng.random();
    format!("/*{token:08x}*/{payload}")
}

impl TimeDetector {
    #[must_use]
    pub fn new(mean: f64, stddev: f64) -> Self {
        Self {
            baseline_mean_ms: mean,
            baseline_stddev_ms: stddev,
        }
    }

    /// Build from an existing [`crate::detection::baseline::Baseline`].
    ///
    /// Robust moments (P2.1): the raw per-sample durations
    /// ([`crate::detection::baseline::Baseline::durations`], filled at
    /// collection time by `Baseline::new` — see `collect_baseline`) are passed
    /// through [`strip_time_outliers_ms`] with `TIME_OUTLIER_MAD_COEFF` (10,
    /// same as sqlmap master) *before* the mean/stddev are recomputed (same
    /// Bessel-corrected formulas as `Baseline::new`, so clean samples stay
    /// byte-identical). One spike among the 3-5 baseline samples no longer
    /// inflates both moments and explodes the delay bar; MAD trims it from the
    /// clean bulk. sqlmap's own `stripTimeOutliers` only trims from 15 samples
    /// up (`MIN_TIME_RESPONSES // 2` of its 30-measurement model); we keep the
    /// same robust stats on a 3-sample baseline (documented conservative
    /// deviation: trimming makes the bar tighter, and the min-sleep-fraction
    /// gate, double-shot and benign control still stand between jitter and a
    /// finding).
    ///
    /// Reuses the baseline's mean/stddev so the time threshold stays
    /// consistent with [`crate::detection::baseline::Baseline::threshold_ms`]
    /// at `sigma = 2.0` on fast targets (same floor of 100ms, same
    /// multiplier). On slow targets (`mean > 1s`) the adaptive floor
    /// `max(100ms, mean*0.1)` widens the threshold proportionally.
    ///
    /// PR20 divergence (intentional, documented): `Baseline::threshold_ms`
    /// keeps the static 100ms floor for generic fast differentials, while
    /// this detector widens on slow targets (mean 5s: 6000 here vs 5200
    /// there). A sleep probe on a 5s-mean target must tolerate ±200ms
    /// wobble without flagging it as `SQLi`; the relaxed
    /// `adaptive_min_sleep_fraction` (0.3 above 3s mean) pairs with it so a
    /// real 5s sleep (`~10s` measured) still confirms. Fast targets
    /// (`mean <= 1s`) stay byte-identical (`from_baseline_matches_threshold_ms`).
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn from_baseline(baseline: &crate::detection::baseline::Baseline) -> Self {
        // Imported/hand-built baselines may carry the moments without the raw
        // durations (`durations` is RAM-only sampling data): fall back to the
        // stored moments rather than degrading to zeros.
        if baseline.durations.is_empty() {
            return Self::new(baseline.mean_ms, baseline.stddev_ms);
        }
        let raw: Vec<f64> = baseline
            .durations
            .iter()
            .map(|d| d.as_secs_f64() * 1000.0)
            .collect();
        let clean = strip_time_outliers_ms(&raw, TIME_OUTLIER_MAD_COEFF);
        // `strip_time_outliers_ms` never empties a non-empty input; the guard
        // keeps a hypothetical future edit from dividing by zero.
        if clean.is_empty() {
            return Self::new(baseline.mean_ms, baseline.stddev_ms);
        }
        let mean = clean.iter().sum::<f64>() / clean.len() as f64;
        let variance = if clean.len() < 2 {
            0.0
        } else {
            clean.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / (clean.len() - 1) as f64
        };
        Self::new(mean, variance.sqrt())
    }

    /// Anomaly bar for sleep probes: `mean + 2 * max(stddev, adaptive floor)`.
    /// See [`Self::from_baseline`] for the intentional divergence from
    /// [`crate::detection::baseline::Baseline::threshold_ms`] on slow targets.
    #[must_use]
    pub fn threshold(&self) -> f64 {
        self.baseline_mean_ms
            + SIGMA_MULTIPLIER
                * self
                    .baseline_stddev_ms
                    .max(adaptive_stddev_floor_ms(self.baseline_mean_ms))
    }

    #[must_use]
    pub fn evaluate(&self, measured_ms: f64, expected_sleep_secs: f64) -> TimeResult {
        let expected = expected_sleep_secs * 1000.0 + self.baseline_mean_ms;
        let threshold = self.threshold();
        let min_fraction = adaptive_min_sleep_fraction(self.baseline_mean_ms);
        let is_vuln = measured_ms > threshold
            && (measured_ms - self.baseline_mean_ms) > expected_sleep_secs * 1000.0 * min_fraction;
        let confidence = if is_vuln {
            let ratio = ((measured_ms - self.baseline_mean_ms) / (expected_sleep_secs * 1000.0))
                .clamp(0.0, 1.5);
            (0.6 + ratio * 0.3).clamp(0.0, 1.0)
        } else {
            0.1
        };
        TimeResult {
            is_vulnerable: is_vuln,
            confidence,
            measured_ms,
            expected_ms: expected,
        }
    }

    /// Two-shot confirmation against network jitter: both shots must
    /// independently exceed [`Self::threshold`] (via [`Self::evaluate`]).
    /// A single slow response (hiccup, GC pause, WAF throttle) never
    /// confirms. Reported `measured_ms` is the mean of both shots and
    /// confidence is re-derived from that mean, so callers keep a single
    /// calibrated score.
    #[must_use]
    pub fn evaluate_confirmed(
        &self,
        first_ms: f64,
        second_ms: f64,
        expected_sleep_secs: f64,
    ) -> TimeResult {
        let first = self.evaluate(first_ms, expected_sleep_secs);
        let second = self.evaluate(second_ms, expected_sleep_secs);
        if first.is_vulnerable && second.is_vulnerable {
            self.evaluate(first_ms.midpoint(second_ms), expected_sleep_secs)
        } else {
            // Negative: report the weaker shot so evidence shows the miss.
            let weaker = first_ms.min(second_ms);
            let mut r = self.evaluate(weaker, expected_sleep_secs);
            r.is_vulnerable = false;
            r.confidence = 0.1;
            r.measured_ms = weaker;
            r
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detection::baseline::{Baseline, Sample};
    use std::time::Duration;

    fn baseline(mean_ms: u64) -> Baseline {
        let samples = vec![
            Sample {
                status: 200,
                body: b"ok".to_vec(),
                duration: Duration::from_millis(mean_ms),
                headers: Vec::new(),
            },
            Sample {
                status: 200,
                body: b"ok".to_vec(),
                duration: Duration::from_millis(mean_ms),
                headers: Vec::new(),
            },
            Sample {
                status: 200,
                body: b"ok".to_vec(),
                duration: Duration::from_millis(mean_ms),
                headers: Vec::new(),
            },
        ];
        Baseline::new(&samples)
    }

    fn durations_baseline(ms: &[u64]) -> Baseline {
        let samples = ms
            .iter()
            .map(|m| Sample {
                status: 200,
                body: b"ok".to_vec(),
                duration: Duration::from_millis(*m),
                headers: Vec::new(),
            })
            .collect::<Vec<_>>();
        Baseline::new(&samples)
    }

    #[test]
    fn from_baseline_matches_threshold_ms() {
        let bl = baseline(100);
        let det = TimeDetector::from_baseline(&bl);
        assert!((det.baseline_mean_ms - bl.mean_ms).abs() < f64::EPSILON);
        assert!((det.baseline_stddev_ms - bl.stddev_ms).abs() < f64::EPSILON);
        // Same formula: mean + 2 * max(stddev, 100).
        assert!((det.threshold() - bl.threshold_ms(2.0)).abs() < f64::EPSILON);
    }

    #[test]
    fn single_shot_detects_sleep() {
        let det = TimeDetector::new(100.0, 10.0);
        let r = det.evaluate(3200.0, 3.0);
        assert!(r.is_vulnerable);
        assert!(r.confidence >= 0.6);
    }

    #[test]
    fn single_shot_rejects_baseline_jitter() {
        let det = TimeDetector::new(100.0, 10.0);
        let r = det.evaluate(150.0, 3.0);
        assert!(!r.is_vulnerable);
    }

    #[test]
    fn confirmed_requires_both_shots() {
        let det = TimeDetector::new(100.0, 10.0);
        let ok = det.evaluate_confirmed(3200.0, 3300.0, 3.0);
        assert!(ok.is_vulnerable);
        let flaky = det.evaluate_confirmed(3200.0, 120.0, 3.0);
        assert!(!flaky.is_vulnerable);
        assert!((flaky.confidence - 0.1).abs() < f64::EPSILON);
    }

    #[test]
    fn confirmed_reports_mean() {
        let det = TimeDetector::new(100.0, 10.0);
        let r = det.evaluate_confirmed(3000.0, 3400.0, 3.0);
        assert!(r.is_vulnerable);
        assert!((r.measured_ms - 3200.0).abs() < f64::EPSILON);
    }

    #[test]
    fn adaptive_floor_stays_static_on_fast_targets() {
        // L1 byte-identical: mean <= 1s => floor 100ms.
        assert!((adaptive_stddev_floor_ms(100.0) - 100.0).abs() < f64::EPSILON);
        assert!((adaptive_stddev_floor_ms(1000.0) - 100.0).abs() < f64::EPSILON);
        assert!((adaptive_min_sleep_fraction(100.0) - 0.5).abs() < f64::EPSILON);
        let det = TimeDetector::new(100.0, 10.0);
        assert!((det.threshold() - 300.0).abs() < f64::EPSILON);
    }

    #[test]
    fn adaptive_floor_scales_on_slow_targets() {
        // mean 5s => floor max(100, 500) = 500, threshold 5000 + 2*500 = 6000.
        assert!((adaptive_stddev_floor_ms(5000.0) - 500.0).abs() < f64::EPSILON);
        assert!((adaptive_min_sleep_fraction(5000.0) - 0.3).abs() < f64::EPSILON);
        let det = TimeDetector::new(5000.0, 10.0);
        assert!((det.threshold() - 6000.0).abs() < f64::EPSILON);
    }

    #[test]
    fn slow_baseline_sleep_stays_detectable() {
        // Phase 3: mean 5s, sleep 5s => measured ~10s must confirm.
        let det = TimeDetector::new(5000.0, 50.0);
        let r = det.evaluate(10_000.0, 5.0);
        assert!(r.is_vulnerable, "5s sleep on 5s mean must detect");
        assert!(r.confidence >= 0.6);
        // Jitter just under threshold must not flag.
        let jitter = det.evaluate(5500.0, 5.0);
        assert!(!jitter.is_vulnerable);
        // Two-shot confirmation holds on slow targets too.
        let ok = det.evaluate_confirmed(10_000.0, 10_200.0, 5.0);
        assert!(ok.is_vulnerable);
    }

    #[test]
    fn strip_outliers_drops_single_hiccup() {
        let out = strip_time_outliers_ms(&[100.0, 110.0, 105.0, 5000.0], 10.0);
        assert_eq!(out.len(), 3);
        assert!(
            !out.iter().any(|v| *v > 1000.0),
            "lone 5s hiccup must be trimmed: {out:?}"
        );
        assert!(out.contains(&100.0) && out.contains(&110.0) && out.contains(&105.0));
    }

    #[test]
    fn strip_outliers_keeps_clean_models_untouched() {
        // Clean model: no value exceeds median + 10 * MAD (sqlmap docstring
        // parity), so the input is returned byte-identical.
        let clean = [100.0, 110.0, 105.0];
        assert_eq!(strip_time_outliers_ms(&clean, 10.0), clean);
        // Constant model: MAD == 0 -> degenerate, returned as-is.
        let constant = [42.0; 5];
        assert_eq!(strip_time_outliers_ms(&constant, 10.0), constant);
    }

    #[test]
    fn strip_outliers_never_guts_half_the_sample() {
        // Wide/bimodal models: whatever the cutoff, at least half the sample
        // survives (anti-gutting guard).
        for values in [
            vec![50.0, 50.0, 50.0, 1000.0, 1000.0],
            vec![10.0, 10.0, 1000.0, 1000.0],
            vec![1.0, 2.0, 3.0, 4000.0, 9000.0],
        ] {
            let out = strip_time_outliers_ms(&values, 10.0);
            assert!(
                out.len() >= values.len() / 2,
                "trimmed below half: {values:?} -> {out:?}"
            );
        }
    }

    #[test]
    fn strip_outliers_handles_empty_and_single() {
        assert!(strip_time_outliers_ms(&[], 10.0).is_empty());
        assert_eq!(strip_time_outliers_ms(&[1000.0], 10.0), vec![1000.0]);
    }

    #[test]
    fn from_baseline_ignores_single_polluted_sample() {
        // One 5s hiccup among two ~100ms samples. Historical (raw) moments:
        // mean ~1737ms, stddev ~2822ms -> threshold ~7.4s, hiding a real 3s
        // sleep. The robust model stays tight instead.
        let bl = durations_baseline(&[100, 110, 5000]);
        let detector = TimeDetector::from_baseline(&bl);
        assert!(
            detector.baseline_mean_ms < 200.0,
            "robust mean must not absorb the spike: {}",
            detector.baseline_mean_ms
        );
        assert!(
            detector.baseline_mean_ms < bl.mean_ms,
            "robust mean {} must sit below raw baseline mean {}",
            detector.baseline_mean_ms,
            bl.mean_ms
        );
        assert!(
            detector.threshold() < 500.0,
            "robust threshold must stay under 500ms, got {}",
            detector.threshold()
        );
        // A real 3s sleep is still detected against the tight bar...
        let real_sleep = detector.evaluate(3300.0, 3.0);
        assert!(
            real_sleep.is_vulnerable,
            "robust threshold must keep a real 3s sleep detectable"
        );
        // ... while a hiccup below the sleep fraction is still rejected.
        assert!(!detector.evaluate(400.0, 3.0).is_vulnerable);
    }

    #[test]
    fn from_baseline_clean_samples_match_raw_moments() {
        // Non-constant but outlier-free samples: no trimming, byte-identical
        // moments (the robust path must not perturb the historical model).
        let bl = durations_baseline(&[100, 110, 105]);
        let detector = TimeDetector::from_baseline(&bl);
        assert!((detector.baseline_mean_ms - bl.mean_ms).abs() < f64::EPSILON);
        assert!((detector.baseline_stddev_ms - bl.stddev_ms).abs() < f64::EPSILON);
    }

    #[test]
    fn cache_variant_preserves_payload_core() {
        let payload = "' AND SLEEP(3) -- -";
        let mut rng = crate::seeded_rng::make_rng(Some(42));
        let variant = cache_variant(payload, &mut rng);
        let inner = variant
            .strip_prefix("/*")
            .and_then(|rest| rest.split_once("*/"));
        let Some((token, core)) = inner else {
            panic!("variant must be prefixed by a /*…*/ comment: {variant}");
        };
        assert_eq!(token.len(), 8, "8 hex chars expected: {token}");
        assert!(token.chars().all(|c| c.is_ascii_hexdigit()), "{token}");
        assert_eq!(core, payload, "SQL after the comment must stay identical");
    }

    #[test]
    fn cache_variant_bytes_differ_and_stay_seeded() {
        let payload = "'; SELECT pg_sleep(3) --";
        let build = |seed: u64| {
            let mut rng = crate::seeded_rng::make_rng(Some(seed));
            cache_variant(payload, &mut rng)
        };
        let one = build(7);
        let two = build(7);
        let three = build(8);
        assert_ne!(one, payload, "second shot must not replay identical bytes");
        assert!(one.ends_with(payload));
        assert_eq!(one, two, "same seed -> same variant");
        assert_ne!(one, three, "different seeds -> different variant");
    }
}
