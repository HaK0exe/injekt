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
    assert_eq!(strip_time_outliers_ms(&[], 10.0), [] as [f64; 0]);
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
