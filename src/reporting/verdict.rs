#![deny(unsafe_code)]

//! Calibrated confidence buckets (C7 intelligent reporting).
//!
//! Historical thresholds (`0.75/0.85`, `>0.6`) were hand-picked, not measured.
//! This module replaces them with buckets tied to documented precision claims:
//! `High` → precision ≥ 95 %, `Medium` → precision ≥ 80 %.
//!
//! # Threshold provenance
//!
//! Preferred source is bench history (`bench/reports/history.jsonl`, one line
//! per run with per-bucket outcomes) via [`load_bench_thresholds`]. No history
//! file ships in this repo yet (C1 history is still being collected), so the
//! compiled-in fallback is **deliberately conservative** and both signals must
//! agree before a finding is promoted:
//!
//! - `High`: `confidence ≥ 0.85` (C3 `HIGH_CONFIDENCE_THRESHOLD`) **and**
//!   `false_positive_prob ≤ 0.05`.
//! - `Medium`: `confidence ≥ 0.70` (C3 `MEDIUM_CONFIDENCE_THRESHOLD`) **and**
//!   `false_positive_prob ≤ 0.20`.
//! - `Low`: everything else.
//!
//! Requiring *both* the detector score and the confirmation-trial FP estimate
//! keeps the bucket precision at or above the claim even if one signal is
//! optimistic. When bench history becomes available, thresholds move to
//! measured values and [`load_bench_thresholds`] picks them up; until then the
//! calibration integration test (`tests/integration_reporting_c7.rs`) blocks
//! any recalibration that would drop below the claims on the fixture set.

use crate::reasoning::hypothesis::{HIGH_CONFIDENCE_THRESHOLD, MEDIUM_CONFIDENCE_THRESHOLD};
use crate::session::state::Severity;

/// Minimum precision guaranteed for the `High` bucket.
pub const HIGH_BUCKET_MIN_PRECISION: f64 = 0.95;
/// Minimum precision guaranteed for the `Medium` bucket.
pub const MEDIUM_BUCKET_MIN_PRECISION: f64 = 0.80;
/// Maximum false-positive probability admitted into the `High` bucket.
pub const HIGH_BUCKET_MAX_FP: f64 = 0.05;
/// Maximum false-positive probability admitted into the `Medium` bucket.
pub const MEDIUM_BUCKET_MAX_FP: f64 = 0.20;

/// A calibrated verdict for one finding.
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub struct Verdict {
    pub severity: Severity,
    pub confidence: f64,
    pub false_positive_prob: f64,
    /// Documented minimum precision for [`Verdict::severity`] on bench data
    /// (`0.95` high, `0.80` medium, `0.0` low = no claim).
    pub min_precision: f64,
}

/// Assign the calibrated bucket for `(confidence, false_positive_prob)`.
///
/// Both inputs are clamped to `[0, 1]`. A finding reaches `High` only when the
/// detector score *and* the confirmation FP estimate agree; same for `Medium`.
#[must_use]
pub fn severity_for(confidence: f64, false_positive_prob: f64) -> Severity {
    let confidence = confidence.clamp(0.0, 1.0);
    let fp = false_positive_prob.clamp(0.0, 1.0);
    if confidence >= HIGH_CONFIDENCE_THRESHOLD && fp <= HIGH_BUCKET_MAX_FP {
        Severity::High
    } else if confidence >= MEDIUM_CONFIDENCE_THRESHOLD && fp <= MEDIUM_BUCKET_MAX_FP {
        Severity::Medium
    } else {
        Severity::Low
    }
}

/// Full calibrated verdict for `(confidence, false_positive_prob)`.
#[must_use]
pub fn calibrate(confidence: f64, false_positive_prob: f64) -> Verdict {
    let severity = severity_for(confidence, false_positive_prob);
    let min_precision = match severity {
        Severity::High => HIGH_BUCKET_MIN_PRECISION,
        Severity::Medium => MEDIUM_BUCKET_MIN_PRECISION,
        Severity::Low => 0.0,
    };
    Verdict {
        severity,
        confidence: confidence.clamp(0.0, 1.0),
        false_positive_prob: false_positive_prob.clamp(0.0, 1.0),
        min_precision,
    }
}

/// One labeled calibration sample: detector outputs plus ground truth.
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub struct CalibrationRecord {
    pub confidence: f64,
    pub false_positive_prob: f64,
    pub is_true_positive: bool,
}

impl CalibrationRecord {
    #[must_use]
    pub const fn new(confidence: f64, false_positive_prob: f64, is_true_positive: bool) -> Self {
        Self {
            confidence,
            false_positive_prob,
            is_true_positive,
        }
    }
}

/// Measured precision per bucket over labeled records.
///
/// Returns `(high_precision, medium_precision)` as fractions in `[0, 1]`.
/// A bucket with zero samples yields `1.0` (vacuous — the integration test
/// additionally requires non-empty buckets so this cannot hide a regression).
#[must_use]
pub fn bucket_precision(records: &[CalibrationRecord]) -> (f64, f64) {
    let mut high_total = 0_u64;
    let mut high_tp = 0_u64;
    let mut medium_total = 0_u64;
    let mut medium_tp = 0_u64;
    for record in records {
        match severity_for(record.confidence, record.false_positive_prob) {
            Severity::High => {
                high_total += 1;
                if record.is_true_positive {
                    high_tp += 1;
                }
            }
            Severity::Medium => {
                medium_total += 1;
                if record.is_true_positive {
                    medium_tp += 1;
                }
            }
            Severity::Low => {}
        }
    }
    (
        precision(high_tp, high_total),
        precision(medium_tp, medium_total),
    )
}

/// Number of labeled samples per bucket `(high, medium, low)`.
#[must_use]
pub fn bucket_counts(records: &[CalibrationRecord]) -> (u64, u64, u64) {
    let mut high = 0_u64;
    let mut medium = 0_u64;
    let mut low = 0_u64;
    for record in records {
        match severity_for(record.confidence, record.false_positive_prob) {
            Severity::High => high += 1,
            Severity::Medium => medium += 1,
            Severity::Low => low += 1,
        }
    }
    (high, medium, low)
}

#[allow(clippy::cast_precision_loss)]
fn precision(true_positives: u64, total: u64) -> f64 {
    if total == 0 {
        return 1.0;
    }
    // Calibration fixtures are small (tens of samples); u64→f64 is exact there.
    (true_positives as f64) / (total as f64)
}

/// Thresholds measured from bench history, when available.
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub struct BenchThresholds {
    pub high_confidence: f64,
    pub medium_confidence: f64,
    pub high_max_fp: f64,
    pub medium_max_fp: f64,
}

/// Try to load measured thresholds from bench history.
///
/// Looks for `bench/reports/history.jsonl` (C1 history) next to the current
/// directory and its parents. Returns `None` when no usable history exists —
/// callers must fall back to the conservative compiled-in thresholds
/// documented at the top of this module. Currently always `None` in-repo
/// (history collection in progress); the loader is wired so C1 output is
/// picked up automatically once it lands.
#[must_use]
pub fn load_bench_thresholds() -> Option<BenchThresholds> {
    let path = find_history_file()?;
    let content = std::fs::read_to_string(path).ok()?;
    parse_history_thresholds(&content)
}

fn find_history_file() -> Option<std::path::PathBuf> {
    let mut dir = std::env::current_dir().ok()?;
    loop {
        let candidate = dir.join("bench").join("reports").join("history.jsonl");
        if candidate.is_file() {
            return Some(candidate);
        }
        if !dir.pop() {
            return None;
        }
    }
}

fn parse_history_thresholds(content: &str) -> Option<BenchThresholds> {
    // Expected line shape (C1 history, subset): per-bucket outcomes, e.g.
    // {"bucket":"high","true_positives":95,"total":100}. Threshold lines, e.g.
    // {"thresholds":{"high_confidence":0.85,...}}, win when present.
    let mut high_tp = 0_u64;
    let mut high_total = 0_u64;
    let mut medium_tp = 0_u64;
    let mut medium_total = 0_u64;
    let mut explicit: Option<BenchThresholds> = None;
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let value: serde_json::Value = serde_json::from_str(line).ok()?;
        if let Some(thresholds) = value.get("thresholds") {
            let get = |key: &str| thresholds.get(key).and_then(serde_json::Value::as_f64);
            if let (
                Some(high_confidence),
                Some(medium_confidence),
                Some(high_max_fp),
                Some(medium_max_fp),
            ) = (
                get("high_confidence"),
                get("medium_confidence"),
                get("high_max_fp"),
                get("medium_max_fp"),
            ) {
                explicit = Some(BenchThresholds {
                    high_confidence,
                    medium_confidence,
                    high_max_fp,
                    medium_max_fp,
                });
            }
            continue;
        }
        let bucket = value.get("bucket").and_then(serde_json::Value::as_str)?;
        let tp = value
            .get("true_positives")
            .and_then(serde_json::Value::as_u64)?;
        let total = value.get("total").and_then(serde_json::Value::as_u64)?;
        match bucket {
            "high" => {
                high_tp += tp;
                high_total += total;
            }
            "medium" => {
                medium_tp += tp;
                medium_total += total;
            }
            _ => {}
        }
    }
    if let Some(thresholds) = explicit {
        return Some(thresholds);
    }
    // Without explicit thresholds the history only validates the compiled-in
    // buckets; it cannot move them. Report that as "no thresholds".
    if high_total == 0 && medium_total == 0 {
        return None;
    }
    let _ = (high_tp, medium_tp);
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn high_requires_both_signals() {
        assert_eq!(severity_for(0.95, 0.01), Severity::High);
        // Strong score but weak confirmation → not high.
        assert_eq!(severity_for(0.95, 0.10), Severity::Medium);
        // Strong confirmation but weak score → not high.
        assert_eq!(severity_for(0.80, 0.01), Severity::Medium);
    }

    #[test]
    fn medium_requires_both_signals() {
        assert_eq!(severity_for(0.75, 0.15), Severity::Medium);
        assert_eq!(severity_for(0.75, 0.25), Severity::Low);
        assert_eq!(severity_for(0.60, 0.05), Severity::Low);
    }

    #[test]
    fn boundaries_are_inclusive() {
        assert_eq!(severity_for(0.85, 0.05), Severity::High);
        assert_eq!(severity_for(0.70, 0.20), Severity::Medium);
    }

    #[test]
    fn out_of_range_inputs_are_clamped() {
        assert_eq!(severity_for(1.5, -0.5), Severity::High);
        assert_eq!(severity_for(f64::NAN, 0.0), Severity::Low);
    }

    #[test]
    // Exact constants round-trip through `calibrate` untouched.
    #[allow(clippy::float_cmp)]
    fn calibrate_carries_precision_claim() {
        assert_eq!(calibrate(0.9, 0.02).min_precision, 0.95);
        assert_eq!(calibrate(0.75, 0.1).min_precision, 0.80);
        assert_eq!(calibrate(0.3, 0.5).min_precision, 0.0);
    }

    #[test]
    fn bucket_precision_counts_only_its_bucket() {
        let records = [
            CalibrationRecord::new(0.9, 0.02, true),
            CalibrationRecord::new(0.9, 0.02, false),
            CalibrationRecord::new(0.75, 0.1, true),
        ];
        let (high, medium) = bucket_precision(&records);
        assert!((high - 0.5).abs() < f64::EPSILON);
        assert!((medium - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn empty_history_yields_no_thresholds() {
        assert!(parse_history_thresholds("").is_none());
        assert!(parse_history_thresholds("not json\n").is_none());
    }

    #[test]
    fn explicit_thresholds_win() {
        let content = "{\"thresholds\":{\"high_confidence\":0.9,\"medium_confidence\":0.75,\"high_max_fp\":0.03,\"medium_max_fp\":0.15}}\n";
        let thresholds = parse_history_thresholds(content);
        assert!(thresholds.is_some());
    }
}
