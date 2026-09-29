#![deny(unsafe_code)]

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Trial {
    pub true_conf: f64,
    pub false_conf: f64,
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ConfirmationResult {
    pub confirmed: bool,
    pub score: f64,
    pub false_positive_prob: f64,
    pub trials: usize,
}

impl ConfirmationResult {
    #[must_use]
    pub fn new(confirmed: bool, score: f64, trials: usize) -> Self {
        let fp = if confirmed {
            (1.0 - score).clamp(0.0, 1.0)
        } else {
            score.clamp(0.0, 1.0)
        };
        Self {
            confirmed,
            score,
            false_positive_prob: fp,
            trials,
        }
    }
}

/// Re-test TRUE/FALSE inverted payload pairs. Requires 3 trials minimum.
/// Confirmation requires majority of trials with `true_conf` > 0.6 AND
/// (`false_conf` < 0.4 OR a decisive gap: `true_conf` > 0.9 with
/// `true_conf - false_conf` > 0.5). The gap clause covers small JSON
/// envelopes whose boilerplate tokens (`request_id`, …) floor the FALSE
/// similarity above 0.4 even for a textbook oracle (TRUE == baseline,
/// FALSE = empty set — live bench A1: 1.0 vs 0.4375).
#[must_use]
// Trial counts are small (single-digit confirmation retries); usize->f64 precision loss is not reachable.
#[allow(clippy::cast_precision_loss)]
pub fn confirm(trials: &[Trial]) -> ConfirmationResult {
    let n = trials.len();
    if n < 3 {
        return ConfirmationResult::new(false, 0.0, n);
    }
    let mut pass_count = 0usize;
    let mut score_sum = 0.0;
    for t in trials {
        let true_ok = t.true_conf > 0.6;
        // Gap clause: a TRUE branch locked on the baseline (> 0.9) with a
        // decisive differential (> 0.5) confirms even when envelope
        // boilerplate keeps the FALSE similarity at/above 0.4.
        let false_ok =
            t.false_conf < 0.4 || (t.true_conf > 0.9 && t.true_conf - t.false_conf > 0.5);
        if true_ok && false_ok {
            pass_count += 1;
        }
        score_sum += f64::midpoint(t.true_conf, 1.0 - t.false_conf);
    }
    let avg_score = score_sum / n as f64;
    let confirmed = pass_count as f64 / n as f64 > 0.5;
    let score = if confirmed {
        avg_score
    } else {
        1.0 - avg_score
    };
    ConfirmationResult::new(confirmed, score.clamp(0.0, 1.0), n)
}

/// Aggregate per-trial similarities for evidence display.
///
/// Returns the mean `(true_conf, false_conf)` over *passing* trials (same
/// per-trial pass rule as [`confirm`]), so the rendered `true_sim` /
/// `false_sim` reflect the measured majority instead of whichever trial ran
/// last. Neutral transport trials (`0.5`/`0.5`) and ignored-status trials
/// (`0.0`/`1.0`) never pass and are excluded. When no trial passes (e.g. an
/// inverted oracle decided on the swapped pass), falls back to the mean over
/// all trials; empty input yields `(0.0, 0.0)`.
///
/// Decision inputs (`score`, `false_positive_prob`) still come from
/// [`confirm`]/[`confirm_either`]; this only affects display.
#[must_use]
// Trial counts are small (single-digit confirmation retries); usize->f64 precision loss is not reachable.
#[allow(clippy::cast_precision_loss)]
pub fn aggregate_sims(trials: &[Trial]) -> (f64, f64) {
    fn passes(t: &Trial) -> bool {
        t.true_conf > 0.6
            && (t.false_conf < 0.4 || (t.true_conf > 0.9 && t.true_conf - t.false_conf > 0.5))
    }
    let mut sum_true = 0.0;
    let mut sum_false = 0.0;
    let mut count = 0usize;
    for t in trials.iter().filter(|t| passes(t)) {
        sum_true += t.true_conf;
        sum_false += t.false_conf;
        count += 1;
    }
    if count == 0 {
        // No passing trial: mean over all trials (inverted/degenerate
        // shapes), still more representative than the last trial alone.
        for t in trials {
            sum_true += t.true_conf;
            sum_false += t.false_conf;
        }
        count = trials.len();
    }
    if count == 0 {
        return (0.0, 0.0);
    }
    (sum_true / count as f64, sum_false / count as f64)
}

/// Confirm a boolean oracle in EITHER direction.
///
/// A boolean injection has two stable states; either one may coincide with
/// the baseline page. Normal direction: TRUE≈baseline, FALSE differs (e.g.
/// id-lookup sinks). Inverted direction: FALSE≈baseline, TRUE differs (e.g.
/// login-bypass sinks where the baseline IS the failed state).
/// Returns the result plus whether the inverted assignment won. When both
/// directions confirm (degenerate page), normal wins.
#[must_use]
pub fn confirm_either(trials: &[Trial]) -> (ConfirmationResult, bool) {
    let normal = confirm(trials);
    if normal.confirmed {
        return (normal, false);
    }
    let swapped: Vec<Trial> = trials
        .iter()
        .map(|t| Trial {
            true_conf: t.false_conf,
            false_conf: t.true_conf,
        })
        .collect();
    // Swapping exchanges the roles: the confirmation rule stays
    // "baseline-like > 0.6 AND different < 0.4", now tested against the
    // FALSE branch as the baseline-like one. Same bar, no extra FP room
    // beyond the symmetry of a two-state oracle.
    let inverted = confirm(&swapped);
    if inverted.confirmed {
        (inverted, true)
    } else {
        (normal, false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn needs_three_trials() {
        let r = confirm(&[Trial {
            true_conf: 0.9,
            false_conf: 0.1,
        }]);
        assert!(!r.confirmed);
    }
    #[test]
    fn confirms_majority_pass() {
        let r = confirm(&[
            Trial {
                true_conf: 0.8,
                false_conf: 0.2,
            },
            Trial {
                true_conf: 0.9,
                false_conf: 0.1,
            },
            Trial {
                true_conf: 0.7,
                false_conf: 0.3,
            },
        ]);
        assert!(r.confirmed);
        assert!(r.false_positive_prob < 0.5);
    }
    #[test]
    fn rejects_false_high() {
        let r = confirm(&[
            Trial {
                true_conf: 0.8,
                false_conf: 0.5,
            },
            Trial {
                true_conf: 0.9,
                false_conf: 0.6,
            },
            Trial {
                true_conf: 0.7,
                false_conf: 0.4,
            },
        ]);
        assert!(!r.confirmed);
    }
    #[test]
    fn either_accepts_normal_direction() {
        let trials = [
            Trial {
                true_conf: 0.9,
                false_conf: 0.1,
            },
            Trial {
                true_conf: 0.8,
                false_conf: 0.2,
            },
            Trial {
                true_conf: 0.85,
                false_conf: 0.15,
            },
        ];
        let (r, inverted) = confirm_either(&trials);
        assert!(r.confirmed);
        assert!(!inverted);
    }
    #[test]
    fn either_accepts_inverted_login_style_oracle() {
        // Baseline IS the failed state: FALSE≈baseline, TRUE differs.
        let trials = [
            Trial {
                true_conf: 0.3,
                false_conf: 0.95,
            },
            Trial {
                true_conf: 0.25,
                false_conf: 0.9,
            },
            Trial {
                true_conf: 0.35,
                false_conf: 0.92,
            },
        ];
        assert!(!confirm(&trials).confirmed);
        let (r, inverted) = confirm_either(&trials);
        assert!(r.confirmed);
        assert!(inverted);
    }
    #[test]
    fn either_rejects_ambiguous_superset_oracle() {
        // Neither branch matches the baseline (e.g. OR-superset TRUE plus
        // empty FALSE on a 1-row baseline): no direction is stable.
        let trials = [
            Trial {
                true_conf: 0.54,
                false_conf: 0.28,
            },
            Trial {
                true_conf: 0.55,
                false_conf: 0.3,
            },
            Trial {
                true_conf: 0.52,
                false_conf: 0.27,
            },
        ];
        let (r, _) = confirm_either(&trials);
        assert!(!r.confirmed);
    }
    #[test]
    fn confirms_locked_baseline_with_decisive_gap() {
        // Live bench A1 shape: TRUE == baseline (1.0), FALSE = empty `data`
        // set (0.4375 — envelope boilerplate floors it above the 0.4 bar).
        // The gap clause (1.0 - 0.4375 = 0.5625 > 0.5) must confirm.
        let trials = [
            Trial {
                true_conf: 1.0,
                false_conf: 0.4375,
            },
            Trial {
                true_conf: 1.0,
                false_conf: 0.4375,
            },
            Trial {
                true_conf: 1.0,
                false_conf: 0.4375,
            },
        ];
        let (r, inverted) = confirm_either(&trials);
        assert!(r.confirmed);
        assert!(!inverted);
    }
    #[test]
    fn rejects_small_gap_near_threshold() {
        // TRUE locked but gap indecisive (0.95 - 0.5 = 0.45 < 0.5):
        // stays rejected so the gap clause cannot launder weak oracles.
        let trials = [
            Trial {
                true_conf: 0.95,
                false_conf: 0.5,
            },
            Trial {
                true_conf: 0.95,
                false_conf: 0.5,
            },
            Trial {
                true_conf: 0.95,
                false_conf: 0.5,
            },
        ];
        let (r, _) = confirm_either(&trials);
        assert!(!r.confirmed);
    }
    #[test]
    fn aggregate_sims_means_passing_trials_only() {
        // Two passing trials + one neutral transport trial: the neutral
        // trial must not drag the evidence mean.
        let (t, f) = aggregate_sims(&[
            Trial {
                true_conf: 0.9,
                false_conf: 0.1,
            },
            Trial {
                true_conf: 0.5,
                false_conf: 0.5,
            },
            Trial {
                true_conf: 0.8,
                false_conf: 0.2,
            },
        ]);
        assert!((t - 0.85).abs() < 1e-9, "{t}");
        assert!((f - 0.15).abs() < 1e-9, "{f}");
    }
    #[test]
    fn aggregate_sims_falls_back_to_all_when_none_pass() {
        // Inverted oracle (decided on the swapped pass): no original trial
        // passes, so evidence is the mean over all trials.
        let (t, f) = aggregate_sims(&[
            Trial {
                true_conf: 0.3,
                false_conf: 0.9,
            },
            Trial {
                true_conf: 0.3,
                false_conf: 0.9,
            },
            Trial {
                true_conf: 0.3,
                false_conf: 0.9,
            },
        ]);
        assert!((t - 0.3).abs() < 1e-9, "{t}");
        assert!((f - 0.9).abs() < 1e-9, "{f}");
        assert_eq!(aggregate_sims(&[]), (0.0, 0.0));
    }
}
