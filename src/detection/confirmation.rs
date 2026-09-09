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
/// Confirmation requires majority of trials with `true_conf` > 0.6 AND `false_conf` < 0.4.
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
        let false_ok = t.false_conf < 0.4;
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
}
