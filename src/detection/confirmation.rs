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
}
