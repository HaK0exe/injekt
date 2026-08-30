#![deny(unsafe_code)]

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

/// Re-test TRUE/FALSE inverted payloads. Requires 3 trials minimum.
#[must_use]
pub fn confirm(results: &[(bool, f64)]) -> ConfirmationResult {
    let trials = results.len();
    if trials < 3 {
        return ConfirmationResult::new(false, 0.0, trials);
    }
    let mut true_hits = 0usize;
    let mut score_sum = 0.0;
    for (is_true, conf) in results {
        if *is_true {
            true_hits += 1;
        }
        score_sum += conf;
    }
    let avg = score_sum / trials as f64;
    // Expect true branch to succeed and false branch to fail; simplified: >60% true hits => confirmed
    let confirmed = true_hits as f64 / trials as f64 > 0.6 && avg > 0.5;
    let score = if confirmed { avg } else { 1.0 - avg };
    ConfirmationResult::new(confirmed, score.clamp(0.0, 1.0), trials)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn needs_three_trials() {
        let r = confirm(&[(true, 0.9)]);
        assert!(!r.confirmed);
    }
    #[test]
    fn confirms_majority() {
        let r = confirm(&[(true, 0.8), (true, 0.9), (true, 0.85)]);
        assert!(r.confirmed);
    }
}
