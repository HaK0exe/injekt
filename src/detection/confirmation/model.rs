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
