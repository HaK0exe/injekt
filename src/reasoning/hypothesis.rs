#![deny(unsafe_code)]

use crate::{
    dbms::context::{DbmsBelief, InjectionContext, QuoteContext},
    session::state::TechniqueKind,
};
use serde::{Deserialize, Serialize};

/// High confidence threshold (calibrated for precision >= 95%).
pub const HIGH_CONFIDENCE_THRESHOLD: f64 = 0.85;
/// Medium confidence threshold (calibrated for precision >= 80%).
pub const MEDIUM_CONFIDENCE_THRESHOLD: f64 = 0.70;
/// Refutation / pruning threshold below which a hypothesis is dropped.
pub const REFUTED_POSTERIOR_THRESHOLD: f64 = 0.04;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum HypothesisState {
    /// Hypothesis is being tested / actively probed.
    Pending,
    /// Hypothesis confirmed by differential testing and verification trials.
    Confirmed,
    /// Hypothesis refuted by negative probes (early stop).
    Refuted,
    /// Hypothesis abandoned due to repeated WAF blocks or budget limits.
    Abandoned,
}

impl std::fmt::Display for HypothesisState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Confirmed => write!(f, "confirmed"),
            Self::Refuted => write!(f, "refuted"),
            Self::Abandoned => write!(f, "abandoned"),
        }
    }
}

/// A reasoned hypothesis for an injection vector on a specific parameter.
///
/// Updates use a log-additive posterior model:
/// `log_odds(posterior) = log_odds(prior) + sum(log_likelihood_ratios) - waf_penalties`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Hypothesis {
    pub param: String,
    pub technique: TechniqueKind,
    pub dbms_belief: DbmsBelief,
    pub context: InjectionContext,
    pub prior: f64,
    pub log_odds: f64,
    pub posterior: f64,
    pub cost_spent: usize,
    pub state: HypothesisState,
    pub trials_passed: usize,
    pub trials_total: usize,
    pub waf_penalties: usize,
}

impl Hypothesis {
    /// Creates a new hypothesis with calibrated baseline priors conditioned
    /// on injection context and DBMS belief.
    #[must_use]
    pub fn new(
        param: String,
        technique: TechniqueKind,
        dbms_belief: DbmsBelief,
        context: InjectionContext,
    ) -> Self {
        let prior = compute_calibrated_prior(technique, &context, &dbms_belief);
        let log_odds = prob_to_log_odds(prior);
        let posterior = prior;
        Self {
            param,
            technique,
            dbms_belief,
            context,
            prior,
            log_odds,
            posterior,
            cost_spent: 0,
            state: HypothesisState::Pending,
            trials_passed: 0,
            trials_total: 0,
            waf_penalties: 0,
        }
    }

    /// Record a probe observation with its log-likelihood delta and cost in requests.
    pub fn record_probe(&mut self, is_positive: bool, signal_strength: f64, request_cost: usize) {
        self.cost_spent = self.cost_spent.saturating_add(request_cost);
        if self.state != HypothesisState::Pending {
            return;
        }

        let delta = if is_positive {
            // Positive signal: delta in [+1.5, +4.0] depending on signal strength (0..1)
            1.5 + (signal_strength.clamp(0.0, 1.0) * 2.5)
        } else {
            // Negative signal: -1.2 to -2.0
            -1.5
        };

        self.apply_log_delta(delta);
    }

    /// Record an explicit confirmation trial outcome (e.g. from 3-trial verification).
    pub fn record_trial(&mut self, passed: bool) {
        self.trials_total = self.trials_total.saturating_add(1);
        if passed {
            self.trials_passed = self.trials_passed.saturating_add(1);
            // Strong confirmation evidence
            self.apply_log_delta(3.5);
        } else {
            // Trial failure penalises hypothesis
            self.apply_log_delta(-2.5);
        }
    }

    /// Record a WAF blocking response (403/406/rate-limit).
    pub fn record_waf_penalty(&mut self) {
        self.waf_penalties = self.waf_penalties.saturating_add(1);
        self.apply_log_delta(-1.0);
        if self.waf_penalties >= 3 && self.posterior < MEDIUM_CONFIDENCE_THRESHOLD {
            self.state = HypothesisState::Abandoned;
        }
    }

    fn apply_log_delta(&mut self, delta: f64) {
        self.log_odds += delta;
        // Clamp log_odds to avoid numerical instability
        self.log_odds = self.log_odds.clamp(-12.0, 12.0);
        self.posterior = log_odds_to_prob(self.log_odds);

        // Update state based on calibrated thresholds
        if self.posterior >= HIGH_CONFIDENCE_THRESHOLD && self.trials_passed > 0 {
            self.state = HypothesisState::Confirmed;
        } else if self.posterior <= REFUTED_POSTERIOR_THRESHOLD {
            self.state = HypothesisState::Refuted;
        }
    }

    #[must_use]
    pub fn is_confirmed(&self) -> bool {
        self.state == HypothesisState::Confirmed
    }

    #[must_use]
    pub fn is_refuted(&self) -> bool {
        self.state == HypothesisState::Refuted
    }

    #[must_use]
    pub fn is_terminal(&self) -> bool {
        self.state != HypothesisState::Pending
    }
}

/// Convert probability in (0, 1) to log-odds.
#[must_use]
pub fn prob_to_log_odds(p: f64) -> f64 {
    let p_clamped = p.clamp(1e-6, 1.0 - 1e-6);
    (p_clamped / (1.0 - p_clamped)).ln()
}

/// Convert log-odds to probability in (0, 1).
#[must_use]
pub fn log_odds_to_prob(log_odds: f64) -> f64 {
    1.0 / (1.0 + (-log_odds).exp())
}

/// Calibrated priors derived from benchmark baseline and context inference.
#[must_use]
pub fn compute_calibrated_prior(
    technique: TechniqueKind,
    context: &InjectionContext,
    dbms_belief: &DbmsBelief,
) -> f64 {
    let base_prior = match technique {
        TechniqueKind::Boolean => 0.20,
        TechniqueKind::Error => 0.15,
        TechniqueKind::Time => 0.10,
        TechniqueKind::Union | TechniqueKind::Stacked | TechniqueKind::Json => 0.05,
        TechniqueKind::Oob => 0.02,
    };

    let mut prior: f64 = base_prior;

    // Adjust for JSON context
    if context.json {
        if technique == TechniqueKind::Json {
            prior = 0.45;
        } else if technique == TechniqueKind::Stacked {
            prior *= 0.5;
        }
    }

    // Adjust for ORDER BY context
    if context.order_by {
        if technique == TechniqueKind::Union {
            prior = 0.35;
        } else if technique == TechniqueKind::Boolean {
            prior = 0.30;
        }
    }

    // Adjust for Quote context
    if context.quote == QuoteContext::None && context.numeric {
        // Numeric bare injections respond very well to boolean arithmetic
        if technique == TechniqueKind::Boolean {
            prior = (prior * 1.3).min(0.50);
        }
    }

    // Adjust for DBMS belief certainty (if DBMS is strongly suspected)
    let (_, dbms_prob) = dbms_belief.top_candidate();
    if dbms_prob > 0.8 {
        prior = (prior * 1.15).min(0.60);
    }

    prior.clamp(0.01, 0.90)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_odds_roundtrip() {
        for p in [0.01, 0.05, 0.20, 0.50, 0.85, 0.95, 0.99] {
            let log_odds = prob_to_log_odds(p);
            let recovered = log_odds_to_prob(log_odds);
            assert!((p - recovered).abs() < 1e-4);
        }
    }

    #[test]
    fn test_hypothesis_confirmation_lifecycle() {
        let mut h = Hypothesis::new(
            "id@query".to_owned(),
            TechniqueKind::Boolean,
            DbmsBelief::uniform(),
            InjectionContext::new(),
        );
        assert_eq!(h.state, HypothesisState::Pending);

        // Positive probe
        h.record_probe(true, 0.9, 1);
        assert!(h.posterior > h.prior);

        // Verification trial pass
        h.record_trial(true);
        assert!(h.posterior >= HIGH_CONFIDENCE_THRESHOLD);
        assert_eq!(h.state, HypothesisState::Confirmed);
        assert!(h.is_confirmed());
    }

    #[test]
    fn test_hypothesis_refutation_lifecycle() {
        let mut h = Hypothesis::new(
            "id@query".to_owned(),
            TechniqueKind::Boolean,
            DbmsBelief::uniform(),
            InjectionContext::new(),
        );

        // Multiple negative probes
        for _ in 0..4 {
            h.record_probe(false, 0.0, 1);
        }

        assert!(h.posterior <= REFUTED_POSTERIOR_THRESHOLD);
        assert_eq!(h.state, HypothesisState::Refuted);
        assert!(h.is_refuted());
    }

    #[test]
    fn test_waf_penalty() {
        let mut h = Hypothesis::new(
            "id@query".to_owned(),
            TechniqueKind::Error,
            DbmsBelief::uniform(),
            InjectionContext::new(),
        );

        let initial_post = h.posterior;
        h.record_waf_penalty();
        assert!(h.posterior < initial_post);
        assert_eq!(h.waf_penalties, 1);
    }
}
