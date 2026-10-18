/// Early stopping mechanism for clean targets (N1/N2 veto: 25 negatives)
/// and early resolution on confirmed vulnerabilities.
///
/// Counts consecutive negative **requests within the current technique
/// family** (per-request cost, not per technique): `record_requests`
/// adds `spent` on a negative outcome. The streak resets at every
/// technique boundary via [`EarlyStop::reset_negative_streak`] (called by
/// the orchestrator when it pops the next family), so the veto only *arms*
/// on a single family spending `>= max_negative_probes` negative
/// requests (e.g. a full L2 boolean matrix on a clean target).
///
/// Enforcement is separate: [`crate::detection::scanner::scheduler::Scheduler::pop`] only honors the veto after
/// a full pass (every enqueued family dequeued at least once), so an armed
/// veto can never starve never-attempted families (a boolean-negative
/// target may still be nosql-positive; cross-family starvation would be a
/// silent false negative, the worst failure mode for a scanner). B1: the
/// pre-fix `pop` checked the veto *before* the boundary reset could run,
/// so L2 boolean (~40 req, top EVI) vetoed error/time/union/nosql unseen.
///
/// Inter-param isolation is separate: each parameter repart d'un compteur
/// frais via [`EarlyStop::reset_for_new_param`] (called by the orchestrator
/// at each parameter boundary), while the cross-param total stays visible
/// in `SessionState::request_count` and in the [`crate::detection::scanner::scheduler::RequestBudget`]. Any
/// confirmed finding locks `confirmed` and disables the stop for the rest
/// of the parameter (both resets preserve it).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct EarlyStop {
    /// Maximum consecutive negative outcomes before early stopping on a clean parameter.
    pub max_negative_probes: usize,
    /// Consecutive negative probes observed on the current parameter.
    pub negative_count: usize,
    /// Whether any confirmed finding was recorded for this parameter.
    pub confirmed: bool,
}

impl Default for EarlyStop {
    fn default() -> Self {
        Self {
            max_negative_probes: 25,
            negative_count: 0,
            confirmed: false,
        }
    }
}

impl EarlyStop {
    #[must_use]
    pub const fn new(max_negative_probes: usize) -> Self {
        Self {
            max_negative_probes,
            negative_count: 0,
            confirmed: false,
        }
    }

    pub fn record_result(&mut self, is_finding: bool) {
        self.record_requests(is_finding, 1);
    }

    /// Per-request variant (Phase 0) : ajoute `requests_spent` (pas 1) sur
    /// négatif, de sorte que `max_negative_probes` se compare à des
    /// requêtes et trippe mid-pass sur cible propre.
    pub fn record_requests(&mut self, is_finding: bool, requests_spent: usize) {
        if is_finding {
            self.confirmed = true;
        } else {
            self.negative_count = self.negative_count.saturating_add(requests_spent.max(1));
        }
    }

    #[must_use]
    pub fn should_stop(&self) -> bool {
        if self.confirmed {
            return false;
        }
        self.max_negative_probes > 0 && self.negative_count >= self.max_negative_probes
    }

    pub fn reset_for_new_param(&mut self) {
        self.negative_count = 0;
        self.confirmed = false;
    }

    /// Reset the negative streak at a technique-family boundary (the
    /// orchestrator calls this when it starts a new family on the same
    /// parameter). Unlike [`EarlyStop::reset_for_new_param`], `confirmed`
    /// is preserved: a confirmed finding keeps disabling the veto for the
    /// rest of the parameter.
    pub fn reset_negative_streak(&mut self) {
        self.negative_count = 0;
    }
}
