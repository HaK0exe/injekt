use std::collections::HashMap;

/// Tracks global and per-parameter request consumption against configured limits.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct RequestBudget {
    max_requests: Option<usize>,
    max_per_param: Option<usize>,
    spent_total: usize,
    spent_per_param: HashMap<String, usize>,
}

impl RequestBudget {
    #[must_use]
    pub fn new(max_requests: Option<usize>, max_per_param: Option<usize>) -> Self {
        Self {
            max_requests,
            max_per_param,
            spent_total: 0,
            spent_per_param: HashMap::new(),
        }
    }

    #[must_use]
    pub fn unlimited() -> Self {
        Self {
            max_requests: None,
            max_per_param: None,
            spent_total: 0,
            spent_per_param: HashMap::new(),
        }
    }

    pub fn record_request(&mut self, param: &str, count: usize) {
        self.spent_total = self.spent_total.saturating_add(count);
        let entry = self.spent_per_param.entry(param.to_owned()).or_insert(0);
        *entry = entry.saturating_add(count);
    }

    #[must_use]
    pub fn is_exhausted(&self) -> bool {
        if let Some(max) = self.max_requests {
            self.spent_total >= max
        } else {
            false
        }
    }

    #[must_use]
    pub fn is_param_exhausted(&self, param: &str) -> bool {
        if self.is_exhausted() {
            return true;
        }
        if let Some(max_p) = self.max_per_param {
            let spent = self.spent_per_param.get(param).copied().unwrap_or(0);
            spent >= max_p
        } else {
            false
        }
    }

    #[must_use]
    pub fn remaining_total(&self) -> Option<usize> {
        self.max_requests
            .map(|max| max.saturating_sub(self.spent_total))
    }

    #[must_use]
    pub const fn spent_total(&self) -> usize {
        self.spent_total
    }

    #[must_use]
    pub const fn max_requests(&self) -> Option<usize> {
        self.max_requests
    }

    #[must_use]
    pub fn spent_for_param(&self, param: &str) -> usize {
        self.spent_per_param.get(param).copied().unwrap_or(0)
    }
}
