use crate::detection::response_diff::adaptive_similarity;
use crate::session::state::SessionState;
use crate::error::InjektError;
use crate::session::scrubber::Scrubber;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Result of a single discovery fuzzing round on one candidate parameter.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DiscoverResult {
    /// The candidate parameter that was fuzzed
    pub candidate: String,
    /// The original parameter value (before fuzzing)
    pub original_value: String,
    /// The fuzzed payload that was sent
    pub payload: String,
    /// The HTTP status code returned
    pub status: u16,
    /// Whether the response body changed compared to baseline (similarity < threshold)
    pub body_changed: bool,
    /// Adaptive similarity score vs baseline (0=identical, 1=completely different)
    pub similarity: f64,
    /// Whether this parameter was flagged as potentially injectable
    pub flagged: bool,
}

/// Wordlist of parameter names to fuzz-discover hidden injectable params.
/// Curated from Intigriti 2026 research, sqlmap-2026, and framework defaults.
/// ~152 entries, bounded usage to keep request budget reasonable.
#[derive(Debug, Clone)]
pub struct ParameterWordlist {
    names: Vec<String>,
    /// How many fuzzing rounds to run per candidate (default derived from max_discover)
    rounds: usize,
}

impl ParameterWordlist {
    /// Build the wordlist from the embedded source. Returns the count.
    pub fn len(&self) -> usize {
        self.names.len()
 ... O  j\ &    
 pol