#![deny(unsafe_code)]

use crate::{
    reporting::evidence::Evidence,
    session::{scrubber::Scrubber, state::Finding},
};
use serde::Serialize;

#[derive(Debug, Serialize)]
#[non_exhaustive]
pub struct JsonReport {
    pub target: String,
    pub findings: Vec<Finding>,
    pub evidences: Vec<Evidence>,
    pub request_count: u64,
}

impl JsonReport {
    #[must_use]
    pub fn new(
        target: impl Into<String>,
        findings: Vec<Finding>,
        evidences: Vec<Evidence>,
        request_count: u64,
    ) -> Self {
        Self {
            target: target.into(),
            findings,
            evidences,
            request_count,
        }
    }

    #[must_use]
    pub fn to_json(&self, scrubber: &Scrubber) -> String {
        let scrubbed_evidences: Vec<Evidence> = self
            .evidences
            .iter()
            .map(|e| e.scrubbed(scrubber))
            .collect();
        // findings evidence already scrubbed via Evidence
        let report = JsonReport {
            target: scrubber.scrub(&self.target),
            findings: self.findings.clone(),
            evidences: scrubbed_evidences,
            request_count: self.request_count,
        };
        serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".to_owned())
    }
}
