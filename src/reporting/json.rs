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
    /// Extracted DB data (banner, tables, dump rows, …) collected during the
    /// scan — the actual payoff of `--dump`/`--banner`/`--current-user`/etc.
    /// Previously only ever reachable via `--export-encrypted`; now surfaced
    /// in the plain report too so it isn't silently lost when that flag is
    /// omitted.
    pub extracted: Vec<String>,
    pub request_count: u64,
}

impl JsonReport {
    #[must_use]
    pub fn new(
        target: impl Into<String>,
        findings: Vec<Finding>,
        evidences: Vec<Evidence>,
        extracted: Vec<String>,
        request_count: u64,
    ) -> Self {
        Self {
            target: target.into(),
            findings,
            evidences,
            extracted,
            request_count,
        }
    }

    #[must_use]
    pub fn scrubbed(&self, scrubber: &Scrubber) -> Self {
        let scrubbed_evidences: Vec<Evidence> = self
            .evidences
            .iter()
            .map(|e| e.scrubbed(scrubber))
            .collect();
        let scrubbed_findings: Vec<Finding> =
            self.findings.iter().map(|f| f.scrubbed(scrubber)).collect();
        Self {
            target: scrubber.scrub(&self.target),
            findings: scrubbed_findings,
            evidences: scrubbed_evidences,
            extracted: self.extracted.clone(),
            request_count: self.request_count,
        }
    }

    #[must_use]
    pub fn to_json(&self, scrubber: &Scrubber) -> String {
        let report = self.scrubbed(scrubber);
        serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".to_owned())
    }
}
