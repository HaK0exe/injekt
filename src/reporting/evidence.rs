#![deny(unsafe_code)]

use crate::session::scrubber::Scrubber;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Evidence {
    pub request: String,
    pub response: String,
    pub technique: String,
    pub parameter: String,
    pub confidence: f64,
}

impl Evidence {
    #[must_use]
    pub fn new(
        request: impl Into<String>,
        response: impl Into<String>,
        technique: impl Into<String>,
        parameter: impl Into<String>,
        confidence: f64,
    ) -> Self {
        Self {
            request: request.into(),
            response: response.into(),
            technique: technique.into(),
            parameter: parameter.into(),
            confidence,
        }
    }

    #[must_use]
    pub fn scrubbed(&self, scrubber: &Scrubber) -> Self {
        Self {
            request: scrubber.scrub(&self.request),
            response: scrubber.scrub(&self.response),
            technique: self.technique.clone(),
            parameter: scrubber.scrub(&self.parameter),
            confidence: self.confidence,
        }
    }
}

#[derive(Debug, Default)]
pub struct EvidenceCollector {
    evidences: Vec<Evidence>,
}

impl EvidenceCollector {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    pub fn push(&mut self, e: Evidence) {
        self.evidences.push(e);
    }
    #[must_use]
    pub fn all(&self) -> &[Evidence] {
        &self.evidences
    }
    #[must_use]
    pub fn scrubbed_all(&self, scrubber: &Scrubber) -> Vec<Evidence> {
        self.evidences
            .iter()
            .map(|e| e.scrubbed(scrubber))
            .collect()
    }
}
