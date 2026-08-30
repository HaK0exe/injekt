#![deny(unsafe_code)]
use serde::Serialize;

#[derive(Serialize)]
pub struct Output {
    pub findings: Vec<String>,
}

#[must_use]
pub fn to_json(findings: &[String]) -> String {
    serde_json::to_string_pretty(&Output {
        findings: findings.to_vec(),
    })
    .unwrap_or_default()
}
