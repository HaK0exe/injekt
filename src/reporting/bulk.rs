#![deny(unsafe_code)]

use crate::session::{scrubber::Scrubber, state::Finding};

/// Bulk report format version.
pub const BULK_REPORT_VERSION: u8 = 1;

/// Per-target outcome of a bulk scan.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct BulkTargetResult {
    pub target: String,
    pub findings: Vec<Finding>,
    pub request_count: u64,
    pub error: Option<String>,
}

impl BulkTargetResult {
    #[must_use]
    pub fn ok(target: String, findings: Vec<Finding>, request_count: u64) -> Self {
        Self {
            target,
            findings,
            request_count,
            error: None,
        }
    }

    #[must_use]
    pub fn failed(target: String, request_count: u64, error: String) -> Self {
        Self {
            target,
            findings: Vec::new(),
            request_count,
            error: Some(error),
        }
    }
}

/// Aggregated result of scanning several targets sequentially.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct BulkReport {
    pub version: u8,
    pub targets_total: usize,
    pub targets_ok: usize,
    pub targets_failed: usize,
    pub request_count_total: u64,
    pub per_target: Vec<BulkTargetResult>,
}

impl BulkReport {
    #[must_use]
    pub fn empty(targets_total: usize) -> Self {
        Self {
            version: BULK_REPORT_VERSION,
            targets_total,
            targets_ok: 0,
            targets_failed: 0,
            request_count_total: 0,
            per_target: Vec::new(),
        }
    }

    /// Scrubbed JSON value (targets + findings + errors go through `scrubber`).
    #[must_use]
    pub fn to_json(&self, scrubber: &Scrubber) -> serde_json::Value {
        let per_target: Vec<serde_json::Value> = self
            .per_target
            .iter()
            .map(|r| {
                let findings: Vec<serde_json::Value> = r
                    .findings
                    .iter()
                    .map(|f| match serde_json::to_value(f.scrubbed(scrubber)) {
                        Ok(v) => v,
                        Err(_) => serde_json::Value::Null,
                    })
                    .collect();
                let error = r.error.as_deref().map(|e| scrubber.scrub(e));
                serde_json::json!({
                    "target": scrubber.scrub(&r.target),
                    "findings": findings,
                    "request_count": r.request_count,
                    "error": error,
                })
            })
            .collect();
        serde_json::json!({
            "version": self.version,
            "targets_total": self.targets_total,
            "targets_ok": self.targets_ok,
            "targets_failed": self.targets_failed,
            "request_count_total": self.request_count_total,
            "per_target": per_target,
        })
    }

    /// Console summary: totals plus one line per target. Never prints evidence,
    /// targets and errors are scrubbed — no secrets on stdout.
    pub fn print_summary(&self, scrubber: &Scrubber) {
        use owo_colors::OwoColorize;

        println!(
            "{} {}/{} {}  {}  {}",
            "▶ bulk scan:".bold(),
            self.targets_ok,
            self.targets_total,
            "ok".green(),
            format!("{} failed", self.targets_failed).red(),
            format!("{} requests", self.request_count_total).dimmed()
        );
        for r in &self.per_target {
            let target = scrubber.scrub(&r.target);
            if let Some(e) = r.error.as_deref() {
                println!(
                    "  {} {target}: {}",
                    "✗".red().bold(),
                    scrubber.scrub(e).red()
                );
            } else {
                let findings = r.findings.len();
                let mark = if findings > 0 {
                    "!".yellow().bold().to_string()
                } else {
                    "✓".green().to_string()
                };
                println!(
                    "  {mark} {target}: findings={findings} reqs={}",
                    r.request_count
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::state::TechniqueKind;

    fn finding() -> Finding {
        Finding::new(
            "http://example.com/?id=1",
            "id@query",
            TechniqueKind::Boolean,
            0.9,
            "boolean true_sim=0.95",
        )
    }

    fn report() -> BulkReport {
        BulkReport {
            version: BULK_REPORT_VERSION,
            targets_total: 2,
            targets_ok: 1,
            targets_failed: 1,
            request_count_total: 42,
            per_target: vec![
                BulkTargetResult::ok("http://example.com/?id=1".to_owned(), vec![finding()], 30),
                BulkTargetResult::failed(
                    "http://example.com/?id=2".to_owned(),
                    12,
                    "baseline failed".to_owned(),
                ),
            ],
        }
    }

    #[test]
    fn to_json_carries_version_and_totals() {
        let v = report().to_json(&Scrubber::new(true));
        assert_eq!(
            v.get("version").and_then(serde_json::Value::as_u64),
            Some(u64::from(BULK_REPORT_VERSION))
        );
        assert_eq!(
            v.get("targets_total").and_then(serde_json::Value::as_u64),
            Some(2)
        );
        assert_eq!(
            v.get("targets_ok").and_then(serde_json::Value::as_u64),
            Some(1)
        );
        assert_eq!(
            v.get("targets_failed").and_then(serde_json::Value::as_u64),
            Some(1)
        );
        assert_eq!(
            v.get("request_count_total")
                .and_then(serde_json::Value::as_u64),
            Some(42)
        );
    }

    #[test]
    fn to_json_scrubs_targets_and_evidence() {
        let secret = "Authorization: Bearer abc123";
        let mut f = finding();
        f.evidence = secret.to_owned();
        let r = BulkReport {
            version: BULK_REPORT_VERSION,
            targets_total: 1,
            targets_ok: 1,
            targets_failed: 0,
            request_count_total: 1,
            per_target: vec![BulkTargetResult::ok(secret.to_owned(), vec![f], 1)],
        };
        let v = r.to_json(&Scrubber::new(false));
        let s = serde_json::to_string(&v).unwrap_or_default();
        assert!(!s.contains("abc123"), "secret leaked: {s}");
    }

    #[test]
    fn empty_report_counts_zero() {
        let r = BulkReport::empty(3);
        assert_eq!(r.targets_total, 3);
        assert_eq!(r.targets_ok, 0);
        assert_eq!(r.targets_failed, 0);
        assert_eq!(r.request_count_total, 0);
        assert!(r.per_target.is_empty());
    }

    #[test]
    fn print_summary_does_not_panic() {
        report().print_summary(&Scrubber::new(false));
    }
}
