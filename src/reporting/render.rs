#![deny(unsafe_code)]

//! Single dispatch for `--format` report serialization (C7).
//!
//! All formats render from an (already scrubbed) [`JsonReport`]; every
//! renderer scrubs again (idempotent), so `--output` files never carry
//! secrets regardless of format. Console output is intentionally untouched
//! by `--format`.

use crate::{
    cli::args::ReportFormat,
    reporting::{json::JsonReport, junit, markdown, sarif},
    session::scrubber::Scrubber,
};

/// Serialize `report` in the requested `--format`.
#[must_use]
pub fn render_report(report: &JsonReport, format: ReportFormat, scrubber: &Scrubber) -> String {
    match format {
        ReportFormat::Json => report.to_json(scrubber),
        ReportFormat::Sarif => sarif::to_sarif(
            &report.target,
            &report.findings,
            "injekt",
            &report.meta.version,
            scrubber,
        ),
        ReportFormat::Junit => junit::to_junit(&report.target, &report.findings, scrubber),
        ReportFormat::Md => markdown::to_markdown(
            &report.target,
            &report.findings,
            report.request_count,
            &report.meta.version,
            scrubber,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        reporting::json::ReportMeta,
        session::state::{Finding, TechniqueKind},
    };

    fn report() -> JsonReport {
        let finding = Finding::new(
            "https://example.com/?id=1",
            "id@query",
            TechniqueKind::Boolean,
            0.95,
            "boolean true_sim=0.95 false_sim=0.10",
        )
        .with_false_positive_prob(0.02);
        JsonReport::new(
            "https://example.com/?id=1",
            vec![finding],
            vec![],
            vec![],
            42,
            ReportMeta::default(),
        )
    }

    #[test]
    fn all_formats_render_without_panic() {
        let scrubber = Scrubber::new(false);
        let report = report();
        for format in [
            ReportFormat::Json,
            ReportFormat::Sarif,
            ReportFormat::Junit,
            ReportFormat::Md,
        ] {
            let out = render_report(&report, format, &scrubber);
            assert!(!out.is_empty(), "empty output for {format}");
        }
    }

    #[test]
    fn json_default_carries_c7_fields() {
        let scrubber = Scrubber::new(true);
        let value: serde_json::Value =
            serde_json::from_str(&render_report(&report(), ReportFormat::Json, &scrubber))
                .unwrap_or(serde_json::Value::Null);
        let finding = &value["findings"][0];
        assert!(finding.get("false_positive_prob").is_some(), "{value}");
        assert!(finding.get("severity").is_some(), "{value}");
        assert!(finding.get("remediation").is_some(), "{value}");
        assert!(finding.get("waf").is_some(), "{value}");
    }
}
