#![allow(clippy::unwrap_used, clippy::expect_used)]
//! C7 intelligent reporting (`docs/ROADMAP-v1.0.md` §C7 + §v0.6).
//!
//! What this file pins:
//!
//! - **Calibration is blocking:** `high` bucket precision ≥ 95 % and `medium`
//!   ≥ 80 % on `tests/fixtures/verdict_calibration.json`. Any recalibration
//!   that drops below the claims fails here — not silently in a release.
//! - **Golden files (no `insta` in this repo):** SARIF / `JUnit` / Markdown
//!   render byte-identical to `tests/golden/c7_report.*`. Refresh with
//!   `UPDATE_GOLDEN=1 cargo test --test integration_reporting_c7` after a
//!   deliberate renderer change, then review the diff like an `insta` review.
//! - **Zero secrets:** every renderer (plus the golden files on disk) is
//!   asserted secret-free through the redacting [`Scrubber`].
//! - **`--no-redact` never in CI:** workflows under `.github/workflows` must
//!   not pass `--no-redact` (local debugging only).
//! - **Backwards compatibility:** pre-C7 minimal finding JSON (6 fields)
//!   still deserializes via `#[serde(default)]`.
//! - **`--format` contract:** default `json`, `sarif|junit|md` accepted.

use clap::Parser;
use injekt::{
    cli::args::{Cli, ReportFormat},
    reporting::{junit, markdown, sarif, verdict::CalibrationRecord},
    session::{
        scrubber::Scrubber,
        state::{Finding, TechniqueKind},
    },
};

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn manifest_path(relative: &str) -> String {
    format!("{}/{relative}", env!("CARGO_MANIFEST_DIR"))
}

fn fixed_timestamp() -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc3339("2026-01-15T12:00:00Z")
        .expect("fixed timestamp")
        .with_timezone(&chrono::Utc)
}

/// Deterministic two-finding fixture (no secrets anywhere): one `high`
/// boolean hit, one `medium` error hit with WAF context + trace ref.
fn golden_findings() -> Vec<Finding> {
    let high = Finding::new(
        "https://example.com/?id=1",
        "id@query",
        TechniqueKind::Boolean,
        0.95,
        "boolean true_sim=0.95 false_sim=0.10 trials=3/3",
    )
    .with_false_positive_prob(0.02)
    .with_diff("TRUE≈baseline FALSE≠baseline".to_owned())
    .with_trace_ref("trace:9f2c41aa07bd3e55".to_owned())
    .with_timestamp(fixed_timestamp());
    let mut medium = Finding::new(
        "https://example.com/?id=1",
        "q@query",
        TechniqueKind::Error,
        0.78,
        "error pattern Xpath tamper=space2comment",
    )
    .with_false_positive_prob(0.12)
    .with_waf(Some("cloudflare".to_owned()), true)
    .with_timestamp(fixed_timestamp());
    medium.dbms = Some("postgres".to_owned());
    vec![high, medium]
}

fn secret_finding() -> Finding {
    Finding::new(
        "https://example.com/?id=1",
        "id@query",
        TechniqueKind::Error,
        0.9,
        "evidence Authorization: Bearer abc123 cookie=session=xyz",
    )
}

fn load_calibration_fixture() -> Vec<CalibrationRecord> {
    let content = std::fs::read_to_string(manifest_path("tests/fixtures/verdict_calibration.json"))
        .expect("calibration fixture readable");
    let values: serde_json::Value =
        serde_json::from_str(&content).expect("calibration fixture is JSON");
    values
        .as_array()
        .expect("fixture is an array")
        .iter()
        .map(|entry| {
            CalibrationRecord::new(
                entry["confidence"].as_f64().expect("confidence f64"),
                entry["false_positive_prob"]
                    .as_f64()
                    .expect("false_positive_prob f64"),
                entry["label"].as_str().expect("label str") == "tp",
            )
        })
        .collect()
}

// ---------------------------------------------------------------------------
// calibration (blocking)
// ---------------------------------------------------------------------------

#[test]
fn calibration_high_precision_at_least_95_percent() {
    let records = load_calibration_fixture();
    let (high, _) = injekt::reporting::verdict::bucket_precision(&records);
    let (high_n, _, _) = injekt::reporting::verdict::bucket_counts(&records);
    assert!(high_n > 0, "high bucket must be non-empty (vacuous pass)");
    assert!(
        high >= injekt::reporting::verdict::HIGH_BUCKET_MIN_PRECISION,
        "high bucket precision {high:.3} < 0.95 on fixture: recalibration blocked"
    );
}

#[test]
fn calibration_medium_precision_at_least_80_percent() {
    let records = load_calibration_fixture();
    let (_, medium) = injekt::reporting::verdict::bucket_precision(&records);
    let (_, medium_n, _) = injekt::reporting::verdict::bucket_counts(&records);
    assert!(
        medium_n > 0,
        "medium bucket must be non-empty (vacuous pass)"
    );
    assert!(
        medium >= injekt::reporting::verdict::MEDIUM_BUCKET_MIN_PRECISION,
        "medium bucket precision {medium:.3} < 0.80 on fixture: recalibration blocked"
    );
}

// ---------------------------------------------------------------------------
// golden files (manual, insta-style)
// ---------------------------------------------------------------------------

fn check_golden(name: &str, rendered: &str) {
    let path = manifest_path(&format!("tests/golden/{name}"));
    if std::env::var("UPDATE_GOLDEN").is_ok() {
        std::fs::write(&path, rendered).expect("golden refresh writable");
        return;
    }
    let expected = std::fs::read_to_string(&path)
        .unwrap_or_else(|_| panic!("golden file missing: {path} (run with UPDATE_GOLDEN=1)"));
    assert!(
        expected == rendered,
        "golden mismatch for {name}: review the diff, then UPDATE_GOLDEN=1 to accept"
    );
}

#[test]
fn golden_sarif() {
    let scrubber = Scrubber::new(false);
    let findings = golden_findings();
    let rendered = sarif::to_sarif(
        "https://example.com/?id=1",
        &findings,
        "injekt",
        env!("CARGO_PKG_VERSION"),
        &scrubber,
    );
    // Envelope sanity before the byte comparison (clearer failure).
    let value: serde_json::Value = serde_json::from_str(&rendered).expect("golden sarif is JSON");
    assert_eq!(value["version"], "2.1.0");
    check_golden("c7_report.sarif.json", &rendered);
}

#[test]
fn golden_junit() {
    let scrubber = Scrubber::new(false);
    let rendered = junit::to_junit("https://example.com/?id=1", &golden_findings(), &scrubber);
    assert!(rendered.contains("<testsuite"), "junit envelope");
    check_golden("c7_report.junit.xml", &rendered);
}

#[test]
fn golden_markdown() {
    let scrubber = Scrubber::new(false);
    let rendered = markdown::to_markdown(
        "https://example.com/?id=1",
        &golden_findings(),
        42,
        env!("CARGO_PKG_VERSION"),
        &scrubber,
    );
    assert!(rendered.contains("### Remediation"), "markdown body");
    check_golden("c7_report.md", &rendered);
}

// ---------------------------------------------------------------------------
// zero secrets
// ---------------------------------------------------------------------------

const SECRET_MARKERS: &[&str] = &["abc123", "AKIA", "eyJhbGci", "BEGIN PRIVATE", "session=xyz"];

#[test]
fn all_renderers_redact_secrets() {
    let scrubber = Scrubber::new(false);
    let findings = vec![secret_finding()];
    let target = "https://example.com/?id=1";
    let rendered = [
        injekt::reporting::render::render_report(
            &injekt::reporting::json::JsonReport::new(
                target,
                findings.clone(),
                vec![],
                vec![],
                9,
                injekt::reporting::json::ReportMeta::default(),
            ),
            ReportFormat::Json,
            &scrubber,
        ),
        sarif::to_sarif(target, &findings, "injekt", "0.0.0", &scrubber),
        junit::to_junit(target, &findings, &scrubber),
        markdown::to_markdown(target, &findings, 9, "0.0.0", &scrubber),
    ];
    for (index, out) in rendered.iter().enumerate() {
        for marker in SECRET_MARKERS {
            assert!(
                !out.contains(marker),
                "renderer {index} leaked secret marker {marker}"
            );
        }
        assert!(
            out.contains("REDACTED"),
            "renderer {index} shows no redaction trace"
        );
    }
}

#[test]
fn golden_files_contain_no_secrets() {
    for name in [
        "tests/golden/c7_report.sarif.json",
        "tests/golden/c7_report.junit.xml",
        "tests/golden/c7_report.md",
    ] {
        let content = std::fs::read_to_string(manifest_path(name))
            .unwrap_or_else(|_| panic!("golden file missing: {name}"));
        for marker in SECRET_MARKERS {
            assert!(
                !content.contains(marker),
                "golden file {name} contains secret marker {marker}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// --no-redact interdit en CI
// ---------------------------------------------------------------------------

#[test]
fn no_redact_flag_forbidden_in_ci_workflows() {
    let dir = manifest_path(".github/workflows");
    let entries = std::fs::read_dir(&dir).expect("workflows dir readable");
    let mut checked = 0;
    for entry in entries {
        let entry = entry.expect("workflow entry readable");
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("yml")
            && path.extension().and_then(|e| e.to_str()) != Some("yaml")
        {
            continue;
        }
        let content = std::fs::read_to_string(&path).expect("workflow readable");
        assert!(
            !content.contains("--no-redact") && !content.contains("no_redact"),
            "CI workflow {} must not use --no-redact (local debugging only)",
            path.display()
        );
        checked += 1;
    }
    assert!(checked > 0, "no workflows checked in {dir}");
}

// ---------------------------------------------------------------------------
// compat + --format contract
// ---------------------------------------------------------------------------

#[test]
fn pre_c7_minimal_finding_json_still_deserializes() {
    let legacy = serde_json::json!({
        "target": "https://example.com/?id=1",
        "parameter": "id@query",
        "technique": "Boolean",
        "confidence": 0.9,
        "dbms": "mysql",
        "evidence": "boolean true_sim=0.9",
        "timestamp": "2026-01-15T12:00:00Z",
    });
    let finding: Finding =
        serde_json::from_value(legacy).expect("legacy finding deserializes via defaults");
    assert!((finding.false_positive_prob - 1.0).abs() < f64::EPSILON);
    assert!(finding.remediation.is_empty());
    assert!(finding.evidence_detail.hashes.is_empty());
    assert!(!finding.waf.blocking);
    // Serialization exposes the C7 schema.
    let value = serde_json::to_value(&finding).expect("finding serializes");
    for key in [
        "false_positive_prob",
        "severity",
        "remediation",
        "evidence_detail",
        "waf",
    ] {
        assert!(value.get(key).is_some(), "C7 key missing: {key}");
    }
}

#[test]
fn report_format_defaults_to_json() {
    assert!(matches!(ReportFormat::default(), ReportFormat::Json));
    let cli = Cli::try_parse_from(["injekt", "scan", "--target", "https://example.com/?id=1"])
        .expect("cli parses");
    assert!(matches!(cli.format, ReportFormat::Json));
    for (flag, expected) in [
        ("sarif", ReportFormat::Sarif),
        ("junit", ReportFormat::Junit),
        ("md", ReportFormat::Md),
    ] {
        let cli = Cli::try_parse_from([
            "injekt",
            "--format",
            flag,
            "scan",
            "--target",
            "https://example.com/?id=1",
        ])
        .expect("cli parses with --format");
        assert_eq!(cli.format, expected, "--format {flag} not honoured");
    }
}
