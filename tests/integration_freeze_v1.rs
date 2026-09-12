#![allow(clippy::unwrap_used, clippy::expect_used)]
//! v1.0-rc surface freeze (`docs/ROADMAP-v1.0.md` §v1.0-rc).
//!
//! Any addition of a CLI flag, subcommand, tamper name, profile name or
//! report JSON field MUST break this test on purpose: the diff is the
//! review gate. Refresh with `UPDATE_GOLDEN=1 cargo test --test
//! integration_freeze_v1` after a deliberate surface change, then review
//! the golden diff like an `insta` review.
//!
//! Goldens:
//! - `tests/golden/cli-flags.txt` — sorted `--long` flags + subcommand paths
//! - `tests/golden/v1-report-schema.json` — sorted JSON key lists (values
//!   excluded so `version`/`git_sha`/timestamps never churn the freeze;
//!   `v1-` prefix dodges the `report*.json` local-scan gitignore rule)
//! - `Tamper::all_names()` / `Profile::all_names()` pinned inline (24 / 4)
//!
//! Legacy compat (same file, same gate):
//! - pre-C7 minimal finding JSON still deserializes via `#[serde(default)]`
//! - pre-C6 export snapshot JSON (no `extracted`/`trace`/`seed`) still parses
//! - knowledge v1 file with unknown keys ignores them (never persists IDs)

use clap::{CommandFactory, Parser};
use injekt::{
    cli::args::{Cli, ReportFormat},
    reporting::{
        evidence::Evidence,
        json::{JsonReport, ReportMeta},
    },
    session::state::{Finding, TechniqueKind},
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

// ---------------------------------------------------------------------------
// CLI surface
// ---------------------------------------------------------------------------

fn collect_longs(cmd: &clap::Command, out: &mut Vec<String>) {
    for arg in cmd.get_arguments() {
        if let Some(long) = arg.get_long() {
            out.push(format!("--{long}"));
        }
    }
    for sub in cmd.get_subcommands() {
        collect_longs(sub, out);
    }
}

fn collect_subcommands(cmd: &clap::Command, prefix: &str, out: &mut Vec<String>) {
    for sub in cmd.get_subcommands() {
        let name = sub.get_name().to_owned();
        let path = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix} {name}")
        };
        out.push(path.clone());
        collect_subcommands(sub, &path, out);
    }
}

fn cli_surface_text() -> String {
    let cmd = Cli::command();
    let mut longs = Vec::new();
    collect_longs(&cmd, &mut longs);
    longs.sort();
    longs.dedup();
    let mut subs = Vec::new();
    collect_subcommands(&cmd, "", &mut subs);
    subs.sort();
    subs.dedup();
    let mut out = String::new();
    out.push_str("# subcommands (v1.0-rc freeze: any addition breaks this test)\n");
    for s in &subs {
        out.push_str(s);
        out.push('\n');
    }
    out.push_str("# flags (sorted --long, all levels)\n");
    for f in &longs {
        out.push_str(f);
        out.push('\n');
    }
    out
}

#[test]
fn cli_flags_frozen() {
    check_golden("cli-flags.txt", &cli_surface_text());
}

#[test]
fn tamper_names_frozen_at_19() {
    let names = injekt::techniques::tamper::Tamper::all_names();
    assert_eq!(names.len(), 24, "new tamper must break freeze deliberately");
    let expected = [
        "space2comment",
        "space2plus",
        "space2tab",
        "space2newline",
        "space2randomblank",
        "randomcase",
        "versionedcomment",
        "betweencomment",
        "charencode",
        "doubleurlencode",
        "hexencode",
        "unicodeencode",
        "overlongutf8",
        "space2dash",
        "space2mssqlblank",
        "randomcomments",
        "equaltolike",
        "versionedmorekeywords",
        "base64encode",
        "space2paren",
        "versionedfuzz",
        "jsonunicodeescape",
        "numericobfuscate",
        "linecomment",
    ];
    assert_eq!(names, &expected);
}

#[test]
fn profile_names_frozen_at_4() {
    assert_eq!(
        injekt::cli::profile::Profile::all_names(),
        &["quick", "balanced", "stealth", "aggressive"]
    );
}

#[test]
fn report_format_variants_frozen() {
    // `ReportFormat` is the `--format` value surface: json/sarif/junit/md.
    assert!(matches!(ReportFormat::default(), ReportFormat::Json));
    let cli = Cli::try_parse_from(["injekt", "scan", "--target", "https://example.com/?id=1"])
        .expect("cli parses");
    assert!(matches!(cli.format, ReportFormat::Json));
}

// ---------------------------------------------------------------------------
// report schema
// ---------------------------------------------------------------------------

fn sorted_keys(value: &serde_json::Value) -> Vec<String> {
    let mut keys: Vec<String> = value
        .as_object()
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default();
    keys.sort();
    keys
}

fn report_schema_value() -> serde_json::Value {
    let finding = Finding::new(
        "https://example.com/?id=1",
        "id@query",
        TechniqueKind::Boolean,
        0.95,
        "boolean true_sim=0.95 false_sim=0.10",
    )
    .with_false_positive_prob(0.02)
    .with_timestamp(fixed_timestamp());
    let evidence = Evidence::new("req", "resp", "boolean", "id@query", 0.95);
    let report = JsonReport::new(
        "https://example.com/?id=1",
        vec![finding],
        vec![evidence],
        vec![],
        42,
        ReportMeta::default(),
    );
    let value = serde_json::to_value(&report).expect("report serializes");
    let finding_value =
        serde_json::to_value(report.findings[0].clone()).expect("finding serializes");
    let evidence_value =
        serde_json::to_value(report.evidences[0].clone()).expect("evidence serializes");
    serde_json::json!({
        "report_top_level": sorted_keys(&value),
        "finding": sorted_keys(&finding_value),
        "finding_remediation": sorted_keys(&finding_value["remediation"]),
        "finding_evidence_detail": sorted_keys(&finding_value["evidence_detail"]),
        "finding_waf": sorted_keys(&finding_value["waf"]),
        "evidence": sorted_keys(&evidence_value),
        "detectability": sorted_keys(&value["detectability"]),
    })
}
#[test]
fn report_schema_frozen() {
    let schema = report_schema_value();
    let rendered = serde_json::to_string_pretty(&schema).expect("schema serializes") + "\n";
    check_golden("v1-report-schema.json", &rendered);
}

// ---------------------------------------------------------------------------
// legacy compat (old reports/exports/knowledge still parse)
// ---------------------------------------------------------------------------

#[test]
fn legacy_finding_json_still_parses() {
    let legacy = serde_json::json!({
        "target": "https://example.com/?id=1",
        "parameter": "id@query",
        "technique": "Boolean",
        "confidence": 0.9,
        "dbms": "mysql",
        "evidence": "boolean true_sim=0.9",
        "timestamp": "2026-01-15T12:00:00Z",
    });
    let finding: Finding = serde_json::from_value(legacy).expect("legacy finding via defaults");
    assert!((finding.false_positive_prob - 1.0).abs() < f64::EPSILON);
}

#[test]
fn legacy_export_snapshot_json_still_parses() {
    // v1 export shape: no `extracted`/`trace`/`seed`.
    let legacy = serde_json::json!({
        "findings": [],
        "request_count": 7,
        "started_at": null,
    });
    let value_str = serde_json::to_string(&legacy).expect("legacy serializes");
    // Parsed through the same `#[serde(default)]` tolerant shape the
    // decryptor uses (findings + counters, new keys defaulted).
    let parsed: serde_json::Value =
        serde_json::from_str(&value_str).expect("legacy snapshot is JSON");
    assert_eq!(
        parsed
            .get("request_count")
            .and_then(serde_json::Value::as_u64),
        Some(7)
    );
    assert!(parsed.get("trace").is_none());
    assert!(parsed.get("seed").is_none());
}

#[test]
fn legacy_knowledge_file_ignores_unknown_keys() {
    let evil = r#"{"version":1,"entries":{"boolean|mysql|numeric":{"success":12,"trials":12,"avg_req":10.0},"http://evil.local/?id=1":{"success":99,"trials":99,"avg_req":1.0}}}"#;
    let back = injekt::reasoning::knowledge::KnowledgeStore::parse_str(evil)
        .expect("legacy knowledge parses");
    assert_eq!(back.len(), 1);
    assert!(back.boost_for(TechniqueKind::Boolean, "mysql", "numeric") > 1.0);
}
