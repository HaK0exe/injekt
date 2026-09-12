#![allow(clippy::unwrap_used, clippy::expect_used)]
//! C1 bench-parser contract (`docs/ROADMAP-v1.0.md` §C1 + §v0.4).
//!
//! What this file pins, and why it lives in Rust rather than only in
//! `bench/runner/selftest.py`:
//!
//! - **Producer side (native):** the [`JsonReport`] JSON shape that
//!   `bench/runner/run.py::parse_injekt_report` consumes (`findings[]`,
//!   `request_count`, top-level `version/seed/profile/techniques/level/tampers`
//!   provenance). Built with the real report types, so a Rust-side rename
//!   breaks here first — not silently on the official runner.
//! - **Consumer side (subprocess):** sqlmap/ghauri fixtures (vuln + clean per
//!   tool) exercised against the *real* Python parsers via `python3 -c`,
//!   plus `run.py compare` on a v0.3-baseline vs v0.4-regressed history pair
//!   (expect `REGRESSION`, exit 1, N1/N2 FP warning) and the pure canary
//!   verdict helpers. Skipped gracefully when no Python interpreter exists
//!   (offline Rust-only environments); CI images all ship `python3`.
//! - **Ground truth schema:** `bench/runner/scenarios.toml` must stay
//!   well-formed (A1–A7 + N1–N2, `expected`/`negative` consistency, evasion
//!   tamper names known to [`Tamper`], URLs parseable).

use injekt::{
    reporting::json::{JsonReport, ReportMeta},
    session::{
        scrubber::Scrubber,
        state::{Finding, TechniqueKind},
    },
    target::url::TargetUrl,
    techniques::tamper::Tamper,
};
use std::io::Write;
use std::process::{Command, Stdio};

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// Absolute path to `bench/runner` (independent of test cwd).
fn runner_dir() -> String {
    format!("{}/bench/runner", env!("CARGO_MANIFEST_DIR"))
}

/// Probe for a Python interpreter; `None` means "skip python-backed checks".
fn python_bin() -> Option<String> {
    for bin in ["python3", "python"] {
        let ok = Command::new(bin)
            .arg("--version")
            .output()
            .is_ok_and(|o| o.status.success());
        if ok {
            return Some(bin.to_owned());
        }
    }
    None
}

/// Run `code` with `bench/runner` on `sys.path`, feeding `stdin_text` on stdin.
/// Returns parsed stdout JSON, or `None` on any failure (caller skips).
fn eval_runner(code: &str, stdin_text: &str) -> Option<serde_json::Value> {
    let py = python_bin()?;
    let prelude = format!(
        "import sys, json; sys.path.insert(0, {}); import run as R; ",
        serde_json::to_string(&runner_dir()).expect("runner dir serializes")
    );
    let mut child = Command::new(py)
        .args(["-c", &format!("{prelude}{code}")])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    child
        .stdin
        .as_mut()
        .expect("piped stdin")
        .write_all(stdin_text.as_bytes())
        .ok()?;
    let out = child.wait_with_output().ok()?;
    if !out.status.success() {
        return None;
    }
    serde_json::from_slice(&out.stdout).ok()
}

macro_rules! require_python_json {
    ($expr:expr) => {
        match $expr {
            Some(v) => v,
            None => {
                eprintln!("SKIP: no working python3 interpreter for runner parsers");
                return;
            }
        }
    };
}

/// Unique scratch dir per test (no `tempfile` crate in dev-deps; std only).
fn scratch_dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "injekt-bench-{}-{}-{}",
        name,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

fn vuln_report() -> JsonReport {
    let mut finding = Finding::new(
        "http://127.0.0.1:8000/api/users?id=1",
        "id@query",
        TechniqueKind::Boolean,
        0.74,
        "TRUE≈baseline, FALSE≠baseline",
    );
    finding.dbms = Some("mysql".to_owned());
    let meta = ReportMeta::current(
        Some(42),
        Some("stealth".to_owned()),
        vec!["boolean".to_owned()],
        1,
        vec!["space2comment".to_owned()],
    );
    JsonReport::new(
        "http://127.0.0.1:8000/api/users?id=1",
        vec![finding],
        Vec::new(),
        Vec::new(),
        143,
        meta,
    )
}

// ---------------------------------------------------------------------------
// producer side: injekt JSON report contract (native)
// ---------------------------------------------------------------------------

/// The exact keys `parse_injekt_report` reads must be present and typed.
#[test]
fn injekt_vuln_report_matches_runner_contract() {
    let value: serde_json::Value =
        serde_json::from_str(&vuln_report().to_json(&Scrubber::new(false)))
            .expect("report serializes to JSON");
    let findings = value["findings"].as_array().expect("findings is a list");
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0]["parameter"], "id@query");
    assert_eq!(findings[0]["technique"], "Boolean");
    assert_eq!(findings[0]["confidence"], 0.74);
    assert_eq!(findings[0]["dbms"], "mysql");
    assert_eq!(value["request_count"], 143);
    // Provenance consumed for history.jsonl rows.
    assert_eq!(value["seed"], 42);
    assert_eq!(value["profile"], "stealth");
    assert_eq!(value["techniques"], serde_json::json!(["boolean"]));
    assert_eq!(value["level"], 1);
    assert_eq!(value["tampers"], serde_json::json!(["space2comment"]));
    assert_eq!(value["version"], env!("CARGO_PKG_VERSION"));
}

/// Clean report: zero findings, but counters + provenance still present so the
/// runner records a valid negative-control row (N1/N2 need these, not nulls).
#[test]
fn injekt_clean_report_is_a_valid_negative_row() {
    let report = JsonReport::new(
        "http://127.0.0.1:8000/api/health?id=1",
        Vec::new(),
        Vec::new(),
        Vec::new(),
        50,
        ReportMeta::current(Some(7), None, vec!["boolean".to_owned()], 1, Vec::new()),
    );
    let value: serde_json::Value = serde_json::from_str(&report.to_json(&Scrubber::new(false)))
        .expect("report serializes to JSON");
    assert_eq!(value["findings"], serde_json::json!([]));
    assert_eq!(value["request_count"], 50);
    assert_eq!(value["seed"], 7);
    assert_eq!(value["version"], env!("CARGO_PKG_VERSION"));
}

/// Default meta keeps historical behaviour: version/level always emitted.
#[test]
fn injekt_meta_defaults_are_emitted() {
    let meta = ReportMeta::default();
    let report = JsonReport::new(
        "http://127.0.0.1/",
        Vec::new(),
        Vec::new(),
        Vec::new(),
        0,
        meta,
    );
    let value: serde_json::Value = serde_json::from_str(&report.to_json(&Scrubber::new(false)))
        .expect("report serializes to JSON");
    assert_eq!(value["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(value["level"], 1);
}

/// End-to-end across languages: the real `parse_injekt_report` reads a report
/// produced by the real Rust types (vuln detected, clean silent).
#[test]
fn injekt_reports_round_trip_through_python_parser() {
    let dir = scratch_dir("roundtrip");
    let vuln_path = dir.join("vuln.json");
    let clean_path = dir.join("clean.json");
    std::fs::write(&vuln_path, vuln_report().to_json(&Scrubber::new(false)))
        .expect("write vuln fixture");
    let clean = JsonReport::new(
        "http://127.0.0.1:8000/api/health?id=1",
        Vec::new(),
        Vec::new(),
        Vec::new(),
        50,
        ReportMeta::default(),
    );
    std::fs::write(&clean_path, clean.to_json(&Scrubber::new(false))).expect("write clean fixture");
    let code = format!(
        "print(json.dumps({{ \
           'vuln': R.parse_injekt_report({}), \
           'clean': R.parse_injekt_report({}) }}))",
        serde_json::to_string(&vuln_path.to_string_lossy()).expect("path serializes"),
        serde_json::to_string(&clean_path.to_string_lossy()).expect("path serializes"),
    );
    let v = require_python_json!(eval_runner(&code, ""));
    assert_eq!(v["vuln"]["detected"], true);
    assert_eq!(v["vuln"]["request_count"], 143);
    assert_eq!(v["vuln"]["confidence"], 0.74);
    assert_eq!(v["clean"]["detected"], false);
    assert_eq!(v["clean"]["request_count"], 50);
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// consumer side: sqlmap / ghauri log fixtures through the real parsers
// ---------------------------------------------------------------------------

const SQLMAP_VULN: &str = "sqlmap identified the following injection point(s) \
 with a total of 0 HTTP(s) requests:\n---\nParameter: id (GET)\n    \
 Type: boolean-based blind\n    Title: AND boolean-based blind - WHERE or HAVING clause\n    \
 Payload: id=1 AND 1234=1234\n    Type: time-based blind\n    \
 Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)\n---\n\
 [INFO] the back-end DBMS is MySQL\nback-end DBMS: MySQL >= 5.0.12\n";

const SQLMAP_CLEAN: &str = "[*] starting @ 12:00:00\n\
 [WARNING] GET parameter 'id' does not appear to be dynamic\n\
 [CRITICAL] all tested parameters do not appear to be injectable.\n";

const GHAURI_VULN: &str = "Ghauri v0.8.4 (https://github.com/r0oth3x49/ghauri)\n\
 ghauri identified the following injection point(s) with a total of 0 HTTP(s) requests:\n---\n\
 Parameter: id (GET)\n    Type: boolean-based blind\n    \
 Title: AND boolean-based blind - WHERE or HAVING clause\n---\n\
 [INFO] the back-end DBMS is PostgreSQL\n";

const GHAURI_CLEAN: &str = "Ghauri v0.8.4 (https://github.com/r0oth3x49/ghauri)\n\
 [WARNING] heuristic test shows that GET parameter 'id' might not be injectable\n\
 [CRITICAL] all tested parameters do not appear to be injectable.\n";

fn parse_log(tool_fn: &str, log: &str) -> Option<serde_json::Value> {
    eval_runner(
        &format!("print(json.dumps(R.{tool_fn}(sys.stdin.read())))"),
        log,
    )
}

#[test]
fn sqlmap_vuln_and_clean_logs_parse() {
    let vuln = require_python_json!(parse_log("parse_sqlmap", SQLMAP_VULN));
    assert_eq!(vuln["detected"], true);
    assert_eq!(vuln["techniques"], serde_json::json!(["boolean", "time"]));
    assert_eq!(vuln["params"], serde_json::json!(["id@get"]));
    assert_eq!(vuln["dbms"], serde_json::json!(["MySQL"]));
    assert!(vuln["confidence"].is_null());
    assert!(vuln["request_count"].is_null());

    let clean = require_python_json!(parse_log("parse_sqlmap", SQLMAP_CLEAN));
    assert_eq!(clean["detected"], false);
    assert_eq!(clean["techniques"], serde_json::json!([]));
}

#[test]
fn ghauri_vuln_and_clean_logs_parse() {
    let vuln = require_python_json!(parse_log("parse_ghauri", GHAURI_VULN));
    assert_eq!(vuln["detected"], true);
    assert_eq!(vuln["techniques"], serde_json::json!(["boolean"]));
    assert_eq!(vuln["dbms"], serde_json::json!(["PostgreSQL"]));

    let clean = require_python_json!(parse_log("parse_ghauri", GHAURI_CLEAN));
    assert_eq!(clean["detected"], false);
    assert_eq!(clean["techniques"], serde_json::json!([]));
}

/// All three parsers expose one normalized shape: the documented contract keys
/// (`detected`, `techniques`, `params`, `dbms`, `confidence`,
/// `request_count`, `elapsed_s`) are present in every parser output, with null
/// where the source has no such datum. Per-tool extras are allowed (`tool` on
/// sqlmap/ghauri, `parse_error` on injekt missing-file) — the contract is a
/// subset, not exact equality.
#[test]
fn all_three_parsers_share_one_normalized_shape() {
    let code = "print(json.dumps({ \
        'injekt_keys': sorted(R.parse_injekt_report('/nonexistent/x.json').keys()), \
        'sqlmap_keys': sorted(R.parse_sqlmap('clean').keys()), \
        'ghauri_keys': sorted(R.parse_ghauri('clean').keys()) }))";
    let v = require_python_json!(eval_runner(code, ""));
    let contract = [
        "detected",
        "techniques",
        "params",
        "dbms",
        "confidence",
        "request_count",
        "elapsed_s",
    ];
    for parser in ["injekt_keys", "sqlmap_keys", "ghauri_keys"] {
        let keys = v[parser].as_array().expect("key list");
        for key in contract {
            assert!(
                keys.contains(&serde_json::Value::String(key.to_owned())),
                "{parser} missing normalized key {key}: {keys:?}"
            );
        }
    }
    // sqlmap + ghauri share one core parser: exact same key set.
    assert_eq!(v["sqlmap_keys"], v["ghauri_keys"]);
}

// ---------------------------------------------------------------------------
// ground truth schema: scenarios.toml
// ---------------------------------------------------------------------------

/// `scenarios.toml` is the C1 ground truth — pin its schema in Rust so drift
/// (renamed id, dropped negative flag, unknown evasion tamper) fails `cargo
/// test`, not the official runner.
#[test]
fn scenarios_toml_schema_holds() {
    let path = format!("{}/bench/runner/scenarios.toml", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(&path).expect("scenarios.toml readable");
    let doc: toml::Value = toml::from_str(&text).expect("scenarios.toml parses");
    assert_eq!(doc["defaults"]["repeats"], toml::Value::Integer(5));
    assert_eq!(doc["defaults"]["seed"], toml::Value::Integer(42));
    let scenarios = doc["scenario"].as_array().expect("scenario list");
    let ids: Vec<&str> = scenarios
        .iter()
        .map(|s| s["id"].as_str().expect("scenario id is a string"))
        .collect();
    assert_eq!(
        ids,
        vec!["A1", "A2", "A3", "A4", "A5", "A6", "A7", "N1", "N2"],
        "scenario ids are frozen C1 ground truth"
    );
    for scen in scenarios {
        let id = scen["id"].as_str().expect("id");
        let url = scen["url"].as_str().expect("url");
        assert!(
            TargetUrl::parse(url, true).is_ok(),
            "{id}: url parses with lab-private hosts allowed"
        );
        let expected = scen["expected"].as_array().expect("expected list");
        let negative = scen
            .get("negative")
            .and_then(toml::Value::as_bool)
            .unwrap_or(false);
        if id.starts_with('N') {
            assert!(negative, "{id}: negative control must set negative=true");
            assert!(
                expected.is_empty(),
                "{id}: negative control expects no technique"
            );
        } else {
            assert!(!negative, "{id}: attack scenario must not be negative");
            assert!(
                !expected.is_empty(),
                "{id}: attack scenario needs expected techniques"
            );
        }
        if let Some(evasion) = scen.get("evasion").and_then(toml::Value::as_array) {
            for token in evasion {
                let name = token.as_str().expect("evasion token is a string");
                if name.starts_with("--") {
                    continue; // CLI flag token, not a tamper name
                }
                assert!(
                    Tamper::from_name(name).is_some(),
                    "{id}: evasion tamper {name} unknown to Tamper::from_name"
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// compare: v0.3 baseline vs v0.4-regressed candidate
// ---------------------------------------------------------------------------

fn history_line(
    run_id: &str,
    scenario: &str,
    detected: bool,
    tool_version: &str,
) -> serde_json::Value {
    serde_json::json!({
        "ts": "2026-09-09T12:00:00Z",
        "run_id": run_id,
        "tool": "injekt",
        "tool_version": tool_version,
        "scenario": scenario,
        "mode": "power",
        "arm": "stock",
        "repeat": 1,
        "seed": 42,
        "result": {
            "detected": detected,
            "techniques": if detected { serde_json::json!(["boolean"]) } else { serde_json::json!([]) },
            "params": if detected { serde_json::json!(["id@get"]) } else { serde_json::json!([]) },
            "dbms": [],
            "confidence": if detected { Some(0.7) } else { None },
            "request_count": 123,
            "elapsed_s": 23.4,
            "rc": 0
        },
        "report": "reports/x.json",
        "canary_intact": true,
        "request_count_match": true
    })
}

fn write_jsonl(path: &std::path::Path, rows: &[serde_json::Value]) {
    let mut text = String::new();
    for row in rows {
        text.push_str(&serde_json::to_string(row).expect("row serializes"));
        text.push('\n');
    }
    std::fs::write(path, text).expect("history fixture writable");
}

/// C1 `DoD`: `compare` on a v0.3 baseline vs a v0.4 candidate that misses A2 and
/// fires on N1 must print `REGRESSION`, exit 1, and warn about the N1 FP.
#[test]
fn compare_v03_vs_regressed_v04_is_regression_with_fp_warning() {
    let Some(py) = python_bin() else {
        eprintln!("SKIP: no working python3 interpreter for run.py compare");
        return;
    };
    let dir = scratch_dir("compare");
    let base = dir.join("v03.jsonl");
    let cand = dir.join("v04.jsonl");
    write_jsonl(
        &base,
        &[
            history_line("run-v03", "A1", true, "injekt 0.3.0"),
            history_line("run-v03", "A2", true, "injekt 0.3.0"),
            history_line("run-v03", "N1", false, "injekt 0.3.0"),
        ],
    );
    write_jsonl(
        &cand,
        &[
            history_line("run-v04", "A1", true, "injekt 0.4.0"),
            history_line("run-v04", "A2", false, "injekt 0.4.0"),
            history_line("run-v04", "N1", true, "injekt 0.4.0"),
        ],
    );
    let run_py = format!("{}/bench/runner/run.py", env!("CARGO_MANIFEST_DIR"));
    let out = Command::new(py)
        .args([
            run_py.as_str(),
            "compare",
            "--baseline",
            &base.to_string_lossy(),
            "--candidate",
            &cand.to_string_lossy(),
        ])
        .output()
        .expect("run.py compare executes");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "regression exits 1\n{stdout}");
    assert!(stdout.contains("REGRESSION"), "verdict printed\n{stdout}");
    assert!(stdout.contains("A2"), "missed scenario named\n{stdout}");
    assert!(
        stderr.contains("N1") && stderr.contains("false positive"),
        "N1 FP warning on stderr\n{stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// canary: destructive run is rejected
// ---------------------------------------------------------------------------

/// Destructive canary state must map to the run-REJECTED verdict (exit 3).
#[test]
fn destructive_canary_maps_to_rejected_verdict() {
    let v = require_python_json!(eval_runner(
        "print(json.dumps({ \
           'intact': R.canary_intact({'mysql': 'untouched', 'postgres': 'untouched', 'mssql': 'untouched'}), \
           'tripped': R.canary_intact({'mysql': 'MODIFIED', 'postgres': 'untouched', 'mssql': 'untouched'}), \
           'empty': R.canary_intact({}), \
           'verdict_ok': R.run_verdict({'arms': {'stock': {'repeats': [{'canary_intact': True}]}}}), \
           'verdict_bad': R.run_verdict({'arms': {'stock': {'repeats': [{'canary_intact': True}, {'canary_intact': False}]}}}) \
         }))",
        ""
    ));
    assert_eq!(v["intact"], true);
    assert_eq!(v["tripped"], false);
    assert_eq!(v["empty"], false);
    assert_eq!(v["verdict_ok"], 0);
    assert_eq!(v["verdict_bad"], 3);
}
