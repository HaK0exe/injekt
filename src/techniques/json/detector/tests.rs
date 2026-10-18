use super::*;

#[test]
fn detects_mysql_json_error() {
    let d = JsonDetector::new();
    let r = d.evaluate_error("SQL error: Invalid JSON text in argument 1 to function json_extract");
    assert!(r.is_vulnerable);
    assert_eq!(r.dbms, Some("mysql".to_owned()));
    assert_eq!(r.channel, Some(JsonChannel::Error));
}

#[test]
fn detects_postgres_json_error() {
    let d = JsonDetector::new();
    let r = d.evaluate_error("ERROR: invalid input syntax for type json (SQLSTATE 22P02)");
    assert!(r.is_vulnerable);
    assert_eq!(r.dbms, Some("postgres".to_owned()));
}

#[test]
fn detects_mssql_json_error() {
    let d = JsonDetector::new();
    let r = d.evaluate_error("Msg 13609, Level 16, State 2: JSON text is not properly formatted.");
    assert!(r.is_vulnerable);
    assert_eq!(r.dbms, Some("mssql".to_owned()));
}

#[test]
fn detects_oracle_json_path_error() {
    let d = JsonDetector::new();
    let r = d.evaluate_error("ORA-40442: JSON path expression syntax error");
    assert!(r.is_vulnerable);
    assert_eq!(r.dbms, Some("oracle".to_owned()));
}

#[test]
fn echo_without_error_context_is_not_vuln() {
    let d = JsonDetector::new();
    // Page reflects the payload but the DB never errored.
    let r = d.evaluate_error("you searched for json_extract foo, results: none");
    assert!(!r.is_vulnerable);
}

#[test]
fn graphql_errors_message_passthrough_mysql() {
    let d = JsonDetector::new();
    let body = r#"{"errors":[{"message":"You have an error in your SQL syntax; check the manual for MySQL near '\"'"}]}"#;
    let r = d.evaluate_error(body);
    assert!(r.is_vulnerable, "{r:?}");
    assert_eq!(r.dbms, Some("mysql".to_owned()));
    assert_eq!(r.channel, Some(JsonChannel::Error));
}

#[test]
fn graphql_errors_message_passthrough_postgres() {
    let d = JsonDetector::new();
    let body =
        r#"{"errors":[{"message":"ERROR: invalid input syntax for type integer: \"abc\""}]}"#;
    let r = d.evaluate_error(body);
    assert!(r.is_vulnerable, "{r:?}");
    assert_eq!(r.dbms, Some("postgres".to_owned()));
}

#[test]
fn rest_sql_message_passthrough() {
    let d = JsonDetector::new();
    let body = r#"{"error":{"sqlMessage":"XPATH syntax error: '~5.7~'"}}"#;
    let r = d.evaluate_error(body);
    assert!(r.is_vulnerable, "{r:?}");
    assert_eq!(r.dbms, Some("mysql".to_owned()));
}

#[test]
fn graphql_extensions_sql_message_passthrough_oracle() {
    let d = JsonDetector::new();
    let body = r#"{"errors":[{"message":"fetch failed","extensions":{"exception":{"sqlMessage":"ORA-01722: invalid number"}}}]}"#;
    let r = d.evaluate_error(body);
    assert!(r.is_vulnerable, "{r:?}");
    assert_eq!(r.dbms, Some("oracle".to_owned()));
}

#[test]
fn benign_graphql_data_is_not_vuln() {
    let d = JsonDetector::new();
    let r = d.evaluate_error(r#"{"data":{"node":{"id":"1"}}}"#);
    assert!(!r.is_vulnerable, "{r:?}");
    let r2 = d.evaluate_error(r#"{"errors":[{"message":"field 'node' not found"}]}"#);
    assert!(!r2.is_vulnerable, "{r2:?}");
}

#[test]
fn extract_envelope_texts() {
    let texts = extract_json_error_texts(
        r#"{"errors":[{"message":"boom","extensions":{"sqlMessage":"ORA-1"}}]}"#,
    );
    assert!(texts.iter().any(|t| t == "boom"), "{texts:?}");
    assert!(texts.iter().any(|t| t == "ORA-1"), "{texts:?}");
    assert_eq!(extract_json_error_texts("not json {{{"), [] as [String; 0]);
    assert_eq!(
        extract_json_error_texts(r#"{"data":{"a":1}}"#),
        [] as [String; 0]
    );
}

#[test]
fn boolean_channel_matches_shared_detector() {
    let d = JsonDetector::new();
    let baseline = "welcome normal page id=1 content baseline 42";
    let r = d.evaluate_boolean(
        baseline,
        baseline,
        "completely different content — false branch unique marker 99",
        100.0,
        105.0,
        108.0,
    );
    assert!(r.is_vulnerable);
    assert!(r.confidence > 0.6);
}

#[test]
fn boolean_channel_no_fp_on_identical() {
    let d = JsonDetector::new();
    let baseline = "welcome normal page id=1 content baseline 42";
    let r = d.evaluate_boolean(baseline, baseline, baseline, 100.0, 101.0, 102.0);
    assert!(!r.is_vulnerable);
}

/// P1.2 — plancher `Some(m)` avec les deux branches dans la bande de
/// bruit : veto exposé (`noise_vetoed`), verdict non vulnérable ; sans
/// plancher (`None`), le flag reste faux.
#[test]
fn boolean_channel_match_ratio_vetoes_noise_band() {
    let d = JsonDetector::new();
    let base = (1..=20)
        .map(|i| format!("tok{i:02}"))
        .collect::<Vec<_>>()
        .join(" ");
    // TRUE ≈ baseline (+1 token → Jaccard 20/21 ≈ 0.952).
    let true_body = format!("{base} extra_true_marker");
    // FALSE dans la bande de bruit de m=0.8 (16 tokens partagés + 1
    // nouveau → 16/21 ≈ 0.762 ≥ 0.75), gap 0.19 > 0.15.
    let false_body = format!(
        "{} extra_false_marker",
        (1..=16)
            .map(|i| format!("tok{i:02}"))
            .collect::<Vec<_>>()
            .join(" ")
    );
    let vetoed = d.evaluate_boolean_with_match_ratio(
        &base,
        &true_body,
        &false_body,
        100.0,
        100.0,
        100.0,
        Some(0.8),
    );
    assert!(vetoed.noise_vetoed, "{vetoed:?}");
    assert!(!vetoed.is_vulnerable, "{vetoed:?}");
    let legacy = d.evaluate_boolean_with_match_ratio(
        &base,
        &true_body,
        &false_body,
        100.0,
        100.0,
        100.0,
        None,
    );
    assert!(!legacy.noise_vetoed, "{legacy:?}");
}
