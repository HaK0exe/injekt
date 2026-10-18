use super::*;
use secrecy::ExposeSecret;

fn exposed(r: &ErrorResult) -> Option<String> {
    r.extracted.as_ref().map(|s| s.expose_secret().to_owned())
}

#[test]
fn detects_mysql_xpath() {
    let d = ErrorDetector::new();
    let r = d.evaluate("XPATH syntax error: '~5.7.32~'");
    assert!(r.is_vulnerable);
}

#[test]
fn detects_mysql_updatexml_variant() {
    let d = ErrorDetector::new();
    let r = d.evaluate("XPATH syntax error: '~8.0.33~' UPDATEXML(1,CONCAT(0x7e))");
    assert!(r.is_vulnerable);
    assert_eq!(r.matched_pattern.as_deref(), Some("mysql_xpath"));
    assert!(
        exposed(&r).is_some_and(|e| e.contains("8.0.33")),
        "xpath quoted value should be extracted"
    );
}

#[test]
fn detects_mysql_bigint_overflow() {
    let d = ErrorDetector::new();
    let r = d.evaluate("BIGINT UNSIGNED value is out of range in 'exp(~(select * ...))'");
    assert!(r.is_vulnerable);
    assert_eq!(r.matched_pattern.as_deref(), Some("mysql_generic"));
}

#[test]
fn detects_mysql_json_keys() {
    let d = ErrorDetector::new();
    let r = d.evaluate("Invalid JSON text in argument 1 to function json_keys");
    assert!(r.is_vulnerable);
}

#[test]
fn detects_pg_invalid_input_syntax() {
    let d = ErrorDetector::new();
    let r = d.evaluate("ERROR: invalid input syntax for type integer: \"PostgreSQL 14.5\"");
    assert!(r.is_vulnerable);
    assert_eq!(r.matched_pattern.as_deref(), Some("postgres"));
    assert!(
        exposed(&r).is_some_and(|e| e.contains("PostgreSQL 14.5")),
        "pg quoted value should be extracted"
    );
}

#[test]
fn detects_pg_division_by_zero_conditional() {
    // PortSwigger conditional-error shape: `1/(SELECT 0)`.
    let d = ErrorDetector::new();
    let r = d.evaluate("ERROR: division by zero");
    assert!(r.is_vulnerable, "{r:?}");
    assert_eq!(r.matched_pattern.as_deref(), Some("postgres"));
}

#[test]
fn detects_pg_chr_variant_reports_postgres() {
    let d = ErrorDetector::new();
    let r = d.evaluate("ERROR: invalid input syntax for integer: \"~13.2~\" pg_query failed");
    assert!(r.is_vulnerable);
}

#[test]
fn detects_mssql_msg245_convert() {
    let d = ErrorDetector::new();
    let r = d.evaluate(
        "Msg 245, Level 16, State 1: Conversion failed when converting the varchar value '14.0' to data type int.",
    );
    assert!(r.is_vulnerable);
    assert_eq!(r.matched_pattern.as_deref(), Some("mssql_convert"));
    assert!(
        exposed(&r).is_some_and(|e| e.contains("14.0")),
        "mssql quoted varchar value should be extracted"
    );
}

#[test]
fn detects_mssql_msg8114() {
    let d = ErrorDetector::new();
    let r = d.evaluate("Msg 8114, Level 16, State 5: Error converting data type varchar to int.");
    assert!(r.is_vulnerable);
    assert!(
        exposed(&r).is_some_and(|e| e.contains("8114")),
        "bare Msg code should be extracted, got {r:?}"
    );
}

#[test]
fn detects_mssql_msg8134_divide_by_zero() {
    // PortSwigger conditional-error shape: `1/0` (Msg 8134).
    let d = ErrorDetector::new();
    let r = d.evaluate("Msg 8134, Level 16, State 1: Divide by zero error encountered.");
    assert!(r.is_vulnerable, "{r:?}");
    assert_eq!(r.matched_pattern.as_deref(), Some("mssql_convert"));
    assert!(
        exposed(&r).is_some_and(|e| e.contains("8134")),
        "bare Msg 8134 code should be extracted, got {r:?}"
    );
}

#[test]
fn detects_mssql_for_xml_path() {
    let d = ErrorDetector::new();
    let r = d.evaluate("SQL Server FOR XML error: unable to serialize @@version");
    assert!(r.is_vulnerable);
}

#[test]
fn detects_oracle_ora01722_alone() {
    let d = ErrorDetector::new();
    let r = d.evaluate("ORA-01722: invalid number");
    assert!(r.is_vulnerable);
    assert_eq!(r.matched_pattern.as_deref(), Some("oracle_number"));
    assert!(
        exposed(&r).is_some_and(|e| e.contains("ORA-01722")),
        "bare ORA- code should be extracted"
    );
}

#[test]
fn detects_oracle_bare_code_and_xmltype() {
    let d = ErrorDetector::new();
    let r = d.evaluate("ORA-06502: PL/SQL: numeric or value error");
    assert!(r.is_vulnerable);
    let r2 = d.evaluate("XMLType parsing failed for banner");
    assert!(r2.is_vulnerable);
}

#[test]
fn detects_sqlite_overflow_and_json() {
    let d = ErrorDetector::new();
    let r = d.evaluate("sqlite3.OperationalError: integer overflow");
    assert!(r.is_vulnerable, "{r:?}");
    assert_eq!(r.matched_pattern.as_deref(), Some("sqlite"));
    let r2 = d.evaluate("Error: malformed JSON in json_extract('__bad__')");
    assert!(r2.is_vulnerable, "{r2:?}");
    assert_eq!(r2.matched_pattern.as_deref(), Some("sqlite"));
    let r3 = d.evaluate("unrecognized token: \"'\" near line 1");
    assert!(r3.is_vulnerable, "{r3:?}");
    // Plain `no such column` without a sqlite token stays silent
    // (shared wording with other engines).
    let r4 = d.evaluate("welcome normal page id=1 no such column mentioned here");
    assert!(!r4.is_vulnerable, "{r4:?}");
}

#[test]
fn legacy_version_extraction_preserved() {
    let d = ErrorDetector::new();
    let r = d.evaluate("MySQL 5.7.32 community");
    assert!(r.is_vulnerable);
    assert!(
        exposed(&r).is_some_and(|e| e.contains("5.7.32")),
        "legacy MySQL version must still extract"
    );
    let r = d.evaluate("Microsoft SQL Server 2019 foo 15.0.2000.5 bar");
    assert!(exposed(&r).is_some_and(|e| e.contains("15.0.2000.5")));
    let r = d.evaluate("Oracle Database 19c Enterprise 19.0.0.0.0");
    assert!(exposed(&r).is_some_and(|e| e.contains("19.0.0.0.0")));
}

#[test]
fn detects_framework_wrappers() {
    let d = ErrorDetector::new();
    let cases = [
        (
            "django.db.utils.ProgrammingError: syntax error at or near \"'\"",
            "django",
        ),
        (
            "django.db.utils.OperationalError: (1054, \"Unknown column\")",
            "django",
        ),
        (
            "Illuminate\\Database\\QueryException SQLSTATE[42000]: Syntax error or access violation",
            "laravel",
        ),
        (
            "ActiveRecord::StatementInvalid: PG::SyntaxError: ERROR: syntax error",
            "rails",
        ),
        (
            "Mysql2::Error: You have an error in your SQL syntax",
            "rails",
        ),
        (
            "System.Data.SqlClient.SqlException: Unclosed quotation mark",
            "aspnet_sqlexception",
        ),
        (
            "SequelizeDatabaseError: You have an error in your SQL syntax",
            "node_sql",
        ),
        (
            "ER_PARSE_ERROR: You have an error in your SQL syntax",
            "node_sql",
        ),
    ];
    for (body, want) in cases {
        let r = d.evaluate(body);
        assert!(r.is_vulnerable, "FW marker must match: {body} -> {r:?}");
        assert_eq!(r.matched_pattern.as_deref(), Some(want), "{body}");
    }
}

#[test]
fn aspnet_yellow_screen_needs_sql_cooccurrence() {
    let d = ErrorDetector::new();
    let r = d.evaluate("Server Error in '/' Application. SqlException: syntax error near '\"");
    assert!(r.is_vulnerable, "{r:?}");
    assert_eq!(
        r.matched_pattern.as_deref(),
        Some("aspnet_server_error"),
        "{r:?}"
    );
    // Bare yellow-screen without SQL context must not match.
    let r2 = d.evaluate("Server Error in '/' Application. NullReference happened");
    assert!(
        !r2.is_vulnerable,
        "yellow-screen alone must not match: {r2:?}"
    );
    // Framework name-dropping without an exception class must not match.
    let r3 = d.evaluate("we wrote a blog post about django and laravel yesterday");
    assert!(!r3.is_vulnerable, "{r3:?}");
}

#[test]
fn pg18_mysql97_banners() {
    // P0-5 fixtures 2026: PG 18.6 / 17.5, MySQL 9.7.1 / 8.4.0 (additive only).
    let d = ErrorDetector::new();
    let r = d.evaluate("PostgreSQL 18.6 on x86_64-pc-linux-gnu");
    assert!(r.is_vulnerable, "PG 18.6 banner must match: {r:?}");
    assert!(
        exposed(&r).is_some_and(|e| e.contains("18.6")),
        "PG 18.6 version must extract: {r:?}"
    );
    let r = d.evaluate("PostgreSQL 17.5 on x86_64-pc-linux-gnu");
    assert!(r.is_vulnerable, "PG 17.5 banner must match: {r:?}");
    assert!(
        exposed(&r).is_some_and(|e| e.contains("17.5")),
        "PG 17.5 version must extract: {r:?}"
    );
    let r = d.evaluate("MySQL 9.7.1 community");
    assert!(r.is_vulnerable, "MySQL 9.7.1 banner must match: {r:?}");
    assert!(
        exposed(&r).is_some_and(|e| e.contains("9.7.1")),
        "MySQL 9.7.1 version must extract: {r:?}"
    );
    let r = d.evaluate("MySQL 8.4.0 LTS");
    assert!(r.is_vulnerable, "MySQL 8.4.0 banner must match: {r:?}");
    assert!(
        exposed(&r).is_some_and(|e| e.contains("8.4.0")),
        "MySQL 8.4.0 version must extract: {r:?}"
    );
}

#[test]
fn no_false_positive_on_normal_page() {
    let d = ErrorDetector::new();
    let r = d.evaluate("welcome normal page id=1 content baseline 42");
    assert!(!r.is_vulnerable);
    assert!(r.matched_pattern.is_none());
    assert!(r.extracted.is_none());
}

#[test]
fn extracted_is_secret_redacted_in_debug() {
    let d = ErrorDetector::new();
    let r = d.evaluate("ORA-01722: invalid number secret-banner-xyz");
    let dbg = format!("{r:?}");
    // SecretString Debug must not leak the raw banner fragment.
    assert!(!dbg.contains("secret-banner-xyz"), "{dbg}");
}

#[test]
fn bare_extractvalue_keyword_is_not_a_finding() {
    // noxtools FP: payload echoed verbatim, no DB error phrase.
    let d = ErrorDetector::new();
    let r = d.evaluate("' AND EXTRACTVALUE(1,CONCAT(0x7e,@@version)) -- -");
    assert!(
        !r.is_vulnerable,
        "bare keyword must not be vulnerable: {r:?}"
    );
    assert!(r.confidence < 0.6, "weak signal only: {r:?}");
    assert_eq!(r.matched_pattern.as_deref(), Some("mysql_xpath_reflected"));
}

#[test]
fn bare_updatexml_keyword_is_not_a_finding() {
    let d = ErrorDetector::new();
    let r = d.evaluate("' AND UPDATEXML(1,CONCAT(0x7e,@@version,0x7e),1) -- -");
    assert!(!r.is_vulnerable, "{r:?}");
}

#[test]
fn reflected_payload_echo_is_not_a_finding() {
    // Exact noxtools shape: `value="...payload..."` attribute echo.
    let d = ErrorDetector::new();
    let payload = "' AND EXTRACTVALUE(1,CONCAT(0x7e,@@version)) -- -";
    let body = format!(
        r#"<input name="amember_login" value="{payload}" autocomplete="username" /><div class="alert alert-error"></div>"#
    );
    let r = d.evaluate_with_context("<html>login baseline</html>", &body, payload);
    assert!(!r.is_vulnerable, "reflected echo must veto: {r:?}");
    // Two valid non-vulnerable outcomes: weak direct (`mysql_xpath_reflected`
    // when the echo is the only signal) or masked veto (`reflected:...`
    // when a strong pattern collapses after masking).
    assert!(
        r.matched_pattern
            .as_deref()
            .is_some_and(|p| p == "mysql_xpath_reflected" || p.starts_with("reflected:")),
        "veto reason must be visible: {r:?}"
    );
}

#[test]
fn reflected_strong_phrase_is_vetoed_after_masking() {
    // Attacker-controlled `XPATH syntax error` string echoed without DB.
    let d = ErrorDetector::new();
    let payload = "XPATH syntax error";
    let body = format!(r#"<input value="{payload}" /><div>normal</div>"#);
    let r = d.evaluate_with_context("<html>baseline</html>", &body, payload);
    assert!(!r.is_vulnerable, "{r:?}");
    assert_eq!(r.matched_pattern.as_deref(), Some("reflected:mysql_xpath"));
}

#[test]
fn real_xpath_error_survives_masking() {
    let d = ErrorDetector::new();
    let payload = "' AND EXTRACTVALUE(1,CONCAT(0x7e,@@version)) -- -";
    let body = format!(r#"<input value="{payload}" />XPATH syntax error: '~5.7.32~'"#);
    let r = d.evaluate_with_context("<html>login baseline</html>", &body, payload);
    assert!(r.is_vulnerable, "real DB error must survive masking: {r:?}");
    assert_eq!(r.matched_pattern.as_deref(), Some("mysql_xpath"));
    assert!(
        exposed(&r).is_some_and(|e| e.contains("5.7.32")),
        "version fragment must come from DB output: {r:?}"
    );
}

#[test]
fn baseline_error_vetoes_footer_fp() {
    let d = ErrorDetector::new();
    let baseline = "Powered by MySQL 5.7.32 community footer";
    let candidate = "Powered by MySQL 5.7.32 community footer";
    let r = d.evaluate_with_context(baseline, candidate, "' AND 1=1 -- -");
    assert!(!r.is_vulnerable, "baseline error is not new signal: {r:?}");
    assert!(
        r.matched_pattern
            .as_deref()
            .is_some_and(|p| p.starts_with("baseline_veto:")),
        "{r:?}"
    );
}

#[test]
fn xpath_without_quoted_value_is_downgraded() {
    let d = ErrorDetector::new();
    let r = d.evaluate("XPATH syntax error occurred");
    assert!(r.is_vulnerable);
    assert!(
        (r.confidence - 0.75).abs() < f64::EPSILON,
        "strong phrase without fragment is 0.75, got {}",
        r.confidence
    );
}

#[test]
fn classify_cast_error_detects_db_and_app_phrases() {
    // Postgres CAST channel (also emitted by app-side integer parsing).
    assert!(classify_cast_error(
        r#"ERROR: invalid input syntax for type integer: "~14.6~""#
    ));
    assert!(classify_cast_error(
        r#"ERROR: invalid input syntax for integer: "zabc""#
    ));
    // MSSQL Msg 245 / 8114 conversion channel.
    assert!(classify_cast_error(
        "Msg 245, Level 16, State 1: Conversion failed when converting the varchar value 'zX' to data type int."
    ));
    assert!(classify_cast_error(
        "Msg 8114, Level 16, State 5: Error converting data type varchar to int."
    ));
    // Bare Msg codes (no surrounding sentence) still classify.
    assert!(classify_cast_error("Msg 8114"));
    assert!(classify_cast_error("msg 245"));
    // MySQL strict-mode conversion messages.
    assert!(classify_cast_error(
        "Incorrect integer value: 'zX' for column 'id' at row 1"
    ));
    assert!(classify_cast_error(
        "Truncated incorrect DOUBLE value: 'zX'"
    ));
    assert!(classify_cast_error(
        "Out of range value for column 'id' at row 1"
    ));
    // Java / .NET / Python application-level type parsers.
    assert!(classify_cast_error(
        r#"java.lang.NumberFormatException: For input string: "zX""#
    ));
    assert!(classify_cast_error(
        "javax.persistence.TypeMismatchException: could not convert"
    ));
    assert!(classify_cast_error(
        "System.FormatException: Input string was not in a correct format."
    ));
    assert!(classify_cast_error(
        "ValueError: invalid literal for int() with base 10: 'zX'"
    ));
    // SQLite / generic ORM wording.
    assert!(classify_cast_error("datatype mismatch"));
    assert!(classify_cast_error("value cannot be converted to a number"));
    assert!(classify_cast_error("column id is not of type numeric"));
}

#[test]
fn classify_cast_error_ignores_normal_syntax_and_arithmetic_bodies() {
    // Normal page: no signature.
    assert!(!classify_cast_error(
        "welcome normal page id=1 content baseline 42"
    ));
    // Pure SQL syntax error is NOT a cast/type error (veto must not fire).
    assert!(!classify_cast_error(
        "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version"
    ));
    // Arithmetic (divide by zero) is not a conversion error either.
    assert!(!classify_cast_error(
        "Msg 8134, Level 16, State 1: Divide by zero error encountered."
    ));
    assert!(!classify_cast_error("ERROR: division by zero"));
    // Non-panic on empty / degenerate input.
    assert!(!classify_cast_error(""));
    assert!(!classify_cast_error("\u{0}\u{feff}<>"));
}

#[test]
fn mask_reflected_is_case_insensitive_and_html_aware() {
    let payload = "' AND EXTRACTVALUE(1,CONCAT(0x7e,@@version)) -- -";
    let body = r#"<input value="' AND extractvalue(1,concat(0x7e,@@version)) -- -" />"#;
    let masked = mask_reflected(body, payload);
    assert!(!contains_xpath_keyword(&masked), "masked: {masked}");
    assert!(is_payload_reflected(body, payload));
    assert!(!is_payload_reflected("<html>clean</html>", payload));
}
