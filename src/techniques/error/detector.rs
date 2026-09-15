#![deny(unsafe_code)]

use regex::Regex;
use secrecy::SecretString;
use std::sync::OnceLock;

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ErrorResult {
    pub is_vulnerable: bool,
    pub confidence: f64,
    pub matched_pattern: Option<String>,
    /// Extracted version/error fragment — secret by design (`SecretString`,
    /// zeroized on drop). Never log raw; use
    /// `crate::session::scrubber::Scrubber::hash_truncated` for traceability
    /// and `Finding::scrubbed` / `push_extracted` for persistence.
    pub extracted: Option<SecretString>,
}

#[derive(Debug)]
pub struct ErrorDetector {
    patterns: Vec<(Regex, String)>,
}

impl Default for ErrorDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ErrorDetector {
    /// # Panics
    /// Panics if an internal static regex fails to compile (never happens in practice).
    #[must_use]
    pub fn new() -> Self {
        let patterns = vec![
            // MySQL XPATH strong: real DB error string. Requires the
            // `XPATH syntax error` phrase — a bare `EXTRACTVALUE` keyword is
            // NOT enough (it self-matches when the app reflects the payload
            // verbatim in `value="...payload..."`, cf. noxtools FP).
            (r"(?i)XPATH syntax error", "mysql_xpath"),
            // MySQL generic: syntax + BIGINT overflow (EXP) + JSON_KEYS.
            (
                r"(?i)SQL syntax.*MySQL|mysql_fetch|valid MySQL result|BIGINT UNSIGNED value is out of range|DOUBLE value is out of range|JSON_KEYS|invalid JSON text",
                "mysql_generic",
            ),
            // Postgres: explicit `invalid input syntax for type/integer`
            // (chr()||version() variant surfaces here) + legacy substrings.
            (
                r"(?i)PostgreSQL.*ERROR|pg_query|invalid input syntax for (type|integer)|cannot cast|invalid input syntax",
                "postgres",
            ),
            // P0-1 framework wrappers (2026): the DB error is wrapped in a
            // framework debug page. Conservative markers only (exception
            // class names). Ordered before the driver patterns so
            // attribution wins (e.g. `SqlException: Unclosed quotation
            // mark` attributes to aspnet, not bare mssql).
            // Django: django.db.utils.* (OperationalError/ProgrammingError).
            (
                r"(?i)django\.db\.utils\.(OperationalError|ProgrammingError|DatabaseError|IntegrityError|DataError)",
                "django",
            ),
            // Laravel: Illuminate QueryException (always paired with
            // SQLSTATE/driver text downstream).
            (r"(?i)Illuminate\\Database\\QueryException", "laravel"),
            // Rails: ActiveRecord + native driver errors.
            (
                r"(?i)ActiveRecord::StatementInvalid|PG::SyntaxError|Mysql2::Error|SQLite3::SQLException|ActiveRecord::JDBCError",
                "rails",
            ),
            // ASP.NET: SqlClient exception class (strong). The generic
            // `Server Error in '/' Application` yellow-screen is handled in
            // `evaluate()` with a SQL co-occurrence guard (too broad alone).
            (
                r"(?i)System\.Data\.SqlClient\.SqlException",
                "aspnet_sqlexception",
            ),
            // Node: Sequelize / TypeORM / Knex + MySQL driver codes.
            (
                r"(?i)Sequelize(DatabaseError|ConnectionError)|QueryFailedError|ER_PARSE_ERROR|ER_BAD_FIELD_ERROR",
                "node_sql",
            ),
            // MSSQL CONVERT/CAST channel: Msg 245 (Conversion failed) /
            // Msg 8114 (Error converting data type varchar to int).
            (
                r"(?i)Msg\s+(245|8114)|Conversion failed.*varchar|Error converting data type (varchar|nvarchar).*int|Syntax error converting.*varchar",
                "mssql_convert",
            ),
            // MSSQL generic: driver + FOR XML PATH variant.
            (
                r"(?i)ODBC SQL Server Driver|Unclosed quotation mark|Microsoft.*SQL Server|SQL Server.*error|FOR XML.*error",
                "mssql",
            ),
            // Oracle ORA-01722 specific (TO_NUMBER on string banner).
            (r"(?i)ORA-01722|invalid number", "oracle_number"),
            // Oracle generic: bare ORA-XXXXX alone + XMLType/XDB variants.
            (
                r"(?i)ORA-\d{5}|Oracle error|quoted string not properly terminated|XMLType|DBMS_XDB|ORA-06502",
                "oracle",
            ),
            // SQLite (P0-3): integer-overflow `abs()` channel + malformed
            // `json_extract` + sqlite3 driver / sqlite_master markers.
            (
                r"(?i)integer overflow|malformed JSON|unrecognized token|sqlite3\.|sqlite_master|SQLITE_ERROR",
                "sqlite",
            ),
            (r"(?i)SQLSTATE\[\w+\]|ODBC.*Driver|JDBC.*error", "generic"),
            // Lowest priority: bare product-name + version banner with no
            // accompanying error phrase (e.g. a verbose footer/status page
            // leaking the backend version). Still a real disclosure, just
            // weaker signal than an actual driver/syntax error above it.
            (
                r"(?i)(?:MySQL|PostgreSQL|Microsoft SQL Server|Oracle).*?\d+\.\d+",
                "version_banner",
            ),
        ];
        let compiled = patterns
            .into_iter()
            .map(|(p, name)| {
                #[allow(clippy::expect_used)]
                let re = Regex::new(p).expect("static error pattern regex");
                (re, name.to_owned())
            })
            .collect();
        Self { patterns: compiled }
    }

    #[must_use]
    pub fn evaluate(&self, body: &str) -> ErrorResult {
        for (re, name) in &self.patterns {
            if re.is_match(body) {
                let extracted = extract_version(body);
                // Strong error phrase with a quoted version fragment is a
                // confirmed error-based signal (0.9). Same phrase without an
                // extractable fragment is weaker (0.75) — still reported but
                // flagged for boolean confirmation downstream.
                let confidence = if extracted.is_some() { 0.9 } else { 0.75 };
                return ErrorResult {
                    is_vulnerable: true,
                    confidence,
                    matched_pattern: Some(name.clone()),
                    extracted,
                };
            }
        }
        // Weak-only: bare EXTRACTVALUE/UPDATEXML keyword with NO `XPATH
        // syntax error` phrase. This is the noxtools FP shape — the app
        // reflects the payload verbatim (`value="...extractvalue...">`)
        // without any DB error. Never a finding on its own.
        if is_aspnet_yellow_screen(body) {
            return ErrorResult {
                is_vulnerable: true,
                confidence: 0.75,
                matched_pattern: Some("aspnet_server_error".to_owned()),
                extracted: extract_version(body),
            };
        }
        if contains_xpath_keyword(body) {
            return ErrorResult {
                is_vulnerable: false,
                confidence: 0.3,
                matched_pattern: Some("mysql_xpath_reflected".to_owned()),
                extracted: None,
            };
        }
        ErrorResult {
            is_vulnerable: false,
            confidence: 0.1,
            matched_pattern: None,
            extracted: None,
        }
    }

    /// Context-aware evaluation: baseline veto + reflected-payload masking.
    ///
    /// - If the baseline already matches an error pattern, the candidate is
    ///   not a new signal (footer/banner FP) → not vulnerable.
    /// - If the candidate only matches because the sent payload is reflected
    ///   verbatim, masking the reflection removes the match → not vulnerable.
    /// - Otherwise delegates to [`Self::evaluate`] on the masked body so the
    ///   returned `extracted` fragment provably comes from DB output, not
    ///   from the echoed payload.
    #[must_use]
    pub fn evaluate_with_context(
        &self,
        baseline_body: &str,
        candidate_body: &str,
        sent_payload: &str,
    ) -> ErrorResult {
        let raw = self.evaluate(candidate_body);
        if !raw.is_vulnerable {
            return raw;
        }
        // Baseline veto: same error already present without injection
        // (e.g. verbose footer `MySQL 5.7`, generic `SQL error` template).
        if self.evaluate(baseline_body).is_vulnerable {
            return ErrorResult {
                is_vulnerable: false,
                confidence: 0.15,
                matched_pattern: raw.matched_pattern.map(|p| format!("baseline_veto:{p}")),
                extracted: None,
            };
        }
        if sent_payload.is_empty() {
            return raw;
        }
        let masked = mask_reflected(candidate_body, sent_payload);
        // Avoid an extra regex pass when nothing was reflected.
        if masked.len() == candidate_body.len() {
            return raw;
        }
        let masked_res = self.evaluate(&masked);
        if !masked_res.is_vulnerable {
            return ErrorResult {
                is_vulnerable: false,
                confidence: 0.25,
                matched_pattern: raw.matched_pattern.map(|p| format!("reflected:{p}")),
                extracted: None,
            };
        }
        masked_res
    }
}

/// Bare `EXTRACTVALUE` / `UPDATEXML` keyword probe (case-insensitive).
/// Used to distinguish a reflected payload echo from a real `XPATH syntax
/// error` DB message.
#[must_use]
pub fn contains_xpath_keyword(body: &str) -> bool {
    let lower = body.to_ascii_lowercase();
    lower.contains("extractvalue") || lower.contains("updatexml")
}

/// ASP.NET yellow-screen guard: `Server Error in '/' Application` alone is
/// too broad (any unhandled exception — the phrase itself contains "error",
/// so generic tokens must NOT count). Only SQL-specific co-occurrence
/// tokens qualify.
#[must_use]
pub fn is_aspnet_yellow_screen(body: &str) -> bool {
    let lower = body.to_ascii_lowercase();
    if !lower.contains("server error in '/' application") {
        return false;
    }
    [
        "sql",
        "syntax",
        "ora-",
        "msg ",
        "sqlstate",
        "sqlexception",
        "odbc",
        "jdbc",
        "unclosed quotation",
    ]
    .iter()
    .any(|t| lower.contains(t))
}

/// Case-insensitive check whether the sent payload is reflected verbatim
/// (or HTML-entity encoded) in the response body. Used for evidence only;
/// the veto itself goes through [`mask_reflected`].
#[must_use]
pub fn is_payload_reflected(body: &str, sent_payload: &str) -> bool {
    if sent_payload.is_empty() || body.is_empty() {
        return false;
    }
    let body_lower = body.to_ascii_lowercase();
    let payload_lower = sent_payload.to_ascii_lowercase();
    if body_lower.contains(&payload_lower) {
        return true;
    }
    // Token-level fallback: server may truncate/escape the full payload but
    // still echo the distinctive function name (observed noxtools shape:
    // `value="...extractvalue(1,concat(0x7e,version()))..."`).
    for token in ["extractvalue", "updatexml"] {
        if payload_lower.contains(token) && body_lower.contains(token) {
            return true;
        }
    }
    false
}

/// Remove case-insensitive occurrences of the sent payload (plus common
/// HTML-entity encoded variants) from the response body.
///
/// The error detector must never match its own echoed payload: a response
/// like `<input value="' AND EXTRACTVALUE...">` contains the keyword but no
/// DB error. Masking before matching turns that FP into a clean negative
/// while preserving a real `XPATH syntax error: '~5.7~'` fragment (which is
/// DB output, not part of the sent payload).
#[must_use]
pub fn mask_reflected(body: &str, sent_payload: &str) -> String {
    if sent_payload.is_empty() || body.is_empty() {
        return body.to_owned();
    }
    let variants = payload_variants(sent_payload);
    let mut out = body.to_owned();
    for variant in &variants {
        if variant.is_empty() {
            continue;
        }
        out = case_insensitive_remove(&out, variant);
        if out.is_empty() {
            break;
        }
    }
    out
}

/// Original payload plus HTML-entity encoded reflections
/// (`htmlspecialchars`-style echo in `value="..."` attributes).
fn payload_variants(payload: &str) -> Vec<String> {
    let mut variants = Vec::with_capacity(3);
    variants.push(payload.to_owned());
    // `&` first to avoid double-encoding.
    let html = payload
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;");
    if html != payload {
        variants.push(html);
    }
    let html39 = payload.replace('&', "&amp;").replace('\'', "&#39;");
    if html39 != payload && !variants.contains(&html39) {
        variants.push(html39);
    }
    variants
}

/// Case-insensitive removal of `needle` from `haystack` via an escaped
/// regex. Falls back to the unmodified body if the regex fails to compile
/// (arbitrary payload input must never panic the detector).
fn case_insensitive_remove(haystack: &str, needle: &str) -> String {
    let pattern = format!("(?i){}", regex::escape(needle));
    match Regex::new(&pattern) {
        Ok(re) => re.replace_all(haystack, "").into_owned(),
        Err(_) => haystack.to_owned(),
    }
}

/// Extract a version/error fragment as [`SecretString`].
///
/// Priority (first hit wins). Specific, quoted-value extractions run before
/// the generic legacy fallback: a body like `invalid input syntax for type
/// integer: "PostgreSQL 14.5"` matches *both* the legacy `PostgreSQL … X.Y`
/// regex (which would wrongly capture just `14.5"`, dropping the `PostgreSQL`
/// prefix and picking up the trailing quote) and the PG-specific quoted-value
/// regex (which correctly captures the full `PostgreSQL 14.5`) — the
/// specific one must win.
/// 1. `XPATH syntax error: '~…~'` quoted value (UPDATEXML/EXTRACTVALUE)
/// 2. PG `invalid input syntax for type integer: "…"` quoted value
/// 3. MSSQL `converting the varchar value '…'` quoted value (Msg 245/8114)
/// 4. bare `ORA-XXXXX…` line (ORA-01722 et al. alone)
/// 5. bare `Msg 245|8114…` line
/// 6. legacy fallback: `MySQL|PostgreSQL|Microsoft SQL Server|Oracle … X.Y…`
///    (bare version banners with no quoted/structured context)
fn extract_version(body: &str) -> Option<SecretString> {
    static LEGACY_RE: OnceLock<Regex> = OnceLock::new();
    static XPATH_RE: OnceLock<Regex> = OnceLock::new();
    static PG_RE: OnceLock<Regex> = OnceLock::new();
    static MSSQL_VAL_RE: OnceLock<Regex> = OnceLock::new();
    static ORA_RE: OnceLock<Regex> = OnceLock::new();
    static MSG_RE: OnceLock<Regex> = OnceLock::new();

    #[allow(clippy::expect_used)]
    let xpath = XPATH_RE.get_or_init(|| {
        Regex::new(r#"XPATH syntax error:\s*['"]([^'"<]+)['"]"#).expect("xpath version regex")
    });
    if let Some(c) = xpath.captures(body)
        && let Some(m) = c.get(1)
    {
        return Some(SecretString::from(m.as_str().to_owned()));
    }

    #[allow(clippy::expect_used)]
    let pg = PG_RE.get_or_init(|| {
        Regex::new(r#"(?i)invalid input syntax for (?:type|integer)[^:]*:\s*["']([^"']+)["']"#)
            .expect("pg version regex")
    });
    if let Some(c) = pg.captures(body)
        && let Some(m) = c.get(1)
    {
        return Some(SecretString::from(m.as_str().to_owned()));
    }

    #[allow(clippy::expect_used)]
    let mssql_val = MSSQL_VAL_RE.get_or_init(|| {
        Regex::new(r#"(?i)converting the (?:varchar|nvarchar) value\s*['"]([^'"]+)['"]"#)
            .expect("mssql value regex")
    });
    if let Some(c) = mssql_val.captures(body)
        && let Some(m) = c.get(1)
    {
        return Some(SecretString::from(m.as_str().to_owned()));
    }

    #[allow(clippy::expect_used)]
    let ora =
        ORA_RE.get_or_init(|| Regex::new(r"(?i)(ORA-\d{5}[^\n<]{0,200})").expect("ora code regex"));
    if let Some(c) = ora.captures(body)
        && let Some(m) = c.get(1)
    {
        return Some(SecretString::from(m.as_str().trim().to_owned()));
    }

    #[allow(clippy::expect_used)]
    let msg = MSG_RE.get_or_init(|| {
        Regex::new(r"(?i)(Msg\s+(?:245|8114)[^\n<]{0,200})").expect("msg code regex")
    });
    if let Some(c) = msg.captures(body)
        && let Some(m) = c.get(1)
    {
        return Some(SecretString::from(m.as_str().trim().to_owned()));
    }

    #[allow(clippy::expect_used)]
    let legacy = LEGACY_RE.get_or_init(|| {
        Regex::new(r"(?i)((?:MySQL|PostgreSQL|Microsoft SQL Server|Oracle).*?\d+\.\d+[^<\s]*)")
            .expect("static version regex")
    });
    if let Some(c) = legacy.captures(body)
        && let Some(m) = c.get(1)
    {
        return Some(SecretString::from(m.as_str().to_owned()));
    }

    None
}

#[cfg(test)]
mod tests {
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
        let r =
            d.evaluate("Msg 8114, Level 16, State 5: Error converting data type varchar to int.");
        assert!(r.is_vulnerable);
        assert!(
            exposed(&r).is_some_and(|e| e.contains("8114")),
            "bare Msg code should be extracted, got {r:?}"
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
    fn mask_reflected_is_case_insensitive_and_html_aware() {
        let payload = "' AND EXTRACTVALUE(1,CONCAT(0x7e,@@version)) -- -";
        let body = r#"<input value="' AND extractvalue(1,concat(0x7e,@@version)) -- -" />"#;
        let masked = mask_reflected(body, payload);
        assert!(!contains_xpath_keyword(&masked), "masked: {masked}");
        assert!(is_payload_reflected(body, payload));
        assert!(!is_payload_reflected("<html>clean</html>", payload));
    }
}
