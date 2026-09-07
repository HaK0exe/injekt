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
            // MySQL XPATH channel: EXTRACTVALUE legacy + UPDATEXML variant.
            (
                r"(?i)XPATH syntax error|EXTRACTVALUE|UPDATEXML",
                "mysql_xpath",
            ),
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
                return ErrorResult {
                    is_vulnerable: true,
                    confidence: 0.9,
                    matched_pattern: Some(name.clone()),
                    extracted,
                };
            }
        }
        ErrorResult {
            is_vulnerable: false,
            confidence: 0.1,
            matched_pattern: None,
            extracted: None,
        }
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
}
