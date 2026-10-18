use super::extract::extract_version;
use super::{
    ErrorDetector, ErrorResult, contains_xpath_keyword, is_aspnet_yellow_screen, mask_reflected,
};
use regex::Regex;

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
            // (chr()||version() variant surfaces here) + legacy substrings +
            // `division by zero` (PortSwigger conditional-error payloads).
            (
                r"(?i)PostgreSQL.*ERROR|pg_query|invalid input syntax for (type|integer)|cannot cast|invalid input syntax|division by zero",
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
            // Msg 8114 (Error converting data type varchar to int) /
            // Msg 8134 (divide by zero, PortSwigger conditional-error).
            (
                r"(?i)Msg\s+(245|8114|8134)|Conversion failed.*varchar|Error converting data type (varchar|nvarchar).*int|Syntax error converting.*varchar|divide by zero",
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
