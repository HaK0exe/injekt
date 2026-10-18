//! Shared JSON error-signature table (P5 split of `json::detector`):
//! per-DBMS `(Regex, name, dbms)` patterns compiled once (`OnceLock`).

use regex::Regex;

pub(super) fn json_patterns() -> &'static [(Regex, &'static str, &'static str)] {
    use std::sync::OnceLock;
    static CELL: OnceLock<Vec<(Regex, &'static str, &'static str)>> = OnceLock::new();
    CELL.get_or_init(|| {
        let raw: &[(&str, &str, &str)] = &[
            (r"invalid json text", "mysql_json", "mysql"),
            (
                r"invalid input syntax for type json",
                "postgres_json",
                "postgres",
            ),
            (
                r"json text is not properly formatted",
                "mssql_json",
                "mssql",
            ),
            (r"ora-40442|ora-40454", "oracle_json_path", "oracle"),
            (
                r"ora-01722.*json|json.*ora-01722",
                "oracle_json_cast",
                "oracle",
            ),
        ];
        raw.iter()
            .filter_map(|(p, name, dbms)| {
                Regex::new(&format!("(?i){p}"))
                    .ok()
                    .map(|re| (re, *name, *dbms))
            })
            .collect()
    })
}
