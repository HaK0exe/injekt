#![deny(unsafe_code)]

/// Postgres 15+ enumeration queries using `information_schema` and `pg_catalog`
#[must_use]
pub fn list_databases() -> &'static str {
    "SELECT string_agg(datname, ',' ORDER BY datname) FROM pg_database WHERE datistemplate = false AND datname NOT IN ('postgres','template0','template1')"
}

#[must_use]
pub fn list_tables(db: &str) -> String {
    format!(
        "SELECT string_agg(table_name, ',' ORDER BY table_name) FROM information_schema.tables WHERE table_schema='public' AND table_catalog='{db}' AND table_type='BASE TABLE'"
    )
}

#[must_use]
pub fn list_columns(db: &str, table: &str) -> String {
    format!(
        "SELECT string_agg(column_name, ',' ORDER BY ordinal_position) FROM information_schema.columns WHERE table_schema='public' AND table_catalog='{db}' AND table_name='{table}'"
    )
}

#[must_use]
pub fn dump_table(db: &str, table: &str, columns: &[String], start: usize, stop: usize) -> String {
    let _ = db;
    let limit = stop.saturating_sub(start);
    // Scalar-only oracle: aggregate to 1×1. NOTE: `db` is the catalog and
    // cannot appear in `FROM` (`"db"."table"` would resolve `db` as a schema
    // and fail); the table lives in schema `public` on the current connection.
    if columns.is_empty() {
        format!("SELECT * FROM \"public\".\"{table}\" LIMIT 1 OFFSET {start}")
    } else if columns.len() == 1 {
        let col = &columns[0];
        format!(
            "SELECT string_agg(\"{col}\", chr(30)) FROM (SELECT \"{col}\" FROM \"public\".\"{table}\" LIMIT {limit} OFFSET {start}) AS t"
        )
    } else {
        let concat = columns
            .iter()
            .map(|c| format!("\"{c}\""))
            .collect::<Vec<_>>()
            .join("||chr(31)||");
        format!(
            "SELECT string_agg(row_data, chr(30)) FROM (SELECT ({concat}) AS row_data FROM \"public\".\"{table}\" LIMIT {limit} OFFSET {start}) AS t"
        )
    }
}

#[must_use]
pub fn count_rows(db: &str, table: &str) -> String {
    let _ = db;
    format!("SELECT COUNT(*) FROM \"public\".\"{table}\"")
}
