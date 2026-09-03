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
    let cols = if columns.is_empty() {
        "*".to_owned()
    } else {
        columns.join(",")
    };
    let limit = stop.saturating_sub(start);
    format!("SELECT {cols} FROM \"{db}\".\"{table}\" LIMIT {limit} OFFSET {start}")
}

#[must_use]
pub fn count_rows(db: &str, table: &str) -> String {
    format!("SELECT COUNT(*) FROM \"{db}\".\"{table}\"")
}
