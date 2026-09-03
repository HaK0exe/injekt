#![deny(unsafe_code)]

/// MySQL 8.x enumeration queries using `information_schema`
#[must_use]
pub fn list_databases() -> &'static str {
    "SELECT GROUP_CONCAT(schema_name ORDER BY schema_name) FROM information_schema.schemata WHERE schema_name NOT IN ('information_schema','mysql','performance_schema','sys')"
}

#[must_use]
pub fn list_tables(db: &str) -> String {
    format!(
        "SELECT GROUP_CONCAT(table_name ORDER BY table_name) FROM information_schema.tables WHERE table_schema='{db}' AND table_type='BASE TABLE'"
    )
}

#[must_use]
pub fn list_columns(db: &str, table: &str) -> String {
    format!(
        "SELECT GROUP_CONCAT(column_name ORDER BY ordinal_position) FROM information_schema.columns WHERE table_schema='{db}' AND table_name='{table}'"
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
    format!("SELECT {cols} FROM `{db}`.`{table}` LIMIT {limit} OFFSET {start}")
}

#[must_use]
pub fn count_rows(db: &str, table: &str) -> String {
    format!("SELECT COUNT(*) FROM `{db}`.`{table}`")
}
