#![deny(unsafe_code)]

/// SQLite enumeration queries using `sqlite_master` / `pragma_table_info`.
/// SQLite has no `information_schema` and a single `main` database, so `db`
/// is accepted for trait parity and ignored.
#[must_use]
pub fn list_databases() -> &'static str {
    "SELECT 'main'"
}

#[must_use]
pub fn list_tables(_db: &str) -> String {
    "SELECT group_concat(tbl_name) FROM sqlite_master WHERE type='table' AND tbl_name NOT LIKE 'sqlite_%'".to_owned()
}

#[must_use]
pub fn list_columns(_db: &str, table: &str) -> String {
    format!("SELECT group_concat(name) FROM pragma_table_info('{table}')")
}

#[must_use]
pub fn dump_table(_db: &str, table: &str, columns: &[String], start: usize, stop: usize) -> String {
    let limit = stop.saturating_sub(start);
    // Scalar-only oracle (`LENGTH((query))` / blind char extraction): exactly
    // 1 row × 1 column. `group_concat` aggregates rows; columns joined with
    // `char(31)` (0x1F), rows are pre-paginated via `LIMIT/OFFSET`.
    if columns.is_empty() {
        format!("SELECT * FROM \"{table}\" LIMIT 1 OFFSET {start}")
    } else if columns.len() == 1 {
        let col = &columns[0];
        format!(
            "SELECT group_concat(\"{col}\", char(30)) FROM (SELECT \"{col}\" FROM \"{table}\" LIMIT {limit} OFFSET {start})"
        )
    } else {
        let concat = columns
            .iter()
            .map(|c| format!("\"{c}\""))
            .collect::<Vec<_>>()
            .join("||char(31)||");
        format!(
            "SELECT group_concat(row_data, char(30)) FROM (SELECT ({concat}) AS row_data FROM \"{table}\" LIMIT {limit} OFFSET {start})"
        )
    }
}

#[must_use]
pub fn count_rows(_db: &str, table: &str) -> String {
    format!("SELECT COUNT(*) FROM \"{table}\"")
}
