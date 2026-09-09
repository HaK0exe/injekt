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
    let limit = stop.saturating_sub(start);
    // Scalar-only oracle (`LENGTH((query))` / `ASCII(SUBSTRING(...))`): the
    // query must return exactly 1 row × 1 column. Multi-column / multi-row
    // `SELECT a,b … LIMIT n` fails with `1241 Operand should contain 1
    // column(s)`. Aggregate rows with `GROUP_CONCAT` over a paginated
    // subquery; columns joined with `0x1F`, rows with `0x1E`.
    if columns.is_empty() {
        // No `--column`: single-row probe (reliable only for single-column
        // tables; use `--column a,b` for a scalar multi-column dump).
        format!("SELECT * FROM `{db}`.`{table}` LIMIT 1 OFFSET {start}")
    } else if columns.len() == 1 {
        let col = &columns[0];
        format!(
            "SELECT GROUP_CONCAT(`{col}` SEPARATOR 0x1E) FROM (SELECT `{col}` FROM `{db}`.`{table}` LIMIT {limit} OFFSET {start}) AS t"
        )
    } else {
        let escaped: Vec<String> = columns.iter().map(|c| format!("`{c}`")).collect();
        let concat = escaped.join(",");
        format!(
            "SELECT GROUP_CONCAT(row_data SEPARATOR 0x1E) FROM (SELECT CONCAT_WS(0x1F,{concat}) AS row_data FROM `{db}`.`{table}` LIMIT {limit} OFFSET {start}) AS t"
        )
    }
}

#[must_use]
pub fn count_rows(db: &str, table: &str) -> String {
    format!("SELECT COUNT(*) FROM `{db}`.`{table}`")
}
