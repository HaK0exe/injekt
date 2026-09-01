#![deny(unsafe_code)]

/// MSSQL 2022 enumeration queries using sys and information_schema
#[must_use]
pub fn list_databases() -> &'static str {
    "SELECT STRING_AGG(name, ',') FROM sys.databases WHERE name NOT IN ('master','tempdb','model','msdb')"
}

#[must_use]
pub fn list_tables(db: &str) -> String {
    format!(
        "SELECT STRING_AGG(TABLE_NAME, ',') FROM {db}.INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE='BASE TABLE'"
    )
}

#[must_use]
pub fn list_columns(db: &str, table: &str) -> String {
    format!(
        "SELECT STRING_AGG(COLUMN_NAME, ',') FROM {db}.INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME='{table}' ORDER BY ORDINAL_POSITION"
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
    format!(
        "SELECT {cols} FROM [{db}].[dbo].[{table}] ORDER BY (SELECT NULL) OFFSET {start} ROWS FETCH NEXT {limit} ROWS ONLY"
    )
}

#[must_use]
pub fn count_rows(db: &str, table: &str) -> String {
    format!("SELECT COUNT(*) FROM [{db}].[dbo].[{table}]")
}
