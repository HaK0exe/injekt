#![deny(unsafe_code)]

/// MSSQL 2022 enumeration queries using sys and `information_schema`
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
    let limit = stop.saturating_sub(start);
    // Scalar-only oracle: aggregate to 1×1 via `STRING_AGG` over a paginated
    // subquery (rows `|`, columns `CHAR(31)`-joined client-side as `|`).
    if columns.is_empty() {
        format!(
            "SELECT * FROM [{db}].[dbo].[{table}] ORDER BY (SELECT NULL) OFFSET {start} ROWS FETCH NEXT 1 ROWS ONLY"
        )
    } else if columns.len() == 1 {
        let col = &columns[0];
        format!(
            "SELECT STRING_AGG([{col}], '|') FROM (SELECT [{col}] FROM [{db}].[dbo].[{table}] ORDER BY (SELECT NULL) OFFSET {start} ROWS FETCH NEXT {limit} ROWS ONLY) AS t"
        )
    } else {
        let concat = columns
            .iter()
            .map(|c| format!("CAST([{c}] AS NVARCHAR(MAX))"))
            .collect::<Vec<_>>()
            .join("+'|'+");
        format!(
            "SELECT STRING_AGG(row_data, '|') FROM (SELECT ({concat}) AS row_data FROM [{db}].[dbo].[{table}] ORDER BY (SELECT NULL) OFFSET {start} ROWS FETCH NEXT {limit} ROWS ONLY) AS t"
        )
    }
}

#[must_use]
pub fn count_rows(db: &str, table: &str) -> String {
    format!("SELECT COUNT(*) FROM [{db}].[dbo].[{table}]")
}
