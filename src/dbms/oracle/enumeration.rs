#![deny(unsafe_code)]

/// Oracle 21c enumeration queries using ALL_* views
#[must_use]
pub fn list_databases() -> &'static str {
    "SELECT LISTAGG(username, ',') WITHIN GROUP (ORDER BY username) FROM all_users WHERE username NOT IN ('SYS','SYSTEM','OUTLN','DBSNMP','APPQOSSYS','AUDSYS','GSMADMIN_INTERNAL','DBSFWUSER','XDB','ORDDATA','ORDPLUGINS','ORDSYS','WMSYS')"
}

#[must_use]
pub fn list_tables(db: &str) -> String {
    format!(
        "SELECT LISTAGG(table_name, ',') WITHIN GROUP (ORDER BY table_name) FROM all_tables WHERE owner='{db}'"
    )
}

#[must_use]
pub fn list_columns(db: &str, table: &str) -> String {
    format!(
        "SELECT LISTAGG(column_name, ',') WITHIN GROUP (ORDER BY column_id) FROM all_tab_columns WHERE owner='{db}' AND table_name='{table}'"
    )
}

#[must_use]
pub fn dump_table(db: &str, table: &str, columns: &[String], start: usize, stop: usize) -> String {
    let limit = stop.saturating_sub(start);
    // Scalar-only oracle: aggregate to 1×1 via `LISTAGG` over a paginated
    // subquery. `db` is the owner (schema), correct in `FROM` here.
    if columns.is_empty() {
        format!(
            "SELECT * FROM (SELECT a.*, ROWNUM rn FROM (SELECT * FROM \"{db}\".\"{table}\") a WHERE ROWNUM <= {}) WHERE rn > {start}",
            start + 1
        )
    } else if columns.len() == 1 {
        let col = &columns[0];
        format!(
            "SELECT LISTAGG(\"{col}\", chr(30)) WITHIN GROUP (ORDER BY \"{col}\") FROM (SELECT \"{col}\" FROM \"{db}\".\"{table}\" OFFSET {start} ROWS FETCH NEXT {limit} ROWS ONLY)"
        )
    } else {
        let concat = columns
            .iter()
            .map(|c| format!("\"{c}\""))
            .collect::<Vec<_>>()
            .join("||chr(31)||");
        format!(
            "SELECT LISTAGG(row_data, chr(30)) WITHIN GROUP (ORDER BY row_data) FROM (SELECT ({concat}) AS row_data FROM \"{db}\".\"{table}\" OFFSET {start} ROWS FETCH NEXT {limit} ROWS ONLY)"
        )
    }
}

#[must_use]
pub fn count_rows(db: &str, table: &str) -> String {
    format!("SELECT COUNT(*) FROM \"{db}\".\"{table}\"")
}
