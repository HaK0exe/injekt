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
    let cols = if columns.is_empty() {
        "*".to_owned()
    } else {
        columns.join(",")
    };
    let _limit = stop.saturating_sub(start);
    // Oracle uses ROWNUM for pagination
    format!(
        "SELECT {cols} FROM (SELECT a.*, ROWNUM rn FROM (SELECT {cols} FROM \"{db}\".\"{table}\") a WHERE ROWNUM <= {stop}) WHERE rn > {start}"
    )
}

#[must_use]
pub fn count_rows(db: &str, table: &str) -> String {
    format!("SELECT COUNT(*) FROM \"{db}\".\"{table}\"")
}
