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
        "SELECT USER_NAME()".to_owned()
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
}
