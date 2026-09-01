#![deny(unsafe_code)]

use crate::dbms::common::{DbmsDetector, DbmsKind};
use crate::dbms::postgres::enumeration;

#[derive(Debug, Default)]
pub struct PostgresDetector;

impl DbmsDetector for PostgresDetector {
    fn kind(&self) -> DbmsKind {
        DbmsKind::Postgres
    }
    fn fingerprint_queries(&self) -> Vec<String> {
        vec![
            "SELECT version()".to_owned(),
            "SELECT current_database()".to_owned(),
        ]
    }
    fn extract_version_query(&self) -> String {
        "SELECT version()".to_owned()
    }
    fn extract_user_query(&self) -> String {
        "SELECT current_user".to_owned()
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
        Some(format!("SELECT pg_read_file('{path}')"))
    }
}
