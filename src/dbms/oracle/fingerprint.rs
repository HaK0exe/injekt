#![deny(unsafe_code)]

use crate::dbms::common::{DbmsDetector, DbmsKind};
use crate::dbms::oracle::enumeration;

#[derive(Debug, Default)]
pub struct OracleDetector;

impl DbmsDetector for OracleDetector {
    fn kind(&self) -> DbmsKind {
        DbmsKind::Oracle
    }
    fn fingerprint_queries(&self) -> Vec<String> {
        vec![
            "SELECT banner FROM v$version WHERE ROWNUM=1".to_owned(),
            "SELECT SYS_CONTEXT('USERENV','CURRENT_USER') FROM dual".to_owned(),
        ]
    }
    fn extract_version_query(&self) -> String {
        "SELECT banner FROM v$version WHERE ROWNUM=1".to_owned()
    }
    fn extract_user_query(&self) -> String {
        "SELECT USER FROM dual".to_owned()
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
        format!("ASCII(SUBSTR(({query}),{},1))>={mid}", pos + 1)
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
