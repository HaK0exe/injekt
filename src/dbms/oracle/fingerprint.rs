#![deny(unsafe_code)]

use crate::dbms::common::{DbmsDetector, DbmsKind};

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
    fn extract_databases_query(&self) -> String {
        "SELECT name FROM v$database".to_owned()
    }
    fn extract_tables_query(&self, _db: &str) -> String {
        "SELECT table_name FROM all_tables".to_owned()
    }
    fn extract_columns_query(&self, _db: &str, table: &str) -> String {
        format!("SELECT column_name FROM all_tab_columns WHERE table_name='{table}'")
    }
    fn file_read_query(&self, _path: &str) -> Option<String> {
        None
    }
}
