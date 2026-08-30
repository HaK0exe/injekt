#![deny(unsafe_code)]

use crate::dbms::common::{DbmsDetector, DbmsKind};

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
    fn extract_databases_query(&self) -> String {
        "SELECT name FROM master..sysdatabases".to_owned()
    }
    fn extract_tables_query(&self, _db: &str) -> String {
        "SELECT name FROM sysobjects WHERE xtype='U'".to_owned()
    }
    fn extract_columns_query(&self, _db: &str, table: &str) -> String {
        format!("SELECT name FROM syscolumns WHERE id=OBJECT_ID('{table}')")
    }
    fn file_read_query(&self, _path: &str) -> Option<String> {
        None
    }
}
