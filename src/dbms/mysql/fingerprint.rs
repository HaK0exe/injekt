#![deny(unsafe_code)]

use crate::dbms::common::{DbmsDetector, DbmsKind};

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
    fn extract_databases_query(&self) -> String {
        "SELECT schema_name FROM information_schema.schemata".to_owned()
    }
    fn extract_tables_query(&self, db: &str) -> String {
        format!("SELECT table_name FROM information_schema.tables WHERE table_schema='{db}'")
    }
    fn extract_columns_query(&self, db: &str, table: &str) -> String {
        format!(
            "SELECT column_name FROM information_schema.columns WHERE table_schema='{db}' AND table_name='{table}'"
        )
    }
    fn file_read_query(&self, path: &str) -> Option<String> {
        Some(format!("SELECT LOAD_FILE('{path}')"))
    }
}

#[must_use]
pub fn is_mysql_banner(s: &str) -> bool {
    s.to_ascii_lowercase().contains("mysql") || s.contains("@@version")
}
