#![deny(unsafe_code)]

use crate::dbms::common::{DbmsDetector, DbmsKind};

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
    fn extract_databases_query(&self) -> String {
        "SELECT datname FROM pg_database".to_owned()
    }
    fn extract_tables_query(&self, _db: &str) -> String {
        "SELECT tablename FROM pg_tables WHERE schemaname='public'".to_owned()
    }
    fn extract_columns_query(&self, _db: &str, table: &str) -> String {
        format!("SELECT column_name FROM information_schema.columns WHERE table_name='{table}'")
    }
    fn file_read_query(&self, path: &str) -> Option<String> {
        Some(format!("SELECT pg_read_file('{path}')"))
    }
}
