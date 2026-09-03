#![deny(unsafe_code)]

use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DbmsError {
    #[error("not detected")]
    NotDetected,
    #[error("query failed: {0}")]
    QueryFailed(String),
    #[error("unsupported dbms: {0}")]
    Unsupported(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DbmsKind {
    MySql,
    Postgres,
    MsSql,
    Oracle,
    Unknown,
}

impl core::fmt::Display for DbmsKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MySql => write!(f, "mysql"),
            Self::Postgres => write!(f, "postgres"),
            Self::MsSql => write!(f, "mssql"),
            Self::Oracle => write!(f, "oracle"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

/// Common DBMS detector trait using native async fn (1.75+).
pub trait DbmsDetector: Send + Sync {
    fn kind(&self) -> DbmsKind;
    fn fingerprint_queries(&self) -> Vec<String>;
    fn extract_version_query(&self) -> String;
    fn extract_user_query(&self) -> String;
    // Identity scalar queries (ghauri parity: --banner/--current-user/--current-db/--hostname)
    fn banner_query(&self) -> String;
    fn current_user_query(&self) -> String;
    fn current_db_query(&self) -> String;
    fn hostname_query(&self) -> String;
    /// `LENGTH((q))` vs `LEN((q))` — used for blind length inference.
    fn length_expr(&self, query: &str) -> String;
    /// `ASCII(SUBSTRING(...))` comparison for blind char extraction.
    fn ascii_cmp_expr(&self, query: &str, pos: usize, mid: u8) -> String;
    // Enumeration methods
    fn list_databases_query(&self) -> String;
    fn list_tables_query(&self, db: &str) -> String;
    fn list_columns_query(&self, db: &str, table: &str) -> String;
    fn dump_table_query(
        &self,
        db: &str,
        table: &str,
        columns: &[String],
        start: usize,
        stop: usize,
    ) -> String;
    fn count_rows_query(&self, db: &str, table: &str) -> String;
    fn file_read_query(&self, path: &str) -> Option<String>;
}

/// Owned detector for a [`DbmsKind`], so generic blind-extraction code can
/// reuse the dialect-specific `length_expr` / `ascii_cmp_expr` instead of
/// re-matching on the kind (single source of truth).
#[must_use]
pub fn detector_for_kind(kind: &DbmsKind) -> Box<dyn DbmsDetector> {
    match kind {
        DbmsKind::MySql => Box::new(crate::dbms::MySqlDetector),
        DbmsKind::Postgres => Box::new(crate::dbms::PostgresDetector),
        DbmsKind::MsSql => Box::new(crate::dbms::MsSqlDetector),
        DbmsKind::Oracle | DbmsKind::Unknown => Box::new(crate::dbms::OracleDetector),
    }
}
