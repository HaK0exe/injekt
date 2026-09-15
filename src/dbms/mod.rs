#![deny(unsafe_code)]
pub mod common;
pub mod context;
pub mod fingerprint;
pub mod mssql;
pub mod mysql;
pub mod oracle;
pub mod postgres;
pub mod sqlite;
pub use common::{DbmsDetector, DbmsError, DbmsKind};
pub use context::{CommentStyle, DbmsBelief, InjectionContext, QuoteContext, analyze_context};
pub use mssql::MsSqlDetector;
pub use mysql::MySqlDetector;
pub use oracle::OracleDetector;
pub use postgres::PostgresDetector;
pub use sqlite::SqliteDetector;
