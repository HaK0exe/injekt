#![deny(unsafe_code)]
pub mod common;
pub mod mssql;
pub mod mysql;
pub mod oracle;
pub mod postgres;
pub use common::{DbmsDetector, DbmsError, DbmsKind};
pub use mssql::MsSqlDetector;
pub use mysql::MySqlDetector;
pub use oracle::OracleDetector;
pub use postgres::PostgresDetector;
