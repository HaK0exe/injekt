use crate::dbms::common::DbmsKind;
use regex::Regex;
use std::sync::OnceLock;

/// Check response text against vendor SQL error signatures.
///
/// # Panics
/// Panics if an internal static error-pattern regex fails to compile (never happens in practice;
/// patterns are compile-time constants validated by unit tests).
#[allow(clippy::similar_names)]
#[must_use]
pub fn check_sql_errors(body: &str) -> Option<(DbmsKind, String)> {
    static MYSQL_ERR: OnceLock<Regex> = OnceLock::new();
    static PG_ERR: OnceLock<Regex> = OnceLock::new();
    static MSSQL_ERR: OnceLock<Regex> = OnceLock::new();
    static ORA_ERR: OnceLock<Regex> = OnceLock::new();
    static SQLITE_ERR: OnceLock<Regex> = OnceLock::new();

    let mysql_re = MYSQL_ERR.get_or_init(|| {
        #[allow(clippy::expect_used)]
        Regex::new(r"(?i)(you have an error in your sql syntax|check the manual that corresponds to your (mysql|mariadb) server version|mysql_fetch_|com\.mysql\.jdbc)").expect("mysql error regex")
    });
    let pg_re = PG_ERR.get_or_init(|| {
        #[allow(clippy::expect_used)]
        Regex::new(r"(?i)(syntax error at or near|unterminated quoted string|pg_query\(|psycopg2\.|org\.postgresql\.)").expect("pg error regex")
    });
    let mssql_re = MSSQL_ERR.get_or_init(|| {
        #[allow(clippy::expect_used)]
        Regex::new(r"(?i)(unclosed quotation mark after the character string|syntax error.*in query expression|microsoft ole db provider for sql server|\[microsoft\]\[odbc sql server driver\]|sqlexception)").expect("mssql error regex")
    });
    let ora_re = ORA_ERR.get_or_init(|| {
        #[allow(clippy::expect_used)]
        Regex::new(r"(?i)(ora-01756|ora-00933|ora-00936|quoted string not properly terminated|oracle error)").expect("oracle error regex")
    });
    let sqlite_re = SQLITE_ERR.get_or_init(|| {
        #[allow(clippy::expect_used)]
        Regex::new(r"(?i)(unrecognized token|sqlite3\.(OperationalError|IntegrityError|DataError|ProgrammingError)|sqlite3\.warning|integer overflow|no such column|no such table|malformed json)").expect("sqlite error regex")
    });

    if let Some(m) = mysql_re.find(body) {
        return Some((DbmsKind::MySql, m.as_str().to_owned()));
    }
    if let Some(m) = pg_re.find(body) {
        return Some((DbmsKind::Postgres, m.as_str().to_owned()));
    }
    if let Some(m) = mssql_re.find(body) {
        return Some((DbmsKind::MsSql, m.as_str().to_owned()));
    }
    if let Some(m) = ora_re.find(body) {
        return Some((DbmsKind::Oracle, m.as_str().to_owned()));
    }
    if let Some(m) = sqlite_re.find(body) {
        return Some((DbmsKind::Sqlite, m.as_str().to_owned()));
    }

    None
}
