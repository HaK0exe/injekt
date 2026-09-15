#![deny(unsafe_code)]

use crate::dbms::{DbmsKind, common::DbmsKind as Kind};
use regex::Regex;
use std::sync::OnceLock;

/// Heuristic banner -> kind
#[must_use]
pub fn banner_to_kind(s: &str) -> DbmsKind {
    let lower = s.to_ascii_lowercase();
    // Check vendor-specific tokens first — generic @@version alone is ambiguous
    // (MySQL uses @@version, MSSQL uses @@VERSION). Reordering prevents
    // a "Microsoft SQL Server @@version" banner from being consumed as MySql.
    if lower.contains("microsoft sql server")
        || lower.contains("mssql")
        || (lower.contains("microsoft") && lower.contains("@@version"))
    {
        return Kind::MsSql;
    }
    if lower.contains("postgres") || lower.contains("postgresql") {
        return Kind::Postgres;
    }
    if lower.contains("mysql") {
        return Kind::MySql;
    }
    if lower.contains("oracle") || lower.contains("ora-") {
        return Kind::Oracle;
    }
    if lower.contains("sqlite") || lower.contains("sqlite_version") {
        return Kind::Sqlite;
    }
    // Fallback: bare @@version without vendor hint — keep Unknown to avoid
    // misclassifying MSSQL banners, but preserve legacy MySql fallback for
    // callers that treat Unknown as MySql. Callers should treat this as low confidence.
    if lower.contains("@@version") {
        return Kind::MySql;
    }
    Kind::Unknown
}

#[must_use]
pub fn guess_from_findings(findings: &[crate::session::state::Finding]) -> Option<DbmsKind> {
    for f in findings {
        if let Some(db) = &f.dbms {
            match db.to_ascii_lowercase().as_str() {
                "mysql" => return Some(Kind::MySql),
                "postgres" => return Some(Kind::Postgres),
                "mssql" => return Some(Kind::MsSql),
                "oracle" => return Some(Kind::Oracle),
                "sqlite" => return Some(Kind::Sqlite),
                _ => {}
            }
        }
        // also scan evidence for version strings
        let k = banner_to_kind(&f.evidence);
        if k != Kind::Unknown {
            return Some(k);
        }
    }
    None
}

/// # Panics
/// Panics if the internal static regex fails to compile (never happens in practice).
#[must_use]
pub fn extract_banner_version(body: &str) -> Option<(DbmsKind, String)> {
    // MySQL XPATH etc already in error detector; broader here
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        #[allow(clippy::expect_used)]
        {
            Regex::new(
                r"(?i)(mysql|postgres|microsoft sql server|oracle|sqlite)[^<\n]*?(\d+\.\d+[^<\s]*)",
            )
            .expect("banner regex")
        }
    });
    re.captures(body).and_then(|c| {
        let db_str = c.get(1)?.as_str().to_ascii_lowercase();
        let ver = c.get(2)?.as_str().to_owned();
        let kind = match db_str.as_str() {
            s if s.contains("mysql") => Kind::MySql,
            s if s.contains("postgres") => Kind::Postgres,
            s if s.contains("microsoft") => Kind::MsSql,
            s if s.contains("oracle") => Kind::Oracle,
            s if s.contains("sqlite") => Kind::Sqlite,
            _ => Kind::Unknown,
        };
        Some((kind, ver))
    })
}

/// Returns a boxed `DbmsDetector` for the given `DbmsKind`.
#[must_use]
pub fn get_detector(kind: DbmsKind) -> Box<dyn crate::dbms::common::DbmsDetector> {
    #[allow(clippy::match_same_arms)]
    match kind {
        DbmsKind::MySql => Box::new(crate::dbms::mysql::MySqlDetector),
        DbmsKind::Postgres => Box::new(crate::dbms::postgres::PostgresDetector),
        DbmsKind::MsSql => Box::new(crate::dbms::mssql::MsSqlDetector),
        DbmsKind::Oracle => Box::new(crate::dbms::oracle::OracleDetector),
        DbmsKind::Sqlite => Box::new(crate::dbms::sqlite::SqliteDetector),
        DbmsKind::Unknown => Box::new(crate::dbms::mysql::MySqlDetector),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn detects_mysql() {
        assert_eq!(banner_to_kind("MySQL 8.0.32"), Kind::MySql);
    }
    #[test]
    fn banner_kinds_pg18_mysql97() {
        // 2026 fixtures: PostgreSQL 18.6 / 17.5, MySQL 9.7.1 / 8.4.0 LTS.
        assert_eq!(
            banner_to_kind("PostgreSQL 18.6 on x86_64-pc-linux-gnu"),
            Kind::Postgres
        );
        assert_eq!(
            banner_to_kind("PostgreSQL 17.5 on x86_64-pc-linux-gnu"),
            Kind::Postgres
        );
        assert_eq!(banner_to_kind("MySQL 9.7.1"), Kind::MySql);
        assert_eq!(banner_to_kind("MySQL 8.4.0"), Kind::MySql);
    }
    #[test]
    fn banner_versions_pg18_mysql97() {
        let r = extract_banner_version("PostgreSQL 18.6 on x86_64-pc-linux-gnu");
        assert!(
            r.is_some_and(|(k, v)| k == Kind::Postgres && v.contains("18.6")),
            "PG 18.6 banner must extract"
        );
        let r = extract_banner_version("PostgreSQL 17.5 on x86_64-pc-linux-gnu");
        assert!(
            r.is_some_and(|(k, v)| k == Kind::Postgres && v.contains("17.5")),
            "PG 17.5 banner must extract"
        );
        let r = extract_banner_version("MySQL 9.7.1");
        assert!(
            r.is_some_and(|(k, v)| k == Kind::MySql && v.contains("9.7.1")),
            "MySQL 9.7.1 banner must extract"
        );
        let r = extract_banner_version("MySQL 8.4.0");
        assert!(
            r.is_some_and(|(k, v)| k == Kind::MySql && v.contains("8.4.0")),
            "MySQL 8.4.0 banner must extract"
        );
    }
    #[test]
    fn guess_from_findings_mysql() {
        use crate::session::state::{Finding, TechniqueKind};
        let mut f = Finding::new("http://a", "id@query", TechniqueKind::Error, 0.9, "XPATH");
        f.dbms = Some("mysql".into());
        assert_eq!(guess_from_findings(&[f]), Some(Kind::MySql));
    }
}
