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

#[must_use]
pub fn extract_banner_version(body: &str) -> Option<(DbmsKind, String)> {
    // MySQL XPATH etc already in error detector; broader here
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        #[allow(clippy::expect_used)]
        {
            Regex::new(r"(?i)(mysql|postgres|microsoft sql server|oracle)[^<\n]*?(\d+\.\d+[^<\s]*)")
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
            _ => Kind::Unknown,
        };
        Some((kind, ver))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn detects_mysql() {
        assert_eq!(banner_to_kind("MySQL 8.0.32"), Kind::MySql);
    }
    #[test]
    fn guess_from_findings_mysql() {
        use crate::session::state::{Finding, TechniqueKind};
        let f = Finding {
            target: "http://a".into(),
            parameter: "id@query".into(),
            technique: TechniqueKind::Error,
            confidence: 0.9,
            dbms: Some("mysql".into()),
            evidence: "XPATH".into(),
            timestamp: chrono::Utc::now(),
        };
        assert_eq!(guess_from_findings(&[f]), Some(Kind::MySql));
    }
}
