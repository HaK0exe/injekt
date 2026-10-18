#![deny(unsafe_code)]

//! Out-of-band (OOB) payload generators per DBMS.
//!
//! OOB exfiltrates via a side channel (DNS / HTTP) instead of the HTTP
//! response body. Every payload embeds a unique token subdomain
//! `<token>.<domain>` so a collaborator (Burp Collaborator, interactsh,
//! self-hosted DNS/HTTP listener) can correlate the callback.
//!
//! References (2024-2026):
//! - `PortSwigger` Web Security Academy, blind `SQLi` OOB labs (Oracle XXE
//!   `EXTRACTVALUE(xmltype(...))`, MSSQL `xp_dirtree`).
//! - `PayloadsAllTheThings`: Postgres `COPY TO PROGRAM nslookup/curl`,
//!   Oracle `UTL_INADDR / UTL_HTTP / DBMS_LDAP`, MSSQL UNC `xp_dirtree /
//!   xp_fileexist / xp_subdirs`, MySQL `LOAD_FILE` UNC (Windows only).
//! - `NetSPI` `PowerUpSQL` UNC path injection cheat sheet (MSSQL).

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

/// Encoding variants for OOB payloads (URL, double-URL, hex, unicode).
/// Reuses the boolean tamper-compatible encoder for WAF evasion.
#[must_use]
pub fn encode_oob_payload(payload: &str, encoding: &str) -> String {
    crate::techniques::boolean::payloads::encode_payload(payload, encoding)
}

mod dbms;
mod dns;

pub use self::dbms::{oob_exfil_payloads_for, oob_payloads_for};
pub use self::dns::{
    build_subdomain, chunk_for_dns, encode_for_dns, is_valid_oob_domain, sanitize_dns_label,
};

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests;
