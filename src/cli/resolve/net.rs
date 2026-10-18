//! Proxy/redirect/DNS helpers + DBMS hint normalisation.

use crate::cli::args::Cli;
use crate::http::redirects::RedirectPolicy;

impl Cli {
    /// `true` when the proxy performs remote DNS (`socks5h://`): local
    /// DNS-time SSRF resolution must be skipped (no local leak, no false
    /// `.onion` failure). Lexical + IP-literal checks still apply.
    #[must_use]
    pub fn uses_remote_dns(&self) -> bool {
        self.effective_proxy()
            .is_some_and(|p| p.to_ascii_lowercase().starts_with("socks5h://"))
    }

    /// Effective redirect policy from `--max-redirects` (`None` = 5).
    /// `0` means "do not follow" ([`RedirectPolicy::None`]); values above
    /// 10 are clamped defensively (clap already constrains CLI input, but
    /// MCP/manual constructions bypass it).
    #[must_use]
    pub fn effective_redirect_policy(&self) -> RedirectPolicy {
        match self.http.max_redirects.unwrap_or(5) {
            0 => RedirectPolicy::None,
            n => RedirectPolicy::Limited(usize::from(n.min(10))),
        }
    }

    /// Normalized `--dbms` hint (`mysql|postgres|mssql|oracle|sqlite`) or `None`
    /// when absent/unknown (unknown warns, falls back to auto-fingerprint).
    #[must_use]
    pub fn normalized_dbms_hint(&self) -> Option<String> {
        let raw = self.detection.dbms.as_deref()?;
        let v = raw.trim().to_ascii_lowercase();
        // Accept common aliases.
        let norm = match v.as_str() {
            "mysql" | "mariadb" | "my" => "mysql",
            "postgres" | "postgresql" | "pg" | "pgsql" => "postgres",
            "mssql" | "sqlserver" | "sql-server" | "tsql" => "mssql",
            "oracle" | "ora" => "oracle",
            "sqlite" => "sqlite",
            _ => {
                tracing::warn!(dbms=%raw, "unknown --dbms, ignoring (auto-fingerprint)");
                return None;
            }
        };
        Some(norm.to_owned())
    }
}
