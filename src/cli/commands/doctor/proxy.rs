//! Check 2 — proxy : parse + validation du schéma, AUCUNE connexion (doctor).

use super::CheckResult;

// ---------------------------------------------------------------------------
// Check 2 — proxy : parse + validation du schéma, AUCUNE connexion
// ---------------------------------------------------------------------------

/// Check 2 (pur) — valeur via la résolution CLI > env > config (appelant) ;
/// absent ⇒ `Warn` (exit direct, anonymisation opt-in) ; présent ⇒
/// `ProxyConfig::parse` (`socks5://` ⇒ `Fail` avec le message DNS-leak
/// existant de `ProxyError::DnsLeak`, jamais dupliqué ; `socks5h://` /
/// http(s) ⇒ `Ok`). Uniquement parse et schéma : aucune connexion testée.
#[must_use]
pub fn check_proxy(proxy: Option<&str>) -> CheckResult {
    let Some(url) = proxy else {
        return CheckResult::warn(
            "proxy: aucun — exit réseau direct (anonymisation opt-in : --proxy \
             socks5h://… ou clé proxy du TOML)",
        );
    };
    // La valeur peut porter `user:pass@` : userinfo TOUJOURS redirigé —
    // même sur les chemins `Ok` (`ProxyError::Invalid` est déjà scrubé
    // côté http::proxy).
    let shown = crate::http::proxy::redact_userinfo(url);
    match crate::http::proxy::ProxyConfig::parse(url) {
        Err(e) => {
            // `DnsLeak` n'écho pas la valeur : on l'ajoute (redirigée).
            let detail = match &e {
                crate::http::proxy::ProxyError::DnsLeak => {
                    format!("{e} [valeur: {shown}]")
                }
                _ => format!("{e}"),
            };
            CheckResult::fail(format!("proxy: refusé — {detail}"))
        }
        Ok(cfg) => {
            let kind = match cfg {
                crate::http::proxy::ProxyConfig::Http(_) => "HTTP(S)",
                crate::http::proxy::ProxyConfig::Socks5h(_) => "SOCKS5h (DNS distant)",
            };
            CheckResult::ok(format!(
                "proxy: {shown} ({kind}) — schéma socks5h/http valide, vérifié \
                 sans connexion (0 socket)",
            ))
        }
    }
}
