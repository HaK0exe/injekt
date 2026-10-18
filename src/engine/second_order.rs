#![deny(unsafe_code)]

//! Second-order (stored) `SQLi` revisit phase (P1): opt-in store/revisit
//! differential, lab-only same-origin. Extracted verbatim from
//! `orchestrator.rs`; no behaviour change.

use super::config::EngineConfig;
use crate::{
    detection::baseline,
    http::{
        client::{HttpClient, RequestSpec},
        timeouts::RequestClass,
    },
    session::{
        scrubber::Scrubber,
        state::{Finding, SessionState, TechniqueKind},
    },
    target::{
        injection::{ProbeOpts, build_injection_spec_with_raw, is_ignored},
        markers::MarkerSet,
        parameters::{ParameterLocation, TargetParameter},
        raw_request::RawRequest,
        url::TargetUrl,
    },
};
use std::{sync::Arc, time::Instant};
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

/// Option B second-order actif borné (lab only, même-origine).
///
/// Stocke un marqueur bénin jetable (`u+8hex`, payload `'<marker>'`
/// style union — jamais de RCE, jamais de stacked exec) sur
/// ≤`max_stores` params Body/Query/Header, puis revisite `revisit_url`
/// (1 store + max 2 GET séquentiels par param, `RequestClass::Default`).
/// Les headers exotiques (`User-Agent`/`X-Forwarded-For`/`Referer`,
/// souvent loggés en base) suivent le même chemin que Body/Query.
/// `TechniqueKind::Union` réutilisé (pas de nouveau kind → reporting
/// inchangé) ; `push_stored()` systématique même sans confirmation
/// (audit passif) ; trace = hashes seuls (`hash_str_hex`), jamais de
/// marqueur en clair dans les logs.
///
/// Gates anti-FP : même-origine stricte (schéma/host/port), abort si le
/// body baseline contient déjà le marqueur, finding seulement si 2/2
/// revisits en 200 non-ignoré reflètent le marqueur (confidence 0.85,
/// FP 0.15, evidence `second-order stored marker reflected
/// confirm=second-pass`).
///
/// # Errors
/// Retourne `InjektError::Other` si `--second-order-revisit-url` est
/// absent/vide, si le revisit n'est pas même-origine que la cible, ou si
/// sa résolution DNS-time échoue (même garde que `run_internal`).
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(crate) async fn run_second_order(
    client: &HttpClient,
    state: &Arc<RwLock<SessionState>>,
    cancel: &CancellationToken,
    config: &EngineConfig,
    scrubber: &Scrubber,
    target: &TargetUrl,
    target_str: &str,
    to_test: &[TargetParameter],
    marker_set: &MarkerSet,
    raw_request: &Arc<Option<RawRequest>>,
    baseline: &baseline::Baseline,
) -> crate::error::Result<()> {
    if !config.second_order.enabled {
        return Ok(());
    }
    let revisit_raw = config.second_order.revisit_url.clone().unwrap_or_default();
    let revisit_raw = revisit_raw.trim().to_owned();
    if revisit_raw.is_empty() {
        return Err(crate::error::InjektError::Other(Box::new(
            std::io::Error::other(
                "--second-order requires --second-order-revisit-url (same-origin path, e.g. /admin)",
            ),
        )));
    }
    // Résolution contre le host cible : chemin (`/admin`) → absolu
    // même-origine ; URL absolue → vérifiée même-origine ci-dessous.
    let revisit_absolute = if revisit_raw.contains("://") {
        revisit_raw.clone()
    } else {
        let path = if revisit_raw.starts_with('/') {
            revisit_raw.clone()
        } else {
            format!("/{revisit_raw}")
        };
        let Some(host) = target.inner().host_str() else {
            return Err(crate::error::InjektError::Other(Box::new(
                std::io::Error::other("second-order: target has no host"),
            )));
        };
        let port_part = target
            .inner()
            .port()
            .map_or_else(String::new, |p| format!(":{p}"));
        format!("{}://{host}{port_part}{path}", target.inner().scheme())
    };
    // Même-origine stricte : schéma + host (insensible à la casse) +
    // port effectif identiques, sinon erreur (pas de SSRF inter-host).
    let revisit_target =
        TargetUrl::parse(&revisit_absolute, config.net.allow_private).map_err(|e| {
            crate::error::InjektError::Other(Box::new(std::io::Error::other(format!(
                "second-order revisit parse failed: {e}"
            ))))
        })?;
    let same_scheme = revisit_target.inner().scheme() == target.inner().scheme();
    let same_host = revisit_target
        .inner()
        .host_str()
        .zip(target.inner().host_str())
        .is_some_and(|(a, b)| a.eq_ignore_ascii_case(b));
    let same_port =
        revisit_target.inner().port_or_known_default() == target.inner().port_or_known_default();
    if !(same_scheme && same_host && same_port) {
        return Err(crate::error::InjektError::Other(Box::new(
            std::io::Error::other(
                "second-order revisit must be same-origin as target (scheme/host/port)",
            ),
        )));
    }
    // Même garde DNS-time que `run_internal` : sauf `remote_dns`
    // (`socks5h://`, le proxy résout à distance), on résout localement.
    if !config.net.allow_private
        && !config.net.remote_dns
        && let Some(host) = revisit_target.inner().host_str()
    {
        TargetUrl::resolve_and_check(host, false)
            .await
            .map_err(|e| crate::error::InjektError::Other(Box::new(e)))?;
    }
    // WAF bloquant : 0 requête extra (même règle que la détection).
    if baseline.is_waf_blocking() {
        warn!(
            target=%scrubber.scrub(target_str),
            "second-order skipped (WAF blocking baseline)"
        );
        return Ok(());
    }
    let max_stores = config.second_order.max_stores.clamp(1, 32);
    // Body/Query + Header (UA/XFF/Referer souvent loggés en base sans
    // sanitisation → second-order via header). `Cookie` exclu : le jar
    // persistant rejouerait le marqueur sur les revisits et fausserait
    // le 2/2 (auto-réflexion, pas stockage serveur).
    let candidates: Vec<TargetParameter> = to_test
        .iter()
        .filter(|p| {
            matches!(
                p.location,
                ParameterLocation::Query | ParameterLocation::Body | ParameterLocation::Header(_)
            )
        })
        .take(max_stores)
        .cloned()
        .collect();
    if candidates.is_empty() {
        debug!("second-order: no Body/Query/Header params to store, 0 extra requests");
        return Ok(());
    }
    info!(
        count = candidates.len(),
        revisit = %scrubber.scrub(&revisit_absolute),
        "second-order active start (lab only, same-origin, benign marker)"
    );
    let baseline_body = baseline.representative_body_str();
    let ignore_codes = config.net.ignore_codes.clone();
    let store_url_hash = crate::reasoning::trace::hash_str_hex(target.as_str());
    let revisit_hash = crate::reasoning::trace::hash_str_hex(&revisit_absolute);
    for param in &candidates {
        if cancel.is_cancelled() {
            break;
        }
        if baseline.is_waf_blocking() {
            break;
        }
        // Marqueur bénin jetable `u+8hex` (même format que les payloads
        // union existants) ; jamais loggé en clair, hashes seuls en trace.
        let hex8: String = uuid::Uuid::new_v4()
            .simple()
            .to_string()
            .chars()
            .take(8)
            .collect();
        let marker_clear = format!("u{hex8}");
        // Gate anti-FP : marqueur déjà présent au baseline → on saute ce
        // param (écho naturel, pas une réflexion stockée).
        if baseline_body.contains(&marker_clear) {
            continue;
        }
        // Audit passif systématique, même si la confirmation échoue.
        {
            let mut st = state.write().await;
            st.push_stored(crate::session::state::StoredProbe::new(
                param.key(),
                secrecy::SecretString::from(marker_clear.clone()),
                store_url_hash.clone(),
            ));
        }
        // Store : payload bénin `'<marker>'` style union (pas de RCE,
        // pas de stacked exec), chemin d'injection existant.
        let payload = format!("'{marker_clear}'");
        let Some(store_spec) = build_injection_spec_with_raw(
            target,
            target_str,
            param,
            &payload,
            marker_set,
            raw_request.as_ref().as_ref(),
            ProbeOpts::new(false, false),
            &config.evasion.payload_opts,
        ) else {
            warn!(param=%param.key(), "second-order store spec build failed, skipping param");
            continue;
        };
        let start = Instant::now();
        let store_resp = client
            .send_with_retry_for_class(store_spec, RequestClass::Default, cancel)
            .await;
        let store_ms = start.elapsed().as_secs_f64() * 1000.0;
        state.write().await.increment_requests();
        let store_ok = match store_resp {
            Ok(r) => {
                match client
                    .read_body_string_for_class(r, RequestClass::Default)
                    .await
                {
                    Ok(body) => {
                        let mut st = state.write().await;
                        let seq = st.next_trace_seq();
                        st.push_trace(crate::reasoning::ProbeRecord::new(
                            seq,
                            param.key(),
                            "union",
                            "second-order:store",
                            config.seed,
                            crate::reasoning::trace::hash_str_hex(&payload),
                            crate::reasoning::trace::hash_str_hex(&body),
                            0.0,
                            store_ms,
                        ));
                        true
                    }
                    Err(e) => {
                        warn!(error=%e, "second-order store body read failed");
                        let mut st = state.write().await;
                        let seq = st.next_trace_seq();
                        st.push_trace(crate::reasoning::ProbeRecord::new(
                            seq,
                            param.key(),
                            "union",
                            "second-order:store",
                            config.seed,
                            crate::reasoning::trace::hash_str_hex(&payload),
                            crate::reasoning::trace::hash_str_hex(""),
                            0.0,
                            store_ms,
                        ));
                        false
                    }
                }
            }
            Err(e) => {
                warn!(error=%e, "second-order store request failed");
                let mut st = state.write().await;
                let seq = st.next_trace_seq();
                st.push_trace(crate::reasoning::ProbeRecord::new(
                    seq,
                    param.key(),
                    "union",
                    "second-order:store",
                    config.seed,
                    crate::reasoning::trace::hash_str_hex(&payload),
                    crate::reasoning::trace::hash_str_hex(""),
                    0.0,
                    store_ms,
                ));
                false
            }
        };
        if !store_ok {
            continue;
        }
        // Revisits : max 2 GET séquentiels, `RequestClass::Default`.
        // Exige 2/2 hits (status 200 + non-ignoré + reflet marqueur).
        let mut hits = 0usize;
        for _ in 0..2 {
            if cancel.is_cancelled() {
                break;
            }
            if baseline.is_waf_blocking() {
                break;
            }
            let start = Instant::now();
            let resp = client
                .send_with_retry_for_class(
                    RequestSpec::get(revisit_absolute.clone()),
                    RequestClass::Default,
                    cancel,
                )
                .await;
            let ms = start.elapsed().as_secs_f64() * 1000.0;
            state.write().await.increment_requests();
            match resp {
                Ok(r) => {
                    let status = r.status().as_u16();
                    match client
                        .read_body_string_for_class(r, RequestClass::Default)
                        .await
                    {
                        Ok(body) => {
                            let hit = status == 200
                                && !is_ignored(status, &ignore_codes)
                                && body.contains(&marker_clear);
                            if hit {
                                hits += 1;
                            }
                            let mut st = state.write().await;
                            let seq = st.next_trace_seq();
                            st.push_trace(crate::reasoning::ProbeRecord::new(
                                seq,
                                param.key(),
                                "union",
                                "second-order:revisit",
                                config.seed,
                                crate::reasoning::trace::hash_str_hex(&revisit_absolute),
                                crate::reasoning::trace::hash_str_hex(&body),
                                f64::from(u8::from(hit)),
                                ms,
                            ));
                        }
                        Err(e) => {
                            warn!(error=%e, "second-order revisit body read failed");
                        }
                    }
                }
                Err(e) => {
                    warn!(error=%e, "second-order revisit request failed");
                }
            }
        }
        if hits >= 2 {
            let evidence = format!(
                "second-order: second-order stored marker reflected confirm=second-pass param={} revisit_hash={revisit_hash} store_hash={store_url_hash}",
                param.key(),
            );
            let finding = Finding::new(
                target.as_str(),
                param.key(),
                TechniqueKind::Union,
                0.85,
                evidence,
            )
            .with_false_positive_prob(0.15)
            .with_waf(baseline.waf_vendor.clone(), baseline.is_waf_blocking());
            state.write().await.push_finding(finding);
            info!(
                param=%scrubber.scrub(&param.key()),
                "second-order stored marker reflected (2/2 revisits)"
            );
        } else {
            debug!(
                param=%scrubber.scrub(&param.key()),
                hits,
                "second-order revisit miss"
            );
        }
    }
    info!("second-order active done");
    Ok(())
}
