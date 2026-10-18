//! Baseline phase moved out of `orchestrator.rs` (P1-fin): 3-sample
//! collection, WAF-aware effective tampers/opts, `BaselineCache` singleflight.
//!
//! Behavior-neutral move: the logic is verbatim from `Engine::collect_baseline`
//! / `Engine::collect_baseline_uncached`; only `self.*` access became explicit
//! `client/state/cancel/config/scrubber/cache` parameters.

use crate::{
    detection::baseline,
    http::{
        client::{HttpClient, RequestSpec},
        timeouts::RequestClass,
    },
    session::{scrubber::Scrubber, state::SessionState},
    target::{
        injection::{ProbeOpts, baseline_all_error, request_spec_from_raw, waf_auto_tampers},
        raw_request::RawRequest,
        url::TargetUrl,
    },
    techniques::tamper::Tamper,
};
use indicatif::{ProgressBar, ProgressStyle};
use std::{io::IsTerminal as _, sync::Arc, time::Instant};
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use super::config::EngineConfig;

/// Spinner hidden when stderr is not a TTY (MCP stdio, pipes, CI).
/// `indicatif` writes to stderr, so stdout JSON-RPC stays clean, but hidden
/// avoids spam + steady-tick CPU in agent mode.
fn spinner(msg: &str) -> ProgressBar {
    if !std::io::stderr().is_terminal() {
        return ProgressBar::hidden();
    }
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner} {msg}")
            .unwrap_or_else(|_| ProgressStyle::default_spinner()),
    );
    pb.set_message(msg.to_owned());
    pb.enable_steady_tick(std::time::Duration::from_millis(80));
    pb
}

/// Outcome of one concurrent baseline fetch (Phase 3, `join_all` borné).
/// `BodyReadFailed` (compté, retry) vs `TransportFailed` (non compté, retry)
/// préserve la comptabilité historique ; `Cancelled` sort proprement.
enum BaselineOutcome {
    Sample(baseline::Sample),
    BodyReadFailed,
    TransportFailed(String),
    Cancelled,
}

/// Collects 3 baseline samples, derives the WAF-aware effective tampers/opts.
/// `Ok(None)` means the run was cancelled with no samples collected — caller
/// should return [`EngineState::Cancelled`](crate::engine::EngineState::Cancelled)
/// immediately.
///
/// When a [`crate::recon::BaselineCache`] is attached (recon mode), reuse
/// the cached entry for `host:port:scheme:raw_hash` instead of re-sending
/// the 3-sample sequence. WAF-blocking baselines bypass the cache in both
/// directions (never served, never stored) so a transient block cannot
/// poison later candidates. Concurrent candidates for the same key
/// singleflight on a per-key mutex: the first collects, the waiters hit.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn collect_baseline(
    client: &HttpClient,
    state: &Arc<RwLock<SessionState>>,
    cancel: &CancellationToken,
    config: &EngineConfig,
    scrubber: &Scrubber,
    cache: Option<&Arc<crate::recon::BaselineCache>>,
    target: &TargetUrl,
    raw_request: Option<&RawRequest>,
) -> crate::error::Result<Option<(baseline::Baseline, Vec<Tamper>, ProbeOpts)>> {
    let Some(cache) = cache.cloned() else {
        return collect_baseline_uncached(
            client,
            state,
            cancel,
            config,
            scrubber,
            target,
            raw_request,
        )
        .await;
    };
    let key = crate::recon::BaselineCache::cache_key(target, raw_request);
    // Singleflight cancellable: `lock_for_key` + per-key mutex sans `select!`
    // bloquaient Ctrl+C jusqu'à la fin du premier collecteur (~90s en recon scan).
    let key_lock = tokio::select! {
        biased;
        () = cancel.cancelled() => {
            return Err(crate::error::InjektError::Cancelled);
        }
        lock = cache.lock_for_key(&key) => lock,
    };
    let per_key_guard = tokio::select! {
        biased;
        () = cancel.cancelled() => {
            return Err(crate::error::InjektError::Cancelled);
        }
        guard = key_lock.lock() => guard,
    };
    // Blocked in either sense (status-count or marker-signal): never serve
    // from cache, otherwise a transient 403/406/429 poisons later candidates.
    // Conservative: cache bypass on `blocked || blocking` even though
    // `effective_tampers` below additionally requires vendor/marker
    // corroboration for the `blocked` case.
    if let Some((cached_baseline, cached_tampers, cached_opts)) = cache.get(&key).await
        && !(cached_baseline.is_waf_blocked() || cached_baseline.is_waf_blocking())
    {
        let hit = (cached_baseline, cached_tampers, cached_opts);
        drop(per_key_guard);
        cache.remove_lock(&key).await;
        return Ok(Some(hit));
    }
    // Blocking entry (or miss): bypass and re-collect below. The lock is
    // always released, including on probe error (`?`): otherwise the
    // per-key mutex orphans in the map and the singleflight window breaks
    // (redundant baselines + unbounded map growth on bulk runs).
    let collected = match collect_baseline_uncached(
        client,
        state,
        cancel,
        config,
        scrubber,
        target,
        raw_request,
    )
    .await
    {
        Ok(c) => c,
        Err(e) => {
            drop(per_key_guard);
            cache.remove_lock(&key).await;
            return Err(e);
        }
    };
    if let Some((fresh_baseline, fresh_tampers, fresh_opts)) = collected.as_ref()
        && !(fresh_baseline.is_waf_blocked() || fresh_baseline.is_waf_blocking())
    {
        cache
            .insert(
                key.clone(),
                (fresh_baseline.clone(), fresh_tampers.clone(), *fresh_opts),
            )
            .await;
    }
    drop(per_key_guard);
    cache.remove_lock(&key).await;
    Ok(collected)
}

/// Uncached baseline collection: 3 samples + WAF-aware tampers/opts.
///
/// Phase 3: les 3 samples sont émis en concurrent (`join_all` borné à 3,
/// sans `spawn` unbounded) ; `attempts <= 6` borne les envois, seuls les
/// ratés sont rejoués. Chaque branche vérifie le `CancellationToken`.
#[allow(clippy::too_many_lines)]
pub(crate) async fn collect_baseline_uncached(
    client: &HttpClient,
    state: &Arc<RwLock<SessionState>>,
    cancel: &CancellationToken,
    config: &EngineConfig,
    scrubber: &Scrubber,
    target: &TargetUrl,
    raw_request: Option<&RawRequest>,
) -> crate::error::Result<Option<(baseline::Baseline, Vec<Tamper>, ProbeOpts)>> {
    // Baseline: 3 requests (hidden when stderr is not a TTY: MCP/CI).
    // `indicatif` draws to stderr only, so stdout JSON-RPC stays clean.
    let pb = spinner("collecting baseline…");
    let phase_started = Instant::now();
    let req_before = state.read().await.request_count();

    let mut samples = Vec::new();
    // Retry samples on body-read failure instead of pushing `Vec::new()`:
    // an empty body scores as similarity ~0 / confidence 0.75 (false
    // positive). Transport errors (`Timeout`, stream reset) are retryable
    // and must never enter the baseline.
    //
    // Phase 3: the 3 samples are fetched concurrently (`join_all`, borné
    // à 3, sans `spawn` unbounded) so `3×5s` TTFB coûte ~5-6s au lieu de
    // 16s séquentiels. `attempts <= 6` borne le total d'envois
    // individuels ; seuls les samples ratés sont rejoués au tour suivant.
    // Chaque branche vérifie le `CancellationToken` avant envoi (le
    // `send_with_retry` + `read_body` restent annulables via le token).
    // `rate_limit acquire_cancellable` + jitter restent dans
    // `send_with_retry`, donc partagés et bornés comme avant.
    let mut attempts = 0usize;
    while samples.len() < 3 && attempts < 6 {
        if cancel.is_cancelled() {
            break;
        }
        let needed = (3usize.saturating_sub(samples.len())).min(6usize.saturating_sub(attempts));
        if needed == 0 {
            break;
        }
        attempts = attempts.saturating_add(needed);
        let futs: Vec<_> = (0..needed)
            .map(|_| async {
                if cancel.is_cancelled() {
                    return BaselineOutcome::Cancelled;
                }
                let spec = raw_request.map_or_else(
                    || RequestSpec::get(target.as_str().to_owned()),
                    |raw| request_spec_from_raw(target, raw),
                );
                // Pure-send timing: `elapsed_send` covers only the last
                // successful `req.send()` — never local pacing (jitter /
                // rate-limit / backoff). Pacing-inflated durations widened
                // `mean/stddev` and desensitized the `time` detector.
                let timed = client
                    .send_with_retry_timed_for_class(spec, RequestClass::Default, cancel)
                    .await;
                match timed {
                    Ok(t) => {
                        let elapsed = t.elapsed_send;
                        let r = t.resp;
                        let status = r.status().as_u16();
                        // Clone headers BEFORE the body read consumes the response.
                        // Values truncated to 128 chars (OPSEC: bounds Set-Cookie
                        // token retention); WAF detection only needs `contains`.
                        let raw_headers: Vec<(String, String)> = r
                            .headers()
                            .iter()
                            .filter_map(|(name, value)| {
                                value.to_str().ok().map(|raw| {
                                    let mut kept = raw.to_owned();
                                    if kept.len() > crate::detection::waf::HEADER_VALUE_KEEP {
                                        kept.truncate(crate::detection::waf::HEADER_VALUE_KEEP);
                                    }
                                    (name.as_str().to_ascii_lowercase(), kept)
                                })
                            })
                            .collect();
                        match tokio::select! {
                            biased;
                            () = cancel.cancelled() => None,
                            res = client.read_body_with_timeout(r) => Some(res),
                        } {
                            Some(Ok(body)) => BaselineOutcome::Sample(baseline::Sample {
                                status,
                                body,
                                duration: elapsed,
                                headers: raw_headers,
                            }),
                            Some(Err(_)) => BaselineOutcome::BodyReadFailed,
                            None => BaselineOutcome::Cancelled,
                        }
                    }
                    Err(e) => {
                        BaselineOutcome::TransportFailed(format!("baseline request failed: {e}"))
                    }
                }
            })
            .collect();
        // Borné à `needed <= 3`, aucun `spawn` (pas de tâche détachée).
        let results = futures::future::join_all(futs).await;
        for outcome in results {
            if cancel.is_cancelled() {
                break;
            }
            match outcome {
                BaselineOutcome::Sample(s) => {
                    if samples.len() < 3 {
                        samples.push(s);
                        state.write().await.increment_requests();
                    }
                }
                BaselineOutcome::BodyReadFailed => {
                    warn!("baseline body read failed, retrying sample");
                    state.write().await.increment_requests();
                }
                BaselineOutcome::Cancelled => {
                    // Sortie propre : ni compté ni warn.
                }
                BaselineOutcome::TransportFailed(msg) => {
                    warn!(error=%msg, "baseline request failed");
                    // A request was sent: count it so `--request-budget`
                    // cannot be bypassed by failing baselines.
                    state.write().await.increment_requests();
                }
            }
            if samples.len() >= 3 {
                break;
            }
        }
    }
    if samples.is_empty() {
        // Clear the spinner line so the log stays clean (`ing` → `ed`
        // is reported via the `warn!`/`Err` below, not a stale bar).
        pb.finish_and_clear();
        if cancel.is_cancelled() {
            return Ok(None);
        }
        return Err(crate::error::InjektError::Other(Box::new(
            std::io::Error::other(
                "baseline failed: no successful responses from target after 3 attempts",
            ),
        )));
    }
    pb.finish_and_clear();
    let mut baseline = baseline::Baseline::new(&samples);
    // CT-mismatch (P0-4): a `--raw-file` API call (`Content-Type:
    // application/json`) answered with HTML/text means a challenge/deny
    // page intercepted the call. Presence-level alone, blocking only
    // with a corroborating status (see `Baseline::apply_ct_mismatch`).
    if let Some(expected_ct) = raw_request.and_then(|r| r.content_type()) {
        baseline.apply_ct_mismatch(&samples, expected_ct);
    }
    {
        let req_done = state.read().await.request_count();
        let req_delta = req_done.saturating_sub(req_before);
        // Status codes are logged so a `blocking=true` verdict stays
        // auditable (e.g. one corroborated 403 among 200s explains the
        // WAF warn below without a body dump).
        let statuses: Vec<u16> = baseline.status_codes.clone();
        info!(
            elapsed_s = phase_started.elapsed().as_secs_f64(),
            requests = req_delta,
            statuses = ?statuses,
            "baseline done in {:.1}s, {req_delta} req (statuses: {statuses:?})",
            phase_started.elapsed().as_secs_f64(),
        );
        // Origin erroring behind the CDN (CF 520–524, 5xx): every
        // differential below compares static error pages, so a full
        // detection run is void by construction — say so loudly instead
        // of burning the budget silently. Scan continues (transient
        // blips happen) but the verdict must be read as "unreachable",
        // never as "not injectable".
        if baseline_all_error(&statuses) {
            warn!(
                statuses = ?statuses,
                "baseline: all samples server-error (5xx) — origin unreachable, detection differentials will be meaningless"
            );
        }
    }
    // C6 trace: baseline samples as hashes only (never clear body/headers).
    // Guarantees a non-empty RAM-only trace even on clean targets.
    {
        let mut st = state.write().await;
        for (idx, sample) in samples.iter().enumerate() {
            let seq = st.next_trace_seq();
            let req_hash = crate::reasoning::trace::hash_str_hex(&format!(
                "baseline:{idx}:{}",
                target.as_str()
            ));
            let resp_hash = crate::reasoning::trace::hash_sha256_hex(sample.body.as_slice());
            #[allow(clippy::cast_precision_loss)]
            let ms = sample.duration.as_secs_f64() * 1000.0;
            st.push_trace(crate::reasoning::ProbeRecord::new(
                seq,
                "baseline",
                "baseline",
                "none",
                config.seed,
                req_hash,
                resp_hash,
                0.0,
                ms,
            ));
        }
    }
    if baseline.is_waf_blocked() {
        warn!(
            target=%scrubber.scrub(target.as_str()),
            "possible WAF detected (repeated 403/406)"
        );
    }
    // Blocking WAF = actionable warn; mere CDN presence (e.g. `cf-ray`
    // on a normal 200, `blocking=false`) = informational `info!` so a
    // `cloudflare` fingerprint doesn't read as an attack blocked.
    if baseline.is_waf_blocking() {
        warn!(
            target=%scrubber.scrub(target.as_str()),
            vendor=%baseline.waf_vendor.as_deref().unwrap_or("unknown"),
            hits=%baseline.waf_hits.join(","),
            blocking=true,
            "WAF blocking signals detected (challenge/deny/rate-limit)"
        );
    } else if baseline.is_waf_suspected() {
        info!(
            target=%scrubber.scrub(target.as_str()),
            vendor=%baseline.waf_vendor.as_deref().unwrap_or("unknown"),
            hits=%baseline.waf_hits.join(","),
            blocking=false,
            "CDN/WAF fingerprinted (informational, no block)"
        );
    }
    // Effective tampers: only an active WAF block auto-enables a bypass.
    // Mere CDN presence (for example `cf-ray` on a normal 200 response)
    // remains informational and must not alter probe semantics. A bare
    // `403/406/429` count without vendor/marker corroboration (app auth,
    // content negotiation, self-induced 429 at high `--threads`) must not
    // auto-tamper either — that would poison probes and bypass the cache.
    let waf_corroborated = baseline.is_waf_blocking() || baseline.is_waf_suspected();
    let effective_tampers: Vec<Tamper> = if (baseline.is_waf_blocking()
        || (baseline.is_waf_blocked() && waf_corroborated))
        && config.evasion.tampers.is_empty()
    {
        info!(
            "WAF suspected and no --tamper given — auto-enabling space2comment,randomcase for detection"
        );
        waf_auto_tampers()
    } else {
        config.evasion.tampers.clone()
    };
    if !effective_tampers.is_empty() {
        info!(
            tampers=?effective_tampers.iter().map(super::super::techniques::tamper::Tamper::name).collect::<Vec<_>>(),
            "WAF tampers active"
        );
    }
    let effective_opts = ProbeOpts::new(config.evasion.hpp, config.evasion.chunked);
    if effective_opts.is_active() {
        info!(hpp=%effective_opts.hpp, chunked=%effective_opts.chunked, "request-level tampers active");
    }
    Ok(Some((baseline, effective_tampers, effective_opts)))
}
