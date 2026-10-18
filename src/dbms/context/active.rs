use super::{
    CommentStyle, ContextProbeResult, DbmsBelief, MAX_CONTEXT_PROBES, QuoteContext,
    check_sql_errors, infer_passive_context,
};
use crate::{
    dbms::common::DbmsKind,
    detection::{baseline::Baseline, response_diff::adaptive_similarity},
    http::client::{HttpClient, RequestSpec},
    session::state::SessionState,
    target::{parameters::TargetParameter, raw_request::RawRequest, url::TargetUrl},
};
use std::{sync::Arc, time::Instant};
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

/// Executes adaptive context and fingerprinting probe (<=8 requests total).
///
/// If `dbms_hint` is provided, exactly 0 active DBMS probes are sent.
///
/// # Errors
/// Returns error if network client encounters unrecoverable failure.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub async fn analyze_context(
    client: &HttpClient,
    state: &Arc<RwLock<SessionState>>,
    cancel: &CancellationToken,
    target: &TargetUrl,
    param: &TargetParameter,
    raw: Option<&RawRequest>,
    baseline: &Baseline,
    dbms_hint: Option<&str>,
) -> ContextProbeResult {
    // 1. Start with passive signals (0 requests)
    let mut context = infer_passive_context(param, raw);
    let mut probes_sent = 0usize;
    let mut error_evidence = None;

    // 2. Initialise DBMS belief
    let mut dbms_belief = if let Some(hint) = dbms_hint {
        info!(
            hint,
            "adaptive context: DBMS pinned by --dbms hint (0 DBMS probe)"
        );
        DbmsBelief::from_hint(hint)
    } else {
        DbmsBelief::uniform()
    };

    if cancel.is_cancelled() {
        return ContextProbeResult {
            context,
            dbms_belief,
            probes_sent,
            error_evidence,
        };
    }

    // If explicit --dbms hint is given, VERROU: send 0 active DBMS probes.
    if dbms_hint.is_some() {
        let (top, _) = dbms_belief.top_candidate();
        context.comment = match top {
            DbmsKind::MySql => CommentStyle::Hash,
            _ => CommentStyle::DashDash,
        };
        return ContextProbeResult {
            context,
            dbms_belief,
            probes_sent,
            error_evidence,
        };
    }

    // Baseline response details
    let baseline_body = baseline.representative_body_str();

    // Probe 1: Benign single quote injection: `param_value'`
    let base_val = if param.original_value.is_empty() {
        "1"
    } else {
        &param.original_value
    };
    let single_quote_payload = format!("{base_val}'");

    if probes_sent < MAX_CONTEXT_PROBES && !cancel.is_cancelled() {
        let (body, _elapsed, status) = fetch_probe_simple(
            client,
            state,
            cancel,
            target,
            param,
            &single_quote_payload,
            raw,
        )
        .await;
        probes_sent = probes_sent.saturating_add(1);

        // Check for vendor error messages
        if let Some((kind, evidence)) = check_sql_errors(&body) {
            info!(%kind, %evidence, "context probe: detected vendor SQL error");
            dbms_belief.update_with_signal(kind, 0.98);
            context.quote = QuoteContext::SingleQuote;
            error_evidence = Some(evidence);

            context.comment = match kind {
                DbmsKind::MySql => CommentStyle::Hash,
                _ => CommentStyle::DashDash,
            };

            return ContextProbeResult {
                context,
                dbms_belief,
                probes_sent,
                error_evidence,
            };
        }

        // If status == 500 or significant difference from baseline, single quote broke query
        // Phase 0 : erreur transport (`status == 0`, body vide, non comptée
        // dans `fetch_probe_simple`) ne doit jamais valoir `quote_broke`.
        let sim = adaptive_similarity(&baseline_body, &body);
        let quote_broke = status != 0 && (status == 500 || sim < 0.65);

        if quote_broke && probes_sent < MAX_CONTEXT_PROBES && !cancel.is_cancelled() {
            // Probe 2: Try comment closure `param_value'-- ` to verify single-quote context
            let comment_closure_payload = format!("{base_val}'-- ");
            let (body_closure, _elapsed, status_closure) = fetch_probe_simple(
                client,
                state,
                cancel,
                target,
                param,
                &comment_closure_payload,
                raw,
            )
            .await;
            probes_sent = probes_sent.saturating_add(1);

            let sim_closure = adaptive_similarity(&baseline_body, &body_closure);
            if (status_closure == 200
                || status_closure == baseline.status_codes.first().copied().unwrap_or(200))
                && sim_closure > 0.80
            {
                debug!("context probe: comment closure restored baseline -> SingleQuote");
                context.quote = QuoteContext::SingleQuote;
                context.comment = CommentStyle::DashDash;
            }
        }
    }

    // Probe 3: If context is still not single quote and value is numeric, verify numeric context
    if context.quote != QuoteContext::SingleQuote
        && context.numeric
        && probes_sent < MAX_CONTEXT_PROBES
        && !cancel.is_cancelled()
    {
        let plus_zero = format!("{base_val}+0");
        let (body_zero, _elapsed, status_zero) =
            fetch_probe_simple(client, state, cancel, target, param, &plus_zero, raw).await;
        probes_sent = probes_sent.saturating_add(1);

        let sim_zero = adaptive_similarity(&baseline_body, &body_zero);
        if (status_zero == 200
            || status_zero == baseline.status_codes.first().copied().unwrap_or(200))
            && sim_zero > 0.85
            && probes_sent < MAX_CONTEXT_PROBES
            && !cancel.is_cancelled()
        {
            let plus_large = format!("{base_val}+999999");
            let (body_large, _elapsed, status_large) =
                fetch_probe_simple(client, state, cancel, target, param, &plus_large, raw).await;
            probes_sent = probes_sent.saturating_add(1);

            let sim_large = adaptive_similarity(&baseline_body, &body_large);
            // Phase 0 : erreur transport (status 0 / body vide) ne confirme
            // jamais le contexte numérique.
            if status_large != 0 && !body_large.is_empty() && sim_large < 0.70 {
                debug!("context probe: arithmetic confirmed numeric bare context");
                context.quote = QuoteContext::None;
                context.numeric = true;
            }
        }
    }

    // Probe 4: If still unknown, check double-quote context
    if context.quote == QuoteContext::Unknown
        && probes_sent < MAX_CONTEXT_PROBES
        && !cancel.is_cancelled()
    {
        let double_quote_payload = format!("{base_val}\"");
        let (body, _elapsed, status) = fetch_probe_simple(
            client,
            state,
            cancel,
            target,
            param,
            &double_quote_payload,
            raw,
        )
        .await;
        probes_sent = probes_sent.saturating_add(1);

        if let Some((kind, evidence)) = check_sql_errors(&body) {
            dbms_belief.update_with_signal(kind, 0.98);
            context.quote = QuoteContext::DoubleQuote;
            error_evidence = Some(evidence);
        } else {
            let sim = adaptive_similarity(&baseline_body, &body);
            // Phase 0 : même garde transport que probe 1.
            if status != 0
                && (status == 500 || sim < 0.65)
                && probes_sent < MAX_CONTEXT_PROBES
                && !cancel.is_cancelled()
            {
                let double_closure = format!("{base_val}\"-- ");
                let (body_closure, _elapsed, status_closure) =
                    fetch_probe_simple(client, state, cancel, target, param, &double_closure, raw)
                        .await;
                probes_sent = probes_sent.saturating_add(1);

                let sim_closure = adaptive_similarity(&baseline_body, &body_closure);
                if (status_closure == 200
                    || status_closure == baseline.status_codes.first().copied().unwrap_or(200))
                    && sim_closure > 0.80
                {
                    context.quote = QuoteContext::DoubleQuote;
                }
            }
        }
    }

    ContextProbeResult {
        context,
        dbms_belief,
        probes_sent,
        error_evidence,
    }
}

async fn fetch_probe_simple(
    client: &HttpClient,
    state: &Arc<RwLock<SessionState>>,
    cancel: &CancellationToken,
    target: &TargetUrl,
    param: &TargetParameter,
    payload: &str,
    raw: Option<&RawRequest>,
) -> (String, f64, u16) {
    let spec = build_spec_for_context(target, param, payload, raw);
    let start = Instant::now();
    let resp = client.send_with_retry(spec, cancel).await;
    let elapsed = start.elapsed().as_secs_f64() * 1000.0;

    match resp {
        Ok(r) => {
            let status = r.status().as_u16();
            match client.read_body_string_with_timeout(r).await {
                Ok(body) => {
                    // Succès transport : seule issue comptée. Un body vide
                    // légitime (200 vide) reste compté (similarité ~1.0 de
                    // toute façon) ; seules les erreurs transport (ci-dessous,
                    // body vide + status 0) ne sont pas comptées (Phase 0).
                    state.write().await.increment_requests();
                    (body, elapsed, status)
                }
                Err(e) => {
                    warn!(error=%e, "context probe body read failed");
                    (String::new(), elapsed, 0)
                }
            }
        }
        Err(e) => {
            warn!(error=%e, "context probe request failed");
            (String::new(), elapsed, 0)
        }
    }
}

#[allow(clippy::too_many_lines)]
pub(super) fn build_spec_for_context(
    target: &TargetUrl,
    param: &TargetParameter,
    payload: &str,
    raw: Option<&RawRequest>,
) -> RequestSpec {
    use crate::target::parameters::ParameterLocation;
    use http::Method;

    match &param.location {
        ParameterLocation::Query => {
            let mut url = target.inner().clone();
            let mut pairs = Vec::new();
            let mut matched = false;
            for (k, v) in target.inner().query_pairs() {
                if k == param.name {
                    pairs.push((k.into_owned(), payload.to_owned()));
                    matched = true;
                } else {
                    pairs.push((k.into_owned(), v.into_owned()));
                }
            }
            if !matched {
                pairs.push((param.name.clone(), payload.to_owned()));
            }
            // Phase 0 bugfix (documenté) : l'ancienne concat `k=v` brute
            // n'encodait rien (`'`/`"`/espace/`+` passés crus, `+` décodé en
            // espace côté serveur → `1+0` devenait `1 0`). `query_pairs_mut`
            // (form_urlencoded) percent-encode (`'`→`%27`, `+`→`%2B`, …) ;
            // `query_pairs()` côté serveur décode à l'identique, L1
            // byte-identique sur payloads alphanumériques.
            {
                let mut qp = url.query_pairs_mut();
                qp.clear();
                for (k, v) in &pairs {
                    qp.append_pair(k, v);
                }
            }

            let mut headers = http::HeaderMap::new();
            if let Some(r) = raw {
                for (k, v) in &r.headers {
                    if let (Ok(name), Ok(val)) = (
                        http::HeaderName::from_bytes(k.as_bytes()),
                        http::HeaderValue::from_str(v),
                    ) {
                        headers.insert(name, val);
                    }
                }
            }
            let method = raw
                .and_then(|r| Method::from_bytes(r.method.as_bytes()).ok())
                .unwrap_or(Method::GET);
            let mut spec = RequestSpec::new(method, url.as_str().to_owned()).with_headers(headers);
            if let Some(body) = raw.and_then(|r| r.body.as_ref()) {
                spec = spec.with_body(body.as_bytes().to_vec());
            }
            spec
        }
        ParameterLocation::Body => {
            let mut headers = http::HeaderMap::new();
            if let Some(r) = raw {
                for (k, v) in &r.headers {
                    if let (Ok(name), Ok(val)) = (
                        http::HeaderName::from_bytes(k.as_bytes()),
                        http::HeaderValue::from_str(v),
                    ) {
                        headers.insert(name, val);
                    }
                }
            }
            let body_str = raw.and_then(|r| r.body.as_deref()).unwrap_or_default();
            let new_body = if body_str.contains(&format!("{}=", param.name)) {
                let mut parts = Vec::new();
                for pair in body_str.split('&') {
                    if let Some((k, _)) = pair.split_once('=') {
                        if k == param.name {
                            parts.push(format!("{k}={payload}"));
                        } else {
                            parts.push(pair.to_owned());
                        }
                    } else {
                        parts.push(pair.to_owned());
                    }
                }
                parts.join("&")
            } else if body_str.is_empty() {
                format!("{}={payload}", param.name)
            } else {
                format!("{body_str}&{}={payload}", param.name)
            };

            let method = raw
                .and_then(|r| Method::from_bytes(r.method.as_bytes()).ok())
                .unwrap_or(Method::POST);
            RequestSpec::new(method, target.as_str().to_owned())
                .with_headers(headers)
                .with_body(new_body.into_bytes())
        }
        ParameterLocation::Header(h) => {
            let mut headers = http::HeaderMap::new();
            if let Some(r) = raw {
                for (k, v) in &r.headers {
                    if let (Ok(name), Ok(val)) = (
                        http::HeaderName::from_bytes(k.as_bytes()),
                        http::HeaderValue::from_str(v),
                    ) {
                        headers.insert(name, val);
                    }
                }
            }
            if let (Ok(name), Ok(val)) = (
                http::HeaderName::from_bytes(h.as_bytes()),
                http::HeaderValue::from_str(payload),
            ) {
                headers.insert(name, val);
            }
            let method = raw
                .and_then(|r| Method::from_bytes(r.method.as_bytes()).ok())
                .unwrap_or(Method::GET);
            RequestSpec::new(method, target.as_str().to_owned()).with_headers(headers)
        }
        ParameterLocation::Cookie => {
            let mut headers = http::HeaderMap::new();
            let mut cookies: Vec<(String, String)> = Vec::new();
            if let Some(r) = raw {
                for (k, v) in &r.headers {
                    if k.eq_ignore_ascii_case("cookie") {
                        for part in v.split(';') {
                            if let Some((ck, cv)) = part.trim().split_once('=') {
                                cookies.push((ck.trim().to_owned(), cv.trim().to_owned()));
                            }
                        }
                    } else if let (Ok(name), Ok(val)) = (
                        http::HeaderName::from_bytes(k.as_bytes()),
                        http::HeaderValue::from_str(v),
                    ) {
                        headers.insert(name, val);
                    }
                }
            }
            let mut found = false;
            for (ck, cv) in &mut cookies {
                if ck == &param.name {
                    payload.clone_into(cv);
                    found = true;
                }
            }
            if !found {
                cookies.push((param.name.clone(), payload.to_owned()));
            }
            let cookie_val = cookies
                .into_iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("; ");
            if let Ok(val) = http::HeaderValue::from_str(&cookie_val) {
                headers.insert(http::header::COOKIE, val);
            }
            let method = raw
                .and_then(|r| Method::from_bytes(r.method.as_bytes()).ok())
                .unwrap_or(Method::GET);
            RequestSpec::new(method, target.as_str().to_owned()).with_headers(headers)
        }
    }
}
