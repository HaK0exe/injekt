//! `NoSQL` detection probe (`test_nosql_bounded`) + its letter/JSON-body fetch
//! helpers (`fetch_nosql_boolean`, `fetch_nosql_error`, `nosql_json_body_spec`,
//! `fetch_spec_boolean`). Moved verbatim from `engine/probes.rs` (P1); no
//! behaviour change.

use crate::engine::fetch::{fetch_for_payload, fetch_for_payload_with_class};
use crate::{
    http::{
        client::{HttpClient, RequestSpec},
        timeouts::RequestClass,
    },
    session::state::{Finding, SessionState, TechniqueKind},
    target::{
        injection::{ProbeOpts, is_ignored, payload_budget},
        markers::MarkerSet,
        parameters::{ParameterLocation, TargetParameter},
        raw_request::RawRequest,
        url::TargetUrl,
    },
    techniques::{
        nosql::{detector::NosqlDetector, payloads::nosql_payloads},
        payload_opts::{PayloadOpts, build_final_payload_with_rng},
        tamper::{Tamper, boolean_safe_transformation_sets},
    },
};
use std::{sync::Arc, time::Instant};
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::techniques::technique::{Technique, TechniqueCtx};
use futures::future::BoxFuture;

/// `NoSQL` (MongoDB) operator injection: boolean differential over `$gt`/`$ne`/
/// `$regex` operator pairs (3-trial confirmation) plus a single-shot error
/// probe (`$where` JS invalide / opérateur inconnu → messages MongoDB).
///
/// Deux chemins d'injection :
/// - bodies JSON (`param` Body + corps JSON) : la feuille
///   `{"user":"admin"}` devient un **objet** `{"user":{"$gt":""}}` via
///   `inject_json_operator` (bypass `{"user": {"$gt": ""}}` sans identifiants).
///   Les tampers chaîne ne s'appliquent pas ici (un opérateur doit rester du
///   JSON valide) ;
/// - Query / Form / Header / Cookie : les mêmes opérateurs sont envoyés comme
///   **chaînes** (`{"$gt": ""}` en valeur de param) via le chemin générique
///   (tampers boolean-safe + `--prefix`/`--suffix` honorés).
pub(crate) struct NosqlTechnique;

impl Technique for NosqlTechnique {
    fn kind(&self) -> TechniqueKind {
        TechniqueKind::Nosql
    }

    #[allow(
        clippy::too_many_arguments,
        clippy::similar_names,
        clippy::too_many_lines
    )]
    fn probe<'a>(&'a self, ctx: &'a TechniqueCtx<'a>) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let client = ctx.client;
            let state = ctx.state;
            let cancel = ctx.cancel;
            let target = ctx.target;
            let target_str = ctx.target_str;
            let param = ctx.param;
            let baseline = ctx.baseline;
            let marker_set = ctx.marker_set;
            let raw = ctx.raw;
            let tampers = ctx.tampers;
            let opts = ctx.opts;
            let popts = ctx.popts;
            let matcher = ctx.matcher;
            let level = ctx.level;
            let ignore_codes = ctx.ignore_codes;
            let seed = ctx.seed;
            let context = ctx.context;
            if context.json {
                debug!(
                    param = param.key(),
                    "nosql: json context, nosql priors boosted"
                );
            }
            debug!(
                param = param.key(),
                context = context.summary(),
                "nosql: context-aware detection"
            );
            let mut rng = crate::seeded_rng::make_rng(seed);
            let detector = NosqlDetector::new();
            let payloads = nosql_payloads();
            let baseline_body = matcher.pre_process(&baseline.representative_body_str());
            let tamper_sets = boolean_safe_transformation_sets(tampers);
            // Chemin opérateur JSON ? Body + corps JSON + feuille scalaire.
            let json_operator_path: Option<String> = match &param.location {
                ParameterLocation::Body => {
                    let body_opt = raw.and_then(|r| r.body.as_deref());
                    let ct = raw.and_then(|r| r.content_type());
                    body_opt
                        .filter(|body| {
                            crate::target::structured::sniff_kind(ct, body)
                                == crate::target::structured::StructuredKind::Json
                        })
                        .map(str::to_owned)
                }
                _ => None,
            };
            for p in payloads
                .iter()
                .take(payload_budget(level, 2, payloads.len()))
            {
                if cancel.is_cancelled() {
                    break;
                }
                let mut found = false;
                // Tampers chaîne uniquement pour le chemin non-JSON ; le chemin
                // opérateur envoie du JSON valide tel quel (1 seul set `none`).
                let tamper_rounds: usize = if json_operator_path.is_some() {
                    1
                } else {
                    tamper_sets.len().max(1)
                };
                for round in 0..tamper_rounds {
                    if cancel.is_cancelled() {
                        break;
                    }
                    let trans: &[Tamper] = if json_operator_path.is_some() {
                        &[]
                    } else {
                        tamper_sets.get(round).map_or(&[], Vec::as_slice)
                    };
                    let tamper_label = if trans.is_empty() {
                        "none".to_owned()
                    } else {
                        trans
                            .iter()
                            .map(crate::techniques::tamper::Tamper::name)
                            .collect::<Vec<_>>()
                            .join(",")
                    };
                    // Channel 1 — boolean differential with confirmation (3 trials)
                    let mut trials: Vec<crate::detection::confirmation::Trial> =
                        Vec::with_capacity(3);
                    let mut last_true = String::new();
                    let mut last_false = String::new();
                    let mut last_t_status: u16 = 0;
                    #[allow(clippy::similar_names)]
                    let mut last_f_status: u16 = 0;
                    for _ in 0..3 {
                        if cancel.is_cancelled() {
                            break;
                        }
                        let (true_raw, true_ms, true_status) = fetch_nosql_boolean(
                            client,
                            state,
                            cancel,
                            target,
                            target_str,
                            param,
                            raw,
                            json_operator_path.as_deref(),
                            &p.true_operator,
                            &p.true_payload,
                            trans,
                            marker_set,
                            opts,
                            popts,
                            &mut rng,
                        )
                        .await;
                        let true_body = matcher.pre_process(&true_raw);
                        let (false_raw, false_ms, false_status) = fetch_nosql_boolean(
                            client,
                            state,
                            cancel,
                            target,
                            target_str,
                            param,
                            raw,
                            json_operator_path.as_deref(),
                            &p.false_operator,
                            &p.false_payload,
                            trans,
                            marker_set,
                            opts,
                            popts,
                            &mut rng,
                        )
                        .await;
                        let false_body = matcher.pre_process(&false_raw);
                        // Transport failure (`status == 0`) is never scored — neutral
                        // trial, consistent with `test_boolean_bounded`.
                        if true_status == 0 || false_status == 0 {
                            trials.push(crate::detection::confirmation::Trial {
                                true_conf: 0.5,
                                false_conf: 0.5,
                            });
                            last_true = true_body;
                            last_false = false_body;
                            last_t_status = true_status;
                            last_f_status = false_status;
                            continue;
                        }
                        if is_ignored(true_status, ignore_codes)
                            || is_ignored(false_status, ignore_codes)
                        {
                            trials.push(crate::detection::confirmation::Trial {
                                true_conf: 0.0,
                                false_conf: 1.0,
                            });
                            last_true = true_body;
                            last_false = false_body;
                            last_t_status = true_status;
                            last_f_status = false_status;
                            continue;
                        }
                        let res = detector.evaluate_boolean_with_match_ratio(
                            &baseline_body,
                            &true_body,
                            &false_body,
                            baseline.mean_ms,
                            true_ms,
                            false_ms,
                            baseline.match_ratio(),
                        );
                        // P1.2 : plancher de bruit appris et DEUX branches dans la
                        // bande (`noise_vetoed`) → trial neutre (0.5/0.5), comme le
                        // chemin booléen pur : il ne peut jamais confirmer.
                        let (t_conf, f_conf) = if res.noise_vetoed {
                            (0.5, 0.5)
                        } else {
                            (res.true_similarity, res.false_similarity)
                        };
                        trials.push(crate::detection::confirmation::Trial {
                            true_conf: t_conf,
                            false_conf: f_conf,
                        });
                        last_true = true_body;
                        last_false = false_body;
                        last_t_status = true_status;
                        last_f_status = false_status;
                    }
                    let (conf, inverted) = crate::detection::confirmation::confirm_either(&trials);
                    if conf.confirmed {
                        if matcher.gate_boolean(
                            &last_true,
                            &last_false,
                            last_t_status,
                            last_f_status,
                        ) == Some(false)
                        {
                            continue;
                        }
                        // Evidence shows the measured majority across trials, not
                        // whichever trial ran last (a trailing neutral/glitch trial
                        // must not rewrite the confirmed differential).
                        let (agg_true, agg_false) =
                            crate::detection::confirmation::aggregate_sims(&trials);
                        let mut finding = Finding::new(
                    target.as_str(),
                    param.key(),
                    TechniqueKind::Nosql,
                    conf.score,
                    format!(
                        "nosql channel=boolean vector={} dbms=mongodb true_sim={:.2} false_sim={:.2} trials={}/3 fp={:.2} tamper={}{}{}{}{}",
                        p.vector,
                        agg_true,
                        agg_false,
                        conf.trials,
                        conf.false_positive_prob,
                        tamper_label,
                        opts.evidence_suffix(),
                        popts.evidence_suffix(),
                        matcher.evidence_suffix(),
                        if inverted { " inverted" } else { "" }
                    ),
                )
                .with_false_positive_prob(conf.false_positive_prob)
                .with_waf(baseline.waf_vendor.clone(), baseline.is_waf_blocking());
                        finding.dbms = Some("mongodb".to_owned());
                        state.write().await.push_finding(finding);
                        found = true;
                        break;
                    }
                    // Channel 2 — single-shot NoSQL error probe
                    let (raw_body, _ms, status) = fetch_nosql_error(
                        client,
                        state,
                        cancel,
                        target,
                        target_str,
                        param,
                        raw,
                        json_operator_path.as_deref(),
                        &p.error_payload,
                        trans,
                        marker_set,
                        opts,
                        popts,
                        &mut rng,
                    )
                    .await;
                    let body = matcher.pre_process(&raw_body);
                    if is_ignored(status, ignore_codes) {
                        continue;
                    }
                    let r = detector.evaluate_error(&body);
                    if r.is_vulnerable {
                        if matcher.matches(&body, status) == Some(false) {
                            continue;
                        }
                        let mut finding = Finding::new(
                            target.as_str(),
                            param.key(),
                            TechniqueKind::Nosql,
                            r.confidence,
                            format!(
                                "nosql channel=error vector={} pattern={:?} tamper={}{}{}{}",
                                p.vector,
                                r.matched_pattern,
                                tamper_label,
                                opts.evidence_suffix(),
                                popts.evidence_suffix(),
                                matcher.evidence_suffix()
                            ),
                        );
                        finding.dbms = Some("mongodb".to_owned());
                        state.write().await.push_finding(finding);
                        found = true;
                        break;
                    }
                }
                if found {
                    break;
                }
            }
        })
    }
}

/// Fetch du bras TRUE/FALSE `NoSQL` : objet opérateur sur bodies JSON,
/// chaîne tamperisée ailleurs. Retourne `(body, ms, status)` comme
/// `fetch_for_payload_with_class` (classe `Boolean`, statut 0 = transport).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn fetch_nosql_boolean(
    client: &HttpClient,
    state: &Arc<RwLock<SessionState>>,
    cancel: &CancellationToken,
    target: &TargetUrl,
    target_str: &str,
    param: &TargetParameter,
    raw: Option<&RawRequest>,
    json_body: Option<&str>,
    operator: &serde_json::Value,
    string_payload: &str,
    trans: &[Tamper],
    marker_set: &MarkerSet,
    opts: ProbeOpts,
    popts: &PayloadOpts,
    rng: &mut rand::rngs::StdRng,
) -> (String, f64, u16) {
    if let Some(original) = json_body
        && let Some(injected) =
            crate::target::structured::inject_json_operator(original, &param.name, operator)
    {
        let spec = nosql_json_body_spec(target, raw, &injected);
        return fetch_spec_boolean(client, state, cancel, spec).await;
    }
    let final_payload = build_final_payload_with_rng(string_payload, trans, popts, rng);
    fetch_for_payload_with_class(
        client,
        state,
        cancel,
        target,
        target_str,
        param,
        &final_payload,
        marker_set,
        raw,
        opts,
        popts,
        RequestClass::Boolean,
    )
    .await
}

/// Fetch de la sonde d'erreur `NoSQL` : objet `$where`/opérateur inconnu sur
/// bodies JSON (parsé depuis le littéral, repli chaîne), chaîne ailleurs.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn fetch_nosql_error(
    client: &HttpClient,
    state: &Arc<RwLock<SessionState>>,
    cancel: &CancellationToken,
    target: &TargetUrl,
    target_str: &str,
    param: &TargetParameter,
    raw: Option<&RawRequest>,
    json_body: Option<&str>,
    error_payload: &str,
    trans: &[Tamper],
    marker_set: &MarkerSet,
    opts: ProbeOpts,
    popts: &PayloadOpts,
    rng: &mut rand::rngs::StdRng,
) -> (String, f64, u16) {
    if let Some(original) = json_body
        && let Ok(op) = serde_json::from_str::<serde_json::Value>(error_payload)
        && op.is_object()
        && let Some(injected) =
            crate::target::structured::inject_json_operator(original, &param.name, &op)
    {
        let spec = nosql_json_body_spec(target, raw, &injected);
        return fetch_spec_boolean(client, state, cancel, spec).await;
    }
    let final_payload = build_final_payload_with_rng(error_payload, trans, popts, rng);
    fetch_for_payload(
        client,
        state,
        cancel,
        target,
        target_str,
        param,
        &final_payload,
        marker_set,
        raw,
        opts,
        popts,
    )
    .await
}

/// `RequestSpec` POST JSON pour un body opérateur déjà injecté (headers
/// préservés, `content-length` recalculé par la stack HTTP).
pub(crate) fn nosql_json_body_spec(
    target: &TargetUrl,
    raw: Option<&RawRequest>,
    injected_body: &str,
) -> RequestSpec {
    let method = raw
        .and_then(|r| http::Method::from_bytes(r.method.as_bytes()).ok())
        .unwrap_or(http::Method::POST);
    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static("application/json"),
    );
    if let Some(r) = raw {
        for (k, v) in &r.headers {
            if k.eq_ignore_ascii_case("content-type") || k.eq_ignore_ascii_case("content-length") {
                continue;
            }
            if let (Ok(name), Ok(val)) = (
                http::HeaderName::from_bytes(k.as_bytes()),
                http::HeaderValue::from_str(v),
            ) {
                headers.insert(name, val);
            }
        }
    }
    RequestSpec::new(method, target.as_str().to_owned())
        .with_headers(headers)
        .with_body(injected_body.as_bytes().to_vec())
}

/// Envoi basse-niveau d'un `RequestSpec` `NoSQL` sous timeout booléen
/// (`RequestClass::Boolean`), compté et borné comme les autres sondes.
/// Transport/body-read en échec → `(String::new(), ms, 0)` (jamais scoré).
pub(crate) async fn fetch_spec_boolean(
    client: &HttpClient,
    state: &Arc<RwLock<SessionState>>,
    cancel: &CancellationToken,
    spec: RequestSpec,
) -> (String, f64, u16) {
    let start = Instant::now();
    let resp = client
        .send_with_retry_for_class(spec, RequestClass::Boolean, cancel)
        .await;
    let elapsed = start.elapsed().as_secs_f64() * 1000.0;
    state.write().await.increment_requests();
    match resp {
        Ok(r) => {
            let status = r.status().as_u16();
            match client
                .read_body_string_for_class(r, RequestClass::Boolean)
                .await
            {
                Ok(body) => (body, elapsed, status),
                Err(e) => {
                    warn!(error=%e, "nosql probe body read failed, skipping score");
                    (String::new(), elapsed, 0)
                }
            }
        }
        Err(e) => {
            warn!(error=%e, "nosql probe request failed, skipping score");
            (String::new(), elapsed, 0)
        }
    }
}
