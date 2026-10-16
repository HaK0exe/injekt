#![deny(unsafe_code)]

//! Confirmation second-pass + mini-mutation (P1).
//! Extracted verbatim from `orchestrator.rs`; no behaviour change.

use super::{
    fetch::{fetch_for_payload, fetch_for_payload_with_class},
    schedule::order_boolean_by_context,
};
use crate::{
    dbms::context::InjectionContext,
    detection::baseline,
    http::{client::HttpClient, timeouts::RequestClass},
    session::state::{Finding, SessionState, TechniqueKind},
    target::{
        injection::{ProbeOpts, is_ignored, payload_budget},
        markers::MarkerSet,
        parameters::{ParameterLocation, TargetParameter},
        raw_request::RawRequest,
        url::TargetUrl,
    },
    techniques::{
        boolean::{detector::BooleanDetector, payloads::boolean_payloads_for},
        payload_opts::{PayloadOpts, build_final_payload_with_rng},
        tamper::Tamper,
    },
};
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};

/// Outcome of the lightweight error→boolean confirmation probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ErrorBoolConfirm {
    Confirmed,
    Denied,
    Inconclusive,
    Skipped,
}

impl ErrorBoolConfirm {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Confirmed => "true",
            Self::Denied => "false",
            Self::Inconclusive => "inconclusive",
            Self::Skipped => "skipped",
        }
    }
}

pub(crate) struct ErrorBoolOutcome {
    pub(crate) verdict: ErrorBoolConfirm,
    pub(crate) true_sim: f64,
    pub(crate) false_sim: f64,
}

/// Lightweight confirmation for error hits without an extracted fragment
/// (confidence 0.75): one boolean TRUE/FALSE pair (+2 requests) on the same
/// parameter, reusing the error-hit tamper set filtered to boolean-safe
/// tampers. Returns `Skipped` without any request when the boolean technique
/// is disabled, `Inconclusive` on transport failure/cancel (never scores
/// `""`), `Denied` on a clean differential or matcher veto.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(crate) async fn confirm_error_with_boolean(
    client: &HttpClient,
    state: &Arc<RwLock<SessionState>>,
    cancel: &CancellationToken,
    target: &TargetUrl,
    target_str: &str,
    param: &TargetParameter,
    baseline: &baseline::Baseline,
    baseline_body: &str,
    marker_set: &MarkerSet,
    raw: Option<&RawRequest>,
    trans: &[Tamper],
    opts: ProbeOpts,
    popts: &PayloadOpts,
    matcher: &crate::detection::matcher::MatcherConfig,
    ignore_codes: &[u16],
    boolean_enabled: bool,
    seed: Option<u64>,
) -> ErrorBoolOutcome {
    const INCONCLUSIVE: ErrorBoolOutcome = ErrorBoolOutcome {
        verdict: ErrorBoolConfirm::Inconclusive,
        true_sim: 0.0,
        false_sim: 0.0,
    };
    // Seeded tamper RNG (`--seed`): same seed yields identical payloads;
    // `None` preserves the historical OS-random behaviour.
    let mut rng = crate::seeded_rng::make_rng(seed);
    if !boolean_enabled {
        return ErrorBoolOutcome {
            verdict: ErrorBoolConfirm::Skipped,
            true_sim: 0.0,
            false_sim: 0.0,
        };
    }
    if cancel.is_cancelled() {
        return INCONCLUSIVE;
    }
    let pairs = boolean_payloads_for(None);
    let Some(pair) = pairs.first() else {
        return INCONCLUSIVE;
    };
    // Keep the WAF-bypass coherence (e.g. auto space2comment) without breaking
    // the TRUE/FALSE differential: drop opaque tampers like base64encode.
    let safe_trans: Vec<Tamper> = trans
        .iter()
        .filter(|t| t.is_boolean_safe())
        .cloned()
        .collect();
    let true_payload =
        build_final_payload_with_rng(&pair.true_payload, &safe_trans, popts, &mut rng);
    let false_payload =
        build_final_payload_with_rng(&pair.false_payload, &safe_trans, popts, &mut rng);
    let (true_raw, true_ms, true_status) = fetch_for_payload_with_class(
        client,
        state,
        cancel,
        target,
        target_str,
        param,
        &true_payload,
        marker_set,
        raw,
        opts,
        popts,
        RequestClass::Boolean,
    )
    .await;
    if cancel.is_cancelled() {
        return INCONCLUSIVE;
    }
    let (false_raw, false_ms, false_status) = fetch_for_payload_with_class(
        client,
        state,
        cancel,
        target,
        target_str,
        param,
        &false_payload,
        marker_set,
        raw,
        opts,
        popts,
        RequestClass::Boolean,
    )
    .await;
    // Transport/body failures are never scored as `""` — inconclusive, not denied.
    if true_status == 0 || false_status == 0 {
        return INCONCLUSIVE;
    }
    if is_ignored(true_status, ignore_codes) || is_ignored(false_status, ignore_codes) {
        return ErrorBoolOutcome {
            verdict: ErrorBoolConfirm::Denied,
            true_sim: 0.0,
            false_sim: 1.0,
        };
    }
    let true_body = matcher.pre_process(&baseline.strip_dynamic_content(&true_raw));
    let false_body = matcher.pre_process(&baseline.strip_dynamic_content(&false_raw));
    let res = BooleanDetector::new().evaluate_with_match_ratio(
        baseline_body,
        &true_body,
        &false_body,
        baseline.mean_ms,
        true_ms,
        false_ms,
        baseline.match_ratio(),
    );
    if matcher.gate_boolean(&true_body, &false_body, true_status, false_status) == Some(false) {
        return ErrorBoolOutcome {
            verdict: ErrorBoolConfirm::Denied,
            true_sim: res.true_similarity,
            false_sim: res.false_similarity,
        };
    }
    if res.is_vulnerable && res.confidence > 0.6 {
        ErrorBoolOutcome {
            verdict: ErrorBoolConfirm::Confirmed,
            true_sim: res.true_similarity,
            false_sim: res.false_similarity,
        }
    } else {
        ErrorBoolOutcome {
            verdict: ErrorBoolConfirm::Denied,
            true_sim: res.true_similarity,
            false_sim: res.false_similarity,
        }
    }
}

/// `true` when at least one finding justifies fingerprint + enumeration:
/// any finding that is not an unconfirmed error probe. Error hits without a
/// fragment stay at `0.55 unconfirmed` until `confirm_error_with_boolean`
/// upgrades them to `0.9 bool_confirm=true` — running DBMS guessing or the
/// boolean-oracle enumerator on the unconfirmed shape yields `postgres` FPs
/// followed by `enumeration length inference failed` after a single probe
/// (observed on clean Next.js targets).
#[must_use]
pub(crate) fn is_confirmed_finding(f: &Finding) -> bool {
    !f.evidence.contains("unconfirmed") && f.confidence >= 0.5
}

/// `true` when at least one confirmed finding exists (see
/// [`is_confirmed_finding`]). Fingerprint filling and `--dbs`-style
/// enumeration require this; unconfirmed-only snapshots must stay silent.
#[must_use]
pub(crate) fn has_confirmed_finding(findings: &[Finding]) -> bool {
    findings.iter().any(is_confirmed_finding)
}

/// `true` when at least one finding justifies the heavy boolean-oracle
/// extraction: a *confirmed* boolean finding, or an error finding with an
/// extracted fragment (`extracted=yes`) or a confirmed boolean differential
/// (`bool_confirm=true`). Unconfirmed 0.55 error findings alone never qualify
/// — they would burn ~270-700 requests into `inference inconsistency`.
#[must_use]
pub(crate) fn is_extraction_eligible(findings: &[Finding]) -> bool {
    findings.iter().any(|f| {
        (f.technique == TechniqueKind::Boolean && is_confirmed_finding(f))
            || (f.technique == TechniqueKind::Error
                && (f.evidence.contains("extracted=yes")
                    || f.evidence.contains("bool_confirm=true")))
    })
}

/// Recover the injection [`TargetParameter`] for a finding (`name@location`,
/// split at the last `@`; unknown locations fall back to `Query`).
pub(crate) fn param_from_finding(finding: &Finding) -> TargetParameter {
    let (name, loc_str) = match finding.parameter.rsplit_once('@') {
        Some((n, l)) => (n.to_owned(), l.to_owned()),
        None => (finding.parameter.clone(), "query".to_owned()),
    };
    let location = if loc_str == "query" {
        ParameterLocation::Query
    } else if loc_str == "body" {
        ParameterLocation::Body
    } else if loc_str == "cookie" {
        ParameterLocation::Cookie
    } else if let Some(h) = loc_str.strip_prefix("header:") {
        ParameterLocation::Header(h.to_owned())
    } else {
        ParameterLocation::Query
    };
    TargetParameter::new(name, location, "1")
}

/// Push one C6 confirm trace record (hashes only, never clear secrets).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn push_confirm_trace(
    state: &Arc<RwLock<SessionState>>,
    param_key: &str,
    technique: TechniqueKind,
    mutation_plan: &str,
    seed: Option<u64>,
    payload: &str,
    body: &str,
    diff: f64,
    ms: f64,
) {
    let mut st = state.write().await;
    let seq = st.next_trace_seq();
    st.push_trace(crate::reasoning::ProbeRecord::from_clear(
        seq,
        param_key,
        &technique.to_string(),
        mutation_plan,
        seed,
        payload,
        body,
        diff,
        ms,
    ));
}

/// DBMS label hint from a finding's `dbms` field for quote-correct confirm
/// payloads (`None` = generic polyglots, historical default).
pub(crate) fn dbms_label_from_finding(finding: &Finding) -> Option<&'static str> {
    let v = finding.dbms.as_deref()?.trim().to_ascii_lowercase();
    match v.as_str() {
        "mysql" | "mariadb" => Some("mysql"),
        "postgres" | "postgresql" | "pgsql" => Some("postgres"),
        "mssql" | "sqlserver" | "sql-server" | "tsql" => Some("mssql"),
        "oracle" | "ora" => Some("oracle"),
        "sqlite" => Some("sqlite"),
        _ => None,
    }
}

/// Parse the confirmed UNION column width from evidence (`columns=N`,
/// `columns=Some(N)` or `columns=[N, ..]`). Returns `None` when absent or
/// unparsable — the caller falls back to the historical default width 3.
/// Pure, never panics (operator-controlled evidence).
pub(crate) fn parse_union_columns(evidence: &str) -> Option<usize> {
    let key = "columns=";
    let start = evidence.find(key)? + key.len();
    let rest = evidence[start..].trim_start();
    // Shapes: `3`, `Some(3)`, `[3, 4]`, `Ok(3)`. Scan the first ASCII digit run.
    let mut digits = String::new();
    let mut in_digits = false;
    for c in rest.chars() {
        if c.is_ascii_digit() {
            digits.push(c);
            in_digits = true;
        } else if in_digits {
            break;
        }
    }
    if digits.is_empty() {
        return None;
    }
    let parsed: usize = digits.parse().ok()?;
    if parsed == 0 || parsed > 32 {
        return None;
    }
    Some(parsed)
}

/// C5-tardif base payload for mutation: one raw base string per technique.
///
/// - `boolean`/`json`/`nosql` : le côté `TRUE` de la première paire (la mutation
///   vérifie que `TRUE` reste `≈baseline`, 1 requête par variante).
/// - `error`/`time`/`union`/`stacked` : le premier core DBMS-aware.
/// - `oob` : `None` (jamais muté).
///
/// `None` = pas de base disponible → 0 requête de mutation.
pub(crate) fn mutation_base_payload(finding: &Finding) -> Option<String> {
    let label = dbms_label_from_finding(finding);
    match finding.technique {
        TechniqueKind::Boolean => crate::techniques::boolean::payloads::boolean_payloads_for(label)
            .first()
            .map(|p| p.true_payload.clone()),
        TechniqueKind::Json => crate::techniques::json::payloads::json_payloads_for(label)
            .first()
            .map(|p| p.true_payload.clone()),
        TechniqueKind::Nosql => crate::techniques::nosql::payloads::nosql_payloads()
            .first()
            .map(|p| p.true_payload.clone()),
        TechniqueKind::Error => crate::techniques::error::payloads::error_payloads_for(label)
            .first()
            .map(|p| p.payload.clone()),
        TechniqueKind::Time => crate::techniques::time::payloads::time_payloads_for(label, 3)
            .first()
            .map(|p| p.payload.clone()),
        TechniqueKind::Union => crate::techniques::union::payloads::union_payloads_for(label, 3)
            .first()
            .map(|p| p.payload.clone()),
        TechniqueKind::Stacked => crate::techniques::stacked::payloads::stacked_payloads_for(label)
            .first()
            .map(|p| p.payload.clone()),
        TechniqueKind::Oob => None,
    }
}

/// C5-tardif mini-mutation second-pass (confirmés seuls).
///
/// Appelée **uniquement** depuis [`Engine::run_confirm_second_pass`], après
/// une re-validation réussie, donc uniquement sur des findings déjà
/// confirmés — jamais en détection première, jamais sur cible propre.
/// Garanties :
/// - gate [`crate::mutation::should_attempt_mutation`] : `--no-mutation`,
///   WAF blocking, non-confirmé, OOB → 0 requête, 0 trace.
/// - borné : ≤ [`crate::mutation::MAX_MUTATION_VARIANTS`] variantes,
///   1 requête chacune, ≤ [`crate::mutation::MAX_MUTATION_REQUESTS_PER_FINDING`]
///   par finding (4 effectives).
/// - seedé : `seed` dérivée du run (`derive_confirm_seed`).
/// - tracé : chaque sonde pousse un `ProbeRecord` `mutation:<famille>`.
/// - échec silencieux : le résultat ne crée ni ne supprime aucun finding ;
///   le finding d'origine est toujours conservé.
///   Retourne le nombre de requêtes de mutation envoyées (0..=4).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_mutation_for_finding(
    client: &HttpClient,
    state: &Arc<RwLock<SessionState>>,
    cancel: &CancellationToken,
    target: &TargetUrl,
    target_str: &str,
    param: &TargetParameter,
    finding: &Finding,
    marker_set: &MarkerSet,
    raw: Option<&RawRequest>,
    baseline: &baseline::Baseline,
    effective_tampers: &[Tamper],
    opts: ProbeOpts,
    popts: &PayloadOpts,
    matcher: &crate::detection::matcher::MatcherConfig,
    context: &InjectionContext,
    no_mutation: bool,
    seed: Option<u64>,
) -> usize {
    use crate::mutation::{MiniMutator, should_attempt_mutation};
    let baseline_blocking = baseline.is_waf_blocking() || baseline.is_waf_blocked();
    let confirmed = is_confirmed_finding(finding);
    let is_oob = finding.technique == TechniqueKind::Oob;
    if !should_attempt_mutation(no_mutation, baseline_blocking, confirmed, is_oob) {
        debug!(
            param = %finding.parameter,
            technique = %finding.technique,
            no_mutation,
            baseline_blocking,
            confirmed,
            "mutation skipped (gate)"
        );
        return 0;
    }
    let Some(base) = mutation_base_payload(finding) else {
        return 0;
    };
    let variants = MiniMutator::all_enabled().generate(&base, context, seed);
    if variants.is_empty() {
        return 0;
    }
    mutate_and_trace(
        client,
        state,
        cancel,
        target,
        target_str,
        param,
        finding,
        marker_set,
        raw,
        baseline,
        effective_tampers,
        opts,
        popts,
        matcher,
        &variants,
        seed,
    )
    .await
}

/// Boucle d'envoi des variantes mutées (extrait de [`run_mutation_for_finding`]).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn mutate_and_trace(
    client: &HttpClient,
    state: &Arc<RwLock<SessionState>>,
    cancel: &CancellationToken,
    target: &TargetUrl,
    target_str: &str,
    param: &TargetParameter,
    finding: &Finding,
    marker_set: &MarkerSet,
    raw: Option<&RawRequest>,
    baseline: &baseline::Baseline,
    effective_tampers: &[Tamper],
    opts: ProbeOpts,
    popts: &PayloadOpts,
    matcher: &crate::detection::matcher::MatcherConfig,
    variants: &[crate::mutation::MutatedVariant],
    seed: Option<u64>,
) -> usize {
    // Boolean-safe : les paires TRUE/FALSE exigent des transforms qui
    // préservent le différentiel (même filtre que la détection première).
    let boolean_safe: Vec<Tamper> = effective_tampers
        .iter()
        .filter(|t| t.is_boolean_safe())
        .cloned()
        .collect();
    let tampers_for_variant: &[Tamper] = match finding.technique {
        TechniqueKind::Boolean | TechniqueKind::Json | TechniqueKind::Nosql => &boolean_safe,
        _ => effective_tampers,
    };
    let class = match finding.technique {
        TechniqueKind::Boolean | TechniqueKind::Json | TechniqueKind::Nosql => {
            RequestClass::Boolean
        }
        TechniqueKind::Time => RequestClass::Time,
        _ => RequestClass::Default,
    };
    let baseline_body = matcher.pre_process(&baseline.representative_body_str());
    let mut rng = crate::seeded_rng::make_rng(seed);
    let mut sent = 0usize;
    // Échec silencieux : chaque variante est tracée, jamais touchée aux
    // findings ; le résultat ne crée ni ne supprime rien.
    for variant in variants.iter().take(
        crate::mutation::MAX_MUTATION_REQUESTS_PER_FINDING
            .min(crate::mutation::MAX_MUTATION_VARIANTS),
    ) {
        if cancel.is_cancelled() {
            break;
        }
        let final_payload =
            build_final_payload_with_rng(&variant.payload, tampers_for_variant, popts, &mut rng);
        let (raw_body, ms, status) = fetch_for_payload_with_class(
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
            class,
        )
        .await;
        if cancel.is_cancelled() || status == 0 {
            continue;
        }
        sent = sent.saturating_add(1);
        let body = matcher.pre_process(&raw_body);
        let diff = mutation_diff_signal(
            finding,
            baseline,
            &baseline_body,
            &body,
            ms,
            status,
            &final_payload,
        );
        push_confirm_trace(
            state,
            &param.key(),
            finding.technique,
            &variant.plan_label,
            seed,
            &final_payload,
            &body,
            diff,
            ms,
        )
        .await;
        debug!(
            param = %finding.parameter,
            technique = %finding.technique,
            plan = %variant.plan_label,
            diff,
            status,
            "mutation probe traced (silent, finding kept)"
        );
    }
    if sent > 0 {
        info!(
            param = %finding.parameter,
            technique = %finding.technique,
            sent,
            "mutation second-pass traced (finding kept regardless)"
        );
    }
    sent
}

/// Signal `diff` informatif pour une sonde mutée (traçabilité uniquement).
///
/// Borné `[0.0, 1.0]`, jamais utilisé pour créer/supprimer un finding :
/// la mutation est une preuve d'évasion citée, pas un verdict.
/// `sent_payload` est la chaîne exacte envoyée sur le fil (tampers inclus),
/// exigée par le veto anti-réflexion du détecteur UNION.
pub(crate) fn mutation_diff_signal(
    finding: &Finding,
    baseline: &baseline::Baseline,
    baseline_body: &str,
    body: &str,
    ms: f64,
    _status: u16,
    sent_payload: &str,
) -> f64 {
    match finding.technique {
        TechniqueKind::Boolean | TechniqueKind::Json | TechniqueKind::Nosql => {
            crate::detection::response_diff::adaptive_similarity(baseline_body, body)
                .clamp(0.0, 1.0)
        }
        TechniqueKind::Error => {
            let r = crate::techniques::error::detector::ErrorDetector::new().evaluate_with_context(
                baseline_body,
                body,
                body,
            );
            if r.is_vulnerable { 0.9 } else { 0.1 }
        }
        TechniqueKind::Time => {
            let detector = crate::techniques::time::detector::TimeDetector::from_baseline(baseline);
            if ms > detector.threshold() { 0.9 } else { 0.1 }
        }
        TechniqueKind::Union => {
            let detector = crate::techniques::union::detector::UnionDetector::new();
            let marker = union_marker_for_finding(finding);
            let r = detector.evaluate(
                baseline_body,
                body,
                baseline.mean_ms,
                ms,
                3,
                &marker,
                sent_payload,
            );
            if r.is_vulnerable { 0.85 } else { 0.1 }
        }
        TechniqueKind::Stacked => {
            if body.contains("injekt") || body != baseline_body {
                0.8
            } else {
                0.1
            }
        }
        TechniqueKind::Oob => 0.0,
    }
}

/// Marqueur UNION pour le signal muté : réutilise le premier core DBMS-aware
/// quand il existe, sinon le marqueur générique `injekt`.
pub(crate) fn union_marker_for_finding(finding: &Finding) -> String {
    let label = dbms_label_from_finding(finding);
    crate::techniques::union::payloads::union_payloads_for(label, 3)
        .first()
        .map_or_else(|| "injekt".to_owned(), |p| p.marker.clone())
}

/// Dispatch `--confirm` re-validation per technique (OOB excluded by the
/// caller). Each branch sends fresh payloads built with the derived seed RNG
/// and records hashes-only trace entries. Returns `true` when the differential
/// still holds (keep), `false` when it clearly disappeared (drop).
/// Inconclusive (transport error, `--ignore-code`, cancel) returns `true`
/// (keep): the first pass stays authoritative, the second pass only vetoes on
/// positive evidence of absence — never invents findings.
///
/// Robustness (C5-tardif fix): every branch retries a bounded set of fresh
/// payloads (mirroring the first-pass `payload_budget`, capped) instead of a
/// single `.first()`. The first-pass may have confirmed on the 2nd L1 payload
/// (e.g. `' OR 1=1` after a polyglot miss, or a numeric pair after
/// quote-ordering); re-validating only the head polyglot would drop a true
/// positive on conclusive-but-wrong-family evidence. Keep iff ANY candidate
/// re-confirms; drop only when ALL candidates conclusively fail.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(crate) async fn confirm_finding_second_pass(
    client: &HttpClient,
    state: &Arc<RwLock<SessionState>>,
    cancel: &CancellationToken,
    target: &TargetUrl,
    target_str: &str,
    param: &TargetParameter,
    finding: &Finding,
    marker_set: &MarkerSet,
    raw: Option<&RawRequest>,
    baseline: &baseline::Baseline,
    effective_tampers: &[Tamper],
    mutation_plan: &str,
    opts: ProbeOpts,
    popts: &PayloadOpts,
    matcher: &crate::detection::matcher::MatcherConfig,
    ignore_codes: &[u16],
    seed: Option<u64>,
    context: &InjectionContext,
    level: u8,
) -> bool {
    match finding.technique {
        TechniqueKind::Boolean | TechniqueKind::Json | TechniqueKind::Nosql => {
            confirm_boolean_second_pass(
                client,
                state,
                cancel,
                target,
                target_str,
                param,
                finding,
                marker_set,
                raw,
                baseline,
                effective_tampers,
                mutation_plan,
                opts,
                popts,
                matcher,
                ignore_codes,
                seed,
                context,
                level,
            )
            .await
        }
        TechniqueKind::Error => {
            confirm_error_second_pass(
                client,
                state,
                cancel,
                target,
                target_str,
                param,
                finding,
                marker_set,
                raw,
                baseline,
                effective_tampers,
                mutation_plan,
                opts,
                popts,
                matcher,
                ignore_codes,
                seed,
                context,
                level,
            )
            .await
        }
        TechniqueKind::Time => {
            confirm_time_second_pass(
                client,
                state,
                cancel,
                target,
                target_str,
                param,
                finding,
                marker_set,
                raw,
                baseline,
                effective_tampers,
                mutation_plan,
                opts,
                popts,
                matcher,
                ignore_codes,
                seed,
                level,
            )
            .await
        }
        TechniqueKind::Union => {
            confirm_union_second_pass(
                client,
                state,
                cancel,
                target,
                target_str,
                param,
                finding,
                marker_set,
                raw,
                baseline,
                effective_tampers,
                mutation_plan,
                opts,
                popts,
                matcher,
                ignore_codes,
                seed,
                level,
            )
            .await
        }
        TechniqueKind::Stacked => {
            confirm_stacked_second_pass(
                client,
                state,
                cancel,
                target,
                target_str,
                param,
                finding,
                marker_set,
                raw,
                baseline,
                effective_tampers,
                mutation_plan,
                opts,
                popts,
                matcher,
                ignore_codes,
                seed,
                level,
            )
            .await
        }
        TechniqueKind::Oob => true,
    }
}

/// Second-pass candidate: the historical boolean TRUE/FALSE base pair
/// (quote-aware) or the full JSON/NoSQL payload — error probe included — so a
/// finding confirmed through either channel re-probes the SAME channel with
/// first-pass parity.
enum SecondPassCand {
    Boolean {
        true_base: String,
        false_base: String,
    },
    Json(crate::techniques::json::payloads::JsonPayload),
    Nosql(crate::techniques::nosql::payloads::NosqlPayload),
}

/// Boolean/Json/NoSQL second-pass: fresh TRUE/FALSE pairs (derived seed),
/// same 3-trial `confirm_either` majority bar as the first pass (identical
/// payloads re-sent per trial for `--seed` determinism). Findings whose
/// evidence carries `channel=error` (JSON `__bad__` / `NoSQL` `$where`) are
/// re-probed on the error channel instead: one error payload per candidate,
/// mirroring `test_json_bounded` / `test_nosql_bounded` (1 request each).
///
/// Bounded retry: tries up to `payload_budget(level, 2, len)` candidates
/// (boolean capped at 3 pairs x 3 trials x 2 requests = 18 requests). JSON
/// candidates come from `json_scan_payloads` (direct sweep + GraphQL
/// `variables` envelope) and `NoSQL` from the full catalogue, exactly like the
/// first pass. Keep iff ANY candidate re-confirms; drop only when ALL
/// candidates conclusively fail. Cancel keeps immediately; a run that never
/// manages a measured probe (all transport-neutral) also keeps instead of
/// dropping on network flakes.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(crate) async fn confirm_boolean_second_pass(
    client: &HttpClient,
    state: &Arc<RwLock<SessionState>>,
    cancel: &CancellationToken,
    target: &TargetUrl,
    target_str: &str,
    param: &TargetParameter,
    finding: &Finding,
    marker_set: &MarkerSet,
    raw: Option<&RawRequest>,
    baseline: &baseline::Baseline,
    effective_tampers: &[Tamper],
    mutation_plan: &str,
    opts: ProbeOpts,
    popts: &PayloadOpts,
    matcher: &crate::detection::matcher::MatcherConfig,
    ignore_codes: &[u16],
    seed: Option<u64>,
    context: &InjectionContext,
    level: u8,
) -> bool {
    let mut rng = crate::seeded_rng::make_rng(seed);
    let label = dbms_label_from_finding(finding);
    // Candidates in first-pass order: boolean keeps its quote-aware pairs
    // (unchanged behaviour); JSON mirrors `test_json_bounded`
    // (`json_scan_payloads`: direct sweep + GraphQL `variables` envelope);
    // NoSQL mirrors `test_nosql_bounded` (full catalogue, same budget).
    let candidates: Vec<SecondPassCand> = if finding.technique == TechniqueKind::Json {
        let payloads = crate::engine::schedule::json_scan_payloads(label);
        let take = payload_budget(level, 2, payloads.len());
        payloads
            .into_iter()
            .take(take)
            .map(SecondPassCand::Json)
            .collect()
    } else if finding.technique == TechniqueKind::Nosql {
        let payloads = crate::techniques::nosql::payloads::nosql_payloads();
        let take = payload_budget(level, 2, payloads.len());
        payloads
            .into_iter()
            .take(take)
            .map(SecondPassCand::Nosql)
            .collect()
    } else {
        let mut payloads = crate::techniques::boolean::payloads::boolean_payloads_for(label);
        order_boolean_by_context(&mut payloads, context);
        let take = payload_budget(level, 2, payloads.len()).clamp(1, 3);
        payloads
            .iter()
            .take(take)
            .map(|p| SecondPassCand::Boolean {
                true_base: p.true_payload.clone(),
                false_base: p.false_payload.clone(),
            })
            .collect()
    };
    if candidates.is_empty() {
        return true;
    }
    // Boolean-safe only: opaque tampers would collapse the differential.
    let safe: Vec<Tamper> = effective_tampers
        .iter()
        .filter(|t| t.is_boolean_safe())
        .cloned()
        .collect();
    // NoSQL JSON-body operator path: same detection as `test_nosql_bounded`
    // (`param` body + JSON sniff) — the injected shape is an operator object,
    // not the generic string form, and string tampers don't apply there.
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
    let trans: &[Tamper] = if json_operator_path.is_some() {
        &[]
    } else {
        &safe
    };
    // Error-channel findings (JSON `__bad__` / NoSQL `$where`) carry their
    // differential in the error probe, not the boolean pair: re-probe the
    // error payload (1 request/candidate), mirroring the first pass.
    let error_channel = finding.evidence.contains("channel=error");
    // P1.1 — purge des zones dynamiques marquées avant comparaison.
    let baseline_body =
        matcher.pre_process(&baseline.strip_dynamic_content(&baseline.representative_body_str()));
    // Fail-open ledger: if NO candidate manages a single measured probe (every
    // probe transport-neutral), the finding could not actually be re-probed —
    // keep it instead of dropping on network flakes.
    let mut any_measured = false;
    for cand in &candidates {
        if cancel.is_cancelled() {
            return true;
        }
        if error_channel {
            match cand {
                SecondPassCand::Json(p) => {
                    let probe =
                        build_final_payload_with_rng(&p.error_payload, &safe, popts, &mut rng);
                    let (raw_body, ms, status) = fetch_for_payload(
                        client, state, cancel, target, target_str, param, &probe, marker_set, raw,
                        opts, popts,
                    )
                    .await;
                    // Transport/cancel: candidate not measured, never a veto.
                    if cancel.is_cancelled() || status == 0 {
                        continue;
                    }
                    if is_ignored(status, ignore_codes) {
                        continue;
                    }
                    let body = matcher.pre_process(&baseline.strip_dynamic_content(&raw_body));
                    let r = crate::techniques::json::detector::JsonDetector::new()
                        .evaluate_error(&body);
                    push_confirm_trace(
                        state,
                        &param.key(),
                        finding.technique,
                        mutation_plan,
                        seed,
                        &probe,
                        &body,
                        if r.is_vulnerable { r.confidence } else { 0.1 },
                        ms,
                    )
                    .await;
                    any_measured = true;
                    // Same bar as the first pass: signature still present and
                    // the matcher does not veto the error page.
                    if r.is_vulnerable && matcher.matches(&body, status) != Some(false) {
                        return true;
                    }
                }
                SecondPassCand::Nosql(p) => {
                    let (raw_body, ms, status) = crate::engine::probes::fetch_nosql_error(
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
                    if cancel.is_cancelled() || status == 0 {
                        continue;
                    }
                    if is_ignored(status, ignore_codes) {
                        continue;
                    }
                    let body = matcher.pre_process(&baseline.strip_dynamic_content(&raw_body));
                    let r = crate::techniques::nosql::detector::NosqlDetector::new()
                        .evaluate_error(&body);
                    push_confirm_trace(
                        state,
                        &param.key(),
                        finding.technique,
                        mutation_plan,
                        seed,
                        &p.error_payload,
                        &body,
                        if r.is_vulnerable { r.confidence } else { 0.1 },
                        ms,
                    )
                    .await;
                    any_measured = true;
                    if r.is_vulnerable && matcher.matches(&body, status) != Some(false) {
                        return true;
                    }
                }
                // Boolean findings never carry `channel=error`; nothing to do.
                SecondPassCand::Boolean { .. } => {}
            }
            continue;
        }
        // Build the payload pair once: the 3 trials must re-send the IDENTICAL
        // payloads (seed determinism — the RNG must not advance per trial).
        // NoSQL builds its string form inside `fetch_nosql_boolean` (operator
        // path sends the pre-parsed `Value` as-is), exactly like first pass.
        let (true_payload, false_payload) = match cand {
            SecondPassCand::Boolean {
                true_base,
                false_base,
            } => (
                build_final_payload_with_rng(true_base, &safe, popts, &mut rng),
                build_final_payload_with_rng(false_base, &safe, popts, &mut rng),
            ),
            SecondPassCand::Json(p) => (
                build_final_payload_with_rng(&p.true_payload, &safe, popts, &mut rng),
                build_final_payload_with_rng(&p.false_payload, &safe, popts, &mut rng),
            ),
            SecondPassCand::Nosql(p) => (p.true_payload.clone(), p.false_payload.clone()),
        };
        // 3-trial confirmation per pair (same bar as the first pass):
        // re-send the IDENTICAL payloads (seed determinism — the RNG must
        // not advance per trial) and require a `confirm_either` majority
        // instead of trusting one lucky trial.
        let mut trials: Vec<crate::detection::confirmation::Trial> = Vec::with_capacity(3);
        let mut last_true = String::new();
        let mut last_false = String::new();
        let mut last_true_status: u16 = 0;
        let mut last_false_status: u16 = 0;
        let mut last_true_ms = 0.0;
        let mut last_false_ms = 0.0;
        for _ in 0..3 {
            if cancel.is_cancelled() {
                return true;
            }
            // NoSQL operator/JSON-body parity: `fetch_nosql_boolean` selects
            // the operator-object or string shape exactly like first pass;
            // boolean/JSON use the generic boolean fetch.
            let (true_raw, true_ms, true_status, false_raw, false_ms, false_status) = match cand {
                SecondPassCand::Nosql(p) => {
                    let (true_raw, true_ms, true_status) =
                        crate::engine::probes::fetch_nosql_boolean(
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
                    let (false_raw, false_ms, false_status) =
                        crate::engine::probes::fetch_nosql_boolean(
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
                    (
                        true_raw,
                        true_ms,
                        true_status,
                        false_raw,
                        false_ms,
                        false_status,
                    )
                }
                SecondPassCand::Boolean { .. } | SecondPassCand::Json(_) => {
                    let (true_raw, true_ms, true_status) = fetch_for_payload_with_class(
                        client,
                        state,
                        cancel,
                        target,
                        target_str,
                        param,
                        &true_payload,
                        marker_set,
                        raw,
                        opts,
                        popts,
                        RequestClass::Boolean,
                    )
                    .await;
                    let (false_raw, false_ms, false_status) = fetch_for_payload_with_class(
                        client,
                        state,
                        cancel,
                        target,
                        target_str,
                        param,
                        &false_payload,
                        marker_set,
                        raw,
                        opts,
                        popts,
                        RequestClass::Boolean,
                    )
                    .await;
                    (
                        true_raw,
                        true_ms,
                        true_status,
                        false_raw,
                        false_ms,
                        false_status,
                    )
                }
            };
            if cancel.is_cancelled() {
                return true;
            }
            // Transport/body failure: neutral trial (never confirms), not a veto.
            if true_status == 0 || false_status == 0 {
                trials.push(crate::detection::confirmation::Trial {
                    true_conf: 0.5,
                    false_conf: 0.5,
                });
                continue;
            }
            // Ignored status: negative trial, never a finding.
            if is_ignored(true_status, ignore_codes) || is_ignored(false_status, ignore_codes) {
                trials.push(crate::detection::confirmation::Trial {
                    true_conf: 0.0,
                    false_conf: 1.0,
                });
                continue;
            }
            let true_body = matcher.pre_process(&baseline.strip_dynamic_content(&true_raw));
            let false_body = matcher.pre_process(&baseline.strip_dynamic_content(&false_raw));
            let res = if finding.technique == TechniqueKind::Json {
                crate::techniques::json::detector::JsonDetector::new()
                    .evaluate_boolean_with_match_ratio(
                        &baseline_body,
                        &true_body,
                        &false_body,
                        baseline.mean_ms,
                        true_ms,
                        false_ms,
                        baseline.match_ratio(),
                    )
            } else if finding.technique == TechniqueKind::Nosql {
                crate::techniques::nosql::detector::NosqlDetector::new()
                    .evaluate_boolean_with_match_ratio(
                        &baseline_body,
                        &true_body,
                        &false_body,
                        baseline.mean_ms,
                        true_ms,
                        false_ms,
                        baseline.match_ratio(),
                    )
            } else {
                // P1.2 — veto empirique sur la branche booléenne pure, comme
                // les wrappers JSON/NoSQL ci-dessus (même plancher appris).
                crate::techniques::boolean::detector::BooleanDetector::new()
                    .evaluate_with_match_ratio(
                        &baseline_body,
                        &true_body,
                        &false_body,
                        baseline.mean_ms,
                        true_ms,
                        false_ms,
                        baseline.match_ratio(),
                    )
            };
            // P1.2 : même traduction trial neutre qu'en première passe quand
            // le plancher de bruit a vetoé la paire (`noise_vetoed`, exposé
            // par les trois détecteurs).
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
            last_true_status = true_status;
            last_false_status = false_status;
            last_true_ms = true_ms;
            last_false_ms = false_ms;
            any_measured = true;
        }
        let (conf, inverted) = crate::detection::confirmation::confirm_either(&trials);
        push_confirm_trace(
            state,
            &param.key(),
            finding.technique,
            mutation_plan,
            seed,
            &true_payload,
            &last_true,
            conf.score,
            last_true_ms,
        )
        .await;
        push_confirm_trace(
            state,
            &param.key(),
            finding.technique,
            mutation_plan,
            seed,
            &false_payload,
            &last_false,
            conf.score,
            last_false_ms,
        )
        .await;
        if matcher.gate_boolean(&last_true, &last_false, last_true_status, last_false_status)
            == Some(false)
        {
            continue;
        }
        if conf.confirmed {
            // P0.2 — contrôle à arithmétique aléatoire : la même page doit
            // encore distinguer `r=r` (baseline-like) de `r1=r2` (différent),
            // dans le sens `inverted` de la paire re-confirmée. Contradiction
            // mesurée → candidat suivant ; transport/`None` → neutre (le
            // finding reste conservé, comme aujourd'hui). Budget borné :
            // +2 requêtes seulement ici.
            match crate::detection::control_pair::derive_control_pair(
                &true_payload,
                &false_payload,
                seed,
            ) {
                None => {}
                Some(ctrl) => {
                    let (ctl_true_raw, ctl_true_ms, ctl_true_status) =
                        fetch_for_payload_with_class(
                            client,
                            state,
                            cancel,
                            target,
                            target_str,
                            param,
                            &ctrl.must_true,
                            marker_set,
                            raw,
                            opts,
                            popts,
                            RequestClass::Boolean,
                        )
                        .await;
                    let (ctl_false_raw, ctl_false_ms, ctl_false_status) =
                        fetch_for_payload_with_class(
                            client,
                            state,
                            cancel,
                            target,
                            target_str,
                            param,
                            &ctrl.must_false,
                            marker_set,
                            raw,
                            opts,
                            popts,
                            RequestClass::Boolean,
                        )
                        .await;
                    if cancel.is_cancelled() {
                        return true;
                    }
                    let verdict = if ctl_true_status == 0 || ctl_false_status == 0 {
                        crate::detection::control_pair::ControlVerdict::Neutral
                    } else {
                        crate::detection::control_pair::control_verdict_with_match_ratio(
                            &baseline_body,
                            &matcher.pre_process(&baseline.strip_dynamic_content(&ctl_true_raw)),
                            &matcher.pre_process(&baseline.strip_dynamic_content(&ctl_false_raw)),
                            baseline.mean_ms,
                            ctl_true_ms,
                            ctl_false_ms,
                            inverted,
                            baseline.match_ratio(),
                        )
                    };
                    if verdict == crate::detection::control_pair::ControlVerdict::Veto {
                        continue;
                    }
                }
            }
            return true;
        }
    }
    if !any_measured {
        return true;
    }
    false
}

/// Error second-pass: re-send DBMS-aware error payloads (bounded retry);
/// the DB error pattern must still appear (baseline-vetoed). Fragment findings
/// (`extracted=yes`) keep the bar; `bool_confirm=true` findings additionally
/// require the boolean pair to still hold (via [`confirm_boolean_second_pass`]).
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(crate) async fn confirm_error_second_pass(
    client: &HttpClient,
    state: &Arc<RwLock<SessionState>>,
    cancel: &CancellationToken,
    target: &TargetUrl,
    target_str: &str,
    param: &TargetParameter,
    finding: &Finding,
    marker_set: &MarkerSet,
    raw: Option<&RawRequest>,
    baseline: &baseline::Baseline,
    effective_tampers: &[Tamper],
    mutation_plan: &str,
    opts: ProbeOpts,
    popts: &PayloadOpts,
    matcher: &crate::detection::matcher::MatcherConfig,
    ignore_codes: &[u16],
    seed: Option<u64>,
    context: &InjectionContext,
    level: u8,
) -> bool {
    let mut rng = crate::seeded_rng::make_rng(seed);
    let payloads =
        crate::techniques::error::payloads::error_payloads_for(dbms_label_from_finding(finding));
    let take = payload_budget(level, 2, payloads.len()).clamp(1, 2);
    if payloads.is_empty() {
        return true;
    }
    // P1.1 — purge des zones dynamiques marquées avant comparaison.
    let baseline_body =
        matcher.pre_process(&baseline.strip_dynamic_content(&baseline.representative_body_str()));
    for p in payloads.iter().take(take) {
        if cancel.is_cancelled() {
            return true;
        }
        // Single chain (not expanded): ~2x bound, coherent with detection tamper.
        let tampered = build_final_payload_with_rng(&p.payload, effective_tampers, popts, &mut rng);
        let (raw_body, ms, status) = fetch_for_payload(
            client, state, cancel, target, target_str, param, &tampered, marker_set, raw, opts,
            popts,
        )
        .await;
        if cancel.is_cancelled() || status == 0 || is_ignored(status, ignore_codes) {
            return true;
        }
        let body = matcher.pre_process(&baseline.strip_dynamic_content(&raw_body));
        let r = crate::techniques::error::detector::ErrorDetector::new().evaluate_with_context(
            &baseline_body,
            &body,
            &tampered,
        );
        push_confirm_trace(
            state,
            &param.key(),
            finding.technique,
            mutation_plan,
            seed,
            &tampered,
            &body,
            if r.is_vulnerable { 0.9 } else { 0.1 },
            ms,
        )
        .await;
        if matcher.matches(&body, status) == Some(false) {
            continue;
        }
        if !r.is_vulnerable {
            continue;
        }
        // `bool_confirm=true` findings must still hold the boolean differential.
        if finding.evidence.contains("bool_confirm=true") {
            let ok = confirm_boolean_second_pass(
                client,
                state,
                cancel,
                target,
                target_str,
                param,
                finding,
                marker_set,
                raw,
                baseline,
                effective_tampers,
                mutation_plan,
                opts,
                popts,
                matcher,
                ignore_codes,
                seed,
                context,
                level,
            )
            .await;
            if !ok {
                continue;
            }
        }
        return true;
    }
    false
}

/// Time second-pass: fresh sleep probes + benign control (bounded retry).
/// Keep iff ANY sleep candidate still shows the delay while the control stays
/// fast. Inconclusive (transport/`--ignore-code`/cancel/jitter-dominated
/// baseline) keeps immediately.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(crate) async fn confirm_time_second_pass(
    client: &HttpClient,
    state: &Arc<RwLock<SessionState>>,
    cancel: &CancellationToken,
    target: &TargetUrl,
    target_str: &str,
    param: &TargetParameter,
    finding: &Finding,
    marker_set: &MarkerSet,
    raw: Option<&RawRequest>,
    baseline: &baseline::Baseline,
    effective_tampers: &[Tamper],
    mutation_plan: &str,
    opts: ProbeOpts,
    popts: &PayloadOpts,
    matcher: &crate::detection::matcher::MatcherConfig,
    ignore_codes: &[u16],
    seed: Option<u64>,
    level: u8,
) -> bool {
    let mut rng = crate::seeded_rng::make_rng(seed);
    let label = dbms_label_from_finding(finding);
    // Parité de fenêtre avec `test_time_bounded` : blind sweep complet quand le
    // finding n'a pas d'attribution DBMS, sinon famille DBMS ; budget
    // `payload_budget(level, 4, ..)` identique à la première passe (l'ancien
    // `clamp(1, 2)` ne re-sondait que la tête de liste et perdait les variants
    // concat/heavy).
    let candidates = label.map_or_else(
        || crate::techniques::time::payloads::all_time_payloads(3),
        |label| crate::techniques::time::payloads::time_payloads_for(Some(label), 3),
    );
    let take = payload_budget(level, 4, candidates.len());
    if candidates.is_empty() {
        return true;
    }
    let detector = crate::techniques::time::detector::TimeDetector::from_baseline(baseline);
    for base in candidates.iter().take(take) {
        if cancel.is_cancelled() {
            return true;
        }
        #[allow(clippy::cast_precision_loss)]
        let sleep_ms = base.sleep_secs as f64 * 1000.0;
        if baseline.stddev_ms > sleep_ms * 0.5 {
            return true;
        }
        let payload_str =
            build_final_payload_with_rng(&base.payload, effective_tampers, popts, &mut rng);
        let (raw_body, ms, status) = fetch_for_payload_with_class(
            client,
            state,
            cancel,
            target,
            target_str,
            param,
            &payload_str,
            marker_set,
            raw,
            opts,
            popts,
            RequestClass::Time,
        )
        .await;
        if cancel.is_cancelled() || status == 0 || is_ignored(status, ignore_codes) {
            return true;
        }
        let body = matcher.pre_process(&raw_body);
        push_confirm_trace(
            state,
            &param.key(),
            finding.technique,
            mutation_plan,
            seed,
            &payload_str,
            &body,
            if ms > detector.threshold() { 0.9 } else { 0.1 },
            ms,
        )
        .await;
        if matcher.matches(&body, status) == Some(false) {
            continue;
        }
        #[allow(clippy::cast_precision_loss)]
        let first = detector.evaluate(ms, base.sleep_secs as f64);
        if !first.is_vulnerable {
            continue;
        }
        // Double-shot confirmation (same bar as the primary pass): a single
        // slow response may be jitter/throttle, not SQL. Re-send the sleep
        // payload with an anti-cache comment prefix (`/*8-hex*/`, SQL
        // whitespace on every targeted DBMS, same SQL semantics): identical
        // bytes could be replayed by a reverse-proxy cache — including its
        // timing — and a cache hit must not pass for a second round-trip.
        // Both shots must clear the bar via `evaluate_confirmed` before the
        // benign control runs.
        if cancel.is_cancelled() {
            return true;
        }
        let payload2 = crate::techniques::time::detector::cache_variant(&payload_str, &mut rng);
        let (raw_body2, ms2, status2) = fetch_for_payload_with_class(
            client,
            state,
            cancel,
            target,
            target_str,
            param,
            &payload2,
            marker_set,
            raw,
            opts,
            popts,
            RequestClass::Time,
        )
        .await;
        if cancel.is_cancelled() || status2 == 0 {
            return true;
        }
        if is_ignored(status2, ignore_codes) {
            continue;
        }
        let body2 = matcher.pre_process(&raw_body2);
        push_confirm_trace(
            state,
            &param.key(),
            finding.technique,
            mutation_plan,
            seed,
            &payload2,
            &body2,
            if ms2 > detector.threshold() { 0.9 } else { 0.1 },
            ms2,
        )
        .await;
        if matcher.matches(&body2, status2) == Some(false) {
            continue;
        }
        #[allow(clippy::cast_precision_loss)]
        let confirmed = detector.evaluate_confirmed(ms, ms2, base.sleep_secs as f64);
        if !confirmed.is_vulnerable {
            continue;
        }
        let control_payload = param.original_value.clone();
        let (_control_body, control_ms, control_status) = fetch_for_payload_with_class(
            client,
            state,
            cancel,
            target,
            target_str,
            param,
            &control_payload,
            marker_set,
            raw,
            opts,
            popts,
            RequestClass::Time,
        )
        .await;
        if control_status == 0 || cancel.is_cancelled() {
            return true;
        }
        if control_ms > detector.threshold() {
            return true;
        }
        return true;
    }
    false
}

/// Union second-pass: re-send fresh UNION cores for the finding's DBMS
/// (bounded retry across the finding's column width and its neighbour);
/// the marker differential must still hold for ANY candidate.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn confirm_union_second_pass(
    client: &HttpClient,
    state: &Arc<RwLock<SessionState>>,
    cancel: &CancellationToken,
    target: &TargetUrl,
    target_str: &str,
    param: &TargetParameter,
    finding: &Finding,
    marker_set: &MarkerSet,
    raw: Option<&RawRequest>,
    baseline: &baseline::Baseline,
    effective_tampers: &[Tamper],
    mutation_plan: &str,
    opts: ProbeOpts,
    popts: &PayloadOpts,
    matcher: &crate::detection::matcher::MatcherConfig,
    ignore_codes: &[u16],
    seed: Option<u64>,
    level: u8,
) -> bool {
    let mut rng = crate::seeded_rng::make_rng(seed);
    let label = dbms_label_from_finding(finding);
    // Column widths to retry: the finding's own width first (parsed from
    // evidence `columns=N`), then the historical default 3. Bounded to 2
    // widths × 1 payload each (mirrors the per-cols `payload_budget`).
    let mut widths: Vec<usize> = Vec::with_capacity(2);
    if let Some(w) = parse_union_columns(&finding.evidence) {
        widths.push(w);
    }
    if !widths.contains(&3) {
        widths.push(3);
    }
    let take_widths = payload_budget(level, 1, widths.len()).clamp(1, 2);
    let baseline_body = matcher.pre_process(&baseline.representative_body_str());
    let detector = crate::techniques::union::detector::UnionDetector::new();
    for cols in widths.into_iter().take(take_widths) {
        if cancel.is_cancelled() {
            return true;
        }
        let payloads = crate::techniques::union::payloads::union_payloads_for(label, cols);
        let Some(p) = payloads.first() else {
            continue;
        };
        let tampered = build_final_payload_with_rng(&p.payload, effective_tampers, popts, &mut rng);
        let (raw_body, ms, status) = fetch_for_payload(
            client, state, cancel, target, target_str, param, &tampered, marker_set, raw, opts,
            popts,
        )
        .await;
        if cancel.is_cancelled() || status == 0 || is_ignored(status, ignore_codes) {
            return true;
        }
        let body = matcher.pre_process(&raw_body);
        let r = detector.evaluate(
            &baseline_body,
            &body,
            baseline.mean_ms,
            ms,
            cols,
            &p.marker,
            &tampered,
        );
        push_confirm_trace(
            state,
            &param.key(),
            finding.technique,
            mutation_plan,
            seed,
            &tampered,
            &body,
            if r.is_vulnerable { 0.85 } else { 0.1 },
            ms,
        )
        .await;
        if matcher.matches(&body, status) == Some(false) {
            continue;
        }
        if r.is_vulnerable {
            return true;
        }
    }
    false
}

/// Stacked second-pass: re-send fresh stacked cores (bounded retry); the
/// marker must still execute for ANY candidate.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn confirm_stacked_second_pass(
    client: &HttpClient,
    state: &Arc<RwLock<SessionState>>,
    cancel: &CancellationToken,
    target: &TargetUrl,
    target_str: &str,
    param: &TargetParameter,
    finding: &Finding,
    marker_set: &MarkerSet,
    raw: Option<&RawRequest>,
    baseline: &baseline::Baseline,
    effective_tampers: &[Tamper],
    mutation_plan: &str,
    opts: ProbeOpts,
    popts: &PayloadOpts,
    matcher: &crate::detection::matcher::MatcherConfig,
    ignore_codes: &[u16],
    seed: Option<u64>,
    level: u8,
) -> bool {
    let mut rng = crate::seeded_rng::make_rng(seed);
    let payloads = crate::techniques::stacked::payloads::stacked_payloads_for(
        dbms_label_from_finding(finding),
    );
    let take = payload_budget(level, 2, payloads.len()).clamp(1, 2);
    if payloads.is_empty() {
        return true;
    }
    let baseline_body = matcher.pre_process(&baseline.representative_body_str());
    let detector = crate::techniques::stacked::detector::StackedDetector::new();
    for p in payloads.iter().take(take) {
        if cancel.is_cancelled() {
            return true;
        }
        let tampered = build_final_payload_with_rng(&p.payload, effective_tampers, popts, &mut rng);
        let (raw_body, ms, status) = fetch_for_payload(
            client, state, cancel, target, target_str, param, &tampered, marker_set, raw, opts,
            popts,
        )
        .await;
        if cancel.is_cancelled() || status == 0 || is_ignored(status, ignore_codes) {
            return true;
        }
        let body = matcher.pre_process(&raw_body);
        let r = detector.evaluate(&baseline_body, &body, baseline.mean_ms, ms, p, &tampered);
        push_confirm_trace(
            state,
            &param.key(),
            finding.technique,
            mutation_plan,
            seed,
            &tampered,
            &body,
            if r.is_vulnerable { 0.8 } else { 0.1 },
            ms,
        )
        .await;
        if matcher.matches(&body, status) == Some(false) {
            continue;
        }
        if r.is_vulnerable {
            return true;
        }
    }
    false
}
