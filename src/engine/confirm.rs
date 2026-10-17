#![deny(unsafe_code)]

//! Confirmation second-pass + mini-mutation (P1).
//! Extracted verbatim from `orchestrator.rs`; no behaviour change.

mod boolean;
mod error;
mod mutation;
mod stacked;
mod time;
mod union;

use boolean::confirm_boolean_second_pass;
use error::confirm_error_second_pass;
use mutation::run_mutation_for_finding;
use stacked::confirm_stacked_second_pass;
use time::confirm_time_second_pass;
use union::confirm_union_second_pass;

use super::{
    ai_suggest::run_ai_suggest_for_param,
    config::{BudgetConfig, EngineConfig},
    fetch::fetch_for_payload_with_class,
    schedule::mutation_plan_label,
};
use crate::{
    dbms::context::{DbmsBelief, InjectionContext},
    detection::baseline,
    http::{client::HttpClient, timeouts::RequestClass},
    reporting::verdict::severity_for,
    session::state::{Finding, SessionState, Severity, TechniqueKind},
    target::{
        injection::{ProbeOpts, is_ignored},
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
use tracing::{debug, info, warn};

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

/// Scope of the confirm second-pass (anti-FP P2.4).
///
/// `--confirm` selects [`ConfirmScope::All`] (historical behaviour,
/// C5-tardif mini-mutation included); a default run uses
/// [`ConfirmScope::MediumRisk`], so confirmed findings below the `High`
/// bucket are re-validated for free (0 request when no candidate exists).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConfirmScope {
    /// Every confirmed non-OOB finding (`--confirm`).
    All,
    /// Confirmed non-OOB findings below the `High` bucket (default).
    MediumRisk,
}

/// `true` when a finding must be re-validated by the automatic second-pass
/// (no `--confirm`): confirmed, non-OOB, not calibrated `High`, on any
/// technique whose second-pass re-probes the same channel/variant window as
/// first-pass detection.
///
/// `High` findings (score + FP estimate both agree) already meet the ≥95 %
/// precision claim; re-probing them would only add traffic. `Medium`/`Low`
/// findings carry the residual FP risk, so they are re-validated — the pass
/// never creates findings and inconclusive outcomes keep them (fail-open).
///
/// Every non-OOB technique now has first-pass window parity: `Time` re-sweeps
/// the same payload family/budget (blind sweep included), `Json` replays the
/// GraphQL `variables` envelope, `Json`/`Nosql` re-probe the finding's
/// original channel (`channel=error` → error probe) and `Nosql` keeps the
/// JSON-body operator shape — so a failed re-confirmation is conclusive and
/// auto-dropping no longer risks losing true positives.
pub(crate) fn needs_auto_second_pass(f: &Finding) -> bool {
    f.technique != TechniqueKind::Oob
        && is_confirmed_finding(f)
        && severity_for(f.confidence, f.false_positive_prob) != Severity::High
}

/// `true` when `f` falls in the given second-pass [`ConfirmScope`]: `All`
/// keeps the historical filter (every confirmed non-OOB finding),
/// `MediumRisk` is the strict automatic subset ([`needs_auto_second_pass`]).
pub(crate) fn in_confirm_scope(f: &Finding, scope: ConfirmScope) -> bool {
    match scope {
        ConfirmScope::All => f.technique != TechniqueKind::Oob && is_confirmed_finding(f),
        ConfirmScope::MediumRisk => needs_auto_second_pass(f),
    }
}

/// C6 strict second-pass (real, not a `warn!`).
///
/// Re-sonde confirmed findings with fresh payloads + derived seed
/// (`derive_confirm_seed(base, idx)`), OOB excluded. [`ConfirmScope::All`]
/// (`--confirm`) covers every confirmed finding and documents the ~2x
/// request worst-case; [`ConfirmScope::MediumRisk`] (default) covers only
/// findings below the `High` bucket (bounded anti-FP, 0 request when the
/// snapshot holds none). Never creates new findings — only drops those
/// that fail re-validation, so N1/N2 stay at 0 FP by construction.
/// Inconclusive outcomes (transport error, `--ignore-code`, cancel) keep
/// the finding (fail-open toward the first pass, fail-closed toward new
/// FPs).
///
/// C5-tardif extension (`--confirm` only): after a finding is re-validated
/// (`ok == true`), the mini-mutation ([`crate::mutation`]) probes ≤4
/// deterministic variants (1 request each, `mutation:<famille>` traced,
/// silent failure). The mutation never runs in first-pass detection, never
/// on unconfirmed findings, never under WAF blocking, never when
/// `--no-mutation` is set, and never in the automatic medium-risk scope.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(crate) async fn run_confirm_second_pass(
    client: &HttpClient,
    state: &Arc<RwLock<SessionState>>,
    cancel: &CancellationToken,
    config: &EngineConfig,
    target: &TargetUrl,
    target_str: &str,
    marker_set: &MarkerSet,
    raw_request: &Arc<Option<RawRequest>>,
    baseline: &baseline::Baseline,
    effective_tampers: &[Tamper],
    effective_opts: ProbeOpts,
    context: &InjectionContext,
    dbms_belief: &DbmsBelief,
    detection_started: std::time::Instant,
    scope: ConfirmScope,
) {
    let snapshot = state.read().await.findings().to_vec();
    let candidates: Vec<(usize, Finding)> = snapshot
        .into_iter()
        .enumerate()
        .filter(|(_, f)| in_confirm_scope(f, scope))
        .collect();
    if candidates.is_empty() {
        match scope {
            ConfirmScope::All => {
                debug!("--confirm second-pass: no confirmed non-OOB findings, 0 extra requests");
            }
            ConfirmScope::MediumRisk => {
                debug!("auto second-pass (medium-risk, non-high): no candidates, 0 extra requests");
            }
        }
        return;
    }
    match scope {
        ConfirmScope::All => info!(
            count = candidates.len(),
            "--confirm second-pass start (OOB excluded)"
        ),
        ConfirmScope::MediumRisk => info!(
            count = candidates.len(),
            "auto second-pass (medium-risk, non-high) start (OOB excluded)"
        ),
    }
    let plan = mutation_plan_label(effective_tampers);
    for (idx, finding) in candidates {
        if cancel.is_cancelled() {
            break;
        }
        let derived = crate::reasoning::derive_confirm_seed(config.seed, idx);
        let param = param_from_finding(&finding);
        let ok = confirm_finding_second_pass(
            client,
            state,
            cancel,
            target,
            target_str,
            &param,
            &finding,
            marker_set,
            raw_request.as_ref().as_ref(),
            baseline,
            effective_tampers,
            &plan,
            effective_opts,
            &config.evasion.payload_opts,
            &config.matcher,
            &config.net.ignore_codes,
            derived,
            context,
            config.budget.level,
        )
        .await;
        if ok {
            info!(
                param = %finding.parameter,
                technique = %finding.technique,
                "--confirm re-validated"
            );
            // Link the finding to its confirm trace (opaque hash ref).
            let trace_ref = {
                let st = state.read().await;
                st.trace().records_for(&finding.parameter).last().map(|r| {
                    format!(
                        "confirm#{}:{}",
                        r.seq,
                        r.request_hash.chars().take(16).collect::<String>()
                    )
                })
            };
            if let Some(tref) = trace_ref {
                let mut st = state.write().await;
                if let Some(f) = st
                    .findings_mut()
                    .iter_mut()
                    .find(|x| x.parameter == finding.parameter && x.technique == finding.technique)
                {
                    let current = f.evidence.clone();
                    if !current.contains("confirm=second-pass") {
                        f.evidence = format!("{current} confirm=second-pass");
                    }
                    f.evidence_detail.trace_ref = Some(tref);
                }
            }
            // C5-tardif mini-mutation (`--confirm` only: the mutation is
            // tied to the explicit flag): confirmed-only, bounded, seeded,
            // traced, silent failure (never drops the finding).
            if scope == ConfirmScope::All {
                run_mutation_for_finding(
                    client,
                    state,
                    cancel,
                    target,
                    target_str,
                    &param,
                    &finding,
                    marker_set,
                    raw_request.as_ref().as_ref(),
                    baseline,
                    effective_tampers,
                    effective_opts,
                    &config.evasion.payload_opts,
                    &config.matcher,
                    context,
                    config.no_mutation,
                    derived,
                )
                .await;
            }
        } else {
            warn!(
                param = %finding.parameter,
                technique = %finding.technique,
                "--confirm re-validation failed, dropping finding (was likely FP)"
            );
            let mut st = state.write().await;
            st.findings_mut().retain(|x| {
                !(x.parameter == finding.parameter && x.technique == finding.technique)
            });
            drop(st);
            // `--ai-suggest` post-confirm (opt-in) : le finding droppé
            // rouvre une seconde chance bornée avec des formes inédites
            // (trigger `confirm_dropped`). Gate interne : 0 requête quand
            // OFF/déjà-tenté/sous verrou ; échec silencieux.
            if config.ai.enabled && !cancel.is_cancelled() {
                let ai_deadline = BudgetConfig::detection_deadline(
                    detection_started,
                    config.budget.max_duration_secs,
                );
                run_ai_suggest_for_param(
                    client,
                    state,
                    cancel,
                    config,
                    target,
                    target_str,
                    &param,
                    baseline,
                    marker_set,
                    raw_request.as_ref().as_ref(),
                    effective_tampers,
                    effective_opts,
                    &config.evasion.payload_opts,
                    &config.matcher,
                    &config.net.ignore_codes,
                    derived,
                    context,
                    dbms_belief,
                    ai_deadline,
                    true,
                )
                .await;
            }
        }
    }
    match scope {
        ConfirmScope::All => info!("--confirm second-pass done"),
        ConfirmScope::MediumRisk => info!("auto second-pass done"),
    }
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

/// Recovers the injection point of the first *confirmed* finding (param
/// name + location parsed back out of `finding.parameter`), falling back
/// to the first finding then to a synthetic `id` query param when there
/// is no finding yet. Shared by fingerprint/extraction/enumeration, which
/// all reuse the same confirmed injection point.
pub(crate) async fn first_finding_param(
    state: &Arc<RwLock<SessionState>>,
    target: &TargetUrl,
) -> (TargetParameter, TargetUrl) {
    let st = state.read().await;
    let findings = st.findings().to_vec();
    drop(st);
    // Prefer a confirmed finding so an `0.55 unconfirmed` error never
    // dictates the oracle injection point when a confirmed finding exists.
    let f = findings
        .iter()
        .find(|x| is_confirmed_finding(x))
        .or_else(|| findings.first());
    if let Some(finding) = f {
        // `param_from_finding` splits `name@location` at the LAST '@'
        // (parameter names may contain '@' while locations never do).
        (param_from_finding(finding), target.clone())
    } else {
        // fallback synthetic
        (
            TargetParameter::new("id", ParameterLocation::Query, "1"),
            target.clone(),
        )
    }
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
