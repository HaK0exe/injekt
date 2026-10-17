#![deny(unsafe_code)]

pub use crate::target::injection::{
    APP_FILTER_STATUS, FILTER_STREAK_LIMIT, ProbeOpts, baseline_all_error,
    build_injection_spec_with_raw, filter_params, headers_preserving_raw,
    headers_preserving_raw_keep_ct, inject_body_param, inject_multipart_field, inject_param,
    inject_param_or_marker, inject_with_marker, is_app_filter_block, is_ignored, payload_budget,
    request_spec_from_raw, resolve_effective_tampers, synthetic_raw_from_data, waf_auto_tampers,
};
use crate::{
    http::client::HttpClient,
    session::{scrubber::Scrubber, state::SessionState},
    target::{
        markers::MarkerSet,
        parameters::{ParameterLocation, TargetParameter},
        raw_request::RawRequest,
        url::TargetUrl,
    },
};
use std::{collections::HashMap, sync::Arc, time::Instant};
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

/// `check_deadline` moved to `super::schedule` (P1).
/// Baseline collection moved to `super::baseline` (P1-fin).
pub(crate) use super::baseline::collect_baseline;

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

// `--dbms` hint normalization moved to `super::config` (P1);
// the orchestrator re-export was dropped after the P1-fin moves.

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

        let Some((baseline, effective_tampers, effective_opts)) = collect_baseline(
            &self.client,
            &self.state,
            &self.cancel,
            &self.config,
            &self.scrubber,
            self.baseline_cache.as_ref(),
            &target,
            raw_request.as_ref(),
        )
        .await?
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
        run_detection(
            &self.client,
            &self.state,
            &self.cancel,
            &self.config,
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
        run_confirm_second_pass(
            &self.client,
            &self.state,
            &self.cancel,
            &self.config,
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
            run_second_order(
                &self.client,
                &self.state,
                &self.cancel,
                &self.config,
                &self.scrubber,
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
        run_fingerprint(
            &self.client,
            &self.state,
            &self.cancel,
            &self.config,
            &self.scrubber,
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
                run_extraction(
                    &self.client,
                    &self.state,
                    &self.cancel,
                    &self.config,
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
            run_enumeration(
                &self.client,
                &self.state,
                &self.cancel,
                &self.config,
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
}

/// Second-order revisit phase moved to `super::second_order` (P1).
/// Re-exported here for intra-engine callers during migration.
pub(crate) use super::second_order::run_second_order;

/// Detection sweep moved to `super::detection` (P1-fin).
pub(crate) use super::detection::run_detection;

/// Fingerprint phase moved to `super::fingerprint` (P1-fin).
pub(crate) use super::fingerprint::run_fingerprint;

/// Extraction phase (`--extract` version inference) moved to `super::extraction` (P1).
/// Re-exported here for intra-engine callers during migration.
pub(crate) use super::extraction::run_extraction;

/// Confirmation second-pass + mini-mutation moved to `super::confirm` (P1).
/// Only the items used by the orchestrator body/tests are re-exported here;
/// the rest stay at `crate::engine::confirm::`.
pub(crate) use super::confirm::{ConfirmScope, is_extraction_eligible, run_confirm_second_pass};

/// Enumeration phase (sweep loop) moved to `super::enumerate` (P1).
/// Re-exported here for intra-engine callers during migration.
pub(crate) use super::enumerate::run_enumeration;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod orchestrator_gating_tests {
    use super::{ConfirmScope, is_extraction_eligible};
    use crate::engine::{
        confirm::{
            dbms_label_from_finding, has_confirmed_finding, in_confirm_scope, is_confirmed_finding,
            needs_auto_second_pass,
        },
        detection::{apply_outcome_to_hypothesis, infer_signal_and_trials},
        schedule::{
            dbms_payload_label, order_boolean_by_context, order_by_prefix_for_context,
            parse_finding_dbms,
        },
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
        use crate::detection::scanner::scheduler::{cost_for, cost_for_with_ttfb};
        use crate::engine::schedule::build_scheduler_for_param;
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
        let collected = crate::engine::baseline::collect_baseline_uncached(
            &engine.client,
            &engine.state,
            &engine.cancel,
            &engine.config,
            &engine.scrubber,
            &target,
            None,
        )
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
