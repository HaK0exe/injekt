//! OOB detection probe (`test_oob_bounded`).
//! Moved verbatim from `engine/probes.rs` (P1); no behaviour change.

use crate::engine::{fetch::fetch_for_payload_with_class, schedule::dbms_payload_label};
use crate::{
    http::timeouts::RequestClass,
    session::state::TechniqueKind,
    target::injection::{is_ignored, payload_budget},
    techniques::{
        oob::{
            detector::OobDetector,
            payloads::{is_valid_oob_domain, new_token, oob_payloads_for},
        },
        payload_opts::build_final_payload_with_rng,
        tamper::tamper_transformation_sets,
    },
};
use tracing::{debug, info, warn};

use crate::techniques::oob::verifier::OobVerifier as _;
use crate::techniques::technique::{Technique, TechniqueCtx};
use futures::future::BoxFuture;

/// OOB detection: send DNS/HTTP probes embedding a unique token, then poll the
/// collaborator for the callback.
///
/// OPT-IN: skipped silently when `oob_domain` is `None` (no infra). Invalid
/// domains are rejected with a warning. Without `oob_poll_url` probes are
/// still sent but never auto-confirmed — the operator checks the collaborator
/// UI manually for `<token>.<domain>` (no finding is emitted without
/// evidence, to avoid false positives).
///
/// Flow per parameter: one fresh token per payload index (up to 3
/// DBMS-generic probes, each with tamper variants), cancellable
/// send→wait→poll per variant with early-break on the first token-verified
/// callback (`HttpPollVerifier`). A finding (`TechniqueKind::Oob`,
/// confidence 0.95) is pushed only on callback.
pub(crate) struct OobTechnique;

impl Technique for OobTechnique {
    fn kind(&self) -> TechniqueKind {
        TechniqueKind::Oob
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
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
            let oob_domain = ctx.oob_domain.cloned();
            let oob_poll_url = ctx.oob_poll_url.cloned();
            let oob_wait_secs = ctx.oob_wait_secs;
            let seed = ctx.seed;
            let context = ctx.context;
            let dbms_belief = ctx.dbms_belief;
            let (top_dbms, top_prob) = dbms_belief.top_candidate();
            debug!(param = param.key(), context = context.summary(), %top_dbms, top_prob, "oob: context-aware detection");
            // Seeded tamper RNG (`--seed`): same seed yields identical payloads;
            // `None` preserves the historical OS-random behaviour.
            let mut rng = crate::seeded_rng::make_rng(seed);
            let Some(domain) = oob_domain else {
                return;
            };
            if !is_valid_oob_domain(&domain) {
                warn!(domain=%domain, "invalid --oob-domain, skipping OOB probes");
                return;
            }
            let detector = OobDetector::new(domain.clone());
            let baseline_body = matcher.pre_process(&baseline.representative_body_str());
            // DBMS-aware OOB cores once the belief is actionable (>= 0.85, same bar
            // as `fill_missing_dbms`); otherwise the generic 3-probe sweep.
            // OOB-2: one fresh token per payload index. The token is embedded
            // verbatim in `payload`/`fqdn` at build time (`build_subdomain`), so the
            // whole vector is regenerated per index and the element at that index is
            // taken (O(N²), N<=4) — never a clone+rewrite.
            let dbms_label = dbms_payload_label(dbms_belief);
            let total_payloads = oob_payloads_for(dbms_label, &domain, "oobcount").len();
            let budget = payload_budget(level, 3, total_payloads);
            let tamper_sets = tamper_transformation_sets(tampers);
            let has_poll_url = oob_poll_url
                .as_deref()
                .is_some_and(|u| !u.trim().is_empty());

            // OOB-2 — per-payload loop: send tamper-variants of the regenerated
            // payload, wait for the async DB-side execution, then poll for THIS
            // token (up to 3 polls spaced 2s). A token-verified callback freezes the
            // proof on the triggering payload/token and breaks globally (early-break).
            // Keep the last response for evidence; OOB is async so the body is
            // expected to match baseline.
            let mut last_body = baseline_body.clone();
            let mut last_ms = baseline.mean_ms;
            let mut last_status: u16 = 0;
            let mut probes_sent = 0usize;

            if !has_poll_url {
                // Manual mode (no confirmation infra): one variant per payload is
                // enough; the operator checks the collaborator UI manually. Never a
                // finding without evidence.
                let mut manual_payload: Option<crate::techniques::oob::payloads::OobPayload> = None;
                for payload_idx in 0..budget {
                    if cancel.is_cancelled() {
                        return;
                    }
                    let token_for_variant = new_token();
                    let Some(payload_for_variant) =
                        oob_payloads_for(dbms_label, &domain, &token_for_variant)
                            .into_iter()
                            .nth(payload_idx)
                    else {
                        continue;
                    };
                    if manual_payload.is_none() {
                        manual_payload = Some(payload_for_variant.clone());
                    }
                    // Without confirmation infra one variant per payload is enough;
                    // the operator checks the collaborator UI manually.
                    if let Some(first_set) = tamper_sets.first() {
                        if cancel.is_cancelled() {
                            return;
                        }
                        let tampered = build_final_payload_with_rng(
                            &payload_for_variant.payload,
                            first_set,
                            popts,
                            &mut rng,
                        );
                        let (raw_body, ms, status) = fetch_for_payload_with_class(
                            client,
                            state,
                            cancel,
                            target,
                            target_str,
                            param,
                            &tampered,
                            marker_set,
                            raw,
                            opts,
                            popts,
                            RequestClass::Oob,
                        )
                        .await;
                        probes_sent += 1;
                        // `--ignore-code`: an ignored probe response is discarded
                        // (kept baseline-neutral). No finding follows in manual mode.
                        if !is_ignored(status, ignore_codes) {
                            last_body = matcher.pre_process(&raw_body);
                            last_ms = ms;
                            manual_payload = Some(payload_for_variant.clone());
                        }
                    }
                }
                if probes_sent == 0 {
                    return;
                }
                let Some(manual_probe) = manual_payload else {
                    return;
                };
                let eval_outcome = detector.evaluate_without_callback(
                    &baseline_body,
                    &last_body,
                    baseline.mean_ms,
                    last_ms,
                    &manual_probe,
                );
                if eval_outcome.confidence >= 0.35 {
                    info!(
                        token=%manual_probe.token,
                        fqdn=%manual_probe.fqdn,
                        channel=%manual_probe.channel.to_string(),
                        "oob probe sent (no --oob-poll-url) — check collaborator for callback, no auto-finding"
                    );
                }
                return;
            }

            let poll_verifier = crate::techniques::oob::verifier::HttpPollVerifier::new(
                oob_poll_url.clone().unwrap_or_default(),
                8,
            );
            let full_wait = core::time::Duration::from_secs(oob_wait_secs.clamp(0, 30));
            let mut trigger_payload: Option<crate::techniques::oob::payloads::OobPayload> = None;
            for payload_idx in 0..budget {
                if cancel.is_cancelled() {
                    return;
                }
                let token_for_variant = new_token();
                let Some(payload_for_variant) =
                    oob_payloads_for(dbms_label, &domain, &token_for_variant)
                        .into_iter()
                        .nth(payload_idx)
                else {
                    continue;
                };
                for trans_set in &tamper_sets {
                    if cancel.is_cancelled() {
                        return;
                    }
                    let tampered = build_final_payload_with_rng(
                        &payload_for_variant.payload,
                        trans_set,
                        popts,
                        &mut rng,
                    );
                    let (raw_body, ms, status) = fetch_for_payload_with_class(
                        client,
                        state,
                        cancel,
                        target,
                        target_str,
                        param,
                        &tampered,
                        marker_set,
                        raw,
                        opts,
                        popts,
                        RequestClass::Oob,
                    )
                    .await;
                    probes_sent += 1;
                    // `--ignore-code`: an ignored probe response is discarded
                    // (kept baseline-neutral); a token-verified callback below still
                    // overrides the veto (OOB-3).
                    if is_ignored(status, ignore_codes) {
                        last_status = status;
                        continue;
                    }
                    last_body = matcher.pre_process(&raw_body);
                    last_ms = ms;
                    last_status = status;
                }
                if probes_sent == 0 {
                    continue;
                }
                // Async DB execution + collaborator propagation lag. Full wait for
                // the first payload, then `min(wait, 2s)`: DB-side executions
                // overlap while we poll, so later variants need only a short settle.
                let wait_for_variant = if payload_idx == 0 {
                    full_wait
                } else {
                    core::cmp::min(full_wait, core::time::Duration::from_secs(2))
                };
                if !wait_for_variant.is_zero() {
                    tokio::select! {
                        () = cancel.cancelled() => return,
                        () = tokio::time::sleep(wait_for_variant) => {},
                    }
                }
                let mut callback_seen = false;
                for attempt_idx in 0..3 {
                    if cancel.is_cancelled() {
                        return;
                    }
                    if poll_verifier.verify(&token_for_variant).await {
                        callback_seen = true;
                        break;
                    }
                    if attempt_idx + 1 < 3 {
                        tokio::select! {
                            () = cancel.cancelled() => return,
                            () = tokio::time::sleep(core::time::Duration::from_secs(2)) => {},
                        }
                    }
                }
                if callback_seen {
                    // Freeze the proof on the triggering payload/token.
                    trigger_payload = Some(payload_for_variant);
                    break;
                }
            }
            if probes_sent == 0 {
                return;
            }
            // No token-verified callback across all variants: inconclusive, never a
            // finding (`evaluate_with_callback` only confirms on callback).
            let Some(trigger_probe) = trigger_payload else {
                return;
            };
            let eval_outcome = detector.evaluate_with_callback(
                &baseline_body,
                &last_body,
                baseline.mean_ms,
                last_ms,
                &trigger_probe,
                true,
            );
            if eval_outcome.is_vulnerable {
                // Token-verified collaborator proof outranks response
                // heuristics: OOB executes async and returns a baseline-like
                // page, so a `--ignore-code` hit or `--string`/`--code`
                // mismatch on the last variant must not veto a confirmed
                // callback (vetoing here was a systematic false negative:
                // `evaluate_with_callback` only confirms on callback).
                debug!(param=%param.key(), status=last_status, "oob callback proof overrides response vetos");
                let mut finding = crate::session::state::Finding::new(
                    target.as_str(),
                    param.key(),
                    crate::session::state::TechniqueKind::Oob,
                    eval_outcome.confidence,
                    format!(
                        "oob channel={} dbms={} token={} fqdn={} probes={}{}{}{}",
                        eval_outcome.channel,
                        eval_outcome.dbms.as_deref().unwrap_or("?"),
                        eval_outcome.token,
                        trigger_probe.fqdn,
                        probes_sent,
                        opts.evidence_suffix(),
                        popts.evidence_suffix(),
                        matcher.evidence_suffix(),
                    ),
                )
                // C7: collaborator callback = strongest confirmation available.
                .with_false_positive_prob(0.01)
                .with_waf(baseline.waf_vendor.clone(), baseline.is_waf_blocking());
                finding.dbms = eval_outcome.dbms.clone();
                state.write().await.push_finding(finding);
            }
        })
    }
}
