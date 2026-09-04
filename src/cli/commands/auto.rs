#![deny(unsafe_code)]

//! `injekt auto`: one-command pipeline (`ingestion -> scan -> escalation -> enumeration`).
//!
//! * Single URL (or raw/bulk/stdin/OpenAPI/sitemap/raw-dir ingestion) → direct scan.
//! * Bare host or `--with-recon` → crawl, then test each discovered candidate.
//! * Escalation loop (unless `--no-escalate`): L1 as-configured → L2
//!   (`level ≥ 2` + `space2comment,randomcase`) → L3 (`level 3` + `text-only`
//!   fallback + `hpp`). Stops at the first step with findings, so clean
//!   targets pay a single pass and WAF-ish targets get two extra chances.

use crate::{
    cli::args::{AutoArgs, Cli},
    engine::orchestrator::{Engine, EngineConfig},
    reporting::{console, json::JsonReport},
    session::scrubber::Scrubber,
};
use tokio_util::sync::CancellationToken;

/// One escalation step: label + mutated engine config.
#[derive(Debug, Clone)]
pub struct EscalationStep {
    /// Short label shown in logs (`L1-baseline`, `L2-tamper`, `L3-evasion`).
    pub label: &'static str,
    /// Engine config for this pass.
    pub config: EngineConfig,
}

/// Pure escalation plan: L1 as-configured, L2 widened, L3 evasive.
/// Returns a single step when `escalate` is false.
#[must_use]
pub fn escalation_plan(base: &EngineConfig, escalate: bool) -> Vec<EscalationStep> {
    if !escalate {
        return vec![EscalationStep {
            label: "L1-baseline",
            config: base.clone(),
        }];
    }
    let mut steps = vec![EscalationStep {
        label: "L1-baseline",
        config: base.clone(),
    }];

    let mut l2 = base.clone();
    l2.level = base.level.max(2);
    if l2.tampers.is_empty() {
        l2.tampers = crate::techniques::tamper::parse_tamper_list(Some("space2comment,randomcase"));
    }
    l2.confirm = false;
    steps.push(EscalationStep {
        label: "L2-tamper",
        config: l2,
    });

    let mut l3 = base.clone();
    l3.level = base.level.max(3);
    if l3.tampers.len() < 3 {
        l3.tampers = crate::techniques::tamper::parse_tamper_list(Some(
            "space2comment,randomcase,charencode",
        ));
    }
    l3.matcher.text_only = true;
    l3.hpp = true;
    steps.push(EscalationStep {
        label: "L3-evasion",
        config: l3,
    });
    steps
}

/// CLI entry point for `injekt auto`.
///
/// # Errors
/// Returns an error when ingestion yields no target, the client fails to
/// build, or report output cannot be written.
pub async fn run(cli: &Cli, args: &AutoArgs, cancel: CancellationToken) -> anyhow::Result<()> {
    if let Err(e) = cli.validate_explicit_config() {
        anyhow::bail!("{e}");
    }
    let auto_target = args.target.clone().or_else(|| cli.effective_target());
    let targets = crate::target::ingest::collect_targets(cli, auto_target.as_deref())?;

    if cli.dry_run {
        dry_run(cli, args, &targets);
        return Ok(());
    }

    let wants_recon = args.with_recon
        || targets.iter().any(|t| is_bare_host(t))
        || (targets.len() == 1 && auto_target.as_deref().is_some_and(|t| !t.contains("://")));
    if wants_recon {
        run_auto_recon(cli, args, &targets, &cancel).await
    } else {
        run_auto_direct(cli, args, &targets, &cancel).await
    }
}

fn is_bare_host(target: &str) -> bool {
    !target.contains("://")
}

fn dry_run(cli: &Cli, args: &AutoArgs, targets: &[String]) {
    let scrubber = Scrubber::new(cli.no_redact);
    println!("dry-run: auto pipeline (no request sent)");
    println!("  resolution: {}", cli.resolution_summary());
    println!("  targets: {}", targets.len());
    for target in targets.iter().take(20) {
        println!("    - {}", scrubber.scrub(target));
    }
    if targets.len() > 20 {
        println!("    … ({} more)", targets.len() - 20);
    }
    let base = super::scan::engine_config(cli);
    let steps = escalation_plan(&base, !args.no_escalate);
    println!("  passes: {}", steps.len());
    for step in &steps {
        println!(
            "    - {}: level={} tampers={:?} text-only={} hpp={}",
            step.label,
            step.config.level,
            step.config
                .tampers
                .iter()
                .map(crate::techniques::tamper::Tamper::name)
                .collect::<Vec<_>>(),
            step.config.matcher.text_only,
            step.config.hpp,
        );
    }
    println!(
        "  recon: {}",
        if args.with_recon { "yes" } else { "host-only" }
    );
}

async fn run_auto_direct(
    cli: &Cli,
    args: &AutoArgs,
    targets: &[String],
    cancel: &CancellationToken,
) -> anyhow::Result<()> {
    let scrubber = Scrubber::new(cli.no_redact);
    let mut all_findings = Vec::new();
    let mut all_extracted = Vec::new();
    let mut total_requests: u64 = 0;
    let mut per_target: Vec<(String, usize, u64)> = Vec::new();

    for target in targets {
        if cancel.is_cancelled() {
            tracing::warn!("auto cancelled");
            break;
        }
        let (findings, extracted, requests) =
            scan_with_escalation(cli, args, target, cancel).await?;
        all_extracted.extend(extracted);
        tracing::info!(
            target = %scrubber.scrub(target),
            findings = findings.len(),
            requests,
            "auto target done"
        );
        per_target.push((target.clone(), findings.len(), requests));
        total_requests = total_requests.saturating_add(requests);
        all_findings.extend(findings);
    }

    println!(
        "▶ auto: {} target(s), {} finding(s), {total_requests} requests",
        targets.len(),
        all_findings.len()
    );
    for (target, count, requests) in &per_target {
        println!(
            "  - {}: {count} finding(s), {requests} req",
            scrubber.scrub(target)
        );
    }
    console::print_findings(&all_findings, &scrubber);
    console::print_extracted(&all_extracted);

    if let Some(out) = cli.output.as_deref() {
        let report = JsonReport::new(
            targets.first().cloned().unwrap_or_default(),
            all_findings,
            vec![],
            all_extracted,
            total_requests,
        );
        write_json(out, &report.to_json(&scrubber), &scrubber.scrub(out)).await?;
        tracing::info!(path = %scrubber.scrub(out), "auto json report written (0o600)");
    }
    Ok(())
}

async fn scan_with_escalation(
    cli: &Cli,
    args: &AutoArgs,
    target: &str,
    cancel: &CancellationToken,
) -> anyhow::Result<(Vec<crate::session::state::Finding>, Vec<String>, u64)> {
    let mut base = super::scan::engine_config(cli);
    if args.auto_enumerate {
        base.extract = true;
    }
    let steps = escalation_plan(&base, !args.no_escalate);
    let mut total_requests: u64 = 0;
    for step in &steps {
        if cancel.is_cancelled() {
            break;
        }
        tracing::info!(target = %target, step = step.label, level = step.config.level, "auto pass");
        let client = crate::cli::client_builder::build_client(cli, cli.allow_private)?;
        let engine = Engine::new(step.config.clone(), client, cancel.clone());
        match engine.run(target).await {
            Ok(_) => {
                let handle = engine.state_handle();
                let state = handle.read().await;
                let findings = state.findings().to_vec();
                let extracted = state.extracted_exposed();
                let requests = state.request_count();
                drop(state);
                total_requests = total_requests.saturating_add(requests);
                if !findings.is_empty() {
                    return Ok((findings, extracted, total_requests));
                }
                tracing::info!(step = step.label, "no finding, escalating");
            }
            Err(e) => {
                let requests = engine.state_handle().read().await.request_count();
                total_requests = total_requests.saturating_add(requests);
                tracing::warn!(step = step.label, error = %e, "auto pass failed, escalating");
            }
        }
    }
    Ok((Vec::new(), Vec::new(), total_requests))
}

#[allow(clippy::too_many_lines)]
async fn run_auto_recon(
    cli: &Cli,
    args: &AutoArgs,
    targets: &[String],
    cancel: &CancellationToken,
) -> anyhow::Result<()> {
    let scrubber = Scrubber::new(cli.no_redact);
    let seed = targets.first().cloned().unwrap_or_default();
    let crawl_args = crate::cli::args::ReconCrawlArgs {
        target: seed.clone(),
        depth: args.depth.min(16),
        max_pages: args.max_pages.min(100_000),
        max_per_template: 3,
        include_subdomains: false,
        ignore_robots: false,
    };
    tracing::info!(target = %seed, "auto recon crawl");
    let crawl = super::recon::run_crawl(cli, cancel.clone(), &crawl_args).await?;
    tracing::info!(
        candidates = crawl.report.candidates.len(),
        "auto crawl done"
    );

    if crawl.report.candidates.is_empty() {
        println!("auto: crawl found 0 candidates — falling back to direct scan");
        return run_auto_direct(cli, args, &targets[..1.min(targets.len())], cancel).await;
    }

    let mut base = super::scan::engine_config(cli);
    if args.auto_enumerate {
        base.extract = true;
    }
    let steps = escalation_plan(&base, !args.no_escalate);
    let client = crate::cli::client_builder::build_client(cli, cli.allow_private)?;
    let mut best: Option<crate::recon::discovery::DiscoveryReport> = None;
    for step in &steps {
        if cancel.is_cancelled() {
            break;
        }
        tracing::info!(step = step.label, "auto recon pass");
        let report = crate::recon::discovery::scan_candidates(
            crawl
                .report
                .candidates
                .clone()
                .into_iter()
                .map(scrub_candidate)
                .collect(),
            step.config.clone(),
            client.clone(),
            cancel.clone(),
        )
        .await;
        if !report.findings.is_empty() {
            best = Some(report);
            break;
        }
        best = Some(report);
    }
    let Some(report) = best else {
        anyhow::bail!("auto recon produced no report");
    };
    println!(
        "▶ auto recon: {} candidate(s), {} finding(s), {} requests",
        report.candidates_tested,
        report.findings.len(),
        report.request_count
    );
    console::print_findings(&report.findings, &scrubber);
    if let Some(out) = cli.output.as_deref() {
        let json = serde_json::to_string_pretty(&report)?;
        write_json(out, &json, &scrubber.scrub(out)).await?;
    }
    Ok(())
}

fn scrub_candidate(
    c: crate::recon::parameter::ParameterCandidate,
) -> crate::recon::parameter::ParameterCandidate {
    c
}

async fn write_json(path: &str, json: &str, scrubbed_path: &str) -> anyhow::Result<()> {
    crate::cli::output::file::write_output_file_async(path, json, false, scrubbed_path).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_config() -> EngineConfig {
        EngineConfig::default()
    }

    #[test]
    fn single_step_without_escalation() {
        let steps = escalation_plan(&base_config(), false);
        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].label, "L1-baseline");
    }

    #[test]
    fn three_steps_with_escalation() {
        let steps = escalation_plan(&base_config(), true);
        assert_eq!(steps.len(), 3);
        assert!(steps[1].config.level >= 2);
        assert!(steps[2].config.level >= 3);
        assert!(steps[2].config.matcher.text_only);
        assert!(!steps[0].config.matcher.text_only);
    }

    #[test]
    fn l2_keeps_explicit_tampers() {
        let mut base = base_config();
        base.tampers = crate::techniques::tamper::parse_tamper_list(Some("versionedcomment"));
        let steps = escalation_plan(&base, true);
        assert_eq!(steps[1].config.tampers, base.tampers);
    }

    #[test]
    fn bare_host_detection() {
        assert!(is_bare_host("example.com"));
        assert!(!is_bare_host("https://example.com/?id=1"));
    }
}
