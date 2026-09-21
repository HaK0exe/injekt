#![deny(unsafe_code)]

use crate::{
    cli::args::{Cli, ReconArgs, ReconCommands},
    cli::client_builder::build_client,
    cli::engine_cfg::{EnumGate, build_engine_config},
    cli::knowledge::learn_and_save,
    http::client::HttpClient,
    recon::{
        CrawlConfig, CrawlReport, Crawler,
        discovery::{DiscoveryReport, scan_candidates},
        parameter::ParameterCandidate,
    },
};
use tokio_util::sync::CancellationToken;

/// Result of a recon crawl operation.
#[derive(Debug, Clone)]
pub struct ReconCrawlResult {
    pub report: CrawlReport,
}

/// Result of a recon scan operation (crawl + scan).
#[derive(Debug, Clone, serde::Serialize)]
pub struct ReconScanResult {
    pub crawl: CrawlReport,
    pub scan: DiscoveryReport,
}

impl ReconScanResult {
    /// Scrubbed clone for CLI / MCP output.
    #[must_use]
    pub fn scrubbed(&self, scrubber: &crate::session::scrubber::Scrubber) -> Self {
        Self {
            crawl: self.crawl.scrubbed(scrubber),
            scan: self.scan.scrubbed(scrubber),
        }
    }
}

/// Run a recon crawl and return structured results without printing to stdout.
/// Returned report is scrubbed (`cli.output_opts.no_redact` controls redaction).
///
/// # Errors
/// Returns an error if the HTTP client fails to build or the crawl itself fails.
pub async fn run_crawl(
    cli: &Cli,
    cancel: CancellationToken,
    args: &crate::cli::args::ReconCrawlArgs,
) -> anyhow::Result<ReconCrawlResult> {
    if let Err(e) = cli.validate_explicit_config() {
        anyhow::bail!("{e}");
    }
    tracing::info!(resolution=%cli.resolution_summary(), "recon config resolved");
    let client = build_client(cli, cli.http.allow_private)?;
    let report = crawl(cli, client, args, &cancel).await?;
    let scrubber = crate::session::scrubber::Scrubber::new(cli.output_opts.no_redact);
    Ok(ReconCrawlResult {
        report: report.scrubbed(&scrubber),
    })
}

/// Run a recon scan (crawl + scan candidates) and return structured results without printing.
/// Returned reports are scrubbed.
///
/// # Errors
/// Returns an error if the HTTP client fails to build or the crawl phase fails.
pub async fn run_scan(
    cli: &Cli,
    cancel: CancellationToken,
    args: &crate::cli::args::ReconScanArgs,
) -> anyhow::Result<ReconScanResult> {
    if let Err(e) = cli.validate_explicit_config() {
        anyhow::bail!("{e}");
    }
    tracing::info!(resolution=%cli.resolution_summary(), "recon config resolved");
    let client = build_client(cli, cli.http.allow_private)?;
    let crawl_report = crawl(cli, client.clone(), &args.crawl, &cancel).await?;
    let engine_config = build_engine_config(cli, EnumGate::Strict(args.auto_enumerate));
    let learn_techniques = engine_config.techniques.clone();
    let learn_dbms = engine_config.dbms_hint.clone();
    // `scan_candidates` clones candidates internally, so pass the raw list and
    // scrub afterwards to avoid double work on the crawl path.
    let discovery = scan_candidates(
        crawl_report.candidates.clone(),
        engine_config,
        client,
        cancel,
    )
    .await;
    // C13 post-run (opt-in uniquement) : même delta anonyme que `scan`
    // (`learn_from_run` + fusion + `fsync` + perms 0600). OFF = aucune IO.
    learn_and_save(
        &discovery.findings,
        &learn_techniques,
        learn_dbms.as_deref(),
        discovery.request_count,
        cli,
    );
    let scrubber = crate::session::scrubber::Scrubber::new(cli.output_opts.no_redact);
    Ok(ReconScanResult {
        crawl: crawl_report.scrubbed(&scrubber),
        scan: discovery.scrubbed(&scrubber),
    })
}

/// Parse import file without network access (offline path for `--test=false`).
///
/// # Errors
/// Returns an error if the file cannot be read, exceeds 10 MiB, or its
/// contents fail to parse.
pub fn run_import_offline(
    args: &crate::cli::args::ReconImportArgs,
    no_redact: bool,
) -> anyhow::Result<Vec<ParameterCandidate>> {
    let content = read_limited_import(&args.file)?;
    let candidates = parse_candidates(&content)?;
    let scrubber = crate::session::scrubber::Scrubber::new(no_redact);
    Ok(candidates
        .into_iter()
        .map(|c| c.scrubbed(&scrubber))
        .collect())
}

/// Run recon import with testing (`--test=true`) and return scrubbed results.
/// For offline listing without network traffic, use [`run_import_offline`].
///
/// # Errors
/// Returns an error if `args.test` is false, the file cannot be read/parsed,
/// or the HTTP client fails to build.
pub async fn run_import(
    cli: &Cli,
    cancel: CancellationToken,
    args: &crate::cli::args::ReconImportArgs,
) -> anyhow::Result<DiscoveryReport> {
    if !args.test {
        anyhow::bail!(
            "run_import performs active scanning; use run_import_offline when --test is false"
        );
    }
    if let Err(e) = cli.validate_explicit_config() {
        anyhow::bail!("{e}");
    }
    let client = build_client(cli, cli.http.allow_private)?;
    let content = read_limited_import(&args.file)?;
    let candidates = parse_candidates(&content)?;
    // Imported candidates may span arbitrary hosts: refuse to test them
    // with operator secrets unless reuse was explicitly allowed.
    let candidate_urls: Vec<String> = candidates
        .iter()
        .map(|c| c.url.as_str().to_owned())
        .collect();
    cli.check_secret_reuse(&candidate_urls)?;
    let cfg = build_engine_config(cli, EnumGate::Strict(args.enumerate));
    let learn_techniques = cfg.techniques.clone();
    let learn_dbms = cfg.dbms_hint.clone();
    let discovery = scan_candidates(candidates, cfg, client, cancel).await;
    // C13 post-run opt-in : delta anonyme fusionné (`fsync`, 0600). OFF = 0 IO.
    learn_and_save(
        &discovery.findings,
        &learn_techniques,
        learn_dbms.as_deref(),
        discovery.request_count,
        cli,
    );
    let scrubber = crate::session::scrubber::Scrubber::new(cli.output_opts.no_redact);
    Ok(discovery.scrubbed(&scrubber))
}

fn read_limited_import(path: &str) -> anyhow::Result<String> {
    const MAX_IMPORT_BYTES: u64 = 10 * 1024 * 1024;
    // Hard cap on the read itself (`take`), not a `metadata().len()`
    // pre-check (TOCTOU: the file can grow between `stat` and `read`).
    use std::io::Read as _;
    let file = std::fs::File::open(path)
        .map_err(|e| anyhow::anyhow!("cannot read import file '{path}': {e}"))?;
    let mut limited = file.take(MAX_IMPORT_BYTES.saturating_add(1));
    let mut buf = String::new();
    limited
        .read_to_string(&mut buf)
        .map_err(|e| anyhow::anyhow!("cannot read import file '{path}': {e}"))?;
    if u64::try_from(buf.len()).unwrap_or(u64::MAX) > MAX_IMPORT_BYTES {
        anyhow::bail!("import file '{path}' too large (> {MAX_IMPORT_BYTES} bytes)");
    }
    Ok(buf)
}

/// Original CLI entry point — prints to stdout/stderr.
///
/// `Scan` is a thin deprecated alias over `auto --with-recon` (no
/// escalation, enumeration gated by `--auto-enumerate`); `run_scan` stays
/// available for MCP/tests.
///
/// # Errors
/// Returns an error when the underlying crawl/scan/import operation fails.
pub async fn run(cli: &Cli, args: &ReconArgs, cancel: CancellationToken) -> anyhow::Result<()> {
    // Soft-deprecation: warn as soon as the subcommand is detected, including
    // `--dry-run` (which returns before the dispatch below).
    if matches!(args.command, ReconCommands::Scan(_)) {
        super::common::warn_recon_scan();
    }
    if cli.output_opts.dry_run {
        dry_run(cli, args);
        return Ok(());
    }
    match &args.command {
        ReconCommands::Crawl(crawl_args) => {
            let result = run_crawl(cli, cancel, crawl_args).await?;
            super::common::emit_json_async(
                &result.report,
                cli.output_opts.output.as_deref(),
                cli.output_opts.no_redact,
                cli.output_opts.force,
            )
            .await?;
        }
        ReconCommands::Scan(scan_args) => {
            // Thin alias: `recon scan` → `auto --with-recon` (single pass,
            // no escalation). Keeps `ReconCommands::Scan` + `run_scan`
            // for MCP/tests; CLI behaviour converges on `auto`.
            let auto_args = crate::cli::args::AutoArgs {
                target: Some(scan_args.crawl.target.clone()),
                with_recon: true,
                depth: scan_args.crawl.depth,
                max_pages: scan_args.crawl.max_pages,
                no_escalate: true,
                auto_enumerate: scan_args.auto_enumerate,
            };
            super::auto::run(cli, &auto_args, cancel).await?;
        }
        ReconCommands::Import(import_args) => {
            if import_args.test {
                let result = run_import(cli, cancel, import_args).await?;
                super::common::emit_json_async(
                    &result,
                    cli.output_opts.output.as_deref(),
                    cli.output_opts.no_redact,
                    cli.output_opts.force,
                )
                .await?;
            } else {
                // Offline: list candidates without sending any probes (OPSEC).
                let candidates = run_import_offline(import_args, cli.output_opts.no_redact)?;
                super::common::emit_json_async(
                    &candidates,
                    cli.output_opts.output.as_deref(),
                    cli.output_opts.no_redact,
                    cli.output_opts.force,
                )
                .await?;
            }
        }
    }
    Ok(())
}

/// Offline recon plan (C11): 0 requête, no `HttpClient` built.
/// - `crawl`: crawl envelope only (params unknown until crawl).
/// - `scan`: crawl envelope + scan plan for the seed URL's lexical params.
/// - `import`: offline candidate count when `--test=false`, else test envelope.
fn dry_run(cli: &Cli, args: &ReconArgs) {
    use crate::session::scrubber::Scrubber;
    let scrubber = Scrubber::new(cli.output_opts.no_redact);
    println!("dry-run: recon plan (no request sent)");
    println!("  resolution: {}", cli.resolution_summary());
    match &args.command {
        ReconCommands::Crawl(a) => {
            println!(
                "  mode: crawl target={} depth={} max-pages={} max-per-template={} max-candidates={}",
                scrubber.scrub(&a.target),
                a.depth,
                a.max_pages,
                a.max_per_template,
                a.max_candidates
            );
            println!("  params: unknown until crawl (crawl requires network; dry-run sends 0)");
            println!(
                "  seed={} threads={}",
                cli.effective_seed()
                    .map_or("none".to_owned(), |s| s.to_string()),
                cli.effective_threads(),
            );
        }
        ReconCommands::Scan(a) => {
            println!(
                "  mode: scan target={} depth={} max-pages={} max-candidates={} auto-enumerate={}",
                scrubber.scrub(&a.crawl.target),
                a.crawl.depth,
                a.crawl.max_pages,
                a.crawl.max_candidates,
                a.auto_enumerate
            );
            let cfg = build_engine_config(cli, EnumGate::Strict(a.auto_enumerate));
            if a.crawl.target.contains("://") {
                match crate::cli::plan::build_plan(&a.crawl.target, &cfg) {
                    Ok(plan) => print!(
                        "{}",
                        crate::cli::plan::render_human(
                            &plan.scrubbed(&scrubber),
                            &cli.resolution_summary(),
                            true
                        )
                    ),
                    Err(e) => println!("  seed-target plan failed: {e}"),
                }
            } else {
                println!(
                    "  seed target is a bare host ({}): params unknown until crawl, 0 req",
                    scrubber.scrub(&a.crawl.target)
                );
                println!(
                    "  scan techniques={} level={} seed={} budget_total={}",
                    if cfg.techniques.is_empty() {
                        "all".to_owned()
                    } else {
                        cfg.techniques.join(",")
                    },
                    cfg.budget.level,
                    cfg.seed.map_or("none".to_owned(), |s| s.to_string()),
                    cfg.budget
                        .request_budget
                        .map_or("unlimited".to_owned(), |b| b.to_string()),
                );
            }
        }
        ReconCommands::Import(a) => {
            println!(
                "  mode: import file={} test={} enumerate={}",
                scrubber.scrub(&a.file),
                a.test,
                a.enumerate
            );
            if a.test {
                let cfg = build_engine_config(cli, EnumGate::Strict(a.enumerate));
                println!(
                    "  test envelope (dry-run, 0 req): techniques={} level={} seed={}",
                    if cfg.techniques.is_empty() {
                        "all".to_owned()
                    } else {
                        cfg.techniques.join(",")
                    },
                    cfg.budget.level,
                    cfg.seed.map_or("none".to_owned(), |s| s.to_string()),
                );
            } else {
                match run_import_offline(a, cli.output_opts.no_redact) {
                    Ok(cands) => println!("  candidates (offline, 0 req): {}", cands.len()),
                    Err(e) => println!("  offline import failed: {e}"),
                }
            }
        }
    }
    println!("  0 requête envoyée (HttpClient.send jamais appelé)");
}

async fn crawl(
    cli: &Cli,
    client: HttpClient,
    args: &crate::cli::args::ReconCrawlArgs,
    cancel: &CancellationToken,
) -> anyhow::Result<CrawlReport> {
    if args.max_pages == 0 {
        anyhow::bail!("--max-pages must be greater than zero");
    }
    if args.max_candidates == 0 {
        anyhow::bail!("--max-candidates must be greater than zero");
    }
    tracing::warn!(
        target = %crate::session::scrubber::Scrubber::new(cli.output_opts.no_redact).scrub(&args.target),
        "recon crawl and scan must only be used against systems you are authorized to test"
    );
    let config = CrawlConfig {
        depth: args.depth.min(16),
        max_pages: args.max_pages.min(100_000),
        max_per_template: args.max_per_template.max(1),
        max_candidates: args.max_candidates.min(100_000),
        include_subdomains: args.include_subdomains,
        respect_robots: !args.ignore_robots,
        allow_private: cli.http.allow_private,
        remote_dns: cli.uses_remote_dns(),
    };
    Crawler::new(client, config)
        .crawl(&args.target, cancel)
        .await
}

fn parse_candidates(content: &str) -> anyhow::Result<Vec<ParameterCandidate>> {
    if let Ok(report) = serde_json::from_str::<CrawlReport>(content) {
        return Ok(report.candidates);
    }
    serde_json::from_str(content).map_err(Into::into)
}
