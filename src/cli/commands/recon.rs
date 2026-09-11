#![deny(unsafe_code)]

use crate::{
    cli::args::{Cli, Commands, ReconCommands},
    cli::client_builder::jitter_from_str,
    cli::output::file::write_output_file_sync,
    engine::orchestrator::EngineConfig,
    http::{client::HttpClient, rate_limit::RateLimiter},
    recon::{
        CrawlConfig, CrawlReport, Crawler,
        discovery::{DiscoveryReport, scan_candidates},
        parameter::ParameterCandidate,
    },
};
use http::{HeaderName, HeaderValue};
use std::{sync::Arc, time::Duration};
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
/// Returned report is scrubbed (`cli.no_redact` controls redaction).
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
    let client = build_client(cli)?;
    let report = crawl(cli, client, args, &cancel).await?;
    let scrubber = crate::session::scrubber::Scrubber::new(cli.no_redact);
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
    let client = build_client(cli)?;
    let crawl_report = crawl(cli, client.clone(), &args.crawl, &cancel).await?;
    let engine_config = engine_config(cli, args.auto_enumerate);
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
    if cli.knowledge_enabled() {
        let mut delta = crate::reasoning::knowledge::KnowledgeStore::empty();
        crate::reasoning::knowledge::learn_from_run(
            &mut delta,
            &discovery.findings,
            &learn_techniques,
            learn_dbms.as_deref(),
            discovery.request_count,
        );
        if let Err(e) = crate::reasoning::knowledge::save_delta_if_enabled(
            &delta,
            true,
            cli.knowledge_path.as_deref(),
        ) {
            tracing::warn!(error=%e, "knowledge save failed (run results kept in RAM)");
        }
    }
    let scrubber = crate::session::scrubber::Scrubber::new(cli.no_redact);
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
    let client = build_client(cli)?;
    let content = read_limited_import(&args.file)?;
    let candidates = parse_candidates(&content)?;
    let cfg = engine_config(cli, args.enumerate);
    let learn_techniques = cfg.techniques.clone();
    let learn_dbms = cfg.dbms_hint.clone();
    let discovery = scan_candidates(candidates, cfg, client, cancel).await;
    // C13 post-run opt-in : delta anonyme fusionné (`fsync`, 0600). OFF = 0 IO.
    if cli.knowledge_enabled() {
        let mut delta = crate::reasoning::knowledge::KnowledgeStore::empty();
        crate::reasoning::knowledge::learn_from_run(
            &mut delta,
            &discovery.findings,
            &learn_techniques,
            learn_dbms.as_deref(),
            discovery.request_count,
        );
        if let Err(e) = crate::reasoning::knowledge::save_delta_if_enabled(
            &delta,
            true,
            cli.knowledge_path.as_deref(),
        ) {
            tracing::warn!(error=%e, "knowledge save failed (run results kept in RAM)");
        }
    }
    let scrubber = crate::session::scrubber::Scrubber::new(cli.no_redact);
    Ok(discovery.scrubbed(&scrubber))
}

fn read_limited_import(path: &str) -> anyhow::Result<String> {
    const MAX_IMPORT_BYTES: u64 = 10 * 1024 * 1024;
    let meta = std::fs::metadata(path)
        .map_err(|e| anyhow::anyhow!("cannot stat import file '{path}': {e}"))?;
    if meta.len() > MAX_IMPORT_BYTES {
        anyhow::bail!(
            "import file '{path}' too large ({} bytes > {MAX_IMPORT_BYTES} bytes)",
            meta.len()
        );
    }
    std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("cannot read import file '{path}': {e}"))
}

/// Original CLI entry point — prints to stdout/stderr.
///
/// # Errors
/// Returns an error if no recon subcommand is given or the underlying operation fails.
pub async fn run(cli: Cli, cancel: CancellationToken) -> anyhow::Result<()> {
    if cli.dry_run {
        dry_run(&cli);
        return Ok(());
    }
    let command = match &cli.command {
        Some(Commands::Recon(args)) => &args.command,
        _ => anyhow::bail!("recon command required"),
    };
    match command {
        ReconCommands::Crawl(args) => {
            let result = run_crawl(&cli, cancel, args).await?;
            emit_json(
                &result.report,
                cli.output.as_deref(),
                cli.no_redact,
                cli.force,
            )?;
        }
        ReconCommands::Scan(args) => {
            let result = run_scan(&cli, cancel, args).await?;
            emit_json(&result, cli.output.as_deref(), cli.no_redact, cli.force)?;
        }
        ReconCommands::Import(args) => {
            if args.test {
                let result = run_import(&cli, cancel, args).await?;
                emit_json(&result, cli.output.as_deref(), cli.no_redact, cli.force)?;
            } else {
                // Offline: list candidates without sending any probes (OPSEC).
                let candidates = run_import_offline(args, cli.no_redact)?;
                emit_json(&candidates, cli.output.as_deref(), cli.no_redact, cli.force)?;
            }
        }
    }
    Ok(())
}

/// Offline recon plan (C11): 0 requête, no `HttpClient` built.
/// - `crawl`: crawl envelope only (params unknown until crawl).
/// - `scan`: crawl envelope + scan plan for the seed URL's lexical params.
/// - `import`: offline candidate count when `--test=false`, else test envelope.
fn dry_run(cli: &Cli) {
    use crate::session::scrubber::Scrubber;
    let scrubber = Scrubber::new(cli.no_redact);
    println!("dry-run: recon plan (no request sent)");
    println!("  resolution: {}", cli.resolution_summary());
    let Some(Commands::Recon(args)) = &cli.command else {
        println!("  mode: none (recon subcommand required)");
        println!("  0 requête envoyée (HttpClient.send jamais appelé)");
        return;
    };
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
            let cfg = engine_config(cli, a.auto_enumerate);
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
                let cfg = engine_config(cli, a.enumerate);
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
                match run_import_offline(a, cli.no_redact) {
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
        target = %args.target,
        "recon crawl and scan must only be used against systems you are authorized to test"
    );
    let config = CrawlConfig {
        depth: args.depth.min(16),
        max_pages: args.max_pages.min(100_000),
        max_per_template: args.max_per_template.max(1),
        max_candidates: args.max_candidates.min(100_000),
        include_subdomains: args.include_subdomains,
        respect_robots: !args.ignore_robots,
        allow_private: cli.allow_private,
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

fn engine_config(cli: &Cli, enumerate: bool) -> EngineConfig {
    let tampers = if cli.tamper.is_empty() {
        Vec::new()
    } else {
        crate::techniques::tamper::parse_tamper_list(Some(&cli.tamper.join(",")))
    };
    if !enumerate
        && (cli.dbs
            || cli.tables
            || cli.columns
            || cli.dump
            || cli.banner
            || cli.current_user
            || cli.current_db
            || cli.hostname
            || cli.count)
    {
        tracing::warn!(
            "identity/enumeration flags (--banner/--current-user/--current-db/--hostname/--dbs/--tables/--columns/--dump/--count) require --auto-enumerate for recon scan; ignoring them"
        );
    }
    EngineConfig {
        budget: crate::engine::orchestrator::BudgetConfig {
            threads: cli.effective_threads(),
            level: cli.effective_level(),
            request_budget: None,
        },
        evasion: crate::engine::orchestrator::EvasionConfig {
            payload_opts: cli.payload_opts(),
            tampers,
            hpp: cli.hpp,
            chunked: cli.chunked,
        },
        net: crate::engine::orchestrator::NetConfig {
            allow_private: cli.allow_private,
            remote_dns: cli.uses_remote_dns(),
            ignore_codes: cli.ignore_codes.clone(),
            method_override: cli.method.clone(),
        },
        oob: crate::engine::orchestrator::OobConfig {
            oob_domain: cli.oob_domain.clone(),
            oob_poll_url: cli.oob_poll_url.clone(),
            oob_wait_secs: cli.effective_oob_wait_secs(),
        },
        enumeration: crate::engine::orchestrator::EnumConfig {
            extract: cli.extract,
            dbs: enumerate && cli.dbs,
            tables: enumerate && cli.tables,
            columns: enumerate && cli.columns,
            dump: enumerate && cli.dump,
            banner: enumerate && cli.banner,
            current_user: enumerate && cli.current_user,
            current_db: enumerate && cli.current_db,
            hostname: enumerate && cli.hostname,
            db: cli.db.clone(),
            table: cli.table.clone(),
            column: cli.column.clone(),
            start: cli.start,
            stop: cli.stop,
            count: enumerate && cli.count,
        },
        techniques: if !cli.techniques.is_empty() {
            cli.techniques.clone()
        } else if cli
            .fetch_using
            .as_deref()
            .is_some_and(|v| v == "boolean" || v == "time")
        {
            match cli.fetch_using.as_deref() {
                Some("boolean") => vec!["boolean".to_owned()],
                Some("time") => vec!["time".to_owned()],
                _ => cli.effective_techniques(),
            }
        } else {
            cli.effective_techniques()
        },
        test_params: cli.params.clone(),
        post_data: cli.data.clone(),
        matcher: cli.matcher_config(),
        confirm: cli.confirm,
        no_mutation: cli.no_mutation,
        seed: cli.effective_seed(),
        explain: cli.explain.clone(),
        no_redact: cli.no_redact,
        dbms_hint: cli.normalized_dbms_hint(),
        marker: cli.marker.clone(),
        raw_request: cli.merged_raw_request(),
        // C13 : même porte opt-in que `scan` (OFF = None, aucune IO).
        knowledge: crate::reasoning::knowledge::load_if_enabled(
            cli.knowledge_enabled(),
            cli.knowledge_path.as_deref(),
        ),
        second_order: crate::engine::orchestrator::SecondOrderConfig {
            enabled: cli.second_order,
            revisit_url: cli.second_order_revisit_url.clone(),
            max_stores: cli.effective_second_order_max_stores(),
            ..crate::engine::orchestrator::SecondOrderConfig::default()
        },
    }
}

fn build_client(cli: &Cli) -> anyhow::Result<HttpClient> {
    let value = cli.effective_jitter();
    let jitter = {
        let parsed = jitter_from_str(&value);
        // Preserve the historical warning on unparseable input (the shared
        // helper already fell back to the floored default).
        if value
            .split(',')
            .filter_map(|p| p.trim().parse::<f64>().ok())
            .count()
            != 2
        {
            tracing::warn!(
                value = %value,
                "invalid jitter (expected \"mean_ms,std_ms\"), using default 750,250"
            );
        }
        parsed
    };
    let limiter = Arc::new(RateLimiter::new(cli.effective_rate_limit()));
    let retry = crate::http::retry::RetryPolicy {
        max_retries: cli.effective_retries(),
        base_delay: Duration::from_millis(cli.effective_delay()),
        max_delay: Duration::from_secs(5),
    };
    // Seeded UA + jitter/retry (same contract as `client_builder::build_client`).
    let seed = cli.effective_seed();
    let mut seed_rng = crate::seeded_rng::make_rng(seed);
    let mut builder = HttpClient::builder()
        .timeout(Duration::from_secs(cli.effective_timeout()))
        .identity(crate::http::identity::Identity::random_with_rng(
            &mut seed_rng,
        ))
        .jitter(jitter)
        .rate_limiter(limiter)
        .retry_policy(retry)
        .seed(seed)
        .allow_private(cli.allow_private);
    if let Some(proxy) = cli.effective_proxy() {
        builder = builder.proxy(crate::http::proxy::ProxyConfig::parse(&proxy)?);
    }
    for header in &cli.headers {
        let Some((name, value)) = header.split_once(':') else {
            anyhow::bail!("invalid --headers value, expected 'Name: value'");
        };
        builder = builder.user_header(
            HeaderName::from_bytes(name.trim().as_bytes())?,
            HeaderValue::from_str(value.trim())?,
        );
    }
    if let Some(cookies) = &cli.cookies {
        builder = builder.user_header(
            http::header::COOKIE,
            HeaderValue::from_str(cookies)
                .map_err(|error| anyhow::anyhow!("invalid --cookies header value: {error}"))?,
        );
    }
    builder
        .build()
        .map_err(|error| anyhow::anyhow!("client build: {error}"))
}

fn emit_json<T: serde::Serialize>(
    value: &T,
    path: Option<&str>,
    no_redact: bool,
    force: bool,
) -> anyhow::Result<()> {
    let json = serde_json::to_string_pretty(value)?;
    if let Some(path) = path {
        let scrubber = crate::session::scrubber::Scrubber::new(no_redact);
        let scrubbed_path = scrubber.scrub(path);
        write_output_file_sync(path, &json, force, &scrubbed_path)?;
    } else {
        println!("{json}");
    }
    Ok(())
}
