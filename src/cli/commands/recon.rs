#![deny(unsafe_code)]

use crate::{
    cli::args::{Cli, Commands, ReconCommands},
    engine::orchestrator::EngineConfig,
    http::{client::HttpClient, jitter::Jitter, rate_limit::RateLimiter},
    recon::{
        CrawlConfig, CrawlReport, Crawler,
        discovery::{DiscoveryReport, scan_candidates},
        parameter::ParameterCandidate,
    },
};
use http::{HeaderName, HeaderValue};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt as _;
use std::{io::Write as _, sync::Arc, time::Duration};
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
    let client = build_client(cli)?;
    let crawl_report = crawl(cli, client.clone(), &args.crawl, &cancel).await?;
    let engine_config = engine_config(cli, args.auto_enumerate);
    // `scan_candidates` clones candidates internally, so pass the raw list and
    // scrub afterwards to avoid double work on the crawl path.
    let discovery = scan_candidates(
        crawl_report.candidates.clone(),
        engine_config,
        client,
        cancel,
    )
    .await;
    let scrubber = crate::session::scrubber::Scrubber::new(cli.no_redact);
    Ok(ReconScanResult {
        crawl: crawl_report.scrubbed(&scrubber),
        scan: discovery.scrubbed(&scrubber),
    })
}

/// Parse import file without network access (offline path for `--test=false`).
///
/// # Errors
/// Returns an error if the file cannot be read or its contents fail to parse.
pub fn run_import_offline(
    args: &crate::cli::args::ReconImportArgs,
    no_redact: bool,
) -> anyhow::Result<Vec<ParameterCandidate>> {
    let content = std::fs::read_to_string(&args.file)?;
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
    let client = build_client(cli)?;
    let content = std::fs::read_to_string(&args.file)?;
    let candidates = parse_candidates(&content)?;
    let discovery = scan_candidates(
        candidates,
        engine_config(cli, args.enumerate),
        client,
        cancel,
    )
    .await;
    let scrubber = crate::session::scrubber::Scrubber::new(cli.no_redact);
    Ok(discovery.scrubbed(&scrubber))
}

/// Original CLI entry point — prints to stdout/stderr.
///
/// # Errors
/// Returns an error if no recon subcommand is given or the underlying operation fails.
pub async fn run(cli: Cli, cancel: CancellationToken) -> anyhow::Result<()> {
    let command = match &cli.command {
        Some(Commands::Recon(args)) => &args.command,
        _ => anyhow::bail!("recon command required"),
    };
    match command {
        ReconCommands::Crawl(args) => {
            let result = run_crawl(&cli, cancel, args).await?;
            emit_json(&result.report, cli.output.as_deref())?;
        }
        ReconCommands::Scan(args) => {
            let result = run_scan(&cli, cancel, args).await?;
            emit_json(&result, cli.output.as_deref())?;
        }
        ReconCommands::Import(args) => {
            if args.test {
                let result = run_import(&cli, cancel, args).await?;
                emit_json(&result, cli.output.as_deref())?;
            } else {
                // Offline: list candidates without sending any probes (OPSEC).
                let candidates = run_import_offline(args, cli.no_redact)?;
                emit_json(&candidates, cli.output.as_deref())?;
            }
        }
    }
    Ok(())
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
    tracing::warn!(
        target = %args.target,
        "recon crawl and scan must only be used against systems you are authorized to test"
    );
    let config = CrawlConfig {
        depth: args.depth.min(16),
        max_pages: args.max_pages.min(100_000),
        max_per_template: args.max_per_template.max(1),
        include_subdomains: args.include_subdomains,
        respect_robots: !args.ignore_robots,
        allow_private: cli.allow_private,
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
        threads: cli.threads,
        techniques: if cli.techniques.is_empty() {
            match cli.fetch_using.as_deref() {
                Some("boolean") => vec!["boolean".to_owned()],
                Some("time") => vec!["time".to_owned()],
                _ => vec!["all".to_owned()],
            }
        } else {
            cli.techniques.clone()
        },
        test_params: cli.params.clone(),
        post_data: cli.data.clone(),
        payload_opts: cli.payload_opts(),
        matcher: cli.matcher_config(),
        tampers,
        level: cli.level.unwrap_or(1).clamp(1, 5),
        confirm: cli.confirm,
        ignore_codes: cli.ignore_codes.clone(),
        oob_domain: cli.oob_domain.clone(),
        oob_poll_url: cli.oob_poll_url.clone(),
        oob_wait_secs: cli.oob_wait_secs,
        hpp: cli.hpp,
        chunked: cli.chunked,
        allow_private: cli.allow_private,
        no_redact: cli.no_redact,
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
    }
}

fn build_client(cli: &Cli) -> anyhow::Result<HttpClient> {
    let jitter = cli
        .jitter
        .as_deref()
        .map(|value| {
            let parts: Vec<f64> = value
                .split(',')
                .filter_map(|part| part.parse().ok())
                .collect();
            match parts.as_slice() {
                [mean, standard_deviation] => Jitter::new(*mean, *standard_deviation),
                _ => Jitter::default(),
            }
        })
        .unwrap_or_default();
    let limiter = Arc::new(RateLimiter::new(cli.rate_limit.unwrap_or(10.0)));
    let mut builder = HttpClient::builder()
        .timeout(Duration::from_secs(15))
        .jitter(jitter)
        .rate_limiter(limiter);
    if let Some(proxy) = &cli.proxy {
        builder = builder.proxy(crate::http::proxy::ProxyConfig::parse(proxy)?);
    }
    for header in &cli.headers {
        let Some((name, value)) = header.split_once(':') else {
            anyhow::bail!("invalid --headers value, expected 'Name: value'");
        };
        builder = builder.header(
            HeaderName::from_bytes(name.trim().as_bytes())?,
            HeaderValue::from_str(value.trim())?,
        );
    }
    if let Some(cookies) = &cli.cookies {
        builder = builder.header(
            http::header::COOKIE,
            HeaderValue::from_str(cookies)
                .map_err(|error| anyhow::anyhow!("invalid --cookies header value: {error}"))?,
        );
    }
    builder
        .build()
        .map_err(|error| anyhow::anyhow!("client build: {error}"))
}

fn emit_json<T: serde::Serialize>(value: &T, path: Option<&str>) -> anyhow::Result<()> {
    let json = serde_json::to_string_pretty(value)?;
    if let Some(path) = path {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options.open(path)?;
        file.write_all(json.as_bytes())?;
        file.write_all(b"\n")?;
        file.sync_all()?;
    } else {
        println!("{json}");
    }
    Ok(())
}
