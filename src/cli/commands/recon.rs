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

pub async fn run(cli: Cli, cancel: CancellationToken) -> anyhow::Result<()> {
    let client = build_client(&cli)?;
    let command = match &cli.command {
        Some(Commands::Recon(args)) => &args.command,
        _ => anyhow::bail!("recon command required"),
    };
    match command {
        ReconCommands::Crawl(args) => {
            let report = crawl(&cli, client, args, &cancel).await?;
            emit_json(&report, cli.output.as_deref())?;
        }
        ReconCommands::Scan(args) => {
            let crawl_report = crawl(&cli, client.clone(), &args.crawl, &cancel).await?;
            let engine_config = engine_config(&cli, args.auto_enumerate);
            let discovery = scan_candidates(
                crawl_report.candidates.clone(),
                engine_config,
                client,
                cancel,
            )
            .await;
            let output = ReconScanReport {
                crawl: crawl_report,
                scan: discovery,
            };
            emit_json(&output, cli.output.as_deref())?;
        }
        ReconCommands::Import(args) => {
            let content = std::fs::read_to_string(&args.file)?;
            let candidates = parse_candidates(&content)?;
            if args.test {
                let discovery = scan_candidates(
                    candidates,
                    engine_config(&cli, args.enumerate),
                    client,
                    cancel,
                )
                .await;
                emit_json(&discovery, cli.output.as_deref())?;
            } else {
                emit_json(&candidates, cli.output.as_deref())?;
            }
        }
    }
    Ok(())
}

#[derive(serde::Serialize)]
struct ReconScanReport {
    crawl: CrawlReport,
    scan: DiscoveryReport,
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
    EngineConfig {
        threads: cli.threads,
        techniques: if cli.techniques.is_empty() {
            vec!["all".to_owned()]
        } else {
            cli.techniques.clone()
        },
        tampers,
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
