#![deny(unsafe_code)]

use crate::{
    cli::args::Cli,
    engine::orchestrator::{Engine, EngineConfig},
    http::{client::HttpClient, jitter::Jitter, rate_limit::RateLimiter},
    reporting::{console, json::JsonReport},
    session::scrubber::Scrubber,
};
use std::{sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

pub async fn run(cli: Cli, cancel: CancellationToken) -> anyhow::Result<()> {
    let target = cli
        .effective_target()
        .ok_or_else(|| anyhow::anyhow!("--target required"))?;

    // Build HTTP client (type-state: timeout mandatory)
    let jitter = cli
        .jitter
        .as_deref()
        .map(|s| {
            let parts: Vec<f64> = s.split(',').filter_map(|x| x.parse().ok()).collect();
            match parts.as_slice() {
                [mean, std] => Jitter::new(*mean, *std),
                _ => Jitter::default(),
            }
        })
        .unwrap_or_default();

    let rl = cli
        .rate_limit
        .map(RateLimiter::new)
        .map_or_else(|| Arc::new(RateLimiter::new(10.0)), Arc::new);

    let mut builder = HttpClient::builder().timeout(Duration::from_secs(15));
    builder = builder.jitter(jitter).rate_limiter(rl);
    if let Some(proxy) = &cli.proxy {
        match crate::http::proxy::ProxyConfig::parse(proxy) {
            Ok(p) => builder = builder.proxy(p),
            Err(e) => warn!(error=%e, "invalid proxy, ignoring"),
        }
    }
    let client = builder
        .build()
        .map_err(|e| anyhow::anyhow!("client build: {e}"))?;

    let cfg = EngineConfig {
        threads: cli.threads,
        techniques: if cli.techniques.is_empty() {
            vec!["all".to_owned()]
        } else {
            cli.techniques.clone()
        },
        allow_private: cli.allow_private,
        no_redact: cli.no_redact,
        extract: cli.extract,
    };

    let engine = Engine::new(cfg.clone(), client, cancel.clone());
    let state = engine.run(&target).await?;

    info!(?state, "scan finished");

    // Reporting
    let handle = engine.state_handle();
    let s = handle.read().await;
    let findings = s.findings().to_vec();
    let count = s.request_count();
    drop(s);

    let scrubber = Scrubber::new(cfg.no_redact);
    console::print_findings(&findings);

    if let Some(out) = &cli.output {
        let report = JsonReport::new(target, findings, vec![], count);
        let json = report.to_json(&scrubber);
        std::fs::write(out, json)?;
        info!(path=%out, "json report written");
    }

    if let Some(path) = &cli.export_encrypted {
        warn!("--export-encrypted creates sensitive artefact at {path}");
        // In real usage, prompt for passphrase securely; here we use dummy
        let pass = secrecy::SecretString::from("changeme".to_owned());
        if let Err(e) = crate::session::export::EncryptedExport::encrypt_to_file(
            &*handle.read().await,
            &pass,
            path,
        ) {
            warn!(error=%e, "export failed");
        } else {
            info!("export encrypted written");
        }
    }

    Ok(())
}
