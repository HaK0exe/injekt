#![deny(unsafe_code)]

use crate::{
    cli::args::Cli,
    engine::orchestrator::{Engine, EngineConfig},
    http::{client::HttpClient, jitter::Jitter, rate_limit::RateLimiter},
    reporting::{console, json::JsonReport},
    session::scrubber::Scrubber,
};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::{io::Write as _, sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};
use zeroize::Zeroizing;

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
    {
        let scrubber = Scrubber::new(cfg.no_redact);
        info!(
            target=%scrubber.scrub(&target),
            state=?state,
            "scan finished"
        );
    }

    // Reporting
    let handle = engine.state_handle();
    let s = handle.read().await;
    let findings = s.findings().to_vec();
    let count = s.request_count();
    drop(s);

    let scrubber = Scrubber::new(cfg.no_redact);
    console::print_findings(&findings);

    if let Some(out) = &cli.output {
        let report = JsonReport::new(target.clone(), findings.clone(), vec![], count);
        let json = report.to_json(&scrubber);
        // Write with 0o600 perms on Unix (sensitive report)
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        opts.mode(0o600);
        let mut file = opts.open(out)?;
        file.write_all(json.as_bytes())?;
        file.sync_all()?;
        info!(path=%scrubber.scrub(out), "json report written (0o600)");
    }

    if let Some(path) = &cli.export_encrypted {
        let scrubbed_path = Scrubber::new(cfg.no_redact).scrub(path);
        warn!(path=%scrubbed_path, "export chiffré demandé — artefact sensible");
        // Secure passphrase prompt (rpassword) with fallback to env for CI
        let pass = if let Ok(env_pass) = std::env::var("INJEKT_PASSPHRASE") {
            if env_pass.len() < 12 {
                anyhow::bail!("INJEKT_PASSPHRASE trop courte (min 12)");
            }
            secrecy::SecretString::from(env_pass)
        } else {
            let p1 = Zeroizing::new(
                rpassword::prompt_password("Passphrase export (min 12 chars): ")
                    .map_err(|e| anyhow::anyhow!("tty read: {e}"))?,
            );
            if p1.len() < 12 {
                anyhow::bail!("passphrase trop courte (min 12)");
            }
            let p2 = Zeroizing::new(
                rpassword::prompt_password("Confirmer passphrase: ")
                    .map_err(|e| anyhow::anyhow!("tty read: {e}"))?,
            );
            if p1.as_str() != p2.as_str() {
                anyhow::bail!("passphrases mismatch");
            }
            secrecy::SecretString::from(p1.as_str().to_owned())
        };
        if let Err(e) = crate::session::export::EncryptedExport::encrypt_to_file(
            &*handle.read().await,
            &pass,
            path,
        ) {
            warn!(error=%e, "export failed");
        } else {
            info!(path=%scrubbed_path, "export chiffré écrit (0o600, v2 argon2id)");
        }
    }

    Ok(())
}
