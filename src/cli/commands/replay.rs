#![deny(unsafe_code)]

use anyhow::Context as _;

/// # Errors
/// Returns an error if neither `--file` nor `--import` is given, the file
/// exceeds 10 MiB, the file can't be read, the passphrase is missing/too
/// short, or decryption fails.
// Takes `Cli` by value to match the other command-runner entry points' calling convention.
#[allow(clippy::needless_pass_by_value)]
pub fn run(cli: crate::cli::args::Cli) -> anyhow::Result<()> {
    const MAX_REPLAY_BYTES: u64 = 10 * 1024 * 1024;
    let file = if let Some(crate::cli::args::Commands::Replay(a)) = &cli.command {
        a.file.clone()
    } else {
        cli.import
            .clone()
            .ok_or_else(|| anyhow::anyhow!("--file or --import required"))?
    };
    let meta =
        std::fs::metadata(&file).with_context(|| format!("cannot stat replay file '{file}'"))?;
    if meta.len() > MAX_REPLAY_BYTES {
        anyhow::bail!(
            "replay file '{file}' too large ({} bytes > {MAX_REPLAY_BYTES} bytes)",
            meta.len()
        );
    }
    let data = std::fs::read(&file).context("read replay file")?;
    // Encrypted session export (`--export-encrypted`, XChaCha20-Poly1305 +
    // Argon2id JSON blob): decrypt and print a scrubbed summary. This is an
    // inspection command, not a full scan resume — findings are shown so the
    // operator can re-target manually.
    if let Ok(passphrase) = passphrase_for_replay() {
        match crate::session::export::EncryptedExport::decrypt_from_file(&passphrase, &file) {
            Ok(plain) => {
                print_snapshot_summary(&plain, &cli)?;
                return Ok(());
            }
            Err(e) => {
                // Not an encrypted export (e.g. a recon `crawl.json`): fall
                // through to the raw-size report below with a hint.
                tracing::warn!(error=%e, "not an encrypted export or wrong passphrase");
            }
        }
    }
    println!("replay: {} bytes from {}", data.len(), file);
    println!("hint: set INJEKT_PASSPHRASE (min 12 chars) to decrypt an --export-encrypted session");
    Ok(())
}

/// Passphrase from `INJEKT_PASSPHRASE` (CI-safe) or interactive TTY prompt.
fn passphrase_for_replay() -> anyhow::Result<secrecy::SecretString> {
    if let Ok(env_pass) = std::env::var("INJEKT_PASSPHRASE") {
        if env_pass.len() < 12 {
            anyhow::bail!("INJEKT_PASSPHRASE too short (min 12)");
        }
        return Ok(secrecy::SecretString::from(env_pass));
    }
    // No env: try TTY prompt; non-TTY (CI/MCP) means "no passphrase", caller
    // falls back to the raw-size report.
    if !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        anyhow::bail!("no INJEKT_PASSPHRASE and no TTY");
    }
    let p = rpassword::prompt_password("Passphrase replay (min 12 chars): ").context("tty read")?;
    if p.len() < 12 {
        anyhow::bail!("passphrase too short (min 12)");
    }
    Ok(secrecy::SecretString::from(p))
}

/// Scrubbed human summary of a decrypted snapshot (no secrets printed).
fn print_snapshot_summary(plain: &[u8], cli: &crate::cli::args::Cli) -> anyhow::Result<()> {
    let v: serde_json::Value = serde_json::from_slice(plain).context("invalid snapshot JSON")?;
    let scrubber = crate::session::scrubber::Scrubber::new(cli.no_redact);
    let findings = v.get("findings").and_then(serde_json::Value::as_array);
    let extracted = v.get("extracted").and_then(serde_json::Value::as_array);
    let request_count = v
        .get("request_count")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let started_at = v
        .get("started_at")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("-");
    let n_findings = findings.map_or(0, Vec::len);
    let n_extracted = extracted.map_or(0, Vec::len);
    println!(
        "replay: decrypted session ({n_findings} findings, {n_extracted} extracted, {request_count} requests, started {started_at})"
    );
    if let Some(list) = findings {
        for f in list.iter().take(50) {
            let target = f
                .get("target")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("-");
            let param = f
                .get("parameter")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("-");
            let tech = f
                .get("technique")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("-");
            let conf = f
                .get("confidence")
                .and_then(serde_json::Value::as_f64)
                .unwrap_or(0.0);
            let evidence = f
                .get("evidence")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("");
            println!(
                "  - {} {} {} conf={conf:.2} evidence={}",
                scrubber.scrub(target),
                scrubber.scrub(param),
                tech,
                scrubber.scrub(evidence)
            );
        }
        if n_findings > 50 {
            println!("  … ({} more)", n_findings - 50);
        }
    }
    println!("note: replay inspects the export; re-run `scan --target <url>` to resume testing");
    Ok(())
}
