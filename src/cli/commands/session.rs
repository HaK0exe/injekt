#![deny(unsafe_code)]

//! C17 migration 4 — `injekt session` namespace: encrypted-export
//! re-keying (`session export <PATH> --import <FILE>`) and inspection
//! (`session replay <FILE>`). Both are OFFLINE commands (0 socket, pure
//! OPSEC): local files + passphrase only, no target, no engine. The
//! crypto never changes shape: `session::export` is reused as-is (argon2id
//! v2 blob, 0o600 `create_new`).

use anyhow::Context as _;
use secrecy::SecretString;

/// Passphrase from `INJEKT_PASSPHRASE` (CI-safe) or interactive TTY prompt.
///
/// Centralized helper (C17) for both `session replay` (source read) and
/// `session export` (source + destination prompts): a non-TTY process (CI,
/// MCP, script) without the env means "no passphrase" — the caller decides
/// between a graceful fallback (replay raw-size report) or an error
/// (export cannot proceed the key material).
pub(crate) fn passphrase_for_session(role: &str) -> anyhow::Result<SecretString> {
    if let Ok(env_pass) = std::env::var("INJEKT_PASSPHRASE") {
        if env_pass.len() < 12 {
            anyhow::bail!("INJEKT_PASSPHRASE too short (min 12)");
        }
        return Ok(SecretString::from(env_pass));
    }
    // No env: TTY only; non-TTY (CI/MCP) means "no passphrase available".
    if !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        anyhow::bail!("no INJEKT_PASSPHRASE and no TTY");
    }
    let p = rpassword::prompt_password(format!("Passphrase {role} (min 12 chars): "))
        .context("tty read")?;
    if p.len() < 12 {
        anyhow::bail!("passphrase too short (min 12)");
    }
    Ok(SecretString::from(p))
}

/// # Errors
/// Returns an error when the global `--import <FILE>` is missing (the
/// standalone post-run export stays driven by the `--export-encrypted`
/// flag inside a scan run), the source file fails to decrypt, the
/// destination exists without global `--force`, or the self-verification
/// (decrypt pass after write) fails — the partial output is removed
/// best-effort in that case.
pub fn run_export(
    args: &crate::cli::args::SessionExportArgs,
    opts: &crate::cli::args::OutputOpts,
) -> anyhow::Result<()> {
    let source = opts.import.clone().ok_or_else(|| {
        anyhow::anyhow!(
            "`injekt session export <PATH>` requires the global `--import <FILE>` \
             (re-key an existing encrypted export); the post-run inline export \
             stays driven by the --export-encrypted flag"
        )
    })?;
    let scrubber = crate::session::scrubber::Scrubber::new(opts.no_redact);
    tracing::warn!(
        path = %scrubber.scrub(&source),
        "session export (chiffré) demandé — artefact sensible"
    );
    // Source passphrase: env or TTY single prompt (a typo just fails the
    // decrypt, nothing is written yet). Destination passphrase: read a
    // SECOND time (fresh rotation); the output is then self-verified by a
    // decrypt pass — a typo'd destination passphrase would produce an
    // unrecoverable blob, so the file is re-opened right after the write
    // and removed on failure.
    let source_pass = passphrase_for_session("source")?;
    let dest_pass = passphrase_for_session("destination")?;
    crate::session::export::EncryptedExport::rekey_from_file(
        &source_pass,
        &source,
        &dest_pass,
        &args.path,
        opts.force,
    )?;
    if let Err(e) =
        crate::session::export::EncryptedExport::decrypt_from_file(&dest_pass, &args.path)
    {
        let _ = std::fs::remove_file(&args.path);
        anyhow::bail!(
            "self-verification of the re-keyed export failed ({e}) — partial output removed"
        );
    }
    println!(
        "session export: {} (0o600, argon2id, self-verified)",
        scrubber.scrub(&args.path)
    );
    Ok(())
}

/// C17 — deprecated top-level `injekt replay` alias keeps running (2
/// releases left) with a one-line nudge; `session replay <FILE>` is the
/// same engine. Flag-only wording, no values echoed (OPSEC).
pub(crate) fn warn_legacy_replay_alias() {
    tracing::warn!(
        "legacy `injekt replay` alias deprecated (2 releases left): \
         use `injekt session replay <FILE>`"
    );
}
