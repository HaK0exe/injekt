#![deny(unsafe_code)]

use anyhow::Context as _;

/// # Errors
/// Returns an error if neither `--file` nor `--import` is given, the file
/// exceeds 10 MiB, or the file can't be read.
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
    println!("replay: {} bytes from {}", data.len(), file);
    Ok(())
}
