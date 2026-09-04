#![deny(unsafe_code)]

//! Scaffold helpers: `injekt init`, `injekt completions`, `injekt man`.

use crate::cli::args::{Cli, CompletionsArgs, InitArgs};

const STARTER_CONFIG: &str = r#"# injekt starter config — precedence: CLI flag > INJEKT_* env > this file > --profile > defaults.
# Secrets (--cookies, Authorization) are intentionally NOT supported here.
profile = "balanced"
threads = 5
timeout = 30
retries = 3
delay = 500
rate_limit = 10.0
jitter = "750,250"
level = 1
techniques = ["all"]
# proxy = "socks5h://127.0.0.1:9050"
# oob_wait_secs = 5
"#;

/// Write a starter `injekt.toml`.
///
/// # Errors
/// Returns an error when the destination exists without `--force`, the
/// profile name is unknown, or the file cannot be written.
pub fn run_init(args: &InitArgs) -> anyhow::Result<()> {
    let profile = args.preset.to_ascii_lowercase();
    if !crate::cli::profile::Profile::all_names().contains(&profile.as_str()) {
        anyhow::bail!(
            "unknown preset '{}' (expected one of {:?})",
            args.preset,
            crate::cli::profile::Profile::all_names()
        );
    }
    let path = std::path::Path::new(&args.path);
    if path.exists() && !args.force {
        anyhow::bail!("{} exists (use --force to overwrite)", path.display());
    }
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    let content = STARTER_CONFIG.replace("\"balanced\"", &format!("\"{profile}\""));
    std::fs::write(path, content)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    println!("wrote {}", path.display());
    Ok(())
}

/// Print shell completions to stdout.
///
/// # Errors
/// Returns an error only when the shell name is unknown (clap constrains it
/// anyway, so this is defensive).
pub fn run_completions(cli: &Cli, args: &CompletionsArgs) -> anyhow::Result<()> {
    use clap::CommandFactory as _;
    use clap_complete::{generate, shells};

    let _ = cli;
    let mut cmd = crate::cli::args::Cli::command();
    match args.shell.as_str() {
        "bash" => generate(shells::Bash, &mut cmd, "injekt", &mut std::io::stdout()),
        "zsh" => generate(shells::Zsh, &mut cmd, "injekt", &mut std::io::stdout()),
        "fish" => generate(shells::Fish, &mut cmd, "injekt", &mut std::io::stdout()),
        "powershell" => generate(
            shells::PowerShell,
            &mut cmd,
            "injekt",
            &mut std::io::stdout(),
        ),
        "elvish" => generate(shells::Elvish, &mut cmd, "injekt", &mut std::io::stdout()),
        other => anyhow::bail!("unknown shell '{other}'"),
    }
    Ok(())
}

/// Print a man page (roff) to stdout.
pub fn run_man() {
    use clap::CommandFactory as _;
    let cmd = crate::cli::args::Cli::command();
    let man = clap_mangen::Man::new(cmd);
    let _ = man.render(&mut std::io::stdout());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starter_config_contains_profile() {
        assert!(STARTER_CONFIG.contains("profile ="));
        assert!(STARTER_CONFIG.contains("threads ="));
    }

    #[test]
    fn init_rejects_unknown_profile() {
        let args = InitArgs {
            path: "/tmp/injekt-should-not-exist.toml".to_owned(),
            preset: "nope".to_owned(),
            force: true,
        };
        assert!(run_init(&args).is_err());
    }

    #[test]
    fn init_writes_temp_file() {
        let path = std::env::temp_dir().join(format!("injekt-init-{}.toml", std::process::id()));
        let args = InitArgs {
            path: path.to_string_lossy().into_owned(),
            preset: "stealth".to_owned(),
            force: true,
        };
        assert!(run_init(&args).is_ok());
        let content = std::fs::read_to_string(&path).unwrap_or_default();
        assert!(content.contains("stealth"));
        let _ = std::fs::remove_file(&path);
    }
}
