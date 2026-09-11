#![deny(unsafe_code)]

use owo_colors::OwoColorize;
use std::io::IsTerminal as _;
use tracing_subscriber::{
    fmt::{FmtContext, FormatEvent, FormatFields, format::Writer},
    registry::LookupSpan,
};

/// `false` when colors must be suppressed: `NO_COLOR` set (any value),
/// `TERM=dumb`, `CLICOLOR=0`, or stderr not a TTY (pipe/CI/MCP).
/// Logs go to stderr, so stderr TTY drives the decision here; stdout
/// results use [`stdout_colors_enabled`].
#[must_use]
pub fn colors_enabled() -> bool {
    if std::env::var_os("NO_COLOR").is_some() {
        return false;
    }
    if std::env::var("TERM").is_ok_and(|v| v == "dumb") {
        return false;
    }
    if std::env::var("CLICOLOR").is_ok_and(|v| v == "0") {
        return false;
    }
    std::io::stderr().is_terminal()
}

/// Same gate as [`colors_enabled`] but for stdout results
/// (`reporting::console`): `NO_COLOR`/`TERM=dumb`/`CLICOLOR=0` or stdout
/// piped (JSON pipe, `--output` consumers) disables colors.
#[must_use]
pub fn stdout_colors_enabled() -> bool {
    if std::env::var_os("NO_COLOR").is_some() {
        return false;
    }
    if std::env::var("TERM").is_ok_and(|v| v == "dumb") {
        return false;
    }
    if std::env::var("CLICOLOR").is_ok_and(|v| v == "0") {
        return false;
    }
    std::io::stdout().is_terminal()
}

/// sqlmap-style event formatter: `[HH:MM:SS] [LEVEL] message field=value ...`
/// instead of the default `2026-...Z  WARN crate::module: message`.
pub struct SqlmapStyle;

impl<S, N> FormatEvent<S, N> for SqlmapStyle
where
    S: tracing::Subscriber + for<'a> LookupSpan<'a>,
    N: for<'writer> FormatFields<'writer> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &tracing::Event<'_>,
    ) -> std::fmt::Result {
        let now = chrono::Local::now().format("%H:%M:%S");
        if colors_enabled() {
            write!(writer, "{}", format!("[{now}]").bright_black())?;
            match *event.metadata().level() {
                tracing::Level::ERROR => write!(writer, " {}", "[CRITICAL]".red().bold())?,
                tracing::Level::WARN => write!(writer, " {}", "[WARNING]".yellow().bold())?,
                tracing::Level::INFO => write!(writer, " {}", "[INFO]".bright_cyan().bold())?,
                tracing::Level::DEBUG => write!(writer, " {}", "[DEBUG]".bright_black())?,
                tracing::Level::TRACE => write!(writer, " {}", "[TRACE]".bright_black())?,
            }
        } else {
            write!(writer, "[{now}]")?;
            match *event.metadata().level() {
                tracing::Level::ERROR => write!(writer, " [CRITICAL]")?,
                tracing::Level::WARN => write!(writer, " [WARNING]")?,
                tracing::Level::INFO => write!(writer, " [INFO]")?,
                tracing::Level::DEBUG => write!(writer, " [DEBUG]")?,
                tracing::Level::TRACE => write!(writer, " [TRACE]")?,
            }
        }
        write!(writer, " ")?;
        ctx.format_fields(writer.by_ref(), event)?;
        writeln!(writer)
    }
}

/// Source of truth for the wordmark: `ascii_art.txt` at the repo root, kept
/// as several `----`-separated art variants. We pull the block-glyph one
/// (2nd section) straight from the file instead of retyping it, so the
/// banner can never drift from the actual art.
const ASCII_ART: &str = include_str!("../../../ascii_art.txt");

fn is_separator(line: &str) -> bool {
    let line = line.trim();
    line.len() >= 4 && line.chars().all(|c| c == '-')
}

fn logo_lines() -> impl Iterator<Item = &'static str> {
    ASCII_ART
        .split('\n')
        .skip_while(|l| !is_separator(l))
        .skip(1)
        .take_while(|l| !is_separator(l))
        .filter(|l| !l.trim().is_empty())
}

/// Startup banner: colored wordmark + tagline, always written to stderr so
/// stdout stays pipeable (recon JSON, `--output` reports, MCP JSON-RPC).
/// Plain (no color) when [`colors_enabled`] is `false` (`NO_COLOR`,
/// `TERM=dumb`, pipe/CI).
pub fn banner() {
    if !colors_enabled() {
        for line in logo_lines() {
            eprintln!("{}", line.trim_end());
        }
        eprintln!("by s6stem · v{}", env!("CARGO_PKG_VERSION"));
        eprintln!("zero persistence · anonymisation by design");
        eprintln!();
        return;
    }
    for line in logo_lines() {
        eprintln!("{}", line.trim_end().bright_cyan());
    }
    eprintln!(
        "{} {} {}",
        "by s6stem".bright_black(),
        "·".bright_black(),
        format!("v{}", env!("CARGO_PKG_VERSION")).bright_magenta()
    );
    eprintln!(
        "{}",
        "zero persistence · anonymisation by design".bright_black()
    );
    eprintln!();
}
