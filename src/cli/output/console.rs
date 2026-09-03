#![deny(unsafe_code)]

use owo_colors::OwoColorize;
use tracing_subscriber::{
    fmt::{FmtContext, FormatEvent, FormatFields, format::Writer},
    registry::LookupSpan,
};

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
        write!(writer, "{}", format!("[{now}]").bright_black())?;
        match *event.metadata().level() {
            tracing::Level::ERROR => write!(writer, " {}", "[CRITICAL]".red().bold())?,
            tracing::Level::WARN => write!(writer, " {}", "[WARNING]".yellow().bold())?,
            tracing::Level::INFO => write!(writer, " {}", "[INFO]".bright_cyan().bold())?,
            tracing::Level::DEBUG => write!(writer, " {}", "[DEBUG]".bright_black())?,
            tracing::Level::TRACE => write!(writer, " {}", "[TRACE]".bright_black())?,
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
pub fn banner() {
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
