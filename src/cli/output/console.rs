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
        if crate::cli::output::theme::colors_for(crate::cli::output::theme::Stream::Stderr) {
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
