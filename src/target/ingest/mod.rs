#![deny(unsafe_code)]

//! Multi-source target ingestion (`--bulk-file`, `--stdin`, `--openapi-file`,
//! `--sitemap-file`, `--raw-dir`; plus the unified `--input <PATH|-|DIR>`
//! C17 resolver on top of those same loaders).
//!
//! All entry points are pure over strings except the `*_file` / `*_dir`
//! loaders, which are thin I/O wrappers. Every collected URL is validated
//! with [`TargetUrl::parse`] (same anti-SSRF rules as `--target`): invalid
//! or private targets are skipped with a warning, duplicates removed, output
//! truncated to [`MAX_BULK_TARGETS`].

use std::collections::HashSet;

use crate::target::bulk::MAX_BULK_TARGETS;
use crate::target::url::TargetUrl;

/// Maximum bytes accepted for any ingestion file (`--bulk-file`,
/// `--openapi-file`, `--sitemap-file`, stdin). Fail fast instead of
/// loading unbounded input into RAM.
pub const MAX_INGEST_FILE_BYTES: u64 = 10 * 1024 * 1024;

/// Per-file cap for `--raw-dir` Burp/ZAP exports (raw requests are small;
/// 2 MiB already generous, rejects accidental binary dumps).
pub const MAX_RAW_FILE_BYTES: u64 = 2 * 1024 * 1024;

/// Read a UTF-8 file with a hard byte cap enforced on the read itself
/// (`open` + `take(max+1)`), not just a `metadata().len()` pre-check: the
/// file can grow between `stat` and `read` (TOCTOU), bypassing a pre-check
/// cap into OOM. Returns a descriptive error with the faulty path.
pub(crate) fn read_limited_file(path: &str, max_bytes: u64) -> anyhow::Result<String> {
    use std::io::Read as _;
    let file =
        std::fs::File::open(path).map_err(|e| anyhow::anyhow!("cannot read file '{path}': {e}"))?;
    let mut limited = file.take(max_bytes.saturating_add(1));
    let mut buf = String::new();
    limited
        .read_to_string(&mut buf)
        .map_err(|e| anyhow::anyhow!("cannot read file '{path}': {e}"))?;
    if u64::try_from(buf.len()).unwrap_or(u64::MAX) > max_bytes {
        anyhow::bail!("file '{path}' too large (> {max_bytes} bytes)");
    }
    Ok(buf)
}

/// C17 — famille de format détectée pour `--input` (migration 2, grammaire
/// figée du plan). La détection est un sniff léger sur une fenêtre de début
/// de fichier : fiable pour un document de plus d'un Mo — un OpenAPI/sitemap
/// déclaratif porte sa clé/racine tout au début; un TXT de cibles risque au
/// pire une sur-détection si "openapi" apparaît dans le premier KiB (mettre
/// la liste ailleurs, ou utiliser le mode legacy équivalent).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InputKind {
    Stdin,
    RawDir,
    Openapi,
    Sitemap,
    Text,
}

/// Detection rules: `-` → stdin; existing directory → raw-dir; extension
/// `.json/.yaml/.yml` with an `openapi` marker → openapi; `.xml` carrying
/// a `<urlset` document → sitemap; everything else (including `.xml`
/// without `<urlset`, `.json/.yaml` without `openapi`) → TXT target list.
#[must_use]
fn sniff_input_kind(path: &str, content_first: Option<&str>) -> InputKind {
    if path == "-" {
        return InputKind::Stdin;
    }
    if std::path::Path::new(path).is_dir() {
        return InputKind::RawDir;
    }
    let Some(content) = content_first else {
        return InputKind::Text;
    };
    let ext = std::path::Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    // Sniff window: first KiB (documents declare themselves early).
    let window = &content[..content.len().min(1024)];
    match ext.as_str() {
        "json" | "yaml" | "yml" if window.contains("openapi") => InputKind::Openapi,
        "xml" if window.contains("<urlset") => InputKind::Sitemap,
        _ => InputKind::Text,
    }
}

/// Merge every ingestion source from [`crate::cli::args::Cli`] into one
/// deduplicated target list.
///
/// Precedence is intentionally flat — every source is additive:
/// `--target` / `scan --target` / `auto --target`, `--input <PATH|-|DIR>`
/// (C17, auto-detected on top of the same loaders), `--bulk-file` (or `-`
/// for stdin), `--stdin`, `--openapi-file`, `--sitemap-file`, `--raw-dir`.
///
/// # Errors
/// Returns an error when files cannot be read/parsed, or when no valid
/// target remains after filtering.
#[allow(clippy::too_many_lines)]
pub fn collect_targets(
    cli: &crate::cli::args::Cli,
    extra_target: Option<&str>,
) -> anyhow::Result<Vec<String>> {
    let mut seen = HashSet::<String>::new();
    let mut out = Vec::new();
    // Fail-fast target cap: checked before every insert so a 10 MiB source
    // (~500k URLs) bails instead of filling RAM before the end-of-function
    // check below. Returns `true` when the cap is hit.
    let mut push = |url: String, allow_private: bool| -> bool {
        if out.len() >= MAX_BULK_TARGETS {
            return true;
        }
        let trimmed = url.trim().to_owned();
        if trimmed.is_empty() || !seen.insert(trimmed.clone()) {
            return false;
        }
        match TargetUrl::parse(&trimmed, allow_private) {
            Ok(parsed) => {
                // Bare hosts (`example.com`) are accepted via `https://`
                // default: store the normalized URL so downstream `Engine`
                // and HTTP layers never see a scheme-less string.
                if trimmed.contains("://") {
                    out.push(trimmed);
                } else {
                    // `seen` already deduped the raw form; also dedupe the
                    // normalized form against earlier full URLs.
                    let normalized = parsed.normalized();
                    if seen.insert(normalized.clone()) {
                        out.push(normalized);
                    }
                }
            }
            Err(e) => {
                // Scrubbed: targets may carry `?token=` / `user:pass@` secrets.
                let scrubbed = crate::session::scrubber::Scrubber::new(false).scrub(&trimmed);
                tracing::warn!(target = %scrubbed, error=%e, "skipping invalid ingestion target");
                return false;
            }
        }
        false
    };

    let allow_private = cli.http.allow_private;

    match cli.try_effective_target() {
        Ok(Some(t)) => {
            if push(t, allow_private) {
                anyhow::bail!("ingestion exceeds {MAX_BULK_TARGETS} targets");
            }
        }
        Ok(None) => {}
        Err(e) => anyhow::bail!("{e}"),
    }
    if let Some(t) = extra_target
        && push(t.to_owned(), allow_private)
    {
        anyhow::bail!("ingestion exceeds {MAX_BULK_TARGETS} targets");
    }

    // C17 — `--input <PATH|-|DIR>` : ingestion unifiée (migration 2). Le
    // sniff figé (`sniff_input_kind`) route vers les loaders legacy
    // exactement — mêmes parsers, mêmes caps, mêmes warnings — et la
    // source reste additive (les doublons tombent sur le dedup `seen`).
    if let Some(input) = cli.target_opts.input.as_deref() {
        let file_content = if input == "-" || std::path::Path::new(input).is_dir() {
            None
        } else {
            Some(read_limited_file(input, MAX_INGEST_FILE_BYTES)?)
        };
        let kind = sniff_input_kind(input, file_content.as_deref());
        let targets: Vec<String> = match (kind, file_content.as_deref()) {
            (InputKind::Stdin, _) => parse_targets_text(&read_stdin_all()?),
            (InputKind::RawDir, _) => load_raw_dir_targets(input)?,
            (InputKind::Openapi, Some(content)) => parse_openapi_targets(content),
            (InputKind::Sitemap, Some(content)) => parse_sitemap_targets(content),
            (InputKind::Text, Some(content)) => parse_targets_text(content),
            // Inatteignable : `Stdin`/`RawDir` couvrent tous les cas
            // `content = None` (sniff ne classe Openapi/Sitemap/Text
            // que lorsqu'un contenu fichier a été lu).
            (InputKind::Openapi | InputKind::Sitemap | InputKind::Text, None) => Vec::new(),
        };
        for t in targets {
            if push(t, allow_private) {
                anyhow::bail!("ingestion exceeds {MAX_BULK_TARGETS} targets");
            }
        }
    }

    if let Some(path) = cli.target_opts.bulk_file.as_deref() {
        let content = if path == "-" {
            read_stdin_all()?
        } else {
            read_limited_file(path, MAX_INGEST_FILE_BYTES)
                .map_err(|e| anyhow::anyhow!("cannot read bulk file '{path}': {e}"))?
        };
        for t in parse_targets_text(&content) {
            if push(t, allow_private) {
                anyhow::bail!("ingestion exceeds {MAX_BULK_TARGETS} targets");
            }
        }
    }
    if cli.target_opts.stdin && cli.target_opts.bulk_file.as_deref() != Some("-") {
        let content = read_stdin_all()?;
        for t in parse_targets_text(&content) {
            if push(t, allow_private) {
                anyhow::bail!("ingestion exceeds {MAX_BULK_TARGETS} targets");
            }
        }
    }
    if let Some(path) = cli.target_opts.openapi_file.as_deref() {
        let content = read_limited_file(path, MAX_INGEST_FILE_BYTES)
            .map_err(|e| anyhow::anyhow!("cannot read OpenAPI file '{path}': {e}"))?;
        for t in parse_openapi_targets(&content) {
            if push(t, allow_private) {
                anyhow::bail!("ingestion exceeds {MAX_BULK_TARGETS} targets");
            }
        }
    }
    if let Some(path) = cli.target_opts.sitemap_file.as_deref() {
        let content = read_limited_file(path, MAX_INGEST_FILE_BYTES)
            .map_err(|e| anyhow::anyhow!("cannot read sitemap file '{path}': {e}"))?;
        for t in parse_sitemap_targets(&content) {
            if push(t, allow_private) {
                anyhow::bail!("ingestion exceeds {MAX_BULK_TARGETS} targets");
            }
        }
    }
    if let Some(dir) = cli.target_opts.raw_dir.as_deref() {
        for t in load_raw_dir_targets(dir)? {
            if push(t, allow_private) {
                anyhow::bail!("ingestion exceeds {MAX_BULK_TARGETS} targets");
            }
        }
    }

    if out.len() > MAX_BULK_TARGETS {
        anyhow::bail!("ingestion exceeds {MAX_BULK_TARGETS} targets");
    }
    if out.is_empty() {
        anyhow::bail!("no valid targets from ingestion sources");
    }
    Ok(out)
}

fn read_stdin_all() -> anyhow::Result<String> {
    use std::io::Read as _;
    let mut buf = String::new();
    // Cap stdin like files (10 MiB) to avoid unbounded RAM on piped input.
    let mut limited = std::io::stdin().take(MAX_INGEST_FILE_BYTES + 1);
    limited
        .read_to_string(&mut buf)
        .map_err(|e| anyhow::anyhow!("cannot read stdin: {e}"))?;
    if u64::try_from(buf.len()).unwrap_or(u64::MAX) > MAX_INGEST_FILE_BYTES {
        anyhow::bail!("stdin exceeds {MAX_INGEST_FILE_BYTES} bytes (cap to avoid OOM)");
    }
    Ok(buf)
}

use self::parsers::{parse_openapi_targets, parse_sitemap_targets, parse_targets_text};
use self::raw::load_raw_dir_targets;

mod parsers;
mod raw;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests;
