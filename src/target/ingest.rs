#![deny(unsafe_code)]

//! Multi-source target ingestion (`--bulk-file`, `--stdin`, `--openapi-file`,
//! `--sitemap-file`, `--raw-dir`).
//!
//! All entry points are pure over strings except the `*_file` / `*_dir`
//! loaders, which are thin I/O wrappers. Every collected URL is validated
//! with [`TargetUrl::parse`] (same anti-SSRF rules as `--target`): invalid
//! or private targets are skipped with a warning, duplicates removed, output
//! truncated to [`MAX_BULK_TARGETS`].

use std::collections::HashSet;

use crate::target::bulk::MAX_BULK_TARGETS;
use crate::target::raw_request::RawRequest;
use crate::target::url::TargetUrl;

/// Maximum bytes accepted for any ingestion file (`--bulk-file`,
/// `--openapi-file`, `--sitemap-file`, stdin). Fail fast instead of
/// loading unbounded input into RAM.
pub const MAX_INGEST_FILE_BYTES: u64 = 10 * 1024 * 1024;

/// Per-file cap for `--raw-dir` Burp/ZAP exports (raw requests are small;
/// 2 MiB already generous, rejects accidental binary dumps).
pub const MAX_RAW_FILE_BYTES: u64 = 2 * 1024 * 1024;

/// Read a UTF-8 file with a `metadata().len()` pre-check (no unbounded
/// `read_to_string`). Returns a descriptive error with the faulty path.
fn read_limited_file(path: &str, max_bytes: u64) -> anyhow::Result<String> {
    let meta =
        std::fs::metadata(path).map_err(|e| anyhow::anyhow!("cannot stat file '{path}': {e}"))?;
    if meta.len() > max_bytes {
        anyhow::bail!(
            "file '{path}' too large ({} bytes > {max_bytes} bytes)",
            meta.len()
        );
    }
    std::fs::read_to_string(path).map_err(|e| anyhow::anyhow!("cannot read file '{path}': {e}"))
}

/// Merge every ingestion source from [`crate::cli::args::Cli`] into one
/// deduplicated target list.
///
/// Precedence is intentionally flat — every source is additive:
/// `--target` / `scan --target` / `auto --target`, `--bulk-file` (or `-`
/// for stdin), `--stdin`, `--openapi-file`, `--sitemap-file`, `--raw-dir`.
///
/// # Errors
/// Returns an error when files cannot be read/parsed, or when no valid
/// target remains after filtering.
pub fn collect_targets(
    cli: &crate::cli::args::Cli,
    extra_target: Option<&str>,
) -> anyhow::Result<Vec<String>> {
    let mut seen = HashSet::<String>::new();
    let mut out = Vec::new();
    let mut push = |url: String, allow_private: bool| {
        let trimmed = url.trim().to_owned();
        if trimmed.is_empty() || !seen.insert(trimmed.clone()) {
            return;
        }
        if let Err(e) = TargetUrl::parse(&trimmed, allow_private) {
            tracing::warn!(target = %trimmed, error=%e, "skipping invalid ingestion target");
            return;
        }
        out.push(trimmed);
    };

    let allow_private = cli.allow_private;

    match cli.try_effective_target() {
        Ok(Some(t)) => push(t, allow_private),
        Ok(None) => {}
        Err(e) => anyhow::bail!("{e}"),
    }
    if let Some(t) = extra_target {
        push(t.to_owned(), allow_private);
    }

    if let Some(path) = cli.bulk_file.as_deref() {
        let content = if path == "-" {
            read_stdin_all()?
        } else {
            read_limited_file(path, MAX_INGEST_FILE_BYTES)
                .map_err(|e| anyhow::anyhow!("cannot read bulk file '{path}': {e}"))?
        };
        for t in parse_targets_text(&content) {
            push(t, allow_private);
        }
    }
    if cli.stdin && cli.bulk_file.as_deref() != Some("-") {
        let content = read_stdin_all()?;
        for t in parse_targets_text(&content) {
            push(t, allow_private);
        }
    }
    if let Some(path) = cli.openapi_file.as_deref() {
        let content = read_limited_file(path, MAX_INGEST_FILE_BYTES)
            .map_err(|e| anyhow::anyhow!("cannot read OpenAPI file '{path}': {e}"))?;
        for t in parse_openapi_targets(&content) {
            push(t, allow_private);
        }
    }
    if let Some(path) = cli.sitemap_file.as_deref() {
        let content = read_limited_file(path, MAX_INGEST_FILE_BYTES)
            .map_err(|e| anyhow::anyhow!("cannot read sitemap file '{path}': {e}"))?;
        for t in parse_sitemap_targets(&content) {
            push(t, allow_private);
        }
    }
    if let Some(dir) = cli.raw_dir.as_deref() {
        for t in load_raw_dir_targets(dir)? {
            push(t, allow_private);
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

/// Plain-text target list: one URL per line, `#` / `//` comments skipped.
#[must_use]
pub fn parse_targets_text(content: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
            continue;
        }
        // Keep the raw line; validation/dedup happens in `collect_targets`.
        // Harvest bare `http(s)://` tokens from noisy lines (Burp history copy-paste).
        if trimmed.contains("://") && trimmed.contains(' ') {
            for token in trimmed.split_whitespace() {
                let token = token.trim_matches(|c| c == '"' || c == '\'' || c == ',' || c == ';');
                if token.starts_with("http://") || token.starts_with("https://") {
                    out.push(token.to_owned());
                }
            }
        } else {
            out.push(trimmed.to_owned());
        }
    }
    out
}

/// Minimal `OpenAPI` 3.x harvester (no new dependency, `serde_json::Value` only).
///
/// Uses `servers[0].url` (fallback `https://example.com`), iterates `paths`,
/// replaces `{param}` templates with `1`, and maps `parameters` with
/// `in == "query"` to `?name=1` pairs. Only `http(s)` servers are honoured.
#[must_use]
pub fn parse_openapi_targets(content: &str) -> Vec<String> {
    let doc = match serde_json::from_str::<serde_json::Value>(content) {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!(error=%e, "ignoring invalid OpenAPI JSON");
            return Vec::new();
        }
    };
    let base = doc
        .get("servers")
        .and_then(|s| s.as_array())
        .and_then(|a| a.first())
        .and_then(|s| s.get("url"))
        .and_then(|u| u.as_str())
        .unwrap_or("https://example.com");
    if !(base.starts_with("http://") || base.starts_with("https://")) {
        return Vec::new();
    }
    let base = base.trim_end_matches('/');
    let Some(paths) = doc.get("paths").and_then(|p| p.as_object()) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (path, item) in paths {
        let normalized = replace_path_templates(path);
        let mut queries: Vec<String> = Vec::new();
        if let Some(obj) = item.as_object() {
            for method_item in obj.values() {
                if let Some(params) = method_item.get("parameters").and_then(|p| p.as_array()) {
                    for param in params {
                        let is_query = param.get("in").and_then(|v| v.as_str()) == Some("query");
                        if !is_query {
                            continue;
                        }
                        if let Some(name) = param.get("name").and_then(|n| n.as_str()) {
                            let example = param
                                .get("example")
                                .map(value_to_string)
                                .or_else(|| {
                                    param
                                        .get("schema")
                                        .and_then(|s| s.get("example"))
                                        .map(value_to_string)
                                })
                                .or_else(|| {
                                    param
                                        .get("schema")
                                        .and_then(|s| s.get("default"))
                                        .map(value_to_string)
                                })
                                .unwrap_or_else(|| "1".to_owned());
                            queries.push(format!("{name}={example}"));
                        }
                    }
                }
            }
        }
        queries.sort();
        queries.dedup();
        let url = if queries.is_empty() {
            format!("{base}{normalized}?id=1")
        } else {
            format!("{base}{normalized}?{}", queries.join("&"))
        };
        out.push(url);
    }
    out.sort();
    out.dedup();
    out
}

fn value_to_string(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => {
            if s.is_empty() {
                "1".to_owned()
            } else {
                urlencode_minimal(s)
            }
        }
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        _ => "1".to_owned(),
    }
}

fn urlencode_minimal(input: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        if c.is_ascii_alphanumeric() || "-_.~".contains(c) {
            out.push(c);
        } else if c == ' ' {
            out.push_str("%20");
        } else {
            for byte in c.to_string().as_bytes() {
                let _ = write!(out, "%{byte:02X}");
            }
        }
    }
    out
}

fn replace_path_templates(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    let mut in_brace = false;
    for c in path.chars() {
        match c {
            '{' => {
                in_brace = true;
                out.push('1');
            }
            '}' => in_brace = false,
            _ => {
                if !in_brace {
                    out.push(c);
                }
            }
        }
    }
    if out.starts_with('/') {
        out
    } else {
        format!("/{out}")
    }
}

/// Sitemap harvester: extracts `<loc>https://…</loc>` entries (case-insensitive).
#[must_use]
pub fn parse_sitemap_targets(content: &str) -> Vec<String> {
    use std::sync::OnceLock;
    static RE: OnceLock<Option<regex::Regex>> = OnceLock::new();
    let re = RE.get_or_init(|| regex::Regex::new(r"(?i)<loc>\s*(https?://[^<\s]+)\s*</loc>").ok());
    let Some(re) = re.as_ref() else {
        tracing::warn!("sitemap regex unavailable, skipping sitemap parse");
        return Vec::new();
    };
    let mut out = Vec::new();
    for capture in re.captures_iter(content) {
        if let Some(matched) = capture.get(1) {
            out.push(matched.as_str().trim().to_owned());
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Load every `*.txt`/`*.req` file from `dir` as a Burp/ZAP raw request and
/// return the reconstructed target URLs (`https` preferred, `http` fallback).
///
/// Only files with a `txt`/`req` extension **and** regular-file type are
/// considered (`&&`, not `||`); symlinks are rejected via `symlink_metadata`
/// and each file is capped at [`MAX_RAW_FILE_BYTES`].
///
/// # Errors
/// Returns an error when the directory cannot be listed.
pub fn load_raw_dir_targets(dir: &str) -> anyhow::Result<Vec<String>> {
    let entries =
        std::fs::read_dir(dir).map_err(|e| anyhow::anyhow!("cannot list raw dir '{dir}': {e}"))?;
    let mut out = Vec::new();
    for entry in entries {
        let Ok(entry) = entry else { continue };
        let path = entry.path();
        // Reject symlinks first (TOCTOU-safe: `symlink_metadata`, not `metadata`).
        let symlink_meta = match std::fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!(path = %path.display(), error=%e, "skipping raw file (stat failed)");
                continue;
            }
        };
        if symlink_meta.file_type().is_symlink() {
            tracing::warn!(path = %path.display(), "skipping raw file (symlink rejected)");
            continue;
        }
        // `&&`: extension must match AND entry must be a regular file.
        let has_valid_ext = path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| e.eq_ignore_ascii_case("txt") || e.eq_ignore_ascii_case("req"));
        if !(has_valid_ext && symlink_meta.is_file()) {
            continue;
        }
        if symlink_meta.len() > MAX_RAW_FILE_BYTES {
            tracing::warn!(
                path = %path.display(),
                len = symlink_meta.len(),
                "skipping raw file (exceeds 2 MiB cap)"
            );
            continue;
        }
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(path = %path.display(), error=%e, "skipping unreadable raw file");
                continue;
            }
        };
        let req = match RawRequest::parse(&content) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(path = %path.display(), error=%e, "skipping unparseable raw file");
                continue;
            }
        };
        if let Some(url) = req.to_url("https").or_else(|| req.to_url("http")) {
            out.push(url);
        }
    }
    out.sort();
    out.dedup();
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_skips_comments_and_harvests_tokens() {
        let content = "# c\nhttps://a.example/?id=1\n  https://b.example/?q=x // trailing\n";
        let parsed = parse_targets_text(content);
        assert!(parsed.iter().any(|u| u.contains("a.example")));
        assert!(parsed.iter().any(|u| u.contains("b.example")));
    }

    #[test]
    fn openapi_builds_query_urls() {
        let doc = serde_json::json!({
            "servers": [{"url": "https://api.example.com/v1"}],
            "paths": {
                "/users/{id}": {
                    "get": {"parameters": [
                        {"name": "verbose", "in": "query"},
                        {"name": "page", "in": "query", "schema": {"example": 2}}
                    ]}
                },
                "/health": {"get": {}}
            }
        });
        let targets = parse_openapi_targets(&doc.to_string());
        assert_eq!(targets.len(), 2);
        assert!(
            targets
                .iter()
                .any(|u| u.contains("/users/1") && u.contains("verbose=1"))
        );
        assert!(targets.iter().any(|u| u.contains("/health?id=1")));
    }

    #[test]
    fn openapi_rejects_non_http_servers() {
        let doc = r#"{"servers":[{"url":"ftp://x"}],"paths":{"/a":{"get":{}}}}"#;
        assert!(parse_openapi_targets(doc).is_empty());
    }

    #[test]
    fn sitemap_extracts_locs() {
        let xml = r#"<?xml version="1.0"?><urlset>
<url><loc>https://example.com/?id=1</loc></url>
<url><LOC>https://example.com/search?q=x</LOC></url>
</urlset>"#;
        let targets = parse_sitemap_targets(xml);
        assert_eq!(targets.len(), 2);
    }

    #[test]
    fn path_templates_replaced() {
        assert_eq!(
            replace_path_templates("/users/{id}/posts/{postId}"),
            "/users/1/posts/1"
        );
        assert_eq!(replace_path_templates("users"), "/users");
    }
}
