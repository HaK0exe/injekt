//! Pure string-format parsers for target ingestion (P5 split):
//! plain text, `OpenAPI` 3.x, sitemap XML (+ internal regex helper).
use std::sync::OnceLock;

/// `<loc>` harvester compiled once (was `Regex::new` per sitemap file).
fn sitemap_loc_regex() -> Option<&'static regex::Regex> {
    static CELL: OnceLock<Option<regex::Regex>> = OnceLock::new();
    CELL.get_or_init(|| regex::Regex::new(r"(?i)<loc>\s*(https?://[^<\s]+)\s*</loc>").ok())
        .as_ref()
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
                            // Percent-encode name/value: a raw `&`/`=`/`#` in
                            // an OpenAPI parameter name would otherwise split
                            // the query string or truncate the URL.
                            queries.push(format!(
                                "{}={}",
                                crate::target::openapi_encode(name),
                                crate::target::openapi_encode(&example)
                            ));
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

pub(super) fn replace_path_templates(path: &str) -> String {
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
    let Some(re) = sitemap_loc_regex() else {
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
