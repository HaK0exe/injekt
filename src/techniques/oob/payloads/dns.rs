//! DNS-label helpers for OOB collaborator domains (P5 split): sanitizer,
//! subdomain builder, RFC 1035 domain validation, hex encoding/chunking.

/// Sanitize an arbitrary string into a valid DNS label.
///
/// Keeps `[a-z0-9-]`, lowercases, maps anything else to `-`, strips
/// leading/trailing `-`, truncates to 63 chars. Never returns empty
/// (falls back to `oob`).
#[must_use]
pub fn sanitize_dns_label(input: &str) -> String {
    let mut out: String = input
        .to_ascii_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let trimmed = out.trim_matches('-').to_owned();
    out = trimmed;
    if out.len() > 63 {
        out.truncate(63);
        let trimmed = out.trim_end_matches('-').to_owned();
        out = trimmed;
    }
    if out.is_empty() {
        "oob".to_owned()
    } else {
        out
    }
}

/// Build the fully qualified exfil domain `<token>.<domain>`.
///
/// Both parts are sanitized/lowercased; a trailing dot on `domain` is
/// stripped. Returns e.g. `oobabc123.collab.example.com`.
#[must_use]
pub fn build_subdomain(token: &str, domain: &str) -> String {
    let label = sanitize_dns_label(token);
    let dom = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    format!("{label}.{dom}")
}

/// Validate a user-supplied OOB domain (collaborator base domain).
///
/// Rejects empty strings, URLs with scheme/path/port, whitespace, and
/// labels violating RFC 1035 (length, charset, leading/trailing hyphen).
/// Requires at least one dot (e.g. `x.oastify.com`, not `localhost`).
#[must_use]
pub fn is_valid_oob_domain(domain: &str) -> bool {
    let d = domain.trim().trim_end_matches('.');
    if d.is_empty() || d.len() > 253 {
        return false;
    }
    if d.contains([' ', '\t', '\n', '\r', '/', ':', '@', '?', '#', '_']) {
        return false;
    }
    if d.contains("://") {
        return false;
    }
    if !d.contains('.') {
        return false;
    }
    for label in d.split('.') {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return false;
        }
    }
    true
}

/// Hex-encode a string for DNS exfiltration (keeps `[0-9a-f]` only).
#[must_use]
pub fn encode_for_dns(input: &str) -> String {
    hex::encode(input.as_bytes())
}

/// Split a hex string into DNS-label-sized chunks (default 32 chars keeps
/// room for `token.domain` suffix under the 63-char label limit).
#[must_use]
pub fn chunk_for_dns(hex_data: &str, chunk: usize) -> Vec<String> {
    if hex_data.is_empty() || chunk == 0 {
        return Vec::new();
    }
    hex_data
        .as_bytes()
        .chunks(chunk)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect()
}
