//! Marker tables and body signal scanners (weak/strong corroboration
//! contract; `set_vendor` keeps first-specific-wins over `Generic`).

use super::WafVendor;

/// Truncated body prefix inspected for challenge markers.
pub(super) const BODY_SCAN_LEN: usize = 32 * 1024;

/// Caller-side header value truncation (OPSEC: bounds secret retention).
pub const HEADER_VALUE_KEEP: usize = 128;

/// HTTP statuses corroborating a WAF block when combined with a marker.
/// `520-524` are Cloudflare origin-error codes; `429`/`503` cover
/// rate-limit/ban. Never sufficient alone.
pub(super) const CORROBORATING_STATUS: &[u16] = &[403, 406, 429, 503, 520, 521, 522, 523, 524];

/// Challenge body markers: `(needle, strong)`. Strong markers prove a
/// challenge all by themselves; weak ones only corroborate (need a second
/// weak hit, a header hit, or a corroborating status).
const BODY_MARKERS: &[(&str, bool)] = &[
    ("just a moment", true),
    ("managed challenge", true),
    ("cf-chl", true),
    ("challenges.cloudflare.com", true),
    // NOTE: `cloudflare ray id` is WEAK on purpose — Cloudflare prints a
    // `Ray ID` footer on every proxied page (even clean 200s), so it proves
    // presence, not a challenge. Blocking still fires via strong markers
    // (`just a moment`, `managed challenge`, `1020`/`1015`), the
    // `captcha+cloudflare` rule, or corroboration (2nd weak hit / header /
    // 403-503 status).
    ("cloudflare ray id", false),
    ("error code: 1020", true),
    ("error 1020", true),
    ("error code: 1015", true),
    ("error 1015", true),
    ("attention required", false),
    ("__cf_bm", false),
];

/// Generic / vendor-specific deny markers: `(needle, strong, vendor)`.
/// Weak markers only corroborate (need a header hit, a second weak hit, or
/// a corroborating status); strong ones prove a block on their own.
/// Vendor attribution follows the marker text (`incapsula incident` →
/// Imperva, `akamai edge` → Akamai, …); plain denials map to `Generic`.
const GENERIC_BODY_MARKERS: &[(&str, bool, WafVendor)] = &[
    ("request blocked", false, WafVendor::Generic),
    ("access denied", false, WafVendor::Generic),
    ("403 forbidden", false, WafVendor::Generic),
    ("incapsula incident", true, WafVendor::Imperva),
    ("incapsula", false, WafVendor::Imperva),
    ("akamai edge", false, WafVendor::Akamai),
    ("mod_security", false, WafVendor::ModSecurity),
    ("modsecurity", false, WafVendor::ModSecurity),
    // ALB error-page wording is load-balancer infra, not a WAF verdict —
    // attribute to `AwsAlb`, never `AwsWaf` (ALB ≠ WAF).
    ("awselb", false, WafVendor::AwsAlb),
];

/// Bot-mitigation (P0-4) body markers: `(needle, strong, vendor)`. Same
/// weak/strong corroboration contract as [`GENERIC_BODY_MARKERS`].
/// Weak needles are product words that also appear in benign content
/// (`datadome` in a blog post, `kasada` as a surname); strong needles are
/// challenge-artifact strings (captcha domains, sensor SDK names) that only
/// a bot-mitigation page serves.
const BOT_BODY_MARKERS: &[(&str, bool, WafVendor)] = &[
    ("captcha-delivery.com", true, WafVendor::DataDome),
    ("datadome", false, WafVendor::DataDome),
    ("kpsdk", true, WafVendor::Kasada),
    ("kasada", false, WafVendor::Kasada),
    ("px-captcha", true, WafVendor::Human),
    ("perimeterx", false, WafVendor::Human),
    // Turnstile widget field: a legit site embedding the widget serves this
    // on clean 200s too, so it stays weak (presence only without
    // corroboration). The active-challenge case is covered by the
    // `turnstile` + `cloudflare` rule below.
    ("cf-turnstile-response", false, WafVendor::Turnstile),
];

pub(super) fn push_hit(hits: &mut Vec<String>, hit: &str) {
    if !hits.iter().any(|h| h == hit) {
        hits.push(hit.to_owned());
    }
}

/// Prefer a specific vendor over `Generic`; first specific wins when several
/// fire (deterministic aggregation for `Baseline::new`).
pub(super) fn set_vendor(current: &mut Option<WafVendor>, new: WafVendor) {
    match current {
        None => *current = Some(new),
        Some(WafVendor::Generic) if new != WafVendor::Generic => *current = Some(new),
        _ => {}
    }
}

/// Scan a lowercased body prefix for challenge markers. Returns the hit
/// names (`body:…`), the weak-hit count, whether a strong marker fired, and
/// whether any marker implicates Cloudflare.
pub(super) fn challenge_body_signals(lower: &str) -> (Vec<String>, usize, bool, bool) {
    let mut marker_hits = Vec::new();
    let mut weak_count = 0usize;
    let mut strong_hit = false;
    let mut vendor_cf = false;
    for (needle, strong) in BODY_MARKERS {
        if lower.contains(needle) {
            marker_hits.push(format!("body:{needle}"));
            if *strong {
                strong_hit = true;
            } else {
                weak_count += 1;
            }
            vendor_cf = true;
        }
    }
    (marker_hits, weak_count, strong_hit, vendor_cf)
}

/// Scan a lowercased body prefix for generic/vendor deny markers. Returns
/// the hit names, the weak-hit count, whether a strong marker fired, and
/// the attributed vendor (`Generic` lowest priority — `set_vendor` keeps
/// any specific vendor found elsewhere).
pub(super) fn generic_body_signals(lower: &str) -> (Vec<String>, usize, bool, Option<WafVendor>) {
    let mut marker_hits = Vec::new();
    let mut weak_count = 0usize;
    let mut strong_hit = false;
    let mut vendor: Option<WafVendor> = None;
    for (needle, strong, owner) in GENERIC_BODY_MARKERS {
        if lower.contains(needle) {
            marker_hits.push(format!("body:{needle}"));
            if *strong {
                strong_hit = true;
            } else {
                weak_count += 1;
            }
            set_vendor(&mut vendor, *owner);
        }
    }
    (marker_hits, weak_count, strong_hit, vendor)
}

/// Scan a lowercased body prefix for bot-mitigation markers (P0-4).
/// Same return contract as [`generic_body_signals`]: hit names, weak-hit
/// count, strong flag, attributed vendor (`Generic` never wins over a
/// specific vendor via [`set_vendor`]).
pub(super) fn bot_body_signals(lower: &str) -> (Vec<String>, usize, bool, Option<WafVendor>) {
    let mut marker_hits = Vec::new();
    let mut weak_count = 0usize;
    let mut strong_hit = false;
    let mut vendor: Option<WafVendor> = None;
    for (needle, strong, owner) in BOT_BODY_MARKERS {
        if lower.contains(needle) {
            marker_hits.push(format!("body:{needle}"));
            if *strong {
                strong_hit = true;
            } else {
                weak_count += 1;
            }
            set_vendor(&mut vendor, *owner);
        }
    }
    (marker_hits, weak_count, strong_hit, vendor)
}

/// Whether a status corroborates marker hits into a `blocking` verdict.
/// Shared by [`detect_cloudflare_flat`](crate::detection::waf::detect_cloudflare_flat) and the CT-mismatch merge so both
/// paths agree on which statuses count (never sufficient alone).
#[must_use]
pub const fn is_coroborating_status(status: u16) -> bool {
    matches!(status, 403 | 406 | 429 | 503 | 520 | 521 | 522 | 523 | 524)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn corroborating_status_helper_matches_table() {
        for status in [403, 406, 429, 503, 520, 521, 522, 523, 524] {
            assert!(is_coroborating_status(status), "{status}");
        }
        for status in [200, 201, 301, 400, 404, 500] {
            assert!(!is_coroborating_status(status), "{status}");
        }
    }
}
