#![deny(unsafe_code)]

//! WAF / CDN fingerprinting from response headers + body.
//!
//! The legacy gate ([`crate::detection::baseline::Baseline::is_waf_blocked`])
//! only sees repeated `403`/`406`. Cloudflare usually answers `200` with a
//! managed challenge (`Just a moment`, `cf-ray`, `__cf_bm`) — invisible to a
//! status-only check, yet it silently filters long extraction payloads (the
//! noxtools pentest: detection `mysql_xpath 0.9` but every `extract=true`
//! oracle timed out / `inference inconsistency at pos 0`).
//!
//! Matching is plain case-insensitive `contains`, no regex: the marker set is
//! fixed and small, and a single `to_ascii_lowercase` over a truncated prefix
//! keeps the cost negligible. Header *values* are only ever inspected via
//! `contains` on a caller-truncated prefix (≤128 chars) and only signal
//! *names* are logged — never cookie/session contents (see OPSEC note on
//! [`detect_cloudflare_flat`]).

/// Truncated body prefix inspected for challenge markers.
const BODY_SCAN_LEN: usize = 32 * 1024;
/// Caller-side header value truncation (OPSEC: bounds secret retention).
pub const HEADER_VALUE_KEEP: usize = 128;

/// HTTP statuses corroborating a WAF block when combined with a marker.
/// `520-524` are Cloudflare origin-error codes; `429`/`503` cover
/// rate-limit/ban. Never sufficient alone.
const CORROBORATING_STATUS: &[u16] = &[403, 406, 429, 503, 520, 521, 522, 523, 524];

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
    ("awselb", false, WafVendor::AwsWaf),
];

/// WAF/CDN vendor behind the response, when identifiable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum WafVendor {
    Cloudflare,
    Akamai,
    Imperva,
    ModSecurity,
    F5,
    AwsWaf,
    Sucuri,
    Fastly,
    Generic,
}

impl core::fmt::Display for WafVendor {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Cloudflare => write!(f, "cloudflare"),
            Self::Akamai => write!(f, "akamai"),
            Self::Imperva => write!(f, "imperva"),
            Self::ModSecurity => write!(f, "modsecurity"),
            Self::F5 => write!(f, "f5"),
            Self::AwsWaf => write!(f, "aws-waf"),
            Self::Sucuri => write!(f, "sucuri"),
            Self::Fastly => write!(f, "fastly"),
            Self::Generic => write!(f, "generic"),
        }
    }
}

/// Fingerprinting outcome for one response (or an aggregated baseline).
///
/// Two tiers: `vendor.is_some()` means presence (CDN headers observed —
/// informational), `blocking` means an active challenge/deny/rate-limit was
/// observed and findings should be doubted (see [`downgrade_for_waf`]).
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct WafSignals {
    pub vendor: Option<WafVendor>,
    pub hits: Vec<String>,
    pub blocking: bool,
}

impl WafSignals {
    #[must_use]
    pub const fn is_suspected(&self) -> bool {
        self.vendor.is_some()
    }

    /// Short evidence fragment, e.g. `" waf=cloudflare:cf-ray,body:just a
    /// moment blocking=true"`, or `""` when nothing was detected. Only
    /// signal *names* are included — never header values or body excerpts.
    #[must_use]
    pub fn evidence_suffix(&self) -> String {
        let Some(vendor) = self.vendor else {
            return String::new();
        };
        format!(
            " waf={}:{} blocking={}",
            vendor,
            self.hits.join(","),
            self.blocking
        )
    }
}

/// Lower `confidence` by a fixed step when a blocking WAF was observed.
/// `0.9 → 0.6`: the finding stays visible but can no longer auto-qualify for
/// heavy extraction on its own. Never raises, never goes below `0.0`.
#[must_use]
pub fn downgrade_for_waf(confidence: f64) -> f64 {
    (confidence - 0.3).clamp(0.0, 1.0)
}

/// Detect Cloudflare/WAF signals from a status + `http::HeaderMap` + body.
///
/// Header values are truncated to [`HEADER_VALUE_KEEP`] chars before matching
/// (bounds retention of `Set-Cookie` tokens in RAM).
#[must_use]
pub fn detect_cloudflare(status: u16, headers: &http::HeaderMap, body: &[u8]) -> WafSignals {
    let flat: Vec<(String, String)> = headers
        .iter()
        .filter_map(|(name, value)| {
            value.to_str().ok().map(|raw| {
                let mut kept = raw.to_owned();
                if kept.len() > HEADER_VALUE_KEEP {
                    kept.truncate(HEADER_VALUE_KEEP);
                }
                (name.as_str().to_ascii_lowercase(), kept)
            })
        })
        .collect();
    detect_cloudflare_flat(status, &flat, body)
}

/// Detect Cloudflare/WAF signals from a status + pre-flattened
/// `(lowercased-name, value-prefix)` headers + body.
///
/// OPSEC: callers must pass at most a short value prefix (see
/// [`HEADER_VALUE_KEEP`]) — detection only needs `contains` on markers such
/// as `__cf_bm`, and full cookie values must not be retained.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn detect_cloudflare_flat(
    status: u16,
    headers: &[(String, String)],
    body: &[u8],
) -> WafSignals {
    let mut hits: Vec<String> = Vec::new();
    let mut vendor: Option<WafVendor> = None;
    let mut blocking = false;

    let mut has_ray = false;
    let mut has_server_cf = false;
    let mut has_cf_cookie = false;
    let mut has_mitigated = false;
    let mut has_cache_status = false;

    for (name, value) in headers {
        let value_lower = value.to_ascii_lowercase();
        match name.as_str() {
            "cf-ray" => {
                has_ray = true;
                push_hit(&mut hits, "cf-ray");
            }
            "server" if value_lower.contains("cloudflare") => {
                has_server_cf = true;
                push_hit(&mut hits, "server:cloudflare");
            }
            "set-cookie" => {
                if value_lower.contains("__cf_bm") {
                    has_cf_cookie = true;
                    push_hit(&mut hits, "set-cookie:__cf_bm");
                }
                if value_lower.contains("cf_clearance") {
                    // Clearance cookie = a challenge was solved/traversed.
                    has_cf_cookie = true;
                    has_mitigated = true;
                    push_hit(&mut hits, "set-cookie:cf_clearance");
                }
                // Imperva/Incapsula cookies (`incap_ses_*`, `visid_incap`).
                if value_lower.contains("incap_") || value_lower.contains("visid_incap") {
                    push_hit(&mut hits, "set-cookie:incapsula");
                    set_vendor(&mut vendor, WafVendor::Imperva);
                }
                // F5 BIG-IP persistence cookie.
                if value_lower.contains("bigipserver") || value_lower.contains("bigip") {
                    push_hit(&mut hits, "set-cookie:bigipserver");
                    set_vendor(&mut vendor, WafVendor::F5);
                }
            }
            "cf-mitigated" => {
                has_mitigated = true;
                push_hit(&mut hits, "cf-mitigated");
            }
            "cf-cache-status" | "cf-request-id" => {
                has_cache_status = true;
                push_hit(&mut hits, name.as_str());
            }
            "x-iinfo" => {
                push_hit(&mut hits, "x-iinfo");
                set_vendor(&mut vendor, WafVendor::Imperva);
            }
            "x-mod-security" => {
                push_hit(&mut hits, "x-mod-security");
                set_vendor(&mut vendor, WafVendor::ModSecurity);
            }
            "x-amzn-requestid" | "x-amzn-trace-id" | "x-amz-cf-id" => {
                push_hit(&mut hits, name.as_str());
                set_vendor(&mut vendor, WafVendor::AwsWaf);
            }
            "via" if value_lower.contains("varnish") => {
                push_hit(&mut hits, "via:varnish");
                set_vendor(&mut vendor, WafVendor::Fastly);
            }
            _ => {
                // Prefix / value based vendor headers (names already lowercased).
                if name.starts_with("x-akamai-") {
                    push_hit(&mut hits, name.as_str());
                    set_vendor(&mut vendor, WafVendor::Akamai);
                } else if name.starts_with("x-sucuri-") {
                    push_hit(&mut hits, name.as_str());
                    set_vendor(&mut vendor, WafVendor::Sucuri);
                } else if name.starts_with("x-fastly-") || name.starts_with("fastly-") {
                    push_hit(&mut hits, name.as_str());
                    set_vendor(&mut vendor, WafVendor::Fastly);
                } else if name.starts_with("x-f5-") {
                    push_hit(&mut hits, name.as_str());
                    set_vendor(&mut vendor, WafVendor::F5);
                } else if name == "server" {
                    if value_lower.contains("akamaighost") || value_lower.contains("akamai") {
                        push_hit(&mut hits, "server:akamaighost");
                        set_vendor(&mut vendor, WafVendor::Akamai);
                    }
                    if value_lower.contains("incapsula") {
                        push_hit(&mut hits, "server:incapsula");
                        set_vendor(&mut vendor, WafVendor::Imperva);
                    }
                    if value_lower.contains("mod_security") || value_lower.contains("modsecurity") {
                        push_hit(&mut hits, "server:modsecurity");
                        set_vendor(&mut vendor, WafVendor::ModSecurity);
                    }
                    if value_lower.contains("big-ip") || value_lower.contains("bigip") {
                        push_hit(&mut hits, "server:bigip");
                        set_vendor(&mut vendor, WafVendor::F5);
                    }
                    if value_lower.contains("awselb") {
                        push_hit(&mut hits, "server:awselb");
                        set_vendor(&mut vendor, WafVendor::AwsWaf);
                    }
                    if value_lower.contains("sucuri") {
                        push_hit(&mut hits, "server:sucuri");
                        set_vendor(&mut vendor, WafVendor::Sucuri);
                    }
                    if value_lower.contains("varnish") || value_lower.contains("fastly") {
                        push_hit(&mut hits, "server:varnish");
                        set_vendor(&mut vendor, WafVendor::Fastly);
                    }
                } else {
                    // Value-based fallbacks for CDN headers without a fixed name
                    // (only signal names are recorded, never values).
                    if value_lower.contains("incapsula") {
                        push_hit(&mut hits, "header:incapsula");
                        set_vendor(&mut vendor, WafVendor::Imperva);
                    }
                    if value_lower.contains("sucuri") {
                        push_hit(&mut hits, "header:sucuri");
                        set_vendor(&mut vendor, WafVendor::Sucuri);
                    }
                    if value_lower.contains("fastly") {
                        push_hit(&mut hits, "header:fastly");
                        set_vendor(&mut vendor, WafVendor::Fastly);
                    }
                }
            }
        }
    }

    let cf_headers = has_ray || has_server_cf || has_cf_cookie;
    if cf_headers || has_cache_status {
        set_vendor(&mut vendor, WafVendor::Cloudflare);
    }
    // Any header signal (Cloudflare or vendor-specific) counts for
    // status corroboration — never the status alone.
    let header_hit = !hits.is_empty();

    // Body markers — single lowercased pass over a truncated prefix.
    let prefix_len = body.len().min(BODY_SCAN_LEN);
    let text = String::from_utf8_lossy(&body[..prefix_len]);
    let lower = text.to_ascii_lowercase();
    let (marker_hits, weak_count, strong_hit, marker_cf) = challenge_body_signals(&lower);
    for hit in &marker_hits {
        push_hit(&mut hits, hit);
    }
    let (generic_hits, generic_weak, generic_strong, generic_vendor) = generic_body_signals(&lower);
    for hit in &generic_hits {
        push_hit(&mut hits, hit);
    }
    if let Some(v) = generic_vendor {
        set_vendor(&mut vendor, v);
    }
    let body_hits = weak_count + generic_weak;
    if strong_hit || generic_strong {
        blocking = true;
    }
    if marker_cf {
        set_vendor(&mut vendor, WafVendor::Cloudflare);
    }
    // `captcha` alone is too generic (any home-grown captcha); it only counts
    // co-occurring with a Cloudflare marker in the same body.
    if lower.contains("captcha") && lower.contains("cloudflare") {
        push_hit(&mut hits, "body:captcha+cloudflare");
        blocking = true;
        set_vendor(&mut vendor, WafVendor::Cloudflare);
    }
    // Generic (non-Cloudflare) rate limiting: corroborating status + generic
    // wording, without any Cloudflare marker.
    if vendor.is_none()
        && matches!(status, 429 | 503)
        && (lower.contains("rate limit") || lower.contains("too many requests"))
    {
        push_hit(&mut hits, "body:rate-limited");
        set_vendor(&mut vendor, WafVendor::Generic);
        blocking = true;
    }

    if has_mitigated {
        blocking = true;
    }
    // Challenge artifacts echoed without headers (stripped branding).
    if body_hits >= 2 {
        blocking = true;
    }
    // A corroborating status (429/503/520-524/…) only counts together with an
    // observed marker — never alone.
    if CORROBORATING_STATUS.contains(&status) && (!hits.is_empty()) {
        // `403/406` alone already feed the legacy `is_waf_blocked`; here they
        // corroborate header/body markers into a blocking verdict.
        if header_hit || body_hits > 0 {
            blocking = true;
        }
    }

    WafSignals {
        vendor,
        hits,
        blocking,
    }
}

fn push_hit(hits: &mut Vec<String>, hit: &str) {
    if !hits.iter().any(|h| h == hit) {
        hits.push(hit.to_owned());
    }
}

/// Prefer a specific vendor over `Generic`; first specific wins when several
/// fire (deterministic aggregation for `Baseline::new`).
fn set_vendor(current: &mut Option<WafVendor>, new: WafVendor) {
    match current {
        None => *current = Some(new),
        Some(WafVendor::Generic) if new != WafVendor::Generic => *current = Some(new),
        _ => {}
    }
}

/// Scan a lowercased body prefix for challenge markers. Returns the hit
/// names (`body:…`), the weak-hit count, whether a strong marker fired, and
/// whether any marker implicates Cloudflare.
fn challenge_body_signals(lower: &str) -> (Vec<String>, usize, bool, bool) {
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
fn generic_body_signals(lower: &str) -> (Vec<String>, usize, bool, Option<WafVendor>) {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn detects_cf_ray_header_even_on_200() {
        let r = detect_cloudflare_flat(
            200,
            &headers(&[("cf-ray", "abc123-IAD")]),
            b"<html>ok</html>",
        );
        assert!(r.is_suspected());
        assert_eq!(r.vendor, Some(WafVendor::Cloudflare));
        assert!(r.hits.contains(&"cf-ray".to_owned()));
    }

    #[test]
    fn ray_alone_is_presence_not_blocking() {
        let r = detect_cloudflare_flat(
            200,
            &headers(&[("cf-ray", "abc")]),
            b"<html>normal page</html>",
        );
        assert!(r.is_suspected());
        assert!(!r.blocking, "mere CDN presence must not downgrade: {r:?}");
    }

    #[test]
    fn detects_server_cloudflare_case_insensitive() {
        let r = detect_cloudflare_flat(
            200,
            &headers(&[("server", "CloudFlare")]),
            b"<html>ok</html>",
        );
        assert!(r.is_suspected());
    }

    #[test]
    fn detects_cf_bm_and_clearance_cookies() {
        let r = detect_cloudflare_flat(
            200,
            &headers(&[("set-cookie", "__cf_bm=abc123; path=/; HttpOnly")]),
            b"<html>ok</html>",
        );
        assert!(r.is_suspected());
        assert!(!r.blocking);
        let r2 = detect_cloudflare_flat(
            200,
            &headers(&[("set-cookie", "cf_clearance=xyz; path=/")]),
            b"<html>ok</html>",
        );
        assert!(
            r2.blocking,
            "clearance cookie proves a challenge ran: {r2:?}"
        );
    }

    #[test]
    fn detects_managed_challenge_body() {
        let body = b"<html><head><title>Just a moment...</title></head><body>managed challenge challenges.cloudflare.com</body></html>";
        let r = detect_cloudflare_flat(200, &headers(&[("cf-ray", "x")]), body);
        assert!(r.blocking, "{r:?}");
        assert!(r.hits.len() >= 2, "{r:?}");
    }

    #[test]
    fn detects_attention_required_1020() {
        let body = b"Attention Required! | Cloudflare Ray ID: abc Error code: 1020";
        let r = detect_cloudflare_flat(403, &headers(&[]), body);
        assert!(r.blocking, "{r:?}");
        assert_eq!(r.vendor, Some(WafVendor::Cloudflare));
    }

    #[test]
    fn captcha_alone_is_not_enough() {
        let r = detect_cloudflare_flat(200, &headers(&[]), b"please solve captcha to continue");
        assert!(!r.is_suspected(), "{r:?}");
    }

    #[test]
    fn captcha_plus_cloudflare_is_blocking() {
        let body = b"captcha verification cloudflare ray id abc";
        let r = detect_cloudflare_flat(403, &headers(&[]), body);
        assert!(r.blocking, "{r:?}");
    }

    #[test]
    fn ray_id_footer_alone_is_presence_not_blocking() {
        // Cloudflare prints a `Ray ID` footer on every clean proxied 200 —
        // it must fingerprint the vendor without raising `blocking` (which
        // would wrongly auto-tamper + downgrade confidence by 0.3).
        let body = b"<html>cart ok <!-- Cloudflare Ray ID: abc123 --></html>";
        let r = detect_cloudflare_flat(200, &headers(&[]), body);
        assert!(r.is_suspected(), "{r:?}");
        assert!(!r.blocking, "footer Ray ID must not block: {r:?}");
    }

    #[test]
    fn single_cloudflare_word_is_not_enough() {
        let r = detect_cloudflare_flat(
            200,
            &headers(&[]),
            b"we wrote a blog post about cloudflare yesterday",
        );
        assert!(
            !r.is_suspected(),
            "content word must not fingerprint: {r:?}"
        );
    }

    #[test]
    fn cf_cache_status_alone_is_non_blocking() {
        let r = detect_cloudflare_flat(
            200,
            &headers(&[("cf-cache-status", "HIT")]),
            b"<html>normal</html>",
        );
        assert!(r.is_suspected());
        assert!(!r.blocking);
    }

    #[test]
    fn rate_limit_1015_with_status_is_blocking() {
        let r = detect_cloudflare_flat(429, &headers(&[]), b"error 1015 rate limited");
        assert!(r.blocking, "{r:?}");
    }

    #[test]
    fn origin_errors_need_a_marker() {
        let with_marker = detect_cloudflare_flat(
            524,
            &headers(&[("cf-ray", "x")]),
            b"<html>origin timeout</html>",
        );
        assert!(with_marker.blocking, "{with_marker:?}");
        let bare = detect_cloudflare_flat(524, &headers(&[]), b"<html>origin timeout</html>");
        assert!(
            !bare.is_suspected(),
            "status alone never fingerprints: {bare:?}"
        );
    }

    #[test]
    fn generic_rate_limit_detected() {
        let r = detect_cloudflare_flat(
            429,
            &headers(&[]),
            b"too many requests, rate limit exceeded, try later",
        );
        assert_eq!(r.vendor, Some(WafVendor::Generic));
        assert!(r.blocking);
    }

    #[test]
    fn binary_body_never_panics() {
        let r = detect_cloudflare_flat(200, &headers(&[]), &[0xFF, 0x00, 0x3C, 0xFF, 0x41]);
        assert!(!r.is_suspected());
    }

    #[test]
    fn downgrade_steps_down_and_floors() {
        assert!((downgrade_for_waf(0.9) - 0.6).abs() < f64::EPSILON);
        assert!((downgrade_for_waf(0.75) - 0.45).abs() < f64::EPSILON);
        assert!((downgrade_for_waf(0.2) - 0.0).abs() < f64::EPSILON);
        assert!(downgrade_for_waf(1.5) <= 1.0);
    }

    #[test]
    fn evidence_suffix_format() {
        let r = detect_cloudflare_flat(200, &headers(&[("cf-ray", "x")]), b"ok");
        let suffix = r.evidence_suffix();
        assert!(suffix.starts_with(" waf=cloudflare:"), "{suffix}");
        assert!(suffix.contains("blocking=false"), "{suffix}");
        let clean = WafSignals::default();
        assert_eq!(clean.evidence_suffix(), "");
    }

    #[test]
    fn header_map_variant_matches_flat() {
        let mut map = http::HeaderMap::new();
        map.insert("cf-ray", http::HeaderValue::from_static("abc-IAD"));
        let a = detect_cloudflare(200, &map, b"<html>ok</html>");
        let b = detect_cloudflare_flat(200, &headers(&[("cf-ray", "abc-IAD")]), b"<html>ok</html>");
        assert_eq!(a.vendor, b.vendor);
        assert_eq!(a.hits, b.hits);
        assert_eq!(a.blocking, b.blocking);
    }

    #[test]
    fn vendor_display_labels() {
        assert_eq!(WafVendor::Cloudflare.to_string(), "cloudflare");
        assert_eq!(WafVendor::Akamai.to_string(), "akamai");
        assert_eq!(WafVendor::Imperva.to_string(), "imperva");
        assert_eq!(WafVendor::ModSecurity.to_string(), "modsecurity");
        assert_eq!(WafVendor::F5.to_string(), "f5");
        assert_eq!(WafVendor::AwsWaf.to_string(), "aws-waf");
        assert_eq!(WafVendor::Sucuri.to_string(), "sucuri");
        assert_eq!(WafVendor::Fastly.to_string(), "fastly");
        assert_eq!(WafVendor::Generic.to_string(), "generic");
    }

    #[test]
    fn detects_akamai_headers_presence_not_blocking() {
        let r = detect_cloudflare_flat(
            200,
            &headers(&[("server", "AkamaiGHost"), ("x-akamai-session-info", "x")]),
            b"<html>ok</html>",
        );
        assert_eq!(r.vendor, Some(WafVendor::Akamai));
        assert!(!r.blocking, "presence alone must not block: {r:?}");
    }

    #[test]
    fn detects_imperva_incapsula_headers_and_incident_body() {
        let r = detect_cloudflare_flat(
            200,
            &headers(&[
                ("x-iinfo", "1-1"),
                ("set-cookie", "incap_ses_123=abc; path=/"),
            ]),
            b"<html>ok</html>",
        );
        assert_eq!(r.vendor, Some(WafVendor::Imperva));
        assert!(!r.blocking, "{r:?}");
        let blocked = detect_cloudflare_flat(403, &headers(&[]), b"incapsula incident id 12345");
        assert_eq!(blocked.vendor, Some(WafVendor::Imperva));
        assert!(blocked.blocking, "incident id is strong: {blocked:?}");
    }

    #[test]
    fn detects_modsecurity_server_and_header() {
        let r = detect_cloudflare_flat(
            200,
            &headers(&[("server", "Apache/2 ModSecurity/CRS")]),
            b"<html>ok</html>",
        );
        assert_eq!(r.vendor, Some(WafVendor::ModSecurity));
        assert!(!r.blocking);
        let r2 = detect_cloudflare_flat(
            200,
            &headers(&[("x-mod-security", "activated")]),
            b"<html>ok</html>",
        );
        assert_eq!(r2.vendor, Some(WafVendor::ModSecurity));
    }

    #[test]
    fn detects_f5_bigip_cookie() {
        let r = detect_cloudflare_flat(
            200,
            &headers(&[("set-cookie", "BIGipServerpool=abc; path=/")]),
            b"<html>ok</html>",
        );
        assert_eq!(r.vendor, Some(WafVendor::F5));
        assert!(!r.blocking);
    }

    #[test]
    fn detects_aws_waf_request_id_plus_blocked_body() {
        let presence = detect_cloudflare_flat(
            200,
            &headers(&[("x-amzn-requestid", "abc")]),
            b"<html>ok</html>",
        );
        assert_eq!(presence.vendor, Some(WafVendor::AwsWaf));
        assert!(!presence.blocking);
        let blocked = detect_cloudflare_flat(
            403,
            &headers(&[("x-amzn-requestid", "abc")]),
            b"<html>Request blocked by AWS WAF</html>",
        );
        assert_eq!(blocked.vendor, Some(WafVendor::AwsWaf));
        assert!(blocked.blocking, "{blocked:?}");
    }

    #[test]
    fn detects_sucuri_and_fastly_headers() {
        let s =
            detect_cloudflare_flat(200, &headers(&[("x-sucuri-id", "123")]), b"<html>ok</html>");
        assert_eq!(s.vendor, Some(WafVendor::Sucuri));
        assert!(!s.blocking);
        let f = detect_cloudflare_flat(
            200,
            &headers(&[("x-fastly-request-id", "abc"), ("server", "Varnish")]),
            b"<html>ok</html>",
        );
        assert_eq!(f.vendor, Some(WafVendor::Fastly));
        assert!(!f.blocking);
    }

    #[test]
    fn generic_deny_markers_need_status_to_block() {
        let presence = detect_cloudflare_flat(200, &headers(&[]), b"access denied");
        assert_eq!(presence.vendor, Some(WafVendor::Generic));
        assert!(!presence.blocking, "{presence:?}");
        let blocked = detect_cloudflare_flat(403, &headers(&[]), b"access denied");
        assert!(blocked.blocking, "{blocked:?}");
        let awselb = detect_cloudflare_flat(
            403,
            &headers(&[("server", "awselb/2.0")]),
            b"<html>403 forbidden</html>",
        );
        assert_eq!(awselb.vendor, Some(WafVendor::AwsWaf));
        assert!(awselb.blocking, "{awselb:?}");
    }

    #[test]
    fn status_alone_never_fingerprints_new_vendors() {
        let bare = detect_cloudflare_flat(403, &headers(&[]), b"<html>not found</html>");
        assert!(!bare.is_suspected(), "{bare:?}");
    }
}
