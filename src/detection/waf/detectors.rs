//! Response detectors: Cloudflare managed challenge and generic WAF/CDN
//! fingerprints from status + headers + body.

use super::registry::{
    BODY_SCAN_LEN, CORROBORATING_STATUS, HEADER_VALUE_KEEP, bot_body_signals,
    challenge_body_signals, generic_body_signals, push_hit, set_vendor,
};
use super::{WafSignals, WafVendor};

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
    // Security-significant header signal (vs pure infrastructure presence).
    // Only this flag corroborates a status into `blocking`: `x-amzn-*`,
    // `via: varnish`, `server: awselb/varnish` are emitted on *all* traffic
    // of those platforms (plain ALB, cache) with no WAF implication, so they
    // fingerprint the vendor but must never turn a bare app 403 into a WAF
    // block (which would wrongly auto-tamper + downgrade confidence by 0.3).
    // Vendor fingerprinting (`vendor`) is unaffected — presence still shows.
    let mut corroborating_header_hit = false;

    for (name, value) in headers {
        let value_lower = value.to_ascii_lowercase();
        match name.as_str() {
            "cf-ray" => {
                has_ray = true;
                push_hit(&mut hits, "cf-ray");
                corroborating_header_hit = true;
            }
            "server" if value_lower.contains("cloudflare") => {
                has_server_cf = true;
                push_hit(&mut hits, "server:cloudflare");
                corroborating_header_hit = true;
            }
            "set-cookie" => {
                if value_lower.contains("__cf_bm") {
                    has_cf_cookie = true;
                    push_hit(&mut hits, "set-cookie:__cf_bm");
                    corroborating_header_hit = true;
                }
                if value_lower.contains("cf_clearance") {
                    // Clearance cookie = a challenge was solved/traversed.
                    has_cf_cookie = true;
                    has_mitigated = true;
                    push_hit(&mut hits, "set-cookie:cf_clearance");
                    corroborating_header_hit = true;
                }
                // Imperva/Incapsula cookies (`incap_ses_*`, `visid_incap`).
                if value_lower.contains("incap_") || value_lower.contains("visid_incap") {
                    push_hit(&mut hits, "set-cookie:incapsula");
                    set_vendor(&mut vendor, WafVendor::Imperva);
                    corroborating_header_hit = true;
                }
                // F5 BIG-IP persistence cookie.
                if value_lower.contains("bigipserver") || value_lower.contains("bigip") {
                    push_hit(&mut hits, "set-cookie:bigipserver");
                    set_vendor(&mut vendor, WafVendor::F5);
                    corroborating_header_hit = true;
                }
                // P0-4 bot-mitigation cookies (security products: corroborate).
                // DataDome sets `datadome=<device-check>` on every checked
                // request; Kasada's sensor drops `__kps`/`kpsdk`; HUMAN
                // (PerimeterX) drops `_px3` / `_pxvid`.
                if value_lower.contains("datadome") {
                    push_hit(&mut hits, "set-cookie:datadome");
                    set_vendor(&mut vendor, WafVendor::DataDome);
                    corroborating_header_hit = true;
                }
                if value_lower.contains("__kps") || value_lower.contains("kpsdk") {
                    push_hit(&mut hits, "set-cookie:kasada");
                    set_vendor(&mut vendor, WafVendor::Kasada);
                    corroborating_header_hit = true;
                }
                if value_lower.contains("_px3") || value_lower.contains("_pxvid") {
                    push_hit(&mut hits, "set-cookie:perimeterx");
                    set_vendor(&mut vendor, WafVendor::Human);
                    corroborating_header_hit = true;
                }
            }
            "cf-mitigated" => {
                has_mitigated = true;
                push_hit(&mut hits, "cf-mitigated");
                corroborating_header_hit = true;
            }
            "cf-cache-status" | "cf-request-id" => {
                has_cache_status = true;
                push_hit(&mut hits, name.as_str());
                corroborating_header_hit = true;
            }
            "x-iinfo" => {
                push_hit(&mut hits, "x-iinfo");
                set_vendor(&mut vendor, WafVendor::Imperva);
                corroborating_header_hit = true;
            }
            "x-mod-security" => {
                push_hit(&mut hits, "x-mod-security");
                set_vendor(&mut vendor, WafVendor::ModSecurity);
                corroborating_header_hit = true;
            }
            // Pure infrastructure IDs (every ALB/API-GW response carries
            // them, WAF or not): fingerprint only, never corroborate.
            // Attributed to `AwsAlb`, never `AwsWaf` (ALB ≠ WAF).
            "x-amzn-requestid" | "x-amzn-trace-id" | "x-amz-cf-id" => {
                push_hit(&mut hits, name.as_str());
                set_vendor(&mut vendor, WafVendor::AwsAlb);
            }
            // `via: varnish` is a bare cache, not Fastly (Fastly derives
            // from Varnish but a bare `via` proves no Fastly): fingerprint
            // only.
            "via" if value_lower.contains("varnish") => {
                push_hit(&mut hits, "via:varnish");
                set_vendor(&mut vendor, WafVendor::Varnish);
            }
            _ => {
                // Prefix / value based vendor headers (names already lowercased).
                if name.starts_with("x-akamai-") {
                    push_hit(&mut hits, name.as_str());
                    set_vendor(&mut vendor, WafVendor::Akamai);
                    corroborating_header_hit = true;
                } else if name.starts_with("x-sucuri-") {
                    push_hit(&mut hits, name.as_str());
                    set_vendor(&mut vendor, WafVendor::Sucuri);
                    corroborating_header_hit = true;
                } else if name.starts_with("x-fastly-") || name.starts_with("fastly-") {
                    push_hit(&mut hits, name.as_str());
                    set_vendor(&mut vendor, WafVendor::Fastly);
                    corroborating_header_hit = true;
                } else if name.starts_with("x-f5-") {
                    push_hit(&mut hits, name.as_str());
                    set_vendor(&mut vendor, WafVendor::F5);
                    corroborating_header_hit = true;
                } else if name.starts_with("x-px-") {
                    // HUMAN (PerimeterX) risk headers (`x-px-block`, …).
                    push_hit(&mut hits, name.as_str());
                    set_vendor(&mut vendor, WafVendor::Human);
                    corroborating_header_hit = true;
                } else if name == "server" {
                    if value_lower.contains("akamaighost") || value_lower.contains("akamai") {
                        push_hit(&mut hits, "server:akamaighost");
                        set_vendor(&mut vendor, WafVendor::Akamai);
                        corroborating_header_hit = true;
                    }
                    if value_lower.contains("incapsula") {
                        push_hit(&mut hits, "server:incapsula");
                        set_vendor(&mut vendor, WafVendor::Imperva);
                        corroborating_header_hit = true;
                    }
                    if value_lower.contains("mod_security") || value_lower.contains("modsecurity") {
                        push_hit(&mut hits, "server:modsecurity");
                        set_vendor(&mut vendor, WafVendor::ModSecurity);
                        corroborating_header_hit = true;
                    }
                    if value_lower.contains("big-ip") || value_lower.contains("bigip") {
                        push_hit(&mut hits, "server:bigip");
                        set_vendor(&mut vendor, WafVendor::F5);
                        corroborating_header_hit = true;
                    }
                    // Plain load-balancer banner (every ALB answers this,
                    // WAF or not): fingerprint only, never corroborate.
                    // Attributed to `AwsAlb`, never `AwsWaf` (ALB ≠ WAF).
                    if value_lower.contains("awselb") {
                        push_hit(&mut hits, "server:awselb");
                        set_vendor(&mut vendor, WafVendor::AwsAlb);
                    }
                    if value_lower.contains("sucuri") {
                        push_hit(&mut hits, "server:sucuri");
                        set_vendor(&mut vendor, WafVendor::Sucuri);
                        corroborating_header_hit = true;
                    }
                    // Bare cache banner vs Fastly product banner (split:
                    // `Varnish` is a generic reverse-proxy, `Fastly` only
                    // on explicit `fastly`): fingerprint only, never
                    // corroborate.
                    if value_lower.contains("varnish") {
                        push_hit(&mut hits, "server:varnish");
                        set_vendor(&mut vendor, WafVendor::Varnish);
                    }
                    if value_lower.contains("fastly") {
                        push_hit(&mut hits, "server:fastly");
                        set_vendor(&mut vendor, WafVendor::Fastly);
                    }
                } else {
                    // Value-based fallbacks for CDN headers without a fixed name
                    // (only signal names are recorded, never values).
                    if value_lower.contains("incapsula") {
                        push_hit(&mut hits, "header:incapsula");
                        set_vendor(&mut vendor, WafVendor::Imperva);
                        corroborating_header_hit = true;
                    }
                    if value_lower.contains("sucuri") {
                        push_hit(&mut hits, "header:sucuri");
                        set_vendor(&mut vendor, WafVendor::Sucuri);
                        corroborating_header_hit = true;
                    }
                    if value_lower.contains("fastly") {
                        push_hit(&mut hits, "header:fastly");
                        set_vendor(&mut vendor, WafVendor::Fastly);
                        corroborating_header_hit = true;
                    }
                }
            }
        }
    }

    let cf_headers = has_ray || has_server_cf || has_cf_cookie;
    if cf_headers || has_cache_status {
        set_vendor(&mut vendor, WafVendor::Cloudflare);
    }
    // Security-significant header signals corroborate a status into a
    // blocking verdict — pure infrastructure presence (`x-amzn-*`,
    // `via: varnish`, `server: awselb/varnish`) fingerprints the vendor
    // but never blocks alone. Never the status alone.
    let header_hit = corroborating_header_hit;

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
    let (bot_hits, bot_weak, bot_strong, bot_vendor) = bot_body_signals(&lower);
    for hit in &bot_hits {
        push_hit(&mut hits, hit);
    }
    if let Some(v) = bot_vendor {
        set_vendor(&mut vendor, v);
    }
    let body_hits = weak_count + generic_weak + bot_weak;
    if strong_hit || generic_strong || bot_strong {
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
    // Turnstile (P0-4): Cloudflare's interactive challenge. Same
    // co-occurrence contract as `captcha` — the bare word alone also names
    // the legit widget embedded on clean pages, so `cloudflare` must appear
    // in the same body (challenge pages always brand it).
    if lower.contains("turnstile") && lower.contains("cloudflare") {
        push_hit(&mut hits, "body:turnstile+cloudflare");
        blocking = true;
        set_vendor(&mut vendor, WafVendor::Turnstile);
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
