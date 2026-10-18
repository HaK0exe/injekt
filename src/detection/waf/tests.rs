//! Detector tests: `detect_cloudflare_flat` behaviour matrix (moved
//! verbatim from the pre-split `waf.rs`; `headers` is shared with
//! `ct.rs` tests).

use super::*;

pub(super) fn headers(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
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
fn detects_aws_alb_request_id_plus_blocked_body() {
    // Plain ALB infrastructure (`x-amzn-*` on every ALB/API-GW
    // response, WAF or not) fingerprints `AwsAlb` — never `AwsWaf`
    // (ALB ≠ WAF). `AwsWaf` stays reserved for explicit WAF signals.
    let presence = detect_cloudflare_flat(
        200,
        &headers(&[("x-amzn-requestid", "abc")]),
        b"<html>ok</html>",
    );
    assert_eq!(presence.vendor, Some(WafVendor::AwsAlb));
    assert!(!presence.blocking);
    let blocked = detect_cloudflare_flat(
        403,
        &headers(&[("x-amzn-requestid", "abc")]),
        b"<html>Request blocked by AWS WAF</html>",
    );
    assert_eq!(blocked.vendor, Some(WafVendor::AwsAlb));
    assert!(blocked.blocking, "{blocked:?}");
}

#[test]
fn detects_sucuri_and_fastly_headers() {
    let s = detect_cloudflare_flat(200, &headers(&[("x-sucuri-id", "123")]), b"<html>ok</html>");
    assert_eq!(s.vendor, Some(WafVendor::Sucuri));
    assert!(!s.blocking);
    let f = detect_cloudflare_flat(
        200,
        &headers(&[("x-fastly-request-id", "abc"), ("server", "Varnish")]),
        b"<html>ok</html>",
    );
    // `x-fastly-*` is an explicit Fastly product signal and wins over
    // the generic `server: Varnish` cache banner (first-specific-wins).
    assert_eq!(f.vendor, Some(WafVendor::Fastly));
    assert!(!f.blocking);
}

#[test]
fn bare_varnish_is_not_fastly() {
    // `Varnish` is a generic reverse-proxy/cache; Fastly derives from
    // it but a bare `via`/`server` banner proves no Fastly.
    let via = detect_cloudflare_flat(200, &headers(&[("via", "1.1 varnish")]), b"<html>ok</html>");
    assert_eq!(via.vendor, Some(WafVendor::Varnish));
    assert!(!via.blocking);
    let server =
        detect_cloudflare_flat(200, &headers(&[("server", "Varnish")]), b"<html>ok</html>");
    assert_eq!(server.vendor, Some(WafVendor::Varnish));
    assert!(!server.blocking);
    // Explicit Fastly product banner keeps its own label.
    let fastly = detect_cloudflare_flat(200, &headers(&[("server", "Fastly")]), b"<html>ok</html>");
    assert_eq!(fastly.vendor, Some(WafVendor::Fastly));
    assert!(!fastly.blocking);
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
    // Blocking here comes from the `403 forbidden` body marker + 403
    // status (body corroboration path), not from the infra banner —
    // and the label is `aws-alb`, never `aws-waf`.
    assert_eq!(awselb.vendor, Some(WafVendor::AwsAlb));
    assert!(awselb.blocking, "{awselb:?}");
}

#[test]
fn status_alone_never_fingerprints_new_vendors() {
    let bare = detect_cloudflare_flat(403, &headers(&[]), b"<html>not found</html>");
    assert!(!bare.is_suspected(), "{bare:?}");
}

#[test]
fn infra_headers_fingerprint_without_blocking_on_bare_status() {
    // Pure infrastructure headers (every ALB / Varnish response carries
    // them, WAF or not) must fingerprint the infra vendor but never turn a
    // bare app 403 into a WAF block — otherwise every ALB 403 would
    // wrongly auto-tamper + downgrade confidence by 0.3. Labels must be
    // infra (`aws-alb` / `varnish`), never `aws-waf` / `fastly`.
    for (hdrs, expected) in [
        (vec![("x-amzn-requestid", "abc")], WafVendor::AwsAlb),
        (vec![("x-amzn-trace-id", "abc")], WafVendor::AwsAlb),
        (vec![("x-amz-cf-id", "abc")], WafVendor::AwsAlb),
        (vec![("via", "1.1 varnish")], WafVendor::Varnish),
        (vec![("server", "awselb/2.0")], WafVendor::AwsAlb),
        (vec![("server", "Varnish")], WafVendor::Varnish),
    ] {
        let r = detect_cloudflare_flat(403, &headers(&hdrs), b"<html>not found</html>");
        assert!(r.is_suspected(), "infra must fingerprint: {r:?}");
        assert_eq!(r.vendor, Some(expected), "infra label: {r:?}");
        assert!(
            r.vendor != Some(WafVendor::AwsWaf) && r.vendor != Some(WafVendor::Fastly),
            "infra must never claim a WAF/CDN product: {r:?}"
        );
        assert!(!r.blocking, "infra + bare 403 must not block: {r:?}");
    }
    // With a deny body marker the same responses still block (body
    // corroboration path, unchanged).
    let with_body = detect_cloudflare_flat(
        403,
        &headers(&[("x-amzn-requestid", "abc")]),
        b"<html>access denied</html>",
    );
    assert!(with_body.blocking, "{with_body:?}");
    assert_eq!(with_body.vendor, Some(WafVendor::AwsAlb), "{with_body:?}");
}

#[test]
fn security_headers_still_corroborate_status() {
    // Product-security headers keep corroborating a status (no body
    // marker needed) — only pure-infra headers were demoted.
    let imperva = detect_cloudflare_flat(
        403,
        &headers(&[("x-iinfo", "1-1")]),
        b"<html>not found</html>",
    );
    assert!(imperva.blocking, "{imperva:?}");
    let akamai = detect_cloudflare_flat(
        403,
        &headers(&[("server", "AkamaiGHost")]),
        b"<html>not found</html>",
    );
    assert!(akamai.blocking, "{akamai:?}");
    // Cloudflare keeps its historical semantics (test-pinned).
    let cf = detect_cloudflare_flat(
        524,
        &headers(&[("cf-ray", "x")]),
        b"<html>origin timeout</html>",
    );
    assert!(cf.blocking, "{cf:?}");
}

#[test]
fn datadome_cookie_and_captcha_domain() {
    // `datadome` cookie = product presence, never a block alone.
    let presence = detect_cloudflare_flat(
        200,
        &headers(&[("set-cookie", "datadome=abc123; path=/; HttpOnly")]),
        b"<html>ok</html>",
    );
    assert_eq!(presence.vendor, Some(WafVendor::DataDome), "{presence:?}");
    assert!(!presence.blocking, "{presence:?}");
    // DataDome captcha domain in body = active challenge, strong.
    let blocked = detect_cloudflare_flat(
        200,
        &headers(&[]),
        b"<html><script src='https://geo.captcha-delivery.com/captcha.js'></script></html>",
    );
    assert_eq!(blocked.vendor, Some(WafVendor::DataDome), "{blocked:?}");
    assert!(blocked.blocking, "{blocked:?}");
    // Bare product word alone is weak: presence, no block.
    let word = detect_cloudflare_flat(200, &headers(&[]), b"we use datadome here");
    assert_eq!(word.vendor, Some(WafVendor::DataDome), "{word:?}");
    assert!(!word.blocking, "{word:?}");
}

#[test]
fn kasada_sensor_cookie_and_sdk() {
    let presence = detect_cloudflare_flat(
        200,
        &headers(&[("set-cookie", "__kps=abc; path=/")]),
        b"<html>ok</html>",
    );
    assert_eq!(presence.vendor, Some(WafVendor::Kasada), "{presence:?}");
    assert!(!presence.blocking, "{presence:?}");
    let blocked = detect_cloudflare_flat(
        200,
        &headers(&[]),
        b"<html><script>kpsdk.init()</script></html>",
    );
    assert_eq!(blocked.vendor, Some(WafVendor::Kasada), "{blocked:?}");
    assert!(blocked.blocking, "{blocked:?}");
}

#[test]
fn human_perimeterx_cookie_header_and_captcha() {
    let cookie = detect_cloudflare_flat(
        200,
        &headers(&[("set-cookie", "_px3=abc; path=/")]),
        b"<html>ok</html>",
    );
    assert_eq!(cookie.vendor, Some(WafVendor::Human), "{cookie:?}");
    assert!(!cookie.blocking, "{cookie:?}");
    let header = detect_cloudflare_flat(
        403,
        &headers(&[("x-px-block", "1")]),
        b"<html>not found</html>",
    );
    assert_eq!(header.vendor, Some(WafVendor::Human), "{header:?}");
    assert!(
        header.blocking,
        "security header corroborates status: {header:?}"
    );
    let captcha = detect_cloudflare_flat(
        200,
        &headers(&[]),
        b"<html><div id='px-captcha'>verify</div></html>",
    );
    assert_eq!(captcha.vendor, Some(WafVendor::Human), "{captcha:?}");
    assert!(captcha.blocking, "{captcha:?}");
}

#[test]
fn turnstile_needs_cloudflare_cooccurrence() {
    // Bare `turnstile` word (legit widget embed) = weak presence only.
    let widget = detect_cloudflare_flat(
        200,
        &headers(&[]),
        b"<html><div class='cf-turnstile-response'></div></html>",
    );
    assert_eq!(widget.vendor, Some(WafVendor::Turnstile), "{widget:?}");
    assert!(!widget.blocking, "widget embed must not block: {widget:?}");
    // Turnstile + Cloudflare branding = active challenge.
    let challenge = detect_cloudflare_flat(
        200,
        &headers(&[]),
        b"<html>verifying you are human turnstile cloudflare<script src='https://challenges.cloudflare.com/turnstile/v0/api.js'></script></html>",
    );
    assert!(challenge.blocking, "{challenge:?}");
}
