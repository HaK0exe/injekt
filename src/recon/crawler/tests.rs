use super::decode::decode_embedded_url;
use super::extract::extract_document;
use super::robots::RobotsRules;
use crate::recon::parameter::ParamType;
use crate::target::parameters::ParameterLocation;
use url::Url;

#[test]
fn extracts_links_and_forms() {
    let base = Url::parse("https://example.com/start").unwrap();
    let doc = extract_document(
        &base,
        r"<a href='/item?id=7'>x</a><form method='post' action='/login'><input name='user' value='a'><input type='hidden' name='csrf' value='x'></form>",
    );
    assert_eq!(doc.candidates.len(), 4);
    assert!(doc.candidates.iter().any(|c| c.param_name == "id"));
    assert!(
        doc.candidates
            .iter()
            .any(|c| { c.param_name == "user" && c.location == ParameterLocation::Body })
    );
    assert!(doc.candidates.iter().any(|c| {
        c.param_name == "csrf"
            && c.location == ParameterLocation::Body
            && c.param_type == ParamType::Hidden
    }));
}

#[test]
fn robots_prefers_longest_allow() {
    let rules = RobotsRules::parse("User-agent: *\nDisallow: /private\nAllow: /private/public\n");
    assert!(!rules.allows("/private/a"));
    assert!(rules.allows("/private/public/a"));
}

#[test]
fn decode_embedded_url_handles_html_and_json_escapes() {
    assert_eq!(
        decode_embedded_url("/api?a=1&amp;desc=x"),
        "/api?a=1&desc=x"
    );
    assert_eq!(decode_embedded_url(r"/api?a=1\u0026b=2"), "/api?a=1&b=2");
    // Single decode only: `&amp;lt;` -> `&lt;`, not `<`.
    assert_eq!(decode_embedded_url("/api?q=&amp;lt;"), "/api?q=&lt;");
    // Multibyte UTF-8 survives JS unescaping.
    assert_eq!(
        decode_embedded_url(r"/api?q=caf\u00e9-\u65e5\u672c\u8a9e"),
        "/api?q=caf\u{e9}-\u{65e5}\u{672c}\u{8a9e}"
    );
    // Lone `\u` without 4 hex digits is kept verbatim, no panic.
    assert_eq!(decode_embedded_url(r"/api?q=\u12"), "/api?q=\\u12");
}

#[test]
fn decode_embedded_url_resolves_double_escapes() {
    // Double-escaped separator: `&amp;amp;` must split into two params,
    // not one `amp;`-prefixed remnant.
    assert_eq!(decode_embedded_url("/api?a=1&amp;amp;b=2"), "/api?a=1&b=2");
    // Double-escaped JSON separator: source-level `\\u0026` collapses to
    // `\u0026` on pass 1 and to `&` on pass 2.
    assert_eq!(decode_embedded_url(r"/api?a=1\\u0026b=2"), "/api?a=1&b=2");
    // Trailing backslash from an escaped closing quote is a JS artefact.
    assert_eq!(
        decode_embedded_url(r"/api/path?locale=HK_EN\\"),
        "/api/path?locale=HK_EN"
    );
    // Single-decode pin preserved: `&amp;lt;` stops at `&lt;`.
    assert_eq!(decode_embedded_url("/api?q=&amp;lt;"), "/api?q=&lt;");
    // Idempotent on clean URLs.
    assert_eq!(decode_embedded_url("/api?a=1&b=2"), "/api?a=1&b=2");
}

#[test]
fn js_endpoint_regex_handles_escaped_quotes_and_backslashes() {
    let base = Url::parse("https://example.com/page").unwrap();
    // Escaped quote inside the value must not cut the match: both params
    // survive and no value keeps a trailing backslash.
    let doc = extract_document(&base, r#"var u="/api/x?title=a\'b&desc=c";"#);
    assert!(
        doc.candidates.iter().any(|c| c.param_name == "desc"),
        "desc must survive an escaped quote: {:?}",
        doc.candidates
            .iter()
            .map(|c| &c.param_name)
            .collect::<Vec<_>>()
    );
    assert!(
        !doc.candidates
            .iter()
            .any(|c| c.original_value.ends_with('\\')),
        "no trailing backslash artefact expected"
    );
    // Double-escaped separator inside JS splits into two params.
    let doc2 = extract_document(&base, r#"var u="/api/y?one=1&amp;amp;two=2";"#);
    assert!(doc2.candidates.iter().any(|c| c.param_name == "one"));
    assert!(doc2.candidates.iter().any(|c| c.param_name == "two"));
    assert!(
        !doc2
            .candidates
            .iter()
            .any(|c| c.param_name.contains("amp;")),
        "no amp; remnant expected"
    );
}
#[test]
fn js_embedded_endpoints_split_params_after_decode() {
    let base = Url::parse("https://example.com/page").unwrap();
    let doc = extract_document(&base, r#"var u="/api/dynamic-og?title=Hi&amp;desc=New";"#);
    assert!(
        doc.candidates.iter().any(|c| c.param_name == "desc"),
        "amp;desc must decode to desc: {:?}",
        doc.candidates
            .iter()
            .map(|c| &c.param_name)
            .collect::<Vec<_>>()
    );
    assert!(
        !doc.candidates.iter().any(|c| c.param_name.contains("amp;")),
        "no amp; remnant expected"
    );
    let doc2 = extract_document(&base, r#"var u="/api/x?cate=A\u0026desc=B";"#);
    assert!(doc2.candidates.iter().any(|c| c.param_name == "cate"));
    assert!(doc2.candidates.iter().any(|c| c.param_name == "desc"));
}

#[test]
fn templated_and_internal_js_endpoints_are_dropped() {
    let base = Url::parse("https://example.com/page").unwrap();
    let doc = extract_document(
        &base,
        r#"var a="/bg/agent?q=%7Bsearch_term_string%7D"; var b="/cdn-cgi/content?id=abc";"#,
    );
    assert!(
        doc.candidates.is_empty(),
        "placeholders + cdn-cgi must yield no candidates: {:?}",
        doc.candidates
            .iter()
            .map(|c| c.url.as_str().to_owned())
            .collect::<Vec<_>>()
    );
    assert_eq!(doc.links, [] as [Url; 0]);
}
