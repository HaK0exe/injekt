use super::*;

#[test]
fn scope_is_boundary_aware() {
    let root = Url::parse("https://example.com/").unwrap();
    assert!(is_in_scope(
        &root,
        &Url::parse("https://api.example.com/x").unwrap(),
        true
    ));
    assert!(!is_in_scope(
        &root,
        &Url::parse("https://notexample.com/x").unwrap(),
        true
    ));
}

#[test]
fn template_key_collapses_id_segments_and_sorts_query_names() {
    let a = Url::parse("https://example.com/product/1?id=5&sort=asc").unwrap();
    let b = Url::parse("https://example.com/product/2?sort=desc&id=9").unwrap();
    assert_eq!(page_template_key(&a), page_template_key(&b));
}

#[test]
fn template_key_distinguishes_different_paths() {
    let product = Url::parse("https://example.com/product/1?id=5").unwrap();
    let category = Url::parse("https://example.com/category/1?id=5").unwrap();
    assert_ne!(page_template_key(&product), page_template_key(&category));
}

#[test]
fn template_key_leaves_plain_navigation_untouched() {
    let about = Url::parse("https://example.com/about").unwrap();
    let contact = Url::parse("https://example.com/contact").unwrap();
    assert_ne!(page_template_key(&about), page_template_key(&contact));
    // Same URL visited twice still collapses to itself (still visitable once).
    assert_eq!(page_template_key(&about), page_template_key(&about));
}

#[test]
fn static_asset_detects_listed_extensions_case_insensitive() {
    use crate::recon::parameter::CandidateMethod;
    let css = Url::parse("https://example.com/wp-content/post-123.css?ver=3.8.0").unwrap();
    assert!(is_static_asset(&css));
    assert!(should_skip_candidate(&css, "ver", CandidateMethod::Get));
    let js = Url::parse("https://example.com/app.JS?v=1").unwrap();
    assert!(is_static_asset(&js));
    let svg = Url::parse("https://example.com/logo.svg?_=1699999").unwrap();
    assert!(is_static_asset(&svg));
    // Business routes are never static.
    for clean in [
        "https://example.com/?p=123",
        "https://example.com/?s=hello",
        "https://example.com/api/search?q=x",
        "https://example.com/load.php?ver=3.8",
    ] {
        let url = Url::parse(clean).unwrap();
        assert!(!is_static_asset(&url), "{clean}");
        assert!(
            !should_skip_candidate(&url, "ver", CandidateMethod::Get),
            "{clean}"
        );
    }
}

#[test]
fn skip_candidate_requires_both_conditions() {
    use crate::recon::parameter::CandidateMethod;
    // Static ext + business param → preserved.
    let api_js = Url::parse("https://example.com/api.js?id=7").unwrap();
    assert!(is_static_asset(&api_js));
    assert!(!should_skip_candidate(&api_js, "id", CandidateMethod::Get));
    // POST forms always preserved, even on static-looking paths.
    let css = Url::parse("https://example.com/style.css?ver=1").unwrap();
    assert!(!should_skip_candidate(&css, "ver", CandidateMethod::Post));
    // Never-filter paths exempt.
    let wp = Url::parse("https://example.com/wp-json/wp/v2/posts?ver=1").unwrap();
    assert!(!is_static_asset(&wp));
    assert!(!should_skip_candidate(&wp, "ver", CandidateMethod::Get));
    assert!(!should_skip_crawl_url(&wp));
    let secure = Url::parse("https://example.com/secure/login?ver=1").unwrap();
    assert!(!should_skip_candidate(&secure, "ver", CandidateMethod::Get));
}

#[test]
fn cache_busting_names_are_case_insensitive() {
    for name in ["VER", "V", "Version", "_", "CACHE", "Cb"] {
        assert!(is_cache_busting_param(name), "{name}");
    }
    for name in ["id", "s", "p", "page", "q", "amember_redirect_url", "debug"] {
        assert!(!is_cache_busting_param(name), "{name}");
    }
}

#[test]
fn skip_crawl_url_drops_cache_busted_assets_only() {
    let busted = Url::parse("https://example.com/style.css?ver=3.8.0").unwrap();
    assert!(should_skip_crawl_url(&busted));
    let bare = Url::parse("https://example.com/style.css").unwrap();
    assert!(should_skip_crawl_url(&bare));
    let mixed = Url::parse("https://example.com/app.min.js?ver=1&debug=true").unwrap();
    assert!(
        !should_skip_crawl_url(&mixed),
        "business param debug=true keeps the fetch"
    );
    let page = Url::parse("https://example.com/?p=123").unwrap();
    assert!(!should_skip_crawl_url(&page));
}

#[test]
fn internal_paths_are_always_skipped() {
    use crate::recon::parameter::CandidateMethod;
    for raw in [
        "https://example.com/cdn-cgi/content?id=abc",
        "https://example.com/cdn-cgi/challenge-platform/h/b?id=1",
        "https://example.com/_next/static/chunks/app.js?id=1",
    ] {
        let url = Url::parse(raw).unwrap();
        assert!(is_internal_crawl_path(&url), "{raw}");
        assert!(
            should_skip_candidate(&url, "id", CandidateMethod::Get),
            "{raw}"
        );
        assert!(should_skip_crawl_url(&url), "{raw}");
    }
    let page = Url::parse("https://example.com/bg/agent?category=all").unwrap();
    assert!(!is_internal_crawl_path(&page));
    assert!(!should_skip_crawl_url(&page));
}

#[test]
fn templated_tokens_are_skipped() {
    use crate::recon::parameter::CandidateMethod;
    assert!(is_templated_token("{search_term_string}"));
    // Raw `%7B` is only caught after `Url` percent-decoding (see below):
    // the token helper itself is a literal brace check.
    assert!(!is_templated_token("%7Bsearch_term_string%7D"));
    // `%7B...%7D` percent-decodes via `query_pairs`, so the encoded form
    // is caught at the crawl-URL level too.
    let encoded = Url::parse("https://example.com/bg/agent?q=%7Bsearch_term_string%7D").unwrap();
    assert!(should_skip_crawl_url(&encoded));
    let raw = Url::parse("https://example.com/bg/agent?q={search_term_string}").unwrap();
    assert!(should_skip_crawl_url(&raw));
    // `should_skip_candidate` is name-only by design (value filtering
    // lives in `add_link_candidates` where the value is available): a
    // clean name with a templated value is kept here but dropped upstream.
    assert!(!should_skip_candidate(&raw, "q", CandidateMethod::Get));
    // Templated *names* are dropped at the candidate level.
    let raw_name = Url::parse("https://example.com/bg/agent?%7Bq%7D=x").unwrap();
    assert!(should_skip_candidate(
        &raw_name,
        "{q}",
        CandidateMethod::Get
    ));
    // Real values still pass.
    let clean = Url::parse("https://example.com/bg/agent?category=all").unwrap();
    assert!(!should_skip_crawl_url(&clean));
    assert!(!should_skip_candidate(
        &clean,
        "category",
        CandidateMethod::Get
    ));
}

#[test]
fn tracking_params_are_skipped_on_get_only() {
    use crate::recon::parameter::CandidateMethod;
    for name in [
        "utm_source",
        "utm_medium",
        "utm_campaign",
        "UTM_TERM",
        "callback",
        "_",
    ] {
        let url = Url::parse(&format!("https://example.com/page?{name}=x")).unwrap();
        assert!(
            should_skip_candidate(&url, name, CandidateMethod::Get),
            "{name}"
        );
        // POST form fields are always preserved.
        assert!(
            !should_skip_candidate(&url, name, CandidateMethod::Post),
            "{name} POST"
        );
    }
    // Business params still pass.
    let clean = Url::parse("https://example.com/page?id=1").unwrap();
    assert!(!should_skip_candidate(&clean, "id", CandidateMethod::Get));
}

#[test]
fn image_geometry_skipped_on_static_assets_only() {
    use crate::recon::parameter::CandidateMethod;
    let rendition = Url::parse("https://example.com/img/thumb-1600x1062.jpeg?w=800").unwrap();
    assert!(should_skip_candidate(&rendition, "w", CandidateMethod::Get));
    let api = Url::parse("https://example.com/api/list?w=800").unwrap();
    assert!(!should_skip_candidate(&api, "w", CandidateMethod::Get));
}

#[test]
fn placeholder_values_detected() {
    assert!(is_placeholder_value("{search_term_string}"));
    assert!(is_placeholder_value("{}"));
    assert!(is_placeholder_value("{model}\\\\\\"));
    // Pure JS artefact: only backslashes.
    assert!(is_placeholder_value("\\"));
    // Genuinely empty values stay testable.
    assert!(!is_placeholder_value(""));
    // Real values pass, even with a trailing backslash artefact stripped.
    assert!(!is_placeholder_value("HK_EN\\"));
    assert!(!is_placeholder_value("instaview"));
    assert!(!is_placeholder_value("8"));
}

#[test]
fn candidate_template_key_collapses_instances() {
    let a = Url::parse("https://example.com/product/1?id=5").unwrap();
    let b = Url::parse("https://example.com/product/2?id=9").unwrap();
    assert_eq!(
        candidate_template_key(&a, "id"),
        candidate_template_key(&b, "id")
    );
    // Different param names are different sinks.
    assert_ne!(
        candidate_template_key(&a, "id"),
        candidate_template_key(&a, "q")
    );
    // Different routes are different sinks; param case is folded.
    let other = Url::parse("https://example.com/category/1?id=5").unwrap();
    assert_ne!(
        candidate_template_key(&a, "id"),
        candidate_template_key(&other, "id")
    );
    assert_eq!(
        candidate_template_key(&a, "ID"),
        candidate_template_key(&a, "id")
    );
}
