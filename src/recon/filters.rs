#![deny(unsafe_code)]

use url::Url;

#[must_use]
pub fn is_in_scope(root: &Url, candidate: &Url, include_subdomains: bool) -> bool {
    if !matches!(candidate.scheme(), "http" | "https") {
        return false;
    }
    let (Some(root_host), Some(candidate_host)) = (root.host_str(), candidate.host_str()) else {
        return false;
    };
    if root.port_or_known_default() != candidate.port_or_known_default() {
        return false;
    }
    candidate_host.eq_ignore_ascii_case(root_host)
        || (include_subdomains
            && candidate_host
                .to_ascii_lowercase()
                .ends_with(&format!(".{}", root_host.to_ascii_lowercase())))
}

#[must_use]
pub fn normalize_page_url(mut url: Url) -> Url {
    url.set_fragment(None);
    url
}

/// Signature of a page's "shape": path with id-like segments collapsed to a
/// placeholder, plus the sorted/deduplicated set of query parameter names
/// (never values). Two URLs sharing a signature are the same template with
/// different instance data (`/product/1?id=5` vs `/product/2?id=9`) — used to
/// cap how many instances of one template a crawl fetches, so pagination and
/// enumeration traps can't burn the whole page budget on redundant pages.
/// Deliberately conservative: only purely-numeric or long hex/uuid-like
/// segments are collapsed, so ordinary navigation (distinct words, slugs,
/// short path segments) is left untouched and still visited per-URL.
#[must_use]
pub fn page_template_key(url: &Url) -> String {
    let path = url
        .path_segments()
        .map(|segments| {
            segments
                .map(|segment| {
                    if is_id_like_segment(segment) {
                        "{id}"
                    } else {
                        segment
                    }
                })
                .collect::<Vec<_>>()
                .join("/")
        })
        .unwrap_or_default();
    let mut param_names: Vec<String> = url
        .query_pairs()
        .map(|(name, _)| name.into_owned())
        .collect();
    param_names.sort_unstable();
    param_names.dedup();
    format!("{path}?{}", param_names.join(","))
}

/// Static asset extensions — never SQLi-testable as parameters and never
/// worth a crawl fetch. Compared case-insensitively against the extension of
/// the last path segment (`Url::path()` excludes query/fragment already).
///
/// Deliberately conservative: `json` is NOT listed (P1 keeps `/data.json?ver=`
/// testable pending observed noise), and extension alone never drops a
/// candidate — see [`should_skip_candidate`].
pub const STATIC_ASSET_EXTENSIONS: &[&str] = &[
    "css", "js", "map", "png", "jpg", "jpeg", "gif", "svg", "ico", "webp", "avif", "bmp", "woff",
    "woff2", "ttf", "eot", "otf", "mp4", "webm", "mp3", "wav", "ogg",
];

/// Cache-busting parameter names — only filtered when combined with a static
/// asset URL (see [`should_skip_candidate`]). Order is load-bearing for tests:
/// keep alphabetical.
pub const CACHE_BUSTING_PARAMS: &[&str] = &["_", "cache", "cb", "v", "ver", "version"];

/// Tracking / cache-buster parameter names that are never `SQLi` sinks:
/// analytics tags, JSONP callbacks, client-side cache-busters, ad click IDs.
/// Unlike [`CACHE_BUSTING_PARAMS`] (static assets only), these are dropped on
/// any GET URL — `?utm_source=` / `?callback=jQuery...` / `?_=...` never reach
/// a SQL sink. Order is load-bearing for tests: keep alphabetical.
pub const TRACKING_PARAMS: &[&str] = &[
    "_",
    "callback",
    "dclid",
    "fbclid",
    "gclid",
    "msclkid",
    "utm_campaign",
    "utm_content",
    "utm_medium",
    "utm_source",
    "utm_term",
];

/// Image-geometry parameter names — only meaningful on static renditions
/// (`thumb.jpg?w=800`). Compared case-insensitively. Only filtered combined
/// with a static asset URL (see [`should_skip_candidate`]).
pub const IMAGE_GEOMETRY_PARAMS: &[&str] = &["h", "height", "mh", "mw", "w", "width"];

/// Paths that are never filtered, even with a static-looking suffix or a
/// cache-busting param: `WordPress` API, aMember auth flows, WP AJAX.
fn is_never_filter_path(path: &str) -> bool {
    path.starts_with("/wp-json/") || path == "/wp-json" || path.starts_with("/secure/")
}

/// `true` when the URL path ends with a known static asset extension.
/// Never-filter paths (`/wp-json/…`, `/secure/…`) are always `false`.
#[must_use]
pub fn is_static_asset(url: &Url) -> bool {
    if is_never_filter_path(url.path()) {
        return false;
    }
    let last_segment = url.path().rsplit('/').next().unwrap_or("");
    let Some(dot) = last_segment.rfind('.') else {
        return false;
    };
    let ext = &last_segment[dot + 1..];
    STATIC_ASSET_EXTENSIONS
        .iter()
        .any(|known| known.eq_ignore_ascii_case(ext))
}

/// `true` for cache-busting parameter names (`ver`, `v`, `version`, …),
/// matched case-insensitively.
#[must_use]
pub fn is_cache_busting_param(name: &str) -> bool {
    CACHE_BUSTING_PARAMS
        .iter()
        .any(|known| known.eq_ignore_ascii_case(name))
}

/// `true` for tracking / cache-buster names (`utm_*`, `callback`, `_`, ad
/// click IDs), matched case-insensitively. These never reach a SQL sink.
#[must_use]
pub fn is_tracking_param(name: &str) -> bool {
    TRACKING_PARAMS
        .iter()
        .any(|known| known.eq_ignore_ascii_case(name))
}

/// `true` for image-geometry names (`w`, `h`, `width`, …), matched
/// case-insensitively. Only meaningful combined with a static asset URL.
#[must_use]
pub fn is_image_geometry_param(name: &str) -> bool {
    IMAGE_GEOMETRY_PARAMS
        .iter()
        .any(|known| known.eq_ignore_ascii_case(name))
}

/// `true` for placeholder / non-testable parameter values: OpenSearch-style
/// `{...}` templates (raw or percent-decoded — `Url::query_pairs` decodes
/// `%7B...%7D`), or values that are only JS-string artefacts (empty after
/// trimming whitespace and trailing `\` left by an escaped closing quote).
/// A genuinely empty value (`?id=`) is kept: it is still injectable.
#[must_use]
pub fn is_placeholder_value(value: &str) -> bool {
    let stripped = value.trim().trim_matches('\\').trim();
    if stripped.is_empty() {
        return !value.is_empty();
    }
    is_templated_token(stripped)
}

/// Template signature of a candidate sink: lowercased host + path with
/// id-like segments collapsed + lowercased param name. Candidates sharing a
/// signature are the same sink shape with different instance data
/// (`/product/1?id=` vs `/product/2?id=`) — used to cap redundant instances
/// before they burn scan budget. Query *values* are deliberately excluded.
#[must_use]
pub fn candidate_template_key(url: &Url, param_name: &str) -> String {
    let host = url.host_str().unwrap_or_default().to_ascii_lowercase();
    let path = url
        .path_segments()
        .map(|segments| {
            segments
                .map(|segment| {
                    if is_id_like_segment(segment) {
                        "{id}"
                    } else {
                        segment
                    }
                })
                .collect::<Vec<_>>()
                .join("/")
        })
        .unwrap_or_default();
    format!("{host}|{path}|{}", param_name.to_ascii_lowercase())
}

/// `true` when a GET query candidate should be dropped: static asset URL +
/// cache-busting param name (e.g. `post-123.css?ver=3.8.0` Elementor noise).
/// POST form candidates and never-filter paths are always preserved.
/// Internal endpoints (`/cdn-cgi/`, `/_next/`) are never testable either.
#[must_use]
pub fn should_skip_candidate(
    url: &Url,
    param_name: &str,
    method: crate::recon::parameter::CandidateMethod,
) -> bool {
    if method == crate::recon::parameter::CandidateMethod::Post {
        return false;
    }
    if is_internal_crawl_path(url) {
        return true;
    }
    if is_never_filter_path(url.path()) {
        return false;
    }
    // OpenSearch-style placeholders (`q={search_term_string}`) are templates,
    // not injectable values. `query_pairs` already percent-decodes `%7B`.
    if is_templated_token(param_name) {
        return true;
    }
    // Analytics / JSONP / cache-buster names never reach a SQL sink.
    if is_tracking_param(param_name) {
        return true;
    }
    is_static_asset(url)
        && (is_cache_busting_param(param_name) || is_image_geometry_param(param_name))
}

/// `true` when a crawl queue link should not be fetched at all: a static
/// asset carrying only cache-busting query params (or no query). A static
/// asset with a business param (`/api.js?id=7`) is still fetched so the
/// `id` candidate survives — only the `ver`-style params are dropped by
/// [`should_skip_candidate`]. Internal endpoints and templated query values
/// (`?q={search_term_string}`) are never fetched either.
#[must_use]
pub fn should_skip_crawl_url(url: &Url) -> bool {
    if is_internal_crawl_path(url) {
        return true;
    }
    // Templated query values are OpenSearch placeholders, not real pages:
    // fetching `?q={search_term_string}` literally wastes budget and yields a
    // bogus candidate.
    if url
        .query_pairs()
        .any(|(name, value)| is_templated_token(&name) || is_templated_token(&value))
    {
        return true;
    }
    if is_never_filter_path(url.path()) {
        return false;
    }
    if !is_static_asset(url) {
        return false;
    }
    let mut pairs = url.query_pairs();
    let Some((first_name, _)) = pairs.next() else {
        return true;
    };
    if !is_cache_busting_param(&first_name) {
        return false;
    }
    pairs.all(|(name, _)| is_cache_busting_param(&name))
}

/// `true` for Cloudflare/internal build paths that are never SQLi-testable:
/// `/cdn-cgi/...` (challenge/content endpoints), `/_next/...` (Next.js build
/// artefacts). Checked before the never-filter exemptions so internals stay
/// filtered even if they carry a whitelisted prefix.
#[must_use]
pub fn is_internal_crawl_path(url: &Url) -> bool {
    let path = url.path();
    path == "/cdn-cgi"
        || path.starts_with("/cdn-cgi/")
        || path == "/_next"
        || path.starts_with("/_next/")
}

/// `true` for OpenSearch-style template tokens (`{search_term_string}`).
/// `Url::query_pairs` already percent-decodes `%7B...%7D`, so a brace check
/// covers both raw and encoded forms.
#[must_use]
pub fn is_templated_token(s: &str) -> bool {
    s.contains('{') || s.contains('}')
}

/// A path segment that looks like an instance identifier rather than a fixed
/// route word: purely numeric, or long enough (>= 8 chars) hex/uuid-like.
fn is_id_like_segment(segment: &str) -> bool {
    if segment.is_empty() {
        return false;
    }
    if segment.chars().all(|c| c.is_ascii_digit()) {
        return true;
    }
    segment.len() >= 8 && segment.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
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
        let encoded =
            Url::parse("https://example.com/bg/agent?q=%7Bsearch_term_string%7D").unwrap();
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
}
