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

/// `true` when a GET query candidate should be dropped: static asset URL +
/// cache-busting param name (e.g. `post-123.css?ver=3.8.0` Elementor noise).
/// POST form candidates and never-filter paths are always preserved.
#[must_use]
pub fn should_skip_candidate(
    url: &Url,
    param_name: &str,
    method: crate::recon::parameter::CandidateMethod,
) -> bool {
    if method == crate::recon::parameter::CandidateMethod::Post {
        return false;
    }
    if is_never_filter_path(url.path()) {
        return false;
    }
    is_static_asset(url) && is_cache_busting_param(param_name)
}

/// `true` when a crawl queue link should not be fetched at all: a static
/// asset carrying only cache-busting query params (or no query). A static
/// asset with a business param (`/api.js?id=7`) is still fetched so the
/// `id` candidate survives — only the `ver`-style params are dropped by
/// [`should_skip_candidate`].
#[must_use]
pub fn should_skip_crawl_url(url: &Url) -> bool {
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
}
