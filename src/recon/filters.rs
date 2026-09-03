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
}
