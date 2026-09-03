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
}
