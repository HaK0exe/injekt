#![deny(unsafe_code)]

//! Request-level WAF evasion: HTTP Parameter Pollution (HPP) + chunked transfer.
//!
//! Unlike string [`crate::techniques::tamper::Tamper`]s (which rewrite the payload
//! itself), these operate on the HTTP request shape:
//! - **HPP**: duplicate the parameter (`?id=1&id=<PAYLOAD>`). Backends typically
//!   take the last (PHP/ASP) or first (some WAFs inspect only the first)
//!   occurrence, so a WAF seeing `id=1` lets the malicious duplicate through.
//! - **Chunked**: send Body injections with `Transfer-Encoding: chunked` (real
//!   chunk framing via streaming body) to bypass WAFs inspecting
//!   `Content-Length` bodies. Only meaningful for requests with a body
//!   (`ParameterLocation::Body`); no-op otherwise.

/// Build an HPP query URL: keep all original pairs, append `param_name=payload`
/// as a duplicate (never replaces the original value).
///
/// `?id=1` + payload `X` → `?id=1&id=X`.
#[must_use]
pub fn hpp_query_url(base: &url::Url, param_name: &str, payload: &str) -> String {
    let mut url = base.clone();
    let mut pairs: Vec<(String, String)> = url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    pairs.push((param_name.to_owned(), payload.to_owned()));
    url.query_pairs_mut().clear();
    for (k, v) in pairs {
        url.query_pairs_mut().append_pair(&k, &v);
    }
    url.to_string()
}

/// Build an HPP form body: keep all original fields, append `param_name=payload`
/// as a duplicate. `existing=None` yields a single-field body.
#[must_use]
pub fn hpp_body_str(existing: Option<&str>, param_name: &str, payload: &str) -> String {
    let mut pairs: Vec<(String, String)> = existing
        .map(|body| {
            url::form_urlencoded::parse(body.as_bytes())
                .map(|(k, v)| (k.into_owned(), v.into_owned()))
                .collect()
        })
        .unwrap_or_default();
    pairs.push((param_name.to_owned(), payload.to_owned()));
    url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs)
        .finish()
}

/// Whether the chunked framing applies: only when the caller opted in via
/// `--chunked` **and** the request actually carries a body.
#[must_use]
pub const fn should_apply_chunked(has_body: bool, chunked: bool) -> bool {
    has_body && chunked
}

/// Split a body into `chunk_size` byte pieces for streaming (pure helper so the
/// framing strategy is unit-testable without HTTP).
#[must_use]
pub fn chunk_body_pieces(body: &[u8], chunk_size: usize) -> Vec<bytes::Bytes> {
    let size = chunk_size.max(1);
    if body.is_empty() {
        return Vec::new();
    }
    body.chunks(size)
        .map(bytes::Bytes::copy_from_slice)
        .collect()
}

/// Count how many times `param_name` occurs in the query string of `url_str`.
/// Returns 0 on unparsable URLs (never panics — proptest-friendly).
#[must_use]
pub fn count_query_occurrences(url_str: &str, param_name: &str) -> usize {
    let Ok(parsed) = url::Url::parse(url_str) else {
        return 0;
    };
    parsed
        .query_pairs()
        .filter(|(k, _)| k == param_name)
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hpp_query_duplicates_param() {
        let base: url::Url = "http://ex/?id=1".parse().expect("url");
        let out = hpp_query_url(&base, "id", "PAYLOAD");
        assert_eq!(count_query_occurrences(&out, "id"), 2);
        assert!(out.contains("id=1"), "keeps original: {out}");
        // payload is percent-encoded by append_pair
        assert!(out.contains("id=PAYLOAD"), "appends duplicate: {out}");
    }

    #[test]
    fn hpp_query_missing_param_appends() {
        let base: url::Url = "http://ex/?a=b".parse().expect("url");
        let out = hpp_query_url(&base, "id", "1");
        assert_eq!(count_query_occurrences(&out, "id"), 1);
        assert!(out.contains("a=b"), "preserves others: {out}");
    }

    #[test]
    fn hpp_query_preserves_other_params_order() {
        let base: url::Url = "http://ex/?a=1&id=1&b=2".parse().expect("url");
        let out = hpp_query_url(&base, "id", "X");
        assert_eq!(count_query_occurrences(&out, "id"), 2);
        assert!(out.contains("a=1"), "{out}");
        assert!(out.contains("b=2"), "{out}");
    }

    #[test]
    fn hpp_body_duplicates_field() {
        let out = hpp_body_str(Some("id=1&x=2"), "id", "PAYLOAD");
        // form_urlencoded serializes duplicate keys twice
        assert_eq!(out.matches("id=").count(), 2, "got {out}");
        assert!(out.contains("x=2"), "got {out}");
    }

    #[test]
    fn hpp_body_none_single_field() {
        let out = hpp_body_str(None, "id", "1");
        assert_eq!(out, "id=1");
    }

    #[test]
    fn chunked_only_with_body() {
        assert!(should_apply_chunked(true, true));
        assert!(!should_apply_chunked(false, true));
        assert!(!should_apply_chunked(true, false));
        assert!(!should_apply_chunked(false, false));
    }

    #[test]
    fn chunk_pieces_split() {
        let pieces = chunk_body_pieces(b"abcdefgh", 5);
        assert_eq!(pieces.len(), 2);
        assert_eq!(&pieces[0][..], b"abcde");
        assert_eq!(&pieces[1][..], b"fgh");
        // reassembly is lossless
        let joined: Vec<u8> = pieces.iter().flat_map(|b| b.to_vec()).collect();
        assert_eq!(joined, b"abcdefgh");
    }

    #[test]
    fn chunk_pieces_empty() {
        assert!(chunk_body_pieces(b"", 5).is_empty());
    }

    #[test]
    fn chunk_size_zero_clamped() {
        let pieces = chunk_body_pieces(b"ab", 0);
        assert_eq!(pieces.len(), 2);
    }

    #[test]
    fn count_occurrences_bad_url() {
        assert_eq!(count_query_occurrences("not a url", "id"), 0);
    }
}
