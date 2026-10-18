//! Response Content-Type mismatch signal (P0-4): an API payload answered
//! by an HTML challenge/deny page.

/// Response `Content-Type` category for CT-mismatch detection. Returns
/// `None` for missing/unparsable values (no verdict without a signal).
fn ct_category(content_type: &str) -> Option<&'static str> {
    let mime = content_type.split(';').next()?.trim().to_ascii_lowercase();
    if mime.is_empty() || !mime.contains('/') {
        return None;
    }
    if mime.contains("json") || mime.ends_with("+json") {
        Some("json")
    } else if mime.contains("xml") || mime.ends_with("+xml") {
        Some("xml")
    } else if mime.contains("html") {
        Some("html")
    } else if mime.starts_with("text/") {
        Some("text")
    } else {
        // Binary/octet-stream/images/…: apps legitimately vary these, and
        // bot challenges are HTML — never a mismatch signal.
        None
    }
}

/// Request/response Content-Type mismatch (P0-4): the caller sent an API
/// payload (`expected_ct`, e.g. `application/json` from `--raw-file`) but
/// the response is a different document kind (typically `text/html` — a
/// challenge/deny page intercepted the call).
///
/// Only runs when the *expected* kind is `json`/`xml` (API targets, the
/// P0-2 GraphQL/REST case): form/HTML targets legitimately receive varied
/// types, so anything else yields `None`. Returns the hit name
/// (`ct-mismatch:expected-json-got-html`) or `None` when kinds agree, the
/// response kind is binary/missing, or the expectation is not an API kind.
/// Never panics; header lookup is case-insensitive on already-lowercased
/// names.
#[must_use]
pub fn ct_mismatch_hit(expected_ct: &str, headers: &[(String, String)]) -> Option<String> {
    let expected = ct_category(expected_ct)?;
    if expected != "json" && expected != "xml" {
        return None;
    }
    let response_ct = headers
        .iter()
        .find(|(name, _)| name == "content-type")
        .map(|(_, value)| value.as_str())?;
    let response = ct_category(response_ct)?;
    if response == expected {
        return None;
    }
    Some(format!("ct-mismatch:expected-{expected}-got-{response}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detection::waf::tests::headers;

    #[test]
    fn ct_mismatch_flags_json_api_served_html() {
        let html = headers(&[("content-type", "text/html; charset=utf-8")]);
        let hit = ct_mismatch_hit("application/json", &html);
        assert_eq!(
            hit.as_deref(),
            Some("ct-mismatch:expected-json-got-html"),
            "{hit:?}"
        );
        // Agreement: no signal.
        let json = headers(&[("content-type", "application/json")]);
        assert_eq!(ct_mismatch_hit("application/json", &json), None);
        // Vendor suffix / parameters ignored.
        let json_ct = headers(&[("content-type", "application/problem+json; charset=utf-8")]);
        assert_eq!(ct_mismatch_hit("application/json", &json_ct), None);
        // Non-API expectations never flag (form targets vary legitimately).
        assert_eq!(ct_mismatch_hit("text/html", &html), None);
        assert_eq!(ct_mismatch_hit("", &html), None);
        // Missing / binary response CT: no verdict.
        assert_eq!(ct_mismatch_hit("application/json", &headers(&[])), None);
        let bin = headers(&[("content-type", "application/octet-stream")]);
        assert_eq!(ct_mismatch_hit("application/json", &bin), None);
        // XML APIs covered too.
        let xml_hit = ct_mismatch_hit("application/xml", &html);
        assert_eq!(
            xml_hit.as_deref(),
            Some("ct-mismatch:expected-xml-got-html"),
            "{xml_hit:?}"
        );
    }
}
