#![deny(unsafe_code)]

//! Shared reflection guards for injection detectors.
//!
//! A page reflecting the injected value back (search results, preview, debug
//! output) must never be mistaken for execution proof. These helpers are
//! shared by the STACKED and UNION detectors so both apply the same veto to
//! raw, percent-encoded, form-encoded (`+`) and HTML-escaped echoes.

/// `true` when the response merely echoes our input instead of executing it:
/// the raw, percent-decoded (`%27`), form-decoded (`+` as space) or
/// HTML-entity-decoded body contains the exact string we sent. A marker only
/// proves execution when it appears *without* its surrounding payload syntax
/// (search-results pages reflecting `?q=` input are the classic false
/// positive).
#[must_use]
pub fn is_payload_echo(body: &str, sent_payload: &str) -> bool {
    if sent_payload.is_empty() {
        return false;
    }
    if body.contains(sent_payload) {
        return true;
    }
    // Encoded reflections: the page may echo the URL-encoded, `+`-spaced or
    // HTML-escaped form of our input instead of the raw payload.
    if percent_decode(body, false).contains(sent_payload) {
        return true;
    }
    if percent_decode(body, true).contains(sent_payload) {
        return true;
    }
    if html_decode_entities(body).contains(sent_payload) {
        return true;
    }
    // Server-side normalization echo: our encoded payload, decoded once,
    // appears verbatim in the response.
    let decoded_sent = percent_decode(sent_payload, true);
    if decoded_sent != sent_payload && body.contains(&decoded_sent) {
        return true;
    }
    false
}

/// Remove from `body` every form of `sent_payload` a reflecting page may
/// contain: verbatim, percent-decoded/encoded (`%27`, `+` or `%20` spaces)
/// and HTML-decoded/escaped (`&#39;`, `&quot;`, …) variants. Defense in depth
/// on top of [`is_payload_echo`]: an echoed payload is removed before the
/// marker/diff checks so it cannot contribute to marker presence or the diff
/// signal. Empty `sent_payload` is the identity; never panics.
#[must_use]
pub fn strip_payload(body: &str, sent_payload: &str) -> String {
    if sent_payload.is_empty() {
        return body.to_owned();
    }
    let mut stripped = body.to_owned();
    for variant in payload_variants(sent_payload) {
        stripped = stripped.replace(&variant, "");
    }
    stripped
}

/// All plausible wire forms of `sent_payload`, longest first so a longer
/// encoded variant is removed before one of its substrings. Empty variants
/// (a fully decoded payload degenerating to nothing) are dropped.
fn payload_variants(sent_payload: &str) -> Vec<String> {
    let mut variants = vec![
        sent_payload.to_owned(),
        percent_decode(sent_payload, false),
        percent_decode(sent_payload, true),
        html_decode_entities(sent_payload),
        percent_encode(sent_payload, false),
        percent_encode(sent_payload, true),
        html_encode_entities(sent_payload),
    ];
    variants.sort_by_key(|variant| core::cmp::Reverse(variant.len()));
    variants.dedup();
    variants.retain(|variant| !variant.is_empty());
    variants
}

/// Percent-encode in the common URL/query-string form: ASCII alphanumerics
/// and the unreserved `*-._` set pass through, spaces become `+` when
/// `plus_for_space` and `%20` otherwise, every other byte becomes uppercase
/// `%XX`. Never panics.
fn percent_encode(input: &str, plus_for_space: bool) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'*' | b'-' | b'.' | b'_' => {
                out.push(char::from(byte));
            }
            b' ' if plus_for_space => out.push('+'),
            _ => {
                out.push('%');
                out.push(hex_digit(byte >> 4));
                out.push(hex_digit(byte & 0x0f));
            }
        }
    }
    out
}

/// Uppercase hexadecimal digit for a 4-bit nibble.
fn hex_digit(nibble: u8) -> char {
    char::from(match nibble {
        0..=9 => b'0' + nibble,
        _ => b'A' + (nibble - 10),
    })
}

/// Minimal HTML-entity encoder mirroring [`html_decode_entities`] (encode set
/// identical to its decode set): `&` first to avoid double-encoding, `'` as
/// the numeric `&#39;` form emitted by common escaping helpers.
fn html_encode_entities(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Minimal percent-decoder (`%XX` → byte). With `plus_as_space`, `+` decodes
/// to a space (query-string echo form). Invalid sequences are kept verbatim;
/// invalid UTF-8 becomes `U+FFFD` via lossy conversion. Never panics.
fn percent_decode(input: &str, plus_as_space: bool) -> String {
    let bytes = input.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let byte = bytes[i];
        if byte == b'%'
            && i + 3 <= bytes.len()
            && let Ok(hex) = core::str::from_utf8(&bytes[i + 1..i + 3])
            && let Ok(decoded) = u8::from_str_radix(hex, 16)
        {
            out.push(decoded);
            i += 3;
            continue;
        }
        if plus_as_space && byte == b'+' {
            out.push(b' ');
        } else {
            out.push(byte);
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Minimal HTML-entity decoder (same set as `matcher::strip_html` plus
/// `&#39;`/`&apos;`), `&amp;` last to avoid double-decoding `&amp;lt;`.
fn html_decode_entities(input: &str) -> String {
    input
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#x27;", "'")
        .replace("&#X27;", "'")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_raw_percent_form_and_html_echoes() {
        let payload = "'; SELECT 'u1234abcd' -- -";
        assert!(is_payload_echo(&format!("results: {payload}"), payload));
        // Query-string echo: `+` spaces, `%27`/`%3B` sequences.
        assert!(is_payload_echo(
            "results: %27%3B+SELECT+%27u1234abcd%27+--+-",
            payload
        ));
        // RFC 3986 style: `%20` spaces.
        assert!(is_payload_echo(
            "results: %27%3B%20SELECT%20%27u1234abcd%27%20--%20-",
            payload
        ));
        // HTML-escaped echo.
        assert!(is_payload_echo(
            "results: &#39;; SELECT &#39;u1234abcd&#39; -- -",
            payload
        ));
        assert!(is_payload_echo("ref &quot;x&lt;y&gt;", "x<y>"));
        // Server-side normalization: the encoded payload comes back decoded.
        assert!(is_payload_echo(
            "results: '; SELECT 'x' -- -",
            "%27%3B%20SELECT%20%27x%27%20--%20-"
        ));
    }

    #[test]
    fn empty_payload_is_never_an_echo() {
        assert!(!is_payload_echo("anything", ""));
        assert!(!is_payload_echo("", ""));
    }

    #[test]
    fn non_echo_is_not_rejected() {
        assert!(!is_payload_echo(
            "welcome normal page id=1",
            "'; SELECT 1 -- -"
        ));
    }

    #[test]
    fn strip_payload_removes_every_encoded_variant() {
        let payload = "'; SELECT 'u1234abcd' -- -";
        let raw = format!("before {payload} after");
        assert_eq!(strip_payload(&raw, payload), "before  after");
        let form = "before %27%3B+SELECT+%27u1234abcd%27+--+- after";
        assert_eq!(strip_payload(form, payload), "before  after");
        let rfc = "before %27%3B%20SELECT%20%27u1234abcd%27%20--%20- after";
        assert_eq!(strip_payload(rfc, payload), "before  after");
        let html = "before &#39;; SELECT &#39;u1234abcd&#39; -- - after";
        assert_eq!(strip_payload(html, payload), "before  after");
    }

    #[test]
    fn strip_payload_is_identity_for_empty_payload() {
        assert_eq!(strip_payload("unchanged body", ""), "unchanged body");
        assert_eq!(strip_payload("", "'; SELECT 1 -- -"), "");
    }

    #[test]
    fn strip_payload_leaves_genuine_output_intact() {
        // The marker alone (real UNION output) never matches a payload variant.
        let payload = "'; UNION SELECT 1,2,'u1234abcd'-- -";
        let genuine = "welcome page u1234abcd success";
        assert_eq!(strip_payload(genuine, payload), genuine);
    }

    #[test]
    fn percent_helpers_never_panic_on_invalid_input() {
        assert_eq!(percent_decode("100%", false), "100%");
        assert_eq!(percent_decode("a%2", false), "a%2");
        assert_eq!(percent_decode("a%zz", false), "a%zz");
        assert_eq!(percent_decode("%27+x", true), "' x");
        assert_eq!(percent_decode("%27+x", false), "'+x");
        // Lone surrogate/high bytes become lossy replacement characters.
        assert_eq!(percent_decode("%FF", false), "\u{FFFD}");
    }

    #[test]
    fn percent_encode_roundtrips_typical_payloads() {
        let payload = "'; SELECT 'u1234abcd' -- -";
        let encoded = percent_encode(payload, true);
        assert_eq!(percent_decode(&encoded, true), payload);
        let encoded_rfc = percent_encode(payload, false);
        assert_eq!(percent_decode(&encoded_rfc, false), payload);
    }
}
