use regex::Regex;
use std::sync::OnceLock;

/// Volatile JSON string fields normalized to `""` (per-response randomness,
/// CSRF tokens). Exact `"field"` match only, so real data is untouched
/// (`"my_request_id"` or `"trace_id_suffix"` never match). Besides the classic
/// CSRF fields this covers Rails' `authenticity_token` and the
/// OTEL/microservice correlation fields (`trace_id`/`traceId`/`requestId`/
/// `correlation_id`), plus Angular/Laravel `xsrf_token`/`x-xsrf-token`: all
/// rotate per request exactly like `request_id`.
const VOLATILE_JSON_STRING_FIELDS: &[&str] = &[
    "request_id",
    "requestId",
    "trace_id",
    "traceId",
    "correlation_id",
    "csrf_token",
    "csrftoken",
    "csrfmiddlewaretoken",
    "xsrf_token",
    "x-xsrf-token",
    "authenticity_token",
    "_token",
    "nonce",
];
/// Volatile JSON numeric fields normalized to `0` (epoch floats, timestamps).
const VOLATILE_JSON_NUMERIC_FIELDS: &[&str] = &["generated_at", "timestamp"];
/// `<input …>` markers: any occurrence (case-insensitive) inside the tag means
/// the tag carries per-response state, so its `value` is blanked.
const CSRF_TAG_MARKERS: [&[u8]; 3] = [b"csrf", b"token", b"nonce"];
/// `<meta …>` markers: matching any (case-insensitive, attribute order
/// irrelevant) marks the tag as a CSRF meta, so its `content` is blanked.
const CSRF_META_MARKERS: [&[u8]; 3] = [b"csrf-token", b"csrf_token", b"xsrf-token"];
/// Every JSON JWT header encodes `{"` as `eyJ`, giving a cheap `contains`
/// prefilter for [`jwt_re`].
const JWT_PREFIX: &str = "eyJ";
/// Fixed stand-in for any JWT found: rotating access/refresh tokens compare
/// equal without any secret material surviving in the normalized text.
const JWT_PLACEHOLDER: &str = "[REDACTED-JWT]";

/// Bench anti-noise: `bench/app.py::noisy()` injects a random `request_id`
/// (8 hex chars) + `generated_at` (epoch float) into every JSON envelope so
/// naive string-compare diffing breaks. Normalize volatile fields to fixed
/// placeholders before any similarity so two identical pages with different
/// noise compare ~1.0. Handles pretty-printed (`"request_id": "abc",`) and
/// compact (`"request_id":"abc"`) shapes; unknown fields are untouched.
/// On top of the JSON fields, CSRF-shaped `<input>`/`<meta>` values are
/// blanked (only when the tag or the value looks like a credential — see
/// `scrub_input_tag`/`scrub_meta_tag`) and JWTs are folded to
/// `JWT_PLACEHOLDER`. Free-form hex/digit runs are deliberately *not*
/// touched: masking them would hide real data, so every rule stays scoped to
/// a named volatile region. Bodies without any marker are returned unchanged
/// (cheap path); the probes below are single `memchr`-backed scans so several
/// MiB of body stay cheap to compare.
#[must_use]
pub fn normalize_response_for_diff(body: &str) -> String {
    let has_json_noise = VOLATILE_JSON_STRING_FIELDS
        .iter()
        .chain(VOLATILE_JSON_NUMERIC_FIELDS.iter())
        .any(|f| body.contains(f));
    let has_jwt = body.contains(JWT_PREFIX);
    let has_html_tags = body.contains('<') && has_html_tag_marker(body);
    if !has_json_noise && !has_jwt && !has_html_tags {
        return body.to_owned();
    }
    let mut out = body.to_owned();
    if has_json_noise {
        for field in VOLATILE_JSON_STRING_FIELDS {
            out = normalize_json_field(&out, field, "\"\"");
        }
        for field in VOLATILE_JSON_NUMERIC_FIELDS {
            out = normalize_json_field(&out, field, "0");
        }
    }
    if has_html_tags {
        apply_tag_rewrites(&mut out, input_tag_re(), scrub_input_tag);
        apply_tag_rewrites(&mut out, meta_tag_re(), scrub_meta_tag);
    }
    if has_jwt && let Some(re) = jwt_re() {
        out = re.replace_all(&out, JWT_PLACEHOLDER).into_owned();
    }
    out
}

/// True when the body opens a `<input …>` or `<meta …>` tag
/// (ASCII-case-insensitive). Linear scan, called only after a `'<'` memchr hit
/// on the caller side, so tag-free bodies never pay for the regex engine.
fn has_html_tag_marker(body: &str) -> bool {
    let bytes = body.as_bytes();
    let mut from = 0;
    while let Some(offset) = bytes[from..].iter().position(|&b| b == b'<') {
        let start = from + offset;
        let rest = &bytes[start..];
        if starts_with_ignore_case(rest, b"<input") || starts_with_ignore_case(rest, b"<meta") {
            return true;
        }
        from = start + 1;
    }
    false
}

/// `<input …>` open tags, case-insensitive, bounded by the next `>`: per-tag
/// work stays proportional to the tag, never to the body.
fn input_tag_re() -> Option<&'static Regex> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?is)<input\b[^>]*>").ok())
        .as_ref()
}

/// `<meta …>` open tags, same bounds as [`input_tag_re`].
fn meta_tag_re() -> Option<&'static Regex> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?is)<meta\b[^>]*>").ok())
        .as_ref()
}

/// Base64url JWT: three dot-separated segments with the `eyJ` header prefix
/// (the `{8,}` repetitions are linear-time under the `regex` automata — no
/// backtracking risk; the character class excludes `.` so segments cannot
/// overlap).
fn jwt_re() -> Option<&'static Regex> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}").ok()
    })
    .as_ref()
}

/// Rewrite every [`Regex`] match through `rewrite` in place. `.into_owned()`
/// copies only when the prefilter saw a marker without a real tag match.
fn apply_tag_rewrites(out: &mut String, re: Option<&Regex>, rewrite: fn(&str) -> String) {
    let Some(re) = re else {
        return;
    };
    let replaced = re
        .replace_all(out, |caps: &regex::Captures<'_>| {
            rewrite(caps.get(0).map_or("", |m| m.as_str()))
        })
        .into_owned();
    *out = replaced;
}

/// Clear the `value` of one `<input …>` tag when the tag is CSRF-shaped
/// (`csrf`/`token`/`nonce` anywhere, case-insensitive — covers
/// `name="csrf_token"`, `name="authenticity_token"`, `name="nonce"`) or when
/// the value itself is a credible rotating token ([`is_credible_token`]).
/// Anything else keeps its exact bytes.
fn scrub_input_tag(tag: &str) -> String {
    let bytes = tag.as_bytes();
    let csrf_shaped = CSRF_TAG_MARKERS
        .iter()
        .any(|needle| contains_ignore_case(bytes, needle));
    rewrite_attr_values(tag, "value", csrf_shaped)
}

/// Clear the `content` of `<meta …>` tags carrying a CSRF marker
/// ([`CSRF_META_MARKERS`]). Matching the marker anywhere in the tag keeps
/// attribute order and quoting irrelevant; other metas are untouched.
fn scrub_meta_tag(tag: &str) -> String {
    let bytes = tag.as_bytes();
    let csrf_shaped = CSRF_META_MARKERS
        .iter()
        .any(|needle| contains_ignore_case(bytes, needle));
    if !csrf_shaped {
        return tag.to_owned();
    }
    rewrite_attr_values(tag, "content", true)
}

/// Blank quoted values of `attr="…"`/`attr='…'` in one tag. With
/// `clear_all = false` only values that look like credentials are blanked.
/// The attribute name must start the tag or follow whitespace/`/`, so
/// `data-value`, `myvalue` or free text never match.
fn rewrite_attr_values(tag: &str, attr: &str, clear_all: bool) -> String {
    let bytes = tag.as_bytes();
    let name = attr.as_bytes();
    let mut spans: Vec<(usize, usize)> = Vec::new();
    let mut i = 0;
    while i + name.len() <= bytes.len() {
        let boundary = i == 0 || matches!(bytes[i - 1], b' ' | b'\t' | b'\n' | b'\r' | b'/');
        if boundary
            && bytes[i..i + name.len()].eq_ignore_ascii_case(name)
            // `=` or whitespace must follow, so `values` cannot match `value`.
            && bytes
                .get(i + name.len())
                .is_some_and(|b| b.is_ascii_whitespace() || *b == b'=')
            && let Some((start, end)) = quoted_value_span(bytes, i + name.len(), clear_all)
        {
            spans.push((start, end));
            i = end;
            continue;
        }
        i += 1;
    }
    if spans.is_empty() {
        return tag.to_owned();
    }
    splice_out(tag, &spans)
}

/// Byte span of a quoted `attr`'s value (between the quotes) when it should be
/// blanked: the value must be `"`/`'`-quoted, and either `clear_all` is set or
/// the value is a credible token.
fn quoted_value_span(bytes: &[u8], mut at: usize, clear_all: bool) -> Option<(usize, usize)> {
    while bytes.get(at).is_some_and(u8::is_ascii_whitespace) {
        at += 1;
    }
    if bytes.get(at) != Some(&b'=') {
        return None;
    }
    at += 1;
    while bytes.get(at).is_some_and(u8::is_ascii_whitespace) {
        at += 1;
    }
    let quote = *bytes.get(at)?;
    if quote != b'"' && quote != b'\'' {
        return None;
    }
    let value_start = at + 1;
    let value_end = value_start + bytes.get(value_start..)?.iter().position(|&b| b == quote)?;
    if clear_all || is_credible_token(&bytes[value_start..value_end]) {
        Some((value_start, value_end))
    } else {
        None
    }
}

/// Heuristic for "per-response credential, not user data": at least 20 chars
/// of `[A-Za-z0-9_\-+/=]` spanning two or more character classes
/// (lower/upper/digit/symbol). Bare digit runs, single-case words and short
/// ids never qualify, so ordinary text is never masked.
fn is_credible_token(value: &[u8]) -> bool {
    if value.len() < 20 {
        return false;
    }
    let (mut lower, mut upper, mut digit, mut symbol) = (false, false, false, false);
    for &b in value {
        match b {
            b'a'..=b'z' => lower = true,
            b'A'..=b'Z' => upper = true,
            b'0'..=b'9' => digit = true,
            b'_' | b'-' | b'+' | b'/' | b'=' => symbol = true,
            _ => return false,
        }
    }
    usize::from(lower) + usize::from(upper) + usize::from(digit) + usize::from(symbol) >= 2
}

/// Rebuild `s` with every span removed. Spans are non-overlapping and start at
/// ASCII quote positions, so all slicing stays on char boundaries.
fn splice_out(s: &str, spans: &[(usize, usize)]) -> String {
    let mut out = String::with_capacity(s.len());
    let mut cursor = 0;
    for &(start, end) in spans {
        out.push_str(&s[cursor..start]);
        cursor = end;
    }
    out.push_str(&s[cursor..]);
    out
}

#[inline]
fn starts_with_ignore_case(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.len() >= needle.len() && haystack[..needle.len()].eq_ignore_ascii_case(needle)
}

#[inline]
fn contains_ignore_case(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if haystack.len() < needle.len() {
        return false;
    }
    (0..=haystack.len() - needle.len()).any(|i| {
        haystack[i].eq_ignore_ascii_case(&needle[0])
            && haystack[i..i + needle.len()].eq_ignore_ascii_case(needle)
    })
}

/// Replace the value of one `"field": <value>` JSON member with `placeholder`,
/// preserving keys, separators and structure. String values (`"..."`) and
/// bare numbers/literals (`123.4`, `null`) are both handled; anything else
/// leaves the body intact so detection never scores a mangled page.
fn normalize_json_field(body: &str, field: &str, placeholder: &str) -> String {
    let needle = format!("\"{field}\"");
    let mut out = String::with_capacity(body.len());
    let mut rest = body;
    while let Some(start) = rest.find(needle.as_str()) {
        let after_key = &rest[start + needle.len()..];
        let Some(colon_off) = after_key.find(':') else {
            out.push_str(rest);
            return out;
        };
        // Byte offset of the value start inside `after_key`.
        let mut value_off = colon_off + 1;
        let bytes = after_key.as_bytes();
        while value_off < bytes.len() && bytes[value_off].is_ascii_whitespace() {
            value_off += 1;
        }
        if value_off >= bytes.len() {
            out.push_str(rest);
            return out;
        }
        // End offset (exclusive) of the value inside `after_key`.
        let mut value_end = None;
        if bytes[value_off] == b'"' {
            let mut i = value_off + 1;
            while i < bytes.len() {
                if bytes[i] == b'\\' {
                    i = i.saturating_add(2);
                } else if bytes[i] == b'"' {
                    value_end = Some(i + 1);
                    break;
                } else {
                    i += 1;
                }
            }
        } else {
            let mut i = value_off;
            while i < bytes.len()
                && (bytes[i].is_ascii_alphanumeric() || matches!(bytes[i], b'.' | b'+' | b'-'))
            {
                i += 1;
            }
            if i > value_off {
                value_end = Some(i);
            }
        }
        let Some(value_end) = value_end else {
            out.push_str(rest);
            return out;
        };
        out.push_str(&rest[..start]);
        out.push_str(needle.as_str());
        out.push_str(": ");
        out.push_str(placeholder);
        rest = &after_key[value_end..];
    }
    out.push_str(rest);
    out
}
