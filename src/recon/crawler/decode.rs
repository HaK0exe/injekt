/// Decode URLs embedded in HTML/JS/JSON before `Url::join`.
///
/// JS-embedded endpoints frequently carry HTML-escaped (`&amp;`) or
/// JSON-escaped (`\u0026`) separators (Next.js `__NEXT_DATA__`, inline
/// `<script>`). Without decoding, `?title=a&amp;desc=b` parses as a single
/// `amp;desc` param and `?a=1\u0026b=2` as one garbled value — both yield
/// `1/1` single-param scans and wasted probes.
///
/// Order matters (same as `matcher::strip_html`): `\uXXXX` + `\/` first,
/// then `&lt;/&gt;/&quot;/&#x27;/&#39;`, `&amp;` last to avoid turning
/// `&amp;lt;` into `<`.
///
/// Double-escaping is common (HTML-escaped JSON inside HTML, JS string
/// literals built from already-escaped data), so both phases run to a
/// bounded fixed point (max 3 passes):
/// - JS escapes: `\\u0026` (source-level) collapses to `\u0026` on pass 1
///   and to `&` on pass 2. Trade-off: a literal backslash that is genuinely
///   part of a query value (vanishingly rare — WHATWG parsers treat `\` as
///   `/` on `http(s)` URLs anyway) may be over-decoded; structural
///   correctness of the extracted URL wins for a scanner.
/// - HTML entities run one full pass (pinning `&amp;lt;` to `&lt;`, never
///   `<`), then only `&amp;` is repeated: it is the query separator, so a
///   remnant corrupts param splitting (`amp;`-prefixed names), while other
///   entities only affect values.
///
/// A trailing `\` run left by an escaped closing quote (`"...en\\"`) is
/// stripped: it is a JS-string artefact, never a meaningful URL suffix.
#[must_use]
pub(super) fn decode_embedded_url(raw: &str) -> String {
    let mut current = raw.to_owned();
    for _ in 0..3 {
        let next = decode_js_string_escapes(&current);
        if next == current {
            break;
        }
        current = next;
    }
    let mut decoded = decode_html_entities_once(&current);
    for _ in 0..3 {
        if !decoded.contains("&amp;") {
            break;
        }
        let next = decoded.replace("&amp;", "&");
        if next == decoded {
            break;
        }
        decoded = next;
    }
    decoded.trim_end_matches('\\').to_owned()
}

/// Single HTML-entity pass for embedded URLs: `&lt;/&gt;/&quot;/&#x27;/&#39;`
/// first, `&amp;` last so `&amp;lt;` decodes to `&lt;`, never `<`.
fn decode_html_entities_once(raw: &str) -> String {
    raw.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#x27;", "'")
        .replace("&#X27;", "'")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

/// Minimal JS string unescape: `\uXXXX`, `\/`, `\\`, `\"`, `\'`, plus
/// `\n`/`\r`/`\t`. Unknown escapes are kept verbatim; lone `\u` without 4
/// hex digits is kept. Char-based (never byte-indexes `&str`) so multibyte
/// UTF-8 survives intact.
fn decode_js_string_escapes(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        let Some(next) = chars.next() else {
            out.push('\\');
            break;
        };
        match next {
            'u' => {
                let hex: String = chars.by_ref().take(4).collect();
                if hex.len() == 4
                    && let Ok(code) = u32::from_str_radix(&hex, 16)
                {
                    if let Some(ch) = char::from_u32(code) {
                        out.push(ch);
                    } else {
                        out.push_str("\\u");
                        out.push_str(&hex);
                    }
                } else {
                    out.push_str("\\u");
                    out.push_str(&hex);
                }
            }
            'n' => out.push('\n'),
            'r' => out.push('\r'),
            't' => out.push('\t'),
            '/' => out.push('/'),
            '\\' | '"' | '\'' => out.push(next),
            _ => {
                out.push('\\');
                out.push(next);
            }
        }
    }
    out
}
