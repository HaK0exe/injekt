use regex::Regex;

/// Bare `EXTRACTVALUE` / `UPDATEXML` keyword probe (case-insensitive).
/// Used to distinguish a reflected payload echo from a real `XPATH syntax
/// error` DB message.
#[must_use]
pub fn contains_xpath_keyword(body: &str) -> bool {
    let lower = body.to_ascii_lowercase();
    lower.contains("extractvalue") || lower.contains("updatexml")
}

/// Conversion/type-error signatures shared by **data-type parsing** failures
/// (application casting or DB `CAST`/`CONVERT`), as opposed to SQL *syntax*
/// errors.
///
/// These phrases are deliberately SHARED between genuine DB conversion errors
/// and application-level "input must be an integer" rejections: a numeric
/// parameter (`id=1`) whose app/ORM rejects any non-strictly-numeric value
/// emits the *same* wording as a real SQL `CAST` error. This classifier must
/// therefore NEVER be used as a standalone positive `SQLi` signal — it only
/// labels a candidate body so the caller can run a **negative control**
/// (send a non-numeric, SQL-syntax-free value and check whether the same
/// phrasing comes back; the veto decision belongs to that control, P1.3).
///
/// Matched case-insensitively (body lowercased once):
/// - PostgreSQL: `invalid input syntax for type integer` / `… for integer`
/// - MSSQL: `Msg 245`, `Msg 8114`, `Conversion failed when converting`,
///   `Error converting data type`
/// - Java: `NumberFormatException`, `TypeMismatchException`
/// - .NET: `System.FormatException`,
///   `Input string was not in a correct format`
/// - Python: `ValueError: invalid literal`
/// - MySQL: `Out of range value`, `Incorrect integer value`,
///   `Truncated incorrect`
/// - SQLite/generic: `datatype mismatch`, `cannot be converted to`,
///   `is not of type numeric`
///
/// Intentionally excluded: `Msg 8134` / `divide by zero` (arithmetic, not a
/// conversion) and `ORA-01722` / `invalid number` (also the classic
/// Oracle error-based detection channel).
#[must_use]
pub fn classify_cast_error(body: &str) -> bool {
    const CAST_SIGNATURES: [&str; 17] = [
        "invalid input syntax for type integer",
        "invalid input syntax for integer",
        "msg 245",
        "msg 8114",
        "conversion failed when converting",
        "error converting data type",
        "system.formatexception",
        "numberformatexception",
        "input string was not in a correct format",
        "valueerror: invalid literal",
        "typemismatchexception",
        "out of range value",
        "incorrect integer value",
        "truncated incorrect",
        "datatype mismatch",
        "cannot be converted to",
        "is not of type numeric",
    ];
    let lower = body.to_ascii_lowercase();
    CAST_SIGNATURES.iter().any(|sig| lower.contains(sig))
}

/// ASP.NET yellow-screen guard: `Server Error in '/' Application` alone is
/// too broad (any unhandled exception — the phrase itself contains "error",
/// so generic tokens must NOT count). Only SQL-specific co-occurrence
/// tokens qualify.
#[must_use]
pub fn is_aspnet_yellow_screen(body: &str) -> bool {
    let lower = body.to_ascii_lowercase();
    if !lower.contains("server error in '/' application") {
        return false;
    }
    [
        "sql",
        "syntax",
        "ora-",
        "msg ",
        "sqlstate",
        "sqlexception",
        "odbc",
        "jdbc",
        "unclosed quotation",
    ]
    .iter()
    .any(|t| lower.contains(t))
}

/// Case-insensitive check whether the sent payload is reflected verbatim
/// (or HTML-entity encoded) in the response body. Used for evidence only;
/// the veto itself goes through [`mask_reflected`].
#[must_use]
pub fn is_payload_reflected(body: &str, sent_payload: &str) -> bool {
    if sent_payload.is_empty() || body.is_empty() {
        return false;
    }
    let body_lower = body.to_ascii_lowercase();
    let payload_lower = sent_payload.to_ascii_lowercase();
    if body_lower.contains(&payload_lower) {
        return true;
    }
    // Token-level fallback: server may truncate/escape the full payload but
    // still echo the distinctive function name (observed noxtools shape:
    // `value="...extractvalue(1,concat(0x7e,version()))..."`).
    for token in ["extractvalue", "updatexml"] {
        if payload_lower.contains(token) && body_lower.contains(token) {
            return true;
        }
    }
    false
}

/// Remove case-insensitive occurrences of the sent payload (plus common
/// HTML-entity encoded variants) from the response body.
///
/// The error detector must never match its own echoed payload: a response
/// like `<input value="' AND EXTRACTVALUE...">` contains the keyword but no
/// DB error. Masking before matching turns that FP into a clean negative
/// while preserving a real `XPATH syntax error: '~5.7~'` fragment (which is
/// DB output, not part of the sent payload).
#[must_use]
pub fn mask_reflected(body: &str, sent_payload: &str) -> String {
    if sent_payload.is_empty() || body.is_empty() {
        return body.to_owned();
    }
    let variants = payload_variants(sent_payload);
    let mut out = body.to_owned();
    for variant in &variants {
        if variant.is_empty() {
            continue;
        }
        out = case_insensitive_remove(&out, variant);
        if out.is_empty() {
            break;
        }
    }
    out
}

/// Original payload plus HTML-entity encoded reflections
/// (`htmlspecialchars`-style echo in `value="..."` attributes).
fn payload_variants(payload: &str) -> Vec<String> {
    let mut variants = Vec::with_capacity(3);
    variants.push(payload.to_owned());
    // `&` first to avoid double-encoding.
    let html = payload
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;");
    if html != payload {
        variants.push(html);
    }
    let html39 = payload.replace('&', "&amp;").replace('\'', "&#39;");
    if html39 != payload && !variants.contains(&html39) {
        variants.push(html39);
    }
    variants
}

/// Case-insensitive removal of `needle` from `haystack` via an escaped
/// regex. Falls back to the unmodified body if the regex fails to compile
/// (arbitrary payload input must never panic the detector).
fn case_insensitive_remove(haystack: &str, needle: &str) -> String {
    let pattern = format!("(?i){}", regex::escape(needle));
    match Regex::new(&pattern) {
        Ok(re) => re.replace_all(haystack, "").into_owned(),
        Err(_) => haystack.to_owned(),
    }
}
