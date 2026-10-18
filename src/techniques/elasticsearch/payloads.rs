#![deny(unsafe_code)]

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ElasticsearchPayload {
    pub true_payload: String,
    pub false_payload: String,
    pub error_payload: String,
}

impl ElasticsearchPayload {
    #[must_use]
    pub fn new(
        true_payload: impl Into<String>,
        false_payload: impl Into<String>,
        error_payload: impl Into<String>,
    ) -> Self {
        Self {
            true_payload: true_payload.into(),
            false_payload: false_payload.into(),
            error_payload: error_payload.into(),
        }
    }
}

#[must_use]
pub fn elasticsearch_payloads() -> Vec<ElasticsearchPayload> {
    vec![
        ElasticsearchPayload::new(
            r#"{"query":{"match_all":{}}}"#,
            r#"{"query":{"term":{"status":"injekt_nomatch_zzz"}}}"#,
            r#"{"query":{"invalid_query_injekt":1}}"#,
        ),
        ElasticsearchPayload::new(
            r#"{"query":{"wildcard":{"status":"*"}}}"#,
            r#"{"query":{"wildcard":{"status":"injekt_nomatch_zzz"}}}"#,
            r#"{"query":{"range":{"status":{"gt":"not_a_date"}}}}"#,
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payloads_non_empty() {
        let v = elasticsearch_payloads();
        assert!(!v.is_empty());
        for p in &v {
            assert_ne!(p.true_payload, p.false_payload);
            assert!(!p.error_payload.is_empty());
        }
    }
}
