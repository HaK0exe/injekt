#![deny(unsafe_code)]

use serde::{Deserialize, Serialize};

/// Where a parameter lives.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ParameterLocation {
    Query,
    Body,
    Header(String),
    Cookie,
}

impl core::fmt::Display for ParameterLocation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Query => write!(f, "query"),
            Self::Body => write!(f, "body"),
            Self::Header(h) => write!(f, "header:{h}"),
            Self::Cookie => write!(f, "cookie"),
        }
    }
}

/// Single injectable parameter with original value preserved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct TargetParameter {
    pub name: String,
    pub location: ParameterLocation,
    pub original_value: String,
}

impl TargetParameter {
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        location: ParameterLocation,
        original_value: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            location,
            original_value: original_value.into(),
        }
    }

    /// Unique key for reporting.
    #[must_use]
    pub fn key(&self) -> String {
        format!("{}@{}", self.name, self.location)
    }
}

/// Collect all parameter locations from URL + body + headers (helper).
#[must_use]
pub fn collect_from_url_query(url: &crate::target::url::TargetUrl) -> Vec<TargetParameter> {
    url.query_params()
        .into_iter()
        .map(|(k, v)| TargetParameter::new(k, ParameterLocation::Query, v))
        .collect()
}

#[must_use]
pub fn collect_from_body(body: &str) -> Vec<TargetParameter> {
    if body.is_empty() {
        return Vec::new();
    }
    let trimmed = body.trim();
    // JSON bodies (`--data '{"a":1}'`): expose top-level keys as body params.
    // Urlencoded parsing would otherwise yield a single aberrant `{"a":1}` key.
    if trimmed.starts_with('{')
        && trimmed.ends_with('}')
        && let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed)
        && let Some(obj) = value.as_object()
    {
        return obj
            .iter()
            .map(|(k, v)| {
                let s = match v {
                    serde_json::Value::String(s) => s.clone(),
                    serde_json::Value::Null => String::new(),
                    _ => v.to_string(),
                };
                TargetParameter::new(k.clone(), ParameterLocation::Body, s)
            })
            .collect();
    }
    url::form_urlencoded::parse(body.as_bytes())
        .map(|(k, v)| TargetParameter::new(k.into_owned(), ParameterLocation::Body, v.into_owned()))
        .collect()
}

#[must_use]
pub fn collect_from_raw_request(
    req: &crate::target::raw_request::RawRequest,
) -> Vec<TargetParameter> {
    let mut out = Vec::new();
    if let Some(body) = &req.body {
        out.extend(collect_from_body(body));
    }
    // Headers as injectable (X-Forwarded-For etc) — only if needed; for now just body
    out
}
