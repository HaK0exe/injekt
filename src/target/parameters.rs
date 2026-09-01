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
