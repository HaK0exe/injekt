#![deny(unsafe_code)]

use crate::target::parameters::{ParameterLocation, TargetParameter};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use url::Url;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum CandidateMethod {
    Get,
    Post,
}

impl core::fmt::Display for CandidateMethod {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Get => write!(f, "GET"),
            Self::Post => write!(f, "POST"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParamType {
    Link,
    Input,
    Hidden,
    Select,
    Textarea,
    Javascript,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FormContext {
    pub source_url: Url,
    pub fields: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParameterCandidate {
    pub url: Url,
    pub method: CandidateMethod,
    pub param_name: String,
    pub location: ParameterLocation,
    pub param_type: ParamType,
    pub original_value: String,
    pub form_context: Option<FormContext>,
}

impl ParameterCandidate {
    #[must_use]
    pub fn target_parameter(&self) -> TargetParameter {
        TargetParameter::new(
            self.param_name.clone(),
            self.location.clone(),
            self.original_value.clone(),
        )
    }

    #[must_use]
    pub fn raw_request(&self) -> crate::target::raw_request::RawRequest {
        let mut headers = std::collections::HashMap::new();
        if let Some(host) = self.url.host_str() {
            let authority = self
                .url
                .port()
                .map_or_else(|| host.to_owned(), |port| format!("{host}:{port}"));
            headers.insert("Host".to_owned(), authority);
        }
        let body = if self.method == CandidateMethod::Post {
            headers.insert(
                "Content-Type".to_owned(),
                "application/x-www-form-urlencoded".to_owned(),
            );
            let fields = self
                .form_context
                .as_ref()
                .map(|context| context.fields.clone())
                .unwrap_or_else(|| {
                    BTreeMap::from([(self.param_name.clone(), self.original_value.clone())])
                });
            Some(
                url::form_urlencoded::Serializer::new(String::new())
                    .extend_pairs(fields)
                    .finish(),
            )
        } else {
            None
        };
        let path = match self.url.query() {
            Some(query) => format!("{}?{query}", self.url.path()),
            None => self.url.path().to_owned(),
        };
        crate::target::raw_request::RawRequest {
            method: self.method.to_string(),
            path,
            headers,
            body,
            http_version: "HTTP/1.1".to_owned(),
        }
    }

    #[must_use]
    pub fn dedup_key(&self) -> String {
        let mut normalized = self.url.clone();
        normalized.set_fragment(None);
        let mut names: Vec<String> = normalized
            .query_pairs()
            .map(|(name, _)| name.into_owned())
            .collect();
        if matches!(self.location, ParameterLocation::Body)
            && let Some(context) = &self.form_context
        {
            names.extend(context.fields.keys().cloned());
        }
        names.sort();
        names.dedup();
        normalized.set_query(None);
        format!(
            "{}|{}|{}|{}|{}",
            self.method,
            normalized,
            names.join(","),
            self.location,
            self.param_name
        )
    }
}
