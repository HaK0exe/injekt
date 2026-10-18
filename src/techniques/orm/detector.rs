#![deny(unsafe_code)]

use crate::techniques::boolean::detector::{BooleanDetector, BooleanResult};
use regex::Regex;

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct OrmResult {
    pub is_vulnerable: bool,
    pub confidence: f64,
    pub matched_pattern: Option<String>,
}

#[derive(Debug)]
pub struct OrmDetector {
    boolean: BooleanDetector,
}

impl Default for OrmDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl OrmDetector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            boolean: BooleanDetector::new(),
        }
    }

    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn evaluate_boolean_with_match_ratio(
        &self,
        baseline_body: &str,
        true_body: &str,
        false_body: &str,
        baseline_ms: f64,
        true_ms: f64,
        false_ms: f64,
        match_ratio: Option<f64>,
    ) -> BooleanResult {
        self.boolean.evaluate_with_match_ratio(
            baseline_body,
            true_body,
            false_body,
            baseline_ms,
            true_ms,
            false_ms,
            match_ratio,
        )
    }

    #[must_use]
    pub fn evaluate_error(&self, body: &str) -> OrmResult {
        let patterns: &[(&str, &str)] = &[
            (r"(?i)hibernate", "hibernate"),
            (r"(?i)prisma", "prisma"),
            (r"(?i)django", "django"),
            (r"(?i)sqlalchemy", "sqlalchemy"),
            (r"(?i)sequelize", "sequelize"),
            (r"(?i)typeorm", "typeorm"),
            (r"(?i)knex", "knex"),
            (r"(?i)raw query", "raw_query"),
            (r"(?i)sql syntax", "sql_syntax"),
            (r"(?i)exception", "exception"),
        ];
        for (pattern, name) in patterns {
            if let Ok(re) = Regex::new(pattern)
                && re.is_match(body)
            {
                let lowered = body.to_ascii_lowercase();
                if lowered.contains("error")
                    || lowered.contains("exception")
                    || lowered.contains("invalid")
                    || lowered.contains("syntax")
                {
                    return OrmResult {
                        is_vulnerable: true,
                        confidence: 0.8,
                        matched_pattern: Some((*name).to_owned()),
                    };
                }
            }
        }
        OrmResult {
            is_vulnerable: false,
            confidence: 0.0,
            matched_pattern: None,
        }
    }
}
