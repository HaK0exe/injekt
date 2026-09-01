#![deny(unsafe_code)]

use regex::Regex;
use std::sync::OnceLock;

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ErrorResult {
    pub is_vulnerable: bool,
    pub confidence: f64,
    pub matched_pattern: Option<String>,
    pub extracted: Option<String>,
}

#[derive(Debug)]
pub struct ErrorDetector {
    patterns: Vec<(Regex, String)>,
}

impl Default for ErrorDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ErrorDetector {
    #[must_use]
    pub fn new() -> Self {
        let patterns = vec![
            (r"XPATH syntax error|EXTRACTVALUE", "mysql_xpath"),
            (
                r"SQL syntax.*MySQL|mysql_fetch|valid MySQL result",
                "mysql_generic",
            ),
            (
                r"PostgreSQL.*ERROR|pg_query|invalid input syntax",
                "postgres",
            ),
            (
                r"ODBC SQL Server Driver|Unclosed quotation mark|Microsoft.*SQL Server",
                "mssql",
            ),
            (
                r"ORA-\d{5}|Oracle error|quoted string not properly terminated",
                "oracle",
            ),
            (r"SQLSTATE\[\w+\]", "generic"),
        ];
        let compiled = patterns
            .into_iter()
            .map(|(p, name)| {
                #[allow(clippy::expect_used)]
                let re = Regex::new(p).expect("static error pattern regex");
                (re, name.to_owned())
            })
            .collect();
        Self { patterns: compiled }
    }

    #[must_use]
    pub fn evaluate(&self, body: &str) -> ErrorResult {
        for (re, name) in &self.patterns {
            if re.is_match(body) {
                let extracted = extract_version(body);
                return ErrorResult {
                    is_vulnerable: true,
                    confidence: 0.9,
                    matched_pattern: Some(name.clone()),
                    extracted,
                };
            }
        }
        ErrorResult {
            is_vulnerable: false,
            confidence: 0.1,
            matched_pattern: None,
            extracted: None,
        }
    }
}

fn extract_version(body: &str) -> Option<String> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        #[allow(clippy::expect_used)]
        {
            Regex::new(r"(?:MySQL|PostgreSQL|Microsoft SQL Server|Oracle).*?(\d+\.\d+[^<\s]*)")
                .expect("static version regex")
        }
    });
    re.captures(body)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn detects_mysql_xpath() {
        let d = ErrorDetector::new();
        let r = d.evaluate("XPATH syntax error: '~5.7.32~'");
        assert!(r.is_vulnerable);
    }
}
