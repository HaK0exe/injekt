#![deny(unsafe_code)]

use serde::{Deserialize, Serialize};

/// Structured info about injekt capabilities.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InfoResult {
    pub version: String,
    pub techniques: Vec<String>,
    pub tampers: Vec<String>,
    pub oob: String,
    pub request_tampers: String,
    pub dbms: Vec<String>,
    pub docs: String,
}

/// Return structured info without printing to stdout.
#[must_use]
pub fn info() -> InfoResult {
    InfoResult {
        version: env!("CARGO_PKG_VERSION").to_string(),
        techniques: vec![
            "boolean".to_string(),
            "time".to_string(),
            "error".to_string(),
            "union".to_string(),
            "stacked".to_string(),
            "oob".to_string(),
            "json".to_string(),
        ],
        tampers: crate::techniques::tamper::Tamper::all_names()
            .iter()
            .map(std::string::ToString::to_string)
            .collect(),
        oob: "opt-in via --oob-domain <collaborator> [--oob-poll-url <url> with {token}]"
            .to_string(),
        request_tampers:
            "--hpp (duplicate ?id=1&id=PAYLOAD), --chunked (Transfer-Encoding: chunked body)"
                .to_string(),
        dbms: vec![
            "mysql".to_string(),
            "postgres".to_string(),
            "mssql".to_string(),
            "oracle".to_string(),
        ],
        docs: "docs/OPSEC.md (JA3, jitter, proxy socks5h)".to_string(),
    }
}

/// Original CLI entry point — prints to stdout.
pub fn run() {
    use owo_colors::OwoColorize;

    let info = info();
    println!(
        "{} {}",
        "modern SQLi detection".bold(),
        "— zero persistence, OPSEC by design".bright_black()
    );
    println!();
    let row = |label: &str, value: &str| {
        println!("  {:<18} {}", label.bright_cyan().bold(), value);
    };
    row("Techniques", &info.techniques.join(", "));
    row("Tampers", &info.tampers.join(", "));
    row("OOB", &info.oob);
    row("Request tampers", &info.request_tampers);
    row("DBMS", &info.dbms.join(", "));
    row("Docs", &info.docs);
}
