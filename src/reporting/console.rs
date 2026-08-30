#![deny(unsafe_code)]

use crate::session::state::Finding;
use owo_colors::OwoColorize;
use tabled::{Table, Tabled};

#[derive(Tabled)]
struct Row {
    #[tabled(rename = "Target")]
    target: String,
    #[tabled(rename = "Param")]
    param: String,
    #[tabled(rename = "Technique")]
    technique: String,
    #[tabled(rename = "Conf")]
    conf: String,
    #[tabled(rename = "DBMS")]
    dbms: String,
}

pub fn print_findings(findings: &[Finding]) {
    if findings.is_empty() {
        println!("{}", "No findings.".yellow());
        return;
    }
    let rows: Vec<Row> = findings
        .iter()
        .map(|f| Row {
            target: f.target.clone(),
            param: f.parameter.clone(),
            technique: f.technique.to_string(),
            conf: format!("{:.2}", f.confidence),
            dbms: f.dbms.clone().unwrap_or_else(|| "-".to_owned()),
        })
        .collect();
    let table = Table::new(rows).to_string();
    println!("{}", table.bright_white());
    for f in findings {
        println!(
            "{} {} evidence: {}",
            "→".green(),
            f.parameter.cyan(),
            f.evidence.dimmed()
        );
    }
}
