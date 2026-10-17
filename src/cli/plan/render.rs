//! Human/JSON renders of the offline plan (`--dry-run`, MCP `plan`)
//! and offline `--explain` helpers.

use crate::session::scrubber::Scrubber;

use super::model::ExecutionPlan;

/// Human-readable multi-line render (scrubbed when `no_redact == false`).
#[must_use]
pub fn render_human(plan: &ExecutionPlan, resolution: &str, no_redact: bool) -> String {
    use core::fmt::Write as _;
    let scrubber = Scrubber::new(no_redact);
    let mut out = String::new();
    out.push_str("dry-run: execution plan (0 request sent)\n");
    let _ = writeln!(out, "  target: {}", scrubber.scrub(&plan.target));
    out.push_str("  resolution: ");
    out.push_str(resolution);
    out.push('\n');
    let techs = if plan.techniques.is_empty() {
        "all".to_owned()
    } else {
        plan.techniques.join(",")
    };
    let _ = writeln!(
        out,
        "  seed={} level={} threads={} techniques={}",
        plan.seed.map_or("none".to_owned(), |s| s.to_string()),
        plan.level,
        plan.threads,
        techs,
    );
    let _ = writeln!(
        out,
        "  dbms_hint={} budget_spent={} budget_total={} dry_run={}",
        plan.dbms_hint.as_deref().unwrap_or("none"),
        plan.budget_spent,
        plan.budget_total
            .map_or("unlimited".to_owned(), |b| b.to_string()),
        plan.dry_run,
    );
    out.push_str("  params: ");
    out.push_str(&plan.params.len().to_string());
    out.push('\n');
    for p in &plan.params {
        let _ = writeln!(
            out,
            "    - {} [{}] {} dbms={}@{:.2}",
            scrubber.scrub(&p.param),
            p.location,
            scrubber.scrub(&p.context_summary),
            p.dbms_top,
            p.dbms_prob,
        );
    }
    out.push_str("  ordered probes: ");
    out.push_str(&plan.ordered.len().to_string());
    out.push('\n');
    for (idx, probe) in plan.ordered.iter().enumerate() {
        let _ = writeln!(
            out,
            "    {}. {} {} prior={:.2} evi={:.2} cost={:.2} score={:.3} seed={}",
            idx + 1,
            scrubber.scrub(&probe.param),
            probe.technique,
            probe.prior,
            probe.evi,
            probe.cost,
            probe.score,
            probe.seed.map_or("none".to_owned(), |s| s.to_string()),
        );
    }
    out.push_str("  0 requête envoyée (HttpClient.send jamais appelé)\n");
    out
}

/// Offline `--explain` helper: scrubbed evidence → [`crate::reasoning::explain_line`].
#[must_use]
pub fn explain_offline(
    param: &str,
    evidence: &str,
    confidence: f64,
    requests: u64,
    seed: Option<u64>,
    no_redact: bool,
) -> String {
    let scrubber = Scrubber::new(no_redact);
    let clean_evidence = scrubber.scrub(evidence);
    let trace = crate::reasoning::ReasoningTrace::new();
    crate::reasoning::explain_line(
        &clean_evidence,
        confidence.clamp(0.0, 1.0),
        param,
        &trace,
        requests,
        seed,
    )
}

/// Extract `(evidence, confidence, requests, seed)` for `param` from a
/// decrypted snapshot / findings JSON value (offline, mirrors
/// `replay::print_snapshot_explain` matching: case-insensitive exact param).
#[must_use]
pub fn finding_from_export(
    export: &serde_json::Value,
    param: &str,
) -> Option<(String, f64, u64, Option<u64>)> {
    let want = param.trim().to_ascii_lowercase();
    let findings = export.get("findings")?.as_array()?;
    let mut matched: Option<(String, f64)> = None;
    for f in findings {
        let p = f.get("parameter")?.as_str().unwrap_or("");
        if p.to_ascii_lowercase() == want {
            let ev = f
                .get("evidence")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("")
                .to_owned();
            let conf = f
                .get("confidence")
                .and_then(serde_json::Value::as_f64)
                .unwrap_or(0.0);
            matched = Some((ev, conf));
            break;
        }
    }
    let (evidence, confidence) = matched?;
    let requests = export
        .get("request_count")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let seed = export.get("seed").and_then(serde_json::Value::as_u64);
    Some((evidence, confidence, requests, seed))
}
