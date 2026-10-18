use super::scope::is_confirmed_finding;
use crate::session::state::{Finding, SessionState, TechniqueKind};
use crate::target::{
    parameters::{ParameterLocation, TargetParameter},
    url::TargetUrl,
};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Recover the injection [`TargetParameter`] for a finding (`name@location`,
/// split at the last `@`; unknown locations fall back to `Query`).
pub(crate) fn param_from_finding(finding: &Finding) -> TargetParameter {
    let (name, loc_str) = match finding.parameter.rsplit_once('@') {
        Some((n, l)) => (n.to_owned(), l.to_owned()),
        None => (finding.parameter.clone(), "query".to_owned()),
    };
    let location = if loc_str == "query" {
        ParameterLocation::Query
    } else if loc_str == "body" {
        ParameterLocation::Body
    } else if loc_str == "cookie" {
        ParameterLocation::Cookie
    } else if let Some(h) = loc_str.strip_prefix("header:") {
        ParameterLocation::Header(h.to_owned())
    } else {
        ParameterLocation::Query
    };
    TargetParameter::new(name, location, "1")
}

/// Recovers the injection point of the first *confirmed* finding (param
/// name + location parsed back out of `finding.parameter`), falling back
/// to the first finding then to a synthetic `id` query param when there
/// is no finding yet. Shared by fingerprint/extraction/enumeration, which
/// all reuse the same confirmed injection point.
pub(crate) async fn first_finding_param(
    state: &Arc<RwLock<SessionState>>,
    target: &TargetUrl,
) -> (TargetParameter, TargetUrl) {
    let st = state.read().await;
    let findings = st.findings().to_vec();
    drop(st);
    // Prefer a confirmed finding so an `0.55 unconfirmed` error never
    // dictates the oracle injection point when a confirmed finding exists.
    let f = findings
        .iter()
        .find(|x| is_confirmed_finding(x))
        .or_else(|| findings.first());
    if let Some(finding) = f {
        // `param_from_finding` splits `name@location` at the LAST '@'
        // (parameter names may contain '@' while locations never do).
        (param_from_finding(finding), target.clone())
    } else {
        // fallback synthetic
        (
            TargetParameter::new("id", ParameterLocation::Query, "1"),
            target.clone(),
        )
    }
}

/// Push one C6 confirm trace record (hashes only, never clear secrets).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn push_confirm_trace(
    state: &Arc<RwLock<SessionState>>,
    param_key: &str,
    technique: TechniqueKind,
    mutation_plan: &str,
    seed: Option<u64>,
    payload: &str,
    body: &str,
    diff: f64,
    ms: f64,
) {
    let mut st = state.write().await;
    let seq = st.next_trace_seq();
    st.push_trace(crate::reasoning::ProbeRecord::from_clear(
        seq,
        param_key,
        &technique.to_string(),
        mutation_plan,
        seed,
        payload,
        body,
        diff,
        ms,
    ));
}

/// DBMS label hint from a finding's `dbms` field for quote-correct confirm
/// payloads (`None` = generic polyglots, historical default).
pub(crate) fn dbms_label_from_finding(finding: &Finding) -> Option<&'static str> {
    let v = finding.dbms.as_deref()?.trim().to_ascii_lowercase();
    match v.as_str() {
        "mysql" | "mariadb" => Some("mysql"),
        "postgres" | "postgresql" | "pgsql" => Some("postgres"),
        "mssql" | "sqlserver" | "sql-server" | "tsql" => Some("mssql"),
        "oracle" | "ora" => Some("oracle"),
        "sqlite" => Some("sqlite"),
        _ => None,
    }
}
