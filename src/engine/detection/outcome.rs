use crate::engine::schedule::parse_finding_dbms;
use crate::{
    detection::baseline,
    reasoning::Hypothesis,
    session::state::{Finding, TechniqueKind},
};

/// Fold a technique outcome into `hyp`. `Finding`s are untouched; only the
/// belief moves. Unconfirmed error hits stay probe-only (no trial) so they
/// can never reach the `>= 0.85 + trial` confirmed state.
/// A confirmed DBMS label (`fill_missing_dbms` bar: `>= 0.85`) also promotes
/// `hyp.dbms_belief` for the next tour: the following technique on the same
/// parameter selects quote-correct, engine-specific payloads instead of
/// re-spraying generics.
pub(crate) fn apply_outcome_to_hypothesis(
    hyp: &mut Hypothesis,
    kind: TechniqueKind,
    new_findings: &[Finding],
    cost: usize,
    baseline: &baseline::Baseline,
) {
    if baseline.is_waf_blocking() {
        hyp.record_waf_penalty();
    }
    if new_findings.is_empty() {
        hyp.record_probe(false, 0.0, cost);
        return;
    }
    let unconfirmed_only = new_findings
        .iter()
        .all(|f| f.evidence.contains("unconfirmed"));
    let (signal, trials) = infer_signal_and_trials(kind, new_findings, unconfirmed_only);
    hyp.record_probe(true, signal, cost);
    for _ in 0..trials {
        hyp.record_trial(true);
    }
    if !unconfirmed_only {
        for finding in new_findings {
            if let Some(dbms_kind) = parse_finding_dbms(finding.dbms.as_deref()) {
                hyp.dbms_belief.update_with_signal(dbms_kind, 0.9);
                break;
            }
        }
    }
}

/// Default positive signal strength + confirming trials per technique.
/// `confirm_either` 3-trial logic lives inside the detectors and is unchanged;
/// one passed detector confirmation counts as one hypothesis trial here.
///
/// Provisional calibration (v0.5): `boolean`/`error` 0.9, `union` 0.85,
/// `time`/`stacked` 0.8 mirror the historical detector confidences
/// (`diff_against_baseline` 0.75/0.85 branches, 3-trial `confirm_either`).
/// Recalibrate against `bench/reports/history.jsonl` once 5+ runs per
/// scenario exist (`run.py compare --from v0.4`): `high` must hold precision
/// `>= 95%`, `medium >= 80%`, else adjust here and re-run the bench matrix.
pub(crate) fn infer_signal_and_trials(
    kind: TechniqueKind,
    new_findings: &[Finding],
    unconfirmed_only: bool,
) -> (f64, usize) {
    if unconfirmed_only {
        return (0.4, 0);
    }
    match kind {
        TechniqueKind::Boolean | TechniqueKind::Error => (0.9, 1),
        TechniqueKind::Time | TechniqueKind::Stacked => (0.8, 1),
        TechniqueKind::Union => (0.85, 1),
        TechniqueKind::Json
        | TechniqueKind::Nosql
        | TechniqueKind::Transit
        | TechniqueKind::Orm
        | TechniqueKind::Graphql
        | TechniqueKind::Elasticsearch => {
            let boolean_channel = new_findings
                .iter()
                .any(|f| f.evidence.contains("channel=boolean"));
            if boolean_channel { (0.9, 1) } else { (0.75, 1) }
        }
        TechniqueKind::Oob => (1.0, 1),
    }
}
