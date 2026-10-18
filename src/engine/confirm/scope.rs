use crate::reporting::verdict::severity_for;
use crate::session::state::{Finding, Severity, TechniqueKind};

/// `true` when at least one finding justifies fingerprint + enumeration:
/// any finding that is not an unconfirmed error probe. Error hits without a
/// fragment stay at `0.55 unconfirmed` until `confirm_error_with_boolean`
/// upgrades them to `0.9 bool_confirm=true` — running DBMS guessing or the
/// boolean-oracle enumerator on the unconfirmed shape yields `postgres` FPs
/// followed by `enumeration length inference failed` after a single probe
/// (observed on clean Next.js targets).
#[must_use]
pub(crate) fn is_confirmed_finding(f: &Finding) -> bool {
    !f.evidence.contains("unconfirmed") && f.confidence >= 0.5
}

/// `true` when at least one confirmed finding exists (see
/// [`is_confirmed_finding`]). Fingerprint filling and `--dbs`-style
/// enumeration require this; unconfirmed-only snapshots must stay silent.
#[must_use]
pub(crate) fn has_confirmed_finding(findings: &[Finding]) -> bool {
    findings.iter().any(is_confirmed_finding)
}

/// `true` when at least one finding justifies the heavy boolean-oracle
/// extraction: a *confirmed* boolean finding, or an error finding with an
/// extracted fragment (`extracted=yes`) or a confirmed boolean differential
/// (`bool_confirm=true`). Unconfirmed 0.55 error findings alone never qualify
/// — they would burn ~270-700 requests into `inference inconsistency`.
#[must_use]
pub(crate) fn is_extraction_eligible(findings: &[Finding]) -> bool {
    findings.iter().any(|f| {
        (f.technique == TechniqueKind::Boolean && is_confirmed_finding(f))
            || (f.technique == TechniqueKind::Error
                && (f.evidence.contains("extracted=yes")
                    || f.evidence.contains("bool_confirm=true")))
    })
}

/// Scope of the confirm second-pass (anti-FP P2.4).
///
/// `--confirm` selects [`ConfirmScope::All`] (historical behaviour,
/// C5-tardif mini-mutation included); a default run uses
/// [`ConfirmScope::MediumRisk`], so confirmed findings below the `High`
/// bucket are re-validated for free (0 request when no candidate exists).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConfirmScope {
    /// Every confirmed non-OOB finding (`--confirm`).
    All,
    /// Confirmed non-OOB findings below the `High` bucket (default).
    MediumRisk,
}

/// `true` when a finding must be re-validated by the automatic second-pass
/// (no `--confirm`): confirmed, non-OOB, not calibrated `High`, on any
/// technique whose second-pass re-probes the same channel/variant window as
/// first-pass detection.
///
/// `High` findings (score + FP estimate both agree) already meet the ≥95 %
/// precision claim; re-probing them would only add traffic. `Medium`/`Low`
/// findings carry the residual FP risk, so they are re-validated — the pass
/// never creates findings and inconclusive outcomes keep them (fail-open).
///
/// Every non-OOB technique now has first-pass window parity: `Time` re-sweeps
/// the same payload family/budget (blind sweep included), `Json` replays the
/// GraphQL `variables` envelope, `Json`/`Nosql` re-probe the finding's
/// original channel (`channel=error` → error probe) and `Nosql` keeps the
/// JSON-body operator shape — so a failed re-confirmation is conclusive and
/// auto-dropping no longer risks losing true positives.
pub(crate) fn needs_auto_second_pass(f: &Finding) -> bool {
    f.technique != TechniqueKind::Oob
        && is_confirmed_finding(f)
        && severity_for(f.confidence, f.false_positive_prob) != Severity::High
}

/// `true` when `f` falls in the given second-pass [`ConfirmScope`]: `All`
/// keeps the historical filter (every confirmed non-OOB finding),
/// `MediumRisk` is the strict automatic subset ([`needs_auto_second_pass`]).
pub(crate) fn in_confirm_scope(f: &Finding, scope: ConfirmScope) -> bool {
    match scope {
        ConfirmScope::All => f.technique != TechniqueKind::Oob && is_confirmed_finding(f),
        ConfirmScope::MediumRisk => needs_auto_second_pass(f),
    }
}
