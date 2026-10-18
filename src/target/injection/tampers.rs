use crate::techniques::tamper::Tamper;

/// Auto-tampers applied when a blocking WAF is seen and the user gave none:
/// `space2comment` (space-signature bypass) + `randomcase` (case-signature
/// bypass, 429 rate-limit hardening). Pure and unit-testable. HPP/chunked
/// are never auto-enabled (request-shape changes stay explicit opt-in).
#[must_use]
pub fn waf_auto_tampers() -> Vec<Tamper> {
    vec![Tamper::Space2Comment, Tamper::RandomCase]
}

/// Resolve the effective tamper set for a run: the WAF auto-pair when
/// `waf_blocking` fired and the user gave none, otherwise the user set
/// unchanged (explicit `--tamper` always wins). Pure and unit-testable.
#[must_use]
pub fn resolve_effective_tampers(waf_blocking: bool, user_tampers: &[Tamper]) -> Vec<Tamper> {
    if waf_blocking && user_tampers.is_empty() {
        waf_auto_tampers()
    } else {
        user_tampers.to_vec()
    }
}
