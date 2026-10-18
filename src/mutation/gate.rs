/// Miroir de la règle orchestrateur `is_confirmed_finding` :
/// `!evidence.contains("unconfirmed") && confidence >= 0.5`.
///
/// Dupliquée ici (plutôt qu'importée) car le prédicat vit dans un module
/// privé de l'orchestrateur ; tout changement de seuil doit mettre à jour
/// les deux sites (test `gate_mirrors_orchestrator_rule` en garde-fou).
#[must_use]
pub fn is_confirmed_evidence(evidence: &str, confidence: f64) -> bool {
    !evidence.contains("unconfirmed") && confidence >= 0.5
}

/// Porte d'entrée unique : `true` ssi une mutation peut être tentée.
///
/// - `no_mutation` (`--no-mutation`) → `false` (échappement opérateur).
/// - `baseline_blocking` (WAF en blocage actif) → `false` (WAF-penalty :
///   pas de spray sous WAF).
/// - finding non confirmé ou OOB → `false` (confirmés seuls, jamais de
///   mutation sur cible non confirmée, jamais d'OOB muté).
// 4 booléens positionnels = la porte elle-même (un struct ajouterait du
// bruit d'appel pour un prédicat pur) ; appel unique côté orchestrateur.
#[allow(clippy::fn_params_excessive_bools)]
#[must_use]
pub const fn should_attempt_mutation(
    no_mutation: bool,
    baseline_blocking: bool,
    finding_confirmed: bool,
    technique_is_oob: bool,
) -> bool {
    !no_mutation && !baseline_blocking && finding_confirmed && !technique_is_oob
}
