//! Check 3 — cadence : règle figée `1000/rate_limit ≥ 1000/jitter_ms` (doctor).

use super::CheckResult;
use crate::cli::profile::Profile;

// ---------------------------------------------------------------------------
// Check 3 — cohérence cadence (jitter vs rate-limit)
// ---------------------------------------------------------------------------

/// Parse `"mean_ms,std_ms"` avec la même tolérance que
/// `client_builder::jitter_from_str` (tokens non numériques filtrés,
/// exactement 2 retenus) ; σ est replié ≥ 1.0 comme au runtime
/// (`Jitter::next_delay_with_rng`) ; NaN/∞ refusés (le parse f64 les
/// accepterait sinon). `None` = invalide ⇒ défaut `"750,250"` au runtime.
#[must_use]
pub fn parse_jitter_pair(jitter: &str) -> Option<(f64, f64)> {
    let parts: Vec<f64> = jitter
        .split(',')
        .filter_map(|x| x.trim().parse().ok())
        .collect();
    match parts.as_slice() {
        [mean, std] if mean.is_finite() && std.is_finite() && *std >= 0.0 => {
            Some((*mean, std.max(1.0)))
        }
        _ => None,
    }
}

/// Format `f64` lisible : entier sans décimales, sinon 2 décimales
/// (`1.0 → "1"`, `2.5 → "2.5"`, `0.05 → "0.05"`).
fn fmt_rate(v: f64) -> String {
    if !v.is_finite() {
        return "0".to_owned();
    }
    let s = format!("{v:.2}");
    let trimmed = s.trim_end_matches('0').trim_end_matches('.');
    if trimmed.is_empty() {
        "0".to_owned()
    } else {
        trimmed.to_owned()
    }
}

/// Check 3 (pur) — règle figée (§3 du plan) : `1000/rate_limit ≥
/// jitter_mean − 2·jitter_std` ⇒ `Ok` ; sinon `Warn` chiffré « cadence plus
/// rapide que le jitter → pattern détectable » + correction proposée.
///
/// Neutralité déterministe : pas de `rate_limit` explicite **et** pas de
/// profil ⇒ check neutre (on ne redit rien) ; la ligne reprend quand même
/// les valeurs effectives, en signalant un jitter explicite (lequel n'est
/// pas une cadence — règle inchangée). `rate ≤ 0` ⇒ `Warn` (le runtime
/// clamp le limiter à 0.1 rps) ; jitter non parseable ⇒ `Warn` (le runtime
/// retombe sur le défaut floored `"750,250"`).
#[must_use]
pub fn check_cadence(
    rate: f64,
    rate_explicit: bool,
    jitter: &str,
    jitter_explicit: bool,
    profile: Option<Profile>,
) -> CheckResult {
    if !rate_explicit && profile.is_none() {
        let jitter_note = if jitter_explicit { " (explicite)" } else { "" };
        return CheckResult::ok(format!(
            "cadence: rien d'explicite, check neutre (rate {} rps · \
             jitter \"{jitter}\"{jitter_note})",
            fmt_rate(rate),
        ));
    }
    if rate <= 0.0 {
        return CheckResult::warn(format!(
            "cadence: rate_limit {} ≤ 0 — le runtime clampe le limiter à \
             0.1 rps (10s/req)",
            fmt_rate(rate),
        ));
    }
    let Some((mean, std)) = parse_jitter_pair(jitter) else {
        return CheckResult::warn(format!(
            "cadence: jitter \"{jitter}\" invalide (attendu \"mean_ms,std_ms\") — \
             défaut \"750,250\" utilisé au runtime",
        ));
    };
    let interval_ms = 1000.0 / rate;
    let floor_ms = mean - 2.0 * std;
    if interval_ms >= floor_ms {
        CheckResult::ok(format!(
            "cadence: {} rps ({interval_ms:.0}ms) ≥ plancher jitter 2σ \
             ({mean:.0}−2×{std:.0}={floor_ms:.0}ms) — cohérent (jitter \"{jitter}\")",
            fmt_rate(rate),
        ))
    } else {
        // Correction : le plus grand rate encore cohérent, borné par le bas
        // (`1000/rate ≥ floor` ⟺ `rate ≤ 1000/floor`) — arrondi par le bas
        // à 2 décimales pour rester strictement dans la borne.
        let suggested = (1000.0 / floor_ms * 100.0).floor() / 100.0;
        CheckResult::warn(format!(
            "cadence: {} rps ({interval_ms:.0}ms) < plancher jitter 2σ \
             ({mean:.0}−2×{std:.0}={floor_ms:.0}ms) — cadence plus rapide que \
             le jitter → pattern détectable ; correction : --rate-limit {} \
             (ou jitter plus court, ex. \"300,100\")",
            fmt_rate(rate),
            fmt_rate(suggested),
        ))
    }
}
