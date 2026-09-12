#![deny(unsafe_code)]

//! C5-tardif mini mutation (scope réduit, v0.7).
//!
//! Mini-AST volontairement minuscule : 4 familles string-level à sémantique
//! préservée (`TRUE` reste `TRUE`), appliquées **uniquement** sur des payloads
//! déjà confirmés, **uniquement** depuis le second-pass `--confirm`
//! ([`crate::engine::orchestrator`]), jamais en détection première.
//!
//! # Invariants (`DoD` C5-tardif)
//!
//! - Confirmés seuls : [`should_attempt_mutation`] refuse tout finding non
//!   confirmé (`unconfirmed` ou `confidence < 0.5`, même règle que
//!   l'orchestrateur), tout OOB, et tout appel avec `--no-mutation`.
//! - Borné : [`MAX_MUTATION_VARIANTS`] (4) variantes max par finding,
//!   [`MAX_MUTATION_REQUESTS_PER_FINDING`] (8) requêtes max par finding
//!   (l'orchestrateur envoie 1 requête par variante, soit ≤ 4 requêtes
//!   effectives, sous le plafond de 8).
//! - Seedé : [`MiniMutator::generate`] est déterministe pour un même
//!   `(base, contexte, seed)` ; seule `case_mix` tire de l'aléa, via
//!   [`crate::seeded_rng::make_rng`].
//! - Tracé : chaque variante porte un `mutation_plan` `mutation:<famille>`
//!   (noms seuls, jamais de payload en clair) poussé en trace hashes-only.
//! - Échec silencieux : une variante qui ne confirme pas ne modifie ni ne
//!   supprime le finding d'origine (l'orchestrateur ignore le résultat).
//! - WAF-penalty : baseline en blocage actif → 0 requête de mutation
//!   (pas de spray sous WAF).
//!
//! # Familles
//!
//! - `quote_fence` : ajoute une parenthèse de fermeture après le quote
//!   ouvrant (`' OR …` → `') OR …`) pour les contextes parenthésés.
//! - `paren_wrap` : parenthèse le prédicat (`1=1` → `(1=1)`).
//! - `comment_swap` : permute le terminateur (`-- -` ↔ `--` ↔ `#`) en
//!   respectant [`CommentStyle`].
//! - `case_mix` : mélange de casse déterministe (seedé).
//!
//! Aucun plugin system (décision roadmap : pas de `C8` en v1.0) : ce module
//! est un mini-mutateur fermé, pas un registre extensible.

use crate::dbms::context::{CommentStyle, InjectionContext, QuoteContext};
use crate::seeded_rng::make_rng;

/// Variantes max par finding (`DoD` C5-tardif).
pub const MAX_MUTATION_VARIANTS: usize = 4;

/// Requêtes max par finding pour la phase mutation (`DoD` C5-tardif).
///
/// L'orchestrateur envoie 1 requête par variante (≤ 4 effectives) ; le
/// plafond de 8 laisse la marge d'une paire TRUE/FALSE si un futur
/// confirm-muté l'exige, sans jamais sprayer.
pub const MAX_MUTATION_REQUESTS_PER_FINDING: usize = 8;

/// Famille de mutation (mini-AST scope réduit).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum MutationFamily {
    /// `'` → `')` (fence parenthésé).
    QuoteFence,
    /// `1=1` → `(1=1)`.
    ParenWrap,
    /// `-- -` ↔ `--` ↔ `#`.
    CommentSwap,
    /// Casse mélangée seedée.
    CaseMix,
}

impl MutationFamily {
    /// Nom stable pour `mutation_plan` (traçabilité, jamais de payload).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::QuoteFence => "quote_fence",
            Self::ParenWrap => "paren_wrap",
            Self::CommentSwap => "comment_swap",
            Self::CaseMix => "case_mix",
        }
    }

    /// Label `mutation_plan` poussé en trace (`mutation:<famille>`).
    #[must_use]
    pub fn plan_label(self) -> String {
        format!("mutation:{}", self.name())
    }
}

impl core::fmt::Display for MutationFamily {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Une variante mutée : payload + famille + label de trace.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct MutatedVariant {
    /// Famille appliquée.
    pub family: MutationFamily,
    /// Payload muté (jamais loggé en clair : hashé en trace).
    pub payload: String,
    /// `mutation:<famille>` pour [`crate::reasoning::ProbeRecord::mutation_plan`].
    pub plan_label: String,
}

impl MutatedVariant {
    #[must_use]
    pub fn new(family: MutationFamily, payload: String) -> Self {
        let plan_label = family.plan_label();
        Self {
            family,
            payload,
            plan_label,
        }
    }
}

/// Push one candidate variant unless capped, no-op, or duplicate.
/// Free function (not a closure) to avoid E0502 double-borrow of `out`.
fn push_variant(
    out: &mut Vec<MutatedVariant>,
    base: &str,
    family: MutationFamily,
    candidate: Option<String>,
) {
    if out.len() >= MAX_MUTATION_VARIANTS {
        return;
    }
    let Some(payload) = candidate else {
        return;
    };
    if payload == base || out.iter().any(|v: &MutatedVariant| v.payload == payload) {
        return;
    }
    out.push(MutatedVariant::new(family, payload));
}

/// Mini-mutateur C5-tardif : 4 interrupteurs, tous ON par défaut.
///
/// `--no-mutation` désactive l'appel côté orchestrateur (pas ici) ; ce
/// struct ne fait que générer des variantes pures (0 requête).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// 4 booléens nommés = le scope C5-tardif lui-même (1 par famille
// `quote_fence/paren_wrap/comment_swap/case_mix`), comme `EnumConfig`
// et `Cli` qui portent déjà cette autorisation dans le dépot.
#[allow(clippy::struct_excessive_bools)]
#[non_exhaustive]
pub struct MiniMutator {
    /// Active `quote_fence`.
    pub quote_fence: bool,
    /// Active `paren_wrap`.
    pub paren_wrap: bool,
    /// Active `comment_swap`.
    pub comment_swap: bool,
    /// Active `case_mix`.
    pub case_mix: bool,
}

impl Default for MiniMutator {
    fn default() -> Self {
        Self::all_enabled()
    }
}

impl MiniMutator {
    /// Toutes familles actives (défaut : mutation ON, scope restreint).
    #[must_use]
    pub const fn all_enabled() -> Self {
        Self {
            quote_fence: true,
            paren_wrap: true,
            comment_swap: true,
            case_mix: true,
        }
    }

    /// Aucune famille (génère 0 variante ; équivalent local de `--no-mutation`).
    #[must_use]
    pub const fn none() -> Self {
        Self {
            quote_fence: false,
            paren_wrap: false,
            comment_swap: false,
            case_mix: false,
        }
    }

    /// Génère ≤ [`MAX_MUTATION_VARIANTS`] variantes déterministes de `base`.
    ///
    /// Ordre fixe : `quote_fence`, `paren_wrap`, `comment_swap`, `case_mix`.
    /// Les no-ops (transformée == `base`) et les doublons sont sautés, donc
    /// un payload sans quote ni commentaire peut rendre < 4 variantes.
    /// `base` vide rend `Vec::new()`. Ne fait aucun I/O.
    #[must_use]
    pub fn generate(
        &self,
        base: &str,
        context: &InjectionContext,
        seed: Option<u64>,
    ) -> Vec<MutatedVariant> {
        if base.is_empty() {
            return Vec::new();
        }
        let mut out: Vec<MutatedVariant> = Vec::with_capacity(MAX_MUTATION_VARIANTS);
        // `push_variant` is a free function (not a closure) so the
        // duplicate scan (`out.iter()`) does not double-borrow `out`
        // alongside the `push` (E0502).
        if self.quote_fence {
            push_variant(
                &mut out,
                base,
                MutationFamily::QuoteFence,
                apply_quote_fence(base, context),
            );
        }
        if self.paren_wrap && out.len() < MAX_MUTATION_VARIANTS {
            push_variant(
                &mut out,
                base,
                MutationFamily::ParenWrap,
                apply_paren_wrap(base),
            );
        }
        if self.comment_swap && out.len() < MAX_MUTATION_VARIANTS {
            push_variant(
                &mut out,
                base,
                MutationFamily::CommentSwap,
                apply_comment_swap(base, context.comment),
            );
        }
        if self.case_mix && out.len() < MAX_MUTATION_VARIANTS {
            push_variant(
                &mut out,
                base,
                MutationFamily::CaseMix,
                apply_case_mix(base, seed),
            );
        }
        out
    }
}

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

// ── transforms (pures, déterministes) ────────────────────────────────────

/// `quote_fence` : `'` → `')`, `"` → `")`.
///
/// Skippé en contexte numérique nu ([`QuoteContext::None`] + `numeric`) :
/// il n'y a pas de quote à fencer et la variante serait du bruit.
/// Skippé si `base` ne commence pas par un quote (rien à fencer).
fn apply_quote_fence(base: &str, context: &InjectionContext) -> Option<String> {
    if context.quote == QuoteContext::None && context.numeric {
        return None;
    }
    if let Some(rest) = base.strip_prefix('\'') {
        let mut out = String::with_capacity(base.len() + 1);
        out.push('\'');
        out.push(')');
        out.push_str(rest);
        return Some(out);
    }
    if let Some(rest) = base.strip_prefix('"') {
        let mut out = String::with_capacity(base.len() + 1);
        out.push('"');
        out.push(')');
        out.push_str(rest);
        return Some(out);
    }
    None
}

/// `paren_wrap` : parenthèse le prédicat boolean.
///
/// Tente dans l'ordre : `1=1` → `(1=1)`, `1=2` → `(1=2)`,
/// `1 LIKE 1` → `(1 LIKE 1)`, `1 LIKE 2` → `(1 LIKE 2)`,
/// `'1'='1'` → `('1'='1')`, `'1'='2'` → `('1'='2')`.
/// Fallback générique : ` OR ` → ` OR (` + `)` avant le terminateur.
/// `None` si rien ne change (préserve la borne utile).
fn apply_paren_wrap(base: &str) -> Option<String> {
    for (needle, replacement) in [
        ("1=1", "(1=1)"),
        ("1=2", "(1=2)"),
        ("1 LIKE 1", "(1 LIKE 1)"),
        ("1 LIKE 2", "(1 LIKE 2)"),
        ("'1'='1'", "('1'='1')"),
        ("'1'='2'", "('1'='2')"),
    ] {
        if base.contains(needle) {
            return Some(base.replacen(needle, replacement, 1));
        }
    }
    // Fallback : parenthèse la branche `OR …` jusqu'au terminateur.
    let or_pos = base.find(" OR ")?;
    let after_or = or_pos + " OR ".len();
    let tail_start = base.len();
    let comment_at = base
        .rfind(" --")
        .or_else(|| base.rfind('#'))
        .unwrap_or(tail_start);
    if comment_at <= after_or {
        return None;
    }
    let mut out = String::with_capacity(base.len() + 2);
    out.push_str(&base[..after_or]);
    out.push('(');
    out.push_str(&base[after_or..comment_at]);
    out.push(')');
    out.push_str(&base[comment_at..]);
    if out == base { None } else { Some(out) }
}

/// `comment_swap` : permute le terminateur en respectant `CommentStyle`.
///
/// - `Hash` : tout terminateur `-- -` / `--` → `#` ; `#` → `#` inchangé (no-op).
/// - autres : ` -- -` → ` --`, ` --` → ` -- -`, `#` → ` -- -`.
///   `None` quand il n'y a pas de terminateur reconnu (pas de bruit).
fn apply_comment_swap(base: &str, style: CommentStyle) -> Option<String> {
    if style == CommentStyle::Hash {
        if base.ends_with(" -- -") {
            let stripped = base.strip_suffix(" -- -").unwrap_or(base);
            let mut out = String::with_capacity(base.len());
            out.push_str(stripped);
            out.push('#');
            return Some(out);
        }
        if base.ends_with(" --") {
            let stripped = base.strip_suffix(" --").unwrap_or(base);
            let mut out = String::with_capacity(base.len());
            out.push_str(stripped);
            out.push('#');
            return Some(out);
        }
        return None;
    }
    if base.ends_with(" -- -") {
        let stripped = base.strip_suffix(" -- -").unwrap_or(base);
        let mut out = String::with_capacity(base.len());
        out.push_str(stripped);
        out.push_str(" --");
        return Some(out);
    }
    if base.ends_with(" --") {
        let stripped = base.strip_suffix(" --").unwrap_or(base);
        let mut out = String::with_capacity(base.len());
        out.push_str(stripped);
        out.push_str(" -- -");
        return Some(out);
    }
    if base.ends_with('#') {
        let stripped = base.strip_suffix('#').unwrap_or(base);
        let mut out = String::with_capacity(base.len() + 4);
        out.push_str(stripped);
        out.push_str(" -- -");
        return Some(out);
    }
    None
}

/// `case_mix` : mélange de casse déterministe via `seed`.
///
/// Même `seed` → même sortie ; `None` = OS-random (historique).
/// `None` si aucun caractère ASCII alphabétique (rien à mixer).
fn apply_case_mix(base: &str, seed: Option<u64>) -> Option<String> {
    use rand::Rng as _;
    if !base.chars().any(|c| c.is_ascii_alphabetic()) {
        return None;
    }
    let mut rng = make_rng(seed);
    let out: String = base
        .chars()
        .map(|c| {
            if c.is_ascii_alphabetic() && rng.random_bool(0.5) {
                if c.is_ascii_lowercase() {
                    c.to_ascii_uppercase()
                } else {
                    c.to_ascii_lowercase()
                }
            } else {
                c
            }
        })
        .collect();
    if out == base {
        // Collision 2^-N (payload sans lettre déjà exclu) : forcer un flip
        // déterministe sur la première lettre pour garantir une variante.
        let mut forced = String::with_capacity(base.len());
        let mut flipped = false;
        for c in base.chars() {
            if !flipped && c.is_ascii_alphabetic() {
                flipped = true;
                if c.is_ascii_lowercase() {
                    forced.push(c.to_ascii_uppercase());
                } else {
                    forced.push(c.to_ascii_lowercase());
                }
            } else {
                forced.push(c);
            }
        }
        return Some(forced);
    }
    Some(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::dbms::context::QuoteContext;

    fn default_context() -> InjectionContext {
        InjectionContext::new()
    }

    #[test]
    fn bound_never_exceeds_four() {
        let m = MiniMutator::all_enabled();
        let variants = m.generate("' OR 1=1 -- -", &default_context(), Some(42));
        assert!(
            variants.len() <= MAX_MUTATION_VARIANTS,
            "got {} variants",
            variants.len()
        );
        assert_eq!(MAX_MUTATION_VARIANTS, 4);
        assert_eq!(MAX_MUTATION_REQUESTS_PER_FINDING, 8);
    }

    #[test]
    fn empty_base_yields_no_variant() {
        let m = MiniMutator::all_enabled();
        assert!(m.generate("", &default_context(), Some(1)).is_empty());
    }

    #[test]
    fn deterministic_same_seed() {
        let m = MiniMutator::all_enabled();
        let ctx = default_context();
        let a = m.generate("' OR 1=1 -- -", &ctx, Some(7));
        let b = m.generate("' OR 1=1 -- -", &ctx, Some(7));
        assert_eq!(a, b);
        // Le plan est tracé : chaque variante porte `mutation:<famille>`.
        for v in &a {
            assert!(
                v.plan_label.starts_with("mutation:"),
                "plan_label must be traced: {}",
                v.plan_label
            );
            assert_eq!(v.plan_label, v.family.plan_label());
        }
    }

    #[test]
    fn all_families_present_on_canonical_payload() {
        let m = MiniMutator::all_enabled();
        let variants = m.generate("' OR 1=1 -- -", &default_context(), Some(42));
        assert_eq!(variants.len(), 4, "got {variants:?}");
        let names: Vec<&str> = variants.iter().map(|v| v.family.name()).collect();
        assert_eq!(
            names,
            vec!["quote_fence", "paren_wrap", "comment_swap", "case_mix"]
        );
    }

    #[test]
    fn quote_fence_skipped_on_numeric_bare_context() {
        let m = MiniMutator {
            quote_fence: true,
            paren_wrap: false,
            comment_swap: false,
            case_mix: false,
        };
        let mut ctx = InjectionContext::new();
        ctx.quote = QuoteContext::None;
        ctx.numeric = true;
        assert!(m.generate("' OR 1=1 -- -", &ctx, Some(1)).is_empty());
    }

    #[test]
    fn paren_wrap_preserves_truth_marker() {
        let out = apply_paren_wrap("' OR 1=1 -- -").expect("paren variant");
        assert!(out.contains("(1=1)"), "got {out}");
        let out_false = apply_paren_wrap("' OR 1=2 -- -").expect("paren false variant");
        assert!(out_false.contains("(1=2)"), "got {out_false}");
    }

    #[test]
    fn comment_swap_cycles_without_breaking_terminator() {
        let dash_variant =
            apply_comment_swap("' OR 1=1 -- -", CommentStyle::DashDash).expect("swap -- - -> --");
        assert!(dash_variant.ends_with(" --"), "got {dash_variant}");
        assert!(!dash_variant.ends_with(" -- -"));
        let back = apply_comment_swap(&dash_variant, CommentStyle::DashDash).expect("swap back");
        assert!(back.ends_with(" -- -"), "got {back}");
        let hash_variant =
            apply_comment_swap("' OR 1=1 -- -", CommentStyle::Hash).expect("swap to hash");
        assert!(hash_variant.ends_with('#'), "got {hash_variant}");
    }

    #[test]
    fn case_mix_seeded_deterministic_and_letter_preserving() {
        let a = apply_case_mix("' OR SELECT 1 -- -", Some(11)).expect("case variant");
        let b = apply_case_mix("' OR SELECT 1 -- -", Some(11)).expect("case variant");
        assert_eq!(a, b);
        assert_eq!(a.to_ascii_lowercase(), "' or select 1 -- -");
    }

    #[test]
    fn gate_mirrors_orchestrator_rule() {
        // Confirmé : TRUE.
        assert!(is_confirmed_evidence(
            "boolean true_sim=0.9 trials=3/3",
            0.9
        ));
        // `unconfirmed` ou confiance < 0.5 : jamais de mutation.
        assert!(!is_confirmed_evidence("error 0.55 unconfirmed", 0.55));
        assert!(!is_confirmed_evidence("boolean trials=1/3", 0.4));
    }

    #[test]
    fn gate_blocks_no_mutation_waf_unconfirmed_oob() {
        // Défaut : ON.
        assert!(should_attempt_mutation(false, false, true, false));
        // `--no-mutation` : OFF.
        assert!(!should_attempt_mutation(true, false, true, false));
        // WAF-penalty : pas de spray si blocking.
        assert!(!should_attempt_mutation(false, true, true, false));
        // Jamais sans finding confirmé.
        assert!(!should_attempt_mutation(false, false, false, false));
        // Jamais d'OOB muté.
        assert!(!should_attempt_mutation(false, false, true, true));
    }

    #[test]
    fn disabled_families_yield_nothing() {
        let m = MiniMutator::none();
        assert!(
            m.generate("' OR 1=1 -- -", &default_context(), Some(1))
                .is_empty()
        );
    }

    #[test]
    fn variants_never_duplicate_base() {
        let m = MiniMutator::all_enabled();
        let base = "' OR 1=1 -- -";
        for v in m.generate(base, &default_context(), Some(3)) {
            assert_ne!(v.payload, base);
        }
    }
}
