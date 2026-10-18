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
//!   respectant [`crate::dbms::context::CommentStyle`].
//! - `case_mix` : mélange de casse déterministe (seedé).
//!
//! Aucun plugin system (décision roadmap : pas de `C8` en v1.0) : ce module
//! est un mini-mutateur fermé, pas un registre extensible.

mod apply;
mod gate;
mod mutator;
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests;
mod types;

pub use gate::{is_confirmed_evidence, should_attempt_mutation};
pub use mutator::MiniMutator;
pub use types::{
    MAX_MUTATION_REQUESTS_PER_FINDING, MAX_MUTATION_VARIANTS, MutatedVariant, MutationFamily,
};
