use super::apply::{apply_case_mix, apply_comment_swap, apply_paren_wrap, apply_quote_fence};
use super::types::{MAX_MUTATION_VARIANTS, MutatedVariant, MutationFamily, push_variant};
use crate::dbms::context::InjectionContext;

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
