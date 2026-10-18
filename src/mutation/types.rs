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
pub(super) fn push_variant(
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
