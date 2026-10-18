use serde::{Deserialize, Serialize};

/// Paire brute suggérée par le LLM (avant validation locale).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct SuggestedPair {
    /// Branche TRUE candidate.
    #[serde(rename = "true")]
    pub true_branch: String,
    /// Branche FALSE candidate (même shape).
    #[serde(rename = "false")]
    pub false_branch: String,
}

/// Erreur de parsing de réponse LLM (jamais de payload/clef en clair).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseLlmError {
    /// JSON introuvable ou invalide.
    InvalidJson,
    /// Schéma hors-contrat (champs manquants, liste vide, trop de paires).
    BadSchema,
}

impl core::fmt::Display for ParseLlmError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidJson => write!(f, "invalid LLM JSON"),
            Self::BadSchema => write!(f, "LLM response off-schema"),
        }
    }
}

impl std::error::Error for ParseLlmError {}
