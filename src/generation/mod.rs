#![deny(unsafe_code)]

//! Génération d'injections à la volée par grammaire déterministe (Track A).
//!
//! OFF par défaut = listes historiques, comportement byte-identical.
//! ON (`--generative conservative|aggressive`) = les paires historiques
//! d'abord (ordre inchangé), puis des paires synthétisées (fences ×
//! logiques × prédicats, [`grammar`]) jusqu'au budget :
//! - `Conservative` : prédicats noyau (`EqInt`/`EqStr`/`Like`/`In`/`Between`).
//! - `Aggressive` : tous les prédicats (noyau + `Rlike`/`CaseWhen`/`Div`/
//!   `Xor`/`ChrFunc`, ce dernier dialectisé par `DbmsKind`).
//!
//! Pur et seedé (`--seed` rejoue à l'identique) ; la dédup contre
//! l'historique évite toute requête redondante ; le pipeline tampers,
//! l'évaluation et les budgets (`payload_budget`) sont inchangés.

pub mod builder;
pub mod grammar;

pub use builder::{
    GeneratedCandidate, build_pair, candidate_label, dedupe_against, enumerate_candidates,
};
pub use grammar::{Logic, Predicate, QuoteFence, Separator, comment_for};

/// Plafond `--max-generated` (paires générées par paramètre et par
/// technique). `0` = génération désactivée même en mode ON. CYCLIQUE :
/// une fenêtre de 32 couvre l'écart max 16 entre paires spaceless quelle
/// que soit la rotation seed (garantie, pas de chance).
pub const MAX_GENERATED: u8 = 32;
/// Défaut `--max-generated` (conservateur : 2 historiques L1 + 4 générées).
pub const DEFAULT_MAX_GENERATED: u8 = 4;

/// Mode de génération (`--generative`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum GenerativeMode {
    /// Listes historiques uniquement (défaut, byte-identical).
    #[default]
    Off,
    /// Historique + prédicats noyau générés.
    Conservative,
    /// Tout l'historique + tous les prédicats générés.
    Aggressive,
}

impl GenerativeMode {
    /// Nom canonique (`--generative`, logs, traces).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Conservative => "conservative",
            Self::Aggressive => "aggressive",
        }
    }

    /// Parse insensible à la casse/espaces. Inconnu → `None` (fail-closed → OFF).
    #[must_use]
    pub fn from_name(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "off" => Some(Self::Off),
            "conservative" => Some(Self::Conservative),
            "aggressive" => Some(Self::Aggressive),
            _ => None,
        }
    }

    /// `true` quand la génération est active.
    #[must_use]
    pub const fn is_active(self) -> bool {
        !matches!(self, Self::Off)
    }
}

impl core::fmt::Display for GenerativeMode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Configuration résolue (RAM-only, aucun secret).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct GenerativeConfig {
    /// Mode (`Off` = byte-identical).
    pub mode: GenerativeMode,
    /// Paires générées max (`0..=MAX_GENERATED`).
    pub max_generated: u8,
}

impl Default for GenerativeConfig {
    fn default() -> Self {
        Self {
            mode: GenerativeMode::Off,
            max_generated: DEFAULT_MAX_GENERATED,
        }
    }
}

impl GenerativeConfig {
    /// Construit depuis la CLI résolue (clamp défensif `0..=MAX_GENERATED`
    /// pour les constructions manuelles hors clap).
    #[must_use]
    pub const fn from_parts(mode: GenerativeMode, max_generated: u8) -> Self {
        let capped = if max_generated > MAX_GENERATED {
            MAX_GENERATED
        } else {
            max_generated
        };
        Self {
            mode,
            max_generated: capped,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn mode_names_roundtrip() {
        assert_eq!(
            GenerativeMode::from_name("conservative"),
            Some(GenerativeMode::Conservative)
        );
        assert_eq!(
            GenerativeMode::from_name("  AGGRESSIVE "),
            Some(GenerativeMode::Aggressive)
        );
        assert_eq!(GenerativeMode::from_name("off"), Some(GenerativeMode::Off));
        assert_eq!(GenerativeMode::from_name("nope"), None);
        assert!(!GenerativeMode::Off.is_active());
        assert!(GenerativeMode::Conservative.is_active());
    }

    #[test]
    fn config_clamps_and_defaults() {
        let d = GenerativeConfig::default();
        assert_eq!(d.mode, GenerativeMode::Off);
        assert_eq!(d.max_generated, DEFAULT_MAX_GENERATED);
        let c = GenerativeConfig::from_parts(GenerativeMode::Aggressive, 255);
        assert_eq!(c.max_generated, MAX_GENERATED);
        let z = GenerativeConfig::from_parts(GenerativeMode::Conservative, 0);
        assert_eq!(z.max_generated, 0);
    }
}
