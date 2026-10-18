use super::mapping::{normalize_context_class, normalize_dbms, parse_technique};
use crate::session::state::TechniqueKind;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

/// Version du schéma du fichier knowledge (gelée en v1.0-rc).
pub const KNOWLEDGE_SCHEMA_VERSION: u8 = 1;
/// Échantillons minimum avant tout boost (cold-start neutre, anti-surconfiance).
pub const MIN_SAMPLES: u64 = 10;
/// Borne de `alpha` : `boost = 1 + alpha`, `alpha ∈ [-0.5, +0.5]`.
pub const MAX_ALPHA: f64 = 0.5;
/// Borne basse du boost knowledge (avant clamp scheduler `[0.5, 2.0]`).
pub const KNOWLEDGE_MIN_BOOST: f64 = 0.5;
/// Borne haute du boost knowledge (avant clamp scheduler `[0.5, 2.0]`).
pub const KNOWLEDGE_MAX_BOOST: f64 = 1.5;
/// Nom du fichier sous `~/.cache/injekt/`.
pub const KNOWLEDGE_FILE_NAME: &str = "knowledge.json";

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum KnowledgeError {
    #[error("io error: {0}")]
    Io(String),
    #[error("serialization error: {0}")]
    Serialization(String),
}

/// Clé d'agrégat anonyme `(technique, dbms, context_class)`, vocabulaire fermé.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub struct KnowledgeKey {
    pub technique: String,
    pub dbms: String,
    pub context_class: String,
}

impl KnowledgeKey {
    #[must_use]
    pub fn new(technique: TechniqueKind, dbms: &str, context_class: &str) -> Self {
        Self {
            technique: technique.to_string(),
            dbms: normalize_dbms(dbms).to_owned(),
            context_class: normalize_context_class(context_class).to_owned(),
        }
    }

    /// Clé sérialisée `technique|dbms|context_class` (format fichier v1).
    #[must_use]
    pub fn flattened(&self) -> String {
        format!("{}|{}|{}", self.technique, self.dbms, self.context_class)
    }

    /// Parse inverse de [`Self::flattened`], avec normalisation stricte.
    /// Retourne `None` si la clé n'appartient pas au vocabulaire fermé.
    #[must_use]
    pub fn parse_flattened(s: &str) -> Option<Self> {
        let (tech, rest) = s.split_once('|')?;
        let (dbms, ctx) = rest.split_once('|')?;
        let technique = parse_technique(tech)?;
        Some(Self::new(technique, dbms, ctx))
    }
}

/// Compteurs agrégés anonymes pour une clé.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct KnowledgeEntry {
    pub success: u64,
    pub trials: u64,
    pub avg_req: f64,
}

impl Default for KnowledgeEntry {
    fn default() -> Self {
        Self {
            success: 0,
            trials: 0,
            avg_req: 0.0,
        }
    }
}

/// Store knowledge : agrégats seuls, aucun identifiant.
#[derive(Debug, Clone, Default, PartialEq)]
#[non_exhaustive]
pub struct KnowledgeStore {
    pub version: u8,
    pub entries: HashMap<KnowledgeKey, KnowledgeEntry>,
}
