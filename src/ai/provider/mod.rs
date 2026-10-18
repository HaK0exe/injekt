//! Providers LLM — formats wire `OpenAI` Chat Completions + `Anthropic` Messages.
//!
//! Deux couches :
//! - **pure** (testée sans réseau) : corps de requête + parsing strict vers
//!   `Vec<SuggestedPair>` ;
//! - **HTTP** ([`fetch_suggestions`]) : client `reqwest` dédié (connexion
//!   directe, sans cookies/proxy — l'endpoint recommandé est local), timeout
//!   dédié, `CancellationToken`, clé API en header sans jamais la logger.
//!
//! Schéma de sortie strict imposé au modèle (les deux providers) :
//! `[{"true": "...", "false": "..."}]`, au plus `max_pairs` paires.
//! Tout le reste (texte autour, code fences) est toléré au parsing puis
//! rejeté si hors-schéma. Chaque paire passe ensuite par
//! [`crate::ai::validator::validate_ai_pair`] avant tout envoi cible.

mod anthropic;
mod fetch;
mod openai;
mod parse;
mod types;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests;

pub use anthropic::{ANTHROPIC_VERSION, anthropic_request_body, parse_anthropic_response};
pub use fetch::{AiFetchError, fetch_suggestions};
pub use openai::{openai_request_body, parse_openai_response};
pub use types::{ParseLlmError, SuggestedPair};
