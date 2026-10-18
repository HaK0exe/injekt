use serde::{Deserialize, Serialize};

use super::parse::parse_pairs_loose;
use super::types::{ParseLlmError, SuggestedPair};

// ── `Anthropic` Messages ───────────────────────────────────────────────

/// Corps de requête `Anthropic` (`POST {endpoint}` + headers `x-api-key`,
/// `anthropic-version: 2023-06-01` à l'envoi).
#[derive(Debug, Clone, Serialize)]
struct AnthropicRequest {
    model: String,
    max_tokens: u32,
    system: String,
    messages: Vec<AnthropicMessage>,
}

/// Message `Anthropic`.
#[derive(Debug, Clone, Serialize)]
struct AnthropicMessage {
    role: String,
    content: String,
}

/// Réponse `Anthropic` (blocs `content[]`, texte concaténé).
#[derive(Debug, Clone, Deserialize)]
struct AnthropicResponse {
    content: Vec<AnthropicBlock>,
}

/// Bloc de contenu `Anthropic`.
#[derive(Debug, Clone, Deserialize)]
struct AnthropicBlock {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    text: String,
}

/// Version d'API `Anthropic` épinglée à l'envoi.
pub const ANTHROPIC_VERSION: &str = "2023-06-01";

/// Construit le corps JSON `Anthropic` (pur, testé).
#[must_use]
pub fn anthropic_request_body(model: &str, system: &str, user: &str) -> String {
    let req = AnthropicRequest {
        model: model.to_owned(),
        max_tokens: 1024,
        system: system.to_owned(),
        messages: vec![AnthropicMessage {
            role: "user".to_owned(),
            content: user.to_owned(),
        }],
    };
    serde_json::to_string(&req).unwrap_or_else(|_| "{}".to_owned())
}

/// Parse une réponse `Anthropic` vers au plus `max_pairs` paires.
///
/// # Errors
/// Retourne [`ParseLlmError::InvalidJson`] si l'enveloppe est illisible,
/// [`ParseLlmError::BadSchema`] si le contenu est hors-contrat.
pub fn parse_anthropic_response(
    body: &str,
    max_pairs: u8,
) -> Result<Vec<SuggestedPair>, ParseLlmError> {
    let resp: AnthropicResponse =
        serde_json::from_str(body).map_err(|_| ParseLlmError::InvalidJson)?;
    let mut text = String::new();
    for block in &resp.content {
        if block.kind == "text" {
            text.push_str(&block.text);
        }
    }
    parse_pairs_loose(&text, max_pairs)
}
