use serde::{Deserialize, Serialize};

use super::parse::parse_pairs_loose;
use super::types::{ParseLlmError, SuggestedPair};

// ── `OpenAI` Chat Completions ──────────────────────────────────────────

/// Corps de requête `OpenAI` (`POST {endpoint}`).
#[derive(Debug, Clone, Serialize)]
struct OpenAiRequest {
    model: String,
    messages: Vec<OpenAiMessage>,
    temperature: f32,
    response_format: OpenAiResponseFormat,
}

/// Message chat `OpenAI`.
#[derive(Debug, Clone, Serialize)]
struct OpenAiMessage {
    role: String,
    content: String,
}

/// Force le mode JSON (`json_object`).
#[derive(Debug, Clone, Serialize)]
struct OpenAiResponseFormat {
    #[serde(rename = "type")]
    kind: String,
}

/// Réponse `OpenAI` (champs utiles uniquement, reste ignoré).
#[derive(Debug, Clone, Deserialize)]
struct OpenAiResponse {
    choices: Vec<OpenAiChoice>,
}

/// Choix `OpenAI`.
#[derive(Debug, Clone, Deserialize)]
struct OpenAiChoice {
    message: OpenAiChoiceMessage,
}

/// Message de choix `OpenAI`.
#[derive(Debug, Clone, Deserialize)]
struct OpenAiChoiceMessage {
    content: String,
}

/// Construit le corps JSON `OpenAI` (pur, testé).
#[must_use]
pub fn openai_request_body(model: &str, system: &str, user: &str) -> String {
    let req = OpenAiRequest {
        model: model.to_owned(),
        messages: vec![
            OpenAiMessage {
                role: "system".to_owned(),
                content: system.to_owned(),
            },
            OpenAiMessage {
                role: "user".to_owned(),
                content: user.to_owned(),
            },
        ],
        temperature: 0.0,
        response_format: OpenAiResponseFormat {
            kind: "json_object".to_owned(),
        },
    };
    serde_json::to_string(&req).unwrap_or_else(|_| "{}".to_owned())
}

/// Parse une réponse `OpenAI` vers au plus `max_pairs` paires.
/// Tolère code fences et texte autour du JSON.
///
/// # Errors
/// Retourne [`ParseLlmError::InvalidJson`] si l'enveloppe est illisible,
/// [`ParseLlmError::BadSchema`] si le contenu est hors-contrat.
pub fn parse_openai_response(
    body: &str,
    max_pairs: u8,
) -> Result<Vec<SuggestedPair>, ParseLlmError> {
    let resp: OpenAiResponse =
        serde_json::from_str(body).map_err(|_| ParseLlmError::InvalidJson)?;
    let content = resp
        .choices
        .first()
        .map_or("", |c| c.message.content.as_str());
    parse_pairs_loose(content, max_pairs)
}
