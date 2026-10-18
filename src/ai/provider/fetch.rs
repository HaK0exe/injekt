use secrecy::ExposeSecret as _;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

use super::anthropic::{ANTHROPIC_VERSION, anthropic_request_body, parse_anthropic_response};
use super::openai::{openai_request_body, parse_openai_response};
use super::types::{ParseLlmError, SuggestedPair};
use crate::ai::{AiProviderKind, AiSuggestConfig};

// ── envoi HTTP ───────────────────────────────────────────────────────

/// Erreur d'appel provider (endpoint/URL scrubbed, jamais de clé en clair).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AiFetchError {
    /// Config incomplète (`!is_complete()`) : 0 appel réseau.
    Incomplete,
    /// Annulé (`CancellationToken`) avant ou pendant l'appel.
    Cancelled,
    /// Erreur réseau/timeout/construction client (message statique + statut,
    /// jamais l'URL brute ni la clé).
    Network(String),
    /// Statut HTTP non-2xx du provider.
    BadStatus(u16),
    /// Réponse illisible ou hors-schéma.
    Parse(ParseLlmError),
}

impl core::fmt::Display for AiFetchError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Incomplete => write!(f, "incomplete AI config"),
            Self::Cancelled => write!(f, "AI fetch cancelled"),
            Self::Network(msg) => write!(f, "AI network error: {msg}"),
            Self::BadStatus(code) => write!(f, "AI provider status {code}"),
            Self::Parse(e) => write!(f, "AI response error: {e}"),
        }
    }
}

impl std::error::Error for AiFetchError {}

/// Appelle le provider LLM et retourne au plus `cfg.max_suggestions` paires
/// brutes (à valider via [`crate::ai::validator::validate_ai_pair`] avant
/// tout envoi cible).
///
/// Client `reqwest` dédié : connexion directe sans cookies ni proxy (endpoint
/// local recommandé), timeout `cfg.timeout_secs`. La clé API ne transite
/// qu'en header (`Authorization: Bearer` côté `OpenAI`, `x-api-key` côté
/// `Anthropic`) et n'apparaît dans aucun log/erreur. Échec silencieux côté
/// appelant : toute `Err` signifie "pas de suggestion", jamais de finding.
///
/// # Errors
/// - [`AiFetchError::Incomplete`] : config incomplète (0 réseau).
/// - [`AiFetchError::Cancelled`] : `cancel` trippé.
/// - [`AiFetchError::Network`] : client/réseau/timeout/body.
/// - [`AiFetchError::BadStatus`] : statut non-2xx.
/// - [`AiFetchError::Parse`] : réponse hors-contrat.
pub async fn fetch_suggestions(
    cfg: &AiSuggestConfig,
    system: &str,
    user: &str,
    cancel: &CancellationToken,
) -> Result<Vec<SuggestedPair>, AiFetchError> {
    if !cfg.is_complete() {
        return Err(AiFetchError::Incomplete);
    }
    if cancel.is_cancelled() {
        return Err(AiFetchError::Cancelled);
    }
    let provider = cfg.provider.ok_or(AiFetchError::Incomplete)?;
    let endpoint = cfg.endpoint.as_deref().unwrap_or("").trim();
    let model = cfg.model.as_deref().unwrap_or("").trim();
    if endpoint.is_empty() || model.is_empty() {
        return Err(AiFetchError::Incomplete);
    }
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(cfg.timeout_secs.max(1)))
        .build()
        .map_err(|_| AiFetchError::Network("client build failed".to_owned()))?;
    let (body, mut req) = match provider {
        AiProviderKind::OpenAi => {
            let body = openai_request_body(model, system, user);
            let mut req = client
                .post(endpoint)
                .header("Content-Type", "application/json");
            if let Some(key) = cfg.api_key.as_ref() {
                let exposed = key.expose_secret();
                let mut bearer = String::with_capacity(exposed.len() + 7);
                bearer.push_str("Bearer ");
                bearer.push_str(exposed);
                req = req.header("Authorization", bearer);
            }
            (body, req)
        }
        AiProviderKind::Anthropic => {
            let body = anthropic_request_body(model, system, user);
            let mut req = client
                .post(endpoint)
                .header("Content-Type", "application/json")
                .header("anthropic-version", ANTHROPIC_VERSION);
            if let Some(key) = cfg.api_key.as_ref() {
                req = req.header("x-api-key", key.expose_secret());
            }
            (body, req)
        }
    };
    req = req.body(body);
    let resp = tokio::select! {
        () = cancel.cancelled() => return Err(AiFetchError::Cancelled),
        res = req.send() => res.map_err(|_| AiFetchError::Network("request failed".to_owned()))?,
    };
    if cancel.is_cancelled() {
        return Err(AiFetchError::Cancelled);
    }
    let status = resp.status();
    if !status.is_success() {
        return Err(AiFetchError::BadStatus(status.as_u16()));
    }
    let text = tokio::select! {
        () = cancel.cancelled() => return Err(AiFetchError::Cancelled),
        res = resp.text() => res.map_err(|_| AiFetchError::Network("body read failed".to_owned()))?,
    };
    let max_pairs = cfg.max_suggestions;
    match provider {
        AiProviderKind::OpenAi => {
            parse_openai_response(&text, max_pairs).map_err(AiFetchError::Parse)
        }
        AiProviderKind::Anthropic => {
            parse_anthropic_response(&text, max_pairs).map_err(AiFetchError::Parse)
        }
    }
}
