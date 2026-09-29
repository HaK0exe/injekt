#![deny(unsafe_code)]

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

use secrecy::ExposeSecret as _;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio_util::sync::CancellationToken;

use crate::ai::{AiProviderKind, AiSuggestConfig};

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

// ── parsing commun ───────────────────────────────────────────────────

/// Extrait le premier segment JSON du texte (bloc fencé ou prose avec
/// tableau/objet) puis valide le schéma : liste non vide de paires
/// `true`/`false` non vides, tronquée à `max_pairs` (au moins 1).
fn parse_pairs_loose(text: &str, max_pairs: u8) -> Result<Vec<SuggestedPair>, ParseLlmError> {
    let json = extract_json(text).ok_or(ParseLlmError::InvalidJson)?;
    let mut pairs: Vec<SuggestedPair> =
        serde_json::from_str(&json).map_err(|_| ParseLlmError::BadSchema)?;
    if pairs.is_empty() {
        return Err(ParseLlmError::BadSchema);
    }
    // Branches vides = hors-contrat (le validator les rejetterait de toute
    // façon, mais on échoue tôt sans requête cible).
    pairs.retain(|p| !p.true_branch.trim().is_empty() && !p.false_branch.trim().is_empty());
    if pairs.is_empty() {
        return Err(ParseLlmError::BadSchema);
    }
    let cap = usize::from(max_pairs.max(1));
    pairs.truncate(cap);
    Ok(pairs)
}

/// Extrait le premier segment JSON (`[`…`]` ou `{`…`}`) du texte.
/// Supporte les fences ```json … ```. `None` si introuvable.
fn extract_json(text: &str) -> Option<String> {
    let t = text.trim();
    // Fence ```json … ``` ou ``` … ``` : prend le contenu du premier bloc.
    if let Some(start) = t.find("```") {
        let after_open = &t[start + 3..];
        let fence_end = after_open.find('\n').map_or(0, |i| i + 1);
        let inner = &after_open[fence_end..];
        if let Some(close) = inner.find("```") {
            let candidate = inner[..close].trim();
            if candidate.starts_with('[') || candidate.starts_with('{') {
                return Some(candidate.to_owned());
            }
        }
    }
    // premier `[`… dernier `]` (tableau), sinon premier `{`… dernier `}`.
    if let (Some(s), Some(e)) = (t.find('['), t.rfind(']'))
        && s < e
    {
        return Some(t[s..=e].to_owned());
    }
    if let (Some(s), Some(e)) = (t.find('{'), t.rfind('}'))
        && s < e
    {
        // Objet unique → enveloppe en liste pour le schéma commun.
        return Some(format!("[{}]", &t[s..=e]));
    }
    None
}

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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn openai_body_has_json_mode_and_roles() {
        let b = openai_request_body("llama3.1:8b", "SYS", "USER");
        let v: serde_json::Value = serde_json::from_str(&b).expect("valid json");
        assert_eq!(v["model"], "llama3.1:8b");
        assert_eq!(v["temperature"], 0.0);
        assert_eq!(v["response_format"]["type"], "json_object");
        assert_eq!(v["messages"][0]["role"], "system");
        assert_eq!(v["messages"][1]["role"], "user");
    }

    #[test]
    fn openai_parses_choices_content_with_fence() {
        let inner = r#"[{"true": "' OR 1=1 -- -", "false": "' OR 1=2 -- -"}]"#;
        let fenced = format!("```json\n{inner}\n```");
        let body = serde_json::json!({
            "choices": [{"message": {"content": fenced}}]
        })
        .to_string();
        let pairs = parse_openai_response(&body, 3).expect("parse");
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].true_branch, "' OR 1=1 -- -");
    }

    #[test]
    fn openai_rejects_empty_choices_and_bad_schema() {
        assert_eq!(
            parse_openai_response(r#"{"choices": []}"#, 3),
            Err(ParseLlmError::InvalidJson)
        );
        assert_eq!(
            parse_openai_response("not json at all", 3),
            Err(ParseLlmError::InvalidJson)
        );
        let bad = r#"{"choices": [{"message": {"content": "[]"}}]}"#;
        assert_eq!(parse_openai_response(bad, 3), Err(ParseLlmError::BadSchema));
    }

    #[test]
    fn anthropic_body_pins_version_fields() {
        let b = anthropic_request_body("claude-sonnet-4-5", "SYS", "USER");
        let v: serde_json::Value = serde_json::from_str(&b).expect("valid json");
        assert_eq!(v["model"], "claude-sonnet-4-5");
        assert_eq!(v["max_tokens"], 1024);
        assert_eq!(v["system"], "SYS");
        assert_eq!(v["messages"][0]["role"], "user");
        assert_eq!(ANTHROPIC_VERSION, "2023-06-01");
    }

    #[test]
    fn anthropic_concats_text_blocks_and_truncates() {
        let body = r#"{"content": [
            {"type": "text", "text": "intro "},
            {"type": "tool_use", "text": "ignored"},
            {"type": "text", "text": "[{\"true\": \"a OR 1=1\", \"false\": \"a OR 1=2\"}, {\"true\": \"b OR 2=2\", \"false\": \"b OR 2=3\"}]"}
        ]}"#;
        let pairs = parse_anthropic_response(body, 1).expect("parse");
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].true_branch, "a OR 1=1");
    }

    #[test]
    fn extract_json_handles_prose_and_object() {
        let p = extract_json("voici: [1,2] fin").expect("array");
        assert_eq!(p, "[1,2]");
        let o = extract_json("résultat {\"true\": \"x\", \"false\": \"y\"} ok").expect("obj");
        assert!(o.starts_with('['));
        assert!(o.contains("\"true\""));
        assert!(extract_json("aucun json ici").is_none());
    }

    fn openai_cfg(endpoint: &str) -> AiSuggestConfig {
        AiSuggestConfig::from_cli(
            true,
            Some(AiProviderKind::OpenAi),
            Some(endpoint.to_owned()),
            Some("llama3.1:8b".to_owned()),
            None,
            3,
            30,
        )
    }

    fn anthropic_cfg(endpoint: &str) -> AiSuggestConfig {
        AiSuggestConfig::from_cli(
            true,
            Some(AiProviderKind::Anthropic),
            Some(endpoint.to_owned()),
            Some("claude-sonnet-4-5".to_owned()),
            Some(secrecy::SecretString::from("sk-test")),
            3,
            30,
        )
    }

    #[tokio::test]
    async fn fetch_openai_success() {
        use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};
        let server = MockServer::start().await;
        let inner = r#"[{"true": "' OR 1=1 -- -", "false": "' OR 1=2 -- -"}]"#;
        let envelope = serde_json::json!({
            "choices": [{"message": {"content": inner}}]
        })
        .to_string();
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(envelope))
            .mount(&server)
            .await;
        let cfg = openai_cfg(&format!("{}/v1/chat/completions", server.uri()));
        let pairs = fetch_suggestions(&cfg, "SYS", "USER", &CancellationToken::new())
            .await
            .expect("fetch");
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].true_branch, "' OR 1=1 -- -");
    }

    #[tokio::test]
    async fn fetch_anthropic_success_pins_version_header() {
        use wiremock::matchers::header;
        use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};
        let server = MockServer::start().await;
        let inner = r#"[{"true": "' AND 1=1 -- -", "false": "' AND 1=2 -- -"}]"#;
        let envelope = serde_json::json!({
            "content": [{"type": "text", "text": inner}]
        })
        .to_string();
        Mock::given(method("POST"))
            .and(header("anthropic-version", ANTHROPIC_VERSION))
            .and(header("x-api-key", "sk-test"))
            .respond_with(ResponseTemplate::new(200).set_body_string(envelope))
            .mount(&server)
            .await;
        let cfg = anthropic_cfg(&format!("{}/v1/messages", server.uri()));
        let pairs = fetch_suggestions(&cfg, "SYS", "USER", &CancellationToken::new())
            .await
            .expect("fetch");
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].false_branch, "' AND 1=2 -- -");
    }

    #[tokio::test]
    async fn fetch_bad_status_and_cancelled() {
        use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        let cfg = openai_cfg(&format!("{}/v1/chat/completions", server.uri()));
        assert_eq!(
            fetch_suggestions(&cfg, "SYS", "USER", &CancellationToken::new()).await,
            Err(AiFetchError::BadStatus(500))
        );
        let cancelled = CancellationToken::new();
        cancelled.cancel();
        assert_eq!(
            fetch_suggestions(&cfg, "SYS", "USER", &cancelled).await,
            Err(AiFetchError::Cancelled)
        );
    }

    #[tokio::test]
    async fn fetch_incomplete_never_calls_network() {
        // Config par défaut : 0 appel, même avec un endpoint valide.
        let cfg = AiSuggestConfig::default();
        assert_eq!(
            fetch_suggestions(&cfg, "SYS", "USER", &CancellationToken::new()).await,
            Err(AiFetchError::Incomplete)
        );
    }
}
