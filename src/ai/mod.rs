#![deny(unsafe_code)]

//! Opt-in `--ai-suggest` second-pass (post-échec / WAF-block uniquement).
//!
//! OFF par défaut = 0 appel LLM, comportement historique byte-identical.
//! ON = le gate [`should_attempt_ai_suggest`] autorise un seul passage par
//! paramètre, après la détection classique, uniquement quand le run est
//! reparti bredouille face à un signal de blocage/filtrage :
//! WAF (`403/406/429` ou challenge), filtre applicatif (`400` streak), ou
//! `--confirm` droppé. Jamais en détection première, jamais sur origine
//! down (5xx), jamais sous budget/deadline épuisés, jamais sur OOB seul.
//!
//! OPSEC : le prompt ([`prompt`]) n'embarque que des signaux abstraits —
//! jamais cookies/headers/body cible/extracted data. La clé API reste un
//! `secrecy::SecretString` + `zeroize`, redacted en `Debug`/logs via
//! [`crate::session::scrubber::Scrubber`]. Toute suggestion LLM passe par
//! [`validator`] avant le moindre envoi réseau vers la cible.

pub mod prompt;
pub mod provider;
pub mod validator;

use secrecy::SecretString;

/// Bornes `--ai-max-suggestions` (`1..=5`, défaut 3). 1 paire = 2 requêtes.
pub const MIN_AI_SUGGESTIONS: u8 = 1;
/// Nombre maximal de paires suggérées par paramètre.
pub const MAX_AI_SUGGESTIONS: u8 = 5;
/// Valeur par défaut (3 paires = 6 requêtes max par paramètre).
pub const DEFAULT_AI_SUGGESTIONS: u8 = 3;
/// Timeout HTTP par défaut des appels provider (secondes).
pub const DEFAULT_AI_TIMEOUT_SECS: u64 = 30;

/// Provider wire format (`--ai-provider`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AiProviderKind {
    /// `OpenAI` Chat Completions (`/v1/chat/completions`).
    OpenAi,
    /// `Anthropic` Messages (`/v1/messages`).
    Anthropic,
}

impl AiProviderKind {
    /// Nom canonique (`--ai-provider`, logs, traces hashes-only).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::OpenAi => "openai",
            Self::Anthropic => "anthropic",
        }
    }

    /// Parse insensible à la casse/espaces. Inconnu → `None` (fail-closed).
    #[must_use]
    pub fn from_name(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "openai" => Some(Self::OpenAi),
            "anthropic" => Some(Self::Anthropic),
            _ => None,
        }
    }
}

impl core::fmt::Display for AiProviderKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Configuration résolue du second-pass IA (RAM-only, jamais persistée).
#[non_exhaustive]
#[derive(Clone)]
pub struct AiSuggestConfig {
    /// `--ai-suggest` (maître). `false` = chemin byte-identical.
    pub enabled: bool,
    /// Provider (`None` = non résolu → le gate refuse).
    pub provider: Option<AiProviderKind>,
    /// Endpoint LLM (jamais loggé en clair : userinfo/query scrubbed).
    pub endpoint: Option<String>,
    /// Modèle (ex. `llama3.1:8b`, `claude-sonnet-4-5`).
    pub model: Option<String>,
    /// Clé API (jamais loggée, jamais dans le prompt).
    pub api_key: Option<SecretString>,
    /// Paires max par paramètre (`1..=5`).
    pub max_suggestions: u8,
    /// Timeout HTTP provider (secondes).
    pub timeout_secs: u64,
}

// `Debug` manuel : endpoint scrubbed, clé `[REDACTED]`, jamais de secret.
impl core::fmt::Debug for AiSuggestConfig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let scrub = crate::session::scrubber::Scrubber::new(false);
        f.debug_struct("AiSuggestConfig")
            .field("enabled", &self.enabled)
            .field("provider", &self.provider)
            .field(
                "endpoint",
                &self.endpoint.as_deref().map(|e| scrub.scrub(e)),
            )
            .field("model", &self.model)
            .field(
                "api_key",
                &self.api_key.as_ref().map(|_| "[REDACTED]".to_owned()),
            )
            .field("max_suggestions", &self.max_suggestions)
            .field("timeout_secs", &self.timeout_secs)
            .finish_non_exhaustive()
    }
}

impl Default for AiSuggestConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            provider: None,
            endpoint: None,
            model: None,
            api_key: None,
            max_suggestions: DEFAULT_AI_SUGGESTIONS,
            timeout_secs: DEFAULT_AI_TIMEOUT_SECS,
        }
    }
}

impl AiSuggestConfig {
    /// Construit depuis la CLI résolue. Les valeurs absurdes sont clampées
    /// (constructions manuelles hors clap) ; l'absence de provider/endpoint/
    /// model avec `enabled` fait échouer le gate (fail-closed, voir
    /// `Cli::validate_ai_opts` pour le fail-fast CLI).
    #[must_use]
    pub fn from_cli(
        enabled: bool,
        provider: Option<AiProviderKind>,
        endpoint: Option<String>,
        model: Option<String>,
        api_key: Option<SecretString>,
        max_suggestions: u8,
        timeout_secs: u64,
    ) -> Self {
        let capped = max_suggestions.clamp(MIN_AI_SUGGESTIONS, MAX_AI_SUGGESTIONS);
        Self {
            enabled,
            provider,
            endpoint,
            model,
            api_key,
            max_suggestions: capped,
            timeout_secs: timeout_secs.max(1),
        }
    }

    /// `true` ssi la config est complète pour un appel provider.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.enabled
            && self.provider.is_some()
            && self
                .endpoint
                .as_deref()
                .is_some_and(|e| !e.trim().is_empty())
            && self.model.as_deref().is_some_and(|m| !m.trim().is_empty())
    }
}

/// Porte d'entrée unique du second-pass IA : `true` ssi une suggestion peut
/// être tentée pour ce paramètre.
///
/// - `enabled` : `--ai-suggest` (OFF = byte-identical, 0 appel).
/// - `findings_empty` : le run classique n'a rien confirmé sur ce param.
/// - `trigger` : au moins un signal d'échec actionnable — WAF bloquant
///   (`is_waf_blocked() || is_waf_blocking()`), filtre applicatif
///   (`filter_streak >= FILTER_STREAK_LIMIT`), ou `--confirm` droppé.
/// - `hard_stop` : verrou global — origine down (`baseline_all_error`),
///   budget épuisé, deadline dépassée, `cancel` trippé, ou OOB seul
///   (jamais de suggestion OOB/stackée).
// 4 booléens positionnels = la porte elle-même (même pattern que
// `mutation::should_attempt_mutation`) ; appel unique côté orchestrateur.
#[allow(clippy::fn_params_excessive_bools)]
#[must_use]
pub const fn should_attempt_ai_suggest(
    enabled: bool,
    findings_empty: bool,
    trigger: bool,
    hard_stop: bool,
) -> bool {
    enabled && findings_empty && trigger && !hard_stop
}

/// Combine les trois déclencheurs d'échec en un seul signal `trigger`.
#[allow(clippy::fn_params_excessive_bools)]
#[must_use]
pub const fn ai_trigger(waf_signal: bool, filter_hit: bool, confirm_dropped: bool) -> bool {
    waf_signal || filter_hit || confirm_dropped
}

/// Combine les verrous globaux en un seul `hard_stop`.
#[allow(clippy::fn_params_excessive_bools)]
#[must_use]
pub const fn ai_hard_stop(
    baseline_all_error: bool,
    budget_exhausted: bool,
    deadline_past: bool,
    cancelled: bool,
    oob_only: bool,
) -> bool {
    baseline_all_error || budget_exhausted || deadline_past || cancelled || oob_only
}

/// Label de trace hashes-only (`ai:<provider>+<n>`, jamais de payload).
#[must_use]
pub fn ai_plan_label(provider: AiProviderKind, index: u8) -> String {
    format!("ai:{}+{index}", provider.name())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn gate_mirrors_spec() {
        // Défaut OFF : jamais.
        assert!(!should_attempt_ai_suggest(false, true, true, false));
        // Findings présents : jamais (pas de spray sur cible confirmée).
        assert!(!should_attempt_ai_suggest(true, false, true, false));
        // Sans trigger : jamais.
        assert!(!should_attempt_ai_suggest(true, true, false, false));
        // Hard stop : jamais.
        assert!(!should_attempt_ai_suggest(true, true, true, true));
        // Cas nominal : post-échec avec signal.
        assert!(should_attempt_ai_suggest(true, true, true, false));
    }

    #[test]
    fn trigger_is_any_signal() {
        assert!(!ai_trigger(false, false, false));
        assert!(ai_trigger(true, false, false));
        assert!(ai_trigger(false, true, false));
        assert!(ai_trigger(false, false, true));
        assert!(ai_trigger(true, true, true));
    }

    #[test]
    fn hard_stop_is_any_lock() {
        assert!(!ai_hard_stop(false, false, false, false, false));
        assert!(ai_hard_stop(true, false, false, false, false));
        assert!(ai_hard_stop(false, true, false, false, false));
        assert!(ai_hard_stop(false, false, true, false, false));
        assert!(ai_hard_stop(false, false, false, true, false));
        assert!(ai_hard_stop(false, false, false, false, true));
    }

    #[test]
    fn provider_names_roundtrip() {
        assert_eq!(
            AiProviderKind::from_name("openai"),
            Some(AiProviderKind::OpenAi)
        );
        assert_eq!(
            AiProviderKind::from_name("  ANTHROPIC "),
            Some(AiProviderKind::Anthropic)
        );
        assert_eq!(AiProviderKind::from_name("nope"), None);
        assert_eq!(AiProviderKind::OpenAi.name(), "openai");
        assert_eq!(AiProviderKind::Anthropic.name(), "anthropic");
    }

    #[test]
    fn config_clamps_and_completeness() {
        let cfg = AiSuggestConfig::from_cli(false, None, None, None, None, 0, 0);
        assert_eq!(cfg.max_suggestions, MIN_AI_SUGGESTIONS);
        assert_eq!(cfg.timeout_secs, 1);
        assert!(!cfg.is_complete());
        let cfg = AiSuggestConfig::from_cli(
            true,
            Some(AiProviderKind::OpenAi),
            Some("http://localhost:11434/v1/chat/completions".to_owned()),
            Some("llama3.1:8b".to_owned()),
            None,
            9,
            30,
        );
        assert_eq!(cfg.max_suggestions, MAX_AI_SUGGESTIONS);
        assert!(cfg.is_complete());
        // Clé locale absente = OK (gateway local sans auth).
    }

    #[test]
    fn debug_never_leaks_key_or_endpoint_secrets() {
        let cfg = AiSuggestConfig::from_cli(
            true,
            Some(AiProviderKind::Anthropic),
            Some("https://api.anthropic.com/v1/messages?token=s3cr3t".to_owned()),
            Some("claude-sonnet-4-5".to_owned()),
            Some(SecretString::from("sk-ant-s3cr3t")),
            3,
            30,
        );
        let dbg = format!("{cfg:?}");
        assert!(!dbg.contains("sk-ant-s3cr3t"), "clé en clair: {dbg}");
        assert!(!dbg.contains("s3cr3t"), "secret endpoint: {dbg}");
        assert!(dbg.contains("[REDACTED]"), "marqueur absent: {dbg}");
        // La clé existe bien en mémoire (pas d'effacement accidentel).
        assert_eq!(
            cfg.api_key
                .as_ref()
                .map(secrecy::ExposeSecret::expose_secret),
            Some("sk-ant-s3cr3t")
        );
    }

    #[test]
    fn plan_label_is_hash_only() {
        assert_eq!(ai_plan_label(AiProviderKind::OpenAi, 0), "ai:openai+0");
        assert_eq!(
            ai_plan_label(AiProviderKind::Anthropic, 2),
            "ai:anthropic+2"
        );
    }
}
