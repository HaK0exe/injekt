#![allow(clippy::unwrap_used, clippy::expect_used)]

//! `--ai-suggest` end-to-end (double-mock `wiremock`) :
//! fausse cible WAF (baseline `200` propre, `403` sur payloads `OR`,
//! différentiel uniquement sur la paire `AND 7=7/7=8` du LLM) + faux
//! endpoint LLM (`OpenAI` et `Anthropic`).
//!
//! - `ai_suggest_finds_waf_blocked_boolean_via_openai` : 1 finding
//!   `Boolean` avec `ai:openai+0` en évidence, LLM appelé exactement 1 fois,
//!   phase IA ≤ 2 requêtes cible (1 paire).
//! - `ai_suggest_off_stays_silent_byte_identical` : même cible, AI OFF →
//!   0 finding, 0 appel LLM.
//! - `ai_suggest_finds_via_anthropic` : même scénario en format `Anthropic`
//!   Messages (contrat headers + parsing).

use injekt::{
    ai::{AiProviderKind, AiSuggestConfig},
    engine::{Engine, EngineConfig},
    http::{client::HttpClient, jitter::Jitter, rate_limit::RateLimiter},
};
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};

const BASELINE_BODY: &str = "welcome page id=1 normal content row";
const ALT_BODY: &str = "no results found nothing here";

fn test_client() -> HttpClient {
    HttpClient::builder()
        .timeout(Duration::from_secs(10))
        .jitter(Jitter::new(1.0, 0.5).with_min(0))
        .rate_limiter(std::sync::Arc::new(RateLimiter::disabled()))
        .allow_private(true)
        .build()
        .expect("client build")
}

/// WAF simulé : `403` sur tout payload contenant `OR` (les sondes boolean
/// classiques meurent ici), `200` sinon ; différentiel réservé aux littéraux
/// `7=7` (TRUE, corps baseline) vs `7=8` (FALSE, corps alternatif) que seul
/// le LLM suggère (les payloads natifs utilisent `1=1`/`1=2` → corps
/// identiques → pas de différentiel).
fn waf_responder(req: &wiremock::Request) -> ResponseTemplate {
    let url = req.url.to_string();
    let upper = url.to_ascii_uppercase();
    // `%27` = `'`, `%3D` = `=`. Les littéraux IA sont les seuls en `7`.
    if url.contains("7%3D7") || url.contains("7=7") {
        return ResponseTemplate::new(200).set_body_string(BASELINE_BODY);
    }
    if url.contains("7%3D8") || url.contains("7=8") {
        return ResponseTemplate::new(200).set_body_string(ALT_BODY);
    }
    if upper.contains("OR") {
        return ResponseTemplate::new(403).set_body_string("blocked by waf");
    }
    ResponseTemplate::new(200).set_body_string(BASELINE_BODY)
}

async fn mount_target() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(waf_responder)
        .mount(&server)
        .await;
    server
}

async fn mount_openai_llm(pair_true: &str, pair_false: &str) -> MockServer {
    let server = MockServer::start().await;
    let envelope = serde_json::json!({
        "choices": [{"message": {"content": serde_json::json!([
            {"true": pair_true, "false": pair_false}
        ]).to_string()}}]
    })
    .to_string();
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(envelope))
        .mount(&server)
        .await;
    server
}

async fn mount_anthropic_llm(pair_true: &str, pair_false: &str) -> MockServer {
    let server = MockServer::start().await;
    let envelope = serde_json::json!({
        "content": [{"type": "text", "text": serde_json::json!([
            {"true": pair_true, "false": pair_false}
        ]).to_string()}]
    })
    .to_string();
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(envelope))
        .mount(&server)
        .await;
    server
}

fn boolean_cfg_with_ai(ai: AiSuggestConfig) -> EngineConfig {
    let mut cfg = EngineConfig::default();
    cfg.budget.threads = 1;
    cfg.techniques = vec!["boolean".to_owned()];
    cfg.budget.level = 1;
    cfg.net.allow_private = true;
    cfg.no_redact = true;
    cfg.enumeration.extract = false;
    cfg.ai = ai;
    cfg
}

async fn llm_calls(server: &MockServer, path: &str) -> usize {
    server
        .received_requests()
        .await
        .iter()
        .flatten()
        .filter(|r| r.url.path() == path)
        .count()
}

async fn target_ai_probes(server: &MockServer) -> usize {
    server
        .received_requests()
        .await
        .iter()
        .flatten()
        .filter(|r| {
            let q = r.url.to_string();
            q.contains("7%3D7") || q.contains("7%3D8") || q.contains("7=7") || q.contains("7=8")
        })
        .count()
}

#[tokio::test]
async fn ai_suggest_finds_waf_blocked_boolean_via_openai() {
    let target = mount_target().await;
    let llm = mount_openai_llm("' AND 7=7 -- -", "' AND 7=8 -- -").await;
    let ai = AiSuggestConfig::from_cli(
        true,
        Some(AiProviderKind::OpenAi),
        Some(format!("{}/v1/chat/completions", llm.uri())),
        Some("test-model".to_owned()),
        None,
        3,
        30,
    );
    let engine = Engine::new(
        boolean_cfg_with_ai(ai),
        test_client(),
        CancellationToken::new(),
    );
    let url = format!("{}/?id=1", target.uri());
    engine.run(&url).await.expect("engine run");
    let findings = engine.state_handle().read().await.findings().to_vec();
    assert_eq!(findings.len(), 1, "expected exactly the AI finding");
    let f = &findings[0];
    assert_eq!(f.technique, injekt::session::state::TechniqueKind::Boolean);
    assert!(
        f.evidence.contains("ai:openai+0"),
        "evidence must cite the AI plan label, got {}",
        f.evidence
    );
    assert_eq!(llm_calls(&llm, "/v1/chat/completions").await, 1);
    assert_eq!(
        target_ai_probes(&target).await,
        2,
        "exactly one TRUE/FALSE pair"
    );
}

#[tokio::test]
async fn ai_suggest_off_stays_silent_byte_identical() {
    let target = mount_target().await;
    let cfg = {
        let mut c = EngineConfig::default();
        c.budget.threads = 1;
        c.techniques = vec!["boolean".to_owned()];
        c.budget.level = 1;
        c.net.allow_private = true;
        c.no_redact = true;
        c.enumeration.extract = false;
        c
    };
    assert!(!cfg.ai.enabled, "AI must default OFF");
    let engine = Engine::new(cfg, test_client(), CancellationToken::new());
    let url = format!("{}/?id=1", target.uri());
    engine.run(&url).await.expect("engine run");
    let findings = engine.state_handle().read().await.findings().to_vec();
    assert!(
        findings.is_empty(),
        "WAF-blocked boolean must stay silent without AI, got {findings:?}"
    );
}

#[tokio::test]
async fn ai_suggest_finds_via_anthropic() {
    let target = mount_target().await;
    let llm = mount_anthropic_llm("' AND 7=7 -- -", "' AND 7=8 -- -").await;
    let ai = AiSuggestConfig::from_cli(
        true,
        Some(AiProviderKind::Anthropic),
        Some(format!("{}/v1/messages", llm.uri())),
        Some("test-model".to_owned()),
        None,
        3,
        30,
    );
    let engine = Engine::new(
        boolean_cfg_with_ai(ai),
        test_client(),
        CancellationToken::new(),
    );
    let url = format!("{}/?id=1", target.uri());
    engine.run(&url).await.expect("engine run");
    let findings = engine.state_handle().read().await.findings().to_vec();
    assert_eq!(findings.len(), 1, "expected exactly the AI finding");
    assert!(
        findings[0].evidence.contains("ai:anthropic+0"),
        "evidence must cite the Anthropic plan label, got {}",
        findings[0].evidence
    );
    assert_eq!(llm_calls(&llm, "/v1/messages").await, 1);
    assert_eq!(target_ai_probes(&target).await, 2);
}

/// Mock "flaky" : différentiel booléen sur les 6 premières sondes
/// `1=1`/`1=2` (la détection L1 confirme via la 2e paire — le polyglotte ne
/// matche pas ces motifs), puis page plate (le re-sondage `--confirm`
/// échoue → finding droppé → trigger `confirm_dropped`).
fn flaky_counter() -> std::sync::Arc<std::sync::atomic::AtomicUsize> {
    std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0))
}

#[tokio::test]
async fn ai_suggest_fires_after_confirm_drop() {
    use std::sync::atomic::Ordering;
    let target = MockServer::start().await;
    let counter = flaky_counter();
    let responder_counter = counter.clone();
    Mock::given(method("GET"))
        .respond_with(move |req: &wiremock::Request| {
            let url = req.url.to_string();
            let is_true = url.contains("1%3D1") || url.contains("%271%27%3D%271");
            let is_false = url.contains("1%3D2") || url.contains("%271%27%3D%272");
            if is_true || is_false {
                let n = responder_counter.fetch_add(1, Ordering::SeqCst) + 1;
                if n <= 6 {
                    if is_false {
                        return ResponseTemplate::new(200).set_body_string(ALT_BODY);
                    }
                    return ResponseTemplate::new(200).set_body_string(BASELINE_BODY);
                }
            }
            ResponseTemplate::new(200).set_body_string(BASELINE_BODY)
        })
        .mount(&target)
        .await;
    let llm = mount_openai_llm("' AND 7=7 -- -", "' AND 7=8 -- -").await;
    let ai = AiSuggestConfig::from_cli(
        true,
        Some(AiProviderKind::OpenAi),
        Some(format!("{}/v1/chat/completions", llm.uri())),
        Some("test-model".to_owned()),
        None,
        3,
        30,
    );
    let mut cfg = boolean_cfg_with_ai(ai);
    cfg.confirm = true;
    cfg.seed = Some(7);
    let engine = Engine::new(cfg, test_client(), CancellationToken::new());
    let url = format!("{}/?id=1", target.uri());
    engine.run(&url).await.expect("engine run");
    // Le finding de détection a été droppé par --confirm, et la paire IA
    // (plate sur ce mock) n'a rien confirmé : 0 finding, mais exactement
    // 1 appel LLM prouve que le drop a déclenché le second-pass.
    let findings = engine.state_handle().read().await.findings().to_vec();
    assert!(
        findings.is_empty(),
        "confirm-dropped finding must stay dropped, got {findings:?}"
    );
    assert_eq!(llm_calls(&llm, "/v1/chat/completions").await, 1);
    assert_eq!(target_ai_probes(&target).await, 2);
}
