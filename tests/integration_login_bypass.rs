#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Bypass d'authentification (le scénario CVE-2026 emblématique : `LiteLLM`
//! pre-auth, Fortinet, Drupal) : la branche TRUE ouvre la session
//! ("Welcome back"), la FALSE retombe sur l'échec — différentiel INVERSÉ
//! par rapport au boolean classique (TRUE≈baseline). Prouve end-to-end que
//! `confirm_either` (pass swapped) confirme et tague ` inverted`.

use injekt::{
    engine::{Engine, EngineConfig},
    http::{client::HttpClient, jitter::Jitter, rate_limit::RateLimiter},
};
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};

const LOGIN_FAILED: &str = "Login failed invalid credentials try again";
const LOGIN_OK: &str = "Welcome back admin dashboard session established";

fn test_client() -> HttpClient {
    HttpClient::builder()
        .timeout(Duration::from_secs(10))
        .jitter(Jitter::new(1.0, 0.5).with_min(0))
        .rate_limiter(std::sync::Arc::new(RateLimiter::disabled()))
        .allow_private(true)
        .build()
        .expect("client build")
}

/// Formulaire simulé `GET /?user=<payload>&pass=x` :
/// - FALSE (`'1'='2'`, `1=2`) → échec (corps baseline) ;
/// - TRUE (`'1'='1'`, `1=1`) → session ouverte (corps distinct) ;
/// - tout le reste → échec.
fn login_responder(req: &wiremock::Request) -> ResponseTemplate {
    let url = req.url.to_string();
    // Branches FALSE d'abord (fail-closed si ambigu).
    if url.contains("%271%27%3D%272") || url.contains("1%3D2") {
        return ResponseTemplate::new(200).set_body_string(LOGIN_FAILED);
    }
    if url.contains("%271%27%3D%271") || url.contains("1%3D1") {
        return ResponseTemplate::new(200).set_body_string(LOGIN_OK);
    }
    ResponseTemplate::new(200).set_body_string(LOGIN_FAILED)
}

#[tokio::test]
async fn login_bypass_confirms_inverted() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(login_responder)
        .mount(&server)
        .await;
    let mut cfg = EngineConfig::default();
    cfg.budget.threads = 1;
    cfg.techniques = vec!["boolean".to_owned()];
    cfg.budget.level = 1;
    cfg.net.allow_private = true;
    cfg.no_redact = true;
    cfg.enumeration.extract = false;
    cfg.seed = Some(7);
    cfg.test_params = vec!["user".to_owned()];
    let engine = Engine::new(cfg, test_client(), CancellationToken::new());
    let url = format!("{}/?user=admin&pass=x", server.uri());
    engine.run(&url).await.expect("engine run");
    let findings = engine.state_handle().read().await.findings().to_vec();
    assert_eq!(findings.len(), 1, "expected the login bypass finding");
    let f = &findings[0];
    assert_eq!(f.technique, injekt::session::state::TechniqueKind::Boolean);
    assert!(
        f.evidence.contains("inverted"),
        "evidence must cite the inverted oracle, got {}",
        f.evidence
    );
    assert_eq!(f.parameter, "user@query");
}
