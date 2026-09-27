#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Track A generation end-to-end (`wiremock`) :
//!
//! Cible qui ne répond en différentiel QUE aux fins de branches `'b'`
//! (`'a'='b'`, `LIKE 'b'` — formes EqStr/LIKE générées) : l'historique L1
//! (polyglotte + `' OR 1=1`, sans `'b'`) reste muet dans les deux modes, et
//! seul `--generative conservative` (fenêtre de 8 paires — couvre toute
//! rotation seed vu l'écart max 5 entre paires EqStr/LIKE) confirme.
//!
//! - `generative_off_stays_silent` : OFF → 0 finding (byte-identical).
//! - `generative_conservative_finds_novel_shape` : 1 finding `Boolean` avec
//!   `gen=` en évidence (label `gen:<fence>+<logic>+<pred>`).

use injekt::{
    engine::{Engine, EngineConfig},
    generation::{GenerativeConfig, GenerativeMode},
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

/// Seule la fin de branche `'b'` (`%27b%27` encodé) rend le corps alternatif ;
/// tout le reste (baseline, historique L1, TRUE générés `'a'`) est stable.
fn like_responder(req: &wiremock::Request) -> ResponseTemplate {
    let url = req.url.to_string();
    if url.contains("%27b%27") || url.contains("%27B%27") {
        return ResponseTemplate::new(200).set_body_string(ALT_BODY);
    }
    ResponseTemplate::new(200).set_body_string(BASELINE_BODY)
}

fn boolean_cfg(generative: GenerativeConfig) -> EngineConfig {
    let mut cfg = EngineConfig::default();
    cfg.budget.threads = 1;
    cfg.techniques = vec!["boolean".to_owned()];
    cfg.budget.level = 1;
    cfg.net.allow_private = true;
    cfg.no_redact = true;
    cfg.enumeration.extract = false;
    cfg.seed = Some(42);
    cfg.generative = generative;
    cfg
}

#[tokio::test]
async fn generative_off_stays_silent() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(like_responder)
        .mount(&server)
        .await;
    let engine = Engine::new(
        boolean_cfg(GenerativeConfig::default()),
        test_client(),
        CancellationToken::new(),
    );
    let url = format!("{}/?id=1", server.uri());
    engine.run(&url).await.expect("engine run");
    let findings = engine.state_handle().read().await.findings().to_vec();
    assert!(
        findings.is_empty(),
        "OFF must stay silent on novel-only shapes, got {findings:?}"
    );
}

#[tokio::test]
async fn generative_conservative_finds_novel_shape() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(like_responder)
        .mount(&server)
        .await;
    let gen_cfg = GenerativeConfig::from_parts(GenerativeMode::Conservative, 8);
    let engine = Engine::new(
        boolean_cfg(gen_cfg),
        test_client(),
        CancellationToken::new(),
    );
    let url = format!("{}/?id=1", server.uri());
    engine.run(&url).await.expect("engine run");
    let findings = engine.state_handle().read().await.findings().to_vec();
    assert_eq!(findings.len(), 1, "expected the generated finding");
    let f = &findings[0];
    assert_eq!(f.technique, injekt::session::state::TechniqueKind::Boolean);
    assert!(
        f.evidence.contains("gen="),
        "evidence must cite the generation label, got {}",
        f.evidence
    );
}

/// WAF à signatures naïves (style CRS 2026) : `403` sur tout mot-clé espacé
/// WAF à signatures naïves (style CRS 2026) : `403` sur tout mot-clé espacé
/// (`+OR+`, `+AND+`, `%20OR%20` — tue 100% de la liste historique), `200`
/// sinon ; différentiel réservé aux fins spaceless (`(1)=(2)`, `(1)LIKE(2)`).
fn keyword_waf_responder(req: &wiremock::Request) -> ResponseTemplate {
    let url = req.url.to_string();
    let upper = url.to_ascii_uppercase();
    if upper.contains("+OR+")
        || upper.contains("+AND+")
        || upper.contains("%20OR%20")
        || upper.contains("%20AND%20")
    {
        return ResponseTemplate::new(403).set_body_string("blocked by waf");
    }
    if url.contains("%281%29%3D%282%29") || url.contains("%29LIKE%282%29") {
        return ResponseTemplate::new(200).set_body_string(ALT_BODY);
    }
    ResponseTemplate::new(200).set_body_string(BASELINE_BODY)
}

#[tokio::test]
async fn classic_list_dies_on_keyword_waf() {
    // Sanity : sans génération, la liste L1 (que du ` OR ` espacé) est
    // intégralement bloquée — le différentiel `'b'` ne suffit plus ici car
    // les paires EqStr/LIKE historiques sont elles aussi espacées.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(keyword_waf_responder)
        .mount(&server)
        .await;
    let engine = Engine::new(
        boolean_cfg(GenerativeConfig::default()),
        test_client(),
        CancellationToken::new(),
    );
    let url = format!("{}/?id=1", server.uri());
    engine.run(&url).await.expect("engine run");
    let findings = engine.state_handle().read().await.findings().to_vec();
    assert!(
        findings.is_empty(),
        "classic spaced list must die on keyword WAF, got {findings:?}"
    );
}

#[tokio::test]
async fn generative_spaceless_bypasses_keyword_waf() {
    // Les paires spaceless (`'OR(1)=(1)-- -`, aucun `+OR+`) traversent ;
    // la première confirme (`(1)=(1)`→baseline, `(1)=(2)`→alt). Fenêtre 32
    // ≥ écart cyclique max 16 entre spaceless : toute rotation seed couvre
    // au moins une paire confirmante (garantie, pas de chance).
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(keyword_waf_responder)
        .mount(&server)
        .await;
    let gen_cfg = GenerativeConfig::from_parts(GenerativeMode::Conservative, 32);
    let engine = Engine::new(
        boolean_cfg(gen_cfg),
        test_client(),
        CancellationToken::new(),
    );
    let url = format!("{}/?id=1", server.uri());
    engine.run(&url).await.expect("engine run");
    let findings = engine.state_handle().read().await.findings().to_vec();
    assert_eq!(findings.len(), 1, "expected the spaceless finding");
    let f = &findings[0];
    assert_eq!(f.technique, injekt::session::state::TechniqueKind::Boolean);
    assert!(
        f.evidence.contains("nospace"),
        "evidence must cite the spaceless family, got {}",
        f.evidence
    );
}

/// WAF évolué : tue les mots-clés espacés (`+OR+`/`+AND+`, toute la liste
/// historique + paires espacées générées) ET les formes spaceless
/// (`(1)=`, `(1)LIKE` — apprises du test précédent). Ne restent que les
/// séparateurs tab/newline : différentiel sur `1=1`/`1=2` et `'b'`.
fn evolved_waf_responder(req: &wiremock::Request) -> ResponseTemplate {
    let url = req.url.to_string();
    let upper = url.to_ascii_uppercase();
    if upper.contains("+OR+")
        || upper.contains("+AND+")
        || upper.contains("%20OR%20")
        || upper.contains("%20AND%20")
        || url.contains("%281%29%3D")
        || url.contains("%281%29LIKE")
    {
        return ResponseTemplate::new(403).set_body_string("blocked by waf");
    }
    if url.contains("1%3D2") || url.contains("%27b%27") {
        return ResponseTemplate::new(200).set_body_string(ALT_BODY);
    }
    ResponseTemplate::new(200).set_body_string(BASELINE_BODY)
}

#[tokio::test]
async fn evolved_waf_kills_classic_and_spaceless() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(evolved_waf_responder)
        .mount(&server)
        .await;
    let engine = Engine::new(
        boolean_cfg(GenerativeConfig::default()),
        test_client(),
        CancellationToken::new(),
    );
    let url = format!("{}/?id=1", server.uri());
    engine.run(&url).await.expect("engine run");
    let findings = engine.state_handle().read().await.findings().to_vec();
    assert!(
        findings.is_empty(),
        "OFF must stay silent on evolved WAF, got {findings:?}"
    );
}

#[tokio::test]
async fn generative_tab_bypasses_evolved_waf() {
    // Fenêtre de 16 ≥ écart max 14 entre paires EqInt/EqStr-TAB : toute
    // rotation seed couvre au moins une paire tab confirmante.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(evolved_waf_responder)
        .mount(&server)
        .await;
    let gen_cfg = GenerativeConfig::from_parts(GenerativeMode::Conservative, 16);
    let mut cfg = boolean_cfg(gen_cfg);
    cfg.seed = Some(11);
    let engine = Engine::new(cfg, test_client(), CancellationToken::new());
    let url = format!("{}/?id=1", server.uri());
    engine.run(&url).await.expect("engine run");
    let findings = engine.state_handle().read().await.findings().to_vec();
    assert_eq!(findings.len(), 1, "expected the tab/newline finding");
    let f = &findings[0];
    assert_eq!(f.technique, injekt::session::state::TechniqueKind::Boolean);
    assert!(
        f.evidence.contains("+tab") || f.evidence.contains("+nl"),
        "evidence must cite a tab/newline label, got {}",
        f.evidence
    );
}
