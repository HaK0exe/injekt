#![allow(clippy::unwrap_used, clippy::expect_used)]

//! P1.1 — marquage générique du contenu dynamique (`findDynamicContent`).
//!
//! La page mock tourne à chaque requête dans une zone NON nommée
//! (`<div class="banner">ads-<compteur hex>`) encadrée par deux flancs stables
//! de plus de 40 chars, et le paramètre `id` n'est pas injectable. Sans le
//! marquage P1.1, la baseline serait instable (`is_stable()` false) et la
//! détection booléenne serait entièrement sautée (`baseline unstable — skipping
//! injection detection`), soit ~3 requêtes. Avec le marquage, la baseline
//! redevient stable, les sondes booléennes partent réellement (baseline +
//! payloads) et le scan se termine sans finding.

use injekt::{
    engine::{Engine, EngineConfig},
    http::{client::HttpClient, jitter::Jitter, rate_limit::RateLimiter},
    session::state::Finding,
};
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio_util::sync::CancellationToken;
use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};

fn test_client() -> HttpClient {
    HttpClient::builder()
        .timeout(Duration::from_secs(10))
        .jitter(Jitter::new(1.0, 0.5).with_min(0))
        .rate_limiter(Arc::new(RateLimiter::disabled()))
        .allow_private(true)
        .build()
        .expect("client build")
}

fn boolean_cfg() -> EngineConfig {
    let mut cfg = EngineConfig::default();
    cfg.budget.threads = 1;
    cfg.budget.level = 1;
    cfg.techniques = vec!["boolean".to_owned()];
    cfg.net.allow_private = true;
    cfg.no_redact = true;
    cfg.enumeration.extract = false;
    cfg.seed = Some(7);
    cfg
}

/// Page dont seule la bannière (`ads-<hex>`, hors champs volatils nommés)
/// change à chaque requête ; les flancs (header/footer) font > 40 chars.
fn page(banner: &str) -> String {
    format!(
        "<html><body><h1>Product listing</h1>\
         <div class=\"header\">Lorem ipsum dolor sit amet, congue tation referrentur ei sed</div>\
         <div class=\"banner\">{banner}</div>\
         <div class=\"footer\">Usu sumo indoctum ad, pri paulo molestiae complectitur no</div>\
         </body></html>"
    )
}

#[tokio::test]
async fn rotating_unnamed_zone_is_marked_and_scan_stays_clean() {
    let server = MockServer::start().await;
    let counter = Arc::new(AtomicUsize::new(0));
    let responder_counter = Arc::clone(&counter);
    Mock::given(method("GET"))
        .respond_with(move |_req: &wiremock::Request| {
            let n = responder_counter.fetch_add(1, Ordering::SeqCst);
            ResponseTemplate::new(200).set_body_string(page(&format!("ads-{n:08x}")))
        })
        .mount(&server)
        .await;

    let engine = Engine::new(boolean_cfg(), test_client(), CancellationToken::new());
    engine
        .run(&format!("{}/?id=1", server.uri()))
        .await
        .expect("engine run");
    let findings: Vec<Finding> = engine.state_handle().read().await.findings().to_vec();
    assert!(
        findings.is_empty(),
        "paramètre non injectable : 0 finding attendu, got {findings:?}"
    );
    // Baseline instable ⇒ détection sautée après ~3 requêtes. Ici le scan doit
    // réellement sonder : preuve que les marquages ont stabilisé la baseline.
    let requests = counter.load(Ordering::SeqCst);
    assert!(
        requests > 5,
        "détection booléenne attendue après baseline stabilisée, {requests} requêtes vues"
    );
}
