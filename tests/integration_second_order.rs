#![allow(clippy::unwrap_used, clippy::expect_used)]

use injekt::session::state::{SessionState, StoredProbe};
use secrecy::SecretString;
use std::sync::{Arc, Mutex};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

/// Proof-of-concept harness for second-order (Option A passive + future Option B actif).
/// POST /register stocke `user`, GET /admin reflète le stock.
/// Aucune payload RCE, uniquement marqueur bénin `u<hex>`.
#[tokio::test]
async fn second_order_store_then_manual_revisit_harness() {
    let store: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));

    let server = MockServer::start().await;

    let s1 = Arc::clone(&store);
    Mock::given(method("POST"))
        .and(path("/register"))
        .respond_with(move |req: &wiremock::Request| {
            let body = String::from_utf8_lossy(&req.body).into_owned();
            let user = url::form_urlencoded::parse(body.as_bytes())
                .find(|(k, _)| k == "user")
                .map(|(_, v)| v.into_owned())
                .unwrap_or_default();
            s1.lock().unwrap().push(user);
            ResponseTemplate::new(200).set_body_string("registered")
        })
        .mount(&server)
        .await;

    let s2 = Arc::clone(&store);
    Mock::given(method("GET"))
        .and(path("/admin"))
        .respond_with(move |_: &wiremock::Request| {
            let all = s2.lock().unwrap().join(",");
            ResponseTemplate::new(200).set_body_string(format!("users:{all}"))
        })
        .mount(&server)
        .await;

    // Marqueur bénin jetable, tracké en RAM-only via StoredProbe.
    let marker = "uabc12345";
    let mut state = SessionState::new();
    state.push_stored(StoredProbe::new(
        "user@body",
        SecretString::from(marker.to_owned()),
        "register-hash",
    ));
    assert_eq!(state.stored_count(), 1);

    // 1. Store via POST.
    let http = reqwest::Client::new();
    let register_url = format!("{}/register", server.uri());
    let resp = http
        .post(&register_url)
        .body(format!("user={marker}"))
        .send()
        .await
        .expect("store POST");
    assert_eq!(resp.status().as_u16(), 200);

    // 2. Manual revisit (opérateur, futur Option B automatisé borné).
    let admin_url = format!("{}/admin", server.uri());
    let body = http
        .get(&admin_url)
        .send()
        .await
        .expect("revisit GET")
        .text()
        .await
        .expect("read body");
    assert!(
        body.contains(marker),
        "stored marker must reflect on revisit, got {body}"
    );

    // 3. Cas négatif : marqueur jamais stocké ne doit pas apparaître.
    assert!(
        !body.contains("u00000000"),
        "unknown marker must not reflect, got {body}"
    );
}

#[tokio::test]
async fn second_order_no_reflection_without_store() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/admin"))
        .respond_with(|_: &wiremock::Request| {
            ResponseTemplate::new(200).set_body_string("users:alice,bob")
        })
        .mount(&server)
        .await;

    let http = reqwest::Client::new();
    let body = http
        .get(format!("{}/admin", server.uri()))
        .send()
        .await
        .expect("GET")
        .text()
        .await
        .expect("read body");
    assert!(
        !body.contains("uabc12345"),
        "clean admin must not reflect marker, got {body}"
    );
}

/// Option B actif borné (engine-level) : POST /register stocke le marqueur
/// bénin (`u+8hex`, payload `'<marker>'`), GET /admin le reflète sur 2/2
/// revisits → 1 finding `Union` 0.85/0.15 + audit passif `push_stored`.
/// OFF (défaut) = 0 requête extra (byte-identique, 2 runs OFF déterministes
/// à `request_count` égal) ; ON = 1 store + 2 revisits (+ ≤8 fingerprint
/// sur le finding confirmé).
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn second_order_active_finds_stored_reflection() {
    use injekt::engine::{Engine, EngineConfig, SecondOrderConfig};
    use injekt::http::{client::HttpClient, jitter::Jitter, rate_limit::RateLimiter};
    use std::time::Duration;
    use tokio_util::sync::CancellationToken;

    fn test_client() -> HttpClient {
        HttpClient::builder()
            .timeout(Duration::from_secs(5))
            .jitter(Jitter::new(1.0, 0.5).with_min(0))
            .rate_limiter(Arc::new(RateLimiter::disabled()))
            .allow_private(true)
            .build()
            .expect("client build")
    }

    let store: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let server = MockServer::start().await;

    let s1 = Arc::clone(&store);
    Mock::given(method("POST"))
        .and(path("/register"))
        .respond_with(move |req: &wiremock::Request| {
            let body = String::from_utf8_lossy(&req.body).into_owned();
            let user = url::form_urlencoded::parse(body.as_bytes())
                .find(|(k, _)| k == "user")
                .map(|(_, v)| v.into_owned())
                .unwrap_or_default();
            s1.lock().unwrap().push(user);
            ResponseTemplate::new(200).set_body_string("registered")
        })
        .mount(&server)
        .await;

    let s2 = Arc::clone(&store);
    Mock::given(method("GET"))
        .and(path("/admin"))
        .respond_with(move |_: &wiremock::Request| {
            let all = s2.lock().unwrap().join(",");
            ResponseTemplate::new(200).set_body_string(format!("users:{all}"))
        })
        .mount(&server)
        .await;

    let target = format!("{}/register", server.uri());

    // OFF (défaut) : référence byte-identique, aucun stored, aucun finding.
    // Deux runs OFF avec la même seed doivent coûter exactement pareil
    // (chemin déterministe, 0 requête extra).
    let mut cfg_off = EngineConfig::test_defaults();
    cfg_off.post_data = Some("user=test".to_owned());
    cfg_off.techniques = vec!["boolean".to_owned()];
    cfg_off.seed = Some(42);
    let engine_off = Engine::new(cfg_off, test_client(), CancellationToken::new());
    engine_off.run(&target).await.expect("run off");
    let handle_off = engine_off.state_handle();
    let st_off = handle_off.read().await;
    let req_off = st_off.request_count();
    let findings_off = st_off.findings().len();
    let stored_off = st_off.stored_count();
    drop(st_off);

    let mut cfg_off2 = EngineConfig::test_defaults();
    cfg_off2.post_data = Some("user=test".to_owned());
    cfg_off2.techniques = vec!["boolean".to_owned()];
    cfg_off2.seed = Some(42);
    let engine_off2 = Engine::new(cfg_off2, test_client(), CancellationToken::new());
    engine_off2.run(&target).await.expect("run off bis");
    let handle_off2 = engine_off2.state_handle();
    let req_off2 = handle_off2.read().await.request_count();
    drop(handle_off2);

    // ON : même cible + revisit même-origine `/admin`.
    let mut cfg_on = EngineConfig::test_defaults();
    cfg_on.post_data = Some("user=test".to_owned());
    cfg_on.techniques = vec!["boolean".to_owned()];
    cfg_on.seed = Some(42);
    let mut second_order = SecondOrderConfig::default();
    second_order.enabled = true;
    second_order.revisit_url = Some("/admin".to_owned());
    second_order.max_stores = 8;
    cfg_on.second_order = second_order;
    let engine_on = Engine::new(cfg_on, test_client(), CancellationToken::new());
    engine_on.run(&target).await.expect("run on");
    let handle_on = engine_on.state_handle();
    let st_on = handle_on.read().await;
    let req_on = st_on.request_count();
    let stored_on = st_on.stored_count();
    let findings = st_on.findings().to_vec();
    drop(st_on);

    assert_eq!(
        findings_off, 0,
        "clean register must yield 0 findings when OFF"
    );
    assert_eq!(stored_off, 0, "OFF must not push stored probes");
    assert_eq!(
        req_off2, req_off,
        "OFF default path must be deterministic (byte-identical, 0 extra req)"
    );
    // ON = 1 store + 2 revisits séquentiels (3 req), plus au plus le
    // fingerprint déclenché par le nouveau finding confirmé (4 DBMS ×
    // paire true/false = 8 req max, mock sans différentiel → 8).
    let delta = req_on.saturating_sub(req_off);
    assert!(
        (3..=11).contains(&delta),
        "ON must cost 3 second-order req + ≤8 fingerprint (OFF={req_off} ON={req_on} delta={delta})"
    );
    assert!(stored_on >= 1, "ON must audit the store passively");
    assert_eq!(
        findings.len(),
        1,
        "expected 1 second-order finding, got {findings:?}"
    );
    let finding = &findings[0];
    assert_eq!(
        finding.technique,
        injekt::session::state::TechniqueKind::Union,
        "second-order reuses Union kind (no new kind)"
    );
    assert!(
        (finding.confidence - 0.85).abs() < 0.001,
        "confidence must be 0.85, got {}",
        finding.confidence
    );
    assert!(
        (finding.false_positive_prob - 0.15).abs() < 0.001,
        "false_positive must be 0.15, got {}",
        finding.false_positive_prob
    );
    assert!(
        finding
            .evidence
            .contains("second-order stored marker reflected confirm=second-pass"),
        "evidence must carry the gate string, got {}",
        finding.evidence
    );
    assert!(
        finding.evidence.starts_with("second-order:"),
        "evidence must carry the second-order prefix, got {}",
        finding.evidence
    );
}
