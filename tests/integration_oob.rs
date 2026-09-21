#![allow(clippy::unwrap_used, clippy::expect_used)]

use injekt::{
    engine::{Engine, EngineConfig},
    http::{client::HttpClient, jitter::Jitter, rate_limit::RateLimiter},
};
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};

fn test_client() -> HttpClient {
    HttpClient::builder()
        .timeout(Duration::from_secs(5))
        .jitter(Jitter::new(1.0, 0.5).with_min(0))
        .rate_limiter(std::sync::Arc::new(RateLimiter::disabled()))
        .allow_private(true)
        .build()
        .expect("client build")
}

fn baseline_page() -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_string("welcome normal page id=1 content")
}

fn engine_with_oob(
    oob_domain: Option<String>,
    oob_poll_url: Option<String>,
    ignore_codes: Vec<u16>,
) -> (Engine, CancellationToken) {
    let client = test_client();
    let mut cfg = EngineConfig::default();
    cfg.budget.threads = 1;
    cfg.techniques = vec!["oob".to_owned()];
    cfg.net.allow_private = true;
    cfg.net.ignore_codes = ignore_codes;
    cfg.no_redact = true;
    cfg.enumeration.extract = false;
    cfg.oob.oob_domain = oob_domain;
    cfg.oob.oob_poll_url = oob_poll_url;
    cfg.oob.oob_wait_secs = 0;
    let cancel = CancellationToken::new();
    let engine = Engine::new(cfg, client, cancel.clone());
    (engine, cancel)
}

#[tokio::test]
async fn oob_confirmed_when_poll_reports_seen() {
    let target = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(baseline_page())
        .mount(&target)
        .await;

    // Collaborator shim: confirms only the polled token (echoes it back
    // with seen:true), like a token-attributing backend.
    let poll = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(|req: &wiremock::Request| {
            let token = req
                .url
                .query_pairs()
                .find_map(|(k, v)| (k == "token").then(|| v.into_owned()))
                .unwrap_or_default();
            ResponseTemplate::new(200)
                .set_body_string(format!(r#"{{"seen":true,"token":"{token}"}}"#))
        })
        .mount(&poll)
        .await;

    let (engine, _cancel) = engine_with_oob(
        Some("collab.example.com".to_owned()),
        Some(poll.uri()),
        vec![],
    );
    let url = format!("{}/?id=1", target.uri());
    let state = engine.run(&url).await.expect("engine run");
    assert_eq!(state, injekt::engine::EngineState::Done);

    let findings = engine.state_handle().read().await.findings().to_vec();
    let oob = findings
        .iter()
        .find(|f| f.technique == injekt::session::state::TechniqueKind::Oob)
        .expect("oob finding present on callback");
    assert!(
        (oob.confidence - 0.95).abs() < 1e-6,
        "confidence {}",
        oob.confidence
    );
    assert!(oob.evidence.contains("token="), "evidence {}", oob.evidence);
    assert!(
        oob.evidence.contains("collab.example.com"),
        "evidence {}",
        oob.evidence
    );
}

#[tokio::test]
async fn oob_no_finding_when_poll_reports_seen_without_token() {
    // Bare `{"seen":true}` that never echoes the token (e.g. a stale
    // callback for another token in a shared collaborator inbox) must NOT
    // confirm — cross-token false-positive guard.
    let target = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(baseline_page())
        .mount(&target)
        .await;

    let poll = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"seen":true}"#))
        .mount(&poll)
        .await;

    let (engine, _cancel) = engine_with_oob(
        Some("collab.example.com".to_owned()),
        Some(poll.uri()),
        vec![],
    );
    let url = format!("{}/?id=1", target.uri());
    let _ = engine.run(&url).await.expect("engine run");
    let findings = engine.state_handle().read().await.findings().to_vec();
    assert!(
        findings
            .iter()
            .all(|f| f.technique != injekt::session::state::TechniqueKind::Oob),
        "bare seen:true without token must not confirm, got {findings:?}"
    );
}

#[tokio::test]
async fn oob_callback_overrides_ignored_last_status() {
    // `--ignore-code 200` + token-verified callback: the external proof
    // outranks the response veto (OOB executes async and returns a
    // baseline-like page). Without the override this was a systematic
    // false negative (veto on `last_status` after `callback_seen`).
    let target = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(baseline_page())
        .mount(&target)
        .await;

    let poll = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(|req: &wiremock::Request| {
            let token = req
                .url
                .query_pairs()
                .find_map(|(k, v)| (k == "token").then(|| v.into_owned()))
                .unwrap_or_default();
            ResponseTemplate::new(200)
                .set_body_string(format!(r#"{{"seen":true,"token":"{token}"}}"#))
        })
        .mount(&poll)
        .await;

    let (engine, _cancel) = engine_with_oob(
        Some("collab.example.com".to_owned()),
        Some(poll.uri()),
        vec![200],
    );
    let url = format!("{}/?id=1", target.uri());
    let state = engine.run(&url).await.expect("engine run");
    assert_eq!(state, injekt::engine::EngineState::Done);

    let findings = engine.state_handle().read().await.findings().to_vec();
    assert!(
        findings
            .iter()
            .any(|f| f.technique == injekt::session::state::TechniqueKind::Oob),
        "token-verified callback must survive --ignore-code veto, got {findings:?}"
    );
}

#[tokio::test]
async fn oob_no_finding_when_no_callback() {
    let target = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(baseline_page())
        .mount(&target)
        .await;

    let poll = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(r#"{"seen":false,"interactions":[]}"#),
        )
        .mount(&poll)
        .await;

    let (engine, _cancel) = engine_with_oob(
        Some("collab.example.com".to_owned()),
        Some(poll.uri()),
        vec![],
    );
    let url = format!("{}/?id=1", target.uri());
    let _ = engine.run(&url).await.expect("engine run");
    let findings = engine.state_handle().read().await.findings().to_vec();
    assert!(
        findings
            .iter()
            .all(|f| f.technique != injekt::session::state::TechniqueKind::Oob),
        "no OOB finding without callback, got {findings:?}"
    );
}

#[tokio::test]
async fn oob_skipped_without_domain() {
    let target = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(baseline_page())
        .mount(&target)
        .await;

    let (engine, _cancel) = engine_with_oob(None, None, vec![]);
    let url = format!("{}/?id=1", target.uri());
    let state = engine.run(&url).await.expect("engine run");
    assert_eq!(state, injekt::engine::EngineState::Done);
    let findings = engine.state_handle().read().await.findings().to_vec();
    assert!(
        findings.is_empty(),
        "oob without domain must not emit findings"
    );
}

#[tokio::test]
async fn oob_skipped_with_invalid_domain() {
    let target = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(baseline_page())
        .mount(&target)
        .await;

    let (engine, _cancel) =
        engine_with_oob(Some("http://not-a-domain/path".to_owned()), None, vec![]);
    let url = format!("{}/?id=1", target.uri());
    let _ = engine.run(&url).await.expect("engine run");
    let findings = engine.state_handle().read().await.findings().to_vec();
    assert!(findings.is_empty(), "invalid oob domain must be skipped");
}

#[tokio::test]
async fn oob_callback_attributes_triggering_variant() {
    // OOB-2: per-payload tokens + send→wait→poll per variant with early-break.
    // Stateful shim confirms only the 2nd distinct polled token: the finding
    // must attribute THAT token (evidence contains 2nd, not 1st) and the
    // engine must stop there (exactly 2 distincts polled).
    use std::sync::{Arc, Mutex};
    let target = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(baseline_page())
        .mount(&target)
        .await;

    let seen_order: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_clone = seen_order.clone();
    let poll = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(move |req: &wiremock::Request| {
            let token = req
                .url
                .query_pairs()
                .find_map(|(k, v)| (k == "token").then(|| v.into_owned()))
                .unwrap_or_default();
            if token.is_empty() {
                return ResponseTemplate::new(200).set_body_string(r#"{"seen":false}"#.to_owned());
            }
            let distinct_len = {
                let mut guard = seen_clone.lock().unwrap();
                if !guard.contains(&token) {
                    guard.push(token.clone());
                }
                guard.len()
            };
            if distinct_len == 2 {
                let second = seen_clone
                    .lock()
                    .unwrap()
                    .get(1)
                    .cloned()
                    .unwrap_or_default();
                if token == second {
                    return ResponseTemplate::new(200)
                        .set_body_string(format!(r#"{{"seen":true,"token":"{token}"}}"#));
                }
            }
            ResponseTemplate::new(200)
                .set_body_string(r#"{"seen":false,"interactions":[]}"#.to_owned())
        })
        .mount(&poll)
        .await;

    let (engine, _cancel) = engine_with_oob(
        Some("collab.example.com".to_owned()),
        Some(poll.uri()),
        vec![],
    );
    let url = format!("{}/?id=1", target.uri());
    let state = engine.run(&url).await.expect("engine run");
    assert_eq!(state, injekt::engine::EngineState::Done);

    let findings = engine.state_handle().read().await.findings().to_vec();
    let oob = findings
        .iter()
        .find(|f| f.technique == injekt::session::state::TechniqueKind::Oob)
        .expect("oob finding present on 2nd-token callback");

    let seen = seen_order.lock().unwrap().clone();
    assert_eq!(
        seen.len(),
        2,
        "early-break must poll exactly 2 distinct tokens, got {seen:?}"
    );
    let first = &seen[0];
    let second = &seen[1];
    assert!(
        oob.evidence.contains(second),
        "evidence must attribute triggering (2nd) token {second}, got {}",
        oob.evidence
    );
    assert!(
        !oob.evidence.contains(&format!("token={first}")),
        "evidence must not attribute 1st token {first}, got {}",
        oob.evidence
    );
}

#[tokio::test]
async fn oob_manual_mode_sends_probes_without_finding() {
    // No poll URL: probes are sent for manual collaborator check, but the
    // engine must not invent a finding without evidence.
    let target = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(baseline_page())
        .mount(&target)
        .await;

    let (engine, _cancel) = engine_with_oob(Some("collab.example.com".to_owned()), None, vec![]);
    let url = format!("{}/?id=1", target.uri());
    let _ = engine.run(&url).await.expect("engine run");
    let findings = engine.state_handle().read().await.findings().to_vec();
    assert!(
        findings
            .iter()
            .all(|f| f.technique != injekt::session::state::TechniqueKind::Oob),
        "manual mode must not auto-confirm, got {findings:?}"
    );
    // Probes were still sent: baseline (3) + 3 OOB payloads.
    let count = engine.state_handle().read().await.request_count();
    assert!(count >= 6, "probes should have been sent, count={count}");
}
