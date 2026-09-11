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

/// Minimal query decoder for the mock (ASCII-only payloads): `+` → space,
/// `%XX` → byte. Keeps invalid sequences verbatim.
fn decoded_query(req: &wiremock::Request) -> String {
    let raw = req.url.query().unwrap_or_default().replace('+', " ");
    let bytes = raw.as_bytes();
    let mut out = String::with_capacity(raw.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 3 <= bytes.len()
            && let Ok(hex) = std::str::from_utf8(&bytes[i + 1..i + 3])
            && let Ok(byte) = u8::from_str_radix(hex, 16)
        {
            out.push(char::from(byte));
            i += 3;
            continue;
        }
        out.push(char::from(bytes[i]));
        i += 1;
    }
    out
}

fn length_guess(query: &str) -> Option<usize> {
    let start = query.find(">=")? + 2;
    let digits: String = query[start..]
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    digits.parse().ok()
}

/// Backend with a working boolean differential but a dead extraction oracle:
/// - `1=2` (false branch) renders a clearly different page,
/// - `LENGTH(...)>=N` is stable with true length 5,
/// - `ASCII(...)` probes always render a *different* page, so the oracle
///   answers stuck-at-false and binary-search consistency fails from
///   position 0 (`actual < low (32)`).
fn enum_responder(req: &wiremock::Request) -> ResponseTemplate {
    const BASE: &str = "welcome page id=1 normal content";
    const ALT: &str = "welcome page id=1 normal content EXTRA DIFFERENT SECONDARY PAGE VARIANT WITH LOTS OF EXTRA WORDS FOR DISSIMILARITY";
    let query = decoded_query(req);
    let body = if query.contains("1=2") || query.contains("'1'='2'") || query.contains("ASCII(") {
        ALT
    } else if query.contains("LENGTH(") {
        if length_guess(&query).is_some_and(|n| n > 5) {
            ALT
        } else {
            BASE
        }
    } else {
        BASE
    };
    ResponseTemplate::new(200).set_body_string(body)
}

/// `--dbs` enumeration on a boolean finding whose char oracle is dead must
/// finish `Ok` (field skipped) instead of failing the run with
/// `extraction failed: inference inconsistency`.
#[tokio::test]
async fn enumeration_skips_unstable_oracle_without_failing() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(enum_responder)
        .mount(&server)
        .await;

    let mut cfg = EngineConfig::default();
    cfg.budget.threads = 1;
    cfg.techniques = vec!["boolean".to_owned()];
    cfg.net.allow_private = true;
    cfg.no_redact = true;
    cfg.enumeration.extract = false;
    cfg.enumeration.dbs = true;
    let engine = Engine::new(cfg, test_client(), CancellationToken::new());
    let target = format!("{}/?id=1", server.uri());
    let state = engine.run(&target).await.expect("run stays Ok");
    assert_eq!(state, injekt::engine::EngineState::Done);
    let findings = engine.state_handle().read().await.findings().to_vec();
    assert!(
        findings
            .iter()
            .any(|f| f.technique == injekt::session::state::TechniqueKind::Boolean),
        "boolean finding expected, got {findings:?}"
    );
}
