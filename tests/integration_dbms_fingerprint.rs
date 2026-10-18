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

fn baseline_body() -> &'static str {
    "welcome normal page id=1 content baseline 42"
}

/// Évalue la première comparaison entière `(\d+)=(\d+)` d'une valeur déjà
/// décodée : `Some(true)` = branche logiquement vraie, `Some(false)` = fausse,
/// `None` = pas de comparaison entière.
///
/// P0.2 : les contrôles `r=r`/`r1=r2` tirent des entiers aléatoires ; un mock
/// qui ne matche que les littéraux historiques (`1=2`) les verrait comme
/// baseline et serait vété comme faux positif — ce mock évalue donc la
/// logique comme un vrai oracle.
fn eval_int_comparison(text: &str) -> Option<bool> {
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'=' {
            i += 1;
            continue;
        }
        let mut start = i;
        while start > 0 && bytes[start - 1].is_ascii_digit() {
            start -= 1;
        }
        let rhs_start = i + 1;
        let mut end = rhs_start;
        while end < bytes.len() && bytes[end].is_ascii_digit() {
            end += 1;
        }
        if start < i
            && end > rhs_start
            && let (Ok(lhs), Ok(rhs)) = (
                text[start..i].parse::<u64>(),
                text[rhs_start..end].parse::<u64>(),
            )
        {
            return Some(lhs == rhs);
        }
        i = rhs_start;
    }
    None
}

/// Minimal boolean-oracle backend: any injected integer condition that is
/// logically true (generic boolean payload or the MySQL versioned-comment
/// probe) renders like baseline, a logically false one renders differently.
/// Good enough to exercise the plumbing from a generic (dbms-less) boolean
/// finding through the active fingerprint probe without modelling real
/// per-DBMS SQL semantics.
fn oracle_responder(req: &wiremock::Request) -> ResponseTemplate {
    let id = req
        .url
        .query_pairs()
        .find(|(k, _)| k == "id")
        .map(|(_, v)| v.into_owned())
        .unwrap_or_default();
    if eval_int_comparison(&id) == Some(false) {
        return ResponseTemplate::new(200)
            .set_body_string("completely different content unique 987654");
    }
    ResponseTemplate::new(200).set_body_string(baseline_body())
}

#[tokio::test]
async fn active_probe_confirms_mysql_when_passive_signals_are_absent() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(oracle_responder)
        .mount(&server)
        .await;

    let client = test_client();
    let mut cfg = EngineConfig::default();
    cfg.budget.threads = 1;
    cfg.techniques = vec!["boolean".to_owned()];
    cfg.net.allow_private = true;
    cfg.no_redact = true;
    let cancel = CancellationToken::new();
    let engine = Engine::new(cfg, client, cancel);
    let target = format!("{}/?id=1", server.uri());
    engine.run(&target).await.expect("engine run");

    let findings = engine.state_handle().read().await.findings().to_vec();
    assert!(!findings.is_empty(), "expected a generic boolean finding");
    // After the fingerprint phase, the active probe should have filled dbms
    // in — the boolean detector itself never tags one, so this is only
    // possible via the new active differential probe.

    let dbms = findings
        .first()
        .and_then(|f| f.dbms.clone())
        .expect("active fingerprint probe should have filled dbms=mysql");
    assert_eq!(dbms, "mysql");
}
