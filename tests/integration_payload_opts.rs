#![allow(clippy::unwrap_used, clippy::expect_used)]

use injekt::{
    engine::{Engine, EngineConfig},
    http::{client::HttpClient, jitter::Jitter, rate_limit::RateLimiter},
    session::state::TechniqueKind,
    techniques::payload_opts::PayloadOpts,
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
    "welcome normal page content baseline 42"
}

fn different_body() -> &'static str {
    "completely different page xyz 99 unique"
}

/// Évalue la première comparaison entière `(\d+)=(\d+)` d'un payload (URL
/// `%3D`-encodée ou texte brut) : `Some(true)` = branche logiquement vraie,
/// `Some(false)` = fausse, `None` = pas de comparaison entière.
///
/// P0.2 : les contrôles `r=r`/`r1=r2` utilisent des entiers aléatoires ; un
/// mock qui ne matche que les littéraux historiques (`1=2`) ne les verrait
/// pas et serait vété comme faux positif — ce mock évalue donc la logique
/// comme un vrai oracle.
fn eval_int_comparison(text: &str) -> Option<bool> {
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let eq_len = if bytes[i] == b'=' {
            1
        } else if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && bytes[i + 1] == b'3'
            && matches!(bytes[i + 2], b'D' | b'd')
        {
            3
        } else {
            i += 1;
            continue;
        };
        let mut start = i;
        while start > 0 && bytes[start - 1].is_ascii_digit() {
            start -= 1;
        }
        let rhs_start = i + eq_len;
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

/// Boolean differential on raw query string: FALSE probes differ, everything else is baseline.
fn query_responder(req: &wiremock::Request) -> ResponseTemplate {
    if eval_int_comparison(req.url.as_str()) == Some(false) {
        ResponseTemplate::new(200).set_body_string(different_body())
    } else {
        ResponseTemplate::new(200).set_body_string(baseline_body())
    }
}

/// Boolean differential scoped to the `id` query param only; `q` never differs.
fn scoped_query_responder(req: &wiremock::Request) -> ResponseTemplate {
    let id_value: String = req
        .url
        .query_pairs()
        .filter(|(k, _)| k == "id")
        .map(|(_, v)| v.into_owned())
        .collect();
    if eval_int_comparison(&id_value) == Some(false) {
        ResponseTemplate::new(200).set_body_string(different_body())
    } else {
        ResponseTemplate::new(200).set_body_string(baseline_body())
    }
}

/// Boolean differential on POST form body.
fn body_responder(req: &wiremock::Request) -> ResponseTemplate {
    let body = String::from_utf8_lossy(&req.body);
    if eval_int_comparison(&body) == Some(false) {
        ResponseTemplate::new(200).set_body_string(different_body())
    } else {
        ResponseTemplate::new(200).set_body_string(baseline_body())
    }
}

fn boolean_cfg() -> EngineConfig {
    let mut cfg = EngineConfig::default();
    cfg.budget.threads = 1;
    cfg.techniques = vec!["boolean".to_owned()];
    cfg.net.allow_private = true;
    cfg.no_redact = true;
    cfg
}

#[tokio::test]
async fn suffix_passthrough_keeps_finding_and_marks_evidence() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(query_responder)
        .mount(&server)
        .await;

    let mut cfg = boolean_cfg();
    let mut popts = PayloadOpts::default();
    popts.suffix = Some(" -- -".to_owned());
    cfg.evasion.payload_opts = popts;
    let engine = Engine::new(cfg, test_client(), CancellationToken::new());
    let target = format!("{}/?id=1", server.uri());
    engine.run(&target).await.expect("engine run");
    let findings = engine.state_handle().read().await.findings().to_vec();
    let finding = findings
        .iter()
        .find(|f| f.technique == TechniqueKind::Boolean)
        .expect("boolean finding with neutral suffix");
    assert!(
        finding.evidence.contains("suffix="),
        "evidence should carry payload-opts suffix, got {}",
        finding.evidence
    );
}

#[tokio::test]
async fn data_posts_body_and_finds_body_param() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(body_responder)
        .mount(&server)
        .await;

    let mut cfg = boolean_cfg();
    cfg.post_data = Some("id=1&user=guest".to_owned());
    let engine = Engine::new(cfg, test_client(), CancellationToken::new());
    engine.run(&server.uri()).await.expect("engine run");
    let findings = engine.state_handle().read().await.findings().to_vec();
    assert!(
        findings
            .iter()
            .any(|f| f.technique == TechniqueKind::Boolean && f.parameter == "id@body"),
        "expected boolean finding on id@body via --data, got {:?}",
        findings.iter().map(|f| &f.parameter).collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn param_filter_selects_only_id() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(scoped_query_responder)
        .mount(&server)
        .await;

    // Filter on q (never injectable here) -> no findings.
    let mut cfg = boolean_cfg();
    cfg.test_params = vec!["q".to_owned()];
    let engine = Engine::new(cfg, test_client(), CancellationToken::new());
    let target = format!("{}/?id=1&q=1", server.uri());
    engine.run(&target).await.expect("engine run");
    assert!(
        engine.state_handle().read().await.findings().is_empty(),
        "-p q must yield no findings when only id is injectable"
    );

    // Filter on id -> finding on id@query.
    let mut cfg = boolean_cfg();
    cfg.test_params = vec!["id".to_owned()];
    let engine = Engine::new(cfg, test_client(), CancellationToken::new());
    engine.run(&target).await.expect("engine run");
    let findings = engine.state_handle().read().await.findings().to_vec();
    assert!(
        findings
            .iter()
            .any(|f| f.technique == TechniqueKind::Boolean && f.parameter == "id@query"),
        "expected boolean finding on id@query via -p id, got {:?}",
        findings.iter().map(|f| &f.parameter).collect::<Vec<_>>()
    );
}
