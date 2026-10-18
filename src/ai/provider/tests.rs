use super::*;

use super::parse::extract_json;
use crate::ai::{AiProviderKind, AiSuggestConfig};
use tokio_util::sync::CancellationToken;

#[test]
fn openai_body_has_json_mode_and_roles() {
    let b = openai_request_body("llama3.1:8b", "SYS", "USER");
    let v: serde_json::Value = serde_json::from_str(&b).expect("valid json");
    assert_eq!(v["model"], "llama3.1:8b");
    assert_eq!(v["temperature"], 0.0);
    assert_eq!(v["response_format"]["type"], "json_object");
    assert_eq!(v["messages"][0]["role"], "system");
    assert_eq!(v["messages"][1]["role"], "user");
}

#[test]
fn openai_parses_choices_content_with_fence() {
    let inner = r#"[{"true": "' OR 1=1 -- -", "false": "' OR 1=2 -- -"}]"#;
    let fenced = format!("```json\n{inner}\n```");
    let body = serde_json::json!({
        "choices": [{"message": {"content": fenced}}]
    })
    .to_string();
    let pairs = parse_openai_response(&body, 3).expect("parse");
    assert_eq!(pairs.len(), 1);
    assert_eq!(pairs[0].true_branch, "' OR 1=1 -- -");
}

#[test]
fn openai_rejects_empty_choices_and_bad_schema() {
    assert_eq!(
        parse_openai_response(r#"{"choices": []}"#, 3),
        Err(ParseLlmError::InvalidJson)
    );
    assert_eq!(
        parse_openai_response("not json at all", 3),
        Err(ParseLlmError::InvalidJson)
    );
    let bad = r#"{"choices": [{"message": {"content": "[]"}}]}"#;
    assert_eq!(parse_openai_response(bad, 3), Err(ParseLlmError::BadSchema));
}

#[test]
fn anthropic_body_pins_version_fields() {
    let b = anthropic_request_body("claude-sonnet-4-5", "SYS", "USER");
    let v: serde_json::Value = serde_json::from_str(&b).expect("valid json");
    assert_eq!(v["model"], "claude-sonnet-4-5");
    assert_eq!(v["max_tokens"], 1024);
    assert_eq!(v["system"], "SYS");
    assert_eq!(v["messages"][0]["role"], "user");
    assert_eq!(ANTHROPIC_VERSION, "2023-06-01");
}

#[test]
fn anthropic_concats_text_blocks_and_truncates() {
    let body = r#"{"content": [
        {"type": "text", "text": "intro "},
        {"type": "tool_use", "text": "ignored"},
        {"type": "text", "text": "[{\"true\": \"a OR 1=1\", \"false\": \"a OR 1=2\"}, {\"true\": \"b OR 2=2\", \"false\": \"b OR 2=3\"}]"}
    ]}"#;
    let pairs = parse_anthropic_response(body, 1).expect("parse");
    assert_eq!(pairs.len(), 1);
    assert_eq!(pairs[0].true_branch, "a OR 1=1");
}

#[test]
fn extract_json_handles_prose_and_object() {
    let p = extract_json("voici: [1,2] fin").expect("array");
    assert_eq!(p, "[1,2]");
    let o = extract_json("résultat {\"true\": \"x\", \"false\": \"y\"} ok").expect("obj");
    assert!(o.starts_with('['));
    assert!(o.contains("\"true\""));
    assert!(extract_json("aucun json ici").is_none());
}

fn openai_cfg(endpoint: &str) -> AiSuggestConfig {
    AiSuggestConfig::from_cli(
        true,
        Some(AiProviderKind::OpenAi),
        Some(endpoint.to_owned()),
        Some("llama3.1:8b".to_owned()),
        None,
        3,
        30,
    )
}

fn anthropic_cfg(endpoint: &str) -> AiSuggestConfig {
    AiSuggestConfig::from_cli(
        true,
        Some(AiProviderKind::Anthropic),
        Some(endpoint.to_owned()),
        Some("claude-sonnet-4-5".to_owned()),
        Some(secrecy::SecretString::from("sk-test")),
        3,
        30,
    )
}

#[tokio::test]
async fn fetch_openai_success() {
    use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};
    let server = MockServer::start().await;
    let inner = r#"[{"true": "' OR 1=1 -- -", "false": "' OR 1=2 -- -"}]"#;
    let envelope = serde_json::json!({
        "choices": [{"message": {"content": inner}}]
    })
    .to_string();
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(envelope))
        .mount(&server)
        .await;
    let cfg = openai_cfg(&format!("{}/v1/chat/completions", server.uri()));
    let pairs = fetch_suggestions(&cfg, "SYS", "USER", &CancellationToken::new())
        .await
        .expect("fetch");
    assert_eq!(pairs.len(), 1);
    assert_eq!(pairs[0].true_branch, "' OR 1=1 -- -");
}

#[tokio::test]
async fn fetch_anthropic_success_pins_version_header() {
    use wiremock::matchers::header;
    use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};
    let server = MockServer::start().await;
    let inner = r#"[{"true": "' AND 1=1 -- -", "false": "' AND 1=2 -- -"}]"#;
    let envelope = serde_json::json!({
        "content": [{"type": "text", "text": inner}]
    })
    .to_string();
    Mock::given(method("POST"))
        .and(header("anthropic-version", ANTHROPIC_VERSION))
        .and(header("x-api-key", "sk-test"))
        .respond_with(ResponseTemplate::new(200).set_body_string(envelope))
        .mount(&server)
        .await;
    let cfg = anthropic_cfg(&format!("{}/v1/messages", server.uri()));
    let pairs = fetch_suggestions(&cfg, "SYS", "USER", &CancellationToken::new())
        .await
        .expect("fetch");
    assert_eq!(pairs.len(), 1);
    assert_eq!(pairs[0].false_branch, "' AND 1=2 -- -");
}

#[tokio::test]
async fn fetch_bad_status_and_cancelled() {
    use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;
    let cfg = openai_cfg(&format!("{}/v1/chat/completions", server.uri()));
    assert_eq!(
        fetch_suggestions(&cfg, "SYS", "USER", &CancellationToken::new()).await,
        Err(AiFetchError::BadStatus(500))
    );
    let cancelled = CancellationToken::new();
    cancelled.cancel();
    assert_eq!(
        fetch_suggestions(&cfg, "SYS", "USER", &cancelled).await,
        Err(AiFetchError::Cancelled)
    );
}

#[tokio::test]
async fn fetch_incomplete_never_calls_network() {
    // Config par défaut : 0 appel, même avec un endpoint valide.
    let cfg = AiSuggestConfig::default();
    assert_eq!(
        fetch_suggestions(&cfg, "SYS", "USER", &CancellationToken::new()).await,
        Err(AiFetchError::Incomplete)
    );
}
