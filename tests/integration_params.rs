#![allow(clippy::unwrap_used, clippy::expect_used)]

use injekt::engine::orchestrator::{filter_params, synthetic_raw_from_data};
use injekt::target::parameters::{ParameterLocation, TargetParameter, collect_from_raw_request};

fn qp(name: &str) -> TargetParameter {
    TargetParameter::new(name, ParameterLocation::Query, "1")
}

fn body(name: &str) -> TargetParameter {
    TargetParameter::new(name, ParameterLocation::Body, "1")
}

#[test]
fn empty_filter_returns_all() {
    let params = vec![qp("id"), qp("q")];
    let out = filter_params(params, &[]);
    assert_eq!(out.len(), 2);
}

#[test]
fn filter_by_bare_name_case_insensitive() {
    let params = vec![qp("id"), qp("q"), body("user")];
    let out = filter_params(params, &["ID".to_owned()]);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].name, "id");
}

#[test]
fn filter_by_location_prefix() {
    let params = vec![qp("user"), body("user")];
    let out = filter_params(params, &["body:user".to_owned()]);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].location.to_string(), "body");
}

#[test]
fn filter_by_full_key() {
    let params = vec![qp("id"), body("id")];
    let out = filter_params(params, &["id@query".to_owned()]);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].location.to_string(), "query");
}

#[test]
fn filter_no_match_returns_empty() {
    let params = vec![qp("id")];
    let out = filter_params(params, &["nope".to_owned()]);
    assert!(out.is_empty());
}

#[test]
fn filter_preserves_markers() {
    let params = vec![
        TargetParameter::new("marker_asterisk", ParameterLocation::Query, "*"),
        qp("id"),
    ];
    let out = filter_params(params, &["id".to_owned()]);
    assert_eq!(out.len(), 2);
}

#[test]
fn synthetic_raw_empty_is_none() {
    assert!(synthetic_raw_from_data("").is_none());
    assert!(synthetic_raw_from_data("   ").is_none());
}

#[test]
fn synthetic_raw_builds_post_body() {
    let raw = synthetic_raw_from_data("id=1&user=admin").expect("some");
    assert_eq!(raw.method, "POST");
    assert_eq!(raw.body.as_deref(), Some("id=1&user=admin"));
    let params = collect_from_raw_request(&raw);
    let names: Vec<&str> = params.iter().map(|p| p.name.as_str()).collect();
    assert!(names.contains(&"id"));
    assert!(names.contains(&"user"));
    assert!(params.iter().all(|p| p.location.to_string() == "body"));
}

#[test]
fn filter_by_cookie_and_header_location() {
    let params = vec![
        TargetParameter::new("PHPSESSID", ParameterLocation::Cookie, "abc"),
        TargetParameter::new(
            "X-Forwarded-For",
            ParameterLocation::Header("X-Forwarded-For".to_owned()),
            "1.2.3.4",
        ),
        qp("id"),
    ];
    let out = filter_params(params.clone(), &["cookie:PHPSESSID".to_owned()]);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].name, "PHPSESSID");
    let out = filter_params(params, &["header:X-Forwarded-For".to_owned()]);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].name, "X-Forwarded-For");
}

#[test]
fn synthetic_raw_json_sets_content_type_and_keys() {
    use injekt::target::parameters::collect_from_body;
    let raw = synthetic_raw_from_data(r#"{"a":1,"b":"x"}"#).expect("some");
    assert_eq!(raw.method, "POST");
    assert_eq!(raw.path, "/");
    assert_eq!(
        raw.headers.get("Content-Type").map(String::as_str),
        Some("application/json")
    );
    let params = collect_from_raw_request(&raw);
    let names: Vec<&str> = params.iter().map(|p| p.name.as_str()).collect();
    assert!(names.contains(&"a"));
    assert!(names.contains(&"b"));
    // Direct body helper also extracts JSON keys (no aberrant single key).
    let direct = collect_from_body(r#"{"a":1}"#);
    assert_eq!(direct.len(), 1);
    assert_eq!(direct[0].name, "a");
}
