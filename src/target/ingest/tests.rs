use super::parsers::replace_path_templates;
use super::*;

#[test]
fn text_skips_comments_and_harvests_tokens() {
    let content = "# c\nhttps://a.example/?id=1\n  https://b.example/?q=x // trailing\n";
    let parsed = parse_targets_text(content);
    assert!(parsed.iter().any(|u| u.contains("a.example")));
    assert!(parsed.iter().any(|u| u.contains("b.example")));
}

#[test]
fn openapi_builds_query_urls() {
    let doc = serde_json::json!({
        "servers": [{"url": "https://api.example.com/v1"}],
        "paths": {
            "/users/{id}": {
                "get": {"parameters": [
                    {"name": "verbose", "in": "query"},
                    {"name": "page", "in": "query", "schema": {"example": 2}}
                ]}
            },
            "/health": {"get": {}}
        }
    });
    let targets = parse_openapi_targets(&doc.to_string());
    assert_eq!(targets.len(), 2);
    assert!(
        targets
            .iter()
            .any(|u| u.contains("/users/1") && u.contains("verbose=1"))
    );
    assert!(targets.iter().any(|u| u.contains("/health?id=1")));
}

#[test]
fn openapi_rejects_non_http_servers() {
    let doc = r#"{"servers":[{"url":"ftp://x"}],"paths":{"/a":{"get":{}}}}"#;
    assert_eq!(parse_openapi_targets(doc), [] as [String; 0]);
}

#[test]
fn sitemap_extracts_locs() {
    let xml = r#"<?xml version="1.0"?><urlset>
<url><loc>https://example.com/?id=1</loc></url>
<url><LOC>https://example.com/search?q=x</LOC></url>
</urlset>"#;
    let targets = parse_sitemap_targets(xml);
    assert_eq!(targets.len(), 2);
}

#[test]
fn path_templates_replaced() {
    assert_eq!(
        replace_path_templates("/users/{id}/posts/{postId}"),
        "/users/1/posts/1"
    );
    assert_eq!(replace_path_templates("users"), "/users");
}

#[test]
fn limited_read_rejects_oversize_file() {
    // `--raw-file` and ingestion share this cap: no unbounded RAM.
    let mut path = std::env::temp_dir();
    path.push(format!("injekt-test-oversize-{}.txt", std::process::id()));
    let len = usize::try_from(MAX_RAW_FILE_BYTES + 16).expect("cap fits usize");
    let big = "x".repeat(len);
    std::fs::write(&path, &big).expect("write temp oversize file");
    let err = read_limited_file(&path.to_string_lossy(), MAX_RAW_FILE_BYTES)
        .expect_err("must reject oversize file");
    assert!(err.to_string().contains("too large"), "{err}");
    std::fs::remove_file(&path).expect("cleanup temp file");
}

// ---------------------------------------------------------------------------
// C17 migration 2 — `--input` auto-detection (frozen grammar)
// ---------------------------------------------------------------------------

#[test]
fn input_kind_stdin_marker() {
    assert_eq!(sniff_input_kind("-", None), InputKind::Stdin);
    // The `-` marker wins even with an explicit first-kib window.
    assert_eq!(sniff_input_kind("-", Some("whatever")), InputKind::Stdin);
}

#[test]
fn input_kind_directory_wins_over_extension() {
    let dir = std::env::temp_dir().join(format!("injekt-input-dir-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    // A directory named `*.xml` must still resolve as RawDir.
    let xml_dir = std::env::temp_dir().join(format!("injekt-input-dir-{}.xml", std::process::id()));
    std::fs::create_dir_all(&xml_dir).expect("create temp xml dir");
    let a = sniff_input_kind(&dir.to_string_lossy(), None);
    let b = sniff_input_kind(&xml_dir.to_string_lossy(), None);
    std::fs::remove_dir(&dir).expect("cleanup");
    std::fs::remove_dir(&xml_dir).expect("cleanup");
    assert_eq!(a, InputKind::RawDir);
    assert_eq!(b, InputKind::RawDir);
}

#[test]
fn input_kind_openapi_by_marker_in_window() {
    // json + clef `openapi` present in the first KiB.
    assert_eq!(
        sniff_input_kind(
            "spec.json",
            Some(r#"{"openapi":"3.0.1","info":{"title":"t"},"paths":{}}"#)
        ),
        InputKind::Openapi
    );
    // yaml/yml: prefix clef, openapi key within the window.
    assert_eq!(
        sniff_input_kind("spec.yaml", Some("openapi: 3.0.1\ninfo:\n  title: t\n")),
        InputKind::Openapi
    );
    assert_eq!(
        sniff_input_kind("spec.yml", Some("openapi: 3.0.1\n")),
        InputKind::Openapi
    );
    // json without the marker → page TXT list.
    assert_eq!(
        sniff_input_kind("data.json", Some(r#"{"foo":"bar"}"#)),
        InputKind::Text
    );
    // Marker too late (> first KiB) → TXT list (cas documenté du sniff).
    let padding = " ".repeat(1030);
    assert_eq!(
        sniff_input_kind("late.json", Some(&format!("{padding}\"openapi\":"))),
        InputKind::Text
    );
}

#[test]
fn input_kind_sitemap_by_urlset_root() {
    // .xml + `<urlset` root → sitemap (tolerant to attributes,
    // `<urlset xmlns="...">`).
    assert_eq!(
        sniff_input_kind(
            "map.xml",
            Some(
                r#"<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>https://a.example/</loc></url></urlset>"#
            )
        ),
        InputKind::Sitemap
    );
    // XML without `<urlset` → TXT list (e.g. an exported Burp xml).
    assert_eq!(
        sniff_input_kind("items.xml", Some("<items><e/></items>")),
        InputKind::Text
    );
}

#[test]
fn input_kind_text_list_default() {
    assert_eq!(
        sniff_input_kind("targets.txt", Some("https://a.example/?id=1\n")),
        InputKind::Text
    );
    assert_eq!(
        sniff_input_kind("targets", Some("https://a.example/?id=1")),
        InputKind::Text
    );
    // Unreadable contents (read error): TXT fallback without panic.
    assert_eq!(sniff_input_kind("targets.txt", None), InputKind::Text);
}

#[test]
fn ext_sniff_is_case_insensitive() {
    assert_eq!(
        sniff_input_kind("SPEC.JSON", Some(r#"{"openapi":"3.0.1"}"#)),
        InputKind::Openapi
    );
    assert_eq!(
        sniff_input_kind("MAP.Xml", Some("<urlset><url/></urlset>")),
        InputKind::Sitemap
    );
}
