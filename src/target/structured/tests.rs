use super::*;
use serde_json::Value;
use std::fmt::Write as _;

#[test]
fn sniff_prefers_content_type() {
    assert_eq!(
        sniff_kind(Some("application/json"), "<a>x</a>"),
        StructuredKind::Json
    );
    assert_eq!(
        sniff_kind(Some("Application/JSON; charset=utf-8"), "a=1"),
        StructuredKind::Json
    );
    assert_eq!(
        sniff_kind(Some("text/xml"), "{\"a\":1}"),
        StructuredKind::Xml
    );
    assert_eq!(
        sniff_kind(Some("application/soap+xml"), "x"),
        StructuredKind::Xml
    );
    assert_eq!(
        sniff_kind(Some("application/x-www-form-urlencoded"), "a=1&b=2"),
        StructuredKind::Form
    );
}

#[test]
fn sniff_falls_back_to_body() {
    assert_eq!(sniff_kind(None, "{\"a\":1}"), StructuredKind::Json);
    assert_eq!(sniff_kind(Some(""), "  {\"a\":1}"), StructuredKind::Json);
    assert_eq!(sniff_kind(None, "  <a>x</a>"), StructuredKind::Xml);
    assert_eq!(sniff_kind(None, "a=1&b=2"), StructuredKind::Form);
    assert_eq!(sniff_kind(None, ""), StructuredKind::Form);
    // Limitation documentée : tableau racine classé Form.
    assert_eq!(sniff_kind(None, "[1,2]"), StructuredKind::Form);
}

#[test]
fn split_name_routes_prefixes() {
    assert_eq!(split_name("json:/a/0"), (StructuredKind::Json, "/a/0"));
    assert_eq!(split_name("json:"), (StructuredKind::Json, ""));
    assert_eq!(split_name("xml:User"), (StructuredKind::Xml, "User"));
    assert_eq!(split_name("xml:"), (StructuredKind::Xml, ""));
    assert_eq!(split_name("id"), (StructuredKind::Form, "id"));
    assert_eq!(split_name("jsonx:y"), (StructuredKind::Form, "jsonx:y"));
    assert_eq!(split_name(""), (StructuredKind::Form, ""));
}

#[test]
fn names_roundtrip_through_split_and_inject() {
    let body = "{\"a\":{\"b\":1}}";
    assert_eq!(
        json_paths(body),
        vec![("json:/a/b".to_owned(), "1".to_owned())]
    );
    let (kind, rest) = split_name("json:/a/b");
    assert_eq!(kind, StructuredKind::Json);
    assert_eq!(
        inject_json_path(body, rest, "2"),
        Some("{\"a\":{\"b\":\"2\"}}".to_owned())
    );
}

#[test]
fn json_paths_flattens_nested_and_arrays() {
    let body = "{\"a\":{\"b\":1},\"c\":[true,\"x\",null]}";
    assert_eq!(
        json_paths(body),
        vec![
            ("json:/a/b".to_owned(), "1".to_owned()),
            ("json:/c/0".to_owned(), "true".to_owned()),
            ("json:/c/1".to_owned(), "x".to_owned()),
            ("json:/c/2".to_owned(), String::new()),
        ]
    );
}

#[test]
fn json_paths_handles_roots_and_invalid() {
    assert_eq!(json_paths("{oops"), [] as [(String, String); 0]);
    assert_eq!(json_paths(""), [] as [(String, String); 0]);
    assert_eq!(json_paths("{}"), [] as [(String, String); 0]);
    assert_eq!(
        json_paths("42"),
        vec![("json:".to_owned(), "42".to_owned())]
    );
    assert_eq!(
        json_paths("\"hi\""),
        vec![("json:".to_owned(), "hi".to_owned())]
    );
    assert_eq!(
        json_paths("true"),
        vec![("json:".to_owned(), "true".to_owned())]
    );
}

#[test]
fn xml_tags_extracts_leaf_text() {
    assert_eq!(
        xml_tags("<a>1</a><b>x</b>"),
        vec![
            ("xml:a".to_owned(), "1".to_owned()),
            ("xml:b".to_owned(), "x".to_owned()),
        ]
    );
}

#[test]
fn xml_tags_ignores_attrs_and_keeps_namespaces() {
    assert_eq!(
        xml_tags("<a id=\"1\" class=\"c\">x</a>"),
        vec![("xml:a".to_owned(), "x".to_owned())]
    );
    assert_eq!(
        xml_tags("<soap:Body>hi</soap:Body>"),
        vec![("xml:soap:Body".to_owned(), "hi".to_owned())]
    );
}

#[test]
fn xml_tags_flattens_nested_naively_and_rejects_invalid() {
    // Le parent `<a>` contient `<` donc ne matche pas ; seul `<b>` sort.
    assert_eq!(
        xml_tags("<a><b>x</b></a>"),
        vec![("xml:b".to_owned(), "x".to_owned())]
    );
    assert_eq!(xml_tags("not xml at all"), [] as [(String, String); 0]);
    assert_eq!(xml_tags("<a>unclosed"), [] as [(String, String); 0]);
    assert_eq!(xml_tags(""), [] as [(String, String); 0]);
}

#[test]
fn inject_json_replaces_leaf_and_breaks_typing() {
    let body = "{\"a\":{\"b\":1}}";
    assert_eq!(
        inject_json_path(body, "a.b", "' OR '1'='1"),
        Some("{\"a\":{\"b\":\"' OR '1'='1\"}}".to_owned())
    );
    assert_eq!(
        inject_json_path(body, "/a/b", "x"),
        Some("{\"a\":{\"b\":\"x\"}}".to_owned())
    );
    assert_eq!(
        inject_json_path(body, "json:/a/b", "x"),
        Some("{\"a\":{\"b\":\"x\"}}".to_owned())
    );
    assert_eq!(
        inject_json_path("{\"c\":[1,2]}", "c[1]", "x"),
        Some("{\"c\":[1,\"x\"]}".to_owned())
    );
}

#[test]
fn inject_json_rejects_bad_paths() {
    let body = "{\"a\":{\"b\":1}}";
    assert!(inject_json_path(body, "", "x").is_none());
    assert!(inject_json_path(body, "/", "x").is_none());
    assert!(inject_json_path(body, "json:", "x").is_none());
    assert!(inject_json_path(body, "a.zzz", "x").is_none());
    assert!(inject_json_path(body, "a.b.c", "x").is_none());
    assert!(inject_json_path(body, "a", "x").is_none());
    assert!(inject_json_path("{oops", "a", "x").is_none());
    assert!(inject_json_path("{\"c\":[1]}", "c.5", "x").is_none());
}

#[test]
fn inject_json_operator_replaces_leaf_with_object() {
    let body = "{\"user\":\"admin\",\"pass\":\"secret\"}";
    let gt: Value = serde_json::from_str("{\"$gt\": \"\"}").unwrap_or(Value::Null);
    let lt: Value = serde_json::from_str("{\"$lt\": \"\"}").unwrap_or(Value::Null);
    // `serde_json` sans `preserve_order` trie les clés (BTree) : `pass` avant `user`.
    assert_eq!(
        inject_json_operator(body, "user", &gt),
        Some("{\"pass\":\"secret\",\"user\":{\"$gt\":\"\"}}".to_owned())
    );
    assert_eq!(
        inject_json_operator(body, "json:/pass", &lt),
        Some("{\"pass\":{\"$lt\":\"\"},\"user\":\"admin\"}".to_owned())
    );
    // Objet existant préservé (pas de double injection).
    let nested = "{\"user\":{\"$gt\":\"\"}}";
    assert!(inject_json_operator(nested, "user", &gt).is_none());
    assert!(inject_json_operator(body, "", &gt).is_none());
    assert!(inject_json_operator("{oops", "user", &gt).is_none());
}

#[test]
fn inject_xml_replaces_first_occurrence_verbatim() {
    assert_eq!(
        inject_xml_tag("<a>1</a><a>2</a>", "a", "y"),
        Some("<a>y</a><a>2</a>".to_owned())
    );
    assert_eq!(
        inject_xml_tag("<a id=\"1\">x</a>", "a", "y"),
        Some("<a id=\"1\">y</a>".to_owned())
    );
    assert_eq!(
        inject_xml_tag("<a>x</a>", "xml:a", "y"),
        Some("<a>y</a>".to_owned())
    );
    // Choix documenté : break-out inséré tel quel, sans échappement.
    assert_eq!(
        inject_xml_tag("<a>1</a><a>2</a>", "a", "</a><b>x</b>"),
        Some("<a></a><b>x</b></a><a>2</a>".to_owned())
    );
    let special = "Tom & Jerry <3 \"q\" 's'";
    let got = inject_xml_tag("<a>x</a>", "a", special);
    assert!(got.is_some_and(|s| s.contains(special)));
}

#[test]
fn inject_xml_rejects_missing_or_empty_tag() {
    assert!(inject_xml_tag("<a>x</a>", "b", "y").is_none());
    assert!(inject_xml_tag("<a>x</a>", "", "y").is_none());
    assert!(inject_xml_tag("<a>x</a>", "xml:", "y").is_none());
    assert!(inject_xml_tag("plain", "a", "y").is_none());
}

#[test]
fn pairs_truncate_at_cap() {
    let mut json_body = String::from("{");
    for i in 0..(MAX_STRUCTURED_PAIRS + 100) {
        if i > 0 {
            json_body.push(',');
        }
        let _ = write!(json_body, "\"k{i}\":{i}");
    }
    json_body.push('}');
    assert_eq!(json_paths(&json_body).len(), MAX_STRUCTURED_PAIRS);

    let mut xml_body = String::new();
    for i in 0..(MAX_STRUCTURED_PAIRS + 100) {
        let _ = write!(xml_body, "<k{i}>v</k{i}>");
    }
    assert_eq!(xml_tags(&xml_body).len(), MAX_STRUCTURED_PAIRS);
}

#[test]
fn json_paths_enforces_max_depth() {
    assert_eq!(json_paths(&nested_json_body(8)).len(), 1);
    assert_eq!(
        json_paths(&nested_json_body(12)),
        [] as [(String, String); 0]
    );
}

#[test]
fn tolerant_inputs_never_panic() {
    let bodies = [
        "",
        " ",
        "\u{FEFF}{\"a\":1}",
        "é\u{1F600}ß",
        "{{{{",
        "<<<<",
        "\u{FFFD}\u{FFFD}",
        "<a>\u{1F600}</a>",
        "{\"a\":\"\u{FFFD}\"}",
        "<a id=>x</a>",
        "</>",
        "<a/>",
    ];
    for body in bodies {
        let _kind = sniff_kind(None, body);
        assert!(json_paths(body).len() <= MAX_STRUCTURED_PAIRS);
        assert!(xml_tags(body).len() <= MAX_STRUCTURED_PAIRS);
        let _injected_json = inject_json_path(body, "a", "p");
        let _injected_xml = inject_xml_tag(body, "a", "p");
        let _split = split_name(body);
    }
}

#[test]
fn default_kind_is_form() {
    assert_eq!(StructuredKind::default(), StructuredKind::Form);
}

/// Construit `{"k":...{"k":1}...}` à `depth` niveaux (feuille scalaire).
#[must_use]
fn nested_json_body(depth: usize) -> String {
    let mut body = String::from("1");
    for _ in 0..depth {
        body = format!("{{\"k\":{body}}}");
    }
    body
}
