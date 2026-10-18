use super::*;

const LOREM: &str = "Lorem ipsum dolor sit amet, congue tation referrentur ei sed. Ne nec legimus habemus recusabo, natum reque et per. Facer tritani reprehendunt eos id, modus constituam est te. Usu sumo indoctum ad, pri paulo molestiae complectitur no.";
const LOREM_INJECTED: &str = "Lorem ipsum dolor sit amet, congue tation referrentur ei sed. Ne nec legimus habemus recusabo, natum reque et per. <script src='ads.js'></script>Facer tritani reprehendunt eos id, modus constituam est te. Usu sumo indoctum ad, pri paulo molestiae complectitur no.";

#[test]
fn sqlmap_doctest_marking() {
    let markings = find_dynamic_content(LOREM, LOREM_INJECTED);
    assert_eq!(markings.len(), 1, "{markings:?}");
    assert_eq!(markings[0].prefix.as_deref(), Some("natum reque et per. "));
    assert_eq!(markings[0].suffix.as_deref(), Some("Facer tritani repreh"));
    // La purge retire la zone insérée et rend la page à son état stable.
    let stripped = remove_dynamic_content(LOREM_INJECTED, &markings);
    assert_eq!(stripped, LOREM);
    // La page sans la zone ne bouge pas (le motif `.+?` exige un infixe).
    assert_eq!(remove_dynamic_content(LOREM, &markings), LOREM);
}

#[test]
fn dynamic_zone_at_page_start_gets_none_prefix() {
    let stable = "Usu sumo indoctum ad, pri paulo molestiae complectitur no. Facer tritani reprehendunt eos id, modus constituam est te.";
    let first = format!("ads-0123456789abcdef{stable}");
    let second = format!("ads-fedcba9876543210{stable}");
    let markings = find_dynamic_content(&first, &second);
    assert_eq!(markings.len(), 1, "{markings:?}");
    assert_eq!(markings[0].prefix, None, "{markings:?}");
    assert_eq!(markings[0].suffix.as_deref(), Some(stable), "{markings:?}");
    let stripped_first = remove_dynamic_content(&first, &markings);
    let stripped_second = remove_dynamic_content(&second, &markings);
    assert_eq!(stripped_first, stripped_second);
    assert!(!stripped_first.contains("0123456789abcdef"));
}

#[test]
fn dynamic_zone_at_page_end_gets_none_suffix() {
    let stable = "Lorem ipsum dolor sit amet, congue tation referrentur ei sed. Ne nec legimus habemus recusabo.";
    let first = format!("{stable}ads-0123456789abcdef");
    let second = format!("{stable}ads-fedcba9876543210");
    let markings = find_dynamic_content(&first, &second);
    assert_eq!(markings.len(), 1, "{markings:?}");
    assert_eq!(markings[0].suffix, None, "{markings:?}");
    let prefix = markings[0].prefix.as_deref().expect("prefix marqué");
    assert!(first.starts_with(prefix), "prefix={prefix:?}");
    let stripped_first = remove_dynamic_content(&first, &markings);
    let stripped_second = remove_dynamic_content(&second, &markings);
    assert_eq!(stripped_first, stripped_second);
    assert!(!stripped_first.contains("0123456789abcdef"));
}

#[test]
fn identical_pages_have_no_markings() {
    assert_eq!(
        find_dynamic_content(LOREM, LOREM),
        [] as [DynamicMarking; 0]
    );
    assert_eq!(
        find_dynamic_content("short", "short"),
        [] as [DynamicMarking; 0]
    );
}

#[test]
fn very_different_pages_are_not_marked() {
    // Pré-filtre `quick_ratio` : aucun caractère commun → rien à marquer.
    let first = "a".repeat(120);
    let second = "b".repeat(120);
    assert_eq!(
        find_dynamic_content(&first, &second),
        [] as [DynamicMarking; 0]
    );
}

#[test]
fn oversized_pages_degrade_silently() {
    let first = "a".repeat(MAX_DYNAMIC_SCAN_CHARS / 2 + 1);
    let second = "b".repeat(MAX_DYNAMIC_SCAN_CHARS / 2 + 1);
    assert_eq!(
        find_dynamic_content(&first, &second),
        [] as [DynamicMarking; 0]
    );
}

#[test]
fn remove_handles_each_marking_shape_and_is_idempotent() {
    let cases: [(DynamicMarking, &str); 4] = [
        (
            DynamicMarking {
                prefix: None,
                suffix: Some("TAIL".to_owned()),
            },
            "TAIL",
        ),
        (
            DynamicMarking {
                prefix: Some("HEAD".to_owned()),
                suffix: None,
            },
            "HEAD",
        ),
        (
            DynamicMarking {
                prefix: Some("HEAD".to_owned()),
                suffix: Some("TAIL".to_owned()),
            },
            "HEADTAIL",
        ),
        (
            DynamicMarking {
                prefix: None,
                suffix: None,
            },
            "HEAD-0123456789abcdef-TAIL",
        ),
    ];
    for (marking, expected) in cases {
        let page = "HEAD-0123456789abcdef-TAIL";
        let stripped = remove_dynamic_content(page, std::slice::from_ref(&marking));
        assert_eq!(stripped, expected, "{marking:?}");
        let twice = remove_dynamic_content(&stripped, std::slice::from_ref(&marking));
        assert_eq!(twice, stripped, "idempotent pour {marking:?}");
    }
}

#[test]
fn unicode_multibyte_flanks_do_not_panic() {
    let left = "安定した日本語のコンテンツです。これは非常に長い静的なフランクであり、動的部分の左側に位置します。";
    let right =
        "動的部分の右側に位置する、これもまた非常に長い静的なフランクです。以上、テスト終わり。";
    let first = format!("{left}ads-😀😀😀😀{right}");
    let second = format!("{left}ads-🚀🚀🚀🚀{right}");
    let markings = find_dynamic_content(&first, &second);
    assert_eq!(markings.len(), 1, "{markings:?}");
    let stripped_first = remove_dynamic_content(&first, &markings);
    let stripped_second = remove_dynamic_content(&second, &markings);
    assert_eq!(stripped_first, stripped_second);
    assert!(!stripped_first.contains('😀'));
    assert!(!stripped_second.contains('🚀'));
}

#[test]
fn empty_inputs_are_noops() {
    assert_eq!(find_dynamic_content("", LOREM), [] as [DynamicMarking; 0]);
    assert_eq!(find_dynamic_content(LOREM, ""), [] as [DynamicMarking; 0]);
    assert_eq!(remove_dynamic_content("", &[]), "");
    let marking = DynamicMarking {
        prefix: None,
        suffix: None,
    };
    assert_eq!(remove_dynamic_content("unchanged", &[marking]), "unchanged");
}
