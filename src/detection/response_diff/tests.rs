use super::similarity::{MAX_LEVENSHTEIN_LEN, truncate};
use super::*;
#[test]
fn lev_identical() {
    assert!((levenshtein_similarity("hello", "hello") - 1.0).abs() < 1e-6);
}
#[test]
// jaccard("", "") takes the early-return literal-1.0 path; exact comparison is safe.
#[allow(clippy::float_cmp)]
fn jaccard_empty() {
    assert_eq!(jaccard("", ""), 1.0);
}
#[test]
fn empty_candidate_never_significant() {
    // A transport/body error surfacing as `""` must not map to the
    // `combined_sim < 0.5 => 0.75` false positive.
    let diff = diff_against_baseline("hello world baseline body", "", 100.0, 110.0, 100.0);
    assert!(!diff.is_significant());
    assert!(diff.confidence < 0.4);
}
#[test]
fn truncate_never_splits_char_boundary() {
    // `🌍` is 4 bytes: char-based truncation keeps whole chars.
    let s = format!("{}{}", "a".repeat(4095), "🌍".repeat(8));
    assert!(s.chars().count() > MAX_LEVENSHTEIN_LEN);
    let t = truncate(&s);
    assert!(t.chars().count() <= MAX_LEVENSHTEIN_LEN);
    assert!(s.starts_with(t));
    // Must not panic and must stay valid UTF-8 (len check is enough:
    // `&s[..end]` would have panicked above on a split boundary).
    assert!(t.is_char_boundary(t.len()));
    // Similarity over such bodies must not panic either.
    let _ = levenshtein_similarity(&s, &s);
}
#[test]
fn cjk_bodies_use_levenshtein_not_jaccard() {
    // 400 CJK chars = 1200 bytes: the old byte-length switch routed this
    // to Jaccard; char-based routing keeps precise Levenshtein.
    let a = "漢".repeat(400);
    let b = format!("{}{}{}", "漢".repeat(200), "字", "漢".repeat(199));
    assert!(a.len() > MAX_LEVENSHTEIN_LEN);
    assert!(a.chars().count() <= MAX_LEVENSHTEIN_LEN);
    assert!(adaptive_similarity(&a, &b) > 0.95);
}
#[test]
fn bench_noise_normalized_before_similarity() {
    // `bench/app.py::noisy()` shape: same page, different per-response
    // `request_id` + `generated_at` must compare ~identical.
    let a = "{\n  \"data\": [{\"id\": 1}],\n  \"request_id\": \"a1b2c3d4\",\n  \"generated_at\": 1757328000.123\n}";
    let b = "{\n  \"data\": [{\"id\": 1}],\n  \"request_id\": \"e5f6a7b8\",\n  \"generated_at\": 1757328001.456\n}";
    assert!(adaptive_similarity(a, b) > 0.95);
    let diff = diff_against_baseline(a, b, 100.0, 105.0, 100.0);
    assert!(!diff.is_significant());
    // Compact shape normalizes too.
    let c = "{\"data\":1,\"request_id\":\"aaaa\",\"generated_at\":1.5}";
    let d = "{\"data\":1,\"request_id\":\"bbbb\",\"generated_at\":2.5}";
    assert!(adaptive_similarity(c, d) > 0.95);
}
#[test]
fn normalize_leaves_clean_bodies_untouched() {
    let body = "{\"data\": [1, 2, 3]}";
    assert_eq!(normalize_response_for_diff(body), body);
    assert_eq!(normalize_response_for_diff(""), "");
}
#[test]
fn csrf_nonce_noise_normalized_before_similarity() {
    // Django/Laravel shape: per-response CSRF + timestamp must not read
    // as a differential (false positive).
    let a = "{\"data\":1,\"csrf_token\":\"abc123\",\"timestamp\":1757328000.1}";
    let b = "{\"data\":1,\"csrf_token\":\"xyz789\",\"timestamp\":1757328001.9}";
    assert!(adaptive_similarity(a, b) > 0.95);
    let diff = diff_against_baseline(a, b, 100.0, 105.0, 100.0);
    assert!(!diff.is_significant());
    // Real data fields are untouched: placeholders replace only volatile
    // values, data differences survive normalization.
    let norm_c = normalize_response_for_diff("{\"data\":[1,2,3,4,5,6],\"csrf_token\":\"same\"}");
    let norm_d = normalize_response_for_diff("{\"data\":[9,8,7],\"csrf_token\":\"same\"}");
    assert!(norm_c.contains("[1,2,3,4,5,6]"));
    assert!(norm_d.contains("[9,8,7]"));
    assert_ne!(norm_c, norm_d);
}
#[test]
fn extra_volatile_json_fields_normalized_exact_match_only() {
    let a = "{\"data\":1,\"requestId\":\"a1\",\"trace_id\":\"t1\",\"traceId\":\"t2\",\
             \"correlation_id\":\"c1\",\"authenticity_token\":\"tok1\",\
             \"xsrf_token\":\"x1\",\"x-xsrf-token\":\"x2\"}";
    let b = "{\"data\":1,\"requestId\":\"b9\",\"trace_id\":\"u9\",\"traceId\":\"u8\",\
             \"correlation_id\":\"c9\",\"authenticity_token\":\"tok9\",\
             \"xsrf_token\":\"y9\",\"x-xsrf-token\":\"y8\"}";
    assert_eq!(
        normalize_response_for_diff(a),
        normalize_response_for_diff(b)
    );
    assert!(adaptive_similarity(a, b) > 0.95);
    let diff = diff_against_baseline(a, b, 100.0, 105.0, 100.0);
    assert!(!diff.is_significant());
    // Exact `"field"` match: lookalike keys keep their data.
    let c = "{\"data\":1,\"my_request_id\":\"keep-me\",\"trace_id_suffix\":\"keep-me-too\"}";
    assert_eq!(normalize_response_for_diff(c), c);
}
#[test]
fn csrf_meta_and_form_token_rotation_scores_similar() {
    let page = |meta: &str, form: &str| {
        format!(
            "<html><head><meta name=\"csrf-token\" content=\"{meta}\"></head>\
             <body><form><input type=\"hidden\" name=\"authenticity_token\" value=\"{form}\">\
             <p>dashboard</p></form></body></html>"
        )
    };
    let a = page("AAAAmetaTokenValueAAAA", "BBBBformTokenValueBBBB");
    let b = page("CCCCmetaTokenValueCCCC", "DDDDformTokenValueDDDD");
    let sim = adaptive_similarity(&a, &b);
    assert!(sim > 0.95, "similarity {sim}");
    let diff = diff_against_baseline(&a, &b, 100.0, 105.0, 100.0);
    assert!(!diff.is_significant(), "confidence {}", diff.confidence);
    let norm = normalize_response_for_diff(&a);
    assert!(norm.contains("content=\"\""), "{norm}");
    assert!(norm.contains("value=\"\""), "{norm}");
    assert!(!norm.contains("AAAAmetaTokenValueAAAA"), "{norm}");
    assert!(!norm.contains("BBBBformTokenValueBBBB"), "{norm}");
}
#[test]
fn csrf_meta_case_and_attribute_order_normalized() {
    let a = "<meta content=\"rotating-one\" name=\"csrf-token\">";
    let b = "<META NAME=\"CSRF-TOKEN\" CONTENT=\"rotating-two\">";
    let norm_a = normalize_response_for_diff(a);
    let norm_b = normalize_response_for_diff(b);
    assert!(norm_a.contains("content=\"\""), "{norm_a}");
    assert!(norm_a.contains("name=\"csrf-token\""), "{norm_a}");
    assert!(norm_b.contains("CONTENT=\"\""), "{norm_b}");
    // A meta without a CSRF marker is left alone.
    let other = "<meta name=\"description\" content=\"rotating but not a token\">";
    assert_eq!(normalize_response_for_diff(other), other);
}
#[test]
fn rotating_jwt_tokens_are_placeheld() {
    let jwt_a = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.c2lnbmF0dXJlLWFhYQ";
    let jwt_b = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJib2IiLCJpYXQiOjF9.c2lnbmF0dXJlLWJiYg";
    let a = format!("{{\"data\":1,\"access_token\":\"{jwt_a}\"}}");
    let b = format!("{{\"data\":1,\"access_token\":\"{jwt_b}\"}}");
    let norm = normalize_response_for_diff(&a);
    assert!(norm.contains("[REDACTED-JWT]"), "{norm}");
    assert!(!norm.contains(jwt_a), "{norm}");
    assert!(adaptive_similarity(&a, &b) > 0.95);
    let diff = diff_against_baseline(&a, &b, 100.0, 105.0, 100.0);
    assert!(!diff.is_significant());
    // Segments shorter than 8 chars are not JWTs: untouched.
    let near = "eyJab.cdef.ghij";
    assert_eq!(normalize_response_for_diff(near), near);
}
#[test]
fn short_input_values_and_free_text_untouched() {
    for body in [
        "<input value=\"12345\">",
        "<input type=\"text\" name=\"search\" value=\"hello world\">",
        "order total: 12345678901234567890",
        "{\"users\":[{\"id\":1,\"name\":\"admin\"},{\"id\":2,\"name\":\"guest\"}]}",
        "<a href=\"/reports?token=abc\">reports</a>",
    ] {
        assert_eq!(normalize_response_for_diff(body), body, "{body}");
    }
    // Long hex in free text survives even when the HTML pass does run.
    let marked = "<input name=\"csrf_token\" value=\"rotating-value-1\">\
                  <p>sha deadbeefdeadbeefdeadbeefdeadbeef</p>";
    let norm = normalize_response_for_diff(marked);
    assert!(norm.contains("deadbeefdeadbeefdeadbeefdeadbeef"), "{norm}");
    assert!(norm.contains("value=\"\""), "{norm}");
}
#[test]
fn credible_input_token_cleared_single_class_left_alone() {
    // Mixed-class token >= 20 chars: cleared even without a CSRF name.
    let token_input = "<input type=\"hidden\" name=\"state\" value=\"AbCd1234EfGh5678IjKl\">";
    assert_eq!(
        normalize_response_for_diff(token_input),
        "<input type=\"hidden\" name=\"state\" value=\"\">"
    );
    // Single-class values are not credible tokens: byte-identical output.
    for body in [
        "<input name=\"amount\" value=\"123456789012345678901\">",
        "<input name=\"slug\" value=\"abcdefghijklmnopqrst\">",
        "<input name=\"id\" value=\"ABCDEFGHIJKLMNOPQRST\">",
    ] {
        assert_eq!(normalize_response_for_diff(body), body, "{body}");
    }
}
#[test]
fn django_csrfmiddlewaretoken_rotation_scores_similar() {
    let page = |token: &str| {
        format!(
            "<form><input type=\"hidden\" name=\"csrfmiddlewaretoken\" value=\"{token}\">\
             <p>profile</p></form>"
        )
    };
    let a = page("WT1xY2ZhbHBoYW51bWVyaWNhbDMy");
    let b = page("WT2xY2ZhbHBoYW51bWVyaWNhbDMy");
    assert!(adaptive_similarity(&a, &b) > 0.95);
    assert_eq!(
        normalize_response_for_diff(&a),
        normalize_response_for_diff(&b)
    );
}
#[test]
fn classify_high_similarity_is_same() {
    assert_eq!(classify_page_similarity(0.99, None), PageSimilarity::Same);
    assert_eq!(classify_page_similarity(1.0, None), PageSimilarity::Same);
}
#[test]
fn classify_low_similarity_is_different() {
    assert_eq!(
        classify_page_similarity(0.01, None),
        PageSimilarity::Different
    );
    assert_eq!(
        classify_page_similarity(0.0, None),
        PageSimilarity::Different
    );
}
#[test]
fn classify_exact_bounds_stay_in_gray_zone() {
    // `0.98` n'est pas `> UPPER_RATIO_BOUND` : on continue vers la zone
    // grise, où l'absence de ratio appris laisse le verdict indéterminé.
    assert_eq!(
        classify_page_similarity(UPPER_RATIO_BOUND, None),
        PageSimilarity::Undetermined
    );
    // `0.02` n'est pas `< LOWER_RATIO_BOUND` : même chose côté bas.
    assert_eq!(
        classify_page_similarity(LOWER_RATIO_BOUND, None),
        PageSimilarity::Undetermined
    );
    // Avec un ratio appris, les valeurs exactes aux bornes sont tranchées.
    assert_eq!(
        classify_page_similarity(UPPER_RATIO_BOUND, Some(UPPER_RATIO_BOUND)),
        PageSimilarity::Same
    );
    assert_eq!(
        classify_page_similarity(LOWER_RATIO_BOUND, Some(0.9)),
        PageSimilarity::Different
    );
}
#[test]
fn classify_gray_zone_without_learned_ratio_is_undetermined() {
    for similarity in [0.03, 0.5, 0.97] {
        assert_eq!(
            classify_page_similarity(similarity, None),
            PageSimilarity::Undetermined,
            "similarity {similarity}"
        );
    }
}
#[test]
fn classify_gray_zone_uses_learned_ratio_with_tolerance() {
    // `m - DIFF_TOLERANCE` vaut exactement 0.85 pour m = 0.9 (IEEE 754).
    let m = 0.9;
    let floor = m - DIFF_TOLERANCE;
    assert_eq!(
        classify_page_similarity(0.95, Some(m)),
        PageSimilarity::Same
    );
    assert_eq!(classify_page_similarity(m, Some(m)), PageSimilarity::Same);
    // Pile sur le plancher : toujours Same (`>=`).
    assert_eq!(
        classify_page_similarity(floor, Some(m)),
        PageSimilarity::Same
    );
    // Juste sous le plancher : Different.
    assert_eq!(
        classify_page_similarity(floor - 1e-9, Some(m)),
        PageSimilarity::Different
    );
    // Autre plancher : la borne suit le ratio appris.
    assert_eq!(
        classify_page_similarity(0.44, Some(0.5)),
        PageSimilarity::Different
    );
    assert_eq!(
        classify_page_similarity(0.45, Some(0.5)),
        PageSimilarity::Same
    );
}
#[test]
fn classify_nan_is_undetermined() {
    assert_eq!(
        classify_page_similarity(f64::NAN, None),
        PageSimilarity::Undetermined
    );
    assert_eq!(
        classify_page_similarity(f64::NAN, Some(0.9)),
        PageSimilarity::Undetermined
    );
    // Garde défensive : un plancher NaN ne doit pas produire un faux
    // « Different » par échec de comparaison.
    assert_eq!(
        classify_page_similarity(0.5, Some(f64::NAN)),
        PageSimilarity::Undetermined
    );
}
#[test]
fn classify_clamps_out_of_range_inputs() {
    assert_eq!(classify_page_similarity(1.5, None), PageSimilarity::Same);
    assert_eq!(
        classify_page_similarity(-1.0, None),
        PageSimilarity::Different
    );
    // Les infinis sont clampés aux bornes ; seul NaN reste indéterminé.
    assert_eq!(
        classify_page_similarity(f64::INFINITY, None),
        PageSimilarity::Same
    );
    assert_eq!(
        classify_page_similarity(f64::NEG_INFINITY, None),
        PageSimilarity::Different
    );
}
#[test]
fn classify_is_monotone_in_similarity() {
    // En similarité croissante, le verdict ne peut que progresser
    // Different -> Undetermined -> Same, jamais régresser.
    let rank = |v: PageSimilarity| match v {
        PageSimilarity::Different => 0_u8,
        PageSimilarity::Undetermined => 1,
        PageSimilarity::Same => 2,
    };
    let samples = [0.0, 0.01, 0.02, 0.1, 0.5, 0.85, 0.9, 0.98, 0.99, 1.0];
    for m in [None, Some(0.9)] {
        let ranks: Vec<u8> = samples
            .iter()
            .map(|&s| rank(classify_page_similarity(s, m)))
            .collect();
        assert!(
            ranks.windows(2).all(|w| w[0] <= w[1]),
            "non monotone pour {m:?} : {ranks:?}"
        );
    }
}
