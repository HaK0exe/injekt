use super::*;
use std::time::Duration;

fn sample(status: u16, body: &[u8], headers: &[(&str, &str)]) -> Sample {
    Sample {
        status,
        body: body.to_vec(),
        duration: Duration::from_millis(50),
        headers: headers
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect(),
    }
}

#[test]
fn baseline_without_signals_is_clean() {
    let samples = vec![
        sample(200, b"<html>hello</html>", &[]),
        sample(200, b"<html>hello</html>", &[]),
        sample(200, b"<html>hello</html>", &[]),
    ];
    let bl = Baseline::new(&samples);
    assert!(!bl.is_waf_blocked());
    assert!(!bl.is_waf_suspected());
    assert!(!bl.is_waf_blocking());
    assert_eq!(bl.waf_evidence_suffix(), "");
}

#[test]
fn stable_requires_same_status_and_body() {
    let samples = vec![
        sample(200, b"same", &[]),
        sample(200, b"same", &[]),
        sample(200, b"same", &[]),
    ];
    assert!(Baseline::new(&samples).is_stable());

    let mut different_status = samples.clone();
    different_status[2].status = 302;
    assert!(!Baseline::new(&different_status).is_stable());

    let mut different_body = samples;
    different_body[2].body = b"different".to_vec();
    assert!(!Baseline::new(&different_body).is_stable());
}

#[test]
fn rotating_csrf_token_keeps_baseline_stable() {
    let body = |token: &str| {
        format!(
            "<html><body><form><input type=\"hidden\" name=\"csrf_token\" value=\"{token}\">\
             <h1>Welcome</h1></form></body></html>"
        )
    };
    let samples = vec![
        sample(200, body("a1b2c3d4e5f6a7b8").as_bytes(), &[]),
        sample(200, body("9f8e7d6c5b4a3210").as_bytes(), &[]),
        sample(200, body("0123456789abcdef").as_bytes(), &[]),
    ];
    let bl = Baseline::new(&samples);
    // The raw bodies really differ; normalization absorbs the rotation.
    assert_ne!(bl.body_hashes[0], bl.body_hashes[1]);
    assert_eq!(bl.normalized_hashes.len(), 3);
    assert!(bl.is_stable());
}

#[test]
fn rotating_json_trace_id_keeps_baseline_stable() {
    let body = |trace: &str| format!("{{\"data\":1,\"trace_id\":\"{trace}\"}}");
    let samples = vec![
        sample(200, body("0123456789abcdef").as_bytes(), &[]),
        sample(200, body("fedcba9876543210").as_bytes(), &[]),
        sample(200, body("aabbccddeeff0011").as_bytes(), &[]),
    ];
    assert!(Baseline::new(&samples).is_stable());
}

#[test]
fn unnamed_rotating_zone_is_marked_and_stabilized() {
    // Bannière rotative NON nommée (hors champs volatils connus) entre
    // deux flancs stables > 40 chars : sqlmap la marque et la purge.
    let body = |token: &str| {
        format!(
            "{{\"header\":\"Lorem ipsum dolor sit amet, congue tation referrentur ei sed\",\
             \"banner\":\"ads-{token}\",\
             \"footer\":\"Usu sumo indoctum ad, pri paulo molestiae complectitur no\"}}"
        )
    };
    let samples = vec![
        sample(200, body("a1b2c3d4").as_bytes(), &[]),
        sample(200, body("9f8e7d6c").as_bytes(), &[]),
        sample(200, body("01234567").as_bytes(), &[]),
    ];
    let bl = Baseline::new(&samples);
    assert!(!bl.dynamic_markings.is_empty(), "zone rotative à marquer");
    assert!(bl.is_stable(), "page stable hors zone marquée");
    let stripped: Vec<String> = samples
        .iter()
        .map(|s| bl.strip_dynamic_content(&String::from_utf8_lossy(&s.body)))
        .collect();
    assert_eq!(stripped[0], stripped[1]);
    assert_eq!(stripped[1], stripped[2]);
    assert!(!stripped[0].contains("a1b2c3d4"));
}

#[test]
fn content_change_between_big_stable_flanks_is_marked_dynamic() {
    // Les flancs stables (input + `<h1>`) dépassent 40 chars ; la zone
    // entre eux (`Dashboard` vs `Reports`) est traitée comme dynamique,
    // comme sqlmap : la page redevient stable après purge.
    let body = |token: &str, heading: &str| {
        format!("<input type=\"hidden\" name=\"csrf_token\" value=\"{token}\"><h1>{heading}</h1>")
    };
    let samples = vec![
        sample(200, body("a1b2c3d4e5f6a7b8", "Dashboard").as_bytes(), &[]),
        sample(200, body("9f8e7d6c5b4a3210", "Dashboard").as_bytes(), &[]),
        sample(200, body("0123456789abcdef", "Reports").as_bytes(), &[]),
    ];
    let bl = Baseline::new(&samples);
    assert!(
        !bl.dynamic_markings.is_empty(),
        "zone Dashboard/Reports marquée"
    );
    assert!(bl.is_stable(), "stable après purge des zones marquées");
}

#[test]
fn large_real_content_change_still_unstable() {
    // Aucun flanc commun >= 40 chars (les seuls fragments partagés sont
    // des mots courts) : rien à marquer, le gate reste fail-closed.
    let first = format!(
        "<html><body>{}</body></html>",
        "The quick brown fox jumps over the lazy dog. ".repeat(4)
    );
    let second = format!(
        "<html><body>{}</body></html>",
        "Pack my box with five dozen liquor jugs. ".repeat(4)
    );
    let samples = vec![
        sample(200, first.as_bytes(), &[]),
        sample(200, first.as_bytes(), &[]),
        sample(200, second.as_bytes(), &[]),
    ];
    let bl = Baseline::new(&samples);
    assert!(bl.dynamic_markings.is_empty(), "{:?}", bl.dynamic_markings);
    assert!(!bl.is_stable());
}

#[test]
fn identical_pages_with_static_csrf_stay_stable() {
    let body = b"<input name=\"csrf_token\" value=\"fixed-token-value\"><h1>ok</h1>";
    let samples = vec![
        sample(200, body, &[]),
        sample(200, body, &[]),
        sample(200, body, &[]),
    ];
    let bl = Baseline::new(&samples);
    assert_eq!(bl.normalized_hashes.len(), bl.body_hashes.len());
    assert!(bl.is_stable());
}

#[test]
fn rotating_token_with_changing_length_stays_unstable() {
    let body = |token: &str| format!("<input name=\"csrf_token\" value=\"{token}\"><h1>ok</h1>");
    let samples = vec![
        sample(200, body("short-token-1").as_bytes(), &[]),
        sample(200, body("a-much-longer-rotating-token-2").as_bytes(), &[]),
        sample(200, body("medium-token-333").as_bytes(), &[]),
    ];
    // Normalization blanks all three values, but the raw byte length is
    // part of the stability key: a sample envelope whose size moved keeps
    // the gate fail-closed (documented residual strictness).
    assert!(!Baseline::new(&samples).is_stable());
}

#[test]
fn baseline_propagates_cf_presence_without_blocking() {
    let headers = [("cf-ray", "abc-IAD"), ("server", "cloudflare")];
    let samples = vec![
        sample(200, b"<html>hello</html>", &headers),
        sample(200, b"<html>hello</html>", &headers),
        sample(200, b"<html>hello</html>", &headers),
    ];
    let bl = Baseline::new(&samples);
    assert!(!bl.is_waf_blocked());
    assert!(bl.is_waf_suspected());
    assert!(
        !bl.is_waf_blocking(),
        "mere CDN presence must not downgrade"
    );
    assert_eq!(bl.waf_vendor.as_deref(), Some("cloudflare"));
    assert!(bl.waf_evidence_suffix().contains("waf=cloudflare:"));
}

#[test]
fn baseline_blocking_challenge_propagates() {
    let headers = [("cf-ray", "abc-IAD")];
    let body = b"<html><title>Just a moment...</title>managed challenge</html>";
    let samples = vec![
        sample(200, body, &headers),
        sample(200, body, &headers),
        sample(200, body, &headers),
    ];
    let bl = Baseline::new(&samples);
    assert!(bl.is_waf_suspected());
    assert!(bl.is_waf_blocking());
    assert!(bl.waf_evidence_suffix().contains("blocking=true"));
}

#[test]
fn ct_mismatch_json_api_served_html_is_presence() {
    let headers = [("content-type", "text/html; charset=utf-8")];
    let samples = vec![
        sample(200, b"<html>ok</html>", &headers),
        sample(200, b"<html>ok</html>", &headers),
    ];
    let mut bl = Baseline::new(&samples);
    assert!(!bl.is_waf_suspected());
    bl.apply_ct_mismatch(&samples, "application/json");
    assert!(bl.is_waf_suspected());
    assert!(
        !bl.is_waf_blocking(),
        "mismatch alone must not block: {}",
        bl.waf_evidence_suffix()
    );
    assert_eq!(bl.waf_vendor.as_deref(), Some("generic"));
    assert!(
        bl.waf_hits
            .iter()
            .any(|h| h == "ct-mismatch:expected-json-got-html"),
        "{}",
        bl.waf_evidence_suffix()
    );
}

#[test]
fn ct_mismatch_with_coroborating_status_blocks() {
    let headers = [("content-type", "text/html")];
    let samples = vec![sample(403, b"<html>denied</html>", &headers)];
    let mut bl = Baseline::new(&samples);
    bl.apply_ct_mismatch(&samples, "application/json");
    assert!(bl.is_waf_blocking(), "{}", bl.waf_evidence_suffix());
}

#[test]
fn ct_mismatch_noop_when_kinds_agree() {
    let headers = [("content-type", "application/json")];
    let samples = vec![sample(200, b"{\"a\":1}", &headers)];
    let mut bl = Baseline::new(&samples);
    bl.apply_ct_mismatch(&samples, "application/json");
    assert!(!bl.is_waf_suspected());
    assert_eq!(bl.waf_evidence_suffix(), "");
    // Non-API expectations never flag.
    let html = [("content-type", "text/html")];
    let html_samples = vec![sample(200, b"<html>ok</html>", &html)];
    let mut bl2 = Baseline::new(&html_samples);
    bl2.apply_ct_mismatch(&html_samples, "text/html");
    assert!(!bl2.is_waf_suspected());
}

#[test]
fn stable_page_learns_no_match_ratio() {
    let samples = vec![
        sample(200, b"<html>same</html>", &[]),
        sample(200, b"<html>same</html>", &[]),
        sample(200, b"<html>same</html>", &[]),
    ];
    let bl = Baseline::new(&samples);
    assert!(bl.is_stable());
    // Médiane Jaccard = 1.0 > UPPER_RATIO_BOUND : aucun plancher appris,
    // le veto empirique du détecteur booléen reste inactif.
    assert_eq!(bl.match_ratio(), None);
}

#[test]
fn fewer_than_two_samples_learn_no_match_ratio() {
    assert_eq!(Baseline::new(&[]).match_ratio(), None);
    let one = vec![sample(200, b"<html>same</html>", &[])];
    assert_eq!(Baseline::new(&one).match_ratio(), None);
}

#[test]
fn noisy_non_markable_page_learns_match_ratio() {
    // Bruit résiduel NON marquable : la valeur JSON aléatoire est encadrée
    // par des blocs communs courts (< 2 * DYNAMICITY_BOUNDARY_LENGTH) →
    // aucune zone P1.1 ; les tokens stables restent majoritaires → médiane
    // Jaccard 7/9 (le `:` dupliqué ne compte qu'une fois par ensemble),
    // dans la zone grise.
    let body = |banner: &str| format!("{{ \"banner\" : \"{banner}\" , \"note\" : \"short\" }}");
    let samples = vec![
        sample(200, body("ads-aaaaaaaa").as_bytes(), &[]),
        sample(200, body("ads-bbbbbbbb").as_bytes(), &[]),
        sample(200, body("ads-cccccccc").as_bytes(), &[]),
    ];
    let bl = Baseline::new(&samples);
    assert!(
        bl.dynamic_markings.is_empty(),
        "zone non marquable attendue : {:?}",
        bl.dynamic_markings
    );
    let Some(m) = bl.match_ratio() else {
        panic!("plancher appris attendu sur la page bruitée");
    };
    assert!(m < 0.98, "médiane bruitée < 0.98 attendue, got {m}");
    assert!(
        (m - 7.0 / 9.0).abs() < 1e-9,
        "médiane Jaccard 7/9 attendue, got {m}"
    );
}

#[test]
fn markable_noise_page_learns_raw_median() {
    // Zone rotative marquable (P1.1) entre deux flancs stables > 40 chars :
    // la baseline redevient stable APRÈS purge, mais le `match_ratio` est
    // appris sur les textes normalisés BRUTS (avant purge) — la médiane
    // reste < 1, un plancher est donc appris. C'est la cible du veto P1.2 :
    // les pages rendues utilisables comme oracle par le marquage.
    let body = |token: &str| {
        format!(
            "{{\"header\":\"Lorem ipsum dolor sit amet, congue tation referrentur ei sed\",\
             \"banner\":\"ads-{token}\",\
             \"footer\":\"Usu sumo indoctum ad, pri paulo molestiae complectitur no\"}}"
        )
    };
    let samples = vec![
        sample(200, body("a1b2c3d4").as_bytes(), &[]),
        sample(200, body("9f8e7d6c").as_bytes(), &[]),
        sample(200, body("01234567").as_bytes(), &[]),
    ];
    let bl = Baseline::new(&samples);
    assert!(!bl.dynamic_markings.is_empty());
    assert!(bl.is_stable(), "oracle utilisable grâce au marquage P1.1");
    let Some(m) = bl.match_ratio() else {
        panic!("plancher appris attendu sur la zone marquée");
    };
    assert!(m < 0.98, "médiane brute < 1 attendue, got {m}");
    assert!(m > 0.5, "la majorité des tokens restent stables, got {m}");
}
