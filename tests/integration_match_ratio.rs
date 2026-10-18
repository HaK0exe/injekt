#![allow(clippy::unwrap_used, clippy::expect_used)]

//! P1.2 (partie 2/2) — plancher de bruit appris (`match_ratio`) + veto booléen.
//!
//! Couvre l'intégration RÉELLE des deux briques (pas de mock) :
//! [`Baseline::new`] apprend le plancher sur trois échantillons d'une page
//! dont la bannière tourne dans une zone marquable P1.1 (la page reste un
//! oracle utilisable : `is_stable()`), puis
//! [`BooleanDetector::evaluate_with_match_ratio`] reçoit des corps réels
//! (échantillon représentatif, branche TRUE ≈ baseline, branche FALSE dans la
//! bande de bruit) et vétote le « différentiel ».
//!
//! # Limite assumée (pas de scénario wiremock de bout en bout)
//!
//! La mise en scène demandée — mock wiremock sur lequel les probes TRUE/FALSE
//! produiraient, SANS plancher, un verdict vulnérable via la logique gap —
//! s'est révélée infaisable proprement :
//! - la première passe booléenne (`test_boolean_bounded`) et la seconde passe
//!   (`confirm_boolean_second_pass`) ne consomment QUE `true_similarity` /
//!   `false_similarity` (poussées dans les `Trial`) : le champ `is_vulnerable`
//!   du détecteur n'y est jamais lu, donc le veto n'y est pas observable de
//!   bout en bout ;
//! - les deux sites moteur où `is_vulnerable` EST lu — la confirmation
//!   erreur→booléen (`confirm_error_with_boolean`) et l'heuristique de
//!   fingerprint (`active_fingerprint_probe`) — exigeraient une chorégraphie
//!   fragile (pattern d'erreur DB + bruit marquable + bande de bruit exacte
//!   sur les payloads réels), pour une preuve déjà couverte ici au niveau des
//!   fonctions.
//!
//! Les valeurs Jaccard attendues sont exactes (ensembles de tokens) :
//! `j_true` = 24/25 = 0.96, `j_false` = m = 21/27 ≈ 0.778, gap ≈ 0.182 > 0.15.

use injekt::{
    detection::baseline::{Baseline, Sample},
    detection::dynamic_content::DynamicMarking,
    techniques::boolean::detector::BooleanDetector,
};
use std::time::Duration;

/// Page dont la bannière (3 tokens rotatifs) est encadrée par deux flancs
/// stables > 40 chars : marquable par P1.1, donc stable après purge.
fn page(tag: &str) -> String {
    let banner = format!("ads-{tag}-a ads-{tag}-b ads-{tag}-c");
    format!(
        "<html><body><h1>Product listing</h1>\
         <div class=\"header\">Lorem ipsum dolor sit amet, congue tation referrentur ei sed</div>\
         <div class=\"banner\">{banner}</div>\
         <div class=\"footer\">Usu sumo indoctum ad, pri paulo molestiae complectitur no</div>\
         </body></html>"
    )
}

fn sample(body: String) -> Sample {
    Sample {
        status: 200,
        body: body.into_bytes(),
        duration: Duration::from_millis(50),
        headers: Vec::new(),
    }
}

/// Page stable (aucun bruit résiduel) : aucun plancher appris → le veto
/// empirique reste inactif et le verdict historique (gap ancré) est conservé,
/// même en passant le `match_ratio` (absent) de la baseline.
#[test]
fn stable_page_learns_no_floor_and_keeps_legacy_verdict() {
    let samples = vec![
        sample(page("01234567")),
        sample(page("01234567")),
        sample(page("01234567")),
    ];
    let baseline = Baseline::new(&samples);
    assert!(baseline.is_stable());
    assert_eq!(
        baseline.match_ratio(),
        None,
        "page parfaitement stable → pas de plancher (comportement fixe conservé)"
    );

    let base = baseline.representative_body_str();
    let true_body = format!("{base} extra_true_marker");
    let false_body = page("fedcba98");
    let detector = BooleanDetector::new();
    let verdict = detector.evaluate_with_match_ratio(
        &base,
        &true_body,
        &false_body,
        100.0,
        100.0,
        100.0,
        baseline.match_ratio(),
    );
    assert!(
        verdict.is_vulnerable,
        "sans plancher appris, le gap ancré garde son verdict : {verdict:?}"
    );
}

/// Page bruitée dans une zone marquable : un plancher `Some(m)` est appris sur
/// les textes normalisés bruts (avant purge P1.1), puis le veto transforme un
/// « différentiel » resté dans la bande de bruit en verdict non vulnérable.
#[test]
fn markable_noise_learns_floor_and_vetoes_noise_band_pair() {
    let samples = vec![
        sample(page("01234567")),
        sample(page("89abcdef")),
        sample(page("fedcba98")),
    ];
    let baseline = Baseline::new(&samples);
    assert!(
        baseline.is_stable(),
        "la page bruitée reste un oracle utilisable grâce au marquage P1.1"
    );
    assert_ne!(baseline.dynamic_markings, [] as [DynamicMarking; 0]);
    let Some(floor) = baseline.match_ratio() else {
        panic!("plancher appris attendu sur la zone marquée");
    };
    assert!(
        (floor - 21.0 / 27.0).abs() < 1e-9,
        "médiane Jaccard 21/27 attendue, got {floor}"
    );

    // Corps réels : la baseline est l'échantillon représentatif (tag
    // `89abcdef`) ; TRUE ≈ baseline (+1 token, Jaccard 24/25 = 0.96) ; FALSE
    // est une autre réponse réelle de la page (tag `fedcba98`), à la
    // similarité du bruit appris (21/27). Gap ≈ 0.182 > 0.15 et branche TRUE
    // ancrée → sans plancher la logique historique confirme ; avec le
    // plancher, les deux branches restent `Same` (≥ m − 0.05) → veto.
    let base = baseline.representative_body_str();
    let true_body = format!("{base} extra_true_marker");
    let false_body = page("fedcba98");
    let detector = BooleanDetector::new();

    let legacy = detector.evaluate(&base, &true_body, &false_body, 100.0, 100.0, 100.0);
    assert!(
        legacy.is_vulnerable,
        "sans plancher : gap ancré → vulnérable : {legacy:?}"
    );

    let vetoed = detector.evaluate_with_match_ratio(
        &base,
        &true_body,
        &false_body,
        100.0,
        100.0,
        100.0,
        baseline.match_ratio(),
    );
    assert!(
        !vetoed.is_vulnerable,
        "les deux branches restent dans la bande de bruit → veto : {vetoed:?}"
    );
    assert!(
        (vetoed.confidence - 0.2).abs() < 1e-9,
        "confiance non vulnérable attendue, got {}",
        vetoed.confidence
    );
    // Le veto ne falsifie jamais les mesures : les similarités restent celles
    // du chemin historique.
    assert!((vetoed.true_similarity - legacy.true_similarity).abs() < 1e-12);
    assert!((vetoed.false_similarity - legacy.false_similarity).abs() < 1e-12);
}
