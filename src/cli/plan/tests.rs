#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::engine::orchestrator::EngineConfig;
use crate::session::scrubber::Scrubber;
use crate::target::parameters::TargetParameter;
use crate::target::raw_request::RawRequest;

use super::*;

fn test_cfg() -> EngineConfig {
    let mut cfg = EngineConfig::default();
    cfg.net.allow_private = true;
    cfg
}

#[test]
fn empty_techniques_means_all_eight() {
    let kinds = technique_kinds_for_names(&[]);
    assert_eq!(kinds.len(), 8);
    let all = technique_kinds_for_names(&["all".to_owned()]);
    assert_eq!(all.len(), 8);
}

#[test]
fn unknown_techniques_fall_back_to_all() {
    let kinds = technique_kinds_for_names(&["nope".to_owned()]);
    assert_eq!(kinds.len(), 8);
}

#[test]
fn plan_is_offline_and_nonempty() {
    let mut cfg = test_cfg();
    cfg.techniques = vec!["all".to_owned()];
    let plan = build_plan("http://example.com/?id=1", &cfg).expect("plan");
    assert!(plan.dry_run);
    assert_eq!(plan.budget_spent, 0);
    assert!(!plan.is_empty());
    assert_eq!(plan.params.len(), 1);
    assert_eq!(plan.ordered.len(), 8);
    // `boolean` leads on a bare numeric param (entropie binaire Phase 0 :
    // EVI `4·p·(1-p)·base` → boolean prior 0.26 ⇒ 0.77 vs `error` prior
    // 0.15 ⇒ 0.46 ; l'ancien `(1-p)·base` donnait `error` 0.765 vs
    // `boolean` 0.74 — bugfix documenté, ordre L1 changé voulu), and
    // scores never rise.
    assert_eq!(plan.ordered[0].technique, "boolean");
    let mut prev = f64::INFINITY;
    for probe in &plan.ordered {
        assert!(
            probe.score <= prev + 1e-12,
            "scores not ordered: {} > {prev}",
            probe.score
        );
        prev = probe.score;
    }
}

#[test]
fn exotic_headers_gated_by_level() {
    // L1 : byte-identique historique (query seule, 0 synthétique).
    let (_, l1) = params_for_target_offline("http://example.com/?id=1", true, &[], None, None, 1)
        .expect("plan l1");
    assert_eq!(l1.len(), 1);
    assert_eq!(l1[0].key(), "id@query");
    // L2+ : UA/Referer/XFF/X-Real-IP ajoutés (second-order via header).
    let (_, l2) = params_for_target_offline("http://example.com/?id=1", true, &[], None, None, 2)
        .expect("plan l2");
    assert_eq!(l2.len(), 5);
    for name in ["User-Agent", "Referer", "X-Forwarded-For", "X-Real-IP"] {
        assert!(
            l2.iter()
                .any(|p| p.key() == format!("{name}@header:{name}")),
            "missing {name}: {:?}",
            l2.iter().map(TargetParameter::key).collect::<Vec<_>>()
        );
    }
}

#[test]
fn plan_is_deterministic_for_same_seed() {
    let mut a = test_cfg();
    a.seed = Some(42);
    let mut b = test_cfg();
    b.seed = Some(42);
    let pa = build_plan("http://example.com/?id=1", &a).expect("pa");
    let pb = build_plan("http://example.com/?id=1", &b).expect("pb");
    assert_eq!(pa.ordered, pb.ordered);
}

#[test]
fn plan_never_carries_secret_values() {
    let mut cfg = test_cfg();
    cfg.raw_request = Some(RawRequest {
        method: "GET".to_owned(),
        path: "/".to_owned(),
        headers: [("cookie".to_owned(), "sess=supersecret123".to_owned())]
            .into_iter()
            .collect(),
        body: None,
        http_version: "HTTP/1.1".to_owned(),
    });
    let plan = build_plan("http://example.com/?id=1", &cfg).expect("plan");
    let json = serde_json::to_string(&plan.scrubbed(&Scrubber::new(false))).expect("json");
    assert!(!json.contains("supersecret123"), "{json}");
}

#[test]
fn explain_offline_matches_roadmap_shape() {
    let line = explain_offline(
        "id@query",
        "boolean true_sim=0.91 false_sim=0.22 trials=3/3",
        0.95,
        14,
        Some(42),
        false,
    );
    assert_eq!(
        line,
        "TRUE≈baseline 0.91, FALSE≠baseline 0.22, 3/3, waf=none, 14 req, seed 42"
    );
}

fn base_config() -> EngineConfig {
    EngineConfig::default()
}

#[test]
fn single_step_without_escalation() {
    let steps = escalation_plan(&base_config(), false);
    assert_eq!(steps.len(), 1);
    assert_eq!(steps[0].label, "L1-baseline");
}

#[test]
fn three_steps_with_escalation() {
    let steps = escalation_plan(&base_config(), true);
    assert_eq!(steps.len(), 3);
    assert!(steps[1].config.budget.level >= 2);
    assert!(steps[2].config.budget.level >= 3);
    assert!(steps[2].config.matcher.text_only);
    assert!(!steps[0].config.matcher.text_only);
}

#[test]
fn l2_keeps_explicit_tampers() {
    let mut base = base_config();
    base.evasion.tampers = crate::techniques::tamper::parse_tamper_list(Some("versionedcomment"));
    let steps = escalation_plan(&base, true);
    assert_eq!(steps[1].config.evasion.tampers, base.evasion.tampers);
}

#[test]
fn l3_adds_equaltolike_without_base64() {
    use crate::techniques::tamper::Tamper;
    let steps = escalation_plan(&base_config(), true);
    let l3 = &steps[2].config.evasion.tampers;
    assert!(
        l3.contains(&Tamper::EqualToLike),
        "L3 should add equaltolike: {l3:?}"
    );
    assert!(
        !l3.contains(&Tamper::Base64Encode),
        "base64encode must stay opt-in (breaks boolean differentials): {l3:?}"
    );
    // bounded escalation: 6 tampers → 8 sets, not exponential
    assert_eq!(
        crate::techniques::tamper::tamper_transformation_sets(l3).len(),
        l3.len() + 2
    );
}

#[test]
fn l2_adds_versionedfuzz() {
    use crate::techniques::tamper::Tamper;
    let steps = escalation_plan(&base_config(), true);
    let l2 = &steps[1].config.evasion.tampers;
    assert!(
        l2.contains(&Tamper::VersionedFuzz),
        "L2 should add versionedfuzz: {l2:?}"
    );
    assert!(
        !l2.contains(&Tamper::Base64Encode),
        "base64encode must stay opt-in: {l2:?}"
    );
}

#[test]
fn l3_adds_numericobfuscate_and_linecomment() {
    use crate::techniques::tamper::Tamper;
    let steps = escalation_plan(&base_config(), true);
    let l3 = &steps[2].config.evasion.tampers;
    assert!(
        l3.contains(&Tamper::NumericObfuscate),
        "L3 should add numericobfuscate: {l3:?}"
    );
    assert!(
        l3.contains(&Tamper::LineComment),
        "L3 should add linecomment: {l3:?}"
    );
}
