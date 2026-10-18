use super::apply::{apply_case_mix, apply_comment_swap, apply_paren_wrap};
use super::*;
use crate::dbms::context::QuoteContext;
use crate::dbms::context::{CommentStyle, InjectionContext};

fn default_context() -> InjectionContext {
    InjectionContext::new()
}

#[test]
fn bound_never_exceeds_four() {
    let m = MiniMutator::all_enabled();
    let variants = m.generate("' OR 1=1 -- -", &default_context(), Some(42));
    assert!(
        variants.len() <= MAX_MUTATION_VARIANTS,
        "got {} variants",
        variants.len()
    );
    assert_eq!(MAX_MUTATION_VARIANTS, 4);
    assert_eq!(MAX_MUTATION_REQUESTS_PER_FINDING, 8);
}

#[test]
fn empty_base_yields_no_variant() {
    let m = MiniMutator::all_enabled();
    assert_eq!(
        m.generate("", &default_context(), Some(1)),
        [] as [MutatedVariant; 0]
    );
}

#[test]
fn deterministic_same_seed() {
    let m = MiniMutator::all_enabled();
    let ctx = default_context();
    let a = m.generate("' OR 1=1 -- -", &ctx, Some(7));
    let b = m.generate("' OR 1=1 -- -", &ctx, Some(7));
    assert_eq!(a, b);
    // Le plan est tracé : chaque variante porte `mutation:<famille>`.
    for v in &a {
        assert!(
            v.plan_label.starts_with("mutation:"),
            "plan_label must be traced: {}",
            v.plan_label
        );
        assert_eq!(v.plan_label, v.family.plan_label());
    }
}

#[test]
fn all_families_present_on_canonical_payload() {
    let m = MiniMutator::all_enabled();
    let variants = m.generate("' OR 1=1 -- -", &default_context(), Some(42));
    assert_eq!(variants.len(), 4, "got {variants:?}");
    let names: Vec<&str> = variants.iter().map(|v| v.family.name()).collect();
    assert_eq!(
        names,
        vec!["quote_fence", "paren_wrap", "comment_swap", "case_mix"]
    );
}

#[test]
fn quote_fence_skipped_on_numeric_bare_context() {
    let m = MiniMutator {
        quote_fence: true,
        paren_wrap: false,
        comment_swap: false,
        case_mix: false,
    };
    let mut ctx = InjectionContext::new();
    ctx.quote = QuoteContext::None;
    ctx.numeric = true;
    assert_eq!(
        m.generate("' OR 1=1 -- -", &ctx, Some(1)),
        [] as [MutatedVariant; 0]
    );
}

#[test]
fn paren_wrap_preserves_truth_marker() {
    let out = apply_paren_wrap("' OR 1=1 -- -").expect("paren variant");
    assert!(out.contains("(1=1)"), "got {out}");
    let out_false = apply_paren_wrap("' OR 1=2 -- -").expect("paren false variant");
    assert!(out_false.contains("(1=2)"), "got {out_false}");
}

#[test]
fn comment_swap_cycles_without_breaking_terminator() {
    let dash_variant =
        apply_comment_swap("' OR 1=1 -- -", CommentStyle::DashDash).expect("swap -- - -> --");
    assert!(dash_variant.ends_with(" --"), "got {dash_variant}");
    assert!(!dash_variant.ends_with(" -- -"));
    let back = apply_comment_swap(&dash_variant, CommentStyle::DashDash).expect("swap back");
    assert!(back.ends_with(" -- -"), "got {back}");
    let hash_variant =
        apply_comment_swap("' OR 1=1 -- -", CommentStyle::Hash).expect("swap to hash");
    assert!(hash_variant.ends_with('#'), "got {hash_variant}");
}

#[test]
fn case_mix_seeded_deterministic_and_letter_preserving() {
    let a = apply_case_mix("' OR SELECT 1 -- -", Some(11)).expect("case variant");
    let b = apply_case_mix("' OR SELECT 1 -- -", Some(11)).expect("case variant");
    assert_eq!(a, b);
    assert_eq!(a.to_ascii_lowercase(), "' or select 1 -- -");
}

#[test]
fn gate_mirrors_orchestrator_rule() {
    // Confirmé : TRUE.
    assert!(is_confirmed_evidence(
        "boolean true_sim=0.9 trials=3/3",
        0.9
    ));
    // `unconfirmed` ou confiance < 0.5 : jamais de mutation.
    assert!(!is_confirmed_evidence("error 0.55 unconfirmed", 0.55));
    assert!(!is_confirmed_evidence("boolean trials=1/3", 0.4));
}

#[test]
fn gate_blocks_no_mutation_waf_unconfirmed_oob() {
    // Défaut : ON.
    assert!(should_attempt_mutation(false, false, true, false));
    // `--no-mutation` : OFF.
    assert!(!should_attempt_mutation(true, false, true, false));
    // WAF-penalty : pas de spray si blocking.
    assert!(!should_attempt_mutation(false, true, true, false));
    // Jamais sans finding confirmé.
    assert!(!should_attempt_mutation(false, false, false, false));
    // Jamais d'OOB muté.
    assert!(!should_attempt_mutation(false, false, true, true));
}

#[test]
fn disabled_families_yield_nothing() {
    let m = MiniMutator::none();
    assert_eq!(
        m.generate("' OR 1=1 -- -", &default_context(), Some(1)),
        [] as [MutatedVariant; 0]
    );
}

#[test]
fn variants_never_duplicate_base() {
    let m = MiniMutator::all_enabled();
    let base = "' OR 1=1 -- -";
    for v in m.generate(base, &default_context(), Some(3)) {
        assert_ne!(v.payload, base);
    }
}
