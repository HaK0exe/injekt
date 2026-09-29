#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Propriétés du générateur par grammaire : paires cohérentes, jamais
//! effondrées, forme booléenne, terminateur respecté, labels tracés.

use injekt::dbms::common::DbmsKind;
use injekt::dbms::context::QuoteContext;
use injekt::generation::{Logic, Predicate, QuoteFence, Separator, build_pair};
use proptest::prelude::*;

fn fence_of(i: usize) -> QuoteFence {
    QuoteFence::ordered_for_context(&QuoteContext::Unknown)[i % 9]
}

fn pred_of(i: usize) -> Predicate {
    Predicate::all_ordered()[i % Predicate::all_ordered().len()]
}

fn kind_of(i: usize) -> DbmsKind {
    match i % 6 {
        0 => DbmsKind::MySql,
        1 => DbmsKind::Postgres,
        2 => DbmsKind::MsSql,
        3 => DbmsKind::Oracle,
        4 => DbmsKind::Sqlite,
        _ => DbmsKind::Unknown,
    }
}

proptest! {
    #[test]
    fn generated_pairs_are_coherent(
        fi in 0usize..36,
        li in 0usize..2,
        pi in 0usize..40,
        ki in 0usize..12,
        ci in 0usize..3,
        si in 0usize..3,
    ) {
        let fence = fence_of(fi);
        let logic = if li == 0 { Logic::Or } else { Logic::And };
        let pred = pred_of(pi);
        let kind = kind_of(ki);
        let comment = [" -- -", " --", "#"][ci % 3];
        let sep = [Separator::Space, Separator::Tab, Separator::Newline][si % 3];
        let p = build_pair(fence, logic, pred, kind, comment, sep);
        prop_assert!(!p.true_payload.is_empty());
        // Forme espacée `{open}{sep}{kw}{sep}…` vs spaceless `{open}{kw}…`
        // (le séparateur est ignoré).
        let open = fence.open();
        let kw = logic.keyword();
        let s = sep.as_str();
        // Forme espacée `{open} {kw} …` vs spaceless `{open}{kw}…`.
        let prefix = if pred.is_spaceless() {
            format!("{open}{kw}")
        } else {
            format!("{open}{s}{kw}{s}")
        };
        prop_assert!(p.true_payload.starts_with(&prefix));
        prop_assert!(p.false_payload.starts_with(&prefix));
        prop_assert!(p.true_payload.ends_with(comment));
        prop_assert!(p.false_payload.ends_with(comment));
        // Longueur bornée (anti-flood) : bien sous la limite validator.
        prop_assert!(p.true_payload.len() < 256);
        prop_assert!(p.false_payload.len() < 256);
        prop_assert_ne!(p.true_payload, p.false_payload);
    }

    #[test]
    fn enumerate_is_deterministic_per_seed(
        seed in 0u64..100,
        max in 1u8..16,
    ) {
        use injekt::dbms::context::InjectionContext;
        use injekt::generation::{GenerativeMode, enumerate_candidates};
        let ctx = InjectionContext::new();
        let a = enumerate_candidates(&ctx, DbmsKind::Unknown, " -- -", GenerativeMode::Aggressive, max, Some(seed));
        let b = enumerate_candidates(&ctx, DbmsKind::Unknown, " -- -", GenerativeMode::Aggressive, max, Some(seed));
        prop_assert_eq!(a.len(), b.len());
        for (x, y) in a.iter().zip(b.iter()) {
            prop_assert_eq!(&x.payload.true_payload, &y.payload.true_payload);
            prop_assert_eq!(&x.label, &y.label);
        }
        prop_assert!(a.len() <= usize::from(max));
    }
}
