//! Gating/routing unit tests for `engine::orchestrator` facade items
//! (ex `orchestrator_gating_tests`, P5 split): confirm scope, second-pass
//! windows, dbms labels, payload ordering, belief promotion, calibration.

use crate::engine::{
    confirm::{
        ConfirmScope, dbms_label_from_finding, has_confirmed_finding, in_confirm_scope,
        is_confirmed_finding, is_extraction_eligible, needs_auto_second_pass,
    },
    detection::{apply_outcome_to_hypothesis, infer_signal_and_trials},
    schedule::{
        dbms_payload_label, order_boolean_by_context, order_by_prefix_for_context,
        parse_finding_dbms,
    },
};
use crate::{
    dbms::{
        DbmsKind,
        context::{DbmsBelief, InjectionContext, QuoteContext},
    },
    detection::baseline::{Baseline, Sample},
    reasoning::Hypothesis,
    session::state::{Finding, TechniqueKind},
};
use std::time::Duration;

fn finding(technique: TechniqueKind, confidence: f64, evidence: &str) -> Finding {
    Finding::new(
        "https://example.com/?id=1",
        "id@query",
        technique,
        confidence,
        evidence,
    )
}

#[test]
fn unconfirmed_error_does_not_count_as_confirmed() {
    let f = finding(
        TechniqueKind::Error,
        0.55,
        "error pattern X bool_confirm=false unconfirmed",
    );
    assert!(!is_confirmed_finding(&f));
    assert!(!has_confirmed_finding(&[f]));
}

#[test]
fn boolean_and_confirmed_error_count() {
    let b = finding(
        TechniqueKind::Boolean,
        0.8,
        "boolean true_sim=0.9 false_sim=0.1",
    );
    let e = finding(
        TechniqueKind::Error,
        0.9,
        "error extracted=yes bool_confirm=true",
    );
    assert!(is_confirmed_finding(&b));
    assert!(has_confirmed_finding(&[e]));
    // Mixed: one confirmed suffices even with an unconfirmed alongside.
    let u = finding(TechniqueKind::Error, 0.55, "error unconfirmed");
    assert!(has_confirmed_finding(&[u, b]));
}

#[test]
fn auto_second_pass_excludes_high_bucket() {
    // P2.4: `High` (score + FP estimate both agree) already meets the
    // ≥95 % precision claim — re-probing it would only add traffic.
    let high = finding(TechniqueKind::Boolean, 0.9, "boolean true_sim=0.95")
        .with_false_positive_prob(0.02);
    assert!(!needs_auto_second_pass(&high));
    // `--confirm` still re-validates it (scope All = historical filter).
    assert!(in_confirm_scope(&high, ConfirmScope::All));
}

#[test]
fn auto_second_pass_includes_medium_and_low() {
    let medium = finding(TechniqueKind::Boolean, 0.75, "boolean true_sim=0.8")
        .with_false_positive_prob(0.10);
    let low =
        finding(TechniqueKind::Stacked, 0.6, "stacked marker=ok").with_false_positive_prob(0.40);
    assert!(needs_auto_second_pass(&medium));
    assert!(needs_auto_second_pass(&low));
    assert!(in_confirm_scope(&medium, ConfirmScope::MediumRisk));
    assert!(in_confirm_scope(&low, ConfirmScope::MediumRisk));
}

#[test]
fn auto_second_pass_includes_former_window_mismatch_techniques() {
    // P2.4b: first-pass window parity fixed the former gaps — `Time`
    // re-sweeps the same payload family/budget (blind sweep included),
    // `Json` replays the GraphQL envelope, `Json`/`Nosql` re-probe the
    // finding's original channel (`channel=error` → error probe) and
    // `Nosql` keeps the JSON-body operator shape. A failed
    // re-confirmation is now conclusive, so these techniques join the
    // automatic scope instead of staying `--confirm`-only.
    let time =
        finding(TechniqueKind::Time, 0.6, "time delay control=ok").with_false_positive_prob(0.40);
    let json = finding(TechniqueKind::Json, 0.75, "channel=error").with_false_positive_prob(0.10);
    let nosql = finding(TechniqueKind::Nosql, 0.75, "channel=error").with_false_positive_prob(0.10);
    for f in [&time, &json, &nosql] {
        assert!(needs_auto_second_pass(f), "{f:?}");
        assert!(in_confirm_scope(f, ConfirmScope::MediumRisk), "{f:?}");
        assert!(in_confirm_scope(f, ConfirmScope::All), "{f:?}");
    }
}

#[test]
fn auto_second_pass_excludes_unconfirmed_and_oob() {
    let unconfirmed = finding(TechniqueKind::Error, 0.55, "error pattern unconfirmed");
    assert!(!needs_auto_second_pass(&unconfirmed));
    // OOB is never re-probed (collaborator proof is already authoritative).
    let oob = finding(TechniqueKind::Oob, 0.9, "oob seen=true").with_false_positive_prob(0.01);
    assert!(!needs_auto_second_pass(&oob));
    // Scope All keeps the historical OOB exclusion.
    assert!(!in_confirm_scope(&oob, ConfirmScope::All));
}

#[test]
fn all_scope_takes_every_confirmed_non_oob() {
    // `--confirm` byte-identical: High/Medium/Low confirmed findings are
    // all re-validated; unconfirmed and OOB stay out.
    let high = finding(TechniqueKind::Union, 0.9, "union columns=3").with_false_positive_prob(0.02);
    let medium = finding(TechniqueKind::Boolean, 0.75, "boolean true_sim=0.8")
        .with_false_positive_prob(0.10);
    let low =
        finding(TechniqueKind::Stacked, 0.6, "stacked marker=ok").with_false_positive_prob(0.40);
    let unconfirmed = finding(TechniqueKind::Error, 0.55, "error pattern unconfirmed");
    let oob = finding(TechniqueKind::Oob, 0.9, "oob seen=true");
    for f in [&high, &medium, &low] {
        assert!(in_confirm_scope(f, ConfirmScope::All), "{f:?}");
    }
    for f in [&unconfirmed, &oob] {
        assert!(!in_confirm_scope(f, ConfirmScope::All), "{f:?}");
    }
    // The automatic scope is the strict subset: High stays out.
    assert!(!in_confirm_scope(&high, ConfirmScope::MediumRisk));
    assert!(in_confirm_scope(&medium, ConfirmScope::MediumRisk));
    assert!(in_confirm_scope(&low, ConfirmScope::MediumRisk));
}

#[test]
fn stacked_or_time_only_is_confirmed_but_not_oracle_eligible() {
    // Post-#17/#18 findings are confirmed (two-shot), but they cannot
    // feed a boolean-differential oracle: enumeration must stay silent.
    let stacked = finding(
        TechniqueKind::Stacked,
        0.6,
        "stacked dbms=generic marker=stacked_abc tamper=none confirmed=true",
    );
    let time = finding(
        TechniqueKind::Time,
        0.75,
        "time delay 3000ms > threshold 300ms tamper=none control=50ms",
    );
    assert!(has_confirmed_finding(&[stacked.clone(), time.clone()]));
    assert!(!is_extraction_eligible(&[stacked, time]));
}

#[test]
fn boolean_stays_oracle_eligible() {
    let b = finding(
        TechniqueKind::Boolean,
        0.8,
        "boolean true_sim=0.9 false_sim=0.1",
    );
    assert!(has_confirmed_finding(std::slice::from_ref(&b)));
    assert!(is_extraction_eligible(std::slice::from_ref(&b)));
}

// v0.5-4 loop-closure: `>= 0.85` bar drives quote-correct payloads.

#[test]
fn dbms_label_needs_point_eight_five() {
    assert_eq!(dbms_payload_label(&DbmsBelief::uniform()), None);
    let mut confident = DbmsBelief::uniform();
    confident.update_with_signal(DbmsKind::MySql, 0.9);
    assert_eq!(dbms_payload_label(&confident), Some("mysql"));
    let mut weak = DbmsBelief::uniform();
    weak.update_with_signal(DbmsKind::Postgres, 0.6);
    // 0.6 signal still normalizes below the 0.85 fill bar.
    assert_eq!(dbms_payload_label(&weak), None);
}

#[test]
fn finding_dbms_roundtrip() {
    assert_eq!(parse_finding_dbms(Some("mysql")), Some(DbmsKind::MySql));
    assert_eq!(
        parse_finding_dbms(Some("PostgreSQL")),
        Some(DbmsKind::Postgres)
    );
    assert_eq!(parse_finding_dbms(Some("mssql")), Some(DbmsKind::MsSql));
    assert_eq!(parse_finding_dbms(Some("oracle")), Some(DbmsKind::Oracle));
    assert_eq!(parse_finding_dbms(Some("sqlite")), Some(DbmsKind::Sqlite));
    assert_eq!(parse_finding_dbms(None), None);
    assert_eq!(parse_finding_dbms(Some("unknown-db")), None);
}

#[test]
fn finding_label_keeps_sqlite_quote_style() {
    // P0-3: a confirmed sqlite finding must drive `--`-style confirm
    // payloads (was: `None` → generic `-- -` polyglots).
    use crate::session::state::{Finding, TechniqueKind};
    let mut f = Finding::new("http://a", "id@query", TechniqueKind::Error, 0.9, "e");
    f.dbms = Some("sqlite".to_owned());
    assert_eq!(dbms_label_from_finding(&f), Some("sqlite"));
    f.dbms = Some("  SQLITE ".to_owned());
    assert_eq!(dbms_label_from_finding(&f), Some("sqlite"));
    f.dbms = None;
    assert_eq!(dbms_label_from_finding(&f), None);
    f.dbms = Some("unknown-db".to_owned());
    assert_eq!(dbms_label_from_finding(&f), None);
}

#[test]
fn json_scan_appends_graphql_after_direct() {
    // P0-2: `variables`-envelope probes ride last so L1 (`take(2)`)
    // stays byte-identical to the historical direct sweep.
    let v = crate::engine::schedule::json_scan_payloads(None);
    assert_eq!(v.len(), 8, "{v:?}");
    for (i, p) in v.iter().enumerate().take(6) {
        assert!(
            !p.true_payload.contains("variables"),
            "direct {i}: {}",
            p.true_payload
        );
    }
    assert!(
        v[6].true_payload.contains("\"variables\""),
        "{}",
        v[6].true_payload
    );
    assert!(
        v[7].true_payload.contains("\"variables\""),
        "{}",
        v[7].true_payload
    );
    // DBMS-narrowed belief keeps only its own envelope probe.
    let mysql = crate::engine::schedule::json_scan_payloads(Some("mysql"));
    assert_eq!(mysql.len(), 4, "{mysql:?}");
    assert!(mysql[3].true_payload.contains("\"variables\""));
    // sqlite has no envelope probe (narrow 2-payload JSON1 sweep).
    let sqlite = crate::engine::schedule::json_scan_payloads(Some("sqlite"));
    assert_eq!(sqlite.len(), 2, "{sqlite:?}");
    assert!(
        sqlite.iter().all(|p| !p.true_payload.contains("variables")),
        "{sqlite:?}"
    );
}

#[test]
fn boolean_order_follows_quote_context() {
    use crate::techniques::boolean::payloads::boolean_payloads_for;
    let mut numeric_ctx = InjectionContext::new();
    numeric_ctx.quote = QuoteContext::None;
    numeric_ctx.numeric = true;
    let mut payloads = boolean_payloads_for(None);
    order_boolean_by_context(&mut payloads, &numeric_ctx);
    assert!(
        payloads
            .first()
            .is_some_and(|p| p.true_payload.starts_with('1')),
        "numeric bare must lead with `1 AND/OR`"
    );

    let mut dq_ctx = InjectionContext::new();
    dq_ctx.quote = QuoteContext::DoubleQuote;
    let mut payloads = boolean_payloads_for(None);
    order_boolean_by_context(&mut payloads, &dq_ctx);
    assert!(
        payloads
            .first()
            .is_some_and(|p| p.true_payload.starts_with('"')),
        "double-quote must lead with `\"`"
    );
}

#[test]
fn order_by_prefix_is_quote_correct() {
    let mut ctx = InjectionContext::new();
    ctx.quote = QuoteContext::DoubleQuote;
    assert_eq!(order_by_prefix_for_context(&ctx), "\"");
    let mut numeric = InjectionContext::new();
    numeric.quote = QuoteContext::None;
    numeric.numeric = true;
    assert_eq!(order_by_prefix_for_context(&numeric), "");
    assert_eq!(order_by_prefix_for_context(&InjectionContext::new()), "'");
}

#[test]
fn oob_payloads_narrow_with_confident_belief() {
    use crate::techniques::oob::payloads::oob_payloads_for;
    let mut belief = DbmsBelief::uniform();
    belief.update_with_signal(DbmsKind::MsSql, 0.9);
    let label = dbms_payload_label(&belief);
    assert_eq!(label, Some("mssql"));
    let narrowed = oob_payloads_for(label, "example.oob", "tok123");
    assert!(!narrowed.is_empty());
    assert!(narrowed.iter().all(|p| p.dbms == "mssql"));
    let generic = oob_payloads_for(None, "example.oob", "tok123");
    assert_eq!(generic.len(), 3);
}

#[test]
fn confirmed_dbms_finding_promotes_hypothesis_belief() {
    let baseline = Baseline::new(&[
        Sample {
            status: 200,
            body: b"ok".to_vec(),
            duration: Duration::from_millis(50),
            headers: Vec::new(),
        },
        Sample {
            status: 200,
            body: b"ok".to_vec(),
            duration: Duration::from_millis(51),
            headers: Vec::new(),
        },
        Sample {
            status: 200,
            body: b"ok".to_vec(),
            duration: Duration::from_millis(52),
            headers: Vec::new(),
        },
    ]);
    let mut hyp = Hypothesis::new(
        "id@query".to_owned(),
        TechniqueKind::Union,
        DbmsBelief::uniform(),
        InjectionContext::new(),
    );
    let mut f = finding(
        TechniqueKind::Union,
        0.9,
        "union columns=3 order_by_inferred=3 tamper=none",
    );
    f.dbms = Some("postgres".to_owned());
    apply_outcome_to_hypothesis(&mut hyp, TechniqueKind::Union, &[f], 5, &baseline);
    let (top, prob) = hyp.dbms_belief.top_candidate();
    assert_eq!(top, DbmsKind::Postgres);
    assert!(prob >= 0.85, "post-promotion prob {prob} < 0.85");
    assert!(hyp.is_confirmed());
}

#[test]
fn signal_calibration_matches_provisional_table() {
    // Provisional v0.5 table (recalibrate on `history.jsonl` once 5+ runs
    // per scenario exist): boolean/error 0.9, union 0.85, time/stacked
    // 0.8, json boolean-channel 0.9 else 0.75, oob 1.0.
    let confirmed = finding(TechniqueKind::Boolean, 0.9, "boolean ok");
    assert_eq!(
        infer_signal_and_trials(TechniqueKind::Boolean, &[confirmed], false),
        (0.9, 1)
    );
    let confirmed = finding(TechniqueKind::Union, 0.9, "union ok");
    assert_eq!(
        infer_signal_and_trials(TechniqueKind::Union, &[confirmed], false),
        (0.85, 1)
    );
    let confirmed = finding(TechniqueKind::Time, 0.8, "time ok");
    assert_eq!(
        infer_signal_and_trials(TechniqueKind::Time, &[confirmed], false),
        (0.8, 1)
    );
    let unconfirmed = finding(TechniqueKind::Error, 0.55, "error unconfirmed");
    assert_eq!(
        infer_signal_and_trials(TechniqueKind::Error, &[unconfirmed], true),
        (0.4, 0)
    );
}
