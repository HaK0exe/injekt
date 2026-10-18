// Tests C14 : 1 plante par variante de cause + priorités + surfaces scrub/serialize
// (fichier séparé sous la barre 500L ; convention allow-header par fichier).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;

fn cli_argv(tokens: &[&str]) -> Vec<String> {
    tokens.iter().copied().map(str::to_owned).collect()
}

// ------------------------------------------------------------------
// 1 test par variante — suggestion frappée au token
// ------------------------------------------------------------------

#[test]
fn unstable_baseline_suggests_direct_fetch_and_time() {
    let argv = cli_argv(&["--target", "https://lab.tld/?id=1"]);
    let diag = Diagnostic::derive(&DiagSignals {
        unstable_statuses: vec![200, 403, 200],
        argv: argv.clone(),
        ..DiagSignals::default()
    })
    .expect("unstable baseline must derive");
    match diag.cause {
        InconclusiveCause::UnstableBaseline { statuses } => {
            assert_eq!(statuses, vec![200, 403, 200]);
        }
        other => panic!("wrong cause: {other:?}"),
    }
    assert_eq!(
        diag.suggestion.as_deref(),
        Some("injekt --target \"https://lab.tld/?id=1\" --fetch-using direct --techniques time")
    );
}

#[test]
fn baseline_unreachable_reuses_the_unstable_mapping() {
    let argv = cli_argv(&["--target", "https://lab.tld/p"]);
    let diag = Diagnostic::derive(&DiagSignals {
        baseline_all_error: true,
        argv: argv.clone(),
        ..DiagSignals::default()
    })
    .expect("unreachable baseline must derive");
    assert_eq!(diag.cause.code(), "BaselineUnreachable");
    // URL sans métacaractère shell (`-_.:/` sont passables sans quote).
    assert_eq!(
        diag.suggestion.as_deref(),
        Some("injekt --target https://lab.tld/p --fetch-using direct --techniques time")
    );
}

#[test]
fn waf_blocked_appends_complete_tamper_chain_once() {
    let argv = cli_argv(&["--target", "https://lab.tld/?id=1"]);
    let diag = Diagnostic::derive(&DiagSignals {
        count_403: WAF_BLOCK_COUNT_MIN,
        argv: argv.clone(),
        ..DiagSignals::default()
    })
    .expect("waf blocked must derive");
    assert_eq!(
        diag.suggestion.as_deref(),
        Some("injekt --target \"https://lab.tld/?id=1\" --tamper space2comment,randomcase")
    );
    assert_eq!(diag.cause.code(), "WafBlocked");
}

#[test]
fn waf_blocked_is_silent_when_tamper_already_set() {
    let argv = cli_argv(&["--target", "https://lab.tld/", "--tamper", "randomcase"]);
    let diag = Diagnostic::derive(&DiagSignals {
        count_403: 10,
        argv: argv.clone(),
        ..DiagSignals::default()
    })
    .expect("waf blocked must derive");
    assert!(
        diag.suggestion.is_none(),
        "operator chose tampers explicitly — nothing to add, got {:?}",
        diag.suggestion
    );
}

#[test]
fn rate_limited_appends_ignore_code_and_rate_limit() {
    let argv = cli_argv(&["--target", "https://lab.tld/?id=1"]);
    let diag = Diagnostic::derive(&DiagSignals {
        count_429: RATE_LIMIT_COUNT_MIN,
        argv: argv.clone(),
        ..DiagSignals::default()
    })
    .expect("rate limited must derive");
    assert_eq!(diag.cause.code(), "RateLimited");
    assert_eq!(
        diag.suggestion.as_deref(),
        Some("injekt --target \"https://lab.tld/?id=1\" --ignore-code 429 --rate-limit 2")
    );
}

#[test]
fn rate_limited_dupes_do_not_override_operator_flags() {
    let argv = cli_argv(&[
        "--target",
        "https://lab.tld/",
        "--ignore-code",
        "503",
        "--rate-limit",
        "10",
    ]);
    let diag = Diagnostic::derive(&DiagSignals {
        count_429: 30,
        argv: argv.clone(),
        ..DiagSignals::default()
    })
    .expect("rate limited must derive");
    assert!(
        diag.suggestion.is_none(),
        "both flags already present, no override possible"
    );
}

#[test]
fn network_timeout_suggests_doctor_not_flags() {
    let argv = cli_argv(&["--target", "https://lab.tld/"]);
    let diag = Diagnostic::derive(&DiagSignals {
        network_timeout: true,
        argv,
        ..DiagSignals::default()
    })
    .expect("network timeout must derive");
    assert_eq!(diag.cause.code(), "NetworkTimeout");
    assert_eq!(diag.suggestion.as_deref(), Some("run `injekt doctor`"));
    // Pas d'argv requis : le conseil est procédural.
    assert_eq!(
        Diagnostic::derive(&DiagSignals {
            network_timeout: true,
            ..DiagSignals::default()
        })
        .expect("network timeout must derive")
        .suggestion
        .as_deref(),
        Some("run `injekt doctor`")
    );
}

#[test]
fn budget_exhausted_is_pure_info_without_suggestion() {
    let argv = cli_argv(&["--target", "https://lab.tld/"]);
    let diag = Diagnostic::derive(&DiagSignals {
        over_request_budget: true,
        argv,
        ..DiagSignals::default()
    })
    .expect("budget must derive");
    assert_eq!(diag.cause.code(), "BudgetExhausted");
    assert!(diag.suggestion.is_none());
    assert!(diag.why.contains("--request-budget"));
}

#[test]
fn duration_expired_is_pure_info_without_suggestion() {
    let argv = cli_argv(&["--target", "https://lab.tld/"]);
    let diag = Diagnostic::derive(&DiagSignals {
        duration_expired: true,
        argv,
        ..DiagSignals::default()
    })
    .expect("duration must derive");
    assert_eq!(diag.cause.code(), "DurationExpired");
    assert!(diag.suggestion.is_none());
    assert!(diag.why.contains("--max-duration"));
}

// ------------------------------------------------------------------
// Priorité stricte, pas de suggestion factice, argv déjà équipé
// ------------------------------------------------------------------

#[test]
fn instability_wins_over_rate_limiting() {
    let diag = Diagnostic::derive(&DiagSignals {
        unstable_statuses: vec![200, 500, 200],
        count_429: 40,
        argv: cli_argv(&["--target", "https://lab.tld/"]),
        ..DiagSignals::default()
    })
    .expect("priority must pick unstable");
    assert_eq!(diag.cause.code(), "UnstableBaseline");
}

#[test]
fn unreachable_wins_over_waf() {
    let diag = Diagnostic::derive(&DiagSignals {
        baseline_all_error: true,
        count_403: 12,
        argv: cli_argv(&["--target", "https://lab.tld/"]),
        ..DiagSignals::default()
    })
    .expect("priority must pick unreachable");
    assert_eq!(diag.cause.code(), "BaselineUnreachable");
}

#[test]
fn waf_wins_over_rate_limit() {
    let diag = Diagnostic::derive(&DiagSignals {
        count_403: 5,
        count_429: 9,
        argv: cli_argv(&["--target", "https://lab.tld/"]),
        ..DiagSignals::default()
    })
    .expect("priority must pick waf");
    assert_eq!(diag.cause.code(), "WafBlocked");
}

#[test]
fn cancellation_never_suggests() {
    let mut signals = DiagSignals {
        unstable_statuses: vec![200, 500],
        count_429: 42,
        cancelled: true,
        argv: cli_argv(&["--target", "https://lab.tld/"]),
        ..DiagSignals::default()
    };
    signals.cancelled = true;
    assert!(
        Diagnostic::derive(&signals).is_none(),
        "Ctrl+C yields no advice"
    );
}

#[test]
fn no_signal_yields_no_diagnostic() {
    assert!(Diagnostic::derive(&DiagSignals::default()).is_none());
}

#[test]
fn empty_argv_never_fabricates_a_command() {
    let diag = Diagnostic::derive(&DiagSignals {
        count_429: RATE_LIMIT_COUNT_MIN,
        ..DiagSignals::default()
    })
    .expect("cause still derives without argv");
    assert_eq!(diag.cause.code(), "RateLimited");
    assert!(
        diag.suggestion.is_none(),
        "no argv → no fabricated command, got {:?}",
        diag.suggestion
    );
}

#[test]
fn time_in_techniques_skips_duplicate_narrowing() {
    let argv = cli_argv(&[
        "--target",
        "https://lab.tld/",
        "--techniques",
        "boolean,time",
    ]);
    let diag = Diagnostic::derive(&DiagSignals {
        unstable_statuses: vec![200, 500],
        argv: argv.clone(),
        ..DiagSignals::default()
    })
    .expect("unstable must derive");
    assert_eq!(diag.cause.code(), "UnstableBaseline");
    // L'argv est rejoué tel quel (jamais réécrit) : les `--techniques`
    // de l'opérateur restent dans la commande, seul `--fetch-using` est
    // patché (le set embarque déjà `time`).
    assert_eq!(
        diag.suggestion.as_deref(),
        Some("injekt --target https://lab.tld/ --techniques boolean,time --fetch-using direct")
    );
}

#[test]
fn techniques_inline_equals_and_all_forms_are_covered() {
    assert!(argv_techniques_include_time(&cli_argv(&[
        "--techniques=boolean,time,error"
    ])));
    assert!(argv_techniques_include_time(&cli_argv(&[
        "--techniques=all"
    ])));
    assert!(argv_techniques_include_time(&cli_argv(&[
        "--techniques",
        "all"
    ])));
    assert!(!argv_techniques_include_time(&cli_argv(&[
        "--techniques",
        "boolean"
    ])));
}

#[test]
fn fetch_using_already_direct_still_adds_time_only() {
    let argv = cli_argv(&["--fetch-using", "direct", "--target", "https://lab.tld/"]);
    let diag = Diagnostic::derive(&DiagSignals {
        unstable_statuses: vec![200, 500],
        argv,
        ..DiagSignals::default()
    })
    .expect("unstable must derive");
    assert_eq!(
        diag.suggestion.as_deref(),
        Some("injekt --fetch-using direct --target https://lab.tld/ --techniques time")
    );
}

// ------------------------------------------------------------------
// Surfaces Debug / scrub
// ------------------------------------------------------------------

#[test]
fn debug_never_renders_the_raw_suggestion() {
    let argv = cli_argv(&["--target", "https://lab.tld/?token=abcd"]);
    let diag = Diagnostic::derive(&DiagSignals {
        count_429: 9,
        argv,
        ..DiagSignals::default()
    })
    .expect("rate limited must derive");
    let dump = format!("{diag:?}");
    assert!(!dump.contains("abcd"), "Debug leaked the token: {dump}");
    assert!(!dump.contains("lab.tld"), "Debug leaked the target: {dump}");
}

#[test]
fn scrubbed_suggestion_redacts_url_token() {
    let argv = cli_argv(&["--target", "https://lab.tld/?id=1&token=abcd"]);
    let diag = Diagnostic::derive(&DiagSignals {
        count_429: 9,
        argv,
        ..DiagSignals::default()
    })
    .expect("rate limited must derive");
    let scrubbed = diag.scrubbed(&Scrubber::new(false));
    let suggestion = scrubbed.suggestion.expect("suggestion present");
    assert!(
        !suggestion.contains("abcd"),
        "raw token in scrubbed suggestion: {suggestion}"
    );
    assert!(suggestion.contains("[REDACTED]"), "{suggestion}");
    // `--no-redact` passe au travers (debug local).
    assert!(
        diag.scrubbed(&Scrubber::new(true))
            .suggestion
            .expect("suggestion present")
            .contains("abcd")
    );
}

#[test]
fn serialize_renders_flat_cause_and_four_keys() {
    let diag = Diagnostic::derive(&DiagSignals {
        count_403: WAF_BLOCK_COUNT_MIN,
        count_429: RATE_LIMIT_COUNT_MIN,
        argv: cli_argv(&["--target", "https://lab.tld/"]),
        ..DiagSignals::default()
    })
    .expect("waf wins over rate by priority");
    let value: serde_json::Value = serde_json::to_value(&diag).expect("diagnostic serializes");
    assert_eq!(value["cause"], "WafBlocked");
    // URL sans métacaractère shell : pas de quote nécessaire.
    assert_eq!(
        value["suggestion"],
        "injekt --target https://lab.tld/ --tamper space2comment,randomcase"
    );
    assert_eq!(
        value
            .as_object()
            .expect("object")
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        vec!["cause", "evidence", "suggestion", "why"]
    );
}

#[test]
fn serialized_suggestion_can_be_none() {
    let diag = Diagnostic::derive(&DiagSignals {
        duration_expired: true,
        argv: cli_argv(&["--target", "https://lab.tld/"]),
        ..DiagSignals::default()
    })
    .expect("duration derives");
    let value: serde_json::Value = serde_json::to_value(&diag).expect("diagnostic serializes");
    assert_eq!(value["cause"], "DurationExpired");
    assert!(value["suggestion"].is_null());
}
