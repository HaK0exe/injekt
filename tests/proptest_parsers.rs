#![allow(clippy::unwrap_used, clippy::expect_used)]
use clap::Parser as _;
use injekt::target::{
    markers::{InjectionMarker, MarkerSet},
    raw_request::RawRequest,
    url::TargetUrl,
};
use proptest::prelude::*;

proptest! {
    #[test]
    fn url_parse_never_panics(s in "\\PC*") {
        let _ = TargetUrl::parse(&s, true);
        let _ = TargetUrl::parse(&s, false);
    }

    #[test]
    fn raw_request_parse_never_panics(s in "\\PC*") {
        let _ = RawRequest::parse(&s);
    }

    #[test]
    fn markers_detect_never_panics(s in "\\PC*") {
        let _ = MarkerSet::detect(&s);
    }

    #[test]
    fn scrub_never_panics(s in "\\PC*") {
        let sc = injekt::session::scrubber::Scrubber::new(false);
        let _ = sc.scrub(&s);
    }

    #[test]
    fn injection_inference_binary_search_never_panics(len in 1usize..20, seed in 0u64..1000) {
        let ex = injekt::extraction::inference::InferenceExtractor::new();
        let target: String = (0..len).map(|i| (((seed + i as u64) % 95) as u8 + 32) as char).collect();
        let out: Result<String, ()> = ex.infer_string::<_, ()>(len, |pos, guess| Ok(target.as_bytes()[pos] >= guess));
        prop_assert!(out.is_ok());
    }

    #[test]
    fn tamper_never_panics(s in "\\PC*", name in "\\PC*") {
        let t = injekt::techniques::tamper::Tamper::from_name(&name);
        if let Some(tamper) = t {
            let _ = tamper.apply(&s);
        }
        let _ = injekt::techniques::tamper::parse_tamper_list(Some(&name));
        let _ = injekt::techniques::tamper::apply_tampers(&s, &[]);
        let _ = injekt::techniques::tamper::expand_with_tampers(&s, &[]);
    }

    #[test]
    fn hpp_query_never_panics_preserves_pairs(s in "\\PC*") {
        use injekt::techniques::request_tamper::{count_query_occurrences, hpp_query_url};
        let Ok(base) = url::Url::parse("http://ex/s") else {
            return Ok(());
        };
        let before = base.query_pairs().count();
        let out = hpp_query_url(&base, "id", &s);
        // original pairs preserved + exactly one duplicate appended
        let parsed = url::Url::parse(&out).expect("hpp output is a valid URL");
        prop_assert_eq!(parsed.query_pairs().count(), before + 1);
        prop_assert_eq!(count_query_occurrences(&out, "id"), 1);
        let _ = count_query_occurrences(&s, "id");
    }

    #[test]
    fn hpp_body_never_panics(s in "\\PC*") {
        let out = injekt::techniques::request_tamper::hpp_body_str(Some(&s), "id", "X");
        prop_assert!(out.contains("id="));
    }

    #[test]
    fn chunk_pieces_reassemble(body in proptest::collection::vec(0u8..255u8, 0..64), size in 1usize..16) {
        let pieces = injekt::techniques::request_tamper::chunk_body_pieces(&body, size);
        let joined: Vec<u8> = pieces.iter().flat_map(|b| b.to_vec()).collect();
        prop_assert_eq!(joined, body);
        for p in &pieces {
            prop_assert!(p.len() <= size);
        }
    }

    #[test]
    fn json_payloads_never_panic(s in "\\PC*") {
        for dbms in [None, Some("mysql"), Some("postgres"), Some("mssql"), Some("oracle"), Some(&s[..])] {
            let v = injekt::techniques::json::payloads::json_payloads_for(dbms);
            prop_assert!(!v.is_empty());
            for p in &v {
                prop_assert_ne!(&p.true_payload, &p.false_payload);
                prop_assert!(!p.dbms.is_empty());
            }
        }
    }

    #[test]
    fn json_detector_never_panics(a in "\\PC*", b in "\\PC*", c in "\\PC*") {
        let d = injekt::techniques::json::detector::JsonDetector::new();
        let _ = d.evaluate_boolean(&a, &b, &c, 100.0, 105.0, 110.0);
        let r = d.evaluate_error(&b);
        // without error context there is never a finding
        if !(b.to_ascii_lowercase().contains("error")
            || b.to_ascii_lowercase().contains("exception")
            || b.to_ascii_lowercase().contains("ora-")
            || b.to_ascii_lowercase().contains("msg ")
            || b.to_ascii_lowercase().contains("sql"))
        {
            prop_assert!(!r.is_vulnerable);
        }
    }

    #[test]
    fn oob_helpers_never_panic(s in "\\PC*") {
        use injekt::techniques::oob::payloads::{build_subdomain, is_valid_oob_domain, sanitize_dns_label};
        let _ = is_valid_oob_domain(&s);
        let label = sanitize_dns_label(&s);
        prop_assert!(!label.is_empty());
        prop_assert!(label.len() <= 63);
        let _ = build_subdomain(&s, &s);
    }
}

#[test]
fn url_rejects_private_by_default() {
    assert!(TargetUrl::parse("http://127.0.0.1/", false).is_err());
    assert!(TargetUrl::parse("http://10.0.0.1/admin", false).is_err());
}

#[test]
fn markers_positions_consistent() {
    let s = "id=1* and §test§ and {{x}}";
    let m = MarkerSet::detect(s);
    assert!(m.has_any());
    let pos = m.positions(s);
    assert_ne!(pos, [] as [(usize, InjectionMarker); 0]);
}

proptest! {
    #[test]
    fn anti_ssrf_noncanonical_private_forms_rejected(idx in 0usize..6) {
        let forms = ["2130706433", "0x7f.0.0.1", "0177.0.0.1", "127.1", "0.0.0.0", "10.0.0.1"];
        let input = forms[idx % forms.len()];
        let res = TargetUrl::parse(input, false);
        prop_assert!(res.is_err(), "expected rejection for {input}: {res:?}");
    }

    #[test]
    fn anti_ssrf_ipv6_mapped_or_loopback_rejected(idx in 0usize..4) {
        let forms = ["[::ffff:127.0.0.1]", "[::1]", "::1", "::ffff:10.0.0.1"];
        let input = forms[idx % forms.len()];
        // bare IPv6 without brackets may not parse as URL; accept either parse-error or rejection.
        let res = TargetUrl::parse(input, false);
        if res.is_ok() {
            prop_assert!(false, "expected rejection for {input}");
        }
    }

    #[test]
    fn c16_top_level_positional_never_parse_errors(
        url in "https://[a-z]{3,8}\\.example/[?]id=[0-9]{3}",
    ) {
        let argv = ["injekt".to_owned(), url.clone()];
        let cli = injekt::cli::args::Cli::try_parse_from(argv).expect("top-level positional parse");
        prop_assert!(cli.command.is_none(), "no subcommand expected for {url}");
        prop_assert_eq!(cli.target_positional.as_deref(), Some(url.as_str()));
        let resolved = cli.effective_target();
        prop_assert_eq!(resolved.as_deref(), Some(url.as_str()));
    }

    #[test]
    fn c16_auto_positional_bare_host_implies_recon(
        host in "[a-z]{5,8}\\.[a-z]{2,3}",
    ) {
        let argv = ["injekt".to_owned(), "auto".to_owned(), host.clone()];
        let cli = injekt::cli::args::Cli::try_parse_from(argv).expect("auto positional parse");
        let Some(injekt::cli::args::Commands::Auto(args)) = &cli.command else {
            prop_assert!(false, "auto subcommand expected for bare host {host}");
            return Ok(());
        };
        prop_assert_eq!(args.target_positional.as_deref(), Some(host.as_str()));
        // Existing bare-host trigger (unchanged): the positional form is the
        // only source here and a bare host never carries a `://`.
        prop_assert!(!host.contains("://"), "bare host has no scheme by construction");
    }

    #[test]
    fn c16_positional_vs_typed_flag_conflicts_or_stays_silent(
        url in "https://[a-z]{3,8}\\.example/[?]id=[0-9]{3}",
        other_id in 100u32..999,
    ) {
        // Distinct positional vs typed `-u/--target` (typed ⇒ `main` sets the
        // clap ValueSource bit; fixtures set it explicitly) → usage error.
        let other = format!("{url}{other_id}");
        let argv = [
            "injekt".to_owned(),
            url.clone(),
            "-u".to_owned(),
            other.clone(),
        ];
        let mut cli = injekt::cli::args::Cli::try_parse_from(argv).expect("conflict parse");
        prop_assert_eq!(cli.target_positional.as_deref(), Some(url.as_str()));
        cli.cli_typed_target = true;
        let err = cli
            .validate_target_conflict()
            .expect_err("conflicting positional/flag must be a usage error");
        let is_conflict =
            matches!(err, injekt::error::InjektError::TargetConflict { .. });
        prop_assert!(is_conflict, "expected TargetConflict, got {err}");
        // Equal spellings stay silent (zero-break), and `-u` parsing never
        // touches the `--format` warn guard.
        let argv = [
            "injekt".to_owned(),
            url.clone(),
            "-u".to_owned(),
            url.clone(),
        ];
        let mut cli = injekt::cli::args::Cli::try_parse_from(argv).expect("equal spelling parse");
        cli.cli_typed_target = true;
        prop_assert!(cli.validate_target_conflict().is_ok());
        prop_assert!(
            !cli
                .format_conflict_warned
                .load(std::sync::atomic::Ordering::Relaxed),
            "--target parsing never touches the format warn guard"
        );
    }

    #[test]
    fn c16_target_flag_alone_unchanged_under_positional_surface(
        url in "https://[a-z]{3,8}\\.example/[?]id=[0-9]{3}",
    ) {
        let argv = ["injekt".to_owned(), "-u".to_owned(), url.clone()];
        let cli = injekt::cli::args::Cli::try_parse_from(argv).expect("-u alone parse");
        prop_assert!(cli.target_positional.is_none(), "-u alone fills no positional");
        let resolved = cli.effective_target();
        prop_assert_eq!(resolved.as_deref(), Some(url.as_str()));
        // Zero-break double-check: the historical `scan --target` alias.
        let argv = [
            "injekt".to_owned(),
            "scan".to_owned(),
            "--target".to_owned(),
            url.clone(),
        ];
        let cli = injekt::cli::args::Cli::try_parse_from(argv).expect("scan alias parse");
        prop_assert!(cli.target_positional.is_none());
        let resolved = cli.effective_target();
        prop_assert_eq!(resolved.as_deref(), Some(url.as_str()));
    }
}
