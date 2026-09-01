#![allow(clippy::unwrap_used)]
use injekt::target::{markers::MarkerSet, raw_request::RawRequest, url::TargetUrl};
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
    assert!(!pos.is_empty());
}
