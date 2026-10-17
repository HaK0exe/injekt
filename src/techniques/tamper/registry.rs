//! Tamper name registry: comma-list parsing, aliases and presets.

use super::Tamper;

/// Parse a comma-separated tamper list (e.g. `"space2comment,randomcase"`).
/// Unknown names are ignored with a `tracing::warn!`; empty input yields `Vec::new()`.
///
/// Preset aliases (expanded inline, case-insensitive, never in
/// [`Tamper::all_names`]):
/// - `"cloudflare-generic"` → `randomcase,space2comment,versionedmorekeywords`
/// - `"aggressive"` → `randomcase,space2paren,versionedfuzz,equaltolike`
#[must_use]
pub fn parse_tamper_list(input: Option<&str>) -> Vec<Tamper> {
    let Some(raw) = input else {
        return Vec::new();
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("none") {
        return Vec::new();
    }
    let mut out = Vec::new();
    for part in trimmed.split(',') {
        let name = part.trim();
        if name.is_empty() {
            continue;
        }
        if name.eq_ignore_ascii_case("cloudflare-generic") {
            out.extend([
                Tamper::RandomCase,
                Tamper::Space2Comment,
                Tamper::VersionedMoreKeywords,
            ]);
        } else if name.eq_ignore_ascii_case("aggressive") {
            out.extend([
                Tamper::RandomCase,
                Tamper::Space2Paren,
                Tamper::VersionedFuzz,
                Tamper::EqualToLike,
            ]);
        } else if let Some(t) = Tamper::from_name(name) {
            out.push(t);
        } else {
            tracing::warn!(tamper=%name, available=?Tamper::all_names(), "unknown tamper ignored");
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::techniques::tamper::Tamper;

    #[test]
    fn parse_empty() {
        assert!(parse_tamper_list(None).is_empty());
        assert!(parse_tamper_list(Some("")).is_empty());
        assert!(parse_tamper_list(Some("none")).is_empty());
    }

    #[test]
    fn parse_single() {
        let v = parse_tamper_list(Some("space2comment"));
        assert_eq!(v, vec![Tamper::Space2Comment]);
    }

    #[test]
    fn parse_multiple_mixed_case() {
        let v = parse_tamper_list(Some("Space2Comment, RandomCase , charencode"));
        assert_eq!(
            v,
            vec![
                Tamper::Space2Comment,
                Tamper::RandomCase,
                Tamper::CharEncode
            ]
        );
    }

    #[test]
    fn parse_unknown_ignored() {
        let v = parse_tamper_list(Some("space2comment,notreal,hexencode"));
        assert_eq!(v, vec![Tamper::Space2Comment, Tamper::HexEncode]);
    }

    #[test]
    fn new_tampers_registered_in_from_name_and_all_names() {
        for name in [
            "space2dash",
            "randomcomments",
            "equaltolike",
            "base64encode",
        ] {
            assert!(
                Tamper::all_names().contains(&name),
                "{name} missing from all_names"
            );
            assert!(
                Tamper::from_name(name).is_some(),
                "{name} missing from from_name"
            );
        }
    }

    #[test]
    fn parse_new_tampers() {
        let v = parse_tamper_list(Some(
            "space2dash,space2mssqlblank,randomcomments,equaltolike,versionedmorekeywords,base64encode",
        ));
        assert_eq!(
            v,
            vec![
                Tamper::Space2Dash,
                Tamper::Space2MssqlBlank,
                Tamper::RandomComments,
                Tamper::EqualToLike,
                Tamper::VersionedMoreKeywords,
                Tamper::Base64Encode,
            ]
        );
    }

    #[test]
    fn parse_new_aliases() {
        assert_eq!(parse_tamper_list(Some("dash")), vec![Tamper::Space2Dash]);
        assert_eq!(
            parse_tamper_list(Some("mssqlblank")),
            vec![Tamper::Space2MssqlBlank]
        );
        assert_eq!(
            parse_tamper_list(Some("equal2like")),
            vec![Tamper::EqualToLike]
        );
        assert_eq!(parse_tamper_list(Some("b64")), vec![Tamper::Base64Encode]);
        assert_eq!(
            parse_tamper_list(Some("morekeywords")),
            vec![Tamper::VersionedMoreKeywords]
        );
    }

    #[test]
    fn all_names_covers_new_tampers() {
        for name in [
            "space2dash",
            "space2mssqlblank",
            "randomcomments",
            "equaltolike",
            "versionedmorekeywords",
            "base64encode",
        ] {
            assert!(
                Tamper::all_names().contains(&name),
                "all_names missing {name}"
            );
            assert!(Tamper::from_name(name).is_some());
        }
        assert_eq!(Tamper::all_names().len(), 24);
    }

    #[test]
    fn p0_tampers_registered_with_aliases() {
        for name in [
            "space2paren",
            "versionedfuzz",
            "jsonunicodeescape",
            "numericobfuscate",
            "linecomment",
        ] {
            assert!(
                Tamper::all_names().contains(&name),
                "all_names missing {name}"
            );
            assert!(Tamper::from_name(name).is_some());
        }
        assert_eq!(Tamper::from_name("paren"), Some(Tamper::Space2Paren));
        assert_eq!(
            Tamper::from_name("equalobfuscate"),
            Some(Tamper::NumericObfuscate)
        );
        assert_eq!(Tamper::from_name("numeric"), Some(Tamper::NumericObfuscate));
        assert_eq!(
            Tamper::from_name("jsonunicode"),
            Some(Tamper::JsonUnicodeEscape)
        );
        assert_eq!(Tamper::from_name("commentfuzz"), Some(Tamper::LineComment));
        // I1: `JsonUnicodeEscape` (like `Base64Encode`) is NOT boolean-safe:
        // it escapes the injection quote itself, both branches go inert.
        assert!(!Tamper::Base64Encode.is_boolean_safe());
        assert!(!Tamper::JsonUnicodeEscape.is_boolean_safe());
        for name in Tamper::all_names() {
            let t = Tamper::from_name(name).expect("known tamper");
            if t == Tamper::Base64Encode || t == Tamper::JsonUnicodeEscape {
                continue;
            }
            assert!(t.is_boolean_safe(), "{name} should be boolean-safe");
        }
    }

    #[test]
    fn preset_cloudflare_generic_expands() {
        assert_eq!(
            parse_tamper_list(Some("cloudflare-generic")),
            vec![
                Tamper::RandomCase,
                Tamper::Space2Comment,
                Tamper::VersionedMoreKeywords,
            ]
        );
        // case-insensitive, composes with other names
        assert_eq!(
            parse_tamper_list(Some("CloudFlare-Generic, hexencode")),
            vec![
                Tamper::RandomCase,
                Tamper::Space2Comment,
                Tamper::VersionedMoreKeywords,
                Tamper::HexEncode,
            ]
        );
    }

    #[test]
    fn preset_aggressive_expands() {
        assert_eq!(
            parse_tamper_list(Some("aggressive")),
            vec![
                Tamper::RandomCase,
                Tamper::Space2Paren,
                Tamper::VersionedFuzz,
                Tamper::EqualToLike,
            ]
        );
    }

    #[test]
    fn presets_are_aliases_not_variants() {
        assert!(!Tamper::all_names().contains(&"cloudflare-generic"));
        assert!(!Tamper::all_names().contains(&"aggressive"));
        assert!(Tamper::from_name("cloudflare-generic").is_none());
        assert!(Tamper::from_name("aggressive").is_none());
    }
}
