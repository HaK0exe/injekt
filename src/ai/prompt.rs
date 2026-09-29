#![deny(unsafe_code)]

//! Construction du prompt LLM — signaux abstraits uniquement (0 secret).
//!
//! N'embarque JAMAIS : cookies/headers/body cible, URL brute (userinfo,
//! tokens), raw-file, extracted data, clé API. Seuls partent :
//! résumé de contexte (`InjectionContext::summary`), DBMS top-candidat,
//! vendor WAF + hits + blocking, style de commentaire, et 2-3 squelettes
//! de payloads échoués (formes génériques type `' OR <INT>=<INT> -- -`,
//! jamais les payloads bruts essayés).

use crate::dbms::context::{DbmsBelief, InjectionContext};

/// Signaux abstraits envoyés au LLM (cap ~1 Ko, voir [`build_user_prompt`]).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AiSignals {
    /// Résumé de contexte (`InjectionContext::summary`, soit
    /// `quote/numeric/json/order_by/comment`).
    pub context_summary: String,
    /// Top-candidat DBMS (`mysql:0.85`, `unknown:0.20`, …).
    pub dbms_hint: String,
    /// Fournisseur WAF observé (`cloudflare`, `generic`, `none`).
    pub waf_vendor: String,
    /// Noms de signaux WAF (jamais de valeurs) + `blocking=true/false`.
    pub waf_detail: String,
    /// Squelettes génériques des payloads échoués (formes, pas payloads).
    pub failed_shapes: Vec<String>,
    /// Style de commentaire actif (`-- `, `#`, …).
    pub comment_style: String,
}

impl AiSignals {
    /// Construit depuis l'état de détection (pur, 0 I/O, 0 secret).
    /// `failed_shapes` est tronqué à 3 squelettes de ≤ 64 chars.
    #[must_use]
    pub fn collect(
        context: &InjectionContext,
        belief: &DbmsBelief,
        waf_vendor: Option<&str>,
        waf_hits: &[String],
        waf_blocking: bool,
        failed_shapes: &[String],
        comment_style: &str,
    ) -> Self {
        let (kind, prob) = belief.top_candidate();
        let shapes: Vec<String> = failed_shapes
            .iter()
            .take(3)
            .map(|s| truncate_shape(s))
            .collect();
        Self {
            context_summary: context.summary(),
            dbms_hint: format!("{kind}:{prob:.2}"),
            waf_vendor: waf_vendor.unwrap_or("none").to_owned(),
            waf_detail: format!("hits={} blocking={waf_blocking}", waf_hits.join(",")),
            failed_shapes: shapes,
            comment_style: comment_style.to_owned(),
        }
    }
}

/// Tronque un squelette à 64 chars (jamais de panique UTF-8).
fn truncate_shape(s: &str) -> String {
    s.chars().take(64).collect()
}

/// Prompt système : cadre strict — JSON uniquement, paires booléennes
/// cohérentes, pas de stacked/RCE/time.
#[must_use]
pub const fn system_prompt() -> &'static str {
    "You are a SQL injection evasion advisor for an authorized pentest scanner. \
    Rules: reply with STRICT JSON only: a list of at most N objects \
    [{\"true\": \"...\", \"false\": \"...\"}] where each pair is a boolean-based \
    TRUE/FALSE injection of the SAME shape with a minimal literal flip \
    (e.g. 1=1 vs 1=2). Same quote fence and comment terminator on both branches. \
    No stacked queries (no semicolons), no xp_/EXEC/OUTFILE/LOAD_FILE, no SLEEP or \
    time functions, no shell. Keep each branch under 512 chars. No explanation \
    outside the JSON."
}

/// Prompt utilisateur à partir des signaux (cap ~1 Ko, tronqué si besoin).
#[must_use]
pub fn build_user_prompt(signals: &AiSignals, max_pairs: u8) -> String {
    let mut out = String::with_capacity(1024);
    out.push_str("Context: ");
    out.push_str(&signals.context_summary);
    out.push_str("\nDBMS: ");
    out.push_str(&signals.dbms_hint);
    out.push_str("\nWAF vendor: ");
    out.push_str(&signals.waf_vendor);
    out.push(' ');
    out.push_str(&signals.waf_detail);
    out.push_str("\nComment style: ");
    out.push_str(&signals.comment_style);
    out.push_str("\nFailed shapes (do NOT repeat verbatim, vary the bypass):\n");
    for shape in &signals.failed_shapes {
        out.push_str("- ");
        out.push_str(shape);
        out.push('\n');
    }
    out.push_str("\nPropose at most ");
    out.push_str(&max_pairs.to_string());
    out.push_str(" fresh TRUE/FALSE pairs as JSON.\n");
    if out.len() > 1024 {
        out.truncate(1024);
    }
    out
}

/// Squelettise un payload échoué en forme générique (runs de chiffres →
/// `<INT>`), pour ne jamais envoyer les littéraux exacts au LLM tout en
/// préservant la forme (fences, opérateurs, terminateur). Les quotes et le
/// reste sont conservés tels quels : un fence ouvrant `'` non refermé ne doit
/// jamais absorber le reste du payload. Pure, jamais de secret (la sonde ne
/// contient déjà que des constantes génériques).
#[must_use]
pub fn skeletonize(payload: &str) -> String {
    let mut out = String::with_capacity(payload.len());
    let mut chars = payload.chars().peekable();
    while let Some(c) = chars.next() {
        if c.is_ascii_digit() {
            while chars.peek().is_some_and(char::is_ascii_digit) {
                chars.next();
            }
            out.push_str("<INT>");
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::dbms::context::{CommentStyle, InjectionContext, QuoteContext};

    fn sample_ctx() -> InjectionContext {
        InjectionContext {
            quote: QuoteContext::SingleQuote,
            numeric: false,
            json: false,
            order_by: false,
            comment: CommentStyle::DashDash,
        }
    }

    #[test]
    fn collect_caps_shapes_and_never_empty() {
        let belief = DbmsBelief::uniform();
        let sig = AiSignals::collect(
            &sample_ctx(),
            &belief,
            Some("cloudflare"),
            &["cf-ray".to_owned(), "challenge".to_owned()],
            true,
            &[
                "a".to_owned(),
                "b".to_owned(),
                "c".to_owned(),
                "d".to_owned(),
            ],
            "-- ",
        );
        assert_eq!(sig.failed_shapes.len(), 3);
        assert!(sig.context_summary.contains("quote="));
        assert!(sig.dbms_hint.contains("unknown"));
        assert_eq!(sig.waf_vendor, "cloudflare");
        assert!(sig.waf_detail.contains("blocking=true"));
    }

    #[test]
    fn user_prompt_capped_at_1k() {
        let belief = DbmsBelief::uniform();
        let sig = AiSignals::collect(
            &sample_ctx(),
            &belief,
            None,
            &[],
            false,
            &["x".repeat(500)],
            "-- ",
        );
        let p = build_user_prompt(&sig, 3);
        assert!(p.len() <= 1024);
        assert!(p.contains("Propose at most 3"));
    }

    #[test]
    fn skeletonize_abstracts_literals() {
        assert_eq!(skeletonize("' OR 1=1 -- -"), "' OR <INT>=<INT> -- -");
        assert_eq!(skeletonize("1 AND 23=23"), "<INT> AND <INT>=<INT>");
        // Fence ouvrant non refermé : forme préservée, rien n'est absorbé.
        assert_eq!(skeletonize("' OR 'a'='a"), "' OR 'a'='a");
    }

    #[test]
    fn system_prompt_is_strict_json() {
        let s = system_prompt();
        assert!(s.contains("STRICT JSON"));
        assert!(s.contains("No stacked queries"));
    }
}
