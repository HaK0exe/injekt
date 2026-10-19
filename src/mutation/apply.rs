use crate::dbms::context::{CommentStyle, InjectionContext, QuoteContext};
use crate::seeded_rng::make_rng;

// ── transforms (pures, déterministes) ────────────────────────────────────

/// `quote_fence` : `'` → `')`, `"` → `")`.
///
/// Skippé en contexte numérique nu ([`QuoteContext::None`] + `numeric`) :
/// il n'y a pas de quote à fencer et la variante serait du bruit.
/// Skippé si `base` ne commence pas par un quote (rien à fencer).
pub(super) fn apply_quote_fence(base: &str, context: &InjectionContext) -> Option<String> {
    if context.quote == QuoteContext::None && context.numeric {
        return None;
    }
    if let Some(rest) = base.strip_prefix('\'') {
        let mut out = String::with_capacity(base.len() + 1);
        out.push('\'');
        out.push(')');
        out.push_str(rest);
        return Some(out);
    }
    if let Some(rest) = base.strip_prefix('"') {
        let mut out = String::with_capacity(base.len() + 1);
        out.push('"');
        out.push(')');
        out.push_str(rest);
        return Some(out);
    }
    None
}

/// `paren_wrap` : parenthèse le prédicat boolean.
///
/// Tente dans l'ordre : `1=1` → `(1=1)`, `1=2` → `(1=2)`,
/// `1 LIKE 1` → `(1 LIKE 1)`, `1 LIKE 2` → `(1 LIKE 2)`,
/// `'1'='1'` → `('1'='1')`, `'1'='2'` → `('1'='2')`.
/// Fallback générique : ` OR ` → ` OR (` + `)` avant le terminateur.
/// `None` si rien ne change (préserve la borne utile).
pub(super) fn apply_paren_wrap(base: &str) -> Option<String> {
    for (needle, replacement) in [
        ("1=1", "(1=1)"),
        ("1=2", "(1=2)"),
        ("1 LIKE 1", "(1 LIKE 1)"),
        ("1 LIKE 2", "(1 LIKE 2)"),
        ("'1'='1'", "('1'='1')"),
        ("'1'='2'", "('1'='2')"),
    ] {
        if base.contains(needle) {
            return Some(base.replacen(needle, replacement, 1));
        }
    }
    // Fallback : parenthèse la branche `OR …` jusqu'au terminateur.
    let or_pos = base.find(" OR ")?;
    let after_or = or_pos + " OR ".len();
    let tail_start = base.len();
    let comment_at = base
        .rfind(" --")
        .or_else(|| base.rfind('#'))
        .unwrap_or(tail_start);
    if comment_at <= after_or {
        return None;
    }
    let mut out = String::with_capacity(base.len() + 2);
    out.push_str(&base[..after_or]);
    out.push('(');
    out.push_str(&base[after_or..comment_at]);
    out.push(')');
    out.push_str(&base[comment_at..]);
    if out == base { None } else { Some(out) }
}

/// `comment_swap` : permute le terminateur en respectant `CommentStyle`.
///
/// - `Hash` : tout terminateur `-- -` / `--` → `#` ; `#` → `#` inchangé (no-op).
/// - autres : ` -- -` → ` --`, ` --` → ` -- -`, `#` → ` -- -`.
///   `None` quand il n'y a pas de terminateur reconnu (pas de bruit).
pub(super) fn apply_comment_swap(base: &str, style: CommentStyle) -> Option<String> {
    if style == CommentStyle::Hash {
        if base.ends_with(" -- -") {
            let stripped = base.strip_suffix(" -- -").unwrap_or(base);
            let mut out = String::with_capacity(base.len());
            out.push_str(stripped);
            out.push('#');
            return Some(out);
        }
        if base.ends_with(" --") {
            let stripped = base.strip_suffix(" --").unwrap_or(base);
            let mut out = String::with_capacity(base.len());
            out.push_str(stripped);
            out.push('#');
            return Some(out);
        }
        return None;
    }
    if base.ends_with(" -- -") {
        let stripped = base.strip_suffix(" -- -").unwrap_or(base);
        let mut out = String::with_capacity(base.len());
        out.push_str(stripped);
        out.push_str(" --");
        return Some(out);
    }
    if base.ends_with(" --") {
        let stripped = base.strip_suffix(" --").unwrap_or(base);
        let mut out = String::with_capacity(base.len());
        out.push_str(stripped);
        out.push_str(" -- -");
        return Some(out);
    }
    if base.ends_with('#') {
        let stripped = base.strip_suffix('#').unwrap_or(base);
        let mut out = String::with_capacity(base.len() + 4);
        out.push_str(stripped);
        out.push_str(" -- -");
        return Some(out);
    }
    None
}

/// `case_mix` : mélange de casse déterministe via `seed`.
///
/// Même `seed` → même sortie ; `None` = OS-random (historique).
/// `None` si aucun caractère ASCII alphabétique (rien à mixer).
pub(super) fn apply_case_mix(base: &str, seed: Option<u64>) -> Option<String> {
    use rand::RngExt as _;
    if !base.chars().any(|c| c.is_ascii_alphabetic()) {
        return None;
    }
    let mut rng = make_rng(seed);
    let out: String = base
        .chars()
        .map(|c| {
            if c.is_ascii_alphabetic() && rng.random_bool(0.5) {
                if c.is_ascii_lowercase() {
                    c.to_ascii_uppercase()
                } else {
                    c.to_ascii_lowercase()
                }
            } else {
                c
            }
        })
        .collect();
    if out == base {
        // Collision 2^-N (payload sans lettre déjà exclu) : forcer un flip
        // déterministe sur la première lettre pour garantir une variante.
        let mut forced = String::with_capacity(base.len());
        let mut flipped = false;
        for c in base.chars() {
            if !flipped && c.is_ascii_alphabetic() {
                flipped = true;
                if c.is_ascii_lowercase() {
                    forced.push(c.to_ascii_uppercase());
                } else {
                    forced.push(c.to_ascii_lowercase());
                }
            } else {
                forced.push(c);
            }
        }
        return Some(forced);
    }
    Some(out)
}
