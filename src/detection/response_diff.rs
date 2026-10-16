#![deny(unsafe_code)]

use regex::Regex;
use std::sync::OnceLock;

/// Result of diffing a response against baseline.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct DiffResult {
    pub similarity: f64, // 0..1 (1 = identical)
    pub time_delta_ms: f64,
    pub length_delta: i64,
    pub confidence: f64,
    pub technique: Option<String>,
}

impl DiffResult {
    #[must_use]
    pub fn is_significant(&self) -> bool {
        self.confidence > 0.6
    }
}

const MAX_LEVENSHTEIN_LEN: usize = 1024;
/// Volatile JSON string fields normalized to `""` (per-response randomness,
/// CSRF tokens). Exact `"field"` match only, so real data is untouched
/// (`"my_request_id"` or `"trace_id_suffix"` never match). Besides the classic
/// CSRF fields this covers Rails' `authenticity_token` and the
/// OTEL/microservice correlation fields (`trace_id`/`traceId`/`requestId`/
/// `correlation_id`), plus Angular/Laravel `xsrf_token`/`x-xsrf-token`: all
/// rotate per request exactly like `request_id`.
const VOLATILE_JSON_STRING_FIELDS: &[&str] = &[
    "request_id",
    "requestId",
    "trace_id",
    "traceId",
    "correlation_id",
    "csrf_token",
    "csrftoken",
    "csrfmiddlewaretoken",
    "xsrf_token",
    "x-xsrf-token",
    "authenticity_token",
    "_token",
    "nonce",
];
/// Volatile JSON numeric fields normalized to `0` (epoch floats, timestamps).
const VOLATILE_JSON_NUMERIC_FIELDS: &[&str] = &["generated_at", "timestamp"];
/// `<input …>` markers: any occurrence (case-insensitive) inside the tag means
/// the tag carries per-response state, so its `value` is blanked.
const CSRF_TAG_MARKERS: [&[u8]; 3] = [b"csrf", b"token", b"nonce"];
/// `<meta …>` markers: matching any (case-insensitive, attribute order
/// irrelevant) marks the tag as a CSRF meta, so its `content` is blanked.
const CSRF_META_MARKERS: [&[u8]; 3] = [b"csrf-token", b"csrf_token", b"xsrf-token"];
/// Every JSON JWT header encodes `{"` as `eyJ`, giving a cheap `contains`
/// prefilter for [`jwt_re`].
const JWT_PREFIX: &str = "eyJ";
/// Fixed stand-in for any JWT found: rotating access/refresh tokens compare
/// equal without any secret material surviving in the normalized text.
const JWT_PLACEHOLDER: &str = "[REDACTED-JWT]";

/// Bench anti-noise: `bench/app.py::noisy()` injects a random `request_id`
/// (8 hex chars) + `generated_at` (epoch float) into every JSON envelope so
/// naive string-compare diffing breaks. Normalize volatile fields to fixed
/// placeholders before any similarity so two identical pages with different
/// noise compare ~1.0. Handles pretty-printed (`"request_id": "abc",`) and
/// compact (`"request_id":"abc"`) shapes; unknown fields are untouched.
/// On top of the JSON fields, CSRF-shaped `<input>`/`<meta>` values are
/// blanked (only when the tag or the value looks like a credential — see
/// `scrub_input_tag`/`scrub_meta_tag`) and JWTs are folded to
/// [`JWT_PLACEHOLDER`]. Free-form hex/digit runs are deliberately *not*
/// touched: masking them would hide real data, so every rule stays scoped to
/// a named volatile region. Bodies without any marker are returned unchanged
/// (cheap path); the probes below are single `memchr`-backed scans so several
/// MiB of body stay cheap to compare.
#[must_use]
pub fn normalize_response_for_diff(body: &str) -> String {
    let has_json_noise = VOLATILE_JSON_STRING_FIELDS
        .iter()
        .chain(VOLATILE_JSON_NUMERIC_FIELDS.iter())
        .any(|f| body.contains(f));
    let has_jwt = body.contains(JWT_PREFIX);
    let has_html_tags = body.contains('<') && has_html_tag_marker(body);
    if !has_json_noise && !has_jwt && !has_html_tags {
        return body.to_owned();
    }
    let mut out = body.to_owned();
    if has_json_noise {
        for field in VOLATILE_JSON_STRING_FIELDS {
            out = normalize_json_field(&out, field, "\"\"");
        }
        for field in VOLATILE_JSON_NUMERIC_FIELDS {
            out = normalize_json_field(&out, field, "0");
        }
    }
    if has_html_tags {
        apply_tag_rewrites(&mut out, input_tag_re(), scrub_input_tag);
        apply_tag_rewrites(&mut out, meta_tag_re(), scrub_meta_tag);
    }
    if has_jwt && let Some(re) = jwt_re() {
        out = re.replace_all(&out, JWT_PLACEHOLDER).into_owned();
    }
    out
}

/// True when the body opens a `<input …>` or `<meta …>` tag
/// (ASCII-case-insensitive). Linear scan, called only after a `'<'` memchr hit
/// on the caller side, so tag-free bodies never pay for the regex engine.
fn has_html_tag_marker(body: &str) -> bool {
    let bytes = body.as_bytes();
    let mut from = 0;
    while let Some(offset) = bytes[from..].iter().position(|&b| b == b'<') {
        let start = from + offset;
        let rest = &bytes[start..];
        if starts_with_ignore_case(rest, b"<input") || starts_with_ignore_case(rest, b"<meta") {
            return true;
        }
        from = start + 1;
    }
    false
}

/// `<input …>` open tags, case-insensitive, bounded by the next `>`: per-tag
/// work stays proportional to the tag, never to the body.
fn input_tag_re() -> Option<&'static Regex> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?is)<input\b[^>]*>").ok())
        .as_ref()
}

/// `<meta …>` open tags, same bounds as [`input_tag_re`].
fn meta_tag_re() -> Option<&'static Regex> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?is)<meta\b[^>]*>").ok())
        .as_ref()
}

/// Base64url JWT: three dot-separated segments with the `eyJ` header prefix
/// (the `{8,}` repetitions are linear-time under the `regex` automata — no
/// backtracking risk; the character class excludes `.` so segments cannot
/// overlap).
fn jwt_re() -> Option<&'static Regex> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}").ok()
    })
    .as_ref()
}

/// Rewrite every [`Regex`] match through `rewrite` in place. `.into_owned()`
/// copies only when the prefilter saw a marker without a real tag match.
fn apply_tag_rewrites(out: &mut String, re: Option<&Regex>, rewrite: fn(&str) -> String) {
    let Some(re) = re else {
        return;
    };
    let replaced = re
        .replace_all(out, |caps: &regex::Captures<'_>| {
            rewrite(caps.get(0).map_or("", |m| m.as_str()))
        })
        .into_owned();
    *out = replaced;
}

/// Clear the `value` of one `<input …>` tag when the tag is CSRF-shaped
/// (`csrf`/`token`/`nonce` anywhere, case-insensitive — covers
/// `name="csrf_token"`, `name="authenticity_token"`, `name="nonce"`) or when
/// the value itself is a credible rotating token ([`is_credible_token`]).
/// Anything else keeps its exact bytes.
fn scrub_input_tag(tag: &str) -> String {
    let bytes = tag.as_bytes();
    let csrf_shaped = CSRF_TAG_MARKERS
        .iter()
        .any(|needle| contains_ignore_case(bytes, needle));
    rewrite_attr_values(tag, "value", csrf_shaped)
}

/// Clear the `content` of `<meta …>` tags carrying a CSRF marker
/// ([`CSRF_META_MARKERS`]). Matching the marker anywhere in the tag keeps
/// attribute order and quoting irrelevant; other metas are untouched.
fn scrub_meta_tag(tag: &str) -> String {
    let bytes = tag.as_bytes();
    let csrf_shaped = CSRF_META_MARKERS
        .iter()
        .any(|needle| contains_ignore_case(bytes, needle));
    if !csrf_shaped {
        return tag.to_owned();
    }
    rewrite_attr_values(tag, "content", true)
}

/// Blank quoted values of `attr="…"`/`attr='…'` in one tag. With
/// `clear_all = false` only values that look like credentials are blanked.
/// The attribute name must start the tag or follow whitespace/`/`, so
/// `data-value`, `myvalue` or free text never match.
fn rewrite_attr_values(tag: &str, attr: &str, clear_all: bool) -> String {
    let bytes = tag.as_bytes();
    let name = attr.as_bytes();
    let mut spans: Vec<(usize, usize)> = Vec::new();
    let mut i = 0;
    while i + name.len() <= bytes.len() {
        let boundary = i == 0 || matches!(bytes[i - 1], b' ' | b'\t' | b'\n' | b'\r' | b'/');
        if boundary
            && bytes[i..i + name.len()].eq_ignore_ascii_case(name)
            // `=` or whitespace must follow, so `values` cannot match `value`.
            && bytes
                .get(i + name.len())
                .is_some_and(|b| b.is_ascii_whitespace() || *b == b'=')
            && let Some((start, end)) = quoted_value_span(bytes, i + name.len(), clear_all)
        {
            spans.push((start, end));
            i = end;
            continue;
        }
        i += 1;
    }
    if spans.is_empty() {
        return tag.to_owned();
    }
    splice_out(tag, &spans)
}

/// Byte span of a quoted `attr`'s value (between the quotes) when it should be
/// blanked: the value must be `"`/`'`-quoted, and either `clear_all` is set or
/// the value is a credible token.
fn quoted_value_span(bytes: &[u8], mut at: usize, clear_all: bool) -> Option<(usize, usize)> {
    while bytes.get(at).is_some_and(u8::is_ascii_whitespace) {
        at += 1;
    }
    if bytes.get(at) != Some(&b'=') {
        return None;
    }
    at += 1;
    while bytes.get(at).is_some_and(u8::is_ascii_whitespace) {
        at += 1;
    }
    let quote = *bytes.get(at)?;
    if quote != b'"' && quote != b'\'' {
        return None;
    }
    let value_start = at + 1;
    let value_end = value_start + bytes.get(value_start..)?.iter().position(|&b| b == quote)?;
    if clear_all || is_credible_token(&bytes[value_start..value_end]) {
        Some((value_start, value_end))
    } else {
        None
    }
}

/// Heuristic for "per-response credential, not user data": at least 20 chars
/// of `[A-Za-z0-9_\-+/=]` spanning two or more character classes
/// (lower/upper/digit/symbol). Bare digit runs, single-case words and short
/// ids never qualify, so ordinary text is never masked.
fn is_credible_token(value: &[u8]) -> bool {
    if value.len() < 20 {
        return false;
    }
    let (mut lower, mut upper, mut digit, mut symbol) = (false, false, false, false);
    for &b in value {
        match b {
            b'a'..=b'z' => lower = true,
            b'A'..=b'Z' => upper = true,
            b'0'..=b'9' => digit = true,
            b'_' | b'-' | b'+' | b'/' | b'=' => symbol = true,
            _ => return false,
        }
    }
    usize::from(lower) + usize::from(upper) + usize::from(digit) + usize::from(symbol) >= 2
}

/// Rebuild `s` with every span removed. Spans are non-overlapping and start at
/// ASCII quote positions, so all slicing stays on char boundaries.
fn splice_out(s: &str, spans: &[(usize, usize)]) -> String {
    let mut out = String::with_capacity(s.len());
    let mut cursor = 0;
    for &(start, end) in spans {
        out.push_str(&s[cursor..start]);
        cursor = end;
    }
    out.push_str(&s[cursor..]);
    out
}

#[inline]
fn starts_with_ignore_case(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.len() >= needle.len() && haystack[..needle.len()].eq_ignore_ascii_case(needle)
}

#[inline]
fn contains_ignore_case(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if haystack.len() < needle.len() {
        return false;
    }
    (0..=haystack.len() - needle.len()).any(|i| {
        haystack[i].eq_ignore_ascii_case(&needle[0])
            && haystack[i..i + needle.len()].eq_ignore_ascii_case(needle)
    })
}

/// Replace the value of one `"field": <value>` JSON member with `placeholder`,
/// preserving keys, separators and structure. String values (`"..."`) and
/// bare numbers/literals (`123.4`, `null`) are both handled; anything else
/// leaves the body intact so detection never scores a mangled page.
fn normalize_json_field(body: &str, field: &str, placeholder: &str) -> String {
    let needle = format!("\"{field}\"");
    let mut out = String::with_capacity(body.len());
    let mut rest = body;
    while let Some(start) = rest.find(needle.as_str()) {
        let after_key = &rest[start + needle.len()..];
        let Some(colon_off) = after_key.find(':') else {
            out.push_str(rest);
            return out;
        };
        // Byte offset of the value start inside `after_key`.
        let mut value_off = colon_off + 1;
        let bytes = after_key.as_bytes();
        while value_off < bytes.len() && bytes[value_off].is_ascii_whitespace() {
            value_off += 1;
        }
        if value_off >= bytes.len() {
            out.push_str(rest);
            return out;
        }
        // End offset (exclusive) of the value inside `after_key`.
        let mut value_end = None;
        if bytes[value_off] == b'"' {
            let mut i = value_off + 1;
            while i < bytes.len() {
                if bytes[i] == b'\\' {
                    i = i.saturating_add(2);
                } else if bytes[i] == b'"' {
                    value_end = Some(i + 1);
                    break;
                } else {
                    i += 1;
                }
            }
        } else {
            let mut i = value_off;
            while i < bytes.len()
                && (bytes[i].is_ascii_alphanumeric() || matches!(bytes[i], b'.' | b'+' | b'-'))
            {
                i += 1;
            }
            if i > value_off {
                value_end = Some(i);
            }
        }
        let Some(value_end) = value_end else {
            out.push_str(rest);
            return out;
        };
        out.push_str(&rest[..start]);
        out.push_str(needle.as_str());
        out.push_str(": ");
        out.push_str(placeholder);
        rest = &after_key[value_end..];
    }
    out.push_str(rest);
    out
}

/// Similarities below this threshold all take the same detection branch
/// (`combined_sim < 0.5` in [`diff_against_baseline`]), so the DP result
/// is interchangeable with `0.0` there — the early-exit below exploits this.
const EARLY_EXIT_SIM: f64 = 0.5;

/// Normalized Levenshtein similarity 0..1. Truncates inputs to 1024 chars
/// and skips the O(n·m) DP when the length difference alone guarantees a
/// similarity below [`EARLY_EXIT_SIM`].
/// Bench noise (`request_id`/`generated_at`) is normalized first so direct
/// callers get the same anti-noise behaviour as [`adaptive_similarity`].
#[must_use]
// Inputs are truncated to MAX_LEVENSHTEIN_LEN (1024); casts are always lossless.
#[allow(clippy::cast_precision_loss)]
pub fn levenshtein_similarity(a: &str, b: &str) -> f64 {
    let norm_a = normalize_response_for_diff(a);
    let norm_b = normalize_response_for_diff(b);
    let a_trunc = truncate(&norm_a);
    let b_trunc = truncate(&norm_b);
    // Early-exit: edit distance >= |n-m|, so similarity <= 1 - |n-m|/max.
    // Char counts are O(n); the DP they skip is O(n*m).
    let n_chars = a_trunc.chars().count();
    let m_chars = b_trunc.chars().count();
    let max_len = n_chars.max(m_chars).max(1);
    let len_diff = n_chars.abs_diff(m_chars);
    if 1.0 - (len_diff as f64 / max_len as f64) < EARLY_EXIT_SIM {
        return 0.0;
    }
    let dist = levenshtein_distance(a_trunc, b_trunc);
    // `dist` counts chars (see `levenshtein_distance`); the denominator must
    // too — `.len()` is bytes and overstates similarity on CJK/emoji.
    let max_len = a_trunc.chars().count().max(b_trunc.chars().count()).max(1) as f64;
    1.0 - (dist as f64 / max_len)
}

fn levenshtein_distance(a: &str, b: &str) -> usize {
    let a_chars: Vec<char> = a.chars().collect();
    let b_chars: Vec<char> = b.chars().collect();
    let n = a_chars.len();
    let m = b_chars.len();
    if n == 0 {
        return m;
    }
    if m == 0 {
        return n;
    }
    let mut prev: Vec<usize> = (0..=m).collect();
    let mut cur = vec![0; m + 1];
    for i in 1..=n {
        cur[0] = i;
        for j in 1..=m {
            let cost = usize::from(a_chars[i - 1] != b_chars[j - 1]);
            cur[j] = (prev[j] + 1).min(cur[j - 1] + 1).min(prev[j - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    prev[m]
}

#[inline]
fn truncate(s: &str) -> &str {
    // Char-based (not byte-based): 1024 CJK chars are ~3 KiB but cost the
    // same DP as 1024 ASCII chars. Byte slicing would also under-truncate
    // CJK to ~341 chars and overstate similarity denominators.
    match s.char_indices().nth(MAX_LEVENSHTEIN_LEN) {
        Some((idx, _)) => &s[..idx],
        None => s,
    }
}

/// Choose similarity strategy based on body size: Levenshtein for small, Jaccard for large.
/// Both inputs are normalized for bench noise (`request_id`/`generated_at`)
/// before comparison so per-response randomness never reads as a differential.
///
/// The switch is char-based: byte length would route ~350 CJK/emoji chars
/// (>1024 bytes) to Jaccard while Levenshtein measures chars — degraded
/// precision on non-ASCII targets.
#[must_use]
pub fn adaptive_similarity(a: &str, b: &str) -> f64 {
    let norm_a = normalize_response_for_diff(a);
    let norm_b = normalize_response_for_diff(b);
    if norm_a.chars().count() > MAX_LEVENSHTEIN_LEN || norm_b.chars().count() > MAX_LEVENSHTEIN_LEN
    {
        jaccard(&norm_a, &norm_b)
    } else {
        levenshtein_similarity(&norm_a, &norm_b)
    }
}

/// Jaccard index over whitespace tokens.
/// Normalizes bench noise first (see [`normalize_response_for_diff`]): direct
/// callers such as the boolean detector get the same anti-noise behaviour as
/// [`adaptive_similarity`] without pre-processing.
#[must_use]
// Token-set sizes never approach f64's 2^52 mantissa limit for HTTP response bodies.
#[allow(clippy::cast_precision_loss)]
pub fn jaccard(a: &str, b: &str) -> f64 {
    let norm_a = normalize_response_for_diff(a);
    let norm_b = normalize_response_for_diff(b);
    let sa: std::collections::HashSet<&str> = norm_a.split_whitespace().collect();
    let sb: std::collections::HashSet<&str> = norm_b.split_whitespace().collect();
    if sa.is_empty() && sb.is_empty() {
        return 1.0;
    }
    let inter = sa.intersection(&sb).count() as f64;
    let union = sa.union(&sb).count() as f64;
    inter / union.max(1.0)
}

/// Build `DiffResult` from baseline and candidate response.
#[must_use]
// HTTP response bodies never approach i64::MAX/usize precision-loss thresholds.
#[allow(clippy::cast_possible_wrap)]
pub fn diff_against_baseline(
    baseline_body: &str,
    candidate_body: &str,
    baseline_ms: f64,
    candidate_ms: f64,
    sigma: f64,
) -> DiffResult {
    let time_delta = candidate_ms - baseline_ms;
    let length_delta = candidate_body.len() as i64 - baseline_body.len() as i64;
    // An empty candidate must never score as a finding: a transport/body
    // error surfacing as `""` yields similarity ~0 and would otherwise map
    // to confidence 0.75 (false positive). Callers must skip scoring on
    // `Err`/status 0; this guard is the last line of defence.
    if candidate_body.is_empty() {
        return DiffResult {
            similarity: 0.0,
            time_delta_ms: time_delta,
            length_delta,
            confidence: 0.0,
            technique: None,
        };
    }
    let similarity = adaptive_similarity(baseline_body, candidate_body);
    let j = jaccard(baseline_body, candidate_body);
    let combined_sim = (similarity * 0.7 + j * 0.3).clamp(0.0, 1.0);
    let time_significant = time_delta > sigma * 2.0;
    let confidence = if time_significant && combined_sim < 0.9 {
        0.85
    } else if combined_sim < 0.5 {
        0.75
    } else if time_significant {
        0.65
    } else {
        1.0 - combined_sim
    };
    DiffResult {
        similarity: combined_sim,
        time_delta_ms: time_delta,
        length_delta,
        confidence: confidence.clamp(0.0, 1.0),
        technique: None,
    }
}

// ---------------------------------------------------------------------------
// Classification de similarité de page (plan anti-FP P1.2, partie 1/2).
//
// Reprend la fin de `comparison()` de sqlmap 2026 (`lib/core/comparison.py`,
// constantes dans `lib/core/settings.py`) sous forme pure, sans toucher à
// `diff_against_baseline` : les seuils sont consommés par la couche détection
// dans une passe ultérieure.
// ---------------------------------------------------------------------------

/// Borne haute sqlmap 2026 (`lib/core/settings.py::UPPER_RATIO_BOUND`) : au-delà
/// de cette similarité la page est considérée identique à la baseline, sans
/// attendre de ratio appris.
pub const UPPER_RATIO_BOUND: f64 = 0.98;

/// Borne basse sqlmap 2026 (`lib/core/settings.py::LOWER_RATIO_BOUND`) : en
/// dessous, la page est considérée complètement différente.
pub const LOWER_RATIO_BOUND: f64 = 0.02;

/// Tolérance sqlmap 2026 (`lib/core/settings.py::DIFF_TOLERANCE`) : marge
/// autour du plancher de bruit appris (`match_ratio`) avant qu'une similarité
/// en zone grise ne soit classée `Different`.
pub const DIFF_TOLERANCE: f64 = 0.05;

/// Verdict de similarité d'une page candidate face à la baseline, calqué sur
/// le triplet `True`/`False`/`None` renvoyé par `comparison()` de sqlmap 2026.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PageSimilarity {
    /// Page jugée identique : similarité au-dessus de [`UPPER_RATIO_BOUND`],
    /// ou au-dessus du plancher de bruit appris à [`DIFF_TOLERANCE`] près.
    Same,
    /// Page jugée franchement différente : similarité sous
    /// [`LOWER_RATIO_BOUND`], ou sous le plancher de bruit appris à
    /// [`DIFF_TOLERANCE`] près.
    Different,
    /// Zone grise sans plancher de bruit appris (ou entrée NaN) : impossible
    /// de trancher sans calibration — l'appelant doit rester prudent.
    Undetermined,
}

/// Classe une similarité de page `0..1` (1 = identique) selon la logique de
/// `comparison()` de sqlmap 2026 :
///
/// 1. `similarity > UPPER_RATIO_BOUND` → [`PageSimilarity::Same`] ;
/// 2. `similarity < LOWER_RATIO_BOUND` → [`PageSimilarity::Different`] ;
/// 3. sinon `match_ratio`, appris empiriquement sur des paires de réponses
///    « même page » (chez nous : les échantillons de baseline) :
///    - `None` → [`PageSimilarity::Undetermined`], comme sqlmap qui ne tranche
///      pas tant que `kb.matchRatio` n'est pas calibré ;
///    - `Some(m)` → `Same` si `similarity >= m - DIFF_TOLERANCE`, sinon
///      `Different`.
///
/// # Déviation assumée vs sqlmap
///
/// sqlmap renvoie `(ratio - matchRatio) > DIFF_TOLERANCE` dans une convention
/// « negative logic » propre à son moteur d'inférence (`True` y signifie
/// « page inchangée » pour l'inférence booléenne). Ici la polarité est
/// exprimée en espace-similarité : une branche reste « baseline-like » tant
/// que sa similarité ne chute pas sous le plancher de bruit appris
/// (`match_ratio`), à `DIFF_TOLERANCE` près. La borne est donc
/// `m - DIFF_TOLERANCE` et non `m + DIFF_TOLERANCE` : le ratio appris est
/// traité comme un plancher de bruit à ne pas percer, pas comme un seuil à
/// dépasser.
///
/// # Entrées dégénérées
///
/// `similarity` est d'abord clampée dans `[0,1]` (les `±∞` retombent donc sur
/// les bornes) ; NaN, que le clamp laisse inchangé, donne `Undetermined`. Un
/// `match_ratio` non fini (`Some(NaN)`) est également traité comme
/// `Undetermined` : un plancher de bruit NaN rendrait le verdict `Different`
/// par simple échec de comparaison, soit un faux positif — on préfère
/// l'abstention. La fonction ne panique jamais.
#[must_use]
pub fn classify_page_similarity(similarity: f64, match_ratio: Option<f64>) -> PageSimilarity {
    let similarity = similarity.clamp(0.0, 1.0);
    if !similarity.is_finite() {
        return PageSimilarity::Undetermined;
    }
    if similarity > UPPER_RATIO_BOUND {
        return PageSimilarity::Same;
    }
    if similarity < LOWER_RATIO_BOUND {
        return PageSimilarity::Different;
    }
    match match_ratio.filter(|m| m.is_finite()) {
        None => PageSimilarity::Undetermined,
        Some(m) => {
            if similarity >= m - DIFF_TOLERANCE {
                PageSimilarity::Same
            } else {
                PageSimilarity::Different
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn lev_identical() {
        assert!((levenshtein_similarity("hello", "hello") - 1.0).abs() < 1e-6);
    }
    #[test]
    // jaccard("", "") takes the early-return literal-1.0 path; exact comparison is safe.
    #[allow(clippy::float_cmp)]
    fn jaccard_empty() {
        assert_eq!(jaccard("", ""), 1.0);
    }
    #[test]
    fn empty_candidate_never_significant() {
        // A transport/body error surfacing as `""` must not map to the
        // `combined_sim < 0.5 => 0.75` false positive.
        let diff = diff_against_baseline("hello world baseline body", "", 100.0, 110.0, 100.0);
        assert!(!diff.is_significant());
        assert!(diff.confidence < 0.4);
    }
    #[test]
    fn truncate_never_splits_char_boundary() {
        // `🌍` is 4 bytes: char-based truncation keeps whole chars.
        let s = format!("{}{}", "a".repeat(4095), "🌍".repeat(8));
        assert!(s.chars().count() > MAX_LEVENSHTEIN_LEN);
        let t = truncate(&s);
        assert!(t.chars().count() <= MAX_LEVENSHTEIN_LEN);
        assert!(s.starts_with(t));
        // Must not panic and must stay valid UTF-8 (len check is enough:
        // `&s[..end]` would have panicked above on a split boundary).
        assert!(t.is_char_boundary(t.len()));
        // Similarity over such bodies must not panic either.
        let _ = levenshtein_similarity(&s, &s);
    }
    #[test]
    fn cjk_bodies_use_levenshtein_not_jaccard() {
        // 400 CJK chars = 1200 bytes: the old byte-length switch routed this
        // to Jaccard; char-based routing keeps precise Levenshtein.
        let a = "漢".repeat(400);
        let b = format!("{}{}{}", "漢".repeat(200), "字", "漢".repeat(199));
        assert!(a.len() > MAX_LEVENSHTEIN_LEN);
        assert!(a.chars().count() <= MAX_LEVENSHTEIN_LEN);
        assert!(adaptive_similarity(&a, &b) > 0.95);
    }
    #[test]
    fn bench_noise_normalized_before_similarity() {
        // `bench/app.py::noisy()` shape: same page, different per-response
        // `request_id` + `generated_at` must compare ~identical.
        let a = "{\n  \"data\": [{\"id\": 1}],\n  \"request_id\": \"a1b2c3d4\",\n  \"generated_at\": 1757328000.123\n}";
        let b = "{\n  \"data\": [{\"id\": 1}],\n  \"request_id\": \"e5f6a7b8\",\n  \"generated_at\": 1757328001.456\n}";
        assert!(adaptive_similarity(a, b) > 0.95);
        let diff = diff_against_baseline(a, b, 100.0, 105.0, 100.0);
        assert!(!diff.is_significant());
        // Compact shape normalizes too.
        let c = "{\"data\":1,\"request_id\":\"aaaa\",\"generated_at\":1.5}";
        let d = "{\"data\":1,\"request_id\":\"bbbb\",\"generated_at\":2.5}";
        assert!(adaptive_similarity(c, d) > 0.95);
    }
    #[test]
    fn normalize_leaves_clean_bodies_untouched() {
        let body = "{\"data\": [1, 2, 3]}";
        assert_eq!(normalize_response_for_diff(body), body);
        assert_eq!(normalize_response_for_diff(""), "");
    }
    #[test]
    fn csrf_nonce_noise_normalized_before_similarity() {
        // Django/Laravel shape: per-response CSRF + timestamp must not read
        // as a differential (false positive).
        let a = "{\"data\":1,\"csrf_token\":\"abc123\",\"timestamp\":1757328000.1}";
        let b = "{\"data\":1,\"csrf_token\":\"xyz789\",\"timestamp\":1757328001.9}";
        assert!(adaptive_similarity(a, b) > 0.95);
        let diff = diff_against_baseline(a, b, 100.0, 105.0, 100.0);
        assert!(!diff.is_significant());
        // Real data fields are untouched: placeholders replace only volatile
        // values, data differences survive normalization.
        let norm_c =
            normalize_response_for_diff("{\"data\":[1,2,3,4,5,6],\"csrf_token\":\"same\"}");
        let norm_d = normalize_response_for_diff("{\"data\":[9,8,7],\"csrf_token\":\"same\"}");
        assert!(norm_c.contains("[1,2,3,4,5,6]"));
        assert!(norm_d.contains("[9,8,7]"));
        assert_ne!(norm_c, norm_d);
    }
    #[test]
    fn extra_volatile_json_fields_normalized_exact_match_only() {
        let a = "{\"data\":1,\"requestId\":\"a1\",\"trace_id\":\"t1\",\"traceId\":\"t2\",\
                 \"correlation_id\":\"c1\",\"authenticity_token\":\"tok1\",\
                 \"xsrf_token\":\"x1\",\"x-xsrf-token\":\"x2\"}";
        let b = "{\"data\":1,\"requestId\":\"b9\",\"trace_id\":\"u9\",\"traceId\":\"u8\",\
                 \"correlation_id\":\"c9\",\"authenticity_token\":\"tok9\",\
                 \"xsrf_token\":\"y9\",\"x-xsrf-token\":\"y8\"}";
        assert_eq!(
            normalize_response_for_diff(a),
            normalize_response_for_diff(b)
        );
        assert!(adaptive_similarity(a, b) > 0.95);
        let diff = diff_against_baseline(a, b, 100.0, 105.0, 100.0);
        assert!(!diff.is_significant());
        // Exact `"field"` match: lookalike keys keep their data.
        let c = "{\"data\":1,\"my_request_id\":\"keep-me\",\"trace_id_suffix\":\"keep-me-too\"}";
        assert_eq!(normalize_response_for_diff(c), c);
    }
    #[test]
    fn csrf_meta_and_form_token_rotation_scores_similar() {
        let page = |meta: &str, form: &str| {
            format!(
                "<html><head><meta name=\"csrf-token\" content=\"{meta}\"></head>\
                 <body><form><input type=\"hidden\" name=\"authenticity_token\" value=\"{form}\">\
                 <p>dashboard</p></form></body></html>"
            )
        };
        let a = page("AAAAmetaTokenValueAAAA", "BBBBformTokenValueBBBB");
        let b = page("CCCCmetaTokenValueCCCC", "DDDDformTokenValueDDDD");
        let sim = adaptive_similarity(&a, &b);
        assert!(sim > 0.95, "similarity {sim}");
        let diff = diff_against_baseline(&a, &b, 100.0, 105.0, 100.0);
        assert!(!diff.is_significant(), "confidence {}", diff.confidence);
        let norm = normalize_response_for_diff(&a);
        assert!(norm.contains("content=\"\""), "{norm}");
        assert!(norm.contains("value=\"\""), "{norm}");
        assert!(!norm.contains("AAAAmetaTokenValueAAAA"), "{norm}");
        assert!(!norm.contains("BBBBformTokenValueBBBB"), "{norm}");
    }
    #[test]
    fn csrf_meta_case_and_attribute_order_normalized() {
        let a = "<meta content=\"rotating-one\" name=\"csrf-token\">";
        let b = "<META NAME=\"CSRF-TOKEN\" CONTENT=\"rotating-two\">";
        let norm_a = normalize_response_for_diff(a);
        let norm_b = normalize_response_for_diff(b);
        assert!(norm_a.contains("content=\"\""), "{norm_a}");
        assert!(norm_a.contains("name=\"csrf-token\""), "{norm_a}");
        assert!(norm_b.contains("CONTENT=\"\""), "{norm_b}");
        // A meta without a CSRF marker is left alone.
        let other = "<meta name=\"description\" content=\"rotating but not a token\">";
        assert_eq!(normalize_response_for_diff(other), other);
    }
    #[test]
    fn rotating_jwt_tokens_are_placeheld() {
        let jwt_a = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.c2lnbmF0dXJlLWFhYQ";
        let jwt_b = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJib2IiLCJpYXQiOjF9.c2lnbmF0dXJlLWJiYg";
        let a = format!("{{\"data\":1,\"access_token\":\"{jwt_a}\"}}");
        let b = format!("{{\"data\":1,\"access_token\":\"{jwt_b}\"}}");
        let norm = normalize_response_for_diff(&a);
        assert!(norm.contains("[REDACTED-JWT]"), "{norm}");
        assert!(!norm.contains(jwt_a), "{norm}");
        assert!(adaptive_similarity(&a, &b) > 0.95);
        let diff = diff_against_baseline(&a, &b, 100.0, 105.0, 100.0);
        assert!(!diff.is_significant());
        // Segments shorter than 8 chars are not JWTs: untouched.
        let near = "eyJab.cdef.ghij";
        assert_eq!(normalize_response_for_diff(near), near);
    }
    #[test]
    fn short_input_values_and_free_text_untouched() {
        for body in [
            "<input value=\"12345\">",
            "<input type=\"text\" name=\"search\" value=\"hello world\">",
            "order total: 12345678901234567890",
            "{\"users\":[{\"id\":1,\"name\":\"admin\"},{\"id\":2,\"name\":\"guest\"}]}",
            "<a href=\"/reports?token=abc\">reports</a>",
        ] {
            assert_eq!(normalize_response_for_diff(body), body, "{body}");
        }
        // Long hex in free text survives even when the HTML pass does run.
        let marked = "<input name=\"csrf_token\" value=\"rotating-value-1\">\
                      <p>sha deadbeefdeadbeefdeadbeefdeadbeef</p>";
        let norm = normalize_response_for_diff(marked);
        assert!(norm.contains("deadbeefdeadbeefdeadbeefdeadbeef"), "{norm}");
        assert!(norm.contains("value=\"\""), "{norm}");
    }
    #[test]
    fn credible_input_token_cleared_single_class_left_alone() {
        // Mixed-class token >= 20 chars: cleared even without a CSRF name.
        let token_input = "<input type=\"hidden\" name=\"state\" value=\"AbCd1234EfGh5678IjKl\">";
        assert_eq!(
            normalize_response_for_diff(token_input),
            "<input type=\"hidden\" name=\"state\" value=\"\">"
        );
        // Single-class values are not credible tokens: byte-identical output.
        for body in [
            "<input name=\"amount\" value=\"123456789012345678901\">",
            "<input name=\"slug\" value=\"abcdefghijklmnopqrst\">",
            "<input name=\"id\" value=\"ABCDEFGHIJKLMNOPQRST\">",
        ] {
            assert_eq!(normalize_response_for_diff(body), body, "{body}");
        }
    }
    #[test]
    fn django_csrfmiddlewaretoken_rotation_scores_similar() {
        let page = |token: &str| {
            format!(
                "<form><input type=\"hidden\" name=\"csrfmiddlewaretoken\" value=\"{token}\">\
                 <p>profile</p></form>"
            )
        };
        let a = page("WT1xY2ZhbHBoYW51bWVyaWNhbDMy");
        let b = page("WT2xY2ZhbHBoYW51bWVyaWNhbDMy");
        assert!(adaptive_similarity(&a, &b) > 0.95);
        assert_eq!(
            normalize_response_for_diff(&a),
            normalize_response_for_diff(&b)
        );
    }
    #[test]
    fn classify_high_similarity_is_same() {
        assert_eq!(classify_page_similarity(0.99, None), PageSimilarity::Same);
        assert_eq!(classify_page_similarity(1.0, None), PageSimilarity::Same);
    }
    #[test]
    fn classify_low_similarity_is_different() {
        assert_eq!(
            classify_page_similarity(0.01, None),
            PageSimilarity::Different
        );
        assert_eq!(
            classify_page_similarity(0.0, None),
            PageSimilarity::Different
        );
    }
    #[test]
    fn classify_exact_bounds_stay_in_gray_zone() {
        // `0.98` n'est pas `> UPPER_RATIO_BOUND` : on continue vers la zone
        // grise, où l'absence de ratio appris laisse le verdict indéterminé.
        assert_eq!(
            classify_page_similarity(UPPER_RATIO_BOUND, None),
            PageSimilarity::Undetermined
        );
        // `0.02` n'est pas `< LOWER_RATIO_BOUND` : même chose côté bas.
        assert_eq!(
            classify_page_similarity(LOWER_RATIO_BOUND, None),
            PageSimilarity::Undetermined
        );
        // Avec un ratio appris, les valeurs exactes aux bornes sont tranchées.
        assert_eq!(
            classify_page_similarity(UPPER_RATIO_BOUND, Some(UPPER_RATIO_BOUND)),
            PageSimilarity::Same
        );
        assert_eq!(
            classify_page_similarity(LOWER_RATIO_BOUND, Some(0.9)),
            PageSimilarity::Different
        );
    }
    #[test]
    fn classify_gray_zone_without_learned_ratio_is_undetermined() {
        for similarity in [0.03, 0.5, 0.97] {
            assert_eq!(
                classify_page_similarity(similarity, None),
                PageSimilarity::Undetermined,
                "similarity {similarity}"
            );
        }
    }
    #[test]
    fn classify_gray_zone_uses_learned_ratio_with_tolerance() {
        // `m - DIFF_TOLERANCE` vaut exactement 0.85 pour m = 0.9 (IEEE 754).
        let m = 0.9;
        let floor = m - DIFF_TOLERANCE;
        assert_eq!(
            classify_page_similarity(0.95, Some(m)),
            PageSimilarity::Same
        );
        assert_eq!(classify_page_similarity(m, Some(m)), PageSimilarity::Same);
        // Pile sur le plancher : toujours Same (`>=`).
        assert_eq!(
            classify_page_similarity(floor, Some(m)),
            PageSimilarity::Same
        );
        // Juste sous le plancher : Different.
        assert_eq!(
            classify_page_similarity(floor - 1e-9, Some(m)),
            PageSimilarity::Different
        );
        // Autre plancher : la borne suit le ratio appris.
        assert_eq!(
            classify_page_similarity(0.44, Some(0.5)),
            PageSimilarity::Different
        );
        assert_eq!(
            classify_page_similarity(0.45, Some(0.5)),
            PageSimilarity::Same
        );
    }
    #[test]
    fn classify_nan_is_undetermined() {
        assert_eq!(
            classify_page_similarity(f64::NAN, None),
            PageSimilarity::Undetermined
        );
        assert_eq!(
            classify_page_similarity(f64::NAN, Some(0.9)),
            PageSimilarity::Undetermined
        );
        // Garde défensive : un plancher NaN ne doit pas produire un faux
        // « Different » par échec de comparaison.
        assert_eq!(
            classify_page_similarity(0.5, Some(f64::NAN)),
            PageSimilarity::Undetermined
        );
    }
    #[test]
    fn classify_clamps_out_of_range_inputs() {
        assert_eq!(classify_page_similarity(1.5, None), PageSimilarity::Same);
        assert_eq!(
            classify_page_similarity(-1.0, None),
            PageSimilarity::Different
        );
        // Les infinis sont clampés aux bornes ; seul NaN reste indéterminé.
        assert_eq!(
            classify_page_similarity(f64::INFINITY, None),
            PageSimilarity::Same
        );
        assert_eq!(
            classify_page_similarity(f64::NEG_INFINITY, None),
            PageSimilarity::Different
        );
    }
    #[test]
    fn classify_is_monotone_in_similarity() {
        // En similarité croissante, le verdict ne peut que progresser
        // Different -> Undetermined -> Same, jamais régresser.
        let rank = |v: PageSimilarity| match v {
            PageSimilarity::Different => 0_u8,
            PageSimilarity::Undetermined => 1,
            PageSimilarity::Same => 2,
        };
        let samples = [0.0, 0.01, 0.02, 0.1, 0.5, 0.85, 0.9, 0.98, 0.99, 1.0];
        for m in [None, Some(0.9)] {
            let ranks: Vec<u8> = samples
                .iter()
                .map(|&s| rank(classify_page_similarity(s, m)))
                .collect();
            assert!(
                ranks.windows(2).all(|w| w[0] <= w[1]),
                "non monotone pour {m:?} : {ranks:?}"
            );
        }
    }
}
