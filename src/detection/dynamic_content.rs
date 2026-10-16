#![deny(unsafe_code)]

//! P1.1 — marquage générique de contenu dynamique (`findDynamicContent`).
//!
//! sqlmap (`lib/core/common.py::findDynamicContent`) compare deux pages
//! baseline et repère les zones qui bougent entre deux **flancs stables
//! identiques** : un bloc commun de plus de `2 * DYNAMICITY_BOUNDARY_LENGTH`
//! caractères est retenu comme flanc ; pour chaque paire de flancs adjacents,
//! les 20 derniers caractères du flanc gauche et les 20 premiers du flanc
//! droit deviennent un *marquage* `(préfixe, suffixe)` de la zone
//! intermédiaire. [`remove_dynamic_content`] purge ensuite ces zones (et les
//! deux bords de page, préfixe/suffixe `None`) avant toute comparaison
//! différentielle — ce qui rend un oracle utilisable sur une page qui « bouge »
//! dans une zone que
//! [`normalize_response_for_diff`](crate::detection::response_diff::normalize_response_for_diff)
//! ne connaît pas (bannière publicitaire, compteur, identifiant aléatoire hors
//! des champs volatiles nommés).
//!
//! Port fidèle de l'algorithme : matching blocks difflib (`autojunk`
//! désactivé), principe préfixe/suffixe, `trimAlphaNum`, remplacement par
//! expressions régulières. Trois déviations pragmatiques sont documentées :
//! - cap dur [`MAX_DYNAMIC_SCAN_CHARS`] sur la somme des deux pages (en
//!   chars) : au-delà, `vec![]` silencieux (sqlmap attrape `MemoryError`/
//!   `TypeError` autour du matching et abandonne aussi, sans borne explicite) ;
//! - pré-filtre de recouvrement type difflib `quick_ratio`
//!   (`2 * Σ_c min(count_a(c), count_b(c)) / (len_a + len_b)`, O(n)) : en
//!   dessous de 0.5, deux pages trop différentes ne peuvent pas produire de
//!   flancs fiables → `vec![]`, et le coût du DP du plus long match reste
//!   borné en pratique ;
//! - pages identiques → `vec![]` direct (résultat identique à sqlmap — les
//!   blocs pleins sont écartés par les gardes de bord — mais calcul évité).
//!
//! Limite d'intégration : seuls les points de comparaison booléens/erreur
//! purgent les marquages ; l'inférence DBMS, l'énumération et les détecteurs
//! union/stacked/oob/json/nosql gardent leurs corps bruts (hors périmètre).

use regex::Regex;
use std::collections::HashMap;

/// Longueur des flancs conservés dans un marquage (préfixe/suffixe) et seuil
/// d'exclusion des blocs trop courts (`> 2 * DYNAMICITY_BOUNDARY_LENGTH`).
pub const DYNAMICITY_BOUNDARY_LENGTH: usize = 20;

/// Cap dur de la somme des deux pages (en chars) soumises au matching :
/// au-delà, aucune zone n'est marquée (dégradation silencieuse, cf. doc du
/// module).
pub const MAX_DYNAMIC_SCAN_CHARS: usize = 200_000;

/// Seuil du pré-filtre de recouvrement type difflib `quick_ratio`.
const MIN_QUICK_RATIO: f64 = 0.5;

/// Marquage d'une zone dynamique : les deux flancs stables qui l'encadrent.
///
/// `prefix: None` = zone dynamique en tête de page (purge `^.+?suffixe`) ;
/// `suffix: None` = zone dynamique en fin de page (purge `préfixe.+$`) ; les
/// deux = zone intermédiaire (`préfixe.+?suffixe`). `(None, None)` est ignoré
/// au retrait, comme chez sqlmap.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DynamicMarking {
    /// Flanc stable gauche (`None` si la zone touche le début de la page).
    pub prefix: Option<String>,
    /// Flanc stable droit (`None` si la zone touche la fin de la page).
    pub suffix: Option<String>,
}

/// Repère les zones dynamiques entre `first` et `second` (port de
/// `findDynamicContent`, `merge` géré par l'appelant qui accumule).
///
/// Les indices sont des positions de **chars** (jamais d'octets) : les
/// préfixes/suffixes extraits restent des chaînes UTF-8 valides.
///
/// # Exemples
///
/// Le doctest sqlmap (`Lorem ipsum` + `<script src='ads.js'>`) :
///
/// ```
/// use injekt::detection::dynamic_content::find_dynamic_content;
///
/// let first = "Lorem ipsum dolor sit amet, congue tation referrentur ei sed. Ne nec legimus habemus recusabo, natum reque et per. Facer tritani reprehendunt eos id, modus constituam est te. Usu sumo indoctum ad, pri paulo molestiae complectitur no.";
/// let second = "Lorem ipsum dolor sit amet, congue tation referrentur ei sed. Ne nec legimus habemus recusabo, natum reque et per. <script src='ads.js'></script>Facer tritani reprehendunt eos id, modus constituam est te. Usu sumo indoctum ad, pri paulo molestiae complectitur no.";
///
/// let markings = find_dynamic_content(first, second);
/// assert_eq!(markings.len(), 1);
/// assert_eq!(markings[0].prefix.as_deref(), Some("natum reque et per. "));
/// assert_eq!(markings[0].suffix.as_deref(), Some("Facer tritani repreh"));
/// ```
#[must_use]
pub fn find_dynamic_content(first: &str, second: &str) -> Vec<DynamicMarking> {
    if first.is_empty() || second.is_empty() {
        return Vec::new();
    }
    // Déviations pragmatiques (cf. doc du module) : identiques → rien à
    // marquer ; cap de taille ; recouvrement trop faible.
    if first == second {
        return Vec::new();
    }
    let a: Vec<char> = first.chars().collect();
    let b: Vec<char> = second.chars().collect();
    if a.len().saturating_add(b.len()) > MAX_DYNAMIC_SCAN_CHARS {
        return Vec::new();
    }
    if quick_overlap_ratio(&a, &b) < MIN_QUICK_RATIO {
        return Vec::new();
    }
    // Blocs communs (sentinelle finale incluse), trop courts écartés.
    let mut blocks: Vec<Option<(usize, usize, usize)>> = matching_blocks(&a, &b)
        .into_iter()
        .filter(|&(_, _, length)| length > 2 * DYNAMICITY_BOUNDARY_LENGTH)
        .map(Some)
        .collect();
    if blocks.is_empty() {
        return Vec::new();
    }
    // Sentinelles de bord : le premier/dernier bloc est encadré par « rien ».
    blocks.insert(0, None);
    blocks.push(None);
    let mut markings: Vec<DynamicMarking> = Vec::new();
    for i in 0..blocks.len() - 1 {
        let mut prefix = blocks[i].map(|(start, _, length)| slice_chars(&a, start, length));
        let mut suffix = blocks[i + 1].map(|(start, _, length)| slice_chars(&a, start, length));
        // Gardes sqlmap : un flanc collé au bord de page ne marque rien (la
        // zone dynamique serait le bord lui-même).
        if prefix.is_none() && blocks[i + 1].is_some_and(|(start, _, _)| start == 0) {
            continue;
        }
        if suffix.is_none() && blocks[i].is_some_and(|(start, _, length)| start + length >= a.len())
        {
            continue;
        }
        if let (Some(p), Some(s)) = (&prefix, &suffix) {
            let mut p = tail_chars(p, DYNAMICITY_BOUNDARY_LENGTH);
            let mut s = head_chars(s, DYNAMICITY_BOUNDARY_LENGTH);
            for page in [first, second] {
                let pattern = format!("(?s){}(.+?){}", regex::escape(&p), regex::escape(&s));
                if let Ok(re) = Regex::new(&pattern)
                    && let Some(infix) = re.captures(page).and_then(|caps| caps.get(1))
                {
                    let infix = infix.as_str();
                    // Le premier match trouvé fixe le trim (sqlmap : break au
                    // premier des deux pages qui matche).
                    if infix.chars().next().is_some_and(char::is_alphanumeric) {
                        p = trim_alpha_num(&p);
                    }
                    if infix.chars().last().is_some_and(char::is_alphanumeric) {
                        s = trim_alpha_num(&s);
                    }
                    break;
                }
            }
            prefix = Some(p);
            suffix = Some(s);
        }
        let marking = DynamicMarking {
            prefix: prefix.filter(|p| !p.is_empty()),
            suffix: suffix.filter(|s| !s.is_empty()),
        };
        if !markings.contains(&marking) {
            markings.push(marking);
        }
    }
    markings
}

/// Purge d'une page les zones couvertes par `markings` (port de
/// `removeDynamicContent`).
///
/// Les marquages sont appliqués dans l'ordre, chacun via `replace_all`
/// (équivalent `re.sub` sans `count`) : `(None, Some(s))` → `^.+?s`,
/// `(Some(p), None)` → `p.+$`, `(Some(p), Some(s))` → `p.+?s` remplacé par
/// `p` + `s`. Les remplacements sont **littéraux** (le crate `regex` est
/// linéaire, pas de backtracking catastrophique).
#[must_use]
pub fn remove_dynamic_content(page: &str, markings: &[DynamicMarking]) -> String {
    if page.is_empty() || markings.is_empty() {
        return page.to_owned();
    }
    let mut out = page.to_owned();
    for marking in markings {
        let prefix = marking.prefix.as_deref().filter(|p| !p.is_empty());
        let suffix = marking.suffix.as_deref().filter(|s| !s.is_empty());
        match (prefix, suffix) {
            (None, None) => {}
            (None, Some(suffix)) => {
                let pattern = format!("(?s)^.+?{}", regex::escape(suffix));
                if let Ok(re) = Regex::new(&pattern) {
                    out = replace_with_literal(&re, &out, suffix);
                }
            }
            (Some(prefix), None) => {
                let pattern = format!("(?s){}.+$", regex::escape(prefix));
                if let Ok(re) = Regex::new(&pattern) {
                    out = replace_with_literal(&re, &out, prefix);
                }
            }
            (Some(prefix), Some(suffix)) => {
                let pattern = format!("(?s){}.+?{}", regex::escape(prefix), regex::escape(suffix));
                if let Ok(re) = Regex::new(&pattern) {
                    out = replace_with_literal(&re, &out, &format!("{prefix}{suffix}"));
                }
            }
        }
    }
    out
}

/// `Regex::replace_all` avec remplacement littéral : pas d'expansion `$name`
/// (fidèle à `re.sub`, qui n'interprète que les backslashes).
fn replace_with_literal(re: &Regex, text: &str, replacement: &str) -> String {
    re.replace_all(text, |_: &regex::Captures<'_>| replacement.to_owned())
        .into_owned()
}

/// Blocs communs maximaux entre `a` et `b`, triés, non adjacents, suivis de la
/// sentinelle `(len(a), len(b), 0)` — port de
/// `difflib.SequenceMatcher.get_matching_blocks` avec `autojunk` désactivé.
#[allow(clippy::many_single_char_names, clippy::similar_names)]
fn matching_blocks(a: &[char], b: &[char]) -> Vec<(usize, usize, usize)> {
    let mut b2j: HashMap<char, Vec<usize>> = HashMap::new();
    for (idx, &c) in b.iter().enumerate() {
        b2j.entry(c).or_default().push(idx);
    }
    let (la, lb) = (a.len(), b.len());
    let mut queue = vec![(0usize, la, 0usize, lb)];
    let mut found: Vec<(usize, usize, usize)> = Vec::new();
    while let Some((alo, ahi, blo, bhi)) = queue.pop() {
        let (i, j, k) = find_longest_match(a, b, &b2j, alo, ahi, blo, bhi);
        if k > 0 {
            found.push((i, j, k));
            // Sous-ranges gauche/droite autour du meilleur bloc (difflib).
            if alo < i && blo < j {
                queue.push((alo, i, blo, j));
            }
            if i + k < ahi && j + k < bhi {
                queue.push((i + k, ahi, j + k, bhi));
            }
        }
    }
    found.sort_unstable();
    // Fusion des blocs adjacents (difflib ≥ 2.5).
    let mut non_adjacent: Vec<(usize, usize, usize)> = Vec::new();
    let (mut i1, mut j1, mut k1) = (0usize, 0usize, 0usize);
    for &(i2, j2, k2) in &found {
        if i1 + k1 == i2 && j1 + k1 == j2 {
            k1 += k2;
        } else {
            if k1 > 0 {
                non_adjacent.push((i1, j1, k1));
            }
            i1 = i2;
            j1 = j2;
            k1 = k2;
        }
    }
    if k1 > 0 {
        non_adjacent.push((i1, j1, k1));
    }
    non_adjacent.push((la, lb, 0));
    non_adjacent
}

/// Plus long match dans la fenêtre `a[alo..ahi]` × `b[blo..bhi]` — port de
/// `difflib.SequenceMatcher.find_longest_match` (algorithme `j2len`, puis
/// extension gauche/droite ; les passes « junk » de difflib sont des no-ops
/// sans `isjunk`).
#[allow(clippy::many_single_char_names, clippy::similar_names)]
fn find_longest_match(
    a: &[char],
    b: &[char],
    b2j: &HashMap<char, Vec<usize>>,
    alo: usize,
    ahi: usize,
    blo: usize,
    bhi: usize,
) -> (usize, usize, usize) {
    let mut besti = alo;
    let mut bestj = blo;
    let mut bestsize = 0usize;
    let mut j2len: HashMap<usize, usize> = HashMap::new();
    for (offset, &ca) in a[alo..ahi].iter().enumerate() {
        let i = alo + offset;
        let mut newj2len: HashMap<usize, usize> = HashMap::new();
        if let Some(indices) = b2j.get(&ca) {
            for &j in indices {
                if j < blo {
                    continue;
                }
                if j >= bhi {
                    break;
                }
                let k = j
                    .checked_sub(1)
                    .and_then(|prev| j2len.get(&prev))
                    .copied()
                    .unwrap_or(0)
                    + 1;
                newj2len.insert(j, k);
                if k > bestsize {
                    besti = i + 1 - k;
                    bestj = j + 1 - k;
                    bestsize = k;
                }
            }
        }
        j2len = newj2len;
    }
    while besti > alo && bestj > blo && a[besti - 1] == b[bestj - 1] {
        besti -= 1;
        bestj -= 1;
        bestsize += 1;
    }
    while besti + bestsize < ahi
        && bestj + bestsize < bhi
        && a[besti + bestsize] == b[bestj + bestsize]
    {
        bestsize += 1;
    }
    (besti, bestj, bestsize)
}

/// Recouvrement `quick_ratio` de difflib : `2 * Σ_c min(count_a(c), count_b(c))
/// / (len_a + len_b)`, en O(n).
#[allow(clippy::cast_precision_loss)]
fn quick_overlap_ratio(a: &[char], b: &[char]) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 1.0;
    }
    let mut counts: HashMap<char, usize> = HashMap::new();
    for &c in b {
        *counts.entry(c).or_insert(0) += 1;
    }
    let mut matches = 0usize;
    for &c in a {
        if let Some(remaining) = counts.get_mut(&c)
            && *remaining > 0
        {
            *remaining -= 1;
            matches += 1;
        }
    }
    2.0 * matches as f64 / (a.len() + b.len()) as f64
}

/// Tranche `chars[start..start + length]` (bornes garanties par les blocs
/// difflib, qui restent dans les pages).
fn slice_chars(chars: &[char], start: usize, length: usize) -> String {
    chars[start..start + length].iter().collect()
}

/// `value[:n]` en chars.
fn head_chars(value: &str, n: usize) -> String {
    value.chars().take(n).collect()
}

/// `value[-n:]` en chars.
fn tail_chars(value: &str, n: usize) -> String {
    let total = value.chars().count();
    value.chars().skip(total.saturating_sub(n)).collect()
}

/// Port de `trimAlphaNum` : retire les caractères alphanumériques (Unicode,
/// comme `str.isalnum()` en Python) en fin puis en tête.
fn trim_alpha_num(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    let mut start = 0usize;
    let mut end = chars.len();
    while end > start && chars[end - 1].is_alphanumeric() {
        end -= 1;
    }
    while start < end && chars[start].is_alphanumeric() {
        start += 1;
    }
    chars[start..end].iter().collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const LOREM: &str = "Lorem ipsum dolor sit amet, congue tation referrentur ei sed. Ne nec legimus habemus recusabo, natum reque et per. Facer tritani reprehendunt eos id, modus constituam est te. Usu sumo indoctum ad, pri paulo molestiae complectitur no.";
    const LOREM_INJECTED: &str = "Lorem ipsum dolor sit amet, congue tation referrentur ei sed. Ne nec legimus habemus recusabo, natum reque et per. <script src='ads.js'></script>Facer tritani reprehendunt eos id, modus constituam est te. Usu sumo indoctum ad, pri paulo molestiae complectitur no.";

    #[test]
    fn sqlmap_doctest_marking() {
        let markings = find_dynamic_content(LOREM, LOREM_INJECTED);
        assert_eq!(markings.len(), 1, "{markings:?}");
        assert_eq!(markings[0].prefix.as_deref(), Some("natum reque et per. "));
        assert_eq!(markings[0].suffix.as_deref(), Some("Facer tritani repreh"));
        // La purge retire la zone insérée et rend la page à son état stable.
        let stripped = remove_dynamic_content(LOREM_INJECTED, &markings);
        assert_eq!(stripped, LOREM);
        // La page sans la zone ne bouge pas (le motif `.+?` exige un infixe).
        assert_eq!(remove_dynamic_content(LOREM, &markings), LOREM);
    }

    #[test]
    fn dynamic_zone_at_page_start_gets_none_prefix() {
        let stable = "Usu sumo indoctum ad, pri paulo molestiae complectitur no. Facer tritani reprehendunt eos id, modus constituam est te.";
        let first = format!("ads-0123456789abcdef{stable}");
        let second = format!("ads-fedcba9876543210{stable}");
        let markings = find_dynamic_content(&first, &second);
        assert_eq!(markings.len(), 1, "{markings:?}");
        assert_eq!(markings[0].prefix, None, "{markings:?}");
        assert_eq!(markings[0].suffix.as_deref(), Some(stable), "{markings:?}");
        let stripped_first = remove_dynamic_content(&first, &markings);
        let stripped_second = remove_dynamic_content(&second, &markings);
        assert_eq!(stripped_first, stripped_second);
        assert!(!stripped_first.contains("0123456789abcdef"));
    }

    #[test]
    fn dynamic_zone_at_page_end_gets_none_suffix() {
        let stable = "Lorem ipsum dolor sit amet, congue tation referrentur ei sed. Ne nec legimus habemus recusabo.";
        let first = format!("{stable}ads-0123456789abcdef");
        let second = format!("{stable}ads-fedcba9876543210");
        let markings = find_dynamic_content(&first, &second);
        assert_eq!(markings.len(), 1, "{markings:?}");
        assert_eq!(markings[0].suffix, None, "{markings:?}");
        let prefix = markings[0].prefix.as_deref().expect("prefix marqué");
        assert!(first.starts_with(prefix), "prefix={prefix:?}");
        let stripped_first = remove_dynamic_content(&first, &markings);
        let stripped_second = remove_dynamic_content(&second, &markings);
        assert_eq!(stripped_first, stripped_second);
        assert!(!stripped_first.contains("0123456789abcdef"));
    }

    #[test]
    fn identical_pages_have_no_markings() {
        assert!(find_dynamic_content(LOREM, LOREM).is_empty());
        assert!(find_dynamic_content("short", "short").is_empty());
    }

    #[test]
    fn very_different_pages_are_not_marked() {
        // Pré-filtre `quick_ratio` : aucun caractère commun → rien à marquer.
        let first = "a".repeat(120);
        let second = "b".repeat(120);
        assert!(find_dynamic_content(&first, &second).is_empty());
    }

    #[test]
    fn oversized_pages_degrade_silently() {
        let first = "a".repeat(MAX_DYNAMIC_SCAN_CHARS / 2 + 1);
        let second = "b".repeat(MAX_DYNAMIC_SCAN_CHARS / 2 + 1);
        assert!(find_dynamic_content(&first, &second).is_empty());
    }

    #[test]
    fn remove_handles_each_marking_shape_and_is_idempotent() {
        let cases: [(DynamicMarking, &str); 4] = [
            (
                DynamicMarking {
                    prefix: None,
                    suffix: Some("TAIL".to_owned()),
                },
                "TAIL",
            ),
            (
                DynamicMarking {
                    prefix: Some("HEAD".to_owned()),
                    suffix: None,
                },
                "HEAD",
            ),
            (
                DynamicMarking {
                    prefix: Some("HEAD".to_owned()),
                    suffix: Some("TAIL".to_owned()),
                },
                "HEADTAIL",
            ),
            (
                DynamicMarking {
                    prefix: None,
                    suffix: None,
                },
                "HEAD-0123456789abcdef-TAIL",
            ),
        ];
        for (marking, expected) in cases {
            let page = "HEAD-0123456789abcdef-TAIL";
            let stripped = remove_dynamic_content(page, std::slice::from_ref(&marking));
            assert_eq!(stripped, expected, "{marking:?}");
            let twice = remove_dynamic_content(&stripped, std::slice::from_ref(&marking));
            assert_eq!(twice, stripped, "idempotent pour {marking:?}");
        }
    }

    #[test]
    fn unicode_multibyte_flanks_do_not_panic() {
        let left = "安定した日本語のコンテンツです。これは非常に長い静的なフランクであり、動的部分の左側に位置します。";
        let right = "動的部分の右側に位置する、これもまた非常に長い静的なフランクです。以上、テスト終わり。";
        let first = format!("{left}ads-😀😀😀😀{right}");
        let second = format!("{left}ads-🚀🚀🚀🚀{right}");
        let markings = find_dynamic_content(&first, &second);
        assert_eq!(markings.len(), 1, "{markings:?}");
        let stripped_first = remove_dynamic_content(&first, &markings);
        let stripped_second = remove_dynamic_content(&second, &markings);
        assert_eq!(stripped_first, stripped_second);
        assert!(!stripped_first.contains('😀'));
        assert!(!stripped_second.contains('🚀'));
    }

    #[test]
    fn empty_inputs_are_noops() {
        assert!(find_dynamic_content("", LOREM).is_empty());
        assert!(find_dynamic_content(LOREM, "").is_empty());
        assert!(remove_dynamic_content("", &[]).is_empty());
        let marking = DynamicMarking {
            prefix: None,
            suffix: None,
        };
        assert_eq!(remove_dynamic_content("unchanged", &[marking]), "unchanged");
    }
}
