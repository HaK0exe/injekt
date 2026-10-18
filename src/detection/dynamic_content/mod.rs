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

use self::diff::{
    head_chars, matching_blocks, quick_overlap_ratio, slice_chars, tail_chars, trim_alpha_num,
};

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
mod diff;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests;
