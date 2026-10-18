//! difflib-compatible matching engine (P5 split of
//! `detection::dynamic_content`): SequenceMatcher blocks (autojunk off),
//! longest-match DP, quick-overlap prefilter and UTF-8 char helpers.

use std::collections::HashMap;

pub(super) fn matching_blocks(a: &[char], b: &[char]) -> Vec<(usize, usize, usize)> {
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
pub(super) fn quick_overlap_ratio(a: &[char], b: &[char]) -> f64 {
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
pub(super) fn slice_chars(chars: &[char], start: usize, length: usize) -> String {
    chars[start..start + length].iter().collect()
}

/// `value[:n]` en chars.
pub(super) fn head_chars(value: &str, n: usize) -> String {
    value.chars().take(n).collect()
}

/// `value[-n:]` en chars.
pub(super) fn tail_chars(value: &str, n: usize) -> String {
    let total = value.chars().count();
    value.chars().skip(total.saturating_sub(n)).collect()
}

/// Port de `trimAlphaNum` : retire les caractères alphanumériques (Unicode,
/// comme `str.isalnum()` en Python) en fin puis en tête.
pub(super) fn trim_alpha_num(value: &str) -> String {
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
