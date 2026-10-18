use super::kind::MAX_STRUCTURED_PAIRS;
use regex::Regex;
use std::sync::OnceLock;

/// Extrait les feuilles `XML` en paires `(nom-complet, texte-direct)`.
///
/// Motif d'ouverture `<Tag attributs?>texte` ; le fermant `</Tag>` est vérifié
/// par comparaison string (la crate `regex` ne supporte pas les backrefs).
/// Balayage global : premier niveau et imbriqués aplatis naïvement,
/// attributs ignorés, noms préfixés `xml:`. Corps sans match : vecteur vide.
/// Tronqué à [`MAX_STRUCTURED_PAIRS`].
#[must_use]
pub fn xml_tags(body: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let Some(re) = xml_open_regex() else {
        return out;
    };
    for captures in re.captures_iter(body) {
        if out.len() >= MAX_STRUCTURED_PAIRS {
            break;
        }
        let (Some(tag_match), Some(text_match), Some(open_match)) =
            (captures.get(1), captures.get(2), captures.get(0))
        else {
            continue;
        };
        let tag = tag_match.as_str();
        let closer = format!("</{tag}>");
        if body[open_match.end()..].starts_with(&closer) {
            out.push((format!("xml:{tag}"), text_match.as_str().to_owned()));
        }
    }
    out
}

/// Remplace le contenu du PREMIER `<tag>ancien</tag>` par `payload` TEL QUEL.
///
/// Le payload est inséré verbatim, sans échappement `XML` : le break-out par
/// fermeture de tag dans le payload est le comportement voulu (voir choix
/// documenté en tête de module). Les attributs du tag ouvrant sont tolérés,
/// la fermeture doit être stricte (`</Tag>`). `tag` accepte le préfixe `xml:`.
/// `None` si tag vide/absent ou corps sans match.
#[must_use]
pub fn inject_xml_tag(body: &str, tag: &str, payload: &str) -> Option<String> {
    if tag.is_empty() {
        return None;
    }
    let bare = match tag.strip_prefix("xml:") {
        Some(rest) => rest,
        None => tag,
    };
    if bare.is_empty() {
        return None;
    }
    // Regex-free scan (was `Regex::new` per call — hot loop over every
    // payload × tamper variant). Semantics kept: first `<tag attrs?>content`
    // with strict `</tag>`, attributes tolerated, self-closers ignored,
    // content without `<`.
    let closer = format!("</{bare}>");
    let mut search_from = 0usize;
    while let Some(open_rel) = body[search_from..].find('<') {
        let open_idx = search_from + open_rel;
        let after_lt = &body[open_idx + 1..];
        // Must be exactly `<bare` (not `</bare`, not `<barely`).
        if after_lt.starts_with('/') || !after_lt.starts_with(bare) {
            search_from = open_idx + 1;
            continue;
        }
        let after_tag = &after_lt[bare.len()..];
        let first = after_tag.chars().next();
        if !first.is_some_and(|c| c == '>' || c.is_ascii_whitespace()) {
            // Longer tag name (`<ab>` when looking for `a`) or `<a/>`.
            search_from = open_idx + 1;
            continue;
        }
        // End of the opening tag: first `>` (attributes cannot contain `>`).
        let gt_rel = after_tag.find('>')?;
        let content_start = open_idx + 1 + bare.len() + gt_rel + 1;
        // Content runs to the next `<` and must be followed by strict `</tag>`.
        let lt_rel = body[content_start..].find('<')?;
        let content_end = content_start + lt_rel;
        if body[content_end..].starts_with(&closer) {
            let mut out = String::with_capacity(body.len() + payload.len());
            out.push_str(&body[..content_start]);
            out.push_str(payload);
            out.push_str(&body[content_end..]);
            return Some(out);
        }
        search_from = content_end + 1;
    }
    None
}

/// Motif d'ouverture `XML` partagé par [`xml_tags`].
const XML_OPEN_PATTERN: &str = r"<([\w:.-]+)(?:\s[^>]*)?>([^<]*)";

/// `Regex` d'ouverture compilée une fois ; `None` impossible en pratique
/// (motif constant valide) mais propagé sans `panic` par principe.
fn xml_open_regex() -> Option<&'static Regex> {
    static CELL: OnceLock<Option<Regex>> = OnceLock::new();
    CELL.get_or_init(|| Regex::new(XML_OPEN_PATTERN).ok())
        .as_ref()
}
