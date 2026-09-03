#![deny(unsafe_code)]

//! Helpers purs pour les corps structurés (`form` / `JSON` / `XML`).
//!
//! Module isolé : fonctions pures uniquement, sans I/O, sans état global
//! (hormis une `regex` compilée paresseusement), jamais de `panic` quelle
//! que soit l'entrée. Le coordinateur possède le câblage collect/inject et
//! s'appuie sur la convention de nommage ci-dessous.
//!
//! # Convention de nommage (`TargetParameter.name`)
//!
//! - `JSON` : `json:` suivi d'un pointeur `/`-joint, ex. `json:/a/0/b`
//!   (objet `a`, indice de tableau `0`, clé `b` — équivalent point/crochets
//!   `a[0].b`). Les segments échappent `~` en `~0` et `/` en `~1` (style
//!   `RFC6901`). Les clés retournées par [`json_paths`] incluent déjà le
//!   préfixe `json:` et sont prêtes pour un aller-retour via [`split_name`].
//! - `XML` : `xml:` suivi du nom du tag, ex. `xml:User`. Premier niveau et
//!   imbriqués sont aplatis naïvement par balayage global : chaque
//!   `<Tag>texte</Tag>` (attributs ignorés, valeur = texte direct brut sans
//!   `<`, entités non décodées) donne une paire, dans l'ordre du document,
//!   doublons inclus. Les namespaces restent verbatim (`xml:soap:Body`).
//! - Sinon le nom est un champ `form` utilisé verbatim.
//!
//! [`split_name`] redécoupe un nom en `(StructuredKind, reste)` ; `reste`
//! s'injecte tel quel dans [`inject_json_path`] / [`inject_xml_tag`] (les
//! deux acceptent aussi la forme préfixée). [`inject_json_path`] accepte les
//! deux syntaxes de chemin : pointeur `/a/0/b` et point/crochets `a.b[0]`.
//!
//! # Choix d'échappement `XML` : payload inséré TEL QUEL
//!
//! [`inject_xml_tag`] insère `payload` verbatim, sans échappement `XML`.
//! Justification : parité d'exploitation avec les autres vecteurs —
//! l'objectif est le break-out de tag (ex. `</User><Injection/>`), que tout
//! échappement neutraliserait. Risque assumé et documenté : le document
//! résultant peut être malformé ; c'est le comportement voulu pour un
//! vecteur d'injection (même philosophie que [`inject_json_path`], qui casse
//! volontairement le typage `JSON` en remplaçant la feuille par une chaîne).
//!
//! # Garde-fous
//!
//! - [`MAX_STRUCTURED_PAIRS`] (500) : [`json_paths`] et [`xml_tags`] tronquent.
//! - [`MAX_JSON_DEPTH`] (8, racine = 0) : les scalaires plus profonds sont ignorés.
//! - Corps `JSON` invalide ou sans `XML` reconnaissable : vecteur vide.
//! - Limites connues : tableau `JSON` racine (`[...]`) classé `Form` par
//!   [`sniff_kind`] ; clés `JSON` contenant `.`, `[` ou `]` non adressables
//!   par [`inject_json_path`] ; auto-fermants `<Tag/>` ignorés ; fermeture
//!   `XML` stricte (`</Tag>` sans espace).

use std::sync::OnceLock;

use regex::Regex;
use serde_json::Value;

/// Nombre maximal de paires `(nom, valeur)` retournées par [`json_paths`]
/// et [`xml_tags`].
pub const MAX_STRUCTURED_PAIRS: usize = 500;

/// Profondeur `JSON` maximale explorée par [`json_paths`] (racine = 0).
/// Les scalaires situés au-delà sont ignorés.
pub const MAX_JSON_DEPTH: usize = 8;

/// Saveur d'un corps de requête, utilisée pour router collect/inject.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum StructuredKind {
    /// Formulaire `urlencoded` ou corps non reconnu.
    #[default]
    Form,
    /// Corps `JSON` (`Content-Type` contenant `json`, ou corps trimmé
    /// commençant par `{`).
    Json,
    /// Corps `XML`/`SOAP` (`Content-Type` contenant `xml`/`soap`, ou corps
    /// trimmé commençant par `<`).
    Xml,
}

/// Détecte la saveur d'un corps : `Content-Type` d'abord, forme du corps sinon.
///
/// La comparaison sur le `Content-Type` est insensible à la casse. Un
/// `Content-Type` `None` ou vide (ou sans mot-clé) bascule sur le sniff du
/// corps trimmé : `{` donne [`StructuredKind::Json`], `<` donne
/// [`StructuredKind::Xml`], sinon [`StructuredKind::Form`].
#[must_use]
pub fn sniff_kind(content_type: Option<&str>, body: &str) -> StructuredKind {
    if let Some(ct) = content_type {
        let lowered = ct.to_ascii_lowercase();
        if lowered.contains("json") {
            return StructuredKind::Json;
        }
        if lowered.contains("xml") || lowered.contains("soap") {
            return StructuredKind::Xml;
        }
    }
    let trimmed = body.trim_start();
    if trimmed.starts_with('{') {
        StructuredKind::Json
    } else if trimmed.starts_with('<') {
        StructuredKind::Xml
    } else {
        StructuredKind::Form
    }
}

/// Redécoupe un nom de paramètre en `(saveur, reste)`.
///
/// `json:` préfixe vers [`StructuredKind::Json`], `xml:` vers
/// [`StructuredKind::Xml`], sinon [`StructuredKind::Form`] avec le nom intact.
/// Le `reste` s'injecte tel quel dans [`inject_json_path`]/[`inject_xml_tag`].
#[must_use]
pub fn split_name(name: &str) -> (StructuredKind, &str) {
    if let Some(rest) = name.strip_prefix("json:") {
        (StructuredKind::Json, rest)
    } else if let Some(rest) = name.strip_prefix("xml:") {
        (StructuredKind::Xml, rest)
    } else {
        (StructuredKind::Form, name)
    }
}

/// Aplatit un corps `JSON` en paires `(nom-complet, valeur-scalaire)`.
///
/// Les noms incluent le préfixe `json:` (ex. `json:/a/0/b`). Objets imbriqués
/// et tableaux indicés (base 0) ; les scalaires sont stringifiés (`String`
/// telle quelle, `Null` vers `""`, autres via rendu `JSON`) ; racine scalaire
/// vers `json:`. `JSON` invalide : vecteur vide. Tronqué à
/// [`MAX_STRUCTURED_PAIRS`], profondeur limitée à [`MAX_JSON_DEPTH`].
#[must_use]
pub fn json_paths(body: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let Ok(value) = serde_json::from_str::<Value>(body) else {
        return out;
    };
    flatten_json(&value, "", 0, &mut out);
    out
}

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

/// Remplace une feuille `JSON` par `Value::String(payload)` et resérialise.
///
/// `path` accepte le pointeur (`/a/0/b`, avec ou sans préfixe `json:`) comme
/// la forme point/crochets (`a.b[0]`). La feuille devient volontairement une
/// chaîne (casse le typage d'origine pour le break-out). `None` si : corps
/// invalide, chemin vide/racine, clé/indice absent, traversée d'un scalaire,
/// ou cible non-scalaire (objet/tableau préservés).
#[must_use]
pub fn inject_json_path(body: &str, path: &str, payload: &str) -> Option<String> {
    let segments = json_path_segments(path);
    if segments.is_empty() {
        return None;
    }
    let mut value: Value = serde_json::from_str(body).ok()?;
    let mut pointer = String::new();
    for segment in &segments {
        pointer.push('/');
        pointer.push_str(&escape_json_segment(segment));
    }
    let slot = value.pointer_mut(&pointer)?;
    if slot.is_object() || slot.is_array() {
        return None;
    }
    *slot = Value::String(payload.to_owned());
    serde_json::to_string(&value).ok()
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
    let pattern = format!(
        r"<{tag}(?:\s[^>]*)?>([^<]*)</{tag}>",
        tag = regex::escape(bare)
    );
    let re = Regex::new(&pattern).ok()?;
    let captures = re.captures(body)?;
    let content = captures.get(1)?;
    let mut out = String::with_capacity(body.len() + payload.len());
    out.push_str(&body[..content.start()]);
    out.push_str(payload);
    out.push_str(&body[content.end()..]);
    Some(out)
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

/// Stringifie un scalaire `JSON` (objets/tableaux exclus par construction).
#[must_use]
fn scalar_to_string(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        _ => value.to_string(),
    }
}

/// Échappe un segment de pointeur (`~` puis `/`, style `RFC6901`).
#[must_use]
fn escape_json_segment(segment: &str) -> String {
    segment.replace('~', "~0").replace('/', "~1")
}

/// Inverse de [`escape_json_segment`].
#[must_use]
fn unescape_json_segment(segment: &str) -> String {
    segment.replace("~1", "/").replace("~0", "~")
}

/// Descente récursive bornée (`profondeur` + `cap`) accumulant les feuilles.
fn flatten_json(value: &Value, prefix: &str, depth: usize, out: &mut Vec<(String, String)>) {
    if out.len() >= MAX_STRUCTURED_PAIRS || depth > MAX_JSON_DEPTH {
        return;
    }
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if out.len() >= MAX_STRUCTURED_PAIRS {
                    break;
                }
                let mut child_prefix = String::with_capacity(prefix.len() + key.len() + 1);
                child_prefix.push_str(prefix);
                child_prefix.push('/');
                child_prefix.push_str(&escape_json_segment(key));
                flatten_json(child, &child_prefix, depth + 1, out);
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                if out.len() >= MAX_STRUCTURED_PAIRS {
                    break;
                }
                let child_prefix = format!("{prefix}/{index}");
                flatten_json(child, &child_prefix, depth + 1, out);
            }
        }
        _ => {
            out.push((format!("json:{prefix}"), scalar_to_string(value)));
        }
    }
}

/// Tokenise un chemin `JSON` en segments : préfixe `json:` optionnel, puis
/// découpe sur `.`, `/`, `[`, `]` (vides ignorés), avec déséchappement
/// `~1`/`~0`. Accepte donc `/a/0/b`, `a.b[0]`, `json:/a/0/b`.
#[must_use]
fn json_path_segments(path: &str) -> Vec<String> {
    let trimmed = path.trim();
    let bare = match trimmed.strip_prefix("json:") {
        Some(rest) => rest,
        None => trimmed,
    };
    bare.split(['.', '/', '[', ']'])
        .filter(|segment| !segment.is_empty())
        .map(unescape_json_segment)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Write as _;

    #[test]
    fn sniff_prefers_content_type() {
        assert_eq!(
            sniff_kind(Some("application/json"), "<a>x</a>"),
            StructuredKind::Json
        );
        assert_eq!(
            sniff_kind(Some("Application/JSON; charset=utf-8"), "a=1"),
            StructuredKind::Json
        );
        assert_eq!(
            sniff_kind(Some("text/xml"), "{\"a\":1}"),
            StructuredKind::Xml
        );
        assert_eq!(
            sniff_kind(Some("application/soap+xml"), "x"),
            StructuredKind::Xml
        );
        assert_eq!(
            sniff_kind(Some("application/x-www-form-urlencoded"), "a=1&b=2"),
            StructuredKind::Form
        );
    }

    #[test]
    fn sniff_falls_back_to_body() {
        assert_eq!(sniff_kind(None, "{\"a\":1}"), StructuredKind::Json);
        assert_eq!(sniff_kind(Some(""), "  {\"a\":1}"), StructuredKind::Json);
        assert_eq!(sniff_kind(None, "  <a>x</a>"), StructuredKind::Xml);
        assert_eq!(sniff_kind(None, "a=1&b=2"), StructuredKind::Form);
        assert_eq!(sniff_kind(None, ""), StructuredKind::Form);
        // Limitation documentée : tableau racine classé Form.
        assert_eq!(sniff_kind(None, "[1,2]"), StructuredKind::Form);
    }

    #[test]
    fn split_name_routes_prefixes() {
        assert_eq!(split_name("json:/a/0"), (StructuredKind::Json, "/a/0"));
        assert_eq!(split_name("json:"), (StructuredKind::Json, ""));
        assert_eq!(split_name("xml:User"), (StructuredKind::Xml, "User"));
        assert_eq!(split_name("xml:"), (StructuredKind::Xml, ""));
        assert_eq!(split_name("id"), (StructuredKind::Form, "id"));
        assert_eq!(split_name("jsonx:y"), (StructuredKind::Form, "jsonx:y"));
        assert_eq!(split_name(""), (StructuredKind::Form, ""));
    }

    #[test]
    fn names_roundtrip_through_split_and_inject() {
        let body = "{\"a\":{\"b\":1}}";
        assert_eq!(
            json_paths(body),
            vec![("json:/a/b".to_owned(), "1".to_owned())]
        );
        let (kind, rest) = split_name("json:/a/b");
        assert_eq!(kind, StructuredKind::Json);
        assert_eq!(
            inject_json_path(body, rest, "2"),
            Some("{\"a\":{\"b\":\"2\"}}".to_owned())
        );
    }

    #[test]
    fn json_paths_flattens_nested_and_arrays() {
        let body = "{\"a\":{\"b\":1},\"c\":[true,\"x\",null]}";
        assert_eq!(
            json_paths(body),
            vec![
                ("json:/a/b".to_owned(), "1".to_owned()),
                ("json:/c/0".to_owned(), "true".to_owned()),
                ("json:/c/1".to_owned(), "x".to_owned()),
                ("json:/c/2".to_owned(), String::new()),
            ]
        );
    }

    #[test]
    fn json_paths_handles_roots_and_invalid() {
        assert!(json_paths("{oops").is_empty());
        assert!(json_paths("").is_empty());
        assert!(json_paths("{}").is_empty());
        assert_eq!(
            json_paths("42"),
            vec![("json:".to_owned(), "42".to_owned())]
        );
        assert_eq!(
            json_paths("\"hi\""),
            vec![("json:".to_owned(), "hi".to_owned())]
        );
        assert_eq!(
            json_paths("true"),
            vec![("json:".to_owned(), "true".to_owned())]
        );
    }

    #[test]
    fn xml_tags_extracts_leaf_text() {
        assert_eq!(
            xml_tags("<a>1</a><b>x</b>"),
            vec![
                ("xml:a".to_owned(), "1".to_owned()),
                ("xml:b".to_owned(), "x".to_owned()),
            ]
        );
    }

    #[test]
    fn xml_tags_ignores_attrs_and_keeps_namespaces() {
        assert_eq!(
            xml_tags("<a id=\"1\" class=\"c\">x</a>"),
            vec![("xml:a".to_owned(), "x".to_owned())]
        );
        assert_eq!(
            xml_tags("<soap:Body>hi</soap:Body>"),
            vec![("xml:soap:Body".to_owned(), "hi".to_owned())]
        );
    }

    #[test]
    fn xml_tags_flattens_nested_naively_and_rejects_invalid() {
        // Le parent `<a>` contient `<` donc ne matche pas ; seul `<b>` sort.
        assert_eq!(
            xml_tags("<a><b>x</b></a>"),
            vec![("xml:b".to_owned(), "x".to_owned())]
        );
        assert!(xml_tags("not xml at all").is_empty());
        assert!(xml_tags("<a>unclosed").is_empty());
        assert!(xml_tags("").is_empty());
    }

    #[test]
    fn inject_json_replaces_leaf_and_breaks_typing() {
        let body = "{\"a\":{\"b\":1}}";
        assert_eq!(
            inject_json_path(body, "a.b", "' OR '1'='1"),
            Some("{\"a\":{\"b\":\"' OR '1'='1\"}}".to_owned())
        );
        assert_eq!(
            inject_json_path(body, "/a/b", "x"),
            Some("{\"a\":{\"b\":\"x\"}}".to_owned())
        );
        assert_eq!(
            inject_json_path(body, "json:/a/b", "x"),
            Some("{\"a\":{\"b\":\"x\"}}".to_owned())
        );
        assert_eq!(
            inject_json_path("{\"c\":[1,2]}", "c[1]", "x"),
            Some("{\"c\":[1,\"x\"]}".to_owned())
        );
    }

    #[test]
    fn inject_json_rejects_bad_paths() {
        let body = "{\"a\":{\"b\":1}}";
        assert!(inject_json_path(body, "", "x").is_none());
        assert!(inject_json_path(body, "/", "x").is_none());
        assert!(inject_json_path(body, "json:", "x").is_none());
        assert!(inject_json_path(body, "a.zzz", "x").is_none());
        assert!(inject_json_path(body, "a.b.c", "x").is_none());
        assert!(inject_json_path(body, "a", "x").is_none());
        assert!(inject_json_path("{oops", "a", "x").is_none());
        assert!(inject_json_path("{\"c\":[1]}", "c.5", "x").is_none());
    }

    #[test]
    fn inject_xml_replaces_first_occurrence_verbatim() {
        assert_eq!(
            inject_xml_tag("<a>1</a><a>2</a>", "a", "y"),
            Some("<a>y</a><a>2</a>".to_owned())
        );
        assert_eq!(
            inject_xml_tag("<a id=\"1\">x</a>", "a", "y"),
            Some("<a id=\"1\">y</a>".to_owned())
        );
        assert_eq!(
            inject_xml_tag("<a>x</a>", "xml:a", "y"),
            Some("<a>y</a>".to_owned())
        );
        // Choix documenté : break-out inséré tel quel, sans échappement.
        assert_eq!(
            inject_xml_tag("<a>1</a><a>2</a>", "a", "</a><b>x</b>"),
            Some("<a></a><b>x</b></a><a>2</a>".to_owned())
        );
        let special = "Tom & Jerry <3 \"q\" 's'";
        let got = inject_xml_tag("<a>x</a>", "a", special);
        assert!(got.is_some_and(|s| s.contains(special)));
    }

    #[test]
    fn inject_xml_rejects_missing_or_empty_tag() {
        assert!(inject_xml_tag("<a>x</a>", "b", "y").is_none());
        assert!(inject_xml_tag("<a>x</a>", "", "y").is_none());
        assert!(inject_xml_tag("<a>x</a>", "xml:", "y").is_none());
        assert!(inject_xml_tag("plain", "a", "y").is_none());
    }

    #[test]
    fn pairs_truncate_at_cap() {
        let mut json_body = String::from("{");
        for i in 0..(MAX_STRUCTURED_PAIRS + 100) {
            if i > 0 {
                json_body.push(',');
            }
            let _ = write!(json_body, "\"k{i}\":{i}");
        }
        json_body.push('}');
        assert_eq!(json_paths(&json_body).len(), MAX_STRUCTURED_PAIRS);

        let mut xml_body = String::new();
        for i in 0..(MAX_STRUCTURED_PAIRS + 100) {
            let _ = write!(xml_body, "<k{i}>v</k{i}>");
        }
        assert_eq!(xml_tags(&xml_body).len(), MAX_STRUCTURED_PAIRS);
    }

    #[test]
    fn json_paths_enforces_max_depth() {
        assert_eq!(json_paths(&nested_json_body(8)).len(), 1);
        assert!(json_paths(&nested_json_body(12)).is_empty());
    }

    #[test]
    fn tolerant_inputs_never_panic() {
        let bodies = [
            "",
            " ",
            "\u{FEFF}{\"a\":1}",
            "é\u{1F600}ß",
            "{{{{",
            "<<<<",
            "\u{FFFD}\u{FFFD}",
            "<a>\u{1F600}</a>",
            "{\"a\":\"\u{FFFD}\"}",
            "<a id=>x</a>",
            "</>",
            "<a/>",
        ];
        for body in bodies {
            let _kind = sniff_kind(None, body);
            assert!(json_paths(body).len() <= MAX_STRUCTURED_PAIRS);
            assert!(xml_tags(body).len() <= MAX_STRUCTURED_PAIRS);
            let _injected_json = inject_json_path(body, "a", "p");
            let _injected_xml = inject_xml_tag(body, "a", "p");
            let _split = split_name(body);
        }
    }

    #[test]
    fn default_kind_is_form() {
        assert_eq!(StructuredKind::default(), StructuredKind::Form);
    }

    /// Construit `{"k":...{"k":1}...}` à `depth` niveaux (feuille scalaire).
    #[must_use]
    fn nested_json_body(depth: usize) -> String {
        let mut body = String::from("1");
        for _ in 0..depth {
            body = format!("{{\"k\":{body}}}");
        }
        body
    }
}
