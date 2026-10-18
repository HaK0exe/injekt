use super::kind::{MAX_JSON_DEPTH, MAX_STRUCTURED_PAIRS};
use serde_json::Value;

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

/// Remplace une feuille `JSON` par `Value::String(payload)` et resérialise.
///
/// `path` accepte le pointeur (`/a/0/b`, avec ou sans préfixe `json:`) comme
/// la forme point/crochets (`a.b[0]`). La feuille devient volontairement une
/// chaîne (casse le typage d'origine pour le break-out). `None` si : corps
/// invalide, chemin vide/racine, clé/indice absent, traversée d'un scalaire,
/// ou cible non-scalaire (objet/tableau préservés).
#[must_use]
pub fn inject_json_path(body: &str, path: &str, payload: &str) -> Option<String> {
    inject_json_value(body, path, &Value::String(payload.to_owned()))
}

/// Remplace une feuille `JSON` par un opérateur arbitraire et resérialise.
///
/// Variante `NoSQL` de [`inject_json_path`] : la feuille scalaire
/// (`{"user":"admin"}`) devient un objet opérateur (`{"user":{"$gt":""}}`)
/// au lieu d'une chaîne. C'est le vecteur `{"user": {"$gt": ""}}` des logins
/// MongoDB : `$gt ""` est toujours vrai → bypass sans identifiants.
///
/// Mêmes règles de chemin que [`inject_json_path`] (pointeur `/a/0/b` ou
/// point/crochets `a.b[0]`, préfixe `json:` accepté). `None` si : corps
/// invalide, chemin vide/racine, clé/indice absent, traversée d'un scalaire,
/// ou cible déjà objet/tableau (préservés : on ne remplace jamais un
/// opérateur existant par un autre, pour éviter les faux positifs).
#[must_use]
pub fn inject_json_operator(
    body: &str,
    path: &str,
    operator: &serde_json::Value,
) -> Option<String> {
    inject_json_value(body, path, operator)
}

/// Cœur partagé de [`inject_json_path`] / [`inject_json_operator`].
fn inject_json_value(body: &str, path: &str, replacement: &Value) -> Option<String> {
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
    *slot = replacement.clone();
    serde_json::to_string(&value).ok()
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
