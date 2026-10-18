/// Nombre maximal de paires `(nom, valeur)` retournées par [`crate::target::structured::json_paths`]
/// et [`crate::target::structured::xml_tags`].
pub const MAX_STRUCTURED_PAIRS: usize = 500;

/// Profondeur `JSON` maximale explorée par [`crate::target::structured::json_paths`] (racine = 0).
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
/// Le `reste` s'injecte tel quel dans [`crate::target::structured::inject_json_path`]/[`crate::target::structured::inject_xml_tag`].
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
