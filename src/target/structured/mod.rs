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

mod json;
mod kind;
#[cfg(test)]
mod tests;
mod xml;

pub use json::{inject_json_operator, inject_json_path, json_paths};
pub use kind::{MAX_JSON_DEPTH, MAX_STRUCTURED_PAIRS, StructuredKind, sniff_kind, split_name};
pub use xml::{inject_xml_tag, xml_tags};
