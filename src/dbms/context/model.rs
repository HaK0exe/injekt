use crate::dbms::common::DbmsKind;
use serde::{Deserialize, Serialize};

/// Maximum total requests allowed for context and fingerprint probing (C2 invariant: <=8 req p95).
pub const MAX_CONTEXT_PROBES: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub enum QuoteContext {
    #[default]
    Unknown,
    /// Unquoted / numeric context (e.g. `WHERE id = 1`).
    None,
    /// Single quoted string literal (e.g. `WHERE name = 'admin'`).
    SingleQuote,
    /// Double quoted string literal or identifier (e.g. `WHERE name = "admin"`).
    DoubleQuote,
    /// Parenthesized expression (e.g. `WHERE (id = 1)`).
    Parenthesis,
}

impl std::fmt::Display for QuoteContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown => write!(f, "unknown"),
            Self::None => write!(f, "none (numeric/bare)"),
            Self::SingleQuote => write!(f, "single-quote (')"),
            Self::DoubleQuote => write!(f, "double-quote (\")"),
            Self::Parenthesis => write!(f, "parenthesis (())"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub enum CommentStyle {
    #[default]
    /// Standard SQL comment (`-- `).
    DashDash,
    /// Hash comment (`#`, MySQL).
    Hash,
    /// C-style comment block (`/* ... */`).
    SlashStar,
    /// Semicolon followed by comment (`;--`, MSSQL stacked).
    SemiDashDash,
}

impl std::fmt::Display for CommentStyle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DashDash => write!(f, "-- "),
            Self::Hash => write!(f, "#"),
            Self::SlashStar => write!(f, "/* */"),
            Self::SemiDashDash => write!(f, ";--"),
        }
    }
}

/// Inferred SQL injection context for a target parameter.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub struct InjectionContext {
    pub quote: QuoteContext,
    pub numeric: bool,
    pub json: bool,
    pub order_by: bool,
    pub comment: CommentStyle,
}

impl InjectionContext {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            quote: QuoteContext::Unknown,
            numeric: false,
            json: false,
            order_by: false,
            comment: CommentStyle::DashDash,
        }
    }

    /// Returns a short human-readable summary of the inferred context.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "quote={}, numeric={}, json={}, order_by={}, comment={}",
            self.quote, self.numeric, self.json, self.order_by, self.comment
        )
    }
}

/// Probability distribution / belief over supported DBMS engines.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct DbmsBelief {
    pub mysql: f64,
    pub postgres: f64,
    pub mssql: f64,
    pub oracle: f64,
    pub sqlite: f64,
}

impl Default for DbmsBelief {
    fn default() -> Self {
        Self::uniform()
    }
}

impl DbmsBelief {
    #[must_use]
    pub const fn uniform() -> Self {
        Self {
            mysql: 0.20,
            postgres: 0.20,
            mssql: 0.20,
            oracle: 0.20,
            sqlite: 0.20,
        }
    }

    /// Pinned belief from an explicit `--dbms` hint (0 active probe sent).
    #[must_use]
    pub fn from_hint(hint: &str) -> Self {
        let lower = hint.trim().to_ascii_lowercase();
        match lower.as_str() {
            "mysql" | "mariadb" => Self {
                mysql: 1.0,
                postgres: 0.0,
                mssql: 0.0,
                oracle: 0.0,
                sqlite: 0.0,
            },
            "postgres" | "postgresql" | "pgsql" => Self {
                mysql: 0.0,
                postgres: 1.0,
                mssql: 0.0,
                oracle: 0.0,
                sqlite: 0.0,
            },
            "mssql" | "sqlserver" => Self {
                mysql: 0.0,
                postgres: 0.0,
                mssql: 1.0,
                oracle: 0.0,
                sqlite: 0.0,
            },
            "oracle" | "ora" => Self {
                mysql: 0.0,
                postgres: 0.0,
                mssql: 0.0,
                oracle: 1.0,
                sqlite: 0.0,
            },
            "sqlite" | "sqlite3" => Self {
                mysql: 0.0,
                postgres: 0.0,
                mssql: 0.0,
                oracle: 0.0,
                sqlite: 1.0,
            },
            _ => Self::uniform(),
        }
    }

    #[must_use]
    pub fn top_candidate(&self) -> (DbmsKind, f64) {
        let candidates = [
            (DbmsKind::MySql, self.mysql),
            (DbmsKind::Postgres, self.postgres),
            (DbmsKind::MsSql, self.mssql),
            (DbmsKind::Oracle, self.oracle),
            (DbmsKind::Sqlite, self.sqlite),
        ];
        // Phase 0 bugfix (documenté) : l'ancien `max_by` retournait le
        // *dernier* max en cas d'égalité (`oracle` sur belief uniforme),
        // biaisant `compute_calibrated_prior` (+15% si prob > 0.8 est faux
        // ici) et le `fill_missing_dbms` précoce. Tie-break explicite :
        // `max - min < 1e-9` (uniforme) ou top-2 à `< 1e-9` → `Unknown`.
        // L1 par défaut inchangé hors égalité (seuil sous le bruit de
        // `normalize()`).
        let mut max = f64::NEG_INFINITY;
        let mut min = f64::INFINITY;
        for (_, p) in &candidates {
            let v = if p.is_finite() { *p } else { 0.0 };
            if v > max {
                max = v;
            }
            if v < min {
                min = v;
            }
        }
        if !max.is_finite() || !min.is_finite() {
            return (DbmsKind::Unknown, 0.0);
        }
        if (max - min).abs() < 1e-9 {
            return (DbmsKind::Unknown, max);
        }
        let mut best_kind = DbmsKind::Unknown;
        let mut best = f64::NEG_INFINITY;
        let mut second = f64::NEG_INFINITY;
        for (kind, prob) in candidates {
            let p = if prob.is_finite() { prob } else { 0.0 };
            if p > best {
                second = best;
                best = p;
                best_kind = kind;
            } else if p > second {
                second = p;
            }
        }
        if (best - second).abs() < 1e-9 {
            return (DbmsKind::Unknown, best);
        }
        (best_kind, best)
    }

    pub fn update_with_signal(&mut self, kind: DbmsKind, confidence: f64) {
        let conf = confidence.clamp(0.0, 1.0);
        let rem = (1.0 - conf).max(0.0);
        match kind {
            DbmsKind::MySql => {
                self.mysql = conf;
                self.postgres = (self.postgres * rem).clamp(0.0, 1.0);
                self.mssql = (self.mssql * rem).clamp(0.0, 1.0);
                self.oracle = (self.oracle * rem).clamp(0.0, 1.0);
                self.sqlite = (self.sqlite * rem).clamp(0.0, 1.0);
            }
            DbmsKind::Postgres => {
                self.postgres = conf;
                self.mysql = (self.mysql * rem).clamp(0.0, 1.0);
                self.mssql = (self.mssql * rem).clamp(0.0, 1.0);
                self.oracle = (self.oracle * rem).clamp(0.0, 1.0);
                self.sqlite = (self.sqlite * rem).clamp(0.0, 1.0);
            }
            DbmsKind::MsSql => {
                self.mssql = conf;
                self.mysql = (self.mysql * rem).clamp(0.0, 1.0);
                self.postgres = (self.postgres * rem).clamp(0.0, 1.0);
                self.oracle = (self.oracle * rem).clamp(0.0, 1.0);
                self.sqlite = (self.sqlite * rem).clamp(0.0, 1.0);
            }
            DbmsKind::Oracle => {
                self.oracle = conf;
                self.mysql = (self.mysql * rem).clamp(0.0, 1.0);
                self.postgres = (self.postgres * rem).clamp(0.0, 1.0);
                self.mssql = (self.mssql * rem).clamp(0.0, 1.0);
                self.sqlite = (self.sqlite * rem).clamp(0.0, 1.0);
            }
            DbmsKind::Sqlite => {
                self.sqlite = conf;
                self.mysql = (self.mysql * rem).clamp(0.0, 1.0);
                self.postgres = (self.postgres * rem).clamp(0.0, 1.0);
                self.mssql = (self.mssql * rem).clamp(0.0, 1.0);
                self.oracle = (self.oracle * rem).clamp(0.0, 1.0);
            }
            DbmsKind::Unknown => {}
        }
        self.normalize();
    }

    fn normalize(&mut self) {
        let sum = self.mysql + self.postgres + self.mssql + self.oracle + self.sqlite;
        if sum > 0.0 {
            self.mysql /= sum;
            self.postgres /= sum;
            self.mssql /= sum;
            self.oracle /= sum;
            self.sqlite /= sum;
        } else {
            *self = Self::uniform();
        }
    }

    #[must_use]
    pub fn probability_of(&self, kind: DbmsKind) -> f64 {
        match kind {
            DbmsKind::MySql => self.mysql,
            DbmsKind::Postgres => self.postgres,
            DbmsKind::MsSql => self.mssql,
            DbmsKind::Oracle => self.oracle,
            DbmsKind::Sqlite => self.sqlite,
            DbmsKind::Unknown => 0.0,
        }
    }
}

/// Result of the adaptive context and fingerprint analysis.
#[derive(Debug, Clone)]
pub struct ContextProbeResult {
    pub context: InjectionContext,
    pub dbms_belief: DbmsBelief,
    pub probes_sent: usize,
    pub error_evidence: Option<String>,
}
