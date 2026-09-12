#![deny(unsafe_code)]

use crate::{
    dbms::common::DbmsKind,
    detection::{baseline::Baseline, response_diff::adaptive_similarity},
    http::client::{HttpClient, RequestSpec},
    session::state::SessionState,
    target::{parameters::TargetParameter, raw_request::RawRequest, url::TargetUrl},
};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::{sync::Arc, sync::OnceLock, time::Instant};
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

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
            mysql: 0.25,
            postgres: 0.25,
            mssql: 0.25,
            oracle: 0.25,
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
            },
            "postgres" | "postgresql" | "pgsql" => Self {
                mysql: 0.0,
                postgres: 1.0,
                mssql: 0.0,
                oracle: 0.0,
            },
            "mssql" | "sqlserver" => Self {
                mysql: 0.0,
                postgres: 0.0,
                mssql: 1.0,
                oracle: 0.0,
            },
            "oracle" | "ora" => Self {
                mysql: 0.0,
                postgres: 0.0,
                mssql: 0.0,
                oracle: 1.0,
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
            }
            DbmsKind::Postgres => {
                self.postgres = conf;
                self.mysql = (self.mysql * rem).clamp(0.0, 1.0);
                self.mssql = (self.mssql * rem).clamp(0.0, 1.0);
                self.oracle = (self.oracle * rem).clamp(0.0, 1.0);
            }
            DbmsKind::MsSql => {
                self.mssql = conf;
                self.mysql = (self.mysql * rem).clamp(0.0, 1.0);
                self.postgres = (self.postgres * rem).clamp(0.0, 1.0);
                self.oracle = (self.oracle * rem).clamp(0.0, 1.0);
            }
            DbmsKind::Oracle => {
                self.oracle = conf;
                self.mysql = (self.mysql * rem).clamp(0.0, 1.0);
                self.postgres = (self.postgres * rem).clamp(0.0, 1.0);
                self.mssql = (self.mssql * rem).clamp(0.0, 1.0);
            }
            DbmsKind::Unknown => {}
        }
        self.normalize();
    }

    fn normalize(&mut self) {
        let sum = self.mysql + self.postgres + self.mssql + self.oracle;
        if sum > 0.0 {
            self.mysql /= sum;
            self.postgres /= sum;
            self.mssql /= sum;
            self.oracle /= sum;
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

/// Check response text against vendor SQL error signatures.
///
/// # Panics
/// Panics if an internal static error-pattern regex fails to compile (never happens in practice;
/// patterns are compile-time constants validated by unit tests).
#[allow(clippy::similar_names)]
#[must_use]
pub fn check_sql_errors(body: &str) -> Option<(DbmsKind, String)> {
    static MYSQL_ERR: OnceLock<Regex> = OnceLock::new();
    static PG_ERR: OnceLock<Regex> = OnceLock::new();
    static MSSQL_ERR: OnceLock<Regex> = OnceLock::new();
    static ORA_ERR: OnceLock<Regex> = OnceLock::new();

    let mysql_re = MYSQL_ERR.get_or_init(|| {
        #[allow(clippy::expect_used)]
        Regex::new(r"(?i)(you have an error in your sql syntax|check the manual that corresponds to your (mysql|mariadb) server version|mysql_fetch_|com\.mysql\.jdbc)").expect("mysql error regex")
    });
    let pg_re = PG_ERR.get_or_init(|| {
        #[allow(clippy::expect_used)]
        Regex::new(r"(?i)(syntax error at or near|unterminated quoted string|pg_query\(|psycopg2\.|org\.postgresql\.)").expect("pg error regex")
    });
    let mssql_re = MSSQL_ERR.get_or_init(|| {
        #[allow(clippy::expect_used)]
        Regex::new(r"(?i)(unclosed quotation mark after the character string|syntax error.*in query expression|microsoft ole db provider for sql server|\[microsoft\]\[odbc sql server driver\]|sqlexception)").expect("mssql error regex")
    });
    let ora_re = ORA_ERR.get_or_init(|| {
        #[allow(clippy::expect_used)]
        Regex::new(r"(?i)(ora-01756|ora-00933|ora-00936|quoted string not properly terminated|oracle error)").expect("oracle error regex")
    });

    if let Some(m) = mysql_re.find(body) {
        return Some((DbmsKind::MySql, m.as_str().to_owned()));
    }
    if let Some(m) = pg_re.find(body) {
        return Some((DbmsKind::Postgres, m.as_str().to_owned()));
    }
    if let Some(m) = mssql_re.find(body) {
        return Some((DbmsKind::MsSql, m.as_str().to_owned()));
    }
    if let Some(m) = ora_re.find(body) {
        return Some((DbmsKind::Oracle, m.as_str().to_owned()));
    }

    None
}

/// Passive inference from parameter name, value, and request content type (0 HTTP request).
#[must_use]
pub fn infer_passive_context(
    param: &TargetParameter,
    raw: Option<&RawRequest>,
) -> InjectionContext {
    let mut ctx = InjectionContext::new();

    // 1. JSON context
    if let Some(r) = raw {
        if r.headers
            .iter()
            .any(|(k, v)| k.eq_ignore_ascii_case("content-type") && v.contains("application/json"))
        {
            ctx.json = true;
        }
        if let Some(body) = &r.body {
            let trimmed = body.trim();
            if (trimmed.starts_with('{') && trimmed.ends_with('}'))
                || (trimmed.starts_with('[') && trimmed.ends_with(']'))
            {
                ctx.json = true;
            }
        }
    }

    // 2. Order by context from parameter name
    let name_l = param.name.to_ascii_lowercase();
    if name_l == "order"
        || name_l == "orderby"
        || name_l == "sort"
        || name_l == "sort_by"
        || name_l == "dir"
        || name_l == "direction"
        || name_l == "by"
    {
        ctx.order_by = true;
    }

    // 3. Numeric context hint from value
    let val_trimmed = param.original_value.trim();
    if !val_trimmed.is_empty() && val_trimmed.chars().all(|c| c.is_ascii_digit()) {
        ctx.numeric = true;
        ctx.quote = QuoteContext::None;
    }

    ctx
}

/// Executes adaptive context and fingerprinting probe (<=8 requests total).
///
/// If `dbms_hint` is provided, exactly 0 active DBMS probes are sent.
///
/// # Errors
/// Returns error if network client encounters unrecoverable failure.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub async fn analyze_context(
    client: &HttpClient,
    state: &Arc<RwLock<SessionState>>,
    cancel: &CancellationToken,
    target: &TargetUrl,
    param: &TargetParameter,
    raw: Option<&RawRequest>,
    baseline: &Baseline,
    dbms_hint: Option<&str>,
) -> ContextProbeResult {
    // 1. Start with passive signals (0 requests)
    let mut context = infer_passive_context(param, raw);
    let mut probes_sent = 0usize;
    let mut error_evidence = None;

    // 2. Initialise DBMS belief
    let mut dbms_belief = if let Some(hint) = dbms_hint {
        info!(
            hint,
            "adaptive context: DBMS pinned by --dbms hint (0 DBMS probe)"
        );
        DbmsBelief::from_hint(hint)
    } else {
        DbmsBelief::uniform()
    };

    if cancel.is_cancelled() {
        return ContextProbeResult {
            context,
            dbms_belief,
            probes_sent,
            error_evidence,
        };
    }

    // If explicit --dbms hint is given, VERROU: send 0 active DBMS probes.
    if dbms_hint.is_some() {
        let (top, _) = dbms_belief.top_candidate();
        context.comment = match top {
            DbmsKind::MySql => CommentStyle::Hash,
            _ => CommentStyle::DashDash,
        };
        return ContextProbeResult {
            context,
            dbms_belief,
            probes_sent,
            error_evidence,
        };
    }

    // Baseline response details
    let baseline_body = baseline.representative_body_str();

    // Probe 1: Benign single quote injection: `param_value'`
    let base_val = if param.original_value.is_empty() {
        "1"
    } else {
        &param.original_value
    };
    let single_quote_payload = format!("{base_val}'");

    if probes_sent < MAX_CONTEXT_PROBES && !cancel.is_cancelled() {
        let (body, _elapsed, status) = fetch_probe_simple(
            client,
            state,
            cancel,
            target,
            param,
            &single_quote_payload,
            raw,
        )
        .await;
        probes_sent = probes_sent.saturating_add(1);

        // Check for vendor error messages
        if let Some((kind, evidence)) = check_sql_errors(&body) {
            info!(%kind, %evidence, "context probe: detected vendor SQL error");
            dbms_belief.update_with_signal(kind, 0.98);
            context.quote = QuoteContext::SingleQuote;
            error_evidence = Some(evidence);

            context.comment = match kind {
                DbmsKind::MySql => CommentStyle::Hash,
                _ => CommentStyle::DashDash,
            };

            return ContextProbeResult {
                context,
                dbms_belief,
                probes_sent,
                error_evidence,
            };
        }

        // If status == 500 or significant difference from baseline, single quote broke query
        // Phase 0 : erreur transport (`status == 0`, body vide, non comptée
        // dans `fetch_probe_simple`) ne doit jamais valoir `quote_broke`.
        let sim = adaptive_similarity(&baseline_body, &body);
        let quote_broke = status != 0 && (status == 500 || sim < 0.65);

        if quote_broke && probes_sent < MAX_CONTEXT_PROBES && !cancel.is_cancelled() {
            // Probe 2: Try comment closure `param_value'-- ` to verify single-quote context
            let comment_closure_payload = format!("{base_val}'-- ");
            let (body_closure, _elapsed, status_closure) = fetch_probe_simple(
                client,
                state,
                cancel,
                target,
                param,
                &comment_closure_payload,
                raw,
            )
            .await;
            probes_sent = probes_sent.saturating_add(1);

            let sim_closure = adaptive_similarity(&baseline_body, &body_closure);
            if (status_closure == 200
                || status_closure == baseline.status_codes.first().copied().unwrap_or(200))
                && sim_closure > 0.80
            {
                debug!("context probe: comment closure restored baseline -> SingleQuote");
                context.quote = QuoteContext::SingleQuote;
                context.comment = CommentStyle::DashDash;
            }
        }
    }

    // Probe 3: If context is still not single quote and value is numeric, verify numeric context
    if context.quote != QuoteContext::SingleQuote
        && context.numeric
        && probes_sent < MAX_CONTEXT_PROBES
        && !cancel.is_cancelled()
    {
        let plus_zero = format!("{base_val}+0");
        let (body_zero, _elapsed, status_zero) =
            fetch_probe_simple(client, state, cancel, target, param, &plus_zero, raw).await;
        probes_sent = probes_sent.saturating_add(1);

        let sim_zero = adaptive_similarity(&baseline_body, &body_zero);
        if (status_zero == 200
            || status_zero == baseline.status_codes.first().copied().unwrap_or(200))
            && sim_zero > 0.85
            && probes_sent < MAX_CONTEXT_PROBES
            && !cancel.is_cancelled()
        {
            let plus_large = format!("{base_val}+999999");
            let (body_large, _elapsed, status_large) =
                fetch_probe_simple(client, state, cancel, target, param, &plus_large, raw).await;
            probes_sent = probes_sent.saturating_add(1);

            let sim_large = adaptive_similarity(&baseline_body, &body_large);
            // Phase 0 : erreur transport (status 0 / body vide) ne confirme
            // jamais le contexte numérique.
            if status_large != 0 && !body_large.is_empty() && sim_large < 0.70 {
                debug!("context probe: arithmetic confirmed numeric bare context");
                context.quote = QuoteContext::None;
                context.numeric = true;
            }
        }
    }

    // Probe 4: If still unknown, check double-quote context
    if context.quote == QuoteContext::Unknown
        && probes_sent < MAX_CONTEXT_PROBES
        && !cancel.is_cancelled()
    {
        let double_quote_payload = format!("{base_val}\"");
        let (body, _elapsed, status) = fetch_probe_simple(
            client,
            state,
            cancel,
            target,
            param,
            &double_quote_payload,
            raw,
        )
        .await;
        probes_sent = probes_sent.saturating_add(1);

        if let Some((kind, evidence)) = check_sql_errors(&body) {
            dbms_belief.update_with_signal(kind, 0.98);
            context.quote = QuoteContext::DoubleQuote;
            error_evidence = Some(evidence);
        } else {
            let sim = adaptive_similarity(&baseline_body, &body);
            // Phase 0 : même garde transport que probe 1.
            if status != 0
                && (status == 500 || sim < 0.65)
                && probes_sent < MAX_CONTEXT_PROBES
                && !cancel.is_cancelled()
            {
                let double_closure = format!("{base_val}\"-- ");
                let (body_closure, _elapsed, status_closure) =
                    fetch_probe_simple(client, state, cancel, target, param, &double_closure, raw)
                        .await;
                probes_sent = probes_sent.saturating_add(1);

                let sim_closure = adaptive_similarity(&baseline_body, &body_closure);
                if (status_closure == 200
                    || status_closure == baseline.status_codes.first().copied().unwrap_or(200))
                    && sim_closure > 0.80
                {
                    context.quote = QuoteContext::DoubleQuote;
                }
            }
        }
    }

    ContextProbeResult {
        context,
        dbms_belief,
        probes_sent,
        error_evidence,
    }
}

async fn fetch_probe_simple(
    client: &HttpClient,
    state: &Arc<RwLock<SessionState>>,
    cancel: &CancellationToken,
    target: &TargetUrl,
    param: &TargetParameter,
    payload: &str,
    raw: Option<&RawRequest>,
) -> (String, f64, u16) {
    let spec = build_spec_for_context(target, param, payload, raw);
    let start = Instant::now();
    let resp = client.send_with_retry(spec, cancel).await;
    let elapsed = start.elapsed().as_secs_f64() * 1000.0;

    match resp {
        Ok(r) => {
            let status = r.status().as_u16();
            match client.read_body_string_with_timeout(r).await {
                Ok(body) => {
                    // Succès transport : seule issue comptée. Un body vide
                    // légitime (200 vide) reste compté (similarité ~1.0 de
                    // toute façon) ; seules les erreurs transport (ci-dessous,
                    // body vide + status 0) ne sont pas comptées (Phase 0).
                    state.write().await.increment_requests();
                    (body, elapsed, status)
                }
                Err(e) => {
                    warn!(error=%e, "context probe body read failed");
                    (String::new(), elapsed, 0)
                }
            }
        }
        Err(e) => {
            warn!(error=%e, "context probe request failed");
            (String::new(), elapsed, 0)
        }
    }
}

#[allow(clippy::too_many_lines)]
fn build_spec_for_context(
    target: &TargetUrl,
    param: &TargetParameter,
    payload: &str,
    raw: Option<&RawRequest>,
) -> RequestSpec {
    use crate::target::parameters::ParameterLocation;
    use http::Method;

    match &param.location {
        ParameterLocation::Query => {
            let mut url = target.inner().clone();
            let mut pairs = Vec::new();
            let mut matched = false;
            for (k, v) in target.inner().query_pairs() {
                if k == param.name {
                    pairs.push((k.into_owned(), payload.to_owned()));
                    matched = true;
                } else {
                    pairs.push((k.into_owned(), v.into_owned()));
                }
            }
            if !matched {
                pairs.push((param.name.clone(), payload.to_owned()));
            }
            // Phase 0 bugfix (documenté) : l'ancienne concat `k=v` brute
            // n'encodait rien (`'`/`"`/espace/`+` passés crus, `+` décodé en
            // espace côté serveur → `1+0` devenait `1 0`). `query_pairs_mut`
            // (form_urlencoded) percent-encode (`'`→`%27`, `+`→`%2B`, …) ;
            // `query_pairs()` côté serveur décode à l'identique, L1
            // byte-identique sur payloads alphanumériques.
            {
                let mut qp = url.query_pairs_mut();
                qp.clear();
                for (k, v) in &pairs {
                    qp.append_pair(k, v);
                }
            }

            let mut headers = http::HeaderMap::new();
            if let Some(r) = raw {
                for (k, v) in &r.headers {
                    if let (Ok(name), Ok(val)) = (
                        http::HeaderName::from_bytes(k.as_bytes()),
                        http::HeaderValue::from_str(v),
                    ) {
                        headers.insert(name, val);
                    }
                }
            }
            let method = raw
                .and_then(|r| Method::from_bytes(r.method.as_bytes()).ok())
                .unwrap_or(Method::GET);
            let mut spec = RequestSpec::new(method, url.as_str().to_owned()).with_headers(headers);
            if let Some(body) = raw.and_then(|r| r.body.as_ref()) {
                spec = spec.with_body(body.as_bytes().to_vec());
            }
            spec
        }
        ParameterLocation::Body => {
            let mut headers = http::HeaderMap::new();
            if let Some(r) = raw {
                for (k, v) in &r.headers {
                    if let (Ok(name), Ok(val)) = (
                        http::HeaderName::from_bytes(k.as_bytes()),
                        http::HeaderValue::from_str(v),
                    ) {
                        headers.insert(name, val);
                    }
                }
            }
            let body_str = raw.and_then(|r| r.body.as_deref()).unwrap_or_default();
            let new_body = if body_str.contains(&format!("{}=", param.name)) {
                let mut parts = Vec::new();
                for pair in body_str.split('&') {
                    if let Some((k, _)) = pair.split_once('=') {
                        if k == param.name {
                            parts.push(format!("{k}={payload}"));
                        } else {
                            parts.push(pair.to_owned());
                        }
                    } else {
                        parts.push(pair.to_owned());
                    }
                }
                parts.join("&")
            } else if body_str.is_empty() {
                format!("{}={payload}", param.name)
            } else {
                format!("{body_str}&{}={payload}", param.name)
            };

            let method = raw
                .and_then(|r| Method::from_bytes(r.method.as_bytes()).ok())
                .unwrap_or(Method::POST);
            RequestSpec::new(method, target.as_str().to_owned())
                .with_headers(headers)
                .with_body(new_body.into_bytes())
        }
        ParameterLocation::Header(h) => {
            let mut headers = http::HeaderMap::new();
            if let Some(r) = raw {
                for (k, v) in &r.headers {
                    if let (Ok(name), Ok(val)) = (
                        http::HeaderName::from_bytes(k.as_bytes()),
                        http::HeaderValue::from_str(v),
                    ) {
                        headers.insert(name, val);
                    }
                }
            }
            if let (Ok(name), Ok(val)) = (
                http::HeaderName::from_bytes(h.as_bytes()),
                http::HeaderValue::from_str(payload),
            ) {
                headers.insert(name, val);
            }
            let method = raw
                .and_then(|r| Method::from_bytes(r.method.as_bytes()).ok())
                .unwrap_or(Method::GET);
            RequestSpec::new(method, target.as_str().to_owned()).with_headers(headers)
        }
        ParameterLocation::Cookie => {
            let mut headers = http::HeaderMap::new();
            let mut cookies: Vec<(String, String)> = Vec::new();
            if let Some(r) = raw {
                for (k, v) in &r.headers {
                    if k.eq_ignore_ascii_case("cookie") {
                        for part in v.split(';') {
                            if let Some((ck, cv)) = part.trim().split_once('=') {
                                cookies.push((ck.trim().to_owned(), cv.trim().to_owned()));
                            }
                        }
                    } else if let (Ok(name), Ok(val)) = (
                        http::HeaderName::from_bytes(k.as_bytes()),
                        http::HeaderValue::from_str(v),
                    ) {
                        headers.insert(name, val);
                    }
                }
            }
            let mut found = false;
            for (ck, cv) in &mut cookies {
                if ck == &param.name {
                    payload.clone_into(cv);
                    found = true;
                }
            }
            if !found {
                cookies.push((param.name.clone(), payload.to_owned()));
            }
            let cookie_val = cookies
                .into_iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("; ");
            if let Ok(val) = http::HeaderValue::from_str(&cookie_val) {
                headers.insert(http::header::COOKIE, val);
            }
            let method = raw
                .and_then(|r| Method::from_bytes(r.method.as_bytes()).ok())
                .unwrap_or(Method::GET);
            RequestSpec::new(method, target.as_str().to_owned()).with_headers(headers)
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::float_cmp)]
mod tests {
    use super::*;

    #[test]
    fn test_dbms_belief_from_hint() {
        let b = DbmsBelief::from_hint("mysql");
        assert_eq!(b.mysql, 1.0);
        assert_eq!(b.postgres, 0.0);
        assert_eq!(b.top_candidate().0, DbmsKind::MySql);

        let pg = DbmsBelief::from_hint("postgres");
        assert_eq!(pg.postgres, 1.0);
        assert_eq!(pg.mysql, 0.0);
        assert_eq!(pg.top_candidate().0, DbmsKind::Postgres);

        let mssql = DbmsBelief::from_hint("mssql");
        assert_eq!(mssql.mssql, 1.0);
        assert_eq!(mssql.top_candidate().0, DbmsKind::MsSql);

        let ora = DbmsBelief::from_hint("oracle");
        assert_eq!(ora.oracle, 1.0);
        assert_eq!(ora.top_candidate().0, DbmsKind::Oracle);
    }

    #[test]
    fn test_dbms_belief_uniform_and_update() {
        let mut b = DbmsBelief::uniform();
        assert_eq!(b.mysql, 0.25);
        assert_eq!(b.postgres, 0.25);

        b.update_with_signal(DbmsKind::Postgres, 0.9);
        assert!(b.postgres > 0.8);
        assert!(b.mysql < 0.1);
        assert_eq!(b.top_candidate().0, DbmsKind::Postgres);
    }

    #[test]
    fn test_check_sql_errors_mysql() {
        let err = "Error: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version at line 1";
        let res = check_sql_errors(err);
        assert!(res.is_some());
        let (kind, _) = res.unwrap_or((DbmsKind::Unknown, String::new()));
        assert_eq!(kind, DbmsKind::MySql);
    }

    #[test]
    fn test_check_sql_errors_postgres() {
        let err = "ERROR: syntax error at or near \"WHERE\" at character 42";
        let res = check_sql_errors(err);
        assert!(res.is_some());
        let (kind, _) = res.unwrap_or((DbmsKind::Unknown, String::new()));
        assert_eq!(kind, DbmsKind::Postgres);
    }

    #[test]
    fn test_check_sql_errors_mssql() {
        let err = "Microsoft OLE DB Provider for SQL Server: Unclosed quotation mark after the character string ''";
        let res = check_sql_errors(err);
        assert!(res.is_some());
        let (kind, _) = res.unwrap_or((DbmsKind::Unknown, String::new()));
        assert_eq!(kind, DbmsKind::MsSql);
    }

    #[test]
    fn test_check_sql_errors_oracle() {
        let err = "ORA-01756: quoted string not properly terminated";
        let res = check_sql_errors(err);
        assert!(res.is_some());
        let (kind, _) = res.unwrap_or((DbmsKind::Unknown, String::new()));
        assert_eq!(kind, DbmsKind::Oracle);
    }

    #[test]
    fn test_infer_passive_context() {
        use crate::target::parameters::ParameterLocation;

        let num_param = TargetParameter {
            name: "id".to_owned(),
            original_value: "42".to_owned(),
            location: ParameterLocation::Query,
        };
        let ctx = infer_passive_context(&num_param, None);
        assert!(ctx.numeric);
        assert_eq!(ctx.quote, QuoteContext::None);

        let sort_param = TargetParameter {
            name: "sort".to_owned(),
            original_value: "asc".to_owned(),
            location: ParameterLocation::Query,
        };
        let ctx_sort = infer_passive_context(&sort_param, None);
        assert!(ctx_sort.order_by);
    }

    #[test]
    fn test_top_candidate_tie_break_returns_unknown() {
        // Phase 0 : uniforme (ancien `max_by` → `oracle`, dernier max)
        // doit retourner `Unknown`.
        let uniform = DbmsBelief::uniform();
        let (kind, prob) = uniform.top_candidate();
        assert_eq!(kind, DbmsKind::Unknown);
        assert!((prob - 0.25).abs() < 1e-12);
        // Near-tie sous 1e-9 → Unknown.
        let near = DbmsBelief {
            mysql: 0.250_000_000_000_5,
            postgres: 0.25,
            mssql: 0.25,
            oracle: 0.25,
        };
        assert_eq!(near.top_candidate().0, DbmsKind::Unknown);
        // Top-2 ex æquo (mysql == postgres >> autres) → Unknown.
        let duel = DbmsBelief {
            mysql: 0.4,
            postgres: 0.4,
            mssql: 0.1,
            oracle: 0.1,
        };
        assert_eq!(duel.top_candidate().0, DbmsKind::Unknown);
        // Gagnant franc inchangé.
        let mut clear = DbmsBelief::uniform();
        clear.update_with_signal(DbmsKind::Postgres, 0.9);
        assert_eq!(clear.top_candidate().0, DbmsKind::Postgres);
    }

    #[test]
    fn test_build_spec_query_percent_encodes_payload() {
        use crate::target::{parameters::ParameterLocation, url::TargetUrl};
        let target = TargetUrl::parse("http://example.com/?id=1&other=a", true).unwrap();
        let param = TargetParameter {
            name: "id".to_owned(),
            original_value: "1".to_owned(),
            location: ParameterLocation::Query,
        };
        for payload in ["1'", "1\"-- ", "1+0", "1+999999", "a b&c=d"] {
            let spec = build_spec_for_context(&target, &param, payload, None);
            // Roundtrip : le serveur décode à l'identique.
            let parsed = url::Url::parse(&spec.url).unwrap();
            let decoded = parsed
                .query_pairs()
                .find(|(k, _)| k == "id")
                .map(|(_, v)| v.into_owned())
                .unwrap_or_default();
            assert_eq!(decoded, payload, "roundtrip {payload}");
            // Caractères à risque encodés dans l'URL brute.
            if payload.contains('\'') {
                assert!(spec.url.contains("%27"), "quote encodée: {}", spec.url);
            }
            if payload.contains('+') {
                assert!(spec.url.contains("%2B"), "plus encodé: {}", spec.url);
            }
        }
    }
}
