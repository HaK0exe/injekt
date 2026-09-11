#![deny(unsafe_code)]

use crate::{
    http::client::{HttpClient, RequestSpec},
    recon::{
        filters::{
            candidate_template_key, is_in_scope, is_internal_crawl_path, is_placeholder_value,
            is_templated_token, normalize_page_url, page_template_key, should_skip_candidate,
            should_skip_crawl_url,
        },
        parameter::{CandidateMethod, FormContext, ParamType, ParameterCandidate},
    },
    target::{parameters::ParameterLocation, url::TargetUrl},
};
use regex::Regex;
use scraper::{ElementRef, Html, Selector};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    sync::OnceLock,
    time::Duration,
};
use tokio_util::sync::CancellationToken;
use url::Url;

#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)]
pub struct CrawlConfig {
    pub depth: usize,
    pub max_pages: usize,
    /// Cap on how many pages sharing the same [`page_template_key`] are
    /// fetched — guards against pagination/listing/calendar traps burning
    /// the whole `max_pages` budget on redundant instances of one page shape.
    pub max_per_template: usize,
    /// Cap on redundant candidate instances sharing one sink shape
    /// ([`candidate_template_key`]) and on the total candidate list
    /// (`max_candidates`): listing/gallery/proxy endpoints otherwise queue
    /// hundreds of near-identical params that burn scan budget.
    pub max_candidates: usize,
    pub include_subdomains: bool,
    pub respect_robots: bool,
    pub allow_private: bool,
    /// Skip local DNS-time SSRF resolution (proxy resolves remotely, e.g.
    /// `socks5h://`). Lexical + IP-literal checks still apply.
    pub remote_dns: bool,
}

impl Default for CrawlConfig {
    fn default() -> Self {
        Self {
            depth: 2,
            max_pages: 100,
            max_per_template: 3,
            max_candidates: 500,
            include_subdomains: false,
            respect_robots: true,
            allow_private: false,
            remote_dns: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrawlReport {
    pub target: Url,
    pub pages_visited: usize,
    pub candidates: Vec<ParameterCandidate>,
    pub warnings: Vec<String>,
}

impl CrawlReport {
    /// Scrubbed clone for CLI / MCP output (candidate URLs may carry tokens).
    #[must_use]
    pub fn scrubbed(&self, scrubber: &crate::session::scrubber::Scrubber) -> Self {
        let target = scrubber
            .scrub(self.target.as_str())
            .parse()
            .unwrap_or_else(|_| self.target.clone());
        Self {
            target,
            pages_visited: self.pages_visited,
            candidates: self
                .candidates
                .iter()
                .map(|c| c.scrubbed(scrubber))
                .collect(),
            warnings: self.warnings.iter().map(|w| scrubber.scrub(w)).collect(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Crawler {
    client: HttpClient,
    config: CrawlConfig,
}

impl Crawler {
    #[must_use]
    pub fn new(client: HttpClient, config: CrawlConfig) -> Self {
        Self { client, config }
    }

    /// # Errors
    /// Returns an error if the target URL fails to parse or a network request fails.
    #[allow(clippy::too_many_lines)]
    pub async fn crawl(
        &self,
        target: &str,
        cancel: &CancellationToken,
    ) -> anyhow::Result<CrawlReport> {
        let started = std::time::Instant::now();
        let root =
            parse_target_with_remote_dns(target, self.config.allow_private, self.config.remote_dns)
                .await?;
        tracing::info!(
            "starting crawl at '{root}' (depth: {}, max pages: {})",
            self.config.depth,
            self.config.max_pages
        );
        let robots = if self.config.respect_robots {
            self.load_robots_logged(&root, cancel).await
        } else {
            RobotsRules::default()
        };
        // `Crawl-delay` from robots.txt is honoured as a minimum per-fetch
        // delay (in addition to the client's rate limiter / jitter).
        let crawl_delay = robots.crawl_delay;
        if let Some(d) = crawl_delay {
            tracing::info!(delay=?d, "robots.txt crawl-delay active");
        }
        let mut queue = VecDeque::from([(root.clone(), 0usize)]);
        let mut queued = HashSet::from([normalize_page_url(root.clone()).to_string()]);
        let mut visited = HashSet::new();
        let mut template_counts: HashMap<String, usize> = HashMap::new();
        let mut capped_templates = HashSet::new();
        let mut candidate_keys = HashSet::new();
        let mut candidate_template_counts: HashMap<String, usize> = HashMap::new();
        let mut candidates = Vec::new();
        let mut warnings = Vec::new();
        let mut dropped_placeholder = 0usize;
        let mut dropped_template_cap = 0usize;
        let mut dropped_noise = 0usize;
        let mut dropped_over_cap = 0usize;

        while let Some((page_url, depth)) = queue.pop_front() {
            if cancel.is_cancelled() || visited.len() >= self.config.max_pages {
                break;
            }
            if !robots.allows(page_url.path()) {
                continue;
            }
            let page_key = normalize_page_url(page_url.clone()).to_string();
            if visited.contains(&page_key) {
                continue;
            }
            // Cap instances of the same page shape (path pattern + query
            // param names) before committing this page as visited, so
            // pagination/listing/calendar traps can't burn the whole
            // max_pages budget on redundant variants of one template.
            let template_key = page_template_key(&page_url);
            let template_count = template_counts.entry(template_key.clone()).or_insert(0);
            if *template_count >= self.config.max_per_template {
                if capped_templates.insert(template_key.clone()) {
                    tracing::info!(
                        "template '{template_key}' reached --max-per-template ({}), skipping further instances",
                        self.config.max_per_template
                    );
                }
                continue;
            }
            *template_count += 1;
            visited.insert(page_key);
            // Honour robots `Crawl-delay` (parsed in `RobotsRules`): minimum
            // delay between page fetches, cancellable via Ctrl+C.
            if let Some(delay) = crawl_delay {
                tokio::select! {
                    () = cancel.cancelled() => break,
                    () = tokio::time::sleep(delay) => {},
                }
            }
            let response = self
                .client
                .send_with_retry(RequestSpec::get(page_url.to_string()), cancel)
                .await;
            let response = match response {
                Ok(response) => response,
                Err(error) => {
                    tracing::warn!("{page_url}: {error}");
                    warnings.push(format!("{page_url}: {error}"));
                    continue;
                }
            };
            if !response.status().is_success() {
                tracing::warn!("{}: HTTP {}", page_url, response.status());
                warnings.push(format!("{}: HTTP {}", page_url, response.status()));
                continue;
            }
            let is_html = response
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .is_none_or(|value| value.contains("html") || value.starts_with("text/"));
            if !is_html {
                continue;
            }
            // Bounded body read with cancellation: unbounded `text()` can hang
            // on slow/incomplete responses and Ctrl+C must abort the wait.
            let body = tokio::select! {
                () = cancel.cancelled() => {
                    tracing::debug!("{page_url}: crawl cancelled during body read");
                    continue;
                }
                body = self.client.read_body_string_with_timeout(response) => match body {
                    Ok(body) => body,
                    Err(error) => {
                        tracing::warn!("{page_url}: body read failed: {error}");
                        warnings.push(format!("{page_url}: body read failed: {error}"));
                        continue;
                    }
                },
            };
            let extracted = extract_document(&page_url, &body);
            let mut found_here = 0usize;
            for candidate in extracted.candidates {
                if !is_in_scope(&root, &candidate.url, self.config.include_subdomains)
                    || TargetUrl::parse(candidate.url.as_str(), self.config.allow_private).is_err()
                    || !robots.allows(candidate.url.path())
                {
                    continue;
                }
                if should_skip_candidate(&candidate.url, &candidate.param_name, candidate.method) {
                    dropped_noise += 1;
                    continue;
                }
                // Templated values (`{...}`, backslash-only artefacts) are
                // template placeholders, not injectable inputs.
                if is_placeholder_value(&candidate.original_value) {
                    dropped_placeholder += 1;
                    continue;
                }
                if !candidate_keys.insert(candidate.dedup_key()) {
                    continue;
                }
                // Same sink shape (host + path pattern + param) with different
                // instance data: keep the first few, drop the rest so one
                // listing/gallery/proxy family can't flood the scan budget.
                let sink_key = candidate_template_key(&candidate.url, &candidate.param_name);
                let sink_count = candidate_template_counts.entry(sink_key).or_insert(0);
                if *sink_count >= self.config.max_per_template {
                    dropped_template_cap += 1;
                    continue;
                }
                *sink_count += 1;
                if candidates.len() >= self.config.max_candidates {
                    dropped_over_cap += 1;
                    continue;
                }
                candidates.push(candidate);
                found_here += 1;
            }
            if found_here > 0 {
                tracing::info!(
                    "[{}/{}] {page_url} ({found_here} parameter{} found)",
                    visited.len(),
                    self.config.max_pages,
                    if found_here == 1 { "" } else { "s" }
                );
            } else {
                tracing::debug!(
                    "[{}/{}] {page_url} (no parameters)",
                    visited.len(),
                    self.config.max_pages
                );
            }
            if depth < self.config.depth {
                for link in extracted.links {
                    if is_in_scope(&root, &link, self.config.include_subdomains)
                        && TargetUrl::parse(link.as_str(), self.config.allow_private).is_ok()
                        && robots.allows(link.path())
                        && !should_skip_crawl_url(&link)
                    {
                        let key = normalize_page_url(link.clone()).to_string();
                        if queued.insert(key) {
                            queue.push_back((link, depth + 1));
                        }
                    }
                }
            }
        }

        candidates.sort_by_key(ParameterCandidate::dedup_key);
        tracing::info!(
            "crawl finished: {} page(s) visited, {} parameter(s) kept ({} placeholder, {} noise, {} template-capped, {} over --max-candidates {}) in {:.2}s",
            visited.len(),
            candidates.len(),
            dropped_placeholder,
            dropped_noise,
            dropped_template_cap,
            dropped_over_cap,
            self.config.max_candidates,
            started.elapsed().as_secs_f64()
        );
        Ok(CrawlReport {
            target: root,
            pages_visited: visited.len(),
            candidates,
            warnings,
        })
    }

    async fn load_robots_logged(&self, root: &Url, cancel: &CancellationToken) -> RobotsRules {
        let rules = self.load_robots(root, cancel).await;
        if rules.disallow.is_empty() && rules.allow.is_empty() {
            tracing::info!("no robots.txt restrictions found");
        } else {
            tracing::info!(
                "parsed robots.txt ({} disallow, {} allow rule(s))",
                rules.disallow.len(),
                rules.allow.len()
            );
        }
        rules
    }

    async fn load_robots(&self, root: &Url, cancel: &CancellationToken) -> RobotsRules {
        let mut robots_url = root.clone();
        robots_url.set_path("/robots.txt");
        robots_url.set_query(None);
        robots_url.set_fragment(None);
        let request = RequestSpec::get(robots_url.to_string());
        match self.client.send_with_retry(request, cancel).await {
            Ok(response) if response.status().is_success() => {
                // Bounded + cancellable like page bodies; failure falls back
                // to default (no restrictions), never an error.
                let body = tokio::select! {
                    () = cancel.cancelled() => return RobotsRules::default(),
                    body = self.client.read_body_string_with_timeout(response) => body.ok(),
                };
                body.map_or_else(RobotsRules::default, |b| RobotsRules::parse(&b))
            }
            _ => RobotsRules::default(),
        }
    }
}

#[allow(dead_code)]
async fn parse_target(target: &str, allow_private: bool) -> anyhow::Result<Url> {
    parse_target_with_remote_dns(target, allow_private, false).await
}

async fn parse_target_with_remote_dns(
    target: &str,
    allow_private: bool,
    remote_dns: bool,
) -> anyhow::Result<Url> {
    let with_scheme = if target.contains("://") {
        target.to_owned()
    } else {
        format!("https://{target}")
    };
    // Lexical (+ DNS-time unless the proxy resolves remotely) SSRF check;
    // per-link filtering in the crawl loop stays lexical-only for speed,
    // enforcement happens per-fetch inside `HttpClient::send_with_retry`.
    let parsed = TargetUrl::validate_redirect_location_with_remote_dns(
        &with_scheme,
        allow_private,
        remote_dns,
    )
    .await
    .map_err(|error| anyhow::anyhow!("invalid recon target: {error}"))?;
    Ok(parsed.inner().clone())
}

#[derive(Debug, Default)]
struct ExtractedDocument {
    links: Vec<Url>,
    candidates: Vec<ParameterCandidate>,
}

fn extract_document(base: &Url, body: &str) -> ExtractedDocument {
    let document = Html::parse_document(body);
    let mut out = ExtractedDocument::default();
    let anchor_selector = selector("a[href]");
    for anchor in document.select(&anchor_selector) {
        if let Some(url) = resolve_attr(base, &anchor, "href") {
            add_link_candidates(&mut out, url, ParamType::Link);
        }
    }

    let form_selector = selector("form");
    let field_selector = selector("input[name], select[name], textarea[name]");
    for form in document.select(&form_selector) {
        let action = form
            .value()
            .attr("action")
            .and_then(|action| base.join(action).ok())
            .unwrap_or_else(|| base.clone());
        let method = if form
            .value()
            .attr("method")
            .is_some_and(|method| method.eq_ignore_ascii_case("post"))
        {
            CandidateMethod::Post
        } else {
            CandidateMethod::Get
        };
        let mut fields = BTreeMap::new();
        let mut typed_fields = Vec::new();
        for field in form.select(&field_selector) {
            let Some(name) = field.value().attr("name") else {
                continue;
            };
            if name.is_empty() || field.value().attr("disabled").is_some() {
                continue;
            }
            let value = field_value(&field);
            fields.insert(name.to_owned(), value.clone());
            typed_fields.push((name.to_owned(), value, field_type(&field)));
        }
        let mut target_url = action;
        if method == CandidateMethod::Get {
            let mut query = target_url.query_pairs_mut();
            for (name, value) in &fields {
                query.append_pair(name, value);
            }
        }
        if method == CandidateMethod::Get {
            out.links.push(target_url.clone());
        }
        for (name, value, param_type) in typed_fields {
            out.candidates.push(ParameterCandidate {
                url: target_url.clone(),
                method,
                param_name: name,
                location: if method == CandidateMethod::Get {
                    ParameterLocation::Query
                } else {
                    ParameterLocation::Body
                },
                param_type,
                original_value: value,
                form_context: Some(FormContext {
                    source_url: base.clone(),
                    fields: fields.clone(),
                }),
            });
        }
    }

    if let Some(js_endpoint) = js_endpoint_regex() {
        for captures in js_endpoint.captures_iter(body) {
            if let Some(raw) = captures.get(1) {
                let decoded = decode_embedded_url(raw.as_str());
                if let Ok(url) = base.join(&decoded) {
                    add_link_candidates(&mut out, url, ParamType::Javascript);
                }
            }
        }
    }
    out
}

/// Decode URLs embedded in HTML/JS/JSON before `Url::join`.
///
/// JS-embedded endpoints frequently carry HTML-escaped (`&amp;`) or
/// JSON-escaped (`\u0026`) separators (Next.js `__NEXT_DATA__`, inline
/// `<script>`). Without decoding, `?title=a&amp;desc=b` parses as a single
/// `amp;desc` param and `?a=1\u0026b=2` as one garbled value — both yield
/// `1/1` single-param scans and wasted probes.
///
/// Order matters (same as `matcher::strip_html`): `\uXXXX` + `\/` first,
/// then `&lt;/&gt;/&quot;/&#x27;/&#39;`, `&amp;` last to avoid turning
/// `&amp;lt;` into `<`.
///
/// Double-escaping is common (HTML-escaped JSON inside HTML, JS string
/// literals built from already-escaped data), so both phases run to a
/// bounded fixed point (max 3 passes):
/// - JS escapes: `\\u0026` (source-level) collapses to `\u0026` on pass 1
///   and to `&` on pass 2. Trade-off: a literal backslash that is genuinely
///   part of a query value (vanishingly rare — WHATWG parsers treat `\` as
///   `/` on `http(s)` URLs anyway) may be over-decoded; structural
///   correctness of the extracted URL wins for a scanner.
/// - HTML entities run one full pass (pinning `&amp;lt;` to `&lt;`, never
///   `<`), then only `&amp;` is repeated: it is the query separator, so a
///   remnant corrupts param splitting (`amp;`-prefixed names), while other
///   entities only affect values.
///
/// A trailing `\` run left by an escaped closing quote (`"...en\\"`) is
/// stripped: it is a JS-string artefact, never a meaningful URL suffix.
#[must_use]
fn decode_embedded_url(raw: &str) -> String {
    let mut current = raw.to_owned();
    for _ in 0..3 {
        let next = decode_js_string_escapes(&current);
        if next == current {
            break;
        }
        current = next;
    }
    let mut decoded = decode_html_entities_once(&current);
    for _ in 0..3 {
        if !decoded.contains("&amp;") {
            break;
        }
        let next = decoded.replace("&amp;", "&");
        if next == decoded {
            break;
        }
        decoded = next;
    }
    decoded.trim_end_matches('\\').to_owned()
}

/// Single HTML-entity pass for embedded URLs: `&lt;/&gt;/&quot;/&#x27;/&#39;`
/// first, `&amp;` last so `&amp;lt;` decodes to `&lt;`, never `<`.
fn decode_html_entities_once(raw: &str) -> String {
    raw.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#x27;", "'")
        .replace("&#X27;", "'")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

/// Minimal JS string unescape: `\uXXXX`, `\/`, `\\`, `\"`, `\'`, plus
/// `\n`/`\r`/`\t`. Unknown escapes are kept verbatim; lone `\u` without 4
/// hex digits is kept. Char-based (never byte-indexes `&str`) so multibyte
/// UTF-8 survives intact.
fn decode_js_string_escapes(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        let Some(next) = chars.next() else {
            out.push('\\');
            break;
        };
        match next {
            'u' => {
                let hex: String = chars.by_ref().take(4).collect();
                if hex.len() == 4
                    && let Ok(code) = u32::from_str_radix(&hex, 16)
                {
                    if let Some(ch) = char::from_u32(code) {
                        out.push(ch);
                    } else {
                        out.push_str("\\u");
                        out.push_str(&hex);
                    }
                } else {
                    out.push_str("\\u");
                    out.push_str(&hex);
                }
            }
            'n' => out.push('\n'),
            'r' => out.push('\r'),
            't' => out.push('\t'),
            '/' => out.push('/'),
            '\\' | '"' | '\'' => out.push(next),
            _ => {
                out.push('\\');
                out.push(next);
            }
        }
    }
    out
}

fn add_link_candidates(out: &mut ExtractedDocument, mut url: Url, param_type: ParamType) {
    // Cloudflare/internal endpoints are never SQLi-testable and never worth
    // a crawl fetch (`/cdn-cgi/...`, `/_next/...` build artefacts).
    if is_internal_crawl_path(&url) {
        return;
    }
    url.set_fragment(None);
    // Collect pairs first: `query_pairs` borrows `url` while we also push.
    let pairs: Vec<(String, String)> = url
        .query_pairs()
        .map(|(n, v)| (n.into_owned(), v.into_owned()))
        .collect();
    for (name, value) in pairs {
        // OpenSearch-style placeholders (`q={search_term_string}`, decoded
        // from `%7B...%7D` by `query_pairs`) are templates, not values.
        // `is_placeholder_value` additionally drops JS-string artefacts
        // (backslash-only values); genuinely empty values stay testable.
        if is_templated_token(&name) || is_placeholder_value(&value) {
            continue;
        }
        // Drop Elementor-style `post-*.css?ver=3.8.0` noise at the source:
        // static asset + cache-busting param is never SQLi-testable.
        if should_skip_candidate(&url, &name, CandidateMethod::Get) {
            continue;
        }
        out.candidates.push(ParameterCandidate {
            url: url.clone(),
            method: CandidateMethod::Get,
            param_name: name,
            location: ParameterLocation::Query,
            param_type,
            original_value: value,
            form_context: None,
        });
    }
    if !should_skip_crawl_url(&url) {
        out.links.push(url);
    }
}

fn selector(value: &str) -> Selector {
    Selector::parse(value).unwrap_or_else(|_| unreachable!("static selector is valid"))
}

/// JS endpoint pattern compiled once (was `Regex::new` per crawled page).
/// Escape-aware: `(?:\\.|[^\"'])*` lets an escaped quote (`\"`, `\'`) or an
/// escaped backslash (`\\`) live inside the URL instead of cutting the match
/// and leaving a trailing `\` artefact in the candidate.
fn js_endpoint_regex() -> Option<&'static Regex> {
    static CELL: OnceLock<Option<Regex>> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(
            r#"[\"']((?:https?://(?:\\.|[^\"'])+|/(?:\\.|[^\"'])+)[?&][A-Za-z_][A-Za-z0-9_.-]*=(?:\\.|[^\"'])*)[\"']"#,
        )
        .ok()
    })
    .as_ref()
}

fn resolve_attr(base: &Url, element: &ElementRef<'_>, attr: &str) -> Option<Url> {
    let value = element.value().attr(attr)?;
    if value.starts_with('#') || value.starts_with("javascript:") || value.starts_with("mailto:") {
        return None;
    }
    // `scraper` already decodes most entities, but JS-injected `href`s and
    // double-escaped payloads can still carry `&amp;`/`\u0026`: decoding here
    // is idempotent (single-decode, `&amp;` last).
    let decoded = decode_embedded_url(value);
    base.join(&decoded).ok().map(normalize_page_url)
}

fn field_value(field: &ElementRef<'_>) -> String {
    if field.value().name() == "select" {
        let option_selector = selector("option[selected], option");
        return field
            .select(&option_selector)
            .next()
            .and_then(|option| option.value().attr("value"))
            .unwrap_or_default()
            .to_owned();
    }
    if field.value().name() == "textarea" {
        return field.text().collect::<String>();
    }
    field.value().attr("value").unwrap_or_default().to_owned()
}

fn field_type(field: &ElementRef<'_>) -> ParamType {
    match field.value().name() {
        "select" => ParamType::Select,
        "textarea" => ParamType::Textarea,
        _ if field
            .value()
            .attr("type")
            .is_some_and(|kind| kind.eq_ignore_ascii_case("hidden")) =>
        {
            ParamType::Hidden
        }
        _ => ParamType::Input,
    }
}

#[derive(Debug, Default)]
struct RobotsRules {
    disallow: Vec<String>,
    allow: Vec<String>,
    crawl_delay: Option<Duration>,
}

impl RobotsRules {
    fn parse(body: &str) -> Self {
        let mut rules = Self::default();
        let mut applies = false;
        for raw_line in body.lines() {
            let line = raw_line.split('#').next().unwrap_or_default().trim();
            let Some((name, value)) = line.split_once(':') else {
                continue;
            };
            let name = name.trim();
            let value = value.trim();
            if name.eq_ignore_ascii_case("user-agent") {
                applies = value == "*" || value.eq_ignore_ascii_case("injekt");
            } else if applies && name.eq_ignore_ascii_case("disallow") && !value.is_empty() {
                rules.disallow.push(value.to_owned());
            } else if applies && name.eq_ignore_ascii_case("allow") && !value.is_empty() {
                rules.allow.push(value.to_owned());
            } else if applies && name.eq_ignore_ascii_case("crawl-delay") {
                rules.crawl_delay = value
                    .parse::<f64>()
                    .ok()
                    .map(|seconds| Duration::from_secs_f64(seconds.max(0.0)));
            }
        }
        rules
    }

    fn allows(&self, path: &str) -> bool {
        let allowed_len = self
            .allow
            .iter()
            .filter(|rule| path.starts_with(rule.as_str()))
            .map(String::len)
            .max()
            .unwrap_or(0);
        let denied_len = self
            .disallow
            .iter()
            .filter(|rule| path.starts_with(rule.as_str()))
            .map(String::len)
            .max()
            .unwrap_or(0);
        denied_len == 0 || allowed_len >= denied_len
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn extracts_links_and_forms() {
        let base = Url::parse("https://example.com/start").unwrap();
        let doc = extract_document(
            &base,
            r"<a href='/item?id=7'>x</a><form method='post' action='/login'><input name='user' value='a'><input type='hidden' name='csrf' value='x'></form>",
        );
        assert_eq!(doc.candidates.len(), 4);
        assert!(doc.candidates.iter().any(|c| c.param_name == "id"));
        assert!(
            doc.candidates
                .iter()
                .any(|c| { c.param_name == "user" && c.location == ParameterLocation::Body })
        );
        assert!(doc.candidates.iter().any(|c| {
            c.param_name == "csrf"
                && c.location == ParameterLocation::Body
                && c.param_type == ParamType::Hidden
        }));
    }

    #[test]
    fn robots_prefers_longest_allow() {
        let rules =
            RobotsRules::parse("User-agent: *\nDisallow: /private\nAllow: /private/public\n");
        assert!(!rules.allows("/private/a"));
        assert!(rules.allows("/private/public/a"));
    }

    #[test]
    fn decode_embedded_url_handles_html_and_json_escapes() {
        assert_eq!(
            decode_embedded_url("/api?a=1&amp;desc=x"),
            "/api?a=1&desc=x"
        );
        assert_eq!(decode_embedded_url(r"/api?a=1\u0026b=2"), "/api?a=1&b=2");
        // Single decode only: `&amp;lt;` -> `&lt;`, not `<`.
        assert_eq!(decode_embedded_url("/api?q=&amp;lt;"), "/api?q=&lt;");
        // Multibyte UTF-8 survives JS unescaping.
        assert_eq!(
            decode_embedded_url(r"/api?q=caf\u00e9-\u65e5\u672c\u8a9e"),
            "/api?q=caf\u{e9}-\u{65e5}\u{672c}\u{8a9e}"
        );
        // Lone `\u` without 4 hex digits is kept verbatim, no panic.
        assert_eq!(decode_embedded_url(r"/api?q=\u12"), "/api?q=\\u12");
    }

    #[test]
    fn decode_embedded_url_resolves_double_escapes() {
        // Double-escaped separator: `&amp;amp;` must split into two params,
        // not one `amp;`-prefixed remnant.
        assert_eq!(decode_embedded_url("/api?a=1&amp;amp;b=2"), "/api?a=1&b=2");
        // Double-escaped JSON separator: source-level `\\u0026` collapses to
        // `\u0026` on pass 1 and to `&` on pass 2.
        assert_eq!(decode_embedded_url(r"/api?a=1\\u0026b=2"), "/api?a=1&b=2");
        // Trailing backslash from an escaped closing quote is a JS artefact.
        assert_eq!(
            decode_embedded_url(r"/api/path?locale=HK_EN\\"),
            "/api/path?locale=HK_EN"
        );
        // Single-decode pin preserved: `&amp;lt;` stops at `&lt;`.
        assert_eq!(decode_embedded_url("/api?q=&amp;lt;"), "/api?q=&lt;");
        // Idempotent on clean URLs.
        assert_eq!(decode_embedded_url("/api?a=1&b=2"), "/api?a=1&b=2");
    }

    #[test]
    fn js_endpoint_regex_handles_escaped_quotes_and_backslashes() {
        let base = Url::parse("https://example.com/page").unwrap();
        // Escaped quote inside the value must not cut the match: both params
        // survive and no value keeps a trailing backslash.
        let doc = extract_document(&base, r#"var u="/api/x?title=a\'b&desc=c";"#);
        assert!(
            doc.candidates.iter().any(|c| c.param_name == "desc"),
            "desc must survive an escaped quote: {:?}",
            doc.candidates
                .iter()
                .map(|c| &c.param_name)
                .collect::<Vec<_>>()
        );
        assert!(
            !doc.candidates
                .iter()
                .any(|c| c.original_value.ends_with('\\')),
            "no trailing backslash artefact expected"
        );
        // Double-escaped separator inside JS splits into two params.
        let doc2 = extract_document(&base, r#"var u="/api/y?one=1&amp;amp;two=2";"#);
        assert!(doc2.candidates.iter().any(|c| c.param_name == "one"));
        assert!(doc2.candidates.iter().any(|c| c.param_name == "two"));
        assert!(
            !doc2
                .candidates
                .iter()
                .any(|c| c.param_name.contains("amp;")),
            "no amp; remnant expected"
        );
    }
    #[test]
    fn js_embedded_endpoints_split_params_after_decode() {
        let base = Url::parse("https://example.com/page").unwrap();
        let doc = extract_document(&base, r#"var u="/api/dynamic-og?title=Hi&amp;desc=New";"#);
        assert!(
            doc.candidates.iter().any(|c| c.param_name == "desc"),
            "amp;desc must decode to desc: {:?}",
            doc.candidates
                .iter()
                .map(|c| &c.param_name)
                .collect::<Vec<_>>()
        );
        assert!(
            !doc.candidates.iter().any(|c| c.param_name.contains("amp;")),
            "no amp; remnant expected"
        );
        let doc2 = extract_document(&base, r#"var u="/api/x?cate=A\u0026desc=B";"#);
        assert!(doc2.candidates.iter().any(|c| c.param_name == "cate"));
        assert!(doc2.candidates.iter().any(|c| c.param_name == "desc"));
    }

    #[test]
    fn templated_and_internal_js_endpoints_are_dropped() {
        let base = Url::parse("https://example.com/page").unwrap();
        let doc = extract_document(
            &base,
            r#"var a="/bg/agent?q=%7Bsearch_term_string%7D"; var b="/cdn-cgi/content?id=abc";"#,
        );
        assert!(
            doc.candidates.is_empty(),
            "placeholders + cdn-cgi must yield no candidates: {:?}",
            doc.candidates
                .iter()
                .map(|c| c.url.as_str().to_owned())
                .collect::<Vec<_>>()
        );
        assert!(doc.links.is_empty());
    }
}
