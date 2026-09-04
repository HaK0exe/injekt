#![deny(unsafe_code)]

use crate::{
    http::client::{HttpClient, RequestSpec},
    recon::{
        filters::{is_in_scope, normalize_page_url, page_template_key},
        parameter::{CandidateMethod, FormContext, ParamType, ParameterCandidate},
    },
    target::{parameters::ParameterLocation, url::TargetUrl},
};
use regex::Regex;
use scraper::{ElementRef, Html, Selector};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    time::Duration,
};
use tokio_util::sync::CancellationToken;
use url::Url;

#[derive(Debug, Clone)]
pub struct CrawlConfig {
    pub depth: usize,
    pub max_pages: usize,
    /// Cap on how many pages sharing the same [`page_template_key`] are
    /// fetched — guards against pagination/listing/calendar traps burning
    /// the whole `max_pages` budget on redundant instances of one page shape.
    pub max_per_template: usize,
    pub include_subdomains: bool,
    pub respect_robots: bool,
    pub allow_private: bool,
}

impl Default for CrawlConfig {
    fn default() -> Self {
        Self {
            depth: 2,
            max_pages: 100,
            max_per_template: 3,
            include_subdomains: false,
            respect_robots: true,
            allow_private: false,
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
        let root = parse_target(target, self.config.allow_private)?;
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
        let mut queue = VecDeque::from([(root.clone(), 0usize)]);
        let mut queued = HashSet::from([normalize_page_url(root.clone()).to_string()]);
        let mut visited = HashSet::new();
        let mut template_counts: HashMap<String, usize> = HashMap::new();
        let mut capped_templates = HashSet::new();
        let mut candidate_keys = HashSet::new();
        let mut candidates = Vec::new();
        let mut warnings = Vec::new();

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
                if is_in_scope(&root, &candidate.url, self.config.include_subdomains)
                    && TargetUrl::parse(candidate.url.as_str(), self.config.allow_private).is_ok()
                    && robots.allows(candidate.url.path())
                    && candidate_keys.insert(candidate.dedup_key())
                {
                    candidates.push(candidate);
                    found_here += 1;
                }
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
            "crawl finished: {} page(s) visited, {} parameter(s) found in {:.2}s",
            visited.len(),
            candidates.len(),
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

fn parse_target(target: &str, allow_private: bool) -> anyhow::Result<Url> {
    let with_scheme = if target.contains("://") {
        target.to_owned()
    } else {
        format!("https://{target}")
    };
    let parsed = TargetUrl::parse(&with_scheme, allow_private)
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

    if let Ok(js_endpoint) = Regex::new(
        r#"[\"']((?:https?://[^\"']+|/[^\"']+)[?&][A-Za-z_][A-Za-z0-9_.-]*=[^\"']*)[\"']"#,
    ) {
        for captures in js_endpoint.captures_iter(body) {
            if let Some(raw) = captures.get(1)
                && let Ok(url) = base.join(raw.as_str())
            {
                add_link_candidates(&mut out, url, ParamType::Javascript);
            }
        }
    }
    out
}

fn add_link_candidates(out: &mut ExtractedDocument, mut url: Url, param_type: ParamType) {
    url.set_fragment(None);
    for (name, value) in url.query_pairs() {
        out.candidates.push(ParameterCandidate {
            url: url.clone(),
            method: CandidateMethod::Get,
            param_name: name.into_owned(),
            location: ParameterLocation::Query,
            param_type,
            original_value: value.into_owned(),
            form_context: None,
        });
    }
    out.links.push(url);
}

fn selector(value: &str) -> Selector {
    Selector::parse(value).unwrap_or_else(|_| unreachable!("static selector is valid"))
}

fn resolve_attr(base: &Url, element: &ElementRef<'_>, attr: &str) -> Option<Url> {
    let value = element.value().attr(attr)?;
    if value.starts_with('#') || value.starts_with("javascript:") || value.starts_with("mailto:") {
        return None;
    }
    base.join(value).ok().map(normalize_page_url)
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
}
