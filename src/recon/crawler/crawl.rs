use super::config::{CrawlConfig, CrawlReport};
use super::extract::extract_document;
use super::robots::RobotsRules;
use crate::http::client::{HttpClient, RequestSpec};
use crate::recon::filters::{
    candidate_template_key, is_in_scope, is_placeholder_value, normalize_page_url,
    page_template_key, should_skip_candidate, should_skip_crawl_url,
};
use crate::recon::parameter::ParameterCandidate;
use crate::target::url::TargetUrl;
use std::collections::{HashMap, HashSet, VecDeque};
use tokio_util::sync::CancellationToken;
use url::Url;

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
                // Bounded queue: `queued` counts distinct URLs ever seen. Without a
                // push-side cap, `?page=1..∞` traps queue tens of thousands of
                // `Url` before `visited.len() >= max_pages` breaks the pop loop.
                // Cap pending+visited to a small multiple of `max_pages`.
                let queue_cap = self.config.max_pages.saturating_mul(4).max(64);
                for link in extracted.links {
                    if queued.len() >= queue_cap {
                        dropped_over_cap += 1;
                        break;
                    }
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
