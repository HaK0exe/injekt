use super::decode::decode_embedded_url;
use crate::recon::filters::{
    is_internal_crawl_path, is_placeholder_value, is_templated_token, normalize_page_url,
    should_skip_candidate, should_skip_crawl_url,
};
use crate::recon::parameter::{CandidateMethod, FormContext, ParamType, ParameterCandidate};
use crate::target::parameters::ParameterLocation;
use regex::Regex;
use scraper::{ElementRef, Html, Selector};
use std::collections::BTreeMap;
use std::sync::OnceLock;
use url::Url;

#[derive(Debug, Default)]
pub(super) struct ExtractedDocument {
    pub(super) links: Vec<Url>,
    pub(super) candidates: Vec<ParameterCandidate>,
}

pub(super) fn extract_document(base: &Url, body: &str) -> ExtractedDocument {
    let document = Html::parse_document(body);
    let mut out = ExtractedDocument::default();
    if let Some(anchor_selector) = selector("a[href]") {
        for anchor in document.select(&anchor_selector) {
            if let Some(url) = resolve_attr(base, &anchor, "href") {
                add_link_candidates(&mut out, url, ParamType::Link);
            }
        }
    }

    let form_selector = selector("form");
    let field_selector = selector("input[name], select[name], textarea[name]");
    let (Some(form_selector), Some(field_selector)) = (form_selector, field_selector) else {
        return out;
    };
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

/// Parse a CSS selector, returning `None` instead of panicking when the
/// static selector fails to compile (never happens in practice — all call
/// sites use hardcoded selectors — but `unreachable!` would be a prod panic
/// if `scraper` ever tightened its parser).
fn selector(value: &str) -> Option<Selector> {
    Selector::parse(value).ok()
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
        let Some(option_selector) = selector("option[selected], option") else {
            return String::new();
        };
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
