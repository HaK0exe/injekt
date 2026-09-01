#![allow(clippy::expect_used, clippy::unwrap_used)]

use injekt::{
    http::{client::HttpClient, jitter::Jitter, rate_limit::RateLimiter},
    recon::{CandidateMethod, CrawlConfig, Crawler},
    target::parameters::ParameterLocation,
};
use std::{sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

fn fast_client() -> HttpClient {
    HttpClient::builder()
        .timeout(Duration::from_secs(2))
        .jitter(Jitter::new(0.0, 0.0))
        .rate_limiter(Arc::new(RateLimiter::new(1_000.0)))
        .build()
        .expect("client")
}

#[tokio::test]
async fn recon_crawler_discovers_links_forms_and_js_candidates() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/robots.txt"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/html")
                .set_body_string(
                    r#"
            <a href="/item?id=7">item</a>
            <a href="/next">next</a>
            <form method="post" action="/login">
              <input name="user" value="admin">
              <input type="hidden" name="csrf" value="token">
            </form>
            <script>const url = "/api/search?q=term";</script>
            "#,
                ),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/next"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/html")
                .set_body_string(r#"<a href="/deep?page=1">deep</a>"#),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/item"))
        .respond_with(ResponseTemplate::new(200).insert_header("content-type", "text/html"))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/search"))
        .respond_with(ResponseTemplate::new(200).insert_header("content-type", "text/html"))
        .mount(&server)
        .await;

    let crawler = Crawler::new(
        fast_client(),
        CrawlConfig {
            depth: 1,
            max_pages: 10,
            include_subdomains: false,
            respect_robots: true,
            allow_private: true,
        },
    );
    let report = crawler
        .crawl(&server.uri(), &CancellationToken::new())
        .await
        .expect("crawl");

    assert!(report.pages_visited >= 2);
    assert!(report.candidates.iter().any(|candidate| {
        candidate.param_name == "id" && candidate.location == ParameterLocation::Query
    }));
    assert!(report.candidates.iter().any(|candidate| {
        candidate.param_name == "q" && candidate.location == ParameterLocation::Query
    }));
    assert!(report.candidates.iter().any(|candidate| {
        candidate.param_name == "user"
            && candidate.method == CandidateMethod::Post
            && candidate.location == ParameterLocation::Body
    }));
}

#[tokio::test]
async fn recon_crawler_respects_robots_disallow() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/robots.txt"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/plain")
                .set_body_string("User-agent: *\nDisallow: /private\n"),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/html")
                .set_body_string(r#"<a href="/private/secret?id=1">secret</a>"#),
        )
        .mount(&server)
        .await;

    let crawler = Crawler::new(
        fast_client(),
        CrawlConfig {
            depth: 2,
            max_pages: 10,
            include_subdomains: false,
            respect_robots: true,
            allow_private: true,
        },
    );
    let report = crawler
        .crawl(&server.uri(), &CancellationToken::new())
        .await
        .expect("crawl");

    assert!(
        report
            .candidates
            .iter()
            .all(|candidate| !candidate.url.path().starts_with("/private"))
    );
}
