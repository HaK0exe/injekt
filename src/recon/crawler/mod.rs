#![deny(unsafe_code)]

mod config;
mod crawl;
mod decode;
mod extract;
mod robots;
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests;

pub use config::{CrawlConfig, CrawlReport};
pub use crawl::Crawler;
