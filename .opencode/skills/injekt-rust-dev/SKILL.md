---
name: injekt-rust-dev
description: Develops, lints and tests injekt Rust codebase (MSRV 1.88, edition 2024, deny unsafe/unwrap/expect). Use when editing src/, adding detection techniques, DBMS fingerprint, tampers, HTTP client, orchestrator, session/scrubber, or running cargo fmt/clippy/test, insta snapshots, wiremock integration tests in injekt repo.
---

# Injekt Rust Dev

## When to use

Any edit under `src/`, `tests/`, `Cargo.toml`, or running `cargo fmt/clippy/test`, `cargo insta review`. Covers `cli/`, `target/`, `http/`, `detection/`, `techniques/`, `dbms/`, `extraction/`, `recon/`, `session/`, `reporting/`, `engine/orchestrator.rs`, `mcp/`.

## Non-negotiables — build fails otherwise

- `#![deny(unsafe_code)]`, `clippy::{unwrap_used, expect_used, dbg_macro, todo} = deny`, `pedantic = warn` (`Cargo.toml`, `src/lib.rs`, `src/main.rs`).
- Never `unwrap()/expect()/dbg!()/todo!()` in `src/`. Propagate via `crate::error::InjektError` (`thiserror 2.x`, `#[non_exhaustive]`) or `anyhow`.
- Every `tests/*.rs` needs header `#![allow(clippy::unwrap_used, clippy::expect_used)]`.
- Keep `#[non_exhaustive]`, newtypes (`TargetUrl`, `Payload`), manual `Debug` for secret types, `const fn`, exhaustive `match` where present.
- MSRV 1.88, edition 2024. No new unsafe, no unbounded spawns.

## Workflow — run in order, stop on red

```bash
cargo fmt --check
cargo clippy -- -D warnings
cargo test
cargo test --doc
cargo test --test integration_http -- --nocapture  # focused
cargo insta review  # only after snapshot change, accept/reject explicitly
```

No CI gate for `cargo deny check` (no `deny.toml` in repo). `justfile` mirrors same steps.

Checklist:

```
Dev Progress:
- [ ] cargo fmt --check clean
- [ ] cargo clippy -- -D warnings clean
- [ ] cargo test + --doc green
- [ ] insta snapshots reviewed if touched
- [ ] OPSEC invariants preserved (see below)
```

## Architecture quirks — MUST respect

- `HttpClient::builder().timeout(...).build()` — `timeout()` mandatory typestate `NeedTimeout`, won't compile without. See `src/http/client.rs`.
- Target: `Cli::effective_target()` = `--raw-file` > global `--target` > `scan --target`. `recon crawl/scan` take bare host/URL, not global flag shape.
- Anti-SSRF: private/loopback rejected unless `--allow-private` (lab only).
- Proxy: `socks5://` rejected `DnsLeak`, always `socks5h://` remote DNS. See `src/http/proxy.rs`.
- WAF: repeated 403/406 -> `Baseline::is_waf_blocked()` + auto `space2comment,randomcase` only.
- OOB OPT-IN: without `--oob-poll-url` containing `{token}`, never auto-confirmed. Egress from target DB, not via `--proxy`.
- Concurrency: bounded `buffer_unordered(threads)` + `tokio::time::timeout` + `CancellationToken`. `tracing` default `info`, `-v` -> `debug`, `RUST_LOG` override.
- Engine: `src/engine/orchestrator.rs` `parse -> baseline -> detection -> fingerprint -> extraction(opt-in)`.

## OPSEC invariants — load-bearing

- `SessionState` RAM-only `Arc<RwLock<..>>` + `ZeroizeOnDrop`. Disk only via `--export-encrypted/--output/--import/recon import --file` (all opt-in, 0o600).
- Secrets = `secrecy::SecretString` + `zeroize`. All output via `session/scrubber.rs`. Never log secrets, never `--no-redact` except local debug, never commit `*.enc`/`report.json`/Burp raws.
- `HttpClient` rustls, jitter `Normal(750,250)` floor 200ms always on, token-bucket 10/s default, `Identity` UA+Sec-CH-UA rotation, in-mem `CookieJar`.

## Tests

- `wiremock 0.6` `MockServer` real local HTTP for integration (`integration_http|integration_tamper|integration_oob|integration_recon|integration_union|integration_stacked|integration_request_tamper`).
- `proptest` for target parsers (`tests/proptest_parsers.rs`), `insta` snapshots, doc-tests.
- New technique/DBMS: add detector + payloads under `src/techniques/<name>/` + `src/dbms/<kind>/`, wiremock blind + noisy (`request_id`) cases, 0 FP on N1/N2 style negatives.

Example:

```bash
cargo test --test integration_tamper space2comment
cargo test --test integration_recon -- --nocapture
cargo test --doc
```

## Anti-patterns

- Adding `unwrap/expect/todo/dbg` to silence compiler.
- Skipping `timeout()` or using unbounded `spawn`.
- Storing URLs/cookies/bodies in knowledge/stats, logging secrets, disabling scrubber.
- Adding tampers/levels without bench proof (`bench/` + `request_count` cross-check <5%).
- Treating `--confirm` as real second-pass (currently warning-only, in-detection 3-trial still applies).

## References

- `AGENTS.md` (source of truth for agent rules), `Cargo.toml` lints, `src/lib.rs`/`src/main.rs` denies, `DOCUMENTATION.md` Architecture + Development, `docs/OPSEC.md`, `docs/ROADMAP-v1.0.md` (C1-C13 order).
