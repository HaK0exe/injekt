# AGENTS.md — injekt

Single Rust crate (lib + binary). MSRV 1.88, edition 2024. `src/main.rs` parses `cli::args::Cli` then dispatches to `cli::commands::{scan,recon,replay,info}`; scan/recon funnel into `src/engine/orchestrator.rs` state machine (`parse → baseline → detection → fingerprint → extraction(opt-in)`).

## Commands (verified in `Cargo.toml` / `README.md`)

```bash
cargo fmt --check
cargo clippy -- -D warnings
cargo test
cargo test --doc
cargo test --test <integration_http|integration_tamper|integration_oob|integration_recon|integration_union|integration_stacked|integration_request_tamper> <test_name>
cargo insta review   # snapshots used; accept/reject after snapshot test changes
```

No CI workflows, no `deny.toml`, no rustfmt config — `cargo deny check` from README has no config in repo, don't treat as gating.

## Lints — will fail build if ignored

`Cargo.toml` + `src/lib.rs` / `src/main.rs`: `#![deny(unsafe_code)]`, `clippy::{unwrap_used, expect_used, dbg_macro, todo} = deny`, `pedantic = warn`.

- Never add `unwrap()`/`expect()`/`dbg!()`/`todo!()` in `src/`; propagate via `crate::error::InjektError` (`thiserror 2.x`, `#[non_exhaustive]`) or `anyhow`.
- Every `tests/*.rs` needs `#![allow(clippy::unwrap_used, clippy::expect_used)]` header (see existing integration tests); scoped `#[allow(...)]` for intentional cases in `src/`.
- Keep `#[non_exhaustive]`, newtypes (`TargetUrl`, `Payload`), manual `Debug` for secret types, `const fn` / exhaustive `match` where already used.

## Architecture quirks (not obvious from filenames)

- `HttpClient::builder().timeout(...).build()` — `timeout()` is mandatory (typestate `NeedTimeout`); won't compile without it. See `src/http/client.rs`.
- Target resolution: `Cli::effective_target()` prefers `--raw-file` (Burp/ZAP raw request via `target/raw_request.rs`) over global `--target` over `scan --target`. `recon crawl/scan` take bare host or URL, not the global flag shape.
- Anti-SSRF: private/loopback targets rejected unless `--allow-private` (lab only).
- Proxy: `socks5://` is rejected with `DnsLeak` — always use `socks5h://` (remote DNS). See `src/http/proxy.rs`.
- WAF: repeated 403/406 → `Baseline::is_waf_blocked()` + auto `space2comment` tamper.
- OOB (`techniques/oob`, OPT-IN): without `--oob-poll-url` containing `{token}`, probes are sent but never auto-confirmed — no finding without collaborator proof. Egress originates from target DB server, not via `--proxy`; use self-hosted collaborator.
- Concurrency: bounded `buffer_unordered(threads)` + `tokio::time::timeout` + `CancellationToken` (Ctrl+C graceful). Don't introduce unbounded spawns.

## OPSEC / secrets (load-bearing)

- Zero persistence by default: `SessionState` is RAM-only (`Arc<RwLock<…>>`, `ZeroizeOnDrop`). Only `--export-encrypted` / `--output` / `--import` / `recon import --file` touch disk — all opt-in, warn accordingly.
- Secrets (`--cookies`, tokens, extracted data, passphrases) are `secrecy::SecretString` + `zeroize`; all output passes through `session/scrubber.rs`. Never log secrets, never use `--no-redact` except local debugging, never commit `*.enc` / `report.json` / raw Burp files.
- `tracing` filter defaults to `info`, `-v` → `debug`, overridable via `RUST_LOG`.

## Tests

- Integration tests use `wiremock 0.6` `MockServer` (real local HTTP); `proptest` covers target parsers (`tests/proptest_parsers.rs`); `insta` for snapshots.
- Run focused: `cargo test --test integration_http -- --nocapture` for debugging; doc-tests via `cargo test --doc`.
