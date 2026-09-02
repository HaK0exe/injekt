# injekt

**Modern SQL injection detection & exploitation in Rust — zero persistence, anonymisation by design.**

> Superior to `sqlmap`/`ghauri` in performance, maintainability and discretion. Everything lives in RAM and is wiped on exit.

[![Rust 1.88](https://img.shields.io/badge/rust-1.88%2B-orange)](https://www.rust-lang.org) [![Edition 2024](https://img.shields.io/badge/edition-2024-blue)](https://doc.rust-lang.org/edition-guide/) [![License: MIT](https://img.shields.io/badge/License-MIT-green)](LICENSE) [![unsafe_code deny](https://img.shields.io/badge/unsafe-deny-success)](https://doc.rust-lang.org/rustc/lints/listing/allowed-by-default.html)

[Français](README.fr.md) | [OPSEC](docs/OPSEC.md) | [Research Notes](docs/RESEARCH_NOTES.md)

---

## Why injekt?

| Concern | sqlmap / ghauri | injekt v2 |
|---|---|---|
| **Persistence** | SQLite session files, cache on disk | **RAM only** (`Arc<RwLock<SessionState>>`), `ZeroizeOnDrop`, `SecretString` — nothing written unless `--export-encrypted` |
| **OPSEC** | Fixed cadence, leaky headers, `socks5://` DNS leak | Human jitter (`Normal` 750±250ms), realistic UA rotation with `Sec-CH-UA` alignment, `socks5h://` enforced, scrubber auto-redaction |
| **Performance** | Unbounded threads, blocking code | Bounded `buffer_unordered(n)`, native `async fn` traits, `tokio::time::timeout` everywhere, `CancellationToken` graceful shutdown |
| **Maintainability** | Python, `async_trait` macros | Rust 2024 edition, `thiserror 2.x`, newtypes, type-state builder, `clippy pedantic` + `deny(warnings)` |

**Two principles drive every decision:**
1. **Zero persistence by default** — no DB, no file, no cache.
2. **Anonymisation by design** — never leak secrets (logs, reports, memory, network).

---

## Features

- **Targets**: strict URL parsing (`url` crate), private/loopback anti-SSRF rejection, Burp/ZAP raw-request parser, `ParameterLocation{Query,Body,Header,Cookie}`, markers `*` / `§` / `{{}}`.
- **HTTP** (`src/http/`): type-state builder (`timeout()` mandatory before `build()`), `Arc<reqwest::Client>` rustls, jitter, `RateLimiter` token-bucket, in-memory `CookieJar` (`zeroize`), `Identity` rotation, `ProxyConfig` Tor `socks5h://`, retry exponential + jitter, redirect policy, gzip/br.
- **Detection** (`src/detection/`): 3-5 baselines → SHA-256 + mean/σ + WAF 403/406 detection, Levenshtein + Jaccard diff (`DiffResult{similarity,time_delta,confidence}`), confirmation TRUE/FALSE inverted (3 trials min).
- **Techniques** (`src/techniques/`): `boolean` (`OR 1=1` / `AND 1=1`, comment per DBMS), `time` (`SLEEP/pg_sleep/WAITFOR/BENCHMARK`, threshold `baseline+2σ`), `error` (`EXTRACTVALUE/CONVERT/CAST`), `union` (ORDER BY enumeration), `stacked` (`; SELECT` marker), `oob` (OPT-IN DNS/HTTP via `--oob-domain`, collaborator polling), `tamper` WAF evasion (`--tamper space2comment,randomcase,versionedcomment,charencode,doubleurlencode,hexencode,unicodeencode,overlongutf8,space2plus/tab/newline/randomblank,betweencomment` + auto `space2comment` on WAF 403/406).
- **DBMS** (`src/dbms/`): trait `DbmsDetector` with native `async fn`, fingerprint for MySQL 8.x (`@@version`), Postgres 15+ (`version()`), MSSQL 2022 (`@@version`), Oracle 21c (`v$version`).
- **Extraction** (`src/extraction/`): binary search ASCII 32-126, `buffer_unordered` bounded, verification (length + checksum), `SecretString` zeroized after report.
- **Recon** (`src/recon/`): static crawler for links, forms, and basic JS endpoints; same-origin scope control, robots.txt support, candidate deduplication, and rate-limited scan/enumeration handoff.
- **Session** (`src/session/`): `SessionState` RAM, `Scrubber` (`Authorization/Cookie/JWT/AKIA*/PEM` → `[REDACTED]`), encrypted export `XChaCha20-Poly1305` + `Argon2id` **OPT-IN**.
- **Reporting** (`src/reporting/`): JSON + console (`owo-colors`, `tabled`, `indicatif`), evidence scrubbed.
- **Engine** (`src/engine/orchestrator.rs`): state machine `parse → baseline → detection → fingerprint → extraction(opt-in)`, bounded concurrency, progress bars, structured `tracing`.

---

## Installation

**Prerequisites:** Rust 1.88+ (`rustup update`)

```bash
git clone https://github.com/<you>/injekt
cd injekt
cargo build --release
# binary at ./target/release/injekt

# or install to $CARGO_HOME/bin
cargo install --path .
```

**Toolchain checks (required):**
```bash
cargo fmt --check
cargo clippy -- -D warnings
cargo test
cargo deny check   # advisories + licenses (install cargo-deny)
```

---

## Quick Start

```bash
# Basic scan (boolean/time/error, 5 threads)
injekt --target "https://example.com/search?q=1" --threads 5

# Scan subcommand (equivalent)
injekt scan --target "https://example.com/?id=1"

# Discover parameterized URLs and forms without testing
injekt recon crawl --target "example.com" --depth 2 --max-pages 100

# Crawl, test each discovered parameter, then enumerate confirmed findings
injekt recon scan --target "example.com" --auto-enumerate --dbs

# Import previously discovered candidates
injekt recon import --file discovered.json --test

# Specific techniques + DBMS
injekt --target "https://example.com/?id=1" --techniques boolean,error --dbms mysql

# WAF bypass: try tampered variants (original + each single + full chain)
injekt --target "https://example.com/?id=1" --tamper space2comment,randomcase --techniques boolean,union
injekt --target "https://example.com/?id=1" --tamper versionedcomment,charencode  # MySQL versioned + URL encode

# Request-level tampers: HPP (?id=1&id=PAYLOAD) and chunked (streamed body)
injekt --target "https://example.com/?id=1" --hpp --techniques boolean
injekt recon scan --target "example.com" --hpp --chunked --auto-enumerate --dbs

# OPSEC: Tor + jitter + rate limit + no private IP bypass
injekt --target "https://example.com/?id=1" \
  --proxy socks5h://127.0.0.1:9050 \
  --jitter "750,250" --rate-limit 5

# Allow private lab targets
injekt --target "http://192.168.1.10/?id=1" --allow-private

# Encrypted session export (OPT-IN) — creates sensitive artefact
injekt --target "https://example.com/?id=1" --export-encrypted ./session.enc
injekt --import ./session.enc --target "https://example.com/?id=1"  # resume
injekt replay --file ./session.enc
injekt info

# Output
injekt --target "https://example.com/?id=1" --output report.json
cat report.json | jq .
```

**Raw request (Burp):**
```bash
# Save Burp request to req.txt then:
# (parser at src/target/raw_request.rs supports multipart, Content-Type auto)
```

---

## CLI Reference

```
injekt [OPTIONS] [COMMAND]

Commands:
  scan    Run detection (default when --target is given)
  recon   Crawl targets, discover parameters, scan candidates, import candidate JSON
  replay  Replay encrypted session
  info    Show version / techniques / DBMS

Options:
  -u, --target <URL>              Target URL
      --method <METHOD>           HTTP method (default GET)
      --headers <H1,H2>           Extra headers (comma-separated)
      --cookies <STR>             Cookies (SecretString, redacted in logs)
      --proxy <URL>               http(s):// or socks5h:// (socks5:// rejected - DNS leak)
      --threads <N>               Concurrency [default: 5]
      --techniques <LIST>         boolean,time,error,union,stacked,oob,all [default: all]
      --tamper <LIST>             WAF tampers: space2comment,space2plus,space2tab,space2newline,space2randomblank,randomcase,versionedcomment,betweencomment,charencode,doubleurlencode,hexencode,unicodeencode,overlongutf8 [default: none, auto space2comment on WAF 403/406]
      --hpp                       HTTP Parameter Pollution: duplicate ?id=1&id=PAYLOAD (Query/Body)
      --chunked                   Chunked transfer: streamed Transfer-Encoding: chunked body (Body only)
      --oob-domain <DOMAIN>       Collaborator base domain (enables OOB probes, OPT-IN)
      --oob-poll-url <URL>        Poll URL with {token} placeholder (auto-confirm callbacks)
      --oob-wait-secs <N>         Wait before polling collaborator [default: 5]
      --dbms <KIND>               mysql|postgres|mssql|oracle
      --extract                   Enable data extraction (opt-in, SecretString)
      --output <PATH>             JSON report path
      --rate-limit <RPS>          Token-bucket req/s
      --jitter <MEAN,STD>         e.g. "750,250" ms
      --marker <STR>              Injection marker (*, §, {{}})
      --export-encrypted <PATH>   Encrypted snapshot (XChaCha20-Poly1305/Argon2id)
      --import <PATH>             Import encrypted snapshot
      --no-redact                 Disable scrubbing (local only!)
      --allow-private             Allow loopback/private IPs (anti-SSRF bypass)
  -v, --verbose                   Debug logs (tracing)
  -h, --help
  -V, --version
```

Recon subcommands:

```bash
injekt recon crawl --target <HOST|URL> [--depth N] [--max-pages N] [--include-subdomains] [--ignore-robots]
injekt recon scan --target <HOST|URL> [--depth N] [--max-pages N] [--auto-enumerate]
injekt recon import --file discovered.json [--test] [--enumerate]
```

---

## OPSEC

See [`docs/OPSEC.md`](docs/OPSEC.md) — summary:

- **No disk writes** unless `--export-encrypted`; `SessionState` is `Arc<RwLock<…>>` and `ZeroizeOnDrop`.
- **Scrubber** (`src/session/scrubber.rs`): `Authorization`, `Cookie`, `Set-Cookie`, `X-Api-Key`, JWT `eyJ…`, `AKIA[0-9A-Z]{16}`, PEM → `[REDACTED]` or 8-hex hash.
- **Identity** (`src/http/identity.rs`): realistic UA pool (Chrome 126 / Firefox 128 / Safari 17.5) with matching `Sec-CH-UA`.
- **Jitter** (`src/http/jitter.rs`): `rand_distr::Normal`, never regular cadence.
- **Proxy** (`src/http/proxy.rs`): `socks5h://` enforces remote DNS; `socks5://` without `h` is rejected.
- **TLS**: `rustls` (stable JA3 fingerprinted — documented limitation; use external proxy for JA3 randomization).
- **NEVER** `--no-redact` on shared reports.

---

## Architecture

```
src/
├── main.rs / lib.rs
├── cli/{args,commands/{scan,recon,replay,info},output/{console,json,format}}
├── target/{url,raw_request,parameters,markers}
├── http/{client,identity,proxy,cookies,redirects,retry,jitter,rate_limit}
├── detection/{baseline,response_diff,confirmation,scanner/{engine,scheduler}}
├── techniques/{boolean,time,error,union,stacked,oob}/{detector,payloads} (+oob/verifier) + tamper (WAF evasion) + request_tamper (HPP/chunked)
├── dbms/{common,mysql,postgres,mssql,oracle}/{fingerprint,payloads,queries}
├── extraction/{engine,inference,verification}
├── recon/{crawler,discovery,filters,parameter}
├── session/{state,scrubber,export}
├── reporting/{console,json,evidence}
└── engine/orchestrator
```

Key patterns: newtypes (`TargetUrl`, `Payload`), type-state builder, `#[non_exhaustive]`, `Cow`, `Arc` only when shared, exhaustive `match`, `const fn`, manual `Debug` for secrets, `#[deny(unsafe_code)]`.

---

## Development

```bash
cargo fmt
cargo clippy -- -D warnings
cargo test -- --nocapture
cargo test --doc

# wiremock 0.6, insta snapshots, proptest for parsers
cargo insta review
```

**MSRV** 1.88, **edition** 2024. Lints in `Cargo.toml`:
```toml
[lints.rust]
unsafe_code = "deny"
[lints.clippy]
pedantic = { level = "warn", priority = -1 }
unwrap_used = "deny"
expect_used = "deny"
```

---

## Security

- No `unsafe` (`#![deny(unsafe_code)]` crate-wide).
- `zeroize` + `secrecy::SecretString` for cookies, tokens, extracted data, passphrases.
- Offline, zero telemetry.

> **Disclaimer:** Use only on systems you own or have explicit permission to test. The authors are not responsible for misuse.

---

## License

MIT — see [LICENSE](LICENSE).

## Acknowledgments

Inspired by `sqlmap`/`ghauri` but rewritten for Rust 2024 best practices, OPSEC-first design, and bounded async.
