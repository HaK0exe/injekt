# injekt

**Modern SQL injection detection & exploitation in Rust — zero persistence, anonymisation by design.**

> Superior to `sqlmap`/`ghauri` in performance, maintainability and discretion. Everything lives in RAM and is wiped on exit.

[![CI](https://github.com/HaK0exe/injekt/actions/workflows/ci.yml/badge.svg)](https://github.com/HaK0exe/injekt/actions/workflows/ci.yml) [![Rust 1.88](https://img.shields.io/badge/rust-1.88%2B-orange)](https://www.rust-lang.org) [![Edition 2024](https://img.shields.io/badge/edition-2024-blue)](https://doc.rust-lang.org/edition-guide/) [![License: MIT](https://img.shields.io/badge/License-MIT-green)](LICENSE) [![unsafe_code deny](https://img.shields.io/badge/unsafe-deny-success)](https://doc.rust-lang.org/rustc/lints/listing/allowed-by-default.html)

[Français](README.fr.md) | [OPSEC](docs/OPSEC.md) | [Research Notes](docs/RESEARCH_NOTES.md) | [Full Documentation](DOCUMENTATION.md)

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
- **Techniques** (`src/techniques/`): `boolean` (`OR 1=1` / `AND 1=1`, comment per DBMS), `time` (`SLEEP/pg_sleep/WAITFOR/BENCHMARK`, threshold `baseline+2σ`), `error` (`EXTRACTVALUE/CONVERT/CAST`), `union` (ORDER BY enumeration), `stacked` (`; SELECT` marker), `oob` (OPT-IN DNS/HTTP via `--oob-domain`, collaborator polling), `json` (dual-channel boolean + error over `JSON_EXTRACT`/`->>`/`JSON_VALUE`/`OPENJSON`/`JSON_EXISTS` per DBMS), `tamper` WAF evasion (`--tamper space2comment,randomcase,versionedcomment,charencode,doubleurlencode,hexencode,unicodeencode,overlongutf8,space2plus/tab/newline/randomblank/dash,betweencomment,randomcomments,equaltolike,base64encode` + auto `space2comment` on WAF 403/406).
- **DBMS** (`src/dbms/`): trait `DbmsDetector` with native `async fn`, fingerprint for MySQL 8.x (`@@version`), Postgres 15+ (`version()`), MSSQL 2022 (`@@version`), Oracle 21c (`v$version`).
- **Extraction** (`src/extraction/`): binary search ASCII 32-126, `buffer_unordered` bounded, verification (length + checksum), `SecretString` zeroized after report.
- **Recon** (`src/recon/`): static crawler for links, forms, and basic JS endpoints; same-origin scope control, robots.txt support, candidate deduplication, and rate-limited scan/enumeration handoff.
- **Session** (`src/session/`): `SessionState` RAM, `Scrubber` (`Authorization/Cookie/JWT/AKIA*/PEM` → `[REDACTED]`), encrypted export `XChaCha20-Poly1305` + `Argon2id` **OPT-IN**.
- **Reporting** (`src/reporting/`): JSON + console (`owo-colors`, `tabled`, `indicatif`), evidence scrubbed.
- **Engine** (`src/engine/orchestrator.rs`): state machine `parse → baseline → detection → fingerprint → extraction(opt-in)`, bounded concurrency, progress bars, structured `tracing`.

---

## Installation

### One-line install (Linux/macOS, no Rust required)

```bash
curl -fsSL https://raw.githubusercontent.com/HaK0exe/injekt/main/install.sh | sh
```

Detects your OS/arch, downloads the matching binary from the latest
[GitHub Release](https://github.com/HaK0exe/injekt/releases), verifies it against
`SHA256SUMS`, and installs it to `~/.local/bin` (override with `INJEKT_INSTALL_DIR`;
pin a version with `INJEKT_VERSION=v0.1.0`). Read [`install.sh`](install.sh) before
piping it to `sh` — same rule as any curl-pipe installer.

### Prebuilt binary (manual, no Rust required)

Every tagged release publishes binaries for Linux, macOS (x86_64 + arm64) and Windows —
grab one from [GitHub Releases](https://github.com/HaK0exe/injekt/releases), verify against
`SHA256SUMS`, extract, and run:

```bash
tar xzf injekt-*-x86_64-unknown-linux-gnu.tar.gz
cd injekt-*/
./injekt --no-banner info
```

### From source

**Prerequisites:** Rust 1.88+ (`rustup update`)

```bash
git clone https://github.com/HaK0exe/injekt
cd injekt
cargo build --release
# binary at ./target/release/injekt

# or install to $CARGO_HOME/bin
cargo install --path .
```

CI (`.github/workflows/ci.yml`) builds and tests every push/PR on Linux, macOS and
Windows, so `main` is verified cross-platform at all times.

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

# Presets: quick / balanced / stealth / aggressive (explicit flags always win)
injekt --target "https://example.com/?id=1" --profile quick
injekt --target "https://example.com/?id=1" --profile stealth \
  --proxy socks5h://127.0.0.1:9050
injekt --target "https://example.com/?id=1" --profile aggressive --level 3

# Config file + env (precedence: CLI > env > file > profile > defaults)
injekt --config ./injekt.toml --target "https://example.com/?id=1"
INJEKT_PROFILE=stealth INJEKT_THREADS=2 injekt --target "https://example.com/?id=1"

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

# JSON-function endpoints (configs, API blobs)
injekt --target "https://example.com/?id=1" --techniques json --dbms mysql

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

# MCP Server (for AI assistants)
injekt mcp  # See [MCP Documentation](docs/MCP.md) for client setup

# Output
injekt --target "https://example.com/?id=1" --output report.json
cat report.json | jq .
```

**Raw request (Burp/ZAP):**
```bash
# Save the Burp/ZAP request (headers + body) to req.txt, then:
injekt --raw-file req.txt --threads 5
# --raw-file takes priority over --target; parser supports multipart + auto Content-Type.
```

---

## CLI Reference

See [Full Documentation](DOCUMENTATION.md#cli-reference) for complete option tables and examples.

```
injekt [OPTIONS] [COMMAND]

Commands:
  scan    Run detection (default when --target is given)
  recon   Crawl targets, discover parameters, scan candidates, import candidate JSON
  replay  Replay encrypted session
  info    Show version / techniques / DBMS
  mcp     MCP server over stdio (Claude Code, Codex, OpenCode, Cursor, VS Code)

Options:
  -u, --target <URL>              Target URL (--raw-file takes priority if both given)
  -m, --bulk-file <PATH>          Bulk scan: one target/line, `#` comments skipped, max 1000
                                  (conflicts with --target/--raw-file/--export-encrypted)
      --profile <NAME>            Preset: quick|balanced|stealth|aggressive (explicit flags win)
      --config <PATH>             TOML config file (default: ./injekt.toml, ~/.config/injekt/config.toml)
      --raw-file <PATH>           Burp/ZAP raw request file (alternative to --target)
      --method <METHOD>           HTTP method (default GET)
      --headers <H1,H2>           Extra headers (comma-separated)
      --cookies <STR>             Cookies (SecretString, redacted in logs)
      --data <STR>                POST body to test (alternative to --raw-file)
  -p, --params <LIST>             Test only these params (e.g. -p id, -p body:user,cookie:PHPSESSID)
      --proxy <URL>               http(s):// or socks5h:// (socks5:// rejected - DNS leak)
      --threads <N>               Concurrency [default: 5]
      --timeout <SEC>             Request timeout [default: 30]
      --retries <N>               Max retries [default: 3]
      --delay <MS>                Base retry delay, exponential backoff [default: 500]
      --rate-limit <RPS>          Token-bucket req/s [default: 10]
      --jitter <MEAN,STD>         Milliseconds, e.g. "750,250" [default: 750,250 — on even without the flag]
      --techniques <LIST>         boolean,time,error,union,stacked,oob,json,all [default: all]
      --fetch-using <MODE>        Force oracle: direct, boolean or time (narrows techniques)
      --tamper <LIST>             WAF tampers: space2comment,space2plus,space2tab,space2newline,space2randomblank,space2dash,randomcase,versionedcomment,betweencomment,randomcomments,equaltolike,charencode,doubleurlencode,hexencode,unicodeencode,overlongutf8,base64encode [default: none, auto space2comment on WAF 403/406]
      --hpp                       HTTP Parameter Pollution: duplicate ?id=1&id=PAYLOAD (Query/Body)
      --chunked                   Chunked transfer: streamed Transfer-Encoding: chunked body (Body only)
      --prefix/--suffix <STR>     Payload prefix/suffix applied after tampers
      --safe-chars <STR>          Extra chars exempted from percent-encoding
      --skip-urlencode            Send payloads without URL-encoding (use with care)
      --string/--not-string <STR> Response must (not) contain substring, else veto finding
      --code <N>                  Response status must equal N, else veto finding
      --text-only                 Strip HTML tags/entities before matching
      --level <1-5>               Aggressiveness [default: 1]
      --confirm                   Strict second-pass confirmation (~2x requests, OOB skipped)
      --ignore-code <LIST>        Status codes treated as negative probes (e.g. 429,503)
      --oob-domain <DOMAIN>       Collaborator base domain (enables OOB probes, OPT-IN)
      --oob-poll-url <URL>        Poll URL with {token} placeholder (auto-confirm callbacks)
      --oob-wait-secs <N>         Wait before polling collaborator [default: 5]
      --dbms <KIND>               mysql|postgres|mssql|oracle (default: auto-fingerprint)
      --extract                   Enable data extraction (opt-in, SecretString)
      --dbs/--tables/--columns/--dump  Enumeration (needs --extract or recon --auto-enumerate)
  -b, --banner, --current-user, --current-db, --hostname  Identity enumeration
      --db/--table/--column <NAME>  Enumeration scope; --start/--stop/--count for dumps
      --marker <STR>              Injection marker (*, §, {{}})
      --output <PATH>             JSON report path (0o600 on Unix)
      --export-encrypted <PATH>   Encrypted snapshot (XChaCha20-Poly1305/Argon2id)
      --import <PATH>             Import encrypted snapshot
      --no-redact                 Disable scrubbing (local only!)
      --allow-private             Allow loopback/private IPs (anti-SSRF bypass, lab only)
      --no-banner                 Suppress startup banner (stderr; stdout stays clean)
  -v, --verbose                   Debug logs (tracing)
  -h, --help
  -V, --version
```

Recon subcommands (note: recon takes `--target`, not `-u`):

```bash
injekt recon crawl --target <HOST|URL> [--depth N] [--max-pages N] [--max-per-template N] [--include-subdomains] [--ignore-robots]
injekt recon scan --target <HOST|URL> [--depth N] [--max-pages N] [--auto-enumerate]
injekt recon import --file discovered.json [--test] [--enumerate]
```

### Presets & config (non-breaking)

| Preset | Threads | Rate | Jitter (ms) | Level | Techniques |
|---|---|---|---|---|---|
| `quick` | 10 | 20/s | 200,100 | 1 | boolean,error |
| `balanced` | 5 | 10/s | 750,250 | 1 | all (= historical defaults) |
| `stealth` | 2 | 3/s | 1200,400 | 1 | boolean,error |
| `aggressive` | 8 | 10/s | 500,200 | 3 | all |

Precedence: explicit CLI flag > `INJEKT_*` env > config file > `--profile` > built-in defaults.
No preset ever sets a proxy or enables extraction — those stay explicit opt-in.

```toml
# injekt.toml (or --config <PATH>, or ~/.config/injekt/config.toml)
profile = "stealth"
threads = 2
rate_limit = 3.0
jitter = "1200,400"
timeout = 30
retries = 3
delay = 800
level = 1
techniques = ["boolean", "error"]
proxy = "socks5h://127.0.0.1:9050"
```

Env: `INJEKT_PROFILE`, `INJEKT_CONFIG`, `INJEKT_THREADS`, `INJEKT_TIMEOUT`,
`INJEKT_RETRIES`, `INJEKT_DELAY`, `INJEKT_RATE_LIMIT`, `INJEKT_JITTER`,
`INJEKT_TECHNIQUES`, `INJEKT_LEVEL`, `INJEKT_PROXY`, `INJEKT_DBMS`, `INJEKT_TAMPER`.

---

## OPSEC

See [`docs/OPSEC.md`](docs/OPSEC.md) and [Full Documentation](DOCUMENTATION.md#opsec-features) — summary:

- **No disk writes** unless `--export-encrypted`; `SessionState` is `Arc<RwLock<…>>` and `ZeroizeOnDrop`.
- **Scrubber** (`src/session/scrubber.rs`): `Authorization`, `Cookie`, `Set-Cookie`, `X-Api-Key`, JWT `eyJ…`, `AKIA[0-9A-Z]{16}`, PEM → `[REDACTED]` or 8-hex hash.
- **Identity** (`src/http/identity.rs`): realistic UA pool (Chrome 126 / Firefox 128 / Safari 17.5) with matching `Sec-CH-UA`.
- **Jitter** (`src/http/jitter.rs`): `rand_distr::Normal` in **milliseconds**, never regular cadence (default 750±250ms, floor 200ms — active even without `--jitter`).
- **Rate limit**: token bucket, default **10 req/s** unless `--rate-limit` is set.
- **Proxy** (`src/http/proxy.rs`): `socks5h://` enforces remote DNS; `socks5://` without `h` is rejected.
- **TLS**: `rustls` (stable JA3 fingerprinted — documented limitation; use external proxy for JA3 randomization).
- **NEVER** `--no-redact` on shared reports.

---

## Architecture

See [Full Documentation](DOCUMENTATION.md#architecture) for detailed module structure and design patterns.

```
src/
├── main.rs / lib.rs
├── cli/{args,profile,file_config,commands/{scan,recon,replay,info},output/{console,json,format}}
├── target/{url,raw_request,parameters,markers}
├── http/{client,identity,proxy,cookies,redirects,retry,jitter,rate_limit}
├── detection/{baseline,response_diff,confirmation,scanner/{engine,scheduler}}
├── techniques/{boolean,time,error,union,stacked,oob,json}/{detector,payloads} (+oob/verifier) + tamper (WAF evasion) + request_tamper (HPP/chunked)
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

See [Full Documentation](DOCUMENTATION.md#development-workflow) for detailed workflow.

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
