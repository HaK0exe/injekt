# ADR 0004: Auto-Discovery Crawler for SQLi Target Discovery

## Status
Proposed

## Context
Currently, `injekt` requires the user to provide a specific URL with an injectable parameter (e.g., `https://example.com/page?id=1`). Users often only have a domain name (e.g., `monplanq.com`) and want the tool to automatically discover vulnerable endpoints.

We need a reconnaissance phase that:
1. Crawls a given domain to discover URLs with parameters
2. Tests each parameter for SQL injection vulnerabilities
3. Runs enumeration on confirmed vulnerable parameters

## Decision
Introduce a new `recon` module with a `crawler` subcommand that performs automated discovery.

### Architecture

```
src/recon/
├── mod.rs              # Public API
├── crawler.rs          # HTTP crawler (HTML parsing, link extraction)
├── parameter.rs        # Parameter candidate representation
├── discovery.rs        # Orchestration: crawl → test → enumerate
└── filters.rs          # Scope/allowlist/denylist filtering
```

### Crawler Design
- **Static HTML parsing** (no headless browser initially) using `html5ever`/`scraper`
- Extract: `<a href>`, `<form action>`, `<input name>`, JS endpoints (basic regex)
- Respect `robots.txt` (optional, configurable)
- Configurable depth, max pages, same-domain-only vs subdomains
- Deduplication by normalized URL + parameter set

### Parameter Candidate
```rust
struct ParameterCandidate {
    url: Url,
    method: Method,
    param_name: String,
    location: ParameterLocation, // Query, Body, Cookie, Header
    param_type: ParamType,       // Input, Hidden, Select, Textarea, etc.
    form_context: Option<FormContext>,
}
```

### Discovery Orchestration
1. **Crawl** → collect `Vec<ParameterCandidate>`
2. **Filter** → deduplicate, scope, allowlist/denylist
3. **Test** → run baseline + detection per candidate (parallel, rate-limited)
4. **Report** → list vulnerable parameters with technique + confidence
5. **Enumerate** (optional `--auto-enumerate`) → run enumeration on confirmed vulns

### CLI Interface
```bash
# Discovery only
injekt recon crawl --target monplanq.com --depth 2 --max-pages 100

# Discovery + auto-test + enumerate
injekt recon scan --target monplanq.com --auto-enumerate --dbs

# Import discovered params from file
injekt recon import --file discovered.json --test --enumerate
```

### Integration with Existing Engine
- Reuse `Engine`, `EngineConfig`, `HttpClient` from `src/engine/`
- Share `baseline`, `detection`, `fingerprint`, `enumeration` phases
- Output compatible with `--output` / `--export-encrypted`

## Consequences
### Positive
- End-to-end workflow from domain → enumerated data
- No manual URL/parameter hunting needed
- Reuses existing robust detection/enumeration logic

### Negative
- Increased complexity (crawler, deduplication, scope management)
- False positives/negatives from static parsing (JS-heavy apps missed)
- Potential for aggressive crawling (rate limiting critical)
- Longer scan times

### Risks
- Legal/ethical: Only scan authorized targets (enforce via `--allow-private` + warnings)
- DoS risk: Built-in rate limiter + jitter mandatory
- Maintenance: Crawler needs updates for modern web patterns

## Alternatives Considered
1. **Headless browser (chromiumoxide/headless_chrome)** — Better JS support, heavier deps, slower
2. **External tool integration (gau, katana, hakrawler)** — Simpler, but adds external dependency
3. **Passive recon only (waybackurls, alienvault OTX)** — Misses hidden params, no auth context

## Implementation Phases
1. **Phase 1**: Basic static crawler + parameter extraction (HTML forms/links)
2. **Phase 2**: Deduplication, scope filtering, CLI `recon crawl`
3. **Phase 3**: Integration with detection engine (`recon scan --test`)
4. **Phase 4**: Auto-enumeration (`--auto-enumerate --dbs`)
5. **Phase 5**: Authenticated crawling (cookie/header import), JS endpoint discovery

## References
- OWASP Testing Guide: Crawling and Spidering
- SQLMap's `--crawl` option (reference implementation)
- `feroxbuster`/`katana` for crawler patterns