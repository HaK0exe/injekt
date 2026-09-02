# ADR 0007: Request-Level Tampers (HPP + Chunked Transfer)

## Status
Implemented

## Context
ADR 0005 (string tampers) explicitly left two WAF vectors out of scope because
they rewrite the HTTP request shape, not the payload string:
- **HPP** (HTTP Parameter Pollution): duplicate `?id=1&id=<PAYLOAD>`. Naive
  WAFs inspect only the first occurrence while backends (PHP/ASP) take the
  last — the malicious duplicate sails through.
- **Chunked transfer**: `Transfer-Encoding: chunked` bodies bypass WAFs that
  only inspect `Content-Length` bodies (Black Hat USA 2024, `docs/RESEARCH_NOTES.md`).

## Decision
Introduce `src/techniques/request_tamper.rs` (pure, testable helpers) plus
`ProbeOpts{hpp, chunked}` threaded through the engine, and real chunk framing
in `HttpClient`.

### Pure helpers (`request_tamper.rs`)
- `hpp_query_url(base, name, payload)` — keeps all original pairs, appends
  `name=payload` as duplicate (`?id=1` → `?id=1&id=<PAYLOAD>`).
- `hpp_body_str(existing, name, payload)` — same for form bodies.
- `should_apply_chunked(has_body, chunked)` — chunked only applies with a body.
- `chunk_body_pieces(body, size)` — split for streaming (reassembly-tested).
- `count_query_occurrences(url, name)` — never panics (proptest-friendly).

### Engine (`orchestrator.rs`)
- `ProbeOpts{hpp, chunked}` (`Copy`) — built once as `effective_opts` from
  `EngineConfig`, cloned into detection workers, captured by extraction /
  enumeration oracles. `evidence_suffix()` appends ` hpp=true chunked=false`
  to every finding (traceability, empty when inactive).
- `build_injection_spec_with_raw(..., opts)`:
  - Query + HPP → `hpp_query_url`; Body + HPP → duplicate field via
    `inject_body_param(..., hpp)`; Header/Cookie/markers unchanged.
  - Body + chunked → drops `Content-Length`, sets
    `Transfer-Encoding: chunked` (Query without body: documented no-op).
- All detection (`boolean/error/time/union` incl. ORDER BY `/stacked/oob`),
  extraction oracles (`LENGTH`, `ASCII(SUBSTRING)`) and `extract_enum_field`
  honour `opts`.

### HTTP (`http/client.rs`)
- `build_request` detects `Transfer-Encoding: chunked` in the spec and sends
  the body via `Body::wrap_stream` in 5-byte pieces → real chunk framing on
  the wire (verified server-side in tests), instead of `Content-Length`.
- Requires `reqwest/stream` feature + `bytes` dependency.

### CLI
```bash
injekt --target "https://ex/?id=1" --hpp --techniques boolean
injekt recon scan --target ex.com --hpp --chunked --auto-enumerate --dbs
```
`info` lists request tampers. Flags are global (work for `scan` and `recon`).

### Scope limits
- HPP targets Query/Body only (Cookie/Header duplication is backend-specific).
- Chunked targets Body only; Query + `--chunked` is a no-op (still finds
  normally — covered by test).
- No auto-enable (unlike `space2comment` on WAF 403/406): HPP doubles params
  and chunked changes framing, so both stay explicit OPT-IN.

## Testing
- Unit (`request_tamper.rs`, 10 tests): duplication, order preservation,
  empty-body edge, chunk split/reassembly, bad-URL counting.
- Proptest (5 new): tamper never-panics, HPP pair preservation/count,
  chunk reassembly for arbitrary bytes/sizes, OOB helper bounds.
- Integration (`tests/integration_request_tamper.rs`, 5 tests):
  - HPP bypasses a first-value-inspecting WAF mock (finding + `hpp=true`);
    same mock without `--hpp` yields 0 findings.
  - Chunked Body bypasses a content-length-inspecting mock (finding +
    `chunked=true`); without `--chunked`, 0 findings.
  - Client-level: server observes `transfer-encoding: chunked` and the body
    reassembles byte-identical.

## Consequences
Positive: two more WAF classes bypassed with zero new infra; bounded cost
(no variant expansion — HPP/chunked are orthogonal flags, not multiplied with
tamper sets); evidence traces the active shape.

Negative: HPP doubles parameter bytes; chunked streaming adds framing
overhead; both rely on backend quirks (last-wins params, chunk-tolerant
servers) that vary per stack.

## Alternatives Considered
1. **HPP/Chunked as `Tamper` string variants** — rejected: they are not string
   transforms and need `RequestSpec`/client support.
2. **Auto-enable like `space2comment`** — rejected: shape changes are louder
   than a whitespace swap; stay explicit.
3. **Full `Transfer-Encoding` obfuscation (`x-chunked`, case mixing)** —
   deferred: hyper normalises framing headers.

## References
- `docs/RESEARCH_NOTES.md` § Évasion WAF (chunked, HPP)
- ADR 0005 § Out of Scope; Black Hat USA 2024 WAF bypass
