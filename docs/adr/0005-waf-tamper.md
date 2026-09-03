# ADR 0005: WAF Evasion via Tamper Scripts

## Status
Implemented

## Context
WAFs (Cloudflare, ModSecurity, AWS WAF, Imperva) block common SQLi payloads by
matching signatures: ` OR 1=1`, `UNION SELECT`, whitespace, or keywords. Current
`injekt` payloads are literal (`' OR 1=1 -- -`, `SLEEP(...)`, `ORDER BY 4`)
and are trivially fingerprinted. `sqlmap`'s `tamper/` directory (70+ scripts)
demonstrates that lightweight payload transformations — without infra — bypass a
large fraction of signature WAFs.

We need WAF evasion that:
1. Works without external infra (unlike OOB)
2. Is composable and bounded (no `2^t` explosion)
3. Integrates with all techniques (boolean, error, time, union, stacked, oob)
4. Preserves OPSEC (still rate-limited, jittered, no extra persistence)
5. Is opt-in via `--tamper` but auto-enables a safe default when WAF is suspected

## Decision
Introduce `src/techniques/tamper.rs` with 13 tampers mapped from `sqlmap` +
`PayloadsAllTheThings` and Black Hat USA 2024 WAF bypass research.

### Tamper Catalogue
| Tamper | Transform | Origin | DBMS scope |
|--------|-----------|--------|------------|
| `space2comment` | `" "` → `/**/` | sqlmap `space2comment` | generic |
| `space2plus` | `" "` → `+` | RFC 1738 | generic |
| `space2tab` | `" "` → `%09` | `space2randomblank` | generic |
| `space2newline` | `" "` → `%0a` | WAF whitespace variants | generic |
| `space2randomblank` | `" "` → random `%09/%0a/%0c/%0d/%a0/+` | sqlmap `randomblank` | generic |
| `randomcase` | `SeLeCt` | sqlmap `randomcase` | generic |
| `versionedcomment` | `SELECT` → `/*!50000SELECT*/` | MySQL versioned | MySQL |
| `betweencomment` | `SELECT` → `S/**/E/**/L...` | `between` | generic |
| `charencode` | `'` → `%27` (percent) | `charencode` | generic |
| `doubleurlencode` | `%27` → `%2527` | double URL | generic |
| `hexencode` | `AB` → `%41%42` | `hexencode` | generic |
| `unicodeencode` | `A` → `%u0041` | unicode | generic* |
| `overlongutf8` | `/` → `%c0%af` | UTF-8 overlong | generic |

`*` `unicodeencode` is accepted by some Java/WAF stacks (IIS); harmless elsewhere.

### Composition & Bounding
- CLI: `--tamper space2comment,randomcase` (comma-separated, `value_delimiter = ','`)
- `parse_tamper_list(Some("a,b")) -> Vec<Tamper>` — unknown names warn via `tracing::warn!`
- `tamper_transformation_sets(&tampers) -> Vec<Vec<Tamper>>` returns `[]` + each single + full chain; deduped. For `t = [a,b,c]` -> 5 sets (`t.len()+2`), not `2^t`.
- `apply_tampers(payload, &set) -> String` applies sequentially.
- Paired payloads (boolean TRUE/FALSE) use the same transformation set to keep comparison valid.

```rust
let sets = tamper_transformation_sets(&tampers);
for trans in &sets {
    let true_p = apply_tampers(&base_true, trans);
    let false_p = apply_tampers(&base_false, trans);
    // 3 trials per variant, break on confirm
}
```

Evidence records `tamper=space2comment` or `tamper=none`.

### Integration Points
- `EngineConfig.tampers: Vec<Tamper>` — cloned into async detection workers via `Arc<Vec<Tamper>>`
- Detection: `test_boolean_bounded`, `test_error_bounded`, `test_time_bounded`, `test_union_bounded` (incl. `enumerate_columns_via_order_by`), `test_stacked_bounded`, `test_oob_bounded` all loop over `tamper_transformation_sets`
- Extraction: `LENGTH` / `ASCII(SUBSTRING)` oracle payloads use `apply_tampers(&base, &effective_tampers)` (single chain, not expanded, to keep binary search bounded)
- Enumeration: `extract_enum_field` accepts `&[Tamper]` and tampers both length and oracle payloads
- WAF auto-fallback: if `baseline.is_waf_blocked() && tampers.is_empty()` then `effective_tampers = [Space2Comment]` with `info!` log. Preserves bounded requests while giving a free bypass attempt.

### What Is Out of Scope
- **Chunked transfer** (`Transfer-Encoding: chunked`) — requires `reqwest` streaming body, not just payload string transform. Documented as future HTTP-level tamper.
- **HPP** (duplicate `?id=1&id=payload`) — requires `RequestSpec` duplication, not string transform. Future request-level tamper.
- **Whitespace overlong beyond 2-byte** (e.g. `%c0%80`) — covered by `overlongutf8`.

### CLI & Reporting
```bash
injekt --target "https://ex/?id=1" --tamper space2comment,randomcase
injekt --target "https://ex/?id=1" --tamper versionedcomment,charencode --techniques union
injekt info  # lists Techniques + Tampers + DBMS
```
`info` prints `Tampers: space2comment, ...`. Evidence: `boolean ... tamper=space2comment`.

### Testing
- Unit: `src/techniques/tamper.rs` 20 tests (parse, each tamper, expand dedupe, chain order)
- Integration: `tests/integration_tamper.rs` 6 tests
  - `tamper_space2comment_bypasses_waf_boolean` — wiremock WAF mock blocks `+or+` but allows `/**/`, verifies finding with tamper label
  - `without_tamper_waf_blocks_boolean` — same mock without tamper yields 0 findings
  - `tamper_versionedcomment_produces_evidence` — etc.
  - Bounded `expand` / `tamper_transformation_sets` to `t.len()+2`

### Consequences
Positive:
- Bypasses signature WAFs without infra
- Bounded request blowup (`t.len()+2` not exponential)
- Composable with existing techniques and recon

Negative:
- More requests per parameter (up to 5x) — still bounded and rate-limited
- `randomcase`/`space2randomblank` are non-deterministic — evidence is still deterministic per run, but replay with same seed may differ (acceptable; documented)

Risks:
- Aggressive tamper combos could still trigger WAF rate-limit — mitigated by jitter/rate-limiter + bounded sets

### Alternatives Considered
1. **Per-payload `encode_payload` only** (previous `boolean/payloads.rs`) — insufficient, no keyword wrapping, no whitespace variants
2. **External tamper binary** — adds dependency, breaks zero-persistence
3. **Full `2^t` expansion** — exponential request blowup, DoS risk

## References
- OWASP WAF Evasion, PayloadsAllTheThings SQLi
- sqlmap `tamper/` (`space2comment`, `randomcase`, `charencode`, `versionedkeywords`, `between`)
- Black Hat USA 2024 WAF bypass
- `docs/RESEARCH_NOTES.md` § Évasion WAF
