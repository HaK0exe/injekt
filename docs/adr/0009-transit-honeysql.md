# ADR 0009: Transit JSON / HoneySQL Structured Query-Builder Injection

## Status
Implemented

## Context

Certain Clojure APIs use Muuntaja to decode request bodies. Muuntaja supports
`Content-Type: application/transit+json`, which can represent Clojure keywords
and nested maps that ordinary JSON cannot. When such a decoded structure is
passed, without strict validation, into a HoneySQL query builder, the map can be
interpreted as a SQL query shape rather than as a plain value.

Example payload:

```http
Content-Type: application/transit+json

["^ ","~:user-id",["^ ","~:from",["~:core_user"],"~:select",["~:password"]]]
```

Decoded conceptually:

```clojure
{:user-id {:from [:core_user]
           :select [:password]}}
```

If HoneySQL interprets `{:user-id ...}` as a subquery, the resulting SQL can
become:

```sql
SELECT password FROM core_user
```

This is not classic SQL injection through a string parameter. It is a
**typed serialization / query-builder injection**: type confusion plus unsafe
interpretation of user-controlled structured data.

This technique is relevant for authorized bug bounty and targeted Clojure API
testing, but it is not a universal SQLi payload. It requires all of the
following:

1. The endpoint accepts `application/transit+json`.
2. The backend decodes it with Muuntaja or an equivalent Transit decoder.
3. The decoded value reaches HoneySQL without coercion/validation.
4. HoneySQL interprets the value as a query/map/subquery.
5. The resulting behavior is observable or demonstrable.

## Decision

Introduce a dedicated technique family, tentatively named `transit` (CLI:
`transit` or `structured-query-builder`), instead of forcing it into the
existing `json` or `error` techniques.

The technique should be **opt-in**, **non-destructive by default**, and built
around structured probes rather than classic SQL strings.

## Proposed module layout

```text
src/techniques/transit/
  mod.rs
  encoder.rs       # minimal Transit JSON encoder for Clojure maps/keywords
  payloads.rs      # non-destructive HoneySQL-shaped probes
  detector.rs      # response/error/behavior comparison
  scan.rs          # Technique impl + TechniqueCtx integration
```

## Required changes

### 1. Technique kind

Add to `src/session/state.rs`:

```rust
pub enum TechniqueKind {
    ...
    Transit,
}
```

Display:

```rust
Self::Transit => write!(f, "transit"),
```

Remediation guidance should state:

- Do not pass decoded client-controlled maps directly to HoneySQL.
- Coerce expected scalar inputs before query construction.
- Validate and allow-list expected keys/types.
- Reject unexpected Transit/JSON structures.
- Use parameterized values or explicit query templates.

### 2. CLI technique option

Add to `src/cli/args/detection.rs`:

```rust
pub enum TechniqueOpt {
    ...
    Transit,
    All,
}
```

Default scan technique list should keep `transit` out of the default vec, like
`json`, `stacked`, and `oob`, unless explicitly requested.

### 3. Technique registry

Add to `src/techniques/mod.rs`:

```rust
pub mod transit;
```

Add to `technique_for`:

```rust
&crate::techniques::transit::scan::TransitTechnique,
```

Update the registry array size from 8 to 9.

### 4. Transit encoder

Implement a minimal, dependency-free encoder for the subset needed by probes.

Initial supported forms:

- keyword: `~:name`
- map: `["^ ", "~:key", value]`
- vector: `["~#list", [...]]` or Transit vector form depending on needed shape
- scalar strings/numbers

The encoder must:

- never panic;
- return `Result<String, InjektError>` or a safe fallback;
- avoid embedding secrets;
- be covered by unit tests;
- not require a full Transit implementation.

First encoder target:

```rust
encode_map(&[("user-id", encode_map(&[("select", vec![1])]))])
```

Expected output shape:

```json
["^ ","~:user-id",["^ ","~:select",[1]]]
```

### 5. Payloads

Payloads should be **non-destructive** and **minimal**.

Initial probe set:

| Probe | Clojure shape | Purpose |
|---|---|---|
| `select-one` | `{:user-id {:select [1]}}` | Detect whether a scalar input becomes a subquery |
| `select-constant` | `{:user-id {:select [1] :from [[:dual]]}}` | Detect query-builder interpretation with explicit from |
| `boolean-true` | `{:user-id {:select [1]}}` | Compare against baseline true behavior |
| `boolean-false` | `{:user-id {:select [0]}}` | Compare against baseline false behavior |
| `error-probe` | malformed/incomplete Transit or HoneySQL-shaped map | Trigger decoder/builder errors |

Payloads should carry:

```rust
pub struct TransitPayload {
    pub name: String,
    pub transit_body: String,
    pub expected_sql_shape: Option<String>,
    pub dbms_hint: Option<String>,
}
```

Do not include destructive extraction payloads in the initial version. Extraction
can be considered only after detection is stable and authorized.

### 6. Content-Type handling

The technique must force:

```http
Content-Type: application/transit+json
Accept: application/json
```

Important architectural note: Transit probes usually replace the **whole request
body**, not a single body field. Therefore this is closer to a request-level
tamper/body mode than to standard per-parameter injection. Initial integration
should either:

- add a request-body injection path for whole-body replacement; or
- provide a dedicated `--transit` / recon mode that sends Transit bodies
  directly.

Standard `json:/...` path injection is not sufficient for Transit.

### 7. Detection strategy

Use a multi-signal detector:

1. **Boolean differential**
   - Send true probe and false probe.
   - Compare pre-processed response bodies.
   - Use existing 3-trial confirmation logic.

2. **Error channel**
   - Look for Clojure/HoneySQL/SQL error strings.
   - Require error context, not just payload echo.
   - Examples:
     - `clojure`
     - `honey`
     - `muuntaja`
     - `transit`
     - SQLSTATE/vendor error strings
     - `invalid`
     - `exception`

3. **Behavioral signal**
   - Baseline body vs probe body.
   - Unexpected type interpretation, such as returning a column value instead
     of an object.
   - Status code changes only as supporting signal, never sole proof.

4. **Reproducibility**
   - Repeat probe at least 3 times.
   - Reject findings if responses are unstable.

Confidence should start conservative, e.g. `0.7` for boolean differential and
`0.8` for error channel with strong context.

### 8. Engine integration

Add `test_transit_bounded` after `json` and before `oob`.

Flow:

1. Determine whether the target is a JSON body endpoint.
2. For each probe and tamper set:
   - send true probe;
   - send false probe;
   - run boolean differential;
   - send error probe;
   - run error detection.
3. First confirmed signal wins.
4. Record evidence with:
   - `channel=boolean|error|behavior`
   - `probe=select-one|...`
   - `content_type=application/transit+json`
   - `tamper=...`

The technique should honor:

- cancellation;
- `--max-duration`;
- ignore codes;
- bounded payload budgets;
- scrubber/no-redact rules.

### 9. Tamper interaction

Most Transit payloads must remain valid Transit JSON. Therefore:

- String tampers should not be applied to the whole Transit body by default.
- If tampers are used, apply them only to string leaves or disable tampers for
  this technique.
- Prefer `none` tamper set initially.
- Document that WAF bypass for Transit may require separate research.

### 10. Tests

Unit tests:

- encoder produces expected Transit JSON;
- encoder never panics on arbitrary strings;
- payloads are non-empty and distinct;
- detector rejects payload echo without error context;
- detector accepts strong Clojure/HoneySQL/SQL errors.

Integration tests (`tests/integration_transit.rs`):

1. Mock Clojure API interprets `{:select [1]}` as subquery and returns
   `1`.
2. Boolean differential finds the vulnerability.
3. Error-only mock finds via `channel=error`.
4. Static/normal JSON endpoint yields no finding.
5. Technique fires under `--techniques transit`.
6. Technique does not fire under default technique list unless requested.

Proptest:

- encoder never panics;
- detector never panics;
- no finding without sufficient evidence.

### 11. Documentation

Add:

- `docs/adr/0009-transit-honeysql.md` status updated to Implemented when done.
- Playbook section: Clojure/Transit/HoneySQL testing.
- README technique list update.
- MCP/tool descriptions if exposed.

## Phases

### Phase 1: Research and fixtures

- Collect real Muuntaja Transit examples.
- Verify HoneySQL map-to-subquery behavior.
- Build wiremock fixtures.
- Define expected error strings.

Deliverable: test fixtures + ADR refinement.

### Phase 2: Encoder and payloads

- Implement minimal Transit encoder.
- Add payload structs.
- Add unit tests.

Deliverable: `src/techniques/transit/encoder.rs`, `payloads.rs`.

### Phase 3: Detector

- Implement boolean/error/behavior detection.
- Reuse existing matcher and confirmation helpers.
- Add unit tests for false positives.

Deliverable: `src/techniques/transit/detector.rs`.

### Phase 4: Technique and engine wiring

- Implement `TransitTechnique`.
- Add `TechniqueKind::Transit`.
- Add CLI option.
- Wire into engine.
- Update registry.

Deliverable: end-to-end opt-in scan support.

### Phase 5: Integration tests and hardening

- Add `tests/integration_transit.rs`.
- Run `cargo fmt`, `cargo clippy -- -D warnings`, `cargo test`.
- Review snapshots if added.

Deliverable: stable, tested feature.

### Phase 6: Documentation and reporting

- Update playbook, README, ADR.
- Add remediation guidance.
- Add examples.

Deliverable: user-facing documentation.

## Risks and limitations

1. **False positives**: a normal API may accept Transit and return 200 without
   SQL interpretation.
2. **Framework specificity**: only relevant to Clojure/Muuntaja/HoneySQL stacks.
3. **Content-Type switching**: may be blocked by WAFs or proxies.
4. **Encoder complexity**: full Transit support is large; initial version must
   stay minimal.
5. **Ethical scope**: this technique can expose sensitive data if misused.
   It must remain opt-in, non-destructive, and clearly documented as
   authorized-use only.

## Alternatives considered

1. **Add payloads to `json` technique** — rejected: different serialization
   format, different Content-Type, different detection semantics.
2. **Manual only, no injekt support** — acceptable short-term, but a dedicated
   module keeps evidence and reporting clean.
3. **Full Transit parser/encoder dependency** — rejected initially: too much
   surface area; a minimal encoder is safer and easier to audit.

## Recommendation

Proceed with Phase 1 and Phase 2 first. Do not wire the technique into the
default scan until fixtures and false-positive behavior are validated.