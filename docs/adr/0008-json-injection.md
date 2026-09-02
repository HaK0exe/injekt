# ADR 0008: JSON-Function SQL Injection

## Status
Implemented

## Context
Apps storing JSON (configs, preferences, API blobs) splice user input into
`JSON_EXTRACT` / `->>` / `JSON_VALUE` expressions. A quote break-out there is
classic SQLi in a JSON context, but signature WAFs tuned for `OR 1=1` and
detectors probing only bare comparisons can miss it. `docs/RESEARCH_NOTES.md`
listed JSON injection (`JSON_EXTRACT`, `->>` on MySQL 8.x / Postgres 15+) as
roadmap; vendor error strings are now verified (see References).

We need JSON coverage that:
1. Probes the JSON-function context per DBMS (boolean differential)
2. Exploits JSON parsing errors as an error channel (often the only signal)
3. Reuses tamper variants, HPP/chunked request shape and confirmation logic
4. Attributes DBMS for fingerprint like every other technique

## Decision
Introduce `src/techniques/json/` with payloads + dual-channel detector,
wired as a first-class technique (`json`, included in `all`, opt-in explicit).

### Payloads (`payloads.rs`)
`JsonPayload{true_payload, false_payload, error_payload, dbms}`,
`json_payloads_for(dbms)` — 2 base payloads per DBMS, generic fallback covers
mysql + postgres + mssql (same `take(2)` convention as other techniques):

| DBMS | Boolean pair | Error probe (`__bad__` sentinel doc) |
|------|--------------|--------------------------------------|
| mysql | `JSON_EXTRACT('{"k":1}','$.k')=1/2`, `'{"k":1}'->>'$.k'='1'/'2'` | `JSON_EXTRACT('__bad__','$')` → `Invalid JSON text` |
| postgres | `('{"k":1}'::json->>'k')='1'/'2'`, `::jsonb` variant | `('__bad__'::json->>'k')` → `invalid input syntax for type json` |
| mssql | `JSON_VALUE('{"k":1}','$.k')='1'/'2'`, `OPENJSON … WHERE [key]='k'` | `JSON_VALUE('__bad__',…)` → `JSON text is not properly formatted` (Msg 13609) |
| oracle | `JSON_VALUE('{"k":1}','$.k')='1'/'2'`, `JSON_EXISTS` CASE pair | `JSON_VALUE('{"k":1}','$..[')` → `ORA-40442` (malformed path) |

Comments follow the per-DBMS convention (`-- -` mysql, `--` others).
`BAD_DOC = "__bad__"` is exported so mocks/tests key off the same sentinel.

### Detector (`detector.rs`)
- Boolean channel: delegates to the shared `BooleanDetector` (same TRUE≈
  baseline / FALSE≠baseline semantics, 3-trial confirmation upstream).
- Error channel: per-DBMS JSON error regexes **plus mandatory error context**
  (`error|exception|ora-|msg |sql`) — a page merely echoing the payload is
  not a finding. Match → confidence 0.9 with `dbms` + `matched_pattern`.

### Engine integration
- `test_json_bounded` (after `stacked`, before `oob`): per base payload ×
  tamper set → boolean pair first, then single-shot error probe; first
  confirm wins. Evidence carries `channel=boolean|error`, `dbms`, `tamper=`
  and the HPP/chunked suffix.
- `TechniqueKind::Json` (`json`); boolean-channel findings set
  `dbms = payload.dbms`, so `guess_from_findings` fingerprints for free.
- `json` is in `all` but **not** in the default technique vec (same as
  `stacked`/`oob`) — no extra requests unless asked.
- Extraction/enumeration reuse the boolean oracle unchanged.

### CLI
```bash
injekt --target "https://ex/?id=1" --techniques json --dbms mysql
injekt --target "https://ex/?id=1" --tamper space2comment --techniques json
```

## Testing
- Unit (13): payload shape per DBMS (comments, sentinels, pair prefixes),
  error detection per vendor string, echo-without-context rejection, boolean
  channel true/false behaviour via the shared detector.
- Integration (`tests/integration_json.rs`, 4): boolean channel finds +
  `dbms=mysql` attribution; error-only mock finds via `channel=error`;
  fires under `all`; static page yields no finding.
- Proptest (2): payload generation never panics / non-empty over arbitrary
  DBMS inputs; detector never panics, never vulnerable without error context.

## Consequences
Positive: JSON-context endpoints covered on all four DBMS; error channel
catches fully-blind JSON points; zero new infra; bounded requests
(`take(2)` × tamper sets, same as siblings).

Negative: Oracle `JSON_VALUE` lax mode may return NULL instead of erroring
on some malformed docs — the malformed-*path* probe is the reliable Oracle
signal; quoted-string JSON columns (`'{"k":1}'` literal form) assume the app
compares extracted text, which may not match every backend.

## Alternatives Considered
1. **Reuse `error` technique with JSON payloads appended** — rejected: mixes
   channels and DBMS attribution; a dedicated technique keeps evidence clean.
2. **Boolean-only (no error channel)** — rejected: JSON endpoints are often
   blind; the error probe is the cheapest high-signal request.
3. **Time-based JSON (`JSON_EXTRACT` + `SLEEP`)** — deferred: composes poorly
   (function nesting varies per DBMS); boolean+error covers detection.

## References
- MySQL 8.x `JSON_EXTRACT` / `->>` / `JSON_UNQUOTE`; `Invalid JSON text in
  argument 1 to function json_extract` (verified via StackOverflow reports)
- Postgres `->` / `->>` / `::json` cast; `invalid input syntax for type json`
  (SQLSTATE 22P02)
- MSSQL `JSON_VALUE` / `OPENJSON`; `JSON text is not properly formatted`
  (Msg 13609, MS docs)
- Oracle `JSON_VALUE` / `JSON_EXISTS`; ORA-40442 path syntax / ORA-40454
  path-not-literal (Ask TOM, Oracle forums)
- `docs/RESEARCH_NOTES.md` § Techniques d'injection (JSON roadmap item)
