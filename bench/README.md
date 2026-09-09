# bench/ — Phase 1 benchmark lab (injekt vs sqlmap vs ghauri)

Local dev here, **official results on a dedicated stable runner**.
Oracle + OOB + UNION/JSON-as-group are **Phase 2** (see § Non-goals).

## Layout

```text
bench/
  docker-compose.yml   app + mysql:8.4 + postgres:17 + mssql:2022 + waf-pl1/pl2
  app/                 FastAPI target (INTENTIONALLY VULNERABLE — lab only)
  db/{mysql,pg,mssql}/seed.sql   identical data, per-dialect DDL
  runner/
    scenarios.toml     ground truth A1–A7 + N1–N2
    run.py             reset / run / check-canary / pin  (stdlib only)
  reports/             gitignored run artefacts
  versions.lock        frozen digests + tool versions for official runs
```

## Quick start (local)

```bash
cd bench
docker compose up --build -d
sleep 15  # mssql needs ~10-20s on first boot
python3 runner/run.py reset
python3 runner/run.py check-canary   # all three must read 'untouched'
curl -s 'http://127.0.0.1:8000/api/users?id=1' | head -c 300
curl -s 'http://127.0.0.1:8082/api/users?id=1' -o /dev/null -w '%{http_code}\n'  # WAF up
```

## Run a scenario (injekt)

```bash
export INJEKT_BIN=$PWD/../target/release/injekt   # or leave unset for cargo run
python3 runner/run.py run --scenario A1 --mode power
python3 runner/run.py run --scenario A1 --mode stealth
```

Modes: `power` (threads 10, jitter 200±100ms, rate 20/s, level 3 — OPSEC
handicap neutralised) vs `stealth` (threads 2, jitter 1200±400ms, rate 3/s,
level 1, boolean+error — stock behaviour, metric = request count, not time).
A3 additionally forces threads/rate under its 5/s server limit (see
`SCENARIO_FLAGS` in `run.py`, replacing — not duplicating — mode flags).

Arms: every scenario runs `stock` (no tamper) plus, when the sink has a
documented filter, `evasion` with the tool-appropriate bypass
(`scenarios.toml:evasion`, e.g. `--tamper space2comment`). A scenario is only
meaningful if at least one arm is solvable — verified manually before wiring.

Every repeat: reseed → run (600s timeout) → parse `--output` JSON
(`--force` overwrite per repeat) → assert `canary.marker == 'untouched'`
on all 3 DBs → summary JSON in `reports/` with per-arm detect rates.

## Freeze for official runs

```bash
python3 runner/run.py pin   # writes versions.lock (image digests + tool versions)
```

Record in the report: `versions.lock` content, runner specs, date.
Request counts in Phase 1 come from injekt's own `request_count`;
the official runner cross-checks against WAF/nginx access logs.

## WAF reality check (measured, not assumed)

- Image `owasp/modsecurity-crs:nginx` rolling tag pulled **CRS 3.3.10**
  (not 4.x — verify with `run.py pin`; digest frozen in `versions.lock`).
- CRS PL1/PL2 anomaly scoring (threshold 5) blocks the whole standard
  repertoire on query/cookie sinks: `OR`/`AND`/`UNION`/`ORDER BY`/`||`/`&&`,
  `/**/`/`/*!*/`, `--`, `SLEEP`/`BENCHMARK`/`IF(`/`EXTRACTVALUE` — probed
  and confirmed 403 one by one. Query-behind-WAF is therefore a documented
  **control** (expect 0/0/0), not a scored scenario.
- Custom headers (`X-User-Id`) are NOT inspected by CRS SQLi rules at PL1
  or PL2 → A6/A7 test the realistic vector-shift bypass.
- CRS PL2 rule 920320 (+5, missing User-Agent) blocks faceless probes:
  this caught injekt sending no UA on header probes (identity system was
  never wired into the client builders — fixed, one line each).
- Cookie sinks ARE inspected by CRS (403 control).

## Why this target is not basic

- Errors fully masked (HTTP 200 generic envelope) — error-based must fail.
- `request_id` + `generated_at` noise breaks naive string-compare diffing.
- App filters per endpoint (whitespace / `=` / case-sensitive blocklist)
  force real tamper usage; CRS PL1/PL2 in front of the same sink (A6/A7).
- N1/N2 negative controls: any finding there is a counted false positive.
- `canary` tripwire row flags destructive payloads.

## Non-goals (Phase 2)

Group B (UNION vs ghauri — unsupported upstream, TODO on its README),
JSON-function techniques, OOB + self-hosted collaborator, Oracle XE
(2 CPU/2 Go, ~10 min boot), sqlmap/ghauri matrix wiring in `run.py`.
