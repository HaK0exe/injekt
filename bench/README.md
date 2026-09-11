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
    scenarios.toml     ground truth A1–A7 + N1–N2 ([defaults] repeats=5, seed=42)
    run.py             reset / run / check-canary / pin / versions / compare / matrix (stdlib only)
    selftest.py        offline smoke test: parser fixtures, compare/matrix, jsonl validity
  reports/             gitignored run artefacts (+ raw/ full logs, history.jsonl)
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
A tripped canary (`marker != 'untouched'` on any DB, or an unreadable marker)
**rejects the run**: summary + `history.jsonl` rows are still written for
forensics (`canary_intact: false`), but `run` exits **3** and `check-canary`
exits **3** as well. Exit codes: `0` ok / no regression, `1` `compare`
regression, `2` spec/load error, `3` canary TRIPPED (run REJECTED).

Repeats default to **5** per arm (`scenarios.toml [defaults] repeats`,
overridable per invocation with `run --repeats N`).

Determinism: `run --seed BASE` (default `scenarios.toml [defaults] seed = 42`);
repeat *i* uses seed BASE+*i*. The seed is passed as injekt `--seed` when the
binary supports it (probed via `--help`; old binaries get a provenance-only
warning instead of a failure) and is **always** recorded in the summary and in
`history.jsonl`.

Request-count cross-check (C1 metrology): after each injekt run the harness
compares the engine log counter (`engine done ... requests=N` in stdout)
against the JSON report's `request_count` field. Two independent channels —
log line vs serialized field — so a mismatch (`[WARN] request_count MISMATCH`,
`request_count_match: false` in summary/history) means a serialization bug or
a stale report read. Caveat: both channels originate engine-side, so this does
NOT catch engine miscounts; the official runner cross-checks against WAF/nginx
access logs. No counter in the log (timeout/crash/old binary) → check skipped
(`match: null`), never silently passed.

Raw logs: full stdout/stderr of every repeat are kept on disk under
`reports/raw/<run_id>-<arm>-r<N>.stdout|stderr.log` (injekt today; sqlmap/ghauri
raw logs go to the same directory when Phase 1b live wiring lands).

## history.jsonl — every run appends, compares read

Each `run` repeat appends **one JSON line** to `reports/history.jsonl`
(override with `run --history PATH`; parent dirs created as needed).
Append-only, gitignored like the rest of `reports/`. Schema per line:

```json
{"ts": "2026-09-09T21:00:00Z", "run_id": "20260909T210000Z-injekt-A1-power-a1b2c3d4",
 "tool": "injekt", "tool_version": "injekt 0.3.0",
 "scenario": "A1", "mode": "power", "arm": "stock", "repeat": 1, "seed": 42,
 "result": {"detected": true, "techniques": ["Boolean"], "params": ["id@query"],
            "dbms": ["None"], "confidence": 0.74, "request_count": 143,
            "elapsed_s": 29.8, "rc": 0},
 "report": "reports/injekt-A1-power-stock-r1.json",
 "raw_stdout": "reports/raw/20260909T210000Z-injekt-A1-power-a1b2c3d4-stock-r1.stdout.log",
 "raw_stderr": "reports/raw/20260909T210000Z-injekt-A1-power-a1b2c3d4-stock-r1.stderr.log",
 "canary_intact": true, "request_count_match": true}
```

`run_id` groups the repeats of one invocation; `seed`, `tool_version` and the
normalized `result` make runs comparable across versions and tools.

## compare — baseline vs candidate, exit 1 on regression

```bash
python3 runner/run.py compare --baseline <history.jsonl|run-id|.summary.json> \
                              --candidate <history.jsonl|run-id|.summary.json> \
                              [--history reports/history.jsonl]
```

Each of `--baseline`/`--candidate` accepts an existing history.jsonl file, an
old `*.summary.json` (expanded to rows for pre-history comparisons), or a
run-id prefix resolved inside `--history`. Rows aggregate per
(scenario, mode, arm): detection (any repeat), avg `request_count`, avg elapsed.
Output is a human-readable table with a verdict per row (`OK` / `IMPROVED` /
`SAME-MISS` / `REGRESSION`); detections on N1/N2 negative controls print an
FP warning on stderr (`[warn] ... false positive`). C1 gate coverage: a
v0.3-baseline vs v0.4-regressed pair (candidate misses A2 and fires on N1)
yields verdict `REGRESSION` + exit 1 + FP warning; an FP-only candidate
(N1/N2 detections, nothing missed) warns but exits 0. Exit code: **1** if the candidate misses anything the baseline
found, **0** otherwise, **2** on spec/load errors.

## matrix — 3-tool × scenarios table from history

```bash
python3 runner/run.py matrix [--history reports/history.jsonl] [--mode power] [--tool injekt]
```

Reads history (live full-matrix execution stays manual via repeated `run`
invocations — a matrix run reseeds DBs and takes hours, so it is not a CI
job) and prints a compact per-tool table: scenarios covered, scenarios with
≥1 detection, detected repeats, avg requests (`-` when the tool reports none,
e.g. sqlmap/ghauri), avg time. `--tool` is repeatable for filtering.

## Tool parsers — one normalized shape

`parse_injekt_report(path)` plus `parse_sqlmap(text)` / `parse_ghauri(text)`
all return the same dict: `detected`, `techniques`, `params`, `dbms`,
`confidence`, `request_count`, `elapsed_s` (`None` where the source has no such
datum — key present, null value). sqlmap technique mapping: `boolean-based
blind→boolean`, `error-based→error`, `time-based blind→time`, `UNION
query→union`, `stacked queries→stacked`, `inline query→inline`;
`Parameter: id (GET)` → `id@get`. ghauri mirrors sqlmap's output wording
(`Parameter:`/`Type:`/`Title:`/`the back-end DBMS is ...`), so both share one
core parser; if upstream wording drifts, the kept raw logs are the fix source.
Neither tool prints confidence or a total HTTP request count in normal output
(counts need sqlmap's `-t` traffic file — future Phase 1b wiring).

## Offline smoke test (no docker, no network)

```bash
python3 runner/selftest.py   # 45 checks, exit 0 = green
```

Covers parser fixtures (vuln + clean logs per tool), cross-check
match/mismatch/skipped, `compare` exit codes (1/0/2 incl. run-id form,
v0.3-vs-v0.4 named REGRESSION, N1/N2 FP warnings incl. FP-only exit 0),
canary verdict (`canary_intact` pure helper + `run_verdict` exit 3 on
destructive state), `matrix` over a 3-tool fixture, json-lines validity, and `--help`/`versions`
entry points. CI (`.github/workflows/bench-smoke.yml`) runs `--help`,
`selftest.py`, a `scenarios.toml` ground-truth check (A1–A7+N1–N2, no docker),
a `versions.lock` format check, and the live docker path (A1+N1) only
when docker + a running lab are actually present (guarded, honest skip
otherwise).

## Freeze for official runs

```bash
python3 runner/run.py pin        # writes versions.lock (image digests + tool versions)
python3 runner/run.py versions   # print live tool versions only (no docker, no file write)
```

`pin` records the 4 image digests plus `tool:injekt|sqlmap|ghauri` one-line
versions (ANSI stripped). Fixed in C1: `tool:injekt` used to capture the
human/ANSI `info` output (multi-line garbage in the lock file); it now probes
`injekt --version`. The lock file carries a `# pinned_at <UTC>` header; image
lines are untouched by the fix (digests byte-identical). `versions` is the
read-only companion for CI/dev checks without docker.

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
(2 CPU/2 Go, ~10 min boot), sqlmap/ghauri *live-run* wiring in `run.py`
(parsers + history/compare/matrix are done; only the `run --tool sqlmap|ghauri`
execution path remains Phase 1b).
