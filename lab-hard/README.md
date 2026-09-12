# lab-hard/ — HARD lab full-2026 (injekt vs sqlmap vs ghauri)

**INTENTIONALLY VULNERABLE — lab only. Never expose to the internet.**
Isolated from `bench/` (ports 9000/9082/9080/9360/9432/9533, db `hard`).

Calibrated on 2026 web research: LiteLLM CVE-2026-42208 (Bearer → PG UNION),
Team82 JSON-SQLi, PortSwigger OOB, Hive 2026 5 types, Gecko Apr-2026
(auth-flow + ORM `whereRaw` + second-order).

## Layout

```text
lab-hard/
  docker-compose.yml   app + mysql:8.4 + postgres:17 + mssql:2022 + [oracle:23ai opt-in] + collab + waf-strict (CRS4 PL2)
  app/                 FastAPI HARD (H1-H15 + N3-N5, INTENTIONALLY VULNERABLE)
  db/{mysql,pg,mssql,oracle}/seed.sql
  collaborator/        self-hosted OOB (HTTP /poll/{token} + DNS log, stdlib only)
  waf/                 CRS4 PL2 strict overlay + ban 10x403/60s => 429
  runner/              scenarios-hard.toml + run-hard.py (stdlib only)
  reports/             gitignored (summaries + history-hard.jsonl + raw/)
```

## Quick start

```bash
cd lab-hard
docker compose up --build -d
sleep 15  # mssql needs ~10-20s on first boot
python3 runner/run-hard.py reset
python3 runner/run-hard.py check-canary   # mysql/pg/mssql must read 'untouched'
curl -s 'http://127.0.0.1:9000/' | head -c 200
curl -s 'http://127.0.0.1:9082/' -o /dev/null -w '%{http_code}\n'  # WAF up
curl -s 'http://127.0.0.1:9080/health'    # collab up
```

Oracle (opt-in, ~2 CPU/2 Go, ~10 min first boot):

```bash
docker compose --profile oracle up --build -d
```

## Run a scenario (injekt)

```bash
export INJEKT_BIN=$PWD/../target/release/injekt   # or cargo run fallback
python3 runner/run-hard.py run --scenario H1 --mode power
python3 runner/run-hard.py run --scenario H1 --mode stealth --arm evasion
python3 runner/run-hard.py run --scenario H6 --mode power --arm oob   # collab proof
python3 runner/run-hard.py run --scenario H12 --mode power --arm hpp
```

Arms: `stock` (no tamper, must FAIL on H1/H11/H12/H16 = proof HARD) +
`evasion` (scenario tamper) + `hpp` (H8/H12) + `oob` (H6/H7, auto
`--oob-domain oob.labhard --oob-poll-url http://127.0.0.1:9080/poll/{token}`).
Second-order H9: register a payload first, then scan the profile:

```bash
curl -s -X POST http://127.0.0.1:9000/h/register \
  -H 'Content-Type: application/json' -d '{"nick":"x'"'"' OR '"'"'1'"'"'='"'"'1","bio":"t"}'
```

Every repeat: run → parse `--output` JSON → cross-check
`engine done requests=N` vs `request_count` → assert canary → append
`history-hard.jsonl`. Tripwire `marker != 'untouched'` **rejects the run**
(exit 3). Exit codes: 0 ok / 1 compare regression / 2 spec error / 3 canary.

## Compare / matrix

```bash
python3 runner/run-hard.py compare --baseline reports/history-hard.jsonl --candidate <other>
python3 runner/run-hard.py matrix --mode power
```

`compare` prints OK/IMPROVED/SAME-MISS/REGRESSION per (scenario,mode,arm);
detections on N3/N4/N5 warn FP on stderr. FP-only warns, exits 0.

## Why this lab is HARD

- Errors fully masked (200 generic) — error-based must fail (except H15 confirm).
- `request_id` + `generated_at` noise breaks naive diffing.
- H1 spaces-filter + H11 gauntlet (spaces + `/**/` + `/*!*/` blocked) force
  real tamper chains (`space2comment`/`space2tab`/`randomcase`/encodings).
- H6/H7 OOB-only: CONSTANT response, collab proof required (egress from DB).
- H9 second-order: POST stores safe, GET replays stored vuln.
- H12 HPP-only: `?id=1&id=PAYLOAD` uses last raw (naive WAF sees first).
- CRS4 PL2 strict + Authorization inspection (CVE-2026-42208) + ban 10x403→429.
- N3/N4/N5 negative controls + honeypot ban: any finding = FP.
- Fingerprint-trap H14: identical shape 4 engines, versions masked.

## OPSEC

- Lab only: `injekt --allow-private` required (loopback anti-SSRF bypass).
- OOB egress originates from target DB, not via `--proxy`.
- `socks5://` rejected (`DnsLeak`) — use `socks5h://`.
- Never commit `reports/`, `*.enc`, raw Burp files.
