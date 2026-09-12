# 07 — Automatisation (auto, bulk, MCP, utilitaires)

## 7.1 `auto` — pipeline ingestion → scan → escalade → enum

```bash
# URL directe → scan + escalade auto :
injekt auto --target "https://example.com/?id=1"
# Host nu → implique recon (crawl puis test) :
injekt auto --target example.com
injekt auto --target example.com --with-recon --depth 2 --max-pages 100
# Sans escalade (une passe) + énumération auto :
injekt auto --target "https://example.com/?id=1" --no-escalate
injekt auto --target "https://example.com/?id=1" --auto-enumerate --dbs
# Ingestions aussi supportées (bulk/raw-dir/openapi/sitemap/stdin via flags globaux) :
injekt auto --bulk-file targets.txt --output auto-report.json
injekt auto --target "https://example.com/?id=1" --dry-run   # plan sans requête
```

Escalade (sauf `--no-escalate`), **arrêt à la 1re passe avec findings**
(cibles saines = 1 passe, cibles WAF = jusqu'à 3) :

| Passe | Label | Config |
|---|---|---|
| 1 | `L1-baseline` | Config telle quelle |
| 2 | `L2-tamper` | `level ≥ 2` + `space2comment,randomcase,versionedfuzz` (si tampers vides) |
| 3 | `L3-evasion` | `level ≥ 3` + `space2comment,randomcase,charencode,equaltolike,numericobfuscate,linecomment` (si <6 tampers) + `text-only` + `hpp` |

`base64encode` n'est **jamais** auto-activé (casse boolean). Tampers explicites
conservés en L2/L3. `--auto-enumerate` force `extract=true`.

Quand l'utiliser : tri multi-cibles, re-test après fix, junior encadré.
Quand l'éviter : cible ultra-sensible au bruit (préférer scan manuel stealth L1),
besoin de contrôle fin des tampers/matchers par palier.

## 7.2 Bulk & ingest à grande échelle

```bash
# Bulk séquentiel : erreurs par cible enregistrées, boucle continue, rapport agrégé :
injekt --bulk-file targets.txt --output bulk-report.json --threads 3
# Limites : max 1000 (erreur dure), `#`/vides ignorés, doublons dédupliqués.
# Conflits : --bulk-file × --target/--raw-file ; --bulk-file × --export-encrypted (→ --output).
# --cookies/Authorization rejoués sur CHAQUE cible (warning) — bulk multi-clients = non.
```

`--raw-dir`, `--stdin`, `--openapi-file`, `--sitemap-file` : cf. chap. 2.4.
Toujours `--dry-run` sur ces ingest (volume surprise = dépassement de scope).

## 7.3 MCP (agent IA, stdio)

```bash
injekt mcp   # logs sur stderr, JSON-RPC sur stdout (jamais pollué)
```

| Outil | Rôle | Notes |
|---|---|---|
| `scan` | Scan URL | Quasi-parité CLI ; `output` relatif sans `..`, `0o600` ; `export_encrypted` rejeté |
| `recon_crawl` | Crawl sans test | Inline JSON seul (pas d'`output`) |
| `recon_scan` | Crawl + test | `auto_enumerate`, `extract`, `dbs…` supportés |
| `info` | Capacités | Techniques/tampers/DBMS |

Gaps CLI-only (volontaires) : `--raw-file`, `--marker`, `--method`, `--import`/`replay`/`--export-encrypted`,
`--bulk-file`, `--level`/`--confirm`/`--ignore-code` (**MCP = level 1, sans seconde passe**),
`-v/--no-banner`. `timeout/retries/delay` acceptés mais défauts compilés (30 s/3/500 ms).
Scans longs > timeout d'appel agent : borner `max_pages/depth/threads`.
Config clients : voir `docs/MCP.md` (OpenCode `opencode.json`, Claude Code `.mcp.json`,
Codex `config.toml`, Cursor `.cursor/mcp.json`, VS Code `.vscode/mcp.json`).
Smoke test :
```bash
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"smoke","version":"0"}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' \
  | ./target/debug/injekt mcp 2>/dev/null
```

## 7.4 `replay` & `init`/`completions`/`man` (rappels)

```bash
INJEKT_PASSPHRASE='...' injekt replay --file ./session.enc  # inspection scrubbed
injekt init --preset balanced --path ./injekt.toml          # scaffold (chap. 1)
injekt completions bash | zsh | fish | powershell | elvish
injekt man | man -l -
```
