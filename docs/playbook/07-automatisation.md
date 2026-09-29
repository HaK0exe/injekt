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
| 2 | `L2-tamper` | `level ≥ 2` + `space2comment,randomcase,versionedfuzz` (si tampers vides) + `confirm=false` forcé |
| 3 | `L3-evasion` | `level ≥ 3` + `space2comment,randomcase,charencode,equaltolike,numericobfuscate,linecomment` (si <6 tampers) + `text-only` + `hpp` |

`base64encode` n'est **jamais** auto-activé (casse boolean). Tampers explicites
conservés en L2/L3. `--auto-enumerate` force `extract=true`.

## 7.1b Budgets, reproductibilité, knowledge (compatibles `auto`)

```bash
# Borner chaque passe d'auto (direct + recon) :
injekt auto --target "https://example.com/?id=1" --max-duration 120 --request-budget 500
# Run reproductible + verdict lisible :
injekt auto --target "https://example.com/?id=1" --seed 42 --output auto-report.json
injekt --target "https://example.com/?id=1" --explain 'id@query'
# Knowledge opt-in (deltas anonymes, fusion + fsync + 0600) :
injekt auto --target "https://example.com/?id=1" --allow-knowledge
```

- `--max-duration N` (`0..=86400`, `INJEKT_MAX_DURATION`, OPT-IN) : budget temps de la
  **phase detection uniquement** — baseline/contexte/fingerprint/énumération exclus.
  Arrêt coopératif propre (`Done`, sans erreur, sans finding inventé).
- `--request-budget N` (`0..=1000000`, `INJEKT_REQUEST_BUDGET`, OPT-IN) : arrêt coopératif
  quand le `request_count` global est atteint (la technique courante finit, aucune
  nouvelle ne démarre ; léger dépassement possible en concurrence). Les deux passent
  par `build_engine_config` → actifs sur **chaque passe** d'`auto`.
- `--seed N` (`INJEKT_SEED`) : tampers, jitter, rotation UA, backoff déterministes ;
  enregistré dans le rapport (`seed`). L'aléa crypto de l'export reste OS-random.
- `--explain 'id@query'` (`INJEKT_EXPLAIN`) : verdict une-ligne post-scan depuis la
  trace RAM + evidence (`TRUE≈baseline 0.91, FALSE≠baseline 0.22, 3/3, waf=none,
  14 req, seed 42`), 0 requête ; aussi via `replay --file` (chap. 8.1).
- `--allow-knowledge` (`INJEKT_ALLOW_KNOWLEDGE`, chemin `--knowledge-path` /
  `INJEKT_KNOWLEDGE_PATH`, défaut `~/.cache/injekt/knowledge.json`) : post-run
  `learn_and_save` — agrégats anonymes `(technique, dbms, contexte)` uniquement,
  jamais cible/param/seed/secret. OFF = aucune IO. Actif sur `scan`, `bulk`,
  `auto` (direct + recon).

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

6 outils (vérifiés contre `src/mcp/tools.rs`) :

| Outil | Rôle | Notes |
|---|---|---|
| `scan` | Scan URL | JSON inline + `output` opt-in (relatif, `0o600`, `create_new`) ; `export_encrypted` rejeté (`invalid_params`) |
| `recon_crawl` | Crawl sans test | Inline JSON seul (pas d'`output`) |
| `recon_scan` | Crawl + test | `auto_enumerate`, `extract`, `dbs…` + `output` |
| `info` | Capacités | Techniques/tampers/DBMS |
| `plan` | Plan d'exécution offline | **0 requête** (jamais de `HttpClient`) ; `level`/`seed` acceptés (`level` clampé 1-5) pour l'ordonnancement uniquement |
| `explain` | Verdict offline d'un finding | 0 requête, depuis `evidence` ou snapshot `export_json` ; secrets jamais en sortie |

Gaps CLI-only (volontaires, `base_cli`) : `--raw-file`, `--marker`, `--method`,
`--import`/`replay`/`--export-encrypted`, `--bulk-file`, `--allow-secret-reuse`
(forcé `false` ; outils single-target → gate triviale), `--level`/`--confirm`/`--seed`/
`--ignore-code` (**scan/recon = level 1, sans seconde passe, unseeded**), `--format`
(MCP = JSON inline), `--dry-run` (couvert par `plan`), `--profile`/`--config`,
`-v/--no-banner` (forcés `false`/`true` : stdout = JSON-RPC), `--force` (MCP =
`create_new` strict, jamais d'écrasement), knowledge toujours OFF
(`allow_knowledge=false`).

Exposés (défauts du builder partagé quand absents) : `timeout`/`retries`/`delay`
(30 s/3/500 ms), `max_duration`/`request_budget` (OPT-IN, `None` = illimité),
jitter **ms** (`"750,250"`), `rate_limit`, `max_redirects`, proxy/headers/cookies,
`oob_*`, `hpp`/`chunked`, `no_redact` (warn serveur). Écritures disque : param
`output` uniquement — relatif sans `..` (parent canonicalisé, symlink-safe), cap
10 MiB, `0o600`, warn serveur. Scans longs > timeout d'appel agent : borner
`max_pages/depth/threads`.
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
