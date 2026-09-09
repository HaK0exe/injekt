# Playbook Pentest injekt — de A à Z

> **Usage autorisé uniquement.** N'utilisez `injekt` que sur des systèmes que vous possédez
> ou avec une **autorisation écrite explicite**. L'opérateur reste responsable.
> Voir `docs/OPSEC.md`, `DOCUMENTATION.md`, `README.md`.

`injekt` : détection & exploitation SQLi en Rust — **zéro persistance par défaut**,
**anonymisation by design**, concurrence bornée, pipeline `parse → baseline →
detection → fingerprint → extraction (opt-in)`.

## Carte du playbook

| Chapitre | Contenu | Fichier |
|---|---|---|
| 0 | Méthodologie pentest + périmètre + règles d'engagement | `README.md` (ce fichier) |
| 1 | Installation, `info`, `init`, profils, config, `dry-run` | `01-installation-configuration.md` |
| 2 | Reconnaissance : `recon crawl/scan/import`, ingest OpenAPI/Sitemap/Raw/Bulk | `02-reconnaissance.md` |
| 3 | Scan & détection : techniques, `--level`, `--dbms`, matchers, baseline/WAF | `03-scan-detection.md` |
| 4 | Évasion WAF : 19 tampers, `--hpp`, `--chunked`, `--prefix/suffix`, encoding | `04-evasion-waf.md` |
| 5 | Fingerprint DBMS + exploitation : `--extract`, `--dbs/--tables/--columns/--dump`, identité | `05-exploitation-enumeration.md` |
| 6 | OPSEC : proxy `socks5h`, jitter, rate-limit, scrubber, `--allow-private`, `--export-encrypted`/`replay` | `06-opsec.md` |
| 7 | Automatisation : `auto` (escalade L1/L2/L3), bulk, `completions`/`man`, MCP | `07-automatisation.md` |
| 8 | Reporting : `--output`, schéma JSON, bulk report, preuves, troubleshooting | `08-reporting.md` |
| 9 | Cheatsheet : arbre de décision, one-liners, codes de sortie, limites | `09-cheatsheet.md` |

## Méthodologie (workflow recommandé)

```
0. Autorisation écrite + scope (URLs/hosts, créneaux, contacts, interdit)
   │
1. Installation + `injekt info` + `injekt init` + `injekt --dry-run`
   │
2. Recon passive-ish : `recon crawl` → relecture candidats → `recon import` (sans --test = offline)
   │
3. Scan ciblé : 1 URL paramétrée → `--profile quick` puis `balanced`
   │             → lecture baseline/WAF → ajustement
   │
4. Évasion si WAF : `--tamper` progressif → `--hpp`/`--chunked` → `--level 2/3`
   │
5. Fingerprint DBMS : auto puis `--dbms mysql|postgres|mssql|oracle` forcé si doute
   │
6. Exploitation OPT-IN : `--extract --dbs` → `--tables` → `--columns` → `--dump`
   │                     (+ `--banner/--current-user/--current-db/--hostname`)
   │
7. Pipeline auto (option) : `injekt auto` avec escalade L1→L2→L3
   │
8. Reporting : `--output report.json` (0o600) → tri findings → nettoyage secrets
```

**Règle d'or :** un finding `exit 0` ne veut rien dire seul — `exit 0` = succès
d'exécution **y compris "aucun finding"**. La vérité est dans `report.json`
(`findings`, `evidences`, `extracted`, `request_count`).

## Ce que couvre l'outil (vue exhaustive)

### Cibles (`src/target/`)
- URL stricte (`url` crate), anti-SSRF (privé/loopback rejeté sans `--allow-private`).
- `ParameterLocation{Query,Body,Header,Cookie}`, marqueurs `*` / `§` / `{{}}`.
- `--raw-file` (Burp/ZAP : méthode + headers + cookies + body rejoués, prioritaire sur `--target`).
- Bodies : urlencoded, JSON imbriqué (`json:` paths), XML/SOAP (`xml:` tags), multipart.
- `--raw-dir` (multi-raw `*.txt`, URL-only), `--bulk-file` (max 1000, `#` ignorés),
  `--stdin` / `--bulk-file -`, `--openapi-file` (OpenAPI 3.x `servers`+`paths`),
  `--sitemap-file` (`<loc>`).
- `--method`, `--headers`, `--cookies`, `--data` (overlay de `--raw-file`).

### HTTP (`src/http/`)
- Builder type-state : `timeout()` obligatoire. `Arc<reqwest::Client>` + rustls.
- Jitter Normal **millisecondes** (défaut `750,250`, plancher 200 ms, **toujours actif**).
- Token-bucket rate-limit (défaut **10 req/s**, pas de mode illimité).
- `CookieJar` mémoire (`SecretString`, zeroized), rotation d'identité
  (Chrome 126 / Firefox 128 / Safari 17.5 + `Sec-CH-UA` aligné),
  `ProxyConfig` (`socks5h://` exigé, `socks5://` → `DnsLeak`), retry exponentiel + jitter,
  politique de redirect, gzip/br.

### Détection (`src/detection/`, `src/engine/orchestrator.rs`)
- Machine à états : `parse → baseline → detection → fingerprint → extraction(opt-in)`.
- Baseline 3-5 requêtes → SHA-256 + moyenne/σ + fingerprint WAF/CDN (statuts, headers, challenge bodies).
- Diff Levenshtein + Jaccard (`DiffResult{similarity,time_delta,confidence}`),
  confirmation TRUE/FALSE inversée (min 3 essais), baseline/WAF **avant** `--ignore-code`.
- Matchers : `--string/--not-string/--code/--text-only`, `--ignore-code 429,503`.
- Concurrence bornée `buffer_unordered(threads)` + `tokio::time::timeout` + `CancellationToken` (Ctrl+C propre).

### Techniques (`src/techniques/`, 7 familles)
| Technique | Idée | Flag |
|---|---|---|
| `boolean` | `OR 1=1` / `AND 1=1`, commentaire par DBMS | `--techniques boolean` |
| `time` | `SLEEP/pg_sleep/WAITFOR/BENCHMARK`, seuil `baseline+2σ` | `time` |
| `error` | `EXTRACTVALUE/CONVERT/CAST`, erreurs reflétées masquées | `error` |
| `union` | Énumération `ORDER BY` | `union` |
| `stacked` | `; SELECT` marker (garde SELECT-only) | `stacked` |
| `oob` | DNS/HTTP collaborateur **OPT-IN** | `oob` + `--oob-domain` |
| `json` | `JSON_EXTRACT/->>/JSON_VALUE/OPENJSON/JSON_EXISTS` dual boolean+error | `json` |
| `all` | Tout (défaut historique) | `all` |

`--fetch-using direct|boolean|time` restreint l'oracle. `--level 1-5` :
L1 budget historique, L2 double, L3+ tout + `ORDER BY` élargi.

### Évasion
- 19 tampers (`--tamper`, voir chap. 4) + auto `space2comment` **uniquement sur blocage WAF actif**.
- `--hpp` (pollution `?id=1&id=PAYLOAD`, Query/Body), `--chunked` (`Transfer-Encoding: chunked`, Body).
- `--prefix/--suffix` (après tampers), `--safe-chars`, `--skip-urlencode`.

### DBMS (`src/dbms/`)
- Trait `DbmsDetector` (`async fn` natif), fingerprint MySQL 8.x (`@@version`),
  Postgres 15+ (`version()`), MSSQL 2022 (`@@version`), Oracle 21c (`v$version`).
- `--dbms mysql|postgres|mssql|oracle` (alias `mariadb→mysql`, `pg→postgres`, `sqlserver→mssql`, `ora→oracle`).

### Extraction (`src/extraction/`)
- Recherche binaire ASCII 32-126, `buffer_unordered` borné, vérification
  (longueur + checksum), `SecretString` zeroized après rapport. **Opt-in `--extract`.**

### Recon (`src/recon/`)
- Crawler statique (liens, formulaires, endpoints JS), scope same-origin,
  `robots.txt`, déduplication, `max-per-template` anti-piège pagination/calendrier.

### Session / Reporting / OPSEC
- `SessionState` RAM (`Arc<RwLock>` + `ZeroizeOnDrop`). Zéro écriture disque sauf
  `--export-encrypted` / `--output` / `--import` / `recon import` (opt-in).
- `Scrubber` : `Authorization/Cookie/Set-Cookie/X-Api-Key`, JWT `eyJ…`, `AKIA…`, PEM → `[REDACTED]`.
- Export chiffré XChaCha20-Poly1305 + Argon2id (passphrase ≥12 chars), `replay` = inspection.
- JSON + console (`owo-colors`, `tabled`, `indicatif`), preuves scrubbées, fichiers `0o600`.

### Commandes CLI
`scan` · `recon crawl|scan|import` · `replay` · `info` · `auto` (ingest→scan→escalade→enum) ·
`init` · `completions` · `man` · `mcp` (stdio pour Claude Code/Codex/OpenCode/Cursor/VS Code).

## Prérequis opérateur

- [ ] Autorisation écrite, scope, fenêtre de tir, procédure d'arrêt d'urgence.
- [ ] Lab d'abord (`--allow-private` **uniquement** en lab, jamais en prod non autorisée).
- [ ] `--dry-run` avant tout tir réseau pour valider résolution config + cibles.
- [ ] Proxy Tor (`socks5h://`) prêt si réseau hostile, collaborateur OOB auto-hébergé si besoin.
- [ ] Dossier d'affaires hors repo (jamais de `*.enc` / `report.json` / raw Burp committé).

Suite : `01-installation-configuration.md`.
