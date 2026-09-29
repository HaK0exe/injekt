# 08 — Reporting & forensics

## 8.0 UX terminal et flux de sortie

Les logs de progression et de diagnostic sont écrits sur **stderr**. Le
résultat humain du scan est écrit sur **stdout**. Cette séparation permet par
exemple de conserver les findings tout en masquant les logs :

```bash
injekt --target "https://example.com/?id=1" 2>scan.log
```

Un scan mono-cible se termine par un résumé :

```text
◆ Scan complete
  Status: CLEAN | FINDINGS | INCONCLUSIVE | CANCELLED
  Target: https://example.com/?id=1
  Requests: 42
  Duration: 12.4s
```

- `CLEAN` : un run complet, aucun finding confirmé ; ce n'est pas une
  garantie de sécurité absolue.
- `INCONCLUSIVE` : run arrêté tôt ou oracle inutilisable (baseline instable /
  tout-5xx, `--request-budget` / `--max-duration`) — ne jamais le lire comme
  "non injectable".
- `FINDINGS` : au moins un finding est affiché ensuite avec son niveau (`HIGH`,
  `MED`, `LOW`).
- `CANCELLED` : arrêt demandé par Ctrl+C ; les résultats déjà collectés sont
  conservés.

Les couleurs suivent `NO_COLOR`, `TERM=dumb`, `CLICOLOR=0` et la détection TTY.
`--no-banner` supprime seulement la bannière de démarrage. Pour la CI ou les
pipelines, préférez `--output` et `--format json|sarif|junit|md`.

## 8.1 `--output` (source de vérité)

```bash
injekt --target "https://example.com/?id=1" --output report.json
cat report.json | jq .
# Écrasement protégé : create_new (refuse si le fichier existe), chemins
# absolus/traversants refusés — opt-in conscient :
injekt --target "https://example.com/?id=1" --output report.json --force
# Fichiers 0o600 sur Unix (même avec --force). --no-banner garde stdout propre
# (banner sur stderr). --force logge un warning (traversée explicite).
```

Schéma `JsonReport` (C7 complet, cf. `DOCUMENTATION.md` § Report schema) :
```jsonc
{
  "target": "https://example.com/?id=1",  // scrubbé sauf --no-redact
  "findings": [
    {
      "target": "https://example.com/?id=1",
      "parameter": "id@query",
      "technique": "Boolean",
      "confidence": 0.95,
      // Verdict calibré (buckets : high → précision ≥95%, medium → ≥80%) :
      "false_positive_prob": 0.02,       // mesuré (essais de confirmation) ou 1-confidence
      "severity": "high",                // high|medium|low, RECOMPUTÉ live au rendu
      "remediation": {
        "summary": "Use parameterized queries / prepared statements; …",
        "parameterized_example": "db.query(\"SELECT * FROM users WHERE id = ?\", [user_input])"
      },
      "evidence_detail": {
        "hashes": [],                    // SHA-256 hex (traçabilité, sans secrets)
        "diff": "TRUE≈baseline FALSE≠baseline",
        "trace_ref": "trace:9f2c41aa07bd3e55"  // null tant que le moteur de traces (C6) n'a pas atterri
      },
      "waf": {"vendor": "cloudflare", "blocking": true},
      "dbms": "mysql",
      "evidence": "boolean true_sim=0.95 …",  // snippet de preuve scrubbé
      "timestamp": "2026-01-15T12:00:00Z"
    }
  ],
  "evidences": [ /* snippets scrubés (request/response/technique/parameter/confidence) */ ],
  "extracted": [ /* --dbs/--tables/--columns/--dump/--banner/… — NON scrubbé, sensible */ ],
  "request_count": 123,
  // Provenance C1 (top-level, additive) :
  "version": "0.3.0",
  "git_sha": null,        // renseigné si compilé avec GIT_SHA (release/CI)
  "seed": 42,             // null = run non déterministe
  "profile": "stealth",   // null = pas de preset
  "techniques": ["boolean", "error"],
  "level": 1,
  "tampers": ["space2comment"]
}
```

Compat pré-C7 : les findings minimaux (`target,parameter,technique,confidence,dbms,
evidence,timestamp`) désérialisent toujours — chaque champ C7 est `#[serde(default)]`
(`false_positive_prob` → `1.0`, `severity` → bucket `Low` par défaut). Surtout :
**la sévérité stockée n'est jamais trustée** — `live_severity()` la recompute depuis
`(confidence, fp)` à chaque rendu (`Finding::normalize` au push, `sarif`/`junit`/`md`
via `live_severity`), donc un export pré-C7 ne peut jamais gonfler un rapport.
Buckets (`src/reporting/verdict.rs`) : `High` = `confidence ≥ 0.85` **et** `fp ≤ 0.05` ;
`Medium` = `confidence ≥ 0.70` **et** `fp ≤ 0.20` ; sinon `Low` (les deux signaux
doivent concorder).

`--format` (défaut `json`, env `INJEKT_FORMAT`, console inchangée, tout format scrubbé) :

| Format | Contenu | Consommateur |
|---|---|---|
| `json` | Schéma ci-dessus | `jq`, bench, MCP |
| `sarif` | SARIF **2.1.0** (rules `injekt/sqli-<technique>`, niveaux `error`/`warning`/`note`, `security-severity` dérivée du bucket calibré, remediation + `trace_ref` + WAF en `properties`) | GitHub code scanning, CI |
| `junit` | 1 `<testcase>` + `<failure>` **par finding** (chaque finding fait échouer le build, même `low` ; tri par sévérité au dashboard) ; scan clean = 1 cas passant `no-injection` | Dashboards CI |
| `md` | Table + 1 section par finding avec remediation, evidence scrubbé, contexte WAF, trace ref | Rapport humain |

```bash
injekt --target "https://example.com/?id=1" --output report.sarif --format sarif
injekt --target "https://example.com/?id=1" --output report.xml --format junit
injekt --target "https://example.com/?id=1" --output report.md --format md
# INJEKT_FORMAT=sarif fonctionne aussi. --format respecté aussi par auto et bulk.
```

Bulk (`BulkReport`) : `version`, `targets_total`, `targets_ok`, `targets_failed`,
`request_count_total`, `per_target[]` (`target`, `findings`, `request_count`, `error`) —
**sans `extracted`** (seuls single-target et `auto` en portent). `--format json` =
JSON par cible (schéma ci-dessus) ; `--format sarif|junit|md` = **un seul document
agrégé** (tous les findings fusionnés, cible `bulk (N ok / M total)`, `extracted` vide).

`--explain 'id@query'` (`INJEKT_EXPLAIN`) : verdict raisonné une-ligne post-scan
(`TRUE≈baseline 0.91, FALSE≠baseline 0.22, 3/3, waf=none, 14 req, seed 42`),
**0 requête** — lit findings + trace RAM (`scan`, ou `replay --file` sur export
déchiffré).

`exit 0` = exécution OK **même sans finding** — ne jamais conclure sur le code seul.

## 8.2 Rédaction du finding (template)

```markdown
### [CRITIQUE/HAUTE] Injection SQL boolean — `GET /product?id`
- Cible : https://… (paramètre `id`, location Query, DBMS mysql, confiance X)
- Preuve : `OR 1=1` TRUE vs `AND 1=2` FALSE (diff Jaccard/Levenshtein, 3 essais), baseline SHA…
- Reproduction : `injekt --target "…?id=1" --techniques boolean --dbms mysql --level 1`
  (N requêtes, tampers […], jitter […], proxy […] — commande exacte archivée)
- Impact prouvé : `--banner` → MySQL 8.x ; `--current-db` → `shop` (PAS de dump de masse)
- Remédiation : requêtes préparées/ORM paramétré, moindre privilège, messages d'erreur génériques, WAF en défense en profondeur (pas en fix)
- Statut : à corriger / corrigé vérifié via `recon import --file … --test`
```

Joindre `report.json` (scrubbé) + commandes exactes + `request_count` par phase.
Données extraites : annexe chiffrée séparée, jamais dans le corps du rapport.

## 8.3 Preuves & traçabilité

- `reporting/evidence.rs` : findings/cibles/preuves via `Scrubber::scrub()`.
- Archiver par phase : `01-crawl.json`, `02-scan-L1.json`, `03-evasion-L2.json`,
  `04-enum-identity.json` (+ `session.enc` si besoin, passphrase hors rapport).
- `replay` pour auditer un export sans rescanner :
  `INJEKT_PASSPHRASE='…' injekt replay --file ./session.enc`.
- Codes de sortie : `0` succès (même sans finding) · `1` runtime (réseau/cible/fichier/export) ·
  `2` usage (pas de cible, conflit `--bulk-file`, commande inconnue).

## 8.4 Troubleshooting (symptôme → cause → fix)

| Symptôme | Cause probable | Fix |
|---|---|---|
| 0 finding, `request_count` faible | Pas de params / scope vide | `recon crawl` + `-p` + `--dry-run` ingest |
| 0 finding, WAF loggé | Blocage actif | Chap. 4 (tampers→HPP→L2/L3→OOB) |
| Résultats instables | Page dynamique (CSRF/pub) | `--text-only`, `--string/--not-string`, `--level 2` |
| 429/503 polluent | Rate-limit/infra | `--ignore-code 429,503` + `--rate-limit 3 --threads 2` |
| Time-based bruité | Seuil `baseline+2σ` fragile | `--fetch-using boolean`, `--techniques boolean,error`, jitter stable |
| OOB sans finding | Pas de `--oob-poll-url{token}` | Ajouter poll URL ou vérif manuelle collaborateur |
| Faux positifs JS | Comparaison HTML brute | `--text-only` + `--code` |
| Scan lent | `aggressive`/L3 + gros bulk | `--profile quick` pilote, puis ciblé ; borner `max-pages` |
| `--raw-file` ignoré | URL `--target` aussi donnée | Normal : raw prioritaire (voulu) ; vérifier `to_url https→http` |
| Export illisible | Passphrase <12 chars / TTY absent (MCP) | `INJEKT_PASSPHRASE` ≥12, CLI uniquement |

Limites dures à rappeler au client : JA3 stable (proxy externe pour TLS furtif),
TOCTOU DNS sans proxy, recon 15 s hardcodé (`--timeout` ne s'y applique pas),
bulk 1000 cibles, crawl depth 16 / pages 100 000, level max 5, passphrase min 12 chars,
`--max-duration` max 86400 s (24 h, phase detection seule), `--request-budget` max
1000000, jitter en **ms** avec floor 200 ms (actif par défaut 750±250 ms),
rate-limit 10 req/s (pas de mode illimité), rapports `--output` capés à 10 MiB,
pas de reprise depuis export (re-`scan`).
