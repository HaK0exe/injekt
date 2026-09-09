# 08 — Reporting & forensics

## 8.1 `--output` (source de vérité)

```bash
injekt --target "https://example.com/?id=1" --output report.json
cat report.json | jq .
# Écrasement protégé : refuse si le fichier existe ou si chemin absolu/traversant —
# opt-in conscient :
injekt --target "https://example.com/?id=1" --output report.json --force
# Fichiers 0o600 sur Unix. --no-banner garde stdout propre (banner sur stderr).
```

Schéma `JsonReport` :
```jsonc
{
  "target": "https://example.com/?id=1",  // scrubbé sauf --no-redact
  "findings": [ /* paramètre, technique, dbms, confiance, evidence */ ],
  "evidences": [ /* snippets scrubés */ ],
  "extracted": [ /* --dbs/--tables/--columns/--dump/--banner/… — NON scrubbé, sensible */ ],
  "request_count": 123
}
```

Bulk (`BulkReport`) : `targets_ok`, `targets_failed`, `request_count_total`,
`per_target[]` (**sans** `extracted` — single-target et `auto` en ont).
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
TOCTOU DNS sans proxy, recon 15 s hardcodé, bulk 1000, crawl depth 16 / pages 100 000,
level max 5, passphrase min 12, pas de reprise depuis export (re-`scan`).
