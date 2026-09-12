# 02 — Reconnaissance (crawl, ingest, import)

Objectif : **découvrir des paramètres testables sans tester** (phase silencieuse),
puis tester proprement. Jamais de scan aveugle sur domaine entier sans cadrage.

## 2.1 `recon crawl` — découverte passive-ish

```bash
# Découverte seule : liens + formulaires + endpoints JS, sans injection
injekt recon crawl --target "example.com" --depth 2 --max-pages 100

# Options de cadrage :
injekt recon crawl --target "https://example.com/app" \
  --depth 3 --max-pages 200 --max-per-template 3 \
  --include-subdomains --ignore-robots
```

| Option | Défaut | Rôle pentest |
|---|---|---|
| `--target <HOST\|URL>` | requis | Host nu ou URL. **Ici `--target` long uniquement** (le `-u` global ne satisfait pas recon). |
| `--depth` | 2 (max 16) | Profondeur de crawl. 2 = tri, 3-4 = exhaustif. |
| `--max-pages` | 100 (max 100 000) | Budget pages. Borner pour OPSEC/temps client MCP. |
| `--max-per-template` | 3 | Anti-piège : max pages par forme (path + noms de params). Protège contre pagination/calendrier/listing qui brûleraient le budget. |
| `--include-subdomains` | false | Élargit le scope — **uniquement si autorisé au contrat**. |
| `--ignore-robots` | false | Ignore `robots.txt`. Par défaut on le respecte. |

Le crawler est **statique** (pas de headless) : scope same-origin, déduplication,
`robots.txt` supporté. Timeout HTTP recon = **15 s hardcodé** (`--timeout` ne s'applique pas).

Sortie : candidats `ParameterCandidate` (URL + location Query/Body/Header/Cookie + nom).
**Relire les candidats avant de tester** — c'est votre surface d'attaque contractuelle.

## 2.2 `recon scan` — crawl + test

```bash
# Crawl puis test de chaque paramètre découvert :
injekt recon scan --target "example.com" --auto-enumerate --dbs

# Avec cadrage + techniques réduites (discret) :
injekt recon scan --target "example.com" --depth 2 --max-pages 50 \
  --techniques boolean,error --threads 2 --rate-limit 3
```

- `--auto-enumerate` : après détection, énumère (`--dbs`-style) sur findings confirmés.
- Tous les flags globaux (techniques, tampers, proxy, jitter, `--extract`, `--dbms`, `-p`, matchers…) s'appliquent.
- `--hpp --chunked` aussi supportés ici.

Workflow conseillé :
1. `recon crawl` petit (`--max-pages 50`) → valider scope.
2. `recon scan` avec `--profile stealth` sur scope validé.
3. `recon scan --auto-enumerate --dbs` uniquement après 1er finding (évite l'exfil inutile).

## 2.3 `recon import` — rejouer des candidats JSON

```bash
# Lister sans tirer (offline, aucun probe) :
injekt recon import --file discovered.json
# Tester activement :
injekt recon import --file discovered.json --test
# Tester + énumérer :
injekt recon import --file discovered.json --test --enumerate
```

- `--test` = scan actif (requêtes réseau). Sans `--test` = listing offline.
- `--enumerate` = énumération sur findings confirmés.
- Idéal pour : revue client du scope → re-test après fix → partage d'équipe sans re-crawler.

## 2.4 Ingestion massive (sans crawler)

Priorité `Cli::effective_target()` : `--raw-file` > `-u/--target` global > `scan --target`.
`--bulk-file` est **exclusif** avec `--target`/`--raw-file`.

```bash
# Bulk : 1 cible/ligne, `#` commentaires, lignes vides ignorées, doublons dédupliqués, max 1000 (erreur dure au-delà)
cat > targets.txt <<'EOF'
https://site1.com/?id=1
https://site2.com/search?q=test
# https://hors-scope.com/?id=1
https://site3.com/api?user=admin
EOF
injekt --bulk-file targets.txt --output bulk-report.json --threads 3
# Alias stdin :
cat targets.txt | injekt --stdin --output bulk-report.json
injekt --bulk-file - --output bulk-report.json < targets.txt

# Raw Burp/ZAP : rejoue méthode + headers + cookies + body (prioritaire)
injekt --raw-file req.txt --threads 5
# + overrides (CLI gagne sur fichier ; fichier gagne sur --data si les deux ont un body) :
injekt --raw-file req.txt --method POST --headers "X-Test: 1" --cookies "sess=abc" --data "id=1"

# Dossier de raws (multi-ingest, URL-only) :
injekt --raw-dir ./burp-exports/ --output bulk-report.json

# OpenAPI 3.x (servers + paths → query params) et Sitemap (<loc>) :
injekt --openapi-file openapi.json --dry-run    # toujours dry-run d'abord !
injekt --openapi-file openapi.json --output report.json
injekt --sitemap-file sitemap.xml --dry-run
injekt --sitemap-file sitemap.xml --output report.json
```

Bodies couverts par `--raw-file` : urlencoded, JSON imbriqué, XML/SOAP, multipart (valeurs de champs).
`--raw-dir` reste URL-only (pas de bodies). En bulk, `--cookies`/`Authorization` sont
**rejoués sur chaque cible** (warning loggé — attention au cross-scope).

## 2.5 Ciblage fin : `-p`, `--method`, `--data`, `--marker`

```bash
# Tester uniquement certains params (nom nu ou scopé) :
injekt --target "https://example.com/?id=1&lang=fr" -p id
injekt --target "https://example.com/?id=1" -p body:user,cookie:PHPSESSID
injekt --target "https://example.com/?id=1" -p query:id,header:X-Forwarded-For

# POST :
injekt --target "https://example.com/search" --method POST --data "q=test&lang=fr"
injekt --target "https://example.com/search" --method POST --data "q=test" --chunked --techniques boolean

# JSON imbriqué / XML / headers / cookies :
injekt --target "https://api.example.com/user?id=1" --method POST \
  --headers "Content-Type: application/json" \
  --data '{"user":{"id":1}}' --techniques json --dbms postgres
injekt --target "https://example.com/?id=1" --headers "X-Forwarded-For: 127.0.0.1" -p header:X-Forwarded-For
injekt --target "https://example.com/?id=1" --cookies "sess=abc; theme=dark" -p cookie:sess

# Marqueurs d'injection (auto-détecté par défaut) :
injekt --target "https://example.com/?id=1*" --marker "*"
# `*` (suffixe), `§param§` (entouré), `{{param}}` (template)
```

`ParameterLocation` : Query, Body, Header, Cookie — tout est testable, mais
**Header/Cookie = bruit + risque de log** : borner avec `-p` et `--profile stealth`.

## 2.6 Checklist de fin de recon

- [ ] Candidats relus, hors-scope purgés (`--include-subdomains` justifié ?).
- [ ] `robots.txt` respecté sauf dérogation écrite (`--ignore-robots` tracé au rapport).
- [ ] 1-2 cibles pilotes identifiées pour le scan (pas tout le domaine d'un coup).
- [ ] `discovered.json` archivé (rejouable via `recon import`).
