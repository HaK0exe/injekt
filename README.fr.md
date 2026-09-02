# injekt

**Détection et exploitation d'injections SQL moderne en Rust — zéro persistance, anonymisation by design.**

> Supérieur à `sqlmap`/`ghauri` en performance, maintenabilité et discrétion. Tout vit en RAM et est wipé à la sortie.

[![Rust 1.88](https://img.shields.io/badge/rust-1.88%2B-orange)](https://www.rust-lang.org) [![Édition 2024](https://img.shields.io/badge/edition-2024-blue)](https://doc.rust-lang.org/edition-guide/) [![Licence: MIT](https://img.shields.io/badge/Licence-MIT-green)](LICENSE) [![unsafe_code deny](https://img.shields.io/badge/unsafe-deny-success)](https://doc.rust-lang.org/rustc/lints/listing/allowed-by-default.html)

[English](README.md) | [OPSEC](docs/OPSEC.md) | [Notes de recherche](docs/RESEARCH_NOTES.md)

---

## Pourquoi injekt ?

| Problématique | sqlmap / ghauri | injekt v2 |
|---|---|---|
| **Persistance** | Fichiers SQLite, cache disque | **RAM uniquement** (`Arc<RwLock<SessionState>>`), `ZeroizeOnDrop`, `SecretString` — rien n'est écrit sans `--export-encrypted` |
| **OPSEC** | Cadence fixe, headers prévisibles, fuite DNS `socks5://` | Jitter humain (`Normal` 750±250ms), rotation UA réaliste avec `Sec-CH-UA` aligné, `socks5h://` imposé, scrubber automatique |
| **Performance** | Threads non bornés, code bloquant | `buffer_unordered(n)` borné, `async fn` natifs, `tokio::time::timeout` partout, `CancellationToken` arrêt propre |
| **Maintenabilité** | Python, macros `async_trait` | Rust édition 2024, `thiserror 2.x`, newtypes, builder type-state, `clippy pedantic` + `deny(warnings)` |

**Deux principes dominent tout :**
1. **Zéro persistance par défaut** — aucune base, aucun fichier, aucun cache.
2. **Anonymisation by design** — ne jamais fuiter de secrets (logs, rapports, mémoire, réseau).

---

## Fonctionnalités

- **Cibles** : parsing URL strict (`url` crate), rejet IPs privées/loopback anti-SSRF, parser raw-request Burp/ZAP, `ParameterLocation{Query,Body,Header,Cookie}`, marqueurs `*` / `§` / `{{}}`.
- **HTTP** (`src/http/`) : builder type-state (`timeout()` obligatoire avant `build()`), `Arc<reqwest::Client>` rustls, jitter, `RateLimiter` token-bucket, `CookieJar` mémoire (`zeroize`), rotation `Identity`, `ProxyConfig` Tor `socks5h://`, retry exponentiel + jitter, gzip/br.
- **Détection** (`src/detection/`) : baseline 3-5 requêtes → SHA-256 + moyenne/écart-type + détection WAF 403/406, diff Levenshtein + Jaccard (`DiffResult{similarity,time_delta,confidence}`), confirmation TRUE/FALSE inversés (3 essais min).
- **Techniques** (`src/techniques/`) : `boolean` (`OR 1=1` / `AND 1=1`, commentaires par SGBD), `time` (`SLEEP/pg_sleep/WAITFOR/BENCHMARK`, seuil `baseline+2σ`), `error` (`EXTRACTVALUE/CONVERT/CAST`), `union` (énumération ORDER BY), `stacked` (marqueur `; SELECT`), `oob` (OPT-IN DNS/HTTP via `--oob-domain`, polling collaborateur), `json` (boolean + erreurs sur `JSON_EXTRACT`/`->>`/`JSON_VALUE`/`OPENJSON`/`JSON_EXISTS` par SGBD), `tamper` évasion WAF (`--tamper space2comment,randomcase,versionedcomment,charencode,doubleurlencode,hexencode,unicodeencode,overlongutf8,...` + auto `space2comment` sur WAF 403/406), tampers requête (`--hpp` pollution `?id=1&id=PAYLOAD`, `--chunked` `Transfer-Encoding: chunked` streamé).
- **SGBD** (`src/dbms/`) : trait `DbmsDetector` en `async fn` natifs, fingerprint MySQL 8.x (`@@version`), Postgres 15+ (`version()`), MSSQL 2022 (`@@version`), Oracle 21c (`v$version`).
- **Extraction** (`src/extraction/`) : recherche binaire ASCII 32-126, `buffer_unordered` borné, vérification longueur + checksum, `SecretString` wipé après rapport.
- **Recon** (`src/recon/`) : crawler statique pour liens, formulaires et endpoints JS basiques ; périmètre same-origin, support robots.txt, déduplication des candidats et passage rate-limité vers scan/énumération.
- **Session** (`src/session/`) : `SessionState` RAM, `Scrubber` (`Authorization/Cookie/JWT/AKIA*/PEM` → `[REDACTED]`), export chiffré `XChaCha20-Poly1305` + `Argon2id` **OPT-IN**.
- **Reporting** (`src/reporting/`) : JSON + console (`owo-colors`, `tabled`, `indicatif`), preuves scrubbed.
- **Moteur** (`src/engine/orchestrator.rs`) : machine d'états `parse → baseline → detection → fingerprint → extraction(opt-in)`, concurrence bornée, barres de progression, `tracing` structuré.

---

## Installation

**Prérequis :** Rust 1.88+ (`rustup update`)

```bash
git clone https://github.com/<you>/injekt
cd injekt
cargo build --release
# binaire dans ./target/release/injekt

# ou installation dans $CARGO_HOME/bin
cargo install --path .
```

**Vérifications obligatoires :**
```bash
cargo fmt --check
cargo clippy -- -D warnings
cargo test
cargo deny check   # advisories + licences (installer cargo-deny)
```

---

## Démarrage rapide

```bash
# Scan de base (boolean/time/error, 5 threads)
injekt --target "https://example.com/search?q=1" --threads 5

# Sous-commande scan (équivalent)
injekt scan --target "https://example.com/?id=1"

# Découvrir URLs paramétrées et formulaires sans tester
injekt recon crawl --target "example.com" --depth 2 --max-pages 100

# Crawler, tester chaque paramètre découvert, puis énumérer les vulnérabilités confirmées
injekt recon scan --target "example.com" --auto-enumerate --dbs

# Importer des candidats déjà découverts
injekt recon import --file discovered.json --test

# Techniques et SGBD ciblés
injekt --target "https://example.com/?id=1" --techniques boolean,error --dbms mysql

# Endpoints JSON (configs, blobs API)
injekt --target "https://example.com/?id=1" --techniques json --dbms mysql

# Contournement WAF : variantes tampers (original + chaque simple + chaîne complète)
injekt --target "https://example.com/?id=1" --tamper space2comment,randomcase --techniques boolean,union

# Tampers requête : HPP (duplique ?id=1&id=PAYLOAD) et chunked (body streamé)
injekt --target "https://example.com/?id=1" --hpp --techniques boolean
injekt recon scan --target "example.com" --hpp --chunked --auto-enumerate --dbs

# OPSEC : Tor + jitter + rate limit
injekt --target "https://example.com/?id=1" \
  --proxy socks5h://127.0.0.1:9050 \
  --jitter "750,250" --rate-limit 5

# Autoriser les cibles privées en labo
injekt --target "http://192.168.1.10/?id=1" --allow-private

# Export chiffré de session (OPT-IN) — crée un artefact sensible
injekt --target "https://example.com/?id=1" --export-encrypted ./session.enc
injekt --import ./session.enc --target "https://example.com/?id=1"  # reprise
injekt replay --file ./session.enc
injekt info

# Sortie JSON
injekt --target "https://example.com/?id=1" --output report.json
cat report.json | jq .
```

---

## Référence CLI

```
injekt [OPTIONS] [COMMAND]

Commandes:
  scan    Lance la détection (défaut quand --target est fourni)
  recon   Crawle les cibles, découvre les paramètres, scanne les candidats, importe du JSON
  replay  Rejoue une session chiffrée
  info    Affiche version / techniques / SGBD

Options:
  -u, --target <URL>              URL cible
      --method <METHOD>           Méthode HTTP (défaut GET)
      --headers <H1,H2>           Headers supplémentaires (séparés par virgules)
      --cookies <STR>             Cookies (SecretString, masqué dans les logs)
      --proxy <URL>               http(s):// ou socks5h:// (socks5:// refusé - fuite DNS)
      --threads <N>               Concurrence [défaut: 5]
      --techniques <LISTE>        boolean,time,error,union,stacked,oob,json,all [défaut: all]
      --tamper <LISTE>            Tampers WAF : space2comment,space2plus,space2tab,space2newline,space2randomblank,randomcase,versionedcomment,betweencomment,charencode,doubleurlencode,hexencode,unicodeencode,overlongutf8 [défaut: aucun, auto space2comment sur WAF 403/406]
      --hpp                       Pollution paramètres : duplique ?id=1&id=PAYLOAD (Query/Body)
      --chunked                   Transfert chunked : body streamé Transfer-Encoding: chunked (Body uniquement)
      --oob-domain <DOMAINE>      Domaine collaborateur (active sondes OOB, OPT-IN)
      --oob-poll-url <URL>        URL de polling avec placeholder {token} (auto-confirmation)
      --oob-wait-secs <N>         Attente avant polling [défaut: 5]
      --dbms <TYPE>               mysql|postgres|mssql|oracle
      --extract                   Active l'extraction (opt-in, SecretString)
      --output <CHEMIN>           Chemin rapport JSON
      --rate-limit <RPS>          Token-bucket req/s
      --jitter <MOY,ECART>        ex. "750,250" ms
      --marker <STR>              Marqueur d'injection (*, §, {{}})
      --export-encrypted <CHEMIN> Snapshot chiffré (XChaCha20-Poly1305/Argon2id)
      --import <CHEMIN>           Importe un snapshot chiffré
      --no-redact                 Désactive le masquage (local uniquement !)
      --allow-private             Autorise les IPs loopback/privées (bypass anti-SSRF)
  -v, --verbose                   Logs debug (tracing)
  -h, --help
  -V, --version
```

Sous-commandes recon:

```bash
injekt recon crawl --target <HOTE|URL> [--depth N] [--max-pages N] [--include-subdomains] [--ignore-robots]
injekt recon scan --target <HOTE|URL> [--depth N] [--max-pages N] [--auto-enumerate]
injekt recon import --file discovered.json [--test] [--enumerate]
```

---

## OPSEC

Voir [`docs/OPSEC.md`](docs/OPSEC.md) — résumé :

- **Aucune écriture disque** sans `--export-encrypted` ; `SessionState` est `Arc<RwLock<…>>` et `ZeroizeOnDrop`.
- **Scrubber** (`src/session/scrubber.rs`) : `Authorization`, `Cookie`, `Set-Cookie`, `X-Api-Key`, JWT `eyJ…`, `AKIA[0-9A-Z]{16}`, PEM → `[REDACTED]` ou hash 8-hex.
- **Identité** (`src/http/identity.rs`) : pool UA réaliste (Chrome 126 / Firefox 128 / Safari 17.5) avec `Sec-CH-UA` cohérent.
- **Jitter** (`src/http/jitter.rs`) : `rand_distr::Normal`, jamais de cadence fixe.
- **Proxy** (`src/http/proxy.rs`) : `socks5h://` impose DNS distant ; `socks5://` sans `h` est rejeté.
- **TLS** : `rustls` (empreinte JA3 stable — limitation documentée ; utiliser un proxy externe pour randomiser JA3).
- **JAMAIS** `--no-redact` sur un rapport partagé.

---

## Architecture

```
src/
├── main.rs / lib.rs
├── cli/{args,commands/{scan,recon,replay,info},output/{console,json,format}}
├── target/{url,raw_request,parameters,markers}
├── http/{client,identity,proxy,cookies,redirects,retry,jitter,rate_limit}
├── detection/{baseline,response_diff,confirmation,scanner/{engine,scheduler}}
├── techniques/{boolean,time,error,union,stacked,oob,json}/{detector,payloads} (+oob/verifier) + tamper (évasion WAF) + request_tamper (HPP/chunked)
├── dbms/{common,mysql,postgres,mssql,oracle}/{fingerprint,payloads,queries}
├── extraction/{engine,inference,verification}
├── recon/{crawler,discovery,filters,parameter}
├── session/{state,scrubber,export}
├── reporting/{console,json,evidence}
└── engine/orchestrator
```

Patterns clés : newtypes (`TargetUrl`, `Payload`), builder type-state, `#[non_exhaustive]`, `Cow`, `Arc` uniquement si partagé, `match` exhaustif, `const fn`, `Debug` manuel pour secrets, `#[deny(unsafe_code)]`.

---

## Développement

```bash
cargo fmt
cargo clippy -- -D warnings
cargo test -- --nocapture
cargo test --doc

# wiremock 0.6, insta snapshots, proptest pour les parsers
cargo insta review
```

**MSRV** 1.88, **édition** 2024. Lints dans `Cargo.toml` :
```toml
[lints.rust]
unsafe_code = "deny"
[lints.clippy]
pedantic = { level = "warn", priority = -1 }
unwrap_used = "deny"
expect_used = "deny"
```

---

## Sécurité

- Aucun `unsafe` (`#![deny(unsafe_code)]` partout).
- `zeroize` + `secrecy::SecretString` pour cookies, tokens, données extraites, passphrases.
- Hors ligne, zéro télémétrie.

> **Avertissement :** Utiliser uniquement sur des systèmes vous appartenant ou avec autorisation explicite. Les auteurs ne sont pas responsables d'un mauvais usage.

---

## Licence

MIT — voir [LICENSE](LICENSE).

## Remerciements

Inspiré par `sqlmap`/`ghauri` mais réécrit pour les best practices Rust 2024, design OPSEC-first et async borné.
