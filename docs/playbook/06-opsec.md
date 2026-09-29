# 06 — OPSEC (anonymisation, réseau, secrets)

> `injekt` est OPSEC-first : RAM-only, jitter humain, UA réalistes, `socks5h` imposé,
> scrubber auto. Mais **l'OPSEC reste de la responsabilité opérateur** (proxy, cadence,
> scope, artefacts). Ce chapitre est **load-bearing**.

## 6.1 Zéro persistance (par défaut)

- `SessionState` = `Arc<RwLock>` RAM + `ZeroizeOnDrop`. Cookies/tokens/données
  extraites/passphrases = `secrecy::SecretString` + `zeroize`.
- **Aucune écriture disque** sauf opt-in : `--export-encrypted` / `--output` /
  `--import` / `recon import --file`. Tout le reste est RAM.
- **Knowledge Engine (`--allow-knowledge`, défaut OFF) : OFF = RAM-only, 0 lecture /
  0 écriture, boost neutre `1.0` byte-identique. ON = lecture au boot de
  `~/.cache/injekt/knowledge.json` (ou `--knowledge-path` / `INJEKT_KNOWLEDGE_PATH`,
  précédence explicite > env > défaut), boost `1+alpha` borné `[0.5,1.5]` puis clamp
  scheduler `[0.5,2.0]`, écriture post-run (fusion, `fsync`, perms `0600`).
  **Agrégats anonymes `(technique, dbms, contexte)` uniquement — jamais de
  cible/param/seed/secret persisté.** ⚠️ Persistance opt-in : activer = accepter
  qu'un fichier d'historique survive au run (auditable `jq`, 0 URL/host/secret).
- `tracing` : `info` défaut, `-v` → `debug` (`RUST_LOG` override). **Aucun secret en log**
  (`Debug` manuel sur `Cli` : cookies/proxy/headers/oob-poll-url → `[REDACTED]`).

Checklist :
- [ ] `--output` / `--export-encrypted` pointent **hors repo**, dossier d'affaire chiffré.
- [ ] Jamais de `*.enc`, `report.json`, raw Burp committés (`.gitignore` vérifié).
- [ ] `--no-redact` **jamais** sur rapport partagé (debug local uniquement, warning loggé).

## 6.2 Scrubber (redaction auto)

`src/session/scrubber.rs` sur findings/cibles/preuves/JSON :

| Pattern | Remplacement |
|---|---|
| `Authorization`, `Cookie`/`Cookie2`, `Set-Cookie`, `X-Api-Key` (+ `Proxy-Authorization`, `WWW-Authenticate`, `X-Auth/Session/Csrf/Access-Token`, `X-Api-Secret`, `Api-Key/Secret/Token`, `Refresh/Id-Token`, `Client-Secret`…) | `[REDACTED]` (ligne entière `Nom: [REDACTED]`) |
| JWT `eyJ…` | `[REDACTED-JWT]` |
| AWS `AKIA`/`ASIA`/`ABIA`/`ACCA` + 16 chars | `[REDACTED-AWS-KEY]` (secrets `aws_secret…` 40 chars → `[REDACTED-AWS-SECRET]`) |
| Bloc PEM `-----BEGIN …-----` → `-----END …-----` (entier, pas la seule 1re ligne) | `[REDACTED-PEM]` |
| Tokens provider (GitHub `ghp_…`, GitLab `glpat-…`, Slack `xox…`, Stripe `sk/rk_live…`, OpenAI `sk-…`), `Bearer`/`Basic` inline | `[REDACTED-*-TOKEN]` / `Bearer [REDACTED]` / `Basic [REDACTED]` |
| userinfo URL (`scheme://user:pass@host`, cible comme proxy) | `scheme://[REDACTED]@` (host conservé) |
| Query `?token=…` / `?password=…` / `?sessionid=…`…, JSON `"password": "…"`, form `password=…` (une seule liste de clés sensibles partagée) | `clé=[REDACTED]` (clé conservée pour triage) |
| Collaborateur OOB (domaines publics `oastify`/`interactsh`/`burpcollaborator`, clés `oob_domain:`/`oob_poll_url=`) | `[REDACTED-OOB]` / `clé: [REDACTED]` |

Traçabilité sans fuite : hash tronqué **16-hex** (SHA-256 64-bit) sur les preuves,
jamais le secret. `seed` = pas un secret (déterminisme rejouable), jamais redacté.

`Debug` manuels scrubbed (jamais de secret en log/panic/`tracing`) :
`TargetOpts` (`--target` avec `?token=`/`user:pass@` scrubbé, jamais brut),
`HttpOpts` (`--cookies`/`--proxy`/`--headers` → `[REDACTED]`),
`DetectionOpts` (`--data`/`--oob-domain` scrubbed, `--oob-poll-url` → `[REDACTED]`),
`EvasionOpts` (URLs scrubbed).

Exception volontaire : **données DB extraites (`--extract/--dump`) en clair par design**.
Ce sont elles qui fuient le plus — chiffrer le rapport, minimiser le dump (chap. 5).

## 6.3 Réseau : proxy, jitter, rate-limit, identité

```bash
# Tor (DNS distant — le `h` est obligatoire) :
injekt --target "https://example.com/?id=1" --proxy socks5h://127.0.0.1:9050
# HTTP upstream :
injekt --target "https://example.com/?id=1" --proxy http://proxy:8080
# Cadence humaine + token bucket :
injekt --target "https://example.com/?id=1" \
  --proxy socks5h://127.0.0.1:9050 \
  --jitter "750,250" --rate-limit 5 --threads 3
# Furtif maximal :
injekt --target "https://example.com/?id=1" --profile stealth --proxy socks5h://127.0.0.1:9050
```

- `socks5://` (sans `h`) = **rejeté** (`ProxyError::DnsLeak`, fuite DNS locale).
  Avec `socks5h://` : résolution locale sautée (pas de fuite, `.onion` OK) ; contrôles
  lexicaux + IP littérale conservés. Sans proxy : validation lexicale + DNS-time par hop
  (fenêtre TOCTOU résiduelle sans pinning — limite connue).
- `--jitter "MEAN,STD"` en **millisecondes** (`Normal`, plancher 200 ms).
  **Actif même sans flag** (`750,250`). `--profile stealth` = `1200,400`.
- `--rate-limit` : token bucket, **défaut 10 req/s, toujours appliqué** (pas d'illimité).
- Identité : pool UA Chrome 126 / Firefox 128 / Safari 17.5 + `Sec-CH-UA` aligné,
  `Accept/Language` cohérents, rotation par requête, ordre headers normalisé.
- Redirects : `--headers`/`--cookies` opérateur **same-origin uniquement** ;
  headers par-requête stripés cross-host, `CookieJar` scopé par URL.
  `--max-redirects <N>` (`0..=10`, défaut `5`, env `INJEKT_MAX_REDIRECTS`) :
  `0` = aucun suivi (la 3xx est rendue telle quelle) ; chaque hop suivi est
  **re-validé SSRF + stripé des secrets cross-origin**. Valeurs > 10 clampées.
- TLS : `rustls`, **JA3 stable** (limite documentée — passer par proxy externe type
  boringssl/mitmproxy pour randomiser).

## 6.4 Anti-SSRF (`--allow-private`)

```bash
# Lab local uniquement :
injekt --target "http://192.168.1.10/?id=1" --allow-private
injekt --target "http://127.0.0.1:8080/?id=1" --allow-private
```

Privé/loopback **rejeté par défaut** (MCP : `allow_private=false` aussi) —
rejet lexical + DNS-time par hop : `is_private`/`is_loopback`/`is_link_local`/`is_unspecified`
(+ plages carrier-grade explicites) **et IPv4 non-canoniques** (`2130706433`,
`0x7f.0.0.1`, `0177.0.0.1`, `127.1` — sémantique `inet_aton`/libc qui résoudrait
vers loopback/privé). `socks5://` (sans `h`) = **rejeté** (`ProxyError::DnsLeak`,
fuite DNS locale) — `socks5h://` exigé ; `socks://` / `socks4://` ambigus =
rejetés aussi (`Invalid`). Sans proxy : fenêtre TOCTOU résiduelle sans pinning
d'IP (limite connue). Recon : timeout HTTP **15 s hardcodé** (`--timeout` inopérant).
En mission : vérifier son absence (`dry-run` + relecture commande). En lab : l'assumer
explicitement au rapport (preuve que le bypass était volontaire).

## 6.5 Export chiffré & replay (OPT-IN sensible)

```bash
# Export : passphrase demandée (≥12 chars) ou INJEKT_PASSPHRASE (CI) → XChaCha20-Poly1305 + Argon2id (salt 16B, nonce 24B)
injekt --target "https://example.com/?id=1" --export-encrypted ./session.enc
# Inspection : déchiffre + résumé scrubbé (findings, request count) — PAS une reprise de scan :
INJEKT_PASSPHRASE='...' injekt replay --file ./session.enc
```

- Artefact sensible : `warn!` loggé, clé jamais stockée, `0o600` Unix.
- `scan --import` = **rejeté** (legacy). `replay --file` = inspecter un export ;
  `recon import --file` = rejouer des candidats.
- MCP : `export_encrypted` **rejeté** (`invalid_params`, pas de TTY).
- Pour reprendre : relancer `injekt --target <url>` (ou `auto --target <url>`) — `scan --target` n'est qu'un alias historique (pas de "resume" depuis l'export).

## 6.6 Replay de secrets (`--allow-secret-reuse`, OPT-IN conscient)

```bash
# Bulk multi-origines SANS le flag + secrets = refus avant tout tir (fail-closed) :
injekt --bulk-file targets.txt --cookies "sess=abc" --output bulk-report.json
# → refusing to replay --cookies/--headers across N origins; pass --allow-secret-reuse…
# Avec le flag = replay explicite (warning loggé) :
injekt --bulk-file targets.txt --cookies "sess=abc" --allow-secret-reuse --output bulk-report.json
```

- Gate : `--cookies` non vide ou header `Authorization:`/`Cookie:` + cibles sur
  > 1 origine (scheme/host/port) = erreur. Mono-origine = passe toujours.
  Couvre bulk (`--bulk-file`/`--stdin`/`--openapi-file`/`--sitemap-file`/`--raw-dir`)
  **et** `recon import --test`. Règle opérationnelle : **un jeu de secrets = une origine** ;
  multi-clients/scopes distincts = runs séparés, jamais un bulk partagé.
  `--max-redirects 0` en complément si les secrets ne doivent suivre aucun hop.

## 6.7 Checklist opérateur (à cocher par mission)

1. [ ] `--proxy socks5h://…` en réseau hostile ; `socks5://` banni.
2. [ ] `--allow-private` absent (sauf lab tracé).
3. [ ] `--export-encrypted` seulement si reprise nécessaire ; stockage chiffré.
4. [ ] `--no-redact` jamais en partagé ; dump minimal ; rapports `0o600` + `--force` conscient.
5. [ ] OOB : collaborateur auto-hébergé, jamais de domaine tiers ; egress DB non proxyfiable assumé.
6. [ ] `--dry-run` passé + scope relu avant chaque phase active **et sur chaque ingest**
   (openapi/sitemap/raw-dir/stdin).
7. [ ] `--allow-secret-reuse` conscient en bulk/import (un secret = une origine ;
   multi-scopes = runs séparés) ; `--max-redirects` relu (`0` si secrets sensibles).
8. [ ] `--allow-knowledge` **OFF par défaut** (ON = persistance `~/.cache/injekt/knowledge.json`
   assumée, agrégats anonymes uniquement).
9. [ ] Dossier d'affaire **hors repo** : `*.enc`, `report.json`, raws Burp jamais
   committés (`.gitignore` vérifié).
