# 06 — OPSEC (anonymisation, réseau, secrets)

> `injekt` est OPSEC-first : RAM-only, jitter humain, UA réalistes, `socks5h` imposé,
> scrubber auto. Mais **l'OPSEC reste de la responsabilité opérateur** (proxy, cadence,
> scope, artefacts). Ce chapitre est **load-bearing**.

## 6.1 Zéro persistance (par défaut)

- `SessionState` = `Arc<RwLock>` RAM + `ZeroizeOnDrop`. Cookies/tokens/données
  extraites/passphrases = `secrecy::SecretString` + `zeroize`.
- **Aucune écriture disque** sauf opt-in : `--export-encrypted` / `--output` /
  `--import` / `recon import --file`. Tout le reste est RAM.
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
| `Authorization: Bearer …`, `Cookie`, `Set-Cookie`, `X-Api-Key` | `[REDACTED]` |
| JWT `eyJ…` | `[REDACTED]` (+ hash 8-hex) |
| AWS `AKIA[0-9A-Z]{16}` | `[REDACTED]` (+ hash) |
| PEM `-----BEGIN PRIVATE KEY-----` | `[REDACTED]` |

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
- TLS : `rustls`, **JA3 stable** (limite documentée — passer par proxy externe type
  boringssl/mitmproxy pour randomiser).

## 6.4 Anti-SSRF (`--allow-private`)

```bash
# Lab local uniquement :
injekt --target "http://192.168.1.10/?id=1" --allow-private
injekt --target "http://127.0.0.1:8080/?id=1" --allow-private
```

Privé/loopback **rejeté par défaut** (MCP : `allow_private=false` aussi).
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
- Pour reprendre : relancer `scan --target <url>` (pas de "resume" depuis l'export).

## 6.6 Checklist opérateur (à cocher par mission)

1. [ ] `--proxy socks5h://…` en réseau hostile ; `socks5://` banni.
2. [ ] `--allow-private` absent (sauf lab tracé).
3. [ ] `--export-encrypted` seulement si reprise nécessaire ; stockage chiffré.
4. [ ] `--no-redact` jamais en partagé ; dump minimal ; rapports `0o600` + `--force` conscient.
5. [ ] OOB : collaborateur auto-hébergé, jamais de domaine tiers ; egress DB non proxyfiable assumé.
6. [ ] `--dry-run` passé + scope relu avant chaque phase active.
