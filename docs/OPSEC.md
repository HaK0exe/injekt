# OPSEC — injekt

## Principes

- **Zéro persistance** : `SessionState` en `Arc<RwLock<_>>` RAM, `ZeroizeOnDrop`, aucun fichier sauf `--export-encrypted` opt-in.
- **Anonymisation** : `scrubber.rs` masque `Authorization`, `Cookie`, `Set-Cookie`, `X-Api-Key`, JWT `eyJ...`, `AKIA*`, PEM. `[REDACTED]` ou hash 8 hex.

## Réseau

### Proxy & DNS
- `--proxy socks5h://127.0.0.1:9050` (Tor) — **obligatoire `h`** pour DNS distant. `socks5://` rejeté (`ProxyError::DnsLeak`) pour éviter fuite DNS locale.
- `--proxy http://proxy:8080` pour HTTP. Vérifier `http::proxy::ProxyConfig`.

### Jitter humain
- `http/jitter.rs` : `Normal(mean=750ms, sd=250ms, min=200ms)`. `Jitter::next_delay()` + `sleep().await` entre requêtes. Jamais d'intervalle fixe.
- Configure via `--jitter "750,250"` ou `--rate-limit 5` (token bucket).

### Identité
- `http/identity.rs` : pool UA Chrome 126 / Firefox 128 / Safari 17.5, `Sec-CH-UA` aligné, `Accept`/`Accept-Language` cohérents. Rotation `Identity::random()`.
- Ordre headers normalisé (UA → Accept → ...). Limitation JA3: `rustls` empreinte fixe (pas de `ClientHello` random). Mitigation: proxy externe ou `docs` mention.

### Cookies
- `http/cookies.rs` : jar mémoire `HashMap<String, SecretString>`, zeroized, jamais disque.

## Export chiffré (OPT-IN)

```sh
injekt --target "https://example.com/?id=1" --export-encrypted ./session.enc
# passphrase demandée, dérivation Argon2id → XChaCha20-Poly1305, salt 16B, nonce 24B
injekt --import ./session.enc
```
- Artefact sensible : prévenir utilisateur, `warn!` log. Clé jamais stockée, `SecretString` zeroized.

## Logs & preuves

- `reporting/evidence.rs` : toute sortie passe `Scrubber::scrub()`. `--no-redact` uniquement en local explicite.
- `tracing` niveau `info` par défaut, `verbose` → `debug`. Aucun secret en log.

## Limitations connues

- **JA3** : `rustls` JA3 stable. Pour anonymisation TLS avancée, utiliser proxy `boringssl` externe. Documenté.
- **WAF** : détection 403/406 répétitifs → `Baseline::is_waf_blocked()`, ajuster threads/jitter.
- **OOB** (`techniques/oob`, OPT-IN) : exfil DNS/HTTP via `--oob-domain <collaborateur>` + `--oob-poll-url <url>` (placeholder `{token}`). Sans `--oob-poll-url`, sondes envoyées mais jamais auto-confirmées (vérif manuelle UI collaborateur, aucun finding sans preuve). L'egress part du **serveur DB cible** (non proxyfiable) — collaborateur auto-hébergé recommandé, jamais de domaine tiers non contrôlé.

## Checklist opérateur

1. Toujours `--proxy socks5h://...` en réseau hostile.
2. Vérifier `--allow-private` désactivé (anti-SSRF) sauf lab.
3. Utiliser `--export-encrypted` uniquement si reprise nécessaire.
4. Ne jamais `--no-redact` en rapport partagé.
