# 01 — Installation & configuration

## 1.1 Installation

### Binaire précompilé (sans Rust)
```bash
# Install automatique (Linux/macOS) : détecte OS/arch, vérifie SHA256SUMS, installe dans ~/.local/bin
curl -fsSL https://raw.githubusercontent.com/HaK0exe/injekt/main/install.sh | sh
# Options :
INJEKT_INSTALL_DIR=~/.local/bin INJEKT_VERSION=v0.3.0 sh install.sh
# Toujours lire install.sh avant curl|sh (règle curl-pipe).
```

```bash
# Manuel : GitHub Releases → vérifier SHA256SUMS → extraire → tester
tar xzf injekt-*-x86_64-unknown-linux-gnu.tar.gz
cd injekt-*/
./injekt --no-banner info
```

### Depuis les sources (Rust 1.88+, édition 2024)
```bash
git clone https://github.com/HaK0exe/injekt
cd injekt
cargo build --release        # binaire ./target/release/injekt
cargo install --path .       # vers $CARGO_HOME/bin

# Checks exigés (dev) :
cargo fmt --check
cargo clippy -- -D warnings
cargo test
cargo test --doc
```

## 1.2 Premier contact : `info`

```bash
injekt info
injekt --no-banner info   # stdout propre (banner sur stderr)
```

Sortie attendue (v0.3.0) :
```
Techniques      boolean, time, error, union, stacked, oob, json
Tampers         space2comment, space2plus, space2tab, space2newline, space2randomblank, ...
Profiles        quick, balanced, stealth, aggressive
OOB             opt-in via --oob-domain <collaborator> [--oob-poll-url <url> with {token}]
Request tampers --hpp, --chunked
DBMS            mysql, postgres, mssql, oracle
Docs            docs/OPSEC.md
```

> Si `info` ne liste pas 7 techniques / 19 tampers / 4 DBMS → binaire périmé.

## 1.3 Profils (`--profile`)

Aucun profil n'active proxy ni extraction — toujours opt-in explicite.

| Profil | Threads | Timeout | Retries | Delay | Rate | Jitter (ms) | Level | Techniques |
|---|---|---|---|---|---|---|---|---|
| `quick` | 10 | 15 s | 1 | 200 ms | 20/s | 200,100 | 1 | boolean,error |
| `balanced` | 5 | 30 s | 3 | 500 ms | 10/s | 750,250 | 1 | all (= défaut historique) |
| `stealth` | 2 | 30 s | 3 | 800 ms | 3/s | 1200,400 | 1 | boolean,error |
| `aggressive` | 8 | 30 s | 3 | 500 ms | 10/s | 500,200 | 3 | all |

```bash
injekt --target "https://example.com/?id=1" --profile quick
injekt --target "https://example.com/?id=1" --profile stealth --proxy socks5h://127.0.0.1:9050
injekt --target "https://example.com/?id=1" --profile aggressive --level 3
# Un flag explicite gagne toujours sur le profil :
injekt --target "https://example.com/?id=1" --profile stealth --threads 5 --techniques boolean,error,union
```

## 1.4 Config file + env (`injekt init`)

Précédence stricte : **CLI > `INJEKT_*` env > fichier config > `--profile` > défauts**.

```bash
# Génère un starter (0o600 sur Unix) :
injekt init --preset stealth --path ./injekt.toml
cat ./injekt.toml
# Écraser un existant :
injekt init --preset balanced --path ./injekt.toml --force   # --force est global
```

Contenu type :
```toml
profile = "stealth"
threads = 2
timeout = 30
retries = 3
delay = 800
rate_limit = 3.0
jitter = "1200,400"
level = 1
techniques = ["boolean", "error"]
# proxy = "socks5h://127.0.0.1:9050"
# oob_wait_secs = 5
# Secrets (--cookies, Authorization) INTERDITS ici (volontaire).
```

```bash
# Fichier explicite + env :
injekt --config ./injekt.toml --target "https://example.com/?id=1"
INJEKT_PROFILE=stealth INJEKT_THREADS=2 INJEKT_PROXY=socks5h://127.0.0.1:9050 injekt --target "https://example.com/?id=1"
```

Variables supportées : `INJEKT_PROFILE|CONFIG|TARGET|THREADS|TIMEOUT|RETRIES|DELAY|`
`RATE_LIMIT|JITTER|TECHNIQUES|LEVEL|PROXY|DBMS|TAMPER|OOB_DOMAIN|OOB_POLL_URL|OOB_WAIT_SECS|PASSPHRASE`.
`RUST_LOG` override le niveau `tracing` (`info` défaut, `-v` → `debug`).
Fichier auto-découvert : `./injekt.toml` puis `~/.config/injekt/config.toml`.
Un `--config` explicite manquant/illisible = **exit 1** ; auto-découvert = warning seul.

## 1.5 `dry-run` — valider sans tirer

```bash
# N'envoie AUCUNE requête : résout config + cibles + plan d'exécution
injekt --target "https://example.com/?id=1" --profile stealth --dry-run
injekt auto --target example.com --with-recon --dry-run
injekt --bulk-file targets.txt --dry-run
injekt --openapi-file openapi.json --dry-run
```

Checklist pre-engagement :
- [ ] `dry-run` affiche `profile/config/threads/rate/jitter/level` attendus.
- [ ] Nombre de cibles correct (bulk/openapi/sitemap/raw-dir : surprises fréquentes).
- [ ] Proxy affiché si réseau hostile (jamais de scan nu sur cible WAFisée sans raison).
- [ ] `--allow-private` **absent** sauf lab.

## 1.6 Utilitaires : `completions`, `man`

```bash
injekt completions bash >> ~/.bash_completion
injekt completions zsh   # fish | powershell | elvish aussi
injekt man | man -l -    # man page roff sur stdout
```

## 1.7 Pièges de démarrage

| Symptôme | Cause | Fix |
|---|---|---|
| `socks5://` rejeté | Fuite DNS locale | Utiliser `socks5h://` (avec `h`) |
| Target privée rejetée | Anti-SSRF | `--allow-private` **lab uniquement** |
| `--bulk-file` + `--target` refusés | Modes exclusifs | Un seul mode à la fois |
| `--export-encrypted` + `--bulk-file` refusés | Conflit | `--output` pour rapport bulk agrégé |
| Config ignorée | Précédence | CLI/env gagnent sur fichier/profil — vérifier `resolution_summary` en `-v` |
