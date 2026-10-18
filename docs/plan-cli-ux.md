# Plan : UX CLI — diagnostics `INCONCLUSIVE`, doctor, consolidation (suivi d'avancement)

> Doc de pilotage. Source de vérité pour découper le chantier UX en phases committables.
> Chantier **complémentaire** de `docs/REFACTOR_PLAN.md` (qui, lui, restructure les god-files) :
> ici on ne restructure pas le code, on réduit la surface CLI et on rend la sortie actionnable.
> Numérotation de continuité de la roadmap `docs/ROADMAP-v1.0.md` : chantiers **C14–C18**.
>
> Principes intangibles : défaut OFF = byte-identical, `deny(unsafe,unwrap,expect,dbg,todo)`,
> MSRV 1.88 / édition 2024, zero-persistence (aucun nouvel état sur disque), `Scrubber`
> sur toute sortie, `socks5h://` uniquement, bounded `buffer_unordered(threads)` +
> `CancellationToken`. Gate de chaque phase : `cargo fmt --check && cargo clippy -- -D
> warnings && cargo test` verts + doc-tests.

---

## Table des matières

1. [Décisions figées avec l'opérateur](#0-décisions-figées-avec-lopérateur)
2. [Audit code réel — hypothèses corrigées](#1-audit-code-réel--hypothèses-corrigées)
3. [C14 — Moteur de diagnostics `INCONCLUSIVE`](#2-c14--moteur-de-diagnostics-inconclusive)
4. [C15 — `injekt doctor`](#3-c15--injekt-doctor)
5. [C16 — CLI vague 1 (zéro breaking)](#4-c16--cli-vague-1-zéro-breaking)
6. [C17 — CLI vague 2 (migrations coexistantes)](#5-c17--cli-vague-2-migrations-coexistantes)
7. [C18 — Dry-run v2 au niveau requête](#6-c18--dry-run-v2-au-niveau-requête)
8. [Politique de migration et versionnage](#7-politique-de-migration-et-versionnage)
9. [CLI cible et schéma JSON (annexe)](#8-cli-cible-et-schéma-json-annexe)
10. [Suivi d'avancement](#9-suivi-davancement)

---

## 0. Décisions figées avec l'opérateur

- **Objectif** : sortie actionnable (chaque `INCONCLUSIVE` → cause + commande rejouable),
  surface CLI ~50 flags → ~20 visibles (le reste en config TOML), `doctor` pour tuer
  la classe d'erreurs de config silencieuse.
- **Ne pas toucher** : `--confirm` C6 (implémenté, second-pass strict réel),
  `init` / `completions` / `man` (existent, cachés de `-h`), MCP core, moteur de
  détection, calibration des signaux (`infer_signal_and_trials`), zéro mode
  interactif, zéro mémorisation entre runs.
- **Ordre des phases** : C14 → C15 → C16 → (gate utilisateur + suite verte) → C17
  dans un prompt/PR dédiée → C18. Rationale : C14 change le sentiment d'usage
  sans toucher un seul flag CLI ; C17 est la seule phase large, menée sur socle vert
  et réversible (mur de dépréciation).
- **Diagnostics** : table de décision déterministe (pas d'heuristique libre),
  max 1 suggestion par run, priorité stricte entre causes.
- **Suggestion = argv complet rejouable** : provenant de l'argv capturé dans
  `main`, patché, **scrubbé** avant affichage (les cibles portent des tokens).
- **Migration CLI** : preneur d'un flag ancien = warning stderr scrubbed + commande
  équivalente affichée ; flags anciens fonctionnels **2 releases** avant suppression.
- **Config interne inchangée** : les consolidations C17 ne fusionnent que la
  couche clap ; `EnumConfig` / `MatcherConfig` restent identiques, la CLI mappe
  nouveau → même config. Parité MCP obligatoire (`mcp/tools/{mod,params}`).
- **Doctor** : 0 requête HTTP par défaut (OPSEC) ; chaque check est une fn pure
  testée sans réseau.
- **Dry-run v2** : étend le dry-run C11 existant (`cli::plan`), construit via les
  builders purs (`build_injection_spec_with_raw`, `resolve_effective_tampers`) —
  pas de mock de transport, assert 0 requête réseau.
- **Schema évolutif** : tout ajout au `JsonReport` = bump `schema_version` + regen
  golden `tests/integration_freeze_v1.rs` **documentée** dans CHANGELOG (le freeze
  existe pour détecter le drift, pas pour interdire l'évolution volontaire).

## 1. Audit code réel — hypothèses corrigées

Relecture vérifiée du code (2026-10-19). Plusieurs hypothèses de la discussion
initiale étaient **fausses** — elles ne doivent pas réapparaître dans les prompts
d'implémentation :

| Hypothèse discutée | Réalité du code |
|---|---|
| `--confirm` "warning-only" | FAUX — implémenté (`engine::confirm`, scope `All`/`MediumRisk` auto) |
| `init` / `completions` / `man` à ajouter | existent (`cli/commands/scaffold.rs`, cachés de `-h`) |
| `--dry-run` à ajouter | existe au niveau plan (C11, `cli::plan`) — C18 l'enrichit |
| Precedence CLI > env > config > profile > defaults à ajouter | déjà codé (`Cli::file_cache`, `file_config.rs`) |
| Auto-tampers WAF à ajouter | déjà fait (`resolve_effective_tampers`, testé) |
| `INCONCLUSIVE` ≠ CLEAN à garantir | déjà garanti (`reporting::console::run_status`, testé) |
| Deprecation warnings scan / recon scan à ajouter | déjà centralisés (`commands/common.rs::warn_scan_explicit`) |

Écart réel identifié au passage : le message `InjektError::NoTarget` (`src/lib.rs`)
des codes dépréciés (`injekt scan --target`) — fix cosmétique en C16.
`Cargo.toml` est déjà à l'état de l'art (rust-version 1.88 explicite, clap 4.6.x,
deny lints en `[lints.*]`) — rien à moderniser côté packaging.

## 2. C14 — Moteur de diagnostics `INCONCLUSIVE`

Cœur du plan. Le moteur décide chaque cause d'arrêt et produit **une** commande
corrective rejouable : la documentation exécutable du tool.

**Fichiers**

- Nouveau : `src/engine/diagnostics.rs` — types purs, 0 IO, 0 réseau.
- Touchés : `engine::pipeline` `run_internal` (les 3 retours `Inconclusive` précoces
  + la dégradation finale : budget pré-baseline, baseline instable, baseline 5xx,
  budget/durée/cancel), `engine::orchestrator` (re-export), `crate::session::state`
  (setter RAM-only `set_inconclusive_cause`), `reporting::console::print_run_summary`,
  `reporting::json` (champ optionnel), `src/main.rs` + `cli::args` (capture argv).

**Design**

- [x] `InconclusiveCause` (`#[non_exhaustive]`, match exhaustifs) :
  `UnstableBaseline{statuses}` · `BaselineUnreachable` · `WafBlocked{count_403}` ·
  `RateLimited{count_429}` · `NetworkTimeout` · `BudgetExhausted` · `DurationExpired`
  (les deux derniers = info pure, sans suggestion).
- [x] `Diagnostic::derive(sig) -> Option<Diagnostic>` **pure et déterministe**, priorité
  stricte : unstable > unreachable > waf > rate > timeout > budget. Max 1/run.
- [x] Sources de la dérivation = ce que le tail de `run_internal` agrège déjà :
  `!baseline.is_stable()`, `baseline_all_error`, `BudgetConfig::is_over_request_budget
  / is_over_max_duration`, compteurs `403/429` drainés du client via
  `SessionState::add_detectability`/`absorb_detectability` (limité : absent si
  `shared_client` — recon scan) non `take_detectability_counts`,
  `cancel.is_cancelled()`.
- [x] Suggestion = patch appliqué à l'argv original puis `Scrubber::scrub`
  (un flag n'est ajouté que s'il est absent de l'argv ; argv empty ⇒ `None`,
  jamais de commande fabriquée sans cible). Mapping figé :
  - `UnstableBaseline` / `BaselineUnreachable` → `--fetch-using direct`
    (+ `--techniques time` si l'oracle booléen est indiscernable) ;
  - `WafBlocked` → `--tamper space2comment,randomcase` (chaîne complète ; absent si
    l'opérateur a déjà posé `--tamper` explicitement) ;
  - `RateLimited` → `--ignore-code 429 --rate-limit 2` seulement si un des deux
    flag est absent (doubler le jitter abandonné : le pacing vit déjà dans le
    client, une suggestion ici ajouterait une seconde source de vérité sur le débit) ;
  - `NetworkTimeout` → « run `injekt doctor` » ;
  - `BudgetExhausted` / `DurationExpired` → pas de suggestion (info pure).
- [x] Affichage : une ligne `→ suggestion: <cmd scrubbée>` sous `INCONCLUSIVE`
  dans `print_run_summary` (helper pur `suggestion_line`, testé) ; champ
  `diagnostic: Option<{cause, evidence, suggestion, why}>` dans `JsonReport`
  (pas de champ `schema_version` dans le crate : freeze = extension
  `tests/golden/v1-report-schema.json` + regen délibérée documentée).

**Tests**

- [x] 1 test unitaire **par variante** (suggestion == exactement la commande attendue).
- [x] Wiremock : baseline instable (200/500/200 → `UnstableBaseline`) et 429 répétés
  (`RateLimited`) — la cause remonte au rapport (intégration via `run_scan`) et au
  chemin programme (`Engine::run`, suggestion `None` sans argv).
- [x] Console : helper pur `suggestion_line` (exact) + smoke `print_run_summary` ;
  regen `integration_freeze_v1` commentée dans le commit.

**Acceptation** : démo wiremock `INCONCLUSIVE → suggestion` complète ; fmt/clippy/test
verts ; aucune évolution du moteur de détection.

## 3. C15 — `injekt doctor`

Nouvelle sous-commande vérifiant la **config locale** — jamais la cible.

**Fichiers** : nouveau `src/cli/commands/doctor.rs` ; variante `Doctor` dans
`Commands` ; early-branch dans `main.rs` comme `Mcp` (avant l'init tracing,
stdout propre).

**Checks** (fn pures, `fn check_x(&Cfg) -> CheckResult`)

- [ ] config : `./injekt.toml` puis `~/.config/injekt/config.toml`, parse TOML,
  résumé (profile, threads) — réutilise `file_config.rs` tel quel ;
- [ ] proxy : ré-exécute `http::proxy::ProxyConfig::parse` (`socks5://` → l'erreur
  `DnsLeak` **existante**, ne pas dupliquer) ;
- [ ] cohérence jitter/rate : `1/rate_limit` ≥ jitter_mean − 2σ ; sinon warning
  chiffré « cadence plus rapide que le jitter → pattern détectable » (parse la
  string `"mean,std"` des valeurs `cli::profile::Profile`) ;
- [ ] ingestion : paths des sources ingestion existent et lisibles (lexical).

Sortie : `✓ / ! / ✗` une ligne chacun, exit 0 sans `✗`, 1 avec. Test sans réseau
(mocker le TCP si nécessaire) ; toute IO réseau hors flag explicite est une
régression OPSEC.

**Acceptation** : `injekt doctor` sur 3 configs (valide / TOML cassé / `socks5://`)
→ sortie attendue ; 0 socket ouvert par défaut.

## 4. C16 — CLI vague 1 (zéro breaking)

Une PR de trois items (petits, committables séparément) :

- [ ] **Positional** : `injekt <URL>` (top-level, coexiste avec `Option<Commands>` —
  token non-matching subcommand → positional) et `injekt auto <URL|HOST>` (positional
  dans `AutoArgs`, bare host ⇒ `--with-recon` inchangé). Précidence cible documentée :
  `--raw-file > positional > --target(-u) > env`. Verrouillage parse par `proptest`
  dans `tests/proptest_parsers.rs` (+ codec subcommand-first).
- [ ] **Format par extension** : `--output x.sarif` ⇒ SARIF quand `--format` n'est
  défini ni par CLI ni par env ni par config. Ordre final : CLI > env > extension >
  config > default `json`, warning si conflit.
- [ ] **Fix cosmétique** : `InjektError::NoTarget` (message déprécié), commentaire
  mort `InitArgs` sur `Cli::force` (`cli/args/root.rs`).

**Acceptation** : `injekt <URL>` tourne ; `--output x.sarif` sans `--format` → SARIF ;
roughly zéro changement de comportement de détection.

## 5. C17 — CLI vague 2 (migrations coexistantes)

Prompt/PR **dédiée**, un commit par migration, gate utilisateur entre chaque.
Interne inchangé (`EnumConfig`, `MatcherConfig`), parité MCP vérifiée.

- [ ] **`--enum <items>` + `--scope <db[.table[.col]]>`** fusionnent le cluster
  `EnumOpts` (15 bools : `--dbs --tables --columns --dump -b --current-user
  --current-db --hostname --db --table --column`). Items : `dbs,tables,columns,dump,
  user,db,hostname`. `--start/--stop/--count` inchangés. Anciens flags → warning +
  commande équivalente + mapping vers les mêmes champs `EnumConfig`. ⚠ `mcp/tools/params.rs`
  expose les mêmes — les deux shapes restent.
- [ ] **`--input <PATH|-|DIR>`** (detection auto du format : dir → raw-dir ; `.xml`
  racine `<urlset>` → sitemap ; `.json/.yaml` clé `openapi` → OpenAPI ; `-` → stdin ;
  sinon liste TXT `#`-commenté) fusionne les 7 modes ingestion. Point de branch
  central : `target::ingest` (`collect_targets`). `is_bulk()` couvre le nouveau flag.
- [ ] **`--match EXPR` / `--veto EXPR`** (rép.) remappent `--string/--not-string/--code`
  vers `detection::matcher::MatcherConfig`. Grammaire figée : `status==N`, `status!=N`,
  `body=CONTENU` (contient littéral), `body~RE` (regex) — littéral et regex
  **distingués explicitement**. `--text-only` reste un preprocessing (pas un veto).
- [ ] **Session namespace** : `injekt session export <PATH>` / `session replay <FILE>`
  ; `replay` devient alias caché déprécié ; `--export-encrypted` déprécié ; réutilise
  `session::export` tel quel (v2 argon2id 0o600).

**Acceptation par migration** : flag ancien fonctionnel avec warning + ligne
équivalente ; suite `integration_enumeration.rs` / `tests/mcp_stdio.rs` maintenue
verte sur les deux shapes.

## 6. C18 — Dry-run v2 au niveau requête

Étend le dry-run C11 (`cli::plan`), ne recrée pas.

- [ ] Après le plan, imprimer les **specs de requêtes post-tamper** : `build_injection_spec_with_raw`
  (builder pur, retourne la spec sans envoyer) + `resolve_effective_tampers` +
  ordonnancement (`engine::schedule`). Contenu : baselines ×3 + premier pair
  TRUE/FALSE par technique et param planifiés.
- [ ] `--dry-run[=N]` borne l'affichage (défaut 10) ; jitter exact quand `--seed`,
  sinon distribution ; sortie scrubbée ; section priors knowledge conservée.
- [ ] Test critique : **assert 0 requête** (le client HTTP ne se construit pas) —
  regression OPSEC immédiatement visible.

**Acceptation** : dry-run v2 sur cible fictive → specs post-tamper complètes,
`0 requête` attesté dans le test.

## 7. Politique de migration et versionnage

- Coexistence : flags anciens fonctionnels + warning pendant **2 releases** puis
  suppression (listées dans CHANGELOG + table ancien→nouveau).
- Mapping de release : à synchroniser avec le plan de versions de `docs/ROADMAP-v1.0.md`
  (la v0.4 y a déjà du contenu) — cible indicative : C14→C16 en une release,
  C17 en une release dédiée, C18 dans la suivante avec les premières suppressions.
- Tout flag déplacé en config TOML reste settable ; section `[legacy]` documentée.
- CHANGELOG : entrée par chantier + section « Migration guide » dès C17.

## 8. CLI cible et schéma JSON (annexe)

```text
injekt [OPTIONS] <URL>            # scan direct (positional C16)
injekt auto [OPTIONS] <URL|HOST>  # recon → scan → escalation → enum
injekt recon crawl <URL>          # découverte seule
injekt session export <PATH>      # export chiffré (C17)
injekt session replay <FILE>      # inspection chiffrée (C17)
injekt doctor                     # santé de la config (C15)
injekt init | completions | man | info | mcp     # existants, cachés
```

Exemple de diagnostic (JSON, champ optionnel — retro-compatible) :

```json
{
  "target": "https://lab.example.com/?id=1",
  "state": "INCONCLUSIVE",
  "diagnostic": {
    "cause": "UnstableBaseline",
    "evidence": "5/5 baselines differ (statuses mixtes) — oracle inutilisable",
    "suggestion": "injekt https://lab.example.com/?id=1 --fetch-using direct --techniques time",
    "why": "un oracle de comparaison instable ne peut pas valider un booléen TRUE/FALSE"
  }
}
```

## 9. Suivi d'avancement

> Format : `> Progrès AAAA-MM-JJ (chantier étape): …` — mêmes conventions que
> `docs/REFACTOR_PLAN.md`.

- > Progrès 2026-10-19 (C14 done): moteur diagnostics `INCONCLUSIVE` câblé —
  `src/engine/diagnostics.rs` (types purs : `InconclusiveCause`/`Diagnostic`/`DiagSignals`,
  priorité figée, patch argv déterministe + `shell_quote`), dérivation aux 3 points de
  dégradation du pipeline (`early.rs` budget pré-baseline + baseline instable /
  `finalize.rs` tail), `SessionState::set_inconclusive_cause` (RAM-only, zeroized),
  `EngineConfig.argv: Zeroizing<Vec<String>>` capturé dans `main` (`Cli::captured_argv`,
  MCP ⇒ `None`), `JsonReport.diagnostic` optionnel (`skip_serializing_if` — rapport
  sans diagnostic byte-identique), console `→ suggestion:` sous INCONCLUSIVE via
  `print_run_summary`. Tests : 1/variante + priorités + scrub (unit), intégration
  wiremock `integration_diagnostics.rs` (unstable via `run_scan` + scrub token,
  429 répétés → `RateLimited`, engine sans argv ⇒ suggestion `None`), SessionState
  tests. Limites documentées : `NetworkTimeout` tient la table sans producteur live
  (client ne compte pas les timeouts), compteurs detectability absents si
  `shared_client`, `cancel` ⇒ jamais de diagnostic. Gates fmt/clippy/test/doc/deny
  verts ; regen golden `v1-report-schema.json` délibérée (clé `diagnostic`, revue
  du diff : 4 clés fixes + top-level `diagnostic` quand attaché).
- [aucun encore] Période : doc créé, C14 non démarré.
