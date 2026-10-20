# CHANGELOG — injekt

Format: `Added / Changed / Fixed / Security` par version. Les courbes
bench (`requêtes`, `temps`, `FP`, `détectabilité`) sont remplies depuis
`bench/reports/history.jsonl` après runs live — `TBD(history.jsonl)`
signifie "en attente de runs live", pas une régression.

Seuils calibrés (C7, gelés v1.0-rc — voir `src/reporting/verdict.rs` +
`tests/fixtures/verdict_calibration.json` + `tests/integration_reporting_c7.rs`):

- `High` → précision ≥ 95 % : `confidence ≥ 0.85` **et** `false_positive_prob ≤ 0.05`
- `Medium` → précision ≥ 80 % : `confidence ≥ 0.70` **et** `false_positive_prob ≤ 0.20`
- `Low` : tout le reste (aucune précision promise)
- Source préférée : `bench/reports/history.jsonl` via
  `load_bench_thresholds()` ; en l'absence d'historique (état actuel),
  repli conservateur compilé ci-dessus (les deux signaux doivent concorder).
  Toute recalibration sous les précisions promises casse le test de calibration.

## [Unreleased]

### Added
- **C17 — CLI vague 2, migration 1 (`--enum` + `--scope`)** : `--enum <ITEMS>`
  (items figés par value_parser : `dbs,tables,columns,dump,banner,user,db,hostname`,
  séparés par `,` — items inconnus ⇒ usage exit 2) et `--scope
  <DB[.TABLE[.COLUMN]]>` remplacent le cluster legacy d'`EnumOpts` en conservant
  le mapping vers les mêmes champs internes d'`EnumConfig` (UNION : une
  nouvelle shape ne désactive jamais un flag explicite). La parité MCP est
  inchangée : les paramètres booléens individuels écrivent le même socle.
- **C17 — CLI vague 2, migration 2 (`--input <PATH|-|DIR>`)** : ingestion
  unifiée sur les mêmes loaders legacy (`target::ingest`). Sniff figé : `-`
  → stdin; dossier existant → raw-dir; `.json/.yaml/.yml` avec un marqueur
  `openapi` dans le premier KiB → openapi; `.xml` avec un document `<urlset`
  → sitemap; sinon liste TXT (`#` commentaires). Source additive comme les
  modes legacy (dedup sur les chevauchements, cap `MAX_BULK_TARGETS`
  inchangé) ; `is_bulk()` couvre `--input` (pipeline bulk déclenché) ;
  `injekt doctor` liste désormais la 6e source (`--input` : fichier ou
  dossier tous deux valides, alias stdin accepté).
- **C17 — CLI vague 2, migration 3 (`--match`/`--veto`)** : expressions
  de matcher répétables (OU interne des exprs) remappées exactement vers
  `detection::matcher::MatcherConfig` : `--match status==N` /
  `--veto status!=N` ⇔ `code` (doit être égal) ; `--match body=…` ⇔
  `string` ; `--veto body=…` ⇔ `not_string` ; `--veto status==N` ⇒ champ
  nouveau `veto_codes` (pas d'équivalent legacy) ; `body~RE` ⇒ deux
  listes de regex **compilées dans le resolver** (`match_regex` /
  `veto_regex` — compilation au build de config, jamais par réponse :
  hot path inchangé en CPU). Grammaire figée validée au parse (usage
  exit 2 : forme inconnue, status non-u16, `body=` vide, regex
  non compilable) ; littéral et regex explicitement distincts (`=`
  contains, `~` regex — `regex` déjà dépendance déclarée : zéro nouvelle
  dep). `--text-only` reste un preprocessing (pas un veto).
- **C17 — CLI vague 2, migration 4 (namespace `session`)** :
  `injekt session export <PATH> --import <FILE>` (re-key d'un export
  chiffré : déchiffrement puis rechiffrement **tel quel** du snapshot —
  passthrough byte-for-byte du JSON déchiffré, sel/nonce argon2id
  OS-aléatoires neufs, blob toujours réécrit en version courante = mise à
  niveau v1/v2 → v3 au passage ; 0o600 `create_new`, refus d'écrasement
  sauf `--force`, output auto-vérifié par un déchiffrement immédiat avec
  suppression best-effort si échec) et `injekt session replay <FILE>`
  (shape positionnelle du même moteur d'inspection `replay::run`).
  Passphrases via `INJEKT_PASSPHRASE` (min 12, même valeur des deux côtés
  si env) ou prompt TTY (lecture source puis destination distinctes) ;
  le helper est mutualisé dans `commands::session::passphrase_for_session`
  (le prompt replay historique délègue, où l'absence de TTY/env reste un
  repli gracieux vers le rapport raw-size — pour `session export` c'est
  une erreur bloquante, aucun write sans key material). Offline, 0 socket.
- **P5 — dialecte SQLite complet (`--dbms sqlite`)** : le 5e dialecte
  (`DbmsKind::Sqlite` — fingerprint `sqlite_version()` et grammaire
  `src/dbms/sqlite/*` présents depuis la base) est routé de bout en bout
  par le hint `--dbms` : payloads error (`abs(-9223372036854775808)`
  overflow, `json_extract('__bad__','$') malformed`), time (proxy CPU
  `RANDOMBLOB`/`LIKE` — pas de `SLEEP()` SQL portable), boolean/union
  (terminator ` --`), énumération `sqlite_master` / `pragma_table_info`
  (`--tables`/`--columns`), dumps par `group_concat` paginé `LIMIT/OFFSET`,
  identité (`banner` = `sqlite_version()`, `current_db` = `main`,
  `current_user` = `sqlite`), extraction blind `UNICODE(SUBSTR((q),i,1))`.
  Alias `sqlite3` accepté aux trois routeurs (`normalized_dbms_hint`,
  `dbms_hint_kind`, `DbmsBelief::from_hint`) et dans le docstring MCP.
  **Défaut inchangé (OFF)** : sans `--dbms`, l'auto-fingerprint reste
  byte-identique (aucune requête supplémentaire) — le hint ne fait que
  restreindre le vocabulaire du run. Nouvelle suite
  `tests/integration_dbms_sqlite.rs` (wiremock : confirmation boolean +
  dump tables via l'oracle `LENGTH`/`UNICODE`, pureté dialecte sur le
  sink de requêtes — aucun payload mysql/pg/mssql/oracle envoyé sous
  hint sqlite, alias `sqlite3`). Docs playbook 05/README. Comble le gap
  G5 (`docs/plan-gaps-2026.md` §2).

### Changed
- Flags legacy d'`EnumOpts` (`--dbs/--tables/--columns/--dump`,
  `-b/--banner`, `--current-user`, `--current-db`, `--hostname`,
  `--db/--table/--column`) : **deprecated, fonctionnels encore 2 releases**.
  Un warning unique par run liste le mapping équivalent (`--dbs -> --enum
  dbs`, le triple → `--scope`) sans valeur écho (scrub-by-design). Gate
  `recon` strict étendu aux deux nouvelles shapes (pas d'`--auto-enumerate`
  ⇒ ignorées avec le warning historical).
- Modes ingestion legacy (`--bulk-file/-m`, `--stdin`, `--openapi-file`,
  `--sitemap-file`, `--raw-dir` — pas concernés : `--raw-file` reste la
  voie single-scan exclusive) : inchangés et alternatifs à `--input` ;
  aucune dépréciation forcée à ce stade (coexistence additive).
- Matchers legacy (`--string`, `--not-string`, `--code`) : **deprecated,
  fonctionnels encore 2 releases** ; warning unique par run + paires
  flag-only (`--string -> --match body=<string>`,
  `--not-string -> --veto body=<string>`, `--code <N> -> --match
  status==<N>` — les valeurs ne sont jamais échos dans une ligne de
  warning). Ordre `matches()` étendu (premier veto gagne) : `code` →
  `veto_codes` → `not_string` → `veto_regex` → conditions valid-page
  (`string` OU `match_regex`). `evidence_suffix()` étendu
  (`re-match:`/`re-veto:`/`status-veto:`, sources truncées 24 chars).
- Namespace `session` (C17 migration 4) : `injekt replay` devient un
  **alias caché déprécié** (fonctionnel encore 2 releases, warning
  flag-only unique à chaque run : `injekt session replay <FILE>`). Le
  flag `--export-encrypted` devient **déprécié** (fonctionnel inchangé
  post-run, warning unique) — la rotation de passphrase passe par
  `injekt session export <PATH> --import <FILE>`.

### Migration guide
- Énumération : `injekt <URL> --dbs --current-user` ⇒ `injekt <URL> --enum
  dbs,user` (ou `--enum dbs --enum user`, répétable).
- Scope : `injekt <URL> --db shop --table users --column password` ⇒
  `injekt <URL> --enum columns --scope shop.users.password`. Un nom de db
  contenant un `.` littéral garde le triple legacy (la CLI n'est pas un
  parseur de noms).
- Ingestion : `--bulk-file f.txt` ⇔ `--input f.txt` (TXT) ; `--stdin` ⇔
  `--input -` ; `--openapi-file spec.json` ⇔ `--input spec.json` (sniff);
  `--sitemap-file sitemap.xml` ⇔ `--input sitemap.xml` (sniff);
  `--raw-dir dumps/` ⇔ `--input dumps/` (dossier). Une source ambiguë
  (JSON sans clé `openapi`, XML sans `<urlset>`) retombe en liste TXT —
  utiliser le mode legacy équivalent si l'intention diffère.
- Matchers : `--string welcome` ⇔ `--match body=welcome` ;
  `--not-string fatal` ⇔ `--veto body=fatal` ; `--code 200` ⇔
  `--match status==200` ; nouveau sans équivalent legacy :
  `--veto status==503`, `--veto body~waf|rate.bound`,
  `--match body~servicing` (regex, validé au parse ; répétable, OU
  interne ; premier veto gagne dans l'ordre `matches()`).
- Le reporting, le rapport JSON et la sortie console restent byte-identiques :
  seul l'appel CLI change (l'engine struct reçoit les mêmes champs).
- Namespace session : `injekt replay --file s.enc` ⇒ `injekt session
  replay s.enc` (shape positionnelle, le flag `--file` reste accepté par
  l'alias legacy jusqu'à sa suppression) ; rotation de passphrase :
  `injekt session export s-v2.enc --import s.enc` (passphrase
  destination distincte sous TTY ; sous env les deux côtés utilisent
  `INJEKT_PASSPHRASE` — une rotation réelle sous env exige deux
  processus avec des envs différents). `--export-encrypted` reste la
  voie d'export inline post-run ; aucun changement de comportement du
  blob (formats inchangés, versions reconnues élargies au re-key).

## [0.4.0] — 2026-10-19 — Hardening v1.0-rc (première release taguée post-v0.3.0)

> **Consolidation de versions :** les jalons C1→C13 documentés plus bas sous les
> intitulés `[0.4.0]`→`[0.7.0]` sont des jalons internes du plan de versions
> (`docs/ROADMAP-v1.0.md` §4), jamais tagués au fil du travail — leurs contenus
> font partie de cette release `0.4.0`. Les intitulés sont conservés pour la
> granularité : à lire comme des jalons, pas des releases taguées.

Roadmap `docs/ROADMAP-v1.0.md` §v1.0-rc : rien de nouveau — geler, durcir, prouver.

### Added

- **C16 — CLI vague 1 (zéro breaking)** : (1) positional `injekt <URL>` /
  `injekt auto <URL|HOST>` (coexiste avec `-u/--target` / env `INJEKT_TARGET` /
  aliases existants ; précidence `--raw-file > positional > --target > env` ;
  positional > env **silencieusement**, conflit usage `TargetConflict`
  (`InjektError`, exit 2) seulement pour un flag `-u/--target` **tapé** ≠
  positional, valeurs égales ⇒ silencieux) ; (2) `--format` déduit de
  l'extension de `--output` (`cli::resolve::format::infer_from_extension` :
  `.json/.sarif/.junit|.xml/.md|.markdown` ; précidence CLI > env
  `INJEKT_FORMAT` > extension > clé `format` du TOML > default `json` ; warning
  de conflit une fois max par invocation (`Arc<AtomicBool>` anti-clone),
  extensions inconnues jamais déduites jamais warning, clé TOML inconnue ⇒
  warn) ; (3) fixes : `InjektError::NoTarget` (message retourne les formes
  positionnelles, exit 2 inchangé), `TargetConflict` helper d'usage,
  commentaire mort `InitArgs`. Zéro flag supprimé, `scan`/`auto --target`/
  aliases inchangés (zéro-break), parité MCP adaptée (`tools/builder`).
  Tests : `tests/integration_cli_c16.rs` (9 tests, binaire réel : positional,
  sarif-par-extension + contenu rendu, config-TOML < extension, warning
  conflit, unknown ext silencieuse) + proptests `tests/proptest_parsers.rs`
  (positional vs subcommand, conflits) + regen délibérée du freeze surface.

- **C15 — `injekt doctor`** (0 socket TCP, 0 fetch — vérifie la config
  LOCALE, jamais la cible, jamais le réseau) : nouvelle sous-commande
  `cli::commands::doctor`, early-branchée dans `main` comme le serveur MCP
  (AVANT l'init tracing et le banner : stdout pur). Quatre checks purs
  `fn check_*(…) -> CheckResult {level: Ok/Warn/Fail, line}` testés sans
  réseau : (1) **config** — même boucle de candidats que `file_config::load`
  (`--config` > `./injekt.toml` > `~/.config/injekt/config.toml`), résumé
  une ligne (preset effectif + provenance, threads) ; fichier absent ⇒
  `Warn` « défauts intégrés » et TOML cassé ⇒ `Fail` avec l'erreur
  ligne/colonne du crate `toml` (écart volontaire vs runtime : le fichier
  cassé y est ignoré en silence — le doctor tue la classe d'erreurs
  silencieuse ; preset fichier inconnu ⇒ `Warn`) ; (2) **proxy** — valeur
  via la résolution CLI>env>config existante, `ProxyConfig::parse` en
  validation de schéma UNIQUEMENT (aucune connexion) : `socks5://` ⇒ `Fail`
  avec le message `DnsLeak` existant («socks5 without remote DNS (socks5://)
  leaks DNS — use socks5h://», jamais réécrit), `socks5h://`/http(s) ⇒ `Ok`,
  absent ⇒ `Warn` opt-in ; userinfo `user:pass@` toujours redirigé (via
  `redact_userinfo` passé `pub(crate)` puis le `Scrubber` standard) ; (3)
  **cadence** — règle figée `1000/rate_limit ≥ jitter_mean − 2·jitter_std`
  ⇒ cohérent, sinon `Warn` chiffré «cadence plus rapide que le jitter →
  pattern détectable» + correction `--rate-limit ≤ 1000/floor` (Σ replié
  ≥ 1.0 comme au runtime, lenience `jitter_from_str` conservée) ;
  neutralité déterministe : rien d'explicite côté rate **et** pas de profil
  ⇒ check neutre (le doctor ne redit pas les défauts) ; rate ≤ 0 ⇒ `Warn`
  (clamp runtime `RateLimiter` 0.1 rps) ; (4) **ingestion** — stat lexical
  `fs::metadata` des 5 sources (`--bulk-file/--raw-file/--raw-dir/
  --openapi-file/--sitemap-file`, `--bulk-file -` = alias stdin) :
  absent/illisible ⇒ `Fail` (le run échouerait à l'ingestion), type inversé
  fichier↔dossier ⇒ `Warn`. Sortie : `✓ / ! / ✗` une ligne par check
  (couleurs via la gate `stdout_colors_enabled` du repo ; `--no-redact`
  respecté), exit `0` sans `✗`, `1` avec (mapping `main` — `run` de `main.rs`
  retourne désormais `Result<ExitCode>` ; `NoTarget` → 2
  inchangé ; `DoctorArgs` sans aucun flag, bras défensif `dispatch`).
  Tests : 26 unitaires sans réseau + `tests/integration_doctor.rs` (7
  tests, **aucun serveur wiremock**), dont un tripwire OPSEC end-to-end :
  binaire réel + `TcpListener` OS jamais accepté — toute tentative de
  connexion du doctor ferait échouer l'`accept → WouldBlock`. Freeze
  surface : regen délibérée du golden `cli-flags.txt` (revue du diff :
  exactement 1 entrée subcommand `doctor`, 0 flag nouveau).
- **C14 — diagnostics `INCONCLUSIVE`** (zéro nouveau flag, zéro évolution du
  moteur de détection) : un run dégradé explique sa cause et propose le rejeu.
  `src/engine/diagnostics.rs` (types purs, 0 IO) : `InconclusiveCause`
  (`#[non_exhaustive]` — `UnstableBaseline{statuses}`, `BaselineUnreachable`,
  `WafBlocked{count_403}`, `RateLimited{count_429}`, `NetworkTimeout`,
  `BudgetExhausted`, `DurationExpired`), `Diagnostic::derive(&DiagSignals)` pure
  et déterministe (priorité stricte unstable > unreachable > waf > rate >
  timeout > budget > durée ; `cancel` ⇒ jamais de diagnostic ; max 1/run),
  posé par les 3 points de dégradation du pipeline (budget pré-baseline,
  baseline instable depuis `run_baseline_phase`, tail `finalize_run`) dans la
  `SessionState` RAM-only (`set_inconclusive_cause`, zeroized). La suggestion
  est un **patch déterministe de l'argv original** (capturé dans `main` via
  `Cli::captured_argv`, transporté en `EngineConfig.argv: Zeroizing<Vec<String>>`
  — Debug masqué, zéro persistance) : `UnstableBaseline`/`BaselineUnreachable`
  → `--fetch-using direct` (+ `--techniques time` si absent) ;
  `WafBlocked` → `--tamper space2comment,randomcase` seulement si l'opérateur
  n'a pas déjà posé `--tamper` ; `RateLimited` → `--ignore-code 429
  --rate-limit 2` (chaque flag seulement s'il est absent) ; `NetworkTimeout`
  → « run `injekt doctor` » ; budget/durée → info pure sans suggestion ;
  argv vide (MCP, code programmatique) ⇒ jamais de commande fabriquée.
  Sorties : `JsonReport.diagnostic` optionnel (4 clés fixes `cause` plat
  `code()`/`evidence`/`suggestion`/`why` ; absent quand `None` — rapport
  pré-C14 byte-identique) scrubbé à la sortie, et une ligne
  `→ suggestion: <cmd scrubbée>` imprimée sous `INCONCLUSIVE` par le résumé
  console. Limites figées : `NetworkTimeout` tient la table sans producteur
  live (le client ne compte pas encore les timeouts — prix pour C15/
  compteurs transport), compteurs `403/429` drainés une seule fois depuis le
  client (`absorb_detectability`) et absents si `shared_client` (recon scan).
  Freeze report : golden `tests/golden/v1-report-schema.json` étendu
  (entrée `diagnostic` + top-level `diagnostic`) — regen délibérée
  `UPDATE_GOLDEN=1 cargo test --test integration_freeze_v1`, diff de 8 lignes
  revu (aucun flag CLI ajouté : `cli-flags.txt` intact).
- Bannière : `ascii_art.txt` est la source unique de *tous* les arts
  (sections délimitées par des lignes `---- nom`, légende = nom de l'art
  au-dessus). Un art est tiré au sort à chaque run (`--seed` le rend
  déterministe) ; `INJEKT_BANNER_ART=<nom>` l'épingle, `=list` énumère,
  `=random` force la rotation. Rendu : dégradé vertical cyan → magenta sur
  les arts clairs, art truecolor imprimé brut sur TTY couleur et strippé
  proprement sur pipe/`NO_COLOR`/`TERM=dumb`. Aucun nouveau flag CLI : le
  freeze surface reste intact.
- Gel surface : `tests/integration_freeze_v1.rs` + goldens
  `tests/golden/cli-flags.txt` (flags `--long` + subcommands) et
  `tests/golden/report-schema.json` (clés JSON triées, valeurs exclues).
  Tout ajout futur de flag/champ/tamper/profile casse le test volontairement
  (`UPDATE_GOLDEN=1` + revue diff pour accepter).
  `Tamper::all_names()` gelé à 19, `Profile::all_names()` gelé à 4.
- Compat legacy vérifiée : findings pré-C7 (6 champs) via `#[serde(default)]`,
  snapshots export v1 (sans `extracted`/`trace`/`seed`), knowledge v1
  (clés hors vocabulaire ignorées), blob chiffré v1/v2 toujours lisibles.

### Changed

- Terminal UX : les scans mono-cible affichent désormais un résumé final
  compact (`CLEAN`/`FINDINGS`/`CANCELLED`, cible, requêtes, durée) ; les logs
  restent sur `stderr` et les résultats humains sur `stdout`. Les couleurs
  suivent `NO_COLOR`, `TERM=dumb`, `CLICOLOR=0` et la détection TTY.

- `src/session/scrubber.rs` (audit v1.0-rc) : couverture étendue —
  headers auth élargis (`X-Access/Session/Csrf-Token`, `X-Api-Secret`,
  `Proxy-Authenticate`, `WWW-Authenticate`, …), userinfo URL
  (`scheme://user:pass@host` → `scheme://[REDACTED]@`), valeurs query
  sensibles (`token`/`sessionid`/`password`/…), valeurs JSON
  (`"password": "…"`), paires form/body (`password=…`), tokens provider
  (GitHub `ghp_`/`github_pat_`, GitLab `glpat-`, Slack `xox*`, Stripe
  `sk_live|test`, OpenAI `sk-`), `Basic` inline, secret AWS
  (`aws_secret…`), collaborator OOB (`oastify`/`interactsh`/
  `burpcollaborator`/`oast.*` → `[REDACTED-OOB]`, clés `oob_domain`/
  `oob_poll_url`/`collaborator` → `[REDACTED]`). `seed` n'est PAS un secret
  (replay) et n'est jamais redacté.
- `src/session/export.rs` : `Snapshot: Zeroize` manuel (findings +
  extracted + trace wiped après sérialisation, `json` déjà `Zeroizing`) ;
  version blob documentée gelée (`v3`, lecteurs v1/v2/v3).
- Refactor interne P4 (aucun impact CLI/surface) : aucun fichier `src/`
  ne dépasse 500 lignes sans être découpé en sous-répertoires avec `mod.rs`
  final en re-exports (`http/client`, `detection/{waf,baseline,response_diff,
  confirmation,control_pair,scanner/scheduler}`, `session/{state,scrubber}`,
  `target/{injection,structured}`, `dbms/context`, `techniques/{tamper,
  detectors}`, `engine/{confirm,detection}`, `mcp/tools`, `recon/crawler`,
  `reasoning/knowledge`, `ai/provider`, `mutation`, … ; ~24 étapes,
  move-only vérifié en multiset, arbre + vérifs dans `docs/REFACTOR_PLAN.md`).
  Résultat : max ~443L par fichier, 1047 tests + 5 doc-tests verts,
  rustdoc à 19 warnings inchangé à chaque étape.

### Security

- Audit OPSEC trace + knowledge + scrubber (preuves : tests) :
  - tous renderers (`reporting/*`, `reasoning/trace.rs render`,
    `mcp/tools.rs`, `cli/output/`) scrubbed (double-scrub idempotent) ;
  - `ReasoningTrace` = hashes SHA-256 uniquement, jamais clair ;
  - `knowledge.json` = agrégats `(technique, dbms, contexte)` seuls,
    vocabulaire fermé, perms `0600`, `Scrubber` no-op vérifié ;
  - exports `--export-encrypted`/`--output` = `0600` + `create_new`
    (pas d'écrasement) + `fsync`.
- `cargo audit` : voir §Outillage. `cargo deny` : pas de config repo
  (cf. `AGENTS.md` — non gating), non lancé, non installé.

## [0.7.0] — DX + Mémoire + Évasion tardive (C11 + C13 + C5-scope-réduit)

### Added

- C11 : `--dry-run` (plan lisible, 0 requête, priors knowledge affichés),
  `validate --config` + JSON Schema, `info` enrichi, `cli/plan.rs`
  (scheduler sans `HttpClient`), MCP `plan`/`explain`.
- C13 Knowledge Engine (stats, pas ML) : opt-in `--allow-knowledge`,
  store `~/.cache/injekt/knowledge.json` (ou `--knowledge-path` /
  `INJEKT_KNOWLEDGE_PATH`), clé `(technique, dbms, contexte)` →
  `{trials, success, req_p50}`, Beta-Binomial + Laplace, boost borné
  `[0.5, 1.5]` puis clamp scheduler `[0.5, 2.0]` (jamais veto),
  `min_samples=10`, cold-start neutre byte-identique, `knowledge
  show/reset/export --anonymized`.
- C5-scope-réduit : mini-AST (`whitespace`/`comment`/`case`/`predicate`),
  `Parse→Normalize→Mutate→Render`, preuve `render(parse(x))==x`,
  branché C4/C13, compat `--tamper`, 0 nouveau nom (`all_names()` gelé).

### Courbes v0.6 → v0.7 (à remplir après runs live)

- `detect_rate` à budget égal : TBD(history.jsonl)
- `req_p50/p95` à détection égale : TBD(history.jsonl)
- `fp` N1/N2 : `0` attendu (veto sinon)
- `time_p50/p95` : TBD(history.jsonl)

## [0.6.0] — Preuve + Verdict sobre (C6 + C7 + C10-partiel)

### Added

- C6 : `--confirm` réel (second-pass, ~2× req, OOB exclu), `replay --file
  session.enc`, `--explain id@query` (`TRUE≈baseline 0.91, FALSE≠baseline
  0.22, 3/3, waf=none, 14 req, seed 42`), `--seed 42` reproductible,
  `reasoning/trace.rs` (`ProbeRecord` hashes uniquement, `Scrubber` +
  `Zeroize`), export chiffré v3 (trace + seed, lecture v1/v2 préservée).
- C7 : `confidence` + `false_positive_prob` + `severity` + `remediation`
  (exemple paramétré générique) + `evidence{hashes,diff,trace_ref}` +
  `waf{vendor,blocking}`, `--format sarif|junit|md` (défaut `json`),
  `Scrubber` sur tous renderers, buckets calibrés (voir Seuils ci-dessus).
- C10-partiel : pool time isolé (2 slots), timeouts par classe (boolean 10s,
  time 15s, oob 30s), `429 + Retry-After` honoré, `detectability{403,429}`
  au rapport, jitter seedé, floor 200 ms.

### Courbes v0.5 → v0.6 (à remplir après runs live)

- `detect_rate` à budget égal : TBD(history.jsonl)
- `fp` N1/N2 avec `--confirm` : `0` attendu (0 nouveau FP)
- A3 `0×429 p95` : TBD(history.jsonl)
- `time_p95` à détection égale : TBD(history.jsonl)

## [0.5.0] — Reasoning Core (C2 + C3 + C4)

### Added

- C2 : `dbms/context.rs` (`ContextProbe` 3–5 req max →
  `InjectionContext{quote, numeric, json, order_by, comment}` +
  `DbmsBelief{probas}`), pipeline `parse→baseline→context+fingerprint→
  detection ciblée`, `--dbms` hint = prior.
- C3 : `reasoning/hypothesis.rs` (`Hypothesis{param, technique, dbms_belief,
  context, prior, likelihood, posterior, cost_spent, state}`,
  `posterior ∝ prior × likelihood`), boucle `while budget && pending`,
  `EngineConfig + seed, budget`, refactor `run_detection` (<150 lignes,
  sans plugin).
- C4 : `scheduler.rs` réécrit (`BinaryHeap<ScoredProbe>`, `score =
  EVI × boost / cost`, `RequestBudget`, `EarlyStop`), baseline mutualisée
  par host, `knowledge_boost` borné consommé (C13 futur).

### Courbes v0.4 → v0.5 (à remplir après runs live)

- `detect_rate` à 60 req/param vs baseline : TBD(history.jsonl)
- N1/N2 arrêt `≤ 25` req p95, `0` finding : TBD(history.jsonl)
- CLI inchangé : oui (freeze `cli-flags.txt` en témoin)

## [0.4.0] — Metrology (C1)

### Added

- C1 : `bench/runner` (`reset/run/check-canary/pin/matrix/history` +
  parseurs `--output` injekt/sqlmap/ghauri), `bench/reports/<date>-<gitsha>.json`,
  `history.jsonl` (1 ligne = 1 run : version, scénario, bras, mode, `detect,
  fp, req_p50/p95, time_p50/p95, canary_ok`), `run.py compare --from v0.4
  --to HEAD` (`IMPROVED/FLAT/REGRESSION`, seuils : `detect_rate` −10pp ou
  tout `fp>0` ou `req_p50` +20 % → `REGRESSION`), `reporting/json.rs`
  (`+request_count, seed, profile, tampers, git_sha` via `Scrubber`),
  `versions.lock` gelé, CI `bench-smoke` (A1+N1 sans docker) par PR,
  `--seed` minimal (RNG seedé, salt/nonce export toujours OS-random).

### Courbes (baseline — première ligne d'historique)

- `detect_rate`, `fp_rate`, `req_p50/p95`, `time_p50/p95`, `canary_ok`,
  `detectability(403/429)` par scénario × bras × mode : TBD(history.jsonl)
  (5 runs de suite requis pour la baseline, `compare` détecte une régression
  injectée volontairement).

## Outillage

- `cargo fmt --check` : gate.
- `cargo clippy --all-targets -- -D warnings` : gate.
- `cargo test` (+ `--doc`, goldens `UPDATE_GOLDEN=1` + revue diff) : gate.
- `cargo audit` : lancé si installé (`cargo-audit 0.22.2` présent dans
  l'env v1.0-rc — voir sortie en revue), findings à trier avant release.
- `cargo deny` : pas de config repo (`AGENTS.md` — ne pas traiter comme
  gating), non installé, non lancé.
- Nightly 7j verts requis avant v1.0 publique (DoD roadmap).
