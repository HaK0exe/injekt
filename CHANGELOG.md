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

## [Unreleased] — v1.0-rc (hardening, en cours)

Roadmap `docs/ROADMAP-v1.0.md` §v1.0-rc : rien de nouveau — geler, durcir, prouver.

### Added

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
