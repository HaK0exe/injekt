# injekt — Roadmap raisonnement jusqu'à v1.0

> **Statut :** document d'architecture directeur. Phase 1 terminée (8/9 scénarios, 0 FP, canaries intacts).
> **Principe :** injekt ne bat pas sqlmap/ghauri en ajoutant des payloads. Il les bat en **raisonnant mieux avec moins de requêtes, zéro FP, et chaque finding explicable et rejouable.**
> **Interdit :** centaines de payloads, dizaines de tampers, copie sqlmap, feature bloat.
> **Version cible :** v1.0 publique. **Version actuelle :** v0.3.0. **MSRV :** 1.88, édition 2024, `deny(unsafe,unwrap,expect,dbg,todo)`.

---

## Table des matières

1. [État Phase 1 vérifié](#1-état-phase-1-vérifié)
2. [Règles de priorisation](#2-règles-de-priorisation)
3. [Chantiers C1–C12](#3-chantiers-c1c12)
4. [Plan de versions v0.4 → v1.0](#4-plan-de-versions-v04--v10)
5. [Matrice](#5-matrice)
6. [Analyse critique](#6-analyse-critique)
7. [Annexe A — Protocole benchmark scientifique](#annexe-a--protocole-benchmark-scientifique)
8. [Annexe B — Architecture cible](#annexe-b--architecture-cible)
9. [Annexe C — Glossaire et prochaines décisions](#annexe-c--glossaire-et-prochaines-décisions)

---

## 1. État Phase 1 vérifié

### 1.1 Ce qui marche

- Moteur d'évasion fonctionnel : 19 tampers (`src/techniques/tamper.rs`), borne `t.len()+2`, `is_boolean_safe`, préservation `-- -`, auto `space2comment` sur WAF block.
- Confirmation robuste : 3 trials, majorité, `confirm_either` normal/inversé pour login-bypass (`src/detection/confirmation.rs`).
- Baseline + diff : 3 échantillons, `mean+σ`, SHA-256, WAF Cloudflare, Levenshtein 1024 + Jaccard 0.7/0.3, garde `""→conf 0.0` anti-FP.
- Découverte headers/cookies, identity/UA câblée (`Sec-CH-UA` aligné, fix règle CRS 920320).
- Bench reproductible en cours : `bench/docker-compose` (FastAPI vulnérable + mysql:8.4 + pg:17 + mssql:2022 + ModSec CRS PL1/PL2), `scenarios.toml` A1–A7+N1–N2, modes `power/stealth`, bras `stock/evasion`, `canary.marker==untouched`, `run.py reset/run/check-canary/pin`, `versions.lock`.
- OPSEC : RAM-only (`Arc<RwLock<SessionState>>`, `ZeroizeOnDrop`, `SecretString`), `Scrubber`, `socks5h://` enforced (`socks5://` rejeté `DnsLeak`), jitter `Normal(750,250)` floor 200ms, `CancellationToken`, `buffer_unordered` borné.

### 1.2 Dettes structurantes (source des chantiers)

| Sous-système | Fichier | Dette |
|---|---|---|
| Orchestrateur | `src/engine/orchestrator.rs` (~1400 lignes, `too_many_lines`) | 7 branches `if technique==` en dur, fingerprint **après** détection, `--confirm` = `warn!` no-op, `EngineConfig` 30+ champs plats |
| Scheduler | `src/detection/scanner/scheduler.rs` + `engine.rs` | `Scheduler` FIFO `VecDeque` **mort** (non utilisé, l'orchestrateur fait `buffer_unordered` direct). Aucun coût, priorité, budget, early-stop |
| Diff | `src/detection/response_diff.rs` | Seuils magiques `0.5/0.6/0.9`, pas de normalisation `request_id/generated_at`, pas de test statistique |
| Fingerprint | `src/dbms/fingerprint.rs` | Passif après-coup + 4 sondes aveugles, pas d'inférence contexte (numeric/string/quote/JSON/`ORDER BY`) |
| Tampers | `src/techniques/tamper.rs` | String-level, `RandomCase/Space2RandomBlank` non déterministes (flaky), `Base64Encode` casse le différentiel |
| Extraction | `src/extraction/inference.rs` | Seulement version-string, ~270–700 req, pas de checkpoint |
| Session | `src/session/state.rs`, `reporting/evidence.rs` | `Finding{target,parameter,technique,confidence,dbms,evidence}` trop pauvre pour expliquer |
| Recon | `src/recon/discovery.rs` | Un `Engine`+baseline par candidat (N baselines pour N candidats même host) |
| Bench | `bench/runner/` | Groupe B (UNION/JSON/OOB), Oracle XE, matrice sqlmap/ghauri = TODO Phase 2. `request_count` auto-déclaré sans cross-check logs |

### 1.3 Fenêtre concurrentielle 2026 (vérifiée AnySearch)

- ghauri : plus rapide que sqlmap sur time-based blind (cas ~4 min vs sqlmap), mais moins de features, pas d'UNION assumé, Python threads non bornés, session SQLite sur disque.
- sqlmap : ~100+ tampers, puissant mais bruyant, persistant, non-OPSEC, aucune notion de budget.
- Aucun des deux : budget de requêtes, fingerprint adaptatif précoce, mutation sémantique, replay déterministe, reporting calibré. **C'est la fenêtre injekt.**

---

## 2. Règles de priorisation

- **Impact (1–5)** : réduction FP / requêtes, détection à budget constant, adoption.
- **Difficulté (1–5)** : 1 = refactor local, 5 = nouveau sous-système + protocole.
- **Dette (Faible/Moyenne/Forte/Critique)** : ce qui pourrit si ignoré.
- **Valeur long terme (1–5)** : différenciation vs sqlmap/ghauri à 2 ans.
- **Monnaie commune :** le budget requêtes. Chaque nouvelle sonde justifie son coût en information. Refus : tout chantier "N payloads / N tampers".

---

## 3. Chantiers C1–C12

Chaque chantier suit le gabarit imposé : pourquoi, problème, impact utilisateur, impact architecture, dépendances, risques, critères de validation, tests à écrire, priorisation.

### C1 — Benchmarking reproductible (sqlmap + ghauri + protocole scientifique)

- **Pourquoi :** sans protocole, "plus intelligent / plus rapide" = marketing. `bench/README.md` l'avoue : aucun comparatif shippé. Socle qui rend C3/C4/C5 mesurables.
- **Problème résolu :** `request_count` auto-déclaré, pas de cross-check logs WAF/nginx, `repeats=3` sans intervalles, pas de matrice adverse, Groupe B absent.
- **Impact utilisateur :** confiance — `bench/reports/<date>-<gitsha>.json` + `versions.lock` citables en rapport pentest / issue.
- **Impact architecture :** `bench/` devient harness : `runner/run.py reset/run/check-canary/pin/matrix` + parseurs `--output` JSON injekt / sqlmap / ghauri. `src/reporting/json.rs` expose `request_count, seed, profile, tampers, git_sha` (via `Scrubber`, sans secret).
- **Dépendances :** aucune. Bloque la validation de C3/C4/C5.
- **Risques :** flakiness MSSQL (~10–20s boot), Oracle XE (2 CPU/2Go, ~10 min), CRS rolling tag (3.3.10 mesuré, pas 4.x). Mitigation : `pin` digests, timeout 600s, reseed, canary bloquant.
- **Critères de validation :** `matrix --tools injekt,sqlmap,ghauri --scenarios A1-A7,N1-N2,B1-Bx` vert local + runner dédié ; par scénario/bras/mode : `detect_rate, fp_rate, p50/p95 requêtes, p50/p95 temps, canary_ok` ; N1/N2 `fp_rate==0` sinon veto release ; écart `request_count` vs logs < 5%.
- **Tests à écrire :** `tests/integration_bench_parsers.rs` (fixtures gelées 3 outils) ; test canary destructif → run rejeté ; `proptest` schéma `scenarios.toml` (ids uniques, `expected ⊆ techniques`, `negative ⟺ expected==[]`) ; CI `bench-smoke` (A1+N1 sans docker) par PR.
- **Priorisation : Impact 5 | Difficulté 3 | Dette Forte | Valeur 5.**

### C2 — Adaptive Fingerprinting (avant détection, pas après)

- **Pourquoi :** tester 7 techniques puis deviner le DBMS = inverse du raisonnement. Contexte + DBMS divisent le budget par 3–4.
- **Problème résolu :** `run_fingerprint` seulement `if !findings.is_empty()`, `guess_from_findings` + banner regex + 4 sondes aveugles, `--dbms` hint sous-exploité.
- **Impact utilisateur :** moins de requêtes en `stealth`, fingerprint cité en evidence, `--dbms` = vrai accélérateur.
- **Impact architecture :** nouveau `src/dbms/context.rs` : `ContextProbe` (3–5 req max) → `InjectionContext{quote, numeric, json, order_by, comment}` + `DbmsBelief{probas}`. Orchestrateur : `parse→baseline→context+fingerprint→detection ciblée`. `dbms_hint` devient prior bayésien.
- **Dépendances :** C1 (preuve du gain à budget constant). Réutilise `BooleanDetector::evaluate` + `Baseline`.
- **Risques :** sondes contexte vues comme bruit WAF. Mitigation : sondes bénignes + `ignore_codes` + downgrade `waf_blocking`.
- **Critères de validation :** A1–A7 contexte ≥ 90%, DBMS ≥ 85% avant détection lourde ; budget fingerprint ≤ 8 req p95 ; 0 régression N1/N2.
- **Tests à écrire :** `wiremock` matrice 4 DBMS × 4 contextes ; `insta` evidences fingerprint ; `--dbms mysql` → 0 sonde active (verrouiller le comportement actuel).
- **Priorisation : Impact 5 | Difficulté 3 | Dette Forte | Valeur 5.**

### C3 — Hypothesis Engine (cœur "intelligent")

- **Pourquoi :** passer de "7 techniques × N params" à "registre d'hypothèses notées, mise à jour, arrêt tôt". Changement de paradigme.
- **Problème résolu :** `run_detection` = 7 blocs `if` identiques, aucune poda, aucune mémoire inter-technique, aucun early-exit N1/N2.
- **Impact utilisateur :** `--level` = budget lisible ("L1 ≈ 40 req/param"), sortie `--explain` possible, FP en chute (évidence cumulée exigée).
- **Impact architecture :** nouveau `src/reasoning/hypothesis.rs` : `Hypothesis{param, technique, dbms_belief, context, prior, likelihood, posterior, cost_spent, state}` ; `posterior ∝ prior × likelihood(diff, confirmation, waf_penalty)`. L'orchestrateur boucle `while budget && pending { scheduler.next() → probe → update }`. `SessionState.findings` inchangé (stable) + `ReasoningTrace` interne rejouable. RNG seedable (C6). Contraintes : `#[non_exhaustive]`, `InjektError`, pas de `unwrap`.
- **Dépendances :** C2 (priors), C4 (choix prochaine sonde), C1 (calibration likelihoods sur bench).
- **Risques :** sur-engineering bayésien (priors inventés). Mitigation : v1 = scoring log-additif + seuils calibrés bench, pas de réseau bayésien.
- **Critères de validation :** à budget égal (ex. 60 req/param) `detect_rate ≥ baseline` A1–A7 ; N1/N2 arrêt ≤ 25 req/param p95, 0 finding ; `confirm()` existant réutilisé.
- **Tests à écrire :** unit (`prior 0.1 + 3 trials 0.9/0.1 → Confirmed`, ambigu → Pending, `waf_blocking` → pénalisé) ; `proptest` monotonie ; intégration `wiremock` oracle stable → 1 finding, oracle bruité (`request_id`) → 0 finding.
- **Priorisation : Impact 5 | Difficulté 5 | Dette Critique | Valeur 5.** Le plus important et le plus dur.

### C4 — Cost-Based Scheduler (remplace le FIFO mort)

- **Pourquoi :** FIFO + `buffer_unordered` = aucun arbitrage. En stealth chaque requête coûte 400ms+ : l'ordre est la performance.
- **Problème résolu :** pas de coût (time = cher/lent), pas d'EVI, pas de stop global, `recon/discovery.rs` respawn baseline par candidat.
- **Impact utilisateur :** `-p/--threads/--rate-limit/--jitter` cohérents : `budget_spent/budget_total`, `next_best_probe` visibles ; `stealth` détecte à < 100 req.
- **Impact architecture :** réécrit `src/detection/scanner/scheduler.rs` : `BinaryHeap<ScoredProbe>`, `score = EVI(posterior,dbms) / cost(requêtes,temps,risque WAF)`, `RequestBudget`, `EarlyStop`. `ScanEngine` garde `buffer_unordered` mais reçoit des tâches ordonnées. Baseline mutualisée par host en `recon scan`.
- **Dépendances :** C3 (posteriors), C2 (coûts DBMS-spécifiques).
- **Risques :** starvation (boolean affame union). Mitigation : round-robin par param + ε-greedy + `payload_budget()` conservé comme enveloppe (`level` garde-fou).
- **Critères de validation :** A3 (5/s + blocklist) sans 429 p95 ; `recon scan` 10 candidats même host = 1 baseline ; même `--seed` → même ordre.
- **Tests à écrire :** unit (coût time > boolean, EVI confirmante > redondante, stop sur budget) ; intégration `--threads 1 --seed 42` deux runs → même séquence ; test famine (union ≥ 1 sonde).
- **Priorisation : Impact 4 | Difficulté 4 | Dette Critique | Valeur 5.**

### C5 — Mutation Engine (AST sémantique, pas scripts regex)

- **Pourquoi :** `tamper.rs` = remplacement string + rustines (`split_trailing_comment`). Ne scale pas, casse la sémantique (`Base64Encode` tue le différentiel). L'évasion moderne préserve le sens SQL.
- **Problème résolu :** aucune garantie "TRUE reste TRUE", aléatoire non seedé, explosion `t.len()+2` aveugle, regex `KEYWORDS` statique.
- **Impact utilisateur :** `--tamper` déclaratif + sûr : mêmes différentiels, moins de FP WAF, mutation exacte citée et rejouable.
- **Impact architecture :** nouveau `src/mutation/` : `SqlAst → Normalize → Mutate{Whitespace,Comment,Case,KeywordVersion,Encoding,PredicateRewrite} → Render(dialect)` avec preuve `render(parse(x))==x`. `Tamper` devient couche rendu compat (noms CLI conservés, pas supprimés en v1.0). `boolean_safe_transformation_sets` → `mutation_plans(context, dbms_belief)` branché C2/C3. `rand::rng()` → `StdRng::seed_from_u64(seed)`.
- **Dépendances :** C2 (dialecte/quote), C1 bras `evasion` (A1 `space2comment`, A2 `equaltolike` comme oracles).
- **Risques :** écrire un parseur SQL complet = 6 mois perdus. Mitigation : mini-AST ciblé + `sqlparser` en dev-dependency pour tests d'équivalence uniquement. Pas d'Oracle complet jour 1.
- **Critères de validation :** `∀ mutation boolean-safe, eval(TRUE)==TRUE ∧ eval(FALSE)==FALSE` (harness + bench A1/A2 evasion) ; déterminisme seedé ; `all_names().len()` gelé en v1.0 (0 nouveau tamper string-level).
- **Tests à écrire :** `proptest` round-trip + préservation TRUE/FALSE ; `insta` catalogue par dialecte ; intégration A1/A2 via Mutation Engine.
- **Priorisation : Impact 4 | Difficulté 5 | Dette Forte | Valeur 5.**

### C6 — Replay & Explain Engine (`--confirm` réel + `--explain` + `--seed`)

- **Pourquoi :** `--confirm` = warning "not implemented". Un finding non rejoué n'est pas un finding. Sans seed, debug des tampers aléatoires impossible.
- **Problème résolu :** confirmation intra-run seulement, pas de second-pass inter-run, pas de journal déterministe, `Evidence` inexplicable.
- **Impact utilisateur :** `--confirm` = vrai second-pass (~2× req, OOB exclu) ; `replay --file session.enc` re-vérifie ; `--explain id@query` = "TRUE≈baseline 0.91, FALSE≠baseline 0.22, 3/3, waf=none, 14 req, seed 42" ; `--seed 42` = reproductible.
- **Impact architecture :** `src/reasoning/trace.rs` : `ProbeRecord{seq, param, technique, mutation_plan, seed, request_hash, response_hash, diff, ms}` (hashes, pas secrets ; `Scrubber` + `Zeroize`). `SessionState` + `trace` RAM-only (export `XChaCha20/Argon2id` réutilisé). `EngineConfig + seed, confirm_réel, explain`. Tous RNG seedés.
- **Dépendances :** C3/C4 (log des décisions), C8 (format export stable).
- **Risques :** stocker trop (secrets). Mitigation : hashes + longueurs + diffs, jamais bodies bruts sauf `--export-encrypted` opt-in. `scrubbed()` étendu à la trace.
- **Critères de validation :** `--confirm` 0 nouveau FP N1/N2 ; 2 runs même seed → même séquence ; `replay` offline verdict identique ou re-sonde minimale documentée.
- **Tests à écrire :** intégration `--confirm` ; seed → mêmes payloads (incl. `RandomCase`) ; OPSEC trace sans `Cookie/Authorization/JWT` en clair.
- **Priorisation : Impact 5 | Difficulté 3 | Dette Moyenne | Valeur 5.**

### C7 — Intelligent Reporting (confiance calibrée)

- **Pourquoi :** `0.75/0.85` + `>0.6` = nombres inventés. Inutilisables en rapport pentest. injekt doit sortir des verdicts défendables, pas des dumps.
- **Problème résolu :** `false_positive_prob` calculé mais non exposé, pas de remediation, pas de SARIF/JUnit, console non-machine.
- **Impact utilisateur :** JSON : `confidence, false_positive_prob, severity, remediation{parameterized_example}, evidence{hashes,diff,trace_ref}, waf{vendor,blocking}` ; `--format sarif|junit|md` pour CI.
- **Impact architecture :** `src/reporting/` : `verdict.rs` (calibration bench), `sarif.rs`, `markdown.rs`. `Finding` étendu compat (`#[serde(default)]`) : `+ false_positive_prob, severity, remediation, trace_ref`. `Scrubber` obligatoire sur tous renderers.
- **Dépendances :** C1 (calibration), C6 (trace_ref).
- **Risques :** sur-promesse ("0.97"). Mitigation : buckets conservateurs + doc "fréquence bench, pas garantie".
- **Critères de validation :** `high → précision ≥ 95%`, `medium ≥ 80%` sur bench sinon recalibration ; `insta` 3 formats ; aucun secret dans golden files.
- **Tests à écrire :** calibration sur fixtures bench ; `insta` SARIF/JUnit/Markdown ; `--no-redact` interdit en CI.
- **Priorisation : Impact 4 | Difficulté 2 | Dette Moyenne | Valeur 4.**

### C8 — Plugin Architecture (interne d'abord)

- **Pourquoi :** ajouter une technique = toucher 200 lignes + 10 signatures `too_many_arguments`. Tue la vélocité.
- **Problème résolu :** pas de trait `Technique`, pas de registre, `techniques: Vec<String>` non validé.
- **Impact utilisateur :** aucun direct v1.0 (interne). Indirect : nouvelles techniques sans casser CLI. Post-v1.0 : `--plugin` si demandé.
- **Impact architecture :** `src/techniques/api.rs` : `trait TechniqueDetector{name,cost,supports,evaluate}` + `Registry`. Migration 2 temps : wrapper les 7 detectors sans changer logique, puis brancher C3/C4. **Pas de WASM/dylib en v1.0.** Pas d'`async_trait` macro (native `async fn` déjà pour `DbmsDetector`).
- **Dépendances :** C3/C4 consommateurs. Sinon indépendant.
- **Risques :** abstraction prématurée. Mitigation : trait 5 méthodes, CLI inchangé.
- **Critères de validation :** `run_detection` < 150 lignes, 0 `if technique=="x"`, bench A1–A7 identique ; stub-technique < 100 lignes + 1 ligne registre ; clippy vert.
- **Tests à écrire :** registre 7 techniques, noms CLI stables ; `supports()` (union refusé sans `order_by`, oob sans `--oob-domain`) ; `--techniques all` == union des 7.
- **Priorisation : Impact 3 | Difficulté 3 | Dette Forte | Valeur 4.**

### C9 — Multi-agent orchestration (hors v1.0)

- **Pourquoi / pourquoi pas :** séduisant ("agents qui débattent") mais injekt est déjà `buffer_unordered` + `CancellationToken`. Gain marginal, coût non-déterminisme/OPSEC énorme.
- **Problème niche réel :** `recon scan` N engines sans partage (WAF cible 1 n'aide pas cible 2).
- **Impact utilisateur :** quasi-nul v1.0. Post-v1.0 : partage opt-in `waf_vendor` + `dbms_prior` même infra.
- **Impact architecture :** recommandation **pas d'agents LLM/autonomes**. Seul niveau acceptable : `src/reasoning/coordinator.rs` partage lecture-seule `Baseline/WAF/DbmsBelief`. MCP (`src/mcp/`) reste l'interface agent, pas le moteur.
- **Dépendances :** C3/C4 + preuve C1.
- **Risques :** non-déterminisme, explosion requêtes, fuite inter-cible. Veto OPSEC par défaut.
- **Critères (si post-v1.0) :** même seed → même résultat ; total partagé ≤ somme isolées ; `--share-beliefs` explicite requis.
- **Tests :** isolation par défaut (2 cibles, croyances non partagées).
- **Priorisation : Impact 2 | Difficulté 5 | Dette Faible | Valeur 2. P3 hors v1.0.**

### C10 — Performance & concurrency (sobre)

- **Pourquoi :** "50 threads" tue l'OPSEC et n'efface pas le dominant (jitter 750ms + `pg_sleep` 5s). Levier = moins de requêtes (C3/C4) + moins d'attente inutile.
- **Problème résolu :** time-based bloque des slots 5s, timeout global 30s même pour sondes 200ms, jitter non seedé.
- **Impact utilisateur :** `power`/`stealth` tiennent leurs promesses sans tuning. `Ctrl+C` gracieux préservé.
- **Impact architecture :** `src/http/` + `ScanEngine` : pool time isolé (2 slots), timeouts par classe (boolean 10s, time 15s, oob 30s), `429 + Retry-After` honoré (A3), jitter seedé, profiles inchangés.
- **Dépendances :** C4 (coût temps), C6 (seed).
- **Risques :** régression OPSEC. Mitigation : floor 200ms conservé, `stealth` jamais auto-monté.
- **Critères :** A3 0×429 p95, temps p95 -20% à détection égale, 0 spawn non borné audité.
- **Tests :** isolation time (5×`pg_sleep(5)` + 5 boolean < 6s) ; 429 backoff ; `CancellationToken` 0 orpheline.
- **Priorisation : Impact 3 | Difficulté 3 | Dette Moyenne | Valeur 3.**

### C11 — Developer Experience

- **Pourquoi :** `EngineConfig` 30 champs, pas de `--dry-run`, `replay` incomplet, MCP minimal, pas de schéma config → 2 jours perdus par contributeur.
- **Problème résolu :** erreurs tardives, pas de prévisualisation, `injekt.toml` non validé, playbook décorrélé du `--help`.
- **Impact utilisateur :** `--dry-run` = plan lisible (params, contexte, budget, ordre, 0 requête) ; `validate --config` + JSON Schema ; `info` enrichi.
- **Impact architecture :** `src/cli/plan.rs` (dry-run = scheduler sans `HttpClient`), `schema.rs` (`schemars` déjà via MCP réutilisé). `mcp/tools.rs` : `plan/scan/replay/explain`. Aucun changement moteur.
- **Dépendances :** C3/C4/C6.
- **Risques :** scope creep docs. Mitigation : dry-run = sortie scheduler existant.
- **Critères :** `--dry-run` 0 requête (mock), sortie `insta` ; TOML invalide → erreur ligne + suggestion ; `DOCUMENTATION.md#cli-reference` générée depuis `clap`.
- **Tests :** dry-run 0 HTTP ; `proptest` precedence CLI>env>file>profile>défauts ; `mcp_stdio.rs` étendu `plan/explain`.
- **Priorisation : Impact 3 | Difficulté 2 | Dette Moyenne | Valeur 4.**

### C12 — CI/CD & benchmark automation

- **Pourquoi :** badge vert sans gate bench = régressions silencieuses (1 FP N1 annule "0 FP"). `cargo deny check` sans config = bruit.
- **Problème résolu :** pas de nightly bench, pas de matrice adverse auto, `insta` manuel, MSRV non vérifiée.
- **Impact utilisateur :** chaque release : `bench/reports/` + `versions.lock` + changelog `detect_rate/fp_rate`.
- **Impact architecture :** `.github/workflows/` : `ci.yml` (`fmt, clippy -D warnings, test, test --doc, insta --check, msrv 1.88`) ; `bench-nightly.yml` (compose + matrix A1–A7+N1, artefacts 30j, alerte `fp>0` ou chute > 10pp) ; `release.yml` (`pin` + SHA256SUMS). PR gatées sur `bench-smoke` léger uniquement, nightly informatif (pas flaky-gate).
- **Dépendances :** C1, C7 (seuils).
- **Risques :** runner instable, CI ×3. Mitigation : smoke sans docker en PR, nightly runner dédié stable.
- **Critères :** FP volontaire N1 → rouge ; nightly 7 nuits vertes ; `deny.toml` ajouté ou mention retirée du README.
- **Tests :** méta-tests CI (fixture `N1-fp` → rouge, `A1-ok` → vert).
- **Priorisation : Impact 4 | Difficulté 2 | Dette Forte | Valeur 5.**

---

## 4. Plan de versions v0.4 → v1.0

### v0.4 — Metrology (4–6 semaines)

- **Objectif :** prouver, pas ajouter.
- **Fonctionnalités :** C1 Groupe A complet (stock+evasion, power+stealth, `pin`, cross-check logs) + C12 `bench-smoke` PR + `--seed` minimal (RNG seedé).
- **Architecture concernée :** `bench/runner`, `reporting/json` (`+seed,git_sha,profile`), `Tamper` RNG seedé. Logique orchestrateur inchangée.
- **Migrations :** aucune breaking. `report.json` champs ajoutés `#[serde(default)]`. `versions.lock` gelé.
- **DoD :** `matrix` vert local, `bench-smoke` gate PR, N1/N2 `fp==0`, `bench/README` CRS figé. Tag `v0.4.0`.

### v0.5 — Reasoning Core (6–8 semaines)

- **Objectif :** le moteur raisonne.
- **Fonctionnalités :** C2 (≤8 req) + C3 (Hypothesis v1) + C4 (EVI/coût, baseline mutualisée, early-stop) + C8-interne (trait `Technique`).
- **Architecture :** nouveaux `src/reasoning/`, `src/dbms/context.rs`, `scheduler.rs` réécrit, `orchestrator: baseline→context→reasoning loop→fingerprint fill→extraction gate`.
- **Migrations :** `EngineConfig + seed, budget` ; `Scheduler` FIFO supprimé (interne). `Finding` inchangé.
- **DoD :** à budget égal `detect_rate ≥ baseline` ; N1/N2 ≤25 req ; CLI `--techniques/--level/--tamper` inchangé ; `run_detection` résorbe `too_many_lines`.

### v0.6 — Evasion sûre + Preuve (6 semaines)

- **Objectif :** muter sans casser, confirmer pour de vrai.
- **Fonctionnalités :** C5 (mini-AST, plans `boolean-safe`, compat `--tamper`) + C6 (`--confirm` réel, `replay`, `--explain`, trace hashée) + C10 (pool time isolé, timeouts par classe, 429).
- **Architecture :** `src/mutation/`, `src/reasoning/trace.rs`, `http/` timeouts par classe. `tamper.rs` → couche rendu.
- **Migrations :** `--confirm` devient réel (~2× req, documenté). `--seed` stable. Export chiffré version+1, lecture v0.5 préservée.
- **DoD :** A1/A2 evasion via Mutation Engine ; `--confirm` 0 nouveau FP ; même seed → même séquence ; trace sans secret ; A3 0×429.

### v0.7 — Verdict + Ouverture (4 semaines)

- **Objectif :** sortie rapport/CI, base extensible.
- **Fonctionnalités :** C7 (buckets calibrés, SARIF/JUnit/Markdown) + C8 finalisé + C11 (`--dry-run`, `validate`, schéma, MCP `plan/explain`).
- **Architecture :** `reporting/{verdict,sarif,markdown}`, `cli/{plan,schema}`, `mcp/tools` étendus. `Finding` étendu compat.
- **Migrations :** `report.json` champs optionnels ; `--format` ajouté (défaut `json`) ; `Finding.dbms` inchangé.
- **DoD :** `high→≥95%`, `medium→≥80%` sinon recalibration bloquante ; `insta` 3 formats ; `--dry-run` 0 requête ; doc CLI générée depuis `clap`.

### v1.0-rc → v1.0 publique (3–4 semaines hardening)

- **Objectif :** rien de nouveau. Geler, durcir, prouver.
- **Gel :** `Tamper::all_names()` gelé, CLI gelé, `report.json` schema v1 + JSON Schema publié.
- **Bench :** Groupe B (UNION/JSON/OOB+collaborateur, Oracle XE si stable sinon "non supporté" explicite). Matrice officielle 3 outils sur runner dédié, `reports/` publiés, `versions.lock` cité.
- **Audit OPSEC :** `socks5h`, jitter floor, `scrubber` tous renderers, `--no-redact` jamais défaut, RAM-only re-vérifié, `cargo audit/deny` tranché.
- **DoD v1.0 :** `fp==0` N1/N2, `canary==untouched`, `detect_rate` publié sans régression vs v0.7 ; nightly 7j verts ; 0 `todo!/unwrap/expect` en `src/` ; MSRV 1.88 prouvée ; changelog + migrations. C9 exclu.

Ordre : **C1 → C2+C8-interne → C3+C4 → C6 → C5 → C7+C10+C11 → C12 continu → rc.**

---

## 5. Matrice

| Chantier | Impact | Complexité | Priorité | Prérequis | ROI |
|---|---|---|---|---|---|
| C1 Benchmark reproductible | 5 | 3 | **P0** | — | Très haut |
| C3 Hypothesis Engine | 5 | 5 | **P0** | C1, C2 | Très haut |
| C2 Adaptive Fingerprinting | 5 | 3 | **P0** | C1 | Très haut |
| C4 Cost-Based Scheduler | 4 | 4 | **P0** | C2, C3 | Très haut |
| C6 Replay & Explain | 5 | 3 | **P0** | C3/C4 | Très haut |
| C12 CI/CD + bench automation | 4 | 2 | **P0** | C1 | Haut |
| C5 Mutation Engine AST | 4 | 5 | **P1** | C2, C1 | Haut |
| C7 Intelligent Reporting | 4 | 2 | **P1** | C1, C6 | Haut |
| C8 Plugin Architecture interne | 3 | 3 | **P1** | — puis C3/C4 | Moyen-haut |
| C10 Perf sobre | 3 | 3 | **P1** | C4, C6 | Moyen |
| C11 DX | 3 | 2 | **P2** | C3/C4/C6 | Moyen |
| C9 Multi-agent | 2 | 5 | **P3 hors v1.0** | C3/C4+C1 | Faible |

---

## 6. Analyse critique

### 6.1 Séduisant mais perte de temps avant v1.0

1. **200 payloads + 50 tampers.** CRS PL1/PL2 bloque déjà tout le répertoire standard en query/cookie (mesuré). Le vector-shift headers (A6/A7) a plus rapporté que 100 payloads.
2. **ML/LLM-détecteur black-box.** Incompatible offline, OPSEC, explicabilité. Scoring log-additif calibré = 80% du gain, 10% du risque.
3. **Multi-agent LLM autonome.** Non-déterministe, in-auditable, fuite inter-cible. MCP = interface agent, moteur = déterministe.
4. **WASM/dylib plugins publics.** Surface sécu + MSRV + ABI. Trait interne suffit.
5. **Oracle/UNION/OOB complet jour 1.** XE 10 min boot, OOB exige collaborateur + preuve `{token}` (egress DB, pas proxy). "Non supporté" documenté > 0/0 silencieux.
6. **GUI temps réel.** `indicatif+tabled` suffit ; investir dans SARIF + `--explain`.
7. **JA3 maison / TLS custom.** `rustls` stable assumé, mitigation proxy honnête. Fork TLS = dette.
8. **Crawler headless / second-order JS-heavy.** Flakiness + poids + OPSEC. Crawler statique + `max_per_template` sain pour v1.0.

### 6.2 Vrais avantages concurrentiels

| sqlmap/ghauri ne font pas | injekt v1.0 fait | Effet |
|---|---|---|
| Budget, arrêt précoce | C3+C4 EVI/coût, early-stop | Finit en stealth/rate-limit là où les autres se font bannir |
| Fingerprint précoce | C2 ≤8 req | 3–4× moins de sondes aveugles |
| Mutation sémantique | C5 TRUE reste TRUE, seedé | Evasion sans casser le différentiel |
| Zero-persistence + OPSEC | RAM-only, `Zeroize`, `socks5h`, jitter, `Sec-CH-UA` | Auditable en mission (SQLite vs RAM) |
| Preuve rejouable | C6 seed/confirm/replay/explain | Finding défendable en revue |
| Benchmark adverse publié | C1+C12 matrice 3 outils, `versions.lock`, canary | Premier à publier `fp_rate` + protocole |
| Verdict CI-ready | C7 proba calibrée, SARIF/JUnit | Branchement CI / Code Scanning |

Formule : **moins de requêtes, zéro FP, chaque finding expliqué + rejoué, stealth par construction.**

### 6.3 Bloquants absolus v1.0

1. **C1+C12** : sans bench officiel + gate `fp==0`, pas de crédibilité.
2. **C3+C4** : sans hypothèses + scheduler, "autre lanceur de payloads en Rust".
3. **C2** : sans fingerprint précoce, stealth explose, A4/A5 hors portée.
4. **C6** : `--confirm` no-op en publique = faute. Seed + replay + explain obligatoires.
5. **Gel + audit** : CLI, `report.json` v1 + Schema, OPSEC, `fmt/clippy/test --doc/insta` verts, MSRV prouvée.

Le reste peut être partiel s'il est **documenté comme limite**.

---

## Annexe A — Protocole benchmark scientifique

- Scénarios : A1–A7 (positifs, `expected` techniques), N1–N2 (négatifs, `expected=[]`, tout finding = FP), Groupe B Phase 2 (UNION vs ghauri, JSON-as-group, OOB+collaborateur, Oracle).
- Bras : `stock` (sans tamper) + `evasion` (`scenarios.toml:evasion`, ex. A1 `space2comment`, A2 `equaltolike`). Scénario valide seulement si ≥1 bras solvable (vérifié manuel avant wiring).
- Modes : `power` (threads 10, jitter 200±100, 20/s, level 3, handicap OPSEC neutralisé) vs `stealth` (threads 2, jitter 1200±400, 3/s, level 1, boolean+error, métrique = requêtes pas temps). A3 force threads/rate sous 5/s (`SCENARIO_FLAGS`, remplace mode).
- Répétitions : `repeats=3` Phase 1 → ≥5 en officiel, reseed→run 600s→parse `--output` JSON→assert `canary==untouched` 3 DB→summary `reports/`.
- Métriques : `detect_rate, fp_rate, p50/p95 requêtes, p50/p95 temps, canary_ok`. `request_count` cross-checké logs WAF/nginx (< 5% écart).
- Gel : `run.py pin` → `versions.lock` (digests images + versions outils) + specs runner + date cités dans tout rapport.
- Réalités mesurées : CRS 3.3.10 (pas 4.x) bloque tout répertoire query/cookie PL1/PL2 (contrôle 0/0/0 attendu) ; headers custom non inspectés → vector-shift A6/A7 ; règle 920320 exige UA (déjà fix) ; cookie inspecté (contrôle 403).
- Cible non-basique : erreurs masquées (enveloppe 200), bruit `request_id`+`generated_at` anti-string-compare naïf, filtres app par endpoint, N1/N2 contrôles, canary destructif.

## Annexe B — Architecture cible

```text
parse → baseline → context+fingerprint → reasoning loop → fingerprint fill → extraction(opt-in) → enumeration → done
                           │                    │
                     dbms/context.rs      reasoning/hypothesis.rs + scheduler.rs
                                                │ probes via techniques/api.rs (registre)
                                                │ mutations via mutation/ (AST, seedé)
                                                └── trace.rs → reporting/verdict + replay/explain
bench/runner/matrix ── calibre ──► likelihoods, coûts, seuils verdict
recon/scan ── baseline mutualisée + beliefs partagées lecture-seule (opt-in post-v1.0)
session/state ── findings (stable) + trace (hashes, Zeroize, Scrubber)
```

Invariants : `deny(unsafe,unwrap,expect,dbg,todo)` en `src/` ; `#[non_exhaustive]`, newtypes, `const fn`, `match` exhaustifs ; `InjektError` (`thiserror 2.x`) ; secrets `SecretString`+`zeroize`, sortie via `scrubber` ; `timeout()` typestate obligatoire ; `socks5h://` seul ; `buffer_unordered` borné + `timeout` + `CancellationToken` ; zéro écriture disque sauf `--export-encrypted/--output/--import` opt-in.

## Annexe C — Glossaire et prochaines décisions

- **EVI :** expected value of information — gain espéré d'une sonde divisé par son coût.
- **Bras :** variante `stock` vs `evasion` d'un même scénario.
- **Canary :** ligne tripwire ; `marker != 'untouched'` = run invalide (payload destructif).
- **Décisions attendues :** valider ordre `v0.4 → v0.5 → v0.6 → v0.7 → rc` ; trancher `deny.toml` (ajouter config vs retirer du README) ; figer runner officiel dédié ; accepter gel `all_names()` en v1.0.
