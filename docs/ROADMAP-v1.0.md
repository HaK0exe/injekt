# injekt — Roadmap raisonnement jusqu'à v1.0

> **Statut :** document d'architecture directeur. Phase 1 terminée (8/9 scénarios, 0 FP, canaries intacts). Révision intégrant la revue lead : Mutation tardive, plugin hors v1.0, Knowledge Engine, Vision produit, historique bench.
> **Signature :** **le premier scanner SQLi orienté raisonnement : il dépense chaque requête comme une ressource, explique chacune de ses décisions et produit des résultats reproductibles avec un minimum de bruit.**
> **Principe :** moins de requêtes → moins de bruit → plus de raisonnement → zéro FP.
> **Interdit :** centaines de payloads, dizaines de tampers, copie sqlmap, feature bloat, LLM autonome, GUI, WASM.
> **Version cible :** v1.0 publique. **Version actuelle :** v0.3.0. **MSRV :** 1.88, édition 2024, `deny(unsafe,unwrap,expect,dbg,todo)`.

---

## Table des matières

1. [Vision v1 — objectif produit](#0-vision-v1--objectif-produit)
2. [État Phase 1 vérifié](#1-état-phase-1-vérifié)
3. [Règles de priorisation](#2-règles-de-priorisation)
4. [Chantiers v1.0 (C1–C7, C10, C11, C13, C5-tardif)](#3-chantiers-v10)
5. [Plan de versions v0.4 → v1.0](#4-plan-de-versions-v04--v10)
6. [Matrice](#5-matrice)
7. [Analyse critique](#6-analyse-critique)
8. [Annexe A — Protocole benchmark scientifique + historique](#annexe-a--protocole-benchmark-scientifique--historique)
9. [Annexe B — Architecture cible](#annexe-b--architecture-cible)
10. [Annexe C — Glossaire et prochaines décisions](#annexe-c--glossaire-et-prochaines-décisions)
11. [Annexe D — Post-v1.0 (plugin, multi-agent)](#annexe-d--post-v10-plugin-multi-agent)

---

## 0. Vision v1 — objectif produit

La roadmap est technique ; le cap est produit. Quand un pentester lance injekt v1, il doit obtenir :

```text
< 100 requêtes en stealth par paramètre
0 faux positif sur contrôles N1/N2 (veto release sinon)
1 finding = 1 explication (TRUE≈baseline, FALSE≠baseline, trials, WAF, coût, seed)
1 replay déterministe (--seed + --confirm + replay --file)
1 rapport directement envoyable (JSON calibré + SARIF/JUnit/Markdown + remediation)
```

Si un chantier ne rapproche pas de l'une de ces 5 lignes, il ne rentre pas en v1.0. C'est le filtre anti-"feature zoo", et c'est ce qui rend la signature crédible : on ne vend pas "le plus puissant", on vend **le plus sobre, le plus expliqué, le plus reproductible**.

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
| Scheduler | `src/detection/scanner/scheduler.rs` + `engine.rs` | `Scheduler` FIFO `VecDeque` **mort** (non utilisé). Aucun coût, priorité, budget, early-stop, mémoire inter-run |
| Diff | `src/detection/response_diff.rs` | Seuils magiques `0.5/0.6/0.9`, pas de normalisation `request_id/generated_at`, pas de test statistique |
| Fingerprint | `src/dbms/fingerprint.rs` | Passif après-coup + 4 sondes aveugles, pas d'inférence contexte (numeric/string/quote/JSON/`ORDER BY`) |
| Tampers | `src/techniques/tamper.rs` | String-level suffisants pour la Phase 1, mais `RandomCase/Space2RandomBlank` non déterministes (flaky), `Base64Encode` casse le différentiel. **Pas le goulot actuel : le goulot c'est la décision, pas l'évasion.** |
| Extraction | `src/extraction/inference.rs` | Seulement version-string, ~270–700 req, pas de checkpoint |
| Session | `src/session/state.rs`, `reporting/evidence.rs` | `Finding{target,parameter,technique,confidence,dbms,evidence}` trop pauvre pour expliquer ; aucune mémoire statistique |
| Recon | `src/recon/discovery.rs` | Un `Engine`+baseline par candidat (N baselines même host) |
| Bench | `bench/runner/` | Groupe B, Oracle XE, matrice sqlmap/ghauri = TODO. `request_count` auto-déclaré sans cross-check logs. **Aucun historique inter-versions.** |

### 1.3 Fenêtre concurrentielle 2026 (vérifiée AnySearch)

- ghauri : plus rapide que sqlmap sur time-based blind (~4 min rapporté), mais moins de features, pas d'UNION assumé, Python threads non bornés, session SQLite sur disque.
- sqlmap : ~100+ tampers, puissant mais bruyant, persistant, non-OPSEC, aucune notion de budget.
- Aucun des deux : budget de requêtes, fingerprint adaptatif précoce, mémoire statistique, replay déterministe, reporting calibré, benchmark adverse publié. **C'est la fenêtre.**

---

## 2. Règles de priorisation

- **Impact (1–5)** : rapprochement des 5 lignes Vision v1.
- **Difficulté (1–5)** : 1 = refactor local, 5 = nouveau sous-système + protocole.
- **Dette (Faible/Moyenne/Forte/Critique)** : ce qui pourrit si ignoré.
- **Valeur long terme (1–5)** : différenciation à 2 ans.
- **Monnaie commune :** le budget requêtes. Chaque sonde justifie son coût en information. Refus : tout chantier "N payloads / N tampers".
- **Règle revue-lead :** décider quoi tester (C2/C3/C4/C13) avant d'investir dans comment muter (C5). L'AST vient en dernier.

---

## 3. Chantiers v1.0

Ordre d'exécution : **C1 → C2 → C3 → C4 → C6 → C7 → C10 → C11 → C13 → C5-tardif**, C12 en continu. C8 (plugin) et C9 (multi-agent) hors v1.0, voir Annexe D.

### C1 — Benchmarking reproductible + historique inter-versions

- **Pourquoi :** sans protocole, "plus intelligent" = marketing. Sans historique, on améliore une métrique en régressant une autre sans le voir. Socle de C3/C4/C13.
- **Problème résolu :** `request_count` auto-déclaré, pas de cross-check logs, `repeats=3` sans intervalles, pas de matrice adverse, Groupe B absent, **aucune comparaison v0.3→v0.4→…**.
- **Impact utilisateur :** confiance — `bench/reports/<date>-<gitsha>.json` + `versions.lock` citables ; courbe `requêtes/temps/FP/détectabilité` par version publiée au changelog.
- **Impact architecture :** `bench/` devient harness : `runner/run.py reset/run/check-canary/pin/matrix/history` + parseurs `--output` JSON injekt / sqlmap / ghauri. `reporting/json.rs` expose `request_count, seed, profile, tampers, git_sha` (via `Scrubber`). Nouveau `bench/reports/history.jsonl` (1 ligne = 1 run : version, scénario, bras, mode, `detect, fp, req_p50/p95, time_p50/p95, canary_ok`) + `run.py compare --from v0.3 --to HEAD` (tableau + verdict régression).
- **Dépendances :** aucune. Bloque C3/C4/C13.
- **Risques :** flakiness MSSQL/Oracle, CRS rolling tag (3.3.10 mesuré). Mitigation : `pin` digests, timeout 600s, reseed, canary bloquant, historique avec barres d'erreur (pas de chiffre isolé).
- **Critères de validation :** `matrix --tools injekt,sqlmap,ghauri` vert local + runner dédié ; N1/N2 `fp==0` veto ; écart `request_count` vs logs < 5% ; `history.jsonl` rempli 5 runs de suite, `compare` détecte une régression injectée volontairement (>10pp `detect_rate` ou tout `fp>0`).
- **Tests à écrire :** `tests/integration_bench_parsers.rs` (fixtures 3 outils) ; canary destructif → run rejeté ; `proptest` schéma `scenarios.toml` ; CI `bench-smoke` (A1+N1 sans docker) par PR ; test `compare` : fixture v0.3 vs v0.4-régressée → verdict `REGRESSION`.
- **Priorisation : Impact 5 | Difficulté 3 | Dette Forte | Valeur 5.**

### C2 — Adaptive Fingerprinting (avant détection, pas après)

- **Pourquoi :** tester 7 techniques puis deviner le DBMS = inverse du raisonnement. Contexte + DBMS divisent le budget par 3–4.
- **Problème résolu :** `run_fingerprint` seulement `if !findings`, 4 sondes aveugles, `--dbms` hint sous-exploité.
- **Impact utilisateur :** Vision v1 ligne 1 (<100 req) : moins de sondes aveugles en `stealth`, fingerprint cité en evidence.
- **Impact architecture :** nouveau `src/dbms/context.rs` : `ContextProbe` (3–5 req max) → `InjectionContext{quote, numeric, json, order_by, comment}` + `DbmsBelief{probas}`. Orchestrateur : `parse→baseline→context+fingerprint→detection ciblée`. `dbms_hint` = prior, et C13 l'affine (pas de conflit : hint > stats > bench-default).
- **Dépendances :** C1 (preuve à budget constant).
- **Risques :** sondes vues comme bruit WAF. Mitigation : sondes bénignes + `ignore_codes` + downgrade `waf_blocking`.
- **Critères de validation :** A1–A7 contexte ≥ 90%, DBMS ≥ 85% avant détection lourde ; ≤ 8 req p95 ; 0 régression N1/N2.
- **Tests à écrire :** `wiremock` 4 DBMS × 4 contextes ; `insta` evidences ; `--dbms mysql` → 0 sonde active (verrou).
- **Priorisation : Impact 5 | Difficulté 3 | Dette Forte | Valeur 5.**

### C3 — Hypothesis Engine (cœur)

- **Pourquoi :** passer de "7 techniques × N params" à "registre d'hypothèses notées, mise à jour, arrêt tôt". Tout le reste (scheduler, explain, replay, reporting, knowledge) consomme ses posteriors.
- **Problème résolu :** `run_detection` = 7 blocs `if` identiques, aucune poda, aucune mémoire inter-technique, aucun early-exit N1/N2.
- **Impact utilisateur :** `--level` = budget lisible ; FP en chute (évidence cumulée exigée) ; `--explain` possible.
- **Impact architecture :** nouveau `src/reasoning/hypothesis.rs` : `Hypothesis{param, technique, dbms_belief, context, prior, likelihood, posterior, cost_spent, state}` ; `posterior ∝ prior × likelihood(diff, confirmation, waf_penalty)`. Boucle `while budget && pending { scheduler.next() → probe → update }`. `SessionState.findings` inchangé + `ReasoningTrace` interne. RNG seedable (C6). Refactor interne de `run_detection` en fonctions (<150 lignes) **sans plugin system** (décision revue : split simple, pas de trait/registre en v1.0).
- **Dépendances :** C2 (priors), C4 (choix sonde), C1 (calibration sur bench), C13 (priors statistiques en surcouche, §C13).
- **Risques :** sur-engineering bayésien. Mitigation : v1 = log-additif + seuils calibrés bench.
- **Critères de validation :** à budget égal (60 req/param) `detect_rate ≥ baseline` A1–A7 ; N1/N2 arrêt ≤ 25 req p95, 0 finding ; `confirm()` réutilisé.
- **Tests à écrire :** unit (confirm/pending/pénalité WAF) ; `proptest` monotonie ; `wiremock` oracle stable → 1 finding, bruité (`request_id`) → 0.
- **Priorisation : Impact 5 | Difficulté 5 | Dette Critique | Valeur 5.** Le plus important et le plus dur.

### C4 — Cost-Based Scheduler (remplace le FIFO mort)

- **Pourquoi :** FIFO + `buffer_unordered` = aucun arbitrage. En stealth chaque requête coûte 400ms+ : l'ordre est la performance.
- **Problème résolu :** pas de coût (time cher/lent), pas d'EVI, pas de stop global, baseline répétée par candidat en `recon`.
- **Impact utilisateur :** Vision ligne 1 : `stealth` détecte à < 100 req ; `budget_spent/budget_total`, `next_best_probe` visibles.
- **Impact architecture :** réécrit `scheduler.rs` : `BinaryHeap<ScoredProbe>`, `score = EVI(posterior, dbms, knowledge) / cost(req, temps, risque WAF)`, `RequestBudget`, `EarlyStop`. Baseline mutualisée par host. C13 branche `knowledge_boost` multiplicatif borné (ex. 0.5×–2×, jamais veto : les stats conseillent, l'évidence décide).
- **Dépendances :** C3, C2.
- **Risques :** starvation, sur-confiance stats. Mitigation : round-robin + ε-greedy + `payload_budget()` enveloppe + boost borné + cold-start = priors bench.
- **Critères de validation :** A3 sans 429 p95 ; `recon` 10 candidats = 1 baseline ; même `--seed` → même ordre ; avec knowledge vide, ordre == sans knowledge (neutralité).
- **Tests à écrire :** unit (coût, EVI, stop, boost borné) ; intégration seed-déterministe ; famine (union ≥ 1 sonde).
- **Priorisation : Impact 4 | Difficulté 4 | Dette Critique | Valeur 5.**

### C6 — Replay & Explain Engine (`--confirm` réel + `--explain` + `--seed`)

- **Pourquoi :** `--confirm` no-op = faute professionnelle en v1.0 publique. Sans seed, debug des tampers aléatoires impossible.
- **Problème résolu :** confirmation intra-run seulement, pas de second-pass, pas de journal, `Evidence` inexplicable.
- **Impact utilisateur :** Vision lignes 3–4 : `--confirm` second-pass (~2× req, OOB exclu) ; `replay --file session.enc` ; `--explain id@query` = "TRUE≈baseline 0.91, FALSE≠baseline 0.22, 3/3, waf=none, 14 req, seed 42" ; `--seed 42` reproductible.
- **Impact architecture :** `src/reasoning/trace.rs` : `ProbeRecord{seq, param, technique, mutation_plan, seed, request_hash, response_hash, diff, ms}` (hashes, `Scrubber` + `Zeroize`). `SessionState + trace` RAM-only (export `XChaCha20/Argon2id`). `EngineConfig + seed, confirm_réel, explain`. Tous RNG seedés.
- **Dépendances :** C3/C4. (Dépendance C8 supprimée : format d'export stabilisé directement, sans couche plugin.)
- **Risques :** stocker des secrets. Mitigation : hashes + longueurs + diffs uniquement.
- **Critères de validation :** `--confirm` 0 nouveau FP N1/N2 ; 2 runs même seed → même séquence ; `replay` offline verdict identique ou re-sonde documentée.
- **Tests à écrire :** intégration `--confirm` ; seed → mêmes payloads ; trace sans secret en clair.
- **Priorisation : Impact 5 | Difficulté 3 | Dette Moyenne | Valeur 5.**

### C7 — Intelligent Reporting (confiance calibrée)

- **Pourquoi :** `0.75/0.85` + `>0.6` = nombres inventés, inutilisables en rapport. Vision ligne 5 (rapport envoyable).
- **Problème résolu :** `false_positive_prob` non exposé, pas de remediation, pas de SARIF/JUnit.
- **Impact utilisateur :** JSON : `confidence, false_positive_prob, severity, remediation{parameterized_example}, evidence{hashes,diff,trace_ref}, waf{vendor,blocking}` ; `--format sarif|junit|md`.
- **Impact architecture :** `reporting/{verdict,sarif,markdown}`. `Finding` étendu compat (`#[serde(default)]`). `Scrubber` sur tous renderers. Seuils calibrés sur C1 + historique (pas à la main).
- **Dépendances :** C1 (calibration + historique), C6 (trace_ref).
- **Risques :** sur-promesse. Mitigation : buckets conservateurs + doc "fréquence bench".
- **Critères de validation :** `high→précision≥95%`, `medium→≥80%` sinon recalibration bloquante ; `insta` 3 formats ; 0 secret en golden files.
- **Tests à écrire :** calibration sur fixtures ; `insta` SARIF/JUnit/Markdown ; `--no-redact` interdit en CI.
- **Priorisation : Impact 4 | Difficulté 2 | Dette Moyenne | Valeur 4.**

### C10 — Performance & concurrency (sobre)

- **Pourquoi :** "50 threads" tue l'OPSEC ; le dominant = jitter + `pg_sleep`. Levier = moins de requêtes (C3/C4) + moins d'attente inutile.
- **Problème résolu :** time-based bloque les slots, timeout global unique, jitter non seedé.
- **Impact utilisateur :** `power`/`stealth` tiennent leurs promesses ; `Ctrl+C` gracieux préservé.
- **Impact architecture :** pool time isolé (2 slots), timeouts par classe (boolean 10s, time 15s, oob 30s), `429 + Retry-After` honoré (A3), jitter seedé.
- **Dépendances :** C4, C6.
- **Risques :** régression OPSEC. Mitigation : floor 200ms, `stealth` jamais auto-monté.
- **Critères :** A3 0×429 p95, temps p95 -20% à détection égale, 0 spawn non borné.
- **Tests :** isolation time ; 429 backoff ; `CancellationToken` 0 orpheline.
- **Priorisation : Impact 3 | Difficulté 3 | Dette Moyenne | Valeur 3.**

### C11 — Developer Experience

- **Pourquoi :** `EngineConfig` 30 champs, pas de `--dry-run`, MCP minimal → 2 jours perdus par contributeur.
- **Problème résolu :** erreurs tardives, pas de prévisualisation, `injekt.toml` non validé.
- **Impact utilisateur :** `--dry-run` = plan lisible (params, contexte, budget, ordre, 0 requête, priors knowledge affichés) ; `validate --config` + JSON Schema ; `info` enrichi.
- **Impact architecture :** `cli/plan.rs` (scheduler sans `HttpClient`), `schema.rs` (`schemars` déjà via MCP). `mcp/tools` : `plan/scan/replay/explain`. Aucun changement moteur.
- **Dépendances :** C3/C4/C6 (+C13 affichage priors).
- **Risques :** scope creep. Mitigation : dry-run = sortie scheduler existant.
- **Critères :** `--dry-run` 0 requête, sortie `insta` ; TOML invalide → erreur ligne + suggestion ; doc CLI générée depuis `clap`.
- **Tests :** dry-run 0 HTTP ; `proptest` precedence CLI>env>file>profile>défauts ; `mcp_stdio` étendu.
- **Priorisation : Impact 3 | Difficulté 2 | Dette Moyenne | Valeur 4.**

### C13 — Knowledge Engine (nouveau, statistiques — pas du ML)

- **Pourquoi (revue lead) :** C2/C3/C4 décident bien à froid, mais rien n'apprend d'un scan à l'autre. Le payload qui marche souvent sur `postgres + CRS` doit voir son score monter ; celui qui échoue partout doit descendre. Pas de ML : des comptes.
- **Problème résolu :** priors figés (bench ou `--dbms`), scheduler sans mémoire inter-runs, ré-apprentissage du même échec à chaque mission.
- **Impact utilisateur :** Vision ligne 1 : de mission en mission, le même budget détecte plus vite (convergence mesurée sur historique, pas ressentie). `--dry-run` montre "prior bench 0.20 → knowledge 0.47 (n=63)".
- **Impact architecture :** nouveau `src/reasoning/knowledge.rs`, **opt-in et local-only** (zéro-persistence par défaut préservé) :
  - Clé d'agrégat (jamais de cible) : `(technique, dbms, waf_vendor|none, context_quote|numeric|json, mutation_famille)` → `{trials, success, req_p50}` avec lissage de Laplace + décroissance temporelle (demi-vie 90j, anti-fossilisation CRS qui change).
  - Moteur : Beta-Binomial conjugué (`α=success+1, β=fail+1`), Thompson/UCB-lite pour le boost scheduler **borné 0.5×–2×**, cold-start = priors bench C1, `min_samples=10` avant tout boost, veto impossible (l'évidence du run courant gagne toujours).
  - Stockage : `--learn` opt-in → `~/.cache/injekt/knowledge.json` (ou `--knowledge-file`), agrégats seuls (aucune URL, param, cookie, body — auditable `jq`), `knowledge export/import --anonymized` pour partage d'équipe sans fuite. Sans `--learn` : 100% RAM, 0 écriture (comportement actuel inchangé).
  - Scheduler (C4) : `score = EVI × knowledge_boost(borné) / cost`. Hypothesis (C3) : `prior = mix(bench_prior, knowledge_posterior, w= n/(n+k))`.
- **Dépendances :** C3/C4 terminés (consommateurs), C1 (priors bench + validation du gain sur historique rejoué).
- **Risques :** overfit labo (bench ≠ prod), boucle auto-renforçante, fuite de cibles via stats. Mitigation : bornes + `min_samples` + decay + agrégats sans identifiants + `knowledge show` transparent + `knowledge reset`. Test d'anti-fuite : le fichier ne contient aucune URL/host.
- **Critères de validation :** sur historique rejoué (C1) : à budget égal, `detect_rate` avec knowledge ≥ sans, et jamais de FP ajouté sur N1/N2 ; knowledge vide → comportement bit-identique au sans-knowledge ; fichier knowledge audité 0 URL/host/secret.
- **Tests à écrire :** unit Beta-Binomial (convergence, Laplace, decay) ; `proptest` bornes du boost ; intégration replay-historique (apprend A1 `space2comment` sur mysql, ne dégrade pas A2 pg) ; test OPSEC `knowledge.json` sans identifiants ; test neutralité cold-start.
- **Priorisation : Impact 4 | Difficulté 3 | Dette Moyenne | Valeur 5.** Le multiplicateur du raisonnement, sans son coût.

### C5 — Mutation Engine (AST, TARDIF — après le raisonnement)

- **Pourquoi (revue lead, inversé) :** le moteur Phase 1 ne souffre pas des tampers — il souffre de ne pas décider quoi tester. L'AST SQL est énorme ; investi trop tôt, il arrive avant que le scheduler sache s'en servir. Il vient **en dernier**, branché sur un raisonnement mature.
- **Problème résolu (alors seulement) :** `tamper.rs` string-level, aucune garantie "TRUE reste TRUE", aléatoire non seedé. En attendant, les 19 tampers + `is_boolean_safe` + borne `t.len()+2` suffisent (prouvé A1/A2 bras evasion).
- **Impact utilisateur :** `--tamper` déclaratif + sûr, mutation citée et rejouable. Aucun changement CLI visible en v1.0 (compat noms).
- **Impact architecture :** nouveau `src/mutation/` (mini-AST ciblé : prédicats, whitespace, commentaires, encodages) : `Parse→Normalize→Mutate→Render(dialect)` avec preuve `render(parse(x))==x`. `Tamper` = couche rendu compat. `mutation_plans(context, dbms_belief, knowledge)` branché C2/C3/C4/C13. `sqlparser` en dev-dependency pour tests d'équivalence uniquement. Pas d'Oracle complet jour 1. Scope v1.0 volontairement réduit : familles whitespace/comment/case/predicate déjà couvertes, pas de parseur SQL général.
- **Dépendances :** C2, C1 bras evasion (oracles), C4/C13 (qui choisissent les plans — d'où la position tardive).
- **Risques :** parseur général = 6 mois perdus. Mitigation : mini-AST + tests d'équivalence + gel `all_names()` (0 nouveau tamper string-level).
- **Critères de validation :** `∀ mutation boolean-safe, eval(TRUE)==TRUE ∧ eval(FALSE)==FALSE` ; déterminisme seedé ; A1/A2 evasion via Mutation Engine.
- **Tests à écrire :** `proptest` round-trip + TRUE/FALSE ; `insta` catalogue par dialecte ; intégration A1/A2.
- **Priorisation : Impact 3 (en v1.0, car non-goulot) | Difficulté 5 | Dette Moyenne (n'explose qu'après v1.0) | Valeur 4 (forte post-v1.0). P2 tardif.**

---

## 4. Plan de versions v0.4 → v1.0

### v0.4 — Metrology (4–6 semaines)

- **Objectif :** prouver, pas ajouter. Historique démarre ici (baseline v0.4 = point de comparaison de toutes les suivantes).
- **Fonctionnalités :** C1 (matrix 3 outils + `history.jsonl` + `compare`) + C12 `bench-smoke` PR + `--seed` minimal (RNG seedé).
- **Architecture :** `bench/runner`, `reporting/json` (`+seed,git_sha,profile`), tampers seedés. Orchestrateur inchangé.
- **Migrations :** aucune breaking. Champs `#[serde(default)]`. `versions.lock` gelé.
- **DoD :** `matrix` vert, `bench-smoke` gate, N1/N2 `fp==0`, `compare` détecte une régression injectée, `bench/README` CRS figé. Tag `v0.4.0` + première ligne d'historique.

### v0.5 — Reasoning Core (6–8 semaines)

- **Objectif :** le moteur raisonne (et décide quoi tester).
- **Fonctionnalités :** C2 (≤8 req) + C3 (Hypothesis v1) + C4 (EVI/coût, baseline mutualisée, early-stop) + refactor interne `run_detection` **sans plugin** (split en fonctions, <150 lignes).
- **Architecture :** `src/reasoning/`, `src/dbms/context.rs`, `scheduler.rs` réécrit, `orchestrator: baseline→context→reasoning loop→extraction gate`.
- **Migrations :** `EngineConfig + seed, budget` ; FIFO supprimé (interne). `Finding` inchangé.
- **DoD :** à budget égal `detect_rate ≥ v0.4` (**vérifié par `compare --from v0.4`**, pas à l'œil) ; N1/N2 ≤25 req ; CLI inchangé ; historique v0.5 > v0.4 à requêtes égales ou < à détection égale.

### v0.6 — Preuve + Verdict sobre (5–6 semaines)

- **Objectif :** chaque finding est prouvé, calibré, rapportable.
- **Fonctionnalités :** C6 (`--confirm` réel, `replay`, `--explain`, trace) + C7 (buckets calibrés, SARIF/JUnit/Markdown) + C10-partiel (pool time isolé, timeouts par classe, 429).
- **Architecture :** `reasoning/trace.rs`, `reporting/{verdict,sarif,markdown}`, `http/` timeouts par classe.
- **Migrations :** `--confirm` devient réel (~2× req, documenté). `--seed` stable. Export chiffré version+1, lecture v0.5 préservée. `--format` ajouté (défaut `json`).
- **DoD :** `--confirm` 0 nouveau FP ; même seed → même séquence ; trace sans secret ; `high→≥95%`, `medium→≥80%` ; A3 0×429 ; `compare --from v0.5` : FP et requêtes en baisse à `detect_rate` constant.

### v0.7 — DX + Mémoire + Évasion tardive (5–6 semaines)

- **Objectif :** le moteur apprend, l'utilisateur pilote, l'évasion devient sémantique (dans cet ordre).
- **Fonctionnalités :** C11 (`--dry-run`, `validate`, schéma, MCP `plan/explain`) + C13 (knowledge opt-in, boost borné, `knowledge show/reset/export`) + C5-scope-réduit (mini-AST branché sur C4/C13, compat `--tamper`, 0 nouveau nom).
- **Architecture :** `cli/plan.rs`, `reasoning/knowledge.rs` (fichier local opt-in, agrégats anonymes), `mutation/` (familles couvertes uniquement).
- **Migrations :** knowledge 100% opt-in (défaut = comportement v0.6 bit-identique) ; `all_names()` gelé.
- **DoD :** `--dry-run` 0 requête + priors affichés ; knowledge vide → neutre, rempli → `detect_rate` + à budget égal sur historique rejoué, 0 FP ajouté, 0 identifiant au fichier ; A1/A2 evasion via Mutation Engine ; `compare --from v0.6` vert.

### v1.0-rc → v1.0 publique (3–4 semaines hardening)

- **Objectif :** rien de nouveau. Geler, durcir, prouver. Les 5 lignes Vision v1 sont le DoD.
- **Gel :** CLI, `report.json` schema v1 + JSON Schema, `all_names()`, knowledge-schema v1.
- **Bench :** Groupe B si stable (sinon "non supporté" explicite), matrice officielle 3 outils sur runner dédié, `reports/` + `history.jsonl` + `versions.lock` publiés.
- **Audit OPSEC :** `socks5h`, jitter floor, `scrubber` tous renderers + trace + knowledge, `--no-redact` jamais défaut, RAM-only re-vérifié (sauf knowledge opt-in documenté), `cargo audit/deny` tranché.
- **DoD v1.0 :** `<100 req/param` stealth p95 à détection égale ; `fp==0` N1/N2 ; tout finding `--explain` + `replay` OK ; rapport SARIF/Markdown envoyable sans retouche ; nightly 7j verts ; 0 `todo!/unwrap/expect` en `src/` ; MSRV 1.88 prouvée ; changelog avec courbes v0.4→v1.0 (temps, requêtes, FP, détectabilité). C8/C9 exclus.

Ordre : **C1 → C2 → C3 → C4 → C6 → C7 → C10 → C11 → C13 → C5-tardif**, C12 continu.

---

## 5. Matrice

| Chantier | Impact | Complexité | Priorité | Prérequis | ROI |
|---|---|---|---|---|---|
| C1 Benchmark + historique | 5 | 3 | **P0** | — | Très haut |
| C3 Hypothesis Engine | 5 | 5 | **P0** | C1, C2 | Très haut |
| C2 Adaptive Fingerprinting | 5 | 3 | **P0** | C1 | Très haut |
| C4 Cost-Based Scheduler | 4 | 4 | **P0** | C2, C3 | Très haut |
| C6 Replay & Explain | 5 | 3 | **P0** | C3/C4 | Très haut |
| C12 CI/CD + bench automation | 4 | 2 | **P0** | C1 | Haut |
| C13 Knowledge Engine (stats) | 4 | 3 | **P0/P1** | C3/C4, C1 | Très haut (multiplicateur) |
| C7 Intelligent Reporting | 4 | 2 | **P1** | C1, C6 | Haut |
| C10 Perf sobre | 3 | 3 | **P1** | C4, C6 | Moyen |
| C11 DX | 3 | 2 | **P1** | C3/C4/C6 | Moyen-haut (adoption) |
| C5 Mutation AST (tardif, scope réduit) | 3 | 5 | **P2 tardif** | C2, C1, C4/C13 | Moyen en v1.0, fort post-v1.0 |
| C9 Multi-agent | 2 | 5 | **P3 hors v1.0** | — | Faible |
| C8 Plugin system | 2 | 3 | **Retiré v1.0** | — | Faible (solo-dev) |

---

## 6. Analyse critique

### 6.1 Séduisant mais perte de temps avant v1.0 (confirmé + plugin)

1. **200 payloads + 50 tampers.** CRS bloque le répertoire standard en query/cookie (mesuré). Vector-shift headers > 100 payloads.
2. **ML/LLM-détecteur black-box + LLM autonome (C9).** Incompatible offline/OPSEC/explicabilité. C13 (comptes Beta-Binomiaux) donne le gain d'apprentissage sans le coût.
3. **Plugin system (C8) — retiré v1.0 (revue lead).** Seul dev, 0 consommateur externe, abstraction qui ralentit le cœur C3/C4. Un split de fonctions suffit. Réévaluer post-v1.0 à ≥3 techniques externes demandées. Voir Annexe D.
4. **Mutation AST précoce — repoussée (revue lead).** Non-goulot en Phase 1 ; investie avant un scheduler mature, elle est prématurée. En dernier, scope réduit.
5. **Oracle/UNION/OOB complet jour 1.** "Non supporté" documenté > 0/0 silencieux.
6. **GUI, JA3 maison, crawler headless.** Même veto : `indicatif+tabled`, proxy, crawler statique + `max_per_template`.

### 6.2 Vrais avantages concurrentiels (signature)

| sqlmap/ghauri ne font pas | injekt v1.0 fait | Effet |
|---|---|---|
| Budget, arrêt précoce | C3+C4 EVI/coût, early-stop | Finit en stealth/rate-limit là où les autres se font bannir |
| Fingerprint précoce | C2 ≤8 req | 3–4× moins de sondes aveugles |
| Mémoire statistique | C13 Beta-Binomial opt-in | Converge de mission en mission, sans ML |
| Preuve rejouable | C6 seed/confirm/replay/explain | Finding défendable en revue |
| Zero-persistence + OPSEC | RAM-only, `Zeroize`, `socks5h`, jitter, `Sec-CH-UA` | Auditable (SQLite vs RAM ; knowledge opt-in documenté) |
| Benchmark adverse + historique | C1+C12 matrix + `history.jsonl` | Premier à publier `fp_rate` + courbes par version |
| Verdict CI-ready | C7 calibré, SARIF/JUnit | Branchement CI / Code Scanning |
| Évasion sémantique tardive | C5 TRUE reste TRUE, seedé | Sans casser le différentiel |

Formule (signature) : **le premier scanner SQLi orienté raisonnement : chaque requête est une ressource dépensée, chaque décision est expliquée, chaque résultat est reproductible avec un minimum de bruit.**

### 6.3 Bloquants absolus v1.0 (= Vision v1)

1. **C1+C12+historique** : sans bench + `compare` inter-versions + gate `fp==0`, pas de crédibilité.
2. **C3+C4** : sans hypothèses + scheduler, "autre lanceur de payloads en Rust".
3. **C2** : sans fingerprint précoce, stealth explose.
4. **C6** : `--confirm` no-op en publique = faute. Seed + replay + explain obligatoires.
5. **C7 + gel + audit** : rapport envoyable, CLI/schema gelés, OPSEC re-audité (trace + knowledge inclus), MSRV prouvée.
6. **C13 minimal** : opt-in, neutre à vide, gain prouvé sur historique, 0 fuite. Sans lui, le scheduler reste amnésique — acceptable en rc, pas en v1.0 finale.

Le reste partiel doit être **documenté comme limite**.

---

## Annexe A — Protocole benchmark scientifique + historique

- Scénarios : A1–A7 (`expected` techniques), N1–N2 (`expected=[]`, finding = FP), Groupe B Phase 2.
- Bras : `stock` + `evasion` (A1 `space2comment`, A2 `equaltolike`). Scénario valide si ≥1 bras solvable.
- Modes : `power` (10 threads, 200±100, 20/s, level 3) vs `stealth` (2 threads, 1200±400, 3/s, level 1, boolean+error, métrique = requêtes). A3 force sous 5/s.
- Répétitions : `repeats=3` Phase 1 → ≥5 officiel, reseed→run 600s→parse `--output`→assert `canary==untouched`→summary.
- Métriques : `detect_rate, fp_rate, req_p50/p95, time_p50/p95, canary_ok` (+ `detectability` : 403/429 par run). Cross-check logs (<5%).
- **Historique (revue lead) :** `history.jsonl` append-only (version, git_sha, scénario, bras, mode, métriques) ; `run.py compare --from v0.4 --to HEAD` rend `IMPROVED/FLAT/REGRESSION` par métrique avec seuils (régression = `detect_rate` −10pp ou tout `fp>0` ou `req_p50` +20% à détection égale) ; chaque release publie la courbe v0.4→… dans le changelog ; C13 se valide en rejouant l'historique (pas en relançant 50 runs).
- Gel : `pin` → `versions.lock` + specs + date cités.
- Réalités mesurées : CRS 3.3.10 bloque répertoire query/cookie (contrôle 0/0/0) ; headers custom aveugles → A6/A7 ; 920320 exige UA ; cookie inspecté ; erreurs masquées ; bruit `request_id`+`generated_at` ; filtres par endpoint ; canary destructif.

## Annexe B — Architecture cible

```text
parse → baseline → context+fingerprint → reasoning loop → fingerprint fill → extraction(opt-in) → done
                           │                    │
                     dbms/context.rs      reasoning/hypothesis.rs + scheduler.rs
                                                │ sondes (7 techniques, split simple, PAS de plugin en v1.0)
                                                │ mutations: tamper.rs (v0.4-0.6) → mutation/ mini-AST (v0.7 tardif)
                                                │ knowledge.rs (opt-in, boost borné 0.5-2x, jamais veto)
                                                └── trace.rs → reporting/verdict + replay/explain
bench/matrix+history ── calibre ──► likelihoods, coûts, seuils, priors knowledge cold-start
recon/scan ── baseline mutualisée (pas de partage inter-cible en v1.0)
session/state ── findings (stable) + trace (hashes, Zeroize, Scrubber)
knowledge.json (OPT-IN ~/.cache, agrégats anonymes, jamais d'URL/secret)
```

Invariants : `deny(unsafe,unwrap,expect,dbg,todo)` ; `#[non_exhaustive]`, newtypes, `const fn`, `match` exhaustifs ; `InjektError` ; `SecretString`+`zeroize`, sortie via `scrubber` (trace + knowledge inclus) ; `timeout()` typestate ; `socks5h://` seul ; `buffer_unordered` borné + `timeout` + `CancellationToken` ; zéro écriture sauf `--export-encrypted/--output/--import/--learn` opt-in explicites.

## Annexe C — Glossaire et prochaines décisions

- **EVI :** gain d'information espéré / coût.
- **Bras :** `stock` vs `evasion`.
- **Canary :** `marker != 'untouched'` = run invalide.
- **Knowledge :** comptes `(technique,dbms,waf,contexte,mutation)` → Beta-Binomial, pas du ML.
- **Décisions attendues :** valider ordre `v0.4→v0.5→v0.6→v0.7→rc` et scope-réduit C5 ; valider knowledge opt-in `~/.cache` + schéma v1 ; trancher `deny.toml` ; figer runner officiel ; accepter gel `all_names()` en v1.0.

## Annexe D — Post-v1.0 (plugin, multi-agent)

- **C8 Plugin system — sorti de v1.0 (revue lead, solo-dev, 0 consommateur).** Réévaluer si ≥3 techniques externes demandées ou contribution récurrente. Alors seulement : `techniques/api.rs` (`name/cost/supports/evaluate` + registre), 2 temps (wrapper puis branchement), jamais WASM/dylib sans audit. En v1.0 : split de fonctions, rien de plus.
- **C9 Multi-agent — hors v1.0.** Pas d'agents LLM. Éventuel `reasoning/coordinator.rs` lecture-seule inter-cibles `recon` (`--share-beliefs` explicite) si C1 prouve un gain. MCP reste l'interface agent, pas le moteur.
- **C5 plein AST** (parseur général, Oracle complet) : post-v1.0 si la v1.0-scope-réduit prouve le pattern sur A1/A2.
