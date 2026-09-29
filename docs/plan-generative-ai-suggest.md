# Plan : génération à la volée + `--ai-suggest` (suivi d'avancement)

> Doc de pilotage. Source de vérité pour découper le travail en agents parallèles.
> Principes intangibles : défaut OFF = byte-identical, `deny(unsafe,unwrap,expect,dbg,todo)`,
> `make_rng(seed)` unique, budget borné, RAM-only, `SecretString` + `scrubber`,
> `buffer_unordered(threads)` + `CancellationToken`.
> Rappel roadmap v1.0 : **« LLM autonome » interdit** — `--ai-suggest` est un
> conseiller opt-in post-échec uniquement, jamais un décideur.

## Décisions figées avec l'opérateur

- LLM : **pas de génération live en détection**. Uniquement `--ai-suggest` après échec / WAF-block.
- Providers : endpoint **compatible OpenAI Chat Completions + Anthropic Messages** (au moins ces deux formats).
- Ordre : ce doc d'abord, agents ensuite, implémentation après synthèse.

## Track A — PayloadBuilder par grammaire déterministe (pas de LLM)

- [ ] A1 `src/generation/` : enums fermées `Fence{Bare,Single,Double,Backtick,Paren(u8)}`, `Logic{Or,And}`, `Predicate{EqInt,EqStr,Like,Rlike,In,Between,CaseWhen,Div,Xor,ChrFunc}`, `Terminator` dérivé de `InjectionContext.comment + DbmsKind`. `#[non_exhaustive]`, `const fn` / `match` exhaustifs.
- [ ] A2 `build_pair(fence, logic, predicate, ctx, dbms, rng) -> GeneratedPair{true,false}` : même shape, flip minimal `1<->2` / `a<->b`, garantie `true != false`. 0 I/O, 0 requête.
- [ ] A3 Déterminisme : même `(ctx, dbms, seed)` → même séquence via `crate::seeded_rng::make_rng`. Tests `same_seed` / `different_seeds`.
- [ ] A4 Traçabilité hashes-only : label `gen:<fence>+<logic>+<pred>` en `ProbeRecord`, jamais payload clair (même pattern que `MiniMutator::plan_label`).
- [ ] A5 Wiring boolean V1 : `orchestrator.rs` (~L4655 `.take(payload_budget(level,2,len))`) — défaut OFF = liste actuelle inchangée ; ON = 2 historiques d'abord (polyglotte + `' OR 1=1`), puis génération jusqu'au budget.
- [ ] A6 Feedback : si `is_app_filter_block(400/400)` streak `FILTER_STREAK_LIMIT=3` ou `Baseline::is_waf_blocked()`, prioriser la dimension filtrée (espace → forme `space2paren`-native, quote → `Bare`/numeric).
- [ ] A7 Extension V2 : `time` / `error` / `union` avec prédicats dialectaux (`SLEEP`/`pg_sleep`/`WAITFOR`, `EXTRACTVALUE`…), toujours derrière `payload_allowance()`. Interaction `généré → muté`, jamais l'inverse.
- [ ] A8 CLI : `--generative <off|conservative|aggressive>` (défaut `off`) + `--max-generated N` plafonné. Tranché : nouveau flag, pas de surcharge de `--level`.
- [ ] A9 Tests : unit (cohérence, terminator par DBMS, jamais vide/collapsé), `proptest` style `tests/proptest_parsers.rs`, snapshot `insta` séquence L1/L2, intégration `wiremock` (`integration_generative` : single-quote, numeric, WAF 403 → auto-tamper, filtre 400).

## Track B — `--ai-suggest` post-échec / WAF-block (OpenAI + Anthropic)

- [ ] B1 Gate pur `should_attempt_ai_suggest()` dans `src/ai/mod.rs` : `ai_suggest==true && findings.is_empty() && (waf_blocked || waf_blocking || filter_streak>=3 || confirm_dropped) && !baseline_all_error() && !budget_exhausted && !deadline_past && !cancelled && !oob_only`. Un seul passage par param. 0 requête.
- [ ] B2 CLI dans `src/cli/args/detection.rs` : `--ai-suggest` (bool, `INJEKT_AI_SUGGEST`), `--ai-provider <openai|anthropic>` (`INJEKT_AI_PROVIDER`), `--ai-endpoint <url>` (requis si suggest), `--ai-model <name>` (requis), `--ai-api-key` (`SecretString`, env `INJEKT_AI_API_KEY` uniquement), `--ai-max-suggestions N` (`1..=5`, défaut 3), `--ai-timeout S` (défaut 30). `Debug` manuel : endpoint scrubbed, model clair, key `[REDACTED]`. `resolve.rs` : `requires`, anti-SSRF/`allow-private` cohérent pour endpoint loopback.
- [ ] B3 `src/ai/provider.rs` : `trait LlmProvider { fn suggest(...) }` + `OpenAiChatProvider` (`POST {model, messages:[system,user], response_format:json_object, temperature:0}` → `choices[0].message.content`) + `AnthropicProvider` (`POST {model, max_tokens, system, messages:[{role:user,content}]}` + header `x-api-key` + `anthropic-version: 2023-06-01` → `content[]` texte concaténé). Sélection par `--ai-provider`. Timeouts via `HttpClient::builder().timeout().build()`, `RequestClass::Default`. Erreurs via `InjektError`, jamais `unwrap/expect`.
- [ ] B4 `src/ai/prompt.rs` : `build_ai_context()` = abstraits uniquement — `InjectionContext::summary()`, `DbmsBelief::top_candidate()`, `waf_vendor/hits/blocking`, `comment style`, 2-3 squelettes (`' OR <INT>=<INT> -- -`, jamais payload brut, jamais cookies/headers/body/target brute, jamais extracted data). Cap ~1 Ko. System prompt : « retourne JSON strict `[{"true":"...","false":"..."}]`, paires boolean cohérentes, pas de stacked/RCE ». Parsing strict `serde_json`, rejet si hors-schéma.
- [ ] B5 `src/ai/validator.rs` (bloquant, 0 requête cible si échec) : `true != false`, flip minimal, longueur ≤ 512, charset whitelist SQL, rejet `;` stacked / `xp_` / `EXEC` / `OUTFILE` / `LOAD_FILE` / sleep déguisé (sauf technique time autorisée), équivalent `is_boolean_safe` (rejette base64-opaque / quote-escaped inerte), dédup vs déjà-essayés (hash set session).
- [ ] B6 Wiring orchestrator second-pass : après techniques, pour chaque paire validée → même `HttpClient`, `buffer_unordered(threads)`, `CancellationToken`, compté `SessionState::request_count` + `RequestBudget`. 1 paire = 2 requêtes → max 3 suggestions = 6 requêtes/param. Éval via `BooleanDetector::evaluate` + vetos `string/not_string/code`. Échec silencieux, finding originel jamais modifié.
- [ ] B7 OPSEC : `warn!` opt-in explicite (données abstraites → endpoint tiers, privilégier localhost/Ollama). Clé en `SecretString` + `zeroize`, sortie via `scrubber`, `--no-redact` interdit sauf debug local. RAM-only, trace `ai:<provider>+<n>` hashes-only.
- [ ] B8 Tests : unit validator (collapse/stacked/charset/dédup/déterminisme prompt), gate `should_attempt_ai_suggest`, `wiremock` double-mock (fausse cible WAF 403 + faux endpoint LLM stub OpenAI et Anthropic → ≤6 requêtes, 0 finding inventé ; sans flag → 0 appel LLM), `cargo test --doc`.
- [ ] B9 Docs : `DOCUMENTATION.md` + `docs/playbook/03-scan-detection.md` + `README`/`README.fr` (section opt-in + exemples OpenAI vs Anthropic + avertissement OPSEC).

## Garde-fous communs (DoD chaque PR)

- [ ] `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test`, `cargo test --doc` verts.
- [ ] L1 sans flags = byte-identical (listes + budgets + traces inchangés).
- [ ] Toute randomness via `make_rng(seed)` ; `--seed` rejoue à l'identique.
- [ ] Concurrency bornée + `CancellationToken` + `tokio::time::timeout` ; pas de spawn non borné.
- [ ] Aucun secret en log/trace/rapport sans scrub ; en-tête `#![allow(clippy::unwrap_used, clippy::expect_used)]` sur chaque nouveau `tests/*.rs`.

## Découpage agents (4 lots parallèles, lecture seule d'abord)

1. `agent-generation` → spec détaillée `src/generation/` (A1-A4, A9-partiel).
2. `agent-ai-providers` → spec `src/ai/provider.rs + prompt.rs` OpenAI + Anthropic (B3-B4).
3. `agent-cli-orchestrator` → spec flags + gate + wiring second-pass (A5-A6-A8, B1-B2-B6).
4. `agent-validator-tests` → spec `validator.rs` + matrices de tests + OPSEC (A9-partiel, B5-B8).

## Journal d'avancement

- [x] 2026-09-22 : doc créé.
- [x] 2026-09-22 : 4 sous-agents Task rejetés par le provider (`free tier can only be used from within OpenCode`) → bascule en specs directes solo, sans modification de code pour l'instant.
- [x] 2026-09-22 : étape 1 implémentée (flags + gate + validator + providers/prompt purs, 0 réseau) :
  - `src/cli/args/detection.rs` : 7 flags `--ai-*` + `Debug` scrubbed/redacted.
  - `src/cli/resolve.rs` : `effective_ai_*` + `validate_ai_opts` + 4 tests.
  - `src/ai/mod.rs` : `AiProviderKind`, `AiSuggestConfig`, `should_attempt_ai_suggest`/`ai_trigger`/`ai_hard_stop`, `ai_plan_label` + 6 tests.
  - `src/ai/validator.rs` : `validate_ai_pair` (pattern/inert avant forme/charset) + 8 tests.
  - `src/ai/prompt.rs` : `AiSignals`, `system_prompt`, `build_user_prompt` (cap 1 Ko), `skeletonize` (digits→`<INT>`) + 4 tests.
  - `src/ai/provider.rs` : bodies + parsers `OpenAI`/`Anthropic` (+ `ANTHROPIC_VERSION`) + 6 tests.
  - `scan`/`auto`/`recon scan` : fail-fast `validate_ai_opts`. MCP : AI exclu (CLI-only).
  - `cargo fmt`, `clippy --all-targets -D warnings`, `cargo test --lib` (680 ok), `--doc` (4 ok), `integration_http` (9 ok) verts.
- [x] 2026-09-22 : étape 2 implémentée (wiring second-pass, double-mock vert) :
  - `SessionState` : `app_filter_hits` + `waf_hits` (RAM-only, dedup par param, `Zeroize`/`wipe`/`Clone` couverts).
  - `fetch_for_payload_with_class` : mémorise les hits WAF live (`403/406/429`) par param — 0 changement quand AI OFF (gate `config.ai.enabled` ; `record_status` existant resté intact car jamais appelé en run).
  - `EngineConfig.ai: AiSuggestConfig` + `engine_cfg.rs` (clé en `SecretString`) ; MCP : AI exclu (CLI-only).
  - `provider::fetch_suggestions` : client `reqwest` dédié (direct, sans cookies/proxy), timeout, `CancellationToken` (`select!`), headers `Authorization: Bearer` / `x-api-key` + `anthropic-version`, erreurs sans secret + 4 tests `wiremock`.
  - `run_ai_suggest_for_param` : gate → signaux abstraits (+ squelettes L1 anti-répétition) → fetch → validator → sondes `RequestClass::Boolean` (tampers boolean-safe, RNG seedé) → `BooleanDetector` + veto matcher → finding `trials=1/1` + trace `ai:<provider>+<n>` hashes-only. Trigger = WAF baseline/blocking OU filtre `400` OU empreinte WAF live ; hard-stop = origine down/budget/deadline/cancel/boolean désactivé (`--confirm` droppé = V2 documenté).
  - `tests/integration_ai_suggest.rs` : cible WAF simulée (`403` sur `OR`, différentiel réservé à la paire IA `AND 7=7/7=8`) — OFF silencieux, OpenAI 1 finding `ai:openai+0` (1 appel LLM, 2 requêtes cible), Anthropic idem.
  - Golden `cli-flags.txt` refreshé (7 flags, diff reviewé) ; `DOCUMENTATION.md` : 7 lignes flags.
  - `cargo fmt`, `clippy --all-targets -D warnings`, `cargo test` complet : 36 suites OK, 0 échec.
- [x] 2026-09-22 : étape 3 implémentée (Track A generation, vert du 1er coup) :
  - `src/generation/grammar.rs` : `QuoteFence` (9, `open()`/`ordered_for_context`), `Logic`, `Predicate` (10, noyau/exotique, `ChrFunc` dialectisé `CHAR`/`CHR`), `comment_for` (convention historique + `#`).
  - `src/generation/builder.rs` : `build_pair` (`{open} {LOGIC} {pred} {comment}`), `enumerate_candidates` (fences×logics×preds, rotation seedée), `dedupe_against` (anti-redondance historique), `candidate_label` (`gen:<fence>+<logic>+<pred>`).
  - `src/generation/mod.rs` : `GenerativeMode::{Off,Conservative,Aggressive}`, `GenerativeConfig` (clamp `0..=16`, défaut `Off/4`).
  - CLI `--generative` + `--max-generated` (+ `resolve`, `Debug`, MCP exclu) ; `EngineConfig.generative` + `engine_cfg`.
  - Wiring `test_boolean_bounded` : historique d'abord (ordre/budgets inchangés), générées ensuite ; `gen=` en évidence. OFF = byte-identical.
  - `tests/proptest_generation.rs` (cohérence × shape × terminateur × déterminisme seed) ; `tests/integration_generative.rs` (cible différentielle `'b'` : OFF muet, conservative 1 finding `gen=`) ; golden refreshé (9 flags AI+generation au total) ; `DOCUMENTATION.md`.
  - `cargo fmt`, `clippy --all-targets -D warnings`, `cargo test` complet : 38 suites OK, 0 échec.
- [x] Plan complet : Track A + Track B implémentés et vérifiés.
- [x] 2026-09-23 : durcissement "post-`' OR '1'='1`" (payloads 2026) :
  - `QuoteFence::Bare` rejoue le littéral `1` (`1AND(1)=(1)-- -` valide en numérique).
  - Nouveaux prédicats noyau `NoSpaceEq` (`(1)=(1)`/`(1)=(2)`) et `NoSpaceLike` (`(1)LIKE(1)`/`(1)LIKE(2)`), rendus sans espaces (`'OR(1)=(1)-- -`), énumérés en premier. Noyau 5→7 (conservative 90→126, agressif 180→216).
  - `tests/integration_generative.rs` : WAF à signatures (`403` sur `+OR+`/`+AND+`) — la liste classique meurt à 100%, le spaceless généré confirme (`gen=...nospace...`).
  - `tests/proptest_generation.rs` : propriété de préfixe spaceless vs espacé.
- [x] 2026-09-23 : séparateurs natifs tab/newline (dimension grammaire, pas tamper) :
  - `Separator::{Space,Tab,Newline}` : `{open}{sep}{LOGIC}{sep}{pred}` (spaceless ignore). Pool conservative 306→9×2×17, agressif 576 (labels `+tab`/`+nl`, espace inchangé).
  - Plafond `--max-generated` 16→32 (fenêtre ≥ écart cyclique max, garantie anti-rotation).
  - Validator IA : `\t`/`\n` autorisés (jamais loggés en clair).
  - `tests/integration_generative.rs` : WAF évolué (tue espacé + spaceless) — OFF muet, tab/newline confirme (`gen=...+tab|+nl`). Debug au passage : les URLs wiremock ont révélé que `IN (2)` tabulé matchait l'ancien mock large → mock resserré sur les fins spaceless exactes.
  - `cargo fmt`, `clippy --all-targets -D warnings`, `cargo test` complet : 38 suites OK, 0 échec.
- [x] 2026-09-23 : bypass login inversé (`tests/integration_login_bypass.rs`) — le scénario CVE-2026 (auth pre-auth style `LiteLLM`/Fortinet/Drupal) : TRUE ouvre la session, FALSE retombe sur l'échec. Prouve end-to-end que `confirm_either` (pass swapped) confirme et tague ` inverted` (`user@query`). Bonus : sans filtre `-p`, les deux champs confirment — comportement correct.
  - `cargo fmt`, `clippy --all-targets -D warnings`, `cargo test` complet : 39 suites OK, 0 échec.
