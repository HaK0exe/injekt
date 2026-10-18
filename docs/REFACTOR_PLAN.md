# Plan de refactor architecture — injekt

> Date: 2026-10-15 — État des lieux: ~48k LOC `src/`, god file `src/engine/orchestrator.rs` 9504L (20% du projet).
> Progrès 2026-10-15: P0 ✅, P1 ✅ (config 292L + injection 724L + fetch 164L + confirm 1395L + schedule 336L + probes 2192L hors orchestrator: 9504→4570L, -4934L), P2-scaffold ✅. Tout vert: fmt/clippy/test lib 718 + 38 tests techniques + doc.
> Progrès 2026-10-17 (suite P1-fin): `ai_suggest` 391L + `enumerate` (extract_enum_field + run_enumeration) branchés/branchée; helpers `dbms_hint_kind`→`config.rs`, `first_finding_param`→`confirm.rs` (dédupliqué via `param_from_finding`). orchestrator 4735→3807L (-928L), re-exports `pub(crate) use` conservés. fmt/clippy/lib 814 verts.
> Progrès 2026-10-17 (P1-fin terminé, orchestrator vidé): phases extraites en modules dédiés — `extraction.rs` (385L), `second_order.rs` (372L), `run_confirm_second_pass`→`confirm.rs`, `baseline.rs` (424L: collect_baseline* + BaselineOutcome + spinner), `fingerprint.rs` (286L: run_fingerprint + active_fingerprint_probe), `detection.rs` (794L: run_detection + DetectionShared + run_detection_for_param + run_one_technique + dispatch_probe_{first,second}_half + apply_outcome_to_hypothesis + infer_signal_and_trials + progress_bar), `pipeline.rs` (717L: run_internal + absorb_detectability + build_raw_request + effective_marker_set + select_params). Tous les re-exports `pub(crate) use` orphelins supprimés; les tests importent directement `crate::engine::<module>::…`. orchestrator 3807→836L (9504L au départ, -91%). Suite complète verte (lib 814 + toutes intégrations + doc).
> Progrès 2026-10-17 (P1 réellement clos): `confirm.rs` 2019→746L éclaté en `confirm/{boolean,error,time,union,stacked,mutation}.rs` (parent = scope/gating + dispatch, sous-modules = second pass verbatim); `engine/probes.rs` (2373L) **dissous** → `techniques/<t>/scan.rs` (8 `test_*_bounded` + helpers `fetch_nosql_*`, `enumerate_columns_via_order_by`; fichiers 171–479L), `engine/mod.rs` ne déclare plus `probes`. Le move a introduit une dépendance `techniques/<t>/scan.rs` → `crate::engine::{confirm,fetch,schedule}` (cycle de modules autorisé par rustc, à inverser en P2 par `trait Technique`/`ProbeExecutor`). Tout vert (fmt/clippy -D warnings/lib 814 + intégrations + doc).
> Reste: la queue des >500L (13 fichiers après `engine/detection.rs`, dont `engine/orchestrator.rs` 840L et `engine/pipeline.rs` 729L en cours côté session parallèle, `ai/provider.rs` 569L, `techniques/oob/payloads.rs` 563L, `engine/confirm/boolean.rs` 557L, `session/export.rs` 549L, `engine/enumerate.rs` 547L); re-évaluer la dédup P2 après P4.
> Progrès 2026-10-18 (P4 étape 1): `techniques/tamper.rs` (1916L) → `tamper/{mod,registry,pipeline,space,keywords,encoding,numeric,signatures}.rs` (move-only vérifié en multiset: 1772 lignes; 12 helpers passés `pub(super)`; 70 tests redistribués par famille; max 370L; 2 commentaires-séparateurs supprimés). Validé en worktree isolé (worktree propre à `a02f1ca`) pour ne pas croiser le chantier ADR-0009 `transit` en cours: fmt/clippy/tests 1031 verts.
> Progrès 2026-10-18 (P4 étape 2): `http/client.rs` (1202L) → `client/{mod,error,builder,sender,body,redirect,throttle}.rs` (move-only vérifié en multiset: 1079 lignes non-scaffold; 6 helpers passés `pub(super)`; 3 liens intradoc qualifiés (`TIME_POOL_SLOTS` ×2, `CookieJar`) car leur `use` change de fichier; 1 signature rewrappée par rustfmt (`resolve_redirect_url`); 2 tests répartis `mod.rs`/`redirect.rs`; max 443L). `trait HttpSender` non extrait (move-only d'abord). Validé dans l'arbre principal une fois `transit` mergé (4380cf3): fmt/clippy -D warnings verts, tests 1044 verts (hors 1 échec du chantier graphql/orm en cours: `learn_from_run` vs nouveaux `TechniqueKind`), 5 doc-tests verts.
> Progrès 2026-10-18 (P4 étape 3): `detection/waf.rs` (1194L) → `waf/{mod,vendor,registry,detectors,ct,tests}.rs` (move-only vérifié en multiset: 1093 lignes; 8 helpers `pub(super)` (5 fns + 2 consts dans `registry.rs`, 1 helper de test); 1 lien intradoc qualifié (`detect_cloudflare_flat` dans `registry.rs`); 36 tests répartis par famille (vendor 3, registry 1, ct 1, détecteur 31 via `tests.rs` dé-indenté d'un niveau; 3 reflows rustfmt documentés); max 465L). `trait WafDetector` non extrait (move-only d'abord). Validé sur `feat/modern-injections-2026`: fmt/clippy -D warnings verts, 1044 tests verts (seul l'échec graphql/orm hors périmètre), 5 doc-tests verts, aucun nouveau warning rustdoc.
> Progrès 2026-10-18 (P4 étape 4): `mcp/tools.rs` (1026L) → `tools/{mod,server,builder,router,params}.rs` (move-only vérifié en multiset: 980 lignes; adaptations de visibilité uniquement: 7 fns + champ `cancel` en `pub(super)`, `#[tool_router(vis = "pub(super)")]` pour que le `tool_router()` généré reste joignable depuis `server.rs` où `#[tool_handler]` s'expanse — ensemble effectif inchangé; max 439L). Pas de fichier par handler: la macro rmcp exige tous les `#[tool]` dans un seul impl block. Validé sur worktree isolé pendant le commit elasticsearch puis sur l'arbre fusionné `36646ad`: fmt/clippy -D warnings verts, 1045 tests verts (échec graphql/orm connu exclu), 5 doc-tests verts, 0 nouveau warning rustdoc (19 = 19).
> Progrès 2026-10-18 (P4 étape 5): `dbms/context.rs` (1003L) → `context/{mod,model,errors,passive,active,tests}.rs` (move-only vérifié en multiset: 915 lignes; 2 adaptations: `build_spec_for_context` en `pub(super)` pour les tests, module de tests converti en module-file dé-indenté + 3 `use` extra; max 445L). `crate::dbms::context::*` stable via re-exports. Validé dans l'arbre principal: fmt/clippy -D warnings verts, 1045 tests verts (échec graphql/orm connu exclu), 5 doc-tests verts, 0 nouveau warning rustdoc (19 = 19).
> Progrès 2026-10-18 (P4 étape 13): `engine/confirm.rs` (751L, racine du module déjà doté de 6 sous-modules) → `confirm/{mod,error_bool,scope,second_pass,params,dispatch}.rs` (move-only vérifié en multiset: 689 lignes; aucun changement de visibilité/lien/corps — les items croisés étaient déjà `pub(crate)` et les appels utilisent des noms non qualifiés servis par les nouveaux préambules; en-tête redistribué: doc de module (2L) verbatim dans mod.rs, decls/re-exports préservant les chemins `engine::confirm::X`; `in_confirm_scope`/`needs_auto_second_pass` n'étant consommés que par les tests de `orchestrator` (cfg(test)), leur re-export porte `#[allow(unused_imports)]`; max 222L). `crate::engine::confirm::*` surface inchangée. Validé: fmt OK, clippy lib+bins `-D warnings` vert, clippy all-targets avec l'unique allowance du lint de l'autre session, 1047 tests verts (0 test dans confirm), 5 doc-tests verts, rustdoc 19 = 19 (aucun nouveau).
> Progrès 2026-10-18 (P4 étape 14): `target/injection.rs` (724L) → `injection/{mod,opts,filters,tampers,raw,inject,headers,spec}.rs` (move-only vérifié en multiset: 684 lignes; aucun changement de visibilité/corps/lien — tous les items étaient déjà `pub`, appels par noms non qualifiés, et le lien intradoc `sniff_kind` reste non résolu comme dans la baseline; imports redistribués en préambules; mod.rs re-exporte les 20 items publics, `crate::target::injection::*` stable; max 324L). Validé: fmt OK, clippy lib+bins `-D warnings` vert, clippy all-targets avec l'unique allowance du lint de l'autre session, 1047 tests verts (0 test dans injection), 5 doc-tests verts, rustdoc 19 = 19 (aucun nouveau).
> Progrès 2026-10-18 (P4 étape 15): `detection/control_pair.rs` (704L) → `control_pair/{mod,control,tests}.rs` (move-only vérifié en multiset: 662 lignes; doc de module 22L verbatim dans mod.rs, liens intradoc résolus via les re-exports; 3 items privés lus par le module de tests passent `pub(super)` (CONTROL_VALUE_MIN/MAX, find_int_comparison), visibilité effective inchangée; tests.rs: corps dé-indenté + 7 lignes d'extras (consts/helper + imports response_diff/detector qui venaient du `use` privé du parent); 1 re-split rustfmt documenté (`let pair =` + call joint); max 401L). Validé: fmt OK, clippy lib+bins `-D warnings` vert, clippy all-targets avec l'unique allowance du lint de l'autre session, 1047 tests verts (14 control_pair), 5 doc-tests verts, rustdoc 19 = 19 (aucun nouveau).
> Progrès 2026-10-18 (P4 étape 16): `target/structured.rs` (647L) → `structured/{mod,kind,json,xml,tests}.rs` (move-only vérifié en multiset: 598 lignes; doc de module 45L verbatim dans mod.rs, liens résolus via les re-exports; 4 liens intradoc de kind.rs qualifiés `crate::target::structured::X` (le module json importe déjà les consts utilisées en code, liens via l'import); tests.rs: corps dé-indenté + 1 extra (`use serde_json::Value;`), aucun helper privé utilisé par les tests donc aucune visibilité changée; max 285L). Validé: fmt OK, clippy lib+bins `-D warnings` vert, clippy all-targets avec l'unique allowance du lint de l'autre session, 1047 tests verts (18 structured), 5 doc-tests verts, rustdoc 19 = 19 (aucun nouveau).
> Progrès 2026-10-18 (P4 étape 17): `detection/confirmation.rs` (635L) → `confirmation/{mod,model,stats,verdict,tests}.rs` (move-only vérifié en multiset: 622 lignes; doc de module 4L verbatim dans mod.rs; `binomial_tail_at_least` lu par le module de tests passe `pub(super)`, visibilité effective inchangée; tests.rs: corps dé-indenté + 1 extra (import du helper privé); aucun lien à changer (les liens `confirm`/`confirm_either` vivent dans verdict.rs avec leurs cibles); max 383L). Validé: fmt OK, clippy lib+bins `-D warnings` vert, clippy all-targets avec l'unique allowance du lint de l'autre session, 1047 tests verts (17 confirmation), 5 doc-tests verts, rustdoc 19 = 19 (aucun nouveau).
> Progrès 2026-10-18 (P4 étape 18): `session/scrubber.rs` (627L) → `scrubber/{mod,redact,headers,secrets,patterns,oob,tests}.rs` (move-only vérifié en multiset: 584 lignes; doc de la structure `Scrubber` verbatim dans redact.rs; 8 helpers libres appelés depuis l'impl passent `pub(super)` (le 9e, `scrub_provider_tokens`, reste privé, appelé dans son fichier); tests.rs: dé-indent seul, aucun extra ni allow; aucun lien à changer, pas de doc de module; max 238L). Surface OPSEC inchangée (`crate::session::scrubber::Scrubber`). Validé: fmt OK, clippy lib+bins `-D warnings` vert, clippy all-targets avec l'unique allowance du lint de l'autre session, 1047 tests verts (15 scrubber), 5 doc-tests verts, rustdoc 19 = 19 (aucun nouveau).
> Progrès 2026-10-18 (P4 étape 19): `mutation/mod.rs` (580L) → `mutation/{mod,types,mutator,gate,apply,tests}.rs` (move-only vérifié en multiset: 536 lignes; doc de module 37L verbatim dans mod.rs; 5 helpers privés appelés à travers la nouvelle frontière passent `pub(super)` (`push_variant` + les 4 transforms), visibilité effective inchangée; tests.rs: dé-indent + 2 extras (transforms utilisés par les tests + CommentStyle/InjectionContext), l'allow unwrap/expect va sur `mod tests;`; 1 lien de doc qualifié ([`CommentStyle`] → [`crate::dbms::context::CommentStyle`], l'import vit désormais dans apply.rs); max 163L). Validé: fmt OK, clippy lib+bins `-D warnings` vert, clippy all-targets avec l'unique allowance du lint de l'autre session, 1047 tests verts (16 mutation), 5 doc-tests verts, rustdoc 19 = 19 (aucun nouveau).
> Progrès 2026-10-18 (P4 étape 20): `engine/detection.rs` (576L) → `detection/{mod,runner,shared,param,dispatch,outcome}.rs` (move-only vérifié en multiset: 538 lignes, édits appliqués par index de ligne — collision attendue `context_probes: usize,` champ vs signature; doc de module 6L verbatim dans mod.rs; 12 modifications de visibilité `pub(super)`: struct DetectionShared + ses 9 champs (lus/écrits par runner/param/dispatch), run_detection_for_param (appelé par runner), run_one_technique (appelé par param) — build_technique_ctx/progress_bar restent privés (appel unique intra-fichier); 1 lien intradoc qualifié ([`Hypothesis`] → [`crate::reasoning::Hypothesis`], l'import vit désormais dans param.rs); 2 imports scaffold recréés post-split (ensure_union_starvation_guard → param.rs, apply_outcome_to_hypothesis → dispatch.rs); le re-export pub(crate) des 2 fns d'outcome, consommées hors module par les seuls tests d'orchestrator, porte `#[allow(unused_imports)]` (même pattern que confirm); 0 test dans le fichier; max 260L). Validé: fmt OK, clippy `-D warnings` vert (lib+bins ET all-targets — l'allowance proptest de l'autre session a disparu), 1047 tests verts, 5 doc-tests verts, rustdoc 19 = 19 (aucun nouveau).
> Progrès 2026-10-18 (P4 étape 12): `detection/baseline.rs` (846L) → `baseline/{mod,model,analysis,tests}.rs` (move-only vérifié en multiset: 791 lignes; 2 consts WAF privées déplacées dans analysis.rs (placement verbatim, consommateur unique); 3 liens intradoc qualifiés (`normalize_response_for_diff` dans model; `super::waf::*` ×2 en `crate::detection::waf::*` dans analysis); 3 appels code `super::waf::*` → `waf::*` via `use crate::detection::waf;` (import module, pas de réécriture); 3 joins rustfmt documentés (2 tests, 1 analysis après qualification); tests.rs: +1 `use` (Duration), 0 unwrap/expect donc pas d'allow; max 425L). `crate::detection::baseline::{Baseline,Sample,collect_baseline}` stable via re-exports. Validé: fmt OK, clippy lib+bins `-D warnings` vert, clippy all-targets avec l'unique allowance du lint de l'autre session, 1047 tests verts (18 baseline), 5 doc-tests verts, rustdoc 19 = 19 (aucun nouveau).
> Progrès 2026-10-18 (P4 étape 11): `recon/crawler.rs` (890L) → `crawler/{mod,config,crawl,extract,decode,robots,tests}.rs` (move-only vérifié en multiset: 824 lignes; 11 visibilités `pub(super)` — `ExtractedDocument` + champs, `extract_document`, `decode_embedded_url`, `RobotsRules` + champs + `parse`/`allows` — tout consommé par un sibling ou les tests, ensembles effectifs inchangés; 2 liens intradoc qualifiés en `crate::recon::filters::{page_template_key,candidate_template_key}`; 1 join rustfmt documenté; +6 `use` explicites dans tests.rs (remplace le bloc privé du parent) et glob `use super::*` retiré (devenu inutilisé); max 305L). `recon::crawler::{CrawlConfig,CrawlReport,Crawler}` stable via re-exports. Validé: fmt OK, clippy lib+bins `-D warnings` vert, clippy all-targets avec l'unique allowance du lint de l'autre session, 1047 tests verts (7 crawler), 5 doc-tests verts, rustdoc 19 = 19 (aucun nouveau).
> Progrès 2026-10-18 (P4 étape 10): `reasoning/knowledge.rs` (934L) → `knowledge/{mod,types,store,scoring,mapping,io,tests}.rs` (move-only vérifié en multiset: 862 lignes; 2 visibilités `pub(super)` (`boost_from_counts`, `clamp_knowledge_range` — store + tests), `KnowledgeFile`/`default_knowledge_version` déplacés dans store.rs (placement verbatim), 1 re-wrap rustfmt documenté, +6 `use` dans tests.rs (imports privés du parent), doc de module (67 lignes) conservée verbatim dans mod.rs; max 292L). `crate::reasoning::knowledge::*` stable via re-exports. Validé: fmt OK, clippy lib+bins `-D warnings` vert, clippy all-targets avec l'unique allowance du lint de l'autre session, 1047 tests verts (15 knowledge), 5 doc-tests verts, rustdoc 19 = 19 (aucun nouveau).
> Progrès 2026-10-18 (P4 étape 9): `techniques/error/detector.rs` (941L) → `error/detector/{mod,model,rules,classify,extract,tests}.rs` (move-only vérifié en multiset: 879 lignes; 2 visibilités `pub(super)` (`extract_version`, champ `patterns`) pour les accès sibling, ensembles effectifs inchangés; 1 reflow rustfmt documenté; aucun lien intradoc à qualifier; max 450L). `crate::techniques::error::detector::*` stable via re-exports. Validé: fmt OK, clippy lib+bins `-D warnings` vert, clippy all-targets avec l'unique allowance du lint de l'autre session, 1047 tests verts (30 detector), 5 doc-tests verts, rustdoc 19 = 19 (aucun nouveau).
> Progrès 2026-10-18 (P4 étape 8): `detection/response_diff.rs` (954L) → `response_diff/{mod,normalize,similarity,diff,classify,tests}.rs` (move-only vérifié en multiset: 914 lignes; 2 visibilités `pub(super)` (`MAX_LEVENSHTEIN_LEN` déplacé dans similarity.rs + `truncate`, lus par les tests — ensemble effectif inchangé), 2 liens intradoc qualifiés, 1 reflow rustfmt documenté, +1 `use` dans tests.rs; max 342L). `crate::detection::response_diff::*` stable via re-exports. Validé: fmt OK, clippy lib+bins `-D warnings` vert, clippy all-targets avec l'unique allowance `redundant_pattern_matching` (lint dans le proptest anti-SSRF non commité de l'autre session, hors périmètre), 1047 tests verts (23 response_diff), 5 doc-tests verts, rustdoc 19 = 19 (2 warnings pré-existants relocalisés, aucun nouveau).
> Progrès 2026-10-18 (P4 étape 7, première de la queue >500L): `detection/scanner/scheduler.rs` (1015L) → `scheduler/{mod,scoring,budget,early_stop,heap,tests}.rs` (move-only vérifié en multiset: 906 lignes; 13 liens intradoc qualifiés en `crate::detection::scanner::scheduler::*` (frontières scoring/early_stop/heap), 3 reflows rustfmt documentés sur les assertions de tests dé-indentées, `#[allow(clippy)]` déplacé sur `mod tests;`, +1 `use TechniqueKind` dans tests.rs (l'import privé du parent n'est plus en scope); max 386L). `crate::detection::scanner::scheduler::*` stable via re-exports. Validé: fmt/clippy -D warnings verts, 1045 tests verts (18 tests scheduler), 5 doc-tests verts, 0 nouveau warning rustdoc (19 = 19).
> Progrès 2026-10-18 (P4 étape 6, fin de la liste P4 explicite): `session/state.rs` (915L) → `state/{mod,finding,probe,session,tests}.rs` (move-only vérifié en multiset: 835 lignes; 4 adaptations: 2 × `super::scrubber::Scrubber` → `crate::session::scrubber::Scrubber` (profondeur +1), lien intradoc `SessionState::push_finding` qualifié, champ `extracted` en `pub(super)` (tests), `#[cfg(test)] mod tests` converti en module-file dé-indenté; max 422L). `crate::session::state::*` stable via re-exports. Validé dans l'arbre principal: fmt/clippy -D warnings verts, 1045 tests verts (échec graphql/orm connu exclu), 5 doc-tests verts, 0 nouveau warning rustdoc (19 = 19).
> Progrès 2026-10-18 (P3 étape 3): `cli/plan.rs` (677L) + `commands/auto.rs` (502L) → `plan/{planner,model,render,escalation,tests}.rs` (parent 27L; `EscalationStep`/`escalation_plan` extraits d'`auto.rs` vers `plan/escalation.rs`); move-only vérifié en multiset (496+53+185+126 lignes), chemins publics `cli::plan::*` stables via re-exports; `auto.rs` 502→366L; 1031 tests verts.
> Progrès 2026-10-18 (P3 étape 2): `cli/resolve.rs` (1323L) éclaté en `resolve/{snapshot,effective,ai,validate,opts,target,net,auth,tests}.rs` (move-only, corps vérifiés verbatim en multiset: 781 lignes de corps + 444 de tests identiques); `file_snapshot` passé `pub(super)`; mémoïsation `Cli::file_cache: Arc<OnceLock<FileConfig>>` (étape 1) inchangée; 1031 tests verts.
> Progrès 2026-10-18 (P2 fait): `techniques/technique.rs` = `TechniqueCtx` (entrées partagées) + trait dyn-safe `Technique { kind, probe }` + registre `technique_for`; les 8 `test_*_bounded` sont des `impl Technique` (corps verbatim derrière un préambule `let x = ctx.x;`); `detection.rs` perd `dispatch_probe_{first,second}_half` (~235L) au profit de `build_technique_ctx` + lookup registre (796→571L). P2b dédup mécanique: `ctx.fetch`/`ctx.fetch_with_class` (18 sites d'appel d'arguments 11-12 → 1 ligne) + `tamper::tamper_label` (8x) → scan.rs 2631→2354L. Ajouter une technique = 1 fichier `scan.rs` + 1 entrée registre, zéro modif de l'exécuteur. Note: la réduction « ~1500L » estimée en P2 n'est pas atteinte — les corps restants sont du contrôle par technique (budgets/trials/matchers) ; toute fusion supplémentaire toucherait au FP/FN et sort du move-only (à re-évaluer après P4).
> Objectif restant: aucun fichier >500L, aucune fn >80L hors glue, suppression du god object, frontières `cli -> app -> domain <- infra`.
> Contraintes inviolables: voir `AGENTS.md` + skill `injekt-rust-dev` (deny `unsafe/unwrap/expect/dbg/todo`, MSRV 1.88 ed.2024, OPSEC zero-persistence, `secrecy::SecretString`, `HttpClient::builder().timeout().build()` obligatoire, `socks5h://` uniquement, bounded `buffer_unordered` + `CancellationToken`).

## 1. État des lieux chiffré (vérifié `wc -l`)

```
47986 total src/
 9504 src/engine/orchestrator.rs
 1906 src/techniques/tamper.rs
 1202 src/http/client.rs
 1194 src/detection/waf.rs
 1144 src/cli/resolve.rs
 1025 src/mcp/tools.rs
 1003 src/dbms/context.rs
  997 src/detection/scanner/scheduler.rs
  926 src/reasoning/knowledge.rs
  890 src/recon/crawler.rs
  885 src/session/state.rs
```

Points chauds `orchestrator.rs` (>150L/fn):

```
 run_enumeration 810L (L3866), run_second_order 652L (L1932), extract_enum_field 648L (L8686),
 collect_baseline_uncached 351L (L1319), run_extraction 354L (L3511), run_internal 449L (L673),
 run_ai_suggest_for_param 306L, test_boolean_bounded 319L, test_oob_bounded 291L,
 test_nosql 266L, test_json 259L, test_union 232L, test_time 204L, etc.
307 refs `crate::` vers 15 modules depuis 1 fichier.
#[allow(clippy::too_many_lines)] sur run_internal = aveu.
```

Autres smells:

- `cli/resolve.rs` 1144L: ~30x `effective_*` dans `impl Cli`, chaque getter rappelle `file_snapshot()` → re-`load()` TOML + parse à chaque fois. Pas mémoïsé.
- `http/client.rs` 1202L: `ClientBuilder` typestate + `RequestSpec` + `TimedResponse` + `send_with_retry*` + `follow_spec` + `resolve_redirect_url` + throttle mélangés.
- `detection/waf.rs` 1194L: enum + registry + regex + 4 familles de signaux dans 1 fichier.
- `techniques/tamper.rs` 1906L: 1 enum + ~20 `apply_*`.
- Pas de `trait Technique`: 8x `test_*_bounded` copiés-collés (budget → payloads → scheduler → fetch → matcher → hypothesis → trace).
- Couplage logique circulaire: `orchestrator` dépend de tout, `cli/resolve`, `cli/plan`, `cli/commands/*`, `mutation`, `recon/*` dépendent en retour d'`orchestrator` (14 fichiers `rg -l orchestrator`).

## 2. Architecture cible

```
cli/ (thin: parse + resolve 1x -> AppConfig)
  |
app/ (NOUVEAU, ex-engine/phases: pipeline + use-cases)
  |- pipeline.rs (parse->baseline->detect->confirm->fingerprint->extract, <200L)
  |- phases/{baseline.rs, detection.rs, confirm.rs, fingerprint.rs, extraction.rs, enumeration.rs, second_order.rs}
  |- inject/{spec.rs, marker.rs, multipart.rs}
  |- confirm/{boolean.rs, error.rs, time.rs, union.rs, stacked.rs}
domain/ (pur, sans tokio/reqwest)
  |- techniques: trait Technique + 8 impls
  |- detection: Signal, Matcher, Scheduler pur
  |- dbms, target, session
infra/ (adapters)
  |- http/{client, sender, redirect}, tracing, scrubber, knowledge_store
```

Règle: `cli -> app -> domain <- infra`, jamais `domain -> infra`. `Engine` devient façade fine qui injecte des traits.

Arborescence cible (extrait):

```
src/engine/
  mod.rs, config.rs, pipeline.rs
  phases/{baseline.rs, detection.rs, confirm.rs, fingerprint.rs, extraction.rs, enumeration.rs, second_order.rs}
  inject/{spec.rs, marker.rs, multipart.rs}
  confirm/{boolean.rs, error.rs, time.rs, union.rs, stacked.rs}
src/techniques/mod.rs  # pub trait Technique { kind, payloads, probe, confirm }
src/cli/resolve/{mod.rs, precedence.rs, profile_resolver.rs, file_snapshot.rs, validate.rs}
src/http/{builder.rs, sender.rs, redirect.rs, throttle.rs, timeouts.rs}
src/detection/waf/{mod.rs, vendor.rs, registry.rs, detectors/*.rs}
src/target/injection.rs  # ex inject_param*, headers_preserving_*, multipart
```

## 3. Phases

### P0 — Quick wins, zéro risque (1 PR)
- [ ] Mémoïser `file_snapshot()`: `OnceCell<FileConfig>` ou passer `&FileConfig` en param. Supprime N lectures disque par invocation.
- [ ] Extraire fns pures `orchestrator.rs`: `filter_params, payload_budget, is_ignored, synthetic_raw_from_data` + `inject_param*, headers_preserving_*, inject_multipart_field, build_injection_spec_with_raw` → `src/target/injection.rs`.
- [ ] Gate anti-régression: ajouter check `wc -l` dans `justfile` + `clippy::too_many_lines` seuil 150.
- Done: `cargo fmt --check`, `clippy -- -D warnings`, `cargo test` verts, aucun changement comportemental.

### P1 — Découpe orchestrator (le gros morceau, moves purs sans logique)
- [x] `run_second_order 652L` → `engine/second_order.rs` ✅ 2026-10-17
- [x] `run_enumeration 810L + extract_enum_field 648L` → `engine/enumerate.rs` ✅ 2026-10-17 (fichier unique; split colonnes non fait)
- [x] `run_extraction 354L` → `engine/extraction.rs` ✅
- [x] `collect_baseline* 351L + run_internal 449L` → `engine/baseline.rs` + `engine/pipeline.rs` ✅
- [x] `run_fingerprint* / run_detection*` → `engine/fingerprint.rs` + `engine/detection.rs` ✅
- [x] orchestrator 836L, plus aucun méthode hors façade `new/with_*/run/run_candidate/state_handle` ✅
- [x] `confirm_* 150-220L x6` → `engine/confirm/*.rs` ✅ (2019→746L parent + 6 sous-modules)
- [x] `test_*_bounded x8` → `techniques/<t>/scan.rs` ✅ (move seul, déduplication en P2; `engine/probes.rs` supprimé)
- État: `pipeline.rs 717L` (glue run_internal+helpers), `detection.rs 796L` (sweep+dispatch) — sous-cible 250/400L, allègement prévu par P2 (trait Technique `ProbeExecutor`). Tests wiremock verts à chaque move.

### P2 — `trait Technique` + `ProbeExecutor` (supprime ~1500L duplication)
- [x] Introduire `pub trait Technique: Send+Sync { fn kind(); fn payloads(ctx); async fn probe(ctx,p); fn confirm(); }` ✅ (scaffold `techniques/technique.rs`; `payloads/confirm` restent dans les scan/confirm par technique)
- [x] Fusionner `run_detection_for_param + dispatch_probe_* + run_one_technique` en `scheduler.rs + executor.rs` générique ✅ (scheduler = `run_detection_for_param`; exécuteur générique = `run_one_technique` + `build_technique_ctx`; les 2 dispatchs supprimés)
- [x] Les 8 `test_*_bounded` deviennent `impl Technique` ✅ (+ dédup P2b: `ctx.fetch*`, `tamper_label`)
- [~] Done: ajouter technique = 1 nouveau fichier, 0 modif god file ✅ ; tests blind+noisy + 0 FP N1/N2 par technique (suite verte, pas de re-run bench matrix)

### P3 — Config & CLI
- [x] `Budget/Evasion/Net/Oob/EnumConfig + EngineConfig` regroupés dans `engine/config.rs` ✅ (312L; `ProbeOpts` vit dans `target/injection.rs`, scopé au fetch par probe — inchangé)
- [x] `resolve.rs` → `resolve/{snapshot,effective,ai,validate,opts,target,net,auth,tests}.rs` ✅ (move-only, corps verbatim; `ResolvedSnapshot` ré-exporté; `file_snapshot` en `pub(super)`; sous-modules ≤204L hors tests 469L)
- [x] Mémoïsation: `Cli::file_cache: Arc<OnceLock<FileConfig>>` (`#[arg(skip)]`, par instance) → 1 lecture TOML/process ✅ (test régression `file_snapshot_memoized_within_instance`)
- [x] `plan.rs` (677L) + `commands/auto.rs` (502L) → extraire `Planner` ✅ (`plan/{planner,model,render,escalation,tests}.rs`, parent 27L, sous-modules ≤304L; `escalation_plan` sorti d'`auto.rs` 502→366L; move-only, `cli::plan::*` stable)
- Done: 1 seule lecture config par process, `resolve/` chaque fichier <250L.

### P4 — Infra (parallélisable)
- [~] `http/client.rs` (1202L) → `client/{mod,error,builder,sender,body,redirect,throttle}.rs` ✅ move-only vérifié (multiset 1079 lignes; 6 helpers `pub(super)`; 3 liens intradoc qualifiés; max 443L); `trait HttpSender` (mocks unitaires) différé, à extraire sans changement de comportement.
- [~] `waf.rs` (1194L) → `waf/{mod,vendor,registry,detectors,ct,tests}.rs` ✅ move-only vérifié (multiset 1093 lignes; 8 helpers `pub(super)`; 36 tests par famille; max 465L); `trait WafDetector` différé, à extraire sans changement de comportement.
- [x] `tamper.rs` (1916L) → `tamper/{mod,registry,pipeline,space,keywords,encoding,numeric,signatures}.rs` ✅ (move-only vérifié; 12 helpers `pub(super)`; 70 tests par famille; `crate::techniques::tamper::*` stable via re-exports)
- [~] `mcp/tools.rs` (1026L) → `tools/{mod,server,builder,router,params}.rs` ✅ move-only vérifié (multiset 980 lignes; adaptations: 7 fns + champ `cancel` passés `pub(super)`, `#[tool_router(vis = "pub(super)")]` pour garder le `tool_router()` généré visible depuis `server.rs` où `#[tool_handler]` s'expanse — visibilité effective inchangée; max 439L). Pas de fichier par handler : la macro rmcp exige tous les `#[tool]` dans un seul impl block.
- [~] `context.rs` (1003L) → `context/{mod,model,errors,passive,active,tests}.rs` ✅ move-only vérifié (multiset 915 lignes; `build_spec_for_context` `pub(super)`; tests en module-file dé-indenté; max 445L).
- [~] `state.rs` (915L) → `state/{mod,finding,probe,session,tests}.rs` ✅ move-only vérifié (multiset 835 lignes; adaptations: 2 chemins `scrubber` qualifiés, lien intradoc qualifié, champ `extracted` `pub(super)`, tests en module-file dé-indenté; max 422L). Liste P4 explicite terminée — reste la queue des >500L (28 fichiers).
- Done: chaque fichier <500L, doc-tests + insta revus si snapshots touchés.

## 4. Agents lancés (2026-10-15)

| Agent | Scope (disjoint, read-only d'abord) | Livrable |
|-------|-------------------------------------|----------|
| A — orchestrator | `src/engine/orchestrator.rs` uniquement | tableau fn→L→dépendances→fichier cible P1 + ordre de moves sans conflit |
| B — cli/resolve | `src/cli/resolve.rs + args/ + profile.rs + file_config.rs` | graphe `effective_*` + plan `resolve/` + patch mémoïsation `OnceCell` |
| C — infra http/waf/tamper | `src/http/client.rs + detection/waf.rs + techniques/tamper.rs` | plans de split + traits `HttpSender`/`WafDetector` + registries |
| D — techniques/domain | `src/techniques/*/ + dbms/context.rs + detection/scanner/` | spec `trait Technique` + matrice duplication `test_*_bounded` + plan P2 |

Consignes communes aux agents: NE PAS éditer `orchestrator.rs` en parallèle (conflits), read-only + proposer patchs. Respect skill `injekt-rust-dev` + OPSEC. Retour = liste fichiers + signatures + risques + ordre d'application.

## 5. Vérification (après chaque agent / chaque PR)

```bash
cargo fmt --check
cargo clippy -- -D warnings
cargo test
cargo test --doc
cargo test --test integration_http -- --nocapture
cargo insta review  # seulement si snapshot touché
```

## 6. Risques
- Moves massifs `orchestrator.rs` → conflits git si parallélisé en écriture → d'où phase analyse read-only d'abord, application séquentielle ensuite.
- `#[allow(clippy::too_many_lines)]` à retirer seulement quand P1 fini.
- Ne pas logger secrets, ne pas stocker URLs/cookies dans knowledge/stats, garder `ZeroizeOnDrop`, `0o600` exports.
