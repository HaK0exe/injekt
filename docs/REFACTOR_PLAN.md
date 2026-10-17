# Plan de refactor architecture — injekt

> Date: 2026-10-15 — État des lieux: ~48k LOC `src/`, god file `src/engine/orchestrator.rs` 9504L (20% du projet).
> Progrès 2026-10-15: P0 ✅, P1 ✅ (config 292L + injection 724L + fetch 164L + confirm 1395L + schedule 336L + probes 2192L hors orchestrator: 9504→4570L, -4934L), P2-scaffold ✅. Tout vert: fmt/clippy/test lib 718 + 38 tests techniques + doc.
> Progrès 2026-10-17 (suite P1-fin): `ai_suggest` 391L + `enumerate` (extract_enum_field + run_enumeration) branchés/branchée; helpers `dbms_hint_kind`→`config.rs`, `first_finding_param`→`confirm.rs` (dédupliqué via `param_from_finding`). orchestrator 4735→3807L (-928L), re-exports `pub(crate) use` conservés. fmt/clippy/lib 814 verts.
> Progrès 2026-10-17 (P1-fin terminé, orchestrator vidé): phases extraites en modules dédiés — `extraction.rs` (385L), `second_order.rs` (372L), `run_confirm_second_pass`→`confirm.rs`, `baseline.rs` (424L: collect_baseline* + BaselineOutcome + spinner), `fingerprint.rs` (286L: run_fingerprint + active_fingerprint_probe), `detection.rs` (794L: run_detection + DetectionShared + run_detection_for_param + run_one_technique + dispatch_probe_{first,second}_half + apply_outcome_to_hypothesis + infer_signal_and_trials + progress_bar), `pipeline.rs` (717L: run_internal + absorb_detectability + build_raw_request + effective_marker_set + select_params). Tous les re-exports `pub(crate) use` orphelins supprimés; les tests importent directement `crate::engine::<module>::…`. orchestrator 3807→836L (9504L au départ, -91%). Suite complète verte (lib 814 + toutes intégrations + doc).
> Progrès 2026-10-17 (P1 réellement clos): `confirm.rs` 2019→746L éclaté en `confirm/{boolean,error,time,union,stacked,mutation}.rs` (parent = scope/gating + dispatch, sous-modules = second pass verbatim); `engine/probes.rs` (2373L) **dissous** → `techniques/<t>/scan.rs` (8 `test_*_bounded` + helpers `fetch_nosql_*`, `enumerate_columns_via_order_by`; fichiers 171–479L), `engine/mod.rs` ne déclare plus `probes`. Le move a introduit une dépendance `techniques/<t>/scan.rs` → `crate::engine::{confirm,fetch,schedule}` (cycle de modules autorisé par rustc, à inverser en P2 par `trait Technique`/`ProbeExecutor`). Tout vert (fmt/clippy -D warnings/lib 814 + intégrations + doc).
> Reste: P2 `trait Technique`/`ProbeExecutor` (dédup ~1500L, `detection.rs` 796L + scan 171-479L), P3 `cli/resolve.rs` (1295L) + mémoïsation `file_snapshot`, P4 splits `http/client.rs` (1202L), `detection/waf.rs` (1194L), `techniques/tamper.rs` (1906L), puis `mcp/tools.rs`, `dbms/context.rs`, `state.rs`.
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
- [ ] Introduire `pub trait Technique: Send+Sync { fn kind(); fn payloads(ctx); async fn probe(ctx,p); fn confirm(); }`
- [ ] Fusionner `run_detection_for_param + dispatch_probe_* + run_one_technique` en `scheduler.rs + executor.rs` générique.
- [ ] Les 8 `test_*_bounded` deviennent `impl Technique`.
- Done: ajouter technique = 1 nouveau fichier, 0 modif god file. Tests blind+noisy + 0 FP N1/N2 par technique.

### P3 — Config & CLI
- [ ] `Budget/Evasion/Net/Oob/EnumConfig + EngineConfig + ProbeOpts` → `engine/config.rs`
- [ ] `resolve.rs` → `ResolvedConfig` construite 1x, validée 1x (`precedence.rs`, `validate.rs`)
- [ ] `plan.rs 677L + commands/auto.rs 502L` → extraire `Planner`
- Done: 1 seule lecture config par process, `resolve/` chaque fichier <250L.

### P4 — Infra (parallélisable)
- [ ] `http/client.rs` → `{builder,sender,redirect,throttle,timeouts}.rs` + `trait HttpSender` pour mocks unitaires.
- [ ] `waf.rs` → `{vendor,registry,detectors/*}.rs` avec `trait WafDetector`.
- [ ] `tamper.rs` → `tamper/{space,comment,case,encode,...}.rs`.
- [ ] `context.rs`, `state.rs` (Finding vs SessionState vs StoredProbe), `mcp/tools.rs` (1 handler/outil).
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
