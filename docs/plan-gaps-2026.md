# Plan : combler les gaps 2026 de injekt (série v1.1 — doc de pilotage)

> **Statut : VALIDÉ - décisions D1..D4 tranchées par l'opérateur (2026-10-18).**
> Doc de pilotage de la série v1.1, post-tag v1.0. L'ADR
> `docs/adr/0010-second-order.md` est à rédiger à l'amorçage du chantier P1
> (unique décision touchant la « ligne rouge » écriture cible).
>
> **Doctrine respectée** (non négociable, cf. `docs/ROADMAP-v1.0.md` §6.1) :
> - v1.0-rc en cours = *geler, durcir, prouver* — **rien de nouveau avant le tag v1.0** ;
> - pas de ML/LLM-détecteur black-box, pas d'agent LLM autonome ;
> - pas de « 200 payloads + 50 tampers » (qualité > quantité, vector-shift) ;
> - chaque requête est une ressource dépensée, chaque décision expliquée
>   (signature : *le premier scanner SQLi orienté raisonnement*).
>
> **Invariant par PR** : `cargo fmt --check` / `clippy -D warnings` / `cargo test`
> / `--doc` verts ; défaut OFF = byte-identical sur tous les flux existants ;
> aléa via `make_rng(seed)` (`--seed` rejouable) ; concurrence bornée
> (`buffer_unordered` + `timeout` + `CancellationToken`) ; `SecretString` +
> scrubber ; zéro écriture disque sauf opt-in explicite ; header
> `#![allow(clippy::unwrap_used, clippy::expect_used)]` sur chaque nouveau
> `tests/*.rs` ; golden CLI + docs (DOCUMENTATION.md, playbook chap. + README)
> à chaque flag nouveau.

---

## 0. Où on en est (référence unique : playbook ch. 10 §10.8)

Ce qui **existe déjà** — ne pas re-planifier :

- 8 familles (boolean/time/error/union/stacked/oob/json/nosql), tampers HTTP
  (HPP/chunked), 24 tampers + presets, extraction checksum, DBMS fingerprint
  (mysql/postgres/mssql/oracle), C13 knowledge (Beta-Binomial, Thompson/UCB-lite
  boost 0.5×–2×), C5-tardif mini-AST (4 familles mutation préservant TRUE/FALSE),
  génération grammaticale (`--generative`, spaceless, tab/nl), `--ai-suggest`
  (OpenAI/Anthropic, post-échec uniquement), MCP stdio, verdict C7 calibré
  (High ≥ 95 % / Medium ≥ 80 %), bench + `history.jsonl`.

Ce qui **manque** (les 6 gaps de ce plan) :

| Gap | État | Valeur si comblé |
|---|---|---|
| G1 Second-ordre (stored) | ❌ | Couvre la famille la plus furtive ; aucun scanner grand public n'est fiable dessus avec preuve rejouable |
| G2 Recherche adaptative de bypass (payload-level) | ⚠ partiel (boost technique-level C13 existe, mais pas de politique tamper×fence×separator en run) | Contourne les WAF à signatures mortes sur les chaînes canoniques |
| G3 Oracle temporel statistique fin | ⚠ basique (seuil baseline+2σ) | Extrait malgré rate-limit/bruit sur les cibles « lentes autorisées » |
| G4 Registre de profils WAF | ⚠ presets + auto 2 tampers seulement | Réduit le coût de placement en évasion (fingerprints → tamper set recommandé) |
| G5 Dialecte SQLite | ❌ (fingerprint présent, payloads absents) | Cheap win : stack lab/API courantes ; vocabulaire knowledge l'anticipe déjà (`sqlite` dans `DbmsKind`) |
| G6 Tags recon GraphQL/LLM-endpoints | ❌ | Cartographie passive des surfaces IA sans attaque (préalable éthique) |

Framing versions : tout ceci est **série v1.1** (post-tag v1.0). Un seul overlap
partiel avec la ROADMAP : Annexe D (post-v1.0 plugin/multi-agent) ; ce plan ne
préjuge pas du plugin.

---

## 1. Décisions opérateur — **tranchées (2026-10-18)**

| # | Décision | Verdict |
|---|---|---|
| D1 | **G1 écrit sur la cible** (marqueur bénin via l'app). Aujourd'hui `injekt` ne modifie *aucun* état applicatif — G1 rompt ce contrat. | ✅ **ACCEPTE** : flag unique `--second-order` + `warn!` au lancement + inventaire des écritures dans le rapport (purge manuelle) + ADR 0010 (rollback non garanti). Version semi-manuelle (phase B seule) conservée en fallback `--second-order manual` |
| D2 | **G3 vs jitter/rate-limit** : l'oracle statistique fin et le jitter partagent le même canal (latence) | ✅ confirmé par défaut : `--time-stat` réservé à `--profile aggressive`, tension documentée, jamais auto-monté |
| D3 | **G1/G2 dans le MCP ?** | ✅ **CLI + MCP direct** (pas de phase CLI-only) — voir garde-fous §4.1 |
| D4 | **Ordre des PRs** | ✅ **P5 d'abord** (SQLite), puis P2, P1, P3, P4, P6 — cf. §8 |

### 4.1 Garde-fous D3 — écriture cible exposée au MCP

Exposer `second-order` (écriture sur cible) à des **agents externes** est la
décision à risque de tout ce plan. Règles liées :

- le paramètre `write_target` est **explicite dans le schéma de l'outil MCP**
  (`src/mcp/tools/builder.rs`, même modèle que `allow_knowledge`) et est
  **jamais inféré** : un agent qui l'imagine pas n'écrit pas ;
- parité avec le CLI : `--second-order` côté CLI ⇔ `write_target: true` côté
  MCP ; `manual` ⇔ `write_target: false` (phase B seule) ;
- le résultat MCP renvoyé suit les règles existantes : scrubber sur toute
  évidence, trace hashes-only, jamais de secret;
- l'avertissement `warn!` du CLI devient un champ `warned: true` du tool
  result — preuve que l'agent a été informé ;

---

## 2. P5 (premier) — Dialecte SQLite complet (`--dbms sqlite`)

**Objectif :** apporter au moteur un 5e dialecte SQL dont le fingerprint existe
déjà (`DbmsKind::Sqlite`, regex d'erreurs `SQLITE_ERR` dans
`src/dbms/context/errors.rs`, entrée `model.rs`), aujourd'hui inutilisable en
attaque car absent des payloads/flags.

**Design :**

- `src/dbms/sqlite/{fingerprint,payloads,queries}.rs` — grammaire par SGBD :
  - boolean : paires `(1)=(1)` / `(1)=(2)` et `'a'='a'` / `'a'='b'`
    (fence quote ou parens selon le contexte d'injection) ;
  - terminateur `--` + `/* */` (pas de `#`) ; concaténation `||` ;
  - time : **pas de SLEEP natif portable en SQL** (`sqlite3_busy_timeout`
    n'est pas du SQL) → la technique `time` est exclue du dialecte et
    documentée comme limite ; l'oracle reste boolean/error/union ;
  - error : `CAST('x' AS <type_invalide>)`, erreurs `no such column/table`,
    `unrecognized token` (déjà en regex) ;
  - union + énumération : `sqlite_master` (`LIMIT`/`WHERE`),
    `sqlite_version()` ; pas de `information_schema` ;
  - extraction : `substr(t,i,1)` (canal binaire inchangé).
- Flag `--dbms sqlite` + alias `sqlite3` ; défaut auto reste « fingerprint →
  sqlite si erreur reflétée ».
- Knowledge : clé `(technique, sqlite, context_class)` déjà admise.

**Critères d'acceptance :**

1. `integration_dbms_sqlite` : wiremock backend simulé SQLite → paires
   boolean confirmées + dumping `sqlite_master` via `--extract` (opt-in) ;
2. détection négative : payload MySQL envoyé sur contexte sqlite → 0 finding ;
3. documentation : playbook chap. 3/5, liste `--dbms` mise à jour,
   golden refresh.

**Effort :** S (2-3 jours). **Risques :** faibles — module isolé.

---

## 3. P2 — Recherche adaptative de bypass (payload-level bandit)

**Objectif :** répondre au gap « boucle reward-driven en run » — sélectionner
**dans le run** la combinaison tamper × fence × separator qui confirme, en
épuisant un budget minimal — sans ML, sans réseau de neurones.

**Distinction clé avec C13 :** C13 booste des **techniques** (boolean vs time…)
entre runs ; ici on optimise des **payloads/évasions** pendant le run. Les deux
s'empilent sans se contredire : le prior du bandit peut être initialisé par
`knowledge.rs` (`--allow-knowledge`) si l'opérateur l'active.

**Design :**

- Nouveau `src/bypass_search/{policy.rs,space.rs}` (RAM-only, seedé) :
  - **Espace discret fermé** : `{∅, 1 tamper, chaîne courte, preset} ×
    {QuoteFence} × {Space, Tab, Newline, spaceless}` — composé uniquement à
    partir des enums existants (`techniques/tamper`, `generation/grammar.rs`) ;
    ~15×9×4 combinaisons bornées, élaguées par les garde-fous boolean-safe ;
  - **Politique** : UCB1 sur bras « combo » avec plafond
    `--max-adaptive N` (défaut 8 requêtes/param) ;
    reward = +10 confirmation boolean, +1 « WAF traversé sans diff »
    (500 : BDD atteinte, syntaxe cassée), −1 bloqué (403/406/challenge),
    0 neutre ;
  - **Sortie** : la variante gagnante nourrit le finding d'origine comme
    *évidence* (traces `lab=ucb:<combo>` hashes-only) — jamais un finding
    nouveau non confirmé (règle `is_app_filter_block` etc. inchangées) ;
  - **Déclencheur** : uniquement *post*-échec des tampers canoniques ET
    `Baseline::is_waf_blocked()` / streak filtre ≥ 3 (réuse du gate de
    `should_attempt_ai_suggest`, flag à part : `--adaptive-bypass`) ;
  - Interaction `ai-suggest` : les deux gates sont exclusives dans le même
    passage (bypass adapté joué d'abord, IA en dernier recours — jamais l'inverse).
- Budget : param-level borné (le cap met fin à la recherche), déclencheur
  unique par param, aucune interaction avec le rate-limit global.

**Critères d'acceptance :**

1. `integration_adaptive_bypass` : backend WAF simulé bloquant `+OR+`/
   `+AND+`, `/**/` **et** chaque tamper isolé — la combinaison trouvée par
   le bandit (ex. `space2paren+versionedfuzz`) confirme ;
   double-voie : OFF = 0 requête adaptative (byte-identical), ON = finding ;
2. déterminisme : même seed → même séquence de variantes testées (trace) ;
3. budget : aucune séquence N+1 requête après le cap ;
4. golden CLI + doc `03`/`04`.

**Effort :** M (5-8 jours). **Risques :** sur-optimisation sur le labo —
mitigation : validation bench adversarial (scénarios A1/A2/A6/A7 existants)
avant PR.

---

## 4. P1 — Second-ordre (stored SQLi) — *ADR 0010 requis*

**Objectif :** détecter la famille « poison à retardement » avec preuve
rejouable, sans occulter que la détection de la famille est intrinsèquement
*difficile*. Aucun scanner grand public ne la couvre automatiquement avec
confirmation — c'est **le positionnement signature** de v1.1.

**Contour honnête :** on ne prétend pas à une détection *générale* du
second-ordre (l'événement peut ne s'exécuter que dans des flux admin que le
crawl ne voit pas). On cible le **patron dominant et détectable** : une valeur
stockée via un paramètre de surface, puis re-rendue dans un flux crawlé
(profil, formulaire) dont le *consommateur* concatène — le reflet ré-apparait
dans une page et dégrade le rendu de façon structurelle (diff, erreur SQL
reflétée).

**Design — 2 phases opt-in** (`--second-order`, *off* par défaut) :

- **Phase A — inoculation** : sur un paramètre *écrivable* pointé par
  l'opérateur (`-p src@POST` + `--data`), stocker un **marqueur bénin** via la
  requête normale de l'app (paramétrée par construction) : forme sans quote
  `injekt-<hash8>` par défaut, forme avec quote (`injekt-<hash8>'`)
  uniquement si D1 validé — la quote est ce qui ré-apparaît cassé côté
  consommateur. C'est la **seule écriture cible** du tooling (ADR 0010,
  rollback non garanti) ;
- **Phase B — chasse au consommateur** :
  1. crawl des flux accessibles sous la même session/compte
     (réutilisation `recon crawl`) ;
  2. pour chaque page rendue, détecter si le marqueur est reflété **et** sous
     quelle forme (brut, cassé, error SQL voisine) — signal d'un contexte
     construit depuis la base ;
  3. confirmer sur le paramètre consommateur avec la procédure boolean
     inversée usuelle (`BooleanDetector`, `confirm_either`, seed rejouable) ;
  4. finding étiqueté `origin=second-order`, rapport avec les 2 requêtes
     (scrubbées) ;
- **État** : `SessionState` (RAM) prolongé par `MarkerStore{source_param,
  marker_hash, consumer_hints}` ; `--export-encrypted` permet de
  séparer phase A et phase B en deux exécutions ;
- **MCP** (D3 = direct) : outil `second_order` avec paramètre explicite
  `write_target` (garde-fous §4.1) ;
- **Fallback semi-manuel** : `--second-order manual` = phase B uniquement
  (marqueur stocké à la main par l'opérateur — 0 écriture cible).

**Critères d'acceptance :**

1. `integration_second_order` : wiremock `/register` (INSERT paramétré) +
   `/report` (SELECT concaténé reflétant le champ) → finding avec
   confirmation inversée, tag `second-order`, 0 finding sans marqueur ;
2. sans `--second-order` → byte-identical (0 requête phase A/B) ;
2b. `--second-order manual` → 0 écriture (phase B seule), finding possible
    quand le marqueur opérateur est détecté côté consommateur ;
3. OPSEC : `warn!` au lancement, inventaire des mutations opérées dans le
   rapport (quelles valeurs il faudra purger à la main) ;
4. rapport : `explain` couvre les deux sauts (phase A puis B).

**Effort :** L (10-15 jours, dont la moitié en tests wiremock).
**Risques :** faux positifs à cheval (marqueur écrit jamais relut dans un
flux réel) — mitigations : confirmation inversée obligatoire sur le
consommateur, gate opt-in, tests double-phase.

---

## 5. P3 — Oracle temporel statistique (`--time-stat`)

**Objectif :** rendre l'oracle time robuste pour les cibles à bruit de latence
élevé (tail latency, rate-limiting intermittent), à budget de requêtes
maîtrisé : agrégation robuste à la place d'un seuil `baseline + 2σ` unique.

**Design :**

- `src/techniques/time/stat.rs` : k sondes par condition (défaut 3,
  plafond 5), stats **médiane + MAD** (moins sensibles que
  moyenne/σ à la tail-latency) ; confirmation uniquement si les k mesures
  concordent (pas de décision sur une mesure isolée) ;
- `--time-stat` (OFF par défaut, jamais auto-monté, réservé à
  `--profile aggressive`) — D2 : le jitter/rate-limit OPSEC restent inchangés,
  la tension est documentée plutôt que résolue ;
- **Fallback** sans `--time-stat` : seuil `baseline + 2σ` historique.

**Critères d'acceptance :**

1. `integration_time_stat` : wiremock à delay conditionnel + latence de base
   (~50 ms) + bruit gaussien simulé — `--time-stat` confirme là où l'oracle
   historique échoue ; FP ≤ 1/20 (proptest sur distributions de latence) ;
2. non-régression : mode OFF byte-identical ;
3. doc tension OPSEC (chap. 3 + `docs/OPSEC.md`).

**Effort :** S-M (3-5 jours). **Risques :** FP si le bruit réel n'est pas
gaussien — mitigations : concordance des k mesures + vetos infra
(429/503) inchangés.

**Repoussé (G3 bis — HTTP/3 micro-timing transport)** : l'écosystème Rust h3
(reqwest/quinn) reste **instable/experimental** au moment T ; passer le
transport QUIC change aussi la signature réseau finale (OPSEC) et les
fallbacks proxy (`socks5h`) ne transportent pas h3. → **rejet v1.1**, rester
en évaluation continue ; la valeur immédiate viendra de P3 (statistique).

---

## 6. P4 — Registre de profils WAF (`--waf-profile`)

**Objectif :** implémenter la version *légère et honnête* du « miroir WAF
sémantique » : une table de correspondance fingerprint → tamper-set
recommandé, enrichie par knowledge (compatible C13).

**Design :**

- `src/detection/waf_profiles.rs` : table data-driven (amorcée depuis les
  fingerprints collectés au bench : Cloudflare, AWS WAF, Akamai, ModSec/CRS,
  Imperva…) → liste de tampers priorisés (aucun tamper nouveau —
  réutilisation du set existant) ;
- `--waf-profile <name>` (hint manuel) + profil déduit du fingerprint si
  connu ;
  - `--dry-run` affiche le plan (profil + tampers recommandés) ;
  - `Baseline::is_waf_blocked()` reste la gâchette runtime ;
- Knowledge (opt-in) : extension de la clé d'agrégat avec `waf_vendor`
  (schema v1 → v2 opt-in) pour booster `(waf_vendor → tamper)` par replay.

**Critères d'acceptance :**

1. critère mesurable : à confirmation égale, `req_p50` avec profil connu ≤
   sans profil (mesuré sur `bench/reports/history.jsonl`) ;
2. profil inconnu → hint ignoré, jamais auto-monté ;
3. bench : vérifier sur `bench/` les scénarios `WAF=CRS/Cloudflare`.

**Effort :** M (4-6 jours). **Risques :** fossilisation (CRS évolue) —
mitigation : décroissance temporelle déjà dans C13 + `knowledge reset`.

---

## 7. P6 — Recon : tags GraphQL / endpoints LLM (passive)

**Objectif :** cartographier **sans tester** les surfaces modernes (route
`/graphql`, journal introspection, endpoints de chat/completions) —
préparation à la cautèle, pas implémentation d'attaque RAG (hors scope SQLi,
voir §9).

**Design :**

- `src/recon/crawler` : détection passive URL-based (`/graphql`, `.graphql`)
  et pattern de réponse GraphQL (objet `errors` + `message`) sur les GET
  existant du crawl — **0 sonde réseau supplémentaire par défaut** ;
- report JSON : section `surfaces{graphql:[…], llm:[…]}` — les URLs y
  figurent car collectées passivement (comme les paramètres actuels des
  `findings`) ; scrubber inchangé ;
- `--recon-introspection` (OPT-IN) : sonde POST `{"query":"{__typename}"}`
  par endpoint ciblé, uniquement cible autorisée — reste détection, pas
  exploitation.

**Critères d'acceptance :**

1. wiremock multi-endpoints → les tags apparaissent dans `--output` JSON ;
2. default OFF byte-identical (0 sonde réseau sans flag) ;
3. doc chap. 2.

**Effort :** S (2 jours). **Risques :** aucun significatif.

---

## 8. Séquencement proposé (série v1.1)

```
v1.0 tag (contrat actuel : gel rc, C1..C13, audit OPSEC final)
  │
  ├─ v1.1.0  P5 SQLite dialecte       (PR payloads → union/énumération ; wiremock)
  ├─ v1.1.1  P2 Bypass adaptatif      (pas de ligne rouge → pas d'ADR lourd)
  ├─ v1.1.2  P1 Second-ordre          (ADR 0010 avant code — D1 + D3 validés)
  ├─ v1.1.3  P3 Time-stat             (doc tension OPSEC, bench latence)
  ├─ v1.1.4  P4 WAF profiles          (bench-driven, knowledge opt-in)
  └─ v1.1.5  P6 Recon tags            (passif ; MCP à l'itération suivante)
```

**Ordre justifié :** P5 = cheap win immédiat et module isolé ; P2 = pas
d'écriture cible (le seul ADR est léger) ; P1 = plus forte valeur mais
2 décisions d'avance (D1/D3) donc ADR avant code ; P3/P4 = validation par
le bench (CAL-1/C1 déjà en place) ; P6 = dernière marge dérisoire
(append-only).

---

## 9. Bornes (« won't do ») — cohérence doctrine

| Item | Statut | Pourquoi |
|---|---|---|
| RCE/weaponization (`xp_cmdshell`, `OUTFILE`, `LOAD_FILE`) | won't do (déjà codé) | hors mandat détection ; SELECT-only au-dessus du code |
| Agent LLM autonome en détection | won't do | veto ROADMAP §6.1 ; explicabilité/OPSEC ; `--ai-suggest` reste conseiller post-échec |
| RAG / vector-DB poisoning, prompt-injection | won't do (sauf P6 tags passifs) | autre couche d'attaque (app IA), pas du SQLi ; envisager un *tool* séparé plus tard |
| ML black-box détecteur | won't do | idem ; C13 comptes suffit (preuve `history.jsonl`) |
| JA3 randomisation maison | won't do | coverage via proxy externe ; rustls stable documenté |
| Transport HTTP/3/QUIC | blocked (revue continue) | écosystème h3 rust instable ; signature réseau finale change ; pas de valeur mesurée encore |

---

## 10. Journal

- [x] 2026-10-18 : plan créé (plan mode), basé sur playbook ch. 10 §10.8,
  CHANGELOG (v1.0-rc en cours), ROADMAP §6.1 vetos + C13/C5 implémentés.
- [x] 2026-10-18 : **D1..D4 tranchées par l'opérateur** — D1 accepté (ADR 0010),
  D3 = MCP direct (garde-fous §4.1), D4 = P5 d'abord.
- [x] 2026-10-18 : dépôt dans le repo (`docs/plan-gaps-2026.md`, mode build).
- [ ] À l'amorçage P1 : rédiger `docs/adr/0010-second-order.md` avant le code.
- [ ] À chaque PR : appliquer l'invariant d'en-tête (byte-identical OFF,
  fmt/clippy/test/doc, golden + docs).
